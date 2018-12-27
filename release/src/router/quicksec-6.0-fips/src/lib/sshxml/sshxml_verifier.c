/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Verifier for XML.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshXmlVerifier"


/************************** Static help functions ***************************/

/* Lookup element declaration for the element `name', `name_len'.  The
   function returns the declaration or NULL if the element is
   unknown. */
static SshXmlElementDecl
ssh_xml_verifier_lookup_element_decl(SshXmlVerifier verifier,
                                     const unsigned char *name,
                                     size_t name_len)
{
  SshXmlElementDeclStruct decl_struct;
  SshADTHandle h;

  /* Do we know this element? */

  memset(&decl_struct, 0, sizeof(decl_struct));
  decl_struct.header.name = (unsigned char *) name;
  decl_struct.header.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(verifier->elements, &decl_struct);
  if (h == SSH_ADT_INVALID)
    return NULL;

  return ssh_adt_get(verifier->elements, h);
}

/* Lookup or create an element declaration for the element `name',
   `name_return'.  If the element already exists, the function returns
   its current declaration and sets the argument `unique_return' to
   FALSE.  Otherwise the function creates a new declaration and sets
   `unique_return' to TRUE.  The function returns NULL if the system
   ran out of memory. */
static SshXmlElementDecl
ssh_xml_verifier_insert_element_decl(SshXmlVerifier verifier,
                                     const unsigned char *name,
                                     size_t name_len,
                                     Boolean *unique_return)
{
  SshXmlElementDecl decl;

  *unique_return = TRUE;

  /* Do we know this element? */
  decl = ssh_xml_verifier_lookup_element_decl(verifier, name, name_len);
  if (decl)
    {
      /* The element already exists. */
      *unique_return = FALSE;
      return decl;
    }

  /* The element is unknown. */

  decl = ssh_calloc(1, sizeof(*decl));
  if (decl == NULL)
    return NULL;

  decl->header.name = ssh_xml_intern(verifier->dtd_parser, name, name_len);
  if (decl->header.name == NULL)
    {
      ssh_free(decl);
      return NULL;
    }
  decl->header.name_len = name_len;

  /* Insert it to our list of elements. */
  (void) ssh_adt_insert(verifier->elements, decl);

  return decl;
}

/* Push a new element into the verifier's syntax tree.  The function
   returns TRUE if the operation was successful and FALSE
   otherwise. */
static Boolean
ssh_xml_verifier_push_element(SshXmlVerifier verifier)
{
  SshXmlVerifierElement element;

  element = ssh_calloc(1, sizeof(*element));
  if (element == NULL)
    return FALSE;

  element->next = verifier->syntax_tree;
  verifier->syntax_tree = element;

  return TRUE;
}

/* Pop an element from the verifier's syntax tree. */
static void
ssh_xml_verifier_pop_element(SshXmlVerifier verifier)
{
  SshXmlVerifierElement element;

  SSH_ASSERT(verifier->syntax_tree != NULL);

  element = verifier->syntax_tree;
  verifier->syntax_tree = element->next;

  ssh_free(element);
}

/* Clear all dynamic state from the verifier `verifier'.  After this
   call, the verifier is clean like just after
   ssh_xml_verifier_create. */
static void
ssh_xml_verifier_clear(SshXmlVerifier verifier)
{
  SshADTHandle h;

  if (verifier->general_entities)
    ssh_xml_clear_entities(verifier->dtd_parser, verifier->general_entities,
                           TRUE);
  if (verifier->parameter_entities)
    ssh_xml_clear_entities(verifier->dtd_parser, verifier->parameter_entities,
                           TRUE);

  if (verifier->elements)
    {
      while ((h = ssh_adt_enumerate_start(verifier->elements))
             != SSH_ADT_INVALID)
        {
          SshXmlElementDecl decl = ssh_adt_get(verifier->elements, h);

          ssh_adt_delete(verifier->elements, h);

          ssh_xml_verifier_destroy_dfa(decl->dfa);

          ssh_xml_attribute_definitions_free(verifier->dtd_parser,
                                             decl->attributes);
          ssh_free(decl);
        }
    }

  if (verifier->ids)
    {
      while ((h = ssh_adt_enumerate_start(verifier->ids)) != SSH_ADT_INVALID)
        {
          SshXmlID id = ssh_adt_get(verifier->ids, h);

          ssh_adt_delete(verifier->ids, h);
          ssh_free(id->name);
          ssh_free(id);
        }
    }

  /* Clear syntax tree. */
  while (verifier->syntax_tree)
    ssh_xml_verifier_pop_element(verifier);

  /* Flags and state variables. */
  verifier->root_element = NULL;

  if (verifier->obstack)
    ssh_obstack_clear(verifier->obstack);
}


/***************************** Content handler ******************************/

static SshOperationHandle
ssh_xml_verifier_start_document(SshXmlParser parser, SshXmlResultCB result_cb,
                                void *result_cb_context,
                                void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  /* Pass the callback forward. */
  if (verifier->content_handler.start_document)
    return (*verifier->content_handler.start_document)(
                                                parser,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}


static SshOperationHandle
ssh_xml_verifier_end_document(SshXmlParser parser, SshXmlResultCB result_cb,
                              void *result_cb_context,
                              void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  /* Pass the callback forward. */
  if (verifier->content_handler.end_document)
    return (*verifier->content_handler.end_document)(
                                                parser,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}


static SshOperationHandle
ssh_xml_verifier_start_element(SshXmlParser parser,
                               const unsigned char *name, size_t name_len,
                               SshADTContainer attributes,
                               SshXmlResultCB result_cb,
                               void *result_cb_context,
                               void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshXmlElementDecl decl;
  SshUInt32 i;
  SshXmlAttribute attr;
  SshXmlAttributeDefinition attrdef;
  SshADTHandle h;
  Boolean unique;
  SshXmlVerifierElement element = verifier->syntax_tree;

  /* Verify if the document type has been selected. */
  if (verifier->root_element)
    {
      /* Do we know this element? */
      decl = ssh_xml_verifier_lookup_element_decl(verifier, name, name_len);
      if (decl == NULL)
        {
          /* Call the parser's error handler so we get all user
             options applied for the message. */
          ssh_xml_fatal_error(verifier->parser,
                              "Element `", name, "' is not declared", NULL);
        not_well_formed:
          (*result_cb)(SSH_XML_ERROR_NOT_WELL_FORMED, result_cb_context);
          return NULL;
        }

      /* Does this element match the content specification of our element. */
      if (element)
        {
          SshXmlElementDecl pdecl = element->decl;

          /* Check if the content spec matches. */
          switch (pdecl->content_spec)
            {
            case SSH_XML_ELEMENT_CONTENT_EMPTY:
              ssh_xml_fatal_error(verifier->parser,
                                  "Child `", name, "' not allowed for an "
                                  "empty element `",
                                  pdecl->header.name, "'", NULL);
              goto not_well_formed;
              break;

            case SSH_XML_ELEMENT_CONTENT_ANY:
              /* It matches always. */
              break;

            case SSH_XML_ELEMENT_CONTENT_EXPR:
              if (!ssh_xml_verifier_execute_dfa(pdecl->dfa, name,
                                                &element->dfa_state))
                {
                  ssh_xml_fatal_error(verifier->parser,
                                      "Element `", pdecl->header.name,
                                      "' does not allow element `", name,
                                      "' here", NULL);
                  goto error_not_well_formed;
                }
              break;
            }
        }
      else
        {
          /* It must match our root element. */
          if (name != verifier->root_element)
            {
              ssh_xml_fatal_error(verifier->parser,
                                  "Root element `", name ,"' does not match "
                                  "document's root element `",
                                  verifier->root_element, "'", NULL);
              (*result_cb)(SSH_XML_ERROR_NOT_WELL_FORMED, result_cb_context);
              return NULL;
            }
        }

      /* Push a new syntax tree frame. */
      if (!ssh_xml_verifier_push_element(verifier))
        goto error_memory;

      /* Save element declaration. */
      verifier->syntax_tree->decl = decl;


      /* Check the validity of attributes. */

      /* First, enumerate over all attributes and see that they match
         their specification. */
      for (h = ssh_adt_enumerate_start(attributes);
           h;
           h = ssh_adt_enumerate_next(attributes, h))
        {
          attr = ssh_adt_get(attributes, h);

          /* Do we know its definition? */

          if (decl->attributes)
            attrdef = ssh_xml_lookup_attribute_definitions(
                                                        decl->attributes,
                                                        attr->header.name,
                                                        attr->header.name_len);
          else
            attrdef = NULL;

          if (attrdef == NULL)
            {
              if (attr->header.name_len > 3
                  && memcmp(attr->header.name, "xml", 3) == 0)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Ignoring `xml' prefixed attribute `%s'",
                             attr->header.name));
                  continue;
                }

              /* The attribute is not defined. */
              ssh_xml_fatal_error(verifier->parser,
                                  "Attribute `", attr->header.name,
                                  "' is not defined", NULL);
            error_not_well_formed:
              (*result_cb)(SSH_XML_ERROR_NOT_WELL_FORMED, result_cb_context);
              return NULL;
            }

          /* Attribute-value normalization for non-CDATA attributes. */
          if (attrdef->type != SSH_XML_ATTRIBUTE_TYPE_CDATA)
            {
              SshInt32 i, j;

              /* Skip all leading whitespace.  The input is UTF-8 and
                 that's why we can do this without decoding the
                 individual characters. */
              for (i = 0; i < attr->value_len && attr->value[i] == ' '; i++)
                ;
              if (i > 0)
                {
                  memmove(attr->value, attr->value + i, attr->value_len - i);
                  attr->value_len -= i;
                }

              /* Skip all trailing whitespace. */
              for (i = attr->value_len - 1;
                   i >= 0 && attr->value[i] == ' ';
                   i--)
                ;
              attr->value_len = i + 1;

              /* Replace all sequences of space characters with a
                 single space character. */
              for (i = 0; i < attr->value_len; i++)
                {
                  if (attr->value[i] == ' ')
                    {
                      for (j = i + 1;
                           j < attr->value_len && attr->value[j] == ' ';
                           j++)
                        ;
                      if (j > i + 1)
                        {
                          memmove(attr->value + i + 1, attr->value + j,
                                  attr->value_len - j);
                          attr->value_len -= j - i - 1;
                        }
                    }
                }
              attr->value[attr->value_len] = '\0';
            }

          /* Check that fixed values are really fixed. */
          if (attrdef->default_type == SSH_XML_ATTRIBUTE_DEFAULT_TYPE_FIXED)
            if (attr->value_len != attrdef->value_len
                || memcmp(attr->value, attrdef->value, attr->value_len) != 0)
              {
                ssh_xml_fatal_error(verifier->parser,
                                    "Value of the attribute `",
                                    attr->header.name, "' does not match the ",
                                    "fixed default value `",
                                    attrdef->value, "'", NULL);
                goto error_not_well_formed;
              }

          /* Check that the attribute value matches its type. */
          switch (attrdef->type)
            {
            case SSH_XML_ATTRIBUTE_TYPE_CDATA:
              /* Nothing special here. */
              break;

            case SSH_XML_ATTRIBUTE_TYPE_ID:
              {
                SshXmlIDStruct id_struct;
                SshXmlID id;
                SshADTHandle handle;
                SshXmlAttrEnumCtxStruct enum_ctx;
                SshUInt32 count;

                /* Enumerate the value. */
                ssh_xml_value_enum_init(attr->value, attr->value_len,
                                        SSH_XML_ATTR_ENUM_IDREFS,
                                        &enum_ctx);
                for (count = 0; ; count++)
                  {
                    const unsigned char *value;
                    size_t len;

                    value = ssh_xml_attr_value_enum_next(&enum_ctx, &len);
                    if ((value == NULL
                         && (count == 0 || enum_ctx.invalid))
                        || (value && count > 0))
                      {
                        ssh_xml_fatal_error(verifier->parser,
                                            "Invalid ID value `",
                                            attr->value, "'", NULL);
                        goto error_not_well_formed;
                      }
                    if (value == NULL)
                      /* Value processed. */
                      break;

                    /* Intern the value. */
                    id_struct.header.name
                      = ssh_xml_intern(verifier->dtd_parser, value, len);
                    if (id_struct.header.name == NULL)
                      goto error_memory;
                    id_struct.header.name_len = len;

                    /* Do we already know this ID value? */
                    handle = ssh_adt_get_handle_to_equal(verifier->ids,
                                                         &id_struct);
                    if (handle != SSH_ADT_INVALID)
                      {
                        /* Found it.  Is it already defined? */
                        id = ssh_adt_get(verifier->ids, handle);
                        if (id->defined)
                          {
                            /* Yes.  This is a second definition for
                               the same ID. */
                            ssh_xml_fatal_error(verifier->parser,
                                                "ID attribute value `",
                                                attr->value, "' is not unique",
                                                NULL);
                            goto error_not_well_formed;
                          }
                        else
                          {
                            /* No.  There were a forward reference for
                               this ID earlier in the document. */
                            ssh_free(id->name);
                            id->name = NULL;

                            id->defined = 1;
                          }
                      }
                    else
                      {
                        /* This is the first definition and reference
                           for this ID. */

                        id = ssh_calloc(1, sizeof(*id));
                        if (id == NULL)
                          goto error_memory;

                        id->header = id_struct.header;
                        id->defined = 1;

                        (void) ssh_adt_insert(verifier->ids, id);
                      }
                  }
              }
              break;

            case SSH_XML_ATTRIBUTE_TYPE_IDREF:
            case SSH_XML_ATTRIBUTE_TYPE_IDREFS:
              {
                SshUInt32 count;
                SshXmlIDStruct id_struct;
                SshXmlID id;
                SshXmlAttrEnumCtxStruct enum_ctx;
                SshXmlInput input;

                /* Enumerate the value. */
                ssh_xml_value_enum_init(attr->value, attr->value_len,
                                        SSH_XML_ATTR_ENUM_IDREFS,
                                        &enum_ctx);
                for (count = 0; ; count++)
                  {
                    const unsigned char *value;
                    size_t len;

                    value = ssh_xml_attr_value_enum_next(&enum_ctx, &len);
                    if ((value == NULL && count == 0)
                        || (value && count > 0
                            && (attrdef->type
                                == SSH_XML_ATTRIBUTE_TYPE_IDREF)))
                      {
                        ssh_xml_fatal_error(verifier->parser,
                                            "Invalid value `",
                                            attr->value, "'", NULL);
                        goto error_not_well_formed;
                      }
                    if (value == NULL)
                      /* Values processed. */
                      break;

                    /* Do we know this ID? */
                    id_struct.header.name = (unsigned char *) value;
                    id_struct.header.name_len = len;
                    if (ssh_adt_get_handle_to_equal(verifier->ids,
                                                    &id_struct)
                        == SSH_ADT_INVALID)
                      {
                        /* This is still unknown.  Are forward
                           references allowed? */
                        if (verifier->params.no_forward_id_refs)
                          {
                            /* No they are not.  This is then a fatal
                               error. */
                            ssh_xml_fatal_error(verifier->parser,
                                                "Reference to an unknown ID `",
                                                value, "'", NULL);
                            goto error_not_well_formed;
                          }

                        /* Let's add a place-holder so that we can
                           report this as an error if the rest of the
                           document does not define the header. */
                        id = ssh_calloc(1, sizeof(*id));
                        if (id == NULL)
                          goto error_memory;

                        id->header.name
                          = ssh_xml_intern(verifier->dtd_parser, value, len);
                        if (id->header.name == NULL)
                          {
                            ssh_free(id);
                            goto error_memory;
                          }
                        id->header.name_len = len;

                        /* Store location from which this ID was
                           referenced. */

                        if (verifier->dtd)
                          input = verifier->dtd_parser->input;
                        else
                          input = verifier->parser->input;

                        id->name = ssh_strdup(input->name);
                        if (id->name == NULL)
                          {
                            ssh_free(id);
                            goto error_memory;
                          }
                        id->line = input->line;
                        id->column = input->column;

                        (void) ssh_adt_insert(verifier->ids, id);
                      }
                  }
              }
              break;

            case SSH_XML_ATTRIBUTE_TYPE_ENTITY:
            case SSH_XML_ATTRIBUTE_TYPE_ENTITIES:
              /* These are not implemented yet. */
              break;

            case SSH_XML_ATTRIBUTE_TYPE_NMTOKEN:
            case SSH_XML_ATTRIBUTE_TYPE_NMTOKENS:
              {
                SshUInt32 count;
                SshXmlAttrEnumCtxStruct enum_ctx;

                /* Enumerate the value. */
                ssh_xml_value_enum_init(attr->value, attr->value_len,
                                        SSH_XML_ATTR_ENUM_NMTOKENS,
                                        &enum_ctx);
                for (count = 0; ; count++)
                  {
                    const unsigned char *value;
                    size_t len;

                    value = ssh_xml_attr_value_enum_next(&enum_ctx, &len);
                    if ((value == NULL && count == 0)
                        || (value && count > 0
                            && (attrdef->type
                                == SSH_XML_ATTRIBUTE_TYPE_NMTOKEN)))
                      {
                        ssh_xml_fatal_error(verifier->parser,
                                            "Invalid value `",
                                            attr->value, "'", NULL);
                        goto error_not_well_formed;
                      }
                    if (value == NULL)
                      /* Values processed. */
                      break;
                  }
              }
              break;

            case SSH_XML_ATTRIBUTE_TYPE_NOTATION:
            case SSH_XML_ATTRIBUTE_TYPE_ENUMERATION:
              /* Strip leading whitespace. */
              for (i = 0;
                   i < attr->value_len && SSH_XML_IS_SPACE(attr->value[i]);
                   i++)
                ;
              if (i)
                {
                  memmove(attr->value, attr->value + i,
                          attr->value_len - i + 1);
                  attr->value_len -= i;
                }

              /* Strip trailing whitespace. */
              if (attr->value_len > 0)
                {
                  for (attr->value_len--;
                       attr->value_len > 0;
                       attr->value_len--)
                    if (!SSH_XML_IS_SPACE(attr->value[attr->value_len]))
                      break;
                  attr->value_len++;
                }

              /* The value must be found from the enumeration. */
              for (i = 0; i < attrdef->num_enums; i++)
                if (attr->value_len == attrdef->enum_lens[i]
                    && memcmp(attr->value, attrdef->enums[i],
                              attr->value_len) == 0)
                  break;

              if (i >= attrdef->num_enums)
                {
                  ssh_xml_fatal_error(
                        verifier->parser,
                        "Value `", attr->value,"' of the attribute `",
                        attr->header.name, "' does not match ",
                        attrdef->type == SSH_XML_ATTRIBUTE_TYPE_ENUMERATION
                        ? "enumeration" : "notation", " values", NULL);
                  goto error_not_well_formed;
                }
              break;
            }
        }

      /* Next, iterate over all attribute definitions and check
         required and default values. */
      if (decl->attributes)
        for (h = ssh_adt_enumerate_start(decl->attributes);
             h;
             h = ssh_adt_enumerate_next(decl->attributes, h))
          {
            attrdef = ssh_adt_get(decl->attributes, h);

            /* Was the attribute specified? */
            attr = ssh_xml_lookup_attribute(attributes, attrdef->header.name,
                                            attrdef->header.name_len);
            if (attr)
              /* Yes it was.  And therefore, we have already checked
                 it in the first phase. */
              continue;

            /* Handle missing attributes. */
            switch (attrdef->default_type)
              {
              case SSH_XML_ATTRIBUTE_DEFAULT_TYPE_REQUIRED:
                ssh_xml_fatal_error(verifier->parser,
                                    "Required attribute `",
                                    attrdef->header.name,
                                    "' not specified", NULL);
                goto error_not_well_formed;
                break;

              case SSH_XML_ATTRIBUTE_DEFAULT_TYPE_IMPLIED:
                /* These can be omitted. */
                break;

              case SSH_XML_ATTRIBUTE_DEFAULT_TYPE_FIXED:
              case SSH_XML_ATTRIBUTE_DEFAULT_TYPE_DEFAULT:
                /* Insert a new attribute with the default value. */
                attr = ssh_xml_insert_attribute(verifier->parser, attributes,
                                                attrdef->header.name,
                                                attrdef->header.name_len,
                                                &unique);
                if (attr == NULL)
                  {
                  error_memory:
                    ssh_xml_error(verifier->parser, "Out of memory", NULL);
                    (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
                    return NULL;
                  }

                /* Set the default value. */
                attr->value = ssh_memdup(attrdef->value, attrdef->value_len);
                if (attr->value == NULL)
                  goto error_memory;
                attr->value_len = attrdef->value_len;
                break;
              }
          }
    }

  /* Pass the call forward. */
  if (verifier->content_handler.start_element)
    return (*verifier->content_handler.start_element)(
                                                parser,
                                                name, name_len, attributes,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_verifier_end_element(SshXmlParser parser,
                             const unsigned char *name, size_t name_len,
                             SshXmlResultCB result_cb, void *result_cb_context,
                             void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshXmlVerifierElement element = verifier->syntax_tree;

  /* Verify if the document type has been selected. */
  if (verifier->root_element)
    {
      /* Check that EOF is allowed by current element's content spec. */
      switch (element->decl->content_spec)
        {
        case SSH_XML_ELEMENT_CONTENT_EMPTY:
        case SSH_XML_ELEMENT_CONTENT_ANY:
          /* These are just fine. */
          break;

        case SSH_XML_ELEMENT_CONTENT_EXPR:
          /* Check that DFA accepts EOF. */
          if (!ssh_xml_verifier_execute_dfa(element->decl->dfa,
                                            SSH_XML_DFA_INPUT_EOF,
                                            &element->dfa_state))
            {
              ssh_xml_fatal_error(verifier->parser,
                                  "End of element `", name,
                                  "' is not allowed yet", NULL);
              (*result_cb)(SSH_XML_ERROR_NOT_WELL_FORMED, result_cb_context);
              return NULL;
            }
          break;
        }

      /* Pop a syntax tree frame. */
      ssh_xml_verifier_pop_element(verifier);
    }

  /* Was this the end of our root element? */
  if (verifier->syntax_tree == NULL)
    {
      SshADTHandle h;
      Boolean not_well_formed = FALSE;

      /* Yes it was.  Report all references for undefined ID
         attributes. */

      for (h = ssh_adt_enumerate_start(verifier->ids);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(verifier->ids, h))
        {
          SshXmlID id = ssh_adt_get(verifier->ids, h);
          SshXmlInputStruct input;

          if (id->defined)
            continue;

          /* Create a fake input object. */
          memset(&input, 0, sizeof(input));
          input.name = id->name;
          input.line = id->line;
          input.column = id->column;

          ssh_xml_fatal_error_with_input(verifier->parser, &input,
                                         "Reference to an unknown ID `",
                                         id->header.name, "'", NULL);
          not_well_formed = TRUE;
        }
      if (not_well_formed)
        {
          (*result_cb)(SSH_XML_ERROR_NOT_WELL_FORMED, result_cb_context);
          return NULL;
        }
    }

  /* Pass the call forward. */
  if (verifier->content_handler.end_element)
    return (*verifier->content_handler.end_element)(
                                                parser, name, name_len,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_verifier_characters(SshXmlParser parser,
                            const unsigned char *data, size_t data_len,
                            Boolean all_whitespace,
                            SshXmlResultCB result_cb, void *result_cb_context,
                            void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshXmlVerifierElement element = verifier->syntax_tree;

  /* Verify if the document type has been selected. */
  if (verifier->root_element)
    {
      /* Check that character data is allowed by element's content spec. */
      switch (element->decl->content_spec)
        {
        case SSH_XML_ELEMENT_CONTENT_EMPTY:
        not_matched:
          if (all_whitespace)
            {
              /* Notify it as ignorable whitespace. */
              if (verifier->content_handler.ignorable_wspace)
                return (*verifier->content_handler.ignorable_wspace)(
                                                parser,
                                                data, data_len, FALSE,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);
              else
                (*result_cb)(SSH_XML_OK, result_cb_context);
            }
          else
            {
              ssh_xml_fatal_error(verifier->parser,
                                  "Element `", element->decl->header.name,
                                  "' does not allow character data here",
                                  NULL);
              (*result_cb)(SSH_XML_ERROR_NOT_WELL_FORMED, result_cb_context);
            }
          /* Callback is now called synchronously. */
          return NULL;
          break;

        case SSH_XML_ELEMENT_CONTENT_ANY:
          /* These are just fine. */
          break;

        case SSH_XML_ELEMENT_CONTENT_EXPR:
          /* Check that DFA accepts EOF. */
          if (!ssh_xml_verifier_execute_dfa(element->decl->dfa,
                                            SSH_XML_DFA_INPUT_PCDATA,
                                            &element->dfa_state))
            goto not_matched;
          break;
        }
    }

  /* Pass the call forward. */
  if (verifier->content_handler.characters)
    return (*verifier->content_handler.characters)(
                                                parser,
                                                data, data_len, all_whitespace,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_verifier_ignorable_wspace(SshXmlParser parser,
                                  const unsigned char *data, size_t data_len,
                                  Boolean in_dtd,
                                  SshXmlResultCB result_cb,
                                  void *result_cb_context,
                                  void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  if (verifier->content_handler.ignorable_wspace)
    return (*verifier->content_handler.ignorable_wspace)(
                                                parser,
                                                data, data_len, in_dtd,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_verifier_pi(SshXmlParser parser,
                    const unsigned char *name, size_t name_len,
                    const unsigned char *data, size_t data_len,
                    SshXmlResultCB result_cb, void *result_cb_context,
                    void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  if (verifier->content_handler.pi)
    return (*verifier->content_handler.pi)(parser, name, name_len,
                                           data, data_len,
                                           result_cb, result_cb_context,
                                           verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

const
static SshXmlContentHandlerStruct ssh_xml_verifier_content_handler =
{
  ssh_xml_verifier_start_document,
  ssh_xml_verifier_end_document,
  ssh_xml_verifier_start_element,
  ssh_xml_verifier_end_element,
  ssh_xml_verifier_characters,
  ssh_xml_verifier_ignorable_wspace,
  ssh_xml_verifier_pi,
};


/****************************** Error handler *******************************/

static void
ssh_xml_verifier_warning(SshXmlParser parser,
                         const char *input_name, SshUInt32 line,
                         SshUInt32 column,
                         const char *message, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  if (verifier->error_handler.warning)
    (*verifier->error_handler.warning)(parser, input_name, line, column,
                                       message, verifier->handler_context);
}

static void
ssh_xml_verifier_error(SshXmlParser parser,
              const char *input_name, SshUInt32 line, SshUInt32 column,
              const char *message, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  if (verifier->error_handler.error)
    (*verifier->error_handler.error)(parser, input_name, line, column,
                                     message, verifier->handler_context);
}

static void
ssh_xml_verifier_fatal_error(SshXmlParser parser,
                    const char *input_name, SshUInt32 line, SshUInt32 column,
                    const char *message, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  if (verifier->error_handler.fatal_error)
    (*verifier->error_handler.fatal_error)(parser, input_name, line, column,
                                           message, verifier->handler_context);
}

const
static SshXmlErrorHandlerStruct ssh_xml_verifier_error_handler =
{
  ssh_xml_verifier_warning,
  ssh_xml_verifier_error,
  ssh_xml_verifier_fatal_error,
};


/******************************* DTD handler ********************************/

static SshOperationHandle
ssh_xml_verifier_entity_decl(SshXmlParser parser,
                             const unsigned char *name, size_t name_len,
                             Boolean general, Boolean internal,
                             const unsigned char *value, size_t value_len,
                             const unsigned char *pubid, size_t pubid_len,
                             const unsigned char *sysid, size_t sysid_len,
                             const unsigned char *ndata, size_t ndata_len,
                             SshXmlResultCB result_cb, void *result_cb_context,
                             void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshADTContainer bag;
  SshXmlEntity entity;
  Boolean unique;
  char *input_stream_name;

  if (general)
    bag = verifier->general_entities;
  else
    bag = verifier->parameter_entities;

  if (verifier->dtd)
    /* We are currently parsing an external DTD. */
    input_stream_name = verifier->dtd_parser->input->name;
  else
    input_stream_name = verifier->parser->input->name;

  entity = ssh_xml_insert_entity(verifier->dtd_parser, bag, input_stream_name,
                                 general, name, name_len, &unique);
  if (entity == NULL)
    {
    error_memory:
      (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
      return NULL;
    }

  if (!unique)
    {
      /* Warn if the enity is defined twise at the same location (DTD
         or XML's inlined DTD). */
      if (verifier->dtd == entity->from_dtd)
        ssh_xml_warning(verifier->parser, "Entity `", name, "' is not unique",
                        NULL);
    }
  else
    {
      if (verifier->dtd)
        /* We are currently parsing an external DTD.  Let's mark where
           this entity was defined. */
        entity->from_dtd = 1;

      if (internal)
        {
          entity->internal = 1;
          entity->value.internal.data = ssh_memdup(value, value_len);
          if (entity->value.internal.data == NULL)
            goto error_memory;
          entity->value.internal.data_len = value_len;
        }
      else
        {
          if (pubid)
            {
              entity->value.external.pubid = ssh_memdup(pubid, pubid_len);
              if (entity->value.external.pubid == NULL)
                goto error_memory;
              entity->value.external.pubid_len = pubid_len;
            }

          if (sysid)
            {
              entity->value.external.sysid = ssh_memdup(sysid, sysid_len);
              if (entity->value.external.sysid == NULL)
                goto error_memory;
              entity->value.external.sysid_len = sysid_len;
            }

          if (ndata)
            {
              entity->value.external.ndata = ssh_memdup(ndata, ndata_len);
              if (entity->value.external.ndata == NULL)
                goto error_memory;
              entity->value.external.ndata_len = ndata_len;
            }
        }
    }

  /* And pass the call forward. */
  if (verifier->dtd_handler.entity_decl)
    return (*verifier->dtd_handler.entity_decl)(parser,
                                                name, name_len,
                                                general, internal,
                                                value, value_len,
                                                pubid, pubid_len,
                                                sysid, sysid_len,
                                                ndata, ndata_len,
                                                result_cb, result_cb_context,
                                                verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}


static SshOperationHandle
ssh_xml_verifier_notation_decl(SshXmlParser parser,
                               const unsigned char *name,
                               size_t name_len,
                               const unsigned char *pubid,
                               size_t pubid_len,
                               const unsigned char *sysid,
                               size_t sysid_len,
                               SshXmlResultCB result_cb,
                               void *result_cb_context,
                               void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  /* Pass the call forward. */
  if (verifier->dtd_handler.notation_decl)
    return (*verifier->dtd_handler.notation_decl)(parser,
                                                  name, name_len,
                                                  pubid, pubid_len,
                                                  sysid, sysid_len,
                                                  result_cb, result_cb_context,
                                                  verifier->handler_context);
  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}


static SshOperationHandle
ssh_xml_verifier_element_decl(SshXmlParser parser,
                              const unsigned char *name, size_t name_len,
                              SshXmlElementContentSpec content_spec,
                              const unsigned char *content_spec_expr,
                              size_t content_spec_expr_len,
                              SshXmlResultCB result_cb,
                              void *result_cb_context, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshXmlElementDecl decl;
  Boolean unique;

  decl = ssh_xml_verifier_insert_element_decl(verifier, name, name_len,
                                              &unique);
  if (decl == NULL)
    {
      /* Out of memory. */
      (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
      return NULL;
    }

  if (decl->declared)
    {
      ssh_xml_fatal_error(verifier->parser, "Element `", name,
                          "' declared more than once", NULL);
      (*result_cb)(SSH_XML_ERROR_NOT_VALID, result_cb_context);
      return NULL;
    }

  /* Initialize the element. */
  decl->declared = 1;
  decl->content_spec = content_spec;

  if (content_spec == SSH_XML_ELEMENT_CONTENT_EXPR)
    {
      /* Create a DFA for verifying its content. */
      decl->dfa = ssh_xml_verifier_create_dfa(verifier,
                                              content_spec_expr,
                                              content_spec_expr_len);
      if (decl->dfa == NULL)
        {
          if (verifier->dfa.error == SSH_XML_ERROR_MEMORY)
            ssh_xml_error(verifier->parser, "Out of memory", NULL);
          else
            ssh_xml_error(verifier->parser,
                          "Malformed content specification `",
                          content_spec_expr, "'",  NULL);

          (*result_cb)(verifier->dfa.error, result_cb_context);
          return NULL;
        }
    }

  /* Notify user or complete operation immediately. */
  if (verifier->dtd_handler.element_decl)
    return (*verifier->dtd_handler.element_decl)(parser, name, name_len,
                                                 content_spec,
                                                 content_spec_expr,
                                                 content_spec_expr_len,
                                                 result_cb, result_cb_context,
                                                 verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

static SshOperationHandle
ssh_xml_verifier_attlist_decl(SshXmlParser parser,
                              const unsigned char *element_name,
                              size_t element_name_len,
                              SshADTContainer attribute_defs,
                              SshXmlResultCB result_cb,
                              void *result_cb_context, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshXmlElementDecl decl;
  Boolean unique;
  SshADTHandle h;
  Boolean id_seen = FALSE;

  decl = ssh_xml_verifier_insert_element_decl(verifier, element_name,
                                              element_name_len, &unique);
  if (decl == NULL)
    {
      /* Out of memory. */
      (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
      return NULL;
    }

  if (decl->attributes == NULL)
    {
      /* Simply steal the attributes from the parser. */

      if (verifier->dtd)
        ssh_xml_steal_attribute_definitions(verifier->dtd_parser);
      else
        ssh_xml_steal_attribute_definitions(verifier->parser);

      decl->attributes = attribute_defs;
    }
  else
    {
      SshADTHandle h, hnext;
      SshXmlAttributeDefinition def, def2;

      /* Merge new attribute definitions into the existing ones. */
      for (h = ssh_adt_enumerate_start(attribute_defs);
           h != SSH_ADT_INVALID;
           h = hnext)
        {
          hnext = ssh_adt_enumerate_next(attribute_defs, h);

          def = ssh_adt_get(attribute_defs, h);

          /* Do we already know this attribute definition. */
          def2 = ssh_xml_lookup_attribute_definitions(decl->attributes,
                                                      def->header.name,
                                                      def->header.name_len);
          if (def2)
            {

              /* The attribute is defined more than once. */
              if (verifier->params.no_attr_decl_override)
                {
                  ssh_xml_error(verifier->parser,
                                "Attribute `", def->header.name,
                                "' of element `", element_name,
                                "' defined more than once", NULL);
                  (*result_cb)(SSH_XML_ERROR, result_cb_context);
                  return NULL;
                }
              else
                {
                  ssh_xml_warning(verifier->parser,
                                  "Attribute `", def->header.name,
                                  "' of element `", element_name,
                                  "' defined more than once", NULL);
                }
            }
          else
            {
              /* Not defined yet.  Let's steal the definition from our
                 argument container. */
              ssh_adt_delete(attribute_defs, h);
              ssh_adt_insert(decl->attributes, def);
            }
        }
    }

  /* Check the validity of the attributes so far. */
  for (h = ssh_adt_enumerate_start(decl->attributes);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(decl->attributes, h))
    {
      SshXmlAttributeDefinition attrdef = ssh_adt_get(decl->attributes, h);

      if (attrdef->type == SSH_XML_ATTRIBUTE_TYPE_ID)
        {
          /* One ID per element type. */
          if (id_seen)
            {
              ssh_xml_fatal_error(verifier->parser, "Element `",
                                  element_name, "' has more than one ",
                                  "ID attributes", NULL);
              (*result_cb)(SSH_XML_ERROR_NOT_VALID, result_cb_context);
              return NULL;
            }

          /* Check ID attribute default value. */
          switch (attrdef->default_type)
            {
            case SSH_XML_ATTRIBUTE_DEFAULT_TYPE_REQUIRED:
            case SSH_XML_ATTRIBUTE_DEFAULT_TYPE_IMPLIED:
              /* These are accepted. */
              break;

            default:
              ssh_xml_fatal_error(verifier->parser, "ID attribute `",
                                  attrdef->header.name, "' of element `",
                                  element_name, "' has invalid default type: ",
                                  "expected #IMPLIED or #REQUIRED", NULL);
              (*result_cb)(SSH_XML_ERROR_NOT_VALID, result_cb_context);
              return NULL;
              break;
            }

          /* An ID attribute seen. */
          id_seen = TRUE;
        }
    }

  /* And pass the information forward. */
  if (verifier->dtd_handler.attlist_decl)
    return (*verifier->dtd_handler.attlist_decl)(parser,
                                                 element_name,
                                                 element_name_len,
                                                 attribute_defs,
                                                 result_cb, result_cb_context,
                                                 verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}


static void
ssh_xml_verifier_dtd_result_cb(SshXmlResult result, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  /* Free the DTD name. */
  ssh_free(verifier->dtd_name);
  verifier->dtd_name = NULL;

  /* We are not parsing DTD anymore. */
  verifier->dtd = 0;

  /* This completes our operation. */
  if (!verifier->dtd_parse_handle_aborted)
    {
      if (verifier->dtd_parse_handle_registered)
        {
          ssh_operation_unregister(&verifier->dtd_parse_handle);
          verifier->dtd_parse_handle_registered = FALSE;
        }

      /* Complete the pending DOCTYPE operation. */
      (*verifier->result_cb)(result, verifier->result_cb_context);
    }
}


static void
ssh_xml_verifier_dtd_cb(SshStream stream, const char *stream_name,
                        SshXmlDestructorCB destructor_cb,
                        void *destructor_cb_context, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshOperationHandle handle;

  if (stream == NULL)
    {
      ssh_xml_fatal_error(verifier->parser, "Could not open DTD (SYSID ",
                          verifier->dtd_name, ")", NULL);
      ssh_free(verifier->dtd_name);
      verifier->dtd_name = NULL;

      /* This completes our operation. */
      if (!verifier->dtd_parse_handle_aborted)
        {
          if (verifier->dtd_parse_handle_registered)
            {
              ssh_operation_unregister(&verifier->dtd_parse_handle);
              verifier->dtd_parse_handle_registered = FALSE;
            }
          (*verifier->result_cb)(SSH_XML_ERROR, verifier->result_cb_context);
        }
      return;
    }

  /* Set that the stream name is set. */
  if (stream_name == NULL)
    stream_name = verifier->dtd_name;

  /* Parser DTD stream. */
  verifier->dtd = 1;
  handle = ssh_xml_parser_parse_stream(verifier->dtd_parser, TRUE,
                                       stream, stream_name,
                                       destructor_cb, destructor_cb_context,
                                       ssh_xml_verifier_dtd_result_cb,
                                       verifier);
  if (handle)
    verifier->handle = handle;
}


static void
ssh_xml_verifier_abort_cb(void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  /* Mark operation aborted. */
  verifier->dtd_parse_handle_aborted = TRUE;

  /* Abort the pending sub-operation. */
  SSH_ASSERT(verifier->handle != NULL);
  ssh_operation_abort(verifier->handle);
  verifier->handle = NULL;

  /* Free the DTD name. */
  ssh_free(verifier->dtd_name);
  verifier->dtd_name = NULL;

  /* The XML parse operation was aborted.  Clear all dynamic state
     from the verifier. */
  ssh_xml_verifier_clear(verifier);
}


static SshOperationHandle
ssh_xml_verifier_doctype(SshXmlParser parser,
                         const unsigned char *name, size_t name_len,
                         const unsigned char *pubid, size_t pubid_len,
                         const unsigned char *sysid, size_t sysid_len,
                         SshXmlResultCB result_cb, void *result_cb_context,
                         void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;
  SshOperationHandle handle;

  /* Save the name of the root element. */
  verifier->root_element = (unsigned char *) name;

  /* Try to fetch the DTD if it is specified. */
  if ((pubid || sysid) && verifier->dtd_callback)
    {
      /* Store completion callback. */
      verifier->result_cb = result_cb;
      verifier->result_cb_context = result_cb_context;

      /* Save the name of the DTD file.  The name of the DTD is also
         our flag to determine whether the DTD parsing operation is
         synchronous or asynchronous.  In the synchronous case, the
         `dtd_name' will be freed after our `dtd_callback' below.  In
         the asynchronous case, it is still non-null.  See the
         ssh_xml_verifier_dtd_cb and ssh_xml_verifier_dtd_result_cb
         for the details. */
      verifier->dtd_name = ssh_memdup(sysid, sysid_len);
      if (verifier->dtd_name == NULL)
        {
          (*result_cb)(SSH_XML_ERROR_MEMORY, result_cb_context);
          return NULL;
        }

      /* Fetch DTD. */
      handle = (*verifier->dtd_callback)(parser, pubid, pubid_len,
                                         sysid, sysid_len,
                                         ssh_xml_verifier_dtd_cb, verifier,
                                         verifier->dtd_callback_context);
      if (handle)
        /* The DTD retrieval was asynchronous.  We can store the
           handle without overriding the possible parse operation
           handle. */
        verifier->handle = handle;

      /* Check whether the whole operation was asynchronous. */
      if (verifier->dtd_name)
        {
          /* Yes it was. */
          verifier->dtd_parse_handle_registered = TRUE;
          verifier->dtd_parse_handle_aborted = FALSE;
          ssh_operation_register_no_alloc(&verifier->dtd_parse_handle,
                                          ssh_xml_verifier_abort_cb,
                                          verifier);
          return &verifier->dtd_parse_handle;
        }

      /* The operation was synchronous. */
      return NULL;
    }

  /* Otherwise, pass it to our user (or complete the operation). */
  if (verifier->dtd_handler.doctype)
    return (*verifier->dtd_handler.doctype)(parser, name, name_len,
                                            pubid, pubid_len,
                                            sysid, sysid_len,
                                            result_cb, result_cb_context,
                                            verifier->handler_context);

  (*result_cb)(SSH_XML_OK, result_cb_context);
  return NULL;
}

const
static SshXmlDtdHandlerStruct ssh_xml_verifier_dtd_handler =
{
  ssh_xml_verifier_entity_decl,
  ssh_xml_verifier_notation_decl,
  ssh_xml_verifier_element_decl,
  ssh_xml_verifier_attlist_decl,
  ssh_xml_verifier_doctype,
};


/***************************** Entity resolver ******************************/

static SshOperationHandle
ssh_xml_verifier_entity_resolver(SshXmlParser parser,
                                 const char *where_defined, Boolean general,
                                 const unsigned char *name, size_t name_len,
                                 const unsigned char *pubid, size_t pubid_len,
                                 const unsigned char *sysid, size_t sysid_len,
                                 SshXmlStreamCB result_cb,
                                 void *result_cb_context,
                                 void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  if (name)
    {
      SshXmlEntityStruct entity_struct;
      SshXmlEntity entity;
      SshADTContainer bag;
      SshADTHandle h;

      /* An internal entity.  Do we know it? */

      memset(&entity_struct, 0, sizeof(entity_struct));
      entity_struct.header.name = (unsigned char *) name;
      entity_struct.header.name_len = name_len;

      if (general)
        bag = verifier->general_entities;
      else
        bag = verifier->parameter_entities;

      h = ssh_adt_get_handle_to_equal(bag, &entity_struct);
      if (h != SSH_ADT_INVALID)
        {
          /* Yes, we know it. */
          entity = ssh_adt_get(bag, h);
          if (entity->internal)
            {
              SshStream stream;

              /* And since it is an internal entity, we have its
                 value. */
              stream = ssh_data_stream_create(entity->value.internal.data,
                                              entity->value.internal.data_len,
                                              TRUE);
              (*result_cb)(stream, entity->where_defined, NULL_FNPTR, NULL,
                           result_cb_context);
              return NULL;
            }

          /* It is an external entity.  Let's perform lookup with
             it using the user-supplied entity resolver. */

          where_defined = entity->where_defined;

          name = NULL;
          name_len = 0;

          pubid = entity->value.external.pubid;
          pubid_len = entity->value.external.pubid_len;

          sysid = entity->value.external.sysid;
          sysid_len = entity->value.external.sysid_len;
        }
      /* FALLTHROUGH to the user-supplied entity resolver. */
    }

  if (verifier->entity_resolver)
    return (*verifier->entity_resolver)(parser, where_defined, general,
                                        name, name_len,
                                        pubid, pubid_len,
                                        sysid, sysid_len,
                                        result_cb, result_cb_context,
                                        verifier->handler_context);

  (*result_cb)(NULL, NULL, NULL_FNPTR, NULL, result_cb_context);
  return NULL;
}


/************************* Parse done notification **************************/

static void
ssh_xml_verifier_parse_done_cb(SshXmlParser parser, void *context)
{
  SshXmlVerifier verifier = (SshXmlVerifier) context;

  /* Clear us. */
  ssh_xml_verifier_clear(verifier);

  /* Pass the call forward. */
  if (verifier->parse_done_cb)
    (*verifier->parse_done_cb)(parser, verifier->handler_context);
}


/************************ Public interface functions ************************/

SshXmlVerifier
ssh_xml_verifier_create(SshXmlVerifierParams params,
                        SshXmlVerifierDtdCB dtd_callback,
                        void *dtd_callback_context)
{
  SshXmlVerifier verifier;

  verifier = ssh_calloc(1, sizeof(*verifier));
  if (verifier == NULL)
    goto error;

  if ((verifier->obstack = ssh_obstack_create(NULL)) == NULL)
    goto error;

  /* Store parameters. */
  if (params)
    verifier->params = *params;

  /* Store handlers. */
  verifier->dtd_callback = dtd_callback;
  verifier->dtd_callback_context = dtd_callback_context;

  /* Create a DTD parser. */
  verifier->dtd_parser
    = ssh_xml_parser_create(NULL,
                            &ssh_xml_verifier_content_handler,
                            &ssh_xml_verifier_error_handler,
                            &ssh_xml_verifier_dtd_handler,
                            ssh_xml_verifier_entity_resolver,
                            NULL_FNPTR,
                            verifier);
  if (verifier->dtd_parser == NULL)
    goto error;

  /* Create input conversion module that is used in the content
     specification handling. */
  verifier->dfa.input_conv = ssh_charset_init(SSH_CHARSET_UTF8,
                                              SSH_CHARSET_UNICODE32);
  if (verifier->dfa.input_conv == NULL)
    goto error;

  /* Create containers for DTD elements. */

  verifier->general_entities = ssh_xml_name_hash_create(verifier->dtd_parser);
  verifier->parameter_entities
    = ssh_xml_name_hash_create(verifier->dtd_parser);
  verifier->elements = ssh_xml_name_hash_create(verifier->dtd_parser);
  verifier->ids = ssh_xml_name_hash_create(verifier->dtd_parser);

  if (verifier->general_entities == NULL
      || verifier->parameter_entities == NULL
      || verifier->elements == NULL
      || verifier->ids == NULL)
    goto error;

  /* All done. */
  return verifier;


  /* Error handling. */

 error:

  ssh_xml_verifier_destroy(verifier);

  return NULL;
}


void
ssh_xml_verifier_destroy(SshXmlVerifier verifier)
{
  if (verifier == NULL)
    return;

  /* Unhook from the XML parser. */
  ssh_xml_verifier_unhook(verifier);

  /* Clear all dynamic information from the verifier. */
  ssh_xml_verifier_clear(verifier);

  if (verifier->general_entities)
    ssh_adt_destroy(verifier->general_entities);
  if (verifier->parameter_entities)
    ssh_adt_destroy(verifier->parameter_entities);

  if (verifier->elements)
    ssh_adt_destroy(verifier->elements);
  if (verifier->ids)
    ssh_adt_destroy(verifier->ids);

  ssh_xml_parser_destroy(verifier->dtd_parser);

  if (verifier->dfa.input_conv)
    ssh_charset_free(verifier->dfa.input_conv);

  if (verifier->obstack)
    ssh_obstack_destroy(verifier->obstack);
  ssh_free(verifier);
}


Boolean
ssh_xml_parser_set_verifier(SshXmlParser parser, SshXmlVerifier verifier)
{
  /* Store pointer to our XML parser. */
  verifier->parser = parser;

  /* Hook between the low-level parser and the user-supplied handlers.
     Since we are the same implementation, we can access the parse's
     internal fields directly.  There is actually functions for doing
     this but we do not want to bloat the code more than necessary. */

  verifier->content_handler     = parser->content_handler;
  verifier->error_handler       = parser->error_handler;
  verifier->dtd_handler         = parser->dtd_handler;
  verifier->entity_resolver     = parser->entity_resolver;
  verifier->parse_done_cb       = parser->parse_done_cb;
  verifier->handler_context     = parser->handler_context;

  /* Register our own handlers. */
  parser->content_handler       = ssh_xml_verifier_content_handler;
  parser->error_handler         = ssh_xml_verifier_error_handler;
  parser->dtd_handler           = ssh_xml_verifier_dtd_handler;
  parser->entity_resolver       = ssh_xml_verifier_entity_resolver;
  parser->parse_done_cb         = ssh_xml_verifier_parse_done_cb;
  parser->handler_context       = verifier;

  /* All done. */
  return TRUE;
}


void
ssh_xml_verifier_unhook(SshXmlVerifier verifier)
{
  SshXmlParser parser = verifier->parser;

  if (parser == NULL)
    return;

  /* Return the original handlers. */
  parser->content_handler       = verifier->content_handler;
  parser->error_handler         = verifier->error_handler;
  parser->dtd_handler           = verifier->dtd_handler;
  parser->entity_resolver       = verifier->entity_resolver;
  parser->parse_done_cb         = verifier->parse_done_cb;
  parser->handler_context       = verifier->handler_context;

  verifier->parser = NULL;
}
