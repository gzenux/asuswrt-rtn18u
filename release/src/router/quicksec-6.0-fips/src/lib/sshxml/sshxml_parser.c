/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Parser for the Extensible Markup Language (XML) 1.0.  The parser
   reads unicode character (possible from different input encodings)
   from an input stream of type SshStream.  It parses the input and
   notifies the application about parsed elements of the XML document.
   The API follows the look and feel of the Simple API for XML (SAX).
*/

/* TODO:

   - Check errors.  Currently the system generates lots of not
     well-formed error but those should be generated only when the
     specification says so.

   - It should be possible to specify the input encoding when an input
     stream is entered into the system: add the encoding values into
     the public API and add the argument there.  All work is already
     done.

   - Verifying namespace declarations.

*/

#include "sshincludes.h"
#include "sshxml_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshXmlParser"

/* Match an `unsigned char' data `data' to the C-string `string'. */
#define SSH_MATCH(data, string) (strcmp((char *) data, string) == 0)

/* Call the handler function `func' and store its SshOperationHandle
   into `parser->callback_handle'.  The macro assumes that the parser
   pointer is in the local variable `parser'.  Note that it is safe to
   store the handle into `parser->callback_handle' in both synchronous
   and asynchronous cases since the parser is built so that further
   computation (and asynchronous calls) are made from the completion
   callbacks of this macro.  In other words: trust me, I know what I
   am doing. */
#define SSH_XML_HANDLER(_handler) parser->callback_handle = (*parser->_handler)


/******************************* A name hash ********************************/

/* Count hash value for the name of an SshXmlNameHashHeader object. */
static SshUInt32
ssh_xml_name_hash(void *ptr, void *ctx)
{
  SshXmlNameHashHeader item = (SshXmlNameHashHeader) ptr;
  SshUInt32 hash;
  size_t i;

  for (hash = 0, i = 0; i < item->name_len; i++)
    hash = (hash << 5) ^ item->name[i] ^ (hash >> 16) ^ (hash >> 7);

  return hash;
}

/* Compare the names of two SshXmlNameHashHeader objects. */
static int
ssh_xml_name_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshXmlNameHashHeader item1 = (SshXmlNameHashHeader) ptr1;
  SshXmlNameHashHeader item2 = (SshXmlNameHashHeader) ptr2;

  if (item1->name_len != item2->name_len)
    return -1;

  return memcmp(item1->name, item2->name, item1->name_len);
}


SshADTContainer
ssh_xml_name_hash_create(SshXmlParser parser)
{
  return ssh_adt_create_generic(SSH_ADT_BAG,

                                SSH_ADT_HEADER,
                                SSH_ADT_OFFSET_OF(SshXmlNameHashHeaderStruct,
                                                  adt_header),

                                SSH_ADT_HASH,           ssh_xml_name_hash,
                                SSH_ADT_COMPARE,        ssh_xml_name_compare,
                                SSH_ADT_CONTEXT,        parser,

                                SSH_ADT_ARGS_END);
}


/********************** Prototypes for state functions **********************/

SSH_FSM_STEP(ssh_xml_st_start_document);

SSH_FSM_STEP(ssh_xml_st_start);

SSH_FSM_STEP(ssh_xml_st_cdata);
SSH_FSM_STEP(ssh_xml_st_cdata_read);

SSH_FSM_STEP(ssh_xml_st_lt_markup);
SSH_FSM_STEP(ssh_xml_st_lt_exlam_markup);

SSH_FSM_STEP(ssh_xml_st_almost_comment);/* Have already seen `<!-'. */
SSH_FSM_STEP(ssh_xml_st_comment);

SSH_FSM_STEP(ssh_xml_st_section); /* Start of `<![' section. */
SSH_FSM_STEP(ssh_xml_st_section_name);
SSH_FSM_STEP(ssh_xml_st_section_name_read);
SSH_FSM_STEP(ssh_xml_st_section_parsed);

SSH_FSM_STEP(ssh_xml_st_almost_section_end); /* Have already seen `]]'. */

SSH_FSM_STEP(ssh_xml_st_section_cdata);
SSH_FSM_STEP(ssh_xml_st_section_ignore);

SSH_FSM_STEP(ssh_xml_st_decl);  /* Have already seen `<!{Name}'. */
SSH_FSM_STEP(ssh_xml_st_decl_name_read);
SSH_FSM_STEP(ssh_xml_st_decl_parsed);

SSH_FSM_STEP(ssh_xml_st_pi);
SSH_FSM_STEP(ssh_xml_st_pi_name_read);
SSH_FSM_STEP(ssh_xml_st_pi_collect);
SSH_FSM_STEP(ssh_xml_st_pi_cb);

SSH_FSM_STEP(ssh_xml_st_xmldecl);
SSH_FSM_STEP(ssh_xml_st_xmldecl_name_read);
SSH_FSM_STEP(ssh_xml_st_xmldecl_eq);
SSH_FSM_STEP(ssh_xml_st_xmldecl_value);
SSH_FSM_STEP(ssh_xml_st_xmldecl_value_read);
SSH_FSM_STEP(ssh_xml_st_xmldecl_more);

SSH_FSM_STEP(ssh_xml_st_start_tag);
SSH_FSM_STEP(ssh_xml_st_start_tag_name_read);
SSH_FSM_STEP(ssh_xml_st_start_tag_attribute);
SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_name);
SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_name_read);
SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_eq);
SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_value);
SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_value_read);
SSH_FSM_STEP(ssh_xml_st_start_tag_parsed);
SSH_FSM_STEP(ssh_xml_st_start_tag_parsed_cb);

SSH_FSM_STEP(ssh_xml_st_end_tag);
SSH_FSM_STEP(ssh_xml_st_end_tag_name_read);
SSH_FSM_STEP(ssh_xml_st_end_tag_whitespace);
SSH_FSM_STEP(ssh_xml_st_end_tag_parsed_cb);

SSH_FSM_STEP(ssh_xml_st_reference);
SSH_FSM_STEP(ssh_xml_st_reference_read);

SSH_FSM_STEP(ssh_xml_st_xml_doctype);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_name);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_name_read);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_check_external_id);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_external_id_read);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_check_embedded_dtd);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_parsed);
SSH_FSM_STEP(ssh_xml_st_xml_doctype_parsed_cb);

SSH_FSM_STEP(ssh_xml_st_dtd_element);
SSH_FSM_STEP(ssh_xml_st_dtd_element_name);
SSH_FSM_STEP(ssh_xml_st_dtd_element_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_element_content_spec);
SSH_FSM_STEP(ssh_xml_st_dtd_element_content_keyword);
SSH_FSM_STEP(ssh_xml_st_dtd_element_content_expr);
SSH_FSM_STEP(ssh_xml_st_dtd_element_content_expr_end);
SSH_FSM_STEP(ssh_xml_st_dtd_element_content_parsed);
SSH_FSM_STEP(ssh_xml_st_dtd_element_parsed);

SSH_FSM_STEP(ssh_xml_st_dtd_attlist);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_element_name);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_element_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attdef);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_name);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_type);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_type_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_notation);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum_name);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum_more);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_defaultdecl);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_defaultdecl_name);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_default_value);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_default_value_read);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attdef_parsed);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_parsed);
SSH_FSM_STEP(ssh_xml_st_dtd_attlist_parsed_cb);

SSH_FSM_STEP(ssh_xml_st_dtd_entity);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_type);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_def);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_read);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata_name);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata_data);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata_data_read);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter_name);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter_def);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_internal_read);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_external_read);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_parsed);
SSH_FSM_STEP(ssh_xml_st_dtd_entity_parsed_cb);

SSH_FSM_STEP(ssh_xml_st_dtd_notation);
SSH_FSM_STEP(ssh_xml_st_dtd_notation_name);
SSH_FSM_STEP(ssh_xml_st_dtd_notation_name_read);
SSH_FSM_STEP(ssh_xml_st_dtd_notation_id);
SSH_FSM_STEP(ssh_xml_st_dtd_notation_parsed);
SSH_FSM_STEP(ssh_xml_st_dtd_notation_parsed_cb);

SSH_FSM_STEP(ssh_xml_st_error); /* Parsing failed (error already reported). */
SSH_FSM_STEP(ssh_xml_st_end);
SSH_FSM_STEP(ssh_xml_st_end_cb);

/* Sub-state machine for reading a name. */
SSH_FSM_STEP(ssh_xml_st_sub_read_name);
SSH_FSM_STEP(ssh_xml_st_sub_read_nmtoken);
SSH_FSM_STEP(ssh_xml_st_sub_read_name_read_chars);

/* Sub-state machine for skipping mandatory whitespace. */
SSH_FSM_STEP(ssh_xml_st_sub_mandatory_whitespace);

/* Sub-state machine for skipping optional whitespace. */
SSH_FSM_STEP(ssh_xml_st_sub_optional_whitespace);

/* Sub-state machines for reading literal values. */

SSH_FSM_STEP(ssh_xml_st_sub_read_entity_value);
SSH_FSM_STEP(ssh_xml_st_sub_read_attribute_value);
SSH_FSM_STEP(ssh_xml_st_sub_read_system_literal);
SSH_FSM_STEP(ssh_xml_st_sub_read_pubid_literal);

SSH_FSM_STEP(ssh_xml_st_sub_read_literal);
SSH_FSM_STEP(ssh_xml_st_sub_read_literal_chars);
SSH_FSM_STEP(ssh_xml_st_sub_read_literal_reference);
SSH_FSM_STEP(ssh_xml_st_sub_read_literal_reference_value_as_is);

/* Sub-state machine for reading references. */
SSH_FSM_STEP(ssh_xml_st_sub_read_reference);
SSH_FSM_STEP(ssh_xml_st_sub_read_reference_charref);
SSH_FSM_STEP(ssh_xml_st_sub_read_reference_charref_base10);
SSH_FSM_STEP(ssh_xml_st_sub_read_reference_charref_base16);
SSH_FSM_STEP(ssh_xml_st_sub_read_reference_read_chars);

/* Sub-state machine for reading External IDs. */
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_notation);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_name);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_name_read);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_public);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_public_read);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_system);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_system_read);
SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_done);


/****************************** Help functions ******************************/

/* Report a warning or an error `ap' using the handler function
   `func'. */
static void
ssh_xml_notify(SshXmlParser parser, SshXmlInput input,
               void (*func)(SshXmlParser parser, const char *input_name,
                            SshUInt32 line, SshUInt32 column,
                            const char *message, void *context),
               void *func_context,
               va_list ap)
{
  SshBufferStruct buffer;
  char *cp;

  if (!func)
    return;

  ssh_buffer_init(&buffer);

  while ((cp = va_arg(ap, char *)) != NULL)
    if (ssh_buffer_append(&buffer, (unsigned char *) cp, strlen(cp))
        != SSH_BUFFER_OK)
      goto error;





  /* Make the message null-terminated. */
  if (ssh_buffer_append(&buffer, (unsigned char *) "\0", 1) != SSH_BUFFER_OK)
    goto error;

  (*func)(parser, input->name, input->line, input->column,
          (char *) ssh_buffer_ptr(&buffer),
          func_context);

  ssh_buffer_uninit(&buffer);
  return;


  /* Error handling. */

 error:

  SSH_DEBUG(SSH_D_ERROR, ("Out of memory"));
  ssh_buffer_uninit(&buffer);
}


void
ssh_xml_warning(SshXmlParser parser, ...)
{
  va_list ap;

  va_start(ap, parser);
  ssh_xml_notify(parser, parser->input, parser->error_handler.warning,
                 parser->handler_context,
                 ap);
  va_end(ap);
}


void
ssh_xml_error(SshXmlParser parser, ...)
{
  va_list ap;

  va_start(ap, parser);
  ssh_xml_notify(parser, parser->input, parser->error_handler.error,
                 parser->handler_context,
                 ap);
  va_end(ap);
}


void
ssh_xml_fatal_error(SshXmlParser parser, ...)
{
  va_list ap;

  va_start(ap, parser);
  ssh_xml_notify(parser, parser->input, parser->error_handler.fatal_error,
                 parser->handler_context,
                 ap);
  va_end(ap);
}


void
ssh_xml_fatal_error_with_input(SshXmlParser parser, SshXmlInput input, ...)
{
  va_list ap;

  va_start(ap, input);
  ssh_xml_notify(parser, input, parser->error_handler.fatal_error,
                 parser->handler_context,
                 ap);
  va_end(ap);
}

/* A short-cut error handler for reporting an `out-of-memory'
   error. */
static void
ssh_xml_error_out_of_memory(SshXmlParser parser)
{
  if (parser->parse_result != SSH_XML_OK)
    /* We have already reported an error. */
    return;

  ssh_xml_fatal_error(parser, "Out of memory", NULL);
  parser->parse_result = SSH_XML_ERROR_MEMORY;
}

/* A short-cut error handler for reporting a `premature end of file'
   error. */
static void
ssh_xml_error_premature_eof(SshXmlParser parser)
{
  if (parser->parse_result != SSH_XML_OK)
    /* We have already reported an error. */
    return;

  ssh_xml_fatal_error(parser, "Premature end-of-file", NULL);
  parser->parse_result = SSH_XML_ERROR_NOT_WELL_FORMED;
}

/* A short-cut error handler for reporting `not well-formed'
   errors. */
static void
ssh_xml_error_not_well_formed(SshXmlParser parser, ...)
{
  va_list ap;

  if (parser->parse_result != SSH_XML_OK)
    /* We have already reported an error. */
    return;

  va_start(ap, parser);
  ssh_xml_notify(parser, parser->input, parser->error_handler.fatal_error,
                 parser->handler_context,
                 ap);
  va_end(ap);

  parser->parse_result = SSH_XML_ERROR_NOT_WELL_FORMED;
}


void
ssh_xml_value_enum_init(const unsigned char *value, size_t value_len,
                        SshXmlAttrEnumType enum_type,
                        SshXmlAttrEnumCtx enum_ctx)
{
  memset(enum_ctx, 0, sizeof(*enum_ctx));

  enum_ctx->value = value;
  enum_ctx->value_len = value_len;
  enum_ctx->type = enum_type;
}


Boolean
ssh_xml_value_enum_next_char(SshXmlAttrEnumCtx enum_ctx,
                             SshXmlChar *char_return)
{
  SshUInt32 ch;

  if (enum_ctx->pos >= enum_ctx->value_len)
    return FALSE;

  ch = enum_ctx->value[enum_ctx->pos++];
  if (ch >= 0x80)
    {
      SshUInt32 ch2;
      int utf8size, i;

      /* Bigger than a single character.  Determine its size. */

      ch2 = ch;
      for (utf8size = 0;
           utf8size < 8 && ((ch2 << utf8size) & 0x80) != 0;
           utf8size++)
        ;

      if (utf8size < 2 || utf8size > 6)
        {
          enum_ctx->invalid = 1;
          return FALSE;
        }

      /* Mask out extra bits and roll the first byte to the correct
         position. */
      ch = (ch & (0x7f >> utf8size)) << (6 * (utf8size - 1));

      /* Read consecutive bytes that make up the UCS4 character */

      for (i = utf8size - 2; i >= 0; i--)
        {
          if (enum_ctx->pos >= enum_ctx->value_len)
            {
              enum_ctx->invalid = 1;
              return FALSE;
            }
          ch2 = enum_ctx->value[enum_ctx->pos++];
          if ((ch2 & 0xc0) != 0x80)
            {
              enum_ctx->invalid = 1;
              return FALSE;
            }
          ch |= (ch2 & 0x3f) << (6 * i);
        }
    }

  *char_return = ch;

  return TRUE;
}


unsigned char *
ssh_xml_intern(SshXmlParser parser, const unsigned char *name, size_t name_len)
{
  SshXmlNameHashHeaderStruct header_struct;
  SshXmlNameHashHeader header;
  SshADTHandle h;

  /* Do we already know this item? */

  memset(&header_struct, 0, sizeof(header_struct));
  header_struct.name = (unsigned char *) name;
  header_struct.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(parser->interned_names, &header_struct);
  if (h == SSH_ADT_INVALID)
    {
      /* Intern the name. */
      header = ssh_calloc(1, sizeof(*header));
      if (header == NULL)
        return NULL;

      header->name = ssh_memdup(name, name_len);
      if (header->name == NULL)
        {
          ssh_free(header);
          return NULL;
        }
      header->name_len = name_len;

      (void) ssh_adt_insert(parser->interned_names, header);
    }
  else
    header = ssh_adt_get(parser->interned_names, h);

  /* Return the interned name. */
  return header->name;
}

/* Free the attribute structure `attr'. */
static void
ssh_xml_attribute_free(SshXmlAttribute attr)
{
  ssh_free(attr->value);
  ssh_free(attr);
}

/* Free the element attributes `attributes'. */
void
ssh_xml_attributes_free(SshADTContainer attributes)
{
  SshADTHandle h;

  if (attributes == NULL)
    return;

  while ((h = ssh_adt_enumerate_start(attributes)) != SSH_ADT_INVALID)
    {
      SshXmlAttribute attr = ssh_adt_get(attributes, h);

      ssh_adt_delete(attributes, h);
      ssh_xml_attribute_free(attr);
    }

  ssh_adt_destroy(attributes);
}

/* Free the element structure `element'. */
static void
ssh_xml_element_free(SshXmlElement element)
{
  /* Free namespace declarations. */
  while (element->namespaces)
    {
      SshXmlNamespace ns = element->namespaces;

      element->namespaces = ns->next;
      ssh_free(ns);
    }

  /* Free attributes. */
  ssh_xml_attributes_free(element->attributes);

  ssh_free(element);
}

/* Free the entity structure `entity'. */
static void
ssh_xml_entity_free(SshXmlParser parser, SshXmlEntity entity)
{
  if (entity->internal)
    {
      ssh_free(entity->value.internal.data);
    }
  else
    {
      ssh_free(entity->value.external.pubid);
      ssh_free(entity->value.external.sysid);
      ssh_free(entity->value.external.ndata);
    }

  ssh_free(entity->where_defined);
  ssh_free(entity);
}


void
ssh_xml_clear_entities(SshXmlParser parser, SshADTContainer bag,
                       Boolean clear_all)
{
  SshADTHandle h, hnext;

  for (h = ssh_adt_enumerate_start(bag);
       h;
       h = hnext)
    {
      SshXmlEntity entity;

      hnext = ssh_adt_enumerate_next(bag, h);

      entity = ssh_adt_get(bag, h);
      if (entity->predefined && !clear_all)
        continue;

      ssh_adt_delete(bag, h);
      ssh_xml_entity_free(parser, entity);
    }
}


void
ssh_xml_attribute_definitions_free(SshXmlParser parser, SshADTContainer bag)
{
  SshADTHandle h;

  if (bag == NULL)
    return;

  while ((h = ssh_adt_enumerate_start(bag)) != SSH_ADT_INVALID)
    {
      SshXmlAttributeDefinition attdef = ssh_adt_get(bag, h);

      /* Remove it from the bag. */
      ssh_adt_delete(bag, h);

      /* Free the fields of the definition structure and the
         structure. */

      /* Free enumeration arrays. */
      ssh_free(attdef->enums);
      ssh_free(attdef->enum_lens);

      ssh_free(attdef->value);
      ssh_free(attdef);
    }

  /* And finally, destroy the ADT bag. */
  ssh_adt_destroy(bag);
}


void
ssh_xml_steal_attribute_definitions(SshXmlParser parser)
{
  SSH_ASSERT(parser->attribute_definitions != NULL);
  parser->attribute_definitions = NULL;
}


void
ssh_xml_steal_attributes(SshXmlParser parser)
{
  SSH_ASSERT(parser->parse_tree != NULL);
  parser->parse_tree->attributes = NULL;
}


SshXmlAttributeDefinition
ssh_xml_lookup_attribute_definitions(SshADTContainer bag,
                                     const unsigned char *name,
                                     size_t name_len)
{
  SshXmlAttributeDefinitionStruct attdef_struct;
  SshADTHandle h;

  memset(&attdef_struct, 0, sizeof(attdef_struct));
  attdef_struct.header.name = (unsigned char *) name;
  attdef_struct.header.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(bag, &attdef_struct);
  if (h == SSH_ADT_INVALID)
    return NULL;

  return ssh_adt_get(bag, h);
}


/* Stream callback for the input streams being parsed. */
static void
ssh_xml_stream_callback(SshStreamNotification notification, void *context)
{
  SshXmlParser parser = (SshXmlParser) context;

  /* Simply signal the I/O condition. */
  ssh_fsm_condition_signal(&parser->fsm, &parser->io_cond);
}

/* Prepares the parser to process the current input encoding that is
   already set into the parser.  The function returns TRUE if the
   input encoding was selected and FALSE otherwise. */
static Boolean
ssh_xml_select_input_encoding(SshXmlParser parser)
{
  SSH_ASSERT(parser->input != NULL);

  /* Free old supporting modules. */
  if (parser->chr_conv)
    {
      ssh_charset_free(parser->chr_conv);
      parser->chr_conv = NULL;
    }

  /* Select new supporting module. */
  switch (parser->input->encoding)
    {
    case SSH_XML_INPUT_ENC_UNKNOWN:
      /* Nothing here. */
      break;

    case SSH_XML_INPUT_ENC_UTF_8:
      parser->chr_conv = ssh_charset_init(SSH_CHARSET_UTF8,
                                          SSH_CHARSET_UNICODE32);
      if (parser->chr_conv == NULL)
        return FALSE;
      break;

    case SSH_XML_INPUT_ENC_UCS_4_BE:
    case SSH_XML_INPUT_ENC_UCS_4_LE:
    case SSH_XML_INPUT_ENC_UCS_4_2143:
    case SSH_XML_INPUT_ENC_UCS_4_3412:
      /* Nothing here. */
      break;

    case SSH_XML_INPUT_ENC_ISO_8859_1:
    case SSH_XML_INPUT_ENC_US_ASCII:
      /* Nothing here. */
      break;

    case SSH_XML_INPUT_ENC_UTF_16_BE:
    case SSH_XML_INPUT_ENC_UTF_16_LE:
      /* Nothing here. */
      break;
    }

  return TRUE;
}

/* Push the input stream `stream' to the top of the input stream
   stack. */
static Boolean
ssh_xml_push_input_stream(SshXmlParser parser, SshStream stream,
                          const char *stream_name,
                          SshXmlInputEncoding encoding,
                          SshXmlDestructorCB destructor_cb,
                          void *destructor_cb_context)
{
  SshXmlInput input;

  if (parser->input_stack_depth > 32)
    {
      ssh_xml_error_not_well_formed(parser,
                                    "Too deep recursion in input stack",
                                    NULL);
      return FALSE;
    }

  input = ssh_calloc(1, sizeof(*input));
  if (input == NULL)
    return FALSE;

  if (stream_name == NULL)
    stream_name = "<Unknown>";
  input->name = ssh_strdup(stream_name);
  if (input->name == NULL)
    {
      ssh_free(input);
      return FALSE;
    }

  input->stream = stream;
  input->destructor_cb = destructor_cb;
  input->destructor_cb_context = destructor_cb_context;
  input->line = 1;
  input->encoding = encoding;

  /* Link it to the head of the parser's input stream stack. */
  input->next = parser->input;
  parser->input = input;

  /* Select the new input encoding. */
  if (!ssh_xml_select_input_encoding(parser))
    {
      parser->input = input->next;
      ssh_free(input->name);
      ssh_free(input);
      return FALSE;
    }

  /* Set notification callback for the stream. */
  ssh_stream_set_callback(stream, ssh_xml_stream_callback, parser);

  parser->input_stack_depth++;

  return TRUE;
}

/* Pop the top-most input stream from the stack of input streams in
   the parser `parser'.  The input stream stack must not be empty. */
static Boolean
ssh_xml_pop_input_stream(SshXmlParser parser)
{
  SshXmlInput input;

  SSH_ASSERT(parser->input != NULL);

  input = parser->input;
  parser->input = input->next;

  parser->input_stack_depth--;

  ssh_free(input->name);
  ssh_stream_destroy(input->stream);

  if (input->destructor_cb)
    (*input->destructor_cb)(input->destructor_cb_context);

  ssh_free(input);

  /* Select the input encoding if we still have input frames. */
  if (parser->input && !ssh_xml_select_input_encoding(parser))
    return FALSE;

  return TRUE;
}

/* Push a new lexer frame to the top of the lexer stack of the parser
   `parser'.  The function returns TRUE if the frame was pushed and
   FALSE if the system run out of memory. */
static Boolean
ssh_xml_push_lexer_frame(SshXmlParser parser)
{
  SshXmlLexer lexer;

  lexer = ssh_calloc(1, sizeof(*lexer));
  if (lexer == NULL)
    return FALSE;

  /* Link the new lexer frame into parser's lexer stack. */
  lexer->next = parser->lexer;
  parser->lexer = lexer;

  return TRUE;
}

/* Pop the top-most lexer frame of the lexer stack of the parser
   `parser'.  The lexer stack must not be empty. */
static void
ssh_xml_pop_lexer_frame(SshXmlParser parser)
{
  SshXmlLexer lexer;

  SSH_ASSERT(parser->lexer != NULL);

  lexer = parser->lexer;
  parser->lexer = lexer->next;

  ssh_free(lexer->data);
  ssh_free(lexer);
}

/* Push an element to the parse tree.  The arguments `name',
   `name_len' specify the name of the element. */
static Boolean
ssh_xml_push_element(SshXmlParser parser, unsigned char *name, size_t name_len)
{
  SshXmlElement element;

  element = ssh_calloc(1, sizeof(*element));
  if (element == NULL)
    return FALSE;

  /* Store the element name. */
  element->name = ssh_xml_intern(parser, name, name_len);
  if (element->name == NULL)
    goto error;

  element->name_len = name_len;

  element->attributes = ssh_xml_name_hash_create(parser);
  if (element->attributes == NULL)
    goto error;

  /* Link the new element to the parse tree. */
  element->next = parser->parse_tree;
  parser->parse_tree = element;

  /* All done. */
  return TRUE;


  /* Error handling. */

 error:

  ssh_xml_element_free(element);

  return FALSE;
}

/* Pop an element from the parser's parse tree. */
static void
ssh_xml_pop_element(SshXmlParser parser)
{
  SshXmlElement element = parser->parse_tree;

  SSH_ASSERT(element != NULL);

  parser->parse_tree = element->next;

  ssh_xml_element_free(element);
}


SshXmlAttribute
ssh_xml_insert_attribute(SshXmlParser parser, SshADTContainer bag,
                         const unsigned char *name, size_t name_len,
                         Boolean *unique_return)
{
  SshXmlAttributeStruct attr_struct;
  SshXmlAttribute attr = NULL;
  SshADTHandle h;

  *unique_return = TRUE;

  /* Do we know this attribute. */

  memset(&attr_struct, 0, sizeof(attr_struct));
  attr_struct.header.name = (unsigned char *) name;
  attr_struct.header.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(bag, &attr_struct);
  if (h != SSH_ADT_INVALID)
    {
      /* The name already exists. */
      *unique_return = FALSE;
      return ssh_adt_get(bag, h);
    }

  /* The attribute is unknown.  Let's add it now. */

  attr = ssh_calloc(1, sizeof(*attr));
  if (attr == NULL)
    goto error;

  attr->header.name = ssh_xml_intern(parser, name, name_len);
  if (attr->header.name == NULL)
    goto error;

  attr->header.name_len = name_len;

  /* Insert the attribute into the bag. */
  (void) ssh_adt_insert(bag, attr);

  /* All done. */
  return attr;


  /* Error handling. */

 error:

  if (attr)
    ssh_xml_attribute_free(attr);

  return NULL;
}


SshXmlAttribute
ssh_xml_lookup_attribute(SshADTContainer bag, const unsigned char *name,
                         size_t name_len)
{
  SshXmlAttributeStruct attr_struct;
  SshADTHandle h;

  /* Check if we know it. */
  memset(&attr_struct, 0, sizeof(attr_struct));
  attr_struct.header.name = (unsigned char *) name;
  attr_struct.header.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(bag, &attr_struct);
  if (h == SSH_ADT_INVALID)
    return NULL;

  return ssh_adt_get(bag, h);
}


SshXmlEntity
ssh_xml_insert_entity(SshXmlParser parser, SshADTContainer bag,
                      const char *input_stream_name,
                      Boolean general, const unsigned char *name,
                      size_t name_len, Boolean *unique_return)
{
  SshXmlEntityStruct entity_struct;
  SshXmlEntity entity = NULL;
  SshADTHandle h;

  *unique_return = TRUE;

  /* Do we know this entity. */

  memset(&entity_struct, 0, sizeof(entity_struct));
  entity_struct.header.name = (unsigned char *) name;
  entity_struct.header.name_len = name_len;

  h = ssh_adt_get_handle_to_equal(bag, &entity_struct);
  if (h != SSH_ADT_INVALID)
    {
      /* The name already exists. */
      *unique_return = FALSE;
      return ssh_adt_get(bag, h);
    }

  /* The entity is unknown.  Let's add it now. */

  entity = ssh_calloc(1, sizeof(*entity));
  if (entity == NULL)
    goto error;

  if (general)
    entity->general = 1;

  entity->header.name = ssh_xml_intern(parser, name, name_len);
  if (entity->header.name == NULL)
    goto error;

  /* Store the name of the defining stream. */
  if (input_stream_name)
    {
      entity->where_defined = ssh_strdup(input_stream_name);
      if (entity->where_defined == NULL)
        goto error;
    }

  entity->header.name_len = name_len;

  /* Insert the entity into the bag. */
  (void) ssh_adt_insert(bag, entity);

  /* All done. */
  return entity;


  /* Error handling. */

 error:

  if (entity)
    ssh_xml_entity_free(parser, entity);

  return NULL;
}

/* Clear all dynamic state from the parser `parser'.  If the argument
   `clear_all' is TRUE, the all resources (also predefined entities)
   will be freed.  Otherwise, the function clear the parser into the
   same state in which it is after ssh_xml_parser_create() call. */
static void
ssh_xml_parser_clear(SshXmlParser parser, Boolean clear_all)
{
  if (parser == NULL)
    return;

  /* Clear stacks. */
  while (parser->input)
    (void) ssh_xml_pop_input_stream(parser);
  while (parser->lexer)
    ssh_xml_pop_lexer_frame(parser);
  while (parser->parse_tree)
    ssh_xml_pop_element(parser);

  /* Clear input encoding supporting modules. */
  if (parser->chr_conv)
    {
      ssh_charset_free(parser->chr_conv);
      parser->chr_conv = NULL;
    }

  /* Clear possible PEReference name collection. */
  if (parser->pereference)
    {
      ssh_free(parser->pereference->data);
      ssh_free(parser->pereference);
      parser->pereference = NULL;
    }

  /* Interned names. */
  if (clear_all && (parser->interned_names != NULL))
    {
      SshADTHandle h;

      while ((h = ssh_adt_enumerate_start(parser->interned_names))
             != SSH_ADT_INVALID)
        {
          SshXmlNameHashHeader header = ssh_adt_get(parser->interned_names, h);

          ssh_adt_delete(parser->interned_names, h);
          ssh_free(header->name);
          ssh_free(header);
        }
    }

  /* Clear general entities. */
  if (parser->general_entities)
    ssh_xml_clear_entities(parser, parser->general_entities, clear_all);

  /* Clear Parameter entities. */
  if (parser->parameter_entities)
    ssh_xml_clear_entities(parser, parser->parameter_entities, clear_all);

  /* Clear possible attribute definition bag. */
  ssh_xml_attribute_definitions_free(parser, parser->attribute_definitions);
  parser->attribute_definitions = NULL;

  /* Clear temporary data blocks. */

  ssh_free(parser->data1);
  parser->data1 = NULL;
  parser->data1_len = 0;

  ssh_free(parser->data2);
  parser->data2 = NULL;
  parser->data2_len = 0;

  ssh_free(parser->data3);
  parser->data3 = NULL;
  parser->data3_len = 0;

  /* Notify our user (next-level parser in chained parsers) that we
     are done. */
  if (parser->parse_done_cb)
    (*parser->parse_done_cb)(parser, parser->handler_context);
}

/* Append character `ch' into token buffer of the lexer frame `lexer'.
   The function returns TRUE if the operation was successful or FALSE
   if the system run out of memory. */
static Boolean
ssh_xml_append(SshXmlParser parser, SshXmlLexer lexer, SshXmlChar ch)
{
  SshUInt32 ibuf = (SshUInt32) ch;
  unsigned char buf[6];
  size_t len;

  SSH_ASSERT(lexer != NULL);

  /* Convert character into UTF-8. */
  len = ssh_charset_convert(parser->output_conv, &ibuf, sizeof(ibuf),
                            buf, sizeof(buf));

  if (lexer->data_len + len + 1 > lexer->data_allocated)
    {
      unsigned char *data;

      /* Realloc data buffer. */
      data = ssh_realloc(lexer->data, lexer->data_allocated,
                         lexer->data_len + len + 128);
      if (data == NULL)
        return FALSE;

      lexer->data = data;
      lexer->data_allocated = lexer->data_len + len + 128;
    }
  SSH_ASSERT(lexer->data_len + len + 1 <= lexer->data_allocated);

  memcpy(lexer->data + lexer->data_len, buf, len);
  lexer->data_len += len;

  /* The data is always null-terminated.  And we allocated space for
     the trailing null-character above. */
  lexer->data[lexer->data_len] = '\0';

  return TRUE;
}

/* A callback function that is called to complete a parameter entity
   resolving. */
static void
ssh_xml_resolve_parameter_entity_cb(SshStream stream, const char *stream_name,
                                    SshXmlDestructorCB destructor_cb,
                                    void *destructor_cb_context,
                                    void *context)
{
  SshXmlParser parser = (SshXmlParser) context;
  SshStream space_stream;
  SshXmlEntityStruct entity_struct;
  SshXmlEntity entity;
  SshADTHandle h;

  SSH_DEBUG(SSH_D_MIDOK, ("Callback called"));

  /* This completes the handler call. */
  parser->callback_handle = NULL;

  if (stream == NULL)
    {
      /* The callback failed to provide the value.  Let's see if we
         know it. */

      SSH_ASSERT(parser->pereference != NULL);
      memset(&entity_struct, 0, sizeof(entity_struct));
      entity_struct.header.name = parser->pereference->data;
      entity_struct.header.name_len = parser->pereference->data_len;

      h = ssh_adt_get_handle_to_equal(parser->parameter_entities,
                                      &entity_struct);
      if (h == SSH_ADT_INVALID)
        {
        unknown_entity:
          ssh_xml_warning(parser, "Unknown parameter entity `",
                          parser->pereference->data, "'", NULL);
          goto out;
        }

      /* We know its value. */

      entity = ssh_adt_get(parser->parameter_entities, h);
      if (!entity->internal)
        goto unknown_entity;

      /* Create an input stream. */
      destructor_cb = NULL_FNPTR;
      destructor_cb_context = NULL;
      stream = ssh_data_stream_create(entity->value.internal.data,
                                      entity->value.internal.data_len,
                                      TRUE);
      if (stream == NULL)
        {
          /* Could not create stream. */
          ssh_xml_error_out_of_memory(parser);
          goto out;
        }

      /* FALLTHROUGH. */
    }

  /* Got the stream.  Push it as a new input stream to the parser's
     input stream stack. */

  /* Add one space character before and after the value, unless the
     parameter reference was in a literal value. */
  if (!parser->in_literal)
    {
      space_stream = ssh_data_stream_create((unsigned char *) " ", 1, TRUE);
      if (space_stream == NULL)
        {
        error_memory:
          ssh_stream_destroy(stream);
          if (destructor_cb)
            (*destructor_cb)(destructor_cb_context);

          ssh_xml_error_out_of_memory(parser);
          goto out;
        }
      if (!ssh_xml_push_input_stream(parser, space_stream, "<SpaceStream>",
                                     SSH_XML_INPUT_ENC_ISO_8859_1,
                                     NULL_FNPTR, NULL))
        {
          ssh_stream_destroy(space_stream);
          goto error_memory;
        }
    }

  /* Set a default name for the input stream if it is not provided by
     our caller. */
  if (stream_name == NULL)
    stream_name = "<ParameterEntity>";

  /* Push the result stream. */
  if (!ssh_xml_push_input_stream(parser, stream, stream_name,
                                 SSH_XML_INPUT_ENC_UNKNOWN,
                                 destructor_cb, destructor_cb_context))
    goto error_memory;

  /* And the trailing space character. */
  if (!parser->in_literal)
    {
      space_stream = ssh_data_stream_create((unsigned char *) " ", 1, TRUE);
      if (space_stream == NULL)
        {
          /* The result stream is already pushed in the input
             stack.  It will be destroyed when the parser is
             destroyed in the error handler. */
          ssh_xml_error_out_of_memory(parser);
          goto out;
        }
      if (!ssh_xml_push_input_stream(parser, space_stream, "<SpaceStream>",
                                     SSH_XML_INPUT_ENC_ISO_8859_1,
                                     NULL_FNPTR, NULL))
        {
          ssh_stream_destroy(space_stream);
          goto out;
        }
    }

 out:

  /* Clear pereference since we do not need it anymore. */
  ssh_free(parser->pereference->data);
  ssh_free(parser->pereference);
  parser->pereference = NULL;

  /* Check if this was a synchronous or an asynchronous callback. */
  if (parser->peref_flag)
    {
      /* Synchronous.  Let's clear the flag to indicate that we are
         already called. */
      SSH_DEBUG(SSH_D_MIDOK, ("Synchronous callback"));
      parser->peref_flag = 0;

      /* Our caller will continue computation. */
    }
  else
    {
      /* Asynchronous.  Let's wake up the parser thread. */
      SSH_DEBUG(SSH_D_MIDOK, ("Asynchronous callback"));
      parser->blocked = 0;
      ssh_fsm_condition_signal(&parser->fsm, &parser->io_cond);
    }
}

/* A callback function that is called to complete an entity
   resolving. */
static void
ssh_xml_resolve_entity_cb(SshStream stream, const char *stream_name,
                          SshXmlDestructorCB destructor_cb,
                          void *destructor_cb_context, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshXmlParser parser = (SshXmlParser) ssh_fsm_get_tdata(thread);
  SshXmlEntityStruct entity_struct;
  SshXmlEntity entity;
  SshADTHandle h;
  SshADTContainer bag;

  SSH_DEBUG(SSH_D_MIDOK, ("Callback called"));

  /* This completes the handler call. */
  parser->callback_handle = NULL;

  if (stream == NULL)
    {
      /* Let's see if we know its value. */

      SSH_ASSERT(parser->lexer != NULL);
      memset(&entity_struct, 0, sizeof(entity_struct));
      entity_struct.header.name = parser->lexer->data;
      entity_struct.header.name_len = parser->lexer->data_len;

      if (parser->general_entity)
        bag = parser->general_entities;
      else
        bag = parser->parameter_entities;

      h = ssh_adt_get_handle_to_equal(bag, &entity_struct);
      if (h == SSH_ADT_INVALID)
        {
          /* This is an unknown entity.  Its refernces will be
             replaced with an empty string. */
          ssh_xml_warning(parser, "Unknown ",
                          parser->general_entity ? "general" : "parameter",
                          " entity", NULL);
          goto out;
        }

      /* We know its value. */

      entity = ssh_adt_get(bag, h);
      if (!entity->internal)
        {
          /* We can't handle external entities so this is an unknown
             entity. */
          ssh_xml_warning(parser, "Unknown ",
                          parser->general_entity ? "general" : "parameter",
                          " entity", NULL);
          goto out;
        }

      /* Create an input stream. */
      destructor_cb = NULL_FNPTR;
      destructor_cb_context = NULL;
      stream = ssh_data_stream_create(entity->value.internal.data,
                                      entity->value.internal.data_len,
                                      TRUE);
      if (stream == NULL)
        {
          /* Could not create stream. */
          ssh_xml_error_out_of_memory(parser);
          goto error;
        }

      /* FALLTHROUGH. */
    }

  /* Set a default name for the input stream if it is not provided by
     our caller. */
  if (stream_name == NULL)
    {
      if (parser->general_entity)
        stream_name = "<GeneralEntity>";
      else
        stream_name = "<ParameterEntity>";
    }

  /* Push a new input stream. */
  if (!ssh_xml_push_input_stream(parser, stream, stream_name,
                                 SSH_XML_INPUT_ENC_UNKNOWN,
                                 destructor_cb, destructor_cb_context))
    {
      ssh_stream_destroy(stream);
      if (destructor_cb)
        (*destructor_cb)(destructor_cb_context);

      ssh_xml_error_out_of_memory(parser);
      goto error;
    }

  /* Mark the type of the expansion stream. */

  if (parser->general_entity)
    parser->input->general_entity = 1;
  else
    parser->input->parameter_entity = 1;

  if (parser->in_literal)
    parser->input->from_literal = 1;

  /* All done. */
 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);

  return;


  /* Error handling. */

error:

  SSH_FSM_SET_NEXT(ssh_xml_st_error);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Resolve the entity `name'. */
static void
ssh_xml_resolve_entity(SshXmlParser parser, Boolean general,
                       unsigned char *name, size_t name_len,
                       SshXmlStreamCB callback, void *context)
{
  SshXmlEntityStruct entity_struct;
  SshXmlEntity entity;
  SshADTHandle h;
  SshADTContainer bag;
  char *where_defined = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("Resolving entity `%s'", name));

  /* Check if we know the entity. */

  memset(&entity_struct, 0, sizeof(entity_struct));
  entity_struct.header.name = name;
  entity_struct.header.name_len = name_len;

  if (general)
    bag = parser->general_entities;
  else
    bag = parser->parameter_entities;

  h = ssh_adt_get_handle_to_equal(bag, &entity_struct);
  if (h != SSH_ADT_INVALID)
    {
      /* We know it. */
      entity = ssh_adt_get(bag, h);
      where_defined = entity->where_defined;

      /* Handle pre-defined entities now. */
      if (entity->predefined)
        {
          /* Call the entity resolving callback indicating error.  The
             callback will the fetch the entity and return its
             value. */
          (*callback)(NULL, NULL, NULL_FNPTR, NULL, context);
          return;
        }
      /* FALLTHROUGH. */
    }

  /* Call user-callback.*/
  if (parser->entity_resolver)
    SSH_XML_HANDLER(entity_resolver)(parser, where_defined, general,
                                     name, name_len,
                                     NULL, 0, NULL, 0,
                                     callback, context,
                                     parser->handler_context);
  else
    (*callback)(NULL, NULL, NULL_FNPTR, NULL, context);
}

/* Decode one character from the current input stream of the parser
   `parser'.  The function returns TRUE if a character (or an EOF)
   could be decoded and FALSE if there is not enough input currently
   available.  The character is returned in `ch_return' and the
   argument `eof_return' is set to TRUE if the end-of-file was
   reached. */
static Boolean
ssh_xml_input_decode(SshXmlParser parser, SshXmlChar *ch_return,
                     Boolean *eof_return)
{
  SshXmlChar ch, ch2;
  size_t len;
  int result;
  unsigned char *ucp;

  *eof_return = FALSE;

  if (parser->input->ungetch_valid)
    {
      *ch_return = parser->input->ungetch;
      parser->input->ungetch_valid = 0;
      return TRUE;
    }

  while (1)
    {
      /* Compute how much we have input data. */
      len = parser->input->data_in_buf - parser->input->bufpos;
      ucp = parser->input->buf + parser->input->bufpos;

      /* Try to decode the next character from the already buffered data. */
      switch (parser->input->encoding)
        {
        case SSH_XML_INPUT_ENC_UNKNOWN:
          /* We don't know yet the input encoding.  Let's see if we
             have any data from which we can try to resolve the input
             encoding. */
          if (len >= 4)
            {
              size_t prefix_len = 0;

              /* We have enough data. */
              if (memcmp(ucp, ssh_custr("\x00\x00\xfe\xff"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_BE;
                  prefix_len = 4;
                }
              else if (memcmp(ucp, ssh_custr("\xff\xfe\x00\x00"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_LE;
                  prefix_len = 4;
                }
              else if (memcmp(ucp, ssh_custr("\x00\x00\xff\xfe"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_2143;
                  prefix_len = 4;
                }
              else if (memcmp(ucp, ssh_custr("\xfe\xff\x00\x00"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_3412;
                  prefix_len = 4;
                }
              else if (memcmp(ucp, ssh_custr("\xfe\xff"), 2) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_16_BE;
                  prefix_len = 2;
                }
              else if (memcmp(ucp, ssh_custr("\xff\xfe"), 2) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_16_LE;
                  prefix_len = 2;
                }
              else if (memcmp(ucp, ssh_custr("\xef\xbb\xbf"), 2) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_8;
                  prefix_len = 3;
                }
              else if (memcmp(ucp, ssh_custr("\x00\x00\x00\x3c"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_BE;
                }
              else if (memcmp(ucp, ssh_custr("\x3c\x00\x00\x00"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_LE;
                }
              else if (memcmp(ucp, ssh_custr("\x00\x00\x3c\x00"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_2143;
                }
              else if (memcmp(ucp, ssh_custr("\x00\x3c\x00\x00"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UCS_4_3412;
                }
              else if (memcmp(ucp, ssh_custr("\x00\x3c\x00\x3f"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_16_BE;
                }
              else if (memcmp(ucp, ssh_custr("\x3c\x00\x3f\x00"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_16_LE;
                }
              else if (memcmp(ucp, ssh_custr("\x3c\x3f\x78\x6d"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_8;
                }
#if 0
              else if (memcmp(ucp, ssh_custr("\x4c\x6f\xa7\x94"), 4) == 0)
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_EBCDIC;
                }
#endif /* 0 */
              else
                {
                  parser->input->encoding = SSH_XML_INPUT_ENC_UTF_8;
                }

              /* Consume the prefix. */
              parser->input->bufpos += prefix_len;

              /* Select the new input encoding and continue decoding
                 our input stream. */
              if (!ssh_xml_select_input_encoding(parser))
                {
                  /* Out of memory. */
                  *eof_return = TRUE;
                  return TRUE;
                }
              continue;
            }
          break;

        case SSH_XML_INPUT_ENC_UTF_8:
          SSH_ASSERT(parser->chr_conv != NULL);
          len = ssh_charset_convert(parser->chr_conv, ucp, len, &ch,
                                    sizeof(SshXmlChar));
          /* Update how many bytes were consumed. */
          parser->input->bufpos
            += ssh_charset_input_consumed(parser->chr_conv);

          /* Did we got a character? */
          if (len == sizeof(SshXmlChar))
            {
              /* Yes we did. */
              *ch_return = ch;
              goto got_character;
            }
          /* Read more input. */
          break;

        case SSH_XML_INPUT_ENC_UTF_16_BE:
          if (len >= 2)
            {
              ch = ucp[0];
              ch <<= 8;
              ch |= ucp[1];

              if (ch < 0xd800 || ch > 0xdfff)
                {
                  /* It was encoded as single 16-bit integer. */
                  *ch_return = ch;
                  parser->input->bufpos += 2;
                  goto got_character;
                }
              if (0xd800 <= ch && ch <= 0xdbff)
                {
                  if (len >= 4)
                    {
                      ch2 = ucp[2];
                      ch2 <<= 8;
                      ch2 |= ucp[3];

                      if (0xdc00 <= ch2 && ch2 <= 0xdfff)
                        {
                          /* It was encoded as two 16-bit integers. */
                          *ch_return = (((ch & 0x3ff) << 10)
                                        | (ch2 & 0x3ff));
                          parser->input->bufpos += 4;
                          goto got_character;
                        }
                    }
                  /* Read more input. */
                }
              else
                {
                  /* Invalid input sequence. */
                  *ch_return = 0xffffffff;
                  goto got_character;
                }
            }
          /* Read more. */
          break;

        case SSH_XML_INPUT_ENC_UTF_16_LE:
          if (len >= 2)
            {
              ch = ucp[1];
              ch <<= 8;
              ch |= ucp[0];

              if (ch < 0xd800 || ch > 0xdfff)
                {
                  /* It was encoded as single 16-bit integer. */
                  *ch_return = ch;
                  parser->input->bufpos += 2;
                  goto got_character;
                }
              if (0xd800 <= ch && ch <= 0xdbff)
                {
                  if (len >= 4)
                    {
                      ch2 = ucp[3];
                      ch2 <<= 8;
                      ch2 |= ucp[2];

                      if (0xdc00 <= ch2 && ch2 <= 0xdfff)
                        {
                          /* It was encoded as two 16-bit integers. */
                          *ch_return = (((ch & 0x3ff) << 10)
                                        | (ch2 & 0x3ff));
                          parser->input->bufpos += 4;
                          goto got_character;
                        }
                    }
                  /* Read more input. */
                }
              else
                {
                  /* Invalid input sequence. */
                  *ch_return = 0xffffffff;
                  goto got_character;
                }
            }
          /* Read more. */
          break;

        case SSH_XML_INPUT_ENC_UCS_4_BE:
          if (len >= 4)
            {
              ch = ucp[0];
              ch <<= 8;
              ch |= ucp[1];
              ch <<= 8;
              ch |= ucp[2];
              ch <<= 8;
              ch |= ucp[3];
              *ch_return = ch;
              parser->input->bufpos += 4;
              goto got_character;
            }
          break;

        case SSH_XML_INPUT_ENC_UCS_4_LE:
          if (len >= 4)
            {
              ch = ucp[3];
              ch <<= 8;
              ch |= ucp[2];
              ch <<= 8;
              ch |= ucp[1];
              ch <<= 8;
              ch |= ucp[0];
              *ch_return = ch;
              parser->input->bufpos += 4;
              goto got_character;
            }
          break;

        case SSH_XML_INPUT_ENC_UCS_4_2143:
          if (len >= 4)
            {
              ch = ucp[1];
              ch <<= 8;
              ch |= ucp[0];
              ch <<= 8;
              ch |= ucp[3];
              ch <<= 8;
              ch |= ucp[2];
              *ch_return = ch;
              parser->input->bufpos += 4;
              goto got_character;
            }
          break;

        case SSH_XML_INPUT_ENC_UCS_4_3412:
          if (len >= 4)
            {
              ch = ucp[2];
              ch <<= 8;
              ch |= ucp[3];
              ch <<= 8;
              ch |= ucp[0];
              ch <<= 8;
              ch |= ucp[1];
              *ch_return = ch;
              parser->input->bufpos += 4;
              goto got_character;
            }
          break;

        case SSH_XML_INPUT_ENC_ISO_8859_1:
        case SSH_XML_INPUT_ENC_US_ASCII:
          if (len)
            {
              /* Got one character. */
              *ch_return = ucp[0];
              parser->input->bufpos++;
              goto got_character;
            }
          break;
        }

      /* Move existing data to the beginning of the buffer. */
      if (len)
        memmove(parser->input->buf, parser->input->buf + parser->input->bufpos,
                len);

      parser->input->data_in_buf = len;
      parser->input->bufpos = 0;

      /* Read more data. */
      result = ssh_stream_read(parser->input->stream,
                               parser->input->buf + len,
                               sizeof(parser->input->buf) - len);
      if (result < 0)
        {
          /* Would block. */
          return FALSE;
        }
      else if (result == 0)
        {
          /* EOF encountered. */
          /* Have we yet resolved our input encoding? */
          if (parser->input->encoding == SSH_XML_INPUT_ENC_UNKNOWN)
            {
              /* Select it now and restart. */
              parser->input->encoding = SSH_XML_INPUT_ENC_UTF_8;
              if (!ssh_xml_select_input_encoding(parser))
                {
                  /* Out of memory. */
                  *eof_return = TRUE;
                  return TRUE;
                }
              continue;
            }

          /* Is this really an EOF? */
          if (parser->input->next)
            {
              /* Well, we have more frames to check.  Check if the
                 input stream had any leftover data. */
              if (parser->input->bufpos < parser->input->data_in_buf)
                ssh_xml_warning(parser,
                                "Garbage at the end of an input stream",
                                NULL);
              /* Pop this input stream and continue reading the next
                 one. */
              if (ssh_xml_pop_input_stream(parser))
                /* Input stream successfully restored. */
                continue;

              /* Out of memory in selecting input encoding. */
            }

          *eof_return = TRUE;
          return TRUE;
        }
      else
        {
          /* Read something. */
          parser->input->data_in_buf += result;
          continue;
        }
    }

 got_character:

  /* Handle line and column numbers. */
  if (*ch_return == '\n')
    {
      parser->input->line++;
      parser->input->column = 0;
    }
  parser->input->column++;

  return TRUE;
}

/* Unget the character `ch' into the input stream `input'. */
static void
ssh_xml_input_ungetch(SshXmlInput input, SshXmlChar ch)
{
  input->ungetch = ch;
  input->ungetch_valid = 1;
}

/* Get a character from the input stream of the parser `parser'.  The
   function returns TRUE if a character (or an EOF) could be get and
   FALSE if there is not enough input currently available.  The
   character is returned in `ch_return' and the argument `eof_return'
   is set to TRUE if the end-of-file was reached. */
static Boolean
ssh_xml_getch(SshXmlParser parser, SshXmlChar *ch_return, Boolean *eof_return)
{
  SshXmlChar ch;
  Boolean eof;
  SshXmlChar ch2;
  Boolean eof2;

  if (parser->blocked)
    return FALSE;

  /* Is the EOF seen? */
  if (parser->at_eof)
    {
      *eof_return = TRUE;
      return TRUE;
    }

  /* As a default, let's assume that we get something. */
  *eof_return = FALSE;

  /* Is the ungetch valid? */
  if (parser->ungetch_valid)
    {
      *ch_return = parser->ungetch;
      parser->ungetch_valid = 0;
      return TRUE;
    }

 restart:

  /* Decode a character. */
  if (!ssh_xml_input_decode(parser, &ch, &eof))
    return FALSE;

  if (eof)
    {
      parser->at_eof = 1;
      *eof_return = TRUE;

      if (parser->pereference)
        ssh_xml_error_premature_eof(parser);

      return TRUE;
    }

  /* Got something. */

  /* End-of-Line handling. */
  if (ch == '\r')
    {
      /* Peek one character. */
      if (!ssh_xml_input_decode(parser, &ch2, &eof2))
        {
          /* Unget the first character and wait that the input has
             more source. */
          ssh_xml_input_ungetch(parser->input, ch);
          return FALSE;
        }
      if (!eof2 && ch2 != '\n')
        /* This character is put back to the input. */
        ssh_xml_input_ungetch(parser->input, ch2);

      /* The different End-of-Line sequences are canonized into a
         single '\n' character. */
      ch = '\n';
    }

  /* Handle parameter entity references. */
  if (parser->pereference)
    {
      if ((parser->pereference->data_len == 0
           && !SSH_XML_IS_NAME_FIRST_CHAR(ch))
          || (parser->pereference->data_len
              && (!SSH_XML_IS_NAME_CHAR(ch) && ch != ';')))
        {
          ssh_xml_error_not_well_formed(parser,
                                        "Invalid parameter reference name",
                                        NULL);
          parser->at_eof = 1;
          *eof_return = TRUE;
          return TRUE;
        }

      if (ch == ';')
        {
          /* End of a parameter reference.  Let's resolve the entity. */
          parser->peref_flag = 1;
          ssh_xml_resolve_entity(parser, FALSE, parser->pereference->data,
                                 parser->pereference->data_len,
                                 ssh_xml_resolve_parameter_entity_cb,
                                 parser);

          /* Check if this was a synchronous or an asynchronous
             call. */
          if (parser->peref_flag)
            {
              /* Asynchronous.  Let's clear the flag to indicate that
                 the callback is asynchronous whenever it arrives. */
              parser->peref_flag = 0;
              parser->blocked = 1;

              /* Notify our caller that not enough input was
                 available. */
              return FALSE;
            }
          else
            {
              /* Synchronous.  Check the result status. */
              if (parser->parse_result != SSH_XML_OK)
                {
                  /* It failed.  Notify the failure by indicating an
                     EOF. */
                  parser->at_eof = 1;
                  *eof_return = TRUE;
                  return TRUE;
                }

              /* The operation was successful.  Continue decoding
                 characters. */
              goto restart;
            }
        }
      else
        {
          /* Append character. */
          if (!ssh_xml_append(parser, parser->pereference, ch))
            {
              /* Out of memory. */
              ssh_xml_error_out_of_memory(parser);
              parser->at_eof = 1;
              *eof_return = TRUE;
              return TRUE;
            }

          /* Read more input. */
          goto restart;
        }
    }
  else if (ch == '%' && parser->dtd && !parser->in_comment
           && !parser->in_ignore && !parser->in_literal)
    {
      /* Peek one character. */
      if (!ssh_xml_input_decode(parser, &ch2, &eof2))
        {
          /* Unget the first character and wait that the input has
             more source. */
          ssh_xml_input_ungetch(parser->input, ch);
          return FALSE;
        }

      if (!eof2 && SSH_XML_IS_NAME_FIRST_CHAR(ch2))
        {
          ssh_xml_input_ungetch(parser->input, ch2);

          /* Start collecting PEReference. */
          parser->pereference = ssh_calloc(1, sizeof(*parser->pereference));
          if (parser->pereference == NULL)
            {
              ssh_xml_error_out_of_memory(parser);
              parser->at_eof = 1;
              *eof_return = TRUE;
              return TRUE;
            }
          goto restart;
        }

      /* This was not a PEReference. */
      if (!eof2)
        ssh_xml_input_ungetch(parser->input, ch2);
    }

  /* Got a character.  Let's pass it to our caller. */

  *eof_return = eof;
  *ch_return = ch;

  return TRUE;
}

/* Unget the character `ch' into the parser `parser'. */
static void
ssh_xml_ungetch(SshXmlParser parser, SshXmlChar ch)
{
  parser->ungetch = ch;
  parser->ungetch_valid = 1;
}

/* The SshXmlResultCB argument for handler methods. */
static void
ssh_xml_result_cb(SshXmlResult result, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshXmlParser parser = (SshXmlParser) ssh_fsm_get_tdata(thread);

  /* This completes the handler call. */
  parser->callback_handle = NULL;

  if (result != SSH_XML_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Handler failed: result=%d", result));
      parser->parse_result = result;

      /* Go to the error state unless we are already at the end
         document.  If we are at the end document, it means that this
         call did come from its result callback and we must continue
         from our current continue state. */
      if (!parser->end_document)
        SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A timeout that calls user's parse result callback. */
static void
ssh_xml_parse_result_timeout(void *context)
{
  SshXmlParser parser = (SshXmlParser) context;
  SshXmlResultCB result_cb;
  void *result_cb_context;

  result_cb = parser->result_cb;
  result_cb_context = parser->result_cb_context;

  parser->result_cb = NULL_FNPTR;
  parser->result_cb_context = NULL;

  /* This completes the asynchronous parsing operation. */
  if (!parser->parse_handle_aborted)
    {
      ssh_operation_unregister(&parser->parse_handle);

      /* And notify user about the completion of the parse operation. */
      if (result_cb)
        (*result_cb)(parser->parse_result, result_cb_context);
    }
}

/* An operation abort callback for the parse operation. */
static void
ssh_xml_parse_abort_cb(void *context)
{
  SshXmlParser parser = (SshXmlParser) context;

  /* Abort possible handler callback. */
  if (parser->callback_handle)
    {
      ssh_operation_abort(parser->callback_handle);
      parser->callback_handle = NULL;
    }

  parser->result_cb = NULL_FNPTR;
  parser->result_cb_context = NULL;
  parser->parse_handle_aborted = TRUE;

#if 0
  ssh_fsm_kill_thread(&parser->thread);
#endif

  ssh_fsm_set_next(&parser->thread, ssh_xml_st_end_cb);
  ssh_fsm_continue(&parser->thread);

  /* Clear all dynamic state from the parser. */
  ssh_xml_parser_clear(parser, TRUE);
}


/***************************** State functions ******************************/

SSH_FSM_STEP(ssh_xml_st_start_document)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Call user callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->content_handler.start_document)
          SSH_XML_HANDLER(content_handler.start_document)(
                                        parser, ssh_xml_result_cb, thread,
                                        parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_xml_st_start)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      if (parser->parse_tree)
        {
          ssh_xml_error_premature_eof(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
      else
        {
          SSH_FSM_SET_NEXT(ssh_xml_st_end);
        }
      return SSH_FSM_CONTINUE;
    }

  /* Check the character. */
  if (ch == '<')
    {
      /** Start of a '<' markup. */
      SSH_FSM_SET_NEXT(ssh_xml_st_lt_markup);
      return SSH_FSM_CONTINUE;
    }
  else if (ch == '&')
    {
      if (parser->parse_tree == NULL)
        {
          /** Reference at top-level. */
          ssh_xml_error_not_well_formed(parser,
                                        "General reference at top-level",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      /* References are valid only in XML. */
      if (parser->dtd)
        {
          /** Reference in DTD. */
          ssh_xml_error_not_well_formed(parser, "General Reference in DTD",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      parser->lexer->data_len = 0;

      /** Reference. */
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_reference);
      return SSH_FSM_CONTINUE;
    }
  else if (ch == ']')
    {
      SshXmlChar ch2;

      /* Peek a character. */
      if (!ssh_xml_getch(parser, &ch2, &eof))
        {
          ssh_xml_ungetch(parser, ch);
          SSH_FSM_CONDITION_WAIT(&parser->io_cond);
        }

      if (eof)
        {
          /** EOF. */
          ssh_xml_error_premature_eof(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      if (ch2 == ']')
        {
          /* A possible section end. */
          SSH_FSM_SET_NEXT(ssh_xml_st_almost_section_end);
          return SSH_FSM_CONTINUE;
        }
      else
        {
          /* Just ']' followed by something not interesting. */
          ssh_xml_ungetch(parser, ch2);
        }

      if (parser->doctype_dtd)
        {
          /** Embedded DTD parsed. */
          parser->dtd = 0;
          parser->doctype_dtd = 0;
          SSH_FSM_SET_NEXT(ssh_xml_st_xml_doctype_parsed);
          return SSH_FSM_CONTINUE;
        }

      /* We have already seen one ']' which we can not put back into
         the stream.  We are about to collect CDATA so let's append
         the first item here. */
      parser->cdata_wspace = 0;
      parser->lexer->data_len = 0;

      if (!ssh_xml_append(parser, parser->lexer, (SshXmlChar) ']'))
        {
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      SSH_FSM_SET_NEXT(ssh_xml_st_cdata);
      return SSH_FSM_CONTINUE;
    }

  /* Start collecting CDATA.  As a default all CDATA is whitespace.
     If any other characters are found, those will turn the flag
     off. */
  parser->cdata_wspace = 1;

  /* Unget the first CDATA character. */
  ssh_xml_ungetch(parser, ch);

  /** Collect CDATA. */
  parser->lexer->data_len = 0;
  SSH_FSM_SET_NEXT(ssh_xml_st_cdata);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_cdata)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    goto end_of_cdata;

  /* Still more character data? */
  if (ch == '&')
    {
      /** Read reference. */
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_reference);
      return SSH_FSM_CONTINUE;
    }
  else if (ch == '<')
    {
      /** CDATA read. */
      ssh_xml_ungetch(parser, ch);
      goto end_of_cdata;
    }
  else if (ch == ']')
    {
      if (parser->dtd)
        {
          /** End of CDATA. */
          ssh_xml_ungetch(parser, ch);
        end_of_cdata:
          SSH_FSM_SET_NEXT(ssh_xml_st_cdata_read);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Is the input still whitespace only? */
  if (parser->cdata_wspace && !SSH_XML_IS_SPACE(ch))
    /* No it isn't. */
    parser->cdata_wspace = 0;

  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Collect more data. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_cdata_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Did we collect any data? */
  if (parser->lexer->data_len == 0)
    {
      /** Continue parsing. */
      SSH_FSM_SET_NEXT(ssh_xml_st_start);
      return SSH_FSM_CONTINUE;
    }

  /* Check if the CDATA is allowed here. */
  if (!parser->cdata_wspace
      && (parser->parse_tree == NULL || parser->dtd))
    {
      /** CDATA in top-level / DTD. */
      ssh_xml_error_not_well_formed(parser,
                                    "Character data in ",
                                    parser->dtd ? "DTD" : "top-level",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Call the user-callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);
  SSH_FSM_ASYNC_CALL(
    do
      {
        /* Check what we got. */
        if (parser->cdata_wspace
            && (parser->parse_tree == NULL || parser->dtd))
          {
            /* This is ignorable whitespace. */
            if (parser->content_handler.ignorable_wspace)
              SSH_XML_HANDLER(content_handler.ignorable_wspace)(
                                                parser,
                                                parser->lexer->data,
                                                parser->lexer->data_len,
                                                parser->dtd,
                                                ssh_xml_result_cb,
                                                thread,
                                                parser->handler_context);
            else
              ssh_xml_result_cb(SSH_XML_OK, thread);
          }
        else
          {
            /* Normal character data. */
            if (parser->content_handler.characters)
              SSH_XML_HANDLER(content_handler.characters)(
                                                parser,
                                                parser->lexer->data,
                                                parser->lexer->data_len,
                                                parser->cdata_wspace,
                                                ssh_xml_result_cb,
                                                thread,
                                                parser->handler_context);
            else
              ssh_xml_result_cb(SSH_XML_OK, thread);
          }
      }
    while (0);
  );
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_xml_st_lt_markup)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Check what character follows the initial `<'. */
  if (ch == '!')
    /** Start of `<!' markup. */
    SSH_FSM_SET_NEXT(ssh_xml_st_lt_exlam_markup);
  else if (ch == '?')
    /** PI. */
    SSH_FSM_SET_NEXT(ssh_xml_st_pi);
  else if (ch == '/')
    /** End-tag. */
    SSH_FSM_SET_NEXT(ssh_xml_st_end_tag);
  else
    {
      if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
        {
          /** Start-tag. */
          ssh_xml_ungetch(parser, ch);
          SSH_FSM_SET_NEXT(ssh_xml_st_start_tag);
        }
      else
        {
          /** Not well-formed. */
          ssh_xml_error_not_well_formed(parser, "Invalid `<' markup", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_lt_exlam_markup)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Check what character we got. */
  if (ch == '-')
    /** Almost a comment. */
    SSH_FSM_SET_NEXT(ssh_xml_st_almost_comment);
  else if (ch == '[')
    /** Section. */
    SSH_FSM_SET_NEXT(ssh_xml_st_section);
  else
    {
      if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
        {
          /** Declaration. */
          ssh_xml_ungetch(parser, ch);
          SSH_FSM_SET_NEXT(ssh_xml_st_decl);
        }
      else
        {
          /** Not well-formed. */
          ssh_xml_error_not_well_formed(parser, "Invalid `<!' markup", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_almost_comment)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }
  else if (ch == '-')
    {
      /** Comment. */
      parser->comment_end_len = 0;
      parser->in_comment = 1;
      SSH_FSM_SET_NEXT(ssh_xml_st_comment);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser, "Invalid comment start", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_comment)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch <= 0xff)
    {
      if (parser->comment_end_len >= sizeof(parser->comment_end))
        {
          memmove(parser->comment_end, parser->comment_end + 1,
                  sizeof(parser->comment_end) - 1);
          parser->comment_end_len--;
        }
      parser->comment_end[parser->comment_end_len++] = ch;

      if (parser->comment_end_len == 3)
        {
          if (memcmp(parser->comment_end, "-->", 3) == 0)
            {
              /** Comment skipped. */
              parser->in_comment = 0;
              SSH_FSM_SET_NEXT(ssh_xml_st_start);
              return SSH_FSM_CONTINUE;
            }
          if (memcmp(parser->comment_end, "--", 2) == 0)
            {
              /** String `--' in comment. */
              ssh_xml_error_not_well_formed(parser,
                                            "String `--' occurred in comment",
                                            NULL);
              SSH_FSM_SET_NEXT(ssh_xml_st_error);
              return SSH_FSM_CONTINUE;
            }
        }
    }
  else
    {
      /* Just a part of a comment. */
      parser->comment_end_len = 0;
    }

  /* Consume more. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_section)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Mark that we have not seen any whitespace yet. */
  parser->had_whitespace = 0;

  /** Skip possible whitespace */
  parser->lexer->continue_state = ssh_xml_st_section_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_section_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read the section name. */
  parser->lexer->continue_state = ssh_xml_st_section_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_section_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip optional whitespace. */
  parser->lexer->continue_state = ssh_xml_st_section_parsed;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_section_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read the terminator. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch != '[')
    {
      ssh_xml_error_not_well_formed(parser, "Invalid section start", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("<![%s", parser->lexer->data));

  /* Check the section type. */
  if (SSH_MATCH(parser->lexer->data, "CDATA"))
    {
      if (parser->had_whitespace)
        {
          /* The CDATA section start must not have whitespace around
             its name. */
          ssh_xml_error_not_well_formed(parser,
                                        "Whitespace around CDATA section "
                                        "start", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
      else
        {
          /* This was a valid CDATA section start. */
          parser->cdata_wspace = 1;
          parser->lexer->data_len = 0;
          parser->comment_end_len = 0;
          SSH_FSM_SET_NEXT(ssh_xml_st_section_cdata);
        }
    }
  else if (SSH_MATCH(parser->lexer->data, "IGNORE"))
    {
      /* Conditional sections are only valid in the external DTD
         subsets. */
      if (parser->dtd && !parser->doctype_dtd)
        {
          parser->comment_end_len = 0;
          parser->ignore_nesting_count = 0;
          parser->in_ignore = 1;
          SSH_FSM_SET_NEXT(ssh_xml_st_section_ignore);
        }
      else
        {
          ssh_xml_error_not_well_formed(parser,
                                        "IGNORE section outside external DTD",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }
  else if (SSH_MATCH(parser->lexer->data, "INCLUDE"))
    {
      /* Conditional sections are only valid in the external DTD
         subsets. */
      if (parser->dtd && !parser->doctype_dtd)
        {
          parser->include_nesting_count++;
          SSH_FSM_SET_NEXT(ssh_xml_st_start);
        }
      else
        {
          ssh_xml_error_not_well_formed(parser,
                                        "INCLUDE section outside external DTD",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }
  else
    {
      ssh_xml_error_not_well_formed(parser, "Unknown section type `",
                                    parser->lexer->data, "'", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_almost_section_end)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek one more character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }
  else if (ch == '>')
    {
      /* Section end.  They are only valid in the external DTD
         subsets. */
      if (parser->dtd && !parser->doctype_dtd)
        {
          if (parser->include_nesting_count == 0)
            {
              /* Unbalanced section end. */
              ssh_xml_error_not_well_formed(parser,
                                            "Unbalanced section end `]]>'",
                                            NULL);
              SSH_FSM_SET_NEXT(ssh_xml_st_error);
            }
          else
            {
              /* One section processed. */
              parser->include_nesting_count--;
              SSH_FSM_SET_NEXT(ssh_xml_st_start);
            }
        }
      else
        {
          ssh_xml_error_not_well_formed(parser,
                                        "Section end `]]>' outside "
                                        "external DTD", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }
  else
    {
      /* Put this character back. */
      ssh_xml_ungetch(parser, ch);

      /* Start collecting CDATA.  We have already seen `]]'. */
      parser->cdata_wspace = 0;
      parser->lexer->data_len = 0;

      if (!ssh_xml_append(parser, parser->lexer, (SshXmlChar) ']'))
        {
        error_memory:
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      if (!ssh_xml_append(parser, parser->lexer, (SshXmlChar) ']'))
        goto error_memory;

      SSH_FSM_SET_NEXT(ssh_xml_st_cdata);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_section_cdata)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;
  size_t i;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch <= 0xff)
    {
      if (parser->comment_end_len >= sizeof(parser->comment_end))
        {
          /* Still whitespace only? */
          if (parser->cdata_wspace
              && !SSH_XML_IS_SPACE(parser->comment_end[0]))
            /* No. */
            parser->cdata_wspace = 0;

          /* Save the first saved character. */
          if (!ssh_xml_append(parser, parser->lexer, parser->comment_end[0]))
            {
            error_memory:
              ssh_xml_error_out_of_memory(parser);
              SSH_FSM_SET_NEXT(ssh_xml_st_error);
              return SSH_FSM_CONTINUE;
            }
          memmove(parser->comment_end, parser->comment_end + 1,
                  sizeof(parser->comment_end) - 1);
          parser->comment_end_len--;
        }
      parser->comment_end[parser->comment_end_len++] = ch;

      if (parser->comment_end_len == 3
          && memcmp(parser->comment_end, "]]>", 3) == 0)
        {
          /** CDATA section read. */
          SSH_FSM_SET_NEXT(ssh_xml_st_cdata_read);
          return SSH_FSM_CONTINUE;
        }

      /* Read more data. */
      return SSH_FSM_CONTINUE;
    }
  else
    {
      /* Save all cached data. */
      for (i = 0; i < parser->comment_end_len; i++)
        {
          /* Still whitespace only? */
          if (parser->cdata_wspace
              && !SSH_XML_IS_SPACE(parser->comment_end[i]))
            /* No. */
            parser->cdata_wspace = 0;

          if (!ssh_xml_append(parser, parser->lexer, parser->comment_end[i]))
            goto error_memory;
        }
      parser->comment_end_len = 0;
    }

  /* Still whitespace only? */
  if (parser->cdata_wspace && !SSH_XML_IS_SPACE(ch))
    /* No. */
    parser->cdata_wspace = 0;

  /* Save the newly read character. */
  if (!ssh_xml_append(parser, parser->lexer, ch))
    goto error_memory;

  /* Read more. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_section_ignore)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch <= 0xff)
    {
      if (parser->comment_end_len >= sizeof(parser->comment_end))
        {
          memmove(parser->comment_end, parser->comment_end + 1,
                  sizeof(parser->comment_end) - 1);
          parser->comment_end_len--;
        }
      parser->comment_end[parser->comment_end_len++] = ch;

      if (parser->comment_end_len == 3)
        {
          if (memcmp(parser->comment_end, "<![", 3) == 0)
            {
              /* Start of another section. */
              parser->ignore_nesting_count++;
            }
          else if (memcmp(parser->comment_end, "]]>", 3) == 0)
            {
              /* End of a section. */
              if (parser->ignore_nesting_count == 0)
                {
                  /** End of an ignore section. */
                  parser->in_ignore = 0;
                  SSH_FSM_SET_NEXT(ssh_xml_st_start);
                  return SSH_FSM_CONTINUE;
                }

              /* Decrement nesting count. */
              parser->ignore_nesting_count--;
            }
        }
    }
  else
    {
      /* Just some data. */
      parser->comment_end_len = 0;
    }

  /* Consume more. */
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_decl)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read declaration name. */
  parser->lexer->continue_state = ssh_xml_st_decl_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_decl_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Check what declarations are allowed at this parsing mode. */
  if (parser->dtd)
    {
      /* Parsing DTD. */
      if (SSH_MATCH(parser->lexer->data, "ELEMENT"))
        SSH_FSM_SET_NEXT(ssh_xml_st_dtd_element);
      else if (SSH_MATCH(parser->lexer->data, "ATTLIST"))
        SSH_FSM_SET_NEXT(ssh_xml_st_dtd_attlist);
      else if (SSH_MATCH(parser->lexer->data, "ENTITY"))
        SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity);
      else if (SSH_MATCH(parser->lexer->data, "NOTATION"))
        SSH_FSM_SET_NEXT(ssh_xml_st_dtd_notation);
      else
        {
          /** Not well-formed. */
          ssh_xml_error_not_well_formed(parser, "Invalid declaration in DTD",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }
  else
    {
      /* Parsing XML. */
      if (SSH_MATCH(parser->lexer->data, "DOCTYPE"))
        SSH_FSM_SET_NEXT(ssh_xml_st_xml_doctype);
      else
        {
          /** Not well-formed. */
          ssh_xml_error_not_well_formed(parser, "Invalid declaration in XML",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_decl_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read the terminator character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch != '>')
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser, "Invalid declaration", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /** Continue parsing. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_pi)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read target name. */
  parser->lexer->continue_state = ssh_xml_st_pi_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_pi_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Is this an XMLDecl? */
  if (SSH_MATCH(parser->lexer->data, "xml"))
    {
      /** XMLDecl. */



      parser->xmldecl_state = SSH_XML_DECL_VERSION;
      parser->lexer->continue_state = ssh_xml_st_xmldecl;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);
      return SSH_FSM_CONTINUE;
    }

  /* Save the PI name. */
  parser->data1 = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (parser->data1 == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  parser->data1_len = parser->lexer->data_len;

  /* Collect PI data. */
  parser->lexer->data_len = 0;
  SSH_FSM_SET_NEXT(ssh_xml_st_pi_collect);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_pi_collect)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
    eof:
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ch == '?')
    {
      SshXmlChar ch2;

      /* Peek another character. */
      if (!ssh_xml_getch(parser, &ch2, &eof))
        {
          ssh_xml_ungetch(parser, ch);
          SSH_FSM_CONDITION_WAIT(&parser->io_cond);
        }
      if (eof)
        goto eof;

      if (ch2 == '>')
        {
          /* Processing instruction collected.  Call user callback. */
          SSH_FSM_SET_NEXT(ssh_xml_st_pi_cb);
          SSH_FSM_ASYNC_CALL(
            do
              {
                if (parser->content_handler.pi)
                  SSH_XML_HANDLER(content_handler.pi)(parser,
                                                      parser->data1,
                                                      parser->data1_len,
                                                      parser->lexer->data,
                                                      parser->lexer->data_len,
                                                      ssh_xml_result_cb,
                                                      thread,
                                                      parser->handler_context);
                else
                  ssh_xml_result_cb(SSH_XML_OK, thread);
              }
            while (0);
          );
          SSH_NOTREACHED;
        }

      /* This was not end of the processing instructions. */
      ssh_xml_ungetch(parser, ch2);
    }

  /* Append data. */
  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Collect more data. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_pi_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Free temporary variables. */
  ssh_free(parser->data1);
  parser->data1 = NULL;

  /** Continue parsing. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xmldecl)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read the keyword literal. */
  parser->lexer->continue_state = ssh_xml_st_xmldecl_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xmldecl_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Check the token. */
 restart:
  switch (parser->xmldecl_state)
    {
    case SSH_XML_DECL_VERSION:
      if (!SSH_MATCH(parser->lexer->data, "version"))
        {
          if (!parser->params.strict_1_0_ed_2)
            {
              /* XML 1.0 (Second Edition) says that version info can
                 not be omitted.  But there seems to be
                 implementations allowing this. */
              parser->xmldecl_state++;
              goto restart;
            }
          /** Not well-formed. */
        malformed:
          ssh_xml_error_not_well_formed(parser, "Malformed XML declaration",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      break;

    case SSH_XML_DECL_ENCODING:
      if (!SSH_MATCH(parser->lexer->data, "encoding"))
        {
          parser->xmldecl_state++;
          goto restart;
        }
      break;

    case SSH_XML_DECL_SDDECL:
      if (!SSH_MATCH(parser->lexer->data, "standalone"))
        {
          parser->xmldecl_state++;
          goto restart;
        }
      break;

    case SSH_XML_DECL_END:
      goto malformed;
      break;
    }

  /* XML 1.0 (Second Edition) does not allow whitespace between
     attribute name and `='. */
  if (parser->params.strict_1_0_ed_2)
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_xmldecl_eq);
    }
  else
    {
      parser->lexer->continue_state = ssh_xml_st_xmldecl_eq;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xmldecl_eq)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek one character. */

  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch != '=')
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser, "Malformed XML declaration",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* XML 1.0 (Second Edition) does not allow whitespace between
     attribute name and `='. */
  if (parser->params.strict_1_0_ed_2)
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_xmldecl_value);
    }
  else
    {
      parser->lexer->continue_state = ssh_xml_st_xmldecl_value;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xmldecl_value)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read value. */
  parser->lexer->continue_state = ssh_xml_st_xmldecl_value_read;
  /* System literal allows more characters than are actually allowed
     here but we will check the validity of the value later so this
     does not hurt us. */
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_system_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xmldecl_value_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Check the value. */
  switch (parser->xmldecl_state)
    {
    case SSH_XML_DECL_VERSION:
      if (!SSH_MATCH(parser->lexer->data, "1.0"))
        {
          /** Malformed version number. */



          ssh_xml_error_not_well_formed(parser,
                                        "Invalid XML version number `",
                                        parser->lexer->data, "'", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      break;

    case SSH_XML_DECL_ENCODING:
      if (!ssh_xml_input_encoding((char *) parser->lexer->data,
                                  &parser->input->encoding))
        {
          /** Unknown input encoding. */



          ssh_xml_error_not_well_formed(parser,
                                        "Unsupported input encoding `",
                                        parser->lexer->data, "'", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      /* Select current input encoding. */
      if (!ssh_xml_select_input_encoding(parser))
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      break;

    case SSH_XML_DECL_SDDECL:
      if (SSH_MATCH(parser->lexer->data, "yes"))
        parser->standalone = 1;
      else if (SSH_MATCH(parser->lexer->data, "no"))
        parser->standalone = 0;
      else
        {
          /** Malformed standalone specification. */
          ssh_xml_error_not_well_formed(parser,
                                        "Malformed standalone specification `",
                                        parser->lexer->data, "'", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      break;

    case SSH_XML_DECL_END:
      SSH_NOTREACHED;
      break;
    }

  /* This attribute is processed. */
  parser->xmldecl_state++;

  /* Check if we have more attributes. */



  parser->lexer->continue_state = ssh_xml_st_xmldecl_more;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xmldecl_more)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
    eof:
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == '?')
    {
      SshXmlChar ch2;

      /* Peek another character. */
      if (!ssh_xml_getch(parser, &ch2, &eof))
        {
          ssh_xml_ungetch(parser, ch);
          SSH_FSM_CONDITION_WAIT(&parser->io_cond);
        }
      if (eof)
        goto eof;

      if (ch2 != '>')
        {
          /** Not well formed. */
          ssh_xml_error_not_well_formed(parser, "Malformed XML declaration",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
        }
      else
        {
          /** XMLDecl parsed. */
          SSH_FSM_SET_NEXT(ssh_xml_st_start);
        }
    }
  else
    {
      /** More attributes follow. */
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_xmldecl);
    }

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_start_tag)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Elements are valid only in XML. */
  if (parser->dtd)
    {
      /** Element in DTD. */
      ssh_xml_error_not_well_formed(parser, "Element in an %s DTD",
                                    (parser->doctype_dtd
                                     ? "embedded" : "external"),
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }


  /** Read element name. */
  parser->lexer->continue_state = ssh_xml_st_start_tag_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  SSH_DEBUG(SSH_D_LOWSTART, ("<%s", parser->lexer->data));

  /* Push an element to our parse stack. */
  if (!ssh_xml_push_element(parser, parser->lexer->data,
                            parser->lexer->data_len))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /** Optional attributes. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start_tag_attribute);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_attribute)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_start_tag_attribute_name;



  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Check if we still have attributes left. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
    eof:
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == '/')
    {
      /* An empty tag. */
      if (parser->parse_tree->empty)
        {
          /* A second '/' character seen. */
        second_slash:
          ssh_xml_error_not_well_formed(parser,
                                        "Multiple `/' characters at the "
                                        "end of an element", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      parser->parse_tree->empty = 1;

      /* Read a character. */
      if (!ssh_xml_getch(parser, &ch, &eof))
        SSH_FSM_CONDITION_WAIT(&parser->io_cond);

      if (eof)
        goto eof;

      /* A special check to get good error messages. */
      if (ch == '/')
        goto second_slash;

      /* FALLTHROUGH */
    }
  if (ch == '>')
    {
      /** Start tag parsed. */
      SSH_FSM_SET_NEXT(ssh_xml_st_start_tag_parsed);
      return SSH_FSM_CONTINUE;
    }
  if (!SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** Invalid name. */
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid attribute name first character",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  ssh_xml_ungetch(parser, ch);

  /** Read attribute name. */
  parser->lexer->continue_state = ssh_xml_st_start_tag_attribute_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  Boolean unique;

  SSH_DEBUG(SSH_D_LOWOK, ("Attribute %s", parser->lexer->data));

  parser->current_attribute
    = ssh_xml_insert_attribute(parser,
                               parser->parse_tree->attributes,
                               parser->lexer->data,
                               parser->lexer->data_len,
                               &unique);
  if (parser->current_attribute == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  else if (!unique)
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Attribute specified more than once",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* XML 1.0 (Second Edition) does not allow whitespace between
     attribute name and `='. */
  if (parser->params.strict_1_0_ed_2)
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_start_tag_attribute_eq);
    }
  else
    {
      parser->lexer->continue_state = ssh_xml_st_start_tag_attribute_eq;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_eq)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read `=' character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ch != '=')
    {
      /** The `=' character missing. */
      ssh_xml_error_not_well_formed(parser,
                                    "No `=' character between attribute name "
                                    "and value", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* XML 1.0 (Second Edition) does not allow whitespace between `='
     and attribute value. */
  if (parser->params.strict_1_0_ed_2)
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_start_tag_attribute_value);
    }
  else
    {
      parser->lexer->continue_state = ssh_xml_st_start_tag_attribute_value;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_value)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Read attribute value. */
  parser->lexer->continue_state = ssh_xml_st_start_tag_attribute_value_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_attribute_value);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_attribute_value_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlAttribute attr = parser->current_attribute;

  SSH_DEBUG(SSH_D_LOWOK, ("Value %s", parser->lexer->data));
  SSH_ASSERT(attr != NULL);
  SSH_ASSERT(attr->value == NULL);

  attr->value = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (attr->value == NULL)
    {
      /** Out of memory. */
    error_memory:
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  attr->value_len = parser->lexer->data_len;

  /* Handle namespace declarations. */
  if (attr->header.name_len >= 5
      && memcmp(attr->header.name, "xmlns", 5) == 0)
    {
      SshXmlElement element = parser->parse_tree;

      /* This is a namespace declaration. */
      if (attr->header.name_len == 5)
        {
          /* Declaring the default name space. */
          if (element->default_namespace)
            {
              ssh_xml_error_not_well_formed(parser,
                                            "Default namespace declared "
                                            "more than once", NULL);
              SSH_FSM_SET_NEXT(ssh_xml_st_error);
              return SSH_FSM_CONTINUE;
            }

          /* Declare the default namespace. */
          element->default_namespace = ssh_xml_intern(parser, attr->value,
                                                      attr->value_len);
          if (element->default_namespace == NULL)
            goto error_memory;
        }
      else
        {
          SshXmlNamespace ns;

          /* Defining a namespace prefix. */





          ns = ssh_calloc(1, sizeof(*ns));
          if (ns == NULL)
            goto error_memory;

          /* Intern prefix. */
          ns->prefix = ssh_xml_intern(parser, attr->header.name + 6,
                                      attr->header.name_len - 6);
          if (ns->prefix == NULL)
            {
              ssh_free(ns);
              goto error_memory;
            }
          ns->prefix_len = attr->header.name_len - 6;

          /* Intern URI. */
          ns->uri = ssh_xml_intern(parser, attr->value, attr->value_len);
          if (ns->uri == NULL)
            goto error_memory;

          /* Link it to the elements namespace declarations. */
          ns->next = element->namespaces;
          element->namespaces = ns;
        }

      /* Remove the object from the attributes bag. */
      ssh_adt_delete_object(element->attributes, attr);

      /* And free it. */
      ssh_xml_attribute_free(attr);
    }

  parser->current_attribute = NULL;

  /* Continue reading attributes. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start_tag_attribute);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  SSH_FSM_SET_NEXT(ssh_xml_st_start_tag_parsed_cb);
  SSH_FSM_ASYNC_CALL(
        do
          {
            SshXmlElement element = parser->parse_tree;

            if (parser->content_handler.start_element)
              SSH_XML_HANDLER(content_handler.start_element)(
                                                parser,
                                                element->name,
                                                element->name_len,
                                                element->attributes,
                                                ssh_xml_result_cb,
                                                thread,
                                                parser->handler_context);
            else
              ssh_xml_result_cb(SSH_XML_OK, thread);
          }
        while (0);
  );
  SSH_NOTREACHED;

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_start_tag_parsed_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlElement element = parser->parse_tree;

  /* Check if this was an empty element. */
  if (element->empty)
    {
      /* Yes it is.  CAll the `end element' method directly. */
      SSH_FSM_SET_NEXT(ssh_xml_st_end_tag_parsed_cb);
      SSH_FSM_ASYNC_CALL(
        do
          {
            if (parser->content_handler.end_element)
              SSH_XML_HANDLER(content_handler.end_element)(
                                                parser,
                                                element->name,
                                                element->name_len,
                                                ssh_xml_result_cb,
                                                thread,
                                                parser->handler_context);
            else
              ssh_xml_result_cb(SSH_XML_OK, thread);
          }
        while (0);
      );
      SSH_NOTREACHED;
    }
  else
    {
      /* Continue parsing. */
      SSH_FSM_SET_NEXT(ssh_xml_st_start);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_end_tag)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read element name. */
  parser->lexer->continue_state = ssh_xml_st_end_tag_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_end_tag_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_end_tag_whitespace;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_end_tag_whitespace)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;
  SshXmlElement element = parser->parse_tree;

  /* Read the terminator character. */

  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch != '>')
    {
      ssh_xml_error_not_well_formed(parser, "Malformed end-tag", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* We must have an open element. */
  if (element == NULL)
    {
      ssh_xml_error_not_well_formed(parser, "Unmatched end-tag `",
                                    parser->lexer->data, "' at top-level",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Check that the end-tag matches the tag being currently open. */
  if (element->name_len != parser->lexer->data_len
      || memcmp(element->name, parser->lexer->data, element->name_len) != 0)
    {
      ssh_xml_error_not_well_formed(parser,
                                    "End-tag name `", parser->lexer->data,
                                    "' does not match the "
                                    "currently open start-tag `",
                                    element->name, "'", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* The end-tag matches the currently open start-tag.  Notify
     user. */
  SSH_FSM_SET_NEXT(ssh_xml_st_end_tag_parsed_cb);
  SSH_FSM_ASYNC_CALL(
        do
          {
            if (parser->content_handler.end_element)
              SSH_XML_HANDLER(content_handler.end_element)(
                                                parser,
                                                element->name,
                                                element->name_len,
                                                ssh_xml_result_cb,
                                                thread,
                                                parser->handler_context);
            else
              ssh_xml_result_cb(SSH_XML_OK, thread);
          }
        while (0);
  );
  SSH_NOTREACHED;
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_end_tag_parsed_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  SSH_ASSERT(parser->parse_tree != NULL);

  /* Pop an element from the parse tree. */
  ssh_xml_pop_element(parser);

  /* And continue parsing. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_reference)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  if (!ssh_xml_push_lexer_frame(parser))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Read reference. */
  parser->lexer->continue_state = ssh_xml_st_reference_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_reference);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_reference_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Pop lexer frame. */
  ssh_xml_pop_lexer_frame(parser);

  /** Continue reading CDATA. */
  SSH_FSM_SET_NEXT(ssh_xml_st_cdata);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_xml_doctype)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_xml_doctype_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read name. */
  parser->lexer->continue_state = ssh_xml_st_xml_doctype_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_xml_doctype_check_external_id;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_check_external_id)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek one character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  /* Check what follows. */
  if (eof)
    {
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }
  else if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** ExternalID. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_xml_doctype_external_id_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id);
    }
  else
    {
      /* No ExternalID.  */
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_xml_doctype_check_embedded_dtd);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_external_id_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_xml_doctype_check_embedded_dtd;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_check_embedded_dtd)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;
  Boolean unique;
  SshXmlAttribute attr;

  /* Push a temporary element to hold the DOCTYPE's attributes. */
  if (!ssh_xml_push_element(parser, parser->lexer->data,
                            parser->lexer->data_len))
    {
      /** Out of memory. */
    error_memory:
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Save ExternalID attributes at element's attributes. */

  if (parser->data1)
    {
      attr = ssh_xml_insert_attribute(parser, parser->parse_tree->attributes,
                                      (unsigned char *) "PUBLIC", 6, &unique);
      if (attr == NULL)
        goto error_memory;

      attr->value = parser->data1;
      attr->value_len = parser->data1_len;

      parser->data1 = NULL;
      parser->data1_len = 0;
    }

  if (parser->data2)
    {
      attr = ssh_xml_insert_attribute(parser, parser->parse_tree->attributes,
                                      (unsigned char *) "SYSTEM", 6, &unique);
      if (attr == NULL)
        goto error_memory;

      attr->value = parser->data2;
      attr->value_len = parser->data2_len;

      parser->data2 = NULL;
      parser->data2_len = 0;
    }

  /* Peek one character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  /* Check what follows. */
  if (eof)
    {
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }
  else if (ch == '[')
    {
      /* An embedded DTD. */

      parser->doctype_dtd = 1;
      parser->dtd = 1;

      /** Parse embedded DTD. */
      SSH_FSM_SET_NEXT(ssh_xml_st_start);
    }
  else
    {
      /** End of DOCTYPE declaration. */
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_xml_doctype_parsed);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlElement element = parser->parse_tree;
  unsigned char *pubid = NULL;
  size_t pubid_len = 0;
  unsigned char *sysid = NULL;
  size_t sysid_len = 0;
  SshXmlAttribute attr;

  attr = ssh_xml_lookup_attribute(parser->parse_tree->attributes,
                                  (unsigned char *) "PUBLIC", 6);
  if (attr)
    {
      pubid = attr->value;
      pubid_len = attr->value_len;
    }

  attr = ssh_xml_lookup_attribute(parser->parse_tree->attributes,
                                  (unsigned char *) "SYSTEM", 6);
  if (attr)
    {
      sysid = attr->value;
      sysid_len = attr->value_len;
    }


  SSH_FSM_SET_NEXT(ssh_xml_st_xml_doctype_parsed_cb);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->dtd_handler.doctype)
          SSH_XML_HANDLER(dtd_handler.doctype)(
                                        parser,
                                        element->name, element->name_len,
                                        pubid, pubid_len,
                                        sysid, sysid_len,
                                        ssh_xml_result_cb,
                                        thread,
                                        parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_xml_doctype_parsed_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Pop temporary element. */
  ssh_xml_pop_element(parser);

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_decl_parsed;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_dtd_element)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_element_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read element name. */
  parser->lexer->continue_state = ssh_xml_st_dtd_element_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Save element name. */
  parser->data1 = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (parser->data1 == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  parser->data1_len = parser->lexer->data_len;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_element_content_spec;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_content_spec)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (ch == '(')
    {
      /** Children or mixed. */
      ssh_xml_ungetch(parser, ch);
      parser->paren_level = 0;
      parser->lexer->data_len = 0;
      SSH_FSM_SET_NEXT(ssh_xml_st_dtd_element_content_expr);
    }
  else if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** A keyword content spec. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_dtd_element_content_keyword;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Malformed element content specification",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_content_keyword)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlElementContentSpec spec;

  /* Check the keyword. */
  if (SSH_MATCH(parser->lexer->data, "EMPTY"))
    spec = SSH_XML_ELEMENT_CONTENT_EMPTY;
  else if (SSH_MATCH(parser->lexer->data, "ANY"))
    spec = SSH_XML_ELEMENT_CONTENT_ANY;
  else
    {
      /** Unknown content spec. */
      ssh_xml_error_not_well_formed(parser,
                                    "Unknown element content specification `",
                                    parser->lexer->data, "'", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Call user callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_element_content_parsed);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->dtd_handler.element_decl)
          SSH_XML_HANDLER(dtd_handler.element_decl)(
                                        parser,
                                        parser->data1, parser->data1_len,
                                        spec, NULL, 0,
                                        ssh_xml_result_cb, thread,
                                        parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_content_expr)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Append character into our buffer. */
  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  /* Check the special characters. */
  if (ch == '(')
    {
      parser->paren_level++;
    }
  else if (ch == ')')
    {
      parser->paren_level--;
      if (parser->paren_level == 0)
        {
          /* End of expression, except the possible occurrence
             specifier. */
          SSH_FSM_SET_NEXT(ssh_xml_st_dtd_element_content_expr_end);
        }
    }

  /* Continue parsing (or move to the end state set above). */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_content_expr_end)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == '?' || ch == '*' || ch == '+')
    {
      /* This character belongs to the expression. */
      if (!ssh_xml_append(parser, parser->lexer, ch))
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
    }
  else
    ssh_xml_ungetch(parser, ch);

  /* Call user callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_element_content_parsed);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->dtd_handler.element_decl)
          SSH_XML_HANDLER(dtd_handler.element_decl)(
                                        parser,
                                        parser->data1, parser->data1_len,
                                        SSH_XML_ELEMENT_CONTENT_EXPR,
                                        parser->lexer->data,
                                        parser->lexer->data_len,
                                        ssh_xml_result_cb, thread,
                                        parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_content_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Free dynamically allocate copy of the element name. */
  ssh_free(parser->data1);
  parser->data1 = NULL;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_element_parsed;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_element_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read the terminator character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ch != '>')
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser, "Malformed element declaration",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /** Continue parsing. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_element_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_element_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read element name. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_element_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_element_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Save element name. */
  parser->data1 = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (parser->data1 == NULL)
    {
      /** Out of memory. */
    error_memory:
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  parser->data1_len = parser->lexer->data_len;

  /* Create ADT container for attribute definitions. */
  parser->attribute_definitions = ssh_xml_name_hash_create(parser);
  if (parser->attribute_definitions == NULL)
    goto error_memory;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attdef;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attdef)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == '>')
    {
      /** Attlist parsed. */
      SSH_FSM_SET_NEXT(ssh_xml_st_dtd_attlist_parsed);
    }
  else if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** A new attribute definition. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attribute_name;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser, "Malformed attribute definition",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlAttributeDefinition attdef;

  /* Check if the attribute definition already exists in the bag. */

  SSH_ASSERT(parser->attribute_definitions != NULL);
  attdef = ssh_xml_lookup_attribute_definitions(parser->attribute_definitions,
                                                parser->lexer->data,
                                                parser->lexer->data_len);
  if (attdef)
    {
      /* The first definition is used. */
      ssh_xml_warning(parser,
                      "Attribute `", parser->lexer->data,
                      "' defined more than once", NULL);
      parser->current_attdef = NULL;
    }
  else
    {
      /* Create a new attribute definition. */
      attdef = ssh_calloc(1, sizeof(*attdef));
      if (attdef == NULL)
        {
          /** Out of memory. */
        error_memory:
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      /* Save attribute name. */
      attdef->header.name = ssh_xml_intern(parser, parser->lexer->data,
                                           parser->lexer->data_len);
      if (attdef->header.name == NULL)
        {
          ssh_free(attdef);
          goto error_memory;
        }
      attdef->header.name_len = parser->lexer->data_len;

      /* Insert attribute definition into the attdef bag. */
      (void) ssh_adt_insert(parser->attribute_definitions, attdef);

      /* This is our current attribute definition. */
      parser->current_attdef = attdef;
    }

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attribute_type;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_type)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** Read the type name. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state
        = ssh_xml_st_dtd_attlist_attribute_type_name_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);
    }
  else if (ch == '(')
    {
      /** Enumerated type. */
      parser->in_enum = 1;
      parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_ENUMERATION;
      if (parser->current_attdef)
        parser->current_attdef->type = parser->current_attdef_type;
      parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attribute_enum;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Malformed attribute declaration type",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_type_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Prepare for the most common case below. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_defaultdecl;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  /* Check the type name. */
  if (SSH_MATCH(parser->lexer->data, "CDATA"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_CDATA;
  else if (SSH_MATCH(parser->lexer->data, "ID"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_ID;
  else if (SSH_MATCH(parser->lexer->data, "IDREF"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_IDREF;
  else if (SSH_MATCH(parser->lexer->data, "IDREFS"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_IDREFS;
  else if (SSH_MATCH(parser->lexer->data, "ENTITY"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_ENTITY;
  else if (SSH_MATCH(parser->lexer->data, "ENTITIES"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_ENTITIES;
  else if (SSH_MATCH(parser->lexer->data, "NMTOKEN"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_NMTOKEN;
  else if (SSH_MATCH(parser->lexer->data, "NMTOKENS"))
    parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_NMTOKENS;
  else if (SSH_MATCH(parser->lexer->data, "NOTATION"))
    {
      parser->current_attdef_type = SSH_XML_ATTRIBUTE_TYPE_NOTATION;
      parser->lexer->continue_state
        = ssh_xml_st_dtd_attlist_attribute_notation;
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser, "Invalid attribute type `",
                                    parser->lexer->data, "'", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  if (parser->current_attdef)
    parser->current_attdef->type = parser->current_attdef_type;

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_notation)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == '(')
    {
      /** Start of notation values. */
      parser->in_enum = 1;
      parser->lexer->continue_state
        = ssh_xml_st_dtd_attlist_attribute_enum_name;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Malformed notation attribute type",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attribute_enum_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Read name or nmtoken. */
  parser->lexer->continue_state
    = ssh_xml_st_dtd_attlist_attribute_enum_name_read;
  if (parser->current_attdef_type == SSH_XML_ATTRIBUTE_TYPE_ENUMERATION)
    SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_nmtoken);
  else
    SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlAttributeDefinition attdef = parser->current_attdef;
  Boolean add = TRUE;

  /* Check that the new enumeration value is unique. */
  if (attdef == NULL)
    add = FALSE;
  else
    if (attdef->type == SSH_XML_ATTRIBUTE_TYPE_ENUMERATION)
      {
        SshUInt32 i;

        for (i = 0; i < attdef->num_enums; i++)
          if (attdef->enum_lens[i] == parser->lexer->data_len
              && memcmp(attdef->enums[i], parser->lexer->data,
                        parser->lexer->data_len) == 0)
            {
              /* It is already specified. */
              ssh_xml_warning(parser,
                              "Enumeration value `", parser->lexer->data,
                              "' defined more than once", NULL);
              add = FALSE;
            }
      }

  /* Add the value. */
  if (add)
    {
      unsigned char *data;
      unsigned char **nenums;
      size_t *nlens;

      data = ssh_xml_intern(parser, parser->lexer->data,
                            parser->lexer->data_len);
      if (data == NULL)
        {
          /** Out of memory. */
        error_memory:
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      /* Reallocate buffers. */

      nenums = ssh_realloc(attdef->enums,
                           attdef->num_enums * sizeof(*attdef->enums),
                           (attdef->num_enums + 1) * sizeof(*attdef->enums));
      if (nenums == NULL)
        goto error_memory;

      attdef->enums = nenums;

      nlens = ssh_realloc(attdef->enum_lens,
                          attdef->num_enums * sizeof(*attdef->enum_lens),
                          ((attdef->num_enums + 1)
                           * sizeof(*attdef->enum_lens)));
      if (nlens == NULL)
        goto error_memory;

      attdef->enum_lens = nlens;

      /* Store the new value. */
      attdef->enums[attdef->num_enums] = data;
      attdef->enum_lens[attdef->num_enums] = parser->lexer->data_len;
      attdef->num_enums++;
    }

  /** Check if there are more tokens. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attribute_enum_more;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attribute_enum_more)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (ch == '|')
    {
      /** More enums to read */
      parser->lexer->continue_state
        = ssh_xml_st_dtd_attlist_attribute_enum_name;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
    }
  else if (ch == ')')
    {
      /** All values read. */
      parser->in_enum = 0;
      parser->lexer->continue_state = ssh_xml_st_dtd_attlist_defaultdecl;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);
    }
  else
    {
      /** Malformed enumeration list. */
      ssh_xml_error_not_well_formed(parser, "Malformed enumeration list",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_defaultdecl)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Check the default type. */
  if (ch == '#')
    {
      /** Read default declaration name. */
      parser->lexer->continue_state = ssh_xml_st_dtd_attlist_defaultdecl_name;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);
    }
  else if (ch == '"' || ch == '\'')
    {
      /** Read the default value. */
      if (parser->current_attdef)
        parser->current_attdef->default_type
          = SSH_XML_ATTRIBUTE_DEFAULT_TYPE_DEFAULT;
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state
        = ssh_xml_st_dtd_attlist_default_value_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_attribute_value);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Malformed attribute default value "
                                    "declaration", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_defaultdecl_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlAttributeDefaultType deftype;

  /* Prepare for the most common case below. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_attlist_attdef_parsed);

  /* Check the type of the default declaration. */
  if (SSH_MATCH(parser->lexer->data, "REQUIRED"))
    deftype = SSH_XML_ATTRIBUTE_DEFAULT_TYPE_REQUIRED;
  else if (SSH_MATCH(parser->lexer->data, "IMPLIED"))
    deftype = SSH_XML_ATTRIBUTE_DEFAULT_TYPE_IMPLIED;
  else if (SSH_MATCH(parser->lexer->data, "FIXED"))
    {
      deftype = SSH_XML_ATTRIBUTE_DEFAULT_TYPE_FIXED;
      /** Skip whitespace. */
      parser->lexer->continue_state = ssh_xml_st_dtd_attlist_default_value;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);
    }
  else
    {
      /** Invalid default type. The following shuts up compiler. */
      deftype =  SSH_XML_ATTRIBUTE_DEFAULT_TYPE_DEFAULT;
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid attribute default type `#",
                                    parser->lexer->data, "'", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  if (parser->current_attdef)
    parser->current_attdef->default_type = deftype;

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_default_value)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ch == '"' || ch == '\'')
    {
      /** Read the default value. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state
        = ssh_xml_st_dtd_attlist_default_value_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_attribute_value);
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Malformed attribute default value "
                                    "declaration", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_default_value_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Save default value. */
  if (parser->current_attdef)
    {
      parser->current_attdef->value = ssh_memdup(parser->lexer->data,
                                                 parser->lexer->data_len);
      if (parser->current_attdef->value == NULL)
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      parser->current_attdef->value_len = parser->lexer->data_len;
    }

  /** An attribute definition parsed. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_attlist_attdef_parsed);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_attdef_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* No current attribute definition anymore. */
  parser->current_attdef = NULL;

  /** Continue parsing. */
  parser->lexer->continue_state = ssh_xml_st_dtd_attlist_attdef;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Call user callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_attlist_parsed_cb);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->dtd_handler.attlist_decl)
          SSH_XML_HANDLER(dtd_handler.attlist_decl)(
                                        parser,
                                        parser->data1, parser->data1_len,
                                        parser->attribute_definitions,
                                        ssh_xml_result_cb,
                                        thread,
                                        parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ssh_xml_st_dtd_attlist_parsed_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Free dynamic element name. */
  ssh_free(parser->data1);
  parser->data1 = NULL;

  /* Free attribute definitions. */
  ssh_xml_attribute_definitions_free(parser, parser->attribute_definitions);
  parser->attribute_definitions = NULL;

  /** Continue parsing. */
  SSH_FSM_SET_NEXT(ssh_xml_st_start);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_type;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_type)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek one character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** GEDecl. */
      ssh_xml_ungetch(parser, ch);
      parser->general_entity = 1;
      SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_general);
    }
  else
    {
      /** PEDecl. */
      ssh_xml_ungetch(parser, ch);
      parser->general_entity = 0;
      SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_parameter);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read entity name. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_general_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  Boolean unique;

  /* Create a new entity. */
  parser->current_entity = ssh_xml_insert_entity(parser,
                                                 parser->general_entities,
                                                 parser->input->name,
                                                 TRUE,
                                                 parser->lexer->data,
                                                 parser->lexer->data_len,
                                                 &unique);
  if (parser->current_entity == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (!unique)
    {
      /* The first binding is used. */
      ssh_xml_warning(parser,
                      "Entity `", parser->lexer->data,
                      "' defined more than once", NULL);
      parser->current_entity = NULL;
    }

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_general_def;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_def)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Check the type of the definition. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }
  else if (ch == '\'' || ch == '"')
    {
      /* Read entity value. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_dtd_entity_internal_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_entity_value);
    }
  else if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** ExternalID. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_dtd_entity_general_extid_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid general entity definition", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip optional whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_general_extid_ndata;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Peek a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Put the character back into the input stream. */
  ssh_xml_ungetch(parser, ch);

  if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /* Maybe NDATA. */
      parser->lexer->continue_state
        = ssh_xml_st_dtd_entity_general_extid_ndata_name;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);
    }
  else
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_external_read);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Check whether the name was NDATA. */
  if (SSH_MATCH(parser->lexer->data, "NDATA"))
    {
      parser->lexer->continue_state
        = ssh_xml_st_dtd_entity_general_extid_ndata_data;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);
    }
  else
    {
      ssh_xml_error_not_well_formed(parser,
                                    "Malformed general entity declaration",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata_data)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Read the data. */
  parser->lexer->continue_state
    = ssh_xml_st_dtd_entity_general_extid_ndata_data_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_general_extid_ndata_data_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlEntity entity = parser->current_entity;

  if (entity)
    {
      /* Save the notation data. */
      entity->value.external.ndata = ssh_memdup(parser->lexer->data,
                                                parser->lexer->data_len);
      if (entity->value.external.ndata == NULL)
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      entity->value.external.ndata_len = parser->lexer->data_len;
    }

  /* Entity declaration parsed. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_external_read);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (ch != '%')
    {
      ssh_xml_error_not_well_formed(parser, "Invalid parameter reference",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_parameter_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read entity name. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_parameter_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  Boolean unique;

  /* Create a new parameter entity. */
  parser->current_entity = ssh_xml_insert_entity(parser,
                                                 parser->parameter_entities,
                                                 parser->input->name,
                                                 FALSE, parser->lexer->data,
                                                 parser->lexer->data_len,
                                                 &unique);
  if (parser->current_entity == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  if (!unique)
    {
      /* The first binding is used. */
      ssh_xml_warning(parser,
                      "Parameter entity `",parser->lexer->data,
                      "' defined more than once", NULL);
      parser->current_entity = NULL;
    }

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_entity_parameter_def;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_parameter_def)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Check the type of the definition. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }
  else if (ch == '\'' || ch == '"')
    {
      /* Read entity value. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_dtd_entity_internal_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_entity_value);
    }
  else if (SSH_XML_IS_NAME_FIRST_CHAR(ch))
    {
      /** ExternalID. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_dtd_entity_external_read;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      /** Not well-formed. */
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid parameter entity definition",
                                    NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_internal_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlEntity entity = parser->current_entity;

  /* Save the value.  Note that `entity' can be NULL if the entity is
     already defined. */
  if (entity)
    {
      entity->internal = 1;

      entity->value.internal.data = ssh_memdup(parser->lexer->data,
                                               parser->lexer->data_len);
      if (entity->value.internal.data == NULL)
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      entity->value.internal.data_len = parser->lexer->data_len;
    }

  /** An internal entity parsed. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_parsed);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_external_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlEntity entity = parser->current_entity;

  if (entity)
    {
      /* Steal the IDs. */
      entity->value.external.pubid = parser->data1;
      entity->value.external.pubid_len = parser->data1_len;
      entity->value.external.sysid = parser->data2;
      entity->value.external.sysid_len = parser->data2_len;
    }
  else
    {
      /* Free the IDs. */
      ssh_free(parser->data1);
      ssh_free(parser->data2);
    }
  parser->data1 = NULL;
  parser->data1_len = 0;
  parser->data2 = NULL;
  parser->data2_len = 0;

  /** Entity parsed. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_parsed);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlEntity entity = parser->current_entity;

  if (entity == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_parsed_cb);
      return SSH_FSM_CONTINUE;
    }

  /* Call DTD handler's entity callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_entity_parsed_cb);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->dtd_handler.entity_decl)
          {
            if (entity->internal)
              SSH_XML_HANDLER(dtd_handler.entity_decl)(
                                parser,
                                entity->header.name,
                                entity->header.name_len,
                                entity->general ? TRUE : FALSE,
                                TRUE,
                                entity->value.internal.data,
                                entity->value.internal.data_len,
                                NULL, 0, NULL, 0, NULL, 0,
                                ssh_xml_result_cb, thread,
                                parser->handler_context);
            else
              SSH_XML_HANDLER(dtd_handler.entity_decl)(
                                parser,
                                entity->header.name,
                                entity->header.name_len,
                                entity->general ? TRUE : FALSE,
                                FALSE,
                                NULL, 0,
                                entity->value.external.pubid,
                                entity->value.external.pubid_len,
                                entity->value.external.sysid,
                                entity->value.external.sysid_len,
                                entity->value.external.ndata,
                                entity->value.external.ndata_len,
                                ssh_xml_result_cb, thread,
                                parser->handler_context);
          }
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0)
  );
  SSH_NOTREACHED;
  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ssh_xml_st_dtd_entity_parsed_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* This entity is now handled. */
  parser->current_entity = NULL;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_decl_parsed;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_dtd_notation)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_notation_name;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_notation_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read notation name. */
  parser->lexer->continue_state = ssh_xml_st_dtd_notation_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_notation_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_dtd_notation_id;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_notation_id)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Save notation name. */
  parser->data3 = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (parser->data3 == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  parser->data3_len = parser->lexer->data_len;

  /** ExternalID or PublicID. */
  parser->lexer->continue_state = ssh_xml_st_dtd_notation_parsed;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id_notation);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_dtd_notation_parsed)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Call DTD handler's notation callback. */
  SSH_FSM_SET_NEXT(ssh_xml_st_dtd_notation_parsed_cb);
  SSH_FSM_ASYNC_CALL(
    do
      {
        if (parser->dtd_handler.notation_decl)
          SSH_XML_HANDLER(dtd_handler.notation_decl)(parser,
                                                     parser->data3,
                                                     parser->data3_len,
                                                     parser->data1,
                                                     parser->data1_len,
                                                     parser->data2,
                                                     parser->data2_len,
                                                     ssh_xml_result_cb, thread,
                                                     parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0);
  );
  SSH_NOTREACHED;
  return SSH_FSM_SUSPENDED;
}

SSH_FSM_STEP(ssh_xml_st_dtd_notation_parsed_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Free the name and IDs. */

  ssh_free(parser->data1);
  parser->data1 = NULL;
  parser->data1_len = 0;

  ssh_free(parser->data2);
  parser->data2 = NULL;
  parser->data2_len = 0;

  ssh_free(parser->data3);
  parser->data3 = NULL;
  parser->data3_len = 0;

  /** Skip whitespace and parse the declaration end. */
  parser->lexer->continue_state = ssh_xml_st_decl_parsed;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_xml_st_error)
{
#ifdef DEBUG_LIGHT
  SshXmlParser parser = (SshXmlParser) thread_context;
#endif /* DEBUG_LIGHT */

  /* Check that the parse result code is set. */
  SSH_ASSERT(parser->parse_result != SSH_XML_OK);

  SSH_FSM_SET_NEXT(ssh_xml_st_end);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_end)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  SSH_FSM_SET_NEXT(ssh_xml_st_end_cb);
  SSH_FSM_ASYNC_CALL(
    do
      {
        parser->end_document = 1;
        if (parser->content_handler.end_document)
          SSH_XML_HANDLER(content_handler.end_document)(
                                                parser,
                                                ssh_xml_result_cb, thread,
                                                parser->handler_context);
        else
          ssh_xml_result_cb(SSH_XML_OK, thread);
      }
    while (0)
  );
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_xml_st_end_cb)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Clear all dynamic state from the parser. */
  ssh_xml_parser_clear(parser, FALSE);

  /* Register a zero-timeout that call's user's parse result
     callback. */
  if (parser->result_cb)
    ssh_register_timeout(&parser->result_cb_timeout,
                         0, 0,
                         ssh_xml_parse_result_timeout, parser);

  /* And we are done with our parser thread. */
  return SSH_FSM_FINISH;
}


/* Sub-state machine for reading a name. */

SSH_FSM_STEP(ssh_xml_st_sub_read_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Init token buffer to empty. */
  parser->lexer->data_len = 0;
  parser->colon_seen = 0;
  parser->name_nmtoken = 0;

  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name_read_chars);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_nmtoken)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Init token buffer to empty. */
  parser->lexer->data_len = 0;
  parser->colon_seen = 0;
  parser->name_nmtoken = 1;

  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name_read_chars);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_name_read_chars)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** Name read. */
      SSH_FSM_SET_NEXT(parser->lexer->continue_state);
      return SSH_FSM_CONTINUE;
    }

  if (!parser->name_nmtoken && parser->lexer->data_len == 0)
    {
      /* This must be a valid name first character. */
      if (!SSH_XML_IS_NAME_FIRST_CHAR(ch))
        {
          /** Invalid name. */
          ssh_xml_error_not_well_formed(parser,
                                        "Invalid name first character", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
    }
  else
    {
      /* Non name characters terminate the name. */
      if (!SSH_XML_IS_NAME_CHAR(ch))
        {
          /* End of name. */
          ssh_xml_ungetch(parser, ch);

          /* Check the validity of ':' characters as the last
             character. */
          if (!parser->params.no_namespaces && !parser->in_enum
              && parser->colon_seen
              && parser->lexer->data[parser->lexer->data_len - 1] == ':')
            {
              /** Invalid name. */
              ssh_xml_error_not_well_formed(parser, "Invalid name", NULL);
              SSH_FSM_SET_NEXT(ssh_xml_st_error);
            }
          else
            {
              SSH_FSM_SET_NEXT(parser->lexer->continue_state);
            }
          return SSH_FSM_CONTINUE;
        }
    }

  /* Check for valid Namespace Constraint name. */
  if (!parser->params.no_namespaces && !parser->in_enum && ch == ':')
    {
      if (parser->colon_seen)
        {
          /** Invalid name. */
          ssh_xml_error_not_well_formed(parser,
                                        "The `:' character appeared more "
                                        "than once in a name", NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      parser->colon_seen = 1;
    }

  /* One more character for the name. */
  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Read more. */
  return SSH_FSM_CONTINUE;
}

/* Sub-state machine for skipping mandatory whitespace. */

SSH_FSM_STEP(ssh_xml_st_sub_mandatory_whitespace)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (!SSH_XML_IS_SPACE(ch))
    {
      ssh_xml_error_not_well_formed(parser, "Expected whitespace", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* We got one whitespace character.  Everything else is extra and
     therefore optional. */
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

/* Sub-state machine for skipping optional whitespace. */

SSH_FSM_STEP(ssh_xml_st_sub_optional_whitespace)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** All done. */
      SSH_FSM_SET_NEXT(parser->lexer->continue_state);
      return SSH_FSM_CONTINUE;
    }

  if (SSH_XML_IS_SPACE(ch))
    {
      /* Skip more whitespace. */
      parser->had_whitespace = 1;
      return SSH_FSM_CONTINUE;
    }

  ssh_xml_ungetch(parser, ch);

  /** All done. */
  SSH_FSM_SET_NEXT(parser->lexer->continue_state);
  return SSH_FSM_CONTINUE;
}

/* Sub-state machines for reading attribute values. */

SSH_FSM_STEP(ssh_xml_st_sub_read_entity_value)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  parser->literal_type = SSH_XML_LITERAL_ENTITY_VALUE;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_attribute_value)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  parser->literal_type = SSH_XML_LITERAL_ATTRIBUTE_VALUE;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_system_literal)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  parser->literal_type = SSH_XML_LITERAL_SYSTEM_LITERAL;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_pubid_literal)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  parser->literal_type = SSH_XML_LITERAL_PUBID_LITERAL;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_literal)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read the quote character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == '\'' || ch == '"')
    {
      parser->lexer->literal_endch = ch;
    }
  else
    {
      /** Invalid literal. */
      ssh_xml_error_not_well_formed(parser, "Invalid literal value", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Init token buffer to empty. */
  parser->lexer->data_len = 0;
  parser->in_literal = 1;

  /** Read attribute value. */
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal_chars);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_literal_chars)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Was it the terminator character?  It is not the terminator if the
     character did came from the expansion value of a general entity
     in a literal. */
  if (ch == parser->lexer->literal_endch
      && !(parser->input->general_entity && parser->input->from_literal))
    {
      /** Literal read. */
      parser->in_literal = 0;
      SSH_FSM_SET_NEXT(parser->lexer->continue_state);
      return SSH_FSM_CONTINUE;
    }

  /* Check references. */
  if ((ch == '%' && parser->literal_type == SSH_XML_LITERAL_ENTITY_VALUE)
      || (ch == '&'
          && (parser->literal_type == SSH_XML_LITERAL_ENTITY_VALUE
              || parser->literal_type == SSH_XML_LITERAL_ATTRIBUTE_VALUE)))
    {
      /* These references are parsed.  Or actually, in entity values,
         we parse only parameter and character references.  Our `read
         reference' sub-state machine is clever enough to detect this
         case and handle it for us. */
      if (!ssh_xml_push_lexer_frame(parser))
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      /* Read reference. */
      ssh_xml_ungetch(parser, ch);
      parser->lexer->continue_state = ssh_xml_st_sub_read_literal_reference;
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_reference);
      return SSH_FSM_CONTINUE;
    }

  /* Check that the character is valid for this literal type. */
  switch (parser->literal_type)
    {
    case SSH_XML_LITERAL_ENTITY_VALUE:
      /* The references were the only special cases and they are
         already handled above. */
      break;

    case SSH_XML_LITERAL_ATTRIBUTE_VALUE:
      /* Attribute-value normalization for whitespace characters. */
      if (SSH_XML_IS_SPACE(ch))
        ch = ' ';
      break;

    case SSH_XML_LITERAL_SYSTEM_LITERAL:
      /* No special characters for system literals. */
      break;

    case SSH_XML_LITERAL_PUBID_LITERAL:
      if (!SSH_XML_IS_PUBID_CHAR(ch))
        {
          /** Malformed literal. */
          ssh_xml_error_not_well_formed(parser,
                                        "Invalid character for pubid literal",
                                        NULL);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }
      break;
    }

  /* One character more read. */
  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Read more. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_literal_reference)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Pop lexer frame. */
  ssh_xml_pop_lexer_frame(parser);

  /* Parameter entity references in entity values are inserted as-is.
     They are not parsed again.  Therefore, we must detect the case
     here and append the new input stream into our literal value. */
  if (!parser->general_entity
      && parser->literal_type == SSH_XML_LITERAL_ENTITY_VALUE)
    {
      /** Reference value as-is. */
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal_reference_value_as_is);
      return SSH_FSM_CONTINUE;
    }

  /* This input frame is parsed. */

  /* Continue parsing literal. */
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal_chars);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_literal_reference_value_as_is)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (!parser->input->general_entity && !parser->input->parameter_entity)
    {
      /* The value of a general entity consumed.  Continue reading
         literal chars. */
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal_chars);
      return SSH_FSM_CONTINUE;
    }

  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Read more. */
  return SSH_FSM_CONTINUE;
}


/* Sub-state machine for reading references. */

SSH_FSM_STEP(ssh_xml_st_sub_read_reference)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch, ch2;
  Boolean eof;

  /* Check the type of the reference.  We need to peek two
     characters. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** Error. */
    eof:
      ssh_xml_error_premature_eof(parser);
    error:
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /* Peek the second character. */
  if (!ssh_xml_getch(parser, &ch2, &eof))
    {
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_CONDITION_WAIT(&parser->io_cond);
    }
  if (eof)
    goto eof;

  if (ch == '&')
    {
      /* Store the type of the entity. */
      parser->general_entity = 1;

      if (ch2 == '#')
        {
          /** CharRef. */
          SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_reference_charref);
          return SSH_FSM_CONTINUE;
        }
      else if (parser->in_literal
               && parser->literal_type == SSH_XML_LITERAL_ENTITY_VALUE)
        {
          /* General reference in entity value.  These are not
             expanded. */
          ssh_xml_pop_lexer_frame(parser);
          if (!ssh_xml_append(parser, parser->lexer, ch))
            {
              ssh_xml_error_out_of_memory(parser);
              goto error;
            }
          ssh_xml_ungetch(parser, ch2);

          /* Continue by reading literal chars. */
          SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_literal_chars);
          return SSH_FSM_CONTINUE;
        }
    }
  else if (ch == '%')
    {
      /* Store the type of the entity. */
      parser->general_entity = 0;
    }
  else
    {
      /** Invalid entity reference. */
      ssh_xml_error_not_well_formed(parser, "Invalid entity reference", NULL);
      goto error;
    }

  /* Check that the reference name is a valid name. */
  if (!SSH_XML_IS_NAME_FIRST_CHAR(ch2))
    {
      /** Invalid name. */
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid entity name first character",
                                    NULL);
      goto error;
    }
  else
    {
      if (!ssh_xml_append(parser, parser->lexer, ch2))
        {
          /** Out of memory. */
          ssh_xml_error_out_of_memory(parser);
          goto error;
        }
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_reference_read_chars);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_reference_charref)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** EOF. */
      ssh_xml_error_premature_eof(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == 'x')
    {
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_reference_charref_base16);
    }
  else
    {
      ssh_xml_ungetch(parser, ch);
      SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_reference_charref_base10);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_reference_charref_base10)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** Error. */
      ssh_xml_error_premature_eof(parser);
    error:
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == ';')
    {
      /** CharRef read.  Append it directly to our caller's token
          buffer. */
      ch = strtoul((char *) parser->lexer->data, NULL, 10);
      if (!ssh_xml_append(parser, parser->lexer->next, ch))
        {
          ssh_xml_error_out_of_memory(parser);
          goto error;
        }
      SSH_FSM_SET_NEXT(parser->lexer->continue_state);
      return SSH_FSM_CONTINUE;
    }

  if ('0' <= ch && ch <= '9')
    {
      /* Append this character. */
      if (!ssh_xml_append(parser, parser->lexer, ch))
        {
          ssh_xml_error_out_of_memory(parser);
          goto error;
        }
    }
  else
    {
      /* Invalid character. */
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid digit in a character reference",
                                    NULL);
      goto error;
    }

  /* Continue reading. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_reference_charref_base16)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Get a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /** Error. */
      ssh_xml_error_premature_eof(parser);
    error:
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == ';')
    {
      /** CharRef read.  Append it directly to our caller's token
          buffer. */
      ch = strtoul((char *) parser->lexer->data, NULL, 16);
      if (!ssh_xml_append(parser, parser->lexer->next, ch))
        {
          ssh_xml_error_out_of_memory(parser);
          goto error;
        }
      SSH_FSM_SET_NEXT(parser->lexer->continue_state);
      return SSH_FSM_CONTINUE;
    }

  if (('0' <= ch && ch <= '9')
      || ('a' <= ch && ch <= 'f')
      || ('A' <= ch && ch <= 'F'))
    {
      /* Append this character. */
      if (!ssh_xml_append(parser, parser->lexer, ch))
        {
          ssh_xml_error_out_of_memory(parser);
          goto error;
        }
    }
  else
    {
      /* Invalid character. */
      ssh_xml_error_not_well_formed(parser,
                                    "Invalid digit in a character constant",
                                    NULL);
      goto error;
    }

  /* Continue reading. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_reference_read_chars)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* Read a character. */
  if (!ssh_xml_getch(parser, &ch, &eof))
    SSH_FSM_CONDITION_WAIT(&parser->io_cond);

  if (eof)
    {
      /* Error. */
      ssh_xml_error_premature_eof(parser);
    error:
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  if (ch == ';')
    {
      /** Name read. */
      SSH_FSM_SET_NEXT(parser->lexer->continue_state);
      SSH_FSM_ASYNC_CALL(ssh_xml_resolve_entity(parser,
                                                (parser->general_entity
                                                 ? TRUE : FALSE),
                                                parser->lexer->data,
                                                parser->lexer->data_len,
                                                ssh_xml_resolve_entity_cb,
                                                thread));
      SSH_NOTREACHED;
    }
  if (!SSH_XML_IS_NAME_CHAR(ch))
    {
      ssh_xml_error_not_well_formed(parser, "Invalid reference name", NULL);
      goto error;
    }

  /* Append this character. */
  if (!ssh_xml_append(parser, parser->lexer, ch))
    {
      ssh_xml_error_out_of_memory(parser);
      goto error;
    }

  /* Continue reading. */
  return SSH_FSM_CONTINUE;
}

/* Sub-state machine for reading External IDs. */

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  parser->extid_notation = 0;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_notation)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  parser->extid_notation = 1;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_name)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Clear temporary state variables. */
  parser->data1 = NULL;
  parser->data1_len = 0;
  parser->data2 = NULL;
  parser->data2_len = 0;

  /* Push a fresh lexer frame since we call other sub-state
     machines. */
  if (!ssh_xml_push_lexer_frame(parser))
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /** Read name. */
  parser->lexer->continue_state = ssh_xml_st_sub_read_external_id_name_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_name);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_name_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Check the type of the external reference. */
  if (SSH_MATCH(parser->lexer->data, "PUBLIC"))
    {
      parser->extid_public = 1;
      parser->lexer->continue_state = ssh_xml_st_sub_read_external_id_public;
    }
  else if (SSH_MATCH(parser->lexer->data, "SYSTEM"))
    {
      parser->extid_public = 0;
      parser->lexer->continue_state = ssh_xml_st_sub_read_external_id_system;
    }
  else
    {
      /** Invalid external id type. */
      ssh_xml_error_not_well_formed(parser, "Invalid external ID type `",
                                    parser->lexer->data, "'", NULL);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }

  /** Skip whitespace. */
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_mandatory_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_public)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /** Read PubidLiteral. */
  parser->lexer->continue_state = ssh_xml_st_sub_read_external_id_public_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_pubid_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_public_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Save public ID. */
  parser->data1 = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (parser->data1 == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  parser->data1_len = parser->lexer->data_len;

  /** Skip whitespace. */
  parser->lexer->continue_state = ssh_xml_st_sub_read_external_id_system;



  SSH_FSM_SET_NEXT(ssh_xml_st_sub_optional_whitespace);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_system)
{
  SshXmlParser parser = (SshXmlParser) thread_context;
  SshXmlChar ch;
  Boolean eof;

  /* The SystemLiteral can be omitted from notation's PublicID. */
  if (parser->extid_public && parser->extid_notation)
    {
      /* Check if there is SystemLiteral. */
      if (!ssh_xml_getch(parser, &ch, &eof))
        SSH_FSM_CONDITION_WAIT(&parser->io_cond);

      if (eof)
        {
          /** EOF. */
          ssh_xml_error_premature_eof(parser);
          SSH_FSM_SET_NEXT(ssh_xml_st_error);
          return SSH_FSM_CONTINUE;
        }

      /* Put the character back to the input stream. */
      ssh_xml_ungetch(parser, ch);

      if (ch == '>')
        {
          /** SystemLitral omitted. */
          SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id_done);
          return SSH_FSM_CONTINUE;
        }
      /* The SystemLiteral is there.  Let's read it. */
    }

  /** Read SystemLiteral. */
  parser->lexer->continue_state = ssh_xml_st_sub_read_external_id_system_read;
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_system_literal);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_system_read)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Save system ID. */
  parser->data2 = ssh_memdup(parser->lexer->data, parser->lexer->data_len);
  if (parser->data2 == NULL)
    {
      /** Out of memory. */
      ssh_xml_error_out_of_memory(parser);
      SSH_FSM_SET_NEXT(ssh_xml_st_error);
      return SSH_FSM_CONTINUE;
    }
  parser->data2_len = parser->lexer->data_len;

  /** All done. */
  SSH_FSM_SET_NEXT(ssh_xml_st_sub_read_external_id_done);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_xml_st_sub_read_external_id_done)
{
  SshXmlParser parser = (SshXmlParser) thread_context;

  /* Pop lexer frame. */
  ssh_xml_pop_lexer_frame(parser);

  /** Return to our caller. */
  SSH_FSM_SET_NEXT(parser->lexer->continue_state);

  return SSH_FSM_CONTINUE;
}



/******************* Creating and destroying XML parsers ********************/

SshXmlParser
ssh_xml_parser_create(SshXmlParams params,
                      const SshXmlContentHandlerStruct *content_handler,
                      const SshXmlErrorHandlerStruct *error_handler,
                      const SshXmlDtdHandlerStruct *dtd_handler,
                      SshXmlEntityCB entity_resolver,
                      SshXmlParseDoneCB parse_done_cb,
                      void *handler_context)
{
  SshXmlParser parser;
  int i;
  Boolean unique;

  /* Allocate a parser object. */
  parser = ssh_calloc(1, sizeof(*parser));
  if (parser == NULL)
    return NULL;

  /* Store parameters. */
  if (params)
    parser->params = *params;

  /* Store handlers. */

  if (content_handler)
    parser->content_handler = *content_handler;
  if (error_handler)
    parser->error_handler = *error_handler;
  if (dtd_handler)
    parser->dtd_handler = *dtd_handler;

  parser->entity_resolver = entity_resolver;
  parser->parse_done_cb = parse_done_cb;
  parser->handler_context = handler_context;

  /* Create an unicode -> UTF-8 conversion module. */
  parser->output_conv = ssh_charset_init(SSH_CHARSET_UNICODE32,
                                         SSH_CHARSET_UTF8);
  if (parser->output_conv == NULL)
    goto error;

  /* Initialize entity bags. */
  parser->interned_names = ssh_xml_name_hash_create(parser);
  parser->general_entities = ssh_xml_name_hash_create(parser);
  parser->parameter_entities = ssh_xml_name_hash_create(parser);
  if (parser->interned_names == NULL
      || parser->general_entities == NULL
      || parser->parameter_entities == NULL)
    goto error;

  /* Initialize predefined entities. */
  for (i = 0; i < ssh_xml_pre_defined_entities_num_items; i++)
    {
      parser->current_entity
        = ssh_xml_insert_entity(
                        parser, parser->general_entities, NULL, TRUE,
                        (unsigned char *) ssh_xml_pre_defined_entities[i].name,
                        strlen(ssh_xml_pre_defined_entities[i].name),
                        &unique);
      if (parser->current_entity == NULL)
        {
          goto error;
        }
      else
        {
          SshXmlEntity entity = parser->current_entity;

          SSH_ASSERT(unique);

          entity->predefined = 1;
          entity->internal = 1;

          entity->value.internal.data_len
            = strlen(ssh_xml_pre_defined_entities[i].value);
          entity->value.internal.data
            = ssh_memdup(ssh_xml_pre_defined_entities[i].value,
                         entity->value.internal.data_len);
          if (entity->value.internal.data == NULL)
            goto error;
        }
    }
  parser->current_entity = NULL;

  /* Initialize FSM instance and its synchronization variables. */
  ssh_fsm_init(&parser->fsm, parser);
  ssh_fsm_condition_init(&parser->fsm, &parser->io_cond);

  /* All done. */
  return parser;


  /* Error handling. */

 error:

  ssh_xml_parser_destroy(parser);

  return NULL;
}


void
ssh_xml_parser_destroy(SshXmlParser parser)
{
  if (parser == NULL)
    return;

  /* Clear all dynamic state. */
  ssh_xml_parser_clear(parser, TRUE);

  /* Free the parser structure. */

  if (parser->output_conv)
    ssh_charset_free(parser->output_conv);

  if (parser->interned_names)
    ssh_adt_destroy(parser->interned_names);
  if (parser->general_entities)
    ssh_adt_destroy(parser->general_entities);
  if (parser->parameter_entities)
    ssh_adt_destroy(parser->parameter_entities);
  ssh_fsm_uninit(&parser->fsm);
  ssh_free(parser);
}


void
ssh_xml_parser_feature(SshXmlParser parser, const char *feature,
                       Boolean enable)
{
  if (strcmp(feature, SSH_XML_PARSER_NAMESPACES) == 0)
    parser->params.no_namespaces = !enable;
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("Unknown feature `%s'", feature));
    }
}


/*********************** Low-level parsing functions ************************/

/* Start parsing the input stream `stream' with the XML parser
   `parser'.  The argument `dtd' specifies whether the input stream
   contains DTD or XML data.  The parser will call the result callback
   `result_cb' when the parsing is complete. */
SshOperationHandle
ssh_xml_parser_parse_stream(SshXmlParser parser, Boolean dtd, SshStream stream,
                            const char *stream_name,
                            SshXmlDestructorCB destructor_cb,
                            void *destructor_cb_context,
                            SshXmlResultCB result_cb, void *context)
{
  /* No recursive parsing supported. */
  SSH_ASSERT(parser->result_cb == NULL_FNPTR);

  /* Push our input stream.. */
  if (!ssh_xml_push_input_stream(parser, stream, stream_name,
                                 SSH_XML_INPUT_ENC_UNKNOWN,
                                 destructor_cb, destructor_cb_context))
    {
      /* The stream was not freed in the error case. */
      ssh_stream_destroy(stream);
      if (destructor_cb)
        (*destructor_cb)(destructor_cb_context);
      goto error;
    }

  /* Push a top-level lexer frame. */
  if (!ssh_xml_push_lexer_frame(parser))
    goto error;

  /* Store completion callback and its context. */
  parser->result_cb = result_cb;
  parser->result_cb_context = context;

  /* Initialize the parser to top-level. */
  parser->standalone = 0;
  parser->parse_result = SSH_XML_OK;
  if (dtd)
    parser->dtd = 1;
  else
    parser->dtd = 0;
  parser->doctype_dtd = 0;
  parser->in_comment = 0;
  parser->in_literal = 0;
  parser->in_ignore = 0;
  parser->in_enum = 0;
  parser->ungetch_valid = 0;
  parser->blocked = 0;
  parser->at_eof = 0;
  parser->end_document = 0;
  parser->comment_end_len = 0;
  parser->include_nesting_count = 0;

  /* And start an FSM thread to parse the input stream. */
  ssh_fsm_thread_init(&parser->fsm, &parser->thread, ssh_xml_st_start_document,
                      NULL_FNPTR, NULL_FNPTR, parser);

  /* And return an operation handle for the parse operation. */
  ssh_operation_register_no_alloc(&parser->parse_handle,
                                  ssh_xml_parse_abort_cb, parser);
  return &parser->parse_handle;


  /* Error handling. */

 error:

  ssh_xml_parser_clear(parser, FALSE);

  (*result_cb)(SSH_XML_ERROR_MEMORY, context);
  return NULL;
}
