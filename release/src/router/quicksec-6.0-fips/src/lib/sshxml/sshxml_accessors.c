/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Accessor methods for names, attributes, attribute definitions, and
   locations.
*/

#include "sshincludes.h"
#include "sshxml_internal.h"

/***************************** Public functions *****************************/

Boolean
ssh_xml_match(const unsigned char *name, size_t name_len,
              const unsigned char *string, size_t string_len)
{
  if (name_len == 0)
    name_len = strlen((char *) name);

  if (string_len == 0)
    string_len = strlen((char *) string);

  if (name_len != string_len)
    return FALSE;

  return memcmp(name, string, string_len) == 0;
}


const unsigned char *
ssh_xml_get_local_name(SshXmlParser parser,
                       const unsigned char *name, size_t name_len,
                       size_t *local_name_len_return)
{
  size_t i;

  for (i = 0; i < name_len; i++)
    if (name[i] == ':')
      {
        if (local_name_len_return)
          *local_name_len_return = name_len - i - 1;

        return name + i + 1;
      }

  if (local_name_len_return)
    *local_name_len_return = name_len;

  return name;
}


const unsigned char *
ssh_xml_get_namespace(SshXmlParser parser,
                      const unsigned char *name, size_t name_len,
                      size_t *namespace_name_len_return)
{
  size_t i;
  SshXmlElement element;
  SshXmlNamespace ns;

  /* Get the namespace prefix. */
  for (i = 0; i < name_len; i++)
    if (name[i] == ':')
      {
        /* Found a namespace prefix. */
        for (element = parser->parse_tree; element; element = element->next)
          for (ns = element->namespaces; ns; ns = ns->next)
            if (ns->prefix_len == i && memcmp(ns->prefix, name, i) == 0)
              {
                /* Found a match. */
                if (namespace_name_len_return)
                  *namespace_name_len_return = strlen((char*) ns->uri);
                return ns->uri;
              }
      }

  /* No namespace prefix.  Lookup the default namespace. */
  for (element = parser->parse_tree; element; element = element->next)
    if (element->default_namespace)
      {
        if (element->default_namespace[0])
          {
            /* We had a non-zero default namespace. */
            if (namespace_name_len_return)
              *namespace_name_len_return =
                strlen((char *) element->default_namespace);
            return element->default_namespace;
          }
        else
          /* An empty namespace URI disables the default namespace. */
          return NULL;
      }

  return NULL;
}


const unsigned char *
ssh_xml_get_attr_namespace(SshXmlParser parser,
                           const unsigned char *name, size_t name_len,
                           size_t *namespace_name_len_return)
{
  size_t i;

  /* Get the namespace prefix. */
  for (i = 0; i < name_len; i++)
    if (name[i] == ':')
      {
        /* Found the namespace prefix. */
        return ssh_xml_get_namespace(parser, name, name_len,
                                     namespace_name_len_return);
      }

  /* Attributes do not have default namespace. */
  return NULL;
}


SshADTHandle
ssh_xml_get_attr_handle_by_name(SshADTContainer attributes,
                                const unsigned char *name, size_t name_len)
{
  SshXmlAttributeStruct attr_struct;

  memset(&attr_struct, 0, sizeof(attr_struct));
  attr_struct.header.name = (unsigned char *)name;

  if (name_len == 0)
    name_len = strlen((char *) name);

  attr_struct.header.name_len = name_len;

  return ssh_adt_get_handle_to_equal(attributes, &attr_struct);
}


const unsigned char *
ssh_xml_attr_handle_get_name(SshADTContainer attributes,
                             SshADTHandle handle, size_t *name_len_return)
{
  SshXmlAttribute attr = ssh_adt_get(attributes, handle);

  if (attr == NULL)
    return NULL;

  if (name_len_return)
    *name_len_return = attr->header.name_len;

  return attr->header.name;
}


const unsigned char *
ssh_xml_attr_handle_get_value(SshADTContainer attributes,
                              SshADTHandle handle,
                              size_t *value_len_return)
{
  SshXmlAttribute attr = ssh_adt_get(attributes, handle);

  if (attr == NULL)
    return NULL;

  if (value_len_return)
    *value_len_return = attr->value_len;

  return attr->value;
}


const unsigned char *
ssh_xml_get_attr_value(SshADTContainer attributes,
                       const unsigned char *name, size_t name_len,
                       size_t *value_len_return)
{
  SshADTHandle h;

  h = ssh_xml_get_attr_handle_by_name(attributes, name, name_len);
  if (h == SSH_ADT_INVALID)
    return NULL;

  return ssh_xml_attr_handle_get_value(attributes, h, value_len_return);
}


void
ssh_xml_attr_value_enum_init(SshADTContainer attributes,
                             const unsigned char *attr_name,
                             size_t attr_name_len,
                             SshXmlAttrEnumType enum_type,
                             SshXmlAttrEnumCtx enum_ctx)
{
  const unsigned char *value;
  size_t value_len = 0;

  value = ssh_xml_get_attr_value(attributes, attr_name, attr_name_len,
                                 &value_len);
  ssh_xml_value_enum_init(value, value_len, enum_type, enum_ctx);
}


const unsigned char *
ssh_xml_attr_value_enum_next(SshXmlAttrEnumCtx enum_ctx,
                             size_t *value_len_return)
{
  size_t start;
  SshXmlChar ch;

  if (enum_ctx->value == NULL)
    {
    done:
      *value_len_return = 0;
      return NULL;
    }

  /* Skip leading whitespace. */
  while (1)
    {
      start = enum_ctx->pos;

      if (!ssh_xml_value_enum_next_char(enum_ctx, &ch))
        goto done;

      if (!SSH_XML_IS_SPACE(ch))
        break;
    }

  /* Now we have the first character in `ch'.  Check that it is valid
     for the enumeration type. */
  switch (enum_ctx->type)
    {
    case SSH_XML_ATTR_ENUM_IDREFS:
    case SSH_XML_ATTR_ENUM_ENTITIES:
      if (!SSH_XML_IS_NAME_FIRST_CHAR(ch))
        {
          enum_ctx->invalid = 1;
          goto done;
        }
      break;

    case SSH_XML_ATTR_ENUM_NMTOKENS:
      if (!SSH_XML_IS_NAME_CHAR(ch))
        {
          enum_ctx->invalid = 1;
          goto done;
        }
      break;
    }

  /* Read more chacters. */
  while (1)
    {
      size_t pos = enum_ctx->pos;

      if (!ssh_xml_value_enum_next_char(enum_ctx, &ch) || SSH_XML_IS_SPACE(ch))
        {
          /* End of token reached. */
          enum_ctx->pos = pos;
          break;
        }

      if (!SSH_XML_IS_NAME_CHAR(ch))
        {
          enum_ctx->invalid = 1;
          goto done;
        }
    }

  *value_len_return = enum_ctx->pos - start;

  return enum_ctx->value + start;
}


/********************** Locations in the input stream ***********************/

void
ssh_xml_location(SshXmlParser parser,
                 const char **input_stream_name_return,
                 SshUInt32 *linenum_return,
                 SshUInt32 *column_return)
{
  SshXmlInputStruct empty_input = {0};
  SshXmlInput input;

  input = parser->input;
  if (input == NULL)
    input = &empty_input;

  if (input_stream_name_return)
    *input_stream_name_return = input->name;
  if (linenum_return)
    *linenum_return = input->line;
  if (column_return)
    *column_return = input->column;
}
