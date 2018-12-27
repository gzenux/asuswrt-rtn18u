/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Pretty print ASN.1 tree to stdout
*/

#include "sshincludes.h"
#include "sshber.h"
#include "sshasn1.h"
#include "sshasn1i.h"
#include "sshenum.h"

#ifdef SSHDIST_ASN1
/* Mapping between identity type name and doi identity type number */
const SshKeywordStruct ssh_asn1_error_codes[] =
{
  { "Ok", SSH_ASN1_STATUS_OK },
  { "Ok garbage at end", SSH_ASN1_STATUS_OK_GARBAGE_AT_END },
  { "Bad garbage at end", SSH_ASN1_STATUS_BAD_GARBAGE_AT_END },
  { "Operation failed", SSH_ASN1_STATUS_OPERATION_FAILED },
  { "Constructed assumed", SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED },
  { "List empty", SSH_ASN1_STATUS_LIST_EMPTY },
  { "Missing closing marker", SSH_ASN1_STATUS_MISSING_CLOSING_MARKER },
  { "Format string too short", SSH_ASN1_STATUS_FORMAT_STRING_TOO_SHORT },
  { "Unknown command", SSH_ASN1_STATUS_UNKNOWN_COMMAND },
  { "Format string ended", SSH_ASN1_STATUS_FORMAT_STRING_END },
  { "Node null", SSH_ASN1_STATUS_NODE_NULL },
  { "All null", SSH_ASN1_STATUS_ALL_NULL },
  { "No child", SSH_ASN1_STATUS_NO_CHILD },
  { "No parent", SSH_ASN1_STATUS_NO_PARENT },
  { "Ber open failed", SSH_ASN1_STATUS_BER_OPEN_FAILED },
  { "Ber step failed", SSH_ASN1_STATUS_BER_STEP_FAILED },
  { "Ber close failed", SSH_ASN1_STATUS_BER_CLOSE_FAILED },
  { "Ber decode failed", SSH_ASN1_STATUS_BER_DECODE_FAILED },
  { "Ber decode failed", SSH_ASN1_STATUS_BER_ENCODE_FAILED },
  { "Buffer overflow", SSH_ASN1_STATUS_BUFFER_OVERFLOW },
  { "Buffer too small", SSH_ASN1_STATUS_BUFFER_TOO_SMALL },
  { "Match not found", SSH_ASN1_STATUS_MATCH_NOT_FOUND },
  { "Choice too many matches", SSH_ASN1_STATUS_CHOICE_TOO_MANY_MATCHES },
  { "Not yet implemented", SSH_ASN1_STATUS_NOT_YET_IMPLEMENTED },
  { NULL, 0 }
};

/* Convert Asn1 status code to string */
const char *ssh_asn1_error_string(SshAsn1Status status)
{
  const char *string;

  string = ssh_find_keyword_name(ssh_asn1_error_codes, status);
  if (string == NULL)
    return "UNKNOWN CODE, update ssh_asn1_error_codes table in asn1.c";
  return string;
}

#ifdef DEBUG_LIGHT

static const SshKeywordStruct classes[] =
{
  { "univ", SSH_ASN1_CLASS_UNIVERSAL },
  { "appl", SSH_ASN1_CLASS_APPLICATION },
  { "cont", SSH_ASN1_CLASS_CONTEXT },
  { "priv", SSH_ASN1_CLASS_PRIVATE },
  { NULL, 0 }
};

static const SshKeywordStruct encodings[] =
{
  { "prim", SSH_ASN1_ENCODING_PRIMITIVE },
  { "cnst", SSH_ASN1_ENCODING_CONSTRUCTED },
  { NULL, 0 }
};

static const SshKeywordStruct length_encodings[] =
{
  { "def", SSH_ASN1_LENGTH_DEFINITE },
  { "ind", SSH_ASN1_LENGTH_INDEFINITE },
  { NULL, 0 }
};
static const SshKeywordStruct tags[] =
{
  { "reserved", SSH_ASN1_TAG_RESERVED_0 },
  { "boolean", SSH_ASN1_TAG_BOOLEAN },
  { "integer", SSH_ASN1_TAG_INTEGER },
  { "bit string", SSH_ASN1_TAG_BIT_STRING },
  { "octet string", SSH_ASN1_TAG_OCTET_STRING },
  { "null", SSH_ASN1_TAG_NULL },
  { "object identifier", SSH_ASN1_TAG_OID_TYPE },
  { "ode", SSH_ASN1_TAG_ODE_TYPE },
  { "eti", SSH_ASN1_TAG_ETI_TYPE },
  { "real", SSH_ASN1_TAG_REAL },
  { "enum", SSH_ASN1_TAG_ENUM },
  { "embedded", SSH_ASN1_TAG_EMBEDDED },
  { "utf8 string", SSH_ASN1_TAG_UTF8_STRING },
  { "reserved", SSH_ASN1_TAG_RESERVED_1 },
  { "reserved", SSH_ASN1_TAG_RESERVED_2 },
  { "reserved", SSH_ASN1_TAG_RESERVED_3 },
  { "sequence", SSH_ASN1_TAG_SEQUENCE },
  { "set", SSH_ASN1_TAG_SET },
  { "numeric string", SSH_ASN1_TAG_NUMERIC_STRING },
  { "printable string", SSH_ASN1_TAG_PRINTABLE_STRING },
  { "teletex string", SSH_ASN1_TAG_TELETEX_STRING },
  { "videotex string", SSH_ASN1_TAG_VIDEOTEX_STRING },
  { "ia5 string", SSH_ASN1_TAG_IA5_STRING },
  { "universal time", SSH_ASN1_TAG_UNIVERSAL_TIME },
  { "generalized time", SSH_ASN1_TAG_GENERALIZED_TIME },
  { "graphic string", SSH_ASN1_TAG_GRAPHIC_STRING },
  { "visible string", SSH_ASN1_TAG_VISIBLE_STRING },
  { "general string", SSH_ASN1_TAG_GENERAL_STRING },
  { "universal string", SSH_ASN1_TAG_UNIVERSAL_STRING },
  { "unrestricted string", SSH_ASN1_TAG_UNRESTRICTED_STRING },
  { "bmp string", SSH_ASN1_TAG_BMP_STRING },
  { "reserved", SSH_ASN1_TAG_RESERVED_4 },
  { NULL },
};

static void print_buf(unsigned char *buf, unsigned int length)
{
  int i;

  printf(" \"");
  for (i = 0; i < length; i++)
    {
      if (i > 0 && (i % 40) == 0)
        printf("\\  ");
      printf("%c", buf[i]);
    }
  printf("\"\n");
}

static void print_hex(unsigned char *buf, unsigned int length)
{
  int i;

  if (length == 0)
    {
      printf("\n");
      return;
    }

  printf("  : ");
  for (i = 0; i < length; i++)
    {
      if (i > 0)
        printf(" ");
      if (i > 0 && (i % (75/3)) == 0)
        printf("\n  : ");

      printf("%02x", (unsigned int)buf[i]);
    }
  printf("\n");
}

static void print_node(int level, SshAsn1Node node)
{
  SshAsn1Class classp;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  size_t length;
  unsigned char *data;
  SshAsn1Status status;
  int i;
  const char *name;

  if ((status = ssh_asn1_node_get(node, &classp, &encoding, &tag_number,
                                  &length_encoding,
                                  &length, &data)) != SSH_ASN1_STATUS_OK)
    {
      printf("error: status %d\n", status);
      exit(1);
    }

  printf("%04lu ", (unsigned long) length);

  name = ssh_find_keyword_name(classes, classp);
  if (name)
    printf(" %s", name);
  else
    printf(" unknown class[%d]", classp);

  name = ssh_find_keyword_name(encodings, encoding);
  if (name)
    printf(" %s", name);
  else
    printf(" unknown encoding[%u]", encoding);

  name = ssh_find_keyword_name(length_encodings, length_encoding);
  if (name)
    printf(" %s", name);
  else
    printf(" unknown length encoding[%d]", length_encoding);

  printf(": ");

  for (i = 0; i < level; i++)
    printf(". ");

  if (classp == SSH_ASN1_CLASS_UNIVERSAL)
    {
      name = ssh_find_keyword_name(tags, tag_number);
      if (name)
        printf(" %s", name);
      else
        printf("*** universal, yet unknown ***");
    }
  else
    printf(" %u", (unsigned int)tag_number);

  if (classp == SSH_ASN1_CLASS_UNIVERSAL)
    switch (tag_number)
      {
      case SSH_ASN1_TAG_SET:
      case SSH_ASN1_TAG_SEQUENCE:
        printf("\n");
        break;

      case SSH_ASN1_TAG_OCTET_STRING:
        printf("\n");
        print_hex(data, length);
        break;
      case SSH_ASN1_TAG_VISIBLE_STRING:
      case SSH_ASN1_TAG_PRINTABLE_STRING:
      case SSH_ASN1_TAG_TELETEX_STRING:
      case SSH_ASN1_TAG_IA5_STRING:
        print_buf(data, length);
        break;
      case SSH_ASN1_TAG_GENERALIZED_TIME:
      case SSH_ASN1_TAG_UNIVERSAL_TIME:
      default:
        printf("\n");
        print_hex(data, length);
        break;
      }
  else
    {
      printf("\n");
      print_hex(data, length);
    }

  /* Remember to free what you've allocated. */
  ssh_free(data);
}

void ssh_asn1_print_node_recurse(SshAsn1Node node, int level)
{
  SshAsn1Node sub;

  do
    {
      print_node(level, node);
      if ((sub = ssh_asn1_node_child(node)) != NULL)
        {
          level++;
          ssh_asn1_print_node_recurse(sub, level);
          level--;
          node = ssh_asn1_node_parent(sub);
        }
    }
  while ((node = ssh_asn1_node_next(node)) != NULL);
}

void ssh_asn1_print_tree(SshAsn1Tree tree)
{
  ssh_asn1_print_node_recurse(ssh_asn1_get_root(tree), 0);
}

void ssh_asn1_print_node(SshAsn1Node node)
{
  ssh_asn1_print_node_recurse(node, 0);
}

#endif /* DEBUG_LIGHT */
#endif /* SSHDIST_ASN1 */
