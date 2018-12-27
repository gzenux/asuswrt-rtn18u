/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SCEP protocol, common code for client and server.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshinet.h"
#include "sshasn1.h"
#include "x509.h"
#include "x509internal.h"

#include "sshpkcs7.h"
#include "x509scep.h"
#include "sshfsm.h"
#include "scep-internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshX509Scep"

SshX509Attribute
scep_add_attribute(SshX509Attribute next,
                   unsigned int ber_tag_type,
                   const char *oid, const unsigned char *data, size_t data_len)
{
  SshX509Attribute a = ssh_calloc(1, sizeof(*a));
  SshAsn1Node node;
  SshAsn1Context context;
  SshAsn1Status rv;

  if (!a)
    return NULL;

  a->type = SSH_X509_ATTR_UNKNOWN;
  if ((a->oid = ssh_strdup(oid)) == NULL)
    {
      ssh_free(a);
      return NULL;
    }
  a->next = next;

  if (data == NULL)
    return a;

  if ((context = ssh_asn1_init()) == NULL)
    {
      ssh_free(a);
      return NULL;
    }

  if (data_len == 0)
    data_len = strlen((const char *)data);

  switch (ber_tag_type)
    {
    case SSH_ASN1_TAG_PRINTABLE_STRING:
      rv = ssh_asn1_create_node(context, &node,
                                "(set () (printable-string ()))",
                                data, data_len);
      break;
    case SSH_ASN1_TAG_OCTET_STRING:
      rv = ssh_asn1_create_node(context, &node,
                                "(set () (octet-string ()))",
                                data, data_len);
      break;
    default:
      rv = SSH_ASN1_STATUS_OPERATION_FAILED;
      SSH_NOTREACHED;
    }

  if (rv == SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_encode_node(context, node);
      ssh_asn1_node_get_data(node, &a->data, &a->len);
    }
  else
    {
      ssh_free(a);
      a = NULL;
    }
  ssh_asn1_free(context);
  return a;
}

static char *toprintable(const unsigned char *octets, size_t len)
{
  SshMPIntegerStruct si;
  char *buf;
  int i;

  ssh_mprz_init(&si);
  ssh_mprz_set_buf(&si, octets, len);
  buf = ssh_mprz_get_str(&si, 16);

  if (buf == NULL)
    return NULL;

  ssh_mprz_clear(&si);
  for (i = strlen(buf); i != 0;)
    {
      if (islower((unsigned char)buf[i-1]))
        buf[i-1] = toupper((unsigned char)buf[i-1]);
      i--;
    }
  return buf;
}

SshX509Attribute
scep_add_attributes(char *type,
                    char *status, char *failure,
                    unsigned char *snonce, size_t snonce_len,
                    unsigned char *rnonce, size_t rnonce_len,
                    unsigned char *txid, size_t txid_len)
{
  SshX509Attribute attrs = NULL;

  if (txid_len == 32)
    attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_PRINTABLE_STRING,
                               SCEP_TXID, txid, txid_len);
  else
    {
      char *buf = toprintable(txid, txid_len);
      if (buf == NULL)
        return NULL;

      attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_PRINTABLE_STRING,
                                 SCEP_TXID, (unsigned char *)buf + 2,
                                 strlen(buf + 2));
      ssh_free(buf);
    }

  if (snonce && snonce_len)
    {
      attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_OCTET_STRING,
                                 SCEP_SNONCE, snonce, snonce_len);
    }

  if (rnonce && rnonce_len)
    {
#if 0
      char *buf = toprintable(rnonce, rnonce_len);
      attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_OCTET_STRING,
                                 SCEP_RNONCE, (unsigned char *)buf+2,
                                 strlen(buf + 2));
      ssh_free(buf);
#else
      attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_OCTET_STRING,
                                 SCEP_RNONCE, rnonce, rnonce_len);
#endif
    }

  attrs = scep_add_attribute(attrs, 0, "1.2.840.113549.1.9.4", NULL, 0);
  attrs = scep_add_attribute(attrs, 0, "1.2.840.113549.1.9.3", NULL, 0);

  if (failure && failure[0])
    attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_PRINTABLE_STRING,
                               SCEP_FINFO, (const unsigned char *)failure, 0);

  if (status && status[0])
    attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_PRINTABLE_STRING,
                               SCEP_STATUS, (const unsigned char *)status, 0);

  attrs = scep_add_attribute(attrs, SSH_ASN1_TAG_PRINTABLE_STRING,
                             SCEP_TXTYPE, (const unsigned char *)type, 0);

  return attrs;
}



Boolean scep_decode_string_attribute(SshAsn1Context context,
                                     SshX509Attribute attr,
                                     unsigned char **str,
                                     size_t *strlen)
{
  SshAsn1Status rv;
  SshAsn1Node node;

  if (ssh_asn1_decode_node(context, attr->data, attr->len, &node)
      == SSH_ASN1_STATUS_OK)
    {
      rv = ssh_asn1_read_node(context, node,
                              "(set () (printable-string ()))",
                              str, strlen);
      if (rv == SSH_ASN1_STATUS_OK)
        return TRUE;
      rv = ssh_asn1_read_node(context, node,
                              "(set () (octet-string ()))",
                              str, strlen);
      if (rv == SSH_ASN1_STATUS_OK)
        return TRUE;
    }
  return FALSE;
}
#endif /* SSHDIST_CERT */
