/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the certificate request message formats, as
   described in RFC-2511, March 1999.
*/

#include "sshincludes.h"
#include "sshasn1.h"
#include "oid.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertCrmf"

#define BAILOUT(_rv,_code)      \
do {                            \
  (_rv) = (_code);              \
  goto bailout;                 \
} while (0)

SshX509Status
ssh_crmf_decode_encrypted_value(const unsigned char *buf,
                                size_t len,
                                SshX509EncryptedValue *value_return)
{
  SshAsn1Context asn1context;
  SshX509Status rv = SSH_X509_OK;
  SshAsn1Node node;
  Boolean intended_found, symmetric_found, key_found, keyalg_found, hint_found;
  SshAsn1Node intendednode, symmetricnode, keyalgnode;
  Boolean ignored_found, params_found;
  SshAsn1Node ignorednode, paramsnode;
  unsigned char *key, *hint, *data;
  size_t keylen, hintlen, datalen;
  SshX509EncryptedValue value = NULL;
  char *oids;
  const SshOidStruct *oid;
  SshAsn1Status status;

  if ((asn1context = ssh_asn1_init()) == NULL)
    BAILOUT(rv, SSH_X509_FAILURE);

  status = ssh_asn1_decode_node(asn1context, buf, len, &node);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    BAILOUT(rv, SSH_X509_FAILED_ASN1_DECODE);

  if (ssh_asn1_read_node(asn1context, node,
                         "(sequence ()"
                         "  (optional (any (0)))"
                         "  (optional (any (1)))"
                         "  (optional (bit-string (2)))"
                         "  (optional (any (3)))"
                         "  (optional (octet-string (4)))"
                         "  (bit-string ()))",
                         &intended_found, &intendednode,
                         &symmetric_found, &symmetricnode,
                         &key_found, &key, &keylen,
                         &keyalg_found, &keyalgnode,
                         &hint_found, &hint, &hintlen,
                         &data, &datalen)
      == SSH_ASN1_STATUS_OK)
    {
      if ((value = ssh_calloc(1, sizeof(*value))) == NULL)
        BAILOUT(rv, SSH_X509_FAILED_ASN1_DECODE);

      if (intended_found)
        {
          if (ssh_asn1_read_node(asn1context, intendednode,
                                 "(sequence (0)"
                                 "  (object-identifier ())"
                                 "  (optional (any ())))",
                                 &oids,
                                 &ignored_found, &ignorednode)
              == SSH_ASN1_STATUS_OK)
            {
              if ((oid = ssh_oid_find_by_oid(oids)) == NULL ||
                  (value->intended_alg = ssh_strdup(oid->std_name)) == NULL)
                {
                  ssh_free(oids);
                  BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
                }
              ssh_free(oids);
            }
          else
            BAILOUT(rv, SSH_X509_FAILED_ASN1_DECODE);
        }

      if (symmetric_found)
        {
          if (ssh_asn1_read_node(asn1context, symmetricnode,
                                 "(sequence (1)"
                                 "  (object-identifier ())"
                                 "  (optional (any ())))",
                                 &oids,
                                 &params_found, &paramsnode)
              == SSH_ASN1_STATUS_OK)
            {
              if ((oid = ssh_oid_find_by_oid(oids)) == NULL ||
                  (value->symmetric_alg = ssh_strdup(oid->name)) == NULL)
                {
                  ssh_free(oids);
                  BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
                }
              ssh_free(oids);

              /* At this time we only support params for DES/3DES */
              if (!strncmp(oid->name, "des", 3) ||
                  !strncmp(oid->name, "3des", 4))
                {
                  if (ssh_asn1_read_node(asn1context, paramsnode,
                                         "(octet-string ())",
                                         &value->symmetric_alg_iv,
                                         &value->symmetric_alg_iv_len)
                      != SSH_ASN1_STATUS_OK)
                    BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
                }
              else
                BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
            }
          else
            BAILOUT(rv, SSH_X509_FAILED_ASN1_DECODE);
        }

      if (key_found)
        {
          value->encrypted_sym_key = key;
          value->encrypted_sym_key_len = keylen / 8;
        }

      if (keyalg_found)
        {
          if (ssh_asn1_read_node(asn1context, keyalgnode,
                                 "(sequence (3)"
                                 "  (object-identifier ())"
                                 "  (optional (any ())))",
                                 &oids,
                                 &ignored_found, &ignorednode)
              == SSH_ASN1_STATUS_OK)
            {
              if ((oid = ssh_oid_find_by_oid(oids)) == NULL ||
                  (value->key_alg = ssh_strdup(oid->std_name)) == NULL)
                {
                  ssh_free(oids);
                  BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
                }
              ssh_free(oids);
            }
          else
            BAILOUT(rv, SSH_X509_FAILED_ASN1_DECODE);
        }

      if (hint_found)
        {
          value->value_hint = hint;
          value->value_hint_len = hintlen;
        }

      value->encrypted_value = data;
      value->encrypted_value_len = datalen / 8;
    }

 bailout:
  if (rv != SSH_X509_OK)
    {
      if (value)
        ssh_crmf_encrypted_value_free(value);
    }
  else
    *value_return = value;

  ssh_asn1_free(asn1context);

  return rv;
}

SshX509EncryptedValue ssh_crmf_encrypted_value_allocate(void)
{
  SshX509EncryptedValue value;

  if ((value = ssh_malloc(sizeof(*value))) != NULL)
    {
      ssh_x509_encrypted_value_init(value);
    }
  return value;
}

void ssh_crmf_encrypted_value_free(SshX509EncryptedValue value)
{
  ssh_x509_encrypted_value_clear(value);
  ssh_free(value);
}


SshX509Status
ssh_crmf_encode_encrypted_value(const SshX509EncryptedValue value,
                                unsigned char **buf, size_t *buf_len)
{
  SshAsn1Context asn1context;
  SshAsn1Node intendednode, symmetricnode, keynode, keyalgnode, hintnode;
  SshAsn1Node node;
  const SshOidStruct *oid;
  SshX509Status rv = SSH_X509_FAILURE;

  if ((asn1context = ssh_asn1_init()) == NULL)
    return rv;

  if (value->intended_alg)
    {
      oid = ssh_oid_find_by_std_name_of_type(value->intended_alg, SSH_OID_PK);
      if (oid)
        ssh_asn1_create_node(asn1context, &intendednode,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (null ()))",
                             oid->oid);
      else
        BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
    }
  else
    intendednode = NULL;

  if (value->symmetric_alg)
    {
      oid = ssh_oid_find_by_alt_name_of_type(value->symmetric_alg,
                                             SSH_OID_CIPHER);
      if (oid)
        ssh_asn1_create_node(asn1context, &symmetricnode,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (octet-string ()))",
                             oid->oid,
                             value->symmetric_alg_iv,
                             value->symmetric_alg_iv_len);
      else
        BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
    }
  else
    symmetricnode = NULL;

  if (value->encrypted_sym_key)
    {
      ssh_asn1_create_node(asn1context, &keynode,
                           "(bit-string (2))",
                           value->encrypted_sym_key,
                           8 * value->encrypted_sym_key_len);
    }
  else
    keynode = NULL;

  if (value->key_alg)
    {
      oid = ssh_oid_find_by_std_name_of_type(value->key_alg, SSH_OID_PK);
      if (oid)
        ssh_asn1_create_node(asn1context, &keyalgnode,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (null ()))",
                             oid->oid);
      else
        BAILOUT(rv, SSH_X509_FAILED_UNKNOWN_VALUE);
    }
  else
    keyalgnode = NULL;

  if (value->value_hint)
    {
      ssh_asn1_create_node(asn1context, &hintnode,
                           "(octet-string (4))",
                           value->value_hint, value->value_hint_len);
    }
  else
    hintnode = NULL;

  if (ssh_asn1_create_node(asn1context, &node,
                           "(sequence ()"
                           "  (any (0))" /* intendedAlg */
                           "  (any (1))" /* symmAlg */
                           "  (any ())"  /* encSymmKey */
                           "  (any (3))" /* keyAlg */
                           "  (any ())"  /* valueHint */
                           "  (bit-string ()))",
                           intendednode,
                           symmetricnode,
                           keynode,
                           keyalgnode,
                           hintnode,
                           value->encrypted_value,
                           8 * value->encrypted_value_len)
      == SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_encode_node(asn1context, node);
      ssh_asn1_node_get_data(node, buf, buf_len);
      rv = SSH_X509_OK;
    }
  else
    rv = SSH_X509_FAILED_ASN1_ENCODE;

 bailout:
  ssh_asn1_free(asn1context);
  return rv;
}
#endif /* SSHDIST_CERT */
