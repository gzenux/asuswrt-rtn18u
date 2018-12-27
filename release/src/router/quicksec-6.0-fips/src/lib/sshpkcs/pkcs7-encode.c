/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoding.

   This library can handle BER or DER encoded PKCS#7 messages, however,
   it produces DER messages. This is because the underlaying ASN.1
   BER/DER code is biased towards DER.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "sshber.h"
#include "sshgetput.h"
#include "sshglist.h"

#include "x509.h"
#include "x509internal.h"
#include "oid.h"
#include "sshpkcs5.h"
#include "pkcs6.h"
#include "sshpkcs7.h"
#include "pkcs7-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPkcs7Encode"

SshPkcs7Status
ssh_pkcs7_encode_data(SshPkcs7 pkcs7,
                      unsigned char **data, size_t *data_length);

static SshPkcs7Status
ssh_pkcs7_recursive_encode(SshAsn1Context context,
                           SshPkcs7 pkcs7,
                           SshAsn1Node *root);




static SshPkcs7Status
ssh_pkcs7_encode_oids(SshAsn1Context context,
                      SshGList list, SshAsn1Node *node)
{
  SshAsn1Status rv;
  SshAsn1Node   params_node, asn1_node, asn1_list = NULL;
  SshGListNode  list_node;
  char *oid;

  SSH_DEBUG(5, ("Encode lists of algorithm identifiers."));

  asn1_list = NULL;
  for (list_node = list->head; list_node; list_node = list_node->next)
    {
      /* Take the oid from the list.  Create parameters, none at the
         moment, then encode and add the result to list. */
      oid = list_node->data;
      params_node = NULL;

      /* No need to care about the result, NULL params node is OK, and
         if out of memory, the next create will fail anyway. */
      (void) ssh_asn1_create_node(context, &params_node, "(null ())");

      rv = ssh_asn1_create_node(context, &asn1_node,
                                "(sequence ()"
                                "  (object-identifier ())"
                                "  (any ()))",
                                oid,
                                params_node);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;

      asn1_list = ssh_asn1_add_list(asn1_list, asn1_node);
    }

  /* The encoded list is ok. */
  *node = asn1_list;
  return SSH_PKCS7_OK;
}

SshPkcs7Status ssh_pkcs7_encode_signer_infos(SshAsn1Context context,
                                             SshGList       glist,
                                             SshAsn1Node   *node_return)
{
  SshAsn1Status rv;
  SshAsn1Node list, node, auth_attr, unauth_attr;
  SshAsn1Node issuer_node, d_params, de_params;
  SshGListNode gnode;
  SshMPIntegerStruct version;
  const char *d_algorithm, *de_algorithm;

  SSH_DEBUG(5, ("Encode list of signer infos."));

  ssh_mprz_init_set_ui(&version, 1);
  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshPkcs7SignerInfo signer = gnode->data;
      size_t der_len;
      unsigned char *der;

      ssh_x509_name_reset(signer->issuer_name);
      if (!ssh_x509_name_pop_der_dn(signer->issuer_name, &der, &der_len))
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
      if (der_len == 0)
        {
          /* We may have received this name such that it was not der
             encoded (e.g. came from user without
             ssh_x509_cert_encode()) having been called. Now encode
             name with crypto library default rules. */
          ssh_free(der); ssh_x509_name_reset(signer->issuer_name);
          ssh_x509_encode_dn_name(context, signer->issuer_name->type,
                                  signer->issuer_name,
                                  ssh_x509_get_configuration());
          ssh_x509_name_pop_der_dn(signer->issuer_name, &der, &der_len);
        }
      rv = ssh_asn1_decode_node(context, der, der_len, &issuer_node);
      ssh_free(der);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;

      d_algorithm = ssh_pkcs7_algorithm_oids(signer->digest_algorithm);
      (void) ssh_asn1_create_node(context, &d_params, "(null ())");

      de_algorithm =
        ssh_pkcs7_algorithm_oids(signer->digest_encryption_algorithm);
      (void) ssh_asn1_create_node(context, &de_params, "(null ())");

      if (signer->auth_attributes)
        ssh_pkcs6_attr_encode_asn1(context,
                                   signer->auth_attributes, &auth_attr);
      else
        auth_attr = NULL;

      if (signer->unauth_attributes)
        ssh_pkcs6_attr_encode_asn1(context,
                                   signer->unauth_attributes, &unauth_attr);
      else
        unauth_attr = NULL;

      /* Encode ASN.1 */
      rv = ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                "  (integer ())"
                                "  (sequence ()"
                                "    (any ())"
                                "    (integer ()))"
                                "  (sequence ()"
                                "    (object-identifier ())"
                                "    (any ()))"
                                "  (any (0))"
                                "  (sequence ()"
                                "    (object-identifier ())"
                                "    (any ()))"
                                "  (octet-string ())"
                                "  (any (1)))",
                                &version,
                                issuer_node,
                                &signer->serial_number,
                                d_algorithm,
                                d_params,
                                auth_attr,
                                de_algorithm,
                                de_params,
                                signer->encrypted_digest,
                                signer->encrypted_digest_length,
                                unauth_attr);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          ssh_mprz_clear(&version);
          return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }
      list = ssh_asn1_add_list(list, node);
    }

  ssh_mprz_clear(&version);
  *node_return = list;
  return SSH_PKCS7_OK;
}
static SshPkcs7Status
ssh_pkcs7_encode_certs(SshAsn1Context context,
                       SshGList glist, SshAsn1Node *node_return)
{
  SshAsn1Node   list, node;
  SshGListNode  gnode;
  SshAsn1Status status;

  SSH_DEBUG(5, ("Encode list of certificates."));

  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshPkcs6Cert pcert = gnode->data;

      if (pcert->ber_buf == NULL)
        return SSH_PKCS7_PKCS6_CERT_NOT_ENCODED;

      status = ssh_asn1_decode_node(context,
                                    pcert->ber_buf, pcert->ber_length,
                                    &node);

      if (status == SSH_ASN1_STATUS_OK ||
          status == SSH_ASN1_STATUS_OK_GARBAGE_AT_END ||
          status == SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
        list = ssh_asn1_add_list(list, node);
      else
        return SSH_PKCS7_ASN1_DECODING_FAILED;
    }

  *node_return = list;
  return SSH_PKCS7_OK;
}
static SshPkcs7Status
ssh_pkcs7_encode_crls(SshAsn1Context context,
                      SshGList glist, SshAsn1Node *node_return)
{
  SshAsn1Node   list, node;
  SshGListNode  gnode;

  SSH_DEBUG(5, ("Encode list of CRLs."));

  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshPkcs6Crl crl = gnode->data;

      if (crl->ber_buf == NULL)
        return SSH_PKCS7_PKCS6_CRL_NOT_ENCODED;

      if (ssh_asn1_decode_node(context,
                               crl->ber_buf, crl->ber_length,
                               &node) != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_DECODING_FAILED;
      else
        list = ssh_asn1_add_list(list, node);
    }
  *node_return = list;
  return SSH_PKCS7_OK;
}



static SshPkcs7Status
ssh_pkcs7_encode_recipient_infos(SshAsn1Context context,
                                 SshGList glist, SshAsn1Node *node_return)
{
  SshAsn1Status rv;
  SshAsn1Node   list, node, issuer_node, ke_params = NULL;
  SshGListNode  gnode;
  SshMPIntegerStruct        version;
  const char   *ke_algorithm;

  SSH_DEBUG(5, ("Encode list of recipient infos."));

  ssh_mprz_init_set_ui(&version, 0);
  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshPkcs7RecipientInfo recipient = gnode->data;
      unsigned char *der;
      size_t der_len;

      ssh_x509_name_reset(recipient->issuer_name);
      if (!ssh_x509_name_pop_der_dn(recipient->issuer_name, &der, &der_len))
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
      if (der_len == 0)
        {
          /* We may have received this name such that it was not der
             encoded (e.g. came from user without
             ssh_x509_cert_encode()) having been called. Now encode
             name with crypto library default rules. */
          ssh_free(der); ssh_x509_name_reset(recipient->issuer_name);
          ssh_x509_encode_dn_name(context, recipient->issuer_name->type,
                                  recipient->issuer_name,
                                  ssh_x509_get_configuration());
          ssh_x509_name_pop_der_dn(recipient->issuer_name, &der, &der_len);
        }

      rv = ssh_asn1_decode_node(context, der, der_len, &issuer_node);
      ssh_free(der);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;

      ke_algorithm =
        ssh_pkcs7_algorithm_oids(recipient->key_encryption_algorithm);
      (void) ssh_asn1_create_node(context, &ke_params, "(null ())");

      rv = ssh_asn1_create_node(context, &node,
                                "(sequence ()"
                                "  (integer ())"
                                "  (sequence ()"
                                "    (any ())"
                                "    (integer ()))"
                                "  (sequence ()"
                                "    (object-identifier ())"
                                "    (any ()))"
                                "  (octet-string ()))",
                                &version,
                                issuer_node,
                                &recipient->serial_number,
                                ke_algorithm,
                                ke_params,
                                recipient->encrypted_key,
                                recipient->encrypted_key_length);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          ssh_mprz_clear(&version);
          return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }
      else
        list = ssh_asn1_add_list(list, node);
    }
  ssh_mprz_clear(&version);

  *node_return = list;
  return SSH_PKCS7_OK;
}

static SshPkcs7Status
ssh_pkcs7_encode_cipher_info(SshAsn1Context context,
                             SshPkcs7CipherInfo cipher,
                             SshAsn1Node *algorithm_node)
{
  const char *oids;
  SshAsn1Node params_node = NULL;
  SshUInt32 kl;

  /* PKCS#12 case */
  if (cipher->salt_len > 0 && cipher->rounds > 0)
    {
      oids = ssh_pkcs7_algorithm_oids(cipher->name);
      if (ssh_asn1_create_node(context, &params_node,
                               "(sequence ()"
                               "  (octet-string ()))"
                               "  (integer-short ())",
                               cipher->salt, cipher->salt_len,
                               cipher->rounds) == SSH_ASN1_STATUS_OK)
        goto encode_node;
      else
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
    }

  /* Sometimes we need to look up the oid with specified key size. */
  oids = ssh_pkcs7_algorithm_oids(cipher->name);
  if (oids == NULL)
    {
      unsigned char oidname[128];
      unsigned char temp[128], *p;

      ssh_ustrncpy(temp, cipher->name, sizeof(temp));
      if ((p = ssh_ustr(strstr(ssh_sstr(temp), "-cbc"))) != NULL)
        *p = '\000';

      ssh_snprintf(oidname, sizeof(oidname),
                   "%s%ld-cbc", temp, cipher->key_length * 8);
      oids = ssh_pkcs7_algorithm_oids(oidname);
      if (oids == NULL)
        return SSH_PKCS7_ALGORITHM_UNKNOWN;
    }

  if (!ssh_usstrncmp(cipher->name, "des", 3)
      || !ssh_usstrncmp(cipher->name, "3des", 4)
      || !ssh_usstrncmp(cipher->name, "aes", 3))
    {
      if (ssh_asn1_create_node(context, &params_node,
                               "(octet-string ())",
                               cipher->iv, cipher->iv_len)
          != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
    }
  else if (!ssh_usstrcmp(cipher->name, "rc2-cbc"))
    {
      switch (cipher->key_length)
        {
        case 40:  kl = 160; break;
        case 64:  kl = 120; break;
        case 128: kl = 58; break;
        default:  kl = cipher->key_length; break;
        }
      if (ssh_asn1_create_node(context, &params_node,
                               "(sequence ()"
                               "  (integer-short ())"
                               "  (octet-string ()))",
                               kl, cipher->iv, cipher->iv_len)
          != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
    }
  else if (!ssh_usstrncmp(cipher->name, "rc5-cbc", 7))
    {
      if (ssh_asn1_create_node(context, &params_node,
                               "(sequence ()"
                               "  (integer-short ())"
                               "  (integer-short ())"
                               "  (integer-short ())"
                               "  (octet-string ()))",
                               16,
                               cipher->rounds,
                               cipher->block_length,
                               cipher->iv, cipher->iv_len)
          != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
    }
  else
    {
      return SSH_PKCS7_ALGORITHM_UNKNOWN;
    }

 encode_node:
  if (ssh_asn1_create_node(context, algorithm_node,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (any ()))",
                           oids, params_node) != SSH_ASN1_STATUS_OK)
    return SSH_PKCS7_ASN1_ENCODING_FAILED;
  else
    return SSH_PKCS7_OK;
}



/* the recursive encoder. */

SshPkcs7Status ssh_pkcs7_recursive_encode_content(SshAsn1Context context,
                                                  SshPkcs7 pkcs7,
                                                  SshAsn1Node *node)
{
  SshAsn1Status rv;
  SshAsn1Node certificates = NULL, crls = NULL,
    algorithm_identifiers = NULL, algorithm_params = NULL,
    algorithm_node = NULL,
    content_info = NULL, signer_infos = NULL, recipient_infos = NULL;
  const char *encrypted_content_type, *algorithm_oid;
  SshPkcs7Status status;

  SSH_DEBUG(5, ("Encode recursively the content."));

  /* Jump to the correct case. */
  switch (pkcs7->type)
    {
    case SSH_PKCS7_DATA:
      SSH_DEBUG(5, ("Encode DATA."));
      /* Generate the data node. (for zero length data create zero
         length octet string. */
      if (pkcs7->data_length)
        rv = ssh_asn1_create_node(context, node,
                                  "(octet-string ())",
                                  pkcs7->data, pkcs7->data_length);
      else
        {
          *node = NULL;
          rv = SSH_ASN1_STATUS_OK;
        }

      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;

      break;

    case SSH_PKCS7_SIGNED_DATA:
      SSH_DEBUG(5, ("Encode SIGNED DATA."));

      if (pkcs7->content == NULL)
        return SSH_PKCS7_CONTENT_UNDECLARED;

      if (pkcs7->signer_infos == NULL)
        return SSH_PKCS7_SIGNERS_UNDECLARED;

      /* Perform recursive encoding. */
      status = ssh_pkcs7_recursive_encode(context,
                                          pkcs7->content, &content_info);
      if (status != SSH_PKCS7_OK)
        return status;

      /* Encode algorithm identifiers. */
      status = ssh_pkcs7_encode_oids(context,
                                     pkcs7->digest_algorithms,
                                     &algorithm_identifiers);
      if (status != SSH_PKCS7_OK)
        return status;

      /* Encode signer information. */
      if (pkcs7->signer_infos)
        {
          status = ssh_pkcs7_encode_signer_infos(context,
                                                 pkcs7->signer_infos,
                                                 &signer_infos);
          if (status != SSH_PKCS7_OK)
            return status;
        }

      /* Encode certificates. */
      if (pkcs7->certificates)
        {
          SshAsn1Node cert_tmp;

          status = ssh_pkcs7_encode_certs(context, pkcs7->certificates,
                                          &cert_tmp);
          if (status != SSH_PKCS7_OK)
            return status;
          rv = ssh_asn1_create_node(context, &certificates,
                                    "(set (0) (any ()))",
                                    cert_tmp);
          if (rv != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }
      /* Encode CRLs. */
      if (pkcs7->crls)
        {
          SshAsn1Node crls_tmp;
          status = ssh_pkcs7_encode_crls(context, pkcs7->crls, &crls_tmp);
          if (status != SSH_PKCS7_OK)
            return status;

          rv = ssh_asn1_create_node(context, &crls,
                                    "(set (1) (any ()))",
                                    crls_tmp);
          if (rv != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }

      /* Generate the necessary information for encoding. As the
         digesting methods are described in the signer infos, we may
         as well help the application and do some work here. */
      rv = ssh_asn1_create_node(context, node,
                                "(sequence ()"
                                "  (integer-short ())"  /* Version. */
                                "  (set () (any ()))"   /* Algorithm ids. */
                                "  (any ())"            /* Content info. */
                                "  (any (0))"           /* certificates */
                                "  (any (1))"           /* crls */
                                "  (set () (any ())))", /* signer infos */
                                pkcs7->version,
                                algorithm_identifiers,
                                content_info,
                                certificates,
                                crls,
                                signer_infos);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
      break;











    case SSH_PKCS7_ENVELOPED_DATA:
      SSH_DEBUG(5, ("Encode ENVELOPED DATA."));

      if (pkcs7->recipient_infos == NULL)
        return SSH_PKCS7_RECIPIENTS_UNDECLARED;

      /* Build necessary nodes first. */
      status = ssh_pkcs7_encode_recipient_infos(context,
                                                pkcs7->recipient_infos,
                                                &recipient_infos);
      if (status != SSH_PKCS7_OK)
        return status;

      /* Find the encrypted content type. */
      encrypted_content_type =
        ssh_pkcs7_content_type_oids(pkcs7->encrypted_type);

      status = ssh_pkcs7_encode_cipher_info(context,
                                            &pkcs7->cipher_info,
                                            &algorithm_node);
      if (status != SSH_PKCS7_OK)
        return status;

      /* Here we need to encode the enveloped information. */
      rv = ssh_asn1_create_node(context, node,
                                "(sequence ()"
                                "  (integer-short ())"   /* version. */
                                "  (set () (any ()))"    /* recipient infos. */
                                "  (sequence ()"
                                "    (object-identifier ())" /* content type */
                                "    (any ())"
                                "    (octet-string (0))))" ,   /* content */
                                pkcs7->version,
                                recipient_infos,
                                encrypted_content_type,
                                algorithm_node,
                                pkcs7->data, pkcs7->data_length);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
      break;

    case SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA:
      SSH_DEBUG(5, ("Encode SIGNED ENVELOPED DATA."));

      if (pkcs7->recipient_infos == NULL)
        return SSH_PKCS7_RECIPIENTS_UNDECLARED;
      if (pkcs7->signer_infos == NULL)
        return SSH_PKCS7_SIGNERS_UNDECLARED;

      if (pkcs7->recipient_infos)
        {
          /* Build necessary nodes first. */
          status = ssh_pkcs7_encode_recipient_infos(context,
                                                    pkcs7->recipient_infos,
                                                    &recipient_infos);
          if (status != SSH_PKCS7_OK)
            return status;
        }

      if (pkcs7->signer_infos)
        {
          /* Encode signer information. */
          status = ssh_pkcs7_encode_signer_infos(context,
                                                 pkcs7->signer_infos,
                                                 &signer_infos);
          if (status != SSH_PKCS7_OK)
            return status;
        }

      if (pkcs7->digest_algorithms)
        {
          /* Encode algorithm identifiers. */
          status = ssh_pkcs7_encode_oids(context,
                                         pkcs7->digest_algorithms,
                                         &algorithm_identifiers);
          if (status != SSH_PKCS7_OK)
            return status;
        }

      /* Build suitable certificate sets. */
      if (pkcs7->certificates)
        {
          SshAsn1Node cert_tmp;
          status = ssh_pkcs7_encode_certs(context,
                                          pkcs7->certificates,
                                          &cert_tmp);
          if (status != SSH_PKCS7_OK)
            return status;
          rv = ssh_asn1_create_node(context, &certificates,
                                    "(set (0) (any ()))", cert_tmp);
          if (rv != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }

      /* CRL set. */
      if (pkcs7->crls)
        {
          SshAsn1Node crls_tmp;

          status = ssh_pkcs7_encode_crls(context, pkcs7->crls, &crls_tmp);
          if (status != SSH_PKCS7_OK)
            return status;
          rv = ssh_asn1_create_node(context, &crls,
                                    "(set (1) (any ()))", crls_tmp);
          if (rv != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }

      /* Find the encrypted content type. */
      encrypted_content_type =
        ssh_pkcs7_content_type_oids(pkcs7->encrypted_type);

      status = ssh_pkcs7_encode_cipher_info(context,
                                            &pkcs7->cipher_info,
                                            &algorithm_node);
      if (status != SSH_PKCS7_OK)
        return status;

      rv = ssh_asn1_create_node(context, node,
                                "(sequence ()"
                                "  (integer-short ())" /* Version */
                                "  (set () (any ()))"  /* recipients */
                                "  (set () (any ()))"  /* Digest alg. */
                                "  (sequence ()"
                                "    (object-identifier ())"   /* type */
                                "    (any ())"                 /* cipher */
                                "    (octet-string ()))"       /* content */
                                "  (any (0))"   /* certificates. */
                                "  (any (1))"   /* crls. */
                                "  (set () (any ())))",  /* signer infos */
                                pkcs7->version,
                                recipient_infos,
                                algorithm_identifiers,
                                encrypted_content_type,
                                algorithm_node,
                                pkcs7->data, pkcs7->data_length,
                                certificates,
                                crls,
                                signer_infos);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;

      break;

    case SSH_PKCS7_DIGESTED_DATA:
      SSH_DEBUG(5, ("Encode DIGESTED DATA."));

      if (pkcs7->content == NULL)
        return SSH_PKCS7_CONTENT_UNDECLARED;

      status = ssh_pkcs7_recursive_encode(context,
                                          pkcs7->content,
                                          &content_info);
      if (status != SSH_PKCS7_OK)
        return status;

      /* Create new algorithm information. */

      algorithm_oid =
        ssh_pkcs7_algorithm_oids(pkcs7->content_digest_algorithm);
      algorithm_params = NULL;

      /* Encode. */
      rv = ssh_asn1_create_node(context, node,
                                "(sequence ()"
                                "  (integer-short ())"
                                "  (sequence ()"
                                "    (object-identifier ())"
                                "    (any ()))"
                                "  (any ())"
                                "  (octet-string ()))",
                                pkcs7->version,
                                algorithm_oid,
                                algorithm_params,
                                content_info,
                                pkcs7->content_digest,
                                pkcs7->content_digest_length);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
      break;

    case SSH_PKCS7_ENCRYPTED_DATA:
      SSH_DEBUG(5, ("Encode ENCRYPTED DATA."));

      encrypted_content_type =
        ssh_pkcs7_content_type_oids(pkcs7->encrypted_type);

      /* Create new algorithm information. */
      status = ssh_pkcs7_encode_cipher_info(context,
                                            &pkcs7->cipher_info,
                                            &algorithm_node);
      if (status != SSH_PKCS7_OK)
        return status;

      /* This is almost trivial. */
      rv = ssh_asn1_create_node(context, node,
                                "(sequence ()"
                                "  (integer-short ())"
                                "  (sequence ()"
                                "    (object-identifier ())"
                                "    (any ())"
                                "    (octet-string (0))))",
                                pkcs7->version,
                                encrypted_content_type,
                                algorithm_node,
                                pkcs7->data, pkcs7->data_length);
      if (rv != SSH_ASN1_STATUS_OK)
        return SSH_PKCS7_ASN1_ENCODING_FAILED;
      break;

    default:
      return SSH_PKCS7_CONTENT_TYPE_UNKNOWN;
    }
  /* Node has been set accordingly. */
  return SSH_PKCS7_OK;
}

static SshPkcs7Status
ssh_pkcs7_recursive_encode(SshAsn1Context context,
                           SshPkcs7 pkcs7,
                           SshAsn1Node *root)
{
  SshAsn1Status rv;
  SshAsn1Node   node;
  SshPkcs7Status status;
  const char *content_type;

  SSH_DEBUG(5, ("Encode recursively."));

  status = ssh_pkcs7_recursive_encode_content(context, pkcs7, &node);
  if (status == SSH_PKCS7_OK)
    {
      content_type = ssh_pkcs7_content_type_oids(pkcs7->type);
      rv = ssh_asn1_create_node(context, root,
                                "(sequence ()"
                                "  (object-identifier ())"
                                "  (any (e 0)))",
                                content_type,
                                node);
      if (rv != SSH_ASN1_STATUS_OK)
        status = SSH_PKCS7_ASN1_ENCODING_FAILED;
    }
  return status;
}

/* Main encoding routine. */
SshPkcs7Status ssh_pkcs7_encode(SshPkcs7 pkcs7,
                                unsigned char **data,
                                size_t *data_length)
{
  SshAsn1Context context;
  SshAsn1Node    node;
  SshAsn1Status  rv;
  SshPkcs7Status status;

  SSH_DEBUG(5, ("Encode PKCS-7 object."));

  /* Initialize the ASN.1 BER/DER allocation context. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS7_FAILURE;

  /* Run the encoding procedure, which generates the ASN.1 nodes. */
  status = ssh_pkcs7_recursive_encode(context, pkcs7, &node);
  if (status != SSH_PKCS7_OK)
    {
      ssh_asn1_free(context);
      return status;
    }

  /* Encode the contents of the node. */
  rv = ssh_asn1_encode_node(context, node);
  if (rv != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS7_ASN1_ENCODING_FAILED;
    }

  /* Node generate the BER/DER coding. */
  rv = ssh_asn1_node_get_data(node, data, data_length);
  if (rv != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_PKCS7_ASN1_ENCODING_FAILED;
    }

  /* Free the ASN.1 parser context. */
  ssh_asn1_free(context);
  return SSH_PKCS7_OK;
}

/* Main encoding routine. */
SshPkcs7Status
ssh_pkcs7_encode_data(SshPkcs7 pkcs7,
                      unsigned char **data, size_t *data_length)
{
  SshAsn1Context context;
  SshAsn1Node    node;
  SshAsn1Status  rv;
  SshPkcs7Status status;

  SSH_DEBUG(5, ("Encode PKCS-7 object (just the content)."));

  /* Initialize the ASN.1 BER/DER allocation context. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS7_FAILURE;

  status = ssh_pkcs7_recursive_encode_content(context, pkcs7, &node);
  if (status != SSH_PKCS7_OK)
    {
      ssh_asn1_free(context);
      return status;
    }

  if (!node)
    {
      *data = NULL;
      *data_length = 0;
      ssh_asn1_free(context);
      return SSH_PKCS7_OK;
    }
  /* Encode the contents of the node. We may fail here (in case of
     data only content with status constructed assumed). */
  rv = ssh_asn1_encode_node(context, node);
  if (rv == SSH_ASN1_STATUS_OK ||
      rv == SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED)
    {
      /* Node generate the BER/DER coding. */
      rv = ssh_asn1_node_get_data(node, data, data_length);
    }

  ssh_asn1_free(context);

  if (rv != SSH_ASN1_STATUS_OK)
    {
      status = SSH_PKCS7_ASN1_ENCODING_FAILED;
    }

  return status;
}
#endif /* SSHDIST_CERT */
