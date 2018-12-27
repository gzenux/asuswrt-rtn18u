/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoding
   and decoding.

   This library is low level one, meaning that knowledge of
   cryptography is kept in minimum, though PKCS #7 is very much tied to
   cryptography.  (This library may perform some conversion from SSH
   cryptographic names to ASN.1 OIDs defined in PKCS standards.)

   This library can handle BER or DER encoded PKCS #7 messages,
   however, it produces DER messages. This is because the underlaying
   ASN.1 BER/DER code is biased towards DER.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
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
#define SSH_DEBUG_MODULE "SshPkcs7Decode"

/***** PKCS7 ******/

static SshPkcs7Status
ssh_pkcs7_decode_oids(SshAsn1Context context,
                      SshAsn1Node node, SshGList *list)
{
  SshAsn1Status  rv;
  SshGList       mylist;
  SshAsn1Node    params;
  char          *oid;

  SSH_DEBUG(5, ("Decoding lists of algorithm identifiers."));

  /* Allocate the list. */
  mylist = ssh_glist_allocate();
  for (; node; node = ssh_asn1_node_next(node))
    {
      /* Read the ASN.1 BER tree. */
      rv =
        ssh_asn1_read_node(context, node,
                           "(sequence (l*)"
                           "  (object-identifier ())"
                           "  (any ()))",
                           &oid,
                           &params);
      /* Check for error. */
      if (rv != SSH_ASN1_STATUS_OK)
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_oid_free, NULL);
          return SSH_PKCS7_ASN1_DECODING_FAILED;
        }

      /* Ignoring parameters, in this version. */

      /* Add to the list. */
      ssh_glist_add_item(mylist, oid, SSH_GLIST_TAIL);
    }
  /* Give the caller our list. */
  *list = mylist;
  return SSH_PKCS7_OK;
}


/* Certificates. Decode, Encode and Free */

static SshPkcs7Status
ssh_pkcs7_decode_certs(SshAsn1Context context,
                       SshAsn1Node node, SshGList *list)
{
  SshAsn1Status rv;
  SshAsn1Node   cert, extended_cert;
  SshGList      mylist;
  SshX509Status x509_status;

  SSH_DEBUG(5, ("Decode list of certificates."));

  mylist = ssh_glist_allocate();
  for (; mylist && node; node = ssh_asn1_node_next(node))
    {
      SshPkcs6Cert pcert;
      int which;

      SSH_DEBUG(6, ("Certificate to be decoded."));
      rv = ssh_asn1_read_node(context, node,
                              "(choice"
                              "  (any (u 16))"
                              "  (any (l* 0)))",
                              &which, &cert, &extended_cert);

      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Failed to decode the Asn.1 as '%s'.",
                        ssh_asn1_error_string(rv)));
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_certificate_free,
                                       NULL);
          return SSH_PKCS7_ASN1_DECODING_FAILED;
        }

      /* Allocate the node for the information of the certificate. */
      if ((pcert = ssh_malloc(sizeof(*pcert))) != NULL)
        {
          ssh_pkcs6_cert_init(pcert);
          if (pcert->certificate == NULL || pcert->attr == NULL)
            {
              ssh_free(pcert);
              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_certificate_free,
                                           NULL);
              return SSH_PKCS7_FAILURE;
            }
        }
      else
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_certificate_free,
                                       NULL);
          return SSH_PKCS7_FAILURE;
        }

      switch (which)
        {
        case 0: /* Normal certificate. */
          SSH_DEBUG(5, ("Normal certificate."));
          x509_status = ssh_x509_cert_decode_asn1(context, cert,
                                                  pcert->certificate);
          if (x509_status != SSH_X509_OK)
            {
              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_certificate_free,
                                           NULL);
              ssh_pkcs6_cert_free(pcert);
              return SSH_PKCS7_ASN1_DECODING_FAILED;
            }
          /* Get the BER encoding. */
          rv = ssh_asn1_node_get_data(cert,
                                      &pcert->ber_buf, &pcert->ber_length);
          if (rv != SSH_ASN1_STATUS_OK)
            {
              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_certificate_free,
                                           NULL);
              ssh_pkcs6_cert_free(pcert);
              return SSH_PKCS7_ASN1_DECODING_FAILED;
            }
          break;

        case 1: /* Decode the extended certificate. */
          SSH_DEBUG(5, ("Extented certificate."));
          if (ssh_pkcs6_cert_decode_asn1(context, extended_cert, pcert)
              != SSH_PKCS6_OK)
            {
              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_certificate_free,
                                           NULL);
              ssh_pkcs6_cert_free(pcert);
              return SSH_PKCS7_PKCS6_DECODING_FAILED;
            }

          /* Get the BER encoding. */
          rv = ssh_asn1_node_get_data(extended_cert,
                                      &pcert->ber_buf, &pcert->ber_length);
          if (rv != SSH_ASN1_STATUS_OK)
            {
              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_certificate_free,
                                           NULL);
              ssh_pkcs6_cert_free(pcert);
              return SSH_PKCS7_ASN1_DECODING_FAILED;
            }
          pcert->extended = TRUE;
          break;

        default:
          /* This is an internal error; ASN.1 decoder returned junk
             after indicating successful status. */
          ssh_fatal("ssh_pkcs7_decode_certs: Asn.1 decoder failure.");
          break;
        }

      /* Push to the list. */
      ssh_glist_add_item(mylist, pcert, SSH_GLIST_TAIL);
    }

  *list = mylist;
  return SSH_PKCS7_OK;
}


/* CRLs. */

static SshPkcs7Status
ssh_pkcs7_decode_crls(SshAsn1Context context,
                      SshAsn1Node node, SshGList *list)
{
  SshAsn1Status rv;
  SshGList      mylist;

  SSH_DEBUG(5, ("Decode list of CRLs."));

  mylist = ssh_glist_allocate();
  for (; mylist && node; node = ssh_asn1_node_next(node))
    {
      SshPkcs6Crl crl;

      if ((crl = ssh_malloc(sizeof(*crl))) != NULL)
        ssh_pkcs6_crl_init(crl);
      else
        {
          ssh_glist_free_with_iterator(mylist, ssh_pkcs7_glist_crl_free, NULL);
          return SSH_PKCS7_FAILURE;
        }

      /* Decode the CRL. */
      if (ssh_x509_crl_decode_asn1(context, node, crl->crl) != SSH_X509_OK)
        {
          ssh_glist_free_with_iterator(mylist, ssh_pkcs7_glist_crl_free, NULL);
          ssh_pkcs6_crl_free(crl);
          return SSH_PKCS7_ASN1_DECODING_FAILED;
        }

      /* Take the ber buf. */
      rv = ssh_asn1_node_get_data(node, &crl->ber_buf, &crl->ber_length);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          ssh_glist_free_with_iterator(mylist, ssh_pkcs7_glist_crl_free, NULL);
          ssh_pkcs6_crl_free(crl);
          return SSH_PKCS7_ASN1_ENCODING_FAILED;
        }

      /* Build the list. */
      ssh_glist_add_item(mylist, crl, SSH_GLIST_TAIL);
    }
  *list = mylist;
  return SSH_PKCS7_OK;
}



static SshPkcs7Status
ssh_pkcs7_decode_signer_infos(SshAsn1Context context,
                              SshAsn1Node node, SshGList *list)
{
  SshAsn1Status  rv;
  SshAsn1Node    issuer_name, digest_params, auth_attr;
  SshAsn1Node    digest_encryption_params, unauth_attr;
  SshGList       mylist;
  SshMPIntegerStruct         version, serial_number;
  unsigned char *digest_algorithm, *digest_encryption_algorithm;
  unsigned char *encrypted_digest;
  size_t         encrypted_digest_length;
  Boolean        auth_attr_found, unauth_attr_found;

  SSH_DEBUG(5, ("Decode list of signer infos."));

  ssh_mprz_init(&version);
  ssh_mprz_init(&serial_number);

  mylist = ssh_glist_allocate();
  for (; mylist && node; node = ssh_asn1_node_next(node))
    {
      SshPkcs7SignerInfo signer_info;
      const SshOidStruct *oids;

      rv = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (integer ())"
                              "  (sequence ()"
                              "    (any ())"
                              "    (integer ()))"
                              "  (sequence ()"
                              "    (object-identifier ())"
                              "    (any ()))"
                              "  (optional "
                              "    (any (0)))"
                              "  (sequence ()"
                              "    (object-identifier ())"
                              "    (any ()))"
                              "  (octet-string ())"
                              "  (optional"
                              "    (any ())))",
                              &version,
                              &issuer_name,
                              &serial_number,
                              &digest_algorithm,
                              &digest_params,
                              &auth_attr_found,
                              &auth_attr,
                              &digest_encryption_algorithm,
                              &digest_encryption_params,
                              &encrypted_digest, &encrypted_digest_length,
                              &unauth_attr_found,
                              &unauth_attr);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_signer_info_free,
                                       NULL);
          ssh_mprz_clear(&version);
          ssh_mprz_clear(&serial_number);
          return SSH_PKCS7_ASN1_DECODING_FAILED;
        }

      /* Handle the arguments read. */
      if (ssh_mprz_cmp_ui(&version, 0) != 0 &&
          ssh_mprz_cmp_ui(&version, 1) != 0)
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_signer_info_free,
                                       NULL);
          ssh_free(digest_algorithm);
          ssh_free(digest_encryption_algorithm);
          ssh_free(encrypted_digest);
          ssh_mprz_clear(&version);
          ssh_mprz_clear(&serial_number);

          return SSH_PKCS7_ASN1_DECODING_FAILED;
        }
      ssh_mprz_clear(&version);

      /* Allocate a new signer info context. */
      signer_info = ssh_calloc(1, sizeof(*signer_info));
      if (!signer_info)
        {
          goto decoding_failed;
        }

      ssh_pkcs7_signer_info_init(signer_info);

      if (auth_attr_found)
        {
          if (ssh_pkcs6_attr_decode_asn1(context,
                                         auth_attr,
                                         &signer_info->auth_attributes)
              != SSH_PKCS6_OK)
            {
            decoding_failed:
              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_signer_info_free,
                                           NULL);
              ssh_free(digest_algorithm);
              ssh_free(digest_encryption_algorithm);
              ssh_free(encrypted_digest);
              ssh_mprz_clear(&serial_number);
              ssh_pkcs7_free_signer_info(signer_info);
              return SSH_PKCS7_ASN1_DECODING_FAILED;
            }
        }

      if (unauth_attr_found)
        {
          if (ssh_pkcs6_attr_decode_asn1(context,
                                         unauth_attr,
                                         &signer_info->unauth_attributes)
              != SSH_PKCS6_OK)
            goto decoding_failed;
        }

      /* Handle the issuer name. */
      if (issuer_name)
        {
          unsigned char *der;
          size_t         der_length;

          if (ssh_asn1_node_get_data(issuer_name, &der, &der_length)
              != SSH_ASN1_STATUS_OK)
            goto decoding_failed;

          ssh_x509_name_push_der_dn(&signer_info->issuer_name,
                                    der, der_length);
          ssh_free(der);
        }

      /* Copy the serial number. */
      ssh_mprz_set(&signer_info->serial_number, &serial_number);
      ssh_mprz_clear(&serial_number);

      /* Figure out the algorithms. */
      oids = ssh_oid_find_by_oid_of_type(digest_algorithm, SSH_OID_HASH);
      ssh_free(digest_algorithm);
      if (oids == NULL)
        signer_info->digest_algorithm = NULL;
      else
        signer_info->digest_algorithm = ssh_strdup(oids->name);

      oids = ssh_oid_find_by_oid_of_type(digest_encryption_algorithm,
                                         SSH_OID_PK);
      ssh_free(digest_encryption_algorithm);
      if (oids == NULL)
        signer_info->digest_encryption_algorithm = NULL;
      else
        signer_info->digest_encryption_algorithm = ssh_strdup(oids->name);

      /* Copy the encrypted digest. */
      signer_info->encrypted_digest        = encrypted_digest;
      signer_info->encrypted_digest_length = encrypted_digest_length;

      /* Add to the list. */
      ssh_glist_add_item(mylist, signer_info, SSH_GLIST_TAIL);
    }

  *list = mylist;
  return SSH_PKCS7_OK;
}



/* Recipient infos. */

static SshPkcs7Status
ssh_pkcs7_decode_recipient_infos(SshAsn1Context context,
                                 SshAsn1Node node, SshGList *list)
{
  SshAsn1Status rv;
  SshGList     mylist;
  SshMPIntegerStruct       serial_number;
  SshWord      version;
  SshAsn1Node  issuer_name, key_encryption_params;
  unsigned char *key_encryption_algorithm;
  unsigned char *encrypted_key;
  size_t         encrypted_key_length;

  SSH_DEBUG(5, ("Decode list of recipient infos."));

  ssh_mprz_init(&serial_number);

  mylist = ssh_glist_allocate();
  for (; node; node = ssh_asn1_node_next(node))
    {
      SshPkcs7RecipientInfo recipient_info;
      const SshOidStruct *oids;

      key_encryption_algorithm = NULL;
      rv = ssh_asn1_read_node(context, node,
                              "(sequence ()"
                              "  (integer-short ())"
                              "  (sequence ()"
                              "    (any ())"
                              "    (integer ()))"
                              "  (sequence ()"
                              "    (object-identifier ())"
                              "    (any ()))"
                              "  (octet-string ()))",
                              &version,
                              &issuer_name,
                              &serial_number,
                              &key_encryption_algorithm,
                              &key_encryption_params,
                              &encrypted_key, &encrypted_key_length);

      if (rv != SSH_ASN1_STATUS_OK)
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_recipient_info_free,
                                       NULL);
          ssh_mprz_clear(&serial_number);
          return SSH_PKCS7_ASN1_DECODING_FAILED;
        }

      if (version != 0)
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_recipient_info_free,
                                       NULL);
          /* Free details. */
          ssh_mprz_clear(&serial_number);
          ssh_free(key_encryption_algorithm);
          ssh_free(encrypted_key);
          return SSH_PKCS7_VERSION_UNKNOWN;
        }

      /* Build recipient info. */
      recipient_info = ssh_malloc(sizeof(*recipient_info));
      if (!recipient_info)
        {
          ssh_glist_free_with_iterator(mylist,
                                       ssh_pkcs7_glist_recipient_info_free,
                                       NULL);
          ssh_mprz_clear(&serial_number);
          ssh_free(key_encryption_algorithm);
          ssh_free(encrypted_key);
          return SSH_PKCS7_FAILURE;
        }
      ssh_pkcs7_recipient_info_init(recipient_info);

      /* Handle the name. */
      if (issuer_name)
        {
          unsigned char *der = NULL;
          size_t         der_length;

          if (ssh_asn1_node_get_data(issuer_name, &der, &der_length)
              != SSH_ASN1_STATUS_OK)
            {
            decoding_failed:
              ssh_free(der);

              ssh_glist_free_with_iterator(mylist,
                                           ssh_pkcs7_glist_recipient_info_free,
                                           NULL);
              /* Free details. */
              ssh_pkcs7_free_recipient_info(recipient_info);
              ssh_mprz_clear(&serial_number);
              ssh_free(key_encryption_algorithm);
              ssh_free(encrypted_key);
              return SSH_PKCS7_ASN1_DECODING_FAILED;
            }

          if (!ssh_x509_name_push_der_dn(&recipient_info->issuer_name,
                                         der, der_length))
            goto decoding_failed;

          ssh_free(der);
        }

      /* Copy the serial number. */
      ssh_mprz_set(&recipient_info->serial_number, &serial_number);

      /* Figure out the encryption algorithm. */
      oids = ssh_oid_find_by_oid_of_type(key_encryption_algorithm,
                                         SSH_OID_PK);
      ssh_free(key_encryption_algorithm);
      if (oids == NULL)
        recipient_info->key_encryption_algorithm = NULL;
      else
        recipient_info->key_encryption_algorithm = ssh_strdup(oids->name);

      /* Copy the encrypted key. */
      recipient_info->encrypted_key = encrypted_key;
      recipient_info->encrypted_key_length = encrypted_key_length;

      /* Handle the data just read. */
      ssh_glist_add_item(mylist, recipient_info, SSH_GLIST_TAIL);
    }
  ssh_mprz_clear(&serial_number);

  *list = mylist;
  return SSH_PKCS7_OK;
}


static SshPkcs7Status
ssh_pkcs7_decode_cipher_info(SshAsn1Context context,
                             SshAsn1Node algorithm_node,
                             SshPkcs7CipherInfo cipher)
{
  Boolean iv_found, kl_found, p12 = FALSE;
  SshUInt32 kl, version;
  unsigned char *algorithm_oid;
  SshAsn1Node params_node;
  const SshOidStruct *oid;
  const char *native;

  if (ssh_asn1_read_node(context, algorithm_node,
                         "(sequence (l*)"
                         "  (object-identifier ())"
                         "  (any ()))",
                         &algorithm_oid, &params_node)
      != SSH_ASN1_STATUS_OK)
    return SSH_PKCS7_ALGORITHM_UNKNOWN;

  memset(cipher, 0, sizeof(*cipher));
  oid = ssh_oid_find_by_oid_of_type(algorithm_oid, SSH_OID_CIPHER);
  if (!oid)
    {
      p12 = TRUE;
      oid = ssh_oid_find_by_oid_of_type(algorithm_oid, SSH_OID_PKCS12);
    }
  ssh_free(algorithm_oid);

  if (oid)
    {
      if (p12)
        {
          if (ssh_asn1_read_node(context, params_node,
                                 "(sequence ()"
                                 "  (octet-string ())"
                                 "  (integer-short ()))",
                                 &cipher->salt, &cipher->salt_len,
                                 &cipher->rounds) == SSH_ASN1_STATUS_OK)
            {
              const SshOidPkcs5Struct *extra = oid->extra;

              native = ssh_cipher_alias_get_native(extra->cipher);
              cipher->name = ssh_strdup(native);
              cipher->hash = ssh_strdup(extra->hash);
              if (cipher->name == NULL || cipher->hash == NULL)
                {
                  ssh_free(cipher->name);
                  ssh_free(cipher->hash);
                  return SSH_PKCS7_FAILURE;
                }
              cipher->key_length = extra->keylen;
              return SSH_PKCS7_OK;
            }
          else
            return SSH_PKCS7_ALGORITHM_UNKNOWN;
        }

      if (!strncmp(oid->name, "des", 3)
          || !strncmp(oid->name, "3des", 4)
          || !strncmp(oid->name, "aes", 3))
        {
          if (ssh_asn1_read_node(context, params_node,
                                 "(octet-string ())",
                                 &cipher->iv, &cipher->iv_len)
              != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ALGORITHM_UNKNOWN;
        }
      else if (!strcmp(oid->name, "rc2-cbc"))
        {
          if (ssh_asn1_read_node(context, params_node,
                                 "(sequence ()"
                                 "  (optional (integer-short ()))"
                                 "  (octet-string ()))",
                                 &kl_found, &kl,
                                 &cipher->iv, &cipher->iv_len)
              != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ALGORITHM_UNKNOWN;

          if (!kl_found)
            cipher->key_length = 32;
          else
            {
              switch (kl)
                {
                case 160: cipher->key_length = 40; break;
                case 120: cipher->key_length = 64; break;
                case 58:  cipher->key_length = 128; break;
                default:
                  if (kl < 256)
                    return SSH_PKCS7_ALGORITHM_UNKNOWN;
                  else
                    cipher->key_length = kl;
                }
            }
        }
      else if (!strncmp(oid->name, "rc5-cbc", 7))
        {
          if (ssh_asn1_read_node(context, params_node,
                                 "(sequence ()"
                                 "  (integer-short ())"
                                 "  (integer-short ())"
                                 "  (integer-short ())"
                                 "  (optional (octet-string ())))",
                                 &version,
                                 &cipher->rounds,
                                 &cipher->block_length,
                                 &iv_found, &cipher->iv, &cipher->iv_len)
              != SSH_ASN1_STATUS_OK)
            return SSH_PKCS7_ALGORITHM_UNKNOWN;

          if ((version != 16) ||
              (cipher->block_length != 64 && cipher->block_length != 128) ||
              (cipher->rounds < 8 || cipher->rounds > 128))
            return SSH_PKCS7_ALGORITHM_UNKNOWN;

          if (!iv_found)
            {
              cipher->iv_len = cipher->block_length;
              if ((cipher->iv = ssh_calloc(cipher->iv_len,
                                           sizeof(unsigned char))) == NULL)
                {
                  return SSH_PKCS7_FAILURE;
                }
            }
        }

      native = ssh_cipher_alias_get_native(oid->name);
      if ((cipher->name = ssh_strdup(native)) != NULL)
        return SSH_PKCS7_OK;
      else
        return SSH_PKCS7_FAILURE;
    }
  else
    return SSH_PKCS7_ALGORITHM_UNKNOWN;
}



SshPkcs7Status
ssh_pkcs7_recursive_decode(SshAsn1Context context,
                           SshAsn1Node root,
                           SshPkcs7 *pkcs7_return);

/* Decode the content of the PKCS #7 message.  */
static SshPkcs7Status
ssh_pkcs7_recursive_decode_content(SshAsn1Context context,
                                   SshAsn1Node node,
                                   SshPkcs7ContentType type,
                                   SshPkcs7 *pkcs7_return)
{
  SshAsn1Status rv;
  SshAsn1Node   digest_alg_node, certs_node,
    crls_node, signer_info_node, recipient_node,
    content_info, algorithm_node, algorithm_params;
  Boolean found, certs_found, crls_found;
  unsigned char *content_type_oid, *algorithm_oid;
  const SshOidStruct *oids;
  SshPkcs7Status status, returned_status;
  SshPkcs7 pkcs7;
  unsigned char *data;
  size_t data_length;

  SSH_DEBUG(5, ("Recursively decode content type %u.", type));

  /* Hope for the best. */
  status = SSH_PKCS7_OK;

  /* Allocate a PKCS #7 data structure, suitable cleared. */
  if ((pkcs7 = ssh_pkcs7_allocate()) == NULL)
    {
      *pkcs7_return = NULL;
      return SSH_PKCS7_FAILURE;
    }

  /* Put the correct content type where it belongs. */
  pkcs7->type = type;

  if (node == NULL)
    {
      *pkcs7_return = pkcs7;
      pkcs7         = NULL;
      return SSH_PKCS7_OK;
    }

  /* Store the ber pointers */
  ssh_asn1_node_get_data(node, &pkcs7->ber, &pkcs7->ber_length);

  /* Now switch to the correct decoding of the content, by the content type. */
  switch (pkcs7->type)
    {
    case SSH_PKCS7_DATA:
      SSH_DEBUG(5, ("Decode DATA."));
      rv = ssh_asn1_read_node(context, node,
                              "(octet-string (l*))",
                              &pkcs7->data,
                              &pkcs7->data_length);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Asn.1 decoding of data failed."));
          status = SSH_PKCS7_CONTENT_DECODING_FAILED;
          goto failed;
        }
      break;

    case SSH_PKCS7_SIGNED_DATA:
      SSH_DEBUG(5, ("Decode SIGNED DATA."));
      rv = ssh_asn1_read_node(context, node,
                              "(sequence (l*)"
                              "  (integer-short ())"  /* Version */
                              "  (set (l*) (any ()))" /* Digest Alg. OIDs */
                              "  (any ())"            /* Content info. */
                              "  (optional"
                              "    (set (l* 0) (any ())))" /* Certificates */
                              "  (optional"
                              "    (set (l* 1) (any ())))" /* CRLs */
                              "  (set (l*) (any ())))",    /* Signer infos */
                              &pkcs7->version,
                              &digest_alg_node,
                              &content_info,
                              &certs_found, &certs_node,
                              &crls_found, &crls_node,
                              &signer_info_node);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Asn.1 decoding of signed data failed."));
          status = SSH_PKCS7_CONTENT_DECODING_FAILED;
          goto failed;
        }

      /* We're not yet done, not even close.  First determine whether
         the version is correct. */
      if (pkcs7->version != 1)
        {
          status = SSH_PKCS7_VERSION_UNKNOWN;
          goto failed;
        }

      SSH_DEBUG(5, ("Recursive decoding of contents."));
      returned_status = ssh_pkcs7_recursive_decode(context,
                                                   content_info,
                                                   &pkcs7->content);

      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }

      SSH_DEBUG(5, ("Decoding digest algorithm identifiers."));
      returned_status = ssh_pkcs7_decode_oids(context,
                                              digest_alg_node,
                                              &pkcs7->digest_algorithms);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }

      /* Decode the certificates. */
      if (certs_found)
        {
          SSH_DEBUG(5, ("Decoding certificates."));
          returned_status = ssh_pkcs7_decode_certs(context,
                                                   certs_node,
                                                   &pkcs7->certificates);
          if (returned_status != SSH_PKCS7_OK)
            {
              status = returned_status;
              goto failed;
            }
        }

      /* Decode the CRLs. */
      if (crls_found)
        {
          SSH_DEBUG(5, ("Decoding crls."));
          returned_status = ssh_pkcs7_decode_crls(context,
                                                  crls_node,
                                                  &pkcs7->crls);
          if (returned_status != SSH_PKCS7_OK)
            {
              status = returned_status;
              goto failed;
            }
        }

      SSH_DEBUG(5, ("Finally decoding signer information."));
      returned_status = ssh_pkcs7_decode_signer_infos(context,
                                                      signer_info_node,
                                                      &pkcs7->signer_infos);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }
      break;











    case SSH_PKCS7_ENVELOPED_DATA:
      SSH_DEBUG(5, ("Decode ENVELOPED DATA."));
      rv = ssh_asn1_read_node(context, node,
                              "(sequence (l*)"
                              "  (integer-short ())"         /* Version */
                              "  (set (l*) (any ()))"        /* Recipients */
                              "  (sequence (l*)"
                              "     (object-identifier ())"  /* Content type */
                              "     (any (l*))"             /* Parameters */
                              "     (optional"
                              "      (octet-string (l* 0)))))",
                              &pkcs7->version,
                              &recipient_node,
                              &content_type_oid,
                              &algorithm_node,
                              &found, &data, &data_length);

      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Asn.1 decoding of enveloped data failed"));
          status = SSH_PKCS7_CONTENT_DECODING_FAILED;
          goto failed;
        }

      if (!found)
        {
          /* Make sure that the data doesn't contain anything misleading. */
          pkcs7->data = NULL;
          pkcs7->data_length = 0;
        }
      else
        {
          pkcs7->data = data;
          pkcs7->data_length = data_length;
        }

      /* Handle the version. */
      if (pkcs7->version != 0)
        {
          status = SSH_PKCS7_VERSION_UNKNOWN;
          goto failed;
        }

      /* Handle the recipients. */
      returned_status =
        ssh_pkcs7_decode_recipient_infos(context,
                                         recipient_node,
                                         &pkcs7->recipient_infos);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }

      /* Handle the content type. */
      oids = ssh_oid_find_by_oid_of_type(content_type_oid, SSH_OID_PKCS7);
      ssh_free(content_type_oid);
      if (oids == NULL)
        {
          status = SSH_PKCS7_CONTENT_TYPE_UNKNOWN;
          goto failed;
        }
      pkcs7->encrypted_type = oids->extra_int;

      if (ssh_pkcs7_decode_cipher_info(context,
                                       algorithm_node,
                                       &pkcs7->cipher_info) != SSH_PKCS7_OK)
        {
          status = SSH_PKCS7_ALGORITHM_UNKNOWN;
          goto failed;
        }
      break;

    case SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA:
      SSH_DEBUG(5, ("Decode SIGNED ENVELOPED DATA."));
      rv = ssh_asn1_read_node(context, node,
                              "(sequence (l*)"
                              "  (integer-short ())"     /* Version */
                              "  (set (l*) (any ()))"    /* Recipients */
                              "  (set (l*) (any ()))"    /* Digest alg. */
                              "  (sequence (l*)"
                              "    (object-identifier ())"  /* Content type */
                              "    (any (l*))"                /* Cipher */
                              "    (optional"
                              "      (octet-string (l*))))"   /* Content */
                              "  (optional"
                              "    (set (l* 0) (any ())))"   /* Certificates */
                              "  (optional"
                              "    (set (l* 1) (any ())))"   /* CRLs */
                              "  (set (l*) (any ())))",     /* Signers */
                              &pkcs7->version,
                              &recipient_node,
                              &digest_alg_node,
                              &content_type_oid,
                              &algorithm_node,
                              &found, &pkcs7->data, &pkcs7->data_length,
                              &certs_found, &certs_node,
                              &crls_found, &crls_node,
                              &signer_info_node);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Asn.1 decoding signed and enveloped data failed"));
          status = SSH_PKCS7_CONTENT_DECODING_FAILED;
          goto failed;
        }

      /* Check if data was found. */
      if (!found)
        {
          /* Make sure that the data doesn't contain anything misleading. */
          pkcs7->data        = NULL;
          pkcs7->data_length = 0;
        }

      /* Handle the version. */
      if (pkcs7->version != 1)
        {
          SSH_DEBUG(5, ("Version not 1."));
          status = SSH_PKCS7_VERSION_UNKNOWN;
          goto failed;
        }

      /* Handle recipients. */
      returned_status =
        ssh_pkcs7_decode_recipient_infos(context,
                                         recipient_node,
                                         &pkcs7->recipient_infos);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }

      /* Handle the digest algorithms. */
      returned_status = ssh_pkcs7_decode_oids(context,
                                              digest_alg_node,
                                              &pkcs7->digest_algorithms);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }

      /* Handle the content type. */
      oids = ssh_oid_find_by_oid_of_type(content_type_oid, SSH_OID_PKCS7);
      ssh_free(content_type_oid);
      if (oids == NULL)
        {
          status = SSH_PKCS7_CONTENT_TYPE_UNKNOWN;
          goto failed;
        }
      pkcs7->encrypted_type = oids->extra_int;

      /* Find the cipher algorithm. */
      if (ssh_pkcs7_decode_cipher_info(context,
                                       algorithm_node,
                                       &pkcs7->cipher_info) != SSH_PKCS7_OK)
        {
          status = SSH_PKCS7_ALGORITHM_UNKNOWN;
          goto failed;
        }

      /* Decode the certificates. */
      if (certs_found)
        {
          returned_status =
            ssh_pkcs7_decode_certs(context, certs_node, &pkcs7->certificates);
          if (returned_status != SSH_PKCS7_OK)
            {
              status = returned_status;
              goto failed;
            }
        }

      /* Decode the CRLs. */
      if (crls_found)
        {
          returned_status =
            ssh_pkcs7_decode_crls(context, crls_node, &pkcs7->crls);
          if (returned_status != SSH_PKCS7_OK)
            {
              status = returned_status;
              goto failed;
            }
        }

      /* Decode signer infos. */
      returned_status = ssh_pkcs7_decode_signer_infos(context,
                                                      signer_info_node,
                                                      &pkcs7->signer_infos);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }
      break;

    case SSH_PKCS7_DIGESTED_DATA:
      SSH_DEBUG(5, ("Decode DIGESTED DATA."));

      rv = ssh_asn1_read_node(context, node,
                              "(sequence (l*)"
                              "  (integer-short ())"       /* Version */
                              "  (sequence (l*)"
                              "    (object-identifier ())" /* Algorithm */
                              "    (any ()))"
                              "  (any ())"                 /* Content */
                              "  (octet-string ()))",      /* Digest */
                              &pkcs7->version,
                              &algorithm_oid,
                              &algorithm_params,
                              &content_info,
                              &pkcs7->content_digest,
                              &pkcs7->content_digest_length);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Asn.1 decoding digested data failed"));
          status = SSH_PKCS7_CONTENT_DECODING_FAILED;
          goto failed;
        }

      /* Check the version. */
      if (pkcs7->version != 0)
        {
          status = SSH_PKCS7_VERSION_UNKNOWN;
          goto failed;
        }

      /* Handle the algorithm oid. */
      oids = ssh_oid_find_by_oid_of_type(algorithm_oid, SSH_OID_HASH);
      ssh_free(algorithm_oid);
      if (oids == NULL)
        {
          status = SSH_PKCS7_ALGORITHM_UNKNOWN;
          goto failed;
        }
      pkcs7->content_digest_algorithm = ssh_strdup(oids->name);

      /* Now harder part of actually figuring out the content. This
         happens with a clever recursive jump.  */
      returned_status = ssh_pkcs7_recursive_decode(context,
                                                   content_info,
                                                   &pkcs7->content);
      if (returned_status != SSH_PKCS7_OK)
        {
          status = returned_status;
          goto failed;
        }
      break;

    case SSH_PKCS7_ENCRYPTED_DATA:
      SSH_DEBUG(5, ("Decode ENCRYPTED DATA."));
      rv = ssh_asn1_read_node(context, node,
                              "(sequence (l*)"
                              "  (integer-short ())"        /* Version */
                              "  (sequence (l*)"
                              "    (object-identifier ())"  /* Content type */
                              "    (any (l*))"                /* Cipher */
                              "    (optional"
                              "      (octet-string (l* 0)))))", /* Content */
                              &pkcs7->version,
                              &content_type_oid,
                              &algorithm_node,
                              &found,
                              &pkcs7->data, &pkcs7->data_length);
      if (rv != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(5, ("Asn.1 decoding encrypted data failed"));
          status = SSH_PKCS7_CONTENT_DECODING_FAILED;
          goto failed;
        }

      /* Check if found. */
      if (!found)
        {
          /* Make sure that the data doesn't contain anything misleading. */
          pkcs7->data        = NULL;
          pkcs7->data_length = 0;
        }

      /* Handle the version number. */
      if (pkcs7->version != 0)
        {
          status = SSH_PKCS7_VERSION_UNKNOWN;
          goto failed;
        }

      /* Handle the content type. */
      oids = ssh_oid_find_by_oid_of_type(content_type_oid, SSH_OID_PKCS7);
      ssh_free(content_type_oid);
      if (oids == NULL)
        {
          status = SSH_PKCS7_CONTENT_TYPE_UNKNOWN;
          goto failed;
        }
      pkcs7->encrypted_type = oids->extra_int;

      /* Find the cipher algorithm. */
      if (ssh_pkcs7_decode_cipher_info(context,
                                       algorithm_node,
                                       &pkcs7->cipher_info) != SSH_PKCS7_OK)
        {
          status = SSH_PKCS7_ALGORITHM_UNKNOWN;
          goto failed;
        }
      break;


    default:
      status = SSH_PKCS7_CONTENT_TYPE_UNKNOWN;
      goto failed;
    }

  /* Return the correct PKCS #7 data structure. */
  *pkcs7_return = pkcs7;
  pkcs7         = NULL;

failed:
  /* Assume that if we get here without passing the copy of the
     pointers above, then it implies that a failure has occurred, and
     the context must be freed. */
  if (pkcs7)
    ssh_pkcs7_free(pkcs7);

  return status;
}

SshPkcs7Status
ssh_pkcs7_recursive_decode(SshAsn1Context context,
                           SshAsn1Node root,
                           SshPkcs7 *pkcs7_return)
{
  SshAsn1Status   rv;
  SshAsn1Node     node;
  SshPkcs7Status  status;
  const SshOidStruct    *oids;
  unsigned char  *content_type;
  Boolean         node_found;

  SSH_DEBUG(5, ("Decode content (ASN.1)."));

  /* Make sure that we don't return garbage. */
  *pkcs7_return = NULL;

  /* Check for the trivial case. */
  if (root == NULL)
    return SSH_PKCS7_OK;

  /* Decode the top layer. */
  rv = ssh_asn1_read_node(context, root,
                          "(sequence (*)"
                          "  (object-identifier ())"
                          "  (optional (any (l*e 0))))",
                          &content_type,
                          &node_found,
                          &node);

  if (rv != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(5, ("Asn.1 decoding PKCS#7 top level data structure failed."));
      status = SSH_PKCS7_ASN1_DECODING_FAILED;
      goto failed;
    }

  /* Determine the content type, which will tell us about the next
     move in decoding. */
  oids = ssh_oid_find_by_oid_of_type(content_type, SSH_OID_PKCS7);
  ssh_free(content_type);
  if (oids == NULL)
    {
      SSH_DEBUG(5, ("Content type unknown."));
      status = SSH_PKCS7_CONTENT_TYPE_UNKNOWN;
      goto failed;
    }

  if (node_found == FALSE)
    node = NULL;

  /* Call the function which decodes the content. */
  status = ssh_pkcs7_recursive_decode_content(context, node,
                                              oids->extra_int,
                                              pkcs7_return);

  /* Failure? */
failed:
  return status;
}

/* Main decoding routine, which sets up the ASN.1 BER/DER decoding. */
SshPkcs7Status
ssh_pkcs7_decode(const unsigned char *data, size_t data_length,
                 SshPkcs7 *pkcs7)
{
  SshAsn1Context context;
  SshAsn1Node    node;
  SshAsn1Status  rv;
  SshPkcs7Status status;

  SSH_DEBUG(5, ("Decode blob of PKCS-7."));

  /* Initialize the ASN.1 BER/DER allocation context. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS7_FAILURE;
  ssh_asn1_set_limits(context, data_length, 0);

  rv = ssh_asn1_decode_node(context, data, data_length, &node);
  if (rv != SSH_ASN1_STATUS_OK &&
      rv != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      rv != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      status = SSH_PKCS7_ASN1_DECODING_FAILED;
      goto failed;
    }

  /* Run the recursive decoder. */
  status = ssh_pkcs7_recursive_decode(context, node, pkcs7);

failed:
  ssh_asn1_free(context);
  return status;
}

SshPkcs7Status ssh_pkcs7_decode_data(const unsigned char *data,
                                     size_t data_length,
                                     SshPkcs7ContentType content_type,
                                     SshPkcs7 *pkcs7)
{
  SshPkcs7Status status;
  SshAsn1Context context;
  SshAsn1Status rv;
  SshAsn1Node node;

  if ((context = ssh_asn1_init()) == NULL)
    return SSH_PKCS7_FAILURE;

  rv = ssh_asn1_decode_node(context, data, data_length, &node);
  if (rv != SSH_ASN1_STATUS_OK &&
      rv != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      rv != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      status = SSH_PKCS7_ASN1_DECODING_FAILED;
      goto failed;
    }
  status = ssh_pkcs7_recursive_decode_content(context, node,
                                              content_type, pkcs7);

 failed:
  ssh_asn1_free(context);
  return status;
}
#endif /* SSHDIST_CERT */
