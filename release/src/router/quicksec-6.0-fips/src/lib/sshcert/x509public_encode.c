/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decode and encode routines for x509 public keys.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"
#ifdef SSHDIST_CRYPT_ECP
#include "sshmp-ecp.h"
#include "eckeys.h"
#endif /* SSHDIST_CRYPT_ECP */


#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertX509"

SshAsn1Node ssh_x509_encode_public_key_internal(SshAsn1Context context,
                                                SshPublicKey key)
{
  SshAsn1Node pk_param, pk_info;
  SshAsn1Tree pk_tree;
  SshAsn1Status status;
  const SshOidStruct *oids;
  unsigned char *pk = NULL;
  size_t pk_len;
#ifdef SSHDIST_CRYPT_ECP
  unsigned char *param_buf = NULL;
  size_t param_len;
#endif /* SSHDIST_CRYPT_ECP */

  const SshX509PkAlgorithmDefStruct *algorithm;
  SshMPIntegerStruct n, e, p, q, g, y;
  Boolean ok;


  /* Encode information about the public key. */

  if (key == NULL)
    return NULL;

  algorithm = ssh_x509_public_key_algorithm(key);
  if (algorithm == NULL)
    return NULL;

  oids = ssh_oid_find_by_std_name_of_type(algorithm->known_name, SSH_OID_PK);
  if (oids == NULL)
    return NULL;

  /* Initialize pointers. */
  pk_param = NULL;
  pk_tree = NULL;

  ok = FALSE;

  switch (algorithm->algorithm)
    {
    case SSH_X509_PKALG_RSA:
      ssh_mprz_init(&n);
      ssh_mprz_init(&e);

      /* Create null parameters. */
      status = ssh_asn1_create_node(context, &pk_param, "(null ())");
      if (status != SSH_ASN1_STATUS_OK)
        goto rsa_failed;

      if (ssh_public_key_get_info(key,
                                  SSH_PKF_MODULO_N, &n,
                                  SSH_PKF_PUBLIC_E, &e,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        goto rsa_failed;

      /* Create the tree out of the public key. */
      status =
        ssh_asn1_create_tree(context, &pk_tree,
                             "(sequence ()"
                             "(integer ())"   /* n */
                             "(integer ()))", /* e */
                             &n, &e);
      if (status != SSH_ASN1_STATUS_OK)
        goto rsa_failed;

      ok = TRUE;

    rsa_failed:
      ssh_mprz_clear(&n);
      ssh_mprz_clear(&e);
      break;

    case SSH_X509_PKALG_DSA:
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);
      ssh_mprz_init(&y);

      if (ssh_public_key_get_info(key,
                                  SSH_PKF_PRIME_P, &p,
                                  SSH_PKF_PRIME_Q, &q,
                                  SSH_PKF_GENERATOR_G, &g,
                                  SSH_PKF_PUBLIC_Y, &y,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        goto dsa_failed;

      status =
        ssh_asn1_create_node(context, &pk_param,
                             "(sequence ()"
                             "  (integer ())"
                             "  (integer ())"
                             "  (integer ()))",
                             &p, &q, &g);
      if (status != SSH_ASN1_STATUS_OK)
        goto dsa_failed;

      status =
        ssh_asn1_create_tree(context, &pk_tree,
                             "(integer ())",
                             &y);

      if (status != SSH_ASN1_STATUS_OK)
        goto dsa_failed;

      ok = TRUE;

    dsa_failed:
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&y);
      ssh_mprz_clear(&g);
      break;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_X509_PKALG_ECDSA:
      if (!ssh_x509_encode_ecp_key_params(key,TRUE,
                                          &param_buf, &param_len))
        break;
      if (ssh_asn1_decode_node(context, param_buf,
                               param_len, &pk_param)
                                  != SSH_ASN1_STATUS_OK)
        {
          ssh_free(param_buf);
          break;
        }
      ssh_free(param_buf);
      if (!ssh_x509_encode_ecp_public_key_internal(key,
                                                   &pk, &pk_len))
        break;
      ok = TRUE;
      break;
#endif /* SSHDIST_CRYPT_ECP */
    default:
      ssh_fatal("ssh_x509_encode_public_key: algorithm detection failed.");
      break;
    }

  pk_info = NULL;
  if (ok)
    {
#ifdef SSHDIST_CRYPT_ECP
      if (algorithm->algorithm == SSH_X509_PKALG_ECDSA)
        ;
      else
        {
#endif /* SSHDIST_CRYPT_ECP */
          status = ssh_asn1_encode(context, pk_tree);
          if (status == SSH_ASN1_STATUS_OK)
            ssh_asn1_get_data(pk_tree, &pk, &pk_len);
          else
            return NULL;
#ifdef SSHDIST_CRYPT_ECP
        }
#endif /* SSHDIST_CRYPT_ECP */
      status = ssh_asn1_create_node(context, &pk_info,
                                    "(sequence ()"
                                    "  (sequence ()"
                                    "    (object-identifier ())"
                                    "    (any ()))"
                                    "  (bit-string ()))",
                                    oids->oid,
                                    pk_param,
                                    pk, pk_len * 8);
      ssh_free(pk);

      if (status != SSH_ASN1_STATUS_OK)
        pk_info = NULL;
    }
  return pk_info;
}

SshAsn1Node ssh_x509_encode_public_group_internal(SshAsn1Context context,
                                                  SshPkGroup pk_group)
{
  SshAsn1Node pk_param, pk_info;
  SshAsn1Status status;
  const SshOidStruct *oids;
  const SshX509PkAlgorithmDefStruct *algorithm;
  SshMPIntegerStruct p, q, g;
  Boolean ok;

  /* Encode information about the public key. */
  if (pk_group == NULL)
    return NULL;

  algorithm = ssh_x509_public_group_algorithm(pk_group);
  if (algorithm == NULL)
    return NULL;

  oids = ssh_oid_find_by_std_name_of_type(algorithm->known_name, SSH_OID_PK);
  if (oids == NULL)
    return NULL;

  /* Initialize pointers. */
  pk_param = NULL;

  ok = FALSE;
  switch (algorithm->algorithm)
    {
    case SSH_X509_PKALG_DH:
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);

      if (ssh_pk_group_get_info(pk_group,
                                SSH_PKF_PRIME_P, &p,
                                SSH_PKF_PRIME_Q, &q,
                                SSH_PKF_GENERATOR_G, &g,
                                SSH_PKF_END) != SSH_CRYPTO_OK)
        goto dh_failed;

      status =
        ssh_asn1_create_node(context, &pk_param,
                             "(sequence ()"
                             "  (integer ())"
                             "  (integer ())"
                             "  (integer ()))",
                             &p, &q, &g);
      if (status != SSH_ASN1_STATUS_OK)
        goto dh_failed;

      ok = TRUE;

    dh_failed:
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&g);
      break;

    default:
      ssh_fatal("ssh_x509_encode_public_key: algorithm detection failed.");
      break;
    }

  pk_info = NULL;
  if (ok)
    {
      status =
        ssh_asn1_create_node(context, &pk_info,
                             "(sequence ()"
                             "  (sequence ()"
                             "    (object-identifier ())"
                             "    (any ())))",
                             oids->oid,
                             pk_param);
      if (status != SSH_ASN1_STATUS_OK)
        pk_info = NULL;
    }

  return pk_info;
}

SshAsn1Node ssh_x509_encode_public_key(SshAsn1Context context,
                                       SshX509PublicKey pkey)
{
  if (pkey == NULL)
    return NULL;

  if (pkey->public_key)
    return ssh_x509_encode_public_key_internal(context, pkey->public_key);
  if (pkey->public_group)
    return ssh_x509_encode_public_group_internal(context, pkey->public_group);
  return NULL;
}

/* This function computes standard PKIX key identifier for the
   certificate. The method is as RFC2459 section 4.2.1.2 suggests.
   The function returns NULL if the certificate does not contain
   public key. */
unsigned char *
ssh_x509_cert_compute_key_identifier(SshX509Certificate c,
                                     const char *hash_algorithm,
                                     size_t *kid_len)
{
  SshAsn1Node node, any;
  SshAsn1Context context;
  unsigned char *oid, *pk, *kid = NULL;
  size_t pkbits;

  *kid_len = 0;

  if (c->subject_pkey.pk_type == SSH_X509_PKALG_UNKNOWN)
    return NULL;
  else
    {
      if ((context = ssh_asn1_init()) == NULL)
        return NULL;

      node = ssh_x509_encode_public_key(context, &c->subject_pkey);
      if (node)
        {
          if (ssh_asn1_read_node(context, node,
                                 "(sequence ()"
                                 "  (sequence ()"
                                 "    (object-identifier ())"
                                 "    (any ()))"
                                 "  (bit-string ()))",
                                 &oid, &any, &pk, &pkbits)
              == SSH_ASN1_STATUS_OK)
            {
              SshHash hash;

              if (ssh_hash_allocate(hash_algorithm, &hash) == SSH_CRYPTO_OK)
                {
                  *kid_len = ssh_hash_digest_length(hash_algorithm);
                  if ((kid = ssh_malloc(*kid_len)) != NULL)
                    {
                      ssh_hash_update(hash, pk, pkbits/8);
                      ssh_hash_final(hash, kid);
                    }
                  ssh_hash_free(hash);
                }
              ssh_free(oid);
              ssh_free(pk);
            }
        }
      ssh_asn1_free(context);
    }
  return kid;
}
/* This function computes key identifier per Ikev2 way */
unsigned char *
ssh_x509_cert_compute_key_identifier_ike(SshX509Certificate c,
                                         const char *hash_algorithm,
                                         size_t *kid_len)
{
  SshAsn1Node node;
  SshAsn1Context context;
  unsigned char *data = NULL, *kid = NULL;
  size_t len;
  SshHash hash;

  *kid_len = 0;

  if (c->subject_pkey.pk_type == SSH_X509_PKALG_UNKNOWN)
    return NULL;
  else
    {
      if ((context = ssh_asn1_init()) == NULL)
        return NULL;

      if ((node = ssh_x509_encode_public_key(context, &c->subject_pkey))
          != NULL)
        {
          if (ssh_asn1_encode_node(context, node) == SSH_ASN1_STATUS_OK)
            {
              ssh_asn1_node_get_data(node, &data, &len);
              if (ssh_hash_allocate(hash_algorithm, &hash) == SSH_CRYPTO_OK)
                {
                  *kid_len = ssh_hash_digest_length(hash_algorithm);
                  if ((kid = ssh_malloc(*kid_len)) != NULL)
                    {
                      ssh_hash_update(hash, data, len);
                      ssh_hash_final(hash, kid);
                    }
                  ssh_hash_free(hash);
                }
              ssh_free(data);
            }
        }
      ssh_asn1_free(context);
    }
  return kid;
}
#endif /* SSHDIST_CERT */
