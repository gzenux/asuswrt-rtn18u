/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   PKCS#8 private key formats.
*/

#include "sshincludes.h"
#include "sshasn1.h"
#include "x509.h"
#include "oid.h"

#include "sshpkcs1.h"
#include "sshpkcs5.h"
#include "sshpkcs8.h"

#include "sshmp.h"
#ifdef SSHDIST_CRYPT_ECP
#include "sshmp-ecp.h"
#include "eckeys.h"
#endif /* SSHDIST_CRYPT_ECP */

#define SSH_DEBUG_MODULE "SshPkcs8"

#ifdef SSHDIST_CERT
/* Routines to handle specific private keys. */

Boolean
ssh_pkcs8_encode_dsa_private_key(SshPrivateKey private_key,
                                 unsigned char **buf, size_t *buf_len,
                                 unsigned char **params, size_t *params_len);

SshPrivateKey
ssh_pkcs8_decode_dsa_private_key(SshAsn1Context context,
                                 unsigned char *buf, size_t buf_len,
                                 SshAsn1Node params);

Boolean
ssh_pkcs8_encode_dsa_private_key(SshPrivateKey private_key,
                                 unsigned char **buf, size_t *buf_len,
                                 unsigned char **params, size_t *params_len)
{
  SshAsn1Context context = NULL;
  SshAsn1Node    prv_key;
  SshAsn1Status  status;
  const char *name;
  SshMPIntegerStruct p, q, g, y, x;
  Boolean rv = FALSE;
  SshAsn1Node dsaparam;

  *buf = NULL;
  *buf_len = 0;
  *params = NULL;
  *params_len = 0;

  /* Try to decode the name of the private key. */
  if (ssh_private_key_get_info(private_key,
                               SSH_PKF_KEY_TYPE, &name,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;

  if (strcmp(name, "dl-modp") != 0)
    return FALSE;

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&y);
  ssh_mprz_init(&x);

  /* Initialize the ASN.1 parser. */
  context = ssh_asn1_init();
  if (context == NULL)
    goto failed;

  if (ssh_private_key_get_info(private_key,
                               SSH_PKF_PRIME_P, &p,
                               SSH_PKF_PRIME_Q, &q,
                               SSH_PKF_GENERATOR_G, &g,
                               SSH_PKF_PUBLIC_Y, &y,
                               SSH_PKF_SECRET_X, &x,
                               SSH_PKF_END)
      == SSH_CRYPTO_OK)
    {
#if 0
      status = ssh_asn1_create_node(context, &prv_key,
                                    "(sequence ()"
                                    "  (integer-short ())" /* version */
                                    "  (integer ())"   /* p */
                                    "  (integer ())"   /* q */
                                    "  (integer ())"   /* g */
                                    "  (integer ())"   /* y */
                                    "  (integer ()))",  /* x */
                                    (SshWord)0, &p, &q, &g, &y, &x);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
#else
      status = ssh_asn1_create_node(context, &dsaparam,
                                    "(sequence ()"
                                    "  (integer ())"   /* p,q,g */
                                    "  (integer ())"
                                    "  (integer ()))",
                                    &p, &q, &g);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      status = ssh_asn1_create_node(context, &prv_key, "(integer ())", &x);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;

      status = ssh_asn1_encode_node(context, dsaparam);
      if (status != SSH_ASN1_STATUS_OK)
        goto failed;
      ssh_asn1_node_get_data(dsaparam, params, params_len);
#endif
      status = ssh_asn1_encode_node(context, prv_key);
      if (status != SSH_ASN1_STATUS_OK)
        {
          ssh_free(*params);
          goto failed;
        }
      ssh_asn1_node_get_data(prv_key, buf, buf_len);

      rv = TRUE;
    }

failed:
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&x);
  if (context)
    ssh_asn1_free(context);
  return rv;
}

SshPrivateKey
ssh_pkcs8_decode_dsa_private_key(SshAsn1Context context,
                                 unsigned char *buf, size_t buf_len,
                                 SshAsn1Node params)
{
  SshAsn1Tree    tree;
  SshAsn1Status  status;
  SshWord        version = 42;
  SshMPIntegerStruct p, q, g, y, x;
  SshPrivateKey  private_key;
  SshCryptoStatus crypto_status = SSH_CRYPTO_OPERATION_FAILED;

  /* Initialize the private key. */
  private_key = NULL;

  status = ssh_asn1_decode(context, buf, buf_len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      return NULL;
    }

  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&g);
  ssh_mprz_init(&y);
  ssh_mprz_init(&x);

  if (ssh_asn1_read_tree(context, tree,
                         "(sequence ()"
                         "  (integer-short ())"  /* version */
                         "  (integer ())"  /* p */
                         "  (integer ())"  /* q */
                         "  (integer ())"  /* g */
                         "  (integer ())"  /* y */
                         "  (integer ()))", /* x */
                         &version, &p, &q, &g, &y, &x)
      == SSH_ASN1_STATUS_OK)
    goto key_read;

  if (ssh_asn1_read_tree(context, tree, "(integer ())", &x)
      == SSH_ASN1_STATUS_OK)
    {
      if (ssh_asn1_read_node(context, params,
                             "(sequence ()"
                             " (integer ())"
                             " (integer ())"
                             " (integer ()))",
                             &p, &q, &g) == SSH_ASN1_STATUS_OK)
        {
          version = 0;
          ssh_mprz_powm(&y, &g, &x, &p);
          goto key_read;
        }
    }
  return NULL;

 key_read:
  private_key = NULL;
  if (version == 0)
    crypto_status =
      ssh_private_key_define(&private_key,
                             "dl-modp",
                             SSH_PKF_PRIME_P, &p,
                             SSH_PKF_PRIME_Q, &q,
                             SSH_PKF_GENERATOR_G, &g,
                             SSH_PKF_PUBLIC_Y, &y,
                             SSH_PKF_SECRET_X, &x,
                             SSH_PKF_END);

  ssh_mprz_clear(&p);
  ssh_mprz_clear(&g);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&x);

  if (crypto_status != SSH_CRYPTO_OK)
    private_key = NULL;

  return private_key;
}

#ifdef SSHDIST_CRYPT_ECP
SshPrivateKey
ssh_pkcs8_decode_ecdsa_private_key(SshAsn1Context context,
                                   unsigned char *buf, size_t buf_len,
                                   SshAsn1Node params)
{
  SshAsn1Tree tree;
  SshAsn1Node attrs = NULL;
  SshAsn1Status status;
  SshPrivateKey private_key = NULL;
  SshECPCurveStruct E;
  SshECPPointStruct P, Y;
  const char *out_name = NULL;
  SshMPIntegerStruct x, n, version;
  size_t field_len;
  size_t prv_key_str_len, pub_key_len;
  Boolean attrs_found = FALSE;
  Boolean pub_key_found = FALSE;
  Boolean pc = FALSE;
  unsigned char * prv_key_str = NULL;
  unsigned char * pub_key = NULL;

  status = ssh_asn1_decode(context, buf, buf_len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    return NULL;

  ssh_mprz_init(&version);
  status =
         ssh_asn1_read_tree(context, tree,
                            "(sequence ()"
                            "   (integer  ())" /* version */
                            "   (octet-string ())" /* private key */
                            "   (optional"
                            "       (any (e 0)))"
                            "   (optional "
                            "     (bit-string (e 1))))", /* Public key */
                            &version,
                            &prv_key_str, &prv_key_str_len,
                            &attrs_found, &attrs,
                            &pub_key_found, &pub_key, &pub_key_len);

  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  if ((params == NULL) && (attrs == NULL))
    goto failed;

  if (ssh_mprz_cmp_ui(&version, 1) != 0)
    goto failed;

  if (ssh_x509_decode_ecp_curve(context, params,
                                &E, &P,
                                &n, &out_name,
                                &field_len) != SSH_X509_OK)
    goto failed;

  ssh_mprz_init(&x);
  ssh_mprz_set_buf(&x, prv_key_str, prv_key_str_len);

  ssh_ecp_init_point(&Y, &E);

  if (pub_key_found)
    {
      if (!ssh_ecp_set_point_from_octet_str(&Y, &E, field_len,
                                            pub_key, pub_key_len, &pc))
        goto failed_1;

      if (ssh_private_key_define(&private_key,
                                 "ec-modp",
                                 SSH_PKF_PRIME_P, &E.q,
                                 SSH_PKF_GENERATOR_G, &P.x, &P.y,
                                 SSH_PKF_PRIME_Q, &n,
                                 SSH_PKF_CURVE_A, &E.a,
                                 SSH_PKF_CURVE_B, &E.b,
                                 SSH_PKF_CARDINALITY, &E.c,
                                 SSH_PKF_PUBLIC_Y, &Y.x, &Y.y,
                                 SSH_PKF_SECRET_X, &x,
                                 SSH_PKF_PREDEFINED_GROUP, out_name,
                                 SSH_PKF_POINT_COMPRESS, FALSE,
                                 SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          private_key = NULL;
          goto failed_1;
        }
    }
  else
    {
      if (ssh_private_key_define(&private_key,
                                 "ec-modp",
                                 SSH_PKF_PRIME_P, &E.q,
                                 SSH_PKF_GENERATOR_G, &P.x, &P.y,
                                 SSH_PKF_PRIME_Q, &n,
                                 SSH_PKF_CURVE_A, &E.a,
                                 SSH_PKF_CURVE_B, &E.b,
                                 SSH_PKF_CARDINALITY, &E.c,
                                 SSH_PKF_SECRET_X, &x,
                                 SSH_PKF_PREDEFINED_GROUP, out_name,
                                 SSH_PKF_POINT_COMPRESS, FALSE,
                                 SSH_PKF_END) != SSH_CRYPTO_OK)
        private_key = NULL;
    }

failed_1:
  ssh_ecp_clear_curve(&E);
  ssh_ecp_clear_point(&P);
  ssh_ecp_clear_point(&Y);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&n);
failed:
  if (pub_key_found)
    ssh_free(pub_key);
  if (prv_key_str)
    ssh_free(prv_key_str);
  ssh_mprz_clear(&version);
  return private_key;
}

Boolean
ssh_pkcs8_encode_ecdsa_private_key(SshPrivateKey private_key,
                                 unsigned char **buf, size_t *buf_len,
                                 unsigned char **params, size_t *params_len)
{
  Boolean rv = FALSE;

  *buf = NULL;
  *buf_len = 0;
  *params = NULL;
  *params_len = 0;

  if (!ssh_x509_encode_ecp_private_key_internal(private_key,
                                               SSH_X509_ECP_ENCODE_PUBLIC_KEY,
                                               buf, buf_len))
    goto failed;

  if (!ssh_x509_encode_ecp_key_params(private_key, FALSE,
                                      params, params_len))
    goto failed;

  rv = TRUE;

failed:
  return rv;
}
#endif /* SSHDIST_CRYPT_ECP */


/* Encode the PKCS-8 private key. Returns a binary DER encoding. */
SshX509Status
ssh_pkcs8_encode_private_key(const SshPrivateKey private_key,
                             unsigned char **buf, size_t *buf_len)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Node paramnode = NULL;
  SshAsn1Status status;
  SshX509Status rv = SSH_X509_FAILED_UNKNOWN_VALUE;
  const SshOidStruct *oids;
  const SshX509PkAlgorithmDefStruct *algorithm;
  unsigned char *oct_s, *params;
  size_t oct_s_len, params_len;

  /* Initialize. */
  oct_s     = NULL;
  oct_s_len = 0;

  /* Find the algorithm we are after. */
  algorithm = ssh_x509_private_key_algorithm(private_key);
  if (algorithm == NULL)
    return SSH_X509_FAILED_UNKNOWN_VALUE;

  oids = ssh_oid_find_by_std_name_of_type(algorithm->known_name, SSH_OID_PK);
  if (oids == NULL)
    return SSH_X509_FAILED_UNKNOWN_VALUE;

  /* Initialize the ASN.1 parser. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_X509_FAILED_ASN1_ENCODE;

  switch (algorithm->algorithm)
    {
    case SSH_X509_PKALG_RSA:
      /* Use the PKCS-1 format code. */
      if (!ssh_pkcs1_encode_private_key(private_key, &oct_s, &oct_s_len))
        {
          rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
          goto failed;
        }
      ssh_asn1_create_node(context, &paramnode, "(null ())");
      break;

    case SSH_X509_PKALG_DSA:
      if (!ssh_pkcs8_encode_dsa_private_key(private_key,
                                            &oct_s, &oct_s_len,
                                            &params, &params_len))
        {
          rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
          goto failed;
        }
      if (ssh_asn1_decode_node(context, params, params_len, &paramnode)
          != SSH_ASN1_STATUS_OK)
        {
          ssh_free(params);
          goto failed;
        }
      ssh_free(params);
      break;
#ifdef SSHDIST_CRYPT_ECP
   case SSH_X509_PKALG_ECDSA:
      if (!ssh_pkcs8_encode_ecdsa_private_key(private_key,
                                              &oct_s, &oct_s_len,
                                              &params, &params_len))
        {
          rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
          goto failed;
        }
      if (ssh_asn1_decode_node(context, params, params_len, &paramnode)
          != SSH_ASN1_STATUS_OK)
        {
          ssh_free(params);
          goto failed;
        }
      ssh_free(params);
      break;
#endif /* SSHDIST_CRYPT_ECP */
    default:
      rv = SSH_X509_FAILED_UNKNOWN_VALUE;
      goto failed;
      break;
    }

  status =
    ssh_asn1_create_tree(context, &tree,
                         "(sequence ()"
                         "  (integer-short ())"
                         "  (sequence ()"
                         "    (object-identifier ())"
                         "    (any ()))"
                         "  (octet-string ()))",
                         (SshWord)0,
                         oids->oid,
                         paramnode,
                         oct_s, oct_s_len);

  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  status = ssh_asn1_encode(context, tree);
  if (status != SSH_ASN1_STATUS_OK)
    {
      rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  ssh_asn1_get_data(tree, buf, buf_len);
  rv = SSH_X509_OK;

 failed:
  ssh_free(oct_s);
  ssh_asn1_free(context);
  return rv;
}

/* Decode the PKCS-8 private key. */
SshX509Status
ssh_pkcs8_decode_private_key(const unsigned char *buf, size_t buf_len,
                             SshPrivateKey *key)
{
  SshPrivateKey private_key;
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Node alg_param = NULL;
  SshAsn1Status status;
  const SshOidStruct *oids;
  unsigned char *oid;
  SshX509Status rv;
  SshMPIntegerStruct version;
  unsigned char *oct_s;
  size_t         oct_s_len;
  Boolean attributes_found;
  SshAsn1Node attributes = NULL;

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP,
                    ("Decoding pkcs8-encoded private key buffer"),
                    buf, buf_len);

  /* Initialize. */
  private_key = NULL;
  oct_s       = NULL;
  oct_s_len   = 0;

  /* Initialize ASN.1 context. */
  if ((context = ssh_asn1_init()) == NULL)
    return SSH_X509_FAILURE;

  status =
    ssh_asn1_decode(context, buf, buf_len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    {
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  ssh_mprz_init(&version);

  status =
    ssh_asn1_read_tree(context, tree,
                       "(sequence ()"
                       "  (integer ())"
                       "  (sequence ()"
                       "    (object-identifier ())"
                       "    (any ()))"
                       "  (octet-string ())"
                       "  (optional"
                       "    any (0)))",
                       &version,
                       &oid,
                       &alg_param,
                       &oct_s, &oct_s_len,
                       &attributes_found, &attributes);

  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&version);
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto failed;
    }

  ssh_mprz_clear(&version);

  oids = ssh_oid_find_by_oid_of_type(oid, SSH_OID_PK);
  /* Free the oid array. */
  ssh_free(oid);

  if (oids == NULL)
    {
      rv = SSH_X509_FAILED_UNKNOWN_VALUE;
      goto failed;
    }

  switch (((SshOidPk)oids->extra)->alg_enum)
    {
    case SSH_X509_PKALG_RSA:
      private_key = ssh_pkcs1_decode_private_key(oct_s, oct_s_len);
      break;
    case SSH_X509_PKALG_DSA:
      private_key = ssh_pkcs8_decode_dsa_private_key(context,
                                                     oct_s, oct_s_len,
                                                     alg_param);
      break;
#ifdef SSHDIST_CRYPT_ECP
    case SSH_X509_PKALG_ECDSA:

      private_key = ssh_pkcs8_decode_ecdsa_private_key(context,
                                                       oct_s, oct_s_len,
                                                       alg_param);
      break;
#endif /* SSHDIST_CRYPT_ECP */
    default:
      rv = SSH_X509_FAILED_UNKNOWN_VALUE;
      goto failed;
    }
  if (private_key)
    {
      rv = SSH_X509_OK;
      *key = private_key;
    }
  else
    rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;

 failed:
  ssh_free(oct_s);
  ssh_asn1_free(context);
  return rv;
}

/* Encrypted private keys per PKCS8 version 1.2 section 7. */

SshX509Status
ssh_pkcs8_encrypt_private_key(const unsigned char *ciphername,
                              const char *hashname,
                              const unsigned char *password,
                              size_t password_len,
                              const SshPrivateKey key,
                              unsigned char **buf, size_t *len)
{
  unsigned char salt[8], *src, *dst;
  size_t i, src_len, dst_len, iters = 1024;
  SshAsn1Context context;
  SshAsn1Node pbeparam, node;
  unsigned char probe[64];
  const SshOidStruct *oid;
  SshX509Status rv;

  /* Encode keymaterial. */
  if ((rv = ssh_pkcs8_encode_private_key(key, &src, &src_len))
      != SSH_X509_OK)
    return rv;

  /* Create salt. */
  for (i = 0; i < sizeof(salt); i++) salt[i] = ssh_random_get_byte();

  /* Probe for this oid being supported at pkcs5 or pkcs12. */
  ssh_snprintf(probe, sizeof(probe), "pbewith%sand%s", hashname, ciphername);
  if ((oid = ssh_oid_find_by_std_name(ssh_sstr(probe))) != NULL)
    {
      dst = ssh_pkcs5_pbes1_encrypt(ciphername, hashname,
                                    password, password_len, salt, iters,
                                    src, src_len,
                                    &dst_len);
    }
  else if ((oid = ssh_oid_find_by_oid_of_type(ciphername, SSH_OID_PKCS12))
           != NULL)
    {
      const SshOidPkcs5Struct *extra = oid->extra;

      if (hashname && strcmp(hashname, extra->hash))
        return SSH_X509_FAILED_UNKNOWN_VALUE;

      dst = ssh_pkcs12_pbe_encrypt(extra->cipher,
                                   extra->keylen, extra->hash, iters,
                                   password, password_len,
                                   salt, sizeof(salt), src, src_len,
                                   &dst_len);
    }
  else
    {
      ssh_free(src);
      return SSH_X509_FAILED_UNKNOWN_VALUE;
    }

  ssh_free(src);

  /* If OK, then encode the PKCS8 encrypted private key payload. */
  if (dst)
    {
      if ((context = ssh_asn1_init()) == NULL)
        {
          ssh_free(dst);
          return SSH_X509_FAILURE;
        }
      /* PKCS#5 PBEParameter */
      if (ssh_asn1_create_node(context, &pbeparam,
                               "(sequence ()"
                               "  (octet-string ())"
                               "  (integer-short ()))",
                               salt, sizeof(salt),
                               iters)
          == SSH_ASN1_STATUS_OK)
        {
          if (ssh_asn1_create_node(context, &node,
                                   "(sequence ()"
                                   "  (sequence ()"
                                   "    (object-identifier ())"
                                   "    (any ()))"
                                   "  (octet-string ()))",
                                   oid->oid, pbeparam, dst, dst_len)
              == SSH_ASN1_STATUS_OK)
            {
              ssh_asn1_encode_node(context, node);
              ssh_asn1_node_get_data(node, buf, len);
              ssh_asn1_free(context);
              ssh_free(dst);
              return SSH_X509_OK;
            }
        }
      ssh_asn1_free(context);
      ssh_free(dst);
      return SSH_X509_FAILED_ASN1_ENCODE;
    }
  return SSH_X509_FAILED_UNKNOWN_VALUE;
}

/* Decrypt the private key `key'from PKCS8 encoded encrypted private
   key from `buf' whose length is `len' bytes. The cipher key is
   derived from `password' with PKCS5 kdf1 function. The calling
   application has to know proper password to use with the block from
   out-of-band information. */
SshX509Status
ssh_pkcs8_decrypt_private_key(const unsigned char *password,
                              size_t password_len,
                              const unsigned char *buf, size_t len,
                              SshPrivateKey *key)
{
  const SshOidStruct *oid;
  const SshOidPkcs5Struct *extra;
  SshX509Status rv = SSH_X509_FAILED_UNKNOWN_STYLE;
  unsigned char *src = NULL, *dst = NULL, *salt;
  size_t src_len, dst_len, salt_len;
  size_t iterations;
  SshAsn1Context context;
  SshAsn1Node node, pbeparam;
  unsigned char *pbeoid = NULL;
  Boolean pkcs12;

  if ((context = ssh_asn1_init()) == NULL)
    return SSH_X509_FAILURE;

  if (ssh_asn1_decode_node(context, buf, len, &node) != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(context);
      return SSH_X509_FAILED_ASN1_DECODE;
    }

  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (sequence ()"
                         "    (object-identifier ())"
                         "    (any ()))"
                         "  (octet-string ()))",
                         &pbeoid, &pbeparam, &src, &src_len)
      != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to read ASN1 node"));
      rv = SSH_X509_FAILED_UNKNOWN_STYLE;
      pbeoid = NULL;
      goto exit;
    }

  /* now check based on pbeoid which algorithms to use. */
  if ((oid = ssh_oid_find_by_oid_of_type(pbeoid, SSH_OID_PKCS5))
      != NULL)
    pkcs12 = FALSE;
  else if ((oid = ssh_oid_find_by_oid_of_type(pbeoid, SSH_OID_PKCS12))
           != NULL)
    pkcs12 = TRUE;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unknown PBE identifier: '%s'",
                             (char *) pbeoid));
      rv = SSH_X509_FAILED_UNKNOWN_STYLE;
      goto exit;
    }

  extra = oid->extra;

  if (ssh_asn1_read_node(context, pbeparam,
                         "(sequence ()"
                         "  (octet-string ())"
                         "  (integer-short ()))",
                         &salt, &salt_len,
                         &iterations) != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to decode PBE parameters with identifier "
                 " '%s' = '%s'", oid->oid, oid->std_name));
      rv = SSH_X509_FAILED_ASN1_DECODE;
      goto exit;
    }

  if (pkcs12)
    {
      dst = ssh_pkcs12_pbe_decrypt(extra->cipher, extra->keylen,
                                   extra->hash, iterations,
                                   password, password_len,
                                   salt, salt_len,
                                   src, src_len,
                                   &dst_len);

    }
  else
    {
      dst = ssh_pkcs5_pbes1_decrypt(extra->cipher, extra->hash,
                                    password, password_len,
                                    salt, iterations,
                                    src, src_len,
                                    &dst_len);
    }

  if (dst)
    {
      rv = ssh_pkcs8_decode_private_key(dst, dst_len, key);
      ssh_free(dst);
    }
  else
    rv = SSH_X509_FAILURE;

  ssh_free(salt);

  /* We might have failed due to missing password */
  if (rv != SSH_X509_OK && password == NULL)
    rv = SSH_X509_PASSPHRASE_NEEDED;

 exit:
  if (pbeoid != NULL)
    ssh_free(pbeoid);
  ssh_free(src);
  ssh_asn1_free(context);
  return rv;
}
#endif /* SSHDIST_CERT */
