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


#ifdef SSHDIST_CRYPT_ECP
SshX509Status
ssh_x509_decode_ecdsa_public_key(SshAsn1Context context,
                                 SshAsn1Node pk_param,
                                 SshX509PublicKey pkey,
                                 const unsigned char* key_name,
                                 unsigned char* key_data,
                                 size_t key_data_len)
{
  SshX509Status rv;
  SshMPIntegerStruct n;
  SshECPCurveStruct E;
  SshECPPointStruct P, Y;
  const char *out_name = NULL;
  size_t enc_len;
  Boolean pc;

  rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
  if (key_data_len == 0)
    return rv;

  if ((rv = ssh_x509_decode_ecp_curve(context, pk_param,
                                      &E, &P,
                                      &n, &out_name,
                                      &enc_len)) != SSH_X509_OK)
    return rv;

  ssh_ecp_init_point(&Y, &E);

  if (!ssh_ecp_set_point_from_octet_str(&Y, &E, enc_len,
                                        key_data, key_data_len, &pc))
    {
      rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
      goto fail;
    }

  /* All parameters obtained define the public key */
  if (ssh_public_key_define(&pkey->public_key,
                            key_name,
                            SSH_PKF_PRIME_P, &E.q,
                            SSH_PKF_GENERATOR_G, &P.x, &P.y,
                            SSH_PKF_PRIME_Q, &n,
                            SSH_PKF_CURVE_A, &E.a,
                            SSH_PKF_CURVE_B, &E.b,
                            SSH_PKF_CARDINALITY, &E.c,
                            SSH_PKF_PUBLIC_Y, &Y.x, &Y.y,
                            SSH_PKF_PREDEFINED_GROUP, out_name,
                            SSH_PKF_POINT_COMPRESS, pc,
                            SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
      goto fail;
    }
  rv = SSH_X509_OK;

fail:
  ssh_ecp_clear_curve(&E);
  ssh_ecp_clear_point(&P);
  ssh_ecp_clear_point(&Y);
  ssh_mprz_clear(&n);
  return rv;
}
#endif /* SSHDIST_CRYPT_ECP */

SshX509Status ssh_x509_decode_asn1_public_key(SshAsn1Context context,
                                              SshAsn1Node pk_info,
                                              SshX509PublicKey pkey)
{
  unsigned char *pk;
  unsigned char *pk_oid;
  SshMPIntegerStruct p, q, g, y;
#ifdef SSHDIST_CRYPT_RSA
  SshMPIntegerStruct n, e;
#endif /* SSHDIST_CRYPT_RSA */
  size_t pk_len;
  SshAsn1Node params, pub_key = NULL;
  SshAsn1Status status;
  const SshOidStruct *oid;
  SshAsn1Tree tree;
  unsigned int which;
  SshX509Status rv;

  /* Decode the input blob. */
  status =
    ssh_asn1_read_node(context, pk_info,
                       "(sequence ()"
                       "  (sequence ()"             /* Algorithm identifier! */
                       "    (object-identifier ())" /* object identifier */
                       "    (any ()))"              /* any by algorithm */
                       "  (bit-string ()))",        /* the public key */
                       &pk_oid,
                       &params,
                       &pk, &pk_len);

  if (status != SSH_ASN1_STATUS_OK)
    return SSH_X509_FAILED_PUBLIC_KEY_OPS;

  /* First figure out information about the name of the algorithm. */
  oid = ssh_oid_find_by_oid_of_type(pk_oid, SSH_OID_PK);
  ssh_free(pk_oid);

  if (oid == NULL)
    {
      ssh_free(pk);
      return SSH_X509_FAILED_UNKNOWN_VALUE;
    }

  /* Set output fields. */
  pkey->pk_type                 = ((SshOidPk)oid->extra)->alg_enum;
  pkey->subject_key_usage_mask  = ((SshOidPk)oid->extra)->key_usage;
  pkey->ca_key_usage_mask       = ((SshOidPk)oid->extra)->ca_key_usage;

 /* The elliptic curve public key is actually an OCTET string mapped to
  a BIT STRING. For other type of crypto systems this is an ASN.1
  encoding.Now lets try to find out what the bit string keeps in itself.
  Then take the first node which should be the public key. */
  if (pkey->pk_type != SSH_X509_PKALG_ECDSA)
    {
      /* pk_len in bits */
      status = ssh_asn1_decode(context, pk, pk_len/8, &tree);
      ssh_free(pk);
      pk = NULL;
      pk_len = 0;
      if (status != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_DECODE;
      pub_key = ssh_asn1_get_current(tree);
    }

  rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;

  /* We have here at the moment very simple oid->index number which can
     be used to refer into some algorithm internally. E.g. what is being
     done here. */
  switch (((SshOidPk)oid->extra)->alg_enum)
    {
#ifdef SSHDIST_CRYPT_RSA
    case SSH_X509_PKALG_RSA:
      ssh_mprz_init(&n);
      ssh_mprz_init(&e);

      SSH_ASSERT(pub_key != NULL);
      /* Get public key. */
      status =
        ssh_asn1_read_node(context, pub_key,
                           "(sequence ()"
                           "  (integer ())"    /* n -- the modulus */
                           "  (integer ()))",  /* e -- the exponent */
                           &n, &e);
      if (status != SSH_ASN1_STATUS_OK)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto rsa_failed;
        }
      /* Define the public key. */
      if (ssh_public_key_define(&pkey->public_key, oid->name,
                                SSH_PKF_MODULO_N, &n,
                                SSH_PKF_PUBLIC_E, &e,
                                SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
          goto rsa_failed;
        }

      rv = SSH_X509_OK;

    rsa_failed:
      ssh_mprz_clear(&e);
      ssh_mprz_clear(&n);
      break;
#endif /* SSHDIST_CRYPT_RSA */

#ifdef SSHDIST_CRYPT_DSA
    case SSH_X509_PKALG_DSA:
      /* Initialize temporary variables for the key. */
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);
      ssh_mprz_init(&y);

      SSH_ASSERT(pub_key != NULL);
      /* With DSA we don't want to skip parameters ;) */
      status =
        ssh_asn1_read_node(context, params,
                           "(choice "
                           "  (null ())"
                           "  (sequence ()"
                           "  (integer ())"   /* p -- the field modulus */
                           "  (integer ())"   /* q -- the order of generator */
                           "  (integer ())))", /* g -- the generator */
                           &which, &p, &q, &g);
      if (status != SSH_ASN1_STATUS_OK || which == 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("DSA params read failed."));
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto dsa_failed;
        }

      /* Parse DSA public key. */
      status =
        ssh_asn1_read_node(context, pub_key,
                           "(integer ())",   /* this is easy, public key y */
                           &y);
      if (status != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("DSA public key read failed."));
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto dsa_failed;
        }

      /* Should be called only if parameters available! */
      if (ssh_public_key_define(&pkey->public_key, oid->name,
                                SSH_PKF_PRIME_P, &p,
                                SSH_PKF_PRIME_Q, &q,
                                SSH_PKF_GENERATOR_G, &g,
                                SSH_PKF_PUBLIC_Y, &y,
                                SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("DSA public key define failed."));
          rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
          goto dsa_failed;
        }

      rv = SSH_X509_OK;

    dsa_failed:
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&g);
      ssh_mprz_clear(&y);
      break;
#endif /* SSHDIST_CRYPT_DSA */

#ifdef SSHDIST_CRYPT_DH
    case SSH_X509_PKALG_DH:
      /* Initialize temporary variables for the key. */
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);

      SSH_ASSERT(pub_key != NULL);

      /* With Diffie-Hellman we don't want to skip parameters ;) */
      status =
        ssh_asn1_read_node(context, params,
                           "(choice "
                           "  (null ())"
                           "  (sequence ()"
                           "  (integer ())"   /* p -- the field modulus */
                           "  (integer ())"   /* q -- the order of generator */
                           "  (integer ())))", /* g -- the generator */
                           &which, &p, &q, &g);
      if (status != SSH_ASN1_STATUS_OK || which == 0)
        {
          rv = SSH_X509_FAILED_ASN1_DECODE;
          goto dh_failed;
        }

      /* Should be called only if parameters available! */
      if (ssh_pk_group_generate(&pkey->public_group, oid->name,
                                SSH_PKF_PRIME_P, &p,
                                SSH_PKF_PRIME_Q, &q,
                                SSH_PKF_GENERATOR_G, &g,
                                SSH_PKF_END) != SSH_CRYPTO_OK)
        {
          rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
          goto dh_failed;
        }

      rv = SSH_X509_OK;

    dh_failed:
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&g);
      break;
#endif /* SSHDIST_CRYPT_DH */

#ifdef SSHDIST_CRYPT_ECP
    case SSH_X509_PKALG_ECDSA:
      rv = ssh_x509_decode_ecdsa_public_key(context, params,
                                            pkey, oid->name,
                                            pk, pk_len);
      ssh_free(pk);
      break;
#endif /* SSHDIST_CRYPT_ECP */
    default:
      break;
    }

  return rv;
}

SshPublicKey
ssh_x509_decode_public_key(const unsigned char *buf,
                           size_t buf_len)
{
  SshAsn1Context context;
  SshAsn1Node node;
  SshAsn1Status asn1_status;
  SshX509Status x509_status;
  SshX509PublicKey x509_key;
  SshPublicKey key = NULL;

  x509_key = ssh_calloc(1, sizeof(*x509_key));
  if (x509_key == NULL)
    return NULL;

  context = ssh_asn1_init();
  if (context == NULL)
    {
      ssh_free(x509_key);
      return NULL;
    }

  ssh_asn1_set_limits(context, buf_len, 0);

  asn1_status = ssh_asn1_decode_node(context, buf, buf_len, &node);

  if (asn1_status != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ASN1 buffer"));
      ssh_free(x509_key);
      ssh_asn1_free(context);
      return NULL;
    }

  x509_status = ssh_x509_decode_asn1_public_key(context,
                                                node,
                                                x509_key);

  if (x509_status != SSH_X509_OK)
    {
      ssh_free(x509_key);
      ssh_asn1_free(context);

      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to decode key from ASN1, status: %u",
                 x509_status));
      return NULL;
    }

  key = x509_key->public_key;

  ssh_free(x509_key);
  ssh_asn1_free(context);

  return key;
}
#endif /* SSHDIST_CERT */
