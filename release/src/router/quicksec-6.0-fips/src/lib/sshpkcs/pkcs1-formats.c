/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of RSA PKCS 1 public key and private key encodings.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshmp.h"
#include "sshasn1.h"
#include "sshpkcs1.h"

#ifdef SSHDIST_CERT

/* Routines for encoding and decoding private keys.*/
Boolean
ssh_pkcs1_encode_private_key(SshPrivateKey private_key,
                             unsigned char **buf, size_t *buf_len)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  const char *name;
  Boolean rv = FALSE; /* Assume failure. */
  SshAsn1Status status;
  SshMPIntegerStruct n, p, q, e, d, u, p_1, q_1, dp, dq, version;

  /* Try to decode the name of the private key. */
  if (ssh_private_key_get_info(private_key,
                               SSH_PKF_KEY_TYPE, &name,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;


  if (strcmp(name, "if-modn") != 0)
    return FALSE;

  if ((context = ssh_asn1_init()) == NULL)
    return FALSE;

  /* Initialize few variables. */
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);
  ssh_mprz_init(&d);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&u);
  ssh_mprz_init(&p_1);
  ssh_mprz_init(&q_1);
  ssh_mprz_init(&dp);
  ssh_mprz_init(&dq);
  ssh_mprz_init(&version);

  /* Get the necessary information of the SSH style RSA key. */
  if (ssh_private_key_get_info(private_key,
                               SSH_PKF_MODULO_N,  &n,
                               SSH_PKF_PUBLIC_E,  &e,
                               SSH_PKF_SECRET_D,  &d,
                               SSH_PKF_PRIME_P,   &p,
                               SSH_PKF_PRIME_Q,   &q,
                               SSH_PKF_INVERSE_U, &u,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_mprz_clear(&n);
      ssh_mprz_clear(&e);
      ssh_mprz_clear(&d);
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&u);
      goto failed;
    }

  /* Convert and compute all necessary extra information for RSA PKCS
     1 format.

     Note: SSH RSA p and q are given in reverse order than in the PKCS
     1.
  */
  ssh_mprz_set(&p_1, &p);
  ssh_mprz_sub_ui(&p_1, &p_1, 1);
  ssh_mprz_set(&q_1, &q);
  ssh_mprz_sub_ui(&q_1, &q_1, 1);
  ssh_mprz_mod(&dp, &d, &p_1);
  ssh_mprz_mod(&dq, &d, &q_1);

  ssh_mprz_set_ui(&version, 0);

  /* Add to the encoding. */

  status =
    ssh_asn1_create_tree(context, &tree,
                         "(sequence ()"
                         "(integer ())"  /* version */
                         "(integer ())"  /* n */
                         "(integer ())"  /* e */
                         "(integer ())"  /* d */
                         "(integer ())"  /* p */
                         "(integer ())"  /* q */
                         "(integer ())"  /* d mod (p-1) */
                         "(integer ())"  /* d mod (q-1) */
                         "(integer ()))", /* q^-1 mod p */
                         &version,
                         &n, &e, &d, &q, &p,
                         &dq, &dp, &u);

  ssh_mprz_clear(&version);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&p_1);
  ssh_mprz_clear(&q_1);
  ssh_mprz_clear(&dp);
  ssh_mprz_clear(&dq);

  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  /* Encode the generated tree. */
  status = ssh_asn1_encode(context, tree);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  ssh_asn1_get_data(tree, buf, buf_len);

  rv = TRUE;
failed:
  ssh_asn1_free(context);
  return rv;
}

SshPrivateKey
ssh_pkcs1_decode_private_key(const unsigned char *buf, size_t buf_len)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshPrivateKey private_key;
  SshAsn1Status status;
  SshCryptoStatus crypt_status;
  SshMPIntegerStruct n, p, q, e, d, u, dp, dq, version;

  /* Initialize. */
  private_key = NULL;

  /* Initialize ASN.1 context. */
  if ((context = ssh_asn1_init()) == NULL)
    return NULL;

  /* Decode the input. */
  status =
    ssh_asn1_decode(context, buf, buf_len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    goto failed;

  /* Initialize the RSA variables. */
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);
  ssh_mprz_init(&d);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&u);
  ssh_mprz_init(&dp);
  ssh_mprz_init(&dq);
  ssh_mprz_init(&version);

  /* Read from the opened structure. */
  status =
    ssh_asn1_read_tree(context, tree,
                       "(sequence ()"
                       "  (integer ())"  /* version */
                       "  (integer ())"  /* n */
                       "  (integer ())"  /* e */
                       "  (integer ())"  /* d */
                       "  (integer ())"  /* p */
                       "  (integer ())"  /* q */
                       "  (integer ())"  /* d mod (p-1) */
                       "  (integer ())"  /* d mod (q-1) */
                       "  (integer ()))", /* u */
                       &version,
                       &n, &e, &d, &q, &p,
                       &dq, &dp, &u);

  if (status != SSH_ASN1_STATUS_OK || ssh_mprz_cmp_ui(&version, 0) != 0)
    {
      ssh_mprz_clear(&n);
      ssh_mprz_clear(&e);
      ssh_mprz_clear(&d);
      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&u);
      ssh_mprz_clear(&dp);
      ssh_mprz_clear(&dq);
      ssh_mprz_clear(&version);
      goto failed;
    }

  /* Generate the SSH RSA Private key. */
  crypt_status =
    ssh_private_key_define(&private_key,
                           "if-modn",
                           SSH_PKF_MODULO_N, &n,
                           SSH_PKF_PUBLIC_E, &e,
                           SSH_PKF_SECRET_D, &d,
                           SSH_PKF_PRIME_P,  &p,
                           SSH_PKF_PRIME_Q,  &q,
                           SSH_PKF_INVERSE_U, &u,
                           SSH_PKF_END);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&dp);
  ssh_mprz_clear(&dq);
  ssh_mprz_clear(&version);

  if (crypt_status != SSH_CRYPTO_OK)
    goto failed;

failed:
  ssh_asn1_free(context);
  return private_key;
}

/* Routines for encoding and decoding public keys.*/
Boolean ssh_pkcs1_encode_public_key(SshPublicKey public_key,
                                    unsigned char **buf,
                                    size_t *buf_len)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  const char *name;
  Boolean rv = FALSE; /* Assume failure. */
  SshAsn1Status status;
  SshMPIntegerStruct n, e;

  /* Try to decode the name of the private key. */
  if (ssh_public_key_get_info(public_key,
                              SSH_PKF_KEY_TYPE, &name,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;


  if (strcmp(name, "if-modn") != 0)
    return FALSE;

  if ((context = ssh_asn1_init()) == NULL)
    return FALSE;

  /* Initialize few variables. */
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);

  /* Get the necessary information of the SSH style RSA key. */
  if (ssh_public_key_get_info(public_key,
                              SSH_PKF_MODULO_N,  &n,
                              SSH_PKF_PUBLIC_E,  &e,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_mprz_clear(&n);
      ssh_mprz_clear(&e);
      goto failed;
    }

  /* Add to the encoding. */

  status =
    ssh_asn1_create_tree(context, &tree,
                         "(sequence ()"
                         " (integer ())"   /* n */
                         " (integer ()))", /* e */
                         &n, &e);

  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);

  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  /* Encode the generated tree. */
  status = ssh_asn1_encode(context, tree);
  if (status != SSH_ASN1_STATUS_OK)
    goto failed;

  ssh_asn1_get_data(tree, buf, buf_len);

  rv = TRUE;
failed:
  ssh_asn1_free(context);
  return rv;
}

SshPublicKey ssh_pkcs1_decode_public_key(const unsigned char *buf,
                                         size_t buf_len)
{
  SshAsn1Context context;
  SshAsn1Tree tree;
  SshAsn1Status status;
  SshPublicKey public_key;
  SshCryptoStatus crypt_status;
  SshMPIntegerStruct n, e;

  /* Initialize. */
  public_key = NULL;

  /* Initialize ASN.1 context. */
  if ((context = ssh_asn1_init()) == NULL)
    return NULL;

  /* Decode the input. */
  status =
    ssh_asn1_decode(context, buf, buf_len, &tree);
  if (status != SSH_ASN1_STATUS_OK &&
      status != SSH_ASN1_STATUS_OK_GARBAGE_AT_END &&
      status != SSH_ASN1_STATUS_BAD_GARBAGE_AT_END)
    goto failed;

  /* Initialize the RSA variables. */
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);

  /* Read from the opened structure. */
  status =
    ssh_asn1_read_tree(context, tree,
                       "(sequence ()"
                       "  (integer ())"    /* n */
                       "  (integer ()))",  /* e */
                       &n, &e);

  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&n);
      ssh_mprz_clear(&e);
      goto failed;
    }

  /* Generate the SSH RSA Private key. */
  crypt_status =
    ssh_public_key_define(&public_key,
                          "if-modn",
                          SSH_PKF_MODULO_N, &n,
                          SSH_PKF_PUBLIC_E, &e,
                          SSH_PKF_END);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);

  if (crypt_status != SSH_CRYPTO_OK)
    goto failed;

failed:
  ssh_asn1_free(context);
  return public_key;
}

/* pkcs1-formats.c */
#endif /* SSHDIST_CERT */
