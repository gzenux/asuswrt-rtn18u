/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Take on the RSA operations and key definition, modified after
   Tatu Ylonen's original SSH implementation.

   Description of the RSA algorithm can be found e.g. from the
   following sources:

   - Bruce Schneier: Applied Cryptography.  John Wiley & Sons, 1994.
   - Jennifer Seberry and Josed Pieprzyk: Cryptography: An Introduction to
     Computer Security.  Prentice-Hall, 1989.
   - Man Young Rhee: Cryptography and Secure Data Communications.  McGraw-Hill,
     1994.
   - R. Rivest, A. Shamir, and L. M. Adleman: Cryptographic Communications
     System and Method.  US Patent 4,405,829, 1983.
   - Hans Riesel: Prime Numbers and Computer Methods for Factorization.
     Birkhauser, 1994.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "sshhash_i.h"
#include "rsa.h"

#define SSH_DEBUG_MODULE "SshCryptoRSA"

SshCryptoStatus
ssh_rsa_make_private_key_of_all(SshMPInteger p, SshMPInteger q,
                                SshMPInteger n, SshMPInteger e,
                                SshMPInteger d, SshMPInteger u,
                                void **key_ctx)
{
  SshRSAPrivateKey *private_key = ssh_malloc(sizeof(*private_key));


  if (private_key)
    {
      ssh_mprz_init_set(&private_key->e, e);
      ssh_mprz_init_set(&private_key->d, d);
      ssh_mprz_init_set(&private_key->n, n);
      ssh_mprz_init_set(&private_key->u, u);
      ssh_mprz_init_set(&private_key->p, p);
      ssh_mprz_init_set(&private_key->q, q);

      ssh_mprz_init(&private_key->dp);
      ssh_mprz_init(&private_key->dq);
      ssh_mprz_init(&private_key->r);

      ssh_mprz_init(&private_key->b_exp);
      ssh_mprz_init(&private_key->b_inv);

      /* We generate a new random prime r and from this dp, dq */
      ssh_rsa_private_key_generate_crt_exponents(&private_key->dp,
                                                 &private_key->dq,
                                                 &private_key->r,
                                                 &private_key->p,
                                                 &private_key->q,
                                                 &private_key->d);

      /* Initialize blinding integers */
      ssh_rsa_private_key_init_blinding(&private_key->b_exp,
                                        &private_key->b_inv,
                                        &private_key->n,
                                        &private_key->e);

      /* Check failure */
      if (ssh_mprz_isnan(&private_key->p) ||
          ssh_mprz_isnan(&private_key->q) ||
          ssh_mprz_isnan(&private_key->e) ||
          ssh_mprz_isnan(&private_key->d) ||
          ssh_mprz_isnan(&private_key->n) ||
          ssh_mprz_isnan(&private_key->u) ||
          ssh_mprz_isnan(&private_key->dp) ||
          ssh_mprz_isnan(&private_key->dq) ||
          ssh_mprz_isnan(&private_key->r) ||
          ssh_mprz_isnan(&private_key->b_exp) ||
          ssh_mprz_isnan(&private_key->b_inv))
        {
          ssh_mprz_clear(&private_key->p);
          ssh_mprz_clear(&private_key->q);
          ssh_mprz_clear(&private_key->e);
          ssh_mprz_clear(&private_key->d);
          ssh_mprz_clear(&private_key->n);
          ssh_mprz_clear(&private_key->u);
          ssh_mprz_clear(&private_key->dp);
          ssh_mprz_clear(&private_key->dq);
          ssh_mprz_clear(&private_key->r);
          ssh_mprz_clear(&private_key->b_exp);
          ssh_mprz_clear(&private_key->b_inv);

          ssh_free(private_key);
          return SSH_CRYPTO_OPERATION_FAILED;
        }

      private_key->bits = ssh_mprz_bit_size(n);
      *key_ctx = (void *)private_key;

      return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_NO_MEMORY;
}

void ssh_rsa_private_key_init(SshRSAPrivateKey *private_key)
{
  /* Initialize with zeroes. */
  ssh_mprz_init_set_ui(&private_key->e, 0);
  ssh_mprz_init_set_ui(&private_key->d, 0);
  ssh_mprz_init_set_ui(&private_key->n, 0);
  ssh_mprz_init_set_ui(&private_key->u, 0);
  ssh_mprz_init_set_ui(&private_key->p, 0);
  ssh_mprz_init_set_ui(&private_key->q, 0);
  ssh_mprz_init_set_ui(&private_key->dp, 0);
  ssh_mprz_init_set_ui(&private_key->dq, 0);
  ssh_mprz_init_set_ui(&private_key->r, 0);
  ssh_mprz_init_set_ui(&private_key->b_exp, 0);
  ssh_mprz_init_set_ui(&private_key->b_inv, 0);
  private_key->bits = 0;
}


/* Making the key from this bunch of information. */

SshCryptoStatus
ssh_rsa_public_key_make_action(void *context, void **key_ctx)
{
  SshRSAInitCtx *ctx = context;
  SshRSAPublicKey *public_key;

  if (ssh_mprz_cmp_ui(&ctx->e, 0) == 0 ||
      ssh_mprz_cmp_ui(&ctx->n, 0) == 0)
    return SSH_CRYPTO_KEY_INVALID;

  if ((public_key = ssh_malloc(sizeof(*public_key))) != NULL)
    {
      ssh_mprz_init_set(&public_key->e, &ctx->e);
      ssh_mprz_init_set(&public_key->n, &ctx->n);

      /* Compute the size of the public key. */
      public_key->bits = ssh_mprz_bit_size(&public_key->n);

      *key_ctx = (void *)public_key;
      return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_NO_MEMORY;
}


/* Try to handle the given data in a reasonable manner. */
SshCryptoStatus
ssh_rsa_private_key_define_action(void *context, void **key_ctx)
{
  SshRSAInitCtx *ctx = context;

  if (ssh_mprz_cmp_ui(&ctx->d, 0) != 0 &&
      ssh_mprz_cmp_ui(&ctx->p, 0) != 0 &&
      ssh_mprz_cmp_ui(&ctx->q, 0) != 0 &&
      ssh_mprz_cmp_ui(&ctx->e, 0) != 0 &&
      ssh_mprz_cmp_ui(&ctx->n, 0) != 0 &&
      ssh_mprz_cmp_ui(&ctx->u, 0) != 0)
    {
      return
        ssh_rsa_make_private_key_of_all(&ctx->p, &ctx->q,
                                        &ctx->n, &ctx->e,
                                        &ctx->d, &ctx->u, key_ctx);
    }
  return SSH_CRYPTO_KEY_INVALID;
}

SshCryptoStatus ssh_rsa_private_key_derive_public_key(const void *private_key,
                                                      void **public_key)
{
  const SshRSAPrivateKey *prv = private_key;
  SshRSAPublicKey *pub;

  if ((pub = ssh_malloc(sizeof(*pub))) != NULL)
    {
      ssh_mprz_init_set(&pub->n, &prv->n);
      ssh_mprz_init_set(&pub->e, &prv->e);

      /* Size of the public key modulus. */
      pub->bits = prv->bits;
      *public_key = (void *)pub;
      return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_NO_MEMORY;
}

/* Performs a private-key RSA operation (encrypt/decrypt).  The
   computation is done using the Chinese Remainder Theorem, which is
   faster than direct modular exponentiation. */
static SshCryptoStatus ssh_rsa_private(SshMPInteger input,
                                       SshMPInteger output,
                                       SshRSAPrivateKey *prv)
{
  SshMPIntegerStruct p2, q2, k;
  SshMPIntegerStruct blind, pr, qr, verify;

  if (ssh_mprz_cmp(input, &prv->n) >= 0)
    return SSH_CRYPTO_DATA_TOO_LONG;

  /* Initialize temporary variables. */
  ssh_mprz_init(&p2);
  ssh_mprz_init(&q2);
  ssh_mprz_init(&k);
  ssh_mprz_init(&pr);
  ssh_mprz_init(&qr);
  ssh_mprz_init(&blind);
  ssh_mprz_init(&verify);

  /* Blind the input integer */
  ssh_mprz_mul(&blind, input, &prv->b_exp);
  ssh_mprz_mod(&blind, &blind, &prv->n);

  /* Compute p2 = (blind mod pr) ^ dp mod pr. */
  ssh_mprz_mul(&pr, &prv->p, &prv->r);
  ssh_mprz_mod(&p2, &blind, &pr);
  ssh_mprz_powm(&p2, &p2, &prv->dp, &pr);

  /* Compute q2 = (blind mod qr) ^ dq mod qr. */
  ssh_mprz_mul(&qr, &prv->q, &prv->r);
  ssh_mprz_mod(&q2, &blind, &qr);
  ssh_mprz_powm(&q2, &q2, &prv->dq, &qr);

  /* Check to see if an error occured during the CRT computations, i.e.
     verify that p2 = q2 mod r */
  ssh_mprz_sub(&verify, &p2, &q2);
  ssh_mprz_mod(&verify, &verify, &prv->r);

  if (ssh_mprz_cmp_ui(&verify, 0) && ssh_mprz_cmp(&verify, &prv->r))
    {
      ssh_mprz_clear(&verify);
      ssh_mprz_clear(&blind);
      ssh_mprz_clear(&p2);
      ssh_mprz_clear(&q2);
      ssh_mprz_clear(&k);
      ssh_mprz_clear(&pr);
      ssh_mprz_clear(&qr);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Now the verification test has passed, we continue with
     the CRT operation */

  /* Compute k = ((q2 - p2) mod q) * u mod q. */
  ssh_mprz_sub(&k, &q2, &p2);
  ssh_mprz_mul(&k, &k, &prv->u);
  ssh_mprz_mod(&k, &k, &prv->q);

  /* Compute output = p2 + p * k. */
  ssh_mprz_mul(output, &prv->p, &k);
  ssh_mprz_add(output, output, &p2);

  /* Unblind the output integer */
  ssh_mprz_mul(output, output, &prv->b_inv);
  ssh_mprz_mod(output, output, &prv->n);

  /* Update the blinding integers. We do this by squaring (mod n)
     the blinding integers. */
  ssh_mprz_square(&prv->b_exp, &prv->b_exp);
  ssh_mprz_mod(&prv->b_exp, &prv->b_exp, &prv->n);

  ssh_mprz_square(&prv->b_inv, &prv->b_inv);
  ssh_mprz_mod(&prv->b_inv, &prv->b_inv, &prv->n);

  /* Clear temporary variables. */
  ssh_mprz_clear(&verify);
  ssh_mprz_clear(&blind);
  ssh_mprz_clear(&p2);
  ssh_mprz_clear(&q2);
  ssh_mprz_clear(&k);
  ssh_mprz_clear(&pr);
  ssh_mprz_clear(&qr);

  if (ssh_mprz_isnan(output))
    return SSH_CRYPTO_OPERATION_FAILED;
  else
    return SSH_CRYPTO_OK;
}

/* Performs a public-key RSA operation (encrypt/decrypt). */

static SshCryptoStatus ssh_rsa_public(SshMPInteger input, SshMPInteger output,
                                     const SshRSAPublicKey *pub)
{
  if (ssh_mprz_cmp(input, &pub->n) >= 0)
    return SSH_CRYPTO_DATA_TOO_LONG;

  /* Exponentiate. */
  ssh_mprz_powm(output, input, &pub->e, &pub->n);

  if (ssh_mprz_isnan(output))
    return SSH_CRYPTO_OPERATION_FAILED;
  else
    return SSH_CRYPTO_OK;
}

/* This function is specific to PKCS-1v2 and might need revision
   after possible updates. However, there is little we can help
   here. */
unsigned char *
ssh_rsa_pkcs1v2_default_explicit_param(const char *hash,
                                       size_t *param_len)
{
  *param_len = 0;
  return ssh_strdup("");
}


/* The routines using the RGF's. */

SshCryptoStatus
ssh_rsa_public_key_encrypt(const void *public_key,
                           const unsigned char *plaintext,
                           size_t plaintext_len,
                           unsigned char *ciphertext_buffer,
                           size_t ciphertext_buffer_len,
                           size_t *ciphertext_len_return,
                           SshRGF rgf)
{
  const SshRSAPublicKey *pub = public_key;
  SshMPIntegerStruct t1, t2;
  SshCryptoStatus status;
  unsigned char *buf;
  size_t rgf_length_return;

  /* Get size. */
  *ciphertext_len_return = (pub->bits + 7)/8;

  /* Check lengths. */
  if (*ciphertext_len_return < plaintext_len)
    return SSH_CRYPTO_DATA_TOO_LONG;

  if (*ciphertext_len_return > ciphertext_buffer_len)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  /* Now run the RGF. */
  if ((status = ssh_rgf_for_encryption(rgf, pub->bits,
                                       plaintext, plaintext_len,
                                       &buf, &rgf_length_return))
      != SSH_CRYPTO_OK)
    {
      return status;
    }

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  /* Convert to integer. */
  ssh_mprz_set_buf(&t2, buf, rgf_length_return);
  ssh_free(buf);

  /* Public key encrypt. */
  if ((status = ssh_rsa_public(&t2, &t1, pub)) != SSH_CRYPTO_OK)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return status;
    }

  /* Linearize again. */
  ssh_mprz_get_buf(ciphertext_buffer, *ciphertext_len_return, &t1);

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rsa_private_key_decrypt(const void *private_key,
                            const unsigned char *ciphertext,
                            size_t ciphertext_len,
                            unsigned char *plaintext_buffer,
                            size_t plaintext_buffer_len,
                            size_t *plaintext_length_return,
                            SshRGF rgf)
{
  SshRSAPrivateKey *prv =  (SshRSAPrivateKey *) private_key;
  SshMPIntegerStruct t1, t2;
  SshCryptoStatus status;
  size_t prv_size = (prv->bits + 7)/8;
  unsigned char *decrypted_msg, *output_msg;
  size_t output_msg_len;

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  /* Unlinearize. */
  ssh_mprz_set_buf(&t1, ciphertext, ciphertext_len);

  /* Private key operation. */
  if ((status = ssh_rsa_private(&t1, &t2, prv)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed RSA private key operation"));

      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return status;
    }

  /* Linearize. */
  if ((decrypted_msg = ssh_malloc(prv_size)) == NULL)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return SSH_CRYPTO_NO_MEMORY;
    }

  ssh_mprz_get_buf(decrypted_msg, prv_size, &t2);

  if ((status = ssh_rgf_for_decryption(rgf, prv->bits,
                                       decrypted_msg, prv_size,
                                       &output_msg, &output_msg_len))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed RSA rgf operation"));

      ssh_free(decrypted_msg);
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return status;
    }

  ssh_free(decrypted_msg);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  /* Now check the output size. */
  if (output_msg_len > plaintext_buffer_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid output size for RSA operation"));

      ssh_free(output_msg);
      return SSH_CRYPTO_DATA_TOO_SHORT;
    }

  memcpy(plaintext_buffer, output_msg, output_msg_len);
  *plaintext_length_return = output_msg_len;
  ssh_free(output_msg);

  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_rsa_public_key_verify(const void *public_key,
                          const unsigned char *signature,
                          size_t signature_len,
                          SshRGF rgf)
{
  const SshRSAPublicKey *pub = public_key;
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;
  SshMPIntegerStruct t1, t2;
  unsigned char *buf;
  size_t buf_len, len;

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  /* Unlinearize. */
  ssh_mprz_set_buf(&t1, signature, signature_len);
  if (ssh_mprz_isnan(&t1) ||
      ssh_mprz_cmp(&t1, &pub->n) >= 0 ||
      ssh_mprz_cmp_ui(&t1, 0) <= 0)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      goto failed;
    }

  /* Allocate temporary buffer. */
  buf_len = (pub->bits + 7)/8;
  if ((buf = ssh_malloc(buf_len)) == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      goto failed;
    }

  /* Retrieve the original form of the signature. */
  if ((status = ssh_rsa_public(&t1, &t2, pub)) != SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      goto failed;
    }


  /* Unlinearize. */
  len = ssh_mprz_get_buf(buf, buf_len, &t2);

  /* Clear multiple precision integers. */
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
  if (len == 0
      || (status = ssh_rgf_for_verification(rgf, pub->bits,
                                            buf, buf_len))
      != SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      goto failed;
    }

  ssh_free(buf);

  status = SSH_CRYPTO_OK;
failed:

  return status;
}

SshCryptoStatus
ssh_rsa_private_key_sign(const void *private_key,
                         SshRGF rgf,
                         unsigned char *signature_buffer,
                         size_t signature_buffer_len,
                         size_t *signature_length_return)
{
  SshRSAPrivateKey *prv =  (SshRSAPrivateKey *) private_key;
  unsigned char *output_msg;
  SshMPIntegerStruct t1, t2;
  size_t rgf_length_return;
  SshCryptoStatus status;

  if ((prv->bits + 7)/8 > signature_buffer_len)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  /* Build the data to be signed. */
  if ((status = ssh_rgf_for_signature(rgf, prv->bits,
                                      &output_msg, &rgf_length_return))
      != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Compute signature. */

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  /* Unlinearize. */
  ssh_mprz_set_buf(&t1, output_msg, rgf_length_return);
  ssh_free(output_msg);

  /* The return length must be equal to the octet size of the key. */
  *signature_length_return =  (prv->bits + 7)/8;

  /* Private key operation. */
  status = ssh_rsa_private(&t1, &t2, prv);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return status;
    }
  /* Linearize. */

  ssh_mprz_get_buf(signature_buffer, *signature_length_return, &t2);

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  return SSH_CRYPTO_OK;
}

/* Compute sizes needed in each operation. */

size_t ssh_rsa_public_key_max_encrypt_input_len(const void *public_key,
                                                SshRGF rgf)
{
  const SshRSAPublicKey *pub = public_key;
  size_t len = ((pub->bits + 7)/8 - 3 - SSH_RSA_MINIMUM_PADDING);

  if (len > 0 && len < SSH_RSA_MAX_BYTES)
    return len;
  return 0;
}

size_t ssh_rsa_public_key_max_none_encrypt_input_len(const void *public_key,
                                                     SshRGF rgf)
{
  const SshRSAPublicKey *pub = public_key;
  size_t len = ((pub->bits + 7)/8);

  if (len > 0 && len < SSH_RSA_MAX_BYTES)
    return len;
  return 0;
}

size_t ssh_rsa_private_key_max_decrypt_input_len(const void *private_key,
                                                 SshRGF rgf)
{
  const SshRSAPrivateKey *prv = private_key;

  return (prv->bits + 7)/8;
}

size_t ssh_rsa_private_key_max_signature_input_len(const void *private_key,
                                                   SshRGF rgf)
{
  return (size_t)-1;
}

size_t
ssh_rsa_private_key_max_signature_unhash_input_len(const void *private_key,
                                                   SshRGF rgf)
{
  const SshRSAPrivateKey *prv = private_key;
  size_t len = ((prv->bits + 7)/8 - 3 - SSH_RSA_MINIMUM_PADDING);

  if (len > 0 && len < SSH_RSA_MAX_BYTES)
    return len;
  return 0;
}

size_t ssh_rsa_public_key_max_encrypt_output_len(const void *public_key,
                                                 SshRGF rgf)
{
  const SshRSAPublicKey *pub = public_key;

  return (pub->bits + 7)/8;
}

size_t ssh_rsa_private_key_max_decrypt_output_len(const void *private_key,
                                                  SshRGF rgf)
{
  const SshRSAPrivateKey *prv = private_key;

  return (prv->bits + 7)/8;
}

size_t ssh_rsa_private_key_max_signature_output_len(const void *private_key,
                                                    SshRGF rgf)
{
  const SshRSAPrivateKey *prv = private_key;

  return (prv->bits + 7)/8;
}

/* rsa.c */
