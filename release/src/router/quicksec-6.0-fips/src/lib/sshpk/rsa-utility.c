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
#include "sshencode.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "sshhash_i.h"
#include "rsa.h"

/* Explicit copying routines. */
#define SSH_DEBUG_MODULE "SshCryptoRSA"

SshCryptoStatus
ssh_rsa_private_key_copy(void *op_src, void **op_dest)
{
  SshRSAPrivateKey *prv_dest, *prv_src = op_src;

  if ((prv_dest = ssh_malloc(sizeof(*prv_dest))) != NULL)
    {
      /* Copy bit counts. */
      prv_dest->bits = prv_src->bits;

      *op_dest = (void *)prv_dest;

      ssh_mprz_init_set(&prv_dest->n, &prv_src->n);
      ssh_mprz_init_set(&prv_dest->e, &prv_src->e);
      ssh_mprz_init_set(&prv_dest->d, &prv_src->d);
      ssh_mprz_init_set(&prv_dest->u, &prv_src->u);
      ssh_mprz_init_set(&prv_dest->p, &prv_src->p);
      ssh_mprz_init_set(&prv_dest->q, &prv_src->q);

      ssh_mprz_init(&prv_dest->dp);
      ssh_mprz_init(&prv_dest->dq);
      ssh_mprz_init(&prv_dest->r);

      ssh_mprz_init(&prv_dest->b_exp);
      ssh_mprz_init(&prv_dest->b_inv);

      /* We generate a new random prime r and from this dp, dq */
      ssh_rsa_private_key_generate_crt_exponents(&prv_dest->dp, &prv_dest->dq,
                                                 &prv_dest->r, &prv_dest->p,
                                                 &prv_dest->q, &prv_dest->d);

      /* We need to generate new blinding integers and not just copy them
         from the old key */
      ssh_rsa_private_key_init_blinding(&prv_dest->b_exp, &prv_dest->b_inv,
                                        &prv_dest->n, &prv_dest->e);
      return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus ssh_rsa_public_key_copy(void *op_src, void **op_dest)
{
  SshRSAPublicKey *pub_dest, *pub_src = op_src;

  if ((pub_dest = ssh_malloc(sizeof(*pub_dest))) != NULL)
    {
      ssh_mprz_init_set(&pub_dest->n, &pub_src->n);
      ssh_mprz_init_set(&pub_dest->e, &pub_src->e);
      pub_dest->bits = pub_src->bits;

      *op_dest = (void *)pub_dest;
      return SSH_CRYPTO_OK;
    }
  return SSH_CRYPTO_NO_MEMORY;
}

/* Initialization functions. */

SshCryptoStatus ssh_rsa_private_key_init_action(void **context)
{
  SshRSAInitCtx *ctx;

  if ((ctx = ssh_malloc(sizeof(*ctx))) != NULL)
    {
      ssh_mprz_init_set_ui(&ctx->n, 0);
      ssh_mprz_init_set_ui(&ctx->p, 0);
      ssh_mprz_init_set_ui(&ctx->q, 0);
      ssh_mprz_init_set_ui(&ctx->e, 0);
      ssh_mprz_init_set_ui(&ctx->d, 0);
      ssh_mprz_init_set_ui(&ctx->u, 0);

      ctx->bits = 0;
      *context = (void *)ctx;
      return SSH_CRYPTO_OK;
    }
  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus ssh_rsa_public_key_init_action(void **context)
{
  return ssh_rsa_private_key_init_action(context);
}


void ssh_rsa_private_key_init_ctx_free(void *context)
{
  SshRSAInitCtx *ctx = context;

  ssh_mprz_clear(&ctx->n);
  ssh_mprz_clear(&ctx->p);
  ssh_mprz_clear(&ctx->q);
  ssh_mprz_clear(&ctx->e);
  ssh_mprz_clear(&ctx->d);
  ssh_mprz_clear(&ctx->u);

  ssh_free(ctx);
}

/* Special actions. */

const char *
ssh_rsa_action_put(void *context, va_list ap,
                   void *input_context,
                   SshCryptoType type,
                   SshPkFormat format)
{
  SshRSAInitCtx *ctx = context;
  SshMPInteger temp;
  char *r;

  r = "p";
  switch (format)
    {
    case SSH_PKF_SIZE:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
        return NULL;
      ctx->bits = va_arg(ap, unsigned int);
      r = "i";
      break;
    case SSH_PKF_PRIME_P:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
        return NULL;
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(&ctx->p, temp);
      break;
    case SSH_PKF_PRIME_Q:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
        return NULL;
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(&ctx->q, temp);
      break;
    case SSH_PKF_MODULO_N:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(&ctx->n, temp);
      break;
    case SSH_PKF_SECRET_D:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
        return NULL;
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(&ctx->d, temp);
      break;
    case SSH_PKF_INVERSE_U:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
        return NULL;
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(&ctx->u, temp);
      break;
    case SSH_PKF_PUBLIC_E:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(&ctx->e, temp);
      break;
    default:
      return NULL;
    }
  return r;
}

const char *
ssh_rsa_action_private_key_put(void *context, va_list ap,
                               void *input_context,
                               SshPkFormat format)
{
  return ssh_rsa_action_put(context, ap,
                            input_context,
                            SSH_CRYPTO_TYPE_PRIVATE_KEY,
                            format);
}

const char *
ssh_rsa_action_private_key_get(void *context, va_list ap,
                               void **output_context,
                               SshPkFormat format)
{
  SshRSAPrivateKey *prv = context;
  unsigned int *size;
  SshMPInteger temp;
  char *r;

  r = "p";
  switch (format)
    {
    case SSH_PKF_SIZE:
      size = va_arg(ap, unsigned int *);
      *size = ssh_mprz_bit_size(&prv->n);
      break;
    case SSH_PKF_PRIME_P:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &prv->p);
      break;
    case SSH_PKF_PRIME_Q:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &prv->q);
      break;
    case SSH_PKF_MODULO_N:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &prv->n);
      break;
    case SSH_PKF_SECRET_D:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &prv->d);
      break;
    case SSH_PKF_INVERSE_U:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &prv->u);
      break;
    case SSH_PKF_PUBLIC_E:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &prv->e);
      break;
    default:
      return NULL;
    }
  return r;
}

const char *
ssh_rsa_action_public_key_put(void *context, va_list ap,
                              void *input_context,
                              SshPkFormat format)
{
  return ssh_rsa_action_put(context, ap,
                            input_context,
                            SSH_CRYPTO_TYPE_PUBLIC_KEY,
                            format);
}

const char *
ssh_rsa_action_public_key_get(void *context, va_list ap,
                              void **output_context,
                              SshPkFormat format)
{
  SshRSAPublicKey *pub = context;
  unsigned int *size;
  SshMPInteger temp;
  char *r;

  r = "p";
  switch (format)
    {
    case SSH_PKF_SIZE:
      size = va_arg(ap, unsigned int *);
      *size = ssh_mprz_bit_size(&pub->n);
      break;
    case SSH_PKF_MODULO_N:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &pub->n);
      break;
    case SSH_PKF_PUBLIC_E:
      temp = va_arg(ap, SshMPInteger );
      ssh_mprz_set(temp, &pub->e);
      break;
    default:
      return NULL;
    }
  return r;
}


/* Frees any memory associated with the private key. */

void ssh_rsa_private_key_free(void *private_key)
{
  SshRSAPrivateKey *prv = private_key;

  ssh_mprz_clear(&prv->n);
  ssh_mprz_clear(&prv->e);
  ssh_mprz_clear(&prv->d);
  ssh_mprz_clear(&prv->u);
  ssh_mprz_clear(&prv->p);
  ssh_mprz_clear(&prv->q);

  ssh_mprz_clear(&prv->dp);
  ssh_mprz_clear(&prv->dq);
  ssh_mprz_clear(&prv->r);

  ssh_mprz_clear(&prv->b_exp);
  ssh_mprz_clear(&prv->b_inv);

  ssh_free(prv);
}

void ssh_rsa_public_key_free(void *public_key)
{
  SshRSAPublicKey *pub = public_key;

  ssh_mprz_clear(&pub->e);
  ssh_mprz_clear(&pub->n);

  ssh_free(pub);
}

/* Importing and exporting private keys. */
SshCryptoStatus
ssh_rsa_private_key_export(const void *private_key,
                           unsigned char **buf,
                           size_t *length_return)
{
  const SshRSAPrivateKey *prv = private_key;

  /* Linearize. */
  *length_return =
    ssh_encode_array_alloc(buf,
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &prv->e),
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &prv->d),
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &prv->n),
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &prv->u),
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &prv->p),
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &prv->q),
                           SSH_FORMAT_END);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rsa_private_key_import(const unsigned char *buf,
                           size_t len,
                           void **private_key)
{
  SshMPIntegerStruct n, e, d, u, p, q;
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;

  /* Initialize. */
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);
  ssh_mprz_init(&d);
  ssh_mprz_init(&u);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);

  /* Unlinearize. */
  if (ssh_decode_array(buf, len,
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &e),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &d),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &n),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &u),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &p),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &q),
                       SSH_FORMAT_END) != 0)
    {
      status = ssh_rsa_make_private_key_of_all(&p, &q, &n, &e, &d, &u,
                                               private_key);
    }

  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);

  return status;
}

SshCryptoStatus
ssh_rsa_public_key_import(const unsigned char *buf,
                          size_t len,
                          void **public_key)
{
  SshRSAPublicKey *pub = ssh_malloc(sizeof(*pub));

  if (pub)
    {
      ssh_mprz_init(&pub->n);
      ssh_mprz_init(&pub->e);

      if (ssh_decode_array(buf, len,
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &pub->e),
                       SSH_DECODE_SPECIAL_NOALLOC(ssh_mprz_decode_rendered,
                                                  &pub->n),
                       SSH_FORMAT_END) == 0)
        {
          ssh_mprz_clear(&pub->n);
          ssh_mprz_clear(&pub->e);
          ssh_free(pub);
          return SSH_CRYPTO_OPERATION_FAILED;
        }

      pub->bits = ssh_mprz_bit_size(&pub->n);

      *public_key = pub;

      return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_NO_MEMORY;
}

SshCryptoStatus
ssh_rsa_public_key_export(const void *public_key,
                          unsigned char **buf,
                          size_t *length_return)
{
  const SshRSAPublicKey *pub = public_key;

  *length_return =
    ssh_encode_array_alloc(buf,
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &pub->e),
                           SSH_ENCODE_SPECIAL(ssh_mprz_encode_rendered,
                                              &pub->n),
                           SSH_FORMAT_END);

 return SSH_CRYPTO_OK;
}
