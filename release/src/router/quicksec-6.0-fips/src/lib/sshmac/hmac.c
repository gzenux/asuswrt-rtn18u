/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Message authentication code calculation routines, using the HMAC
   structure.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "sshmac_i.h"
#include "sshcrypt_i.h"
#include "hmac.h"

#define SSH_DEBUG_MODULE "SshCryptHmac"


/* Generic Hmac interface code. */
typedef struct
{
  unsigned char *ipad, *opad;
  const SshHashDefStruct *hash_def;
  void *hash_context;
} SshHmacCtx;

size_t
ssh_hmac_ctxsize(const SshHashDefStruct *hash_def)
{
  return
    sizeof(SshHmacCtx) +
    (*hash_def->ctxsize)() +
    hash_def->input_block_length * 2;
}

SshCryptoStatus
ssh_hmac_init(void *context, const unsigned char *key, size_t keylen,
              const SshHashDefStruct *hash_def)
{
  SshHmacCtx *created = context;
  SshCryptoStatus status;
  unsigned int i;

  /* Compute positions in allocated space. */
  created->hash_context = (unsigned char *)created +
    sizeof(SshHmacCtx);
  created->ipad = (unsigned char *)created->hash_context +
    (*hash_def->ctxsize)();

  created->opad = created->ipad + hash_def->input_block_length;

  /* Clear pads. */
  memset(created->ipad, 0, hash_def->input_block_length * 2);

  /* Remember the hash function used to define this mac. */
  created->hash_def = hash_def;

  if (hash_def->init &&
      (*hash_def->init)(created->hash_context) != SSH_CRYPTO_OK)
    return SSH_CRYPTO_NO_MEMORY;

  if (keylen > created->hash_def->input_block_length)
    {
      /* Do some hashing. */

      /* Compute the ipad. */
      (*created->hash_def->reset_context)(created->hash_context);
      (*created->hash_def->update)(created->hash_context, key, keylen);
      status = (*created->hash_def->final)(created->hash_context,
                                           created->ipad);

      if (status != SSH_CRYPTO_OK)
        return status;

      memcpy(created->opad, created->ipad,
             created->hash_def->input_block_length);
    }
  else
    {
      memcpy(created->ipad, key, keylen);
      memcpy(created->opad, key, keylen);
    }

  for (i = 0; i < created->hash_def->input_block_length; i++)
    {
      created->ipad[i] ^= 0x36;
      created->opad[i] ^= 0x5c;
    }

  return SSH_CRYPTO_OK;
}

void ssh_hmac_uninit(void *context)
{
  SshHmacCtx *ctx = context;

  if (ctx->hash_def->uninit)
    (*ctx->hash_def->uninit)(ctx->hash_context);
}

/* Restart the Hmac operation. */
SshCryptoStatus ssh_hmac_start(void *context)
{
  SshHmacCtx *ctx = context;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->ipad,
                           ctx->hash_def->input_block_length);

  return SSH_CRYPTO_OK;
}

/* Update the Hmac context. */
void ssh_hmac_update(void *context, const unsigned char *buf,
                     size_t len)
{
  SshHmacCtx *ctx = context;
  (*ctx->hash_def->update)(ctx->hash_context, buf, len);
}

/* Finalize the digest. */
SshCryptoStatus ssh_hmac_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;

  status = (*ctx->hash_def->final)(ctx->hash_context, digest);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, digest,
                           ctx->hash_def->digest_length);
  return (*ctx->hash_def->final)(ctx->hash_context, digest);
}

/* Finalize 128 bits of the digest. */
SshCryptoStatus ssh_hmac_256_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 32);
  return status;
}

/* Finalize 128 bits of the digest. */
SshCryptoStatus ssh_hmac_192_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 24);
  return status;
}

/* Finalize 128 bits of the digest. */
SshCryptoStatus ssh_hmac_128_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 16);
  return status;
}

/* Finalize 96 bits of the digest. */
SshCryptoStatus ssh_hmac_96_final(void *context, unsigned char *digest)
{
  SshHmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char buffer[SSH_MAX_HASH_DIGEST_LENGTH];

  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  if (status != SSH_CRYPTO_OK)
    return status;

  (*ctx->hash_def->reset_context)(ctx->hash_context);
  (*ctx->hash_def->update)(ctx->hash_context, ctx->opad,
                           ctx->hash_def->input_block_length);
  (*ctx->hash_def->update)(ctx->hash_context, buffer,
                           ctx->hash_def->digest_length);
  status = (*ctx->hash_def->final)(ctx->hash_context, buffer);
  memcpy(digest, buffer, 12);
  return status;
}

/* Do everything with just one call. */
SshCryptoStatus ssh_hmac_of_buffer(void *context, const unsigned char *buf,
                                   size_t len, unsigned char *digest)
{
  SshCryptoStatus status;

  status = ssh_hmac_start(context);
  if (status == SSH_CRYPTO_OK)
    {
      ssh_hmac_update(context, buf, len);
      status = ssh_hmac_final(context, digest);
    }
  return status;
}

SshCryptoStatus ssh_hmac_256_of_buffer(void *context, const unsigned char *buf,
                                       size_t len, unsigned char *digest)
{
  SshCryptoStatus status;

  status = ssh_hmac_start(context);
  if (status == SSH_CRYPTO_OK)
    {
      ssh_hmac_update(context, buf, len);
      status = ssh_hmac_256_final(context, digest);
    }
  return status;
}

SshCryptoStatus ssh_hmac_192_of_buffer(void *context, const unsigned char *buf,
                                       size_t len, unsigned char *digest)
{
  SshCryptoStatus status;

  status = ssh_hmac_start(context);
  if (status == SSH_CRYPTO_OK)
    {
      ssh_hmac_update(context, buf, len);
      status = ssh_hmac_192_final(context, digest);
    }
  return status;
}

SshCryptoStatus ssh_hmac_128_of_buffer(void *context, const unsigned char *buf,
                                       size_t len, unsigned char *digest)
{
  SshCryptoStatus status;

  status = ssh_hmac_start(context);
  if (status == SSH_CRYPTO_OK)
    {
      ssh_hmac_update(context, buf, len);
      status = ssh_hmac_128_final(context, digest);
    }
  return status;
}

SshCryptoStatus ssh_hmac_96_of_buffer(void *context, const unsigned char *buf,
                                      size_t len, unsigned char *digest)
{
  SshCryptoStatus status;

  status = ssh_hmac_start(context);
  if (status == SSH_CRYPTO_OK)
    {
      ssh_hmac_update(context, buf, len);
      status = ssh_hmac_96_final(context, digest);
    }
  return status;
}

void ssh_hmac_zeroize(void *context)
{
  SshHmacCtx *ctx = context;

  /* Reset hash and zeroize context */
  (*ctx->hash_def->reset_context)(ctx->hash_context);
  ssh_crypto_zeroize(ctx->hash_context, (*ctx->hash_def->ctxsize)());

  /* Clear pads. */
  memset(ctx->ipad, 0, ctx->hash_def->input_block_length * 2);
}

/* hmac.c */
