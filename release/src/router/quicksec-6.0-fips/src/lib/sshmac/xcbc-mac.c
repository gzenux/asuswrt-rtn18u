/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   The XCBC-MAC, a cipher based Mac similar to CBC-MAC, but this one is
   secure.

   This implementation follows that of RFC 3566 with
   the modifications described in draft-hoffman-rfc3664bis-03.txt to allow for
   input keys of size different to the cipher block size.

   This draft only concerns the usage of XCBC Mac for the AES cipher.
   Some alterations will be required (concerning the key scheduling) if
   XCBC Mac is to be used with arbitrary ciphers. Until such an RFC
   appears or equivalent appears, XCBC Mac should only be used with the
   AES cipher.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "sshmac_i.h"
#include "xcbc-mac.h"

#define SSH_DEBUG_MODULE "SshCryptXCbcMac"

/* Generic CBC-MAC interface code. */
typedef struct
{
  const SshCipherMacBaseDefStruct *cipher_basedef;

  /* key material. */
  unsigned char *key2, *key3;

  /* holds the intermediate mac value, and any necessary buffering when the
   input data is not a multiple of the cipher block length. */
  unsigned char *workarea;

  /* indicates position in the workarea buffer. */
  unsigned int counter;

  /* Error status */
  SshCryptoStatus status;

  /* cipher context. */
  void *context;
} SshXCBCmacCtx;


size_t ssh_xcbcmac_ctxsize(const SshCipherMacBaseDefStruct *cipher_def)
{
  return
    sizeof(SshXCBCmacCtx) +
    2 * cipher_def->block_length + /* one block each for key2 and key3 */
    2 * cipher_def->block_length + /* two blocks for the workarea */
    (*cipher_def->ctxsize)(); /* for the cipher context */
}

SshCryptoStatus
ssh_xcbcmac_init(void *context, const unsigned char *key, size_t keylen,
                 const SshCipherMacBaseDefStruct *cipher_def)
{
  SshXCBCmacCtx *created = context;
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  unsigned char padded_key[SSH_CIPHER_MAX_BLOCK_SIZE];
  unsigned char key1[SSH_CIPHER_MAX_BLOCK_SIZE];
  SshCryptoStatus status;

  if (keylen < cipher_def->block_length)
    {
      memset(padded_key, 0, cipher_def->block_length);
      memcpy(padded_key, key, keylen);
      key = padded_key;
      keylen = cipher_def->block_length;
    }
  else if (keylen > cipher_def->block_length)
    {
      memset(padded_key, 0, cipher_def->block_length);
      status = ssh_xcbcmac_init(context, padded_key, cipher_def->block_length,
                                cipher_def);
      if (status != SSH_CRYPTO_OK)
        return status;

      status = ssh_xcbcmac_start(context);
      if (status != SSH_CRYPTO_OK)
        return status;

      ssh_xcbcmac_update(context, key, keylen);
      status = ssh_xcbcmac_final(context, padded_key);
      if (status != SSH_CRYPTO_OK)
        return status;

      key = padded_key;
      keylen = cipher_def->block_length;
    }

  /* Align the pointers in the allocated memory. */
  created->workarea = (unsigned char *)created + sizeof(SshXCBCmacCtx);

  created->key2 = (unsigned char *)created->workarea +
    2 * cipher_def->block_length;
  created->key3 = (unsigned char *)created->workarea +
    3 * cipher_def->block_length;

  created->context = (unsigned char *)created->workarea +
    4 * cipher_def->block_length;

  /* Set the cipher def. */
  created->cipher_basedef = cipher_def;
  created->status = SSH_CRYPTO_OK;

  /* Clear workarea and the iv. */
  memset(created->workarea, 0, 2 * cipher_def->block_length);
  memset(iv, 0, cipher_def->block_length);

  memset(key1, 0x01, cipher_def->block_length);
  memset(created->key2, 0x02, cipher_def->block_length);
  memset(created->key3, 0x03, cipher_def->block_length);

  /* Initialize counter */
  created->counter = 0;

  status = (*created->cipher_basedef->init)(created->context,
                                            key, keylen, TRUE);

  if (status != SSH_CRYPTO_OK)
    return status;

  /* Now compute the keys 'key1', 'key2' and 'key3' by encrypting with
     the base key. We can use the CBC mac to encrypt, as it is equivalent
     to standard encryption for a single block (providing the iv is zero). */
  status = (*created->cipher_basedef->cbcmac)(created->context, key1,
                                              cipher_def->block_length, iv);

  if (status != SSH_CRYPTO_OK)
    return status;

  /* Set key1 to the '0x0101010..'  block encrypted under key. */
  memcpy(key1, iv, cipher_def->block_length);

  /* Clean the iv */
  memset(iv, 0, cipher_def->block_length);
  status = (*created->cipher_basedef->cbcmac)(created->context, created->key2,
                                              cipher_def->block_length, iv);

  if (status != SSH_CRYPTO_OK)
    return status;

  /* Set key2 to the '0x0202020..'  block encrypted under key. */
  memcpy(created->key2, iv, cipher_def->block_length);

  /* Clean the iv */
  memset(iv, 0, cipher_def->block_length);
  status = (*created->cipher_basedef->cbcmac)(created->context, created->key3,
                                              cipher_def->block_length, iv);

  if (status != SSH_CRYPTO_OK)
    return status;

  /* Set key3 to the '0x0303030..'  block encrypted under key. */
  memcpy(created->key3, iv, cipher_def->block_length);

  /* Clean the iv and cipher context */
  if (created->cipher_basedef->uninit)
    (*created->cipher_basedef->uninit)(created->context);

  memset(iv, 0, cipher_def->block_length);
  memset(created->context, 0, (*cipher_def->ctxsize)());

  /* Rekey the cipher using the key 'key1' */
  status = (*created->cipher_basedef->init)(created->context,
                                            key1, keylen, TRUE);

  if (status != SSH_CRYPTO_OK)
    return status;

  SSH_DEBUG(SSH_D_MY, ("XCBC Mac initialized OK"));
  return SSH_CRYPTO_OK;
}


SshCryptoStatus ssh_xcbcmac_start(void *context)
{
  SshXCBCmacCtx *ctx = context;

  /* Initialize counter */
  ctx->counter = 0;

  /* Clear workarea and the iv. */
  memset(ctx->workarea, 0, 2 * ctx->cipher_basedef->block_length);

  return SSH_CRYPTO_OK;
}

/* This is much the same as the cbc-mac update. */
void ssh_xcbcmac_update(void *context, const unsigned char *buf,
                        size_t len)
{
  SshXCBCmacCtx *ctx = context;
  unsigned int i, j;
  unsigned char *iv, *block;
  SshCryptoStatus status;
  const int block_length = ctx->cipher_basedef->block_length;

  SSH_ASSERT(block_length != 0);

  iv = ctx->workarea;
  block = iv + block_length;

  SSH_DEBUG(SSH_D_MY, ("In XCBC update"));

  /* Number of bytes processed initially with the 'block' buffer. */
  i = 0;

  if (ctx->counter < block_length)
    {
      for (j = ctx->counter; j < block_length && i < len; i++, j++)
        block[j] = buf[i];

      ctx->counter = j;

      /* Not enough input bytes to form a full block, just return and
         wait for more input. */
      if (ctx->counter != block_length)
        return;

      /* If no more input bytes, return. */
      if (len - i == 0)
        return;
    }
  else
    {
      /* If no more input bytes, return. */
      if (!len)
        return;
    }

   /* mac the single block 'block' */
  status = (*ctx->cipher_basedef->cbcmac)(ctx->context,
                                          block,
                                          block_length,
                                          iv);

  if (status != SSH_CRYPTO_OK)
    ctx->status = status;

  /* Clean block */
  memset(block, 0, block_length);

  /* Reset the counter */
  j = (len - i) % block_length;

   if (j == 0)
     j = block_length;

   ctx->counter = j;

   if (len - i - j)
     {
       status = (*ctx->cipher_basedef->cbcmac)(ctx->context, buf + i,
                                               len - i - j, iv);

       if (status != SSH_CRYPTO_OK)
         ctx->status = status;
     }

  memcpy(block, buf + (len - j), j);
}

SshCryptoStatus
ssh_xcbcmac_final(void *context, unsigned char *digest)
{
  SshXCBCmacCtx *ctx = context;
  SshCryptoStatus status;
  unsigned char *block, *iv;
  unsigned int i;

  SSH_DEBUG(SSH_D_MY, ("In XCBC final"));

  if (ctx->status != SSH_CRYPTO_OK)
    return ctx->status;

  iv = ctx->workarea;
  block = iv + ctx->cipher_basedef->block_length;

  if (ctx->counter < ctx->cipher_basedef->block_length)
    {
      /* the last block is not full or we are mac'ing the empty string,
         so need to pad with "10000..." */
      block[ctx->counter] = 0x80;
      for (i = ctx->counter + 1; i < ctx->cipher_basedef->block_length; i++)
        block[i] = 0;

      /* xor with key3 */
      for (i = 0; i < ctx->cipher_basedef->block_length; i++)
        block[i] ^= ctx->key3[i];
    }
  else
    {
      /* the last block is full, no padding required  */
      for (i = 0; i < ctx->cipher_basedef->block_length; i++)
        block[i] ^= ctx->key2[i];  /* xor with key2 */
    }

  status = (*ctx->cipher_basedef->cbcmac)(ctx->context,
                                          block,
                                          ctx->cipher_basedef->block_length,
                                          iv);

  memcpy(digest, iv, ctx->cipher_basedef->block_length);
  return status;
}

/* Final 96 bits of the digest, this only makes sense if the digest
   is larger than 96 bits (i.e. not for DES or 3DES) */
SshCryptoStatus
ssh_xcbcmac_96_final(void *context, unsigned char *digest)
{
  SshXCBCmacCtx *ctx = context;
  unsigned char buffer[SSH_CIPHER_MAX_BLOCK_SIZE];
  SshCryptoStatus status;

  SSH_DEBUG(SSH_D_MY, ("In XCBC 96 final"));

  status = ssh_xcbcmac_final(ctx, buffer);
  memcpy(digest, buffer, 12);

  memset(buffer, 0, SSH_CIPHER_MAX_BLOCK_SIZE);
  return status;
}

void
ssh_xcbcmac_uninit(void *context)
{
  SshXCBCmacCtx *ctx = context;

  if (ctx->cipher_basedef->uninit)
    (*ctx->cipher_basedef->uninit)(ctx->context);
}
