/**
   @copyright
   Copyright (c) 2013 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Combined encryption and authentication using the Counter with
   CBC-MAC (CCM) mode of operation as described in RFC3610.
*/


#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshmp.h"
#include "mode-ccm.h"
#include "rijndael.h"

#ifdef SSHDIST_CRYPT_MODE_CCM

#define SSH_DEBUG_MODULE "SshCryptCCM"

/* The only allowed block size in RFC3610. */
#define MODE_CCM_BLOCK_BYTES 16

/* Maximum AAD length. Must not be greater than (2^16 - 2^8) that can
   be encoded using two octets. */
#define MODE_CCM_MAX_AAD_BYTES 256

/* Utility types. */

typedef struct {
  unsigned char buf[MODE_CCM_BLOCK_BYTES];
  unsigned len;
} SshCCMBlock;

typedef struct {
  const unsigned char *ptr;
  unsigned rem;
} SshCCMReader;

/* CCM cipher state. */
typedef struct
{
  /* cipher context used IV encryption */
  void *aes_ecb_cipher_ctx;

  unsigned flags;
  size_t crypt_len;
  unsigned char iv[16];
#define MODE_CCM_ENCRYPT 1
#define MODE_CCM_TRANSFORMING 2
#define MODE_CCM_ERROR 4
  /* CCM parameter M = ICV length in bytes. */
  unsigned M;
  /* CCM parameter L = number of bytes in the message length field. */
  unsigned L;
  /* Buffer for storing AAD temporarily. */
  unsigned char aadbuf[MODE_CCM_MAX_AAD_BYTES];
  unsigned aadlen;
  /* ICV workspace. */
  unsigned char icvbuf[MODE_CCM_BLOCK_BYTES];
  /* Authentication workspace. */
  SshCCMBlock U;
  /* Current counter and counter block. */
  size_t Counter;
  SshCCMBlock A;
  /* Current key block. */
  SshCCMBlock S;
} SshCCMCtx;

/* Utility functions. */

static inline void
mode_ccm_start(SshCCMReader *r, const unsigned char *buf, unsigned len)
{
  r->ptr = buf;
  r->rem = len;
}

static inline Boolean
mode_ccm_remaining(const SshCCMReader *r)
{
  return r->rem > 0;
}

static inline void
mode_ccm_forward_bytes(SshCCMReader *r, unsigned bytes)
{
  unsigned u;

  if (r->rem < bytes)
    u = r->rem;
  else
    u = bytes;

  r->ptr += u;
  r->rem -= u;
}

static inline void
mode_ccm_forward_block(SshCCMReader *r)
{
  mode_ccm_forward_bytes(r, MODE_CCM_BLOCK_BYTES);
}

static inline void
mode_ccm_put_byte(SshCCMBlock *b, unsigned offset, unsigned char byte)
{
  b->buf[offset] = byte;
}

static inline void
mode_ccm_put_bytes(
  SshCCMBlock *b, unsigned offset, unsigned char *buf, unsigned len)
{
  memcpy(b->buf + offset, buf, len);
}

static inline void
mode_ccm_put_bigendian(
  SshCCMBlock *b, unsigned offset, size_t value, unsigned bytes)
{
  unsigned bitshift;
  int i;

  for (i = 0; i < bytes; i++)
    {
      bitshift = (bytes - 1 - i) << 3;
      b->buf[offset + i] = (value >> bitshift) & 0xff;
    }
}

static inline void
mode_ccm_xor_byte(SshCCMBlock *b, unsigned offset, unsigned char byte)
{
  b->buf[offset] ^= byte;
}

static inline void
mode_ccm_xor(unsigned char *dst, const unsigned char *src, unsigned len)
{
  const unsigned char *s = src;
  unsigned char *d = dst;
  int i;

  for (i = 0; i < len; i++)
    *d++ ^= *s++;
}

static inline unsigned
mode_ccm_xor_remaining_sub(
  unsigned char *dst, const SshCCMBlock *b, unsigned offset, SshCCMReader *r)
{
  unsigned len;
  int i;

  if (offset + r->rem < sizeof b->buf)
    len = r->rem;
  else
    len = sizeof b->buf - offset;

  for (i = 0; i < len; i++)
    dst[offset + i] = b->buf[offset + i] ^ r->ptr[i];

  return len;
}

static inline unsigned
mode_ccm_xor_remaining_at(SshCCMBlock *b, unsigned offset, SshCCMReader *r)
{
  return mode_ccm_xor_remaining_sub(b->buf, b, offset, r);
}

static inline unsigned
mode_ccm_xor_remaining(SshCCMBlock *b, SshCCMReader *r)
{
  return mode_ccm_xor_remaining_at(b, 0, r);
}

static inline unsigned
mode_ccm_xor_remaining_to(
  unsigned char *dst, const SshCCMBlock *b, SshCCMReader *r)
{
  return mode_ccm_xor_remaining_sub(dst, b, 0, r);
}

static inline void
mode_ccm_xor_incremental(SshCCMBlock *b, SshCCMReader *r)
{
  unsigned len;

  len = mode_ccm_xor_remaining_sub(b->buf + b->len, b, 0, r);

  b->len += len;
  if (b->len >= sizeof b->buf)
    b->len = 0;
}

static inline void
mode_ccm_xor_incremental_bytes(
  SshCCMBlock *b, const unsigned char *buf, unsigned len)
{
  mode_ccm_xor(b->buf + b->len, buf, len);

  b->len += len;
  if (b->len >= sizeof b->buf)
    b->len = 0;
}

static inline Boolean
mode_ccm_complete(SshCCMBlock *b)
{
  return b->len == 0;
}

static inline void
mode_ccm_crypt_to(SshCCMCtx *ctx, SshCCMBlock *dst, const SshCCMBlock *src)
{
  SshCryptoStatus status;

  status = ssh_rijndael_ecb(ctx->aes_ecb_cipher_ctx,
                            dst->buf, src->buf, sizeof dst->buf);
  SSH_ASSERT(status == SSH_CRYPTO_OK);
}

static inline void
mode_ccm_crypt(SshCCMCtx *ctx, SshCCMBlock *b)
{
  mode_ccm_crypt_to(ctx, b, b);
}

size_t
ssh_ccm_aes_ctxsize(void)
{
#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
  /* Need to add 16 for possible padding because when Intel AES instructions
     are used the cipher context needs to be 16-aligned. */
  return sizeof(SshCCMCtx) + ssh_rijndael_ctxsize() + 16;
#else
  return sizeof(SshCCMCtx) + ssh_rijndael_ctxsize();
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */
}

SshCryptoStatus
ssh_ccm_init(
  void *context, const unsigned char *key, size_t keylen,
  Boolean for_encryption, unsigned parameter_m, unsigned parameter_l)
{
  SshCCMCtx *ctx = context;
  SshCryptoStatus status;

  memset(ctx, 0, sizeof *ctx);
  if (for_encryption)
    ctx->flags |= MODE_CCM_ENCRYPT;
  ctx->aes_ecb_cipher_ctx = (unsigned char *)ctx + sizeof(SshCCMCtx);
#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
  {
    /* Make sure the context-data is 16-aligned */
    SshUInt32 offset =
            ((*(long long unsigned int *)&(ctx->aes_ecb_cipher_ctx)) % 16);

    if (offset != 0)
      {
        ctx->aes_ecb_cipher_ctx += (16 -offset);
      }
  }
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */
  ctx->M = parameter_m;
  ctx->L = parameter_l;

  status = ssh_aes_init(ctx->aes_ecb_cipher_ctx, key, keylen, TRUE);
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
        ("Cipher initialization failed status=%u", (unsigned)status));
      return status;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_ccm_aes_init(
  void *context, const unsigned char *key, size_t keylen,
  Boolean for_encryption)
{
 return ssh_ccm_init(context, key, keylen, for_encryption, 16, 4);
}

SshCryptoStatus
ssh_ccm_64_aes_init(
  void *context, const unsigned char *key, size_t keylen,
  Boolean for_encryption)
{
 return ssh_ccm_init(context, key, keylen, for_encryption, 8, 4);
}

SshCryptoStatus
ssh_ccm_96_aes_init(
  void *context, const unsigned char *key, size_t keylen,
  Boolean for_encryption)
{
 return ssh_ccm_init(context, key, keylen, for_encryption, 12, 4);
}

SshCryptoStatus
ssh_ccm_64_2_aes_init(
  void *context, const unsigned char *key, size_t keylen,
  Boolean for_encryption)
{
 return ssh_ccm_init(context, key, keylen, for_encryption, 8, 2);
}

SshCryptoStatus
ssh_ccm_80_2_aes_init(
  void *context, const unsigned char *key, size_t keylen,
  Boolean for_encryption)
{
 return ssh_ccm_init(context, key, keylen, for_encryption, 10, 2);
}

SshCryptoStatus
ssh_ccm_auth_start(void *context, const unsigned char *iv,
                   const unsigned char *aad, size_t aad_len,
                   size_t crypt_len)
{
  SshCCMCtx *ctx = context;

  ctx->flags &= ~MODE_CCM_ERROR;
  ctx->flags &= ~MODE_CCM_TRANSFORMING;
  ctx->aadlen = 0;
  ctx->crypt_len = crypt_len;

  memcpy(ctx->iv, iv, 16);

  if (aad != NULL && aad_len > 0)
    {
      ssh_ccm_update(context, aad, aad_len);
    }
  return SSH_CRYPTO_OK;
}

void
ssh_ccm_update(void *context, const unsigned char *buf, size_t len)
{
  SshCCMCtx *ctx = context;

  /* Data for authentication only (not encrypted) must be processed
     before any data is encrypted. */
  if ((ctx->flags & MODE_CCM_TRANSFORMING))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot accept AAD after message"));
      ctx->flags |= MODE_CCM_ERROR;
      return;
    }

  if (ctx->aadlen + len > sizeof ctx->aadbuf)
    {
      SSH_DEBUG(SSH_D_ERROR, ("AAD too large to process"));
      ctx->flags |= MODE_CCM_ERROR;
      return;
    }

  memcpy(ctx->aadbuf + ctx->aadlen, buf, len);
  ctx->aadlen += len;
}

SshCryptoStatus ssh_ccm_final(void *context, unsigned char *digest)
{
  SshCCMCtx *ctx = context;

  if (!(ctx->flags & MODE_CCM_TRANSFORMING))
    {
      /* This would be the place to do auth-only CCM. */
      SSH_DEBUG(SSH_D_ERROR, ("No transforming done before finalization"));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  memset(&ctx->A, 0, sizeof ctx->A);
  memset(&ctx->S, 0, sizeof ctx->S);

  if (!mode_ccm_complete(&ctx->U))
    mode_ccm_crypt(ctx, &ctx->U);

  /* Calculate final U = T XOR first-M-bytes(S_0) */
  mode_ccm_xor(ctx->icvbuf, ctx->U.buf, ctx->M);
  memset(&ctx->U, 0, sizeof ctx->U);

  memcpy(digest, ctx->icvbuf, ctx->M);
  memset(ctx->icvbuf, 0, sizeof ctx->icvbuf);

  ctx->flags &= ~MODE_CCM_TRANSFORMING;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_ccm_final_verify(void *context, unsigned char *digest)
{
  unsigned char tmp[16];
  SshCryptoStatus stat;
  size_t dlen = ((SshCCMCtx*)context)->M;

  stat = ssh_ccm_final(context, tmp);
  if (stat == SSH_CRYPTO_OK)
    {
      if (memcmp(digest, tmp, dlen) != 0)
        return SSH_CRYPTO_OPERATION_FAILED;
    }
  return stat;
}


SshCryptoStatus ssh_ccm_transform(
  void *context, unsigned char *dest, const unsigned char *src, size_t len)
{
  SshCCMCtx *ctx = context;
  unsigned char *dst = dest;
  SshCCMBlock *U, *A, *S;
  unsigned M, L, Adata;
  unsigned char Flags;
  SshCCMReader r;
  unsigned bytes;

  if ((ctx->flags & MODE_CCM_ERROR))
    return SSH_CRYPTO_OPERATION_FAILED;

  /* CCM parameters. */
  M = ctx->M;
  L = ctx->L;

  /* Working blocks. */
  U = &ctx->U;
  A = &ctx->A;
  S = &ctx->S;

  /* AAD present flag. */
  if (ctx->aadlen > 0)
    Adata = 1;
  else
    Adata = 0;

  /* Do initializations on first call only. */
  if ((ctx->flags & MODE_CCM_TRANSFORMING))
    goto initialized;
  ctx->flags |= MODE_CCM_TRANSFORMING;

  /* Calculate X_1 = E(K, B_0) and store it directly into U. */
  Flags = Adata << 6;
  Flags |= ((M - 2) / 2) << 3;
  Flags |= L - 1;
  mode_ccm_put_byte(U, 0, Flags);
  mode_ccm_put_bytes(U, 1, ctx->iv, 15 - L);
  mode_ccm_put_bigendian(U, 16 - L, ctx->crypt_len, L);
  mode_ccm_crypt(ctx, U);

  /* Authenticate AAD using X_i+1 = E(K, X_i XOR B_i). */
  if (ctx->aadlen)
    {
      mode_ccm_xor_byte(U, 0, (ctx->aadlen >> 8) & 0xff);
      mode_ccm_xor_byte(U, 1, ctx->aadlen & 0xff);

      mode_ccm_start(&r, ctx->aadbuf, ctx->aadlen);
      mode_ccm_xor_remaining_at(U, 2, &r);
      mode_ccm_crypt(ctx, U);
      mode_ccm_forward_bytes(&r, 14);

      while (mode_ccm_remaining(&r))
        {
          mode_ccm_xor_remaining(U, &r);
          mode_ccm_crypt(ctx, U);
          mode_ccm_forward_block(&r);
        }

      ctx->aadlen = 0;
    }

  /* Make A_0. */
  ctx->Counter = 0;
  Flags = L - 1;
  mode_ccm_put_byte(A, 0, Flags);
  mode_ccm_put_bytes(A, 1, ctx->iv, 15 - L);
  mode_ccm_put_bigendian(A, 16 - L, ctx->Counter, L);

  /* Calculate S_0 = E(K, A_0) and copy for later use. */
  mode_ccm_crypt_to(ctx, S, A);
  memcpy(ctx->icvbuf, S->buf, M);

 initialized:

  /* Encrypt or decrypt and authenticate message by XORing S_i = E(K,
     A_i) with the message and doing X_i+1 = E(K, X_i XOR B_i) before
     (encryption) or after (decryption). */

  mode_ccm_start(&r, src, len);
  while (mode_ccm_remaining(&r))
    {
      if (mode_ccm_complete(U))
        {
          ctx->Counter++;
          mode_ccm_put_bigendian(A, 16 - L, ctx->Counter, L);
          mode_ccm_crypt_to(ctx, S, A);
        }

      if ((ctx->flags & MODE_CCM_ENCRYPT))
        {
          mode_ccm_xor_incremental(U, &r);
          if (mode_ccm_complete(U))
            mode_ccm_crypt(ctx, U);
        }

      bytes = mode_ccm_xor_remaining_to(dst, S, &r);

      if (!(ctx->flags & MODE_CCM_ENCRYPT))
        {
          mode_ccm_xor_incremental_bytes(U, dst, bytes);
          if (mode_ccm_complete(U))
            mode_ccm_crypt(ctx, U);
        }

      dst += bytes;
      mode_ccm_forward_bytes(&r, bytes);
    }

  return SSH_CRYPTO_OK;
}

#endif /* SSHDIST_CRYPT_MODE_CCM */
