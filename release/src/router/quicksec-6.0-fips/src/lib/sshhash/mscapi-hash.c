/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Hash routines for MSCAPI.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "sshcrypt.h"
#ifdef SSHDIST_MSCAPI
#ifdef HAVE_MSCAPI_CRYPTO
#include <wincrypt.h>
#include "sshhash_i.h"
#include "md5.h"
#include "sha.h"
#include "sshgetput.h"

#define SSH_DEBUG_MODULE "SshMscapiHash"

typedef struct {
  HCRYPTPROV prov;
  HCRYPTHASH hash_obj;
  Boolean in_error;
} SshMscapiHashContext;


size_t mscapi_hash_ctxsize()
{
  return sizeof(SshMscapiHashContext);
}

SshCryptoStatus mscapi_hash_init(void *context, ALG_ID algid)
{
  SshMscapiHashContext *ctx = context;

  /* Get handle to a crypto context */
  if (!CryptAcquireContext(&ctx->prov,  NULL,  NULL,  PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptAcquireContext failed: %x", GetLastError()));
      ctx->prov = 0;
      ctx->in_error = TRUE;
      return SSH_CRYPTO_NO_MEMORY;
    }

  return SSH_CRYPTO_OK;
}

void mscapi_hash_uninit(void *context, ALG_ID algid)
{
  SshMscapiHashContext *ctx = context;

  /* Release crypto context */
  CryptReleaseContext(ctx->prov, 0);
}

void mscapi_hash_reset_context(void *context, ALG_ID algid)
{
  SshMscapiHashContext *ctx = context;

  if (ctx->hash_obj)
    {
      CryptDestroyHash(ctx->hash_obj);
      ctx->hash_obj = 0;
    }
  ctx->in_error = FALSE;

  SSH_DEBUG(SSH_D_LOWOK, ("Resetting hash context for algorithm id %d",
                          (int) algid));
  /* Create the hash object */
  if (!CryptCreateHash(ctx->prov, algid, 0, 0, &ctx->hash_obj))
    {
      SSH_DEBUG(SSH_D_FAIL,
                  ("CryptCreateHash failed: %x", GetLastError()));
      ctx->hash_obj = 0;
      ctx->in_error = TRUE;
    }
}

void mscapi_hash_update(void *context, BYTE *buf, DWORD len)
{
  SshMscapiHashContext *ctx = context;

  if (!ctx->in_error && !CryptHashData(ctx->hash_obj, buf, len, 0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("CryptHashData failed: %x", GetLastError()));
      ctx->in_error = TRUE;
    }
}

SshCryptoStatus
mscapi_hash_final(void *c, BYTE *digest, DWORD digest_len)
{
  SshMscapiHashContext *ctx = c;
  DWORD return_len = digest_len;

  if (!ctx->in_error &&
      !CryptGetHashParam(ctx->hash_obj, HP_HASHVAL, digest, &return_len, 0))
    {
      ctx->in_error = TRUE;
      SSH_DEBUG(SSH_D_FAIL, ("CryptGetHashParam failed: %x", GetLastError()));
    }

  if (return_len != digest_len)
    ctx->in_error = TRUE;

  if (ctx->hash_obj)
    {
      CryptDestroyHash(ctx->hash_obj);
      ctx->hash_obj = 0;
    }

  return ctx->in_error ? SSH_CRYPTO_OPERATION_FAILED : SSH_CRYPTO_OK;
}

/* Algorithm specific instances of the MSCAPI hash routines */


/* MD5 */

size_t ssh_md5_ctxsize()
{
  return mscapi_hash_ctxsize();
}

SshCryptoStatus ssh_md5_init(void *context)
{
  return mscapi_hash_init(context, CALG_MD5);
}

void ssh_md5_uninit(void *context)
{
  mscapi_hash_uninit(context, CALG_MD5);
}

void ssh_md5_reset_context(void *context)
{
  mscapi_hash_reset_context(context, CALG_MD5);
}

void ssh_md5_update(void *context, const unsigned char *buf, size_t len)
{
  mscapi_hash_update(context, (BYTE *)buf, (DWORD)len);
}

SshCryptoStatus ssh_md5_final(void *context, unsigned char *digest)
{
  return mscapi_hash_final(context, digest, 16);
}

void
ssh_md5_of_buffer(unsigned char digest[16], const unsigned char *buf,
                  size_t len)
{
  SshMscapiHashContext context;
  memset(&context, 0, sizeof(context));
  ssh_md5_reset_context(&context);
  ssh_md5_update(&context, buf, (DWORD) len);
  ssh_md5_final(&context, digest);
}

/* SHA1 */

size_t ssh_sha_ctxsize()
{
  return mscapi_hash_ctxsize();
}

SshCryptoStatus ssh_sha_init(void *context)
{
  return mscapi_hash_init(context, CALG_SHA1);
}

void ssh_sha_uninit(void *context)
{
  mscapi_hash_uninit(context, CALG_SHA1);
}

void ssh_sha_reset_context(void *context)
{
  mscapi_hash_reset_context(context, CALG_SHA1);
}

void ssh_sha_update(void *context, const unsigned char *buf, size_t len)
{
  mscapi_hash_update(context, (BYTE *)buf, (DWORD) len);
}

SshCryptoStatus ssh_sha_final(void *context, unsigned char *digest)
{
  return mscapi_hash_final(context, digest, 20);
}

void
ssh_sha_of_buffer(unsigned char digest[20],
                  const unsigned char *buf, size_t len)
{
  SshMscapiHashContext context;
  memset(&context, 0, sizeof(context));
  ssh_sha_reset_context(&context);
  ssh_sha_update(&context, buf, (DWORD) len);
  ssh_sha_final(&context, digest);
}

SshCryptoStatus ssh_sha_96_final(void *c, unsigned char *digest)
{
  SshCryptoStatus status;
  unsigned char tmp_digest[20];
  status = ssh_sha_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 12);
  return status;
}

SshCryptoStatus ssh_sha_80_final(void *c, unsigned char *digest)
{
  SshCryptoStatus status;
  unsigned char tmp_digest[20];
  status = ssh_sha_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 10);
  return status;
}


/* Extra routines. */

void ssh_sha_transform(SshUInt32 buf[5], const unsigned char in[64])
{
  SSH_NOTREACHED;
}

void ssh_sha_permuted_transform(SshUInt32 buf[5], const unsigned char in[64])
{
  SSH_NOTREACHED;
}

#endif /* HAVE_MSCAPI_CRYPTO */
#endif /* SSHDIST_MSCAPI */
