/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   FL-HMAC - Implementation for HMAC algorithms using FIPS Library.

             The following algorithms are supported:
              - HMAC-SHA-1 with 160/96-bits MAC
              - HMAC-SHA-256 with 256/128/96-bits MAC
              - HMAC-SHA-224 with 224/128-bits MAC
              - HMAC-SHA-512 with 512/256/128-bits MAC
              - HMAC-SHA-384 with 384/192/128 -bits MAC
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "sshmac_i.h"
#include "sshfl.h"

#include <fl.h>
#include <fl-hmac.h>

#define SSH_DEBUG_MODULE "SshCryptoFlHmac"

#if defined SSHDIST_CRYPT_SHA || \
    defined SSHDIST_CRYPT_SHA256 || \
    defined SSHDIST_CRYPT_SHA512

/******************************** Generic code *******************************/

/* FL HMAC Context used for all algorithms */
typedef struct
{
  /* MAC algorithm */
  FL_MacAlgorithm_t algorithm;
  /* Key asset */
  FL_KeyAsset_t key_asset;
  /* MAC length */
  size_t mac_len;
  /* State asset */
  FL_AnyAsset_t state;

} FlHmacContext;


static Boolean
fl_hmac_is_lib_functional(void)
{
  FL_LibStatus_t status;

  status = FL_LibStatus();
  if (status == FL_STATUS_ERROR)
    {
      return FALSE;
    }
  else
    {
      return TRUE;
    }
}

size_t
fl_hmac_ctxsize(const SshHashDefStruct *unused)
{
  return sizeof(FlHmacContext);
}

static void
fl_hmac_free_asset(FL_AnyAsset_t *asset)
{
  FL_RV rv;

  /* Free state object. */
  rv = FL_AssetCheck(*asset, FL_CHECK_EXISTS);
  if (rv == FLR_OK)
    {
      SSH_FL_ASSETFREE(*asset);
    }

   *asset = FL_ASSET_INVALID;
}

static SshCryptoStatus
fl_hmac_create_key_asset(FL_MacAlgorithm_t algorithm,
                         const unsigned char *key,
                         size_t key_len,
                         FL_KeyAsset_t *key_asset_p)
{
  FL_PolicySmallBits_t policy_bits;
  FL_RV rv;

  /* Set algorithm specific policy bits. */
  switch (algorithm)
    {
    case FL_ALGO_HMAC_SHA1:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA1 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    case FL_ALGO_HMAC_SHA2_256:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA2_256 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    case FL_ALGO_HMAC_SHA2_224:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA2_224 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    case FL_ALGO_HMAC_SHA2_512:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA2_512 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    case FL_ALGO_HMAC_SHA2_384:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA2_384 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported algorithm: %d", algorithm));
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  /* Create asset object for key. */
  SSH_FL_ASSETALLOCATEBASIC(rv, policy_bits, key_len, key_asset_p);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetAllocateBasic failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hmac_is_lib_functional());

      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Load key to asset object. */
  rv = FL_AssetLoadValue(*key_asset_p, key, key_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetLoadValue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hmac_is_lib_functional());

      /* Free key asset object */
      fl_hmac_free_asset(key_asset_p);

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
fl_hmac_init(void *context,
             FL_MacAlgorithm_t algorithm,
             const unsigned char *key,
             size_t key_len,
             size_t mac_len)
{
  FlHmacContext *hmac_ctx = context;
  FL_KeyAsset_t key_asset;
  SshCryptoStatus status;

  /* Create key asset. */
  status = fl_hmac_create_key_asset(algorithm, key, key_len, &key_asset);
  if (status == SSH_CRYPTO_OK)
    {
      /* Save algorithm, MAC length and key asset. */
      hmac_ctx->algorithm = algorithm;
      hmac_ctx->mac_len = mac_len;
      hmac_ctx->key_asset = key_asset;
      hmac_ctx->state = FL_ASSET_INVALID;
    }

  return status;
}

void
fl_hmac_uninit(void *context)
{
  FlHmacContext *hmac_ctx = context;

  /* Free state object. */
  fl_hmac_free_asset(&hmac_ctx->state);

  /* Free key asset object. */
  fl_hmac_free_asset(&hmac_ctx->key_asset);
}

SshCryptoStatus
fl_hmac_start(void *context)
{
  FlHmacContext *hmac_ctx = context;
  FL_RV rv;

  /* Free state object. */
  fl_hmac_free_asset(&hmac_ctx->state);

  /* Acquire state for storing intermediate values */
  SSH_FL_ALLOCATE_STATE(rv, &hmac_ctx->state);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_ALLOCATE_STATE failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hmac_is_lib_functional());
      return  SSH_CRYPTO_NO_MEMORY;
    }

  /* Start MAC processing */
  rv = FL_MacGenerateInit(hmac_ctx->key_asset,
                          hmac_ctx->state,
                          hmac_ctx->algorithm,
                          NULL,
                          0);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_MacGenerateInit failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hmac_is_lib_functional());

      /* Free state object. */
      fl_hmac_free_asset(&hmac_ctx->state);
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

void
fl_hmac_update(void *context,
               const unsigned char *buf,
               size_t len)
{
  FlHmacContext *hmac_ctx = context;
  FL_RV rv;

  /* Continue MAC processing */
  rv = FL_MacGenerateContinue(hmac_ctx->state, buf, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_MacGenerateContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hmac_is_lib_functional());
      return;
    }
}

SshCryptoStatus
fl_hmac_final(void *context,
              unsigned char *mac)
{
  FlHmacContext *hmac_ctx = context;
  FL_RV rv;

  /* Finish MAC processing */
  rv = FL_MacGenerateFinish(hmac_ctx->state, mac, hmac_ctx->mac_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_MacGenerateFinish failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hmac_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_hmac_of_buffer(void *context,
                  const unsigned char *buf,
                  size_t len,
                  unsigned char *mac)
{
  SshCryptoStatus status;

  status = fl_hmac_start(context);
  if (status == SSH_CRYPTO_OK)
    {
      fl_hmac_update(context, buf, len);
      status = fl_hmac_final(context, mac);
    }

  return status;
}

#endif /* SSHDIST_CRYPT_SHA || SSHDIST_CRYPT_SHA256 || SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA

/********************* HMAC-SHA-1 specific implementation ********************/

SshCryptoStatus
fl_hmac_sha1_init(void *context,
                  const unsigned char *key,
                  size_t key_len,
                  const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA1, key, key_len, 20);
}

SshCryptoStatus
fl_hmac_sha1_96_init(void *context,
                     const unsigned char *key,
                     size_t key_len,
                     const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA1, key, key_len, 12);
}

#endif /*  SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256

/******************** HMAC-SHA-256 specific implementation *******************/

SshCryptoStatus
fl_hmac_sha256_init(void *context,
                    const unsigned char *key,
                    size_t key_len,
                    const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_256, key, key_len, 32);
}

SshCryptoStatus
fl_hmac_sha256_128_init(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_256, key, key_len, 16);
}

SshCryptoStatus
fl_hmac_sha256_96_init(void *context,
                       const unsigned char *key,
                       size_t key_len,
                       const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_256, key, key_len, 12);
}


/******************** HMAC-SHA-224 specific implementation *******************/

SshCryptoStatus
fl_hmac_sha224_init(void *context,
                    const unsigned char *key,
                    size_t key_len,
                    const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_224, key, key_len, 28);
}

SshCryptoStatus
fl_hmac_sha224_128_init(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_224, key, key_len, 16);
}

#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512

/******************** HMAC-SHA-512 specific implementation *******************/

SshCryptoStatus
fl_hmac_sha512_init(void *context,
                    const unsigned char *key,
                    size_t key_len,
                    const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_512, key, key_len, 64);
}

SshCryptoStatus
fl_hmac_sha512_256_init(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_512, key, key_len, 32);
}

SshCryptoStatus
fl_hmac_sha512_128_init(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_512, key, key_len, 16);
}


/******************** HMAC-SHA-384 specific implementation *******************/

SshCryptoStatus
fl_hmac_sha384_init(void *context,
                    const unsigned char *key,
                    size_t key_len,
                    const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_384, key, key_len, 48);
}

SshCryptoStatus
fl_hmac_sha384_192_init(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_384, key, key_len, 24);
}

SshCryptoStatus
fl_hmac_sha384_128_init(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        const SshHashDefStruct *unused)
{
  return fl_hmac_init(context, FL_ALGO_HMAC_SHA2_384, key, key_len, 16);
}

#endif /* SSHDIST_CRYPT_SHA512 */
