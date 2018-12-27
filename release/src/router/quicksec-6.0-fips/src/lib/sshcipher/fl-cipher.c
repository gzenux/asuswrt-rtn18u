/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   FL-Cipher - Implementation for cipher algorithms using FIPS Library.

               The following algorithms are supported:
                - DES3 with ECB/CBC modes
                - AES with ECB/CBC/CTR/GCM/CCM modes
                - AES XCBC MAC
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshfl.h"

#include <fl.h>
#include <fl-cipher.h>

#define SSH_DEBUG_MODULE "SshCryptoFlCipher"

#if defined SSHDIST_CRYPT_DES || \
    defined SSHDIST_CRYPT_RIJNDAEL || \
    defined SSHDIST_CRYPT_MODE_GCM || \
    defined SSHDIST_CRYPT_MODE_CCM

/******************************** Generic code *******************************/

/* FL Cipher Context used for all algorithms */
typedef struct {
  /* Cipher algorithm */
  FL_Algorithm_t algorithm;
  /* Key asset */
  FL_KeyAsset_t key_asset;
  /* State asset */
  FL_AnyAsset_t state;
  /* Tag length (Used only for AES-GCM and AES-CCM) */
  size_t tag_len;

} FlCipherContext;


static Boolean
fl_cipher_is_lib_functional(void)
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

static void
fl_cipher_free_asset(FL_AnyAsset_t *asset)
{
  FL_RV rv;

  rv = FL_AssetCheck(*asset, FL_CHECK_EXISTS);
  if (rv == FLR_OK)
    {
      SSH_FL_ASSETFREE(*asset);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to free nonexisting asset"));
    }

  *asset = FL_ASSET_INVALID;
}

static SshCryptoStatus
fl_cipher_init_context(void *context,
                       FL_Algorithm_t algorithm,
                       const unsigned char *key,
                       size_t key_len,
                       size_t tag_len)
{
  FlCipherContext *cipher_ctx = context;
  FL_PolicySmallBits_t policy_bits;
  FL_KeyAsset_t key_asset;
  FL_AnyAsset_t state;
  FL_RV rv;

  /* Set algorithm specific policy bits. */
  switch (algorithm)
    {
    case FL_ALGO_ECB_DES3_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_ECB_DES3_ENCRYPT;
      break;
    case FL_ALGO_ECB_DES3_DECRYPT:
      policy_bits = FL_POLICY_ALGO_ECB_DES3_DECRYPT;
      break;
    case FL_ALGO_CBC_DES3_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_CBC_DES3_ENCRYPT;
      break;
    case FL_ALGO_CBC_DES3_DECRYPT:
      policy_bits = FL_POLICY_ALGO_CBC_DES3_DECRYPT;
      break;

    case FL_ALGO_ECB_AES_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_ECB_AES_ENCRYPT;
      break;
    case FL_ALGO_ECB_AES_DECRYPT:
      policy_bits = FL_POLICY_ALGO_ECB_AES_DECRYPT;
      break;
    case FL_ALGO_CBC_AES_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_CBC_AES_ENCRYPT;
      break;
    case FL_ALGO_CBC_AES_DECRYPT:
      policy_bits = FL_POLICY_ALGO_CBC_AES_DECRYPT;
      break;

    case FL_ALGO_CTR128_AES:
      policy_bits = FL_POLICY_ALGO_CTR128_AES;
      break;

    case FL_ALGO_CCM_AES_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_CCM_AES_ENCRYPT;
      break;
    case FL_ALGO_CCM_AES_DECRYPT:
      policy_bits = FL_POLICY_ALGO_CCM_AES_DECRYPT;
      break;

    case FL_ALGO_GCM_AES_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_GCM_AES_ENCRYPT;
      break;
    case FL_ALGO_GCM_AES_DECRYPT:
      policy_bits = FL_POLICY_ALGO_GCM_AES_DECRYPT;
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported algorithm: %d", algorithm));
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  /* Create asset object for key. */
  SSH_FL_ASSETALLOCATEBASIC(rv, policy_bits, key_len, &key_asset);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetAllocateBasic failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Load key to asset object. */
  rv = FL_AssetLoadValue(key_asset, key, key_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetLoadValue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      fl_cipher_free_asset(&key_asset);

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  /* Acquire state for storing intermediate values */
  SSH_FL_ALLOCATE_STATE(rv, &state);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_ALLOCATE_STATE failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      fl_cipher_free_asset(&key_asset);

      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Store algorithm and assets to context. */
  cipher_ctx->algorithm = algorithm;
  cipher_ctx->key_asset = key_asset;
  cipher_ctx->state = state;
  cipher_ctx->tag_len = tag_len;

  return SSH_CRYPTO_OK;
}

static void
fl_cipher_uninit(void *context)
{
  FlCipherContext *cipher_ctx = context;

  /* Free state asset object */
  fl_cipher_free_asset(&cipher_ctx->state);

  /* Free key asset object */
  fl_cipher_free_asset(&cipher_ctx->key_asset);
}

#endif /* SSHDIST_CRYPT_DES ||
          SSHDIST_CRYPT_RIJNDAEL ||
          SSHDIST_CRYPT_MODE_GCM ||
          SSHDIST_CRYPT_MODE_CCM */

#if defined SSHDIST_CRYPT_DES || \
    defined SSHDIST_CRYPT_RIJNDAEL

static void
fl_cipher_start(void *context,
                const unsigned char *iv,
                size_t iv_len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Start cipher processing */
  rv = FL_CipherInit(cipher_ctx->key_asset,
                     cipher_ctx->state,
                     cipher_ctx->algorithm,
                     iv,
                     iv_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CipherInit failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());
      return;
    }
}

static SshCryptoStatus
fl_cipher_transform(void *context,
                    unsigned char *dest,
                    const unsigned char *src,
                    size_t len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Continue cipher processing */
  rv = FL_CipherContinue(cipher_ctx->state, src, dest, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CipherContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

#endif /* SSHDIST_CRYPT_DES || SSHDIST_CRYPT_RIJNDAEL */

#ifdef SSHDIST_CRYPT_DES

/* Key length of DES3 algorithm */
#define FL_CIPHER_DES3_KEY_LEN 24

/************************* DES3-ECB/CBC implementation ***********************/

/* Table of weak keys that are checked for. This includes the usual
   weak and semi-weak keys. */
#define FL_CIPHER_DES_WEAK_KEYS  (4 + 6*2)
static const unsigned char
fl_cipher_des_weak_keys[FL_CIPHER_DES_WEAK_KEYS][8] =
{
  /* The weak keys. */
  { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
  { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
  { 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
  { 0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1 },

  /* The semi-weak keys. */
  { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe },
  { 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01 },

  { 0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1 },
  { 0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e },

  { 0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1 },
  { 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01 },

  { 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },
  { 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e },

  { 0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e },
  { 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01 },

  { 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe },
  { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1 }
};

static Boolean
fl_cipher_des_is_weak_key(const unsigned char *key)
{
  int i;

  /* Do weak key checks. */
  for (i = 0; i < FL_CIPHER_DES_WEAK_KEYS; i++)
    {
      int j, match;

      for (j = 0, match = 0; j < 8; j++)
        {
          if ((key[j] & 0xfe) != (fl_cipher_des_weak_keys[i][j] & 0xfe))
            break;

          match++;
        }

      /* Was a weak key? */
      if (match == 8)
        return TRUE;
    }

  return FALSE;
}

static SshCryptoStatus
fl_cipher_des3_check_key(const unsigned char *key,
                         size_t key_len)
{
  /* Check key length */
  if (key_len < FL_CIPHER_DES3_KEY_LEN)
    {
      return SSH_CRYPTO_KEY_TOO_SHORT;
    }

  /* Check des weak keys. */
  if (fl_cipher_des_is_weak_key(key) == TRUE)
    {
      return SSH_CRYPTO_KEY_WEAK;
    }
  if (fl_cipher_des_is_weak_key(key + 8) == TRUE)
    {
      return SSH_CRYPTO_KEY_WEAK;
    }
  if (fl_cipher_des_is_weak_key(key + 16) == TRUE)
    {
      return SSH_CRYPTO_KEY_WEAK;
    }

  /* Check if K1 is same than K2, or K2 is same than K3. */
  if (memcmp(key, key + 8, 8) == 0 ||
      memcmp(key + 8, key + 16, 8) == 0)
    {
      return SSH_CRYPTO_KEY_INVALID;
    }

  return SSH_CRYPTO_OK;
}

size_t
fl_cipher_des3_ctxsize(void)
{
  return sizeof(FlCipherContext);
}

SshCryptoStatus
fl_cipher_des3_init_ecb(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        Boolean for_encryption)
{
  FL_Algorithm_t algorithm;

  /* Check key length */
  if (key_len < FL_CIPHER_DES3_KEY_LEN)
    {
      return SSH_CRYPTO_KEY_TOO_SHORT;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_ECB_DES3_ENCRYPT : FL_ALGO_ECB_DES3_DECRYPT;

  return fl_cipher_init_context(context,
                                algorithm,
                                key,
                                FL_CIPHER_DES3_KEY_LEN,
                                0);
}

SshCryptoStatus
fl_cipher_des3_init_cbc(void *context,
                        const unsigned char *key,
                        size_t key_len,
                        Boolean for_encryption)
{
  FL_Algorithm_t algorithm;

  /* Check key length */
  if (key_len < FL_CIPHER_DES3_KEY_LEN)
    {
      return SSH_CRYPTO_KEY_TOO_SHORT;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CBC_DES3_ENCRYPT : FL_ALGO_CBC_DES3_DECRYPT;

  return fl_cipher_init_context(context,
                                algorithm,
                                key,
                                FL_CIPHER_DES3_KEY_LEN,
                                0);
}

SshCryptoStatus
fl_cipher_des3_init_ecb_with_key_check(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption)
{
  FL_Algorithm_t algorithm;
  SshCryptoStatus status;

  /* Check key */
  status = fl_cipher_des3_check_key(key, key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_ECB_DES3_ENCRYPT : FL_ALGO_ECB_DES3_DECRYPT;

  return fl_cipher_init_context(context,
                                algorithm,
                                key,
                                FL_CIPHER_DES3_KEY_LEN,
                                0);
}

SshCryptoStatus
fl_cipher_des3_init_cbc_with_key_check(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption)
{
  FL_Algorithm_t algorithm;
  SshCryptoStatus status;

  /* Check key */
  status = fl_cipher_des3_check_key(key, key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CBC_DES3_ENCRYPT : FL_ALGO_CBC_DES3_DECRYPT;

  return fl_cipher_init_context(context,
                                algorithm,
                                key,
                                FL_CIPHER_DES3_KEY_LEN,
                                0);
}

void
fl_cipher_des3_uninit(void *context)
{
  fl_cipher_uninit(context);
}

SshCryptoStatus
fl_cipher_des3_start_ecb(void *context,
                         const unsigned char *unused)
{
  fl_cipher_start(context, NULL, 0);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_des3_start_cbc(void *context,
                         const unsigned char *iv)
{
  fl_cipher_start(context, iv, 8);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_des3_transform_ecb(void *context,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len)
{
  /* Make transform */
  return fl_cipher_transform(context, dest, src, len);
}

SshCryptoStatus
fl_cipher_des3_transform_cbc(void *context,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len)
{
  /* Make transform */
  return fl_cipher_transform(context, dest, src, len);
}

#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_RIJNDAEL

/*********************** AES-ECB/CBC/CTR implementation **********************/

static SshCryptoStatus
fl_cipher_aes_check_key_len(size_t key_len)
{
  /* Check key length */
  if (key_len == 16 || key_len == 24 || key_len == 32)
    {
      return SSH_CRYPTO_OK;
    }
  else
    {
      return SSH_CRYPTO_KEY_INVALID;
    }
}

size_t
fl_cipher_aes_ctxsize(void)
{
  return sizeof(FlCipherContext);
}

SshCryptoStatus
fl_cipher_aes_init_ecb(void *context,
                       const unsigned char *key,
                       size_t key_len,
                       Boolean for_encryption)
{
  FL_Algorithm_t algorithm;
  SshCryptoStatus status;

  /* Check key length */
  status = fl_cipher_aes_check_key_len(key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_ECB_AES_ENCRYPT : FL_ALGO_ECB_AES_DECRYPT;

  return fl_cipher_init_context(context, algorithm, key, key_len, 0);
}

SshCryptoStatus
fl_cipher_aes_init_cbc(void *context,
                       const unsigned char *key,
                       size_t key_len,
                       Boolean for_encryption)
{
  FL_Algorithm_t algorithm;
  SshCryptoStatus status;

  /* Check key length */
  status = fl_cipher_aes_check_key_len(key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CBC_AES_ENCRYPT : FL_ALGO_CBC_AES_DECRYPT;

  return fl_cipher_init_context(context, algorithm, key, key_len, 0);
}

SshCryptoStatus
fl_cipher_aes_init_ctr(void *context,
                       const unsigned char *key,
                       size_t key_len,
                       Boolean for_encryption)
{
  SshCryptoStatus status;

  /* Check key length */
  status = fl_cipher_aes_check_key_len(key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Init context. */
  return fl_cipher_init_context(context, FL_ALGO_CTR128_AES, key, key_len, 0);
}

void
fl_cipher_aes_uninit(void *context)
{
  fl_cipher_uninit(context);
}

SshCryptoStatus
fl_cipher_aes_start_ecb(void *context,
                        const unsigned char *unused)
{
  fl_cipher_start(context, NULL, 0);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_start_cbc(void *context,
                        const unsigned char *iv)
{
  fl_cipher_start(context, iv, 16);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_start_ctr(void *context,
                        const unsigned char *iv)
{
  fl_cipher_start(context, iv, 16);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_transform_ecb(void *context,
                            unsigned char *dest,
                            const unsigned char *src,
                            size_t len)
{
  /* Make transform */
  return fl_cipher_transform(context, dest, src, len);
}

SshCryptoStatus
fl_cipher_aes_transform_cbc(void *context,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len)
{
  /* Make transform */
  return fl_cipher_transform(context, dest, src, len);
}

SshCryptoStatus
fl_cipher_aes_transform_ctr(void *context,
                            unsigned char *dest,
                            const unsigned char *src,
                            size_t len)
{
  /* Make transform */
  return fl_cipher_transform(context, dest, src, len);
}

SshCryptoStatus
fl_aes_xcbc_mac(void *context, const unsigned char *src, size_t len,
                unsigned char *iv_arg)
{
  unsigned char temp[16];
  SshCryptoStatus status = SSH_CRYPTO_OK;

  /* Length is multiple of AES blocksize */
  SSH_ASSERT(len % 16 == 0);
  SSH_ASSERT(len != 0);

  fl_cipher_start(context, iv_arg, 16);

  /* Operate cbc step by step as we only need the last block */
  while (len > 0)
    {
      status = fl_cipher_transform(context, temp, src, 16);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed AES-XCBC MAC AES transform"));
          goto end;
        }

      src += 16;
      len -= 16;
    }

  memcpy(iv_arg, temp, 16);
  memset(temp, 0, sizeof(temp));

 end:
  return status;
}

#endif /* SSHDIST_CRYPT_RIJNDAEL */

#ifdef SSHDIST_CRYPT_MODE_GCM

/*************************** AES-GCM implementation **************************/

/* FIPS library requires upper limit for number of bytes to process. */
#define FL_CIPHER_AES_GCM_MAX_PLAINTEXT_LEN 65536

static SshCryptoStatus
fl_cipher_aes_gcm_check_key_len(size_t key_len)
{
  /* Check key length */
  if (key_len == 16 || key_len == 24 || key_len == 32)
    {
      return SSH_CRYPTO_OK;
    }
  else
    {
      return SSH_CRYPTO_KEY_INVALID;
    }
}

size_t
fl_cipher_aes_gcm_ctxsize(void)
{
  return sizeof(FlCipherContext);
}

static SshCryptoStatus
fl_cipher_aes_gcm_init(void *context,
                       const unsigned char *key,
                       size_t key_len,
                       size_t tag_len,
                       Boolean for_encryption)
{
  FL_Algorithm_t algorithm;
  SshCryptoStatus status;

  /* Check key length */
  status = fl_cipher_aes_gcm_check_key_len(key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_GCM_AES_ENCRYPT : FL_ALGO_GCM_AES_DECRYPT;

  return fl_cipher_init_context(context, algorithm, key, key_len, tag_len);
}

SshCryptoStatus
fl_cipher_aes_gcm_init_8(void *context,
                         const unsigned char *key,
                         size_t key_len,
                         Boolean for_encryption)
{
  return fl_cipher_aes_gcm_init(context,
                                key,
                                key_len,
                                8,
                                for_encryption);
}

SshCryptoStatus
fl_cipher_aes_gcm_init_12(void *context,
                          const unsigned char *key,
                          size_t key_len,
                          Boolean for_encryption)
{
  return fl_cipher_aes_gcm_init(context,
                                key,
                                key_len,
                                12,
                                for_encryption);
}

SshCryptoStatus
fl_cipher_aes_gcm_init_16(void *context,
                          const unsigned char *key,
                          size_t key_len,
                          Boolean for_encryption)
{
  return fl_cipher_aes_gcm_init(context,
                                key,
                                key_len,
                                16,
                                for_encryption);
}

void
fl_cipher_aes_gcm_uninit(void *context)
{
  fl_cipher_uninit(context);
}

SshCryptoStatus
fl_cipher_aes_gcm_start(void *context,
                        const unsigned char *iv,
                        const unsigned char *aad,
                        size_t aad_len,
                        size_t crypt_len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Start cipher processing */
  rv = FL_CryptAuthInit(cipher_ctx->key_asset,
                        cipher_ctx->state,
                        cipher_ctx->algorithm,
                        iv,
                        12,
                        aad,
                        aad_len,
                        FL_CIPHER_AES_GCM_MAX_PLAINTEXT_LEN,
                        16);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthInit failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_gcm_transform(void *context,
                            unsigned char *dest,
                            const unsigned char *src,
                            size_t len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Continue cipher processing */
  rv = FL_CryptAuthContinue(cipher_ctx->state, src, dest, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_gcm_final(void *context,
                        unsigned char *tag)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Check algorithm */
  if (cipher_ctx->algorithm != FL_ALGO_GCM_AES_ENCRYPT)
    {
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Finish cipher processing */
  rv = FL_EncryptAuthFinish(cipher_ctx->state, tag, cipher_ctx->tag_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EncryptAuthFinish failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_gcm_final_verify(void *context,
                               unsigned char *tag)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Check algorithm */
  if (cipher_ctx->algorithm != FL_ALGO_GCM_AES_DECRYPT)
    {
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Finish cipher processing */
  rv = FL_DecryptAuthFinish(cipher_ctx->state, tag, cipher_ctx->tag_len);
  if (rv == FLR_OK)
    {
      return SSH_CRYPTO_OK;
    }
  else if (rv == FLR_VERIFY_MISMATCH)
    {
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_DecryptAuthFinish failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));

      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }
}

#ifdef SSHDIST_FIPSLIB_1_1
SshCryptoStatus
fl_cipher_aes_gmac_start(void *context,
                         const unsigned char *iv,
                         const unsigned char *aad,
                         size_t aad_len,
                         size_t crypt_len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Start cipher processing */
  rv = FL_CryptAuthInit(cipher_ctx->key_asset,
                        cipher_ctx->state,
                        cipher_ctx->algorithm,
                        iv,
                        12,
                        NULL,
                        0,
                        FL_CIPHER_AES_GCM_MAX_PLAINTEXT_LEN,
                        16);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthInit failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  rv = FL_CryptGcmAadContinue(cipher_ctx->state, aad, aad_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptGcmAadContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

void
fl_cipher_aes_gmac_update(void *cipher_context,
                          const unsigned char *buf,
                          size_t len)
{
  FlCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_ctx != NULL);

  rv = FL_CryptGcmAadContinue(cipher_ctx->state, buf, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptGcmAadContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());
      return;
    }
}

SshCryptoStatus
fl_cipher_aes_gmac_transform(void *context,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len)

{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  SSH_ASSERT(cipher_ctx != NULL);

  rv = FL_CryptGcmAadContinue(cipher_ctx->state, src, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptGcmAadContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  if (dest != src) memcpy(dest, src, len);

  return SSH_CRYPTO_OK;
}
#endif /* SSHDIST_FIPSLIB_1_1 */
#endif /* SSHDIST_CRYPT_MODE_GCM */

#ifdef SSHDIST_CRYPT_MODE_CCM

/*************************** AES-CCM implementation **************************/

static SshCryptoStatus
fl_cipher_aes_ccm_check_key_len(size_t key_len)
{
  /* Check key length */
  if (key_len == 16 || key_len == 24 || key_len == 32)
    {
      return SSH_CRYPTO_OK;
    }
  else
    {
      return SSH_CRYPTO_KEY_INVALID;
    }
}

size_t
fl_cipher_aes_ccm_ctxsize(void)
{
  return sizeof(FlCipherContext);
}

static SshCryptoStatus
fl_cipher_aes_ccm_init(void *context,
                       const unsigned char *key,
                       size_t key_len,
                       size_t tag_len,
                       Boolean for_encryption)
{
  FL_Algorithm_t algorithm;
  SshCryptoStatus status;

  /* Check key length */
  status = fl_cipher_aes_ccm_check_key_len(key_len);
  if (status != SSH_CRYPTO_OK)
    {
      return status;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CCM_AES_ENCRYPT : FL_ALGO_CCM_AES_DECRYPT;

  return fl_cipher_init_context(context, algorithm, key, key_len, tag_len);
}

SshCryptoStatus
fl_cipher_aes_ccm_init_8(void *context,
                         const unsigned char *key,
                         size_t key_len,
                         Boolean for_encryption)
{
  return fl_cipher_aes_ccm_init(context,
                                key,
                                key_len,
                                8,
                                for_encryption);
}

SshCryptoStatus
fl_cipher_aes_ccm_init_12(void *context,
                          const unsigned char *key,
                          size_t key_len,
                          Boolean for_encryption)
{
  return fl_cipher_aes_ccm_init(context,
                                key,
                                key_len,
                                12,
                                for_encryption);
}

SshCryptoStatus
fl_cipher_aes_ccm_init_16(void *context,
                          const unsigned char *key,
                          size_t key_len,
                          Boolean for_encryption)
{
  return fl_cipher_aes_ccm_init(context,
                                key,
                                key_len,
                                16,
                                for_encryption);
}

void
fl_cipher_aes_ccm_uninit(void *context)
{
  fl_cipher_uninit(context);
}

SshCryptoStatus
fl_cipher_aes_ccm_start(void *context,
                        const unsigned char *iv,
                        const unsigned char *aad,
                        size_t aad_len,
                        size_t crypt_len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Start cipher processing */
  rv = FL_CryptAuthInit(cipher_ctx->key_asset,
                        cipher_ctx->state,
                        cipher_ctx->algorithm,
                        iv,
                        11,
                        aad,
                        aad_len,
                        crypt_len,
                        cipher_ctx->tag_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthInit failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_ccm_transform(void *context,
                            unsigned char *dest,
                            const unsigned char *src,
                            size_t len)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Continue cipher processing */
  rv = FL_CryptAuthContinue(cipher_ctx->state, src, dest, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_ccm_final(void *context,
                        unsigned char *tag)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Check algorithm */
  if (cipher_ctx->algorithm != FL_ALGO_CCM_AES_ENCRYPT)
    {
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Finish cipher processing */
  rv = FL_EncryptAuthFinish(cipher_ctx->state, tag, cipher_ctx->tag_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EncryptAuthFinish failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
fl_cipher_aes_ccm_final_verify(void *context,
                               unsigned char *tag)
{
  FlCipherContext *cipher_ctx = context;
  FL_RV rv;

  /* Check algorithm */
  if (cipher_ctx->algorithm != FL_ALGO_CCM_AES_DECRYPT)
    {
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Finish cipher processing */
  rv = FL_DecryptAuthFinish(cipher_ctx->state, tag, cipher_ctx->tag_len);
  if (rv == FLR_OK)
    {
      return SSH_CRYPTO_OK;
    }
  else if (rv == FLR_VERIFY_MISMATCH)
    {
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_DecryptAuthFinish failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));

      SSH_VERIFY(fl_cipher_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }
}

#endif /* SSHDIST_CRYPT_MODE_CCM */
