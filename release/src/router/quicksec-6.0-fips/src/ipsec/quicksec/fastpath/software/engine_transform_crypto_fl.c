/**
   @copyright
   Copyright (c) 2014 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
  Implements functions declared in engine_transform_crypto.h. This
  implementation uses the cryptographic algorithms from FIPS library
  or from SSH Crypto library depending on configuration of this module.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#include "fastpath_swi.h"
#include "engine_transform_crypto.h"
#include "sshfl.h"
#include "sshcrypt.h"
#include <fl.h>
#include <fl-hmac.h>

#define SSH_DEBUG_MODULE "SshEngineFastpathTransformCryptoFl"

/* Definition structure for cipher algorithms. */
typedef struct SshFastpathCipherDefRec
{
  /* Name of cipher. */
  const char *name;

  /* Block length. */
  unsigned int block_len;

  /* ICV length. */
  unsigned int icv_len;

  /* Combined mode cipher. */
  Boolean combined_mode_on;

  /* Counter mode cipher. */
  Boolean counter_mode_on;

  /* AAD required (Used only for ESP) */
  Boolean aad_required;

  /* IV included into the AAD. */
  Boolean aad_include_iv;

  /* Nonce length for conter mode ciphers. */
  SshUInt8 nonce_size;

  /* Allocate cipher context. */
  SshTransformResult (*allocate)(const char *name,
                                 const unsigned char *key,
                                 size_t key_len,
                                 Boolean for_encryption,
                                 void **cipher_context_p);

  /* Free cipher. */
  void (*free)(void **cipher_context_p);

  /* Start cipher operation. */
  SshTransformResult (*start)(void *cipher_context,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *aad,
                              size_t aad_len,
                              size_t crypt_len);

  /* Continue ICV calculation. (Used with combined algorithms) */
  SshTransformResult (*update)(void *cipher_context,
                               const unsigned char *buf,
                               size_t len);

  /* Return calculated ICV. (Used with combined algorithms) */
  SshTransformResult (*result)(void *cipher_context,
                               unsigned char *icv,
                               size_t icv_len);

  /* Verify calculated ICV. (Used with combined algorithms) */
  SshTransformResult (*verify)(void *cipher_context,
                               unsigned char *icv,
                               size_t icv_len);

  /* Encryption and decryption. */
  SshTransformResult (*transform)(void *cipher_context,
                                  unsigned char *dest,
                                  const unsigned char *src,
                                  size_t len);

} *SshFastpathCipherDef, SshFastpathCipherDefStruct;


/* Definition structure for MAC algorithms. */
typedef struct SshFastpathMacDefRec
{
  /* Name of MAC. */
  const char *name;

  /* ICV length. */
  unsigned int icv_len;

  /* Allocate MAC context. */
  SshTransformResult (*allocate)(const char *name,
                                 const unsigned char *key,
                                 size_t key_len,
                                 void **mac_context);

  /* Free MAC context. */
  void (*free)(void **mac_context_p);

  /* Start calculation of ICV. */
  void (*start)(void *mac_context);

  /* Continue ICV calculation. */
  SshTransformResult (*update)(void *mac_context,
                               const unsigned char *buf,
                               size_t len);

  /* Return calculated ICV. */
  SshTransformResult (*result)(void *mac_context,
                               unsigned char *icv,
                               size_t icv_len);

  /* Verify calculated ICV. */
  SshTransformResult (*verify)(void *mac_context,
                               const unsigned char *icv,
                               size_t icv_len);

} *SshFastpathMacDef, SshFastpathMacDefStruct;



/* Declarations for functions using FIPS Crypto API. */

static SshTransformResult
fl_fastpath_cipher_allocate(void **context,
                            FL_Algorithm_t algorithm,
                            const unsigned char *key,
                            size_t key_len,
                            size_t tag_len);

static SshTransformResult
fl_fastpath_cipher_des3_cbc_allocate(const char *name,
                                     const unsigned char *key,
                                     size_t key_len,
                                     Boolean for_encryption,
                                     void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_cbc_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_ctr_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p);

static void
fl_fastpath_cipher_free(void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_start(void *cipher_context,
                         const unsigned char *iv,
                         size_t iv_len,
                         const unsigned char *aad,
                         size_t aad_len,
                         size_t crypt_size);

static SshTransformResult
fl_fastpath_cipher_auth_start(void *cipher_context,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *aad,
                              size_t aad_len,
                              size_t crypt_len);

static SshTransformResult
fl_fastpath_cipher_auth_result(void *cipher_context,
                               unsigned char *icv,
                               size_t icv_len);

static SshTransformResult
fl_fastpath_cipher_auth_verify(void *cipher_context,
                               unsigned char *icv,
                               size_t icv_len);

static SshTransformResult
fl_fastpath_cipher_transform(void *cipher_context,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len);

static SshTransformResult
fl_fastpath_cipher_auth_transform(void *cipher_context,
                                  unsigned char *dest,
                                  const unsigned char *src,
                                  size_t len);

static SshTransformResult
fl_fastpath_cipher_gmac_auth_start(void *cipher_context,
                                   const unsigned char *iv,
                                   size_t iv_len,
                                   const unsigned char *aad,
                                   size_t aad_len,
                                   size_t crypt_len);

static SshTransformResult
fl_fastpath_cipher_gmac_auth_update(void *cipher_context,
                                    const unsigned char *buf,
                                    size_t len);

static SshTransformResult
fl_fastpath_cipher_gmac_auth_transform(void *cipher_context,
                                       unsigned char *dest,
                                       const unsigned char *src,
                                       size_t len);

static SshTransformResult
fl_fastpath_cipher_aes_gcm_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_gcm_8_allocate(const char *name,
                                      const unsigned char *key,
                                      size_t key_len,
                                      Boolean for_encryption,
                                      void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_gcm_12_allocate(const char *name,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption,
                                       void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_ccm_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_ccm_8_allocate(const char *name,
                                      const unsigned char *key,
                                      size_t key_len,
                                      Boolean for_encryption,
                                      void **cipher_context_p);

static SshTransformResult
fl_fastpath_cipher_aes_ccm_12_allocate(const char *name,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption,
                                       void **cipher_context_p);

static SshTransformResult
fl_fastpath_hmac_sha1_96_init(const char *name,
                              const unsigned char *key,
                              size_t key_len, void **context);

static SshTransformResult
fl_fastpath_hmac_sha256_128_init(const char *name,
                                 const unsigned char *key,
                                 size_t key_len, void **context);

static SshTransformResult
fl_fastpath_hmac_sha384_192_init(const char *name,
                                 const unsigned char *key,
                                 size_t key_len, void **context);

static SshTransformResult
fl_fastpath_hmac_sha512_256_init(const char *name,
                                 const unsigned char *key,
                                 size_t key_len, void **context);

static void
fl_fastpath_hmac_uninit(void **context);

static void
fl_fastpath_hmac_start(void *context);

static SshTransformResult
fl_fastpath_hmac_update(void *context,
                        const unsigned char *buf,
                        size_t len);

static SshTransformResult
fl_fastpath_hmac_result(void *context,
                        unsigned char *icv,
                        size_t icv_len);

static SshTransformResult
fl_fastpath_hmac_verify(void *context,
                        const unsigned char *icv,
                        size_t icv_len);


static SshTransformResult
fl_fastpath_mac_xcbc_aes_init(const char *name,
                              const unsigned char *key,
                              size_t key_len, void **context);

static void
fl_fastpath_mac_xcbc_aes_uninit(void **context);

static void
fl_fastpath_mac_xcbc_start(void *context);

static SshTransformResult
fl_fastpath_mac_xcbc_update(void *context,
                            const unsigned char *buf,
                            size_t len);

static SshTransformResult
fl_fastpath_mac_xcbc_aes_96_result(void *context,
                                   unsigned char *icv,
                                   size_t icv_len);

static SshTransformResult
fl_fastpath_mac_xcbc_verify(void *context,
                            const unsigned char *icv,
                            size_t icv_len);




#ifdef SSHDIST_CRYPT_DES
SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_3des_cbc_def =
  {
    "3des-cbc",
    8,
    0,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    0,
    fl_fastpath_cipher_des3_cbc_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_start,
    NULL,
    NULL,
    NULL,
    fl_fastpath_cipher_transform
  };
#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_cbc_def =
  {
    "aes-cbc",
    16,
    0,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    0,
    fl_fastpath_cipher_aes_cbc_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_start,
    NULL,
    NULL,
    NULL,
    fl_fastpath_cipher_transform
  };

SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_ctr_def =
  {
    "aes-ctr",
    16,
    0,
    FALSE,
    TRUE,
    FALSE,
    FALSE,
    4,
    fl_fastpath_cipher_aes_ctr_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_start,
    NULL,
    NULL,
    NULL,
    fl_fastpath_cipher_transform
  };

#ifdef SSHDIST_CRYPT_MODE_GCM
SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_gcm_def =
  {
    "aes-gcm",
    16,
    16,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    4,
    fl_fastpath_cipher_aes_gcm_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_auth_start,
    NULL,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_auth_transform
  };

SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_gcm_64_def =
  {
    "aes-gcm-8",
    16,
    8,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    4,
    fl_fastpath_cipher_aes_gcm_8_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_auth_start,
    NULL,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_auth_transform
  };

SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_gcm_96_def =
  {
    "aes-gcm-12",
    16,
    12,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    4,
    fl_fastpath_cipher_aes_gcm_12_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_auth_start,
    NULL,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_auth_transform
  };

SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_null_auth_aes128_gmac_def =
  {
    "gmac-aes",
    16,
    16,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    4,
    fl_fastpath_cipher_aes_gcm_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_gmac_auth_start,
    fl_fastpath_cipher_gmac_auth_update,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_gmac_auth_transform
  };
#endif /* SSHDIST_CRYPT_MODE_GCM */

#ifdef SSHDIST_CRYPT_MODE_CCM
SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_ccm_def =
  {
    "aes-ccm",
    16,
    16,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    3,
    fl_fastpath_cipher_aes_ccm_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_auth_start,
    NULL,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_auth_transform
  };

SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_ccm_64_def =
  {
    "aes-ccm-8",
    16,
    8,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    3,
    fl_fastpath_cipher_aes_ccm_8_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_auth_start,
    NULL,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_auth_transform
  };

SSH_RODATA
const SshFastpathCipherDefStruct ssh_fastpath_aes128_ccm_96_def =
  {
    "aes-ccm-12",
    16,
    12,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    3,
    fl_fastpath_cipher_aes_ccm_12_allocate,
    fl_fastpath_cipher_free,
    fl_fastpath_cipher_auth_start,
    NULL,
    fl_fastpath_cipher_auth_result,
    fl_fastpath_cipher_auth_verify,
    fl_fastpath_cipher_auth_transform
  };
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */

#ifdef SSHDIST_CRYPT_SHA
SSH_RODATA_IN_TEXT
SshFastpathMacDefStruct ssh_fastpath_mac_sha1_96_def =
  {
    "hmac-sha1-96",
    12,
    fl_fastpath_hmac_sha1_96_init,
    fl_fastpath_hmac_uninit,
    fl_fastpath_hmac_start,
    fl_fastpath_hmac_update,
    fl_fastpath_hmac_result,
    fl_fastpath_hmac_verify
  };
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
SSH_RODATA_IN_TEXT
SshFastpathMacDefStruct ssh_fastpath_mac_sha256_128_def =
  {
    "hmac-sha256-128",
    16,
    fl_fastpath_hmac_sha256_128_init,
    fl_fastpath_hmac_uninit,
    fl_fastpath_hmac_start,
    fl_fastpath_hmac_update,
    fl_fastpath_hmac_result,
    fl_fastpath_hmac_verify
  };
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
SSH_RODATA_IN_TEXT
SshFastpathMacDefStruct ssh_fastpath_mac_sha384_192_def =
  {
    "hmac-sha384-192",
    24,
    fl_fastpath_hmac_sha384_192_init,
    fl_fastpath_hmac_uninit,
    fl_fastpath_hmac_start,
    fl_fastpath_hmac_update,
    fl_fastpath_hmac_result,
    fl_fastpath_hmac_verify
  };

SSH_RODATA_IN_TEXT
SshFastpathMacDefStruct ssh_fastpath_mac_sha512_256_def =
  {
    "hmac-sha512-256",
    32,
    fl_fastpath_hmac_sha512_256_init,
    fl_fastpath_hmac_uninit,
    fl_fastpath_hmac_start,
    fl_fastpath_hmac_update,
    fl_fastpath_hmac_result,
    fl_fastpath_hmac_verify
  };
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA_IN_TEXT
SshFastpathMacDefStruct ssh_fastpath_mac_xcbc_aes_96_def =
  {
    "xcbcmac-aes-96",
    12,
    fl_fastpath_mac_xcbc_aes_init,
    fl_fastpath_mac_xcbc_aes_uninit,
    fl_fastpath_mac_xcbc_start,
    fl_fastpath_mac_xcbc_update,
    fl_fastpath_mac_xcbc_aes_96_result,
    fl_fastpath_mac_xcbc_verify
  };
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */

static const char
*fl_fastpath_rv_to_string(FL_RV rv)
{
  const char *string = NULL;

  switch (rv)
    {
    case FLR_OK:
      string = "OK";
      break;
    case FLR_VERIFY_MISMATCH:
      string = "Verify operation failed";
      break;
    case FLR_OUTPUT_LENGTH:
      string = "Output buffer too small or not provided";
      break;
    case FLR_WRONG_STATE:
      string = "Function called in wrong state";
      break;
    case FLR_OPERATION_FAILED:
      string = "Cryptographic operation failed";
      break;
    case FLR_INVALID_DATA:
      string = "Invalid data provided for the operation";
      break;
    case FLR_INVALID_ALGORITHM:
      string = "Invalid algorithm";
      break;
    case FLR_INVALID_ARGUMENTS:
      string = "Invalid arguments";
      break;
    case FLR_ASSET_STORAGE:
      string = "Asset Storage is full";
      break;
    case FLR_SELFTEST_FAILED:
      string = "Selftest failed";
      break;
    case FLR_PRIVILEGE_VIOLATION:
      string = "Privilege violation";
      break;
    case FLR_RESOURCE_NOT_FOUND:
      string = "Resource not found";
      break;
    case FLR_RNG_ENTROPY:
      string = "Unable to obtain sufficient entropy";
      break;
    case FLR_RNG_CONTINUOUS_TEST_FAILURE:
      string = "Continuous RNG test failed";
      break;
    default:
      string = "Unknown return value";
      break;
    }

  return string;
}

static Boolean
fl_fastpath_is_lib_functional(void)
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

static const SshFastpathCipherDefStruct *
fastpath_get_cipher_def(SshEngineTransformRun trr,
                        SshPmTransform transform)
{
  const SshFastpathCipherDefStruct *cipher_def;
  cipher_def = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      cipher_def = &ssh_fastpath_aes128_cbc_def;
      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      cipher_def = &ssh_fastpath_aes128_ctr_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      cipher_def = &ssh_fastpath_aes128_gcm_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      cipher_def = &ssh_fastpath_aes128_gcm_64_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_12)
    {
      cipher_def = &ssh_fastpath_aes128_gcm_96_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      cipher_def = &ssh_fastpath_null_auth_aes128_gmac_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
  else if (transform & SSH_PM_CRYPT_AES_CCM)
    {
      cipher_def = &ssh_fastpath_aes128_ccm_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_8)
    {
      cipher_def = &ssh_fastpath_aes128_ccm_64_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_12)
    {
      cipher_def = &ssh_fastpath_aes128_ccm_96_def;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
  else if (transform & SSH_PM_CRYPT_3DES)
    {
      cipher_def = &ssh_fastpath_3des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 24);
    }
#endif /* SSHDIST_CRYPT_DES */
  else if (transform & SSH_PM_CRYPT_EXT1)
    {
      if (cipher_def == NULL)
        {
          ssh_warning("EXT1 cipher not configured");
          return NULL;
        }
    }
  else if (transform & SSH_PM_CRYPT_EXT2)
    {
      if (cipher_def == NULL)
        {
          ssh_warning("EXT2 cipher not configured");
          return NULL;
        }
    }
  else
    {
      /* No cipher configured. */
      SSH_ASSERT(trr->cipher_key_size == 0);
    }

  return cipher_def;
}

const SshFastpathMacDefStruct *
fastpath_get_mac_def(SshEngineTransformRun trr,
                     SshPmTransform transform)
{
  const SshFastpathMacDefStruct *mac_def;
  mac_def = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_SHA is undefined */
    }
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      mac_def = &ssh_fastpath_mac_sha1_96_def;
      SSH_ASSERT(trr->mac_key_size == 20);
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      mac_def = &ssh_fastpath_mac_sha256_128_def;
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      mac_def = &ssh_fastpath_mac_sha384_192_def;
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      mac_def = &ssh_fastpath_mac_sha512_256_def;
    }
#endif /* SSHDIST_CRYPT_SHA512 */
  else if ((transform & SSH_PM_MAC_HMAC_SHA2))
    {
      SSH_ASSERT(0); /* Unsupported sha2 key size requested... */
    }
#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_MAC_XCBC_AES)
    {
      mac_def = &ssh_fastpath_mac_xcbc_aes_96_def;
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
  else if (transform & SSH_PM_MAC_EXT1)
    {
      ssh_warning("EXT1 MAC not yet supported");
      return NULL;
    }
  else if (transform & SSH_PM_MAC_EXT2)
    {
      ssh_warning("EXT2 MAC not yet supported");
      return NULL;
    }
  else
    {
      /* No MAC configured. */
      SSH_ASSERT(trr->mac_key_size == 0);
    }

  return mac_def;
}

/* Cipher IV types. */
typedef enum
{
  /* IV not used. */
  SSH_TRANSFORM_IV_NONE,
  /* IV used with CBC mode. */
  SSH_TRANSFORM_IV_CBC,
  /* IV used with CTR mode. */
  SSH_TRANSFORM_IV_CTR,
  /* IV used with CTR mode and the last word of IV initialized to 1. */
  SSH_TRANSFORM_IV_CTR_WITH_ONE

} SshTransformIvType;


/* Additional Authenticated Data (AAD) types. */
typedef enum
{
  /* AAD not used. */
  SSH_TRANSFORM_AAD_UNUSED,
  /* AAD contains SPI and 32-bit Sequence Number. */
  SSH_TRANSFORM_AAD_DEFAULT,
  /* AAD contains SPI and 62-bit Sequence Number. */
  SSH_TRANSFORM_AAD_WITH_ESN,
  /* AAD contains SPI, 32-bit Sequence Number and IV. */
  SSH_TRANSFORM_AAD_WITH_IV,
  /* AAD contains SPI, 64-bit Sequence Number and IV. */
  SSH_TRANSFORM_AAD_WITH_ESN_AND_IV

} SshTransformAadType;


#define FASTPATH_TRANSFORM_MAX_NONCE_LEN  4

#define FASTPATH_TRANSFORM_MAX_PACKET_IV_LEN  8

typedef struct SshTransformSwCryptoFlContextRec
{
  /* Cipher descriptor. (NULL if encryption is not performed.) */
  const SshFastpathCipherDefStruct *cipher_def;

  /* Cipher context. */
  void *cipher_context;

  /* MAC descriptor. (NULL is integrity calculation is not done with
     MAC e.g. if combined mode cipher is used.) */
  const SshFastpathMacDefStruct *mac_def;

  /* MAC context. */
  void *mac_context;

  /* IV type of cipher. */
  SshTransformIvType cipher_iv_type;

  /* The cipher nonce for counter mode ciphers. */
  unsigned char cipher_nonce[FASTPATH_TRANSFORM_MAX_NONCE_LEN];
  SshUInt8 cipher_nonce_size;

  /* AAD type, if combined mode cipher is used. */
  SshTransformAadType aad_type;

  /* TRUE, if AH in use. */
  Boolean is_ah;

  /* Generated packet IV.
     Used in AH case when selected algorithm is AES-GMAC. */
  unsigned char packet_iv[FASTPATH_TRANSFORM_MAX_PACKET_IV_LEN];
  unsigned int packet_iv_len;

  unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned int icv_len;

} *SshTransformSwCryptoFlContext;

void
transform_crypto_init(void)
{
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "Using FIPSLib backend for engine transform crypto");
}

SshTransformResult
transform_crypto_alloc(SshFastpathTransformContext tc,
                       SshEngineTransformRun trr,
                       SshPmTransform transform)
{
  SshTransformSwCryptoFlContext scc = NULL;
  const SshFastpathCipherDefStruct *cipher_def = NULL;
  const SshFastpathMacDefStruct *mac_def = NULL;

  SshTransformResult result;

  if (tc->with_sw_cipher)
    {
      cipher_def = fastpath_get_cipher_def(trr, transform);
      if (cipher_def == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Requested SW cipher not supported."));
          goto error;
        }
    }

  if (tc->with_sw_mac)
    {
      mac_def = fastpath_get_mac_def(trr, transform);
      if (mac_def == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Requested SW MAC not supported."));
          goto error;
        }
    }

  scc = ssh_malloc(sizeof *scc);
  if (scc == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher context"));
      goto error;
    }

  /* Initialize SW crypto context. */
  scc->cipher_def = cipher_def;
  scc->cipher_context = NULL;
  scc->mac_def = mac_def;
  scc->mac_context = NULL;
  scc->cipher_iv_type = SSH_TRANSFORM_IV_NONE;
  scc->cipher_nonce_size = 0;
  scc->aad_type = SSH_TRANSFORM_AAD_UNUSED;
  scc->is_ah = FALSE;
  scc->packet_iv_len = 0;
  scc->icv_len = 0;

  tc->sw_crypto = scc;

  if (cipher_def != NULL)
    {
      /* Allocate cipher context. */
      result = (*cipher_def->allocate)(cipher_def->name, trr->mykeymat,
                                       trr->cipher_key_size, tc->for_output,
                                       &scc->cipher_context);

      if (result != SSH_TRANSFORM_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cipher initialization failed: %d", result));
          goto error;
        }
    }

  if (mac_def != NULL)
    {
      /* Allocate MAC context. */
      result = (*mac_def->allocate)(mac_def->name,
                                  trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                                  trr->mac_key_size, &scc->mac_context);

      if (result != SSH_TRANSFORM_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC initialization failed: %d", result));
          goto error;
        }
    }

  /* Determine cipher block length, ICV length and AAD type. */

  if (scc->cipher_def != NULL)
    {
      tc->cipher_block_len = (SshUInt8) scc->cipher_def->block_len;
      tc->icv_len = (SshUInt8) scc->cipher_def->icv_len;

      /* Copy nonce existing at the end of the key material. */
      if (scc->cipher_def->nonce_size > 0)
        {
          memcpy(scc->cipher_nonce, trr->mykeymat + trr->cipher_key_size,
                 scc->cipher_def->nonce_size);
          scc->cipher_nonce_size = scc->cipher_def->nonce_size;
        }

      /* Set counter mode. */
      tc->counter_mode = (scc->cipher_def->counter_mode_on == TRUE) ? 1 : 0;

      /* Set IV type. */
      if (scc->cipher_def->counter_mode_on == TRUE)
        {
          scc->cipher_iv_type = (scc->cipher_def->combined_mode_on == TRUE) ?
            SSH_TRANSFORM_IV_CTR : SSH_TRANSFORM_IV_CTR_WITH_ONE;
        }
      else
        {
          scc->cipher_iv_type = SSH_TRANSFORM_IV_CBC;
        }

#ifdef SSH_IPSEC_AH
      if (transform & SSH_PM_IPSEC_AH)
        {
          tc->icv_len += tc->cipher_iv_len;
        }
      else
#endif /* SSH_IPSEC_AH */
        {
          if (scc->cipher_def->aad_required == TRUE)
            {
              if (transform & SSH_PM_IPSEC_LONGSEQ)
                {
                  scc->aad_type = (scc->cipher_def->aad_include_iv == FALSE) ?
                    SSH_TRANSFORM_AAD_WITH_ESN :
                    SSH_TRANSFORM_AAD_WITH_ESN_AND_IV;
                }
              else
                {
                  scc->aad_type = (scc->cipher_def->aad_include_iv == FALSE) ?
                    SSH_TRANSFORM_AAD_DEFAULT : SSH_TRANSFORM_AAD_WITH_IV;
                }
            }
        }
    }
  else
    {
      tc->cipher_block_len = 0;
    }

  if (scc->mac_def != NULL)
    {
      tc->icv_len = scc->mac_def->icv_len;
    }

#ifdef SSH_IPSEC_AH
  if (transform & SSH_PM_IPSEC_AH)
    {
      scc->is_ah = TRUE;

      if (scc->mac_def != NULL)
        {
          scc->icv_len = scc->mac_def->icv_len;
        }
      else
        {
          scc->icv_len = scc->cipher_def->icv_len;
          scc->packet_iv_len = tc->cipher_iv_len;
        }
    }
#endif /* SSH_IPSEC_AH */

  return SSH_TRANSFORM_SUCCESS;

 error:
  transform_crypto_free(tc);

  return SSH_TRANSFORM_FAILURE;
}

void
transform_crypto_free(SshFastpathTransformContext tc)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  tc->sw_crypto = NULL;

  if (scc != NULL)
    {
      if (scc->cipher_def != NULL)
        {
          (*scc->cipher_def->free)(&scc->cipher_context);
        }

      if (scc->mac_def != NULL)
        {
          (*scc->mac_def->free)(&scc->mac_context);
        }

      ssh_free(scc);
    }
}

/* Maximum AAD length. */
#define FASTPATH_TRANSFORM_MAX_AAD_LEN   24

static void
transform_cipher_generate_aad(SshFastpathTransformContext tc,
                              SshUInt32 seq_num_low,
                              SshUInt32 seq_num_high,
                              unsigned char *iv,
                              unsigned int iv_len,
                              unsigned char *aad,
                              unsigned int *aad_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc->aad_type != SSH_TRANSFORM_AAD_UNUSED);

  if (scc->aad_type == SSH_TRANSFORM_AAD_DEFAULT)
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_low);
      *aad_len = 8;
    }
  else if (scc->aad_type == SSH_TRANSFORM_AAD_WITH_ESN)
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_high);
      SSH_PUT_32BIT(aad + 8, seq_num_low);
      *aad_len = 12;
    }
  else if (scc->aad_type == SSH_TRANSFORM_AAD_WITH_IV)
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_low);
      memcpy(aad + 8, iv, iv_len);
      *aad_len = 8 + iv_len;
      SSH_ASSERT(*aad_len <= FASTPATH_TRANSFORM_MAX_AAD_LEN);
    }
  else  /* SSH_TRANSFORM_AAD_WITH_ESN_AND_IV */
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_high);
      SSH_PUT_32BIT(aad + 8, seq_num_low);
      memcpy(aad + 12, iv, iv_len);
      *aad_len = 12 + iv_len;
      SSH_ASSERT(*aad_len <= FASTPATH_TRANSFORM_MAX_AAD_LEN);
    }
}

static SshTransformResult
transform_cipher_start_decrypt(SshFastpathTransformContext tc,
                               SshUInt32 seq_num_low,
                               SshUInt32 seq_num_high,
                               unsigned char *iv,
                               unsigned int iv_len,
                               size_t crypt_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;
  SshTransformResult result;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher_def != NULL);
  SSH_ASSERT(scc->cipher_iv_type != SSH_TRANSFORM_IV_NONE);

  /* Generate IV based on IV type. */
  if (scc->cipher_iv_type == SSH_TRANSFORM_IV_CBC)
    {
      SSH_ASSERT(scc->is_ah == FALSE);

      result = (*scc->cipher_def->start)(scc->cipher_context, iv, iv_len, NULL,
                                         0, crypt_len);
    }
  else
    {
      unsigned char cipher_iv[SSH_CIPHER_MAX_BLOCK_SIZE];
      unsigned int cipher_iv_len;

      memcpy(cipher_iv, scc->cipher_nonce, scc->cipher_nonce_size);
      memcpy(cipher_iv + scc->cipher_nonce_size, iv, iv_len);

      if (scc->cipher_iv_type == SSH_TRANSFORM_IV_CTR)
        {
          cipher_iv_len = scc->cipher_nonce_size + iv_len;
        }
      else
        {
          /* Initialize the last word of the block to 1 for AES CTR. */
          SSH_PUT_32BIT(cipher_iv + scc->cipher_nonce_size + iv_len, 1);

          cipher_iv_len = scc->cipher_nonce_size + iv_len + 4;
        }

      /* Start decryption. */
      if (scc->aad_type != SSH_TRANSFORM_AAD_UNUSED)
        {
          unsigned char aad[FASTPATH_TRANSFORM_MAX_AAD_LEN];
          unsigned int aad_len;

          /* Generate AAD. */
          transform_cipher_generate_aad(tc, seq_num_low, seq_num_high, iv,
                                        iv_len, aad, &aad_len);

          result = (*scc->cipher_def->start)(scc->cipher_context, cipher_iv,
                                             cipher_iv_len, aad, aad_len,
                                             crypt_len);
        }
      else
        {
          result = (*scc->cipher_def->start)(scc->cipher_context, cipher_iv,
                                             cipher_iv_len, NULL, 0,
                                             crypt_len);
        }
    }

  return result;
}

static SshTransformResult
transform_cipher_start_encrypt(SshFastpathTransformContext tc,
                               SshUInt32 seq_num_low,
                               SshUInt32 seq_num_high,
                               size_t crypt_len,
                               unsigned char *iv,
                               unsigned int iv_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;
  SshTransformResult result;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher_def != NULL);
  SSH_ASSERT(scc->cipher_iv_type != SSH_TRANSFORM_IV_NONE);

  /* Start encryption based on IV type. */
  if (scc->cipher_iv_type == SSH_TRANSFORM_IV_CBC)
    {
      unsigned char zero_iv[SSH_CIPHER_MAX_BLOCK_SIZE] = { 0 };
      /* Don't clear nonce block because extra bytes may give some
         additional randomness. */
      unsigned char nonce_block[SSH_CIPHER_MAX_BLOCK_SIZE];

      SSH_ASSERT(scc->cipher_def->block_len == iv_len);
      SSH_ASSERT(scc->cipher_def->combined_mode_on == FALSE);
      SSH_ASSERT(scc->is_ah == FALSE);

      /* Start encryption by using zero IV. */
      result = (*scc->cipher_def->start)(scc->cipher_context, zero_iv, iv_len,
                                         NULL, 0, 0);

      if (result == SSH_TRANSFORM_SUCCESS)
        {
          /* Set unique nonce block by using sequence numbers. */
          SSH_PUT_32BIT(nonce_block, seq_num_low);
          SSH_PUT_32BIT(nonce_block + 4, seq_num_high);

          /* Generate IV for cipher by encrypting nonce block.
             This same IV will be copied into packet. */
          result = (*scc->cipher_def->transform)(scc->cipher_context, iv,
                                                 nonce_block, iv_len);
        }
    }
  else
    {
      unsigned char cipher_iv[SSH_CIPHER_MAX_BLOCK_SIZE];
      unsigned int cipher_iv_len;

      SSH_ASSERT(iv_len == 8);

      memcpy(cipher_iv, scc->cipher_nonce, scc->cipher_nonce_size);
      SSH_PUT_32BIT(cipher_iv + scc->cipher_nonce_size, seq_num_low);
      SSH_PUT_32BIT(cipher_iv + scc->cipher_nonce_size + 4, seq_num_high);

      if (scc->cipher_iv_type == SSH_TRANSFORM_IV_CTR)
        {
          cipher_iv_len = scc->cipher_nonce_size + iv_len;
        }
      else
        {
          /* Initialize the last word of the block to 1 for AES CTR. */
          SSH_PUT_32BIT(cipher_iv + scc->cipher_nonce_size + iv_len, 1);
          cipher_iv_len = scc->cipher_nonce_size + iv_len + 4;
        }

      /* Save IV which will be copied into packet. */
      memcpy(iv, cipher_iv + scc->cipher_nonce_size, iv_len);

      /* Start encryption. */
      if (scc->aad_type != SSH_TRANSFORM_AAD_UNUSED)
        {
          unsigned char aad[FASTPATH_TRANSFORM_MAX_AAD_LEN];
          unsigned int aad_len;

          /* Generate AAD. */
          transform_cipher_generate_aad(tc, seq_num_low, seq_num_high, iv,
                                        iv_len, aad, &aad_len);

          result = (*scc->cipher_def->start)(scc->cipher_context, cipher_iv,
                                             cipher_iv_len, aad, aad_len,
                                             crypt_len);
        }
      else
        {
          /* Start encryption. */
          result = (*scc->cipher_def->start)(scc->cipher_context, cipher_iv,
                                             cipher_iv_len, NULL, 0,
                                             crypt_len);
        }
    }

  return result;
}

/* Public functions used with ESP. */

SshTransformResult
transform_esp_cipher_start_encrypt(SshFastpathTransformContext tc,
                                   SshUInt32 seq_num_low,
                                   SshUInt32 seq_num_high,
                                   size_t crypt_len,
                                   unsigned char *iv,
                                   unsigned int iv_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher_def != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  return transform_cipher_start_encrypt(tc, seq_num_low, seq_num_high,
                                        crypt_len, iv, iv_len);
}

SshTransformResult
transform_esp_cipher_start_decrypt(SshFastpathTransformContext tc,
                                   SshUInt32 seq_num_low,
                                   SshUInt32 seq_num_high,
                                   unsigned char *iv,
                                   unsigned int iv_len,
                                   size_t crypt_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher_def != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  return transform_cipher_start_decrypt(tc, seq_num_low, seq_num_high, iv,
                                        iv_len, crypt_len);
}

SshTransformResult
transform_esp_cipher_update(SshFastpathTransformContext tc,
                            unsigned char *dest,
                            const unsigned char *src,
                            size_t len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher_def != NULL);

  return (*scc->cipher_def->transform)(scc->cipher_context, dest, src, len);
}

SshTransformResult
transform_esp_cipher_update_remaining(SshFastpathTransformContext tc,
                                      unsigned char *dest,
                                      const unsigned char *src,
                                      size_t len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher_def != NULL);

  return (*scc->cipher_def->transform)(scc->cipher_context,dest, src, len);
}

void
transform_esp_mac_start(SshFastpathTransformContext tc)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->mac_def != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  (*scc->mac_def->start)(scc->mac_context);
}

SshTransformResult
transform_esp_mac_update(SshFastpathTransformContext tc,
                         const unsigned char * buf,
                         size_t len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->mac_def != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  return (*scc->mac_def->update)(scc->mac_context, buf, len);
}

SshTransformResult
transform_esp_icv_result(SshFastpathTransformContext tc,
                         unsigned char *icv,
                         unsigned char icv_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);

  if (scc->mac_def != NULL)
    {
      return (*scc->mac_def->result)(scc->mac_context, icv, icv_len);
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);

      return (*scc->cipher_def->result)(scc->cipher_context, icv, icv_len);
    }
}

SshTransformResult
transform_esp_icv_verify(SshFastpathTransformContext tc,
                         unsigned char *icv,
                         unsigned char icv_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);

  if (scc->mac_def != NULL)
    {
      return (*scc->mac_def->verify)(scc->mac_context, icv, icv_len);
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);

      return (*scc->cipher_def->verify)(scc->cipher_context, icv, icv_len);
    }
}

#ifdef SSH_IPSEC_AH

/* Public functions used with AH. */

SshTransformResult
transform_ah_start_computation(SshFastpathTransformContext tc,
                               SshUInt32 seq_num_low,
                               SshUInt32 seq_num_high)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac_def != NULL)
    {
      (*scc->mac_def->start)(scc->mac_context);

      return SSH_TRANSFORM_SUCCESS;
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);
      SSH_ASSERT(scc->packet_iv_len == 8);

      return transform_cipher_start_encrypt(tc, seq_num_low, seq_num_high, 0,
                                            scc->packet_iv,
                                            scc->packet_iv_len);
    }
}

SshTransformResult
transform_ah_result(SshFastpathTransformContext tc,
                    unsigned char *icv,
                    unsigned int icv_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);
  SSH_ASSERT(tc->icv_len == icv_len);

  if (scc->mac_def != NULL)
    {
      return (*scc->mac_def->result)(scc->mac_context, icv, icv_len);
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);
      SSH_ASSERT(scc->packet_iv_len == 8);

      /* Copy generated IV at the beginning of ICV buffer. */
      memcpy(icv, scc->packet_iv, scc->packet_iv_len);

      /* Adjust ICV pointer and get ICV result. */
      icv += scc->packet_iv_len;

      return (*scc->cipher_def->result)(scc->cipher_context, icv,
                                        scc->icv_len);
    }
}

SshTransformResult
transform_ah_start_verify(SshFastpathTransformContext tc,
                          unsigned char *icv,
                          unsigned int icv_len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);
  SSH_ASSERT(tc->icv_len == icv_len);

  if (scc->mac_def != NULL)
    {
      (*scc->mac_def->start)(scc->mac_context);

      /* Copy ICV used in final verify operation. */
      memcpy(scc->icv, icv, icv_len);

      return SSH_TRANSFORM_SUCCESS;
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);
      SSH_ASSERT(scc->packet_iv_len == 8);

      /* Copy ICV part used in final verify operation. */
      memcpy(scc->icv, icv + scc->packet_iv_len, scc->icv_len);

      /* Start decryption. In AES-GMAC case IV is at the beginning of
         ICV buffer. */
      return transform_cipher_start_decrypt(tc, 0, 0, icv, scc->packet_iv_len,
                                            0);
    }
}

SshTransformResult
transform_ah_verify(SshFastpathTransformContext tc)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac_def != NULL)
    {
      return (*scc->mac_def->verify)(scc->mac_context, scc->icv, scc->icv_len);
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);

      return (*scc->cipher_def->verify)(scc->cipher_context, scc->icv,
                                        scc->icv_len);
    }
}

SshTransformResult
transform_ah_update(SshFastpathTransformContext tc,
                    const unsigned char *buf,
                    size_t len)
{
  SshTransformSwCryptoFlContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac_def != NULL)
    {
      return (*scc->mac_def->update)(scc->mac_context, buf, len);
    }
  else
    {
      SSH_ASSERT(scc->cipher_def->combined_mode_on == TRUE);

      return (*scc->cipher_def->update)(scc->cipher_context, buf, len);
    }
}

#endif /* SSH_IPSEC_AH */



/**************************** FL cipher operations **************************/

/* Key length of DES3 algorithm */
#define FL_CIPHER_DES3_KEY_LEN 24

/* FL Cipher Context used for all FL algorithms */
typedef struct {
  /* Cipher algorithm */
  FL_Algorithm_t algorithm;
  /* Key asset */
  FL_KeyAsset_t key_asset;
  /* State asset */
  FL_AnyAsset_t state;
  /* Tag length (Used only for AES-GCM) */
  size_t tag_len;
} FlFastpathCipherContext;

static SshTransformResult
fl_fastpath_aes_check_key_len(size_t key_len)
{
  /* Check key length */
  if (key_len == 16 || key_len == 24 || key_len == 32)
    {
      return SSH_TRANSFORM_SUCCESS;
    }
  else
    {
      return SSH_TRANSFORM_FAILURE;
    }
}

static void
fl_fastpath_cipher_free_asset(FL_AnyAsset_t *asset)
{
  FL_RV rv;

  rv = FL_AssetCheck(*asset, FL_CHECK_EXISTS);
  if (rv == FLR_OK)
    {
      SSH_FL_ASSETFREE(*asset);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to free nonexisting asset"));
    }

  *asset = FL_ASSET_INVALID;
}

static SshTransformResult
fl_fastpath_cipher_allocate(void **context,
                            FL_Algorithm_t algorithm,
                            const unsigned char *key,
                            size_t key_len,
                            size_t tag_len)

{
  FlFastpathCipherContext *cipher_ctx = NULL;
  FL_PolicySmallBits_t policy_bits;
  FL_KeyAsset_t key_asset;
  FL_AnyAsset_t state;
  FL_RV rv;

  *context = NULL;
  cipher_ctx = ssh_calloc(1, sizeof(FlFastpathCipherContext));
  if (cipher_ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to allocate memory for cipher context."));
      return SSH_TRANSFORM_FAILURE;
    }

  /* Set algorithm specific policy bits. */
  switch (algorithm)
    {
    case FL_ALGO_CBC_DES3_ENCRYPT:
      policy_bits = FL_POLICY_ALGO_CBC_DES3_ENCRYPT;
      break;
    case FL_ALGO_CBC_DES3_DECRYPT:
      policy_bits = FL_POLICY_ALGO_CBC_DES3_DECRYPT;
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
      ssh_free(cipher_ctx);
      return SSH_TRANSFORM_FAILURE;
    }

  /* Create asset object for key. */
  SSH_FL_ASSETALLOCATEBASIC(rv, policy_bits, key_len, &key_asset);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetAllocateBasic failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      ssh_free(cipher_ctx);

      return SSH_TRANSFORM_FAILURE;
    }

  /* Load key to asset object. */
  rv = FL_AssetLoadValue(key_asset, key, key_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetLoadValue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      fl_fastpath_cipher_free_asset(&key_asset);
      ssh_free(cipher_ctx);

      return SSH_TRANSFORM_FAILURE;
    }

  /* Acquire state for storing intermediate values */
  SSH_FL_ALLOCATE_STATE(rv, &state);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_ALLOCATE_STATE failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      fl_fastpath_cipher_free_asset(&key_asset);
      ssh_free(cipher_ctx);

      return SSH_TRANSFORM_FAILURE;
    }

  /* Store algorithm and assets to context. */
  cipher_ctx->algorithm = algorithm;
  cipher_ctx->key_asset = key_asset;
  cipher_ctx->state = state;
  cipher_ctx->tag_len = tag_len;

  *context = cipher_ctx;

  return SSH_TRANSFORM_SUCCESS;
}

static void
fl_fastpath_cipher_free(void **cipher_context)
{
  FlFastpathCipherContext *cipher_ctx = *cipher_context;

  if (cipher_ctx != NULL)
    {
      /* Free state asset object */
      fl_fastpath_cipher_free_asset(&cipher_ctx->state);

      /* Free key asset object */
      fl_fastpath_cipher_free_asset(&cipher_ctx->key_asset);
      ssh_free(cipher_ctx);
    }

  *cipher_context = NULL;
}

static SshTransformResult
fl_fastpath_cipher_start(void *cipher_context,
                         const unsigned char *iv,
                         size_t iv_len,
                         const unsigned char *aad,
                         size_t aad_len,
                         size_t crypt_len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_context != NULL);

  /* Start cipher processing */
  rv = FL_CipherInit(cipher_ctx->key_asset, cipher_ctx->state,
                     cipher_ctx->algorithm, iv, iv_len);

  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CipherInit failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_auth_start(void *cipher_context,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *aad,
                              size_t aad_len,
                              size_t crypt_len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_context != NULL);

  /* Start cipher processing */
  rv = FL_CryptAuthInit(cipher_ctx->key_asset, cipher_ctx->state,
                        cipher_ctx->algorithm, iv, iv_len, aad, aad_len,
                        crypt_len, cipher_ctx->tag_len);

  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthInit failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_gmac_auth_start(void *cipher_context,
                                   const unsigned char *iv,
                                   size_t iv_len,
                                   const unsigned char *aad,
                                   size_t aad_len,
                                   size_t crypt_len)
{

  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_context != NULL);

  /* Start cipher processing */
  rv = FL_CryptAuthInit(cipher_ctx->key_asset, cipher_ctx->state,
                        cipher_ctx->algorithm, iv, iv_len, NULL, 0,
                        crypt_len, cipher_ctx->tag_len);

  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthInit failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  rv = FL_CryptGcmAadContinue(cipher_ctx->state, aad, aad_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptGcmAadContinue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_gmac_auth_update(void *cipher_context,
                                    const unsigned char *buf,
                                    size_t len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_ctx != NULL);
  SSH_DEBUG(SSH_D_FAIL, ("update:"));

  rv = FL_CryptGcmAadContinue(cipher_ctx->state, buf, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptGcmAadContinue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_auth_result(void *cipher_context,
                               unsigned char *icv,
                               size_t icv_len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(icv_len == cipher_ctx->tag_len);

  /* Check algorithm */
  if (cipher_ctx->algorithm != FL_ALGO_GCM_AES_ENCRYPT &&
      cipher_ctx->algorithm != FL_ALGO_CCM_AES_ENCRYPT)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Finish cipher processing */
  rv = FL_EncryptAuthFinish(cipher_ctx->state, icv, icv_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("EncryptAuthFinish failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;

}

static SshTransformResult
fl_fastpath_cipher_auth_verify(void *cipher_context,
                               unsigned char *icv,
                               size_t icv_len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  /* Check algorithm */
  if (cipher_ctx->algorithm != FL_ALGO_GCM_AES_DECRYPT &&
      cipher_ctx->algorithm != FL_ALGO_CCM_AES_DECRYPT)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Finish cipher processing */
  rv = FL_DecryptAuthFinish(cipher_ctx->state, icv, cipher_ctx->tag_len);
  if (rv == FLR_OK)
    {
      return SSH_TRANSFORM_SUCCESS;
    }
  else if (rv == FLR_VERIFY_MISMATCH)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_DecryptAuthFinish failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));

      return SSH_TRANSFORM_FAILURE;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_DecryptAuthFinish failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));

      SSH_VERIFY(fl_fastpath_is_lib_functional());

      return SSH_TRANSFORM_FAILURE;
    }
}

static SshTransformResult
fl_fastpath_cipher_transform(void *cipher_context,
                             unsigned char *dest,
                             const unsigned char *src,
                             size_t len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_ctx != NULL);

  /* Continue cipher processing */
  rv = FL_CipherContinue(cipher_ctx->state, src, dest, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CipherContinue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_auth_transform(void *cipher_context,
                                  unsigned char *dest,
                                  const unsigned char *src,
                                  size_t len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_ctx != NULL);

  /* Continue cipher processing */
  rv = FL_CryptAuthContinue(cipher_ctx->state, src, dest, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptAuthContinue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_gmac_auth_transform(void *cipher_context,
                                       unsigned char *dest,
                                       const unsigned char *src,
                                       size_t len)
{
  FlFastpathCipherContext *cipher_ctx = cipher_context;
  FL_RV rv;

  SSH_ASSERT(cipher_ctx != NULL);

  rv = FL_CryptGcmAadContinue(cipher_ctx->state, src, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_CryptGcmAadContinue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  if (dest != src) memcpy(dest, src, len);

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_cipher_des3_cbc_allocate(const char *name,
                                     const unsigned char *key,
                                     size_t key_len,
                                     Boolean for_encryption,
                                     void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Check key length */
  if (key_len < FL_CIPHER_DES3_KEY_LEN)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CBC_DES3_ENCRYPT : FL_ALGO_CBC_DES3_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     FL_CIPHER_DES3_KEY_LEN, 0);
}

static SshTransformResult
fl_fastpath_cipher_aes_cbc_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Check key length */
  if (fl_fastpath_aes_check_key_len(key_len) == SSH_TRANSFORM_FAILURE)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CBC_AES_ENCRYPT : FL_ALGO_CBC_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key, key_len,
                                     0);
}

static SshTransformResult
fl_fastpath_cipher_aes_ctr_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p)
{
  /* Check key length */
  if (fl_fastpath_aes_check_key_len(key_len) == SSH_TRANSFORM_FAILURE)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return fl_fastpath_cipher_allocate(cipher_context_p, FL_ALGO_CTR128_AES, key,
                                     key_len, 0);
}

static SshTransformResult
fl_fastpath_cipher_aes_gcm_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_GCM_AES_ENCRYPT : FL_ALGO_GCM_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     key_len, 16);

}

static SshTransformResult
fl_fastpath_cipher_aes_gcm_8_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_GCM_AES_ENCRYPT : FL_ALGO_GCM_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     key_len, 8);

}

static SshTransformResult
fl_fastpath_cipher_aes_gcm_12_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_GCM_AES_ENCRYPT : FL_ALGO_GCM_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     key_len, 12);

}

static SshTransformResult
fl_fastpath_cipher_aes_ccm_allocate(const char *name,
                                    const unsigned char *key,
                                    size_t key_len,
                                    Boolean for_encryption,
                                    void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CCM_AES_ENCRYPT : FL_ALGO_CCM_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     key_len, 16);

}

static SshTransformResult
fl_fastpath_cipher_aes_ccm_8_allocate(const char *name,
                                      const unsigned char *key,
                                      size_t key_len,
                                      Boolean for_encryption,
                                      void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CCM_AES_ENCRYPT : FL_ALGO_CCM_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     key_len, 8);

}

static SshTransformResult
fl_fastpath_cipher_aes_ccm_12_allocate(const char *name,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption,
                                       void **cipher_context_p)
{
  FL_Algorithm_t algorithm;

  /* Resolve algorithm and init context. */
  algorithm = (for_encryption == TRUE) ?
    FL_ALGO_CCM_AES_ENCRYPT : FL_ALGO_CCM_AES_DECRYPT;

  return fl_fastpath_cipher_allocate(cipher_context_p, algorithm, key,
                                     key_len, 12);

}

/* ******************************* MAC ************************************* */

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

} FlFastpathMacContext;

static void
fl_fastpath_hmac_free_asset(FL_AnyAsset_t *asset)
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

static SshTransformResult
fl_fastpath_hmac_create_key_asset(FL_MacAlgorithm_t algorithm,
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
    case FL_ALGO_HMAC_SHA2_512:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA2_512 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    case FL_ALGO_HMAC_SHA2_384:
      policy_bits = FL_POLICY_ALGO_HMAC_SHA2_384 | FL_POLICY_ALGO_MAC_GENERATE;
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported algorithm: %d", algorithm));
      return SSH_TRANSFORM_FAILURE;
    }

  /* Create asset object for key. */
  SSH_FL_ASSETALLOCATEBASIC(rv, policy_bits, key_len, key_asset_p);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetAllocateBasic failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      return SSH_TRANSFORM_FAILURE;
    }

  /* Load key to asset object. */
  rv = FL_AssetLoadValue(*key_asset_p, key, key_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_AssetLoadValue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      /* Free key asset object */
      fl_fastpath_hmac_free_asset(key_asset_p);

      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_hmac_init(void **context,
                      FL_MacAlgorithm_t algorithm,
                      const unsigned char *key,
                      size_t key_len,
                      size_t mac_len)
{
  FlFastpathMacContext *hmac_ctx;
  FL_KeyAsset_t key_asset;
  SshTransformResult status;

  *context = NULL;
  hmac_ctx = ssh_calloc(1, sizeof(FlFastpathMacContext));
  if (hmac_ctx == NULL)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Create key asset. */
  status = fl_fastpath_hmac_create_key_asset(algorithm, key, key_len,
                                             &key_asset);
  if (status != SSH_TRANSFORM_SUCCESS)
    {
      ssh_free(hmac_ctx);
    }
  else
    {
      /* Save algorithm, MAC length and key asset. */
      hmac_ctx->algorithm = algorithm;
      hmac_ctx->mac_len = mac_len;
      hmac_ctx->key_asset = key_asset;
      hmac_ctx->state = FL_ASSET_INVALID;

      *context = hmac_ctx;
    }

  return status;
}

static SshTransformResult
fl_fastpath_hmac_sha1_96_init(const char *name,
                              const unsigned char *key,
                              size_t key_len, void **context)
{
  return fl_fastpath_hmac_init(context, FL_ALGO_HMAC_SHA1, key, key_len, 12);
}

static SshTransformResult
fl_fastpath_hmac_sha256_128_init(const char *name,
                                 const unsigned char *key,
                                 size_t key_len, void **context)
{
  return fl_fastpath_hmac_init(context, FL_ALGO_HMAC_SHA2_256, key, key_len,
                               16);
}

static SshTransformResult
fl_fastpath_hmac_sha384_192_init(const char *name,
                                 const unsigned char *key,
                                 size_t key_len, void **context)
{
  return fl_fastpath_hmac_init(context, FL_ALGO_HMAC_SHA2_384, key, key_len,
                               24);
}

static SshTransformResult
fl_fastpath_hmac_sha512_256_init(const char *name,
                                 const unsigned char *key,
                                 size_t key_len, void **context)
{
  return fl_fastpath_hmac_init(context, FL_ALGO_HMAC_SHA2_512, key, key_len,
                                32);
}

static void
fl_fastpath_hmac_uninit(void **context)
{
  FlFastpathMacContext *hmac_ctx = *context;

  if (hmac_ctx == NULL)
    return;

  /* Free state object. */
  fl_fastpath_hmac_free_asset(&hmac_ctx->state);

  /* Free key asset object. */
  fl_fastpath_hmac_free_asset(&hmac_ctx->key_asset);

  ssh_free(*context);
  *context = NULL;
}

static void
fl_fastpath_hmac_start(void *context)
{
  FlFastpathMacContext *hmac_ctx = context;
  FL_RV rv;

  /* Free state object. */
  fl_fastpath_hmac_free_asset(&hmac_ctx->state);

  /* Acquire state for storing intermediate values */
  SSH_FL_ALLOCATE_STATE(rv, &hmac_ctx->state);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_ALLOCATE_STATE failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return;
    }

  /* Start MAC processing */
  rv = FL_MacGenerateInit(hmac_ctx->key_asset, hmac_ctx->state,
                          hmac_ctx->algorithm, NULL, 0);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_MacGenerateInit failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      /* Free state object. */
      fl_fastpath_hmac_free_asset(&hmac_ctx->state);
      return;
    }
}

static SshTransformResult
fl_fastpath_hmac_update(void *context,
                        const unsigned char *buf,
                        size_t len)
{
  FlFastpathMacContext *hmac_ctx = context;
  FL_RV rv;

  /* Continue MAC processing */
  rv = FL_MacGenerateContinue(hmac_ctx->state, buf, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_MacGenerateContinue failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_hmac_result(void *context,
                        unsigned char *icv,
                        size_t icv_len)
{
  FlFastpathMacContext *hmac_ctx = context;
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  FL_RV rv;

  /* Finish MAC processing */
  rv = FL_MacGenerateFinish(hmac_ctx->state, icv_result, hmac_ctx->mac_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_MacGenerateFinish failed: %s (%d)",
                             fl_fastpath_rv_to_string(rv), rv));
      SSH_VERIFY(fl_fastpath_is_lib_functional());

      return SSH_TRANSFORM_FAILURE;
    }

  /* Copy result. */
  memcpy(icv, icv_result, icv_len);

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
fl_fastpath_hmac_verify(void *context,
                        const unsigned char *icv,
                        size_t icv_len)
{
  unsigned char l_icv[SSH_MAX_HASH_DIGEST_LENGTH];

  if (fl_fastpath_hmac_result(context, l_icv, icv_len)
      != SSH_TRANSFORM_SUCCESS)
    return SSH_TRANSFORM_FAILURE;

  if (memcmp(icv, l_icv, icv_len) != 0)
    return SSH_TRANSFORM_FAILURE;

  return SSH_TRANSFORM_SUCCESS;
}


/* *************************** FL XCBC MAC ********************************* */
/* This implementation is based on the one in toolkit library (xcbc-mac.c) */

#define FL_MAC_XCBC_BLOCK_LENGTH 16

/* Generic CBC-MAC interface code. */
typedef struct
{
  /* key material. */
  unsigned char key2[FL_MAC_XCBC_BLOCK_LENGTH];
  unsigned char key3[FL_MAC_XCBC_BLOCK_LENGTH];

  /* holds the intermediate mac value, and any necessary buffering when the
   input data is not a multiple of the cipher block length. */
  unsigned char iv[FL_MAC_XCBC_BLOCK_LENGTH];
  unsigned char block[FL_MAC_XCBC_BLOCK_LENGTH];

  /* indicates position in the block buffer. */
  unsigned int counter;

  /* Error status */
  SshTransformResult status;

  /* cipher context. */
  void *fl_ciph_ctx;
} FlFastpathXCBCMacCtx;


static SshTransformResult
fl_fastpath_aes_xcbc_mac(void *fl_ciph_ctx, const unsigned char *src,
                         size_t len, unsigned char *iv_arg)
{
  unsigned char temp[16];
  SshTransformResult status = SSH_TRANSFORM_SUCCESS;

  /* Length is multiple of AES blocksize */
  SSH_ASSERT(len % 16 == 0);
  SSH_ASSERT(len != 0);

  fl_fastpath_cipher_start(fl_ciph_ctx, iv_arg, FL_MAC_XCBC_BLOCK_LENGTH,
                           NULL, 0, 0);

  /* Operate cbc step by step as we only need the last block */
  while (len > 0)
    {
      status = fl_fastpath_cipher_transform(fl_ciph_ctx, temp, src, 16);

      if (status != SSH_TRANSFORM_SUCCESS)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed FL AES-XCBC MAC AES transform"));
          goto end;
        }

      src += 16;
      len -= 16;
    }

  /* copy the iv out */
  memcpy(iv_arg, temp, 16);
  memset(temp, 0, sizeof(temp));

 end:
  return status;
}

static SshTransformResult
fl_fastpath_mac_xcbc_aes_init(const char *name,
                              const unsigned char *key,
                              size_t keylen, void **context)
{
  FlFastpathXCBCMacCtx *created = NULL;
  unsigned char iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  unsigned char key1[SSH_CIPHER_MAX_BLOCK_SIZE];
  SshTransformResult status;

  *context = NULL;
  /* Allocate memory for context. */
  created = ssh_calloc(1, sizeof(FlFastpathXCBCMacCtx));
  if (created == NULL)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Initialize status and counter. */
  created->status = SSH_TRANSFORM_SUCCESS;
  created->counter = 0;

  /* Set initial values for keys. */
  memset(key1,          0x01, FL_MAC_XCBC_BLOCK_LENGTH);
  memset(created->key2, 0x02, FL_MAC_XCBC_BLOCK_LENGTH);
  memset(created->key3, 0x03, FL_MAC_XCBC_BLOCK_LENGTH);

  /* Allocate and initialize the cipher context */
  status = fl_fastpath_cipher_aes_cbc_allocate(name, key, keylen, TRUE,
                                               &created->fl_ciph_ctx);

  if (status != SSH_TRANSFORM_SUCCESS)
    goto error;

  /* Now compute the keys 'key1', 'key2' and 'key3' by encrypting with
     the base key. We can use the CBC mac to encrypt, as it is equivalent
     to standard encryption for a single block (providing the iv is zero). */
  memset(iv, 0, FL_MAC_XCBC_BLOCK_LENGTH);
  status = fl_fastpath_aes_xcbc_mac(created->fl_ciph_ctx, key1,
                                    FL_MAC_XCBC_BLOCK_LENGTH, iv);

  if (status != SSH_TRANSFORM_SUCCESS)
    goto error;

  /* Set key1 to the '0x0101010..'  block encrypted under key. */
  memcpy(key1, iv, FL_MAC_XCBC_BLOCK_LENGTH);

  /* Clean the iv */
  memset(iv, 0, FL_MAC_XCBC_BLOCK_LENGTH);
  status = fl_fastpath_aes_xcbc_mac(created->fl_ciph_ctx, created->key2,
                                    FL_MAC_XCBC_BLOCK_LENGTH, iv);

  if (status != SSH_TRANSFORM_SUCCESS)
    goto error;

  /* Set key2 to the '0x0202020..'  block encrypted under key. */
  memcpy(created->key2, iv, FL_MAC_XCBC_BLOCK_LENGTH);

  /* Clean the iv */
  memset(iv, 0, FL_MAC_XCBC_BLOCK_LENGTH);
  status = fl_fastpath_aes_xcbc_mac(created->fl_ciph_ctx, created->key3,
                                    FL_MAC_XCBC_BLOCK_LENGTH, iv);

  if (status != SSH_TRANSFORM_SUCCESS)
    goto error;

  /* Set key3 to the '0x0303030..'  block encrypted under key. */
  memcpy(created->key3, iv, FL_MAC_XCBC_BLOCK_LENGTH);

  /* Clean the iv and free cipher context */
  fl_fastpath_cipher_free(&created->fl_ciph_ctx);
  memset(iv, 0, FL_MAC_XCBC_BLOCK_LENGTH);

  /* Reallocate and rekey the cipher using the key 'key1' */
  status = fl_fastpath_cipher_aes_cbc_allocate(name, key1, keylen, TRUE,
                                               &created->fl_ciph_ctx);

  if (status != SSH_TRANSFORM_SUCCESS)
    goto error;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("FL XCBC Mac initialized OK"));

  *context = created;
  return status;

 error:
  if (created->fl_ciph_ctx != NULL)
    fl_fastpath_cipher_free(&created->fl_ciph_ctx);
  ssh_free(created);
  return status;
}

void fl_fastpath_mac_xcbc_start(void *context)
{
  FlFastpathXCBCMacCtx *ctx = context;

  /* Initialize counter */
  ctx->counter = 0;

  /* Clear iv and block. */
  memset(ctx->iv, 0, sizeof(ctx->iv));
  memset(ctx->block, 0, sizeof(ctx->block));

  return;
}

static SshTransformResult
fl_fastpath_mac_xcbc_update(void *context,
                            const unsigned char *buf,
                            size_t len)
{
  FlFastpathXCBCMacCtx *ctx = context;
  unsigned int i, j;
  unsigned char *iv, *block;
  SshTransformResult status;
  const int block_length = FL_MAC_XCBC_BLOCK_LENGTH;

  SSH_ASSERT(block_length != 0);

  iv = ctx->iv;
  block = ctx->block;

  SSH_DEBUG(SSH_D_MY, ("In FL XCBC update"));

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
        return SSH_TRANSFORM_FAILURE;

      /* If no more input bytes, return. */
      if (len - i == 0)
        return SSH_TRANSFORM_FAILURE;
    }
  else
    {
      /* If no more input bytes, return. */
      if (!len)
        return SSH_TRANSFORM_FAILURE;
    }

   /* mac the single block 'block' */
  status = fl_fastpath_aes_xcbc_mac(ctx->fl_ciph_ctx, block, block_length, iv);

  if (status != SSH_TRANSFORM_SUCCESS)
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
       status = fl_fastpath_aes_xcbc_mac(ctx->fl_ciph_ctx, buf + i,
                                         len - i - j, iv);

       if (status != SSH_TRANSFORM_SUCCESS)
         ctx->status = status;
     }

  memcpy(block, buf + (len - j), j);

  return SSH_TRANSFORM_FAILURE;
}

SshTransformResult
fl_fastpath_mac_xcbc_aes_96_result(void *context,
                            unsigned char *icv,
                            size_t icv_len)
{
  FlFastpathXCBCMacCtx *ctx = context;
  SshTransformResult status;
  unsigned char *block, *iv;
  unsigned int i;

  SSH_DEBUG(SSH_D_MY, ("In FL XCBC result"));

  if (ctx->status != SSH_TRANSFORM_SUCCESS)
    return ctx->status;

  iv = ctx->iv;
  block = ctx->block;

  if (ctx->counter < FL_MAC_XCBC_BLOCK_LENGTH)
    {
      /* the last block is not full or we are mac'ing the empty string,
         so need to pad with "10000..." */
      block[ctx->counter] = 0x80;
      for (i = ctx->counter + 1; i < FL_MAC_XCBC_BLOCK_LENGTH; i++)
        block[i] = 0;

      /* xor with key3 */
      for (i = 0; i < FL_MAC_XCBC_BLOCK_LENGTH; i++)
        block[i] ^= ctx->key3[i];
    }
  else
    {
      /* the last block is full, no padding required  */
      for (i = 0; i < FL_MAC_XCBC_BLOCK_LENGTH; i++)
        block[i] ^= ctx->key2[i];  /* xor with key2 */
    }

  status = fl_fastpath_aes_xcbc_mac(ctx->fl_ciph_ctx, block,
                                    FL_MAC_XCBC_BLOCK_LENGTH, iv);

  /* take only the first 96 bits */
  memcpy(icv, iv, 12);
  return status;
}

static SshTransformResult
fl_fastpath_mac_xcbc_verify(void *context,
                            const unsigned char *icv,
                            size_t icv_len)
{
  unsigned char l_icv[SSH_MAX_HASH_DIGEST_LENGTH];

  if (fl_fastpath_mac_xcbc_aes_96_result(context, l_icv, icv_len)
      != SSH_TRANSFORM_SUCCESS)
    return SSH_TRANSFORM_FAILURE;

  if (memcmp(icv, l_icv, icv_len) != 0)
    return SSH_TRANSFORM_FAILURE;

  return SSH_TRANSFORM_SUCCESS;
}


static void
fl_fastpath_mac_xcbc_aes_uninit(void **context)
{
  FlFastpathXCBCMacCtx *ctx = *context;

  if (ctx == NULL)
    return;

  fl_fastpath_cipher_free(&ctx->fl_ciph_ctx);

  ssh_free(*context);
  *context = NULL;
}
