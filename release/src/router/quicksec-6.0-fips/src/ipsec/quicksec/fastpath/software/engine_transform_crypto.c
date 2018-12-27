/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
  Implements functions declared in engine_transform_crypto.h. This
  implementation calls the internal functions of different
  cryptographic algorithms directly passing the generic ssh crypto
  API.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
#include "sshcrypt_i.h"
#endif
#include "hmac.h"
#ifdef SSHDIST_CRYPT_DES
#include "des.h"
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_RIJNDAEL
#include "rijndael.h"
#ifdef SSHDIST_CRYPT_MODE_GCM
#include "mode-gcm.h"
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
#include "mode-ccm.h"
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_MD5
#include "md5.h"
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
#include "sha.h"
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
#include "sha256.h"
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
#include "sha512.h"
#endif /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_XCBCMAC
#include "xcbc-mac.h"
#endif /* SSHDIST_CRYPT_XCBCMAC */

#include "fastpath_swi.h"
#include "engine_transform_crypto.h"


#define SSH_DEBUG_MODULE "SshEngineFastpathTransformCrypto"


#ifdef SSHDIST_CRYPT_DES
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_3des_cbc_def =
  {
    "3des-cbc",
    8, 8, { 24, 24, 24 }, ssh_des3_ctxsize,
    ssh_des3_init, ssh_des3_init_with_key_check,
    ssh_des3_start, ssh_des3_cbc,
    ssh_des3_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_des_cbc_def =
  {
    "des-cbc",
    8, 8, { 8, 8, 8 }, ssh_des_ctxsize,
    ssh_des_init, ssh_des_init_with_key_check,
    ssh_des_start, ssh_des_cbc, ssh_des_uninit,
    FALSE, 0,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
  };
#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_cbc_def =
  {
    "aes-cbc",
    16, 16,
    {16, 16, 16},
    ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_init,
    ssh_rijndael_start,
    ssh_rijndael_cbc, ssh_rijndael_uninit, FALSE, 0, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_ctr_def =
  {
    "aes-ctr",
    1, 16,
    {16, 16, 16},
    ssh_rijndael_ctxsize, ssh_rijndael_init_fb, ssh_rijndael_init_fb,
    ssh_rijndael_start,
    ssh_rijndael_ctr, ssh_rijndael_uninit, FALSE, 0, NULL_FNPTR,
    NULL_FNPTR, NULL_FNPTR, NULL_FNPTR, NULL_FNPTR
  };

#ifdef SSHDIST_CRYPT_MODE_GCM
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_def =
  {
    "aes-gcm",
    1, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    NULL_FNPTR,
    ssh_gcm_transform,
    NULL_FNPTR, TRUE,
    16, ssh_gcm_auth_start,
    ssh_gcm_update,
    ssh_gcm_final, ssh_gcm_final_verify, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_64_def =
  {
    "aes-gcm-8",
    1, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    NULL_FNPTR,
    ssh_gcm_transform,
    NULL_FNPTR, TRUE,
    8,  ssh_gcm_auth_start,
    ssh_gcm_update,
    ssh_gcm_64_final, ssh_gcm_64_final_verify, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_gcm_96_def =
  {
    "aes-gcm-12",
    1, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    NULL_FNPTR,
    ssh_gcm_transform,
    NULL_FNPTR, TRUE,
    12, ssh_gcm_auth_start,
    ssh_gcm_update,
    ssh_gcm_96_final, ssh_gcm_96_final_verify, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_null_auth_aes128_gmac_def =
  {
    "gmac-aes",
    1, 16,
    {16, 16, 16},
#ifdef SSH_IPSEC_SMALL
    ssh_gcm_aes_table_256_ctxsize,
    ssh_gcm_aes_table_256_init, ssh_gcm_aes_table_256_init,
#else /* SSH_IPSEC_SMALL */
    ssh_gcm_aes_table_4k_ctxsize,
    ssh_gcm_aes_table_4k_init, ssh_gcm_aes_table_4k_init,
#endif /* SSH_IPSEC_SMALL */
    NULL_FNPTR,
    ssh_gmac_transform,
    NULL_FNPTR, TRUE,
    16, ssh_gcm_auth_start,
    ssh_gcm_update, ssh_gcm_final, ssh_gcm_final_verify, NULL_FNPTR
  };
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_ccm_def =
  {
    "aes-ccm",
    1, 16,
    {16, 16, 16},
    ssh_ccm_aes_ctxsize,
    ssh_ccm_aes_init, ssh_ccm_aes_init,
    NULL_FNPTR,
    ssh_ccm_transform,
    NULL_FNPTR, TRUE,
    16, ssh_ccm_auth_start,
    ssh_ccm_update, ssh_ccm_final, ssh_ccm_final_verify, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_ccm_64_def =
  {
    "aes-ccm-8",
    1, 16,
    {16, 16, 16},
    ssh_ccm_aes_ctxsize,
    ssh_ccm_64_aes_init, ssh_ccm_64_aes_init,
    NULL_FNPTR,
    ssh_ccm_transform,
    NULL_FNPTR, TRUE,
    8, ssh_ccm_auth_start,
    ssh_ccm_update, ssh_ccm_final, ssh_ccm_final_verify, NULL_FNPTR
  };

SSH_RODATA
const SshCipherDefStruct ssh_fastpath_aes128_ccm_96_def =
  {
    "aes-ccm-12",
    1, 16,
    {16, 16, 16},
    ssh_ccm_aes_ctxsize,
    ssh_ccm_96_aes_init, ssh_ccm_96_aes_init,
    NULL_FNPTR,
    ssh_ccm_transform,
    NULL_FNPTR, TRUE,
    12, ssh_ccm_auth_start,
    ssh_ccm_update, ssh_ccm_final, ssh_ccm_final_verify, NULL_FNPTR
  };
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */

#ifdef SSHDIST_CRYPT_MD5
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_md5_96_def =
  {
    "hmac-md5-96",
    12,
    FALSE,
    &ssh_hash_md5_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_96_final, NULL_FNPTR
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_md5_96_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_md5_96_def, NULL
  };
#endif /* SSHDIST_CRYPT_MD5 */

#ifdef SSHDIST_CRYPT_SHA
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha1_96_def =
  {
    "hmac-sha1-96",
    12,
    FALSE,
    &ssh_hash_sha_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_96_final, NULL_FNPTR
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha1_96_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha1_96_def, NULL
  };
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha256_128_def =
  {
    "hmac-sha256-128",
    16,
    FALSE,
    &ssh_hash_sha256_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_128_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha256_128_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha256_128_def, NULL
  };
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha384_192_def =
  {
    "hmac-sha384-192",
    24,
    FALSE,
    &ssh_hash_sha384_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_192_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha384_192_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha384_192_def, NULL
  };

SSH_RODATA_IN_TEXT
SshHashMacDefStruct ssh_fastpath_hash_hmac_sha512_256_def =
  {
    "hmac-sha512-256",
    32,
    FALSE,
    &ssh_hash_sha512_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update,
    ssh_hmac_256_final, NULL_FNPTR,
    NULL_FNPTR,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_hmac_sha512_256_def =
  {
    TRUE, &ssh_fastpath_hash_hmac_sha512_256_def, NULL
  };
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_XCBCMAC
#ifdef SSHDIST_CRYPT_RIJNDAEL
SSH_RODATA_IN_TEXT
SshCipherMacBaseDefStruct ssh_ciphermac_base_aes_def =
  { 16, ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_uninit,
    ssh_rijndael_cbc_mac };

SSH_RODATA_IN_TEXT
SshCipherMacDefStruct ssh_fastpath_cipher_xcbc_aes_96_def =
  {
    "xcbcmac-aes-96",
    12, { 16, 16, 16 },
    &ssh_ciphermac_base_aes_def,
    ssh_xcbcmac_ctxsize,
    ssh_xcbcmac_init,
    ssh_xcbcmac_uninit,
    ssh_xcbcmac_start,
    ssh_xcbcmac_update,
    ssh_xcbcmac_96_final,
  };

SSH_RODATA_IN_TEXT
SshMacDefStruct ssh_fastpath_xcbc_aes_96_def =
  {
    FALSE, NULL, &ssh_fastpath_cipher_xcbc_aes_96_def
  };
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */

static const SshCipherDefStruct *
fastpath_get_cipher_def(
        SshEngineTransformRun trr,
        SshPmTransform transform,
        SshUInt8 *cipher_nonce_size,
        Boolean *cipher_counter_mode)
{
  const SshCipherDefStruct *cipher;
  cipher = NULL;

  *cipher_nonce_size = 0;
  *cipher_counter_mode = FALSE;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      cipher = &ssh_fastpath_aes128_cbc_def;
      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      cipher = &ssh_fastpath_aes128_ctr_def;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      cipher = &ssh_fastpath_aes128_gcm_def;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      cipher = &ssh_fastpath_aes128_gcm_64_def;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_12)
    {
      cipher = &ssh_fastpath_aes128_gcm_96_def;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      cipher = &ssh_fastpath_null_auth_aes128_gmac_def;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#endif /* SSHDIST_CRYPT_MODE_GCM */
#ifdef SSHDIST_CRYPT_MODE_CCM
  else if (transform & SSH_PM_CRYPT_AES_CCM)
    {
      cipher = &ssh_fastpath_aes128_ccm_def;
      *cipher_nonce_size = 3;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_8)
    {
      cipher = &ssh_fastpath_aes128_ccm_64_def;
      *cipher_nonce_size = 3;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_12)
    {
      cipher = &ssh_fastpath_aes128_ccm_96_def;
      *cipher_nonce_size = 3;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
#endif /* SSHDIST_CRYPT_MODE_CCM */
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#ifdef SSHDIST_CRYPT_DES
  else if (transform & SSH_PM_CRYPT_3DES)
    {
      cipher = &ssh_fastpath_3des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 24);
    }
  else if (transform & SSH_PM_CRYPT_DES)
    {
      cipher = &ssh_fastpath_des_cbc_def;
      SSH_ASSERT(trr->cipher_key_size == 8);
    }
#endif /* SSHDIST_CRYPT_DES */
  else if (transform & SSH_PM_CRYPT_EXT1)
    {
      ssh_warning("EXT1 cipher not configured");
    }
  else if (transform & SSH_PM_CRYPT_EXT2)
    {
      ssh_warning("EXT2 cipher not configured");
    }
  else
    {
      /* No cipher configured. */
      SSH_ASSERT(trr->cipher_key_size == 0);
    }

  return cipher;
}

const SshMacDefStruct * fastpath_get_mac_def(SshEngineTransformRun trr,
                                             SshPmTransform transform)
{
  const SshMacDefStruct *mac;

  mac = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_MD5 is undefined */
    }
#ifdef SSHDIST_CRYPT_MD5
  else if (transform & SSH_PM_MAC_HMAC_MD5)
    {
      mac = &ssh_fastpath_hmac_md5_96_def;
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      mac = &ssh_fastpath_hmac_sha1_96_def;
      SSH_ASSERT(trr->mac_key_size == 20);
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      mac = &ssh_fastpath_hmac_sha256_128_def;
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      mac = &ssh_fastpath_hmac_sha384_192_def;
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      mac = &ssh_fastpath_hmac_sha512_256_def;
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
      mac = &ssh_fastpath_xcbc_aes_96_def;
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

  return mac;
}


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
  SSH_TRANSFORM_AAD_WITH_ESN_AND_IV,

} SshTransformAadType;


#define FASTPATH_TRANSFORM_MAX_NONCE_LEN  4

typedef struct SshTransformSwCryptoContextRec
{
  /* Initialization vector for cipher. */
  unsigned char cipher_iv[SSH_CIPHER_MAX_BLOCK_SIZE];

  /* TRUE, when counter mode cipher algorithm used. */
  Boolean cipher_counter_mode;

  /* The cipher nonce for counter mode ciphers. */
  unsigned char cipher_nonce[FASTPATH_TRANSFORM_MAX_NONCE_LEN];
  SshUInt8 cipher_nonce_size;

  /* Cipher descriptor.  This is NULL if no encryption is to be performed. */
  const SshCipherDefStruct *cipher;

  /* Cipher context, or NULL if encryption is performed by hardware
     acceleration. */
  void *cipher_context;

  /* Mac descriptor. */
  const SshMacDefStruct *mac;

  /* Mac context, or NULL if MAC is performed by hardware acceleration. */
  void *mac_context;

  /* AAD type, if combined mode cipher is used. */
  SshTransformAadType aad_type;

  /* TRUE, if AH in use. */
  Boolean is_ah;

  /* Generated packet IV.
     Used in AH case when selected algorithm is AES-GMAC. */
  unsigned char packet_iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  unsigned int packet_iv_len;

  unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned int icv_len;

} * SshTransformSwCryptoContext;

void
transform_crypto_init(void)
{
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "Using SshCrypto backend for engine transform crypto");
}

SshTransformResult
transform_crypto_alloc(
        SshFastpathTransformContext tc,
        SshEngineTransformRun trr,
        SshPmTransform transform)
{
  SshTransformSwCryptoContext scc = NULL;
  const SshCipherDefStruct * cipher = NULL;
  const SshMacDefStruct * mac = NULL;
  SshUInt8 cipher_nonce_size = 0;
  Boolean cipher_counter_mode = FALSE;

  SshCryptoStatus status;

  if (tc->with_sw_cipher)
    {
      cipher = fastpath_get_cipher_def(trr, transform, &cipher_nonce_size,
                                       &cipher_counter_mode);
      if (cipher == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Required SW cipher not found."));
          goto error;
        }
    }

  if (tc->with_sw_mac)
    {
      mac = fastpath_get_mac_def(trr, transform);
      if (mac == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Required SW mac not found."));
          goto error;
        }
    }

  scc = ssh_malloc(sizeof *scc);
  if (!scc)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher context"));
      goto error;
    }

  memset(scc->cipher_iv, 0, sizeof(scc->cipher_iv));
  scc->cipher_context = NULL;
  scc->mac_context = NULL;
  scc->cipher = cipher;
  scc->mac = mac;
  scc->aad_type = SSH_TRANSFORM_AAD_UNUSED;
  scc->is_ah = FALSE;
  scc->packet_iv_len = 0;
  scc->icv_len = 0;

  tc->sw_crypto = scc;

  if (cipher)
    {
#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
      scc->cipher_context = ssh_crypto_malloc_i((*cipher->ctxsize)());
#else
      scc->cipher_context = ssh_malloc((*cipher->ctxsize)());
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */
      if (!scc->cipher_context)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate cipher context"));
          goto error;
        }

      /* For counter mode encryption is the same as decryption. */
      status = (*cipher->init)(scc->cipher_context,
                               trr->mykeymat, trr->cipher_key_size,
                               tc->for_output);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cipher initialization failed: %d", status));
          goto error;
        }
    }

  if (mac)
    {
#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
      if (mac->hmac)
        scc->mac_context = ssh_crypto_malloc_i(
                             (*mac->hash->ctxsize)(mac->hash->hash_def));
      else
        scc->mac_context = ssh_crypto_malloc_i(
                             (*mac->cipher->ctxsize)(mac->cipher->cipher_def));
#else
      if (mac->hmac)
        scc->mac_context =
          ssh_malloc((*mac->hash->ctxsize)(mac->hash->hash_def));
      else
        scc->mac_context =
          ssh_malloc((*mac->cipher->ctxsize)(mac->cipher->cipher_def));
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */

      if (!scc->mac_context)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate MAC context"));
          goto error;
        }

      if (mac->hmac)
        status =
          (*mac->hash->init)(scc->mac_context,
                             trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                             trr->mac_key_size,
                             mac->hash->hash_def);
      else
        status =
          (*mac->cipher->init)(scc->mac_context,
                               trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                               trr->mac_key_size,
                               mac->cipher->cipher_def);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("MAC initialization failed: %d", status));
          goto error;
        }
    }

  /* Determine cipher block length and MAC digest length. */
  if (scc->cipher)
    {
      tc->cipher_block_len = (SshUInt8) scc->cipher->block_length;

      /* Copy nonce existing at the end of the key material. */
      if (cipher_nonce_size > 0)
        {
          memcpy(scc->cipher_nonce, trr->mykeymat + trr->cipher_key_size,
                 cipher_nonce_size);
          scc->cipher_nonce_size = cipher_nonce_size;
        }

      /* Set counter mode. */
      scc->cipher_counter_mode = cipher_counter_mode;
      tc->counter_mode = (scc->cipher_counter_mode == TRUE) ? 1 : 0;
    }
  else
    {
      tc->cipher_block_len = 0;
    }

  if (scc->mac)
    {
      tc->icv_len = scc->mac->hmac ? scc->mac->hash->digest_length :
        scc->mac->cipher->digest_length;
    }
  else if (scc->cipher && scc->cipher->is_auth_cipher)
    {
#ifdef SSH_IPSEC_AH
      if (transform & SSH_PM_IPSEC_AH)
        {
          tc->icv_len = scc->cipher->digest_length + tc->cipher_iv_len;
        }
      else
#endif /* SSH_IPSEC_AH */
        {
          tc->icv_len = (SshUInt8)scc->cipher->digest_length;

          if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
            {
              scc->aad_type = (transform & SSH_PM_IPSEC_LONGSEQ) ?
                SSH_TRANSFORM_AAD_WITH_ESN_AND_IV : SSH_TRANSFORM_AAD_WITH_IV;
            }
          else
            {
              scc->aad_type = (transform & SSH_PM_IPSEC_LONGSEQ) ?
                SSH_TRANSFORM_AAD_WITH_ESN : SSH_TRANSFORM_AAD_DEFAULT;
            }
        }
    }
  else
    {
      tc->icv_len = 0;
    }

#ifdef SSH_IPSEC_AH
  if (transform & SSH_PM_IPSEC_AH)
    {
      scc->is_ah = TRUE;

      if (scc->mac)
        {
          scc->icv_len = tc->icv_len;
        }
      else if (scc->cipher && scc->cipher->is_auth_cipher)
        {
          scc->icv_len =  scc->cipher->digest_length;
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
transform_crypto_free(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  if (scc != NULL)
    {
      if (scc->cipher_context != NULL)
        {
          if (scc->cipher->uninit)
            (*scc->cipher->uninit)(scc->cipher_context);
#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
          ssh_crypto_free_i(scc->cipher_context);
#else
          ssh_free(scc->cipher_context);
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */
        }

      if (scc->mac_context)
        {
          if (scc->mac->hash && scc->mac->hash->uninit)
            (*scc->mac->hash->uninit)(scc->mac_context);
          else if (scc->mac->cipher && scc->mac->cipher->uninit)
            (*scc->mac->cipher->uninit)(scc->mac_context);

#ifdef HAVE_AES_INTEL_INSTRUCTION_SET
          ssh_crypto_free_i(scc->mac_context);
#else
          ssh_free(scc->mac_context);
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */
        }

      ssh_free(scc);
    }

  tc->sw_crypto = NULL;
}


/* Maximum AAD length. */
#define FASTPATH_TRANSFORM_MAX_AAD_LEN   24

static unsigned char *
transform_cipher_generate_aad(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        unsigned char *iv,
        unsigned int iv_len,
        unsigned char *aad,
        unsigned int *aad_len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  if (scc->aad_type == SSH_TRANSFORM_AAD_UNUSED)
    {
      *aad_len = 0;
      return NULL;
    }
  else if (scc->aad_type == SSH_TRANSFORM_AAD_DEFAULT)
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_low);
      *aad_len = 8;
      return aad;
    }
  else if (scc->aad_type == SSH_TRANSFORM_AAD_WITH_ESN)
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_high);
      SSH_PUT_32BIT(aad + 8, seq_num_low);
      *aad_len = 12;
      return aad;
    }
  else if (scc->aad_type == SSH_TRANSFORM_AAD_WITH_IV)
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_low);
      memcpy(aad + 8, iv, iv_len);
      *aad_len = 8 + iv_len;
      SSH_ASSERT(*aad_len <= FASTPATH_TRANSFORM_MAX_AAD_LEN);
      return aad;
    }
  else  /* SSH_TRANSFORM_AAD_WITH_ESN_AND_IV */
    {
      SSH_PUT_32BIT(aad, tc->esp_spi);
      SSH_PUT_32BIT(aad + 4, seq_num_high);
      SSH_PUT_32BIT(aad + 8, seq_num_low);
      memcpy(aad + 12, iv, iv_len);
      *aad_len = 12 + iv_len;
      SSH_ASSERT(*aad_len <= FASTPATH_TRANSFORM_MAX_AAD_LEN);
      return aad;
    }
}


static void
transform_cipher_set_iv(
        SshFastpathTransformContext tc,
        unsigned char *iv,
        unsigned int iv_len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);
  SSH_ASSERT(iv_len <= SSH_CIPHER_MAX_BLOCK_SIZE);

  /* If using counter mode we need to set the initial counter block
     here, except for CCM with a 3 byte nonce (salt) */
  if (scc->cipher_counter_mode == TRUE)
    {
      memcpy(scc->cipher_iv, scc->cipher_nonce, scc->cipher_nonce_size);
      memcpy(scc->cipher_iv + scc->cipher_nonce_size, iv, iv_len);

      if (scc->cipher_nonce_size == 4)
        {
          /* Initialize the last word of the block to 1 */
          SSH_PUT_32BIT(scc->cipher_iv + 4 + iv_len, 1);
        }
    }
  else
    {
      memcpy(scc->cipher_iv, iv, iv_len);
    }
}


/* Public functions used with ESP. */

SshTransformResult
transform_esp_cipher_start_encrypt(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        size_t crypt_len,
        unsigned char *iv,
        unsigned int iv_len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  if (scc->cipher_counter_mode == TRUE)
    {
      SSH_ASSERT(iv_len == 8);

      /* Form the IV */
      memcpy(scc->cipher_iv, scc->cipher_nonce, scc->cipher_nonce_size);
      SSH_PUT_32BIT(scc->cipher_iv + scc->cipher_nonce_size, seq_num_low);
      SSH_PUT_32BIT(scc->cipher_iv + scc->cipher_nonce_size + 4, seq_num_high);

      /* Set the counter part to 1 for all counter modes except AES-CCM */
      if (scc->cipher_nonce_size == 4)
        {
          /* Initialize the last word of the block to 1 */
          SSH_PUT_32BIT(scc->cipher_iv + 4 + iv_len, 1);
        }

      /* Save IV which will be copied into packet. */
      memcpy(iv, scc->cipher_iv + scc->cipher_nonce_size, iv_len);

      if (tc->with_sw_auth_cipher)
        {
          unsigned char aad_buf[FASTPATH_TRANSFORM_MAX_AAD_LEN];
          unsigned int aad_len;
          unsigned char *aad;

          /* Generate AAD. */
          aad = transform_cipher_generate_aad(tc, seq_num_low, seq_num_high,
                                              iv, iv_len, aad_buf, &aad_len);

          /* Start authenticating cipher. */
          status = (*scc->cipher->auth_start)(scc->cipher_context,
                                              scc->cipher_iv, aad,
                                              aad_len, crypt_len);
        }
      else
        {
          status = (*scc->cipher->start)(scc->cipher_context, scc->cipher_iv);
        }
    }
  else
    {
      /* Don't clear nonce block because extra bytes may give some
         additional randomness. */
      unsigned char nonce_block[SSH_CIPHER_MAX_BLOCK_SIZE];

      SSH_ASSERT(!tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->cipher->block_length == iv_len);

      /* Zero cipher IV. */
      memset(scc->cipher_iv, 0, sizeof(scc->cipher_iv));

      status = (*scc->cipher->start)(scc->cipher_context, scc->cipher_iv);

      if (status != SSH_CRYPTO_OK)
        {
          return SSH_TRANSFORM_FAILURE;
        }

      /* Set nonce block. */
      SSH_PUT_32BIT(nonce_block, seq_num_low);
      SSH_PUT_32BIT(nonce_block + 4, seq_num_high);

      /* Generate IV for cipher by encrypting nonce block as recommended
         in NIST Special Publication 800-38A, Appendix C. */
      status = (*scc->cipher->transform)(scc->cipher_context,
                                         iv,
                                         nonce_block,
                                         iv_len);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_cipher_start_decrypt(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        unsigned char *iv,
        unsigned int iv_len,
        size_t crypt_len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  /* Set IV. */
  transform_cipher_set_iv(tc, iv, iv_len);

  if (tc->with_sw_auth_cipher)
    {
      unsigned char aad_buf[FASTPATH_TRANSFORM_MAX_AAD_LEN];
      unsigned int aad_len;
      unsigned char *aad;

      /* Generate AAD. */
      aad = transform_cipher_generate_aad(tc, seq_num_low, seq_num_high, iv,
                                          iv_len, aad_buf, &aad_len);

      /* Start authenticating cipher. */
      (*scc->cipher->auth_start)(scc->cipher_context, scc->cipher_iv, aad,
                                 aad_len, crypt_len);
    }
  else
    {
      /* Start cipher. */
      (*scc->cipher->start)(scc->cipher_context, scc->cipher_iv);
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_cipher_update(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);

  /* Transform the split block in the separate buffer. */
  status = (*scc->cipher->transform)(scc->cipher_context, dest, src, len);

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_cipher_update_remaining(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len)
{
  return transform_esp_cipher_update(tc, dest, src, len);
}


void
transform_esp_mac_start(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->mac != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  if (scc->mac->hmac)
    {
      (*scc->mac->hash->start)(scc->mac_context);
    }
  else
    {
      (*scc->mac->cipher->start)(scc->mac_context);
    }
}


SshTransformResult
transform_esp_mac_update(
        SshFastpathTransformContext tc,
        const unsigned char * buf,
        size_t len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->mac != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  if (scc->mac->hmac)
    {
      (*scc->mac->hash->update)(scc->mac_context, buf, len);
    }
  else
    {
      (*scc->mac->cipher->update)(scc->mac_context, buf, len);
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_icv_result(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned char icv_len)
{
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(icv_len <= SSH_MAX_HASH_DIGEST_LENGTH);
  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          status = (*scc->mac->hash->final)(scc->mac_context, icv_result);
        }
      else
        {
          status = (*scc->mac->cipher->final)(scc->mac_context, icv_result);
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      status = (*scc->cipher->final)(scc->cipher_context, icv_result);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Copy result. */
  memcpy(icv, icv_result, icv_len);

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_icv_verify(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned char icv_len)
{
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(icv_len <= SSH_MAX_HASH_DIGEST_LENGTH);
  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        status = (*scc->mac->hash->final)(scc->mac_context, icv_result);
      else
        status = (*scc->mac->cipher->final)(scc->mac_context, icv_result);

      /* check that ICV is the same */
      if (status == SSH_CRYPTO_OK)
        if (memcmp(icv_result, icv, icv_len) != 0)
          return SSH_TRANSFORM_FAILURE;
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      status = (*scc->cipher->final_verify)(scc->cipher_context, icv);
    }

  if (status != SSH_CRYPTO_OK)
      return SSH_TRANSFORM_FAILURE;

  return SSH_TRANSFORM_SUCCESS;
}


#ifdef SSH_IPSEC_AH

/* Public functions used with AH. */

SshTransformResult
transform_ah_start_computation(SshFastpathTransformContext tc,
                               SshUInt32 seq_num_low,
                               SshUInt32 seq_num_high)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          (*scc->mac->hash->start)(scc->mac_context);
        }
      else
        {
          (*scc->mac->cipher->start)(scc->mac_context);
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->packet_iv_len == 8);

      /* Form the IV */
      memcpy(scc->cipher_iv, scc->cipher_nonce, scc->cipher_nonce_size);
      SSH_PUT_32BIT(scc->cipher_iv + scc->cipher_nonce_size, seq_num_low);
      SSH_PUT_32BIT(scc->cipher_iv + scc->cipher_nonce_size + 4, seq_num_high);

      if (scc->cipher_nonce_size == 4)
        {
          /* Initialize the last word of the block to 1 */
          SSH_PUT_32BIT(scc->cipher_iv + 4 + scc->packet_iv_len, 1);
        }

      /* Save IV which will be copied into packet. */
      memcpy(scc->packet_iv, scc->cipher_iv + scc->cipher_nonce_size,
             scc->packet_iv_len);

      /* Start authenticating cipher. */
      (*scc->cipher->auth_start)(scc->cipher_context, scc->cipher_iv,
                                 NULL, 0, 0);
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_ah_result(SshFastpathTransformContext tc,
                    unsigned char *icv,
                    unsigned int icv_len)
{
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);
  SSH_ASSERT(tc->icv_len == icv_len);

  if (scc->mac)
    {
      SSH_ASSERT(icv_len <= SSH_MAX_HASH_DIGEST_LENGTH);

      if (scc->mac->hmac)
        {
          status = (*scc->mac->hash->final)(scc->mac_context, icv_result);
        }
      else
        {
          status = (*scc->mac->cipher->final)(scc->mac_context, icv_result);
        }

      if (status == SSH_CRYPTO_OK)
        {
          /* Copy result. */
          memcpy(icv, icv_result, icv_len);

          return SSH_TRANSFORM_SUCCESS;
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->packet_iv_len == 8);
      SSH_ASSERT((scc->packet_iv_len + scc->icv_len) == icv_len);

      status = (*scc->cipher->final)(scc->cipher_context, icv_result);

      if (status == SSH_CRYPTO_OK)
        {
          /* Copy generated IV at the beginning of ICV buffer. */
          memcpy(icv, scc->packet_iv, scc->packet_iv_len);

          /* Adjust ICV pointer and get ICV result. */
          icv += scc->packet_iv_len;

          /* Copy result. */
          memcpy(icv, icv_result, scc->icv_len);

          return SSH_TRANSFORM_SUCCESS;
        }
    }

  return SSH_TRANSFORM_FAILURE;
}


SshTransformResult
transform_ah_start_verify(SshFastpathTransformContext tc,
                          unsigned char *icv,
                          unsigned int icv_len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);
  SSH_ASSERT(tc->icv_len == icv_len);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          (*scc->mac->hash->start)(scc->mac_context);
        }
      else
        {
          (*scc->mac->cipher->start)(scc->mac_context);
        }

      /* Copy ICV used in final verify operation. */
      memcpy(scc->icv, icv, icv_len);

      return SSH_TRANSFORM_SUCCESS;
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->packet_iv_len == 8);

      /* Set IV. In AES-GMAC case it is at the beginning of ICV buffer. */
      transform_cipher_set_iv(tc, icv, scc->packet_iv_len);

      /* Copy ICV part used in final verify operation. */
      memcpy(scc->icv, icv + scc->packet_iv_len, scc->icv_len);

      /* Start authenticating cipher. */
      (*scc->cipher->auth_start)(scc->cipher_context, scc->cipher_iv,
                                 NULL, 0, 0);

      return SSH_TRANSFORM_SUCCESS;
    }
}


SshTransformResult
transform_ah_verify(SshFastpathTransformContext tc)
{
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  SshTransformSwCryptoContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        status = (*scc->mac->hash->final)(scc->mac_context, icv_result);
      else
        status = (*scc->mac->cipher->final)(scc->mac_context, icv_result);

      /* check that ICV is the same */
      if (status == SSH_CRYPTO_OK)
        if (memcmp(scc->icv, icv_result, scc->icv_len) != 0)
          return SSH_TRANSFORM_FAILURE;

    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      status = (*scc->cipher->final_verify)(scc->cipher_context, scc->icv);
    }

  if (status != SSH_CRYPTO_OK)
    return SSH_TRANSFORM_FAILURE;

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_ah_update(SshFastpathTransformContext tc,
                    const unsigned char *buf,
                    size_t len)
{
  SshTransformSwCryptoContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac)
    {
      if (scc->mac->hmac)
        {
          (*scc->mac->hash->update)(scc->mac_context, buf, len);
        }
      else
        {
          (*scc->mac->cipher->update)(scc->mac_context, buf, len);
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      (*scc->cipher->update)(scc->cipher_context, buf, len);
    }

  return SSH_TRANSFORM_SUCCESS;
}

#endif /* SSH_IPSEC_AH */
