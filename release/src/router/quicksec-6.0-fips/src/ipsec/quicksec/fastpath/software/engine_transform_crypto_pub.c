/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements functions declared in engine_transform_crypto.h. This
   implementation uses the ssh crypto API.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#include "fastpath_swi.h"
#include "engine_transform_crypto.h"

#include "sshcipher.h"
#include "sshmac.h"


#define SSH_DEBUG_MODULE "SshEngineFastpathTransformCryptoPublic"


static const unsigned char *
fastpath_get_cipher_info(
        SshEngineTransformRun trr,
        SshPmTransform transform,
        SshUInt8 *cipher_block_len,
        SshUInt8 *cipher_nonce_size,
        Boolean *cipher_counter_mode)
{
  const char *cipher_type = NULL;

  *cipher_block_len = 0;
  *cipher_nonce_size = 0;
  *cipher_counter_mode = FALSE;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_RIJNDAEL is undefined */
    }
#ifdef SSHDIST_CRYPT_RIJNDAEL
  else if (transform & SSH_PM_CRYPT_AES)
    {
      cipher_type = "aes-cbc";
      *cipher_block_len = 16;

      SSH_ASSERT(trr->cipher_key_size);
    }
  else if (transform & SSH_PM_CRYPT_AES_CTR)
    {
      cipher_type = "aes-ctr";
      *cipher_block_len = 16;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
#ifdef SSHDIST_CRYPT_MODE_GCM
  else if (transform & SSH_PM_CRYPT_AES_GCM)
    {
      cipher_type = "aes-gcm";
      *cipher_block_len = 16;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_8)
    {
      cipher_type = "aes-gcm-8";
      *cipher_block_len = 16;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_AES_GCM_12)
    {
      cipher_type = "aes-gcm-12";
      *cipher_block_len = 16;
      *cipher_nonce_size = 4;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 4);
    }
  else if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
    {
      cipher_type = "gmac-aes";
      *cipher_block_len = 16;
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
      cipher_type = "aes-ccm";
      *cipher_block_len = 16;
      *cipher_nonce_size = 3;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_8)
    {
      cipher_type = "aes-ccm-8";
      *cipher_block_len = 16;
      *cipher_nonce_size = 3;
      *cipher_counter_mode = TRUE;

      SSH_ASSERT(trr->cipher_key_size);
      SSH_ASSERT(trr->cipher_iv_size == 8);
      SSH_ASSERT(trr->cipher_nonce_size == 3);
    }
  else if (transform & SSH_PM_CRYPT_AES_CCM_12)
    {
      cipher_type = "aes-ccm-12";
      *cipher_block_len = 16;
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
      cipher_type = "3des-cbc";
      *cipher_block_len = 8;

      SSH_ASSERT(trr->cipher_key_size == 24);
    }
  else if (transform & SSH_PM_CRYPT_DES)
    {
      cipher_type = "des-cbc";
      *cipher_block_len = 8;

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

  return  (const unsigned char *) cipher_type;
}


static const unsigned char *
fastpath_get_mac_type(SshEngineTransformRun trr,
                      SshPmTransform transform)
{
  const char * mac_type = NULL;

  if (0)
    {
      /* To avoid the case where SSHDIST_CRYPT_MD5 is undefined */
    }
#ifdef SSHDIST_CRYPT_MD5
  else if (transform & SSH_PM_MAC_HMAC_MD5)
    {
      mac_type = "hmac-md5-96";
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  else if (transform & SSH_PM_MAC_HMAC_SHA1)
    {
      mac_type = "hmac-sha1-96";
      SSH_ASSERT(trr->mac_key_size == 20);
    }
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 32)
    {
      mac_type = "hmac-sha256-128";
    }
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 48)
    {
      mac_type = "hmac-sha384-192";
    }
  else if ((transform & SSH_PM_MAC_HMAC_SHA2) &&
           trr->mac_key_size == 64)
    {
      mac_type = "hmac-sha512-256";
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
      mac_type = "xcbcmac-aes-96";
      SSH_ASSERT(trr->mac_key_size == 16);
    }
#endif /* SSHDIST_CRYPT_RIJNDAEL */
#endif /* SSHDIST_CRYPT_XCBCMAC */
  else if (transform & SSH_PM_MAC_EXT1)
    {
      ssh_warning("EXT1 MAC not yet supported");
    }
  else if (transform & SSH_PM_MAC_EXT2)
    {
      ssh_warning("EXT2 MAC not yet supported");
    }
  else
    {
      /* No MAC configured. */
      SSH_ASSERT(trr->mac_key_size == 0);
    }

  return (const unsigned char *) mac_type;
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

typedef struct SshTransformSwCryptoPubContextRec
{
  /* Initialization vector for cipher. */
  SshCipher cipher;
  SshMac    mac;

  /* TRUE, when counter mode cipher algorithm used. */
  Boolean cipher_counter_mode;

  /* The cipher nonce for counter mode ciphers. */
  unsigned char cipher_nonce[FASTPATH_TRANSFORM_MAX_NONCE_LEN];
  SshUInt8 cipher_nonce_size;

  /* AAD type, if combined mode cipher is used. */
  SshTransformAadType aad_type;

  /* TRUE, if AH in use. */
  Boolean   is_ah;

  /* Generated packet IV.
     Used in AH case when selected algorithm is AES-GMAC. */
  unsigned char packet_iv[SSH_CIPHER_MAX_BLOCK_SIZE];
  unsigned int packet_iv_len;

  unsigned char icv[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned int icv_len;

} * SshTransformSwCryptoPubContext;

void
transform_crypto_init(void)
{
#ifdef HAVE_FIPSLIB
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "Using FIPSLib backend for engine transform crypto pub");
#else
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "Using SshCrypto backend for engine transform crypto pub");
#endif /* HAVE_FIPSLIB */
}

SshTransformResult
transform_crypto_alloc(
        SshFastpathTransformContext tc,
        SshEngineTransformRun trr,
        SshPmTransform transform)
{
  SshTransformSwCryptoPubContext scc = NULL;
  const unsigned char * cipher_type = NULL;
  SshUInt8 cipher_block_len = 0;
  SshUInt8 cipher_nonce_size = 0;
  Boolean cipher_counter_mode = FALSE;

  const unsigned char * mac_type = NULL;
  SshCryptoStatus status;

  if (tc->with_sw_cipher)
    {
      cipher_type =
          fastpath_get_cipher_info(
                  trr,
                  transform,
                  &cipher_block_len,
                  &cipher_nonce_size,
                  &cipher_counter_mode);
      if (cipher_type == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Required SW cipher not found."));
          goto error;
        }
    }

  if (tc->with_sw_mac)
    {
      mac_type = fastpath_get_mac_type(trr, transform);
      if (mac_type == NULL)
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

  memset(scc, 0, sizeof *scc);

  tc->sw_crypto = scc;

  if (cipher_type)
    {
      status =
          ssh_cipher_allocate(
                  cipher_type,
                  trr->mykeymat,
                  trr->cipher_key_size,
                  tc->for_output,
                  &scc->cipher);

      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cipher initialization failed: %d",
                     (int) status));
          goto error;
        }
    }

  if (mac_type)
    {
      status =
          ssh_mac_allocate(
                  mac_type,
                  trr->mykeymat + SSH_IPSEC_MAX_ESP_KEY_BITS/8,
                  trr->mac_key_size,
                  &scc->mac);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("MAC initialization failed: %d",
                     (int) status));
          goto error;
        }
    }

  /* Determine cipher block length and MAC digest length. */
  if (scc->cipher)
    {
      SSH_ASSERT(cipher_block_len > 0);

      tc->cipher_block_len = cipher_block_len;

      if (tc->with_sw_auth_cipher)
        {
          tc->icv_len = ssh_cipher_auth_digest_length(cipher_type);

          /* For ESP set AAD type. */
          if (transform & SSH_PM_IPSEC_ESP)
            {
              if (transform & SSH_PM_CRYPT_NULL_AUTH_AES_GMAC)
                {
                  scc->aad_type = (transform & SSH_PM_IPSEC_LONGSEQ) ?
                    SSH_TRANSFORM_AAD_WITH_ESN_AND_IV :
                    SSH_TRANSFORM_AAD_WITH_IV;
                }
              else
                {
                  scc->aad_type = (transform & SSH_PM_IPSEC_LONGSEQ) ?
                    SSH_TRANSFORM_AAD_WITH_ESN : SSH_TRANSFORM_AAD_DEFAULT;
                }
            }
        }

      /* Copy nonce existing at the end of the key material. */
      if (cipher_nonce_size > 0)
        {
          memcpy(
                  scc->cipher_nonce,
                  trr->mykeymat + trr->cipher_key_size,
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
      tc->icv_len = ssh_mac_length(mac_type);
    }

#ifdef SSH_IPSEC_AH
  if (transform & SSH_PM_IPSEC_AH)
    {
      scc->is_ah = TRUE;
      scc->icv_len = tc->icv_len;

      if (tc->with_sw_auth_cipher)
        {
          scc->packet_iv_len = tc->cipher_iv_len;
        }

      if (tc->icv_len != 0)
        {
          tc->icv_len += tc->cipher_iv_len;
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  if (scc != NULL)
    {
      if (scc->cipher != NULL)
        {
          ssh_cipher_free(scc->cipher);
        }

      if (scc->mac)
        {
          ssh_mac_free(scc->mac);
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

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


static SshTransformResult
transform_cipher_start_decypt(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        unsigned char *iv,
        unsigned int iv_len,
        size_t crypt_len)
{
  unsigned char cipher_iv_buf[SSH_CIPHER_MAX_BLOCK_SIZE];
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  unsigned char *cipher_iv;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);
  SSH_ASSERT(iv_len <= SSH_CIPHER_MAX_BLOCK_SIZE);

  /* If using counter mode we need to set the initial counter block
     here, except for CCM with a 3 byte nonce (salt) */
  if (scc->cipher_counter_mode == TRUE)
    {
      memset(cipher_iv_buf, 0, SSH_CIPHER_MAX_BLOCK_SIZE);

      memcpy(cipher_iv_buf, scc->cipher_nonce, scc->cipher_nonce_size);
      memcpy(cipher_iv_buf + scc->cipher_nonce_size, iv, iv_len);

      if (scc->cipher_nonce_size == 4)
        {
          /* Initialize the last word of the block to 1 */
          SSH_PUT_32BIT(cipher_iv_buf + 4 + iv_len, 1);
        }

      cipher_iv = cipher_iv_buf;
    }
  else
    {
      cipher_iv = iv;
    }

  /* Set IV for cipher. */
  status = ssh_cipher_set_iv(scc->cipher, cipher_iv);
  SSH_ASSERT(status == SSH_CRYPTO_OK);

  /* Start decryption. */
  if (tc->with_sw_auth_cipher)
    {
      unsigned char aad_buf[FASTPATH_TRANSFORM_MAX_AAD_LEN];
      unsigned int aad_len;
      unsigned char *aad;

      /* Generate AAD. */
      aad = transform_cipher_generate_aad(tc, seq_num_low, seq_num_high, iv,
                                          iv_len, aad_buf, &aad_len);

      status = ssh_cipher_auth_start(scc->cipher, aad, aad_len, crypt_len);
    }
  else
    {
      status = ssh_cipher_start(scc->cipher);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}

static SshTransformResult
transform_cipher_start_encrypt(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high,
        size_t crypt_len,
        unsigned char *iv,
        unsigned int iv_len)
{
  unsigned char cipher_iv_buf[SSH_CIPHER_MAX_BLOCK_SIZE] = { 0 };
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  /* If using counter mode we need to set the initial counter block
     here, except for CCM with a 3 byte nonce (salt) */
  if (scc->cipher_counter_mode == TRUE)
    {
      unsigned int cipher_iv_len;

      SSH_ASSERT(iv_len == 8);

      memcpy(cipher_iv_buf, scc->cipher_nonce, scc->cipher_nonce_size);
      SSH_PUT_32BIT(cipher_iv_buf + scc->cipher_nonce_size, seq_num_low);
      SSH_PUT_32BIT(cipher_iv_buf + scc->cipher_nonce_size + 4, seq_num_high);

      if (scc->cipher_nonce_size == 4)
        {
          /* Initialize the last word of the block to 1 */
          SSH_PUT_32BIT(cipher_iv_buf + 4 + iv_len, 1);

          cipher_iv_len = 8 + iv_len;
        }
      else
        {
          cipher_iv_len = iv_len + scc->cipher_nonce_size;
        }

      /* Copy IV stored into packet. */
      memcpy(iv, cipher_iv_buf + scc->cipher_nonce_size, cipher_iv_len);

      /* Set IV for cipher. */
      status = ssh_cipher_set_iv(scc->cipher, cipher_iv_buf);
      SSH_ASSERT(status == SSH_CRYPTO_OK);

      /* Start encryption. */
      if (tc->with_sw_auth_cipher)
        {
          unsigned char aad_buf[FASTPATH_TRANSFORM_MAX_AAD_LEN];
          unsigned int aad_len;
          unsigned char *aad;

          /* Generate AAD. */
          aad = transform_cipher_generate_aad(tc, seq_num_low, seq_num_high,
                                              iv, iv_len, aad_buf, &aad_len);

          status = ssh_cipher_auth_start(scc->cipher, aad, aad_len, crypt_len);
        }
      else
        {
          status = ssh_cipher_start(scc->cipher);
        }

      if (status != SSH_CRYPTO_OK)
        {
          return SSH_TRANSFORM_FAILURE;
        }
    }
  else
    {
      /* Don't clear nonce block because extra bytes may give some
         additional randomness. */
      unsigned char nonce_block[SSH_CIPHER_MAX_BLOCK_SIZE];

      SSH_ASSERT(!tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->is_ah == FALSE);

      /* Set zero IV for cipher. */
      status = ssh_cipher_set_iv(scc->cipher, cipher_iv_buf);
      SSH_ASSERT(status == SSH_CRYPTO_OK);

      /* Start encryption. */
      status = ssh_cipher_start(scc->cipher);
      if (status != SSH_CRYPTO_OK)
        {
          return SSH_TRANSFORM_FAILURE;
        }

      /* Set nonce block. */
      SSH_PUT_32BIT(nonce_block, seq_num_low);
      SSH_PUT_32BIT(nonce_block + 4, seq_num_high);

      /* Generate IV for cipher by encrypting nonce block. This same IV
         is returned to the caller and copied into packet. */

      status = ssh_cipher_transform(scc->cipher, iv, nonce_block, iv_len);
      if (status != SSH_CRYPTO_OK)
        {
          return SSH_TRANSFORM_FAILURE;
        }
    }

  return SSH_TRANSFORM_SUCCESS;
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  /* Start encryption. */
  return
      transform_cipher_start_encrypt(
              tc,
              seq_num_low,
              seq_num_high,
              crypt_len,
              iv,
              iv_len);
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  /* Start decryption. */
  return
      transform_cipher_start_decypt(
              tc,
              seq_num_low,
              seq_num_high,
              iv,
              iv_len,
              crypt_len);
}


SshTransformResult
transform_esp_cipher_update(
        SshFastpathTransformContext tc,
        unsigned char *dest,
        const unsigned char *src,
        size_t len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);

  /* Transform the split block in the separate buffer. */
  status = ssh_cipher_transform(scc->cipher, dest, src, len);
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
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->cipher != NULL);

  status = ssh_cipher_transform_remaining(scc->cipher, dest, src, len);

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  return SSH_TRANSFORM_SUCCESS;
}


void
transform_esp_mac_start(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->mac != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  ssh_mac_reset(scc->mac);
}


SshTransformResult
transform_esp_mac_update(
        SshFastpathTransformContext tc,
        const unsigned char * buf,
        size_t len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->mac != NULL);
  SSH_ASSERT(scc->is_ah == FALSE);

  ssh_mac_update(scc->mac, buf, len);

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_icv_result(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned char icv_len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      status = ssh_mac_final(scc->mac, icv_result);
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      status = ssh_cipher_auth_final(scc->cipher, icv_result);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  /* Copy result */
  memcpy(icv, icv_result, icv_len);

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_esp_icv_verify(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned char icv_len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);

  if (scc->mac)
    {
      status = ssh_mac_final(scc->mac, icv_result);
      if (status == SSH_CRYPTO_OK)
        {
          /* check that ICV is the same */
          if (memcmp(icv_result, icv, icv_len) != 0)
            return SSH_TRANSFORM_FAILURE;
        }
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      status = ssh_cipher_auth_final_verify(scc->cipher, icv);
    }

  if (status != SSH_CRYPTO_OK)
    return SSH_TRANSFORM_FAILURE;

  return SSH_TRANSFORM_SUCCESS;
}

#ifdef SSH_IPSEC_AH

/* Public functions used with AH. */

static Boolean
fastpath_ah_result(
        SshTransformSwCryptoPubContext scc,
        unsigned char *icv_result)
{
  SshCryptoStatus status;

  if (scc->mac)
    {
      status = ssh_mac_final(scc->mac, icv_result);
    }
  else
    {
      status = ssh_cipher_auth_final(scc->cipher, icv_result);
    }

  if (status != SSH_CRYPTO_OK)
    {
      return FALSE;
    }

  return TRUE;
}


SshTransformResult
transform_ah_start_computation(
        SshFastpathTransformContext tc,
        SshUInt32 seq_num_low,
        SshUInt32 seq_num_high)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshTransformResult result;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac)
    {
      ssh_mac_reset(scc->mac);

      result = SSH_TRANSFORM_SUCCESS;
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->packet_iv_len == 8);

      /* Start computation. */
      result =
          transform_cipher_start_encrypt(
                  tc,
                  seq_num_low,
                  seq_num_high,
                  0,
                  scc->packet_iv,
                  scc->packet_iv_len);

      if (result == SSH_TRANSFORM_SUCCESS)
        {
          /* In AH case we have to call SSH specific transform
             function without passing any data. This call will
             set the IV to the SSH specific cryptography module
             existing beneath SSH Crypto API. */
          status = ssh_cipher_transform(scc->cipher, NULL, NULL, 0);

          if (status != SSH_CRYPTO_OK)
            {
              result = SSH_TRANSFORM_FAILURE;
            }
        }
    }

  return result;
}


SshTransformResult
transform_ah_result(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned int icv_len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  unsigned char icv_result[SSH_MAX_HASH_DIGEST_LENGTH];

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);
  SSH_ASSERT(tc->icv_len == icv_len);

  if (fastpath_ah_result(scc, icv_result) == FALSE)
    {
      return SSH_TRANSFORM_FAILURE;
    }

  if (scc->mac)
    {
      /* Copy result. */
      memcpy(icv, icv_result, icv_len);
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->packet_iv_len == 8);
      SSH_ASSERT((scc->packet_iv_len + scc->icv_len) == icv_len);

      /* Copy generated IV at the beginning of ICV buffer. */
      memcpy(icv, scc->packet_iv, scc->packet_iv_len);

      /* Adjust ICV pointer and copy ICV result. */
      icv += scc->packet_iv_len;

      /* Copy result. */
      memcpy(icv, icv_result, scc->icv_len);
    }

  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_ah_start_verify(
        SshFastpathTransformContext tc,
        unsigned char *icv,
        unsigned int icv_len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshTransformResult result;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);
  SSH_ASSERT(tc->icv_len == icv_len);

  if (scc->mac)
    {
      ssh_mac_reset(scc->mac);

      /* Copy ICV used in final verify operation. */
      memcpy(scc->icv, icv, icv_len);

      return SSH_TRANSFORM_SUCCESS;
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);
      SSH_ASSERT(scc->packet_iv_len == 8);

      /* Start authenticating cipher operation. In AES-GMAC case IV is at
         the beginning of ICV buffer. */
      result =
          transform_cipher_start_decypt(
                  tc,
                  0,
                  0,
                  icv,
                  scc->packet_iv_len,
                  0);

      if (result == SSH_TRANSFORM_SUCCESS)
        {
          /* In AH case we have to call SSH specific transform
             function without passing any data. This call will set
             the IV to the SSH specific cryptography module existing
             beneath SSH Crypto API. */

          status = ssh_cipher_transform(scc->cipher, NULL, NULL, 0);

          if (status != SSH_CRYPTO_OK)
            {
              return SSH_TRANSFORM_FAILURE;
            }

          /* Copy ICV part used in final verify operation. */
          memcpy(scc->icv, icv + scc->packet_iv_len, scc->icv_len);
        }

      return result;
    }
}


SshTransformResult
transform_ah_verify(
        SshFastpathTransformContext tc)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  status = ssh_cipher_auth_final_verify(scc->cipher, scc->icv);

  if (status != SSH_CRYPTO_OK)
    {
      return SSH_TRANSFORM_FAILURE;
    }
  return SSH_TRANSFORM_SUCCESS;
}


SshTransformResult
transform_ah_update(
        SshFastpathTransformContext tc,
        const unsigned char *buf,
        size_t len)
{
  SshTransformSwCryptoPubContext scc = tc->sw_crypto;
  SshCryptoStatus status;

  SSH_ASSERT(scc != NULL);
  SSH_ASSERT(scc->is_ah == TRUE);

  if (scc->mac)
    {
      ssh_mac_update(scc->mac, buf, len);
    }
  else
    {
      SSH_ASSERT(tc->with_sw_auth_cipher);

      status = ssh_cipher_auth_continue(scc->cipher, buf, len);

      if (status != SSH_CRYPTO_OK)
        {
          return SSH_TRANSFORM_FAILURE;
        }
    }

  return SSH_TRANSFORM_SUCCESS;
}

#endif /* SSH_IPSEC_AH */
