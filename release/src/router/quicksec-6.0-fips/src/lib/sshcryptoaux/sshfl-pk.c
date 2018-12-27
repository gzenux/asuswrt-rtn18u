/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshfl.h"

#include "fl.h"

#include "fl_sign_raw.h"

#define SSH_DEBUG_MODULE "SshCryptoAuxFlPk"

/* *********************** Key generation ***************************** */

typedef struct SshFlKeyContextRec
{
  FL_KeyAsset_t keyAsset;
  unsigned int signature_len;
} *SshFlKeyContext, SshFlKeyContextStruct;

void ssh_fl_private_key_free(void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;

  SSH_FL_ASSETFREE(key_context->keyAsset);

  ssh_free(key_context);

  return;
}

void ssh_fl_public_key_free(void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;

  SSH_FL_ASSETFREE(key_context->keyAsset);

  ssh_free(key_context);

  return;
}

void *ssh_fl_rsa_private_key_make(unsigned char *p_buf,
                                  size_t p_size,
                                  unsigned char *q_buf,
                                  size_t q_size,
                                  unsigned char *dp_buf,
                                  size_t dp_size,
                                  unsigned char *dq_buf,
                                  size_t dq_size,
                                  unsigned char *q_inv_buf,
                                  size_t q_inv_size,
                                  unsigned int key_size_in_bits)
{
  SshFlKeyContext key_context = NULL;
  size_t key_asset_size;
  unsigned char *key_asset_buffer = NULL;
  SshUInt32 modulus_bitlen;
  FL_RV fl_rv;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  key_context = ssh_malloc(sizeof (SshFlKeyContextStruct));

  if (key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  switch (key_size_in_bits)
    {
    case 1024:
      key_asset_size = sizeof(FL_RSAPrivateKey1024_t);
      break;
    case 2048:
      key_asset_size = sizeof(FL_RSAPrivateKey2048_t);
      break;
    case 3072:
      key_asset_size = sizeof(FL_RSAPrivateKey3072_t);
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Invalid RSA private key size: %u",
                             key_size_in_bits));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(key_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  key_context->signature_len = key_size_in_bits / 8;

  SSH_FL_ASSETALLOCATE(fl_rv,
                       FL_POLICY_ALGO_RSA_PKCS1V1_5_SIGN |
                       FL_POLICY_MASK_HASH,
                       key_asset_size,
                       0,
                       &key_context->keyAsset);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */

  modulus_bitlen = key_size_in_bits;

  memset(key_asset_buffer, 0x00, key_asset_size);

  if (sizeof(SshUInt32) + p_size + q_size + dp_size + dq_size + q_inv_size
      < key_asset_size)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid key parameters"));
      goto fail;
    }

  if (ssh_encode_array(key_asset_buffer, key_asset_size,
                       SSH_FORMAT_DATA, &modulus_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, p_buf, p_size,
                       SSH_FORMAT_DATA, q_buf, q_size,
                       SSH_FORMAT_DATA, dp_buf, dp_size,
                       SSH_FORMAT_DATA, dq_buf, dq_size,
                       SSH_FORMAT_DATA, q_inv_buf, q_inv_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode RSA key asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(key_context->keyAsset,
                            key_asset_buffer,
                            key_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  ssh_free(key_asset_buffer);
  return key_context;

 fail:
  ssh_free(key_context);
  ssh_free(key_asset_buffer);
  return NULL;
}

void *ssh_fl_rsa_public_key_make(unsigned char *e_buf,
                                 size_t e_size,
                                 unsigned char *m_buf,
                                 size_t m_size,

                                 unsigned int e_size_in_bits,
                                 unsigned int m_size_in_bits)
{
  SshFlKeyContext key_context = NULL;
  size_t key_asset_size;
  unsigned char *key_asset_buffer = NULL;
  FL_RV fl_rv;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  key_context = ssh_malloc(sizeof (SshFlKeyContextStruct));

  if (key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  switch (m_size_in_bits)
    {
    case 1024:
      key_asset_size = sizeof(FL_RSAPublicKey1024_t);
      break;
    case 2048:
      key_asset_size = sizeof(FL_RSAPublicKey2048_t);
      break;
    case 3072:
      key_asset_size = sizeof(FL_RSAPublicKey3072_t);
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL, ("Invalid RSA public key size: %u",
                             m_size_in_bits));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(key_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  key_context->signature_len = m_size_in_bits / 8;

  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_ALGO_RSA_PKCS1V1_5_SIGN |
                       FL_POLICY_MASK_HASH |
                       FL_POLICY_FLAG_PUBLIC_KEY,
                       key_asset_size,
                       0,
                       &key_context->keyAsset);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */
  SSH_ASSERT(sizeof (SshUInt32) + sizeof (SshUInt32) + e_size + m_size ==
             key_asset_size);

  memset(key_asset_buffer, 0x00, key_asset_size);

  if (ssh_encode_array(key_asset_buffer, key_asset_size,
                       SSH_FORMAT_DATA, &m_size_in_bits, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, &e_size_in_bits, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, e_buf, e_size,
                       SSH_FORMAT_DATA, m_buf, m_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode RSA key asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(key_context->keyAsset,
                            key_asset_buffer,
                            key_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  ssh_free(key_asset_buffer);
  return key_context;

 fail:
  ssh_free(key_context);
  ssh_free(key_asset_buffer);
  return NULL;
}


void *ssh_fl_dsa_private_key_make(unsigned char *p_buf,
                                  size_t p_size,
                                  unsigned char *q_buf,
                                  size_t q_size,
                                  unsigned char *g_buf,
                                  size_t g_size,
                                  unsigned char *x_buf,
                                  size_t x_size,
                                  unsigned int key_size_in_bits)
{
  SshFlKeyContext key_context = NULL;
  size_t key_asset_size;
  unsigned char *key_asset_buffer = NULL;
  SshUInt32 p_bitlen, q_bitlen;
  FL_RV fl_rv;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  key_context = ssh_malloc(sizeof (SshFlKeyContextStruct));

  if (key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  if ((p_size == 128) && (q_size == 20))
    key_asset_size = sizeof(FL_DSAPrivateKey1024_160_t);
  else if ((p_size == 256) && (q_size == 28))
    key_asset_size = sizeof(FL_DSAPrivateKey2048_224_t);
  else if ((p_size == 256) && (q_size == 32))
    key_asset_size = sizeof(FL_DSAPrivateKey2048_256_t);
  else if ((p_size == 384) && (q_size == 32))
    key_asset_size = sizeof(FL_DSAPrivateKey3072_256_t);
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid DSA private key prime size: %u/%u",
                 8 * p_size, 8 * q_size));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(key_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  key_context->signature_len = q_size * 2;

  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_ALGO_DSA_SIGN |
                       FL_POLICY_ALGO_HASH_SHA1,
                       key_asset_size,
                       0,
                       &key_context->keyAsset);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */
  p_bitlen = p_size * 8;
  q_bitlen = q_size * 8;

  memset(key_asset_buffer, 0x00, key_asset_size);

  if (ssh_encode_array(key_asset_buffer, key_asset_size,
                       SSH_FORMAT_DATA, &q_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, &p_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, p_buf, p_size,
                       SSH_FORMAT_DATA, q_buf, q_size,
                       SSH_FORMAT_DATA, g_buf, g_size,
                       SSH_FORMAT_DATA, x_buf, x_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode DSA key asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(key_context->keyAsset,
                            key_asset_buffer,
                            key_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  ssh_free(key_asset_buffer);
  return key_context;

 fail:
  ssh_free(key_context);
  ssh_free(key_asset_buffer);
  return NULL;
}

void *ssh_fl_dsa_public_key_make(unsigned char *p_buf,
                                 size_t p_size,
                                 unsigned char *q_buf,
                                 size_t q_size,
                                 unsigned char *g_buf,
                                 size_t g_size,
                                 unsigned char *y_buf,
                                 size_t y_size)
{
  SshFlKeyContext key_context = NULL;
  size_t key_asset_size;
  unsigned char *key_asset_buffer = NULL;
  SshUInt32 p_bitlen, q_bitlen;
  FL_RV fl_rv;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  key_context = ssh_malloc(sizeof (SshFlKeyContextStruct));

  if (key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  if ((p_size == 128) && (q_size == 20))
    key_asset_size = sizeof(FL_DSAPublicKey1024_160_t);
  else if ((p_size == 256) && (q_size == 28))
    key_asset_size = sizeof(FL_DSAPublicKey2048_224_t);
  else if ((p_size == 256) && (q_size == 32))
    key_asset_size = sizeof(FL_DSAPublicKey2048_256_t);
  else if ((p_size == 384) && (q_size == 32))
    key_asset_size = sizeof(FL_DSAPublicKey3072_256_t);
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid DSA public key prime size: %u/%u",
                 8 * p_size, 8 * q_size));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(key_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  key_context->signature_len = q_size * 2;
  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_ALGO_DSA_SIGN |
                       FL_POLICY_ALGO_HASH_SHA1 |
                       FL_POLICY_FLAG_PUBLIC_KEY,
                       key_asset_size,
                       0,
                       &key_context->keyAsset);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */
  p_bitlen = p_size * 8;
  q_bitlen = q_size * 8;

  memset(key_asset_buffer, 0x00, key_asset_size);

  if (ssh_encode_array(key_asset_buffer, key_asset_size,
                       SSH_FORMAT_DATA, &q_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, &p_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, p_buf, p_size,
                       SSH_FORMAT_DATA, q_buf, q_size,
                       SSH_FORMAT_DATA, g_buf, g_size,
                       SSH_FORMAT_DATA, y_buf, y_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode DSA key asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(key_context->keyAsset,
                            key_asset_buffer,
                            key_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  ssh_free(key_asset_buffer);
  return key_context;

 fail:
  ssh_free(key_context);
  ssh_free(key_asset_buffer);
  return NULL;
}


void *ssh_fl_ecdsa_private_key_make(unsigned char *x_buf,
                                    size_t x_size,
                                    unsigned int key_size_in_bits)
{
  SshFlKeyContext key_context = NULL;
  size_t key_asset_size, signature_len;
  unsigned char *key_asset_buffer = NULL;
  SshUInt32 p_bitlen;
  FL_RV fl_rv;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  key_context = ssh_malloc(sizeof (SshFlKeyContextStruct));

  if (key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  if (key_size_in_bits == 256)
    {
      key_asset_size = sizeof(FL_ECDSAPrivateKey256_t);
      signature_len = 64;
    }
  else if (key_size_in_bits == 384)
    {
      key_asset_size = sizeof(FL_ECDSAPrivateKey384_t);
      signature_len = 96;
    }
  else if (key_size_in_bits == 521)
    {
      key_asset_size = sizeof(FL_ECDSAPrivateKey521_t);
      signature_len = 132;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ECDSA prime key size: %u",
                             key_size_in_bits));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(key_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  key_context->signature_len = signature_len;

  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_ALGO_ECDSA_SIGN |
                           FL_POLICY_MASK_HASH,
                           key_asset_size,
                           FL_POLICY_MASK_ANY,
                           &key_context->keyAsset);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */
  p_bitlen = key_size_in_bits;

  memset(key_asset_buffer, 0x00, key_asset_size);

  if (ssh_encode_array(key_asset_buffer, key_asset_size,
                       SSH_FORMAT_DATA, &p_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, x_buf, x_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode ECDSA key asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(key_context->keyAsset,
                            key_asset_buffer,
                            key_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  ssh_free(key_asset_buffer);
  return key_context;

 fail:
  ssh_free(key_context);
  ssh_free(key_asset_buffer);
  return NULL;
}

void *ssh_fl_ecdsa_public_key_make(unsigned char *qx_buf,
                                   size_t qx_size,
                                   unsigned char *qy_buf,
                                   size_t qy_size,
                                   unsigned int key_size_in_bits)
{
  SshFlKeyContext key_context = NULL;
  size_t key_asset_size, signature_len;
  unsigned char *key_asset_buffer = NULL;
  SshUInt32 p_bitlen;
  FL_RV fl_rv;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  key_context = ssh_malloc(sizeof (SshFlKeyContextStruct));

  if (key_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  if (key_size_in_bits == 256)
    {
      key_asset_size = sizeof(FL_ECDSAPublicKey256_t);
      signature_len = 64;
    }
  else if (key_size_in_bits == 384)
    {
      key_asset_size = sizeof(FL_ECDSAPublicKey384_t);
      signature_len = 96;
    }
  else if (key_size_in_bits == 521)
    {
      key_asset_size = sizeof(FL_ECDSAPublicKey521_t);
      signature_len = 132;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ECDSA prime key size: %u",
                             key_size_in_bits));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(key_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  key_context->signature_len = signature_len;

  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_ALGO_ECDSA_SIGN |
                           FL_POLICY_MASK_HASH |
                           FL_POLICY_FLAG_PUBLIC_KEY,
                           key_asset_size,
                           FL_POLICY_MASK_ANY,
                           &key_context->keyAsset);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */
  p_bitlen = key_size_in_bits;

  memset(key_asset_buffer, 0x00, key_asset_size);

  if (ssh_encode_array(key_asset_buffer, key_asset_size,
                       SSH_FORMAT_DATA, &p_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, qx_buf, qx_size,
                       SSH_FORMAT_DATA, qy_buf, qy_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to encode ECDSA key asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(key_context->keyAsset,
                            key_asset_buffer,
                            key_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  ssh_free(key_asset_buffer);
  return key_context;

 fail:
  ssh_free(key_context);
  ssh_free(key_asset_buffer);
  return NULL;
}



/* *********************** Signing operation ************************** */

size_t
ssh_fl_signature_size(void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;

  return (size_t) key_context->signature_len;
}

static SshCryptoStatus
private_key_sign(SshProxyRGFId rgf_id,
                 const unsigned char *input_data,
                 size_t input_data_len,
                 unsigned char *signature_buffer,
                 size_t signature_buffer_len,
                 void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  FL_AnyAsset_t state;
  FL_RV fl_rv;

  SSH_ASSERT(key_context->signature_len == signature_buffer_len);

  SSH_FL_ALLOCATE_STATE(fl_rv, &state);

  if (fl_rv != FLR_OK)
    return SSH_CRYPTO_NO_MEMORY;

  switch (rgf_id)
    {
    case SSH_RSA_PKCS1_SHA1:
    case SSH_DSA_NIST_SHA1:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA1,
                          input_data,
                          input_data_len);
      break;
    case SSH_RSA_PKCS1_SHA224:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_224,
                          input_data,
                          input_data_len);
      break;
    case SSH_RSA_PKCS1_SHA256:
    case SSH_ECDSA_NIST_SHA256:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_256,
                          input_data,
                          input_data_len);
      break;
    case SSH_RSA_PKCS1_SHA384:
    case SSH_ECDSA_NIST_SHA384:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_384,
                          input_data,
                          input_data_len);
      break;
    case SSH_RSA_PKCS1_SHA512:
    case SSH_ECDSA_NIST_SHA512:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_512,
                          input_data,
                          input_data_len);
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported RGF identifier: %u", rgf_id));
      goto fail;
    }

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashInit: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  memset(signature_buffer, 0x00, signature_buffer_len);

  if (rgf_id == SSH_ECDSA_NIST_SHA512)
    {
      /* Make buffers suitable for 521-bit curve operations */
      unsigned char *output_buffer;
      size_t output_buffer_len;

      SSH_ASSERT(signature_buffer_len == 132);

      output_buffer_len = signature_buffer_len + 4;
      output_buffer = ssh_malloc(output_buffer_len);

      if (output_buffer == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
          return SSH_CRYPTO_NO_MEMORY;
        }

      memset(output_buffer, 0x00, output_buffer_len);

      fl_rv = FL_HashSignFips186(key_context->keyAsset,
                                 state,
                                 output_buffer,
                                 output_buffer_len);

      memcpy(signature_buffer, output_buffer + 2, 66);
      memcpy(signature_buffer + 66, output_buffer + 2 + 66 + 2, 66);

      ssh_free(output_buffer);
    }
  else
    {
      fl_rv = FL_HashSignFips186(key_context->keyAsset,
                                 state,
                                 signature_buffer,
                                 signature_buffer_len);
    }

  if (fl_rv != FLR_OK)
  {
    SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashSignFips186: %s",
                           ssh_fl_rv_to_string(fl_rv)));
    goto fail;
  }

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Created signature:"),
                    signature_buffer, signature_buffer_len);

  SSH_FL_ASSETFREE(state);
  return SSH_CRYPTO_OK;

 fail:
  SSH_FL_ASSETFREE(state);
  return SSH_CRYPTO_OPERATION_FAILED;
}

static SshCryptoStatus
private_key_sign_nohash(SshProxyRGFId rgf_id,
                        const unsigned char *input_data,
                        size_t input_data_len,
                        unsigned char *signature_buffer,
                        size_t signature_buffer_len,
                        void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  FL_AnyAsset_t state;
  FL_Temporary_t temp;
  FL_RV fl_rv;

  SSH_ASSERT(key_context->signature_len == signature_buffer_len);

  /* Set temp value */
  memset(&temp, 0x00, sizeof(temp));

  switch (input_data_len)
    {
    case 20:
      temp.Algo = FL_ALGO_HASH_SHA1;
      break;
    case 28:
      temp.Algo = FL_ALGO_HASH_SHA2_224;
      break;
    case 32:
      temp.Algo = FL_ALGO_HASH_SHA2_256;
      break;
    case 48:
      temp.Algo = FL_ALGO_HASH_SHA2_384;
      break;
    case 64:
      temp.Algo = FL_ALGO_HASH_SHA2_512;
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid input data length: %u",
                 (unsigned int) input_data_len));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  temp.Algo |= FL_ALGO_FLAG_KEEP;
  memcpy(temp.Intermediate.Digest, input_data, input_data_len);

  /* Set state value */
  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_FLAG_TEMPORARY,
                           sizeof(temp),
                           FL_POLICY_MASK_ANY,
                           &state);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      return SSH_CRYPTO_NO_MEMORY;
    }

  fl_rv = FL_AssetLoadValue(state,
                            (FL_DataInPtr_t) &temp,
                            sizeof(temp));

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  memset(signature_buffer, 0x00, signature_buffer_len);

  if ((rgf_id == SSH_ECDSA_NONE_NONE) &&
      (input_data_len == 64))
    {
      /* Make buffers suitable for 521-bit curve operations */
      unsigned char *output_buffer;
      size_t output_buffer_len;

      SSH_ASSERT(signature_buffer_len == 132);

      output_buffer_len = signature_buffer_len + 4;
      output_buffer = ssh_malloc(output_buffer_len);

      if (output_buffer == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
          return SSH_CRYPTO_NO_MEMORY;
        }

      memset(output_buffer, 0x00, output_buffer_len);

      fl_rv = FL_HashSignFips186(key_context->keyAsset,
                                 state,
                                 output_buffer,
                                 output_buffer_len);

      memcpy(signature_buffer, output_buffer + 2, 66);
      memcpy(signature_buffer + 66, output_buffer + 2 + 66 + 2, 66);

      ssh_free(output_buffer);
    }
  else
    {
      fl_rv = FL_HashSignFips186(key_context->keyAsset,
                                 state,
                                 signature_buffer,
                                 signature_buffer_len);
    }

  if (fl_rv != FLR_OK)
  {
    SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashSignFips186: %s",
                           ssh_fl_rv_to_string(fl_rv)));
    goto fail;
  }

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Created signature:"),
                    signature_buffer, signature_buffer_len);

  SSH_FL_ASSETFREE(state);
  return SSH_CRYPTO_OK;

 fail:
  SSH_FL_ASSETFREE(state);
  return SSH_CRYPTO_OPERATION_FAILED;
}


static SshCryptoStatus
rsa_key_sign_raw(const unsigned char *input_data,
                 size_t input_data_len,
                 unsigned char *output_buffer,
                 size_t output_buffer_len,
                 void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
#ifdef SSHDIST_FIPSLIB_1_1
  FL_Temporary_t temp;
  FL_AnyAsset_t state;
  FL_AnyAlgorithm_t alg;
#else
  unsigned char *input_buffer;
  size_t input_buffer_len;
#endif /* SSHDIST_FIPSLIB_1_1 */
  FL_RV fl_rv;

  /* Allow variable length input data ("rsa-pkcs1-none" scheme) */

  /* Check that input data and pkcs1 padding fit into the signature
     buffer. */
  if (input_data_len > output_buffer_len - 3)
    {
      SSH_DEBUG(SSH_D_FAIL,
               ("Invalid input data length %d bytes, expected max %d bytes",
                input_data_len, output_buffer_len - 3));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Output buffer len equals the RSA key size, accept only
     1024, 2048 and 3072 */
  if ((output_buffer_len != 128) &&
      (output_buffer_len != 256) &&
      (output_buffer_len != 384))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid output buffer size %u",
                 output_buffer_len));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

#ifdef SSHDIST_FIPSLIB_1_1
  /* Find out the hash algorithm */
  if (input_data_len == 20)
    {
      alg =  FL_ALGO_HASH_SHA1;
    }
  else if (input_data_len == 32)
    {
      alg =  FL_ALGO_HASH_SHA2_256;
    }
  else if (input_data_len == 48)
    {
      alg =  FL_ALGO_HASH_SHA2_384;
    }
  else if (input_data_len == 64)
    {
      alg =  FL_ALGO_HASH_SHA2_512;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid input data buffer len: %u",
                 input_data_len));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Create state manually */
  memset(&temp, 0, sizeof(temp));
  temp.Algo = alg;
  temp.Algo |= FL_ALGO_FLAG_KEEP;
  if (alg == FL_ALGO_HASH_SHA2_384 || alg == FL_ALGO_HASH_SHA2_512)
    memcpy(temp.Intermediate.HashVars64Bit, input_data, input_data_len);
  else
    memcpy(temp.Intermediate.HashVars32Bit, input_data, input_data_len);

  fl_rv = FL_AssetAllocate(FL_POLICY_FLAG_TEMPORARY, sizeof temp,
                           FL_POLICY_MASK_ANY, &state);

  if (fl_rv == FLR_OK)
    {
      fl_rv = FL_AssetLoadValue(state, (FL_DataInPtr_t) &temp, sizeof temp);

      if (fl_rv == FLR_OK)
        {
          fl_rv = FL_HashSignPkcs1(key_context->keyAsset,
                                   state,
                                   output_buffer,
                                   0,
                                   output_buffer,
                                   output_buffer_len);
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unable to load FL asset value."));
        }

      FL_AssetFree(state);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to allocate FL asset."));
    }

#else /* SSHDIST_FIPSLIB_1_1 */

  input_buffer = ssh_malloc(output_buffer_len);
  input_buffer_len = output_buffer_len;

  if (input_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory"));
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Manual RAW pkcs1 padding */
  memset(input_buffer, 0x00, input_buffer_len);
  input_buffer[1] = 0x01;
  memset(input_buffer + 2, 0xff,
        input_buffer_len - input_data_len - 3);
  memcpy(input_buffer + input_buffer_len - input_data_len, input_data,
        input_data_len);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Buffer to be RSA-signed"),
                    input_buffer, input_buffer_len);

  fl_rv = FL_Util_DecryptRawRSA(key_context->keyAsset,
                                input_buffer,
                                input_buffer_len,
                                output_buffer,
                                output_buffer_len);

  ssh_free(input_buffer);
#endif /* SSHDIST_FIPSLIB_1_1 */

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_DecryptRawRSA(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      return SSH_CRYPTO_OPERATION_FAILED;
    }
  else
    {
      SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("RSA signature:"),
                        output_buffer, output_buffer_len);
      return SSH_CRYPTO_OK;
    }
}

SshCryptoStatus
ssh_fl_private_key_sign(SshProxyOperationId operation_id,
                        SshProxyRGFId rgf_id,
                        const unsigned char *input_data,
                        size_t input_data_len,
                        unsigned char *output_buffer,
                        size_t output_buffer_len,
                        void *context)
{
  SshCryptoStatus status;

  if ((operation_id != SSH_RSA_PRV_SIGN) &&
      (operation_id != SSH_DSA_PRV_SIGN) &&
      (operation_id != SSH_ECDSA_PRV_SIGN))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unhandled operation id: %u",
                             operation_id));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  switch (rgf_id)
    {
    case SSH_RSA_PKCS1_SHA1:
    case SSH_RSA_PKCS1_SHA224:
    case SSH_RSA_PKCS1_SHA256:
    case SSH_RSA_PKCS1_SHA384:
    case SSH_RSA_PKCS1_SHA512:
    case SSH_DSA_NIST_SHA1:
    case SSH_ECDSA_NIST_SHA224:
    case SSH_ECDSA_NIST_SHA256:
    case SSH_ECDSA_NIST_SHA384:
    case SSH_ECDSA_NIST_SHA512:
      status = private_key_sign(rgf_id,
                                input_data, input_data_len,
                                output_buffer, output_buffer_len,
                                context);
      break;
    case SSH_RSA_PKCS1_NONE:
      status = rsa_key_sign_raw(input_data, input_data_len,
                                output_buffer, output_buffer_len,
                                context);
      break;
    case SSH_DSA_NONE_NONE:
    case SSH_ECDSA_NONE_NONE:
      status = private_key_sign_nohash(rgf_id,
                                       input_data, input_data_len,
                                       output_buffer, output_buffer_len,
                                       context);
      break;
    default:
      status = SSH_CRYPTO_UNSUPPORTED;
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported RGF identifier: %u", rgf_id));
    }

  return status;
}

/* *********************** Verify operation ************************** */

static const FL_Data_t encoded_sha_oid[] =
{
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
  0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static const FL_Data_t encoded_sha_noparams_oid[] =
{
  0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e,
  0x03, 0x02, 0x1a, 0x04, 0x14
};

static const FL_Data_t encoded_sha256_oid[] =
{
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20
};

static const FL_Data_t encoded_sha256_noparams_oid[] =
{
  0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04,
  0x20
};

static const FL_Data_t encoded_sha384_oid[] =
{
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
  0x00, 0x04, 0x30
};

static const FL_Data_t encoded_sha384_noparams_oid[] =
{
  0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04,
  0x30
};

static const FL_Data_t encoded_sha512_oid[] =
{
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
  0x00, 0x04, 0x40
};

static const FL_Data_t encoded_sha512_noparams_oid[] =
{
  0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04,
  0x40
};


typedef struct Pkcs1HashAlgsRec {
  FL_AnyAlgorithm_t alg;
  const FL_Data_t *oid;
  size_t encoded_oid_len;
} *Pkcs1HashAlgs, Pkcs1HashAlgsStruct;


Pkcs1HashAlgsStruct implicit_pkcs1_hash_algs[] =
  {
    { FL_ALGO_HASH_SHA1, encoded_sha_oid,
      sizeof(encoded_sha_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA1, encoded_sha_noparams_oid,
      sizeof(encoded_sha_noparams_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA2_256, encoded_sha256_oid,
      sizeof(encoded_sha256_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA2_256, encoded_sha256_noparams_oid,
      sizeof(encoded_sha256_noparams_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA2_384, encoded_sha384_oid,
      sizeof(encoded_sha384_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA2_384, encoded_sha384_noparams_oid,
      sizeof(encoded_sha384_noparams_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA2_512, encoded_sha512_oid,
      sizeof(encoded_sha512_oid) / sizeof(FL_Data_t) },
    { FL_ALGO_HASH_SHA2_512, encoded_sha512_noparams_oid,
      sizeof(encoded_sha512_noparams_oid) / sizeof(FL_Data_t) },
    { 0, NULL}
};

static FL_AnyAlgorithm_t restricted_pkcs1_hash_algs[] = {
  FL_ALGO_HASH_SHA1
};

static unsigned int num_restricted_pkcs1_hash_algs =
  sizeof (restricted_pkcs1_hash_algs) / sizeof (FL_AnyAlgorithm_t);

static Boolean
restricted_signature_algorithm(FL_AnyAlgorithm_t alg)
{
  unsigned int i;

  for (i = 0; i < num_restricted_pkcs1_hash_algs; i++)
    {
      if (alg == restricted_pkcs1_hash_algs[i])
        return TRUE;
    }

  return FALSE;
}

static SshCryptoStatus
public_key_implicit_pkcs1_verify(SshProxyRGFId rgf_id,
                                 const unsigned char *input_data,
                                 size_t input_data_len,
                                 unsigned char *signature_data,
                                 size_t signature_data_len,
                                 void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  FL_AnyAsset_t state;
  FL_RV fl_rv;
  SshCryptoStatus rv = SSH_CRYPTO_OK;
  unsigned int i;

  SSH_ASSERT(key_context->signature_len == signature_data_len);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK,
                    ("Starting implicit pkcs1 verify operation, signature:"),
                    signature_data, signature_data_len);

  /* FIPS library does not support implicit selection of the hash algorithm, so
     we have to iterate through the options. */
  for (i = 0; implicit_pkcs1_hash_algs[i].oid != NULL; i++)
    {
      /* Check if NIST-800-131a restrictions should be applied. */
      if (rgf_id == SSH_RSA_PKCS1_RESTRICTED &&
          restricted_signature_algorithm(implicit_pkcs1_hash_algs[i].alg)
          == TRUE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Implicit PKCS1 verify with hash id %u not considered",
                     (unsigned int) implicit_pkcs1_hash_algs[i].alg));
          rv = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
          continue;
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Attempting implicit PKCS1 verify with hash id %u",
                     (unsigned int) implicit_pkcs1_hash_algs[i].alg));
        }

      SSH_FL_ALLOCATE_STATE(fl_rv, &state);

      if (fl_rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed FL_ALLOCATE_STATE: %s",
                                 ssh_fl_rv_to_string(fl_rv)));
          goto fail;
        }

      fl_rv = FL_HashInit(state,
                          implicit_pkcs1_hash_algs[i].alg,
                          input_data,
                          input_data_len);

      if (fl_rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashInit: %s",
                                 ssh_fl_rv_to_string(fl_rv)));
          SSH_FL_ASSETFREE(state);
          goto fail;
        }

#ifdef SSHDIST_FIPSLIB_1_1
      fl_rv = FL_HashVerifyPkcs1(key_context->keyAsset,
                                 state,
                                 implicit_pkcs1_hash_algs[i].oid,
                                 implicit_pkcs1_hash_algs[i].encoded_oid_len,
                                 signature_data,
                                 signature_data_len);

#else /* SSHDIST_FIPSLIB_1_1 */
      fl_rv = FL_HashVerifyFips186(key_context->keyAsset,
                                   state,
                                   signature_data,
                                   signature_data_len);
#endif /* SSHDIST_FIPSLIB_1_1 */

      SSH_FL_ASSETFREE(state);

      if (fl_rv == FLR_OK)
        {
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Implicit signature verification succeeded "
                     "with hash id %u",
                     (unsigned int) implicit_pkcs1_hash_algs[i].alg));
          rv = SSH_CRYPTO_OK;
          break;
        }
      else if (fl_rv == FLR_VERIFY_MISMATCH)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Implicit signature verification failed with hash id %u",
                     (unsigned int) implicit_pkcs1_hash_algs[i].alg));
          rv = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
          continue;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashVerifyFips186: %s",
                                 ssh_fl_rv_to_string(fl_rv)));
          goto fail;
        }
    }

  return rv;

 fail:
  return SSH_CRYPTO_OPERATION_FAILED;
}

static SshCryptoStatus
public_key_verify(SshProxyRGFId rgf_id,
                  const unsigned char *input_data,
                  size_t input_data_len,
                  unsigned char *signature_data,
                  size_t signature_data_len,
                  void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  FL_AnyAsset_t state;
  FL_RV fl_rv;
  SshCryptoStatus rv = SSH_CRYPTO_OK;

  SSH_ASSERT(key_context->signature_len == signature_data_len);

  SSH_FL_ALLOCATE_STATE(fl_rv, &state);

  if (fl_rv != FLR_OK)
    return SSH_CRYPTO_NO_MEMORY;

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Starting verify operation, signature:"),
                    signature_data, signature_data_len);

  switch (rgf_id)
    {
    case SSH_RSA_PKCS1_SHA1:
    case SSH_RSA_PKCS1_IMPLICIT:
    case SSH_DSA_NIST_SHA1:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA1,
                          input_data,
                          input_data_len);
      break;
    case SSH_ECDSA_NIST_SHA256:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_256,
                          input_data,
                          input_data_len);
      break;
    case SSH_ECDSA_NIST_SHA384:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_384,
                          input_data,
                          input_data_len);
      break;
    case SSH_ECDSA_NIST_SHA512:
      fl_rv = FL_HashInit(state,
                          FL_ALGO_HASH_SHA2_512,
                          input_data,
                          input_data_len);
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported RGF identifier: %u", rgf_id));
      rv = SSH_CRYPTO_OPERATION_FAILED;
      goto fail;
    }

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashInit: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      rv = SSH_CRYPTO_OPERATION_FAILED;
      goto fail;
    }

  if (rgf_id == SSH_ECDSA_NIST_SHA512)
    {
      unsigned char *signature_buffer;
      size_t signature_buffer_len;

      SSH_ASSERT(signature_data_len == 132);

      signature_buffer_len = signature_data_len + 4;

      signature_buffer = ssh_malloc(signature_buffer_len);

      if (signature_buffer == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failed"));
          rv = SSH_CRYPTO_NO_MEMORY;
          goto fail;
        }

      memset(signature_buffer, 0x00, signature_buffer_len);
      memcpy(signature_buffer + 2 , signature_data, 66);
      memcpy(signature_buffer + 2 + 68, signature_data + 66, 66);

      fl_rv = FL_HashVerifyFips186(key_context->keyAsset,
                                   state,
                                   signature_buffer,
                                   signature_buffer_len);

      ssh_free(signature_buffer);
    }
  else
    {
      fl_rv = FL_HashVerifyFips186(key_context->keyAsset,
                                   state,
                                   signature_data,
                                   signature_data_len);
    }

  if (fl_rv == FLR_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Signature verification succeeded"));
      rv = SSH_CRYPTO_OK;
    }
  else if (fl_rv == FLR_VERIFY_MISMATCH)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Signature verification failed"));
      rv = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashVerifyFips186: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      rv = SSH_CRYPTO_OPERATION_FAILED;
    }

 fail:
  SSH_FL_ASSETFREE(state);
  return rv;
}

static SshCryptoStatus
public_key_verify_nohash(SshProxyRGFId rgf_id,
                         const unsigned char *input_data,
                         size_t input_data_len,
                         unsigned char *signature_data,
                         size_t signature_data_len,
                         void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  FL_AnyAsset_t state;
  FL_Temporary_t temp;
  FL_RV fl_rv;
  SshCryptoStatus rv;

  SSH_ASSERT(key_context->signature_len == signature_data_len);

  /* Set temp value */
  memset(&temp, 0x00, sizeof(temp));

  switch (input_data_len)
    {
    case 20:
      temp.Algo = FL_ALGO_HASH_SHA1;
      break;
    case 28:
      temp.Algo = FL_ALGO_HASH_SHA2_224;
      break;
    case 32:
      temp.Algo = FL_ALGO_HASH_SHA2_256;
      break;
    case 48:
      temp.Algo = FL_ALGO_HASH_SHA2_384;
      break;
    case 64:
      temp.Algo = FL_ALGO_HASH_SHA2_512;
      break;
    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid input data length: %u",
                 (unsigned int) input_data_len));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  temp.Algo |= FL_ALGO_FLAG_KEEP;
  memcpy(temp.Intermediate.Digest, input_data, input_data_len);

  /* Set state value */
  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_FLAG_TEMPORARY,
                           sizeof(temp),
                           FL_POLICY_MASK_ANY,
                           &state);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      return SSH_CRYPTO_NO_MEMORY;
    }

  fl_rv = FL_AssetLoadValue(state,
                            (FL_DataInPtr_t) &temp,
                            sizeof(temp));

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      rv = SSH_CRYPTO_OPERATION_FAILED;
      goto fail;
    }

  if ((rgf_id == SSH_ECDSA_NONE_NONE) &&
      (input_data_len == 64))
    {
      unsigned char *signature_buffer;
      size_t signature_buffer_len;

      SSH_ASSERT(signature_data_len == 132);

      signature_buffer_len = signature_data_len + 4;

      signature_buffer = ssh_malloc(signature_buffer_len);

      if (signature_buffer == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failed"));
          rv = SSH_CRYPTO_NO_MEMORY;
          goto fail;
        }

      memset(signature_buffer, 0x00, signature_buffer_len);
      memcpy(signature_buffer + 2 , signature_data, 66);
      memcpy(signature_buffer + 2 + 68, signature_data + 66, 66);

      fl_rv = FL_HashVerifyFips186(key_context->keyAsset,
                                   state,
                                   signature_buffer,
                                   signature_buffer_len);

      ssh_free(signature_buffer);
    }
  else
    {
      fl_rv = FL_HashVerifyFips186(key_context->keyAsset,
                                   state,
                                   signature_data,
                                   signature_data_len);
    }

  if (fl_rv == FLR_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Signature verification succeeded"));
      rv = SSH_CRYPTO_OK;
    }
  else if (fl_rv == FLR_VERIFY_MISMATCH)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Signature verification failed"));
      rv = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_HashVerifyFips186: %s",
                             ssh_fl_rv_to_string(fl_rv)));
      rv = SSH_CRYPTO_OPERATION_FAILED;
    }

 fail:
  SSH_FL_ASSETFREE(state);
  return rv;
}

#ifdef SSHDIST_FIPSLIB_1_1
static SshCryptoStatus
rsa_key_verify_raw(const unsigned char *input_data,
                   size_t input_data_len,
                   unsigned char *signature_data,
                   size_t signature_data_len,
                   void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  FL_RV fl_rv;
  FL_AnyAlgorithm_t alg;
  FL_Temporary_t temp;
  FL_AnyAsset_t state;

  /* Only accept IKEv1 use with SHA1 and SHA2 */
  if (input_data_len == 20)
    {
      alg =  FL_ALGO_HASH_SHA1;
    }
  else if (input_data_len == 32)
    {
      alg =  FL_ALGO_HASH_SHA2_256;
    }
  else if (input_data_len == 48)
    {
      alg =  FL_ALGO_HASH_SHA2_384;
    }
  else if (input_data_len == 64)
    {
      alg =  FL_ALGO_HASH_SHA2_512;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid input data buffer len: %u",
                 input_data_len));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Accepted key sizes are 1024, 2048 and 3072 */
  if ((signature_data_len != 128) &&
      (signature_data_len != 256) &&
      (signature_data_len != 384))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid bitlenght for RSA signature: %u",
                 signature_data_len * 8));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Raw RSA verify operation, data:"),
                    input_data, input_data_len);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Raw RSA verify operation, signature:"),
                    signature_data, signature_data_len);

  /* Create state manually */
  memset(&temp, 0, sizeof(temp));
  temp.Algo = alg;
  temp.Algo |= FL_ALGO_FLAG_KEEP;
  if (alg == FL_ALGO_HASH_SHA2_384 || alg == FL_ALGO_HASH_SHA2_512)
    memcpy(temp.Intermediate.HashVars64Bit, input_data, input_data_len);
  else
    memcpy(temp.Intermediate.HashVars32Bit, input_data, input_data_len);

  fl_rv = FL_AssetAllocate(FL_POLICY_FLAG_TEMPORARY, sizeof temp,
                           FL_POLICY_MASK_ANY, &state);

  if (fl_rv == FLR_OK)
    {
      fl_rv = FL_AssetLoadValue(state, (FL_DataInPtr_t) &temp, sizeof temp);

      if (fl_rv == FLR_OK)
        {
          fl_rv = FL_HashVerifyPkcs1(key_context->keyAsset,
                                     state,
                                     signature_data,
                                     0,
                                     signature_data,
                                     signature_data_len);
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unable to load FL asset value."));
        }

      FL_AssetFree(state);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to allocate FL asset."));
    }

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Raw RSA signature verification failed"));
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Raw RSA signature verification succeeded"));
      return SSH_CRYPTO_OK;
    }
}

#else /* SSHDIST_FIPSLIB_1_1 */
static SshCryptoStatus
rsa_key_verify_raw(const unsigned char *input_data,
                   size_t input_data_len,
                   unsigned char *signature_data,
                   size_t signature_data_len,
                   void *context)
{
  SshFlKeyContext key_context = (SshFlKeyContext) context;
  unsigned char *output_buffer = NULL, *pkcs1_buffer = NULL;
  size_t output_buffer_len, pkcs1_buffer_len;
  FL_RV fl_rv;
  SshCryptoStatus rv;

  output_buffer_len = signature_data_len;
  output_buffer = ssh_malloc(output_buffer_len);

  if (output_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      rv = SSH_CRYPTO_NO_MEMORY;
      goto end;
    }

  pkcs1_buffer_len = signature_data_len;
  pkcs1_buffer = ssh_malloc(pkcs1_buffer_len);

  if (pkcs1_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      rv = SSH_CRYPTO_NO_MEMORY;
      goto end;
    }

  /* Only accept IKEv1 use with MD5, SHA1 and SHA2 */
  if ((input_data_len != 16) &&
      (input_data_len != 20) &&
      (input_data_len != 32) &&
      (input_data_len != 48) &&
      (input_data_len != 64))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid input data buffer len: %u",
                 input_data_len));
      rv = SSH_CRYPTO_OPERATION_FAILED;
      goto end;
    }

  /* Accepted key sizes are 1024, 2048 and 3072 */
  if ((signature_data_len != 128) &&
      (signature_data_len != 256) &&
      (signature_data_len != 384))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid bitlenght for RSA signature: %u",
                 signature_data_len * 8));
      rv = SSH_CRYPTO_OPERATION_FAILED;
      goto end;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Raw RSA verify operation, data:"),
                    input_data, input_data_len);

  SSH_DEBUG_HEXDUMP(SSH_D_HIGHOK, ("Raw RSA verify operation, signature:"),
                    signature_data, signature_data_len);

  fl_rv = FL_Util_EncryptRawRSA(key_context->keyAsset,
                                signature_data,
                                signature_data_len,
                                output_buffer,
                                output_buffer_len);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_EncryptRawRSA(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      rv = SSH_CRYPTO_OPERATION_FAILED;
      goto end;
    }

  /* Manual RAW pkcs1 padding */
  SSH_ASSERT(input_data_len + 3 < pkcs1_buffer_len);
  memset(pkcs1_buffer, 0x00, pkcs1_buffer_len);
  pkcs1_buffer[1] = 0x01;
  memset(pkcs1_buffer + 2, 0xff,
        pkcs1_buffer_len - input_data_len - 3);
  memcpy(pkcs1_buffer + pkcs1_buffer_len - input_data_len, input_data,
        input_data_len);

  /* Check the signature */
  SSH_ASSERT(pkcs1_buffer_len == output_buffer_len);
  if (memcmp(pkcs1_buffer, output_buffer, output_buffer_len))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Raw RSA signature verification failed"));
      SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("RSA buffer:"),
                        output_buffer, output_buffer_len);
      rv = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Raw RSA signature verification succeeded"));
      rv = SSH_CRYPTO_OK;
    }

 end:
  if (output_buffer != NULL)
    ssh_free(output_buffer);
  if (pkcs1_buffer != NULL)
    ssh_free(pkcs1_buffer);
  return rv;
}
#endif /* SSHDIST_FIPSLIB_1_1 */

SshCryptoStatus
ssh_fl_public_key_verify(SshProxyOperationId operation_id,
                         SshProxyRGFId rgf_id,
                         const unsigned char *input_data,
                         size_t input_data_len,
                         unsigned char *signature_data,
                         size_t signature_data_len,
                         void *context)
{
  SshCryptoStatus status;

  if ((operation_id != SSH_RSA_PUB_VERIFY) &&
      (operation_id != SSH_DSA_PUB_VERIFY) &&
      (operation_id != SSH_ECDSA_PUB_VERIFY))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unhandled operation id: %u",
                             operation_id));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  switch (rgf_id)
    {
    case SSH_RSA_PKCS1_SHA1:
    case SSH_DSA_NIST_SHA1:
    case SSH_ECDSA_NIST_SHA1:
    case SSH_ECDSA_NIST_SHA224:
    case SSH_ECDSA_NIST_SHA256:
    case SSH_ECDSA_NIST_SHA384:
    case SSH_ECDSA_NIST_SHA512:
      status = public_key_verify(rgf_id,
                                 input_data, input_data_len,
                                 signature_data, signature_data_len,
                                 context);
      break;
    case SSH_RSA_PKCS1_IMPLICIT:
    case SSH_RSA_PKCS1_RESTRICTED:
      status = public_key_implicit_pkcs1_verify(rgf_id,
                                                input_data,
                                                input_data_len,
                                                signature_data,
                                                signature_data_len,
                                                context);
      break;
    case SSH_RSA_PKCS1_NONE:
      status = rsa_key_verify_raw(input_data, input_data_len,
                                  signature_data, signature_data_len,
                                  context);
      break;
    case SSH_DSA_NONE_NONE:
    case SSH_ECDSA_NONE_NONE:
      status = public_key_verify_nohash(rgf_id,
                                        input_data, input_data_len,
                                        signature_data, signature_data_len,
                                        context);
      break;
    default:
      status = SSH_CRYPTO_UNSUPPORTED;
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported RGF identifier: %u", rgf_id));
    }

  return status;
}
