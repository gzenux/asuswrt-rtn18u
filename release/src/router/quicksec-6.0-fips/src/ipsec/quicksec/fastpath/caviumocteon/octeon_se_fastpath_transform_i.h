/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file includes internal defines used in transform operations.
*/

#ifndef OCTEON_SE_FASTPATH_TRANSFORM_I_H
#define OCTEON_SE_FASTPATH_TRANSFORM_I_H  1

#include "octeon_se_fastpath_internal.h"

/* Maximum length in 8 byte words that a hash function can output */
#define OCTEON_SE_FASTPATH_MAX_HASH_WORDS 8

/** ESP Padding information is kept here */
typedef struct SeFastpathEspExtraInfoRec
{
  uint64_t iv[2];
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
  uint32_t cipher_nonce;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */
  uint8_t pad_len; /* Total padding length */
  uint8_t nh;
} SeFastpathEspExtraInfoStruct, *SeFastpathEspExtraInfo;

typedef struct SeFastpathMacExtraInfoRec
{
  /* Maximum data that can be inserted as hash prefix */
  union
  {
    uint8_t u8[64];
    uint64_t u64[8];
  } prefix;

  uint32_t prefix_len;

  /* This would be the higher 32 bits of long sequence number */
  uint32_t suffix;
  uint8_t suffix_available;
} SeFastpathMacExtraInfoStruct, *SeFastpathMacExtraInfo;

/** Combined transform */
typedef struct SeFastpathCombinedTransformRec
{
  const char * name;
  size_t cipher_iv_len;
  size_t cipher_key_len;
  size_t pad_boundary;
  size_t mac_key_len;

  uint64_t is_auth_cipher;

  size_t icv_len;

  /* Initialize cipher keys and MAC state. This leaves the crypto
     co-processor in a state suitable for calling the update, encrypt or
     decrypt functions. Therefore the co-processor must not be used for any
     other task between the calls to init and update/encrypt/decrypt. */
  void (*init)(void *context,
               const unsigned char *cipher_key,
               size_t cipher_keylen,
               const unsigned char *mac_key,
               size_t mac_keylen);
  /* For updating only MAC data */
  void (*update)(void *context,
                const unsigned char *data,
                size_t data_len);
  /* Encryption/decryption and computes MAC as well */
  void (*encrypt)(void *context,
                  SeFastpathPacketBuffer dst,
                  SeFastpathPacketBuffer src,
                  SeFastpathMacExtraInfo extra_mac,
                  SeFastpathEspExtraInfo extra_info,
                  uint64_t *digest);
  void (*decrypt)(void *context,
                  SeFastpathPacketBuffer dst,
                  SeFastpathPacketBuffer src,
                  SeFastpathMacExtraInfo extra_mac,
                  SeFastpathEspExtraInfo extra_info,
                  uint64_t *digest);
} SeFastpathCombinedTransformStruct, *SeFastpathCombinedTransform;

SeFastpathCombinedTransform
octeon_se_fastpath_get_combined_transform(uint32_t transform,
                                          uint32_t mac_key_size);
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_I_H */

