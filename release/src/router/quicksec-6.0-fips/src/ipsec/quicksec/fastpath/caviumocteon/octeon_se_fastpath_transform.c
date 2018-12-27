/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements the various hashing and crypto operations.
*/

#include "octeon_se_fastpath_internal.h"
#include "octeon_se_fastpath_transform_i.h"
#include "octeon_se_fastpath_inline.h"

typedef struct SeFastpathCipherCtxRec
{
  uint64_t key[4];
  uint32_t key_len;
} SeFastpathCipherCtxStruct, *SeFastpathCipherCtx;

typedef struct SeFastpathHmacCtxRec
{
  uint32_t total_len;
  uint32_t scratch_len;
#if defined OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
  uint8_t scratch[144];
#else /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */
  uint8_t scratch[80];
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */
} SeFastpathHmacCtxStruct, *SeFastpathHmacCtx;

typedef struct SeFastpathCipherHmacCtxRec
{
  SeFastpathCipherCtxStruct cipher[1];
  SeFastpathHmacCtxStruct hmac[1];
#if defined OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
  uint64_t outer_auth[8];
#elif defined OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  uint64_t outer_auth[4];
#else
  uint64_t outer_auth[3];
#endif
  union
   {
      uint8_t u8;
      struct
        {
          uint8_t is_sha1 : 1;
          uint8_t is_sha256:1;
          uint8_t is_sha384:1;
          uint8_t is_sha512:1;
          uint8_t unused: 4;
        } flag;
   }u;
} SeFastpathCipherHmacCtxStruct, *SeFastpathCipherHmacCtx;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
typedef union SeFastpathAesGCM128BitRec
{
  uint64_t u64[2];
  uint32_t u32[4];
  uint8_t  u8[16];
} SeFastpathAesGCM128BitUnion;

typedef struct SeFastpathAesGcmCtxRec
{
  SeFastpathAesGCM128BitUnion y_i[1];
  SeFastpathAesGCM128BitUnion H[1];
  uint64_t y_0[2];
  SeFastpathCipherCtxStruct cipher[1];
} SeFastpathAesGcmCtxStruct, *SeFastpathAesGcmCtx;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */

typedef enum
{
  OCTEON_SE_FASTPATH_ALGORITHM_MD5,   /** Perform HMAC using MD5 */
  OCTEON_SE_FASTPATH_ALGORITHM_SHA_1  /** Perform HMAC using SHA-1 */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  , OCTEON_SE_FASTPATH_ALGORITHM_SHA_256 = 2
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
  , OCTEON_SE_FASTPATH_ALGORITHM_SHA_512 = 3
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */
} SeFastpathTranformMacAlgo;


/***************************** Crypto ***************************************/

static inline
uint64_t swap64(uint64_t v)
{
  return (((v >> 56) & 0xfful) |
          (((v >> 48) & 0xfful) << 8) |
          (((v >> 40) & 0xfful) << 16) |
          (((v >> 32) & 0xfful) << 24) |
          (((v >> 24) & 0xfful) << 32) |
          (((v >> 16) & 0xfful) << 40) |
          (((v >> 8) & 0xfful) << 48) | (((v >> 0) & 0xfful) << 56));
}

static inline uint32_t
insert_pad(SeFastpathPacketBuffer src,
           SeFastpathEspExtraInfo extra,
           uint16_t input_len,
           uint8_t *pad)
{
  uint16_t len = input_len;
  int i = 0;

  while (len >= 8)
    {
      OCTEON_SE_PUT_64BIT_ALIGNED(&pad[i],
                                  octeon_se_fastpath_buffer_read_word(src));
      i += 8;
      len -= 8;
    }
  if (len > 0)
    OCTEON_SE_PUT_64BIT_ALIGNED(&pad[i],
                        octeon_se_fastpath_buffer_read_partial_word(src, len));

  for (i = 0; i < extra->pad_len; i++)
    pad[input_len + i] = i + 1;

  pad[input_len + i] = extra->pad_len;
  pad[input_len + i + 1] = extra->nh;
  return (input_len + extra->pad_len + 2);
}

typedef struct SeFastpathPadInfoRec
{
  union
  {
    uint64_t u64[4];
    uint8_t  u8[32];
  } pad_info;

  /* Length of padding in bytes */
  uint32_t pad_len;
} SeFastpathPadInfoStruct, *SeFastpathPadInfo;

/* This function extracts and verifies the padding information.
   It returns the length of actual packet bytes before padding in the
   input data. It also extracts the next header information and padding
   length. On error it sets next_header to 0. */
static inline
uint32_t verify_pad(SeFastpathPadInfo pad,
                    uint8_t *pad_length,
                    uint8_t *next_header)

{
  int start;
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_ESP_PADDING_FORMAT_VERIFICATION
  int i;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_ESP_PADDING_FORMAT_VERIFICATION */

  OCTEON_SE_ASSERT(pad->pad_len >= 2);

  *pad_length = pad->pad_info.u8[pad->pad_len - 2];

  /* Allow more padding than fits into the input block. */
  if (cvmx_unlikely(*pad_length > pad->pad_len - 2))
    start = 0;
  else
    start = pad->pad_len - 2 - *pad_length;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_ESP_PADDING_FORMAT_VERIFICATION
  *next_header = 0; /* Error */

  /* Check the padding in the input block backwards from end to start.
     Note that padding bytes outside of the input block are not checked. */
  for (i = pad->pad_len - 2; i > start; i--)
    {
      if (cvmx_unlikely(pad->pad_info.u8[i - 1]
                        != (*pad_length - (pad->pad_len - 2 - i))))
        {
          OCTEON_SE_DEBUG(3, "Packet has invalid ESP padding\n");
          OCTEON_SE_HEXDUMP(9, pad->pad_info.u8, pad->pad_len);
          return 0;
        }
    }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_ESP_PADDING_FORMAT_VERIFICATION */

  *next_header = pad->pad_info.u8[pad->pad_len - 1];
  return start;
}


static inline void
octeon_hash_start_engine(uint64_t *buffer,
                         SeFastpathTranformMacAlgo algo);

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
static inline void
octeon_hash_start_engine_wide(uint64_t *buffer);
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

inline void
octeon_aes_init_key(SeFastpathCipherCtx ctx,
                    const unsigned char *key,
                    size_t keylen)
{
  size_t i, key_words = 0;

  if (keylen <= 16)
    {
      key_words = 2;
      ctx->key_len = 16;
    }
  else if (keylen <= 24)
    {
      key_words = 3;
      ctx->key_len = 24;
    }
  else
    {
      key_words = 4;
      ctx->key_len = 32;
    }

  for (i = 0; i < key_words; i++)
    ctx->key[i] =
      (((uint64_t) ((((i * 8) + 0) < keylen) ? key[(i * 8) + 0] : 0)) << 56) |
      (((uint64_t) ((((i * 8) + 1) < keylen) ? key[(i * 8) + 1] : 0)) << 48) |
      (((uint64_t) ((((i * 8) + 2) < keylen) ? key[(i * 8) + 2] : 0)) << 40) |
      (((uint64_t) ((((i * 8) + 3) < keylen) ? key[(i * 8) + 3] : 0)) << 32) |
      (((uint64_t) ((((i * 8) + 4) < keylen) ? key[(i * 8) + 4] : 0)) << 24) |
      (((uint64_t) ((((i * 8) + 5) < keylen) ? key[(i * 8) + 5] : 0)) << 16) |
      (((uint64_t) ((((i * 8) + 6) < keylen) ? key[(i * 8) + 6] : 0)) << 8) |
      (((uint64_t) ((((i * 8) + 7) < keylen) ? key[(i * 8) + 7] : 0)));
}

inline void
octeon_aes_set_key(SeFastpathCipherCtx ctx)
{
  CVMX_MT_AES_KEY(ctx->key[0],0);
  CVMX_MT_AES_KEY(ctx->key[1],1);

  if (ctx->key_len == 16)
    {
      CVMX_MT_AES_KEYLENGTH(1);
    }
  else if (ctx->key_len == 24)
    {
      CVMX_MT_AES_KEY(ctx->key[2],2);
      CVMX_MT_AES_KEYLENGTH(2);
    }
  else if (ctx->key_len == 32)
    {
      CVMX_MT_AES_KEY(ctx->key[2],2);
      CVMX_MT_AES_KEY(ctx->key[3],3);
      CVMX_MT_AES_KEYLENGTH(3);
    }
}

inline void
octeon_3des_init_key(SeFastpathCipherCtx ctx,
                     const unsigned char *key,
                     size_t keylen)
{
  int i;

  for (i = 0; i < 3; i++)
    ctx->key[i] =
      (((uint64_t) key[(i * 8) + 0]) << 56) |
      (((uint64_t) key[(i * 8) + 1]) << 48) |
      (((uint64_t) key[(i * 8) + 2]) << 40) |
      (((uint64_t) key[(i * 8) + 3]) << 32) |
      (((uint64_t) key[(i * 8) + 4]) << 24) |
      (((uint64_t) key[(i * 8) + 5]) << 16) |
      (((uint64_t) key[(i * 8) + 6]) << 8) |
      ((uint64_t) key[(i * 8) + 7]);
}

inline void
octeon_3des_set_key(SeFastpathCipherCtx ctx)
{
  CVMX_MT_3DES_KEY(ctx->key[0], 0);
  CVMX_MT_3DES_KEY(ctx->key[1], 1);
  CVMX_MT_3DES_KEY(ctx->key[2], 2);
}

inline void
octeon_sha1_reset_context(SeFastpathHmacCtx ctx)
{
  CVMX_MT_HSH_IV(0x67452301EFCDAB89ull, 0);
  CVMX_MT_HSH_IV(0x98BADCFE10325476ull, 1);
  CVMX_MT_HSH_IV(0xC3D2E1F000000000ull, 2);

  ctx->scratch_len = 0;
  ctx->total_len = 0;
}

inline void
octeon_sha1_init(SeFastpathHmacCtx ctx,
                 const unsigned char *mac_key,
                 size_t mac_key_len,
                 uint64_t *outer)
{
  uint64_t hash_key[8];

  OCTEON_SE_ASSERT(mac_key_len == 20);

  /* Calculate opad and store hash state. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[2] &= 0xffffffff00000000ull;
  hash_key[0] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[1] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[2] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[3] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[4] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[5] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[6] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[7] = 0x5c5c5c5c5c5c5c5cull;

  octeon_sha1_reset_context(ctx);
  octeon_hash_start_engine(hash_key, OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  CVMX_MF_HSH_IV(outer[0], 0);
  CVMX_MF_HSH_IV(outer[1], 1);
  CVMX_MF_HSH_IV(outer[2], 2);

  /* Calculate ipad. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[2] &= 0xffffffff00000000ull;
  hash_key[0] ^= 0x3636363636363636ull;
  hash_key[1] ^= 0x3636363636363636ull;
  hash_key[2] ^= 0x3636363636363636ull;
  hash_key[3] = 0x3636363636363636ull;
  hash_key[4] = 0x3636363636363636ull;
  hash_key[5] = 0x3636363636363636ull;
  hash_key[6] = 0x3636363636363636ull;
  hash_key[7] = 0x3636363636363636ull;

  octeon_sha1_reset_context(ctx);
  octeon_hash_start_engine(hash_key, OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  OCTEON_SE_ASSERT(ctx->total_len == 0);
  OCTEON_SE_ASSERT(ctx->scratch_len == 0);
}

inline void
octeon_md5_reset_context(SeFastpathHmacCtx ctx)
{
  CVMX_MT_HSH_IV(0x0123456789abcdefull, 0);
  CVMX_MT_HSH_IV(0xfedcba9876543210ull, 1);

  ctx->scratch_len = 0;
  ctx->total_len = 0;
}

inline void
octeon_md5_init(SeFastpathHmacCtx ctx,
                const unsigned char *mac_key,
                size_t mac_key_len,
                uint64_t *outer)
{
  uint64_t hash_key[8];

  OCTEON_SE_ASSERT(mac_key_len == 16);

  /* Calculate opad and store hash state. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[1] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[2] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[3] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[4] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[5] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[6] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[7] = 0x5c5c5c5c5c5c5c5cull;

  octeon_md5_reset_context(ctx);
  octeon_hash_start_engine(hash_key, OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  CVMX_MF_HSH_IV(outer[0], 0);
  CVMX_MF_HSH_IV(outer[1], 1);

  /* Calculate ipad. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x3636363636363636ull;
  hash_key[1] ^= 0x3636363636363636ull;
  hash_key[2] = 0x3636363636363636ull;
  hash_key[3] = 0x3636363636363636ull;
  hash_key[4] = 0x3636363636363636ull;
  hash_key[5] = 0x3636363636363636ull;
  hash_key[6] = 0x3636363636363636ull;
  hash_key[7] = 0x3636363636363636ull;

  octeon_md5_reset_context(ctx);
  octeon_hash_start_engine(hash_key, OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  OCTEON_SE_ASSERT(ctx->total_len == 0);
  OCTEON_SE_ASSERT(ctx->scratch_len == 0);
}

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
void octeon_sha256_reset_context(SeFastpathHmacCtx ctx)
{
  CVMX_MT_HSH_IV(0x6a09e667bb67ae85ull, 0);
  CVMX_MT_HSH_IV(0x3c6ef372a54ff53aull, 1);
  CVMX_MT_HSH_IV(0x510e527f9b05688cull, 2);
  CVMX_MT_HSH_IV(0x1f83d9ab5be0cd19ull, 3);

  ctx->scratch_len = 0;
  ctx->total_len = 0;
}

void octeon_sha256_init(SeFastpathHmacCtx ctx,
                        const unsigned char *mac_key,
                        size_t mac_key_len,
                        uint64_t *outer)
{
  uint64_t hash_key[8];

  OCTEON_SE_ASSERT(mac_key_len == 32);

  /* Calculate opad and store hash state. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[1] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[2] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[3] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[4] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[5] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[6] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[7] = 0x5c5c5c5c5c5c5c5cull;

  octeon_sha256_reset_context(ctx);
  octeon_hash_start_engine((uint64_t *) hash_key,
                           OCTEON_SE_FASTPATH_ALGORITHM_SHA_256);

  CVMX_MF_HSH_IV(outer[0], 0);
  CVMX_MF_HSH_IV(outer[1], 1);
  CVMX_MF_HSH_IV(outer[2], 2);
  CVMX_MF_HSH_IV(outer[3], 3);

  /* Calculate ipad. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x3636363636363636ull;
  hash_key[1] ^= 0x3636363636363636ull;
  hash_key[2] ^= 0x3636363636363636ull;
  hash_key[3] ^= 0x3636363636363636ull;
  hash_key[4] = 0x3636363636363636ull;
  hash_key[5] = 0x3636363636363636ull;
  hash_key[6] = 0x3636363636363636ull;
  hash_key[7] = 0x3636363636363636ull;

  octeon_sha256_reset_context(ctx);
  octeon_hash_start_engine((uint64_t *) hash_key,
                           OCTEON_SE_FASTPATH_ALGORITHM_SHA_256);

  OCTEON_SE_ASSERT(ctx->total_len == 0);
  OCTEON_SE_ASSERT(ctx->scratch_len == 0);
}
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
void octeon_sha384_reset_context(SeFastpathHmacCtx ctx)
{
  CVMX_MT_HSH_IVW(0xcbbb9d5dc1059ed8ull, 0);
  CVMX_MT_HSH_IVW(0x629a292a367cd507ull, 1);
  CVMX_MT_HSH_IVW(0x9159015a3070dd17ull, 2);
  CVMX_MT_HSH_IVW(0x152fecd8f70e5939ull, 3);
  CVMX_MT_HSH_IVW(0x67332667ffc00b31ull, 4);
  CVMX_MT_HSH_IVW(0x8eb44a8768581511ull, 5);
  CVMX_MT_HSH_IVW(0xdb0c2e0d64f98fa7ull, 6);
  CVMX_MT_HSH_IVW(0x47b5481dbefa4fa4ull, 7);

  ctx->scratch_len = 0;
  ctx->total_len = 0;
}

void octeon_sha384_init(SeFastpathHmacCtx ctx,
                        const unsigned char *mac_key,
                        size_t mac_key_len,
                        uint64_t *outer)
{
  uint64_t hash_key[16];

  OCTEON_SE_ASSERT(mac_key_len == 48);
  octeon_sha384_reset_context(ctx);

  /* Calculate opad and store hash state. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[1] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[2] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[3] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[4] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[5] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[6] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[7] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[8] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[9] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[10] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[11] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[12] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[13] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[14] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[15] = 0x5c5c5c5c5c5c5c5cull;

  octeon_sha384_reset_context(ctx);
  octeon_hash_start_engine_wide((uint64_t *) hash_key);

  CVMX_MF_HSH_IVW(outer[0], 0);
  CVMX_MF_HSH_IVW(outer[1], 1);
  CVMX_MF_HSH_IVW(outer[2], 2);
  CVMX_MF_HSH_IVW(outer[3], 3);
  CVMX_MF_HSH_IVW(outer[4], 4);
  CVMX_MF_HSH_IVW(outer[5], 5);
  CVMX_MF_HSH_IVW(outer[6], 6);
  CVMX_MF_HSH_IVW(outer[7], 7);

  /* Calculate ipad. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x3636363636363636ull;
  hash_key[1] ^= 0x3636363636363636ull;
  hash_key[2] ^= 0x3636363636363636ull;
  hash_key[3] ^= 0x3636363636363636ull;
  hash_key[4] ^= 0x3636363636363636ull;
  hash_key[5] ^= 0x3636363636363636ull;
      hash_key[6] = 0x3636363636363636ull;
      hash_key[7] = 0x3636363636363636ull;
  hash_key[8] = 0x3636363636363636ull;
  hash_key[9] = 0x3636363636363636ull;
  hash_key[10] = 0x3636363636363636ull;
  hash_key[11] = 0x3636363636363636ull;
  hash_key[12] = 0x3636363636363636ull;
  hash_key[13] = 0x3636363636363636ull;
  hash_key[14] = 0x3636363636363636ull;
  hash_key[15] = 0x3636363636363636ull;

  octeon_sha384_reset_context(ctx);
  octeon_hash_start_engine_wide((uint64_t *) hash_key);

  OCTEON_SE_ASSERT(ctx->total_len == 0);
  OCTEON_SE_ASSERT(ctx->scratch_len == 0);
}


void octeon_sha512_reset_context(SeFastpathHmacCtx ctx)
{
  CVMX_MT_HSH_IVW(0x6a09e667f3bcc908ull, 0);
  CVMX_MT_HSH_IVW(0xbb67ae8584caa73bull, 1);
  CVMX_MT_HSH_IVW(0x3c6ef372fe94f82bull, 2);
  CVMX_MT_HSH_IVW(0xa54ff53a5f1d36f1ull, 3);
  CVMX_MT_HSH_IVW(0x510e527fade682d1ull, 4);
  CVMX_MT_HSH_IVW(0x9b05688c2b3e6c1full, 5);
  CVMX_MT_HSH_IVW(0x1f83d9abfb41bd6bull, 6);
  CVMX_MT_HSH_IVW(0x5be0cd19137e2179ull, 7);

  ctx->scratch_len = 0;
  ctx->total_len = 0;
}

void octeon_sha512_init(SeFastpathHmacCtx ctx,
                        const unsigned char *mac_key,
                        size_t mac_key_len,
                        uint64_t *outer)
{
  uint64_t hash_key[16];

  OCTEON_SE_ASSERT(mac_key_len == 64);

  /* Calculate opad and store hash state. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[1] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[2] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[3] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[4] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[5] ^= 0x5c5c5c5c5c5c5c5cull;
      hash_key[6] ^= 0x5c5c5c5c5c5c5c5cull;
      hash_key[7] ^= 0x5c5c5c5c5c5c5c5cull;
  hash_key[8] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[9] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[10] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[11] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[12] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[13] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[14] = 0x5c5c5c5c5c5c5c5cull;
  hash_key[15] = 0x5c5c5c5c5c5c5c5cull;

    octeon_sha512_reset_context(ctx);
  octeon_hash_start_engine_wide((uint64_t *) hash_key);

  CVMX_MF_HSH_IVW(outer[0], 0);
  CVMX_MF_HSH_IVW(outer[1], 1);
  CVMX_MF_HSH_IVW(outer[2], 2);
  CVMX_MF_HSH_IVW(outer[3], 3);
  CVMX_MF_HSH_IVW(outer[4], 4);
  CVMX_MF_HSH_IVW(outer[5], 5);
  CVMX_MF_HSH_IVW(outer[6], 6);
  CVMX_MF_HSH_IVW(outer[7], 7);

  /* Calculate ipad. */
  memcpy(hash_key, mac_key, mac_key_len);
  hash_key[0] ^= 0x3636363636363636ull;
  hash_key[1] ^= 0x3636363636363636ull;
  hash_key[2] ^= 0x3636363636363636ull;
  hash_key[3] ^= 0x3636363636363636ull;
  hash_key[4] ^= 0x3636363636363636ull;
  hash_key[5] ^= 0x3636363636363636ull;
  hash_key[6] ^= 0x3636363636363636ull;
  hash_key[7] ^= 0x3636363636363636ull;
  hash_key[8] = 0x3636363636363636ull;
  hash_key[9] = 0x3636363636363636ull;
  hash_key[10] = 0x3636363636363636ull;
  hash_key[11] = 0x3636363636363636ull;
  hash_key[12] = 0x3636363636363636ull;
  hash_key[13] = 0x3636363636363636ull;
  hash_key[14] = 0x3636363636363636ull;
  hash_key[15] = 0x3636363636363636ull;

    octeon_sha512_reset_context(ctx);
  octeon_hash_start_engine_wide((uint64_t *) hash_key);

  OCTEON_SE_ASSERT(ctx->total_len == 0);
  OCTEON_SE_ASSERT(ctx->scratch_len == 0);
}
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

static inline void
octeon_load_hash_scratch(SeFastpathHmacCtx ctx,
                         const uint8_t *buffer,
                         size_t length,
                         SeFastpathTranformMacAlgo algo)
{
  register size_t len = length;
  register size_t i = 0;

  while (cvmx_likely(len > 0))
    {
      if (len > (64 - ctx->scratch_len))
        {
          memcpy(ctx->scratch + ctx->scratch_len, buffer + i,
                 64 - ctx->scratch_len);
          i += (64 - ctx->scratch_len);
          len -= (64 - ctx->scratch_len);
          ctx->scratch_len = 64;
        }
      else
        {
          memcpy(ctx->scratch + ctx->scratch_len, buffer + i, len);
          ctx->scratch_len += len;
          i += len;
          len = 0;
        }

      OCTEON_SE_ASSERT(ctx->scratch_len <= 64);
      if (cvmx_unlikely(ctx->scratch_len == 64))
        {
          ctx->scratch_len = 0;
          octeon_hash_start_engine((uint64_t *)ctx->scratch, algo);
        }
    }

  ctx->total_len += length;
}

static inline void
octeon_load_hash_scratch_word(SeFastpathHmacCtx ctx,
                              uint64_t word,
                              SeFastpathTranformMacAlgo algo)
{
  OCTEON_SE_ASSERT(ctx->scratch_len < 64);

  OCTEON_SE_PUT_64BIT(ctx->scratch + ctx->scratch_len, word);

  ctx->scratch_len += 8;
  if (cvmx_unlikely(ctx->scratch_len >= 64))
    {
      ctx->scratch_len -= 64;
      octeon_hash_start_engine((uint64_t *) ctx->scratch, algo);
      OCTEON_SE_ASSERT(ctx->scratch_len <= 8);
      OCTEON_SE_COPY_64BIT_ALIGNED(ctx->scratch, ctx->scratch + 64);
    }

  ctx->total_len += 8;
}

static inline void
octeon_load_hash_scratch_double_word(SeFastpathHmacCtx ctx,
                                     uint64_t word0, uint64_t word1,
                                     SeFastpathTranformMacAlgo algo)
{
  OCTEON_SE_ASSERT(ctx->scratch_len < 64);

  OCTEON_SE_PUT_64BIT(ctx->scratch + ctx->scratch_len, word0);
  OCTEON_SE_PUT_64BIT(ctx->scratch + ctx->scratch_len + 8, word1);

  ctx->scratch_len += 16;
  if (cvmx_unlikely(ctx->scratch_len >= 64))
    {
      ctx->scratch_len -= 64;
      octeon_hash_start_engine((uint64_t *) ctx->scratch, algo);
      OCTEON_SE_ASSERT(ctx->scratch_len <= 16);
      OCTEON_SE_COPY_64BIT_ALIGNED(ctx->scratch, ctx->scratch + 64);
      if (ctx->scratch_len > 8)
        OCTEON_SE_COPY_64BIT_ALIGNED(ctx->scratch + 8, ctx->scratch + 72);
    }

  ctx->total_len += 16;
}

static inline void
octeon_hash_start_engine(uint64_t *buffer,
                         SeFastpathTranformMacAlgo algo)
{
  CVMX_MT_HSH_DAT(buffer[0], 0);
  CVMX_MT_HSH_DAT(buffer[1], 1);
  CVMX_MT_HSH_DAT(buffer[2], 2);
  CVMX_MT_HSH_DAT(buffer[3], 3);
  CVMX_MT_HSH_DAT(buffer[4], 4);
  CVMX_MT_HSH_DAT(buffer[5], 5);
  CVMX_MT_HSH_DAT(buffer[6], 6);
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if (cvmx_unlikely(algo == OCTEON_SE_FASTPATH_ALGORITHM_SHA_256))
    {
      CVMX_MT_HSH_STARTSHA256(buffer[7]);
    }
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
  if (cvmx_likely(algo == OCTEON_SE_FASTPATH_ALGORITHM_SHA_1))
    {
      CVMX_MT_HSH_STARTSHA(buffer[7]);
    }
  else
    {
      CVMX_MT_HSH_STARTMD5(buffer[7]);
    }
}

static inline void
octeon_sha1_finish_outer_hmac(SeFastpathCipherHmacCtx ctx,
                              uint64_t *digest)
{
  register uint64_t temp1, temp2, temp3, bits;
  uint64_t *ptr;

  bits = (ctx->hmac->total_len + 64) * 8; /* Add ipad length as well */
  ctx->hmac->scratch[ctx->hmac->scratch_len] = 0x80;
  memset(ctx->hmac->scratch + ctx->hmac->scratch_len + 1, 0,
         64 - ctx->hmac->scratch_len - 1);
  ptr = (uint64_t *) ctx->hmac->scratch;

  CVMX_MT_HSH_DAT(*ptr++, 0);
  CVMX_MT_HSH_DAT(*ptr++, 1);
  CVMX_MT_HSH_DAT(*ptr++, 2);
  CVMX_MT_HSH_DAT(*ptr++, 3);
  CVMX_MT_HSH_DAT(*ptr++, 4);
  CVMX_MT_HSH_DAT(*ptr++, 5);
  CVMX_MT_HSH_DAT(*ptr++, 6);

  if (ctx->hmac->scratch_len < 56)
    {
      CVMX_MT_HSH_STARTSHA(bits);
    }
  else
    {
      CVMX_MT_HSH_STARTSHA(*ptr);
      CVMX_MT_HSH_DATZ(0);
      CVMX_MT_HSH_DATZ(1);
      CVMX_MT_HSH_DATZ(2);
      CVMX_MT_HSH_DATZ(3);
      CVMX_MT_HSH_DATZ(4);
      CVMX_MT_HSH_DATZ(5);
      CVMX_MT_HSH_DATZ(6);
      CVMX_MT_HSH_STARTSHA(bits);
    }

  /* Get result of inner hash */
  CVMX_MF_HSH_IV(temp1, 0);
  CVMX_MF_HSH_IV(temp2, 1);
  CVMX_MF_HSH_IV(temp3, 2);
  temp3 |= 0x80000000;

  /* Store result of outer hash */
  CVMX_MT_HSH_IV(ctx->outer_auth[0], 0);
  CVMX_MT_HSH_IV(ctx->outer_auth[1], 1);
  CVMX_MT_HSH_IV(ctx->outer_auth[2], 2);

  CVMX_MT_HSH_DAT(temp1, 0);
  CVMX_MT_HSH_DAT(temp2, 1);
  CVMX_MT_HSH_DAT(temp3, 2);
  CVMX_MT_HSH_DATZ(3);
  CVMX_MT_HSH_DATZ(4);
  CVMX_MT_HSH_DATZ(5);
  CVMX_MT_HSH_DATZ(6);
  CVMX_MT_HSH_STARTSHA(0x00000000000002a0ull);

  CVMX_MF_HSH_IV(digest[0], 0);
  CVMX_MF_HSH_IV(digest[1], 1);
  digest[1] &= 0xffffffff00000000ull;
}

static inline void
octeon_md5_finish_outer_hash(SeFastpathCipherHmacCtx ctx,
                             uint64_t *digest)
{
  register uint64_t temp1, temp2, temp3;
  uint16_t len;
  uint64_t bits, *ptr;

  len = ctx->hmac->scratch_len;
  bits = (ctx->hmac->total_len + 64) * 8; /* Add ipad length as well */
  bits = swap64(bits);
  ctx->hmac->scratch[len] = 0x80;
  memset(ctx->hmac->scratch + len + 1, 0, 64 - len - 1);
  ptr = (uint64_t *) ctx->hmac->scratch;

  CVMX_MT_HSH_DAT(*ptr++, 0);
  CVMX_MT_HSH_DAT(*ptr++, 1);
  CVMX_MT_HSH_DAT(*ptr++, 2);
  CVMX_MT_HSH_DAT(*ptr++, 3);
  CVMX_MT_HSH_DAT(*ptr++, 4);
  CVMX_MT_HSH_DAT(*ptr++, 5);
  CVMX_MT_HSH_DAT(*ptr++, 6);

  if (len < 56)
    {
      CVMX_MT_HSH_STARTMD5(bits);
    }
  else
    {
      CVMX_MT_HSH_STARTMD5(*ptr);
      CVMX_MT_HSH_DATZ(0);
      CVMX_MT_HSH_DATZ(1);
      CVMX_MT_HSH_DATZ(2);
      CVMX_MT_HSH_DATZ(3);
      CVMX_MT_HSH_DATZ(4);
      CVMX_MT_HSH_DATZ(5);
      CVMX_MT_HSH_DATZ(6);
      CVMX_MT_HSH_STARTMD5(bits);
    }

  /* Get result of inner hash */
  CVMX_MF_HSH_IV(temp1, 0);
  CVMX_MF_HSH_IV(temp2, 1);

  /* Store result of outer hash */
  CVMX_MT_HSH_IV(ctx->outer_auth[0], 0);
  CVMX_MT_HSH_IV(ctx->outer_auth[1], 1);

  CVMX_MT_HSH_DAT(temp1, 0);
  CVMX_MT_HSH_DAT(temp2, 1);
  temp3 = 0x8000000000000000ULL;
  CVMX_MT_HSH_DAT(temp3, 2);
  CVMX_MT_HSH_DATZ(3);
  CVMX_MT_HSH_DATZ(4);
  CVMX_MT_HSH_DATZ(5);
  CVMX_MT_HSH_DATZ(6);
  CVMX_MT_HSH_STARTMD5(0x8002000000000000ull);

  CVMX_MF_HSH_IV(digest[0], 0);
  CVMX_MF_HSH_IV(digest[1], 1);
  digest[1] &= 0xffffffff00000000ull;
}


#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
static inline void
octeon_sha256_finish_outer_hmac(SeFastpathCipherHmacCtx ctx,
                                uint64_t *digest)
{
  register uint64_t temp1, temp2, temp3, temp4;
  uint64_t bits, *ptr;

  bits = (ctx->hmac->total_len + 64) * 8; /* Add ipad length as well */
  ctx->hmac->scratch[ctx->hmac->scratch_len] = 0x80;
  memset(ctx->hmac->scratch + ctx->hmac->scratch_len + 1, 0,
         64 - ctx->hmac->scratch_len - 1);
  ptr = (uint64_t *) ctx->hmac->scratch;

  CVMX_MT_HSH_DAT(*ptr++, 0);
  CVMX_MT_HSH_DAT(*ptr++, 1);
  CVMX_MT_HSH_DAT(*ptr++, 2);
  CVMX_MT_HSH_DAT(*ptr++, 3);
  CVMX_MT_HSH_DAT(*ptr++, 4);
  CVMX_MT_HSH_DAT(*ptr++, 5);
  CVMX_MT_HSH_DAT(*ptr++, 6);

  if (ctx->hmac->scratch_len < 56)
    {
      CVMX_MT_HSH_STARTSHA256(bits);
    }
  else
    {
      CVMX_MT_HSH_STARTSHA256(*ptr);
      CVMX_MT_HSH_DATZ(0);
      CVMX_MT_HSH_DATZ(1);
      CVMX_MT_HSH_DATZ(2);
      CVMX_MT_HSH_DATZ(3);
      CVMX_MT_HSH_DATZ(4);
      CVMX_MT_HSH_DATZ(5);
      CVMX_MT_HSH_DATZ(6);
      CVMX_MT_HSH_STARTSHA256(bits);
    }

  /* Get result of inner hash */
  CVMX_MF_HSH_IV(temp1, 0);
  CVMX_MF_HSH_IV(temp2, 1);
  CVMX_MF_HSH_IV(temp3, 2);
  CVMX_MF_HSH_IV(temp4, 3);

  /* Store result of outer hash */
  CVMX_MT_HSH_IV(ctx->outer_auth[0], 0);
  CVMX_MT_HSH_IV(ctx->outer_auth[1], 1);
  CVMX_MT_HSH_IV(ctx->outer_auth[2], 2);
  CVMX_MT_HSH_IV(ctx->outer_auth[3], 3);

  CVMX_MT_HSH_DAT(temp1, 0);
  CVMX_MT_HSH_DAT(temp2, 1);
  CVMX_MT_HSH_DAT(temp3, 2);
  CVMX_MT_HSH_DAT(temp4, 3);
  CVMX_MT_HSH_DAT(0x8000000000000000ull, 4);
  CVMX_MT_HSH_DATZ(5);
  CVMX_MT_HSH_DATZ(6);
  CVMX_MT_HSH_STARTSHA256(0x0000000000000300ull);

  CVMX_MF_HSH_IV(digest[0], 0);
  CVMX_MF_HSH_IV(digest[1], 1);
}
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
static inline void
octeon_load_hash_scratch_wide(SeFastpathHmacCtx ctx,
                              const uint8_t *buffer,
                              size_t length)
{
  register size_t len = length;
  register size_t i = 0;

  while (cvmx_likely(len > 0))
   {
      if (len > (128 - ctx->scratch_len))
        {
          memcpy(ctx->scratch + ctx->scratch_len, buffer + i,
                 128 - ctx->scratch_len);
          i += (128 - ctx->scratch_len);
          len -= (128 - ctx->scratch_len);
          ctx->scratch_len = 128;
        }
      else
        {
          memcpy(ctx->scratch + ctx->scratch_len, buffer + i, len);
          ctx->scratch_len += len;
          i += len;
          len = 0;
        }

      OCTEON_SE_ASSERT(ctx->scratch_len <= 128);
      if (cvmx_unlikely(ctx->scratch_len == 128))
        {
          ctx->scratch_len = 0;
          octeon_hash_start_engine_wide((uint64_t *)ctx->scratch);
        }
    }
  ctx->total_len += length;
}

static inline void
octeon_load_hash_scratch_word_wide(SeFastpathHmacCtx ctx,
                                   uint64_t word)
{
  OCTEON_SE_ASSERT(ctx->scratch_len < 128);

  OCTEON_SE_PUT_64BIT(ctx->scratch + ctx->scratch_len, word);

  ctx->scratch_len += 8;
  if (cvmx_unlikely(ctx->scratch_len >= 128))
    {
      ctx->scratch_len -= 128;
      octeon_hash_start_engine_wide((uint64_t *) ctx->scratch);
      OCTEON_SE_ASSERT(ctx->scratch_len <= 8);
      OCTEON_SE_COPY_64BIT_ALIGNED(ctx->scratch, ctx->scratch + 128);
    }

  ctx->total_len += 8;
}


static inline void
octeon_load_hash_scratch_double_word_wide(SeFastpathHmacCtx ctx,
                                          uint64_t word0, uint64_t word1)
{
  OCTEON_SE_ASSERT(ctx->scratch_len < 128);

  OCTEON_SE_PUT_64BIT(ctx->scratch + ctx->scratch_len, word0);
  OCTEON_SE_PUT_64BIT(ctx->scratch + ctx->scratch_len + 8, word1);

  ctx->scratch_len += 16;
  if (cvmx_unlikely(ctx->scratch_len >= 128))
    {
      ctx->scratch_len -= 128;
      octeon_hash_start_engine_wide((uint64_t *) ctx->scratch);
      OCTEON_SE_ASSERT(ctx->scratch_len <= 16);
      OCTEON_SE_COPY_64BIT_ALIGNED(ctx->scratch, ctx->scratch + 128);
      if (ctx->scratch_len > 8)
        OCTEON_SE_COPY_64BIT_ALIGNED(ctx->scratch + 8, ctx->scratch + 136);
    }

  ctx->total_len += 16;
}

static inline void
octeon_hash_start_engine_wide(uint64_t *buffer)
{
  CVMX_MT_HSH_DATW(buffer[0],0);
  CVMX_MT_HSH_DATW(buffer[1],1);
  CVMX_MT_HSH_DATW(buffer[2],2);
  CVMX_MT_HSH_DATW(buffer[3],3);
  CVMX_MT_HSH_DATW(buffer[4],4);
  CVMX_MT_HSH_DATW(buffer[5],5);
  CVMX_MT_HSH_DATW(buffer[6],6);
  CVMX_MT_HSH_DATW(buffer[7],7);
  CVMX_MT_HSH_DATW(buffer[8],8);
  CVMX_MT_HSH_DATW(buffer[9],9);
  CVMX_MT_HSH_DATW(buffer[10],10);
  CVMX_MT_HSH_DATW(buffer[11],11);
  CVMX_MT_HSH_DATW(buffer[12],12);
  CVMX_MT_HSH_DATW(buffer[13],13);
  CVMX_MT_HSH_DATW(buffer[14],14);
  CVMX_MT_HSH_STARTSHA512(buffer[15]);
}


static inline void
octeon_sha512_finish_outer_hmac(SeFastpathCipherHmacCtx ctx,
                                uint64_t *digest)
{
  uint64_t temp[8];
  uint64_t *ptr;
  uint64_t bits;

  bits = (ctx->hmac->total_len + 128) * 8; /* Add ipad length as well */
  ctx->hmac->scratch[ctx->hmac->scratch_len] = 0x80;
  memset(ctx->hmac->scratch + ctx->hmac->scratch_len + 1, 0,
        128 - ctx->hmac->scratch_len - 1);
  ptr = (uint64_t *) ctx->hmac->scratch;

  CVMX_MT_HSH_DATW(*ptr++, 0);
  CVMX_MT_HSH_DATW(*ptr++, 1);
  CVMX_MT_HSH_DATW(*ptr++, 2);
  CVMX_MT_HSH_DATW(*ptr++, 3);
  CVMX_MT_HSH_DATW(*ptr++, 4);
  CVMX_MT_HSH_DATW(*ptr++, 5);
  CVMX_MT_HSH_DATW(*ptr++, 6);
  CVMX_MT_HSH_DATW(*ptr++, 7);
  CVMX_MT_HSH_DATW(*ptr++, 8);
  CVMX_MT_HSH_DATW(*ptr++, 9);
  CVMX_MT_HSH_DATW(*ptr++, 10);
  CVMX_MT_HSH_DATW(*ptr++, 11);
  CVMX_MT_HSH_DATW(*ptr++, 12);
  CVMX_MT_HSH_DATW(*ptr++, 13);





  if (ctx->hmac->scratch_len < 112)
    {
      CVMX_MT_HSH_DATWZ(14);
      CVMX_MT_HSH_STARTSHA512(bits);
    }
  else
    {
      CVMX_MT_HSH_DATW(*ptr++, 14);
      CVMX_MT_HSH_STARTSHA512(*ptr);
      CVMX_MT_HSH_DATWZ(0);
      CVMX_MT_HSH_DATWZ(1);
      CVMX_MT_HSH_DATWZ(2);
      CVMX_MT_HSH_DATWZ(3);
      CVMX_MT_HSH_DATWZ(4);
      CVMX_MT_HSH_DATWZ(5);
      CVMX_MT_HSH_DATWZ(6);
      CVMX_MT_HSH_DATWZ(7);
      CVMX_MT_HSH_DATWZ(8);
      CVMX_MT_HSH_DATWZ(9);
      CVMX_MT_HSH_DATWZ(10);
      CVMX_MT_HSH_DATWZ(11);
      CVMX_MT_HSH_DATWZ(12);
      CVMX_MT_HSH_DATWZ(13);
      CVMX_MT_HSH_DATWZ(14);
      CVMX_MT_HSH_STARTSHA512(bits);
    }

  /* Get result of inner hash */
  CVMX_MF_HSH_IVW(temp[0], 0);
  CVMX_MF_HSH_IVW(temp[1], 1);
  CVMX_MF_HSH_IVW(temp[2], 2);
  CVMX_MF_HSH_IVW(temp[3], 3);
  CVMX_MF_HSH_IVW(temp[4], 4);
  CVMX_MF_HSH_IVW(temp[5], 5);
  if (ctx->u.flag.is_sha512)
    {
      CVMX_MF_HSH_IVW(temp[6], 6);
      CVMX_MF_HSH_IVW(temp[7], 7);
    }
 else
    {
      temp[6] = 0;
      temp[7] = 0;
    }

  /* Store result of outer hash */
  CVMX_MT_HSH_IVW(ctx->outer_auth[0], 0);
  CVMX_MT_HSH_IVW(ctx->outer_auth[1], 1);
  CVMX_MT_HSH_IVW(ctx->outer_auth[2], 2);
  CVMX_MT_HSH_IVW(ctx->outer_auth[3], 3);
  CVMX_MT_HSH_IVW(ctx->outer_auth[4], 4);
  CVMX_MT_HSH_IVW(ctx->outer_auth[5], 5);
  CVMX_MT_HSH_IVW(ctx->outer_auth[6], 6);
  CVMX_MT_HSH_IVW(ctx->outer_auth[7], 7);

  CVMX_MT_HSH_DATW(temp[0], 0);
  CVMX_MT_HSH_DATW(temp[1], 1);
  CVMX_MT_HSH_DATW(temp[2], 2);
  CVMX_MT_HSH_DATW(temp[3], 3);
  CVMX_MT_HSH_DATW(temp[4], 4);
  CVMX_MT_HSH_DATW(temp[5], 5);
  if (ctx->u.flag.is_sha384)
    {
      CVMX_MT_HSH_DATW(0x8000000000000000ull, 6);
      CVMX_MT_HSH_DATWZ(7);
      CVMX_MT_HSH_DATWZ(8);
      CVMX_MT_HSH_DATWZ(9);
      CVMX_MT_HSH_DATWZ(10);
      CVMX_MT_HSH_DATWZ(11);
      CVMX_MT_HSH_DATWZ(12);
      CVMX_MT_HSH_DATWZ(13);
      CVMX_MT_HSH_DATWZ(14);
      CVMX_MT_HSH_STARTSHA512(0x0000000000000580ull);
    }
  else
    {
      OCTEON_SE_ASSERT(ctx->u.flag.is_sha512);
      CVMX_MT_HSH_DATW(temp[6], 6);
      CVMX_MT_HSH_DATW(temp[7], 7);
      CVMX_MT_HSH_DATW(0x8000000000000000ull, 8);
      CVMX_MT_HSH_DATWZ(9);
      CVMX_MT_HSH_DATWZ(10);
      CVMX_MT_HSH_DATWZ(11);
      CVMX_MT_HSH_DATWZ(12);
      CVMX_MT_HSH_DATWZ(13);
      CVMX_MT_HSH_DATWZ(14);
      CVMX_MT_HSH_STARTSHA512(0x0000000000000600ull);
    }

  CVMX_MF_HSH_IVW(digest[0], 0);
  CVMX_MF_HSH_IVW(digest[1], 1);
  CVMX_MF_HSH_IVW(digest[2], 2);
  if (ctx->u.flag.is_sha512)
    CVMX_MF_HSH_IVW(digest[3], 3);
}
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
/*  ------------- START AES - SHA 1 BLOCK--------------------*/

void se_fastpath_aes_sha1_init(void *context,
                               const unsigned char *cipher_key,
                               size_t cipher_keylen,
                               const unsigned char *mac_key,
                               size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_aes_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_sha1_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha1 = 1;
}

void
se_fastpath_aes_sha1_encrypt(void *context,
                             SeFastpathPacketBuffer dst,
                             SeFastpathPacketBuffer src,
                             SeFastpathMacExtraInfo extra_mac,
                             SeFastpathEspExtraInfo extra_info,
                             uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  register uint64_t result0, result1;
  uint8_t i;
  uint16_t len;
  uint64_t pad[4];
  SeFastpathTranformMacAlgo algo;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if (cvmx_unlikely(ctx->u.flag.is_sha256))
    algo = OCTEON_SE_FASTPATH_ALGORITHM_SHA_256;
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
    algo = OCTEON_SE_FASTPATH_ALGORITHM_SHA_1;

  octeon_aes_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len, algo);

  CVMX_MT_AES_IV(extra_info->iv[0], 0);
  CVMX_MT_AES_IV(extra_info->iv[1], 1);

  /* Write out the IV in the output buffer */
  octeon_se_fastpath_buffer_write_double_word(dst, extra_info->iv[0],
                                              extra_info->iv[1]);

  octeon_load_hash_scratch_double_word(ctx->hmac,
                                       extra_info->iv[0], extra_info->iv[1],
                                       algo);

  len = src->total_bytes;
  if (cvmx_likely(len >= 16))
    {
      /* Read input and start AES encryption */
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_ENC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_ENC_CBC1(word1);
      len -= 16;

      while (len >= 16)
        {
          /* Get AES encryption result. */
          CVMX_MF_AES_RESULT(result0, 0);
          CVMX_MF_AES_RESULT(result1, 1);

          /* Read input and start AES encryption */
          word0 = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_AES_ENC_CBC0(word0);
          word1 = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_AES_ENC_CBC1(word1);
          len -= 16;

          /* Add AES encryption result to hash and write output. */
          octeon_load_hash_scratch_double_word(ctx->hmac, result0, result1,
                                               algo);
          octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
        }

      /* Get AES encryption result, add to hash and write output. */
      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);
      octeon_load_hash_scratch_double_word(ctx->hmac, result0, result1,
                                           algo);
      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
    }

  /* Maximum length of padding is 17 bytes including len and nh. */
  OCTEON_SE_ASSERT(extra_info->pad_len <= 15);
  len = insert_pad(src, extra_info, len, (uint8_t *) pad);

  OCTEON_SE_ASSERT(len % 16 == 0);

  i = 0;
  do
    {
      OCTEON_SE_ASSERT(i < 4);
      CVMX_MT_AES_ENC_CBC0(pad[i]);
      i++;
      CVMX_MT_AES_ENC_CBC1(pad[i]);
      i++;

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);

      octeon_load_hash_scratch_double_word(ctx->hmac, result0, result1,
                                           algo);
      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
      len -= 16;
    }
  while (len > 0);

  /* The complete payload has been encrypted at this stage. Complete
     inner and outer hash operation. */
  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac,
                             (uint8_t *) &extra_mac->suffix, sizeof(uint32_t),
                             algo);
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if (cvmx_unlikely(ctx->u.flag.is_sha256))
    octeon_sha256_finish_outer_hmac(ctx, digest);
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
  octeon_sha1_finish_outer_hmac(ctx, digest);
}

void
se_fastpath_aes_sha1_decrypt(void *context,
                             SeFastpathPacketBuffer dst,
                             SeFastpathPacketBuffer src,
                             SeFastpathMacExtraInfo extra_mac,
                             SeFastpathEspExtraInfo extra_info,
                             uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  register uint64_t result0, result1;
  uint16_t len, i;
  SeFastpathPadInfoStruct pad[1];
  SeFastpathTranformMacAlgo algo = OCTEON_SE_FASTPATH_ALGORITHM_SHA_1;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if (cvmx_unlikely(ctx->u.flag.is_sha256))
    algo = OCTEON_SE_FASTPATH_ALGORITHM_SHA_256;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

  octeon_aes_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len, algo);

  CVMX_MT_AES_IV(extra_info->iv[0], 0);
  CVMX_MT_AES_IV(extra_info->iv[1], 1);

  octeon_load_hash_scratch_double_word(ctx->hmac,
                                       extra_info->iv[0], extra_info->iv[1],
                                       algo);
  len = src->total_bytes;

  /* Assert that input length has been checked for sanity. */
  OCTEON_SE_ASSERT(len % 16 == 0);

  while (len > 32)
    {
      /* Read input and start AES decryption. */
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC1(word1);

      /* Add input to hash. */
      octeon_load_hash_scratch_double_word(ctx->hmac, word0, word1,
                                           algo);

      /* Get AES decryption result and write output. */
      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);

      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
      len -= 16;
    }

  OCTEON_SE_ASSERT(len == 32);

  i = 0;
  while (len > 0)
    {
      /* Read input and start AES decryption. */
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC1(word1);

      /* Add input to hash. */
      octeon_load_hash_scratch_double_word(ctx->hmac, word0, word1, algo);

      /* Get AES decryption result. */
      CVMX_MF_AES_RESULT(pad->pad_info.u64[i], 0);
      i++;
      CVMX_MF_AES_RESULT(pad->pad_info.u64[i], 1);
      i++;

      len -= 16;
    }

  pad->pad_len = i * 8;
  len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

  /* Write out the actual decrypted packet now */
  i = 0;
  while (len >= 8)
    {
      octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
      len -= 8;
    }
  octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i], len);

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *) &extra_mac->suffix,
                             sizeof(uint32_t),
                             algo);
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if (cvmx_unlikely(ctx->u.flag.is_sha256))
    octeon_sha256_finish_outer_hmac(ctx, digest);
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
  octeon_sha1_finish_outer_hmac(ctx, digest);
}

/*  ------------- END AES - SHA 1 BLOCK--------------------*/


/* ------------START AES - MD5 BLOCK ----------------------*/

void
se_fastpath_aes_md5_init(void *context,
                         const unsigned char *cipher_key,
                         size_t cipher_keylen,
                         const unsigned char *mac_key,
                         size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_aes_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_md5_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
}

void
se_fastpath_aes_md5_encrypt(void *context,
                            SeFastpathPacketBuffer dst,
                            SeFastpathPacketBuffer src,
                            SeFastpathMacExtraInfo extra_mac,
                            SeFastpathEspExtraInfo extra_info,
                            uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  register uint64_t result0, result1;
  uint16_t len;
  uint64_t pad[4];
  uint8_t i;

  octeon_aes_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len,
                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  CVMX_MT_AES_IV(extra_info->iv[0], 0);
  CVMX_MT_AES_IV(extra_info->iv[1], 1);

  octeon_se_fastpath_buffer_write_double_word(dst, extra_info->iv[0],
                                              extra_info->iv[1]);
  octeon_load_hash_scratch_double_word(ctx->hmac,
                                       extra_info->iv[0], extra_info->iv[1],
                                       OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  len = src->total_bytes;
  if (cvmx_likely(len >= 16))
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_ENC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_ENC_CBC1(word1);
      len -= 16;

      while (len >= 16)
        {
          CVMX_MF_AES_RESULT(result0, 0);
          CVMX_MF_AES_RESULT(result1, 1);

          word0 = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_AES_ENC_CBC0(word0);
          word1 = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_AES_ENC_CBC1(word1);
          len -= 16;

          octeon_load_hash_scratch_double_word(ctx->hmac, result0, result1,
                                             OCTEON_SE_FASTPATH_ALGORITHM_MD5);
          octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
        }

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);
      octeon_load_hash_scratch_double_word(ctx->hmac, result0, result1,
                                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);
      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
    }

  /* Maximum length of padding is 17 bytes including len and nh. */
  OCTEON_SE_ASSERT(extra_info->pad_len <= 15);
  len = insert_pad(src, extra_info, len, (uint8_t *) pad);
  OCTEON_SE_ASSERT(len % 16 == 0);

  i = 0;
  do
    {
      OCTEON_SE_ASSERT(i < 4);
      CVMX_MT_AES_ENC_CBC0(pad[i]);
      i++;
      CVMX_MT_AES_ENC_CBC1(pad[i]);
      i++;

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);

      octeon_load_hash_scratch_double_word(ctx->hmac, result0, result1,
                                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);
      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
      len -= 16;
    }
  while (len > 0);

  /* Complete inner hash */
  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *)&extra_mac->suffix,
                             sizeof (uint32_t),
                             OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  octeon_md5_finish_outer_hash(ctx, digest);
}


void
se_fastpath_aes_md5_decrypt(void *context,
                            SeFastpathPacketBuffer dst,
                            SeFastpathPacketBuffer src,
                            SeFastpathMacExtraInfo extra_mac,
                            SeFastpathEspExtraInfo extra_info,
                            uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  register uint64_t result0, result1;
  uint16_t len, i = 0;
  SeFastpathPadInfoStruct pad[1];

  octeon_aes_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len,
                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  CVMX_MT_AES_IV(extra_info->iv[0], 0);
  CVMX_MT_AES_IV(extra_info->iv[1], 1);

  octeon_load_hash_scratch_double_word(ctx->hmac,
                                       extra_info->iv[0], extra_info->iv[1],
                                       OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  len = src->total_bytes;

  /* Assert that input length has been checked for sanity. */
  OCTEON_SE_ASSERT(len % 16 == 0);

  while (len > 32)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC1(word1);

      octeon_load_hash_scratch_double_word(ctx->hmac, word0, word1,
                                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);

      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
      len -= 16;
    }

  OCTEON_SE_ASSERT(len == 32);

  while (len > 0)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC1(word1);

      octeon_load_hash_scratch_double_word(ctx->hmac, word0, word1,
                                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);

      CVMX_MF_AES_RESULT(pad->pad_info.u64[i], 0);
      i++;
      CVMX_MF_AES_RESULT(pad->pad_info.u64[i], 1);
      i++;

      len -= 16;
    }

  pad->pad_len = i * 8;
  len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

  /* Write out the actual decrypted packet now */
  i = 0;
  while (len >= 8)
    {
      octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
      len -= 8;
    }
  octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i], len);

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *)&extra_mac->suffix,
                             sizeof (uint32_t),
                             OCTEON_SE_FASTPATH_ALGORITHM_MD5);
  /* Complete inner hash */
  octeon_md5_finish_outer_hash(ctx, digest);
}

/*  ------------- END AES - MD5 BLOCK--------------------*/


/*  ------------- START 3DES - SHA 1 BLOCK--------------------*/

void se_fastpath_3des_sha1_init(void *context,
                                const unsigned char *cipher_key,
                                size_t cipher_keylen,
                                const unsigned char *mac_key,
                                size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_3des_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_sha1_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha1 = 1;
}

void
se_fastpath_3des_sha1_encrypt(void *context,
                              SeFastpathPacketBuffer dst,
                              SeFastpathPacketBuffer src,
                              SeFastpathMacExtraInfo extra_mac,
                              SeFastpathEspExtraInfo extra_info,
                              uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word;
  register uint64_t result;
  uint16_t len;
  uint64_t pad[2];
  uint8_t i;

  octeon_3des_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len,
                           OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  CVMX_MT_3DES_IV(extra_info->iv[0]);

  octeon_se_fastpath_buffer_write_word(dst, extra_info->iv[0]);
  octeon_load_hash_scratch_word(ctx->hmac, extra_info->iv[0],
                                OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  len = src->total_bytes;
  if (cvmx_likely(len >= 8))
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_3DES_ENC_CBC(word);
      len -= 8;

      while (len >= 8)
        {
          CVMX_MF_3DES_RESULT(result);

          word = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_3DES_ENC_CBC(word);
          len -= 8;

          octeon_load_hash_scratch_word(ctx->hmac, result,
                                        OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
          octeon_se_fastpath_buffer_write_word(dst, result);
        }

      CVMX_MF_3DES_RESULT(result);
      octeon_load_hash_scratch_word(ctx->hmac, result,
                                    OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
      octeon_se_fastpath_buffer_write_word(dst, result);
    }

  /* Maximum length of padding is 9 bytes including len and nh. */
  OCTEON_SE_ASSERT(extra_info->pad_len <= 7);
  len = insert_pad(src, extra_info, len, (uint8_t *) pad);

  OCTEON_SE_ASSERT(len % 8 == 0);

  i = 0;
  do
    {
      OCTEON_SE_ASSERT(i < 2);
      CVMX_MT_3DES_ENC_CBC(pad[i]);
      i++;

      CVMX_MF_3DES_RESULT(result);

      octeon_load_hash_scratch_word(ctx->hmac, result,
                                    OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
      octeon_se_fastpath_buffer_write_word(dst, result);

      len -= 8;
    }
  while (len > 0);

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *)&extra_mac->suffix,
                             sizeof (uint32_t),
                             OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  octeon_sha1_finish_outer_hmac(ctx, digest);
}

void
se_fastpath_3des_sha1_decrypt(void *context,
                              SeFastpathPacketBuffer dst,
                              SeFastpathPacketBuffer src,
                              SeFastpathMacExtraInfo extra_mac,
                              SeFastpathEspExtraInfo extra_info,
                              uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word;
  register uint64_t result;
  uint16_t len, i;
  SeFastpathPadInfoStruct pad[1];

  octeon_3des_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len,
                           OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  CVMX_MT_3DES_IV(extra_info->iv[0]);

  octeon_load_hash_scratch_word(ctx->hmac, extra_info->iv[0],
                                OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  len = src->total_bytes;

  /* Assert that input length has been for sanity. */
  OCTEON_SE_ASSERT(len % 8 == 0);

  while (len > 16)
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_3DES_DEC_CBC(word);
      octeon_load_hash_scratch_word(ctx->hmac, word,
                                    OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
      CVMX_MF_3DES_RESULT(result);
      octeon_se_fastpath_buffer_write_word(dst, result);
      len -= 8;
    }

  OCTEON_SE_ASSERT(len == 16);

  i = 0;
  while (len > 0)
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_3DES_DEC_CBC(word);
      octeon_load_hash_scratch_word(ctx->hmac, word,
                                    OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
      CVMX_MF_3DES_RESULT(pad->pad_info.u64[i]);
      i++;
      len -= 8;
    }

  pad->pad_len = i * 8;
  len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

  /* Write out the actual decrypted packet now */
  i = 0;
  while (len >= 8)
    {
      octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
      len -= 8;
    }
  octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i], len);

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *)&extra_mac->suffix,
                             sizeof (uint32_t),
                             OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

  octeon_sha1_finish_outer_hmac(ctx, digest);
}

/*  ------------- END 3DES - SHA 1 BLOCK--------------------*/


/*  ------------- START 3DES - MD5 BLOCK--------------------*/

void se_fastpath_3des_md5_init(void *context,
                               const unsigned char *cipher_key,
                               size_t cipher_keylen,
                               const unsigned char *mac_key,
                               size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_3des_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_md5_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
}

void
se_fastpath_3des_md5_encrypt(void *context,
                             SeFastpathPacketBuffer dst,
                             SeFastpathPacketBuffer src,
                             SeFastpathMacExtraInfo extra_mac,
                             SeFastpathEspExtraInfo extra_info,
                             uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word;
  register uint64_t result;
  uint16_t len;
  uint64_t pad[2];
  uint8_t i = 0;

  octeon_3des_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len,
                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  CVMX_MT_3DES_IV(extra_info->iv[0]);

  octeon_se_fastpath_buffer_write_word(dst, extra_info->iv[0]);
  octeon_load_hash_scratch_word(ctx->hmac, extra_info->iv[0],
                                OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  len = src->total_bytes;
  if (cvmx_likely(len >= 8))
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_3DES_ENC_CBC(word);
      len -= 8;

      while (len >= 8)
        {
          CVMX_MF_3DES_RESULT(result);

          word = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_3DES_ENC_CBC(word);
          len -= 8;

          octeon_load_hash_scratch_word(ctx->hmac, result,
                                        OCTEON_SE_FASTPATH_ALGORITHM_MD5);
          octeon_se_fastpath_buffer_write_word(dst, result);
        }

      CVMX_MF_3DES_RESULT(result);
      octeon_load_hash_scratch_word(ctx->hmac, result,
                                    OCTEON_SE_FASTPATH_ALGORITHM_MD5);
      octeon_se_fastpath_buffer_write_word(dst, result);
    }
  /* Maximum length of padding is 9 bytes including len and nh. */
  OCTEON_SE_ASSERT(extra_info->pad_len <= 7);
  len = insert_pad(src, extra_info, len, (uint8_t *) pad);

  OCTEON_SE_ASSERT(len % 8 == 0);
  do
    {
      OCTEON_SE_ASSERT(i < 2);
      CVMX_MT_3DES_ENC_CBC(pad[i]);
      i ++;
      CVMX_MF_3DES_RESULT(result);
      octeon_load_hash_scratch_word(ctx->hmac, result,
                                    OCTEON_SE_FASTPATH_ALGORITHM_MD5);
      octeon_se_fastpath_buffer_write_word(dst, result);
      len -= 8;
    }
  while (len > 0);

  /* Complete inner hash */
  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *)&extra_mac->suffix,
                             sizeof (uint32_t),
                             OCTEON_SE_FASTPATH_ALGORITHM_MD5);
  octeon_md5_finish_outer_hash(ctx, digest);
}

void
se_fastpath_3des_md5_decrypt(void *context,
                             SeFastpathPacketBuffer dst,
                             SeFastpathPacketBuffer src,
                             SeFastpathMacExtraInfo extra_mac,
                             SeFastpathEspExtraInfo extra_info,
                             uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word;
  register uint64_t result;
  uint16_t len, i = 0;
  SeFastpathPadInfoStruct pad[1];

  octeon_3des_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len,
                           OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  CVMX_MT_3DES_IV(extra_info->iv[0]);

  octeon_load_hash_scratch_word(ctx->hmac, extra_info->iv[0],
                                OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  len = src->total_bytes;

  /* Assert that input length has been checked for sanity. */
  OCTEON_SE_ASSERT(len % 8 == 0);

  while (len > 16)
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_3DES_DEC_CBC(word);
      octeon_load_hash_scratch_word(ctx->hmac, word,
                                    OCTEON_SE_FASTPATH_ALGORITHM_MD5);
      CVMX_MF_3DES_RESULT(result);
      octeon_se_fastpath_buffer_write_word(dst, result);
      len -= 8;
    }

  OCTEON_SE_ASSERT(len == 16);

  while (len > 0)
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_3DES_DEC_CBC(word);
      octeon_load_hash_scratch_word(ctx->hmac, word,
                                    OCTEON_SE_FASTPATH_ALGORITHM_MD5);
      CVMX_MF_3DES_RESULT(pad->pad_info.u64[i]);
      i++;
      len -= 8;
    }

  pad->pad_len = i * 8;
  len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

  /* Write out the actual decrypted packet now */
  i = 0;
  while (len >= 8)
    {
      octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
      len -= 8;
    }
  octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i], len);

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *)&extra_mac->suffix,
                             sizeof (uint32_t),
                             OCTEON_SE_FASTPATH_ALGORITHM_MD5);

  octeon_md5_finish_outer_hash(ctx, digest);
}

/*  ------------- END 3DES - MD5 BLOCK--------------------*/

/* -------------- START NULL - SHA 1 BLOCK ---------------*/
static inline void
se_fastpath_null_hmac_init(void *context,
                           const unsigned char *cipher_key,
                           size_t cipher_keylen,
                           const unsigned char *mac_key,
                           size_t mac_keylen,
                           SeFastpathTranformMacAlgo algo)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  ctx->u.u8 = 0;
#if defined OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if (cvmx_unlikely(algo == OCTEON_SE_FASTPATH_ALGORITHM_SHA_256))
    {
      octeon_sha256_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
      ctx->u.flag.is_sha256 = 1;
    }
   else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
  if (cvmx_likely(algo == OCTEON_SE_FASTPATH_ALGORITHM_SHA_1))
    {
      octeon_sha1_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
      ctx->u.flag.is_sha1 = 1;
    }
  else
    {
      octeon_md5_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
    }
}

static inline void
se_fastpath_null_hmac_update(void *context,
                             const unsigned char *data,
                             size_t len,
                             SeFastpathTranformMacAlgo algo)
{
  SeFastpathCipherHmacCtx ctx = context;
  octeon_load_hash_scratch(ctx->hmac, data, len, algo);
}

static inline void
se_fastpath_null_hmac_insert_pad_and_hmac(void *context,
                                          SeFastpathPacketBuffer dst,
                                          SeFastpathPacketBuffer src,
                                          SeFastpathMacExtraInfo extra_mac,
                                          SeFastpathEspExtraInfo extra_info,
                                          SeFastpathTranformMacAlgo algo)

{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  uint64_t temp;
  uint64_t pad[2];
  uint16_t len;
  uint8_t i;

  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len, algo);

  len = src->total_bytes;
  while (len >= 16)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_double_word(ctx->hmac, word0, word1, algo);
      octeon_se_fastpath_buffer_write_double_word(dst, word0, word1);
      len -= 16;
    }
  OCTEON_SE_ASSERT(len < 16);

  while (len >= 8)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_word(ctx->hmac, word0, algo);
      octeon_se_fastpath_buffer_write_word(dst, word0);
      len -= 8;
    }
  OCTEON_SE_ASSERT(len < 8);

  if (extra_info)
    {
      len = insert_pad(src, extra_info, len, (uint8_t *) pad);

      OCTEON_SE_ASSERT((len % 4) == 0);
      OCTEON_SE_ASSERT(len <= 12);

      i = 0;
      if (len >= 8)
        {
          octeon_load_hash_scratch_word(ctx->hmac, pad[i], algo);
          octeon_se_fastpath_buffer_write_word(dst, pad[i]);
          i++;
          len -= 8;
        }

      OCTEON_SE_ASSERT(i < 2);
      OCTEON_SE_ASSERT(len < 8);
      octeon_load_hash_scratch(ctx->hmac, (uint8_t *) &pad[i], len, algo);
      octeon_se_fastpath_buffer_write_partial_word(dst, pad[i], len);
    }
  else if (len > 0)
    {
      temp = octeon_se_fastpath_buffer_read_partial_word(src, len);
      octeon_load_hash_scratch(ctx->hmac, (uint8_t *) &temp, len, algo);
      octeon_se_fastpath_buffer_write_partial_word(dst, temp, len);
    }

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *) &extra_mac->suffix,
                             sizeof(uint32_t), algo);
}

static inline void
se_fastpath_null_hmac_remove_pad_and_hmac(void *context,
                                          SeFastpathPacketBuffer dst,
                                          SeFastpathPacketBuffer src,
                                          SeFastpathMacExtraInfo extra_mac,
                                          SeFastpathEspExtraInfo extra_info,
                                          SeFastpathTranformMacAlgo algo)

{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  uint64_t temp;
  uint16_t len;
  uint8_t i;
  SeFastpathPadInfoStruct pad[1];

  octeon_load_hash_scratch(ctx->hmac, extra_mac->prefix.u8,
                           extra_mac->prefix_len, algo);

  len = src->total_bytes;
  while (len > 20)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_double_word(ctx->hmac, word0, word1, algo);
      octeon_se_fastpath_buffer_write_double_word(dst, word0, word1);
      len -= 16;
    }
  OCTEON_SE_ASSERT(len <= 20);
  OCTEON_SE_ASSERT(len >= 5);

  while (len > 12)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_word(ctx->hmac, word0, algo);
      octeon_se_fastpath_buffer_write_word(dst, word0);
      len -= 8;
    }
  OCTEON_SE_ASSERT(len <= 12);
  OCTEON_SE_ASSERT(len >= 5);

  if (extra_info)
    {
      /* Read input in to pad buffer. */
      pad->pad_len = len;
      i = 0;
      if (len >= 8)
        {
          pad->pad_info.u64[i] = octeon_se_fastpath_buffer_read_word(src);
          i++;
          len -= 8;
        }
      if (len > 0)
        pad->pad_info.u64[i] =
          octeon_se_fastpath_buffer_read_partial_word(src, len);

      /* Add to hmac */
      octeon_load_hash_scratch(ctx->hmac, &pad->pad_info.u8[0], pad->pad_len,
                               algo);

      /* Verify padding */
      len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

      /* Write out the actual data */
      i = 0;
      if (len >= 8)
        {
          octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
          len -= 8;
        }
      OCTEON_SE_ASSERT(len < 8);
      octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i],
                                                   len);
    }
  else if (len > 0)
    {
      if (len >= 8)
        {
          word0 = octeon_se_fastpath_buffer_read_word(src);
          octeon_load_hash_scratch_word(ctx->hmac, word0, algo);
          octeon_se_fastpath_buffer_write_word(dst, word0);
          len -= 8;
        }
      OCTEON_SE_ASSERT(len < 8);
      if (len > 0)
        {
      temp = octeon_se_fastpath_buffer_read_partial_word(src, len);
      octeon_load_hash_scratch(ctx->hmac, (uint8_t *) &temp, len, algo);
      octeon_se_fastpath_buffer_write_partial_word(dst, temp, len);
    }
    }

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch(ctx->hmac, (uint8_t *) &extra_mac->suffix,
                             sizeof(uint32_t), algo);
}

void se_fastpath_null_sha1_init(void *context,
                                const unsigned char *cipher_key,
                                size_t cipher_keylen,
                                const unsigned char *mac_key,
                                size_t mac_keylen)
{
  return se_fastpath_null_hmac_init(context, cipher_key, cipher_keylen,
                                    mac_key, mac_keylen,
                                    OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
}

void se_fastpath_null_sha1_update(void *context,
                                  const unsigned char *data,
                                  size_t len)
{
  return se_fastpath_null_hmac_update(context, data, len,
                                      OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);

}

void
se_fastpath_null_sha1_insert_pad_and_hmac(void *context,
                                          SeFastpathPacketBuffer dst,
                                          SeFastpathPacketBuffer src,
                                          SeFastpathMacExtraInfo extra_mac,
                                          SeFastpathEspExtraInfo extra_info,
                                          uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  se_fastpath_null_hmac_insert_pad_and_hmac(context, dst, src,
                                           extra_mac, extra_info,
                                           OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
  octeon_sha1_finish_outer_hmac(ctx, digest);
}

void
se_fastpath_null_sha1_remove_pad_and_hmac(void *context,
                                          SeFastpathPacketBuffer dst,
                                          SeFastpathPacketBuffer src,
                                          SeFastpathMacExtraInfo extra_mac,
                                          SeFastpathEspExtraInfo extra_info,
                                          uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  se_fastpath_null_hmac_remove_pad_and_hmac(context, dst, src,
                                           extra_mac, extra_info,
                                           OCTEON_SE_FASTPATH_ALGORITHM_SHA_1);
  octeon_sha1_finish_outer_hmac(ctx, digest);
}

/* -------------- END NULL - SHA 1 BLOCK ---------------*/

/* -------------- START NULL - MD5 BLOCK ---------------*/

void se_fastpath_null_md5_init(void *context,
                               const unsigned char *cipher_key,
                               size_t cipher_keylen,
                               const unsigned char *mac_key,
                               size_t mac_keylen)
{
  return
    se_fastpath_null_hmac_init(context, cipher_key, cipher_keylen,
                               mac_key, mac_keylen,
                               OCTEON_SE_FASTPATH_ALGORITHM_MD5);
}

void se_fastpath_null_md5_update(void *context,
                                 const unsigned char *data,
                                 size_t len)
{
  return
    se_fastpath_null_hmac_update(context, data, len,
                                 OCTEON_SE_FASTPATH_ALGORITHM_MD5);

}

void
se_fastpath_null_md5_insert_pad_and_hmac(void *context,
                                         SeFastpathPacketBuffer dst,
                                         SeFastpathPacketBuffer src,
                                         SeFastpathMacExtraInfo extra_mac,
                                         SeFastpathEspExtraInfo extra_info,
                                         uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  se_fastpath_null_hmac_insert_pad_and_hmac(context, dst, src,
                                            extra_mac, extra_info,
                                            OCTEON_SE_FASTPATH_ALGORITHM_MD5);
  octeon_md5_finish_outer_hash(ctx, digest);
}

void
se_fastpath_null_md5_remove_pad_and_hmac(void *context,
                                         SeFastpathPacketBuffer dst,
                                         SeFastpathPacketBuffer src,
                                         SeFastpathMacExtraInfo extra_mac,
                                         SeFastpathEspExtraInfo extra_info,
                                         uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  se_fastpath_null_hmac_remove_pad_and_hmac(context, dst, src,
                                            extra_mac, extra_info,
                                            OCTEON_SE_FASTPATH_ALGORITHM_MD5);
  octeon_md5_finish_outer_hash(ctx, digest);
}

/* -------------- END NULL - MD5 BLOCK ---------------*/


#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
/* -------------- START AES - SHA-256 BLOCK ---------------*/
inline void
se_fastpath_aes_sha256_init(void *context,
                            const unsigned char *cipher_key,
                            size_t cipher_keylen,
                            const unsigned char *mac_key,
                            size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_aes_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_sha256_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha256 = 1;
}
/* -------------- END AES - SHA-256 BLOCK ---------------*/

/* -------------- START NULL - SHA-256 BLOCK ---------------*/
void se_fastpath_null_sha256_init(void *context,
                                  const unsigned char *cipher_key,
                                  size_t cipher_keylen,
                                  const unsigned char *mac_key,
                                  size_t mac_keylen)
{
  return se_fastpath_null_hmac_init(context, cipher_key, cipher_keylen,
                                    mac_key, mac_keylen,
                                    OCTEON_SE_FASTPATH_ALGORITHM_SHA_256);
}

void se_fastpath_null_sha256_update(void *context,
                                    const unsigned char *data,
                                    size_t len)
{
  return se_fastpath_null_hmac_update(context, data, len,
                                      OCTEON_SE_FASTPATH_ALGORITHM_SHA_256);
}

void
se_fastpath_null_sha256_insert_pad_and_hmac(void *context,
                                            SeFastpathPacketBuffer dst,
                                            SeFastpathPacketBuffer src,
                                            SeFastpathMacExtraInfo extra_mac,
                                            SeFastpathEspExtraInfo extra_info,
                                            uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  se_fastpath_null_hmac_insert_pad_and_hmac(context, dst, src,
                                         extra_mac, extra_info,
                                         OCTEON_SE_FASTPATH_ALGORITHM_SHA_256);
  octeon_sha256_finish_outer_hmac(ctx, digest);
}


void
se_fastpath_null_sha256_remove_pad_and_hmac(void *context,
                                            SeFastpathPacketBuffer dst,
                                            SeFastpathPacketBuffer src,
                                            SeFastpathMacExtraInfo extra_mac,
                                            SeFastpathEspExtraInfo extra_info,
                                            uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  se_fastpath_null_hmac_remove_pad_and_hmac(context, dst, src,
                                         extra_mac, extra_info,
                                         OCTEON_SE_FASTPATH_ALGORITHM_SHA_256);
  octeon_sha256_finish_outer_hmac(ctx, digest);
}

#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */


#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
/* -------------- START AES - SHA-384/512 BLOCK ---------------*/

void
se_fastpath_aes_sha384_init(void *context,
                            const unsigned char *cipher_key,
                            size_t cipher_keylen,
                            const unsigned char *mac_key,
                            size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_aes_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_sha384_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha384 = 1;
}

void
se_fastpath_aes_sha512_init(void *context,
                            const unsigned char *cipher_key,
                            size_t cipher_keylen,
                            const unsigned char *mac_key,
                            size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_aes_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_sha512_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha512 = 1;
}

void
se_fastpath_aes_sha512_encrypt(void *context,
                               SeFastpathPacketBuffer dst,
                               SeFastpathPacketBuffer src,
                               SeFastpathMacExtraInfo extra_mac,
                               SeFastpathEspExtraInfo extra_info,
                               uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  register uint64_t result0, result1;
  uint8_t i;
  uint16_t len;
  uint64_t pad[4];

  octeon_aes_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch_wide(ctx->hmac, extra_mac->prefix.u8,
                                extra_mac->prefix_len);

  CVMX_MT_AES_IV(extra_info->iv[0], 0);
  CVMX_MT_AES_IV(extra_info->iv[1], 1);

  /* Write out the IV in the output buffer */
  octeon_se_fastpath_buffer_write_double_word(dst, extra_info->iv[0],
                                              extra_info->iv[1]);

  octeon_load_hash_scratch_double_word_wide(ctx->hmac, extra_info->iv[0],
                                            extra_info->iv[1]);

  len = src->total_bytes;
  if (cvmx_likely(len >= 16))
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_ENC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_ENC_CBC1(word1);
      len -= 16;

      while (len >= 16)
        {
          CVMX_MF_AES_RESULT(result0, 0);
          CVMX_MF_AES_RESULT(result1, 1);

          word0 = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_AES_ENC_CBC0(word0);
          word1 = octeon_se_fastpath_buffer_read_word(src);
          CVMX_MT_AES_ENC_CBC1(word1);
          len -= 16;

          octeon_load_hash_scratch_double_word_wide(ctx->hmac, result0,
                                                    result1);
          octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
        }

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);
      octeon_load_hash_scratch_double_word_wide(ctx->hmac, result0, result1);
      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
    }

  /* Maximum length of padding is 17 bytes including len and nh. */
  OCTEON_SE_ASSERT(extra_info->pad_len <= 15);
  len = insert_pad(src, extra_info, len, (uint8_t *) pad);
  OCTEON_SE_ASSERT(len % 16 == 0);

  i = 0;
  do
    {
      OCTEON_SE_ASSERT(i < 4);
      CVMX_MT_AES_ENC_CBC0(pad[i]);
      i++;
      CVMX_MT_AES_ENC_CBC1(pad[i]);
      i++;

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);

      octeon_load_hash_scratch_double_word_wide(ctx->hmac, result0, result1);
      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
      len -= 16;
    }
  while (len > 0);

  /* The complete payload has been encrypted at this stage. Complete
     inner and outer hash operation. */

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch_wide(ctx->hmac,
                                  (uint8_t *) &extra_mac->suffix,
                                  sizeof(uint32_t));

  octeon_sha512_finish_outer_hmac(ctx, digest);
}


void
se_fastpath_aes_sha512_decrypt(void * context,
                               SeFastpathPacketBuffer dst,
                               SeFastpathPacketBuffer src,
                               SeFastpathMacExtraInfo extra_mac,
                               SeFastpathEspExtraInfo extra_info,
                               uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  register uint64_t result0, result1;
  uint16_t len, i;
  SeFastpathPadInfoStruct pad[1];

  octeon_aes_set_key(ctx->cipher);

  /* Copy the extra mac buffer to the mac chain  */
  octeon_load_hash_scratch_wide(ctx->hmac, extra_mac->prefix.u8,
                                extra_mac->prefix_len);

  CVMX_MT_AES_IV(extra_info->iv[0], 0);
  CVMX_MT_AES_IV(extra_info->iv[1], 1);

  octeon_load_hash_scratch_double_word_wide(ctx->hmac, extra_info->iv[0],
                                            extra_info->iv[1]);

  len = src->total_bytes;

  /* Assert that input length has been checked for sanity. */
  OCTEON_SE_ASSERT(len % 16 == 0);

  while (len > 32)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC1(word1);

      octeon_load_hash_scratch_double_word_wide(ctx->hmac, word0, word1);

      CVMX_MF_AES_RESULT(result0, 0);
      CVMX_MF_AES_RESULT(result1, 1);

      octeon_se_fastpath_buffer_write_double_word(dst, result0, result1);
      len -= 16;
    }

  OCTEON_SE_ASSERT(len == 32);

  i = 0;
  while (len > 0)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC0(word0);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      CVMX_MT_AES_DEC_CBC1(word1);

      octeon_load_hash_scratch_double_word_wide(ctx->hmac, word0, word1);

      CVMX_MF_AES_RESULT(pad->pad_info.u64[i], 0);
      i++;
      CVMX_MF_AES_RESULT(pad->pad_info.u64[i], 1);
      i++;

      len -= 16;
    }

  pad->pad_len = i * 8;
  len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

  /* Write out the actual decrypted packet now */
  i = 0;
  while (len >= 8)
    {
      octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
      len -= 8;
    }

  octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i], len);

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch_wide(ctx->hmac, (uint8_t *) &extra_mac->suffix,
                                  sizeof(uint32_t));

  octeon_sha512_finish_outer_hmac(ctx, digest);

}
/* -------------- END AES - SHA-384/512 BLOCK ---------------*/

/* -------------- START NULL - SHA-384/512 BLOCK ---------------*/
void
se_fastpath_null_sha384_init(void *context,
                             const unsigned char *cipher_key,
                             size_t cipher_keylen,
                             const unsigned char *mac_key,
                             size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_sha384_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha384 = 1;
}

void
se_fastpath_null_sha512_init(void *context,
                             const unsigned char *cipher_key,
                             size_t cipher_keylen,
                             const unsigned char *mac_key,
                             size_t mac_keylen)
{
  SeFastpathCipherHmacCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);

  octeon_sha512_init(ctx->hmac, mac_key, mac_keylen, ctx->outer_auth);
  ctx->u.u8 = 0;
  ctx->u.flag.is_sha512 = 1;
}

void
se_fastpath_null_sha512_update(void *context,
                               const unsigned char *data,
                               size_t len)
{
  SeFastpathCipherHmacCtx ctx = context;
  octeon_load_hash_scratch_wide(ctx->hmac, data, len);
}

void
se_fastpath_null_sha512_insert_pad_and_hmac(void *context,
                                            SeFastpathPacketBuffer dst,
                                            SeFastpathPacketBuffer src,
                                            SeFastpathMacExtraInfo extra_mac,
                                            SeFastpathEspExtraInfo extra_info,
                                            uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  uint64_t temp;
  uint64_t pad[2];
  uint16_t len;
  uint8_t i;

  octeon_load_hash_scratch_wide(ctx->hmac, extra_mac->prefix.u8,
                                extra_mac->prefix_len);

  len = src->total_bytes;
  while (len >= 16)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_double_word_wide(ctx->hmac, word0, word1);
      octeon_se_fastpath_buffer_write_double_word(dst, word0, word1);
      len -= 16;
    }
  OCTEON_SE_ASSERT(len < 16);

  while (len >= 8)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_word_wide(ctx->hmac, word0);
      octeon_se_fastpath_buffer_write_word(dst, word0);
      len -= 8;
    }
  OCTEON_SE_ASSERT(len < 8);

  if (extra_info)
    {
      len = insert_pad(src, extra_info, len, (uint8_t *) pad);

      OCTEON_SE_ASSERT((len % 4) == 0);
      OCTEON_SE_ASSERT(len <= 12);

      i = 0;
      if (len >= 8)
        {
          octeon_load_hash_scratch_word_wide(ctx->hmac, pad[i]);
          octeon_se_fastpath_buffer_write_word(dst, pad[i]);
          i++;
          len -= 8;
        }

      OCTEON_SE_ASSERT(i < 2);
      OCTEON_SE_ASSERT(len < 8);
      octeon_load_hash_scratch_wide(ctx->hmac, (uint8_t *) &pad[i], len);
      octeon_se_fastpath_buffer_write_partial_word(dst, pad[i], len);
    }
  else if (len > 0)
    {
      temp = octeon_se_fastpath_buffer_read_partial_word(src, len);
      octeon_load_hash_scratch_wide(ctx->hmac, (uint8_t *) &temp, len);
      octeon_se_fastpath_buffer_write_partial_word(dst, temp, len);
    }

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch_wide(ctx->hmac, (uint8_t *) &extra_mac->suffix,
                                  sizeof(uint32_t));
  octeon_sha512_finish_outer_hmac(ctx, digest);
}

void
se_fastpath_null_sha512_remove_pad_and_hmac(void *context,
                                            SeFastpathPacketBuffer dst,
                                            SeFastpathPacketBuffer src,
                                            SeFastpathMacExtraInfo extra_mac,
                                            SeFastpathEspExtraInfo extra_info,
                                            uint64_t *digest)
{
  SeFastpathCipherHmacCtx ctx = context;
  register uint64_t word0, word1;
  uint64_t temp;
  uint16_t len;
  uint8_t i;
  SeFastpathPadInfoStruct pad[1];

  octeon_load_hash_scratch_wide(ctx->hmac, extra_mac->prefix.u8,
                                extra_mac->prefix_len);

  len = src->total_bytes;
  while (len > 20)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      word1 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_double_word_wide(ctx->hmac, word0, word1);
      octeon_se_fastpath_buffer_write_double_word(dst, word0, word1);
      len -= 16;
    }
  OCTEON_SE_ASSERT(len <= 20);
  OCTEON_SE_ASSERT(len >= 5);

  while (len > 12)
    {
      word0 = octeon_se_fastpath_buffer_read_word(src);
      octeon_load_hash_scratch_word_wide(ctx->hmac, word0);
      octeon_se_fastpath_buffer_write_word(dst, word0);
      len -= 8;
    }
  OCTEON_SE_ASSERT(len <= 12);
  OCTEON_SE_ASSERT(len >= 5);

  if (extra_info)
    {
      /* Read input in to pad buffer. */
      pad->pad_len = len;
      i = 0;
      if (len >= 8)
        {
          pad->pad_info.u64[i] = octeon_se_fastpath_buffer_read_word(src);
          i++;
          len -= 8;
        }
      if (len > 0)
        pad->pad_info.u64[i] =
          octeon_se_fastpath_buffer_read_partial_word(src, len);

      /* Add to hmac */
      octeon_load_hash_scratch_wide(ctx->hmac, &pad->pad_info.u8[0],
                                    pad->pad_len);

      /* Verify padding */
      len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

      /* Write out the actual data */
      i = 0;
      if (len >= 8)
        {
          octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i++]);
          len -= 8;
        }
      OCTEON_SE_ASSERT(len < 8);
      octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i],
                                                   len);
    }
  else if (len > 0)
    {
      if (len >= 8)
        {
          word0 = octeon_se_fastpath_buffer_read_word(src);
          octeon_load_hash_scratch_word_wide(ctx->hmac, word0);
          octeon_se_fastpath_buffer_write_word(dst, word0);
          len -= 8;
        }
      OCTEON_SE_ASSERT(len < 8);
      if (len > 0)
        {
      temp = octeon_se_fastpath_buffer_read_partial_word(src, len);
      octeon_load_hash_scratch_wide(ctx->hmac, (uint8_t *) &temp, len);
      octeon_se_fastpath_buffer_write_partial_word(dst, temp, len);
    }
    }

  if (cvmx_unlikely(extra_mac->suffix_available))
    octeon_load_hash_scratch_wide(ctx->hmac, (uint8_t *) &extra_mac->suffix,
                                  sizeof(uint32_t));
  octeon_sha512_finish_outer_hmac(ctx, digest);
}
/* -------------- END NULL - SHA-384/512 BLOCK ---------------*/

#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
/* -------------- START AES - GCM BLOCK ---------------*/































/********************************************************/

static inline void
octeon_gmac_init(uint64_t *multiplier)
{
  /* Initialize polynomial. */
  CVMX_MT_GFM_POLY(0xe100);

  /* Initialize multiplier. */
  CVMX_MT_GFM_MUL(multiplier[0], 0);
  CVMX_MT_GFM_MUL(multiplier[1], 1);

  /* Clear state. */
  CVMX_MT_GFM_RESINP(0, 0);
  CVMX_MT_GFM_RESINP(0, 1);
}

static inline void
octeon_gmac_calculate_tag(size_t auth_data_len,
                          size_t cipher_data_len,
                          uint64_t *y_0,
                          uint64_t *result)
{
  /* Update GHASH. */
  CVMX_MT_GFM_XOR0((uint64_t) auth_data_len);
  CVMX_MT_GFM_XORMUL1((uint64_t) cipher_data_len);

  /* Get GHASH result. */
  CVMX_MF_GFM_RESINP(result[0], 0);
  CVMX_MF_GFM_RESINP(result[1], 1);

  result[0] ^= y_0[0];
  result[1] ^= y_0[1];
}

static inline void
octeon_gmac_calculate_tag_8(size_t auth_data_len,
                            size_t cipher_data_len,
                            uint64_t *y_0,
                            uint64_t *result)
{
  /* Update GHASH. */
  CVMX_MT_GFM_XOR0((uint64_t) auth_data_len);
  CVMX_MT_GFM_XORMUL1((uint64_t) cipher_data_len);

  /* Get GHASH result. */
  CVMX_MF_GFM_RESINP(result[0], 0);

  result[0] ^= y_0[0];
}

static inline void
octeon_aes_gcm_set_iv(uint32_t nonce,
                      uint64_t *iv,
                      SeFastpathAesGcmCtx context)
{
  union
  {
    uint8_t u8[16];
    uint64_t u64[2];
  } dummy_iv;

  /* Concatenate nonce, iv and initial counter. */
  OCTEON_SE_PUT_32BIT_ALIGNED(dummy_iv.u8, nonce);
  OCTEON_SE_PUT_64BIT(dummy_iv.u8 + 4, *iv);
  OCTEON_SE_PUT_32BIT_ALIGNED(dummy_iv.u8 + 12, 0x01);
  /* Since IV would be exactly 16 bytes long after prefixing nonce and
     suffixing (uint32_t)1 */

  context->y_0[0] = dummy_iv.u64[0];
  context->y_0[1] = dummy_iv.u64[1];

  OCTEON_SE_FASTPATH_ASM_NOREORDER();

  /* Start encrypting y0. */
  CVMX_MT_AES_ENC0(context->y_0[0]);
  CVMX_MT_AES_ENC1(context->y_0[1]);

  /* Initialize y1. */
  context->y_i->u64[0] = dummy_iv.u64[0];
  context->y_i->u64[1] = dummy_iv.u64[1];
  context->y_i->u32[3]++; /* generate counter for the next round */

  /* Get encrypted y0. */
  CVMX_MF_AES_RESULT(context->y_0[0], 0);
  CVMX_MF_AES_RESULT(context->y_0[1], 1);

  OCTEON_SE_FASTPATH_ASM_REORDER();
}

void se_fastpath_aes_gcm_init(void *context,
                              const unsigned char *cipher_key,
                              size_t cipher_keylen,
                              const unsigned char *mac_key,
                              size_t mac_keylen)
{
  SeFastpathAesGcmCtx ctx = context;

  OCTEON_SE_ASSERT(sizeof(*ctx) <= OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE);
  memset(ctx, 0, sizeof(*ctx));

  octeon_aes_init_key(ctx->cipher, cipher_key, cipher_keylen);
  octeon_aes_set_key(ctx->cipher);

  /* Calculate H by running encryption algorithm over 0 */
  CVMX_MT_AES_ENC0(0);
  CVMX_MT_AES_ENC1(0);

  CVMX_MF_AES_RESULT(ctx->H->u64[0], 0);
  CVMX_MF_AES_RESULT(ctx->H->u64[1], 1);

  /* Initialize GHASH */
  octeon_gmac_init(&ctx->H->u64[0]);
}

static inline void
octeon_aes_gcm_process_aad(uint64_t *data,
                           size_t len)
{
  SeFastpathAesGCM128BitUnion temp;
  uint16_t i = 0;

  while (cvmx_unlikely(len > 16))
    {
      CVMX_MT_GFM_XOR0(data[i]);
      i++;
      CVMX_MT_GFM_XORMUL1(data[i]);
      i++;

      len -= 16;
      i += 2;
    }

  /* The last authentication block */
  temp.u64[0] = 0;
  temp.u64[1] = 0;
  memcpy(&temp.u8[0], &data[i], len);

  CVMX_MT_GFM_XOR0(temp.u64[0]);
  CVMX_MT_GFM_XORMUL1(temp.u64[1]);
}

static inline void
octeon_aes_gcm_process_outbound(SeFastpathAesGcmCtx context,
                                SeFastpathPacketBuffer dst,
                                SeFastpathPacketBuffer src,
                                SeFastpathMacExtraInfo extra_mac,
                                SeFastpathEspExtraInfo extra_info)
{
  uint64_t word0, word1;
  uint16_t len, i;
  uint64_t pad[4];
  SeFastpathAesGCM128BitUnion result, mask;

  octeon_aes_set_key(context->cipher);

  /* Write out the IV in the output buffer. */
  octeon_se_fastpath_buffer_write_word(dst, extra_info->iv[0]);

  /* Set up the IV. */
  octeon_aes_gcm_set_iv(extra_info->cipher_nonce, &extra_info->iv[0], context);

  /* Start AES encryption. */
  CVMX_MT_AES_ENC0(context->y_i->u64[0]);
  CVMX_MT_AES_ENC1(context->y_i->u64[1]);

  /* The extra mac info needs to be authenticated. */
  octeon_aes_gcm_process_aad(extra_mac->prefix.u64, extra_mac->prefix_len);

  len = src->total_bytes;
  while (len >= 16)
    {
      /* Read input */
      word0 = octeon_se_fastpath_buffer_read_word(src);
      word1 = octeon_se_fastpath_buffer_read_word(src);

      OCTEON_SE_FASTPATH_ASM_NOREORDER();

      /* Get AES encryption result. */
      CVMX_MF_AES_RESULT(result.u64[0], 0);
      CVMX_MF_AES_RESULT(result.u64[1], 1);

      /* Increment counter for the next round. */
      context->y_i->u32[3]++;

      /* Start AES encryption. */
      CVMX_MT_AES_ENC0(context->y_i->u64[0]);
      CVMX_MT_AES_ENC1(context->y_i->u64[1]);

      OCTEON_SE_FASTPATH_ASM_REORDER();

      /* XOR AES result with input. */
      result.u64[0] ^= word0;
      result.u64[1] ^= word1;

      /* Feed output to GHASH. */
      CVMX_MT_GFM_XOR0(result.u64[0]);
      CVMX_MT_GFM_XORMUL1(result.u64[1]);

      /* Write output. */
      octeon_se_fastpath_buffer_write_double_word(dst, result.u64[0],
                                                  result.u64[1]);

      len -= 16;
    }
  OCTEON_SE_ASSERT(len < 16);

  /* Maximum length of padding is 5 bytes including len and nh. */
  OCTEON_SE_ASSERT(extra_info->pad_len <= 3);
  len = insert_pad(src, extra_info, len, (uint8_t *) pad);
  OCTEON_SE_ASSERT(len <= 20);

  i = 0;
  if (len >= 16)
    {
      OCTEON_SE_FASTPATH_ASM_NOREORDER();

      /* Get AES encryption result. */
      CVMX_MF_AES_RESULT(result.u64[0], 0);
      CVMX_MF_AES_RESULT(result.u64[1], 1);

      /* Start AES encryption. */
      if (len > 16)
        {
          /* Increment counter for the next round */
          context->y_i->u32[3]++;

          CVMX_MT_AES_ENC0(context->y_i->u64[0]);
          CVMX_MT_AES_ENC1(context->y_i->u64[1]);
        }

      OCTEON_SE_FASTPATH_ASM_REORDER();

      /* XOR AES result with input. */
      result.u64[0] ^= pad[0];
      result.u64[1] ^= pad[1];

      /* Feed output to GHASH. */
      CVMX_MT_GFM_XOR0(result.u64[0]);
      CVMX_MT_GFM_XORMUL1(result.u64[1]);

      /* Write output. */
      octeon_se_fastpath_buffer_write_double_word(dst, result.u64[0],
                                                  result.u64[1]);

      len -= 16;
      i = 2;
    }
  OCTEON_SE_ASSERT(len < 16);

  if (len > 0)
    {
      OCTEON_SE_ASSERT(i < 3);

      /* Create output mask from number of leftover bytes. */
      mask.u64[0] = 0;
      mask.u64[1] = 0;
      memset(&mask.u8[0], 0xff, len);

      /* Get AES encryption result. */
      CVMX_MF_AES_RESULT(result.u64[0], 0);
      CVMX_MF_AES_RESULT(result.u64[1], 1);

      /* XOR AES result with input and apply output mask. */
      result.u64[0] ^= pad[i];
      result.u64[1] ^= pad[i + 1];

      result.u64[0] &= mask.u64[0];
      result.u64[1] &= mask.u64[1];

      /* Feed output to GHASH. */
      CVMX_MT_GFM_XOR0(result.u64[0]);
      CVMX_MT_GFM_XORMUL1(result.u64[1]);

      /* Write output. */
      i = 0;
      if (len >= 8)
        {
          octeon_se_fastpath_buffer_write_word(dst, result.u64[0]);
          len -= 8;
          i = 1;
        }
      OCTEON_SE_ASSERT(len < 8);

      octeon_se_fastpath_buffer_write_partial_word(dst, result.u64[i], len);
    }
}

static inline void
octeon_aes_gcm_process_inbound(SeFastpathAesGcmCtx context,
                               SeFastpathPacketBuffer dst,
                               SeFastpathPacketBuffer src,
                               SeFastpathMacExtraInfo extra_mac,
                               SeFastpathEspExtraInfo extra_info)
{
  uint64_t word0, word1;
  uint16_t len, i;
  SeFastpathPadInfoStruct pad[1];
  SeFastpathAesGCM128BitUnion result, mask;

  octeon_aes_set_key(context->cipher);

  /* Set up the IV. */
  octeon_aes_gcm_set_iv(extra_info->cipher_nonce, &extra_info->iv[0], context);

  /* Start AES encryption. */
  CVMX_MT_AES_ENC0(context->y_i->u64[0]);
  CVMX_MT_AES_ENC1(context->y_i->u64[1]);

  /* Process additional authentication data. */
  octeon_aes_gcm_process_aad(extra_mac->prefix.u64, extra_mac->prefix_len);

  len = src->total_bytes;

  /* Assert that input length has been checked for sanity. */
  OCTEON_SE_ASSERT(len % 4 == 0);

  while (len > 20)
    {
      /* Read input. */
      word0 = octeon_se_fastpath_buffer_read_word(src);
      word1 = octeon_se_fastpath_buffer_read_word(src);

      /* Feed input to GHASH. */
      CVMX_MT_GFM_XOR0(word0);
      CVMX_MT_GFM_XORMUL1(word1);

      OCTEON_SE_FASTPATH_ASM_NOREORDER();

      /* Get AES encryption result. */
      CVMX_MF_AES_RESULT(result.u64[0], 0);
      CVMX_MF_AES_RESULT(result.u64[1], 1);

      /* Increment counter for the next round. */
      context->y_i->u32[3]++;

     /* Start AES encryption. */
      CVMX_MT_AES_ENC0(context->y_i->u64[0]);
      CVMX_MT_AES_ENC1(context->y_i->u64[1]);

      OCTEON_SE_FASTPATH_ASM_REORDER();

      /* XOR AES encryption result with input. */
      result.u64[0] ^= word0;
      result.u64[1] ^= word1;

      /* Write output. */
      octeon_se_fastpath_buffer_write_double_word(dst, result.u64[0],
                                                  result.u64[1]);

      len -= 16;
    }

  /* Must have atleast 5 bytes to process padding. */
  OCTEON_SE_ASSERT(len <= 20);
  OCTEON_SE_ASSERT(len >= 5);
  OCTEON_SE_ASSERT(len % 4 == 0);

  memset(pad, 0, sizeof (SeFastpathPadInfoStruct));
  pad->pad_len = len;

  /* Read input. */
  i = 0;
  while (len >= 8)
    {
      OCTEON_SE_ASSERT(i < 2);
      pad->pad_info.u64[i] = octeon_se_fastpath_buffer_read_word(src);
      i++;
      len -= 8;
    }
  if (len > 0)
    pad->pad_info.u64[i] =
      octeon_se_fastpath_buffer_read_partial_word(src, len);

  len = pad->pad_len;
  i = 0;
  if (len >= 16)
    {
      /* Feed input to GHASH. */
      CVMX_MT_GFM_XOR0(pad->pad_info.u64[0]);
      CVMX_MT_GFM_XORMUL1(pad->pad_info.u64[1]);

      OCTEON_SE_FASTPATH_ASM_NOREORDER();

      /* Get AES encryption result. */
      CVMX_MF_AES_RESULT(result.u64[0], 0);
      CVMX_MF_AES_RESULT(result.u64[1], 1);

      /* Start AES encryption. */
      if (len > 16)
        {
          /* Increment counter for the next round. */
          context->y_i->u32[3]++;

          CVMX_MT_AES_ENC0(context->y_i->u64[0]);
          CVMX_MT_AES_ENC1(context->y_i->u64[1]);
        }
      OCTEON_SE_FASTPATH_ASM_REORDER();

      /* XOR AES result with input. */
      pad->pad_info.u64[0] ^= result.u64[0];
      pad->pad_info.u64[1] ^= result.u64[1];

      i += 2;
      len -= 16;
    }
  OCTEON_SE_ASSERT(len < 16);

  if (len > 0)
    {
      OCTEON_SE_ASSERT(i < 3);

      /* Create output mask from number of leftover bytes. */
      mask.u64[0] = 0;
      mask.u64[1] = 0;
      memset(&mask.u8[0], 0xff, len);

      /* Feed input to GHASH. */
      CVMX_MT_GFM_XOR0(pad->pad_info.u64[i]);
      CVMX_MT_GFM_XORMUL1(pad->pad_info.u64[i + 1]);

      /* Get AES encryption result, XOR with input and apply output mask. */
      CVMX_MF_AES_RESULT(result.u64[0], 0);
      CVMX_MF_AES_RESULT(result.u64[1], 1);

      pad->pad_info.u64[i] ^= result.u64[0];
      pad->pad_info.u64[i + 1] ^= result.u64[1];

      pad->pad_info.u64[i] &= mask.u64[0];
      pad->pad_info.u64[i + 1] &= mask.u64[1];
    }

  len = verify_pad(pad, &extra_info->pad_len, &extra_info->nh);

  /* Write output. */
  i = 0;
  while (len >= 8)
    {
      OCTEON_SE_ASSERT(i < 2);
      octeon_se_fastpath_buffer_write_word(dst, pad->pad_info.u64[i]);
      len -= 8;
      i++;
    }
  if (len)
    octeon_se_fastpath_buffer_write_partial_word(dst, pad->pad_info.u64[i],
                                                 len);
}

void se_fastpath_aes_gcm_encrypt(void *ctx,
                                 SeFastpathPacketBuffer dst,
                                 SeFastpathPacketBuffer src,
                                 SeFastpathMacExtraInfo extra_mac,
                                 SeFastpathEspExtraInfo extra_info,
                                 uint64_t *digest)
{
  SeFastpathAesGcmCtx context = ctx;
  size_t total_len = src->total_bytes + 2 + extra_info->pad_len;

  octeon_aes_gcm_process_outbound(context, dst, src, extra_mac, extra_info);
  octeon_gmac_calculate_tag(extra_mac->prefix_len * 8, total_len * 8,
                            context->y_0, digest);
}

void se_fastpath_aes_gcm_decrypt(void *ctx,
                                 SeFastpathPacketBuffer dst,
                                 SeFastpathPacketBuffer src,
                                 SeFastpathMacExtraInfo extra_mac,
                                 SeFastpathEspExtraInfo extra_info,
                                 uint64_t *digest)
{
  SeFastpathAesGcmCtx context = ctx;
  size_t total_len = src->total_bytes;

  octeon_aes_gcm_process_inbound(context, dst, src, extra_mac, extra_info);
  octeon_gmac_calculate_tag(extra_mac->prefix_len * 8, total_len * 8,
                            context->y_0, digest);
}


void se_fastpath_aes_gcm_encrypt_8(void *ctx,
                                   SeFastpathPacketBuffer dst,
                                   SeFastpathPacketBuffer src,
                                   SeFastpathMacExtraInfo extra_mac,
                                   SeFastpathEspExtraInfo extra_info,
                                   uint64_t *digest)
{
  SeFastpathAesGcmCtx context = ctx;
  size_t total_len = src->total_bytes + 2 + extra_info->pad_len;

  octeon_aes_gcm_process_outbound(context, dst, src, extra_mac, extra_info);
  octeon_gmac_calculate_tag_8(extra_mac->prefix_len * 8, total_len * 8,
                              context->y_0, digest);
}

void se_fastpath_aes_gcm_decrypt_8(void *ctx,
                                   SeFastpathPacketBuffer dst,
                                   SeFastpathPacketBuffer src,
                                   SeFastpathMacExtraInfo extra_mac,
                                   SeFastpathEspExtraInfo extra_info,
                                   uint64_t *digest)
{
  SeFastpathAesGcmCtx context = ctx;
  size_t total_len = src->total_bytes;

  octeon_aes_gcm_process_inbound(context, dst, src, extra_mac, extra_info);
  octeon_gmac_calculate_tag_8(extra_mac->prefix_len * 8, total_len * 8,
                              context->y_0, digest);
}
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */
/* -------------- END AES - GCM BLOCK -----------------*/


/** These are actual combined transform struct in the sense that
 * they perform encryption and hashing simultaneously */
SeFastpathCombinedTransformStruct se_fastpath_aes_sha1_def =
  {
    "aes-cbc-hmac-sha1",
    16, 16, 16,
    20, 0,
    12,
    se_fastpath_aes_sha1_init,
    NULL,
    se_fastpath_aes_sha1_encrypt,
    se_fastpath_aes_sha1_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_aes_md5_def =
  {
    "aes-cbc-hmac-md5",
    16, 16, 16,
    16, 0,
    12,
    se_fastpath_aes_md5_init,
    NULL,
    se_fastpath_aes_md5_encrypt,
    se_fastpath_aes_md5_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_3des_sha1_def =
  {
    "3des-cbc-hmac-sha1",
    8, 24, 8,
    20, 0,
    12,
    se_fastpath_3des_sha1_init,
    NULL,
    se_fastpath_3des_sha1_encrypt,
    se_fastpath_3des_sha1_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_3des_md5_def =
  {
    "3des-cbc-hmac-md5",
    8, 24, 8,
    16, 0,
    12,
    se_fastpath_3des_md5_init,
    NULL,
    se_fastpath_3des_md5_encrypt,
    se_fastpath_3des_md5_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_null_sha1_def =
  {
    "null-hmac-sha1",
    0, 0, 4,
    20, 0,
    12,
    se_fastpath_null_sha1_init,
    se_fastpath_null_sha1_update,
    se_fastpath_null_sha1_insert_pad_and_hmac,
    se_fastpath_null_sha1_remove_pad_and_hmac
  };

SeFastpathCombinedTransformStruct se_fastpath_null_md5_def =
  {
    "null-hmac-md5",
    0, 0, 4,
    16, 0,
    12,
    se_fastpath_null_md5_init,
    se_fastpath_null_md5_update,
    se_fastpath_null_md5_insert_pad_and_hmac,
    se_fastpath_null_md5_remove_pad_and_hmac
  };

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
SeFastpathCombinedTransformStruct se_fastpath_aes_sha_256_def =
  {
    "aes-cbc-hmac-sha256",
    16, 16, 16,
    32, 0,
    16,
    se_fastpath_aes_sha256_init,
    NULL,
    se_fastpath_aes_sha1_encrypt,
    se_fastpath_aes_sha1_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_null_sha_256_def =
  {
     "null-hmac-sha256",
     0, 0, 4,
     32, 0,
     16,
     se_fastpath_null_sha256_init,
     se_fastpath_null_sha256_update,
     se_fastpath_null_sha256_insert_pad_and_hmac,
     se_fastpath_null_sha256_remove_pad_and_hmac
  };

#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
SeFastpathCombinedTransformStruct se_fastpath_aes_sha_384_def =
  {
    "aes-cbc-hmac-sha384",
    16, 16, 16,
    48, 0,
    24,
    se_fastpath_aes_sha384_init,
    NULL,
    se_fastpath_aes_sha512_encrypt,
    se_fastpath_aes_sha512_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_aes_sha_512_def =
  {
    "aes-cbc-hmac-sha512",
    16, 16, 16,
    64, 0,
    32,
    se_fastpath_aes_sha512_init,
    NULL,
    se_fastpath_aes_sha512_encrypt,
    se_fastpath_aes_sha512_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_null_sha_384_def =
  {
    "null-hmac-sha384",
    0, 0, 4,
    48, 0,
    24,
    se_fastpath_null_sha384_init,
    se_fastpath_null_sha512_update,
    se_fastpath_null_sha512_insert_pad_and_hmac,
    se_fastpath_null_sha512_remove_pad_and_hmac
  };

SeFastpathCombinedTransformStruct se_fastpath_null_sha_512_def =
  {
    "null-hmac-sha512",
    0, 0, 4,
    64, 0,
    32,
    se_fastpath_null_sha512_init,
    se_fastpath_null_sha512_update,
    se_fastpath_null_sha512_insert_pad_and_hmac,
    se_fastpath_null_sha512_remove_pad_and_hmac
  };

#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
SeFastpathCombinedTransformStruct se_fastpath_aes_gcm_def =
  {
    "aes-128-gcm",
    8, 16, 4,
    0, 1,
    16,
    se_fastpath_aes_gcm_init,
    NULL,
    se_fastpath_aes_gcm_encrypt,
    se_fastpath_aes_gcm_decrypt
  };

SeFastpathCombinedTransformStruct se_fastpath_aes_gcm_8_def =
  {
    "aes-128-gcm",
    8, 16, 4,
    0, 1,
    8,
    se_fastpath_aes_gcm_init,
    NULL,
    se_fastpath_aes_gcm_encrypt_8,
    se_fastpath_aes_gcm_decrypt_8
  };
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */



























/* ******************************************************************** */

SeFastpathCombinedTransform
octeon_se_fastpath_get_combined_transform(uint32_t transform,
                                          uint32_t mac_key_len)
{
  SeFastpathCombinedTransform combined = NULL;

  /* AES cipher */
  if (cvmx_likely(transform & OCTEON_SE_FASTPATH_CRYPT_AES))
    {
      if (cvmx_likely(transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA1))
        {
          combined = &se_fastpath_aes_sha1_def;
        }
      else if (transform & OCTEON_SE_FASTPATH_MAC_HMAC_MD5)
        {
          combined = &se_fastpath_aes_md5_def;
        }
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
      else if ((transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2) &&
               (mac_key_len == 32))
        {
          combined = &se_fastpath_aes_sha_256_def;
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
      else if ((transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2) &&
               (mac_key_len == 48))
        {
          combined = &se_fastpath_aes_sha_384_def;
        }
      else if ((transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2) &&
               (mac_key_len == 64))
        {
          combined = &se_fastpath_aes_sha_512_def;
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */
    }

  /* AES-GCM combined cipher */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
  else if (cvmx_likely(transform & OCTEON_SE_FASTPATH_CRYPT_AES_GCM))
    {
      combined = &se_fastpath_aes_gcm_def;
    }
  else if (transform & OCTEON_SE_FASTPATH_CRYPT_AES_GCM_8)
    {
      combined = &se_fastpath_aes_gcm_8_def;
    }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */

  /* 3DES cipher */
  else if (transform & OCTEON_SE_FASTPATH_CRYPT_3DES)
    {
      if (transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA1)
        {
          combined = &se_fastpath_3des_sha1_def;
        }
      else if (transform & OCTEON_SE_FASTPATH_MAC_HMAC_MD5)
        {
          combined = &se_fastpath_3des_md5_def;
        }
    }

  /* NULL cipher or AH (no cipher) */
  else if ((transform & OCTEON_SE_FASTPATH_CRYPT_NULL)
           || ((transform & OCTEON_SE_FASTPATH_CRYPT_MASK) == 0))
    {
      if (cvmx_likely(transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA1))
        {
          combined = &se_fastpath_null_sha1_def;
        }
      else if (transform & OCTEON_SE_FASTPATH_MAC_HMAC_MD5)
        {
          combined = &se_fastpath_null_md5_def;
        }
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
      else if ((transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2) &&
               (mac_key_len == 32))
        {
          combined = &se_fastpath_null_sha_256_def;
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
      else if ((transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2) &&
               (mac_key_len == 48))
        {
          combined = &se_fastpath_null_sha_384_def;
        }
      else if ((transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2) &&
               (mac_key_len == 64))
        {
          combined = &se_fastpath_null_sha_512_def;
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */
    }

  return combined;
}
