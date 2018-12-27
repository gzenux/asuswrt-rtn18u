/**
   @copyright
   Copyright (c) 2010 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file includes implementation of Intel's Advanced Encryption
   Standard (AES) Instruction Set for all supported AES cipher modes
   of operation, AES-XCBC and GCM-AES. The implementation is based
   on intrinsic functions.

   References:
   - Intel's Advanced Encryption Standard (AES) Instruction Set
   - Intel Carry-Less Multiplication Instructions and its Usage
     for Computing the GCM mode
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshasmidioms.h"
#include "sshrotate.h"
#include "sshgetput.h"
#include "rijndael.h"

#define SSH_DEBUG_MODULE "SshCipherAes"

#ifdef HAVE_AES
#ifdef HAVE_AES_INTEL_INSTRUCTION_SET

#include <cpuid.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

int aes_intel_available() {
  unsigned int a=1,b,c,d;
  __cpuid(1, a,b,c,d);
  return (c & 0x2000000);
}

/* ************************* Basic init functions ************************* */

typedef struct {
  __m128i key_schedule[15];
  __m128i key_schedule_decrypt[15];
  unsigned char iv[16];
  size_t key_len;
  unsigned int rounds;
  Boolean for_encryption;
} *SshRijndaelContext, SshRijndaelContextStruct;


/* Gets the size of Rijndael context. */
size_t ssh_rijndael_ctxsize()
{
  return sizeof(SshRijndaelContextStruct);
}

SshCryptoStatus ssh_aes_init(void *context,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption)
{
  if (keylen != 16 && keylen != 24 && keylen != 32)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  if (!aes_intel_available())
    {
      ssh_warning("Intel AES Instruction Set unavailable");
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return ssh_rijndael_init(context, key, keylen, for_encryption);
}

void ssh_rijndael_uninit(void *context)
{
  return;
}

void ssh_aes_uninit(void *context)
{
  return;
}

SshCryptoStatus ssh_rijndael_init_fb(void *context,
                                     const unsigned char *key,
                                     size_t keylen,
                                     Boolean for_encryption)
{
  SshRijndaelContext ctx = (SshRijndaelContext)context;
  SshCryptoStatus status;

  status = ssh_rijndael_init(context, key, keylen, TRUE);
  ctx->for_encryption = for_encryption;

  return status;
}

SshCryptoStatus ssh_aes_init_fb(void *context,
                                const unsigned char *key,
                                size_t keylen,
                                Boolean for_encryption)
{
  return ssh_aes_init(context, key, keylen, for_encryption);
}


SshCryptoStatus ssh_rijndael_start(void *context, const unsigned char *iv)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;

  memcpy(ctx->iv, iv, 16);
  return SSH_CRYPTO_OK;
}



/* ******************** Internal function definitions ********************* */

static __m128i flip_m128i(__m128i input_m128i);

static __m128i aes_keygen_assist(__m128i temp, SshUInt32 i)
{
  /* Note that the second argument for _mm_aeskeygenassistant()
     is required to be a compile-time constant. */

  switch (i)
    {
    case 0: return _mm_aeskeygenassist_si128(temp, 0x01);
    case 1: return _mm_aeskeygenassist_si128(temp, 0x02);
    case 2: return _mm_aeskeygenassist_si128(temp, 0x04);
    case 3: return _mm_aeskeygenassist_si128(temp, 0x08);
    case 4: return _mm_aeskeygenassist_si128(temp, 0x10);
    case 5: return _mm_aeskeygenassist_si128(temp, 0x20);
    case 6: return _mm_aeskeygenassist_si128(temp, 0x40);
    case 7: return _mm_aeskeygenassist_si128(temp, 0x80);
    case 8: return _mm_aeskeygenassist_si128(temp, 0x1b);
    case 9: return _mm_aeskeygenassist_si128(temp, 0x36);
    case 10: return temp;
    default:
      SSH_NOTREACHED;
      return temp;
    }
}

static void aes_128_key_expansion(__m128i key, __m128i *key_schedule)
{
  __m128i temp1, temp2, temp3;
  int i;

  key_schedule[0] = temp1 = key;

  for (i = 0; i < 10; i++)
    {
      temp2 = aes_keygen_assist(temp1, i);

      temp2 = _mm_shuffle_epi32(temp2, 0xff);
      temp3 = _mm_slli_si128(temp1, 0x4);
      temp1 = _mm_xor_si128(temp1, temp3);
      temp3 = _mm_slli_si128(temp3, 0x4);
      temp1 = _mm_xor_si128(temp1, temp3);
      temp3 = _mm_slli_si128(temp3, 0x4);
      temp1 = _mm_xor_si128(temp1, temp3);
      temp1 = _mm_xor_si128(temp1, temp2);

      key_schedule[i+1] = temp1;
    }
}

static void aes_192_key_expansion(__m128i key, __m128i key2,
                                  __m128i *key_schedule)
{
  __m128i temp, temp2, temp3, temp4;
  int offset, i, key_schedule_temp[48];

  key_schedule[0] = temp = key;
  temp3 = key2;
  offset = 0;

  for (i = 0; i < 8; i++)
    {
      temp2 = aes_keygen_assist(temp3, i);

      temp2 = _mm_shuffle_epi32(temp2, 0x55);
      temp4 = temp;
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp = _mm_xor_si128(temp, temp4);
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp = _mm_xor_si128(temp, temp4);
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp = _mm_xor_si128(temp, temp4);
      temp = _mm_xor_si128(temp, temp2);
      temp2 = _mm_shuffle_epi32(temp, 0xff);
      temp4 = temp3;
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp3 = _mm_xor_si128(temp3, temp4);
      temp3 = _mm_xor_si128(temp3, temp2);

      key_schedule_temp[offset++] = _mm_extract_epi32(temp, 0);
      key_schedule_temp[offset++] = _mm_extract_epi32(temp, 1);
      key_schedule_temp[offset++] = _mm_extract_epi32(temp, 2);
      key_schedule_temp[offset++] = _mm_extract_epi32(temp, 3);
      key_schedule_temp[offset++] = _mm_extract_epi32(temp3, 0);
      key_schedule_temp[offset++] = _mm_extract_epi32(temp3, 1);
    }

  key_schedule[1] = _mm_set_epi32(key_schedule_temp[1],
                                  key_schedule_temp[0],
                                  _mm_extract_epi32(key2, 1),
                                  _mm_extract_epi32(key2, 0));

  for (i = 2; i < offset - 4; i += 4)
    {
      key_schedule[(i/4) + 2] = _mm_set_epi32(key_schedule_temp[i+3],
                                              key_schedule_temp[i+2],
                                              key_schedule_temp[i+1],
                                              key_schedule_temp[i]);
    }
}

static void aes_256_key_expansion(__m128i key, __m128i key2,
                                  __m128i *key_schedule)
{
  __m128i temp, temp2, temp3, temp4;
  int offset, i;

  key_schedule[0] = temp = key;
  key_schedule[1] = temp3 = key2;
  offset = 2;

  for (i = 0; i < 7; i++)
    {
      temp2 = aes_keygen_assist(temp3, i);

      temp2 = _mm_shuffle_epi32(temp2, 0xff);
      temp4 = temp;
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp = _mm_xor_si128(temp, temp4);
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp = _mm_xor_si128(temp, temp4);
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp = _mm_xor_si128(temp, temp4);
      temp = _mm_xor_si128(temp, temp2);

      key_schedule[offset] = temp;
      offset++;

      if (offset == 15)
        return;

      temp4 = _mm_aeskeygenassist_si128(temp, 0x0);
      temp2 = _mm_shuffle_epi32(temp4, 0xaa);
      temp4 = temp3;
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp3 = _mm_xor_si128(temp3, temp4);
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp3 = _mm_xor_si128(temp3, temp4);
      temp4 = _mm_slli_si128(temp4, 0x4);
      temp3 = _mm_xor_si128(temp3, temp4);
      temp3 = _mm_xor_si128(temp3, temp2);

      key_schedule[offset] = temp3;
      offset++;
    }
}

static void aes_decrypt_key_expansion(SshRijndaelContext ctx)
{
  __m128i temp;
  __m128i *key_schedule = ctx->key_schedule;
  __m128i *key_schedule_decrypt = ctx->key_schedule_decrypt;
  int i;

  key_schedule_decrypt[0] = key_schedule[0];

  for (i = 1; i < ctx->rounds; i++)
    {
      temp = key_schedule[i];
      temp = _mm_aesimc_si128(temp);
      key_schedule_decrypt[i] = temp;
    }

  key_schedule_decrypt[i] = key_schedule[i];
}

SshCryptoStatus ssh_rijndael_init(void *context,
                                  const unsigned char *key,
                                  size_t keylen,
                                  Boolean for_encryption)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  __m128i key_temp, key_temp2;

  if (keylen == 16)
    {
      ctx->rounds = 10;

      key_temp = _mm_loadu_si128((__m128i *)key);

      aes_128_key_expansion(key_temp, ctx->key_schedule);
    }
  else if (keylen == 24)
    {
      unsigned char key_remaining[16];
      ctx->rounds = 12;

      memset(key_remaining, 0, 16);
      memcpy(key_remaining, key + 16, 8);

      key_temp = _mm_loadu_si128((__m128i *)key);
      key_temp2 = _mm_loadu_si128((__m128i *)(key_remaining));

      aes_192_key_expansion(key_temp, key_temp2, ctx->key_schedule);
    }
  else if (keylen == 32)
    {
      ctx->rounds = 14;

      key_temp = _mm_loadu_si128((__m128i *)key);
      key_temp2 = _mm_loadu_si128((__m128i *)(key + 16));

      aes_256_key_expansion(key_temp, key_temp2, ctx->key_schedule);
    }
  else
    SSH_NOTREACHED;

  ctx->key_len = keylen;
  ctx->for_encryption = for_encryption;

  if (!for_encryption)
    aes_decrypt_key_expansion(ctx);

  return SSH_CRYPTO_OK;
}

static void ssh_rijndael_encrypt_m128i_block(__m128i *dst,
                                             __m128i *src,
                                             __m128i *round_keys,
                                             unsigned int rounds)
{
  unsigned int i;
  __m128i key_schedule[15];
  __m128i temp;

  for (i = 0; i <= rounds; i++)
    key_schedule[i] = round_keys[i];

  /* First round */
  temp = _mm_xor_si128(*src, key_schedule[0]);

  /* Middle rounds */
  for (i = 1; i < rounds; i++)
    temp = _mm_aesenc_si128(temp, key_schedule[i]);

  /* Last round */
  *dst = _mm_aesenclast_si128(temp, key_schedule[rounds]);
}

static void ssh_rijndael_decrypt_m128i_block(__m128i *dst,
                                             __m128i *src,
                                             __m128i *round_keys,
                                             unsigned int rounds)
{
  unsigned int i;
  __m128i key_schedule[15];;
  __m128i temp;

  for (i = 0; i <= rounds; i++)
    key_schedule[i] = round_keys[i];

  /* First round */
  temp = _mm_xor_si128(*src, key_schedule[rounds]);

  /* Middle rounds */
  for (i = 1; i < rounds; i++)
    temp = _mm_aesdec_si128(temp, key_schedule[rounds - i]);

  /* Last round */
  *dst = _mm_aesdeclast_si128(temp, key_schedule[0]);
}

#define PARALLEL_AES_BLOCKS 8

static void ssh_rijndael_encrypt_m128i_blocks(__m128i *dst,
                                              __m128i *src,
                                              __m128i *round_keys,
                                              unsigned int rounds,
                                              unsigned int blocks)
{
  unsigned int i, j;
  __m128i key_schedule[15];
  __m128i temp[PARALLEL_AES_BLOCKS];

  SSH_ASSERT(blocks <= PARALLEL_AES_BLOCKS);

  for (i = 0; i <= rounds; i++)
    key_schedule[i] = round_keys[i];

  /* First round */
  for (i = 0; i < blocks; i++)
    temp[i] = _mm_xor_si128(src[i], key_schedule[0]);

  /* Middle rounds */
  for (i = 1; i < rounds; i++)
    for (j = 0; j < blocks; j++)
      temp[j] = _mm_aesenc_si128(temp[j], key_schedule[i]);

  /* Last round */
  for (i = 0; i < blocks; i++)
    dst[i] = _mm_aesenclast_si128(temp[i], key_schedule[rounds]);
}

static void ssh_rijndael_decrypt_m128i_blocks(__m128i *dst,
                                              __m128i *src,
                                              __m128i *round_keys,
                                              unsigned int rounds,
                                              unsigned int blocks)
{
  unsigned int i, j;
  __m128i key_schedule[15];
  __m128i temp[PARALLEL_AES_BLOCKS];

  SSH_ASSERT(blocks <= PARALLEL_AES_BLOCKS);

  for (i = 0; i <= rounds; i++)
    key_schedule[i] = round_keys[i];

  /* First round */
  for (i = 0; i < blocks; i++)
    temp[i] = _mm_xor_si128(src[i], key_schedule[rounds]);

  /* Middle rounds */
  for (i = 1; i < rounds; i++)
    for (j = 0; j < blocks; j++)
      temp[j] = _mm_aesdec_si128(temp[j], key_schedule[rounds - i]);

  /* Last round */
  for (i = 0; i < blocks; i++)
    dst[i] = _mm_aesdeclast_si128(temp[i], key_schedule[0]);
}


/* *********************** Modes of operation ***************************** */

/* Encryption and decryption in electronic codebook mode */
SshCryptoStatus ssh_rijndael_ecb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  int progress = 0;
  int blocks, i;
  __m128i src_m128i[PARALLEL_AES_BLOCKS], dest_m128i[PARALLEL_AES_BLOCKS];

  if (len % 16 != 0)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  blocks = len / 16;

  while (blocks > 0)
    {
      for (i = 0; i < blocks && i < PARALLEL_AES_BLOCKS; i++)
        src_m128i[i] = _mm_loadu_si128((__m128i *)(src + progress + (i * 16)));

      if (ctx->for_encryption)
        ssh_rijndael_encrypt_m128i_blocks(dest_m128i,
                                          src_m128i,
                                          ctx->key_schedule,
                                          ctx->rounds,
                                          MIN(blocks, PARALLEL_AES_BLOCKS));
      else
        ssh_rijndael_decrypt_m128i_blocks(dest_m128i,
                                          src_m128i,
                                          ctx->key_schedule_decrypt,
                                          ctx->rounds,
                                          MIN(blocks, PARALLEL_AES_BLOCKS));

      for (i = 0; i < blocks && i < PARALLEL_AES_BLOCKS; i++)
        {
          _mm_storeu_si128((void *)(dest + progress), dest_m128i[i]);
          progress += 16;
        }

      blocks -= PARALLEL_AES_BLOCKS;
    }

  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in cipher block chaining mode. */
SshCryptoStatus ssh_rijndael_cbc(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  unsigned int progress = 0;
  __m128i src_m128i, temp_m128i, temp2_m128i, temp3_m128i;

  if (len % 16 != 0)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  temp3_m128i = temp_m128i = _mm_loadu_si128((__m128i *)(ctx->iv));

  while (progress < len)
    {
      src_m128i = _mm_loadu_si128((__m128i *)(src + progress));

      if (ctx->for_encryption)
        {
          src_m128i = _mm_xor_si128(src_m128i, temp_m128i);

          ssh_rijndael_encrypt_m128i_block(&temp_m128i,
                                           &src_m128i,
                                           ctx->key_schedule,
                                           ctx->rounds);
        }
      else
        {
          ssh_rijndael_decrypt_m128i_block(&temp2_m128i,
                                           &src_m128i,
                                           ctx->key_schedule_decrypt,
                                           ctx->rounds);

          temp_m128i = _mm_xor_si128(temp2_m128i, temp3_m128i);
          temp3_m128i = src_m128i;
        }

      _mm_storeu_si128((void *)(dest + progress), temp_m128i);
      progress += 16;
    }

  /* Store IV */
  if (ctx->for_encryption)
    _mm_storeu_si128((void *)(ctx->iv), temp_m128i);
  else
    _mm_storeu_si128((void *)(ctx->iv), temp3_m128i);

  return SSH_CRYPTO_OK;
}

/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_rijndael_ofb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  unsigned int progress = 0;
  __m128i src_m128i, temp_m128i, temp_iv_m128i;

  if (len % 16 != 0)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  temp_iv_m128i = _mm_loadu_si128((__m128i *)(ctx->iv));

  while (progress < len)
    {
      src_m128i = _mm_loadu_si128((__m128i *)(src + progress));

      ssh_rijndael_encrypt_m128i_block(&temp_iv_m128i,
                                       &temp_iv_m128i,
                                       ctx->key_schedule,
                                       ctx->rounds);

      temp_m128i = _mm_xor_si128(src_m128i, temp_iv_m128i);

      _mm_storeu_si128((void *)(dest + progress), temp_m128i);
      progress += 16;
    }

  /* Store new IV value */
  if (progress > 0)
    _mm_storeu_si128((void *)(ctx->iv), temp_iv_m128i);

  return SSH_CRYPTO_OK;
}

/* This will increment a 128 bit int in big endian way
 * i.e. MSB is first */
static inline __m128i increment_big_endian_m128i(__m128i x)
{
    __m128i res;
    __m128i ONE_m128i =_mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 1);

    res = flip_m128i(x);
    res = _mm_add_epi64(res, ONE_m128i);
    return flip_m128i(res);
}

/* Encrypt/decrypt in output counter mode. */
SshCryptoStatus ssh_rijndael_ctr(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  __m128i src_m128i[PARALLEL_AES_BLOCKS];
  __m128i ctr_arg_m128i[PARALLEL_AES_BLOCKS];
  __m128i temp_m128i[PARALLEL_AES_BLOCKS];
  int blocks = 0, i = 0;
  unsigned int progress = 0;

  blocks = len / 16;

  ctr_arg_m128i[0] = _mm_loadu_si128((__m128i *)(ctx->iv));

  while (blocks > 0)
    {
      for (i = 0; i < blocks && i < PARALLEL_AES_BLOCKS; i++)
        src_m128i[i] = _mm_loadu_si128((__m128i *)(src + progress + (i * 16)));

      for (i = 1; i < blocks && i < PARALLEL_AES_BLOCKS; i++)
        ctr_arg_m128i[i] = increment_big_endian_m128i(ctr_arg_m128i[i - 1]);


      ssh_rijndael_encrypt_m128i_blocks(temp_m128i,
                                        ctr_arg_m128i,
                                        ctx->key_schedule,
                                        ctx->rounds,
                                        MIN(blocks, PARALLEL_AES_BLOCKS));

      for (i = 0; i < blocks && i < PARALLEL_AES_BLOCKS; i++)
        {
          temp_m128i[i] = _mm_xor_si128(src_m128i[i], temp_m128i[i]);
          _mm_storeu_si128((void *)(dest + progress), temp_m128i[i]);
          progress += 16;
          len -= 16;
        }

      /* Increment and continue */
      ctr_arg_m128i[0] = increment_big_endian_m128i(ctr_arg_m128i[i - 1]);
      blocks -= MIN(blocks, PARALLEL_AES_BLOCKS);
    }

  /* partial block */
  if (len)
    {
      __m128i src_part_m128i;
      __m128i ctr_part_arg_m128i;
      __m128i temp_part_m128i;
      SshUInt32 tmp[4];

      SSH_ASSERT(len < 16);

      /* zero padding */
      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, src + progress, len);

      src_part_m128i = _mm_loadu_si128((__m128i *)(tmp));
      ctr_part_arg_m128i = _mm_loadu_si128(&ctr_arg_m128i[0]);

      ssh_rijndael_encrypt_m128i_block(&temp_part_m128i,
                                       &ctr_part_arg_m128i,
                                       ctx->key_schedule,
                                       ctx->rounds);

      temp_part_m128i = _mm_xor_si128(src_part_m128i, temp_part_m128i);
      memcpy(dest + progress, &temp_part_m128i, len);
      progress += len;

      ctr_arg_m128i[0] = increment_big_endian_m128i(ctr_part_arg_m128i);
    }

  /* Store new counter value */
  if (progress > 0)
    _mm_storeu_si128((void *)(ctx->iv), ctr_arg_m128i[0]);

  return SSH_CRYPTO_OK;
}

/* Encrypt/decrypt in cipher feedback mode */
SshCryptoStatus ssh_rijndael_cfb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  unsigned int progress = 0;
  __m128i src_m128i, temp_m128i, temp2_m128i;

  if (len % 16 != 0)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  temp_m128i = _mm_loadu_si128((__m128i *)(ctx->iv));

  while (progress < len)
    {
      src_m128i = _mm_loadu_si128((__m128i *)(src + progress));

      ssh_rijndael_encrypt_m128i_block(&temp2_m128i,
                                       &temp_m128i,
                                       ctx->key_schedule,
                                       ctx->rounds);

      if (ctx->for_encryption)
        {
          temp_m128i = _mm_xor_si128(src_m128i, temp2_m128i);
          _mm_storeu_si128((void *)(dest + progress), temp_m128i);
        }
      else
        {
          temp_m128i = _mm_xor_si128(src_m128i, temp2_m128i);
          _mm_storeu_si128((void *)(dest + progress), temp_m128i);
          temp_m128i = src_m128i;
        }

      progress += 16;
    }

  /* Store IV */
  if (progress > 0)
    _mm_storeu_si128((void *)(ctx->iv), temp_m128i);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rijndael_cbc_mac(void *context, const unsigned char *src, size_t len,
                     unsigned char *iv_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt32 iv[4];
  __m128i src_m128i, dst_m128i;

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 12);

  while (len > 0)
    {
      iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
      iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);
      iv[2] ^= SSH_GET_32BIT_LSB_FIRST(src + 8);
      iv[3] ^= SSH_GET_32BIT_LSB_FIRST(src + 12);


      src_m128i = _mm_loadu_si128((__m128i *)iv);

      ssh_rijndael_encrypt_m128i_block(&dst_m128i,
                                       &src_m128i,
                                       ctx->key_schedule,
                                       ctx->rounds);

      _mm_storeu_si128((void *)iv, dst_m128i);

      src += 16;
      len -= 16;
    }

  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 8, iv[2]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 12, iv[3]);

  memset(iv, 0, sizeof(iv));
  return SSH_CRYPTO_OK;
}

/* *********************** AES-GCM functionality ************************** */

#ifdef SSHDIST_CRYPT_MODE_GCM

typedef struct {
  __m128i h_m128i;
  __m128i y_m128i;
  __m128i icb_m128i;
  __m128i key_schedule[15];
  unsigned char iv[16];
  size_t key_len;
  unsigned int rounds;
  Boolean for_encryption;
  Boolean transform_started;
  unsigned int a_len;
  unsigned int c_len;
} *SshAesGcmContext, SshAesGcmContextStruct;

static __m128i flip_m128i(__m128i input_m128i)
{
  __m128i output_m128i;

  output_m128i = _mm_set_epi8(_mm_extract_epi8(input_m128i, 0),
                              _mm_extract_epi8(input_m128i, 1),
                              _mm_extract_epi8(input_m128i, 2),
                              _mm_extract_epi8(input_m128i, 3),
                              _mm_extract_epi8(input_m128i, 4),
                              _mm_extract_epi8(input_m128i, 5),
                              _mm_extract_epi8(input_m128i, 6),
                              _mm_extract_epi8(input_m128i, 7),
                              _mm_extract_epi8(input_m128i, 8),
                              _mm_extract_epi8(input_m128i, 9),
                              _mm_extract_epi8(input_m128i, 10),
                              _mm_extract_epi8(input_m128i, 11),
                              _mm_extract_epi8(input_m128i, 12),
                              _mm_extract_epi8(input_m128i, 13),
                              _mm_extract_epi8(input_m128i, 14),
                              _mm_extract_epi8(input_m128i, 15));

  return output_m128i;
}

/* NIST Special Publication 800-38D: 6.5 */
static void galois_counter(SshAesGcmContext ctx,
                           unsigned char *dst,
                           const unsigned char *src,
                           size_t len)
{
  unsigned int i, j, n, partial_len;
  __m128i key_schedule[15];
  __m128i temp_m128i, src_m128i, icb_m128i;

  if (len == 0)
    return;

  SSH_ASSERT((len % 16 == 0) || (len < 16));

  icb_m128i = ctx->icb_m128i;

  for (i = 0; i <= ctx->rounds; i++)
    key_schedule[i] = ctx->key_schedule[i];

  n = len / 16;
  partial_len = len % 16;

  for (i = 0; i < n; i++)
    {
      /* First round */
      temp_m128i = _mm_xor_si128(icb_m128i, key_schedule[0]);

      /* Middle rounds */
      for (j = 1; j < ctx->rounds; j++)
        temp_m128i = _mm_aesenc_si128(temp_m128i, key_schedule[j]);

      /* Last round */
      temp_m128i = _mm_aesenclast_si128(temp_m128i,
                                        key_schedule[ctx->rounds]);

      /* Fetch source and XOR to dest */
      src_m128i = _mm_loadu_si128((__m128i *)(src + i * 16));
      temp_m128i = _mm_xor_si128(src_m128i, temp_m128i);
      _mm_storeu_si128((void *)(dst + i * 16), temp_m128i);

      /* Increment and continue */
      icb_m128i = increment_big_endian_m128i(icb_m128i);
    }

  if (partial_len != 0)
    {
      unsigned char partial[16];
      memset(partial, 0x00, 16);
      memcpy(partial, src, partial_len);

      /* First round */
      temp_m128i = _mm_xor_si128(icb_m128i, key_schedule[0]);

      /* Middle rounds */
      for (j = 1; j < ctx->rounds; j++)
        temp_m128i = _mm_aesenc_si128(temp_m128i, key_schedule[j]);

      /* Last round */
      temp_m128i = _mm_aesenclast_si128(temp_m128i,
                                        key_schedule[ctx->rounds]);

      /* Fetch source and XOR to dest */
      src_m128i = _mm_loadu_si128((__m128i *)(partial));
      temp_m128i = _mm_xor_si128(src_m128i, temp_m128i);
      _mm_storeu_si128((void *)(partial), temp_m128i);

      memcpy(dst, partial, partial_len);
    }

  ctx->icb_m128i = icb_m128i;

  return;
}

/* NIST Special Publication 800-38D: 6.3 */
static void galois_mul(__m128i a, __m128i b, __m128i *res)
{
  __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

  /* Inputs and output in reverse byte order */

  tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
  tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
  tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
  tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

  tmp4 = _mm_xor_si128(tmp4, tmp5);
  tmp5 = _mm_slli_si128(tmp4, 8);
  tmp4 = _mm_srli_si128(tmp4, 8);
  tmp3 = _mm_xor_si128(tmp3, tmp5);
  tmp6 = _mm_xor_si128(tmp6, tmp4);

  tmp7 = _mm_srli_epi32(tmp3, 31);
  tmp8 = _mm_srli_epi32(tmp6, 31);
  tmp3 = _mm_slli_epi32(tmp3, 1);
  tmp6 = _mm_slli_epi32(tmp6, 1);

  tmp9 = _mm_srli_si128(tmp7, 12);
  tmp8 = _mm_slli_si128(tmp8, 4);
  tmp7 = _mm_slli_si128(tmp7, 4);
  tmp3 = _mm_or_si128(tmp3, tmp7);
  tmp6 = _mm_or_si128(tmp6, tmp8);
  tmp6 = _mm_or_si128(tmp6, tmp9);

  tmp7 = _mm_slli_epi32(tmp3, 31);
  tmp8 = _mm_slli_epi32(tmp3, 30);
  tmp9 = _mm_slli_epi32(tmp3, 25);

  tmp7 = _mm_xor_si128(tmp7, tmp8);
  tmp7 = _mm_xor_si128(tmp7, tmp9);
  tmp8 = _mm_srli_si128(tmp7, 4);
  tmp7 = _mm_slli_si128(tmp7, 12);
  tmp3 = _mm_xor_si128(tmp3, tmp7);

  tmp2 = _mm_srli_epi32(tmp3, 1);
  tmp4 = _mm_srli_epi32(tmp3, 2);
  tmp5 = _mm_srli_epi32(tmp3, 7);
  tmp2 = _mm_xor_si128(tmp2, tmp4);
  tmp2 = _mm_xor_si128(tmp2, tmp5);
  tmp2 = _mm_xor_si128(tmp2, tmp8);
  tmp3 = _mm_xor_si128(tmp3, tmp2);
  tmp6 = _mm_xor_si128(tmp6, tmp3);

  *res = tmp6;
}

/* NIST Special Publication 800-38D: 6.4 */
static __m128i galois_hash(__m128i h_m128i,
                           __m128i y_m128i,
                           const unsigned char *buffer,
                           size_t len)
{
  __m128i x_m128i, temp_m128i, temp2_m128i;
  int i;

  SSH_ASSERT(len > 0);
  SSH_ASSERT(len % 16 == 0);

  /* H is already stored in reversed byte order */
  temp_m128i = flip_m128i(y_m128i);

  for (i = 0; i < len; i += 16)
    {
      x_m128i = _mm_set_epi8(*(buffer + i),
                             *(buffer + i + 1),
                             *(buffer + i + 2),
                             *(buffer + i + 3),
                             *(buffer + i + 4),
                             *(buffer + i + 5),
                             *(buffer + i + 6),
                             *(buffer + i + 7),
                             *(buffer + i + 8),
                             *(buffer + i + 9),
                             *(buffer + i + 10),
                             *(buffer + i + 11),
                             *(buffer + i + 12),
                             *(buffer + i + 13),
                             *(buffer + i + 14),
                             *(buffer + i + 15));

      temp_m128i = _mm_xor_si128(temp_m128i, x_m128i);  /*          Y xor X  */
      galois_mul(h_m128i, temp_m128i, &temp2_m128i);    /*     H * (Y xor X) */
      temp_m128i = temp2_m128i;                         /* Y = H * (Y xor X) */
    }

  return flip_m128i(temp2_m128i);
}

size_t ssh_gcm_aes_ctxsize(void)
{
  return sizeof(SshAesGcmContextStruct);
}

size_t ssh_gcm_aes_table_256_ctxsize(void)
{
  return ssh_gcm_aes_ctxsize();
}

size_t ssh_gcm_aes_table_4k_ctxsize(void)
{
  return ssh_gcm_aes_ctxsize();
}

size_t ssh_gcm_aes_table_8k_ctxsize(void)
{
  return ssh_gcm_aes_ctxsize();
}

size_t ssh_gcm_aes_table_64k_ctxsize(void)
{
  return ssh_gcm_aes_ctxsize();
}



SshCryptoStatus
ssh_gcm_aes_init(void *context, const unsigned char *key, size_t keylen,
                 Boolean for_encryption)
{
  SshAesGcmContext ctx = (SshAesGcmContext) context;
  __m128i key_temp, key_temp2;
  __m128i zero_m128i, h_m128i;

  if (!aes_intel_available())
    {
      ssh_warning("Intel AES Instruction Set unavailable");
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  /* Pre-calculate key schedules */
  if (keylen == 16)
    {
      ctx->rounds = 10;

      key_temp = _mm_loadu_si128((__m128i *)key);

      aes_128_key_expansion(key_temp, ctx->key_schedule);
    }
  else if (keylen == 24)
    {
      unsigned char key_remaining[16];
      ctx->rounds = 12;

      memset(key_remaining, 0, 16);
      memcpy(key_remaining, key + 16, 8);

      key_temp = _mm_loadu_si128((__m128i *)key);
      key_temp2 = _mm_loadu_si128((__m128i *)key_remaining);

      aes_192_key_expansion(key_temp, key_temp2, ctx->key_schedule);
    }
  else if (keylen == 32)
    {
      ctx->rounds = 14;

      key_temp = _mm_loadu_si128((__m128i *)key);
      key_temp2 = _mm_loadu_si128((__m128i *)(key + 16));

      aes_256_key_expansion(key_temp, key_temp2, ctx->key_schedule);
    }
  else
    SSH_NOTREACHED;

  /* Pre-calculate H */
  zero_m128i = _mm_setzero_si128();
  ssh_rijndael_encrypt_m128i_block(&h_m128i,
                                   &zero_m128i,
                                   ctx->key_schedule,
                                   ctx->rounds);

  ctx->a_len = 0;
  ctx->c_len = 0;
  ctx->key_len = keylen;
  ctx->for_encryption = for_encryption;
  ctx->transform_started = FALSE;
  ctx->y_m128i = zero_m128i;
  memset(ctx->iv, 0, 16);

  /* Pre-invert byte order in H */
  ctx->h_m128i = flip_m128i(h_m128i);

  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_gcm_aes_table_256_init(void *context, const unsigned char *key,
                           size_t keylen, Boolean for_encryption)
{
  return ssh_gcm_aes_init(context, key, keylen, for_encryption);
}

SshCryptoStatus
ssh_gcm_aes_table_4k_init(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption)
{
  return ssh_gcm_aes_init(context, key, keylen, for_encryption);
}

SshCryptoStatus
ssh_gcm_aes_table_8k_init(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption)
{
  return ssh_gcm_aes_init(context, key, keylen, for_encryption);
}

SshCryptoStatus
ssh_gcm_aes_table_64k_init(void *context, const unsigned char *key,
                           size_t keylen, Boolean for_encryption)
{
  return ssh_gcm_aes_init(context, key, keylen, for_encryption);
}


void ssh_gcm_update(void *context, const unsigned char *buffer, size_t len)
{
  SshAesGcmContext ctx = (SshAesGcmContext) context;
  unsigned char partial[16];
  size_t partial_len;

  if (len == 0)
    return;

  partial_len = len % 16;

  /* First multiples of blocksize */
  if (len >= 16)
    {
      ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                                 buffer, len - partial_len);
    }

  /* The last partial block */
  if (partial_len != 0)
    {
      memset(partial, 0x00, 16);
      memcpy(partial, (buffer + len - partial_len), partial_len);
      ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                                 partial, 16);
    }

  ctx->a_len += len;
}


SshCryptoStatus ssh_gcm_auth_start(void *context, const unsigned char *iv,
                                     const unsigned char *aad, size_t aad_len,
                                     size_t crypt_len)
{
  SshAesGcmContext ctx = (SshAesGcmContext) context;

  /* reset */
  ctx->transform_started = FALSE;

  ctx->y_m128i= _mm_setzero_si128();
  ctx->a_len = 0;
  ctx->c_len = 0;

  /* copy iv */
  memcpy(ctx->iv, iv, 12);

  ssh_gcm_update(context, aad, aad_len);
  return SSH_CRYPTO_OK;
}


SshCryptoStatus ssh_gcm_final(void *context, unsigned char *digest)
{
  SshAesGcmContext ctx = (SshAesGcmContext) context;
  unsigned char len_buffer[16];
  unsigned char final_y[16];

  memset(len_buffer, 0x00, 16);
  SSH_PUT_32BIT(len_buffer + 4, ctx->a_len * 8);
  SSH_PUT_32BIT(len_buffer + 12, ctx->c_len * 8);

  /* Create the final y */
  ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                             len_buffer, 16);
  _mm_storeu_si128((void *)(final_y), ctx->y_m128i);

  /* Run through GCTR to get T, old icb is not needed anymore */
  SSH_PUT_32BIT(ctx->iv + 12, 1);
  ctx->icb_m128i = _mm_loadu_si128((__m128i *)ctx->iv);

  /* Create last ciphertext */
  galois_counter(ctx, digest, final_y, 16);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_gcm_96_final(void *context, unsigned char *digest)
{
  SshCryptoStatus status;
  unsigned char full_result[16];

  status = ssh_gcm_final(context, full_result);

  if (status != SSH_CRYPTO_OK)
    return status;

  memcpy(digest, full_result, 12);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_gcm_64_final(void *context, unsigned char *digest)
{
  SshCryptoStatus status;
  unsigned char full_result[16];

  status = ssh_gcm_final(context, full_result);

  if (status != SSH_CRYPTO_OK)
    return status;

  memcpy(digest, full_result, 8);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_gcm_final_verify(void *context, unsigned char *digest)
{
  unsigned char tmp[16];
  SshCryptoStatus stat;

  stat = ssh_gcm_final(context, tmp);
  if (stat == SSH_CRYPTO_OK)
    {
      if (memcmp(digest, tmp, 16) != 0)
        return SSH_CRYPTO_OPERATION_FAILED;
    }
  return stat;
}

SshCryptoStatus ssh_gcm_64_final_verify(void *context, unsigned char *digest)
{
  unsigned char tmp[16];
  SshCryptoStatus stat;

  stat = ssh_gcm_final(context, tmp);
  if (stat == SSH_CRYPTO_OK)
    {
      if (memcmp(digest, tmp, 8) != 0)
        return SSH_CRYPTO_OPERATION_FAILED;
    }
  return stat;
}

SshCryptoStatus ssh_gcm_96_final_verify(void *context, unsigned char *digest)
{
  unsigned char tmp[16];
  SshCryptoStatus stat;

  stat = ssh_gcm_final(context, tmp);
  if (stat == SSH_CRYPTO_OK)
    {
      if (memcmp(digest, tmp, 12) != 0)
        return SSH_CRYPTO_OPERATION_FAILED;
    }
  return stat;
}


SshCryptoStatus ssh_gcm_transform(void *context,
                                  unsigned char *dest,
                                  const unsigned char *src,
                                  size_t len)
{
  SshAesGcmContext ctx = (SshAesGcmContext) context;
  unsigned char partial_block[16];
  unsigned char partial_block_len;

  if (len == 0)
    return SSH_CRYPTO_OK;

  if (!ctx->transform_started)
    {
      /* Set counter value to IV */
      SSH_PUT_32BIT(ctx->iv + 12, 2);
      ctx->icb_m128i = _mm_loadu_si128((__m128i *)ctx->iv);
      ctx->transform_started = TRUE;
    }

  partial_block_len = len % 16;

  if (ctx->for_encryption)
    {
      if (len >= 16)
        {
          /* Create ciphertext */
          galois_counter(ctx, dest, src, len - partial_block_len);

          /* Update auth tag */
          ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                                     dest, len - partial_block_len);
        }

      if (partial_block_len != 0)
        {
          /* Create ciphertext */
          galois_counter(ctx, dest + len - partial_block_len,
                         src + len - partial_block_len, partial_block_len);

          memset(partial_block, 0x00, 16);
          memcpy(partial_block,
                 dest + len - partial_block_len,
                 partial_block_len);

          /* Update auth tag */
          ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                                     partial_block, 16);
        }
    }
  else
    {
      if (len >= 16)
        {
          /* Update auth tag */
          ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                                     src, len - partial_block_len);
          /* Create ciphertext */
          galois_counter(ctx, dest, src, len - partial_block_len);
        }

      if (partial_block_len != 0)
        {
          memset(partial_block, 0x00, 16);
          memcpy(partial_block,
                 src + len - partial_block_len,
                 partial_block_len);

          /* Update auth tag */
          ctx->y_m128i = galois_hash(ctx->h_m128i, ctx->y_m128i,
                                     partial_block, 16);
          /* Create ciphertext */
          galois_counter(ctx, dest + len - partial_block_len, partial_block,
                         partial_block_len);
        }
    }

  /* Update ciphertext len */
  ctx->c_len += len;

  return SSH_CRYPTO_OK;
}


SshCryptoStatus ssh_gmac_transform(void *context,
                                   unsigned char *dest,
                                   const unsigned char *src,
                                   size_t len)
{
  ssh_gcm_update(context, src, len);

  if (dest != src)
    memcpy(dest, src, len);

  return SSH_CRYPTO_OK;
}

#endif /* HAVE_CRYPT_MODE_GCM */
#endif /* HAVE_AES_INTEL_INSTRUCTION_SET */
#endif /* HAVE_AES */



