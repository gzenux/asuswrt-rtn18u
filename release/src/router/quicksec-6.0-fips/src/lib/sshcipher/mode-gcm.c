/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
    Combined encryption and authentication using the Galois/Counter mode of
    operation.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshmp.h"
#include "sshcipher_i.h"
#include "mode-gcm.h"
#include "rijndael.h"

#ifdef SSHDIST_CRYPT_MODE_GCM
#ifndef HAVE_AES_INTEL_INSTRUCTION_SET

#define SSH_DEBUG_MODULE "SshCryptGCM"

SSH_RODATA
static const SshUInt32 ssh_gcm_aes_shoup_4_bit[16] =
{
 0x00000000, 0x1c200000, 0x38400000, 0x24600000,
 0x70800000, 0x6ca00000, 0x48c00000, 0x54e00000,
 0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
 0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000
};

SSH_RODATA
static const SshUInt32 ssh_gcm_aes_shoup_8_bit[256] =
{
  0x00000000, 0x01c20000, 0x03840000, 0x02460000,
  0x07080000, 0x06ca0000, 0x048c0000, 0x054e0000,
  0x0e100000, 0x0fd20000, 0x0d940000, 0x0c560000,
  0x09180000, 0x08da0000, 0x0a9c0000, 0x0b5e0000,
  0x1c200000, 0x1de20000, 0x1fa40000, 0x1e660000,
  0x1b280000, 0x1aea0000, 0x18ac0000, 0x196e0000,
  0x12300000, 0x13f20000, 0x11b40000, 0x10760000,
  0x15380000, 0x14fa0000, 0x16bc0000, 0x177e0000,
  0x38400000, 0x39820000, 0x3bc40000, 0x3a060000,
  0x3f480000, 0x3e8a0000, 0x3ccc0000, 0x3d0e0000,
  0x36500000, 0x37920000, 0x35d40000, 0x34160000,
  0x31580000, 0x309a0000, 0x32dc0000, 0x331e0000,
  0x24600000, 0x25a20000, 0x27e40000, 0x26260000,
  0x23680000, 0x22aa0000, 0x20ec0000, 0x212e0000,
  0x2a700000, 0x2bb20000, 0x29f40000, 0x28360000,
  0x2d780000, 0x2cba0000, 0x2efc0000, 0x2f3e0000,
  0x70800000, 0x71420000, 0x73040000, 0x72c60000,
  0x77880000, 0x764a0000, 0x740c0000, 0x75ce0000,
  0x7e900000, 0x7f520000, 0x7d140000, 0x7cd60000,
  0x79980000, 0x785a0000, 0x7a1c0000, 0x7bde0000,
  0x6ca00000, 0x6d620000, 0x6f240000, 0x6ee60000,
  0x6ba80000, 0x6a6a0000, 0x682c0000, 0x69ee0000,
  0x62b00000, 0x63720000, 0x61340000, 0x60f60000,
  0x65b80000, 0x647a0000, 0x663c0000, 0x67fe0000,
  0x48c00000, 0x49020000, 0x4b440000, 0x4a860000,
  0x4fc80000, 0x4e0a0000, 0x4c4c0000, 0x4d8e0000,
  0x46d00000, 0x47120000, 0x45540000, 0x44960000,
  0x41d80000, 0x401a0000, 0x425c0000, 0x439e0000,
  0x54e00000, 0x55220000, 0x57640000, 0x56a60000,
  0x53e80000, 0x522a0000, 0x506c0000, 0x51ae0000,
  0x5af00000, 0x5b320000, 0x59740000, 0x58b60000,
  0x5df80000, 0x5c3a0000, 0x5e7c0000, 0x5fbe0000,
  0xe1000000, 0xe0c20000, 0xe2840000, 0xe3460000,
  0xe6080000, 0xe7ca0000, 0xe58c0000, 0xe44e0000,
  0xef100000, 0xeed20000, 0xec940000, 0xed560000,
  0xe8180000, 0xe9da0000, 0xeb9c0000, 0xea5e0000,
  0xfd200000, 0xfce20000, 0xfea40000, 0xff660000,
  0xfa280000, 0xfbea0000, 0xf9ac0000, 0xf86e0000,
  0xf3300000, 0xf2f20000, 0xf0b40000, 0xf1760000,
  0xf4380000, 0xf5fa0000, 0xf7bc0000, 0xf67e0000,
  0xd9400000, 0xd8820000, 0xdac40000, 0xdb060000,
  0xde480000, 0xdf8a0000, 0xddcc0000, 0xdc0e0000,
  0xd7500000, 0xd6920000, 0xd4d40000, 0xd5160000,
  0xd0580000, 0xd19a0000, 0xd3dc0000, 0xd21e0000,
  0xc5600000, 0xc4a20000, 0xc6e40000, 0xc7260000,
  0xc2680000, 0xc3aa0000, 0xc1ec0000, 0xc02e0000,
  0xcb700000, 0xcab20000, 0xc8f40000, 0xc9360000,
  0xcc780000, 0xcdba0000, 0xcffc0000, 0xce3e0000,
  0x91800000, 0x90420000, 0x92040000, 0x93c60000,
  0x96880000, 0x974a0000, 0x950c0000, 0x94ce0000,
  0x9f900000, 0x9e520000, 0x9c140000, 0x9dd60000,
  0x98980000, 0x995a0000, 0x9b1c0000, 0x9ade0000,
  0x8da00000, 0x8c620000, 0x8e240000, 0x8fe60000,
  0x8aa80000, 0x8b6a0000, 0x892c0000, 0x88ee0000,
  0x83b00000, 0x82720000, 0x80340000, 0x81f60000,
  0x84b80000, 0x857a0000, 0x873c0000, 0x86fe0000,
  0xa9c00000, 0xa8020000, 0xaa440000, 0xab860000,
  0xaec80000, 0xaf0a0000, 0xad4c0000, 0xac8e0000,
  0xa7d00000, 0xa6120000, 0xa4540000, 0xa5960000,
  0xa0d80000, 0xa11a0000, 0xa35c0000, 0xa29e0000,
  0xb5e00000, 0xb4220000, 0xb6640000, 0xb7a60000,
  0xb2e80000, 0xb32a0000, 0xb16c0000, 0xb0ae0000,
  0xbbf00000, 0xba320000, 0xb8740000, 0xb9b60000,
  0xbcf80000, 0xbd3a0000, 0xbf7c0000, 0xbebe0000,
};


/**************************************************************************/

static
unsigned char reverse_bits(unsigned char w)
{
  unsigned char tmp = 0;

  if (w & 0x1)
    tmp |= 0x80;
  if (w & 0x2)
    tmp |= 0x40;
  if (w & 0x4)
    tmp |= 0x20;
  if (w & 0x8)
    tmp |= 0x10;
  if (w & 0x10)
    tmp |= 0x8;
  if (w & 0x20)
    tmp |= 0x4;
  if (w & 0x40)
    tmp |= 0x2;
  if (w & 0x80)
    tmp |= 0x1;
  return tmp;
}

static
unsigned char reverse_nibble_bits(unsigned char w)
{
  unsigned char tmp = 0;

  if (w & 0x1)
    tmp |= 0x8;
  if (w & 0x2)
    tmp |= 0x4;
  if (w & 0x4)
    tmp |= 0x2;
  if (w & 0x8)
    tmp |= 0x1;
  return tmp;
}

void ssh_gf2n_128_init_ui(SshUInt32 *e, unsigned char w)
{
  w = reverse_bits(w);

  e[0] = (w & 0xff) << 24;
  e[1] = 0;
  e[2] = 0;
  e[3] = 0;
}


/* Multiply an element in GF128 represented by op by the base polynomial
   element (0,1,0,0,....0) storing the result to op. */
void ssh_gf2n_128_mul_base(SshUInt32 *op, SshUInt32 moduli)
{
  int carry_bit = op[3] & 0x1;

  op[3] = op[3] >> 1 | (op[2] & 0x1) << 31;
  op[2] = op[2] >> 1 | (op[1] & 0x1) << 31;
  op[1] = op[1] >> 1 | (op[0] & 0x1) << 31;
  op[0] = op[0] >> 1;

  if (carry_bit)
      op[0] ^= moduli;
}


/* Multiplication of X by Y, storing the result to X. */
void ssh_gf2n_128_mul(SshUInt32 *X, SshUInt32 *Y, SshUInt32 moduli)
{
  SshUInt32 t[4];
  int i;

  t[0] = X[0];
  t[1] = X[1];
  t[2] = X[2];
  t[3] = X[3];

  X[0]= X[1] = X[2] = X[3] = 0;

 for (i = 0; i < 128; i++)
    {
      if (Y[i / 32] & (1 << (31 - i % 32)))
        {
          X[0] ^= t[0];
          X[1] ^= t[1];
          X[2] ^= t[2];
          X[3] ^= t[3];
        }

      ssh_gf2n_128_mul_base(t, moduli);
    }
}





void
ssh_gf2n_128_table_byte_init(void *workspace, SshUInt32 *H,
                             SshUInt32 moduli, unsigned int table_index)
{
  SshUInt32 *m = workspace;
  unsigned int i, j, index;

  SSH_ASSERT(table_index < 16);

  /* m[i] = x_i . H . P^8i */
  for (i = 0; i < 256; i++)
    {
      index = reverse_bits((unsigned char)i);
      ssh_gf2n_128_init_ui(m + 4 * index, (unsigned char)i);

      ssh_gf2n_128_mul(m + 4 * index, H, moduli);
      for (j = 0; j < 8 * table_index; j++)
        ssh_gf2n_128_mul_base(m + 4 * index, moduli);
    }
}

#define GF2N_128_TABLE_BYTE_MUL(ret, op, m, i)                              \
(ret)[0] ^= (m)[4*(256*(i)+(((op)[(i)>>2] >> (24-8*((i) & 3))) & 0xff))];    \
(ret)[1] ^= (m)[4*(256*(i)+(((op)[(i)>>2] >> (24-8*((i) & 3))) & 0xff)) + 1];\
(ret)[2] ^= (m)[4*(256*(i)+(((op)[(i)>>2] >> (24-8*((i) & 3))) & 0xff)) + 2];\
(ret)[3] ^= (m)[4*(256*(i)+(((op)[(i)>>2] >> (24-8*((i) & 3))) & 0xff)) + 3];

/***** Shoup's 8 bit table *************************************************/


#define GF2N_128_TABLE_SHOUP_8_BIT_MUL(ret, op, m, i)                     \
(ret)[0] ^= (m)[4*(((op)[(i)>>2] >> (24 - 8 * ((i) & 3))) & 0xff)];       \
(ret)[1] ^= (m)[4*(((op)[(i)>>2] >> (24 - 8 * ((i) & 3))) & 0xff) + 1];   \
(ret)[2] ^= (m)[4*(((op)[(i)>>2] >> (24 - 8 * ((i) & 3))) & 0xff) + 2];   \
(ret)[3] ^= (m)[4*(((op)[(i)>>2] >> (24 - 8 * ((i) & 3))) & 0xff) + 3];


#define GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(op, w)   \
 w = op[3] & 0xff;                                  \
 op[3] = op[3] >> 8 | (op[2] & 0xff) << 24;         \
 op[2] = op[2] >> 8 | (op[1] & 0xff) << 24;         \
 op[1] = op[1] >> 8 | (op[0] & 0xff) << 24;         \
 op[0] = op[0] >> 8 ^ ssh_gcm_aes_shoup_8_bit[w];





void
ssh_gf2n_128_table_nibble_init(void *workspace, SshUInt32 *H,
                               SshUInt32 moduli, unsigned int table_index)
{
  SshUInt32 *m = workspace;
  unsigned int i, j, index;

  SSH_ASSERT(table_index < 32);

  /* m[i] = x_i . H . P^4i */
  for (i = 0; i < 16; i++)
    {
      index = reverse_nibble_bits((unsigned char)i);

      ssh_gf2n_128_init_ui(m + 4 * index, (unsigned char)i);
      ssh_gf2n_128_mul(m + 4 * index, H, moduli);

     for (j = 0; j < 4 * table_index; j++)
        ssh_gf2n_128_mul_base(m + 4 * index, moduli);
    }
}


#define GF2N_128_TABLE_NIBBLE_MUL(ret, op, m, i)                            \
(ret)[0] ^= (m)[4*(16*(i)+(((op)[(i)>>3] >> (28-4*((i) & 7))) & 0xf))];     \
(ret)[1] ^= (m)[4*(16*(i)+(((op)[(i)>>3] >> (28-4*((i) & 7))) & 0xf)) + 1]; \
(ret)[2] ^= (m)[4*(16*(i)+(((op)[(i)>>3] >> (28-4*((i) & 7))) & 0xf)) + 2]; \
(ret)[3] ^= (m)[4*(16*(i)+(((op)[(i)>>3] >> (28-4*((i) & 7))) & 0xf)) + 3];


/***** Shoup's 4 bit table *************************************************/

#define GF2N_128_TABLE_SHOUP_4_BIT_MUL(ret, op, m, i)                    \
(ret)[0] ^= (m)[4*(((op)[(i)>>3] >> (28 - 4 * ((i) & 7))) & 0xf)];       \
(ret)[1] ^= (m)[4*(((op)[(i)>>3] >> (28 - 4 * ((i) & 7))) & 0xf) + 1];   \
(ret)[2] ^= (m)[4*(((op)[(i)>>3] >> (28 - 4 * ((i) & 7))) & 0xf) + 2];   \
(ret)[3] ^= (m)[4*(((op)[(i)>>3] >> (28 - 4 * ((i) & 7))) & 0xf) + 3];


#define GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(op, w) \
 w = op[3] & 0xf;                                   \
 op[3] = op[3] >> 4 | (op[2] & 0xf) << 28;          \
 op[2] = op[2] >> 4 | (op[1] & 0xf) << 28;          \
 op[1] = op[1] >> 4 | (op[0] & 0xf) << 28;          \
 op[0] = op[0] >> 4 ^ ssh_gcm_aes_shoup_4_bit[w];


/**************************************************************************/

typedef void (*SshGcmUpdateBlock)(void *ctx, const unsigned char *buf);

void gcm_update_block_words_table(void *ctx, const unsigned char *buf);
void gcm_update_block_words_nibble(void *ctx, const unsigned char *buf);
void gcm_update_block_shoup_8_bit(void *ctx, const unsigned char *buf);
void gcm_update_block_shoup_4_bit(void *ctx, const unsigned char *buf);
void gcm_update_block(void *ctx, const unsigned char *buf);

typedef struct
{
  unsigned char encr_y0[16];

  unsigned char in[16];
  unsigned char iv[16];
  SshUInt32 encr_data[2];
  SshUInt32 auth_data[2];

  /* cipher ccontext used for IV encryption */
  void *aes_ecb_cipher_ctx;

  SshGcmUpdateBlock update_block;

  SshUInt32 H[4], X[4];
  SshUInt32 mod;

  SshUInt8 encryption_started;
  SshUInt8 for_encryption;
  SshUInt8 in_error;
  SshUInt8 table_256;
  SshUInt8 table_4k;
  SshUInt8 table_8k;
  SshUInt8 table_64k;

  void *workspace;

} SshGCMCtx;


size_t
ssh_gcm_aes_ctxsize(void)
{
  return sizeof(SshGCMCtx) + ssh_rijndael_ctxsize();
}

size_t
ssh_gcm_aes_table_64k_ctxsize(void)
{
  return (sizeof(SshGCMCtx) + ssh_rijndael_ctxsize() +
         (16 * 256 * sizeof(SshUInt32[4])));
}

size_t
ssh_gcm_aes_table_8k_ctxsize(void)
{
  return (sizeof(SshGCMCtx) + ssh_rijndael_ctxsize() +
         (32 * 16 * sizeof(SshUInt32[4])));
}

size_t
ssh_gcm_aes_table_4k_ctxsize(void)
{
  return (sizeof(SshGCMCtx) + ssh_rijndael_ctxsize() +
         (256 * sizeof(SshUInt32[4])));
}

size_t
ssh_gcm_aes_table_256_ctxsize(void)
{
  return (sizeof(SshGCMCtx) + ssh_rijndael_ctxsize() +
         (16 * sizeof(SshUInt32[4])));
}


SshCryptoStatus
ssh_gcm_init(void *context, const unsigned char *key, size_t keylen,
             Boolean for_encryption, size_t table_size)
{
  SshGCMCtx *created = context;
  SshCryptoStatus status;
  unsigned char encr_zero[16];
  int i;

  SSH_DEBUG(SSH_D_LOWOK, ("Entered"));

  memset(created, 0, sizeof(*created));
  created->for_encryption = (SshUInt8)for_encryption;

  created->aes_ecb_cipher_ctx = (unsigned char *)created + sizeof(SshGCMCtx);

  status = ssh_aes_init(created->aes_ecb_cipher_ctx, key, keylen, TRUE);

  if (status == SSH_CRYPTO_OK)
    {

      memset(encr_zero, 0, sizeof(encr_zero));

      status =  ssh_rijndael_ecb(created->aes_ecb_cipher_ctx,
                                 encr_zero,
                                 encr_zero,
                                 sizeof(encr_zero));
    }

  if (status != SSH_CRYPTO_OK)
    {
#ifdef KERNEL
      SSH_DEBUG(SSH_D_FAIL, ("Cipher initialization failed status=%u",
                             (unsigned int)status));
#else /* !KERNEL */
      SSH_DEBUG(SSH_D_FAIL, ("Cipher transform failed status=%s",
                             ssh_crypto_status_message(status)));
#endif /* KERNEL */
      return status;
    }

 created->mod = (1 << 31) + (1 << 30) + (1 << 29) + (1 << 24);

 created->H[0] = SSH_GET_32BIT(encr_zero);
 created->H[1] = SSH_GET_32BIT(encr_zero + 4);
 created->H[2] = SSH_GET_32BIT(encr_zero + 8);
 created->H[3] = SSH_GET_32BIT(encr_zero + 12);

 switch (table_size)
   {
   case 0:
     created->update_block = gcm_update_block;
     created->workspace = NULL;
     break;

     case 65536:
       created->update_block = gcm_update_block_words_table;
       created->workspace = (unsigned char *)created + sizeof(SshGCMCtx) +
                            ssh_rijndael_ctxsize();

      for (i = 0; i < 16; i++)
        ssh_gf2n_128_table_byte_init((unsigned char *)created->workspace +
                                     i * 256 * sizeof(SshUInt32[4]),
                                     created->H, created->mod, i);
      created->table_64k = 1;
      break;

   case 8192:
     created->update_block = gcm_update_block_words_nibble;
     created->workspace = (unsigned char *)created + sizeof(SshGCMCtx) +
                          ssh_rijndael_ctxsize();


     for (i = 0; i < 32; i++)
       ssh_gf2n_128_table_nibble_init((unsigned char *)created->workspace +
                                      i * 16 * sizeof(SshUInt32[4]),
                                      created->H, created->mod, i);
     created->table_8k = 1;
     break;

   case 4096:
     created->update_block = gcm_update_block_shoup_8_bit;
     created->workspace = (unsigned char *)created + sizeof(SshGCMCtx) +
                          ssh_rijndael_ctxsize();

     ssh_gf2n_128_table_byte_init(created->workspace,
                                  created->H, created->mod, 0);
     created->table_4k = 1;
     break;

   case 256:
     created->update_block = gcm_update_block_shoup_4_bit;
     created->workspace = (unsigned char *)created + sizeof(SshGCMCtx) +
                          ssh_rijndael_ctxsize();

     ssh_gf2n_128_table_nibble_init(created->workspace,
                                    created->H, created->mod, 0);
     created->table_256 = 1;
     break;

   default:
     return SSH_CRYPTO_UNSUPPORTED;
   }
  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_gcm_aes_init(void *context, const unsigned char *key, size_t keylen,
                 Boolean for_encryption)
{
 return ssh_gcm_init(context, key, keylen, for_encryption, 0);
}

SshCryptoStatus
ssh_gcm_aes_table_64k_init(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption)
{
 return ssh_gcm_init(context, key, keylen, for_encryption, 65536);
}

SshCryptoStatus
ssh_gcm_aes_table_8k_init(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption)
{
 return ssh_gcm_init(context, key, keylen, for_encryption, 8192);
}

SshCryptoStatus
ssh_gcm_aes_table_4k_init(void *context,
                          const unsigned char *key, size_t keylen,
                          Boolean for_encryption)
{
 return ssh_gcm_init(context, key, keylen, for_encryption, 4096);
}

SshCryptoStatus
ssh_gcm_aes_table_256_init(void *context,
                           const unsigned char *key, size_t keylen,
                           Boolean for_encryption)
{
 return ssh_gcm_init(context, key, keylen, for_encryption, 256);
}

void gcm_update_block(void *context, const unsigned char *buf)
{
  SshGCMCtx *ctx = (SshGCMCtx *)context;
  SshUInt32 *X = ctx->X;

  X[0] ^= SSH_GET_32BIT(buf);
  X[1] ^= SSH_GET_32BIT(buf + 4);
  X[2] ^= SSH_GET_32BIT(buf + 8);
  X[3] ^= SSH_GET_32BIT(buf + 12);

  ssh_gf2n_128_mul(X, ctx->H, ctx->mod);
}

void gcm_update_block_words_table(void *context, const unsigned char *buf)
{
  SshGCMCtx *ctx = (SshGCMCtx *)context;
  SshUInt32 *m = ctx->workspace;
  SshUInt32 *X = ctx->X;
  SshUInt32 t[4];
#ifdef MINIMAL_STACK
  SShUInt32 i;
#endif /* MINIMAL_STACK */

  X[0] ^= SSH_GET_32BIT(buf);
  X[1] ^= SSH_GET_32BIT(buf + 4);
  X[2] ^= SSH_GET_32BIT(buf + 8);
  X[3] ^= SSH_GET_32BIT(buf + 12);

  t[0] = t[1] = t[2] = t[3] = 0;

#ifdef MINIMAL_STACK
  i = 0;
  while (i < 16)
    {
      GF2N_128_TABLE_BYTE_MUL(t, X, m, i);
      GF2N_128_TABLE_BYTE_MUL(t, X, m, i + 1);
      GF2N_128_TABLE_BYTE_MUL(t, X, m, i + 2);
      GF2N_128_TABLE_BYTE_MUL(t, X, m, i + 3);
      i += 4;
    }
#else  /* MINIMAL_STACK */
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 0);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 1);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 2);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 3);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 4);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 5);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 6);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 7);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 8);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 9);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 10);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 11);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 12);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 13);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 14);
  GF2N_128_TABLE_BYTE_MUL(t, X, m, 15);
#endif /* MINIMAL_STACK */

  X[0] = t[0];
  X[1] = t[1];
  X[2] = t[2];
  X[3] = t[3];
}

void gcm_update_block_words_nibble(void *context, const unsigned char *buf)
{
  SshGCMCtx *ctx = (SshGCMCtx *)context;
  SshUInt32 *m = ctx->workspace;
  SshUInt32 *X = ctx->X;
  SshUInt32 t[4];
#ifdef MINIMAL_STACK
  SshUInt32 i;
#endif /* MINIMAL_STACK */

  X[0] ^= SSH_GET_32BIT(buf);
  X[1] ^= SSH_GET_32BIT(buf + 4);
  X[2] ^= SSH_GET_32BIT(buf + 8);
  X[3] ^= SSH_GET_32BIT(buf + 12);

  t[0] = t[1] = t[2] = t[3] = 0;

#ifdef MINIMAL_STACK
  i = 0;
  while (i < 32)
    {
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 1);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 2);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 3);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 4);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 5);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 6);
      GF2N_128_TABLE_NIBBLE_MUL(t, X, m, i + 7);
      i += 8;
     }
#else /* MINIMAL_STACK */
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 0);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 1);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 2);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 3);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 4);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 5);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 6);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 7);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 8);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 9);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 10);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 11);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 12);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 13);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 14);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 15);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 16);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 17);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 18);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 19);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 20);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 21);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 22);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 23);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 24);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 25);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 26);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 27);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 28);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 29);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 30);
  GF2N_128_TABLE_NIBBLE_MUL(t, X, m, 31);
#endif /* MINIMAL_STACK */

  X[0] = t[0];
  X[1] = t[1];
  X[2] = t[2];
  X[3] = t[3];
}

void gcm_update_block_shoup_8_bit(void *context, const unsigned char *buf)
{
  SshGCMCtx *ctx = (SshGCMCtx *)context;
  SshUInt32 *m = ctx->workspace;
  SshUInt32 *X = ctx->X;
#ifdef MINIMAL_STACK
  SshUInt32 i;
#endif /* MINIMAL_STACK */
  SshUInt32 t[4];
  unsigned char w;

  X[0] ^= SSH_GET_32BIT(buf);
  X[1] ^= SSH_GET_32BIT(buf + 4);
  X[2] ^= SSH_GET_32BIT(buf + 8);
  X[3] ^= SSH_GET_32BIT(buf + 12);

  t[0] = t[1] = t[2] = t[3] = 0;

#ifdef MINIMAL_STACK
  i = 0;
  while (i < 12)
    {
      GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 15 - i);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 14 - i);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 13 - i);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 12 - i);
      GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);

      i += 4;
    }
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 3);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 2);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 1);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  /* No carry after the last multiplication */
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 0);

#else /* MINIMAL_STACK */

  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 15);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 14);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 13);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 12);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 11);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 10);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 9);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 8);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 7);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 6);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 5);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 4);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 3);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 2);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 1);
  GF2N_128_TABLE_SHOUP_8_BIT_MUL_POW(t, w);
  /* No carry after the last multiplication */
  GF2N_128_TABLE_SHOUP_8_BIT_MUL(t, X, m, 0);
#endif /* MINIMAL_STACK */

  X[0] = t[0];
  X[1] = t[1];
  X[2] = t[2];
  X[3] = t[3];
}

void gcm_update_block_shoup_4_bit(void *context, const unsigned char *buf)
{
  SshGCMCtx *ctx = (SshGCMCtx *)context;
  SshUInt32 *m = ctx->workspace;
  SshUInt32 *X = ctx->X;
#ifdef MINIMAL_STACK
  SshUInt32 i;
#endif /* MINIMAL_STACK */
  SshUInt32 t[4];
  unsigned char w;

  X[0] ^= SSH_GET_32BIT(buf);
  X[1] ^= SSH_GET_32BIT(buf + 4);
  X[2] ^= SSH_GET_32BIT(buf + 8);
  X[3] ^= SSH_GET_32BIT(buf + 12);

  t[0] = t[1] = t[2] = t[3] = 0;

#ifdef MINIMAL_STACK
  i = 0;
  while (i < 28)
    {
      GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 31 - i);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 30 - i);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 29 - i);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 28 - i);
      GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

      i+= 4;
    }
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 3);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 2);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 1);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  /* No carry after the last multiplication */
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 0);
#else /* MINIMAL_STACK */

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 31);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 30);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 29);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 28);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 27);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 26);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 25);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 24);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 23);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 22);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 21);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 20);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 19);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 18);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 17);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 16);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 15);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 14);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 13);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 12);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 11);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 10);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 9);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 8);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 7);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 6);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 5);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 4);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 3);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 2);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);

  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 1);
  GF2N_128_TABLE_SHOUP_4_BIT_MUL_POW(t, w);
  /* No carry after the last multiplication */
  GF2N_128_TABLE_SHOUP_4_BIT_MUL(t, X, m, 0);
#endif /* MINIMAL_STACK */


  X[0] = t[0];
  X[1] = t[1];
  X[2] = t[2];
  X[3] = t[3];
}

static void
gcm_update(void *context, const unsigned char *buf, size_t len,
           Boolean final)
{
  SshGCMCtx *ctx = context;
  SshUInt32 t;

  SSH_DEBUG(SSH_D_MY, ("GCM Update entered"));

  /* Data for authentication only (not encrypted) must be processed before
     any data is encrypted. */
  if (ctx->encryption_started)
    {
      ctx->in_error = 1;
      return;
    }

  /* Update bitcount */

  t = ctx->auth_data[0];
  if ((ctx->auth_data[0] = (t + ((SshUInt32)len << 3)) & 0xffffffffL) < t)
    ctx->auth_data[1]++;             /* Carry from low to high */

  ctx->auth_data[1] += (SshUInt32)len >> 29;

  /* Bytes already in ctx->in */
  t = (t >> 3) & 0xf;

  /* Handle any leading odd-sized chunks */
  if (t)
    {
      unsigned char *p = ctx->in + t;

      t = 16 - t;

      if (final)
        {
          memset(p, 0, t);
          (*ctx->update_block)(ctx, ctx->in);
          return;
        }

      if (len < t)
        {
          memcpy(p, buf, len);
          return;
        }
      memcpy(p, buf, t);
      (*ctx->update_block)(ctx, ctx->in);
      buf += t;
      len -= t;
    }

  /* Process data in 16-byte chunks */
  while (len >= 16)
    {
      (*ctx->update_block)(ctx, buf);
      buf += 16;
      len -= 16;
    }

  /* Handle any remaining bytes of data. */
  if (len)
    memcpy(ctx->in, buf, len);
  return;
}


SshCryptoStatus ssh_gcm_auth_start(void *context, const unsigned char *iv,
                                   const unsigned char *aad, size_t aad_len,
                                   size_t crypt_len)
{
  SshGCMCtx *ctx = context;
  unsigned char iv_zero[16];
  SshCryptoStatus status;
  SshUInt32 ctr;

  ctx->encr_data[0] = 0;
  ctx->encr_data[1] = 0;
  ctx->auth_data[0] = 0;
  ctx->auth_data[1] = 0;

  ctx->encryption_started = 0;
  ctx->in_error = 0;

  ctx->X[0] = 0;
  ctx->X[1] = 0;
  ctx->X[2] = 0;
  ctx->X[3] = 0;

  memset(ctx->in, 0, sizeof(ctx->in));
  memset(iv_zero, 0, sizeof(iv_zero));

  /* copy iv */
  memcpy(ctx->iv, iv, 16);

  gcm_update(context, aad, aad_len, FALSE);

  status = ssh_rijndael_start(ctx->aes_ecb_cipher_ctx, iv_zero);
  if (status != SSH_CRYPTO_OK)
    return status;

  status =  ssh_rijndael_ecb(ctx->aes_ecb_cipher_ctx,
                             ctx->encr_y0,
                             ctx->iv, 16);
  if (status != SSH_CRYPTO_OK)
    return status;

  ctr = SSH_GET_32BIT(ctx->iv + 12);
  ctr++;
  SSH_PUT_32BIT(ctx->iv + 12, ctr);

  return SSH_CRYPTO_OK;
}

void
ssh_gcm_update(void *context, const unsigned char *buf, size_t len)
{
  gcm_update(context, buf, len, FALSE);
  return;
}

SshCryptoStatus ssh_gcm_final(void *context, unsigned char *digest)
{
  SshGCMCtx *ctx = context;
  unsigned char buf[16];
  SshUInt32 t1, t2, t3, t4;

  if (ctx->in_error)
    return SSH_CRYPTO_OPERATION_FAILED;

  if (!ctx->encryption_started)
    {
      gcm_update(ctx, NULL, 0, TRUE);

      ctx->encryption_started = 1;
    }

  SSH_PUT_32BIT(buf, ctx->auth_data[1]);
  SSH_PUT_32BIT(buf + 4, ctx->auth_data[0]);
  SSH_PUT_32BIT(buf + 8, ctx->encr_data[1]);
  SSH_PUT_32BIT(buf + 12, ctx->encr_data[0]);
  (*ctx->update_block)(ctx, buf);

  t1 = SSH_GET_32BIT(ctx->encr_y0)      ^ ctx->X[0];
  t2 = SSH_GET_32BIT(ctx->encr_y0 + 4)  ^ ctx->X[1];
  t3 = SSH_GET_32BIT(ctx->encr_y0 + 8)  ^ ctx->X[2];
  t4 = SSH_GET_32BIT(ctx->encr_y0 + 12) ^ ctx->X[3];

  SSH_PUT_32BIT(digest, t1);
  SSH_PUT_32BIT(digest + 4, t2);
  SSH_PUT_32BIT(digest + 8, t3);
  SSH_PUT_32BIT(digest + 12, t4);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_gcm_64_final(void *context, unsigned char *digest)
{
  unsigned char tmp[16];
  SshCryptoStatus stat;

  stat = ssh_gcm_final(context, tmp);
  if (stat == SSH_CRYPTO_OK)
    {
      memcpy(digest, tmp, 8);
    }
  return stat;
}

SshCryptoStatus ssh_gcm_96_final(void *context, unsigned char *digest)
{
  unsigned char tmp[16];
  SshCryptoStatus stat;

  stat = ssh_gcm_final(context, tmp);
  if (stat == SSH_CRYPTO_OK)
    {
      memcpy(digest, tmp, 12);
    }
  return stat;
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
  SshGCMCtx *ctx = context;
  unsigned char buf[16];
  SshUInt32 ctr, t, t1, t2, t3, t4;
  SshCryptoStatus status;

  SSH_DEBUG(SSH_D_MY, ("GCM Transform entered"));

  if (!ctx->encryption_started)
    {
      gcm_update(ctx, NULL, 0, TRUE);

      ctx->encryption_started = 1;
    }

  /* Update bitcount */
  t = ctx->encr_data[0];
  if ((ctx->encr_data[0] = (t + ((SshUInt32)len << 3)) & 0xffffffffL) < t)
    ctx->encr_data[1]++;             /* Carry from low to high */

  ctx->encr_data[1] += (SshUInt32)len >> 29;

  /* Encrypt data and update the digest tag. */
  if (ctx->for_encryption)
    {
      while (len >= 16)
        {
          status = ssh_rijndael_ecb(ctx->aes_ecb_cipher_ctx, buf, ctx->iv, 16);

          if (status != SSH_CRYPTO_OK)
            return status;

          t1 = SSH_GET_32BIT(src) ^ SSH_GET_32BIT(buf);
          SSH_PUT_32BIT(dest, t1);
          t2 = SSH_GET_32BIT(src + 4) ^ SSH_GET_32BIT(buf + 4);
          SSH_PUT_32BIT(dest + 4, t2);
          t3 = SSH_GET_32BIT(src + 8) ^ SSH_GET_32BIT(buf + 8);
          SSH_PUT_32BIT(dest + 8, t3);
          t4 = SSH_GET_32BIT(src + 12) ^ SSH_GET_32BIT(buf + 12);
          SSH_PUT_32BIT(dest + 12, t4);

          (*ctx->update_block)(ctx, dest);

          ctr = SSH_GET_32BIT(ctx->iv + 12);
          ctr++;
          SSH_PUT_32BIT(ctx->iv + 12, ctr);

          src += 16;
          dest += 16;
          len -= 16;
        }

      if (len != 0)
        {
          unsigned char temp[16];

          status = ssh_rijndael_ecb(ctx->aes_ecb_cipher_ctx, buf, ctx->iv, 16);

          if (status != SSH_CRYPTO_OK)
            return status;

          t = SSH_GET_32BIT(src) ^ SSH_GET_32BIT(buf);
          SSH_PUT_32BIT(temp, t);
          t = SSH_GET_32BIT(src + 4) ^ SSH_GET_32BIT(buf + 4);
          SSH_PUT_32BIT(temp + 4, t);
          t = SSH_GET_32BIT(src + 8) ^ SSH_GET_32BIT(buf + 8);
          SSH_PUT_32BIT(temp + 8, t);
          t = SSH_GET_32BIT(src + 12) ^ SSH_GET_32BIT(buf + 12);
          SSH_PUT_32BIT(temp + 12, t);

          memset(buf, 0, 16);
          memcpy(buf, temp, len);
          memcpy(dest, temp, len);

          (*ctx->update_block)(ctx, buf);
        }
    }
  else
    {
      while (len >= 16)
        {
          (*ctx->update_block)(ctx, src);

          status = ssh_rijndael_ecb(ctx->aes_ecb_cipher_ctx, buf, ctx->iv, 16);

          if (status != SSH_CRYPTO_OK)
            return status;

          t = SSH_GET_32BIT(src) ^ SSH_GET_32BIT(buf);
          SSH_PUT_32BIT(dest, t);
          t = SSH_GET_32BIT(src + 4) ^ SSH_GET_32BIT(buf + 4);
          SSH_PUT_32BIT(dest + 4, t);
          t = SSH_GET_32BIT(src + 8) ^ SSH_GET_32BIT(buf + 8);
          SSH_PUT_32BIT(dest + 8, t);
          t = SSH_GET_32BIT(src + 12) ^ SSH_GET_32BIT(buf + 12);
          SSH_PUT_32BIT(dest + 12, t);

          ctr = SSH_GET_32BIT(ctx->iv + 12);
          ctr++;
          SSH_PUT_32BIT(ctx->iv + 12, ctr);

          src += 16;
          dest += 16;
          len -= 16;
        }

      if (len != 0)
        {
          unsigned char temp[16];

          memset(buf, 0, 16);
          memcpy(buf, src, len);

          (*ctx->update_block)(ctx, buf);

          status = ssh_rijndael_ecb(ctx->aes_ecb_cipher_ctx, buf, ctx->iv, 16);

          if (status != SSH_CRYPTO_OK)
            return status;

          t = SSH_GET_32BIT(src) ^ SSH_GET_32BIT(buf);
          SSH_PUT_32BIT(temp, t);
          t = SSH_GET_32BIT(src + 4) ^ SSH_GET_32BIT(buf + 4);
          SSH_PUT_32BIT(temp + 4, t);
          t = SSH_GET_32BIT(src + 8) ^ SSH_GET_32BIT(buf + 8);
          SSH_PUT_32BIT(temp + 8, t);
          t = SSH_GET_32BIT(src + 12) ^ SSH_GET_32BIT(buf + 12);
          SSH_PUT_32BIT(temp + 12, t);

          memcpy(dest, temp, len);
        }
    }

  return SSH_CRYPTO_OK;
}

/* Helper function that looks like ssh_gcm_transform, but
   instead does no encryption but just authenticates data.
   This is used to implement gmac-aes combined "cipher". */
SshCryptoStatus ssh_gmac_transform(void *context,
                                   unsigned char *dest,
                                   const unsigned char *src,
                                   size_t len)
{
  gcm_update(context, src, len, FALSE);
  if (dest != src) memcpy(dest, src, len);
  return SSH_CRYPTO_OK;
}


#endif /* !HAVE_AES_INTEL_INSTRUCTION_SET */
#endif /* SSHDIST_CRYPT_MODE_GCM */
