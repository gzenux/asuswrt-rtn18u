/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   File implements SHA-256 algorithm and variant SHA-224 [RFC 3874].
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "hash-oid.h"
#include "sshgetput.h"

#include "sha256.h"

#define SSH_DEBUG_MODULE "SshSha"

/* Define SHA-256 in transparent way. */
const SshHashDefStruct ssh_hash_sha256_def =
{
  /* Name of the hash function. */
  "sha256",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.1",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Digest size. */
  32,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha256_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha256_reset_context,
  /* Update function */
  ssh_sha256_update,
  /* Final */
  ssh_sha256_final,
  /* ASN1. */
  ssh_hash_oid_asn1_compare_sha256,
  ssh_hash_oid_asn1_generate_sha256
};

/* Define SHA-224 in transparent way. */
const SshHashDefStruct ssh_hash_sha224_def =
{
  /* Name of the hash function. */
  "sha224",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.4",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Digest size. */
  28,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha256_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha224_reset_context,
  /* Update function */
  ssh_sha256_update,
  /* Final */
  ssh_sha224_final,
  /* ASN1. */
  ssh_hash_oid_asn1_compare_sha224,
  ssh_hash_oid_asn1_generate_sha224
};

/* Define SHA-256 in transparent way. */
const SshHashDefStruct ssh_hash_sha256_128_def =
{
  /* Name of the hash function. */
  "sha256-128",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  16,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha256_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha256_reset_context,
  /* Update function */
  ssh_sha256_update,
  /* Final */
  ssh_sha256_128_final,
  /* No ASN1. */
  NULL, NULL
};

/* Define SHA-256 in transparent way. */
const SshHashDefStruct ssh_hash_sha256_96_def =
{
  /* Name of the hash function. */
  "sha256-96",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  12,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha256_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha256_reset_context,
  /* Update function */
  ssh_sha256_update,
  /* Final */
  ssh_sha256_96_final,
  /* No ASN1. */
  NULL, NULL
};

/* Define SHA-256 in transparent way. */
const SshHashDefStruct ssh_hash_sha256_80_def =
{
  /* Name of the hash function. */
  "sha256-80",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Digest size. */
  10,
  /* Input block length. */
  64,
  /* Context size */
  ssh_sha256_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha256_reset_context,
  /* Update function */
  ssh_sha256_update,
  /* Final */
  ssh_sha256_80_final,
  /* No ASN1. */
  NULL, NULL
};

typedef struct
{
  SshUInt32 H[8];
  union
  {
    unsigned char in[64]; /* Input data as bytes. (If buffer is large,
                             it shall be fed directly.) */
    SshUInt32 W[16]; /* Input data after conversion to 32-bit words. */
  } u;
  SshUInt32 total_length[2];
} SshSHA256Context;

/* Right shift and rotate. */
#define ROT32(x,s)   ((((x) >> s) | ((x) << (32 - s))) & 0xffffffff)
#define SHIFT32(x,s) ((x) >> s)

/* These can be optimized---but lets do it when everything works. */
#define CH(x,y,z)  (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define BIG_SIGMA0(x)  (ROT32(x,2) ^ ROT32(x,13) ^ ROT32(x, 22))
#define BIG_SIGMA1(x)  (ROT32(x,6) ^ ROT32(x,11) ^ ROT32(x,25))
#define SMALL_SIGMA0(x) (ROT32(x,7) ^ ROT32(x,18) ^ SHIFT32(x,3))
#define SMALL_SIGMA1(x) (ROT32(x,17) ^ ROT32(x,19) ^ SHIFT32(x,10))

/* We assume that the compiler does a good job in inlining these. Any
   decent compiler should be able to observe that these are constant
   data and could thus move the values inline the code. Obviously
   this might not be the case here as one has a lot of places where
   these are requested. */
static const SshUInt32 table_h[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
  0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
static const SshUInt32 table_h224[8] = {
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31,
  0x68581511, 0x64f98fa7, 0xbefa4fa4 };
static const SshUInt32 table_c[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void ssh_sha256_reset_context(void *c)
{
  SshSHA256Context *ctx = c;
  unsigned int i;

  for (i = 0; i < 8; i++)
    ctx->H[i] = table_h[i];

  ctx->total_length[0] = 0;
  ctx->total_length[1] = 0;
}

void ssh_sha224_reset_context(void *c)
{
  SshSHA256Context *ctx = c;
  unsigned int i;

  for (i = 0; i < 8; i++)
    ctx->H[i] = table_h224[i];

  ctx->total_length[0] = 0;
  ctx->total_length[1] = 0;
}

size_t ssh_sha256_ctxsize()
{
  return sizeof(SshSHA256Context);
}

/* Takes value from scheduled key or computes this key. */
#define FETCH_W(x)                                                        \
do { if (x >= 16) {                                                       \
    ctx->u.W[(x)%16] = SMALL_SIGMA1(ctx->u.W[((x)-2)%16]) +               \
                       ctx->u.W[((x)-7)%16] +                             \
                       SMALL_SIGMA0(ctx->u.W[((x)-15)%16]) +              \
                       ctx->u.W[((x)-16)%16];                             \
} } while(0)
#define GET_W(x) ctx->u.W[(x)%16]

/* Single round of the SHA-256 compression function. Observe that we
   avoid copying material by renaming the variables. */
#define ROUND(a,b,c,d,e,f,g,h,j) \
do { \
  FETCH_W(j); \
  T1 = h + BIG_SIGMA1(e) + CH(e,f,g) + table_c[j] + GET_W(j); \
  T2 = BIG_SIGMA0(a) + MAJ(a,b,c); \
  d += T1; h = T1 + T2; \
} while(0)


static void sha256_transform(SshSHA256Context *ctx,
                             const unsigned char *block)
{
  int i;
  SshUInt32 a,b,c,d,e,f,g,h;
  SshUInt32 T1,T2; /* For ROUND() macro. */

  /* Naive implementation. */

  /* Key scheduling. */

  for (i = 15; i >= 0; i--)
    ctx->u.W[i] = SSH_GET_32BIT(&block[i*4]);

  /* Now the actual engine. */

  /* Copy the internal state to local registers. */
  a = ctx->H[0];
  b = ctx->H[1];
  c = ctx->H[2];
  d = ctx->H[3];
  e = ctx->H[4];
  f = ctx->H[5];
  g = ctx->H[6];
  h = ctx->H[7];

  /* Fully expanded compression loop. */
#define BLOCK(j) \
  ROUND(a,b,c,d,e,f,g,h,j*8+0); \
  ROUND(h,a,b,c,d,e,f,g,j*8+1); \
  ROUND(g,h,a,b,c,d,e,f,j*8+2); \
  ROUND(f,g,h,a,b,c,d,e,j*8+3); \
  ROUND(e,f,g,h,a,b,c,d,j*8+4); \
  ROUND(d,e,f,g,h,a,b,c,j*8+5); \
  ROUND(c,d,e,f,g,h,a,b,j*8+6); \
  ROUND(b,c,d,e,f,g,h,a,j*8+7);

  for(i = 0; i < 8; i++)
    {
      BLOCK(i);
    }

  /* Update the internal state. */
  ctx->H[0] = a + ctx->H[0];
  ctx->H[1] = b + ctx->H[1];
  ctx->H[2] = c + ctx->H[2];
  ctx->H[3] = d + ctx->H[3];
  ctx->H[4] = e + ctx->H[4];
  ctx->H[5] = f + ctx->H[5];
  ctx->H[6] = g + ctx->H[6];
  ctx->H[7] = h + ctx->H[7];
}

/* The rest is basically equivalent to the SHA-1 implementation. */

void ssh_sha256_update(void *c, const unsigned char *buf, size_t len)
{
  SshSHA256Context *context = c;
  unsigned int to_copy = 0;
  unsigned int in_buffer;

  SshUInt32 old_length = context->total_length[0];

  in_buffer = old_length % 64;

  context->total_length[0] += len;
  context->total_length[0] &= 0xFFFFFFFFL;

  if (context->total_length[0] < old_length) /* carry */
    context->total_length[1]++;

  while (len > 0)
    {
      if (in_buffer == 0 && len >= 64)
        {
          sha256_transform(context, buf);
          buf += 64;
          len -= 64;
          continue;
        }

      /* do copy? */
      to_copy = 64 - in_buffer;
      if (to_copy > 0)
        {
          if (to_copy > len)
            to_copy = len;
          memcpy(&context->u.in[in_buffer],
                 buf, to_copy);
          buf += to_copy;
          len -= to_copy;
          in_buffer += to_copy;
          if (in_buffer == 64)
            {
              sha256_transform(context, context->u.in);
              in_buffer = 0;
            }
        }
    }
}

SshCryptoStatus ssh_sha256_final(void *c, unsigned char *digest)
{
  SshSHA256Context *context = c;
  int padding, i;
  unsigned char temp = 0x80;
  unsigned int in_buffer;
  SshUInt32 total_low, total_high;

  total_low = context->total_length[0];
  total_high = context->total_length[1];

  ssh_sha256_update(context, &temp, 1);

  in_buffer = context->total_length[0] % 64;
  padding = (64 - (in_buffer + 9) % 64) % 64;

  if (in_buffer > 56)
    {
      memset(&context->u.in[in_buffer], 0, 64 - in_buffer);
      padding -= (64 - in_buffer);
      sha256_transform(context, context->u.in);
      in_buffer = 0;
    }

  /* Change the byte count to bit count. */
  total_high <<= 3;
  total_high += (total_low >> 29);
  total_low <<= 3;

  SSH_PUT_32BIT(context->u.in + 56, total_high);
  SSH_PUT_32BIT(context->u.in + 60, total_low);

  if ((64 - in_buffer - 8) > 0)
    {
      memset(&context->u.in[in_buffer],
             0, 64 - in_buffer - 8);
    }

  sha256_transform(context, context->u.in);

  /* Copy the internal state to the digest output. */
  for (i = 0; i < 8; i++)
    {
      SSH_PUT_32BIT(digest + i*4, context->H[i]);
    }

  memset(context, 0, sizeof(SshSHA256Context));
  return SSH_CRYPTO_OK;
}

void ssh_sha256_of_buffer(unsigned char digest[32],
                          const unsigned char *buf, size_t len)
{
  SshSHA256Context context;
  ssh_sha256_reset_context(&context);
  ssh_sha256_update(&context, buf, len);
  ssh_sha256_final(&context, digest);
}

SshCryptoStatus ssh_sha224_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[32];
  ssh_sha256_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 28);
  return SSH_CRYPTO_OK;
}

/* Extra routines. */
SshCryptoStatus ssh_sha256_128_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[32];
  ssh_sha256_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 16);
  return SSH_CRYPTO_OK;
}

void ssh_sha256_128_of_buffer(unsigned char digest[16],
                              const unsigned char *buf, size_t len)
{
  SshSHA256Context context;
  ssh_sha256_reset_context(&context);
  ssh_sha256_update(&context, buf, len);
  ssh_sha256_128_final(&context, digest);
}

SshCryptoStatus ssh_sha256_96_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[32];
  ssh_sha256_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 12);
  return SSH_CRYPTO_OK;
}

void ssh_sha256_96_of_buffer(unsigned char digest[12],
                             const unsigned char *buf, size_t len)
{
  SshSHA256Context context;
  ssh_sha256_reset_context(&context);
  ssh_sha256_update(&context, buf, len);
  ssh_sha256_96_final(&context, digest);
}

SshCryptoStatus ssh_sha256_80_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[32];
  ssh_sha256_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 10);
  return SSH_CRYPTO_OK;
}

void ssh_sha256_80_of_buffer(unsigned char digest[10],
                             const unsigned char *buf, size_t len)
{
  SshSHA256Context context;
  ssh_sha256_reset_context(&context);
  ssh_sha256_update(&context, buf, len);
  ssh_sha256_80_final(&context, digest);
}

/* End. */
