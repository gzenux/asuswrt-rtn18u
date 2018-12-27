/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   File implements SHA-512 algorithm and variant SHA-384.
*/

#include "sshincludes.h"















#include "sshcrypt.h"
#include "sshhash_i.h"
#include "hash-oid.h"
#include "sshgetput.h"
#include "sshmp-xuint.h"

#include "sha512.h"

#define SSH_DEBUG_MODULE "SshSha"

/* Define SHA-512 in transparent way. */
const SshHashDefStruct ssh_hash_sha512_def =
{
  /* Name of the hash function. */
  "sha512",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.3",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Digest size. */
  64,
  /* Input block length. */
  128,
  /* Context size */
  ssh_sha512_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha512_reset_context,
  /* Update function */
  ssh_sha512_update,
  /* Final */
  ssh_sha512_final,
  /* ASN1. */
  ssh_hash_oid_asn1_compare_sha512,
  ssh_hash_oid_asn1_generate_sha512
};

/* Define SHA-384 in transparent way. */
const SshHashDefStruct ssh_hash_sha384_def =
{
  /* Name of the hash function. */
  "sha384",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.2",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Digest size. */
  48,
  /* Input block length. */
  128,
  /* Context size */
  ssh_sha512_ctxsize,
  /* Init context */
  NULL,
  /* Uninit context */
  NULL,
  /* Reset function, between long usage of one context. */
  ssh_sha384_reset_context,
  /* Update function */
  ssh_sha512_update,
  /* Final */
  ssh_sha384_final,
  /* No ASN1. */
  ssh_hash_oid_asn1_compare_sha384,
  ssh_hash_oid_asn1_generate_sha384
};

typedef struct
{
  SshXUInt64 H[8];
  union
  {
    unsigned char in[128]; /* Input data as bytes. (If buffer is large,
                              it shall be fed directly.) */
    SshXUInt64 W[16]; /* Input data after conversion to 64-bit words. */
  } u;
  /* Current implementation is limited to 2^64 input bits. */
  SshUInt32 total_length[2];
} SshSHA512Context;

/* Macro for easy definition of 64-bit hex constants. */
#define DW4(x0a, x0b, x1a, x1b, x2a, x2b, x3a, x3b) \
        SSH_XUINT64_STATIC_BUILD(0x##x0b, 0x##x0a), \
        SSH_XUINT64_STATIC_BUILD(0x##x1b, 0x##x1a), \
        SSH_XUINT64_STATIC_BUILD(0x##x2b, 0x##x2a), \
        SSH_XUINT64_STATIC_BUILD(0x##x3b, 0x##x3a)

/* Use DW4 macro to define tables so that we get 4 64-bit values per line. */
static const SshXUInt64 table_h[8] = {
  DW4(6a09e667,f3bcc908,bb67ae85,84caa73b,3c6ef372,fe94f82b,a54ff53a,5f1d36f1),
  DW4(510e527f,ade682d1,9b05688c,2b3e6c1f,1f83d9ab,fb41bd6b,5be0cd19,137e2179)
};

static const SshXUInt64 table_h384[8] = {
  DW4(cbbb9d5d,c1059ed8,629a292a,367cd507,9159015a,3070dd17,152fecd8,f70e5939),
  DW4(67332667,ffc00b31,8eb44a87,68581511,db0c2e0d,64f98fa7,47b5481d,befa4fa4)
};

static const SshXUInt64 table_c[80] = {
  DW4(428a2f98,d728ae22,71374491,23ef65cd,b5c0fbcf,ec4d3b2f,e9b5dba5,8189dbbc),
  DW4(3956c25b,f348b538,59f111f1,b605d019,923f82a4,af194f9b,ab1c5ed5,da6d8118),
  DW4(d807aa98,a3030242,12835b01,45706fbe,243185be,4ee4b28c,550c7dc3,d5ffb4e2),
  DW4(72be5d74,f27b896f,80deb1fe,3b1696b1,9bdc06a7,25c71235,c19bf174,cf692694),
  DW4(e49b69c1,9ef14ad2,efbe4786,384f25e3,0fc19dc6,8b8cd5b5,240ca1cc,77ac9c65),
  DW4(2de92c6f,592b0275,4a7484aa,6ea6e483,5cb0a9dc,bd41fbd4,76f988da,831153b5),
  DW4(983e5152,ee66dfab,a831c66d,2db43210,b00327c8,98fb213f,bf597fc7,beef0ee4),
  DW4(c6e00bf3,3da88fc2,d5a79147,930aa725,06ca6351,e003826f,14292967,0a0e6e70),
  DW4(27b70a85,46d22ffc,2e1b2138,5c26c926,4d2c6dfc,5ac42aed,53380d13,9d95b3df),
  DW4(650a7354,8baf63de,766a0abb,3c77b2a8,81c2c92e,47edaee6,92722c85,1482353b),
  DW4(a2bfe8a1,4cf10364,a81a664b,bc423001,c24b8b70,d0f89791,c76c51a3,0654be30),
  DW4(d192e819,d6ef5218,d6990624,5565a910,f40e3585,5771202a,106aa070,32bbd1b8),
  DW4(19a4c116,b8d2d0c8,1e376c08,5141ab53,2748774c,df8eeb99,34b0bcb5,e19b48a8),
  DW4(391c0cb3,c5c95a63,4ed8aa4a,e3418acb,5b9cca4f,7763e373,682e6ff3,d6b2b8a3),
  DW4(748f82ee,5defb2fc,78a5636f,43172f60,84c87814,a1f0ab72,8cc70208,1a6439ec),
  DW4(90befffa,23631e28,a4506ceb,de82bde9,bef9a3f7,b2c67915,c67178f2,e372532b),
  DW4(ca273ece,ea26619c,d186b8c7,21c0c207,eada7dd6,cde0eb1e,f57d4f7f,ee6ed178),
  DW4(06f067aa,72176fba,0a637dc5,a2c898a6,113f9804,bef90dae,1b710b35,131c471b),
  DW4(28db77f5,23047d84,32caab7b,40c72493,3c9ebe0a,15c9bebc,431d67c4,9c100d4c),
  DW4(4cc5d4be,cb3e42b6,597f299c,fc657e2a,5fcb6fab,3ad6faec,6c44198c,4a475817)
};

void ssh_sha512_reset_context(void *c)
{
  SshSHA512Context *ctx = c;
  unsigned int i;

  for (i = 0; i < 8; i++)
    SSH_XUINT64_ASSIGN(ctx->H[i], table_h[i]);

  ctx->total_length[0] = 0;
  ctx->total_length[1] = 0;
}

void ssh_sha384_reset_context(void *c)
{
  SshSHA512Context *ctx = c;
  unsigned int i;

  for (i = 0; i < 8; i++)
    SSH_XUINT64_ASSIGN(ctx->H[i], table_h384[i]);

  ctx->total_length[0] = 0;
  ctx->total_length[1] = 0;
}

size_t ssh_sha512_ctxsize()
{
  return sizeof(SshSHA512Context);
}







/* Takes value from scheduled key or computes this key. */
#define FETCH_W(x)                                                        \
do { if (x >= 16) {                                                       \
    /* W[i] = SMALL_SIGMA1(W[i-2]) + W[i-7] + SMALL_SIGMA0(W[i-15]) +     \
       W[i-16]; */                                                        \
    /* SMALL_SIGMA1(x) = (ROTR64(x,19) ^ ROTL64(x, 3) ^ SHIFT64(x, 6)) */ \
    SSH_XUINT64_ROR(w1,ctx->u.W[((x)-2)%16],19);                          \
    SSH_XUINT64_ROL(w2,ctx->u.W[((x)-2)%16],3);                           \
    SSH_XUINT64_XOR(w2,w1,w2);                                            \
    SSH_XUINT64_SLR(w1,ctx->u.W[((x)-2)%16],6);                           \
    SSH_XUINT64_XOR(w2,w1,w2);                                            \
    SSH_XUINT64_ADD(W1,w2,ctx->u.W[((x)-7)%16]);                          \
    /* SMALL_SIGMA0(x) = (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHIFT64(x, 7)) */ \
    SSH_XUINT64_ROR(w1,ctx->u.W[((x)-15)%16],1);                          \
    SSH_XUINT64_ROR(w2,ctx->u.W[((x)-15)%16],8);                          \
    SSH_XUINT64_XOR(w2,w1,w2);                                            \
    SSH_XUINT64_SLR(w1,ctx->u.W[((x)-15)%16],7);                          \
    SSH_XUINT64_XOR(w2,w1,w2);                                            \
    SSH_XUINT64_ADD(W1,W1,w2);                                            \
    SSH_XUINT64_ADD(ctx->u.W[(x)%16],W1,ctx->u.W[(x)%16]);                \
} } while(0)
#define GET_W(x) ctx->u.W[(x)%16]

/* Single round of the SHA-512 compression function. Observe that we
   avoid copying material by renaming the variables. */
#define ROUND(a,b,c,d,e,f,g,h,j) \
do { \
  /* T1 = h + BIG_SIGMA1(e) + CH(e,f,g) + table_c[j] + W[j]; */ \
  /* CH(e,f,g) */                                               \
  SSH_XUINT64_NOT(t1,e);                                        \
  SSH_XUINT64_AND(t2,t1,g);                                     \
  SSH_XUINT64_AND(t1,e,f);                                      \
  SSH_XUINT64_XOR(T1,t2,t1);                                    \
  /* BIG_SIGMA1(e) */                                           \
  SSH_XUINT64_ROR(t1,e,14);                                     \
  SSH_XUINT64_ROR(t2,e,18);                                     \
  SSH_XUINT64_XOR(t2,t1,t2);                                    \
  SSH_XUINT64_ROL(t1,e,23);                                     \
  SSH_XUINT64_XOR(t2,t1,t2);                                    \
  /* rest of sum */                                             \
  FETCH_W(j);                                                   \
  SSH_XUINT64_ADD(t1,GET_W(j),table_c[j]);                      \
  SSH_XUINT64_ADD(t2,t2,h);                                     \
  SSH_XUINT64_ADD(t2,t2,t1);                                    \
  SSH_XUINT64_ADD(T1,T1,t2);                                    \
  /* T2 = BIG_SIGMA0(a) + MAJ(a,b,c); */                        \
  /* MAJ(a,b,c) */                                              \
  SSH_XUINT64_AND(t1,a,b);                                      \
  SSH_XUINT64_AND(t2,a,c);                                      \
  SSH_XUINT64_OR(T2,t1,t2);                                     \
  SSH_XUINT64_AND(t2,b,c);                                      \
  SSH_XUINT64_OR(T2,T2,t2);                                     \
  /* BIG_SIGMA0(a) */                                           \
  SSH_XUINT64_ROR(t1,a,28);                                     \
  SSH_XUINT64_ROL(t2,a,30);                                     \
  SSH_XUINT64_XOR(t2,t1,t2);                                    \
  SSH_XUINT64_ROL(t1,a,25);                                     \
  SSH_XUINT64_XOR(t2,t1,t2);                                    \
  SSH_XUINT64_ADD(T2,T2,t2);                                    \
  /* d+=T1; h += T1 + T2; */                                    \
  SSH_XUINT64_ADD(d,d,T1);                                      \
  SSH_XUINT64_ADD(h,T1,T2);                                     \
} while(0)


static void sha512_transform(SshSHA512Context *ctx,
                             const unsigned char *block )
{
  int i;
  SshXUInt64 a,b,c,d,e,f,g,h;
#ifdef MINIMAL_STACK
  /* This rather ugly change seems to make gcc consume less stack. */
  struct SshXUInt64_7 {
    SshXUInt64 T1,T2,t1,t2; /* For ROUND() macro. */
    SshXUInt64 W1,w1,w2; /* For FETCH_W() macro. */
  } *temps;
  struct SshXUInt64_7 storage_temps;
  temps = &storage_temps;
#define W1 (temps->W1)
#define w1 (temps->w1)
#define w2 (temps->w2)
#define T1 (temps->T1)
#define T2 (temps->T2)
#define t1 (temps->t1)
#define t2 (temps->t2)
#else /* MINIMAL_STACK */
  /* Notice: This function takes about 200 bytes of stack. */
  SshXUInt64 W1,w1,w2; /* For FETCH_W() macro. */
  SshXUInt64 T1,T2,t1,t2; /* For ROUND() macro. */
#endif /* MINIMAL_STACK */

  /* Naive implementation. */

  /* Key scheduling. */








  /* Loop in opposite order, to make sure everything works even if
     SshXUInt64 is larger than 8 unsigned chars. */
  for(i = 15; i >= 0; i--)
    SSH_XUINT64_GET(ctx->u.W[i], &block[i*8]);

#ifdef CHECK_SHA512
  printf( "W 0 = %016llx  W 8 = %016llx\n", W[ 0], W[ 8] );
  printf( "W 1 = %016llx  W 9 = %016llx\n", W[ 1], W[ 9] );
  printf( "W 2 = %016llx  W10 = %016llx\n", W[ 2], W[10] );
  printf( "W 3 = %016llx  W11 = %016llx\n", W[ 3], W[11] );
  printf( "W 4 = %016llx  W12 = %016llx\n", W[ 4], W[12] );
  printf( "W 5 = %016llx  W13 = %016llx\n", W[ 5], W[13] );
  printf( "W 6 = %016llx  W14 = %016llx\n", W[ 6], W[14] );
  printf( "W 7 = %016llx  W15 = %016llx\n", W[ 7], W[15] );
  printf( "\n" );
  for(i = 16; i < 80; i+=2)
    printf( "W%2d = %016llx  W%2d = %016llx\n", i, W[ i], i+1, W[i+1] );
  printf( "\n" );
#endif

  /* Now the actual engine. */

  /* Copy the internal state to local registers (or stack). */
  SSH_XUINT64_ASSIGN(a, ctx->H[0]);
  SSH_XUINT64_ASSIGN(b, ctx->H[1]);
  SSH_XUINT64_ASSIGN(c, ctx->H[2]);
  SSH_XUINT64_ASSIGN(d, ctx->H[3]);
  SSH_XUINT64_ASSIGN(e, ctx->H[4]);
  SSH_XUINT64_ASSIGN(f, ctx->H[5]);
  SSH_XUINT64_ASSIGN(g, ctx->H[6]);
  SSH_XUINT64_ASSIGN(h, ctx->H[7]);
















#ifdef MINIMAL_STACK
  /* This change here makes gcc reduce stack consumption by about 170B. */
  for (i = 0; i < 80; i++)
    {
      switch (i % 8)
        {
        case 0:
          ROUND(a,b,c,d,e,f,g,h,i);
          break;

        case 1:
          ROUND(h,a,b,c,d,e,f,g,i);
          break;

        case 2:
          ROUND(g,h,a,b,c,d,e,f,i);
          break;

        case 3:
          ROUND(f,g,h,a,b,c,d,e,i);
          break;

        case 4:
          ROUND(e,f,g,h,a,b,c,d,i);
          break;

        case 5:
          ROUND(d,e,f,g,h,a,b,c,i);
          break;

        case 6:
          ROUND(c,d,e,f,g,h,a,b,i);
          break;

        case 7:
          ROUND(b,c,d,e,f,g,h,a,i);
          break;

        default:
          break;
        }
    }

#else /* MINIMAL_STACK */

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

  for(i = 0; i < 10; i++)
    {
      BLOCK(i);
    }

#endif /* MINIMAL_STACK */

  /* Update the internal state. */






















  SSH_XUINT64_ADD(ctx->H[0], a, ctx->H[0]);
  SSH_XUINT64_ADD(ctx->H[1], b, ctx->H[1]);
  SSH_XUINT64_ADD(ctx->H[2], c, ctx->H[2]);
  SSH_XUINT64_ADD(ctx->H[3], d, ctx->H[3]);
  SSH_XUINT64_ADD(ctx->H[4], e, ctx->H[4]);
  SSH_XUINT64_ADD(ctx->H[5], f, ctx->H[5]);
  SSH_XUINT64_ADD(ctx->H[6], g, ctx->H[6]);
  SSH_XUINT64_ADD(ctx->H[7], h, ctx->H[7]);

#ifdef MINIMAL_STACK
  /* Cleanup the temporary variable substitions. */
#undef W1
#undef w1
#undef w2
#undef T1
#undef T2
#undef t1
#undef t2
#endif /* MINIMAL_STACK */
}

/* The rest is basically equivalent to the SHA-256 implementation. */

void ssh_sha512_update(void *c, const unsigned char *buf, size_t len )
{
  SshSHA512Context *context = c;
  unsigned int to_copy = 0;
  unsigned int in_buffer;

  SshUInt32 old_length = context->total_length[0];

  in_buffer = old_length % 128;

  context->total_length[0] += len;
  context->total_length[0] &= 0xFFFFFFFFL;

  if (context->total_length[0] < old_length) /* carry */
    context->total_length[1]++;

  while (len > 0)
    {
      if (in_buffer == 0 && len >= 128)
        {
          sha512_transform(context, buf);
          buf += 128;
          len -= 128;
          continue;
        }

      /* do copy? */
      to_copy = 128 - in_buffer;
      if (to_copy > 0)
        {
          if (to_copy > len)
            to_copy = len;
          memcpy(&context->u.in[in_buffer],
                 buf, to_copy);
          buf += to_copy;
          len -= to_copy;
          in_buffer += to_copy;
          if (in_buffer == 128)
            {
              sha512_transform(context, context->u.in);
              in_buffer = 0;
            }
        }
    }
}

static SshCryptoStatus sha512_final(void *c, unsigned char *digest,
                                    int num_64bit_words )
{
  SshSHA512Context *context = c;
  int padding, i;
  unsigned char temp = 0x80;
  unsigned int in_buffer;
  SshUInt32 total_low, total_high;

  total_low = context->total_length[0];
  total_high = context->total_length[1];

  ssh_sha512_update(context, &temp, 1);

  in_buffer = context->total_length[0] % 128;
  padding = (128 - (in_buffer + 17) % 128) % 128;

  if (in_buffer > 112)
    {
      memset(&context->u.in[in_buffer], 0, 128 - in_buffer);
      padding -= (128 - in_buffer);
      sha512_transform(context, context->u.in);
      in_buffer = 0;
    }

  /* Change the byte count to bit count. */
  total_high <<= 3;
  total_high += (total_low >> 29);
  total_low <<= 3;

  SSH_PUT_32BIT(context->u.in + 120, total_high);
  SSH_PUT_32BIT(context->u.in + 124, total_low);
  /* Highest bits of length are always zero */
  SSH_PUT_32BIT(context->u.in + 116, 0);
  SSH_PUT_32BIT(context->u.in + 112, 0);

  if ((128 - in_buffer - 16) > 0)
    {
      memset(&context->u.in[in_buffer],
             0, 128 - in_buffer - 16);
    }

  sha512_transform(context, context->u.in);

  /* Copy the internal state to the digest output. */
  for (i = 0; i < num_64bit_words; i++)
    {
      SSH_XUINT64_PUT(context->H[i], digest + i*8);
    }

  memset(context, 0, sizeof(SshSHA512Context));
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_sha512_final(void *c, unsigned char *digest)
{
  return sha512_final(c, digest, 8);
}

void ssh_sha512_of_buffer(unsigned char digest[64],
                          const unsigned char *buf, size_t len)
{
  SshSHA512Context context;
  ssh_sha512_reset_context(&context);
  ssh_sha512_update(&context, buf, len);
  ssh_sha512_final(&context, digest);
}

SshCryptoStatus ssh_sha384_final(void *c, unsigned char *digest)
{
  return sha512_final(c, digest, 6);
}

void ssh_sha384_of_buffer(unsigned char digest[48],
                          const unsigned char *buf, size_t len)
{
  SshSHA512Context context;
  ssh_sha384_reset_context(&context);
  ssh_sha512_update(&context, buf, len);
  ssh_sha384_final(&context, digest);
}









































































/* End. */
