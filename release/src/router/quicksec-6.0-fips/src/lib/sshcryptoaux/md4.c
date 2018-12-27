/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS

#include "sshincludes.h"
#include "sshgetput.h"


/* The type MD4Context is used to represent an MD4 context while the
   computation is in progress.  The normal usage is to first initialize
   the context with md4_init, then add data by calling md4_update one or
   more times, and then call md4_final to get the digest.  */

typedef struct {
  SshUInt32 buf[4];
  SshUInt32 bits[2];
  unsigned char in[64];
} SshMD4Context;

void ssh_md4_reset_context(void *context)
{
  SshMD4Context *ctx = context;
  ctx->buf[0] = 0x67452301L;
  ctx->buf[1] = 0xefcdab89L;
  ctx->buf[2] = 0x98badcfeL;
  ctx->buf[3] = 0x10325476L;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

void ssh_md4_transform(SshUInt32 buf[4], const unsigned char inext[64]);

void ssh_md4_update(void *context, const unsigned char *buf, size_t len)
{
  SshMD4Context *ctx = context;
  SshUInt32 t;

  /* Update bitcount */

  t = ctx->bits[0];
  if ((ctx->bits[0] = (t + ((SshUInt32)len << 3)) & 0xffffffffL) < t)
    ctx->bits[1]++;             /* Carry from low to high */
  ctx->bits[1] += (SshUInt32)len >> 29;

  t = (t >> 3) & 0x3f;

  /* Handle any leading odd-sized chunks */
  if (t)
    {
      unsigned char *p = ctx->in + t;

      t = 64 - t;
      if (len < t)
        {
          memcpy(p, buf, len);
          return;
        }
      memcpy(p, buf, t);
      ssh_md4_transform(ctx->buf, ctx->in);
      buf += t;
      len -= t;
    }

  /* Process data in 64-byte chunks */
  while (len >= 64)
    {
      memcpy(ctx->in, buf, 64);
      ssh_md4_transform(ctx->buf, ctx->in);
      buf += 64;
      len -= 64;
    }

  /* Handle any remaining bytes of data. */
  memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void ssh_md4_final(void *context, unsigned char *digest)
{
  SshMD4Context *ctx = context;
  unsigned int count;
  unsigned char *p;

  /* Compute number of bytes mod 64 */
  count = (ctx->bits[0] >> 3) & 0x3F;

  /* Set the first char of padding to 0x80.  This is safe since there is
     always at least one byte free */
  p = ctx->in + count;
  *p++ = 0x80;

  /* Bytes of padding needed to make 64 bytes */
  count = 64 - 1 - count;

  /* Pad out to 56 mod 64 */
  if (count < 8)
    {
      /* Two lots of padding:  Pad the first block to 64 bytes */
      memset(p, 0, count);
      ssh_md4_transform(ctx->buf, ctx->in);

      /* Now fill the next block with 56 bytes */
      memset(ctx->in, 0, 56);
    }
  else
    {
      /* Pad block to 56 bytes */
      memset(p, 0, count - 8);
    }

  /* Append length in bits and transform */
  SSH_PUT_32BIT_LSB_FIRST(ctx->in + 56, ctx->bits[0]);
  SSH_PUT_32BIT_LSB_FIRST(ctx->in + 60, ctx->bits[1]);
  ssh_md4_transform(ctx->buf, ctx->in);

  /* Convert the internal state to bytes and return as the digest. */
  SSH_PUT_32BIT_LSB_FIRST(digest, ctx->buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(digest + 4, ctx->buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(digest + 8, ctx->buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(digest + 12, ctx->buf[3]);

  memset(ctx, 0, sizeof(*ctx));  /* In case it's sensitive */
  return;
}

/* The three core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) ((x & y) | (x & z) | (y & z))
#define F3(x, y, z) (x ^ y ^ z)

/* This is the central step in the MD4 algorithm. */
#define MD4STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = (w<<s | w>>(32-s)) & 0xffffffff )

/*
 * The core of the MD4 algorithm, this alters an existing MD4 hash to
 * reflect the addition of 16 longwords of new data.  MD4Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void ssh_md4_transform(SshUInt32 buf[4], const unsigned char inext[64])
{
    register SshUInt32 a, b, c, d, i;
    SshUInt32 in[16];

    for (i = 0; i < 16; i++)
      in[i] = SSH_GET_32BIT_LSB_FIRST(inext + 4 * i);

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD4STEP(F1, a, b, c, d, in[0], 3);
    MD4STEP(F1, d, a, b, c, in[1], 7);
    MD4STEP(F1, c, d, a, b, in[2], 11);
    MD4STEP(F1, b, c, d, a, in[3], 19);
    MD4STEP(F1, a, b, c, d, in[4], 3);
    MD4STEP(F1, d, a, b, c, in[5], 7);
    MD4STEP(F1, c, d, a, b, in[6], 11);
    MD4STEP(F1, b, c, d, a, in[7], 19);
    MD4STEP(F1, a, b, c, d, in[8], 3);
    MD4STEP(F1, d, a, b, c, in[9], 7);
    MD4STEP(F1, c, d, a, b, in[10], 11);
    MD4STEP(F1, b, c, d, a, in[11], 19);
    MD4STEP(F1, a, b, c, d, in[12], 3);
    MD4STEP(F1, d, a, b, c, in[13], 7);
    MD4STEP(F1, c, d, a, b, in[14], 11);
    MD4STEP(F1, b, c, d, a, in[15], 19);

    MD4STEP(F2, a, b, c, d, in[0] + 0x5a827999L, 3);
    MD4STEP(F2, d, a, b, c, in[4] + 0x5a827999L, 5);
    MD4STEP(F2, c, d, a, b, in[8] + 0x5a827999L, 9);
    MD4STEP(F2, b, c, d, a, in[12] + 0x5a827999L, 13);
    MD4STEP(F2, a, b, c, d, in[1] + 0x5a827999L, 3);
    MD4STEP(F2, d, a, b, c, in[5] + 0x5a827999L, 5);
    MD4STEP(F2, c, d, a, b, in[9] + 0x5a827999L, 9);
    MD4STEP(F2, b, c, d, a, in[13] + 0x5a827999L, 13);
    MD4STEP(F2, a, b, c, d, in[2] + 0x5a827999L, 3);
    MD4STEP(F2, d, a, b, c, in[6] + 0x5a827999L, 5);
    MD4STEP(F2, c, d, a, b, in[10] + 0x5a827999L, 9);
    MD4STEP(F2, b, c, d, a, in[14] + 0x5a827999L, 13);
    MD4STEP(F2, a, b, c, d, in[3] + 0x5a827999L, 3);
    MD4STEP(F2, d, a, b, c, in[7] + 0x5a827999L, 5);
    MD4STEP(F2, c, d, a, b, in[11] + 0x5a827999L, 9);
    MD4STEP(F2, b, c, d, a, in[15] + 0x5a827999L, 13);

    MD4STEP(F3, a, b, c, d, in[0] + 0x6ed9eba1, 3);
    MD4STEP(F3, d, a, b, c, in[8] + 0x6ed9eba1, 9);
    MD4STEP(F3, c, d, a, b, in[4] + 0x6ed9eba1, 11);
    MD4STEP(F3, b, c, d, a, in[12] + 0x6ed9eba1, 15);
    MD4STEP(F3, a, b, c, d, in[2] + 0x6ed9eba1, 3);
    MD4STEP(F3, d, a, b, c, in[10] + 0x6ed9eba1, 9);
    MD4STEP(F3, c, d, a, b, in[6] + 0x6ed9eba1, 11);
    MD4STEP(F3, b, c, d, a, in[14] + 0x6ed9eba1, 15);
    MD4STEP(F3, a, b, c, d, in[1] + 0x6ed9eba1, 3);
    MD4STEP(F3, d, a, b, c, in[9] + 0x6ed9eba1, 9);
    MD4STEP(F3, c, d, a, b, in[5] + 0x6ed9eba1, 11);
    MD4STEP(F3, b, c, d, a, in[13] + 0x6ed9eba1, 15);
    MD4STEP(F3, a, b, c, d, in[3] + 0x6ed9eba1, 3);
    MD4STEP(F3, d, a, b, c, in[11] + 0x6ed9eba1, 9);
    MD4STEP(F3, c, d, a, b, in[7] + 0x6ed9eba1, 11);
    MD4STEP(F3, b, c, d, a, in[15] + 0x6ed9eba1, 15);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

void ssh_md4_of_buffer(unsigned char digest[16], const unsigned char *buf,
                       size_t len)
{
  SshMD4Context context;
  ssh_md4_reset_context(&context);
  ssh_md4_update(&context, buf, len);
  ssh_md4_final(&context, digest);
}
