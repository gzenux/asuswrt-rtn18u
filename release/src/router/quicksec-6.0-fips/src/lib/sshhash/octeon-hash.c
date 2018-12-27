/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Hash routines for the Cavium Octeon crypto coprocessors.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "sha.h"
#include "md5.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON

#define SSH_DEBUG_MODULE "SshOcteonHash"

#include "octeon-asm.h"


typedef struct {
  SshUInt64 state[3];
  unsigned char in[64];
  SshUInt64 total_length;
} SshSHAContext;


void ssh_sha_reset_context(void *c)
{
  SshSHAContext *context = c;

  context->state[0]=0x67452301EFCDAB89ull;
  context->state[1]=0x98BADCFE10325476ull;
  context->state[2]=0xC3D2E1F000000000ull;
  context->total_length = 0;
}

size_t ssh_sha_ctxsize()
{
  return sizeof(SshSHAContext);
}

SshCryptoStatus ssh_sha_init(void *context)
{
  return SSH_CRYPTO_OK;
}

void ssh_sha_uninit(void *context)
{
}


static void sha_transform(SshSHAContext *context, const unsigned char *buf)
{

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */

  OCTEON_SET_HASH_IV(context->state[0],0);
  OCTEON_SET_HASH_IV(context->state[1],1);
  OCTEON_SET_HASH_IV(context->state[2],2);

  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[0], 0);
  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[1], 1);
  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[2], 2);
  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[3], 3);
  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[4], 4);
  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[5], 5);
  OCTEON_SET_HASH_DAT(((SshUInt64 *)buf)[6], 6);
  OCTEON_SET_HASH_STARTSHA(((SshUInt64 *)buf)[7]);

  OCTEON_GET_HASH_IV(context->state[0],0);
  OCTEON_GET_HASH_IV(context->state[1],1);
  OCTEON_GET_HASH_IV(context->state[2],2);
}


void ssh_sha_update(void *c, const unsigned char *buf, size_t len)
{
  SshSHAContext *context = c;
  unsigned int to_copy = 0;
  unsigned int in_buffer;
  SshUInt64 *ptr;
  SshUInt32 old_length = context->total_length;

  in_buffer = old_length % 64;

  context->total_length += len;

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */

  OCTEON_SET_HASH_IV(context->state[0],0);
  OCTEON_SET_HASH_IV(context->state[1],1);
  OCTEON_SET_HASH_IV(context->state[2],2);

  while (len > 0)
    {
      if (in_buffer == 0 && len >= 64)
        {
          ptr=(SshUInt64 *)buf;
          OCTEON_SET_HASH_DAT(*ptr++, 0);
          OCTEON_SET_HASH_DAT(*ptr++, 1);
          OCTEON_SET_HASH_DAT(*ptr++, 2);
          OCTEON_SET_HASH_DAT(*ptr++, 3);
          OCTEON_SET_HASH_DAT(*ptr++, 4);
          OCTEON_SET_HASH_DAT(*ptr++, 5);
          OCTEON_SET_HASH_DAT(*ptr++, 6);
          OCTEON_SET_HASH_STARTSHA(*ptr);

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
          memcpy(&context->in[in_buffer],
                 buf, to_copy);
          buf += to_copy;
          len -= to_copy;
          in_buffer += to_copy;
          if (in_buffer == 64)
            {
              ptr=(SshUInt64 *)context->in;
              OCTEON_SET_HASH_DAT(*ptr++, 0);
              OCTEON_SET_HASH_DAT(*ptr++, 1);
              OCTEON_SET_HASH_DAT(*ptr++, 2);
              OCTEON_SET_HASH_DAT(*ptr++, 3);
              OCTEON_SET_HASH_DAT(*ptr++, 4);
              OCTEON_SET_HASH_DAT(*ptr++, 5);
              OCTEON_SET_HASH_DAT(*ptr++, 6);
              OCTEON_SET_HASH_STARTSHA(*ptr);
              in_buffer = 0;
            }
        }
    }

  OCTEON_GET_HASH_IV(context->state[0],0);
  OCTEON_GET_HASH_IV(context->state[1],1);
  OCTEON_GET_HASH_IV(context->state[2],2);
}

SshCryptoStatus ssh_sha_final(void *c, unsigned char *digest)
{
  SshSHAContext *context = c;
  unsigned int in_buffer;
  SshUInt64 *ptr;

  in_buffer = context->total_length % 64;

  context->in[in_buffer++]=0x80;

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_HASH_IV(context->state[0],0);
  OCTEON_SET_HASH_IV(context->state[1],1);
  OCTEON_SET_HASH_IV(context->state[2],2);

  if (in_buffer > 56)
    {
      memset(&context->in[in_buffer], 0, 64 - in_buffer);

      ptr=(SshUInt64 *)context->in;
      OCTEON_SET_HASH_DAT(*ptr++, 0);
      OCTEON_SET_HASH_DAT(*ptr++, 1);
      OCTEON_SET_HASH_DAT(*ptr++, 2);
      OCTEON_SET_HASH_DAT(*ptr++, 3);
      OCTEON_SET_HASH_DAT(*ptr++, 4);
      OCTEON_SET_HASH_DAT(*ptr++, 5);
      OCTEON_SET_HASH_DAT(*ptr++, 6);
      OCTEON_SET_HASH_STARTSHA(*ptr);

      in_buffer = 0;
    }

  *(SshUInt64 *)(context->in + 56) = context->total_length * 8;

  if ((64 - in_buffer - 8) > 0)
    {
      memset(&context->in[in_buffer],
             0, 64 - in_buffer - 8);
    }

  ptr=(SshUInt64 *)context->in;
  OCTEON_SET_HASH_DAT(*ptr++, 0);
  OCTEON_SET_HASH_DAT(*ptr++, 1);
  OCTEON_SET_HASH_DAT(*ptr++, 2);
  OCTEON_SET_HASH_DAT(*ptr++, 3);
  OCTEON_SET_HASH_DAT(*ptr++, 4);
  OCTEON_SET_HASH_DAT(*ptr++, 5);
  OCTEON_SET_HASH_DAT(*ptr++, 6);
  OCTEON_SET_HASH_STARTSHA(*ptr);

  OCTEON_GET_HASH_IV(context->state[0], 0);
  OCTEON_GET_HASH_IV(context->state[1], 1);
  OCTEON_GET_HASH_IV(context->state[2], 2);

  memcpy(digest, context->state, 20);
  return SSH_CRYPTO_OK;
}


void ssh_sha_of_buffer(unsigned char digest[20],
                       const unsigned char *buf, size_t len)
{
  SshSHAContext context;
  ssh_sha_reset_context(&context);
  ssh_sha_update(&context, buf, len);
  ssh_sha_final(&context, digest);
}


/* Extra routines. */
SshCryptoStatus ssh_sha_96_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[20];
  ssh_sha_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 12);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_sha_80_final(void *c, unsigned char *digest)
{
  unsigned char tmp_digest[20];
  ssh_sha_final(c, tmp_digest);
  memcpy(digest, tmp_digest, 10);
  return SSH_CRYPTO_OK;
}

/* 'buf' is initialized to the usual initialization state of the SHA-1,
   in hexadecimal, 67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0.
   'in' is 64 bytes to be added to the internal state. The output
   value is stored in 'buf'. */
void ssh_sha_transform(SshUInt32 buf[5], const unsigned char in[64])
{
  SshSHAContext context;

  memset(&context, 0, sizeof(SshSHAContext));

  context.state[0]=0x67452301EFCDAB89ull;
  context.state[1]=0x98BADCFE10325476ull;
  context.state[2]=0xC3D2E1F000000000ull;

  sha_transform(&context, in);

  buf[0] = context.state[0]>>32;
  buf[1] = context.state[0]&0xffffffffu;
  buf[2] = context.state[1]>>32;
  buf[3] = context.state[1]&0xffffffffu;
  buf[4] = context.state[2]>>32;
}

/* 'buf' is initialized to a permutation of the usual initialization state
   of the SHA-1, in hexadecimal, EFCDAB89 98BADCFE 10325476 C3D2E1F0 67452301.
   'in' is 64 bytes to be added to the internal state. The output
   value is stored in 'buf'. */
void ssh_sha_permuted_transform(SshUInt32 buf[5], const unsigned char in[64])
{
  SshSHAContext context;

  memset(&context, 0, sizeof(SshSHAContext));

  context.state[0] = 0xefcdab8998badcfeull;
  context.state[1] = 0x10325476c3d2e1f0ull;
  context.state[2] = 0x6745230100000000ull;

  sha_transform(&context, in);

  buf[0] = context.state[0] >>32;
  buf[1] = context.state[0] & 0xffffffffu;
  buf[2] = context.state[1] >> 32;
  buf[3] = context.state[1] & 0xffffffffu;
  buf[4] = context.state[2] >> 32;
}

/* ************************************************************************ */

typedef struct {

  SshUInt64 state[2];
  unsigned char in[64];
  SshUInt64 total_length;

} SshMD5Context;


void ssh_md5_reset_context(void *context)
{
  SshMD5Context *ctx = context;

  SSH_DEBUG(SSH_D_MY, ("Octeon md5 reset context entered"));

  ctx->state[0] = 0x0123456789abcdefull;
  ctx->state[1] = 0xfedcba9876543210ull;
  ctx->total_length = 0;
}

size_t ssh_md5_ctxsize()
{
  return sizeof(SshMD5Context);
}

SshCryptoStatus ssh_md5_init(void *context)
{
  return SSH_CRYPTO_OK;
}

void ssh_md5_uninit(void *context)
{
}

void ssh_md5_update(void *ctx, const unsigned char *buf, size_t len)
{
  SshMD5Context *context = ctx;
  unsigned int to_copy = 0;
  unsigned int in_buffer;
  SshUInt64 *ptr;
  SshUInt32 old_length = context->total_length;

  in_buffer = old_length % 64;

  context->total_length += len;

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_HASH_IV(context->state[0], 0);
  OCTEON_SET_HASH_IV(context->state[1], 1);
  while (len > 0)
    {
      if (in_buffer == 0 && len >= 64)
        {
          ptr=(SshUInt64 *)buf;
          OCTEON_SET_HASH_DAT(*ptr++, 0);
          OCTEON_SET_HASH_DAT(*ptr++, 1);
          OCTEON_SET_HASH_DAT(*ptr++, 2);
          OCTEON_SET_HASH_DAT(*ptr++, 3);
          OCTEON_SET_HASH_DAT(*ptr++, 4);
          OCTEON_SET_HASH_DAT(*ptr++, 5);
          OCTEON_SET_HASH_DAT(*ptr++, 6);
          OCTEON_SET_HASH_STARTMD5(*ptr);

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
          memcpy(&context->in[in_buffer],
                 buf, to_copy);
          buf += to_copy;
          len -= to_copy;
          in_buffer += to_copy;
          if (in_buffer == 64)
            {
              ptr=(SshUInt64 *)context->in;
              OCTEON_SET_HASH_DAT(*ptr++, 0);
              OCTEON_SET_HASH_DAT(*ptr++, 1);
              OCTEON_SET_HASH_DAT(*ptr++, 2);
              OCTEON_SET_HASH_DAT(*ptr++, 3);
              OCTEON_SET_HASH_DAT(*ptr++, 4);
              OCTEON_SET_HASH_DAT(*ptr++, 5);
              OCTEON_SET_HASH_DAT(*ptr++, 6);
              OCTEON_SET_HASH_STARTMD5(*ptr);
              in_buffer = 0;
            }
        }
    }

  OCTEON_GET_HASH_IV(context->state[0],0);
  OCTEON_GET_HASH_IV(context->state[1],1);
}

SshCryptoStatus ssh_md5_final(void *ctx, unsigned char *digest)
{
  SshMD5Context *context = ctx;
  unsigned int in_buffer;
  SshUInt64 bits, *ptr;

  in_buffer = context->total_length % 64;

  context->total_length *= 8;
  bits = ((context->total_length >> 56) |
          (((context->total_length >> 48) & 0xfful) << 8) |
          (((context->total_length >> 40) & 0xfful) << 16) |
          (((context->total_length >> 32) & 0xfful) << 24) |
          (((context->total_length >> 24) & 0xfful) << 32) |
          (((context->total_length >> 16) & 0xfful) << 40) |
          (((context->total_length >>  8) & 0xfful) << 48) |
          (((context->total_length >>  0) & 0xfful) << 56));

  context->in[in_buffer++] = 0x80;

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */

  OCTEON_SET_HASH_IV(context->state[0],0);
  OCTEON_SET_HASH_IV(context->state[1],1);

  if (in_buffer > 56)
    {
      memset(&context->in[in_buffer], 0, 64 - in_buffer);

      ptr=(SshUInt64 *)context->in;
      OCTEON_SET_HASH_DAT(*ptr++, 0);
      OCTEON_SET_HASH_DAT(*ptr++, 1);
      OCTEON_SET_HASH_DAT(*ptr++, 2);
      OCTEON_SET_HASH_DAT(*ptr++, 3);
      OCTEON_SET_HASH_DAT(*ptr++, 4);
      OCTEON_SET_HASH_DAT(*ptr++, 5);
      OCTEON_SET_HASH_DAT(*ptr++, 6);
      OCTEON_SET_HASH_STARTMD5(*ptr);

      in_buffer = 0;
    }

  *(SshUInt64 *)(context->in + 56) = bits;

  if ((64 - in_buffer - 8) > 0)
    {
      memset(&context->in[in_buffer],
             0, 64 - in_buffer - 8);
    }

  ptr=(SshUInt64 *)context->in;
  OCTEON_SET_HASH_DAT(*ptr++, 0);
  OCTEON_SET_HASH_DAT(*ptr++, 1);
  OCTEON_SET_HASH_DAT(*ptr++, 2);
  OCTEON_SET_HASH_DAT(*ptr++, 3);
  OCTEON_SET_HASH_DAT(*ptr++, 4);
  OCTEON_SET_HASH_DAT(*ptr++, 5);
  OCTEON_SET_HASH_DAT(*ptr++, 6);
  OCTEON_SET_HASH_STARTMD5(*ptr);

  OCTEON_GET_HASH_IV(context->state[0], 0);
  OCTEON_GET_HASH_IV(context->state[1], 1);

  memcpy(digest, context->state, 16);
  return SSH_CRYPTO_OK;
}

void ssh_md5_of_buffer(unsigned char digest[16], const unsigned char *buf,
                       size_t len)
{
  SshMD5Context context;
  ssh_md5_reset_context(&context);
  ssh_md5_update(&context, buf, len);
  ssh_md5_final(&context, digest);
}

#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */


