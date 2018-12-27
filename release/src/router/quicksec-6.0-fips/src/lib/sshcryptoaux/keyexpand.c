/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utility function allowing expansion (or compression) of a fixed-size
   key from arbitrary length passphrase.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshencode.h"
#include "sshcryptoaux.h"

#define SSH_DEBUG_MODULE "SshCryptoAuxKeyExpand"


typedef struct {
  SshUInt32 buf[4];
  SshUInt32 bits[2];
  unsigned char in[64];
} SshHashExpandMD5Context;


#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
        ( w += f(x, y, z) + data,  w = (w<<s | w>>(32-s)) & 0xffffffff,  \
          w += x )

static void md5_hash_transform(SshUInt32 buf[4], const unsigned char inext[64])
{
  register SshUInt32 a, b, c, d, i;
    SshUInt32 in[16];

    for (i = 0; i < 16; i++)
      in[i] = SSH_GET_32BIT_LSB_FIRST(inext + 4 * i);

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478L, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756L, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070dbL, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceeeL, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0fafL, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62aL, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613L, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501L, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8L, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7afL, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1L, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7beL, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122L, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193L, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438eL, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821L, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562L, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340L, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51L, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aaL, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105dL, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453L, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681L, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8L, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6L, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6L, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87L, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14edL, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905L, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8L, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9L, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8aL, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942L, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681L, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122L, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380cL, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44L, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9L, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60L, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70L, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6L, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127faL, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085L, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05L, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039L, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5L, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8L, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665L, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244L, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97L, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7L, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039L, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3L, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92L, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47dL, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1L, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4fL, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0L, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314L, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1L, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82L, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235L, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bbL, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391L, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

static void md5_hash_reset(void *context)
{
  SshHashExpandMD5Context *ctx = context;

  ctx->buf[0] = 0x67452301L;
  ctx->buf[1] = 0xefcdab89L;
  ctx->buf[2] = 0x98badcfeL;
  ctx->buf[3] = 0x10325476L;

  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}


static void md5_hash_update(void *context, const unsigned char *buf,
                            size_t len)
{
  SshHashExpandMD5Context *ctx = context;
  SshUInt32 t;

  /* Update bitcount */

  t = ctx->bits[0];
  if ((ctx->bits[0] = (t + ((SshUInt32)len << 3)) & 0xffffffffL) < t)
    ctx->bits[1]++;             /* Carry from low to high */
  ctx->bits[1] += (SshUInt32)len >> 29;

  t = (t >> 3) & 0x3f;  /* Bytes already in shsInfo->data */

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
      md5_hash_transform(ctx->buf, ctx->in);
      buf += t;
      len -= t;
    }

  /* Process data in 64-byte chunks */
  while (len >= 64)
    {
      memcpy(ctx->in, buf, 64);
      md5_hash_transform(ctx->buf, ctx->in);
      buf += 64;
      len -= 64;
    }

  /* Handle any remaining bytes of data. */
  memcpy(ctx->in, buf, len);
}

static void md5_hash_final(void *context, unsigned char *digest)
{
  SshHashExpandMD5Context *ctx = context;
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
      md5_hash_transform(ctx->buf, ctx->in);

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
  md5_hash_transform(ctx->buf, ctx->in);

  /* Convert the internal state to bytes and return as the digest. */
  SSH_PUT_32BIT_LSB_FIRST(digest, ctx->buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(digest + 4, ctx->buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(digest + 8, ctx->buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(digest + 12, ctx->buf[3]);
  memset(ctx, 0, sizeof(*ctx));  /* In case it's sensitive */
}


/* Expand given passphrase (text, text_len) with pseudo-random
   function to be of length buf_len.

   Method used is a very simple expansion idea, that nevertheless seems
   very solid. The strenght is based on rehashing everything on every
   iteration. Now it seems that this infact isn't very efficient way,
   but we don't need efficient way because hashing is extremely fast.
   However, if faster expansion is needed I suggest something like:

     h_i = HASH(passphrase, f(i))

   where h_i are combined as h_0 | h_1 | h_2 ... to form the expanded
   key. The function f(i) should be some bijective function (maybe
   just f(x) = x ?). */

SshCryptoStatus
ssh_hash_expand_text_md5(const unsigned char *text, size_t text_len,
                         unsigned char *buf, size_t buf_len)
{
  unsigned char *hash_buf;
  size_t hash_buf_len, digest_length;
  size_t i;
  SshHashExpandMD5Context md5_ctx;

  /* Hash and expand the passphrase. Idea is to

       for i = 0 to r
         buf[i] = H(passphrase, buf[0], ..., buf[i - 1])

     this tries to hash passphrase as nicely to the buf as possible.
     */

  digest_length = 16; /* md5 digest length */
  hash_buf_len = ((buf_len + digest_length) / digest_length) * digest_length;

  /* Allocate just once for simplicity in freeing memory. */
  if (!(hash_buf = ssh_malloc(hash_buf_len)))
    {
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Iterate. */
  for (i = 0; i < hash_buf_len; i += digest_length)
    {
      md5_hash_reset(&md5_ctx);
      md5_hash_update(&md5_ctx, text, text_len);
      if (i > 0)
        md5_hash_update(&md5_ctx, hash_buf, i);
      md5_hash_final(&md5_ctx, hash_buf + i);
    }

  /* Copy and free. */
  memcpy(buf, hash_buf, buf_len);
  memset(hash_buf, 0, hash_buf_len);

  ssh_free(hash_buf);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_private_key_import_with_passphrase(const unsigned char *buf, size_t len,
                                       const char *passphrase,
                                       SshPrivateKey *key)
{
  SshUInt32 pk_magic, pk_length;
  char *cipher_name;
  unsigned char *cipher_key;
  size_t got, pass_len, cipher_keylen;
  SshCryptoStatus status;

  got = ssh_decode_array(buf, len,
                         SSH_DECODE_UINT32(&pk_magic),
                         SSH_DECODE_UINT32(&pk_length),
                         SSH_DECODE_UINT32_STR(NULL, NULL),
                         SSH_DECODE_UINT32_SSTR(&cipher_name, NULL),
                         SSH_FORMAT_END);

  if (!got)
    return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;

  /* We can't verify pk_magic since it is defined in ssh-pk-export.c */
  if (/* pk_magic != SSH_PRIVATE_KEY_MAGIC  || */ pk_length < 8)
    {
      ssh_free(cipher_name);
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  pass_len = strlen(passphrase);




  if (ssh_cipher_has_fixed_key_length(cipher_name))
    cipher_keylen = ssh_cipher_get_key_length(cipher_name);
  else
    cipher_keylen = 32;

  SSH_ASSERT(cipher_keylen > 0);

  if (!(cipher_key = ssh_malloc(cipher_keylen)))
    {
      ssh_free(cipher_name);
      return SSH_CRYPTO_NO_MEMORY;
    }

  status =
    ssh_hash_expand_text_md5((const unsigned char *)passphrase, pass_len,
                             cipher_key, cipher_keylen);

  if (status != SSH_CRYPTO_OK)
    {
      ssh_free(cipher_name);
      ssh_free(cipher_key);
      return status;
    }

  status = ssh_private_key_import(buf, len, cipher_key, cipher_keylen, key);

  ssh_free(cipher_key);
  ssh_free(cipher_name);

  return status;
}

SshCryptoStatus
ssh_private_key_export_with_passphrase(SshPrivateKey key,
                                       const char *cipher_name,
                                       const char *passphrase,
                                       unsigned char **bufptr,
                                       size_t *length_return)
{
  size_t cipher_keylen, pass_len;
  unsigned char *cipher_key;
  SshCryptoStatus status;

  pass_len = strlen(passphrase);

  if (pass_len != 0)
    {



      if (ssh_cipher_has_fixed_key_length(cipher_name))
        cipher_keylen = ssh_cipher_get_key_length(cipher_name);
      else
        cipher_keylen = 32;

      SSH_ASSERT(cipher_keylen > 0);

      if (!(cipher_key = ssh_malloc(cipher_keylen)))
        return SSH_CRYPTO_NO_MEMORY;

      status =
        ssh_hash_expand_text_md5((const unsigned char *)passphrase, pass_len,
                                 cipher_key, cipher_keylen);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(cipher_key);
          return status;
        }
    }
  else
    {
      cipher_name = "none";
      cipher_key = NULL;
      cipher_keylen = 0;
    }

  status = ssh_private_key_export(key, cipher_name, cipher_key, cipher_keylen,
                                  bufptr, length_return);

  ssh_free(cipher_key);

  return status;
}

SshCryptoStatus
ssh_cipher_allocate_with_passphrase(const char *cipher_name,
                                    const char *passphrase,
                                    Boolean for_encryption,
                                    SshCipher *cipher_ret)
{
  size_t pass_len, cipher_keylen;
  unsigned char *cipher_key;
  SshCryptoStatus status;

  pass_len = strlen(passphrase);

  if (pass_len != 0)
    {
      cipher_keylen = ssh_cipher_get_key_length(cipher_name);

      if (!cipher_keylen)
        /*cipher_keylen = 32;*/
        cipher_keylen = 1;

      if (!(cipher_key = ssh_malloc(cipher_keylen)))
        return SSH_CRYPTO_NO_MEMORY;

      status =
        ssh_hash_expand_text_md5((const unsigned char *)passphrase, pass_len,
                                 cipher_key, cipher_keylen);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(cipher_key);
          return status;
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Passphrase=\"%s\" Len=%lu",
                              passphrase, (unsigned long)pass_len));
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Cipher Key:"),
                        cipher_key, cipher_keylen);
      SSH_DEBUG(SSH_D_LOWOK,(" Len=%lu", (unsigned long)cipher_keylen));


    }
  else
    {
      cipher_key = NULL;
      cipher_keylen = 0;
    }

  status = ssh_cipher_allocate(cipher_name, cipher_key, cipher_keylen,
                               for_encryption, cipher_ret);

  ssh_free(cipher_key);

  return status;
}
