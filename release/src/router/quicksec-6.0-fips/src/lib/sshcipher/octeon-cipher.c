/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cipher routines for the Cavium Octeon crypto coprocessors.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "rijndael.h"
#include "des.h"

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON

#define SSH_DEBUG_MODULE "SshOcteonCipher"

#include "octeon-asm.h"

/* ****************** AES *********************************************/

typedef struct {
  size_t key_len;
  SshUInt64 key[4];
  SshUInt64 iv[2];
  Boolean for_encryption;
} *SshRijndaelContext, SshRijndaelContextStruct;

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


SshCryptoStatus ssh_rijndael_init(void *context,
                                  const unsigned char *key,
                                  size_t keylen,
                                  Boolean for_encryption)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
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

  ctx->for_encryption = for_encryption;

  for (i = 0; i < key_words; i++)
    ctx->key[i] =
      (((SshUInt64) ((((i * 8) + 0) < keylen) ? key[(i * 8) + 0] : 0)) << 56) |
      (((SshUInt64) ((((i * 8) + 1) < keylen) ? key[(i * 8) + 1] : 0)) << 48) |
      (((SshUInt64) ((((i * 8) + 2) < keylen) ? key[(i * 8) + 2] : 0)) << 40) |
      (((SshUInt64) ((((i * 8) + 3) < keylen) ? key[(i * 8) + 3] : 0)) << 32) |
      (((SshUInt64) ((((i * 8) + 4) < keylen) ? key[(i * 8) + 4] : 0)) << 24) |
      (((SshUInt64) ((((i * 8) + 5) < keylen) ? key[(i * 8) + 5] : 0)) << 16) |
      (((SshUInt64) ((((i * 8) + 6) < keylen) ? key[(i * 8) + 6] : 0)) << 8) |
      (((SshUInt64) ((((i * 8) + 7) < keylen) ? key[(i * 8) + 7] : 0)));

  return SSH_CRYPTO_OK;
}

void ssh_rijndael_uninit(void *context)
{
  return;
}

SshCryptoStatus ssh_aes_init(void *context,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption)
{
  if (keylen < 16)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return ssh_rijndael_init(context, key, keylen, for_encryption);
}

SshCryptoStatus ssh_aes_init_fb(void *context,
                                const unsigned char *key,
                                size_t keylen,
                                Boolean for_encryption)
{
  if (keylen < 16)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return ssh_rijndael_init_fb(context, key, keylen, for_encryption);
}

void ssh_aes_uninit(void *context)
{
  ssh_rijndael_uninit(context);
}


static void ssh_octeon_set_key(SshRijndaelContext ctx)
{
  switch (ctx->key_len)
    {
    case 16:
      OCTEON_SET_AES_KEY(ctx->key[0],0);
      OCTEON_SET_AES_KEY(ctx->key[1],1);
      OCTEON_SET_AES_KEYLENGTH(1);
      break;

    case 24:
      OCTEON_SET_AES_KEY(ctx->key[0],0);
      OCTEON_SET_AES_KEY(ctx->key[1],1);
      OCTEON_SET_AES_KEY(ctx->key[2],2);
      OCTEON_SET_AES_KEYLENGTH(2);
      break;

    case 32:
      OCTEON_SET_AES_KEY(ctx->key[0],0);
      OCTEON_SET_AES_KEY(ctx->key[1],1);
      OCTEON_SET_AES_KEY(ctx->key[2],2);
      OCTEON_SET_AES_KEY(ctx->key[3],3);
      OCTEON_SET_AES_KEYLENGTH(3);
      break;
    }
}


/* Gets the size of Rijndael context. */
size_t ssh_rijndael_ctxsize()
{
  return sizeof(SshRijndaelContextStruct);
}


SshCryptoStatus ssh_rijndael_start(void *context, const unsigned char *iv)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;

  ctx->iv[0] = ((SshUInt64 *)iv)[0];
  ctx->iv[1] = ((SshUInt64 *)iv)[1];

  return SSH_CRYPTO_OK;
}


/* Encryption and decryption in electronic codebook mode */
SshCryptoStatus ssh_rijndael_ecb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_ENC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_AES_DEC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_DEC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }




  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rijndael_cbc(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  OCTEON_SET_AES_IV(ctx->iv[0], 0);
  OCTEON_SET_AES_IV(ctx->iv[1], 1);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC_CBC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_ENC_CBC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_AES_DEC_CBC0(*((SshUInt64 *)(src)));
          OCTEON_SET_AES_DEC_CBC1(*((SshUInt64 *)(src + 8)));

          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest)), 0);
          OCTEON_GET_AES_RESULT(*((SshUInt64 *)(dest + 8)), 1);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }

  OCTEON_GET_AES_IV(ctx->iv[0], 0);
  OCTEON_GET_AES_IV(ctx->iv[1], 1);




  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_rijndael_ofb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 iv[2];

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  iv[0] = ctx->iv[0];
  iv[1] = ctx->iv[1];

  while (len > 0)
    {
      OCTEON_SET_AES_ENC0(iv[0]);
      OCTEON_SET_AES_ENC1(iv[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      *((SshUInt64 *)(dest)) = *((SshUInt64 *)(src)) ^ iv[0];
      *((SshUInt64 *)(dest+8)) = *((SshUInt64 *)(src+8)) ^ iv[1];

      src += 16;
      dest += 16;
      len -= 16;
    }

  ctx->iv[0] = iv[0];
  ctx->iv[1] = iv[1];




  return SSH_CRYPTO_OK;
}

/* Encrypt in counter mode. The call to `ssh_rijndael_encrypt'
   should be made inline (as is done for cbc mode) if counter mode
   needs to be optimized. Notice also that counter mode does not
   require ssh_rijndael_decrypt.

   We assume the counter buffer '*ctr_arg' is treated as a MSB first
   integer and incremented after each block encryption. */

SshCryptoStatus ssh_rijndael_ctr(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 iv[4], ctr[4];

  ctr[0] = SSH_GET_64BIT(&ctx->iv[0]);
  ctr[1] = SSH_GET_64BIT(&ctx->iv[1]);

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  while (len >= 16)
    {
      OCTEON_SET_AES_ENC0(ctr[0]);
      OCTEON_SET_AES_ENC1(ctr[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      *((SshUInt64 *)(dest)) = *((SshUInt64 *)(src)) ^ iv[0];
      *((SshUInt64 *)(dest+8)) = *((SshUInt64 *)(src+8)) ^ iv[1];

      src += 16;
      dest += 16;
      len -= 16;

      /* Increment the counter by 1 (treated as a MSB first integer). */
      if (++ctr[1] == 0)
        ++ctr[0];
    }

  /* Encrypt the last block (which may be less than 16 bytes) */
  if (len)
    {
      unsigned char tmp[16];

      SSH_ASSERT(len < 16);

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, src, len);

      OCTEON_SET_AES_ENC0(ctr[0]);
      OCTEON_SET_AES_ENC1(ctr[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      *((SshUInt64 *)(tmp)) = *((SshUInt64 *)(tmp)) ^ iv[0];
      *((SshUInt64 *)(tmp+8)) = *((SshUInt64 *)(tmp+8)) ^ iv[1];

      memcpy(dest, tmp, len);

      /* Increment the counter by 1 (treated as a MSB first integer). */
      if (++ctr[1] == 0)
        ++ctr[0];
  }

  /* Set the new counter value. */
  SSH_PUT_64BIT(&ctx->iv[0], ctr[0]);
  SSH_PUT_64BIT(&ctx->iv[1], ctr[1]);




  return SSH_CRYPTO_OK;
}



/* Encrypt/decrypt in cipher feedback mode */
SshCryptoStatus ssh_rijndael_cfb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 t, iv[2];

  iv[0] = ctx->iv[0];
  iv[1] = ctx->iv[1];

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC0(iv[0]);
          OCTEON_SET_AES_ENC1(iv[1]);

          OCTEON_GET_AES_RESULT(iv[0], 0);
          OCTEON_GET_AES_RESULT(iv[1], 1);

          *((SshUInt64 *)(dest)) = iv[0] = *((SshUInt64 *)(src)) ^ iv[0];
          *((SshUInt64 *)(dest+8)) = iv[1] = *((SshUInt64 *)(src+8)) ^ iv[1];

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_AES_ENC0(iv[0]);
          OCTEON_SET_AES_ENC1(iv[1]);

          OCTEON_GET_AES_RESULT(iv[0], 0);
          OCTEON_GET_AES_RESULT(iv[1], 1);

          t=*((SshUInt64 *)(src));
          *((SshUInt64 *)(dest)) = iv[0] ^ t;
          iv[0] = t;

          t=*((SshUInt64 *)(src + 8));
          *((SshUInt64 *)(dest + 8)) = iv[1] ^ t;
          iv[1] = t;

          src += 16;
          dest += 16;
          len -= 16;
        }
    }

  ctx->iv[0] = iv[0];
  ctx->iv[1] = iv[1];




  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rijndael_cbc_mac(void *context, const unsigned char *src, size_t len,
                     unsigned char *iv_arg)
{
  SshRijndaelContext ctx = (SshRijndaelContext) context;
  SshUInt64 iv[2];

  iv[0] = ((SshUInt64 *)iv_arg)[0];
  iv[1] = ((SshUInt64 *)iv_arg)[1];

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  ssh_octeon_set_key(ctx);

  while (len > 0)
    {
      iv[0] ^= ((SshUInt64 *)src)[0];
      iv[1] ^= ((SshUInt64 *)src)[1];

      OCTEON_SET_AES_ENC0(iv[0]);
      OCTEON_SET_AES_ENC1(iv[1]);

      OCTEON_GET_AES_RESULT(iv[0], 0);
      OCTEON_GET_AES_RESULT(iv[1], 1);

      src += 16;
      len -= 16;
    }

  ((SshUInt64 *)iv_arg)[0] = iv[0];
  ((SshUInt64 *)iv_arg)[1] = iv[1];





  return SSH_CRYPTO_OK;
}



static inline SshUInt64 swap64(SshUInt64 a)
{
  return ((a >> 56) |
          (((a >> 48) & 0xfful) << 8) |
          (((a >> 40) & 0xfful) << 16) |
          (((a >> 32) & 0xfful) << 24) |
          (((a >> 24) & 0xfful) << 32) |
          (((a >> 16) & 0xfful) << 40) |
          (((a >> 8) & 0xfful) << 48) |
          (((a >> 0) & 0xfful) << 56));
}

/* ****************** 3 DES *********************************************/

typedef struct
{
  Boolean for_encryption;
  SshUInt64 key[3];
  SshUInt64 iv;
} SshTripleDESContext;


size_t ssh_des3_ctxsize()
{
  return sizeof(SshTripleDESContext);
}

SshCryptoStatus ssh_des3_init(void *ptr,
                             const unsigned char *key, size_t keylen,
                             Boolean for_encryption)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)ptr;
  int i;

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  ctx->for_encryption = for_encryption;

  SSH_DEBUG(SSH_D_MY, ("In Octeon 3des init"));

  for (i = 0; i < 3; i++)
    ctx->key[i] =
      (((SshUInt64) key[(i * 8) + 0]) << 56) |
      (((SshUInt64) key[(i * 8) + 1]) << 48) |
      (((SshUInt64) key[(i * 8) + 2]) << 40) |
      (((SshUInt64) key[(i * 8) + 3]) << 32) |
      (((SshUInt64) key[(i * 8) + 4]) << 24) |
      (((SshUInt64) key[(i * 8) + 5]) << 16) |
      (((SshUInt64) key[(i * 8) + 6]) << 8) |
      ((SshUInt64) key[(i * 8) + 7]);

  return SSH_CRYPTO_OK;
}

void ssh_des3_uninit(void *context)
{
  return;
}

SshCryptoStatus ssh_des3_start(void *context, const unsigned char *iv)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;

  ctx->iv = *((SshUInt64 *)iv);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_des3_init_with_key_check(void *ptr,
                            const unsigned char *key, size_t keylen,
                            Boolean for_encryption)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)ptr;
  int i;

  SSH_DEBUG(SSH_D_MY, ("In Octeon 3des init with key check"));

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  if (ssh_des_init_is_weak_key(key))
    return SSH_CRYPTO_KEY_WEAK;

  /* Not a weak key continue. */
  ctx->for_encryption = for_encryption;

  for (i = 0; i < 3; i++)
    ctx->key[i] =
      (((SshUInt64) key[(i * 8) + 0]) << 56) |
      (((SshUInt64) key[(i * 8) + 1]) << 48) |
      (((SshUInt64) key[(i * 8) + 2]) << 40) |
      (((SshUInt64) key[(i * 8) + 3]) << 32) |
      (((SshUInt64) key[(i * 8) + 4]) << 24) |
      (((SshUInt64) key[(i * 8) + 5]) << 16) |
      (((SshUInt64) key[(i * 8) + 6]) << 8) |
      ((SshUInt64) key[(i * 8) + 7]);

  return SSH_CRYPTO_OK;
}


/* Encryption and decryption in electronic codebook mode */
SshCryptoStatus ssh_des3_ecb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *) context;

#ifdef KERNEL
  ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_DEC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }




  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_cbc(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *)context;

#ifdef KERNEL
    ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  OCTEON_SET_3DES_IV(ctx->iv);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC_CBC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_DEC_CBC(*((SshUInt64 *)(src)));
          OCTEON_GET_3DES_RESULT(*((SshUInt64 *)(dest)));

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

 OCTEON_GET_3DES_IV(ctx->iv);




  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_des3_ofb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *) context;
  SshUInt64 iv, t;

  SSH_DEBUG(SSH_D_MY, ("In Octeon 3des OFB"));

#ifdef KERNEL
    ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  iv = ctx->iv;

  while (len > 0)
    {
      OCTEON_SET_3DES_ENC(iv);
      OCTEON_GET_3DES_RESULT(iv);

      t = *((SshUInt64 *)(src)) ^ iv;
      *((SshUInt64 *)(dest)) = t;

      src += 8;
      dest += 8;
      len -= 8;
    }

  ctx->iv = iv;




  return SSH_CRYPTO_OK;
}


/* Encrypt/decrypt in cipher feedback mode */
SshCryptoStatus ssh_des3_cfb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len)
{
  SshTripleDESContext *ctx = (SshTripleDESContext *) context;
  SshUInt64 t, iv;

  iv = ctx->iv;

#ifdef KERNEL
    ENABLE_COP2();
#endif /* KERNEL */
  OCTEON_SET_3DES_KEY(ctx->key[0], 0);
  OCTEON_SET_3DES_KEY(ctx->key[1], 1);
  OCTEON_SET_3DES_KEY(ctx->key[2], 2);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC(iv);
          OCTEON_GET_3DES_RESULT(iv);

          *((SshUInt64 *)(dest)) = iv = *((SshUInt64 *)(src)) ^ iv;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          OCTEON_SET_3DES_ENC(iv);
          OCTEON_GET_3DES_RESULT(iv);

          t = *((SshUInt64 *)(src));
          *((SshUInt64 *)(dest)) = iv ^ t;
          iv  = t;

          src += 8;
          dest += 8;
          len -= 8;
        }
    }

  ctx->iv = iv;




  return SSH_CRYPTO_OK;
}

#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
