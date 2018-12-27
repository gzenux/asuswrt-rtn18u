/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Safenet Look-Aside Accelerator Packet Engine utilities
   for chips with the use of the driver.
*/

#include "safenet_pe_utils.h"

#include "ip_cksum.h"
#include "sshcrypt.h"
#include "sshhash.h"
#include "sshhash_i.h"
#include "sha.h"
#include "sha256.h"
#include "sha512.h"
#include "md5.h"

#include "rijndael.h"

#include "safenet_la_params.h"

#define SSH_DEBUG_MODULE "SshSafenet174x"

/* Linux specific includes we use for
   kernel-mode memory allocation routines */
#ifdef KERNEL
#ifdef __linux__

#include "linux_internal.h"

#include <linux/time.h>
#include <linux/timer.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>

#include <linux/sched.h>

#include <linux/kernel.h>

#ifdef SSH_SAFENET_NOT_COHERENT_CACHE
/* there is no automatically coherent I/O */
#include <linux/dma-mapping.h>
#endif /* SSH_SAFENET_NOT_COHERENT_CACHE */
#endif /* __linux__ */
#endif /* KERNEL */


/******** API of utility functions for glue layer ***********/

#define SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE 128
/* The Safenet device requires as input the HMAC inner and outer precomputes
   when creating SA's and not the usual HMAC key.
   This function computes the HMAC precomputes for SHA-2 from the HMAC key. */
Boolean
ssh_safenet_compute_sha2_precomputes(const PE_HASH_ALG algo,
				     const unsigned char *key,
				     const size_t keylen,
				     unsigned char *inner,
				     unsigned char *outer,
				     const unsigned int inner_outer_limit,
				     unsigned int * const DigestLen_p)
{
  Boolean res = FALSE;
  unsigned char authdata[SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE];
  unsigned int i = 0;

  /* cannot be greater than SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE */
  unsigned int blocksize = 64;
  void *ctx =  NULL;
  size_t ctx_size = 0;

  /* whether word swap is required for SHA512 and SHA384 algorithms */
  unsigned int wordSwap = 0;

  SSH_ASSERT(DigestLen_p != NULL);
  SSH_ASSERT(inner != NULL);
  SSH_ASSERT(outer != NULL);
  SSH_ASSERT(key != NULL);

  *DigestLen_p = 0;

  switch (algo)
    {
    case PE_HASH_ALG_SHA256:
      ctx_size =  ssh_sha256_ctxsize();
      *DigestLen_p = 32;
      blocksize = 64;
      break;

    case PE_HASH_ALG_SHA512:
      ctx_size =  ssh_sha512_ctxsize();
      *DigestLen_p = 64;
      blocksize = 128;
#ifdef PE_REQUIRES_SWAP
      wordSwap = 0;
#else /* PE_REQUIRES_SWAP */
      wordSwap = 1;
#endif /* PE_REQUIRES_SWAP */
      break;

    case PE_HASH_ALG_SHA384:
      ctx_size =  ssh_sha512_ctxsize();
      *DigestLen_p = 64;
      blocksize = 128;
#ifdef PE_REQUIRES_SWAP
      wordSwap = 0;
#else /* PE_REQUIRES_SWAP */
      wordSwap = 1;
#endif /* PE_REQUIRES_SWAP */
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL,
		(": Unknown hash algorithm specified - %d\n",
		 algo));
        goto done;
    }

  SSH_ASSERT(blocksize <= SAFENET_LA_UTILS_MAX_SHA2_BLOCKSIZE);

  if (*DigestLen_p > inner_outer_limit)
    {
      SSH_DEBUG(SSH_D_FAIL,
		(": Not enough space provided for Inner and Outer digest "
		 "- %d, need at least %d bytes\n",
		 inner_outer_limit, *DigestLen_p));
      goto done;
    }

  if (keylen > blocksize)
    {
      SSH_DEBUG(SSH_D_FAIL,
		(": Key length (%d) is greater than the Block size (%d)\n",
		 keylen, blocksize));
        return FALSE;
    }

  ctx = ssh_kernel_alloc(ctx_size, SSH_KERNEL_ALLOC_NOWAIT);
  if (ctx == NULL)
    goto done;

  /* prepare context for inner digest */
  memset(ctx, 0, ctx_size);
  switch (algo)
    {
    case PE_HASH_ALG_SHA256:
      ssh_sha256_reset_context(ctx);
      break;

    case PE_HASH_ALG_SHA512:
      ssh_sha512_reset_context(ctx);
      break;

    case PE_HASH_ALG_SHA384:
      ssh_sha384_reset_context(ctx);
      break;

    default:
      goto done;
    }

  /* inner digest */
  memcpy(authdata, key, keylen);
  memset(authdata+keylen, 0, blocksize - keylen);

  for (i=0; i < blocksize; i++)
    authdata[i] ^= 0x36;

#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
		    ("authdata for inner digest"), authdata, blocksize);
#endif /* SAFENET_DEBUG_HEAVY */

  switch (algo)
    {
    case PE_HASH_ALG_SHA256:
      ssh_sha256_update(ctx, authdata, blocksize);
      break;

    case PE_HASH_ALG_SHA512:
    case PE_HASH_ALG_SHA384:
      ssh_sha512_update(ctx, authdata, blocksize);
      break;

    default:
      goto done;
    }

  for (i = 0; i < *DigestLen_p / 4; i++)
    {
      unsigned int srcindex = (i & 1) ? (i - wordSwap) : (i + wordSwap);

      SSH_PUT_32BIT_LSB_FIRST(inner + i*4, ((SshUInt32*)ctx)[srcindex]);
    }


  /* prepare context for outer digest */
  memset(ctx, 0, ctx_size);
  switch (algo)
    {
    case PE_HASH_ALG_SHA256:
      ssh_sha256_reset_context(ctx);
      break;

    case PE_HASH_ALG_SHA512:
      ssh_sha512_reset_context(ctx);
      break;

    case PE_HASH_ALG_SHA384:
      ssh_sha384_reset_context(ctx);
      break;

    default:
      goto done;
    }

  /* outer digest */
  memcpy(authdata, key, keylen);
  memset(authdata+keylen, 0, blocksize - keylen);

  for (i=0; i < blocksize; i++)
    authdata[i] ^= 0x5c;

#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("authdata for outer digest"),
		    authdata, blocksize);
#endif /* SAFENET_DEBUG_HEAVY */

  switch (algo)
    {
    case PE_HASH_ALG_SHA256:
      ssh_sha256_update(ctx, authdata, blocksize);
      break;

    case PE_HASH_ALG_SHA512:
    case PE_HASH_ALG_SHA384:
      ssh_sha512_update(ctx, authdata, blocksize);
      break;

    default:
      goto done;
    }


  for (i = 0; i < *DigestLen_p/4; i++)
    {
      unsigned int srcindex = (i & 1) ? (i - wordSwap) : (i + wordSwap);
      SSH_PUT_32BIT_LSB_FIRST(outer + i*4, ((SshUInt32*)ctx)[srcindex]);
    }

  res = TRUE;

#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Inner digest"), inner, *DigestLen_p);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Outer digest"), outer, *DigestLen_p);
#endif

 done:
  if (ctx != NULL)
    ssh_kernel_free(ctx);

  return res;
}

/* The Safenet device requires as input the GHash key
   when creating SA's for AES_GCM transform.
   This function computes the GHash key using the AES Cipher key.
   GHash key is a block of 16 '0' bytes encrypted with AES.
*/
Boolean
ssh_safenet_compute_gcm_hashkey(const unsigned char *key,
				const size_t keylen,
				unsigned char hash_key[16])
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  Boolean res = FALSE;
  unsigned char dummy_iv[16];
  void *ctx;

  ctx = ssh_kernel_alloc(ssh_rijndael_ctxsize(), SSH_KERNEL_ALLOC_NOWAIT);
  if (ctx == NULL)
    goto done;

  status = ssh_aes_init(ctx, key, keylen, TRUE);
  if (status != SSH_CRYPTO_OK)
    goto done;

  memset(hash_key, 0, 16 ); /* 128 bit */
  memset(dummy_iv, 0, sizeof(dummy_iv));

  /* Encryption and decryption in electronic codebook mode */
  status = ssh_rijndael_ecb(ctx, hash_key, hash_key, 16, dummy_iv);
  if (status != SSH_CRYPTO_OK)
    goto done;

  res = TRUE;

#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("GCM hash key"), hash_key, 16);
#endif

 done:
  if (ctx != NULL)
    ssh_kernel_free(ctx);

  return res;
}

/* The Safenet device requires as input the HMAC inner and outer precomputes
   when creating SA's and not the usual HMAC key. This computes the HMAC
   precomputes from the HMAC key. */
Boolean
ssh_safenet_compute_hmac_precomputes(Boolean sha_hash,
                                     const unsigned char *key,
                                     size_t keylen,
                                     unsigned char inner[20],
                                     unsigned char outer[20])
{
  unsigned char ipad[64];
  unsigned char opad[64];
  SshUInt32 buf[5];
  int i;

  buf[0] = 0x67452301L;
  buf[1] = 0xefcdab89L;
  buf[2] = 0x98badcfeL;
  buf[3] = 0x10325476L;
  buf[4] = 0xc3d2e1f0L;

  for (i = 0; i < 64; i++)
    {
      ipad[i] = 0x36;
      opad[i] = 0x5c;
    }

  if (keylen > 64)
    return FALSE;

  for (i = 0; i < keylen; i++)
    {
      ipad[i] ^= key[i];
      opad[i] ^= key[i];
    }

  if (sha_hash)
    ssh_sha_transform(buf, ipad);
  else
    ssh_md5_transform(buf, ipad);

  SSH_PUT_32BIT_LSB_FIRST(inner, buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 4, buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 8, buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 12, buf[3]);
  SSH_PUT_32BIT_LSB_FIRST(inner + 16, buf[4]);

  buf[0] = 0x67452301L;
  buf[1] = 0xefcdab89L;
  buf[2] = 0x98badcfeL;
  buf[3] = 0x10325476L;
  buf[4] = 0xc3d2e1f0L;

  if (sha_hash)
    ssh_sha_transform(buf, opad);
  else
    ssh_md5_transform(buf, opad);

  SSH_PUT_32BIT_LSB_FIRST(outer, buf[0]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 4, buf[1]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 8, buf[2]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 12, buf[3]);
  SSH_PUT_32BIT_LSB_FIRST(outer + 16, buf[4]);

#ifdef SAFENET_DEBUG_HEAVY
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Key"), key, keylen);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Inner digest"), inner, 20);
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Outer digest"), outer, 20);
#endif

  return TRUE;
}

void
safenet_copy_key_material(unsigned char *dst,
			  const unsigned char *src, int len)
{
#ifdef PE_REQUIRES_SWAP
  int i;

  /* Swap byte order of each 4 bytes. */
  for (i = 0; i < len; i += 4)
    {
      dst[i + 0] = src[i + 3];
      dst[i + 1] = src[i + 2];
      dst[i + 2] = src[i + 1];
      dst[i + 3] = src[i + 0];
    }
#else /* PE_REQUIRES_SWAP */
  /* No endian issues, just a regular copy. */
  memcpy(dst, src, len);
#endif /* PE_REQUIRES_SWAP */
}


#ifdef SSH_SAFENET_MIN_BYTE_SWAP
void ssh_swap_endian_w(void *buf, size_t num_of_words)
{
  int i = 0;
  for (i = 0; i < num_of_words; i++)
    st_le32( (uint32_t *)buf + i, *((uint32_t *)buf + i));
}
#endif /* SSH_SAFENET_MIN_BYTE_SWAP */
