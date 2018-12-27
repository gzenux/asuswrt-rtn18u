/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   MGF1 for the RSA.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshrgf.h"
#include "sshpk_i.h"

#define SSH_DEBUG_MODULE "SshCryptoRGF"

SshCryptoStatus ssh_rsa_mgf1(const char *hash_name,
                     const unsigned char *seed, size_t seed_len,
                     unsigned char *mask, size_t mask_len)
{
  SshUInt32      i, steps;
  unsigned char  digest[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t digest_len;
  SshHash hash;
  SshCryptoStatus status = SSH_CRYPTO_OK;

  if ((status = ssh_hash_allocate(hash_name, &hash)) != SSH_CRYPTO_OK)
    return status;

  digest_len = ssh_hash_digest_length(hash_name);

  for (i = 0, steps = 0; i < mask_len; i += digest_len, steps++)
    {
      unsigned char counter[4];
      size_t avail;

      SSH_PUT_32BIT(counter, steps);

      ssh_hash_reset(hash);
      ssh_hash_update(hash, seed, seed_len);
      ssh_hash_update(hash, counter, 4);
      if ((status = ssh_hash_final(hash, digest)) != SSH_CRYPTO_OK)
        {
          ssh_hash_free(hash);
          return status;
        }

      /* Now copy the digest to the mask. */
      avail = mask_len - i;
      if (avail >= digest_len)
        memcpy(mask + i, digest, digest_len);
      else
        memcpy(mask + i, digest, avail);
    }
  ssh_hash_free(hash);
  return status;
}
