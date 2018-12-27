/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Take a hash from a given buffer. (this function originally in
   lib/sshcrypto/sshhash/genhash.c)
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash.h"

/* Hashes one buffer with selected hash type and returns the
   digest. This can return error codes from either ssh_hash_allocate
   or ssh_hash_final. */

SshCryptoStatus
ssh_hash_of_buffer(const char *type,
                   const void *buf, size_t len,
                   unsigned char *digest)
{
  SshHash hash;
  SshCryptoStatus status;

  if ((status = ssh_hash_allocate(type, &hash)) != SSH_CRYPTO_OK)
    return status;

  ssh_hash_update(hash, buf, len);
  status = ssh_hash_final(hash, digest);
  ssh_hash_free(hash);

  return status;
}
