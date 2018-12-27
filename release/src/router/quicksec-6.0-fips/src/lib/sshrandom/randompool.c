/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   (P)RNG, relies on system /dev/random to get the data.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"

#define SSH_DEBUG_MODULE "SshRandomPool"

typedef struct SshRandomPoolStateRec {
  /* Pool buffer, allocated memory */
  unsigned char *pool;

  /* Current read offset to pool */
  size_t pool_offset;

  /* Length of the pool true data. (offset + len) is the end of valid
     data, where offset is the start of valid data - thus between
     add_entropy (offset + len) is a constant.*/
  size_t pool_len;

  /* Size of the pool */
  size_t pool_size;
} *SshRandomPoolState, SshRandomPoolStateStruct;

static SshCryptoStatus
ssh_random_pool_get_bytes(void *context, unsigned char *buf, size_t buflen)
{
  SshRandomPoolState state = (SshRandomPoolState) context;

  SSH_DEBUG(5, ("Reading, offset=%d len=%d size=%d buflen=%d",
                state->pool_offset, state->pool_len, state->pool_size,
                buflen));

  /* See if we can satisfy `buflen' bytes from the pool */
  if (state->pool_len < buflen)
    return SSH_CRYPTO_DATA_TOO_LONG;

  SSH_ASSERT(state->pool_len >= buflen);

  memcpy(buf, state->pool + state->pool_offset, buflen);
  state->pool_len -= buflen;
  state->pool_offset += buflen;

  SSH_ASSERT(state->pool_offset + state->pool_len <= state->pool_size);

  /* Request more random noise when the pool length is less than 1/4
     of the pool size. */
  if (4 * state->pool_len <= state->pool_size)
    ssh_crypto_library_request_noise();


  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
ssh_random_pool_add_entropy(void *context,
                            const unsigned char *buf, size_t buflen,
                            size_t estimated_entropy_bits)
{
  SshRandomPoolState state = (SshRandomPoolState) context;

  SSH_DEBUG(5, ("Adding entropy, offset=%d len=%d size=%d buflen=%d",
                state->pool_offset, state->pool_len, state->pool_size,
                buflen));

  /* Check if we can put `buflen' bytes into end of current pool */
  if (state->pool_size - (state->pool_offset + state->pool_len) < buflen)
    {
      size_t new_size;
      unsigned char *new_pool;

      /* No - do two things: allocate compact buffer */
      new_size = state->pool_len + buflen;

      if ((new_pool = ssh_malloc(new_size)) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      memcpy(new_pool, state->pool + state->pool_offset, state->pool_len);

      ssh_free(state->pool);
      state->pool = new_pool;

      state->pool_offset = 0;
      state->pool_size = new_size;
    }

  SSH_ASSERT(state->pool_size - state->pool_len >= buflen);

  /* Yeah, we have enough space at the end */
  memcpy(state->pool + state->pool_len, buf, buflen);
  state->pool_len += buflen;

  SSH_ASSERT((state->pool_offset + state->pool_len) <= state->pool_size);

  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
ssh_random_pool_init(void **context_ret)
{
  SshRandomPoolState state;

  if (!(state = ssh_calloc(1, sizeof(*state))))
    return SSH_CRYPTO_NO_MEMORY;

  state->pool_offset = state->pool_len = state->pool_size = 0;
  state->pool = NULL;

  *context_ret = state;
  return SSH_CRYPTO_OK;
}

static void
ssh_random_pool_uninit(void *context)
{
  SshRandomPoolState state = (SshRandomPoolState) context;

  ssh_free(state->pool);
  ssh_free(state);
}

const SshRandomDefStruct ssh_random_pool = {
  "pool",
  ssh_random_pool_init, ssh_random_pool_uninit,
  ssh_random_pool_add_entropy, ssh_random_pool_get_bytes
};

/* Internal (but not static) function */
SshCryptoStatus
ssh_random_pool_get_length(SshRandom handle, size_t *size_ret)
{
  SshRandomPoolState state;
  SshRandomObject random;

  if (!(random = SSH_CRYPTO_HANDLE_TO_RANDOM(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (random->ops != &ssh_random_pool)
    return SSH_CRYPTO_UNSUPPORTED;

  state = (SshRandomPoolState) random->context;
  *size_ret = state->pool_len;

  return SSH_CRYPTO_OK;
}
