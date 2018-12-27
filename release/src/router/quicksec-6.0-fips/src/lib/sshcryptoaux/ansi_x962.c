/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshmp.h"

#include "ansi_x962.h"

#define SSH_DEBUG_MODULE "CryptoAuxAnsiX962"

#define SEED_KEY_SIZE   64
#define SHA_DIGEST_SIZE 20

/* The random state context. */
typedef struct SshAnsiX962Rec {
  SshMPIntegerStruct xseed, xkey, xval, output;

  unsigned char   xval_buf[SEED_KEY_SIZE];
  unsigned char output_buf[SHA_DIGEST_SIZE];

  size_t next_available_byte;

  /* Total count of the number of random bytes output */
  size_t bytes_output;
} SshAnsiX962Struct;

SshCryptoStatus
ssh_ansi_x962_add_entropy(SshAnsiX962 state,
                          const unsigned char *buf, size_t buflen)
{
  /* Convert the input buffer to an multiple precision integer, xseed. */
  ssh_mprz_set_buf(&state->xseed, buf, buflen);

  /* Add xseed to xkey modulo 2^b (= 2^512). */
  ssh_mprz_add(&state->xseed, &state->xseed, &state->xkey);
  ssh_mprz_mod_2exp(&state->xseed, &state->xseed, 8 * SEED_KEY_SIZE);

  ssh_mprz_set(&state->xkey, &state->xseed);

  if (ssh_mprz_isnan(&state->xseed))
    return SSH_CRYPTO_OPERATION_FAILED;

  return SSH_CRYPTO_OK;
}

void ssh_ansi_x962_uninit(SshAnsiX962 state)
{
  if (state == NULL)
    return;

  /* Clear the multiple precision integers. */
  ssh_mprz_clear(&state->xkey);
  ssh_mprz_clear(&state->xval);
  ssh_mprz_clear(&state->xseed);
  ssh_mprz_clear(&state->output);

  /* Zeroize and free. */
  memset(state, 0, sizeof(*state));
  ssh_free(state);
}

SshAnsiX962
ssh_ansi_x962_init()
{
  SshAnsiX962 state;

  /* The output of SHA-1 is 160 bits and we assume the seed key size
     to be 512 bits. */
  SSH_ASSERT(SHA_DIGEST_SIZE == 20);
  SSH_ASSERT(SEED_KEY_SIZE == 64);

  if (!(state = ssh_calloc(1, sizeof(*state))))
    return NULL;

  /* Initialize the multiple precision integers. */
  ssh_mprz_init_set_ui(&state->xkey, 0);
  ssh_mprz_init_set_ui(&state->xval, 0);
  ssh_mprz_init_set_ui(&state->xseed, 0);
  ssh_mprz_init_set_ui(&state->output, 0);

  if (ssh_mprz_isnan(&state->xkey) || ssh_mprz_isnan(&state->xseed)
      || ssh_mprz_isnan(&state->xval) || ssh_mprz_isnan(&state->output))
    {
      ssh_ansi_x962_uninit(state);
      return NULL;
    }

  state->next_available_byte = SHA_DIGEST_SIZE;

  return state;
}

SshCryptoStatus
ssh_ansi_x962_get_byte(SshAnsiX962 state,
                       unsigned char *byte_ret)
{
  if (state->next_available_byte >= SHA_DIGEST_SIZE)
    {
      SshUInt32 buf[5];
      SshUInt16 seed_len = SHA_DIGEST_SIZE;

      ssh_mprz_set(&state->xval, &state->xseed);

      memset(state->xval_buf, 0x0, sizeof(state->xval_buf));
      /* Linearize xkey to a buffer. */
      if (ssh_mprz_get_buf(state->xval_buf,
                           seed_len, &state->xval) == 0)
        return SSH_CRYPTO_OPERATION_FAILED;

      /* Apply the sha transform. */
      ssh_sha_transform(buf, state->xval_buf);

      SSH_PUT_32BIT(state->output_buf,      buf[0]);
      SSH_PUT_32BIT(state->output_buf + 4,  buf[1]);
      SSH_PUT_32BIT(state->output_buf + 8,  buf[2]);
      SSH_PUT_32BIT(state->output_buf + 12, buf[3]);
      SSH_PUT_32BIT(state->output_buf + 16, buf[4]);

      memset(buf, 0, sizeof(buf));

      /* Convert the 'output_buf' buffer back to integer form. */
      ssh_mprz_set_buf(&state->output, state->output_buf,
                       sizeof(state->output_buf));

      /* Update the integer 'xkey' by adding to it 1 plus 'output' and
         then taking its modulus mod 2^b. */
      ssh_mprz_add_ui(&state->xkey, &state->xkey, 1);
      ssh_mprz_add(&state->xkey, &state->xkey, &state->output);
      ssh_mprz_mod_2exp(&state->xkey, &state->xkey, seed_len * 8);

      /* Update xseed to the new value of xkey. */
      ssh_mprz_set(&state->xseed, &state->xkey);

      if (ssh_mprz_isnan(&state->xseed))
        return SSH_CRYPTO_OPERATION_FAILED;

      state->next_available_byte = 0;
    }

  *byte_ret = state->output_buf[state->next_available_byte++];

  state->bytes_output++;

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_ansi_x962_get_bytes(SshAnsiX962 state,
                        unsigned char *buf, size_t buflen)
{
  unsigned int i;
  SshCryptoStatus status;

  for (i = 0; i < buflen; i++)
    {
      status = ssh_ansi_x962_get_byte(state, &buf[i]);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  return SSH_CRYPTO_OK;
}
