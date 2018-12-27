/**
   @copyright
   Copyright (c) 2013 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"
#include "sshfl.h"

#include "fl.h"

#define SSH_DEBUG_MODULE "SshCryptoRandomFl"

#define FL_RANDOM_REQUIRED_STRENGTH 256

static SshCryptoStatus
ssh_random_nist_sp_800_90_init(void **context_ret)
{
  /* Do nothing */
  *context_ret = NULL;

  return SSH_CRYPTO_OK;
}

static void
ssh_random_nist_sp_800_90_uninit(void *context)
{
  /* Do nothing */
  return;
}

static SshCryptoStatus
ssh_random_nist_sp_800_90_add_entropy(void *context,
                                      const unsigned char *buf,
                                      size_t buflen,
                                      size_t estimated_entropy_bits)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  unsigned char hash_buffer[32] = {0x00};

  FL_AnyAsset_t state;
  FL_RV rv;

  /* Up to 32 bytes allowed by the FIPS library, hash to match the length */
  if (buflen > 0)
    {
      SSH_FL_ALLOCATE_STATE(rv, &state);

      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed FL_ALLOCATE_STATE(): %s, (%d)",
                     ssh_fl_rv_to_string(rv), rv));
          status = SSH_CRYPTO_INTERNAL_ERROR;
          goto end;
        }

      rv = FL_HashInit(state,
                       FL_ALGO_HASH_SHA2_256,
                       buf,
                       buflen);

      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed FL_HashInit(): %s, (%d)",
                     ssh_fl_rv_to_string(rv), rv));
          status = SSH_CRYPTO_INTERNAL_ERROR;
          SSH_FL_ASSETFREE(state);
          goto end;
        }

      rv = FL_HashFinish(state, hash_buffer, 32);

      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed FL_HashFinish(): %s, (%d)",
                     ssh_fl_rv_to_string(rv), rv));
          status = SSH_CRYPTO_INTERNAL_ERROR;
          SSH_FL_ASSETFREE(state);
          goto end;
        }

      rv = FL_RbgReseed(hash_buffer, 32);

      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed FL_RbgReseed(): %s, (%d)",
                     ssh_fl_rv_to_string(rv), rv));
          status = SSH_CRYPTO_INTERNAL_ERROR;
          SSH_FL_ASSETFREE(state);
          goto end;
        }

      SSH_FL_ASSETFREE2(rv, state);

      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed FL_AssetFree(): %s, (%d)",
                     ssh_fl_rv_to_string(rv), rv));
          status = SSH_CRYPTO_INTERNAL_ERROR;
        }
    }
  else
    {
      rv = FL_RbgReseed(NULL, 0);

      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed FL_RbgReseed(): %s, (%d)",
                     ssh_fl_rv_to_string(rv), rv));
          status = SSH_CRYPTO_INTERNAL_ERROR;
        }
    }

 end:
  return status;
}

static SshCryptoStatus
ssh_random_nist_sp_800_90_get_bytes(void *context,
                                    unsigned char *buf, size_t buflen)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  FL_RV rv;

  memset(buf, 0x00, buflen);

  rv = FL_RbgGenerateRandom(FL_RANDOM_REQUIRED_STRENGTH,
                            buf,
                            buflen);

  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed FL_RbgGenerateRandom(): %s, (%d)",
                 ssh_fl_rv_to_string(rv), rv));
      status = SSH_CRYPTO_INTERNAL_ERROR;
    }
  else
    {
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Got random bytes from FIPS-library:"),
                        buf, buflen);
    }

  return status;
}

Boolean ssh_drbg_health_test()
{
  /* Self-tests cannot be initiated from outside, ignore request */
  return TRUE;
}

const SshRandomDefStruct ssh_random_nist_sp_800_90 = {
  "nist-sp-800-90",
  ssh_random_nist_sp_800_90_init,
  ssh_random_nist_sp_800_90_uninit,
  ssh_random_nist_sp_800_90_add_entropy,
  ssh_random_nist_sp_800_90_get_bytes
};
