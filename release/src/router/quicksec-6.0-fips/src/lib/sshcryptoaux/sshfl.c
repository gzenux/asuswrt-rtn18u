/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshentropy.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshfl.h"

#include "fl.h"


#define SSH_DEBUG_MODULE "SshCryptoAuxFl"

/* ***************************** Util ********************************* */

const char *ssh_fl_rv_to_string(FL_RV rv)
{
  const char *string = NULL;

  switch (rv)
    {
    case FLR_OK:
      string = "OK";
      break;
    case FLR_VERIFY_MISMATCH:
      string = "Verify operation failed";
      break;
    case FLR_OUTPUT_LENGTH:
      string = "Output buffer too small or not provided";
      break;
    case FLR_WRONG_STATE:
      string = "Function called in wrong state";
      break;
    case FLR_OPERATION_FAILED:
      string = "Cryptographic operation failed";
      break;
    case FLR_INVALID_DATA:
      string = "Invalid data provided for the operation";
      break;
    case FLR_INVALID_ALGORITHM:
      string = "Invalid algorithm";
      break;
    case FLR_INVALID_ARGUMENTS:
      string = "Invalid arguments";
      break;
    case FLR_ASSET_STORAGE:
      string = "Asset Storage is full";
      break;
    case FLR_SELFTEST_FAILED:
      string = "Selftest failed";
      break;
    case FLR_PRIVILEGE_VIOLATION:
      string = "Privilidge violation";
      break;
    case FLR_RESOURCE_NOT_FOUND:
      string = "Resource not found";
      break;
    case FLR_RNG_ENTROPY:
      string = "Unable to obtain sufficient entropy";
      break;
    case FLR_RNG_CONTINUOUS_TEST_FAILURE:
      string = "Continuous RNG test failed";
      break;
    default:
      string = "Unknown return value";
      break;
    }

  return string;
}

/* *********************** Reference counts *************************** */

static void
ssh_fl_entropy_function(FL_DataOutPtr_t EntropyOut_p,
                        FL_DataLen_t    BufferSize,
                        FL_DataLen_t   *InputSize,
                        FL_BitsLen_t   *EntropySize)
{
  size_t input_size = 0;
  size_t entropy_size = 0;

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting to fetch entropy, buffer size %u",
                             (unsigned int) BufferSize));

  (void) ssh_get_system_entropy((unsigned char *)EntropyOut_p,
                                (size_t)BufferSize,
                                &input_size,
                                &entropy_size);

  *InputSize = (FL_DataLen_t) input_size;
  *EntropySize = (FL_BitsLen_t) entropy_size;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Got %u bits of entropy in %u byte buffer",
             (unsigned int) *EntropySize,
             (unsigned int) *InputSize));
}

SshCryptoStatus ssh_fl_init(void)
{
  FL_LibStatus_t status;
  FL_RV fl_rv;

  /* Check FIPS library status */
  status = FL_LibStatus();

  /* In fipslib1.1 the FL_LibInit() is already called when the library is
   * loaded so we don't need to call it again. */
  switch (status)
    {
      case FL_STATUS_INITIAL:
        /* FIPS Lib not yet initialized, do it now */
        fl_rv = FL_LibInit();
        if (fl_rv != FLR_OK)
          {
            SSH_DEBUG(SSH_D_ERROR, ("Failed FL_LibInit():%s",
                                 ssh_fl_rv_to_string(fl_rv)));
            return SSH_CRYPTO_INTERNAL_ERROR;
          }
        break;
      case FL_STATUS_CRYPTO_OFFICER:
        /* lib already initialized, nothing to do here anymore */
        break;
      default:
        /* Any other lib state is an error at this stage */
        SSH_DEBUG(SSH_D_ERROR, ("Error: FIPS Library status %d", status));
        return SSH_CRYPTO_INTERNAL_ERROR;
    }

  /* Replace the default entropy source. */
  fl_rv = FL_RbgInstallEntropySource(ssh_fl_entropy_function);
  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed FL_RbgInstallEntropySource():%s",
                 ssh_fl_rv_to_string(fl_rv)));
    }

  /* Set FIPS library to User state. */
  fl_rv = FL_LibEnterUserRole();
  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed RbgInstallEntropySource():%s",
                 ssh_fl_rv_to_string(fl_rv)));

      /* Uninit FIPS library */
      (void) FL_LibUnInit();

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}



static void
ssh_fl_zeroize_flids(
        void)
{
  FL_KeyAsset_t key_asset;

  SSH_DEBUG(SSH_D_MIDOK, ("flid zeroize start"));
  do
    {
      FL_RV rv;

      rv =
          FL_AssetAllocateBasic(
                  FL_POLICY_ALGO_HMAC_SHA1 | FL_POLICY_ALGO_MAC_GENERATE,
                  1,
                  &key_asset);
      SSH_VERIFY(rv == FLR_OK);

      rv = FL_AssetCheck(key_asset, FL_CHECK_EXISTS);
      SSH_VERIFY(rv == FLR_OK);

      rv = FL_AssetFree(key_asset);
      SSH_VERIFY(rv == FLR_OK);
    }
  while ((key_asset & 0xffff0000) != 0x10000);
  SSH_DEBUG(SSH_D_MIDOK, ("flid zeroize stop"));

}


void ssh_fl_uninit(void)
{
  FL_LibStatus_t status;
  FL_RV fl_rv;

  /* Check FIPS library status */
  status = FL_LibStatus();
  if (status == FL_STATUS_INITIAL)
    {
      /* FIPS library already in initial state. */
      return;
    }

  ssh_fl_zeroize_flids();

  /* Uninitialize FIPS library */
  fl_rv = FL_LibUnInit();
  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed FL_LibUnInit():%s",
                 ssh_fl_rv_to_string(fl_rv)));
    }
}

