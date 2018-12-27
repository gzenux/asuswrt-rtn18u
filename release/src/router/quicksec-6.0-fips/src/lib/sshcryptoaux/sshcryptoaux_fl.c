/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for auxillary routines related to crypto library but not
   essential for its operations. Eg. helper routines etc.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"

#define SSH_DEBUG_MODULE "SshCryptoAux"


/****************** Cryptographic subsystem initialization *******************/

#define SSH_CRYPTO_SYSTEM_FL_EK_TYPE "fl"
#define SSH_CRYPTO_SYSTEM_FL_EK_INIT_INFO "fl_init_info"


char *ssh_crypto_system_get_ek_type()
{
  return SSH_CRYPTO_SYSTEM_FL_EK_TYPE;
}

char *ssh_crypto_system_get_ek_init_info()
{
  return SSH_CRYPTO_SYSTEM_FL_EK_INIT_INFO;
}

SshCryptoStatus ssh_crypto_system_initialize(void)
{
  SshCryptoStatus status;

  /* Initialize Safezone FIPS library */
  status = ssh_fl_init();
  if (status != SSH_CRYPTO_OK)
    return status;

  /* Initialize ssh crypto library */
  status = ssh_crypto_library_initialize();
  if (status != SSH_CRYPTO_OK)
    {
      ssh_fl_uninit();
      return status;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_crypto_system_uninitialize(void)
{
  SshCryptoStatus status;

  /* Uninitialize ssh crypto library */
  status = ssh_crypto_library_uninitialize();
  if (status == SSH_CRYPTO_LIBRARY_UNINITIALIZED)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("sshcrypto library already uninitialized!"));
    }
  else
  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Error uninitializing crypto library!"));
    }

  /* Uninitialize Safezone FIPS library */
  ssh_fl_uninit();

  return SSH_CRYPTO_OK;
}

