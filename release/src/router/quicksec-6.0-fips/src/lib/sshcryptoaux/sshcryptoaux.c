/**
   @copyright
   Copyright (c) 2002 - 2013, INSIDE Secure Oy. All rights reserved.
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

char *ssh_crypto_system_get_ek_type()
{
  return NULL;
}

char *ssh_crypto_system_get_ek_init_info()
{
  return NULL;
}

SshCryptoStatus ssh_crypto_system_initialize(void)
{
  SshCryptoStatus status;

  /* Initialize ssh crypto library */
  status = ssh_crypto_library_initialize();
  if (status != SSH_CRYPTO_OK)
    {
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

  return SSH_CRYPTO_OK;
}

