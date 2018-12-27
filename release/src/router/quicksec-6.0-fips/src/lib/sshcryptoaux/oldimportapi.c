/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Provides backward-compatible versions of ssh_private_key_import,
   ssh_private_key_export, ssh_public_key_import,
   ssh_public_key_export, ssh_pk_group_import, ssh_pk_group_export,
   ssh_pk_group_import_randomizers and
   ssh_pk_group_export_randomizers.

   Note that all these functions are deprecated and will be removed in
   future releases.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h"

#define SSH_DEBUG_MODULE "SshCryptoAuxOldImport"

SshCryptoStatus
ssh_private_key_export(SshPrivateKey handle,
                       const char *cipher_name,
                       const unsigned char *cipher_key, size_t cipher_keylen,
                       unsigned char **bufptr,
                       size_t *length_return)
{
  return
    ssh_pk_export(bufptr, length_return,
                  SSH_PKF_PRIVATE_KEY, handle,
                  SSH_PKF_ENVELOPE_VERSION, SSH_CRYPTO_ENVELOPE_VERSION_1,
                  SSH_PKF_CIPHER_NAME, cipher_name,
                  SSH_PKF_CIPHER_KEY, cipher_key, cipher_keylen,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_public_key_export(SshPublicKey handle,
                      unsigned char **buf, size_t *length_return)
{
  return
    ssh_pk_export(buf, length_return,
                  SSH_PKF_PUBLIC_KEY, handle,
                  SSH_PKF_ENVELOPE_VERSION, SSH_CRYPTO_ENVELOPE_VERSION_1,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_pk_group_export(SshPkGroup handle,
                    unsigned char **buf, size_t *buf_length)
{
  return
    ssh_pk_export(buf, buf_length,
                  SSH_PKF_PK_GROUP, handle,
                  SSH_PKF_ENVELOPE_VERSION, SSH_CRYPTO_ENVELOPE_VERSION_1,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_pk_group_export_randomizers(SshPkGroup handle,
                                unsigned char **buf, size_t *buf_length)
{
  return
    ssh_pk_export(buf, buf_length, NULL,
                  SSH_PKF_ENVELOPE_VERSION, SSH_CRYPTO_ENVELOPE_VERSION_1,
                  SSH_PKF_PK_GROUP_RANDOMIZERS, handle,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_private_key_import(const unsigned char *buf, size_t len,
                       const unsigned char *cipher_key, size_t cipher_keylen,
                       SshPrivateKey *key_ret)
{
  return
    ssh_pk_import(buf, len, NULL,
                  SSH_PKF_PRIVATE_KEY, key_ret,
                  SSH_PKF_CIPHER_KEY, cipher_key, cipher_keylen,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_public_key_import(const unsigned char *buf, size_t len,
                      SshPublicKey *key_ret)
{
  return
    ssh_pk_import(buf, len, NULL,
                  SSH_PKF_PUBLIC_KEY, key_ret,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_pk_group_import_randomizers(SshPkGroup handle,
                                const unsigned char *buf, size_t buf_length)
{
  return
    ssh_pk_import(buf, buf_length, NULL,
                  SSH_PKF_PK_GROUP_RANDOMIZERS, handle,
                  SSH_PKF_END);
}

SshCryptoStatus
ssh_pk_group_import(const unsigned char *buf, size_t buf_length,
                    SshPkGroup *group_ret)
{
  return
    ssh_pk_import(buf, buf_length, NULL,
                  SSH_PKF_PK_GROUP, group_ret,
                  SSH_PKF_END);
}
