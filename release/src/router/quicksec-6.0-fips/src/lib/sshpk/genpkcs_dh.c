/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface code for public key cryptosystems.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshpk_i.h"

#define SSH_DEBUG_MODULE "SshCryptoGenpkcsDH"

/* Diffie-Hellman key exchange method. */

size_t
ssh_pk_group_object_dh_setup_max_output_length(SshPkGroupObject group)
{
  if (group->diffie_hellman == NULL ||
      group->diffie_hellman->diffie_hellman_exchange_max_length == NULL_FNPTR)
    return 0;

  return (*group->diffie_hellman->
          diffie_hellman_exchange_max_length)(group->context);
}

size_t
ssh_pk_group_object_dh_agree_max_output_length(SshPkGroupObject group)
{
  if (group->diffie_hellman == NULL ||
      group->diffie_hellman->diffie_hellman_secret_value_max_length
      == NULL_FNPTR)
    return 0;

  return (*group->diffie_hellman->
          diffie_hellman_secret_value_max_length)(group->context);
}


size_t
ssh_pk_group_dh_setup_max_output_length(SshPkGroup handle)
{
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return 0;

  return ssh_pk_group_object_dh_setup_max_output_length(group);
}

size_t
ssh_pk_group_dh_agree_max_output_length(SshPkGroup handle)
{
  SshPkGroupObject group;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return 0;

  return ssh_pk_group_object_dh_agree_max_output_length(group);
}


SshCryptoStatus
ssh_pk_group_object_dh_setup(SshPkGroupObject group,
                             SshPkGroupDHSecret *secret,
                             unsigned char *exchange,
                             size_t exchange_length,
                             size_t *return_length)
{
  if (group->diffie_hellman == NULL ||
      group->diffie_hellman->diffie_hellman_setup == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  return (*group->diffie_hellman->diffie_hellman_setup)(group->context,
                                                        secret,
                                                        exchange,
                                                        exchange_length,
                                                        return_length);
}

SshCryptoStatus
ssh_pk_group_dh_setup(SshPkGroup handle,
                      SshPkGroupDHSecret *secret,
                      unsigned char *exchange,
                      size_t exchange_length,
                      size_t *return_length)
{
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return
    ssh_pk_group_object_dh_setup(group, secret,
                                 exchange, exchange_length, return_length);
}

SshCryptoStatus
ssh_pk_group_object_dh_agree(SshPkGroupObject group,
                             SshPkGroupDHSecret secret,
                             const unsigned char *exchange,
                             size_t exchange_length,
                             unsigned char *secret_value_buffer,
                             size_t secret_value_buffer_length,
                             size_t *return_length)
{
  if (group->diffie_hellman == NULL ||
      group->diffie_hellman->diffie_hellman_agree == NULL_FNPTR)
    {
      ssh_pk_group_dh_secret_free(secret);
      return SSH_CRYPTO_UNSUPPORTED;
    }

  return (*group->diffie_hellman->
          diffie_hellman_agree)(group->context,
                                (void *) secret,
                                exchange,
                                exchange_length,
                                secret_value_buffer,
                                secret_value_buffer_length,
                                return_length);
}

SshCryptoStatus
ssh_pk_group_dh_agree(SshPkGroup handle,
                      SshPkGroupDHSecret secret,
                      const unsigned char *exchange,
                      size_t exchange_length,
                      unsigned char *secret_value_buffer,
                      size_t secret_value_buffer_length,
                      size_t *return_length)
{
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return
    ssh_pk_group_object_dh_agree(group, secret, exchange, exchange_length,
                                 secret_value_buffer,
                                 secret_value_buffer_length, return_length);
}

/* Start asyncronous Diffie-Hellman setup operation. The library will call
   given callback when operation is done. Callback may be called immediately
   during this call. The function ssh_operation_abort function may be called to
   abort this operation before it finishes, in which case the callback is not
   called and the SshOperationHandle will be NULL. */
SshOperationHandle
ssh_pk_group_dh_setup_async(SshPkGroup handle,
                            SshPkGroupDHSetup callback,
                            void *context)
{
  SshPkGroupDHSecret secret = NULL;
  unsigned char *exchange;
  size_t exchange_length;
  size_t return_length = 0;
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (!ssh_crypto_library_object_check_use(&status))
    {
      (*callback)(status, NULL, NULL, 0, context);
      return NULL;
    }

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    {
      (*callback)(SSH_CRYPTO_HANDLE_INVALID, NULL, NULL, 0, context);
      return NULL;
    }

  if (group->diffie_hellman &&
      group->diffie_hellman->diffie_hellman_setup_async)
    {
      return (*group->diffie_hellman->diffie_hellman_setup_async)
        (group->context, callback, context);
    }

  exchange_length = ssh_pk_group_dh_setup_max_output_length(handle);
  exchange = ssh_malloc(exchange_length);

  if (exchange == NULL)
    {
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, NULL, 0, context);
      return NULL;
    }

  status = ssh_pk_group_dh_setup(handle, &secret,
                                 exchange, exchange_length,
                                 &return_length);
  (*callback)(status, secret, exchange, return_length, context);
  ssh_free(exchange);

  return NULL;
}


/* Start asyncronous Diffie-Hellman agree operation. The library will call
   given callback when operation is done. Callback may be called immediately
   during this call. The function ssh_operation_abort function may be called to
   abort this operation before it finishes, in which case the callback is not
   called and the SshOperationHandle will be NULL. */
SshOperationHandle
ssh_pk_group_dh_agree_async(SshPkGroup handle,
                            SshPkGroupDHSecret secret,
                            const unsigned char *exchange,
                            size_t exchange_length,
                            SshPkGroupDHAgree callback,
                            void *context)
{
  unsigned char *secret_buffer = NULL;
  size_t secret_buffer_length;
  size_t return_length = 0;
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (!ssh_crypto_library_object_check_use(&status))
    {
      ssh_pk_group_dh_secret_free(secret);

      (*callback)(status, NULL, 0, context);
      return NULL;
    }

  if (!(group = SSH_CRYPTO_HANDLE_TO_PK_GROUP(handle)))
    {
      ssh_pk_group_dh_secret_free(secret);

      (*callback)(SSH_CRYPTO_HANDLE_INVALID, NULL, 0, context);
      return NULL;
    }

  if (group->diffie_hellman &&
      group->diffie_hellman->diffie_hellman_agree_async)
    {
      return (*group->diffie_hellman->diffie_hellman_agree_async)
        (group->context,
         (void *)secret,
         exchange, exchange_length,
         callback, context);
    }

  secret_buffer_length = ssh_pk_group_dh_agree_max_output_length(handle);

  if ((secret_buffer = ssh_malloc(secret_buffer_length)) != NULL)
    {
      status = ssh_pk_group_dh_agree(handle,
                                     secret,
                                     exchange, exchange_length,
                                     secret_buffer, secret_buffer_length,
                                     &return_length);
      (*callback)(status, secret_buffer, return_length, context);
      ssh_free(secret_buffer);
      return NULL;
    }
  else
    {
      ssh_pk_group_dh_secret_free(secret);
      (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, context);
      return NULL;
    }
}
