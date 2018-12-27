/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Routines for generating and defining private keys.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshpk_i.h"
#include "crypto_tests.h"

#define SSH_DEBUG_MODULE "SshCryptoPKPrivate"

/* Private key generation or definition and selection of used schemes
   (although this can be done also with ssh_private_key_select_scheme(...)
   interface, which is probably more suitable).

   We use vararg lists, although not easy to debug they make this
   interface very flexible (at least considering these few algorithm
   families). */

#if !defined(GENERATE) && !defined(DEFINE)
#error "Do not compile this file directly, compile ssh-pk-prv-def.c or " \
       "ssh-pk-prv-gen.c"
#endif

#ifdef GENERATE
SshCryptoStatus
ssh_private_key_generate(SshPrivateKey *key_ret, const char *key_type, ...)
#endif /* GENERATE */
#ifdef DEFINE
SshCryptoStatus
ssh_private_key_define(SshPrivateKey *key_ret, const char *key_type, ...)
#endif /* DEFINE */
{
  SshCryptoStatus status;
  SshPrivateKeyObject private_key;
  const SshPkAction *action;
  SshPkFormat format;
  const char *name, *r;
  char consumed[128], *tmp;
  void *context;
  unsigned int i;
  va_list ap;

  *key_ret = NULL;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  status = SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  /* Get the key type (i.e. strip the scheme information from key_type). */
  if ((tmp = ssh_pk_get_key_type(key_type)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Check if this key type has been registered. */
  for (i = 0; ssh_pk_type_slots[i] != NULL && ssh_pk_type_slots[i]->name; i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, tmp) != 0)
        continue;

#ifdef GENERATE
      if (ssh_pk_type_slots[i]->private_key_action_generate == NULL_FNPTR)
        continue;
#endif /* GENERATE */

      /* Found the key type. */
      break;
    }

  ssh_free(tmp);

  /* No key type found. */
  if (ssh_pk_type_slots[i] == NULL)
    return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  /* Type matches (and if this is call to generate function, the
     generator is defined for the key type) i.e. we've found our
     key type, so continue with finding schemes and parameters. */

  /* Allocate private key context. */
  if ((private_key = ssh_calloc(1, sizeof(*private_key))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  private_key->type = ssh_pk_type_slots[i];

  /* Initialize actions, and verify that context was allocated. */
  if ((status = (*private_key->type->private_key_action_init)(&context)) !=
      SSH_CRYPTO_OK)
    {
      ssh_free(private_key);
      return status;
    }

  /* Set the scheme from the key name. */
  status = ssh_private_key_set_scheme_from_key_name(private_key, key_type);

  if (status != SSH_CRYPTO_OK)
    {
      (*private_key->type->private_key_action_free)(context);
      ssh_free(private_key);
      return status;
    }

  /* Parse vararg list. */
  consumed[0] = '\000';
  while (TRUE)
    {
      va_start(ap, key_type);
      PROCESS(ap, consumed);

      format = va_arg(ap, SshPkFormat);
      strcat(consumed, "i");

      if (format == SSH_PKF_END)
        {
          va_end(ap);
          break;
        }

      /* If the vararg list contains scheme parameters, we need to
         set the scheme again. */
      if (format == SSH_PKF_SIGN || format == SSH_PKF_ENCRYPT ||
          format == SSH_PKF_DH)
        {
          name = va_arg(ap, const char *);
          strcat(consumed, "p");
          status = ssh_private_key_set_scheme(private_key, format, name);

          if (status != SSH_CRYPTO_OK)
            {
              (*private_key->type->private_key_action_free)(context);
              ssh_free(private_key);
              va_end(ap);
              return status;
            }

          va_end(ap);
          continue;
        }

      /* Search name from command lists. */
      action = ssh_pk_find_action(private_key->type->action_list,
                                  format, SSH_PK_ACTION_FLAG_PRIVATE_KEY);
      if (!action)
        {
          (*private_key->type->private_key_action_free)(context);
          ssh_free(private_key);
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      /* Supported only scheme selection and special operations. */
      switch (action->flags & SSH_PK_ACTION_FLAG_GET_PUT)
        {
        case SSH_PK_ACTION_FLAG_GET_PUT:
          r = (*action->action_put)(context, ap, NULL, format);
          if (r == NULL ||
              (sizeof(consumed) - strlen(consumed) - 1) <= strlen(r))
            {
              (*private_key->type->private_key_action_free)(context);
              ssh_free(private_key);
              va_end(ap);
              return SSH_CRYPTO_INTERNAL_ERROR;
            }
          else
            strcat(consumed, r);
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      va_end(ap);
    }

  /* Make the key and remove context. */
#ifdef GENERATE
  status =
    (*private_key->type->private_key_action_generate)(context,
                                                      &private_key->context);
#else /* !GENERATE */
  status =
    (*private_key->type->private_key_action_define)(context,
                                                    &private_key->context);
#endif /* GENERATE */

  (*private_key->type->private_key_action_free)(context);

  /* Quit unhappily. */
  if (status != SSH_CRYPTO_OK)
    {
      ssh_free(private_key);
      return status;
    }

  /* Set the address of the private key to the key context. */
  if (private_key->type->set_key_pointer_to_context)
    {
      status = (*private_key->type->set_key_pointer_to_context)(private_key,
                                                                private_key->
                                                                context);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(private_key);
          return status;
        }
    }

#ifdef SSHDIST_CRYPT_SELF_TESTS
#ifdef GENERATE
  /* We have now generated a private key. Test the consistency of the
     private key. The crypto library enters an error state on failure.
     This test is required by FIPS 140-2 4.9.2 "Conditional Tests" */

  status = ssh_crypto_test_pk_private_consistency(private_key);

  if (status == SSH_CRYPTO_NO_MEMORY)
    {
      ssh_private_key_object_free(private_key);
      return SSH_CRYPTO_NO_MEMORY;
    }
  else if (status != SSH_CRYPTO_OK)
    {
      ssh_private_key_object_free(private_key);
      ssh_crypto_library_error(SSH_CRYPTO_ERROR_KEY_TEST_FAILURE);
      return SSH_CRYPTO_LIBRARY_ERROR;
    }
#else /* !GENERATE */
  /* Let's perform key consistency test. It's no good to import
     invalid keys, since they might later lead to global crypto error
     state. However, notice that while importing a key, consistency
     test is not a persistent error, just a normal failure. */

  if (ssh_crypto_test_pk_private_consistency(private_key) != SSH_CRYPTO_OK)
    {
      ssh_private_key_object_free(private_key);
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }
#endif /* !GENERATE */
#else /* SSHDIST_CRYPT_SELF_TESTS */
  {
    const char *temp_sign;
    temp_sign = ssh_private_key_find_default_scheme(private_key,
                                                    SSH_PKF_SIGN);
    status = ssh_private_key_set_scheme(private_key,
                                        SSH_PKF_SIGN, temp_sign);
    if (status != SSH_CRYPTO_OK)
      {
        ssh_private_key_object_free(private_key);
        return status;
      }
  }
#endif /* SSHDIST_CRYPT_SELF_TESTS */

  if (!ssh_crypto_library_object_use(private_key,
                                     SSH_CRYPTO_OBJECT_TYPE_PRIVATE_KEY))
    {
      ssh_free(private_key);
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Quit happily. */
  *key_ret = SSH_CRYPTO_PRIVATE_KEY_TO_HANDLE(private_key);

  return SSH_CRYPTO_OK;
}

#ifdef DEFINE
/* Function to define the private key object. This is needed in the
   power up tests. Note that this does NOT perform the private key
   consistency test. */
SshCryptoStatus
ssh_private_key_object_define(SshPrivateKeyObject *key_ret,
                              const char *key_type, ...)
{
  SshCryptoStatus status;
  SshPrivateKeyObject private_key;
  const SshPkAction *action;
  SshPkFormat format;
  const char *name, *r;
  char consumed[128], *tmp;
  void *context;
  unsigned int i;
  va_list ap;

  *key_ret = NULL;

  /* Get the key type (i.e. strip the scheme information from key_type). */
  if ((tmp = ssh_pk_get_key_type(key_type)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Check if this key type has been registered. */
  for (i = 0; ssh_pk_type_slots[i] != NULL && ssh_pk_type_slots[i]->name; i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, tmp) != 0)
        continue;

      /* Found the key type. */
      break;
    }

  ssh_free(tmp);

  /* No key type found. */
  if (ssh_pk_type_slots[i] == NULL)
    return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  /* Type matches (and if this is call to generate function, the
     generator is defined for the key type) i.e. we've found our
     key type, so continue with finding schemes and parameters. */

  /* Allocate private key context. */
  if ((private_key = ssh_calloc(1, sizeof(*private_key))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  private_key->type = ssh_pk_type_slots[i];

  /* Initialize actions, and verify that context was allocated. */
  status = (*private_key->type->private_key_action_init)(&context);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_free(private_key);
      return status;
    }

  /* Set the scheme from the key name. */
  status = ssh_private_key_set_scheme_from_key_name(private_key, key_type);

  if (status != SSH_CRYPTO_OK)
    {
      (*private_key->type->private_key_action_free)(context);
      ssh_free(private_key);
      return status;
    }

  /* Parse vararg list. */
  consumed[0] = '\000';
  while (TRUE)
    {
      va_start(ap, key_type);
      PROCESS(ap, consumed);

      format = va_arg(ap, SshPkFormat);
      strcat(consumed, "i");

      if (format == SSH_PKF_END)
        {
          va_end(ap);
          break;
        }

      /* If the vararg list contains scheme parameters, we need to
         set the scheme again. */
      if (format == SSH_PKF_SIGN || format == SSH_PKF_ENCRYPT ||
          format == SSH_PKF_DH)
        {
          name = va_arg(ap, const char *);
          strcat(consumed, "p");
          status = ssh_private_key_set_scheme(private_key, format, name);

          if (status != SSH_CRYPTO_OK)
            {
              (*private_key->type->private_key_action_free)(context);
              ssh_free(private_key);
              va_end(ap);
              return status;
            }

          va_end(ap);
          continue;
        }

      /* Search name from command lists. */
      action = ssh_pk_find_action(private_key->type->action_list,
                                  format, SSH_PK_ACTION_FLAG_PRIVATE_KEY);
      if (!action)
        {
          (*private_key->type->private_key_action_free)(context);
          ssh_free(private_key);
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      /* Supported only scheme selection and special operations. */
      switch (action->flags & SSH_PK_ACTION_FLAG_GET_PUT)
        {
        case SSH_PK_ACTION_FLAG_GET_PUT:
          r = (*action->action_put)(context, ap, NULL, format);
          if (r == NULL ||
              (sizeof(consumed) - strlen(consumed) - 1) <= strlen(r))
            {
              (*private_key->type->private_key_action_free)(context);
              ssh_free(private_key);
              va_end(ap);
              return SSH_CRYPTO_INTERNAL_ERROR;
            }
          else
            strcat(consumed, r);
          break;

        default:
          SSH_NOTREACHED;
          break;
        }

      va_end(ap);
    }

  /* Make the key and remove context. */
  status =
    (*private_key->type->private_key_action_define)(context,
                                                    &private_key->context);

  (*private_key->type->private_key_action_free)(context);

  /* Quit unhappily. */
  if (status != SSH_CRYPTO_OK)
    {
      ssh_free(private_key);
      return status;
    }

  /* Set the address of the private key to the key context. */
  if (private_key->type->set_key_pointer_to_context)
    {
      status = (*private_key->type->set_key_pointer_to_context)(private_key,
                                                                private_key->
                                                                context);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(private_key);
          return status;
        }
    }

  /* Quit happily. */
  *key_ret = private_key;

  return SSH_CRYPTO_OK;
}
#endif /* DEFINE */
