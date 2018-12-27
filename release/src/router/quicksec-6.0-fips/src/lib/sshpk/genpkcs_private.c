/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface code for public key cryptosystems.
*/

#include "sshincludes.h"
#include "sshdsprintf.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshpk_i.h"
#ifdef SSHDIST_CRYPT_SELF_TESTS
#include "crypto_tests.h"
#endif /* SSHDIST_CRYPT_SELF_TESTS */
#include "sshrgf.h"

#define SSH_DEBUG_MODULE "SshCryptoGenpkcsPrivate"

void ssh_rgf_free_cb(Boolean aborted, void *context);

const char * ssh_private_key_find_default_scheme(SshPrivateKeyObject key,
                                                 SshPkFormat format)
{
  const SshPkType *type = key->type;

  if (type == NULL)
    return NULL;

  if (format == SSH_PKF_SIGN && type->signature_list)
      return type->signature_list[0].name;

  if (format == SSH_PKF_ENCRYPT && type->encryption_list)
    return type->encryption_list[0].name;

  if (format == SSH_PKF_DH && type->diffie_hellman_list)
    return type->diffie_hellman_list[0].name;

  return NULL;

}

SshCryptoStatus
ssh_private_key_set_scheme(SshPrivateKeyObject key,
                           SshPkFormat format, const char *scheme)
{
  void *scheme_ptr;

  /* Get the scheme pointer. */
  scheme_ptr = ssh_pk_find_scheme(key->type, format, scheme);

  if (scheme && !scheme_ptr)
    return SSH_CRYPTO_SCHEME_UNKNOWN;

  /* Set the corresponding scheme. */
  switch (format)
    {
    case SSH_PKF_SIGN:
      key->signature = scheme_ptr;
      break;
    case SSH_PKF_ENCRYPT:
      key->encryption = scheme_ptr;
      break;
    case SSH_PKF_DH:
      key->diffie_hellman = scheme_ptr;
      break;
    default:
      return SSH_CRYPTO_SCHEME_UNKNOWN;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Set the scheme of the private key from a key_name. This is called
   when generating or importing private keys. */
SshCryptoStatus
ssh_private_key_set_scheme_from_key_name(SshPrivateKeyObject key,
                                         const char *key_name)
{
  SshCryptoStatus status;
  char *scheme_name;

  if ((scheme_name = ssh_pk_get_scheme_name(key_name, "sign")) != NULL)
    {
      status = ssh_private_key_set_scheme(key, SSH_PKF_SIGN, scheme_name);
      ssh_free(scheme_name);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  if ((scheme_name = ssh_pk_get_scheme_name(key_name, "encrypt")) != NULL)
    {
      status = ssh_private_key_set_scheme(key, SSH_PKF_ENCRYPT, scheme_name);
      ssh_free(scheme_name);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  if ((scheme_name = ssh_pk_get_scheme_name(key_name, "dh")) != NULL)
    {
      status = ssh_private_key_set_scheme(key, SSH_PKF_DH, scheme_name);
      ssh_free(scheme_name);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  return SSH_CRYPTO_OK;
}

/* Select new scheme to be used. That is assuming key supports many
   different schemes and/or padding types this can be of some
   use. Note however, that the key stays the same and some method
   assume keys to be of certain form. Such an example is DSA which by
   standard needs to have parameters of certain form, but this
   function could easily switch to DSA with key that is not of that
   form. Nevertheless I feel that such problems do not make switching
   to other methods unusable (even DSA would work with different
   parameters, although would not conform to the digital signature
   standard). */

SshCryptoStatus
ssh_private_key_select_scheme(SshPrivateKey handle, ...)
{
  SshPkFormat format;
  va_list ap;
  const char *scheme;
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (key->type == NULL)
    return SSH_CRYPTO_KEY_UNINITIALIZED;

  va_start(ap, handle);

  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      scheme = va_arg(ap, const char *);
      SSH_TRACE(10, ("select scheme: key %p: type: %d scheme:, %s",
                     key, format, scheme));
      if (ssh_private_key_set_scheme(key, format, scheme) != SSH_CRYPTO_OK)
        {
          va_end(ap);
          return SSH_CRYPTO_SCHEME_UNKNOWN;
        }
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}

/* Routines for getting scheme names from private keys and public
   keys.  No other information is reasonable to expect to be gotten
   from schemes, although one could think of getting descriptions
   etc... */
SshCryptoStatus
ssh_private_key_get_scheme_name(SshPrivateKeyObject key,
                                SshPkFormat format,
                                const char **name)
{
  switch (format)
    {
    case SSH_PKF_SIGN:
      if (key->signature)
        *name = key->signature->name;
      else
        *name = NULL;
      break;
    case SSH_PKF_ENCRYPT:
      if (key->encryption)
        *name = key->encryption->name;
      else
        *name = NULL;
      break;
    case SSH_PKF_DH:
      if (key->diffie_hellman)
        *name = key->diffie_hellman->name;
      else
        *name = NULL;
      break;
    default:
      return SSH_CRYPTO_SCHEME_UNKNOWN;
      break;
    }
  return SSH_CRYPTO_OK;
}

/* Generate the full name of a particular private key. Inefficient
   (and ugly), but anyway this function does not need to be fast. */
char *
ssh_private_key_object_name(SshPrivateKeyObject key)
{
  unsigned char *buf, *tmp[4], *k;
  unsigned int i, j;

  /* If no schemes, just return the key type. */
  if (!key->signature && !key->encryption && !key->diffie_hellman)
    {
      ssh_dsprintf(&buf, "%s", key->type->name);
      return ssh_sstr(buf);
    }

  /* Generate the key type. */
  ssh_dsprintf(&buf, "%s{", key->type->name);

  for (i = 0; i < 4; i++)
    tmp[i] = NULL;

  /* Generate the scheme information. */
  i = j = 0;
  if (key->signature)
    ssh_dsprintf(&tmp[i++], "sign{%s}", key->signature->name);

  if (key->encryption)
    ssh_dsprintf(&tmp[i++], "encrypt{%s}", key->encryption->name);

  if (key->diffie_hellman)
    ssh_dsprintf(&tmp[i++], "dh{%s}", key->diffie_hellman->name);

  while (tmp[j])
    j++;

  if (j < i || buf == NULL)
    goto memory_fail;

  for (i = 0; i < j ; i++)
    {
      ssh_dsprintf(&k, "%s%s%s%s", buf, i ? "," : "", tmp[i],
                   i == (j - 1) ? "}": "" );

      ssh_free(buf);
      ssh_free(tmp[i]);
      tmp[i] = NULL;
      buf = k;

      if (k == NULL)
        goto memory_fail;
    }

  return (char *) k;

 memory_fail:
  for (i = 0; i < 4; i++)
    ssh_free(tmp[i]);
  ssh_free(buf);

  return NULL;
}

char *
ssh_private_key_name(SshPrivateKey handle)
{
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return NULL;

  return ssh_private_key_object_name(key);
}

SshCryptoStatus
ssh_private_key_precompute(SshPrivateKey handle)
{
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle);
  if (!key)
    return SSH_CRYPTO_HANDLE_INVALID;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (key->type->private_key_precompute)
    return (*key->type->private_key_precompute)(key->context);

  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_private_key_get_info(SshPrivateKey handle, ...)
{
  SshCryptoStatus status;
  const SshPkAction *action;
  SshPkFormat format;
  const char **name_ptr, *r;
  char consumed[128];
  va_list ap;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  consumed[0] = '\000';
  while (TRUE)
    {
      va_start(ap, handle);
      PROCESS(ap, consumed);

      format = va_arg(ap, SshPkFormat);
      strcat(consumed, "i");
      if (format == SSH_PKF_END)
        break;

      /* If looking for scheme information. */
      if (format == SSH_PKF_SIGN || format == SSH_PKF_ENCRYPT ||
          format == SSH_PKF_DH)
            {
              name_ptr = va_arg(ap, const char **);
              strcat(consumed, "p");

              status = ssh_private_key_get_scheme_name(key, format, name_ptr);
              if (status != SSH_CRYPTO_OK)
                {
                  va_end(ap);
                  return status;
                }
              va_end(ap);
              continue;
            }

      /* Seek for the action. */
      action = ssh_pk_find_action(key->type->action_list,
                                  format, SSH_PK_ACTION_FLAG_PRIVATE_KEY);

      if (!action)
        {
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }

      switch (action->flags & (SSH_PK_ACTION_FLAG_GET_PUT |
                               SSH_PK_ACTION_FLAG_KEY_TYPE))
        {
        case SSH_PK_ACTION_FLAG_KEY_TYPE:
          name_ptr = va_arg(ap, const char **);
          strcat(consumed, "p");
          *name_ptr = strchr(key->type->name, ':');
          if (*name_ptr)
            (*name_ptr)++;
          else
            *name_ptr = key->type->name; /* ssh_private_key_name(key); */
          break;

        case SSH_PK_ACTION_FLAG_GET_PUT:
          if (action->action_get == NULL_FNPTR)
            {
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED;
            }

          r = (*action->action_get)(key->context, ap, NULL, format);
          if (r == NULL ||
              (sizeof(consumed) - strlen(consumed) - 1) <= strlen(r))
            {
              va_end(ap);
              return SSH_CRYPTO_INTERNAL_ERROR;
            }
          else
            {
              strcat(consumed, r);
            }
          break;

        default:
          ssh_fatal("ssh_private_key_get_info: internal error.");
          break;
        }

      va_end(ap);
    }

  va_end(ap);
  return SSH_CRYPTO_OK;
}


/* Private key routines copy and free. */
SshCryptoStatus
ssh_private_key_copy(SshPrivateKey handle_src, SshPrivateKey *key_dest)
{
  SshCryptoStatus status;
  SshPrivateKeyObject created, key_src;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key_src = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle_src)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (key_src->type->private_key_copy == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((created = ssh_malloc(sizeof(*created))) != NULL)
    {
      memcpy(created, key_src, sizeof(*created));
      status =
        (*key_src->type->private_key_copy)(key_src->context,
                                           &created->context);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_free(created);
          return status;
        }

      /* Set the address of the copied private key into its context. */
      if (key_src->type->set_key_pointer_to_context)
        {
          status =
            (*key_src->type->set_key_pointer_to_context)(created,
                                                         created->context);

          if (status != SSH_CRYPTO_OK)
            {
              ssh_private_key_object_free(created);
              return status;
            }
        }

      if (!ssh_crypto_library_object_use(created,
                                         SSH_CRYPTO_OBJECT_TYPE_PRIVATE_KEY))
        {
          ssh_private_key_object_free(created);
          *key_dest = NULL;
          return SSH_CRYPTO_NO_MEMORY;
        }

      *key_dest = SSH_CRYPTO_PRIVATE_KEY_TO_HANDLE(created);
      return SSH_CRYPTO_OK;
    }
  else
    return SSH_CRYPTO_NO_MEMORY;
}

/* Allocate a private key structure. This performs only minimal
   instantiation. */
SshCryptoStatus
ssh_private_key_object_allocate(const char *type, SshPrivateKeyObject *key)
{
  SshPrivateKeyObject private_key;
  char *name;
  int i;

  /* Get the key type (i.e. strip the scheme information from key_type). */
  if (!(name = ssh_pk_get_key_type(type)))
    return SSH_CRYPTO_NO_MEMORY;

  /* Find correct key type. */
  for (i = 0, private_key = NULL;
       ssh_pk_type_slots[i] != NULL && ssh_pk_type_slots[i]->name;
       i++)
    {
      if (strcmp(ssh_pk_type_slots[i]->name, name) == 0)
        {
          /* Initialize private key. */
          if ((private_key = ssh_calloc(1, sizeof(*private_key))) != NULL)
            {
              private_key->type = ssh_pk_type_slots[i];
              /*
              private_key->signature = NULL;
              private_key->encryption = NULL;
              private_key->diffie_hellman = NULL;
              private_key->context = NULL;
              */
            }
          else
            {
              ssh_free(name);
              return SSH_CRYPTO_NO_MEMORY;
            }
          break;
        }
    }

  ssh_free(name);
  *key = private_key;

  if (private_key == NULL)
    return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  return SSH_CRYPTO_OK;
}

/* Release a private key structure. */
void
ssh_private_key_object_free(SshPrivateKeyObject key)
{
  if (key->type->private_key_free && key->context)
    (*key->type->private_key_free)(key->context);

  key->context = NULL;
  ssh_free(key);
}

void
ssh_private_key_free(SshPrivateKey handle)
{
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return;

  ssh_crypto_library_object_release(key);
  ssh_private_key_object_free(key);
}

SshCryptoStatus
ssh_private_key_derive_public_key_internal(SshPrivateKeyObject key,
                                           SshPublicKeyObject *public_ret)
{
  SshPublicKeyObject pub;
  void *pub_context;
  SshCryptoStatus status;

  if (key->type->private_key_derive_public_key == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  status = (*key->type->private_key_derive_public_key)(key->context,
                                                       &pub_context);

  if (status != SSH_CRYPTO_OK)
    return status;

  if ((pub = ssh_malloc(sizeof(*pub))) == NULL)
    {
      (*key->type->public_key_free)(pub_context);
      return SSH_CRYPTO_NO_MEMORY;
    }

  pub->context = pub_context;
  pub->type = key->type;

  /* Set up all schemes for compatibility. */
  pub->signature = key->signature;
  pub->encryption = key->encryption;
  pub->diffie_hellman = key->diffie_hellman;

  /* Set the address of the derived public key into its context. */
  if (pub->type->set_key_pointer_to_context)
    {
      status = (*pub->type->set_key_pointer_to_context)(pub, pub_context);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_public_key_object_free(pub);
          return status;
        }
    }

  *public_ret = pub;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_private_key_derive_public_key(SshPrivateKey handle,
                                  SshPublicKey *public_ret)
{
  SshCryptoStatus status;
  SshPublicKeyObject pub = NULL;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  status = ssh_private_key_derive_public_key_internal(key, &pub);

  if (status != SSH_CRYPTO_OK)
    return status;

#ifdef SSHDIST_CRYPT_SELF_TESTS
  /* We have now generated the public key. Test the consistency of the
     public/private key pair. The crypto library enters an error state
     on failure.

     This test is required by FIPS 140-2 4.9.2 "Conditional Tests" */
  status = ssh_crypto_test_pk_consistency(pub, key);

  if (status == SSH_CRYPTO_NO_MEMORY)
    {
      ssh_public_key_object_free(pub);
      *public_ret = NULL;
      return SSH_CRYPTO_NO_MEMORY;
    }
  else if (status != SSH_CRYPTO_OK)
    {
      ssh_public_key_object_free(pub);
      ssh_crypto_library_error(SSH_CRYPTO_ERROR_KEY_TEST_FAILURE);
      *public_ret = NULL;
      return SSH_CRYPTO_LIBRARY_ERROR;
    }
#endif /* SSHDIST_CRYPT_SELF_TESTS */

  if (!ssh_crypto_library_object_use(pub, SSH_CRYPTO_OBJECT_TYPE_PUBLIC_KEY))
    {
      ssh_public_key_object_free(pub);
      *public_ret = NULL;
      return SSH_CRYPTO_NO_MEMORY;
    }

  *public_ret = SSH_CRYPTO_PUBLIC_KEY_TO_HANDLE(pub);
  return SSH_CRYPTO_OK;
}


SshCryptoStatus
ssh_private_key_derive_signature_hash(SshPrivateKey handle, SshHash *hash_ret)
{
  SshRGF rgf;
  SshHash hash;
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (key->signature == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if ((rgf = ssh_rgf_allocate(key->signature->rgf_def)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  hash = ssh_rgf_derive_hash(rgf);
  ssh_rgf_free(rgf);

  *hash_ret = hash;
  return SSH_CRYPTO_OK;
}

size_t
ssh_private_key_object_max_signature_input_len(SshPrivateKeyObject key)
{
  SshRGF rgf;
  size_t len;

  if (key->signature == NULL)
    return 0;

  if (key->signature->private_key_max_signature_input_len == NULL_FNPTR)
    return 0;

  rgf = ssh_rgf_allocate(key->signature->rgf_def);
  if (rgf == NULL)
    return 0;

  len = (*key->signature->private_key_max_signature_input_len)(key->context,
                                                               rgf);
  ssh_rgf_free(rgf);
  return len;
}

size_t
ssh_private_key_max_signature_input_len(SshPrivateKey handle)
{
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return 0;

  return ssh_private_key_object_max_signature_input_len(key);
}

size_t
ssh_private_key_object_max_signature_output_len(SshPrivateKeyObject key)
{
  SshRGF rgf;
  size_t len;

  if (key->signature == NULL)
    return 0;

  if (key->signature->private_key_max_signature_output_len == NULL_FNPTR)
    return 0;

  rgf = ssh_rgf_allocate(key->signature->rgf_def);
  if (rgf == NULL)
    return 0;

  len = (*key->signature->private_key_max_signature_output_len)(key->context,
                                                                rgf);
  ssh_rgf_free(rgf);
  return len;
}

size_t
ssh_private_key_max_signature_output_len(SshPrivateKey handle)
{
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return 0;

  return ssh_private_key_object_max_signature_output_len(key);
}

/* Return the maximal lenght of bytes which may be decrypted with this
   private key. The result is queried from the corresponding private key
   cryptosystem package with a type-specific function. */

size_t
ssh_private_key_object_max_decrypt_input_len(SshPrivateKeyObject key)
{
  SshRGF rgf;
  size_t len;

  if (key->encryption == NULL)
    return 0;

  if (key->encryption->private_key_max_decrypt_input_len == NULL_FNPTR)
    return 0;

  rgf = ssh_rgf_allocate(key->encryption->rgf_def);
  if (rgf == NULL)
    return 0;

  len = (*key->encryption->private_key_max_decrypt_input_len)(key->context,
                                                             rgf);
  ssh_rgf_free(rgf);
  return len;
}

size_t
ssh_private_key_max_decrypt_input_len(SshPrivateKey handle)
{
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return 0;

  return ssh_private_key_object_max_decrypt_input_len(key);
}

/* Similar to the previous function except this will return the maximum
   output lenght with decryption. */

size_t
ssh_private_key_object_max_decrypt_output_len(SshPrivateKeyObject key)
{
  SshRGF rgf;
  size_t len;

  if (key->encryption == NULL)
    return 0;

  if (key->encryption->private_key_max_decrypt_output_len == NULL_FNPTR)
    return 0;

  rgf = ssh_rgf_allocate(key->encryption->rgf_def);
  if (rgf == NULL)
    return 0;

  len = (*key->encryption->private_key_max_decrypt_output_len)(key->context,
                                                               rgf);
  ssh_rgf_free(rgf);
  return len;
}

size_t
ssh_private_key_max_decrypt_output_len(SshPrivateKey handle)
{
  SshPrivateKeyObject key;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return 0;

  return ssh_private_key_object_max_decrypt_output_len(key);
}

/* Private key decrypt and encrypt */
SshCryptoStatus
ssh_private_key_object_decrypt(SshPrivateKeyObject key,
                               const unsigned char *ciphertext,
                               size_t ciphertext_len,
                               unsigned char *plaintext,
                               size_t buffer_len,
                               size_t *plaintext_length_return)
{
  SshRGF rgf;
  SshCryptoStatus status;

  if (key->encryption == NULL ||
      key->encryption->private_key_decrypt == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  rgf = ssh_rgf_allocate(key->encryption->rgf_def);
  if (rgf == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  status = (*key->encryption->private_key_decrypt)(key->context,
                                                   ciphertext,
                                                   ciphertext_len,
                                                   plaintext,
                                                   buffer_len,
                                                   plaintext_length_return,
                                                   rgf);

  ssh_rgf_free(rgf);
  return status;
}

SshCryptoStatus
ssh_private_key_decrypt(SshPrivateKey handle,
                        const unsigned char *ciphertext,
                        size_t ciphertext_len,
                        unsigned char *plaintext,
                        size_t buffer_len,
                        size_t *plaintext_length_return)
{
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return
    ssh_private_key_object_decrypt(key, ciphertext, ciphertext_len,
                                   plaintext, buffer_len,
                                   plaintext_length_return);
}

SshCryptoStatus
ssh_private_key_object_sign(SshPrivateKeyObject key,
                            const unsigned char *data,
                            size_t data_len,
                            unsigned char *signature,
                            size_t signature_len,
                            size_t *signature_length_return)
{
  SshRGF rgf;
  SshCryptoStatus status;

  if (key->signature == NULL ||
      key->signature->private_key_sign == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Key does not support signing operation"));
      return SSH_CRYPTO_UNSUPPORTED;
    }

  rgf = ssh_rgf_allocate(key->signature->rgf_def);
  if (rgf == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  if ((status = ssh_rgf_hash_update(rgf, data, data_len)) == SSH_CRYPTO_OK)
    {
      status = (*key->signature->private_key_sign)(key->context,
                                                   rgf,
                                                   signature, signature_len,
                                                   signature_length_return);
    }
  ssh_rgf_free(rgf);
  return status;
}

SshCryptoStatus
ssh_private_key_sign(SshPrivateKey handle,
                     const unsigned char *data,
                     size_t data_len,
                     unsigned char *signature,
                     size_t signature_len,
                     size_t *signature_length_return)
{
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return
    ssh_private_key_object_sign(key, data, data_len,
                                signature, signature_len,
                                signature_length_return);
}


SshCryptoStatus
ssh_private_key_object_sign_digest(SshPrivateKeyObject key,
                            const unsigned char *digest,
                            size_t digest_len,
                            unsigned char *signature,
                            size_t signature_len,
                            size_t *signature_length_return)
{
  SshRGF rgf;
  SshCryptoStatus status;

  if (key->signature == NULL ||
      key->signature->private_key_sign == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  rgf = ssh_rgf_allocate(key->signature->rgf_def);
  if (rgf == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  if ((status = ssh_rgf_hash_update_with_digest(rgf,
                                                digest, digest_len))
       == SSH_CRYPTO_OK)
    {
      status = (*key->signature->private_key_sign)(key->context,
                                                   rgf,
                                                   signature, signature_len,
                                                   signature_length_return);
    }
  ssh_rgf_free(rgf);
  return status;
}

SshCryptoStatus
ssh_private_key_sign_digest(SshPrivateKey handle,
                            const unsigned char *digest,
                            size_t digest_len,
                            unsigned char *signature,
                            size_t signature_len,
                            size_t *signature_length_return)
{
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  return
    ssh_private_key_object_sign_digest(key, digest, digest_len,
                                       signature, signature_len,
                                       signature_length_return);
}

/* Start asyncronous private key decryption operation. The library will call
   given callback when operation is done. Callback may be called immediately
   during this call. The function ssh_operation_abort function may be called to
   abort this operation before it finishes, in which case the callback is not
   called and the SshOperationHandle will be NULL. */
SshOperationHandle
ssh_private_key_decrypt_async(SshPrivateKey handle,
                              const unsigned char *ciphertext,
                              size_t ciphertext_length,
                              SshPrivateKeyDecryptCB callback,
                              void *context)
{
  unsigned char *plaintext;
  size_t return_length = 0, plaintext_length;
  SshOperationHandle op;
  SshCryptoStatus status;
  SshRGF rgf;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    {
      (*callback)(status, NULL, 0, context);
      return NULL;
    }

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    {
      (*callback)(SSH_CRYPTO_HANDLE_INVALID, NULL, 0, context);
      return NULL;
    }

  if (key->encryption && key->encryption->private_key_decrypt_async)
    {
      rgf = ssh_rgf_allocate(key->encryption->rgf_def);

      if (rgf == NULL)
        {
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, context);
          return NULL;
        }

      /* Asyncronous operation. */
      op = (*key->encryption->
            private_key_decrypt_async)(key->context,
                                       ciphertext, ciphertext_length,
                                       rgf,
                                       callback, context);

      /* The RGF Hash is freed when the handle is destroyed. */
      ssh_operation_attach_destructor(op, ssh_rgf_free_cb, rgf);
      return op;
    }

  plaintext_length = ssh_private_key_object_max_decrypt_output_len(key);
  if ((plaintext = ssh_malloc(plaintext_length)) != NULL)
    {
      status = ssh_private_key_object_decrypt(key,
                                              ciphertext, ciphertext_length,
                                              plaintext, plaintext_length,
                                              &return_length);
      (*callback)(status, plaintext, return_length, context);
      ssh_free(plaintext);
    }
  return NULL;
}

/* Start asyncronous private key signing operation. The library will
   call given callback when operation is done. Callback may be called
   immediately during this call. The function ssh_operation_abort
   function may be called to abort this operation before it finishes,
   in which case the callback is not called and the SshOperationHandle
   will be NULL. */
SshOperationHandle
ssh_private_key_sign_async(SshPrivateKey handle,
                           const unsigned char *data,
                           size_t data_length,
                           SshPrivateKeySignCB callback,
                           void *context)
{
  unsigned char *signature;
  size_t return_length = 0, signature_length;
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    {
      (*callback)(status, NULL, 0, context);
      return NULL;
    }

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    {
      (*callback)(SSH_CRYPTO_HANDLE_INVALID, NULL, 0, context);
      return NULL;
    }

  if (key->signature &&
      key->signature->private_key_sign_async != NULL_FNPTR)
    {
      SshRGF rgf;
      SshOperationHandle handle;

      rgf = ssh_rgf_allocate(key->signature->rgf_def);
      if (rgf == NULL)
        {
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, context);
          return NULL;
        }

      if ((status = ssh_rgf_hash_update(rgf, data, data_length))
          != SSH_CRYPTO_OK)
        {
          ssh_rgf_free(rgf);
          (*callback)(status, NULL, 0, context);
          return NULL;
        }

      /* Asyncronous operation. */
      handle = (*key->signature->
                private_key_sign_async)(key->context,
                                        rgf,
                                        callback, context);

      /* The RGF Hash is freed when the handle is destroyed. */
      ssh_operation_attach_destructor(handle, ssh_rgf_free_cb, rgf);
      return handle;
    }

  signature_length = ssh_private_key_object_max_signature_output_len(key);
  if ((signature = ssh_malloc(signature_length)) != NULL)
    {
      status = ssh_private_key_object_sign(key,
                                           data, data_length,
                                           signature, signature_length,
                                           &return_length);
      (*callback)(status, signature, return_length, context);
      ssh_free(signature);
    }
  return NULL;
}

/* As ssh_private_key_sign but here one can give the hash digest directly. The
   hash which to use can be requested using
   ssh_private_key_derive_signature_hash function. */

SshOperationHandle
ssh_private_key_sign_digest_async(SshPrivateKey handle,
                                  const unsigned char *digest,
                                  size_t digest_length,
                                  SshPrivateKeySignCB callback,
                                  void *context)
{
  unsigned char *signature;
  size_t return_length = 0, signature_length;
  SshCryptoStatus status;
  SshPrivateKeyObject key;

  if (!ssh_crypto_library_object_check_use(&status))
    {
      (*callback)(status, NULL, 0, context);
      return NULL;
    }

  if (!(key = SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(handle)))
    {
      (*callback)(SSH_CRYPTO_HANDLE_INVALID, NULL, 0, context);
      return NULL;
    }

  if (key->signature &&
      key->signature->private_key_sign_async != NULL_FNPTR)
    {
      SshRGF rgf;
      SshOperationHandle op_handle;

      rgf = ssh_rgf_allocate(key->signature->rgf_def);
      if (rgf == NULL)
        {
          (*callback)(SSH_CRYPTO_NO_MEMORY, NULL, 0, context);
          return NULL;
        }

      if ((status = ssh_rgf_hash_update_with_digest(rgf,
                                                    digest, digest_length))
          != SSH_CRYPTO_OK)
        {
          (*callback)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, context);
          ssh_rgf_free(rgf);
          return NULL;
        }

      /* Asyncronous operation. */
      op_handle = (*key->signature->
                   private_key_sign_async)(key->context,
                                           rgf,
                                           callback, context);

      /* The RGF Hash is freed when the handle is destroyed. */
      ssh_operation_attach_destructor(op_handle, ssh_rgf_free_cb, rgf);
      return op_handle;
    }

  signature_length = ssh_private_key_object_max_signature_output_len(key);
  if ((signature = ssh_malloc(signature_length)) != NULL)
    {
      status =
        ssh_private_key_object_sign_digest(key,
                                           digest, digest_length,
                                           signature, signature_length,
                                           &return_length);
      (*callback)(status, signature, return_length, context);
      ssh_free(signature);
    }
  return NULL;
}
