/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshmalloc.h"
#include "sshstream.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshTlsTempkey"

static void regeneration_callback(void *ctx);

static void delete_tempkey(SshTlsTemporaryKey key)
{
  SSH_ASSERT(key->old_private_key == NULL);
  SSH_DEBUG(6, ("Actually deleting a TLS temporary key object."));

  ssh_cancel_timeouts(regeneration_callback, key);

  if (key->public_key != NULL)
    ssh_public_key_free(key->public_key);
  if (key->private_key != NULL)
    ssh_private_key_free(key->private_key);

  ssh_free(key);
}

static void kill_if_unreferenced(SshTlsTemporaryKey key)
{
  SSH_ASSERT(key->deleted);
  if (key->locks == 0)
    delete_tempkey(key);
}

static void regenerate(SshTlsTemporaryKey key)
{
  SshCryptoStatus status;

  SSH_ASSERT(key->old_private_key_locks == 0);
  SSH_ASSERT(key->old_private_key == NULL);

  /* If the current key has locks, remember the private key to
     delete it later. Otherwise delete it immediately. */
  if (key->private_key_locks > 0)
    {
      key->old_private_key_locks = key->private_key_locks;
      key->old_private_key = key->private_key;
    }
  else
    {
      if (key->private_key != NULL)
        ssh_private_key_free(key->private_key);
    }

  /* Free the old public key (if it exists). */
  if (key->public_key != NULL)
    {
      ssh_public_key_free(key->public_key);
      key->public_key = NULL;
    }

  SSH_DEBUG(6, ("Regenerating the temporary TLS asymmetric key."));

  /* Generate a new key. */
  if ((status =
       ssh_private_key_generate(&(key->private_key),
                                "if-modn{encrypt{rsa-pkcs1-none}}",
                                SSH_PKF_SIZE,
                                (unsigned int)512,
                                SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      key->private_key = NULL;
      return;
    }

  if ((status = ssh_private_key_derive_public_key(key->private_key,
                                                  &key->public_key))
      != SSH_CRYPTO_OK)
    {
      ssh_private_key_free(key->private_key);
      key->private_key = NULL;
    }

  /* No locks yet. */
  key->private_key_locks = 0;
}

static void regeneration_callback(void *ctx)
{
  SshTlsTemporaryKey key = (SshTlsTemporaryKey)ctx;

  ssh_xregister_timeout(key->regeneration_interval, 0L,
                       regeneration_callback, ctx);

  if (key->used)
    regenerate(key);
}

SshTlsTemporaryKey ssh_tls_create_temporary_key(int life_span)
{
  SshTlsTemporaryKey key;

  if ((key = ssh_calloc(1, sizeof(*key))) != NULL)
    {
      key->private_key = NULL;
      key->public_key = NULL;
      key->old_private_key = NULL;
      key->private_key_locks = key->old_private_key_locks = key->locks = 0;
      key->regeneration_interval = life_span;
      key->deleted = FALSE;

      SSH_ASSERT(life_span > 0);

      /* Create an initial key. */
      key->used = TRUE;             /* Otherwise the trick does not work. */
      regeneration_callback(key);
    }
  return key;
}

void ssh_tls_lock_temporary_key(SshTlsTemporaryKey key)
{
  SSH_ASSERT(!(key->deleted));
  key->locks++;
}

void ssh_tls_release_temporary_key(SshTlsTemporaryKey key)
{
  key->locks--;
  SSH_ASSERT(key->locks >= 0);
  if (key->deleted) kill_if_unreferenced(key);
}

void ssh_tls_get_temporary_keys(SshTlsTemporaryKey key,
                                SshPublicKey *publicp,
                                SshPrivateKey *privatep)
{
  SSH_ASSERT(key->public_key != NULL);
  SSH_ASSERT(key->private_key != NULL);
  *publicp = key->public_key;
  *privatep = key->private_key;
  key->private_key_locks++;
}

void ssh_tls_release_private_key(SshTlsTemporaryKey key,
                                 SshPrivateKey private_key)
{
  if (key->private_key == private_key)
    {
      key->private_key_locks--;
      SSH_ASSERT(key->private_key_locks >= 0);
    }
  else
    {
      SSH_ASSERT(key->old_private_key == private_key);
      key->old_private_key_locks--;
      SSH_ASSERT(key->old_private_key_locks >= 0);
      if (key->old_private_key_locks == 0)
        {
          ssh_private_key_free(key->old_private_key);
          key->old_private_key = NULL;
        }
    }
  if (key->deleted) kill_if_unreferenced(key);
}

void ssh_tls_destroy_temporary_key(SshTlsTemporaryKey key)
{
  SSH_ASSERT(!key->deleted);
  SSH_DEBUG(6, ("Scheduling a TLS temporary key object for deletion."));
  key->deleted = TRUE;
  kill_if_unreferenced(key);
}
