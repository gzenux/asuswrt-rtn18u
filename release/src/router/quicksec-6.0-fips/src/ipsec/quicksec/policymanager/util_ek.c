/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Handling private and public keys with the externalkey module.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmEk"

#ifdef SSHDIST_EXTERNALKEY

/************************** Static help functions ***************************/

/* Remove the key `key' from the externalkey key storage and free all
   resources the key has allocated.  The key `key' must be deleted and
   it must not have any references left.  The key `key' must not be
   used after this. */
static void
ssh_pm_ek_destroy(SshPm pm, SshPmEk key)
{
  SshUInt32 i;

  SSH_ASSERT(key->deleted);
  SSH_ASSERT(key->refcount == 0);

  ssh_free(key->keypath);
  if (key->private_key)
    {
      ssh_private_key_free(key->private_key);

      /* Update key statistics. */
      if (key->rsa_key)
        {
          if (key->public_key)
            {
              SSH_ASSERT(pm->externalkey_num_rsa > 0);
              pm->externalkey_num_rsa--;
            }
        }
      else if (key->dsa_key)
        {
          if (key->public_key)
            {
              SSH_ASSERT(pm->externalkey_num_dss > 0);
              pm->externalkey_num_dss--;
            }
        }
#ifdef SSHDIST_CRYPT_ECP
      else if (key->ecdsa_key)
        {
          if (key->public_key)
            {
              SSH_ASSERT(pm->externalkey_num_ecdsa > 0);
              pm->externalkey_num_ecdsa--;
            }
        }
#endif /* SSHDIST_CRYPT_ECP */
    }

  if (key->accel_private_key)
    {
      ssh_private_key_free(key->accel_private_key);
    }

  if (key->public_key)
    {
      ssh_pm_auth_domain_discard_public_key_from_all(pm, key->public_key);

      ssh_public_key_free(key->public_key);
    }

  if (key->ber_cert)
    ssh_free(key->ber_cert);

  for (i = 0; i < key->num_ids; i++)
    ssh_pm_ikev2_payload_id_free(key->ids[i]);
  ssh_free(key->ids);

  ssh_free(key);
}


/***************** ADT methods for Externalkey key storage ******************/

static SshUInt32
ssh_pm_ek_hash(void *ptr, void *ctx)
{
  SshPmEk ek = (SshPmEk) ptr;
  SshUInt32 hash = 0;
  int i;

  for (i = 0; ek->keypath[i]; i++)
    hash = ((hash << 5) ^ (unsigned char) ek->keypath[i]
            ^ (hash >> 16) ^ (hash >> 7));

  return hash;
}


static int
ssh_pm_ek_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshPmEk ek1 = (SshPmEk) ptr1;
  SshPmEk ek2 = (SshPmEk) ptr2;

  return strcmp(ek1->keypath, ek2->keypath);
}


static void
ssh_pm_ek_destroy_key(void *ptr, void *ctx)
{
  SshPm pm = (SshPm) ctx;
  SshPmEk ek = (SshPmEk) ptr;

  SSH_ASSERT(ek->refcount == 0);
  ek->deleted = 1;
  ssh_pm_ek_destroy(pm, ek);
}


/******************** Public functions for externalkeys *********************/

Boolean
ssh_pm_ek_init(SshPm pm)
{
  SSH_ASSERT(pm->externalkey_keys == NULL);

  pm->externalkey_keys
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshPmEkStruct, adt_header),

                             SSH_ADT_HASH,      ssh_pm_ek_hash,
                             SSH_ADT_COMPARE,   ssh_pm_ek_compare,
                             SSH_ADT_DESTROY,   ssh_pm_ek_destroy_key,
                             SSH_ADT_CONTEXT,   pm,

                             SSH_ADT_ARGS_END);
  if (pm->externalkey_keys == NULL)
    return FALSE;

  return TRUE;
}


void
ssh_pm_ek_uninit(SshPm pm)
{
  if (pm->externalkey_keys)
    {
      ssh_adt_destroy(pm->externalkey_keys);
      pm->externalkey_keys = NULL;
    }
}


void
ssh_pm_ek_notify(SshEkEvent event,
                 const char *keypath,
                 const char *label,
                 SshEkUsageFlags flags,
                 void *context)
{
  SshPm pm = (SshPm) context;
  SshPmEkStruct ek_struct;
  SshPmEk ek;
  SshADTHandle h;

  switch (event)
    {
    case SSH_EK_EVENT_TOKEN_INSERTED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_EK_EVENT_TOKEN_INSERTED: label=%s",
                                   label));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "External key token inserted");

      break;

    case SSH_EK_EVENT_TOKEN_REMOVED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_EK_EVENT_TOKEN_REMOVED: label=%s",
                                   label));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "External key token removed");

      break;
    case SSH_EK_EVENT_TOKEN_REMOVE_DETECTED:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SSH_EK_EVENT_TOKEN_REMOVED_DETECTED: label=%s",
                 label));
      break;

    case SSH_EK_EVENT_KEY_AVAILABLE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SSH_EK_EVENT_KEY_AVAILABLE: "
                 "label=%s, keypath=%s, flags=0x%lx",
                 label, keypath,
                 (unsigned long) flags));


      /* Do we already know this key? */
      ek_struct.keypath = (char *) keypath;
      h = ssh_adt_get_handle_to_equal(pm->externalkey_keys, &ek_struct);
      if (h == SSH_ADT_INVALID)
        {
          /* No.  Let's add it to our key storage. */
          ek = ssh_calloc(1, sizeof(*ek));
          if (ek == NULL)
            {
            error:
              SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for key"));
              break;
            }

          ek->keypath = ssh_strdup(keypath);
          if (ek->keypath == NULL)
            {
              ssh_free(ek);
              goto error;
            }

          ek->key_id = pm->next_ek_key_id++;
          ek->flags = flags;

          ek->ber_cert = NULL;
          ek->ber_cert_len = 0;

          ssh_adt_insert(pm->externalkey_keys, ek);
        }
      else
        {
          /* Yes.  Let's look it up. */
          ek = ssh_adt_get(pm->externalkey_keys, h);

          /* Mark the key as undeleted. */
          ek->deleted = 0;

          /* Retry to fetch the private key if the previous operation
             failed. */
          if (ek->key_fetched && ek->private_key == NULL)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Retrying to fetch the private key"));
              ek->key_fetched = 0;
            }
        }

      /* Signal our externalkey thread that there is a new key. */
      pm->ek_key_change = 1;
      ssh_fsm_condition_signal(&pm->fsm, &pm->ek_thread_cond);
      break;

    case SSH_EK_EVENT_KEY_UNAVAILABLE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SSH_EK_EVENT_KEY_UNAVAILABLE: label=%s, keypath=%s",
                 label, keypath));

      /* Do we know this key? */
      ek_struct.keypath = (char *) keypath;
      h = ssh_adt_get_handle_to_equal(pm->externalkey_keys, &ek_struct);
      if (h == SSH_ADT_INVALID)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Unknown key"));
        }
      else
        {
          ek = ssh_adt_get(pm->externalkey_keys, h);

          /* Mark the key deleted. */
          ek->deleted = 1;

          /* Are there any references for the key? */
          if (ek->refcount == 0)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying removed key"));
              ssh_adt_detach_object(pm->externalkey_keys, ek);
              ssh_pm_ek_destroy(pm, ek);
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Key has references: not deleting it yet"));
              /* The key will be deleted when the last references goes
                 away. */
            }
        }
      break;

    case SSH_EK_EVENT_PROVIDER_FAILURE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SSH_EK_EVENT_PROVIDER_FAILURE: label=%s, keypath=%s",
                 label, keypath));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "External key provider unavailable");
      break;

    case SSH_EK_EVENT_TOKEN_SCANNED:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_EK_EVENT_TOKEN_SCANNED: label=%s",
                                   label));
      break;

    case SSH_EK_EVENT_PROVIDER_ENABLED:



      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SSH_EK_EVENT_PROVIDER_ENABLED: label=%s, keypath=%s",
                 label, keypath));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "External key provider enabled");
      break;

    case SSH_EK_EVENT_PROVIDER_DISABLED:



      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SSH_EK_EVENT_PROVIDER_DISABLED: label=%s, keypath=%s",
                 label, keypath));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "External key provider disabled");
      break;

    case SSH_EK_EVENT_NONE:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_EK_EVENT_NONE: label=%s, keypath=%s",
                                   label, keypath));
      break;
    }

  /* Call the user-supplied notification callback. */
  if (pm->ek_user_notify_cb)
    (*pm->ek_user_notify_cb)(event, keypath, label, flags,
                             pm->ek_user_notify_cb_context);
}


SshPmEk
ssh_pm_ek_get_next(SshPm pm, SshPmAuthMethod key_selector, SshUInt32 *index)
{
  SshADTHandle h;
  SshPmEk smallest = NULL;
  SshUInt32 smallest_idx = ~(SshUInt32) 0;

  for (h = ssh_adt_enumerate_start(pm->externalkey_keys);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->externalkey_keys, h))
    {
      SshPmEk ek = ssh_adt_get(pm->externalkey_keys, h);

      /* Check type selector. */
      switch (key_selector)
        {
        case SSH_PM_AUTH_RSA:
          if (!ek->rsa_key)
            continue;
          break;

        case SSH_PM_AUTH_DSA:
          if (!ek->dsa_key)
            continue;
          break;

#ifdef SSHDIST_CRYPT_ECP
          case SSH_PM_AUTH_ECP_DSA:
          if (!ek->ecdsa_key)
            continue;
          break;
#endif /* SSHDIST_CRYPT_ECP */
        default:
          SSH_NOTREACHED;
          break;
        }

      if (ek->key_fetched && ek->private_key && ek->public_key && ek->num_ids
          && ek->key_id > *index && ek->key_id < smallest_idx)
        {
          /* Found a better estimate. */
          smallest = ek;
          smallest_idx = ek->key_id;
        }
    }

  if (smallest)
    {
      smallest->refcount++;
      *index = smallest_idx;
    }

  return smallest;
}

SshPmEk
ssh_pm_ek_get_by_identity(SshPm pm, SshIkev2PayloadID id)
{
  SshADTHandle h;
  SshPmEk ek = NULL;
  SshUInt32 i;

  /* Lookup a key using the IKE identity . */
  for (h = ssh_adt_enumerate_start(pm->externalkey_keys);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->externalkey_keys, h))
    {
      SshPmEk key = ssh_adt_get(pm->externalkey_keys, h);

      if (!key->key_fetched || !key->private_key || !key->public_key)
        continue;

      /* See if 'id' matches any of the identities in the external key */
      for (i = 0; i < key->num_ids; i++)
        if (ssh_pm_ikev2_id_compare(key->ids[i], id))
          {
            /* Found a match. */
            ek = key;
            break;
          }
    }

  /* Add a reference to the key. */
  if (ek)
    ek->refcount++;

  return ek;
}

SshPmEk
ssh_pm_ek_get_by_cert(SshPm pm, SshCMCertificate cert)
{
  SshX509Certificate x509_cert;
  unsigned char *keyhash;
  size_t keyhash_len;
  SshADTHandle h;
  SshPmEk ek = NULL;

  /* Get public key from the certificate. */
  if (ssh_cm_cert_get_x509(cert, &x509_cert) != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Getting X.509 certificate from CM certificate failed"));
      return NULL;
    }

  if ((keyhash =
       ssh_x509_cert_compute_key_identifier(x509_cert, "md5", &keyhash_len))
      != NULL)
    {
      /* Lookup a key using the public key hash. */
      for (h = ssh_adt_enumerate_start(pm->externalkey_keys);
           h != SSH_ADT_INVALID;
           h = ssh_adt_enumerate_next(pm->externalkey_keys, h))
        {
          SshPmEk key = ssh_adt_get(pm->externalkey_keys, h);

          if (key->key_fetched &&
              key->private_key && key->public_key
              && !memcmp(keyhash, key->key_hash, sizeof(key->key_hash)))
            {
              /* Found a match. */
              ek = key;
              break;
            }
        }
      ssh_free(keyhash);
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Getting public key hash from X.509 certificate failed"));
    }

  /* Cleanup. */

  ssh_x509_cert_free(x509_cert);

  if (ek)
    ek->refcount++;

  return ek;
}


Boolean
ssh_pm_ek_has_next(SshPm pm, SshPmAuthMethod key_selector, SshUInt32 index)
{
  SshPmEk key = ssh_pm_ek_get_next(pm, key_selector, &index);

  if (key)
    {
      ssh_pm_ek_unref(pm, key);
      return TRUE;
    }

  return FALSE;
}


SshPmEk
ssh_pm_ek_dup(SshPmEk key)
{
  if (key)
    key->refcount++;

  return key;
}


void
ssh_pm_ek_unref(SshPm pm, SshPmEk key)
{
  if (key == NULL)
    return;

  SSH_ASSERT(key->refcount > 0);
  key->refcount--;

  if (key->refcount == 0 && key->deleted)
    {
      /* The key is deleted and we had the last reference to it.
         Let's delete the key. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying removed key"));
      ssh_adt_detach_object(pm->externalkey_keys, key);
      ssh_pm_ek_destroy(pm, key);
    }
}

Boolean
ssh_pm_ek_refresh_certificates(SshPm pm, SshPmAuthDomain ad)
{
  SshPmEk ek;
  SshADTHandle h;
  Boolean success = TRUE;

  for (h = ssh_adt_enumerate_start(pm->externalkey_keys);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->externalkey_keys, h))
    {
      ek = ssh_adt_get(pm->externalkey_keys, h);

      /* All providers might not have certificates installed */
      if (ek->ber_cert_len == 0)
        continue;

      if (!ssh_pm_auth_domain_add_cert(pm,
                                       ad,
                                       ek->ber_cert,
                                       ek->ber_cert_len))
        {
          success = FALSE;
          break;
        }

    }

  return success;
}
#endif /* SSHDIST_EXTERNALKEY */
