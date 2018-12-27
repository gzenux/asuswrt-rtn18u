/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An ID - pre-shared key mapping for IKE pre-shared
   key retrieval.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkePsk"

/************************** Types and definitions ***************************/

/* An ID - key pair. */
struct SshPmIkePskItemRec
{
  SshADTBagHeaderStruct adt_header;

  /* The remote IKE ID information. */
  SshIkev2PayloadID id;

  /* The Pre-shared key. */
  unsigned char *secret;
  size_t secret_len;

  /* Flags */
  SshUInt32 flags;
};

typedef struct SshPmIkePskItemRec SshPmIkePskItemStruct;
typedef struct SshPmIkePskItemRec *SshPmIkePskItem;

/* Private flag values for bookkeeping */
#define SSH_IPM_PSK_FLAG_SEEN 0x00010000
#define SSH_IPM_PSK_FLAG_NEW  0x00020000

/********* Creating the global preshared key container *********************/

static SshUInt32
pm_ike_psk_hash(void *ptr, void *ctx)
{
  SshPmIkePskItem item = (SshPmIkePskItem) ptr;
  SshIkev2PayloadID id = item->id;
  SshUInt32 hash, i;

  for (i = 0, hash = 0; i < id->id_data_size; i++)
    hash = 257 * hash + id->id_data[i] + 3 * (hash >> 23);
  return hash;
}

static int
pm_ike_psk_compare(void *ptr1, void *ptr2, void *ctx)
{
  SshPmIkePskItem item1 = (SshPmIkePskItem) ptr1;
  SshPmIkePskItem item2 = (SshPmIkePskItem) ptr2;

  if (item1->id->id_type != item2->id->id_type)
    return -1;

  if (item1->id->id_data_size != item2->id->id_data_size)
    return -1;

  if (memcmp(item1->id->id_data, item2->id->id_data, item2->id->id_data_size))
    return -1;

  return 0;
}

static void
pm_ike_psk_destroy(void *ptr, void *ctx)
{
  SshPmIkePskItem item = (SshPmIkePskItem) ptr;

  ssh_pm_ikev2_payload_id_free(item->id);
  ssh_free(item->secret);
  ssh_free(item);
}


/* Create an IKE mode ID - secret mapping object. */
Boolean ssh_pm_ike_preshared_keys_create(SshPm pm, SshPmAuthDomain ad)
{
  ad->ike_preshared_keys
    = ssh_adt_create_generic(SSH_ADT_BAG,

                             SSH_ADT_HEADER,
                             SSH_ADT_OFFSET_OF(SshPmIkePskItemStruct,
                                               adt_header),

                             SSH_ADT_HASH,      pm_ike_psk_hash,
                             SSH_ADT_COMPARE,   pm_ike_psk_compare,
                             SSH_ADT_DESTROY,   pm_ike_psk_destroy,
                             SSH_ADT_CONTEXT,   pm,

                             SSH_ADT_ARGS_END);

  if (ad->ike_preshared_keys == NULL)
    return FALSE;

  return TRUE;
}

void
ssh_pm_ike_preshared_keys_destroy(SshPmAuthDomain ad)
{
  if (ad->ike_preshared_keys)
    {
      ssh_adt_destroy(ad->ike_preshared_keys);
      ad->ike_preshared_keys = NULL;
    }
  return;
}

static SshPmIkePskItem
pm_ike_preshared_keys_get(SshPmAuthDomain ad, SshIkev2PayloadID remote)
{
  SshPmIkePskItemStruct item_probe;
  SshADTHandle h;

  memset(&item_probe, 0, sizeof(item_probe));
  item_probe.id = remote;

  h = ssh_adt_get_handle_to_equal(ad->ike_preshared_keys, &item_probe);
  if (h == SSH_ADT_INVALID)
      return NULL;
  return ssh_adt_get(ad->ike_preshared_keys, h);
}

unsigned char *
ssh_pm_ike_preshared_keys_get_secret(SshPmAuthDomain ad,
                                     SshIkev2PayloadID remote,
                                     size_t *key_len)
{



  SshPmIkePskItem item;
  if (remote != NULL && remote->id_type &&
      remote->id_data_size && remote->id_data)
    item = pm_ike_preshared_keys_get(ad, remote);
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("The IKEv2 payload identity is NULL"));
      return NULL;
    }

  if (item)
    {
      *key_len = item->secret_len;
      return item->secret;
    }
  SSH_DEBUG(SSH_D_MIDOK, ("The IKEv2 payload identity %@ is unknown",
                          ssh_pm_ike_id_render, remote));
  return NULL;
}

Boolean
ssh_pm_ike_preshared_keys_remove_id(SshPmAuthDomain ad,
                                    SshIkev2PayloadID remote_id)
{
  SshPmIkePskItemStruct item_probe;
  SshADTHandle h;

  memset(&item_probe, 0, sizeof(item_probe));
  item_probe.id = remote_id;

  h = ssh_adt_get_handle_to_equal(ad->ike_preshared_keys, &item_probe);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The IKEv2 payload identity %@ is unknown",
                             ssh_pm_ike_id_render, remote_id));
      return FALSE;
    }

  ssh_adt_detach(ad->ike_preshared_keys, h);
  return TRUE;
}


Boolean
ssh_pm_psk_compare(SshPmPsk psk1, SshPmPsk psk2)
{
  if (!psk1 || !psk2)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("both psk's are not defined"));
      return FALSE;
    }
  if (psk1->secret_len != psk2->secret_len)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("psk lengths do not match"));
      return FALSE;
    }
  if (memcmp(psk1->secret, psk2->secret, psk1->secret_len) != 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("secrets do not match!"));
      return FALSE;
    }

  return TRUE;
}


unsigned char *
ssh_pm_decode_secret(SshPmSecretEncoding encoding,
                     const unsigned char *secret, size_t secret_len,
                     size_t *len_return,
                     Boolean *invalid_encoding_return)
{
  unsigned char *ucp = NULL;
  size_t i;
  SshUInt32 value;

  *invalid_encoding_return = FALSE;
  *len_return = 0;

  if (secret == NULL || secret_len == 0)
    return NULL;

  switch (encoding)
    {
    case SSH_PM_ENCODING_UNKNOWN:
      return NULL;

    case SSH_PM_BINARY:
      ucp = ssh_memdup(secret, secret_len);
      *len_return = secret_len;
      break;

    case SSH_PM_HEX:
      if ((secret_len % 2) != 0)
        {
          /* The length must be even. */
          *invalid_encoding_return = TRUE;
          return NULL;
        }

      *len_return = secret_len / 2;
      ucp = ssh_malloc(*len_return);
      if (ucp == NULL)
        return NULL;

      i = 0;
      while (secret_len)
        {
          SSH_ASSERT(secret_len >= 2);
          SSH_ASSERT(i < *len_return);

          if (!SSH_PM_IS_HEX(secret[0]) || !SSH_PM_IS_HEX(secret[1]))
            {
              *invalid_encoding_return = TRUE;
              ssh_free(ucp);
              return NULL;
            }

          value = SSH_PM_HEX_TO_INT(secret[0]);
          value <<= 4;
          value += SSH_PM_HEX_TO_INT(secret[1]);

          ucp[i] = (unsigned char) value;

          i++;
          secret += 2;
          secret_len -= 2;
        }
      break;
    }

  return ucp;
}


/********************************************************************/

Boolean ssh_pm_add_ike_preshared_key(SshPm pm,
                                     SshPmAuthDomain ad,
                                     SshPmIdentityType remote_id_type,
                                     SshPmSecretEncoding remote_id_encoding,
                                     const unsigned char *remote_id,
                                     size_t remote_id_len,
                                     SshPmSecretEncoding encoding,
                                     const unsigned char *secret,
                                     size_t secret_len)
{
  SshPmIkePskItem item = NULL;
  SshIkev2PayloadID id = NULL;

  unsigned char *ike_secret = NULL, *idp = NULL;
  size_t ike_secret_len, idp_len;
  Boolean result, malformed;

  if (!ad)
    ad = pm->default_auth_domain;

  if (!ad || ad->ike_preshared_keys == NULL)
    return FALSE;

  /* Decode identity. */
  if ((idp =
       ssh_pm_decode_secret(remote_id_encoding,
                            remote_id, remote_id_len,
                            &idp_len,
                            &malformed)) == NULL)
    {
      if (malformed)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed encoding on IKE identity");
      goto error;
    }
  id = ssh_pm_decode_identity(remote_id_type, idp, idp_len, &result);
  ssh_free(idp);

  if (id == NULL)
    {
      if (result)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed IKE identity");
      else
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate IKE identity"));

      goto error;
    }

  /* Decode secret. */
  ike_secret = ssh_pm_decode_secret(encoding, secret, secret_len,
                                    &ike_secret_len, &result);
  if (ike_secret == NULL)
    {
      if (result)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed IKE secret");
      else
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate IKE secret"));
      goto error;
    }

  /* Check if this identity-secret pair is already known. */
  item = pm_ike_preshared_keys_get(ad, id);
  if (item)
    {
      if ((item->secret_len == ike_secret_len) &&
          !memcmp(item->secret, ike_secret, ike_secret_len))
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("This identity-secret pair is already known"));
          item->flags |= SSH_IPM_PSK_FLAG_SEEN;
          ssh_free(ike_secret);
          ssh_pm_ikev2_payload_id_free(id);
          return TRUE;
        }

      /* Secret associated with the key has changed, and treat this a
         new pair. */
      ssh_pm_ike_preshared_keys_remove_id(ad, id);
      pm_ike_psk_destroy(item, NULL);
    }

  /* This is a new identity-secret pair. */
  item = ssh_calloc(1, sizeof(*item));
  if (!item)
    goto error;

  SSH_DEBUG(SSH_D_LOWOK, ("Added IKE identity %@ with preshared key ",
                          ssh_pm_ike_id_render, id));

  item->id = id;
  item->secret_len = ike_secret_len;
  item->secret = ike_secret;
  item->flags |= SSH_IPM_PSK_FLAG_NEW;
  ssh_adt_insert(ad->ike_preshared_keys, item);
  return TRUE;

  /* Error handling. */
 error:
  ssh_free(ike_secret);
  ssh_pm_ikev2_payload_id_free(id);
  return FALSE;
}

/* Removes a pre-shared key from the remote ID `remote_id'. The function
   returns TRUE if the pre-shared key was known and FALSE otherwise. */
Boolean ssh_pm_remove_ike_preshared_key(SshPm pm,
                                        SshPmAuthDomain ad,
                                        SshPmIdentityType remote_id_type,
                                        SshPmSecretEncoding remote_id_encoding,
                                        const unsigned char *remote_id,
                                        size_t remote_id_len)
{
  Boolean result;
  SshIkev2PayloadID id = NULL;

  unsigned char *idp;
  size_t idp_len;
  Boolean malformed;

  if (!ad)
    ad = pm->default_auth_domain;

  if (!ad || ad->ike_preshared_keys == NULL)
    return FALSE;

  /* Decode identity. */

  if ((idp =
       ssh_pm_decode_secret(remote_id_encoding,
                            remote_id, remote_id_len,
                            &idp_len,
                            &malformed)) == NULL)
    {
      if (malformed)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed encoding on IKE identity");
      return FALSE;
    }
  id = ssh_pm_decode_identity(remote_id_type, idp, idp_len, &result);
  ssh_free(idp);

  if (id == NULL)
    {
      /* The identity was malformed.  Therefore, it can not be
         inserted in our list object. */
      if (result)
        SSH_DEBUG(SSH_D_FAIL, ("Could not allocate IKE ID"));

      return FALSE;
    }

  /* Remove the item from the ADT container. */
  result = ssh_pm_ike_preshared_keys_remove_id(ad, id);

  /* Cleanup. */
  ssh_pm_ikev2_payload_id_free(id);
  return result;
}
