/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CRL related API routines for the validator.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "cert-db.h"

#include "ssh_berfile.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMi"

/****************** CM CRL handling ******************/

SshCMCrl ssh_cm_crl_allocate(SshCMContext cm)
{
  SshCMCrl crl;

  SSH_ASSERT(cm != NULL);
  SSH_DEBUG(SSH_D_HIGHOK, ("Allocate CRL."));

  if ((crl = ssh_calloc(1, sizeof(*crl))) != NULL)
    {
      /* Allocate the CRL. */
      if ((crl->crl = ssh_x509_crl_allocate()) == NULL)
        {
          ssh_free(crl);
          return NULL;
        }

      /* Set up the status information. */
      crl->cm = cm;
      crl->status_flags = 0;

      /* Initialize the CRL structures. */
      crl->entry = NULL;
      crl->ber  = NULL;
      crl->ber_length = 0;

      /* Indicate that the mapping is not yet allocated. */
      crl->revoked = NULL;
      /* Don't trust until verified. */
      crl->trusted = FALSE;
    }
  return crl;
}

void ssh_cm_crl_free(SshCMCrl crl)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Free CRL."));

  if (crl == NULL)
    return;

  if (crl->entry != NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Trying to free crl still in the database."));
      return;
    }

  /* Check if the mapping has been allocated. */
  if (crl->revoked)
    ssh_adt_destroy(crl->revoked);

  /* Free the CRL. */
  ssh_free(crl->ber);
  ssh_x509_crl_free(crl->crl);
  ssh_free(crl);
}

void ssh_cm_crl_remove(SshCMCrl crl)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Removing CRL from the cache."));
  if (crl == NULL)
    return;
  if (crl->entry == NULL)
    {
      ssh_cm_crl_free(crl);
      return;
    }
  /* Remove the crl. */
  ssh_certdb_take_reference(crl->entry);
  ssh_certdb_remove_entry(crl->cm->db, crl->entry);
}

SshCMStatus ssh_cm_crl_set_ber(SshCMCrl crl,
                               const unsigned char *ber, size_t ber_length)
{
  SshBERFile bf;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Set CRL in ber."));

  if (crl->ber != NULL)
    return SSH_CM_STATUS_FAILURE;

  if (crl->cm &&
      ber_length > crl->cm->config->max_crl_length)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CRL (%zd bytes) too long (max %zd bytes)",
                 ber_length, crl->cm->config->max_crl_length));
      return SSH_CM_STATUS_FAILURE;
    }

  if (ssh_ber_file_create(ber, ber_length, &bf) != SSH_BER_FILE_ERR_OK)
    return SSH_CM_STATUS_FAILURE;
  ber_length -= ssh_ber_file_get_free_space(bf);
  ssh_ber_file_destroy(bf);

  if (ssh_x509_crl_decode(ber, ber_length, crl->crl) != SSH_X509_OK)
    return SSH_CM_STATUS_DECODE_FAILED;

  /* Copy the BER encoded part too. */
  crl->ber_length = 0;
  if ((crl->ber = ssh_memdup(ber, ber_length)) != NULL)
    crl->ber_length = ber_length;

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_crl_get_ber(SshCMCrl crl,
                               unsigned char **ber, size_t *ber_length)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get CRL ber/der encoding."));

  if (crl == NULL)
    return SSH_CM_STATUS_FAILURE;
  if (crl->ber == NULL)
    return SSH_CM_STATUS_FAILURE;
  *ber        = crl->ber;
  *ber_length = crl->ber_length;
  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_crl_get_x509(SshCMCrl c, SshX509Crl *crl)
{
  SshX509Crl x509_crl;
  SshX509RevokedCerts revoked;
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get X.509 CRL opened."));

  if (c == NULL)
    return SSH_CM_STATUS_FAILURE;
  if (c->crl == NULL)
    return SSH_CM_STATUS_FAILURE;

  x509_crl = c->crl;

  /* Clean up the names from previous studies. */
  ssh_x509_name_reset(x509_crl->issuer_name);
  ssh_x509_name_reset(x509_crl->extensions.issuer_alt_names);
  for (revoked = x509_crl->revoked; revoked; revoked = revoked->next)
    ssh_x509_name_reset(revoked->extensions.certificate_issuer);

  /* All done. */
  *crl = x509_crl;

  return SSH_CM_STATUS_OK;
}

unsigned int ssh_cm_crl_get_cache_id(SshCMCrl crl)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get CRL local database entry identifier."));
  if (crl->entry == NULL)
    {
      unsigned int entry_id = 0;

      SSH_DEBUG(SSH_D_UNCOMMON, ("Search for the entry identifier."));
      /* The certificate is not itself available thru cache search,
         however, there may be the exactly same certificate. We
         try to return the cache identifier if such
         certificate exists. */

      ssh_cm_check_db_collision(crl->cm, SSH_CM_DATA_TYPE_CRL,
                                crl->ber, crl->ber_length,
                                NULL, &entry_id);

      return entry_id;
    }
  return crl->entry->id;

}


/* Check whether the certificate has a been previously added to the
   database. */
Boolean ssh_cm_crl_check_db_collision(SshCMContext cm,
                                      SshCMCrl cm_crl,
                                      SshCertDBKey **key)
{
  return ssh_cm_check_db_collision(cm, SSH_CM_DATA_TYPE_CRL,
                                   cm_crl->ber, cm_crl->ber_length,
                                   key, NULL);
}



SshCMStatus ssh_cm_add_crl_with_bindings(SshCMCrl crl,
                                         SshCertDBKey *bindings)
{
  SshCertDBEntry *entry;
  SshCMContext cm;

  SSH_DEBUG(SSH_D_HIGHSTART, ("CRL add to local database/memory cache."));

  if (crl == NULL || crl->cm == NULL || crl->cm->db == NULL)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_FAILURE;
    }
  cm  = crl->cm;

  if (cm->config->local_db_writable == FALSE)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_FAILURE;
    }

  /* Allocate a new entry. */
  if (ssh_certdb_alloc_entry(cm->db,
                             SSH_CM_DATA_TYPE_CRL, crl,
                             &entry) != SSH_CDBET_OK)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Explicit crl: %@", ssh_cm_render_crl, crl->crl));

  /* Check for collision in the database. Be a optimist anyway... */
  if (ssh_cm_crl_check_db_collision(cm, crl, &entry->names))
    {
      unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
      size_t length;
      SshHash hash;
      SshCertDBEntryList *found;
      SshCertDBEntryListNode list;
      SshCMCrl old_crl;

      /* First fetch colliding old CRL from local cache, timestamp it and
         clean possible SSH_CM_CRL_FLAG_SKIP-flag */
      if (ssh_hash_allocate(SSH_CM_HASH_ALGORITHM, &hash) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Can't allocate %s",
                                  SSH_CM_HASH_ALGORITHM));

          ssh_certdb_release_entry(cm->db, entry);
          ssh_certdb_key_free(bindings);

          return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
        }

      ssh_hash_update(hash, crl->ber, crl->ber_length);
      ssh_hash_final(hash, digest);
      length = ssh_hash_digest_length(ssh_hash_name(hash));
      ssh_hash_free(hash);

      if (length > 8)
        length = 8;

      /* Get old CRL from the database. */
      if ((ssh_certdb_find(cm->db,
                           SSH_CM_DATA_TYPE_CRL,
                           SSH_CM_KEY_TYPE_BER_HASH,
                           digest, length,
                           &found) == SSH_CDBET_OK) &&
          found->head)
        {
          list = found->head;

          old_crl = list->entry->context;

          ssh_ber_time_set_from_unix_time(&old_crl->fetch_time,
                                          (*cm->config->time_func)
                                          (cm->config->time_context));

          old_crl->status_flags &= ~SSH_CM_CRL_FLAG_SKIP;

          SSH_DEBUG(SSH_D_MIDOK, ("CRL exists already in the database, "
                                  "updated CRL fetch-time."));
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, ("CRL exists already in the database, "
                                 "could not update CRL fetch-time."));
        }

      ssh_certdb_entry_list_free_all(cm->db, found);

      /* Prevent database from freeing the CRL */
      entry->context = NULL;

      /* Free the entry allocated. */
      ssh_certdb_release_entry(cm->db, entry);
      ssh_certdb_key_free(bindings);

      return SSH_CM_STATUS_ALREADY_EXISTS;
    }

  /* Initialize the entry. */
  crl->entry = entry;
  if (!ssh_cm_key_set_from_crl(&entry->names, crl))
    {
      /* Prevent database from freeing the CRL */
      entry->context = NULL;
      ssh_certdb_release_entry(cm->db, entry);
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
    }

  if (bindings)
    ssh_certdb_entry_add_keys(cm->db, entry, bindings);

  /* Add to the database. */
  if (ssh_certdb_add(cm->db, entry) != SSH_CDBET_OK)
    {
      /* Prevent database from freeing the CRL */
      entry->context = NULL;
      ssh_certdb_release_entry(cm->db, entry);

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Local database/memory cache denies the addition."));
      return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
    }

  /* Record CRL addition time */
  ssh_ber_time_set_from_unix_time(&crl->fetch_time,
                                  (*cm->config->time_func)
                                  (cm->config->time_context));

  ssh_certdb_release_entry(cm->db, entry);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_add_crl(SshCMCrl crl)
{
  return ssh_cm_add_crl_with_bindings(crl, NULL);
}


SshCMStatus
ssh_cm_crl_enumerate(SshCMContext cm,
                     SshCMCrlEnumerateCB callback, void *context)
{
  SshCertDBEntry *entry = NULL;

  SSH_DEBUG(SSH_D_UNCOMMON, ("Enumerate crl."));

  /* Check the callback. */
  if (callback == NULL_FNPTR)
    return SSH_CM_STATUS_FAILURE;

  while (TRUE)
    {
      entry = ssh_certdb_iterate_entry_class(cm->db,
                                             SSH_CERTDB_ENTRY_CLASS_ZERO,
                                             entry);
      if (entry == NULL)
        break;

      if (entry->tag == SSH_CM_DATA_TYPE_CRL && entry->context)
        (*callback)((SshCMCrl)entry->context, context);
    }

  return SSH_CM_STATUS_OK;
}

/* Functions which need the availability of CM context. This is a burden
   you need when looking down to the cache level. */

SshCMStatus ssh_cm_crl_set_locked(SshCMCrl c)
{
  unsigned int limit = ~((unsigned int)0);

  SSH_DEBUG(SSH_D_HIGHSTART, ("The CRL will become permament in the cache."));

  if (c == NULL || c->entry == NULL || c->cm == NULL || c->cm->db == NULL)
    return SSH_CM_STATUS_FAILURE;

  /* Set the CRL locked in the cache. */
  ssh_certdb_set_option(c->cm->db, c->entry,
                        SSH_CERTDB_OPTION_MEMORY_LOCK, &limit);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_crl_set_unlocked(SshCMCrl c)
{
  unsigned int limit = 0;
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("The certificate will be unlocked from the cache."));

  if (c == NULL || c->entry == NULL || c->cm == NULL || c->cm->db == NULL)
    return SSH_CM_STATUS_FAILURE;

  /* Set the CRL unlocked in the cache. */
  ssh_certdb_set_option(c->cm->db, c->entry,
                        SSH_CERTDB_OPTION_MEMORY_LOCK, &limit);

  return SSH_CM_STATUS_OK;
}

Boolean ssh_cm_crl_is_locked(SshCMCrl c)
{
  unsigned int limit;

  if (c == NULL || c->entry == NULL || c->cm->db == NULL)
    return FALSE;

  if (ssh_certdb_get_option(c->cm->db, c->entry, SSH_CERTDB_OPTION_MEMORY_LOCK,
                            &limit) != SSH_CDBET_OK)
    return FALSE;

  if (limit == 0)
    return FALSE;

  return TRUE;
}

#endif /* SSHDIST_CERT */
