/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The externalkey thread controlling externalkey events like fetching
   certificates and private keys from notified key paths.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStEk"

#ifdef SSHDIST_EXTERNALKEY

/************************** Static help functions ***************************/

static Boolean
ssh_pm_set_ek_public_key_and_key_hash(SshPm pm,
                                      SshPmEk ek,
                                      SshPublicKey public_key,
                                      const unsigned char *cert,
                                      size_t cert_length)
{
  unsigned char *ber_cert = NULL;
  size_t ber_cert_length = 0;
  unsigned char *keyhash;
  size_t keyhash_len;
  SshX509Certificate x509cert = NULL;
  Boolean not_pem;

  x509cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (x509cert == NULL)
    return FALSE;

  /* See if the certificate is in BER form */
  if (ssh_x509_cert_decode(cert, cert_length, x509cert) == SSH_X509_OK)
    {
      /* OK its in BER format */
      ber_cert = ssh_memdup((unsigned char *)cert, cert_length);
      ber_cert_length = cert_length;
    }
  else
    {
      /* The EK cert is not in BER, try to convert it to BER format,
         assuming it is now in PEM */
      ber_cert = ssh_pm_pem_to_binary(cert, cert_length,
                                      &ber_cert_length, &not_pem);

      /* conversion pem to ber failed.*/
      if (ber_cert == NULL || not_pem)
        goto fail;

      /* Now try to convert the BER cert to an X509 certificate*/
      if (ssh_x509_cert_decode(ber_cert, ber_cert_length,
                               x509cert) != SSH_X509_OK)
        goto fail;
    }

  /* Now compute the Key identifier from the X509 certificate */
  keyhash = ssh_x509_cert_compute_key_identifier(x509cert, "md5",
                                                 &keyhash_len);
  if (keyhash != NULL)
    {
      SSH_ASSERT(keyhash_len <= sizeof(ek->key_hash));

      memcpy(ek->key_hash, keyhash, keyhash_len);
      ssh_free(keyhash);
    }

  if (!ssh_pm_auth_domain_add_cert_to_all(pm, ber_cert, ber_cert_length))
    goto fail;

  SSH_ASSERT(ek->public_key == NULL);
  SSH_ASSERT(ek->ber_cert == NULL);
  ek->public_key = public_key;

  ek->ber_cert = ber_cert;
  ek->ber_cert_len = ber_cert_length;

  ssh_x509_cert_free(x509cert);

  return TRUE;

 fail:
  ssh_x509_cert_free(x509cert);

  if (ber_cert)
    ssh_free(ber_cert);

  return FALSE;
}

/* Completion callback for externalkey's `get certificate' operation.
   If the certificate fetching was successful this stores the fetched
   certificates into certificate manager. */
static void
ssh_pm_ek_get_cert_callback(SshEkStatus status,
                            const unsigned char *cert_return,
                            size_t cert_return_length,
                            void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_tdata(thread);
  SshIkev2PayloadID subject;
  SshIkev2PayloadID *altnames;
  size_t num_altnames;
  SshPublicKey public_key = NULL;
  SshPmEk ek = pm->ek_thread_key;
  size_t i, j;

  pm->ek_thread_status = status;

  switch (status)
    {
    case SSH_EK_OK:
      SSH_DEBUG(SSH_D_MIDOK, ("Certificate %u fetched successfully",
                              (unsigned int) pm->ek_thread_index));
      SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Certificate:"),
                        cert_return, cert_return_length);


      /* Fetch certificate's subject name and alternative subject
         names. */
      subject = ssh_pm_cert_names(cert_return, cert_return_length,
                                  &altnames, &num_altnames,
                                  ek->public_key == NULL ? &public_key : NULL);

#ifdef DEBUG_LIGHT
      if (subject)
        SSH_DEBUG(SSH_D_NICETOKNOW, ("SubjectName %@",
                                     ssh_pm_ike_id_render, subject));
      else
        SSH_DEBUG(SSH_D_NICETOKNOW, ("No SubjectName"));

      SSH_DEBUG(SSH_D_NICETOKNOW, ("%u SubjectAltName%s",
                                   num_altnames,
                                   (num_altnames == 0
                                    ? "s"
                                    : (num_altnames == 1
                                       ? ":"
                                       : "s:"))));

      for (i = 0; i < num_altnames; i++)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("  %@", ssh_pm_ike_id_render, altnames[i]));
#endif /* DEBUG_LIGHT */

      /* Store the identities in the certificate to the external key unless
         they are already set. */
      if (ek->ids == NULL)
        {
          SshUInt32 num_ids = 0;

          if (subject)
            num_ids++;
          for (i = 0; i < num_altnames; i++)
            if (altnames[i])
              num_ids++;

          ek->num_ids = num_ids;
          ek->ids = ssh_calloc(num_ids, sizeof(SshIkev2PayloadID));
          if (ek->ids == NULL)
            {
              if (subject)
                ssh_pm_ikev2_payload_id_free(subject);
              for (i = 0; i < num_altnames; i++)
                ssh_pm_ikev2_payload_id_free(altnames[i]);
              ssh_free(altnames);
              if (public_key)
                {
                  ssh_public_key_free(public_key);
                  public_key = NULL;
                }
              SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
              return;
            }

          j = 0;
          if (subject)
            ek->ids[j++] = subject;

          for (i = 0; i < num_altnames; i++)
            if (altnames[i])
              ek->ids[j++] = altnames[i];
          SSH_ASSERT(j == ek->num_ids);
        }
      else
        {
          if (subject)
            ssh_pm_ikev2_payload_id_free(subject);

          for (i = 0; i < num_altnames; i++)
            ssh_pm_ikev2_payload_id_free(altnames[i]);
        }
      ssh_free(altnames);

      /* Store the public key unless it is already set. */
      if (ek->public_key == NULL)
        {
          if (!ssh_pm_set_ek_public_key_and_key_hash(pm, ek, public_key,
                                                     cert_return,
                                                     cert_return_length))
            {
              SSH_ASSERT(ek->public_key == NULL);
              ssh_public_key_free(public_key);
            }

          public_key = NULL;
        }
      break;

    case SSH_EK_NO_MORE_CERTIFICATES:
      SSH_DEBUG(SSH_D_MIDOK, ("All certificates fetched"));
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Could not fetch certificate %u: %u",
                              (unsigned int) pm->ek_thread_index,
                              (unsigned int) status));


      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "Unable to fetch externalkey certificate");
      break;
    }

  if (public_key)
    ssh_public_key_free(public_key);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Completion callback for externalkey's `get private key' operation.
   If the operation is successful, this stores the SshPrivateKey
   object into the external key object that is currently processed by
   the externalkey thread. */
static void
ssh_pm_ek_get_private_key_callback(SshEkStatus status,
                                   SshPrivateKey private_key_return,
                                   void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_tdata(thread);

  pm->ek_thread_status = status;

  switch (status)
    {
    case SSH_EK_OK:
      SSH_DEBUG(SSH_D_MIDOK, ("Private key fetched successfully"));
      SSH_ASSERT(pm->ek_thread_key->private_key == NULL);
      pm->ek_thread_key->private_key = private_key_return;
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Could not fetch private key: %u", status));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "Unavailable to fetch externalkey private key");
      break;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Completion callback for externalkey's `get accelerate private key'
   operation. If the operation is successful, this stores the SshPrivateKey
   object into the external accelerated key object that is currently
   processed by the externalkey thread. */
static void
ssh_pm_ek_gen_acc_private_key_cb(SshEkStatus status,
                                 SshPrivateKey private_key_return,
                                 void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_tdata(thread);

  /* The original private key may have been a proxy key which cannot
     be accelerated, so failure to accelerate the private key should
     not be signaled as an error, instead we just use the unaccelerated
     private key. */
  pm->ek_thread_status = SSH_EK_OK;

  switch (status)
    {
    case SSH_EK_OK:
      SSH_DEBUG(SSH_D_MIDOK, ("Accelerated Private key fetched successfully"));
      SSH_ASSERT(pm->ek_thread_key->accel_private_key == NULL);
      pm->ek_thread_key->accel_private_key = private_key_return;
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Could not fetch private key: %u", status));
      break;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}




/************************ Externalkey thread states *************************/

SSH_FSM_STEP(ssh_pm_st_ek_start)
{
  SshPm pm = (SshPm) thread_context;

  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED
      && !pm->ek_key_change)
    SSH_FSM_CONDITION_WAIT(&pm->ek_thread_cond);

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_ek_shutdown);
      return SSH_FSM_CONTINUE;
    }

  if (pm->ek_key_change)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_ek_lookup_change);
      return SSH_FSM_CONTINUE;
    }

  SSH_NOTREACHED;
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_ek_shutdown)
{
  SshPm pm = (SshPm) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Policy manager is shutting down: terminating"));
  pm->ek_thread_ok = 0;
  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_ek_lookup_change)
{
  SshPm pm = (SshPm) thread_context;
  SshADTHandle h;

  pm->ek_thread_key = NULL;

  /* Lookup a key that has changes. */
  for (h = ssh_adt_enumerate_start(pm->externalkey_keys);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->externalkey_keys, h))
    {
      SshPmEk ek = ssh_adt_get(pm->externalkey_keys, h);

      if (!ek->deleted && (!ek->certs_fetched || !ek->key_fetched))
        {
          /* Found a key.  Let's lock it so it won't disappear while
             we are processing it. */
          pm->ek_thread_key = ek;
          pm->ek_thread_key->refcount++;
          break;
        }
    }

  if (pm->ek_thread_key == NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("No more key changes"));

      pm->ek_key_change = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_ek_start);

      return SSH_FSM_CONTINUE;
    }

  /* Check certificates. */

  pm->ek_thread_index = 0;
  SSH_FSM_SET_NEXT(ssh_pm_st_ek_certs);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_ek_certs)
{
  SshPm pm = (SshPm) thread_context;

  SSH_ASSERT(pm->ek_thread_key != NULL);

  if (pm->ek_thread_key->certs_fetched)
    {
      /* Certificates are already fetched. */
      SSH_FSM_SET_NEXT(ssh_pm_st_ek_private_key);
      return SSH_FSM_CONTINUE;
    }

  /* Fetch the next certificate. */

  SSH_DEBUG(SSH_D_MIDSTART, ("Fetching certificate %u",
                             (unsigned int) pm->ek_thread_index));

  SSH_FSM_SET_NEXT(ssh_pm_st_ek_get_cert_result);
  SSH_FSM_ASYNC_CALL(ssh_ek_get_certificate(pm->externalkey,
                                            pm->ek_thread_key->keypath,
                                            pm->ek_thread_index,
                                            ssh_pm_ek_get_cert_callback,
                                            thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_ek_get_cert_result)
{
  SshPm pm = (SshPm) thread_context;

  if (pm->ek_thread_status == SSH_EK_OK)
    /* Move ahead. */
    pm->ek_thread_index++;
  else
    /* All done. */
    pm->ek_thread_key->certs_fetched = 1;

  SSH_FSM_SET_NEXT(ssh_pm_st_ek_certs);

  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_ek_private_key)
{
  SshPm pm = (SshPm) thread_context;

  if (pm->ek_thread_key->key_fetched)
    {
      /* Private key is already fetched. */
      SSH_FSM_SET_NEXT(ssh_pm_st_ek_key_done);
      return SSH_FSM_CONTINUE;
    }

  /* Fetch the private key. */

  SSH_DEBUG(SSH_D_MIDSTART, ("Fetching private key"));

  SSH_FSM_SET_NEXT(ssh_pm_st_ek_get_private_key_result);
  SSH_FSM_ASYNC_CALL(ssh_ek_get_private_key(pm->externalkey,
                                            pm->ek_thread_key->keypath,
                                            ssh_pm_ek_get_private_key_callback,
                                            thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_ek_get_private_key_result)
{
  SshPm pm = (SshPm) thread_context;

  /* The private key is fetched even if the operation failed. */
  pm->ek_thread_key->key_fetched = 1;

  /* Get the type of the private key. */
  if (pm->ek_thread_status == SSH_EK_OK)
    {
      SshCryptoStatus status;
      const char *key_type;
      const char *cp;

      status = ssh_private_key_get_info(pm->ek_thread_key->private_key,
                                        SSH_PKF_KEY_TYPE, &key_type,
                                        SSH_PKF_END);
      if (status != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not get type of a private key: %s",
                                  ssh_crypto_status_message(status)));
          ssh_private_key_free(pm->ek_thread_key->private_key);
          pm->ek_thread_key->private_key = NULL;
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Type of the private key is `%s'",
                                  key_type));

          /* Take the suffix from the key-type. */
          cp = strrchr(key_type, ':');
          if (cp)
            cp++;
          else
            cp = key_type;

          if (strcmp(cp, "if-modn") == 0)
            {
              pm->ek_thread_key->rsa_key = 1;

              /* The key is an usable RSA key if we also have the
                 public key. */
              if (pm->ek_thread_key->public_key)
                pm->externalkey_num_rsa++;

              /* Check if algorithm restrictions apply, and set the scheme
                 accodingly. */
              if ((pm->params.enable_key_restrictions &
                   SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
                {
                  const char *rsa_scheme = NULL;
                  SshX509Certificate x509cert = NULL;

                  if (pm->ek_thread_key->ber_cert != NULL &&
                      pm->ek_thread_key->ber_cert_len > 0)
                    {

                      x509cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
                      if (x509cert == NULL)
                        goto error;

                      if (ssh_x509_cert_decode(pm->ek_thread_key->ber_cert,
                                           pm->ek_thread_key->ber_cert_len,
                                           x509cert) != SSH_X509_OK)
                        goto error;

                      if (ssh_cm_cert_allowed_algorithms(
                                              pm->default_auth_domain->cm,
                                              x509cert) != SSH_CM_STATUS_OK)
                        goto error;

                      rsa_scheme =
                        ssh_x509_find_signature_algorithm(x509cert);

                      if (rsa_scheme == NULL)
                        goto error;

                      if (ssh_private_key_select_scheme(
                                      pm->ek_thread_key->private_key,
                                      SSH_PKF_SIGN,
                                      rsa_scheme,
                                      SSH_PKF_END)
                          == SSH_CRYPTO_OK)
                        goto success;

                    error:
                      SSH_DEBUG(SSH_D_FAIL, ("Could not set scheme"));
                      ssh_private_key_free(pm->ek_thread_key->private_key);
                      pm->ek_thread_key->private_key = NULL;
                    }
                success:
                  ssh_x509_cert_free(x509cert);
                }
            }
          else if (strcmp(cp, "dl-modp") == 0)
            {
              pm->ek_thread_key->dsa_key = 1;
              if (pm->ek_thread_key->public_key)
                pm->externalkey_num_dss++;
            }
#ifdef SSHDIST_CRYPT_ECP
          else if (strcmp(cp, "ec-modp") == 0)
            {
              pm->ek_thread_key->ecdsa_key = 1;
              if (pm->ek_thread_key->public_key)
                pm->externalkey_num_ecdsa++;
            }
#endif /* SSHDIST_CRYPT_ECP */
          else
            {
              SSH_DEBUG(SSH_D_FAIL, ("Unsupported private key type `%s'",
                                     key_type));
              ssh_private_key_free(pm->ek_thread_key->private_key);
              pm->ek_thread_key->private_key = NULL;
            }
        }
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_ek_key_done);

  /* If we have a valid private key and an accelerator configured,
     try to accelerate */
  if (pm->ek_thread_key->private_key && pm->accel_short_name)
    {
      SSH_FSM_ASYNC_CALL(ssh_ek_generate_accelerated_private_key(
                                              pm->externalkey,
                                              pm->accel_short_name,
                                              pm->ek_thread_key->private_key,
                                              ssh_pm_ek_gen_acc_private_key_cb,
                                              thread));
      SSH_NOTREACHED;
    }
  else
    {
      return SSH_FSM_CONTINUE;
    }
}

SSH_FSM_STEP(ssh_pm_st_ek_key_done)
{
  SshPm pm = (SshPm) thread_context;

  /* We are done with this key. */
  ssh_pm_ek_unref(pm, pm->ek_thread_key);
  pm->ek_thread_key = NULL;

  /* Lookup more changes. */
  SSH_FSM_SET_NEXT(ssh_pm_st_ek_lookup_change);
  return SSH_FSM_CONTINUE;
}

#endif /* SSHDIST_EXTERNALKEY */
