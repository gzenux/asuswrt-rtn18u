/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager interface to the certificate manager.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmCm"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

Boolean
ssh_pm_cm_init(SshPm pm, SshPmAuthDomain ad)
{
  SshCMConfig config;
  SshCMLocalNetworkStruct lnet;

  config = ssh_cm_config_allocate();
  if (config == NULL)
    return FALSE;

#if 0
  /* APPLICATION NOTE; this is not neccessary if condition described
     in function 'ssh_pm_cm_certificate_notify_callback()' (see
     pm_cm.h) is satisfied. */
  pm->notify_events.certificate = ssh_pm_cm_certificate_notify_callback;
  pm->notify_events.crl = NULL_FNPTR;
  ssh_cm_config_set_notify_callbacks(config, &pm->notify_events, pm);
#endif

  /* Allow 1 minute for TCP connection used by LDAP, HTTP, or OCSP
     backend to establish. */
  ssh_cm_config_tcp_configure(config, SSH_PM_CM_TCP_CONNECT_TIMEOUT);

  if (!ssh_pm_cm_set_access_callback(pm, config))
    {
      ssh_cm_config_free(config);
      return FALSE;
    }

  /* Set a maximum timeout for all CMI lookups. This will make sure that
     an external certificate lookup does not get stuck in the CMI. */
  ssh_cm_config_set_query_expiration(config, SSH_PM_CM_QUERY_EXPIRATION);

  /* set allowed algorithms */
  if ((pm->params.enable_key_restrictions &
       SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
    {
      ssh_cm_config_set_default_allowed_algorithms(config,
                                                   SSH_CMI_HASH_800_131A_2014,
                                                   SSH_CMI_KEY_800_131A_2014);
    }

  ad->cm = ssh_cm_allocate(config);
  if (ad->cm == NULL)
    {
      return FALSE;
    }

  /* Initialize local network properties.  These must be set before
     the external databases are initialized. */
  memset(&lnet, 0, sizeof(lnet));
  lnet.socks = ssh_sstr(pm->params.socks);
  lnet.proxy = ssh_sstr(pm->params.http_proxy);
  ssh_cm_edb_set_local_network(ad->cm, &lnet);

  /* Init external databases. */

#ifdef SSHDIST_LDAP
  /* LDAP */
  if (!ssh_cm_edb_ldap_init(ad->cm, ""))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not initialize LDAP EDB"));
      goto error;
    }
#endif /* SSHDIST_LDAP */

#ifdef SSHDIST_VALIDATOR_HTTP
  /* HTTP */
  if (!ssh_cm_edb_http_init(ad->cm))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not initialize HTTP EDB"));
      goto error;
    }
#endif /* SSHDIST_VALIDATOR_HTTP */

#ifdef SSHDIST_CERT_OCSP
  /* OCSP */
  if (!ssh_cm_edb_ocsp_init(ad->cm))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not initialize OCSP EDB"));
      goto error;
    }
#endif /* SSHDIST_CERT_OCSP */

  /* All done. */
  return TRUE;

  /* Error handling. */

 error:

  ssh_cm_free(ad->cm);
  ad->cm = NULL;

  return FALSE;
}

void
ssh_pm_cm_stop(SshPmAuthDomain ad,
               SshPmCmStopCB callback, void *context)
{
  if (ad->cm)
    /* Stop the certificate manager. */
    ssh_cm_stop(ad->cm, callback, context);
  else
    /* Call the user callback manually. */
    (*callback)(context);
}

void
ssh_pm_cm_uninit(SshPm pm, SshPmAuthDomain ad)
{
  if (ad->cm == NULL)
    return;

  ssh_cm_free(ad->cm);
}

SshPmCa
ssh_pm_cm_new_ca(SshCMContext cm,
                 const unsigned char *cert, size_t cert_len,
                 SshUInt32 id, SshUInt32 flags, Boolean external)
{
  SshX509Certificate x509cert = NULL;
  Boolean reallyca;
  size_t path_len;
  Boolean critical;
  Boolean got_constraints;
  SshPmCa ca = NULL;
  SshCertDBKey *search_keys = NULL;
  SshCMSearchConstraints search;
  SshCMStatus status;
  SshCMCertList cert_list;
  SshCMCertificate cmcert;
  SshMPIntegerStruct trusted_set;
  SshMPInteger mpint;
  unsigned int size, i;

  /* Allocate an internal certificate structure. */

  ca = ssh_calloc(1, sizeof(*ca));
  if (ca == NULL)
    goto error_memory;

  ca->id = id;
  ca->flags = flags;

  /* Decode certificate. */

  ca->cert = ssh_cm_cert_allocate(cm);
  if (ca->cert == NULL)
    goto error_memory;

  status = ssh_cm_cert_set_ber(ca->cert, cert, cert_len);
  if (status != SSH_CM_STATUS_OK)
    {
      Boolean not_pem;
      unsigned char *ber;
      size_t ber_len;

      /* Decoding as binary data failed.  Let's try if the input was
         PEM encoded. */

      SSH_DEBUG(SSH_D_NICETOKNOW, ("BER decoding failed, trying PEM"));

      ber = ssh_pm_pem_to_binary(cert, cert_len, &ber_len, &not_pem);
      if (ber == NULL)
        {
          if (not_pem)
            {
              /* It was not PEM encoded. */
            could_not_decode:
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                            "Could not decode Certificate.  "
                            "The certificate may be corrupted or it was "
                            "given in unrecognized format "
                            "(file format may be wrong)");
              goto error;
            }
          else
            {
              goto error_memory;
            }
        }

      /* Try to decode the certificate. */
      status = ssh_cm_cert_set_ber(ca->cert, ber, ber_len);

      /* Free the decoded certificate data. */
      ssh_free(ber);

      if (status != SSH_CM_STATUS_OK)
        goto could_not_decode;
    }

  /* The certificate is not in `ca->cert'. */

  /* Convert it into an X.509 certificate. */
  if (ssh_cm_cert_get_x509(ca->cert, &x509cert) != SSH_CM_STATUS_OK)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Could not convert CMi certificate to X.509 certificate");
      goto error;
    }

  /* Get basic constraints. */
  got_constraints = ssh_x509_cert_get_basic_constraints(x509cert, &path_len,
                                                        &reallyca, &critical);
  if (!got_constraints)
    SSH_DEBUG(SSH_D_FAIL,
              ("Can not get Basic Constraints from the CA certificate. "
               "According to the RFC-2459, all CA certificates MUST "
               "have the Basic Constraints extension.  However, forcing "
               "the certificate as a point of trust"));

  SSH_DEBUG(SSH_D_HIGHOK, ("This is a %s certificate",
                           (got_constraints && reallyca
                            ? "CA" : "forced as trusted")));

  /* Get certificate's subject name. */
  if (!ssh_x509_cert_get_subject_name_der(x509cert, &ca->cert_subject_dn,
                                          &ca->cert_subject_dn_len))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Could not get subject name from a CA certificate. "
                    "This certificate is not usable as an IPsec "
                    "authenticator, and is not inserted into loal list of "
                    "trusted CAs");
      goto error;
    }

  /* Get certificate's issuer name. */
  if (!ssh_x509_cert_get_issuer_name_der(x509cert, &ca->cert_issuer_dn,
                                          &ca->cert_issuer_dn_len))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Could not get issuer name from a CA certificate. "
                    "This certificate is not usable as an IPsec "
                    "authenticator, and is not inserted into loal list of "
                    "trusted CAs");
      goto error;
    }

  /* Get certificate key identifier */
  ca->cert_key_id = ssh_x509_cert_compute_key_identifier(x509cert,
                                                         "sha1",
                                                         &ca->cert_key_id_len);

  if (ca->cert_key_id == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Could not compute certificate key id for this CA "
                    "certificate. This certificate is not usable as an IPsec "
                    "authenticator, and is not inserted into loal list of "
                    "trusted CAs");
      goto error;
    }

  /* Handle non-CRL issuers. */
  if ((flags & SSH_PM_CA_NO_CRL)
      && ssh_cm_cert_non_crl_issuer(ca->cert) != SSH_CM_STATUS_OK)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                  "Could not set CA certificate to non-CRL issuer. "
                  "This may cause authentication errors if valid CRLs "
                  "are not available");

  /* Mark the certificate as a point of trust. */
  if (ssh_cm_cert_force_trusted(ca->cert) != SSH_CM_STATUS_OK)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                  "Could not force CA certificate as a point of trust");

  /* Lock the certificate in memory. */
  if (external == FALSE)
    ssh_cm_cert_set_locked(ca->cert);

  /* Add certificate to the certificate manager. */
  switch (ssh_cm_add(ca->cert))
    {
    case SSH_CM_STATUS_OK:
      /* This was the initial reference.  Let's init the trusted
         set. */
      ssh_mprz_init(&trusted_set);
      ssh_mprz_set_bit(&trusted_set, id);
      if (ssh_mprz_isnan(&trusted_set))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "Could not set the trusted set for a CA certificate");
          ssh_mprz_clear(&trusted_set);
          goto error;
        }
      ssh_cm_cert_set_trusted_set(ca->cert, &trusted_set);
      ssh_mprz_clear(&trusted_set);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("CA added with ID %u",
                                   (unsigned int) ca->id));
      break;

    case SSH_CM_STATUS_ALREADY_EXISTS:
      /* We have the certificate already.  Let's lookup the first
         occurrence and use it instead. */

      search = ssh_cm_search_allocate();
      if (search == NULL)
        goto error_memory;

      if (!ssh_cm_key_set_cache_id(&search_keys,
                                   ssh_cm_cert_get_cache_id(ca->cert)))
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not set cache ID key for a certificate search"));
          ssh_cm_search_free(search);
          goto error;
        }

      ssh_cm_search_set_keys(search, search_keys);

      /* Find for the certificate. */
      status = ssh_cm_find_local_cert(cm, search, &cert_list);
      if (status != SSH_CM_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));
          goto error;
        }

      /* And use the first one. */

      cmcert = ssh_cm_cert_list_first(cert_list);
      ssh_cm_cert_list_free(cm, cert_list);

      if (cmcert == NULL)
        {
          SSH_DEBUG(SSH_D_UNCOMMON,
                    ("Could not find certificate although it was already "
                     "found from the certificate manager"));
          goto error;
        }

      /* Resolve the CA ID from the certificate. */

      mpint = ssh_cm_cert_get_trusted_set(cmcert);
      if (mpint == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not get trusted set from existing CA"));
          goto error;
        }

      size = ssh_mprz_get_size(mpint, 2);
      for (i = 0; i <= size; i++)
        if (ssh_mprz_get_bit(mpint, i))
          {
            ca->id = i;
            break;
          }
      if (i > size)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not resolve ID of an existing CA"));
          goto error;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("CA certificate already exists with ID %u",
                 (unsigned int) ca->id));

      ssh_cm_cert_free(ca->cert);
      ca->cert = cmcert;
      break;

    default:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Can not insert CA certificate into local database");
      goto error;
    }

  /* All done. */
  ssh_x509_cert_free(x509cert);
  return ca;


  /* Error handling. */

 error_memory:

  SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for CA"));

 error:

  ssh_x509_cert_free(x509cert);
  if (ca)
    {
      if (ca->cert)
        ssh_cm_cert_free(ca->cert);

      ssh_free(ca->cert_subject_dn);
      ssh_free(ca->cert_issuer_dn);
      ssh_free(ca->cert_key_id);
      ssh_free(ca);
    }

  return NULL;
}

void
ssh_pm_cm_remove_ca(SshPmCa ca)
{
  if (ca->cert)
    {
      /* First, unlock the certificate. */
      (void) ssh_cm_cert_set_unlocked(ca->cert);

      /* Second, remove it from the certificate manager. */
      ssh_cm_cert_remove(ca->cert);
    }

  /* Finally, free all resources. */
  ssh_free(ca->cert_subject_dn);
  ssh_free(ca->cert_issuer_dn);
  ssh_free(ca->cert_key_id);
  ssh_free(ca);
}

Boolean
ssh_pm_compare_ca(SshPm pm, SshPmCa ca1, SshPmCa ca2)
{
  unsigned char *ber1, *ber2;
  size_t ber1_length, ber2_length;

  if (ca1->cert == NULL || ca2->cert == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Cannot compare CA certificates"));
      return FALSE;
    }

  if (ca1->flags != ca2->flags)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("CA flags do not match"));
      return FALSE;
    }

  if (ca1->cert == ca2->cert)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Both CA's point to the same certificate"));

      if (ca1->cert_subject_dn_len != ca2->cert_subject_dn_len
          || memcmp(ca1->cert_subject_dn, ca2->cert_subject_dn,
                    ca1->cert_subject_dn_len) != 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("CA subject names do not match"));
          return FALSE;
        }

      if (ca1->cert_issuer_dn_len != ca2->cert_issuer_dn_len
          || memcmp(ca1->cert_issuer_dn, ca2->cert_issuer_dn,
                    ca1->cert_issuer_dn_len) != 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("CA issuer names do not match"));
          return FALSE;
        }

      return TRUE;
    }

  if (ssh_cm_cert_get_ber(ca1->cert, &ber1, &ber1_length) != SSH_CM_STATUS_OK
      || ssh_cm_cert_get_ber(ca2->cert, &ber2, &ber2_length)
      != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Could not get BER for CA certificates"));
      return FALSE;
    }

  if (ber1_length != ber2_length || memcmp(ber1, ber2, ber1_length) != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("CA BER's do not match"));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("CAs match"));
  return TRUE;
}

SshCMCertificate
ssh_pm_cm_new_certificate(SshCMContext cm,
                          const unsigned char *cert, size_t cert_len,
                          Boolean external)
{
  SshCMCertificate cmcert;
  SshCMSearchConstraints search;
  SshCertDBKey *search_keys = NULL;
  SshCMCertList cert_list;
  SshCMStatus status;

  cmcert = ssh_cm_cert_allocate(cm);
  if (cmcert == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate CM certificate"));
      return NULL;
    }

  status = ssh_cm_cert_set_ber(cmcert, cert, cert_len);
  if (status != SSH_CM_STATUS_OK)
    {
      Boolean not_pem;
      unsigned char *ber;
      size_t ber_len;

      /* Decoding as binary data failed.  Let's try if the input was
         PEM encoded. */

      SSH_DEBUG(SSH_D_NICETOKNOW, ("BER decoding failed, trying PEM"));

      ber = ssh_pm_pem_to_binary(cert, cert_len, &ber_len, &not_pem);
      if (ber == NULL)
        {
          if (not_pem)
            {
              /* It was not PEM encoded. */
            could_not_decode:
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                            "Could not decode certificate.  "
                            "The certificate may be corrupted or it was "
                            "given in unrecognized format "
                            "(file format may be wrong)");
            }
          else
            {
              /* Out of memory. */
              SSH_DEBUG(SSH_D_ERROR,
                        ("Out of memory while decoding certificate"));
            }

          ssh_cm_cert_free(cmcert);
          return NULL;
        }

      /* Try to decode the certificate. */
      status = ssh_cm_cert_set_ber(cmcert, ber, ber_len);

      /* Free the decoded certificate data. */
      ssh_free(ber);

      if (status != SSH_CM_STATUS_OK)
        goto could_not_decode;
    }

  /* The certificate is now in `cmcert'. */

  /* Lock the certificate in the cache. */
  if (external == FALSE)
    {
      status = ssh_cm_cert_set_locked(cmcert);

      if (status != SSH_CM_STATUS_OK)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                      "Could not lock certificate in cache");
    }

  switch (ssh_cm_add(cmcert))
    {
    case SSH_CM_STATUS_OK:
      if (external == TRUE)
        ssh_cm_cert_take_reference(cmcert);

      return cmcert;

    case SSH_CM_STATUS_ALREADY_EXISTS:
      /* We have the certificate already in the cache.  Let's lookup
         the first occurrence and use it instead. */

      search = ssh_cm_search_allocate();
      if (search == NULL)
        {
          ssh_cm_cert_free(cmcert);
          return NULL;
        }

      if (!ssh_cm_key_set_cache_id(&search_keys,
                                   ssh_cm_cert_get_cache_id(cmcert)))
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not set cache ID for a certificate search"));
          ssh_cm_search_free(search);
          ssh_cm_cert_free(cmcert);
          return NULL;
        }

      /* We do not need the original cert anymore. */
      ssh_cm_cert_free(cmcert);

      ssh_cm_search_set_keys(search, search_keys);

      /* Find for the certificate. */
      status = ssh_cm_find_local_cert(cm, search, &cert_list);
      if (status != SSH_CM_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));
          return NULL;
        }

      /* Use the first certificate from the result list. */
      cmcert = ssh_cm_cert_list_first(cert_list);
      ssh_cm_cert_list_free(cm, cert_list);

      /* Take a reference to the certificate. */
      if (cmcert)
        ssh_cm_cert_take_reference(cmcert);

      /* Return the certificate (or NULL on error). */
      return cmcert;

    default:
      ssh_cm_cert_free(cmcert);
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                    "Could not insert certificate into local database");
      break;
    }

  return NULL;
}

void
ssh_pm_discard_public_key(SshCMContext cm, SshPublicKey public_key)
{
  SshCMSearchConstraints search;
  SshCertDBKey *keys = NULL;
  SshCMStatus status;
  SshCMCertList cert_list;
  SshCMCertificate cert;
#ifdef DEBUG_LIGHT
  SshUInt32 count = 0;
#endif /* DEBUG_LIGHT */

  /* Find all certificates with the given public key and unlock them.
     After that it is up to the certificate manager to remove them
     from its cache. */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Unlocking certificates"));

  search = ssh_cm_search_allocate();
  if (search == NULL)
    goto error;

  if (!ssh_cm_key_set_public_key(&keys, public_key))
    goto error;

  ssh_cm_search_set_keys(search, keys);

  /* Do find operation. */
  status = ssh_cm_find_local_cert(cm, search, &cert_list);
  if (status != SSH_CM_STATUS_OK)
    {
      if (status == SSH_CM_STATUS_NOT_FOUND)
        SSH_DEBUG(SSH_D_NICETOKNOW, ("Public key not found from database"));
      else
        SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));

      return;
    }

  /* Unlock all certificates. */
  for (cert = ssh_cm_cert_list_first(cert_list);
       cert;
       cert = ssh_cm_cert_list_next(cert_list))
    {
#ifdef DEBUG_LIGHT
      count++;
#endif /* DEBUG_LIGHT */
      ssh_cm_cert_set_unlocked(cert);
    }

  ssh_cm_cert_list_free(cm, cert_list);
  SSH_DEBUG(SSH_D_HIGHOK, ("Unlocked %u certificate%s",
                           (unsigned int) count, count == 1 ? "" : "s"));

  return;

  /* Error handling. */
 error:
  SSH_DEBUG(SSH_D_FAIL, ("Out of memory while searching for certificates"));
  if (search)
    ssh_cm_search_free(search);
}

Boolean
ssh_pm_cm_new_crl(SshCMContext cm, const unsigned char *crl,
                  size_t crl_len, Boolean external)
{
  SshCMCrl cmcrl;
  SshCMStatus status;

  cmcrl = ssh_cm_crl_allocate(cm);
  if (cmcrl == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate CM CRL"));
      return FALSE;
    }

  status = ssh_cm_crl_set_ber(cmcrl, crl, crl_len);
  if (status != SSH_CM_STATUS_OK)
    {
      Boolean not_pem;
      unsigned char *ber;
      size_t ber_len;

      /* Decoding as binary data failed.  Let's try if the input was
         PEM encoded. */

      SSH_DEBUG(SSH_D_NICETOKNOW, ("BER decoding failed, trying PEM"));

      ber = ssh_pm_pem_to_binary(crl, crl_len, &ber_len, &not_pem);
      if (ber == NULL)
        {
          if (not_pem)
            {
              /* It was not PEM encoded. */
            could_not_decode:
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                            "Could not decode CRL.  The certificate may be "
                            "corrupted or it was given in unrecognized format "
                            "(file format may be wrong)");
            }
          else
            {
              /* Out of memory. */
              SSH_DEBUG(SSH_D_ERROR, ("Out of memory while decoding CLR"));
            }

          /* Free the CMi CRL object. */
          ssh_cm_crl_free(cmcrl);

          return FALSE;
        }

      /* Try to decode the CRL. */
      status = ssh_cm_crl_set_ber(cmcrl, ber, ber_len);

      /* Free the decoded CRL data. */
      ssh_free(ber);

      if (status != SSH_CM_STATUS_OK)
        goto could_not_decode;
    }

  /* The CRL is now in `cmcrl'.  Add it to the certificate manager. */
  status = ssh_cm_add_crl(cmcrl);
  if (status == SSH_CM_STATUS_OK)
    {
      /* Lock the CRL in cache if this was not external */
      if (external == FALSE)
        ssh_cm_crl_set_locked(cmcrl);

      return TRUE;
    }

  /* Free the CRL since it was not added into the certificate
     manager. */
  ssh_cm_crl_free(cmcrl);

  if (status == SSH_CM_STATUS_ALREADY_EXISTS)
    /* The CRL was already in the cache. */
    return TRUE;

  /* Operation failed. */
  SSH_DEBUG(SSH_D_FAIL, ("Could not add CRL into certificate manager: %d",
                         status));
  return FALSE;
}

SshCMCertificate
ssh_pm_get_certificate_by_kid(SshPm pm, unsigned char *kid, size_t kid_len)
{
  SshCMSearchConstraints search = NULL;
  SshCertDBKey *local_keys = NULL;
  SshCMCertificate cmcert = NULL;
  SshCMCertList cert_list = NULL;
  SshCMStatus status;

  SSH_ASSERT(pm != NULL);
  SSH_ASSERT(kid != NULL);
  SSH_ASSERT(kid_len == 20);
  SSH_ASSERT(kid_len != 0);

  search = ssh_cm_search_allocate();
  if (search == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate search constraints"));
      goto error;
    }

  ssh_cm_key_set_x509_key_identifier(&local_keys, kid, kid_len);
  ssh_cm_search_set_keys(search, local_keys);

  /* Find for the certificate. */
  status = ssh_cm_find_local_cert(pm->default_auth_domain->cm,
                                  search, &cert_list);
  if (status != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));
      goto error;
    }

  /* And use the first one (if multiple given by CM). */
  cmcert = ssh_cm_cert_list_first(cert_list);
  ssh_cm_cert_list_free(pm->default_auth_domain->cm, cert_list);

 error:
  return cmcert;
}

Boolean
ssh_pm_get_certificate_kid(SshPm pm, const unsigned char *cert,
                           size_t cert_len, unsigned char **kid_ret,
                           size_t *kid_ret_len)
{
  SshCMCertificate cmcert = NULL;
  SshX509Certificate x509cert = NULL;
  SshCMStatus status;
  Boolean ret = FALSE;

  *kid_ret = NULL;
  *kid_ret_len = 0;

  cmcert = ssh_cm_cert_allocate(pm->default_auth_domain->cm);
  if (cmcert == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate CM certificate"));
      goto error;
    }

  status = ssh_cm_cert_set_ber(cmcert, cert, cert_len);
  if (status != SSH_CM_STATUS_OK)
    {
      Boolean not_pem;
      unsigned char *ber;
      size_t ber_len;

      /* Decoding as binary data failed.  Let's try if the input was
         PEM encoded. */

      SSH_DEBUG(SSH_D_NICETOKNOW, ("BER decoding failed, trying PEM"));

      ber = ssh_pm_pem_to_binary(cert, cert_len, &ber_len, &not_pem);
      if (ber == NULL)
        {
          if (not_pem)
            {
              /* It was not PEM encoded. */
            could_not_decode:
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                            "Could not decode certificate.  "
                            "The certificate may be corrupted or it was "
                            "given in unrecognized format "
                            "(file format may be wrong)");
            }
          else
            {
              /* Out of memory. */
              SSH_DEBUG(SSH_D_ERROR,
                        ("Out of memory while decoding certificate"));
            }

          goto error;
        }

      /* Try to decode the certificate. */
      status = ssh_cm_cert_set_ber(cmcert, ber, ber_len);

      /* Free the decoded certificate data. */
      ssh_free(ber);

      if (status != SSH_CM_STATUS_OK)
        goto could_not_decode;
    }

  if (ssh_cm_cert_get_x509(cmcert, &x509cert) != SSH_CM_STATUS_OK)
    goto error;

  *kid_ret = ssh_x509_cert_compute_key_identifier(x509cert,
                                                  SSH_CM_HASH_ALGORITHM,
                                                  kid_ret_len);
  if (*kid_ret == NULL)
    goto error;

  ret = TRUE;

 error:
  if (cmcert)
    ssh_cm_cert_free(cmcert);

  if (x509cert)
    ssh_x509_cert_free(x509cert);

  return ret;
}

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
