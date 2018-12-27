/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate related API routines for the validator.
*/

#include "sshincludes.h"
#include "cmi.h"
#include "cmi-internal.h"
#include "ssh_berfile.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertCMi"

/************ CM Certificate handling ************/

SshCMCertificate ssh_cm_cert_allocate(SshCMContext cm)
{
  SshCMCertificate cert;

  SSH_ASSERT(cm != NULL);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocate certificate."));

  if ((cert = ssh_calloc(1, sizeof(*cert))) != NULL)
    {
      if ((cert->cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) == NULL)
        {
          ssh_free(cert);
          return NULL;
        }

      /* Initialize */
      cert->cm = cm;
      cert->status_flags = 0;

      /* Set the initialization flags always to zero, before any operation. */
      cert->initialization_flags = 0;

      /* Clean the structures. */
      cert->entry      = NULL;
      cert->ber        = NULL;
      cert->ber_length = 0;

      if (cert->cert == NULL)
        {
          ssh_free(cert);
          return NULL;
        }

      cert->private_data            = NULL;
      cert->private_data_destructor = NULL_FNPTR;

      /* This flag is always set on for new certificates. */
      cert->not_checked_against_crl = TRUE;

      /* Set the trustedness and CRL info. */
      ssh_cm_trust_init(cert);

      /* Set up the CRL information. */
      cert->crl_issuer   = TRUE;
      cert->crl_user     = TRUE;
      cert->self_signed  = 0;
      cert->self_issued  = 0;
      ssh_ber_time_zero(&cert->crl_recompute_after);
#ifdef SSHDIST_VALIDATOR_OCSP
      ssh_ber_time_zero(&cert->ocsp_valid_not_before);
      ssh_ber_time_zero(&cert->ocsp_valid_not_after);
#endif /* SSHDIST_VALIDATOR_OCSP */

      /* Set up the flag indicating whether this is a CA (in X.509v1). */
      cert->acting_ca    = FALSE;

      /* Revocation information. */
      cert->status = SSH_CM_VS_OK;
      cert->revocator_was_trusted = FALSE;
    }
  return cert;
}

void ssh_cm_cert_free(SshCMCertificate cert)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Free certificate."));

  if (cert == NULL)
    /* Remove the entry? */
    return;

  if (cert->private_data != NULL)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Calling the private data destructor"
                                  " in certificate free."));
      if (cert->private_data_destructor)
        (*cert->private_data_destructor)(cert, cert->private_data);
      cert->private_data_destructor = NULL_FNPTR;
      cert->private_data            = NULL;
    }

  if (cert->entry != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Tried to free certificate at the database."));
      return;
    }

  ssh_cm_trust_clear(cert);

  /* Free the current certificate. */
  ssh_free(cert->ber);
  ssh_x509_cert_free(cert->cert);
  ssh_free(cert);
}

void ssh_cm_cert_remove(SshCMCertificate cert)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Removing certificate from the cache."));

  if (cert == NULL)
    return;

  if (cert->entry == NULL)
    {
      ssh_cm_cert_free(cert);
      return;
    }

  /* Remove the certificate. */
  if (!ssh_cm_cert_is_locked(cert))
    ssh_certdb_take_reference(cert->entry);

  ssh_certdb_remove_entry(cert->cm->db, cert->entry);
}

void ssh_cm_cert_take_reference(SshCMCertificate cert)
{
  if (cert->entry == NULL)
    return;
  ssh_certdb_take_reference(cert->entry);
}

void ssh_cm_cert_remove_reference(SshCMCertificate cert)
{
  if (cert->entry == NULL)
    return;
  ssh_certdb_release_entry(cert->cm->db, cert->entry);
}

unsigned int ssh_cm_cert_get_cache_id(SshCMCertificate cert)
{
  unsigned int entry_id;

  if (cert->entry == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Search for the entry identifier."));

      /* The certificate is not itself available thru cache search,
         however, there may be the exactly same certificate. We try to
         return the cache identifier if such certificate exists. */
      ssh_cm_check_db_collision(cert->cm, SSH_CM_DATA_TYPE_CERTIFICATE,
                                cert->ber, cert->ber_length,
                                NULL, &entry_id);

    }
  else
    entry_id = cert->entry->id;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Certificate serial %@ entry identifier %d.",
             ssh_cm_render_mp, &cert->cert->serial_number,
             entry_id));
  return entry_id;
}

Boolean
ssh_cm_cert_check_signature_algorithm(SshCMConfig config, const char *sign)
{

static const SshKeywordStruct alg_table[] =
  {
    {"rsa-pkcs1-sha224", SSH_CMI_HASH_SHA2_224 },
    {"rsa-pkcs1-sha256", SSH_CMI_HASH_SHA2_256 },
    {"rsa-pkcs1-sha384", SSH_CMI_HASH_SHA2_384 },
    {"rsa-pkcs1-sha512", SSH_CMI_HASH_SHA2_512 },
    {"rsa-pkcs1-sha1", SSH_CMI_HASH_SHA1 },
    {"rsa-pkcs1-md5", SSH_CMI_HASH_MD5 },
    {"rsa-pss-sha1", SSH_CMI_HASH_SHA1 },
    {"dsa-nist-sha1", SSH_CMI_HASH_SHA1 },
    {"dsa-nist-sha224", SSH_CMI_HASH_SHA2_224 },
    {"dsa-nist-sha256", SSH_CMI_HASH_SHA2_256 },
    {"dsa-nist-sha384", SSH_CMI_HASH_SHA2_384 },
    {"dsa-nist-sha512", SSH_CMI_HASH_SHA2_512 },
    {"dsa-none-sha1", SSH_CMI_HASH_SHA1 },
    {"dsa-none-sha224", SSH_CMI_HASH_SHA2_224 },
    {"dsa-none-sha256", SSH_CMI_HASH_SHA2_256 },
    {"dsa-none-sha384", SSH_CMI_HASH_SHA2_384 },
    {"dsa-none-sha512", SSH_CMI_HASH_SHA2_512 },
    /* Other signing algorithms not considered. */
    { NULL, 0 }
  };
  int id;

  if (config->allowed_hash_functions == SSH_CMI_HASH_ANY)
    return TRUE;

  if (sign == NULL)
    return FALSE;

  id = ssh_find_keyword_number(alg_table, sign);
  if (id == -1)
    return FALSE;

  if ((config->allowed_hash_functions & id) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Signature algorithm %s not allowed.",
                 sign));
      return FALSE;
    }

  return TRUE;
}

Boolean
ssh_cm_cert_check_key_length(SshCMConfig config, SshPublicKey pub)
{
  unsigned int key_size = 0;
  const char *key_type = NULL;
  int key = 0;

  if (config->allowed_keys == (SSH_CMI_KEY_DSA_ANY | SSH_CMI_KEY_RSA_ANY |
                               SSH_CMI_KEY_ECC_ANY))
      return TRUE;

  if (ssh_public_key_get_info(pub,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;

  if (ssh_public_key_get_info(pub,
                             SSH_PKF_SIZE, &key_size,
                             SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;

  SSH_DEBUG(SSH_D_MY, ("key_size %d, key_type %s", key_size, key_type));

  if (strcmp(key_type, "if-modn") == 0)
    {
      if (key_size < 1024)
        key = SSH_CMI_KEY_RSA_1023;
      else if (key_size < 2048)
        key = SSH_CMI_KEY_RSA_2047;
      else if (key_size < 3072)
        key = SSH_CMI_KEY_RSA_3071;
      else if (key_size < 4096)
        key = SSH_CMI_KEY_RSA_4095;
      else if  (key_size < 8192)
        key = SSH_CMI_KEY_RSA_8191;
      else
        key = SSH_CMI_KEY_RSA_8192;
    }
  else if (strcmp(key_type, "dl-modp") == 0)
    {
     if (key_size < 1024)
        key = SSH_CMI_KEY_DSA_1023;
      else if (key_size < 2048)
        key = SSH_CMI_KEY_DSA_2047;
      else if (key_size < 3072)
        key = SSH_CMI_KEY_DSA_3071;
      else
        key = SSH_CMI_KEY_DSA_3072;
    }
  else if (strcmp(key_type, "ec-modp") == 0)
    {
     if (key_size < 224)
        key = SSH_CMI_KEY_ECC_223;
      else if (key_size < 256)
        key = SSH_CMI_KEY_ECC_255;
      else if (key_size < 384)
        key = SSH_CMI_KEY_ECC_383;
      else if (key_size < 512)
        key = SSH_CMI_KEY_ECC_511;
      else if (key_size < 769)
        key = SSH_CMI_KEY_ECC_768;
    }

  SSH_DEBUG(SSH_D_MY, ("config->allowed_keys %#8x, key %#8x",
                       config->allowed_keys, key));
  if ((config->allowed_keys & key) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("%s key with size %u not allowed",
                 key_type, key_size));
      return FALSE;
    }

  return TRUE;
}

Boolean
ssh_cm_cert_check_allowed_algorithms(SshCMConfig config,
                                     SshX509Certificate cert)
{
  if ((ssh_cm_cert_check_key_length(config, cert->subject_pkey.public_key)
       == FALSE) ||
      (ssh_cm_cert_check_signature_algorithm(
                                             config,
                                             cert->pop.signature.pk_algorithm)
       == FALSE))
    return FALSE;

  return TRUE;
}

SshCMStatus
ssh_cm_cert_allowed_algorithms(SshCMContext cm, SshX509Certificate cert)
{
  if (cm == NULL ||
      ssh_cm_cert_check_allowed_algorithms(cm->config, cert) != TRUE)
    return SSH_CM_STATUS_FAILURE;

  return SSH_CM_STATUS_OK;
}

SshCMStatus
ssh_cm_cert_define_trusted(SshCMCertificate c,
                           SshX509Name name, SshPublicKey key)
{
  SshStr str;
  SshBerTimeStruct v_start[1], v_end[1];

  c->is_ca = 1;
  c->self_issued = 1;
  if ((c->ber = ssh_memdup(name->ber, name->ber_len)) == NULL)
    return SSH_CM_STATUS_FAILURE;
  c->ber_length = name->ber_len;

  ssh_x509_name_pop_str_dn(name, &str);
  ssh_x509_cert_set_issuer_name_str(c->cert, str);
  ssh_x509_cert_set_subject_name_str(c->cert, str);
  ssh_str_free(str);

  ssh_x509_cert_set_public_key(c->cert, key);
  ssh_x509_cert_set_basic_constraints(c->cert, 50, TRUE, TRUE);
  ssh_ber_time_set_from_unix_time(v_start, (SshTime)0);
  ssh_ber_time_set_from_unix_time(v_end, (SshTime)0xffffffff);

  ssh_x509_cert_set_validity(c->cert, v_start, v_end);

  ssh_cm_trust_make_root(c, NULL);

  return SSH_CM_STATUS_OK;
}


SshCMStatus ssh_cm_cert_set_ber(SshCMCertificate c,
                                const unsigned char *ber,
                                size_t ber_length)
{
  SshBERFile bf;
  Boolean ca, critical;
  size_t cert_path_len;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Set certificate in ber."));

  if (c->ber != NULL)
    return SSH_CM_STATUS_FAILURE;

  if (c->cm &&
      ber_length > c->cm->config->max_certificate_length)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Certificate (%zd bytes) too long (max %zd bytes)",
                 ber_length, c->cm->config->max_certificate_length));
      return SSH_CM_STATUS_FAILURE;
    }

  if (ssh_ber_file_create(ber, ber_length, &bf) != SSH_BER_FILE_ERR_OK)
    return SSH_CM_STATUS_FAILURE;

  ber_length -= ssh_ber_file_get_free_space(bf);
  ssh_ber_file_destroy(bf);

  /* Start up the certificate. */
  if (ssh_x509_cert_decode(ber, ber_length, c->cert) != SSH_X509_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Certificate decoding in X.509 library failed."));
      return SSH_CM_STATUS_DECODE_FAILED;
    }

  if (ssh_x509_cert_get_basic_constraints(c->cert,
                                          &cert_path_len,
                                          &ca, &critical) && ca)
    c->is_ca = 1;

  /* Copy the BER encoded part too. */
  c->ber_length = 0;
  if ((c->ber = ssh_memdup(ber, ber_length)) != NULL)
    c->ber_length = ber_length;

  if (cm_verify_issuer_name(c, c))
    c->self_issued = 1;

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_force_trusted(SshCMCertificate c)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Force the certificate trusted."));
  if (ssh_cm_trust_is_root(c, NULL) == TRUE)
    SSH_DEBUG(SSH_D_LOWOK, ("Certificate is already trusted root."));

  if (c->entry != NULL)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Caution! Certificate status changed to trusted root."));
  /* Force as the trusted root, and just ordinary trusted too. */
  if (c->entry)
    {
      ssh_cm_cert_set_class(c, SSH_CM_CCLASS_TRUSTED);
      ssh_cm_trust_make_root(c, NULL);
      c->initialization_flags &= (~SSH_CM_CERT_IF_TRUSTED);
    }
  else
    {
      c->initialization_flags |= SSH_CM_CERT_IF_TRUSTED;
    }

  /* Also lock the certificate into cache. */
  ssh_cm_cert_set_locked(c);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_force_untrusted(SshCMCertificate c)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Force the certificate to untrusted state."));
  /* Force as untrusted root certificate. In this case you must
     make it untrusted also. */

  ssh_cm_trust_make_user(c, NULL);

  if (c->entry)
    ssh_cm_cert_set_class(c, SSH_CM_CCLASS_DEFAULT);
  else
    c->initialization_flags &= (~SSH_CM_CERT_IF_TRUSTED);

  /* Unlock the certificate. */
  ssh_cm_cert_set_unlocked(c);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_non_crl_issuer(SshCMCertificate c)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Assume the certificate not to issue CRLs."));
  if (c->entry != NULL)
    SSH_DEBUG(SSH_D_FAIL, ("Caution! Certificate is no longer a CRL issuer."));
  c->crl_issuer = FALSE;
  ssh_ber_time_zero(&c->crl_recompute_after);
  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_make_crl_issuer(SshCMCertificate c)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("The certificate is now CRL issuer."));
  c->crl_issuer = TRUE;
  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_non_crl_user(SshCMCertificate c)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Assume the certificate not to user CRLs."));
  if (c->entry != NULL)
    SSH_DEBUG(SSH_D_FAIL, ("Caution! Certificate is no longer a CRL user."));
  c->crl_user = FALSE;
  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_make_crl_user(SshCMCertificate c)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("The certificate is now CRL user."));
  c->crl_user = TRUE;
  return SSH_CM_STATUS_OK;
}

void ssh_cm_cert_set_trusted_set(SshCMCertificate c,
                                 SshMPInteger trusted_set)
{
  SSH_ASSERT(trusted_set != NULL && c != NULL);

  /* Remark. This function in theory could be used by "malicious" programs
     to create problems. Of course, in practice such a program can do this
     by setting the certificate trusted root and thus avoid this check.
     Anyway, there is practically no reason whatsoever to set this field
     for non-root certificates.

     If you find such use please inform us at SSH. */

  if (!c->trusted.trusted_root &&
      !(c->initialization_flags & SSH_CM_CERT_IF_TRUSTED))
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("Attempt to force trusted set failed. "
                                  "The certificate is not a trusted root."));
      return;
    }

  ssh_mprz_set(&c->trusted.trusted_set, trusted_set);
}

/* The return value MUST not be freed, such an operation would lead
   to mallocation error. */
SshMPInteger ssh_cm_cert_get_trusted_set(SshCMCertificate c)
{
  SSH_ASSERT(c != NULL);
  return &c->trusted.trusted_set;
}

void ssh_cm_cert_set_trusted_not_after(SshCMCertificate c,
                                       SshBerTime trusted_not_after)
{
  SSH_ASSERT(c != NULL);
  if (!c->trusted.trusted_root)
    return;
  ssh_ber_time_set(&c->trusted.trusted_not_after, trusted_not_after);
}

void
ssh_cm_cert_set_path_length(SshCMCertificate c, size_t path_length)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Set the path length for the certificate."));
  c->trusted.path_length = path_length;
}

SshCMStatus ssh_cm_cert_set_private_data(SshCMCertificate c,
                                         void *private_context,
                                         SshCMPrivateDataDestructor destructor)
{
  if (c->private_data != NULL)
    {
      if (c->private_data_destructor)
        (*c->private_data_destructor)(c, c->private_data);
      c->private_data_destructor = NULL_FNPTR;
      c->private_data            = NULL;
    }
  c->private_data_destructor = destructor;
  c->private_data            = private_context;
  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_get_private_data(SshCMCertificate c,
                                         void **private_context)
{
  *private_context = c->private_data;
  if (c->private_data == NULL)
    return SSH_CM_STATUS_FAILURE;
  return SSH_CM_STATUS_OK;
}

#ifdef SSHDIST_VALIDATOR_OCSP
#ifndef SSHDIST_VALIDATOR_HTTP
SshCMStatus ssh_cm_cert_get_inspection_data(SshCMCertificate c,
                                            SshOcspResponse *ocsp)
{
  if (ocsp) *ocsp = c->inspection.ocsp;
  return SSH_CM_STATUS_OK;
}
#endif /* SSHDIST_VALIDATOR_HTTP */
#endif /* SSHDIST_VALIDATOR_OCSP */

SshCMStatus ssh_cm_cert_get_subject_keys(SshCMCertificate c,
                                         SshCertDBKey **keys)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get certificate subject keys."));

  if (ssh_cm_key_set_from_cert(keys, SSH_CM_KEY_CLASS_SUBJECT, c))
    return SSH_CM_STATUS_OK;
  else
    return SSH_CM_STATUS_FAILURE;
}

SshCMStatus ssh_cm_cert_get_issuer_keys(SshCMCertificate c,
                                        SshCertDBKey **keys)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get certificiate issuer keys."));

  if (ssh_cm_key_set_from_cert(keys, SSH_CM_KEY_CLASS_ISSUER, c))
    return SSH_CM_STATUS_OK;
  else
    return SSH_CM_STATUS_FAILURE;
}

/* Return opened certificate. Convenience function. */
SshCMStatus ssh_cm_cert_get_x509(SshCMCertificate c,
                                 SshX509Certificate *cert)
{
  Boolean critical;
  SshX509Name names;

  SSH_DEBUG(SSH_D_MIDOK, ("Get certificate X.509 opened form."));

  ssh_x509_name_reset(c->cert->subject_name);
  if (ssh_x509_cert_get_subject_alternative_names(c->cert, &names, &critical))
    ssh_x509_name_reset(names);
  ssh_x509_name_reset(c->cert->issuer_name);
  if (ssh_x509_cert_get_issuer_alternative_names(c->cert, &names, &critical))
    ssh_x509_name_reset(names);

  ssh_x509_cert_take_ref(c->cert);
  *cert = c->cert;

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_get_ber(SshCMCertificate c,
                                unsigned char **ber, size_t *ber_length)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get certificate ber/der encoding."));

  if (c == NULL)
    return SSH_CM_STATUS_FAILURE;
  if (c->ber == NULL)
    return SSH_CM_STATUS_FAILURE;

  *ber        = c->ber;
  *ber_length = c->ber_length;
  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_get_computed_validity(SshCMCertificate c,
                                              SshBerTime not_before,
                                              SshBerTime not_after)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get validity of the certificate."));
  /* Check the trustedness flag. */
  if (ssh_cm_trust_check(c, NULL, NULL) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The certificate is not trusted."));
      return SSH_CM_STATUS_FAILURE;
    }

  /* Check that the validity times exist. */
  if (ssh_ber_time_available(&c->trusted.valid_not_before) == FALSE ||
      ssh_ber_time_available(&c->trusted.valid_not_after)  == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("The certificate has no validity time available."));
      return SSH_CM_STATUS_FAILURE;
    }

  if (not_before)
    ssh_ber_time_set(not_before, &c->trusted.valid_not_before);
  if (not_after)
    ssh_ber_time_set(not_after,  &c->trusted.valid_not_after);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_get_computed_time(SshCMCertificate c,
                                          SshBerTime computed)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Get the computed time in certificate."));

  if (computed)
    {
      /* Check the trustedness flag. */
      if (ssh_cm_trust_check(c, NULL, NULL) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("The certificate is not trusted."));
          return SSH_CM_STATUS_FAILURE;
        }

      /* Check if the time information is available. */
      if (ssh_ber_time_available(&c->trusted.trusted_computed) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Trust computation time is not available."));
          return SSH_CM_STATUS_FAILURE;
        }

      ssh_ber_time_set(computed, &c->trusted.trusted_computed);
      return SSH_CM_STATUS_OK;
    }
  return SSH_CM_STATUS_FAILURE;
}

/* Following functions '*_is_*' functions return FALSE if the certificate
   is not trusted. This guards from certain problems, however, should this
   be handled by the application? */

Boolean ssh_cm_cert_is_trusted_root(SshCMCertificate c)
{
  if (c->initialization_flags & SSH_CM_CERT_IF_TRUSTED)
    return TRUE;
  return ssh_cm_trust_is_root(c, NULL);
}

Boolean ssh_cm_cert_is_crl_issuer(SshCMCertificate c)
{
  return c->crl_issuer;
}

Boolean ssh_cm_cert_is_crl_user(SshCMCertificate c)
{
  return c->crl_user;
}

Boolean ssh_cm_cert_is_revoked(SshCMCertificate c)
{
  if (ssh_cm_trust_check(c, NULL, NULL) == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Claiming the input certificate to be revoked, "
                              "because it is not trusted at the moment."));
      return TRUE;
    }
  return (c->status == SSH_CM_VS_OK) ? TRUE : FALSE;
}

/* Functions which need the availability of CM context. This is a burden
   you need when looking down to the cache level. */

SshCMStatus ssh_cm_cert_set_locked(SshCMCertificate c)
{
  unsigned int limit = ~((unsigned int)0);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("The certificate will become permament in the cache."));

  if (c == NULL)
    return SSH_CM_STATUS_FAILURE;

  if (c->entry == NULL)
    {
      c->initialization_flags |= SSH_CM_CERT_IF_LOCKED;
      return SSH_CM_STATUS_OK;
    }

  if (c->cm == NULL || c->cm->db == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Certificate manager not initialized."));
      return SSH_CM_STATUS_FAILURE;
    }

  /* Clear initialization flags, just in case. */
  c->initialization_flags &= (~SSH_CM_CERT_IF_LOCKED);

  /* Set the certificate as permanent. */
  ssh_certdb_set_option(c->cm->db, c->entry,
                        SSH_CERTDB_OPTION_MEMORY_LOCK, &limit);

  /* Set the class of the certificate. */
  ssh_cm_cert_set_class(c, SSH_CM_CCLASS_LOCKED);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_cert_set_unlocked(SshCMCertificate c)
{
  unsigned int limit = 0;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("The certificate will be unlocked from the cache."));

  if (c == NULL)
    return SSH_CM_STATUS_FAILURE;

  if (c->entry == NULL)
    {
      c->initialization_flags &= (~SSH_CM_CERT_IF_LOCKED);
      return SSH_CM_STATUS_OK;
    }

  if (c->cm == NULL || c->cm->db == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Certificate manager not initialized."));
      return SSH_CM_STATUS_FAILURE;
    }

  /* Set the certificate as permanent. */
  ssh_certdb_set_option(c->cm->db, c->entry,
                        SSH_CERTDB_OPTION_MEMORY_LOCK, &limit);

  /* Move back to the default class. */
  ssh_cm_cert_set_class(c, SSH_CM_CCLASS_DEFAULT);

  return SSH_CM_STATUS_OK;
}

Boolean ssh_cm_cert_is_locked(SshCMCertificate c)
{
  unsigned int limit;

  if (c->initialization_flags &= SSH_CM_CERT_IF_LOCKED)
    return TRUE;

  if (c->entry == NULL)
    return FALSE;

  if (ssh_certdb_get_option(c->cm->db, c->entry, SSH_CERTDB_OPTION_MEMORY_LOCK,
                            &limit) != SSH_CDBET_OK)
    return FALSE;

  if (limit == 0)
    return FALSE;

  return TRUE;
}

/* Derive the CM Context. */

SshCMContext ssh_cm_cert_derive_cm_context(SshCMCertificate c)
{
  return c->cm;
}


/* Handle the class functions. */

/* Change the class of a certificate. */

#define SSH_CM_REAL_CLASS(app_class) \
  (((app_class) == SSH_CM_CCLASS_INVALID) \
   ? ((int)-1) \
   : ((int)((unsigned int)(app_class) + 3)))

#define SSH_CM_APP_CLASS(real_class) \
  (((real_class) == -1) \
   ? SSH_CM_CCLASS_INVALID \
   : ((unsigned int)((real_class) - 3)))

SshCMStatus ssh_cm_cert_set_class(SshCMCertificate c,
                                  unsigned int app_class)
{
  int real_class = SSH_CM_REAL_CLASS(app_class);

  /* Check the class number. */
  if (real_class > SSH_CM_REAL_CLASS(SSH_CM_CCLASS_MAX))
    return SSH_CM_STATUS_CLASS_TOO_LARGE;

  /* Change the class of the certificate. */
  if (ssh_cm_trust_is_root(c, NULL))
    return SSH_CM_STATUS_CLASS_UNCHANGED;

  /* Set the real class. */
  ssh_certdb_set_entry_class(c->cm->db, c->entry,
                             real_class);
  return SSH_CM_STATUS_OK;
}

unsigned int ssh_cm_cert_get_class(SshCMCertificate c)
{
  return SSH_CM_APP_CLASS(ssh_certdb_get_entry_class(c->cm->db, c->entry));
}

unsigned int ssh_cm_cert_get_next_class(SshCMContext cm,
                                        unsigned int app_class)
{
  unsigned int real_class = SSH_CM_REAL_CLASS(app_class);
  /* Check the class number. */
  if (real_class > SSH_CM_REAL_CLASS(SSH_CM_CCLASS_MAX))
    return SSH_CM_STATUS_CLASS_TOO_LARGE;
  return
    SSH_CM_APP_CLASS(ssh_certdb_get_next_entry_class(cm->db, real_class));
}

SshCMStatus
ssh_cm_cert_enumerate_class(SshCMContext cm,
                            unsigned int app_class,
                            SshCMCertEnumerateCB callback, void *context)
{
  SshCertDBEntry *entry;
  unsigned int real_class = SSH_CM_REAL_CLASS(app_class);

  /* Check the class number. */
  if (real_class > SSH_CM_REAL_CLASS(SSH_CM_CCLASS_MAX))
    return SSH_CM_STATUS_CLASS_TOO_LARGE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enumerate certificate class."));

  /* Check the callback. */
  if (callback == NULL_FNPTR)
    return SSH_CM_STATUS_FAILURE;

  /* Initialize the loop. */
  entry = NULL;
  do
    {
      entry = ssh_certdb_iterate_entry_class(cm->db, real_class, entry);
      /* Now study the entry closer. */
      if (entry != NULL && entry->tag == SSH_CM_DATA_TYPE_CERTIFICATE)
        {
          SshCMCertificate cm_cert;

          /* Get the certificate. */
          cm_cert = entry->context;

          /* Call the callback. */
          (*callback)(cm_cert, context);
        }
    }
  while (entry != NULL);

  return SSH_CM_STATUS_OK;
}


/* Check whether the certificate has a been previously added to the
   database. */
Boolean ssh_cm_cert_check_db_collision(SshCMContext cm,
                                       SshCMCertificate cm_cert,
                                       SshCertDBKey **key)
{
  return ssh_cm_check_db_collision(cm, SSH_CM_DATA_TYPE_CERTIFICATE,
                                   cm_cert->ber, cm_cert->ber_length,
                                   key, NULL);
}

SshCMStatus ssh_cm_add_with_bindings(SshCMCertificate cert,
                                     SshCertDBKey *bindings)
{
  SshCertDBEntry *entry;
  SshCMContext cm;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Certificate add to local database/memory cache."));

  if (cert == NULL)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_FAILURE;
    }
  cm = cert->cm;

  if (cm == NULL || cm->db == NULL)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_FAILURE;
    }

  if (cm->config->local_db_writable == FALSE)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_FAILURE;
    }

  /* Allocate a new entry. */
  if (ssh_certdb_alloc_entry(cm->db,
                             SSH_CM_DATA_TYPE_CERTIFICATE,
                             cert,
                             &entry) != SSH_CDBET_OK)
    {
      ssh_certdb_key_free(bindings);
      return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Explicit certificate: %@",
             ssh_cm_render_certificate, cert->cert));

  /* Check for collision in the database. Be a optimist anyway... */
  if (ssh_cm_cert_check_db_collision(cm, cert, &entry->names))
    {
      /* Prevent database from freeing the Cert */
      entry->context = NULL;
      /* Free the entry allocated. */
      ssh_certdb_release_entry(cm->db, entry);
      ssh_certdb_key_free(bindings);

      SSH_DEBUG(SSH_D_HIGHOK, ("Certificate exists already in the database."));

      return SSH_CM_STATUS_ALREADY_EXISTS;
    }

  /* Initialize the entry. */
  cert->entry = entry;

  if (!ssh_cm_key_set_from_cert(&entry->names, SSH_CM_KEY_CLASS_SUBJECT, cert))
    {
      /* Prevent database from freeing the Cert */
      entry->context = NULL;
      ssh_certdb_release_entry(cm->db, entry);
      ssh_certdb_key_free(bindings);
      cert->entry = NULL;
      return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
    }

  if (bindings)
    ssh_certdb_entry_add_keys(cm->db, entry, bindings);

  /* Add to the database. */
  if (ssh_certdb_add(cm->db, entry) != SSH_CDBET_OK)
    {
      /* Prevent database from freeing the Cert */
      entry->context = NULL;
      ssh_certdb_release_entry(cm->db, entry);

      SSH_DEBUG(SSH_D_FAIL,
                ("Local database/memory cache denies the addition."));
      return SSH_CM_STATUS_COULD_NOT_ALLOCATE;
    }

  /* Handle now the initialization flags of the certificate. */
  if (cert->initialization_flags & SSH_CM_CERT_IF_LOCKED)
    ssh_cm_cert_set_locked(cert);
  if (cert->initialization_flags & SSH_CM_CERT_IF_TRUSTED)
    ssh_cm_cert_force_trusted(cert);

  /* Release the entry. */
  ssh_certdb_release_entry(cm->db, entry);

  return SSH_CM_STATUS_OK;
}

SshCMStatus ssh_cm_add(SshCMCertificate cm_cert)
{
  return ssh_cm_add_with_bindings(cm_cert, NULL);
}
#endif /* SSHDIST_CERT */
