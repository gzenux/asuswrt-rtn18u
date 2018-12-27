/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate related IKE utility functions.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_CRYPT_ECP
#include "sshmp-integer.h"
#endif /* SSHDIST_CRYPT_ECP */

#define SSH_DEBUG_MODULE "SshPmUtilIkeCerts"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
/* Expand ID array `alts' with one slot.  The function returns TRUE if
   the operation is successful and false otherwise. */
static Boolean
ssh_pm_cert_names_alloc_id(SshIkev2PayloadID **alts, size_t *nalts)
{
  SshIkev2PayloadID *new_alts;

  new_alts = ssh_realloc(*alts, *nalts * sizeof(**alts),
                         (*nalts + 1) * sizeof(**alts));
  if (new_alts == NULL)
    return FALSE;

  *alts = new_alts;
  (*nalts)++;

  (*alts)[*nalts - 1] = ssh_calloc(1, sizeof(struct SshIkev2PayloadIDRec));
  if ((*alts)[*nalts - 1] == NULL)
    return FALSE;

  return TRUE;
}

SshIkev2PayloadID
ssh_pm_cert_x509_names(SshX509Certificate x509cert,
                       SshIkev2PayloadID **altnames, size_t *naltnames,
                       SshPublicKey *public_key_return)
{
  char *textname;
  unsigned char *der = NULL, *ipaddr = NULL;
  size_t textlen, nalts = 0, der_len, i;
  Boolean critical;
  SshIpAddrStruct addr;
  SshIkev2PayloadID subject = NULL, *alts = NULL;
  SshX509Name names;

  if (ssh_x509_cert_get_subject_name_der(x509cert, &der, &der_len))
    {
      subject = ssh_calloc(1, sizeof(*subject));
      if (subject == NULL)
        {
          ssh_free(der);
          der_len = 0;
          goto error;
        }

      subject->id_type = SSH_IKEV2_ID_TYPE_ASN1_DN;
      subject->id_data_size = der_len;
      subject->id_data = der;
    }

  if (altnames &&
      ssh_x509_cert_get_subject_alternative_names(x509cert, &names, &critical))
    {
      while (ssh_x509_name_pop_ip(names, &ipaddr, &textlen))
        {
          if (!ssh_pm_cert_names_alloc_id(&alts, &nalts))
            goto error;

          if (textlen == 4)
            SSH_IP4_DECODE(&addr, ipaddr);
          else if (textlen == 16)
            SSH_IP6_DECODE(&addr, ipaddr);
          else
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                            "Certificate contains bad IP address: length=%d",
                            textlen);
              ssh_free(alts[nalts - 1]);
              alts[nalts - 1] = NULL;
              continue;
            }

          if (textlen == 4)
            {
              alts[nalts - 1]->id_type = SSH_IKEV2_ID_TYPE_IPV4_ADDR;
              alts[nalts - 1]->id_data_size = 4;
              alts[nalts - 1]->id_data = ipaddr;
            }
          else
            {
              alts[nalts - 1]->id_type = SSH_IKEV2_ID_TYPE_IPV6_ADDR;
              alts[nalts - 1]->id_data_size = 16;
              alts[nalts - 1]->id_data = ipaddr;
            }
        }
      while (ssh_x509_name_pop_dns(names, &textname))
        {
          if (!ssh_pm_cert_names_alloc_id(&alts, &nalts))
            goto error;

          alts[nalts - 1]->id_type = SSH_IKEV2_ID_TYPE_FQDN;
          alts[nalts - 1]->id_data_size = strlen(textname);
          alts[nalts - 1]->id_data = (unsigned char *) textname;
        }
      while (ssh_x509_name_pop_email(names, &textname))
        {
          if (!ssh_pm_cert_names_alloc_id(&alts, &nalts))
            goto error;

          alts[nalts - 1]->id_type = SSH_IKEV2_ID_TYPE_RFC822_ADDR;
          alts[nalts - 1]->id_data_size = strlen(textname);
          alts[nalts - 1]->id_data = (unsigned char *) textname;
        }
      while (ssh_x509_name_pop_directory_name(names, &textname))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                        "Directory names are not supported as subject "
                        "alternative names.  Skipping DN `%s'.",
                        textname);
          ssh_free(textname);
        }

      *altnames = alts;
      *naltnames = nalts;
    }

  if (public_key_return)
    if (!ssh_x509_cert_get_public_key(x509cert, public_key_return))
      {
        SSH_DEBUG(SSH_D_FAIL,
                  ("Could not get public key from an X.509 certificate"));
        *public_key_return = NULL;
      }

  return subject;

 error:
  if (subject)
    {
      ssh_free(subject->id_data);
      ssh_free(subject);
    }

  if (ipaddr != NULL)
    {
      ssh_free(ipaddr);
    }

  for (i = 0; i < nalts; i++)
    {
      if (alts[i])
        ssh_free(alts[i]->id_data);
      ssh_free(alts[i]);
    }
  ssh_free(alts);
  return NULL;
}

SshIkev2PayloadID
ssh_pm_cert_names(const unsigned char *cert, size_t cert_len,
                  SshIkev2PayloadID **altnames, size_t *naltnames,
                  SshPublicKey *public_key_return)
{
  SshIkev2PayloadID subject = NULL;
  SshX509Certificate x509cert;
  SshX509Status status;

  if (naltnames) *naltnames = 0;
  if (altnames) *altnames = NULL;

  if (cert == NULL || cert_len == 0)
    return NULL;

  x509cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (x509cert == NULL)
    goto error;

  if (ssh_x509_cert_decode(cert, cert_len, x509cert) != SSH_X509_OK)
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
              /* FALLTHROUGH */
            }

          goto error;
        }

      /* Try to decode the certificate. */
      status = ssh_x509_cert_decode(ber, ber_len, x509cert);

      /* Free the decoded certificate data. */
      ssh_free(ber);

      if (status != SSH_X509_OK)
        goto could_not_decode;
    }

  subject = ssh_pm_cert_x509_names(x509cert,
                                   altnames, naltnames, public_key_return);

  ssh_x509_cert_free(x509cert);
  return subject;

  /* Error handling. */

 error:

  if (x509cert)
    ssh_x509_cert_free(x509cert);
  return NULL;
}

unsigned char *
ssh_pm_pem_to_binary(const unsigned char *data, size_t data_len,
                     size_t *len_return,
                     Boolean *not_pem_return)
{
  size_t base64_start;
  size_t base64_end;
  unsigned char *clean;
  size_t clean_len;
  unsigned char *ber;

  /* As a default, we assume it being valid PEM encoded data. */
  *not_pem_return = FALSE;

  /* Remove extra headers. */
  if (!ssh_base64_remove_headers(data, data_len, &base64_start, &base64_end))
    {
      *not_pem_return = TRUE;
      return NULL;
    }

  /* Remove whitespace. */
  clean = ssh_base64_remove_whitespace(data + base64_start,
                                       base64_end - base64_start);
  if (clean == NULL)
    {
      /* Out of memory. */
      return NULL;
    }

  /* Check if it is base64 encoded. */
  clean_len = strlen((char *)clean);
  if (ssh_is_base64_buf(clean, clean_len) != clean_len)
    {
      /* Not base64. */
      ssh_free(clean);
      *not_pem_return = TRUE;
      return NULL;
    }

  /* Decode base64. */
  ber = ssh_base64_to_buf(clean, len_return);

  /* We do not need the cleaned base64 blob anymore. */
  ssh_free(clean);

  /* Return the result.  It is either non-NULL binary data or NULL if
     we run out of memory. */
  return ber;
}

#ifdef SSHDIST_CRYPT_ECP
Boolean ssh_pm_get_key_scheme(void * object,
                              SshPmCmObjectType type,
                              const char ** scheme)
{
  const char *sig_scheme = NULL;
  SshCryptoStatus status = SSH_CRYPTO_OK;
  Boolean rv = FALSE;
  SshMPIntegerStruct p;
  size_t field_len;
  ssh_mprz_init(&p);

  switch (type)
    {
    case SSH_PM_CM_PUBLIC_KEY:
      {
        status = ssh_public_key_get_info((SshPublicKey)object,
                                         SSH_PKF_PRIME_P, &p,
                                         SSH_PKF_END);
        break;
      }

    case SSH_PM_CM_PRIVATE_KEY:
      {
        status = ssh_private_key_get_info((SshPrivateKey)object,
                                          SSH_PKF_PRIME_P, &p,
                                          SSH_PKF_END);
        break;
      }
    default:
      SSH_NOTREACHED;
    }

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to get information from %s",
                 type == SSH_PM_CM_PUBLIC_KEY ? "public key" :
                 "private key"));
      goto fail;
    }

  field_len = ssh_mprz_byte_size(&p);
  if (field_len == 32) /* 256 bit curve */
    {
#ifdef SSHDIST_CRYPT_SHA256
      sig_scheme = "dsa-none-sha256";
#endif /* SSHDIST_CRYPT_SHA256 */
    }
  else if (field_len == 48) /* 384 bit curve */
    {
#ifdef SSHDIST_CRYPT_SHA512
      sig_scheme = "dsa-none-sha384";
#endif /* SSHDIST_CRYPT_SHA512 */
    }
  else if (field_len == 66) /* 521 bit curve */
    {
#ifdef SSHDIST_CRYPT_SHA512
      sig_scheme = "dsa-none-sha512";
#endif /* SSHDIST_CRYPT_SHA512 */
    }
  *scheme = sig_scheme;
  if (sig_scheme != NULL)
    rv = TRUE;
fail:
  ssh_mprz_clear(&p);
  return rv;
}
#endif /* SSHDIST_CRYPT_ECP */
#endif /* SSHDIST_CERT */

void
ssh_pm_cert_request_result_free(SshPmCertReqResult r, SshUInt32 num_cas)
{
  int ca, i;

  if (r == NULL)
    return;

  for (ca = 0; ca < num_cas; ca++)
    {
      for (i = 0; i < r->number_of_certificates[ca]; i++)
        ssh_free(r->certs[ca][i]);

      ssh_free(r->cert_encodings[ca]);
      ssh_free(r->certs[ca]);
      ssh_free(r->cert_lengths[ca]);
    }

  ssh_free(r->number_of_certificates);
  ssh_free(r->cert_encodings);
  ssh_free(r->certs);
  ssh_free(r->cert_lengths);

  ssh_free(r);
}
#endif /* SSHDIST_IKE_CERT_AUTH */
