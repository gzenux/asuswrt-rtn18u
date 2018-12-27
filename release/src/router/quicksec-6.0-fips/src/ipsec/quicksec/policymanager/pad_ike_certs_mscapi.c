/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKE policy manager function calls related to certificates.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkeCerts"

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_MSCAPI
#ifdef WITH_MSCAPI

/***************************** Get Certificate Authorities *******************/

SshOperationHandle
ssh_pm_ike_get_cas(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2PadGetCAsCB reply_callback,
                   void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  SshPmAuthDomain ad = NULL;
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshIkev2CertEncoding ca_encoding = SSH_IKEV2_CERT_X_509;
  const unsigned char *ca_authority_data;
  size_t ca_authority_size;
  SshBufferStruct buffer[1];
  SshUInt32 i;

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is not active when trying to get CAs"));
      error_code = SSH_IKEV2_ERROR_SUSPENDED;
      goto error;
    }

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_FAIL, ("PM is going down when trying to get CAs"));
      error_code = SSH_IKEV2_ERROR_GOING_DOWN;
      goto error;
    }

  /* Ignore request if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Ignoring get certificate authorities request received "
                 "outside IKE negotiation"));
      goto error;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));
  SSH_PM_ASSERT_P1N(p1);

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

  if (ad->num_cas == 0)
    goto error;

#ifdef SSHDIST_IKEV1
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
    {
      SshIkev2CertEncoding *ikev1_ca_encodings = NULL;
      unsigned char **ikev1_ca_authority_data = NULL;
      size_t *ikev1_ca_authority_size = NULL;

      /* IKEv1: use the DER-encoded issuer names of CA certificates. */

      ikev1_ca_encodings = ssh_calloc(ad->num_cas,
                                      sizeof(SshIkev2CertEncoding));
      ikev1_ca_authority_data = ssh_calloc(ad->num_cas,
                                           sizeof(unsigned char *));
      ikev1_ca_authority_size = ssh_calloc(ad->num_cas, sizeof(size_t));

      if (!ikev1_ca_encodings || !ikev1_ca_authority_data ||
          !ikev1_ca_authority_size)
        {
          if (ikev1_ca_encodings)
            ssh_free(ikev1_ca_encodings);
          if (ikev1_ca_authority_data)
            ssh_free(ikev1_ca_authority_data);
          if (ikev1_ca_authority_size)
            ssh_free(ikev1_ca_authority_size);
          error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }

      for (i = 0; i < ad->num_cas; i++)
        {
          SshPmCa ca = ad->cas[i];

          ikev1_ca_encodings[i] = SSH_IKEV2_CERT_X_509;
          ikev1_ca_authority_data[i] = ca->cert_issuer_dn;
          ikev1_ca_authority_size[i] = ca->cert_issuer_dn_len;
        }

      SSH_DEBUG(SSH_D_MIDOK, ("Returning %d CA's for IKEv1 SA to the IKE "
                              "library", ad->num_cas));

      (*reply_callback)(SSH_IKEV2_ERROR_OK,
                        ad->num_cas,
                        ikev1_ca_encodings,
                        (const unsigned char **)ikev1_ca_authority_data,
                        ikev1_ca_authority_size,
                        reply_callback_context);

      ssh_free(ikev1_ca_encodings);
      ssh_free(ikev1_ca_authority_data);
      ssh_free(ikev1_ca_authority_size);
      return NULL;
    }
#endif /* SSHDIST_IKEV1 */

  /* IKEv2: concatenate the SHA-1 key identifiers and specify 1 as the
     number of CAs. */

  ssh_buffer_init(buffer);

  for (i = 0; i < ad->num_cas; i++)
    {
      if (ssh_buffer_append(buffer,
                            ad->cas[i]->cert_key_id,
                            ad->cas[i]->cert_key_id_len) != SSH_BUFFER_OK)
        {
          ssh_buffer_uninit(buffer);
          error_code = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
          goto error;
        }
    }

  ca_authority_data = ssh_buffer_ptr(buffer);
  ca_authority_size = ssh_buffer_len(buffer);

  if (ca_authority_size == 0)
    {
      ssh_buffer_uninit(buffer);
      error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  if (p1->n->ed == NULL)
    p1->n->ed = ed;

  SSH_DEBUG(SSH_D_MIDOK, ("Returning %d CA's for IKEv2 SA to the IKE "
                          "library", (int)ca_authority_size / 20));

  (*reply_callback)(SSH_IKEV2_ERROR_OK,
                    1,
                    &ca_encoding,
                    &ca_authority_data,
                    &ca_authority_size,
                    reply_callback_context);
  ssh_buffer_uninit(buffer);
  return NULL;

 error:
  (*reply_callback)(error_code, 0, NULL, NULL, NULL,
                    reply_callback_context);

  return NULL;
}

/***************************** Get Certificates ******************************/




#define MAX_CERT_PATH_LEN 16

SshOperationHandle
ssh_pm_ike_get_certificates(SshSADHandle sad_handle,
                            SshIkev2ExchangeData ed,
                            SshIkev2PadGetCertificatesCB reply_callback,
                            void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshIkev2PayloadID pid = NULL;
  SshPmTunnel tunnel;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshPmAuthDomain ad = NULL;
  SshCertificate cert = NULL, c;
  SshPrivateKey private_key_out = NULL;
  SshCertificateChain cert_chain = NULL;
  SshIkev2CertEncoding cert_encodings[MAX_CERT_PATH_LEN];
  unsigned char *cert_bers[MAX_CERT_PATH_LEN], *ber;
  size_t cert_lens[MAX_CERT_PATH_LEN], nof_certs = 0, ber_len;
  SshUInt32 i, ret_error = 0;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  SSH_PM_ASSERT_P1(p1);

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    goto error;

  /* Ignore request if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Ignoring get certificates request received outside IKE "
                 "negotiation"));
      goto error;
    }

  if (!p1->n->tunnel || !SSH_PM_P1_USABLE(p1))
    {
      error_code = SSH_IKEV2_ERROR_SA_UNUSABLE;
      goto error;
    }

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

  tunnel = p1->n->tunnel;

  /* Get local identity given at tunnel. */
  pid = ssh_pm_ikev2_payload_id_dup(tunnel->local_identity);
  if (pid == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Local identity not defined; need to be given "
                             "as 'identity' or 'certificate' at tunnel "
                             "object"));
      error_code = SSH_IKEV2_ERROR_OK;
      goto error;
    }

  /* Lookup the preshared key based on our tunnel's local identity if the
     peer has not sent us any certificate requests. If we have a pre-shared
     key available we will use it, if not we will attempt certificate
     lookup. */
  if (p1->n->crs.num_cas == 0)
    {
      size_t key_len;

      if (ssh_pm_ike_preshared_keys_get_secret(ad,
                                               p1->n->tunnel->local_identity,
                                               &key_len) != NULL)
        {
          /* Yes, psk is configured. Fall back to psk. */
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Pre shared key found"));
          error_code = SSH_IKEV2_ERROR_OK;
          goto error;
        }
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No pre shared key found"));
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Prepare for certificate lookup"));

  /* Iterate all local certificates until a suitable one is found. */
  cert = NULL;
  while ((cert = ssh_pm_mscapi_get_local_cert(pid, cert)))
    {
      /* Validate the certificate up to a trusted certificate. */
      cert_chain = ssh_pm_mscapi_get_cert_chain(cert, &ret_error);
      if (cert_chain == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot build cert chain for local identity %@ "
                     "cert %p", ssh_pm_ike_id_render, pid, (void *)cert));
          continue;
        }

      /* If there are no certificate requests, skip selection by CA
         and select the first certificate. */
      if (p1->n->crs.num_cas == 0)
        goto end_search;

      /* Skip the local certificate itself. */
      c = ssh_pm_mscapi_cert_chain_next(cert_chain, NULL);

      /* Check if the issuer chain contains a CA the key id of which
         is in p1->n->crs.cas. */
      while ((c = ssh_pm_mscapi_cert_chain_next(cert_chain, c)))
        {
#ifdef SSHDIST_IKEV1
          if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
            {
              unsigned char *dn;
              size_t dn_len;
              if (!ssh_pm_mscapi_cert_issuer(c, &dn, &dn_len))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Cannot get CA issuer"));
                  continue;
                }

              for (i = 0; i < p1->n->crs.num_cas; i++)
                {
                  if (p1->n->crs.ca_lens[i] == dn_len &&
                      !memcmp(dn, p1->n->crs.cas[i], dn_len))
                    {
                      ssh_free(dn);
                      goto end_search;
                    }
                }
              ssh_free(dn);
            }
          else
#endif /* SSHDIST_IKEV1 */
            {
              unsigned char *kid;
              size_t kid_len;
              if (!ssh_pm_mscapi_cert_key_id(c, &kid, &kid_len))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Cannot get CA key id"));
                  continue;
                }

              for (i = 0; i < p1->n->crs.num_cas; i++)
                {
                  if (!memcmp(kid, p1->n->crs.cas[i], kid_len))
                    {
                      ssh_free(kid);
                      goto end_search;
                    }
                }
              ssh_free(kid);
            }
        }

      ssh_pm_mscapi_free_cert_chain(cert_chain);
      cert_chain = NULL;
    }
 end_search:

  if (!cert)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No suitable certificate for local identity %@",
                             ssh_pm_ike_id_render, pid));
      if (!cert_chain)
        {
          if (p1 && p1->n)
            {
              if ((ret_error & (CERT_TRUST_IS_PARTIAL_CHAIN |
                                CERT_TRUST_IS_UNTRUSTED_ROOT)))
                {
                  p1->n->cmi_failure_mask |= SSH_CM_SSTATE_CERT_CHAIN_LOOP;
                  SSH_DEBUG(SSH_D_FAIL, ("No trusted CA for certificate"));
                }
              else if ((ret_error & CERT_TRUST_IS_NOT_TIME_VALID))
                {
                  p1->n->cmi_failure_mask |=
                    SSH_CM_SSTATE_CERT_NOT_IN_INTERVAL;
                  SSH_DEBUG(SSH_D_FAIL, ("Certificate or CA certificate "
                                         "expired"));
                }
              else
                {
                  p1->n->cmi_failure_mask |= SSH_CM_SSTATE_CERT_NOT_FOUND |
                                             SSH_CM_SSTATE_CERT_INVALID;
                  SSH_DEBUG(SSH_D_FAIL, ("Certificate chain is not valid"));
                }
            }
        }
      goto error;
    }

  private_key_out = ssh_pm_mscapi_get_private_key(cert);
  if (private_key_out == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No private key for local identity %@",
                             ssh_pm_ike_id_render, pid));
      goto error;
    }

  if (!strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
              szOID_X957_DSA))
    {
      p1->local_auth_method = SSH_PM_AUTH_DSA;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Authenticating P1 with DSA"));
    }

  else if (!strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
                   szOID_RSA_RSA))
    {
      p1->local_auth_method = SSH_PM_AUTH_RSA;
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Authenticating P1 with RSA"));
    }
  else
    SSH_DEBUG(SSH_D_FAIL,
              ("Unknown algorithm object id: %s",
               cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId));

  c = NULL;
  while ((c = ssh_pm_mscapi_cert_chain_next(cert_chain, c)))
    {
      if (nof_certs >= MAX_CERT_PATH_LEN)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cert path too long for local id %@",
                                 ssh_pm_ike_id_render, pid));
          goto error;
        }
      if (!ssh_pm_mscapi_export_local_cert(c, &ber, &ber_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot encode cert for local identity %@",
                                 ssh_pm_ike_id_render, pid));
          goto error;
        }

      cert_bers[nof_certs] = ber;
      cert_lens[nof_certs] = ber_len;
      cert_encodings[nof_certs] = SSH_IKEV2_CERT_X_509;
      nof_certs++;

      if ((tunnel->flags & SSH_PM_T_NO_CERT_CHAINS) ||
          (p1->compat_flags & SSH_PM_COMPAT_NO_CERT_CHAINS))
        break;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Returning %d certificates to the IKE library",
                          (int)nof_certs));

  (*reply_callback)(SSH_IKEV2_ERROR_OK,
                    private_key_out,
                    nof_certs,
                    cert_encodings,
                    (const unsigned char **)&cert_bers,
                    cert_lens,
                    reply_callback_context);

  while (nof_certs > 0)
    {
      nof_certs--;
      if (cert_bers[nof_certs])
        ssh_free(cert_bers[nof_certs]);
    }

  if (cert_chain != NULL)
    ssh_pm_mscapi_free_cert_chain(cert_chain);

  if (private_key_out != NULL)
    ssh_private_key_free(private_key_out);

  if (cert != NULL)
    ssh_pm_mscapi_free_cert(cert);

  if (pid != NULL)
    ssh_pm_ikev2_payload_id_free(pid);

  return NULL;

 error:
  (*reply_callback)(error_code, 0, 0, NULL, NULL, NULL,
                    reply_callback_context);

  while (nof_certs > 0)
    {
      nof_certs--;
      if (cert_bers[nof_certs])
        ssh_free(cert_bers[nof_certs]);
    }

  if (cert_chain != NULL)
    ssh_pm_mscapi_free_cert_chain(cert_chain);

  if (private_key_out != NULL)
    ssh_private_key_free(private_key_out);

  if (cert != NULL)
    ssh_pm_mscapi_free_cert(cert);

  if (pid != NULL)
    ssh_pm_ikev2_payload_id_free(pid);
  return NULL;
}

/***************************** Get Public Key ********************************/

SshOperationHandle
ssh_pm_ike_public_key(SshSADHandle sad_handle,
                      SshIkev2ExchangeData ed,
                      SshIkev2PadPublicKeyCB reply_callback,
                      void *reply_callback_context)
{
  SshIkev2Error error_code = SSH_IKEV2_ERROR_OK;
  SshPm pm = sad_handle->pm;
  SshPmP1 p1;
  SshPmAuthDomain ad = NULL;
  SshIkev2PayloadID id;
  SshCertificate cert = NULL, c = NULL;
  SshCertificateChain cert_chain = NULL;
  SshPublicKey public_key = NULL;
  SshUInt32 i, ret_error = 0;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  p1 = (SshPmP1)ed->ike_sa;

  SSH_PM_ASSERT_P1(p1);

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      error_code = SSH_IKEV2_ERROR_SUSPENDED;
      goto error;
    }

  if (p1->n == NULL || !SSH_PM_P1_USABLE(p1))
    {
      error_code = SSH_IKEV2_ERROR_SA_UNUSABLE;
      goto error;
    }

  /* Select a tunnel for the reponder if not already done */
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR))
    {
      error_code = ssh_pm_select_ike_responder_tunnel(sad_handle->pm, p1, ed);
      if (error_code != SSH_IKEV2_ERROR_OK)
        {
          error_code = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
          goto error;
        }
    }

  /* If the IKE initiator has used the "me Tarzan, you Jane" option, then
     check here that that responder has replied with an acceptable identity. */
  if (!ssh_pm_ike_check_requested_identity(sad_handle->pm, p1,
                                           ed->ike_ed->id_r))
    {
      error_code = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
      p1->n->failure_mask |= SSH_PM_E_REMOTE_ID_MISMATCH;

      goto error;
    }

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    id = ed->ike_ed->id_r;
  else
    id = ed->ike_ed->id_i;

  /* Verify correct authentication domain */
  if (!ssh_pm_auth_domain_check_by_ed(pm, ed))
    goto error;
  else
    ad = p1->auth_domain;

  /* Iterate all remote certificates until a suitable one is found. */
  cert = NULL;
  while ((cert = ssh_pm_mscapi_get_remote_cert(id, cert)))
    {
      /* Validate the certificate up to a trusted certificate. */
      cert_chain = ssh_pm_mscapi_get_cert_chain(cert, &ret_error);
      if (cert_chain == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Cannot build cert chain for remote identity %@ "
                     "cert %p", ssh_pm_ike_id_render, id, (void *)cert));
          continue;
        }

      /* Skip the remote certificate itself. */
      c = ssh_pm_mscapi_cert_chain_next(cert_chain, NULL);

      /* Check if the issuer chain contains a CA the key id of which
         is in ad->cas. */
      while ((c = ssh_pm_mscapi_cert_chain_next(cert_chain, c)))
        {
#ifdef SSHDIST_IKEV1
          if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
            {
              unsigned char *dn;
              size_t dn_len;
              if (!ssh_pm_mscapi_cert_issuer(c, &dn, &dn_len))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Cannot get CA key id"));
                  continue;
                }
              for (i = 0; i < ad->num_cas; i++)
                {
                  if (dn_len == ad->cas[i]->cert_issuer_dn_len &&
                      !memcmp(dn, ad->cas[i]->cert_issuer_dn, dn_len))
                    {
                      ssh_free(dn);
                      goto end_search;
                    }
                }
              ssh_free(dn);
            }
          else
#endif /* SSHDIST_IKEV1 */
            {
              unsigned char *kid;
              size_t kid_len;
              if (!ssh_pm_mscapi_cert_key_id(c, &kid, &kid_len))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Cannot get CA key id"));
                  continue;
                }
              for (i = 0; i < ad->num_cas; i++)
                {
                  if (kid_len == ad->cas[i]->cert_key_id_len &&
                      !memcmp(kid, ad->cas[i]->cert_key_id, kid_len))
                    {
                      ssh_free(kid);
                      goto end_search;
                    }
                }
              ssh_free(kid);
            }
        }

      ssh_pm_mscapi_free_cert_chain(cert_chain);
      cert_chain = NULL;
    }
 end_search:

  if (!cert)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No suitable certificate for remote identity %@",
                             ssh_pm_ike_id_render, id));
      if (!cert_chain)
        {
          if (p1 && p1->n)
            {
              if ((ret_error & (CERT_TRUST_IS_PARTIAL_CHAIN |
                                CERT_TRUST_IS_UNTRUSTED_ROOT)))
                {
                  p1->n->cmi_failure_mask |= SSH_CM_SSTATE_CERT_CHAIN_LOOP;
                  SSH_DEBUG(SSH_D_FAIL, ("No trusted CA for certificate"));
                }
              else if ((ret_error & CERT_TRUST_IS_NOT_TIME_VALID))
                {
                  p1->n->cmi_failure_mask |=
                    SSH_CM_SSTATE_CERT_NOT_IN_INTERVAL;
                  SSH_DEBUG(SSH_D_FAIL, ("Certificate or CA certificate "
                                         "expired"));
                }
              else
                {
                  p1->n->cmi_failure_mask |= SSH_CM_SSTATE_CERT_NOT_FOUND |
                                             SSH_CM_SSTATE_CERT_INVALID;
                  SSH_DEBUG(SSH_D_FAIL, ("Certificate chain is not valid"));
                }
            }
        }
      goto error;
    }

  public_key = ssh_pm_mscapi_get_public_key(cert);
  if (public_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot get public key for identity %@",
                             ssh_pm_ike_id_render, id));
      goto error;
    }

  SSH_DEBUG(SSH_D_MIDOK, ("Returning public key to the IKE library"));

  (*reply_callback)(SSH_IKEV2_ERROR_OK, public_key,
                    reply_callback_context);

  if (c != NULL)
    p1->auth_ca_cert = CertDuplicateCertificateContext(c);

  if (public_key != NULL)
    ssh_public_key_free(public_key);

  if (cert_chain != NULL)
    ssh_pm_mscapi_free_cert_chain(cert_chain);

  if (cert != NULL)
    p1->auth_cert = cert;

  return NULL;

 error:
  if (c != NULL)
    c = NULL;

  if (public_key != NULL)
    ssh_public_key_free(public_key);

  if (cert != NULL)
    ssh_pm_mscapi_free_cert(cert);

  if (cert_chain != NULL)
    ssh_pm_mscapi_free_cert_chain(cert_chain);

  (*reply_callback)(error_code, NULL, reply_callback_context);
  return NULL;
}

/***************************** New Certificate Request ***********************/

void
ssh_pm_ike_new_certificate_request(SshSADHandle sad_handle,
                                   SshIkev2ExchangeData ed,
                                   SshIkev2CertEncoding ca_encoding,
                                   const unsigned char *certificate_authority,
                                   size_t certificate_authority_len)
{
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshPmP1Negotiation n = p1->n;
  unsigned char **cas = NULL;
  size_t *ca_lens = NULL;
  int num_cas = 1;
  size_t real_len = certificate_authority_len;
  int i;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p ED %p", ed->ike_sa, ed));

  /* If policymanager is not in active state, we wan't to reject this. */
  if (ssh_pm_get_status(sad_handle->pm) == SSH_PM_STATUS_SUSPENDED)
    goto error;

  if (p1->n == NULL || !SSH_PM_P1_USABLE(p1))
    goto error;

  switch (ca_encoding)
    {
    case SSH_IKEV2_CERT_X_509:
#ifdef SSHDIST_IKEV1
      if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
        {
          /* IKEv1 certifificate request: one DER-encoded
             distinguished issuer name of a CA. */
          real_len = certificate_authority_len;
          num_cas = 1;
        }
      else
#endif /* SSHDIST_IKEV1 */
        {
          /* IKEv2 certificate request: series of 20-byte SHA-1 hashes
             of CA certificate public key infos. */
          if ((certificate_authority_len % 20) != 0)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Invalid CA public key hash length %d",
                         certificate_authority_len));
              return;
            }
          real_len = 20;
          num_cas = certificate_authority_len / real_len;
        }
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL,
                ("Unsupported CA encoding %d", ca_encoding));
      return;
      break;
    }

  cas =
    ssh_realloc(n->crs.cas,
                n->crs.num_cas * sizeof(*n->crs.cas),
                (n->crs.num_cas + num_cas) * sizeof(*n->crs.cas));
  ca_lens =
    ssh_realloc(n->crs.ca_lens,
                n->crs.num_cas * sizeof(*n->crs.ca_lens),
                (n->crs.num_cas + num_cas) * sizeof(*n->crs.ca_lens));

  if (cas == NULL || ca_lens == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not add new certificate request"));
      /* Sorry, we must free also the old ones since the ssh_realloc()
         API requires us to know the old length and now some of our
         arrays might use the old length and some the new length. */

      goto error;
    }

  /* Add new certificate request. */
  for (i = 0; i < num_cas; i++)
    {
      cas[n->crs.num_cas + i] =
        ssh_memdup(certificate_authority + (i * real_len), real_len);
      if (cas[n->crs.num_cas + i] == NULL)
        goto error;

      ca_lens[n->crs.num_cas + i] = real_len;
    }
  n->crs.cas = cas;
  n->crs.ca_lens = ca_lens;
  n->crs.num_cas += num_cas;
  SSH_DEBUG(SSH_D_MIDOK, ("Added %d certificate requests", (int)num_cas));
  return;

 error:
  if (cas) ssh_free(cas);
  if (ca_lens) ssh_free(ca_lens);

  if (n->crs.cas)
    for (i = 0; i < n->crs.num_cas; i++)
      ssh_free(n->crs.cas[i]);

  ssh_free(n->crs.cas);
  ssh_free(n->crs.ca_lens);
  memset(&n->crs, 0, sizeof(n->crs));
  return;
}

/***************************** New Certificate *******************************/

void
ssh_pm_ike_new_certificate(SshSADHandle sad_handle,
                           SshIkev2ExchangeData ed,
                           SshIkev2CertEncoding cert_encoding,
                           const unsigned char *cert_data,
                           size_t cert_data_len)
{
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  size_t pathlength = 0;
  SshCertificate cert;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("New certificate: encoding=%s(%d)",
             ssh_ikev2_cert_encoding_to_string(cert_encoding),
             cert_encoding));
  SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP, ("Certificate:"),
                    cert_data, cert_data_len);






  if (!SSH_PM_P1_USABLE(p1))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("P1 not usable, new certificate not added."));
      return;
    }

  /* Ignore certificate if not in IKE SA negotiation phase. */
  if (p1->n == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Ignoring new certificate received outside IKE negotiation"));
      return;
    }

  switch (cert_encoding)
    {
    case SSH_IKEV2_CERT_ARL:
    case SSH_IKEV2_CERT_CRL:
        SSH_DEBUG(SSH_D_FAIL, ("Adding CRLs not supported"));
      break;

    case SSH_IKEV2_CERT_X_509:
      if (!ssh_pm_mscapi_import_remote_cert(cert_data, cert_data_len, &cert))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Unable to add certificate to cache"));
          return;
        }
      ssh_pm_mscapi_free_cert(cert);
      break;

    default:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Unsupported certificate encoding `%s' (%d)",
                 ssh_ikev2_cert_encoding_to_string(cert_encoding),
                 cert_encoding));
      break;

    }

  SSH_DEBUG(SSH_D_MIDOK, ("Added new certificate"));
}
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */
#endif /* SSHDIST_IKE_CERT_AUTH */
