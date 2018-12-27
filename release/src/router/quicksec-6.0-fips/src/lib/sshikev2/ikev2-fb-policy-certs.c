/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Phase-I certificate policy functions for IKEv1 fallback.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"
#include "sshikev2-util.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#include "ikev2-fb.h"
#include "ikev2-fb-st.h"

#define SSH_DEBUG_MODULE "SshIkev2FallbackCerts"

#ifdef SSHDIST_IKE_CERT_AUTH

/*--------------------------------------------------------------------*/
/*       IKE find public key                                          */
/*--------------------------------------------------------------------*/


void ikev2_fb_find_public_key_cb(SshIkev2Error error_code,
                                 SshPublicKey public_key_out,
                                 void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error_code == SSH_IKEV2_ERROR_OK && public_key_out != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Found public key"));

      if (ssh_public_key_copy(public_key_out, &neg->public_key)
          != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not duplicate public key"));
          neg->public_key = NULL;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Public key lookup failed, error '%s'",
                             ssh_ikev2_error_to_string(error_code)));
      neg->public_key = NULL;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
  return;
}

SSH_FSM_STEP(ikev2_fb_st_find_public_key)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_find_public_key_result);

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, public_key)
                     (neg->server->sad_handle, neg->ed,
                      ikev2_fb_find_public_key_cb,
                      neg));

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_find_public_key_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  (*neg->callbacks.u.find_public_key)(neg->public_key, NULL, 0,
                                      neg->callbacks.callback_context);

  neg->public_key = NULL;
  return SSH_FSM_FINISH;
}

void
ikev2_fb_find_public_key_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_find_public_key(SshIkePMPhaseI pm_info,
                         SshPolicyKeyType key_type_in,
                         const unsigned char *hash_alg_in,
                         SshPolicyFindPublicKeyCB callback_in,
                         void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    goto error;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
    error:
      (*callback_in)(NULL, NULL, 0, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Find pre-shared key policy call entered, "
                          "IKE SA %p", neg->ike_sa));

  neg->ed->state = SSH_IKEV2_STATE_IKE_AUTH_LAST;

  /* First store the remote peer's identity to the IKEv2 exchange
     data structure since the policy manager will access this identity. */
  if (neg->ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      if (neg->ed->ike_ed->id_r == NULL)
        neg->ed->ike_ed->id_r = ikev2_fb_idv1_to_idv2(neg->ed,
                                                      neg->p1_info->remote_id);

      if (neg->ed->ike_ed->id_r == NULL)
        {
          (*callback_in)(NULL, NULL, 0, callback_context_in);
          return;
        }
    }
  else
    {
      if (neg->ed->ike_ed->id_i == NULL)
        neg->ed->ike_ed->id_i = ikev2_fb_idv1_to_idv2(neg->ed,
                                                      neg->p1_info->remote_id);

      if (neg->ed->ike_ed->id_i == NULL)
        {
          (*callback_in)(NULL, NULL, 0, callback_context_in);
          return;
        }
    }

  /* Store the completion callback and its context. */
  neg->callbacks.u.find_public_key = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  /* Take a reference to fallback negotiation structure for the sub thread.
     It will be freed in the sub thread destructor. */
  IKEV2_FB_NEG_TAKE_REF(neg);

  ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                      ikev2_fb_st_find_public_key,
                      NULL_FNPTR,
                      ikev2_fb_find_public_key_sub_thread_destructor, neg);
}

/*--------------------------------------------------------------------*/
/*       IKE new certificate                                          */
/*--------------------------------------------------------------------*/

void
ikev2_fb_new_certificate(SshIkePMPhaseI pm_info,
                         SshIkeCertificateEncodingType cert_encoding,
                         unsigned char *certificate_data,
                         size_t certificate_data_len)
{
  int ikev2_cert_encoding;
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("Entered new certificate policy call, received "
                          "a certificate of encoding %d for IKE SA %p",
                          cert_encoding, neg->ike_sa));

  ikev2_cert_encoding = ikev2_fb_v2_cert_encoding_to_v1(cert_encoding);
  if (ikev2_cert_encoding == -1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not convert IKEv1 cert encoding %d to "
                             "IKEv2 encoding", cert_encoding));
      return;
    }

  SSH_IKEV2_FB_V2_NOTIFY(neg, new_certificate)(neg->server->sad_handle,
                                               neg->ed,
                                               ikev2_cert_encoding,
                                               (const unsigned char *)
                                               certificate_data,
                                               certificate_data_len);
}

/*--------------------------------------------------------------------*/
/*       IKE certificate request                                      */
/*--------------------------------------------------------------------*/

void
ikev2_fb_certificate_request(SshIkePMPhaseI pm_info,
                             SshIkeCertificateEncodingType cert_encoding,
                             unsigned char *certificate_data,
                             size_t certificate_data_len)
{
  int ikev2_cert_encoding;
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("Entered new certificate request policy call, IKE "
                          "SA %p", neg->ike_sa));

  ikev2_cert_encoding = ikev2_fb_v2_cert_encoding_to_v1(cert_encoding);
  if (ikev2_cert_encoding == -1)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not convert IKEv1 cert encoding %d to "
                             "IKEv2 encoding", cert_encoding));
      return;
    }

  SSH_IKEV2_FB_V2_NOTIFY(neg,
                         new_certificate_request)(neg->server->sad_handle,
                                                  neg->ed,
                                                  ikev2_cert_encoding,
                                                  certificate_data,
                                                  certificate_data_len);
}

/*--------------------------------------------------------------------*/
/*       IKE request certificates                                     */
/*--------------------------------------------------------------------*/

void ikev2_fb_request_certificates_cb(SshIkev2Error error_code,
                                      SshPrivateKey private_key_out,
                                      int number_of_certificates,
                                      SshIkev2CertEncoding *cert_encs,
                                      const unsigned char **certs,
                                      size_t *cert_lengths,
                                      void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;
  SshIkeCertificateEncodingType *ikev1_cert_encodings = NULL;
  SshPrivateKey private_key_copy = NULL;
  unsigned char **ikev1_certs = NULL;
  size_t *ikev1_cert_lengths = NULL;
  int i;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Private key/Certificate lookup failed, "
                             "error '%s'",
                             ssh_ikev2_error_to_string(error_code)));
      goto error;
    }

  if (number_of_certificates == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No certificates found"));
      goto error;
    }

  SSH_ASSERT(private_key_out != NULL);

  if (ssh_private_key_copy(private_key_out, &private_key_copy)
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Private key copy failed"));
      goto error;
    }

  /* Copy the returned certificates */
  ikev1_cert_encodings = ssh_calloc(number_of_certificates,
                                    sizeof(SshIkeCertificateEncodingType));
  ikev1_certs = ssh_calloc(number_of_certificates,
                           sizeof(unsigned char *));
  ikev1_cert_lengths = ssh_calloc(number_of_certificates,
                                  sizeof(size_t));

  if (ikev1_cert_encodings == NULL || ikev1_certs == NULL ||
      ikev1_cert_lengths == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failure"));
      goto error;
    }

  for (i = 0; i < number_of_certificates; i++)
    {
      ikev1_cert_encodings[i] =
          (int) ikev2_fb_v2_cert_encoding_to_v1((int) cert_encs[i]);
      ikev1_cert_lengths[i] = cert_lengths[i];
      if (!(ikev1_certs[i] = ssh_memdup(certs[i], cert_lengths[i])))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Certificate copy failed"));
          goto error;
        }
    }

  /* Save the certificates and private key. */
  neg->number_of_certificates = number_of_certificates;
  neg->cert_encodings = ikev1_cert_encodings;
  neg->certs = ikev1_certs;
  neg->cert_lengths = ikev1_cert_lengths;
  neg->private_key = private_key_copy;

  SSH_DEBUG(SSH_D_LOWOK, ("Found %d certificates", number_of_certificates));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
  return;

 error:

  if (private_key_copy)
    ssh_private_key_free(private_key_copy);

  if (ikev1_certs)
    for (i = 0; i < number_of_certificates; i++)
      ssh_free(ikev1_certs[i]);

  ssh_free(ikev1_certs);
  ssh_free(ikev1_cert_encodings);
  ssh_free(ikev1_cert_lengths);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(neg->sub_thread);
}

SSH_FSM_STEP(ikev2_fb_st_request_certs)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  SSH_FSM_SET_NEXT(ikev2_fb_st_request_certs_result);
  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_FB_V2_CALL(neg, get_certificates)
                     (neg->server->sad_handle, neg->ed,
                      ikev2_fb_request_certificates_cb, neg));

  SSH_NOTREACHED;
}

SSH_FSM_STEP(ikev2_fb_st_request_certs_result)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) thread_context;

  if (neg->find_private_key_op)
    {
      neg->find_private_key_op = 0;

      if (neg->callbacks.u.find_private_key)
        (*neg->callbacks.u.find_private_key)(neg->private_key,
                                             neg->callbacks.callback_context);
      neg->private_key = NULL;
      return SSH_FSM_FINISH;
    }
  else
    {
      int *number_of_certs;
      SshIkeCertificateEncodingType **cert_encodings;
      unsigned char ***certs;
      size_t **cert_lengths;

      if (neg->callbacks.u.request_certs == NULL)
        return SSH_FSM_FINISH;

      number_of_certs = ssh_calloc(neg->number_of_cas, sizeof(int));
      cert_encodings = ssh_calloc(neg->number_of_cas,
                                  sizeof(SshIkeCertificateEncodingType *));
      certs = ssh_calloc(neg->number_of_cas, sizeof(unsigned char **));
      cert_lengths = ssh_calloc(neg->number_of_cas, sizeof(size_t *));

      if (!number_of_certs || !cert_encodings || !certs || !cert_lengths)
        {
          ssh_free(number_of_certs);
          ssh_free(cert_encodings);
          ssh_free(certs);
          ssh_free(cert_lengths);

          (*neg->callbacks.u.request_certs)(NULL, NULL, NULL, NULL,
                                            neg->callbacks.callback_context);
          return SSH_FSM_FINISH;
        }
      number_of_certs[0] = neg->number_of_certificates;
      cert_encodings[0] = neg->cert_encodings;
      certs[0] = neg->certs;
      cert_lengths[0] = neg->cert_lengths;

      neg->cert_encodings = NULL;
      neg->cert_lengths = NULL;
      neg->certs = NULL;

      (*neg->callbacks.u.request_certs)(number_of_certs, cert_encodings,
                                        certs, cert_lengths,
                                        neg->callbacks.callback_context);
      return SSH_FSM_FINISH;
    }
}

void
ikev2_fb_request_certs_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;

  /* Free reference to fallback negotiation structure. */
  ikev2_fallback_negotiation_free(neg->fb, neg);
}

void
ikev2_fb_request_certificates(SshIkePMPhaseI pm_info,
                              int number_of_cas,
                              SshIkeCertificateEncodingType
                              *ca_encodings,
                              unsigned char **certificate_authorities,
                              size_t *certificate_authority_lens,
                              SshPolicyRequestCertificatesCB
                              callback_in,
                              void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    goto error;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
    error:
      (*callback_in)(NULL, NULL, NULL, NULL, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Request certificates policy call entered, "
                          "IKE SA %p", neg->ike_sa));

  /* If we have already retrieved the certificates in the find private
     key policy call, then return the certificates immediately. */
  if (neg->certs != NULL)
    {
      int *number_of_certs;
      SshIkeCertificateEncodingType **cert_encodings;
      unsigned char ***certs;
      size_t **cert_lengths;

      SSH_DEBUG(SSH_D_LOWOK, ("Returning cached certs"));

      number_of_certs = ssh_calloc(number_of_cas, sizeof(int));
      cert_encodings = ssh_calloc(number_of_cas,
                                  sizeof(SshIkeCertificateEncodingType *));
      certs = ssh_calloc(number_of_cas, sizeof(unsigned char **));
      cert_lengths = ssh_calloc(number_of_cas, sizeof(size_t *));

      if (!number_of_certs || !cert_encodings || !certs || !cert_lengths)
        {
          ssh_free(neg->cert_encodings); neg->cert_encodings = NULL;
          ssh_free(neg->certs); neg->certs = NULL;
          ssh_free(neg->cert_lengths); neg->cert_lengths = NULL;

          ssh_free(number_of_certs);
          ssh_free(cert_encodings);
          ssh_free(certs);
          ssh_free(cert_lengths);

          (*callback_in)(NULL, NULL, NULL, NULL, callback_context_in);
          return;
        }

      number_of_certs[0] = neg->number_of_certificates;
      cert_encodings[0] = neg->cert_encodings;
      certs[0] = neg->certs;
      cert_lengths[0] = neg->cert_lengths;

      neg->number_of_certificates = neg->number_of_cas = 0;
      neg->cert_encodings = NULL; neg->certs = NULL; neg->cert_lengths = NULL;

      (*callback_in)(number_of_certs, cert_encodings, certs, cert_lengths,
                     callback_context_in);
      return;
    }
  else
    {
      /* Store the completion callback and its context. */
      neg->callbacks.u.request_certs = callback_in;
      neg->callbacks.callback_context = callback_context_in;

      neg->number_of_cas = number_of_cas;

      /* Take a reference to fallback negotiation structure for the sub thread.
         It will be freed in the sub thread destructor. */
      IKEV2_FB_NEG_TAKE_REF(neg);

      /* Start a sub-thread to get our certificates and private key */
      ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                          ikev2_fb_st_request_certs,
                          NULL_FNPTR,
                          ikev2_fb_request_certs_sub_thread_destructor,
                          neg);
      return;
    }
}

/*--------------------------------------------------------------------*/
/*       IKE find private key                                         */
/*--------------------------------------------------------------------*/

void
ikev2_fb_find_private_key(SshIkePMPhaseI pm_info,
                          SshPolicyKeyType key_type,
                          const unsigned char *hash_alg_in,
                          const unsigned char *hash_in,
                          size_t hash_len_in,
                          SshPolicyFindPrivateKeyCB callback_in,
                          void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    goto error;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
    error:
      (*callback_in)(NULL, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Find find private key policy call entered, "
                          "IKE SA %p", neg->ike_sa));

  if (neg->private_key != NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Returning cached private key"));

      (*callback_in)(neg->private_key, callback_context_in);
      neg->private_key = NULL;
      return;
    }
  else
    {
      /* Store the completion callback and its context. */
      neg->callbacks.u.find_private_key = callback_in;
      neg->callbacks.callback_context = callback_context_in;
      neg->find_private_key_op = 1;

      /* Take a reference to fallback negotiation structure for the sub thread.
         It will be freed in the sub thread destructor. */
      IKEV2_FB_NEG_TAKE_REF(neg);

      /* Start a sub-thread to get our certificates and private key */
      ssh_fsm_thread_init(neg->fb->fsm, neg->sub_thread,
                          ikev2_fb_st_request_certs,
                          NULL_FNPTR,
                          ikev2_fb_request_certs_sub_thread_destructor,
                          neg);
      return;
    }
}

/*--------------------------------------------------------------------*/
/*       IKE get certificate authorities                              */
/*--------------------------------------------------------------------*/


void ikev2_fb_get_cas_kid_cb(SshIkev2Error error_code,
                             int number_of_cas,
                             SshIkev2CertEncoding *ca_encodings,
                             const unsigned char **ca_authority_data,
                             size_t *ca_authority_size,
                             void *context)
{
  SshIkev2FbNegotiation neg = (SshIkev2FbNegotiation) context;
  SshIkeCertificateEncodingType *ikev1_ca_encodings = NULL;
  unsigned char **ikev1_ca_names = NULL;
  size_t *ikev1_ca_name_lens = NULL;
  int i, j;

  SSH_IKEV2_FB_V2_COMPLETE_CALL(neg);

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("CA lookup failed, error '%s'",
                             ssh_ikev2_error_to_string(error_code)));
      goto error;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Got %d CA's from the policy manager",
                          number_of_cas));

  /* Allocate memory for IKEv1 CA names, name lengths and CA encodings. */
  ikev1_ca_encodings = ssh_calloc(number_of_cas,
                                  sizeof(SshIkeCertificateEncodingType));
  ikev1_ca_names = ssh_calloc(number_of_cas, sizeof(unsigned char *));
  ikev1_ca_name_lens = ssh_calloc(number_of_cas, sizeof(size_t));

  if (ikev1_ca_encodings == NULL || ikev1_ca_names == NULL ||
      ikev1_ca_name_lens == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory to return CAs"));
      goto error;
    }

  /* Map the IKEv2 CA encoding to IKEv1 encoding. */
  for (i = 0; i < number_of_cas; i++)
    {
      ikev1_ca_encodings[i] = ikev2_fb_v1_cert_encoding_to_v2(ca_encodings[i]);
      ikev1_ca_names[i] =
        ssh_memdup(ca_authority_data[i], ca_authority_size[i]);
      ikev1_ca_name_lens[i] = ca_authority_size[i];

      if (ikev1_ca_names[i] == NULL)
        goto error;
    }

  (*neg->callbacks.u.get_cas)(number_of_cas, ikev1_ca_encodings,
                              ikev1_ca_names, ikev1_ca_name_lens,
                              neg->callbacks.callback_context);
  return;

 error:

  if (ikev1_ca_names)
    for (j = 0; j < number_of_cas; j++)
      ssh_free(ikev1_ca_names[j]);
  ssh_free(ikev1_ca_names);

  ssh_free(ikev1_ca_name_lens);
  ssh_free(ikev1_ca_encodings);

  (*neg->callbacks.u.get_cas)(0, NULL, NULL, NULL,
                              neg->callbacks.callback_context);
  return;
}


void
ikev2_fb_get_certificate_authorities(SshIkePMPhaseI pm_info,
                                     SshPolicyGetCAsCB callback_in,
                                     void *callback_context_in)
{
  SshIkev2FbNegotiation neg;

  neg = ssh_ikev2_fb_p1_get_p1_negotiation(pm_info);
  if (neg == NULL)
    goto error;

  if (neg->ike_error != SSH_IKEV2_ERROR_OK)
    {
    error:
      (*callback_in)(0, NULL, NULL, NULL, callback_context_in);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Get certificate authorities policy call entered, "
                          "IKE SA %p", neg->ike_sa));

  /* Store the completion callback and its context. */
  neg->callbacks.u.get_cas = callback_in;
  neg->callbacks.callback_context = callback_context_in;

  SSH_IKEV2_FB_V2_CALL(neg, get_cas)(neg->server->sad_handle, neg->ed,
                                      ikev2_fb_get_cas_kid_cb, neg);
  return;
}

#endif /* SSHDIST_IKE_CERT_AUTH */
#endif /* SSHDIST_IKEV1 */
