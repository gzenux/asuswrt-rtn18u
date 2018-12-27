/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp policy manager reply functions.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshoperation.h"

#define SSH_DEBUG_MODULE "SshIkeReply"

/*                                                              shade{0.9}
 * ike_reply_done
 * Mark policy manager call done.                               shade{1.0}
 */
void ike_reply_done(SshIkeNegotiation negotiation)
{
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Clear the processing flag and return, so the upper level will know
         that we have replied to query immediately */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return;
    }
  /* Otherwise restart packet. The SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY
     lock flag is cleared in ike_state_restart_packet(). */
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY);
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY;
  ssh_xregister_timeout(0, 0, ike_state_restart_packet, negotiation);
}


/*                                                              shade{0.9}
 * ike_reply_check_deleted
 * Check that negotiation is not yet deleted.                   shade{1.0}
 */
Boolean ike_reply_check_deleted(SshIkeNegotiation negotiation)
{
  if (negotiation->ed->current_state == SSH_IKE_ST_DELETED)
    {
      SSH_DEBUG(4, ("Negotiation already deleted"));
      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* This cannot happen. */
          ssh_fatal("Negotiation deleted while processing "
                    "non asyncronous policy manager call");
        }
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY);

      /* Delete negotiation */
      ike_delete_negotiation(negotiation);
      return TRUE;
    }
  return FALSE;
}


/*                                                              shade{0.9}
 * ike_reply_return_error
 * Return error code to upper level.                            shade{1.0}
 */
void ike_reply_return_error(SshIkeNegotiation negotiation,
                            SshIkeNotifyMessageType ret)
{
  if (negotiation->notification_state ==
      SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
    {
      ssh_fatal("Policy manager function called after the notification "
                "is already send");
    }
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Clear the processing flag and return, so the upper level will know
         that we have replied to query immediately, and it will then check for
         the errors. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return;
    }
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
  negotiation->ed->code = ret;
  /* Restart packet. The SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY
     lock flag is cleared in ike_state_restart_packet(). */
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY);
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY;
  ssh_xregister_timeout(0, 0, ike_state_restart_packet, negotiation);
}


/*                                                              shade{0.9}
 * ike_policy_reply_new_connection
 * Process policy managers reply to new connection.             shade{1.0}
 */
void ike_policy_reply_new_connection(Boolean allow_connection,
                                     SshUInt32 compat_flags,
                                     SshInt32 retry_limit,
                                     SshInt32 retry_timer,
                                     SshInt32 retry_timer_usec,
                                     SshInt32 retry_timer_max,
                                     SshInt32 retry_timer_max_usec,
                                     SshInt32 expire_timer,
                                     SshInt32 expire_timer_usec,
                                     void *context)
{
  SshIkeNegotiation negotiation =
    ((SshIkeNewConnectionCBContext) context)->negotiation;

  /* Check if the negotiation is already deleted during the policy manager
     call? */
  if (negotiation->ed->current_state == SSH_IKE_ST_DELETED ||
      !allow_connection)
    {
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE;
    }
  else
    {
      if (compat_flags != SSH_IKE_FLAGS_USE_DEFAULTS)
        {
          negotiation->ed->compat_flags = compat_flags & 0xffff;
          negotiation->ike_ed->connect_flags = compat_flags;
        }

      if (retry_limit > 0)
        negotiation->ed->retry_limit = retry_limit;

      if (retry_timer > 0 || retry_timer_usec > 0)
        {
          negotiation->ed->retry_timer = retry_timer;
          negotiation->ed->retry_timer_usec = retry_timer_usec;
        }

      if (retry_timer_max > 0 || retry_timer_max_usec > 0)
        {
          negotiation->ed->retry_timer_max = retry_timer_max;
          negotiation->ed->retry_timer_max_usec = retry_timer_max_usec;
        }

      if (expire_timer > 0 || expire_timer_usec > 0)
        {
          negotiation->ed->expire_timer = expire_timer;
          negotiation->ed->expire_timer_usec = expire_timer_usec;
        }
    }

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Clear the processing flag and return, so the upper level will know
         that we have replied to query immediately */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return;
    }

  /* Otherwise restart packet. The SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY
     lock flag is cleared in ike_new_connection_cb_done(). */
  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY);
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY;
  ssh_xregister_timeout(0, 0, ike_new_connection_cb_done, context);
}


#ifdef SSHDIST_IKE_CERT_AUTH

#ifdef SSHDIST_EXTERNALKEY
/*                                                              shade{0.9}
 * ike_policy_reply_accl_public_key
 * Return accelerated public key.                  .            shade{1.0}
 */
void ike_policy_reply_accl_public_key(SshEkStatus status,
                                      SshPublicKey public_key_return,
                                      void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  if (status == SSH_EK_OK)
    {
      /* Accelerated public key found, use it */
      SSH_DEBUG(7, ("Using accelerated public key"));
      ssh_public_key_free(negotiation->ike_ed->public_key);
      negotiation->ike_ed->public_key = public_key_return;
    }
  else
    {
      /* Error occurred, when trying to get the accelerated public key/ */
      SSH_DEBUG(3, ("ssh_ek_generate_accelerated_public_key failed: %d",
                    status));
    }
  /* Restart state machine if needed */
  ike_reply_done(negotiation);
}
#endif /* SSHDIST_EXTERNALKEY */


/*                                                              shade{0.9}
 * ike_policy_reply_find_public_key
 * Process policy managers reply to find public key.            shade{1.0}
 */
void ike_policy_reply_find_public_key(SshPublicKey public_key_out,
                                      unsigned char *hash_out,
                                      size_t hash_len_out,
                                      void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->public_key = public_key_out;
  negotiation->ike_ed->public_key_hash = hash_out;
  negotiation->ike_ed->public_key_hash_len = hash_len_out;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (public_key_out == NULL)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No public key found"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No public key found");

      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED);
      return;
    }
#ifdef SSHDIST_EXTERNALKEY
  if (negotiation->sa->server_context->isakmp_context->external_key &&
      negotiation->sa->server_context->isakmp_context->accelerator_short_name)
    {
      SshIkeContext ic;

      ic = negotiation->sa->server_context->isakmp_context;





      ssh_ek_generate_accelerated_public_key(ic->external_key,
                                             ic->accelerator_short_name,
                                             negotiation->ike_ed->public_key,
                                             ike_policy_reply_accl_public_key,
                                             context);
      /* The ike_policy_reply_accl_public_key will take care of the restarting
         the state machine */
      return;
    }
#endif /* SSHDIST_EXTERNALKEY */
  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_policy_reply_find_private_key
 * Process policy managers reply to find private key.           shade{1.0}
 * Note that the IKE library assumes that it is given the
 * accelerated private key (if one is available) and the
 * IKE library does not attempt to accelerate the private key.
 */
void ike_policy_reply_find_private_key(SshPrivateKey private_key_out,
                                       void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->private_key = private_key_out;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (private_key_out == NULL)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No private key found"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No private key found");
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED);
      return;
    }

  ike_reply_done(negotiation);
  return;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_policy_reply_find_pre_shared_key
 * Process policy managers reply to find pre shared key.        shade{1.0}
 */
void ike_policy_reply_find_pre_shared_key(unsigned char *key_out,
                                          size_t key_out_len,
                                          void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->pre_shared_key = key_out;
  negotiation->ike_ed->pre_shared_key_len = key_out_len;
  SSH_ASSERT(!key_out || key_out_len);
  if (!key_out)
    negotiation->ike_ed->pre_shared_key_len = 1;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (key_out == NULL)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No pre shared key found"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "No pre shared key found");
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED);
      return;
    }

  ike_reply_done(negotiation);
  return;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_policy_reply_request_certificates
 * Process policy managers reply to request certificates.       shade{1.0}
 */
void ike_policy_reply_request_certificates(int *number_of_certificates,
                                           SshIkeCertificateEncodingType
                                           **cert_encodings,
                                           unsigned char ***certs,
                                           size_t **cert_lengths,
                                           void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->number_of_certificates = number_of_certificates;
  negotiation->ike_ed->cert_encodings = cert_encodings;
  negotiation->ike_ed->certs = certs;
  negotiation->ike_ed->cert_lengths = cert_lengths;

  if (ike_reply_check_deleted(negotiation))
    return;

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_policy_reply_get_cas
 * Process policy managers reply to get CAs.                    shade{1.0}
 */
void ike_policy_reply_get_cas(int number_of_cas,
                              SshIkeCertificateEncodingType *ca_encodings,
                              unsigned char **ca_names,
                              size_t *ca_name_lens,
                              void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->own_number_of_cas = number_of_cas;
  negotiation->ike_ed->own_ca_encodings = ca_encodings;
  negotiation->ike_ed->own_certificate_authorities = ca_names;
  negotiation->ike_ed->own_certificate_authority_lens = ca_name_lens;

  if (ike_reply_check_deleted(negotiation))
    return;

  ike_reply_done(negotiation);
  return;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_policy_reply_isakmp_nonce_data_len
 * Process policy managers reply to nonce len.                  shade{1.0}
 */
void ike_policy_reply_isakmp_nonce_data_len(size_t nonce_data_len,
                                            void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->nonce_data_len = nonce_data_len;

  if (ike_reply_check_deleted(negotiation))
    return;

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_policy_reply_isakmp_id
 * Process policy managers reply to identity.                   shade{1.0}
 */
void ike_policy_reply_isakmp_id(SshIkePayloadID id_payload,
                                void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  char id_txt[255];
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_pm_info->local_id = id_payload;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (id_payload == NULL)
    {
      SSH_DEBUG(3, ("Policy manager returned NULL for local "
                    "end identity for isakmp SA"));
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
      return;
    }

  ssh_ike_id_to_string(id_txt, sizeof(id_txt), id_payload);
  ssh_free(negotiation->ike_pm_info->local_id_txt);
  negotiation->ike_pm_info->local_id_txt = ssh_strdup(id_txt);
  if (negotiation->ike_pm_info->local_id_txt == NULL)
    {
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
      return;
    }

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_policy_reply_isakmp_vendor_ids
 * Process policy managers reply to vendor ids.                 shade{1.0}
 */
void ike_policy_reply_isakmp_vendor_ids(int number_of_vids,
                                        unsigned char **vendor_ids,
                                        size_t *vendor_id_lens,
                                        void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->ike_ed->number_of_vids = number_of_vids;
  negotiation->ike_ed->vendor_ids = vendor_ids;
  negotiation->ike_ed->vendor_id_lens = vendor_id_lens;

  if (ike_reply_check_deleted(negotiation))
    return;

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_isakmp_sa_reply
 * Process policy managers reply to isakmp sa query.            shade{1.0}
 */
void ike_isakmp_sa_reply(int proposal_index, int number_of_protocols,
                         int *transforms_indexes, void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SshIkeSA isakmp_sa = negotiation->sa;
  SshIkePayloadSA pl;
  struct SshIkeAttributesRec attrs;

  SSH_DEBUG(5, ("Start"));

  if (ike_reply_check_deleted(negotiation))
    {
      ssh_free(transforms_indexes);
      return;
    }

  if (proposal_index == -1 || number_of_protocols != 1)
    {
      negotiation->ike_ed->selected_proposal = 0;
      negotiation->ike_ed->selected_transform = -1;
      ssh_free(transforms_indexes);

      ike_reply_done(negotiation);
      return;
    }

  pl = &(negotiation->ike_ed->sa_i->pl.sa);
  ssh_ike_clear_isakmp_attrs(&attrs);
  if (!ssh_ike_read_isakmp_attrs(negotiation,
                                 &(pl->proposals[proposal_index].
                                   protocols[0].
                                   transforms[transforms_indexes[0]]),
                                 &attrs))
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Isakmp SA: Internal policy manager error, "
                     "policy manager selected proposal, "
                     "that contains unsupported values"));
      negotiation->ike_ed->selected_proposal = 0;
      negotiation->ike_ed->selected_transform = -1;
      ssh_free(transforms_indexes);

      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED);
      return;
    }

  /* Check for group parameters */
  if (attrs.group_parameters)
    {
      struct SshIkeGrpAttributesRec grp_attrs;

      /* Make sure there isn't any pre defined group descriptor given with
         group */
      if (attrs.group_desc != NULL)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Isakmp SA: Internal policy manager error, "
                         "policy manager selected proposal, "
                         "that contains both group descriptor and "
                         "group parameters"));
          negotiation->ike_ed->selected_proposal = 0;
          negotiation->ike_ed->selected_transform = -1;
          ssh_free(transforms_indexes);

          ike_reply_return_error(negotiation,
                           SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED);
          return;
        }

      ssh_ike_clear_grp_attrs(&grp_attrs);

      if (!ssh_ike_read_grp_attrs(negotiation,
                              &(pl->proposals[proposal_index].
                                protocols[0].
                                transforms[transforms_indexes[0]]),
                              &grp_attrs))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Isakmp SA: Internal policy manager error, "
                         "policy manager selected proposal, "
                         "that contains unsupported group values"));
          negotiation->ike_ed->selected_proposal = 0;
          negotiation->ike_ed->selected_transform = -1;
          ssh_free(transforms_indexes);

          ike_reply_return_error(negotiation,
                           SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED);
          return;
        }
      /* Insert it as group -1 */
      ike_remove_group(negotiation, -1);
      grp_attrs.group_descriptor = -1;
      attrs.group_desc = ike_add_group(negotiation, &grp_attrs);
      ssh_ike_free_grp_attrs(&grp_attrs);
    }

  /* We know that we only have one protocol */
  negotiation->ike_ed->attributes = attrs;
  negotiation->ike_ed->group = attrs.group_desc;

  if (attrs.encryption_algorithm == SSH_IKE_VALUES_ENCR_ALG_CAST_CBC &&
      attrs.key_length != 0 &&
      attrs.key_length <= 80)
    isakmp_sa->encryption_algorithm_name = ssh_custr("cast128-12-cbc");
  else
    {
      isakmp_sa->encryption_algorithm_name =
        ssh_custr(ssh_find_keyword_name(ssh_ike_encryption_algorithms,
                                        attrs.encryption_algorithm));
      if (isakmp_sa->encryption_algorithm_name == NULL)
        isakmp_sa->encryption_algorithm_name = ssh_custr("unknown");
    }

  isakmp_sa->hash_algorithm_name =
    ssh_custr(ssh_find_keyword_name(ssh_ike_hash_algorithms,
                                    attrs.hash_algorithm));
  if (isakmp_sa->hash_algorithm_name == NULL)
    isakmp_sa->hash_algorithm_name = ssh_custr("unknown");

  if (attrs.prf_algorithm == 0)
    isakmp_sa->prf_algorithm_name =
      ssh_custr(ssh_find_keyword_name(ssh_ike_hmac_prf_algorithms,
                                      attrs.hash_algorithm));
  else
    isakmp_sa->prf_algorithm_name =
      ssh_custr(ssh_find_keyword_name(ssh_ike_prf_algorithms,
                                      attrs.prf_algorithm));
  if (isakmp_sa->prf_algorithm_name == NULL)
    isakmp_sa->prf_algorithm_name = ssh_custr("unknown");

  isakmp_sa->kbyte_limit = attrs.life_duration_kb;

  negotiation->ike_pm_info->auth_method = attrs.auth_method;
  switch (attrs.auth_method)
    {
    case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED:
#endif /* SSHDIST_IKE_XAUTH */
      negotiation->ed->auth_method_type = SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY;
      break;
    case SSH_IKE_VALUES_AUTH_METH_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_RSA_SIGNATURES:
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_256:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_384:
    case SSH_IKE_VALUES_AUTH_METH_ECP_DSA_521:
#endif /* SSHDIST_CRYPT_ECP */
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_DSS_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_SIGNATURES:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_SIGNATURES:
#endif /* SSHDIST_IKE_XAUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
      negotiation->ed->auth_method_type = SSH_IKE_AUTH_METHOD_SIGNATURES;
#else /* SSHDIST_IKE_CERT_AUTH */
      goto not_implemented;
#endif /* SSHDIST_IKE_CERT_AUTH */
      break;

    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED:
#endif /* SSHDIST_IKE_XAUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
      negotiation->ed->auth_method_type =
        SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION;
#else /* SSHDIST_IKE_CERT_AUTH */
      goto not_implemented;
#endif /* SSHDIST_IKE_CERT_AUTH */
      break;
#ifdef REMOVED_BY_DOI_DRAFT_07
    case SSH_IKE_VALUES_AUTH_METH_GSSAPI:
      goto not_implemented;
      break;
#endif
    }
  negotiation->ike_pm_info->auth_method_type =
    negotiation->ed->auth_method_type;

#ifdef SSHDIST_IKE_XAUTH
  if (attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES ||
      attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES)
    negotiation->ike_pm_info->hybrid_edge = 1;
  else
  if (attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES ||
      attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES)
    negotiation->ike_pm_info->hybrid_client = 1;
#endif /* SSHDIST_IKE_XAUTH */

  negotiation->ike_ed->selected_proposal = proposal_index;
  negotiation->ike_ed->selected_transform = transforms_indexes[0];

  ssh_free(transforms_indexes);
  ike_reply_done(negotiation);

  return;

#ifdef SSHDIST_IKE_CERT_AUTH
  /* NOTREACHED */
#else /* SSHDIST_IKE_CERT_AUTH */
 not_implemented:
  SSH_IKE_DEBUG(3, negotiation,
                ("Other end selected locally unsupported "
                 "authentication method %d",
                 attrs.auth_method));
  negotiation->ike_ed->selected_proposal = 0;
  negotiation->ike_ed->selected_transform = -1;
  ssh_free(transforms_indexes);
  ike_reply_done(negotiation);

  return;
#endif /* SSHDIST_IKE_CERT_AUTH */
}


/*                                                              shade{0.9}
 * ike_ngm_sa_reply
 * Process policy managers reply to ngm sa query.               shade{1.0}
 */
void ike_ngm_sa_reply(int proposal_index, int number_of_protocols,
                      int *transforms_indexes, void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SshIkePayloadSA pl;
  struct SshIkeGrpAttributesRec attrs;

  SSH_DEBUG(5, ("Start"));

  if (ike_reply_check_deleted(negotiation))
    {
      ssh_free(transforms_indexes);
      return;
    }

  if (proposal_index == -1 || number_of_protocols != 1)
    {
      negotiation->ngm_ed->selected_proposal = 0;
      negotiation->ngm_ed->selected_transform = -1;
      ike_reply_done(negotiation);
      return;
    }

  pl = &(negotiation->ngm_ed->sa_i->pl.sa);
  ssh_ike_clear_grp_attrs(&attrs);
  if (!ssh_ike_read_grp_attrs(negotiation,
                              &(pl->proposals[proposal_index].
                                protocols[0].
                                transforms[transforms_indexes[0]]),
                              &attrs))
    {
      SSH_IKE_DEBUG(3, negotiation, ("NGM sa: Internal policy manager error, "
                                     "policy manager selected proposal, "
                                     "that contains unsupported values"));
      negotiation->ngm_ed->selected_proposal = 0;
      negotiation->ngm_ed->selected_transform = -1;
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED);
      return;
    }
  /* We know that we only have one protocol */
  negotiation->ngm_ed->attributes = attrs;
  negotiation->ngm_ed->selected_proposal = proposal_index;
  negotiation->ngm_ed->selected_transform = transforms_indexes[0];

  ssh_free(transforms_indexes);
  ike_reply_done(negotiation);
  return;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * ike_cfg_attrs_reply
 * Process policy managers reply to cfg attrs.                  shade{1.0}
 */
void ike_cfg_attrs_reply(int number_of_attrs,
                         SshIkePayloadAttr *return_attributes,
                         void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->cfg_ed->number_of_local_attr_payloads = number_of_attrs;
  negotiation->cfg_ed->local_attrs = return_attributes;

  if (ike_reply_check_deleted(negotiation))
    return;

  ike_reply_done(negotiation);
  return;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 * ike_policy_reply_qm_nonce_data_len
 * Process policy managers reply to nonce len.                  shade{1.0}
 */
void ike_policy_reply_qm_nonce_data_len(size_t nonce_data_len,
                                        void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SSH_DEBUG(5, ("Start"));

  negotiation->qm_ed->nonce_data_len = nonce_data_len;

  if (ike_reply_check_deleted(negotiation))
    return;

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_policy_reply_qm_local_id
 * Process policy managers reply to local identity.             shade{1.0}
 */
void ike_policy_reply_qm_local_id(SshIkePayloadID id_payload,
                                  void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  char id_txt[255];
  SSH_DEBUG(5, ("Start"));

  negotiation->qm_pm_info->local_r_id = id_payload;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (id_payload == NULL)
    {
      negotiation->qm_ed->no_local_id = TRUE;
    }
  else
    {
      ssh_ike_id_to_string(id_txt, sizeof(id_txt), id_payload);
      ssh_free(negotiation->qm_pm_info->local_r_id_txt);
      negotiation->qm_pm_info->local_r_id_txt = ssh_strdup(id_txt);
      if (negotiation->qm_pm_info->local_r_id_txt == NULL)
        {
          ike_reply_return_error(negotiation,
                                 SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
          return;
        }
    }

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_policy_reply_qm_remote_id
 * Process policy managers reply to remote identity.            shade{1.0}
 */
void ike_policy_reply_qm_remote_id(SshIkePayloadID id_payload,
                                   void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  char id_txt[255];
  SSH_DEBUG(5, ("Start"));

  negotiation->qm_pm_info->remote_r_id = id_payload;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (id_payload == NULL)
    {
      negotiation->qm_ed->no_remote_id = TRUE;
    }
  else
    {
      ssh_ike_id_to_string(id_txt, sizeof(id_txt), id_payload);
      ssh_free(negotiation->qm_pm_info->remote_r_id_txt);
      negotiation->qm_pm_info->remote_r_id_txt = ssh_strdup(id_txt);
      if (negotiation->qm_pm_info->remote_r_id_txt == NULL)
        {
          ike_reply_return_error(negotiation,
                                 SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
          return;
        }
    }

  ike_reply_done(negotiation);
  return;
}


/*                                                              shade{0.9}
 * ike_qm_sa_reply
 * Process policy managers reply to sa query.                   shade{1.0}
 */
void ike_qm_sa_reply(SshIkeIpsecSelectedSAIndexes return_value,
                     void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  int i, j;
  SshIkePayloadSA sa;
  SshIkePayloadPProtocol proto;
  SshIkePayloadT t;
  SshIkeIpsecSelectedSAIndexes sel;
  SshIkeIpsecSelectedProtocol sel_pro;

  SSH_DEBUG(5, ("Start"));

  negotiation->qm_ed->indexes = return_value;

  if (ike_reply_check_deleted(negotiation))
    return;

  if (return_value == NULL)
    {
      negotiation->qm_ed->indexes =
        ssh_calloc(negotiation->qm_ed->number_of_sas,
                   sizeof(struct SshIkeIpsecSelectedSAIndexesRec));
      if (negotiation->qm_ed->indexes == NULL)
        {
          ike_reply_return_error(negotiation,
                                 SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
          return;
        }
      ike_reply_done(negotiation);
      return;
    }

  /* Copy / read selected sa information from sa proposals to selected_sas
     table */
  /* Allocate table */
  negotiation->qm_ed->selected_sas =
    ssh_calloc(negotiation->qm_ed->number_of_sas,
               sizeof(struct SshIkeIpsecSelectedSARec));
  if (negotiation->qm_ed->selected_sas == NULL)
    {
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
      return;
    }
  for (i = 0; i < negotiation->qm_ed->number_of_sas; i++)
    {
      sa = &(negotiation->qm_ed->sas_i[i]->pl.sa);
      sel = &(negotiation->qm_ed->indexes[i]);
      /* No proposal selected */
      if (sel->proposal_index == -1)
        {
          negotiation->qm_ed->selected_sas[i].number_of_protocols = 0;
          negotiation->qm_ed->selected_sas[i].protocols = NULL;
          SSH_DEBUG(5, ("No proposal selected for sa %d", i));
          continue;
        }

      negotiation->qm_ed->selected_sas[i].number_of_protocols =
        negotiation->qm_ed->indexes[i].number_of_protocols;
      negotiation->qm_ed->selected_sas[i].protocols =
        ssh_calloc(negotiation->qm_ed->selected_sas[i].number_of_protocols,
                   sizeof(struct SshIkeIpsecSelectedProtocolRec));
      if (negotiation->qm_ed->selected_sas[i].protocols == NULL)
        {
          ike_reply_return_error(negotiation,
                                 SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
          return;
        }
      /* Loop through all protocols */
      for (j = 0;
          j < negotiation->qm_ed->selected_sas[i].number_of_protocols;
          j++)
        {
          SSH_DEBUG(5,
                    ("Selected proposal %d, and transform %d for protocol %d",
                     sel->proposal_index,
                     sel->transform_indexes[j], j));
          proto = &(sa->proposals[sel->proposal_index].protocols[j]);
          sel_pro = &(negotiation->qm_ed->selected_sas[i].protocols[j]);
          sel_pro->protocol_id = proto->protocol_id;
          sel_pro->spi_size_out = proto->spi_size;
          sel_pro->spi_out = ssh_memdup(proto->spi, proto->spi_size);
          if (sel_pro->spi_out == NULL)
            {
              ike_reply_return_error(negotiation,
                                     SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
              return;
            }
          sel_pro->spi_size_in = sel->spi_sizes[j];
          sel_pro->spi_in = ssh_memdup(sel->spis[j], sel_pro->spi_size_in);
          if (sel_pro->spi_in == NULL)
            {
              ike_reply_return_error(negotiation,
                                     SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
              return;
            }
          t = &(proto->transforms[sel->transform_indexes[j]]);
          sel_pro->transform_id.generic = t->transform_id.generic;
          ssh_ike_clear_ipsec_attrs(&(sel_pro->attributes));
          if (!ssh_ike_read_ipsec_attrs(negotiation, t,
                                        &(sel_pro->attributes)))
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Internal policy manager error, "
                             "policy manager selected proposal, "
                             "that contains unsupported values"));
              for (i = 0; i < negotiation->qm_ed->number_of_sas; i++)
                {
                  if (negotiation->qm_ed->selected_sas[i].protocols)
                    {
                      for (j = 0; j < negotiation->qm_ed->
                            selected_sas[i].number_of_protocols; j++)
                        {
                          ssh_free(negotiation->qm_ed->
                                   selected_sas[i].protocols[j].spi_in);
                          ssh_free(negotiation->qm_ed->
                                   selected_sas[i].protocols[j].spi_out);
                        }
                      ssh_free(negotiation->qm_ed->selected_sas[i].protocols);
                    }
                }
              ssh_free(negotiation->qm_ed->selected_sas);
              negotiation->qm_ed->selected_sas = NULL;
              ike_reply_return_error(negotiation,
                              SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED);
              return;
            }
        }
    }

  ike_reply_done(negotiation);
  return;
}

/*                                                              shade{0.9}
 * ike_policy_reply_private_payload_out
 * Process policy managers reply to add private payloads.       shade{1.0}
 */
void ike_policy_reply_private_payload_out(int private_payload_id,
                                          unsigned char *data,
                                          size_t data_len,
                                          void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;
  SshIkePayload pl;

  SSH_DEBUG(5, ("Start"));

  if (ike_reply_check_deleted(negotiation))
    return;

  if (private_payload_id == 0)
    {
      ike_reply_done(negotiation);
      return;
    }

  pl = ike_append_payload(negotiation->sa->server_context->isakmp_context,
                          negotiation->ed->isakmp_packet_out,
                          negotiation->sa, negotiation,
                          SSH_IKE_PAYLOAD_TYPE_PRV);
  if (pl == NULL)
    {
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
      return;
    }
  /* Store the information to private payload */
  pl->pl.prv.prv_payload_id = private_payload_id;
  pl->pl.prv.data = ssh_memdup(data, data_len);
  if (pl->pl.prv.data == NULL)
    {
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
      return;
    }
  pl->payload_length = data_len;
  /* Register allocated data */
  if (!ike_register_item(negotiation->ed->isakmp_packet_out, pl->pl.prv.data))
    {
      ike_reply_return_error(negotiation,
                             SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY);
      return;
    }
  return;
}
