/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp state machine input functions module.
*/

#include "sshincludes.h"
#include "isakmp.h"
#include "isakmp_internal.h"
#include "isakmp_notify.h"
#include "sshdebug.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshIkeInput"

/*                                                              shade{0.9}
 * ike_st_i_sa_proposal
 * Call policy manager to query which proposal /
 * transforms to select.                                        shade{1.0}
 */




SshIkeNotifyMessageType ike_st_i_sa_proposal(SshIkeContext isakmp_context,
                                             SshIkePacket isakmp_input_packet,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             SshIkeStateMachine state)
{
  SshIkePayloadSA sa;

  SSH_DEBUG(5, ("Start"));

  /* Check that we have input packet */
  if (!isakmp_input_packet->first_sa_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No SA payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_sa_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple SA payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple SA payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  negotiation->ike_ed->sa_i = isakmp_input_packet->first_sa_payload;
  sa = &(isakmp_input_packet->first_sa_payload->pl.sa);

  if (negotiation->ike_ed->selected_proposal != -1)
    {
      /* Policy manager has responsed and answered to our query. */
      return 0;
    }

  negotiation->ike_pm_info->doi = sa->doi;

  /* Check situation is supported */
  if (sa->situation.situation_flags & SSH_IKE_SIT_SECRECY ||
      sa->situation.situation_flags & SSH_IKE_SIT_INTEGRITY)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Unsupported situation : %x",
                                     (int) sa->situation.situation_flags));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_SITUATION,
                    "Situation field contains flags that are not supported");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, 8,
                          "Invalid situation, secrecy or integrity bits set");
      return SSH_IKE_NOTIFY_MESSAGE_SITUATION_NOT_SUPPORTED;
    }
  /* Send query */
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
  ssh_policy_isakmp_select_sa(negotiation->ike_pm_info,
                              negotiation,
                              isakmp_input_packet->first_sa_payload,
                              ike_isakmp_sa_reply,
                              negotiation);

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of the
         packet until the policy manager answers and calls
         callback function. Clear PROCESSING_PM_QUERY flag before returning to
         the state machine. Note that state machine will set the
         WAITING_PM_REPLY flag. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  /* Policy manager replied immediately, check the reply */
  if (negotiation->ike_ed->selected_proposal == -1)
    {
      /* No proposal selected, return error */
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                    "Policy manager could not find any acceptable proposal");
      SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable proposal");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }
  /* Everything ok, return 0 */
  return 0;
}

/*                                                              shade{0.9}
 * ike_st_i_sa_value
 * Check that the proposal returned by responder
 * mathces one of your proposals sent to other end.
 * If so, store information about selected values
 * to isakmp_sa.                                                shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_sa_value(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayloadSA sa_i, sa_r;
  int proposal;
  struct SshIkeAttributesRec attrs;

  SSH_DEBUG(5, ("Start"));
  if (!isakmp_input_packet->first_sa_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No SA payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_sa_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple SA payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple SA payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  negotiation->ike_ed->sa_r = isakmp_input_packet->first_sa_payload;
  sa_r = &(isakmp_input_packet->first_sa_payload->pl.sa);
  sa_i = &(negotiation->ike_ed->sa_i->pl.sa);

  /* Check that doi's match */
  if (sa_i->doi != sa_r->doi)
    {
      SSH_IKE_DEBUG(3, negotiation, ("DOI changed : %d vs %d",
                                     sa_i->doi, sa_r->doi));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                    "DOI changed from our proposal");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, 4,
                          "DOI changed");
      return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
    }
  negotiation->ike_pm_info->doi = sa_i->doi;

  /* Check that situation is supported */
  if (sa_r->situation.situation_flags & SSH_IKE_SIT_SECRECY ||
      sa_r->situation.situation_flags & SSH_IKE_SIT_INTEGRITY)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Unsupported situation : %x",
                                     (int) sa_r->situation.situation_flags));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_SITUATION,
                    "Situation field contains flags that are not supported");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, 8,
                          "Invalid situation, secrecy or integrity bits set");
      return SSH_IKE_NOTIFY_MESSAGE_SITUATION_NOT_SUPPORTED;
    }

  /* Check that there is only one proposal */
  if (sa_r->number_of_proposals != 1)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Multiple proposals (%d) in the response SA",
                     sa_r->number_of_proposals));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, -1,
                          "Multiple proposal in the response SA, "
                          "must only contain 1");
      return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
    }

  /* Find that proposal from our initial sa list */
  for (proposal = 0; proposal < sa_i->number_of_proposals; proposal++)
    {
      if (sa_i->proposals[proposal].proposal_number ==
          sa_r->proposals[0].proposal_number)
        break;
    }
  /* If matching proposal id found, check that the proposals match */
  if (proposal == sa_i->number_of_proposals ||
      !ike_compare_proposals(negotiation, &sa_i->proposals[proposal],
                             &sa_r->proposals[0],
                             ike_compare_transforms_isakmp))
    {
      /* Either no matching proposal id, or the real proposals didn't match */

      /* Loop through all proposals and try to find match */
      for (proposal = 0; proposal < sa_i->number_of_proposals; proposal++)
        {
          if (ike_compare_proposals(negotiation, &sa_i->proposals[proposal],
                                    &sa_r->proposals[0],
                                    ike_compare_transforms_isakmp))
            break;
        }
      if (proposal == sa_i->number_of_proposals)
        {
          /* No proposal matched, return error */
          SSH_IKE_DEBUG(3, negotiation, ("No matching proposal found"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                        "Other end modified our proposal, or it returned "
                        "completely different proposal");
          SSH_IKE_NOTIFY_TEXT(negotiation,
                              "Responder modified our proposal, or "
                              "returned proposal not offered by us");
          return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
        }
    }
  ssh_ike_clear_isakmp_attrs(&attrs);
  /* We know that we only have one protocol */
  /* Read the attributes from the only (first) proposal, and only (first)
     transform. */
  if (!ssh_ike_read_isakmp_attrs(negotiation,
                                 &(sa_r->proposals[0].protocols[0].
                                   transforms[0]), &attrs))
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Internal error, proposal match found, but there is "
                     "unsupported values in proposal"));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                    "Proposal matched, but our own proposal contained "
                    "unsupported values");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }
  /* Make sure that the authentication method is set to proper values */
  negotiation->ike_pm_info->auth_method = attrs.auth_method;
  switch (attrs.auth_method)
    {
    case SSH_IKE_VALUES_AUTH_METH_PRE_SHARED_KEY:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_PRE_SHARED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_PRE_SHARED:
#endif /* SSHDIST_IKE_XAUTH */
      negotiation->ike_pm_info->auth_method_type =
        SSH_IKE_AUTH_METHOD_PRE_SHARED_KEY;
      break;
#ifdef SSHDIST_IKE_CERT_AUTH
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
      negotiation->ike_pm_info->auth_method_type =
        SSH_IKE_AUTH_METHOD_SIGNATURES;
      break;
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED:
#ifdef SSHDIST_IKE_XAUTH
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED:
    case SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED:
#endif /* SSHDIST_IKE_XAUTH */
      negotiation->ike_pm_info->auth_method_type =
        SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION;
      break;
#endif /* SSHDIST_IKE_CERT_AUTH */
    default:
      SSH_IKE_DEBUG(3, negotiation,
                    ("Another end selected authentication method, "
                     "that is not supported"));
      return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;
    }
  negotiation->ed->auth_method_type =
    negotiation->ike_pm_info->auth_method_type;

#ifdef SSHDIST_IKE_XAUTH
  if (attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_I_DSS_SIGNATURES ||
      attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_I_RSA_SIGNATURES)
    negotiation->ike_pm_info->hybrid_client = 1;
  else
  if (attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_R_DSS_SIGNATURES ||
      attrs.auth_method == SSH_IKE_VALUES_AUTH_METH_HYBRID_R_RSA_SIGNATURES)
    negotiation->ike_pm_info->hybrid_edge = 1;
#endif /* SSHDIST_IKE_XAUTH */

  negotiation->ike_pm_info->sa_start_time = ssh_time();
  if (attrs.life_duration_secs == 0)
    {
      negotiation->ike_pm_info->sa_expire_time =
        negotiation->ike_pm_info->sa_start_time +
        SSH_IKE_DEFAULT_LIFE_DURATION;
    }
  else
    {
      negotiation->ike_pm_info->sa_expire_time =
        negotiation->ike_pm_info->sa_start_time +
        attrs.life_duration_secs;
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
                        ("Another end selected proposal, that contains "
                         "both group descriptor and group parameters"));
          return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;
        }

      ssh_ike_clear_grp_attrs(&grp_attrs);

      if (!ssh_ike_read_grp_attrs(negotiation,
                                  &(sa_r->proposals[0].protocols[0].
                                    transforms[0]),
                                  &grp_attrs))
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Another end selected proposal, that contains "
                         "unsupported group values"));
          return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;
        }
      /* Insert it as group -1 */
      ike_remove_group(negotiation, -1);
      grp_attrs.group_descriptor = -1;
      attrs.group_desc = ike_add_group(negotiation, &grp_attrs);
      ssh_ike_free_grp_attrs(&grp_attrs);
      if (attrs.group_desc == NULL)
        {
          SSH_DEBUG(3, ("Error inserting private group"));
          return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;
        }
    }

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

  negotiation->ike_ed->selected_proposal = proposal;
  negotiation->ike_ed->selected_transform = -1; /* Not intresting */
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_ke
 * Store pointer to the key exchange packet.                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_ke(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state)
{
  SshIkePayload ke;

  if (!isakmp_input_packet->first_ke_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No KE payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_ke_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple KE payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_KE,
                          isakmp_input_packet->first_ke_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_ke_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple KE payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  ke = isakmp_input_packet->first_ke_payload;
  SSH_DEBUG(5, ("Ke[0..%zd] = %08lx %08lx ...",
                ke->pl.ke.key_exchange_data_len,
                (unsigned long)
                SSH_IKE_GET32(ke->pl.ke.key_exchange_data),
                (unsigned long)
                SSH_IKE_GET32(ke->pl.ke.key_exchange_data+4)));

  if (negotiation->ike_pm_info->this_end_is_initiator)
    negotiation->ike_ed->ke_r = ke;
  else
    negotiation->ike_ed->ke_i = ke;
  return 0;
}

/*                                                              shade{0.9}
 * ike_st_i_id
 * Handle ID payload. Note it can be also be encrypted
 * with rsa private key in case of rsa authentication.          shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_id(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload id;
  unsigned char *p;
  size_t len;
  char id_txt[255];

  SSH_DEBUG(5, ("Start"));
  if (!isakmp_input_packet->first_id_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No ID payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_id_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple ID payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                          isakmp_input_packet->first_id_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_id_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple ID payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  id = isakmp_input_packet->first_id_payload;

  /* Read information from packet */
  p = id->pl.id.raw_id_packet;
  len = id->payload_length;

#ifdef SSHDIST_IKE_CERT_AUTH
  if (negotiation->ed->auth_method_type ==
      SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION)
    {
      /* If using rsa encryption authentication
         method find the public key first and
         decrypt the packet using it */

      ret = ike_rsa_decrypt_data(isakmp_context, isakmp_sa, negotiation,
                                 p, id->payload_length,
                                 &p, &len);
      if (ret != 0)
        return ret;

      SSH_IKE_DEBUG_BUFFER(9, negotiation, "Decrypted id", len, p);

      /* Register the mallocated item */
      if (!ike_register_item(isakmp_input_packet, p))
        {
          ssh_free(p);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }
    }
#endif /* SSHDIST_IKE_CERT_AUTH */

  ret = ike_decode_id(isakmp_context, negotiation, id, p, len);
  if (ret != 0)
    return ret;

#ifdef SSHDIST_IKE_ID_LIST
  if ((&id->pl.id)->id_type == IPSEC_ID_LIST &&
      (&id->pl.id)->identification.id_list_items)
    (void) ike_register_item(isakmp_input_packet,
                            (unsigned char *)((&id->pl.id)->
                                        identification.id_list_items));
#endif /* SSHDIST_IKE_ID_LIST */

  if (id->pl.id.port_number != 0 &&
      id->pl.id.port_number != 500)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Warning, ISAKMP SA id port != 0 and port != 500 (== %d)",
                     id->pl.id.port_number));
    }

  negotiation->ike_pm_info->remote_id = ssh_ike_id_dup(&(id->pl.id));

  if (negotiation->ike_pm_info->remote_id == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  ssh_ike_id_to_string(id_txt, sizeof(id_txt),
                       negotiation->ike_pm_info->remote_id);
  ssh_free(negotiation->ike_pm_info->remote_id_txt);
  negotiation->ike_pm_info->remote_id_txt = ssh_strdup(id_txt);
  if (negotiation->ike_pm_info->remote_id_txt == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_cert
 * Handle certificates.                                         shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_cert(SshIkeContext isakmp_context,
                                      SshIkePacket isakmp_input_packet,
                                      SshIkeSA isakmp_sa,
                                      SshIkeNegotiation negotiation,
                                      SshIkeStateMachine state)
{
#ifdef SSHDIST_IKE_CERT_AUTH
  SshIkePayload cert;

  SSH_DEBUG(5, ("Start"));

  if (isakmp_input_packet == NULL)
    return 0;

  cert = isakmp_input_packet->first_cert_payload;
  while (cert != NULL)
    {
      /* Here we simply call policy manager and ask it to process the
         certificates. If it trusts them, it will add the keys to its own
         database, and we will receive them when we call
         ssh_policy_find_public_key. */
      ssh_policy_new_certificate(negotiation->ike_pm_info,
                                 cert->pl.cert.cert_encoding,
                                 cert->pl.cert.certificate_data,
                                 cert->pl.cert.certificate_data_len);
      /* Process next certificate payload */
      cert = cert->next_same_payload;
    }
#endif /* SSHDIST_IKE_CERT_AUTH */
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_cr
 * Handle certificate requests.                                 shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_cr(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_input_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkeStateMachine state)
{
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  SshIkePayload pl;
  SshIkePayloadCR cr;

  if (isakmp_input_packet == NULL)
    return 0;

  SSH_DEBUG(5, ("Start"));
  /* Nothing to be done here, perhaps later we will ask
     policy manager to request certificates this time and assume
     they are ready when we call ike_st_o_cert */
  pl = isakmp_input_packet->first_cr_payload;
  while (pl != NULL)
    {
      cr = &(pl->pl.cr);

      if (cr->certificate_authority_len != 0)
        {
          if (isakmp_context->policy_functions->certificate_request)
            {
              (*isakmp_context->policy_functions->
               certificate_request)(negotiation->ike_pm_info,
                                    cr->certificate_type,
                                    cr->certificate_authority,
                                    cr->certificate_authority_len);
            }
        }
      /* Process next certificate payload */
      pl = pl->next_same_payload;
    }
#endif /* SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */
#endif /* SSHDIST_IKE_CERT_AUTH */
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_hash
 * Verify that the exchange hash matches.                       shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_hash(SshIkeContext isakmp_context,
                                      SshIkePacket isakmp_input_packet,
                                      SshIkeSA isakmp_sa,
                                      SshIkeNegotiation negotiation,
                                      SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH], *p;
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;

  if (!isakmp_input_packet->first_hash_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No HASH payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_hash_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple HASH payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple HASH payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_hash_payload;
  SSH_DEBUG(5, ("Start, hash[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data + 4)));

  /* Take a copy of the hash. */
  p = ike_register_copy(isakmp_input_packet, pl->pl.hash.hash_data,
                        pl->payload_length);
  if (p == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Clear the hash, so it can be used as a revised hash calculation */
  memset(pl->pl.hash.hash_data, 0, pl->payload_length);

  /* Move the hash_data to point to copy */
  pl->pl.hash.hash_data = p;

  ret = ike_calc_mac(isakmp_context, isakmp_sa, negotiation,
                     hash, &hash_len, FALSE, NULL);
  if (ret != 0)
    return ret;

  if (hash_len != pl->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash length mismatch %d != %d",
                                     hash_len, pl->payload_length));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload length does not match the algorithm");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }
  if (memcmp(hash, pl->pl.hash.hash_data, hash_len) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash value mismatch"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload data does not match");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


#ifdef SSHDIST_IKE_CERT_AUTH
/*                                                              shade{0.9}
 * ike_st_i_hash_key
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_hash_key(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;

  pl = isakmp_input_packet->first_hash_payload;
  if (pl == NULL)
    {
      SSH_DEBUG(5, ("Start, no key_hash"));
      return 0;
    }
  if (isakmp_input_packet->first_hash_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple HASH payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple HASH payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  SSH_DEBUG(5, ("Start, key_hash[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data + 4)));

  return ike_find_private_key(isakmp_context, isakmp_sa, negotiation,
                              pl->pl.hash.hash_data, pl->payload_length,
                              isakmp_sa->hash_algorithm_name);
}

/*                                                              shade{0.9}
 * ike_st_i_sig_verify_cb
 * Signature verification done, store result.                   shade{1.0}
 */

void ike_st_i_sig_verify_cb(SshCryptoStatus status,
                            void *context)
{
  SshIkeNegotiation negotiation = (SshIkeNegotiation) context;

  if (status == SSH_CRYPTO_OK)
    {
      negotiation->ike_ed->sig_verify_state =
        SSH_IKE_SIGNATURE_VERIFY_STATE_OK;
    }
  else
    {
      negotiation->ike_ed->sig_verify_state =
        SSH_IKE_SIGNATURE_VERIFY_STATE_FAILED;
    }

 /* Check if we need to restart the state machine */
  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY)
    ike_state_restart_packet(negotiation);
}

/*                                                              shade{0.9}
 * ike_st_i_sig
 * Calculate hash for exchange and verify the
 * signature given by input packet.                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_sig(SshIkeContext isakmp_context,
                                     SshIkePacket isakmp_input_packet,
                                     SshIkeSA isakmp_sa,
                                     SshIkeNegotiation negotiation,
                                     SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  unsigned char *hash;
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
#ifdef SSHDIST_IKE_XAUTH
  SshIkePayload n;
#endif /* SSHDIST_IKE_XAUTH */
  SshIkePayload sig;
  const unsigned char *mac_name;
  char *key_type;
  SshCryptoStatus cret;
  SshOperationHandle handle;
  unsigned char *signature;

#ifdef SSHDIST_IKE_XAUTH
      if (negotiation->ike_pm_info->hybrid_edge)
        {
          hash = ike_register_new(isakmp_input_packet, hash_len);
          if (hash == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

          ret = ike_calc_psk_hash(isakmp_context, isakmp_sa, negotiation,
                                  hash, &hash_len);
          if (ret != 0)
            return ret;

          n = isakmp_input_packet->first_n_payload;
          while (n != NULL)
            {
              if (n->pl.n.notify_message_type ==
                  SSH_IKE_NOTIFY_MESSAGE_CISCO_PSK_HASH)
                break;
              n = n->next_same_payload;
            }
          if (n == NULL)
            {
              SSH_IKE_DEBUG(3, negotiation, ("No PSK hash payload found!"));
              return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
            }

          if (n->pl.n.notification_data_size != hash_len ||
              memcmp(n->pl.n.notification_data, hash, hash_len))
            {
              SSH_IKE_DEBUG(3, negotiation, ("PSK hash mismatch"));
              return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
            }

          return ike_st_i_hash(isakmp_context,
                               isakmp_input_packet,
                               isakmp_sa,
                               negotiation,
                               state);
        }
#endif /* SSHDIST_IKE_XAUTH */

  sig = isakmp_input_packet->first_sig_payload;

  if (negotiation->ike_ed->sig_verify_state ==
      SSH_IKE_SIGNATURE_VERIFY_STATE_OK)
    {
      SSH_DEBUG(5, ("Signature check succeeded"));
      return 0;
    }
  else if (negotiation->ike_ed->sig_verify_state ==
      SSH_IKE_SIGNATURE_VERIFY_STATE_FAILED)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Signature check failed"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sig_payload->
                          payload_start,
                          isakmp_input_packet->first_sig_payload->
                          payload_length, -1,
                          "Signature check failed");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_SIGNATURE;
    }

  if (!isakmp_input_packet->first_sig_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No SIG payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_sig_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple SIG payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SIG,
                          isakmp_input_packet->first_sig_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_sig_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple SIG payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }

  SSH_DEBUG(5, ("Start, sig[0..%zd] = %08lx %08lx ...",
                sig->payload_length,
                (unsigned long)
                SSH_IKE_GET32(sig->pl.sig.signature_data),
                (unsigned long)
                SSH_IKE_GET32(sig->pl.sig.signature_data + 4)));

  ret = ike_find_public_key(isakmp_context, isakmp_sa, negotiation,
                            NULL, 0, NULL);
  if (ret != 0)
    return ret;

  cret = ssh_public_key_get_info(negotiation->ike_ed->public_key,
                                 SSH_PKF_KEY_TYPE, &key_type, SSH_PKF_END);

  if (cret != SSH_CRYPTO_OK)
    {
      SSH_IKE_DEBUG(3, negotiation, ("public_key_get_info failed: %.200s",
                                     ssh_crypto_status_message(cret)));
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }

  mac_name = NULL;
  if (strcmp(key_type, "dl-modp") == 0)
    {
      cret = ssh_public_key_select_scheme(negotiation->ike_ed->public_key,
                                          SSH_PKF_SIGN, "dsa-nist-sha1",
                                          SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_public_key_select_scheme failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      mac_name = ssh_custr("hmac-sha1");
    }
  else if (strcmp(key_type, "if-modn") == 0)
    {
      cret = ssh_public_key_select_scheme(negotiation->ike_ed->public_key,
                                          SSH_PKF_SIGN, "rsa-pkcs1-none",
                                          SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_public_key_select_scheme failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
#ifdef SSHDIST_CRYPT_ECP
  else if (strcmp(key_type, "ec-modp") == 0)
    {
      const char *scheme;
      SshIkeAttributeAuthMethValues auth_method =
        negotiation->ike_ed->attributes.auth_method;

      if (!ike_get_ecp_scheme_and_mac(auth_method,
                                      &scheme, &mac_name))
        {
          SSH_IKE_DEBUG(3, negotiation,
                      ("Unable to get the applicable public key scheme"));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
      cret = ssh_public_key_select_scheme(negotiation->ike_ed->public_key,
                                        SSH_PKF_SIGN,scheme,
                                        SSH_PKF_END);
      if (cret != SSH_CRYPTO_OK)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("ssh_public_key_select_scheme failed: %.200s",
                         ssh_crypto_status_message(cret)));
          return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
        }
    }
#endif /* SSHDIST_CRYPT_ECP */

  signature = ike_register_copy(isakmp_input_packet,
                                sig->pl.sig.signature_data,
                                sig->payload_length);
  if (signature == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Clear the sig, so it can be used as a revised hash calculation */
  memset(sig->pl.sig.signature_data, 0, sig->payload_length);

  /* Move the signature_data to point to copy */
  sig->pl.sig.signature_data = signature;

  hash = ike_register_new(isakmp_input_packet, hash_len);
  if (hash == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  ret = ike_calc_mac(isakmp_context, isakmp_sa, negotiation,
                     hash, &hash_len, FALSE, mac_name);
  if (ret != 0)
    return ret;

  handle = ssh_public_key_verify_digest_async(negotiation->ike_ed->
                                              public_key,
                                              signature,
                                              sig->payload_length,
                                              hash, hash_len,
                                              ike_st_i_sig_verify_cb,
                                              negotiation);
  /* Check if we started async operation, or if it is answered directly. */
  if (handle != NULL)
    {
      /* We started real async operation, go on wait */
      SSH_IKE_DEBUG(6, negotiation,
                    ("Asyncronous public key operation started"));
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  if (negotiation->ike_ed->sig_verify_state ==
      SSH_IKE_SIGNATURE_VERIFY_STATE_OK)
    {
      SSH_DEBUG(5, ("Signature check succeeded"));
      return 0;
    }
  SSH_IKE_DEBUG(3, negotiation, ("Signature check failed"));
  SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                      isakmp_input_packet->first_sig_payload->
                      payload_start,
                      isakmp_input_packet->first_sig_payload->
                      payload_length, -1,
                      "Signature check failed");
  return SSH_IKE_NOTIFY_MESSAGE_INVALID_SIGNATURE;
}
#endif /* SSHDIST_IKE_CERT_AUTH */


/*                                                              shade{0.9}
 * ike_st_i_nonce
 * Nonce payload handling.                                      shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_nonce(SshIkeContext isakmp_context,
                                       SshIkePacket isakmp_input_packet,
                                       SshIkeSA isakmp_sa,
                                       SshIkeNegotiation negotiation,
                                       SshIkeStateMachine state)
{
  SshIkePayload pl;

  if (!isakmp_input_packet->first_nonce_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No NONCE payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_nonce_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple NONCE payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_NONCE,
                          isakmp_input_packet->first_nonce_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_nonce_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple NONCE payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_nonce_payload;
  SSH_DEBUG(5, ("Start, nonce[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.nonce.raw_nonce_packet),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.nonce.raw_nonce_packet + 4)));

  if (pl->payload_length < 8 ||
      pl->payload_length > 256)
    {
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_NONCE,
                          isakmp_input_packet->first_nonce_payload->
                          payload_start,
                          isakmp_input_packet->first_nonce_payload->
                          payload_length, -1,
                          "Nonce length not between 8 and 256 bytes");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }

#ifdef SSHDIST_IKE_CERT_AUTH
  if (negotiation->ed->auth_method_type ==
      SSH_IKE_AUTH_METHOD_PUBLIC_KEY_ENCRYPTION)
    {
      SshIkeNotifyMessageType ret;
      unsigned char *p;
      size_t len;

      /* If using rsa encryption authentication method decrypt the packet
         first */
      ret = ike_rsa_decrypt_data(isakmp_context, isakmp_sa, negotiation,
                                 pl->pl.nonce.raw_nonce_packet,
                                 pl->payload_length,
                                 &p, &len);
      if (ret != 0)
        return ret;

      SSH_IKE_DEBUG_BUFFER(9, negotiation, "Decrypted nonce", len, p);

      /* Register the mallocated item */
      if (!ike_register_item(isakmp_input_packet, p))
        {
          ssh_free(p);
          return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
        }

      /* Change the encrypted data with nonencrypted data */
      pl->pl.nonce.nonce_data = p;
      pl->pl.nonce.nonce_data_len = len;

      /* Check for revised encryption method */
      if (negotiation->ike_pm_info->auth_method ==
          SSH_IKE_VALUES_AUTH_METH_RSA_ENCRYPTION_REVISED)
        {
          /* Decrypt rest of the packets */



          return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;
        }
#ifdef SSHDIST_IKE_XAUTH
      if (negotiation->ike_pm_info->auth_method ==
          SSH_IKE_VALUES_AUTH_METH_XAUTH_I_RSA_ENCRYPTION_REVISED ||
          negotiation->ike_pm_info->auth_method ==
          SSH_IKE_VALUES_AUTH_METH_XAUTH_R_RSA_ENCRYPTION_REVISED)
        {
          /* Decrypt rest of the packets */



          return SSH_IKE_NOTIFY_MESSAGE_ATTRIBUTES_NOT_SUPPORTED;
        }
#endif /* SSHDIST_IKE_XAUTH */
    }
  else
#endif /* SSHDIST_IKE_CERT_AUTH */
    {
      pl->pl.nonce.nonce_data = pl->pl.nonce.raw_nonce_packet;
      pl->pl.nonce.nonce_data_len = pl->payload_length;
    }
  if (negotiation->ike_pm_info->this_end_is_initiator)
    negotiation->ike_ed->nonce_r = pl;
  else
    negotiation->ike_ed->nonce_i = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_hash_1
 * Calc quick mode authentication hash and check it.            shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_hash_1(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  unsigned char *p;

  if (!isakmp_input_packet->first_hash_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No HASH payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_hash_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple HASH payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple HASH payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_hash_payload;
  SSH_DEBUG(5, ("Start, hash[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data + 4)));

  /* Take a copy of the hash. */
  p = ike_register_copy(isakmp_input_packet, pl->pl.hash.hash_data,
                        pl->payload_length);
  if (p == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Clear the hash, so it can be used as a revised hash calculation */
  memset(pl->pl.hash.hash_data, 0, pl->payload_length);

  /* Move the hash_data to point to copy */
  pl->pl.hash.hash_data = p;

  ret = ike_calc_qm_hash(isakmp_context, isakmp_sa, negotiation,
                         isakmp_input_packet, hash, &hash_len, FALSE);

  if (ret != 0)
    return ret;

  if (hash_len != pl->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash length mismatch %d != %d",
                                     hash_len, pl->payload_length));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload length does not match the algorithm");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }
  if (memcmp(hash, pl->pl.hash.hash_data, hash_len) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash value mismatch"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload data does not match");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_hash_2
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_hash_2(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  unsigned char *p;

  if (!isakmp_input_packet->first_hash_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No HASH payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_hash_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple HASH payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple HASH payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_hash_payload;
  SSH_DEBUG(5, ("Start, hash[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data + 4)));

  /* Take a copy of the hash. */
  p = ike_register_copy(isakmp_input_packet, pl->pl.hash.hash_data,
                        pl->payload_length);
  if (p == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Clear the hash, so it can be used as a revised hash calculation */
  memset(pl->pl.hash.hash_data, 0, pl->payload_length);

  /* Move the hash_data to point to copy */
  pl->pl.hash.hash_data = p;

  ret = ike_calc_qm_hash(isakmp_context, isakmp_sa, negotiation,
                         isakmp_input_packet, hash, &hash_len, TRUE);

  if (ret != 0)
    return ret;

  if (hash_len != pl->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash length mismatch %d != %d",
                                     hash_len, pl->payload_length));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload length does not match the algorithm");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }
  if (memcmp(hash, pl->pl.hash.hash_data, hash_len) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash value mismatch"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload data does not match");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_hash_3
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_hash_3(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  unsigned char *p;

  if (!isakmp_input_packet->first_hash_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No HASH payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_hash_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple HASH payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple HASH payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_hash_payload;
  SSH_DEBUG(5, ("Start, hash[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data + 4)));

  /* Take a copy of the hash. */
  p = ike_register_copy(isakmp_input_packet, pl->pl.hash.hash_data,
                        pl->payload_length);
  if (p == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Clear the hash, so it can be used as a revised hash calculation */
  memset(pl->pl.hash.hash_data, 0, pl->payload_length);

  /* Move the hash_data to point to copy */
  pl->pl.hash.hash_data = p;

  ret = ike_calc_qm_hash_3(isakmp_context, isakmp_sa, negotiation,
                           isakmp_input_packet, hash, &hash_len);

  if (ret != 0)
    return ret;

  if (hash_len != pl->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash length mismatch %d != %d",
                                     hash_len, pl->payload_length));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload length does not match the algorithm");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }
  if (memcmp(hash, pl->pl.hash.hash_data, hash_len) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash value mismatch"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload data does not match");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_sa_proposals
 * Process other ends sa proposals.                             shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_sa_proposals(SshIkeContext isakmp_context,
                                                 SshIkePacket
                                                 isakmp_input_packet,
                                                 SshIkeSA isakmp_sa,
                                                 SshIkeNegotiation negotiation,
                                                 SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i, sa_count;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->qm_ed->indexes != NULL)
    {
      /* Policy manager has responsed and answered to our query. */
      return 0;
    }

  /* Count number of sa requests */
  pl = isakmp_input_packet->first_sa_payload;
  for (sa_count = 0; pl != NULL; pl = pl->next_same_payload, sa_count++)
    ;

  if (sa_count == 0)
    {
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                    "Quick mode SA payload missing when trying"
                    " to select proposal");
      SSH_IKE_NOTIFY_TEXT(negotiation, "No SA payload found");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }

  pl = isakmp_input_packet->first_sa_payload;

  negotiation->qm_ed->sas_i = ssh_calloc(sa_count, sizeof(SshIkePayload));
  if (negotiation->qm_ed->sas_i == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  negotiation->qm_ed->number_of_sas = sa_count;
  for (i = 0; i < sa_count; i++, pl = pl->next_same_payload)
    {
      if (pl->pl.sa.doi != SSH_IKE_DOI_IPSEC)
        {
          SSH_IKE_DEBUG(3, negotiation, ("Invalid doi = %d, should be %d",
                                         pl->pl.sa.doi, SSH_IKE_DOI_IPSEC));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                        "SA payload contains invalid DOI number");

          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                              pl->payload_start, pl->payload_length, 4,
                              "Invalid DOI value, should be 1");
          return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
        }
      negotiation->qm_ed->sas_i[i] = pl;
    }

  /* Send query */
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
  ssh_policy_qm_select_sa(negotiation->qm_pm_info,
                          negotiation,
                          sa_count,
                          negotiation->qm_ed->sas_i,
                          ike_qm_sa_reply,
                          negotiation);

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of the
         packet until the policy manager answers and calls
         callback function. Clear PROCESSING_PM_QUERY flag before returning to
         the state machine. Note that state machine will set the
         WAITING_PM_REPLY flag. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }

  /* Policy manager replied immediately, check the reply */
  if (negotiation->qm_ed->selected_sas == NULL)
    {
      /* No proposal selected, return error */
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                    "Policy manager could not find any acceptable "
                    "proposal for quick mode");
      SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable proposal");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }
  /* Everything ok, return 0 */
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_sa_values
 * Quick mode initiator handling selected sa.                   shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_sa_values(SshIkeContext isakmp_context,
                                              SshIkePacket isakmp_input_packet,
                                              SshIkeSA isakmp_sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkePayloadSA sa_i, sa_r;
  int proposal;
  int i, sa_count, j;
  SshIkePayloadPProtocol proto;
  SshIkeIpsecSelectedProtocol sel_pro;
  SshIkePayloadT t;
  SshIkeAttributeLifeDurationValues min_life_duration_secs,
    min_life_duration_kb;

  SSH_DEBUG(5, ("Start"));

  /* Count number of sa replies */
  pl = isakmp_input_packet->first_sa_payload;
  for (sa_count = 0; pl != NULL; pl = pl->next_same_payload, sa_count++)
    ;

  /* Check if it matches our proposals */
  if (sa_count != negotiation->qm_ed->number_of_sas)
    {
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          NULL, 0, -1,
                          "Number of returned SA payloads does not match "
                          "to the number of sent SA payloads");
      return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
    }

  pl = isakmp_input_packet->first_sa_payload;

  negotiation->qm_ed->sas_r = ssh_calloc(sa_count, sizeof(SshIkePayload));
  if (negotiation->qm_ed->sas_r == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
  negotiation->qm_ed->selected_sas =
    ssh_calloc(sa_count, sizeof(struct SshIkeIpsecSelectedSARec));
  if (negotiation->qm_ed->selected_sas == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  min_life_duration_secs = -1;
  min_life_duration_kb = -1;
  for (i = 0; i < sa_count; i++, pl = pl->next_same_payload)
    {
      negotiation->qm_ed->sas_r[i] = pl;
      sa_i = &(negotiation->qm_ed->sas_i[i]->pl.sa);
      sa_r = &(negotiation->qm_ed->sas_r[i]->pl.sa);

      /* Check proposal */
      if (sa_r->number_of_proposals != 1)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Multiple proposals (%d) in the response SA",
                         sa_r->number_of_proposals));
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                              isakmp_input_packet->first_sa_payload->
                              payload_start,
                              isakmp_input_packet->first_sa_payload->
                              payload_length, -1,
                              "Multiple proposal in the response SA, "
                              "must only contain 1");
          return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
        }
      /* Find that proposal from our initial sa list */
      for (proposal = 0; proposal < sa_i->number_of_proposals; proposal++)
        {
          if (sa_i->proposals[proposal].proposal_number ==
              sa_r->proposals[0].proposal_number)
            break;
        }
      /* If matching proposal id found, check that the proposals match */
      if (proposal == sa_i->number_of_proposals ||
          !ike_compare_proposals(negotiation, &sa_i->proposals[proposal],
                                 &sa_r->proposals[0],
                                 ike_compare_transforms_ipsec))
        {
          /* Either no matching proposal id, or the real proposals didn't
             match */

          /* Loop through all proposals and try to find match */
          for (proposal = 0; proposal < sa_i->number_of_proposals; proposal++)
            {
              if (ike_compare_proposals(negotiation,
                                        &sa_i->proposals[proposal],
                                        &sa_r->proposals[0],
                                        ike_compare_transforms_ipsec))
                break;
            }
          if (proposal == sa_i->number_of_proposals)
            {
              /* No proposal matched, return error */
              SSH_IKE_DEBUG(3, negotiation, ("No matching proposal found"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                            "Other end modified our quick mode proposal, or "
                            "it returned completely different proposal");
              SSH_IKE_NOTIFY_TEXT(negotiation,
                                  "Responder modified our proposal, or "
                                  "returned proposal not offered by us");
              return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
            }
        }

      negotiation->qm_ed->selected_sas[i].number_of_protocols =
        sa_r->proposals[0].number_of_protocols;
      negotiation->qm_ed->selected_sas[i].protocols =
        ssh_calloc(negotiation->qm_ed->selected_sas[i].number_of_protocols,
                    sizeof(struct SshIkeIpsecSelectedProtocolRec));
      if (negotiation->qm_ed->selected_sas[i].protocols == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      for (j = 0;
           j < negotiation->qm_ed->selected_sas[i].number_of_protocols;
           j++)
        {
          int pro;

          proto = &(sa_r->proposals[0].protocols[j]);
          sel_pro = &(negotiation->qm_ed->selected_sas[i].protocols[j]);
          for (pro = 0;
               pro < sa_i->proposals[proposal].number_of_protocols;
               pro++)
            if (sa_i->proposals[proposal].protocols[pro].protocol_id ==
                proto->protocol_id)
              break;
          sel_pro->protocol_id = proto->protocol_id;
          sel_pro->spi_size_out = proto->spi_size;
          sel_pro->spi_out = ssh_memdup(proto->spi, proto->spi_size);
          if (sel_pro->spi_out == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
          sel_pro->spi_size_in =
            sa_i->proposals[proposal].protocols[pro].spi_size;
          sel_pro->spi_in =
            ssh_memdup(sa_i->proposals[proposal].protocols[pro].spi,
                        sel_pro->spi_size_in);
          if (sel_pro->spi_in == NULL)
            return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
          t = &(proto->transforms[0]);
          sel_pro->transform_id.generic = t->transform_id.generic;
          ssh_ike_clear_ipsec_attrs(&(sel_pro->attributes));
          if (!ssh_ike_read_ipsec_attrs(negotiation, t,
                                        &(sel_pro->attributes)))
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Internal error our own proposal had "
                             "unsupported values"));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                            "Proposal matched, but our own quick mode "
                            "proposal contained unsupported values");
              return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
            }
          if (sel_pro->attributes.life_duration_secs != 0 &&
              sel_pro->attributes.life_duration_secs <
              min_life_duration_secs)
            {
              min_life_duration_secs = sel_pro->attributes.life_duration_secs;
            }
          if (sel_pro->attributes.life_duration_kb != 0 &&
              sel_pro->attributes.life_duration_kb <
              min_life_duration_kb)
            {
              min_life_duration_kb = sel_pro->attributes.life_duration_kb;
            }
        }
    }
  if (min_life_duration_secs == -1)
    negotiation->qm_pm_info->sa_expire_timer_sec = 0;
  else
    negotiation->qm_pm_info->sa_expire_timer_sec = min_life_duration_secs;
  if (min_life_duration_kb == -1)
    negotiation->qm_pm_info->sa_expire_timer_kb = 0;
  else
    negotiation->qm_pm_info->sa_expire_timer_kb = min_life_duration_kb;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_ids
 * Store qm id values to exchange data.                         shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_ids(SshIkeContext isakmp_context,
                                        SshIkePacket isakmp_input_packet,
                                        SshIkeSA isakmp_sa,
                                        SshIkeNegotiation negotiation,
                                        SshIkeStateMachine state)
{
  SshIkeNotifyMessageType ret;
  SshIkePayload id;
  unsigned char *p;
  size_t len;
  int i;

  id = isakmp_input_packet->first_id_payload;

  i = 0;
  while (id != NULL)
    {
      char id_txt[255];
      SshIkePayloadID id_copy;

      /* Read information from packet */
      p = id->pl.id.raw_id_packet;
      len = id->payload_length;

      ret = ike_decode_id(isakmp_context, negotiation, id, p, len);

      if (ret != 0)
        return ret;

#ifdef SSHDIST_IKE_ID_LIST
      if ((&id->pl.id)->id_type == IPSEC_ID_LIST &&
          (&id->pl.id)->identification.id_list_items)
        (void) ike_register_item(isakmp_input_packet,
                                (unsigned char *)((&id->pl.id)->
                                            identification.id_list_items));
#endif /* SSHDIST_IKE_ID_LIST */

      id_copy = ssh_ike_id_dup(&(id->pl.id));

      if (id_copy == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
      ssh_ike_id_to_string(id_txt, sizeof(id_txt), id_copy);

      if (!negotiation->qm_pm_info->this_end_is_initiator)
        {
          if (i == 0)
            {
              negotiation->qm_pm_info->remote_i_id = id_copy;
              ssh_free(negotiation->qm_pm_info->remote_i_id_txt);
              negotiation->qm_pm_info->remote_i_id_txt = ssh_strdup(id_txt);
              if (negotiation->qm_pm_info->remote_i_id_txt == NULL)
                return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

            }
          else if (i == 1)
            {
              negotiation->qm_pm_info->local_i_id = id_copy;
              ssh_free(negotiation->qm_pm_info->local_i_id_txt);
              negotiation->qm_pm_info->local_i_id_txt = ssh_strdup(id_txt);
              if (negotiation->qm_pm_info->local_i_id_txt == NULL)
                return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }
          else
            {
              ssh_free(id_copy);
              SSH_IKE_DEBUG(3, negotiation, ("More than 2 ids in qm"));
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                                  id->payload_start, id->payload_length, -1,
                                  "More than 2 ID payloads in Quick mode");
              return SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION;
            }
        }
      else
        {
          if (i == 0)
            {
              negotiation->qm_pm_info->local_r_id = id_copy;
              ssh_free(negotiation->qm_pm_info->local_r_id_txt);
              negotiation->qm_pm_info->local_r_id_txt = ssh_strdup(id_txt);
              if (negotiation->qm_pm_info->local_r_id_txt == NULL)
                return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }
          else if (i == 1)
            {
              negotiation->qm_pm_info->remote_r_id = id_copy;
              ssh_free(negotiation->qm_pm_info->remote_r_id_txt);
              negotiation->qm_pm_info->remote_r_id_txt = ssh_strdup(id_txt);
              if (negotiation->qm_pm_info->remote_r_id_txt == NULL)
                return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;
            }
          else
            {
              ssh_free(id_copy);
              SSH_IKE_DEBUG(3, negotiation, ("More than 2 ids in qm"));
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_ID,
                                  id->payload_start, id->payload_length, -1,
                                  "More than 2 ID payloads in Quick mode");
              return SSH_IKE_NOTIFY_MESSAGE_INVALID_ID_INFORMATION;
            }
        }
      i++;
      id = id->next_same_payload;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_qm_ke
 * Store ke data to exchange data.                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_ke(SshIkeContext isakmp_context,
                                       SshIkePacket isakmp_input_packet,
                                       SshIkeSA isakmp_sa,
                                       SshIkeNegotiation negotiation,
                                       SshIkeStateMachine state)
{
  SshIkePayload ke;

  ke = isakmp_input_packet->first_ke_payload;
  if (ke == NULL)
    return 0;
  if (isakmp_input_packet->first_ke_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple KE payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_KE,
                          isakmp_input_packet->first_ke_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_ke_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple KE payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  SSH_DEBUG(5, ("Ke[0..%zd] = %08lx %08lx ...",
                ke->pl.ke.key_exchange_data_len,
                (unsigned long)
                SSH_IKE_GET32(ke->pl.ke.key_exchange_data),
                (unsigned long)
                SSH_IKE_GET32(ke->pl.ke.key_exchange_data+4)));

  if (negotiation->qm_pm_info->this_end_is_initiator)
    negotiation->qm_ed->ke_r = ke;
  else
    negotiation->qm_ed->ke_i = ke;
  return 0;

}


/*                                                              shade{0.9}
 * ike_st_i_qm_nonce
 * Nonce payload handling.                                      shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_qm_nonce(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;

  if (!isakmp_input_packet->first_nonce_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No NONCE payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_nonce_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple NONCE payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_NONCE,
                          isakmp_input_packet->first_nonce_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_nonce_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple NONCE payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_nonce_payload;

  if (pl->payload_length < 8 ||
      pl->payload_length > 256)
    {
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_NONCE,
                          isakmp_input_packet->first_nonce_payload->
                          payload_start,
                          isakmp_input_packet->first_nonce_payload->
                          payload_length, -1,
                          "Nonce length not between 8 and 256 bytes");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }

  pl->pl.nonce.nonce_data = pl->pl.nonce.raw_nonce_packet;
  pl->pl.nonce.nonce_data_len = pl->payload_length;

  SSH_DEBUG(5, ("Nonce[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.nonce.nonce_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.nonce.nonce_data + 4)));

  if (negotiation->qm_pm_info->this_end_is_initiator)
    negotiation->qm_ed->nonce_r = pl;
  else
    negotiation->qm_ed->nonce_i = pl;
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_gen_hash_1
 * Calculate generic authentication hash, and check it.         shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_gen_hash(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;
  unsigned char hash[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t hash_len = SSH_MAX_HASH_DIGEST_LENGTH;
  unsigned char *p;

  if (!isakmp_input_packet->first_hash_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No HASH payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_hash_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple HASH payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_hash_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple HASH payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  pl = isakmp_input_packet->first_hash_payload;
  SSH_DEBUG(5, ("Start, hash[0..%zd] = %08lx %08lx ...",
                pl->payload_length,
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data),
                (unsigned long)
                SSH_IKE_GET32(pl->pl.hash.hash_data + 4)));

  /* Take a copy of the hash. */
  p = ike_register_copy(isakmp_input_packet, pl->pl.hash.hash_data,
                        pl->payload_length);
  if (p == NULL)
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  /* Clear the hash, so it can be used as a revised hash calculation */
  memset(pl->pl.hash.hash_data, 0, pl->payload_length);

  /* Move the hash_data to point to copy */
  pl->pl.hash.hash_data = p;

  ret = ike_calc_gen_hash(isakmp_context, isakmp_sa, negotiation,
                          isakmp_input_packet, hash, &hash_len);
  if (ret != 0)
    return ret;

  if (hash_len != pl->payload_length)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash length mismatch %d != %d",
                                     hash_len, pl->payload_length));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload length does not match the algorithm");
      return SSH_IKE_NOTIFY_MESSAGE_INVALID_HASH_INFORMATION;
    }
  if (memcmp(hash, pl->pl.hash.hash_data, hash_len) != 0)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Hash value mismatch"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_HASH,
                          pl->payload_start, pl->payload_length, -1,
                          "Hash payload data does not match");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_ngm_sa_proposal
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_ngm_sa_proposal(SshIkeContext isakmp_context,
                                                 SshIkePacket
                                                 isakmp_input_packet,
                                                 SshIkeSA isakmp_sa,
                                                 SshIkeNegotiation negotiation,
                                                 SshIkeStateMachine state)
{
  SshIkePayloadSA sa;

  SSH_DEBUG(5, ("Start"));

  /* Check that we have input packet */
  if (!isakmp_input_packet->first_sa_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No SA payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_sa_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple SA payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple SA payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  negotiation->ngm_ed->sa_i = isakmp_input_packet->first_sa_payload;
  sa = &(isakmp_input_packet->first_sa_payload->pl.sa);

  if (negotiation->ngm_ed->selected_proposal != -1)
    {
      /* Policy manager has responsed and answered to our query. */
      return 0;
    }

  /* Check situation is supported */
  if (sa->situation.situation_flags & SSH_IKE_SIT_SECRECY ||
      sa->situation.situation_flags & SSH_IKE_SIT_INTEGRITY)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Unsupported situation : %x",
                                     (int) sa->situation.situation_flags));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_SITUATION,
                    "Situation field in new group mode contains flags "
                    "that are not supported");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, 8,
                          "Invalid situation, secrecy or integrity bits set");
      return SSH_IKE_NOTIFY_MESSAGE_SITUATION_NOT_SUPPORTED;
    }

  /* Send query */
  negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;
  ssh_policy_ngm_select_sa(negotiation->ngm_pm_info,
                           negotiation,
                           isakmp_input_packet->first_sa_payload,
                           ike_ngm_sa_reply,
                           negotiation);

  if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
    {
      /* Policy manager could not reply to query immediately. Return
         RETRY_LATER to state machine so it will postpone processing of the
         packet until the policy manager answers and calls
         callback function. Clear PROCESSING_PM_QUERY flag before returning to
         the state machine. Note that state machine will set the
         WAITING_PM_REPLY flag. */
      negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
      return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
    }
  /* Policy manager replied immediately, check the reply */
  if (negotiation->ngm_ed->selected_proposal == -1)
    {
      /* No proposal selected, return error */
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                    "Policy manager could not find any acceptable "
                    "proposal for new group mode");
      SSH_IKE_NOTIFY_TEXT(negotiation, "Could not find acceptable proposal");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }
  /* Everything ok, return 0 */
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_ngm_sa_values
 * Check that the proposal returned by responder
 * mathces one of your proposals sent to other end.
 * If so, store information about private group
 * to isakmp_sa.                                                shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_ngm_sa_values(SshIkeContext isakmp_context,
                                               SshIkePacket
                                               isakmp_input_packet,
                                               SshIkeSA isakmp_sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkeStateMachine state)
{
  SshIkePayloadSA sa_i, sa_r;
  int proposal;
  struct SshIkeGrpAttributesRec attrs;

  SSH_DEBUG(5, ("Start"));
  if (!isakmp_input_packet->first_sa_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("No SA payload found!"));
      return SSH_IKE_NOTIFY_MESSAGE_EXCHANGE_DATA_MISSING;
    }
  if (isakmp_input_packet->first_sa_payload->next_same_payload)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Multiple SA payloads found!"));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          next_same_payload->payload_length, -1,
                          "Multiple SA payloads found");
      return SSH_IKE_NOTIFY_MESSAGE_PAYLOAD_MALFORMED;
    }
  negotiation->ngm_ed->sa_r = isakmp_input_packet->first_sa_payload;
  sa_r = &(isakmp_input_packet->first_sa_payload->pl.sa);
  sa_i = &(negotiation->ngm_ed->sa_i->pl.sa);

  /* Check that situation is supported */
  if (sa_r->situation.situation_flags & SSH_IKE_SIT_SECRECY ||
      sa_r->situation.situation_flags & SSH_IKE_SIT_INTEGRITY)
    {
      SSH_IKE_DEBUG(3, negotiation, ("Unsupported situation : %x",
                                     (int) sa_r->situation.situation_flags));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_SITUATION,
                    "Situation field in new group mode contains flags "
                    "that are not supported");
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, 8,
                          "Invalid situation, secrecy or integrity bits set");
      return SSH_IKE_NOTIFY_MESSAGE_SITUATION_NOT_SUPPORTED;
    }

  /* Check that there is only one proposal */
  if (sa_r->number_of_proposals != 1)
    {
      SSH_IKE_DEBUG(3, negotiation,
                    ("Multiple proposals (%d) in the response SA",
                     sa_r->number_of_proposals));
      SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_SA,
                          isakmp_input_packet->first_sa_payload->payload_start,
                          isakmp_input_packet->first_sa_payload->
                          payload_length, -1,
                          "Multiple proposal in the response SA, "
                          "must only contain 1");
      return SSH_IKE_NOTIFY_MESSAGE_BAD_PROPOSAL_SYNTAX;
    }

  /* Find that proposal from our initial sa list */
  for (proposal = 0; proposal < sa_i->number_of_proposals; proposal++)
    {
      if (sa_i->proposals[proposal].proposal_number ==
          sa_r->proposals[0].proposal_number)
        break;
    }
  /* If matching proposal id found, check that the proposals match */
  if (proposal == sa_i->number_of_proposals ||
      !ike_compare_proposals(negotiation, &sa_i->proposals[proposal],
                             &sa_r->proposals[0],
                             ike_compare_transforms_ngm))
    {
      /* Either no matching proposal id, or the real proposals didn't match */

      /* Loop through all proposals and try to find match */
      for (proposal = 0; proposal < sa_i->number_of_proposals; proposal++)
        {
          if (ike_compare_proposals(negotiation, &sa_i->proposals[proposal],
                                    &sa_r->proposals[0],
                                    ike_compare_transforms_ngm))
            break;
        }
      if (proposal == sa_i->number_of_proposals)
        {
          /* No proposal matched, return error */
          SSH_IKE_DEBUG(3, negotiation, ("No matching proposal found"));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                        "Other end modified our new group proposal, or it "
                        "returned completely different proposal");
          SSH_IKE_NOTIFY_TEXT(negotiation,
                              "Responder modified our proposal, or "
                              "returned proposal not offered by us");
          return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
        }
    }
  ssh_ike_clear_grp_attrs(&attrs);
  /* We know that we only have one protocol */
  /* Read the attributes from the only (first) proposal, and only (first)
     transform. */
  if (!ssh_ike_read_grp_attrs(negotiation, &(sa_r->proposals[0].protocols[0].
                                             transforms[0]), &attrs))
    {
      SSH_IKE_DEBUG(3, negotiation, ("Internal error, proposal match found, "
                                     "but there is unsupported values "
                                     "in proposal"));
      ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                    "Proposal matched, but our own new group mode proposal "
                    "contained unsupported values");
      return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
    }
  negotiation->ngm_ed->attributes = attrs;
  negotiation->ngm_ed->selected_proposal = proposal;
  negotiation->ngm_ed->selected_transform = -1; /* Not intresting */
  return 0;
}


#ifdef SSHDIST_ISAKMP_CFG_MODE
/*                                                              shade{0.9}
 * ike_st_i_cfg_restart
 *                                                              shade{1.0}
 */
SshIkeNotifyMessageType ike_st_i_cfg_restart(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Start"));

  negotiation->lock_flags &= ~(SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE);
  negotiation->notification_state = SSH_IKE_NOTIFICATION_STATE_NOT_SENT;

  if (!ike_restart_cfg_negotiation(negotiation))
    return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_cfg_attr
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_cfg_attr(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayloadAttr *attrs = NULL;
  int number_of_attrs = 0, i;
  SshIkePayload pl;
  Boolean received_new = FALSE;

  SSH_DEBUG(5, ("Start"));

  if (negotiation->cfg_ed->number_of_remote_attr_payloads == -1)
    {
      pl = isakmp_input_packet->first_attr_payload;
      number_of_attrs = 0;

      while (pl != NULL)
        {
          number_of_attrs++;
          pl = pl->next_same_payload;
        }

      attrs = ssh_calloc(number_of_attrs, sizeof(SshIkePayloadAttr));
      if (attrs == NULL)
        return SSH_IKE_NOTIFY_MESSAGE_OUT_OF_MEMORY;

      pl = isakmp_input_packet->first_attr_payload;
      for (i = 0; i < number_of_attrs; i++, pl = pl->next_same_payload)
        {
          attrs[i] = &(pl->pl.attr);
        }
      negotiation->cfg_ed->remote_attrs = attrs;
      negotiation->cfg_ed->number_of_remote_attr_payloads = number_of_attrs;
      received_new = TRUE;
    }

  if (negotiation->cfg_ed->number_of_local_attr_payloads == -1)
    {
      /* Send query */
      negotiation->lock_flags |= SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY;

      ssh_policy_cfg_fill_attrs(negotiation->cfg_pm_info,
                                number_of_attrs,
                                attrs,
                                ike_cfg_attrs_reply,
                                negotiation);

      if (negotiation->lock_flags & SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY)
        {
          /* Policy manager could not reply to query immediately. Return
             RETRY_LATER to state machine so it will postpone processing of the
             packet until the policy manager answers and calls callback
             function. Clear PROCESSING_PM_QUERY flag before returning to the
             state machine. Note that state machine will set the
             WAITING_PM_REPLY flag. */
          negotiation->lock_flags &=
            ~(SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY);
          return SSH_IKE_NOTIFY_MESSAGE_RETRY_LATER;
        }
      /* Policy manager replied immediately, check the reply */
      if (negotiation->cfg_ed->number_of_local_attr_payloads == -1)
        {
          /* No proposal selected, return error */
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROPOSAL,
                        "Policy manager could not fill attributes "
                        "for configuration mode");
          SSH_IKE_NOTIFY_TEXT(negotiation, "Could not fill in attributes "
                              "requested for the configuration mode");
          return SSH_IKE_NOTIFY_MESSAGE_NO_PROPOSAL_CHOSEN;
        }
    }
  else if (received_new)
    {
      /* Tell policy manager about the received attributes */
      ssh_policy_cfg_notify_attrs(negotiation->cfg_pm_info,
                                  number_of_attrs,
                                  attrs);
    }

  /* Everything ok, return 0 */
  return 0;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */


/*                                                              shade{0.9}
 * ike_st_i_status_n
 * Process status notify payload.                               shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_status_n(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_input_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;

  pl = isakmp_input_packet->first_n_payload;
  while (pl != NULL)
    {
      SSH_DEBUG(5, ("Start, doi = %d, protocol = %d, code = %s (%d), "
                    "spi[0..%zd] = %08lx %08lx ..., "
                    "data[0..%zd] = %08lx %08lx ...",
                    pl->pl.n.doi, pl->pl.n.protocol_id,
                    ssh_ike_error_code_to_string(pl->pl.n.notify_message_type),
                    pl->pl.n.notify_message_type,
                    pl->pl.n.spi_size,
                    (unsigned long)
                    (pl->pl.n.spi_size >= 4 ? SSH_IKE_GET32(pl->pl.n.spi) : 0),
                    (unsigned long)
                    (pl->pl.n.spi_size >= 8 ? SSH_IKE_GET32(pl->pl.n.spi + 4) :
                     0),
                    pl->pl.n.notification_data_size,
                    (unsigned long)
                    (pl->pl.n.notification_data_size >= 4 ?
                     SSH_IKE_GET32(pl->pl.n.notification_data) : 0),
                    (unsigned long)
                    (pl->pl.n.notification_data_size >= 8 ?
                     SSH_IKE_GET32(pl->pl.n.notification_data + 4) : 0)));
      if (pl->pl.n.doi != SSH_IKE_DOI_IPSEC &&
          pl->pl.n.doi != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Unsupported doi = %d in notification payload",
                         pl->pl.n.doi));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                        "Notify payload contains invalid DOI number");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                              pl->payload_start, pl->payload_length, 4,
                              "Invalid DOI value, should be 0 or 1");
          return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
        }

      if (pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_ISAKMP)
        {
          if (pl->pl.n.spi_size != 0 &&
              pl->pl.n.spi_size != SSH_IKE_COOKIE_LENGTH * 2)
            {
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                                  pl->payload_start, pl->payload_length, 12,
                                  "Invalid SPI size, must be 0 or 16.");
              return SSH_IKE_NOTIFY_MESSAGE_INVALID_SPI;
            }





          /* SshIke protocol, check spi */
          ret = ssh_ike_check_isakmp_spi(pl->pl.n.spi_size / 2,
                                         pl->pl.n.spi,
                                         isakmp_sa->cookies.initiator_cookie);
          if (ret != 0)
            {
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                                  pl->payload_start, pl->payload_length, 12,
                                  "Invalid SPI size, must be 0 or 16.");
              return ret;
            }

          ret = ssh_ike_check_isakmp_spi(pl->pl.n.spi_size / 2,
                                         pl->pl.n.spi + SSH_IKE_COOKIE_LENGTH,
                                         isakmp_sa->cookies.responder_cookie);
          if (ret != 0)
            {
              SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                                  pl->payload_start, pl->payload_length, 12,
                                  "Invalid SPI size, must be 0 or 16.");
              return ret;
            }

          switch (pl->pl.n.notify_message_type)
            {
            case SSH_IKE_NOTIFY_MESSAGE_RESPONDER_LIFETIME:
              SSH_DEBUG(7, ("Responder lifetime notification"));
              break;
            case SSH_IKE_NOTIFY_MESSAGE_REPLAY_STATUS:
              if (pl->pl.n.notification_data_size > 4)
                SSH_DEBUG(7, ("Replay status = %d",
                              (int)
                              SSH_IKE_GET32(pl->pl.n.notification_data)));
              else
                SSH_DEBUG(7, ("Replay status, but value missing"));
              break;
            case SSH_IKE_NOTIFY_MESSAGE_INITIAL_CONTACT:
              SSH_DEBUG(7, ("Initial contact"));
              break;
#ifdef SSHDIST_IKE_XAUTH
            case SSH_IKE_NOTIFY_MESSAGE_CISCO_PSK_HASH:
              if (negotiation->ike_pm_info->hybrid_edge)
                SSH_DEBUG(7, ("PSK hash"));
              else
                SSH_DEBUG(7, ("Invalid PSK hash"));
              break;
#endif /* SSHDIST_IKE_XAUTH */
            default:
              SSH_DEBUG(7, ("Invalid status message"));
              break;
            }
        }
      else if (pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH ||
               pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP ||
               pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
        {
          /* ipsec_ah, or ipsec_esp protocol */




        }
      else
        {
          SSH_IKE_DEBUG(3, negotiation, ("Invalid protocol_id = %d",
                                         pl->pl.n.protocol_id));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROTOCOL_ID,
                        "Notification payload contains invalid protocol id");
        }
      if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_AGGR ||
          negotiation->exchange_type == SSH_IKE_XCHG_TYPE_IP)
        {
          ssh_policy_phase_i_notification(negotiation->ike_pm_info,
                                          (isakmp_input_packet->flags &
                                           SSH_IKE_FLAGS_ENCRYPTION) ==
                                          SSH_IKE_FLAGS_ENCRYPTION,
                                          pl->pl.n.protocol_id,
                                          pl->pl.n.spi,
                                          pl->pl.n.spi_size,
                                          pl->pl.n.notify_message_type,
                                          pl->pl.n.notification_data,
                                          pl->pl.n.notification_data_size);
        }
      else if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_NGM)
        {
          ssh_policy_notification(negotiation->ngm_pm_info,
                                  (state->mandatory_input_fields &
                                   SSH_IKE_FIELDS_HASH),
                                  pl->pl.n.protocol_id,
                                  pl->pl.n.spi,
                                  pl->pl.n.spi_size,
                                  pl->pl.n.notify_message_type,
                                  pl->pl.n.notification_data,
                                  pl->pl.n.notification_data_size);
        }
#ifdef SSHDIST_ISAKMP_CFG_MODE
      else if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_CFG)
        {
          ssh_policy_notification(negotiation->cfg_pm_info,
                                  (state->mandatory_input_fields &
                                   SSH_IKE_FIELDS_HASH),
                                  pl->pl.n.protocol_id,
                                  pl->pl.n.spi,
                                  pl->pl.n.spi_size,
                                  pl->pl.n.notify_message_type,
                                  pl->pl.n.notification_data,
                                  pl->pl.n.notification_data_size);
        }
#endif /* SSHDIST_ISAKMP_CFG_MODE */
      else if (negotiation->exchange_type == SSH_IKE_XCHG_TYPE_QM)
        {
          ssh_policy_phase_qm_notification(negotiation->qm_pm_info,
                                           pl->pl.n.protocol_id,
                                           pl->pl.n.spi,
                                           pl->pl.n.spi_size,
                                           pl->pl.n.notify_message_type,
                                           pl->pl.n.notification_data,
                                           pl->pl.n.
                                           notification_data_size);
        }
      else
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Invalid exchange type %d for unknown protocol in "
                         "the status notification",
                         negotiation->exchange_type));
        }
      pl = pl->next_same_payload;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_n
 * Process notify payload.                                      shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_n(SshIkeContext isakmp_context,
                                   SshIkePacket isakmp_input_packet,
                                   SshIkeSA isakmp_sa,
                                   SshIkeNegotiation negotiation,
                                   SshIkeStateMachine state)
{
  SshIkePayload pl;
  SshIkeNotifyMessageType ret;

  pl = isakmp_input_packet->first_n_payload;
  while (pl != NULL)
    {
      SSH_DEBUG(4, ("Start, doi = %d, protocol = %d, code = %s (%d), "
                    "spi[0..%zd] = %08lx %08lx ..., "
                    "data[0..%zd] = %08lx %08lx ...",
                    pl->pl.n.doi, pl->pl.n.protocol_id,
                    ssh_ike_error_code_to_string(pl->pl.n.notify_message_type),
                    pl->pl.n.notify_message_type,
                    pl->pl.n.spi_size,
                    (unsigned long)
                    (pl->pl.n.spi_size >= 4 ? SSH_IKE_GET32(pl->pl.n.spi) : 0),
                    (unsigned long)
                    (pl->pl.n.spi_size >= 8 ? SSH_IKE_GET32(pl->pl.n.spi + 4) :
                     0),
                    pl->pl.n.notification_data_size,
                    (unsigned long)
                    (pl->pl.n.notification_data_size >= 4 ?
                     SSH_IKE_GET32(pl->pl.n.notification_data) : 0),
                    (unsigned long)
                    (pl->pl.n.notification_data_size >= 8 ?
                    SSH_IKE_GET32(pl->pl.n.notification_data + 4) : 0)));

      if (pl->pl.n.notification_data_size > 4)
        {
          if (SSH_IKE_GET32(pl->pl.n.notification_data) ==
              0x800c0001)
            {
              SshIkeDataAttributeStruct attribute;
              unsigned char *ptr;
              size_t i, attr_len;
              SshUInt32 value;

              SSH_IKE_DEBUG(4, negotiation,
                            ("Notification data has attribute list"));
              i = 0;
              while (i + 4 <= pl->pl.n.notification_data_size)
                {
                  if (!ssh_ike_decode_data_attribute(pl->pl.n.
                                                     notification_data + i,
                                                     pl->pl.n.
                                                     notification_data_size -
                                                     i,
                                                     &attr_len,
                                                     &attribute, 0))
                    {
                      SSH_DEBUG(3, ("Data attribute too long"));
                      break;
                    }
                  switch (attribute.attribute_type)
                    {
                    case SSH_IKE_NOTIFY_CLASSES_TYPE_OF_OFFENDING_PAYLOAD:
                      if (!ssh_ike_get_data_attribute_int(&attribute,
                                                          &value, 0))
                        break;
                      SSH_IKE_DEBUG(4, negotiation,
                                    ("Offending payload type = %d",
                                     (int) value));
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_OFFENDING_PAYLOAD_DATA:
                      SSH_IKE_DEBUG_PRINTF_BUFFER(5, negotiation,
                                                  ("Offending payload[%d] = ",
                                                   attribute.attribute_length),
                                                  attribute.attribute_length,
                                                  attribute.attribute);
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_SUGGESTED_PROPOSAL:
                      SSH_IKE_DEBUG_PRINTF_BUFFER(5, negotiation,
                                                  ("Suggested proposal[%d] = ",
                                                   attribute.attribute_length),
                                                  attribute.attribute_length,
                                                  attribute.attribute);
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_ERROR_POSITION_OFFSET:
                      if (!ssh_ike_get_data_attribute_int(&attribute,
                                                          &value, 0))
                        break;
                      SSH_IKE_DEBUG(4, negotiation,
                                    ("Offending payload data offset = %d",
                                     (int) value));
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_ERROR_TEXT:
                      ptr = ssh_memdup(attribute.attribute,
                                       attribute.attribute_length);
                      if (ptr)
                        {
                          SSH_IKE_DEBUG(4, negotiation,
                                        ("Error text = %s", ptr));
                        }
                      ssh_free(ptr);
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_ERROR_TEXT_LANGUAGE:
                      ptr = ssh_memdup(attribute.attribute,
                                        attribute.attribute_length);
                      if (ptr)
                        {
                          SSH_IKE_DEBUG(4, negotiation,
                                        ("Error language = %s", ptr));
                        }
                      ssh_free(ptr);
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_MESSAGE_ID:
                      if (!ssh_ike_get_data_attribute_int(&attribute,
                                                          &value, 0))
                        break;
                      SSH_IKE_DEBUG(4, negotiation,
                                    ("Offending message id = 0x%08x",
                                     (int) value));
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_EXCHANGE_TYPE:
                      if (!ssh_ike_get_data_attribute_int(&attribute,
                                                          &value, 0))
                        break;
                      SSH_IKE_DEBUG(4, negotiation,
                                    ("Offending exchange type = %d",
                                     (int) value));
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_INVALID_FLAG_BITS:
                      if (!ssh_ike_get_data_attribute_int(&attribute,
                                                          &value, 0))
                        break;
                      SSH_IKE_DEBUG(4, negotiation,
                                    ("Invalid flags = 0x%x",
                                     (int) value));
                      break;
                    case SSH_IKE_NOTIFY_CLASSES_VERSION:
                      if (!ssh_ike_get_data_attribute_int(&attribute,
                                                          &value, 0))
                        break;
                      SSH_IKE_DEBUG(4, negotiation,
                                    ("Notify message version = %d",
                                     (int) value));
                      break;
                    }
                  i += attr_len;
                }
            }
        }

      if (pl->pl.n.doi != SSH_IKE_DOI_IPSEC &&
          pl->pl.n.doi != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Unsupported doi = %d in notification payload",
                         pl->pl.n.doi));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                        "Notify payload contains invalid DOI number");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                              pl->payload_start, pl->payload_length, 4,
                              "Invalid DOI value, should be 0 or 1");
          return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
        }

      if (pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_ISAKMP)
        {
          if (pl->pl.n.notify_message_type == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Connected"));
              if (isakmp_sa->isakmp_negotiation->lock_flags &
                  SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE)
                {
                  SSH_DEBUG(7, ("Waited for done, advance state machine"));

                  /* Advance state machine. */
                  ret = ike_state_step(isakmp_context, NULL,
                                       NULL, isakmp_sa,
                                       isakmp_sa->isakmp_negotiation);

                  if (ret == SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
                    {
                      SSH_DEBUG(7, ("Connected, sending notify"));
                      ike_send_notify(isakmp_sa->server_context,
                                      isakmp_sa->isakmp_negotiation, ret);
                    }
                  else if (ret != 0)
                    {
                      SSH_DEBUG(7, ("Error, send notify"));
                      ike_send_notify(isakmp_sa->server_context,
                                      isakmp_sa->isakmp_negotiation, ret);
                    }

                  return 0;
                }
            }
          else if (pl->pl.n.notify_message_type < 8192)
            {
              SSH_IKE_DEBUG(3, negotiation,
                            ("Received notify err = %s (%d) to isakmp sa, "
                             "delete it",
                             ssh_ike_error_code_to_string(pl->pl.n.
                                                          notify_message_type),
                             pl->pl.n.notify_message_type));

              if (isakmp_sa->phase_1_done &&
                  !(state->mandatory_input_fields & SSH_IKE_FIELDS_HASH))
                {
                  SSH_IKE_DEBUG(3, negotiation,
                                ("Ignored unauthenticated notify"));
                }
              else
                {
                  /* Canceling timers */
                  ssh_cancel_timeouts(SSH_ALL_CALLBACKS,
                                      isakmp_sa->isakmp_negotiation);

                  if (isakmp_sa->isakmp_negotiation->notification_state !=
                      SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
                    {
                      isakmp_sa->isakmp_negotiation->notification_state =
                        SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
                      isakmp_sa->isakmp_negotiation->ed->code =
                        pl->pl.n.notify_message_type;
                    }
                  isakmp_sa->isakmp_negotiation->lock_flags |=
                    SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE;

                  ike_debug_exchange_fail_remote(isakmp_sa->isakmp_negotiation,
                                                 pl->pl.n.notify_message_type);

                  /* Add expire timer to be called immediately */
                  ssh_xregister_timeout(0, 0, ike_remove_callback,
                                        isakmp_sa->isakmp_negotiation);
                }
            }
          else
            {
              ssh_policy_notification(negotiation->info_pm_info,
                                      (state->mandatory_input_fields &
                                       SSH_IKE_FIELDS_HASH),
                                      pl->pl.n.protocol_id,
                                      pl->pl.n.spi,
                                      pl->pl.n.spi_size,
                                      pl->pl.n.notify_message_type,
                                      pl->pl.n.notification_data,
                                      pl->pl.n.notification_data_size);
            }
        }
      else if (pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH ||
               pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP ||
               pl->pl.n.protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
        {
          /* ipsec_ah, or ipsec_esp protocol */
          /* Just call to ipsec code and tell the notification. */
          ssh_policy_notification(negotiation->info_pm_info,
                                  (state->mandatory_input_fields &
                                   SSH_IKE_FIELDS_HASH),
                                  pl->pl.n.protocol_id,
                                  pl->pl.n.spi,
                                  pl->pl.n.spi_size,
                                  pl->pl.n.notify_message_type,
                                  pl->pl.n.notification_data,
                                  pl->pl.n.notification_data_size);

          if (pl->pl.n.notify_message_type != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)
            {
              int i, j, k, l;
              SshIkePayload *sa_payloads;

              /* Try to find associated quick mode negotiation and abort
                 that */
              for (i = 0; i < isakmp_sa->number_of_negotiations; i++)
                {
                  if (isakmp_sa->negotiations[i] == NULL ||
                      isakmp_sa->negotiations[i]->exchange_type !=
                      SSH_IKE_XCHG_TYPE_QM ||
                      isakmp_sa->negotiations[i]->ed == NULL ||
                      isakmp_sa->negotiations[i]->qm_ed == NULL ||
                      isakmp_sa->negotiations[i]->qm_pm_info == NULL)
                    continue;

                  if (isakmp_sa->negotiations[i]->qm_pm_info->
                      this_end_is_initiator)
                    sa_payloads = isakmp_sa->negotiations[i]->qm_ed->sas_i;
                  else
                    sa_payloads = isakmp_sa->negotiations[i]->qm_ed->sas_r;
                  if (!sa_payloads)
                    continue;
                  for (j = 0;
                       j < isakmp_sa->negotiations[i]->qm_ed->number_of_sas;
                       j++)
                    {
                      if (!sa_payloads[j])
                        continue;
                      for (k = 0;
                           k < sa_payloads[j]->pl.sa.number_of_proposals;
                           k++)
                        {
                          if (!sa_payloads[j]->pl.sa.proposals)
                            continue;
                          for (l = 0;
                               l < sa_payloads[j]->pl.sa.proposals[k].
                                 number_of_protocols;
                               l++)
                            {
                              if (!sa_payloads[j]->pl.sa.proposals[k].
                                  protocols)
                                continue;
                              if (pl->pl.n.protocol_id ==
                                  sa_payloads[j]->pl.sa.proposals[k].
                                  protocols[l].protocol_id &&
                                  pl->pl.n.spi_size ==
                                  sa_payloads[j]->pl.sa.proposals[k].
                                  protocols[l].spi_size)
                                {
                                  if (pl->pl.n.spi_size == 0 ||
                                      (sa_payloads[j]->pl.sa.proposals[k].
                                       protocols[l].spi != NULL &&
                                       pl->pl.n.spi != NULL &&
                                       memcmp(sa_payloads[j]->pl.sa.
                                              proposals[k].
                                              protocols[l].spi,
                                              pl->pl.n.spi,
                                              pl->pl.n.spi_size) == 0))
                                    {
                                      isakmp_sa->negotiations[i]->ed->code =
                                        pl->pl.n.notify_message_type;
                                      if (isakmp_sa->negotiations[i]->
                                          notification_state
                          != SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
                                        isakmp_sa->negotiations[i]->
                                          notification_state =
                                          SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
                                      ike_remove_callback(isakmp_sa->
                                                          negotiations[i]);
                                      goto out;
                                    }
                                }
                            }
                        }
                    }
                }
            out:
              ;
            }
        }
      else
        {
          SSH_IKE_DEBUG(3, negotiation, ("Invalid protocol_id = %d",
                                         pl->pl.n.protocol_id));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROTOCOL_ID,
                        "Notification payload contains invalid protocol id");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_N,
                              pl->payload_start, pl->payload_length, 8,
                      "Invalid protocol value in notification payload");
          return SSH_IKE_NOTIFY_MESSAGE_INVALID_PROTOCOL_ID;
        }
      pl = pl->next_same_payload;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_d
 *                                                              shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_d(SshIkeContext isakmp_context,
                                   SshIkePacket isakmp_input_packet,
                                   SshIkeSA isakmp_sa,
                                   SshIkeNegotiation negotiation,
                                   SshIkeStateMachine state)
{
  SshIkePayload pl;
  int i;

  for (pl = isakmp_input_packet->first_d_payload;
       pl != NULL;
       pl = pl->next_same_payload)
    {
      SSH_DEBUG(5, ("Start, doi = %d, protocol = %d, "
                    "spis[0..%d][0..%zd] = [%08lx %08lx ...]",
                    pl->pl.d.doi, pl->pl.d.protocol_id,
                    pl->pl.d.number_of_spis,
                    pl->pl.d.spi_size,
                    (unsigned long)
                    (pl->pl.d.number_of_spis * pl->pl.d.spi_size >= 4 ?
                     SSH_IKE_GET32(pl->pl.d.spis[0]) : 0),
                    (unsigned long)
                    (pl->pl.d.number_of_spis * pl->pl.d.spi_size >= 8 ?
                     SSH_IKE_GET32(pl->pl.d.spis[0] + 4) : 0)));
      if (pl->pl.d.doi != SSH_IKE_DOI_IPSEC &&
          pl->pl.d.doi != 0)
        {
          SSH_IKE_DEBUG(3, negotiation,
                        ("Unsupported doi = %d in notification payload",
                         pl->pl.d.doi));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_DOI,
                        "Delete payload contains invalid DOI number");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_D,
                              pl->payload_start, pl->payload_length, 4,
                              "Invalid DOI value, should be 0 or 1");
          return SSH_IKE_NOTIFY_MESSAGE_DOI_NOT_SUPPORTED;
        }
      if (pl->pl.d.protocol_id == SSH_IKE_PROTOCOL_ISAKMP)
        {
          if (pl->pl.d.spi_size != SSH_IKE_COOKIE_LENGTH * 2)
            {
              SSH_IKE_DEBUG(3, negotiation, ("Invalid spi_size = %d",
                                             pl->pl.d.spi_size));
              ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_SPI,
                            "Delete payload contains invalid spi size");
              continue;
            }
          if (!(state->mandatory_input_fields & SSH_IKE_FIELDS_HASH))
            {
              SSH_IKE_DEBUG_BUFFER(3, negotiation,
                                   "Ignored unauthenticated delete "
                                   "notification spi",
                                   pl->pl.d.spi_size, pl->pl.d.spis[0]);
              continue;
            }
          /* SshIke protocol, find sa */
          for (i = 0; i < pl->pl.d.number_of_spis; i++)
            {
              SshIkeSA sa;

              /* Find sa */
              sa = ike_sa_find(isakmp_context, pl->pl.d.spis[i],
                               pl->pl.d.spis[i] +
                               SSH_IKE_COOKIE_LENGTH);
              if (sa == NULL)
                {
                  SSH_IKE_DEBUG_BUFFER(3, negotiation, "invalid spi",
                                       pl->pl.d.spi_size, pl->pl.d.spis[i]);
                  ssh_ike_audit_event(isakmp_context,
                                      SSH_AUDIT_IKE_INVALID_SPI,
                                      SSH_AUDIT_SOURCE_ADDRESS_STR,
                                      isakmp_sa->isakmp_negotiation->
                                      ike_pm_info->local_ip,
                                      SSH_AUDIT_DESTINATION_ADDRESS_STR,
                                      isakmp_sa->isakmp_negotiation->
                                      ike_pm_info->remote_ip,
                                      SSH_AUDIT_SPI, pl->pl.d.spis[i],
                                      2 * SSH_IKE_COOKIE_LENGTH,
                                      SSH_AUDIT_TXT,
                                    "Invalid spi value inside delete payload",
                                      SSH_AUDIT_ARGUMENT_END);
                  continue;
                }
              SSH_IKE_DEBUG_BUFFER(3, negotiation, "delete spi",
                                   pl->pl.d.spi_size, pl->pl.d.spis[i]);

              ssh_ike_audit_event(isakmp_context,
                                  SSH_AUDIT_IKE_DELETE_PAYLOAD_RECEIVED,
                                  SSH_AUDIT_SOURCE_ADDRESS_STR,
                                  isakmp_sa->isakmp_negotiation->
                                  ike_pm_info->local_ip,
                                  SSH_AUDIT_DESTINATION_ADDRESS_STR,
                                  isakmp_sa->isakmp_negotiation->
                                  ike_pm_info->remote_ip,
                                  SSH_AUDIT_SPI, pl->pl.d.spis[i],
                                  2 * SSH_IKE_COOKIE_LENGTH,
                                  SSH_AUDIT_TXT,
                                  "Received delete notification",
                                  SSH_AUDIT_ARGUMENT_END);
              /* Canceling timers */
              ssh_cancel_timeouts(SSH_ALL_CALLBACKS, sa->isakmp_negotiation);

              if (isakmp_sa->isakmp_negotiation->notification_state !=
                  SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT)
                {
                  isakmp_sa->isakmp_negotiation->notification_state =
                    SSH_IKE_NOTIFICATION_STATE_SEND_NOW;
                  isakmp_sa->isakmp_negotiation->ed->code =
                    SSH_IKE_NOTIFY_MESSAGE_DELETED;
                }
              sa->isakmp_negotiation->lock_flags |=
                SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE;

              /* Add expire timer to be called immediately */
              ssh_xregister_timeout(0, 0, ike_remove_callback,
                                   sa->isakmp_negotiation);
            }
        }
      else if (pl->pl.d.protocol_id == SSH_IKE_PROTOCOL_IPSEC_AH ||
               pl->pl.d.protocol_id == SSH_IKE_PROTOCOL_IPSEC_ESP ||
               pl->pl.d.protocol_id == SSH_IKE_PROTOCOL_IPCOMP)
        {
          /* ipsec_ah, or ipsec_esp protocol */
          /* Just call to ipsec code and tell these spis are deleted. */
          ssh_policy_delete(negotiation->info_pm_info,
                            (state->mandatory_input_fields &
                             SSH_IKE_FIELDS_HASH),
                            pl->pl.d.protocol_id,
                            pl->pl.d.number_of_spis,
                            pl->pl.d.spis,
                            pl->pl.d.spi_size);
          /* Just assume the policy manager deleted the SA */
          isakmp_sa->statistics.deleted_suites++;
        }
      else
        {
          SSH_IKE_DEBUG(3, negotiation, ("Invalid protocol_id = %d",
                                         pl->pl.d.protocol_id));
          ssh_ike_audit(negotiation, SSH_AUDIT_IKE_INVALID_PROTOCOL_ID,
                        "Delete payload contains invalid protocol id");
          SSH_IKE_NOTIFY_DATA(negotiation, SSH_IKE_PAYLOAD_TYPE_D,
                              pl->payload_start, pl->payload_length, 8,
                              "Invalid protocol value in delete payload");
          return SSH_IKE_NOTIFY_MESSAGE_INVALID_PROTOCOL_ID;
        }
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_vid
 * Store pointer to the vendor id packet.                       shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_vid(SshIkeContext isakmp_context,
                                     SshIkePacket isakmp_input_packet,
                                     SshIkeSA isakmp_sa,
                                     SshIkeNegotiation negotiation,
                                     SshIkeStateMachine state)
{
  SshIkePayload vid;

  vid = isakmp_input_packet->first_vid_payload;

  while (vid != NULL)
    {
      SSH_DEBUG(5, ("VID[0..%zd] = %08lx %08lx ...",
                    vid->payload_length,
                    (unsigned long)
                    SSH_IKE_GET32(vid->pl.vid.vid_data),
                    (unsigned long)
                    SSH_IKE_GET32(vid->pl.vid.vid_data + 4)));

      ssh_policy_isakmp_vendor_id(negotiation->ike_pm_info,
                                  vid->pl.vid.vid_data,
                                  vid->payload_length);
      vid = vid->next_same_payload;
    }
  return 0;
}


/*                                                              shade{0.9}
 * ike_st_i_encrypt
 * Check that the packet was encrypted.                         shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_encrypt(SshIkeContext isakmp_context,
                                         SshIkePacket isakmp_input_packet,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkeStateMachine state)
{

  if (isakmp_input_packet->flags & SSH_IKE_FLAGS_ENCRYPTION)
    {
      SSH_DEBUG(5, ("Check that packet was encrypted succeeded"));
      return 0;
    }
  else
    {
      SSH_DEBUG(5, ("Check that packet was encrypted failed"));
      SSH_IKE_DEBUG(3, negotiation, ("Packet was sent unencrypted"));
      SSH_IKE_NOTIFY_TEXT(negotiation, "Packet was sent in clear");
      return SSH_IKE_NOTIFY_MESSAGE_AUTHENTICATION_FAILED;
    }
}


/*                                                              shade{0.9}
 * ike_st_i_retry_now
 * Rerun the state machine immediately.                         shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_retry_now(SshIkeContext isakmp_context,
                                           SshIkePacket isakmp_input_packet,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkeStateMachine state)
{
  SSH_DEBUG(5, ("Starting state machine from the beginning"));
  return SSH_IKE_NOTIFY_MESSAGE_RETRY_NOW;
}


/*                                                              shade{0.9}
 * ike_st_i_private
 * Process private payloads.                                    shade{1.0}
 */

SshIkeNotifyMessageType ike_st_i_private(SshIkeContext isakmp_context,
                                         SshIkePacket isakmp_input_packet,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkeStateMachine state)
{
  SshIkePayload prv;
  int packet_number;

  SSH_DEBUG(5, ("Start"));

  if (isakmp_input_packet == NULL)
    return 0;

  prv = isakmp_input_packet->first_private_payload;
  packet_number = negotiation->ed->number_of_packets_in +
    negotiation->ed->number_of_packets_out;

  while (prv != NULL)
    {
      switch (negotiation->exchange_type)
        {
        case SSH_IKE_XCHG_TYPE_IP:
        case SSH_IKE_XCHG_TYPE_AGGR:
          if (negotiation->ed->private_payload_phase_1_input)
            (*negotiation->ed->
             private_payload_phase_1_input)(negotiation->ike_pm_info,
                                            packet_number,
                                            prv->pl.prv.
                                            prv_payload_id,
                                            prv->pl.prv.data,
                                            prv->payload_length,
                                            negotiation->ed->
                                            private_payload_context);
          break;
        case SSH_IKE_XCHG_TYPE_QM:
          if (negotiation->ed->private_payload_phase_qm_input)
            (*negotiation->ed->
             private_payload_phase_qm_input)(negotiation->qm_pm_info,
                                             packet_number,
                                             prv->pl.prv.
                                             prv_payload_id,
                                             prv->pl.prv.data,
                                             prv->payload_length,
                                             negotiation->ed->
                                             private_payload_context);
          break;
        case SSH_IKE_XCHG_TYPE_NGM:
          if (negotiation->ed->private_payload_phase_2_input)
            (*negotiation->ed->
             private_payload_phase_2_input)(negotiation->ngm_pm_info,
                                            packet_number,
                                            prv->pl.prv.
                                            prv_payload_id,
                                            prv->pl.prv.data,
                                            prv->payload_length,
                                            negotiation->ed->
                                            private_payload_context);
          break;
#ifdef SSHDIST_ISAKMP_CFG_MODE
        case SSH_IKE_XCHG_TYPE_CFG:
          if (negotiation->ed->private_payload_phase_2_input)
            (*negotiation->ed->
             private_payload_phase_2_input)(negotiation->cfg_pm_info,
                                            packet_number,
                                            prv->pl.prv.
                                            prv_payload_id,
                                            prv->pl.prv.data,
                                            prv->payload_length,
                                            negotiation->ed->
                                            private_payload_context);
          break;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
        case SSH_IKE_XCHG_TYPE_INFO:
          if (negotiation->ed->private_payload_phase_2_input)
            (*negotiation->ed->
             private_payload_phase_2_input)(negotiation->info_pm_info,
                                            packet_number,
                                            prv->pl.prv.
                                            prv_payload_id,
                                            prv->pl.prv.data,
                                            prv->payload_length,
                                            negotiation->ed->
                                            private_payload_context);
          break;
        default:
          break;
        }
      /* Process next private payload */
      prv = prv->next_same_payload;
    }
  return 0;
}
