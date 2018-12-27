/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE AUTH responder out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateAuthRespOut"

/* Start IKE AUTH state. */
SSH_FSM_STEP(ikev2_state_auth_responder_out)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_EAP_AUTH
  if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
    {
      if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_STARTED)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("1st EAP packet"));
          /** EAP enabled, but this is 1st packet. */
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_idr);
          /* Mark that 1st packet is done. */
          packet->ed->ike_ed->eap_state = SSH_IKEV2_EAP_1ST_DONE;
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Using EAP"));
          /** EAP enabled, and 1st packet done. */
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_done);
        }
    }
  else
#endif /* SSHDIST_IKE_EAP_AUTH */
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("No EAP"));
      /** No EAP. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_idr);
    }

  packet->ed->next_payload_offset = -1;
  packet->ed->buffer = ssh_buffer_allocate();
  if (packet->ed->buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  return SSH_FSM_CONTINUE;
}

/* Add IDr payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_idr)
{
  SshIkev2Packet packet = thread_context;
#ifdef SSHDIST_IKE_CERT_AUTH
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_cert);
#else /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_check);
#endif /* SSHDIST_IKE_CERT_AUTH */
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, id) */
  SSH_FSM_ASYNC_CALL(ikev2_add_id(packet, TRUE));
}

#ifdef SSHDIST_IKE_CERT_AUTH
/* Add optional CERT payloads. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_cert)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_check);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_certificates) */
  SSH_FSM_ASYNC_CALL(ikev2_add_certs(packet));
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Check auth type. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_check)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

#ifdef SSHDIST_IKE_EAP_AUTH
  if (ed->eap_state == SSH_IKEV2_EAP_1ST_DONE
#ifdef SSHDIST_IKE_CERT_AUTH
      && ed->private_key == NULL
#endif /* SSHDIST_IKE_CERT_AUTH */
      )
    {
      /** EAP has been started but private key is missing.
          Attemp EAP only auth. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_eap);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IKE_EAP_AUTH */

  ed->data_to_signed =
    ikev2_auth_data(packet, TRUE, TRUE, FALSE, &ed->data_to_signed_len);
  if (ed->data_to_signed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating data_to_signed"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

#ifdef SSHDIST_IKE_EAP_AUTH
  if (ed->eap_state == SSH_IKEV2_EAP_DONE)
    {
      /** EAP finished */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_eap);
    }
  else
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_CERT_AUTH
  if (ed->private_key != NULL)
    {
      /** Do we have private key? */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_pk);
    }
  else
#endif /* SSHDIST_IKE_CERT_AUTH */
    {
      /** Check for shared key. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_shared_key);
    }
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_EAP_AUTH
/* Add AUTH payload based on EAP keys. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_eap)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding AUTH(EAP)"));
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_done);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_shared_key) */
  SSH_FSM_ASYNC_CALL(ikev2_add_auth_eap(packet));
}
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
/* Add AUTH payload based on signature. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_pk)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("We have private key adding AUTH(SIG)"));
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_done);
  SSH_FSM_ASYNC_CALL(ikev2_add_auth_public_key(packet));
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Fetch shared key. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_shared_key)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Using shared key, adding AUTH(SHARED_KEY)"));
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_done);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, shared_key) */
  SSH_FSM_ASYNC_CALL(ikev2_add_auth_shared_key(packet));
}

/* Check if we had auth payload from the other end. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_auth_done)
{
#ifdef SSHDIST_IKE_EAP_AUTH
  SshIkev2Packet packet = thread_context;
#endif /* SSHDIST_IKE_EAP_AUTH */

  /** No EAP or EAP done. */
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_cp);

#ifdef SSHDIST_IKE_EAP_AUTH
  /* Check for EAP packet. */
  if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
    {
      /* Check if we are already finished. */
      if (packet->ed->ike_ed->eap_state != SSH_IKEV2_EAP_DONE)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP still in progress"));
          /** EAP still in progress */
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_eap);
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("EAP done, add last packet payloads"));
        }
    }
#endif /* SSHDIST_IKE_EAP_AUTH */
#ifdef SSHDIST_IKE_REDIRECT
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_redirect);
  SSH_FSM_ASYNC_CALL(ikev2_check_redirect(packet));
#else /* SSHDIST_IKE_REDIRECT */
  return SSH_FSM_CONTINUE;
#endif /* SSHDIST_IKE_REDIRECT */
}


#ifdef SSHDIST_IKE_REDIRECT
SSH_FSM_STEP(ikev2_state_auth_responder_out_redirect)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Error error = SSH_IKEV2_ERROR_OK;

  if (packet->ed->redirect == FALSE)
  {
    /* Continue as normal if we don't have to redirect */
    SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_cp);

#ifdef SSHDIST_IKE_EAP_AUTH
  /* Check for EAP packet. */
  if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
    {
      /* Check if we are already finished. */
      if (packet->ed->ike_ed->eap_state != SSH_IKEV2_EAP_DONE)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP still in progress"));
          /** EAP still in progress */
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_eap);
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("EAP done, add last packet payloads"));
        }
    }
#endif /* SSHDIST_IKE_EAP_AUTH */
    return SSH_FSM_CONTINUE;
  }
  SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("Send REDIRECT Notify"));
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_encrypt);

  /* Send REDIRECT Notify */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);
  error = ikev2_make_redirect_payload(packet, packet->ed->buffer, NULL);
  if (error != SSH_IKEV2_ERROR_OK)
    return ikev2_error(packet, error);

  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKE_REDIRECT */

/* Add optional CP payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_cp)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* If we are in the first authentication step of multiple authentication,
     jump over the SA and TS processing for now. */
  if (packet->ed->ike_ed->resp_require_another_auth)
    {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Expecting another authentication from the "
                           "initiator, skip adding SA and TS payloads."));
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_encrypt);

          return SSH_FSM_CONTINUE;
    }
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_select_sa);

  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, conf_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_conf(packet));
}


void
ikev2_reply_cb_auth_responder_select_ipsec_sa(SshIkev2Error error_code,
                                              int proposal_index,
                                              SshIkev2PayloadTransform
                                              selected_transforms
                                              [SSH_IKEV2_TRANSFORM_TYPE_MAX],
                                              void *context)
{
  SshIkev2Packet packet = context;

  if (!ikev2_select_sa_reply(packet, error_code, selected_transforms,
                             packet->ed->ipsec_ed->ipsec_sa_transforms))
    return;
  packet->ed->ipsec_ed->spi_outbound =
    packet->ed->sa->spis.ipsec_spis[proposal_index];
  packet->ed->ipsec_ed->sa = packet->ed->sa;
  packet->ed->ipsec_ed->sa->proposal_number = proposal_index + 1;
  packet->ed->ipsec_ed->ipsec_sa_protocol =
    packet->ed->ipsec_ed->sa->protocol_id[proposal_index];
  packet->ed->sa = NULL;
}

/* Do the SA payload processing, i.e. call to the policy
   manager spd select ike SA function. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_select_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_narrow_ts);
  if (packet->ed->ipsec_ed->error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, select_ipsec_sa)
                     (ike_sa->server->sad_handle, packet->ed,
                      packet->ed->sa,
                      ikev2_reply_cb_auth_responder_select_ipsec_sa,
                      packet));
}

void ikev2_reply_cb_auth_responder_narrow(SshIkev2Error error_code,
                                          SshIkev2PayloadTS return_ts_local,
                                          SshIkev2PayloadTS return_ts_remote,
                                          void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  if (error_code == SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                      ("Traffic selectors narrowed successfully"));
      if (return_ts_local)
        packet->ed->ipsec_ed->ts_local = return_ts_local;
      else
        packet->ed->ipsec_ed->ts_local = packet->ed->ipsec_ed->ts_r;

      ssh_ikev2_ts_take_ref(packet->ike_sa->server->sad_handle,
                            packet->ed->ipsec_ed->ts_local);
      if (return_ts_remote)
        packet->ed->ipsec_ed->ts_remote = return_ts_remote;
      else
        packet->ed->ipsec_ed->ts_remote = packet->ed->ipsec_ed->ts_i;

      ssh_ikev2_ts_take_ref(packet->ike_sa->server->sad_handle,
                            packet->ed->ipsec_ed->ts_remote);
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL,
                      ("Error: Traffic selectors narrow failed: %d",
                       error_code));
      ikev2_ipsec_error(packet, error_code);
    }
}

/* Narrow the traffic selector. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_narrow_ts)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_sa);

  if (packet->ed->ipsec_ed->error != SSH_IKEV2_ERROR_OK)
    return SSH_FSM_CONTINUE;

  if (packet->ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_USE_TRANSPORT_MODE_TS)
    {
      if (ikev2_transport_mode_natt_ts_check(packet->ed) == FALSE)
        return ikev2_ipsec_error(packet, SSH_IKEV2_ERROR_TS_UNACCEPTABLE);
      ikev2_transport_mode_natt_ts_substitute(packet->ed,
                                              packet->ed->ipsec_ed->ts_r,
                                              packet->ed->ipsec_ed->ts_i);
    }

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, narrow)
                     (ike_sa->server->sad_handle, packet->ed,
                      packet->ed->ipsec_ed->ts_r,
                      packet->ed->ipsec_ed->ts_i,
                      ikev2_reply_cb_auth_responder_narrow,
                      packet));
}

/* Add SA payload. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadTransform trans;
  SshIkev2PayloadSA sa;
  SshIkev2Error err;
  int i;

  if (packet->ed->ipsec_ed->error != SSH_IKEV2_ERROR_OK)
    {
      /** Error in child sa creation. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_error_notify);
      return SSH_FSM_CONTINUE;
    }
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_ts);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_SA);

  sa = ssh_ikev2_sa_allocate(ike_sa->server->sad_handle);
  if (sa == NULL)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      trans = packet->ed->ipsec_ed->ipsec_sa_transforms[i];
      /* Do not send DH group for the initial exchange. */
      if (i == SSH_IKEV2_TRANSFORM_TYPE_D_H)
        continue;
      if (trans != NULL)
        {
          err = ssh_ikev2_sa_add(sa,
                                 (SshUInt8) 0,
                                 trans->type,
                                 trans->id,
                                 trans->transform_attribute);
          if (err != SSH_IKEV2_ERROR_OK)
            {
              ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);
              return ikev2_error(packet, err);
            }
        }
    }
  /* Add SA payload. */
  sa->protocol_id[0] = packet->ed->ipsec_ed->ipsec_sa_protocol;
  sa->proposal_number = packet->ed->ipsec_ed->sa->proposal_number;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding SAr2"));
  if (ikev2_encode_sa(packet, packet->ed->buffer, sa,
                      &packet->ed->next_payload_offset) == 0)
    {
      ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
  ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);

  return SSH_FSM_CONTINUE;
}

/* Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_ts)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_notify);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_TS_I);

  /* Add TSi payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding TSi"));
  if (ikev2_encode_ts(packet, packet->ed->buffer,
                      packet->ed->ipsec_ed->ts_remote,
                      &packet->ed->next_payload_offset, TRUE) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  /* Update the next payload pointer of that payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_TS_R);

  /* Add TSr payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding TSr"));
  if (ikev2_encode_ts(packet, packet->ed->buffer,
                      packet->ed->ipsec_ed->ts_local,
                      &packet->ed->next_payload_offset, FALSE) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_EAP_AUTH
/* Request EAP payloads and add them. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_eap)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_eap_check);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_eap(packet));
}

/* Check if eap is done. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_eap_check)
{
  SshIkev2Packet packet = thread_context;

  if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE)
    {
      /* EAP is finished, have we received the AUTH payload from the remote
         end? */
      if (packet->ed->ike_ed->auth_remote == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Error: Mandatory AUTH payload missing "
                           "after EAP DONE"));

          ikev2_audit(packet->ike_sa,
                      SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "Mandatory AUTH payload missing "
                      "after EAP DONE");

          return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP is finished, add AUTH(EAP)"));
      /** EAP finished */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_auth_check);
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP still in progress, send packet"));
      /** EAP still in progress. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_notify);
    }
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKE_EAP_AUTH */

/* Send error notify about the IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_error_notify)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];
  size_t len;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_notify);

  memset(notify, 0, sizeof(SshIkev2PayloadNotifyStruct));
  notify->notify_message_type = (int) packet->ed->ipsec_ed->error;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Adding N(%s) request",
                   ssh_ikev2_notify_to_string(notify->notify_message_type)));

  /* Update the next payload pointer of that payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  len = ikev2_encode_notify(packet, packet->ed->buffer, notify,
                            &packet->ed->next_payload_offset);
  if (len == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
  return SSH_FSM_CONTINUE;
}

/* Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_notify)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_notify_done);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, notify_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_notify(packet));
}

/* Done with adding Notify payloads. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_notify_done)
{
#ifdef SSHDIST_IKE_MOBIKE
  SshIkev2Packet packet = thread_context;

  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    /** If MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_mobike);
  else
#endif /* SSHDIST_IKE_MOBIKE */
    /** No MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_vid);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_MOBIKE
/* Added MOBIKE related notify payloads for MOBIKE enabled SA's . */
SSH_FSM_STEP(ikev2_state_auth_responder_out_mobike)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error error_code;
  SshIkev2PayloadNotify notify;

  SSH_ASSERT(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_vid);

  error_code = ikev2_check_no_nats_notify(packet);

  if (error_code != SSH_IKEV2_ERROR_OK)
    return ikev2_ipsec_error(packet, error_code);

  /* Enforce that MobIKE initiator has done port floating
     if both ends support NAT-T. */
  if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_DISABLED)
      && !(ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T))
    {
      notify = packet->ed->notify;
      while (notify)
        {
          /* Check if initiator has sent NAT-D payloads. */
          if ((notify->notify_message_type
               == SSH_IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP)
              || (notify->notify_message_type
                  == SSH_IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP))
            {
              /* MobIKE initiator has sent NAT-D payloads, but has not
                 done port floating. Tear down IKE SA. */
              if (!(ike_sa->flags
                    & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE))
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("MobIKE initiator has not floated to "
                             "NAT-T port."));
                  return ikev2_ipsec_error(packet,
                                           SSH_IKEV2_ERROR_INVALID_SYNTAX);
                }
              break;
            }
          notify = notify->next_notify;
        }
    }

  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_additional_address_list) */
  SSH_FSM_ASYNC_CALL(ikev2_add_additional_addresses(packet));
}
#endif /* SSHDIST_IKE_MOBIKE */

/* Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_vid)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_EAP_AUTH
  if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
    {
      if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE)
        {
          /** EAP done, install the SA. */
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_install);
        }
      else
        {
          /** EAP not finished, send packet. */
          SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_encrypt);
        }
    }
  else
#endif /* SSHDIST_IKE_EAP_AUTH */
    {
      /** No EAP, install the SA. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_install);
    }

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, vendor_id_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_vid(packet));
}

void ikev2_reply_cb_auth_responder_install(SshIkev2Error error_code,
                                           void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_ipsec_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IPsec SA installed successfully"));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IPsec SA install failed: %d",
                                 error_code));
}

/* Install IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_install)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadNotify notify;

  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_install_done);

  /* Authentication performed, now update the notification list. */
  for (notify = packet->ed->notify; notify; notify = notify->next_notify)
    notify->authenticated = TRUE;

  if (packet->ed->ipsec_ed->error == SSH_IKEV2_ERROR_OK)
    SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_sa_install)
                       (ike_sa->server->sad_handle,
                        packet->ed,
                        ikev2_reply_cb_auth_responder_install,
                        packet));
  else
    {
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_spi_delete)
        (ike_sa->server->sad_handle, packet->ed->ipsec_ed->spi_inbound);
      return SSH_FSM_CONTINUE;
    }
}

/* Call done callbacks. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_install_done)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Exchange finished."));
  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_out_encrypt);

  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE;
  ikev2_debug_ike_sa_open(ike_sa);

  ike_sa->server->statistics->total_ike_sas++;
  ike_sa->server->statistics->total_ike_sas_responded++;

  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_done)
    (ike_sa->server->sad_handle, packet->ed, SSH_IKEV2_ERROR_OK);
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
    (ike_sa->server->sad_handle, packet->ed, packet->ed->ipsec_ed->error);

  return SSH_FSM_CONTINUE;
}

/* Encrypt packet. */
SSH_FSM_STEP(ikev2_state_auth_responder_out_encrypt)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error err;
  Boolean free_sa = TRUE;

  /* Send packet next. */
  SSH_FSM_SET_NEXT(ikev2_state_send);

  err = ikev2_encrypt_packet(packet, packet->ed->buffer);
  ssh_buffer_free(packet->ed->buffer);
  packet->ed->buffer = NULL;

  if (err == SSH_IKEV2_ERROR_OK
#ifdef SSHDIST_IKE_EAP_AUTH
      && (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed) == FALSE
          || packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE)
#endif /* SSHDIST_IKE_EAP_AUTH */
      )
    ikev2_debug_exchange_end(packet);

  /* This will call
     SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done) */
  ikev2_responder_exchange_done(packet);

  /* Then we destroy the IKE SA (providing we are not expecting more EAP
     packets or EAP is not enabled in the first place). */

#ifdef SSHDIST_IKE_EAP_AUTH
  if ((SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed) == FALSE) ||
      (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE))
    free_sa = TRUE;
  else
    free_sa = FALSE;
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if ((packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE
       || packet->ed->ike_ed->first_auth_verified)
      && packet->ed->ike_ed->resp_require_another_auth)
    {
      free_sa = FALSE;

      SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("Marking first authentication done"));
      packet->ed->ike_ed->first_auth_done = 1;

      /* Prepare for the second EAP-authentication */
      packet->ed->ike_ed->eap_state = SSH_IKEV2_NO_EAP;
      /* packet->ed->application_context = NULL; */
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if (free_sa)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Freeing IKE exchange data"));
      ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
      ike_sa->initial_ed = NULL;
      ikev2_free_exchange_data(ike_sa, packet->ed);
      packet->ed = NULL;
    }

  return ikev2_error(packet, err);
}
