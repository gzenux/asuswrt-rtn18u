/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE AUTH initiator out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateAuthInitOut"

/* Start IKE AUTH state. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_idi);

  packet->ed->next_payload_offset = -1;
  packet->ed->buffer = ssh_buffer_allocate();
  if (packet->ed->buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  packet->ed->packet_to_process = packet;
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Making sure that the SKEYSEED is calculated"));
  ikev2_skeyseed(ike_sa);
  if (packet->ed->operation != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("Started async SKEYSEED calculation, waiting"));
      return SSH_FSM_SUSPENDED;
    }
  packet->ed->packet_to_process = NULL;

  return SSH_FSM_CONTINUE;
}

/* Add IDi payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_idi)
{
  SshIkev2Packet packet = thread_context;
#ifdef SSHDIST_IKE_CERT_AUTH
  /** If certificate support compiled in */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_cert);
#else /* SSHDIST_IKE_CERT_AUTH */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_idr);
#endif /* SSHDIST_IKE_CERT_AUTH */
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, id) */
  SSH_FSM_ASYNC_CALL(ikev2_add_id(packet, TRUE));
}

#ifdef SSHDIST_IKE_CERT_AUTH
/* Add optional CERT payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_cert)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_certreq);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_certificates) */
  SSH_FSM_ASYNC_CALL(ikev2_add_certs(packet));
}

/* Add optional CERTREQ payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_certreq)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_idr);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_cas) */
  SSH_FSM_ASYNC_CALL(ikev2_add_certreq(packet));
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Add optional IDr payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_idr)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_check);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, id) */
  SSH_FSM_ASYNC_CALL(ikev2_add_id(packet, FALSE));
}

/* Check auth type. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_check)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  ed->data_to_signed =
    ikev2_auth_data(packet, TRUE, FALSE, TRUE, &ed->data_to_signed_len);
  if (ed->data_to_signed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating data_to_signed"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

#ifdef SSHDIST_IKE_CERT_AUTH
  if (ed->private_key != NULL)
    {
      /** We have private key */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_pk);
    }
  else
#endif /* SSHDIST_IKE_CERT_AUTH */
    {
      /** Check for shared key. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_shared_key);
    }
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_EAP_AUTH
/* Add AUTH payload based on EAP keys. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_eap)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding AUTH(EAP)"));

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /** Multiple auth support compiled in */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_eap_another_auth);
#else /* SSH_IKEV2_MULTIPLE_AUTH */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_done);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_shared_key) */
  SSH_FSM_ASYNC_CALL(ikev2_add_auth_eap(packet));
}
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
SSH_FSM_STEP(ikev2_state_auth_initiator_out_eap_another_auth)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_done);

  if (packet->ed->ike_ed->init_another_auth_follows &&
      packet->ed->ike_ed->peer_supports_multiple_auth)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("Adding N(ANOTHER_AUTH_FOLLOWS)"));
      ikev2_add_another_auth_follows(packet);
    }

  return SSH_FSM_CONTINUE;
}
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


#ifdef SSHDIST_IKE_CERT_AUTH
/* Add AUTH payload based on signature. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_pk)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("We have private key, adding AUTH(SIG)"));

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_done);

  SSH_FSM_ASYNC_CALL(ikev2_add_auth_public_key(packet));
}
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Fetch shared key. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_shared_key)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Try to use shared key"));
  /** Added shared key AUTH. */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_done);
  /** Could not find shared key => enable EAP. */
  /* SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_done); */
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, shared_key) */
  SSH_FSM_ASYNC_CALL(ikev2_add_auth_shared_key(packet));
}

/* Auth payload done, see whether we were doing EAP if so
   then, we have the packet ready, otherwise continue normal
   processing. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_auth_done)
{
#ifdef SSHDIST_IKE_EAP_AUTH
  SshIkev2Packet packet = thread_context;

  if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
   {
      /* We are using eap. See if this is first packet. */
      if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_STARTED)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("No shared key found, enabling EAP"));
          /** EAP enabled, but 1st packet. */
          SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_alloc_sa);
          packet->ed->ike_ed->eap_state = SSH_IKEV2_EAP_1ST_DONE;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
          /* If we intend to initiate multiple authentications and
             first authentication is done in EAP, add notify here. */
          if (packet->ed->ike_ed->init_another_auth_follows)
            {
              SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                              ("Adding N(MULTIPLE_AUTH_SUPPORTED)"));
              ikev2_add_multiple_auth_notify(packet);
            }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Using EAP"));
          /** Using EAP, but not 1st packet. */
          SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);
        }
    }
  else
#else /* SSHDIST_IKE_EAP_AUTH */
#ifdef DEBUG_LIGHT
  SshIkev2Packet packet = thread_context;
#endif /* DEBUG_LIGHT */
#endif /* SSHDIST_IKE_EAP_AUTH */
  {
    SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("No EAP"));
    /** Continue normal processing. */
    SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_alloc_sa);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
    /* If we are not using EAP, we know we are sending AUTH-payload
       in this packet. Add multiple auth notifies if needed. */
    if (packet->ed->ike_ed->init_another_auth_follows &&
        packet->ed->ike_ed->peer_supports_multiple_auth)
      {
        SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                        ("Adding N(MULTIPLE_AUTH_SUPPORTED)"));
        ikev2_add_multiple_auth_notify(packet);


        SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                        ("Adding N(ANOTHER_AUTH_FOLLOWS)"));
        ikev2_add_another_auth_follows(packet);
      }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  }
  return SSH_FSM_CONTINUE;
}

void ikev2_reply_cb_auth_initiator_ipsec_spi_allocate(SshIkev2Error error_code,
                                                      SshUInt32 spi,
                                                      void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                    ("IPsec SA allocated successfully spi = 0x%08lx",
                     spi));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IPsec SA allocate failed: %d",
                                 error_code));
  packet->ed->ipsec_ed->spi_inbound = spi;
 }

/* Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_alloc_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_cp);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_spi_allocate)
                     (ike_sa->server->sad_handle, packet->ed,
                      ikev2_reply_cb_auth_initiator_ipsec_spi_allocate,
                      packet));
}

/* Add optional CP payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_cp)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_fill_sa);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, conf_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_conf(packet));
}

void ikev2_reply_cb_auth_initiator_fill_ipsec_sa(SshIkev2Error error_code,
                                                 SshIkev2PayloadSA sa,
                                                 void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  /* Set the error code if error. */
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IPsec SA filled successfully"));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IPsec SA fill failed: %d",
                                 error_code));

  packet->ed->ipsec_ed->sa_i = sa;
}

/* Fill the SA payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_fill_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_sa);
  SSH_FSM_ASYNC_CALL(
                     SSH_IKEV2_POLICY_CALL(packet, ike_sa, fill_ipsec_sa)
                     (ike_sa->server->sad_handle, packet->ed,
                      ikev2_reply_cb_auth_initiator_fill_ipsec_sa,
                      packet));

}

/* Add SA payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_ts);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_SA);

  /* Add SA payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding SAi2"));
  if (ikev2_encode_sa(packet, packet->ed->buffer, packet->ed->ipsec_ed->sa_i,
                      &packet->ed->next_payload_offset) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}

/* Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_ts)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_MOBIKE
  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE)
    /** If MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_mobike_add_nat_notifies);
  else
#endif /* SSHDIST_IKE_MOBIKE */
    /** No MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_TS_I);

  /* Add TSi payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding TSi"));
  if (ikev2_encode_ts(packet, packet->ed->buffer,
                      packet->ed->ipsec_ed->ts_local,
                      &packet->ed->next_payload_offset, TRUE) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  /* Update the next payload pointer of that payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_TS_R);

  /* Add TSr payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding TSr"));
  if (ikev2_encode_ts(packet, packet->ed->buffer,
                      packet->ed->ipsec_ed->ts_remote,
                      &packet->ed->next_payload_offset, FALSE) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_MOBIKE
/** Do port floating or add NO_NATS_ALLOWED notify payload for MOBIKE
    enabled SA's . */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_mobike_add_nat_notifies)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_ASSERT(ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE);

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_mobike_add_additional_addrs);

  /* Float to use the NAT-T port unless NAT-T was disabled for this
     negotiation. */
  if (!(ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_DISABLED)
      && !(ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("IKE SA supports both MOBIKE and NAT-T "
                                   "floating to use NAT-T ports."));

      ike_sa->remote_port = ike_sa->server->nat_t_remote_port;
      ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;
      packet->use_natt = 1;
      packet->remote_port = ike_sa->remote_port;
    }
  else if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_NO_NATS_ALLOWED)
    {
      ikev2_add_no_nats_notify(packet);
    }

  return SSH_FSM_CONTINUE;
}

/** Add MOBIKE_SUPPORTED and additional addresses notify payloads. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_mobike_add_additional_addrs)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];

  SSH_ASSERT((packet->ike_sa->flags
              & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE));

  SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);

  /* Add MOBIKE supported notify */
  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type =  SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 0;
  notify->notification_data = NULL;

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(MOBIKE_SUPPORTED)"));
  if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                          &packet->ed->next_payload_offset) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);

  /* Add additional addresses. */
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, get_additional_address_list) */
  SSH_FSM_ASYNC_CALL(ikev2_add_additional_addresses(packet));
}

#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSHDIST_IKE_EAP_AUTH
/* Send out EAP payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_eap)
{
  SshIkev2Packet packet = thread_context;

  packet->ed->next_payload_offset = -1;
  packet->ed->buffer = ssh_buffer_allocate();
  if (packet->ed->buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  packet->ed->ike_ed->auth_remote = NULL;
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_eap_check);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_eap(packet));
}

/* Check if eap is done. */
SSH_FSM_STEP(ikev2_state_auth_initiator_out_eap_check)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP is finished, add AUTH(EAP)"));

      ed->data_to_signed =
        ikev2_auth_data(packet, TRUE, FALSE, TRUE, &ed->data_to_signed_len);
      if (ed->data_to_signed == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating data_to_signed"));
          return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
        }

      /** EAP finished */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_auth_eap);
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("EAP still in progress, send packet"));
      /** EAP still in progress. */
      SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);
    }
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKE_EAP_AUTH */

