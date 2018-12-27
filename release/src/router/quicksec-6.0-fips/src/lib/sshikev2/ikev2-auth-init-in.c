/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE AUTH initiator in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateAuthInitIn"

/* Initiator side IKE AUTH packet in. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in)
{
  SshIkev2Packet packet = thread_context;

  /** Have IDr and AUTH payloads. */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_check_auth);

  /* Check if we have mandatory payloads. */
  if (packet->ed->ike_ed->id_r == NULL ||
      packet->ed->ike_ed->auth_remote == NULL)
    {
#ifdef SSHDIST_IKE_EAP_AUTH
      /* Nope, check if we are using EAP */
      if (SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))
        {
          /** No AUTH or IDr payloads and EAP enabled */
          SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_eap);
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("No IDr or AUTH payloads, but EAP enabled"));
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_EAP"));
          packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_EAP;
        }
      else
#endif /* SSHDIST_IKE_EAP_AUTH */
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Error: IKE_AUTH packet is missing IDr or AUTH "
                           "payload"));
          ikev2_audit(packet->ike_sa,
                      SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                      "IKE_AUTH packet is missing IDr or AUTH "
                      "payload");

          ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
        }
    }
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Initiator side IKE SA INIT packet, check if we have AUTH
   payload, and its type. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_check_auth)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2SaExchangeData ed = packet->ed->ike_ed;

  ed->data_to_signed =
    ikev2_auth_data(packet, FALSE, TRUE, FALSE, &ed->data_to_signed_len);
  if (ed->data_to_signed == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating data_to_signed"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  switch (packet->ed->ike_ed->auth_remote->auth_method)
    {
#ifdef SSHDIST_IKE_CERT_AUTH
    case SSH_IKEV2_AUTH_METHOD_RSA_SIG:
    case SSH_IKEV2_AUTH_METHOD_DSS_SIG:
#ifdef SSHDIST_CRYPT_ECP
    case SSH_IKEV2_AUTH_METHOD_ECP_DSA_256:
    case SSH_IKEV2_AUTH_METHOD_ECP_DSA_384:
    case SSH_IKEV2_AUTH_METHOD_ECP_DSA_521:
#endif /* SSHDIST_CRYPT_ECP */
      /** Auth_method == RSA_SIG or DSS_SIG. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_public_key);
      break;
#endif /* SSHDIST_IKE_CERT_AUTH */
    case SSH_IKEV2_AUTH_METHOD_SHARED_KEY:
      /** Auth_method == SHARED_KEY. */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_shared_key);
      break;
    default:
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Invalid auth_method type : %d",
                       packet->ed->ike_ed->auth_remote->auth_method));
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
      break;
    }
  return SSH_FSM_CONTINUE;
}

/* Verify shared key AUTH payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_shared_key)
{
  SshIkev2Packet packet = thread_context;

  /* This can be either the EAP shared key packet or normal
     pre shared key  packet. */
#ifdef SSHDIST_IKE_REDIRECT
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_redirect);
#else /* SSHDIST_IKE_REDIRECT */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_eap);
#endif /* SSHDIST_IKE_REDIRECT */

#ifdef SSHDIST_IKE_EAP_AUTH
  if (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE)
    {
      /** If Eap is done */
      /* This will call
         SSH_IKEV2_POLICY_CALL(packet, ike_sa, eap_shared_key) */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify EAP AUTH payload"));
      SSH_FSM_ASYNC_CALL(ikev2_check_auth_eap(packet));
    }
  else
#endif /* SSHDIST_IKE_EAP_AUTH */
    {
      /* This will call
         SSH_IKEV2_POLICY_CALL(packet, ike_sa, shared_key) */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify shared key AUTH payload"));
      SSH_FSM_ASYNC_CALL(ikev2_check_auth_shared_key(packet));
    }
}

#ifdef SSHDIST_IKE_CERT_AUTH
/* Get public key. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_public_key)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Fetching public key"));
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_verify_signature);
  /* This will call
     SSH_IKEV2_POLICY_CALL(packet, ike_sa, public_key) */
  SSH_FSM_ASYNC_CALL(ikev2_check_auth_public_key(packet));
}

/* Verify signature. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_verify_signature)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verifying signature"));
#ifdef SSHDIST_IKE_REDIRECT
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_redirect);
#else /* SSHDIST_IKE_REDIRECT */
  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_eap);
#endif /* SSHDIST_IKE_REDIRECT */
  SSH_FSM_ASYNC_CALL(ikev2_check_auth_public_key_verify(packet));
}
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKE_REDIRECT
SSH_FSM_STEP(ikev2_state_auth_initiator_in_redirect)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotify notify;
  SshIkev2NotifyMessageType error;
  int i;
  size_t gw_payload_size;

  error = SSH_IKEV2_NOTIFY_INVALID_SYNTAX;
  for(i = 0, notify = packet->ed->notify;
      i < packet->ed->notify_count && notify != NULL;
      i++, notify = notify->next_notify)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_REDIRECT &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size != 0)
        {
          /* Check redirect gw address type */
          switch(notify->notification_data[0])
            {
              case SSH_IKEV2_REDIRECT_GW_IDENT_IPV4:   /* IPv4 */
                gw_payload_size = 2 + 4;
                break;
              case SSH_IKEV2_REDIRECT_GW_IDENT_IPV6:   /* IPv6 */
                gw_payload_size = 2 + 16;
                break;
              case SSH_IKEV2_REDIRECT_GW_IDENT_FQDN:   /* not supported */
                SSH_IKEV2_DEBUG(SSH_D_ERROR,
                               ("REDIRECT notify received with "
                                "unsupported (FQDN) GW Ident Type"));
                return ikev2_error(packet, (int) error);
              default:  /* invalid */
                SSH_IKEV2_DEBUG(SSH_D_ERROR,
                               ("REDIRECT notify received with "
                                "invalid GW Identity Type"));
                return ikev2_error(packet, (int) error);
            }

          SSH_IP_DECODE(packet->ed->redirect_addr,
                        notify->notification_data + 2,
                        gw_payload_size - 2);
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "Redirected from gateway %@ to gateway %@.",
                        ssh_ipaddr_render, packet->remote_ip,
                        ssh_ipaddr_render, packet->ed->redirect_addr);

          /* Valid redirection. Next state after handling will finish
             the negotiation */
          SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_finish);
          SSH_FSM_ASYNC_CALL(ikev2_redirected(packet));
        }
    }

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_eap);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKE_REDIRECT */

/* Check for EAP payload. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_eap)
{
  SshIkev2Packet packet = thread_context;

  if (packet->ed->ipsec_ed->error != SSH_IKEV2_ERROR_OK)
    {
      /* There was error when creating the IPsec SA. */
      /** There was error code for the IPsec SA */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_finish);
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing up IPsec SPI"));
      SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, ipsec_spi_delete)
        (packet->ed->ike_sa->server->sad_handle,
         packet->ed->ipsec_ed->spi_inbound);
      return SSH_FSM_CONTINUE;
    }

  /* If we do not have mandatory payloads, then this must be
     EAP only packet, and we simply send return EAP packet
     to the other end. */
  if ((packet->ed->sa == NULL ||
       packet->ed->ipsec_ed->ts_i == NULL ||
       packet->ed->ipsec_ed->ts_r == NULL)
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      && packet->ed->ike_ed->eap_state != SSH_IKEV2_EAP_DONE
      && SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed)
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
      )
    {
#ifdef SSHDIST_IKE_EAP_AUTH
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("No SAr2, TSi, or TSr so must be EAP packet"));
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_EAP"));
      packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_EAP;
      /** No SA, TSi and TSr, must be EAP only packet */
      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_end);
#else /* SSHDIST_IKE_EAP_AUTH */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: IKE_AUTH packet is missing SA, TSi or TSr  "
                       "payload and we are not using EAP"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "IKE_AUTH packet is missing SA, TSi or TSr "
                  "payload and we are not using EAP");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
#endif /* SSHDIST_IKE_EAP_AUTH */
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  else if (packet->ed->sa == NULL &&
           packet->ed->ipsec_ed->ts_i == NULL &&
           packet->ed->ipsec_ed->ts_r == NULL &&
           packet->ed->ike_ed->init_another_auth_follows &&
           (packet->ed->ike_ed->eap_state == SSH_IKEV2_EAP_DONE
            ||
            (packet->ed->ike_ed->first_auth_verified
             && !SSH_IKEV2_EAP_ENABLED(packet->ed->ike_ed))))
    {
      /** Responder is expecting a second authentication and
          sends SA and TS payloads after receiving it */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("SAr2, TSi and TSr are missing and we still have "
                       "second authentication left. Verifying AUTH from "
                       "responder and sending second AUTH."));

      /* NULL the application context to make room for the second
         EAP-authentication context. */
      /* packet->ed->application_context = NULL; */

      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_first_auth_in_end);
    }
  else if (packet->ed->sa == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL,
                      ("Error: IKE_AUTH packet is missing SA payload. This "
                       "is either a corrupted packet or the peer requires "
                       "second authentication round"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Error: IKE_AUTH packet is missing SA payload. This "
                  "is either a corrupted packet or the peer requires "
                  "second authentication round");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_LAST"));
      packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_LAST;
      /** We did have SA, TSi and TSr. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("SAr2, TSi, or TSr, so this is final packet"));

      SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_sa);
    }
  return SSH_FSM_CONTINUE;
}

/* Do the SA payload processing, i.e. verify that the
   returned SA matches our proposal. This will also fill in
   the ipsec_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_ts);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify SAr2"));

  if (!ikev2_verify_sa(packet, packet->ed->sa,
                       packet->ed->ipsec_ed->sa_i,
                       packet->ed->ipsec_ed->ipsec_sa_transforms,
                       FALSE))
    return SSH_FSM_CONTINUE;


  /* Ok. the proposal returned by the other end is ok. */
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("SAr2 was ok"));

  /* As this is reply packet, there must be only one proposal. */
  packet->ed->ipsec_ed->spi_outbound =
    packet->ed->sa->spis.ipsec_spis[0];
  packet->ed->ipsec_ed->ipsec_sa_protocol =
    packet->ed->sa->protocol_id[0];
  return SSH_FSM_CONTINUE;
}

/* Check the traffic selectors. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_ts)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_done);

  if (packet->ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_USE_TRANSPORT_MODE_TS)
    {
      if (ikev2_transport_mode_natt_ts_check(packet->ed) == FALSE)
        {
          SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_finish);
          return ikev2_ipsec_error(packet, SSH_IKEV2_ERROR_TS_UNACCEPTABLE);
        }
      ikev2_transport_mode_natt_ts_substitute(packet->ed,
                                              packet->ed->ipsec_ed->ts_i,
                                              packet->ed->ipsec_ed->ts_r);
    }

  if (!ssh_ikev2_ts_match(packet->ed->ipsec_ed->ts_local,
                          packet->ed->ipsec_ed->ts_i) ||
      !ssh_ikev2_ts_match(packet->ed->ipsec_ed->ts_remote,
                          packet->ed->ipsec_ed->ts_r))
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Traffic selectors does not match"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_TRAFFIC_SELECTORS,
                  "Traffic selectors do not match");

      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  /* Free the original TS payloads, and replace them with
     the ones returned from the other end. */
  ssh_ikev2_ts_free(packet->ike_sa->server->sad_handle,
                    packet->ed->ipsec_ed->ts_local);
  ssh_ikev2_ts_free(packet->ike_sa->server->sad_handle,
                    packet->ed->ipsec_ed->ts_remote);
  packet->ed->ipsec_ed->ts_local = packet->ed->ipsec_ed->ts_i;
  packet->ed->ipsec_ed->ts_remote = packet->ed->ipsec_ed->ts_r;

  /* Remove duplicate items from the narrowed traffic selectors in case the
     responder did not corectly narrow them. */
  if (!ssh_ikev2_ts_remove_duplicate_items(packet->ike_sa->server->sad_handle,
                                           packet->ed->ipsec_ed->ts_local) ||
      !ssh_ikev2_ts_remove_duplicate_items(packet->ike_sa->server->sad_handle,
                                           packet->ed->ipsec_ed->ts_remote))
    {
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  packet->ed->ipsec_ed->ts_i = NULL;
  packet->ed->ipsec_ed->ts_r = NULL;
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("TSi and TSr were ok"));
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_EAP_AUTH
/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Sending EAP packet"));

  if (ikev2_transmit_window_full(packet->ike_sa->transmit_window) == TRUE)
    {
      return ikev2_error(packet, SSH_IKEV2_ERROR_WINDOW_FULL);
    }

  /** Send next EAP packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out_eap); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_auth_initiator_out_eap);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;
  reply_packet->exchange_type = SSH_IKEV2_EXCH_TYPE_IKE_AUTH;
  reply_packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;

  ikev2_transmit_window_insert(
          reply_packet->ike_sa->transmit_window,
          reply_packet);

  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_auth_initiator_first_auth_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Packet reply_packet;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Move to process second AUTH"));

  /* Mark first authentication done and return eap_state to start */
  packet->ed->ike_ed->first_auth_done = 1;
  packet->ed->ike_ed->authentication_round = 2;
  packet->ed->ike_ed->eap_state = SSH_IKEV2_EAP_STARTED;

  if (ikev2_transmit_window_full(packet->ike_sa->transmit_window))
    return ikev2_error(packet, SSH_IKEV2_ERROR_WINDOW_FULL);

  /** Send next AUTH packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet,
                                ikev2_state_second_auth_initiator_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;
  reply_packet->exchange_type = SSH_IKEV2_EXCH_TYPE_IKE_AUTH;
  reply_packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;

  ikev2_transmit_window_insert(
          ike_sa->transmit_window,
          reply_packet);

  return SSH_FSM_FINISH;
}
#endif /* SSH_IKEV2_MULTIPLE_AUTH */


void ikev2_reply_cb_auth_initiator_install(SshIkev2Error error_code,
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

/* SA exchange done. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_done)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadNotify notify;

  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in_finish);

  /* Authentication performed, now update the notification list. */
  for (notify = packet->ed->notify; notify; notify = notify->next_notify)
    notify->authenticated = TRUE;

#ifdef SSHDIST_IKE_MOBIKE
  if (ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE)
    {
      /* Check if the responder also supports MOBIKE, if so mark this SA as
         a MOBIKE enabled SA. */
      for (notify = packet->ed->notify; notify; notify = notify->next_notify)
        {
          if (notify->notify_message_type == SSH_IKEV2_NOTIFY_MOBIKE_SUPPORTED)
            {
              SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("Both ends support MOBIKE, "
                                            "enabling MOBIKE for this SA"));
              ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED;
              break;
            }
        }
    }
#endif /* SSHDIST_IKE_MOBIKE */

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_sa_install)
                     (ike_sa->server->sad_handle,
                      packet->ed,
                      ikev2_reply_cb_auth_initiator_install,
                      packet));
}

/* Finish the exchange. */
SSH_FSM_STEP(ikev2_state_auth_initiator_in_finish)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  ikev2_debug_exchange_end(packet);

  ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE;
  ikev2_debug_ike_sa_open(ike_sa);

  ike_sa->server->statistics->total_ike_sas++;
  ike_sa->server->statistics->total_ike_sas_initiated++;

  /* Clear information about any received unprotected error notifications,
     as they clearly were not sent by the authenticated IKE peer of this
     negotiation. */
  if (ike_sa->received_unprotected_error != SSH_IKEV2_ERROR_OK)
    SSH_DEBUG(SSH_D_UNCOMMON,
              ("Ignoring unprotected error notification '%s' (%d) received "
               "for IKEv2 SA %p",
               ssh_ikev2_error_to_string(ike_sa->received_unprotected_error),
               (int) ike_sa->received_unprotected_error,
               ike_sa));
  ike_sa->received_unprotected_error = SSH_IKEV2_ERROR_OK;

  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_done)
    (ike_sa->server->sad_handle, packet->ed, SSH_IKEV2_ERROR_OK);
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
    (ike_sa->server->sad_handle, packet->ed, packet->ed->ipsec_ed->error);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Calling finished callback"));
  if (packet->ed->callback)
    {
      (*(packet->ed->callback))(ike_sa->server->sad_handle,
                                ike_sa,
                                packet->ed, SSH_IKEV2_ERROR_OK);
      /* Clear the callback so it will not be called twice. */
      packet->ed->callback = NULL_FNPTR;
    }
  /* Unregister operation and mark that we do not have operation registered
     anymore. */
  ssh_operation_unregister_no_free(packet->ed->ipsec_ed->operation_handle);
  packet->ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing reference and exchange data"));

  /* Then we destroy the IKE SA initial ED (from the operation handle). */
  ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
  ike_sa->initial_ed = NULL;

  /* Then we destroy the ED from packet, as it is no longer needed. */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;

  /* Finally free the IKE SA reference (from the operation handle). */
  SSH_IKEV2_IKE_SA_FREE(ike_sa);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Initial exchange finished"));

  return SSH_FSM_FINISH;
}
