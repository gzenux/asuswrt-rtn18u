/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE SA INIT initiator in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateSaInitInitIn"

/* Initiator side IKE SA INIT packet in. */
SSH_FSM_STEP(ikev2_state_init_initiator_in)
{
  SshIkev2Packet packet = thread_context;

  if (packet->ed->sa == NULL || packet->ed->ke == NULL ||
      packet->ed->nonce == NULL)
    {
      if (packet->ed->notify_count != 0)
        {
          /** No SA, KE, and Nonce, but We have notify. */
          SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_notify);
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("No SA, KE or NONCE payloads, but NOTIFY"));
          return SSH_FSM_CONTINUE;
        }
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("No SA, KE or NONCE payloads"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  /* The error notifies that may have a zero responder IKE SPI are
     processed above. Verify that packet IKE SPIs match the values in
     IKE SA and drop packet if they mismatch. */
  if (memcmp(packet->ike_sa->ike_spi_i, packet->ike_spi_i,
             sizeof(packet->ike_spi_i)) != 0
      || memcmp(packet->ike_spi_r, "\0\0\0\0\0\0\0\0", 8) == 0
      || memcmp(packet->ike_sa->ike_spi_r, packet->ike_spi_r,
                sizeof(packet->ike_spi_r)) != 0)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Invalid IKE SPIs in IKE_SA_INIT response: "
                       "packet I %08lx %08lx R %08lx %08lx vs "
                       "SA I %08lx %08lx R %08lx %08lx",
                       SSH_GET_32BIT(packet->ike_spi_i),
                       SSH_GET_32BIT(packet->ike_spi_i + 4),
                       SSH_GET_32BIT(packet->ike_spi_r),
                       SSH_GET_32BIT(packet->ike_spi_r + 4),
                       SSH_GET_32BIT(packet->ike_sa->ike_spi_i),
                       SSH_GET_32BIT(packet->ike_sa->ike_spi_i + 4),
                       SSH_GET_32BIT(packet->ike_sa->ike_spi_r),
                       SSH_GET_32BIT(packet->ike_sa->ike_spi_r + 4)));
      return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
    }

  /** We have SA, KE and Nonce. */
  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_sa);
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}


/* Check for COOKIE or INVALID_KE_PAYLOAD payload. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_notify)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotify notify;
  SshIkev2NotifyMessageType error;
  int i;
#ifdef SSHDIST_IKE_REDIRECT
  size_t gw_payload_size;
#endif /* SSHDIST_IKE_REDIRECT */

  /* If not other error code is found use INVALID SYNTAX, as we didn't
     have the mandatory payloads in this payload, only notify. */
  error = SSH_IKEV2_NOTIFY_INVALID_SYNTAX;
  for(i = 0, notify = packet->ed->notify;
      i < packet->ed->notify_count && notify != NULL;
      i++, notify = notify->next_notify)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_COOKIE &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size != 0)
        {
          /* Cookie notification, ok, continue. */
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("N(COOKIE) found"));
          /** N(cookie) found, start from beginning */
          SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_restart);
          return SSH_FSM_CONTINUE;
        }
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size == 2)
        {
          /* Invalid KE payload notification, ok, continue. */
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("N(INVALID_KE_PAYLOAD) found"));
          /** N(INVALID_KE) found, start from beginning */
          SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_restart);
          return SSH_FSM_CONTINUE;
        }

#ifdef SSHDIST_IKE_REDIRECT
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_REDIRECT &&
          notify->spi_size == 0 &&
          notify->spi_data == NULL &&
          notify->notification_size != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("REDIRECT notify received "
                " notification_size %d our nonce %@",
                notify->notification_size,
                ssh_ikev2_payload_nonce_render, packet->ed->ike_ed->ni ));

          /* TODO format logging */

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

          /* Verify the nonce data is the same we sent */
          if ( (notify->notification_size - gw_payload_size) ==
                  packet->ed->ike_ed->ni->nonce_size                &&
                memcmp(notify->notification_data + gw_payload_size,
                       packet->ed->ike_ed->ni->nonce_data,
                       packet->ed->ike_ed->ni->nonce_size) == 0)
            {
              SSH_IKEV2_DEBUG(SSH_D_MY, ("REDIRECT is valid"));

              SSH_IP_DECODE(packet->ed->redirect_addr,
                            notify->notification_data + 2,
                            gw_payload_size - 2);
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            "Redirected from gateway %@ to gateway %@.",
                            ssh_ipaddr_render, packet->remote_ip,
                            ssh_ipaddr_render, packet->ed->redirect_addr);

              /* Valid redirection. Next state after handling will simply
               * finish the negotiation */
              SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_redirected);
              SSH_FSM_ASYNC_CALL(ikev2_redirected(packet));
            }
          else
            {
              SSH_IKEV2_DEBUG(SSH_D_ERROR, ("REDIRECT is NOT valid"));
              /* discard and wait for another response */
              return ikev2_error(packet, SSH_IKEV2_ERROR_DISCARD_PACKET);
            }
        }
#endif /* SSHDIST_IKE_REDIRECT */

      if (notify->notify_message_type < SSH_IKEV2_NOTIFY_INITIAL_CONTACT &&
          notify->notify_message_type != SSH_IKEV2_NOTIFY_RESERVED)
        {
          /* Use the error code we got from the other end when
             reporting the error. */
          error = notify->notify_message_type;
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("N(%d) error found",
                                          notify->notify_message_type));
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("N(%d) found",
                                          notify->notify_message_type));
        }
    }
  /** Some other notification. */
  /* SSH_FSM_SET_NEXT(ikev2_state_error); */
  return ikev2_error(packet, (int) error);
}

#ifdef SSHDIST_IKE_REDIRECT
SSH_FSM_STEP(ikev2_state_init_initiator_in_redirected)
{
  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_IKE_REDIRECT */

SSH_FSM_STEP(ikev2_state_init_initiator_in_restart)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet new_packet;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Allocating new first packet"));

  new_packet = ikev2_packet_allocate(packet->ike_sa->server->context,
                                     ikev2_state_init_initiator_out);
  if (new_packet != NULL)
    {
      SshIkev2Sa ike_sa = packet->ike_sa;

      memcpy(new_packet->ike_spi_i, packet->ike_spi_i, 8);
      /* Changed accordingly to the clarification draft to always use
         zero SPI when restarting, instead of copying the old SPI. */
      memset(new_packet->ike_spi_r, 0, 8);
      new_packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NONE;
      new_packet->major_version = 2;
      new_packet->minor_version = 0;
      new_packet->exchange_type = packet->exchange_type;
      new_packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;
      new_packet->message_id = 0;
      new_packet->encoded_packet_len = 0;
      new_packet->encoded_packet = NULL;
      *(new_packet->remote_ip) = *(packet->remote_ip);
      new_packet->remote_port = packet->remote_port;
      new_packet->server = packet->server;
      new_packet->use_natt = packet->use_natt;
      /* Steal the reference to the IKE SA */
      new_packet->ike_sa = packet->ike_sa;
      packet->ike_sa = NULL;
      /* the new packet steal the reference from the old */
      new_packet->ed = packet->ed;
      packet->ed = NULL;

      ikev2_transmit_window_reset(ike_sa->transmit_window);

      ikev2_transmit_window_insert(
              ike_sa->transmit_window,
              new_packet);

      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Allocated new first packet"));

      /* Clear information about any received unprotected error notifications,
         as we are restarting the IKE_SA_INIT exchange. */
      if (new_packet->ike_sa->received_unprotected_error != SSH_IKEV2_ERROR_OK)
        SSH_DEBUG(SSH_D_UNCOMMON,
                  ("Ignoring unprotected error notification '%s' (%d) "
                   "received for IKEv2 SA %p",
                   ssh_ikev2_error_to_string(new_packet->ike_sa->
                                             received_unprotected_error),
                   (int) new_packet->ike_sa->received_unprotected_error,
                   new_packet->ike_sa));
      new_packet->ike_sa->received_unprotected_error = SSH_IKEV2_ERROR_OK;

      return SSH_FSM_FINISH;
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: packet allocate failed"));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
      return SSH_FSM_CONTINUE;
    }
}

/* Do the SA payload processing, i.e. verify that the
   returned SA matches our proposal. This will also fill in
   the ike_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_ke);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify SAr1"));
  if (!ikev2_verify_sa(packet, packet->ed->sa,
                       packet->ed->ike_ed->sa_i,
                       packet->ed->ike_ed->ike_sa_transforms,
                       TRUE))
    return SSH_FSM_CONTINUE;
  ikev2_error(packet,
              ikev2_fill_in_algorithms(packet->ike_sa,
                                       packet->ed->ike_ed->ike_sa_transforms));

  /* Ok. the proposal returned by the other end is ok. */
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("SAr1 was ok"));
  return SSH_FSM_CONTINUE;
}

/* Check the KE payload. It must match the selected proposal
   from the SA, and also the group we selected when sending
   our KE payload out. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_ke)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_nonce);
  if (packet->ed->ike_ed->ike_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]
      ->id != packet->ed->ke->dh_group ||
      packet->ed->ke->dh_group != packet->ed->ike_ed->group_number)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("KE group didn't match"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_KEY_INFORMATION,
                  "Invalid Diffie-Hellman group in KE payload");

      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  ssh_ikev2_sa_free(packet->ike_sa->server->sad_handle, packet->ed->sa);
  packet->ed->sa = NULL;
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("KE was ok"));
  return SSH_FSM_CONTINUE;
}

/* Check the nonce. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_nat_t);
  ikev2_check_nonce(packet, &(packet->ed->ike_ed->nr));
  return SSH_FSM_CONTINUE;
}

/* Check the NAT-T notifies. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_nat_t)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_multiple_auth);
#else /* SSH_IKEV2_MULTIPLE_AUTH */
  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_end);
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  ikev2_check_nat_detection(packet, TRUE);

  return SSH_FSM_CONTINUE;
}

#ifdef SSH_IKEV2_MULTIPLE_AUTH
/* Check if responder supports multiple authentications */
SSH_FSM_STEP(ikev2_state_init_initiator_in_multiple_auth)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in_end);

  if (ikev2_check_multiple_auth(packet))
    packet->ed->ike_ed->peer_supports_multiple_auth = 1;
  else
    packet->ed->ike_ed->peer_supports_multiple_auth = 0;

  return SSH_FSM_CONTINUE;
}
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

/* Input processing done, start output processing of next packet. */
SSH_FSM_STEP(ikev2_state_init_initiator_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error error;

  /* Ok, we managed to process the packet properly, lets mark
     it to window. */
  ikev2_transmit_window_acknowledge(
          packet->ike_sa->transmit_window,
          packet->message_id);

  /* Store last packet received. */
  packet->ed->ike_ed->remote_ike_sa_init =
    ssh_obstack_memdup(packet->ed->obstack,
                       (packet->use_natt ?
                        packet->encoded_packet + 4 :
                        packet->encoded_packet),
                       (packet->use_natt ?
                        packet->encoded_packet_len - 4 :
                        packet->encoded_packet_len));
  if (packet->ed->ike_ed->remote_ike_sa_init == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory copying packet"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
  packet->ed->ike_ed->remote_ike_sa_init_len =
    (packet->use_natt ?
     packet->encoded_packet_len - 4 :
     packet->encoded_packet_len);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = AUTH_1ST"));
  packet->ed->state = SSH_IKEV2_STATE_IKE_AUTH_1ST;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /* Moving to authentication round one */
  packet->ed->ike_ed->authentication_round = 1;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /** Start IKE_AUTH exchange. */
  /* SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_out); */

  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_auth_initiator_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  reply_packet->exchange_type = SSH_IKEV2_EXCH_TYPE_IKE_AUTH;
  reply_packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR;

  error = ikev2_transmit_window_insert(ike_sa->transmit_window, reply_packet);
  if (error != SSH_IKEV2_ERROR_OK)
    {
      ikev2_packet_done(reply_packet);

      return ikev2_error(packet, error);
    }

  SSH_ASSERT(reply_packet->message_id == 1);
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Move to the IKE_AUTH exchange"));

  if (ike_sa->flags &
      (SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT |
       SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT))
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("One end is behind NAT, enable NAT-T"));
      reply_packet->use_natt = 1;
      ike_sa->remote_port = ike_sa->server->nat_t_remote_port;
      reply_packet->remote_port = ike_sa->remote_port;
      ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE;
    }
  return SSH_FSM_FINISH;
}
