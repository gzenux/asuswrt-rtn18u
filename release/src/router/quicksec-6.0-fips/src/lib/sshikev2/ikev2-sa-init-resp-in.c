/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for IKE SA INIT responder in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateSaInitRespIn"


/* Responder side IKE SA INIT packet in. */
SSH_FSM_STEP(ikev2_state_init_responder_in)
{
  SshIkev2Packet packet = thread_context;

#ifdef SSHDIST_IKE_REDIRECT
  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_redirect_start);
#else /* SSHDIST_IKE_REDIRECT */
  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_cookie);
#endif /* SSHDIST_IKE_REDIRECT */

  ikev2_debug_exchange_begin(packet);

  SSH_DEBUG(SSH_D_LOWSTART, ("State = IKE_INIT_SA"));
  packet->ed->state = SSH_IKEV2_STATE_IKE_INIT_SA;

  if (packet->ed->sa == NULL || packet->ed->ke == NULL ||
      packet->ed->nonce == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("No SA, KE or NONCE payloads"));
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  /* Check the packet's notify payloads */
  ikev2_process_notify(packet);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_REDIRECT
SSH_FSM_STEP(ikev2_state_init_responder_in_redirect_start)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_redirect);
  SSH_FSM_ASYNC_CALL(ikev2_check_redirect(packet));
}

SSH_FSM_STEP(ikev2_state_init_responder_in_redirect)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  if (packet->ed->redirect == FALSE)
  {
    /* Continue as normal if we don't have to redirect */
    SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_cookie);
    return SSH_FSM_CONTINUE;
  }
  SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Send REDIRECT Notify"));

  /* Send REDIRECT Notify */
  reply_packet = ikev2_reply_packet_allocate(packet, ikev2_state_redirect_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  /* Redirecting terminates current negotiation */
  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_IKE_REDIRECT */

/* Responder side IKE SA INIT packet, check if we have
   cookie, and if it is needed. */
SSH_FSM_STEP(ikev2_state_init_responder_in_cookie)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_REQUIRE_COOKIE)
    {
      SshIkev2PayloadNotify notify;
      SshIkev2Error err;

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Check for required N(COOKIE)"));

      /* We do require cookies, lets check if we have
         already it in there. */
      notify = packet->ed->notify;
      while (notify != NULL)
        {
          if (notify->notify_message_type == SSH_IKEV2_NOTIFY_COOKIE &&
              notify->spi_size == 0 &&
              notify->spi_data == NULL)
            {
              if (packet->ed->ike_ed->cookie == NULL)
                {
                  err = ikev2_generate_cookie(packet, ike_sa,
                                              notify->notification_data,
                                              notify->notification_size);
                  if (err != SSH_IKEV2_ERROR_OK)
                    return ikev2_error(packet, err);
                }

              if (notify->notification_size ==
                  packet->ed->ike_ed->cookie_len &&
                  memcmp(notify->notification_data, packet->ed->ike_ed->cookie,
                         packet->ed->ike_ed->cookie_len) == 0)
                {
                  /** Cookie found and it is valid. */
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                                  ("N(COOKIE) found and is valid"));
                  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_sa);
                  return SSH_FSM_CONTINUE;
                }
            }
          notify = notify->next_notify;
        }
      if (packet->ed->ike_ed->cookie == NULL)
        {
          err = ikev2_generate_cookie(packet, ike_sa, NULL, 0);
          if (err != SSH_IKEV2_ERROR_OK)
            return ikev2_error(packet, err);
        }
      /** We didn't find cookies, request one. */
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("N(COOKIE) not found, request one"));
      SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_request_cookie);
      return SSH_FSM_CONTINUE;
    }
  /** No cookie required, so continue. */
  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_sa);
  return SSH_FSM_CONTINUE;
}

void
ikev2_reply_cb_init_responder_select_ike_sa(SshIkev2Error error_code,
                                            int proposal_index,
                                            SshIkev2PayloadTransform
                                            selected_transforms
                                            [SSH_IKEV2_TRANSFORM_TYPE_MAX],
                                            void *context)
{
  SshIkev2Packet packet = context;

  if (!ikev2_select_sa_reply(packet, error_code,
                             selected_transforms,
                             packet->ed->ike_ed->ike_sa_transforms))
    return;
  packet->ed->sa->proposal_number = proposal_index + 1;

  ikev2_error(packet,
              ikev2_fill_in_algorithms(packet->ike_sa,
                                       packet->ed->ike_ed->ike_sa_transforms));
}

/* Do the SA payload processing, i.e. call to the policy
   manager spd select ike SA function. */
SSH_FSM_STEP(ikev2_state_init_responder_in_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_ke);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, select_ike_sa)
                     (ike_sa->server->sad_handle, packet->ed,
                      packet->ed->sa,
                      ikev2_reply_cb_init_responder_select_ike_sa,
                      packet));
}

/* Check the KE payload. It must match the selected proposal
   from the SA. */
SSH_FSM_STEP(ikev2_state_init_responder_in_ke)
{
  SshIkev2Packet packet = thread_context;

  if (packet->ed->ike_ed->ike_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id
      != packet->ed->ke->dh_group)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("KE payload does not match selected group send "
                       "N(INVALID_KE_PAYLOAD)"));
      /** Send INVALID_KE_PAYLOAD error. */
      SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_invalid_ke);
    }
  else
    {
      /** Valid group, continue. */
      SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_nonce);
    }
  return SSH_FSM_CONTINUE;
}

/* Check the nonce. */
SSH_FSM_STEP(ikev2_state_init_responder_in_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_nat_t);
  ikev2_check_nonce(packet, &(packet->ed->ike_ed->ni));
  return SSH_FSM_CONTINUE;
}

/* Check the NAT-T notifies. */
SSH_FSM_STEP(ikev2_state_init_responder_in_nat_t)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_init_responder_in_end);
  ikev2_check_nat_detection(packet, FALSE);

  return SSH_FSM_CONTINUE;
}

/* Request cookie from the other end. */
SSH_FSM_STEP(ikev2_state_init_responder_in_request_cookie)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Request N(cookie). */
  /* SSH_FSM_SET_NEXT(ikev2_state_request_cookie_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_request_cookie_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Request N(COOKIE)"));
  return SSH_FSM_FINISH;
}

/* Send INVALID_KE_PAYLOAD error with proper group. */
SSH_FSM_STEP(ikev2_state_init_responder_in_invalid_ke)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Send N(INVALID_KE). */
  /* SSH_FSM_SET_NEXT(ikev2_state_ke_error_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_ke_error_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Send N(INVALID_KE_PAYLOAD)"));
  return SSH_FSM_FINISH;
}

/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_init_responder_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  ikev2_receive_window_register_request(
          packet->ike_sa->receive_window,
          packet);

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

  /** Send reply IKE_SA_INIT packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_init_responder_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_init_responder_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  ikev2_receive_window_insert_response(
          reply_packet->ike_sa->receive_window,
          reply_packet);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Send reply IKE_SA_INIT packet"));

  return SSH_FSM_FINISH;
}
