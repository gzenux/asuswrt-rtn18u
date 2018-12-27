/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2State"

/* Start IKE state machine. This will assume that the thread
   in the SshIkev2Packet structure is initialized and
   working, and it can use that to run the state machine. In
   the end this will call the ikev2_udp_send and give the
   fsm thread to him. The packet receive state machine will
   simply return SSH_FSM_CONTINUE to the thread after this
   function returns.*/
void ikev2_state(SshIkev2Packet packet)
{
  ssh_fsm_set_next(packet->thread, ikev2_state_decode);
}

/* Set thread to error state, and store error code to the
   packet. Then return SSH_FSM_CONTINUE. So after this the
   packet processing will continue from error state and it
   will check whether we need to send error message or not. */
SshFSMStepStatus ikev2_error(SshIkev2Packet packet, SshIkev2Error error)
{
  if (error != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Moving to error state, error = %d",
                                       error));
      packet->error = error;
      ikev2_debug_exchange_fail_local(packet, error);
      ssh_fsm_set_next(packet->thread, ikev2_state_error);
    }
  return SSH_FSM_CONTINUE;
}

/* Just like ikev2_error() but the error was received from the IKE
   peer instead of being detected locally. */
SshFSMStepStatus ikev2_error_remote(SshIkev2Packet packet, SshIkev2Error error)
{
  if (error != SSH_IKEV2_ERROR_OK)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Moving to error state, error = %d",
                                       error));
      packet->error = error;
      ikev2_debug_exchange_fail_remote(packet, error);
      ssh_fsm_set_next(packet->thread, ikev2_state_error);
    }
  return SSH_FSM_CONTINUE;
}

/* If this is fatal error then set the thread to error
   state, otherwise store the error code to the ipsec_ed so
   that we will be sending the error notify afterwords. */
SshFSMStepStatus ikev2_ipsec_error(SshIkev2Packet packet,
                                   SshIkev2Error error)
{
  int error_code = error;

  if (error_code != SSH_IKEV2_ERROR_OK)
    {
      if (error_code == SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN ||
          error_code == SSH_IKEV2_ERROR_TS_UNACCEPTABLE ||
          error_code == SSH_IKEV2_ERROR_INTERNAL_ADDRESS_FAILURE ||
          error_code == SSH_IKEV2_ERROR_TEMPORARY_FAILURE ||
          error_code == SSH_IKEV2_ERROR_CHILD_SA_NOT_FOUND ||
          error_code == SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED ||
          error_code == SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED ||
          error_code == SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS)
        {
          ikev2_debug_exchange_fail_local(packet, error_code);
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("IPsec error = %d", error_code));
          packet->ed->ipsec_ed->error = error_code;
        }
      else
        return ikev2_error(packet, error_code);
    }
  return SSH_FSM_CONTINUE;
}

/* Restart the packet state machine. */
void ikev2_restart_packet(SshIkev2Packet packet)
{
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Restarting packet"));
  SSH_ASSERT(ike_sa->initial_ed->packet_to_process == packet);
  ike_sa->initial_ed->packet_to_process = NULL;

  /* Assert that the packet thread has been started, not yet destroyed
     and not waiting for asynch call completion. */
  SSH_ASSERT(packet->thread_started);
  SSH_ASSERT(!packet->destroyed);
  SSH_ASSERT(!ssh_fsm_get_callback_flag(packet->thread));
  ssh_fsm_continue(packet->thread);
}

/* Do cleanup on error. */
void ikev2_do_cleanup(SshIkev2Packet packet, SshIkev2Sa ike_sa,
                      SshIkev2ExchangeData ed, Boolean timeout)
{







  if (ike_sa->initial_ed != NULL
      || (ed && ed->ipsec_ed && (ed->state == SSH_IKEV2_STATE_REKEY_IKE)))
    {
      if (ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          ike_sa->server->statistics->total_init_failures++;
          if (timeout &&
              ike_sa->initial_ed != NULL &&
              ike_sa->initial_ed->state == SSH_IKEV2_STATE_IKE_INIT_SA)
            {
              ike_sa->server->statistics->total_init_no_response++;
            }
        }
      else
        {
          ike_sa->server->statistics->total_resp_failures++;
        }
      /* OK added to the ikev2_state_error. */
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_done)
        (ike_sa->server->sad_handle, ed, packet->error);
    }

  if (ed && ed->ipsec_ed && (ed->state != SSH_IKEV2_STATE_REKEY_IKE))
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("Calling IPsec SA done callback with error"));
      /* OK added to the ikev2_state_error. */
      SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
        (ike_sa->server->sad_handle, ed, packet->error);

      if (ed->ipsec_ed->spi_inbound != 0)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing up IPsec SPI"));
          /* OK added to the ikev2_state_error. */
          SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_spi_delete)
            (ike_sa->server->sad_handle, ed->ipsec_ed->spi_inbound);
          ed->ipsec_ed->spi_inbound = 0;
        }
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Calling finished callback"));
  if (ed && ed->callback)
    {
      (*(ed->callback))(ike_sa->server->sad_handle, ike_sa, ed, packet->error);
      ed->callback = NULL_FNPTR;
    }

  /* If IKE SA rekey failed free reference to the new IKE SA. */
  if (ed && ed->ipsec_ed && (ed->state == SSH_IKEV2_STATE_REKEY_IKE)
      && ike_sa->rekey != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Cleaning up IKE SA rekey context"));

      /* This end is the responder for the IKE SA rekey. */
      if ((packet->received
           && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0)
          || (!packet->received
              && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0))
        {
          if (ike_sa->rekey->responded_new_sa != NULL)
            SSH_IKEV2_IKE_SA_FREE(ike_sa->rekey->responded_new_sa);
          ike_sa->rekey->responded_new_sa = NULL;
          ssh_free(ike_sa->rekey->responded_smaller_nonce);
          ike_sa->rekey->responded_smaller_nonce = NULL;
          ike_sa->rekey->responded_smaller_nonce_len = 0;
        }

      /* This end is the initiator for the IKE SA rekey. */
      else
        {
          if (ike_sa->rekey->initiated_new_sa != NULL)
            SSH_IKEV2_IKE_SA_FREE(ike_sa->rekey->initiated_new_sa);
          ike_sa->rekey->initiated_new_sa = NULL;
          ssh_free(ike_sa->rekey->initiated_smaller_nonce);
          ike_sa->rekey->initiated_smaller_nonce = NULL;
          ike_sa->rekey->initiated_smaller_nonce_len = 0;
        }

      /* Free IKE SA rekey structure if there are no other users for it. */
      if (ike_sa->rekey->initiated_new_sa == NULL
          && ike_sa->rekey->responded_new_sa == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing IKE SA rekey context"));
          ssh_free(ike_sa->rekey->initiated_smaller_nonce);
          ssh_free(ike_sa->rekey->responded_smaller_nonce);
          ssh_free(ike_sa->rekey);
          ike_sa->rekey = NULL;
        }
    }

  if (ed && ed->ipsec_ed &&
      (ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_OPERATION_REGISTERED))
    {
      ssh_operation_unregister_no_free(ed->ipsec_ed->operation_handle);
      ed->ipsec_ed->flags &= ~SSH_IKEV2_IPSEC_OPERATION_REGISTERED;

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing reference"));

      /* Free ED reference (from the operation handle). If this is an initial
         exchange, then the ED we are freeing is in ike_sa->initial_ed, which
         must therefore be cleared. */
      if (ike_sa->initial_ed == ed)
        ike_sa->initial_ed = NULL;
      ikev2_free_exchange_data(ike_sa, ed);
      ed = NULL;

      /* Free the IKE SA reference (from the operation handle). */
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
    }

  if (ed && ed->info_ed &&
      (ed->info_ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED))
    {
      ssh_operation_unregister_no_free(ed->info_ed->operation_handle);
      ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing reference"));

      /* Free ED reference (from the operation handle). */
      ikev2_free_exchange_data(ike_sa, ed);

      /* Free IKE SA reference (from the operation handle). */
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
    }
}

/* Do delete on error. */
void ikev2_do_error_delete(SshIkev2Packet packet, SshIkev2Sa ike_sa)
{
  /* We need to stop the retransmissions. */
  ikev2_transmit_window_flush(ike_sa->transmit_window);

  /* We need to set packet->ike_sa to null, so we do not do
     anything to the ike_sa when freeing the packet. Note,
     that packet has one reference to the ike_sa, but the
     ike_sa_delete consumes one reference, so we steal the
     reference from the packet, and give it to the
     ike_sa_delete. */
  packet->ike_sa = NULL;
  if (ike_sa->waiting_for_delete)
    {
      /* This SA has already been deleted, so we are simply
         waiting for the ACK and we got error while
         processing that. Simply free one reference from the
         SA, so that will cause the SA to be deleted. */
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Already deleted freeing"));
      SSH_IKEV2_IKE_SA_FREE(ike_sa);
      return;
    }
  /* If this fails, there is not really much we can do.
     Ignore the error messages now. */
  /* OK added to the ikev2_state_error. */
  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete)
    (ike_sa->server->sad_handle, ike_sa, NULL, NULL);
}

/* Transmit error state. */
void ikev2_xmit_error(SshIkev2Packet packet, SshIkev2Error error)
{
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2ExchangeData ed;

  ed = packet->ed;
  if (ed == NULL)
    ed = ike_sa->initial_ed;

  SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Transmit error"));

  packet->error = error;

  if (error == SSH_IKEV2_ERROR_TIMEOUT)
    ikev2_debug_exchange_fail_local(packet, error);
  else
    ikev2_debug_exchange_fail_remote(packet, error);

  ikev2_do_cleanup(packet, ike_sa, ed, TRUE);

  if (ed)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing exchange data"));
      /* Then we destroy the exchange data */
      ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
      ike_sa->initial_ed = NULL;
      ikev2_free_exchange_data(ike_sa, packet->ed);
      packet->ed = NULL;
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Exchange failed after timeout"));
  ikev2_do_error_delete(packet, ike_sa);
}

void ikev2_responder_exchange_done(SshIkev2Packet packet)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Responder exchange done"));
  SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done)
    (packet->ed->ike_sa->server->sad_handle, packet->error, packet->ed);
}

/* Error processing state. */
SSH_FSM_STEP(ikev2_state_error)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2ExchangeData ed;
  int error = packet->error;

  ed = packet->ed;
  if (ed == NULL)
    ed = ike_sa->initial_ed;

  SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Negotiation failed because of error %s (%d)",
                               ssh_ikev2_error_to_string(error),
                               error));

  if (error == SSH_IKEV2_ERROR_DISCARD_PACKET)
    {
      /* Discard this packet - this case catches the forged packet to
         existing SA (e.g. packet authentication failures) */
      return SSH_FSM_FINISH;
    }

  /* This might call
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_done)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_spi_delete) */
  ikev2_do_cleanup(packet, ike_sa, ed, FALSE);

  if ((packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
      && ((packet->received
           && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0)
          ||
          (!packet->received
           && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0)))
    {
      /* Ok, IKE SA is active and this is request, so we can
         really send error message back instead of deleting
         the IKE SA. */
      /* Check if this is non-fatal error message. If this
         is fatal error, then do not send notification back,
         as we want the IKE SA to be deleted. */
      /* NOTE: UNSUPPORTED_CRITICAL_PAYLOAD requires special
         handling as it has 1 byte of data. */
      /* packet->error == SSH_IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD || */
      if (error == SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN ||
          error == SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED ||
          error == SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS ||
          error == SSH_IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE ||
          error == SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED ||
          error == SSH_IKEV2_NOTIFY_TS_UNACCEPTABLE ||
          error == SSH_IKEV2_NOTIFY_UNACCEPTABLE_ADDRESS ||
          error == SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED ||
          error == SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE ||
          error == SSH_IKEV2_NOTIFY_CHILD_SA_NOT_FOUND)
        {
          SshIkev2Packet reply_packet;

          if (packet->ed)
            {
     /* This will call
        SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done) */
              ikev2_responder_exchange_done(packet);
            }

          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Send N(%s) error notify as a response",
                           ssh_ikev2_notify_to_string(error)));
          /** Send reply error notify packet. */
          /* SSH_FSM_SET_NEXT(ikev2_state_send_error); */
          reply_packet =
            ikev2_reply_packet_allocate(packet, ikev2_state_send_error);
          if (reply_packet != NULL)
            {
              reply_packet->error = error;

              ikev2_receive_window_insert_response(
                      reply_packet->ike_sa->receive_window,
                      reply_packet);

              return SSH_FSM_FINISH;
            }
        }
    }

  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
      && (ed != NULL)
      && (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
      && ((packet->received
           && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0)
          ||
          (!packet->received
           && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0)))
    {
      /* For non-established IKE SA's, send back an unauthenticated
         encrypted notification to the peer if the error code is any
         of those below.  The half open SA timer (in policy mananger)
         will take of deleting the IKE SA. */
      if (error == SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN ||
          error == SSH_IKEV2_NOTIFY_AUTHENTICATION_FAILED ||
          error == SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED ||
          error == SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED ||
          error == SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE)
        {
          SshIkev2Packet reply_packet;

          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Send N(%s) unauthenticated error notify "
                           "as a response",
                           ssh_ikev2_notify_to_string(error)));

          /** Send unauthenticated reply error notify packet. */
          /* SSH_FSM_SET_NEXT(ikev2_state_send_error); */
          reply_packet =
            ikev2_reply_packet_allocate(packet, ikev2_state_send_error);
          if (reply_packet != NULL)
            {
              reply_packet->error = error;

              ikev2_receive_window_insert_response(
                      reply_packet->ike_sa->receive_window,
                      reply_packet);

              return SSH_FSM_FINISH;
            }
        }
    }

  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
      && (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
      && ((packet->received
           && (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) == 0)))
    {
      if (error == SSH_IKEV2_NOTIFY_INVALID_MAJOR_VERSION)
        {
          SshIkev2Packet reply_packet;

          SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                          ("Send N(%s) plaintext error notify as a response",
                           ssh_ikev2_notify_to_string(error)));

          /** Send unprotected reply error notify packet. */
          /* SSH_FSM_SET_NEXT(ikev2_state_send_error); */
          reply_packet =
            ikev2_reply_packet_allocate(packet,
                                        ikev2_state_send_unprotected_error);
          if (reply_packet != NULL)
            {
              reply_packet->error = error;
              /* Note that the error response is not inserted to the receive
                 window because the violating SA_INIT request has not been
                 inserted to the receive window because invalid major version
                 is detected during IKE header decoding. */
              return SSH_FSM_FINISH;
            }
        }
    }

  if (ed)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing exchange data"));
      /* Then we destroy the IKE SA exchange data */
      ikev2_free_exchange_data(ike_sa, ike_sa->initial_ed);
      ike_sa->initial_ed = NULL;
      ikev2_free_exchange_data(ike_sa, packet->ed);
      packet->ed = NULL;
    }

  if ((packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
      && packet->error_from_notify
      && (error == SSH_IKEV2_NOTIFY_INVALID_KE_PAYLOAD ||
          error == SSH_IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN ||
          error == SSH_IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED ||
          error == SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS ||
          error == SSH_IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE ||
          error == SSH_IKEV2_NOTIFY_FAILED_CP_REQUIRED ||
          error == SSH_IKEV2_NOTIFY_TS_UNACCEPTABLE ||
          error == SSH_IKEV2_NOTIFY_UNACCEPTABLE_ADDRESS ||
          error == SSH_IKEV2_NOTIFY_UNEXPECTED_NAT_DETECTED ||
          error == SSH_IKEV2_NOTIFY_TEMPORARY_FAILURE ||
          error == SSH_IKEV2_NOTIFY_CHILD_SA_NOT_FOUND))
    {
      /* This is non fatal error, so simply finish this
         exchange. */
      SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                      ("Received N(%s) error notify",
                       ssh_ikev2_notify_to_string(error)));
      return SSH_FSM_FINISH;
    }

#ifdef SSHDIST_IKEV1
  if (error == SSH_IKEV2_ERROR_USE_IKEV1)
    {
      SSH_FSM_SET_NEXT(ikev2_packet_v1_start);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IKEV1 */

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Fatal error %s, delete IKE SA",
                   ssh_ikev2_notify_to_string(error)));

  /* This might call
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, ike_sa_delete) */
  ikev2_do_error_delete(packet, ike_sa);
  return SSH_FSM_FINISH;
}

/* Send error notify. */
SSH_FSM_STEP(ikev2_state_send_error)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];
  SshIkev2Error err;
  SshBuffer buffer;
  size_t len;
  SshIkev2PayloadNotify recv_notify;
  unsigned char spi_buf[4];

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  notify->protocol = 0;
  notify->notify_message_type = (int) packet->error;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 0;
  notify->notification_data = NULL;

  /* RFC5996, 2.25:
     "A CHILD_SA_NOT_FOUND notification SHOULD be sent when a peer receives
     a request to rekey a Child SA that does not exist.  The SA that the
     initiator attempted to rekey is indicated by the SPI field in the
     Notify payload, which is copied from the SPI field in the REKEY_SA
     notification." */
  if (packet->error == SSH_IKEV2_ERROR_CHILD_SA_NOT_FOUND)
    {
      /* Lookup up the received REKEY_SA notify payload and copy SPI
         protocol ID and value to the CHILD_SA_NOT_FOUND error notify. */
      for (recv_notify = packet->ed->notify;
           recv_notify != NULL;
           recv_notify = recv_notify->next_notify)
        {
          if (recv_notify->notify_message_type == SSH_IKEV2_NOTIFY_REKEY_SA
              && recv_notify->spi_size == 4
              && recv_notify->spi_data != NULL)
            {
              notify->protocol = recv_notify->protocol;
              notify->spi_size = 4;
              notify->spi_data = spi_buf;
              memcpy(notify->spi_data, recv_notify->spi_data, 4);
              break;
            }
        }
    }

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Adding N(%s) error notify",
                   ssh_ikev2_notify_to_string((int) packet->error)));
  len = ikev2_encode_notify(packet, buffer, notify, NULL);
  if (len == 0)
    {
      ssh_buffer_free(buffer);
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NOTIFY;

  err = ikev2_encrypt_packet(packet, buffer);
  ssh_buffer_free(buffer);
  SSH_FSM_SET_NEXT(ikev2_state_send);
  /* Then we destroy the exchange */
  ikev2_free_exchange_data(packet->ed->ike_sa, packet->ed);
  packet->ed = NULL;
  return ikev2_error(packet, err);
}

SSH_FSM_STEP(ikev2_state_send_unprotected_error)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadNotifyStruct notify[1];
  SshIkev2Error err;
  SshBuffer buffer;
  size_t len;

  buffer = ssh_buffer_allocate();
  if (buffer == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR,
                      ("Error: Out of memory allocating buffer"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  notify->protocol = SSH_IKEV2_PROTOCOL_ID_NONE;
  notify->notify_message_type = (int) packet->error;
  notify->spi_size = 0;
  notify->spi_data = NULL;
  notify->notification_size = 0;
  notify->notification_data = NULL;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                  ("Adding N(%s) error notify",
                   ssh_ikev2_notify_to_string((int) packet->error)));
  len = ikev2_encode_notify(packet, buffer, notify, NULL);
  if (len == 0)
    {
      ssh_buffer_free(buffer);
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NOTIFY;

  if (packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
    {
      memset(packet->ike_spi_r, 0, 8);
    }

  err = ikev2_encode_header(packet, buffer);
  ssh_buffer_free(buffer);

  SSH_FSM_SET_NEXT(ikev2_state_send);
  return ikev2_error(packet, err);
}

/* Decode packet. */
SSH_FSM_STEP(ikev2_state_decode)
{
  SshIkev2Packet packet = thread_context;
  SshFSMStepStatus status;

  SSH_FSM_SET_NEXT(ikev2_state_dispatch);
  /** Called during packet decode */
  /* SSH_IKEV2_POLICY_NOTIFY(ike_sa, new_certificate)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, new_certificate_request)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, notify_received)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, vendor_id)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, conf_received)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, eap_received)
     SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_update) */
  status = ikev2_decode_packet(packet);
  if (status == SSH_FSM_SUSPENDED)
    {
      /* We are suspending ourselves, so we need to set the next
         state to be back to ourself, so we will be rerunning
         this code next time. */
      /** Async operation started, retry. */
      SSH_FSM_SET_NEXT(ikev2_state_decode);
    }
  return status;
}

/* Dispatch where to go next. */
SSH_FSM_STEP(ikev2_state_dispatch)
{
  SshIkev2Packet packet = thread_context;
  Boolean process_packet;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Dispatching packet"));

  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_ABORTED)
    {
      SSH_IKEV2_DEBUG(SSH_D_UNCOMMON,
                      ("Dispatching packet, but IKE SA is already aborted"));
      return SSH_FSM_FINISH;
    }

  packet->ike_sa->last_input_packet_time = ssh_time();

  if (packet->message_id == 0 &&
      packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_SA_INIT)
    {
      /* This is IKE_SA_INIT exchange, check who is initiator. */
      if ((packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR))
        {
          /* They are initiator, so this must be their first packet. */
          if (!(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))
            {
              /** Initiator's IKE_SA_INIT packet. */
              SSH_FSM_SET_NEXT(ikev2_state_init_responder_in);
              SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Responder side IKE_SA_INIT"));
              return SSH_FSM_CONTINUE;
            }
        }
      else
        {
          /* They are responder, so this must be their first response to your
             request. */
          if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
            {
              /** Responder's reply to our IKE_SA_INIT packet. */
              SSH_FSM_SET_NEXT(ikev2_state_init_initiator_in);
              SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Initiator side IKE_SA_INIT"));
              return SSH_FSM_CONTINUE;
            }
        }

      goto error;
    }

  /* INIT requests and responses are acked or registered to windows
     later in processing. */

  /* quick duplicate packets can get this far */
  if ((packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE) != 0)
    {
      process_packet =
          ikev2_transmit_window_acknowledge(
                  packet->ike_sa->transmit_window,
                  packet->message_id);
      if (process_packet == TRUE)
        {
          /* If we continue to process the response packet we need
             back pointer from ed in case policy manager decides to
             abort the exchange. */
          packet->ed->response_packet = packet;
        }
    }
  else
    {
      process_packet =
          ikev2_receive_window_register_request(
                  packet->ike_sa->receive_window,
                  packet);
    }

  if (process_packet == FALSE)
    {
      return SSH_FSM_FINISH;
    }

  if (packet->message_id > 0 &&
           packet->exchange_type == SSH_IKEV2_EXCH_TYPE_IKE_AUTH)
    {
      /* This is IKE_AUTH exchange, check who is initiator. */
      if ((packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR))
        {
          /* They are initiator, so this must be their second packet. */
          if (!(packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE))
            {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
              if (packet->ed->ike_ed->first_auth_done &&
                  packet->ed->ike_ed->resp_require_another_auth)
                {
                  /** Initiator's second IKE_AUTH packet. */
                  SSH_FSM_SET_NEXT(ikev2_state_second_auth_responder_in);
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Responder side second "
                                                "IKE_AUTH"));
                  return SSH_FSM_CONTINUE;
                }
              else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                {
                  /** Initiator's IKE_AUTH packet. */
                  SSH_FSM_SET_NEXT(ikev2_state_auth_responder_in);
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Responder side IKE_AUTH"));
                  return SSH_FSM_CONTINUE;
                }
            }
        }
      else
        {
          /* They are responder, so this must be their first response to our
             request. */
          if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
            {
#ifdef SSH_IKEV2_MULTIPLE_AUTH
              if (packet->ed->ike_ed->first_auth_done)
                {
                  /** Initiator's second IKE_AUTH packet. */
                  SSH_FSM_SET_NEXT(ikev2_state_second_auth_initiator_in);
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Initiator side second "
                                                "IKE_AUTH"));
                  return SSH_FSM_CONTINUE;
                }
              else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                {
                  /** Responder's reply to our IKE_AUTH packet. */
                  SSH_FSM_SET_NEXT(ikev2_state_auth_initiator_in);
                  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Initiator side IKE_AUTH"));
                  return SSH_FSM_CONTINUE;
                }
            }
        }
    }
  else if ((packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
           packet->exchange_type == SSH_IKEV2_EXCH_TYPE_CREATE_CHILD_SA)
    {
      /* This is CREATE_CHILD_SA exchange, check if this is
         request or response. */
      if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        {
          if (packet->ed->state == SSH_IKEV2_STATE_REKEY_IKE)
            {
              /** Responder's reply to our CREATE_CHILD_SA rekey IKE SA. */
              SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in);
              SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                              ("Initiator side CREATE_CHILD_SA rekey "
                               "IKE SA"));
              return SSH_FSM_CONTINUE;
            }
          /** Responder's reply to our CREATE_CHILD_SA packet. */
          SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in);
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Initiator side CREATE_CHILD_SA"));
          return SSH_FSM_CONTINUE;
        }
      else
        {
          if (packet->ed->ipsec_ed->ts_i == NULL)
            {
              /** Initiator's CREATE_CHILD_SA rekey IKE SA packet. */
              SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in);
              SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                              ("Responder side CREATE_CHILD_SA "
                               "rekey IKE SA"));
              return SSH_FSM_CONTINUE;
            }
          /** Initiator's CREATE_CHILD_SA packet. */
          SSH_FSM_SET_NEXT(ikev2_state_child_responder_in);
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Responder side CREATE_CHILD_SA"));
          return SSH_FSM_CONTINUE;
        }
    }
  else if ((packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
           packet->exchange_type == SSH_IKEV2_EXCH_TYPE_INFORMATIONAL)
    {
      /* This is INFORMATIONAL exchange, check if this is
         request or response. */
      if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        {
          /** Responder's reply to our INFORMATIONAL packet. */
          SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in);
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Initiator side INFORMATIONAL"));
          return SSH_FSM_CONTINUE;
        }
      else
        {
          /** Initiator's INFORMATIONAL packet. */
          SSH_FSM_SET_NEXT(ikev2_state_info_responder_in);
          SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Responder side INFORMATIONAL"));
          return SSH_FSM_CONTINUE;
        }
    }

 error:
  /* Unknown exchange, send error. */
  SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Invalid message 0x%08lx exchange type = %d",
                               (unsigned long) packet->message_id,
                               packet->exchange_type));
  return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
}

/* Add notifies and vendor IDs. */
SSH_FSM_STEP(ikev2_state_responder_notify_vid)
{
  SSH_FSM_SET_NEXT(ikev2_state_responder_notify);
  return SSH_FSM_CONTINUE;
}

/* Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_responder_notify)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_responder_vid);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, notify_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_notify(packet));
}

/* Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_responder_vid)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_responder_notify_vid_continue);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, vendor_id_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_vid(packet));
}

/* Continue negotiation thread. */
SSH_FSM_STEP(ikev2_state_responder_notify_vid_continue)
{
  SshIkev2Packet packet = thread_context;

  SSH_ASSERT(packet->ed->state == SSH_IKEV2_STATE_CREATE_CHILD
             || packet->ed->state == SSH_IKEV2_STATE_REKEY_IKE
             || packet->ed->state == SSH_IKEV2_STATE_INFORMATIONAL
             || packet->ed->state == SSH_IKEV2_STATE_INFORMATIONAL_DELETING);

  switch (packet->ed->state)
    {
    case SSH_IKEV2_STATE_CREATE_CHILD:
      /** CHILD */
      SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_agree);
      break;

    case SSH_IKEV2_STATE_REKEY_IKE:
      /** IKE REKEY */
      SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_agree);
      break;

    case SSH_IKEV2_STATE_INFORMATIONAL:
    case SSH_IKEV2_STATE_INFORMATIONAL_DELETING:
      /** INFORMATIONAL */
      SSH_FSM_SET_NEXT(ikev2_state_info_responder_out_encrypt);
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  return SSH_FSM_CONTINUE;
}

/* Add notifies, vendor IDs, do encryption and send. */
SSH_FSM_STEP(ikev2_state_notify_vid_encrypt_send)
{
  SSH_FSM_SET_NEXT(ikev2_state_notify);
  return SSH_FSM_CONTINUE;
}

/* Request Notify payloads and add them. */
SSH_FSM_STEP(ikev2_state_notify)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_vid);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, notify_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_notify(packet));
}

/* Request vendor ID payloads and add them. */
SSH_FSM_STEP(ikev2_state_vid)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_encrypt);

  /*  This will call
      SSH_IKEV2_POLICY_CALL(packet, ike_sa, vendor_id_request) */
  SSH_FSM_ASYNC_CALL(ikev2_add_vid(packet));
}

/* Encrypt packet. */
SSH_FSM_STEP(ikev2_state_encrypt)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Error err;

  /* Send packet next. */
  SSH_FSM_SET_NEXT(ikev2_state_send);

  err = ikev2_encrypt_packet(packet, packet->ed->buffer);
  ssh_buffer_free(packet->ed->buffer);
  packet->ed->buffer = NULL;
  return ikev2_error(packet, err);
}


/* Send message. Note that the send function will steal the
   thread and packet, so we do not need to do anything for
   the thread or the packet. */
SSH_FSM_STEP(ikev2_state_send)
{
  SshIkev2Packet packet = thread_context;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Sending packet"));

  ikev2_udp_send(packet->ike_sa, packet);
  return SSH_FSM_CONTINUE;
}

/* Allocates reply packet, and copies all necessarely fields
   to it. Returns NULL in case of error, and in that case
   also sets the next state to be error. */
SshIkev2Packet ikev2_reply_packet_allocate(SshIkev2Packet packet,
                                           SshFSMStepCB first_state)
{
  SshIkev2Packet reply_packet;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Allocating reply packet"));

  reply_packet = ikev2_packet_allocate(packet->ike_sa->server->context,
                                       first_state);
  /* Check we succeded, if not we simply drop the packet. */
  if (reply_packet != NULL)
    {
      memcpy(reply_packet->ike_spi_i, packet->ike_spi_i, 8);
      memcpy(reply_packet->ike_spi_r, packet->ike_spi_r, 8);
      reply_packet->first_payload = SSH_IKEV2_PAYLOAD_TYPE_NONE;
      reply_packet->major_version = 2;
      reply_packet->minor_version = 0;
      reply_packet->exchange_type = packet->exchange_type;
      if (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE)
        {
          /* Already response packet. */
          reply_packet->flags =
            packet->flags &
            (SSH_IKEV2_PACKET_FLAG_RESPONSE | SSH_IKEV2_PACKET_FLAG_INITIATOR);
        }
      else
        {
          if (packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR)
            reply_packet->flags = SSH_IKEV2_PACKET_FLAG_RESPONSE;
          else
            reply_packet->flags = SSH_IKEV2_PACKET_FLAG_INITIATOR |
              SSH_IKEV2_PACKET_FLAG_RESPONSE;
        }
      reply_packet->message_id = packet->message_id;
      reply_packet->encoded_packet_len = 0;
      reply_packet->encoded_packet = NULL;
      *(reply_packet->remote_ip) = *(packet->remote_ip);
      reply_packet->remote_port = packet->remote_port;
      reply_packet->server = packet->server;
      reply_packet->use_natt = packet->use_natt;
      /* Steal the reference to the IKE SA */
      reply_packet->ike_sa = packet->ike_sa;
      packet->ike_sa = NULL;

      if (packet->ed && packet->ed->response_packet == packet)
        {
          packet->ed->response_packet = NULL;
        }

      /* steal reference */
      reply_packet->ed = packet->ed;
      packet->ed = NULL;
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Allocated reply packet"));
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_ERROR, ("Error: packet allocate failed"));
      ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
  return reply_packet;
}
