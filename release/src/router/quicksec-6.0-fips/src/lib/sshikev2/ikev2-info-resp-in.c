/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for INFORMATIONAL responder in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateInfoRespIn"

/* Responder side INFORMATIONAL packet in. */
SSH_FSM_STEP(ikev2_state_info_responder_in)
{
  SshIkev2Packet packet = thread_context;
#ifdef SSHDIST_IKE_MOBIKE
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadNotify notify;
#endif /* SSHDIST_IKE_MOBIKE */

  ikev2_debug_exchange_begin(packet);

  SSH_DEBUG(SSH_D_LOWSTART, ("State = INFORMATIONAL"));
  packet->ed->state = SSH_IKEV2_STATE_INFORMATIONAL;

#ifdef SSHDIST_IKE_MOBIKE
  /* Ignore MobIKE releated notifies with if a notify has previously
     been received with larger message id than in the current packet. */
  notify = packet->ed->notify;
  while (notify != NULL)
    {
      SshIkev2NotifyMessageType type = notify->notify_message_type;

         if (notify->spi_size == 0
             && notify->spi_data == NULL
             && notify->notification_size == 0
             && notify->notification_data == NULL)
           {
             if (type == SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES)
               {
                 if (ike_sa->max_update_address_mid > packet->message_id)
                   packet->ed->info_ed->flags |= SSH_IKEV2_INFO_EMPTY_RESPONSE;
                 else
                   ike_sa->max_update_address_mid = packet->message_id;
               }
             if (type == SSH_IKEV2_NOTIFY_ADDITIONAL_IP4_ADDRESS ||
                 type == SSH_IKEV2_NOTIFY_ADDITIONAL_IP6_ADDRESS ||
                 type == SSH_IKEV2_NOTIFY_NO_ADDITIONAL_ADDRESSES)
               {
                 if (ike_sa->max_additional_address_mid > packet->message_id)
                   packet->ed->info_ed->flags |= SSH_IKEV2_INFO_EMPTY_RESPONSE;
                 else
                  ike_sa->max_additional_address_mid = packet->message_id;
               }
           }
      notify = notify->next_notify;
   }
#endif /* SSHDIST_IKE_MOBIKE */

  if (packet->ed->info_ed->flags & SSH_IKEV2_INFO_EMPTY_RESPONSE)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Ignoring MobIKE related notify with "
                               "smaller message ID then seen previously"));
      SSH_FSM_SET_NEXT(ikev2_state_info_responder_in_end);
    }
  else
    {
      SSH_FSM_SET_NEXT(ikev2_state_info_responder_in_check_notify);
    }
  return SSH_FSM_CONTINUE;
}

/* Check for notify payloads */
SSH_FSM_STEP(ikev2_state_info_responder_in_check_notify)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_info_responder_in_check_delete);
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}


void ikev2_info_ipsec_spi_delete_received_cb(SshIkev2Error error_code,
                                             SshIkev2ProtocolIdentifiers
                                             protocol,
                                             int number_of_spis,
                                             SshUInt32 *spi_array,
                                             void *context)
{
  SshIkev2Packet packet = context;
  SshIkev2PayloadDelete del;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);

  if (error_code == SSH_IKEV2_ERROR_OK && number_of_spis != 0)
    {
      del = ssh_obstack_alloc(packet->ed->obstack, sizeof(*del));
      if (del == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating delete"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }

      del->protocol = protocol;
      del->spi_size = 4;
      del->number_of_spis = number_of_spis;
      del->spi.spi_array =
        (void *) ssh_obstack_memdup(packet->ed->obstack, spi_array,
                                    number_of_spis * sizeof(*spi_array));
      if (del->spi.spi_array == NULL)
        {
          SSH_IKEV2_DEBUG(SSH_D_ERROR,
                          ("Error: Out of memory allocating spi table"));
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }
      del->next_delete = packet->ed->info_ed->del;
      packet->ed->info_ed->del = del;
    }
}

/* Wait for timeout and then free the reference. */
void ikev2_free_ref_after_timeout(void *context)
{
  SshIkev2Sa ike_sa = context;
  /* Clear the flag that we are waiting in the timeout, so we we
     do not try to cancel the timeout and free the ref again
     when shutting down. */
  ike_sa->flags &= ~(SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED);
  SSH_DEBUG(SSH_D_LOWSTART, ("[%p/%p] Doing delete of IKE SA",
                             NULL, ike_sa));
  SSH_IKEV2_IKE_SA_FREE(ike_sa);
}

/* Check for delete payloads */
SSH_FSM_STEP(ikev2_state_info_responder_in_check_delete)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadDelete del;

  /* Do we have delete payloads. */
  del = packet->ed->delete_payloads;
  while (del != NULL)
    {
      packet->ed->delete_payloads = del->next_delete;
      if (del->spi_size == 4 &&
          (del->protocol == SSH_IKEV2_PROTOCOL_ID_AH ||
           del->protocol == SSH_IKEV2_PROTOCOL_ID_ESP))
        {
          SSH_FSM_ASYNC_CALL(
                             SSH_IKEV2_POLICY_CALL(packet, packet->ed->ike_sa,
                                                   ipsec_spi_delete_received)
                             (packet->ed->ike_sa->server->sad_handle,
                              packet->ed,
                              del->protocol, del->number_of_spis,
                              del->spi.spi_array,
                              ikev2_info_ipsec_spi_delete_received_cb,
                              packet));
        }
      /* protocol should be ID_IKE, ID_NONE is kept for backwards
         compatibility */
      else if (del->spi_size == 0 &&
               (del->protocol == SSH_IKEV2_PROTOCOL_ID_IKE ||
                del->protocol == SSH_IKEV2_PROTOCOL_ID_NONE) &&
               del->number_of_spis == 0)
        {
          SshTimeout timeout;
          /* Deleting this SA. We already have one reference
             for this packet, but we need to take new one as
             the delete callback will take one reference.
             The SA will then be deleted when the final
             reference to the SA goes away when we send this
             packet out. If the IKE SA is already deleted,
             then do nothing. */
          if (packet->ed->ike_sa->waiting_for_delete == NULL)
            {
              SSH_IKEV2_IKE_SA_TAKE_REF(packet->ed->ike_sa);
              /* We are not interested about the time when
                 the SA is actually deleted (i.e. the reply
                 cb) as it will happen only after this
                 exchange is finished. */
              SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, ike_sa_delete)
                (packet->ed->ike_sa->server->sad_handle,
                 packet->ed->ike_sa, NULL, NULL);
              /* We do not want to delete the SA immediately
                 after the we have sent reply back, as there
                 might be some retransmits coming in from
                 the other end, thus we keep an extra
                 reference it for 30 seconds and free it
                 after that. */
              timeout = ssh_register_timeout(NULL, IKEV2_SA_KEEP_TIME, 0,
                                             ikev2_free_ref_after_timeout,
                                             packet->ed->ike_sa);
              if (timeout != NULL)
                {
                  /* We managed to install timeout, take one
                     extra ref. */
                  SSH_IKEV2_IKE_SA_TAKE_REF(packet->ed->ike_sa);
                  SSH_IKEV2_DEBUG(SSH_D_LOWSTART,
                                  ("Postponing delete of IKE SA"));
                  packet->ed->ike_sa->flags |=
                    SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED;
                }
            }
        }
      else
        {
          SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                          ("Ignored invalid delete for protocol %s (%d), with "
                           "spi size of %d, and %d spis",
                           ssh_ikev2_protocol_to_string(del->protocol),
                           del->protocol, del->spi_size, del->number_of_spis));
        }

      del = packet->ed->delete_payloads;
    }
  SSH_FSM_SET_NEXT(ikev2_state_info_responder_in_check_nat);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_state_info_responder_in_check_nat)
{
#ifdef SSHDIST_IKE_MOBIKE
  SshIkev2Packet packet = thread_context;
  Boolean nat_t_enabled, nat_src, nat_dst;

  SSH_FSM_SET_NEXT(ikev2_state_info_responder_in_end);

  if (!(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED))
    return SSH_FSM_CONTINUE;

  /* Check if a NAT is detected between the endpoints used for this
     negotiation. */
  if (!ikev2_compute_nat_detection(packet, TRUE, &nat_t_enabled,
                                   &nat_src, &nat_dst))
    return SSH_FSM_CONTINUE;

  if (nat_t_enabled && nat_src)
    packet->ed->info_ed->remote_end_behind_nat = 1;
  if (nat_t_enabled && nat_dst)
    packet->ed->info_ed->local_end_behind_nat = 1;
#endif /* SSHDIST_IKE_MOBIKE */

  SSH_FSM_SET_NEXT(ikev2_state_info_responder_in_end);
  return SSH_FSM_CONTINUE;
}

/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_info_responder_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Send reply INFORMATIONAL packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_info_responder_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_info_responder_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  ikev2_receive_window_insert_response(
          reply_packet->ike_sa->receive_window,
          reply_packet);

  return SSH_FSM_FINISH;
}
