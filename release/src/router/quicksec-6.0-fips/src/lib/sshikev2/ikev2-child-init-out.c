/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE_CHILD initiator out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateChildInitOut"

/* Start CREATE_CHILD state. */
SSH_FSM_STEP(ikev2_state_child_initiator_out)
{
  SshIkev2Packet packet = thread_context;

  ikev2_debug_exchange_begin(packet);

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_alloc_sa);

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

void
ikev2_reply_cb_child_initiator_ipsec_spi_allocate(SshIkev2Error error_code,
                                                  SshUInt32 spi,
                                                  void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IPsec SPI allocated successfully = %08lx",
                                  (unsigned long) spi));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IPsec SPI allocate failed: %d",
                                 error_code));
  packet->ed->ipsec_ed->spi_inbound = spi;
}

/* Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_alloc_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_fill_sa);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_spi_allocate)
                     (ike_sa->server->sad_handle, packet->ed,
                      ikev2_reply_cb_child_initiator_ipsec_spi_allocate,
                      packet));
}

void ikev2_reply_cb_child_initiator_fill_ipsec_sa(SshIkev2Error error_code,
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
SSH_FSM_STEP(ikev2_state_child_initiator_out_fill_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_rekey_n);
  SSH_FSM_ASYNC_CALL(
                     SSH_IKEV2_POLICY_CALL(packet, ike_sa, fill_ipsec_sa)
                     (ike_sa->server->sad_handle, packet->ed,
                      ikev2_reply_cb_child_initiator_fill_ipsec_sa,
                      packet));

}

/* Add optional rekey notify payload */
SSH_FSM_STEP(ikev2_state_child_initiator_out_rekey_n)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_sa);
  if (packet->ed->ipsec_ed->rekeyed_spi != 0)
    {
      SshIkev2PayloadNotifyStruct notify[1];
      unsigned char temp_buffer[4];

      /* NOTE: perhaps we should get the protocol id from the
         old IPsec SA instead of using the proposed
         protocol. */

      notify->protocol = packet->ed->ipsec_ed->sa_i->protocol_id[0];
      notify->notify_message_type = SSH_IKEV2_NOTIFY_REKEY_SA;
      notify->spi_size = 4;
      notify->spi_data = temp_buffer;
      notify->notification_size = 0;
      notify->notification_data = NULL;
      SSH_PUT_32BIT(temp_buffer, packet->ed->ipsec_ed->rekeyed_spi);

      /* First update the next payload pointer of the previous payload. */
      ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_NOTIFY);

      SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding N(REKEY_SA)"));
      if (ikev2_encode_notify(packet, packet->ed->buffer, notify,
                              &packet->ed->next_payload_offset) == 0)
        return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  return SSH_FSM_CONTINUE;
}

/* Add SA payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_nonce);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_SA);

  /* Add SA payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding SAi"));
  if (ikev2_encode_sa(packet, packet->ed->buffer, packet->ed->ipsec_ed->sa_i,
                      &packet->ed->next_payload_offset) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}

/* Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_ke);

  ikev2_create_nonce_and_add(packet, &(packet->ed->ipsec_ed->ni));
  return SSH_FSM_CONTINUE;
}

/* Add KE payload. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_ke)
{
  SshIkev2Packet packet = thread_context;
  SshUInt16 group = packet->ed->ike_sa->dh_group;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_out_ts);
  group = ikev2_find_policy_group(packet, packet->ed->ipsec_ed->sa_i, group);
  if (group == 0)
      return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_add_ke(packet, group));
}

/* Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_child_initiator_out_ts)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_TS_I);

  /* Add TSi payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding TSi"));
  if (ikev2_encode_ts(packet, packet->ed->buffer,
                      packet->ed->ipsec_ed->ts_local,
                      &packet->ed->next_payload_offset,
                      TRUE) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  /* Update the next payload pointer of that payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_TS_R);

  /* Add TSr payload. */
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding TSr"));
  if (ikev2_encode_ts(packet, packet->ed->buffer,
                      packet->ed->ipsec_ed->ts_remote,
                      &packet->ed->next_payload_offset,
                      FALSE) == 0)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}
