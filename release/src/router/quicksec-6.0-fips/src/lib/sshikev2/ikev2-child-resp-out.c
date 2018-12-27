/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE CHILD responder out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateChildRespOut"

/* Start CREATE_CHILD_SA state. */
SSH_FSM_STEP(ikev2_state_child_responder_out)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_sa);

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

/* Add SA payload. */
SSH_FSM_STEP(ikev2_state_child_responder_out_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadTransform trans;
  SshIkev2PayloadSA sa;
  SshIkev2Error err;
  int i;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_nonce);

  /* First update the next payload pointer of the previous payload. */
  ikev2_update_next_payload(packet, SSH_IKEV2_PAYLOAD_TYPE_SA);

  sa = ssh_ikev2_sa_allocate(ike_sa->server->sad_handle);
  if (sa == NULL)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);

  for(i = 0; i < SSH_IKEV2_TRANSFORM_TYPE_MAX; i++)
    {
      trans = packet->ed->ipsec_ed->ipsec_sa_transforms[i];
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
  sa->protocol_id[0] = packet->ed->ipsec_ed->ipsec_sa_protocol;;
  sa->proposal_number = packet->ed->ipsec_ed->sa->proposal_number;;

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

/* Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_child_responder_out_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_ke);

  ikev2_create_nonce_and_add(packet, &(packet->ed->ipsec_ed->nr));
  return SSH_FSM_CONTINUE;
}

/* Add KE payload. */
SSH_FSM_STEP(ikev2_state_child_responder_out_ke)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_ts);
  if (packet->ed->ipsec_ed->group_number == 0)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_add_ke(packet, packet->ed->ipsec_ed->group_number));
}

/* Add TSi/TSr payloads. */
SSH_FSM_STEP(ikev2_state_child_responder_out_ts)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_responder_notify_vid);

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

/* Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_child_responder_out_agree)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_install);
  if (packet->ed->ipsec_ed->group_number == 0)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_child_agree(packet));
}

void ikev2_reply_cb_child_responder_install(SshIkev2Error error_code,
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
SSH_FSM_STEP(ikev2_state_child_responder_out_install)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_install_done);

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_sa_install)
                     (ike_sa->server->sad_handle,
                      packet->ed,
                      ikev2_reply_cb_child_responder_install,
                      packet));
}

/* Call done callbacks. */
SSH_FSM_STEP(ikev2_state_child_responder_out_install_done)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Exchange finished."));
  SSH_FSM_SET_NEXT(ikev2_state_child_responder_out_encrypt);

  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
    (ike_sa->server->sad_handle, packet->ed, SSH_IKEV2_ERROR_OK);

  return SSH_FSM_CONTINUE;
}

/* Encrypt packet. */
SSH_FSM_STEP(ikev2_state_child_responder_out_encrypt)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error err;

  /* Send packet next. */
  SSH_FSM_SET_NEXT(ikev2_state_send);

  err = ikev2_encrypt_packet(packet, packet->ed->buffer);
  ssh_buffer_free(packet->ed->buffer);
  packet->ed->buffer = NULL;

  if (err == SSH_IKEV2_ERROR_OK)
    ikev2_debug_exchange_end(packet);

  /* This will call
     SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done) */
  ikev2_responder_exchange_done(packet);

  /* Then we destroy the exchange */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;
  return ikev2_error(packet, err);
}
