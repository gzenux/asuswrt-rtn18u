/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE CHILD IKE SA rekey responder out.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateIkeRekeyRespOut"

/* Start CREATE_CHILD_SA IKE SA rekey state. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_sa);

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
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2PayloadTransform trans;
  SshIkev2PayloadSA sa;
  SshIkev2Error err;
  int i;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_nonce);

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
  sa->protocol_id[0] = SSH_IKEV2_PROTOCOL_ID_IKE;
  sa->proposal_number = packet->ed->sa->proposal_number;
  memcpy(sa->spis.ike_spi, packet->ed->ipsec_ed->new_ike_sa->ike_spi_r, 8);
  sa->spi_len = 8;
  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Adding SAr2"));
  if (ikev2_encode_sa(packet, packet->ed->buffer, sa,
                      &packet->ed->next_payload_offset) == 0)
    {
      ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);
      return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }
  ssh_ikev2_sa_free(ike_sa->server->sad_handle, sa);
  ssh_ikev2_sa_free(packet->ike_sa->server->sad_handle, packet->ed->sa);
  packet->ed->sa = NULL;

  return SSH_FSM_CONTINUE;
}

/* Add NONCE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_ke);

  ikev2_create_nonce_and_add(packet, &(packet->ed->ipsec_ed->nr));
  if (memcmp(packet->ed->ipsec_ed->ni->nonce_data,
             packet->ed->ipsec_ed->nr->nonce_data,
             (packet->ed->ipsec_ed->ni->nonce_size <
              packet->ed->ipsec_ed->nr->nonce_size) ?
             packet->ed->ipsec_ed->ni->nonce_size :
             packet->ed->ipsec_ed->nr->nonce_size) < 0)
    {
      packet->ike_sa->rekey->responded_smaller_nonce =
        ssh_memdup(packet->ed->ipsec_ed->ni->nonce_data,
                   packet->ed->ipsec_ed->ni->nonce_size);
      packet->ike_sa->rekey->responded_smaller_nonce_len =
        packet->ed->ipsec_ed->ni->nonce_size;
    }
  else
    {
      packet->ike_sa->rekey->responded_smaller_nonce =
        ssh_memdup(packet->ed->ipsec_ed->nr->nonce_data,
                   packet->ed->ipsec_ed->nr->nonce_size);
      packet->ike_sa->rekey->responded_smaller_nonce_len =
        packet->ed->ipsec_ed->nr->nonce_size;
    }
  if (packet->ike_sa->rekey->responded_smaller_nonce == NULL)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}

/* Add KE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_ke)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_responder_notify_vid);
  if (packet->ed->ipsec_ed->group_number == 0)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_add_ke(packet, packet->ed->ipsec_ed->group_number));
}

/* Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_agree)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_install);
  if (packet->ed->ipsec_ed->group_number == 0)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_child_agree(packet));
}

void ikev2_reply_cb_ike_rekey_responder_rekey(SshIkev2Error error_code,
                                              void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);

  if (error_code == SSH_IKEV2_ERROR_OK)
    {
      packet->ed->ipsec_ed->new_ike_sa->flags |=
        SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE;
      ikev2_debug_ike_sa_rekey(
        packet->ed->ipsec_ed->new_ike_sa, packet->ike_sa);
      SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IKE SA rekeyed successfully"));
    }
  else
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IKE SA rekeyed failed: %d",
                                   error_code));
    }
}

/* Install IPsec SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_install)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (ikev2_calculate_rekey_skeyseed(packet->ed) != SSH_CRYPTO_OK)
    {
      return ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
    }

  /* Check for simultaneous rekeys. */
  if (ike_sa->rekey->initiated_smaller_nonce != NULL)
    {
      /* We have already done the IKE SA rekey as a
         initiator for the SA. */
      /* Check if which one is larger. */
      if (memcmp(ike_sa->rekey->initiated_smaller_nonce,
                 ike_sa->rekey->responded_smaller_nonce,
                 (ike_sa->rekey->initiated_smaller_nonce_len <
                  ike_sa->rekey->responded_smaller_nonce_len) ?
                 ike_sa->rekey->initiated_smaller_nonce_len :
                 ike_sa->rekey->responded_smaller_nonce_len) < 0)
        {
          /* This one is larger, so we won, so move them
             again. */
          /** Also move from old one. */
          SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_move_from_old);

          /* As we are the initiator of the loosing SA, we
             need to start delete on it. */
          SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa,
                                                   ike_sa_rekey)
                             (ike_sa->server->sad_handle,
                              TRUE, ike_sa->rekey->initiated_new_sa,
                              packet->ed->ipsec_ed->new_ike_sa,
                              ikev2_reply_cb_ike_rekey_responder_rekey,
                              packet));
          /*NOTREACHED*/
        }
      else
        {
          /** We lost, no need to move from old. */
          SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_encrypt);

          /* We lost here, so do not move this at all. As we
             are responder, the other end will delete this
             SA later. */
          return SSH_FSM_CONTINUE;
        }
    }
  /* Simply move from old one. */
  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_move_from_old);
  return SSH_FSM_CONTINUE;
}

/* Move from old IKE SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_move_from_old)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out_encrypt);

  /* Not a simultaneous rekey (or the initiator is not yet
     finished, move SAs, or we as a responder won).*/
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ike_sa_rekey)
                     (ike_sa->server->sad_handle,
                      FALSE, ike_sa, packet->ed->ipsec_ed->new_ike_sa,
                      ikev2_reply_cb_ike_rekey_responder_rekey,
                      packet));
}

/* Encrypt packet. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_out_encrypt)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;
  SshIkev2Error err;

  /* Send packet next. */
  SSH_FSM_SET_NEXT(ikev2_state_send);

  err = ikev2_encrypt_packet(packet, packet->ed->buffer);
  ssh_buffer_free(packet->ed->buffer);
  packet->ed->buffer = NULL;

  /* This will call
     SSH_IKEV2_POLICY_NOTIFY(packet->ed->ike_sa, responder_exchange_done) */
  ikev2_responder_exchange_done(packet);

  SSH_IKEV2_IKE_SA_FREE(packet->ed->ipsec_ed->new_ike_sa);
  packet->ed->ipsec_ed->new_ike_sa = NULL;
  /* Then we destroy the exchange */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;
  return ikev2_error(packet, err);
}
