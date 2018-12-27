/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE_CHILD initiator out when rekeying IKE SA.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateIkeRekeyInitOut"

/* Start CREATE_CHILD state for IKE SA rekey. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_out_alloc_sa);

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
ikev2_reply_cb_ike_rekey_initiator_ike_sa_allocate(SshIkev2Error error_code,
                                                   SshIkev2Sa ike_sa,
                                                   void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("New IKE SA allocated successfully %p",
                                  ike_sa));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IKE SA allocate failed: %d",
                                 error_code));
  if (ike_sa)
    {
      /* The IKE SA rekey context may have been freed in the rare case
         where a simultaneous IKE SA rekey has failed while this thread
         was allocating the new IKE SA. */
      if (packet->ike_sa->rekey == NULL)
        {
          ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
          return;
        }

      packet->ike_sa->rekey->initiated_new_sa = ike_sa;
      packet->ed->ipsec_ed->new_ike_sa = ike_sa;
      ike_sa->server = packet->server;
      *(ike_sa->remote_ip) = *(packet->remote_ip);
      ike_sa->remote_port = packet->remote_port;
#ifdef SSHDIST_IKE_MOBIKE
      ike_sa->num_additional_ip_addresses =
        packet->ed->ike_sa->num_additional_ip_addresses;
      memcpy(ike_sa->additional_ip_addresses,
             packet->ed->ike_sa->additional_ip_addresses,
             sizeof(ike_sa->additional_ip_addresses));
#endif /* SSHDIST_IKE_MOBIKE */
      ike_sa->flags = packet->ed->ike_sa->flags;
      ike_sa->flags &= ~(SSH_IKEV2_IKE_SA_FLAGS_INITIATOR
                         | SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE
                         | SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED
                         | SSH_IKEV2_IKE_SA_FLAGS_ABORTED);
      ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;

      ikev2_transmit_window_init(ike_sa->transmit_window);
      ikev2_receive_window_init(ike_sa->receive_window);

      ikev2_error(packet, error_code);
      SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
      SSH_IKEV2_IKE_SA_TAKE_REF(packet->ike_sa->rekey->initiated_new_sa);
    }
}

/* Allocate new IKE SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_alloc_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_out_fill_sa);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ike_sa_allocate)
                     (ike_sa->server->sad_handle, TRUE,
                      ikev2_reply_cb_ike_rekey_initiator_ike_sa_allocate,
                      packet));
}

void ikev2_reply_cb_ike_rekey_initiator_fill_ike_sa(SshIkev2Error error_code,
                                                    SshIkev2PayloadSA sa,
                                                    void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);

  /* Set the error code if error. */
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("IKE SA filled successfully"));
  else
    SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IKE SA fill failed: %d",
                                 error_code));

  if (sa)
    {
      memcpy(sa->spis.ike_spi, packet->ed->ipsec_ed->new_ike_sa->ike_spi_i, 8);
      sa->spi_len = 8;
      packet->ed->ipsec_ed->sa_i = sa;
    }
}

/* Fill the SA payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_fill_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_out_sa);
  SSH_FSM_ASYNC_CALL(
                     SSH_IKEV2_POLICY_CALL(packet, ike_sa, fill_ike_sa)
                     (ike_sa->server->sad_handle, packet->ed,
                      ikev2_reply_cb_ike_rekey_initiator_fill_ike_sa,
                      packet));
}

/* Add SA payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_out_nonce);

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
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_out_ke);

  ikev2_create_nonce_and_add(packet, &(packet->ed->ipsec_ed->ni));
  return SSH_FSM_CONTINUE;
}

/* Add KE payload. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_out_ke)
{
  SshIkev2Packet packet = thread_context;
  SshUInt16 group = packet->ed->ike_sa->dh_group;

  SSH_FSM_SET_NEXT(ikev2_state_notify_vid_encrypt_send);
  group = ikev2_find_policy_group(packet, packet->ed->ipsec_ed->sa_i, group);
  if (group == 0)
      return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_add_ke(packet, group));
}
