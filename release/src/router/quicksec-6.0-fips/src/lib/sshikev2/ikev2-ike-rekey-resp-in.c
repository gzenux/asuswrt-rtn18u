/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE CHILD rekey IKE SA responder in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateIkeRekeyRespIn"

/* Responder side CREATE CHILD packet in. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in_alloc_sa);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("State = REKEY_IKE"));
  packet->ed->state = SSH_IKEV2_STATE_REKEY_IKE;

  if (packet->ed->sa == NULL ||
      packet->ed->nonce == NULL ||
      packet->ed->ipsec_ed->ts_i != NULL ||
      packet->ed->ipsec_ed->ts_r != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Mandatory payloads (SAi,Ni) missing or "
                       "extra payloads"));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Mandatory payloads (SAi,Ni) missing or "
                  "extra payloads present");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

void ikev2_reply_cb_ike_rekey_resp_ike_sa_allocate(SshIkev2Error error_code,
                                                   SshIkev2Sa ike_sa,
                                                   void *context)
{
  SshIkev2Packet packet = context;

  packet->operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(packet->thread);
  ikev2_error(packet, error_code);
  if (error_code == SSH_IKEV2_ERROR_OK)
    SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("New IKE SA allocated successfully"));
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

      packet->ike_sa->rekey->responded_new_sa = ike_sa;
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

      ikev2_transmit_window_init(ike_sa->transmit_window);
      ikev2_receive_window_init(ike_sa->receive_window);

      ikev2_error(packet, error_code);
      SSH_IKEV2_IKE_SA_TAKE_REF(ike_sa);
      SSH_IKEV2_IKE_SA_TAKE_REF(packet->ike_sa->rekey->responded_new_sa);
    }
}

/* Allocate IPsec SA. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_alloc_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (ike_sa->rekey == NULL)
    {
      ike_sa->rekey = ssh_calloc(1, sizeof(*ike_sa->rekey));
      if (ike_sa->rekey == NULL)
        return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
    }

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in_sa);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ike_sa_allocate)
                     (ike_sa->server->sad_handle, FALSE,
                      ikev2_reply_cb_ike_rekey_resp_ike_sa_allocate, packet));
}

void
ikev2_reply_cb_ike_rekey_resp_select_ike_sa(SshIkev2Error error_code,
                                            int proposal_index,
                                            SshIkev2PayloadTransform
                                            selected_transforms
                                            [SSH_IKEV2_TRANSFORM_TYPE_MAX],
                                            void *context)
{
  SshIkev2Packet packet = context;

  if (!ikev2_select_sa_reply(packet, error_code,
                             selected_transforms,
                             packet->ed->ipsec_ed->ipsec_sa_transforms))
    return;
  packet->ed->sa->proposal_number = proposal_index + 1;
  ikev2_error(packet,
              ikev2_fill_in_algorithms(packet->ed->ipsec_ed->new_ike_sa,
                                       packet->ed->ipsec_ed->
                                       ipsec_sa_transforms));
  if (packet->ed->sa->spi_len != 8)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Initiators IKE SA spi size is not 8"));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_INVALID_SPI,
                  "Initiators IKE SA spi size is not 8");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  else
    {
      memcpy(packet->ed->ipsec_ed->new_ike_sa->ike_spi_i,
             packet->ed->sa->spis.ike_spi, 8);
    }
}

/* Do the SA payload processing, i.e. call to the policy
   manager spd select ike SA function. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_sa)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in_nonce);
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, select_ike_sa)
                     (ike_sa->server->sad_handle, packet->ed,
                      packet->ed->sa,
                      ikev2_reply_cb_ike_rekey_resp_select_ike_sa,
                      packet));
}

/* Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in_ke);
  ikev2_check_nonce(packet, &(packet->ed->ipsec_ed->ni));
  return SSH_FSM_CONTINUE;
}

/* Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_ke)
{
  SshIkev2Packet packet = thread_context;
  SshUInt16 ke_group, selected_group;

  ke_group = 0;
  selected_group = 0;

  if (packet->ed->ke != NULL)
    ke_group = packet->ed->ke->dh_group;

  if (packet->ed->ipsec_ed->
      ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H] != NULL)
    selected_group = packet->ed->ipsec_ed->
      ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_D_H]->id;

  if (ke_group != selected_group)
    {
      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
                      ("KE payload does not match selected group send "
                       "N(INVALID_KE_PAYLOAD)"));
      /** Send INVALID_KE_PAYLOAD error. */
      SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in_invalid_ke);
    }
  else
    {
      /** Valid group, continue. */
      SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_in_end);
    }
  packet->ed->ipsec_ed->group_number = ke_group;
  return SSH_FSM_CONTINUE;
}

/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  /** Send reply CREATE_CHILD_SA packet. */
  /* SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_responder_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_ike_rekey_responder_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  ikev2_receive_window_insert_response(
          reply_packet->ike_sa->receive_window,
          reply_packet);

  return SSH_FSM_FINISH;
}


/* Send INVALID_KE_PAYLOAD error with proper group. */
SSH_FSM_STEP(ikev2_state_ike_rekey_responder_in_invalid_ke)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Packet reply_packet;

  SSH_IKEV2_IKE_SA_FREE(packet->ike_sa->rekey->responded_new_sa);
  packet->ike_sa->rekey->responded_new_sa = NULL;
  if (packet->ike_sa->rekey->initiated_new_sa == NULL)
    {
      ssh_free(packet->ike_sa->rekey);
      packet->ike_sa->rekey = NULL;
    }

  /** Send N(INVALID_KE). */
  /* SSH_FSM_SET_NEXT(ikev2_state_reply_ke_error_out); */
  reply_packet =
    ikev2_reply_packet_allocate(packet, ikev2_state_reply_ke_error_out);
  if (reply_packet == NULL)
    return SSH_FSM_CONTINUE;

  ikev2_receive_window_insert_response(
          reply_packet->ike_sa->receive_window,
          reply_packet);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Send N(INVALID_KE_PAYLOAD)"));
  return SSH_FSM_FINISH;
}
