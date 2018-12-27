/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE CHILD IKE SA rekey initiator in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateIkeRekeyInitIn"

/* Initiator side CREATE_CHILD_SA packet in. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_sa);

  if (packet->ed->sa == NULL ||
      packet->ed->nonce == NULL ||
      packet->ed->ipsec_ed->ts_i != NULL ||
      packet->ed->ipsec_ed->ts_r != NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Mandatory payloads (SAr,Ni) missing or "
                       "extra payloads"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Mandatory payloads (SAr,Ni) missing");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  ikev2_process_notify(packet);

  if (packet->error == SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN
      || packet->error == SSH_IKEV2_ERROR_INVALID_KE_PAYLOAD)
    {
      /* We need to clear out the rekeying structure if this
         was only the initiator rekey case, so that retry of
         the rekey will work. */
      SSH_IKEV2_IKE_SA_FREE(packet->ike_sa->rekey->initiated_new_sa);
      packet->ike_sa->rekey->initiated_new_sa = NULL;

      if (packet->ike_sa->rekey->responded_new_sa == NULL)
        {
          ssh_free(packet->ike_sa->rekey);
          packet->ike_sa->rekey = NULL;
        }

      /* Continue processing for INVALID_KE_PAYLOAD. */
      if (packet->error != SSH_IKEV2_ERROR_INVALID_KE_PAYLOAD)
        ikev2_error(packet, packet->error);
    }

  return SSH_FSM_CONTINUE;
}

/* Do the SA payload processing, i.e. verify that the
   returned SA matches our proposal. This will also fill in
   the ipsec_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_nonce);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify SAr2"));
  if (!ikev2_verify_sa(packet, packet->ed->sa,
                       packet->ed->ipsec_ed->sa_i,
                       packet->ed->ipsec_ed->ipsec_sa_transforms,
                       TRUE))
    return SSH_FSM_CONTINUE;

  /* Ok. the proposal returned by the other end is ok. */
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("SAr2 was ok"));

  ikev2_error(packet,
              ikev2_fill_in_algorithms(packet->ed->ipsec_ed->new_ike_sa,
                                       packet->ed->ipsec_ed->
                                       ipsec_sa_transforms));
  if (packet->ed->sa->spi_len != 8)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB, ("Responder IKE SA spi len is not 8"));

      ikev2_audit(packet->ike_sa,  SSH_AUDIT_IKE_INVALID_SPI,
                  "Responder IKE SA spi len is not 8");

      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  else
    {
      memcpy(packet->ed->ipsec_ed->new_ike_sa->ike_spi_r,
             packet->ed->sa->spis.ike_spi, 8);
    }
  ssh_ikev2_sa_free(packet->ike_sa->server->sad_handle, packet->ed->sa);
  packet->ed->sa = NULL;
  return SSH_FSM_CONTINUE;
}

/* Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_ke);

  ikev2_check_nonce(packet, &(packet->ed->ipsec_ed->nr));

  if (memcmp(packet->ed->ipsec_ed->ni->nonce_data,
             packet->ed->ipsec_ed->nr->nonce_data,
             (packet->ed->ipsec_ed->ni->nonce_size <
              packet->ed->ipsec_ed->nr->nonce_size) ?
             packet->ed->ipsec_ed->ni->nonce_size :
             packet->ed->ipsec_ed->nr->nonce_size) < 0)
    {
      packet->ike_sa->rekey->initiated_smaller_nonce =
        ssh_memdup(packet->ed->ipsec_ed->ni->nonce_data,
                   packet->ed->ipsec_ed->ni->nonce_size);
      packet->ike_sa->rekey->initiated_smaller_nonce_len =
        packet->ed->ipsec_ed->ni->nonce_size;
    }
  else
    {
      packet->ike_sa->rekey->initiated_smaller_nonce =
        ssh_memdup(packet->ed->ipsec_ed->nr->nonce_data,
                   packet->ed->ipsec_ed->nr->nonce_size);
      packet->ike_sa->rekey->initiated_smaller_nonce_len =
        packet->ed->ipsec_ed->nr->nonce_size;
    }
  if (packet->ike_sa->rekey->initiated_smaller_nonce == NULL)
    return ikev2_error(packet, SSH_IKEV2_ERROR_OUT_OF_MEMORY);
  return SSH_FSM_CONTINUE;
}

/* Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_ke)
{
  SshIkev2Packet packet = thread_context;
  SshUInt16 group;

  if (packet->ed->ke == NULL)
    group = 0;
  else
    group = packet->ed->ke->dh_group;

  if (packet->ed->ipsec_ed->group_number != group)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("KE payload does not match selected group"));

      ikev2_audit(packet->ike_sa, SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "KE payload does not match selected group");

      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_agree);
  return SSH_FSM_CONTINUE;
}

/* Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_agree)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_done);
  if (packet->ed->ipsec_ed->group_number == 0)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_child_agree(packet));
}

void ikev2_reply_cb_ike_rekey_initiator_rekey(SshIkev2Error error_code,
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
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Error: IKE SA rekey failed: %d",
                                   error_code));
    }
}

/* Rekey exchange done. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_done)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  if (ikev2_calculate_rekey_skeyseed(packet->ed) != SSH_CRYPTO_OK)
    {
      return ikev2_error(packet, SSH_IKEV2_ERROR_CRYPTO_FAIL);
    }

  /* Check for simultaneous rekeys. */
  if (ike_sa->rekey->responded_smaller_nonce != NULL)
    {
      /* We have already done the IKE SA rekey as a
         initiator for the SA. */
      /* Check if which one is larger. */
      if (memcmp(ike_sa->rekey->responded_smaller_nonce,
                 ike_sa->rekey->initiated_smaller_nonce,
                 (ike_sa->rekey->initiated_smaller_nonce_len <
                  ike_sa->rekey->responded_smaller_nonce_len) ?
                 ike_sa->rekey->initiated_smaller_nonce_len :
                 ike_sa->rekey->responded_smaller_nonce_len) < 0)
        {
          /* This one is larger, so we won, so move them
             again. */
          /** Move from old one. */
          SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_move_from_old);
          /* As we are the initiator of the winning SA, we
             do not need to delete anything. */
          SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa,
                                                   ike_sa_rekey)
                             (ike_sa->server->sad_handle,
                              FALSE,
                              ike_sa->rekey->responded_new_sa,
                              packet->ed->ipsec_ed->new_ike_sa,
                              ikev2_reply_cb_ike_rekey_initiator_rekey,
                              packet));
          /*NOTREACHED*/
        }
      else
        {
          /** We lost, skip moving from old one. */
          SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_finish);
          /* We lost here, so make sure that the IPsec SAs
             are in the winning SA. As we are initiator, we
             need to delete the newly created SA after some
             timeout. */
          SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa,
                                                   ike_sa_rekey)
                             (ike_sa->server->sad_handle,
                              TRUE,
                              packet->ed->ipsec_ed->new_ike_sa,
                              ike_sa->rekey->responded_new_sa,
                              ikev2_reply_cb_ike_rekey_initiator_rekey,
                              packet));
          /*NOTREACHED*/
        }
    }
  /** Move from old one. */
  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_move_from_old);
  return SSH_FSM_CONTINUE;
}

/* Rekey, move from old one. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_move_from_old)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_ike_rekey_initiator_in_finish);

  /* Not a simultaneous rekey (or the initiator is not yet
     finished, move SAs, or we won).*/
  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ike_sa_rekey)
                     (ike_sa->server->sad_handle,
                      TRUE, ike_sa, packet->ed->ipsec_ed->new_ike_sa,
                      ikev2_reply_cb_ike_rekey_initiator_rekey,
                      packet));
}

/* Finish the exchange. */
SSH_FSM_STEP(ikev2_state_ike_rekey_initiator_in_finish)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

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

  /* Free ED reference (from the operation handle). */
  ikev2_free_exchange_data(ike_sa, packet->ed);

  /* Free the reference to new IKE SA. */
  SSH_IKEV2_IKE_SA_FREE(packet->ed->ipsec_ed->new_ike_sa);
  packet->ed->ipsec_ed->new_ike_sa = NULL;

  /* Then we destroy the ED from packet, as it is no longer needed. */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;

  /* Finally free the IKE SA reference (from the operation handle). */
  SSH_IKEV2_IKE_SA_FREE(ike_sa);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Create child exchange finished"));

  return SSH_FSM_FINISH;
}
