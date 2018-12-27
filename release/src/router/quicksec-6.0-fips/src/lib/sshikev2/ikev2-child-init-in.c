/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for CREATE CHILD initiator in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateChildInitIn"

/* Initiator side CREATE_CHILD_SA packet in. */
SSH_FSM_STEP(ikev2_state_child_initiator_in)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_sa);

  if (packet->ed->sa == NULL ||
      packet->ed->nonce == NULL ||
      packet->ed->ipsec_ed->ts_i == NULL ||
      packet->ed->ipsec_ed->ts_r == NULL)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Mandatory payloads (SAr,Ni,TSi,TSr) missing"));
      ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Do the SA payload processing, i.e. verify that the
   returned SA matches our proposal. This will also fill in
   the ipsec_sa_transforms structure. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_sa)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_nonce);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Verify SAr2"));
  if (!ikev2_verify_sa(packet, packet->ed->sa,
                       packet->ed->ipsec_ed->sa_i,
                       packet->ed->ipsec_ed->ipsec_sa_transforms,
                       FALSE))
    return SSH_FSM_CONTINUE;

  /* Ok. the proposal returned by the other end is ok. */
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("SAr2 was ok"));

  /* As this is reply packet, there must be only one proposal. */
  packet->ed->ipsec_ed->spi_outbound =
    packet->ed->sa->spis.ipsec_spis[0];
  packet->ed->ipsec_ed->ipsec_sa_protocol =
    packet->ed->ipsec_ed->sa_i->protocol_id[0];
  return SSH_FSM_CONTINUE;
}

/* Do the nonce payload processing. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_nonce)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_ke);
  ikev2_check_nonce(packet, &(packet->ed->ipsec_ed->nr));
  return SSH_FSM_CONTINUE;
}

/* Do the KE payload processing. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_ke)
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

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX,
                  "Key Exchange payload does not match selected group");

      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_ts);
  return SSH_FSM_CONTINUE;
}

/* Check the traffic selectors. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_ts)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_agree);

  if (packet->ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_USE_TRANSPORT_MODE_TS)
    {
      if (ikev2_transport_mode_natt_ts_check(packet->ed) == FALSE)
        return ikev2_error(packet, SSH_IKEV2_ERROR_TS_UNACCEPTABLE);
      ikev2_transport_mode_natt_ts_substitute(packet->ed,
                                              packet->ed->ipsec_ed->ts_i,
                                              packet->ed->ipsec_ed->ts_r);
    }

  if (!ssh_ikev2_ts_match(packet->ed->ipsec_ed->ts_local,
                          packet->ed->ipsec_ed->ts_i) ||
      !ssh_ikev2_ts_match(packet->ed->ipsec_ed->ts_remote,
                          packet->ed->ipsec_ed->ts_r))
    {
      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_TRAFFIC_SELECTORS,
                  "Traffic selectors do not match");

      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
                      ("Error: Traffic selectors does not match"));
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }
  /* Free the original TS payloads, and replace them with
     the ones returned from the other end. */
  ssh_ikev2_ts_free(packet->ike_sa->server->sad_handle,
                    packet->ed->ipsec_ed->ts_local);
  ssh_ikev2_ts_free(packet->ike_sa->server->sad_handle,
                    packet->ed->ipsec_ed->ts_remote);
  packet->ed->ipsec_ed->ts_local = packet->ed->ipsec_ed->ts_i;
  packet->ed->ipsec_ed->ts_remote = packet->ed->ipsec_ed->ts_r;
  packet->ed->ipsec_ed->ts_i = NULL;
  packet->ed->ipsec_ed->ts_r = NULL;
  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("TSi and TSr were ok"));
  return SSH_FSM_CONTINUE;
}

/* Calculate the DH agree if needed. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_agree)
{
  SshIkev2Packet packet = thread_context;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_done);
  if (packet->ed->ipsec_ed->group_number == 0)
    return SSH_FSM_CONTINUE;

  SSH_FSM_ASYNC_CALL(ikev2_child_agree(packet));
}

void ikev2_reply_cb_child_initiator_install(SshIkev2Error error_code,
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

/* SA exchange done. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_done)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_FSM_SET_NEXT(ikev2_state_child_initiator_in_finish);

  SSH_FSM_ASYNC_CALL(SSH_IKEV2_POLICY_CALL(packet, ike_sa, ipsec_sa_install)
                     (ike_sa->server->sad_handle,
                      packet->ed,
                      ikev2_reply_cb_child_initiator_install,
                      packet));
}

/* Finish the exchange. */
SSH_FSM_STEP(ikev2_state_child_initiator_in_finish)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  SSH_IKEV2_POLICY_NOTIFY(ike_sa, ipsec_sa_done)
    (ike_sa->server->sad_handle, packet->ed, SSH_IKEV2_ERROR_OK);

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

  /* Then we destroy the ED from packet, as it is no longer needed. */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;

  /* Finally free the IKE SA reference (from the operation handle). */
  SSH_IKEV2_IKE_SA_FREE(ike_sa);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Create child exchange finished"));

  return SSH_FSM_FINISH;
}
