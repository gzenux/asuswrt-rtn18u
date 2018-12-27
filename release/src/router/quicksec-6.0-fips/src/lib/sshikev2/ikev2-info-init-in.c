/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 state machine for INFORMATIONAL initiator in.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"

#define SSH_DEBUG_MODULE "SshIkev2StateInfoRespIn"

/* Initiator side INFORMATIONAL packet in. */
SSH_FSM_STEP(ikev2_state_info_initiator_in)
{
#ifdef SSHDIST_IKE_MOBIKE
  SshIkev2Packet packet = thread_context;

  if (packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
    /** If MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in_check_cookie2);
  else
#endif /* SSHDIST_IKE_MOBIKE */
    /** No MOBIKE */
    SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in_check_notify);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_MOBIKE
/* Check the COOKIE 2 notify */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_cookie2)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2InfoSaExchangeData info_ed = packet->ed->info_ed;
  SshIkev2PayloadNotify notify;
  Boolean cookie2_received = FALSE;

  SSH_ASSERT(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in_check_natt);

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Checking cookie2 for MOBIKE enabled SA"));

  notify = packet->ed->notify;
  while (notify != NULL)
    {
      if (notify->notify_message_type == SSH_IKEV2_NOTIFY_COOKIE2)
        {
          cookie2_received = TRUE;

          if (notify->notification_size != sizeof(info_ed->cookie2) ||
              memcmp(notify->notification_data, info_ed->cookie2,
                     sizeof(info_ed->cookie2)))
            {
              SSH_IKEV2_DEBUG(SSH_D_FAIL,
                              ("Cookie2 does not match that sent"));

              ikev2_audit(packet->ike_sa,
                          SSH_AUDIT_IKE_INVALID_COOKIE,
                          "Cookie2 does not match that sent");

              return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
            }
        }

      notify = notify->next_notify;
    }

  if ((info_ed->flags & SSH_IKEV2_INFO_COOKIE2_ADDED) && !cookie2_received)
    {
      SSH_IKEV2_DEBUG(SSH_D_FAIL, ("Cookie2 sent but not received"));

      ikev2_audit(packet->ike_sa,
                  SSH_AUDIT_IKE_INVALID_COOKIE,
                  "Cookie2 sent but not received");
      return ikev2_error(packet, SSH_IKEV2_ERROR_INVALID_SYNTAX);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ikev2_state_info_initiator_in_check_natt)
{
  SshIkev2Packet packet = thread_context;
  Boolean nat_t_enabled, nat_src, nat_dst;

  SSH_ASSERT(packet->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in_check_notify);

  /* Check if a NAT is detected between the endpoints used for this
     negotiation. */
  if (!ikev2_compute_nat_detection(packet, TRUE, &nat_t_enabled,
                                   &nat_src, &nat_dst))
    return SSH_FSM_CONTINUE;

  if (nat_t_enabled && nat_src)
    packet->ed->info_ed->remote_end_behind_nat = 1;
  if (nat_t_enabled && nat_dst)
    packet->ed->info_ed->local_end_behind_nat = 1;

  return SSH_FSM_CONTINUE;
}

#endif /* SSHDIST_IKE_MOBIKE */


/* Check for notify payloads */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_notify)
{
  SshIkev2Packet packet = thread_context;
  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in_check_delete);
  ikev2_process_notify(packet);
  return SSH_FSM_CONTINUE;
}

/* Check for delete payloads */
SSH_FSM_STEP(ikev2_state_info_initiator_in_check_delete)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2PayloadDelete del;

  /* Do we have delete payloads. */
  del = packet->ed->delete_payloads;
  while (del != NULL)
    {
      packet->ed->delete_payloads = del->next_delete;
      if (del->spi_size == 4)
        {
          SSH_IKEV2_POLICY_CALL(packet, packet->ed->ike_sa,
                                ipsec_spi_delete_received)
            (packet->ed->ike_sa->server->sad_handle, packet->ed,
             del->protocol, del->number_of_spis,
             del->spi.spi_array, NULL_FNPTR, NULL);
          packet->operation = NULL;
        }
      del = packet->ed->delete_payloads;
    }
  SSH_FSM_SET_NEXT(ikev2_state_info_initiator_in_end);

  return SSH_FSM_CONTINUE;
}

/* Input processing done, start output processing. */
SSH_FSM_STEP(ikev2_state_info_initiator_in_end)
{
  SshIkev2Packet packet = thread_context;
  SshIkev2Sa ike_sa = packet->ike_sa;

  ikev2_debug_exchange_end(packet);

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
  ssh_operation_unregister_no_free(packet->ed->info_ed->operation_handle);
  packet->ed->info_ed->flags &= ~SSH_IKEV2_INFO_OPERATION_REGISTERED;

  SSH_IKEV2_DEBUG(SSH_D_LOWSTART, ("Freeing references to IKE SA and ED"));

  /* Free ED reference (from the operation handle). */
  ikev2_free_exchange_data(ike_sa, packet->ed);

  /* Then we destroy the ED from the packet, as it is no longer needed. */
  ikev2_free_exchange_data(ike_sa, packet->ed);
  packet->ed = NULL;

  /* Finally free the IKE SA reference (from the operation handle). */
  SSH_IKEV2_IKE_SA_FREE(ike_sa);

  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Informational exchange finished"));

  return SSH_FSM_FINISH;
}
