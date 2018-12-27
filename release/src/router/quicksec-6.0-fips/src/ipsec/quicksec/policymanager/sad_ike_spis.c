/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPSec SPI allocator.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkeSpis"

static void pm_ipsec_spi_abort(void *context)
{
  SshPmQm qm = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Aborting Spi allocate call for QM %p", qm));

  qm->callbacks.aborted = TRUE;
  qm->callbacks.u.ipsec_spi_allocate_cb = NULL_FNPTR;
  qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;

  ssh_fsm_set_next(&qm->sub_thread, pm_ipsec_spi_allocate_done);
  return;
}

/******************** FSM state functions ***************************/

SSH_FSM_STEP(pm_ipsec_set_authorization_groups)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  SshPmP1 p1 = qm->p1;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  SSH_FSM_SET_NEXT(pm_ipsec_set_authorization_groups_done);

  /* We resolve the group constraints for responder Phase-I's. For IKEv1
     the Phase-I is already finished here, but not for IKEv2. */
  SSH_PM_ASSERT_P1(p1);
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0
      && !p1->auth_group_ids_set)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Resolving authorization group ID"));
      SSH_FSM_ASYNC_CALL(ssh_pm_authorization_p1(pm, p1,
                                                 ssh_pm_authorization_cb,
                                                 thread));
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_ipsec_set_authorization_groups_done)
{
  SshPmQm qm = thread_context;

  /* For responder negotiations continue to policy rule selection. */
  if (!qm->initiator)
    SSH_FSM_SET_NEXT(pm_ipsec_select_policy_rule);

  /* For initiator negotiations the policy rule has been already selected,
     continue directly to SPI allocation. */
  else
    SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_ipsec_select_policy_rule)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  SshPmP1 p1 = qm->p1;
  Boolean forward;
  SshPmTunnel tunnel = NULL;
  Boolean transport_mode_requested;
  SshUInt32 rule_lookup_flags;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  SSH_PM_ASSERT_P1(p1);
  SSH_ASSERT(qm->rule == NULL);

  /* If we have a rule selected from the IKE SA negotiation then check its
     authorization. If that fails we perform rule lookup again to see if
     a matching rule with the correct authorization can be found. However,
     for IKEv1 SA's we must always do rule lookup again, since the rule
     selection in the Phase-I has not considered the traffic selectors,
     or transport mode notifications. */
  if (p1->n != NULL && p1->n->rule != NULL)
    {
      if (p1->n->forward == TRUE)
        tunnel = p1->n->rule->side_to.tunnel;
      else
        tunnel = p1->n->rule->side_from.tunnel;

      if (
#ifdef SSHDIST_IKEV1
          (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0 &&
#endif /* SSHDIST_IKEV1 */
          ssh_pm_check_rule_authorization(p1, p1->n->rule)
          && tunnel != NULL
          && ssh_pm_ike_tunnel_match_encapsulation(tunnel, qm->ed,
                                                   &transport_mode_requested))
        {
          qm->rule = p1->n->rule;
          SSH_PM_RULE_LOCK(qm->rule);

          if (p1->n->forward == TRUE)
            qm->forward = 1;
          else
            qm->forward = 0;

          qm->tunnel = tunnel;
          SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
        }
    }

  if (qm->rule == NULL)
    {
      rule_lookup_flags = (SSH_PM_RULE_LOOKUP_CHECK_AUTH
                           | SSH_PM_RULE_LOOKUP_MATCH_ENCAP);
      if (qm->transport_recv
#ifdef SSHDIST_IKEV1
          && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
          )
        rule_lookup_flags |= SSH_PM_RULE_LOOKUP_TRANSPORT_MODE_TS;

      qm->rule =
        ssh_pm_ike_responder_rule_lookup(pm, p1, qm->ed, rule_lookup_flags,
                                         &forward, &qm->failure_mask);

      if (qm->rule != NULL)
        SSH_PM_RULE_LOCK(qm->rule);

#ifdef SSHDIST_IKEV1
      if (qm->rule != NULL && qm->rule->ike_in_progress &&
          (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Dropping IKEv1 responder request as policy "
                                 "rule is already in use"));
          SSH_PM_RULE_UNLOCK(pm, qm->rule);
          qm->rule = NULL;
          if (p1->n != NULL
              && ((p1->n->failure_mask & SSH_PM_E_LOCAL_TS_MISMATCH)
                  || (p1->n->failure_mask & SSH_PM_E_REMOTE_TS_MISMATCH)))
            qm->error = SSH_IKEV2_ERROR_TS_UNACCEPTABLE;
          else
            qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;

          SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
          return SSH_FSM_CONTINUE;
        }
#endif /* SSHDIST_IKEV1 */

      if (qm->rule != NULL)
        {
          if (forward)
            {
              qm->forward = 1;
              qm->tunnel = qm->rule->side_to.tunnel;
              SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
            }
          else
            {
              qm->forward = 0;
              qm->tunnel = qm->rule->side_from.tunnel;
              SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);
            }
        }
      else
        {
#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKEV1
          /* If rule lookup failed because of access group denial and XAUTH
             is ongoing then wait for XAUTH to complete. After XAUTH
             completes, we check again if a suitable rule is available. */
          if ((qm->failure_mask & SSH_PM_E_ACCESS_GROUP_MISMATCH)
              && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
              && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0
              && p1->ike_sa->xauth_enabled && !p1->ike_sa->xauth_done)
            {
              SSH_DEBUG(SSH_D_HIGHOK,
                        ("Rule lookup failed due to XAUTH access group "
                         "mismatch. Waiting for Xauth to complete"));
              qm->waiting_xauth = 1;
              SSH_FSM_SET_NEXT(pm_ipsec_xauth_wait);
              return SSH_FSM_CONTINUE;
            }
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

          SSH_DEBUG(SSH_D_FAIL,
                    ("No suitable policy rule found, failing negotiation"));
          SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
          qm->error = SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN;
          return SSH_FSM_CONTINUE;
        }
    }

  /* Verify we have selected a tunnel. */
  SSH_ASSERT(qm->tunnel != NULL);
  qm->transform = qm->tunnel->transform;

  /* Update the tunnel used for the Phase-I negotiation. */
  if (p1->n != NULL && qm->tunnel != p1->n->tunnel)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("IKE Responder is changing tunnels from %s to %s",
                 p1->n->tunnel->tunnel_name,
                 qm->tunnel->tunnel_name));

      if (p1->n->tunnel != NULL)
        SSH_PM_TUNNEL_DESTROY(pm, p1->n->tunnel);

      p1->tunnel_id = qm->tunnel->tunnel_id;
      p1->n->tunnel = qm->tunnel;
      SSH_PM_TUNNEL_TAKE_REF(p1->n->tunnel);
    }

  /* Set encapsulation mode for the negotiation. */
  ssh_pm_qm_thread_compute_tunneling_attribute(qm);

  SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKEV1
SSH_FSM_STEP(pm_ipsec_xauth_wait)
{
  SshPmQm qm = thread_context;
  SshPmP1 p1 = qm->p1;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  SSH_DEBUG(SSH_D_LOWOK, ("Xauth wait"));
  SSH_PM_ASSERT_P1(p1);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /* Wait for XAUTH completion. */
  if (!p1->ike_sa->xauth_done)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Suspending QM thread until XAUTH is done,qm=%p", qm));

      SSH_FSM_CONDITION_WAIT(&p1->xauth_wait_condition);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  qm->waiting_xauth = 0;
  SSH_DEBUG(SSH_D_LOWOK, ("Xauth operation done"));

  if (p1->failed)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Xauth has failed"));
      qm->error = SSH_IKEV2_ERROR_AUTHENTICATION_FAILED;
    }

  /* Reselect policy rule now that xauth is done. */
  SSH_FSM_SET_NEXT(pm_ipsec_select_policy_rule);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

SSH_FSM_STEP(pm_ipsec_spi_allocate)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  SshUInt32 spibits = 0;

  if (ssh_pm_check_qm_error(qm, thread, pm_ipsec_spi_allocate_done))
    return SSH_FSM_CONTINUE;

  if (qm->spis[0] != SSH_IPSEC_SPI_IKE_ERROR_RESERVED)
    {
      /* Reusing unused SPI left from previous try (when doing
         initiator side initial try for rekey with invalid KE */
      SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate_done);
      return SSH_FSM_CONTINUE;
    }

  /* AH and ESP share the SPI (can't configure bundles) */
  if (qm->transform & SSH_PM_IPSEC_AH)
    spibits |= (1 << SSH_PME_SPI_AH_IN);
  else if (qm->transform & SSH_PM_IPSEC_ESP)
    spibits |= (1 << SSH_PME_SPI_ESP_IN);

  if (qm->transform & SSH_PM_IPSEC_IPCOMP)
    spibits |= (1 << SSH_PME_SPI_IPCOMP_IN);

  if (ssh_pm_allocate_spis(pm, spibits, qm->spis) == FALSE)
    qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;

  SSH_FSM_SET_NEXT(pm_ipsec_spi_allocate_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_ipsec_spi_allocate_done)
{
  SshPm pm = fsm_context;
  SshPmQm qm = thread_context;
  unsigned int spi_index = 0;
  SshPmSpiOut spi_out;
  Boolean match_address = TRUE;
  SshInetIPProtocolID ipproto = 0;
  int i;

  /* Check for errors. */
  if (qm->error != SSH_IKEV2_ERROR_OK)
    goto error;

  /* If this is a responder IKEv2 IPsec SA rekey, then lookup the old
     outbound SPI entry. If no entry is found, then the IPsec SA that
     is being rekeyed has been already deleted. If an entry is found
     but it is marked as rekeyed, then the remote end most likely
     thinks that this is a simultaneous IPsec SA rekey. In both cases
     RFC5996 specifies that this responder negotiation should be failed
     with a non-fatal error such as CHILD_SA_NOT_FOUND. */
  if (!qm->initiator && qm->rekey
#ifdef SSHDIST_IKEV1
      && (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0
#endif /* SSHDIST_IKEV1 */
      )
    {
      SSH_PM_ASSERT_P1(qm->p1);

      /* Lookup outbound SPI entry for the SA being rekeyed. */
#ifdef SSHDIST_IKE_MOBIKE
      if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
        match_address = FALSE;
#endif /* SSHDIST_IKE_MOBIKE */

      if (qm->transform & SSH_PM_IPSEC_AH)
        ipproto = SSH_IPPROTO_AH;
      else if (qm->transform & SSH_PM_IPSEC_ESP)
        ipproto = SSH_IPPROTO_ESP;

      spi_out = ssh_pm_lookup_outbound_spi(
                          pm, match_address,
                          qm->old_outbound_spi,
                          ipproto,
                          qm->p1->ike_sa->remote_ip,
                          qm->p1->ike_sa->remote_port,
                          qm->p1->ike_sa->server->routing_instance_id);

      if (spi_out == NULL || spi_out->rekeyed)
        {
          /* SPI entry was not found. */
          if (spi_out == NULL)
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Old outbound SPI value %@-%08lx not found",
                       ssh_ipproto_render, (SshUInt32) ipproto,
                       (unsigned long) qm->old_outbound_spi));
          /* SPI entry is already marked as rekeyed. */
          else
            SSH_DEBUG(SSH_D_NICETOKNOW,
                      ("Old outbound SPI value %@-%08lx has already been "
                       "rekeyed",
                       ssh_ipproto_render, (SshUInt32) ipproto,
                       (unsigned long) qm->old_outbound_spi));

          qm->error = SSH_IKEV2_ERROR_CHILD_SA_NOT_FOUND;
          goto error;
        }

      /* SPI entry was found. Store the transform index and old inbound SPI
         of the rekeyed SA. */
      qm->trd_index = spi_out->trd_index;
      qm->old_inbound_spi = spi_out->inbound_spi;

      /* Check if there is a simultaneous IPsec SA rekey going on and
         mark this responder qm so that the nonces can be checked and
         stored in responder_exchange_done. */
      for (i = 0; i < PM_IKE_MAX_WINDOW_SIZE; i++)
        {
          if (qm->p1->initiator_eds[i] != NULL
            && qm->p1->initiator_eds[i]->state == SSH_IKEV2_STATE_CREATE_CHILD
            && qm->p1->initiator_eds[i]->ipsec_ed != NULL
            && (qm->p1->initiator_eds[i]->ipsec_ed->rekeyed_spi
                == qm->old_inbound_spi))
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Simultaneous IPsec SA rekey detected detected for "
                         "inbound SPI %@-%08lx",
                         ssh_ipproto_render, (SshUInt32) ipproto,
                         (unsigned long) qm->old_inbound_spi));
              qm->simultaneous_rekey = 1;
              break;
            }
        }
    }

  /* Return the allocated SPI to IKEv2 library. */
  if (qm->transform & SSH_PM_IPSEC_AH)
    {
      spi_index = SSH_PME_SPI_AH_IN;
      SSH_ASSERT(qm->spis[spi_index] != 0);
    }
  else if (qm->transform & SSH_PM_IPSEC_ESP)
    {
      spi_index = SSH_PME_SPI_ESP_IN;
      SSH_ASSERT(qm->spis[spi_index] != 0);
    }
  else
    SSH_NOTREACHED;

  if (!qm->callbacks.aborted)
    {
      if (qm->callbacks.u.ipsec_spi_allocate_cb != NULL_FNPTR)
        (*qm->callbacks.u.ipsec_spi_allocate_cb)(SSH_IKEV2_ERROR_OK,
                                               qm->spis[spi_index],
                                               qm->callbacks.callback_context);
      ssh_operation_unregister(qm->callbacks.operation);
    }

  return SSH_FSM_FINISH;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("SPI allocation failed with error %d", qm->error));

  SSH_ASSERT(qm->error != SSH_IKEV2_ERROR_OK);

  if (!qm->callbacks.aborted)
    {
      if (qm->callbacks.u.ipsec_spi_allocate_cb != NULL_FNPTR)
        (*qm->callbacks.u.ipsec_spi_allocate_cb)(qm->error, 0,
                                               qm->callbacks.callback_context);
      ssh_operation_unregister(qm->callbacks.operation);
    }

  /* Wake up the main Quick-Mode thread. This is done to clean up the state
     if the negotiation has been aborted. */
  if (qm->initiator)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Continuing Quick Mode thread"));
      ssh_fsm_continue(&qm->thread);
    }

  return SSH_FSM_FINISH;
}

SshOperationHandle
ssh_pm_ipsec_spi_allocate(SshSADHandle sad_handle,
                          SshIkev2ExchangeData ed,
                          SshIkev2SadIPsecSpiAllocateCB reply_callback,
                          void *reply_context)
{
  SshPmQm qm;
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)ed->ike_sa;
  Boolean rekey;
  Boolean initiator;
  SshUInt32 peer_handle;
#ifdef SSH_PM_BLACKLIST_ENABLED
  SshPmBlacklistCheckCode check_code;
  Boolean is_ikev1 = FALSE;
#endif /* SSH_PM_BLACKLIST_ENABLED */

  SSH_PM_ASSERT_P1(p1);

  /* Check if policy manager is suspended or being destroyed. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, 0, reply_context);
      return NULL;
    }

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_GOING_DOWN, 0, reply_context);
      return NULL;
    }

  /* Reconfigure might have got rid of the used tunnel in P1, so we'll
     have to check that the tunnel still exists in the current policy. */
  if (ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id) == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, 0, reply_context);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Tried to allocate IPsec SPI while for "
                                   "P1 with nonexistent tunnel (id %d)",
                                   p1->tunnel_id));

      /* Mark the P1 to be removed really soon and unusable. */
      p1->tunnel_id = SSH_IPSEC_INVALID_INDEX;
      p1->expire_time = ssh_time();
      p1->unusable = 1;
      return NULL;
    }

  if (ed->ipsec_ed->flags & SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_INITIATOR)
    initiator = TRUE;
  else
    initiator = FALSE;

  /* Check if this is an IKEv2 IPsec SA rekey. */
  if (ed->ipsec_ed->rekeyed_spi != 0)
    rekey = TRUE;
  else
    rekey = FALSE;

#if (SSH_PM_MAX_CHILD_SAS > 0)
  /* Check if this peer is allowed to create another child SA with us. */
  if (rekey == FALSE
      && ssh_pm_peer_num_child_sas_by_p1(pm, p1) >= SSH_PM_MAX_CHILD_SAS)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Maximum number of child SAs per peer reached %d: "
                 "terminating",
                 (int) SSH_PM_MAX_CHILD_SAS));
      (*reply_callback)((int) SSH_IKEV2_NOTIFY_NO_ADDITIONAL_SAS, 0,
                        reply_context);
      return NULL;
    }
#endif /* (SSH_PM_MAX_CHILD_SAS > 0) */

#ifdef SSH_PM_BLACKLIST_ENABLED
#ifdef SSHDIST_IKEV1
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    is_ikev1 = TRUE;
  else
    is_ikev1 = FALSE;
#endif /* SSHDIST_IKEV1 */

  switch (ed->state)
    {
    case SSH_IKEV2_STATE_IKE_AUTH_1ST:
#ifdef SSHDIST_IKE_EAP_AUTH
    case SSH_IKEV2_STATE_IKE_AUTH_EAP:
#endif /* SSHDIST_IKE_EAP_AUTH */
    case SSH_IKEV2_STATE_IKE_AUTH_LAST:

      /* In IKEv1 case blacklist check is already done once in ssh_pm_ike_id()
         function and therefore check is skipped here to avoid double check. */
      if (is_ikev1 == TRUE)
        break;

      /* Blacklist check is done only in responder side in the initial
         exchange. */
      if (initiator == FALSE)
        {

          /* Set the check code */
          check_code = SSH_PM_BLACKLIST_CHECK_IKEV2_R_INITIAL_EXCHANGE;

          /* Do blacklist check */
          if (!ssh_pm_blacklist_check(pm, ed->ike_ed->id_i, check_code))
            {
              /* IKE ID is in blacklist. In this case Authentication Failed
                 error is given for the callback function. */
              (*reply_callback)(SSH_IKEV2_ERROR_AUTHENTICATION_FAILED,
                                0,
                                reply_context);
              return NULL;
            }

          p1->enable_blacklist_check = 1;
        }
      break;

    case SSH_IKEV2_STATE_CREATE_CHILD:

      /* Blacklist check is done only in the responder side of the
         CREATE_CHILD exchange if the parent IKEv2 SA has blacklist
         checking enabled or the parent IKE SA is IKEv1.

         The check is necessary for all IKEv1 responder CREATE_CHILD
         exchanges because there is no strict binding between the IKEv1
         SA and it's child SAs. Depending on the policy it may be
         possible that a new IKEv1 SA from a trigger/auto-start
         negotiation has replaced the parent SA for the child SAs. In
         such a case the IKEv1 SA does not have the blacklist checking
         enabled, and as we do not yet know if this exchange is rekeying
         an existing child SA, we must assume so and perform the
         blacklist check for all IKEv1 responder CREATE_CHILD exchanges. */
      if (initiator == FALSE
          && (is_ikev1 == TRUE || p1->enable_blacklist_check))
        {
          /* Solve the check code. */
          if (is_ikev1 == TRUE)
            check_code = SSH_PM_BLACKLIST_CHECK_IKEV1_R_QUICK_MODE_EXCHANGE;
          else if (rekey == TRUE)
            check_code = SSH_PM_BLACKLIST_CHECK_IKEV2_R_IPSEC_SA_REKEY;
          else
            check_code = SSH_PM_BLACKLIST_CHECK_IKEV2_R_CREATE_CHILD_EXCHANGE;

          /* Do blacklist check */
          if (!ssh_pm_blacklist_check(pm, p1->remote_id, check_code))
            {
              /* IKE ID is in blacklist. In this case No Proposal Chosen
                 error is given for the callback function. */
              (*reply_callback)(SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN,
                                0,
                                reply_context);
              return NULL;
            }
        }
      break;

    default:
      break;
    }
#endif /* SSH_PM_BLACKLIST_ENABLED */

  /* Fail IPsec SA negotiation with TEMPORARY_FAILURE if IKE SA is being
     rekeyed. */
  if (p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_TEMPORARY_FAILURE, 0, reply_context);
      return NULL;
    }

  /* Fetch peer handle for p1 and sanity check peer_handle for IKEv2
     IPsec SA responder rekeys.  */
  peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);
  if (rekey == TRUE && initiator == FALSE
      && peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_TEMPORARY_FAILURE, 0, reply_context);
      return NULL;
    }

  /* Store ed to p1 negotiation context. */
  if (p1->n != NULL && p1->n->ed == NULL)
    p1->n->ed = ed;

  /* Allocate a qm for this negotiation. This is done here for responder
     IPsec SA negotiations. */
  if (ed->application_context == NULL)
    {
      qm = ssh_pm_qm_alloc(pm, rekey);
      if (qm != NULL)
        {
          qm->p1 = p1;
          SSH_PM_ASSERT_P1(qm->p1);

          /* Verify that the IKE SA can be used. */
          if (!SSH_PM_P1_USABLE(qm->p1))
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("SPI allocation failed, IKE SA %p cannot be used",
                         qm->p1->ike_sa));

              ssh_pm_qm_free(pm, qm);
              (*reply_callback)(SSH_IKEV2_ERROR_SA_UNUSABLE, 0, reply_context);
              return NULL;
            }

          /* Set peer handle. For IKEv1 responder rekeys it might change
             in SA handler. */
          qm->peer_handle = peer_handle;

          /* Take a reference to peer handle for protecting qm->peer_handle. */
          if (qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
            ssh_pm_peer_handle_take_ref(pm, qm->peer_handle);

          qm->ed = ed;
          ed->application_context = qm;

          if (initiator == TRUE)
            qm->initiator = 1;
          if (rekey == TRUE)
            qm->rekey = 1;

          qm->old_outbound_spi = qm->ed->ipsec_ed->rekeyed_spi;
        }
    }
  else
    {
      qm = ed->application_context;
    }

  if (qm == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, 0, reply_context);
      return NULL;
    }
  SSH_ASSERT(qm != NULL);
  SSH_PM_ASSERT_QM(qm);

  /* Parse notify payloads. */
  ssh_pm_ike_parse_notify_payloads(ed, qm);

  /* Start thread for SPI allocation and related tasks. */
  qm->callbacks.aborted = FALSE;
  qm->callbacks.u.ipsec_spi_allocate_cb = reply_callback;
  qm->callbacks.callback_context = reply_context;

  ssh_operation_register_no_alloc(qm->callbacks.operation,
                                  pm_ipsec_spi_abort, qm);

  ssh_fsm_thread_init(&pm->fsm, &qm->sub_thread,
                      pm_ipsec_set_authorization_groups,
                      NULL_FNPTR,
                      pm_qm_sub_thread_destructor,
                      qm);
  ssh_fsm_set_thread_name(&qm->sub_thread, "SPI allocate");
  return qm->callbacks.operation;
}

void ssh_pm_ipsec_spi_delete(SshSADHandle sad_handle, SshUInt32 spi)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("Received IPsec SPI delete for SPI 0x%08lx from the IKE library",
             (unsigned long) spi));
}
