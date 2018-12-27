/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM shutdown.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStShutdown"


/*--------------------------------------------------------------------*/
/* Shutting down the system
   - wait for reconfiguration to stop
   - shutdown l2tp
   - abort ongoing initiated IKE negotiations
   - shutdown CM
   - wait for QM's to terminate
   - delete SAs
   - wait sub-threads
   - shutdown ike
   - shutdown ek
   - disconnect the engine
*/
/*--------------------------------------------------------------------*/
/** This is entry point for shutting down the system. */
SSH_FSM_STEP(ssh_pm_st_main_shutdown)
{
  SshPm pm = fsm_context;

  SSH_ASSERT(ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED);
  SSH_DEBUG(SSH_D_HIGHSTART, ("Shutting down policy manager"));

  /* Wait for the config thread to terminate. */
  if (pm->config_active)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for config thread to terminate"));
      SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  ssh_cancel_timeout(pm->auto_start_timeout);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SSH_FSM_SET_NEXT(pm_shutdown_vip_tunnels);
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  SSH_FSM_SET_NEXT(pm_shutdown_l2tp_servers);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
SSH_FSM_STEP(pm_shutdown_vip_tunnels)
{
  SshPmTunnel tunnel;
  SshPm pm = fsm_context;
  SshUInt32 shutting_down_count = 0;
  Boolean was_unusable;

  for (tunnel = ssh_pm_tunnel_get_next(pm, NULL);
       tunnel != NULL;
       tunnel = ssh_pm_tunnel_get_next(pm, tunnel))
    {
      was_unusable = FALSE;

      if (tunnel->vip != NULL && tunnel->vip->shutdown == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Shutting down vip tunnel %p", tunnel));

          if (tunnel->vip->unusable == 1)
            was_unusable = TRUE;

          tunnel->vip->unusable = 1;
          tunnel->vip->shutdown = 1;

          if (was_unusable == FALSE)
            {
              shutting_down_count++;
              ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
            }
        }
      else if (tunnel->vip != NULL && tunnel->vip->shutdown == 1)
        {
          shutting_down_count++;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Shutdown vip tunnels, waiting for %u tunnels",
                          shutting_down_count));

  if (shutting_down_count == 0)
    SSH_FSM_SET_NEXT(pm_shutdown_l2tp_servers);
  else
    SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);

  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

SSH_FSM_STEP(pm_shutdown_l2tp_servers)
{
  SSH_FSM_SET_NEXT(pm_shutdown_l2tp);

#ifdef SSHDIST_L2TP
  SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for L2TP servers to terminate"));
  /* Stop L2TP servers. */
  SSH_FSM_ASYNC_CALL({
    ssh_pm_servers_stop((SshPm) fsm_context,
                        SSH_PM_SERVER_L2TP,
                        ssh_pm_servers_stop_cb, thread);
  });
  SSH_NOTREACHED;
#endif /* SSHDIST_L2TP */

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_L2TP
static void
ssh_pm_l2tp_finished_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);

  pm->l2tp = NULL;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /* Wait until all LNS threads have finished. */
  if (pm->num_l2tp_lns_threads > 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Waiting for %d L2TP LNS threads to finish",
                              (int) pm->num_l2tp_lns_threads));
      if (ssh_register_timeout(NULL, 1, 0, ssh_pm_l2tp_finished_cb, thread))
        return;

      SSH_DEBUG(SSH_D_ERROR,
                ("Failed to register L2TP LNS thread timeout, continuing "
                 "shutdown"));
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}
#endif /* SSHDIST_L2TP */

SSH_FSM_STEP(pm_shutdown_l2tp)
{
  SSH_FSM_SET_NEXT(pm_shutdown_abort_ike_negotiations);
#ifdef SSHDIST_L2TP
  SSH_DEBUG(SSH_D_LOWSTART, ("Uninitialize the L2TP library"));

  /** Uninit L2TP. */
  SSH_FSM_ASYNC_CALL(ssh_pm_l2tp_uninit((SshPm) fsm_context,
                                        ssh_pm_l2tp_finished_cb, thread));
  SSH_NOTREACHED;
#endif /* SSHDIST_L2TP */
  return SSH_FSM_CONTINUE;
}

#ifdef WITH_IKE
static void pm_shutdown_abort_ed(SshPm pm, SshPmP1 p1, int index)
{
  SshIkev2ExchangeData tmp;

  if (p1->initiator_eds[index] != NULL)
    {
      tmp = p1->initiator_eds[index];
      p1->initiator_eds[index] = NULL;

      if (tmp->ipsec_ed)
        {
          if (tmp->ipsec_ed->flags & SSH_IKEV2_IPSEC_OPERATION_REGISTERED)
            ssh_operation_abort(tmp->ipsec_ed->operation_handle);
        }
      else if (tmp->info_ed)
        {
          if (tmp->info_ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED)
            ssh_operation_abort(tmp->info_ed->operation_handle);
        }

      ssh_ikev2_exchange_data_free(tmp);
      p1->done = 1;
      p1->failed = 1;
    }
}

static void
pm_delete_sas_timeout_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmP1 p1, next_p1;
  int i;
  SshOperationHandle op;

  pm->delete_timer_count--;

  /* Check for any pending delete operations. */
  for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
    {
      for (p1 = pm->ike_sa_hash[i]; p1; p1 = next_p1)
        {
          SSH_PM_ASSERT_P1(p1);
          next_p1 = p1->hash_next;
          if (p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE])
            {
              /* We have waited long enough, abort pending deletion. */
              if (pm->delete_timer_count == 0)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Aborting pending IKE SA delete operation"));

                  p1->done = 1;
                  p1->failed = 1;

                  /* The operation abort may cause the p1 to be freed. */
                  op = p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE];
                  p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] = NULL;
                  ssh_operation_abort(op);
                }

              /* Give some time for deletions to complete. */
              else
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("IKE SA delete operation pending, "
                             "rescheduling timeout"));
                  ssh_register_timeout(&pm->delete_timer, 1, 0,
                                       pm_delete_sas_timeout_cb, thread);
                  return;
                }
            }
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("SA deletion completed"));
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
pm_delete_sas_cb(SshPm pm, Boolean sa_deletion_started, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  /* Continue shutdown if no SAs deletions were started. */
  if (!sa_deletion_started)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("SA deletion completed"));
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
    }

  /* Give some time for deletions to complete. */
  else
    {
      pm->delete_timer_count = 4;
      ssh_register_timeout(&pm->delete_timer, 0, 500000,
                           pm_delete_sas_timeout_cb, thread);
    }
}
#endif /* WITH_IKE */

SSH_FSM_STEP(pm_shutdown_abort_ike_negotiations)
{
#ifdef WITH_IKE
  SshPm pm = (SshPm) fsm_context;
  SshPmP1 p1, next_p1;
  SshUInt32 j;
  SshPmQm qm, next_qm;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Aborting operations using ongoing IKE negotiations"));
  for (p1 = pm->active_p1_negotiations; p1; p1 = next_p1)
    {
      /* First we'll abort all the active initiator negotiations over
         this IKE SA. */
      next_p1 = p1->n->next;
      for (j = 0; j < PM_IKE_MAX_WINDOW_SIZE; j++)
        pm_shutdown_abort_ed(pm, p1, j);

      /* Tear down active half open IKEv2 SA's */
      if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
#ifdef SSHDIST_IKEV1
          !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
#endif /* SSHDIST_IKEV1 */
          !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) &&
          (p1->ike_sa->ref_cnt == 0))
        {
          /* Delete operation is guanteed to be synchronous, so the result
             can be safely ignored. */
          if (!SSH_PM_P1_DELETED(p1))
            ssh_ikev2_ike_sa_delete(p1->ike_sa,
                                    SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION,
                                    NULL_FNPTR);
        }

#ifdef SSHDIST_IKE_EAP_AUTH
      /* Then we'll fail the responder side EAP. This will eventually
         complete the EAP operation with failure and terminate
         responder side operation. */
      if (p1->n->eap && p1->n->eap->eap && !p1->n->eap->client)
        ssh_eap_authenticate(p1->n->eap->eap,  SSH_EAP_AUTH_FAILURE);
#endif /* SSHDIST_IKE_EAP_AUTH */
    }

  /* Run active Quick-Mode threads to completion if possible */
  for (qm = pm->active_qm_negotiations; qm; qm = next_qm)
    {
      next_qm = qm->next;
      ssh_pm_qm_thread_abort(pm, qm);
    }
#endif /* WITH_IKE */

  SSH_FSM_SET_NEXT(pm_shutdown_wait_qm_termination);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(pm_shutdown_wait_qm_termination)
{
  SshPm pm = (SshPm) fsm_context;
#ifdef WITH_IKE
  SshUInt32 i, j;
  SshPmP1 p1;
#endif /* WITH_IKE */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshPmTunnel tunnel;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  if (pm->stats.num_qm_active)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Waiting for IKE negotiations to terminate. "
                 "%d QM currently active",
                 (int) pm->stats.num_qm_active));
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }
  SSH_DEBUG(SSH_D_LOWSTART,
            ("All Quick-Mode negotiations have terminated."));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Wake up vip threads that are waiting for all references to be freed. */
  for (tunnel = ssh_pm_tunnel_get_next(pm, NULL);
       tunnel != NULL;
       tunnel = ssh_pm_tunnel_get_next(pm, tunnel))
    {
      if (tunnel->vip != NULL)
        ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef WITH_IKE
  SSH_DEBUG(SSH_D_LOWOK,
            ("Aborting operations using completed P1 negotiations"));
  for (i = 0; i < SSH_PM_IKE_SA_HASH_TABLE_SIZE; i++)
    {
      for (p1 = pm->ike_sa_hash[i]; p1; p1 = p1->hash_next)
        {
          SshOperationHandle op;

          for (j = 0; j < PM_IKE_MAX_WINDOW_SIZE; j++)
            pm_shutdown_abort_ed(pm, p1, j);

          for (j = 0; j < PM_IKE_NUM_INITIATOR_OPS; j++)
            {
              /* Do not abort the IKE SA delete operation. If the IKE
                 SA is already being deleted we should not do anything. */
              if (j == PM_IKE_INITIATOR_OP_DELETE)
                continue;

              op = p1->initiator_ops[j];
              /* Clear the operation handle from the p1 to avoid recursive
                 calls while aborting operations. */
              p1->initiator_ops[j] = NULL;
              if (op)
                ssh_operation_abort(op);
            }
        }
    }
#endif /* WITH_IKE */

  SSH_FSM_SET_NEXT(pm_shutdown_stop_cm);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
static void ssh_pm_validators_stop_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

SSH_FSM_STEP(pm_shutdown_stop_cm)
{
  SSH_FSM_SET_NEXT(pm_shutdown_delete_sas);
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Stopping the certificate validators"));
  SSH_FSM_ASYNC_CALL(ssh_pm_cert_validators_stop((SshPm) fsm_context,
                                                 ssh_pm_validators_stop_cb,
                                                 thread));
  SSH_NOTREACHED;
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_shutdown_delete_sas)
{
#ifdef WITH_IKE
  SshPm pm = (SshPm) fsm_context;
  SshUInt32 delete_flags = 0;
#endif /* WITH_IKE */

  SSH_FSM_SET_NEXT(pm_shutdown_wait_sub_threads);

#ifdef WITH_IKE
  SSH_DEBUG(SSH_D_LOWSTART, ("Deleting all IKE and IPsec SAs"));

  /* Do not send delete notifications if PM is suspended. Note that
     ssh_pm_get_status() cannot be used here as it would always return
     SSH_PM_STATUS_DESTROYED. */
  if (pm->policy_suspend_count > 0)
    delete_flags |= SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION;

  SSH_FSM_ASYNC_CALL({
      ssh_pm_delete_by_peer(pm, NULL, delete_flags, pm_delete_sas_cb, thread);
  });
  SSH_NOTREACHED;
#endif /* WITH_IKE */

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_shutdown_wait_sub_threads)
{
  SshPm pm = (SshPm) fsm_context;
  SshADTHandle handle;

  SSH_FSM_SET_NEXT(pm_shutdown_ike_servers);

  /* Wait for other sub-threads to terminate. */
  if (pm->mt_num_sub_threads)
    {
      SshPmRule rule;

      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for sub-threads to terminate"));

      /* Signal all rules. */
      for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
           handle != SSH_ADT_INVALID;
           handle = ssh_adt_enumerate_next(pm->rule_by_id, handle))
        {
          rule = ssh_adt_get(pm->rule_by_id, handle);
          SSH_FSM_CONDITION_BROADCAST(&rule->cond);
        }

      /* And wait that the sub-threads terminate. */
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  SSH_ASSERT(pm->mt_num_sub_threads == 0);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(pm_shutdown_ike_servers)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(pm_shutdown_wait_ike_shutdown);


  SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for IKE servers to terminate"));

#ifdef WITH_IKE
  /* Uninitialize DPD */
  ssh_pm_dpd_uninit(pm);
#endif /* WITH_IKE */

  if (pm->delete_server_timeout_registered)
    ssh_cancel_timeout(&pm->delete_server_timer);

  /* stop IKE servers. */
  SSH_FSM_ASYNC_CALL(ssh_pm_servers_stop(pm, SSH_PM_SERVER_IKE,
                                         ssh_pm_servers_stop_cb, thread));
  SSH_NOTREACHED;
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_shutdown_wait_ike_shutdown)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(pm_shutdown_wait_ek_thread);

  if (pm->stats.num_p1_active)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Waiting for IKE negotiations to terminate. %d Phase-I "
                 "currently active", (int) pm->stats.num_p1_active));
      SSH_FSM_SET_NEXT(pm_shutdown_wait_ike_shutdown);
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("All IKE negotiations have terminated."));
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(pm_shutdown_wait_ek_thread)
{
#ifdef SSHDIST_EXTERNALKEY
  SshPm pm = (SshPm) fsm_context;

  if (pm->ek_thread_ok)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Waiting for externalkey thread to terminate"));

      ssh_fsm_condition_signal(&pm->fsm, &pm->ek_thread_cond);
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  /* Externalkey thread has terminated.  Time to delete IKE SA's. */
#endif /* SSHDIST_EXTERNALKEY */

  SSH_FSM_SET_NEXT(pm_shutdown_radius_acct_wait);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(pm_shutdown_radius_acct_wait)
{
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  SshPm pm = (SshPm) fsm_context;


  if (pm_ras_radius_acct_shutdown(pm) != TRUE)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Waiting for RADIUS Accounting to finish."));

      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  /* RADIUS Accounting has terminated, continue. */
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
  SSH_FSM_SET_NEXT(pm_shutdown_disconnect_engine);

  return SSH_FSM_CONTINUE;
}



static void
pm_st_main_shutdown_engine_disconnected(SshPm pm, Boolean ok, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(pm_shutdown_disconnect_engine)
{
  SshPm pm = (SshPm) fsm_context;

#ifdef SSHDIST_IKE_CERT_AUTH
  /* Re-wait for sub threads */
  if (pm->mt_num_sub_threads)
    SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
#endif /* SSHDIST_IKE_CERT_AUTH */

  SSH_FSM_SET_NEXT(pm_shutdown_complete);

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Cleaning up engine state!"));
  ssh_engine_notify_pm_close(pm->engine);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  SSH_FSM_ASYNC_CALL({
    ssh_pm_disconnect_engine(pm,
                             pm_st_main_shutdown_engine_disconnected,
                             thread);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(pm_shutdown_complete)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Shutdown operation complete"));

  /* Register a zero-timeout that takes care of the final destruction.
     This must be done in a zero-timeout since it will also destroy
     the FSM. */
  ssh_xregister_timeout(0, 0, ssh_pm_destructor_timeout, pm);

  /* The main thread has completed its duties. */
  return SSH_FSM_FINISH;
}
