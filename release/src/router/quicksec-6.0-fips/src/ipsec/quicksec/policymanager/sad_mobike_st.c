/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Mobike initiator and responder state machines.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmSadMobIkeSt"

#ifdef SSHDIST_IPSEC_MOBIKE

/********************* Common to initiator and responder *********************/

/* IPsec SA update completion callback for initiator and responder. */
static void
pm_mobike_update_ipsec_sa_cb(SshPm pm, Boolean status, void *context)
{
  SshPmMobike ctx = (SshPmMobike) context;

  /* Mark non-abortable sub operation completed. */
  ctx->non_abortable = 0;

  SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA address update %s.",
                          (status ? "succeeded" : "failed")));
  if (!ctx->aborted)
    {
      if (status)
        {
          SshPmP1 p1 = ctx->p1;

          ctx->ipsec_sa_updated = 1;

          ssh_pm_log_p1_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                              p1, "MOBIKE address update", FALSE);
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Old Addresses: Local %@ : Remote %@",
                        ssh_ipaddr_render, ctx->old_local_ip,
                        ssh_ipaddr_render, ctx->old_remote_ip);

          ssh_pm_log_p1_additional_addresses(SSH_LOGFACILITY_AUTH,
                                             SSH_LOG_INFORMATIONAL, p1, TRUE);
        }
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}



/*************************** Initiator State Machine *************************/

void pm_mobike_i_abort(void *operation_context)
{
  SshPmMobike ctx = (SshPmMobike) operation_context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Mobike initiator address update thread aborted."));

  /* Address update was suspended, thread does not exist, just free ctx. */
  if (ctx->flags & SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED)
    {
      SSH_ASSERT(ctx->p1->mobike_suspended_operation == ctx);
      ctx->p1->mobike_suspended_operation = NULL;
      ctx->p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_NOT_SUSPENDED;
      ssh_pm_mobike_free(ctx->pm, ctx);
      return;
    }

  /* Mark operation aborted. */
  ctx->aborted = 1;
  ssh_fsm_set_next(ctx->thread, ssh_pm_st_mobike_i_failed);

  /* Check if waiting for an async op completion. This thread may be waiting
     for a non-abortable engine call completion. In such case we let the
     engine call complete and continue the thread to the failure state.
     Otherwise this thread was waiting for an IKE informational exchange
     completion. Those exchanges are aborted by the caller of this function
     so this thread must not wait for the completion but continue immediately
     to failure state. */
  if (ctx->non_abortable == 0)
    {
      if (ssh_fsm_get_callback_flag(ctx->thread))
        SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
      else
        ssh_fsm_continue(ctx->thread);
    }
}

void pm_mobike_i_destructor(SshFSM fsm, void *context)
{
  SshPmMobike ctx = (SshPmMobike) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Mobike initiator address update thread destructor."));

  if ((ctx->flags & SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED) == 0)
    {
      if (!ctx->aborted)
        ssh_operation_unregister(ctx->op);

      ssh_pm_mobike_free(pm, ctx);
    }
}

void pm_mobike_address_update_done_cb(SshSADHandle sad_handle,
                                      SshIkev2Sa ike_sa,
                                      SshIkev2ExchangeData ed,
                                      SshIkev2Error error)
{
  SshPmInfo info = (SshPmInfo) ed->application_context;
  SshPm pm = sad_handle->pm;
  SshPmMobike ctx;

  PM_IKE_ASYNC_CALL_COMPLETE(ike_sa, ed);

  SSH_ASSERT(info != NULL);
  SSH_ASSERT(info->type == SSH_PM_ED_DATA_INFO_MOBIKE);

  ctx = info->u.mobike;

  /* Clear application context. */
  SSH_PM_ASSERT_ED(ed);
  ed->application_context = NULL;

  /* The IKE SA is updated after the informational exchange since
     the message ID's of the IKE SA is updated. */
  ssh_pm_ike_sa_event_updated(pm, ctx->p1);

  /* This should never happen. */
  if (ctx->aborted)
    return;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Address update exchange done for IKE SA %p, error %d",
             ctx->p1, error));

  /* Store error code and multiple_addresses_used flag. */
  ctx->error = error;
  ctx->multiple_addresses_used = ed->multiple_addresses_used;

  /* Leave addresses undefined on error. */
  if (error != SSH_IKEV2_ERROR_OK)
    goto out;

  /* Check if NAT-T was used. */
  if (ed->info_ed->local_end_behind_nat)
    ctx->natt_flags |=
      SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;
  if (ed->info_ed->remote_end_behind_nat)
    ctx->natt_flags |=
      SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

  *ctx->local_ip = *ed->server->ip_address;
  *ctx->remote_ip = *ed->remote_ip;
  ctx->local_port = SSH_PM_IKE_SA_LOCAL_PORT(ctx->p1->ike_sa);
  ctx->remote_port = ed->remote_port;

  SSH_APE_MARK(1, ("MOBIKE address update done"));

 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}

void
ssh_pm_mobike_initiator_continue_address_update(SshPm pm,
                                                SshPmMobike ctx)
{
  ctx->flags &= ~SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED;

  ssh_fsm_set_thread_name(ctx->thread, "Mobike initiator continued");

  ssh_fsm_thread_init(&pm->fsm, ctx->thread,
                      ssh_pm_st_mobike_i_start,
                      NULL, pm_mobike_i_destructor, ctx);
}


SSH_FSM_STEP(ssh_pm_st_mobike_i_start)
{
  SSH_DEBUG(SSH_D_MIDOK, ("Mobike initiator address update thread start."));
  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_address_update);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_address_update)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = ctx->p1;
  int slot;
  SshIkev2ExchangeData ed = NULL;
  SshUInt32 flags = 0;
  SshPmInfo info = NULL;
  SshIkev2Server server;
  Boolean use_natt;
  SshIpAddrStruct remote_ip;
  SshUInt16 remote_port;

  PM_SUSPEND_CONDITION_WAIT(pm, thread);

  SSH_ASSERT(ctx->aborted == 0);

  SSH_DEBUG(SSH_D_MIDOK, ("Starting mobike address update."));

  if (p1->unusable)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Cannot use this IKE SA for sending address update."));
      ctx->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      goto error;
    }

  if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Window full. Cannot send address update."));
      ctx->error = SSH_IKEV2_ERROR_WINDOW_FULL;
      goto error;
    }

  flags |= SSH_IKEV2_INFO_CREATE_FLAGS_REQUEST_ADDRESSES;
  if (ctx->flags & SSH_PM_MOBIKE_FLAGS_PROBE)
    flags |= SSH_IKEV2_INFO_CREATE_FLAGS_PROBE_MESSAGE;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Info exchange flags 0x%lx",
                               (unsigned long) flags));

  ed = ssh_ikev2_info_create(p1->ike_sa, flags);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not allocate exchange data for address update."));
      ctx->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  info = ssh_pm_info_alloc(pm, ed, SSH_PM_ED_DATA_INFO_MOBIKE);
  if (info == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate info exchange context."));
      ctx->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  info->u.mobike = ctx;

  ctx->error = ssh_ikev2_info_add_n(ed, SSH_IKEV2_PROTOCOL_ID_NONE, 0, 0,
                                    SSH_IKEV2_NOTIFY_UPDATE_SA_ADDRESSES,
                                    NULL, 0);
  if (ctx->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not add address update notification."));
      goto error;
    }

  /* Explicitly set local IKE server, remote IP address and remote port for
     the address update informational exchange, otherwise the IKEv2 library
     will use the current IKE SA addresses for NAT-D payloads and additional
     address list. If we are probing the address pair with highest precedence,
     then we use the address pair with address_index 0. Otherwise address_index
     has been bumped up when the address update was restarted. */
  if (ctx->flags & (SSH_PM_MOBIKE_FLAGS_PROBE
                    | SSH_PM_MOBIKE_FLAGS_FORCE_ADDRESSES))
    {
      ctx->error = ssh_pm_mobike_get_address_pair(pm, p1, ctx->address_index,
                                                  &server, &remote_ip);
      if (ctx->error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not get address pair for address update "
                     "informational exchange."));
          goto error;
        }

      SSH_ASSERT(server != NULL);
      SSH_ASSERT(SSH_IP_DEFINED(server->ip_address));

      remote_port = SSH_PM_IKE_SA_REMOTE_PORT(p1->ike_sa);

      if (p1->ike_sa->flags &
          (SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE
           | SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T))
        use_natt = TRUE;
      else
        use_natt = FALSE;

      ssh_ikev2_info_use_addresses(ed, server, use_natt,
                                   &remote_ip, remote_port);
    }
  ed->application_context = info;

  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_address_update_result);
  SSH_FSM_ASYNC_CALL({
      ctx->non_abortable = 0;
      PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
                        ssh_ikev2_info_send(ed,
                                            pm_mobike_address_update_done_cb));
    });
  SSH_NOTREACHED;

 error:
  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
  if (ed)
    ssh_ikev2_info_destroy(ed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_address_update_result)
{
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPm pm = (SshPm) fsm_context;
  SshUInt32 flags = 0;

  PM_SUSPEND_CONDITION_WAIT(pm, thread);

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->error == SSH_IKEV2_ERROR_OK)
    {
      if (ctx->multiple_addresses_used)
        {
          SshIkev2Server server;

          SSH_DEBUG(SSH_D_MIDOK,
                    ("Address update exchange used multiple addresses"));

          ctx->retry_count++;
          if (ctx->retry_count >= SSH_PM_MOBIKE_ADDRESS_UPDATE_MAX_RETRY_COUNT)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Address update retry limit %d reached, "
                         "failing operation",
                         ctx->retry_count));
              SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
              return SSH_FSM_CONTINUE;
            }

          /* Move the IKE SA to use new addresses. Note that eventhough
             the address update succeeded with multiple_addresses_used,
             the restarted address update using this address pair may
             still fail with UNEXPECTED_NAT_DETECTED. The original IKE
             SA address pair is stored in ctx->old_[local|remote]_ip
             so that we can later move the IKE SA back to original
             address pair if necessary. */
          server = ssh_pm_mobike_get_ike_server(pm, ctx->tunnel,
                                                ctx->local_ip,
                                                ctx->local_port);

          if (server == NULL
              || !ssh_pm_mobike_update_p1_addresses(pm, ctx->p1,
                                                    server,
                                                    ctx->remote_ip,
                                                    ctx->remote_port,
                                                    ctx->natt_flags))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Unable to restart address update"));
              SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
              return SSH_FSM_CONTINUE;
            }

          SSH_DEBUG(SSH_D_MIDOK, ("Restarting address update."));

          ctx->multiple_addresses_used = 0;
          ctx->natt_flags = 0;
          ctx->flags &= ~SSH_PM_MOBIKE_FLAGS_PROBE;

          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_start);
        }
      else if (ctx->p1->address_update_pending)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Restarting pending address update."));

          ctx->p1->address_update_pending = 0;
          ctx->retry_count = 0;
          ctx->natt_flags = 0;

          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_start);
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Address update exchange succeeded."));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_update_ike_sa);
        }
    }
  else if (ctx->error == SSH_IKEV2_ERROR_UNEXPECTED_NAT_DETECTED)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Address update exchange failed with %s (%d)",
                              ssh_ikev2_error_to_string(ctx->error),
                              ctx->error));

      ctx->retry_count++;
      if (ctx->retry_count >= SSH_PM_MOBIKE_ADDRESS_UPDATE_MAX_RETRY_COUNT)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Address update retry limit %d reached, "
                     "failing operation",
                     ctx->retry_count));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
          return SSH_FSM_CONTINUE;
        }

      /* If address update did not use multiple addresses, then update
         the IKE SA to request next address pair for the next exchange.
         Otherwise force IKE SA to start requesting addresses from policy
         manager using the current address pair. */
      if (ctx->multiple_addresses_used == 0)
        flags = SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_NEXT_ADDRESS_PAIR;
      else
        flags = SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REQUEST_ADDRESSES;

      if (ssh_ikev2_ike_sa_change_addresses(ctx->p1->ike_sa, NULL, NULL, 0,
                                            flags) != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Unable to restart address update"));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
          return SSH_FSM_CONTINUE;
        }

      /* Mark that the address update must use the next address pair
         for calculating NAT-D payloads and the additional address list. */
      ctx->address_index = ctx->p1->ike_sa->address_index;
      ctx->flags |= SSH_PM_MOBIKE_FLAGS_FORCE_ADDRESSES;

      SSH_DEBUG(SSH_D_MIDOK,
                ("Restarting address update using %s address pair %d.",
                 ctx->multiple_addresses_used ? "current" : "next",
                 ctx->address_index));

      ctx->multiple_addresses_used = 0;
      ctx->natt_flags = 0;
      ctx->flags &= ~SSH_PM_MOBIKE_FLAGS_PROBE;

      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_start);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Address update exchange failed with %s (%d)",
                              ssh_ikev2_error_to_string(ctx->error),
                              ctx->error));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_update_ike_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshIkev2Server server;

  SSH_ASSERT(ctx->aborted == 0);
  SSH_ASSERT(ctx->multiple_addresses_used == 0);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Updating addresses for IKE SA %p", ctx->p1->ike_sa));

  server = ssh_pm_mobike_get_ike_server(pm, ctx->tunnel,
                                        ctx->local_ip, ctx->local_port);

  if (!server ||
      !ssh_pm_mobike_update_p1_addresses(pm, ctx->p1, server,
                                         ctx->remote_ip, ctx->remote_port,
                                         ctx->natt_flags))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA update failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Update succeeded."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_update_ipsec_sa);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_update_ipsec_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = ctx->p1;
  SshPmPeer peer;
  Boolean enable_natt, enable_tcpencap = FALSE;

  SSH_ASSERT(ctx->aborted == 0);

  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_update_ipsec_sa_result);

  peer = ssh_pm_peer_by_p1(pm, p1);
  if (peer == NULL)
    {
      /* No IPsec SAs to update. */
      ctx->ipsec_sa_updated = 1;
      return SSH_FSM_CONTINUE;
    }

  enable_natt = ctx->natt_flags ? TRUE: FALSE;
#ifdef SSH_IPSEC_TCPENCAP
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    enable_tcpencap = TRUE;
#endif /* SSH_IPSEC_TCPENCAP */

  SSH_DEBUG(SSH_D_MIDOK, ("Updating addresses for IPsec SAs, "
                          "local %@:%d remote %@:%d, NATT flags %x, "
                          "routing instance id %d",
                          ssh_ipaddr_render, ctx->local_ip,
                          ctx->natt_flags ? ctx->local_port : 0,
                          ssh_ipaddr_render, ctx->remote_ip,
                          ctx->remote_port, ctx->natt_flags,
                          peer->routing_instance_id));

  /* Indicate that IPsec SAs have been updated. */
  ssh_pm_ipsec_sa_event_peer_updated(pm, peer, enable_natt, enable_tcpencap);

#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_ASYNC_CALL({
    ctx->non_abortable = 1;
    ssh_pme_update_by_peer_handle(pm->engine,
                                  peer->peer_handle, enable_natt,
                                  peer->routing_instance_id,
                                  ctx->local_ip,
                                  ctx->remote_ip, ctx->remote_port,
                                  (enable_tcpencap ?
                                   p1->ike_sa->ike_spi_i : NULL),
                                  pm_mobike_update_ipsec_sa_cb, ctx); });
#else /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_ASYNC_CALL({
    ctx->non_abortable = 1;
    ssh_pme_update_by_peer_handle(pm->engine,
                                  peer->peer_handle, enable_natt,
                                  peer->routing_instance_id,
                                  ctx->local_ip,
                                  ctx->remote_ip, ctx->remote_port,
                                  pm_mobike_update_ipsec_sa_cb, ctx); });
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_update_ipsec_sa_result)
{
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->ipsec_sa_updated)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA update succeeded."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_success);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA update failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_i_failed);
      ctx->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_success)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_ASSERT(ctx->aborted == 0);

  SSH_DEBUG(SSH_D_MIDOK, ("Mobike address update succeeded."));

  if (ctx->callback)
    (*ctx->callback)(pm, ctx->p1, TRUE, ctx->context);

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_mobike_i_failed)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshIkev2Server server;
  SshUInt32 natt_flags = 0;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Mobike initiator address update failure, error 0x%x",
             ctx->error));

  if (ctx->aborted == 0)
    {
      if (ctx->error == SSH_IKEV2_ERROR_WINDOW_FULL)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Suspending address update until IKE finishes."));
          ctx->flags |= SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED;
          SSH_ASSERT(ctx->p1->mobike_suspended_operation == NULL);
          ctx->p1->mobike_suspended_operation = ctx;
          ctx->p1->mobike_suspended_op_type =
            SSH_PM_MOBIKE_OP_INITIATOR_ADDRESS_UPDATE;
          return SSH_FSM_FINISH;
        }

      /* Check if IKE SA needs to be moved back to original addresses. */
      if (ctx->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        natt_flags |= SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;

      if (ctx->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
        natt_flags |=
          SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

      server = ssh_pm_mobike_get_ike_server(pm, ctx->tunnel,
                                            ctx->old_local_ip,
                                            ctx->old_local_port);

      if (server != ctx->p1->ike_sa->server
          || !SSH_IP_EQUAL(ctx->p1->ike_sa->remote_ip, ctx->old_remote_ip)
          || (ctx->p1->ike_sa->remote_port != ctx->old_remote_port)
          || (natt_flags != ctx->old_natt_flags))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Restoring original IKE SA addresses"));

          if (server == NULL
              || !ssh_pm_mobike_update_p1_addresses(pm, ctx->p1,
                                                    server,
                                                    ctx->old_remote_ip,
                                                    ctx->old_remote_port,
                                                    ctx->old_natt_flags))
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Unable to restore original IKE SA addresses for "
                         "IKE SA %p",
                         ctx->p1->ike_sa));
            }
        }

      if (ctx->callback)
        (*ctx->callback)(pm, ctx->p1, FALSE, ctx->context);
    }

  return SSH_FSM_FINISH;
}


/*************************** Performing address update ***********************/

SshOperationHandle
ssh_pm_mobike_initiator_address_update(SshPm pm,
                                       SshPmP1 p1,
                                       SshIkev2ExchangeData ed,
                                       SshPmTunnel tunnel,
                                       SshUInt32 flags,
                                       SshPmMobikeStatusCB callback,
                                       void *context)
{
  SshPmMobike ctx = NULL;

  /* This should be called only for MobIKE enabled IKE SAs. */
  SSH_ASSERT(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_DEBUG(SSH_D_LOWSTART, ("MobIKE initiator address update entered"));

  ctx = ssh_pm_mobike_alloc(pm, p1);
  if (ctx == NULL)
    goto error;

  ctx->callback = callback;
  ctx->context = context;
  ctx->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(ctx->tunnel);
  ctx->flags = flags;

  ssh_fsm_thread_init(&pm->fsm, ctx->thread, ssh_pm_st_mobike_i_start,
                      NULL, pm_mobike_i_destructor, ctx);
  ssh_fsm_set_thread_name(ctx->thread, "Mobike initiator");
  ssh_operation_register_no_alloc(ctx->op, pm_mobike_i_abort, ctx);

  return ctx->op;

 error:
 SSH_DEBUG(SSH_D_FAIL, ("MobIKE initiator address update failed"));
  if (callback)
    (*callback)(pm, p1, FALSE, context);
  return NULL;
}


/************************************ Responder ******************************/

void pm_mobike_r_abort(void *operation_context)
{
  SshPmMobike ctx = (SshPmMobike) operation_context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Mobike responder address update thread aborted."));

  /* Address update was suspended, thread does not exist, just free ctx. */
  if (ctx->flags & SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED)
    {
      SSH_ASSERT(ctx->p1->mobike_suspended_operation == ctx);
      ctx->p1->mobike_suspended_operation = NULL;
      ctx->p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_NOT_SUSPENDED;
      ssh_pm_mobike_free(ctx->pm, ctx);
      return;
    }

  /* Address update was ongoing, go to failed state. */
  ctx->aborted = 1;
  ssh_fsm_set_next(ctx->thread, ssh_pm_st_mobike_r_failed);

  /* Check if waiting for an async op completion. This thread may be waiting
     for a non-abortable engine call completion. In such case we let the
     engine call complete and continue the thread to the failure state.
     Otherwise this thread was waiting for an IKE informational exchange
     completion. Those exchanges are aborted by the caller of this function
     so this thread must not wait for the completion but continue immediately
     to failure state. */
  if (ctx->non_abortable == 0)
    {
      if (ssh_fsm_get_callback_flag(ctx->thread))
        SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
      else
        ssh_fsm_continue(ctx->thread);
    }
}

void pm_mobike_r_destructor(SshFSM fsm, void *context)
{
  SshPmMobike ctx = (SshPmMobike) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Mobike responder address update thread destructor."));

  if ((ctx->flags & SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED) == 0)
    {
      if (!ctx->aborted)
        ssh_operation_unregister(ctx->op);

      ssh_pm_mobike_free(pm, ctx);
    }
}




















static void pm_mobike_rrc_done_cb(SshSADHandle sad_handle,
                                  SshIkev2Sa ike_sa,
                                  SshIkev2ExchangeData ed,
                                  SshIkev2Error error)
{
  SshPmInfo info = (SshPmInfo) ed->application_context;
  SshPm pm = sad_handle->pm;
  SshPmMobike ctx;

  PM_IKE_ASYNC_CALL_COMPLETE(ike_sa, ed);

  SSH_ASSERT(info != NULL);
  SSH_ASSERT(info->type == SSH_PM_ED_DATA_INFO_MOBIKE);

  ctx = info->u.mobike;

  /* Clear application context. */
  SSH_PM_ASSERT_ED(ed);
  ed->application_context = NULL;

  /* The IKE SA is updated after the informational exchange since
     the message ID's of the IKE SA is updated. */
  ssh_pm_ike_sa_event_updated(pm, ctx->p1);

  /* This should never happen. */
  if (ctx->aborted)
    return;

  /* Store error. */
  ctx->error = error;

  /* Store multiple_addresses_used. */
  ctx->multiple_addresses_used = ed->multiple_addresses_used;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}

static SshFSMStepStatus pm_mobike_r_rrc(SshPm pm,
                                        SshPmP1 p1,
                                        SshFSMThread thread,
                                        SshPmMobike ctx)
{
  SshIkev2ExchangeData ed = NULL;
  int slot;
  SshPmInfo info = NULL;
  SshUInt32 flags;

  SSH_ASSERT(ctx->aborted == 0);
  SSH_ASSERT(ctx->rrc_policy & (SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE
                                | SSH_PM_MOBIKE_POLICY_RRC_AFTER_SA_UPDATE));

  SSH_DEBUG(SSH_D_MIDOK,
            ("Performing return routability check for IKE SA %p "
             "local %@:%d remote %@:%d",
             p1->ike_sa,
             ssh_ipaddr_render, &p1->ike_sa->server->ip_address,
             SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
             ssh_ipaddr_render, p1->ike_sa->remote_ip,
             p1->ike_sa->remote_port));

  if (p1->unusable)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Cannot use this IKE SA for return routability check."));
      ctx->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      goto error;
    }

  if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("IKE is busy, delaying return routability check"));
      ctx->error = SSH_IKEV2_ERROR_WINDOW_FULL;
      goto error;
    }

  flags = 0;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Info exchange flags 0x%lx",
                               (unsigned long) flags));

  ed = ssh_ikev2_info_create(p1->ike_sa, flags);
  if (ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate exchange data for "
                             "return routability check."));
      ctx->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }

  info = ssh_pm_info_alloc(pm, ed, SSH_PM_ED_DATA_INFO_MOBIKE);
  if (info == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate info exchange context."));
      ctx->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error;
    }
  info->u.mobike = ctx;

  ed->application_context = info;

  SSH_FSM_ASYNC_CALL({
    ctx->non_abortable = 0;
    PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
                      ssh_ikev2_info_send(ed,
                                          pm_mobike_rrc_done_cb));
  });
  SSH_NOTREACHED;

 error:
  if (ed)
    ssh_ikev2_info_destroy(ed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_start)
{
  SSH_DEBUG(SSH_D_MIDOK, ("Mobike responder address update thread start."));
  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_update_ike_sa);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_update_ike_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = ctx->p1;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->rrc_policy & SSH_PM_MOBIKE_POLICY_NO_RRC)
    SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_update_ipsec_sa);
  else
    SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_check_rrc);

  if ((ctx->flags & SSH_PM_MOBIKE_FLAGS_NO_IKE_SA_UPDATE) == 0)
    {
      SshIkev2Server server = ssh_pm_mobike_get_ike_server(pm,
                                                           ctx->tunnel,
                                                           ctx->local_ip,
                                                           ctx->local_port);
      if (!server ||
          !ssh_pm_mobike_update_p1_addresses(pm, p1, server,
                                             ctx->remote_ip, ctx->remote_port,
                                             ctx->natt_flags))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE SA update failed."));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_failed);
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Update succeeded."));
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_check_rrc)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_ASSERT(ctx->aborted == 0);

  /* Set rrc policy, unless rrc is to be skipped. */
  if ((ctx->rrc_policy & SSH_PM_MOBIKE_POLICY_NO_RRC) == 0)
    {





















        ctx->rrc_policy = pm->mobike_rrc_policy;
    }

#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_get_ike_mapping);
#else /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_pre_rrc);
#endif /* SSH_IPSEC_TCPENCAP */
  return SSH_FSM_CONTINUE;
}

#ifdef SSH_IPSEC_TCPENCAP
void
pm_mobike_r_get_ike_mapping_cb(SshPm pm, SshUInt32 conn_id, void *context)
{
  SshPmMobike ctx = context;

  /* Mark non-abortable sub operation completed. */
  ctx->non_abortable = 0;

  if (conn_id != SSH_IPSEC_INVALID_INDEX)
    ctx->p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_get_ike_mapping)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = ctx->p1;

  SSH_ASSERT(ctx->aborted == 0);
  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_pre_rrc);

  if (p1->compat_flags & SSH_PM_COMPAT_TCPENCAP)
    {
      /* Fetch encapsulating TCP connection ID from the engine. */
      SSH_FSM_ASYNC_CALL({
        ctx->non_abortable = 1;
        ssh_pme_tcp_encaps_get_ike_mapping(pm->engine,
                                           ctx->local_ip,
                                           ctx->remote_ip,
                                           p1->ike_sa->ike_spi_i,
                                           pm_mobike_r_get_ike_mapping_cb,
                                           ctx);
      });
      SSH_NOTREACHED;
    }

  return SSH_FSM_CONTINUE;
}
#endif /* SSH_IPSEC_TCPENCAP */

SSH_FSM_STEP(ssh_pm_st_mobike_r_pre_rrc)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->rrc_policy & SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE)
    {
      PM_SUSPEND_CONDITION_WAIT(pm, thread);

      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_pre_rrc_result);
      return pm_mobike_r_rrc(pm, ctx->p1, thread, ctx);
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_update_ipsec_sa);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_pre_rrc_result)
{
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = (SshPmP1) ctx->p1;
  SshUInt32 natt_flags;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->error == SSH_IKEV2_ERROR_WINDOW_FULL)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Suspending address update until IKE finishes."));
      ctx->flags |= SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED;
      SSH_ASSERT(p1->mobike_suspended_operation == NULL);
      p1->mobike_suspended_operation = ctx;
      p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_RESPONDER_ADDRESS_UPDATE;
      return SSH_FSM_FINISH;
    }
  else if (ctx->error != SSH_IKEV2_ERROR_OK
           || (ctx->multiple_addresses_used && p1->rrc_pending == 0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Return routability check failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_failed);
    }
  else
    {
      /* Check if we have received an address update while doing rrc. */
      natt_flags = 0;
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        natt_flags |= SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
        natt_flags |=
          SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

      p1->rrc_pending = 0;

      if (!SSH_IP_EQUAL(p1->ike_sa->remote_ip, ctx->remote_ip)
          || !SSH_IP_EQUAL(p1->ike_sa->server->ip_address, ctx->local_ip)
          || p1->ike_sa->remote_port != ctx->remote_port
          || SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa) != ctx->local_port
          || natt_flags != ctx->natt_flags)
        {
          /* Yes we have, redo rrc. */

          /* Store fresh address information to mobike context. */
          *ctx->remote_ip = *p1->ike_sa->remote_ip;
          *ctx->local_ip = *p1->ike_sa->server->ip_address;
          ctx->local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
          ctx->remote_port = p1->ike_sa->remote_port;
          ctx->natt_flags = natt_flags;

          SSH_DEBUG(SSH_D_MIDOK, ("Restarting return routability check."));
#ifdef SSH_IPSEC_TCPENCAP
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_get_ike_mapping);
#else /* SSH_IPSEC_TCPENCAP */
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_pre_rrc);
#endif /* SSH_IPSEC_TCPENCAP */
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Return routability check succeeded."));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_update_ipsec_sa);
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_update_ipsec_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmPeer peer;
  SshIpAddrStruct local_ip, remote_ip;
  SshUInt16 remote_port;
  Boolean enable_natt;
  Boolean enable_tcpencap = FALSE;

  SSH_ASSERT(ctx->aborted == 0);

  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_update_ipsec_sa_result);

  peer = ssh_pm_peer_by_p1(pm, ctx->p1);
  if (peer == NULL)
    {
      /* No IPsec SAs to update. */
      ctx->ipsec_sa_updated = 1;
      return SSH_FSM_CONTINUE;
    }

  local_ip = *ctx->p1->ike_sa->server->ip_address;
  remote_ip = *ctx->p1->ike_sa->remote_ip;
  remote_port = ctx->p1->ike_sa->remote_port;
  enable_natt = ctx->natt_flags ? TRUE: FALSE;

  SSH_DEBUG(SSH_D_MIDOK, ("Updating addresses for IPsec SAs, "
                          "local %@:%d remote %@:%d, natt_flags=%x, "
                          "routing instance id %d",
                          ssh_ipaddr_render, &local_ip,
                          SSH_PM_IKE_SA_LOCAL_PORT(ctx->p1->ike_sa),
                          ssh_ipaddr_render, &remote_ip,
                          remote_port, ctx->natt_flags,
                          peer->routing_instance_id));

#ifdef SSH_IPSEC_TCPENCAP
  if (ctx->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    enable_tcpencap = TRUE;
#endif /* SSH_IPSEC_TCPENCAP */

  /* Indicate that IPsec SAs have been updated. */
  ssh_pm_ipsec_sa_event_peer_updated(pm, peer, enable_natt, enable_tcpencap);

#ifdef SSH_IPSEC_TCPENCAP
  SSH_FSM_ASYNC_CALL({
    ctx->non_abortable = 1;
    ssh_pme_update_by_peer_handle(pm->engine,
                                  peer->peer_handle, enable_natt,
                                  peer->routing_instance_id,
                                  &local_ip,
                                  &remote_ip, remote_port,
                                  (enable_tcpencap ?
                                   ctx->p1->ike_sa->ike_spi_i : NULL),
                                  pm_mobike_update_ipsec_sa_cb, ctx); });
#else /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_ASYNC_CALL({
    ctx->non_abortable = 1;
    ssh_pme_update_by_peer_handle(pm->engine,
                                  peer->peer_handle, enable_natt,
                                  peer->routing_instance_id,
                                  &local_ip,
                                  &remote_ip, remote_port,
                                  pm_mobike_update_ipsec_sa_cb, ctx); });
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_update_ipsec_sa_result)
{
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->ipsec_sa_updated)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA update succeeded."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_post_rrc);
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("IPsec SA update failed."));
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_failed);
      ctx->error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_post_rrc)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->rrc_policy & SSH_PM_MOBIKE_POLICY_RRC_AFTER_SA_UPDATE)
    {
      PM_SUSPEND_CONDITION_WAIT(pm, thread);

      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_post_rrc_result);
      return pm_mobike_r_rrc(pm, ctx->p1, thread, ctx);
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_success);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_post_rrc_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = (SshPmP1) ctx->p1;
  SshPmPeer peer;
  SshUInt32 peer_handle = SSH_IPSEC_INVALID_INDEX;
  SshUInt16 remote_port;
  SshUInt32 natt_flags;
  Boolean enable_natt;
  Boolean enable_tcpencap = FALSE;
  SshVriId routing_instance_id = SSH_INTERCEPTOR_VRI_ID_ANY;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->error == SSH_IKEV2_ERROR_WINDOW_FULL)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Suspending address update until IKE finishes."));
      ctx->flags |= SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED;
      SSH_ASSERT(p1->mobike_suspended_operation == NULL);
      p1->mobike_suspended_operation = ctx;
      p1->mobike_suspended_op_type = SSH_PM_MOBIKE_OP_RESPONDER_ADDRESS_UPDATE;
      return SSH_FSM_FINISH;
    }
  else if (ctx->error != SSH_IKEV2_ERROR_OK
           || (ctx->multiple_addresses_used && p1->rrc_pending == 0))
    {
      /* RRC failed, need to move IPsec SA back to old addresses. */

      enable_natt = ctx->old_natt_flags ? TRUE: FALSE;
      remote_port = ctx->old_remote_port;

      SSH_DEBUG(SSH_D_FAIL,
                ("Return routability check failed, "
                 "restoring addresses for IPsec SAs, local %@:%d remote %@:%d",
                 ssh_ipaddr_render, ctx->old_local_ip, ctx->old_local_port,
                 ssh_ipaddr_render, ctx->old_remote_ip, ctx->old_remote_port));

      ssh_pm_log_p1_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          p1, "MOBIKE return routability check failed", FALSE);

      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_failed);

      peer = ssh_pm_peer_by_p1(pm, p1);
      if (peer)
        {
          peer_handle = peer->peer_handle;
          routing_instance_id = peer->routing_instance_id;
        }

#ifdef SSH_IPSEC_TCPENCAP
      if (ctx->old_use_tcp_encaps)
        enable_tcpencap = TRUE;
#endif /* SSH_IPSEC_TCPENCAP */

      /* Indicate that IPsec SAs have been updated. */
      ssh_pm_ipsec_sa_event_peer_updated(pm, peer, enable_natt,
                                         enable_tcpencap);

#ifdef SSH_IPSEC_TCPENCAP
      SSH_FSM_ASYNC_CALL({
        ctx->non_abortable = 1;
        ssh_pme_update_by_peer_handle(pm->engine,
                                      peer_handle,
                                      enable_natt,
                                      routing_instance_id,
                                      ctx->old_local_ip,
                                      ctx->old_remote_ip,
                                      remote_port,
                                      (enable_tcpencap ?
                                       ctx->p1->ike_sa->ike_spi_i : NULL),
                                      pm_mobike_update_ipsec_sa_cb,
                                      ctx); });
#else /* SSH_IPSEC_TCPENCAP */
      SSH_FSM_ASYNC_CALL({
        ctx->non_abortable = 1;
        ssh_pme_update_by_peer_handle(pm->engine,
                                      peer_handle,
                                      enable_natt,
                                      routing_instance_id,
                                      ctx->old_local_ip,
                                      ctx->old_remote_ip,
                                      remote_port,
                                      pm_mobike_update_ipsec_sa_cb,
                                      ctx); });
#endif /* SSH_IPSEC_TCPENCAP */
      SSH_NOTREACHED;
    }
  else
    {
      /* Check if we have received an address update while doing rrc. */

      natt_flags = 0;
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT)
        natt_flags |= SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT)
        natt_flags |=
          SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

      p1->rrc_pending = 0;

      if (!SSH_IP_EQUAL(p1->ike_sa->remote_ip, ctx->remote_ip)
          || !SSH_IP_EQUAL(p1->ike_sa->server->ip_address, ctx->local_ip)
          || p1->ike_sa->remote_port != ctx->remote_port
          || SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa) != ctx->local_port
          || natt_flags != ctx->natt_flags)

        {
          /* Yes we have, update IPsec SAs and redo rrc. */

          /* Store fresh address information to mobike context. */
          *ctx->remote_ip = *p1->ike_sa->remote_ip;
          *ctx->local_ip = *p1->ike_sa->server->ip_address;
          ctx->remote_port = p1->ike_sa->remote_port;
          ctx->local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
          ctx->natt_flags = natt_flags;

          SSH_DEBUG(SSH_D_MIDOK, ("Restarting return routability check."));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_update_ipsec_sa);
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Return routability check succeeded."));
          SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_success);
        }
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_success)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Mobike responder address update succeeded."));

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->callback)
    (*ctx->callback)(pm, ctx->p1, TRUE, ctx->context);

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_failed)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshIkev2Server server;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Mobike responder address update failure, error 0x%x",
             ctx->error));

  if (ctx->aborted == 0)
    {
      server = ssh_pm_mobike_get_ike_server(pm, ctx->tunnel,
                                            ctx->old_local_ip,
                                            ctx->old_local_port);

      /* Restore original IKE SA addresses from ctx. */
      if (server)
        (void) ssh_pm_mobike_update_p1_addresses(pm, ctx->p1,
                                          server,
                                          ctx->old_remote_ip,
                                          ctx->old_remote_port,
                                          ctx->old_natt_flags);

      if (ctx->callback)
        (*ctx->callback)(pm, ctx->p1, FALSE, ctx->context);
    }

  return SSH_FSM_FINISH;
}

/*************************** Receiving address updates ***********************/

SshOperationHandle
ssh_pm_mobike_responder_address_update(SshPm pm,
                                       SshPmP1 p1,
                                       SshIkev2ExchangeData ed,
                                       SshPmMobikeStatusCB callback,
                                       void *context)
{
  SshPmMobike ctx;
  SshPmTunnel tunnel;

  /* This should be called only for MobIKE enabled IKE SAs. */
  SSH_ASSERT(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    {
      if (callback)
        (*callback)(pm, p1, FALSE, context);
      return NULL;
    }

  ctx = ssh_pm_mobike_alloc(pm, p1);
  if (ctx == NULL)
    {
      if (callback)
        (*callback)(pm, p1, FALSE, context);
      return NULL;
    }

  ctx->callback = callback;
  ctx->context = context;

  *ctx->local_ip = *ed->server->ip_address;
  *ctx->remote_ip = *ed->remote_ip;
  ctx->local_port = SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa);
  ctx->remote_port = ed->remote_port;

  ctx->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(ctx->tunnel);

   if (ed->info_ed->local_end_behind_nat)
    ctx->natt_flags |=
      SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT;

  if (ed->info_ed->remote_end_behind_nat)
    ctx->natt_flags |=
      SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT;

  ssh_fsm_thread_init(&pm->fsm, ctx->thread, ssh_pm_st_mobike_r_start,
                      NULL, pm_mobike_r_destructor, ctx);
  ssh_fsm_set_thread_name(ctx->thread, "Mobike responder");
  ssh_operation_register_no_alloc(ctx->op, pm_mobike_r_abort, ctx);

  return ctx->op;
}


void
ssh_pm_mobike_responder_continue_address_update(SshPm pm,
                                                SshPmMobike ctx)
{
  /* This should be called only for MobIKE enabled IKE SAs. */
  SSH_ASSERT(ctx->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  ctx->flags &= ~SSH_PM_MOBIKE_FLAGS_OPERATION_SUSPENDED;
  ctx->flags |= SSH_PM_MOBIKE_FLAGS_NO_IKE_SA_UPDATE;

  ssh_fsm_set_thread_name(ctx->thread, "Mobike responder continued");

  ssh_fsm_thread_init(&pm->fsm, ctx->thread,
                      ssh_pm_st_mobike_r_start,
                      NULL, pm_mobike_r_destructor, ctx);
}


/************************** Forced Responder SA Update ***********************/

static void
pm_mobike_r_route_remote_cb(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
                            const SshIpAddr nexthop, size_t mtu, void *context)
{
  SshPmMobike ctx = (SshPmMobike) context;
  SshInterceptorInterface *ifp;
  SshUInt32 i;
  SshPmTunnelLocalIp local_ip;
  SshIkev2Server server;

  /* Mark non-abortable sub operation completed. */
  ctx->non_abortable = 0;

  if (ctx->aborted)
    goto out;

  if ((flags & SSH_PME_ROUTE_REACHABLE) == 0)
    goto out;

  /* Remote is reachable, lookup suitable local_ip from interface `ifnum'. */
  ifp = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (!ifp)
    goto out;

  for (local_ip = ctx->tunnel->local_ip;
       local_ip != NULL;
       local_ip = local_ip->next)
    {
      if (local_ip->unavailable)
        continue;

      for (i = 0; i < ifp->num_addrs; i++)
        {
          if (SSH_IP_EQUAL(&local_ip->ip, &ifp->addrs[i].addr.ip.ip)
              && ((SSH_IP_IS4(&local_ip->ip) && SSH_IP_IS4(ctx->remote_ip))
                  || (SSH_IP_IS6(&local_ip->ip) && SSH_IP_IS6(ctx->remote_ip))
                  ))
            {
              /* Found matching local_ip, check if need to reselect
                 IKE server. */
              if (!SSH_IP_EQUAL(&local_ip->ip, ctx->local_ip))
                {
                  server =
                    ssh_pm_mobike_get_ike_server(pm, ctx->tunnel,
                                                 &local_ip->ip,
                                                 ctx->tunnel->local_port);
                  if (server)
                    {
                      SshUInt32 natt_flags;
                      *ctx->local_ip = *server->ip_address;

                      ctx->local_port =
                        SSH_PM_IKE_SA_LOCAL_PORT(ctx->p1->ike_sa);

                      if (ctx->p1->ike_sa->flags &
                          SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
                        {
                          ctx->remote_port = server->nat_t_remote_port;
                        }
                      else
                        {
                          ctx->remote_port = server->normal_remote_port;
                        }
                      (void)ssh_pm_mobike_get_exchange_natt_flags(ctx->p1,
                                                                  NULL,
                                                                  &natt_flags);


                      if (ssh_pm_mobike_update_p1_addresses(pm, ctx->p1,
                                                            server,
                                                            ctx->remote_ip,
                                                            ctx->remote_port,
                                                            natt_flags))
                        ctx->flags |= SSH_PM_MOBIKE_FLAGS_REMOTE_REACHABLE;
                    }
                  else
                    SSH_DEBUG(SSH_D_FAIL, ("No IKE server running on %@:%d",
                                           ssh_ipaddr_render, &local_ip->ip,
                                           ctx->tunnel->local_port));
                }
              else
                {
                  ctx->flags |= SSH_PM_MOBIKE_FLAGS_REMOTE_REACHABLE;
                  goto out;
                }
            }
        }
    }

 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(ctx->thread);
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_route_remote)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshInterceptorRouteKeyStruct key;

  SSH_ASSERT(ctx->aborted == 0);

  SSH_DEBUG(SSH_D_MIDOK, ("Looking up route to remote %@",
                          ssh_ipaddr_render, ctx->remote_ip));

  ssh_pm_create_route_key(pm, &key, NULL, ctx->remote_ip,
                          SSH_IPPROTO_UDP, 0, 0,
                          SSH_INVALID_IFNUM,
                          ctx->tunnel->routing_instance_id);

  SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_route_remote_result);
  SSH_FSM_ASYNC_CALL({
    ctx->non_abortable = 1;
    ssh_pme_route(pm->engine, 0, &key, pm_mobike_r_route_remote_cb, ctx);
  });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_mobike_r_route_remote_result)
{
  SshPmMobike ctx = (SshPmMobike) thread_context;
  SshPmP1 p1 = ctx->p1;
  SshUInt32 i;

  SSH_ASSERT(ctx->aborted == 0);

  if (ctx->flags & SSH_PM_MOBIKE_FLAGS_REMOTE_REACHABLE)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_start);

      SSH_DEBUG(SSH_D_MIDOK,
                ("Remote %@ is reachable using local %@",
                 ssh_ipaddr_render, ctx->remote_ip,
                 ssh_ipaddr_render, ctx->local_ip));
    }
  else
    {

      SSH_DEBUG(SSH_D_MIDOK, ("Remote %@ is unreachable",
                              ssh_ipaddr_render, ctx->remote_ip));

      ctx->address_index++;
      for (i = ctx->address_index;
           i < p1->ike_sa->num_additional_ip_addresses;
           i++)
        {
          if (ssh_pm_mobike_valid_address(&p1->ike_sa->
                                          additional_ip_addresses[i]))
            break;

          ctx->address_index++;
        }

      if (ctx->address_index >= p1->ike_sa->num_additional_ip_addresses)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No usable local IP address"));
          SSH_IP_UNDEFINE(ctx->remote_ip);
        }
      else
        {
          *ctx->remote_ip =
            p1->ike_sa->additional_ip_addresses[ctx->address_index];

          /* Clear flag so that IKE SA is updated to the selected addresses. */
          ctx->flags &= ~SSH_PM_MOBIKE_FLAGS_NO_IKE_SA_UPDATE;

          SSH_DEBUG(SSH_D_HIGHOK, ("Trying remote IP address '%@' index %d",
                                   ssh_ipaddr_render, ctx->remote_ip,
                                   ctx->address_index));
        }

      if (SSH_IP_DEFINED(ctx->remote_ip))
        SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_route_remote);
      else
        SSH_FSM_SET_NEXT(ssh_pm_st_mobike_r_failed);
    }

  return SSH_FSM_CONTINUE;
}

SshOperationHandle
ssh_pm_mobike_responder_forced_address_update(SshPm pm,
                                              SshPmP1 p1,
                                              SshPmTunnel tunnel,
                                              SshPmMobikeStatusCB callback,
                                              void *context)
{
  SshPmMobike ctx = NULL;
  SshPmTunnelLocalIp local_ip = NULL;
  SshIpAddr remote_ip = NULL;
  SshIkev2Server server;
  SshUInt32 natt_flags, i = 0;

  /* This should be called only for MobIKE enabled IKE SAs. */
  SSH_ASSERT(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED);

  SSH_DEBUG(SSH_D_HIGHOK, ("Forced responder address update for IKE SA %p",
                           p1->ike_sa));

  /* Lookup suitable address pair. */
  for (local_ip = tunnel->local_ip;
       local_ip != NULL;
       local_ip = local_ip->next)
    {
      /* Skip non-existent statically configured addresses. */
      if (local_ip->unavailable)
        continue;

      for (i = 0; i < p1->ike_sa->num_additional_ip_addresses; i++)
        {
          remote_ip = &p1->ike_sa->additional_ip_addresses[i];
          if (!ssh_pm_mobike_valid_address(remote_ip))
            continue;

          if ((SSH_IP_IS4(&local_ip->ip) && SSH_IP_IS4(remote_ip))
              || (SSH_IP_IS6(&local_ip->ip) && SSH_IP_IS6(remote_ip)))
            goto out;
        }
      remote_ip = NULL;
    }

 out:
  if (local_ip == NULL || remote_ip == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No usable address pairs for IKE SA %p",
                             p1->ike_sa));
      goto error;
    }

  ctx = ssh_pm_mobike_alloc(pm, p1);
  if (ctx == NULL)
    goto error;

  /* Set the index into the array of additional address of ctx->remote_ip.
     Special index of -1 denotes the address in the IKE SA. ctx->address_index
     is incremented after each failed route operation to select the next
     possible remote address to use. */
  if (SSH_IP_EQUAL(remote_ip, p1->ike_sa->remote_ip))
    {
      ctx->address_index = -1;
      ctx->remote_port = p1->ike_sa->remote_port;
    }
  else
    {
      SSH_ASSERT(i < p1->ike_sa->num_additional_ip_addresses);
      SSH_ASSERT(SSH_IP_EQUAL(remote_ip,
                              &p1->ike_sa->additional_ip_addresses[i]));
      ctx->address_index = i;
      ctx->remote_port = 0;
    }
  SSH_DEBUG(SSH_D_MY, ("Address index is %d, remote IP is %@",
                       ctx->address_index, ssh_ipaddr_render, remote_ip));

  ctx->callback = callback;
  ctx->context = context;
  ctx->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(ctx->tunnel);

  /* Skip rrc and just move the IPsec SAs. */
  ctx->rrc_policy = SSH_PM_MOBIKE_POLICY_NO_RRC;

  /* Skip IKE SA update in thread; IKE SA is updated synchronously below. */
  ctx->flags = SSH_PM_MOBIKE_FLAGS_NO_IKE_SA_UPDATE;

  server = ssh_pm_mobike_get_ike_server(pm, tunnel,
                                        &local_ip->ip,
                                        tunnel->local_port);
  if (server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No server running on %@:%d",
                             ssh_ipaddr_render, &local_ip->ip,
                             tunnel->local_port));
      goto error;
    }

  *ctx->local_ip = *server->ip_address;
  *ctx->remote_ip = *remote_ip;

  ctx->local_port = SSH_PM_IKE_SA_LOCAL_PORT(ctx->p1->ike_sa);
  if (ctx->remote_port == 0)
    {
      if (ctx->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
        ctx->remote_port = server->nat_t_remote_port;
      else
        ctx->remote_port = server->normal_remote_port;
    }

  (void)ssh_pm_mobike_get_exchange_natt_flags(p1, NULL, &natt_flags);

  /* Move the IKE SA synchronously to another server, as the IKE server
     may be shut down before address update thread is executed. */
  if (!ssh_pm_mobike_update_p1_addresses(pm, p1, server,
                                         ctx->remote_ip, ctx->remote_port,
                                         natt_flags))
    goto error;

  ssh_fsm_thread_init(&pm->fsm, ctx->thread, ssh_pm_st_mobike_r_route_remote,
                      NULL, pm_mobike_r_destructor, ctx);
  ssh_fsm_set_thread_name(ctx->thread, "Mobike forced responder");
  ssh_operation_register_no_alloc(ctx->op, pm_mobike_r_abort, ctx);

  return ctx->op;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Forced responder update immediate failure"));
  if (ctx)
    ssh_pm_mobike_free(pm, ctx);
  if (callback)
    (*callback)(pm, p1, FALSE, context);
  return NULL;
}

#endif /* SSHDIST_IPSEC_MOBIKE */
