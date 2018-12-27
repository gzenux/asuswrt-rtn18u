/**
   @copyright
   Copyright (c) 2007 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec related utility functions that use or depend on IKE.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "PmUtilIkeIPsec"

/* Tunnel mode is accepted unles explicitly forbidden by the policy. */
void
ssh_pm_qm_thread_compute_tunneling_attribute(SshPmQm qm)
{
  SSH_ASSERT(qm->tunnel != NULL);

  if (!(qm->tunnel->transform & SSH_PM_IPSEC_TUNNEL))
    qm->tunnel_accepted = 0;
  else
    qm->tunnel_accepted = 1;

  SSH_DEBUG(SSH_D_MIDOK, ("Setting the tunnel accepted attribute for "
                          "Quick-Mode %p to %d",
                          qm, qm->tunnel_accepted));
}


void ssh_pm_ike_parse_notify_payloads(SshIkev2ExchangeData ed,
                                      SshPmQm qm)
{
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshIkev2PayloadNotify notify;

  SSH_DEBUG(SSH_D_MIDOK, ("Parsing notify payloads for ed %p, IKE SA %p, "
                          "QM %p", ed, p1, qm));

  /* Parse the notify payloads received in the previous packet */
  for (notify = ed->notify; notify; notify = notify->next_notify)
    {
      switch (notify->notify_message_type)
        {
        case SSH_IKEV2_NOTIFY_INITIAL_CONTACT:
          /* Record that we have received an initial contact
             notification for this Phase-1 negotiation. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Registering initial contact notification from `%@:%d'",
                     ssh_ipaddr_render, ed->ike_sa->remote_ip,
                     ed->ike_sa->remote_port));

          SSH_PM_ASSERT_P1(p1);
          p1->received_1contact = 1;
          break;

        case SSH_IKEV2_NOTIFY_USE_TRANSPORT_MODE:
          if (qm)
            {
              SSH_PM_ASSERT_QM(qm);
              SSH_DEBUG(SSH_D_MIDOK, ("Received use transport notification"));
              qm->transport_recv = 1;
            }
          break;

        case SSH_IKEV2_NOTIFY_IPCOMP_SUPPORTED:
#ifdef SSHDIST_IPSEC_IPCOMP
          if (qm
              && (qm->transform & SSH_PM_IPSEC_IPCOMP)
              && (qm->ipcomp_chosen == 0)
              && (notify->notification_size == 3))
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Received IPComp supported notification"));
              if (qm->initiator)
                {
                  /* Read the selected IPCOMP from response. */
                  qm->ipcomp_spi_out =
                    SSH_GET_16BIT(notify->notification_data);
                  qm->ipcomp_chosen =
                    SSH_GET_8BIT(notify->notification_data + 2);
                }
              else
                {
                  SshUInt8 proposed;

                  /* Responder does selection here, prosessing the
                     initiator request against policy. */







                  proposed = SSH_GET_8BIT(notify->notification_data + 2);

                  if (((qm->transform & SSH_PM_COMPRESS_DEFLATE)
                       && (proposed == SSH_IKEV2_IPCOMP_DEFLATE))
                      ||
                      ((qm->transform & SSH_PM_COMPRESS_LZS)
                       && (proposed == SSH_IKEV2_IPCOMP_LZS)))
                    {
                      qm->ipcomp_chosen = proposed;
                      qm->ipcomp_spi_out =
                        SSH_GET_16BIT(notify->notification_data);
                    }
                }
            }
#endif /* SSHDIST_IPSEC_IPCOMP */
          break;

        default:
          SSH_DEBUG(SSH_D_MIDOK, ("Ignoring notification of type %d",
                                  notify->notify_message_type));

          break;
        }
    }
  return;
}

SshPmTunnel ssh_pm_tunnel_get_by_id(SshPm pm, SshUInt32 tunnel_id)
{
  SshPmTunnelStruct probe;
  SshADTHandle handle;
  SshPmTunnel tunnel;

  probe.tunnel_id = tunnel_id;
  handle = ssh_adt_get_handle_to_equal(pm->tunnels, &probe);
  if (handle == SSH_ADT_INVALID)
    return NULL;

  tunnel = ssh_adt_get(pm->tunnels, handle);
  SSH_ASSERT(tunnel != NULL);

  return tunnel;
}

SshPmTunnel ssh_pm_p1_get_tunnel(SshPm pm, SshPmP1 p1)
{
  SSH_PM_ASSERT_P1(p1);

  if (p1->n != NULL && p1->n->tunnel != NULL)
    return p1->n->tunnel;

  return ssh_pm_tunnel_get_by_id(pm, p1->tunnel_id);
}


#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IKE_XAUTH
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
static void
pm_ike_xauth_done_cb(SshSADHandle sad_handle,
                     SshIkev2Sa sa,
                     SshIkev2ExchangeData ed,
                     SshIkev2Error error)
{
  SshPmInfo info = (SshPmInfo) ed->application_context;
  SshPmP1 p1;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("In IKE XAuth done callback error status %d",
                               error));

  PM_IKE_ASYNC_CALL_COMPLETE(ed->ike_sa, ed);

  SSH_ASSERT(info != NULL);
  SSH_ASSERT(info->type == SSH_PM_ED_DATA_INFO_P1);

  p1 = info->u.p1;
  SSH_PM_ASSERT_ED(ed);
  ed->application_context = NULL;

  if (p1->ike_sa->xauth_enabled)
    {
      ssh_pm_log_xauth_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                             p1,
                             (p1->failed == FALSE));

      SSH_ASSERT(p1->ike_sa->xauth_done == 1);
    }

  if (p1->failed)
    {
      ssh_ikev2_debug_error_local(p1->ike_sa, "Xauth authentication failed");
      SSH_DEBUG(SSH_D_FAIL, ("Xauth negotiation failed, deleting IKE SA"));

      if (!SSH_PM_P1_DELETED(p1))
        {
          SSH_ASSERT(p1->initiator_ops[PM_IKE_INITIATOR_OP_DELETE] == NULL);
          SSH_PM_IKEV2_IKE_SA_DELETE(p1,
                                  SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW,
                                  pm_ike_sa_delete_notification_done_callback);
        }
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Broadcasting to Quick-Mode threads that Xauth "
                           "is now done"));
  ssh_fsm_condition_broadcast(&sad_handle->pm->fsm, &p1->xauth_wait_condition);
}


/* Initiate XAUTH/CFGmode after an IKE negotiation completes. */
Boolean ssh_pm_p1_initiate_xauth_ike(SshPm pm, SshPmP1 p1)
{
  SshIkev2ExchangeData ed;
  SshPmInfo info;
  int slot;

  SSH_DEBUG(SSH_D_LOWOK, ("Preparing to initiate XAUTH/CFGMODE"));

  if (!pm_ike_async_call_possible(p1->ike_sa, &slot))
    return FALSE;

  ed = ssh_ikev2_info_create(p1->ike_sa, 0);
  if (ed == NULL)
    {
      return FALSE;
    }

  info = ssh_pm_info_alloc(pm, ed, SSH_PM_ED_DATA_INFO_P1);
  if (info == NULL)
    {
      ssh_ikev2_info_destroy(ed);
      return FALSE;
    }
  info->u.p1 = p1;
  ed->application_context = info;

  ssh_ikev2_info_add_xauth(ed);

  SSH_DEBUG(SSH_D_LOWOK, ("Starting XAUTH/CFGMODE negotiation"));

  PM_IKE_ASYNC_CALL(p1->ike_sa, ed, slot,
                    ssh_ikev2_info_send(ed, pm_ike_xauth_done_cb));
  return TRUE;
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IKEV1 */

/* Allocate exchange data application context for informational exchange. */
SshPmInfo
ssh_pm_info_alloc(SshPm pm,
                  SshIkev2ExchangeData ed,
                  SshPmExchangeDataType type)
{
  SshPmInfo info;

  info = ssh_obstack_calloc(ed->obstack, sizeof(*info));
  if (info != NULL)
    info->type = type;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Allocated PmInfo %p (data type %d)",
                               info, type));
  return info;
}

/* Utility function for checking if childless `p1' needs to be deleted.
   Note that if the `p1' is deleted, then this function returns TRUE and
   the caller must not use `p1' (unless it is explicitly protected by an
   IKE SA reference). Otherwise `p1' is not deleted and this returns
   FALSE. This function asserts that `p1' is marked for childless SA
   deletion (that is `p1->delete_childless_sa' is set to 1). */
Boolean pm_ike_delete_childless_p1(SshPm pm, SshPmP1 p1)
{
  SshUInt32 flags;

  SSH_ASSERT(p1->delete_childless_sa == 1);

  if (ssh_pm_peer_num_child_sas_by_p1(pm, p1) == 0
      || ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      /* IKE SA needs to be deleted now. */
      if (!SSH_PM_P1_DELETED(p1))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Deleting IKE SA %p", p1->ike_sa));

          /* Send delete notification for the IKE SA. */
          flags = 0;
#ifdef SSHDIST_IKEV1
          /* Force IKEv1 SA to be deleted immediately. */
          flags |= SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

          SSH_PM_IKEV2_IKE_SA_DELETE(p1, flags,
                                  pm_ike_sa_delete_notification_done_callback);
        }

      return TRUE;
    }

  /* The IKE SA was not deleted. */
  return FALSE;
}

/* Perform common tasks after all IKE initiator information exchanges. */
void
pm_ike_info_done_common(SshPm pm,
                        SshPmP1 p1,
                        SshIkev2ExchangeData ed,
                        SshIkev2Error error)
{
#ifdef SSHDIST_IKEV1
  /* Mark expired IKEv1 SAs unusable */
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
      error == SSH_IKEV2_ERROR_SA_UNUSABLE)
    p1->unusable = 1;
  else
#endif /* SSHDIST_IKEV1 */
    /* P1 is fatally failed, request child SA deletion also for
       IKEv1 SAs */
    if (error != SSH_IKEV2_ERROR_OK
        && error != SSH_IKEV2_ERROR_TEMPORARY_FAILURE
        && error != SSH_IKEV2_ERROR_WINDOW_FULL)
      p1->delete_child_sas = 1;

  /* The IKE SA is updated after the informational exchange since
     the window of the IKE SA is updated */
  if (!p1->unusable)
    ssh_pm_ike_sa_event_updated(pm, p1);

  if (error == SSH_IKEV2_ERROR_OK)
    {
      /* Send any delayed delete notifications */
      if (p1->delete_notification_requests != NULL)
        {
          ssh_pm_send_ipsec_delete_notification_requests(pm, p1);
        }

      /* Check if IKE SA is childless and delete if needed */
      else if (p1->delete_childless_sa == 1
               && pm_ike_delete_childless_p1(pm, p1) == TRUE)
        {
          /* IKE SA was deleted */
          return;
        }
    }

#ifdef SSHDIST_IPSEC_MOBIKE
  /* Check MOBIKE status of the exchange */
  ssh_pm_mobike_check_exchange(pm, error, p1, ed);
#endif /* SSHDIST_IPSEC_MOBIKE */
}

/* Callback for initiator informational exchange.
   This function is called for:
   - DPD (eng_upcall.c)
   - IKEv1 DPD (sad_ike_i_negotiation.c)
   - SSH_IKEV2_NOTIFY_INVALID_SELECTORS triggered delete notification
     (spd_ike.c)
   - delete notifications (spd_ike_delete.c)
   - pm_report_unknown_spi (util_ike_spis.c)
*/

void
pm_ike_info_done_callback(SshSADHandle sad_handle,
                          SshIkev2Sa sa,
                          SshIkev2ExchangeData ed,
                          SshIkev2Error error)
{
  SshPmP1 p1 = (SshPmP1) sa;
  SshPmInfo info;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Information Exchange done, IKE error code %s",
             ssh_ikev2_error_to_string(error)));

  SSH_PM_ASSERT_ED(ed);
  SSH_ASSERT(sa == ed->ike_sa);

  PM_IKE_ASYNC_CALL_COMPLETE(sa, ed);
  info = ed->application_context;

  if (info != NULL)
    {
      switch (info->type)
        {
        case SSH_PM_ED_DATA_INFO_QM:
          if (info->u.qm != NULL)
            {
              SSH_PM_ASSERT_QM(info->u.qm);

              /* Clear qm->ed. */
              SSH_ASSERT(info->u.qm->ed == ed);
              info->u.qm->ed = NULL;

              /* Set qm error and continue thread. */
              info->u.qm->error = error;
              info->u.qm->ike_done = 1;
              ssh_fsm_continue(&info->u.qm->thread);

#ifdef SSHDIST_IKEV1
              /* If this qm creating a new IKEv1 SA for DPD timed out,
                 then delete all IPsec SAs with the peer. Note that in
                 this case deleting the IKEv1 SAs child SAs does not
                 work as the new IKE SA has not yet been attached to
                 the peer. */
              if (info->u.qm->dpd && error == SSH_IKEV2_ERROR_TIMEOUT)
                {
                  SSH_DEBUG(SSH_D_LOWOK,
                            ("DPD: IKEv1 SA negotiation timed out, "
                             "deleting IPsec SAs with peer"));
                  ssh_pm_delete_by_peer_handle(sad_handle->pm,
                                               info->u.qm->peer_handle, 0,
                                               NULL_FNPTR, NULL);
                }
#endif /* SSHDIST_IKEV1 */
            }
          /* fall through */
        case SSH_PM_ED_DATA_INFO_DPD:
          if (error == SSH_IKEV2_ERROR_TIMEOUT)
            ssh_pm_dpd_peer_dead(sad_handle->pm, sa->remote_ip, TRUE);
          else if (error == SSH_IKEV2_ERROR_OK)
            ssh_pm_dpd_peer_alive(sad_handle->pm, sa->remote_ip);
          break;

        default:
          /* This completion callback is not called for xauth, mobike
             or old spi invalidation info exchanges, and normal delete
             info exchanges do not set application context. */
          SSH_NOTREACHED;
          break;
        }

      /* `info' is always allocated from ed->obstack and thus is does
         not need to be freed separately. */
      SSH_PM_ASSERT_ED(ed);
      ed->application_context = NULL;
    }

  pm_ike_info_done_common(sad_handle->pm, p1, ed, error);
}


void ssh_pm_qm_thread_abort(SshPm pm, SshPmQm qm)
{
  qm->ike_done = 1;

  if (qm->error != SSH_IKEV2_ERROR_USE_IKEV1)
    {
      qm->aborted = 1;
      qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      SSH_DEBUG(SSH_D_MIDSTART, ("Marking Quick-Mode %p as unusable", qm));
    }

  if (SSH_FSM_THREAD_EXISTS(&qm->sub_thread)
      && !SSH_FSM_IS_THREAD_DONE(&qm->sub_thread))
    {
      /* Assumes the Quick-mode sub-thread will always run to completion. */
      SSH_DEBUG(SSH_D_HIGHOK, ("Quick-Mode sub-thread still running"));

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
#ifdef SSHDIST_IKEV1
      /* The Quick-mode sub-thread may not run to completion if it is
         waiting for XAUTH so special handling is required here.

         A potential problem here is that we force the IKE SA to fail.
         This is not appropiate if we ever need to abort a Quick-Mode but
         are not aborting/destroying the underlying IKE SA. This scenario
         is not supported currently the code below needs changing if that
         is to be added at a later date. */
      if (qm->waiting_xauth)
        {
          if (qm->p1)
            {
              qm->p1->ike_sa->xauth_done = 1;
              qm->p1->failed = 1;
            }
          ssh_fsm_continue(&qm->sub_thread);

          SSH_DEBUG(SSH_D_HIGHOK, ("Continuing XAUTH Quick-Mode sub-thread"));

        }
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
    }
  else
    {
#ifdef SSHDIST_IPSEC_SA_EXPORT
      if (qm->import)
        {
          SSH_DEBUG(SSH_D_HIGHOK, ("Letting QM import thread continue"));
        }
      else
#endif /* SSHDIST_IPSEC_SA_EXPORT */
      if (qm->initiator)
        {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
          /* Fail any connection setup in progress. */
          if (qm->conn_op)
            {
              ssh_operation_abort(qm->conn_op);
              qm->conn_op = NULL;
              ssh_fsm_set_next(&qm->thread, ssh_pm_st_qm_i_n_failed);
              SSH_FSM_CONTINUE_AFTER_CALLBACK(&qm->thread);
            }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
          /* If QM initiator is already negotiating, then let QM
             thread continue. Otherwise QM thread will be advanced to
             terminal state in callback functions. */
          if (!ssh_fsm_get_callback_flag(&qm->thread))
            {
              SSH_DEBUG(SSH_D_MIDSTART,
                        ("Continuing QM thread for qm %p", qm));
              ssh_fsm_continue(&qm->thread);
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDSTART, ("Freeing responder Quick-Mode %p", qm));
          if (qm->ed)
            {
              SSH_PM_ASSERT_ED(qm->ed);
              qm->ed->application_context = NULL;
            }
          ssh_pm_qm_free(pm, qm);
        }
    }
}



void
ssh_pm_qm_route_cb(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
                   const SshIpAddr next_hop, size_t mtu, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  SshIpAddr ip;

  if (qm->aborted)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("QM thread aborted, advancing to terminal state"));
      ssh_fsm_set_next(thread, ssh_pm_st_qm_i_n_failed);
      SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
      return;
    }

  if ((flags & SSH_PME_ROUTE_REACHABLE) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is unreachable",
                 ssh_ipaddr_render, &qm->initial_remote_addr));
      qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
    }
  else if (flags & SSH_PME_ROUTE_LINKBROADCAST)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is a link-local broadcast address",
                 ssh_ipaddr_render, &qm->initial_remote_addr));
      qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
    }
  else
    {
      if (flags & SSH_PME_ROUTE_LOCAL)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("Destination `%@' is our local address",
                   ssh_ipaddr_render, &qm->initial_remote_addr));

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is reachable using "
                 "interface %u: next_hop=%@",
                 ssh_ipaddr_render, &qm->initial_remote_addr,
                 (int) ifnum,
                 ssh_ipaddr_render, next_hop));

      /* If the local IP address is undefined, lookup it now. */
      if (!SSH_IP_DEFINED(&qm->initial_local_addr))
        {
          ip = ssh_pm_find_interface_address(pm, ifnum,
                                          (SSH_IP_IS6(&qm->initial_remote_addr)
                                           ? TRUE : FALSE),
                                           &qm->initial_remote_addr);
          if (ip == NULL)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Interface %d does not have an usable address",
                         (int) ifnum));
              qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Using local IP address `%@'",
                                           ssh_ipaddr_render, ip));
              qm->initial_local_addr = *ip;
            }
        }
    }

  /* The next state is already set by the caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

void
ssh_pm_delete_rule_negotiations(SshPm pm, SshPmRule rule)
{
  SshPmQm qm, qm_ed, next_qm;
  SshPmInfo info;
  SshPmP1 p1;
  SshUInt32 j;
  Boolean found;

  for (qm = pm->active_qm_negotiations; qm; qm = next_qm)
    {
      next_qm = qm->next;
      if (qm->rule != rule)
        continue;

      p1 = qm->p1;
      if (p1 == NULL)
        continue;

      found = FALSE;
      /* Search from the active exchange datas of the IKE SA to see if
         one matches the Quick-Mode 'qm'. */
      for (j = 0; j < PM_IKE_MAX_WINDOW_SIZE && !found; j++)
        {
          if (p1->initiator_eds[j] != NULL)
            {
              qm_ed = NULL;
              if (p1->initiator_eds[j]->ipsec_ed)
                {
                  qm_ed = (SshPmQm) p1->initiator_eds[j]->application_context;
                }
              else if (p1->initiator_eds[j]->info_ed)
                {
                  info = (SshPmInfo) p1->initiator_eds[j]->application_context;
                  if (info && info->type == SSH_PM_ED_DATA_INFO_QM)
                    qm_ed = info->u.qm;
                }

              if (qm != qm_ed)
                continue;

              /* Found the exchange data of the Quick-Mode 'qm'. Abort
                 the operation and move to the next active Quick-Mode. */
              found = TRUE;
              if (p1->initiator_eds[j]->ipsec_ed)
                {
                  SshIkev2ExchangeData tmp;

                  tmp = p1->initiator_eds[j];
                  p1->initiator_eds[j] = NULL;
                  if (tmp->ipsec_ed->flags
                      & SSH_IKEV2_IPSEC_OPERATION_REGISTERED)
                    ssh_operation_abort(tmp->ipsec_ed->operation_handle);
                  ssh_ikev2_exchange_data_free(tmp);
                }
            }
        }
      /* Run the Quick-Mode thread to completion if possible */
      ssh_pm_qm_thread_abort(pm, qm);
    }

  /* Free rule references from all ongoing p1 negotiations so that
     rule deletion can continue. */
  for (p1 = pm->active_p1_negotiations; p1 != NULL; p1 = p1->n->next)
    {
      if (p1->n->rule == rule)
        {
          p1->n->rule = NULL;
          SSH_PM_RULE_UNLOCK(pm, rule);
        }
    }
}

/****************** Simultaneous IPsec SA rekey handling ********************/

void
ssh_pm_qm_simultaneous_rekey_store_nonces(SshPm pm,
                                          SshIkev2ExchangeData ed)
{
  SshPmQm qm = (SshPmQm) ed->application_context;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;
  SshPmQm initiator_qm;
  int i;
  SshIkev2PayloadNonce smallest_nonce;
  Boolean smallest_nonce_is_local;

  /* This function may be called only for successfull responder IKEv2
     CREATE_CHILD negotiations used for IPsec SA rekey. */
  SSH_ASSERT(ed->state == SSH_IKEV2_STATE_CREATE_CHILD);
  SSH_PM_ASSERT_P1(p1);
#ifdef SSHDIST_IKEV1
  SSH_ASSERT((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) == 0);
#endif /* SSHDIST_IKEV1 */

  /* Check if this responder negotiation needs to be checked for simultaneous
     IPsec SA rekey. The qm may be NULL if the negotiation has been aborted. */
  if (qm == NULL)
    return;
  SSH_PM_ASSERT_QM(qm);

  if (!qm->simultaneous_rekey)
    return;

  SSH_ASSERT(qm->rekey);
  SSH_ASSERT(!qm->initiator);

  /* Find the simultaneous initiated IPsec SA rekey. */
  for (i = 0; i < PM_IKE_MAX_WINDOW_SIZE; i++)
    {
      if (p1->initiator_eds[i] != NULL
          && p1->initiator_eds[i]->state == SSH_IKEV2_STATE_CREATE_CHILD
          && p1->initiator_eds[i]->ipsec_ed != NULL
          && (p1->initiator_eds[i]->ipsec_ed->rekeyed_spi
              == qm->old_inbound_spi))
        {
          initiator_qm = (SshPmQm) p1->initiator_eds[i]->application_context;
          if (initiator_qm == NULL)
            continue;

          /* The nonces should always be filled in when this is called. */
          if (qm->ed->ipsec_ed->nr == NULL
              || qm->ed->ipsec_ed->ni == NULL
              || initiator_qm->ed->ipsec_ed->ni == NULL)
            continue;

          /* Compare the available three nonces. */
          if ((qm->ed->ipsec_ed->nr->nonce_size <
               qm->ed->ipsec_ed->ni->nonce_size)
              || memcmp(qm->ed->ipsec_ed->nr->nonce_data,
                        qm->ed->ipsec_ed->ni->nonce_data,
                        qm->ed->ipsec_ed->nr->nonce_size) < 0)
            {
              /* Our nonce from the responded IPsec SA rekey is smaller.
                 Compare with our nonce from the initiated IPsec SA rekey. */
              if ((qm->ed->ipsec_ed->nr->nonce_size <
                   initiator_qm->ed->ipsec_ed->ni->nonce_size)
                  || memcmp(qm->ed->ipsec_ed->nr->nonce_data,
                            initiator_qm->ed->ipsec_ed->ni->nonce_data,
                            qm->ed->ipsec_ed->nr->nonce_size) < 0)
                {
                  /* Our nonce from the responded IPsec SA rekey is the
                     smallest of the three available nonces. */
                  smallest_nonce = qm->ed->ipsec_ed->nr;
                  smallest_nonce_is_local = TRUE;
                }
              else
                {
                  /* Our nonce from the initiated IPsec SA rekey is the
                     smallest of the three available nonces. */
                  smallest_nonce = initiator_qm->ed->ipsec_ed->ni;
                  smallest_nonce_is_local = TRUE;
                }
            }
          else
            {
              /* The remote ends nonce from the responded IPsec SA rekey
                 is smaller. Compare with our nonce from the initiated
                 IPsec SA rekey. */
              if ((qm->ed->ipsec_ed->ni->nonce_size <
                   initiator_qm->ed->ipsec_ed->ni->nonce_size)
                  || memcmp(qm->ed->ipsec_ed->ni->nonce_data,
                            initiator_qm->ed->ipsec_ed->ni->nonce_data,
                            qm->ed->ipsec_ed->ni->nonce_size) < 0)
                {
                  /* Remote ends nonce from the responded IPsec SA rekey is
                     the smallest of the three available nonces. */
                  smallest_nonce = qm->ed->ipsec_ed->ni;
                  smallest_nonce_is_local = FALSE;
                }
              else
                {
                  /* Our nonce from the initiated IPsec SA rekey is
                     the smallest of the three available nonces. */
                  smallest_nonce = initiator_qm->ed->ipsec_ed->ni;
                  smallest_nonce_is_local = TRUE;
                }
            }

          /* Store the smallest nonce in the case that the smallest nonce
             was generated by this end. If it was generated by remote end
             then the fourth missing nonce cannot change the situation and
             thus the smallest nonce does not need to be stored. */
          if (smallest_nonce_is_local == TRUE)
            {
              initiator_qm->simultaneous_rekey_nonce_local = 1;
              memcpy(initiator_qm->simultaneous_rekey_nonce_data,
                     smallest_nonce->nonce_data, smallest_nonce->nonce_size);
              initiator_qm->simultaneous_rekey_nonce_size =
                smallest_nonce->nonce_size;
            }
          else
            {
              initiator_qm->simultaneous_rekey_nonce_local = 0;
            }

          /* Mark the initiated qm as being a simultaneous rekey so that
             the rekey loser can be decided when the initiated rekey
             negotiation completes. */
          initiator_qm->simultaneous_rekey = 1;

          /* Clear the simultaneous rekey flag from this responder qm just
             for sake of clarity and easier debugging. */
          qm->simultaneous_rekey = 0;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Simultaneous IPsec SA rekey detected, "
                     "smallest nonce is currently generated by %s",
                     (smallest_nonce_is_local == TRUE ? "local" : "remote")));

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Responder qm %p initiator qm %p inbound SPI %s-%08lx",
                     qm, initiator_qm,
                     ((qm->transform & SSH_PM_IPSEC_AH) != 0 ? "AH" : "ESP"),
                     (unsigned long) qm->old_inbound_spi));
          return;
        }
    }
}


Boolean
ssh_pm_qm_simultaneous_rekey_decide_loser(SshPm pm, SshPmQm qm)
{
  /* This function may be called only for successfull IKEv2 CREATE_CHILD
     negotiations. */
  SSH_ASSERT(qm->initiator);
  SSH_ASSERT(qm->rekey);
  SSH_ASSERT(qm->simultaneous_rekey);
#ifdef SSHDIST_IKEV1
  SSH_ASSERT((qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
             == 0);
#endif /* SSHDIST_IKEV1 */

  /* The smallest nonce of the earlier checked three nonces was
     generated by remote end. Therefore this end is the winner
     regardless of the value of the remote nonce of this initiated
     IPsec SA rekey. */
  if (qm->simultaneous_rekey_nonce_local == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Simultaneous IPsec SA rekey lost by remote end"));
      return FALSE;
    }

  /* Check the remote nonce of this initiated IPsec SA rekey. */
  if ((qm->ed->ipsec_ed->nr->nonce_size <
       qm->simultaneous_rekey_nonce_size)
      || memcmp(qm->ed->ipsec_ed->nr->nonce_data,
                qm->simultaneous_rekey_nonce_data,
                qm->ed->ipsec_ed->nr->nonce_size) < 0)
    {
      /* Remote ends nonce of the initiated IPsec SA rekey is the
         smallest, therefore this end wins. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Simultaneous IPsec SA rekey lost by remote end"));
      return FALSE;
    }

  /* Our nonce was the smallest, thus we lose and must delete the
     initiated IPsec SA. Note that the rekeyed IPsec SA was already
     installed when processing the responded IPsec SA rekey. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Simultaneous IPsec SA rekey lost by this end"));
  return TRUE;
}


/* *** Utility functions for accessing information from IKE or IPsec SA's ***/

/* Extract IKE SPIs from IKE SA. */
void
ssh_pm_ike_sa_get_cookies(SshPm pm,
                          SshPmIkeSAEventHandle ike_sa,
                          unsigned char *ike_spi_i,
                          unsigned char *ike_spi_r)
{
  SSH_ASSERT(ike_sa != NULL);
  SSH_ASSERT(ike_sa->p1 != NULL);
  SSH_ASSERT(ike_spi_i != NULL);
  SSH_ASSERT(ike_spi_r != NULL);

  memcpy(ike_spi_i, ike_sa->p1->ike_sa->ike_spi_i, 8);
  memcpy(ike_spi_r, ike_sa->p1->ike_sa->ike_spi_r, 8);
}

/* Extract old IKE SPIs from a rekeyed IKE SA. */
void
ssh_pm_ike_sa_get_old_cookies(SshPm pm,
                              SshPmIkeSAEventHandle ike_sa,
                              unsigned char *old_ike_spi_i,
                              unsigned char *old_ike_spi_r)
{
  SSH_ASSERT(ike_sa != NULL);
  SSH_ASSERT(ike_sa->p1 != NULL);
  SSH_ASSERT(old_ike_spi_i != NULL);
  SSH_ASSERT(old_ike_spi_r != NULL);

  memcpy(old_ike_spi_i, ike_sa->p1->old_ike_spi_i, 8);
  memcpy(old_ike_spi_r, ike_sa->p1->old_ike_spi_r, 8);
}

/* Extract IKE SPIs from the parent IKE SA of the IPsec SA. */
void
ssh_pm_ipsec_sa_get_ike_cookies(SshPm pm,
                                SshPmIPsecSAEventHandle ipsec_sa,
                                unsigned char *ike_spi_i,
                                unsigned char *ike_spi_r)
{
  SshPmP1 p1 = NULL;

  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(ike_spi_i != NULL);
  SSH_ASSERT(ike_spi_r != NULL);

  if (ipsec_sa->qm != NULL)
    p1 = ipsec_sa->qm->p1;
  else if (ipsec_sa->peer != NULL)
    p1 = ssh_pm_p1_from_ike_handle(pm, ipsec_sa->peer->ike_sa_handle, FALSE);

  if (p1 != NULL)
    {
      memcpy(ike_spi_i, p1->ike_sa->ike_spi_i, 8);
      memcpy(ike_spi_r, p1->ike_sa->ike_spi_r, 8);
    }
  else
    {
      memset(ike_spi_i, 0, 8);
      memset(ike_spi_r, 0, 8);
    }
}

#ifdef SSHDIST_IPSEC_SA_EXPORT
/* Return IKE SA's tunnel application identifier. */
Boolean
ssh_pm_ike_sa_get_tunnel_application_identifier(SshPm pm,
                                                SshPmIkeSAEventHandle ike_sa,
                                                unsigned char *id,
                                                size_t *id_len)
{
  SSH_ASSERT(ike_sa != NULL);
  SSH_ASSERT(id != NULL);
  SSH_ASSERT(id_len != NULL);

  if (ike_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      if (*id_len < ike_sa->tunnel_application_identifier_len)
        return FALSE;

      memcpy(id, ike_sa->tunnel_application_identifier,
             ike_sa->tunnel_application_identifier_len);
      *id_len = ike_sa->tunnel_application_identifier_len;

      return TRUE;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get tunnel application identifier for SA event other "
             "than SSH_PM_SA_EVENT_CREATED"));

  return FALSE;
}

/* Set IKE SA tunnel. */
void
ssh_pm_ike_sa_set_tunnel(SshPm pm,
                         SshPmIkeSAEventHandle ike_sa,
                         SshPmTunnel tunnel)
{
  SSH_ASSERT(ike_sa != NULL);
  SSH_ASSERT(ike_sa->p1 != NULL);
  SSH_ASSERT(tunnel != NULL);

  if (ike_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Setting tunnel_id %d for IKE SA %p",
                              (int) tunnel->tunnel_id, ike_sa->p1->ike_sa));
      ike_sa->p1->tunnel_id = tunnel->tunnel_id;
      return;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set tunnel id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));
}

#endif /* SSHDIST_IPSEC_SA_EXPORT */

/******************************* IKE SA events ******************************/

void
ssh_pm_ike_sa_event_created(SshPm pm, SshPmP1 p1)
{
  SshPmIkeSAEventHandleStruct ike_sa;

  SSH_PM_ASSERT_P1(p1);

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %p created", p1->ike_sa));

  if (p1->enable_sa_events && pm->ike_sa_callback)
    {
      memset(&ike_sa, 0, sizeof(ike_sa));

      ike_sa.p1 = p1;
      ike_sa.event = SSH_PM_SA_EVENT_CREATED;

      (*pm->ike_sa_callback)(pm, ike_sa.event, &ike_sa,
                             pm->ike_sa_callback_context);
    }
}

void
ssh_pm_ike_sa_event_rekeyed(SshPm pm, SshPmP1 p1)
{
  SshPmIkeSAEventHandleStruct ike_sa;

  SSH_PM_ASSERT_P1(p1);

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %p rekeyed", p1->ike_sa));

  if (p1->enable_sa_events && pm->ike_sa_callback)
    {
      memset(&ike_sa, 0, sizeof(ike_sa));

      ike_sa.p1 = p1;
      ike_sa.event = SSH_PM_SA_EVENT_REKEYED;

      (*pm->ike_sa_callback)(pm, ike_sa.event, &ike_sa,
                             pm->ike_sa_callback_context);
    }
}

void
ssh_pm_ike_sa_event_updated(SshPm pm, SshPmP1 p1)
{
  SshPmIkeSAEventHandleStruct ike_sa;

  SSH_PM_ASSERT_P1(p1);

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %p updated", p1->ike_sa));

  if (p1->enable_sa_events && pm->ike_sa_callback)
    {
      memset(&ike_sa, 0, sizeof(ike_sa));

      ike_sa.p1 = p1;
      ike_sa.event = SSH_PM_SA_EVENT_UPDATED;

      (*pm->ike_sa_callback)(pm, ike_sa.event, &ike_sa,
                             pm->ike_sa_callback_context);
    }
}

void
ssh_pm_ike_sa_event_deleted(SshPm pm, SshPmP1 p1)
{
  SshPmIkeSAEventHandleStruct ike_sa;

  SSH_PM_ASSERT_P1(p1);

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA %p deleted", p1->ike_sa));

  if (p1->enable_sa_events && pm->ike_sa_callback)
    {
      memset(&ike_sa, 0, sizeof(ike_sa));

      ike_sa.p1 = p1;
      ike_sa.event = SSH_PM_SA_EVENT_DELETED;

      (*pm->ike_sa_callback)(pm, ike_sa.event, &ike_sa,
                             pm->ike_sa_callback_context);
    }
}
