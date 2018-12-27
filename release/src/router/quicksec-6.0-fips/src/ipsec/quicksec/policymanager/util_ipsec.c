/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IPsec related utility functions that are independent of the keying
   method. No IKE specific code must be included in this file.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "PmUtilIPSec"


/**************** Help functions for Quick mode threads ********************/

void
pm_qm_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
  SshPmQm qm = (SshPmQm) context;

  SSH_PM_ASSERT_QM(qm);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("In Quick-Mode thread destructor for QM %p",
                               qm));

  /* Release the QM negotiation context for the initiator unless they
     are running the sub thread. If sub-thread is run, then then free
     is delayed to its destructor (if qm->ed == NULL) there. See
     pm_qm_sub_thread_destructor function above. */
  if (!SSH_FSM_THREAD_EXISTS(&qm->sub_thread))
    ssh_pm_qm_free(pm, qm);
}

Boolean ssh_pm_check_qm_error(SshPmQm qm,
                              SshFSMThread thread,
                              SshFSMStepCB error_state)
{
  if (qm->error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Setting QM %p thread to error state", qm));
      ssh_fsm_set_next(thread, error_state);
      return TRUE;
    }
  return FALSE;
}

void
ssh_pm_transform_index_cb(SshPm pm, SshUInt32 ind, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  SshPmPeer peer = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Transform index 0x%x found for QM %p",
                          (unsigned int) ind, qm));
  qm->trd_index = ind;

  if (qm->trd_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Set this flag until a rule referencing this TRD is created.
         Consult ssh_pme_delete_transform() semantics for details. */
      qm->delete_trd_on_error = 1;

      /* No need to free IKE peer reference explicitly, as that is done
         in the SA destroyed event handling. */
      qm->delete_peer_ref_on_error = 0;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /* No need to free VIP reference explicitly, as that is done
         in the SA destroyed event handling. */
      qm->delete_vip_ref_on_error = 0;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
      SSH_ASSERT(peer != NULL);

      /* Increment the child SA counter for IKE SA's. */
      peer->num_child_sas++;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IKEV1
      /* Add a reference to the CFGMode client. This is only done for IKEv1
         SA's. For IKEv2 no extra references are required because IPsec
         SA's (i.e. all objects using the CFG mode addresses) are tied
         to the IKE SA. */
      if (qm->p1 && qm->p1->cfgmode_client &&
          (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
        SSH_PM_CFGMODE_CLIENT_TAKE_REF(pm, qm->p1->cfgmode_client);
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

void
ssh_pm_add_sa_handler_rule_cb(SshPm pm, SshUInt32 ind,
                              const SshEnginePolicyRule rule,
                              void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  SshUInt32 current_index;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Created outbound SA rule %p rule index 0x%x",
                               rule, (unsigned int) ind));
  qm->sa_index = ind;

  if (qm->sa_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Clear this flag as now a rule referencing the TRD exists.
         Consult ssh_pme_delete_transform() semantics for details. */
      qm->delete_trd_on_error = 0;

      current_index = qm->sa_handler_data.added_index;
      qm->sa_handler_data.sa_indices[current_index] = qm->sa_index;
      qm->sa_handler_data.added_index++;
    }

  /* Continue.  The next state is already set by caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}


void
ssh_pm_add_sa_rule_cb(SshPm pm, SshUInt32 ind,
                      const SshEnginePolicyRule rule,
                      void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Created outbound SA rule %p rule index 0x%x",
                               rule, (unsigned int) ind));

  qm->sa_index = ind;

  /* Continue.  The next state is already set by caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

void
ssh_pm_sa_index_cb(SshPm pm, const SshEnginePolicyRule rule,
                   SshUInt32 transform_index, SshUInt32 outbound_spi,
                   void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);

  if (rule != NULL)
    {
      qm->trd_index = rule->transform_index;
      qm->old_outbound_spi = outbound_spi;

      SSH_DEBUG(SSH_D_LOWOK,
                ("Found a policy rule with transform 0x%x "
                 "and outbound SPI 0x%08lx for QM %p",
                 (unsigned int) transform_index,
                 (unsigned long) outbound_spi,
                 qm));
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,("No policy rule or transform found for QM %p",
                             qm));

      qm->trd_index = SSH_IPSEC_INVALID_INDEX;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

void ssh_pm_rule_auto_start_remove(SshPm pm, SshPmRule rule)
{
  if (rule->in_auto_start_adt)
    {
      ssh_adt_detach(pm->rule_by_autostart,
                     &rule->rule_by_autostart_hdr);
      rule->in_auto_start_adt = 0;
    }
}

void ssh_pm_rule_auto_start_insert(SshPm pm, SshPmRule rule)
{
  if (rule->in_auto_start_adt == 0)
    {
      ssh_adt_insert(pm->rule_by_autostart, rule);
      rule->in_auto_start_adt = 1;
    }
}

/* Update success status about auto-start tunnels. */
void ssh_pm_qm_update_auto_start_status(SshPm pm, SshPmQm qm)
{
  SshPmRuleSideSpecification side;

  if (qm->auto_start)
    {
      SSH_ASSERT(qm->tunnel != NULL);
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      SSH_ASSERT((qm->tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
                 ||(qm->tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) != 0);
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
      SSH_ASSERT((qm->tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      if (qm->rule == NULL)
        return;
      else if (qm->forward)
        side = &qm->rule->side_to;
      else
        side = &qm->rule->side_from;

      if (qm->error)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Auto-start rule failed"));

          /* If qm failed locally because of no usable IKE server was
             found, then clear the auto start failure counter so that
             the IKE negotiation is started as soon as possible after
             a valid IKE server has been started. */
          if (qm->error == SSH_PM_QM_ERROR_NO_IKE_PEERS)
            {
              side->as_fail_retry = 0;
            }
          else
            {
              if (side->as_fail_limit < 16)
                side->as_fail_limit++;

              side->as_fail_retry = side->as_fail_limit;
            }

          side->as_up = 0;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start tunnel up"));
          side->as_up = 1;
          side->as_fail_limit = 0;

          /* Check if another rule is waiting for this auto-start tunnel to
             come up, if so signal to the main thread to reconsider the
             auto-start rules. */
          if (qm->tunnel->as_rule_pending)
            {
              qm->tunnel->as_rule_pending = 0;
              pm->auto_start = 1;
              ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
            }
        }

      /* Mark rule and tunnel not having an auto-start negotiation active. */
      side->as_active = 0;
      qm->tunnel->as_active = 0;
    }
  else if (qm->error == 0)
    {
      /* Update success status about auto-start tunnels also for trigger
         and responder negotiations. */
      if (qm->rule == NULL)
        return;
      else if (qm->forward)
        side = &qm->rule->side_to;
      else
        side = &qm->rule->side_from;

      if (side->auto_start)
        {
          side->as_up = 1;
          side->as_fail_limit = 0;
        }
    }

  /* If the autostart status of rule's both directions is ok,
     then detach the rule from autostart ADT. */
  if (qm->rule != NULL
      && (qm->rule->side_to.auto_start == 0
          || qm->rule->side_to.as_up == 1)
      && (qm->rule->side_from.auto_start == 0
          || qm->rule->side_from.as_up == 1))
    {
      ssh_pm_rule_auto_start_remove(pm, qm->rule);
    }
}


/* ************************** IPsec SA events *******************************/

void
ssh_pm_ipsec_sa_event_created(SshPm pm, SshPmQm qm)
{
  SshPmIPsecSAEventHandleStruct ipsec_sa;

  SSH_PM_ASSERT_QM(qm);

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA created"));

  if (pm->ipsec_sa_callback)
    {
      memset(&ipsec_sa, 0, sizeof(ipsec_sa));
      ipsec_sa.event = SSH_PM_SA_EVENT_CREATED;
      ipsec_sa.qm = qm;

      (*pm->ipsec_sa_callback)(pm, ipsec_sa.event, &ipsec_sa,
                               pm->ipsec_sa_callback_context);
    }
}

void
ssh_pm_ipsec_sa_event_rekeyed(SshPm pm, SshPmQm qm)
{
  SshPmIPsecSAEventHandleStruct ipsec_sa;

  SSH_PM_ASSERT_QM(qm);

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA rekeyed"));

  if (pm->ipsec_sa_callback)
    {
      /* Generate rekeyed event for the new SPI values. */
      memset(&ipsec_sa, 0, sizeof(ipsec_sa));
      ipsec_sa.event = SSH_PM_SA_EVENT_REKEYED;
      ipsec_sa.qm = qm;

      (*pm->ipsec_sa_callback)(pm, ipsec_sa.event, &ipsec_sa,
                               pm->ipsec_sa_callback_context);

      /* Generate updated event for the old SPI values. */
      memset(&ipsec_sa, 0, sizeof(ipsec_sa));
      ipsec_sa.event = SSH_PM_SA_EVENT_UPDATED;
      ipsec_sa.update_type = SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED;
      ipsec_sa.outbound_spi = qm->old_outbound_spi;
      ipsec_sa.inbound_spi = qm->old_inbound_spi;
      if (qm->transform & SSH_PM_IPSEC_AH)
        ipsec_sa.ipproto = SSH_IPPROTO_AH;
      else if (qm->transform & SSH_PM_IPSEC_ESP)
        ipsec_sa.ipproto = SSH_IPPROTO_ESP;
      else
        SSH_NOTREACHED;

      /* P1 to peer mapping may change if there are multiple simultaneous
         IKE/IPsec negotiations going on. */
      ipsec_sa.peer = ssh_pm_peer_by_p1(pm, qm->p1);
      if (ipsec_sa.peer == NULL)
        ipsec_sa.peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
      SSH_ASSERT(ipsec_sa.peer != NULL);

      (*pm->ipsec_sa_callback)(pm, ipsec_sa.event, &ipsec_sa,
                               pm->ipsec_sa_callback_context);
    }
}

void
ssh_pm_ipsec_sa_event_deleted(SshPm pm,
                              SshUInt32 outbound_spi,
                              SshUInt32 inbound_spi,
                              SshUInt8 ipproto)
{
  SshPmIPsecSAEventHandleStruct ipsec_sa;

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA deleted"));

  if (pm->ipsec_sa_callback)
    {
      memset(&ipsec_sa, 0, sizeof(ipsec_sa));
      ipsec_sa.event = SSH_PM_SA_EVENT_DELETED;
      ipsec_sa.outbound_spi = outbound_spi;
      ipsec_sa.inbound_spi = inbound_spi;
      ipsec_sa.ipproto = ipproto;

      (*pm->ipsec_sa_callback)(pm, ipsec_sa.event, &ipsec_sa,
                               pm->ipsec_sa_callback_context);
    }
}

void
ssh_pm_ipsec_sa_event_peer_updated(SshPm pm,
                                   SshPmPeer peer,
                                   Boolean enable_natt,
                                   Boolean enable_tcpencap)
{
  SshPmIPsecSAEventHandleStruct ipsec_sa;
  SshPmSpiOut spi_out;

  SSH_DEBUG(SSH_D_LOWOK, ("IPsec SA updated"));

  if (pm->ipsec_sa_callback)
    {
      if (peer == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("No peer found"));
          return;
        }

      memset(&ipsec_sa, 0, sizeof(ipsec_sa));
      ipsec_sa.event = SSH_PM_SA_EVENT_UPDATED;
      ipsec_sa.update_type = SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED;

      for (spi_out = peer->spi_out;
           spi_out != NULL;
           spi_out = spi_out->peer_spi_next)
        {
          /* Skip old SPIs that are marked as rekeyed. */
          if (spi_out->rekeyed)
            continue;

          ipsec_sa.spi_out = spi_out;
          ipsec_sa.peer = peer;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          ipsec_sa.enable_natt = enable_natt;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSH_IPSEC_TCPENCAP
          ipsec_sa.enable_tcpencap = enable_tcpencap;
#endif /* SSH_IPSEC_TCPENCAP */

          (*pm->ipsec_sa_callback)(pm, ipsec_sa.event, &ipsec_sa,
                                   pm->ipsec_sa_callback_context);
        }
    }
}

/* ********************** Other utility functions ****************************/

/* This function is called when the engine delivers an
   SSH_ENGINE_EVENT_DESTROYED or SSH_ENGINE_EVENT_EXPIRED event to
   the policy manager informing that an IPSec SA has been deleted. */
void
ssh_pm_notify_ipsec_sa_delete(SshPm pm,
                              SshPmeFlowEvent event,
                              SshEngineTransform tr)
{
  SshEngineTransformData trd = &tr->data;
  SshUInt32 outbound_spi[2], inbound_spi[2];
  SshUInt8 ipproto;
  unsigned char spi_buf[4];

  /* Indicate that IPsec SA has been destroyed. */
  if (trd->transform & SSH_PM_IPSEC_AH)
    {
      ipproto = SSH_IPPROTO_AH;
      outbound_spi[SSH_PM_SPI_NEW] = trd->spis[SSH_PME_SPI_AH_OUT];
      inbound_spi[SSH_PM_SPI_NEW] = trd->spis[SSH_PME_SPI_AH_IN];
      outbound_spi[SSH_PM_SPI_OLD] = trd->old_spis[SSH_PME_SPI_AH_OUT];
      inbound_spi[SSH_PM_SPI_OLD] = trd->old_spis[SSH_PME_SPI_AH_IN];
    }
  else
    {
      SSH_ASSERT((trd->transform & SSH_PM_IPSEC_ESP));
      ipproto = SSH_IPPROTO_ESP;
      outbound_spi[SSH_PM_SPI_NEW] = trd->spis[SSH_PME_SPI_ESP_OUT];
      inbound_spi[SSH_PM_SPI_NEW] = trd->spis[SSH_PME_SPI_ESP_IN];
      outbound_spi[SSH_PM_SPI_OLD] = trd->old_spis[SSH_PME_SPI_ESP_OUT];
      inbound_spi[SSH_PM_SPI_OLD] = trd->old_spis[SSH_PME_SPI_ESP_IN];
    }

  if (ssh_pm_spi_disable_sa_events(pm, outbound_spi[SSH_PM_SPI_NEW],
                                   inbound_spi[SSH_PM_SPI_NEW], TRUE))
    ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi[SSH_PM_SPI_NEW],
                                  inbound_spi[SSH_PM_SPI_NEW], ipproto);

  /* If the IPsec SA still had old SPI values waiting for invalidation,
     then indicate also that the old SPI values have been destroyed. */
  if (inbound_spi[SSH_PM_SPI_OLD] != 0
      && ssh_pm_spi_disable_sa_events(pm, outbound_spi[SSH_PM_SPI_OLD],
                                      inbound_spi[SSH_PM_SPI_OLD], TRUE))
    ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi[SSH_PM_SPI_OLD],
                                  inbound_spi[SSH_PM_SPI_OLD], ipproto);

  SSH_PUT_32BIT(spi_buf, inbound_spi[SSH_PM_SPI_NEW]);

  ssh_pm_audit_event(pm, SSH_PM_AUDIT_POLICY, SSH_AUDIT_NOTICE,
                     SSH_AUDIT_TXT, "IPsec SA deleted",
                     SSH_AUDIT_IPPROTO, &ipproto, sizeof(ipproto),
                     SSH_AUDIT_SPI, spi_buf, sizeof(spi_buf),
                     SSH_AUDIT_ARGUMENT_END);

  /* And finally notify it is gone */
  ssh_pm_log_trd_event(SSH_LOGFACILITY_AUTH, event, trd);
}

void
ssh_pm_tunnel_select_local_ip(SshPmTunnel tunnel, SshIpAddr peer,
                              SshIpAddr local_ip_ret)
{
  SshPmTunnelLocalIp local_ip;

  SSH_ASSERT(tunnel != NULL);
  SSH_ASSERT(local_ip_ret != NULL);
  SSH_ASSERT(peer != NULL);

  SSH_IP_UNDEFINE(local_ip_ret);
  for (local_ip = tunnel->local_ip;
       local_ip != NULL;
       local_ip = local_ip->next)
    {
      if (SSH_IP_IS4(peer) && SSH_IP_IS4(&local_ip->ip))
        break;

      if (SSH_IP_IS6(peer) && SSH_IP_IS6(&local_ip->ip))
        {
          /* Found link-local local address for link-local peer. */
          if (SSH_IP6_IS_LINK_LOCAL(peer)
              && SSH_IP6_IS_LINK_LOCAL(&local_ip->ip))
            break;

          /* Found global local address for global peer. */
          if (!SSH_IP6_IS_LINK_LOCAL(peer)
              && !SSH_IP6_IS_LINK_LOCAL(&local_ip->ip))
            break;

          /* Found non-optimal link-local/global address pair.
             Continue searching for a better pair. */
          if (!SSH_IP_DEFINED(local_ip_ret))
            *local_ip_ret = local_ip->ip;
        }
    }
  if (local_ip != NULL)
    *local_ip_ret = local_ip->ip;
}


/* **** Utility functions for accessing information from IPsec SA's *********/

SshInetIPProtocolID
ssh_pm_ipsec_sa_get_protocol(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa)
{
  SSH_ASSERT(ipsec_sa != NULL);

  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      if (ipsec_sa->qm->transform & SSH_PM_IPSEC_ESP)
        return SSH_IPPROTO_ESP;
      else if (ipsec_sa->qm->transform & SSH_PM_IPSEC_AH)
        return SSH_IPPROTO_AH;

      SSH_NOTREACHED;
      return SSH_IPPROTO_ANY;

    case SSH_PM_SA_EVENT_DELETED:
      return ipsec_sa->ipproto;

    case SSH_PM_SA_EVENT_UPDATED:
      if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
          SSH_ASSERT(ipsec_sa->spi_out != NULL);
          return ipsec_sa->spi_out->ipproto;
        }
      else if (ipsec_sa->update_type
               == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        return ipsec_sa->ipproto;
      else
        SSH_NOTREACHED;
      break;
    }

  SSH_NOTREACHED;
  return SSH_IPPROTO_ANY;
}

SshUInt32
ssh_pm_ipsec_sa_get_inbound_spi(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa)
{
  SshEngineTransformData trd;
  SshUInt32 spi = 0;

  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      trd = &ipsec_sa->qm->sa_handler_data.trd.data;
      if (ipsec_sa->qm->transform & SSH_PM_IPSEC_ESP)
        spi = trd->spis[SSH_PME_SPI_ESP_IN];
      else if (ipsec_sa->qm->transform & SSH_PM_IPSEC_AH)
        spi = trd->spis[SSH_PME_SPI_AH_IN];
      else if (ipsec_sa->qm->transform & SSH_PM_IPSEC_IPCOMP)
        spi = trd->spis[SSH_PME_SPI_IPCOMP_IN];
      return spi;

    case SSH_PM_SA_EVENT_DELETED:
      return ipsec_sa->inbound_spi;

    case SSH_PM_SA_EVENT_UPDATED:
      if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
          SSH_ASSERT(ipsec_sa->spi_out != NULL);
          return ipsec_sa->spi_out->inbound_spi;
        }
      else if (ipsec_sa->update_type
               == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        return ipsec_sa->inbound_spi;
      else
        SSH_NOTREACHED;
      break;
    }

  SSH_NOTREACHED;
  return spi;
}

SshUInt32
ssh_pm_ipsec_sa_get_outbound_spi(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa)
{
  SshEngineTransformData trd;
  SshUInt32 spi = 0;

  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      trd = &ipsec_sa->qm->sa_handler_data.trd.data;
      if (ipsec_sa->qm->transform & SSH_PM_IPSEC_ESP)
        spi = trd->spis[SSH_PME_SPI_ESP_OUT];
      else if (ipsec_sa->qm->transform & SSH_PM_IPSEC_AH)
        spi = trd->spis[SSH_PME_SPI_AH_OUT];
      else if (ipsec_sa->qm->transform & SSH_PM_IPSEC_IPCOMP)
        spi = trd->spis[SSH_PME_SPI_IPCOMP_OUT];
      return spi;

    case SSH_PM_SA_EVENT_DELETED:
      return ipsec_sa->outbound_spi;

    case SSH_PM_SA_EVENT_UPDATED:
      if (ipsec_sa->update_type == SSH_PM_IPSEC_SA_UPDATE_PEER_UPDATED)
        {
          SSH_ASSERT(ipsec_sa->spi_out != NULL);
          return ipsec_sa->spi_out->outbound_spi;
        }
      else if (ipsec_sa->update_type
               == SSH_PM_IPSEC_SA_UPDATE_OLD_SPI_INVALIDATED)
        return ipsec_sa->outbound_spi;
      else
        SSH_NOTREACHED;
      break;
    }

  SSH_NOTREACHED;
  return spi;
}

SshUInt32
ssh_pm_ipsec_sa_get_old_inbound_spi(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa)
{
  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      return ipsec_sa->qm->old_inbound_spi;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get old outbound SPI for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
  return 0;
}

SshUInt32
ssh_pm_ipsec_sa_get_life_seconds(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa)
{
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      if (ipsec_sa->life_seconds > 0)
        return ipsec_sa->life_seconds;
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      return ipsec_sa->qm->trd_life_seconds;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get SA lifetime for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
  return 0;
}

SshUInt32
ssh_pm_ipsec_sa_get_remaining_life_seconds(SshPm pm,
                                           SshPmIPsecSAEventHandle ipsec_sa)
{
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      return ipsec_sa->qm->trd_life_seconds;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get remaining SA lifetime for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
  return 0;
}

SshUInt32
ssh_pm_ipsec_sa_get_life_kilobytes(SshPm pm, SshPmIPsecSAEventHandle ipsec_sa)
{
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      return ipsec_sa->qm->trd_life_kilobytes;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get SA kilobyte lifetime for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
  return 0;
}

void
ssh_pm_ipsec_sa_get_outbound_sequence_number(SshPm pm,
                                             SshPmIPsecSAEventHandle ipsec_sa,
                                             SshUInt32 *seq_low,
                                             SshUInt32 *seq_high)
{
  SshEngineTransformData trd;

  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      trd = &ipsec_sa->qm->sa_handler_data.trd.data;

      if (ipsec_sa->qm->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          *seq_low = trd->out_packets_low;
          *seq_high = trd->out_packets_high;
        }
      else
        {
          *seq_low = trd->out_packets_low;
          *seq_high = SSH_IPSEC_INVALID_INDEX;
        }
      return;

    default:
      break;
    }

  *seq_low = 0;
  *seq_high = 0;

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get outbound sequence for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}

void
ssh_pm_ipsec_sa_get_replay_window(SshPm pm,
                                  SshPmIPsecSAEventHandle ipsec_sa,
                                  SshUInt32 *replay_offset_low,
                                  SshUInt32 *replay_offset_high,
                                  SshUInt32 *replay_mask)
{
  SshEngineTransformData trd;

  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      trd = &ipsec_sa->qm->sa_handler_data.trd.data;

      *replay_offset_low = trd->replay_offset_low;
      *replay_offset_high = trd->replay_offset_high;
      memcpy(replay_mask, trd->replay_mask, sizeof(trd->replay_mask));
      return;

    default:
      break;
    }

  *replay_offset_low = 0;
  *replay_offset_high = 0;
  memset(replay_mask, 0, sizeof(trd->replay_mask));

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get replay window for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}

#ifdef SSHDIST_IPSEC_SA_EXPORT

/* Sets the outbound sequence numbers for 'ipsec_sa' to 'seq_high' and
   'seq_low'. Specify 'seq_high' as SSH_IPSEC_INVALID_INDEX if SA does
   not use ESN. */
void
ssh_pm_ipsec_sa_set_outbound_sequence_number(SshPm pm,
                                             SshPmIPsecSAEventHandle ipsec_sa,
                                             SshUInt32 seq_low,
                                             SshUInt32 seq_high)
{
  SshEngineTransformData trd;

  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      SSH_DEBUG(SSH_D_LOWOK,
                ("Setting outbound IPsec sequence to 0x%lx 0x%lx for qm %p",
                 (unsigned long) seq_high,
                 (unsigned long) seq_low,
                 ipsec_sa->qm));
      trd = &ipsec_sa->qm->sa_handler_data.trd.data;
      if (ipsec_sa->qm->transform & SSH_PM_IPSEC_LONGSEQ)
        {
          trd->out_packets_low = seq_low;
          trd->out_packets_high = seq_high;
        }
      else
        {
          trd->out_packets_low = seq_low;
          trd->out_packets_high = 0;
        }
      return;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set outbound sequence for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}

/* Sets the replay window for 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_replay_window(SshPm pm,
                                  SshPmIPsecSAEventHandle ipsec_sa,
                                  SshUInt32 replay_offset_low,
                                  SshUInt32 replay_offset_high,
                                  SshUInt32 *replay_mask)
{
  SshEngineTransformData trd;

  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      trd = &ipsec_sa->qm->sa_handler_data.trd.data;

      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Setting replay window for qm %p: "
                         "offset 0x%lx 0x%lx:",
                         ipsec_sa->qm,
                         (unsigned long) replay_offset_high,
                         (unsigned long) replay_offset_low),
                        (unsigned char *) replay_mask,
                        sizeof(trd->replay_mask));

      trd->replay_offset_low = replay_offset_low;
      trd->replay_offset_high = replay_offset_high;
      memcpy(trd->replay_mask, replay_mask, sizeof(trd->replay_mask));

      return;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set replay window for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}

/* Sets the kilobyte lifetime for 'ipsec_sa' to 'life_kilobytes'. */
void
ssh_pm_ipsec_sa_set_life_kilobytes(SshPm pm,
                                   SshPmIPsecSAEventHandle ipsec_sa,
                                   SshUInt32 life_kilobytes)
{
  SSH_ASSERT(ipsec_sa != NULL);
  switch (ipsec_sa->event)
    {
    case SSH_PM_SA_EVENT_CREATED:
    case SSH_PM_SA_EVENT_REKEYED:
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      SSH_DEBUG(SSH_D_LOWOK,
                ("Setting IPsec SA kilobyte lifetime to %d kb for qm %p",
                 (unsigned long) life_kilobytes,
                 ipsec_sa->qm));
      ipsec_sa->qm->trd_life_kilobytes = life_kilobytes;
      return;

    default:
      break;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set kilobyte lifetime for SA event other than "
             "SSH_PM_SA_EVENT_CREATED or SSH_PM_SA_EVENT_REKEYED"));
}


/* Return IPsec SA's tunnel application identifier. */
Boolean
ssh_pm_ipsec_sa_get_tunnel_application_identifier(SshPm pm,
                                              SshPmIPsecSAEventHandle ipsec_sa,
                                              unsigned char *id,
                                              size_t *id_len)
{
  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(id != NULL);
  SSH_ASSERT(id_len != NULL);

  if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      if (*id_len < ipsec_sa->tunnel_application_identifier_len)
        return FALSE;

      memcpy(id, ipsec_sa->tunnel_application_identifier,
             ipsec_sa->tunnel_application_identifier_len);
      *id_len = ipsec_sa->tunnel_application_identifier_len;

      return TRUE;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get tunnel application identifier for SA event other "
             "than SSH_PM_SA_EVENT_CREATED"));

  return FALSE;
}

/* Sets the 'tunnel' for IPsec SA 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_tunnel(SshPm pm,
                           SshPmIPsecSAEventHandle ipsec_sa,
                           SshPmTunnel tunnel)
{
  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(tunnel != NULL);

  if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      SSH_PM_ASSERT_QM(ipsec_sa->qm);

      SSH_DEBUG(SSH_D_LOWOK, ("Setting tunnel_id %d for qm %p",
                              (int) tunnel->tunnel_id, ipsec_sa->qm));
      SSH_PM_TUNNEL_TAKE_REF(tunnel);
      if (ipsec_sa->qm->tunnel)
        SSH_PM_TUNNEL_DESTROY(pm, ipsec_sa->qm->tunnel);
      ipsec_sa->qm->tunnel = tunnel;
      ipsec_sa->qm->sa_handler_data.trd.data.inbound_tunnel_id =
        tunnel->tunnel_id;
      return;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set tunnel id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));
}

/* Return IPsec SA's outer tunnel application identifier. */
Boolean
ssh_pm_ipsec_sa_get_outer_tunnel_application_identifier(SshPm pm,
                                              SshPmIPsecSAEventHandle ipsec_sa,
                                              unsigned char *id,
                                              size_t *id_len)
{
  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(id != NULL);
  SSH_ASSERT(id_len != NULL);

  if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      if (*id_len < ipsec_sa->outer_tunnel_application_identifier_len)
        return FALSE;

      memcpy(id, ipsec_sa->outer_tunnel_application_identifier,
             ipsec_sa->outer_tunnel_application_identifier_len);
      *id_len = ipsec_sa->outer_tunnel_application_identifier_len;

      return TRUE;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get outer tunnel id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));

  return FALSE;
}

/* Sets the 'outer_tunne' for IPsec SA 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_outer_tunnel(SshPm pm,
                                 SshPmIPsecSAEventHandle ipsec_sa,
                                 SshPmTunnel outer_tunnel)
{
  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(outer_tunnel != NULL);

  if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      SSH_PM_ASSERT_QM(ipsec_sa->qm);
      SSH_DEBUG(SSH_D_LOWOK, ("Setting outer_tunnel_id %d for qm %p",
                              (int) outer_tunnel->tunnel_id, ipsec_sa->qm));
      ipsec_sa->qm->sa_handler_data.trd.control.outer_tunnel_id =
        outer_tunnel->tunnel_id;
      return;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set outer tunnel id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));
}

/* Returns the IPsec SA's rule application identifier. */
Boolean
ssh_pm_ipsec_sa_get_rule_application_identifier(SshPm pm,
                                              SshPmIPsecSAEventHandle ipsec_sa,
                                              unsigned char *id,
                                              size_t *id_len)
{
  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(id != NULL);
  SSH_ASSERT(id_len != NULL);

  if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      if (*id_len < ipsec_sa->rule_application_identifier_len)
        return FALSE;

      memcpy(id, ipsec_sa->rule_application_identifier,
             ipsec_sa->rule_application_identifier_len);
      *id_len = ipsec_sa->rule_application_identifier_len;

      return TRUE;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot get rule application identifier for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));

  return FALSE;
}

/* Sets the 'rule' for IPsec SA 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_rule(SshPm pm,
                         SshPmIPsecSAEventHandle ipsec_sa,
                         SshPmRule rule)
{
  SSH_ASSERT(ipsec_sa != NULL);
  SSH_ASSERT(rule != NULL);

  if (ipsec_sa->event == SSH_PM_SA_EVENT_CREATED)
    {
      SSH_PM_ASSERT_QM(ipsec_sa->qm);

      SSH_DEBUG(SSH_D_LOWOK, ("Setting rule_id %d for qm %p",
                              (int) rule->rule_id, ipsec_sa->qm));
      SSH_PM_RULE_LOCK(rule);
      if (ipsec_sa->qm->rule)
        SSH_PM_RULE_UNLOCK(pm, ipsec_sa->qm->rule);
      ipsec_sa->qm->rule = rule;
      return;
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Cannot set rule id for SA event other than "
             "SSH_PM_SA_EVENT_CREATED"));
}

#endif /* SSHDIST_IPSEC_SA_EXPORT */
