/**
   @copyright
   Copyright (c) 2005 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Policy manager SAD module.
*/

#include "sshincludes.h"
#include "sshadt.h"
#include "sshadt_map.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmIkeSAD"

/* The amount of seconds before waiting to delete an IKE SA after it
   has been rekeyed. */
#define SSH_PM_IKE_SA_DELETE_SECONDS_DELAY 30

/*--------------------------------------------------------------------*/

/* Return true if IKE library calls are allowed. */
Boolean pm_ike_async_call_possible(SshIkev2Sa sa, int *slot)
{
  int i;
  SshPmP1 p1 = (SshPmP1)sa;
  Boolean reserve_for_rekey = FALSE;
  SshUInt32 transmit_window_size;

#ifdef SSHDIST_IKEV1
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      transmit_window_size = PM_IKE_MAX_WINDOW_SIZE;
    }
  else
#endif /* SSHDIST_IKEV1 */
    {
      transmit_window_size = p1->ike_sa->transmit_window->window_size;
      if (transmit_window_size == 0)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Async call not possible, transmit window size 0"));
          return FALSE;
        }

      if (transmit_window_size > PM_IKE_MAX_WINDOW_SIZE)
        transmit_window_size = PM_IKE_MAX_WINDOW_SIZE;
    }

  /* Check if this IKE SA is being rekeyed. In such case one slot is already
     being used by the IKE library and must be taken into account here. */
  if (p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL)
    reserve_for_rekey = TRUE;

  for (i = 0; i < transmit_window_size; i++)
    {
      if (p1->initiator_eds[i] == NULL)
        {
          if (reserve_for_rekey == FALSE)
            {
              *slot = i;
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Async call using slot %d (transmit window size %d)",
                         i, (int) transmit_window_size));
              return TRUE;
            }
          else
            reserve_for_rekey = FALSE;
        }
    }

  SSH_DEBUG(SSH_D_FAIL,
            ("Async call not possible, all ed slots in use "
             "(transmit window size %d)",
             (int) transmit_window_size));
  return FALSE;
}

Boolean pm_ike_async_call_pending(SshIkev2Sa sa)
{
  int i;
  SshPmP1 p1 = (SshPmP1)sa;

  if (p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL)
    return TRUE;

  for (i = 0; i < PM_IKE_MAX_WINDOW_SIZE; i++)
    {
      if (p1->initiator_eds[i] != NULL)
        return TRUE;
    }

  return FALSE;
}

/************** FSM thread for handling SA negotiation ******************/

/* Free resources used by the Phase-I negotiation. */
static void
ssh_pm_p1_n_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
  SshPmP1 p1 = (SshPmP1) context;
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  SshPmAuthDomain cert_ad;
  SshCMSearchConstraints search_constraints = NULL;
  SshCMCertList cert_list = NULL;
  SshCertDBKey *search_keys = NULL;
  SshCMCertificate cmcert = NULL;
  SshCMStatus status;
  SshUInt32 i;
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  SSH_DEBUG(SSH_D_NICETOKNOW , ("Phase-I negotiation thread destructor"));

  SSH_PM_ASSERT_P1(p1);
  SSH_PM_ASSERT_P1N(p1);
  SSH_ASSERT(p1->n->next || p1->n->prev || pm->active_p1_negotiations == p1);

  /* If we have LA authentication operation ongoing, we must abort it now. */
  if (p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH])
    ssh_operation_abort(p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH]);

  p1->initiator_ops[PM_IKE_INITIATOR_OP_LA_AUTH] = NULL;

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (p1->first_round_auth_domain)
    cert_ad = p1->first_round_auth_domain;
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    cert_ad = p1->auth_domain;

  if (!cert_ad)
    {
      SSH_ASSERT(p1->n->num_ca_certificate_ids == 0);
      SSH_ASSERT(p1->n->num_user_certificate_ids == 0);
    }

  /* Free the references to the CA certificates. */
  for (i = 0; i < p1->n->num_ca_certificate_ids; i++)
    {
      search_constraints = ssh_cm_search_allocate();
      search_keys = NULL;
      if (search_constraints == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate CM search."));
          continue;
        }

      if (!ssh_cm_key_set_cache_id(&search_keys,
                                  p1->n->ca_certificate_ids[i]))
        {
          ssh_cm_search_free(search_constraints);
          SSH_DEBUG(SSH_D_ERROR, ("Failed to set cache ID to search"
                                  " constraints."));
          continue;
        }

      ssh_cm_search_set_keys(search_constraints, search_keys);
      status = ssh_cm_find_local_cert(cert_ad->cm, search_constraints,
                                      &cert_list);
      if (status != SSH_CM_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));
          continue;
        }

      /* This is safe to do, as the cache id must be unique and therefore
         there cannot be more elements in this list. */
      cmcert = ssh_cm_cert_list_first(cert_list);
      SSH_ASSERT(cmcert != NULL);
      ssh_cm_cert_list_free(cert_ad->cm, cert_list);
      ssh_cm_cert_remove_reference(cmcert);

      /* Invalidate the ID. */
      p1->n->ca_certificate_ids[i] = 0;
    }

  /* Free the references to the certificates. */
  for (i = 0; i < p1->n->num_user_certificate_ids; i++)
    {
      search_constraints = ssh_cm_search_allocate();
      search_keys = NULL;
      if (search_constraints == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Failed to allocate CM search."));
          continue;
        }

      if (!ssh_cm_key_set_cache_id(&search_keys,
                                   p1->n->user_certificate_ids[i]))
        {
          ssh_cm_search_free(search_constraints);
          SSH_DEBUG(SSH_D_ERROR, ("Failed to set cache ID to search"
                                  " constraints."));
          continue;
        }

      ssh_cm_search_set_keys(search_constraints, search_keys);
      status = ssh_cm_find_local_cert(cert_ad->cm, search_constraints,
                                      &cert_list);
      if (status != SSH_CM_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Search failed: %d", status));
          continue;
        }

      /* This is safe to do, as the cache id must be unique and therefore
         there cannot be more elements in this list. */
      cmcert = ssh_cm_cert_list_first(cert_list);
      SSH_ASSERT(cmcert != NULL);
      ssh_cm_cert_list_free(cert_ad->cm, cert_list);
      ssh_cm_cert_remove_reference(cmcert);

      /* Invalidate the ID. */
      p1->n->user_certificate_ids[i] = 0;
    }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  ssh_pm_p1_negotiation_free(pm, p1->n);
  p1->n = NULL;

  if (p1->delete_with_negotiation)
    {
      SshADTHandle handle;

      handle = ssh_adt_get_handle_to_equal(pm->sad_handle->ike_sa_by_spi,
                                           p1->ike_sa);
      if (handle != SSH_ADT_INVALID)
        ssh_adt_detach(pm->sad_handle->ike_sa_by_spi, handle);

      ssh_ikev2_ike_sa_uninit(p1->ike_sa);
      ssh_pm_p1_free(pm, p1);
    }
}

SSH_FSM_STEP(ssh_pm_st_p1_negotiation)
{
  SshPmP1 p1 = thread_context;

  /* Just wait until the Phase-I is completed */
  if (!p1->done)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Suspending until IKE completes"));
      return SSH_FSM_SUSPENDED;
    }

  /* Wait for sub thread to finish. */
  if (SSH_FSM_THREAD_EXISTS(&p1->n->sub_thread))
    {
      SSH_FSM_WAIT_THREAD(&p1->n->sub_thread);
      SSH_NOTREACHED;
    }

  /* Wait until all threads waiting on the Phase-I have gone away. */
  SSH_PM_ASSERT_P1N(p1);
  if (p1->n->wait_num_threads)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("P1 negotiation terminating; waiting for %d threads",
                 (int) p1->n->wait_num_threads));
      SSH_FSM_CONDITION_BROADCAST(&p1->n->wait_condition);
      SSH_FSM_CONDITION_WAIT(&p1->n->wait_condition);
    }

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IKE_XAUTH
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /* For responder negotiations check if we should initiate
     XAUTH/CFGMODE to the peer. */
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
      !(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) &&
      !p1->failed)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_check_cfgmode);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IKEV1 */

#ifdef SSH_IPSEC_TCPENCAP
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_tcp_encaps_check_natt);
  else
#endif /* SSH_IPSEC_TCPENCAP */
    SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_done);

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IKE_XAUTH
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
SSH_FSM_STEP(ssh_pm_st_p1_negotiation_check_cfgmode)
{
  SshPmP1 p1 = thread_context;
  SshPm pm = fsm_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Checking whether to initiate Xauth/CFGMode"));

  /* Extended authentication should be initiated where the client
     indicates it will not start qm before XAUTH is done.

     We may also start a CFGMODE exchange here even if not doing XAUTH.
     This is when the remote peer will not initiate CFGMODE and expects
     the gateway to do so (SoftRemote behaves in this fashion). In this
     case the p1->ike_sa->server_cfg_pending flag is set */
  if (p1->ike_sa->server_cfg_pending ||
      (pm->xauth.enabled && (p1->ike_sa->xauth_enabled)))
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Initiating Xauth/CFGMode"));

      PM_SUSPEND_CONDITION_WAIT(pm, thread);

      if (p1->ike_sa->xauth_enabled)
        p1->ike_sa->xauth_started = 1;

      if (!ssh_pm_p1_initiate_xauth_ike(pm, p1))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to start Xauth/CFGmode"));
        }
    }

#ifdef SSH_IPSEC_TCPENCAP
  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_tcp_encaps_check_natt);
  else
#endif /* SSH_IPSEC_TCPENCAP */
    SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_done);

  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IKEV1 */

#ifdef SSH_IPSEC_TCPENCAP
static void
pm_st_p1_negotiation_update_ike_mapping_cb(SshPm pm, SshUInt32 conn_id,
                                           void *context)
{
  SshPmP1 p1 = context;

  SSH_DEBUG(SSH_D_LOWOK,
            ("TCP encapsulation IKE mapping updated: "
             "IKE SA %p connection entry 0x%lx",
             p1->ike_sa, (unsigned long) conn_id));

  if (conn_id == SSH_IPSEC_INVALID_INDEX)
    p1->ike_sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&p1->n->thread);
}

SSH_FSM_STEP(ssh_pm_st_p1_negotiation_tcp_encaps_check_natt)
{
  SshPmP1 p1 = thread_context;
  SshPm pm = fsm_context;

  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE)
      && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP))
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Removing TCP encapsulation for IKE SA %p",
                 p1->ike_sa));

      /* IKE SA has moved to using NATT, remove TCP encapsulation mapping. */

      SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_tcp_encaps_check_natt);
      SSH_FSM_ASYNC_CALL({
        ssh_pme_tcp_encaps_update_ike_mapping(pm->engine, FALSE,
                                    NULL, NULL, p1->ike_sa->ike_spi_i, NULL,
                                    pm_st_p1_negotiation_update_ike_mapping_cb,
                                    p1);
      });
      SSH_NOTREACHED;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_p1_negotiation_done);
  return SSH_FSM_CONTINUE;
}
#endif /* SSH_IPSEC_TCPENCAP */

SSH_FSM_STEP(ssh_pm_st_p1_negotiation_done)
{
  /* We are finished with this thread. */
  return SSH_FSM_FINISH;
}


/************** FSM thread for handling SA deletion ******************/

/* This is the completion callback for ssh_pme_delete_by_peer_handle(). */
static void
pm_ike_sa_delete_cb(SshPm pm,
                    Boolean done,
                    SshUInt32 peer_handle,
                    SshEngineTransform tr,
                    void *policy_context,
                    void *context)
{
  SshFSMThread thread = context;
  SshPmP1 p1 = ssh_fsm_get_tdata(thread);
  SshUInt32 outbound_spi[2];
  SshUInt32 inbound_spi[2];
  SshUInt8 ipproto = 0;
  int num_spis, i;

  SSH_DEBUG(SSH_D_LOWOK, ("In IKE SA delete callback for p1 %p, done=%d",
                          p1, done));

  /* Indicate that the IPsec SA has been destroyed. */
  if (tr != NULL)
    {
      num_spis = 0;
      if (tr->data.transform & SSH_PM_IPSEC_AH)
        {
          ipproto = SSH_IPPROTO_AH;
          if (tr->data.spis[SSH_PME_SPI_AH_IN] != 0)
            {
              outbound_spi[num_spis] = tr->data.spis[SSH_PME_SPI_AH_OUT];
              inbound_spi[num_spis++] = tr->data.spis[SSH_PME_SPI_AH_IN];
            }
          if (tr->data.old_spis[SSH_PME_SPI_AH_IN] != 0)
            {
              outbound_spi[num_spis] = tr->data.old_spis[SSH_PME_SPI_AH_OUT];
              inbound_spi[num_spis++] = tr->data.old_spis[SSH_PME_SPI_AH_IN];
            }
        }
      else if (tr->data.transform & SSH_PM_IPSEC_ESP)
        {
          ipproto = SSH_IPPROTO_ESP;
          if (tr->data.spis[SSH_PME_SPI_ESP_IN] != 0)
            {
              outbound_spi[num_spis] = tr->data.spis[SSH_PME_SPI_ESP_OUT];
              inbound_spi[num_spis++] = tr->data.spis[SSH_PME_SPI_ESP_IN];
            }
          if (tr->data.old_spis[SSH_PME_SPI_ESP_IN] != 0)
            {
              outbound_spi[num_spis] = tr->data.old_spis[SSH_PME_SPI_ESP_OUT];
              inbound_spi[num_spis++] = tr->data.old_spis[SSH_PME_SPI_ESP_IN];
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Invalid transform mask 0x%08lx, not ESP or AH",
                     (unsigned long) tr->data.transform));
          SSH_NOTREACHED;
          goto out;
        }

      /* Indicate that the IPsec SA has been destroyed. */
      for (i = 0; i < num_spis; i++)
        {
          if (ssh_pm_spi_disable_sa_events(pm, outbound_spi[i],
                                           inbound_spi[i], TRUE))
            ssh_pm_ipsec_sa_event_deleted(pm, outbound_spi[i],
                                          inbound_spi[i], ipproto);
        }
    }

 out:
  p1->delete_child_sas_done = done ? 1 : 0;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(pm_ike_sa_delete)
{
  SshPm pm = fsm_context;
  SshPmP1 p1 = thread_context;
  SshPmPeer peer;

  /* Wait first for the Phase-I negotiation thread to end. */
  if (p1->n)
    {
      SSH_DEBUG(SSH_D_HIGHSTART,
                ("Wait for Phase-I negotiation thread to finish p1=%p, "
                 "marking p1 as failed", p1));
      p1->done = 1;
      p1->failed = 1;

      ssh_fsm_continue(&p1->n->thread);
      SSH_FSM_WAIT_THREAD(&p1->n->thread);
    }

  peer = ssh_pm_peer_by_p1(pm, p1);

  if (p1->delete_child_sas_done)
    {
#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      /* Free the address */
      if (p1->cfgmode_client && p1->cfgmode_client->free_cb)
        {
          /* Release client IP addresses from client store. */
          SSH_PM_CFGMODE_CLIENT_FREE_REF(pm, p1->cfgmode_client);
          p1->cfgmode_client = NULL;
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

      /* Clear the mapping of IPSec SA's to the parent IKE SA. The
         ssh_pm_peer_p1_update_p1 function moves IKE peer from the
         old to the new IKE SA. When the new IKE SA is NULL as is specified
         here, this clears the old IKE SA from the IKE peer. Note that the
         mapping from IPsec SA's to the IKE peer is not modified. */
      if (peer)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Clearing IKE SA %p from peer handle", p1));
          ssh_pm_peer_update_p1(pm, peer, NULL);
        }

      /* There might be multiple IKE peers pointing to same IKE SA. */
      peer = ssh_pm_peer_by_p1(pm, p1);
      if (peer == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Terminating thread for deleting IPSec SA's "
                                  "for IKE SA %p", p1));
          return SSH_FSM_FINISH;
        }

      /* Continue deleting child SAs. */
      p1->delete_child_sas_done = 0;
    }

  SSH_FSM_SET_NEXT(pm_ike_sa_delete);

#ifdef SSHDIST_IKEV1
  /* For IKEv1 SA's we do not delete their child IPsec SA's, unless explicitly
     requested (fatal initiator error or we are deleting SAs by peer). */
  if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
      && !p1->delete_child_sas)
    {
      p1->delete_child_sas_done = 1;
      return SSH_FSM_CONTINUE;
    }
  else
#endif /* SSHDIST_IKEV1 */
    {
      /* For IKEv2 SA's, delete all child IPSec SA's. */
      SSH_DEBUG(SSH_D_LOWOK, ("Deleting child SAs for IKE SA %p", p1));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /* Mark virtual IP interface unusable. */
      if (!p1->rekeyed)
        ssh_pm_vip_mark_unusable(pm, p1);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      if (peer)
        {
          SSH_FSM_ASYNC_CALL({
            ssh_pme_delete_by_peer_handle(pm->engine, peer->peer_handle,
                                          pm_ike_sa_delete_cb, thread);
          });
          SSH_NOTREACHED;
        }

      /* IKE SA does not have any child SAs. */
      p1->delete_child_sas_done = 1;
      return SSH_FSM_CONTINUE;
    }
  SSH_NOTREACHED;
}

void pm_ike_sa_delete_abort(void *context)
{
  SshPmP1 p1 = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Aborting IKE SA delete for IKE SA %p", p1));
  ssh_free(p1->ike_sa->waiting_for_delete);
  p1->ike_sa->waiting_for_delete = NULL;
}

static void
pm_p1_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = (SshPm) ssh_fsm_get_gdata_fsm(fsm);
  SshPmP1 p1 = (SshPmP1) context;

  SSH_PM_ASSERT_P1(p1);

  /* Free the IKE SA reference taken for the duration of child SA
     deletion. If this is the last reference, then the IKE SA is
     destroyed and the delete callback is called. */
  SSH_PM_IKE_SA_FREE_REF(pm->sad_handle, p1->ike_sa);
}

static void pm_start_ipsec_sa_delete_thread(SshPm pm, SshPmP1 p1)
{
  SSH_DEBUG(SSH_D_LOWOK, ("Starting thread to delete IPSec SA's"));

  /* Take one reference for the duration of child SA deletion. */
  SSH_PM_IKE_SA_TAKE_REF(p1->ike_sa);

  /* We use the p1->delete_child_sas_done for indicating when the delete
     operation is finished. */
  p1->delete_child_sas_done = 0;
  ssh_fsm_thread_init(&pm->fsm, &p1->thread,
                      pm_ike_sa_delete, NULL_FNPTR,
                      pm_p1_thread_destructor,
                      p1);
  ssh_fsm_set_thread_name(&p1->thread, "IKE delete");
}

static void pm_p1_destroy(SshPm pm, SshPmP1 p1)
{
  SshADTHandle handle;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshPmTunnel tunnel;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  SSH_PM_ASSERT_P1(p1);
  SSH_ASSERT(p1->ike_sa->ref_cnt == 0);
  SSH_ASSERT(p1->delete_child_sas_started);
  SSH_ASSERT(p1->delete_child_sas_done);

  if (p1->ike_sa->waiting_for_delete)
    {
      /* Call the deleted callback now */
      SSH_DEBUG(SSH_D_LOWOK, ("Calling IKE waiting for delete callback "
                              "for IKE SA %p", p1));

      if (p1->ike_sa->waiting_for_delete->delete_callback)
        (*p1->ike_sa->waiting_for_delete->delete_callback)
          (SSH_IKEV2_ERROR_OK,
           p1->ike_sa->waiting_for_delete->delete_callback_context);

      ssh_operation_unregister(p1->ike_sa->waiting_for_delete->
                               operation_handle);
      ssh_free(p1->ike_sa->waiting_for_delete);
      p1->ike_sa->waiting_for_delete = NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Destroying Phase-I object %p", p1));

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel && tunnel->vip)
    ssh_pm_virtual_ip_free(pm, SSH_IPSEC_INVALID_INDEX, tunnel);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL, "");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "IKE SA destroyed: ");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Initiator SPI %@ Responder SPI %@",
                    ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_i,
                    ssh_pm_render_ike_spi, p1->ike_sa->ike_spi_r);
    }

  handle = ssh_adt_get_handle_to_equal(pm->sad_handle->ike_sa_by_spi,
                                       p1->ike_sa);
  if (handle != SSH_ADT_INVALID)
    ssh_adt_detach(pm->sad_handle->ike_sa_by_spi, handle);

  /* Call the SA notification callback if this SA was
     successfully negotiated earlier. */
  ssh_pm_ike_sa_event_deleted(pm, p1);

  ssh_pm_ike_sa_hash_remove(pm, p1);

  ssh_ikev2_ike_sa_uninit(p1->ike_sa);

  /* Free this Phase-1 structure. */
  ssh_pm_p1_free(pm, p1);
}

SshOperationHandle
ssh_pm_ike_sa_delete(SshSADHandle sad_handle,
                     SshIkev2Sa sa,
                     SshIkev2SadDeleteCB reply_callback,
                     void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1 = (SshPmP1)sa;
  SshPmQm qm, next_qm;
  int i;

  SSH_ASSERT(sa->waiting_for_delete == NULL);
  SSH_ASSERT(sa->ref_cnt > 0);

  SSH_DEBUG(SSH_D_MIDSTART, ("Deleting IKE SA %p, current refcount %d",
                             sa, (int) sa->ref_cnt));

  if ((sa->waiting_for_delete =
       ssh_calloc(1, sizeof(*sa->waiting_for_delete))) == NULL)
    {
      SSH_PM_IKE_SA_FREE_REF(sad_handle, sa);
      if (reply_callback)
        (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY,
                          reply_callback_context);
      return NULL;
    }

  /* Don't use this SA for new negotiations, and abort all the operations
     using it. */
  p1->unusable = 1;

  for (i = 0; i < PM_IKE_NUM_INITIATOR_OPS; i++)
    {
      SshOperationHandle op = p1->initiator_ops[i];

      /* Do not abort the IKE SA delete operation. */
      if (i == PM_IKE_INITIATOR_OP_DELETE)
        continue;

      /* Clear the operation handle from the p1 to avoid recursive
         calls aborting the operations. */
      p1->initiator_ops[i] = NULL;
      if (op)
        ssh_operation_abort(op);
    }

  /* For IKEv1 SAs we might receive an SA deletion from the peer while
     still having active negotiations on that SA.  For IKEv2 SAs we
     might have window larger than one exchange, and in that case we
     need to take care of all but the offending exchange by hand. In
     such cases we abort the negotiations here. */
  for (i = 0; i < PM_IKE_MAX_WINDOW_SIZE; i++)
    {
      if (p1->initiator_eds[i] != NULL)
        {
          SshIkev2ExchangeData tmp = p1->initiator_eds[i];

          if (tmp->ipsec_ed)
            {
              /* Abort active IPsec negotiations */
              p1->initiator_eds[i] = NULL;
              if (tmp->ipsec_ed->flags & SSH_IKEV2_IPSEC_OPERATION_REGISTERED)
                ssh_operation_abort(tmp->ipsec_ed->operation_handle);
            }
          else if (tmp->info_ed)
            {
              /* Abort active info exchanges */
              p1->initiator_eds[i] = NULL;
              if (tmp->info_ed->flags & SSH_IKEV2_INFO_OPERATION_REGISTERED)
                ssh_operation_abort(tmp->info_ed->operation_handle);
            }
          ssh_ikev2_exchange_data_free(tmp);
        }
    }

  /* Run active Quick-Mode threads to completion if possible */
  for (qm = pm->active_qm_negotiations; qm; qm = next_qm)
    {
      next_qm = qm->next;

      if (qm->p1 == p1)
        {
          SSH_DEBUG(SSH_D_MIDSTART, ("Failing Quick-Mode %p, reason IKE "
                                     "SA deletion", qm));





          ssh_pm_qm_thread_abort(pm, qm);
          qm->p1 = NULL;
        }
    }
  /* We're gone - no-one should miss */
  if (p1->n)
    p1->n->wait_num_threads = 0;

  SSH_DEBUG(SSH_D_LOWSTART, ("Entered IKE SA %p delete, %d references "
                             "outstanding", sa, (int) sa->ref_cnt));

  sa->waiting_for_delete->delete_callback = reply_callback;
  sa->waiting_for_delete->delete_callback_context = reply_callback_context;
  ssh_operation_register_no_alloc(sa->waiting_for_delete->operation_handle,
                                  pm_ike_sa_delete_abort, p1);

  /* Delete child SAs immediately. */
  if (p1->delete_child_sas_started == 0)
    {
      p1->delete_child_sas_started = 1;
      pm_start_ipsec_sa_delete_thread(pm, p1);
    }

  /* Set expire time to time of IKE SA deletion. */
  p1->expire_time = ssh_time();

  if (sa->ref_cnt > 1)
    {
      SSH_PM_IKE_SA_FREE_REF(sad_handle, sa);
      return sa->waiting_for_delete->operation_handle;
    }

  SSH_ASSERT(sa->ref_cnt == 1);

  SSH_PM_IKE_SA_FREE_REF(sad_handle, sa);

  return NULL;
}

/* Take reference to the IKE SA. */
void
ssh_pm_ike_sa_take_ref(SshSADHandle sad_handle, SshIkev2Sa ike_sa)
{
  SSH_PM_IKE_SA_TAKE_REF(ike_sa);
}

/* Free one reference to the IKE SA. If this was last reference then
   delete the IKE SA. */
void
pm_ike_sa_free_ref(SshSADHandle sad_handle, SshIkev2Sa ike_sa)

{
  SshPmP1 p1 = (SshPmP1) ike_sa;

  p1 = ssh_adt_get_object_from_equal(sad_handle->ike_sa_by_spi,
                                     ike_sa);

  SSH_ASSERT(p1 != NULL);
  SSH_ASSERT((void *)p1 == (void *)ike_sa);

  /* Decrement reference count, and check whether we still
     have references. */
  --ike_sa->ref_cnt;
  if (ike_sa->ref_cnt == 0)
    {
      SSH_DEBUG(SSH_D_HIGHSTART, ("No more references to SA %p", ike_sa));
      if (ike_sa->waiting_for_delete)
        pm_p1_destroy(sad_handle->pm, p1);
    }
}

void
ssh_pm_ike_sa_free_ref(SshSADHandle sad_handle, SshIkev2Sa ike_sa)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("Freeing reference to IKE SA %p to ref count %d",
             ike_sa, ike_sa->ref_cnt - 1));
  pm_ike_sa_free_ref(sad_handle, ike_sa);
}


/***************************** IKE SA rekeys ****************************/

static void pm_ike_sa_rekey_aborted(void *context)
{
  SshPmIkeRekey rekey = context;

  SSH_DEBUG(SSH_D_HIGHOK, ("Aborting IKE SA rekey operation for IKE SA's "
                           "old %p, new %p", rekey->old_p1, rekey->new_p1));

  rekey->reply_callback = NULL_FNPTR;
}

SSH_FSM_STEP(pm_rekey_ike_sa_start)
{
#ifdef SSH_IPSEC_TCPENCAP
  SshPmIkeRekey rekey = thread_context;

  if (rekey->old_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP)
    SSH_FSM_SET_NEXT(pm_rekey_ike_sa_update_ike_mapping);
  else
#endif /* SSH_IPSEC_TCPENCAP */
    SSH_FSM_SET_NEXT(pm_rekey_ike_sa_update_ipsec_sas);

  return SSH_FSM_CONTINUE;
}

#ifdef SSH_IPSEC_TCPENCAP
static void
pm_rekey_ike_sa_update_ike_mapping_cb(SshPm pm, SshUInt32 conn_id,
                                      void *context)
{
  SshPmIkeRekey rekey = context;

  SSH_DEBUG(SSH_D_LOWOK,
            ("TCP encapsulation IKE mapping updated: "
             "IKE SA %p connection entry 0x%lx",
             rekey->new_p1, (unsigned long) conn_id));

  if (conn_id != SSH_IPSEC_INVALID_INDEX)
    rekey->new_p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&rekey->thread);
}

SSH_FSM_STEP(pm_rekey_ike_sa_update_ike_mapping)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmIkeRekey rekey = thread_context;
  unsigned char *new_ike_spi = NULL;

  SSH_ASSERT(rekey->old_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP);

  /* Check if rekeyed IKE SA is using TCP encaps or NATT.
     NULL ike_spi means the IKE mapping is removed.*/
  if ((rekey->new_p1->ike_sa->flags
       & SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE) == 0)
    new_ike_spi = rekey->new_p1->ike_sa->ike_spi_i;

  /* Clear TCP encaps flag from new p1, it is set when the IKE SPI
     mapping is fetched from the engine. */
  rekey->new_p1->ike_sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;

  SSH_DEBUG(SSH_D_MIDOK,
            ("%s TCP encapsulation IKE mapping: IKE SA %p",
             (new_ike_spi == NULL ? "Removing" : "Updating"),
             rekey->new_p1->ike_sa));

  /* Update IKE mapping to new p1. */
  SSH_FSM_SET_NEXT(pm_rekey_ike_sa_update_ipsec_sas);
  SSH_FSM_ASYNC_CALL({
    ssh_pme_tcp_encaps_update_ike_mapping(pm->engine, FALSE,
                                     rekey->old_p1->ike_sa->server->ip_address,
                                     rekey->old_p1->ike_sa->remote_ip,
                                     rekey->old_p1->ike_sa->ike_spi_i,
                                     new_ike_spi,
                                     pm_rekey_ike_sa_update_ike_mapping_cb,
                                     rekey);
  });
  SSH_NOTREACHED;
}
#endif /* SSH_IPSEC_TCPENCAP */

SSH_FSM_STEP(pm_rekey_ike_sa_update_ipsec_sas)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmIkeRekey rekey = thread_context;
  Boolean status = TRUE;
  SshPmPeer peer;

  SSH_FSM_SET_NEXT(pm_rekey_ike_sa_finish);

  SSH_DEBUG(SSH_D_LOWSTART, ("Moving IPSec SA's from IKE SA %p to IKE SA %p",
                             rekey->old_p1, rekey->new_p1));

  /* Update new IKE SA to IKE peer. Note that the IKE peer handle in IPsec
     SAs stays unmodified. */
  do
    {
      /* There might be multiple IKE peers pointing to same IKE SA. */
      peer = ssh_pm_peer_by_p1(pm, rekey->old_p1);
      if (peer && !ssh_pm_peer_update_p1(pm, peer, rekey->new_p1))
        status = FALSE;
    }
  while (peer != NULL);

  /* The old Phase-I is now rekeyed. */
  rekey->old_p1->rekeyed = 1;

  SSH_DEBUG(SSH_D_MIDSTART, ("IKE SA %p rekeyed with status %s", rekey->new_p1,
                             status ? "SUCCESS" : "FAILURE"));

  if (status != TRUE)
    {
      SshIkev2Error error;

      rekey->new_p1->failed = 1;
      pm->stats.num_p1_done++;
      pm->stats.num_p1_failed++;

      error = SSH_IKEV2_ERROR_INVALID_ARGUMENT;

      ssh_pm_log_p1_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          rekey->new_p1, "failed", TRUE);
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: %s (%d)",
                    ssh_ikev2_error_to_string(error), error);

      /* Wake up the thread controlling this negotiation. */
      SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 thread"));
      if (rekey->new_p1->n)
        ssh_fsm_continue(&rekey->new_p1->n->thread);
    }
  else if (!rekey->new_p1->done)
    {
      rekey->new_p1->done = 1;
      pm->stats.num_p1_done++;
      pm->stats.num_p1_rekeyed++;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      /* Transfer ownership of network connection to the new P1, or
       * release it if the new P1 already has a connection. */
      if (rekey->old_p1->conn_handle)
        {
          if (rekey->new_p1->conn_handle == NULL)
            rekey->new_p1->conn_handle = rekey->old_p1->conn_handle;
          else
            ssh_pm_connection_release(rekey->old_p1->conn_handle);
          rekey->old_p1->conn_handle = NULL;
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      ssh_pm_log_p1_success(pm, rekey->new_p1, TRUE);

      /* Put us to the hash of completed IKE SAs. */
      ssh_pm_ike_sa_hash_insert(pm, rekey->new_p1);

      /* The IKE SA was successfully rekeyed.  Let's call the SA
         notification callback if it is set. */

      /* Lie to the effect that the IKE SA is already done. */
      SSH_ASSERT((rekey->new_p1->ike_sa->flags &
                  SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE) == 0);
      rekey->new_p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE;

      /* Store the old SPI's used in SA import/export. */
      memcpy(rekey->new_p1->old_ike_spi_i,
             rekey->old_p1->ike_sa->ike_spi_i, 8);
      memcpy(rekey->new_p1->old_ike_spi_r,
             rekey->old_p1->ike_sa->ike_spi_r, 8);

      /* Enable SA events for the new IKE SA and indicate IKE SA rekey. */
      rekey->new_p1->enable_sa_events = 1;
      ssh_pm_ike_sa_event_rekeyed(pm, rekey->new_p1);

      /* Restore the IKE_SA_DONE flag */
      rekey->new_p1->ike_sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE;

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "IKE SA negotiations: %u done, %u successful, %u failed",
                    (unsigned int) pm->stats.num_p1_done,
                    (unsigned int) (pm->stats.num_p1_done -
                                    pm->stats.num_p1_failed),
                    (unsigned int) pm->stats.num_p1_failed);

#ifdef SSH_IPSEC_SMALL
      /* Register timeout for rekeying the IKE SA. */
      SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(rekey->new_p1,
                                rekey->new_p1->expire_time
                                - ssh_pm_ike_sa_soft_grace_time(rekey->new_p1),
                                ssh_time());
#endif /* SSH_IPSEC_SMALL */

      /* Wake up the thread controlling this negotiation. */
      if (rekey->new_p1->n)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 negotiation thread"));
          ssh_fsm_continue(&rekey->new_p1->n->thread);
        }

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      /* Continue to renew RAS attributes, if such have been allocated
         for the IKE SA and this rekey operation has not been aborted. */
      if (rekey->new_p1->cfgmode_client != NULL
          && rekey->reply_callback != NULL_FNPTR)
        {
          /* Take a reference to new IKE SA so that it does not
             disappear before RAS attribute renewal is started. */
          SSH_PM_IKE_SA_TAKE_REF(rekey->new_p1->ike_sa);
          SSH_FSM_SET_NEXT(pm_rekey_ike_sa_renew_ras_attrs);
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    }

  /* Complete rekey operation towards IKEv2 library. */
  if (status)
    {
      if (rekey->reply_callback != NULL_FNPTR)
        (*rekey->reply_callback)(SSH_IKEV2_ERROR_OK, rekey->reply_context);
    }
  else
    {
      if (rekey->reply_callback != NULL_FNPTR)
        (*rekey->reply_callback)(SSH_IKEV2_ERROR_INVALID_ARGUMENT,
                             rekey->reply_context);

    }

  if (rekey->reply_callback != NULL_FNPTR)
    ssh_operation_unregister(rekey->operation);

  rekey->reply_callback = NULL_FNPTR;

  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_ISAKMP_CFG_MODE
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
void
pm_rekey_ike_sa_renew_ras_attrs_cb(SshPm pm,
                                   Boolean status,
                                   void *context)
{
  SshUInt32 ike_sa_handle = SSH_PM_PTR_TO_UINT32(context);
  SshPmP1 new_p1;

  /* Retrieve p1. */
  new_p1 = ssh_pm_p1_from_ike_handle(pm, ike_sa_handle, FALSE);
  if (new_p1 == NULL)
    {
      /* This should never happen, because if the IKE SA is deleted
         then the remote access attribute renew operation is aborted
         and this callback is never called. */
      SSH_DEBUG(SSH_D_ERROR,
                ("IKE SA 0x%lx has been deleted while renewing remote "
                 "access attributes",
                 (unsigned long) ike_sa_handle));
      return;
    }

  /* Remote access attribute renewal operation has completed, clear
     operation handle. */
  new_p1->initiator_ops[PM_IKE_INITIATOR_OP_RAS] = NULL;
  if (status == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Failed to renew remote access attributes"));

      /* Delete IKE SA if it is not already pending for deletion. */
      if (!SSH_PM_P1_DELETED(new_p1))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Deleting rekeyed IKE SA %p", new_p1));
          SSH_PM_IKEV2_IKE_SA_DELETE(new_p1, 0,
                                     pm_ike_sa_delete_done_callback);
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Renewed remote access attributes for rekeyed IKE SA %p",
                 new_p1));
    }
}

SSH_FSM_STEP(pm_rekey_ike_sa_renew_ras_attrs)
{
  SshPm pm = fsm_context;
  SshPmIkeRekey rekey = thread_context;
  void *context;

  /* Renew remote access attributes. Note that this is deliberately
     not done in a SSH_FSM_ASYNC_CALL so that the operation can be
     aborted in a similar way to other operations in initiator_ops[]. */
  context = SSH_PM_UINT32_TO_PTR(SSH_PM_IKE_SA_INDEX(rekey->new_p1));

  SSH_ASSERT(rekey->new_p1->initiator_ops[PM_IKE_INITIATOR_OP_RAS] == NULL);
  rekey->new_p1->initiator_ops[PM_IKE_INITIATOR_OP_RAS] =
    ssh_pm_cfgmode_client_store_renew(rekey->pm,
                                      rekey->new_p1->cfgmode_client,
                                      pm_rekey_ike_sa_renew_ras_attrs_cb,
                                      context);

  /* Free the IKE SA reference. The IKE SA is allowed to vanish during
     the renewal operation. */
  SSH_PM_IKE_SA_FREE_REF(pm->sad_handle, rekey->new_p1->ike_sa);

  /* Continue rekey thread. */
  SSH_FSM_SET_NEXT(pm_rekey_ike_sa_finish);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

SSH_FSM_STEP(pm_rekey_ike_sa_finish)
{
  return SSH_FSM_FINISH;
}

static void pm_rekey_ike_sa_destructor(SshFSM fsm, void *context)
{
  SshPmIkeRekey rekey = context;
  SshPm pm = rekey->pm;

  ssh_pm_p1_rekey_free(pm, rekey);
}

/* Move IPsec SA's from 'old_p1' to 'new_p1' */
static SshOperationHandle
pm_ike_move_ipsec_sas(SshPm pm,
                      SshPmP1 old_p1, SshPmP1 new_p1,
                      SshIkev2SadRekeyedCB reply_callback,
                      void *reply_context)
{
  SshPmIkeRekey rekey;

  SSH_DEBUG(SSH_D_LOWOK, ("Starting thread to move IPSec SA's from IKE "
                          "SA %p to IKE SA %p", old_p1, new_p1));

  rekey = ssh_pm_p1_rekey_alloc(pm);

  if (rekey == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, reply_context);
      return NULL;
    }

  rekey->reply_callback = reply_callback;
  rekey->reply_context = reply_context;
  rekey->old_p1 = old_p1;
  rekey->new_p1 = new_p1;
  rekey->pm = pm;

  ssh_operation_register_no_alloc(rekey->operation,
                                  pm_ike_sa_rekey_aborted, rekey);

  ssh_fsm_thread_init(&pm->fsm, &rekey->thread,
                      pm_rekey_ike_sa_start, NULL_FNPTR,
                      pm_rekey_ike_sa_destructor, rekey);
  ssh_fsm_set_thread_name(&rekey->thread, "IKE SA rekey");

  return rekey->operation;
}

SshOperationHandle
ssh_pm_ike_sa_rekey(SshSADHandle sad_handle,
                    Boolean delete_old,
                    SshIkev2Sa old_sa,
                    SshIkev2Sa new_sa,
                    SshIkev2SadRekeyedCB reply_callback,
                    void *reply_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 new_p1 = (SshPmP1) new_sa;
  SshPmP1 old_p1 = (SshPmP1) old_sa;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshPmTunnel tunnel;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  int i;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Entered IKE SA rekey policy call, delete_old=%d, "
             "old_sa=%p [%s], new_sa=%p [%s]",
             delete_old, old_sa,
             ((old_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
              "initiator" : "responder"),
             new_sa,
             ((old_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ?
              "initiator" : "responder")));






  /* RFC5996, 2.25.1 and 2.25.2:
     If this a responder IKE SA rekey that is attempting to rekey an
     IKE SA that has any ongoing initiator exchanges (other than IKE SA
     rekey), then fail this responder IKE SA rekey with TEMPORARY_FAILURE. */
  if ((new_p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) == 0)
    {
      for (i = 0; i < PM_IKE_NUM_INITIATOR_OPS; i++)
        {
          if (old_p1->initiator_eds[i] != NULL
              && old_p1->initiator_eds[i]->state != SSH_IKEV2_STATE_REKEY_IKE)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Old IKE SA %p has an initiator exchange ongoing, "
                         "failing responder IKE SA rekey "
                         "with TEMPORARY_FAILURE",
                         old_p1));
              (*reply_callback)(SSH_IKEV2_ERROR_TEMPORARY_FAILURE,
                                reply_context);
              return NULL;
            }
        }
    }

  /* Don't use the old SA for new negotiations. */
  old_p1->unusable = 1;

  /* If we should delete the old SA, then put its expiry time to
     SSH_PM_IKE_SA_DELETE_SECONDS_DELAY and let the pm_ike_sa_timer
     take care of the deletion. If delete_old is FALSE, the remote peer
     should take care of deleting the IKE SA, in this case we put its
     expiry time to 10 times this value, so that this SA will eventually
     get deleted even if the remote peer does not initiate the delete
     exchange. */
  if (delete_old)
    {
      old_p1->expire_time = ssh_time() + SSH_PM_IKE_SA_DELETE_SECONDS_DELAY;
    }
  else
    {
      old_p1->expire_time =
        ssh_time() + (10 * SSH_PM_IKE_SA_DELETE_SECONDS_DELAY);
    }

  /* Check for simultaneous rekeys for which the losing SA should get
     deleted. This is the case when the old SA is not yet completed. */
  if (old_p1->done == 0)
    {
      SSH_ASSERT(!(old_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE));
      SSH_ASSERT(old_p1->n != NULL);

      SSH_DEBUG(SSH_D_HIGHOK, ("Placing the losing simultaneous IKE "
                               "rekeyed SA to the IKE SA hash table"));

      /* Mark as failed so it will not get used in new negotiations */
      old_p1->failed = 1;
      old_p1->done = 1;

      /* Put us to the hash of completed IKE SAs so that the IKE SA
         timer can find and delete this SA. */
      ssh_pm_ike_sa_hash_insert(pm, old_p1);
    }

  /* Copy the required information from the old to the new SA */
  if (!new_p1->rekey_notified)
    {
      new_p1->rekey_notified = 1;
      new_p1->expire_time = ssh_time() + (SshTime) old_p1->lifetime;
      new_p1->lifetime = old_p1->lifetime;
      new_p1->tunnel_id = old_p1->tunnel_id;
      new_p1->dh_group = old_p1->dh_group;
      new_p1->local_auth_method = old_p1->local_auth_method;
      new_p1->remote_auth_method = old_p1->remote_auth_method;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      tunnel = ssh_pm_p1_get_tunnel(pm, new_p1);
      if (tunnel && tunnel->vip)
        ssh_pm_virtual_ip_take_ref(pm, tunnel);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

      if (old_p1->auth_domain)
        {
          new_p1->auth_domain = old_p1->auth_domain;
          ssh_pm_auth_domain_take_ref(new_p1->auth_domain);
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      new_p1->second_local_auth_method = old_p1->second_local_auth_method;
      new_p1->second_remote_auth_method = old_p1->second_remote_auth_method;

      if (old_p1->first_round_auth_domain)
        {
          new_p1->first_round_auth_domain = old_p1->first_round_auth_domain;
          ssh_pm_auth_domain_take_ref(new_p1->first_round_auth_domain);
        }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

      if (old_p1->local_id)
        {
          new_p1->local_id = ssh_pm_ikev2_payload_id_dup(old_p1->local_id);
          if (new_p1->local_id == NULL)
            goto fail;
        }

      if (old_p1->remote_id)
        {
          new_p1->remote_id = ssh_pm_ikev2_payload_id_dup(old_p1->remote_id);
          if (new_p1->remote_id == NULL)
            goto fail;
        }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (old_p1->second_local_id)
        {
          new_p1->second_local_id =
            ssh_pm_ikev2_payload_id_dup(old_p1->second_local_id);
          if (new_p1->second_local_id == NULL)
            goto fail;
        }

      if (old_p1->second_remote_id)
        {
          new_p1->second_remote_id =
            ssh_pm_ikev2_payload_id_dup(old_p1->second_remote_id);
          if (new_p1->second_remote_id == NULL)
            goto fail;
        }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
      if (old_p1->eap_remote_id)
        {
          new_p1->eap_remote_id =
            ssh_pm_ikev2_payload_id_dup(old_p1->eap_remote_id);
          if (new_p1->eap_remote_id == NULL)
            goto fail;
        }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (old_p1->second_eap_remote_id)
        {
          new_p1->second_eap_remote_id =
            ssh_pm_ikev2_payload_id_dup(old_p1->second_eap_remote_id);
          if (new_p1->second_eap_remote_id == NULL)
            goto fail;
        }

#endif /* SSH_IKEV2_MULTIPLE_AUTH */
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
      if (old_p1->auth_cert)
        {
          new_p1->auth_cert = old_p1->auth_cert;
          ssh_cm_cert_take_reference(new_p1->auth_cert);
        }

      if (old_p1->auth_ca_cert)
        {
          new_p1->auth_ca_cert = old_p1->auth_ca_cert;
          ssh_cm_cert_take_reference(new_p1->auth_ca_cert);
        }
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
      if (old_p1->local_secret)
        {
          new_p1->local_secret = ssh_memdup(old_p1->local_secret,
                                            old_p1->local_secret_len);

          if (new_p1->local_secret == NULL)
            goto fail;
          new_p1->local_secret_len = old_p1->local_secret_len;
        }

      if (old_p1->num_authorization_group_ids)
        {
          new_p1->authorization_group_ids =
            ssh_memdup(old_p1->authorization_group_ids,
                       sizeof(old_p1->authorization_group_ids[0]) *
                       old_p1->num_authorization_group_ids);

          if (new_p1->authorization_group_ids == NULL)
            goto fail;

          new_p1->num_authorization_group_ids =
            old_p1->num_authorization_group_ids;

          new_p1->auth_group_ids_set = 1;
        }
      if (old_p1->num_xauth_authorization_group_ids)
        {
          new_p1->xauth_authorization_group_ids =
            ssh_memdup(old_p1->xauth_authorization_group_ids,
                       sizeof(old_p1->xauth_authorization_group_ids[0]) *
                       old_p1->num_xauth_authorization_group_ids);

          if (new_p1->xauth_authorization_group_ids == NULL)
            goto fail;

          new_p1->num_xauth_authorization_group_ids =
            old_p1->num_xauth_authorization_group_ids;
        }
      new_p1->compat_flags = old_p1->compat_flags;
#ifdef SSHDIST_ISAKMP_CFG_MODE
      if (old_p1->remote_access_attrs)
        {
          new_p1->remote_access_attrs =
            ssh_pm_dup_remote_access_attrs(old_p1->remote_access_attrs);

          if (new_p1->remote_access_attrs == NULL)
            goto fail;
        }
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
      if (old_p1->cfgmode_client && !new_p1->cfgmode_client)
        {
          /* Move cfgmode client from old to new */
          new_p1->cfgmode_client = old_p1->cfgmode_client;
          old_p1->cfgmode_client = NULL;
        }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

      /* Move delayed IPsec delete notification requests to the new p1. */
      if (old_p1->delete_notification_requests != NULL)
        {
          SshPmIPsecDeleteNotificationRequest n;

          /* Go to the tail of delete notification requests of old p1. */
          for (n = old_p1->delete_notification_requests;
               n->next != NULL;
               n = n->next)
            ;

          /* Append delete notification requests of the new p1 to tail. */
          SSH_ASSERT(n->next == NULL);
          n->next = new_p1->delete_notification_requests;

          /* Move the delayed delete notification requests to new p1. */
          new_p1->delete_notification_requests =
            old_p1->delete_notification_requests;
          old_p1->delete_notification_requests = NULL;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Moved delayed IPsec SPI delete notifications from "
                     "old p1 %p to new p1 %p",
                     old_p1, new_p1));
        }

#ifdef SSH_PM_BLACKLIST_ENABLED
      /* Copy enable blacklist check flag to new p1. */
      new_p1->enable_blacklist_check = old_p1->enable_blacklist_check;
#endif /* SSH_PM_BLACKLIST_ENABLED */
    }

#ifdef SSH_IPSEC_SMALL
  /* Register timeout for deleting the old IKE SA. */
  if (old_p1)
    SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(old_p1, old_p1->expire_time,
                                       ssh_time());
#endif /* SSH_IPSEC_SMALL */

  return pm_ike_move_ipsec_sas(pm, old_p1, new_p1, reply_callback,
                               reply_context);

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("IKE SA rekey operation failed, out of memory"));

  (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, reply_context);
  return NULL;
}


/************ FSM thread for handling received SPI delete notifications *****/

typedef struct SshPmDeleteRecvContextRec
{
  /* ED from which obstack this context is allocated from. */
  SshIkev2ExchangeData ed;

  SshIpAddrStruct remote_ip[1];
  SshUInt16 remote_port;
  SshInetIPProtocolID ipproto;
  SshIkev2ProtocolIdentifiers protocol;

  /* Outbound SPI's received. */
  SshUInt32 *outbound_spis;
  SshUInt32 num_outbound_spis_recv; /* input count */
  SshUInt32 outbound_spi_index; /* index */

  /* Inbound SPI's sent. */
  SshUInt32 *inbound_spis;
  SshUInt32 num_inbound_spis; /* response count */

  SshOperationHandleStruct op[1];
  SshFSMThreadStruct thread[1];
  SshPmSaCallbacksStruct callbacks;
} *SshPmDeleteRecvContext, SshPmDeleteRecvContextStruct;

SSH_FSM_STEP(pm_ipsec_spi_delete);
SSH_FSM_STEP(pm_ipsec_spi_delete_done);

static void pm_ipsec_spi_delete_thread_destructor(SshFSM fsm, void *context)
{
  SshPmDeleteRecvContext dl = context;
  SshIkev2Sa ike_sa = dl->ed->ike_sa;
  SshPm pm = ssh_fsm_get_gdata(dl->thread);

  SSH_ASSERT(dl != NULL);

  /* Free ed reference.
     This might free the obstack this dl was allocated from. */
  ssh_ikev2_exchange_data_free(dl->ed);
  SSH_PM_IKE_SA_FREE_REF(pm->sad_handle, ike_sa);
}

static void pm_ipsec_spi_delete_aborted(void *context)
{
  SshPmDeleteRecvContext dl = context;

  SSH_ASSERT(dl != NULL);
  dl->callbacks.aborted = TRUE;
  dl->callbacks.u.delete_received_cb = NULL_FNPTR;
}

static void
pm_ipsec_spi_delete_cb(SshPm pm,
                       SshUInt8 ipproto,
                       SshUInt8 num_spis,
                       SshUInt32 *inbound_spis,
                       SshUInt32 *outbound_spis,
                       void *context)
{
  SshPmDeleteRecvContext dl = context;
  SshPmP1 p1 = (SshPmP1) dl->ed->ike_sa;
  int i, j;

  /* The deleted transform may still have had the old SPI values.
     Check if the received outbound SPI's contain the old SPI value,
     that is, if the remote end requested deletion of the old outbound
     SPI also. If yes, then send the old inbound SPI in the response.
     Otherwise request a delayed delete notification for the old inbound
     SPI value.

     For IKEv1 the inbound SPI value is always sent in a delayed delete
     notification because according to the protocol no response is sent
     for the delete request. */
  for (i = 0; i < num_spis; i++)
    {
      SSH_ASSERT(inbound_spis[i] != 0);
      for (j = 0; j < dl->num_outbound_spis_recv; j++)
        {
          /* The deleted outbound SPI was in the delete request. */
          if (outbound_spis[i] != 0 &&
              outbound_spis[i] == dl->outbound_spis[j])
            {
              /* Mark that the received outbound SPI has been processed. */
              dl->outbound_spis[j] = 0;

              /* Add the inbound SPI to the response. */
              dl->inbound_spis[dl->num_inbound_spis++] = inbound_spis[i];
              SSH_ASSERT(dl->num_inbound_spis <= dl->num_outbound_spis_recv);
              break;
            }
        }

      /* The deleted SPI was not in the delete request or the delete request
         was received on a IKEv1 SA. Request a delete notification for this
         SPI. The delete notification is sent in a separate informational
         exchange. */
      if (j >= dl->num_outbound_spis_recv
#ifdef SSHDIST_IKEV1
          || (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) != 0
#endif /* SSHDIST_IKEV1 */
          )
        ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto,
                                                 inbound_spis[i]);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(dl->thread);
}

SSH_FSM_STEP(pm_ipsec_spi_delete)
{
  SshPmDeleteRecvContext dl = thread_context;
  SshPm pm = ssh_fsm_get_gdata(thread);

  /* Skip any outbound SPI values that have been already processed.
     The outbound SPI in the slot may have been an old SPI which was
     deleted while deleting the transform by new SPI value. */
  while (dl->outbound_spi_index < dl->num_outbound_spis_recv
         && dl->outbound_spis[dl->outbound_spi_index] == 0)
    dl->outbound_spi_index++;

  if (dl->outbound_spi_index < dl->num_outbound_spis_recv)
    {
      /* Lookup IPsec SA by outbound SPI and delete it. ssh_pm_delete_by_spi
         will pass our inbound SPI value to IKE library, which will respond
         with delete notification (except if IKEv1 is used). */
      SSH_FSM_SET_NEXT(pm_ipsec_spi_delete);
      SSH_FSM_ASYNC_CALL({
          ssh_pm_delete_by_spi(pm,
                               dl->outbound_spis[dl->outbound_spi_index++],
                               dl->ed->ike_sa->server->routing_instance_id,
                               dl->ipproto, dl->remote_ip, dl->remote_port,
                               pm_ipsec_spi_delete_cb, dl);
        });
    }
  else
    {
      SSH_FSM_SET_NEXT(pm_ipsec_spi_delete_done);
      return SSH_FSM_CONTINUE;
    }
}

SSH_FSM_STEP(pm_ipsec_spi_delete_done)
{
  SshPmDeleteRecvContext dl = thread_context;
  SshPm pm = ssh_fsm_get_gdata(thread);
  SshPmP1 p1 = (SshPmP1) dl->ed->ike_sa;

  if (!dl->callbacks.aborted)
    {
      ssh_operation_unregister(dl->callbacks.operation);

      if (dl->callbacks.u.delete_received_cb)
        (*dl->callbacks.u.delete_received_cb)(SSH_IKEV2_ERROR_OK,
                                              dl->protocol,
                                              dl->num_inbound_spis,
                                              dl->inbound_spis,
                                              dl->callbacks.callback_context);
    }

  /* Send any pending delete notifications. */
  ssh_pm_send_ipsec_delete_notification_requests(pm, p1);

  return SSH_FSM_FINISH;
}

SshOperationHandle
ssh_pm_ipsec_spi_delete_received(SshSADHandle sad_handle,
                                 SshIkev2ExchangeData ed,
                                 SshIkev2ProtocolIdentifiers protocol,
                                 int number_of_spis,
                                 SshUInt32 *spi_array,
                                 SshIkev2SadDeleteReceivedCB reply_callback,
                                 void *reply_context)
{
  SshPm pm = sad_handle->pm;
  SshPmDeleteRecvContext dl;
  SshInetIPProtocolID ipproto;
  int i;





  SSH_DEBUG(SSH_D_NICETOKNOW, ("SPI delete received called for %d spis ",
                               number_of_spis));

  if (protocol == SSH_IKEV2_PROTOCOL_ID_AH)
    ipproto = SSH_IPPROTO_AH;
  else if (protocol == SSH_IKEV2_PROTOCOL_ID_ESP)
    ipproto = SSH_IPPROTO_ESP;
  else
    {
      SSH_NOTREACHED;
      goto error;
    }

  for (i = 0; i < number_of_spis; i++)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("SPI delete received: SPI %@-%08lx",
                 ssh_ipproto_render, (SshUInt32) ipproto,
                 (unsigned long) spi_array[i]));

      /* Mark that we have received a delete notification for this spi. */
      ssh_pm_spi_mark_delete_received(pm, spi_array[i], ipproto,
                                  ed->ike_sa->remote_ip,
                                  ed->ike_sa->remote_port,
                                  ed->ike_sa->server->routing_instance_id);
    }

  /* Allocate an operation context from ed's obstack. */
  dl = ssh_obstack_calloc(ed->obstack, sizeof(*dl));
  if (dl == NULL)
    goto error;

  dl->inbound_spis =
    (SshUInt32 *)ssh_obstack_calloc(ed->obstack,
                                    number_of_spis * sizeof(spi_array[0]));
  if (dl->inbound_spis == NULL)
    goto error;

  dl->outbound_spis =
    (SshUInt32 *)ssh_obstack_memdup(ed->obstack,
                                    spi_array,
                                    number_of_spis * sizeof(spi_array[0]));
  if (dl->outbound_spis == NULL)
    goto error;

  SSH_PM_IKE_SA_TAKE_REF(ed->ike_sa);
  ssh_ikev2_exchange_data_take_ref(ed);
  dl->ed = ed;
  dl->callbacks.aborted = FALSE;
  dl->callbacks.u.delete_received_cb = reply_callback;
  dl->callbacks.callback_context = reply_context;
  ssh_operation_register_no_alloc(dl->callbacks.operation,
                                  pm_ipsec_spi_delete_aborted, dl);
  dl->ipproto = ipproto;
  dl->protocol = protocol;
  dl->num_inbound_spis = 0;
  dl->num_outbound_spis_recv = number_of_spis;
  dl->outbound_spi_index = 0;
  *dl->remote_ip = *ed->ike_sa->remote_ip;
  dl->remote_port = ed->ike_sa->remote_port;

  SSH_DEBUG(SSH_D_LOWOK, ("Starting thread for IPsec SPI deletion"));

  ssh_fsm_thread_init(&pm->fsm, dl->thread,
                      pm_ipsec_spi_delete, NULL_FNPTR,
                      pm_ipsec_spi_delete_thread_destructor, dl);
  ssh_fsm_set_thread_name(dl->thread, "IPsec SPI delete");

  return dl->callbacks.operation;

 error:
  if (reply_callback != NULL_FNPTR)
    (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY,
                      protocol, 0, NULL, reply_context);
  return NULL;
}


/****************************** Enumerating IKE SAs *************************/

void
ssh_pm_ike_enumerate(SshSADHandle sad_handle,
                     SshIkev2SadIkeSaEnumerateCB enumerate_callback,
                     void *context)
{
  SshADTHandle handle, next;

  for (handle = ssh_adt_enumerate_start(sad_handle->ike_sa_by_spi);
       handle != SSH_ADT_INVALID;
       handle = next)
    {
      SshIkev2Sa ike_sa;

      next = ssh_adt_enumerate_next(sad_handle->ike_sa_by_spi, handle);

      ike_sa = ssh_adt_get(sad_handle->ike_sa_by_spi, handle);

      (*enumerate_callback)(SSH_IKEV2_ERROR_OK, ike_sa, context);
    }

  /* And terminate */
  (*enumerate_callback)(SSH_IKEV2_ERROR_OK, NULL, context);
}


/********************************* IKE SA allocation *************************/

SshOperationHandle
ssh_pm_ike_sa_allocate(SshSADHandle sad_handle,
                       Boolean initiator,
                       SshIkev2SadIkeSaAllocateCB reply_callback,
                       void *reply_callback_context)
{
  SshPm pm = sad_handle->pm;
  SshPmP1 p1;
  SshIkev2Sa sa;
  unsigned char *spi;
  int i;
  unsigned char zero_spi[] = { 0, 0, 0, 0, 0, 0, 0, 0 };

  SSH_DEBUG(SSH_D_HIGHSTART, ("Entered"));

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_SUSPENDED)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_SUSPENDED, NULL,
                        reply_callback_context);
      return NULL;
    }

  /* Allocate a Phase-1 SA structure. */
  p1 = ssh_pm_p1_alloc(pm);
  if (p1 == NULL)
    {
      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL,
                        reply_callback_context);
      return NULL;
    }

  /* Set the expiry time for reaping of half-open IKE SA's whose last
     IKE packet time is zero. This time is used for deleting half-open
     IKE SA's whose IKE SA window was never updated (and hence has zero
     last IKE packet time).

     The expiry time will be updated to the actual lifetime of the IKE
     SA when SA negotiation is completed. */
  p1->expire_time = ssh_time() + SSH_PM_IKE_SA_INITIAL_EXPIRY_TIME;

  /* Allocate a Phase-1 SA negotiation structure. */
  p1->n = ssh_pm_p1_negotiation_alloc(pm);

  if (p1->n == NULL)
    {
      ssh_pm_p1_free(pm, p1);

      (*reply_callback)(SSH_IKEV2_ERROR_OUT_OF_MEMORY, NULL,
                        reply_callback_context);
      return NULL;
    }

  /* Link this negotiation into PM's list of active responder Phase-1
     negotiations */
  p1->n->next = pm->active_p1_negotiations;
  pm->active_p1_negotiations = p1;
  if (p1->n->next)
    p1->n->next->n->prev = p1;

  if ((initiator == FALSE) && (pm->ike_sa_half_timer_registered == 0))
    ssh_pm_ike_sa_half_timer(pm);

  /* Start a thread for the negotiation. */
  ssh_fsm_thread_init(&pm->fsm, &p1->n->thread,
                      ssh_pm_st_p1_negotiation,
                      NULL_FNPTR,
                      ssh_pm_p1_n_thread_destructor, p1);
  ssh_fsm_set_thread_name(&p1->n->thread, "IKE negotiation");

  sa = p1->ike_sa;
  SSH_ASSERT(sa->ref_cnt == 0);

  SSH_IP_UNDEFINE(sa->remote_ip);

  if (initiator)
    {
      spi = sa->ike_spi_i;
      sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;
#ifdef SSHDIST_IKE_MOBIKE
      sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR;
#endif /* SSHDIST_IKE_MOBIKE */
    }
  else
    {
      spi = sa->ike_spi_r;
    }

 again:
  /* Assign SPI, and store SA */
  for (i = 0; i < sizeof(sa->ike_spi_i); i++)
    spi[i] = ssh_random_get_byte();

  if (ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, sa)
      != SSH_ADT_INVALID)
    goto again;

  /* Check for all-zeros SPI. */
  if (memcmp(spi, zero_spi, sizeof(zero_spi)) == 0)
    goto again;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p, ref count %d",
                              sa, (int) sa->ref_cnt));

  ssh_adt_insert(sad_handle->ike_sa_by_spi, sa);

  (*reply_callback)(SSH_IKEV2_ERROR_OK, sa, reply_callback_context);
  return NULL;
}

SshIkev2Sa
ssh_pm_ike_sa_get_by_spi(SshSADHandle sad_handle,
                         const unsigned char *ike_sa_spi)
{
  SshIkev2SaStruct probe;
  SshIkev2Sa sa = NULL;
  SshADTHandle handle;

  memset(&probe, 0, sizeof(probe));

  memcpy(probe.ike_spi_i, ike_sa_spi, sizeof(probe.ike_spi_i));
  probe.flags |= SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;

  handle = ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, &probe);
  if (handle == SSH_ADT_INVALID)
    {
      memcpy(probe.ike_spi_r, ike_sa_spi, sizeof(probe.ike_spi_i));
      probe.flags &= ~SSH_IKEV2_IKE_SA_FLAGS_INITIATOR;
      handle = ssh_adt_get_handle_to_equal(sad_handle->ike_sa_by_spi, &probe);
    }

  if (handle)
    {
      sa = ssh_adt_get(sad_handle->ike_sa_by_spi, handle);
    }
  return sa;
}

SshOperationHandle
ssh_pm_ike_sa_get(SshSADHandle sad_handle,
                  const SshUInt32 ike_version,
                  const unsigned char *ike_sa_spi_i,
                  const unsigned char *ike_sa_spi_r,
                  SshIkev2SadIkeSaGetCB reply_callback,
                  void *reply_callback_context)
{
  SshIkev2Sa sa = NULL;
  SshIkev2Error status = SSH_IKEV2_ERROR_OK;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter"));

  if (ike_version >= 2)
    {
      if (ike_sa_spi_i != NULL)
        sa = ssh_pm_ike_sa_get_by_spi(sad_handle, ike_sa_spi_i);
      else
        sa = ssh_pm_ike_sa_get_by_spi(sad_handle, ike_sa_spi_r);

#ifdef SSHDIST_IKEV1
      /* IKEv1 SAs are stored in the ike_sa_by_spi ADT with the IKEv2 SAs.
         Sanity check IKE version for IKE SPI collision (or for misbehaving
         peer). */
      if (sa != NULL && (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1))
        {
          if (ike_sa_spi_i)
            SSH_DEBUG(SSH_D_UNCOMMON,
                      ("Found IKEv1 SA %p for IKEv2 SPI I 0x%08lx 0x%08lx",
                       sa,
                       (unsigned long) SSH_GET_32BIT(ike_sa_spi_i),
                       (unsigned long) SSH_GET_32BIT(ike_sa_spi_i + 4)));
          else if (ike_sa_spi_r)
            SSH_DEBUG(SSH_D_UNCOMMON,
                      ("Found IKEv1 SA %p for IKEv2 SPI R 0x%08lx 0x%08lx",
                       sa,
                       (unsigned long) SSH_GET_32BIT(ike_sa_spi_r),
                       (unsigned long) SSH_GET_32BIT(ike_sa_spi_r + 4)));
          sa = NULL;
        }
#endif /* SSHDIST_IKEV1 */

      if (sa != NULL)
        SSH_PM_IKE_SA_TAKE_REF(sa);

      SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p", sa));
      (*reply_callback)(status, sa, reply_callback_context);
      return NULL;
    }
#ifdef SSHDIST_IKEV1
  else if (ike_version == 1)
    {
      /* Return non-NULL SA for IKEv1 fallbacked SA's. They are all
         managed inside IKEv1 library, and we know nothing about them
         (except that the ikev2-recv.c does not use those for version 1
         packet reception. */
      if (ssh_ikev2_fb_get_sa(sad_handle->pm->ike_context, ike_sa_spi_i,
                              ike_sa_spi_r))
        sa = (SshIkev2Sa) SSH_IKEV2_FB_IKEV1_SA;

      SSH_DEBUG(SSH_D_HIGHSTART, ("Returning SA %p", sa));
      (*reply_callback)(status, sa, reply_callback_context);
      return NULL;
    }
#endif /* SSHDIST_IKEV1 */

  /* Unsupported IKE protocol version, fail lookup. */
  (*reply_callback)(SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION, NULL,
                    reply_callback_context);
  return NULL;
}


void pm_qm_sub_thread_destructor(SshFSM fsm, void *context)
{
  SshPmQm qm = context;
  SshPm pm = ssh_fsm_get_gdata_fsm(fsm);

  /* Free the QM at the end of sub thread if it was delayed this
     late. */
  if (qm->error
      && qm->ed == NULL
      && !SSH_FSM_THREAD_EXISTS(&qm->thread))
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Freeing QM from the sub thread destructor"));
      ssh_pm_qm_free(pm, qm);
    }
}


/* Allocate exchange context. The IKE library calls this
   when it needs a exchange context to be allocated. This
   should allocate one obstack and store the obstack pointer
   to the SshIkev2ExchangeData obstack field. The IKEv2
   library will then initialize rest of the exchange data.
   This returns NULL if alloc fails. */
SshIkev2ExchangeData
ssh_pm_ike_exchange_data_alloc(SshSADHandle sad_handle,
                               SshIkev2Sa sa)
{
  SshIkev2ExchangeData ed;
  SshObStackContext obstack;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Allocate IKE exchange data for SA %p", sa));





  obstack = ssh_obstack_create(NULL);
  if (obstack == NULL)
    return NULL;

  ed = ssh_obstack_alloc(obstack, sizeof(*ed));
  if (ed == NULL)
    {
      ssh_obstack_destroy(obstack);
      return NULL;
    }
  memset(ed, 0, sizeof(*ed));

  ed->obstack = obstack;
  ed->application_context = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Exchange data allocated ED %p", ed));
  return ed;
}

/* Free exchange context. The IKE library calls this when it
   needs to free the exchange context. It has already
   uninitialized the exchange data from its own parts before
   calling this function. */
void ssh_pm_ike_exchange_data_free(SshSADHandle sad_handle,
                                   SshIkev2ExchangeData exchange_data)
{
  SshPmQm qm = NULL;
  SshPmInfo info = NULL;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Enter SA %p, ED %p application context %p",
                              exchange_data->ike_sa, exchange_data,
                              exchange_data->application_context));

  SSH_PM_ASSERT_ED(exchange_data);
  if (exchange_data->application_context != NULL)
    {
      /* Cast `application_context' to SshPmInfo to get the detailed data
         type. SshPmInfo is always allocated from ed->obstack and thus does
         not need to be freed separately. */
      info = (SshPmInfo) exchange_data->application_context;
      switch (info->type)
        {
        case SSH_PM_ED_DATA_QM:
          qm = (SshPmQm) exchange_data->application_context;
          SSH_PM_ASSERT_QM(qm);
          info = NULL;
          break;

        case SSH_PM_ED_DATA_INFO_QM:
          qm = info->u.qm;
          break;

        case SSH_PM_ED_DATA_INFO_P1:
          /* Nothing to do here for now. */
          break;

#ifdef SSHDIST_IPSEC_MOBIKE
        case SSH_PM_ED_DATA_INFO_MOBIKE:
          break;
#endif /* SSHDIST_IPSEC_MOBIKE */

        case SSH_PM_ED_DATA_INFO_OLD_SPI:
        case SSH_PM_ED_DATA_INFO_DPD:
          break;

        default:
          SSH_NOTREACHED;
        }
    }

  if (qm)
    {
      SSH_PM_ASSERT_QM(qm);
      qm->ed = NULL;

      /* Release the QM negotiation context for the responder unless
         they are running the sub thread. If sub-thread is run, then
         then free is delayed to its destructor (if qm->ed == NULL)
         there. See pm_qm_sub_thread_destructor function above. */
      if (!qm->initiator
          && !SSH_FSM_THREAD_EXISTS(&qm->sub_thread))
        ssh_pm_qm_free(sad_handle->pm, qm);
    }
  ssh_obstack_destroy(exchange_data->obstack);
}


/* IKE SA done policy call. This may be called twice for the same IKE SA
   in initial IKE SA negotiation. This is called also in IKE SA rekey failure
   case, successful IKE SA rekey does not call this. */
void
ssh_pm_ike_sa_done(SshSADHandle sad_handle,
                   SshIkev2ExchangeData ed,
                   SshIkev2Error status)
{
  SshPm pm = sad_handle->pm;
  SshUInt32 lifetime;
  SshPmP1 p1;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshPmTunnel tunnel;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  SSH_DEBUG(SSH_D_MIDOK, ("IKE SA done: error status=%s (%d)",
                          ssh_ikev2_error_to_string(status), status));

  SSH_ASSERT(ed != NULL);

  p1 = (SshPmP1) ed->ike_sa;

  SSH_PM_ASSERT_P1(p1);

  p1->done = 1;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel && tunnel->vip)
    ssh_pm_virtual_ip_take_ref(pm, tunnel);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Set the Diffie-Hellman group */
  if (ed->ike_ed)
    p1->dh_group = ed->ike_ed->group_number;

  pm->stats.num_p1_done++;

  if (p1->failed || status != SSH_IKEV2_ERROR_OK)
    {
      pm->stats.num_p1_failed++;

      if (ed->state == SSH_IKEV2_STATE_REKEY_IKE)
        {
          ssh_pm_log_p1_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                              p1, "failed", TRUE);
        }
      else
        {
          p1->failed = 1;
          ssh_pm_log_p1_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                              p1, "failed", FALSE);
        }

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: %s (%d)",
                    ssh_ikev2_error_to_string(status), status);

      if (p1->n && (p1->n->failure_mask || p1->n->ike_failure_mask))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Reason:");
          if (p1->n->failure_mask)
            ssh_pm_log_rule_selection_failure(SSH_LOGFACILITY_AUTH,
                                              SSH_LOG_INFORMATIONAL,
                                              p1,
                                              p1->n->failure_mask);

          if (p1->n->ike_failure_mask)
            ssh_pm_log_ike_sa_selection_failure(SSH_LOGFACILITY_AUTH,
                                                SSH_LOG_INFORMATIONAL,
                                                p1,
                                                p1->n->ike_failure_mask);
        }
#ifdef SSHDIST_IKE_CERT_AUTH
      if (p1->n && p1->n->cmi_failure_mask)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Reason:");
          ssh_pm_log_cmi_failure(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                                 p1, p1->n->cmi_failure_mask);
        }
#endif /* SSHDIST_IKE_CERT_AUTH */
    }
  else
    {
      /* In success case this is only called for initial IKE SA negotiation. */
      SSH_PM_ASSERT_P1N(p1);
      SSH_ASSERT(p1->n->tunnel != NULL);
      SSH_ASSERT(ed->ike_ed != NULL);

#ifdef SSHDIST_IKEV1
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
          if (p1->compat_flags & SSH_PM_COMPAT_SET_ACK_CFG)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Peer indicates support for CFG SET/ACK mode"));

              if ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
                  || (p1->n->tunnel->flags & SSH_PM_TR_ALLOW_CFGMODE)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
                  )
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Server will initiate CFG mode SET/ACK "
                             "exchange after Phase-I completes"));
                  p1->ike_sa->server_cfg_pending = 1;
                }
            }

#ifdef SSHDIST_IKE_XAUTH
          if (p1->n->tunnel->flags & SSH_PM_T_XAUTH_METHODS)
            p1->ike_sa->xauth_enabled = 1;
#endif /* SSHDIST_IKE_XAUTH */
        }
#endif /* SSHDIST_IKEV1 */

      if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
        {
          p1->local_id = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_i);
          p1->remote_id = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_r);
        }
      else
        {
          p1->local_id = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_r);
          p1->remote_id = ssh_pm_ikev2_payload_id_dup(ed->ike_ed->id_i);
        }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR &&
          ed->ike_ed->second_id_i != NULL)
        {
          p1->second_local_id =
            ssh_pm_ikev2_payload_id_dup(ed->ike_ed->second_id_i);
        }
      else if (ed->ike_ed->second_id_i != NULL)
        {
          p1->second_remote_id =
            ssh_pm_ikev2_payload_id_dup(ed->ike_ed->second_id_i);
        }

#endif /*  SSH_IKEV2_MULTIPLE_AUTH */

      if (p1->local_id == NULL || p1->remote_id == NULL)
        {
          p1->failed = 1;
          pm->stats.num_p1_failed++;
          return;
        }

        {
          /* update remote and local IDs to peers */

          SshPmPeer peer;

          peer = ssh_pm_peer_by_p1(pm, p1);
          while (peer != NULL)
            {
              ssh_pm_peer_update_p1(pm, peer, p1);

              peer = ssh_pm_peer_next_by_ike_sa_handle(pm, peer);
            }
        }

      /* Process the possible pending initial contact notification now. */
      if (p1->received_1contact)
        ssh_pm_process_initial_contact_notification(pm, p1);

#ifdef SSHDIST_IKEV1
      /* Lifetimes are negotiated for IKEv1 SA's, the negotiated value is
         set to the IKE exchange data. For IKEv2 SA's we use the value
         from the local policy. */
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
          lifetime = p1->n->tunnel->u.ike.ike_sa_life_seconds;

          SSH_DEBUG(SSH_D_MIDOK,
                    ("Proposed/Policy IKE SA lifetime %d/%d",
                     (int) ed->ike_ed->sa_life_seconds,
                     (int) p1->n->tunnel->u.ike.ike_sa_life_seconds));

          if (lifetime > ed->ike_ed->sa_life_seconds &&
              ed->ike_ed->sa_life_seconds)
            lifetime = ed->ike_ed->sa_life_seconds;
        }
      else
#endif /* SSHDIST_IKEV1 */
        lifetime = p1->n->tunnel->u.ike.ike_sa_life_seconds;

      /* Do not allow too short IKE SA lifetimes. */
      if (lifetime < SSH_PM_IKE_SA_MIN_LIFETIME)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Proposed lifetime too short (%u), "
                                  "enforced lifetime (%u).", lifetime,
                                  SSH_PM_IKE_SA_MIN_LIFETIME));
          lifetime = SSH_PM_IKE_SA_MIN_LIFETIME;
        }

      /* Update the expire time of the IKE SA. */
      p1->expire_time = ssh_time() + (SshTime) lifetime;
      p1->lifetime = lifetime;

      ssh_pm_log_p1_success(pm, p1, FALSE);
#ifdef SSHDIST_IKE_MOBIKE
      if (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED)
        ssh_pm_log_p1_additional_addresses(SSH_LOGFACILITY_AUTH,
                                           SSH_LOG_INFORMATIONAL, p1, FALSE);
#endif /* SSHDIST_IKE_MOBIKE */

      /* The IKE SA was successfully negotiated. Enable IKE SA events and
         indicate IKE SA creation. */
      p1->enable_sa_events = 1;
      ssh_pm_ike_sa_event_created(pm, p1);

      /* Put us to the hash of completed IKE SAs. */
      ssh_pm_ike_sa_hash_insert(pm, p1);

#ifdef SSH_IPSEC_SMALL
      /* Register timeout for rekeying the IKE SA. */
      SSH_PM_IKE_SA_REGISTER_TIMER_EVENT(p1,
                                         p1->expire_time
                                         - ssh_pm_ike_sa_soft_grace_time(p1),
                                         ssh_time());
#endif /* SSH_IPSEC_SMALL */
    }

  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "IKE SA negotiations: %u done, %u successful, %u failed",
                (unsigned int) pm->stats.num_p1_done,
                (unsigned int) (pm->stats.num_p1_done -
                                pm->stats.num_p1_failed),
                (unsigned int) pm->stats.num_p1_failed);

  /* Check that the negotiation is still valid here. It is possible given
     the bizarre semantics of the IKE library that this function may be
     called twice for the same IKE SA. If a second call does occur the
     p1->n may have been cleared shortly after the first call is received. */
  if (p1->n &&
      ((p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR) ||
       status == SSH_IKEV2_ERROR_OK))
    {
      /* Wake up the thread controlling this negotiation.  We always
         do this for the initiator. For the responder we do this only if
         the negotiation is successful. If the negotiation has failed, the
         IKE SA may be kept in the IKE library to handle retransmissions
         from the initiator. In such cases the IKE SA will be deleted by
         the policy manager's IKE SA timer. */
      SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 thread"));
      ssh_fsm_continue(&p1->n->thread);
    }

  /* Check if p1 is marked unusable and delete it right away. */
  if (p1->unusable && !SSH_PM_P1_DELETED(p1))
    {
      SshUInt32 flags = 0;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("P1 is marked unusable, deleting IKE SA %p",
                                   p1->ike_sa));

#ifdef SSHDIST_IKEV1
      flags = SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW;
#endif /* SSHDIST_IKEV1 */

      SSH_PM_IKEV2_IKE_SA_DELETE(p1,
                                 flags,
                                 pm_ike_sa_delete_notification_done_callback);
    }
}
