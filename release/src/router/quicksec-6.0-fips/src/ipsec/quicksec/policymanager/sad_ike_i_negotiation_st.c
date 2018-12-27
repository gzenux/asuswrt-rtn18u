/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Quick-Mode negotiation.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStQmNegotiation"

/***********************  Callback functions ******************************/

/* Callback function completing an ssh_pme_have_transform_with_peer()
   call. It is used to check whether system has any SAs with the
   given peer.  Based on the result, the system determines whether to
   send an initial contact notification or not. */
static void
ssh_pm_transform_with_peer_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);

  if (status)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Have IPSec SAs: not sending INITIAL-CONTACT"));
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDOK, ("No IPSec SAs: might send INITIAL-CONTACT"));
      qm->send_initial_contact = 1;
    }

  if (qm->aborted)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("QM thread aborted, advancing to terminal state"));
      ssh_fsm_set_next(thread, ssh_pm_st_qm_i_n_failed);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

void ssh_pm_ike_sa_allocated(SshIkev2Error error,
                             SshIkev2Sa ike_sa,
                             void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmP1 p1;
  SshPmPeer peer;

  SSH_DEBUG(SSH_D_LOWSTART, ("IKE SA allocated, ike error code %s (%d)",
                             ssh_ikev2_error_to_string(error),
                             (int) error));

  if (error != SSH_IKEV2_ERROR_OK)
    {
      qm->error = error;
      qm->p1 = NULL;
    }
  else
    {
      p1 = (SshPmP1) ike_sa;

      SSH_PM_ASSERT_P1(p1);
      SSH_PM_ASSERT_P1N(p1);

      qm->p1 = p1;

#ifdef SSH_PM_BLACKLIST_ENABLED
      {
        SshPmPeer peer;

        /* Copy enable blacklist check flag from peer. */
        peer = ssh_pm_peer_by_handle(p1->pm, qm->peer_handle);
        if (peer)
          p1->enable_blacklist_check = peer->enable_blacklist_check;
      }
#endif /* SSH_PM_BLACKLIST_ENABLED */
    }

  /* Mark that qm is no longer allocating IKE SA for the peer. After this
     step subsequent qm threads will find the just allocated IKE SA and
     wait until the negotiation is completed. */
  if (qm->allocating_ike_sa)
    {
      /* Assert that qm->peer_handle points to a valid peer object.
         The flag qm->allocating_ike_sa could never have been set if
         there was no such peer object, thus this assert fails only
         if there is a real bug. */
      SSH_ASSERT(qm->peer_handle != SSH_IPSEC_INVALID_INDEX);
      peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
      SSH_ASSERT(peer != NULL);
      SSH_ASSERT(peer->allocating_ike_sa != 0);
      peer->allocating_ike_sa = 0;
      qm->allocating_ike_sa = 0;
    }

  if (qm->aborted)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("QM thread aborted, advancing to terminal state"));
      ssh_fsm_set_next(thread, ssh_pm_st_qm_i_n_failed);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* Callback for initiator IPSEC exchange. */
void
pm_ipsec_sa_done_callback(SshSADHandle sad_handle,
                          SshIkev2Sa sa,
                          SshIkev2ExchangeData ed,
                          SshIkev2Error error)
{
  SshPmQm qm;
  SshPmP1 p1 = (SshPmP1) ed->ike_sa;

  SSH_ASSERT(ed != NULL);





  SSH_DEBUG(SSH_D_MIDOK,
            ("IPSec Exchange done, IKE error code %s, ed %p",
             ssh_ikev2_error_to_string(error), ed));

#ifdef SSHDIST_IKEV1




  if (ed->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1
      && error == SSH_IKEV2_ERROR_SA_UNUSABLE)
    {
      SSH_DEBUG(SSH_D_FAIL,("IPSec SA done, unusable error for IKEv1 SA %p, "
                            "qm %p", sa, ed->application_context));
      return;
    }
#endif /* SSHDIST_IKEV1 */

  /* IKE SA has changed if this was a create child negotiation. */
  if (ed->state == SSH_IKEV2_STATE_CREATE_CHILD)
    ssh_pm_ike_sa_event_updated(sad_handle->pm, p1);

  SSH_ASSERT(ed->ike_sa == sa);
  PM_IKE_ASYNC_CALL_COMPLETE(ed->ike_sa, ed);

  qm = (SshPmQm) ed->application_context;
  if (qm != NULL)
    {
      SSH_PM_ASSERT_QM(qm);
      qm->ike_done = 1;

      /* Do not overwrite qm->error with SSH_IKEV2_ERROR_OK,
         it might have been set by SA handler. */
      if (error != SSH_IKEV2_ERROR_OK)
        {
          if (ed->ipsec_ed &&
              !(ed->ipsec_ed->flags &
                SSH_IKEV2_IPSEC_OPERATION_REGISTERED))
            {
              SshPmP1 p1 = qm->p1;

              /* Handle the case where the Quick-Mode has failed before the
                 ipsec send operation has started and this exchange is also
                 creating a new IKE SA. In this case we need to wake up
                 the Phase-I negotiation thread, as it is waiting for
                 the Phase-I negotiation to complete. */
              if (p1 && p1->n && !p1->done)
                {
                  p1->done = 1;
                  p1->failed = 1;
                  p1->delete_with_negotiation = 1;
                  SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 thread"));
                  SSH_ASSERT(SSH_FSM_THREAD_EXISTS(&p1->n->thread));
                  ssh_fsm_continue(&p1->n->thread);
                }
            }

          qm->error = error;
        }

      if ((qm->error == SSH_IKEV2_ERROR_TIMEOUT)
          && SSH_IP_DEFINED(&qm->initial_remote_addr))
        ssh_pm_dpd_peer_dead(sad_handle->pm,
                             &qm->initial_remote_addr, FALSE);

      if (qm->error)
        ssh_fsm_set_next(&qm->thread, ssh_pm_st_qm_i_n_failed);

      ssh_fsm_continue(&qm->thread);
    }

#ifdef SSHDIST_IPSEC_MOBIKE
  ssh_pm_mobike_check_exchange(sad_handle->pm, error, (SshPmP1) sa, ed);
#endif /* SSHDIST_IPSEC_MOBIKE */
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
static void
ssh_pm_qm_request_connection_cb(SshConnection conn_handle, void *context)
{
  SshPmQm qm = (SshPmQm) context;
  SshFSMThread thread = &qm->thread;

  qm->conn_op = NULL;

  if (conn_handle != NULL)
    {
      qm->conn_handle = conn_handle;
    }
  else
    {
      qm->error = SSH_PM_QM_ERROR_NETWORK_UNAVAILABLE;
      ssh_fsm_set_next(thread, ssh_pm_st_qm_i_n_failed);
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ssh_pm_qm_request_connection(SshPmQm qm)
{
  qm->conn_op = ssh_pm_connection_request(&qm->initial_remote_addr,
                                          ssh_pm_qm_request_connection_cb,
                                          qm);
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */


/********************************** States **********************************/

SSH_FSM_STEP(ssh_pm_st_qm_i_n_start)
{
  SshPmQm qm = (SshPmQm) thread_context;

  /* Set encapsulation mode for the negotiation. */
  ssh_pm_qm_thread_compute_tunneling_attribute(qm);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Check outer tunnel VIP status. */
  if (qm->tunnel->outer_tunnel != NULL)
    {
      if (SSH_PM_TUNNEL_IS_VIRTUAL_IP(qm->tunnel->outer_tunnel)
          && !SSH_PM_VIP_READY(qm->tunnel->outer_tunnel))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Outer tunnel virtual IP setup is not ready."));
          qm->error = SSH_PM_QM_ERROR_NETWORK_UNAVAILABLE;
          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
          return SSH_FSM_CONTINUE;
        }
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_select_p1);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_select_p1)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshIpAddr dst;
  SshIpAddr src = NULL;
  SshPmPeer peer;
  int i = 0;

  /* Select which tunnel to use for p1 in nested tunnel case. */
  SSH_PM_QM_SET_P1_TUNNEL(qm);
  SSH_ASSERT(qm->p1_tunnel != NULL);
  SSH_PM_TUNNEL_TAKE_REF(qm->p1_tunnel);

  /* It is possible we do not get a valid IKE SA here if the IKE SA is
     currently being rekeyed. In this case we lookup a new p1 (which
     should find the rekeyed IKE SA). */
  if (qm->p1 != NULL && !qm->p1->unusable)
    {
      /* Is this p1 still waiting to finish? */
      if (!qm->p1->done && !qm->p1->failed)
        goto wait_p1;

      /* We do not wan't to start new quick mode if following
         conditions are met. */
      if (!qm->p1->done || qm->p1->failed || qm->p1->rekey_pending
          || qm->p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL)
        {
          SSH_ASSERT(qm->p1->unusable == 0);
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("QM not started: p1 %s%s, rekey %s",
                     (qm->p1->done ? "done" : ""),
                     (qm->p1->failed ? " failed" : ""),
                     (qm->p1->rekey_pending ? "pending" :
                     (qm->p1->initiator_ops[PM_IKE_INITIATOR_OP_REKEY] != NULL?
                       "ongoing" : "not active"))));
          qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
          return SSH_FSM_CONTINUE;
        }

      /* Check the server is not pending deletion */
      if (ssh_pm_servers_select(pm, qm->p1->ike_sa->server->ip_address,
                                SSH_PM_SERVERS_MATCH_IKE_SERVER,
                                qm->p1->ike_sa->server,
                                SSH_INVALID_IFNUM,
                                qm->p1->ike_sa->server->routing_instance_id) !=
                                NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Have an existing usable Phase-1"));
          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Lookup a matching Phase-1 SA for this negotiation. We use one
     already established with the address at selector, or one
     established with tunnel's peer IP. */

  /* If we are using transport mode or doing rekey or DPD for IKEv1 keyed
     IPsec SA, use the src address also as selector for p1 lookup if
     available. In transport mode we'll have to use the correct interface
     in negotiating the IKE, or else we'll end up in not usable SA's. In
     rekey and DPD we have to use the same addresses as the IPsec SA is
     using. */
  if (SSH_IP_DEFINED(&qm->sel_src)
      && ((qm->p1_tunnel->flags & SSH_PM_T_TRANSPORT_MODE)
          || qm->rekey || qm->dpd))
    src = &qm->sel_src;

  /* Check sanity of the selected dst address. */
  if (SSH_IP_DEFINED(&qm->sel_dst))
    {
      /* compare all the interface ip with peers specified and qm->sel_dst */
      for (i = 0; i < qm->p1_tunnel->num_peers; i++)
        {
          dst = &qm->p1_tunnel->peers[i];
          if (ssh_pm_find_interface_by_address(pm, dst,
                                  qm->p1_tunnel->routing_instance_id,
                                  NULL) != NULL)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Destined to local interface ip"));
              goto error_immediately;
            }
        }

      dst = &qm->sel_dst;
      if (ssh_pm_find_interface_by_address(pm, dst,
                                  qm->p1_tunnel->routing_instance_id,
                                  NULL) != NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Destined to local interface ip"));
          goto error_immediately;
        }
    }

  /* Start looking up a suitable existing IKE SA. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Looking for a suitable IKE SA"));

  /* Use selected dst address if tunnel does not specify any peers
     or we are creating a new IKEv1 SA for DPD or IPsec SA rekey. For
     triggers prefer tunnel peers in IKE SA lookup. */
  if (qm->dpd || qm->rekey || qm->p1_tunnel->num_peers == 0)
    dst = &qm->sel_dst;
  else
    dst = &qm->p1_tunnel->peers[0];

  i = 0;
  while (dst)
    {
      qm->p1 = ssh_pm_lookup_p1(pm, qm->rule, qm->p1_tunnel, qm->peer_handle,
                                src, dst, FALSE);
      if (qm->p1 != NULL)
        {
#ifdef SSH_IPSEC_TCPENCAP
          /* Consider only p1's with matching encapsulating TCP connection. */
          if (memcmp(qm->tcp_encaps_conn_spi,
                     "\x00\x00\x00\x00\x00\x00\x00\x00",
                     SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH) != 0
              && memcmp(qm->tcp_encaps_conn_spi, qm->p1->ike_sa->ike_spi_i,
                        SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH) != 0)
            qm->p1 = NULL;
          else
#endif /* SSH_IPSEC_TCPENCAP */
            break;
        }

      /* If already processing destination address selector, we're done */
      if (dst == &qm->sel_dst)
        break;

      /* Take next peer, or destination address selector if all peers
         have been processed. */
      i++;
      if (i < qm->p1_tunnel->num_peers)
        dst = &qm->p1_tunnel->peers[i];
      else
        dst = &qm->sel_dst;
    }

  if (qm->p1 == NULL)
    {
      peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
      if (peer != NULL)
        {
          /* If the qm was started from a from-tunnel rule, then do not
             allocate a new IKEv1 SA for idle events and IPsec rekeys. */
          if (peer->use_ikev1 && !qm->forward && (qm->dpd || qm->rekey))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Peer uses IKEv1 and IKE SA has expired, "
                         "ignoring responder %s event.",
                         (qm->rekey ? "rekey" : "idle")));
              goto error_immediately;
            }

          /* If there is another qm thread allocating an IKE SA with the
             same peer, then ignore this event as otherwise we may end up
             having multiple IKE SAs with the peer. Note that this can
             happen when rekeying IKEv1 keyed IPsec SAs or when performing
             IKEv1 DPD. */
          if (peer->allocating_ike_sa)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Another qm thread is negotiating an IKE SA "
                         "with peer, ignoring %s event",
                         (qm->rekey ? "rekey" : (qm->dpd ? "idle" : "trigger"))
                         ));
              goto error_immediately;
            }

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Marking that qm %p is allocating an IKE SA with peer %p",
                     qm, peer));
          peer->allocating_ike_sa = 1;
          qm->allocating_ike_sa = 1;
        }

      /* Allocate a new Phase-1. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No Phase-1 available: allocating a new one"));

      qm->next_peer_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_find_ike_peer);
      return SSH_FSM_CONTINUE;
    }

  if (!qm->p1->done)
    {
    wait_p1:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Phase-1 in progress: waiting for its completion"));
      qm->p1->n->wait_num_threads++;
      qm->next_peer_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_wait_p1);

      /* Reset error state */
      qm->error = SSH_IKEV2_ERROR_OK;
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Found an existing Phase-1"));
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);
  return SSH_FSM_CONTINUE;

 error_immediately:
  qm->error = SSH_PM_QM_ERROR_P1_FAILED;
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_wait_p1)
{
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmP1 p1 = qm->p1;

  if (p1 == NULL)
    {
      /* The Phase-1 negotiation vanished */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Phase-1 aborted"));
      qm->error = SSH_PM_QM_ERROR_P1_FAILED;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
      return SSH_FSM_CONTINUE;
    }

  if (!p1->done)
    {
      /* QM thread was aborted while waiting for a responder p1 */
      if (qm->error != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Quick Mode %p has been aborted while "
                                 "waiting for Phase-I to complete", qm));

          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);






          qm->p1 = NULL;
          SSH_ASSERT(p1->n->wait_num_threads > 0);
          p1->n->wait_num_threads--;
          return SSH_FSM_CONTINUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Waiting for Phase-1 to finish"));
          SSH_FSM_CONDITION_WAIT(&p1->n->wait_condition);
        }
    }

  if (p1->failed)
    {
      /* The Phase-1 negotiation failed. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Phase-1 failed"));
      qm->error = SSH_PM_QM_ERROR_P1_FAILED;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
    }
  else
    {
      /* Everything ok. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Phase-1 was successful"));
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);
    }

  /* Notify Phase-1 thread that we are detached from it. */
  SSH_ASSERT(p1->n->wait_num_threads > 0);
  p1->n->wait_num_threads--;

  SSH_FSM_CONDITION_BROADCAST(&p1->n->wait_condition);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_find_ike_peer)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  Boolean found;

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_select_server);

  /* If using tunnel peers and all peers have been tried without success,
     or not using tunnel peers, then use the specified remote address
     (from qm->sel_dst) as our peer.
     Do not use rule destination selectors of auto start rules. */
  if (((qm->next_peer_index == qm->p1_tunnel->num_peers
        && SSH_IP_DEFINED(&qm->sel_dst)
        && !qm->p1_tunnel->as_active)
       || (qm->p1_tunnel->num_peers == 0
           && qm->p1_tunnel->as_active
           && SSH_IP_DEFINED(&qm->sel_dst))
#ifdef SSHDIST_IKE_REDIRECT
      || (qm->ike_redirected > 0 && SSH_IP_DEFINED(&qm->sel_dst) &&
           !qm->p1_tunnel->as_active)
#endif /* SSHDIST_IKE_REDIRECT */
       )
      && !SSH_IP_EQUAL(&qm->initial_remote_addr, &qm->sel_dst))
    {
      /* We do not utilize cached dead peer information in this case. */
      qm->initial_remote_addr = qm->sel_dst;
      qm->next_peer_index++;
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      if (qm->conn_handle)
        {
          ssh_pm_connection_release(qm->conn_handle);
          qm->conn_handle = NULL;
        }
      SSH_FSM_ASYNC_CALL(ssh_pm_qm_request_connection(qm));
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    }
  else if (qm->next_peer_index < qm->p1_tunnel->num_peers)
    {
      /* Take the first IKE peer that is not known to be dead. Start
         by figuring out if we have peers alive. */
      do
        {
          qm->initial_remote_addr =
            qm->p1_tunnel->peers[qm->next_peer_index++];
          found = !ssh_pm_dpd_peer_dead_p(pm, &qm->initial_remote_addr);
          SSH_DEBUG(SSH_D_MIDOK, ("Check Peer %@ alive %s",
                                  ssh_ipaddr_render,
                                  &qm->initial_remote_addr,
                                  found == TRUE ? "yes" : "no"));
        }
      while (!found && qm->next_peer_index < qm->p1_tunnel->num_peers);

      /* If all peers are dead, we'll pick one. */
      if (!found)
        {
          qm->initial_remote_addr =
            qm->p1_tunnel->peers[qm->p1_tunnel->last_attempted_peer];

          qm->p1_tunnel->last_attempted_peer++;
          SSH_DEBUG(0, ("Not found, trying next... %d",
                        qm->p1_tunnel->last_attempted_peer));
          if (qm->p1_tunnel->last_attempted_peer >= qm->p1_tunnel->num_peers)
            {
              qm->p1_tunnel->last_attempted_peer = 0;
            }
        }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      if (qm->conn_handle)
        {
          ssh_pm_connection_release(qm->conn_handle);
          qm->conn_handle = NULL;
        }
      SSH_FSM_ASYNC_CALL(ssh_pm_qm_request_connection(qm));
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    }
  else
    {
      /* No more IKE peers to try. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("No more IKE peers to try: tried %d",
                                   (int) qm->next_peer_index));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "Message: IKE SA negotiation could not be initiated.");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "Reason:  Peer is not reachable.");

      qm->error = SSH_PM_QM_ERROR_NO_IKE_PEERS;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_select_server)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshUInt32 ifnum = SSH_INVALID_IFNUM;
  SshInterceptorRouteKeyStruct key;

  /* Route peer IP address to resolve our local IP address to that
     direction. */

  /* Does the tunnel specify a local IP address to use?
     Use the local IP with highest precedence. */
  if (qm->p1_tunnel->local_ip != NULL
      || qm->p1_tunnel->local_interface != NULL
#ifdef SSHDIST_IPSEC_DNSPOLICY
      || qm->p1_tunnel->local_dns_address != NULL
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      )
    {
      SshPmTunnelLocalIp local_ip;

      /* Find the local ip with highest precedence,
         that matches the peer IP address family. */
      for (local_ip = qm->p1_tunnel->local_ip;
           local_ip != NULL;
           local_ip = local_ip->next)
        {
          /* Skip non-existent statically configured addresses. */
          if (local_ip->unavailable)
            continue;

          /* IPv4 case. */
          if (SSH_IP_IS4(&local_ip->ip)
              && SSH_IP_IS4(&qm->initial_remote_addr))
            {
              qm->initial_local_addr = local_ip->ip;
              break;
            }

          /* IPv6 case. Checking of these addresses are of
             same kind (i.e. LINK_LOCAL & LINK_LOCAL or
             GLOBAL & GLOBAL) */
          if ((SSH_IP_IS6(&local_ip->ip)
               && SSH_IP_IS6(&qm->initial_remote_addr)) &&
              (SSH_IP6_IS_LINK_LOCAL(&local_ip->ip) ==
               SSH_IP6_IS_LINK_LOCAL(&qm->initial_remote_addr)))
            {
              qm->initial_local_addr = local_ip->ip;
              break;
            }
        }

      if (local_ip == NULL)
        {
          /* No suitable local IP found, select next peer address. */
          SSH_DEBUG(SSH_D_FAIL,
                    ("No suitable local IP address found for peer IP %@",
                     ssh_ipaddr_render, &qm->initial_remote_addr));
          SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_find_ike_peer);
          return SSH_FSM_CONTINUE;
        }

      /* Fetch also the interface number for the address. */
      (void) ssh_pm_find_interface_by_address(pm,
                                   &qm->initial_local_addr,
                                   qm->p1_tunnel->routing_instance_id,
                                   &ifnum);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("QM initial local IP %@ ifnum %d",
                                   ssh_ipaddr_render, &qm->initial_local_addr,
                                   (int) ifnum));
    }
#ifdef SSHDIST_IKEV1
  /* If this is a rekey (or DPD) for an IKEv1 negotiated IPsec SA, and the
     original IKEv1 has been deleted, then qm->sel_src contains the local
     address which was used in the negotiation. */
  else if ((qm->rekey || qm->dpd) && SSH_IP_DEFINED(&qm->sel_src))
    {
      qm->initial_local_addr = qm->sel_src;

      /* Fetch also the interface number for the address. */
      (void) ssh_pm_find_interface_by_address(pm, &qm->initial_local_addr,
                                  qm->p1_tunnel->routing_instance_id,
                                  &ifnum);
    }
#endif /* SSHDIST_IKEV1 */
  /* If this is transport mode and we have a trigger packet,
     try to select the used IKE server from our local server
     matching the source of trigger packet. */
  else if ((qm->p1_tunnel->flags & SSH_PM_T_TRANSPORT_MODE) && qm->trigger)
    {
      if (ssh_pm_find_interface_by_address(pm, &qm->sel_src,
                                   qm->p1_tunnel->routing_instance_id,
                                   NULL))
        qm->initial_local_addr = qm->sel_src;
      else
        SSH_IP_UNDEFINE(&qm->initial_local_addr);
    }
  else
    {
      /* Undefine the local address so that the `ssh_pm_qm_route_cb'
         knows to fill it for us. */
      SSH_IP_UNDEFINE(&qm->initial_local_addr);
    }

  /** Route peer IP address. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Routing IKE peer IP address `%@' to "
                               "resolve our local address using ifnum %d",
                               ssh_ipaddr_render, &qm->initial_remote_addr,
                               (int) ifnum));

  ssh_pm_create_route_key(pm, &key, &qm->initial_local_addr,
                          &qm->initial_remote_addr, SSH_IPPROTO_UDP,
                          0, 0, ifnum, qm->p1_tunnel->routing_instance_id);

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_route_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_route(pm->engine, 0, &key,
                                   ssh_pm_qm_route_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_route_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (qm->error && qm->error != SSH_IKEV2_ERROR_USE_IKEV1)
    {
      /** Route operation failed. */
      ssh_pm_dpd_peer_dead(pm, &qm->initial_remote_addr, FALSE);

      /* Clear route operation failure, leave others. */
      if (qm->error == SSH_IKEV2_ERROR_XMIT_ERROR)
        qm->error = SSH_IKEV2_ERROR_OK;

      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_find_ike_peer);
      return SSH_FSM_CONTINUE;
    }

  /* The route callback selected our local IP address. */
  SSH_ASSERT(SSH_IP_DEFINED(&qm->initial_local_addr));

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_alloc_ike_sa);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_alloc_ike_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshIkev2Server server;
  SshUInt32 ike_sa_flags = 0;
  SshUInt32 server_flags = 0;
#ifdef SSHDIST_IKEV1
  SshPmPeer peer;
#endif /* SSHDIST_IKEV1 */

  if ((qm->error != SSH_IKEV2_ERROR_OK &&
       qm->error != SSH_IKEV2_ERROR_USE_IKEV1) ||
      qm->aborted == 1)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
      return SSH_FSM_CONTINUE;
    }
  PM_SUSPEND_CONDITION_WAIT(pm, thread);

#ifdef SSHDIST_IKEV1
  peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);

  /* Fallback to IKEv1 if previous attempt indicates so and local policy
     allows this. */
  if ((qm->error == SSH_IKEV2_ERROR_USE_IKEV1
       && (qm->p1_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1))
      || !(qm->p1_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2))
    {
      qm->error = SSH_IKEV2_ERROR_OK;
      ike_sa_flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1;
    }

  /* Start with IKEv1 if peer is known to require IKEv1 and local
     policy allows this. */
  else if (qm->error == SSH_IKEV2_ERROR_OK
           && (peer != NULL && peer->use_ikev1)
           && (qm->p1_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1))
    {
      ike_sa_flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1;
    }
#endif /* SSHDIST_IKEV1 */

  if (qm->p1_tunnel->flags & SSH_PM_TI_START_WITH_NATT
#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      || (qm->rekey && qm->sel_dst_port != 0)
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IKEV1 */
      )
    ike_sa_flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T;

  if (qm->p1_tunnel->flags & SSH_PM_T_DISABLE_NATT)
    ike_sa_flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T;

#ifdef SSHDIST_IPSEC_MOBIKE
  if (qm->p1_tunnel->flags & SSH_PM_T_MOBIKE)
    ike_sa_flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE;

  /* Add NO_NATS_ALLOWED flag automatically if NAT-T is disabled and
     tunnel does not specify TCP encapsulation. */
  if ((ike_sa_flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T)
      && ((qm->p1_tunnel->flags & SSH_PM_T_NO_NATS_ALLOWED)
#ifdef SSH_IPSEC_TCPENCAP
          || (qm->p1_tunnel->flags & SSH_PM_T_TCPENCAP) == 0
#endif /* SSH_IPSEC_TCPENCAP */
          ))
    ike_sa_flags |= SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_NO_NATS_ALLOWED;
#endif /* SSHDIST_IPSEC_MOBIKE */

  SSH_DEBUG(SSH_D_HIGHSTART, ("Allocating IKE SA with flags %x",
                              (unsigned long) ike_sa_flags));

  /* Try to select an IKE server when we know the local IP address and port. */
#if 0
  /* We do not wan't to use qm->packet_ifnum for selecting server interface.
     This is the interface where the trigger came, it might not be
     the interface we wan't to use for conversation with peer. */
  if (qm->packet_ifnum != SSH_INVALID_IFNUM)
    server_flags |= SSH_PM_SERVERS_MATCH_IFNUM;
#endif /* 0 */

  if (qm->p1_tunnel->local_port)
    server_flags |= SSH_PM_SERVERS_MATCH_PORT;
  server = ssh_pm_servers_select_ike(pm, &qm->initial_local_addr,
                                     server_flags,
                                     SSH_INVALID_IFNUM,
                                     qm->p1_tunnel->local_port,
                                     qm->p1_tunnel->routing_instance_id);

  if (server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No IKE server running on local IP address `%@'",
                             ssh_ipaddr_render, &qm->initial_local_addr));

      /** No IKE server running. */
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_find_ike_peer);
      return SSH_FSM_CONTINUE;
    }

  /** Allocate IKE SA. */
#ifdef SSH_IPSEC_TCPENCAP
  if ((qm->p1_tunnel->flags & SSH_PM_T_TCPENCAP) &&
      (ike_sa_flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T) == 0)
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_create_ike_mapping);
  else if (memcmp(qm->tcp_encaps_conn_spi,
                  "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0)
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_create_ike_mapping);
  else
#endif /* SSH_IPSEC_TCPENCAP */
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_check_initial_contact);
  SSH_FSM_ASYNC_CALL({
    ssh_ikev2_ike_sa_allocate(server,
                              &qm->initial_remote_addr,
                              ike_sa_flags,
                              ssh_pm_ike_sa_allocated,
                              thread);
  });
  SSH_NOTREACHED;
  return SSH_FSM_CONTINUE;
}

#ifdef SSH_IPSEC_TCPENCAP
void pm_qm_i_n_create_ike_mapping_cb(SshPm pm, SshUInt32 conn_id,
                                     void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmQm qm = (SshPmQm) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_LOWOK,
            ("TCP encapsulation mapping created (or updated): "
             "IKE SA %p connection id 0x%lx local %@ remote %@",
             qm->p1->ike_sa, (unsigned long) conn_id,
             ssh_ipaddr_render, qm->p1->ike_sa->server->ip_address,
             ssh_ipaddr_render, qm->p1->ike_sa->remote_ip));

  if (conn_id != SSH_IPSEC_INVALID_INDEX)
    {
    qm->p1->ike_sa->flags |= SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;
      /* Add TCPENCAP to compat flags, so that we send the TCPENCAP
         vendor ID also in the case that this is a responder IPsec
         SA rekey and a new IKEv1 SA is negotiated for that purpose. */
      qm->p1->compat_flags |= SSH_PM_COMPAT_TCPENCAP;
      /* Update qm->tcp_encaps_conn_spi. */
      memcpy(qm->tcp_encaps_conn_spi, qm->p1->ike_sa->ike_spi_i,
             SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH);
    }
  else
    qm->p1->ike_sa->flags &= ~SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_create_ike_mapping)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmP1 p1 = qm->p1;

  if (qm->error || qm->p1 == NULL)
    {
      /* IKE SA allocation failed. Go immediately to next state
         for error handling. */
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_create_ike_mapping_result);

  /* Create a new IKE mapping. */
  if (memcmp(qm->tcp_encaps_conn_spi, "\x00\x00\x00\x00\x00\x00\x00\x00",
             SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH) == 0)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Creating TCP encapsulation IKE mapping: "
                 "IKE SA %p local %@:%d remote %@:%d spi 0x%08lx 0x%08lx",
                 p1->ike_sa,
                 ssh_ipaddr_render, qm->p1->ike_sa->server->ip_address,
                 qm->tunnel->tcp_encaps_config.local_port,
                 ssh_ipaddr_render, qm->p1->ike_sa->remote_ip,
                 qm->tunnel->tcp_encaps_config.peer_port,
                 SSH_GET_32BIT(p1->ike_sa->ike_spi_i),
                 SSH_GET_32BIT(p1->ike_sa->ike_spi_i + 4)));

      SSH_FSM_ASYNC_CALL({
        ssh_pme_tcp_encaps_create_ike_mapping(pm->engine,
                                        qm->p1->ike_sa->server->ip_address,
                                        qm->p1->ike_sa->remote_ip,
                                        qm->tunnel->
                                        tcp_encaps_config.local_port,
                                        qm->tunnel->
                                        tcp_encaps_config.peer_port,
                                        p1->ike_sa->ike_spi_i,
                                        SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
                                        SSH_PM_IKE_SA_REMOTE_PORT(p1->ike_sa),
                                        pm_qm_i_n_create_ike_mapping_cb,
                                        thread);
      });
      SSH_NOTREACHED;
    }

  /* Update existing IKE mapping with new IKE cookie. */
  else if (memcmp(qm->tcp_encaps_conn_spi, p1->ike_sa->ike_spi_i,
                  SSH_IPSEC_TCPENCAP_IKE_COOKIE_LENGTH) != 0)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("Updating TCP encapsulation IKE mapping: "
                 "IKE SA %p SPI 0x%08lx 0x%08lx mapping SPI 0x%08lx 0x%08lx",
                 p1->ike_sa,
                 SSH_GET_32BIT(p1->ike_sa->ike_spi_i),
                 SSH_GET_32BIT(p1->ike_sa->ike_spi_i + 4),
                 SSH_GET_32BIT(qm->tcp_encaps_conn_spi),
                 SSH_GET_32BIT(qm->tcp_encaps_conn_spi + 4)));

      SSH_FSM_ASYNC_CALL({
        ssh_pme_tcp_encaps_update_ike_mapping(pm->engine, FALSE,
                                              p1->ike_sa->server->ip_address,
                                              p1->ike_sa->remote_ip,
                                              qm->tcp_encaps_conn_spi,
                                              p1->ike_sa->ike_spi_i,
                                              pm_qm_i_n_create_ike_mapping_cb,
                                              thread);
      });
      SSH_NOTREACHED;
    }

  /* Existing IKE mapping matches new IKE cookie, need to do nothing. */

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_create_ike_mapping_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  if ((qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("TCP encapsulation IKE mapping creation failed"));
      qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_check_initial_contact);
  return SSH_FSM_CONTINUE;
}
#endif /* SSH_IPSEC_TCPENCAP */









SSH_FSM_STEP(ssh_pm_st_qm_i_n_check_initial_contact)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;

  if (qm->error || qm->p1 == NULL)
    {
      /* IKE SA allocation failed. Go immediately to next state
         for error handling. */
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);
      return SSH_FSM_CONTINUE;
    }

  /** Check Quick-Mode SAs with the remote peer. Use port from tunnel if it
      defines one. */
  SSH_DEBUG(SSH_D_LOWOK, ("Checking whether to send initial contact, remote "
                          "peer is %@:%d",
                          ssh_ipaddr_render, &qm->initial_remote_addr,
                          (qm->p1->ike_sa->remote_port ?
                           qm->p1->ike_sa->remote_port : 500)));




  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);
  SSH_FSM_ASYNC_CALL(ssh_pme_have_transform_with_peer(
                                                pm->engine,
                                                &qm->initial_remote_addr,
                                                qm->p1->ike_sa->remote_port,
                                                ssh_pm_transform_with_peer_cb,
                                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_restart_qm)
{
  SshPmQm qm = (SshPmQm) thread_context;

  /* Check if the P1 has disappeared while starting this thread. */
  if (qm->p1 == NULL)
    {
      qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Start thread for this new QM */
#ifdef SSH_IPSEC_TCPENCAP
  if ((qm->p1_tunnel->flags & SSH_PM_T_TCPENCAP) &&
      !qm->p1->done &&
      (qm->p1->ike_sa->flags &
       SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T) == 0)
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_create_ike_mapping);
  else
#endif /* SSH_IPSEC_TCPENCAP */
    SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_prepare_qm);

  if (qm->p1->unusable || !qm->p1->done || qm->p1->failed ||
      qm->p1->rekey_pending)
    {
      /* P1 is unusable. */
      qm->error = SSH_IKEV2_ERROR_SA_UNUSABLE;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_prepare_qm)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmP1 p1 = qm->p1;
  int slot;

  if (qm->error || qm->p1 == NULL || qm->aborted == 1 ||
      !pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Negotiation in error state or IKE is busy."));
      goto error_immediately;
    }
  PM_SUSPEND_CONDITION_WAIT(pm, thread);

  SSH_PM_ASSERT_P1(p1);

  /* Check if the policy manager is shutting down. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Policy manager is shutting down: terminating"));
      qm->error = SSH_IKEV2_ERROR_GOING_DOWN;
      goto error_immediately;
    }

#if (SSH_PM_MAX_CHILD_SAS > 0)
  /* Check if we are allowed to create another child SA with this peer. */
  if (ssh_pm_peer_num_child_sas_by_p1(pm, p1) > SSH_PM_MAX_CHILD_SAS)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Maximum number of child SAs per peer reached %d: "
                 "terminating",
                 (int) SSH_PM_MAX_CHILD_SAS));
      qm->error = SSH_IKEV2_ERROR_OUT_OF_MEMORY;
      goto error_immediately;
    }
#endif /* (SSH_PM_MAX_CHILD_SAS > 0) */

  /* If this operation is to create an IKE SA also, then set the tunnel
     to the Phase-I negotiation structure. */
  if (p1->n && !p1->done)
    {
      p1->tunnel_id = qm->p1_tunnel->tunnel_id;
      p1->n->tunnel = qm->p1_tunnel;
      SSH_PM_TUNNEL_TAKE_REF(p1->n->tunnel);

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* If this is a rekey which requires a new IKEv1 SA to be negotiated,
         then qm->sel_dst_port contains the remote NAT-T port */
      if (qm->rekey &&
          (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
          qm->sel_dst_port != 0)
        {
          p1->ike_sa->remote_port = qm->sel_dst_port;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IKEV1 */
    }

  qm->ike_done = 0;

#ifdef SSHDIST_IKEV1
  /* Ready to do an information exchange. */
  if (qm->dpd || qm->unknown_spi)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_do_info);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_IKEV1 */

  qm->ed = ssh_ikev2_ipsec_create_sa(p1->ike_sa, 0);
  if (qm->ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate exchange data"));
      goto error_immediately;
    }
  qm->ed->application_context = qm;

#ifdef SSHDIST_IKEV1
  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE))
    {
      qm->ed->ike_ed->exchange_type =
        (qm->p1_tunnel->flags & SSH_PM_TI_AGGRESSIVE_MODE)
        ? SSH_IKE_XCHG_TYPE_AGGR
        : SSH_IKE_XCHG_TYPE_IP;
#ifdef SSHDIST_IPSEC_XAUTH_CLIENT
      if (qm->p1_tunnel->flags & SSH_PM_T_XAUTH_METHODS)
        p1->ike_sa->xauth_enabled = 1;
#endif /* SSHDIST_IPSEC_XAUTH_CLIENT */
      qm->ed->ike_ed->sa_life_seconds =
        qm->p1_tunnel->u.ike.ike_sa_life_seconds;
    }
  qm->ed->ipsec_ed->sa_life_seconds = qm->tunnel->u.ike.life_seconds;
  qm->ed->ipsec_ed->sa_life_kbytes = qm->tunnel->u.ike.life_kb;
#endif /* SSHDIST_IKEV1 */

  if (qm->rekey)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Calling ipsec rekey for QM, old inbound spi "
                              "0x%08lx",
                              (unsigned long) qm->old_inbound_spi));
      ssh_ikev2_ipsec_rekey(qm->ed, qm->old_inbound_spi);
    }

  /* Ready to start Quick-Mode. */
  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_do_qm);
  return SSH_FSM_CONTINUE;

 error_immediately:

  SSH_DEBUG(SSH_D_FAIL, ("Quick-Mode %p has failed before IPSec send "
                         "operation has begun", qm));

  /* Handle the case where the Quick-Mode has failed before the ipsec send
     operation has started and this exchange is also creating a new IKE SA.
     In this case we need to wake up the Phase-I negotiation thread, as it
     is waiting for the Phase-I negotiation to complete. */
  if (p1 && p1->n && !p1->done)
    {
      p1->done = 1;
      p1->failed = 1;
      p1->delete_with_negotiation = 1;
      SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 thread"));
      SSH_ASSERT(SSH_FSM_THREAD_EXISTS(&p1->n->thread));
      ssh_fsm_continue(&p1->n->thread);
    }

  if (qm->ed)
    {
      ssh_ikev2_ipsec_exchange_destroy(qm->ed);
      qm->ed = NULL;
    }
  qm->ike_done = 1;
  if (qm->error == SSH_IKEV2_ERROR_OK)
    qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_qm_result);
  return SSH_FSM_CONTINUE;
}

#ifdef SSHDIST_IKEV1
/* Perform an information exchange instead of negotiating an IPsec SA. */
SSH_FSM_STEP(ssh_pm_st_qm_i_n_do_info)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmP1 p1 = qm->p1;
  int slot;
  SshPmInfo info = NULL;
  unsigned char spi_buf[4];

  SSH_ASSERT(qm->dpd || qm->unknown_spi);

  if (qm->error || qm->p1 == NULL || qm->aborted == 1
      || !pm_ike_async_call_possible(p1->ike_sa, &slot))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Negotiation in error state or IKE is busy."));
      goto error_immediately;
    }

  PM_SUSPEND_CONDITION_WAIT(pm, thread);

  SSH_PM_ASSERT_P1(p1);

  /* Check if the policy manager is shutting down. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Policy manager is shutting down: terminating"));
      qm->error = SSH_IKEV2_ERROR_GOING_DOWN;
      goto error_immediately;
    }

  /* For DPD check peer liveliness by creating a new IKE SA within the
     informational exchange. */
  if (qm->dpd && (p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE))
    {
      /* We have established a new SA since triggered for DPD with
         nonexistent SA just a moment ago... This serves as a
         evidence of the peer being alive. */
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_success);
      return SSH_FSM_CONTINUE;
    }

  qm->ed = ssh_ikev2_info_create(p1->ike_sa, 0);
  if (qm->ed == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate informational exchange "
                             "data"));
      goto error_immediately;
    }

  info = ssh_pm_info_alloc(pm, qm->ed, SSH_PM_ED_DATA_INFO_QM);
  if (info == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate informational exchange "
                             "context"));
      goto error_immediately;
    }
  info->u.qm = qm;

  /* Add an invalid SPI notification for the unknown SPI value. */
  if (qm->unknown_spi)
    {
      SSH_PUT_32BIT(spi_buf, qm->unknown_spi);
      if (ssh_ikev2_info_add_n(qm->ed,
                               (qm->sel_ipproto == SSH_IPPROTO_ESP ?
                                SSH_IKEV2_PROTOCOL_ID_ESP :
                                SSH_IKEV2_PROTOCOL_ID_AH),
                               spi_buf, sizeof(spi_buf),
                               SSH_IKEV2_NOTIFY_INVALID_SPI,
                               spi_buf, sizeof(spi_buf))
          != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Cannot add notify payload"));
          goto error_immediately;
        }
    }

  /* See pm_ike_info_done_callback */
  qm->ed->application_context = info;

  /* Definitely not initial contact, as we are here triggered
     by a transform. */
  qm->send_initial_contact = 0;

  if (!(p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE))
    {
      qm->ed->ike_ed->exchange_type =
        (qm->tunnel->flags & SSH_PM_TI_AGGRESSIVE_MODE)
        ? SSH_IKE_XCHG_TYPE_AGGR
        : SSH_IKE_XCHG_TYPE_IP;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_qm_result);

  SSH_DEBUG(SSH_D_LOWOK, ("Starting info send operation"));

  PM_IKE_ASYNC_CALL(p1->ike_sa, qm->ed, slot,
                    ssh_ikev2_info_send(qm->ed,
                                        pm_ike_info_done_callback));
  return SSH_FSM_CONTINUE;

 error_immediately:

  SSH_DEBUG(SSH_D_FAIL, ("Quick-Mode %p has failed before info send "
                         "operation has begun", qm));

  /* Handle the case where the Quick-Mode has failed before the info send
     operation has started and this exchange is also creating a new IKE SA.
     In this case we need to wake up the Phase-I negotiation thread, as it
     is waiting for the Phase-I negotiation to complete. */
  if (p1 && p1->n && !p1->done)
    {
      p1->done = 1;
      p1->failed = 1;
      p1->delete_with_negotiation = 1;
      SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 thread"));
      SSH_ASSERT(SSH_FSM_THREAD_EXISTS(&p1->n->thread));
      ssh_fsm_continue(&p1->n->thread);
    }

  if (qm->ed)
    {
      ssh_ikev2_info_destroy(qm->ed);
      qm->ed = NULL;
    }
  qm->ike_done = 1;
  if (qm->error == SSH_IKEV2_ERROR_OK)
    qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_qm_result);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IKEV1 */

/* Create trigger and send */
SSH_FSM_STEP(ssh_pm_st_qm_i_n_do_qm)
{
  SshPmQm qm = (SshPmQm) thread_context;
  SshIkev2TriggeringPacketStruct trigger_packet, *trigger;
  int slot;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Create IPsec SA: local ts %@, remote ts %@",
                              ssh_ikev2_ts_render, qm->local_ts,
                              ssh_ikev2_ts_render, qm->remote_ts));
  trigger = NULL;

  if (qm->p1 == NULL || qm->aborted == 1)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_qm_result);
      goto error_immediately;
    }

  PM_SUSPEND_CONDITION_WAIT(qm->p1->pm, thread);

#ifdef SSHDIST_IKEV1
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_ISAKMP_CFG_MODE
  /* For rules requesting the address of the local traffic selector to
     be adjusted, set up a dummy trigger packet to cause the IKE lib
     to allocate the overriding local address. */
  if ((qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
      (qm->rule->flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS))
    {
      memset(&trigger_packet, 0, sizeof trigger_packet);
      memset(&qm->sel_src, 0, sizeof qm->sel_src);
      trigger_packet.source_ip =  &qm->sel_src;
      trigger = &trigger_packet;
    }
  else
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  /* For IKEv1 negotiations the trigger packet is used for
     overriding the policy rule's traffic selectors, so we pass
     it only if the policy rule does not define any traffic
     selectors. That is, the rule has default match all traffic
     selectors, and the tunnel does not have perport or perhost
     flags set. */
  if ((qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1) &&
      qm->send_trigger_ts)
    {
      /* Select only IP addresses from the trigger packet,
         and let protocol and port ranges to match all. */
      trigger_packet.source_ip = NULL;
      if (qm->rule->side_from.default_ts)
        {
          trigger_packet.source_ip =  &qm->sel_src;
          trigger_packet.source_port = 0;
          trigger_packet.protocol = 0;
          trigger = &trigger_packet;
        }

      trigger_packet.destination_ip = NULL;
      if (qm->rule->side_to.default_ts)
        {
          trigger_packet.destination_ip =  &qm->sel_dst;
          trigger_packet.destination_port = 0;
          trigger_packet.protocol = 0;
          trigger = &trigger_packet;
        }
    }
  /* Handle IKEv2 below */
  else
#endif /* SSHDIST_IKEV1 */
  /* If this QM negotiation is the result of a trigger, then inform
     the IKE library about the triggering packet.  */
  if (qm->send_trigger_ts)
    {
      trigger_packet.source_ip =  &qm->sel_src;
      trigger_packet.destination_ip =  &qm->sel_dst;
      trigger_packet.protocol = qm->sel_ipproto;
      trigger_packet.source_port = qm->sel_src_port;
      trigger_packet.destination_port = qm->sel_dst_port;
      trigger = &trigger_packet;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_qm_result);

  if (!pm_ike_async_call_possible(qm->p1->ike_sa, &slot))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Async call not possible, failing negotiation"));
      goto error_immediately;
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Starting IPSec send operation"));

  PM_IKE_ASYNC_CALL(qm->p1->ike_sa, qm->ed, slot,
                    ssh_ikev2_ipsec_send(qm->ed, trigger,
                                         qm->local_ts,
                                         qm->remote_ts,
                                         pm_ipsec_sa_done_callback));

  return SSH_FSM_CONTINUE;

 error_immediately:
  /* Handle the case where the Quick-Mode has failed before the ipsec send
     operation has started and this exchange is also creating a new IKE SA.
     In this case we need to wake up the Phase-I negotiation thread, as it
     is waiting for the Phase-I negotiation to complete. */
  if (qm->p1 && qm->p1->n && !qm->p1->done)
    {
      qm->p1->done = 1;
      qm->p1->failed = 1;
      qm->p1->delete_with_negotiation = 1;
      SSH_DEBUG(SSH_D_LOWOK, ("Waking up the Phase-1 thread"));
      SSH_ASSERT(SSH_FSM_THREAD_EXISTS(&qm->p1->n->thread));
      ssh_fsm_continue(&qm->p1->n->thread);
    }

  if (qm->ed)
    {
      ssh_ikev2_ipsec_exchange_destroy(qm->ed);
      qm->ed = NULL;
    }
  qm->ike_done = 1;
  qm->error = SSH_IKEV2_ERROR_XMIT_ERROR;
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_qm_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("In QM Result ike done/error is %d/%d", qm->ike_done, qm->error));

  /* Wait until the IKE completes. */
  if (!qm->ike_done)
    {
      /* Sleep until the operation is complete. */
      SSH_DEBUG(SSH_D_LOWOK, ("Suspending until IKE completes"));
      return SSH_FSM_SUSPENDED;
    }

  /* Check the result. */
  if (qm->error)
    {






      qm->p1 = NULL;
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
    }
  else
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_sa_handler_result);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_sa_handler_result)
{
  SshPmQm qm = (SshPmQm) thread_context;

  /* Wait until the transform is installed. */
  if (!qm->sa_handler_done)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Suspending until SA handler completes"));
      return SSH_FSM_SUSPENDED;
    }

  if (qm->error)
    {
      SSH_DEBUG(SSH_D_FAIL, ("SA handler failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_qm_i_n_success);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_failed)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmQm qm = (SshPmQm) thread_context;
  SshPmPeer peer;

  /* Reset allocating IKE SA flag from peer. */
  if (qm->allocating_ike_sa)
    {
      /* Assert that qm->peer_handle points to a valid peer object.
         The flag qm->allocating_ike_sa could never have been set if
         there was no such peer object, thus this assert fails only
         if there is a bug somewhere in the peer handle reference
         counting. */
      SSH_ASSERT(qm->peer_handle != SSH_IPSEC_INVALID_INDEX);
      peer = ssh_pm_peer_by_handle(pm, qm->peer_handle);
      SSH_ASSERT(peer != NULL);
      SSH_ASSERT(peer->allocating_ike_sa != 0);
      peer->allocating_ike_sa = 0;
      qm->allocating_ike_sa = 0;
    }

  /* Return back to our caller's failure state. */
  SSH_ASSERT(qm->fsm_qm_i_n_failed != NULL_FNPTR);
  SSH_FSM_SET_NEXT(qm->fsm_qm_i_n_failed);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_qm_i_n_success)
{
  SshPmQm qm = (SshPmQm) thread_context;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Transfer ownership of network connection to P1, or release it
   * if the P1 already has a connection. */
  if (qm->conn_handle)
    {
      if (qm->p1->conn_handle == NULL)
        qm->p1->conn_handle = qm->conn_handle;
      else
        ssh_pm_connection_release(qm->conn_handle);
      qm->conn_handle = NULL;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSHDIST_IKEV1
  /* If this qm was creating a new IKEv1 SA, then attach the
     negotiated IKE SA to peer. */
  if (qm->dpd && qm->peer_handle != SSH_IPSEC_INVALID_INDEX)
    {
      SshPm pm = (SshPm) fsm_context;

      SSH_DEBUG(SSH_D_LOWOK,
                ("DPD: New IKEv1 SA created, attaching IKE SA to peer"));
      SSH_ASSERT(ssh_pm_peer_by_handle(pm, qm->peer_handle) != NULL);
      ssh_pm_peer_update_p1(pm,
                            ssh_pm_peer_by_handle(pm, qm->peer_handle),
                            qm->p1);
    }
#endif /* SSHDIST_IKEV1 */

  /* Return back to our caller's success state. */
  SSH_ASSERT(qm->fsm_qm_i_n_success != NULL_FNPTR);
  SSH_FSM_SET_NEXT(qm->fsm_qm_i_n_success);

  return SSH_FSM_CONTINUE;
}
