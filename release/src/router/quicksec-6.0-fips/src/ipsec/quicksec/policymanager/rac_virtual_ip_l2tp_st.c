/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Virtual IP with L2TP (Layer 2 Tunneling Protocol).
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_L2TP

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmStVirtualIpL2tp"


/************************** Static help functions ***************************/

/* A callback function that is called to complete a route operation
   for the L2TP tunnel's remote peer.  If the destination is
   reachable, the function sets the local IP address to be used to the
   `vip->t.l2tp.local_ip'. */
static void
ssh_pm_l2tp_route_cb(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
                     const SshIpAddr next_hop, size_t mtu, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);
  SshIpAddr ip;

  /* As a default we fail since this is the most common case below. */
  vip->t.l2tp.route_ok = 0;

  if ((flags & SSH_PME_ROUTE_REACHABLE) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is unreachable",
                 ssh_ipaddr_render,
                 &vip->tunnel->peers[vip->t.l2tp.peer_index]));
    }
  else if (flags & SSH_PME_ROUTE_LOCAL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is our local address",
                 ssh_ipaddr_render,
                 &vip->tunnel->peers[vip->t.l2tp.peer_index]));
    }
  else if (flags & SSH_PME_ROUTE_LINKBROADCAST)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is a link-local broadcast address",
                 ssh_ipaddr_render,
                 &vip->tunnel->peers[vip->t.l2tp.peer_index]));
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%@' is reachable using interface %d",
                 ssh_ipaddr_render,
                 &vip->tunnel->peers[vip->t.l2tp.peer_index],
                 (int) ifnum));

      /* Select the local IP address to use with the peer. */
      ip = ssh_pm_find_interface_address(pm, ifnum,
                                         (SSH_IP_IS6(&vip->tunnel->peers[
                                                vip->t.l2tp.peer_index])
                                          ? TRUE : FALSE),
                                         next_hop);
      if (ip == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Interface %d does not have an usable address",
                    (int) ifnum));
        }
      else
        {
          vip->t.l2tp.route_ok = 1;
          vip->t.l2tp.local_ifnum = ifnum;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Using local IP address `%@'",
                                       ssh_ipaddr_render, ip));
          vip->t.l2tp.local_ip = *ip;
        }
    }

  /* The next state is already set by the caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* An SshPmLegacyAuthClientQueryResultCB argument for the
   SshPmLegacyAuthClientQueryCB function.  */
static void
ssh_pm_l2tp_auth_query_result_cb(Boolean success,
                                 const unsigned char *user_name,
                                 size_t user_name_len,
                                 const unsigned char *user_password,
                                 size_t user_password_len,
                                 const unsigned char *passcode,
                                 size_t passcode_len,
                                 const unsigned char *next_pin,
                                 size_t next_pin_len,
                                 const unsigned char *answer,
                                 size_t answer_len,
                                 void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  vip->t.l2tp.auth_ok = 0;
  vip->la_auth_operation = NULL;

  if (success)
    {
      vip->t.l2tp.user_name = ssh_memdup(user_name, user_name_len);
      vip->t.l2tp.user_password = ssh_memdup(user_password, user_password_len);
      if (vip->t.l2tp.user_name == NULL || vip->t.l2tp.user_password == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not store authentication information"));
          ssh_free(vip->t.l2tp.user_name);
          ssh_free(vip->t.l2tp.user_password);
          vip->t.l2tp.user_name = NULL;
          vip->t.l2tp.user_password = NULL;
        }
      else
        {
          vip->t.l2tp.user_name_len = user_name_len;
          vip->t.l2tp.user_password_len = user_password_len;
          vip->t.l2tp.auth_ok = 1;
        }
    }
  else
    {
      /* The callback failed the operation. */
      vip->t.l2tp.auth_cb_fail = 1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to complete a transform rule
   lookup. */
static void
ssh_pm_l2tp_lac_find_transform_rule_cb(SshPm pm,
                                       const SshEnginePolicyRule rule,
                                       SshUInt32 transform_index,
                                       SshUInt32 outbound_spi,
                                       void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (rule != NULL)
    {
      vip->t.l2tp.sa_rule_index = rule->rule_index;
      vip->t.l2tp.trd_index = rule->transform_index;
    }
  else
    {
      vip->t.l2tp.sa_rule_index = SSH_IPSEC_INVALID_INDEX;
      vip->t.l2tp.trd_index = SSH_IPSEC_INVALID_INDEX;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to notify the status of L2TP
   tunnel rule addition. */
static void
ssh_pm_l2tp_add_tunnel_rule_cb(SshPm pm, SshUInt32 ind,
                               const SshEnginePolicyRule rule,
                               void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  vip->t.l2tp.tunnel_index = ind;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A status callback function for rule lock operation. */
static void
ssh_pm_l2tp_lock_sa_rule_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  if (!status)
    {
      /* Taking a reference failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Taking a reference to the SA rule failed"));
      vip->t.l2tp.sa_rule_index = SSH_IPSEC_INVALID_INDEX;
    }
  else
    {
      vip->t.l2tp.ref_to_sa_rule = 1;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function to complete the tunnel rule deletion from the engine. */
static void
ssh_pm_l2tp_delete_tunnel_rule_cb(SshPm pm, Boolean done,
                                  SshUInt32 rule_index,
                                  SshUInt32 peer_handle,
                                  SshEngineTransform tr,
                                  void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_LOWOK, ("Deleted L2TP tunnel rule %u", (int) rule_index));

  if (done)
    {
      SSH_ASSERT(rule_index == SSH_IPSEC_INVALID_INDEX
                 || rule_index == vip->t.l2tp.tunnel_index);
      vip->t.l2tp.tunnel_index = SSH_IPSEC_INVALID_INDEX;
    }

  /* Continue.  The next state is already set by our caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function to complete the SA rule deletion from the engine. */
static void
ssh_pm_l2tp_delete_sa_rule_cb(SshPm pm, Boolean done,
                              SshUInt32 rule_index,
                              SshUInt32 peer_handle,
                              SshEngineTransform tr,
                              void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);
  SshUInt32 inbound_spi[2];
  int num_spis;
  SshUInt8 ipproto;
#ifdef DEBUG_LIGHT
  int i;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_LOWOK,
            ("Deleted reference to L2TP SA rule %u", (int) rule_index));

  if (done)
    {
      SSH_ASSERT(rule_index == SSH_IPSEC_INVALID_INDEX
                 || rule_index == vip->t.l2tp.sa_rule_index);
      vip->t.l2tp.sa_rule_index = SSH_IPSEC_INVALID_INDEX;
      vip->t.l2tp.ref_to_sa_rule = 0;
    }

  if (tr != NULL)
    {
      num_spis = 0;
      if (tr->data.transform & SSH_PM_IPSEC_AH)
        {
          ipproto = SSH_IPPROTO_AH;
          if (tr->data.spis[SSH_PME_SPI_AH_IN] != 0)
            inbound_spi[num_spis++] = tr->data.spis[SSH_PME_SPI_AH_IN];
          if (tr->data.old_spis[SSH_PME_SPI_AH_IN] != 0)
            inbound_spi[num_spis++] = tr->data.old_spis[SSH_PME_SPI_AH_IN];
        }
      else if (tr->data.transform & SSH_PM_IPSEC_ESP)
        {
          ipproto = SSH_IPPROTO_ESP;
          if (tr->data.spis[SSH_PME_SPI_ESP_IN] != 0)
            inbound_spi[num_spis++] = tr->data.spis[SSH_PME_SPI_ESP_IN];
          if (tr->data.old_spis[SSH_PME_SPI_ESP_IN] != 0)
            inbound_spi[num_spis++] = tr->data.old_spis[SSH_PME_SPI_ESP_IN];
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Invalid transform mask 0x%08lx, not ESP or AH",
                     (unsigned long) tr->data.transform));
          SSH_NOTREACHED;
          goto out;
        }

      /* Send delete notification. */
      SSH_ASSERT(vip->tunnel != NULL);

#ifdef DEBUG_LIGHT
      for (i = 0; i < num_spis; i++)
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Sending delete notification for SPI %@-%08lx",
                     ssh_ipproto_render, (SshUInt32) ipproto,
                     (unsigned long) inbound_spi[i]));
        }
#endif /* DEBUG_LIGHT */

      ssh_pm_send_ipsec_delete_notification(pm, peer_handle, vip->tunnel,
                                            vip->rules->rule, ipproto,
                                            num_spis, inbound_spi);
    }

  /* Continue.  The next state is already set by our caller. */
 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}


/***************** Static help functions for LAC sub-thread *****************/

/* Session status callback for LAC incoming call sessions. */
static void
ssh_pm_l2tp_lac_session_status_cb(SshL2tpSessionInfo info,
                                  SshL2tpSessionStatus status,
                                  void *callback_context)
{
  SshFSMThread thread = (SshFSMThread) callback_context;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  vip->t.l2tp.operation = NULL;
  vip->t.l2tp.info = info;
  vip->t.l2tp.status = status;
  vip->t.l2tp.l2tp_status = 1;

  /* Handle the failure and termination cases here so we will avoid a
     possible race conditions with the L2TP and PPP libraries. */
  switch (status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            (info != NULL ? info->tunnel : NULL), info,
                            "failed");
      if (info && info->tunnel && info->tunnel->result_code)
        {
          /* An error in the L2TP tunnel. */
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Result:  %s",
                        ssh_find_keyword_name(ssh_l2tp_tunnel_result_codes,
                                              info->tunnel->result_code));
          if (info->result_code == SSH_L2TP_SESSION_RESULT_ERROR)
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          "  Error:   %s",
                          ssh_find_keyword_name(ssh_l2tp_error_codes,
                                                info->tunnel->error_code));
          if (info->tunnel->error_message)
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          "  Message: %.*s",
                          (int) info->tunnel->error_message_len,
                          info->tunnel->error_message);
        }
      else if (info)
        {
          /* An error in the L2TP session. */
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  Result:  %s",
                        ssh_find_keyword_name(ssh_l2tp_session_result_codes,
                                              info->result_code));
          if (info->result_code == SSH_L2TP_SESSION_RESULT_ERROR)
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          "  Error:   %s",
                          ssh_find_keyword_name(ssh_l2tp_error_codes,
                                                info->error_code));
          if (info->error_message)
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                          "  Message: %.*s",
                          (int) info->error_message_len, info->error_message);
        }
      break;

    case SSH_L2TP_SESSION_TERMINATED:
      if (vip->t.l2tp.ppp)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Terminating PPP"));
          ssh_ppp_destroy(vip->t.l2tp.ppp);
          vip->t.l2tp.ppp = NULL;
        }

      /* The info is no longer valid. */
      vip->t.l2tp.info = NULL;
      break;

    default:
      /* Everything else (and the rest of the cases above) are handled
         at the LAC thread's event handler state. */
      break;
    }

  SSH_FSM_CONDITION_SIGNAL(&vip->t.l2tp.status_cond);
}

/* A callback function that the L2TP module calls when it wants to
   output a data frame to the PPP module of the session. */
static void
ssh_pm_l2tp_lac_data_cb(SshL2tpSessionInfo session, const unsigned char *data,
                        size_t data_len)
{
  SshPmVip vip = (SshPmVip) session->upper_level_data;
  unsigned char *buf;

  if (vip->t.l2tp.ppp == NULL)
    /* No PPP yet.  This should no happen. */
    return;

  buf = ssh_memdup(data, data_len);
  if (buf == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not duplicate PPP frame"));
      return;
    }

  ssh_ppp_frame_input(vip->t.l2tp.ppp, buf, 0, data_len);
}

/* A callback function to get the PPP authentication secret for
   LAC. */
static void
ssh_pm_l2tp_lac_get_secret(SshPPPHandle ppp, SshPppAuthType auth_type,
                           void *user_ctx, void *ppp_ctx,
                           SshUInt8 *name, SshUInt32 namelen)
{
  SshFSMThread thread = (SshFSMThread) user_ctx;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Getting secret for `%.*s'",
                               (int) namelen, name));

  ssh_ppp_return_secret(ppp, ppp_ctx,
                        vip->t.l2tp.user_password,
                        vip->t.l2tp.user_password_len);
}

#ifdef SSHDIST_IKE_EAP_AUTH
static void
ssh_pm_l2tp_lac_get_token(SshPPPHandle ppp, SshPppAuthType auth_type,
                          SshUInt8 eap_type, SshEapTokenType tok_type,
                          void *user_ctx, void *ppp_context,
                          SshUInt8 *name, SshUInt32 namelen)
{
  SshFSMThread thread = (SshFSMThread) user_ctx;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);
  SshEapTokenStruct eap_token;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Getting EAP token for `%.*s'",
                               (int) namelen, name));

  if (tok_type != SSH_EAP_TOKEN_SHARED_SECRET)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Only support for shared secrets in EAP implemented"));
      goto fail;
    }

  if (vip->t.l2tp.user_password == NULL)
    goto fail;

  ssh_eap_init_token_secret(&eap_token,
                            vip->t.l2tp.user_password,
                            vip->t.l2tp.user_password_len);

  ssh_ppp_return_token(ppp,eap_type,ppp_context,&eap_token);

  return;

  /* Error handling. */

 fail:
  ssh_ppp_return_token(ppp, eap_type, ppp_context, NULL);
}
#endif /* SSHDIST_IKE_EAP_AUTH */

/* Signal callback for LAC's PPP instance. */
static void
ssh_pm_l2tp_lac_signal_cb(void *ctx, SshPppSignal signal)
{
  SshFSMThread thread = (SshFSMThread) ctx;
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  vip->t.l2tp.signal = signal;
  vip->t.l2tp.ppp_signal = 1;

  SSH_FSM_CONDITION_SIGNAL(&vip->t.l2tp.status_cond);
}

/* Frame output callback for LAC's PPP instance. */
static void
ssh_pm_l2tp_lac_output_cb(SshPPPHandle ppp, void *ctx, SshUInt8 *buffer,
                          unsigned long offset, unsigned long len)
{
  SshFSMThread thread = (SshFSMThread) ctx;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmVip vip = (SshPmVip) ssh_fsm_get_tdata(thread);

  ssh_l2tp_session_send(pm->l2tp, vip->t.l2tp.info, buffer + offset, len);
  ssh_free(buffer);
}

/* Log a PPP event `event' with the ssh_log_event() to the system
   event log. */
static void
ssh_pm_l2tp_lac_log_ppp_event(SshPmVip vip, const char *event)
{
  ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        vip->t.l2tp.info->tunnel,
                        vip->t.l2tp.info, "failed");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Message: PPP failure");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Reason:  %s", event);
}


/***************** Fetching virtual IP parameters with L2TP *****************/

/* This state starts acquiring an IP address for the virtual IP
   interface and possibly other tunneling attributes. It is entered
   from state `ssh_pm_st_vip_get_attrs' of the generic part of the
   FSM. After attribute retrieval is completed (or failed), the FSM
   should return to the `ssh_pm_st_vip_get_attrs_result' state of the
   generic part. */

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp)
{
  SshPmVip vip = (SshPmVip) thread_context;

  if (vip->tunnel->num_peers == 0)
    {
      /** No L2TP peers. */
      SSH_DEBUG(SSH_D_FAIL, ("Tunnel does not specify any peers"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Try next peer. */
  vip->t.l2tp.peer_index = 0;
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_next_peer);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_next_peer)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshUInt32 ifnum = SSH_INVALID_IFNUM;
  SshInterceptorRouteKeyStruct key;

  if (vip->t.l2tp.peer_index >= vip->tunnel->num_peers)
    {
      /** No more L2TP peers. */
      SSH_DEBUG(SSH_D_FAIL, ("No more peers to try: tried %u",
                             (unsigned int) vip->t.l2tp.peer_index));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_failed);
      return SSH_FSM_CONTINUE;
    }

  /* Does the tunnel specify a local IP address to use?
     Use always the local IP with highest precedence (first in the list). */
  if (vip->tunnel->local_ip != NULL)
    /* Yes.  Let's resolve the interface number by the local IP
       address. */
    (void) ssh_pm_find_interface_by_address(pm, &vip->tunnel->local_ip->ip,
                                            vip->tunnel->routing_instance_id,
                                            &ifnum);

  /* Store the peer IP address. */
  ssh_pm_vip_flush_sgw_routes(vip);
  ssh_pm_vip_create_sgw_route(vip,
                              &vip->tunnel->peers[vip->t.l2tp.peer_index]);

  ssh_pm_create_route_key(pm, &key, vip->tunnel->local_ip ?
                          &vip->tunnel->local_ip->ip : NULL,
                          &vip->tunnel->peers[vip->t.l2tp.peer_index],
                          SSH_IPPROTO_UDP, 0, 0, ifnum,
                          vip->tunnel->routing_instance_id);

  /** Route peer IP address. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_route_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_route(pm->engine, 0,
                                   &key, ssh_pm_l2tp_route_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_route_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  if (!vip->t.l2tp.route_ok)
    {
      /** Try the next peer. */
      vip->t.l2tp.peer_index++;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_next_peer);
      return SSH_FSM_CONTINUE;
    }

  /* The callback selected our local IP address. */
  SSH_ASSERT(SSH_IP_DEFINED(&vip->t.l2tp.local_ip));

  /** Get authentication credentials. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_query_authentication);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_query_authentication)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  /** Query user-name and password. */
  if (pm->la_client_query_cb)
    {
      vip->t.l2tp.operation_id = pm->la_client_next_operation_id++;
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_query_result);
      SSH_FSM_ASYNC_CALL({
        vip->la_auth_operation =
          (*pm->la_client_query_cb)(vip->t.l2tp.operation_id,
                                &vip->tunnel->peers[vip->t.l2tp.peer_index],
                                NULL, 0, NULL, 0,
                                (SSH_PM_LA_L2TP
                                 | SSH_PM_LA_ATTR_USER_NAME
                                 | SSH_PM_LA_ATTR_USER_PASSWORD),
                                0,
                                ssh_pm_l2tp_auth_query_result_cb, thread,
                                pm->la_client_context);
      });
      SSH_NOTREACHED;
    }

  /** No authentication callback set. */
  SSH_DEBUG(SSH_D_FAIL,
            ("No legacy authentication client query callback set"));
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_failed);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_query_result)
{
  SshPmVip vip = (SshPmVip) thread_context;

  if (!vip->t.l2tp.auth_ok)
    {
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            NULL, NULL, "error");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: Could not query authentication information");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Reason:  %s",
                    (vip->t.l2tp.auth_cb_fail
                     ? "Operation canceled"
                     : "Out of memory"));

      /** No authentication. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_failed);
    }
  else
    {
      /** Got authentication. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_start);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_start)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  /* Start a sub-thread (and its synchronization variables) for
     handling the L2TP initiator functionality. */

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting L2TP LAC thread"));

  ssh_fsm_condition_init(&pm->fsm, &vip->t.l2tp.status_cond);

  vip->t.l2tp.tunnel_index = SSH_IPSEC_INVALID_INDEX;
  vip->t.l2tp.sa_rule_index = SSH_IPSEC_INVALID_INDEX;

  vip->t.l2tp.lac_state = SSH_PM_VIP_LAC_CONNECTING;

  ssh_fsm_thread_init(&pm->fsm, &vip->t.l2tp.thread,
                      ssh_pm_st_vip_l2tp_lac_start,
                      NULL_FNPTR, NULL_FNPTR, vip);
  ssh_fsm_set_thread_name(&vip->t.l2tp.thread, "VIP L2TP");

  /** Wait for LAC thread. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_wait_lac);
  SSH_FSM_CONDITION_WAIT(&vip->cond);
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_wait_lac)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshUInt8 l2tp_flags;

  if (vip->t.l2tp.lac_state != SSH_PM_VIP_LAC_CONNECTED)
    {
      if (vip->t.l2tp.lac_state != SSH_PM_VIP_LAC_TERMINATED)
        {
          if (vip->t.l2tp.operation)
            {
              SSH_DEBUG(SSH_D_LOWSTART, ("Aborting LAC operation"));
              ssh_operation_abort(vip->t.l2tp.operation);
              vip->t.l2tp.operation = NULL;
              if (vip->t.l2tp.ppp)
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("Terminating PPP"));
                  ssh_ppp_destroy(vip->t.l2tp.ppp);
                  vip->t.l2tp.ppp = NULL;
                  vip->t.l2tp.status = SSH_L2TP_SESSION_TERMINATED;
                }
              else
                {
                  vip->t.l2tp.status = SSH_L2TP_SESSION_OPEN_FAILED;
                }
              vip->t.l2tp.l2tp_status = 1;
              SSH_FSM_CONDITION_SIGNAL(&vip->t.l2tp.status_cond);
            }
          SSH_FSM_WAIT_THREAD(&vip->t.l2tp.thread);
        }

      SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_failed);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("L2TP session established"));
  SSH_ASSERT(SSH_IP_DEFINED(&vip->attrs.addresses[0]));
  SSH_ASSERT(vip->t.l2tp.trd_index != SSH_IPSEC_INVALID_INDEX);

  /* Update L2TP and PPP attributes to the transform. */

  l2tp_flags = 0;
  if (vip->t.l2tp.output_acfc)
    l2tp_flags |= SSH_ENGINE_L2TP_PPP_ACFC;
  if (vip->t.l2tp.output_pfc)
    l2tp_flags |= SSH_ENGINE_L2TP_PPP_PFC;

  ssh_pme_update_transform_l2tp_info(pm->engine, vip->t.l2tp.trd_index,
                                     l2tp_flags,
                                     vip->t.l2tp.info->tunnel->local_id,
                                     vip->t.l2tp.info->local_id,
                                     vip->t.l2tp.info->tunnel->remote_id,
                                     vip->t.l2tp.info->remote_id);

  /* We got attributes. */
  vip->successful = 1;

  ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        vip->t.l2tp.info->tunnel,
                        vip->t.l2tp.info,
                        "completed");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Configuration data received:");
  ssh_pm_log_remote_access_attributes(SSH_LOGFACILITY_AUTH,
                                      SSH_LOG_INFORMATIONAL,
                                      &vip->attrs);

  /** L2TP session established. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_result);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_failed)
{
  SshPmVip vip = (SshPmVip) thread_context;

  /* Release all L2TP related resources. */

  ssh_free(vip->t.l2tp.user_name);
  vip->t.l2tp.user_name = NULL;

  ssh_free(vip->t.l2tp.user_password);
  vip->t.l2tp.user_password = NULL;

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_l2tp_failed_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_get_attrs_l2tp_failed_done)
{
  /** Try the next method. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_get_attrs_result);
  return SSH_FSM_CONTINUE;
}

/************************* Configuring L2TP tunnel **************************/

/* This state is called by the generic part of the virtual IP FSM to
   create rules for the L2TP tunnel. Return to state
   `ssh_pm_st_vip_setup_tunnel_result' of the generic part. */

SSH_FSM_STEP(ssh_pm_st_vip_setup_tunnel_l2tp)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshIpAddr addr_low, addr_high;
  SshIkev2PayloadTS ts;

  memset(&engine_rule, 0, sizeof(engine_rule));

  /* Make tunnel rule depend on the original trigger rule. This ensures
     that the rule gets deleted when the trigger rule is deleted. */
  engine_rule.depends_on =
    vip->rules->rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT];

  engine_rule.precedence = SSH_PM_SA_PRECEDENCE(vip->rules->rule);

  /* Selectors. */

  addr_low = &vip->attrs.addresses[0];
  addr_high = &vip->attrs.addresses[0];

  SSH_DEBUG(SSH_D_NICETOKNOW, ("L2TP tunnel selectors: low=%@, high=%@",
                               ssh_ipaddr_render, addr_low,
                               ssh_ipaddr_render, addr_high));

  if (SSH_IP_IS4(addr_low))
    {
      engine_rule.protocol = (SshUInt8) SSH_PROTOCOL_IP4;
      SSH_IP4_ENCODE(addr_low, engine_rule.src_ip_low);
      SSH_IP4_ENCODE(addr_high, engine_rule.src_ip_high);
    }
  else
    {
      engine_rule.protocol = (SshUInt8) SSH_PROTOCOL_IP6;
      SSH_IP6_ENCODE(addr_low, engine_rule.src_ip_low);
      SSH_IP6_ENCODE(addr_high, engine_rule.src_ip_high);
    }

  engine_rule.selectors |= SSH_SELECTOR_SRCIP;

  ts = vip->rules->rule->side_to.ts;
  if (ts && ts->number_of_items_used > 0)
    {
      int dummy;
      SSH_IP_ENCODE(ts->items[0].start_address, engine_rule.dst_ip_low, dummy);
      SSH_IP_ENCODE(ts->items[0].end_address, engine_rule.dst_ip_high, dummy);
      engine_rule.selectors |= SSH_SELECTOR_DSTIP;
    }

  /* Rule type. */
  engine_rule.type = SSH_ENGINE_RULE_APPLY;
  engine_rule.transform_index = vip->t.l2tp.trd_index;

  /* Since we are adding a new rule applying the same transform, we
     must lock the new rule (and its transform) by adding an extra
     reference to the rule.  This means that the rule (and its
     transform) will remain in the engine until we explicitly free it
     by calling ssh_pme_delete_rule().  This way initial contact or
     delete notifications won't invalidate our rule index. */
  engine_rule.flags |= SSH_ENGINE_RULE_PM_REFERENCE;

  if (vip->rules->rule->side_from.tunnel)
    engine_rule.tunnel_id = vip->rules->rule->side_from.tunnel->tunnel_id;

  /* Timeout and lifetime values for flows. */
  engine_rule.flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  engine_rule.flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  engine_rule.flow_max_lifetime = 0;
  engine_rule.flags |= SSH_PM_ENGINE_RULE_FORWARD;

  /* No policy context. */

  /** Add L2TP rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_tunnel_l2tp_add_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_l2tp_add_tunnel_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_setup_tunnel_l2tp_add_rule_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  if (vip->t.l2tp.tunnel_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_FAIL, ("L2TP rule creation failed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_tunnel_result);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("L2TP tunnel rule created: index=0x%x",
                               (unsigned int) vip->t.l2tp.tunnel_index));

  /** Take a reference to the IPSec SA rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_setup_tunnel_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_reference_to_rule(pm->engine,
                                                   vip->t.l2tp.sa_rule_index,
                                                   vip->t.l2tp.trd_index,
                                                   ssh_pm_l2tp_lock_sa_rule_cb,
                                                   thread));
  SSH_NOTREACHED;
}


/************************* Shutting down L2TP session ************************/

/* This state is called by the generic part of the virtual IP FSM to
   terminate the L2TP session. Return to state
   `ssh_pm_st_vip_shutdown_session_result' of the generic part. This state
   machine signals the PPP library to halt and frees dynamically allocated
   username and password from VIP L2TP context. */

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_session_l2tp)
{
  SshPmVip vip = (SshPmVip) thread_context;

  if (vip->t.l2tp.lac_state == SSH_PM_VIP_LAC_CONNECTING)
    {
      /* The LAC is still connecting.  Let's wait until it is
         connected. */
      SSH_FSM_CONDITION_WAIT(&vip->cond);
    }

  if (vip->t.l2tp.lac_state == SSH_PM_VIP_LAC_CONNECTED)
    {
      /* The tunnel is destroying but LAC is still at the connected
         state.  This means that the policy manager shutting down or
         our virtual IP rule has gone away.  Halt the PPP
         connection. */
      if (vip->t.l2tp.ppp && !vip->t.l2tp.ppp_halt)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Signalling PPP to halt"));
          ssh_ppp_halt(vip->t.l2tp.ppp);
          vip->t.l2tp.ppp_halt = 1;
        }

      /* Wait for PPP (and L2TP) to terminate. */
      SSH_FSM_CONDITION_WAIT(&vip->cond);
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_session_l2tp_finish);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_session_l2tp_finish)
{
  SshPmVip vip = (SshPmVip) thread_context;

  /** Cleanup all remaining resources. */
  ssh_free(vip->t.l2tp.user_name);
  ssh_free(vip->t.l2tp.user_password);

  /** L2TP session shutdown complete. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_session_result);
  return SSH_FSM_CONTINUE;
}

/************************* Cleaning up L2TP tunnel **************************/

/* This state is called by the generic part of the virtual IP FSM to do
   final L2TP cleantup. Return to state `ssh_pm_st_vip_shutdown_complete'
   of the generic part. This state machine deletes the L2TP rules. Note that
   no delete notifications are sent for IPsec SAs that are deleted due to
   the rule removal. In normal shutdown and reconfigure cases the delete
   notifications are sent elsewhere and this code does not need to worry
   about them. */

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_cleanup_l2tp)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  if (vip->t.l2tp.tunnel_index != SSH_IPSEC_INVALID_INDEX)
    {
      /** Delete L2TP tunnel rule. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying L2TP tunnel rule %u",
                                   (unsigned int) vip->t.l2tp.tunnel_index));
      SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine,
                                             vip->t.l2tp.tunnel_index,
                                             ssh_pm_l2tp_delete_tunnel_rule_cb,
                                             thread));
      SSH_NOTREACHED;
    }

  /** Delete L2TP SA rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_cleanup_l2tp_delete_sa_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_cleanup_l2tp_delete_sa_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  if (vip->t.l2tp.sa_rule_index != SSH_IPSEC_INVALID_INDEX
      && vip->t.l2tp.ref_to_sa_rule)
    {
      /** Delete L2TP SA rule. */
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying reference to L2TP SA rule %u",
                                   (unsigned int) vip->t.l2tp.sa_rule_index));
      SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine,
                                             vip->t.l2tp.sa_rule_index,
                                             ssh_pm_l2tp_delete_sa_rule_cb,
                                             thread));
      SSH_NOTREACHED;
    }

  /** L2TP SA rule deleted. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_cleanup_l2tp_finish);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_shutdown_cleanup_l2tp_finish)
{
  /** L2TP tunnel cleanup complete. */
  SSH_DEBUG(SSH_D_LOWOK, ("L2TP cleanup complete"));
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_shutdown_complete);
  return SSH_FSM_CONTINUE;
}

/****************************** LAC sub-thread ******************************/

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_start)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  unsigned char addr[SSH_IP_ADDR_STRING_SIZE];
  unsigned char port[64];
  SshPmServer server;

  SSH_DEBUG(SSH_D_LOWSTART, ("Initiating L2TP LAC incoming call to `%@:%d'",
                             ssh_ipaddr_render,
                             &vip->tunnel->peers[vip->t.l2tp.peer_index],
                             SSH_IPSEC_L2TP_PORT));
  ssh_ipaddr_print(&vip->tunnel->peers[vip->t.l2tp.peer_index],
                   addr, sizeof(addr));
  ssh_snprintf(ssh_sstr(port), sizeof(port), "%d", SSH_IPSEC_L2TP_PORT);

  /* Select L2TP server to use. */
  server = ssh_pm_servers_select(pm, &vip->t.l2tp.local_ip, 0, NULL,
                                 0, vip->tunnel->routing_instance_id);
  if (server == NULL || server->l2tp_server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No L2TP server running on local IP address `%@'",
                             ssh_ipaddr_render, &vip->t.l2tp.local_ip));

      /** No L2TP server running. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Mark the statuses invalid. */
  vip->t.l2tp.l2tp_status = 0;
  vip->t.l2tp.ppp_signal = 0;

  /* Start LAC incoming call. */
  vip->t.l2tp.operation =
    ssh_l2tp_lac_session_open(pm->l2tp, server->l2tp_server,
                              0, addr, port,
                              NULL, 0, NULL,
                              ssh_pm_l2tp_lac_session_status_cb,
                              thread);

  /* And wait for a status notification. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_wait_open);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_wait_open)
{
  SshPmVip vip = (SshPmVip) thread_context;

  if (!vip->t.l2tp.l2tp_status)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for session opening"));
      SSH_FSM_CONDITION_WAIT(&vip->t.l2tp.status_cond);
    }
  vip->t.l2tp.l2tp_status = 0;

  switch (vip->t.l2tp.status)
    {
    case SSH_L2TP_SESSION_OPEN_FAILED:
      SSH_DEBUG(SSH_D_FAIL, ("Could not open LAC session"));
      break;

    case SSH_L2TP_SESSION_OPENED:
      SSH_DEBUG(SSH_D_LOWOK, ("LAC session opened"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_lookup_sa);
      return SSH_FSM_CONTINUE;
      break;

    default:
      SSH_DEBUG(SSH_D_UNCOMMON, ("Received unexpected status %d",
                                 vip->t.l2tp.status));
      break;
    }

  /* The LAC opeation failed. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_lookup_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;
  SshIpAddrStruct src, dst;
  SshUInt16 src_port, dst_port;

  /* Lookup IPSec SA protecting L2TP traffic. */

  SSH_VERIFY(ssh_ipaddr_parse(&src, vip->t.l2tp.info->tunnel->local_addr));
  SSH_VERIFY(ssh_ipaddr_parse(&dst, vip->t.l2tp.info->tunnel->remote_addr));
  src_port = ssh_uatoi(vip->t.l2tp.info->tunnel->local_port);
  dst_port = ssh_uatoi(vip->t.l2tp.info->tunnel->remote_port);

  SSH_DEBUG(SSH_D_LOWSTART, ("Looking up IPSec SA for the L2TP tunnel: "
                             "local=%@.%d, remote=%@.%d",
                             ssh_ipaddr_render, &src,
                             src_port,
                             ssh_ipaddr_render, &dst,
                             dst_port));

  /** Lookup IPSec SA. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_lookup_sa_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_find_transform_rule(
                pm->engine,
                0, vip->t.l2tp.local_ifnum,
                &src, &dst,
                SSH_IPPROTO_UDP,
                src_port, dst_port,
                0,
                vip->t.l2tp.info->tunnel->attributes.ssh_transform_index,
                (SSH_PME_TRANSFORM_PER_PORT_SRC
                 | SSH_PME_MATCH_INACTIVE_RULES),
                ssh_pm_l2tp_lac_find_transform_rule_cb,
                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_lookup_sa_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  if (vip->t.l2tp.trd_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** No IPSec SA found. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not find IPSec SA for L2TP tunnel"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Transform %u protects L2TP tunnel",
                               (unsigned int) vip->t.l2tp.trd_index));

  /* Update L2TP session information in the transform.  First we
     update only L2TP attributes.  Later when the PPP negotiation is
     complete, we will update PPP attributes. */

  ssh_pme_update_transform_l2tp_info(pm->engine, vip->t.l2tp.trd_index,
                                     (SSH_ENGINE_L2TP_PPP_ACFC
                                      | SSH_ENGINE_L2TP_PPP_PFC),
                                     vip->t.l2tp.info->tunnel->local_id,
                                     vip->t.l2tp.info->local_id,
                                     vip->t.l2tp.info->tunnel->remote_id,
                                     vip->t.l2tp.info->remote_id);
  /** Start PPP. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_start_ppp);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_start_ppp)
{
  SshPmVip vip = (SshPmVip) thread_context;
  SshPppParamsStruct ppp;

  /* Bind our virtual IP thread into the newly opened L2TP session. */
  SSH_ASSERT(vip->t.l2tp.info != NULL);
  vip->t.l2tp.info->upper_level_data = vip;
  vip->t.l2tp.info->data_cb = ssh_pm_l2tp_lac_data_cb;

  /* Initialize a PPP instance. */

  memset(&ppp, 0, sizeof(ppp));

  ppp.ctx = thread;

  ppp.mschapv2_client = 1;
  ppp.mschapv1_client = 1;

  ppp.pap_client = 1;
  ppp.chap_client = 1;

  ppp.ipcp = 1;

  ppp.frame_mode = SSH_PPP_MODE_L2TP;

  ppp.name = vip->t.l2tp.user_name;
  ppp.namelen = vip->t.l2tp.user_name_len;

  ppp.get_client_secret_cb = ssh_pm_l2tp_lac_get_secret;
#ifdef SSHDIST_IKE_EAP_AUTH
  ppp.get_client_eap_token_cb = ssh_pm_l2tp_lac_get_token;
#endif /* SSHDIST_IKE_EAP_AUTH */
  ppp.signal_cb = ssh_pm_l2tp_lac_signal_cb;
  ppp.output_frame_cb = ssh_pm_l2tp_lac_output_cb;

  /* Define client address, otherwise the PPP lib does not send a
     proper IP-Address configure request. */
  ssh_ipaddr_parse(&ppp.own_ipv4_addr, "0.0.0.0");

  /* Request DNS addresses. */
  ssh_ipaddr_parse(&ppp.own_dns_primary, "0.0.0.0");
  ssh_ipaddr_parse(&ppp.own_dns_secondary, "0.0.0.0");

  vip->t.l2tp.ppp = ssh_ppp_session_create(&ppp);
  if (vip->t.l2tp.ppp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not create PPP session"));
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
    }
  else
    {
      /* PPP session created.  Now, start the PPP negotiation. */
      ssh_ppp_boot(vip->t.l2tp.ppp);

      /* Wait for PPP. */
      SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_wait_events);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_wait_events)
{
  SshPmVip vip = (SshPmVip) thread_context;

  /* Wait until something interesting happens. */
  if (!vip->t.l2tp.l2tp_status && !vip->t.l2tp.ppp_signal)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for L2TP and PPP events"));
      SSH_FSM_CONDITION_WAIT(&vip->t.l2tp.status_cond);
    }
  if (vip->t.l2tp.l2tp_status)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("L2TP session status %d", vip->t.l2tp.status));

      switch (vip->t.l2tp.status)
        {
        case SSH_L2TP_SESSION_OPEN_FAILED:
        case SSH_L2TP_SESSION_OPENED:
          SSH_NOTREACHED;
          break;

        case SSH_L2TP_SESSION_TERMINATED:
          SSH_DEBUG(SSH_D_LOWOK, ("L2TP session terminated"));
          SSH_ASSERT(vip->t.l2tp.ppp == NULL);

          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_terminate);
          return SSH_FSM_CONTINUE;
          break;

        case SSH_L2TP_SESSION_WAN_ERROR_NOTIFY:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("WAN error notify"));
          break;

        case SSH_L2TP_SESSION_SET_LINK_INFO:
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Set link info: send=0x%lx, receive=0x%lx",
                     vip->t.l2tp.info->accm.send_accm,
                     vip->t.l2tp.info->accm.receive_accm));
          break;
        }

      /* Event handled. */
      vip->t.l2tp.l2tp_status = 0;
    }

  if (vip->t.l2tp.ppp_signal)
    {
      Boolean input_acfc;
      Boolean input_pfc;
      SshUInt16 input_mru;
      SshUInt16 output_mru;
      SshL2tpAccmStruct accm;

      SSH_DEBUG(SSH_D_LOWOK, ("PPP signal %d", vip->t.l2tp.signal));

      switch (vip->t.l2tp.signal)
        {
        case SSH_PPP_SIGNAL_LCP_UP:
          /* Address control field compression. */
          input_acfc = ssh_ppp_get_lcp_input_acfc(vip->t.l2tp.ppp);
          vip->t.l2tp.output_acfc
            = ssh_ppp_get_lcp_output_acfc(vip->t.l2tp.ppp) ? 1 : 0;

          /* Protocol field compression. */
          input_pfc = ssh_ppp_get_lcp_input_pfc(vip->t.l2tp.ppp);
          vip->t.l2tp.output_pfc
            = ssh_ppp_get_lcp_output_pfc(vip->t.l2tp.ppp) ? 1 : 0;

          /* MRU. */
          input_mru = (SshUInt16) ssh_ppp_get_lcp_input_mru(vip->t.l2tp.ppp);
          output_mru = (SshUInt16) ssh_ppp_get_lcp_output_mru(vip->t.l2tp.ppp);

          /* Asynchronous control character map. */
          accm.receive_accm = ssh_ppp_get_lcp_input_accm(vip->t.l2tp.ppp);
          accm.send_accm = ssh_ppp_get_lcp_output_accm(vip->t.l2tp.ppp);

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("LCP up: "
                     "input[acfc=%d, pfc=%d, mru=%d, accm=0x%08lx], "
                     "output[acfc=%d, pfc=%d, mru=%d, accm=0x%08lx]",
                     input_acfc, input_pfc, input_mru,
                     (unsigned long) accm.receive_accm,
                     vip->t.l2tp.output_acfc, vip->t.l2tp.output_pfc,
                     output_mru, (unsigned long) accm.send_accm));
          break;

        case SSH_PPP_SIGNAL_LCP_DOWN:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_LCP_DOWN"));
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
          break;

        case SSH_PPP_SIGNAL_IPCP_UP:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_IPCP_UP"));

          /* Fetch all interesting attributes. */
          vip->attrs.num_addresses = 1;
          ssh_ppp_get_ipcp_own_ip(vip->t.l2tp.ppp, &vip->attrs.addresses[0]);
          ssh_ppp_get_ipcp_peer_ip(vip->t.l2tp.ppp, &vip->u.l2tp.peer_address);

          ssh_ppp_get_ipcp_own_dns_primary(
                                        vip->t.l2tp.ppp,
                                        &vip->attrs.dns[vip->attrs.num_dns]);
          if (SSH_IP_DEFINED(&vip->attrs.dns[vip->attrs.num_dns]))
            vip->attrs.num_dns++;
          ssh_ppp_get_ipcp_own_dns_secondary(
                                        vip->t.l2tp.ppp,
                                        &vip->attrs.dns[vip->attrs.num_dns]);
          if (SSH_IP_DEFINED(&vip->attrs.dns[vip->attrs.num_dns]))
            vip->attrs.num_dns++;

          ssh_ppp_get_ipcp_own_nbns_primary(
                                        vip->t.l2tp.ppp,
                                        &vip->attrs.wins[vip->attrs.num_wins]);
          if (SSH_IP_DEFINED(&vip->attrs.wins[vip->attrs.num_wins]))
            vip->attrs.num_wins++;
          ssh_ppp_get_ipcp_own_nbns_secondary(
                                        vip->t.l2tp.ppp,
                                        &vip->attrs.wins[vip->attrs.num_wins]);
          if (SSH_IP_DEFINED(&vip->attrs.wins[vip->attrs.num_wins]))
            vip->attrs.num_wins++;

          /* Check if our IP address was really negotiated. */
          if (!SSH_IP_DEFINED(&vip->attrs.addresses[0]))
            {
              /* The address was not negotiated. */
              SSH_DEBUG(SSH_D_FAIL, ("No LAC IP address negotiated"));
              SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
            }
          else
            {
              /* Got the address. */
              vip->t.l2tp.lac_state = SSH_PM_VIP_LAC_CONNECTED;
              SSH_FSM_CONDITION_SIGNAL(&vip->cond);
            }
          break;

        case SSH_PPP_SIGNAL_IPCP_DOWN:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_IPCP_DOWN"));
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
          break;

        case SSH_PPP_SIGNAL_IPCP_FAIL:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_IPCP_FAIL"));
          ssh_pm_l2tp_lac_log_ppp_event(vip, "IPCP failed");
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
          break;

        case SSH_PPP_SIGNAL_FATAL_ERROR:
          SSH_DEBUG(SSH_D_ERROR, ("SSH_PPP_SIGNAL_FATAL_ERROR"));
          ssh_pm_l2tp_lac_log_ppp_event(vip, "Fatal error");
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
          break;

        case SSH_PPP_SIGNAL_PPP_HALT:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_PPP_HALT"));
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
          break;

        case SSH_PPP_SIGNAL_SERVER_AUTH_FAIL:
        case SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL:
          SSH_DEBUG(SSH_D_FAIL, ("Authentication failed"));
          ssh_pm_l2tp_lac_log_ppp_event(vip, "Authentication failed");
          SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_close_session);
          break;

        case SSH_PPP_SIGNAL_SERVER_AUTH_OK:
        case SSH_PPP_SIGNAL_CLIENT_AUTH_OK:
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Authentication OK"));
          break;
        }

      /* Signal handled. */
      vip->t.l2tp.ppp_signal = 0;
    }

  /* And continue from the next state. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_close_session)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmVip vip = (SshPmVip) thread_context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Closing L2TP session"));

  if (vip->t.l2tp.ppp)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Destroying PPP instance 0x%p",
                                 vip->t.l2tp.ppp));
      ssh_ppp_destroy(vip->t.l2tp.ppp);
      vip->t.l2tp.ppp = NULL;
    }

  SSH_ASSERT(vip->t.l2tp.info != NULL);
  /* Actually, we close the L2TP tunnel.  It closes the session too
     but this way we get the control connection closed nicely. */
  ssh_l2tp_tunnel_destroy(pm->l2tp, vip->t.l2tp.info->tunnel->local_id);

  /* Wait until the L2TP session has been terminated. */
  SSH_FSM_SET_NEXT(ssh_pm_st_vip_l2tp_lac_wait_events);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_vip_l2tp_lac_terminate)
{
  SshPmVip vip = (SshPmVip) thread_context;

  /* Notify the virtual IP thread about our termination. */
  vip->t.l2tp.lac_state = SSH_PM_VIP_LAC_TERMINATED;
  SSH_FSM_CONDITION_SIGNAL(&vip->cond);

  SSH_DEBUG(SSH_D_LOWOK, ("LAC sub-thread terminating"));

  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
