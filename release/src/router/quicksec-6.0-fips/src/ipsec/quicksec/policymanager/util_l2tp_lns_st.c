/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   L2TP LNS.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP

#define SSH_DEBUG_MODULE "SshPmStL2tp"

/************************** Static help functions ***************************/

/* A callback function that is called to complete a route operation
   for the L2TP tunnel's remote peer. */
static void
ssh_pm_l2tp_lns_route_cb(SshPm pm, SshUInt32 flags, SshUInt32 ifnum,
                         const SshIpAddr next_hop, size_t mtu, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);

  /* As a default we fail since this is the most common case below. */
  t->n->route_ok = 0;

  if ((flags & SSH_PME_ROUTE_REACHABLE) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Destination `%s' is unreachable",
                                   t->n->info->remote_addr));
    }
  else if (flags & SSH_PME_ROUTE_LOCAL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Destination `%s' is our local address",
                                   t->n->info->remote_addr));
    }
  else if (flags & SSH_PME_ROUTE_LINKBROADCAST)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%s' is a link-local broadcast address",
                 t->n->info->remote_addr));
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Destination `%s' is reachable using interface %d",
                 t->n->info->remote_addr, (int) ifnum));
      t->n->route_ok = 1;
      t->local_ifnum = ifnum;
    }

  /* The next state is already set by the caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to complete a transform rule
   lookup. */
static void
ssh_pm_l2tp_lns_transform_cb(SshPm pm, const SshEnginePolicyRule rule,
                             SshUInt32 transform_index, SshUInt32 outbound_spi,
                             void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);

  if (rule != NULL)
    {
      t->sa_rule_index = rule->rule_index;
      t->trd_index = rule->transform_index;
      t->dst_nat_port = rule->nat_dst_port;
    }
  else
    {
      t->sa_rule_index = SSH_IPSEC_INVALID_INDEX;
      t->trd_index = SSH_IPSEC_INVALID_INDEX;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to complete an engine rule get
   operation. */
static void
ssh_pm_l2tp_lns_get_rule_cb(SshPm pm, const SshEnginePolicyRule rule,
                            void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);

  if (rule)
    {
      if (rule->policy_context == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Get rule returns non-master rule"));
        }
      else
        {
          SshPmRule pm_rule = (SshPmRule) rule->policy_context;
          SshPmTunnel tunnel, rev_tunnel;

          /* Get the tunnel. */
          if (rule->flags & SSH_PM_ENGINE_RULE_FORWARD)
            {
              tunnel = pm_rule->side_to.tunnel;
              rev_tunnel = pm_rule->side_from.tunnel;
            }
          else
            {
              tunnel = pm_rule->side_from.tunnel;
              rev_tunnel = pm_rule->side_to.tunnel;
            }

          if (tunnel == NULL || (tunnel->flags & SSH_PM_TR_ALLOW_L2TP) == 0)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("L2TP not allowed"));
            }
          else
            {
              /* All ok. */
              t->n->get_rule_ok = 1;

              /* Check whether we should do proxy ARP for our clients
                 in the private network. */
              if (tunnel->flags & SSH_PM_TR_PROXY_ARP)
                t->proxy_arp = 1;

              SSH_ASSERT(pm_rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT]
                         != SSH_IPSEC_INVALID_INDEX);
              t->l2tp_rule_index
                = pm_rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT];

              t->outbound_rule_precedence = SSH_PM_SA_PRECEDENCE(pm_rule);

              /* The index of the reverse tunnel. */
              if (rev_tunnel)
                t->reverse_tunnel_id = rev_tunnel->tunnel_id;
              t->rule = pm_rule;

              t->tunnel = tunnel;
#ifdef SSHDIST_IPSEC_NAT
              if (rule->flags & SSH_ENGINE_RULE_FORCE_NAT_DST)
                {
                  t->dst_nat_ip_low = rule->nat_dst_ip_low;
                  t->dst_nat_ip_high = rule->nat_dst_ip_high;
                  if (t->dst_nat_port == 0)
                  t->dst_nat_port = rule->nat_dst_port;
                  t->dst_nat_flags = rule->nat_flags;
                }
              else
                {
                  SSH_IP_UNDEFINE(&t->dst_nat_ip_low);
                  SSH_IP_UNDEFINE(&t->dst_nat_ip_high);
                }

              t->dst_nat_selector_ip = rule->nat_selector_dst_ip;
              t->dst_nat_selector_port = rule->nat_selector_dst_port;
#endif /* SSHDIST_IPSEC_NAT */

              SSH_DEBUG(SSH_D_LOWOK,
                        ("L2TP session allowed: outbound_rule_precedence=%u",
                         (unsigned int) t->outbound_rule_precedence));
            }
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("No IPSec SA rule found"));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function completing L2TP control traffic engine rule
   addition. */
static void
ssh_pm_l2tp_lns_add_l2tp_control_rule_cb(SshPm pm, SshUInt32 ind,
                                         const SshEnginePolicyRule rule,
                                         void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);

  t->control_rule_index = ind;
  t->n->l2tp_rule_ok = (ind != SSH_IPSEC_INVALID_INDEX);

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function completing engine rule addition. */
static void
ssh_pm_l2tp_lns_add_rule_cb(SshPm pm, SshUInt32 ind,
                            const SshEnginePolicyRule rule,
                            void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);

  s->outbound_rule_index = ind;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function to complete an IPSec rule deletion from the
   engine. */
static void
ssh_pm_l2tp_lns_delete_outbound_rule_cb(SshPm pm, Boolean done,
                                        SshUInt32 rule_index,
                                        SshUInt32 peer_handle,
                                        SshEngineTransform tr,
                                        void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);

  if (done)
    s->outbound_rule_index = SSH_IPSEC_INVALID_INDEX;

  /* Continue.  The next state is already set by our caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function to complete the L2TP SA rule deletion from the
   engine. */
static void
ssh_pm_l2tp_lns_delete_sa_rule_cb(SshPm pm, Boolean done,
                                  SshUInt32 rule_index,
                                  SshUInt32 peer_handle,
                                  SshEngineTransform tr,
                                  void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);
  SshUInt32 inbound_spi[2];
  int num_spis;
  SshUInt8 ipproto;
#ifdef DEBUG_LIGHT
  int i;
#endif /* DEBUG_LIGHT */

  if (done)
    t->sa_rule_index = SSH_IPSEC_INVALID_INDEX;

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
      SSH_ASSERT(t->tunnel != NULL);
#ifdef DEBUG_LIGHT
      for (i = 0; i < num_spis; i++)
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Sending delete notification for SPI %@-%08lx",
                     ssh_ipproto_render, (SshUInt32) ipproto,
                     (unsigned long) inbound_spi[i]));
        }
#endif /* DEBUG_LIGHT */

      ssh_pm_send_ipsec_delete_notification(pm, peer_handle, t->tunnel,
                                            t->rule, ipproto, num_spis,
                                            inbound_spi);
    }

 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function to complete an outbound rule deletion from the
   engine. */
static void
ssh_pm_l2tp_lns_delete_control_rule_cb(SshPm pm, Boolean done,
                                       SshUInt32 rule_index,
                                       SshUInt32 peer_handle,
                                       SshEngineTransform tr,
                                       void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);

  if (done)
    t->control_rule_index = SSH_IPSEC_INVALID_INDEX;

  /* Continue.  The next state is already set by our caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function completing engine ARP addition. */
static void
ssh_pm_l2tp_lns_add_arp_cb(SshPm pm, Boolean success, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);

  if (success)
    s->arp_ok = 1;
  else
    s->arp_ok = 0;

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is passed as
   SshPmRemoteAccessAttrsAllocResultCB for the attribute allocation
   function. */
static void
ssh_pm_lns_attribute_cb(SshPmRemoteAccessAttrs attributes, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);
  SshUInt32 i;
  SshPmLnsTunnel t = (SshPmLnsTunnel) s->info->tunnel->upper_level_data;

  /* Mark alloc operation completed. */
  s->sub_operation = NULL;

  if (attributes)
    {
      /* Store all interesting attributes into PPP parameters. */

      /* Peer IP address. */
      if (SSH_IP_IS4(&attributes->addresses[0]))
        s->ppp_params->peer_ipv4_addr = attributes->addresses[0];

      /* Save the dynamically allocated address so we can free it
         later when it is not used anymore. */
      s->dynamic_lac_ip = attributes->addresses[0];
      s->dynamic_lac_ip_context = attributes->address_context;
      s->dynamic_lac_ip_tunnel_id = t->tunnel->tunnel_id;
      SSH_ASSERT(s->dynamic_lac_ip_tunnel_id != 0);

      /* Free the other remote access addresses. */
      if (t->tunnel->u.ike.remote_access_free_cb != NULL_FNPTR)
        {
          for (i = 1; i < attributes->num_addresses; i++)
            {
              (*t->tunnel->u.ike.remote_access_free_cb)
                (pm, &attributes->addresses[i], attributes->address_context,
                 t->tunnel->u.ike.remote_access_cb_context);
            }
        }

      /* Own IP address. */
      if (SSH_IP_IS4(&attributes->own_address))
        s->ppp_params->own_ipv4_addr = attributes->own_address;

      /* Name servers. */

      if (SSH_IP_DEFINED(&attributes->dns[0]))
        s->ppp_params->peer_dns_primary = attributes->dns[0];
      if (SSH_IP_DEFINED(&attributes->dns[1]))
        s->ppp_params->peer_dns_secondary = attributes->dns[1];

      if (SSH_IP_DEFINED(&attributes->wins[0]))
        s->ppp_params->peer_nbns_primary = attributes->wins[0];
      if (SSH_IP_DEFINED(&attributes->wins[1]))
        s->ppp_params->peer_nbns_secondary = attributes->wins[1];
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate remote access attributes"));
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* The completion callback of type SshPmPasswdAuthResultCB for the
   SshPmPasswdAuthCB function. */
static void
ssh_pm_l2tp_lns_get_passwd_cb(const unsigned char *user_password,
                              size_t user_password_len,
                              void *context)
{
  SshPmLnsSession s = (SshPmLnsSession) context;

  if (user_password)
    {
      /* Cache password. */
      s->user_password = ssh_memdup(user_password, user_password_len);
      if (s->user_password == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not cache user password"));
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Received password from callback"));
          s->user_password_len = user_password_len;
        }
    }

  /* And return the value; either NULL to indicate an error or the
     cache password. */
#ifdef SSHDIST_IKE_EAP_AUTH
  if (s->auth_type == SSH_PPP_AUTH_EAP
      || s->auth_type == SSH_PPP_AUTH_EAP_ID)
    {
      SshEapTokenStruct eap_token;

      ssh_eap_init_token_secret(&eap_token,
                                s->user_password,
                                (unsigned long)s->user_password_len);
      ssh_ppp_return_token(s->ppp,s->ppp_eap_type,s->ppp_get_secret_context,
                           &eap_token);
      return;
    }
#endif /* SSHDIST_IKE_EAP_AUTH */

  ssh_ppp_return_secret(s->ppp, s->ppp_get_secret_context,
                        s->user_password,
                        (SshUInt32)s->user_password_len);
}

static Boolean
ssh_pm_l2tp_lns_fetch_secret(SshPm pm, SshPmLnsSession s,
                             SshPppAuthType auth_type,
                             SshUInt8 eap_type,
                             void *ppp_context,
                             SshUInt8 *name, SshUInt32 namelen)
{
  /* Clear possible old cache values. */

  ssh_free(s->user_name);
  s->user_name = NULL;
  s->user_name_len = 0;

  ssh_free(s->user_password);
  s->user_password = NULL;
  s->user_password_len = 0;

  /* Cache the name. */
  s->user_name = ssh_memdup(name, namelen);
  if (s->user_name == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not cache user name"));
      goto error;
    }
  s->user_name_len = namelen;

  /* Do we have a password authentication callback. */
  if (pm->passwd_auth_callback)
    {
      /* Yes we have.  Let's call it. */
      s->auth_type = auth_type;
      s->ppp_get_secret_context = ppp_context;
#ifdef SSHDIST_IKE_EAP_AUTH
      s->ppp_eap_type = eap_type;
#endif /* SSHDIST_IKE_EAP_AUTH */
      (*pm->passwd_auth_callback)(s->user_name, s->user_name_len,
                                  ssh_pm_l2tp_lns_get_passwd_cb, s,
                                  pm->passwd_auth_callback_context);
      return TRUE;
    }

  /* No callback set. */
  SSH_DEBUG(SSH_D_FAIL, ("No password authentication callback set"));
 error:
  return FALSE;
}

#ifdef SSHDIST_IKE_EAP_AUTH
/* A callback function to get EAP authentication tokens. */
static void
ssh_pm_l2tp_lns_get_token(SshPPPHandle ppp, SshPppAuthType auth_type,
                          SshUInt8 eap_type, SshEapTokenType tok_type,
                          void *context, void *ppp_context,
                          SshUInt8 *name, SshUInt32 namelen)
{
  SshFSMThread thread = (SshFSMThread)context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_LOWSTART, ("Looking up EAP token for '%.*s'",
                             (int)namelen,name));

  if (tok_type != SSH_EAP_TOKEN_SHARED_SECRET)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Only support for EAP shared secrets implemented"));
      goto fail;
    }

  /* Cache the authentication type for logging */
  s->ppp_auth_type = auth_type;

  if (s->user_name_len == namelen && memcmp(name,s->user_name,namelen) == 0)
    {
      SshEapTokenStruct eap_token;

      ssh_eap_init_token_secret(&eap_token,
                                s->user_password,
                                (unsigned long)s->user_password_len);
      ssh_ppp_return_token(ppp, eap_type, ppp_context, &eap_token);
      return;
    }

  /* If setup of async passwd fetch failed, fail authentication */

  if (ssh_pm_l2tp_lns_fetch_secret(pm,s,auth_type,
                                   eap_type,
                                   ppp_context,name,namelen) == TRUE)
    return;

 fail:
  ssh_ppp_return_token(ppp,eap_type,ppp_context,NULL);
}
#endif /* SSHDIST_IKE_EAP_AUTH */

/* A callback function to get the PPP authentication secret. */
static void
ssh_pm_l2tp_lns_get_secret(SshPPPHandle ppp, SshPppAuthType auth_type,
                           void *context, void *ppp_context,
                           SshUInt8 *name, SshUInt32 namelen)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);

  SSH_DEBUG(SSH_D_LOWSTART, ("Looking up secret for `%.*s': auth_type=%d",
                             (int) namelen, name,
                             auth_type));

  /* Store the used authentication type. */
  s->ppp_auth_type = auth_type;

  /* Do we already have password for the user? */
  if (s->user_name_len == namelen && memcmp(name, s->user_name, namelen) == 0)
    {
      /* Yes, we have a valid password. */
      SSH_DEBUG(SSH_D_LOWOK, ("Returning cached password"));
      ssh_ppp_return_secret(ppp, ppp_context, s->user_password,
                            (SshUInt32)s->user_password_len);
      return;
    }

  if (ssh_pm_l2tp_lns_fetch_secret(pm, s, auth_type, 0,
                                   ppp_context, name, namelen) == FALSE)
    ssh_ppp_return_secret(ppp, ppp_context, NULL, 0);
}

/* Close the L2TP LNS session `session'.  This destroys the session's
   PPP and L2TP session.  Later, when the session is shut down, the
   final session object termination will be handled via the L2TP
   session's info callback.  The optional argument `message' specifies
   the reason why the session is closed.  If the `message' is set, the
   function will log an event with the ssh_log_event() describing the
   session termination. */
static void
ssh_pm_l2tp_lns_close_session(SshPm pm, SshPmLnsSession s, const char *message)
{
  if (s->ppp)
    {
      ssh_ppp_destroy(s->ppp);
      s->ppp = NULL;
    }

  SSH_ASSERT(s->info != NULL);

  if (message)
    {
      /* Log the session termination. */
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            s->info->tunnel, s->info, "failed");
      if (s->user_name)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "  User-name: %.*s",
                        (int) s->user_name_len, s->user_name);
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        "");
        }

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: PPP failure");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Reason:  %s", message);
    }

  ssh_l2tp_session_close(pm->l2tp,
                         s->info->tunnel->local_id,
                         s->info->local_id,
                         SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE,
                         0, NULL, 0, 0, 0, NULL, 0);
}

/* Signal callback for LNS' PPP instance. */
static void
ssh_pm_l2tp_lns_signal_cb(void *ctx, SshPppSignal signal)
{
  SshFSMThread thread = (SshFSMThread) ctx;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);
  Boolean input_acfc;
  Boolean input_pfc;
  SshUInt16 input_mru;
  SshUInt16 output_mru;
  SshL2tpAccmStruct accm;

  if (s->terminated)
    /* The session is already terminated. */
    return;

  switch (signal)
    {
    case SSH_PPP_SIGNAL_LCP_UP:
      /* Address control field compression. */
      input_acfc = ssh_ppp_get_lcp_input_acfc(s->ppp);
      s->output_acfc = ssh_ppp_get_lcp_output_acfc(s->ppp) ? 1 : 0;

      /* Protocol field compression. */
      input_pfc = ssh_ppp_get_lcp_input_pfc(s->ppp);
      s->output_pfc = ssh_ppp_get_lcp_output_pfc(s->ppp) ? 1 : 0;

      /* MRU. */
      input_mru = (SshUInt16) ssh_ppp_get_lcp_input_mru(s->ppp);
      output_mru = (SshUInt16) ssh_ppp_get_lcp_output_mru(s->ppp);

      /* Asynchronous control character map. */
      accm.receive_accm = ssh_ppp_get_lcp_input_accm(s->ppp);
      accm.send_accm = ssh_ppp_get_lcp_output_accm(s->ppp);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("LCP up: "
                 "input[acfc=%d, pfc=%d, mru=%d, accm=0x%08lx], "
                 "output[acfc=%d, pfc=%d, mru=%d, accm=0x%08lx]",
                 input_acfc, input_pfc, input_mru,
                 (unsigned long) accm.receive_accm,
                 s->output_acfc, s->output_pfc, output_mru,
                 (unsigned long) accm.send_accm));

      ssh_l2tp_lns_set_link_info(pm->l2tp,
                                 s->info->tunnel->local_id,
                                 s->info->local_id,
                                 &accm);
      break;

    case SSH_PPP_SIGNAL_LCP_DOWN:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("LCP down"));

      accm.send_accm = 0xffffffff;
      accm.receive_accm = 0xffffffff;

      ssh_l2tp_lns_set_link_info(pm->l2tp,
                                 s->info->tunnel->local_id,
                                 s->info->local_id,
                                 &accm);
      break;

    case SSH_PPP_SIGNAL_IPCP_UP:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_IPCP_UP"));

      /* Fetch all interesting attributes. */
      ssh_ppp_get_ipcp_peer_ip(s->ppp, &s->lac_ip);

      /* The session reached established state. */
      s->ppp_up = 1;
      ssh_fsm_condition_signal(&pm->fsm, &s->cond);
      break;

    case SSH_PPP_SIGNAL_IPCP_DOWN:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_IPCP_DOWN"));
      ssh_pm_l2tp_lns_close_session(pm, s, NULL);
      break;

    case SSH_PPP_SIGNAL_IPCP_FAIL:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_IPCP_FAIL"));
      ssh_pm_l2tp_lns_close_session(pm, s, "IPCP failed");
      break;

    case SSH_PPP_SIGNAL_FATAL_ERROR:
      SSH_DEBUG(SSH_D_ERROR, ("SSH_PPP_SIGNAL_FATAL_ERROR"));
      ssh_pm_l2tp_lns_close_session(pm, s, "Fatal error");
      break;

    case SSH_PPP_SIGNAL_PPP_HALT:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("SSH_PPP_SIGNAL_PPP_HALT"));
      ssh_pm_l2tp_lns_close_session(pm, s, NULL);
      break;

    case SSH_PPP_SIGNAL_SERVER_AUTH_FAIL:
    case SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL:
      SSH_DEBUG(SSH_D_FAIL, ("Authentication failed"));
      ssh_pm_l2tp_lns_close_session(pm, s, "Authentication failed");
      break;

    case SSH_PPP_SIGNAL_SERVER_AUTH_OK:
    case SSH_PPP_SIGNAL_CLIENT_AUTH_OK:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Authentication OK"));
      break;
    }
}

/* Frame output callback for LNS' PPP instance. */
static void
ssh_pm_l2tp_lns_output_cb(SshPPPHandle ppp, void *ctx, SshUInt8 *buffer,
                          unsigned long offset, unsigned long len)
{
  SshFSMThread thread = (SshFSMThread) ctx;
  SshPm pm = (SshPm) ssh_fsm_get_gdata(thread);
  SshPmLnsSession s = (SshPmLnsSession) ssh_fsm_get_tdata(thread);

  if (!s->terminated)
    /* The session is still active. */
    ssh_l2tp_session_send(pm->l2tp, s->info, buffer + offset, len);

  ssh_free(buffer);
}

static void
ssh_pm_l2tp_lns_delay_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

static void
ssh_pm_l2tp_lns_lock_cb(SshPm pm, Boolean status, void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) ssh_fsm_get_tdata(thread);

  if (!status)
    {
      /* Taking a reference failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Taking a reference to the SA rule failed"));
      t->sa_rule_index = SSH_IPSEC_INVALID_INDEX;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/****************************** Tunnel states *******************************/

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;
  SshInterceptorRouteKeyStruct key;
  SshIpAddrStruct ip;
  SshL2tpServer l2tp_server;
  SshPmServer server;
  SshUInt32 ifnum = SSH_INVALID_IFNUM;

  /* Check if the operation is already aborted. */
  if (t->n->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_aborted);
      return SSH_FSM_CONTINUE;
    }

  /* Resolve the local interface number from the L2TP server. */
  l2tp_server = ssh_l2tp_tunnel_get_server(pm->l2tp, t->n->info->local_id);
  if (l2tp_server == NULL)
    {
      /** L2TP server not found. */
    server_not_found:
      t->n->error_message = "Tunnel peer not reachable";
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_reject);
      return SSH_FSM_CONTINUE;
    }
  server = ssh_pm_servers_select_by_l2tp_server(pm, l2tp_server);
  if (server == NULL)
    goto server_not_found;

  ifnum = server->ifnum;

  /* Route the peer IP address to resolve our interface and its
     properties. */

  SSH_VERIFY(ssh_ipaddr_parse(&ip, t->n->info->remote_addr));

  ssh_pm_create_route_key(pm, &key, NULL, &ip, SSH_IPPROTO_UDP,
                          0, 0, ifnum, server->routing_instance_id);

  /** Route peer IP address. */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_route_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_route(pm->engine, 0, &key,
                                   ssh_pm_l2tp_lns_route_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_route_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;
  SshIpAddrStruct src, dst;
  SshUInt16 src_port, dst_port;

  /* Check if the operation is already aborted. */
  if (t->n->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_aborted);
      return SSH_FSM_CONTINUE;
    }

  if (!t->n->route_ok)
    {
      /** Peer not reachable. */
      t->n->error_message = "Tunnel peer not reachable";
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_reject);
      return SSH_FSM_CONTINUE;
    }

  /* Lookup the IPSec SA that protects this L2TP tunnel. */

  SSH_VERIFY(ssh_ipaddr_parse(&src, t->n->info->local_addr));
  SSH_VERIFY(ssh_ipaddr_parse(&dst, t->n->info->remote_addr));
  src_port = ssh_uatoi(t->n->info->local_port);
  dst_port = ssh_uatoi(t->n->info->remote_port);

  SSH_DEBUG(SSH_D_LOWSTART, ("Looking up IPSec SA for the L2TP tunnel: "
                             "local=%@.%d, remote=%@.%d",
                             ssh_ipaddr_render, &src,
                             src_port,
                             ssh_ipaddr_render, &dst,
                             dst_port));

  SSH_DEBUG(SSH_D_LOWSTART, ("Transform index %u %x",
                             t->n->info->attributes.ssh_transform_index,
                             t->n->info->attributes.ssh_transform_index));

  /** Lookup IPSec SA. */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_transform_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_find_transform_rule(
                                pm->engine,
                                0, t->local_ifnum,
                                &src, &dst,
                                SSH_IPPROTO_UDP,
                                src_port, dst_port,
                                0,
                                t->n->info->attributes.ssh_transform_index,
                                (SSH_PME_TRANSFORM_L2TP_PEER
                                 | SSH_PME_MATCH_INACTIVE_RULES
                                 | SSH_PME_REQUIRE_POLICY_CONTEXT),
                                ssh_pm_l2tp_lns_transform_cb,
                                thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_transform_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Check if the operation is already aborted. */
  if (t->n->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_aborted);
      return SSH_FSM_CONTINUE;
    }

  if (t->trd_index == SSH_IPSEC_INVALID_INDEX)
    {
      /** No IPSec SA for the L2TP tunnel. */
      SSH_DEBUG(SSH_D_FAIL, ("No IPSec protection for L2TP tunnel"));
      t->n->error_message = "No IPSec protection for the L2TP tunnel";
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_reject);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Rule %u, transform %u protects L2TP tunnel",
                          (unsigned int) t->sa_rule_index,
                          (unsigned int) t->trd_index));

  /** Fetch SA rule. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Fetching IPSec SA rule"));
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_get_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_get_rule(pm->engine, t->sa_rule_index,
                                      ssh_pm_l2tp_lns_get_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_get_rule_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Check if the operation is already aborted. */
  if (t->n->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_aborted);
      return SSH_FSM_CONTINUE;
    }

  if (!t->n->get_rule_ok)
    {
      /** L2TP tunnel not allowed. */
      SSH_DEBUG(SSH_D_FAIL, ("L2TP session not allowed"));
      t->n->error_message = "L2TP session not allowed";
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_reject);
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_add_control_rule);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_reference_to_rule(pm->engine,
                                                   t->sa_rule_index,
                                                   t->trd_index,
                                                   ssh_pm_l2tp_lns_lock_cb,
                                                   thread));
  SSH_NOTREACHED;

}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_add_control_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshIpAddrStruct ip;

  /* Check if the lock operation failed. */
  if (t->sa_rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      t->n->error_message = "L2TP control traffic apply rule not found";
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_reject);
      return SSH_FSM_CONTINUE;
    }

  /* Looks good so far.  Now, let's create a rule allowing our L2TP
     control packets to get into the tunnel.  We need this since the
     L2TP control UDP flow can timeout and we might want to send, for
     example, HELLO packets to the LAC. */

  memset(&engine_rule, 0, sizeof(engine_rule));

  engine_rule.precedence = t->outbound_rule_precedence;
  SSH_ASSERT(t->n->info != NULL);

  /* Source IP address. */
  ssh_ipaddr_parse(&ip, t->n->info->local_addr);
  if (SSH_IP_IS4(&ip))
    {
      engine_rule.protocol = SSH_PROTOCOL_IP4;
      SSH_IP4_ENCODE(&ip, engine_rule.src_ip_low);
      SSH_IP4_ENCODE(&ip, engine_rule.src_ip_high);
    }
  else
    {
      engine_rule.protocol = SSH_PROTOCOL_IP6;
      SSH_IP6_ENCODE(&ip, engine_rule.src_ip_low);
      SSH_IP6_ENCODE(&ip, engine_rule.src_ip_high);
    }
  engine_rule.selectors |= SSH_SELECTOR_SRCIP;

  /* Destination IP address. */
  ssh_ipaddr_parse(&ip, t->n->info->remote_addr);
  if (SSH_IP_IS4(&ip))
    {
      SSH_ASSERT(engine_rule.protocol == SSH_PROTOCOL_IP4);
      SSH_IP4_ENCODE(&ip, engine_rule.dst_ip_low);
      SSH_IP4_ENCODE(&ip, engine_rule.dst_ip_high);
    }
  else
    {
      SSH_ASSERT(engine_rule.protocol == SSH_PROTOCOL_IP6);
      SSH_IP6_ENCODE(&ip, engine_rule.dst_ip_low);
      SSH_IP6_ENCODE(&ip, engine_rule.dst_ip_high);
    }
  engine_rule.selectors |= SSH_SELECTOR_DSTIP;

  /* IP protocol and port numbers. */

  engine_rule.ipproto = SSH_IPPROTO_UDP;
  engine_rule.selectors |= SSH_SELECTOR_IPPROTO;

  engine_rule.src_port_low = ssh_uatoi(t->n->info->local_port);
  engine_rule.src_port_high = engine_rule.src_port_low;
  engine_rule.selectors |= SSH_SELECTOR_SRCPORT;

  engine_rule.dst_port_low = ssh_uatoi(t->n->info->remote_port);
  engine_rule.dst_port_high = engine_rule.dst_port_low;
  engine_rule.selectors |= SSH_SELECTOR_DSTPORT;

  /* Traffic initiated from the local stack. */
  engine_rule.selectors |= SSH_SELECTOR_FROMLOCAL;

  /* The transform to apply. */
  engine_rule.type = SSH_ENGINE_RULE_APPLY;
  engine_rule.transform_index = t->trd_index;

  /* Do not allow flows to switch rule from this APPLY rule. */
  engine_rule.flags |= SSH_PM_ENGINE_RULE_FLOW_REF;

  /* Require an explicit ssh_pme_delete_rule() from the PM */
  engine_rule.flags |= SSH_ENGINE_RULE_PM_REFERENCE;

#ifdef SSHDIST_IPSEC_NAT
  if (SSH_IP_DEFINED(&t->dst_nat_ip_low))
    {
      engine_rule.nat_dst_ip_low = t->dst_nat_ip_low;
      engine_rule.nat_dst_ip_high = t->dst_nat_ip_high;
      engine_rule.nat_dst_port = t->dst_nat_port;
      engine_rule.nat_flags = t->dst_nat_flags;
      engine_rule.flags |= SSH_ENGINE_RULE_FORCE_NAT_DST;
    }
  if (SSH_IP_DEFINED(&t->dst_nat_selector_ip))
    {
      engine_rule.nat_selector_dst_ip = t->dst_nat_selector_ip;
      engine_rule.nat_selector_dst_port = t->dst_nat_selector_port;
    }
#endif /* SSHDIST_IPSEC_NAT */

  /* The rule depends on the IPSec SA rule.  This way the rule will
     get removed when the IPSec SA is destroyed.  */
  engine_rule.depends_on = t->sa_rule_index;

  /* Timeout and lifetime values for flows. */
  engine_rule.flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  engine_rule.flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  engine_rule.flow_max_lifetime = 0;

  /* It is not necessary to create an IPSec flow for this rule. */
  engine_rule.flags |= SSH_ENGINE_RULE_NO_IPSEC_FLOW;

#ifdef SSHDIST_IPSEC_NAT
  /* Keep source port unmodified */
  engine_rule.nat_flags |= SSH_PM_NAT_SHARE_PORT_SRC;
#endif /* SSHDIST_IPSEC_NAT */

  /* We do not set policy context. */

  /** Create outbound L2TP control rule. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating outbound L2TP control traffic rule"));
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_add_l2tp_control_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_l2tp_lns_add_l2tp_control_rule_cb,
                                      thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_add_l2tp_control_rule_result)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Check if the operation is already aborted. */
  if (t->n->aborted)
    {
      /** Operation aborted. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_aborted);
      return SSH_FSM_CONTINUE;
    }

  if (!t->n->l2tp_rule_ok)
    {
      /** L2TP rule creation failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not create L2TP control traffic rule"));
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_out_of_resources);
      return SSH_FSM_CONTINUE;
    }

  /* We are accepting this tunnel.  Let's store the tunnel structure
     into the tunnel's `upper_level_data'.  Here we add the second
     reference to the LNS tunnel object. */
  t->refcount++;
  SSH_ASSERT(t->n->info->upper_level_data == NULL);
  t->n->info->upper_level_data = t;

  /** Tunnel accepted. */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_accept);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_accept)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Accept this new tunnel. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("New tunnel request accepted"));
  (*t->n->req_completion_cb)(TRUE, NULL, 0, NULL, 0, 0, NULL, 0,
                             t->n->req_completion_cb_context);

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_reject)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Reject the tunnel request. */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Tunnel request rejected: %s",
                               t->n->error_message));

  ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        t->n->info, NULL, "failed");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Message: Tunnel request rejected");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Reason:  %s", t->n->error_message);

  (*t->n->req_completion_cb)(FALSE, NULL, 0, NULL,
                             SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_GENERIC,
                             (unsigned char *) t->n->error_message,
                             strlen(t->n->error_message),
                             t->n->req_completion_cb_context);

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_out_of_resources)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Reject the tunnel request. */

  ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        t->n->info, NULL, "failed");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Message: Tunnel request rejected");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Reason:  Out of resources");

  (*t->n->req_completion_cb)(FALSE, NULL, 0, NULL,
                             SSH_L2TP_TUNNEL_RESULT_ERROR,
                             SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,
                             NULL, 0,
                             t->n->req_completion_cb_context);

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_aborted)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  SSH_DEBUG(SSH_D_FAIL, ("Tunnel request aborted"));
  SSH_ASSERT(t->n->aborted);

  ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        t->n->info, NULL, "failed");
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Message: Tunnel request aborted");

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_request_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_request_terminate)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Unregister the operation handle unless the operation was
     aborted. */
  if (!t->n->aborted)
    ssh_operation_unregister(&t->n->operation_handle);

  SSH_DEBUG(SSH_D_LOWOK, ("Terminating tunnel request thread"));
  return SSH_FSM_FINISH;
}


/****************************** Session states ******************************/

SSH_FSM_STEP(ssh_pm_st_lns_session_opened)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;
  SshPmLnsTunnel t;

  /* Update L2TP session information in the transform.  Now we know
     only L2TP negotiated parameters.  The PPP parameters are updated
     when the PPP negotiation is complete. */

  t = (SshPmLnsTunnel) s->info->tunnel->upper_level_data;
  ssh_pme_update_transform_l2tp_info(pm->engine, t->trd_index,
                                     (SSH_ENGINE_L2TP_PPP_ACFC
                                      | SSH_ENGINE_L2TP_PPP_PFC),
                                     s->info->tunnel->local_id,
                                     s->info->local_id,
                                     s->info->tunnel->remote_id,
                                     s->info->remote_id);

  /** Take a reference to the IPSec SA rule. */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_alloc_attributes);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_alloc_attributes)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;
  SshPmLnsTunnel t = NULL;
  SshPmRemoteAccessAttrsAllocCB alloc_cb = NULL;
  void *alloc_cb_context = NULL;

  t = (SshPmLnsTunnel) s->info->tunnel->upper_level_data;
  if (t->tunnel->u.ike.remote_access_alloc_cb)
    {
      alloc_cb = t->tunnel->u.ike.remote_access_alloc_cb;
      alloc_cb_context = t->tunnel->u.ike.remote_access_cb_context;
    }
  else
    SSH_DEBUG(SSH_D_ERROR, ("Address pool is not configured"));

  /* Allocate a temporary PPP parameters for the session. */
  s->ppp_params = ssh_calloc(1, sizeof(*s->ppp_params));
  if (s->ppp_params == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate PPP parameters"));

      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            s->info->tunnel, s->info, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: Could not start PPP");

      /** Out of memory. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Do basic initialization for the PPP parameters. */

  s->ppp_params->ctx = thread;

  s->ppp_params->mschapv2_server = 1;
  s->ppp_params->mschapv1_server = 1;
  s->ppp_params->pap_server = 1;
  s->ppp_params->chap_server = 1;
#ifdef SSHDIST_IKE_EAP_AUTH
  {
    SshL2tpTunnelAttributes tunnel_attrs;

    /* Check if the EAP can be enabled.  There seems to be some
       compatibility issues. */

    tunnel_attrs = &s->info->tunnel->attributes;
    if (tunnel_attrs->vendor_name_len >= 27
        && memcmp(tunnel_attrs->vendor_name, "Deterministic Networks Inc.",
                  27) == 0)
      {
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("The PPP implementation of the remote L2TP client "
                   "(Vendor Name `%.*s') does not handle PPP authentication "
                   "method negotiation correctly: disabling EAP",
                   tunnel_attrs->vendor_name_len, tunnel_attrs->vendor_name));
        ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,
                      "The PPP implementation of the remote L2TP client "
                      "(Vendor Name `%.*s') does not handle PPP "
                      "authentication method negotiation correctly: "
                      "disabling EAP",
                      tunnel_attrs->vendor_name_len,
                      tunnel_attrs->vendor_name);
        s->ppp_params->eap_md5_server = 0;
      }
    else
      {
        s->ppp_params->eap_md5_server = 1;
      }
  }
#endif /* SSHDIST_IKE_EAP_AUTH */

  s->ppp_params->ipcp = 1;
  s->ppp_params->frame_mode = SSH_PPP_MODE_L2TP;

  /* System name for authentication. */
  s->ppp_params->name = (SshUInt8 *) pm->params.hostname;
  if (pm->params.hostname)
    s->ppp_params->namelen = ssh_ustrlen(pm->params.hostname);

  /* Set the PPP callbacks. */
  s->ppp_params->get_server_secret_cb = ssh_pm_l2tp_lns_get_secret;
#ifdef SSHDIST_IKE_EAP_AUTH
  s->ppp_params->get_server_eap_token_cb = ssh_pm_l2tp_lns_get_token;
#endif /* SSHDIST_IKE_EAP_AUTH */

  s->ppp_params->signal_cb = ssh_pm_l2tp_lns_signal_cb;
  s->ppp_params->output_frame_cb = ssh_pm_l2tp_lns_output_cb;

  /** Allocate client attributes and IP. */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_alloc_attributes_result);

  if (alloc_cb)
    {
      SSH_FSM_ASYNC_CALL({
        s->sub_operation = (*alloc_cb)(pm,
                                         NULL, 0, NULL,
                                       ssh_pm_lns_attribute_cb,
                                       thread,
                                       alloc_cb_context);
      });
      SSH_NOTREACHED;
    }

  /* No default allocation callback set.  Let's continue directly from
     the result state. */
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_alloc_attributes_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;

  /* Check if we allocated peer IP address. */
  if (SSH_IP_DEFINED(&s->ppp_params->peer_ipv4_addr))
    {
      /* IP address defined.  Force our peer to commit to this IP
         address. */
      s->ppp_params->peer_ipv4_netaddr = s->ppp_params->peer_ipv4_addr;
      s->ppp_params->peer_ipv4_mask = s->ppp_params->peer_ipv4_addr;
    }
  else
    {
      /* No IP address allocated.  Let the peer to choose the
         address. */
      (void) ssh_ipaddr_parse(&s->ppp_params->peer_ipv4_netaddr,
                              ssh_custr("0.0.0.0"));
      (void) ssh_ipaddr_parse(&s->ppp_params->peer_ipv4_mask,
                              ssh_custr("255.255.255.255"));
    }

  /* Is our own IP defined? */
  if (!SSH_IP_DEFINED(&s->ppp_params->own_ipv4_addr))
    {
      /* No it isn't.  Leave our address undefined. */
      s->ppp_params->query_without_ip = TRUE;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Starting PPP"));

  s->ppp = ssh_ppp_session_create(s->ppp_params);

  /* We do not need the PPP parameters anymore. */
  ssh_free(s->ppp_params);
  s->ppp_params = NULL;

  if (s->ppp == NULL)
    {
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            s->info->tunnel, s->info, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: Could not start PPP");

      /** PPP session creation failed. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_RADIUS
  /* Should we use RADIUS for authentication? */
  if (pm->default_auth_domain->radius_client)
    {
      if (pm->l2tp_radius.client == NULL)
        {
          /* Configure PPP RADIUS configuration. */
          pm->l2tp_radius.client =
            pm->default_auth_domain->radius_client;
          pm->l2tp_radius.servers =
            pm->default_auth_domain->radius_server_info;
          pm->l2tp_radius.use_framed_ip_address = TRUE;
#ifdef SSHDIST_IKE_EAP_AUTH
          /* Use the same RADIUS config as CHAP/PAP */
          pm->l2tp_eap_radius.radius_servers =
            pm->default_auth_domain->radius_server_info;
          pm->l2tp_eap_radius.radius_client =
            pm->default_auth_domain->radius_client;
          pm->l2tp_radius.eap_radius_config =
            &pm->l2tp_eap_radius;
#endif /* SSHDIST_IKE_EAP_AUTH */
        }

      ssh_ppp_configure_radius(s->ppp, &pm->l2tp_radius);
      s->uses_radius = 1;
    }
#endif /* SSHDIST_RADIUS */

  ssh_ppp_boot(s->ppp);

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_wait_ppp);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_wait_ppp)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;
  SshPmLnsTunnel t;
  SshUInt8 l2tp_flags;
  SshEnginePolicyRuleStruct engine_rule;

  /* Wait for interesting events. */
  if (!s->ppp_up && !s->terminated)
    SSH_FSM_CONDITION_WAIT(&s->cond);

  if (s->terminated)
    {
      /** L2TP session terminated. */
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* Fetch our LNS tunnel structure. */
  t = (SshPmLnsTunnel) s->info->tunnel->upper_level_data;

  /* Check if the LAC really has an IP address. */
  if (!SSH_IP_DEFINED(&s->lac_ip))
    {
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            s->info->tunnel, s->info, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: No LAC IP address negotiated");

      /** No LAC IP address negotiated. */
      SSH_DEBUG(SSH_D_FAIL, ("No LAC IP address negotiated"));
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
      return SSH_FSM_CONTINUE;
    }

  /* PPP link up. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("PPP link up: lac IP `%@'",
                               ssh_ipaddr_render, &s->lac_ip));

#ifdef SSHDIST_RADIUS
  /* Check if our dynamically allocate client IP address was used. */
  if (SSH_IP_DEFINED(&s->dynamic_lac_ip))
    {
      switch (ssh_ppp_get_radius_ip_status(s->ppp))
        {
        case SSH_PPP_RADIUS_IP_STATUS_NONE:
        case SSH_PPP_RADIUS_IP_STATUS_NAS_CONFIGURED:
          /* Yes it was. */
          break;

        case SSH_PPP_RADIUS_IP_STATUS_RADIUS_CONFIGURED:
        case SSH_PPP_RADIUS_IP_STATUS_CLIENT_CONFIGURED:
          /* No it wasn't.  Let's release the dynamic address
             immediately. */
          if (t->tunnel->u.ike.remote_access_free_cb != NULL_FNPTR)
            {
              (*t->tunnel->u.ike.remote_access_free_cb)
                (pm, &s->dynamic_lac_ip, s->dynamic_lac_ip_context,
                 t->tunnel->u.ike.remote_access_cb_context);
            }
          SSH_IP_UNDEFINE(&s->dynamic_lac_ip);
          break;
        }
    }
#endif /* SSHDIST_RADIUS */

  /* Update transform's L2TP information.  Now we know also the PPP
     negotiated parameters. */

  l2tp_flags = 0;
  if (s->output_acfc)
    l2tp_flags |= SSH_ENGINE_L2TP_PPP_ACFC;
  if (s->output_pfc)
    l2tp_flags |= SSH_ENGINE_L2TP_PPP_PFC;

  ssh_pme_update_transform_l2tp_info(pm->engine, t->trd_index, l2tp_flags,
                                     s->info->tunnel->local_id,
                                     s->info->local_id,
                                     s->info->tunnel->remote_id,
                                     s->info->remote_id);

  /* Create outbound rule for traffic to LAC. */

  memset(&engine_rule, 0, sizeof(engine_rule));

  engine_rule.precedence = t->outbound_rule_precedence;
  engine_rule.tunnel_id = t->reverse_tunnel_id;

  /* Destination IP address selector. */
  if (SSH_IP_IS4(&s->lac_ip))
    {
      engine_rule.protocol = SSH_PROTOCOL_IP4;
      SSH_IP4_ENCODE(&s->lac_ip, engine_rule.dst_ip_low);
      SSH_IP4_ENCODE(&s->lac_ip, engine_rule.dst_ip_high);
    }
  else
    {
      engine_rule.protocol = SSH_PROTOCOL_IP6;
      SSH_IP6_ENCODE(&s->lac_ip, engine_rule.dst_ip_low);
      SSH_IP6_ENCODE(&s->lac_ip, engine_rule.dst_ip_high);
    }
  engine_rule.selectors |= SSH_SELECTOR_DSTIP;

  /* The transform to apply. */
  engine_rule.type = SSH_ENGINE_RULE_APPLY;
  engine_rule.transform_index = t->trd_index;

  /* Since we are adding a new rule applying the same transform, we
     must lock the new rule (and its transform) by adding an extra
     reference to the rule.  This means that the rule (and its
     transform) will remain in the engine until we explicitly free it
     by calling ssh_pme_delete_rule().  This way initial contact or
     delete notifications won't invalidate our rule index. */
  engine_rule.flags |= SSH_ENGINE_RULE_PM_REFERENCE;

  /* The rule depends on the high-level L2TP rule. */
  engine_rule.depends_on = t->l2tp_rule_index;

  /* Timeout and lifetime values for flows. */
  engine_rule.flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  engine_rule.flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  engine_rule.flow_max_lifetime = 0;

  /* It is not necessary to create an IPSec flow for this rule. */
  engine_rule.flags |= SSH_ENGINE_RULE_NO_IPSEC_FLOW;

  /* We do not set policy context. */

  /** Create outbound rule. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating outbound rule"));
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_add_rule_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_l2tp_lns_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_add_rule_result)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) s->info->tunnel->upper_level_data;
  unsigned char media_addr[SSH_ETHERH_ADDRLEN];
  SshUInt32 flags;

  if (s->outbound_rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            s->info->tunnel, s->info, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: Could not create L2TP rule");

      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not create L2TP outbound rule"));
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Outbound rule created: index=0x%x",
                          (unsigned int) s->outbound_rule_index));

  /* Add a permanent ARP entry for the remote access client. */

  /* Create a fake ethernet address. */
  memset(media_addr, 0, sizeof(media_addr));
  if (SSH_IP_IS4(&s->lac_ip))
    {
      media_addr[1] = 2;
      SSH_IP4_ENCODE(&s->lac_ip, media_addr + 2);
    }
  else
    {
      SshUInt32 value;

      value = SSH_IP6_WORD0_TO_INT(&s->lac_ip);
      value ^= SSH_IP6_WORD1_TO_INT(&s->lac_ip);
      value ^= SSH_IP6_WORD2_TO_INT(&s->lac_ip);
      value ^= SSH_IP6_WORD3_TO_INT(&s->lac_ip);

      media_addr[1] = 2;
      SSH_PUT_32BIT(media_addr + 2, value);
    }

  /* Flags for ARP entry. */
  flags = SSH_PME_ARP_PERMANENT | SSH_PME_ARP_GLOBAL;
  if (t->proxy_arp)
    flags |= SSH_PME_ARP_PROXY;

  /** Add ARP entry. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Adding ARP entry"));
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_add_arp_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_arp_add(pm->engine, &s->lac_ip, 0,
                                     media_addr, sizeof(media_addr),
                                     flags,
                                     ssh_pm_l2tp_lns_add_arp_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_add_arp_result)
{
  SshPmLnsSession s = (SshPmLnsSession) thread_context;

  if (!s->arp_ok)
    {
      ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                            s->info->tunnel, s->info, "failed");
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  Message: Could not add ARP entry");

      /** Rule creation failed. */
      SSH_DEBUG(SSH_D_FAIL, ("Could not add ARP entry"));
      SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
      return SSH_FSM_CONTINUE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("ARP entry added"));

  /* The L2TP session is now established. */
  ssh_pm_log_l2tp_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                        s->info->tunnel, s->info, "completed");
  if (s->user_name)
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                  "  User-name: %.*s", (int) s->user_name_len, s->user_name);
  if (s->ppp_auth_type)
    {
      const char *auth_name = "???";

      switch (s->ppp_auth_type)
        {
        case SSH_PPP_AUTH_CHAP:
          auth_name = "CHAP";
          break;

        case SSH_PPP_AUTH_PAP:
          auth_name = "PAP";
          break;

        case SSH_PPP_AUTH_EAP:
          auth_name = "EAP";
          break;

        case SSH_PPP_AUTH_EAP_ID:
          auth_name = "EAP-ID";
          break;

        case SSH_PPP_AUTH_MSCHAPv1:
          auth_name = "MS-CHAPv1";
          break;

        case SSH_PPP_AUTH_MSCHAPv2:
          auth_name = "MS-CHAPv2";
          break;

        case SSH_PPP_AUTH_MSCHAP_CHPWv2:
          auth_name = "MS-CHAP-CHPWv2";
          break;

        case SSH_PPP_AUTH_MSCHAP_CHPWv3:
          auth_name = "MS-CHAP-CHPWv3";
          break;
        }

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "  PPP Authentication method: %s",auth_name);
    }
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                "  Virtual IP: %@", ssh_ipaddr_render, &s->lac_ip);

  /** Session established. */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_established);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_established)
{
  SshPmLnsSession s = (SshPmLnsSession) thread_context;

  /* Wait for session termination. */
  if (!s->terminated)
    SSH_FSM_CONDITION_WAIT(&s->cond);

  /** Session terminated. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Session terminated"));
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_terminate)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;
  SshPmTunnel tunnel;

  /* Shutdown our PPP instance. */
  if (s->ppp)
    {
      ssh_ppp_destroy(s->ppp);
      s->ppp = NULL;
    }

  /* Free dynamically allocated fields from the session. */

  ssh_free(s->ppp_params);
  s->ppp_params = NULL;

  ssh_free(s->user_name);
  s->user_name = NULL;

  ssh_free(s->user_password);
  s->user_password = NULL;

  /* Remove ARP entry if it was added. */
  if (s->arp_ok)
    ssh_pme_arp_remove(pm->engine, &s->lac_ip, 0);

  /* Free dynamically allocated client IP address. */
  if (SSH_IP_DEFINED(&s->dynamic_lac_ip))
    {
      SSH_ASSERT(s->dynamic_lac_ip_tunnel_id != 0);
      tunnel = ssh_pm_tunnel_get_by_id(pm, s->dynamic_lac_ip_tunnel_id);
      if (tunnel != NULL && tunnel->u.ike.remote_access_free_cb != NULL_FNPTR)
        {
          (*tunnel->u.ike.remote_access_free_cb)
            (pm, &s->dynamic_lac_ip, s->dynamic_lac_ip_context,
             tunnel->u.ike.remote_access_cb_context);
        }
      SSH_IP_UNDEFINE(&s->dynamic_lac_ip);
    }

  /** Delete L2TP Outbound rule */
  SSH_FSM_SET_NEXT(ssh_pm_st_lns_session_terminate_delete_outbound_rule);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_session_terminate_delete_outbound_rule)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsSession s = (SshPmLnsSession) thread_context;

  if (s->outbound_rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine,
                                             s->outbound_rule_index,
                                      ssh_pm_l2tp_lns_delete_outbound_rule_cb,
                                      thread));
      SSH_NOTREACHED;
    }

  /* Delete rule */
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_terminate)
{
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("tearing down tunnel instance"));

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_terminate_delete_control);
  SSH_FSM_ASYNC_CALL(ssh_register_timeout(&t->tunnel_timeout,
                                          0, 200000,
                                          ssh_pm_l2tp_lns_delay_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_terminate_delete_control)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("removing control rule reference"));

  /* Delete all control rule SA's */
  if (t->control_rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine, t->control_rule_index,
                                      ssh_pm_l2tp_lns_delete_control_rule_cb,
                                      thread));
      SSH_NOTREACHED;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_lns_tunnel_terminate_delete_sa);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_lns_tunnel_terminate_delete_sa)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmLnsTunnel t = (SshPmLnsTunnel) thread_context;

  /* Delete all SA rule's */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("removing SA rule reference"));
  if (t->sa_rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      SSH_FSM_ASYNC_CALL(ssh_pme_delete_rule(pm->engine, t->sa_rule_index,
                                             ssh_pm_l2tp_lns_delete_sa_rule_cb,
                                             thread));
      SSH_NOTREACHED;
    }

  return SSH_FSM_FINISH;
}
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
