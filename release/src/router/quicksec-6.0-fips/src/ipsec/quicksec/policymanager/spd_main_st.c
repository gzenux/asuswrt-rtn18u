/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   The main thread controlling PM start and event waiting.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmStMain"

/* The interval how often failed auto-start rules are checked and
   their failure TTLs are decremented. */
#define SSH_PM_AUTO_START_TIMER_INTERVAL        5

static void ssh_pm_auto_start_timer(void *context);

/*************************** System default rules ***************************/

/* System default rules. */
typedef struct SshPmPolicyRuleRec
{
  const char *name;
  SshUInt16 selectors;
  SshUInt32 flags;
  SshUInt16 src_port_low, src_port_high;
  SshUInt16 dst_port_low, dst_port_high;
  SshUInt32 tunnel_id;
  SshUInt8 protocol;            /* SshInterceptorProtocol */
  SshUInt8 ipproto;
  SshUInt8 icmp_type, icmp_code;
  SshEnginePolicyRuleType rule_type;
  int routing_instance_id;
} SshPmPolicyRuleStruct, *SshPmPolicyRule;

static const SshPmPolicyRuleStruct ssh_pm_default_rules[] =
  {
    /* Allow system-decapsulated packets (NAT-T and L2TP) to the local
       stack. These rules MUST BE no-flow rules, because it is not possible
       to deduce the tunnel_id == 1 based on flow and rule. */
    {"L2TP control and NAT-T IKE IPv4 packets in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_TOLOCAL), SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     1, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
#if defined (WITH_IPV6)
    {"L2TP control and NAT-T IKE IPv6 packets in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_TOLOCAL), SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     1, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
#endif /* WITH_IPV6 */

#if defined (WITH_IPV6)
    /* Pass IPv6 Neighbor discovery packets. */
    {"Router Solicitation",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_IPV6ICMP,
     SSH_ICMP6_TYPE_ROUTER_SOLICITATION, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"Router Advertisement",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_IPV6ICMP,
     SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"Neighbor Solicitation",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_IPV6ICMP,
     SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"Neighbor Advertisement",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_IPV6ICMP,
     SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    /* Allow ICMPv6 unreachable and too big messages destined to local IKE
       port. The IKE ports are checked by the engine and tunnel_id value 1
       is used for matching only those packets. */
    {"ICMPv6 Unreachable",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     1, SSH_PROTOCOL_IP6, SSH_IPPROTO_IPV6ICMP,
     SSH_ICMP6_TYPE_UNREACH, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"ICMPv6 Too Big",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     1, SSH_PROTOCOL_IP6, SSH_IPPROTO_IPV6ICMP,
     SSH_ICMP6_TYPE_TOOBIG, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
#endif /* WITH_IPV6 */

    /* Allow ICMP unreachable messages destined to local IKE port. The IKE
       ports are checked by the engine and tunnel_id value 1 is used for
       matching only those packets. */
    {"ICMP Unreachable",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_ICMPTYPE | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     1, SSH_PROTOCOL_IP4, SSH_IPPROTO_ICMP,
     SSH_ICMP_TYPE_UNREACH, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    /* Note: Check the constant in SSH_ENGINE_MAX_RULES formula in
       ipsec_params.h when adding new default rules! */
  };

static const SshUInt32 ssh_pm_num_default_rules
= (sizeof(ssh_pm_default_rules) / sizeof(ssh_pm_default_rules[0]));

static const SshPmPolicyRuleStruct ssh_pm_default_dhcp_client_rules[] =
  {
    {"DHCP client IPv4 pass-by out",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT |
      SSH_SELECTOR_FROMLOCAL),
     SSH_ENGINE_RULE_PASS_UNMODIFIED  | SSH_ENGINE_NO_FLOW,
     0, 0, 67, 67,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    {"DHCP client IPv4 pass-by in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
      SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_RULE_PASS_UNMODIFIED | SSH_ENGINE_NO_FLOW,
     67, 67, 0, 0,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    {"DHCP client IPv6 pass-by out",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT |
      SSH_SELECTOR_FROMLOCAL),
     SSH_ENGINE_RULE_PASS_UNMODIFIED  | SSH_ENGINE_NO_FLOW,
     0, 0, 547, 547,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    {"DHCP client IPv6 pass-by in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
      SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_RULE_PASS_UNMODIFIED | SSH_ENGINE_NO_FLOW,
     547, 547, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
  };

static const SshUInt32 ssh_pm_num_default_dhcp_client_rules
= (sizeof(ssh_pm_default_dhcp_client_rules)
   / sizeof(ssh_pm_default_dhcp_client_rules[0]));

static const SshPmPolicyRuleStruct ssh_pm_default_dhcp_server_rules[] =
  {
    {"DHCP server IPv4 pass-by in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
      SSH_SELECTOR_DSTPORT | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     68, 68, 67, 67,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    {"DHCP server IPv4 pass-by out",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
      SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     67, 67, 68, 68,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    {"DHCP server IPv6 pass-by out",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
      SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     547, 547, 546, 546,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

    {"DHCP server IPv6 pass-by in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT |
      SSH_SELECTOR_DSTPORT | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW | SSH_ENGINE_RULE_PASS_UNMODIFIED,
     546, 546, 547, 547,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
  };

static const SshUInt32 ssh_pm_num_default_dhcp_server_rules
= (sizeof(ssh_pm_default_dhcp_server_rules)
   / sizeof(ssh_pm_default_dhcp_server_rules[0]));

static const SshPmPolicyRuleStruct ssh_pm_default_dns_rules[] =
  {
    /* Allow DNS traffic, initiated from our local stack. */
    {"DNS IPv4 UDP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL), 0,
     0, 0, 53, 53,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"DNS IPv4 TCP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL), 0,
     0, 0, 53, 53,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_TCP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
#if defined (WITH_IPV6)
    {"DNS IPv6 UDP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL), 0,
     0, 0, 53, 53,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"DNS IPv6 TCP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_FROMLOCAL), 0,
     0, 0, 53, 53,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_TCP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
#endif /* WITH_IPV6 */
  };

static const SshUInt32 ssh_pm_num_default_dns_rules
= (sizeof(ssh_pm_default_dns_rules) / sizeof(ssh_pm_default_dns_rules[0]));

/* Default rules for passing IKE packets. The ports are set by the
   values of pm->params->*_ike_ports and pm->params->*_ike_natt_ports. */
static const SshPmPolicyRuleStruct ssh_pm_default_ike_rules[] =
  {
    /* Allow IKE traffic from our IKE server (from and to the local
       stack). */
    {"IKE IPv4 out",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT | SSH_SELECTOR_FROMLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"IKE IPv4 in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},

#if defined (WITH_IPV6)
    {"IKE IPv6 out",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_SRCPORT | SSH_SELECTOR_FROMLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
    {"IKE IPv6 in",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_TOLOCAL),
     SSH_ENGINE_NO_FLOW,
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     SSH_ENGINE_RULE_PASS, SSH_INTERCEPTOR_VRI_ID_ANY},
#endif /* WITH_IPV6 */

    /* Note: Check the constant in SSH_ENGINE_MAX_RULES formula in
       ipsec_params.h when adding new default rules! */
  };

static const SshUInt32 ssh_pm_num_default_ike_rules
= (sizeof(ssh_pm_default_ike_rules) / sizeof(ssh_pm_default_ike_rules[0]));

/* Rules for processing AH and ESP packets with unknown SPI's.
   The 'flags' and 'rule_type' are not set here, they are determined
   by the values of pm->params.pass_unknown_ipsec_packet */
static const SshPmPolicyRuleStruct ssh_pm_unknown_ipsec_rules[] =
  {
    {"Unknown IPv4 AH",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_TOLOCAL),
     0, /* flags */
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_AH, 0, 0,
     0, SSH_INTERCEPTOR_VRI_ID_ANY}, /* rule_type */
    {"Unknown IPv4 ESP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_TOLOCAL),
     0, /* flags */
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_ESP, 0, 0,
     0, SSH_INTERCEPTOR_VRI_ID_ANY}, /* rule_type */
    {"Unknown IPv4 NAT-T ESP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_TOLOCAL),
     0, /* flags */
     0, 0, SSH_IPSEC_IKE_NATT_PORT, SSH_IPSEC_IKE_NATT_PORT,
     0, SSH_PROTOCOL_IP4, SSH_IPPROTO_UDP, 0, 0,
     0, SSH_INTERCEPTOR_VRI_ID_ANY}, /* rule_type */
#if defined (WITH_IPV6)
    {"Unknown IPv6 AH",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_TOLOCAL),
     0, /* flags */
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_AH, 0, 0,
     0, SSH_INTERCEPTOR_VRI_ID_ANY}, /* rule_type */
    {"Unknown IPv6 ESP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_TOLOCAL),
     0, /* flags */
     0, 0, 0, 0,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_ESP, 0, 0,
     0, SSH_INTERCEPTOR_VRI_ID_ANY}, /* rule_type */
    {"Unknown IPv6 NAT-T ESP",
     (SSH_SELECTOR_IPPROTO | SSH_SELECTOR_DSTPORT | SSH_SELECTOR_TOLOCAL),
     0, /* flags */
     0, 0, SSH_IPSEC_IKE_NATT_PORT, SSH_IPSEC_IKE_NATT_PORT,
     0, SSH_PROTOCOL_IP6, SSH_IPPROTO_UDP, 0, 0,
     0, SSH_INTERCEPTOR_VRI_ID_ANY}, /* rule_type */
#endif /* WITH_IPV6 */

    /* Note: Check the constant in SSH_ENGINE_MAX_RULES formula in
       ipsec_params.h when adding new default rules! */
  };

static const SshUInt32 ssh_pm_num_unknown_ipsec_rules
= (sizeof(ssh_pm_unknown_ipsec_rules) / sizeof(ssh_pm_unknown_ipsec_rules[0]));

/************************** Static help functions ***************************/

/* A callback function that is called to notify the status of engine
   rule deletion. */
void
ssh_pm_delete_rule_cb(SshPm pm, Boolean done,
                      SshUInt32 rule_index,
                      SshUInt32 peer_handle,
                      SshEngineTransform tr,
                      void *context)
{
  SshFSMThread thread = (SshFSMThread) context;
  SshPmRule rule;
  SshPmTunnel tunnel;
  SshUInt32 inbound_spi[2];
  SshUInt8 ipproto;
#ifdef WITH_IKE
  SshPmStatus pm_status;
  SshPmP1 p1;
  int num_spis;
  int i;
#endif /* WITH_IKE */

  if (done)
    pm->mt_index = SSH_IPSEC_INVALID_INDEX;

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

#ifdef DEBUG_LIGHT
      for (i = 0; i < num_spis; i++)
        SSH_DEBUG(SSH_D_LOWSTART,
              ("Sending delete notification for deleted IPsec SPI %@-%08lx",
               ssh_ipproto_render, (SshUInt32) ipproto,
               (unsigned long) inbound_spi[i]));
#endif /* DEBUG_LIGHT */

      /* Send delete notification for IKE keyed ones. */
      rule = ssh_adt_get(pm->mt_current.container, pm->mt_current.handle);
      tunnel = rule->side_to.tunnel;

      if (tunnel == NULL)
        tunnel = rule->side_from.tunnel;

#ifdef WITH_IKE
      if (tunnel != NULL && !tunnel->manual_tn)
        {
          /* Can we send the message syncronously? */





          pm_status = ssh_pm_get_status(pm);
          if (pm_status == SSH_PM_STATUS_ACTIVE ||
              pm_status == SSH_PM_STATUS_DESTROYED)
            {
              /* Send delete notification synchronously. */
              ssh_pm_send_ipsec_delete_notification(pm, peer_handle,
                                                    tunnel, rule, ipproto,
                                                    num_spis, inbound_spi);
            }
          else
            {
              /* Request delayed IPsec delete notification. */
              p1 = ssh_pm_lookup_p1(pm, rule, tunnel, peer_handle, NULL,
                                    NULL, TRUE);
              if (p1 != NULL)
                {
                  for (i = 0; i < num_spis; i++)
                    {
                      ssh_pm_request_ipsec_delete_notification(pm, p1, ipproto,
                                                               inbound_spi[i]);
                    }
                }
            }
        }
#endif /* WITH_IKE */
    }

  /* Continue.  The next state is already set by our caller. */
 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called when server shutdown has completed */
void ssh_pm_servers_stop_cb(void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  /* Continue.  The next state is already set by caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}

/* A callback function that is called to notify the status of engine
   rule addition. */
void
ssh_pm_add_rule_cb(SshPm pm, SshUInt32 ind,
                   const SshEnginePolicyRule rule,
                   void *context)
{
  SshFSMThread thread = (SshFSMThread) context;

  pm->mt_index = ind;

  /* Continue.  The next state is already set by caller. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(thread);
}


/**************************** Main thread states ****************************/

SSH_FSM_STEP(ssh_pm_st_main_initialize)
{
  SshPm pm = (SshPm) fsm_context;
  SshCryptoLibraryStatus crypto_status;

  /* Check crypto library status before continuing initialization. */
  crypto_status = ssh_crypto_library_get_status();

  /* Everything ok, safe to continue pm initialization. */
  if (crypto_status == SSH_CRYPTO_LIBRARY_STATUS_OK)
    {
      SSH_FSM_SET_NEXT(ssh_pm_st_main_send_random_salt);
      return SSH_FSM_CONTINUE;
    }

  /* Crypto library is still busy with self tests, wait for a while. */
  else if (crypto_status == SSH_CRYPTO_LIBRARY_STATUS_SELF_TEST)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Waiting for crypto library initialization to complete"));
      SSH_FSM_ASYNC_CALL(ssh_register_timeout(&pm->main_thread_timeout,
                                              0, 200000,
                                              ssh_pm_timeout_cb, thread));
      SSH_NOTREACHED;
    }

  /* Crypto library failure is a fatal error. */
  ssh_fatal("Crypto library initialization failed!");
  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(ssh_pm_st_main_send_random_salt)
{
  SshPm pm = (SshPm) fsm_context;
  SshUInt32 salt[4];
  unsigned char *cp;
  int i;

  /* Create salt. */
  cp = (unsigned char *) salt;

  for (i = 0; i < sizeof(salt); i++)
    cp[i] = ssh_random_get_byte();

  /*  Send random salt to the engine (it is used to make
      flow ids unpredictable for an external attacker). */
  ssh_pm_salt_to_engine(pm, salt);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_start)
{
  SshPm pm = (SshPm) fsm_context;

  /* Start auto-start rule timer. */
  ssh_pm_auto_start_timer(pm);

  /* And wait for interesting events. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_wait_interfaces);
  return SSH_FSM_CONTINUE;
}

/* This timeout is called if the engine does not sent an interface change
   notification within 5 seconds of starting the policy manager. It
   continues execution of the policy manager's main thread (another option
   here would be to shutdown the policymanager if this expiry timeout is
   delivered). */
static void pm_interface_change_expire_timer(void *context)
{
  SshPm pm = (SshPm) context;

  SSH_DEBUG(SSH_D_HIGHOK, ("In interface change expire timeout"));

  /* Fake an interface change event. */
  pm->iface_change = 1;

  ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);

  /* Clear the structure so it is safe to call ssh_cancel_timeout on it */
  memset(&pm->interface_change_timeout, 0,
         sizeof(pm->interface_change_timeout));
}

SSH_FSM_STEP(ssh_pm_st_main_start_wait_interfaces)
{
  SshPm pm = (SshPm) fsm_context;

  /* Wait until we receive the initial interface notification. */
  if (!pm->iface_change)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for interface information"));

      ssh_register_timeout(&pm->interface_change_timeout, 5, 0,
                           pm_interface_change_expire_timer, pm);

     SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  ssh_cancel_timeout(&pm->interface_change_timeout);

  /* Perform any interface information dependent initialization. */
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Get virtual adapters from the engine. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Getting virtual adapters from engine"));
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_get_virtual_adapters);
  return SSH_FSM_CONTINUE;
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  /* Create default rules. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating default rules"));
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_rules);
  return SSH_FSM_CONTINUE;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
}

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
SSH_FSM_STEP(ssh_pm_st_main_start_get_virtual_adapters)
{
  SshPm pm = (SshPm) fsm_context;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_get_virtual_adapters_result);
  SSH_FSM_ASYNC_CALL({
    ssh_pme_virtual_adapter_list(pm->engine,
                                 SSH_INVALID_IFNUM,
                                 ssh_pm_vip_get_virtual_adapters_cb,
                                 thread);
  });
  SSH_NOTREACHED;
}


SSH_FSM_STEP(ssh_pm_st_main_start_get_virtual_adapters_result)
{
  /* Create default rules. */
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating default rules"));
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_rules);
  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

static void
create_engine_rule_from_pm_rule(SshEnginePolicyRule engine_rule,
                                const SshPmPolicyRuleStruct *pm_rule)
{
  SshUInt16 port;

  memset(engine_rule, 0, sizeof(*engine_rule));

  engine_rule->transform_index = SSH_IPSEC_INVALID_INDEX;
  engine_rule->depends_on = SSH_IPSEC_INVALID_INDEX;

  engine_rule->flags = pm_rule->flags;
  engine_rule->selectors = pm_rule->selectors;
  engine_rule->precedence = SSH_PM_RULE_PRI_SYSTEM_DEFAULT;

  engine_rule->tunnel_id = pm_rule->tunnel_id;
  engine_rule->routing_instance_id = pm_rule->routing_instance_id;

  if (engine_rule->selectors & SSH_SELECTOR_SRCPORT)
    {
      engine_rule->src_port_low = pm_rule->src_port_low;
      engine_rule->src_port_high = pm_rule->src_port_high;
    }

  if (engine_rule->selectors & SSH_SELECTOR_DSTPORT)
    {
      engine_rule->dst_port_low = pm_rule->dst_port_low;
      engine_rule->dst_port_high = pm_rule->dst_port_high;
    }

  engine_rule->protocol = pm_rule->protocol;

  if (engine_rule->selectors & SSH_SELECTOR_IPPROTO)
    engine_rule->ipproto = pm_rule->ipproto;

  /* For ICMP the type and code are encoded in the destination port selector,
     the src port selector is unused. */
  if (engine_rule->selectors & SSH_SELECTOR_ICMPTYPE)
    {
      port = (SshUInt16) pm_rule->icmp_type;
      port <<= 8;
      engine_rule->dst_port_low  = port;
      engine_rule->dst_port_high = port | 0x00ff;
      engine_rule->src_port_low  = 0;
      engine_rule->src_port_high = 0xffff;
    }

  if (engine_rule->selectors & SSH_SELECTOR_ICMPCODE)
    {
      engine_rule->dst_port_low  = ((engine_rule->dst_port_low & 0xff00)
                                    | pm_rule->icmp_code);
      engine_rule->dst_port_high  = ((engine_rule->dst_port_high & 0xff00)
                                     | pm_rule->icmp_code);
      engine_rule->src_port_low  = 0;
      engine_rule->src_port_high = 0xffff;
    }

  /* Timeout and lifetime values for flows. */
  engine_rule->flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  engine_rule->flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  engine_rule->flow_max_lifetime = 0;

  /* All default rules are marked as forward rules */
  engine_rule->flags |= SSH_PM_ENGINE_RULE_FORWARD;
  engine_rule->type = (SshUInt8) pm_rule->rule_type;
  return;
}


/** Default L2TP and IPv6 neighbor discovery pass-by rules */
SSH_FSM_STEP(ssh_pm_st_main_start_default_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshUInt32 i;

  if (pm->mt_current.index >= ssh_pm_num_default_rules)
    {
      /* All default rules created. */
      pm->mt_current.index = 0;
      pm->mt_current.sub_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dns_rules);
      return SSH_FSM_CONTINUE;
    }

  /* Create default rule number `pm->mt_current.index'. */
  i = pm->mt_current.index;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating default rule `%s'", ssh_pm_default_rules[i].name));

  create_engine_rule_from_pm_rule(&engine_rule, &ssh_pm_default_rules[i]);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_rules_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}


SSH_FSM_STEP(ssh_pm_st_main_start_default_rules_add_result)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    SSH_DEBUG(SSH_D_ERROR, ("Failed to add default rule %u",
                            (unsigned int) pm->mt_current.index));

  /* Move to the next rule. */
  pm->mt_current.index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_rules);
  return SSH_FSM_CONTINUE;
}


/** Default DNS pass-by rules */
SSH_FSM_STEP(ssh_pm_st_main_start_dns_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshUInt32 i;

  if ((pm->params.flags & SSH_PM_PARAM_FLAG_NO_DNS_FROM_LOCAL_PASS_RULE) ||
      (pm->mt_current.index >= ssh_pm_num_default_dns_rules))
    {
      /* All DNS rules created. */
      pm->mt_current.index = 0;
      pm->mt_current.sub_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dhcp_client_rules);
      return SSH_FSM_CONTINUE;
    }

  /* Create default rule number `pm->mt_current.index'. */
  i = pm->mt_current.index;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating default DNS rule `%s'",
             ssh_pm_default_dns_rules[i].name));

  create_engine_rule_from_pm_rule(&engine_rule, &ssh_pm_default_dns_rules[i]);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dns_rules_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_start_dns_rules_add_result)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    SSH_DEBUG(SSH_D_ERROR, ("Failed to add default rule %u",
                            (unsigned int) pm->mt_current.index));

  /* Move to the next rule. */
  pm->mt_current.index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dns_rules);
  return SSH_FSM_CONTINUE;
}

/** Default DHCP client pass-by rules */
SSH_FSM_STEP(ssh_pm_st_main_start_dhcp_client_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshUInt32 i;

  if ((pm->params.flags & SSH_PM_PARAM_FLAG_DISABLE_DHCP_CLIENT_PASSBY_RULE) ||
      (pm->mt_current.index >= ssh_pm_num_default_dhcp_client_rules))
    {
      /* All DNS rules created. */
      pm->mt_current.index = 0;
      pm->mt_current.sub_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dhcp_server_rules);
      return SSH_FSM_CONTINUE;
    }

  /* Create default rule number `pm->mt_current.index'. */
  i = pm->mt_current.index;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating default DHCP client rule `%s'",
             ssh_pm_default_dhcp_client_rules[i].name));

  create_engine_rule_from_pm_rule(&engine_rule,
                                  &ssh_pm_default_dhcp_client_rules[i]);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dhcp_client_rules_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_start_dhcp_client_rules_add_result)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    SSH_DEBUG(SSH_D_ERROR, ("Failed to add default rule %u",
                            (unsigned int) pm->mt_current.index));

  /* Move to the next rule. */
  pm->mt_current.index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dhcp_client_rules);
  return SSH_FSM_CONTINUE;
}

/** Default DHCP server pass-by rules */
SSH_FSM_STEP(ssh_pm_st_main_start_dhcp_server_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshUInt32 i;

  if (!(pm->params.flags & SSH_PM_PARAM_FLAG_ENABLE_DHCP_SERVER_PASSBY_RULE) ||
      (pm->mt_current.index >= ssh_pm_num_default_dhcp_server_rules))
    {
      /* All DNS rules created. */
      pm->mt_current.index = 0;
      pm->mt_current.sub_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_ike_rules);
      return SSH_FSM_CONTINUE;
    }

  /* Create default rule number `pm->mt_current.index'. */
  i = pm->mt_current.index;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating default DHCP server rule `%s'",
             ssh_pm_default_dhcp_server_rules[i].name));

  create_engine_rule_from_pm_rule(&engine_rule,
                                  &ssh_pm_default_dhcp_server_rules[i]);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dhcp_server_rules_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_start_dhcp_server_rules_add_result)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    SSH_DEBUG(SSH_D_ERROR, ("Failed to add default rule %u",
                            (unsigned int) pm->mt_current.index));

  /* Move to the next rule. */
  pm->mt_current.index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_dhcp_server_rules);
  return SSH_FSM_CONTINUE;
}

/** Default IKE pass-by rules */
/* Each of the rules in ssh_pm_default_ike_rules is added multiple times,
   one for each configured normal IKE port and once for each configured
   NAT-T IKE port. */
SSH_FSM_STEP(ssh_pm_st_main_start_default_ike_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshUInt32 i, j;

  if (pm->mt_current.index >= ssh_pm_num_default_ike_rules)
    {
      /* All default rules created. */
      pm->mt_current.index = 0;
      pm->mt_current.sub_index = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_start_unknown_ipsec_rules);
      return SSH_FSM_CONTINUE;
    }

  i = pm->mt_current.index;
  j = pm->mt_current.sub_index;

  SSH_ASSERT(j < 2 * pm->params.num_ike_ports);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating default IKE rule `%s'",
                               ssh_pm_default_ike_rules[i].name));

  SSH_DEBUG(SSH_D_MIDOK, ("Default IKE pass rule IKE on %s "
                          "local port %d, remote port %d",
                          (j & 1) ? "NAT-T" : "normal",
                          (j & 1) ?
                          pm->params.local_ike_natt_ports[j / 2] :
                          pm->params.local_ike_ports[j / 2],
                          (j & 1) ?
                          pm->params.remote_ike_natt_ports[j / 2] :
                          pm->params.remote_ike_ports[j / 2]));

  create_engine_rule_from_pm_rule(&engine_rule,
                                  &ssh_pm_default_ike_rules[i]);

  if (j & 1)
    {
      if (engine_rule.selectors & SSH_SELECTOR_FROMLOCAL)
        engine_rule.src_port_low = pm->params.local_ike_natt_ports[j / 2];
      else if (engine_rule.selectors & SSH_SELECTOR_TOLOCAL)
        engine_rule.dst_port_low = pm->params.local_ike_natt_ports[j / 2];
      else
        SSH_NOTREACHED;
    }
  else
    {
      if (engine_rule.selectors & SSH_SELECTOR_FROMLOCAL)
        engine_rule.src_port_low = pm->params.local_ike_ports[j / 2];
      else if (engine_rule.selectors & SSH_SELECTOR_TOLOCAL)
        engine_rule.dst_port_low = pm->params.local_ike_ports[j / 2];
      else
        SSH_NOTREACHED;
    }

  engine_rule.src_port_high = engine_rule.src_port_low;
  engine_rule.dst_port_high = engine_rule.dst_port_low;

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_ike_rules_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_start_default_ike_rules_add_result)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    SSH_DEBUG(SSH_D_ERROR, ("Failed to add default IKE rule %u",
                            (unsigned int) pm->mt_current.index));

  /* Move to the next rule. */
  if (++pm->mt_current.sub_index == 2 * pm->params.num_ike_ports)
    {
      pm->mt_current.sub_index = 0;
      pm->mt_current.index++;
    }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_default_ike_rules);
  return SSH_FSM_CONTINUE;
}


/** Default unknown IPsec SA rules */
SSH_FSM_STEP(ssh_pm_st_main_start_unknown_ipsec_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshEnginePolicyRuleStruct engine_rule;
  SshUInt32 i;

  if (pm->mt_current.index >= ssh_pm_num_unknown_ipsec_rules)
    {
      /* All unknown IPsec rules created. */
      SSH_FSM_SET_NEXT(ssh_pm_st_main_start_complete);
      return SSH_FSM_CONTINUE;
    }

  /* Create default rule number `pm->mt_current.index'. */
  i = pm->mt_current.index;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Creating unknown IPsec rule `%s'",
             ssh_pm_unknown_ipsec_rules[i].name));

  create_engine_rule_from_pm_rule(&engine_rule,
                                  &ssh_pm_unknown_ipsec_rules[i]);

  /* Set the rule flags and rule type based on whether we pass packets with
     unknown SPI's to the crash recovery module or to the local stack. */
  if (pm->params.pass_unknown_ipsec_packets)
    {
      engine_rule.type = SSH_ENGINE_RULE_PASS;
    }
  else
    {
      engine_rule.flags |= (SSH_ENGINE_NO_FLOW | SSH_PM_ENGINE_RULE_CR);
      engine_rule.type = SSH_ENGINE_RULE_TRIGGER;
   }

  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_unknown_ipsec_rules_add_result);
  SSH_FSM_ASYNC_CALL(ssh_pme_add_rule(pm->engine, FALSE, &engine_rule,
                                      ssh_pm_add_rule_cb, thread));
  SSH_NOTREACHED;
}

SSH_FSM_STEP(ssh_pm_st_main_start_unknown_ipsec_rules_add_result)
{
  SshPm pm = (SshPm) fsm_context;

  if (pm->mt_index == SSH_IPSEC_INVALID_INDEX)
    SSH_DEBUG(SSH_D_ERROR, ("Failed to add default rule %u",
                            (unsigned int) pm->mt_current.index));

  /* Move to the next rule. */
  pm->mt_current.index++;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_start_unknown_ipsec_rules);
  return SSH_FSM_CONTINUE;
}


SSH_FSM_STEP(ssh_pm_st_main_start_complete)
{
  SshPm pm = (SshPm) fsm_context;

  /* The policy manager is not fully functional. */
  SSH_DEBUG(SSH_D_LOWOK, ("Policy manager started"));

  /* Let's call the user-provided completion callback. */
  SSH_ASSERT(pm->create_cb != NULL_FNPTR);
  (*pm->create_cb)(pm, pm->create_cb_context);

  /* And enter the main loop. */
  SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
  return SSH_FSM_CONTINUE;
}

/************************ Handling auto-start rules *************************/

/* Try to establish IPSec tunnel of rule `rule'.  If the operation is
   successful, the function starts a Quick-Mode thread that negotiates
   the tunnel. */
static void ssh_pm_rule_auto_start(SshPm pm, SshPmRule rule, Boolean forward)
{
  SshPmQm qm;
  SshPmRuleSideSpecification src, dst;

  if (forward)
    {
      src = &rule->side_from;
      dst = &rule->side_to;
    }
  else
    {
      src = &rule->side_to;
      dst = &rule->side_from;
    }

  SSH_ASSERT(dst->tunnel != NULL);

  if (dst->as_up)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Rule already up"));
      return;
    }
  if (dst->as_active)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start already active for rule"));
      return;
    }
  if (dst->as_fail_retry > 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start rule has failed: timeout %d",
                                   dst->as_fail_retry));
      return;
    }

  /* This tunnel is currently being used for auto-start rule. */
  if (dst->as_active == 0 && dst->tunnel->as_active != 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Auto-start already active for tunnel"));
      /* Mark that another rule is waiting for the auto-start tunnel to
         come up. */
      dst->tunnel->as_rule_pending = 1;
      return;
    }

  /* Check if the rule is already being used for a Quick-Mode negotiation. */
  if (rule->ike_in_progress)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The rule already has an ongoing IKE "
                             "negotiation. Dropping auto-start request."));
      return;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    {
      if (!ssh_pm_use_virtual_ip(pm, dst->tunnel, rule))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not get virtual IP interface"));
          dst->as_active = 0;
          dst->tunnel->as_active = 0;

          goto fail;
        }
      if (dst->tunnel->vip->unusable)
        {
         /* VIP interface was just started, no nothing else. */
          goto end;
        }
      /* Otherwise continue with QM negotiation unless... */
#ifdef SSHDIST_L2TP
      /* ... this is an L2TP tunnel. */
      if (dst->tunnel->flags & SSH_PM_TI_L2TP)
        goto end;
#endif /* SSHDIST_L2TP */
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
      if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
        {
          SSH_DEBUG(SSH_D_ERROR,
            ("Invalid attempt to start QM with config mode placeholder rule"));
          goto fail;
        }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
    }

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Allocate and init Quick-Mode context for this negotiation. */
  qm = ssh_pm_qm_alloc(pm, FALSE);
  if (qm == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No more Quick-Mode structures left"));
      goto fail;
    }

  qm->initiator = 1;
  if (forward)
    qm->forward = 1;
  qm->auto_start = 1;

  rule->ike_in_progress = 1;
  qm->rule = rule;
  SSH_PM_RULE_LOCK(qm->rule);

  qm->tunnel = dst->tunnel;
  SSH_PM_TUNNEL_TAKE_REF(qm->tunnel);

  /* Packet ifnum is needed later at the trigger processing and we
     will resolve it before entering the normal trigger processing. */

  /* Create hand-crafted packet attributes. */

  SSH_ASSERT(src->ts->number_of_items_used > 0);
  SSH_ASSERT(dst->ts->number_of_items_used > 0);

  if (SSH_IP_DEFINED(dst->ts->items[0].start_address))
    {
      qm->sel_dst = *dst->ts->items[0].start_address;
    }
  else
    {
      if (SSH_IP_DEFINED(src->ts->items[0].start_address))
        {
          if (SSH_IP_IS4(src->ts->items[0].start_address))
            ssh_ipaddr_parse(&qm->sel_dst, ssh_custr("0.0.0.0"));
          else
            ssh_ipaddr_parse(&qm->sel_dst, ssh_custr("::"));
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR, ("Selectors undefined in auto-start rule!"));
          rule->ike_in_progress = 0;
          ssh_pm_qm_free(pm, qm);
          goto fail;
        }
    }

  /* Source address. */
  if (SSH_IP_DEFINED(src->ts->items[0].start_address))
    {
      qm->sel_src = *src->ts->items[0].start_address;
    }
  else
    {
      if (SSH_IP_IS4(&qm->sel_dst))
        ssh_ipaddr_parse(&qm->sel_src, ssh_custr("0.0.0.0"));
      else
        ssh_ipaddr_parse(&qm->sel_src, ssh_custr("::"));
    }

  SSH_ASSERT((SSH_IP_IS4(&qm->sel_dst) && SSH_IP_IS4(&qm->sel_src)) ||
             (SSH_IP_IS6(&qm->sel_dst) && SSH_IP_IS6(&qm->sel_src)));

  /* Protocol and port numbers. */
  qm->sel_ipproto = SSH_IPPROTO_ANY;
  if (src->ts->items[0].proto)
    qm->sel_ipproto = src->ts->items[0].proto;

  qm->sel_src_port = src->ts->items[0].start_port;
  qm->sel_dst_port = dst->ts->items[0].start_port;

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Set NAT configuration, so qm thread does not think a NAT is in effect. */
  qm->packet_orig_src_ip = qm->sel_src;
  qm->packet_orig_src_port = qm->sel_src_port;
  if (SSH_IP_DEFINED(dst->ts->items[0].start_address))
    qm->packet_orig_dst_ip = *dst->ts->items[0].start_address;
  else
    qm->packet_orig_dst_ip = qm->sel_dst;

  qm->packet_orig_dst_port = qm->sel_dst_port;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Create SA traffic selectors for this negotiation from the policy rule. */
  if (!ssh_pm_resolve_policy_rule_traffic_selectors(pm, qm))
    {
      rule->ike_in_progress = 0;
      ssh_pm_qm_free(pm, qm);
      goto fail;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Take a vip reference for the duration of the qm negotiation. */
  if (SSH_PM_RULE_IS_VIRTUAL_IP(qm->rule))
    {
      SSH_ASSERT(qm->tunnel->vip != NULL);
      if (!ssh_pm_virtual_ip_take_ref(pm, qm->tunnel))
        {
          rule->ike_in_progress = 0;
          ssh_pm_qm_free(pm, qm);
          goto fail;
        }
      qm->vip = qm->tunnel->vip;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Start a Quick-Mode initiator thread. */
  ssh_fsm_thread_init(&pm->fsm, &qm->thread,
                      ssh_pm_st_qm_i_auto_start,
                      NULL_FNPTR, pm_qm_thread_destructor, qm);
  ssh_fsm_set_thread_name(&qm->thread, "QM auto start");

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
 end:
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  /* Mark rule and tunnel having already an auto-start thread. */
  dst->as_active = 1;
  dst->tunnel->as_active = 1;
  return;

 fail:
  /* Mark auto-start failed. */
  if (dst->as_fail_limit < 16)
    dst->as_fail_limit++;
  dst->as_fail_retry = dst->as_fail_limit;
  return;
}

/* A function for scheduling the ssh_pm_auto_start_timer. */
static void pm_schedule_auto_start_timer(SshPm pm)
{
  SshADTHandle handle;
  SshPmRule rule;
  unsigned long timeout = SSH_PM_AUTO_START_TIMER_INTERVAL;
  Boolean start_timer = FALSE;

  for (handle = ssh_adt_enumerate_start(pm->rule_by_autostart);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_autostart, handle))
    {
      rule = ssh_adt_get(pm->rule_by_autostart, handle);

      if (SSH_PM_RULE_INACTIVE(pm, rule))
        continue;

      SSH_ASSERT(rule->side_to.auto_start || rule->side_from.auto_start);

      /* Check forward direction. */
      if (rule->side_to.auto_start)
        {
          SSH_ASSERT(rule->side_to.tunnel != NULL);
          if (rule->side_to.as_fail_retry)
            {
              /* Register timer to update as_fail_retry */
              start_timer = TRUE;
            }
          else if (rule->side_to.as_fail_retry == 0
                   && rule->side_to.as_up == 0)
            {
              /* Register timer to auto-start rule as soon as possible. */
              start_timer = TRUE;
            }
          else if (rule->side_to.tunnel->as_active)
            {
              /* Register timer to check the status of currently active
                 auto-starts. */
              start_timer = TRUE;
            }

          if (rule->side_to.tunnel->as_rule_pending)
            {
              /* Handle pending auto-starts immediately. */
              timeout = 0;
              start_timer = TRUE;
              break;
            }
        }

      /* Check reverse direction. Note that auto-start is enabled in reverse
         direction only for manual key tunnels. */
      else
        {
          SSH_ASSERT(rule->side_from.auto_start);
          SSH_ASSERT(rule->side_from.tunnel != NULL);
          if (rule->side_from.as_fail_retry)
            {
              /* Register timer to update as_fail_retry */
              start_timer = TRUE;
            }
          else if (rule->side_from.as_fail_retry == 0
                   && rule->side_from.as_up == 0)
            {
              /* Register timer to auto-start rule as soon as possible. */
              start_timer = TRUE;
            }
          else if (rule->side_from.tunnel->as_active)
            {
              /* Register timer to check the status of currently active
                 auto-starts. */
              start_timer = TRUE;
            }

          if (rule->side_from.tunnel->as_rule_pending)
            {
              /* Handle pending auto-starts immediately. */
              timeout = 0;
              start_timer = TRUE;
              break;
            }
        }
    }

  if (start_timer == FALSE)
    {
      ssh_cancel_timeout(pm->auto_start_timeout);
      pm->auto_start_timeout_registered = FALSE;
      SSH_DEBUG(SSH_D_LOWOK, ("No auto-start timer scheduled"));
    }
  else if (pm->auto_start_timeout_registered == FALSE)
    {
      /* Add some jitter to the auto start timeout interval to help
         avoiding simultaneous IPsec negotiations. */
      unsigned long usec = ssh_random_get_byte();
      usec *= 1000;

      SSH_DEBUG(SSH_D_LOWOK, ("Rescheduling auto-start timer to %d.%06d",
                              timeout, usec));

      pm->auto_start_timeout_registered = TRUE;
      ssh_register_timeout(pm->auto_start_timeout,
                           timeout, usec,
                           ssh_pm_auto_start_timer, pm);
    }
}

/* A timer for aging failed auto-start rules. */
static void ssh_pm_auto_start_timer(void *context)
{
  SshPm pm = (SshPm) context;
  SshPmRule rule;
  SshUInt32 count = 0;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_LOWOK, ("Auto-start timer triggered"));
  pm->auto_start_timeout_registered = FALSE;

  for (handle = ssh_adt_enumerate_start(pm->rule_by_autostart);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_autostart, handle))
    {
      rule = ssh_adt_get(pm->rule_by_autostart, handle);

      if (SSH_PM_RULE_INACTIVE(pm, rule))
        continue;

      SSH_ASSERT(rule->side_to.auto_start || rule->side_from.auto_start);

      if (rule->side_to.auto_start)
        {
          SSH_ASSERT(rule->side_to.tunnel != NULL);

          if (rule->side_to.as_fail_retry)
            rule->side_to.as_fail_retry--;

          if (rule->side_to.as_fail_retry == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Activating auto-start rule `%@'",
                         ssh_pm_rule_render, rule));
              count++;
            }
          else if (rule->side_to.tunnel->as_rule_pending)
            {
              count++;
            }
        }
      else
        {
          SSH_ASSERT(rule->side_from.auto_start != 0);
          SSH_ASSERT(rule->side_from.tunnel != NULL);

          if (rule->side_from.as_fail_retry)
            rule->side_from.as_fail_retry--;

          if (rule->side_from.as_fail_retry == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Activating auto-start rule `%@'",
                         ssh_pm_rule_render, rule));
              count++;
            }
          else if (rule->side_from.tunnel->as_rule_pending)
            {
              count++;
            }
        }
    }

  if (count > 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Activated %u rules: notifying main thread",
                              (unsigned int) count));
      pm->auto_start = 1;
      ssh_fsm_condition_broadcast(&pm->fsm, &pm->main_thread_cond);
    }

  pm_schedule_auto_start_timer(pm);
}

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
SSH_FSM_STEP(ssh_pm_st_main_cfgmode_rules)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmTunnel tunnel;
  Boolean rules_changed = FALSE;
  SshADTHandle handle;

  SSH_ASSERT(pm->cfgmode_rules);

  pm->cfgmode_rules = 0;
  SSH_FSM_SET_NEXT(ssh_pm_st_main_run);

  /* Do not attempt anything if policy manager is suspended. */
  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Policy manager is not active, ignoring cfgmode-rules"));
      return SSH_FSM_CONTINUE;
    }

  /* Add policy rules based on config mode associated with a virtual
     adapter that has come up, or delete previously added rules
     associated with a virtual adapter going down. */
  for (handle = ssh_adt_enumerate_start(pm->tunnels);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->tunnels, handle))
    {
      tunnel = ssh_adt_get(pm->tunnels,  handle);

      if (tunnel->vip != NULL &&
          ssh_pm_virtual_ip_update_cfgmode_rules(pm, tunnel->vip))
        rules_changed = TRUE;
    }

  /* If no  rules were added or deleted then do nothing more. */
  if (!rules_changed)
    return SSH_FSM_CONTINUE;

  /* Makefile additions/deletions pending. */
  ssh_pm_config_make_pending(pm);

  /* Transfer pending changes to batch. */
  ssh_pm_config_pending_to_batch(pm);

  /* Direct this thread to do the batch. */
  pm->batch_active = 1;

  return SSH_FSM_CONTINUE;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

SSH_FSM_STEP(ssh_pm_st_main_auto_start)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRule rule;
  SshADTHandle handle;

  SSH_ASSERT(pm->auto_start);

  /* Do not attempt auto-start if policy manager is suspended. */
  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_ACTIVE)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Policy manager is not active, ignoring auto-start"));
      pm->auto_start = 0;
      SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
      return SSH_FSM_CONTINUE;
    }

  /* Check if there are any auto-start rules which need some
     actions. */
  for (handle = ssh_adt_enumerate_start(pm->rule_by_autostart);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_autostart, handle))
    {
      rule = ssh_adt_get(pm->rule_by_autostart, handle);

      SSH_DEBUG(SSH_D_LOWSTART, ("Checking rule `%@'",
                                 ssh_pm_rule_render, rule));

      if (SSH_PM_RULE_INACTIVE(pm, rule))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Rule is not in the active configuration"));
          continue;
        }

      SSH_ASSERT(rule->side_to.auto_start != 0
                 || rule->side_from.auto_start != 0);

      /* Check the forward direction of the rule. */
      if (rule->side_to.auto_start)
        {
          SSH_ASSERT(rule->side_to.tunnel != NULL);
          if ((rule->side_to.tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
              || ((rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER)
                  && ssh_pm_vip_rule_interface_trigger(pm, rule))
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
              )
            {
              ssh_pm_rule_auto_start(pm, rule, TRUE);
            }
        }

      /* Check the reverse direction of the rule. Note that auto-start is
         enabled in the reverse direction only for manual-key tunnels. */
      if (rule->side_from.auto_start)
        {
          SSH_ASSERT(rule->side_from.tunnel != NULL);
          if ((rule->side_from.tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0)
            {
              ssh_pm_rule_auto_start(pm, rule, FALSE);
            }
        }
    }

  pm->auto_start = 0;

  pm_schedule_auto_start_timer(pm);

  SSH_FSM_SET_NEXT(ssh_pm_st_main_run);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_pm_st_main_run)
{
  SshPm pm = (SshPm) fsm_context;

  /* The policy manager is now fully  */

  /* Wait until something interesting happens. */
  if ((ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
      && !pm->iface_change
      && !pm->batch_active
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
      && !pm->cfgmode_rules
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
      && !pm->auto_start)
    {
      /* Nothing to do.  Signal our condition variable since the
         modification waiters wait on it. */
      SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

      /* And wait that someone schedules us some work. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Waiting for events"));
      SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);
    }

  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Policy manager destroyed"));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_shutdown);
      return SSH_FSM_CONTINUE;
    }

  if (pm->batch_active)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Policy modification"));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_batch_start);
      return SSH_FSM_CONTINUE;
    }

  if (pm->iface_change)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Interface change"));

      /* Set batch_active to disable reconfigurations */
      pm->batch_active = 1;

      SSH_FSM_SET_NEXT(ssh_pm_st_main_iface_change);
      return SSH_FSM_CONTINUE;
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if (pm->cfgmode_rules)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Config mode rules update"));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_cfgmode_rules);
      return SSH_FSM_CONTINUE;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

  if (pm->auto_start)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Auto-start"));
      SSH_FSM_SET_NEXT(ssh_pm_st_main_auto_start);
      return SSH_FSM_CONTINUE;
    }

  /* One of the cases above must have been true. */
  SSH_NOTREACHED;
  return SSH_FSM_FINISH;
}
