/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Rule object handling.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "util_dnsresolver.h"
#include "sshicmp-util.h"
#include "sshmp-xuint.h"

#define SSH_DEBUG_MODULE "SshPmRules"

/* Flag to check valid Multicast traffic selectors */
#define SSH_PM_RULE_TS_CHECK_MULTICAST_SRC 0x00000001

/* Internal function for setting traffic selectors.
   Parameters test_flags has extra flags like
   SSH_PM_RULE_TS_CHECK_MULTICAST_SRC
 */
static Boolean ssh_pm_rule_set_ts_internal(SshPmRule rule,
                           SshPmRuleSide side,
                           SshIkev2PayloadTS ts,
                           SshUInt32 test_flags);

/************************** Static help functions ***************************/

/* Sanity check for rule's tunnels.  This verifies that the tunnel
   `tunnel' has all necessary settings.  The function returns TRUE if
   the tunnel is valid and FALSE otherwise. */
static Boolean
pm_verify_tunnel(SshPmTunnel tunnel)
{
  SshPmTunnel p1_tunnel;
#ifdef WITH_IPV6
  SshUInt16 link_local_peer_cnt = 0;
  SshUInt16 i;
#endif /* WITH_IPV6 */

  if (tunnel == NULL)
    return TRUE;

  /* Select the tunnel used for p1 negotiations and check IKE configuration
     from that tunnel. */
  SSH_PM_TUNNEL_GET_P1_TUNNEL(p1_tunnel, tunnel);
  SSH_ASSERT(p1_tunnel != NULL);

  /* There is a special case, in which a tunnel does not have identity,
     local secret, authentication domain or manual key set. In such case
     we must check if the default authentication domain has a private key
     set to be used in local authentication. If it exists, we can mark
     this tunnel as using IKE and continue. */
  if (p1_tunnel->ike_tn == 0 && p1_tunnel->manual_tn == 0 &&
      p1_tunnel->pm->default_auth_domain->private_key != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No manual key, identity, authentication domain or manual "
                 "key set for tunnel. Using private key in default "
                 "authentication domain for local IKE authentication."));
      p1_tunnel->ike_tn = 1;
    }

  if (p1_tunnel->ike_tn)
    {
#ifdef SSHDIST_IPSEC_MOBIKE
      if (p1_tunnel->flags & SSH_PM_T_MOBIKE
          && SSH_PM_TUNNEL_NUM_LOCAL_ADDRS(p1_tunnel) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "No local addresses or interfaces specified for "
                        "a MobIKE enabled tunnel");
          return FALSE;
        }
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSH_IPSEC_TCPENCAP
      if (p1_tunnel->flags & SSH_PM_T_TCPENCAP)
        {
          if (p1_tunnel->flags & SSH_PM_TI_START_WITH_NATT)
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "IPsec over TCP cannot enabled "
                            "with 'start-with-natt'");
              return FALSE;
            }
          if (p1_tunnel->flags & SSH_PM_T_NO_NATS_ALLOWED)
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "IPsec over TCP cannot enabled "
                            "with 'no-nats-allowed'");
              return FALSE;
            }
        }
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSHDIST_IKEV1
      if (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1 &&
          tunnel->auth_domain_name != NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Setting non-default authentication domain for "
                        "IKEv1-tunnel is not allowed.");
          return FALSE;
        }
#endif /* SSHDIST_IKEV1 */
    }
  else if (p1_tunnel->manual_tn == 0)
    {
      /* No keying material whatsoever. */
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Tunnel does not specify any keying method "
                    "(IKE or manual)");
      return FALSE;
    }

  if (tunnel->ike_tn)
    {
      /* If using AES counter mode, we must also use authentication */
      if ((tunnel->transform & SSH_PM_CRYPT_AES_CTR) &&
          ((tunnel->transform & SSH_PM_MAC_MASK) == 0))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "AES counter mode cannot be used without an "
                        "authentication algorithm");
          return FALSE;
        }
    }
  else if (tunnel->manual_tn)
    {
      /* If the `manual_tn' is set, then check we are not using AES counter
         mode as this is forbidden to use with manual keys. */
      if ((tunnel->transform & SSH_PM_CRYPT_AES_CTR))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "AES counter mode cannot be used with manual keys");
          return FALSE;
        }
      if ((tunnel->transform & SSH_PM_COMBINED_MASK))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "AES gcm or gmac cannot be used with manual keys");
          return FALSE;
        }
#ifdef SSH_IPSEC_TCPENCAP
      if (p1_tunnel->flags & SSH_PM_T_TCPENCAP)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "IPsec over TCP cannot be used with manual keys");
          return FALSE;
        }
#endif /* SSH_IPSEC_TCPENCAP */
    }

#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
  if (tunnel->local_identity != NULL &&
      tunnel->u.ike.local_cert_kid != NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot specify local identity and local certificate "
                    "together.");
      return FALSE;
    }

#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

  if (tunnel->local_identity == NULL &&
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT
      tunnel->ike_tn &&
      tunnel->u.ike.local_cert_kid == NULL &&
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */
      tunnel->id_type != SSH_PM_IDENTITY_ANY)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Tunnel has identity type set without an identity "
                    "specified");
      return FALSE;
    }

#ifdef SSHDIST_IKE_ID_LIST
  if (p1_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2)
    {
      if ((p1_tunnel->local_identity && p1_tunnel->local_identity->id_type ==
           (int) IPSEC_ID_LIST) ||
          (p1_tunnel->remote_identity && p1_tunnel->remote_identity->id_type ==
           (int) IPSEC_ID_LIST))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "The ID_LIST identity type cannot be used with IKEv2 "
                        "tunnels");
          return FALSE;
        }
    }
#endif /* SSHDIST_IKE_ID_LIST */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  if (tunnel->outer_tunnel != NULL
      && SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel->outer_tunnel)
      && tunnel->local_ip != NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Tunnel local IP cannot be defined for inner tunnels "
                    "using virtual IP outer tunnel.");
      return FALSE;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef WITH_IPV6
  /* Little bit sanity checking for ipv6 link-local addresses. */
  for (i = 0; i < tunnel->num_peers; i++)
    {
      if (SSH_IP6_IS_LINK_LOCAL(&tunnel->peers[i]))
        link_local_peer_cnt++;
    }

  /* All of the peers are not friends of link-local. */
  if (link_local_peer_cnt &&
      (link_local_peer_cnt != tunnel->num_peers))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Some of the peers specified for a tunnel are link-local"
                    " and some are global addresses.");
      return FALSE;
    }

  if (link_local_peer_cnt && tunnel->num_local_interfaces == 0)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Link-local peers configured, but no local interfaces "
                    "are specified.");
      return FALSE;
    }
#endif /* WITH_IPV6 */

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (tunnel->second_auth_domain_name &&
      !tunnel->second_local_identity &&
      !(tunnel->flags & SSH_PM_TI_DONT_INITIATE))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "If second authentication domain is set for a tunnel "
                    "second identity or SSH_PM_TI_DONT_INITIATE must also "
                    "be set.");
      return FALSE;
    }

  if (!tunnel->second_auth_domain_name &&
      tunnel->second_local_identity)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "If second identity is set for a tunnel second "
                    "authentication domain must also be set.");
      return FALSE;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  return TRUE;
}

/* Post check for auto-start rule `rule'.  This verifies that the user
   did provide enough information (remote IKE peer IP address) that we
   can establish this rule automatically.  The function returns TRUE
   if all required information is given and FALSE otherwise. */
static Boolean
pm_rule_post_check_auto_start(SshPmRule rule, SshPmTunnel tunnel,
                              SshPmRuleSideSpecification side)
{
  SSH_ASSERT(tunnel != NULL);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SSH_ASSERT((tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
             || (tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) != 0);
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
  SSH_ASSERT((tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0);
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* For tunnel mode it is sufficient that an IKE peer is specified. For
     transport mode the following checks below are also required */
  if (tunnel->transform & SSH_PM_IPSEC_TUNNEL)
    {
      if (tunnel->num_peers
#ifdef SSHDIST_IPSEC_DNSPOLICY
          || tunnel->num_dns_peers
#endif /* SSHDIST_IPSEC_DNSPOLICY */
          )
        /* Explicit IKE peers specified. */
        return TRUE;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* For L2TP tunnels the following checks below on the traffic selector item
     are not required. This is because the SA protecting L2TP traffic takes
     its selectors from the IKE peer addresses and L2TP ports, it does not
     use the selectors from the policy rule that is input to this routine. */
  if (tunnel->flags & SSH_PM_TI_L2TP)
    return TRUE;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */


  /* Enforce that there is exactly one traffic selector item. */
  if (!side->ts || side->ts->number_of_items_used != 1)
    {
      if (tunnel->transform & SSH_PM_IPSEC_TUNNEL)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Auto-start rule specifies zero or more than one "
                      "traffic selector item and no IKE peer is specified.");
      else
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Auto-start rule specifies zero or more than one "
                      "traffic selector item with transport mode.");
      return FALSE;
    }


  /* Now check that IP addresses in the traffic slector item specify
     a single IP address. */
  if ((!SSH_IP_DEFINED(side->ts->items[0].start_address)
       || !SSH_IP_EQUAL(side->ts->items[0].start_address,
                        side->ts->items[0].end_address))
#ifdef SSHDIST_IPSEC_DNSPOLICY
      && !side->dns_addr_sel_ref
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      )
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Auto-start rule does not specify single IP address "
                    "or domain name for its remote peer.");
      return FALSE;
    }

  return TRUE;
}

static Boolean
pm_rule_post_check_manual_key(SshPm pm, SshPmRule rule)
{
  SshPmTunnel tunnel;

  /* Check to-tunnel */
  if (rule->side_to.tunnel != NULL && rule->side_to.tunnel->manual_tn)
    {
      tunnel = rule->side_to.tunnel;

      if (tunnel->num_peers == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Tunnel peer must be defined for manual key tunnels.");
          return FALSE;
        }

      if ((tunnel->flags & SSH_PM_T_TRANSPORT_MODE) &&
          ((rule->side_to.ts->number_of_items_used == 0) ||
           (rule->side_from.ts->number_of_items_used == 0)))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Traffic selectors must be defined for "
                        "transport mode manual keyed tunnels");
          return FALSE;
        }

      if (tunnel->u.manual.trd_inner_protocol == SSH_PROTOCOL_NUM_PROTOCOLS)
        {
          if (SSH_IP_IS4(rule->side_to.ts->items[0].start_address))
            tunnel->u.manual.trd_inner_protocol = SSH_PROTOCOL_IP4;
          else if (SSH_IP_IS6(rule->side_to.ts->items[0].start_address))
            tunnel->u.manual.trd_inner_protocol = SSH_PROTOCOL_IP6;
          else
            SSH_NOTREACHED;
        }
      else
        {
          if ((!SSH_IP_IS4(rule->side_to.ts->items[0].start_address)
               && tunnel->u.manual.trd_inner_protocol == SSH_PROTOCOL_IP4)
              || (!SSH_IP_IS6(rule->side_to.ts->items[0].start_address)
                  && tunnel->u.manual.trd_inner_protocol == SSH_PROTOCOL_IP6))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "The IP versions of traffic selectors of all "
                            "to-tunnel rules for a single manual key tunnel "
                            "must be equal.");
              return FALSE;
            }
        }
    }

  /* Check from-tunnel */
  if (rule->side_from.tunnel != NULL && rule->side_from.tunnel->manual_tn)
    {
      tunnel = rule->side_from.tunnel;

      if (tunnel->num_peers == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Tunnel peer must be defined for manual key tunnels.");
          return FALSE;
        }

      if ((tunnel->flags & SSH_PM_T_TRANSPORT_MODE) &&
          ((rule->side_to.ts->number_of_items_used == 0) ||
           (rule->side_from.ts->number_of_items_used == 0)))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Traffic selectors must be defined for "
                        "transport mode manual keyed tunnels");
          return FALSE;
        }

      if (tunnel->u.manual.trd_inner_protocol == SSH_PROTOCOL_NUM_PROTOCOLS)
        {
          if (SSH_IP_IS4(rule->side_from.ts->items[0].start_address))
            tunnel->u.manual.trd_inner_protocol = SSH_PROTOCOL_IP4;
          else if (SSH_IP_IS6(rule->side_from.ts->items[0].start_address))
            tunnel->u.manual.trd_inner_protocol = SSH_PROTOCOL_IP6;
          else
            SSH_NOTREACHED;
        }
      else
        {
          if ((!SSH_IP_IS4(rule->side_from.ts->items[0].start_address)
               && tunnel->u.manual.trd_inner_protocol == SSH_PROTOCOL_IP4)
              || (!SSH_IP_IS6(rule->side_from.ts->items[0].start_address)
                  && tunnel->u.manual.trd_inner_protocol == SSH_PROTOCOL_IP6))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "The IP versions of traffic selectors of all "
                            "from-tunnel rules for a single manual key tunnel "
                            "must be equal.");
              return FALSE;
            }
        }
    }

  return TRUE;
}


/* Check if the rule's side specification `side' has any selectors. */
static Boolean
pm_rule_has_selectors(SshPmRuleSideSpecification side)
{
  if (side->ifname
      || side->local_stack
#ifdef SSHDIST_IPSEC_DNSPOLICY
      || side->dns_addr_sel_ref
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      || side->ts)
    return TRUE;

  /* No selectors set. */
  return FALSE;
}

int ssh_pm_rule_hash_adt(void *ptr, void *context)
{
  SshPmRule r = ptr;

  return r->rule_id;
}

int ssh_pm_rule_compare_adt(void *ptr1, void *ptr2, void *context)
{
  SshPmRule r1 = ptr1;
  SshPmRule r2 = ptr2;

  if (r1->rule_id == r2->rule_id)
    return 0;
  else if (r1->rule_id < r2->rule_id)
    return -1;
  else
    return 1;
}

int ssh_pm_rule_prec_compare_adt(void *ptr1, void *ptr2, void *context)
{
  SshPmRule r1 = ptr1;
  SshPmRule r2 = ptr2;

  if (r1->precedence == r2->precedence)
    return 0;
  else if (r1->precedence < r2->precedence)
    return 1;
  else
    return -1;
}

void ssh_pm_rule_destroy_adt(void *ptr, void *context)
{
  SshPm pm = context;
  SshPmRule rule = ptr;

  ssh_pm_rule_free(pm, rule);
}

/* Verify the rule's traffic selectors are appropiate when application
   gateways are in use. The rule must have a TCP or UDP constaint on the
   IP protocol */
static Boolean pm_rule_verify_appgw_sane(SshPm pm, SshPmRule rule)
{
  SshIkev2PayloadTSItem from, to;
  Boolean proto_set = FALSE;

  if (rule->service == NULL || rule->service->appgw_ident == NULL)
    return TRUE;

  if (rule->side_from.ts == NULL && rule->side_to.ts == NULL)
    return FALSE;

  if (rule->side_from.ts && rule->side_from.ts->number_of_items_used)
    {
      from = &rule->side_from.ts->items[0];

      if (from->proto != SSH_IPPROTO_TCP && from->proto != SSH_IPPROTO_UDP)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Application gateway can only be "
                                  "configured for TCP or UDP"));
          return FALSE;
        }

      proto_set = TRUE;
    }

  if (rule->side_to.ts && rule->side_to.ts->number_of_items_used)
    {
      to = &rule->side_to.ts->items[0];

      if (to->proto != SSH_IPPROTO_TCP && to->proto != SSH_IPPROTO_UDP)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Application gateway can only be "
                                  "configured for TCP or UDP"));
          return FALSE;
        }

      proto_set = TRUE;
    }

  /* The above checks that at least one traffic selector has its IP protocol
     set to TCP or UDP. In pm_rule_verify_ts_sane() it is checked that all
     traffic selector items have a common IP protocol. */
  return proto_set;
}

/* Verify the user has given a sane traffic selector. The IKE library
   takes care of sanity checking the individual TS items, here we just
   check that the different traffic selector items will combine to
   form engine rules that make sense. */
static Boolean pm_rule_verify_ts_sane(SshPm pm, SshPmRule rule)
{
  SshIkev2PayloadTSItem from, to;
  Boolean ikev1_tunnel = FALSE;
  SshUInt32 i, j;

  /* Check appgw configuration */
  if (!pm_rule_verify_appgw_sane(pm, rule))
    return FALSE;

  /* For simplicity restrict rules with per-host/perport tunnels to
     have at most one traffic selector item. */
  if (rule->side_to.tunnel &&
      ((rule->side_to.tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
       (rule->side_to.tunnel->flags & SSH_PM_T_PER_PORT_SA)))
    {
      if ((rule->side_to.ts != NULL &&
           (rule->side_to.ts->number_of_items_used > 1)) ||
          (rule->side_from.ts != NULL &&
           (rule->side_from.ts->number_of_items_used > 1)))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Per-host or per-port rules cannot be used with "
                        "multiple traffic selector items");
          return FALSE;
        }
    }
  if (rule->side_from.tunnel &&
      ((rule->side_from.tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
       (rule->side_from.tunnel->flags & SSH_PM_T_PER_PORT_SA)))
    {
      if ((rule->side_from.ts != NULL &&
           (rule->side_from.ts->number_of_items_used > 1)) ||
          (rule->side_to.ts != NULL &&
           (rule->side_to.ts->number_of_items_used > 1)))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Per-host or per-port rules cannot be used with "
                        "multiple traffic selector items");
          return FALSE;
        }
    }

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
  if (rule->flags & SSH_PM_RULE_MULTIHOME)
    {
      if (rule->side_to.tunnel &&
          (!(rule->side_to.tunnel->flags & SSH_PM_T_TRANSPORT_MODE) ||
           (rule->side_to.tunnel->transform & SSH_PM_IPSEC_TUNNEL) ||
           (rule->side_to.tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
           (rule->side_to.tunnel->flags & SSH_PM_T_PER_PORT_SA)))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Multi-homed rules cannot be used with tunnels that "
                        "are IPsec tunnel mode, or per-port/per-host tunnels");
          return FALSE;
        }

      if (rule->side_from.tunnel &&
          (!(rule->side_from.tunnel->flags & SSH_PM_T_TRANSPORT_MODE) ||
           (rule->side_from.tunnel->transform & SSH_PM_IPSEC_TUNNEL) ||
           (rule->side_from.tunnel->flags & SSH_PM_T_PER_HOST_SA) ||
           (rule->side_from.tunnel->flags & SSH_PM_T_PER_PORT_SA)))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Multi-homed rules cannot be used with tunnels that "
                        "are IPsec tunnel mode, or per-port/per-host tunnels");
          return FALSE;
        }
    }
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

  if ((rule->side_to.tunnel &&
       (rule->side_to.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)) ||
      (rule->side_from.tunnel &&
       (rule->side_from.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)))
    ikev1_tunnel = TRUE;
  else
    ikev1_tunnel = FALSE;

  if (rule->side_to.ts != NULL)
    {
      for (i = 0; i < rule->side_to.ts->number_of_items_used; i++)
        {
          to = &rule->side_to.ts->items[i];

          /* No port ranges allowed in IKEv1 */
          if (ikev1_tunnel && (to->start_port != to->end_port)
              && (to->start_port != 0 && to->end_port != 0xffff))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "IKEv1 does not support negotiation of "
                            "port ranges");
              return FALSE;
            }
        }
    }

  if (rule->side_from.ts != NULL)
    {
      for (i = 0; i < rule->side_from.ts->number_of_items_used; i++)
        {
          from = &rule->side_from.ts->items[i];

          /* No port ranges allowed in IKEv1 */
          if (ikev1_tunnel && (from->start_port != from->end_port)
              && (from->start_port != 0 && from->end_port != 0xffff))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "IKEv1 does not support negotiation of "
                            "port ranges");
              return FALSE;
            }

          if (rule->side_to.ts != NULL)
            {
              for (j = 0; j < rule->side_to.ts->number_of_items_used; j++)
                {
                  to = &rule->side_to.ts->items[j];

                  /* Check the types agree */
                  if (from->ts_type != to->ts_type)
                    {
                      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                    "Mixed IP address families are not "
                                    "supported");
                      return FALSE;
                    }

#ifdef WITH_IPV6
                  /* Check that the IPv6 addresses are of same kind.
                     So no mixing link-local and global addresses. */
                  if (from->ts_type == SSH_IKEV2_TS_IPV6_ADDR_RANGE &&
                      (SSH_IP6_IS_LINK_LOCAL(from->start_address) !=
                       SSH_IP6_IS_LINK_LOCAL(to->start_address)))
                    {
                      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                    "Mixed IPv6 address types are not "
                                    "supported");
                      return FALSE;
                    }
#endif /* WITH_IPV6 */

                  /* Check the IP protocols agree */
                  if (from->proto && to->proto && from->proto != to->proto)
                    {
                      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                    "Mixed IP protocols are not supported");
                      return FALSE;
                    }

                  /* Check that ports for ICMP are the same for the from and to
                     side. The ICMP type/code selectors are encoded as ports.
                  */
                  if (from->proto == SSH_IPPROTO_ICMP ||
                      from->proto == SSH_IPPROTO_IPV6ICMP)
                    {
                      if (from->start_port &&
                          to->start_port &&
                          from->start_port != to->start_port)
                        {
                          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                        "Inconsistent ICMP selectors");
                          return FALSE;
                        }

                      if (from->end_port != 0xffff &&
                          to->end_port != 0xffff &&
                          from->end_port != to->end_port)
                        {
                          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                        "Inconsistent ICMP selectors");
                          return FALSE;
                        }
                    }
                }
            }
        }
    }

  /* Checks if the 'to' tunnel specifies transport mode */
  if (rule->side_to.tunnel &&
      (((rule->side_to.tunnel->flags & SSH_PM_T_TRANSPORT_MODE)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
        && !(rule->side_to.tunnel->flags & SSH_PM_TI_L2TP)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
        )
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
       || rule->flags & SSH_PM_RULE_MULTIHOME
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
       ))
    {
      for (i = 0;
           rule->side_from.ts != NULL
             && i < rule->side_from.ts->number_of_items_used;
           i++)
        {
          /* If the tunnel specifies a local IP address, it must agree with
             that in the traffic selector. */
          if (rule->side_to.tunnel->local_ip != NULL
              && ((SSH_IP_CMP(&rule->side_to.tunnel->local_ip->ip,
                              rule->side_from.ts->items[i].start_address) < 0)
                  || (SSH_IP_CMP(&rule->side_to.tunnel->local_ip->ip,
                              rule->side_from.ts->items[i].end_address) > 0)))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "Local IP tunnel attribute does not match the "
                            "source selector given in the rule, this is not "
                            "allowed for transport mode");
              return FALSE;
            }
        }

      for (i = 0;
           rule->side_to.ts != NULL
           && i < rule->side_to.ts->number_of_items_used;
           i++)
        {
          /* If the tunnel specifies peer IP addresses, they must agree with
             that in the traffic selector. */
          for (j = 0; j < rule->side_to.tunnel->num_peers; j++)
            {
              if (SSH_IP_CMP(&rule->side_to.tunnel->peers[j],
                             rule->side_to.ts->items[i].start_address)
                  || SSH_IP_CMP(&rule->side_to.tunnel->peers[j],
                                rule->side_to.ts->items[i].end_address))
                {
                  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                "Peer IP tunnel attribute does not match the "
                                "destination selector given in rule, this is "
                                "not allowed for transport mode");
                  return FALSE;
                }
            }
        }
    }

  /* Checks if the 'from' tunnel specifies transport mode */
  if (rule->side_from.tunnel &&
      (((rule->side_from.tunnel->flags & SSH_PM_T_TRANSPORT_MODE)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
        && !(rule->side_from.tunnel->flags & SSH_PM_TI_L2TP)
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
        )
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
       || rule->flags & SSH_PM_RULE_MULTIHOME
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
       ))
    {
      for (i = 0;
           rule->side_to.ts != NULL
             && i < rule->side_to.ts->number_of_items_used;
           i++)
        {
          /* If the tunnel specifies a local IP address, it must agree with
             that in the traffic selector. */
          if (rule->side_from.tunnel->local_ip != NULL
              && ((SSH_IP_CMP(&rule->side_from.tunnel->local_ip->ip,
                              rule->side_to.ts->items[i].start_address) < 0)
                  || (SSH_IP_CMP(&rule->side_from.tunnel->local_ip->ip,
                                 rule->side_to.ts->items[i].end_address) > 0)))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "Local IP tunnel attribute does not match the "
                            "destination selector given in the rule, this is "
                            "not allowed for transport mode");
              return FALSE;
            }
        }

      for (i = 0;
           rule->side_from.ts != NULL
           && i < rule->side_from.ts->number_of_items_used;
           i++)
        {
          /* If the tunnel specifies peer IP addresses, they must agree with
             that in the traffic selector. */
          for (j = 0; j < rule->side_from.tunnel->num_peers; j++)
            if (SSH_IP_CMP(&rule->side_from.tunnel->peers[j],
                           rule->side_from.ts->items[i].start_address)
                || SSH_IP_CMP(&rule->side_from.tunnel->peers[j],
                              rule->side_from.ts->items[i].end_address))
            {
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "Peer IP tunnel attribute does not match the "
                            "source selector given in rule, this is not "
                            "allowed for transport mode");
              return FALSE;
            }

        }
    }

  return TRUE;
}

#ifdef SSHDIST_IPSEC_NAT
/* Calculate number of IP addresses - 1 from given TS.
   (Including possible holes in the TS.) */
static void
pm_rule_count_ts_distance(SshPm pm,
                          SshIkev2PayloadTS ts,
                          SshXUInt128 target128)
{
  SshIpAddr min_ip;
  SshIpAddr max_ip;
  int i;
  SshXUInt128 first_ip128;
  SshXUInt128 last_ip128;

  min_ip = ts->items[0].start_address;
  max_ip = ts->items[0].end_address;
  for(i = 1; i < ts->number_of_items_used; i++)
    {
      min_ip = SSH_IP_MIN(min_ip, ts->items[i].start_address);
      max_ip = SSH_IP_MAX(max_ip, ts->items[i].end_address);
    }

  SSH_XUINT128_FROM_IP(first_ip128, min_ip);
  SSH_XUINT128_FROM_IP(last_ip128, max_ip);
  SSH_XUINT128_SUB(target128, last_ip128, first_ip128);
}


static Boolean
pm_rule_normalize_and_verify_nat_side(SshPm pm,
                                      SshIkev2PayloadTS ts,
                                      SshIpAddr nat_ip_low,
                                      SshIpAddr nat_ip_high,
                                      SshUInt16 nat_port,
                                      SshPmNatFlags nat_flags,
                                      Boolean is_one_to_one)
{
  SshXUInt128 ts_distance128;
  SshXUInt128 nat_ip_low128;
  SshXUInt128 nat_ip_high128;
  SshIpAddrStruct nat_ip_high_calculated  = { 0 };

  if (!ts)
    {
      if (is_one_to_one)
        {
          /* One-to-one NAT requires a traffic selector. */
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "One-to-One NAT rule without corresponding "
                        "selectors. One-To-One NAT rule always "
                        "requires selectors.");
          return FALSE;
        }
    }

  if (!SSH_IP_DEFINED(nat_ip_low) && SSH_IP_DEFINED(nat_ip_high))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "If you define NAT high bound you always need to "
                    "define the low bound as well.");
      return FALSE;
    }

  if (!SSH_IP_DEFINED(nat_ip_low))
    {
      /* No NAT rules for this traffic direction. */
      return TRUE;
    }

  if (is_one_to_one)
    {
      /* Calculate correct nat_ip_high for one-to-one NAT. */
      pm_rule_count_ts_distance(pm, ts, ts_distance128);

      SSH_XUINT128_FROM_IP(nat_ip_low128, nat_ip_low);
      SSH_XUINT128_ADD(nat_ip_high128, nat_ip_low128, ts_distance128);
      SSH_XUINT128_TO_IP(nat_ip_high128, &nat_ip_high_calculated,
                         SSH_IP_ADDR_LEN(nat_ip_low));
    }

  if (!SSH_IP_DEFINED(nat_ip_high))
    {
      if (is_one_to_one)
        {
          /* Use calculated address */
          *(nat_ip_high) = nat_ip_high_calculated;
        }
      else
        {
          /* Assume size of one target IP address. */
          *(nat_ip_high) = *(nat_ip_low);
        }
    }

  if (SSH_IP_ADDR_LEN(nat_ip_low) != SSH_IP_ADDR_LEN(nat_ip_high))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Invalid NAT IP range.");
      return FALSE;
    }

  if (SSH_IP_CMP(nat_ip_low, nat_ip_high)>0)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Invalid NAT IP range.");
      return FALSE;
    }

  if (is_one_to_one)
    {
      /* Ensure length of one-to-one NAT rule matches calculated
         nat_ip_high. */

      if (SSH_IP_CMP(&nat_ip_high_calculated, nat_ip_high) != 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "The length of traffic selector does not match "
                        "length of one-to-one NAT range.");

          return FALSE;
        }
    }

  return TRUE;
}

/* Normalize NAT portion, ie. derive high IP if required. */
static Boolean
pm_rule_normalize_and_verify_nat(SshPm pm, SshPmRule rule)
{
  Boolean res;
  Boolean src_one_to_one = !!(rule->nat_flags &
                              SSH_PM_NAT_ONE_TO_ONE_SRC);
  Boolean dst_one_to_one = !!(rule->nat_flags &
                              SSH_PM_NAT_ONE_TO_ONE_DST);

  res = pm_rule_normalize_and_verify_nat_side(pm,
                                              rule->side_from.ts,
                                              &(rule->nat_src_low),
                                              &(rule->nat_src_high),
                                              rule->nat_src_port,
                                              rule->nat_flags,
                                              src_one_to_one);

  if (res == FALSE) return FALSE;

  return pm_rule_normalize_and_verify_nat_side(pm,
                                               rule->side_to.ts,
                                               &(rule->nat_dst_low),
                                               &(rule->nat_dst_high),
                                               rule->nat_dst_port,
                                               rule->nat_flags,
                                               dst_one_to_one);
}

#endif /* SSHDIST_IPSEC_NAT */

/* Lookup the rule by its ID. */
SshPmRule
ssh_pm_rule_lookup(SshPm pm, SshUInt32 id)
{
  SshADTHandle handle;
  SshPmRuleStruct probe;

  probe.rule_id = id;

  if (pm->config_additions == NULL
      || (handle =
          ssh_adt_get_handle_to_equal(pm->config_additions, &probe))
      == SSH_ADT_INVALID)
    {
      if (pm->iface_pending_additions == NULL
          || (handle =
              ssh_adt_get_handle_to_equal(pm->iface_pending_additions, &probe))
          == SSH_ADT_INVALID)
        {
          if ((handle =
               ssh_adt_get_handle_to_equal(pm->rule_by_id, &probe))
              == SSH_ADT_INVALID)
            {
              return NULL;
            }
          return ssh_adt_get(pm->rule_by_id, handle);
        }
      return ssh_adt_get(pm->iface_pending_additions, handle);
    }
  return ssh_adt_get(pm->config_additions, handle);
}

SshPmRule
ssh_pm_rule_get_next(SshPm pm, SshPmRule previous_rule)
{
  SshADTHandle h;

  if (!previous_rule)
    h = ssh_adt_enumerate_start(pm->rule_by_id);
  else
    h = ssh_adt_enumerate_next(pm->rule_by_id,
                              (SshADTHandle)&previous_rule->rule_by_index_hdr);

  if (h != SSH_ADT_INVALID)
    return (SshPmRule) ssh_adt_get(pm->rule_by_id, h);
  else
    return NULL;
}


/* Compare rule side specifications for equality. */
static Boolean
pm_rule_side_specification_compare(SshPm pm,
                                   SshPmRuleSideSpecification side1,
                                   SshPmRuleSideSpecification side2)
{
#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (side1->dns_addr_sel_ref && !side2->dns_addr_sel_ref)
    return FALSE;
  if (side2->dns_addr_sel_ref && !side1->dns_addr_sel_ref)
    return FALSE;

  if (!side1->dns_addr_sel_ref)
    {
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      /* Two traffic selectors t1, t2 are considered equal iff t1 is
         a subrange of t2 and t2 is a subrange of t1. */
      if (!ssh_ikev2_ts_match(side1->ts, side2->ts) ||
          !ssh_ikev2_ts_match(side2->ts, side1->ts))
        return FALSE;
#ifdef SSHDIST_IPSEC_DNSPOLICY
    }
  else
    if (!ssh_pm_dns_cache_compare(side1->dns_addr_sel_ref,
                                  side2->dns_addr_sel_ref))
      return FALSE;

  if (side1->dns_ifname_sel_ref && !side2->dns_ifname_sel_ref)
    return FALSE;
  if (side2->dns_ifname_sel_ref && !side1->dns_ifname_sel_ref)
    return FALSE;

  if (!side1->dns_ifname_sel_ref)
    {
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      if (side1->ifname && side2->ifname)
        {
          if (strcmp(side1->ifname, side2->ifname) != 0)
            return FALSE;
        }
      else if (side1->ifname && !side2->ifname)
        return FALSE;
      else if (!side1->ifname && side2->ifname)
        return FALSE;
#ifdef SSHDIST_IPSEC_DNSPOLICY
    }
  else
    if (!ssh_pm_dns_cache_compare(side1->dns_ifname_sel_ref,
                                  side2->dns_ifname_sel_ref))
      return FALSE;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  if ((side1->local_stack && !side2->local_stack)
      || (!side1->local_stack && side2->local_stack))
    return FALSE;

  if ((side1->auto_start && !side2->auto_start)
      || (!side1->auto_start && side2->auto_start))
    return FALSE;

  if (side1->tunnel && side2->tunnel)
    {
      if (!ssh_pm_tunnel_compare(pm, side1->tunnel, side2->tunnel))
        return FALSE;
    }
  else if (side1->tunnel && !side2->tunnel)
    return FALSE;
  else if (!side1->tunnel && side2->tunnel)
    return FALSE;

  /* They are equal. */
  return TRUE;
}

/* Create default match all traffic selectors, if no traffic selectors
   have been set to the rule side specification. */
static Boolean
pm_rule_make_default_traffic_selector(SshPm pm,
                                      Boolean ipv6,
                                      SshPmRuleSideSpecification side)
{
  SshIpAddrStruct start_address, end_address;

  if (side->ts
#ifdef SSHDIST_IPSEC_DNSPOLICY
      || side->dns_addr_sel_ref
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      )
    return TRUE;

  side->ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (side->ts == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate a traffic selector"));
      return FALSE;
    }

  if (ipv6)
    {
#if defined (WITH_IPV6)
      SSH_VERIFY(ssh_ipaddr_parse(&start_address, "0:0:0:0:0:0:0:0"));
      SSH_VERIFY(ssh_ipaddr_parse(&end_address,
                                  "ffff:ffff:ffff:ffff:"
                                  "ffff:ffff:ffff:ffff"));

      if (ssh_ikev2_ts_item_add(side->ts, 0,
                                &start_address, &end_address,
                                0, 0xffff) != SSH_IKEV2_ERROR_OK)
        return FALSE;

#endif /* WITH_IPV6 */
    }
  else
    {
      SSH_VERIFY(ssh_ipaddr_parse(&start_address, "0.0.0.0"));
      SSH_VERIFY(ssh_ipaddr_parse(&end_address, "255.255.255.255"));

      if (ssh_ikev2_ts_item_add(side->ts, 0,
                                &start_address, &end_address,
                                0, 0xffff) != SSH_IKEV2_ERROR_OK)
        return FALSE;
    }

  side->default_ts = 1;

  return TRUE;
}

static Boolean
pm_rule_make_default_traffic_selectors(SshPm pm, SshPmRule rule)
{
  Boolean is6 = FALSE;

#ifdef WITH_IPV6
#ifdef SSHDIST_IPSEC_DNSPOLICY
  /* We cannot set default traffic selectors yet, if we do not know
     address families traffic selectors get resolved to. */
  if ((rule->side_from.dns_addr_sel_ref != NULL
       && rule->side_from.ts == NULL)
      ||
      (rule->side_to.dns_addr_sel_ref != NULL
       && rule->side_to.ts == NULL))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("At least one rule traffic selector remains unresolved, "
                 "not setting default selectors yet for rule id %d",
                 rule->rule_id));
      return TRUE;
    }
#endif /* SSHDIST_IPSEC_DNSPOLICY */
#endif /* WITH_IPV6 */

  if (rule->side_to.ts &&
      rule->side_to.ts->number_of_items_used > 0)
    if (SSH_IP_IS6(rule->side_to.ts->items[0].start_address))
      is6 = TRUE;

  if (!is6 &&
      rule->side_from.ts &&
      rule->side_from.ts->number_of_items_used > 0)
    if (SSH_IP_IS6(rule->side_from.ts->items[0].start_address))
      is6 = TRUE;

  if (!pm_rule_make_default_traffic_selector(pm,
                                             is6,
                                             &rule->side_to))
    return FALSE;

  if (!pm_rule_make_default_traffic_selector(pm,
                                             is6,
                                             &rule->side_from))
    return FALSE;

  return TRUE;
}

/* Return traffic selectors from rule (not copied, do not free) */
Boolean
ssh_pm_rule_get_traffic_selectors(SshPm pm, SshPmRule rule,
                                  Boolean forward,
                                  SshIkev2PayloadTS *local,
                                  SshIkev2PayloadTS *remote)
{
  SshPmRuleSideSpecification src;
  SshPmRuleSideSpecification dst;

  *local = *remote = NULL;

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
  *local = src->ts;
  *remote = dst->ts;

  SSH_DEBUG(SSH_D_MIDOK, ("SA traffic selectors: local=%@, remote=%@",
                          ssh_ikev2_ts_render, *local,
                          ssh_ikev2_ts_render, *remote));
  return TRUE;
}

/************************ Public interface functions ************************/

SshPmRule
ssh_pm_rule_create_internal(SshPm pm, SshUInt32 precedence, SshUInt32 flags,
                            SshPmTunnel from_tunnel,
                            SshPmTunnel to_tunnel,
                            SshPmService service)
{
  SshPmRule rule;
  SshUInt32 i;

  /* Check flags validity. */
  if ((flags & SSH_PM_RULE_REJECT) && (flags & SSH_PM_RULE_PASS))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Both REJECT and PASS defined for a rule");
      return NULL;
    }

  if ((flags & SSH_PM_RULE_REJECT) && to_tunnel)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "To-tunnel specified for a REJECT rule");
      return NULL;
    }

  /* Check tunnels. */
  if (!pm_verify_tunnel(from_tunnel))
    return NULL;
  if (!pm_verify_tunnel(to_tunnel))
    return NULL;

  /* Both set-df and clear-df can not be specified. */
  if ((flags & SSH_PM_RULE_DF_SET) && (flags & SSH_PM_RULE_DF_CLEAR))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Both `set-df' and `clear-df' specified for a rule");
      return NULL;
    }

  /* The adjust-local-address flag needs a remote access client to-tunnel. */
  if (flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS)
    {
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      if (to_tunnel == NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "`adjust-local-address' specified for a rule "
                        "without to-tunnel");
          return NULL;
        }
      else if ((to_tunnel->flags & (SSH_PM_TI_CFGMODE | SSH_PM_TI_L2TP)) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "`adjust-local-address' specified for a rule with a "
                        "to-tunnel that is not a remote access client tunnel");
          return NULL;
        }
#else /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Unsupported flag `adjust-local-address' specified for "
                    "a rule");
      return NULL;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
    }

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if (flags & SSH_PM_RULE_CFGMODE_RULES)
    {
      if (!(flags & SSH_PM_RULE_ADJUST_LOCAL_ADDRESS))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "`adjust-local-address' must be used with "
                        "`cfgmode-rules'");
          return NULL;
        }
      if (from_tunnel != NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "`cfgmode-rules' specified for a rule "
                        "with from-tunnel");
          return NULL;
        }
      if (to_tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "`cfgmode-rules' specified for an IKEv2 rule");
          return NULL;
        }
      if ((to_tunnel->flags & SSH_PM_TI_CFGMODE) == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "`cfgmode-rules' specified for a rule with a "
                        "to-tunnel without config mode client capability");
          return NULL;
        }
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

  rule = ssh_pm_rule_alloc(pm);
  if (rule == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "The maximum number of policy rules reached");
      return NULL;
    }

  ssh_fsm_condition_init(&pm->fsm, &rule->cond);

  for (i = 0; i < SSH_PM_RULE_MAX_ENGINE_RULES; i++)
    rule->rules[i] = SSH_IPSEC_INVALID_INDEX;

  rule->precedence = precedence;
  rule->flags = flags;

  if (from_tunnel != NULL)
    {
      ssh_strncpy(rule->routing_instance_name,
                  from_tunnel->routing_instance_name,
                  SSH_INTERCEPTOR_VRI_NAMESIZE);
      rule->routing_instance_id = from_tunnel->routing_instance_id;
    }
  else if (to_tunnel != NULL)
    {
      ssh_strncpy(rule->routing_instance_name,
                  to_tunnel->routing_instance_name,
                  SSH_INTERCEPTOR_VRI_NAMESIZE);
      rule->routing_instance_id = to_tunnel->routing_instance_id;
    }
  else
    {
      ssh_strncpy(rule->routing_instance_name,
                  SSH_INTERCEPTOR_VRI_NAME_GLOBAL,
                  SSH_INTERCEPTOR_VRI_NAMESIZE);
      rule->routing_instance_id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;
    }

  /* The rule will belong to one future commit batch.  This is just
     the cheapest way to set the flag. */
  rule->flags |= SSH_PM_RULE_I_IN_BATCH;

  if (from_tunnel)
    {
      rule->side_from.tunnel = from_tunnel;
      SSH_PM_TUNNEL_TAKE_REF(rule->side_from.tunnel);
      SSH_PM_TUNNEL_ATTACH_RULE(rule->side_from.tunnel, rule, FALSE);
    }

  if (to_tunnel)
    {
      rule->side_to.tunnel = to_tunnel;
      SSH_PM_TUNNEL_TAKE_REF(rule->side_to.tunnel);
      SSH_PM_TUNNEL_ATTACH_RULE(rule->side_to.tunnel, rule, TRUE);
    }

  /* Service of this rule. */
  if (service)
    {
      rule->service = service;
      service->refcount++;
    }

  /* Init extension selectors to the dont-care values. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      rule->extsel_low[i] = 0;
      rule->extsel_high[i] = 0xffffffff;
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  rule->pm = pm;
  return rule;
}


SshPmRule
ssh_pm_rule_create(SshPm pm,
                   SshUInt32 precedence,
                   SshUInt32 flags,
                   SshPmTunnel from_tunnel,
                   SshPmTunnel to_tunnel,
                   SshPmService service)
{
  SshPmRule rule;

  SSH_ASSERT(precedence < 100000000);

  /* Assert that no internal rule flags are set. */
  SSH_ASSERT((flags & 0xfff00000) == 0);

  rule = ssh_pm_rule_create_internal(pm, precedence, flags,
                                     from_tunnel,
                                     to_tunnel,
                                     service);
  return rule;
}

SshPmRule
ssh_pm_rule_copy(SshPm pm, SshPmRule rule)
{
  SshPmRule copy = NULL;
  char *from_ifname = NULL, *to_ifname = NULL;
#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshPmDnsReference from_dns_asr = NULL, to_dns_asr = NULL;
  SshPmDnsReference from_dns_isr = NULL, to_dns_isr = NULL;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  SshUInt32 *agroups = NULL;

  copy = ssh_pm_rule_create(pm, rule->precedence, rule->flags & 0x000fffff,
                            rule->side_from.tunnel, rule->side_to.tunnel,
                            rule->service);
  if (copy == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot create rule"));
      goto fail;
    }

  if ((rule->side_from.ifname &&
       !(from_ifname = ssh_strdup(rule->side_from.ifname))) ||
#ifdef SSHDIST_IPSEC_DNSPOLICY
      (rule->side_from.dns_addr_sel_ref &&
       !(from_dns_asr = ssh_pm_dns_cache_copy(rule->pm->dnscache,
                                              rule->side_from.dns_addr_sel_ref,
                                              rule))) ||
      (rule->side_from.dns_ifname_sel_ref &&
       !(from_dns_isr = ssh_pm_dns_cache_copy(rule->pm->dnscache,
                                          rule->side_from.dns_ifname_sel_ref,
                                          rule))) ||
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      (rule->side_to.ifname &&
       !(to_ifname = ssh_strdup(rule->side_to.ifname))) ||
#ifdef SSHDIST_IPSEC_DNSPOLICY
      (rule->side_to.dns_addr_sel_ref &&
       !(to_dns_asr = ssh_pm_dns_cache_copy(rule->pm->dnscache,
                                              rule->side_to.dns_addr_sel_ref,
                                              rule))) ||
      (rule->side_to.dns_ifname_sel_ref &&
       !(to_dns_isr = ssh_pm_dns_cache_copy(rule->pm->dnscache,
                                            rule->side_to.dns_ifname_sel_ref,
                                            rule))) ||
#endif /* SSHDIST_IPSEC_DNSPOLICY */
      (rule->access_groups &&
       !(agroups = ssh_calloc(sizeof *agroups, rule->num_access_groups))))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Out of memory when copying rule"));
      goto fail;
    }

#ifdef SSHDIST_IPSEC_SA_EXPORT
  if (rule->application_identifier_len > 0)
    {
      copy->application_identifier =
        ssh_malloc(rule->application_identifier_len);
      if (copy->application_identifier == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Out of memory when copying rule's application "
                     "identifier"));
          goto fail;
        }
      memcpy(copy->application_identifier, rule->application_identifier,
             rule->application_identifier_len);
      copy->application_identifier_len = rule->application_identifier_len;
    }
#endif /* SSHDIST_IPSEC_SA_EXPORT */

#ifdef SSHDIST_IPSEC_NAT
  copy->nat_src_low = rule->nat_src_low;
  copy->nat_src_high = rule->nat_src_high;
  copy->nat_src_port = rule->nat_src_port;
  copy->nat_dst_low = rule->nat_dst_low;
  copy->nat_dst_high = rule->nat_dst_high;
  copy->nat_dst_port = rule->nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */

  copy->side_from.ts = rule->side_from.ts;
  if (copy->side_from.ts)
    ssh_ikev2_ts_take_ref(pm->sad_handle, copy->side_from.ts);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  copy->side_from.dns_addr_sel_ref = from_dns_asr;
  copy->side_from.dns_ifname_sel_ref = from_dns_isr;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  copy->side_from.ifname = from_ifname;
  copy->side_from.local_stack = rule->side_from.local_stack;

  copy->side_to.ts = rule->side_to.ts;
  if (copy->side_to.ts)
    ssh_ikev2_ts_take_ref(pm->sad_handle, copy->side_to.ts);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  copy->side_to.dns_addr_sel_ref = to_dns_asr;
  copy->side_to.dns_ifname_sel_ref = to_dns_isr;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  copy->side_to.ifname = to_ifname;
  copy->side_to.local_stack = rule->side_to.local_stack;
  copy->routing_instance_id = rule->routing_instance_id;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memcpy(copy->extsel_low, rule->extsel_low, sizeof rule->extsel_low);
  memcpy(copy->extsel_high, rule->extsel_high, sizeof rule->extsel_high);
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  copy->num_access_groups = rule->num_access_groups;
  if (rule->access_groups)
    {
      copy->access_groups = agroups;
      memcpy(copy->access_groups, rule->access_groups,
             copy->num_access_groups * sizeof *copy->access_groups);
    }

  return copy;

fail:
  if (agroups)
    ssh_free(agroups);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (to_dns_isr)
    ssh_pm_dns_cache_remove(rule->pm->dnscache, to_dns_isr);
  if (to_dns_asr)
    ssh_pm_dns_cache_remove(rule->pm->dnscache, to_dns_asr);
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  if (to_ifname)
    ssh_free(to_ifname);
#ifdef SSHDIST_IPSEC_DNSPOLICY
  if (from_dns_isr)
    ssh_pm_dns_cache_remove(rule->pm->dnscache, from_dns_isr);
  if (from_dns_asr)
    ssh_pm_dns_cache_remove(rule->pm->dnscache, from_dns_asr);
#endif /* SSHDIST_IPSEC_DNSPOLICY */
  if (from_ifname)
    ssh_free(from_ifname);
  if (copy)
    ssh_pm_rule_free(rule->pm, copy);
  return NULL;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY

#define CLONE_SIDE(r, c, side)                                                \
do {                                                                          \
  if ((r)->side.ifname) (c)->side.ifname = ssh_strdup((r)->side.ifname);      \
  (c)->side.dns_ifname_sel_ref = (r)->side.dns_ifname_sel_ref;                \
  (c)->side.dns_addr_sel_ref = (r)->side.dns_addr_sel_ref;                    \
  (c)->side.local_stack = (r)->side.local_stack;                              \
  (c)->side.auto_start = (r)->side.auto_start;                                \
  (c)->side.as_up = (r)->side.as_up;                                          \
  (c)->side.as_fail_retry = (r)->side.as_fail_retry;                          \
} while (0)

#ifdef SSHDIST_IPSEC_NAT
#define CLONE_NAT(r, c, which)                                          \
do {                                                                    \
  memcpy(&(c)->which ## _low, &(r)->which ## _low, sizeof(SshIpAddrStruct)); \
  memcpy(&(c)->which ##_high, &(r)->which ##_high, sizeof(SshIpAddrStruct)); \
  (c)->which ## _port = (r)-> which ## _port;                           \
  (c)->nat_flags = (r)->nat_flags;                                      \
} while (0)
#endif /* SSHDIST_IPSEC_NAT */

/* Clone the given rule. */
SshPmRule
ssh_pm_rule_clone(SshPm pm, SshPmRule rule)
{
  SshPmRule clone;

  if ((clone =
       ssh_pm_rule_create_internal(pm,
                                   rule->precedence, rule->flags,
                                   rule->side_from.tunnel,
                                   rule->side_to.tunnel,
                                   rule->service)) == NULL)
    return NULL;

#ifdef SSHDIST_IPSEC_NAT
  CLONE_NAT(rule, clone, nat_src);
  CLONE_NAT(rule, clone, nat_dst);
#endif /* SSHDIST_IPSEC_NAT */

  CLONE_SIDE(rule, clone, side_to);
  CLONE_SIDE(rule, clone, side_from);
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memcpy(clone->extsel_low, &rule->extsel_low, sizeof(clone->extsel_low));
  memcpy(clone->extsel_high, &rule->extsel_high, sizeof(clone->extsel_high));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  clone->side_from.ts = rule->side_from.ts;
  clone->side_to.ts = rule->side_to.ts;
  if (rule->side_from.ts)
    ssh_ikev2_ts_take_ref(pm->sad_handle, rule->side_from.ts);
  if (rule->side_to.ts)
    ssh_ikev2_ts_take_ref(pm->sad_handle, rule->side_to.ts);

  clone->rule_id = rule->rule_id;
  clone->flags |= SSH_PM_RULE_I_CLONE;
  ssh_strncpy(clone->routing_instance_name, rule->routing_instance_name,
              SSH_INTERCEPTOR_VRI_NAMESIZE);
  clone->routing_instance_id = rule->routing_instance_id;

  return clone;
}

#endif /* SSHDIST_IPSEC_DNSPOLICY */

#ifdef SSHDIST_IPSEC_DNSPOLICY
Boolean
ssh_pm_rule_set_dns(SshPmRule rule, SshPmRuleSide side,
                    const unsigned char *address)
{
  SshPmRuleSideSpecification side_spec;
  SshPmDnsObjectClass oc;

  if (address == NULL)
    return FALSE;

  if (side == SSH_PM_FROM)
    {
      side_spec = &rule->side_from;
      oc = SSH_PM_DNS_OC_R_LOCAL;
    }
  else
    {
      side_spec = &rule->side_to;
      oc = SSH_PM_DNS_OC_R_REMOTE;
    }

  /* Check that there are no port or protocol traffic selectors encoded
     in the 'address' parameter */
  if (strchr((const char *)address, ','))
    return FALSE;

  side_spec->dns_addr_sel_ref =
    ssh_pm_dns_cache_insert(rule->pm->dnscache, address, oc, rule);

  return side_spec->dns_addr_sel_ref != NULL;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/* Adds a traffic selector constraint to the given rule.  This constrains
   which packets the rule applies to. Only one traffic selector can be
   specified for each side of the rule (it is a fatal error to try to
   add more). This function returns TRUE on success and
   FALSE if the traffic selector could not be parsed. */
Boolean ssh_pm_rule_set_traffic_selector(SshPmRule rule,
                                         SshPmRuleSide side,
                                         const char *traffic_selector)
{
  SshPm pm = rule->pm;
  SshIkev2PayloadTS ts;
  int items;
  char *ts_string;

  ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (ts == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot allocate a traffic selector"));
      return FALSE;
    }

  ts_string = ssh_icmputil_string_to_tsstring(traffic_selector);
  if (ts_string != NULL)
    {
      items = ssh_ikev2_string_to_ts(ts_string, ts);
      ssh_free(ts_string);
    }
  else
    items = ssh_ikev2_string_to_ts(traffic_selector, ts);

  if (items == -1)
    {
      ssh_ikev2_ts_free(pm->sad_handle, ts);
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Input traffic selector is corrupt.");
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse the input traffic selector"));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Traffic selector %s parsed into %d items",
                          traffic_selector, items));

  return ssh_pm_rule_set_ts(rule, side, ts);
}

Boolean ssh_pm_rule_set_ts(SshPmRule rule,
                           SshPmRuleSide side,
                           SshIkev2PayloadTS ts)
{
  return ssh_pm_rule_set_ts_internal(rule, side, ts,
                                   SSH_PM_RULE_TS_CHECK_MULTICAST_SRC);
}

Boolean ssh_pm_rule_set_ts_internal(SshPmRule rule,
                                    SshPmRuleSide side,
                                    SshIkev2PayloadTS ts,
                                    SshUInt32 test_flags)
{
  SshPmRuleSideSpecification side_spec;
  SshPm pm = rule->pm;
  SshIkev2PayloadTSItem to;
  int i = 0;

  if (ts == NULL)
    return FALSE;

#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  if (rule->flags & SSH_PM_RULE_CFGMODE_RULES)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "attempt to specify traffic selector for a "
                    "rule with `cfgmode-rules' set");
      ssh_ikev2_ts_free(pm->sad_handle, ts);
      return FALSE;
    }
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

  if (side == SSH_PM_FROM)
    side_spec = &rule->side_from;
  else
    side_spec = &rule->side_to;

  if (side_spec->ts)
    {
      SSH_DEBUG(SSH_D_FAIL, ("This rule side already has a configured "
                             "traffic selector"));
      ssh_ikev2_ts_free(pm->sad_handle, ts);
      return FALSE;
    }

  /* Sanity check the number of items in the supplied traffic selector */
  if (ts->number_of_items_used > SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS)
    {
      ssh_ikev2_ts_free(pm->sad_handle, ts);
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Input traffic selector contains more than the built in "
                    "maximum number of items. "
                    "Increase the value of "
                    "SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS");
      SSH_DEBUG(SSH_D_FAIL, ("Input traffic selector contains %d items",
                             ts->number_of_items_used));
      return FALSE;
    }

  /* Multicast address is not allowed in source traffic selector.
     This check is skipped for dummy "to-tunnel" multicast rules.
   */
  if ((side == SSH_PM_FROM) &&
      (test_flags & SSH_PM_RULE_TS_CHECK_MULTICAST_SRC))
    {
      for (i = 0; i < ts->number_of_items_used; i++)
        {
          to = &(ts->items[i]);
          if (SSH_IP_IS_MULTICAST(to->start_address)) {
            ssh_ikev2_ts_free(pm->sad_handle, ts);
            ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                          "Multicast address is not allowed as source in "
                          "traffic selectors.");
            return FALSE;
          }
        }
    }

  if (ts->number_of_items_used != 1 &&
      ((rule->side_to.tunnel &&
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
        (rule->flags & SSH_PM_RULE_MULTIHOME) == 0 &&
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
        rule->side_to.tunnel->ike_tn &&
        rule->side_to.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)
       ||
       (rule->side_from.tunnel &&
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
        (rule->flags & SSH_PM_RULE_MULTIHOME) == 0 &&
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
        rule->side_from.tunnel->ike_tn &&
        rule->side_from.tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1)))
    {
      ssh_ikev2_ts_free(pm->sad_handle, ts);
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "IKEv1 tunnels only has traffic selectors with one item.");
      SSH_DEBUG(SSH_D_FAIL, ("Cannot parse the input traffic selector"));
      return FALSE;
    }

  side_spec->ts = ts;
  return TRUE;
}

Boolean
ssh_pm_rule_set_routing_instance(SshPmRule rule,
                                 const char *routing_instance_name)
{
  if (routing_instance_name == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Routing instance name not valid for rule."));
      return FALSE;
    }

  /* The set name should match the routing instance name of the tunnel
     it is attached to, if any. */
  if (rule->side_from.tunnel != NULL)
    {
      if (strcmp(rule->side_from.tunnel->routing_instance_name,
                 routing_instance_name) != 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Rule routing instance name '%s' does not "
                         "match the tunnel with routing instance name '%s'",
                         routing_instance_name,
                         rule->side_from.tunnel->routing_instance_name));
          return FALSE;
        }
    }
  else if (rule->side_to.tunnel != NULL)
    {
      if (strcmp(rule->side_to.tunnel->routing_instance_name,
                 routing_instance_name) != 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Rule routing instance name '%s' does not "
                         "match the tunnel with routing instance name '%s'",
                         routing_instance_name,
                         rule->side_to.tunnel->routing_instance_name));
          return FALSE;
        }
    }
  /* Not attached to a tunnel. Set the given name. */
  else
    {
      ssh_strncpy(rule->routing_instance_name, routing_instance_name,
                  SSH_INTERCEPTOR_VRI_NAMESIZE);

      rule->routing_instance_id = ssh_ip_get_interface_vri_id(&rule->pm->ifs,
                                                 rule->routing_instance_name);
    }

  return TRUE;
}

Boolean
ssh_pm_rule_set_ip(SshPmRule rule, SshPmRuleSide side,
                   const unsigned char *ip_low, const unsigned char *ip_high)
{
  SshPmRuleSideSpecification side_spec;
  SshIpAddrStruct low, high;

  if (side == SSH_PM_FROM)
    side_spec = &rule->side_from;
  else
    side_spec = &rule->side_to;

  if (side_spec->ts)
    {
      SSH_DEBUG(SSH_D_FAIL, ("This rule side already has a configured "
                             "traffic selector"));
      return FALSE;
    }

  side_spec->ts = ssh_ikev2_ts_allocate(rule->pm->sad_handle);
  if (side_spec->ts == NULL)
    return FALSE;

  if (!ssh_ipaddr_parse(&low, ip_low) || !ssh_ipaddr_parse(&high, ip_high))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Malformed IP address range `%s-%s'",
                              ip_low, ip_high));
      return FALSE;
    }

  if (ssh_ikev2_ts_item_add(side_spec->ts, 0, &low, &high, 0, 0xffff)
      != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot create traffic selector."));
      side_spec->ts = NULL;
      return FALSE;
    }

  return TRUE;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
Boolean
ssh_pm_rule_set_interface_from_route(SshPmRule rule,
                                     const unsigned char *remote)
{
  rule->side_from.dns_ifname_sel_ref =
    ssh_pm_dns_cache_insert(rule->pm->dnscache,
                            remote, SSH_PM_DNS_OC_R_INTERFACE, rule);

  return rule->side_from.dns_ifname_sel_ref != NULL;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

Boolean
ssh_pm_rule_set_ifname(SshPmRule rule, const char *ifname)
{
  ssh_free(rule->side_from.ifname);
  rule->side_from.ifname = ssh_strdup(ifname);
  if (rule->side_from.ifname == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not duplicate interface name"));
      return FALSE;
    }

  return TRUE;
}


void
ssh_pm_rule_set_local_stack(SshPmRule rule, SshPmRuleSide side)
{
  SshPmRuleSideSpecification side_spec;

  if (side == SSH_PM_FROM)
    side_spec = &rule->side_from;
  else
    side_spec = &rule->side_to;

  side_spec->local_stack = 1;
}


Boolean
ssh_pm_rule_set_extension(SshPmRule rule, SshUInt32 i,
                          SshUInt32 low, SshUInt32 high)
{
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if (i >= SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS)
    return FALSE;

  rule->extsel_low[i] = low;
  rule->extsel_high[i] = high;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  return TRUE;
}

#ifdef SSHDIST_IPSEC_NAT
void
ssh_pm_rule_set_forced_nat(SshPmRule rule,
                           const SshIpAddr nat_src_low,
                           const SshIpAddr nat_src_high,
                           SshUInt16 nat_src_port,
                           const SshIpAddr nat_dst_low,
                           const SshIpAddr nat_dst_high,
                           SshUInt16 nat_dst_port,
                           SshPmNatFlags nat_flags)

{
  /* Copy forced NAT destination */
  if (nat_src_low)
    rule->nat_src_low = *nat_src_low;
  if (nat_src_high)
    rule->nat_src_high = *nat_src_high;
  rule->nat_src_port = nat_src_port;

  if (nat_dst_low)
    rule->nat_dst_low = *nat_dst_low;
  if (nat_dst_high)
    rule->nat_dst_high = *nat_dst_high;
  rule->nat_dst_port = nat_dst_port;

  rule->nat_flags = nat_flags;
}
#endif /* SSHDIST_IPSEC_NAT */


Boolean
ssh_pm_rule_add_authorization_group_id(SshPm pm, SshPmRule rule,
                                       SshUInt32 group_id)
{
  SshUInt32 *tmp;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding group id %d to the rule %p",
                               (int) group_id, rule));

  tmp = ssh_realloc(rule->access_groups,
                    rule->num_access_groups * sizeof(*tmp),
                    (rule->num_access_groups + 1) * sizeof(*tmp));
  if (tmp == NULL)
    return FALSE;

  rule->access_groups = tmp;
  rule->access_groups[rule->num_access_groups++] = group_id;

  return TRUE;
}

#ifdef SSH_IPSEC_MULTICAST
/* For a to-tunnel rule having destination traffic selector
   as multicast address, make sure that local ip/interface is
   given.
   For a from-tunnel rule having destination traffic selector
   as multicast address, create a dummy to-tunnel rule with
   source traffic selector as the same multicast address. This
   dummy rule is drop rule.
*/
Boolean ssh_pm_multicast_check_and_add_to_tunnel(SshPm pm, SshPmRule rule)
{
  SshPmRule nrule;
  SshIkev2PayloadTSItem to,from;
  SshIkev2PayloadTS to_ts, from_ts;
  int i = 0;
  Boolean existing_rule = FALSE;
  SshUInt32 index;

  /* All to-tunnel rule with multicast traffic selector
     should have local ip/interface. */
  if (rule->side_to.tunnel && rule->side_to.ts)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Validating Multicast Tunnel for local ip/interface"));
      /* Search for Multicast destination address in this rule */
      for (i = 0; i < rule->side_to.ts->number_of_items_used; i++)
       {
         to = &(rule->side_to.ts->items[i]);
         if (SSH_IP_IS_MULTICAST(to->start_address))
           {
             if (rule->side_to.tunnel->num_local_ips == 0
                 && rule->side_to.tunnel->num_local_interfaces == 0)
               {
                 ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                               "Tunnel should have local ip/interface for"
                               " having Multicast traffic selector");
                 return FALSE;
               }
             else
               break;
           }
       }
    }

  if (rule->side_from.tunnel && rule->side_to.ts)
    {
      to_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (to_ts == NULL)
       {
         ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                       "Cannot allocate a traffic selector");
         return FALSE;
       }

      /* Search for Multicast destination address in this rule */
      for (i = 0; i < rule->side_to.ts->number_of_items_used; i++)
       {
         to = &(rule->side_to.ts->items[i]);
         if (SSH_IP_IS_MULTICAST(to->start_address))
           {
             ssh_ikev2_ts_item_add(to_ts, to->proto, to->start_address,
                           to->end_address, to->start_port, to->end_port);
           }
       }
      if (to_ts->number_of_items_used == 0)
       {
         ssh_ikev2_ts_free(pm->sad_handle, to_ts);
         return TRUE;
       }

      from_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
      if (from_ts == NULL)
       {
         ssh_ikev2_ts_free(pm->sad_handle, to_ts);
         ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                       "Cannot allocate a traffic selector");
         return FALSE;
       }

      for (i = 0; i < rule->side_from.ts->number_of_items_used; i++)
       {
         from = &(rule->side_from.ts->items[i]);
         ssh_ikev2_ts_item_add(from_ts, from->proto, from->start_address,
                               from->end_address, from->start_port,
                               from->end_port);
       }

      nrule = ssh_pm_rule_create(pm, rule->precedence, 0 /*DROP*/,
                                NULL, rule->side_from.tunnel, NULL);
      if (nrule == NULL)
       {
         ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                       "Could not create dummy multicast to-tunnel rule.");
         goto error;
       }

      /* We add this special to tunnel rule with source Multicast address,
        so we skip the source Multicast check for this rule by passing
        zero as last parameter*/
      ssh_pm_rule_set_ts_internal(nrule, SSH_PM_FROM, to_ts, 0);

      ssh_pm_rule_set_ts_internal(nrule, SSH_PM_TO, from_ts, 1);
      nrule->routing_instance_id = rule->routing_instance_id;

      index = ssh_pm_rule_add(pm, nrule);
      if (index == SSH_IPSEC_INVALID_INDEX)
       {
         ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                       "Could not add dummy multicast to-tunnel rule.");
         goto error;
       }

    /* check for the already existing rules. */
      {
        SshPmRule temp_rule;
        SshADTHandle handle;

        for (handle = ssh_adt_enumerate_start(pm->rule_by_id);
                                  handle != SSH_ADT_INVALID;
             handle = ssh_adt_enumerate_next(pm->rule_by_id, handle))
         {
           temp_rule = ssh_adt_get(pm->rule_by_id, handle);
           if (ssh_pm_rule_compare(pm, temp_rule->rule_id, index))
             {
               ssh_pm_rule_delete(pm, index);
               existing_rule = TRUE;
               break;
             }
         }
      }
      if (!existing_rule)
        {
          nrule->flags |= SSH_PM_RULE_I_SYSTEM;
          nrule->master_rule = rule;
          rule->sub_rule = nrule;
          SSH_DEBUG(SSH_D_NICETOKNOW,("Created dummy multicast to-tunnel "
                                 "rule (id=%d) for from-tunnel rule (id=%d)",
                                 nrule->rule_id, rule->rule_id ));
        }
    }
  return TRUE;

  error:
  ssh_ikev2_ts_free(pm->sad_handle, to_ts);
  ssh_ikev2_ts_free(pm->sad_handle, from_ts);
  return FALSE;
}
#endif /* SSH_IPSEC_MULTICAST */

#ifdef SSHDIST_IPSEC_SA_EXPORT
Boolean ssh_pm_rule_set_application_identifier(SshPmRule rule,
                                               const unsigned char *id,
                                               size_t id_len)
{
  unsigned char *app_id = NULL;

  if (id_len > SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH)
    return FALSE;

  if (id_len > 0)
    {
      app_id = ssh_malloc(id_len);
      if (app_id == NULL)
        return FALSE;
      memcpy(app_id, id, id_len);
      SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                        ("Setting application identifier to rule '%@':",
                         ssh_pm_rule_render, rule), id, id_len);
    }
  else
    SSH_DEBUG(SSH_D_LOWOK,
              ("Clearing application identifier from rule '%@'",
               ssh_pm_rule_render, rule));

  if (rule->application_identifier)
    ssh_free(rule->application_identifier);
  rule->application_identifier = app_id;
  rule->application_identifier_len = id_len;

  return TRUE;
}

Boolean ssh_pm_rule_get_application_identifier(SshPmRule rule,
                                               unsigned char *id,
                                               size_t *id_len)
{
  if (rule->application_identifier_len > *id_len)
    return FALSE;

  if (rule->application_identifier_len > 0)
    memcpy(id, rule->application_identifier, rule->application_identifier_len);

  *id_len = rule->application_identifier_len;

  return TRUE;
}
#endif /* SSHDIST_IPSEC_SA_EXPORT */


SshUInt32
ssh_pm_rule_add(SshPm pm, SshPmRule rule)
{
  SshEnginePolicyRuleStruct engine_rule;
  SshPmMakeEngineRuleStatus status;
  Boolean interface_not_up = FALSE;
  size_t from_index, to_index;

  /* Sanity check for the rule's traffic selectors. */
  if (!pm_rule_verify_ts_sane(pm, rule))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "The rule's traffic selectors are invalid.");
      return SSH_IPSEC_INVALID_INDEX;
    }

  if (rule->flags & SSH_PM_RULE_PASS_UNMODIFIED)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "The rule's flags are invalid.");





      return SSH_IPSEC_INVALID_INDEX;
    }

#ifdef SSHDIST_IPSEC_NAT
  /* Normalize rule's NAT portion (eg. if only rule low IP
     is set, calculate the high IP. Also, in process of doing that,
     verify sanity of nat rules. */
  if (!pm_rule_normalize_and_verify_nat(pm, rule))
    {
      /* ssh_log_event is done in validator, according to the problem
         met... */
      return SSH_IPSEC_INVALID_INDEX;
    }
#endif /* SSHDIST_IPSEC_NAT */

  /* Check outbound IPSec rules (with to-tunnel set) but which has no
     selectors.  The policy enforcement rule of these rules will
     shadow the outbound trigger and this can create very weird
     problems. */
  if (rule->side_to.tunnel
      && (rule->flags & SSH_PM_RULE_PASS)
      && !SSH_PM_RULE_IS_VIRTUAL_IP(rule)
      && (!pm_rule_has_selectors(&rule->side_to)
          && !pm_rule_has_selectors(&rule->side_from)
          && rule->service == NULL))
    ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_WARNING,
                  "Suspicious outbound IPsec rule without any selectors: "
                  "the rule might not work at all");

  /* Auto-start rules. */
  if (rule->side_to.tunnel != NULL
      && ((rule->side_to.tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
          || (rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) != 0
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
          ))
    {
      rule->side_to.auto_start = 1;

      /* Install inactive trigger rule for auto-start rule, unless it's
         appgw rule. */
      if (!(rule->service && rule->service->appgw_ident))
        rule->flags |= SSH_PM_RULE_I_NO_TRIGGER;

      if (!pm_rule_post_check_auto_start(rule, rule->side_to.tunnel,
                                         &rule->side_to))
        return SSH_IPSEC_INVALID_INDEX;
    }

  if (rule->side_from.tunnel != NULL
      && rule->side_from.tunnel->manual_tn
      && (rule->side_from.tunnel->flags & SSH_PM_TI_DELAYED_OPEN) == 0)
    {
      rule->side_from.auto_start = 1;
      if (!pm_rule_post_check_auto_start(rule, rule->side_from.tunnel,
                                         &rule->side_from))
        return SSH_IPSEC_INVALID_INDEX;
    }

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /* Virtual IP. */
  if (SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    {
      /* The tunnels must specify IKE peer. */
      if (rule->side_to.tunnel->num_peers == 0
#ifdef SSHDIST_IPSEC_DNSPOLICY
          && rule->side_to.tunnel->num_dns_peers == 0
#endif /* SSHDIST_IPSEC_DNSPOLICY */
          )
        /* Explicit IKE peers specified. */
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "No IKE peers specified for virtual IP rule");
          return SSH_IPSEC_INVALID_INDEX;
        }
      /* Install inactive trigger rule for interface-trigger rule. */
      if (rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER)
        rule->flags |= SSH_PM_RULE_I_NO_TRIGGER;
    }
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

  /* Create default match all traffic selectors if no traffic selector
     has been set for the rule sides. */
  if (!pm_rule_make_default_traffic_selectors(pm, rule))
    return SSH_IPSEC_INVALID_INDEX;

#ifdef SSHDIST_IPSEC_DNSPOLICY
  SSH_ASSERT((rule->side_from.ts != NULL ||
              rule->side_from.dns_addr_sel_ref != NULL)
             ||
             (rule->side_to.ts != NULL ||
              rule->side_to.dns_addr_sel_ref != NULL));
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /* Post check for rules. */
  engine_rule.protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  /* Check the status of the engine rules formed from each pair of
     traffic selector items. */
  if (rule->side_to.ts && rule->side_from.ts)
    {
      for (from_index = 0;
           from_index < rule->side_from.ts->number_of_items_used;
           from_index++)
        {
          for (to_index = 0;
               to_index < rule->side_to.ts->number_of_items_used;
               to_index++)
            {
              status = ssh_pm_make_engine_rule(pm, &engine_rule, rule,
                                               rule->side_from.ts, from_index,
                                               rule->side_to.ts, to_index,
                                               FALSE);

              switch (status)
                {
                case PM_ENGINE_RULE_NO_INTERFACE:
                  SSH_DEBUG(SSH_D_HIGHOK, ("Unable to transform rule into "
                                           "engine rule"));
                  interface_not_up = TRUE;
                  break;

                case PM_ENGINE_RULE_OK:
                  SSH_ASSERT(engine_rule.protocol
                             != SSH_PROTOCOL_NUM_PROTOCOLS);
                  break;

                case PM_ENGINE_RULE_FAILED:
                default:
                  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                                "Cannot add rule to engine database");
                  return SSH_IPSEC_INVALID_INDEX;
                }
            }
        }
    }

  if (!pm_rule_post_check_manual_key(pm, rule))
    return SSH_IPSEC_INVALID_INDEX;

#ifdef SSH_IPSEC_MULTICAST
  if (!ssh_pm_multicast_check_and_add_to_tunnel(pm, rule))
    return SSH_IPSEC_INVALID_INDEX;
#endif /* SSH_IPSEC_MULTICAST */

  if (!(rule->flags & SSH_PM_RULE_I_CLONE))
    rule->rule_id = pm->next_rule_id++;
  else
    rule->flags &= ~SSH_PM_RULE_I_CLONE;

  if (interface_not_up)
    {
      /* Add this rule to the list of interface pending rule additions. */
      ssh_adt_insert(pm->iface_pending_additions, rule);
    }
  else
   {
     /* Add this rule to the list of configuration's rule
        additions. When doing this, create container if it does not
        exist. */
     if (pm->config_additions == NULL)
       if ((pm->config_additions =
            ssh_adt_create_generic(SSH_ADT_BAG,
                                   SSH_ADT_HEADER,
                                   SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                                     rule_by_index_add_hdr),
                                   SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                                   SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                                   SSH_ADT_DESTROY, ssh_pm_rule_destroy_adt,
                                   SSH_ADT_CONTEXT, pm,
                                   SSH_ADT_ARGS_END))
           == NULL)
         return SSH_IPSEC_INVALID_INDEX;

     ssh_adt_insert(pm->config_additions, rule);
   }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Add rule with rule_id=%d", rule->rule_id));
  return rule->rule_id;
}


void
ssh_pm_rule_delete(SshPm pm, SshUInt32 rule_id)
{
  SshPmRule rule;
  SshPmRuleStruct probe;
  SshADTHandle handle;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Deleting rule with rule_id=%d", rule_id));

  /* Check if this is a rule that was added in the current
     configuration batch. */

  probe.rule_id = rule_id;

  if (pm->config_additions)
    {
      if ((handle =
           ssh_adt_get_handle_to_equal(pm->config_additions, &probe))
          != SSH_ADT_INVALID)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Deleting rule %d from newly added rules",
                                  (int) rule_id));
          ssh_adt_delete(pm->config_additions, handle);
          return;
        }
    }

  if (pm->iface_pending_additions)
    {
      if ((handle =
           ssh_adt_get_handle_to_equal(pm->iface_pending_additions, &probe))
          != SSH_ADT_INVALID)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Deleting rule %d from if-pending rules",
                                  (int) rule_id));
          ssh_adt_delete(pm->iface_pending_additions, handle);
          return;
        }
    }

  handle = ssh_adt_get_handle_to_equal(pm->rule_by_id, &probe);
  if (handle == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Rule ID %d is unknown",
                             (int) rule_id));
      return;
    }
  rule = ssh_adt_get(pm->rule_by_id, handle);

  /* Add this rule to the list of configuration's rule
     deletions. When doing this, create container if it does not
     exist. */
  if (pm->config_deletions == NULL)
    {
      pm->config_deletions = ssh_adt_create_generic(SSH_ADT_BAG,
                                  SSH_ADT_HEADER,
                                  SSH_ADT_OFFSET_OF(SshPmRuleStruct,
                                                    rule_by_index_del_hdr),
                                  SSH_ADT_HASH, ssh_pm_rule_hash_adt,
                                  SSH_ADT_COMPARE, ssh_pm_rule_compare_adt,
                                  SSH_ADT_CONTEXT, pm,
                                  SSH_ADT_ARGS_END);
      if (pm->config_deletions == NULL)
        return;
    }

  if (ssh_adt_get_handle_to_equal(pm->config_deletions, rule)
      != SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Rule ID %d is already about to be deleted.",
                 (int) rule_id));
      return;
    }

  ssh_adt_insert(pm->config_deletions, rule);
}


Boolean
ssh_pm_rule_compare(SshPm pm, SshUInt32 id1, SshUInt32 id2)
{
  SshPmRule rule1 = ssh_pm_rule_lookup(pm, id1);
  SshPmRule rule2 = ssh_pm_rule_lookup(pm, id2);
  SshUInt32 i;

  if (rule1 == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Trying to compare an unknown rule %d",
                              (int) id1));
      return FALSE;
    }
  if (rule2 == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Trying to compare an unknown rule %d",
                              (int) id2));
      return FALSE;
    }

  /* Compare the rules. */

  if (rule1->precedence != rule2->precedence)
    return FALSE;
  if ((rule1->flags & 0x0000ffff) != (rule2->flags & 0x0000ffff))
    return FALSE;

  if (rule1->service && rule2->service)
    {
      if (!ssh_pm_service_compare(pm, rule1->service, rule2->service))
        return FALSE;
    }
  else if (rule1->service && !rule2->service)
    return FALSE;
  else if (!rule1->service && rule2->service)
    return FALSE;

  /* Access groups. */
  if (rule1->num_access_groups != rule2->num_access_groups)
    return FALSE;
  for (i = 0; i < rule1->num_access_groups; i++)
    if (rule1->access_groups[i] != rule2->access_groups[i])
      return FALSE;

  if (!pm_rule_side_specification_compare(pm, &rule1->side_from,
                                          &rule2->side_from))
    return FALSE;
  if (!pm_rule_side_specification_compare(pm, &rule1->side_to,
                                          &rule2->side_to))
    return FALSE;

#ifdef SSHDIST_IPSEC_NAT
  if ((SSH_IP_DEFINED(&rule1->nat_src_low) ||
       SSH_IP_DEFINED(&rule2->nat_src_low)) &&
      (!SSH_IP_EQUAL(&rule1->nat_src_low, &rule2->nat_src_low) ||
       !SSH_IP_EQUAL(&rule1->nat_src_high, &rule2->nat_src_high)))
    return FALSE;
  if ((SSH_IP_DEFINED(&rule1->nat_dst_low) ||
       SSH_IP_DEFINED(&rule2->nat_dst_low)) &&
      (!SSH_IP_EQUAL(&rule1->nat_dst_low, &rule2->nat_dst_low) ||
       !SSH_IP_EQUAL(&rule1->nat_dst_high, &rule2->nat_dst_high)))
    return FALSE;
  if (rule1->nat_src_port != rule2->nat_src_port)
    return FALSE;
  if (rule1->nat_dst_port != rule2->nat_dst_port)
    return FALSE;
  if (rule1->nat_flags != rule2->nat_flags)
    return FALSE;
#endif /* SSHDIST_IPSEC_NAT */

  /* Check VRF routing instance identifier. */
  if (rule1->routing_instance_id != rule2->routing_instance_id)
    return FALSE;

  /* Check the extension selectors. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
    {
      if (rule1->extsel_low[i] != rule2->extsel_low[i] ||
          rule1->extsel_high[i] != rule2->extsel_high[i])
        return FALSE;
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* They are equal. */
  return TRUE;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
SshPmDnsStatus
pm_rule_get_dns_status(SshPm pm, SshPmRule rule)
{
  SshPmDnsStatus dnsstat = SSH_PM_DNS_STATUS_OK;
  SshPmDnsStatus status = SSH_PM_DNS_STATUS_OK;
  SshPmDnsStatus peer_dnsstat, tmp_stat;
  SshPmTunnelLocalDnsAddress local_dns;
  int i;

  SSH_ASSERT(rule != NULL);

  /* Require all rule DNS names to be valid */
  status = ssh_pm_dns_cache_status(rule->side_from.dns_addr_sel_ref);
  if (status != SSH_PM_DNS_STATUS_ERROR && rule->side_from.ts == NULL)
    status = SSH_PM_DNS_STATUS_ERROR;
  dnsstat |= status;

  status = ssh_pm_dns_cache_status(rule->side_to.dns_addr_sel_ref);
  if (status != SSH_PM_DNS_STATUS_ERROR && rule->side_to.ts == NULL)
    status = SSH_PM_DNS_STATUS_ERROR;
  dnsstat |= status;

  if (rule->side_to.tunnel)
    {
      /* Require tunnel local DNS names to be valid */
      for (local_dns = rule->side_to.tunnel->local_dns_address;
           local_dns != NULL;
           local_dns = local_dns->next)
        {
          status = ssh_pm_dns_cache_status(local_dns->ref);
          if (status != SSH_PM_DNS_STATUS_ERROR
              && !SSH_IP_DEFINED(&local_dns->ip->ip))
            status = SSH_PM_DNS_STATUS_ERROR;
          dnsstat |= status;
        }

      /* Require atleast one tunnel peer DNS name to be valid */
      peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
      for (i = 0; i < rule->side_to.tunnel->num_dns_peers; i++)
        {
          tmp_stat =
            ssh_pm_dns_cache_status(rule->side_to.tunnel->
                                    dns_peer_ip_ref_array[i].ref);
          if (peer_dnsstat > tmp_stat)
            peer_dnsstat = tmp_stat;
        }
      if (i != 0)
        {
          for (i = 0; i < rule->side_to.tunnel->num_peers; i++)
            if (SSH_IP_DEFINED(&rule->side_to.tunnel->peers[i]))
              break;
          if (i == rule->side_to.tunnel->num_peers)
            peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
          dnsstat |= peer_dnsstat;
        }
    }

  if (rule->side_from.tunnel)
    {
      /* Require tunnel local DNS names to be valid */
      for (local_dns = rule->side_from.tunnel->local_dns_address;
           local_dns != NULL;
           local_dns = local_dns->next)
        {
          status = ssh_pm_dns_cache_status(local_dns->ref);
          if (status != SSH_PM_DNS_STATUS_ERROR
              && !SSH_IP_DEFINED(&local_dns->ip->ip))
            status = SSH_PM_DNS_STATUS_ERROR;
          dnsstat |= status;
        }

      /* Require atleast one tunnel peer DNS name to be valid */
      peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
      for (i = 0; i < rule->side_from.tunnel->num_dns_peers; i++)
        {
          tmp_stat =
            ssh_pm_dns_cache_status(rule->side_from.tunnel->
                                    dns_peer_ip_ref_array[i].ref);
          if (peer_dnsstat > tmp_stat)
            peer_dnsstat = tmp_stat;
        }
      if (i != 0)
        {
          for (i = 0; i < rule->side_from.tunnel->num_peers; i++)
            if (SSH_IP_DEFINED(&rule->side_from.tunnel->peers[i]))
              break;
          if (i == rule->side_from.tunnel->num_peers)
            peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
          dnsstat |= peer_dnsstat;
        }
    }

  /* Function returns either SSH_PM_DNS_STATUS_ERROR,
     SSH_PM_DNS_STATUS_STALE, or SSH_PM_DNS_STATUS_OK. */

  if (dnsstat & SSH_PM_DNS_STATUS_ERROR)
    return SSH_PM_DNS_STATUS_ERROR;
  else if (dnsstat & SSH_PM_DNS_STATUS_STALE)
    return SSH_PM_DNS_STATUS_STALE;
  return dnsstat;
}

SshPmDnsStatus
ssh_pm_rule_get_dns_status(SshPm pm, SshUInt32 rule_id)
{
  SshPmRule rule = NULL;
  SshPmRuleStruct probe;
  SshADTHandle handle;

  memset(&probe, 0, sizeof(probe));
  probe.rule_id = rule_id;

  handle = ssh_adt_get_handle_to_equal(pm->rule_by_id, &probe);
  if (handle != SSH_ADT_INVALID)
    {
      rule = ssh_adt_get(pm->rule_by_id, handle);
    }
  else
    {
      handle = ssh_adt_get_handle_to_equal(pm->iface_pending_additions,
                                           &probe);
      if (handle != SSH_ADT_INVALID)
        rule = ssh_adt_get(pm->iface_pending_additions, handle);
    }

  if (rule != NULL)
    return pm_rule_get_dns_status(pm, rule);
  else
    return SSH_PM_DNS_STATUS_ERROR;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

void
ssh_pm_commit(SshPm pm, SshPmStatusCB callback, void *context)
{
  SSH_ASSERT(!pm->config_active);

  /* Make additions/deletions `pending'. */
  ssh_pm_config_make_pending(pm);

  /* Start configuration thread.  It waits until the main thread has
     finished its current commit batch and schedules this batch for
     processing. */
  pm->config_active = 1;
  pm->config_callback = callback;
  pm->config_callback_context = context;

  ssh_fsm_thread_init(&pm->fsm, &pm->config_thread,
                      ssh_pm_st_config_start, NULL_FNPTR, NULL_FNPTR, pm);
  ssh_fsm_set_thread_name(&pm->config_thread, "Config");
}


void
ssh_pm_abort(SshPm pm)
{
  SSH_ASSERT(!pm->config_active);

  SSH_DEBUG(SSH_D_LOWOK, ("PM abort entered"));

  /* Free additions and deletions . */
  if (pm->config_additions)
    ssh_adt_clear(pm->config_additions);

  if (pm->config_deletions)
    ssh_adt_clear(pm->config_deletions);

  ssh_adt_clear(pm->iface_pending_additions);

#ifdef SSH_PM_BLACKLIST_ENABLED
  ssh_pm_blacklist_abort(pm);
#endif /* SSH_PM_BLACKLIST_ENABLED */
}

void
ssh_pm_config_make_pending(SshPm pm)
{
  /* Steal current additions and deletions. */
  pm->config_pending_additions = pm->config_additions;
  pm->config_additions = NULL;
  pm->config_pending_deletions = pm->config_deletions;
  pm->config_deletions = NULL;
}

void
ssh_pm_config_pending_to_batch(SshPm pm)
{
  SshADTHandle handle;
  SshPmRule rule;

  SSH_ASSERT(pm->batch.additions == NULL);
  SSH_ASSERT(pm->batch.deletions == NULL);

  /* Schedule additions, this is done by stealing the configuration
     additions container. */
  pm->batch.additions = pm->config_pending_additions;
  pm->config_pending_additions = NULL;

  /* Convert delete requests into real delete flags.  Also mark that
     the rule belongs to the active batch. */
  if (pm->config_pending_deletions)
    {
      for (handle = ssh_adt_enumerate_start(pm->config_pending_deletions);
           handle != SSH_ADT_INVALID;
           handle = ssh_adt_enumerate_next(pm->config_pending_deletions,
                                           handle))
        {
          rule = ssh_adt_get(pm->config_pending_deletions, handle);
          rule->flags |= (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED);
          SSH_DEBUG(SSH_D_MIDOK, ("Mark rule (id=%d) as deleted",
                                  rule->rule_id));
        }

      /* Mark subrules to be deleted. */
      for (handle = ssh_adt_enumerate_start(pm->config_pending_deletions);
           handle != SSH_ADT_INVALID;
           handle = ssh_adt_enumerate_next(pm->config_pending_deletions,
                                           handle))
        {
          rule = ssh_adt_get(pm->config_pending_deletions, handle);
          for (rule = rule->sub_rule; rule != NULL; rule = rule->sub_rule)
            {
              /* Skip rules already inserted and then encountered by
                 ssh_adt_enumerate_next() above. */
              if (rule->flags & SSH_PM_RULE_I_DELETED)
                continue;
              SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Mark sub rule (id=%d) as deleted",
                         rule->rule_id));
              rule->flags |=
                (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED);
              ssh_adt_insert(pm->config_pending_deletions, rule);
            }
        }
    }

  pm->batch.deletions = pm->config_pending_deletions;
  pm->config_pending_deletions = NULL;
}
