/**
   @copyright
   Copyright (c) 2005 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Engine rule creation for policy and SA rules.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "sshmp-xuint.h"

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshPmRules"

#ifdef  SSHDIST_IPSEC_NAT
/* Calculate number of IP addresses - 1 from given TS.
   (Including possible holes in the TS.) */
static void
pm_erule_get_ts_ips(SshIkev2PayloadTS ts,
                    SshIpAddr first_ip,
                    SshIpAddr last_ip )
{
  SshIpAddr min_ip;
  SshIpAddr max_ip;
  int i;

  min_ip = ts->items[0].start_address;
  max_ip = ts->items[0].end_address;
  for(i = 1; i < ts->number_of_items_used; i++)
    {
      min_ip = SSH_IP_MIN(min_ip, ts->items[i].start_address);
      max_ip = SSH_IP_MAX(max_ip, ts->items[i].end_address);
    }

  *(first_ip) = *(min_ip);
  *(last_ip) = *(max_ip);
}

/* Transform one-to-one NAT according to subset of ip-addresses
   in the whole traffic selector that are matched by the source
   or destination range present in this engine rule. */
static void
pm_erule_nat_one_to_one_truncate(SshIkev2PayloadTS ts,
                                 unsigned char *ip_low_c,
                                 unsigned char *ip_high_c,
                                 SshIpAddr nat_ip_low,
                                 SshIpAddr nat_ip_high)
{
  SshIpAddrStruct ip_low;
  SshIpAddrStruct ip_high;
  SshIpAddrStruct first_ip;
  SshIpAddrStruct last_ip;
  SshXUInt128 distance128;
  SshXUInt128 first_ip128;
  SshXUInt128 last_ip128;
  SshXUInt128 current_ip128;
  SshXUInt128 adjusted_ip128;
  SshXUInt128 temp128;

  /* Get IP addresses from rule. */
  SSH_IP_DECODE(&ip_low, ip_low_c, SSH_IP_ADDR_LEN(nat_ip_low));
  SSH_IP_DECODE(&ip_high, ip_high_c, SSH_IP_ADDR_LEN(nat_ip_low));

  pm_erule_get_ts_ips(ts, &first_ip, &last_ip);

  /* Ensure addresses in the rule are within calculated bounds. */
  SSH_ASSERT(SSH_IP_CMP(&last_ip, &ip_high) >= 0);
  SSH_ASSERT(SSH_IP_CMP(&first_ip, &ip_low) <= 0);

  SSH_XUINT128_FROM_IP(first_ip128, &first_ip);
  SSH_XUINT128_FROM_IP(current_ip128, &ip_low);
  SSH_XUINT128_SUB(distance128, current_ip128, first_ip128);

  /* Tune start of NAT range. */
  SSH_XUINT128_FROM_IP(first_ip128, nat_ip_low);
  SSH_XUINT128_ADD(adjusted_ip128, first_ip128, distance128);
  SSH_XUINT128_TO_IP(adjusted_ip128, nat_ip_low,
                     SSH_IP_ADDR_LEN(nat_ip_low));

  /* Tune the end of NAT range. */
  SSH_XUINT128_FROM_IP(first_ip128, &ip_low);
  SSH_XUINT128_FROM_IP(last_ip128, &ip_high);
  SSH_XUINT128_SUB(distance128, last_ip128, first_ip128);
  SSH_XUINT128_ADD(temp128, adjusted_ip128, distance128);
  SSH_XUINT128_ASSIGN(adjusted_ip128, temp128);
  SSH_XUINT128_TO_IP(adjusted_ip128, nat_ip_high,
                    SSH_IP_ADDR_LEN(nat_ip_low));
}
#endif /* SSHDIST_IPSEC_NAT */

/* Add first item of 'src' and 'dst' traffic selectors into given
   engine rule. */
static Boolean
pm_erule_add_ts(SshEnginePolicyRule erule,
                SshIkev2PayloadTS src, size_t src_item,
                SshIkev2PayloadTS dst, size_t dst_item)
{
  SshIkev2PayloadTSItem item;
  SshUInt8 src_proto = 0;
  size_t len;

  if (src)
    {
      SSH_ASSERT(src_item < src->number_of_items_used);
      item = &src->items[src_item];

      if (item->proto != 0 && item->proto != SSH_IPPROTO_ANY)
        {
          src_proto = item->proto;
          erule->selectors |= SSH_SELECTOR_IPPROTO;
          erule->ipproto = item->proto;
        }

      if (item->start_port != 0 || item->end_port != 65535)
        {
          erule->src_port_low = item->start_port;
          erule->src_port_high = item->end_port;
          erule->selectors |= SSH_SELECTOR_SRCPORT;
        }

      if (SSH_IP_DEFINED(item->start_address))
        {
          if (!SSH_IP_IS_NULLADDR(item->start_address) ||
              !SSH_IP_IS_NULLADDR(item->end_address))
            erule->selectors |= SSH_SELECTOR_SRCIP;

          if (SSH_IP_IS4(item->start_address))
            erule->protocol = SSH_PROTOCOL_IP4;
          else
            erule->protocol = SSH_PROTOCOL_IP6;

          SSH_IP_ENCODE(item->start_address, erule->src_ip_low, len);
          SSH_IP_ENCODE(item->end_address, erule->src_ip_high, len);
        }
    }

  if (dst)
    {
      SSH_ASSERT(dst_item < dst->number_of_items_used);
      item = &dst->items[dst_item];

      if (src_proto && item->proto && src_proto != item->proto)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Inconsistent IP proto in traffic selector"
                                 " %d %d", src_proto, item->proto));
          return FALSE;
        }

      if (item->proto != 0 && item->proto != SSH_IPPROTO_ANY)
        {
          erule->selectors |= SSH_SELECTOR_IPPROTO;
          erule->ipproto = item->proto;
        }

      if (item->start_port != 0 || item->end_port != 65535)
        {
          erule->dst_port_low = item->start_port;
          erule->dst_port_high = item->end_port;
          erule->selectors |= SSH_SELECTOR_DSTPORT;
        }

      if (SSH_IP_DEFINED(item->start_address))
        {
          if (!SSH_IP_IS_NULLADDR(item->start_address) ||
              !SSH_IP_IS_NULLADDR(item->end_address))
            erule->selectors |= SSH_SELECTOR_DSTIP;

          if (SSH_IP_IS4(item->start_address))
            erule->protocol = SSH_PROTOCOL_IP4;
          else
            erule->protocol = SSH_PROTOCOL_IP6;

          SSH_IP_ENCODE(item->start_address, erule->dst_ip_low, len);
          SSH_IP_ENCODE(item->end_address, erule->dst_ip_high, len);
        }
    }

  if ((erule->ipproto == SSH_IPPROTO_ICMP ||
       erule->ipproto == SSH_IPPROTO_IPV6ICMP)
      && ((erule->selectors & SSH_SELECTOR_SRCPORT) ||
          (erule->selectors & SSH_SELECTOR_DSTPORT)))
    {
      SshUInt16 low = 0;
      SshUInt16 high = 0;

      SSH_DEBUG(SSH_D_MY, ("ICMP engine rule : modifiying ports selectors "
                           "so type/code are encoded in the dst port "
                           "src ports=0x%x-0x%x dst ports=0x%x-0x%x",
                           erule->src_port_low, erule->src_port_high,
                           erule->dst_port_low, erule->dst_port_high));

      /* Check consistency of ICMP selectors, different src and dst
         port selectors are not allowed. */
      if (erule->selectors & SSH_SELECTOR_SRCPORT)
        {
          if ((erule->selectors & SSH_SELECTOR_DSTPORT)
              && (erule->src_port_low != erule->dst_port_low
                  || erule->src_port_high != erule->dst_port_high))
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Src port range &d-%d does not match dst %d-%d",
                         erule->src_port_low, erule->src_port_high,
                         erule->dst_port_low, erule->dst_port_high));
              return FALSE;
            }

          /* Clear the src port selectors */
          low = erule->src_port_low;
          high = erule->src_port_high;
          erule->src_port_low = 0;
          erule->src_port_high = 0;
        }

      /* If the src port selectors were set but not the dst port selectors,
         then copy the src port selectors to dst port selectors. */
      if ((erule->selectors & SSH_SELECTOR_DSTPORT) == 0)
        {
          erule->dst_port_low = low;
          erule->dst_port_high = high;
        }

      /* Do we have a ICMP type selector? i.e. a specific value for the
         ICMP type. */
      if (((erule->dst_port_low >> 8) & 0xff) ==
          ((erule->dst_port_high >> 8) & 0xff))
        erule->selectors |= SSH_SELECTOR_ICMPTYPE;

      /* Do we have a ICMP code selector? i.e. a specific value for the
         ICMP code. */
      if ((erule->dst_port_low & 0xff) ==
          (erule->dst_port_high & 0xff))
        erule->selectors |= SSH_SELECTOR_ICMPCODE;

      /* Clear src port selector flag and set dst port selector flag. */
      erule->selectors &= ~SSH_SELECTOR_SRCPORT;
      erule->selectors |= SSH_SELECTOR_DSTPORT;
    }

  return TRUE;
}


/* Convert high-level rule `rule' into an engine rule.  The rule is
   created to `erule' which is allocated by the caller.  The argument
   `enforcement' specifies whether this rule is the policy enforcement
   rule (trigger's reverse drop rule) or implementation rule.  The
   function returns TRUE if the engine rule could be created or FALSE
   if the system did not have enough information (interface
   information is unavailable or a required interface is missing). */
SshPmMakeEngineRuleStatus
ssh_pm_make_engine_rule(SshPm pm, SshEnginePolicyRule erule, SshPmRule rule,
                        SshIkev2PayloadTS local_ts, size_t local_index,
                        SshIkev2PayloadTS remote_ts, size_t remote_index,
                        Boolean enforcement)
{
  SshPmRuleSideSpecification src, dst;
  Boolean passby;

  memset(erule, 0, sizeof(*erule));
  erule->transform_index = SSH_IPSEC_INVALID_INDEX;
  erule->depends_on = SSH_IPSEC_INVALID_INDEX;
  erule->ipproto = SSH_IPPROTO_ANY;
  erule->protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  /* Policy enforcement rules must be at a higher precedence level
     since otherwise we could have ambiguous rules at the same
     precedence level. */
  if (enforcement)
    erule->precedence = SSH_PM_SA_PRECEDENCE(rule);
  else
    erule->precedence = SSH_PM_RULE_PRECEDENCE(rule);

  if (enforcement)
    {
      /* Policy enformcement rule in reverse direction dropping any
         plain-text traffic. */
      SSH_ASSERT(rule->flags & SSH_PM_RULE_PASS);
      SSH_ASSERT(rule->side_to.tunnel != NULL);
      dst = &rule->side_from;
      src = &rule->side_to;
      passby = FALSE;
    }
  else
    {
      src = &rule->side_from;
      dst = &rule->side_to;
      passby = rule->flags & SSH_PM_RULE_PASS;
    }

  if (rule->side_from.local_stack)
    {
      if (!enforcement)
        erule->selectors |= SSH_SELECTOR_FROMLOCAL;
      else
        erule->selectors |= SSH_SELECTOR_TOLOCAL;
    }
  if (rule->side_to.local_stack)
    {
      if (!enforcement)
        erule->selectors |= SSH_SELECTOR_TOLOCAL;
      else
        erule->selectors |= SSH_SELECTOR_FROMLOCAL;
    }

  if (enforcement)
    {
      /* The policy enformcement rules are in the global rule-set. */
    }
  else
    {
      /* If the source tunnel is specified, we are inserted in the
         tunnel's ingress filter rule set. */
      if (src->tunnel)
        erule->tunnel_id = src->tunnel->tunnel_id;
    }

  /* Add traffic selectors to engine rule */
  if (!pm_erule_add_ts(erule, local_ts, local_index, remote_ts, remote_index))
    return PM_ENGINE_RULE_FAILED;

  /* The protocol is mandatory.  Let's default to IPv4 unless addresses
     specify something else. */
  if (erule->protocol == SSH_PROTOCOL_NUM_PROTOCOLS)
    erule->protocol = SSH_PROTOCOL_IP4;

  /* Interface number for the source side. */
  if (src->ifname)
    {
      SshUInt32 ifnum;

      if (ssh_pm_find_interface(pm, src->ifname, &ifnum) == NULL)
        {
          /* The interface is not known.  We can not create this
             rule before the interface comes up. */
          return PM_ENGINE_RULE_NO_INTERFACE;
        }
      erule->selectors |= SSH_SELECTOR_IFNUM;
      erule->selector_ifnum = (SshEngineIfnum) ifnum;
    }

  if (rule->routing_instance_id >= 0)
    {
      erule->selectors |= SSH_SELECTOR_RIID;
    }
  erule->routing_instance_id = rule->routing_instance_id;

  /* Extension selectors. */
  ssh_pm_set_extension_selectors(rule, erule);

  /* Flow timeout and lifetime values. */
  erule->flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  erule->flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  erule->flow_max_lifetime = 0;

  /* The type of the rule. */
  if (passby)
    {
      if (dst->tunnel)
        {
#ifdef SSHDIST_IPSEC_NAT
          /* If this is an APPGW trigger rule we must do this. */
          if (dst->tunnel->flags & SSH_PM_T_PORT_NAT)
            erule->flags |= SSH_PM_ENGINE_RULE_TT_NAT;
#endif /* SSHDIST_IPSEC_NAT */

          if (dst->tunnel->flags & SSH_PM_TI_DONT_INITIATE)
            erule->type = SSH_ENGINE_RULE_DROP;
          else
            {
              erule->flags |= SSH_PM_ENGINE_RULE_TOTUNNEL;
              erule->type = SSH_ENGINE_RULE_TRIGGER;

              if (rule->service != NULL && rule->service->appgw_ident != NULL)
                {
                  erule->flags |= SSH_PM_ENGINE_RULE_FLOW_REF;
                  erule->flags |= SSH_PM_ENGINE_RULE_APPGW;
                  erule->flags |= SSH_ENGINE_RULE_UNDEFINED;
                }
            }
        }
      else
        {
          /* Check if we need an application gateway trigger. */
          if (rule->service && rule->service->appgw_ident)
            {
              erule->type = SSH_ENGINE_RULE_TRIGGER;
              erule->flags |= SSH_PM_ENGINE_RULE_FLOW_REF;
              erule->flags |= SSH_PM_ENGINE_RULE_APPGW;
            }
          else
            erule->type = SSH_ENGINE_RULE_PASS;
        }
    }
  else if (enforcement)
    {
      /* Policy enforcement by dropping plain-text traffic. */
      erule->type = SSH_ENGINE_RULE_DROP;
    }
  else if (rule->flags & SSH_PM_RULE_REJECT)
    {
      erule->type = SSH_ENGINE_RULE_REJECT;
    }
  else
    {
      erule->type = SSH_ENGINE_RULE_DROP;
    }

#ifdef SSHDIST_IPSEC_NAT
  /* Forced source NAT */
  if (SSH_IP_DEFINED(&rule->nat_src_low))
    {
      erule->nat_src_ip_low = rule->nat_src_low;
      erule->nat_src_ip_high = rule->nat_src_high;
      erule->nat_src_port = rule->nat_src_port;
      erule->nat_flags = rule->nat_flags;
      erule->flags |= SSH_ENGINE_RULE_FORCE_NAT_SRC;

      if ((erule->protocol == SSH_PROTOCOL_IP4
           && ((!SSH_IP_IS4(&erule->nat_src_ip_low)) ||
               (!SSH_IP_IS4(&erule->nat_src_ip_high))))
          || (erule->protocol == SSH_PROTOCOL_IP6
              && ((!SSH_IP_IS6(&erule->nat_src_ip_low)) ||
                  (!SSH_IP_IS6(&erule->nat_src_ip_high)))))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("forced nat protocol type does not match rule protocol"));

          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "  Cannot insert this rule, the forced NAT protocol"
                        " type does not match rule protocol");
          return PM_ENGINE_RULE_FAILED;
        }

      if ((erule->nat_flags & SSH_PM_NAT_ONE_TO_ONE_SRC))
        {
          /* Sensible one-to-one source NAT rule needs source
             matching selector to be present. */
          SSH_ASSERT((erule->selectors & SSH_SELECTOR_SRCIP));

          /* Truncate rule range according to source range
             present in this engine rule. */
          pm_erule_nat_one_to_one_truncate(local_ts,
                                           erule->src_ip_low,
                                           erule->src_ip_high,
                                           &erule->nat_src_ip_low,
                                           &erule->nat_src_ip_high);
        }
    }
  /* Forced destination NAT */
  if (SSH_IP_DEFINED(&rule->nat_dst_low))
    {
      erule->nat_dst_ip_low = rule->nat_dst_low;
      erule->nat_dst_ip_high = rule->nat_dst_high;
      erule->nat_dst_port = rule->nat_dst_port;
      erule->nat_flags = rule->nat_flags;
      erule->flags |= SSH_ENGINE_RULE_FORCE_NAT_DST;
      if ((erule->protocol == SSH_PROTOCOL_IP4
           && ((!SSH_IP_IS4(&erule->nat_dst_ip_low)) ||
               (!SSH_IP_IS4(&erule->nat_dst_ip_high))))
          || (erule->protocol == SSH_PROTOCOL_IP6
              && ((!SSH_IP_IS6(&erule->nat_dst_ip_low)) ||
                  (!SSH_IP_IS6(&erule->nat_dst_ip_high)))))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("forced nat protocol type does not match rule protocol"));

          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "  Cannot insert this rule, the forced NAT protocol"
                        " type does not match the rule protocol");
          return PM_ENGINE_RULE_FAILED;
        }

      if ((erule->nat_flags & SSH_PM_NAT_ONE_TO_ONE_DST))
        {
          /* Sensible one-to-one destination NAT rule needs destination
             matching selector to be present. */
          SSH_ASSERT((erule->selectors & SSH_SELECTOR_DSTIP));

          /* Truncate rule range according to source range
             present in this engine rule. */
          pm_erule_nat_one_to_one_truncate(remote_ts,
                                           erule->dst_ip_low,
                                           erule->dst_ip_high,
                                           &erule->nat_dst_ip_low,
                                           &erule->nat_dst_ip_high);
        }
    }

#endif /* SSHDIST_IPSEC_NAT */

  /* Rule flags. */

  if (rule->flags & SSH_PM_RULE_NO_FLOW || enforcement)
    erule->flags |= SSH_ENGINE_NO_FLOW;
  if (rule->flags & SSH_PM_RULE_LOG)
    erule->flags |= SSH_ENGINE_LOG_CONNECTIONS;
  if (rule->flags & SSH_PM_RULE_RATE_LIMIT)
    erule->flags |= SSH_ENGINE_RATE_LIMIT;





  /* All batch additions are forward rules */
  erule->flags |= SSH_PM_ENGINE_RULE_FORWARD;

  /* And store our policy context.  It is a pointer to our high-level
     rule. */
  erule->policy_context = rule;

  if (erule->type == SSH_ENGINE_RULE_TRIGGER && rule->service != NULL
      && erule->ipproto == SSH_IPPROTO_UDP
      && rule->service->appgw_ident != NULL)
    erule->flow_idle_datagram_timeout =
      SSH_ENGINE_DEFAULT_UDP_APPGW_TRIGGER_TIMEOUT;

  return PM_ENGINE_RULE_OK;
}

/* Create a traffic selector the inner tunnel IKE traffic. */

SshIkev2PayloadTS
ssh_pm_calculate_inner_ike_ts(SshPm pm,
                              SshIkev2PayloadTS policy_ts,
                              SshUInt16 ike_port,
                              SshUInt16 ike_natt_port)
{
  SshIkev2PayloadTS ike_ts = NULL, result_ts = NULL;
  SshIpAddrStruct start_address, end_address;
  SshUInt16 start_port, end_port;

  SSH_ASSERT(policy_ts->number_of_items_used > 0);

  /* Create all zeros address of the same address family. */
  ssh_ipaddr_set_bits(&start_address, policy_ts->items[0].start_address,
                      0, 0);
  /* Create all f's address of the same address family. */
  ssh_ipaddr_set_bits(&end_address, policy_ts->items[0].start_address, 0, 1);

  /* Allocate traffic selector for IKE. */
  ike_ts = ssh_ikev2_ts_allocate(pm->sad_handle);
  if (ike_ts == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate traffic selector"));
      goto out;
    }

  /* Add item for normal IKE port. */
  if (ike_port != 0)
    {
      start_port = ike_port;
      end_port = ike_port;
    }
  else
    {
      start_port = 0;
      end_port = 0xffff;
    }
  if (ssh_ikev2_ts_item_add(ike_ts, SSH_IPPROTO_UDP,
                            &start_address, &end_address,
                            start_port, end_port)
      != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create IKE traffic selector"));
      goto out;
    }

  /* Add item for NAT-T IKE port. */
  if (ike_natt_port != 0)
    {
      start_port = ike_natt_port;
      end_port = ike_natt_port;

      if (ssh_ikev2_ts_item_add(ike_ts, SSH_IPPROTO_UDP,
                                &start_address, &end_address,
                                start_port, end_port)
          != SSH_IKEV2_ERROR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not create IKE NAT-T traffic selector"));
          goto out;
        }
    }

  /* Narrow IKE traffic selector. */
  if (!ssh_ikev2_ts_narrow(pm->sad_handle, FALSE,
                           &result_ts, ike_ts, policy_ts))
    {
      SSH_ASSERT(result_ts == NULL);
      SSH_DEBUG(SSH_D_MIDOK,
                ("IKE traffic selector narrowed to empty traffic selector"));
    }
  else
    {
      ssh_pm_ts_max_enforce(pm->sad_handle, &result_ts);
      SSH_DEBUG(SSH_D_MIDOK, ("IKE traffic selector narrowed to %@",
                              ssh_ikev2_ts_render, result_ts));
    }

 out:
  if (ike_ts)
    ssh_ikev2_ts_free(pm->sad_handle, ike_ts);

  /* Return narrowed IKE traffic selector. */
  return result_ts;
}


/* Create a trigger rule for the inner tunnel IKE traffic. */

SshPmMakeEngineRuleStatus
ssh_pm_make_inner_ike_trigger_rule(SshPm pm, SshEnginePolicyRule erule,
                                   SshIkev2PayloadTS local_ts,
                                   size_t local_index,
                                   SshIkev2PayloadTS remote_ts,
                                   size_t remote_index,
                                   SshUInt32 precedence,
                                   Boolean from_local,
                                   SshPmRule policy_context)
{
  /* Initialize engine rule. */
  memset(erule, 0, sizeof(*erule));
  erule->transform_index = SSH_IPSEC_INVALID_INDEX;
  erule->depends_on = SSH_IPSEC_INVALID_INDEX;
  erule->ipproto = SSH_IPPROTO_ANY;
  erule->protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  /* Timeout and lifetime values for flows. */
  erule->flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  erule->flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  erule->flow_max_lifetime = 0;

  /* Add traffic selectors to engine rule */
  if (!pm_erule_add_ts(erule, local_ts, local_index, remote_ts, remote_index))
    return PM_ENGINE_RULE_FAILED;

  SSH_ASSERT(erule->protocol != SSH_PROTOCOL_NUM_PROTOCOLS);

  /* Set rule type and flags. */
  erule->type = SSH_ENGINE_RULE_TRIGGER;
  erule->flags |= SSH_PM_ENGINE_RULE_TOTUNNEL;
  erule->flags |= SSH_ENGINE_NO_FLOW;

  erule->flags |= SSH_PM_ENGINE_RULE_FORWARD;

  if (from_local)
    erule->selectors |= SSH_SELECTOR_FROMLOCAL;

  /* Assert that the precedence is higher than the default
     IKE passby rules' precedence */
  SSH_ASSERT(precedence >= SSH_PM_RULE_PRI_USER_HIGH);
  erule->precedence = precedence;

  erule->policy_context = policy_context;

  return PM_ENGINE_RULE_OK;
}

Boolean
ssh_pm_make_inner_ike_outbound_apply_rule(SshPm pm, SshEnginePolicyRule erule,
                                          SshIkev2PayloadTS local_ts,
                                          size_t local_index,
                                          SshIkev2PayloadTS remote_ts,
                                          size_t remote_index,
                                          SshUInt32 transform_index,
                                          SshUInt32 dependent_rule_index,
                                          SshUInt32 precedence,
                                          Boolean from_local,
                                          Boolean forward,
                                          SshPmRule policy_context)
{
  /* Initialize engine rule. */
  memset(erule, 0, sizeof(*erule));
  erule->transform_index = SSH_IPSEC_INVALID_INDEX;
  erule->depends_on = SSH_IPSEC_INVALID_INDEX;
  erule->ipproto = SSH_IPPROTO_ANY;
  erule->protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  /* Timeout and lifetime values for flows. */
  erule->flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  erule->flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  erule->flow_max_lifetime = 0;

  /* Add traffic selectors to engine rule */
  if (!pm_erule_add_ts(erule, local_ts, local_index, remote_ts, remote_index))
    return PM_ENGINE_RULE_FAILED;

  SSH_ASSERT(erule->protocol != SSH_PROTOCOL_NUM_PROTOCOLS);

  /* Set rule type and flags. */
  erule->type = SSH_ENGINE_RULE_APPLY;
  erule->flags |= SSH_PM_ENGINE_RULE_TOTUNNEL;
  erule->flags |= SSH_ENGINE_NO_FLOW;
  erule->flags |= SSH_PM_ENGINE_RULE_SA_OUTBOUND;

  if (forward)
    erule->flags |= SSH_PM_ENGINE_RULE_FORWARD;

  if (from_local)
    erule->selectors |= SSH_SELECTOR_FROMLOCAL;

  erule->transform_index = transform_index;
  erule->depends_on = dependent_rule_index;

  /* Assert that the precedence is higher than the default
     IKE passby rules' precedence */
  SSH_ASSERT(precedence >= SSH_PM_RULE_PRI_USER_HIGH);
  erule->precedence = precedence;

  erule->policy_context = policy_context;

  return TRUE;
}

Boolean
ssh_pm_make_inner_ike_inbound_pass_rule(SshPm pm, SshEnginePolicyRule erule,
                                        SshIkev2PayloadTS local_ts,
                                        size_t local_index,
                                        SshIkev2PayloadTS remote_ts,
                                        size_t remote_index,
                                        SshUInt32 inbound_tunnel_id,
                                        SshUInt32 precedence,
                                        Boolean to_local,
                                        SshPmRule policy_context)
{
  /* Initialize engine rule. */
  memset(erule, 0, sizeof(*erule));
  erule->transform_index = SSH_IPSEC_INVALID_INDEX;
  erule->depends_on = SSH_IPSEC_INVALID_INDEX;
  erule->ipproto = SSH_IPPROTO_ANY;
  erule->protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

  /* Timeout and lifetime values for flows. */
  erule->flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  erule->flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  erule->flow_max_lifetime = 0;

  /* Add traffic selectors to engine rule.
     Use remote as src and local as dst. */
  if (!pm_erule_add_ts(erule, remote_ts, remote_index, local_ts, local_index))
    return PM_ENGINE_RULE_FAILED;

  SSH_ASSERT(erule->protocol != SSH_PROTOCOL_NUM_PROTOCOLS);

  /* Set rule type and flags. */
  erule->type = SSH_ENGINE_RULE_PASS;
  erule->flags |= SSH_ENGINE_NO_FLOW;

  erule->flags |= SSH_PM_ENGINE_RULE_FORWARD;

  if (to_local)
    erule->selectors |= SSH_SELECTOR_TOLOCAL;

  SSH_ASSERT(inbound_tunnel_id > 1);
  erule->tunnel_id = inbound_tunnel_id;

  /* Assert that the precedence is higher than the default
     IKE passby rules' precedence */
  SSH_ASSERT(precedence >= SSH_PM_RULE_PRI_USER_HIGH);
  erule->precedence = precedence;

  erule->policy_context = policy_context;

  return TRUE;
}

/* Create an outbound SA rule for the Quick-Mode negotiation done with
   the rule `rule'.  The argument `forward' specifies the direction of
   the rule `rule' that is used in the negotiation.  This does not set
   transform index of the rule `rule'.  */

Boolean
ssh_pm_make_sa_outbound_rule(SshPm pm,
                             SshPmQm qm,
                             Boolean forward, SshPmRule rule,
                             SshIkev2PayloadTS local_ts, size_t local_index,
                             SshIkev2PayloadTS remote_ts, size_t remote_index,
                             SshEnginePolicyRule engine_rule)
{
  SshPmTunnel from_tunnel, to_tunnel;
  SshIkev2PayloadTSItem local_tsitem, remote_tsitem;
  SshInterceptorProtocol protocol_src = SSH_PROTOCOL_NUM_PROTOCOLS;
  SshInterceptorProtocol protocol_dst = SSH_PROTOCOL_NUM_PROTOCOLS;
  SshInetIPProtocolID ipproto;

  memset(engine_rule, 0, sizeof(*engine_rule));

  /* Traffic seletors. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Traffic selectors: local=%@ [%d], remote=%@ [%d]",
             ssh_ikev2_ts_render, local_ts, local_index,
             ssh_ikev2_ts_render, remote_ts, remote_index));

  engine_rule->precedence = SSH_PM_SA_PRECEDENCE(rule);

  SSH_ASSERT(local_ts != NULL);
  SSH_ASSERT(remote_ts != NULL);
  SSH_ASSERT(local_index < local_ts->number_of_items_used);
  SSH_ASSERT(remote_index < remote_ts->number_of_items_used);

  if (forward)
    engine_rule->flags |= SSH_PM_ENGINE_RULE_FORWARD;

  local_tsitem = &local_ts->items[local_index];
  remote_tsitem = &remote_ts->items[remote_index];

  /* Source IP address range. */
  if (local_tsitem->ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
    protocol_src = SSH_PROTOCOL_IP4;
  else
    protocol_src = SSH_PROTOCOL_IP6;

  if (protocol_src == SSH_PROTOCOL_IP4)
    {
      SSH_IP4_ENCODE(local_tsitem->start_address, engine_rule->src_ip_low);
      SSH_IP4_ENCODE(local_tsitem->end_address, engine_rule->src_ip_high);
    }
  else
    {
      SSH_IP6_ENCODE(local_tsitem->start_address, engine_rule->src_ip_low);
      SSH_IP6_ENCODE(local_tsitem->end_address, engine_rule->src_ip_high);
    }
  /* If the selector specified a null-address, convert it into a
     match-all IP address range.  We need to check only the
     high-end of the proxy ID since ip_low <= ip_high. */
  if (SSH_IP_IS_NULLADDR(local_tsitem->end_address))
    memset(engine_rule->src_ip_high, 0xff, SSH_IP_ADDR_SIZE);

  /* Source IP selector set. */
  engine_rule->selectors |= SSH_SELECTOR_SRCIP;

  /* Destination IP address range. */
  if (remote_tsitem->ts_type == SSH_IKEV2_TS_IPV4_ADDR_RANGE)
    protocol_dst = SSH_PROTOCOL_IP4;
  else
    protocol_dst = SSH_PROTOCOL_IP6;

  if (protocol_dst == SSH_PROTOCOL_IP4)
    {
      SSH_IP4_ENCODE(remote_tsitem->start_address, engine_rule->dst_ip_low);
      SSH_IP4_ENCODE(remote_tsitem->end_address, engine_rule->dst_ip_high);
    }
  else
    {
      SSH_IP6_ENCODE(remote_tsitem->start_address, engine_rule->dst_ip_low);
      SSH_IP6_ENCODE(remote_tsitem->end_address, engine_rule->dst_ip_high);
    }
  /* If the selector specified a null-address, convert it into a
     match-all IP address range.  We need to check only the
     high-end of the proxy ID since ip_low <= ip_high. */
  if (SSH_IP_IS_NULLADDR(remote_tsitem->end_address))
    memset(engine_rule->dst_ip_high, 0xff, SSH_IP_ADDR_SIZE);

  /* Destination IP selector set. */
  engine_rule->selectors |= SSH_SELECTOR_DSTIP;

  /* Set port number selectors. */
  if (local_tsitem->start_port > 0 || local_tsitem->end_port < 0xffff)
    {
      engine_rule->src_port_low = local_tsitem->start_port;
      engine_rule->src_port_high = local_tsitem->end_port;
      engine_rule->selectors |= SSH_SELECTOR_SRCPORT;
    }

  if (remote_tsitem->start_port > 0 || remote_tsitem->end_port < 0xffff)
    {
      engine_rule->dst_port_low = remote_tsitem->start_port;
      engine_rule->dst_port_high = remote_tsitem->end_port;
      engine_rule->selectors |= SSH_SELECTOR_DSTPORT;
    }

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Use the IKE peer as destination selector for transport mode when
     the peer is behind NAT. */
  if (qm->p1 != NULL &&
      qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT &&
      qm->transport_sent &&
      qm->transport_recv)
    {
      SshIpAddr remote_ip;

      remote_ip = &qm->sa_handler_data.trd.data.gw_addr;

#ifdef SSHDIST_IKEV1
      if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
          if (SSH_IP_IS4(remote_ip))
            {
              SSH_IP4_ENCODE(remote_ip, engine_rule->dst_ip_low);
              SSH_IP4_ENCODE(remote_ip, engine_rule->dst_ip_high);
              protocol_dst = SSH_PROTOCOL_IP4;
            }
          else
            {
              SSH_IP6_ENCODE(remote_ip, engine_rule->dst_ip_low);
              SSH_IP6_ENCODE(remote_ip, engine_rule->dst_ip_high);
              protocol_dst = SSH_PROTOCOL_IP6;
            }

          engine_rule->selectors |= SSH_SELECTOR_DSTIP;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("IKEv1 peer is behind NAT and transport mode used, "
                     "using IKE peer ip %@ as destination selector",
                     ssh_ipaddr_render, remote_ip));
        }
#endif /* SSHDIST_IKEV1 */

      if (qm->sa_handler_data.trd.data.transform & SSH_PM_IPSEC_L2TP)
        {
          SSH_ASSERT(qm->transport_sent && qm->transport_recv);

          /* Do a destination NAT to the original transport mode
             address. This should patch up the PORT number for
             outbound traffic to such a value that the remote
             endpoint will accept this. */
          engine_rule->nat_dst_ip_low = *remote_ip;
          engine_rule->nat_dst_ip_high = *remote_ip;
          engine_rule->nat_dst_port = engine_rule->dst_port_low;

          /* Grab a random selector for the traffic */
          engine_rule->nat_selector_dst_ip = *remote_ip;
          engine_rule->nat_selector_dst_port = 0;

          engine_rule->flags |= SSH_ENGINE_RULE_FORCE_NAT_DST;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("L2tp NAT-T connection coming in, applying "
                     "internal NAT-to"));
        }
    }

#ifdef SSHDIST_IKEV1
  /* Use the IKE local IP as source selector for transport mode when
     the local end is behind NAT. */
  if (qm->p1 != NULL &&
      qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT &&
      qm->transport_sent &&
      qm->transport_recv)
    {
      if (qm->p1->ike_sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
        {
          SshIpAddr local_ip;

          local_ip = &qm->sa_handler_data.trd.data.own_addr;

          if (SSH_IP_IS4(local_ip))
            {
              SSH_IP4_ENCODE(local_ip, engine_rule->src_ip_low);
              SSH_IP4_ENCODE(local_ip, engine_rule->src_ip_high);
              protocol_src = SSH_PROTOCOL_IP4;
            }
          else
            {
              SSH_IP6_ENCODE(local_ip, engine_rule->src_ip_low);
              SSH_IP6_ENCODE(local_ip, engine_rule->src_ip_high);
              protocol_src = SSH_PROTOCOL_IP6;
            }

          engine_rule->selectors |= SSH_SELECTOR_SRCIP;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Local end is behind NAT and transport mode used, "
                     "using IKE local ip %@ as source selector",
                     ssh_ipaddr_render, local_ip));
        }
    }
#endif /* SSHDIST_IKEV1 */
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Sanity check for source and destination proxy IDs. */
  if (protocol_src != protocol_dst)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Source and destination Proxy IDs "
                              "specify different protocols"));
      return FALSE;
    }

  engine_rule->protocol = (SshUInt8) protocol_src;

  /* IP protocol. */
  if (local_tsitem->proto && remote_tsitem->proto
      && local_tsitem->proto != remote_tsitem->proto)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Source and destination Proxy IDs "
                              "specify different IP protocol IDs"));
      return FALSE;
    }

  if (local_tsitem->proto)
    ipproto = local_tsitem->proto;
  else
    ipproto = remote_tsitem->proto;

  ipproto = (ipproto == 0) ? SSH_IPPROTO_ANY : ipproto;

  engine_rule->ipproto = (SshUInt8) ipproto;
  if (ipproto != SSH_IPPROTO_ANY)
    engine_rule->selectors |= SSH_SELECTOR_IPPROTO;

  /* If the rule specifies a single ICMP type / code, then add ICMP
     selector flags to the apply rule. In addition, clear the src port
     selectors as the are not used by the engine. */
  if ((engine_rule->selectors & SSH_SELECTOR_IPPROTO) &&
      (engine_rule->ipproto == SSH_IPPROTO_ICMP ||
       engine_rule->ipproto == SSH_IPPROTO_IPV6ICMP))
    {
      engine_rule->selectors |= SSH_SELECTOR_SRCPORT;
      engine_rule->src_port_low = 0;
      engine_rule->src_port_high = 0xffff;

      engine_rule->selectors |= SSH_SELECTOR_DSTPORT;
      engine_rule->dst_port_low = remote_tsitem->start_port;
      engine_rule->dst_port_high = remote_tsitem->end_port;

      if (((engine_rule->dst_port_low >> 8) & 0xff) ==
          ((engine_rule->dst_port_high >> 8) & 0xff))
        engine_rule->selectors |= SSH_SELECTOR_ICMPTYPE;

      if ((engine_rule->dst_port_low & 0xff) ==
          (engine_rule->dst_port_high & 0xff))
        engine_rule->selectors |= SSH_SELECTOR_ICMPCODE;
    }

  /* Set the interface selector if the rule's from-interface in the
     forward case specifies an interface selector.  In the reverse
     case, we will create the SA outbound rule in an inactive mode at
     a low precedence level.  Therefore, it can not open unwanted
     outbound sessions. */




  if (forward && rule->side_from.ifname)
    {
      SshUInt32 ifnum;

      if (ssh_pm_find_interface(pm, rule->side_from.ifname, &ifnum) == NULL)
        {
          /* The from-interface is not known.  We can not install this
             SA. */
          return FALSE;
        }
      engine_rule->selectors |= SSH_SELECTOR_IFNUM;
      engine_rule->selector_ifnum = (SshEngineIfnum) ifnum;
    }

  if (forward && rule->side_from.local_stack)
    {
      engine_rule->selectors |= SSH_SELECTOR_FROMLOCAL;
    }

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
  if (rule->flags & SSH_PM_RULE_MULTIHOME)
    engine_rule->flags |= SSH_ENGINE_RULE_SCTP_MULTIHOME;
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

  /* Extension selectors. */
  ssh_pm_set_extension_selectors(rule, engine_rule);

  engine_rule->type = SSH_ENGINE_RULE_APPLY;

  /* The caller must set the `transform_index'. */

  /* The SA rule depends on the high-level rule's trigger rule. */
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
  /* For all rules corresponding to SCTP paths of a particular SCTP
     association, the rules depend on the original trigger rule. All
     paths belong to the same SCTP association and are destroyed with
     the policy enforcement rule at the same time */
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */
#if 0
  SSH_ASSERT(rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT]
             != SSH_IPSEC_INVALID_INDEX);
#endif
  engine_rule->depends_on = rule->rules[SSH_PM_RULE_ENGINE_IMPLEMENT];

  /* Set the tunnel ID which specify the rule set to which the rule is
     added. */

  if (forward)
    {
      from_tunnel = rule->side_from.tunnel;
      to_tunnel = rule->side_to.tunnel;
    }
  else
    {
      from_tunnel = rule->side_to.tunnel;
      to_tunnel = rule->side_from.tunnel;
    }

  if (from_tunnel)
    engine_rule->tunnel_id = from_tunnel->tunnel_id;

  /* Timeout and lifetime values for flows. */
  engine_rule->flow_idle_datagram_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
  engine_rule->flow_idle_session_timeout = SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
  engine_rule->flow_max_lifetime = 0;

  /* Some additional rule flags. */
  if (rule->flags & SSH_PM_RULE_LOG)
    engine_rule->flags |= SSH_ENGINE_LOG_CONNECTIONS;
  if (rule->flags & SSH_PM_RULE_RATE_LIMIT)
    engine_rule->flags |= SSH_ENGINE_RATE_LIMIT;
  if (rule->flags & SSH_PM_RULE_NO_FLOW)
    engine_rule->flags |= SSH_ENGINE_NO_FLOW;

  /* If tunnel is outgoing */
  if (to_tunnel)
    {
      /* If this is an APPGW trigger rule we must do this. */
      engine_rule->flags |= SSH_PM_ENGINE_RULE_TOTUNNEL;
#ifdef SSHDIST_IPSEC_NAT
      if (to_tunnel->flags & SSH_PM_T_PORT_NAT)
        engine_rule->flags |= SSH_PM_ENGINE_RULE_TT_NAT;
#endif /* SSHDIST_IPSEC_NAT */
    }

#ifdef SSHDIST_IPSEC_NAT
  /* Forced source NAT */
  if (SSH_IP_DEFINED(&rule->nat_src_low))
    {
      engine_rule->nat_src_ip_low = rule->nat_src_low;
      engine_rule->nat_src_ip_high = rule->nat_src_high;
      engine_rule->nat_src_port = rule->nat_src_port;
      engine_rule->nat_flags = rule->nat_flags;
      engine_rule->flags |= SSH_ENGINE_RULE_FORCE_NAT_SRC;
    }
  /* Forced destination NAT */
  if (SSH_IP_DEFINED(&rule->nat_dst_low))
    {
      engine_rule->nat_dst_ip_low = rule->nat_dst_low;
      engine_rule->nat_dst_ip_high = rule->nat_dst_high;
      engine_rule->nat_dst_port = rule->nat_dst_port;
      engine_rule->nat_flags = rule->nat_flags;
      engine_rule->flags |= SSH_ENGINE_RULE_FORCE_NAT_DST;
    }
#endif /* SSHDIST_IPSEC_NAT */
  /** Copy VRF routing instance identifier for the engine rule. */
  if (rule->routing_instance_id >= 0)
    {
      engine_rule->selectors |= SSH_SELECTOR_RIID;
    }
  engine_rule->routing_instance_id = rule->routing_instance_id;

  /* The caller sets the `policy_context'. */
  return TRUE;
}
