/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the packet processing functions in the 'non-fastpath'
   part of the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEnginePacketHandler"

static SshEngineActionRet
engine_packet_handle_pmtu(SshEngine engine, SshEnginePacketContext pc)
{
  SshEngineActionRet ret;

#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      if (pc->ipproto == SSH_IPPROTO_IPV6ICMP
          && pc->icmp_type == SSH_ICMP6_TYPE_TOOBIG
          && (pc->pp->flags & SSH_ENGINE_P_TOLOCAL))
        {
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
          /* We have an ICMPv6 Too Big destined to
             one of our own IP addresses. */
          ret = ssh_engine_handle_pmtu_icmp(engine, pc);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          return ret;
        }
    }
  else
#endif /* WITH_IPV6 */
    if (pc->pp->protocol == SSH_PROTOCOL_IP4)
      {
        if (pc->ipproto == SSH_IPPROTO_ICMP
            && pc->icmp_type == SSH_ICMP_TYPE_UNREACH
            && pc->u.rule.icmp_code == SSH_ICMP_CODE_UNREACH_NEEDFRAG
            && (pc->pp->flags & SSH_ENGINE_P_TOLOCAL))
          {
            ssh_kernel_mutex_lock(engine->flow_control_table_lock);
            /* We have an ICMP Unreachable/Fragmentation needed destined to
               one of our own IP addresses. */
            ret = ssh_engine_handle_pmtu_icmp(engine, pc);
            ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
            return ret;
          }
      }

  return SSH_ENGINE_RET_OK;
}

/* pc -> quadruple */
static void
engine_packet_handler_lookup_prepare(SshEnginePacketContext pc,
                                     unsigned char *srcip, SshUInt16 *sport,
                                     unsigned char *dstip, SshUInt16 *dport,
                                     size_t *len)
{
  SSH_IP_ENCODE(&pc->src, srcip, *len);
  SSH_IP_ENCODE(&pc->dst, dstip, *len);

  switch (pc->ipproto)
    {
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_SCTP:
      *sport = pc->u.rule.src_port;
      *dport = pc->u.rule.dst_port;
      break;
    case SSH_IPPROTO_ICMP:
    case SSH_IPPROTO_IPV6ICMP:
      *sport = 0;
      *dport = (pc->icmp_type << 8) | pc->u.rule.icmp_code;
      break;
    default:
      *sport = *dport = 0;
      break;
    }

#ifdef DEBUG_LIGHT
  {
    int i;
    char ipproto_buf[50];
    SshUInt32 pc_flags = 0;
    SshUInt32 pp_flags = 0;
    SshVriId routing_instance=-1;

    for (i = 0; ssh_ip_protocol_id_keywords[i].name; i++)
      if (ssh_ip_protocol_id_keywords[i].code == pc->ipproto)
        {
          ssh_snprintf(ipproto_buf, sizeof(ipproto_buf), "%s",
                       ssh_ip_protocol_id_keywords[i].name);
          break;
        }
    if (ssh_ip_protocol_id_keywords[i].name == NULL)
      ssh_snprintf(ipproto_buf, sizeof(ipproto_buf), "(unknown %u)",
                   (unsigned int) pc->ipproto);

    pc_flags = pc->flags;
    if (pc->pp)
      {
        pp_flags = pc->pp->flags;
        routing_instance = pc->pp->routing_instance_id;
      }

    SSH_DEBUG(SSH_D_HIGHSTART,
              ("Rule lookup prepare: src=%@ dst=%@ ipproto=%s "
               "srcport=%d dstport=%d pc->flags=0x%x "
               "pp->flags=0x%x, routing instance=%d",
               ssh_ipaddr_render, &pc->src,
               ssh_ipaddr_render, &pc->dst,
               ipproto_buf,
               (int) *sport, (int) *dport,
               (unsigned int) pc_flags,
               (unsigned int) pp_flags,
               routing_instance));
  }
#endif /* DEBUG_LIGHT */
}


static SshEngineActionRet
engine_packet_handler_rule_lookup(SshEngine engine,
                                  SshEnginePacketContext pc)
{
  Boolean policy_lookups_disabled;
  unsigned char src_ip[SSH_IP_ADDR_SIZE], dst_ip[SSH_IP_ADDR_SIZE];
  SshUInt16 src_port, dst_port;
  size_t len = 0;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Check whether policy lookups are allowed. */
  policy_lookups_disabled = engine->policy_lookups_disabled;






  if (policy_lookups_disabled)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_NOLOOKUP);
      return SSH_ENGINE_RET_DROP;
    }

  /* Look up matching policy rules, unless it has already been cached
     into the policy context. */
  if (pc->rule == NULL)
    {
      engine_packet_handler_lookup_prepare(pc,
                                           src_ip, &src_port,
                                           dst_ip, &dst_port,
                                           &len);
      pc->rule = ssh_engine_rule_lookup(engine,
                                        engine->policy_rule_set,
                                        src_ip, dst_ip, len,
                                        pc->ipproto,
                                        src_port, dst_port,
                                        pc);

      /* Check if 'pc->pp' got freed by ssh_engine_rule_lookup() */
      if (pc->pp == NULL)
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          return SSH_ENGINE_RET_ERROR;
        }

      if (pc->rule == NULL)
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_NORULE);
          SSH_TRACE(SSH_D_HIGHOK,
                    ("no policy rule found, using default rule"));

          /* Select a default rule. */

          /* DHCP requests map to the default DHCP rules. */
          if (pc->pp && (pc->pp->flags & SSH_ENGINE_P_FROMLOCAL)
              && SSH_IP_IS4(&pc->dst)
              && pc->ipproto == engine->dhcp_ipv4_out_rule->ipproto
              && dst_port == engine->dhcp_ipv4_out_rule->dst_port_low)
            pc->rule = engine->dhcp_ipv4_out_rule;
          else if (pc->pp && (pc->pp->flags & SSH_ENGINE_P_TOLOCAL)
              && SSH_IP_IS4(&pc->src)
              && pc->ipproto == engine->dhcp_ipv4_in_rule->ipproto
              && src_port == engine->dhcp_ipv4_in_rule->src_port_low)
            pc->rule = engine->dhcp_ipv4_in_rule;
          else if (pc->pp && (pc->pp->flags & SSH_ENGINE_P_FROMLOCAL)
              && SSH_IP_IS6(&pc->dst)
              && pc->ipproto == engine->dhcp_ipv6_out_rule->ipproto
              && dst_port == engine->dhcp_ipv6_out_rule->dst_port_low)
            pc->rule = engine->dhcp_ipv6_out_rule;
          else if (pc->pp && (pc->pp->flags & SSH_ENGINE_P_TOLOCAL)
              && SSH_IP_IS6(&pc->src)
              && pc->ipproto == engine->dhcp_ipv6_in_rule->ipproto
              && src_port == engine->dhcp_ipv6_in_rule->src_port_low)
            pc->rule = engine->dhcp_ipv6_in_rule;

          /* Other packets match the default pass/drop rule. */
          else if (engine->ipm_open ||
                   (engine->flags & SSH_ENGINE_DROP_IF_NO_IPM))
            pc->rule = engine->drop_rule;
          else
            pc->rule = engine->pass_rule;
        }

      /* Increment the reference count of the rule. */
      SSH_ENGINE_INCREMENT_RULE_REFCNT(pc->rule);
#ifdef SSH_IPSEC_STATISTICS
      pc->rule->stats.times_used++;
#endif /* SSH_IPSEC_STATISTICS */
    }

  SSH_ASSERT(pc->rule != NULL);

  return SSH_ENGINE_RET_OK;
}

static SshEngineActionRet
engine_packet_handler_verify_sa_selectors(SshEngine engine,
                                          SshEnginePacketContext pc)
{
  unsigned char src_ip[SSH_IP_ADDR_SIZE], dst_ip[SSH_IP_ADDR_SIZE];
  SshUInt16 src_port, dst_port;
  size_t ip_len;
  SshEngineTransformControl c_trd;
  SshUInt32 rule_index;
  SshEnginePolicyRule rule;
#ifdef SSHDIST_L2TP
  SshEngineTransformData d_trd;
#endif /* SSHDIST_L2TP */

  SSH_ASSERT(pc->pp != NULL);
  SSH_ASSERT(pc->prev_transform_index != SSH_IPSEC_INVALID_INDEX);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Verifying that decapsulated packet matches the SA selectors "
             "of transform 0x%lx",
             (unsigned long) pc->prev_transform_index));





  /* Fetch transform used for decapsulation. */
  c_trd = SSH_ENGINE_GET_TRD(engine, pc->prev_transform_index);
  if (c_trd == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Transform has 0x%lx disappeared for decapsulated packet",
                 (unsigned long) pc->prev_transform_index));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
      return SSH_ENGINE_RET_FAIL;
    }

#ifdef SSHDIST_L2TP
  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                     pc->prev_transform_index);
  if (d_trd->transform & SSH_PM_IPSEC_L2TP)
    {
      FASTPATH_RELEASE_TRD(engine->fastpath, pc->prev_transform_index);
      SSH_DEBUG(SSH_D_LOWOK, ("Skipping SA selector check for l2tp packet"));
      return SSH_ENGINE_RET_OK;
    }

  FASTPATH_RELEASE_TRD(engine->fastpath, pc->prev_transform_index);
#endif /* SSHDIST_L2TP */

  engine_packet_handler_lookup_prepare(pc,
                                       src_ip, &src_port,
                                       dst_ip, &dst_port,
                                       &ip_len);

  /* Find APPLY rule to the transform. */
  for (rule_index = c_trd->rules;
       rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = rule->trd_next)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);
      SSH_ASSERT(rule != NULL);
      if (rule->type == SSH_ENGINE_RULE_APPLY)
        {
          /* Compare packet 5-tupple to SA selectors in APPLY rule.
             Note that APPLY rule is for reverse direction, thus packet
             source/destination addresses and ports must be compared to
             the opposite rule selector. */
          if (rule->protocol != pc->pp->protocol)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: protocol mismatch",
                                      (int) rule_index));
              continue;
            }

          if ((rule->selectors & SSH_SELECTOR_SRCIP)
              && (memcmp(rule->src_ip_low, dst_ip, ip_len) > 0
                  || memcmp(rule->src_ip_high, dst_ip, ip_len) < 0))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: destination IP mismatch",
                                      (int) rule_index));
              continue;
            }

          if ((rule->selectors & SSH_SELECTOR_DSTIP)
              && (memcmp(rule->dst_ip_low, src_ip, ip_len) > 0
                  || memcmp(rule->dst_ip_high, src_ip, ip_len) < 0))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: source IP mismatch",
                                      (int) rule_index));
              continue;
            }

          if ((rule->selectors & SSH_SELECTOR_IPPROTO)
              && rule->ipproto != pc->ipproto)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: IP protocol mismatch",
                                      (int) rule_index));
              continue;
            }

          if ((rule->selectors & SSH_SELECTOR_SRCPORT)
              && (rule->src_port_low > dst_port
                  || rule->src_port_high < dst_port))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: destination port mismatch",
                                      (int) rule_index));
              continue;
            }

          if (rule->selectors & SSH_SELECTOR_DSTPORT)
            {
              if ((rule->selectors & SSH_SELECTOR_ICMPTYPE)
                  && ((rule->dst_port_low & 0xff00) != (dst_port & 0xff00)))
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: ICMP type mismatch",
                                          (int) rule_index));
                  continue;
                }

              if ((rule->selectors & SSH_SELECTOR_ICMPCODE)
                  && ((rule->dst_port_low & 0x00ff) != (dst_port & 0x00ff)))
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: ICMP code mismatch",
                                          (int) rule_index));
                  continue;
                }

              if ((rule->selectors &
                   (SSH_SELECTOR_ICMPTYPE | SSH_SELECTOR_ICMPCODE)) == 0
                  && (rule->dst_port_low > src_port
                      || rule->dst_port_high < src_port))
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("Rule %d: source port mismatch",
                                          (int) rule_index));
                  continue;
                }
            }

          /* Packet fits into SA selectors. */
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Rule %d: decapsulated packet matches SA selectors",
                     (int) rule_index));
          return SSH_ENGINE_RET_OK;
        }
    }

  SSH_ASSERT(rule_index == SSH_IPSEC_INVALID_INDEX);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Decapsulated packet does not match the SA selectors, "
             "dropping packet."));
  pc->audit.corruption = SSH_PACKET_CORRUPTION_IPSEC_INVALID_SELECTORS;
  return SSH_ENGINE_RET_DROP;
}

static Boolean
engine_packet_handler_trd_verify(SshEnginePacketContext pc,
                                 SshEngineFlowData d_flow,
                                 Boolean forward)
{
  int i;

  /* Check if packet was decapsulated using transform index in the
     opposite direction. */
  if ((forward
       && (pc->prev_transform_index == d_flow->reverse_transform_index)) ||
      (!forward
       && (pc->prev_transform_index == d_flow->forward_transform_index)))
    return TRUE;

  /* Check if packet was decapsulated using one of allowed rx transform
     indexes. */
  else
    {
      for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
        {
          if ((forward
               && (d_flow->forward_rx_transform_index[i]
                   == SSH_IPSEC_INVALID_INDEX))
              || (!forward
                  && (d_flow->reverse_rx_transform_index[i]
                      == SSH_IPSEC_INVALID_INDEX)))
            break;

          if ((forward
               && (pc->prev_transform_index
                   == d_flow->forward_rx_transform_index[i]))
              || (!forward
                  && (pc->prev_transform_index
                      == d_flow->reverse_rx_transform_index[i])))
            return TRUE;
        }
    }

  return FALSE;
}

static void
engine_packet_handler_trd_allow_decaps(SshEnginePacketContext pc,
                                       SshEngineFlowData d_flow,
                                       Boolean forward)
{
  int i;

  /* Lookup an unused slot. */
  for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
    {
      if ((forward && (d_flow->forward_rx_transform_index[i]
                       == SSH_IPSEC_INVALID_INDEX))
          || (!forward && (d_flow->reverse_rx_transform_index[i]
                           == SSH_IPSEC_INVALID_INDEX)))
        break;
    }

  /* Use an unused slot or move all trd indexes one slot
     earlier and reuse last slot. */
  if (i == SSH_ENGINE_NUM_RX_TRANSFORMS)
    {
      for (i = 0; (i + 1) < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
        {
          /* SSH_ENGINE_NUM_RX_TRANSFORMS is configurable compile time, and
             may be larger than 1 */
          /* coverity[dead_error_line] */
          if (forward)
            d_flow->forward_rx_transform_index[i]
              = d_flow->forward_rx_transform_index[i+1];
          else
            d_flow->reverse_rx_transform_index[i]
              = d_flow->reverse_rx_transform_index[i+1];
        }
    }
  SSH_ASSERT(i < SSH_ENGINE_NUM_RX_TRANSFORMS);

  if (forward)
    d_flow->forward_rx_transform_index[i]
      = pc->prev_transform_index;
  else
    d_flow->reverse_rx_transform_index[i]
      = pc->prev_transform_index;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Inbound %s transform index for flow %d updated to %lx",
             (forward ? "forward" : "reverse"),
             (int) pc->flow_index,
             (unsigned long) pc->prev_transform_index));
}


static SshEngineActionRet
engine_packet_handle_flow(SshEngine engine, SshEnginePacketContext pc)
{
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshEnginePolicyRule rule;
  SshEngineFlowStatus undangle_status;
  SshEngineActionRet ret;
  Boolean forward;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 nh_index, transform_index;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;

  /* We are now in "non-fastpath context" */

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  c_flow = SSH_ENGINE_GET_FLOW(engine, pc->flow_index);
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, pc->flow_index);

  /* Check the flow is still valid */
  if (d_flow->generation != pc->flow_generation
      || (c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
      SSH_DEBUG(SSH_D_FAIL, ("Flow disappeared."));

      FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return SSH_ENGINE_RET_FAIL;
    }

  SSH_ASSERT(c_flow->rule_index != SSH_IPSEC_INVALID_INDEX);

  /* Check if flow is in drop mode. */
  if (d_flow->data_flags & SSH_ENGINE_FLOW_D_DROP_PKTS)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_DROP);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow is in drop mode."));

      FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return SSH_ENGINE_RET_FAIL;
    }

  /* If this is a trigger flow, then it may be that
     our destination next hop node is still undefined, and
     it must be defined, before we can undangle this flow. */
  if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_TRIGGER) && forward)
    {
      SSH_ASSERT((pc->flags & SSH_ENGINE_PC_HIT_TRIGGER) == 0);
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Packet hit a trigger flow, doing rule execution"));
      pc->flags |= SSH_ENGINE_PC_HIT_TRIGGER;
      SSH_ASSERT(pc->rule == NULL);

      FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Let packet continue to rule execution. */
      return SSH_ENGINE_RET_OK;
    }

  /* Check if rx_transform_index needs to be updated. */
  if (pc->tunnel_id > 1 &&
      (pc->flags & SSH_ENGINE_PC_SKIP_TRD_VERIFY) == 0 &&
      pc->prev_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Check if packet was decapsulated with one of the allowed SAs. */
      if (engine_packet_handler_trd_verify(pc, d_flow, forward) == FALSE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Packet was decapsulated using a mismatching "
                     "transform index %lx",
                     (unsigned long) pc->prev_transform_index));

          /* Packets's prev_transform_index did not match any allowed
             transform indexes, check packet against rule. */
          ret = engine_packet_handler_verify_sa_selectors(engine, pc);
          if (ret == SSH_ENGINE_RET_OK)
            {
              /* Rule's traffic selectors allowed the packet to be
                 decapsulated. Add prev_transform_index to flow's list of
                 allowed trds. */
              engine_packet_handler_trd_allow_decaps(pc, d_flow, forward);
              pc->flags |= SSH_ENGINE_PC_SKIP_TRD_VERIFY;
              FASTPATH_COMMIT_FLOW(engine->fastpath, pc->flow_index, d_flow);
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

              /* Pass packet back to fastpath. */
              return SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
            }

          FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          return ret;
        }
    }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (forward)
    {
      nh_index = d_flow->forward_nh_index;
      transform_index = d_flow->forward_transform_index;
    }
  else
    {
      nh_index = d_flow->reverse_nh_index;
      transform_index = d_flow->reverse_transform_index;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);

  rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);

  if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_PENDING)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      SSH_DEBUG(SSH_D_MIDOK, ("Rerouting flow %lu",
                              (unsigned long) pc->flow_index));

      ret = ssh_engine_reroute_flow(pc);

      /* On success pass packet back to fastpath. */
      if (ret == SSH_ENGINE_RET_OK)
        ret = SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
      return ret;
    }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (nh_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineNextHopData d_nh;
      SshIpAddrStruct next_hop;
      SshEngineIfnum ifnum;
#ifdef WITH_IPV6
      SshInterceptorProtocol nh_protocol;
#endif /* WITH_IPV6 */

      /* Check if nh node needs special processing. */
      d_nh = FASTPATH_GET_NH(engine->fastpath, nh_index);
      SSH_ASSERT(d_nh != NULL);

#ifdef WITH_IPV6
      /* Store nh node IP protocol version for later sanity checks. */
      if (SSH_IP_IS6(&d_nh->dst))
        nh_protocol = SSH_PROTOCOL_IP6;
      else
        nh_protocol = SSH_PROTOCOL_IP4;
#endif /* WITH_IPV6 */

      if (d_nh->flags & (SSH_ENGINE_NH_REROUTE | SSH_ENGINE_NH_EMBRYONIC))
        {
          d_nh->flags &= ~SSH_ENGINE_NH_REROUTE;
          next_hop = d_nh->dst;
          ifnum = d_nh->ifnum;
          FASTPATH_COMMIT_NH(engine->fastpath, nh_index, d_nh);

          /* Check next hop gateway reachability. */
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Checking reachability of next hop %@ ifnum %u "
                     "nh node %u",
                     ssh_ipaddr_render, &next_hop, ifnum, nh_index));
          if (ssh_engine_arp_check_reachability(engine, &next_hop, ifnum)
              == FALSE)
            {
              /* Need to restore NH_REROUTE flag... */
              d_nh = FASTPATH_GET_NH(engine->fastpath, nh_index);
              d_nh->flags |= SSH_ENGINE_NH_REROUTE;
              FASTPATH_COMMIT_NH(engine->fastpath, nh_index, d_nh);

              /* Next hop is not reachable, need to reroute flow. */
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

              SSH_DEBUG(SSH_D_MIDOK, ("Rerouting flow %lu nh %lu",
                                      (unsigned long) pc->flow_index,
                                      (unsigned long) nh_index));

              ret = ssh_engine_reroute_flow(pc);

              /* On success pass packet back to fastpath. */
              if (ret == SSH_ENGINE_RET_OK)
                ret = SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
              return ret;
            }

          /* Else next hop gw is reachable, let packet continue. */
        }

      /* Next hop node does not require special processing. */
      else
        {
          FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
        }

#ifdef DEBUG_LIGHT
#ifdef WITH_IPV6
      /* Sanity check transform outer IP header version. The outer header
         IP address family may change during MOBIKE address update. In such
         case the flows are marked to be re-routed as soon as possible. Any
         matching packets should never end up here unless there is a problem
         with flow re-routing. In such cse drop the packet here to make sure
         that fastpath never sends out IPv6 packets with IPv4 ethertype or
         vice versa. */




      if (transform_index != SSH_IPSEC_INVALID_INDEX)
        {
          SshEngineTransformData d_trd;

          d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                             transform_index);

          if ((SSH_IP_IS4(&d_trd->gw_addr) && nh_protocol != SSH_PROTOCOL_IP4)
              || (SSH_IP_IS6(&d_trd->gw_addr)
                  && nh_protocol != SSH_PROTOCOL_IP6)
              )
            {
              FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

              SSH_DEBUG(SSH_D_ERROR,
                        ("Nexthop protocol %u does not match transform "
                         "protocol, dropping packet",
                         nh_protocol));

              return SSH_ENGINE_RET_DROP;
            }

          FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
        }
#endif /* WITH_IPV6 */
#endif /* DEBUG_LIGHT */
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Refetch flow and check that the flow is still valid. If the flow is not
     dangling that we are done. */
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, pc->flow_index);
  if (d_flow->generation != pc->flow_generation
      || (d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) == 0)
    {
      FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Pass packet back to fastpath */
      return SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
    }

  /* The flow is dangling, attempt to undangle it.  */
  FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Packet hit a non-trigger dangling flow!"));

  /* We should try to undangle the flow and restart the packet */
  undangle_status = ssh_engine_flow_undangle(engine, pc->flow_index);
  switch (undangle_status)
    {
    case SSH_ENGINE_FLOW_STATUS_ERROR:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Error in undangling flow %lu",
                                   (unsigned long) pc->flow_index));
      ssh_engine_free_flow(engine, pc->flow_index);
      pc->flow_index = SSH_IPSEC_INVALID_INDEX;

      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return SSH_ENGINE_RET_FAIL;

    case SSH_ENGINE_FLOW_STATUS_REVERSE_TRIGGER:
      if (forward == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Required reverse trigger for flow %lu tunnel_id %d",
                     (unsigned long) pc->flow_index,
                     (int) rule->tunnel_id));
          /* Fall-through to dangle! */
        }

    case SSH_ENGINE_FLOW_STATUS_DANGLING:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow %lu still dangling!",
                                   (unsigned long) pc->flow_index));
      /* Do nothing. Fall-through to trigger generation and THEN
         drop! */
      break;

      /* The found_flow label requires that flow_table_lock
         be held. */
    case SSH_ENGINE_FLOW_STATUS_WELL_DEFINED:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Flow %lu became well-defined, handling packet",
                 (unsigned long) pc->flow_index));
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Pass packet back to fastpath */
      return SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;

    default:
      SSH_NOTREACHED;
    }

  if (rule->type == SSH_ENGINE_RULE_TRIGGER
      && forward
      && pc->flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Ensure that refcounts do not leak. */
      SSH_ASSERT(pc->rule == NULL);
      pc->rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
      SSH_ENGINE_INCREMENT_RULE_REFCNT(pc->rule);

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* This guarantees that we hit a trigger in engine_rule_execute.c */
      pc->flags |= SSH_ENGINE_PC_HIT_TRIGGER;

      /* Let packet continue to rule execution. */
      return SSH_ENGINE_RET_OK;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
  return SSH_ENGINE_RET_FAIL;
}

void
engine_rule_packet_handler(SshEngine engine, SshEnginePacketContext pc)
{
  SshEngineActionRet ret;

  SSH_INTERCEPTOR_STACK_MARK();

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* We do not want packets with media headers prepended to them. */
  SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Perform PMTU processing */
  ret = engine_packet_handle_pmtu(engine, pc);
  if (ret != SSH_ENGINE_RET_OK)
    goto out;

  /* Handle trigger/dangling flows */
  if (pc->flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      ret = engine_packet_handle_flow(engine, pc);
      if (ret != SSH_ENGINE_RET_OK)
        goto out;
    }

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Verify packet selectors against SA selectors if the packet
     has been decapsulated from a tunnel. */
  if (pc->tunnel_id > 1)
    {
      ret = engine_packet_handler_verify_sa_selectors(engine, pc);
      pc->flags |= SSH_ENGINE_PC_SKIP_TRD_VERIFY;
      if (ret != SSH_ENGINE_RET_OK)
        {
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          goto out;
        }
    }

  /* Perform Rule lookup */
  ret = engine_packet_handler_rule_lookup(engine, pc);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (ret == SSH_ENGINE_RET_OK && pc->rule != NULL)
    {
      /* Found a rule.  Process the packet according to the rule.  This will
         eventually call engine_packet_continue again, which will decrement
         the reference count of the rule when it sees pc->rule non-NULL. */
      ret = ssh_engine_execute_rule(pc);
    }

 out:
  if (ret == SSH_ENGINE_RET_OK)
    ret = SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;

  /* Pass the packet back to fastpath */
  if (ret != SSH_ENGINE_RET_ASYNC)
    engine_packet_continue(pc, ret);
  return;
}

void
engine_packet_continue(SshEnginePacketContext pc, SshEngineActionRet ret)
{
  SshEngine engine = pc->engine;

   /* If we have a rule referenced from the pc, that means a previous
     rule execution has completed.  Decrement the reference count of the
     rule.  */
  if (pc->rule != NULL)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      ssh_engine_decrement_rule_refcnt(engine, pc->rule);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      pc->rule = NULL;
    }
  fastpath_packet_continue(engine->fastpath, pc, ret);
}

Boolean
ssh_engine_packet_start(SshEngine engine, SshInterceptorPacket pp,
                        SshUInt32 tunnel_id, SshUInt32 prev_transform_index,
                        SshUInt32 pc_flags)
{
  SshEnginePacketContext pc;
  SshEngineTransformData trd;

  SSH_DEBUG(SSH_D_LOWOK, ("Sending packet to the fastpath pp=%p, "
                          "tunnel_id=%d, prev_transform_index=%x",
                          pp, (int) tunnel_id,
                          (unsigned int) prev_transform_index));

  if (pp->flags & SSH_PACKET_FROMADAPTER)
    pp->flags |= SSH_ENGINE_P_FROMADAPTER;

  /* Allocate a packet context for the new packet. */
  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  /* Initialize the new pc. */
  ssh_engine_init_pc(pc, engine, pp, tunnel_id, NULL);
  pc->flags = pc_flags;
  pc->prev_transform_index = prev_transform_index;

  /* Initialize transform_counter for outbound nested tunnel packets. */
  if (pc->flags & SSH_ENGINE_PC_RESTARTED_OUT
      && pc->prev_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                       pc->prev_transform_index);
      SSH_ASSERT(trd != NULL);
      SSH_ASSERT(trd->nesting_level > 0);
      pc->transform_counter = trd->nesting_level - 1;
      FASTPATH_RELEASE_TRD(engine->fastpath, pc->prev_transform_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
    }

  /* Send the packet to the fastpath. This will handle the packet as if
     it had just been received from the network. */
  engine_packet_continue(pc, SSH_ENGINE_RET_RESTART);
  return TRUE;
}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
void
engine_address_resolution(SshEngine engine, SshEnginePacketContext pc)
{
  SshEnginePacketData pd;
  SshInterceptorPacket pp = pc->pp;

  pd = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);

  if (pp->protocol == SSH_PROTOCOL_ARP)
    {
      pc->pp = NULL;
      if (ssh_engine_arp_input(engine, pp))
        {
          /* Set 'pp->ifnum_out'. */
          pp->ifnum_out = pp->ifnum_in;

          /* Forward the ARP packet to the native stack. We have the
             saved media header in pd->mediahdr. */
          ssh_engine_encapsulate_and_send(engine, pp,
                                          pd->mediahdr + SSH_ETHERH_OFS_SRC,
                                          pd->mediahdr + SSH_ETHERH_OFS_DST,
                                          SSH_ETHERTYPE_ARP);
          /* Return packet context */
          fastpath_packet_continue(engine->fastpath, pc,
                                   SSH_ENGINE_RET_DEINITIALIZE);
        }
      else
        {
          pc->pp = NULL;
          fastpath_packet_continue(engine->fastpath, pc, SSH_ENGINE_RET_ERROR);
        }
      return;
    }
#if defined (WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      switch (pc->icmp_type)
        {
        case SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT:
          if (!ssh_engine_arp_recv_neighbor_advertisement(engine, pc))
            {
              pc->pp = NULL;
              fastpath_packet_continue(engine->fastpath, pc,
                                       SSH_ENGINE_RET_ERROR);
              return;
            }
          break;

        case SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION:
          if (!ssh_engine_arp_recv_neighbor_solicitation(engine, pc))
            {
              pc->pp = NULL;
              fastpath_packet_continue(engine->fastpath, pc,
                                       SSH_ENGINE_RET_ERROR);
              return;
            }
          break;

        case SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT:
          if (ssh_engine_arp_router_advertisement(engine, pc) == FALSE)
            {
              pc->pp = NULL;
              fastpath_packet_continue(engine->fastpath, pc,
                                       SSH_ENGINE_RET_ERROR);
              return;
            }
          break;

        default:
          break;
        }

      /* Set 'pp->ifnum_out' and let packet continue to local stack. */
      pp->ifnum_out = pp->ifnum_in;
      fastpath_packet_continue(engine->fastpath, pc, SSH_ENGINE_RET_IS_SANE);
      return;
    }
#endif /* WITH_IPV6 */

  fastpath_packet_continue(engine->fastpath, pc, SSH_ENGINE_RET_ERROR);
}
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

Boolean
ssh_engine_copy_transform_data(SshEngine engine, SshEnginePacketContext pc)
{
  SshEngineTransformData d_trd;
  SshEngineFlowData d_flow = NULL;
  SshEngineFlowControl c_flow;
  SshEngineTransformControl c_trd;
  Boolean rv = FALSE;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Perform some checks to verify that the flow and transform objects
     belonging to the packet context are still valid. */

  if (pc->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, pc->transform_index);
      if (c_trd == NULL)
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          SSH_DEBUG(SSH_D_FAIL, ("Transform index is not valid anymore"));
          return FALSE;
        }
    }

  if (pc->flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, pc->flow_index);

      if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0)
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          SSH_DEBUG(SSH_D_FAIL, ("Flow disappeared."));
          return FALSE;
        }
    }

  if (pc->flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, pc->flow_index);

      /* Check the flow is still valid */
      if (d_flow->generation != pc->flow_generation)
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          SSH_DEBUG(SSH_D_FAIL, ("Flow disappeared."));

          FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
          return FALSE;
        }
    }

  fastpath_copy_flow_data(engine->fastpath, d_flow, pc);

  if (pc->flow_index != SSH_IPSEC_INVALID_INDEX)
    FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);

  if (pc->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                         pc->transform_index);






      if (d_trd == NULL || d_trd->transform == 0)
        {
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          SSH_DEBUG(SSH_D_FAIL, ("Transform disappeared."));

          FASTPATH_RELEASE_TRD(engine->fastpath, pc->transform_index);
          return FALSE;
        }
      FASTPATH_RELEASE_TRD(engine->fastpath, pc->transform_index);
    }

  rv = fastpath_copy_transform_data(engine->fastpath, pc);

  return rv;
}




void
engine_rule_packet_handler_init(void)
{
  return;
}
