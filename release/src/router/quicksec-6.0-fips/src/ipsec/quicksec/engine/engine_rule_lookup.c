/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions to perform various rule lookups.  This file is essentially a
   wrapper for the generic rule lookup code implemented either in
   engine_rule_lookup_list.c or engine_rule_lookup_tree.c.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineRuleLookup"




/* We ignore any rules that are still inactive after an IPsec SA rekey.
   This means that the traffic selectors became wider during rekey, but
   the new outbound SA has not yet been activated here at the responder
   end. We cannot send packets matching the wider traffic selectors of
   the new SA using the SPI and keymat of the old SA. This has the
   consequence that some flows may be created from a lowerpriority rule
   (possibly passby), and those flows will never move to use the SA. */
#define SSH_ENGINE_RULE_LOOKUP_RULE_INACTIVE \
  (SSH_ENGINE_RULE_INACTIVE \
   | SSH_ENGINE_RULE_DELETED \
   | SSH_ENGINE_RULE_INSTALL_PENDING)

static Boolean ssh_rule_packet_test_fun(SshEngine engine,
                                        SshEngineLookupPreamble preamble,
                                        const SshUInt32 *extensions,
                                        void *ctx)
{
  SshEnginePacketContext pc = (SshEnginePacketContext) ctx;
  SshInterceptorPacket pp = pc->pp;
  SshEnginePolicyRule rule = (SshEnginePolicyRule)preamble;
  SshUInt32 flags = rule->flags;
  SshUInt16 selectors = rule->selectors;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Test with rule %@", ssh_engine_policy_rule_render, rule));

  /* Check if a previous call to ths function caused 'pc->pp' to be freed.*/
  if (pc->pp == NULL)
    return FALSE;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if ((rule->selectors & SSH_SELECTOR_EXTENSIONS) && extensions != NULL)
    {
      int i;

      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <=
              rule->extension_selector_high[i] &&
              (rule->extension_selector_low[i] > extensions[i] ||
               rule->extension_selector_high[i] < extensions[i]))
            return FALSE;
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4 ||
             pp->protocol == SSH_PROTOCOL_IP6);

#ifndef SSH_IPSEC_SMALL
  if (rule->type == SSH_ENGINE_RULE_DORMANT_APPLY)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Rule is dormant"));
      return FALSE;
    }
#endif /* SSH_IPSEC_SMALL */

  if (rule->flags & SSH_ENGINE_RULE_LOOKUP_RULE_INACTIVE)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Rule is inactive/deleted"));
      return FALSE;
    }

  if (pp->protocol != rule->protocol)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Protocol didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_IFNUM) &&
      pp->ifnum_in != rule->selector_ifnum)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Ifnum didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_RIID) &&
      pp->routing_instance_id != rule->routing_instance_id)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Routing instance didn't match. packet: %d, "
                                 "rule: %d", pp->routing_instance_id,
                                 rule->routing_instance_id));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_IPPROTO) &&
      pc->ipproto != rule->ipproto)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("IPproto didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_FROMLOCAL) &&
      !(pp->flags & SSH_ENGINE_P_FROMLOCAL))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Fromlocal didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_TOLOCAL) &&
      !(pp->flags & SSH_ENGINE_P_TOLOCAL))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Tolocal didn't match"));
      return FALSE;
    }

  /* SSH_ICMPH_TYPE(ucp + hdrlen) and
     SSH_ICMPH_CODE(ucp + hdrlen) */
  if ((selectors & SSH_SELECTOR_ICMPTYPE) &&
      pc->icmp_type != ((rule->dst_port_low >> 8) & 0xff))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("ICMP type didn't match"));
      return FALSE;
    }
  if ((selectors & SSH_SELECTOR_ICMPCODE) &&
      pc->u.rule.icmp_code != (rule->dst_port_low & 0xff))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("ICMP code didn't match"));
      return FALSE;
    }

  /* If the rule is marked as use-once, and has already been used, we
     ignore it, unless we are attached to a flow that just hit this rule. */
  if ((flags & (SSH_ENGINE_RULE_USE_ONCE | SSH_ENGINE_RULE_USED)) ==
      (SSH_ENGINE_RULE_USE_ONCE | SSH_ENGINE_RULE_USED))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Rule usage didn't match"));
      return FALSE;
    }

  /* Additional check for NAT-T encapsulated UDP packets. We need to examine
     the first four bytes of payload data to see if this is an IKE packet or
     a ESP packet which failed flow lookup (i.e. the SPI is unknown). In the
     former case the packet should match the pass rule for inbound IKE NAT-T
     packets. In the latter case the packet should match the NAT-T crash
     recovery trigger rule. */
  if ((selectors & SSH_SELECTOR_IPPROTO) &&
      (selectors & SSH_SELECTOR_DSTPORT) &&
      (selectors & SSH_SELECTOR_TOLOCAL))
    {
      unsigned char *ucp;
      int i;
      Boolean is_ike_natt = FALSE;

      for (i = 0; i < engine->num_ike_ports; i++)
        {
          if (pc->u.rule.dst_port == engine->local_ike_natt_ports[i])
            {
              is_ike_natt = TRUE;
              break;
            }
        }

      if (!is_ike_natt)
        goto not_local_ike_nat_t;

      if (ssh_interceptor_packet_len(pp) < pc->hdrlen + SSH_UDPH_HDRLEN + 4)
        return FALSE;

      ucp = ssh_interceptor_packet_pullup(pp,
                                          pc->hdrlen + SSH_UDPH_HDRLEN + 4);
      if (!ucp)
        {
          pc->pp = NULL;
          return FALSE;
        }

      /* Inspect the first 4 bytes of payload data of the packet to see
         if this is an NAT-T IKE packet or an NAT-T ESP packet with
         unknown SPI. */
      if (memcmp(ucp + pc->hdrlen + SSH_UDPH_HDRLEN, "\0\0\0\0", 4) != 0)
        {
          /* it does not contain ike-marker, e.g. it is esp */
          if (rule->type != SSH_ENGINE_RULE_TRIGGER ||
              ((rule->flags & SSH_PM_ENGINE_RULE_CR) == 0))
            return FALSE;

          SSH_DEBUG(SSH_D_LOWOK, ("NAT-T ESP packet with unknown SPI, "
                                  "trigger to the policymanager"));
        }
      else
        {
          if (rule->type != SSH_ENGINE_RULE_PASS)
            return FALSE;

          SSH_DEBUG(SSH_D_LOWOK, ("Normal NAT-T IKE packet"));
        }
    }
 not_local_ike_nat_t:

  return TRUE;
}


/* This looks up the highest precedence policy rule that matches the
   given packet.  ucp must point to the beginning of the packet, and
   must hold at least hdrlen+8 bytes from the packet.  hdrlen is the
   IP header length (including options) from the packet.  This returns
   the best matching rule, or NULL if no matching rule is found.  If
   several matching rules are found at the same precedence, one of
   them is picked arbitrarily by this function.  `ucp' is a pointer to
   pulled up packet data of pc->hdrlen + 8 bytes.
   Engine->flow_table_lock must be held when this is called. */

SshEnginePolicyRule
ssh_engine_rule_lookup(SshEngine engine,
                       SshEnginePolicyRuleSet rs,
                       const unsigned char *src_ip,
                       const unsigned char *dst_ip,
                       size_t addr_len,
                       SshInetIPProtocolID ipproto,
                       SshUInt16 src_port, SshUInt16 dst_port,
                       SshEnginePacketContext pc)
{
  return (SshEnginePolicyRule)
    ssh_engine_rule_generic_lookup(engine,
                                   engine->policy_rule_set,
                                   src_ip, dst_ip, addr_len,
                                   pc->tunnel_id,
                                   src_port, dst_port,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                                   pc->pp->extension,
#else
                                   NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                                   ssh_rule_packet_test_fun,
                                   pc);
}

Boolean
ssh_engine_flow_test_fun(SshEngine engine,
                         SshEngineLookupPreamble preamble,
                         const SshUInt32 *extensions,
                         void *context)
{
  SshEngineFlowData d_flow;
  SshInterceptorProtocol proto;
  SshEnginePolicyRule rule = (SshEnginePolicyRule) preamble;
  SshUInt32 flags = rule->flags;
  SshUInt16 selectors = rule->selectors;
  Boolean src_local, dst_local;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshEngineNextHopData nh_src, nh_dst;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Test with rule %d, %@",
             (int) rule->rule_index,
             ssh_engine_policy_rule_render, rule));

  d_flow = (SshEngineFlowData) context;

#ifndef SSH_IPSEC_SMALL
  if (rule->type == SSH_ENGINE_RULE_DORMANT_APPLY)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Rule is dormant"));
      return FALSE;
    }
#endif /* SSH_IPSEC_SMALL */

  if (rule->flags & SSH_ENGINE_RULE_LOOKUP_RULE_INACTIVE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Rule is inactive"));
      return FALSE;
    }

  if (SSH_IP_IS4(&d_flow->src_ip))
    proto = SSH_PROTOCOL_IP4;
  else if (SSH_IP_IS6(&d_flow->dst_ip))
    proto = SSH_PROTOCOL_IP6;
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Flow based on unknown protocol."));
      return FALSE;
    }

  if (proto != rule->protocol)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Protocol didn't match"));
      return FALSE;
    }

  src_local = dst_local = FALSE;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Re-route reverse next-hop node */
  if (d_flow->reverse_nh_index != SSH_IPSEC_INVALID_INDEX)
    {
      nh_src = FASTPATH_GET_NH(engine->fastpath, d_flow->reverse_nh_index);
      if (nh_src->flags & SSH_ENGINE_NH_LOCAL)
        src_local = TRUE;
      FASTPATH_RELEASE_NH(engine->fastpath, d_flow->reverse_nh_index);
    }

  if (d_flow->forward_nh_index != SSH_IPSEC_INVALID_INDEX)
    {
      nh_dst = FASTPATH_GET_NH(engine->fastpath, d_flow->forward_nh_index);
      if (nh_dst->flags & SSH_ENGINE_NH_LOCAL)
        dst_local = TRUE;
      FASTPATH_RELEASE_NH(engine->fastpath, d_flow->forward_nh_index);
    }
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  dst_local = d_flow->forward_local;
  src_local = d_flow->reverse_local;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if ((selectors & SSH_SELECTOR_IFNUM) &&
      d_flow->incoming_forward_ifnum != rule->selector_ifnum)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Ifnum didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_RIID) &&
      d_flow->routing_instance_id != rule->routing_instance_id)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Routing instance didn't match. flow data: "
                                 "%d, rule: %d", d_flow->routing_instance_id,
                                 rule->routing_instance_id));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_IPPROTO) &&
      d_flow->ipproto != rule->ipproto)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("IPproto didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_FROMLOCAL)
      && src_local == FALSE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Fromlocal didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_TOLOCAL)
      && dst_local == FALSE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Tolocal didn't match"));
      return FALSE;
    }

  /* SSH_ICMPH_TYPE(ucp + hdrlen) and
     SSH_ICMPH_CODE(ucp + hdrlen) */
  if ((selectors & SSH_SELECTOR_ICMPTYPE) &&
      ((d_flow->dst_port >> 8) & 0xff) != ((rule->dst_port_low >> 8) & 0xff))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("ICMP type didn't match"));
      return FALSE;
    }

  if ((selectors & SSH_SELECTOR_ICMPCODE) &&
      (d_flow->dst_port & 0xff) != (rule->dst_port_low & 0xff))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("ICMP code didn't match"));
      return FALSE;
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if ((rule->selectors & SSH_SELECTOR_EXTENSIONS) && extensions != NULL)
    {
      int i;

      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <=
              rule->extension_selector_high[i] &&
              (rule->extension_selector_low[i] > extensions[i] ||
               rule->extension_selector_high[i] < extensions[i]))
            return FALSE;
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* If the rule is marked as use-once, and has already been used, we
     ignore it. */
  if (((flags & (SSH_ENGINE_RULE_USE_ONCE | SSH_ENGINE_RULE_USED)) ==
       (SSH_ENGINE_RULE_USE_ONCE | SSH_ENGINE_RULE_USED))
      || ((flags & SSH_ENGINE_NO_FLOW) != 0))

    {
      SSH_DEBUG(SSH_D_LOWOK, ("Rule usage didn't match: flags=0x%08x",
                              (unsigned int) flags));
      return FALSE;
    }

  return TRUE;
}


/* Utility function for looking up a rule index for a flow, using selectors
   in the flow.  */

SshEnginePolicyRule
ssh_engine_find_flow_rule(SshEngine engine, SshUInt32 flow_index)
{
  SshEngineFlowData d_flow;
  SshEngineFlowDataStruct flow_struct;
  SshEngineFlowControl c_flow;
  unsigned char src_ip[SSH_IP_ADDR_SIZE], dst_ip[SSH_IP_ADDR_SIZE];
  unsigned int i, i2;
  SshEnginePolicyRule orig_rule, rule;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);
  SSH_ASSERT(c_flow->rule_index != SSH_IPSEC_INVALID_INDEX);
  orig_rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);

  /* Grab a copy of the actual flow instance in the fastpath, so
     we dont have to keep the fastpath flow locked for the duration
     of this operation, which can be costly in the case that
     a lot of rules exist. */
  d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);
  flow_struct = *d_flow;
  d_flow = &flow_struct;
  FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

  SSH_IP_ENCODE(&d_flow->src_ip, src_ip, i);
  SSH_IP_ENCODE(&d_flow->dst_ip, dst_ip, i2);
  SSH_ASSERT(i == i2);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("flow src %@ dst %@ srcport %d dstport %d tunnel_id %d",
             ssh_ipaddr_render, &d_flow->src_ip,
             ssh_ipaddr_render, &d_flow->dst_ip,
             d_flow->src_port, d_flow->dst_port, orig_rule->tunnel_id));

  rule = (SshEnginePolicyRule)
    ssh_engine_rule_generic_lookup(engine,
                                   engine->policy_rule_set,
                                   src_ip, dst_ip, i,
                                   orig_rule->tunnel_id,
                                   d_flow->src_port, d_flow->dst_port,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                                   d_flow->extension,
#else
                                   NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                                   ssh_engine_flow_test_fun,
                                   d_flow);

  return rule;
}

/* Context structure for ssh_engine_pme_find_transform_rule. */
typedef struct SshPmeFindTransformRuleCtx
{
  SshEngine engine;
  SshUInt32 protocol;
  SshUInt32 ifnum;
  SshUInt8 ipproto;
  SshUInt32 impl_tunnel_id;
  SshUInt32 trd_index;
  SshUInt32 flags;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  unsigned char peer_id[SSH_ENGINE_PEER_ID_SIZE];
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
} SshPmeFindTransformRuleCtxStruct, *SshPmeFindTransformRuleCtx;

/* Test function used by ssh_engine_pme_find_transform_rule. */

Boolean ssh_engine_tr_test_fun(SshEngine engine,
                               SshEngineLookupPreamble preamble,
                               const SshUInt32 *extensions,
                               void *context)
{
  SshPmeFindTransformRuleCtx c = (SshPmeFindTransformRuleCtx) context;
  SshEngineTransformData d_trd;
  SshEnginePolicyRule rule = (SshEnginePolicyRule) preamble;

  SSH_DEBUG(SSH_D_LOWOK, ("considering rule (type=%d flags=0x%x tr=0x%x)",
                          rule->type,
                          (unsigned int) rule->flags,
                          (unsigned int) rule->transform_index));

  /* Ignore anything but apply rules unless otherwise specified. */
  if ((rule->type != SSH_ENGINE_RULE_APPLY)
      && ((c->flags & SSH_PME_MATCH_TRIGGER_RULES) == 0
          || rule->type != SSH_ENGINE_RULE_TRIGGER
          || rule->transform_index == SSH_IPSEC_INVALID_INDEX))
    {
      SSH_DEBUG(SSH_D_MY, ("rule type does not match"));
      return FALSE;
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if ((rule->selectors & SSH_SELECTOR_EXTENSIONS) && extensions != NULL)
    {
      int i;

      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <=
              rule->extension_selector_high[i] &&
              (rule->extension_selector_low[i] > extensions[i] ||
               rule->extension_selector_high[i] < extensions[i]))
            return FALSE;
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Check the values for selectors that must match exactly. */
  if (c->protocol != rule->protocol)
    {
      SSH_DEBUG(SSH_D_MY, ("protocol does not match!"));
      return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_IFNUM)
      && c->ifnum != rule->selector_ifnum)
    {
      SSH_DEBUG(SSH_D_MY, ("selector does not match!"));
      return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_IPPROTO)
      && c->ipproto != rule->ipproto)
    {
      SSH_DEBUG(SSH_D_MY, ("ipproto does not match!"));
      return FALSE;
    }

  if (rule->flags & SSH_ENGINE_RULE_DELETED)
    {
      SSH_DEBUG(SSH_D_MY, ("rule already deleted!"));
      return FALSE;
    }

  if ((rule->flags & SSH_ENGINE_RULE_INACTIVE)
      && (c->flags & SSH_PME_MATCH_INACTIVE_RULES) == 0)
    {
      SSH_DEBUG(SSH_D_MY, ("rule inactive!"));
      return FALSE;
    }

  if (c->impl_tunnel_id)
    {
      SshEngineTransformControl c_trd;

      /* Verify that this transform implements the same tunnel. */
      SSH_ASSERT(rule->transform_index != SSH_IPSEC_INVALID_INDEX);

      d_trd = FASTPATH_GET_READ_ONLY_TRD(c->engine->fastpath,
                                         rule->transform_index);
      c_trd = SSH_ENGINE_GET_TRD(c->engine, rule->transform_index);
      SSH_ASSERT(d_trd != NULL);
      if (d_trd->inbound_tunnel_id != c->impl_tunnel_id)
        {
          SSH_DEBUG(SSH_D_MY, ("tunnel id does not match!"));
          FASTPATH_RELEASE_TRD(c->engine->fastpath, rule->transform_index);
          return FALSE;
        }
      FASTPATH_RELEASE_TRD(c->engine->fastpath, rule->transform_index);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if ((c->flags & SSH_PME_MATCH_PEER_ID)
          && memcmp(c->peer_id, c_trd->peer_id, sizeof(c->peer_id)) != 0)
        {
          SSH_DEBUG(SSH_D_MY, ("peer id does not match!"));
          return FALSE;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    }

  if (c->trd_index != SSH_IPSEC_INVALID_INDEX)
    {
      /* Verify that the rule applies correct transform. */
      if (rule->transform_index != c->trd_index)
        {
          SSH_DEBUG(SSH_D_MY, ("transform index does not match!"));
          return FALSE;
        }
    }

  /* Check additional match criteria from flags. */
  if (c->flags & SSH_PME_TRANSFORM_PER_PORT_SRC)
    {
      if (rule->selectors & SSH_SELECTOR_SRCIP)
        {
          /* Source IP selector. */
          if (memcmp(rule->src_ip_low, rule->src_ip_high,
                     sizeof(rule->src_ip_low)) != 0)
            {
              /* Source IP selector specifies a range. */
              SSH_DEBUG(SSH_D_MY, ("source ip selector does not match!"));
              return FALSE;
            }
        }

      if ((rule->selectors & SSH_SELECTOR_SRCPORT) == 0)
        {
          /* No source port selector. */
          SSH_DEBUG(SSH_D_MY, ("source port (low) selector does not match!"));
          return FALSE;
        }

      if (rule->src_port_low != rule->src_port_high)
        {
          SSH_DEBUG(SSH_D_MY, ("source port (high) selector does not match!"));
          /* Source port selector specifies a port range. */
          return FALSE;
        }
    }

  if (c->flags & SSH_PME_TRANSFORM_L2TP_PEER)
    {
      if (rule->selectors & SSH_SELECTOR_DSTIP)
        {
          /* Destination IP selector. */
          if (memcmp(rule->dst_ip_low, rule->dst_ip_high,
                     sizeof(rule->dst_ip_low)) != 0)
            {
              /* Destination IP selector specifies a range. */
              SSH_DEBUG(SSH_D_MY, ("dst ip selector does not match!"));
              return FALSE;
            }
        }
    }

  if (c->flags & SSH_PME_TRANSFORM_PER_PORT_DST)
    {
      if (rule->selectors & SSH_SELECTOR_DSTIP)
        {
          /* Destination IP selector. */
          if (memcmp(rule->dst_ip_low, rule->dst_ip_high,
                     sizeof(rule->dst_ip_low)) != 0)
            {
              /* Destination IP selector specifies a range. */
              SSH_DEBUG(SSH_D_MY, ("dst ip selector does not match!"));
              return FALSE;
            }
        }

      if ((rule->selectors & SSH_SELECTOR_DSTPORT) == 0)
        {
          /* No destination port selector. */
          SSH_DEBUG(SSH_D_MY, ("dst port (low) selector does not match!"));
          return FALSE;
        }

      if (rule->dst_port_low != rule->dst_port_high)
        {
          /* Destination port selector specifies a port range. */
          SSH_DEBUG(SSH_D_MY, ("dst port (high) selector does not match!"));
          return FALSE;
        }
    }

  if ((c->flags & SSH_PME_REQUIRE_POLICY_CONTEXT)
      && rule->policy_context == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("rule does not have required policy context"));
      return FALSE;
    }

  /* Accept the first apply rule we find (precedence will be handled by
     the generic lookup mechanism). */
  return TRUE;
}

/* Utility function for looking up a rule index for a SSH_ENGINE_RULE_APPLY
   rule, which should have selectors matching the parameters. Return
   a valid rule index if found. Otherwise return SSH_IPSEC_INVALID_INDEX.
   See the documentation for ssh_engine_pme_find_transform_rule(). */
SshUInt32
ssh_engine_find_transform_rule(SshEngine engine,
                               SshUInt32 tunnel_id,
                               SshUInt32 ifnum,
                               const SshIpAddr src_ip,
                               const SshIpAddr dst_ip,
                               SshUInt8 ipproto,
                               SshUInt16 src_port,
                               SshUInt16 dst_port,
                               SshUInt32 impl_tunnel_id,
                               SshUInt32 trd_index,
                               unsigned char *peer_id,
                               SshUInt32 flags)
{
  SshEnginePolicyRule rule;
  unsigned char src_ip_buf[SSH_IP_ADDR_SIZE], dst_ip_buf[SSH_IP_ADDR_SIZE];
  size_t addrlen;
  SshUInt32 rule_index = SSH_IPSEC_INVALID_INDEX;
  SshInterceptorProtocol protocol;
  SshPmeFindTransformRuleCtxStruct c;

  SSH_DEBUG(SSH_D_MY,
            ("ifnum %d src %@:%d dst: %@:%d tunnel_id=%d impl_tunnel_id=%d",
             (int) ifnum, ssh_ipaddr_render, src_ip, src_port,
             ssh_ipaddr_render, dst_ip, dst_port,
             (int) tunnel_id, (int) impl_tunnel_id));

  /* Require that rule base is locked */
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Format IP addresses and determine protocol. */
#if defined (WITH_IPV6)
  if (SSH_IP_IS4(dst_ip))
    {
#endif /* WITH_IPV6 */
      SSH_IP4_ENCODE(dst_ip, dst_ip_buf);
      SSH_IP4_ENCODE(src_ip, src_ip_buf);
      addrlen = 4;
      protocol = SSH_PROTOCOL_IP4;
#if defined (WITH_IPV6)
    }
  else
    {
      SSH_IP6_ENCODE(dst_ip, dst_ip_buf);
      SSH_IP6_ENCODE(src_ip, src_ip_buf);
      addrlen = 16;
      protocol = SSH_PROTOCOL_IP6;
    }
#endif /* WITH_IPV6 */

  /* Initialize the context structure. */
  c.engine = engine;
  c.protocol = protocol;
  c.ifnum = ifnum;
  c.ipproto = ipproto;
  c.impl_tunnel_id = impl_tunnel_id;
  c.trd_index = trd_index;
  c.flags = flags;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (peer_id != NULL)
    {
      memcpy(c.peer_id, peer_id, sizeof(c.peer_id));
      c.flags |= SSH_PME_MATCH_PEER_ID;
    }

#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Perform the lookup (locking data structures as needed). */
  rule = (SshEnginePolicyRule)
    ssh_engine_rule_generic_lookup(engine,
                                   engine->policy_rule_set,
                                   src_ip_buf, dst_ip_buf, addrlen,
                                   tunnel_id, src_port, dst_port,
                                   NULL,
                                   ssh_engine_tr_test_fun,
                                   (void *) &c);
  if (rule)
    {
      SSH_ASSERT(rule->type == SSH_ENGINE_RULE_APPLY);
      rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, rule);
      SSH_ASSERT(rule->transform_index != SSH_IPSEC_INVALID_INDEX);
    }
  return rule_index;
}


/* Tries to find an SSH_ENGINE_RULE_APPLY rule that would match a
   packet with the given source address, destination address, IP
   protocol, and port numbers (port numbers are ignored if the
   protocol does not have them).  Furthermore, rules with the
   SSH_ENGINE_NO_FLOW flag are ignored.  If a matching APPLY rule is
   found, this calls the callback with the transform_index of the highest
   precedence rule that matches.  If no rule matches, then this calls the
   callback with SSH_IPSEC_INVALID_INDEX.  The call to the callback may
   occur either during the call to this function or some time later. */

void ssh_engine_pme_find_transform_rule(SshEngine engine,
                                        SshUInt32 tunnel_id,
                                        SshUInt32 ifnum,
                                        const SshIpAddr src_ip,
                                        const SshIpAddr dst_ip,
                                        SshUInt8 ipproto,
                                        SshUInt16 src_port,
                                        SshUInt16 dst_port,
                                        SshUInt32 impl_tunnel_id,
                                        SshUInt32 trd_index,
                                        SshUInt32 flags,
                                        SshPmeSAIndexCB callback,
                                        void *context)
{
  SshUInt32 rule_index;
  SshPmTransform transform;
  SshEnginePolicyRule rule;
  SshEnginePolicyRuleStruct rule_ret;
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshUInt32 outbound_spi = SSH_IPSEC_INVALID_INDEX;
  SshUInt32 transform_index = SSH_IPSEC_INVALID_INDEX;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  rule_index = ssh_engine_find_transform_rule(engine, tunnel_id, ifnum,
                                              src_ip, dst_ip,
                                              ipproto, src_port, dst_port,
                                              impl_tunnel_id, trd_index,
                                              NULL, flags);

  if (rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, SSH_IPSEC_INVALID_INDEX, 0, context);
      return;
    }

  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  rule_ret = *rule;
  rule = &rule_ret;

  SSH_ASSERT(rule != NULL);
  SSH_ASSERT(rule->type == SSH_ENGINE_RULE_APPLY);
  transform_index = rule->transform_index;
  SSH_ASSERT(transform_index != SSH_IPSEC_INVALID_INDEX);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);

  if (c_trd != NULL)
    {
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);

      if (d_trd->transform & SSH_PM_IPSEC_AH)
        outbound_spi = d_trd->spis[SSH_PME_SPI_AH_OUT];
      else if (d_trd->transform & SSH_PM_IPSEC_ESP)
        outbound_spi = d_trd->spis[SSH_PME_SPI_ESP_OUT];
      else if (d_trd->transform & SSH_PM_IPSEC_IPCOMP)
        outbound_spi = d_trd->spis[SSH_PME_SPI_IPCOMP_OUT];

      transform = d_trd->transform;

#ifdef SSHDIST_L2TP
      if (flags & SSH_PME_TRANSFORM_L2TP_PEER)
        rule->nat_dst_port = d_trd->l2tp_remote_port;
#endif /* SSHDIST_L2TP */

      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
    }
  else
    transform = 0;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Call the policy manager callback. */
  (*callback)(engine->pm, rule, transform, outbound_spi, context);
}

/* Test function used by ssh_engine_find_equal_rule. */
static Boolean
ssh_engine_find_equal_test_fun(SshEngine engine,
                               SshEngineLookupPreamble preamble,
                               const SshUInt32 *extensions,
                               void *context)
{
  SshEnginePolicyRule pm_rule = (SshEnginePolicyRule) context;
  SshEnginePolicyRule rule = (SshEnginePolicyRule)preamble;
  size_t addrlen;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (rule->flags & SSH_ENGINE_RULE_DELETED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule is deleted!"));
      return FALSE;
    }

  if (pm_rule->type != rule->type
      || pm_rule->protocol != rule->protocol
      || pm_rule->selectors != rule->selectors
      || pm_rule->depends_on != rule->depends_on
      || pm_rule->flags != rule->flags
      || pm_rule->precedence != rule->precedence
      || pm_rule->tunnel_id != rule->tunnel_id)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("basic rule attributes do not match!"));
      return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_IPPROTO) &&
      pm_rule->ipproto != rule->ipproto)
    return FALSE;

  /* The generic rule lookup code only guarantees that the IP address
     used for the query is in the range. This does not yet mean that
     the range is exact match. */
  if (rule->protocol == SSH_PROTOCOL_IP6)
    addrlen = 16;
  else
    addrlen = 4;

  if (rule->selectors & SSH_SELECTOR_SRCIP)
    {
      if (memcmp(pm_rule->src_ip_low, rule->src_ip_low, addrlen) != 0
          || memcmp(pm_rule->src_ip_high, rule->src_ip_high, addrlen) != 0)
        return FALSE;
    }

  if (rule->selectors & SSH_SELECTOR_DSTIP)
    {
      if (memcmp(pm_rule->dst_ip_low, rule->dst_ip_low, addrlen) != 0
          || memcmp(pm_rule->dst_ip_high, rule->dst_ip_high, addrlen) != 0)
        return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_SRCPORT)
      && (pm_rule->src_port_low != rule->src_port_low
          || pm_rule->src_port_high != rule->src_port_high))
    return FALSE;

  if ((rule->selectors & SSH_SELECTOR_DSTPORT)
      && (pm_rule->dst_port_low != rule->dst_port_low
          || pm_rule->dst_port_high != rule->dst_port_high))
    return FALSE;

  if ((rule->selectors & SSH_SELECTOR_IFNUM)
      && pm_rule->selector_ifnum != rule->selector_ifnum)
    return FALSE;


  if ((rule->selectors & SSH_SELECTOR_RIID)
      && pm_rule->routing_instance_id != rule->routing_instance_id)
    return FALSE;

  if ((rule->selectors & SSH_SELECTOR_ICMPTYPE) ||
      (rule->selectors & SSH_SELECTOR_ICMPCODE))
    {
      if (pm_rule->dst_port_low != rule->dst_port_low)
        return FALSE;
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if ((rule->selectors & SSH_SELECTOR_EXTENSIONS) && extensions != NULL)
    {
      int i;

      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <=
              rule->extension_selector_high[i] &&
              (rule->extension_selector_low[i] > extensions[i] ||
               rule->extension_selector_high[i] < extensions[i]))
            return FALSE;
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */




  return TRUE;
}

/* Test function used when checking if an apply rule already exists in the
   engine when doing IPsec rekeys. */
static Boolean
ssh_engine_find_equal_rekey_test_fun(SshEngine engine,
                                     SshEngineLookupPreamble preamble,
                                     const SshUInt32 *extensions,
                                     void *context)
{
  SshEnginePolicyRule pm_rule = (SshEnginePolicyRule) context;
  SshEnginePolicyRule rule = (SshEnginePolicyRule)preamble;
  size_t addrlen;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (rule->flags & SSH_ENGINE_RULE_DELETED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule is deleted!"));
      return FALSE;
    }

  if (rule->transform_index != pm_rule->transform_index)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule has a different transform index"));
      return FALSE;
    }
  if ((rule->flags & SSH_ENGINE_RULE_REKEY_PENDING) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule is not pending rekey!"));
      return FALSE;
    }

  if (pm_rule->type != rule->type
      || pm_rule->selectors != rule->selectors
      || pm_rule->protocol != rule->protocol
      || pm_rule->depends_on != rule->depends_on
      || pm_rule->protocol != rule->protocol
      || pm_rule->precedence != rule->precedence
      || pm_rule->tunnel_id != rule->tunnel_id
      || pm_rule->ipproto != rule->ipproto)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("basic rule attributes do not match!"));
      return FALSE;
    }

  /* The generic rule lookup code only guarantees that the IP address
     used for the query is in the range. This does not yet mean that
     the range is exact match. */
  if (rule->protocol == SSH_PROTOCOL_IP6)
    addrlen = 16;
  else
    addrlen = 4;

  if (rule->selectors & SSH_SELECTOR_SRCIP)
    {
      if (memcmp(pm_rule->src_ip_low, rule->src_ip_low, addrlen) != 0
          || memcmp(pm_rule->src_ip_high, rule->src_ip_high, addrlen) != 0)
        return FALSE;
    }

  if (rule->selectors & SSH_SELECTOR_DSTIP)
    {
      if (memcmp(pm_rule->dst_ip_low, rule->dst_ip_low, addrlen) != 0
          || memcmp(pm_rule->dst_ip_high, rule->dst_ip_high, addrlen) != 0)
        return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_SRCPORT)
      && (pm_rule->src_port_low != rule->src_port_low
          || pm_rule->src_port_high != rule->src_port_high))
    return FALSE;

  if ((rule->selectors & SSH_SELECTOR_DSTPORT)
      && (pm_rule->dst_port_low != rule->dst_port_low
          || pm_rule->dst_port_high != rule->dst_port_high))
    return FALSE;

  if ((rule->selectors & SSH_SELECTOR_IFNUM)
      && pm_rule->selector_ifnum != rule->selector_ifnum)
    return FALSE;


  if ((rule->selectors & SSH_SELECTOR_RIID)
      && pm_rule->routing_instance_id != rule->routing_instance_id)
      return FALSE;


  if ((rule->selectors & SSH_SELECTOR_ICMPTYPE) ||
      (rule->selectors & SSH_SELECTOR_ICMPCODE))
    {
      if (pm_rule->dst_port_low != rule->dst_port_low)
        return FALSE;
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if ((rule->selectors & SSH_SELECTOR_EXTENSIONS) && extensions != NULL)
    {
      int i;

      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <=
              rule->extension_selector_high[i] &&
              (rule->extension_selector_low[i] > extensions[i] ||
               rule->extension_selector_high[i] < extensions[i]))
            return FALSE;
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */




  return TRUE;
}


SshEnginePolicyRule
ssh_engine_find_equal_rule(SshEngine engine, const SshEnginePolicyRule pm_rule)
{
  size_t addrlen;
  SshEnginePolicyRule match;

  if (pm_rule->protocol == SSH_PROTOCOL_IP6)
    addrlen = 16;
  else
    addrlen = 4;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  match = (SshEnginePolicyRule)
    ssh_engine_rule_generic_lookup(engine,
                                   engine->policy_rule_set,
                                   pm_rule->src_ip_low,
                                   pm_rule->dst_ip_low,
                                   addrlen,
                                   pm_rule->tunnel_id,
                                   pm_rule->src_port_low,
                                   pm_rule->dst_port_low,
                                   NULL,
                                   ssh_engine_find_equal_test_fun,
                                   pm_rule);
  return match;
}


SshEnginePolicyRule
ssh_engine_find_equal_rekey_rule(SshEngine engine,
                                 const SshEnginePolicyRule pm_rule)
{
  size_t addrlen;
  SshEnginePolicyRule match;

  if (pm_rule->protocol == SSH_PROTOCOL_IP6)
    addrlen = 16;
  else
    addrlen = 4;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  match = (SshEnginePolicyRule)
    ssh_engine_rule_generic_lookup(engine,
                                   engine->policy_rule_set,
                                   pm_rule->src_ip_low,
                                   pm_rule->dst_ip_low,
                                   addrlen,
                                   pm_rule->tunnel_id,
                                   pm_rule->src_port_low,
                                   pm_rule->dst_port_low,
                                   NULL,
                                   ssh_engine_find_equal_rekey_test_fun,
                                   pm_rule);
  return match;
}



/* Context structure for ssh_engine_pme_find_matching_transform_rule. */
typedef struct SshPmeFindMatchingTransformRuleCtx
{
  SshEngine engine;
  SshEnginePolicyRule rule;
  SshUInt32 flags;
  SshPmTransform transform;
  SshUInt32 cipher_key_size;
  size_t addrlen;
  SshIpAddrStruct peer_ip;
  SshIpAddrStruct local_ip;
  SshUInt16 local_port;
  SshUInt16 remote_port;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  unsigned char peer_id[SSH_ENGINE_PEER_ID_SIZE];
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
} SshPmeFindMatchingTransformRuleCtxStruct,
  *SshPmeFindMatchingTransformRuleCtx;

/* The flags which are meaningful in the matching transform lookup.
   Some flags in the rule's flags fields are internal and their state
   is not known to the policy manager and therefore they can not be
   used in comparison.  This mask matches all `SSH_SELECTOR_*' flags
   except source and destination IP addresses.  They can not be
   checked since in the L2TP+NAT-T case those selectors are ignored.
   The validity of those selectors is checked explicitly in the test
   function. */
#define SSH_ENGINE_SELECTOR_FLAGS_MASK 0xfff3


/* Test function used by ssh_engine_pme_find_matching_transform_rule. */
Boolean ssh_engine_matching_tr_test_fun(SshEngine engine,
                                        SshEngineLookupPreamble preamble,
                                        const SshUInt32 *extensions,
                                        void *context)
{
  SshEnginePolicyRule rule = (SshEnginePolicyRule) preamble;
  SshPmeFindMatchingTransformRuleCtx c
    = (SshPmeFindMatchingTransformRuleCtx) context;

  /* Check the values which must always match.  Note that since this
     function is used for determining responder rekeys, we will match
     also inactive rules. */
  if (((c->rule->selectors & SSH_ENGINE_SELECTOR_FLAGS_MASK)
       != (rule->selectors & SSH_ENGINE_SELECTOR_FLAGS_MASK))
      || c->rule->protocol != rule->protocol
      || c->rule->type != rule->type
      || c->rule->depends_on != rule->depends_on
      || c->rule->precedence != rule->precedence)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("candidate: selectors=0x%04x flags=0x08%x protocol=%d "
                 "type=%d depends_on=%d precedence=0x%08x",
                 rule->selectors, (unsigned int) rule->flags,
                 rule->protocol, rule->type,
                 (int) rule->depends_on,
                 (unsigned int) rule->precedence));

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("require: selectors=0x%04x flags=0x08%x protocol=%d type=%d "
                 "depends_on=%d precedence=0x%08x",
                 c->rule->selectors, (unsigned int) c->rule->flags,
                 c->rule->protocol,
                 c->rule->type,
                 (int) c->rule->depends_on,
                 (unsigned int) c->rule->precedence));

      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: basic attributes do not match!",
                                   (int) rule->rule_index));
      return FALSE;
    }

  if (rule->flags & SSH_ENGINE_RULE_DELETED)
    return FALSE;

  /* Check optional components. */

  if (rule->selectors & SSH_SELECTOR_SRCIP)
    {
      if ((c->rule->selectors & SSH_SELECTOR_SRCIP) == 0
          || memcmp(c->rule->src_ip_low, rule->src_ip_low, c->addrlen) != 0
          || memcmp(c->rule->src_ip_high, rule->src_ip_high, c->addrlen) != 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: srcip does not match!",
                                       (int) rule->rule_index));
          return FALSE;
        }
    }

  if (rule->selectors & SSH_SELECTOR_DSTIP)
    {
      if ((c->rule->selectors & SSH_SELECTOR_DSTIP) == 0
          || memcmp(c->rule->dst_ip_low, rule->dst_ip_low, c->addrlen) != 0
          || memcmp(c->rule->dst_ip_high, rule->dst_ip_high, c->addrlen) != 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: dstip does not match!",
                                       (int) rule->rule_index));

          return FALSE;
        }
    }

  if ((rule->selectors & SSH_SELECTOR_SRCPORT)
      && (c->rule->src_port_low != rule->src_port_low
          || c->rule->src_port_high != rule->src_port_high))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: src port does not match!",
                                   (int) rule->rule_index));
      return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_DSTPORT)
      && (c->rule->dst_port_low != rule->dst_port_low
          || c->rule->dst_port_high != rule->dst_port_high))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: dst port does not match!",
                                   (int) rule->rule_index));
      return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_IFNUM)
      && c->rule->selector_ifnum != rule->selector_ifnum
      && (c->flags & SSH_PME_RULE_MATCH_ANY_IFNUM) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: ifnum does not match!",
                                   (int) rule->rule_index));
      return FALSE;
    }

  if ((rule->selectors & SSH_SELECTOR_IPPROTO)
      && c->rule->ipproto != rule->ipproto)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: ipproto does not match!",
                                   (int) rule->rule_index));
      return FALSE;
    }






  if ((rule->selectors & SSH_SELECTOR_ICMPTYPE) ||
      (rule->selectors & SSH_SELECTOR_ICMPCODE))
    {
      /* ICMP type/code are encoded in the destination port selector */
      if (c->rule->dst_port_low != rule->dst_port_low)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: icmp type/code do not match!",
                                       (int) rule->rule_index));
          return FALSE;
        }
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if ((rule->selectors & SSH_SELECTOR_EXTENSIONS) && extensions != NULL)
    {
      int i;

      for (i = 0; i < SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS; i++)
        {
          if (rule->extension_selector_low[i] <=
              rule->extension_selector_high[i] &&
              (rule->extension_selector_low[i] > extensions[i] ||
               rule->extension_selector_high[i] < extensions[i]))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("rule %d: extension selectors do not match!",
                         (int) rule->rule_index));
              return FALSE;
            }
        }
    }
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Optional transform bits. */
  if (c->transform)
    {
      SshEngineTransformControl c_trd;
      SshEngineTransformData d_trd;

      SSH_ASSERT(rule->transform_index != SSH_IPSEC_INVALID_INDEX);
      c_trd = SSH_ENGINE_GET_TRD(c->engine, rule->transform_index);
      SSH_ASSERT(c_trd != NULL);

      /* Check if need to find an IKEv1 keyed SA. */
      if ((c->flags & SSH_PME_RULE_MATCH_IKEV1)
          && (c_trd->control_flags & SSH_ENGINE_TR_C_IKEV1_SA) == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: SA transform is not IKEv1: "
                                       "0x%08x",
                                       (int) rule->rule_index,
                                       (unsigned int) c_trd->peer_handle));
          return FALSE;
        }

      d_trd = FASTPATH_GET_READ_ONLY_TRD(c->engine->fastpath,
                                         rule->transform_index);
      SSH_ASSERT(d_trd != NULL);

      if (d_trd->transform != c->transform)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: transform does not match: "
                                       "0x%08x vs 0x%08x",
                                       (int) rule->rule_index,
                                       (unsigned int) d_trd->transform,
                                       (unsigned int) c->transform));
          FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
          return FALSE;
        }

      if (d_trd->transform & SSH_PM_CRYPT_MASK)
        {
          if (d_trd->cipher_key_size != c->cipher_key_size)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("rule %d: transform does not match: "
                         "0x%08x vs 0x%08x",
                         (int) rule->rule_index,
                         (unsigned int) d_trd->transform,
                         (unsigned int) c->transform));
              FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
              return FALSE;
            }
        }

      if (SSH_IP_DEFINED(&c->peer_ip)
          && (!SSH_IP_EQUAL(&c->peer_ip, &d_trd->gw_addr)))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: peer ip does not match: "
                                       "%@ vs %@",
                                       (int) rule->rule_index,
                                       ssh_ipaddr_render, &c->peer_ip,
                                       ssh_ipaddr_render, &d_trd->gw_addr));
          FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
          return FALSE;
        }

      if (SSH_IP_DEFINED(&c->local_ip)
          && (!SSH_IP_EQUAL(&c->local_ip, &d_trd->own_addr)))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: own ip does not match: "
                                       "%@ vs %@",
                                       (int) rule->rule_index,
                                       ssh_ipaddr_render, &c->local_ip,
                                       ssh_ipaddr_render, &d_trd->own_addr));
          FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
          return FALSE;
        }

      if (c->local_port != d_trd->local_port ||
          (c->remote_port != 0 && c->remote_port != d_trd->remote_port))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("ports do not match: "
                                       "%d:%d vs %d:%d",
                                       c->local_port, c->remote_port,
                                       d_trd->local_port, d_trd->remote_port));
          FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
          return FALSE;
        }

      FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if ((c->flags & SSH_PME_RULE_MATCH_PEER_ID)
          && memcmp(c->peer_id, &c_trd->peer_id, SSH_ENGINE_PEER_ID_SIZE))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d: peer id's do not match!",
                                       (int) rule->rule_index));
          return FALSE;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("rule %d matches!",
                               (int) rule->rule_index));
  return TRUE;
}

/* Determines whether we have a matching apply rule already in the
   engine.  The rule must match the same selectors and have the same
   precedence value.  This is intended for determining whether a
   Quick-Mode responder negotiation is a rekey or it establishes a new
   SA.  This calls the callback with the transform data index of the
   matching rule or with the value SSH_IPSEC_INVALID_INDEX if there is
   no matching rule.  The call to the callback may occur either during
   the call to this functoin or some time later. */

void
ssh_engine_pme_find_matching_transform_rule(SshEngine engine,
                                            const SshEnginePolicyRule rule,
                                            SshPmTransform transform,
                                            SshUInt32 cipher_key_size,
                                            const SshIpAddr peer_ip,
                                            const SshIpAddr local_ip,
                                            SshUInt16 local_port,
                                            SshUInt16 remote_port,
                                            const unsigned char *peer_id,
                                            SshUInt32 flags,
                                            SshPmeSAIndexCB callback,
                                            void *context)
{
  SshEnginePolicyRule match;
  unsigned char src_ip_buf[SSH_IP_ADDR_SIZE], dst_ip_buf[SSH_IP_ADDR_SIZE];
  SshUInt16 src_port, dst_port;
  SshUInt32 transform_index = SSH_IPSEC_INVALID_INDEX;
  SshUInt32 transform_flags;
  SshUInt32 outbound_spi = SSH_IPSEC_INVALID_INDEX;
  SshPmeFindMatchingTransformRuleCtxStruct c;

  SSH_ASSERT(rule->type == SSH_ENGINE_RULE_APPLY);

  /* Construct a connection that matches the searched rule. */

  memset(src_ip_buf, 0, SSH_IP_ADDR_SIZE);
  if (rule->selectors & SSH_SELECTOR_SRCIP)
    /* The source IP selector is specified.  Let's use its low end. */
    memcpy(src_ip_buf, rule->src_ip_low, SSH_IP_ADDR_SIZE);

  memset(dst_ip_buf, 0, SSH_IP_ADDR_SIZE);
  if (rule->selectors & SSH_SELECTOR_DSTIP)
    memcpy(dst_ip_buf, rule->dst_ip_low, SSH_IP_ADDR_SIZE);

  /* Resolve the address length from the rule's protocol. */
  if (rule->protocol == SSH_PROTOCOL_IP6)
    c.addrlen = 16;
  else
    c.addrlen = 4;
  SSH_ASSERT(c.addrlen <= SSH_IP_ADDR_SIZE);

  /* Port numbers if specified. */

  if (rule->selectors & SSH_SELECTOR_SRCPORT)
    src_port = rule->src_port_low;
  else
    src_port = 0;

  if (rule->selectors & SSH_SELECTOR_DSTPORT)
    dst_port = rule->dst_port_low;
  else
    dst_port = 0;

  c.engine = engine;
  c.rule = rule;
  c.transform = transform;
  c.cipher_key_size = cipher_key_size;
  c.flags = flags;
  SSH_IP_UNDEFINE(&c.peer_ip);
  if (peer_ip)
    c.peer_ip = *peer_ip;

  SSH_IP_UNDEFINE(&c.local_ip);
  if (local_ip)
    c.local_ip = *local_ip;
  c.local_port = local_port;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (peer_id)
    {
      memcpy(c.peer_id, peer_id, SSH_ENGINE_PEER_ID_SIZE);
      c.flags |= SSH_PME_RULE_MATCH_PEER_ID;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
  c.remote_port = remote_port;

  /* Perform the lookup (locking data structures are needed).  The
     test function will check that the rules match exactly. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  match = (SshEnginePolicyRule)
    ssh_engine_rule_generic_lookup(engine,
                                   engine->policy_rule_set,
                                   src_ip_buf, dst_ip_buf, c.addrlen,
                                   rule->tunnel_id,
                                   src_port, dst_port,
                                   NULL,
                                   ssh_engine_matching_tr_test_fun,
                                   &c);

  transform_flags = 0;

  if (match)
    {
      SshEngineTransformControl c_trd;
      SshEngineTransformData d_trd;

      SSH_ASSERT(match->type == SSH_ENGINE_RULE_APPLY
                 || match->type == SSH_ENGINE_RULE_TRIGGER);

      transform_index = match->transform_index;
      SSH_ASSERT(transform_index != SSH_IPSEC_INVALID_INDEX);

      c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
      if (c_trd != NULL)
        {
          d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                             transform_index);

          if (d_trd->transform & SSH_PM_IPSEC_AH)
            outbound_spi = d_trd->spis[SSH_PME_SPI_AH_OUT];
          else if (d_trd->transform & SSH_PM_IPSEC_ESP)
            outbound_spi = d_trd->spis[SSH_PME_SPI_ESP_OUT];
          else if (d_trd->transform & SSH_PM_IPSEC_IPCOMP)
            outbound_spi = d_trd->spis[SSH_PME_SPI_IPCOMP_OUT];

          transform_flags = d_trd->transform;
          FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
        }
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Call the policy manager callback. */
  (*callback)(engine->pm, match, transform_flags, outbound_spi, context);
}

/* Allocates a policy rule object.  Returns the index of the new rule,
   or SSH_IPSEC_INVALID_INDEX if no more rule objects are available.
   Engine->flow_table_lock must be held when this is called. */

SshUInt32 ssh_engine_rule_allocate(SshEngine engine)
{
  SshUInt32 rule_index;
  SshEnginePolicyRule rule;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  rule_index = engine->rule_table_freelist;
  if (rule_index == SSH_IPSEC_INVALID_INDEX)
    return SSH_IPSEC_INVALID_INDEX;
  SSH_ASSERT(rule_index < engine->rule_table_size);
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  engine->rule_table_freelist = rule->transform_index;
  return rule_index;
}

/* Frees a policy rule object.  Engine->flow_table_lock must be held when
   this is called. */

void ssh_engine_rule_free(SshEngine engine, SshUInt32 rule_index)
{
  SshEnginePolicyRule rule;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(rule_index < engine->rule_table_size);
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  /* Free the rule object now. */
  SSH_ASSERT(rule->refcnt == 0);
  SSH_DEBUG(SSH_D_MIDOK, ("Recycling rule %u",
                          (int) rule_index));
  rule->type = SSH_ENGINE_RULE_NONEXISTENT;
#ifdef DEBUG_LIGHT
  rule->transform_index = 0xdeadbeef;
  rule->depends_on = 0xdeadbeef;
#endif /* DEBUG_LIGHT */
  rule->transform_index = engine->rule_table_freelist;
  engine->rule_table_freelist = rule_index;
}
