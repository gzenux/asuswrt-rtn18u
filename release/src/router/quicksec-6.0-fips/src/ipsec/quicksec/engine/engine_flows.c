/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Flow manipulation functions for the engine (excluding flow lookup, which
   takes place in engine_fastpath.c).
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineFlows"

/* Audits a flow event `event' for the flow `flow'.  The
   engine->flow_control_table_lock must be held when this is called. */

void ssh_engine_audit_flow_event(SshEngine engine, SshUInt32 flow_index,
                                 SshAuditEvent event)
{
  SshEnginePolicyRule rule;
  SshEngineAuditEvent c;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt32 index;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

  if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_LOG_CONNECTIONS) == 0
      || (c_flow->control_flags & SSH_ENGINE_FLOW_C_UNDEFINED) != 0)
    return;

  /* Index to the audit queue to which this audit event should be placed. */
  index = SSH_ENGINE_AUDIT_LEVEL_INFORMATIONAL;
  SSH_ASSERT(index < SSH_ENGINE_NUM_AUDIT_LEVELS);

  if (ssh_engine_audit_rate_limit(engine, index) == TRUE)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Not auditing this event due to rate limiting"));
      engine->audit_flags |= SSH_ENGINE_AUDIT_RATE_LIMITED_EVENT;
      return;
    }

  /* Check if we have space to audit this event, if not we return without
     auditing it. */
  if (engine->audit_table_head[index] ==
      SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_tail[index]))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("Not auditing this event due to resource "
                               "shortages"));
      engine_audit_busy(engine);
      return;
    }

  d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);

  c = &engine->audit_table[index][engine->audit_table_tail[index]];
  memset(c, 0, sizeof(*c));

  engine->audit_event_id++;
  c->audit_id = engine->audit_event_id;

  c->engine = engine;
  c->event = event;
  c->ipproto = d_flow->ipproto;
  c->src_ip = d_flow->src_ip;
  c->dst_ip = d_flow->dst_ip;
  c->src_ifnum = d_flow->incoming_forward_ifnum;
  c->dst_ifnum = d_flow->incoming_reverse_ifnum;
  c->src_port = d_flow->src_port;
  c->dst_port = d_flow->dst_port;
  c->icmp_type = (d_flow->dst_port >> 8) & 0xff;
  c->icmp_code = d_flow->dst_port & 0xff;
  FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

  /* This audit event is not associated with any SPI */
  c->spi = 0;

  /* Compute from tunnel and to tunnel id's */
  c->from_tunnel_id = c->to_tunnel_id = 0;

  if (c_flow->rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
      c->from_tunnel_id = rule->tunnel_id;
      if (rule->transform_index != SSH_IPSEC_INVALID_INDEX)
        {
          SshEngineTransformData d_trd;

          d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                             rule->transform_index);
          SSH_ASSERT(d_trd != NULL);
          c->to_tunnel_id = d_trd->inbound_tunnel_id;
          FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
        }
    }

  /* Move tail pointer ahead one slot. The actual auditing is done when
     the policymanager requests the engine to send it the available audit
     messages. */
  engine->audit_table_tail[index] =
    SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_tail[index]);

  engine_audit_new_event(engine);
}

#ifndef FASTPATH_PROVIDES_LRU_FLOWS
/* Engine side implementation of finding LRU flows, used in the
   case where the fastpath does not provide such functionality. */








SshUInt32
engine_get_lru_flow(SshEngine engine, SshUInt32 lru_level)
{
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt32 flow_index, i, max_to_search = 200;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  flow_index = engine->flow_lru_next + 1;
  if (flow_index >= engine->flow_table_size)
    flow_index = 0;

  /* Search for the first flow with LRU level not greater than
     'lru_level' that does not have the LRU REAP flag set. */
  for (i = 0; i < max_to_search; i++, flow_index++)
    {
      if (flow_index == engine->flow_table_size)
        flow_index = 0;

      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
      /* Skip any flows that are already free. */
      if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID))
        continue;

      d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);
      if (!(d_flow->data_flags & SSH_ENGINE_FLOW_D_VALID) ||
          (d_flow->data_flags & SSH_ENGINE_FLOW_D_NO_LRU_REAP) ||
          d_flow->flow_lru_level > lru_level)
        {
          FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
          continue;
        }
      FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
      SSH_DEBUG(SSH_D_LOWOK, ("Found a suitable flow for reaping index=%d",
                              (int) flow_index));
      engine->flow_lru_next = flow_index;
      return flow_index;
    }

  engine->flow_lru_next = flow_index;
  return SSH_IPSEC_INVALID_INDEX;
}
#endif /* !FASTPATH_PROVIDES_LRU_FLOWS */


/* Free flows of LRU level 'lru_level' until at least 'nflows' are
   free in the flow table.  'nflows' MUST be less than
   SSH_ENGINE_MAX_REAP_FLOWS. Return TRUE if succesfull.

   If FALSE is returned, then no flows have been reaped. */
Boolean
ssh_engine_reap_flows(SshEngine engine, int lru_level, size_t nflows)
{
  SshEngineFlowControl c_flow;
  SshUInt32 already_free;
  SshUInt32 index, i, j;
  SshUInt32 to_be_freed[SSH_ENGINE_MAX_REAP_FLOWS];
  SshEngineFlowData d_flow;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(nflows < SSH_ENGINE_MAX_REAP_FLOWS);

  /* Count the amount of flows available for this operation
     on the freelist */
  already_free = 0;
  index = engine->flow_table_freelist;
  while (index != SSH_IPSEC_INVALID_INDEX && already_free < nflows)
    {
      already_free++;
      c_flow = SSH_ENGINE_GET_FLOW(engine, index);
      index = c_flow->control_next;
    }

  /* Compute a set of candidate flows to reap. */

  for (i = 0;
       (already_free + i) < nflows && i < SSH_ENGINE_MAX_REAP_FLOWS;
       i++)
    {
#ifdef FASTPATH_PROVIDES_LRU_FLOWS
      index = fastpath_get_lru_flow(engine->fastpath, lru_level);
#else /* FASTPATH_PROVIDES_LRU_FLOWS */
      index = engine_get_lru_flow(engine, lru_level);
#endif /* FASTPATH_PROVIDES_LRU_FLOWS */
      if (index == SSH_IPSEC_INVALID_INDEX)
        break;

      d_flow = FASTPATH_GET_FLOW(engine->fastpath, index);
      SSH_ASSERT(!(d_flow->data_flags & SSH_ENGINE_FLOW_D_NO_LRU_REAP));
      d_flow->data_flags |= SSH_ENGINE_FLOW_D_NO_LRU_REAP;
      FASTPATH_COMMIT_FLOW(engine->fastpath, index, d_flow);

      to_be_freed[i] = index;
    }

  if (already_free + i < nflows)
    {
      /* Reset the 'NO_LRU_REAP' bits. */
      for (j = 0; j < i; j++)
        {
          index = to_be_freed[j];
          d_flow = FASTPATH_GET_FLOW(engine->fastpath, index);
          SSH_ASSERT(d_flow->data_flags & SSH_ENGINE_FLOW_D_NO_LRU_REAP);
          d_flow->data_flags &= ~SSH_ENGINE_FLOW_D_NO_LRU_REAP;
          FASTPATH_COMMIT_FLOW(engine->fastpath, index, d_flow);
        }

      SSH_DEBUG(SSH_D_MY,
                ("failed to reap %d flows below lru level %d",
                 nflows, lru_level));
      return FALSE;
    }
  SSH_ASSERT(already_free + i == nflows);

  /* Then simply iterate over engine_free_flow a sufficient amount
     of times */
  for (j = 0; j < i; j++)
    {
      index = to_be_freed[j];

      SSH_ASSERT(index != SSH_IPSEC_INVALID_INDEX);
      SSH_ASSERT(already_free + j < nflows);

      ssh_engine_free_flow(engine, index);
    }

  SSH_ASSERT(already_free + j == nflows);

  SSH_DEBUG(SSH_D_LOWOK,
            ("reaped %ld flows to ensure that %ld flows are available",
             (long) nflows - already_free, (long) nflows));

  return TRUE;
}

/* Return the greatest LRU level of flows which can be reaped
   to make space in the flow table for flows associated
   with the rule with index 'rule_index'. */
int
ssh_engine_flow_reap_lru_level(SshEngine engine,
                               SshUInt32 rule_index)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* An alternative version, which goes up to any non-IPSEC level
     to find a freeable flow record.  It is apparently still an
     open question which of these to alternatives better. */
  return (SSH_ENGINE_N_FLOW_LRU_LEVELS - 1);
}

/* The ssh_engine_flow_is_no_flow() functions returns TRUE, if
   the flow parameters are such, that a flow creation can not
   be supported. This gives the rule execution state machine a hint
   that the packet may be handled as a no-flow packet IF acceptable
   (no NAT, etc..) */
Boolean
ssh_engine_flow_is_no_flow(SshUInt8 ipproto, SshUInt16 dst_port)
{
  if ((ipproto == SSH_IPPROTO_ICMP && dst_port != 0x0800)
      || (ipproto == SSH_IPPROTO_IPV6ICMP && dst_port != 0x8000))
    return TRUE;

  return FALSE;
}


/* Creates and initializes a new flow table node, and adds it to the
   flow hash table (both forward and reverse lists).  `rule_index' is
   the rule that caused this flow to be created; it can be
   SSH_IPSEC_INVALID_INDEX, in which case the flow is not associated
   with any rule.  `flags' is the initial flags for the node (0 for
   normal nodes, SSH_ENGINE_FLOW_D_IPSECINCOMING for incoming IPSEC
   flows).  This returns the index of the node in
   `*flow_index_return'.  This returns TRUE on success, and FALSE if
   the flow could be allocated (for example, the flow table is full).
   If `forward_nh_index' and/or `reverse_nh_index' are set, they must
   already have a reference counted for each of them.  If
   `forward_transform_index' and/or `reverse_transform_index' is set,
   then this increments the reference count of the transform if
   successful.  Engine->flow_table_lock must be held when this is
   called. */

Boolean ssh_engine_create_flow(SshEngine engine,
                               SshUInt32 rule_index,
                               const unsigned char *forward_flow_id,
                               SshIpAddr src_ip,
                               SshIpAddr dst_ip,
                               SshUInt8 ipproto,
                               SshUInt16 src_port,
                               SshUInt16 dst_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                               SshUInt32 ifnum_dst,
                               SshUInt32 ifnum_src,
                               Boolean local_dst,
                               Boolean local_src,
                               SshUInt16 mtu_dst,
                               SshUInt16 mtu_src,
                               SshUInt32 route_selector_dst,
                               SshUInt32 route_selector_src,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                               SshUInt32 forward_nh_index,
                               SshUInt32 reverse_nh_index,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                               SshEngineIfnum incoming_forward_ifnum,
                               SshEngineIfnum incoming_reverse_ifnum,
#ifdef SSHDIST_IPSEC_NAT
                               const SshIpAddr nat_src,
                               const SshIpAddr nat_dst,
                               SshUInt16 nat_src_port,
                               SshUInt16 nat_dst_port,
#endif /* SSHDIST_IPSEC_NAT */
                               SshUInt32 protocol_xid,
                               SshUInt16 c_flags,
                               SshUInt32 d_flags,
                               SshUInt32 forward_transform_index,
                               SshUInt32 reverse_transform_index,
                               SshUInt32 idle_timeout,
                               SshUInt32 max_lifetime,
                               SshVriId routing_instance_id,
                               SshUInt32 *extension,
                               SshUInt32 *flow_index_return)
{
  SshEngineFlowData d_flow;
  SshEngineFlowControl c_flow, c_flow2;
  SshUInt32 flow_index, rule_trd_index, norule_trd_index;
  SshEngineTransformControl c_trd;
  SshEnginePolicyRule rule;
  int level, i, same = 0;
  Boolean dangle_flow;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_MY,
            ("creating flow: ipproto=%u %@:%u -> %@:%u "
             "rule=%d reverse transform=0x%08x "
             "forward transform=0x%08x c_flags=0x%04x d_flags=0x%04x "
             "incoming_forward_ifnum=%d incoming_reverse_ifnum=%d"
             " routing instance id %d",
             ipproto,
             ssh_ipaddr_render, src_ip, src_port,
             ssh_ipaddr_render, dst_ip, dst_port,
             (unsigned int) rule_index,
             (unsigned int) reverse_transform_index,
             (unsigned int) forward_transform_index,
             (unsigned int) c_flags,
             (unsigned int) d_flags,
             (unsigned int) incoming_forward_ifnum,
             (unsigned int) incoming_reverse_ifnum,
             routing_instance_id));

  /* Check that transform indexes are valid. */
  SSH_ASSERT(forward_transform_index == SSH_IPSEC_INVALID_INDEX ||
             forward_transform_index != reverse_transform_index);

  if (ssh_engine_flow_is_no_flow(ipproto, dst_port))
    {
      /* Currently we only support the creation of ICMP flows from
         ICMP echo _request_ packets. If it is desirable to create
         flows from "icmp responses", then this must be taken into
         account when computing the reverse flow id and verifying
         the forward flow id below. */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("ICMP non-echo request. Flow create denied!"));
      return FALSE;
    }

  if (forward_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, forward_transform_index);
      if (c_trd == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Forward transform index is not valid"));
          return FALSE;
        }
    }
  if (reverse_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, reverse_transform_index);
      if (c_trd == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Reverse transform index is not valid"));
          return FALSE;
        }
   }

  level = ssh_engine_flow_reap_lru_level(engine, rule_index);

  if (ssh_engine_reap_flows(engine, level, 1) == FALSE)
    {
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.out_of_flows++;
#endif /* SSH_IPSEC_STATISTICS */

      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate flow"));
      return FALSE;
    }

  /* Allocate a flow descriptor. */
  flow_index = engine->flow_table_freelist;
  SSH_ASSERT(flow_index < engine->flow_table_size);
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

  /* Build datastructure on a local copy to avoid double locking */

  d_flow = FASTPATH_INIT_FLOW(engine->fastpath, flow_index);

  if (engine->flow_table_freelist == engine->flow_table_freelist_last)
    same = 1;

  engine->flow_table_freelist = c_flow->control_next;
  /* Was the index last in the freelist? */
  if (same)
    engine->flow_table_freelist_last = engine->flow_table_freelist;

  SSH_DEBUG(SSH_D_LOWOK, ("Allocated flow %d", (int)flow_index));

  engine->num_free_flows--;
  SSH_ASSERT(engine->num_free_flows < engine->flow_table_size);

  *flow_index_return = SSH_ENGINE_FLOW_WRAP_INDEX(d_flow->generation,
                                                  flow_index);

  /* Initialize the fields of the flow object to temporary sane values. */
  d_flow->data_flags = d_flags | SSH_ENGINE_FLOW_D_VALID;
  c_flow->control_flags = SSH_ENGINE_FLOW_C_VALID | c_flags;
  d_flow->src_ip = *src_ip;
  d_flow->dst_ip = *dst_ip;
  d_flow->ipproto = ipproto;
  d_flow->src_port = src_port;
  d_flow->dst_port = dst_port;
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SSH_ASSERT(extension != NULL);
  memcpy(d_flow->extension, extension, sizeof(d_flow->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */


#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  d_flow->forward_ifnum = ifnum_dst;
  d_flow->reverse_ifnum = ifnum_src;
  d_flow->forward_local = local_dst;
  d_flow->reverse_local = local_src;
  d_flow->forward_mtu = mtu_dst;
  d_flow->reverse_mtu = mtu_src;
  d_flow->forward_route_selector = route_selector_dst;
  d_flow->reverse_route_selector = route_selector_src;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  d_flow->forward_nh_index = forward_nh_index;
  d_flow->reverse_nh_index = reverse_nh_index;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  d_flow->incoming_forward_ifnum = incoming_forward_ifnum;
  d_flow->incoming_reverse_ifnum = incoming_reverse_ifnum;
  d_flow->forward_transform_index = forward_transform_index;
  d_flow->reverse_transform_index = reverse_transform_index;
  d_flow->last_packet_time = engine->run_time;

  /* Set the routing instance ID. */
  d_flow->routing_instance_id = routing_instance_id;

  for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
    {
      d_flow->forward_rx_transform_index[i] = SSH_IPSEC_INVALID_INDEX;
      d_flow->reverse_rx_transform_index[i] = SSH_IPSEC_INVALID_INDEX;
    }

  c_flow->idle_timeout = (idle_timeout == 0) ? 0xffffffff : idle_timeout;
  c_flow->hard_expire_time =
    (max_lifetime == 0) ? 0 : (engine->run_time + max_lifetime);
  c_flow->metric = (SshUInt16) engine->transform_dpd_timeout;
  c_flow->rekey_attempts = 0;

  /* Add the flow to rule->flows.  Note that rule->flows is protected by
     engine->flow_control_table_lock, not rule lock, and that we are
     currently holding a reference to the rule as required. */
  c_flow->rule_index = rule_index;
  rule_trd_index = SSH_IPSEC_INVALID_INDEX;
  rule = NULL;
  if (rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);
      c_flow->rule_index = rule_index;
      c_flow->rule_next = rule->flows;
      c_flow->rule_prev = SSH_IPSEC_INVALID_INDEX;
      if (rule->flows != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow2 = SSH_ENGINE_GET_FLOW(engine, rule->flows);
          c_flow2->rule_prev = flow_index;
        }
      rule->flows = flow_index;
#ifdef SSH_IPSEC_STATISTICS
      rule->stats.num_flows_active++;
      rule->stats.num_flows_total++;
#endif /* SSH_IPSEC_STATISTICS */
      if (rule->type == SSH_ENGINE_RULE_APPLY
          || (rule->type == SSH_ENGINE_RULE_TRIGGER
              && rule->transform_index != SSH_IPSEC_INVALID_INDEX))
        {
          rule_trd_index = rule->transform_index;

          /* Require that if 'rule' defines a transform, AT LEAST the
             forward_transform_index points to it. */
          SSH_ASSERT (rule->transform_index == d_flow->forward_transform_index
                      || (rule->transform_index
                          != d_flow->reverse_transform_index));
        }
    }

  /* This will be set to the index of a trd that is referenced from the flow
     but not from the rule that created the trd. */
  norule_trd_index = SSH_IPSEC_INVALID_INDEX;

  /* Increment the reference count of the forward trd if one was specified. */
  if (forward_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineTransformData d_trd;

      c_trd = SSH_ENGINE_GET_TRD(engine, forward_transform_index);
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                         forward_transform_index);
      SSH_ASSERT(c_trd != NULL);
      SSH_ASSERT(d_trd != NULL);
      SSH_ASSERT(d_trd->transform != 0);

#ifdef SSH_IPSEC_SMALL
      /* Register a engine age timeout to the soft expiry time of the
         transform. */
      ssh_engine_age_timeout_schedule_trd(engine,
                                          SSH_ENGINE_IPSEC_SOFT_EVENT_TIME
                                          (engine, c_flow, c_trd, 0));
#endif /* SSH_IPSEC_SMALL */

#ifdef SSHDIST_L2TP
      if (!(d_trd->transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP)))
#else /* SSHDIST_L2TP */
        if (!(d_trd->transform & SSH_PM_IPSEC_TUNNEL))
#endif /* SSHDIST_L2TP */
          d_flow->data_flags |= SSH_ENGINE_FLOW_D_FWD_REASSEMBLE;
      SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);
#ifdef SSH_IPSEC_STATISTICS
      c_trd->stats.num_flows_active++;
#endif /* SSH_IPSEC_STATISTICS */
      if ((forward_transform_index != rule_trd_index)
          && (rule == NULL
              || rule->type != SSH_ENGINE_RULE_TRIGGER
              || (rule->flags & SSH_ENGINE_RULE_UNDEFINED) == 0))
        norule_trd_index = forward_transform_index;

      FASTPATH_RELEASE_TRD(engine->fastpath, forward_transform_index);
    }

  /* Increment the reference count of the reverse trd if one was specified. */
  if (reverse_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineTransformData d_trd;

      c_trd = SSH_ENGINE_GET_TRD(engine, reverse_transform_index);
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                         reverse_transform_index);
      SSH_ASSERT(c_trd != NULL);
      SSH_ASSERT(d_trd != NULL);
      SSH_ASSERT(d_trd->transform != 0);

#ifdef SSH_IPSEC_SMALL
      /* Register a engine age timeout to the soft expiry time of the
         transform. */
      ssh_engine_age_timeout_schedule_trd(engine,
                                          SSH_ENGINE_IPSEC_SOFT_EVENT_TIME
                                          (engine, c_flow, c_trd, 0));
#endif /* SSH_IPSEC_SMALL */

#ifdef SSHDIST_L2TP
      if (!(d_trd->transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP)))
#else /* SSHDIST_L2TP */
        if (!(d_trd->transform & SSH_PM_IPSEC_TUNNEL))
#endif /* SSHDIST_L2TP */
          d_flow->data_flags |= SSH_ENGINE_FLOW_D_REV_REASSEMBLE;
      SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);
#ifdef SSH_IPSEC_STATISTICS
      c_trd->stats.num_flows_active++;
#endif /* SSH_IPSEC_STATISTICS */
      if (reverse_transform_index != rule_trd_index)
        norule_trd_index = reverse_transform_index;

      FASTPATH_RELEASE_TRD(engine->fastpath, reverse_transform_index);
    }

  /* Add the flow to the trd's list of flows that reference the trd but do not
     reference it from their rule. */
  if (norule_trd_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, norule_trd_index);
      SSH_ASSERT(c_trd != NULL);
      c_flow->control_prev = SSH_IPSEC_INVALID_INDEX;
      c_flow->control_next = c_trd->norule_flows;
      c_trd->norule_flows = flow_index;
      if (c_flow->control_next != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow2 = SSH_ENGINE_GET_FLOW(engine, c_flow->control_next);
          c_flow2->control_prev = flow_index;
        }
      SSH_DEBUG(SSH_D_MY, ("attaching flow %d to trd %d",
                           (int) flow_index, (int) norule_trd_index));
    }

#ifdef SSHDIST_IPSEC_NAT
  /* Save NAT domains and mappings, and increment their reference counts. */
  d_flow->nat_src_port = nat_src_port;
  d_flow->nat_dst_port = nat_dst_port;
  if (nat_src)
    d_flow->nat_src_ip = *nat_src;
  else
    SSH_IP_UNDEFINE(&d_flow->nat_src_ip);
  if (nat_dst)
    d_flow->nat_dst_ip = *nat_dst;
  else
    SSH_IP_UNDEFINE(&d_flow->nat_dst_ip);

  if (!ssh_engine_nat_register_port(engine, &d_flow->nat_src_ip,
                                    d_flow->nat_src_port) ||
      !ssh_engine_nat_register_port(engine, &d_flow->nat_dst_ip,
                                    d_flow->nat_dst_port))
    {
      d_flow->data_flags &= ~SSH_ENGINE_FLOW_D_VALID;
      FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);
      goto fail;
    }

  if ((d_flags & SSH_ENGINE_FLOW_D_NAT_SRC) && nat_src)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("flow nats src to %@:%u",
               ssh_ipaddr_render, nat_src, nat_src_port));

  if ((d_flags & SSH_ENGINE_FLOW_D_NAT_DST) && nat_dst)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("flow nats dst to %@:%u",
               ssh_ipaddr_render, nat_dst, nat_dst_port));

#ifdef SSHDIST_IPSEC_FIREWALL
  /* Default flow index always points to ourself, engine_rule_execute
     overrides this if/when necessary. */
  c_flow->pair_flow_idx = flow_index;
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Initialize protocol-specific fields.  */
  d_flow->protocol_xid = 0;
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
      d_flow->type = SSH_ENGINE_FLOW_TYPE_TCP;
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
      ssh_engine_tcp_init(engine, d_flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
      break;
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
      d_flow->type = SSH_ENGINE_FLOW_TYPE_UDP;
      /* NAT-T UDP SPI and DHCP xid */
      d_flow->protocol_xid = protocol_xid;
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
      ssh_engine_udp_init(engine, d_flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
      break;
    case SSH_IPPROTO_IPV6ICMP:
    case SSH_IPPROTO_ICMP:
      d_flow->type = SSH_ENGINE_FLOW_TYPE_ICMP;
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
      ssh_engine_icmp_init(engine, d_flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
      break;
    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
      d_flow->type = SSH_ENGINE_FLOW_TYPE_RAW;
      d_flow->protocol_xid = protocol_xid;
      break;
    default:



      d_flow->type = SSH_ENGINE_FLOW_TYPE_RAW;
      break;
    }

  memcpy(d_flow->forward_flow_id, forward_flow_id, SSH_ENGINE_FLOW_ID_SIZE);

  /* Compute reverse flow id from flow parameters. */
  if (ssh_engine_flow_compute_flow_id_from_flow(engine, flow_index, d_flow,
                                                FALSE,
                                                d_flow->reverse_flow_id)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to compute reverse flow id!"));

      /* Clear the flow id's. */
      memset(d_flow->forward_flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
      memset(d_flow->reverse_flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
      d_flow->data_flags &= ~SSH_ENGINE_FLOW_D_VALID;
      FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);
      goto fail;
    }

#ifdef DEBUG_LIGHT
  {
    unsigned char tmp_id[SSH_ENGINE_FLOW_ID_SIZE];

    /* Assert that the flow id in the forward direction has been computed
       correctly and can be re-computed correctly from the current state.

       If this is an ipsec incoming flow which has been created for an
       already existing transform, then the transform may have non-zero
       old_spis field, and tmp_id may be non-zero. */
    if ((d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0
        && ssh_engine_flow_compute_flow_id_from_flow(engine, flow_index,
                                                     d_flow, TRUE, tmp_id)
        && memcmp(d_flow->forward_flow_id, tmp_id, SSH_ENGINE_FLOW_ID_SIZE))
      {
        SSH_DEBUG(SSH_D_ERROR, ("Forward flow ID computation failure"));
        SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                          ("Flow 0x%lx forward flow_id",
                           (unsigned long) flow_index),
                          d_flow->forward_flow_id, SSH_ENGINE_FLOW_ID_SIZE);
        SSH_DEBUG_HEXDUMP(SSH_D_ERROR,
                          ("Reconstructed forward flow_id"),
                          tmp_id, SSH_ENGINE_FLOW_ID_SIZE);
        ssh_fatal("Forward flow ID computation failure!");
      }
  }
#endif /* DEBUG_LIGHT */

#ifdef SSH_IPSEC_STATISTICS
  memset(&d_flow->stats, 0, sizeof(d_flow->stats));
  engine->stats.active_flows++;
  engine->stats.total_flows++;
#endif /* SSH_IPSEC_STATISTICS */

  dangle_flow = (d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING
                 ? TRUE : FALSE);
  d_flow->data_flags &= ~SSH_ENGINE_FLOW_D_DANGLING;

  /* Commit flow to fastpath. Now it is temporarily there */
  FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (reverse_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, reverse_transform_index);
      SSH_ASSERT(c_trd != NULL);

      memcpy(c_flow->initiator_peer_id, c_trd->peer_id,
             sizeof(c_flow->initiator_peer_id));
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Audit the new session. */
  ssh_engine_audit_flow_event(engine, flow_index,
                              SSH_AUDIT_ENGINE_SESSION_START);

  if (dangle_flow)
    {
      if (ssh_engine_flow_dangle(engine, flow_index) == FALSE)
        goto fail;
    }

  /* Return success. */
  return TRUE;

 fail:

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Clear the next nop indices in the flow so the ssh_engine_free_flow()
     function does not decrement their reference counts */
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
  d_flow->forward_nh_index = SSH_IPSEC_INVALID_INDEX;
  d_flow->reverse_nh_index = SSH_IPSEC_INVALID_INDEX;

  FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ssh_engine_free_flow(engine, flow_index);
  return FALSE;
}

/* Creates an incoming IPSEC flow for the rule index. Both rule_index
   and rule's transform_index must be valid when this function is
   called. This returns the flow index of the new flow, or
   SSH_IPSEC_INVALID_INDEX if it could not be created (e.g., flow
   table was full).  Engine->flow_table_lock must be held when this is
   called.

   Note on extension selector use:
   This function is called from ssh_engine_pme_add_rule() when policymanager
   is called. The engine has currently no knowledge of the extension
   selector value in use when computing the flow id (the rule
   owning this flow contains a range of extensions selectors). If
   incoming ipsec flows MUST also use extension selector values in
   lookup, then changes are required in:
   - SshEngineTransformDataRec (instance must contain extension selector
   value).
   - Flow id computation for IPsec packets and transforms.
   - Engine/Policymanager API. */
SshUInt32 ssh_engine_create_incoming_ipsec_flow(SshEngine engine,
                                                SshUInt32 rule_index,
                                                SshUInt32 life_seconds)
{
  unsigned char flow_id[SSH_ENGINE_FLOW_ID_SIZE];
  SshEnginePolicyRule rule;
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshUInt8 ipproto;
  SshUInt16 src_port, dst_port;
  SshUInt32 flow_index;
  SshUInt32 idle_timeout;
  SshIpAddrStruct src_ip, dst_ip;
  SshEngineIfnum ifnum;
  SshUInt16 c_flags, d_flags;
#ifdef SSHDIST_IPSEC_NAT
  SshIpAddr nat_src_ip;
  SshUInt16 nat_src_port;
#endif /* SSHDIST_IPSEC_NAT */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SSH_INTERCEPTOR_STACK_MARK();

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memset(extension, 0, sizeof(extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  SSH_ASSERT(rule != NULL);

  c_trd = SSH_ENGINE_GET_TRD(engine, rule->transform_index);
  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                     rule->transform_index);
  SSH_ASSERT(c_trd != NULL);
  SSH_ASSERT(d_trd != NULL);

  /* Determine the IP protocol for packets arriving at the transform. */
  src_ip = d_trd->gw_addr;
  dst_ip = d_trd->own_addr;

  src_port = 0;
  dst_port = 0;

  /* Set the default ifnum and flags */
  ifnum = d_trd->own_ifnum;

  c_flags = SSH_ENGINE_FLOW_C_REROUTE_R | SSH_ENGINE_FLOW_C_REROUTE_I
    | SSH_ENGINE_FLOW_C_IPSECINCOMING;
  d_flags = SSH_ENGINE_FLOW_D_NO_LRU_REAP | SSH_ENGINE_FLOW_D_REV_REASSEMBLE
    | SSH_ENGINE_FLOW_D_FWD_REASSEMBLE | SSH_ENGINE_FLOW_D_IPSECINCOMING
    | SSH_ENGINE_FLOW_D_IGNORE_IFNUM;

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
  /* If we are a SCTP multi-homed rule, get the dst ip address from
     the rule. The incoming ipsec flow does not check the ifnum. */
  if (rule->flags & SSH_ENGINE_RULE_SCTP_MULTIHOME)
    {
      if (rule->protocol == SSH_PROTOCOL_IP4)
        SSH_IP_DECODE(&dst_ip, rule->src_ip_low, 4);
      else
        SSH_IP_DECODE(&dst_ip, rule->src_ip_low, 16);
    }
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

  /* All transforms must have one (and only one) primary flow, regardless
     of whether the transform is shared between multiple incoming IPsec
     flows. */
  if (!(c_trd->control_flags & SSH_ENGINE_TR_C_PRIMARY_IPSEC_FLOW_CREATED))
    {
      c_trd->control_flags |= SSH_ENGINE_TR_C_PRIMARY_IPSEC_FLOW_CREATED;
      c_flags |= SSH_ENGINE_FLOW_C_PRIMARY;
    }

  /* If this a rekey, then compute forward flow id for incoming IPsec flow
     from old SPIs. */
  if (d_trd->old_spis[SSH_PME_SPI_ESP_IN] != 0
      || d_trd->old_spis[SSH_PME_SPI_AH_IN] != 0
      || d_trd->old_spis[SSH_PME_SPI_IPCOMP_IN] != 0)
    {
      c_flags |= SSH_ENGINE_FLOW_C_REKEYOLD;
      idle_timeout = 30;

#ifdef SSH_IPSEC_MULTICAST
      /* If flow has multicast peer, then we need to calculate flow id
         with multicast destination ip address. */
      if (SSH_IP_IS_MULTICAST(&(d_trd->gw_addr)))
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Flow has multicast gw_addr, thus set"
                     " dst_ip = peer ip for flow id calculations"));
          if (!ssh_engine_compute_transform_flowid(engine, d_trd,
                                                   &(d_trd->gw_addr),
                                                   c_trd->outer_tunnel_id,
                                                   TRUE, flow_id))
            {
              SSH_DEBUG(SSH_D_FAIL, ("computing flow ID failed"));
              FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
              return SSH_IPSEC_INVALID_INDEX;
            }
        }
      else
#endif /* SSH_IPSEC_MULTICAST */
        if (!ssh_engine_compute_transform_flowid(engine, d_trd, &dst_ip,
                                                 c_trd->outer_tunnel_id,
                                                 TRUE, flow_id))
          {
            SSH_DEBUG(SSH_D_FAIL, ("computing flow ID failed"));
            FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
            return SSH_IPSEC_INVALID_INDEX;
          }
    }
  else
    {
      /* Not a rekey, set forward flow id to zero. */
      idle_timeout = 0;
      memset(flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (d_trd->transform & SSH_PM_IPSEC_NATT)
    {
      ipproto = SSH_IPPROTO_UDP;
      src_port = d_trd->remote_port;
      dst_port = d_trd->local_port;
    }
  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    if (d_trd->transform & SSH_PM_IPSEC_AH)
      {
        ipproto = SSH_IPPROTO_AH;
      }
    else
      {
        if (d_trd->transform & SSH_PM_IPSEC_ESP)
          ipproto = SSH_IPPROTO_ESP;
        else
          ipproto = SSH_IPPROTO_UDP;
      }

  /* Adjust lifetime for the soft event grace periods.  This also enforces
     certain sane minimum values for them. */
  life_seconds = SSH_ENGINE_IPSEC_HARD_EXPIRE_TIME(life_seconds);

#ifdef SSHDIST_IPSEC_NAT
  if (SSH_IP_DEFINED(&rule->nat_selector_dst_ip))
    {
      d_flags |= SSH_ENGINE_FLOW_D_NAT_SRC;
      nat_src_ip = &rule->nat_selector_dst_ip;
      nat_src_port = rule->nat_selector_dst_port;
    }
  else
    {
      nat_src_ip = NULL;
      nat_src_port = 0;
    }

#endif /* SSHDIST_IPSEC_NAT */

  FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);

  /* Create a flow descriptor for the incoming flow.  Note that we use zero
     flow id for the other direction; it is *extremely* unlikely (2^-128
     probability) that a real flow would have zero flow id).  Thus, the zero
     flow id effectively disables the flow in that direction. */
  if (!ssh_engine_create_flow(engine,
                              rule_index,
                              flow_id,
                              &src_ip, &dst_ip,
                              ipproto, src_port, dst_port,
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
                              0, 0, TRUE, FALSE, 0, 0, 0, 0,
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              SSH_IPSEC_INVALID_INDEX, SSH_IPSEC_INVALID_INDEX,
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
                              ifnum, ifnum,
#ifdef SSHDIST_IPSEC_NAT
                              nat_src_ip, NULL, nat_src_port, 0,
#endif /* SSHDIST_IPSEC_NAT */
                              0,
                              c_flags,
                              d_flags,
                              rule->transform_index,
                              SSH_IPSEC_INVALID_INDEX,
                              idle_timeout, life_seconds,
                              rule->routing_instance_id,
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
                              extension,
#else
                              NULL,
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
                              &flow_index))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("allocating incoming flow failed"));
      return SSH_IPSEC_INVALID_INDEX;
    }
  SSH_DEBUG(SSH_D_MIDOK, ("created incoming IPSEC flow %d", (int)flow_index));
  return flow_index;
}

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
static void
ssh_engine_flow_notification_now(void* ctx)

{
  SshEngineFlowNotification c = (SshEngineFlowNotification)ctx;

  SSH_DEBUG(SSH_D_ERROR, ("Flow; notification timeout"));

  SSH_INTERCEPTOR_STACK_MARK();

  if (ssh_engine_upcall_timeout(c->engine) == FALSE)
    {
      /* Free the packet and the context structure. */
      ssh_free(c);
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending flow free notification flow_index=%d",
             (int) c->flow_index));

  ssh_pmp_flow_free_notification(c->engine->pm, c->flow_index);
  ssh_free(c);
}
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

/* Reset the flow->rule association. Engine->flow_table_lock
   MUST be held during the call. Flow->forward_transform_index
   MUST be consistent with flow->rule->transform_index during
   the call. */
void
ssh_engine_flow_reset_rule(SshEngine engine, SshUInt32 flow_index)
{
  SshEnginePolicyRule rule;
  SshEngineFlowControl prev_flow, next_flow, c_flow;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);

  if (c_flow->rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
      SSH_ASSERT(rule != NULL);

      /* Remove rule->flow association */
      prev_flow = next_flow = NULL;

      if (c_flow->rule_next != SSH_IPSEC_INVALID_INDEX)
        next_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->rule_next);

      if (c_flow->rule_prev != SSH_IPSEC_INVALID_INDEX)
        prev_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->rule_prev);

      if (next_flow != NULL)
        next_flow->rule_prev = c_flow->rule_prev;

      if (prev_flow != NULL)
        prev_flow->rule_next = c_flow->rule_next;

      if (rule->flows == flow_index)
        rule->flows = c_flow->rule_next;

      /* Check if we are the incoming ipsec flow of a rule.  If so, clear
         the `incoming_ipsec_flow' field.  We know that an incoming flow
         always has the trd in its forward_transform_index, and we also
         know that each incoming ipsec flow must have a valid
         flow->rule_index.  We also update statistics. */
      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING)
        {
          /* This flow is no longer an ipsec incoming flow, keep the
             flag in sync. */
          SSH_ASSERT(rule->incoming_ipsec_flow == flow_index ||
                     rule->incoming_ipsec_flow == SSH_IPSEC_INVALID_INDEX);
          SSH_ASSERT(rule->type == SSH_ENGINE_RULE_APPLY
                     || rule->type == SSH_ENGINE_RULE_TRIGGER);
          rule->incoming_ipsec_flow = SSH_IPSEC_INVALID_INDEX;
        }
      c_flow->rule_index = SSH_IPSEC_INVALID_INDEX;
      c_flow->rule_next = SSH_IPSEC_INVALID_INDEX;
      c_flow->rule_prev = SSH_IPSEC_INVALID_INDEX;

#ifdef SSH_IPSEC_STATISTICS
      rule->stats.num_flows_active--;
#endif /* SSH_IPSEC_STATISTICS */
    }
}

/* Reset a flow<->trd association for either the
   forward or reverse transform. This sets either
   flow->forward_transform_index or flow->reverse_transform_index
   to SSH_IPSEC_INVALID_INDEX. engine->flow_control_table_lock
   must be held during the function call. If is_forward == FALSE,
   then flow->rule_index MUST still be valid. */
void
ssh_engine_flow_reset_trd(SshEngine engine, SshUInt32 flow_index,
                          SshEngineFlowData d_flow, Boolean is_forward)
{
  SshEnginePolicyRule rule;
  SshEngineTransformControl c_trd;
  SshEngineFlowControl next_flow, prev_flow, c_flow;
  SshUInt32 trd_idx;
  int i;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);
  SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID);

  SSH_DEBUG(SSH_D_MIDOK, ("flow_index=%d, is_forward=%d, trd_index=0x%08x",
                          (int) flow_index,
                          is_forward,
                          (unsigned int)
                          (is_forward ? d_flow->forward_transform_index
                           : d_flow->reverse_transform_index)));

  if (is_forward)
    {
      trd_idx = d_flow->forward_transform_index;
      d_flow->forward_transform_index = SSH_IPSEC_INVALID_INDEX;
    }
  else
    {
      trd_idx = d_flow->reverse_transform_index;
      d_flow->reverse_transform_index = SSH_IPSEC_INVALID_INDEX;
    }

  for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
    {
      if (is_forward)
        d_flow->reverse_rx_transform_index[i] = SSH_IPSEC_INVALID_INDEX;
      else
        d_flow->forward_rx_transform_index[i] = SSH_IPSEC_INVALID_INDEX;
    }

  if (trd_idx != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, trd_idx);
      SSH_ASSERT(c_trd != NULL);

      /* Mark that there is no primary flow for the transform. */
      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_PRIMARY)
        {
          c_trd->control_flags &= ~SSH_ENGINE_TR_C_PRIMARY_IPSEC_FLOW_CREATED;
        }

      if (c_flow->rule_index != SSH_IPSEC_INVALID_INDEX)
        {
          rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
          SSH_ASSERT(rule != NULL);

          SSH_ASSERT(is_forward == FALSE
                     || rule->type != SSH_ENGINE_RULE_APPLY
                     || rule->transform_index == trd_idx);

          if ((rule->type != SSH_ENGINE_RULE_TRIGGER
               || (rule->flags & SSH_ENGINE_RULE_UNDEFINED) == 0
               || is_forward == FALSE)
              && (trd_idx != rule->transform_index))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("transform is not rule->transform_index."));

              next_flow = prev_flow = NULL;
              if (c_flow->control_next != SSH_IPSEC_INVALID_INDEX)
                next_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->control_next);
              if (c_flow->control_prev != SSH_IPSEC_INVALID_INDEX)
                prev_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->control_prev);

              if (next_flow != NULL)
                next_flow->control_prev = c_flow->control_prev;

              if (prev_flow != NULL)
                prev_flow->control_next = c_flow->control_next;
              else
                {
                  c_trd->norule_flows = c_flow->control_next;
                  SSH_ASSERT(next_flow == NULL
                             || (next_flow->control_prev ==
                                 SSH_IPSEC_INVALID_INDEX));
                }

              c_flow->control_next = SSH_IPSEC_INVALID_INDEX;
              c_flow->control_prev = SSH_IPSEC_INVALID_INDEX;

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("detaching from norule_flows."));
            }
        }
      else
        SSH_DEBUG(SSH_D_NICETOKNOW, ("flow already detached from trd."));

#ifdef SSH_IPSEC_STATISTICS
      c_trd->stats.num_flows_active--;
#endif /* SSH_IPSEC_STATISTICS */

      ssh_engine_decrement_transform_refcnt(engine, trd_idx);
    }
  else
    SSH_DEBUG(SSH_D_NICETOKNOW, ("no transform to reset."));
}

/* Set either the forward or reverse transform index for a flow.
   The relevant transform index must be SSH_IPSEC_INVALID_INDEX
   at the time of call (e.g. reset using ssh_engine_flow_reset_trd()).
   engine->flow_control_table_lock must be held during the call.
   flow->rule_index MUST be valid during the call. */
void
ssh_engine_flow_set_trd(SshEngine engine, SshUInt32 flow_index,
                        SshEngineFlowData d_flow,
                        Boolean is_forward, SshUInt32 new_trd_idx)
{
  SshEnginePolicyRule rule;
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshEngineFlowControl c_flow, c_flow2;
  SshUInt16 flow_frag_flags;

  SSH_DEBUG(SSH_D_MIDOK, ("flow_index=%d, trd_index=0x%08x",
                          (int) flow_index,
                          (unsigned int) new_trd_idx));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

 SSH_ASSERT(new_trd_idx != SSH_IPSEC_INVALID_INDEX);
  c_trd = SSH_ENGINE_GET_TRD(engine, new_trd_idx);
  if (c_trd == NULL)
    return;
  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, new_trd_idx);

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);
  rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
  SSH_ASSERT(rule != NULL);

  if (is_forward)
    {
      SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R);
      SSH_ASSERT(d_flow->forward_transform_index == SSH_IPSEC_INVALID_INDEX);
      d_flow->forward_transform_index = new_trd_idx;
      flow_frag_flags = SSH_ENGINE_FLOW_D_FWD_REASSEMBLE;
    }
  else
    {
      SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I);
      SSH_ASSERT(d_flow->reverse_transform_index == SSH_IPSEC_INVALID_INDEX);
      d_flow->reverse_transform_index = new_trd_idx;
      flow_frag_flags = SSH_ENGINE_FLOW_D_REV_REASSEMBLE;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      memcpy(c_flow->initiator_peer_id, c_trd->peer_id,
             sizeof(c_flow->initiator_peer_id));
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    }

#ifdef SSHDIST_L2TP
  if (!(d_trd->transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP)))
#else /* SSHDIST_L2TP */
    if (!(d_trd->transform & SSH_PM_IPSEC_TUNNEL))
#endif /* SSHDIST_L2TP */
      d_flow->data_flags |= flow_frag_flags;

  /* Here we could clear the flow_frag_flags bit, but this would only
     be useful in the case that a transform could switch from
     transform mode to tunnel mode, and then still we would be
     making the assumption that the FLOW_D_FWD_REASSEMBLE bits
     and FLOW_D_REV_REASSEMBLE bits would ONLY depends on the
     trd->transform. */

  SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);

#ifdef SSH_IPSEC_STATISTICS
  c_trd->stats.num_flows_active++;
#endif /* SSH_IPSEC_STATISTICS */

  if ((rule->type != SSH_ENGINE_RULE_TRIGGER
       || (rule->flags & SSH_ENGINE_RULE_UNDEFINED) == 0
       || is_forward == FALSE)
      && (rule->transform_index != new_trd_idx))
    {
      c_flow->control_prev = SSH_IPSEC_INVALID_INDEX;
      c_flow->control_next = c_trd->norule_flows;

      if (c_trd->norule_flows != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow2 = SSH_ENGINE_GET_FLOW(engine, c_trd->norule_flows);
          c_flow2->control_prev = flow_index;
        }

      c_trd->norule_flows = flow_index;
    }

  FASTPATH_RELEASE_TRD(engine->fastpath, new_trd_idx);
}

/* Set flow->rule association. Engine->flow_table_lock >MUST
   be held during the call. */
void
ssh_engine_flow_set_rule(SshEngine engine, SshUInt32 flow_index,
                         SshUInt32 rule_idx)
{
  SshEnginePolicyRule rule;
  SshEngineFlowControl c_flow, c_flow2;
#ifdef DEBUG_HEAVY
  /* Verify that the flow is not already in the rule->flows list */
  SshUInt32 temp_index;
  rule = SSH_ENGINE_GET_RULE(engine, rule_idx);
  SSH_ASSERT(rule != NULL);
  temp_index = rule->flows;
  while (temp_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, temp_index);
      SSH_ASSERT(c_flow != NULL);
      if (temp_index == flow_index)
        SSH_DEBUG(SSH_D_ERROR, ("ERROR: flow=%d already in rule=%d\n",
                                flow_index, rule_idx));
      temp_index = c_flow->rule_next;
    }
#endif /* DEBUG_HEAVY */

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);
  SSH_ASSERT(c_flow->rule_index == SSH_IPSEC_INVALID_INDEX);

  if (rule_idx != SSH_IPSEC_INVALID_INDEX)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_idx);
      SSH_ASSERT(rule != NULL);

      c_flow->rule_prev = SSH_IPSEC_INVALID_INDEX;
      c_flow->rule_next = rule->flows;

      if (rule->flows != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow2 = SSH_ENGINE_GET_FLOW(engine, rule->flows);
          c_flow2->rule_prev = flow_index;
        }

      rule->flows = flow_index;

#ifdef SSH_IPSEC_STATISTICS
      rule->stats.num_flows_active++;
#endif /* SSH_IPSEC_STATISTICS */
    }

  c_flow->rule_index = rule_idx;
}

/* Find a rule for the reverse_transform_index of flow 'flow', assuming
   that 'flow->rule_index' defines the forward_transform_index.
   The result is placed in *result, with the return value denoting
   success or failure. The assumption is that 'rule' and the rule it
   references are defined and they specify the transform
   applied in the forward direction. Other relevant flow parameters
   (src_ip, dst_ip, etc..) should be defined. The lock
   'engine->flow_control_table_lock' must be held during the call. */
Boolean
ssh_engine_flow_find_reverse_rule(SshEngine engine,
                                  SshUInt32 flow_index,
                                  SshEnginePolicyRule rule,
                                  SshUInt32 *result)
{
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshUInt32 rule_idx, tunnel_id;
  SshIpAddrStruct src_ip, dst_ip;
  SshUInt16 src_port, dst_port;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt32 d_idx;
  SshEngineIfnum incoming_ifnum;
  SshUInt8 ipproto;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(rule != NULL);

  *result = SSH_IPSEC_INVALID_INDEX;
  /* Compute tunnel id for packets coming in the reverse direction. */

  if (rule->tunnel_id == 0)
    {
      /* If the rule requires no tunnel to be used, then there
         obviously is no tunnel in the reverse direction.
         return with SSH_IPSEC_INVALID_INDEX and TRUE. */
      return TRUE;
    }

  SSH_ASSERT((rule->flags & SSH_ENGINE_RULE_UNDEFINED) == 0);

  if (rule->transform_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* If there is no forward transform, then the tunnel id in the
         reverse direction must be 0. */
      tunnel_id = 0;
    }
  else
    {
      /* If there is a transform in the forward direction, packets
         coming back through that transform must have the same
         tunnel id. */
      c_trd = SSH_ENGINE_GET_TRD(engine, rule->transform_index);
      if (c_trd == NULL)
        {
          return FALSE;
        }

      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                         rule->transform_index);
      tunnel_id = d_trd->inbound_tunnel_id;
      FASTPATH_RELEASE_TRD(engine->fastpath, rule->transform_index);
    }

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I) == 0)
    {
      if (c_flow->pair_flow_idx == SSH_IPSEC_INVALID_INDEX)
        {
          return FALSE;
        }
      d_idx = c_flow->pair_flow_idx;
    }
  else
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
    {
      d_idx = flow_index;
    }

  d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, d_idx);
  src_ip = d_flow->dst_ip;
  dst_ip = d_flow->src_ip;
  ipproto = d_flow->ipproto;
  incoming_ifnum = d_flow->incoming_reverse_ifnum;

  /* Do not reverse the src and dst ports for ICMP flows. */
  if ((ipproto == SSH_IPPROTO_ICMP) || (ipproto == SSH_IPPROTO_IPV6ICMP))
    {
      src_port = d_flow->src_port;
      dst_port = d_flow->dst_port;
    }
  else
    {
      src_port = d_flow->dst_port;
      dst_port = d_flow->src_port;
    }

  FASTPATH_RELEASE_FLOW(engine->fastpath, d_idx);


  rule_idx = ssh_engine_find_transform_rule(engine,
                                            tunnel_id,
                                            incoming_ifnum,
                                            &src_ip,
                                            &dst_ip,
                                            ipproto,
                                            src_port,
                                            dst_port,
                                            rule->tunnel_id,
                                            SSH_IPSEC_INVALID_INDEX,
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
                                            c_flow->initiator_peer_id,
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                                            NULL,
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
                                            SSH_PME_MATCH_INACTIVE_RULES);

  if (rule_idx == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Did not find transform rule!"));
      return FALSE;
    }

  *result = rule_idx;
  return TRUE;
}

SshUInt32
ssh_engine_find_dangle_rule(SshEngine engine, SshUInt32 rule_index)
{
  SshEnginePolicyRule rule, orig_rule;
  SshUInt32 orig_rule_index = rule_index;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(rule_index != SSH_IPSEC_INVALID_INDEX);
  orig_rule = SSH_ENGINE_GET_RULE(engine, rule_index);

  do {
    rule = SSH_ENGINE_GET_RULE(engine, rule_index);

    /* flow_undangle() depends on tunnel_id being preserved in dangling
       of the rule. If this is not the case, then "very strange" behaviour
       may occur, when flows actually "switch direction" or something
       even worse. */
    if (orig_rule->tunnel_id != rule->tunnel_id)
      return SSH_IPSEC_INVALID_INDEX;

    /* Allow the original rule to have been deleted. */
    if (rule_index != orig_rule_index &&
        rule->flags & SSH_ENGINE_RULE_DELETED)
      return SSH_IPSEC_INVALID_INDEX;

    if (rule->type == SSH_ENGINE_RULE_TRIGGER
        || rule->type == SSH_ENGINE_RULE_PASS)
      return rule_index;

    if (rule->type == SSH_ENGINE_RULE_APPLY)
      rule_index = rule->depends_on;
    else
      return SSH_IPSEC_INVALID_INDEX;

  } while (rule_index != SSH_IPSEC_INVALID_INDEX);

  return rule_index;
}

/* This function places a flow on the 'dangling' list. The flow
   MUST NOT already be 'dangling'. The flow is attached to a
   suitable rule (TRIGGER or PASS) if one is found, if not
   ssh_engine_flow_dangle() returns FALSE and the flow should
   be destroyed. All transforms are detached from the flow
   and forward_transform_index/reverse_transform_index are used
   for other purposes while the flow is dangling. The
   flow is removed from the reverse_flow_hash. IPsec incoming
   flows cannot be dangled (they result in a return value of FALSE).
   'engine->flow_control_table_lock' must be held during this call. */
Boolean
ssh_engine_flow_dangle(SshEngine engine, SshUInt32 flow_index)
{
  SshEngineFlowControl c_flow, c_flow2;
  SshEngineFlowData d_flow;
  SshEnginePolicyRule rule, orig_rule;
  SshUInt32 rule_index, orig_rule_index;
  SshUInt32 data_flags;

  SSH_DEBUG(SSH_D_MIDOK, ("Dangling flow %d", (int) flow_index));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (engine->ipm_open == FALSE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("PM channel not open. Dangling not possible.\n"));
      return FALSE;
    }

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  SSH_ASSERT(c_flow != NULL);

  d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
  data_flags = d_flow->data_flags;
#ifdef DEBUG_LIGHT
  d_flow = NULL;
#endif /* DEBUG_LIGHT */
  FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

  /* The engine can attempt to dangle already dangling flows,
     when e.g. policy lookups are disabled, or a flow
     is marked as "undefined". */
  if (data_flags & SSH_ENGINE_FLOW_D_DANGLING)
    return TRUE;

  SSH_ASSERT(c_flow->rule_index != SSH_IPSEC_INVALID_INDEX);

  rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);

  /* If we are associated with an APPLY rule, then move us to a
     trigger rule. */
  rule_index = c_flow->rule_index;
  SSH_ASSERT(rule_index != SSH_IPSEC_INVALID_INDEX);

  if (c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING)
    {
      SSH_ASSERT(rule->incoming_ipsec_flow == SSH_IPSEC_INVALID_INDEX
                 || rule->incoming_ipsec_flow == flow_index);
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Cannot dangle ipsec incoming flow!"));

      return FALSE;
    }
  SSH_ASSERT((data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0);

  SSH_ASSERT(flow_index != rule->incoming_ipsec_flow);

  orig_rule_index = c_flow->rule_index;
  orig_rule = SSH_ENGINE_GET_RULE(engine, orig_rule_index);

  if (orig_rule->tunnel_id == 1)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Internal decapsulation tunnel id used. "
                                   "Unable to dangle flow."));
      return FALSE;
    }

  /* Conjure up a trigger rule suitable for this flow. */
  rule_index = ssh_engine_find_dangle_rule(engine, c_flow->rule_index);
  if (rule_index == SSH_IPSEC_INVALID_INDEX)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to find rule to attach flow %d to!",
                 (int) flow_index));
      return FALSE;
    }

  /* Leave dangling flows associated with a trigger rule or
     a "normal" policy rule (such as PASS, etc.). */
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  SSH_ASSERT(rule->type != SSH_ENGINE_RULE_APPLY);

  if (rule_index != c_flow->rule_index
      && ((rule->flags & SSH_PM_ENGINE_RULE_FLOW_REF)
          || (orig_rule->flags & SSH_PM_ENGINE_RULE_FLOW_REF)))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("This flow cannot change rule. Destroy it."));
      return FALSE;
    }

  /* We can no longer return with failure after this point. */
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
  d_flow->data_flags |= SSH_ENGINE_FLOW_D_DANGLING;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("dangling flow %d: moving from rule %d (type %d) "
             "to rule %d (type %d)",
             (int) flow_index, (int) orig_rule_index,
             orig_rule->type,
             (int) rule_index, rule->type));

  SSH_ENGINE_INCREMENT_RULE_REFCNT(orig_rule);
  ssh_engine_flow_reset_trd(engine, flow_index, d_flow, FALSE);
  ssh_engine_flow_reset_trd(engine, flow_index, d_flow, TRUE);
  ssh_engine_flow_reset_rule(engine, flow_index);
  ssh_engine_flow_set_rule(engine, flow_index, rule_index);
  ssh_engine_decrement_rule_refcnt(engine, orig_rule);

  /* Commit d_flow back to fastpath */
  FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);

  /* We leave the flow in the flow table, so packets will still hit
     it. The SSH_ENGINE_FLOW_D_DANGLING flag signals that this
     packets should be considered as triggers. */

  /* Put the flow on the dangling list. We overload the transform index
     fields and use these to save space in the FlowRec. */
  if (engine->flows_dangling_list != SSH_IPSEC_INVALID_INDEX)
    {
      c_flow2 = SSH_ENGINE_GET_FLOW(engine, engine->flows_dangling_list);
      c_flow2->control_prev = flow_index;
    }

  c_flow->control_next = engine->flows_dangling_list;
  c_flow->control_prev = SSH_IPSEC_INVALID_INDEX;
  engine->flows_dangling_list = flow_index;

  return TRUE;
}

/* This function undangles a dangling flow. The flow MUST be dangling.
   If the undangle operation failed due to problems with inconsistent
   state in the engine, the function returns SSH_ENGINE_FLOW_STATUS_ERROR,
   and the flow should be destroyed. If the engine policy does not
   currently allow for the flow to be undangled, then it will return
   SSH_ENGINE_FLOW_STATUS_DANGLING, and the flow is still dangling.
   If the policy and state allow for the flow to be undangled,
   then the flow will be attached to a suitable rule (as specified
   by policy) and acceptable forward and reverse transforms, flow
   id's will be recomputed and the flow will be placed in the
   flow id hash tables. In this case SSH_ENGINE_FLOW_STATUS_WELL_DEFINED
   will be returned.
   'engine->flow_control_table_lock' must be held during this call. */
SshEngineFlowStatus
ssh_engine_flow_undangle(SshEngine engine, SshUInt32 flow_index)
{
  SshEngineFlowControl c_flow, flow_next, flow_prev;
  SshEngineFlowData d_flow = NULL;
  Boolean dangle_flow, free_flow, reverse_trigger;
  SshEnginePolicyRule forward_rule, orig_rule, reverse_rule, transform_rule;
  SshUInt32 fwd_rule_index, rev_rule_index, fwd_flow_idx, rev_flow_idx;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (engine->policy_lookups_disabled)
    return SSH_ENGINE_FLOW_STATUS_DANGLING;

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

  if (c_flow->control_flags
      & (SSH_ENGINE_FLOW_C_UNDEFINED|SSH_ENGINE_FLOW_C_TRIGGER))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("undefined/trigger flow %d can never be undangled!",
                 (int) flow_index));
      return SSH_ENGINE_FLOW_STATUS_DANGLING;
    }

  orig_rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);

  /* Re-evaluate flow against policy. Try to find an APPLY rule,
     as currently we are attached to a trigger rule. */
  dangle_flow = FALSE;
  reverse_trigger = FALSE;
  free_flow = FALSE;
  transform_rule = NULL;

  /* We are not allowed to change rule and we are attached to a
     trigger, assume that trigger rule is good for dangling flows. */
  if ((orig_rule->flags & SSH_PM_ENGINE_RULE_FLOW_REF) != 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Flow is not allowed to change rule, keeping it "
                 "attached to same rule."));
      forward_rule = orig_rule;
      if ((orig_rule->flags & SSH_ENGINE_RULE_UNDEFINED) == 0)
        transform_rule = forward_rule;
    }
  else
    {
      forward_rule = ssh_engine_find_flow_rule(engine, flow_index);
      transform_rule = forward_rule;
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Flow current forward rule is %d",
                 (int)
                 (forward_rule
                  ? forward_rule->rule_index
                  : SSH_IPSEC_INVALID_INDEX)));
    }

  if (forward_rule == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to find forward rule for flow %d",
                 (int) flow_index));
      return SSH_ENGINE_FLOW_STATUS_ERROR;
    }

  if (((forward_rule->flags|orig_rule->flags)
       & SSH_PM_ENGINE_RULE_FLOW_REF) != 0
      && (forward_rule != orig_rule))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("This flow cannot change rule. Destroy it."));
      return SSH_ENGINE_FLOW_STATUS_ERROR;
    }

  /* Try to find a rule... */
  if (forward_rule->type == SSH_ENGINE_RULE_TRIGGER)
    {
      /* Flow is supposed to always be attached to this trigger rule.
         This means that it is most likely an APPGW trigger rule.
         Reverse transform index can be found, after trigger rule
         "from_tunnel" param has been found. */
      if ((forward_rule->flags & SSH_PM_ENGINE_RULE_FLOW_REF)
          && (forward_rule->flags & SSH_ENGINE_RULE_UNDEFINED))
        {
#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
          SshEngineFlowControl tmp_control;

          SSH_ASSERT(forward_rule == orig_rule);

          /* If the "pair flow" has disappeared from under us, then
             this flow must be freed. */
          tmp_control = NULL;
          if (c_flow->pair_flow_idx != SSH_IPSEC_INVALID_INDEX)
            tmp_control = SSH_ENGINE_GET_FLOW(engine, c_flow->pair_flow_idx);

          if (tmp_control == NULL
              || tmp_control->pair_flow_idx != flow_index
              || (tmp_control->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("appgw pair flow disappeared, destroying this flow "
                         "too"));
              return SSH_ENGINE_FLOW_STATUS_ERROR;
            }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
        }
      else if ((forward_rule->flags
                & (SSH_PM_ENGINE_RULE_SLAVE|SSH_PM_ENGINE_RULE_APPGW))
               == 0)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("flow forward_rule is a non-appgw trigger rule. "
                     "dangling flow."));
          dangle_flow = TRUE;
        }
      /* If this was non-tt appgw rule, then everything is ok already. */
    }
  else if (forward_rule->type != SSH_ENGINE_RULE_PASS
           && forward_rule->type != SSH_ENGINE_RULE_APPLY)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Re-routed flow does not pass policy."));
      return SSH_ENGINE_FLOW_STATUS_ERROR;
    }

  /* Remove from list */
  flow_next = flow_prev = NULL;
  fwd_flow_idx = c_flow->control_next;
  rev_flow_idx = c_flow->control_prev;

  if (fwd_flow_idx != SSH_IPSEC_INVALID_INDEX)
    flow_next = SSH_ENGINE_GET_FLOW(engine, fwd_flow_idx);

  if (rev_flow_idx != SSH_IPSEC_INVALID_INDEX)
    flow_prev = SSH_ENGINE_GET_FLOW(engine, rev_flow_idx);

  if (flow_next != NULL)
    flow_next->control_prev = rev_flow_idx;

  if (flow_prev != NULL)
    flow_prev->control_next = fwd_flow_idx;

  if (flow_index == engine->flows_dangling_list)
    engine->flows_dangling_list = fwd_flow_idx;

  c_flow->control_next = SSH_IPSEC_INVALID_INDEX;
  c_flow->control_prev = SSH_IPSEC_INVALID_INDEX;

  /* Break possible flow->rule association. Note that
     forward_transform_index MUST still be valid. */
  SSH_ENGINE_INCREMENT_RULE_REFCNT(orig_rule);
  ssh_engine_flow_reset_rule(engine, flow_index);
  fwd_rule_index = SSH_ENGINE_GET_RULE_INDEX(engine, forward_rule);
  ssh_engine_flow_set_rule(engine, flow_index, fwd_rule_index);
  ssh_engine_decrement_rule_refcnt(engine, orig_rule);

  rev_rule_index = SSH_IPSEC_INVALID_INDEX;
  reverse_rule = NULL;

  /* Lookup reverse rule based on 'flow' and 'transform_rule'. */
  if (dangle_flow == FALSE && free_flow == FALSE)
    {
      if (transform_rule == NULL)
        {
          /* Mark this flow to be freed. */
          free_flow = TRUE;
          goto error;
        }

      if (ssh_engine_flow_find_reverse_rule(engine, flow_index, transform_rule,
                                            &rev_rule_index) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("find_reverse_rule failed()!"));
          dangle_flow = TRUE;
          reverse_trigger = TRUE;
        }
    }

  if (rev_rule_index != SSH_IPSEC_INVALID_INDEX)
    {
      reverse_rule = SSH_ENGINE_GET_RULE(engine, rev_rule_index);
      SSH_ASSERT(reverse_rule->type == SSH_ENGINE_RULE_APPLY);
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("undangling flow %d with reverse rule %d (type %d)",
                 (int) flow_index, (int) rev_rule_index,
                 reverse_rule->type));
    }
  else
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("undangling flow %d with no reverse transform",
               (int) flow_index));


  /* Fetch us a copy of the flow we are working with. */
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);

  if (dangle_flow == FALSE && free_flow == FALSE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Undangling flow %d: %@:%d -> %@:%d",
                                   (int) flow_index,
                                   ssh_ipaddr_render, &d_flow->src_ip,
                                   d_flow->src_port,
                                   ssh_ipaddr_render, &d_flow->dst_ip,
                                   d_flow->dst_port));

      if ((d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) == 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("flow %d already undangled!", (int) flow_index));
          FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
          return SSH_ENGINE_FLOW_STATUS_WELL_DEFINED;
        }


      SSH_ASSERT((d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) != 0);
      SSH_ASSERT((d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0);

      /* Setup new transforms */
      if (transform_rule != NULL
          && (transform_rule->transform_index != SSH_IPSEC_INVALID_INDEX)
          && (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_R))
        ssh_engine_flow_set_trd(engine, flow_index, d_flow, TRUE,
                                transform_rule->transform_index);

      if (reverse_rule != NULL
          && reverse_rule->transform_index != SSH_IPSEC_INVALID_INDEX
          && (c_flow->control_flags & SSH_ENGINE_FLOW_C_REROUTE_I))
        ssh_engine_flow_set_trd(engine, flow_index, d_flow, FALSE,
                                reverse_rule->transform_index);

      /* Now that the re-routed flow has been determined to be
         acceptable. Re-compute the flow id. Short-circuit
         evaluation is used to skip recomputation of flow-id's
         if it is not desirable. */
      if ((ssh_engine_flow_compute_flow_id_from_flow(engine, flow_index,
                                                     d_flow,
                                                     FALSE,
                                                     d_flow->reverse_flow_id)
           == TRUE)
          &&
          (ssh_engine_flow_compute_flow_id_from_flow(engine, flow_index,
                                                     d_flow,
                                                     TRUE,
                                                     d_flow->forward_flow_id)
           == TRUE))
        {
          /* Patch up flow flags */
          d_flow->data_flags &= ~(SSH_ENGINE_FLOW_D_DANGLING);

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Undangling succesful: "
                     "forward trd=0x%08x reverse trd=0x%08x",
                     (unsigned int) d_flow->forward_transform_index,
                     (unsigned int) d_flow->reverse_transform_index));

          FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);

          return SSH_ENGINE_FLOW_STATUS_WELL_DEFINED;
        }

      ssh_engine_flow_reset_trd(engine, flow_index, d_flow, TRUE);
      ssh_engine_flow_reset_trd(engine, flow_index, d_flow, FALSE);
      free_flow = TRUE;
    }

  FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);

 error:
  /* Insert us back into the same spot in the queue we were, this
     is required for undangle_all() and free_flow() */
  if (flow_next != NULL)
    {
      flow_next->control_prev = flow_index;
      c_flow->control_next = fwd_flow_idx;
    }

  if (flow_prev != NULL)
    {
      flow_prev->control_next = flow_index;
      c_flow->control_prev = rev_flow_idx;
    }
  else
    {
      engine->flows_dangling_list = flow_index;
    }

  if (dangle_flow)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Flow %d still dangling!",
                                   (int) flow_index));
      if (reverse_trigger)
        return SSH_ENGINE_FLOW_STATUS_REVERSE_TRIGGER;

      return SSH_ENGINE_FLOW_STATUS_DANGLING;
    }

  SSH_DEBUG(SSH_D_FAIL, ("Error in undangling flow %d!", (int) flow_index));
  SSH_ASSERT(free_flow == TRUE);
  return SSH_ENGINE_FLOW_STATUS_ERROR;
}


/* The ssh_engine_flow_undangle_all() function attempts to undangle
   all flows in the engine, that are dangling. This function
   grabs 'engine->flow_control_table_lock' during it's execution, so it
   MUST NOT be held prior to call. */
void
ssh_engine_flow_undangle_all(SshEngine engine)
{
  SshUInt32 next_flow_idx, flow_idx;
  SshEngineFlowStatus status;
  SshEngineFlowControl c_flow;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (flow_idx = engine->flows_dangling_list;
       flow_idx != SSH_IPSEC_INVALID_INDEX;
       flow_idx = next_flow_idx)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_idx);
      next_flow_idx = c_flow->control_next;

      status = ssh_engine_flow_undangle(engine, flow_idx);
      switch (status)
        {
        case SSH_ENGINE_FLOW_STATUS_ERROR:
          SSH_DEBUG(SSH_D_FAIL,
                    ("Flow undangling failed! Freeing flow %d!",
                     (int) flow_idx));
          ssh_engine_free_flow(engine, flow_idx);
          break;

        case SSH_ENGINE_FLOW_STATUS_WELL_DEFINED:
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Flow %d was undangled.", (int) flow_idx));

          break;

        case SSH_ENGINE_FLOW_STATUS_REVERSE_TRIGGER:
        case SSH_ENGINE_FLOW_STATUS_DANGLING:
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Flow %d still dangling.", (int) flow_idx));
          break;

        default:
          SSH_NOTREACHED;
        }
    }

  engine->undangle_all_pending = 0;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}


/* Frees the given flow and any associated flow id hash and next hop nodes,
   as well as any associated flow table nodes (in the case of IPSEC SAs).
   This must be called with engine->flow_control_table_lock held. */

void ssh_engine_free_flow(SshEngine engine, SshUInt32 flow_index)
{
  SshEngineFlowControl c_flow, flow_next, flow_prev;
  SshEngineFlowData d_flow;
  SshUInt16 c_flags;
  SshUInt32 wrapped_index, d_flags;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt32 forward_nh_index, reverse_nh_index;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  SSH_DEBUG(SSH_D_MIDOK, ("freeing flow %d", (int)flow_index));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  flow_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(flow_index);

  /* Get a pointer to the flow descriptor. */
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

  /* Sanity check: it should not already be free. */
  SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID);

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  if (c_flow->pair_flow_idx != flow_index
      && c_flow->pair_flow_idx != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineFlowControl p_flow;

      p_flow = SSH_ENGINE_GET_FLOW(engine, c_flow->pair_flow_idx);
      p_flow->pair_flow_idx = SSH_IPSEC_INVALID_INDEX;
      c_flow->pair_flow_idx = SSH_IPSEC_INVALID_INDEX;
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

  /* Audit the session being closed. */
  ssh_engine_audit_flow_event(engine, flow_index,
                              SSH_AUDIT_ENGINE_SESSION_END);

  d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
  /* Notify the rate limitation that a flow from '&flow->src_ip' was freed. */
  ssh_engine_flow_rate_unlimit(engine, &d_flow->src_ip);
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

  /* Grab flags while flow is destroyed */
  d_flags = (SshUInt32)d_flow->data_flags;
  c_flags = (SshUInt16)c_flow->control_flags;

  /* Remove the flow from the policy rule that created it.  Note that
     we are still holding a reference on the rule (that was created
     when the flow was created), and rule->flows is protected by
     engine->flow_control_table_lock. */
  if (d_flags & SSH_ENGINE_FLOW_D_DANGLING)
    {
      /* Remove from list. */
      d_flow->data_flags &= ~(SSH_ENGINE_FLOW_D_DANGLING);
      flow_next = flow_prev = NULL;

      if (c_flow->control_next != SSH_IPSEC_INVALID_INDEX)
        flow_next = SSH_ENGINE_GET_FLOW(engine, c_flow->control_next);

      if (c_flow->control_prev != SSH_IPSEC_INVALID_INDEX)
        flow_prev = SSH_ENGINE_GET_FLOW(engine, c_flow->control_prev);

      if (flow_next != NULL)
        flow_next->control_prev = c_flow->control_prev;

      if (flow_prev != NULL)
        flow_prev->control_next = c_flow->control_next;

      if (flow_index == engine->flows_dangling_list)
        engine->flows_dangling_list = c_flow->control_next;

      c_flow->control_next = SSH_IPSEC_INVALID_INDEX;
      c_flow->control_prev = SSH_IPSEC_INVALID_INDEX;

      ssh_engine_flow_reset_rule(engine, flow_index);
    }
  else
    {
      ssh_engine_flow_reset_trd(engine, flow_index, d_flow, FALSE);
      ssh_engine_flow_reset_trd(engine, flow_index, d_flow, TRUE);
      ssh_engine_flow_reset_rule(engine, flow_index);
    }

#ifdef SSHDIST_IPSEC_NAT
  /* Free any ports thay may have been dynamically allocated for NAT. */
  ssh_engine_nat_unregister_port(engine,
                                 &d_flow->nat_src_ip, d_flow->nat_src_port);
  ssh_engine_nat_unregister_port(engine,
                                 &d_flow->nat_dst_ip, d_flow->nat_dst_port);
#endif /* SSHDIST_IPSEC_NAT */

  /* Save the links to other objects. */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  forward_nh_index = d_flow->forward_nh_index;
  reverse_nh_index = d_flow->reverse_nh_index;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Invalidate the flow. */
  c_flow->control_flags = 0;

  d_flow->generation++;

#ifdef DEBUG_LIGHT
  c_flow->rule_next = 0xdeadbeef;
  c_flow->rule_prev = 0xdeadbeef;
  c_flow->rule_index = 0xdeadbeef;
#endif /* DEBUG_LIGHT */

  /* Put the flow descriptor on the freelist. */
  c_flow->control_next = SSH_IPSEC_INVALID_INDEX;
  if (engine->flow_table_freelist_last != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineFlowControl prev_flow;
      /* The list is active at this stage. */
      SSH_ASSERT(engine->flow_table_freelist != SSH_IPSEC_INVALID_INDEX &&
                 engine->num_free_flows != 0);
      prev_flow = SSH_ENGINE_GET_FLOW(engine,
                                      engine->flow_table_freelist_last);
      prev_flow->control_next = flow_index;
      engine->flow_table_freelist_last = flow_index;
    }
  else
    {
      /* List was empty */
      SSH_ASSERT(engine->flow_table_freelist == SSH_IPSEC_INVALID_INDEX &&
                 engine->num_free_flows == 0);
      engine->flow_table_freelist = flow_index;
      engine->flow_table_freelist_last = flow_index;
    }

  engine->num_free_flows++;
  SSH_ASSERT(engine->num_free_flows <= engine->flow_table_size);

  /* Free protocol-specific data. */
  switch (d_flow->type)
    {
    case SSH_ENGINE_FLOW_TYPE_TCP:
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
      ssh_engine_tcp_uninit(engine, d_flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
      break;
    case SSH_ENGINE_FLOW_TYPE_UDP:
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
      ssh_engine_udp_uninit(engine, d_flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
      break;
    case SSH_ENGINE_FLOW_TYPE_ICMP:
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
      ssh_engine_icmp_uninit(engine, d_flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
      break;
    case SSH_ENGINE_FLOW_TYPE_RAW:
      break;
    default:
      ssh_fatal("ssh_engine_free_flow: unknown type %d", (int)d_flow->type);
    }

  wrapped_index = SSH_ENGINE_FLOW_WRAP_INDEX(d_flow->generation, flow_index);

  /* Uninitialize the flow in the fastpath. Now it is invalidated. */
  FASTPATH_UNINIT_FLOW(engine->fastpath, flow_index, d_flow);

#ifdef SSH_IPSEC_STATISTICS
  engine->stats.active_flows--;
#endif /* SSH_IPSEC_STATISTICS */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Free the associated next hop nodes. */
  if (forward_nh_index != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine, forward_nh_index);
  if (reverse_nh_index != SSH_IPSEC_INVALID_INDEX)
    ssh_engine_decrement_next_hop_refcnt(engine, reverse_nh_index);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL
  /* Finally send a notification that a flow has been destroyed,
     do this last, so that the state in the engine is consistent
     with the notification. Note that since the flow table lock
     is held, we can safely reference data in the flow structure. */
  if (c_flags & SSH_ENGINE_FLOW_C_NOTIFY_DELETE)
    {
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
      SshEngineFlowNotification c;
      c = ssh_malloc(sizeof(*c));
      if (c != NULL)
        {
          c->engine = engine;
          c->flow_index = wrapped_index;
          /* Record the timeout before actually wrapping to the
             policymanager thread */
          ssh_engine_record_upcall(engine);
          /* Schedule a timeout that will call
             ssh_engine_flow_notification_now.  Note that w
             intentionally use ssh_register_timeout, not
             ssh_kernel_timeout_register, so that the timeout will
             obey the concurrency control semantics that the
             single-threaded policy manager expects. */
          ssh_register_timeout(&c->tmout_struct, 0L, 0L,
                               ssh_engine_flow_notification_now,
                               c);
        }
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("sending flow free notification flow_index=%d",
                 (int) flow_index));
      ssh_pmp_flow_free_notification(engine->pm, wrapped_index);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
    }
#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */
}

/* Switch flow status between "pass/drop packets". */
void
ssh_engine_pme_flow_set_status(SshEngine engine,
                               SshUInt32 flow_index,
                               SshPmeFlowStatus flow_status,
                               SshPmeStatusCB callback, void *context)
{
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt32 f_index, f_gen;

  SSH_DEBUG(SSH_D_MIDOK,
            ("setting flow %u status to: %u",
             (unsigned int) flow_index, flow_status));

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  f_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(flow_index);
  f_gen = SSH_ENGINE_FLOW_UNWRAP_GENERATION(flow_index);

  c_flow = SSH_ENGINE_GET_FLOW(engine, f_index);
  d_flow = FASTPATH_GET_FLOW(engine->fastpath, f_index);

  if (d_flow->generation != f_gen)
    {
      FASTPATH_RELEASE_FLOW(engine->fastpath, f_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      goto fail;
    }

  d_flow->data_flags &=
    ~(SSH_ENGINE_FLOW_D_DROP_PKTS|SSH_ENGINE_FLOW_D_REJECT_INBOUND);

  switch(flow_status)
    {
    case SSH_PME_FLOW_PASS:
      break;

    case SSH_PME_FLOW_DROP:
      d_flow->data_flags |= SSH_ENGINE_FLOW_D_DROP_PKTS;
      break;

    case SSH_PME_FLOW_REJECT_INBOUND:
      d_flow->data_flags |= SSH_ENGINE_FLOW_D_REJECT_INBOUND;
      break;

    case SSH_PME_FLOW_DROP_EXPIRE:
      d_flow->data_flags |= SSH_ENGINE_FLOW_D_DROP_PKTS;
      c_flow->hard_expire_time =
        engine->run_time + SSH_ENGINE_TRIGGER_FLOW_EXPIRE_TIMEOUT;
      break;

    default:
      SSH_NOTREACHED;
      break;
    }

  FASTPATH_COMMIT_FLOW(engine->fastpath, f_index, d_flow);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (callback)
    (*callback)(engine->pm, TRUE, context);
  return;

 fail:
  if (callback)
    (*callback)(engine->pm, FALSE, context);
  return;
}
