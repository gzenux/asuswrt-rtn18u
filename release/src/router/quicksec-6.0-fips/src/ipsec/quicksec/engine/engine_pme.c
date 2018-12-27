/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains glue code to implement some of the functions defined
   in engine_pm_api.h (the functions that policy manager calls in the engine
   to control the engine).

   Note that these functions must adhere to the locking constraints specified
   in engine_pm_api.h.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */

#define SSH_DEBUG_MODULE "SshEnginePme"

/* Sets debug level in the engine.  Debugging messages will be passed
   to the policy manager.  The format of `level_string' is that
   expected by ssh_debug_set_level_string.  This may set engine debug
   level globally for all engines in the system. */

#ifdef USERMODE_ENGINE
#include "usermodeinterceptor.h"
#include "usermodeinterceptor_internal.h"
#include "usermodeforwarder.h"
#endif /* USERMODE_ENGINE */

void ssh_engine_pme_set_debug_level(SshEngine engine,
                                    const char *level_string)
{
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* In the unified address space, the policy manager debug setting
     sets the debug level also for the engine code. */
#ifdef USERMODE_ENGINE
  /* However, if we have the user-mode interceptor running, we want
     set the debug level for the in-kernel user-mode forwarder. */
  (void) ssh_usermode_interceptor_send_encode(
                                        ssh_usermode_interceptor,
                                        SSH_ENGINE_IPM_FORWARDER_SET_DEBUG,

                                        SSH_FORMAT_UINT32_STR, level_string,
                                        /* Length including the
                                           trailing null-character. */
                                        strlen(level_string) + 1,

                                        SSH_FORMAT_END);
#endif /* USERMODE_ENGINE */
#else /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  ssh_debug_set_level_string(level_string);
#endif /* not SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
}

/* Sends the packet to the engine for reprocessing. The engine processes
   the packet as if it had just arrived from the network (or local TCP/IP
   stack).  This function may operate unreliably (i.e., the engine may not
   actually get the call).  This will copy `data' if this needs it after
   returning. */

void ssh_engine_pme_process_packet(SshEngine engine,
                                   SshUInt32 tunnel_id,
                                   SshInterceptorProtocol protocol,
                                   SshUInt32 ifnum_in,
                                   SshVriId routing_instance_id,
                                   SshUInt32 flags,
                                   SshUInt32 prev_transform_index,
                                   const unsigned char *data,
                                   size_t len)
{
  SshInterceptorPacket pp;
  SshUInt32 pp_flags, pc_flags;
  SshEngineTransformControl c_trd;
  size_t extension_len =
    SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * sizeof(SshUInt32);
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  SSH_INTERCEPTOR_STACK_MARK();

  if (ifnum_in != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) ifnum_in;

  if (flags & SSH_PME_PACKET_DONT_REPROCESS)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Not sending the packet to the engine"));
      return;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("received packet from policy manager, "
                           "tunnel_id=%d, protocol=%d, ifnum_in=%d, "
                           "routing instance %d, flags=0x%08lx, "
                           "prev_transform_idx=0x%08lx, len=%d",
                           (int)tunnel_id, (int)protocol, (int)ifnum_in,
                           routing_instance_id, (unsigned long)flags,
                           (unsigned long)prev_transform_index,
                           (int) (len - extension_len)));

  /* Check that the `prev_transform_index' argument is still valid. */
  if (prev_transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      c_trd = SSH_ENGINE_GET_TRD(engine, prev_transform_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      if (c_trd == NULL)
        /* The transform has been reused. */
        return;
    }

  /* Allocate a packet object. */
  pp_flags = (flags & SSH_PME_PACKET_LOCAL) ?
    SSH_PACKET_FROMPROTOCOL : SSH_PACKET_FROMADAPTER;
  if (flags & SSH_PME_PACKET_HWCKSUM)
    pp_flags |= SSH_PACKET_HWCKSUM;
  if (flags & SSH_PME_PACKET_IP4HDRCKSUMOK)
    pp_flags |= SSH_PACKET_IP4HDRCKSUMOK;
  if (flags & SSH_PME_PACKET_IP4HHWCKSUM)
    pp_flags |= SSH_PACKET_IP4HHWCKSUM;
  if (flags & SSH_PME_PACKET_FRAG_ALLOWED)
    pp_flags |= SSH_PACKET_FRAGMENTATION_ALLOWED;

  SSH_ASSERT(len > extension_len);

  if (routing_instance_id < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("unknown routing instance."));
      return;
    }

  pp = ssh_interceptor_packet_alloc(engine->interceptor, pp_flags,
                                    protocol, eng_ifnum,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    len - extension_len);
  if (!pp)
    {
      SSH_DEBUG(SSH_D_FAIL, ("could not allocate packet, len=%d",
                             (int)len));
      return;
    }
  if (flags & SSH_PME_PACKET_NOTRIGGER)
    pp->flags |= SSH_ENGINE_P_NOTRIGGER;
  if (flags & SSH_PME_PACKET_WASFRAG)
    pp->flags |= SSH_ENGINE_P_WASFRAG;
  if (flags & SSH_PME_PACKET_MEDIABCAST)
    pp->flags |= SSH_PACKET_MEDIABCAST;

  pp->routing_instance_id = routing_instance_id;

  /* Copy data into the packet object. */
  if (!ssh_interceptor_packet_copyin(pp, 0, data, len - extension_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("could not copy data into a packet"));
      /* The packet `pp' is already freed. */
      return;
    }

  /* Copy extension selectors into the packet object. */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memcpy(pp->extension, data + (len - extension_len), extension_len);
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Set initial pc flags. */
  pc_flags = 0;
  if (flags & SSH_PME_PACKET_RESTARTED_OUT)
    pc_flags |= SSH_ENGINE_PC_RESTARTED_OUT;

  /* Send the packet to the fastpath. This will handle the packet as if
     it had just been received from the network (except as controlled
     by the SSH_ENGINE_P_NOTRIGGER flag). */
  if (!ssh_engine_packet_start(engine, pp, tunnel_id, prev_transform_index,
                               pc_flags))
    {
      SSH_DEBUG(SSH_D_FAIL, ("could not send the packet to the fastpath"));
      /* The packet `pp' is already freed. */
      return;
    }
}



#ifdef SSH_IPSEC_STATISTICS

/* Context data for asynchronous get fastpath statistics operation. */
typedef struct SshEngineFastpathStatsCtxRec
{
  SshEngine engine;
  SshPmeGlobalStatsCB callback;
  void *context;
} *SshEngineFastpathStatsCtx;

void fastpath_stats_callback(SshEngine engine,
                             const SshFastpathGlobalStats fastpath_stats,
                             void *context)
{
  SshEngineFastpathStatsCtx ctx = (SshEngineFastpathStatsCtx) context;

  /* Note: we ignore locking when retrieving statistics. */
  (*ctx->callback)(ctx->engine->pm, &ctx->engine->stats, fastpath_stats,
                   ctx->context);
  ssh_free(ctx);
}


/* Retrieves global statistics information from the engine. `callback' will
   be called with `context' and `stats' either during this call or later;
   if the flow index is invalid, then `stats' will be NULL.  The callback
   should copy the statistics if they are needed after the call. */

void ssh_engine_pme_get_global_stats(SshEngine engine,
                                     SshPmeGlobalStatsCB callback,
                                     void *context)
{
  SshEngineFastpathStatsCtx ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(engine->pm, NULL, NULL, context);
      return;
    }
  ctx->engine = engine;
  ctx->callback = callback;
  ctx->context = context;

  fastpath_get_global_stats(engine->fastpath,
                            fastpath_stats_callback, ctx);
  return;
}

/* Returns the index of the next valid flow following the flow
   `flow_index'.  If the `flow_index' has the value
   SSH_IPSEC_INVALID_INDEX, the function returns the index of the
   first valid flow in the engine.  The function returns the flow
   index by calling the callback function `callback' during this call
   or later. */

void ssh_engine_pme_get_next_flow_index(SshEngine engine,
                                        SshUInt32 flow_index,
                                        SshPmeIndexCB callback,
                                        void *context)
{
  SshEngineFlowControl c_flow;
  SshUInt32 i;

  if (flow_index == SSH_IPSEC_INVALID_INDEX)
    i = 0;
  else
    i = flow_index + 1;

  flow_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(flow_index);

  /* Lookup the next valid flow. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (; i < engine->flow_table_size; i++)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, i);
      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID)
        /* Found it. */
        break;
    }

  if (i < engine->flow_table_size)
    /* Found the next flow. */
    flow_index = i;
  else
    /* No more flows available. */
    flow_index = SSH_IPSEC_INVALID_INDEX;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return the result. */
  (*callback)(engine->pm, flow_index, context);
}

/* Retrieves public information about the given flow from the engine.
   `callback' will be called with `context' and `info' either during
   this call or later; if the flow index is invalid, then `info' will
   be NULL.  The callback should copy the info if they are needed
   after the call. */

void ssh_engine_pme_get_flow_info(SshEngine engine, SshUInt32 orig_flow_index,
                                  SshPmeFlowInfoCB callback, void *context)
{
  SshEngineFlowData d_flow;
  SshEngineFlowControl c_flow;
  SshEngineFlowInfoStruct info;
  SshUInt32 flow_index;

  flow_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(orig_flow_index);

  if (flow_index >= engine->flow_table_size
      || orig_flow_index == SSH_IPSEC_INVALID_INDEX)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  /* Copy the flow information into local storage to ensure that the
     flow does not disappear from under us while we are delivering the
     info to the caller. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID))
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, context);
      return;
    }

  d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);

  info.src = d_flow->src_ip;
  info.dst = d_flow->dst_ip;
  info.src_port = d_flow->src_port;
  info.dst_port = d_flow->dst_port;
  info.ipproto = d_flow->ipproto;
#ifdef SSHDIST_IPSEC_NAT
  info.nat_src = d_flow->nat_src_ip;
  info.nat_dst = d_flow->nat_dst_ip;
  info.nat_src_port = d_flow->nat_src_port;
  info.nat_dst_port = d_flow->nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */
  info.forward_transform_index = d_flow->forward_transform_index;
  info.reverse_transform_index = d_flow->reverse_transform_index;
  info.rule_index = c_flow->rule_index;
  info.lru_level = d_flow->flow_lru_level;
  info.idle_time = (SshUInt32)(engine->run_time - d_flow->last_packet_time);
  info.protocol_state = SSH_ENGINE_FLOW_PROTOCOL_NONE;
  info.is_dangling = ((d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING)
                      ? TRUE : FALSE);
  info.is_trigger = ((c_flow->control_flags & SSH_ENGINE_FLOW_C_TRIGGER)
                     ? TRUE : FALSE);
  info.routing_instance_id = d_flow->routing_instance_id;

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  if (d_flow->type == SSH_ENGINE_FLOW_TYPE_TCP)
    {
      switch (d_flow->u.tcp.state)
        {
        case SSH_ENGINE_TCP_INITIAL:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_INITIAL;
          break;
        case SSH_ENGINE_TCP_SYN:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_SYN_ACK;
          break;
        case SSH_ENGINE_TCP_SYN_ACK:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_SYN_ACK_ACK;
          break;
        case SSH_ENGINE_TCP_SYN_ACK_ACK:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_SYN_ACK_ACK;
          break;
        case SSH_ENGINE_TCP_ESTABLISHED:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_ESTABLISHED;
          break;
        case SSH_ENGINE_TCP_FIN_FWD:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_FIN_FWD;
          break;
        case SSH_ENGINE_TCP_FIN_REV:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_FIN_REV;
          break;
        case SSH_ENGINE_TCP_FIN_FIN:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_FIN_FIN;
          break;
        case SSH_ENGINE_TCP_CLOSE_WAIT:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_CLOSE_WAIT;
          break;
        case SSH_ENGINE_TCP_CLOSED:
          info.protocol_state = SSH_ENGINE_FLOW_TCP_CLOSED;
          break;
        }
    }
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

  FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  (*callback)(engine->pm, &info, context);
}

/* Retrieves statistics information for the given flow from the
   engine.  `callback' will be called with `context' and `stats'
   either during this call or later; if the flow index is invalid,
   then `stats' will be NULL.  The callback should copy the statistics
   if they are needed after the call. */

void ssh_engine_pme_get_flow_stats(SshEngine engine, SshUInt32 orig_flow_index,
                                   SshPmeFlowStatsCB callback, void *context)
{
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshEngineFlowStatsStruct stats;
  SshUInt32 flow_index;

  flow_index = SSH_ENGINE_FLOW_UNWRAP_INDEX(orig_flow_index);

  if (flow_index >= engine->flow_table_size
      || orig_flow_index == SSH_IPSEC_INVALID_INDEX)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  /* Copy the flow statistics to local storage to ensure that the flow
     does not disappear from under us while we are delivering the stats
     to the caller. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
  if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID))
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, context);
      return;
    }

  d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);
  stats = d_flow->stats;
  FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  (*callback)(engine->pm, &stats, context);
}

/* Returns the index of the next valid transform following the
   transform `transform_index'.  If the `transform_index' has the
   value SSH_IPSEC_INVALID_INDEX, the function returns the index of
   the first valid transform in the engine.  The function returns the
   transform index by calling the callback function `callback' during
   this call or later. */

void ssh_engine_pme_get_next_transform_index(SshEngine engine,
                                             SshUInt32 transform_index,
                                             SshPmeIndexCB callback,
                                             void *context)
{
  SshUInt32 i;
  SshEngineTransformData d_trd = NULL;
  SshEngineTransformControl c_trd = NULL;

  if (transform_index == SSH_IPSEC_INVALID_INDEX)
    i = 0;
  else
    i = SSH_ENGINE_UNWRAP_TRD_INDEX(transform_index) + 1;

  /* Lookup the next valid transform. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (; i < engine->transform_table_size; i++)
    {
      c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, i);
      SSH_ASSERT(c_trd != NULL);

      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, i);
      if (d_trd->transform != 0)
        {
          FASTPATH_RELEASE_TRD(engine->fastpath, i);
          /* Found it. */
          break;
        }
      FASTPATH_RELEASE_TRD(engine->fastpath, i);
    }

  if (i < engine->transform_table_size)
    /* Found the next transform.  Wrap index and generation into
       `transform_index'. */
    transform_index = SSH_ENGINE_WRAP_TRD_INDEX(i, c_trd->generation);
  else
    /* No more transforms available. */
    transform_index = SSH_IPSEC_INVALID_INDEX;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return the result. */
  (*callback)(engine->pm, transform_index, context);
}

/* Retrieves statistics information for the given transform from the engine.
   `callback' will be called with `context' and `stats' either during this
   call or later; if the transform index is invalid, then `stats' will
   be NULL.  The callback should copy the statistics if they are needed
   after the call. */

void ssh_engine_pme_get_transform_stats(SshEngine engine,
                                        SshUInt32 transform_index,
                                        SshPmeTransformStatsCB callback,
                                        void *context)
{
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshEngineTransformStatsStruct stats;

  /* Copy the flow statistics to local storage to ensure that the flow
     does not disappear from under us while we are delivering the stats
     to the caller. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);

  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);
  if (c_trd == NULL || d_trd->transform == 0)
    {
      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, context);
      return;
    }

  stats.control = c_trd->stats;
  stats.data = d_trd->stats;

  FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  (*callback)(engine->pm, &stats, context);
}

/* Returns the index of the next valid rule following the rule
   `rule_index'.  If the `rule_index' has the value
   SSH_IPSEC_INVALID_INDEX, the function returns the index of the
   first valid rule in the engine.  The function returns the rule
   index by calling the callback function `callback' during this call
   or later. */

void ssh_engine_pme_get_next_rule_index(SshEngine engine,
                                        SshUInt32 rule_index,
                                        SshPmeIndexCB callback,
                                        void *context)
{
  SshEnginePolicyRule rule;
  SshUInt32 i;

  if (rule_index == SSH_IPSEC_INVALID_INDEX)
    i = 0;
  else
    i = rule_index + 1;

  /* Lookup the next valid rule. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (; i < engine->rule_table_size; i++)
    {
      rule = SSH_ENGINE_GET_RULE(engine, i);
      if (rule->type != SSH_ENGINE_RULE_NONEXISTENT)
        /* Found it. */
        break;
    }

  if (i < engine->rule_table_size)
    /* Found the next rule. */
    rule_index = i;
  else
    /* No more rules available. */
    rule_index = SSH_IPSEC_INVALID_INDEX;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return the result. */
  (*callback)(engine->pm, rule_index, context);
}

/* Retrieves statistics information for the given rule from the
   engine.  `callback' will be called with `context' and `stats'
   either during this call or later; if the rule_index is invalid,
   then `stats' will be NULL.  The callback should copy the statistics
   if they are needed after the call. */

void ssh_engine_pme_get_rule_stats(SshEngine engine, SshUInt32 rule_index,
                                   SshPmeRuleStatsCB callback, void *context)
{
  SshEnginePolicyRule rule;
  SshEngineRuleStatsStruct stats;

  if (rule_index >= engine->rule_table_size)
    {
      (*callback)(engine->pm, NULL, context);
      return;
    }

  /* Copy the flow statistics to local storage to ensure that the flow
     does not disappear from under us while we are delivering the stats
     to the caller. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  rule = SSH_ENGINE_GET_RULE(engine, rule_index);
  if (rule->type == SSH_ENGINE_RULE_NONEXISTENT)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, context);
      return;
    }
  stats = rule->stats;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  (*callback)(engine->pm, &stats, context);
}

#endif /* SSH_IPSEC_STATISTICS */

/* Prevents the creation of new flows until
   ssh_engine_pme_enable_policy_lookup is called.  This may either drop or
   delay all packets that would result in a policy rule lookup.  This
   can be used by the policy manager to implement semi-atomic policy
   update by disabling policy lookups while the policy is being
   updated, re-enabling it after all new rules have been added and old
   rules deleted. It is not recommended to disable policy lookups for
   any extended periods of time. */

void ssh_engine_pme_disable_policy_lookup(SshEngine engine,
                                          SshPmeStatusCB callback,
                                          void *context)
{
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  engine->policy_lookups_disabled = TRUE;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (callback)
    (*callback)(engine->pm, FALSE, context);
}

/* Re-enables policy lookups after ssh_engine_pme_disable_policy_lookup has
   been used.  If the engine implemented queuing for the packets, this
   causes the queued packets to be processed. */

void ssh_engine_pme_enable_policy_lookup(SshEngine engine,
                                         SshPmeStatusCB callback,
                                         void *context)
{
  ssh_engine_trigger_uninit(engine);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  engine->policy_lookups_disabled = FALSE;
#ifndef SSH_IPSEC_SMALL
  ssh_engine_rule_lookup_flush(engine, engine->policy_rule_set);
#endif /* SSH_IPSEC_SMALL */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  ssh_engine_flow_undangle_all(engine);

  if (callback)
    (*callback)(engine->pm, TRUE, context);
}

/****************************** ARP  functions ******************************/

/* Adds an ARP entry for the IP address `ip' and media address
   `media_addr', `media_addr_len'.  This calls the callback either
   during this call or at some later time to inidicate whether the ARP
   entry could be added. */

void ssh_engine_pme_arp_add(SshEngine engine,
                            const SshIpAddr ip,
                            SshUInt32 ifnum,
                            const unsigned char *media_addr,
                            size_t media_addr_len,
                            SshUInt32 flags,
                            SshPmeStatusCB callback, void *context)
{
  Boolean success = TRUE;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  if (ifnum != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) ifnum;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (media_addr_len != SSH_ETHERH_ADDRLEN)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid media address length: %u vs. expected %u",
                 media_addr_len, SSH_ETHERH_ADDRLEN));
      goto error;
    }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* The interface_lock protects ARP cache. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Add a new entry to the ARP cache. */
  success = ssh_engine_arp_add(engine, ip, eng_ifnum, media_addr,
                               (flags & SSH_PME_ARP_PERMANENT) ? TRUE : FALSE,
                               (flags & SSH_PME_ARP_PROXY) ? TRUE : FALSE,
                               (flags & SSH_PME_ARP_GLOBAL) ? TRUE : FALSE);

  ssh_kernel_mutex_unlock(engine->interface_lock);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* All done. */
  (*callback)(engine->pm, success, context);
  return;

  /* Error handling. */
 error:
  (*callback)(engine->pm, FALSE, context);
}

/* Removes the ARP entry of the IP address `ip', if one exists.  This
   has no effect if there is no ARP entry for the IP address. */

void ssh_engine_pme_arp_remove(SshEngine engine,
                               const SshIpAddr ip,
                               SshUInt32 ifnum)
{
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  if (ifnum != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) ifnum;

  /* The interface_lock protects the ARP cache. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Remove the ARP entry from the ARP cache. */
  ssh_engine_arp_delete(engine, ip, eng_ifnum);

  ssh_kernel_mutex_unlock(engine->interface_lock);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
}

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
/************************ Virtual adapter functions *************************/

#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
/* Context data for asynchronous virtual adapter operations. */
typedef struct SshEngineVirtualAdapterOpCtxRec
{
  SshEngine engine;
  SshUInt32 num_adapters;
  SshUInt32 num_allocated_adapters;
  SshPmeVirtualAdapter adapters; /* Storage for list operation. */
  Boolean params_set;
  SshVirtualAdapterParamsStruct params[1];
  SshIpAddrStruct client_ip[1];
  SshPmeVirtualAdapterStatusCB callback;
  void *context;
} *SshEngineVirtualAdapterOpCtx;


#ifdef INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE

/* A callback function that is called when the virtual adapter
   configuration is completed. */
static void
ssh_engine_virtual_adapter_configure_cb(SshVirtualAdapterError error,
                                        SshInterceptorIfnum adapter_ifnum,
                                        const unsigned char *adapter_name,
                                        SshVirtualAdapterState adapter_state,
                                        void *adapter_context,
                                        void *context)
{
  SshEngineVirtualAdapterOpCtx c = (SshEngineVirtualAdapterOpCtx) context;
  SshPmeVirtualAdapterStruct adapter;
  SshUInt32 ifnum = SSH_INVALID_IFNUM;

  if (adapter_ifnum != SSH_INTERCEPTOR_INVALID_IFNUM)
    ifnum = (SshUInt32) adapter_ifnum;

  if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
    {
      if (c->params_set)
        {
          SSH_ASSERT(adapter_context != NULL);

          /* Update virtual adapter context. */
          if (!ssh_virtual_adapter_context_update(adapter_context,
                                                  c->params,
                                                  c->client_ip,
                                                  NULL,
                                                  0))
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not update virtual adapter context."));





              error = SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY;
              goto error;
            }
        }

      /* All ok, call completion callback. */
      adapter.adapter_ifnum = ifnum;
      ssh_snprintf(adapter.adapter_name, SSH_INTERCEPTOR_IFNAME_SIZE,
                   "%s", adapter_name);
      adapter.adapter_state = adapter_state;

      (*c->callback)(c->engine->pm, error, 1, &adapter, c->context);
      ssh_free(c);
      return;
    }

 error:
  /* Error, call completion callback. */
  (*c->callback)(c->engine->pm, error, 0, NULL, c->context);
  ssh_free(c);
}
#endif /* INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE */
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */

/* Configures the virtual adapter `adapter_ifnum' with `state', `addresses',
   and `params'. The argument `adapter_ifnum' must be the valid interface
   index of a virtual adapter that has been attached to the engine during
   pm connect.

   The arguments `num_addresses' and `addresses' specify the IP addresses
   for the virtual adapter. The addresses must specify the netmask. If
   `num_addresses' is zero, the address configuration will not be changed.
   Otherwise the existing addresses will be removed from the virtual adapter
   and specified addresses will be added. To clear all addresses from the
   virtual adapter, give an undefined IP address as the only address.

   The argument `state' specifies the state for the virtual adapter.

   The argument `params' specifies optional parameters for the virtual adapter.
   If `params' is non-NULL, then the existing params will be cleared and the
   specified params will be set for the virtual adapter. */

void
ssh_engine_pme_virtual_adapter_configure(SshEngine engine,
                                         SshUInt32 adapter_ifnum,
                                         SshVirtualAdapterState state,
                                         SshUInt32 num_addresses,
                                         SshIpAddr addresses,
                                         SshVirtualAdapterParams params,
                                         SshPmeVirtualAdapterStatusCB callback,
                                         void *context)
{
#if defined(INTERCEPTOR_HAS_VIRTUAL_ADAPTERS) && \
    defined(INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE)
  SshEngineVirtualAdapterOpCtx c = NULL;
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  if (adapter_ifnum != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) adapter_ifnum;

  /* Allocate a context for the asynchronous virtual adapter configuration. */
  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate callback context"));
      goto error;
    }

  /* Take a copy of the params. */
  if (params)
    {
      *c->params = *params;
      c->params_set = TRUE;
    }

  c->engine = engine;
  c->callback = callback;
  c->context = context;

  /* Create the adapter. */
  ssh_virtual_adapter_configure(engine->interceptor,
                                eng_ifnum,
                                state,
                                num_addresses,
                                addresses,
                                params,
                                ssh_engine_virtual_adapter_configure_cb, c);

  /* All done.  The callback will take care of notifying our
     caller. */
  return;

  /* Error handling. */
 error:
  ssh_free(c);
  (*callback)(engine->pm,
              SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY, 0, NULL,
              context);
  return;
#else /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS && ... */
  (*callback)(engine->pm,
              SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT, 0, NULL,
              context);
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS && ... */
}

#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
void
ssh_engine_virtual_adapter_list_cb(SshVirtualAdapterError error,
                                   SshInterceptorIfnum adapter_ifnum,
                                   const unsigned char *adapter_name,
                                   SshVirtualAdapterState adapter_state,
                                   void *adapter_context,
                                   void *context)
{
  SshEngineVirtualAdapterOpCtx c = (SshEngineVirtualAdapterOpCtx) context;
  SshPmeVirtualAdapter adapter, adapters;
  SshUInt32 ifnum = SSH_INVALID_IFNUM;

  if (adapter_ifnum != SSH_INTERCEPTOR_INVALID_IFNUM)
    ifnum = (SshUInt32) adapter_ifnum;

  /* All matching virtual adapters have been enumerated,
     call completion callback */
  if (error == SSH_VIRTUAL_ADAPTER_ERROR_NONEXISTENT)
    {
      (*c->callback)(c->engine->pm, SSH_VIRTUAL_ADAPTER_ERROR_OK,
                     c->num_adapters, c->adapters, c->context);
      ssh_free(c->adapters);
      ssh_free(c);
      return;
    }

  if (error != SSH_VIRTUAL_ADAPTER_ERROR_OK
      && error != SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE)
    {
      (*c->callback)(c->engine->pm, error, 0, NULL, c->context);
      ssh_free(c->adapters);
      ssh_free(c);
      return;
    }

  SSH_ASSERT(error == SSH_VIRTUAL_ADAPTER_ERROR_OK
             || error == SSH_VIRTUAL_ADAPTER_ERROR_OK_MORE);

  if (c->adapters == NULL)
    goto out_of_memory;

  /* Allocate more space for adapters, if necessary. */
  if (c->num_adapters >= c->num_allocated_adapters)
    {
      adapters = ssh_realloc(c->adapters,
                             c->num_allocated_adapters
                             * sizeof(c->adapters[0]),
                             (c->num_allocated_adapters + 10)
                             * sizeof(c->adapters[0]));
      if (adapters == NULL)
        goto out_of_memory;
      c->adapters = adapters;
      c->num_allocated_adapters += 10;
    }

  /* Fill in adapter info. */
  adapter = &c->adapters[c->num_adapters];
  c->num_adapters++;
  adapter->adapter_ifnum = ifnum;
  ssh_snprintf(adapter->adapter_name, SSH_INTERCEPTOR_IFNAME_SIZE,
               "%s", adapter_name);
  adapter->adapter_state = adapter_state;

  /* All ok, wait for next status callback. */
  return;

 out_of_memory:
  SSH_DEBUG(SSH_D_ERROR, ("Out of memory"));
  return;
}
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */

void
ssh_engine_pme_virtual_adapter_list(SshEngine engine,
                                    SshUInt32 adapter_ifnum,
                                    SshPmeVirtualAdapterStatusCB callback,
                                    void *context)
{
#ifdef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
  SshEngineVirtualAdapterOpCtx c;
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  if (adapter_ifnum != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) adapter_ifnum;

  /* Allocate operation context. */
  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate callback context"));
      (*callback)(engine->pm,
                  SSH_VIRTUAL_ADAPTER_ERROR_OUT_OF_MEMORY,
                  0, NULL, context);
      return;
    }

  /* Enumerate matching virtual adapters. */
  c->engine = engine;
  c->callback = callback;
  c->context = context;
  c->num_adapters = 0;
  c->num_allocated_adapters = 10;
  c->adapters = ssh_calloc(c->num_allocated_adapters, sizeof(c->adapters[0]));

  ssh_virtual_adapter_get_status(engine->interceptor, eng_ifnum,
                                 ssh_engine_virtual_adapter_list_cb, c);
  return;
#else /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
  (*callback)(engine->pm,
              SSH_VIRTUAL_ADAPTER_ERROR_OK, 0, NULL, context);
#endif /* not INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
}
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */




void
ssh_engine_pme_redo_flows(SshEngine engine)
{
  SSH_INTERCEPTOR_STACK_MARK();
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("ssh_engine_pme_redo_flows() call received from PM!"));
  ssh_engine_route_change_callback((void *)engine);
}

void ssh_engine_notify_pm_close(SshEngine engine)
{
  SshEngineTransformControl c_trd;
  SshUInt32 i;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Detach all virtual adapters. */
  if (engine->ipm_open)
    ssh_virtual_adapter_uninit(engine->interceptor);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* Lock the flow table lock. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Mark the policy interface not open. */
  engine->ipm_open = FALSE;

  /* Delete all policy rules from the system.  This will also delete
     all flows and transforms.  Some deletions might be slightly
     delayed if there are packets currently being processed.  However,
     since the rules are deleted, no more flows will be created using
     them, and eventually they will all get deleted, as will all
     transforms and flows.  Packet context objects may not all get
     freed, as new packets may arrive at any time.  Some packet
     contexts may also remain in ARP data structures etc. */

  /* Do not delete the default engine rules */
  for (i = SSH_ENGINE_NUM_DEFAULT_RULES; i < engine->rule_table_size; i++)
    {
      SshEnginePolicyRule rule = SSH_ENGINE_GET_RULE(engine, i);
      if (rule->type != SSH_ENGINE_RULE_NONEXISTENT)
        {
          /* If the policy manager has an extra reference to the rule,
             we must remove it now since the policy manager won't do
             it. */
          if (rule->flags & SSH_ENGINE_RULE_PM_REFERENCE)
            {
              /* Clear the reference flag. */
              rule->flags &= ~SSH_ENGINE_RULE_PM_REFERENCE;

              /* Is the rule already deleted? */
              if (rule->flags & SSH_ENGINE_RULE_DELETED && rule->refcnt == 0)
                {
                  ssh_engine_rule_free(engine, i);
                  continue;
                }
            }

          /* Delete this rule only if it has not already been deleted.
             The rule may still be waiting for an execute_rule to die
             out. */
          if ((rule->flags & SSH_ENGINE_RULE_DELETED) == 0)
            ssh_engine_delete_rule(engine, i);
        }
    }

  /* Put all transform objects from the destroy notify list to the trd
     freelist.  The policy manager is no longer interested in the
     destroy notifications. */
  while (engine->transform_destroy_notify_list != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineTransformData d_trd;
      SshUInt32 transform_index = engine->transform_destroy_notify_list;

      c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, transform_index);

      engine->transform_destroy_notify_list = c_trd->rules;

      if (engine->transform_destroy_notify_list == SSH_IPSEC_INVALID_INDEX)
        engine->transform_destroy_notify_list_tail = SSH_IPSEC_INVALID_INDEX;

      c_trd->rules = SSH_IPSEC_INVALID_INDEX;

      /* And put the trd to the freelist. */
      ssh_engine_transform_freelist_put(engine, transform_index);

      /* Recycle the trd node. */
      d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);
      d_trd->transform = 0;
      FASTPATH_UNINIT_TRD(engine->fastpath, transform_index, d_trd);
    }

  /* Handle the case that trd_index has not been associated with
     a outbound SA rule. */
  for (i = 0; i < SSH_ENGINE_PEER_HASH_SIZE; i++)
    {
      while (engine->peer_hash[i] != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd = SSH_ENGINE_GET_TRD(engine, engine->peer_hash[i]);
          if (c_trd == NULL)
            break;

          SSH_ASSERT(c_trd->refcnt == 0);

          /* Temporarily increment the reference count so that it will
             reach zero when we decrement it. */
          SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);
          ssh_engine_decrement_transform_refcnt(engine, engine->peer_hash[i]);
        }
    }

  /* Unlock the flow table lock. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Release all pending audit events. */
  ssh_engine_audit_uninit(engine);

  /* Clear arp cache, since this might otherwise lead into some
     unwanted behavior. */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ssh_engine_arp_clear(engine);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Drop all entries from fragment magic (reassembly) queues. */
  fastpath_notify_close(engine->fastpath);

#ifdef SSHDIST_IPSEC_NAT
  /* Initialize all NAT configurations into default values. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Initialize the ifinfos table.*/
  for (i = 0; i < engine->ifs.nifs; i++)
    {
      SshInterceptorInterface *ifp;
      SshEngineIfInfo if_info;

      ifp = &engine->ifs.ifs[i];
      if_info = (SshEngineIfInfo) ifp->ctx_user;
      if_info->nat_type = SSH_PM_NAT_TYPE_NONE;
    }

  /* The dynamic NAT mappings will be freed when the flows are
     deleted. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
#endif /* SSHDIST_IPSEC_NAT */

  ssh_engine_response_rate_limit_clear(engine);
  ssh_engine_trigger_clear(engine);

#ifdef SSH_IPSEC_TCPENCAP
  /* Remove entries from connection and configuration tables */
  ssh_engine_tcp_encaps_destroy(engine);
#endif /* SSH_IPSEC_TCPENCAP */
}
