/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to send trigger messages to the policy manager.  This file
   also includes the code to rate-limit such messages, so that
   triggers related to "similar" packets are limited to about one per
   second, and that the total number of any kind of triggers per
   second is limited to some reasonable number.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "sshtimeouts.h"

#define SSH_DEBUG_MODULE "SshEngineTrigger"

/* How many bytes of a packet to send to the policy manager if the triggered
   packet size is greater than SSH_ENGINE_MAX_TRIGGER_PACKET_SIZE. The
   policy manager packet needs access to the packet headers, the value below
   should be sufficient for all cases. */
#define SSH_ENGINE_TRUNCATED_TRIGGER_SIZE 512

/* Context structure for keeping information about a trigger.  This is
   needed for getting the required information into the timeout function
   that actually calls ssh_pmp_trigger.  (Note that we cannot use `pc',
   because it will likely be freed before the callback occurs.) */
struct SshEngineTriggerContextRec
{
  SshEngineTriggerContext next;
  unsigned char *linear_packet;
  size_t len;
  SshEngine engine;
  SshUInt32 ifnum;
  SshUInt32 flags;
  SshUInt32 tunnel_id;
  SshVriId routing_instance_id;
  SshUInt32 prev_transform_index;
  SshUInt32 flow_index;
  SshIpAddrStruct nat_src_ip;
  SshIpAddrStruct nat_dst_ip;
  SshUInt16 nat_src_port;
  SshUInt16 nat_dst_port;
  SshEnginePolicyRuleStruct rule;
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  SshTimeoutStruct timeout;
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
};

/* Clears the bitmap of triggers recently sent.  This function is
   called from a timeout that is scheduled when the first trigger
   since last clear is sent.  This function can be called
   concurrently. */

void ssh_engine_trigger_clear(void *context)
{
  SshEngine engine = (SshEngine)context;

  /* Clear the bitmap of triggers sent recently, and clear the indication that
     there is a bit set and timeout scheduled.  This timeout is not
     rescheduled until a trigger is again sent. */
  ssh_kernel_mutex_lock(engine->trigger_lock);
  memset(engine->trigger_bitmap, 0, sizeof(engine->trigger_bitmap));
  engine->trigger_sent = FALSE;
  ssh_kernel_mutex_unlock(engine->trigger_lock);
}

/* Sends the trigger message immediately.  This will be called either
   directly in the packet processing path (non-unified address space
   case) or from a timeout callback (unified address space case).
   This will free the trigger context and the linearized packet.
   Note that this function is single-threaded in the unified case (because
   of being called from a "user-mode" timeout), but may be multi-threaded
   in the non-unified address space case. */

void ssh_engine_trigger_now(void *context)
{
  SshEngineTriggerContext c = (SshEngineTriggerContext)context;
  SshEngineTriggerContext c_prev;
  SshEngine engine = c->engine;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Remove trigger context from list. */
  ssh_kernel_mutex_lock(engine->trigger_lock);
  if (engine->trigger_context == c)
    {
      engine->trigger_context = c->next;
    }
  else
    {
      c_prev = engine->trigger_context;
      while (c_prev != NULL && c_prev->next != c)
        c_prev = c_prev->next;
      SSH_ASSERT(c_prev != NULL && c_prev->next == c);
      c_prev->next = c->next;
    }
  ssh_kernel_mutex_unlock(engine->trigger_lock);

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  if (ssh_engine_upcall_timeout(c->engine) == FALSE)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Dropping trigger, upcall_timeout() failed"));
      ssh_free(c->linear_packet);
      ssh_free(c);
      return;
    }
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  /* Call the corresponding policy manager function (which will be
     just a wrapper that passes the call to the policy manager in the
     non-unified address space case).  This call will free
     c->linear_packet. */
  ssh_pmp_trigger(c->engine->pm,
                  &c->rule,
                  c->flow_index,
                  &c->nat_src_ip,
                  c->nat_src_port,
                  &c->nat_dst_ip,
                  c->nat_dst_port,
                  c->tunnel_id,
                  c->routing_instance_id,
                  c->prev_transform_index, c->ifnum,
                  c->flags, c->linear_packet, c->len);

  /* Free the context structure. */
  ssh_free(c);
}

/* Sends a trigger message to the policy manager, unless it gets
   filtered by the rate limiting mechanism.  This function
   also tries not to send more than about one trigger per second for
   packets with same srcip/dstip/proto/srcport/dstip combination.  The
   reason for this is to avoid queuing huge numbers of packets
   belonging to the same stream when there is no rule to process them
   other than by triggering.  An example of such a situation is a
   sudden "ping -f".  This provides some denial of service protection.
   This returns TRUE if the trigger was either sent or ignored (pc->pp is
   still valid), and FALSE if an error occurred that caused pc->pp to
   become invalid. */
Boolean ssh_engine_trigger(SshEnginePacketContext pc,
                           SshEnginePolicyRule rule,
                           SshUInt32 flow_index)
{
  SshEngine engine = pc->engine;
  SshInterceptorPacket pp = pc->pp;
  unsigned char *linear_packet;
  SshUInt32 hash, slot, wrapped_index, f_gen;
  SshUInt16 c_flags;
  SshEngineTriggerContext c, c_prev;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshIpAddrStruct nat_src_ip, nat_dst_ip;
  SshUInt16 nat_src_port, nat_dst_port;
  size_t packet_len, trigger_len;

  SSH_INTERCEPTOR_STACK_MARK();

  c_flags = 0;
  wrapped_index = SSH_IPSEC_INVALID_INDEX;

  if (flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

      d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);
      f_gen = d_flow->generation;
      wrapped_index = SSH_ENGINE_FLOW_WRAP_INDEX(f_gen, flow_index);

      if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0
          || (d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) == 0
          || (d_flow->generation != f_gen))
        {
          FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          SSH_DEBUG(SSH_D_ERROR, ("Flow trigger no longer required"));
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
          return TRUE;
        }

#ifdef SSHDIST_IPSEC_NAT
      nat_src_ip = d_flow->nat_src_ip;
      nat_dst_ip = d_flow->nat_dst_ip;
      nat_src_port = d_flow->nat_src_port;
      nat_dst_port = d_flow->nat_dst_port;
#else /* SSHDIST_IPSEC_NAT */
      nat_src_ip = d_flow->src_ip;
      nat_dst_ip = d_flow->dst_ip;
      nat_src_port = d_flow->src_port;
      nat_dst_port = d_flow->dst_port;
#endif /* SSHDIST_IPSEC_NAT */
      c_flags = c_flow->control_flags;

      FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
    }
  else
    {
      nat_src_ip = pc->src;
      nat_dst_ip = pc->dst;
      nat_src_port = pc->u.rule.src_port;
      nat_dst_port = pc->u.rule.dst_port;
    }

  /* Mark that the statistics counter for triggers is to be updated. */
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_TRIGGER);

  /* Guard against sending the same packet repeatedly to the policy manager. */
  if (pp->flags & SSH_ENGINE_P_NOTRIGGER)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Double trigger detected!"));
      return TRUE;
    }

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Check if there are too many upcalls already pending.  This limits the
     amount of memory that might be consumed.  (Note that there could also
     be other pending upcalls, but at worst that may just cause some trigger
     to be lost).  We allow at most two simultaneous pending upcalls. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  if (engine->num_pending_upcall_timeouts > 5)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("too many upcalls - trigger ignored"));
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return TRUE;
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

  /* Limit the rate of trigger messages to send for packets with identical
     source/destination/protocol/port fields to about one per second. */

  /* Count the hash value for this packet. */
  hash = (3 * SSH_IP_HASH(&pc->src) +
          5 * SSH_IP_HASH(&pc->dst) +
          7 * pc->ipproto +
          11 * pc->u.rule.src_port +
          13 * pc->u.rule.dst_port);
  hash %= SSH_TRIGGER_BITMAP_SIZE;

  /* Use first half of trigger bitmap for normal triggers, and
     second half for crash recovery triggers.  Crash recovery triggers
     are rate limited separately, so that an attacker can not block
     normal triggers by sending specially crafted ESP packets to the
     SGW. */
  slot = hash / 32;
  if (rule->flags & SSH_PM_ENGINE_RULE_CR)
    slot += SSH_TRIGGER_BITMAP_WORDS;
  SSH_ASSERT(slot < (sizeof(engine->trigger_bitmap)
                     / sizeof(engine->trigger_bitmap[0])));

  ssh_kernel_mutex_lock(engine->trigger_lock);

  /* Check if we have already sent a trigger that hashes to the same
     bit since the last clear. */
  if (engine->trigger_bitmap[slot] & (1 << (hash % 32)))
    {
      ssh_kernel_mutex_unlock(engine->trigger_lock);
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_NOTRIGGER);
      SSH_DEBUG(SSH_D_MIDOK,
                ("trigger not sent because already recently sent"));
      return TRUE;
    }
  /* Mark that we have sent such a trigger.  Schedule a timeout to clear the
     bitmap in one second if we haven't already done so.  Release the lock. */
  engine->trigger_bitmap[slot] |= (1 << (hash % 32));
  if (!engine->trigger_sent)
    {
      /* If first trigger since last clear, schedule the bitmap to be
         cleared. */
      engine->trigger_sent = TRUE;
      ssh_kernel_mutex_unlock(engine->trigger_lock);
      ssh_kernel_timeout_register(0L, 400000L,
                                  ssh_engine_trigger_clear,
                                  (void *)engine);
    }
  else
    ssh_kernel_mutex_unlock(engine->trigger_lock);

  /* Copy the packet into linear memory for convenience. */
  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pp));

  if (pc->packet_len > SSH_ENGINE_MAX_TRIGGER_PACKET_SIZE)
    packet_len = SSH_ENGINE_TRUNCATED_TRIGGER_SIZE;
  else
    packet_len = pc->packet_len;

  SSH_ASSERT(packet_len <= pc->packet_len);

  trigger_len = packet_len +
    SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS * sizeof(SshUInt32);

  linear_packet = ssh_malloc(trigger_len);
  if (linear_packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No memory for trigger packet"));
      return TRUE;
    }
  ssh_interceptor_packet_copyout(pp, 0, linear_packet, packet_len);

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Append the extension selectors to the end of the linear packet */
  memcpy(linear_packet + packet_len, pp->extension, trigger_len - packet_len);
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Trigger by rule %d",
             (int) SSH_ENGINE_GET_RULE_INDEX(engine, rule)));
  /* Allocate and initialize a trigger context. */
  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL)
    {
      ssh_free(linear_packet);
      return TRUE;
    }
  c->linear_packet = linear_packet;
  c->len = trigger_len;
  c->engine = engine;
  if (pp->ifnum_in != SSH_INTERCEPTOR_INVALID_IFNUM)
    c->ifnum = (SshUInt32) pp->ifnum_in;
  else
    c->ifnum = SSH_INVALID_IFNUM;
  c->flags = 0;
  c->nat_src_ip = nat_src_ip;
  c->nat_src_port = nat_src_port;
  c->nat_dst_ip = nat_dst_ip;
  c->nat_dst_port = nat_dst_port;
  c->flow_index = wrapped_index;

  /* Don't reprocess a truncated packet. */
  if (packet_len != pc->packet_len)
    c->flags |= SSH_PME_PACKET_DONT_REPROCESS;
  if (pp->flags & SSH_PACKET_FROMPROTOCOL)
    c->flags |= SSH_PME_PACKET_LOCAL;
  if (pp->flags & SSH_PACKET_MEDIABCAST)
    c->flags |= SSH_PME_PACKET_MEDIABCAST;
  if (pp->flags & SSH_ENGINE_P_WASFRAG)
    c->flags |= SSH_PME_PACKET_WASFRAG;
  if (c_flags & SSH_ENGINE_FLOW_C_TRIGGER)
    c->flags |= SSH_PME_PACKET_SESSION_TRIGGER;
  if (c_flags & SSH_ENGINE_FLOW_C_UNDEFINED)
    c->flags |= SSH_PME_PACKET_APPGW_TRIGGER;
  if (pp->flags & SSH_PACKET_HWCKSUM)
    c->flags |= SSH_PME_PACKET_HWCKSUM;
  if (pp->flags & SSH_PACKET_IP4HDRCKSUMOK)
    c->flags |= SSH_PME_PACKET_IP4HDRCKSUMOK;
  if (pp->flags & SSH_PACKET_IP4HHWCKSUM)
    c->flags |= SSH_PME_PACKET_IP4HHWCKSUM;
  if (pp->flags & SSH_PACKET_FRAGMENTATION_ALLOWED)
    c->flags |= SSH_PME_PACKET_FRAG_ALLOWED;
  if (pc->flags & SSH_ENGINE_PC_RESTARTED_OUT)
    c->flags |= SSH_PME_PACKET_RESTARTED_OUT;

  c->tunnel_id = pc->tunnel_id;
  c->prev_transform_index = pc->prev_transform_index;
  c->rule = *rule;

  c->routing_instance_id = pp->routing_instance_id;

  /* Append trigger context to list. */
  ssh_kernel_mutex_lock(engine->trigger_lock);
  if (engine->trigger_context == NULL)
    {
      engine->trigger_context = c;
    }
  else
    {
      c_prev = engine->trigger_context;
      while (c_prev->next != NULL)
        c_prev = c_prev->next;
      SSH_ASSERT(c_prev->next == NULL);
      c_prev->next = c;
    }
  ssh_kernel_mutex_unlock(engine->trigger_lock);

  /* Send the trigger, either immediately or later, depending on
     configuration. */
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  /* Record the timeout before actually wrapping to the policymanager
     thread */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  ssh_engine_record_upcall(engine);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Schedule the call to the policy manager from a timeout.  Note
     that we intentionally use the "normal" register-timeout here, not
     the kernel version.  See comments in engine_pm_api.h for
     explanation. */
  ssh_register_timeout(&c->timeout,
                       0L, 0L,
                       ssh_engine_trigger_now, (void *) c);
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  ssh_engine_trigger_now(c);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  return TRUE;
}

Boolean ssh_engine_trigger_init(SshEngine engine)
{
  /* Dummy init function never fails. */
  return TRUE;
}

void ssh_engine_trigger_uninit(SshEngine engine)
{
  /* In unified address space the pending triggers are taken care of
     by ssh_engine_upcall_timeout(). */

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  SshEngineTriggerContext c;

  /* Cancel all pending trigger timeouts and free
     pending trigger contexts. */
  ssh_kernel_timeout_cancel(ssh_engine_trigger_now, SSH_KERNEL_ALL_CONTEXTS);
  ssh_kernel_mutex_lock(engine->trigger_lock);
  while (engine->trigger_context != NULL)
    {
      c = engine->trigger_context;
      engine->trigger_context = c->next;
      if (c->linear_packet)
        ssh_free(c->linear_packet);
      ssh_free(c);
    }
  ssh_kernel_mutex_unlock(engine->trigger_lock);
#endif /* !SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
}
