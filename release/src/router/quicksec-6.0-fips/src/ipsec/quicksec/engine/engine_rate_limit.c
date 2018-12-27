/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Rate-limitation code for flows and error responses.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineRateLimit"

/* Clears the bitmap of ICMPs recently sent.  This function is called
   from a timeout that is scheduled when the first ICMP since last
   clear is sent.  This function can be called concurrently with other
   functions. */

void
ssh_engine_response_rate_limit_clear(void *context)
{
  SshEngine engine = (SshEngine)context;

  /* Clear the bitmap of ICMPs sent recently, and clear the indication that
     there is a bit set and timeout scheduled.  This timeout is not
     rescheduled until an ICMP is again sent. */
  ssh_kernel_mutex_lock(engine->trigger_lock);
  memset(engine->response_rate_bitmap, 0,
         sizeof(engine->response_rate_bitmap));
  engine->rate_timeout_scheduled = FALSE;
  ssh_kernel_mutex_unlock(engine->trigger_lock);
}

void
ssh_engine_flow_rate_decrement(void *context)
{
  SshUInt32 total, i;
  Boolean reschedule;
  SshEngine engine = (SshEngine)context;

  reschedule = FALSE;
  total = 0;

  /* Decrease the flow rate limitation counters */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
  for (i = 0; i < SSH_ENGINE_FLOW_RATE_HASH_SIZE; i++)
    {
      if (engine->flow_rate_hash[i])
        {
          /* If we assume that a syn packet takes 40 bytes. Total flow rate
             is a SshUInt32 (max 2^32), then the maximum bandwith across
             ALL interfaces we can handle gracefully is (0.1 * 2^32 * 2^40).
             This should be sufficient. */

          engine->flow_rate_hash[i] = (engine->flow_rate_hash[i] * 90) / 100;
          total += engine->flow_rate_hash[i];
          reschedule = TRUE;
        }
    }

  engine->flow_rate_total = total;
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

  /* Reset the audit event counters. */
  for (i = 0; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    engine->audit_current_rate[i] = 0;

  /* Reschedule timeout */
  if (reschedule)
    ssh_kernel_timeout_register(1L, 0L, ssh_engine_flow_rate_decrement,
                                (void*)engine);
  else
    engine->flow_rate_timeout_scheduled = FALSE;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}

#ifdef SSH_ENGINE_FLOW_RATE_LIMIT
/* This function should be called when a flow is freed. It will
   adjust the rate limitation bitmaps accordingly. The parameters
   for the function should be the same as those used in
   the corresponding call to ssh_engine_flow_rate_limit(),
   although this is not strict. This function must be called with
   the 'engine->flow_control_table_lock' held. */
void
ssh_engine_flow_rate_unlimit(SshEngine engine, const SshIpAddr src)
{
  SshUInt32 hash, masked_ip;

  SSH_ASSERT(engine != NULL);
  SSH_ASSERT(src != NULL);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (SSH_IP_IS4(src))
    {
      SshIpAddrStruct tmp;

      masked_ip = SSH_IP4_TO_INT(src);
      SSH_INT_TO_IP4(&tmp, masked_ip & 0xFFFFFF00);
      hash = SSH_IP_HASH(&tmp);
    }
  else if (SSH_IP_IS6(src))
    {
      SshIpAddrStruct tmp;

      if (ssh_inet_addr_is_ip6_mapped_ip4(src))
        {
          masked_ip = SSH_IP6_WORD3_TO_INT(src);

          SSH_INT_TO_IP4(&tmp, masked_ip & 0xFFFFFF00);
          hash = SSH_IP_HASH(&tmp);
        }
      else
        {
          masked_ip  = SSH_IP6_WORD0_TO_INT(src);
          masked_ip ^= SSH_IP6_WORD1_TO_INT(src);

          SSH_INT_TO_IP4(&tmp, masked_ip);
          hash = SSH_IP_HASH(&tmp);
        }
    }
  else
    return;

  hash = hash % SSH_ENGINE_FLOW_RATE_HASH_SIZE;

  if (engine->flow_rate_hash[hash] > 0)
    {
      engine->flow_rate_hash[hash]--;
      SSH_ASSERT(engine->flow_rate_total > 0);
      engine->flow_rate_total--;
    }
}

/* A simple rate limitation for flows. This function returns TRUE if
   the flow creation should be prohibited due to a rate limit.
   The parameter src is the source address of the packet triggering
   the flow create and pc is the packet context for this packet.
   This function must be called with the 'engine->flow_control_table_lock'
   held. */
Boolean
ssh_engine_flow_rate_limit(SshEngine engine, const SshIpAddr src,
                           Boolean is_trusted)
{
  SshUInt32 hash, masked_ip;
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  SshUInt32 flows_in_use;
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (SSH_IP_IS4(src))
    {
      SshIpAddrStruct tmp;

      masked_ip = SSH_IP4_TO_INT(src);
      SSH_INT_TO_IP4(&tmp, masked_ip & 0xFFFFFF00);
      hash = SSH_IP_HASH(&tmp);
    }
  else if (SSH_IP_IS6(src))
    {
      SshIpAddrStruct tmp;

      if (ssh_inet_addr_is_ip6_mapped_ip4(src))
        {
          masked_ip = SSH_IP6_WORD3_TO_INT(src);

          SSH_INT_TO_IP4(&tmp, masked_ip & 0xFFFFFF00);
          hash = SSH_IP_HASH(&tmp);
        }
      else
        {
          masked_ip  = SSH_IP6_WORD0_TO_INT(src);
          masked_ip ^= SSH_IP6_WORD1_TO_INT(src);

          SSH_INT_TO_IP4(&tmp, masked_ip);
          hash = SSH_IP_HASH(&tmp);
        }
    }
  else
    return FALSE;

  hash = hash % SSH_ENGINE_FLOW_RATE_HASH_SIZE;

  engine->flow_rate_hash[hash]++;
  engine->flow_rate_total++;

  /* Schedule the timeout for decrementing the above */
  if (!engine->flow_rate_timeout_scheduled)
    {
      engine->flow_rate_timeout_scheduled = TRUE;

      ssh_kernel_timeout_register(1L, 0L, ssh_engine_flow_rate_decrement,
                                  (void *)engine);
    }

  /* Always allow some flow creations per hash entry */
  if (engine->flow_rate_hash[hash] <= engine->flow_rate_allow_threshold)
    return FALSE;

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  /* Do not rate limit flows based on median if the threshold has not
     been met. This is also not done if the protocol monitors are not
     enabled, as flows will often stay in the engine untill they are LRU
     reaped. */
  flows_in_use = engine->flow_table_size - engine->num_free_flows;
  if ((flows_in_use * 100 / engine->flow_table_size)
      < engine->flow_rate_limit_threshold)
    return FALSE;
#endif /* SSH_IPSEC_PROTOCOL_MONITORS */

  /* Rate limitation */
  if (((engine->flow_rate_hash[hash] * 100) / engine->flow_rate_total)
      > engine->flow_rate_max_share)
    return TRUE;

  return FALSE;
}
#endif /* SSH_ENGINE_FLOW_RATE_LIMIT */

/* A simple ratelimiter. This function returns TRUE if the packet
  should be dropped to a rate limit. */
Boolean
ssh_engine_response_rate_limit(SshEngine engine,
                               const SshIpAddr src, const SshIpAddr dst,
                               SshUInt16 ipproto,
                               SshUInt16 param_a, SshUInt16 param_b,
                               SshUInt16 checksum)
{
  SshUInt32 hash;

  hash = SSH_IP_HASH(src) * 3 + SSH_IP_HASH(dst) * 5 + ipproto * 7 +
    param_a * 11 + param_b * 13 + checksum * 17;
  hash %= SSH_ICMP_BITMAP_SIZE;

  /* Check if we have already reacted to a similar packet.  This uses a bitmap
     into which various ICMPs and RSTs are hashed.  The bitmap is cleared about
     once per second. */
  ssh_kernel_mutex_lock(engine->trigger_lock);
  if (engine->response_rate_bitmap[hash / 32] & (1 << (hash % 32)))
    {
      ssh_kernel_mutex_unlock(engine->trigger_lock);
      return TRUE;
    }
  engine->response_rate_bitmap[hash / 32] |= (1 << (hash % 32));
  if (!engine->rate_timeout_scheduled)
    {
      /* If first ICMP since last clear, schedule the bitmap to be cleared. */
      engine->rate_timeout_scheduled = TRUE;
      ssh_kernel_mutex_unlock(engine->trigger_lock);
      ssh_kernel_timeout_register(1L, 0L, ssh_engine_response_rate_limit_clear,
                                  (void *)engine);
    }
  else
    ssh_kernel_mutex_unlock(engine->trigger_lock);

  return FALSE;
}

/* A simple rate limiter for audit events */
Boolean
ssh_engine_audit_rate_limit(SshEngine engine, SshUInt32 audit_level)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(audit_level < SSH_ENGINE_NUM_AUDIT_LEVELS);

  if (engine->audit_current_rate[audit_level] > engine->audit_total_rate_limit)
    {
      return TRUE;
    }

  engine->audit_current_rate[audit_level]++;

  /* Schedule the timeout for decrementing the above */
  if (!engine->flow_rate_timeout_scheduled)
    {
      engine->flow_rate_timeout_scheduled = TRUE;

      ssh_kernel_timeout_register(1L, 0L, ssh_engine_flow_rate_decrement,
                                  (void *)engine);
    }

  return FALSE;
}
