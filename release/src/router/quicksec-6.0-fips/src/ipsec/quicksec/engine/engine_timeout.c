/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Timeout processing for the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineTimeout"

#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
#include "sshtimeouts.h"

/* Context structure for keeping information about a transform event.
   This is needed for the unified address space case so that we can
   get the required information into the timeout function that
   actually calls ssh_pmp_transform_event. */
typedef struct SshEngineTransformEventContextRec
{
  SshEngine engine;
  SshPmeFlowEvent event;
  SshUInt32 transform_index;
  SshEngineTransformStruct trdata; /* const */
  SshUInt32 rule_index;
  SshEnginePolicyRuleStruct ruledata; /* const */
  SshTime run_time;
  SshTimeoutStruct timeout;
} SshEngineTransformEventContextStruct, *SshEngineTransformEventContext;

/* Sends the transform event message immediately.  This will be called
   from a timeout callback (unified address space case).  This will
   free the transform event context. Note that this function is
   single-threaded in the unified case (because of being called from a
   "user-mode" timeout). */
void ssh_pmp_transform_event_now(void *context)
{
  SshEngineTransformEventContext c = (SshEngineTransformEventContext)context;

  /* check if the engine is stopping */
  if (ssh_engine_upcall_timeout(c->engine) == FALSE)
    {
      ssh_free(c);
      return;
    }

  /* Call the corresponding policy manager function */
  ssh_pmp_transform_event(c->engine->pm, c->event,
                          c->transform_index,
                          &c->trdata,
                          c->rule_index,
                          (c->rule_index == SSH_IPSEC_INVALID_INDEX
                           ? NULL : &c->ruledata),
                          c->run_time);

  /* Free the context structure. */
  ssh_free(c);
}
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

static Boolean
engine_schedule_transform_event(SshEngine engine,
                                SshPmeFlowEvent event,
                                SshUInt32 transform_index,
                                const SshEngineTransform tr,
                                SshUInt32 rule_index,
                                SshEnginePolicyRule rule,
                                SshTime run_time)
{
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  SshEngineTransformEventContext c;

  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL)
    return FALSE;
  else
    {
      c->engine = engine;
      c->event = event;
      c->transform_index = transform_index;
      c->trdata = *tr;

      c->rule_index = rule_index;
      if (rule)
        c->ruledata = *rule;

      c->run_time = run_time;

      /* Record the timeout before actually wrapping to the
         policymanager thread */
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      ssh_engine_record_upcall(engine);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Schedule the call to the policy manager from a
         timeout. Note that we intentionally use the "normal"
         register-timeout here, not the kernel version.  See
         comments in engine_pm_api.h for explanation. */
      ssh_register_timeout(&c->timeout,
                           0L, 0L, ssh_pmp_transform_event_now,
                           (void *)c);
      return TRUE;
    }
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  return ssh_pmp_transform_event(engine->pm,
                                 event,
                                 transform_index, tr,
                                 rule_index, rule,
                                 engine->run_time);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
}


/* Age timeout resolution in microseconds. */
#define SSH_ENGINE_AGE_TIMER_RESOLUTION 10000

/* Round time in microseconds down to age timeout resolution. */
#define SSH_ENGINE_AGE_TIME_USEC_ROUND(usec)                            \
  (((long) (usec) / SSH_ENGINE_AGE_TIMER_RESOLUTION)                    \
   * SSH_ENGINE_AGE_TIMER_RESOLUTION)

/* Compare two times within age timeout resolution. */
#define SSH_ENGINE_AGE_TIME_CMP(a_sec, a_usec, b_sec, b_usec)           \
  ((a_sec) < (b_sec) ? -1 :                                             \
   ((a_sec) == (b_sec) ?                                                \
    ((SSH_ENGINE_AGE_TIME_USEC_ROUND(a_usec) -                          \
      (SSH_ENGINE_AGE_TIME_USEC_ROUND(b_usec)))) : 1))

/* This call schedules engine age-timeout to be run.

   If 'when' is not zero, timeout will be run latest at that
   time. If packet is TRUE, the timeout will be run roughly after
   engine->age_callback_interval'. For packet being true, this also
   records that packet driven age timeout has been scheduled.

   The age-timeout can be run on two ways

   1) as a repetive timer
   2) packet and event driven

   The first method is quicksec original and is preferred for large
   systems where power consumption is not an issue. The second is
   intented for battery driven systems where frequent repetive timers
   are not desired. At this approach each processed packet schedules
   age timeout unless not already scheduled (call this with 'packet'
   as TRUE). To get transforms rekeyed when there is no active
   traffic, we have second instance of age-timeout scheduled at the
   next possible transform event time. The time of this timer is lower
   of 'when' and already scheduled timeout. */
static void engine_age_timeout_schedule(SshEngine engine,
                                        SshTime when,
                                        Boolean packet)
{
  SshTime timeout_sec, expire_sec;
  SshUInt32 timeout_usec, expire_usec;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  ssh_interceptor_get_time(&engine->run_time, &engine->run_time_usec);

  /* Packet scheduled age timeout requested and already registered. */
  if (packet == TRUE && engine->age_timeout_pkt_scheduled == 1)
    return;

  /* Age timeout requested to near future. */
  if (when == 0)
    {
      timeout_sec = engine->age_callback_interval / 1000000;
      timeout_usec = engine->age_callback_interval % 1000000;
    }

  /* Age timeout requested to exact moment. */
  else
    {
      /* Requested moment is in the past. */
      if (SSH_ENGINE_AGE_TIME_CMP(when, 0,
                                  engine->run_time,
                                  engine->run_time_usec) <= 0)
        {
          timeout_sec = 0;
          timeout_usec = SSH_ENGINE_AGE_TIMER_RESOLUTION;
        }
      else
        {
          timeout_sec = when - engine->run_time;
          timeout_usec = 0;
          SSH_ASSERT(timeout_sec > 0);
        }
    }

  /* Calculate absolute time of age callback. */
  SSH_ENGINE_TIME_ADD(expire_sec, expire_usec,
                      timeout_sec, timeout_usec,
                      engine->run_time, engine->run_time_usec);

  /* Mark that a packet driven age timeout is scheduled. */
  if (packet == TRUE)
    engine->age_timeout_pkt_scheduled = 1;

  /* Next age timeout is already registered before the requested time. */
  if ((engine->age_timeout_sec != 0
       || engine->age_timeout_usec != 0)
      && SSH_ENGINE_AGE_TIME_CMP(engine->age_timeout_sec,
                                 engine->age_timeout_usec,
                                 expire_sec, expire_usec) <= 0)
    return;

  /* Move age timeout or register a new if there was no old timeout
     registered. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Moving engine age timeout to %lu.%06lus at %lu.%06lu",
             (unsigned long) timeout_sec,
             (unsigned long) timeout_usec,
             (unsigned long) expire_sec,
             (unsigned long) expire_usec));
  if (ssh_kernel_timeout_move((SshUInt32) timeout_sec, timeout_usec,
                              ssh_engine_age_timeout, engine) == FALSE)
    {
      /* Register new age timeout. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Registering engine age timeout to %lu.%06lus at %lu.%06lu",
                 (unsigned long) timeout_sec,
                 (unsigned long) timeout_usec,
                 (unsigned long) expire_sec,
                 (unsigned long) expire_usec));
      ssh_kernel_timeout_register((SshUInt32) timeout_sec, timeout_usec,
                                  ssh_engine_age_timeout, engine);
    }

  /* Store the time of next timeout. */
  engine->age_timeout_sec = expire_sec;
  engine->age_timeout_usec = expire_usec;
}

void ssh_engine_age_timeout_schedule(SshEngine engine)
{
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  engine_age_timeout_schedule(engine, 0L, TRUE);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}

void ssh_engine_age_timeout_schedule_trd(SshEngine engine,
                                         SshTime when)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  engine_age_timeout_schedule(engine, when, FALSE);
}

/* Macro for setting next age timeout call. Just to make code more readable. */
#define ENGINE_AGE_TIMEOUT_NEXT_CALL(next_call, when) \
do                                                    \
  {                                                   \
    if ((next_call) == ~0 || (when) < (next_call))    \
      (next_call) = (when);                           \
  }                                                   \
while (0)

/* This function gets called regularly from a timeout.  This traverses
   through some or all of the flow descriptors in the engine, and
   frees those that have expired.  This is called every
   engine->age_callback_usec microseconds, and should traverse through
   engine->age_callback_flows.  This keeps track of the first flow to traverse
   on the next callback in the engine->age_callback_next field. */

void ssh_engine_age_timeout(void *context)
{
  SshEngine engine = (SshEngine)context;
  SshEngineAgeCallbackContext ctx;
  SshTime current_time, soft_expire_time, flow_idle_timeout, next_call;
  SshUInt32 i, j, num_to_free, total_num_processed, total_num_trd_events;
  SshUInt32 flow_index, rule_index, transform_index;
  Boolean too_many, success, add, activate;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshEnginePolicyRule rule, flow_rule;
  SshEnginePolicyRule rule_without_policy_context, rule_with_policy_context;
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshPmeFlowEvent event;
  SshUInt8 engine_undangle_flag, generation;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Check if there is already an age callback running. */
  if (engine->age_callback_running)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("age callback is already running."));
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;
    }
  engine->age_callback_running = 1;

  /* Clear the time of next age timeout call. */
  engine->age_timeout_sec = 0;
  engine->age_timeout_usec = 0;

  /* Get age callback context to local variable. */
  ctx = engine->age_callback_context;
  memset(ctx, 0, sizeof(*ctx));

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  total_num_processed = 0;
  total_num_trd_events = 0;

  /* Loop through all flows in the range which we should go through.
     Any flows which should be freed are collected in a separate table
     and will be freed after we have released the lock. While doing
     this, we'll also record time of next transform event. We use this
     information to schedule call to this function in case we
     traversed thru all flows on the system at a single call. */
 continue_searching:
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  ssh_interceptor_get_time(&engine->run_time, &engine->run_time_usec);

  SSH_DEBUG(SSH_D_HIGHOK, ("Age timeout: run_time %lu, next flow %d",
                           (unsigned long)engine->run_time,
                           (int)engine->age_callback_next));

  flow_index = engine->age_callback_next;
  current_time = engine->run_time;
  engine_undangle_flag = engine->undangle_all_pending;
  num_to_free = 0;
  too_many = FALSE;
  next_call = ~0;

  for (; total_num_processed < engine->age_callback_flows; flow_index++)
    {
      total_num_processed++;

      if (flow_index == engine->flow_table_size)
        flow_index = 0;
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

      /* Skip any flows that are already freed. */
      if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID))
        continue;

      /* Lock flow, copy contents, unlock and work on the copy. */
      d_flow = FASTPATH_GET_READ_ONLY_FLOW(engine->fastpath, flow_index);
      ctx->d_flow_copy = *d_flow;
      FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
      d_flow = &ctx->d_flow_copy;

      generation = d_flow->generation;

      if (d_flow->ipproto == SSH_IPPROTO_TCP)
        flow_idle_timeout = ssh_engine_tcp_get_idle_timeout(engine,
                                                            flow_index,
                                                            d_flow);
      else
        flow_idle_timeout = c_flow->idle_timeout;

      /* Check if we should do something special with the flow. */
      add = FALSE;
      event = SSH_ENGINE_EVENT_IDLE;

      /* Check time-based IPsec SA expirations. */
      if (d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
        {
          /* Ignore events for non-primary incoming IPsec flows. There may
             be multiple incoming IPsec flows pointing to the same transform
             in case SA has multiple APPLY rules due to complex traffic
             selectors or SCTP. */
          if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_PRIMARY) == 0)
            continue;

          /* Incoming IPsec flows - enforce trd lifetime limits. */
          SSH_ASSERT(d_flow->forward_transform_index
                     != SSH_IPSEC_INVALID_INDEX);
          d_trd = FASTPATH_GET_TRD(engine->fastpath,
                                   d_flow->forward_transform_index);
          c_trd = SSH_ENGINE_GET_TRD(engine, d_flow->forward_transform_index);
          SSH_ASSERT(c_trd != NULL);

          /* Events are relevant for IKE keyed SA's only */
          if (!(d_trd->transform & SSH_PM_IPSEC_MANUAL))
            {
              /* Calculate time of next rekey attempt. */
              soft_expire_time =
                SSH_ENGINE_IPSEC_SOFT_EVENT_TIME(engine, c_flow, c_trd,
                                                 c_flow->rekey_attempts);

              /* Check hard expiry. */
              if (c_flow->hard_expire_time != 0
                  && current_time >= c_flow->hard_expire_time)
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Incoming IPsec flow %d hard expiry %ld now %ld",
                             (int) flow_index,
                             (unsigned long) c_flow->hard_expire_time,
                             (unsigned long) current_time));
                  add = TRUE;
                  event = SSH_ENGINE_EVENT_EXPIRED;
                  total_num_trd_events++;
                }

              /* Check if need to invalidate old rekeyed SPI. */
              else if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_REKEYOLD)
                       && c_trd->rekeyed_time != 0
                       && (current_time >=
                           c_trd->rekeyed_time + flow_idle_timeout))
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Rekeyed incoming IPsec flow %d idle timeout %lds"
                             " last rekey %lds ago",
                             (int) flow_index,
                             (unsigned long) flow_idle_timeout,
                             (unsigned long) (current_time
                                              - c_trd->rekeyed_time)));
                  add = TRUE;
                  event = SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED;
                  total_num_trd_events++;
                }

              /* Check if need to trigger rekey. */
              else if (soft_expire_time != 0
                       && current_time >= soft_expire_time)
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Incoming IPsec flow %d soft expiry %ld now %ld",
                             (int) flow_index,
                             (unsigned long) soft_expire_time,
                             (unsigned long) current_time));
                  add = TRUE;
                  event = SSH_ENGINE_EVENT_REKEY_REQUIRED;
                  total_num_trd_events++;
                }

#ifdef SSH_IPSEC_STATISTICS
              /* Check if need to trigger rekey based on kilobyte lifetime.

                 The engine uses kilobyte lifetimes only for sending soft
                 events for SAs. When the first soft event is sent the SA hard
                 expiration is set to SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME
                 seconds in future. The engine generates subsequent soft and
                 hard expire events for the SA based on the remaining lifetime
                 in seconds.

                 Note: our semantics for kilobyte-based expirations is that
                 it is from the sum of the number of bytes transferred in
                 each direction.  This way it is the number of bytes encrypted
                 using the same [master] keys. */
              else if (c_flow->rekey_attempts == 0
                       && ((d_trd->stats.in_octets + d_trd->stats.out_octets) >
                           c_trd->life_bytes))
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Incoming IPsec flow %d kilobyte soft limit %lld "
                             "bytes total processed %lld bytes",
                             (int) flow_index,
                             c_trd->life_bytes,
                             (d_trd->stats.in_octets
                              + d_trd->stats.out_octets)));
                  add = TRUE;
                  event = SSH_ENGINE_EVENT_REKEY_REQUIRED;
                  total_num_trd_events++;

                  /* Adjust hard expire time for the transform. The SA will
                     expire eventually when the time based expiration is
                     reached if the SA has not been rekeyed. */
                  if (c_flow->hard_expire_time >
                      current_time + SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME)
                    c_flow->hard_expire_time = current_time
                      + SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME;
                }
#endif /* SSH_IPSEC_STATISTICS */

              /* Check for end of available sequence number
                 space. Magic value here present approximately 3
                 minutes worth of traffic on sustained 500,000
                 packets per second rate. */
              else if (!(d_trd->transform & SSH_PM_IPSEC_LONGSEQ)
                       && d_trd->out_packets_low > (0xffffffff-0x4ffffff))
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Incoming IPsec flow %d sequence number wrap "
                             "0x%lx",
                             (int) flow_index,
                             (unsigned long) d_trd->out_packets_low));
                  add = TRUE;
                  event = SSH_ENGINE_EVENT_REKEY_REQUIRED;
                  total_num_trd_events++;
                }

              /* Activating new outbound SA after SA rekey.

                 If this end is the responder of the IPsec SA rekey then the
                 new outbound SPI value and key material has been installed
                 but not activated. This end can start sending using the new
                 SPI and key material 1) when this end receives a packet with
                 the new inbound SPI value, 2) when the other end sends a
                 delete notification for the old inbound SPI or 3) when a
                 timeout occurs.

                 The incoming IPsec flow is added to the list of flows needing
                 attention to handle case 1 (i.e. for checking the replay
                 window). Case 3 was already handled above and case 2 is
                 handled by the policy manager. */
              else if ((c_trd->control_flags
                        & SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE))
                {
                  add = TRUE;
                  event = SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED;
                  /* This does not cause an event to policy manager
                     so the rate limit counter is not incremented. */
                }

              /* Transform idle detection. */

              /* If transform has received a packet since last check
                 then clear the worry metric counter, i.e. reset the idle
                 detection state.

                 When the transform is rekeyed c_trd->last_in_packet_time is
                 set to the time of rekey and c_trd->worry_metric_notified
                 is cleared. This means that effectively the idle worry
                 detection state is reset and the next idle event is sent
                 after c_flow->metric seconds have passed since the rekey
                 without receiving a packet from peer. */
              if (c_trd->last_in_packet_time < d_trd->last_in_packet_time)
                {
                  c_trd->worry_metric_notified = 0;
                  c_trd->last_in_packet_time = d_trd->last_in_packet_time;
                }

              /* Decrement idle worry metric counter. */
              if (c_trd->worry_metric_notified > 0)
                c_trd->worry_metric_notified--;

              /* If transform has not received any packets since the last
                 packet was sent using it, and flow worry metric seconds has
                 passed since last received packet, we notify the policy
                 manager, which may then recover the situation.

                 Once a notification is sent, the next idle events for this
                 transform are ignored for a configured number of age timeout
                 rounds. This behaviour is reset whenever a packet is received
                 from peer or the transform is rekeyed. */
              if (event == SSH_ENGINE_EVENT_IDLE
                  && (c_trd->control_flags & SSH_ENGINE_TR_C_DPD_ENABLED)
                  && c_trd->worry_metric_notified == 0
                  && d_trd->last_out_packet_time > c_trd->last_in_packet_time)
                {
                  if (current_time >=
                      c_trd->last_in_packet_time + c_flow->metric)
                    {
                      SSH_DEBUG(SSH_D_MIDOK,
                                ("Incoming IPsec flow %d idle timeout %lds "
                                 "last packet received %lds ago",
                                 (int) flow_index,
                                 (unsigned long) c_flow->metric,
                                 (unsigned long) (current_time
                                                  - c_trd->last_in_packet_time)
                                 ));
                      add = TRUE;
                      event = SSH_ENGINE_EVENT_IDLE;
                      total_num_trd_events++;
                    }
                  else
                    {
                      ENGINE_AGE_TIMEOUT_NEXT_CALL(next_call,
                                                   c_trd->last_in_packet_time
                                                   + c_flow->metric);
                    }
                }

              /* Set next age timeout call. */

              /* Hard expiry. */
              if (c_flow->hard_expire_time != 0
                  && current_time < c_flow->hard_expire_time)
                ENGINE_AGE_TIMEOUT_NEXT_CALL(next_call,
                                             c_flow->hard_expire_time);
              /* Next soft event. */
              if (soft_expire_time != 0
                  && current_time < soft_expire_time)
                {
                  ENGINE_AGE_TIMEOUT_NEXT_CALL(next_call, soft_expire_time);
                }
              else
                {
                  soft_expire_time =
                    SSH_ENGINE_IPSEC_SOFT_EVENT_TIME(engine, c_flow, c_trd,
                                                     c_flow->rekey_attempts+1);
                  if (soft_expire_time != 0
                      && current_time < soft_expire_time)
                    ENGINE_AGE_TIMEOUT_NEXT_CALL(next_call, soft_expire_time);
                }

              /* Time to invalidate old SPIs. */
              if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_REKEYOLD)
                  && current_time < (c_trd->rekeyed_time + flow_idle_timeout))
                ENGINE_AGE_TIMEOUT_NEXT_CALL(next_call,
                                             c_trd->rekeyed_time
                                             + flow_idle_timeout);
            } /* end of IKE keyed */

          /* Age PMTU values. */
          if (c_trd->pmtu_age_time != 0
              && c_trd->pmtu_age_time < current_time)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Aging PMTU of trd_index 0x%lx",
                         (unsigned long) d_flow->forward_transform_index));
              d_trd->pmtu_received = 0;
              c_trd->pmtu_age_time = 0;
            }

          FASTPATH_COMMIT_TRD(engine->fastpath,
                              d_flow->forward_transform_index, d_trd);
        }

      /* Check normal flow idle timeout. */
      else
        {
          if (c_flow->hard_expire_time != 0
              && current_time >= c_flow->hard_expire_time)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Flow %d hard expiry %ld now %ld",
                         (int) flow_index,
                         (unsigned int) c_flow->hard_expire_time,
                         (unsigned int) current_time));
              add = TRUE;
              event = SSH_ENGINE_EVENT_EXPIRED;

            }

          if (flow_idle_timeout != 0xffffffff
              && current_time >= d_flow->last_packet_time + flow_idle_timeout)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Flow %d idle timeout %lds last packet received "
                         "%lds ago",
                         (int) flow_index,
                         (unsigned int) flow_idle_timeout,
                         (unsigned int) (current_time
                                         - d_flow->last_packet_time)));
              add = TRUE;
              event = SSH_ENGINE_EVENT_EXPIRED;
            }

          /* Expire the pmtu information which has been received for this
             flow. Reset the MTU to interface MTU. */
          if (c_flow->reverse_pmtu_expire_time != 0 &&
              c_flow->reverse_pmtu_expire_time < current_time)
            {
              SshEngineFlowData tmp_flow;

              SSH_DEBUG(SSH_D_MIDOK,
                        ("Expiring reverse PMTU information for flow %d",
                         (int) flow_index));

              c_flow->reverse_pmtu_expire_time = 0;
              tmp_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
              tmp_flow->reverse_pmtu = 0;
              FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
            }

          if (c_flow->forward_pmtu_expire_time != 0 &&
              c_flow->forward_pmtu_expire_time < current_time)
            {
              SshEngineFlowData tmp_flow;
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Expiring forward PMTU information for flow %d",
                         (int) flow_index));

              c_flow->forward_pmtu_expire_time = 0;
              tmp_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
              tmp_flow->forward_pmtu = 0;
              FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
            }
        }

      /* Do not process this incoming IPsec flow but break out if maximum
         number of transform events is already reached. */
      if (engine->age_callback_trd_events > 0
          && total_num_trd_events > engine->age_callback_trd_events)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Flow %d event rate limited", flow_index));
          break;
        }

      /* Add the flow to the list if we need to do something on it. */
      if (add)
        {
          if (num_to_free >= SSH_ENGINE_AGE_TIMEOUT_MAX_TO_AGE)
            {
              too_many = TRUE;
              break;
            }

          ctx->to_be_freed[num_to_free].flow_generation = generation;
          ctx->to_be_freed[num_to_free].flow_index = flow_index;
          ctx->to_be_freed[num_to_free].trd_index = SSH_IPSEC_INVALID_INDEX;
          ctx->to_be_freed[num_to_free].rule_index = SSH_IPSEC_INVALID_INDEX;
          ctx->to_be_freed[num_to_free].event = event;

          num_to_free++;
        }
    }
  engine->age_callback_next = flow_index;

  /* Check flows that need attention. */
  for (i = 0; i < num_to_free; i++)
    {
      flow_index = ctx->to_be_freed[i].flow_index;
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);

      /* Check if flow has already been freed because of activating
         new outbound SPI and key material for a transform. In such
         case the APPLY rules and any flows created from them may get
         freed. */
      if ((c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0)
        {
          /* Invalidate the slot in the to_be_freed array. */
          ctx->to_be_freed[i].flow_index = SSH_IPSEC_INVALID_INDEX;
          continue;
        }

      /* Extract transform and rule indexes from IPSECINCOMING flows
         and take references to them. */
      if (c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING)
        {
          SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID);
          SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_PRIMARY);

          activate = FALSE;
          add = TRUE;

          d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
          transform_index = d_flow->forward_transform_index;

          c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
          SSH_ASSERT(c_trd != NULL);

          /* Check if other has activated new SPI value and key material
             after an IPsec SA rekey. */
          if (c_trd->control_flags
              & SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE)
            {
              if (ctx->to_be_freed[i].event
                  == SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED)
                {
                  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath,
                                                     transform_index);
                  for (j = 0; j < SSH_ENGINE_REPLAY_WINDOW_WORDS; j++)
                    {
                      if (d_trd->replay_mask[j] != 0
                          || d_trd->replay_offset_low != 0
                          || d_trd->replay_offset_high != 0)
                        {
                          /* Other end has sent us packets with new
                             inbound SPI. */
                          SSH_DEBUG(SSH_D_LOWOK,
                                    ("Remote end has sent IPsec packets with "
                                     "new inbound SPI, activating new "
                                     "outbound SPI for transform 0x%lx",
                                     (unsigned long) transform_index));
                          activate = TRUE;
                          break;
                        }
                    }
                  FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);

                  /* Ignore event while transform is being rekeyed. */
                  if (c_trd->control_flags & SSH_ENGINE_TR_C_REKEY_PENDING)
                    {
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("Transform 0x%lx is being rekeyed, ignoring "
                                 "SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED",
                                 (unsigned long) transform_index));
                      add = FALSE;
                      activate = FALSE;
                    }

                  /* Check if need to send the
                     SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED event. */
                  else if (c_trd->rekeyed_time != 0
                           && (current_time >=
                               (c_trd->rekeyed_time + c_flow->idle_timeout)))
                    {
                      /* Activate and send event. */
                      activate = TRUE;
                    }
                  else if (c_trd->rekeyed_time != 0)
                    {
                      /* Do not yet send event. */
                      add = FALSE;
                    }
                }

              /* In case of kilobyte based lifetime soft event the SA may
                 still have inactive outbound SPI from previous rekey.
                 Activate outbound SPI so that rekey event is sent for
                 the correct SPI value. */
              else if (ctx->to_be_freed[i].event
                       == SSH_ENGINE_EVENT_REKEY_REQUIRED)
                {
                  /* Ignore event while transform is being rekeyed. */
                  if (c_trd->control_flags & SSH_ENGINE_TR_C_REKEY_PENDING)
                    {
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("Transform 0x%lx is being rekeyed, ignoring "
                                 "SSH_ENGINE_EVENT_REKEY_REQUIRED",
                                 (unsigned long) transform_index));
                      add = FALSE;
                      activate = FALSE;
                    }
                  else
                    {
                      activate = TRUE;
                    }
                }
            }

          if (add)
            {
              /* Temporarily increment the reference count of the
                 transform data (trd) and the rule, to make sure the
                 trd or flow does not disappear from under us. */
              SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);

              ctx->to_be_freed[i].trd_index =
                SSH_ENGINE_WRAP_TRD_INDEX(d_flow->forward_transform_index,
                                          c_trd->generation);

              flow_rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
              SSH_ASSERT(flow_rule != NULL);
              SSH_ENGINE_INCREMENT_RULE_REFCNT(flow_rule);
              ctx->to_be_freed[i].rule_index = c_flow->rule_index;
            }
          else
            {
              /* No need to send the SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED
                 event, remove flow from list of interesting flows. */
              ctx->to_be_freed[i].flow_index = SSH_IPSEC_INVALID_INDEX;
              ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
              ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
            }

          FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

          /* Activate new outbound SPI and key material. */
          if (activate)
            ssh_engine_rekey_activate_outbound(engine, transform_index);

          continue;
        }

      /* Handle normal flows. */

      /* Free the flow. */
      SSH_DEBUG(SSH_D_LOWOK, ("age freeing flow %d", (int)flow_index));
      ssh_engine_free_flow(engine, flow_index);

      /* Invalidate the slot in the to_be_freed array. */
      ctx->to_be_freed[i].flow_index = SSH_IPSEC_INVALID_INDEX;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Then handle the incoming IPSEC flows.  This processing is not atomic;
     engine->flow_control_table_lock may be released during the freeing of each
     flow.  The reference that we took above protects the existence of the
     trd and the flow even if we don't hold locks here.  This code must
     release the references on the trd and flow_rule when no longer needed. */
  for (i = 0; i < num_to_free; i++)
    {
      flow_index = ctx->to_be_freed[i].flow_index;

      /* Skip slots that we already freed above. */
      if (flow_index == SSH_IPSEC_INVALID_INDEX)
        continue;

      event = SSH_ENGINE_EVENT_IDLE;

      ssh_kernel_mutex_lock(engine->flow_control_table_lock);

      /* If the transform generation has changed or
         clear_and_delete_trd() has been called, then
         our cached flow is probably not relevant anymore. */
      c_trd = SSH_ENGINE_GET_TRD(engine, ctx->to_be_freed[i].trd_index);
      if (c_trd == NULL
          || (c_trd->control_flags & SSH_ENGINE_TR_C_DELETE_PENDING))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Transform 0x%x already deleted",
                                  (int) ctx->to_be_freed[i].trd_index));
          if (c_trd != NULL)
            {
              ssh_engine_decrement_transform_refcnt(engine,
                                                ctx->to_be_freed[i].trd_index);
              ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
            }
          if (ctx->to_be_freed[i].rule_index != SSH_IPSEC_INVALID_INDEX)
            {
              flow_rule = SSH_ENGINE_GET_RULE(engine,
                                              ctx->to_be_freed[i].rule_index);
              if (flow_rule)
                ssh_engine_decrement_rule_refcnt(engine, flow_rule);
              ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
            }
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;
        }

      /* This must be an incoming IPSEC flow, and we have an extra
         reference on its trd, which also protects the incoming
         flow. */
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
      d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);

      /* Skip any flows that are already free. */
      if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) ||
          (d_flow->generation != ctx->to_be_freed[i].flow_generation))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPsec incoming flow %d has disappeared",
                                 (int) flow_index));
          FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);
          if (c_trd != NULL)
            {
              ssh_engine_decrement_transform_refcnt(engine,
                                                ctx->to_be_freed[i].trd_index);
              ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
            }
          if (ctx->to_be_freed[i].rule_index != SSH_IPSEC_INVALID_INDEX)
            {
              flow_rule = SSH_ENGINE_GET_RULE(engine,
                                              ctx->to_be_freed[i].rule_index);
              if (flow_rule)
                ssh_engine_decrement_rule_refcnt(engine, flow_rule);
              ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
            }
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;
        }
      SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID);
      SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_PRIMARY);
      SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_IPSECINCOMING);

      /* Copy transform data.  Since it is an IPSEC flow, it must have
         one.  This takes the copy without a lock; we protect the
         existence of the trd with a reference, and the fields which
         may change are not critical for the policy manager. */
      transform_index = d_flow->forward_transform_index;
      FASTPATH_RELEASE_FLOW(engine->fastpath, flow_index);

      SSH_ASSERT(transform_index != SSH_IPSEC_INVALID_INDEX);
      SSH_ASSERT(transform_index == ctx->to_be_freed[i].trd_index);
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);

      /* Copy data prior to modification. */
      ctx->tr.control = *c_trd;
      ctx->tr.data = *d_trd;

      SSH_ASSERT(c_flow->rule_index == ctx->to_be_freed[i].rule_index);
      SSH_ASSERT(c_trd != NULL);
      flow_rule = SSH_ENGINE_GET_RULE(engine, c_flow->rule_index);
      SSH_ASSERT(flow_rule != NULL);

      /* Determine the type of the event to send. */
      switch (ctx->to_be_freed[i].event)
        {
        case SSH_ENGINE_EVENT_EXPIRED:
          FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Sending expired event to the policy manager"));
          event = SSH_ENGINE_EVENT_EXPIRED;
          break;

        case SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED:
          FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
          if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REKEYOLD)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Sending rekey inbound invalidated event for "
                         "transform 0x%lx to the policy manager",
                         (unsigned long) transform_index));
              event = SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED;
            }
          else
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Ignoring rekey inbound invalidated event for "
                         "transform 0x%lx",
                         (unsigned long) transform_index));
              ssh_engine_decrement_transform_refcnt(engine, transform_index);
              ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
              ssh_engine_decrement_rule_refcnt(engine, flow_rule);
              ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
              continue;
            }
          break;

        case SSH_ENGINE_EVENT_REKEY_REQUIRED:
          FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
          if (c_flow->rekey_attempts < SSH_ENGINE_MAX_REKEY_ATTEMPTS)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Sending rekey event for transform 0x%lx to the "
                         "policy manager, rekey attempts %d",
                         (unsigned long) transform_index,
                         (int) c_flow->rekey_attempts));
              event = SSH_ENGINE_EVENT_REKEY_REQUIRED;
            }
          else
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Ignoring rekey event for transform 0x%lx, rekey "
                         "attempts %d",
                         (unsigned long) transform_index,
                         (int) c_flow->rekey_attempts));
              ssh_engine_decrement_transform_refcnt(engine, transform_index);
              ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
              ssh_engine_decrement_rule_refcnt(engine, flow_rule);
              ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
              continue;
            }
          break;

        case SSH_ENGINE_EVENT_IDLE:
          if ((c_trd->control_flags & SSH_ENGINE_TR_C_DPD_ENABLED)
              && current_time >= (c_trd->last_in_packet_time + c_flow->metric)
              && d_trd->last_out_packet_time > c_trd->last_in_packet_time
              && c_trd->worry_metric_notified == 0)
            {
              FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Sending idle event for transform 0x%lx to the "
                         "policy manager",
                         (unsigned long) transform_index));
              event = SSH_ENGINE_EVENT_IDLE;

              /* Skip sending idle events for this transform for the next
                 SSH_ENGINE_AGE_IDLE_EVENT_IGNORE_COUNT age timeout rounds. */
              c_trd->worry_metric_notified =
                SSH_ENGINE_AGE_IDLE_EVENT_IGNORE_COUNT;
            }
          else
            {
              FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Ignoring idle event for transform 0x%lx",
                         (unsigned long) transform_index));
              ssh_engine_decrement_transform_refcnt(engine, transform_index);
              ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
              ssh_engine_decrement_rule_refcnt(engine, flow_rule);
              ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
              continue;
            }
          break;

        default:
          SSH_NOTREACHED;
          FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
          ssh_engine_decrement_transform_refcnt(engine, transform_index);
          ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
          ssh_engine_decrement_rule_refcnt(engine, flow_rule);
          ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;
        }

      /* Find a rule referencing this trd as its first trd.  This takes the
         copy without a lock; same comments as above apply here. */

      rule_with_policy_context = NULL;
      rule_without_policy_context = NULL;

      for (rule_index = c_trd->rules; rule_index != SSH_IPSEC_INVALID_INDEX;
           rule_index = rule->trd_next)
        {
          rule = SSH_ENGINE_GET_RULE(engine, rule_index);
          if (rule->transform_index == transform_index)
            {
              /* Consider only APPLY rules which are not appgw slave
                 rules and have a policy context to be potential
                 master rules for a transform. */
              if (rule->policy_context
                  && (rule->type == SSH_ENGINE_RULE_APPLY)
                  && (rule->flags & SSH_PM_ENGINE_RULE_SLAVE) == 0)
                {
                  rule_with_policy_context = rule;
                  break;
                }
              else
                {
                  rule_without_policy_context = rule;
                }
            }
        }
      if (rule_with_policy_context)
        {
          ctx->ruledata = *rule_with_policy_context;
        }
      else if (rule_without_policy_context)
        {
          ctx->ruledata = *rule_without_policy_context;
        }
      else
        {
          memset(&ctx->ruledata, 0, sizeof(ctx->ruledata));
          ctx->ruledata.type = SSH_ENGINE_RULE_NONEXISTENT;
          ctx->ruledata.transform_index = SSH_IPSEC_INVALID_INDEX;
        }

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Send the event to policy manager. */
      success = engine_schedule_transform_event(engine, event,
                                                transform_index, &ctx->tr,
                                                rule_index, &ctx->ruledata,
                                                engine->run_time);

      /* If sending the event failed, we will get here again on the next
         round around the flow table. */
      if (!success)
        {
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
          ssh_engine_decrement_rule_refcnt(engine, flow_rule);
          ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
          ssh_engine_decrement_transform_refcnt(engine, transform_index);
          ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;
        }

      /* Change state according to the event.  Note that we cannot be sure
         here whether the policy manager has already called us in response
         to the event we just sent. */
      switch (event)
        {
        case SSH_ENGINE_EVENT_REKEY_REQUIRED:
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);

          /* If the policy manager has already responded to the request, then
             the flow will have REKEYOLD set. */
          if (!(c_flow->control_flags & SSH_ENGINE_FLOW_C_REKEYOLD))
            {
              c_flow->control_flags |= SSH_ENGINE_FLOW_C_IPSECSOFTSENT;
              c_flow->rekey_attempts++;
            }

          /* Release rule and transform references. */
          ssh_engine_decrement_rule_refcnt(engine, flow_rule);
          ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
          ssh_engine_decrement_transform_refcnt(engine, transform_index);
          ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;

        case SSH_ENGINE_EVENT_EXPIRED:
          /* The transform has expired.  Free all flows and rules
             referencing this flow. */
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);

          /* Remove refcnt to rule before deleting transform */
          ssh_engine_decrement_rule_refcnt(engine, flow_rule);
          ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;

          /* Leave the transform to the list of transforms to be cleared
             later on. The transform refcnt will be released when the
             list is handled. */

          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;

        case SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED:
        case SSH_ENGINE_EVENT_IDLE:
          /* Release rule and transform references. */
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
          ssh_engine_decrement_rule_refcnt(engine, flow_rule);
          ctx->to_be_freed[i].rule_index = SSH_IPSEC_INVALID_INDEX;
          ssh_engine_decrement_transform_refcnt(engine, transform_index);
          ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          continue;

        default:
          ssh_fatal("ssh_engine_age_timeout: bad event type");
        }
    }

  /* Handle EVENT_EXPIRED related clear_and_delete_trd()'s */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (i = 0; i < num_to_free; i++)
    {
      transform_index = ctx->to_be_freed[i].trd_index;
      if (transform_index == SSH_IPSEC_INVALID_INDEX)
        continue;

      SSH_ASSERT(transform_index != SSH_IPSEC_INVALID_INDEX);

      /* Delete all rules and flows refering to the trd. */
      ssh_engine_clear_and_delete_trd(engine, transform_index);

      /* Decrement the reference count of the transform.  This will most
         likely cause it to be deleted. */
      ssh_engine_decrement_transform_refcnt(engine, transform_index);
      ctx->to_be_freed[i].trd_index = SSH_IPSEC_INVALID_INDEX;
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* If there were more flows to free than we had space for, restart now that
     we have freed some. */
  if (too_many)
    goto continue_searching;

  /* Process all transforms waiting for their destroy notification to
     be sent to the policy manager. */
  num_to_free = SSH_ENGINE_AGE_TIMEOUT_MAX_TO_AGE;
  while (num_to_free)
    {
      SshUInt32 unwrapped_index;

      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      if (engine->transform_destroy_notify_list == SSH_IPSEC_INVALID_INDEX)
        {
          /* All transforms processed. */
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          break;
        }

      /* One more transform to notify.  Remove it from the list. */
      unwrapped_index = engine->transform_destroy_notify_list;




      c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, unwrapped_index);
      SSH_ASSERT(c_trd != NULL);
      engine->transform_destroy_notify_list = c_trd->rules;
      if (engine->transform_destroy_notify_list == SSH_IPSEC_INVALID_INDEX)
        engine->transform_destroy_notify_list_tail = SSH_IPSEC_INVALID_INDEX;

      d_trd = FASTPATH_GET_TRD(engine->fastpath, unwrapped_index);

      /* Clear the link field. */
      c_trd->rules = SSH_IPSEC_INVALID_INDEX;

      /* Create the original wrapped index.  The trd's generation is
         already incremented by one so this does the trick. */
      transform_index = SSH_ENGINE_WRAP_TRD_INDEX(unwrapped_index,
                                                  c_trd->generation - 1);

      SSH_DEBUG(SSH_D_MIDOK,
                ("Sending TRD destroy notify: transform_index 0x%lx",
                 (unsigned long) transform_index));

      ctx->tr.data = *d_trd;
      ctx->tr.control = *c_trd;

      FASTPATH_RELEASE_TRD(engine->fastpath, unwrapped_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Send the destroy notification. */
      ssh_engine_transform_event_normalize_spis(&ctx->tr);
      success = engine_schedule_transform_event(engine,
                                                SSH_ENGINE_EVENT_DESTROYED,
                                                transform_index, &ctx->tr,
                                                SSH_IPSEC_INVALID_INDEX,
                                                NULL, engine->run_time);

      /* If sending the event failed, put the transform back to the
         destroy notify list.  Otherwise, put it to the trd
         freelist. */
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      if (success)
        {
          /* Event sent successfully.  Now we can recycle the trd node. */
          d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);
          d_trd->transform = 0;
          FASTPATH_UNINIT_TRD(engine->fastpath, transform_index, d_trd);
          ssh_engine_transform_freelist_put(engine, unwrapped_index);
          num_to_free--;
        }
      else
        {
          /* Put the trd back to the destroy notify list. */
          if (engine->transform_destroy_notify_list == SSH_IPSEC_INVALID_INDEX)
            {
              engine->transform_destroy_notify_list = unwrapped_index;
              engine->transform_destroy_notify_list_tail = unwrapped_index;
            }
          else
            {
              c_trd->rules = engine->transform_destroy_notify_list;
              engine->transform_destroy_notify_list = unwrapped_index;
            }
          /* And stop sending events. */
          num_to_free = 0;
        }
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
    }
  if (engine_undangle_flag)
    ssh_engine_flow_undangle_all(engine);

  /* Mark age callback finished. After this, the age callback context
     must not be used in this function. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Mark age timeout callback not running anymore. */
  engine->age_callback_running = 0;

  /* Mark packet driven call as done */
  engine->age_timeout_pkt_scheduled = 0;

  /* Register next periodic age timeout. */
  if (engine->age_timeout_repetitive)
    {
      SSH_ENGINE_TIME_ADD(engine->age_timeout_sec,
                          engine->age_timeout_usec,
                          (engine->age_callback_interval / 1000000),
                          (engine->age_callback_interval % 1000000),
                          engine->run_time,
                          engine->run_time_usec);

      SSH_DEBUG(SSH_D_LOWOK,
                ("Moving periodic engine age timeout to %lu.%06lus "
                 "at %lu.%06lu",
                 (unsigned long) (engine->age_callback_interval / 1000000),
                 (unsigned long) (engine->age_callback_interval % 1000000),
                 (unsigned long) engine->age_timeout_sec,
                 (unsigned long) engine->age_timeout_usec));

      /* Moving of a timeout from the same timeout is guaranteed to succeed.*/
      SSH_VERIFY(ssh_kernel_timeout_move(0, engine->age_callback_interval,
                                         ssh_engine_age_timeout, engine)
                 == TRUE);
    }

  /* Register next packet or event driven age timeout. */
  else
    {
      SshTime timeout_sec;
      SshUInt32 timeout_usec;

      /* All done if no packet or event driven age timeout is scheduled. */
      if (next_call == ~0
          && engine->age_timeout_sec == 0
          && engine->age_timeout_usec == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Engine age timeout stopped"));
          goto unlock_out;
        }

      /* Check if next event driven timeout is before any previously
         scheduled age timeout. */
      timeout_sec = 0;
      timeout_usec = 0;
      if (next_call != ~0
          && ((engine->age_timeout_sec == 0 && engine->age_timeout_usec == 0)
              || SSH_ENGINE_AGE_TIME_CMP(next_call, 0,
                                         engine->age_timeout_sec,
                                         engine->age_timeout_usec) < 0))
        {
          /* Sanity check next event driven age timeout. */
          if (SSH_ENGINE_AGE_TIME_CMP(next_call, 0,
                                      engine->run_time,
                                      engine->run_time_usec) > 0)
            {
              SSH_ENGINE_TIME_SUB(timeout_sec, timeout_usec,
                                  next_call, 0,
                                  engine->run_time, engine->run_time_usec);
            }
        }
      else
        {
          /* Previously registered age timeout is next. Sanity check it. */
          if (SSH_ENGINE_AGE_TIME_CMP(engine->age_timeout_sec,
                                      engine->age_timeout_usec,
                                      engine->run_time,
                                      engine->run_time_usec) > 0)
            {
              SSH_ENGINE_TIME_SUB(timeout_sec, timeout_usec,
                                  engine->age_timeout_sec,
                                  engine->age_timeout_usec,
                                  engine->run_time, engine->run_time_usec);
            }
        }

      /* Adjust the timeout if it would trigger too soon. */
      if (timeout_sec == 0
          && timeout_usec < SSH_ENGINE_AGE_TIMER_RESOLUTION)
        timeout_usec = SSH_ENGINE_AGE_TIMER_RESOLUTION;

      /* Calculate the absolute time of next age timeout. */
      SSH_ENGINE_TIME_ADD(engine->age_timeout_sec, engine->age_timeout_usec,
                          timeout_sec, timeout_usec,
                          engine->run_time, engine->run_time_usec);

      /* Move the age timeout. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Moving engine age timeout to %lu.%06lus at %lu.%06lu",
                 (unsigned long) timeout_sec,
                 (unsigned long) timeout_usec,
                 (unsigned long) engine->age_timeout_sec,
                 (unsigned long) engine->age_timeout_usec));

      /* Moving of a timeout from the same timeout is guaranteed to succeed.*/
      SSH_VERIFY(ssh_kernel_timeout_move((SshUInt32) timeout_sec, timeout_usec,
                                         ssh_engine_age_timeout, engine)
                 == TRUE);
    }

 unlock_out:
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}

































































































































































