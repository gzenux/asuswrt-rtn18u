/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Processing audit events in the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_pm_api_marshal.h"

#define SSH_DEBUG_MODULE "SshEngineAudit"

#define SSH_MAX_AUDIT_MESSAGE_SIZE 70000

/* Process audit requests from the policymanager. */
void
ssh_engine_pme_get_audit_events(SshEngine engine, SshUInt32 num_events,
                                SshPmeAuditCB callback,
                                void *callback_context)
{
  SshEngineAuditEvent events, event;
  SshUInt32 i, j, max_events, events_to_send;
  SshUInt32 audit_flags, current_size = 0;
  Boolean more_events = FALSE;

  SSH_ASSERT(callback != NULL_FNPTR);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  audit_flags = engine->audit_flags;
  /* Clear the audit flags. */
  engine->audit_flags = 0;

  max_events = 0;
  for (i = 0; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    {
      /* Compute the maximum number of events to send */
      if (engine->audit_table_tail[i] >= engine->audit_table_head[i])
        {
          max_events +=
            engine->audit_table_tail[i] - engine->audit_table_head[i];
        }
      else
        {
          max_events += engine->audit_table_size -
            (engine->audit_table_head[i]  - engine->audit_table_tail[i]);
        }
    }

  if (max_events > num_events)
    max_events = num_events;

  if (max_events == 0)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, FALSE, audit_flags, 0, NULL, callback_context);
      return;
    }

  events = ssh_calloc(max_events, sizeof(SshEngineAuditEventStruct));
  if (events == NULL)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, FALSE, audit_flags, 0, NULL, callback_context);
      return;
    }

  events_to_send = 0;

  for (i = 0; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    {
      while (engine->audit_table_head[i] != engine->audit_table_tail[i])
        {
          event = &engine->audit_table[i][engine->audit_table_head[i]];

          /* Move ahead in the list. */
          engine->audit_table_head[i]
            = SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_head[i]);

          memcpy((unsigned char *)&events[events_to_send++],
                 event, sizeof(events[0]));
          SSH_ASSERT(events_to_send <= max_events);

          /* Worst case estimate for the encoded size of the event */
          current_size += 2 * sizeof(*event) + event->packet_len;

          if ((events_to_send >= max_events) ||
              (current_size > SSH_MAX_AUDIT_MESSAGE_SIZE))
            goto send_events;
        }
    }

 send_events:

  /* Have we more events available to send to the PM ? */
  for (j = i; j < SSH_ENGINE_NUM_AUDIT_LEVELS; j++)
    {
      if (engine->audit_table_head[j] != engine->audit_table_tail[j])
        {
          more_events = TRUE;
          break;
        }
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Send the audit events to the PM. */
  (*callback)(engine->pm, more_events, audit_flags, events_to_send, events,
              callback_context);

  /* Free any packet data that may have been attached to the audit events. */
  for (i = 0; i < events_to_send; i++)
    {
      event = &events[i];
      if (event->packet)
        ssh_free(event->packet);
    }

  if (events)
    ssh_free(events);

  if (events_to_send)
    SSH_DEBUG(SSH_D_MY, ("Sent %d audit events back to the policymanager",
                         (int) events_to_send));
  return;
}


void ssh_engine_audit_uninit(SshEngine engine)
{
  SshEngineAuditEvent event;
  SshUInt32 i;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (i = 0; i < SSH_ENGINE_NUM_AUDIT_LEVELS; i++)
    {
      while (engine->audit_table_head[i] != engine->audit_table_tail[i])
        {
          event = &engine->audit_table[i][engine->audit_table_head[i]];

          /* Free any packet data associated to this audit event. */
          if (event->packet)
            {
              ssh_free(event->packet);
              event->packet = NULL;
            }

          /* Move ahead in the list. */
          engine->audit_table_head[i]
            = SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_head[i]);
        }
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}



/* Auditing of global events (non-packet related) */
void
engine_audit_event(SshEngine engine, SshAuditEvent event)
{
  SshEngineAuditEvent c;
  SshUInt32 index;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Index to the audit queue to which this audit event should be placed. */
  index = SSH_ENGINE_AUDIT_LEVEL_INFORMATIONAL;
  SSH_ASSERT(index < SSH_ENGINE_NUM_AUDIT_LEVELS);

  if (ssh_engine_audit_rate_limit(engine, index) == TRUE)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Not auditing this event due to rate limiting"));
      engine->audit_flags |= SSH_ENGINE_AUDIT_RATE_LIMITED_EVENT;
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
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
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;
    }
  c = &engine->audit_table[index][engine->audit_table_tail[index]];

  engine->audit_event_id++;

  memset(c, 0, sizeof(*c));
  c->audit_id = engine->audit_event_id;
  c->engine = engine;
  c->event = event;

  /* Move tail pointer ahead one slot. The actual auditing is done when
     the policymanager requests the engine to send it the available audit
     messages. */
  engine->audit_table_tail[index] =
    SSH_ENGINE_AUDIT_RING_INC(engine, engine->audit_table_tail[index]);

  engine_audit_new_event(engine);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return;
}


#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

typedef struct SshEngineAuditPollRequestRec
{
  SshEngine engine;
  SshTimeoutStruct timeout[1];
} *SshEngineAuditPollRequest;

#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
static void engine_audit_request_poll_now(void *context)
{
  SshEngineAuditPollRequest c = context;

  if (!ssh_engine_upcall_timeout(c->engine))
    {
      ssh_free(c);
      return;
    }
  ssh_pm_audit_get_engine_events(c->engine->pm);
  ssh_free(c);
}
#endif /* SSH_PM_AUDIT_REQUESTS_PER_SECOND */

#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

void engine_audit_busy(SshEngine engine)
{
#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
#ifdef SSH_IPSEC_UNIFIED_ADDRESS_SPACE
  SshEngineAuditPollRequest c;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  c = ssh_malloc(sizeof(*c));
  if (c == NULL)
    return;
  c->engine = engine;

  ssh_engine_record_upcall(engine);
  ssh_register_timeout(c->timeout, 0L, 0L,
                       engine_audit_request_poll_now, c);
#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
  ssh_engine_send(engine, FALSE, TRUE,
                  SSH_ENCODE_UINT32((SshUInt32) 0),
                  SSH_ENCODE_CHAR((unsigned int)SSH_EPA_AUDIT_POLL_REQUEST),
                  SSH_ENCODE_UINT32(0),
                  SSH_FORMAT_END);
#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */
#endif /* SSH_PM_AUDIT_REQUESTS_PER_SECOND */
  return;
}

#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
static void engine_audit_request_poll_with_lock(void *context)
{
  SshEngine engine = context;

  engine->audit_timeout_scheduled = 0;

  if (engine->ipm_open == FALSE)
    return;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  engine_audit_busy(engine);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}
#endif /* SSH_PM_AUDIT_REQUESTS_PER_SECOND */

void engine_audit_new_event(SshEngine engine)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
#if SSH_PM_AUDIT_REQUESTS_PER_SECOND == 0
  if (!engine->audit_timeout_scheduled)
    {
      engine->audit_timeout_scheduled = 1;
      ssh_kernel_timeout_register(0L, 200000L,
                                  engine_audit_request_poll_with_lock,
                                  engine);
    }
#endif /* SSH_PM_AUDIT_REQUESTS_PER_SECOND */
}
