/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppEvents"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshbuffer.h"

#ifdef SSHDIST_EAP
#include "ssheap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_linkpkt.h"
#include "sshppp_events.h"
#include "sshppp.h"
#include "sshppp_config.h"
#include "sshppp_flush.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"

static void
ssh_ppp_events_signal_consumption(SshPppEvents evs)
{
  int i;

  for (i = 0; i < evs->num_listeners_output; i++)
    {
      if (evs->listeners_output[i] != NULL)
        {
          ssh_ppp_thread_wakeup(evs->listeners_output[i]);
        }
    }
}

static void
ssh_ppp_events_signal_production(SshPppEvents evs)
{

  if (evs->listener_input != NULL)
    {
      ssh_ppp_thread_wakeup(evs->listener_input);
    }
}

Boolean
ssh_ppp_events_isfull(SshPppEventsOutput out)
{
  SshPppEvents rec;

  if (out == NULL)
    {
      return FALSE;
    }

  rec = (SshPppEvents)out;

  SSH_ASSERT(rec != NULL);
  SSH_ASSERT(rec->reserved_events >= 0);

  return (rec->nevents + rec->reserved_events) == SSH_PPP_EVENT_QUEUE_MAX;
}

Boolean
ssh_ppp_events_isempty(SshPppEventsInput in)
{
  SshPppEvents rec;

  if (in == NULL)
    {
      return TRUE;
    }

  rec = (SshPppEvents)in;

  SSH_ASSERT(rec != NULL);

  return (rec->nevents == 0);
}

void
ssh_ppp_events_flush_output(SshPppEventsOutput out)
{
  ssh_ppp_events_flush_input((SshPppEventsInput)out);
}

void
ssh_ppp_events_flush_input(SshPppEventsInput in)
{
  while ((ssh_ppp_events_get(in)) != SSH_PPP_EVENT_NONE)
    ;
}

void
ssh_ppp_events_signal(SshPppEventsOutput out, SshPppEvent ev)
{
  SshPppEvents rec;
  unsigned long idx;

  if (out == NULL)
    {
      return;
    }

  SSH_ASSERT(!ssh_ppp_events_isfull(out));
  SSH_ASSERT(ev != SSH_PPP_EVENT_NONE);

  rec = (SshPppEvents)out;

  SSH_ASSERT(rec !=  NULL);
  SSH_ASSERT(rec->event_buffer != NULL);

  idx = (rec->event_idx + rec->nevents) % SSH_PPP_EVENT_QUEUE_MAX;

  rec->event_buffer[idx] = ev;
  rec->nevents++;

  ssh_ppp_events_signal_production(rec);
}

SshPppEvent
ssh_ppp_events_peek(SshPppEventsInput in)
{
  SshPppEvents evs;

  evs = (SshPppEvents)in;

  if (evs == NULL)
    {
      return SSH_PPP_EVENT_NONE;
    }

  if (evs->nevents == 0)
    {
      return SSH_PPP_EVENT_NONE;
    }

  return evs->event_buffer[evs->event_idx];
}

SshPppEvent
ssh_ppp_events_get(SshPppEventsInput in)
{
  SshPppEvents rec;
  SshPppEvent ev;

  if (in == NULL)
    {
      return SSH_PPP_EVENT_NONE;
    }

  ev = ssh_ppp_events_peek(in);
  rec = (SshPppEvents)in;

  if (ev != SSH_PPP_EVENT_NONE)
    {
      rec->event_idx = (rec->event_idx + 1) % SSH_PPP_EVENT_QUEUE_MAX;
      rec->nevents--;

      if (rec->nevents == SSH_PPP_EVENT_QUEUE_MAX - 1)
        {
          ssh_ppp_events_signal_consumption(rec);
        }
    }

  return ev;
}

static void
ssh_ppp_events_destroy(SshPppEvents ev)
{
  int i;

  SSH_PRECOND(ev != NULL);

  for (i = 0; i < ev->num_listeners_output; i++)
    {
      if (ev->listeners_output[i] != NULL)
        return;
    }

  if (ev->listener_input != NULL)
    return;


  SSH_DEBUG(SSH_D_MY,("destroying SshPppEvents %p",ev));
  ssh_free(ev->listeners_output);
  ssh_free(ev);
}

void
ssh_ppp_events_detach_input(SshPppEventsInput in,
                            SshPppThread thread)
{
  SshPppEvents rec;

  if (in == NULL || thread == NULL)
    return;

  rec = (SshPppEvents)in;

  SSH_ASSERT(rec->listener_input == thread);

  rec->listener_input = NULL;
  ssh_ppp_events_destroy(rec);
}

void
ssh_ppp_events_detach_output(SshPppEventsOutput out,
                             SshPppThread thread)
{
  SshPppEvents rec;
  int i;

  if (out == NULL || thread == NULL)
    return;

  rec = (SshPppEvents)out;

  for (i = 0; i < rec->num_listeners_output; i++)
    {
      if (rec->listeners_output[i] == thread)
        break;
    }

  SSH_ASSERT(i < rec->num_listeners_output);

  if (i >= rec->num_listeners_output)
    return;

  rec->listeners_output[i] = NULL;
  ssh_ppp_events_destroy(rec);
}

SshPppEventsOutput
ssh_ppp_events_attach_output(SshPppEvents ev,
                             SshPppThread thread)
{
  unsigned long len;
  struct SshPppThreadRec **arr;

  if (ev == NULL)
    return NULL;

  len = sizeof(SshPppThread)*(ev->num_listeners_output+1);

  arr = ssh_malloc(len);

  if (arr == NULL)
    return NULL;

  memcpy(arr,ev->listeners_output,
         ev->num_listeners_output*sizeof(SshPppThread));

  ssh_free(ev->listeners_output);
  ev->listeners_output = arr;

  ev->listeners_output[ev->num_listeners_output++] = thread;

  return (SshPppEventsOutput)ev;
}

SshPppEventsInput
ssh_ppp_events_attach_input(SshPppEvents ev, SshPppThread thread)
{
  if (ev == NULL)
    {
      return NULL;
    }

  SSH_ASSERT(ev->listener_input == NULL);

  ev->listener_input = thread;

  /* This is a a silly hack. As there is only
     one SshPppEventsInput per SshPppEvents,
     we can just use the same handle for the
     SshPppEventsInput and the SshPppEvents
     structures. This does require some care
     when passing the handles, though. */

  return (SshPppEventsInput) ev;
}

SshPppEvents
ssh_ppp_events_create(void)
{
  SshPppEvents rec;

  rec = ssh_malloc(sizeof(*rec));

  if (rec == NULL)
    return NULL;

  rec->event_idx = 0;
  rec->nevents = 0;
  rec->reserved_events = 0;
  rec->listener_input = NULL;
  rec->num_listeners_output = 0;
  rec->listeners_output = NULL;

  SSH_DEBUG(SSH_D_MY,("creating events instance at %p",rec));

  return rec;
}

void
ssh_ppp_events_reserve(SshPppEventsOutput out)
{
  SshPppEvents rec;

  if (out == NULL)
    {
      return;
    }

  rec = (SshPppEvents)out;

  SSH_ASSERT(rec->reserved_events >= 0);

  rec->reserved_events++;

  return;
}

void
ssh_ppp_events_unreserve(SshPppEventsOutput out)
{
  SshPppEvents rec;

  if (out == NULL)
    {
      return;
    }

  rec = (SshPppEvents)out;

  SSH_ASSERT(rec->reserved_events > 0);

  rec->reserved_events--;
  ssh_ppp_events_signal_consumption(rec);

  return;
}

char*
ssh_ppp_event_to_string(SshPppEvent ev)
{
  switch(ev)
    {
    case SSH_PPP_EVENT_NONE: return "NONE";
    case SSH_PPP_EVENT_UP: return "UP";
    case SSH_PPP_EVENT_DOWN: return "DOWN";
    case SSH_PPP_EVENT_OPEN: return "OPEN";
    case SSH_PPP_EVENT_CLOSE: return "CLOSE";
    case SSH_PPP_EVENT_TOPLUS: return "TO+";
    case SSH_PPP_EVENT_TOMINUS: return "TO-";
    case SSH_PPP_EVENT_RCRPLUS: return "RCR+";
    case SSH_PPP_EVENT_RCRMINUS: return "RCR-";
    case SSH_PPP_EVENT_RCA: return "RCA";
    case SSH_PPP_EVENT_RCN: return "RCN";
    case SSH_PPP_EVENT_RTR: return "RTR";
    case SSH_PPP_EVENT_RTA: return "RTA";
    case SSH_PPP_EVENT_RUC: return "RUC";
    case SSH_PPP_EVENT_RXJPLUS: return "RXJ+";
    case SSH_PPP_EVENT_RXJMINUS: return "RXJ-";
    case SSH_PPP_EVENT_RXR: return "RXR";

    case SSH_PPP_EVENT_PENDING: return "PENDING";
    case SSH_PPP_EVENT_FAIL: return "FAIL";

    case SSH_PPP_EVENT_AUTH_OK: return "AUTH OK";
    case SSH_PPP_EVENT_AUTH_PEER_FAIL: return "AUTH PEER FAIL";
    case SSH_PPP_EVENT_AUTH_THIS_FAIL: return "AUTH THIS FAIL";
    case SSH_PPP_EVENT_AUTH_THIS_FAIL_RECHALLENGE:
      return "AUTH FAIL RECHALLENGE";
    case SSH_PPP_EVENT_AUTH_THIS_FAIL_CHANGEPW: return "AUTH FAIL CHANGEPW";
    case SSH_PPP_EVENT_CHALLENGE: return "CHALLENGE";
    case SSH_PPP_EVENT_RESPONSE: return "RESPONSE";
    case SSH_PPP_EVENT_SECRET: return "SECRET";

    case SSH_PPP_EVENT_RESPONSE_RESEND_PLUS: return "RESEND+";
    case SSH_PPP_EVENT_RESPONSE_RESEND_MINUS: return "RESEND-";

    case SSH_PPP_EVENT_BAD_PROTOCOL: return "BAD PROTOCOL";
    case SSH_PPP_EVENT_ISHALT: return "ISHALT";
    case SSH_PPP_EVENT_RCRNEUTRAL: return "RCR NEUTRAL";


    case SSH_PPP_EVENT_DESTROY: return "DESTROY";
    case SSH_PPP_EVENT_HALT: return "HALT";

    case SSH_PPP_EVENT_PROTOCOL_REJECT: return "PROTOCOL REJECT";
    case SSH_PPP_EVENT_IDENTITY_RECV: return "IDENTITY RECV";

    case SSH_PPP_EVENT_SEND_TIME_REMAINING: return "SEND TIME REMAINING";
    case SSH_PPP_EVENT_RECV_TIME_REMAINING: return "RECV TIME REMAINING";

    case SSH_PPP_EVENT_TIMEOUT: return "TIMEOUT";

    case SSH_PPP_EVENT_RENEGOTIATE: return "RENEGOTIATE";
    case SSH_PPP_EVENT_DOWN_UP: return "DOWN-UP";
    case SSH_PPP_EVENT_SUSPENDED: return "SUSPENDED";

    case SSH_PPP_EVENT_FATAL_ERROR: return "FATAL ERROR";
    case SSH_PPP_EVENT_CHANGEPW: return "CHANGEPW";

    }

  SSH_NOTREACHED;

  return "(UNKNOWN EVENT)";
}
