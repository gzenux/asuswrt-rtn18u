/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshtimeouts.h"
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

#define SSH_DEBUG_MODULE "SshPppTimer"

static void
ssh_ppp_timer_timeout_cb(void *context)
{
  SshPppTimer timer;

  SSH_ASSERT(context != NULL);

  timer = (SshPppTimer)context;

  SSH_ASSERT(timer->timer_state == SSH_PPP_TIMER_RUNNING);

  timer->timer_state = SSH_PPP_TIMER_TIMEOUT;

  ssh_ppp_thread_wakeup(timer->thread);
}


void
ssh_ppp_timer_set_timeout(SshPppTimer timer, unsigned long secs,
                          unsigned long usecs)
{
  SSH_ASSERT(timer->timer_state != SSH_PPP_TIMER_RUNNING);
  timer->timer_state = SSH_PPP_TIMER_RUNNING;

  ssh_xregister_timeout(secs,usecs,
                        ssh_ppp_timer_timeout_cb,
                        timer);
}

void
ssh_ppp_timer_cancel_timeout(SshPppTimer timer)
{
  if (timer->timer_state == SSH_PPP_TIMER_RUNNING)
    {
      ssh_cancel_timeouts(ssh_ppp_timer_timeout_cb,timer);
      timer->timer_state = SSH_PPP_TIMER_IDLE;
    }
  /* Cancel an already made timeout, because after calling
     cancel_timeout() the caller does not expect to
     receive a timeout after this. */
  if (timer->timer_state == SSH_PPP_TIMER_TIMEOUT)
    timer->timer_state = SSH_PPP_TIMER_IDLE;
}

Boolean
ssh_ppp_timer_check_timeout(SshPppTimer timer)
{
  if (timer->timer_state == SSH_PPP_TIMER_TIMEOUT)
    {
      timer->timer_state = SSH_PPP_TIMER_IDLE;
      return TRUE;
    }
  return FALSE;
}

void
ssh_ppp_timer_destroy(SshPppTimer rec)
{
  SSH_PRECOND(rec != NULL);

  if (rec->timer_state == SSH_PPP_TIMER_RUNNING)
    {
      ssh_ppp_timer_cancel_timeout(rec);
    }
  ssh_free(rec);
}


SshPppTimer
ssh_ppp_timer_create(SshPppThread thread)
{
  SshPppTimer rec;

  rec = (SshPppTimer)ssh_malloc(sizeof(*rec));

  if (rec == NULL)
    return NULL;

  rec->thread = thread;
  rec->timer_state = SSH_PPP_TIMER_IDLE;

  return rec;
}
