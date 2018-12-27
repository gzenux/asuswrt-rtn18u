/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppIoStream"

#include "sshincludes.h"
#include "ssheloop.h"
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
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_io_stream.h"

/*
  This callback is responsible for making sure the FSM thread
  corresponding to the LCP connection is running, if there is
  data available.
*/

static void
ssh_ppp_stream_wakeup(SshPppFlush rec)
{
  int i;
  for (i = 0; i < rec->nprotocols; i++)
    {
      if (rec->protocols[i].thread != NULL)
        {
          ssh_ppp_thread_wakeup(rec->protocols[i].thread);
        }
    }
}

void
ssh_ppp_stream_cb(SshStreamNotification notification,
                  void* pdata)
{
  SshPppFlush rec;

  rec = (SshPppFlush)pdata;

  SSH_ASSERT(rec != NULL);

  switch (notification)
    {
    case SSH_STREAM_INPUT_AVAILABLE:
      ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_INPUT_CB_ACTIVE,FALSE);
      ssh_ppp_stream_wakeup(rec);
      break;

    case SSH_STREAM_CAN_OUTPUT:
      ssh_ppp_flush_set_flag(rec,SSH_PPP_FLUSH_F_OUTPUT_CB_ACTIVE,FALSE);
      ssh_ppp_stream_wakeup(rec);
      break;

    default:
      break;
    }
}

