/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppFsm"

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
#include "sshppp_auth.h"
#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"
#include "sshppp_lcp_config.h"
#include "sshppp_lcp.h"
#include "sshppp_ipcp_config.h"
#include "sshppp_ipcp.h"

#define SSH_PPP_TERMINATE(g)                                    \
do {                                                            \
  ssh_ppp_thread_set_next((g)->ppp_thread,ssh_ppp_terminating); \
  return SSH_FSM_CONTINUE;                                      \
} while (0)

#define SSH_PPP_DESTROY(g)                                                \
do {                                                                      \
  ssh_ppp_events_flush_input(                                             \
      ssh_ppp_thread_get_cb_inputq(gdata->ppp_thread));                   \
  ssh_ppp_events_signal(ssh_ppp_thread_get_cb_outputq(gdata->ppp_thread), \
                        SSH_PPP_EVENT_DESTROY);                           \
  ssh_ppp_thread_set_next((g)->ppp_thread,ssh_ppp_grave);                 \
  return SSH_FSM_CONTINUE;                                                \
} while (0)

#define SSH_PPP_FATAL(g)                                        \
do {                                                            \
  ssh_ppp_thread_set_next((g)->ppp_thread,ssh_ppp_fatal_error); \
  return SSH_FSM_CONTINUE;                                      \
} while (0)

/* Do not block if we wish to signal a fatal
   error condition */

#define SSH_PPP_BLOCK_EVENTS(g)                         \
do {                                                    \
  if (gdata->fatal_error == 1)                          \
    {                                                   \
      SSH_PPP_FATAL(g);                                 \
    }                                                   \
  if (ssh_ppp_events_isblock((g)))                      \
    {                                                   \
      SSH_PPP_THREAD_SUSPEND(gdata->ppp_thread);        \
    }                                                   \
} while (0)


static void
ssh_ppp_signal_all_lcp(SshPppState gdata, SshPppEvent ev)
{
  SSH_DEBUG(SSH_D_MIDSTART,("PPP Sending event %d to all LCP's",(ev)));
  ssh_ppp_events_signal(gdata->link.events_lcp,ev);
}

static Boolean
ssh_ppp_events_isblock(SshPppState gdata)
{
  struct SshPppLinkRec* link;

  link = &gdata->link;

  if (link->lcp != NULL && ssh_ppp_events_isfull(link->events_lcp))
    {
      return TRUE;
    }

  if (link->auth_client.events_output != NULL
      && ssh_ppp_events_isfull(link->auth_client.events_output))
    {
      return TRUE;
    }

  if (link->auth_server.events_output != NULL
      && ssh_ppp_events_isfull(link->auth_server.events_output))
    {
      return TRUE;
    }

  if( gdata->events_ipcp != NULL
      && ssh_ppp_events_isfull(gdata->events_ipcp))
    {
      return TRUE;
    }
  return FALSE;
}

static int
ssh_ppp_links_allup(SshPppState state)
{
  SshLcpLocal rec;

  if (state->link.lcp != NULL)
    {
      rec = state->link.lcp;
      if (ssh_ppp_protocol_get_status(rec->protocol) != SSH_PPP_LCP_UP)
        {
          return 0;
        }
    }
  return 1;
}

static void
ssh_ppp_links_boot_all(SshPppState state)
{
  SshLcpLocal rec;

  if (state->link.lcp != NULL)
    {
      rec = state->link.lcp;
      ssh_ppp_protocol_boot(state,rec->protocol);
    }
}


/* Figure out if link is authenticated */

static int
ssh_ppp_lcp_isauth(struct SshPppLinkRec *link)
{
  int i = 1;
  SshPppEvent ev;

  if (link->server_auth_required == TRUE)
    {
      if (link->auth_server.impl != NULL)
        {
          ev = ssh_ppp_auth_get_status(&link->auth_server);
          i &= ( ev == SSH_PPP_EVENT_AUTH_OK ? 1 : 0);
        } else {
          i = 0;
        }
    }

  if (link->client_auth_required == TRUE)
    {
      if (link->auth_client.impl != NULL)
        {
          /* Wait till client authentication phase has ended, either
             successfully or as a failure, but consider both a
             success */

          ev = ssh_ppp_auth_get_status(&link->auth_client);

          if (ev != SSH_PPP_EVENT_AUTH_OK
              && ev != SSH_PPP_EVENT_AUTH_THIS_FAIL)
            i = 0;
        }
      else
        {
          i = 0;
        }
    }

  return i;
}


static int
ssh_ppp_links_allauth(SshPppState state)
{
  if (ssh_ppp_lcp_isauth(&state->link) != 1)
    return 0;

  return 1;
}

static void
ssh_ppp_links_filterall_except_lcp(SshPppState state)
{
  SshLcpLocal rec;

  if (state->link.lcp != NULL)
    {
      rec = state->link.lcp;

      ssh_ppp_flush_filter_all(rec->mux_instance);
      ssh_ppp_flush_unfilter(rec->mux_instance,SSH_PPP_PID_LCP);
    }
  return;
}

static void
ssh_ppp_links_unfilterall(SshPppState state)
{
  SshLcpLocal rec;

  if (state->link.lcp != NULL)
    {
      rec = state->link.lcp;
      ssh_ppp_flush_unfilter_all(rec->mux_instance);
    }
  return;
}

static Boolean
ssh_ppp_links_isnegotiation(SshPppState state)
{
  struct SshPppLinkRec* link;

  link = &state->link;

  if (ssh_ppp_protocol_get_status(link->lcp->protocol) != SSH_PPP_LCP_UP)
    {
      return TRUE;
    }
  return FALSE;
}


/* ssh_ppp_links_findfail() returns a link that has FAILED authentication
   (as opposed to merely not completed it). */

SshLcpLocal
ssh_ppp_links_findfail(SshPppState state)
{
  struct SshPppLinkRec *link;
  SshLcpLocal local;
  SshPppEvent ev;

  link = (struct SshPppLinkRec*)(&state->link);
  if (link->lcp != NULL)
    {
      local = link->lcp;

      if (link->server_auth_required == TRUE)
        {
          if (link->auth_server.impl != NULL)
            {
              ev = ssh_ppp_auth_get_status(&link->auth_server);
              if (ev == SSH_PPP_EVENT_AUTH_PEER_FAIL)
                {
                  SSH_DEBUG(SSH_D_FAIL,("peer has failed authentication"));
                  return local;
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("authentication server not created and we require "
                         "authentication"));
              return local;
            }
        }

    if (link->client_auth_required == TRUE)
      {
        if (link->auth_client.impl == NULL)
          {
            SSH_DEBUG(SSH_D_FAIL,
                      ("error instantiating client-side authentication "
                       "agent"));
            return local;
          }
        else
          {
            ev = ssh_ppp_auth_get_status(&link->auth_client);
            if (ev == SSH_PPP_EVENT_AUTH_PEER_FAIL)
              {
                SSH_DEBUG(SSH_D_FAIL,
                          ("peer has failed authentication"));
                return local;
              }
          }
      }
    }
  return NULL;
}

static void
ssh_ppp_setup_auth(SshPppState state, struct SshPppLinkRec *link)
{
  SshUInt32 val;
  SshPppConfigOption opt;
  SshLcpLocal local;

  SSH_DEBUG(SSH_D_MIDSTART,("configuring authentication phase"));

  local = link->lcp;

  if (local == NULL)
    {
      return;
    }

  opt = ssh_ppp_lcp_config_get_option_input(state,local,
                                SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL);

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {

      val = ssh_ppp_config_option_auth_get_protocol(opt);

      if (val == SSH_PPP_PID_CHAP)
        {
          ssh_ppp_flush_unfilter(local->mux_instance,SSH_PPP_PID_CHAP);
        }

#ifdef SSHDIST_EAP
    if (val == SSH_PPP_PID_EAP)
      {
        ssh_ppp_flush_unfilter(local->mux_instance, SSH_PPP_PID_EAP);
      }
#endif /* SSHDIST_EAP */

    if (val == SSH_PPP_PID_PAP)
      {
        ssh_ppp_flush_unfilter(local->mux_instance, SSH_PPP_PID_PAP);
      }
    }

  opt = ssh_ppp_lcp_config_get_option_output(state,local,
                             SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL);
  SSH_ASSERT(opt != NULL);

  link->client_auth_required = FALSE;

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {

      val = ssh_ppp_config_option_auth_get_protocol(opt);

      if (val == SSH_PPP_PID_CHAP)
        {
          link->client_auth_required = TRUE;
          ssh_ppp_flush_unfilter(local->mux_instance,SSH_PPP_PID_CHAP);
        }

#ifdef SSHDIST_EAP
      if (val == SSH_PPP_PID_EAP)
        {
          link->client_auth_required = TRUE;
          ssh_ppp_flush_unfilter(local->mux_instance, SSH_PPP_PID_EAP);
        }
#endif /* SSHDIST_EAP */

      if (val == SSH_PPP_PID_PAP)
        {
          link->client_auth_required = TRUE;
          ssh_ppp_flush_unfilter(local->mux_instance, SSH_PPP_PID_PAP);
        }
    }
}

void
ssh_ppp_lcp_up(SshPppState gdata)
{
  struct SshPppLinkRec *link;

  link = &gdata->link;
  ssh_ppp_setup_auth(gdata,link);

  if (ssh_ppp_links_allauth(gdata) == 1)
    ssh_ppp_links_unfilterall(gdata);
}

/* "Authentication OK" signals are delayed untill both authentication
   protocols have completed. This is required for the case that both
   peers are running an authentication protocol and at least one of
   the protocols does mutual authentication.

   This function is called directly from the authentication protocols
   (instead of via the main PPP FSM thread) to ensure that
   ssh_ppp_links_unfilterall() is called before any packets
   are processed. */
static void
ssh_ppp_server_commit_auth(SshPppState gdata)
{
  SshPppEvent ev;
  struct SshPppLinkRec *link;

  link = &gdata->link;

  if (ssh_ppp_links_allauth(gdata) == 1)
    ssh_ppp_links_unfilterall(gdata);

  if (link->server_auth_required == TRUE && link->auth_server.impl != NULL)
    {
      ev = ssh_ppp_auth_get_status(&link->auth_server);
      if (ev == SSH_PPP_EVENT_AUTH_OK)
        SSH_PPP_SIGNAL_CB(gdata,SSH_PPP_SIGNAL_SERVER_AUTH_OK);
    }

  if (link->client_auth_required == TRUE && link->auth_client.impl != NULL)
    {
      ev = ssh_ppp_auth_get_status(&link->auth_client);
      if (ev == SSH_PPP_EVENT_AUTH_OK || ev == SSH_PPP_EVENT_AUTH_THIS_FAIL)
        SSH_PPP_SIGNAL_CB(gdata,SSH_PPP_SIGNAL_CLIENT_AUTH_OK);
    }
}

void
ssh_ppp_server_auth_ok(SshPppState gdata)
{
  ssh_ppp_server_commit_auth(gdata);
}

void
ssh_ppp_client_auth_ok(SshPppState gdata)
{
  ssh_ppp_server_commit_auth(gdata);
}

void
ssh_ppp_server_auth_fail(SshPppState gdata)
{
  ssh_ppp_links_filterall_except_lcp(gdata);
  SSH_PPP_SIGNAL_CB(gdata,SSH_PPP_SIGNAL_SERVER_AUTH_FAIL);
}

void
ssh_ppp_client_auth_fail(SshPppState gdata)
{
  SshPppEvent ev;
  struct SshPppLinkRec *link;

  link = &gdata->link;

  SSH_ASSERT(link->auth_client.impl != NULL);

  ev = ssh_ppp_auth_get_status(&link->auth_client);

  if (ev == SSH_PPP_EVENT_AUTH_PEER_FAIL)
    {
      ssh_ppp_links_filterall_except_lcp(gdata);
      SSH_PPP_SIGNAL_CB(gdata,SSH_PPP_SIGNAL_SERVER_AUTH_FAIL);
    }
  else
    {
      SSH_PPP_SIGNAL_CB(gdata,SSH_PPP_SIGNAL_CLIENT_AUTH_FAIL);
    }
}

void
ssh_ppp_kill_ipcp(SshPppState gdata)
{
  if (gdata->ipcp != NULL)
    {
      ssh_ppp_ipcp_destroy(gdata->ipcp);
      ssh_ppp_events_detach_output(gdata->events_ipcp, gdata->ppp_thread);
      gdata->ipcp = NULL;
      gdata->events_ipcp = NULL;
    }
}

void
ssh_ppp_kill_ncp_protocols(SshPPPHandle ppp)
{
  ssh_ppp_kill_ipcp(ppp);
}

void
ssh_ppp_down_ncp_protocols(SshPPPHandle gdata)
{
  SshIpcpLocal ipcp;
  SshPppThread ppp_thread;

  if (gdata->ipcp != NULL)
    {

      ipcp = gdata->ipcp;

      /* Make sure that the next thing the IPCP protocol does is go DOWN. */

      ppp_thread = ssh_ppp_protocol_get_thread(ipcp->protocol);
      ssh_ppp_thread_cancel_current_event(ppp_thread);

      ssh_ppp_events_flush_output(gdata->events_ipcp);
      ssh_ppp_events_signal(gdata->events_ipcp, SSH_PPP_EVENT_DOWN);
    }
}

void
ssh_ppp_kill_auth_protocols(SshPppState gdata)
{
  struct SshPppLinkRec *link;

  link = &gdata->link;

  ssh_ppp_auth_uninit(gdata,&link->auth_server);
  ssh_ppp_auth_uninit(gdata,&link->auth_client);
}

void
ssh_ppp_kill_protocols(SshPppState gdata)
{
  SshLcpLocal rec;

  ssh_ppp_kill_ncp_protocols(gdata);
  ssh_ppp_kill_auth_protocols(gdata);

  rec = gdata->link.lcp;

  if (rec != NULL)
    {
      ssh_ppp_lcp_destroy(rec);
      gdata->link.lcp = NULL;
    }

  ssh_ppp_events_detach_output(gdata->link.events_lcp, gdata->ppp_thread);
  gdata->link.events_lcp = NULL;

  if (gdata->link.mux_instance != NULL)
    {
      ssh_ppp_flush_destroy(gdata->link.mux_instance);
      gdata->link.mux_instance = NULL;
    }
}

void
ssh_ppp_cleanup(SshPppState gdata)
{
  if (gdata->ppp_thread != NULL)
    {
      ssh_ppp_thread_destroy(gdata->ppp_thread);
      gdata->ppp_thread = NULL;
    }

  if (gdata->sys_name != NULL)
    {
      ssh_free(gdata->sys_name);
      gdata->sys_name = NULL;
    }

  ssh_fsm_destroy(gdata->fsm);
  ssh_free(gdata);
}

void
ssh_ppp_invalidate_config(SshPppState gdata)
{
  SshLcpLocal lcp;
  SshIpcpLocal ipcp;

  lcp = gdata->link.lcp;
  ipcp = gdata->ipcp;

  if (lcp != NULL)
    {
      ssh_ppp_protocol_options_invalid_set(lcp->protocol, TRUE);
    }

  if (ipcp != NULL)
    {
      ssh_ppp_protocol_options_invalid_set(ipcp->protocol, TRUE);
    }
}

static void
ssh_ppp_fsm_renegotiate(SshPppState gdata)
{
  /* Destroy authentication protocols */

  ssh_ppp_kill_auth_protocols(gdata);

  /* Inform IPCP that the link is currently unavailable */

  ssh_ppp_down_ncp_protocols(gdata);

  /* Begin filtering packets for all other protocols */

  ssh_ppp_links_filterall_except_lcp(gdata);

  /* Signal all links */

  ssh_ppp_signal_all_lcp(gdata, SSH_PPP_EVENT_DOWN_UP);
}

void
ssh_ppp_fatal(SshPppState gdata)
{
  gdata->fatal_error = 1;

  ssh_ppp_thread_wakeup(gdata->ppp_thread);
}

SSH_FSM_STEP(ssh_ppp_dead)
{
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_HIGHOK,("entering ssh_ppp_dead state"));

  /* Wait till we boot */

  if (gdata->ppp_thread->thread_status != SSH_PPP_RUNNING)
    {
      SSH_PPP_THREAD_SUSPEND(gdata->ppp_thread);
    }

  /* Ok.. send events to all and transition to the next state */

  SSH_PPP_BLOCK_EVENTS(gdata);
  ssh_ppp_signal_all_lcp(gdata,SSH_PPP_EVENT_OPEN);

  ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_waking);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ppp_waking)
{
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_HIGHOK,("entering ssh_ppp_waking state"));

  /* Signal all LCP threads that we are ready to roll */

  SSH_PPP_BLOCK_EVENTS(gdata);
  ssh_ppp_signal_all_lcp(gdata,SSH_PPP_EVENT_UP);

  ssh_ppp_links_boot_all(gdata);
  ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_up);

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ppp_up)
{
  SshPppEvent ev;
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_MIDOK,("entering ssh_ppp_up state"));

  ssh_ppp_thread_enter_state(gdata,gdata->ppp_thread);

  SSH_PPP_BLOCK_EVENTS(gdata);

  ev = ssh_ppp_thread_get_event(gdata, gdata->ppp_thread);

  switch (ev)
    {
    case SSH_PPP_EVENT_FATAL_ERROR:
      SSH_PPP_FATAL(gdata);
      break;

    case SSH_PPP_EVENT_RENEGOTIATE:
      ssh_ppp_fsm_renegotiate(gdata);
      break;

      /* Note that default handles even SSH_PPP_EVENT_NONE */

    default:
    case SSH_PPP_EVENT_UP:
      if (ssh_ppp_links_allup(gdata) == 1)
        {
          ssh_ppp_thread_set_next(gdata->ppp_thread,
                                  ssh_ppp_up_to_authenticate);
        }
      break;

    case SSH_PPP_EVENT_DOWN:
      break;

    case SSH_PPP_EVENT_CLOSE:
    case SSH_PPP_EVENT_HALT:
    case SSH_PPP_EVENT_ISHALT:
    case SSH_PPP_EVENT_PROTOCOL_REJECT:
      SSH_PPP_TERMINATE(gdata);

    case SSH_PPP_EVENT_DESTROY:
      SSH_PPP_DESTROY(gdata);

    }

  return ssh_ppp_thread_leave_state(gdata,gdata->ppp_thread);
}

SSH_FSM_STEP(ssh_ppp_up_to_authenticate)
{
  struct SshPppLinkRec *link;
  SshLcpLocal local;
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_MIDOK,("entering ssh_ppp_up_to_authenticate state"));

  SSH_PPP_BLOCK_EVENTS(gdata);

  /* ssh_ppp_lcp_up() has been called before we get to this phase, /
     now boot the authentication protocols if required */

  link = &gdata->link;
  local = link->lcp;
  if (local != NULL)
    {
      if (link->auth_server.impl != NULL)
        {
          SSH_DEBUG(SSH_D_MIDOK,("signaling authentication protocol server"));

          ssh_ppp_events_signal(link->auth_server.events_output,
                                SSH_PPP_EVENT_OPEN);

          ssh_ppp_auth_boot(&link->auth_server);
        }

      if (link->auth_client.impl != NULL)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("signaling authentication protocol server"));

          ssh_ppp_events_signal(link->auth_client.events_output,
                                SSH_PPP_EVENT_OPEN);
          ssh_ppp_auth_boot(&link->auth_client);
        }
    }

  ssh_ppp_thread_set_next(gdata->ppp_thread, ssh_ppp_authenticate);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ppp_authenticate)
{
  SshPppEvent ev;
  SshLcpLocal local;
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_MIDOK,("entering ssh_ppp_authenticate state"));

  ssh_ppp_thread_enter_state(gdata,
                             gdata->ppp_thread);

  ev = ssh_ppp_thread_get_event(gdata,gdata->ppp_thread);

  /* Eat up all events */
  switch (ev)
    {
    case SSH_PPP_EVENT_FATAL_ERROR:
      SSH_PPP_FATAL(gdata);
      break;

    case SSH_PPP_EVENT_RENEGOTIATE:
      ssh_ppp_fsm_renegotiate(gdata);
      ssh_ppp_thread_set_next(gdata->ppp_thread, ssh_ppp_up);
      break;

    case SSH_PPP_EVENT_HALT:
    case SSH_PPP_EVENT_CLOSE:
    case SSH_PPP_EVENT_ISHALT:
      SSH_PPP_TERMINATE(gdata);

    case SSH_PPP_EVENT_DESTROY:
      SSH_PPP_DESTROY(gdata);

    case SSH_PPP_EVENT_DOWN:
      /* The LCP has oscillated away from an UP state due
         to the peer's being out of synch. Destroy authentication
         protocols, and wait for re-negotiation of link. */

      if (ssh_ppp_links_isnegotiation(gdata))
        {
          /* Do not kill auth protocols here, let LCP configuration do it
             instead to avoid races..*/
          ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_up);
          ssh_ppp_links_filterall_except_lcp(gdata);
          return ssh_ppp_thread_leave_state(gdata, gdata->ppp_thread);
        }
      break;
    }

  /* An authentication failure may also occur if an authentication protocol
     has not been instantiated, and authentication is required. In this
     case an SSH_PPP_EVENT_AUTH_{PEER,THIS}_FAIL event will not be generated.
     Hence this structure */

  local = ssh_ppp_links_findfail(gdata);

  if (local != NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("a link failed the authentication phase, "
                 "terminating connection"));
      ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_terminating);
    }
  else if (ssh_ppp_links_allauth(gdata) == 1)
    {
      /* Authentication may also succeed, if no authentication is
         configured */

      ssh_ppp_links_unfilterall(gdata);
      ssh_ppp_thread_set_next(gdata->ppp_thread,
                              ssh_ppp_authenticate_to_network);

      /* Force us to leave this state without another event arriving */

      ssh_ppp_thread_leave_state(gdata,gdata->ppp_thread);
      return SSH_FSM_CONTINUE;
    }

  return ssh_ppp_thread_leave_state(gdata, gdata->ppp_thread);
}

SSH_FSM_STEP(ssh_ppp_authenticate_to_network)
{
  SshIpcpLocal ipcp;
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_MIDOK,("booting network protocols"));







  ipcp = gdata->ipcp;

  SSH_PPP_BLOCK_EVENTS(gdata);

  if (gdata->kludge == 0 && ipcp != NULL)
    {
      ssh_ppp_events_signal(gdata->events_ipcp,SSH_PPP_EVENT_OPEN);
      gdata->kludge = 1;
    }

  if (gdata->kludge == 1 && ipcp != NULL)
    {
      ssh_ppp_events_signal(gdata->events_ipcp,SSH_PPP_EVENT_UP);
      gdata->kludge = 0;
    }

  if (ipcp != NULL)
    {
      ssh_ppp_protocol_boot(gdata,ipcp->protocol);
    }

  ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_network);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ppp_network)
{
  SshPppEvent ev;
  SSH_FSM_GDATA(SshPppState);

  ssh_ppp_thread_enter_state(gdata,gdata->ppp_thread);

  SSH_DEBUG(SSH_D_HIGHOK,("entering ssh_ppp_network state"));

  ev = ssh_ppp_thread_get_event(gdata,gdata->ppp_thread);

  switch (ev)
    {
    case SSH_PPP_EVENT_FATAL_ERROR:
      SSH_PPP_FATAL(gdata);
      break;

    case SSH_PPP_EVENT_RENEGOTIATE:
      ssh_ppp_fsm_renegotiate(gdata);
      ssh_ppp_thread_set_next(gdata->ppp_thread, ssh_ppp_up);
      break;

    case SSH_PPP_EVENT_PROTOCOL_REJECT:
      /* IPCP or CHAP has been rejected, in either case we are going dow */

      if (gdata->ipcp != NULL && ssh_ppp_links_findfail(gdata) == NULL)
        {
          break;
        }

    case SSH_PPP_EVENT_DOWN:
      if (ssh_ppp_links_isnegotiation(gdata))
        {
          ssh_ppp_kill_auth_protocols(gdata);
          ssh_ppp_links_filterall_except_lcp(gdata);
          ssh_ppp_down_ncp_protocols(gdata);
          ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_up);
        }
      break;

    case SSH_PPP_EVENT_AUTH_PEER_FAIL:

      /* An authentication failed event can be received also here,
         e.g. if the CHAP client fails later on in it's
         lifetime. */
      if (ssh_ppp_links_findfail(gdata) == NULL)
        {
          break;
        }
    case SSH_PPP_EVENT_CLOSE:
    case SSH_PPP_EVENT_HALT:
    case SSH_PPP_EVENT_ISHALT:
      SSH_PPP_TERMINATE(gdata);

    case SSH_PPP_EVENT_DESTROY:
      SSH_PPP_DESTROY(gdata);
    }

  return ssh_ppp_thread_leave_state(gdata,gdata->ppp_thread);
}

SSH_FSM_STEP(ssh_ppp_terminating)
{
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_MIDOK,("PPP session terminating"));

  /* Force all links to only LCP traffic, we are going DOWN. */

  ssh_ppp_links_filterall_except_lcp(gdata);

  SSH_PPP_BLOCK_EVENTS(gdata);
  ssh_ppp_signal_all_lcp(gdata,SSH_PPP_EVENT_CLOSE);

  /* At this point we just tear down all non LCP protocols
     and do the terminate req -> terminate ack for LCP.

     A nicer mechanism of first properly negotiating NCP protocol
     shutdown and then LCP mechanism would add an additional
     round of timeouts in the case the other party is dead
  */

  ssh_ppp_kill_ncp_protocols(gdata);
  ssh_ppp_kill_auth_protocols(gdata);

  ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_terminate);

  return SSH_FSM_CONTINUE;
}

/* The PPP thread waits in this state untill all LCP
   connections have "halted", and then destroys
   all other protocols associated with this
   machine.

   A SshPppState object may not be re-used for
   several connections.
*/

SSH_FSM_STEP(ssh_ppp_terminate)
{
  SshLcpLocal lcp;
  SshPppEvent ev;
  int ok;
  SSH_FSM_GDATA(SshPppState);

  ssh_ppp_thread_enter_state(gdata, gdata->ppp_thread);

  SSH_DEBUG(SSH_D_MIDOK,("entering ssh_ppp_terminate state"));

  ev = ssh_ppp_thread_get_event(gdata,gdata->ppp_thread);
  switch (ev)
    {
    case SSH_PPP_EVENT_DESTROY:
      SSH_PPP_DESTROY(gdata);
    case SSH_PPP_EVENT_FATAL_ERROR:
      SSH_PPP_FATAL(gdata);
    }
  ok = 1;

  if (gdata->link.lcp != NULL)
    {
      lcp = gdata->link.lcp;
      if (ssh_ppp_protocol_get_status(lcp->protocol) == SSH_PPP_LCP_HALT)
        {
          ok &= 1;
        }
      else
        {
          ok = 0;
          SSH_DEBUG(SSH_D_MIDOK,("Waiting for LCP to halt"));
        }
    }

  if (ok == 1)
    {
      SSH_PPP_SIGNAL_CB(gdata,SSH_PPP_SIGNAL_PPP_HALT);
      ssh_ppp_thread_set_next(gdata->ppp_thread,ssh_ppp_grave);
    }

  return ssh_ppp_thread_leave_state(gdata, gdata->ppp_thread);
}

/* The purpose of this state is to merely flush the input queues
   and see if we are supposed to destroy ourselves after
   a HALT.
*/

SSH_FSM_STEP(ssh_ppp_grave)
{
  SshPppEvent ev;
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_HIGHOK,("entering ssh_ppp_grave state"));

  ssh_ppp_thread_enter_state(gdata,gdata->ppp_thread);

  ssh_ppp_kill_protocols(gdata);

  ev = ssh_ppp_thread_get_event(gdata,gdata->ppp_thread);

  switch (ev)
    {
    case SSH_PPP_EVENT_DESTROY:
      ssh_ppp_cleanup(gdata);
      return SSH_FSM_FINISH;
    }

  return ssh_ppp_thread_leave_state(gdata,gdata->ppp_thread);
}

/* Dumb state for enterig when we receive a FATAL signal */

SSH_FSM_STEP(ssh_ppp_fatal_error)
{
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_HIGHOK,("entering ssh_ppp_fatal_error state"));

  SSH_PPP_SIGNAL_CB(gdata, SSH_PPP_SIGNAL_FATAL_ERROR);

  SSH_FSM_SET_NEXT(ssh_ppp_fatal_wait);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(ssh_ppp_fatal_wait)
{
  SshPppEvent ev;
  SSH_FSM_GDATA(SshPppState);

  SSH_DEBUG(SSH_D_HIGHOK,("entering ssh_ppp_fatal_wait state"));

  ssh_ppp_thread_enter_state(gdata, gdata->ppp_thread);

  ev = ssh_ppp_thread_get_event(gdata,gdata->ppp_thread);

  switch (ev)
    {
    case SSH_PPP_EVENT_DESTROY:
      SSH_PPP_DESTROY(gdata);
      break;
    }

  return ssh_ppp_thread_leave_state(gdata, gdata->ppp_thread);
}
