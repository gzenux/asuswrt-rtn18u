/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppIpcpConfig"

#include "sshincludes.h"
#include "sshfsm.h"
#include "sshstream.h"
#include "sshtime.h"
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

/* Forward declarations of IPCP implementation */

static void
ssh_ppp_ipcp_tlu(SshPppState state, void*ctx);

static void
ssh_ppp_ipcp_tld(SshPppState state, void*ctx);

static void
ssh_ppp_ipcp_tlf(SshPppState state, void*ctx);

static void
ssh_ppp_ipcp_destructor(void* ctx);

static
SSH_RODATA
SshPppProtocolInterfaceStruct ssh_ppp_ipcp_protocol_impl =
  {
    "IPCP",

    SSH_PPP_PID_IPCP,

    NULL_FNPTR,
    NULL_FNPTR,

    NULL_FNPTR,
    NULL_FNPTR,

    NULL_FNPTR,
    ssh_ppp_ipcp_tlu,
    ssh_ppp_ipcp_tld,
    NULL_FNPTR,
    ssh_ppp_ipcp_tlf,

    NULL_FNPTR,

    ssh_ppp_ipcp_config_get_option_input,
    ssh_ppp_ipcp_config_get_option_output,

    ssh_ppp_ipcp_config_iter_option_input,
    ssh_ppp_ipcp_config_iter_option_output,

    NULL_FNPTR,

    ssh_ppp_ipcp_destructor
  };

static void
ssh_ppp_ipcp_tlu(SshPppState state, void*ctx)
{
  SSH_PPP_SIGNAL_CB(state, SSH_PPP_SIGNAL_IPCP_UP);
}

static void
ssh_ppp_ipcp_tld(SshPppState state, void*ctx)
{
  SSH_PPP_SIGNAL_CB(state, SSH_PPP_SIGNAL_IPCP_DOWN);
}

static void
ssh_ppp_ipcp_tlf(SshPppState state, void*ctx)
{
  SSH_PPP_SIGNAL_CB(state, SSH_PPP_SIGNAL_IPCP_FAIL);
}

static void
ssh_ppp_ipcp_destructor(void* ctx)
{
  SshIpcpLocal ipcp;

  SSH_DEBUG(SSH_D_MY,("destroying IPCP instance %p",ctx));

  ipcp = (SshIpcpLocal)ctx;

  ssh_ppp_ipcp_config_free(&ipcp->config_input);
  ssh_ppp_ipcp_config_free(&ipcp->config_output);

  ssh_free(ctx);
}

void
ssh_ppp_ipcp_destroy(SshIpcpLocal ipcp)
{
  ssh_ppp_protocol_destroy(ipcp->protocol);
}

SshPppEvents
ssh_ppp_ipcp_get_eventq(SshIpcpLocal rec)
{
  return ssh_ppp_protocol_get_eventq(rec->protocol);
}


SshIpcpLocal
ssh_ppp_ipcp_create(SshPppState state,
                    SshLcpLocal lcp)
{
  SshPppProtocol proto;
  SshIpcpLocal local;
  SshPppEvents evs;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Creating a IPCP machine (size %d)",sizeof(SshIpcpLocalStruct)));

  local = ssh_malloc(sizeof(SshIpcpLocalStruct));

  if (local == NULL)
    return NULL;

  evs = ssh_ppp_thread_get_events(state->ppp_thread);

  proto = ssh_ppp_protocol_create(state,
                                  evs,
                                  lcp->mux_instance,
                                  local,
                                  &ssh_ppp_ipcp_protocol_impl);

  if (proto == NULL)
    {
      ssh_free(local);
      return NULL;
    }

  local->protocol = proto;

  if (ssh_ppp_ipcp_config_init(&local->config_input,3) == FALSE)
    {
      ssh_ppp_protocol_destroy(proto);
      ssh_free(local);
      return NULL;

    }

  if (ssh_ppp_ipcp_config_init_supported(&local->config_output) == FALSE)
    {
      ssh_ppp_ipcp_config_free(&local->config_input);
      ssh_ppp_protocol_destroy(proto);
      ssh_free(local);
      return NULL;
    }

  SSH_DEBUG(SSH_D_MY,("IPCP %p CTX %p", proto, local));

  return local;
}

