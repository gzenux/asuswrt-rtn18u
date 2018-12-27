/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppLcp"

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

#ifdef SSHDIST_EAP
#include "sshppp_eap.h"
#endif /* SSHDIST_EAP */

#include "sshppp_internal.h"
#include "sshppp_timer.h"
#include "sshppp_thread.h"
#include "sshppp_protocol.h"
#include "sshppp_chap.h"
#include "sshppp_lcp_config.h"
#include "sshppp_lcp.h"

/* Forward declarations of LCP implementations of protocol functions */

static void
ssh_ppp_lcp_apply_hldc_config(SshLcpLocal local,
                              SshLcpConfig config,
                              SshPppHldcOptionsStruct *hldc_opts);

static void
ssh_ppp_lcp_apply_input_config(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_apply_output_config(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_default_input_config(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_default_output_config(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_this_layer_delay(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_this_layer_up(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_this_layer_down(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_this_layer_started(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_this_layer_failed(SshPppState state, void *ctx);

static void
ssh_ppp_lcp_protocol_reject(SshPppState state, void *ctx, SshUInt16 pid);

static void
ssh_ppp_lcp_destructor(void *ctx);

static
SSH_RODATA
SshPppProtocolInterfaceStruct ssh_ppp_lcp_protocol_impl =
  {
    "LCP",

    SSH_PPP_PID_LCP,

    ssh_ppp_lcp_default_input_config,
    ssh_ppp_lcp_default_output_config,

    ssh_ppp_lcp_apply_input_config,
    ssh_ppp_lcp_apply_output_config,

    ssh_ppp_lcp_this_layer_delay,
    ssh_ppp_lcp_this_layer_up,
    ssh_ppp_lcp_this_layer_down,
    ssh_ppp_lcp_this_layer_started,
    ssh_ppp_lcp_this_layer_failed,

    ssh_ppp_lcp_protocol_reject,

    ssh_ppp_lcp_config_get_option_input,
    ssh_ppp_lcp_config_get_option_output,
    ssh_ppp_lcp_config_iter_option_input,
    ssh_ppp_lcp_config_iter_option_output,

    NULL_FNPTR,

    ssh_ppp_lcp_destructor
  };


/*
  No actual "separate" data structure is used to represent the information
  present in Protocol Data Units. Instead an "opaque" byte-level
  representation of the actual packet is used, from which the relevant
  information is extracted using appropriate functions. Similarily actual
  packets are "marshalled" (or built) directly from the SshPppState and
  SshLCPLocal instances.

  Note: The "Protocol" field is considered to be part of both the HLDC
  and PPP frames. This is the same convention as used in RFC 1661 and
  RFC 1662.
*/


/* Configure the connection according to the defaults set */

static void
ssh_ppp_lcp_apply_hldc_config(SshLcpLocal local,
                              SshLcpConfig config,
                              SshPppHldcOptionsStruct *hldc_opts)
{
  SshUInt32 val;
  SshPppConfigOption opt;

  /* Handle HLDC options.
     PFC and ACFC are boolean options, check only their status */

  opt = ssh_ppp_lcp_config_get_option(config,
                             SSH_LCP_CONFIG_TYPE_PROTOCOL_FIELD_COMPRESSION);

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {
      SSH_DEBUG(SSH_D_LOWOK,("Config: Enabling PFC"));
      ssh_ppp_flush_set_pfc(hldc_opts, TRUE);
    }

  opt = ssh_ppp_lcp_config_get_option(config,
                  SSH_LCP_CONFIG_TYPE_ADDRESS_AND_CONTROL_FIELD_COMPRESSION);

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {
      SSH_DEBUG(SSH_D_LOWOK,("Config: Enabling ACFC"));
      ssh_ppp_flush_set_acfc(hldc_opts, TRUE);
    }

  opt = ssh_ppp_lcp_config_get_option(config, SSH_LCP_CONFIG_TYPE_ACCM);

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {
      val = ssh_ppp_config_option_int32_get_value(opt);

      SSH_DEBUG(SSH_D_LOWOK,("Config: Setting ACCM to 0x%lx",
                             (unsigned long) val));
      ssh_ppp_flush_accm_set(hldc_opts, val);
    }
}

static Boolean
ssh_ppp_lcp_apply_auth_config(SshPppState state,
                              SshLcpLocal local,
                              SshPppConfigOption opt,
                              SshPppAuthProtocol authp,
                              SshPppAuthMode auth_mode)
{
  SshPppConfigStatus config_status;
  SshPppEvents evs;
  SshUInt32 val;
  SshUInt8 chap_alg;
#ifdef DEBUG_LIGHT
  char *ap ="<null>";
#endif

  config_status = ssh_ppp_config_option_get_status(opt);
  val = ssh_ppp_config_option_auth_get_protocol(opt);

  if (config_status == SSH_PPP_CONFIG_STATUS_ACK)
    {
      evs = ssh_ppp_thread_get_events(state->ppp_thread);
      switch (val)
        {
        case SSH_PPP_PID_CHAP:
          /* Choose protocol based on CHAP algorithm */

          chap_alg = ssh_ppp_config_option_auth_chap_get_algorithm(opt);

          switch (chap_alg)
            {
            case SSH_PPP_CHAP_ALGORITHM_MD5:
              if (ssh_ppp_auth_init_chap(state,
                                         authp,
                                         auth_mode,
                                         evs,
                                         state->link.mux_instance)
                  == FALSE)
                {
                  ssh_ppp_fatal(state);
                  return FALSE;
                }

#ifdef DEBUG_LIGHT
              ap = "CHAP";
#endif
              break;
            case SSH_PPP_CHAP_ALGORITHM_MSCHAPV1:
              if (ssh_ppp_auth_init_mschapv1(state,
                                             authp,
                                             auth_mode,
                                             evs,
                                             state->link.mux_instance)
                  == FALSE)
                {
                  ssh_ppp_fatal(state);
                  return FALSE;
                }
#ifdef DEBUG_LIGHT
              ap = "MS-CHAPv1";
#endif

              break;

            case SSH_PPP_CHAP_ALGORITHM_MSCHAPV2:
              if (ssh_ppp_auth_init_mschapv2(state,
                                             authp,
                                             auth_mode,
                                             evs,
                                             state->link.mux_instance)
                  == FALSE)
                {
                  ssh_ppp_fatal(state);
                  return FALSE;
                }
#ifdef DEBUG_LIGHT
              ap = "MS-CHAPv2";
#endif
              break;
            default:
              ssh_ppp_fatal(state);
              return FALSE;
            }
          break;
#ifdef SSHDIST_EAP
        case SSH_PPP_PID_EAP:
          if (ssh_ppp_auth_init_eap(state,
                                    authp,
                                    auth_mode,
                                    evs,
                                    state->link.mux_instance)
              == FALSE)
            {
              ssh_ppp_fatal(state);
              return FALSE;
            }
#ifdef DEBUG_LIGHT
          ap = "EAP";
#endif
          break;
#endif /* SSHDIST_EAP */
        case SSH_PPP_PID_PAP:
          if (ssh_ppp_auth_init_pap(state,
                                    authp,
                                    auth_mode,
                                    evs,
                                    state->link.mux_instance)
              == FALSE)
            {
              ssh_ppp_fatal(state);
              return FALSE;
            }
#ifdef DEBUG_LIGHT
          ap = "PAP";
#endif

          break;
        }
      SSH_DEBUG(SSH_D_HIGHOK,
                ("authentication %s protocol set to %s",
                 (auth_mode == SSH_PPP_AUTH_AUTHENTICATOR?"server":"client"),
                 ap));

      if (authp->impl != NULL && state->sys_name != NULL)
        {
          if (ssh_ppp_auth_set_name(authp,
                                    state->sys_name,
                                    state->sys_name_length) == FALSE)
            {
              ssh_ppp_fatal(state);
              return FALSE;
            }
        }
    }
  else
    {
      return FALSE;
    }
  return TRUE;
}

static void
ssh_ppp_lcp_apply_input_config(SshPppState state, void *ctx)
{
  SshUInt32 val;
  SshPppConfigOption opt;
  SshLcpLocal local;
  SshPppProtocol rec;
  SshPppConfigStatus config_status;
  SshPppMuxProtocol mux;
  SshPppHldcOptionsStruct *hldc_opts;

  SSH_ASSERT(ctx != NULL);

  local = (SshLcpLocal)ctx;
  rec = local->protocol;

  SSH_DEBUG(SSH_D_MIDOK,("lcp: applying input channel configuration"));

  /* Handle magic number */

  opt = ssh_ppp_lcp_config_get_option_input(state,ctx,
                                            SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER);

  if (opt != NULL)
    {
      val = ssh_ppp_config_option_int32_get_value(opt);
      config_status = ssh_ppp_config_option_get_status(opt);

      if (config_status == SSH_PPP_CONFIG_STATUS_ACK)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Config: Setting input magic number to 0x%lx",
                     (unsigned long) val));
          rec->magic_output = val;
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Config: Setting input magic number to 0"));
          rec->magic_output = 0;
        }
    }

  opt = ssh_ppp_lcp_config_get_option_input(state,ctx,
                                            SSH_LCP_CONFIG_TYPE_MRU);

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {
      val = ssh_ppp_config_option_int32_get_value(opt);
      mux = ssh_ppp_thread_get_mux(local->protocol->ppp_thread);

      ssh_ppp_flush_set_input_mru(mux, val);
    }

  hldc_opts = ssh_ppp_flush_get_input_opts(local->mux_instance);
  ssh_ppp_lcp_apply_hldc_config(ctx, &local->config_input, hldc_opts);

  /* Handle authentication */

  ssh_ppp_auth_uninit(state,&state->link.auth_server);

  opt = ssh_ppp_lcp_config_get_option_input(state, ctx,
                                 SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL);

  if (opt != NULL)
    {
      if (ssh_ppp_lcp_apply_auth_config(state,local,opt,
                                        &state->link.auth_server,
                                        SSH_PPP_AUTH_AUTHENTICATOR)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_HIGHOK,("authentication server not configured"));
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK,("authentication server not configured"));
    }
}

static void
ssh_ppp_lcp_apply_output_config(SshPppState state, void *ctx)
{
  SshUInt32 val;
  SshPppConfigOption opt;
  SshLcpLocal local;
  SshPppProtocol rec;
  SshPppConfigStatus config_status;
  SshPppHldcOptionsStruct *hldc_opts;

  local = (SshLcpLocal)ctx;
  rec = local->protocol;

  SSH_DEBUG(SSH_D_MIDOK,
            ("lcp: applying output channel configuration"));

  opt = ssh_ppp_lcp_config_get_option_output(state,ctx,
                                      SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER);

  if (opt != NULL)
    {
      val = ssh_ppp_config_option_int32_get_value(opt);

      config_status = ssh_ppp_config_option_get_status(opt);

      if (config_status == SSH_PPP_CONFIG_STATUS_ACK)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Config: Setting input magic number to 0x%lx",
                     (unsigned long) val));
          rec->magic_input = val;
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Config: Setting input magic number to 0"));
          rec->magic_input = 0;
        }
    }

  opt = ssh_ppp_lcp_config_get_option_output(state,ctx,
                                             SSH_LCP_CONFIG_TYPE_MRU);

  if (ssh_ppp_config_option_get_status(opt) == SSH_PPP_CONFIG_STATUS_ACK)
    {
      val = ssh_ppp_config_option_int32_get_value(opt);
      ssh_ppp_protocol_set_output_mru(local->protocol,val);
    }

  hldc_opts = ssh_ppp_flush_get_output_opts(local->mux_instance);

  ssh_ppp_lcp_apply_hldc_config(ctx, &local->config_output, hldc_opts);

  /* Initialize authentication protocols here, if required */

  ssh_ppp_auth_uninit(state,&state->link.auth_client);

  opt = ssh_ppp_lcp_config_get_option_output(state, ctx,
                               SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL);

  if (opt != NULL)
    {
      if (ssh_ppp_lcp_apply_auth_config(state,local,opt,
                                        &state->link.auth_client,
                                        SSH_PPP_AUTH_PEER) == FALSE)
        {
          SSH_DEBUG(SSH_D_HIGHOK,("authentication client not configured"));
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK,("authentication client not configured"));
    }
}

static void
ssh_ppp_lcp_default_input_config(SshPppState state, void *ctx)
{
  SshPppHldcOptionsStruct *hldc_opts;
  SshLcpLocal local;
  SshPppMuxProtocol mux;

  local = (SshLcpLocal)ctx;

  SSH_DEBUG(SSH_D_MIDOK,
            ("lcp: setting input channel configuration to default"));

  hldc_opts = ssh_ppp_flush_get_input_opts(local->mux_instance);

  ssh_ppp_flush_set_pfc(hldc_opts,FALSE);
  ssh_ppp_flush_set_acfc(hldc_opts,FALSE);
  ssh_ppp_flush_accm_set(hldc_opts,0xFFFFFFFF);

  mux = ssh_ppp_thread_get_mux(local->protocol->ppp_thread);
  ssh_ppp_flush_set_input_mru(mux, 1500);
}

static void
ssh_ppp_lcp_default_output_config(SshPppState state, void *ctx)
{
  SshPppHldcOptionsStruct *hldc_opts;
  SshLcpLocal local;

  local = (SshLcpLocal)ctx;

  SSH_DEBUG(SSH_D_MIDOK,
            ("lcp: setting output channel configuration to default"));

  hldc_opts = ssh_ppp_flush_get_output_opts(local->mux_instance);

  ssh_ppp_flush_set_pfc(hldc_opts,FALSE);
  ssh_ppp_flush_set_acfc(hldc_opts,FALSE);
  ssh_ppp_flush_accm_set(hldc_opts,0xFFFFFFFF);
  ssh_ppp_protocol_set_output_mru(local->protocol,1500);
}

static void
ssh_ppp_lcp_this_layer_delay(SshPppState state, void *ctx)
{
  ssh_ppp_lcp_up(state);
  SSH_PPP_SIGNAL_CB(state,SSH_PPP_SIGNAL_LCP_UP);
}

static void
ssh_ppp_lcp_this_layer_up(SshPppState state, void *ctx)
{
  ;
}

void
ssh_ppp_lcp_this_layer_down(SshPppState state, void *ctx)
{
  SshLcpLocal local;

  local = (SshLcpLocal)ctx;

  ssh_ppp_flush_filter_all(local->mux_instance);
  ssh_ppp_flush_unfilter(local->mux_instance,SSH_PPP_PID_LCP);

  SSH_PPP_SIGNAL_CB(state,SSH_PPP_SIGNAL_LCP_DOWN);
}

static void
ssh_ppp_lcp_this_layer_started(SshPppState state, void *ctx)
{
  SshLcpLocal local;

  local = (SshLcpLocal)ctx;

  ssh_ppp_flush_filter_all(local->mux_instance);
  ssh_ppp_flush_unfilter(local->mux_instance,SSH_PPP_PID_LCP);
}

static void
ssh_ppp_lcp_this_layer_failed(SshPppState state, void *ctx)
{
  SshLcpLocal local;

  local = (SshLcpLocal)ctx;

  ssh_ppp_flush_filter_all(local->mux_instance);
  ssh_ppp_flush_unfilter(local->mux_instance,SSH_PPP_PID_LCP);

  /* We do not signal an LCP failure, but the main control
     state machine will signal that the PPP session
     has ended. */
}

static void
ssh_ppp_lcp_protocol_reject(SshPppState state, void *ctx, SshUInt16 pid)
{
  SshLcpLocal lcp;

  lcp = (SshLcpLocal)ctx;

  /* Filter the rejected protocol at once so as to not generate
     any excessive traffic */

  if (pid != SSH_PPP_PID_LCP)
    {
      ssh_ppp_flush_filter(lcp->mux_instance,pid);
    }

  if (pid == SSH_PPP_PID_IPCP)
    {
      SSH_DEBUG(SSH_D_MIDOK,("IPCP rejected.. shutting it down"));
      SSH_PPP_SIGNAL_CB(state, SSH_PPP_SIGNAL_IPCP_FAIL);
      ssh_ppp_kill_ipcp(state);
    }

  if (pid == SSH_PPP_PID_CHAP
      || pid == SSH_PPP_PID_PAP
      || pid == SSH_PPP_PID_EAP)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("authentication protocol rejected.. shutting it down"));
      ssh_ppp_kill_auth_protocols(state);
    }
}

/* Clean up LCP stuff */

static void
ssh_ppp_lcp_destructor(void* ctx)
{
  SshLcpLocal lcp;

  SSH_DEBUG(SSH_D_MIDOK,("destroying LCP instance %p",ctx));

  lcp = (SshLcpLocal)ctx;

  ssh_ppp_lcp_config_uninit(&lcp->config_input);
  ssh_ppp_lcp_config_uninit(&lcp->config_output);

  ssh_free(lcp);
}

void
ssh_ppp_lcp_disable(SshLcpLocal lcp)
{
  ssh_ppp_flush_disable(lcp->mux_instance);
}

void
ssh_ppp_lcp_destroy(SshLcpLocal lcp)
{
  ssh_ppp_protocol_destroy(lcp->protocol);
}

SshPppEvents
ssh_ppp_lcp_get_eventq(SshLcpLocal rec)
{
  return ssh_ppp_protocol_get_eventq(rec->protocol);
}

/* Create an LCP instance and hook it into the PPP state */

void*
ssh_ppp_lcp_create(SshPppState state,
                   SshPppFlush flushd)
{
  SshPppProtocol proto;
  SshLcpLocal local;
  SshPppEvents evs;
  SshPppMuxProtocol mux;

  SSH_DEBUG(SSH_D_MIDOK,
            ("Attaching a stream and creating LCP machine"));

  local = ssh_malloc(sizeof(SshLcpLocalStruct));

  if (local == NULL)
    return NULL;

  local->mux_instance = flushd;

  /* Create the mux instance, by default allow only LCP traffic through */

  evs = ssh_ppp_thread_get_events(state->ppp_thread);

  proto = ssh_ppp_protocol_create(state,
                                  evs,
                                  local->mux_instance,
                                  local,
                                  &ssh_ppp_lcp_protocol_impl);

  if (proto == NULL)
    {
      ssh_free(local);
      return NULL;
    }

  local->protocol = proto;

  /* Initialize connections with default configurations */

  if (ssh_ppp_lcp_config_init(&local->config_input, 2) == FALSE)
    {
      ssh_ppp_protocol_destroy(proto);
      ssh_free(local);
      return NULL;
    }

  if (ssh_ppp_lcp_config_init(&local->config_output, 5) == FALSE)
    {
      ssh_ppp_protocol_destroy(proto);
      ssh_ppp_lcp_config_uninit(&local->config_input);
      ssh_free(local);
      return NULL;
    }

  ssh_ppp_lcp_default_input_config(state,local);
  ssh_ppp_lcp_default_output_config(state,local);

  /* Tune mux correctly */

  mux = ssh_ppp_thread_get_mux(local->protocol->ppp_thread);

  ssh_ppp_flush_filter_all(local->mux_instance);
  ssh_ppp_flush_unfilter(local->mux_instance,SSH_PPP_PID_LCP);
  ssh_ppp_flush_set_default_recipient(local->mux_instance, mux);

  /* Set boot delay to approx 1/10 sec */
  ssh_ppp_protocol_set_bootdelay(local->protocol, 100000);

  return local;
}
