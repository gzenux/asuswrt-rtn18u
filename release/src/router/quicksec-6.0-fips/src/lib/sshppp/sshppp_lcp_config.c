/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppConfig"

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

Boolean
ssh_ppp_lcp_config_init(SshLcpConfig config, SshUInt8 max_iters)
{
  int ok;
  Boolean ret;

  ok = 1;

  ret = ssh_ppp_config_option_init_mru(&config->maximum_receive_unit,
                                       max_iters);
  ok &= ( ret == TRUE ? 1 : 0 );

  ret = ssh_ppp_config_option_init_auth(&config->authentication_protocol,
                                        max_iters);

  ok &= ( ret == TRUE ? 1 : 0 );

  ret = ssh_ppp_config_option_init_accm(&config->accm,max_iters);

  ok &= ( ret == TRUE ? 1 : 0 );

  /* Magic number "is" magical, for it we only need to have one proposition */
   ret = ssh_ppp_config_option_init_magic(&config->magic_number,1);

   ok &= ( ret == TRUE ? 1: 0 );

  /* Boolean variables only need two options in any case */
   ret=ssh_ppp_config_option_init_pfc(&config->protocol_field_compression,
                                      2);

   ok &= ( ret == TRUE ? 1 : 0 );

   ret = ssh_ppp_config_option_init_acfc(
                          &config->address_and_control_field_compression,2);

   ok &= ( ret == TRUE ? 1 : 0 );

   return ( ok ? TRUE : FALSE );
}

/* Here's to hoping the compiler knows how to optimize this into a
   look-up table.
*/

SshPppConfigOption
ssh_ppp_lcp_config_get_option_input(SshPppState state,
                                    void *ctx , SshUInt8 type)
{
  SshPppConfigOption opt;
  opt = ssh_ppp_lcp_config_get_option(&(((SshLcpLocal)ctx)->config_input),
                                      type);
  return opt;
}

SshPppConfigOption
ssh_ppp_lcp_config_get_option_output(SshPppState state,
                                     void *ctx, SshUInt8 type)
{
  SshPppConfigOption opt;

  opt = ssh_ppp_lcp_config_get_option(&(((SshLcpLocal)ctx)->config_output),
                                      type);
  return opt;
}

SshPppConfigOption
ssh_ppp_lcp_config_get_option(SshLcpConfig config, SshUInt8 type)
{
  switch(type)
    {
    case SSH_LCP_CONFIG_TYPE_MRU:
      return &config->maximum_receive_unit;
    case SSH_LCP_CONFIG_TYPE_AUTHENTICATION_PROTOCOL:
      return &config->authentication_protocol;
    case SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER:
      return &config->magic_number;
    case SSH_LCP_CONFIG_TYPE_PROTOCOL_FIELD_COMPRESSION:
      return &config->protocol_field_compression;
    case SSH_LCP_CONFIG_TYPE_ADDRESS_AND_CONTROL_FIELD_COMPRESSION:
      return &config->address_and_control_field_compression;
    case SSH_LCP_CONFIG_TYPE_ACCM:
      return &config->accm;
    }
  return NULL;
}

SshPppConfigOption
ssh_ppp_lcp_config_iter_option_input(SshPppState state, void *ctx , int i)
{
  SshPppConfigOption opt;
  opt = ssh_ppp_lcp_config_iter_option(&(((SshLcpLocal)ctx)->config_input),i);
  return opt;
}

SshPppConfigOption
ssh_ppp_lcp_config_iter_option_output(SshPppState state, void *ctx, int i)

{
  SshPppConfigOption opt;

  opt = ssh_ppp_lcp_config_iter_option(&(((SshLcpLocal)ctx)->config_output),
                                       i);
  return opt;
}


SshPppConfigOption
ssh_ppp_lcp_config_iter_option(SshLcpConfig config, int i)
{
  switch(i) {
  case 0:
    return &config->maximum_receive_unit;
  case 1:
    return &config->authentication_protocol;
  case 2:
    return &config->magic_number;
  case 3:
    return &config->protocol_field_compression;
  case 4:
    return &config->address_and_control_field_compression;
  case 5:
    return &config->accm;

  }
  return NULL;
}

void
ssh_ppp_lcp_config_uninit(SshLcpConfig config)
{
  ssh_ppp_config_option_uninit(&config->accm);

  ssh_ppp_config_option_uninit(
                             &config->address_and_control_field_compression);

  ssh_ppp_config_option_uninit(&config->protocol_field_compression);
  ssh_ppp_config_option_uninit(&config->magic_number);
  ssh_ppp_config_option_uninit(&config->authentication_protocol);
  ssh_ppp_config_option_uninit(&config->maximum_receive_unit);
}

