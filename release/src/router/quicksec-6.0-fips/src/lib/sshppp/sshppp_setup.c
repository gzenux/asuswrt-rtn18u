/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppSetup"

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
#include "sshppp_ipcp_config.h"
#include "sshppp_ipcp.h"

/* Boot the PPP machine if it is not running.
   This CAN be performed even after it has halted */

void
ssh_ppp_boot(SshPppState state)
{
  SSH_ASSERT(state != NULL);
  SSH_ASSERT(state->ppp_thread != NULL);

  SSH_DEBUG(SSH_D_HIGHOK,("Booting PPP machine"));

  ssh_ppp_thread_boot(state->ppp_thread);
}

SshPppState
ssh_ppp_create(void)
{
  SshPppState state;
  SshFSM fsm;
  SshFSMThread thread;

  SSH_DEBUG(SSH_D_HIGHOK,("Creating a PPP machine"));

  state = ssh_malloc(sizeof(SshPppStateStruct));

  if (state == NULL)
    return NULL;

  fsm = ssh_fsm_create(state);

  if (fsm == NULL)
    {
      ssh_free(state);
      return NULL;
    }

  state->ipcp = NULL;
  state->events_ipcp = NULL;
  state->fsm = fsm;

  thread = ssh_fsm_thread_create(state->fsm, ssh_ppp_dead,
                                 NULL_FNPTR, NULL_FNPTR, NULL);

  if (thread == NULL)
    {
      ssh_free(state);
      ssh_fsm_destroy(fsm);
      return NULL;
    }

  state->ppp_thread = ssh_ppp_thread_create(state,thread, NULL,
                                            "PPP controller");

  if (state->ppp_thread == NULL)
    {
      ssh_fsm_kill_thread(thread);
      ssh_fsm_destroy(fsm);
      ssh_free(state);
      return NULL;
    }

  state->kludge = 0;
  state->cb_mode = 0;
  state->fatal_error = 0;
  state->no_magic_lcp = 0;

  state->no_magic_lcp = 0;
  state->get_server_secret_cb = FALSE;
  state->get_client_secret_cb = FALSE;
  state->sys_name = NULL;
  state->sys_name_length = 0;
  state->ctx = NULL;
  state->signal_cb = NULL_FNPTR;
#ifdef SSHDIST_RADIUS
  state->radius_config = NULL;
#endif /* SSHDIST_RADIUS */

  return state;
}

/* Configure LCP options */

static void
ssh_ppp_lcp_configure_magic(SshPppState gdata,
                            SshLcpLocal lcp,
                            struct SshPppParamsRec *config)
{
  SshPppConfigOption opt;

  if (config->no_magic_lcp)
    {
      opt = ssh_ppp_lcp_config_get_option_input( gdata, lcp,
                                  SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER);
      if (opt != NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("disabling Magic Number negotiation for inbound link"));
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
        }

      opt = ssh_ppp_lcp_config_get_option_output(gdata, lcp,
                                           SSH_LCP_CONFIG_TYPE_MAGIC_NUMBER);
      if (opt != NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("disabling Magic Number negotiation for outbound link"));
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
        }
    }
}

/* Configure the use of CHAP (using MD5) with a suitable preference */

static void
ssh_ppp_lcp_configure_auth(SshPppState gdata,
                           SshLcpLocal lcp,
                           struct SshPppParamsRec *config)
{
  SshUInt8 buf;
  SshPppConfigOption opt;
  struct SshPppLinkRec* link;

  link = &gdata->link;

  /* For the authentication clients, first add both client options
     to the "supported list" in the options and then mark the
     authentications as "acceptable" within those options.

     Then if any authentication type is in use, then set the
     type preference to default, otherwise to reject. */

  opt = &lcp->config_output.authentication_protocol;

#ifndef SSHDIST_EAP
  /* EAP must not be used if it is not included
     int the distribution */
  SSH_ASSERT(config->eap_md5_client == FALSE);
#endif /* SSHDIST_EAP */

  if (config->chap_client == TRUE
      || config->mschapv2_client == TRUE
      || config->mschapv1_client == TRUE
#ifdef SSHDIST_EAP
      || config->eap_md5_client == TRUE



#endif /* SSHDIST_EAP */
      || config->pap_client == TRUE)
    {

      if (config->pap_client)
        {
          ssh_ppp_config_option_auth_set(opt, SSH_PPP_PID_PAP, NULL, 0);
          ssh_ppp_config_option_push(opt);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_PAP);
        }

      if (config->mschapv1_client == TRUE)
        {
          buf = SSH_PPP_CHAP_ALGORITHM_MSCHAPV1;
          ssh_ppp_config_option_auth_set(opt, SSH_PPP_PID_CHAP, &buf, 1);
          ssh_ppp_config_option_push(opt);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_MSCHAPv1);
        }

      if (config->mschapv2_client == TRUE)
        {
          buf = SSH_PPP_CHAP_ALGORITHM_MSCHAPV2;
          ssh_ppp_config_option_auth_set(opt, SSH_PPP_PID_CHAP, &buf, 1);
          ssh_ppp_config_option_push(opt);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_MSCHAPv2);
        }

      if (config->chap_client)
        {
          buf = SSH_PPP_CHAP_ALGORITHM_MD5;
          ssh_ppp_config_option_auth_set(opt,SSH_PPP_PID_CHAP,&buf,1);
          ssh_ppp_config_option_push(opt);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_CHAP);
        }

#ifdef SSHDIST_EAP
      if (config->eap_md5_client



          )
        {
          ssh_ppp_config_option_auth_set(opt,SSH_PPP_PID_EAP,NULL,0);
          ssh_ppp_config_option_push(opt);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_EAP);
        }
#endif /* SSHDIST_EAP */

      ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_DEFAULT);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("rejecting all peer's authentication protocols"));
      ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
    }

  /* For the authentication servers note that the authentication
     type to be proposed is the last one set. If this is not
     acceptable, then a type proposed by the peer, which is
     (as defined via ssh_ppp_config_option_auth_accept())
     is chosen arbitrarily.  */

  opt = &lcp->config_input.authentication_protocol;

#ifndef SSHDIST_EAP
  /* EAP must not be used if it is not included
     int the distribution */
  SSH_ASSERT(config->eap_md5_server == FALSE);
#endif /* SSHDIST_EAP */

  if (config->chap_server == TRUE
      || config->mschapv2_server == TRUE
      || config->mschapv1_server == TRUE
#ifdef SSHDIST_EAP
      || config->eap_md5_server == TRUE



#endif /* SSHDIST_EAP */
      || config->pap_server == TRUE)
    {

      if (config->pap_server == TRUE)
        {
          ssh_ppp_config_option_auth_set(opt, SSH_PPP_PID_PAP,NULL,0);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_PAP);
        }

      if (config->mschapv1_server == TRUE)
        {
          buf = SSH_PPP_CHAP_ALGORITHM_MSCHAPV1;
          ssh_ppp_config_option_auth_set(opt,SSH_PPP_PID_CHAP,&buf,1);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_MSCHAPv1);
        }

      if (config->mschapv2_server == TRUE)
        {
          buf = SSH_PPP_CHAP_ALGORITHM_MSCHAPV2;
          ssh_ppp_config_option_auth_set(opt,SSH_PPP_PID_CHAP,&buf,1);
          ssh_ppp_config_option_auth_accept(opt,SSH_PPP_AUTH_MSCHAPv2);
        }

      if (config->chap_server == TRUE)
        {
          buf = SSH_PPP_CHAP_ALGORITHM_MD5;
          ssh_ppp_config_option_auth_set(opt,SSH_PPP_PID_CHAP,&buf,1);
          ssh_ppp_config_option_auth_accept(opt, SSH_PPP_AUTH_CHAP);
        }


#ifdef SSHDIST_EAP
      if (config->eap_md5_server == TRUE



          )
        {
          ssh_ppp_config_option_auth_set(opt,
                                         SSH_PPP_PID_EAP,NULL,0);

          ssh_ppp_config_option_auth_accept(opt, SSH_PPP_AUTH_EAP);
        }
#endif /* SSHDIST_EAP */

      ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_MANDATORY);

      SSH_DEBUG(SSH_D_MIDOK,("requiring authentication of client"));

      link->server_auth_required = TRUE;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,("no authentication of peer required"));
      ssh_ppp_config_preference_set(opt,
                                    SSH_PPP_CONFIG_PREF_REJECT);
      link->server_auth_required = FALSE;
    }
}

static void
ssh_ppp_config_link_boolean_opt(SshPppConfigOption opt, Boolean val)
{
  if (opt != NULL)
    {

      if (val == FALSE)
        {
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
        }

      if (val != FALSE)
        {
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);
          ssh_ppp_config_option_set_value_status(opt, SSH_PPP_CONFIG_VAL_SET);
        }
    }
}

static void
ssh_ppp_lcp_config_link(SshPppState gdata,
                        SshLcpLocal lcp,
                        struct SshPppParamsRec *config)
{
  SshPppConfigOption opt;
  SshUInt8 link_opt_val;

  link_opt_val = (SshUInt8)(config->pppoe_framing == TRUE ? FALSE : TRUE);

  /* Configure inbound traffic */

  opt = ssh_ppp_lcp_config_get_option_input(gdata, lcp,
                            SSH_LCP_CONFIG_TYPE_PROTOCOL_FIELD_COMPRESSION);
  ssh_ppp_config_link_boolean_opt(opt, link_opt_val);

  opt = ssh_ppp_lcp_config_get_option_input(gdata, lcp,
                  SSH_LCP_CONFIG_TYPE_ADDRESS_AND_CONTROL_FIELD_COMPRESSION);

  ssh_ppp_config_link_boolean_opt(opt, link_opt_val);

  opt = ssh_ppp_lcp_config_get_option_input(gdata, lcp,
                                            SSH_LCP_CONFIG_TYPE_ACCM);

  if (opt != NULL)
    {
      if (config->pppoe_framing == TRUE)
        {
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
        }
      else
        {
          ssh_ppp_config_option_int32_set(opt,0);
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);
        }
    }

  SSH_ASSERT(config->min_input_mru == 0
             || config->max_input_mru
             || config->max_input_mru >= config->min_input_mru);


  opt = ssh_ppp_lcp_config_get_option_input(gdata, lcp,
                                            SSH_LCP_CONFIG_TYPE_MRU);
  if (opt != NULL)
    {
      ssh_ppp_config_option_mru_set_constraint(opt,
                                               config->min_input_mru,
                                               config->max_input_mru);

      ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);

      if (config->max_input_mru != 0)
        {
          ssh_ppp_config_option_int32_set(opt, config->max_input_mru);
        }
      else
        {
          /* For the default value we assume PPP is tunneled within L2TP.
             This means that fragmentation can occurin IPv4
             travelling within PPP or the IPv4 that L2TP is traveling over.

             This default value attempts to optimize so that fragmentation
             occurs at the highest layer, and not at the layer which
             contains the IPsec headers.
          */

          if (config->min_input_mru > 1400)
            {
              ssh_ppp_config_option_int32_set(opt, config->min_input_mru);
            }
          else
            {
              ssh_ppp_config_option_int32_set(opt, 1400);
            }
        }
    }

  /* Configure outbound traffic (negotiated by peer) */

  opt = ssh_ppp_lcp_config_get_option_output(gdata, lcp,
                           SSH_LCP_CONFIG_TYPE_PROTOCOL_FIELD_COMPRESSION);

  ssh_ppp_config_link_boolean_opt(opt, link_opt_val);

  opt = ssh_ppp_lcp_config_get_option_output(gdata, lcp,
                  SSH_LCP_CONFIG_TYPE_ADDRESS_AND_CONTROL_FIELD_COMPRESSION);
  ssh_ppp_config_link_boolean_opt(opt, link_opt_val);

  opt = ssh_ppp_lcp_config_get_option_output(gdata, lcp,
                                             SSH_LCP_CONFIG_TYPE_ACCM);

  if (opt != NULL)
    {
      if (config->pppoe_framing == TRUE)
        {
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
        }
      else
        {
          ssh_ppp_config_option_int32_set(opt,0);
          ssh_ppp_config_option_push(opt);
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);
        }
    }

  SSH_ASSERT(config->min_output_mru == 0
             || config->max_output_mru
             || config->max_output_mru >= config->min_output_mru);

  opt = ssh_ppp_lcp_config_get_option_output(gdata, lcp,
                                             SSH_LCP_CONFIG_TYPE_MRU);
  if (opt != NULL)
    {
      ssh_ppp_config_option_mru_set_constraint(opt,
                                               config->min_output_mru,
                                               config->max_output_mru);

      if (config->max_output_mru != 0)
        {
          ssh_ppp_config_option_int32_set(opt, config->max_output_mru);
          ssh_ppp_config_option_push(opt);
        }

      if (config->min_output_mru != 0)
        {
          ssh_ppp_config_option_int32_set(opt, config->min_output_mru);
          ssh_ppp_config_option_push(opt);
        }

    if ((1400 >= config->min_output_mru || config->min_output_mru == 0)
        && (1400 >= config->max_output_mru || config->max_output_mru == 0))
      {
        ssh_ppp_config_option_int32_set(opt, 1400);
        ssh_ppp_config_option_push(opt);
      }

    if (config->max_output_mru != 0 && config->min_output_mru != 0)
      {
        ssh_ppp_config_option_int32_set(opt,
                        (config->max_output_mru + config->min_output_mru)/2);
        ssh_ppp_config_option_push(opt);
      }
    else
      {
        ssh_ppp_config_option_int32_set(opt, 1500);
        ssh_ppp_config_option_push(opt);
      }
    }
}

static void
ssh_ppp_lcp_configure(SshPppState gdata,
                      SshLcpLocal lcp,
                      SshPppParams config)
{
  /* Reset all option status */
  ssh_ppp_protocol_options_reset(gdata, lcp->protocol);

  /* Re-configure */
  ssh_ppp_lcp_config_link(gdata,lcp,config);

  /* Disable the use of MAGIC in LCP if requested */
  ssh_ppp_lcp_configure_magic(gdata, lcp, config);

  /* Configure authentication */
  ssh_ppp_lcp_configure_auth(gdata, lcp, config);
}

/* Configure negotiation of DNS and NBNS servers for IPCP */

static void
ssh_ppp_ipcp_configure_own_rfc1877(SshPppState ppp,
                                   SshIpcpLocal ipcp,
                                   SshPppParams config,
                                   SshUInt8 type,
                                   SshIpAddr  p)
{
  SshPppConfigOption opt;

  opt = ssh_ppp_ipcp_config_get_option_input(ppp, ipcp, type);

  if (opt != NULL)
    {
      ssh_ppp_config_option_ipv4_set_constraint(opt, 0, 0);

      if (SSH_IP_IS4(p))
        {
          ssh_ppp_config_option_ipv4_set_ip(opt, SSH_IP4_TO_INT(p));
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);
        }
    }
}

static void
ssh_ppp_ipcp_configure_peer_rfc1877(SshPppState ppp,
                                    SshIpcpLocal ipcp,
                                    SshPppParams config,
                                    SshUInt8 type,
                                    SshIpAddr p)
{
  SshPppConfigOption opt;

  opt = ssh_ppp_ipcp_config_get_option_output(ppp, ipcp, type);

  if (opt != NULL)
    {
      if (SSH_IP_IS4(p))
        {

          ssh_ppp_config_option_ipv4_set_ip(opt, SSH_IP4_TO_INT(p));

          ssh_ppp_config_option_ipv4_set_constraint(opt,
                                                    SSH_IP4_TO_INT(p),
                                                    0xFFFFFFFF);

          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_PREFER);

          ssh_ppp_config_option_push(opt);
        }
      else
        {
          ssh_ppp_config_preference_set(opt,SSH_PPP_CONFIG_PREF_REJECT);
        }
    }
}

static void
ssh_ppp_ipcp_configure_rfc1877(SshPppState ppp,
                               SshIpcpLocal ipcp,
                               SshPppParams config)
{
  ssh_ppp_ipcp_configure_own_rfc1877(ppp, ipcp, config,
                                     SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY,
                                     &config->own_dns_primary);

  ssh_ppp_ipcp_configure_own_rfc1877(ppp, ipcp, config,
                                     SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY,
                                     &config->own_dns_secondary);

  ssh_ppp_ipcp_configure_own_rfc1877(ppp, ipcp, config,
                                     SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY,
                                     &config->own_nbns_primary);

  ssh_ppp_ipcp_configure_own_rfc1877(ppp, ipcp, config,
                                     SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY,
                                     &config->own_nbns_secondary);

  ssh_ppp_ipcp_configure_peer_rfc1877(ppp, ipcp, config,
                                      SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY,
                                      &config->peer_dns_primary);

  ssh_ppp_ipcp_configure_peer_rfc1877(ppp, ipcp, config,
                                      SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY,
                                      &config->peer_dns_secondary);

  ssh_ppp_ipcp_configure_peer_rfc1877(ppp, ipcp, config,
                                      SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY,
                                      &config->peer_nbns_primary);

  ssh_ppp_ipcp_configure_peer_rfc1877(ppp, ipcp, config,
                                      SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY,
                                      &config->peer_nbns_secondary);
}

/* Configure the negotiation of IP addresses for IPCP */

static void
ssh_ppp_ipcp_configure_ips(SshPppState gdata,
                           SshIpcpLocal ipcp,
                           struct SshPppParamsRec *config)
{
  SshPppConfigOption opt;
  SshUInt32 val,val2;

  ssh_ppp_protocol_options_reset(gdata, ipcp->protocol);

  /*
     Notes on configuration of peer IP:

     - If only peer_ipv4_addr is set, then if the peer proposes
       a complete invalid address (0.0.0.0, or 255.255.255.255)
       then this address will be provided via a NAK.

     - If a constraint is defined, then if the peer proposes
       an invalid address (as per the constraint), then the
       defined peer_ipv4_addr will be NAK'd.

     - If confirm_only_ip is not set, then if the peer does
       not propose an address acceptable (any address satisfying
       the defined constraint, or anything besides 0.0.0.0 and
       255.255.255.255 in case a constraint is not defined) including
       not proposany an address, then the instance will reply with a
       NAK.

     - If peer_ipv4_addr is undefined and a proposal would be NAK'd,
       then the IP parameter is actually rejected.
  */

  opt = ssh_ppp_ipcp_config_get_option(&ipcp->config_output,
                                       SSH_IPCP_CONFIG_TYPE_IP_ADDRESS);

  SSH_ASSERT(opt != NULL);

  if (SSH_IP_IS4(&config->peer_ipv4_addr))
    {
      val = SSH_IP4_TO_INT(&config->peer_ipv4_addr);

      ssh_ppp_config_option_ipv4_set_ip(opt,val);
      ssh_ppp_config_option_push(opt);

      ssh_ppp_config_preference_set(opt,
                                    SSH_PPP_CONFIG_PREF_PREFER);

    }

  if (SSH_IP_IS4(&config->peer_ipv4_netaddr)
      && SSH_IP_IS4(&config->peer_ipv4_mask))
    {

      val = SSH_IP4_TO_INT(&config->peer_ipv4_netaddr);
      val2 = SSH_IP4_TO_INT(&config->peer_ipv4_mask);
      ssh_ppp_config_option_ipv4_set_constraint(opt,val,val2);

      if (!config->only_confirm_ip
          && SSH_IP_IS4(&config->peer_ipv4_addr))
        {
          ssh_ppp_config_preference_set(opt,
                                        SSH_PPP_CONFIG_PREF_MANDATORY);
        }
    }

  opt = ssh_ppp_ipcp_config_get_option(&ipcp->config_input,
                                       SSH_IPCP_CONFIG_TYPE_IP_ADDRESS);

  SSH_ASSERT(opt != NULL);

  if (SSH_IP_IS4(&config->own_ipv4_addr))
    {
      SshUInt32 addr = SSH_IP4_TO_INT(&config->own_ipv4_addr);
      ssh_ppp_config_option_ipv4_set_ip(opt,addr);


      ssh_ppp_config_preference_set(opt,
                                    SSH_PPP_CONFIG_PREF_MANDATORY);

      if (config->query_without_ip)
        {
          ssh_ppp_config_preference_set(opt,
                                        SSH_PPP_CONFIG_PREF_DEFAULT);
        }
    }

  if (SSH_IP_IS4(&config->own_ipv4_netaddr)
      && SSH_IP_IS4(&config->own_ipv4_mask))
    {
      val = SSH_IP4_TO_INT(&config->own_ipv4_netaddr);
      val2 = SSH_IP4_TO_INT(&config->own_ipv4_mask);

      ssh_ppp_config_option_ipv4_set_constraint(opt,val,val2);
    }

  ssh_ppp_ipcp_configure_rfc1877(gdata, ipcp, config);
}

/* Entry point for input past the SshStream mechanism, in the case
   it is unused */

void
ssh_ppp_frame_input(SshPPPHandle gdata,
                    SshUInt8 *buffer,
                    unsigned long offset,
                    unsigned long len)
{
  struct SshPppLinkRec* link;
  SshPppFlush rec;

  link = &gdata->link;

  SSH_ASSERT(offset < len);

  if (gdata->fatal_error == 1)
    {
      ssh_free(buffer);
      return;
    }

  if (link == NULL)
    {
      ssh_free(buffer);
      return;
    }

  rec = link->mux_instance;

  if (rec == NULL)
    {
      ssh_free(buffer);
      return;
    }

  ssh_ppp_flush_input_frame(gdata, rec,buffer,offset,len);
}

static Boolean
ssh_ppp_use_params(SshPppState gdata, SshPppParams config)
{
  if (gdata->sys_name != NULL)
    {
      ssh_free(gdata->sys_name);
      gdata->sys_name = NULL;
      gdata->sys_name_length = 0;
    }

  if (config->name != NULL)
    {
      gdata->sys_name = ssh_malloc(config->namelen);
      if (gdata->sys_name == NULL)
        return FALSE;

      gdata->sys_name_length = config->namelen;
      memcpy(gdata->sys_name, config->name, config->namelen);
    }

  gdata->get_client_secret_cb = config->get_client_secret_cb;
  gdata->get_server_secret_cb = config->get_server_secret_cb;
  gdata->no_magic_lcp = config->no_magic_lcp;
  gdata->signal_cb = config->signal_cb;
  gdata->ctx = config->ctx;

#ifdef SSHDIST_EAP
  gdata->get_server_eap_token_cb = config->get_server_eap_token_cb;
  gdata->get_client_eap_token_cb = config->get_client_eap_token_cb;
  gdata->eap_server_md5 = (config->eap_md5_server == TRUE?1:0);
  gdata->eap_client_md5 = (config->eap_md5_client == TRUE?1:0);




#endif /* SSHDIST_EAP */

  return TRUE;
}

void
ssh_ppp_free_params(SshPppParams config)
{
  if (config != NULL)
    {
      if (config->name != NULL)
        {
          ssh_free(config->name);
        }
      ssh_free(config);
    }
}
#ifdef SSHDIST_RADIUS
void
ssh_ppp_configure_radius(SshPPPHandle ppp,
                         SshPppRadiusConfiguration config)
{
  SSH_PRECOND(config == NULL || config->client != NULL);
  SSH_PRECOND(config == NULL || config->servers != NULL);

  ppp->radius_config = NULL;

  if (config != NULL)
    ppp->radius_config = config;
}
#endif /* SSHDIST_RADIUS */
/* Create a simple PPP connection over a single
   physical link supporting IPCP, CHAP and LCP */

SshPppState
ssh_ppp_session_create(struct SshPppParamsRec *config)
{
  SshPppState ob;
  SshLcpLocal lcp;
  SshIpcpLocal ipcp;
  SshPppFlush flushd;
  struct SshPppLinkRec *link;
  SshPppEvents evs;

  /* Global state for the PPP connection */

  ob = ssh_ppp_create();

  if (ob == NULL)
    return NULL;

  link = &ob->link;

  if (ssh_ppp_use_params(ob,config) == FALSE)
    {
      ssh_ppp_destroy(ob);
      return NULL;
    }

  /* Create LCP instance and intiailize a SshPPLink struct */

  flushd = ssh_ppp_flush_create(4,
                                config->input_stream,
                                config->output_stream,
                                config->output_frame_cb,
                                config->frame_mode);


  if (flushd == NULL)
    {
      ssh_ppp_destroy(ob);
      return NULL;
    }

  link->mux_instance = flushd;

  lcp = ssh_ppp_lcp_create(ob,flushd);

  if (lcp == NULL)
    {
      ssh_ppp_destroy(ob);
      return NULL;
    }

  /* Configure Link */

  link->lcp = lcp;
  ssh_ppp_auth_init_none(&link->auth_server);
  ssh_ppp_auth_init_none(&link->auth_client);

  link->server_auth_required = FALSE;
  link->client_auth_required = FALSE;

  /* Configure LCP */

  ssh_ppp_lcp_configure(ob, lcp, config);

  evs = ssh_ppp_lcp_get_eventq(lcp);
  link->events_lcp = ssh_ppp_events_attach_output(evs,ob->ppp_thread);

  if (link->events_lcp == NULL)
    {
      ssh_ppp_destroy(ob);
      return NULL;
    }

  /* Create IPCP instance */

  if (config->ipcp)
    {
      ipcp = ssh_ppp_ipcp_create(ob,lcp);
      if (ipcp == NULL)
        {
          ssh_ppp_destroy(ob);
          return NULL;
        }

      ob->ipcp = ipcp;
      evs = ssh_ppp_ipcp_get_eventq(ipcp);
      ob->events_ipcp = ssh_ppp_events_attach_output(evs, ob->ppp_thread);

      if (ob->events_ipcp == NULL)
        {
          ssh_ppp_destroy(ob);
          return NULL;
        }

      ssh_ppp_ipcp_configure_ips(ob,ipcp,config);
    }

  return ob;
}

void
ssh_ppp_renegotiate(SshPPPHandle ppp, SshPppParams config)
{
  SshPppState gdata;
  SshLcpLocal lcp;

  SSH_PRECOND(ppp != NULL);

  gdata = (SshPppState)ppp;

  SSH_DEBUG(SSH_D_HIGHOK,("signaling PPP instance to renegotiate"));

  ssh_ppp_events_flush_input(ssh_ppp_thread_get_cb_inputq(gdata->ppp_thread));

  ssh_ppp_events_signal(ssh_ppp_thread_get_cb_outputq(gdata->ppp_thread),
                        SSH_PPP_EVENT_RENEGOTIATE);

  /* Mark configuration from now on to be invalid, and
     therefore no further UP or OPEN events should be delivered
     with the old configuration. */

  ssh_ppp_invalidate_config(gdata);

  /* Create new configs.. */

  lcp = gdata->link.lcp;

  if (lcp != NULL)
    {
      ssh_ppp_lcp_configure(gdata, lcp, config);
    }

  if (gdata->ipcp != NULL)
    {
      ssh_ppp_ipcp_configure_ips(gdata,gdata->ipcp,config);
    }
}

static void
ssh_ppp_get_ipcp_peer_ipv4_opt(SshPPPHandle ppp,
                               SshUInt8 type,
                               SshIpAddrStruct* p)
{
  SshUInt32 addr;
  SshPppConfigOption opt;
  SshPppConfigStatus config_status;
  SshIPCPConfigOptionValueIPv4Struct* optval;

  SSH_IP_UNDEFINE(p);

  if (ppp->ipcp != NULL)
    {
      opt = ssh_ppp_ipcp_config_get_option_output(ppp, ppp->ipcp, type);

      if (opt != NULL)
        {
          config_status = ssh_ppp_config_option_get_status(opt);
          if (config_status == SSH_PPP_CONFIG_STATUS_ACK)
            {
              optval = ssh_ppp_config_option_get_optionvalue_ipv4(opt);
              addr = optval->host_address;
              SSH_INT_TO_IP4(p, addr);
            }
        }
    }
}

static void
ssh_ppp_get_ipcp_own_ipv4_opt(SshPPPHandle ppp,
                              SshUInt8 type,
                              SshIpAddrStruct* p)
{
  SshUInt32 addr;
  SshPppConfigOption opt;
  SshPppConfigStatus config_status;
  SshIPCPConfigOptionValueIPv4Struct* optval;

  SSH_IP_UNDEFINE(p);

  if (ppp->ipcp != NULL)
    {
      opt = ssh_ppp_ipcp_config_get_option_input(ppp, ppp->ipcp, type);
      if (opt != NULL)
        {
          config_status = ssh_ppp_config_option_get_status(opt);
          if (config_status == SSH_PPP_CONFIG_STATUS_ACK)
            {
              optval = ssh_ppp_config_option_get_optionvalue_ipv4(opt);

              addr = optval->host_address;

              SSH_INT_TO_IP4(p, addr);
            }
        }
    }
}

void
ssh_ppp_get_ipcp_peer_ip(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_peer_ipv4_opt(ppp,
                                 SSH_IPCP_CONFIG_TYPE_IP_ADDRESS,
                                 ip);
}

#ifdef SSHDIST_RADIUS
SshPppRadiusIpStatus
ssh_ppp_get_radius_ip_status(SshPPPHandle ppp)
{
  SshPppConfigOption opt;

  if (ppp->ipcp == NULL)
    return SSH_PPP_RADIUS_IP_STATUS_NONE;

  if (ssh_ppp_ipcp_is_radius(&ppp->ipcp->config_output) == FALSE)
    return SSH_PPP_RADIUS_IP_STATUS_NAS_CONFIGURED;

  opt = ssh_ppp_ipcp_config_get_option(&ppp->ipcp->config_output,
                                       SSH_IPCP_CONFIG_TYPE_IP_ADDRESS);

  if (opt == NULL)
    return SSH_PPP_RADIUS_IP_STATUS_NONE;

  if (ssh_ppp_config_preference_get(opt) == SSH_PPP_CONFIG_PREF_PREFER)
    return SSH_PPP_RADIUS_IP_STATUS_CLIENT_CONFIGURED;

  if (ssh_ppp_config_preference_get(opt) == SSH_PPP_CONFIG_PREF_MANDATORY)
    return SSH_PPP_RADIUS_IP_STATUS_RADIUS_CONFIGURED;

  return SSH_PPP_RADIUS_IP_STATUS_NONE;
}
#endif /* SSHDIST_RADIUS */

void
ssh_ppp_get_ipcp_peer_dns_primary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_peer_ipv4_opt(ppp,
                                 SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY,
                                 ip);
}

void
ssh_ppp_get_ipcp_peer_dns_secondary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_peer_ipv4_opt(ppp,
                                 SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY,
                                 ip);
}

void
ssh_ppp_get_ipcp_peer_nbns_primary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_peer_ipv4_opt(ppp,
                                 SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY,
                                 ip);
}

void
ssh_ppp_get_ipcp_peer_nbns_secondary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_peer_ipv4_opt(ppp,
                                 SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY,
                                 ip);
}

void
ssh_ppp_get_ipcp_own_ip(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_own_ipv4_opt(ppp,
                                SSH_IPCP_CONFIG_TYPE_IP_ADDRESS,
                                ip);
}

void
ssh_ppp_get_ipcp_own_dns_primary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_own_ipv4_opt(ppp,
                                SSH_IPCP_CONFIG_TYPE_DNS_PRIMARY,
                                ip);
}

void
ssh_ppp_get_ipcp_own_dns_secondary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_own_ipv4_opt(ppp,
                                SSH_IPCP_CONFIG_TYPE_DNS_SECONDARY,
                                ip);
}

void
ssh_ppp_get_ipcp_own_nbns_primary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_own_ipv4_opt(ppp,
                                SSH_IPCP_CONFIG_TYPE_NBNS_PRIMARY,
                                ip);
}

void
ssh_ppp_get_ipcp_own_nbns_secondary(SshPPPHandle ppp, SshIpAddr ip)
{
  ssh_ppp_get_ipcp_own_ipv4_opt(ppp,
                                SSH_IPCP_CONFIG_TYPE_NBNS_SECONDARY,
                                ip);
}

SshUInt32
ssh_ppp_get_lcp_input_accm(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  SshPppHldcOptionsStruct* opt;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0xFFFFFFFF;
    }

  opt = ssh_ppp_flush_get_input_opts(lcp->mux_instance);

  SSH_ASSERT(opt != NULL);

  return ssh_ppp_flush_accm_get(opt);
}

int
ssh_ppp_get_lcp_input_pfc(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  SshPppHldcOptionsStruct* opt;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0;
    }

  opt = ssh_ppp_flush_get_input_opts(lcp->mux_instance);

  SSH_ASSERT(opt != NULL);

  return ssh_ppp_flush_get_pfc(opt);
}

int
ssh_ppp_get_lcp_input_acfc(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  SshPppHldcOptionsStruct* opt;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0;
    }

  opt = ssh_ppp_flush_get_input_opts(lcp->mux_instance);

  SSH_ASSERT(opt != NULL);

  return ssh_ppp_flush_get_acfc(opt);
}

unsigned long
ssh_ppp_get_lcp_input_mru(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  unsigned long val;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0;
    }

  val = ssh_ppp_protocol_get_input_mru(lcp->protocol);
  return (val > 1500 ? val : 1500);
}


SshUInt32
ssh_ppp_get_lcp_output_accm(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  SshPppHldcOptionsStruct* opt;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0xFFFFFFFF;
    }

  opt = ssh_ppp_flush_get_output_opts(lcp->mux_instance);

  SSH_ASSERT(opt != NULL);

  return ssh_ppp_flush_accm_get(opt);
}


int
ssh_ppp_get_lcp_output_pfc(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  SshPppHldcOptionsStruct* opt;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0;
    }

  opt = ssh_ppp_flush_get_output_opts(lcp->mux_instance);

  SSH_ASSERT(opt != NULL);

  return ssh_ppp_flush_get_pfc(opt);
}

int
ssh_ppp_get_lcp_output_acfc(SshPPPHandle ppp)
{
  SshLcpLocal lcp;
  SshPppHldcOptionsStruct* opt;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0;
    }

  opt = ssh_ppp_flush_get_output_opts(lcp->mux_instance);

  SSH_ASSERT(opt != NULL);

  return ssh_ppp_flush_get_acfc(opt);
}

unsigned long
ssh_ppp_get_lcp_output_mru(SshPPPHandle ppp)
{
  SshLcpLocal lcp;

  lcp = ppp->link.lcp;

  if (lcp == NULL)
    {
      return 0;
    }

  return ssh_ppp_protocol_get_output_mru(lcp->protocol);
}

static void
ssh_ppp_disable(SshPppState gdata)
{
  struct SshPppLinkRec* link;

  link = &gdata->link;

  if (link->lcp != NULL)
    {
      ssh_ppp_lcp_disable(link->lcp);
    }
}

void
ssh_ppp_destroy(SshPPPHandle ppp)
{
  SshPppState gdata = (SshPppState)ppp;

  if (ppp == NULL)
    return;

#ifdef SSHDIST_RADIUS
  ssh_ppp_configure_radius(ppp, NULL);
#endif /* SSHDIST_RADIUS */

  /* Immediately remove all SshStreams from use,
     so there is no need for further synchronization in
     the destroy operation. */

  ssh_ppp_disable(gdata);

  /* Remove callbacks from use */
  gdata->signal_cb = NULL_FNPTR;

  /* Ok.. we are in callback, we need to fix
     our state to be deterministic.. arrange
     things so we end up in the main PPP
     thread where we can destroy ourself */

  if (gdata->cb_mode == 1)
    {
      SSH_DEBUG(SSH_D_MIDOK,("Signaling PPP machine to destroy itself"));
      ssh_ppp_events_signal(ssh_ppp_thread_get_cb_outputq(gdata->ppp_thread),
                            SSH_PPP_EVENT_DESTROY);
      return;
    }

  /* Get rid of all protocols */

  SSH_DEBUG(SSH_D_MIDOK,
            ("called from outside PPP, tearing PPP instance down now"));

  ssh_ppp_kill_protocols(ppp);

  ssh_fsm_kill_thread(ssh_ppp_thread_get_thread(gdata->ppp_thread));
  ssh_ppp_cleanup(gdata);
}

void
ssh_ppp_halt(SshPPPHandle ppp)
{
  SshPppState gdata = (SshPppState)ppp;
  SshPppEventsInput inq;

  if (ppp == NULL)
    return;

#ifdef SSHDIST_RADIUS
  ssh_ppp_configure_radius(ppp, NULL);
#endif /* SSHDIST_RADIUS */

  SSH_DEBUG(SSH_D_HIGHOK,("signaling PPP instance to halt"));

  if (gdata->cb_mode == 0)
    {
      inq = ssh_ppp_thread_get_cb_inputq(gdata->ppp_thread);
      ssh_ppp_events_flush_input(inq);
    }

  ssh_ppp_events_signal(ssh_ppp_thread_get_cb_outputq(gdata->ppp_thread),
                        SSH_PPP_EVENT_HALT);
}

void
ssh_ppp_forget_secret(SshUInt8* secret,
                      unsigned long secret_length)
{
  if (secret != NULL)
    {
      memset(secret, 0, secret_length);
      ssh_free(secret);
    }
  return;
}

static SshPppAuthProtocol
ssh_ppp_prepare_get(SshPppState gdata, void *auth_ctx)
{
  struct SshPppLinkRec *link;
  SshPppAuthProtocol auth = NULL;

  link = &gdata->link;

  if (auth_ctx == link->auth_server.ctx)
    auth = &link->auth_server;
  else if (auth_ctx == link->auth_client.ctx)
    auth = &link->auth_client;
  else
    SSH_NOTREACHED;

  if (auth == NULL)
    return NULL;

  if (auth->get_secret_cb_state != SSH_PPP_AUTH_SECRET_CB_NONE)
    {
      SSH_DEBUG(SSH_D_MY,
                ("pending authentication request, aborting this call"));
      auth->get_secret_cb_state = SSH_PPP_AUTH_SECRET_CB_REDO;
      return NULL;
    }

  auth->get_secret_cb_state = SSH_PPP_AUTH_SECRET_CB_PENDING;

  return auth;
}

#ifdef SSHDIST_EAP
void
ssh_ppp_get_token(SshPppState gdata,
                  void *auth_ctx,
                  SshPppAuthType auth_type,
                  SshUInt8 auth_protocol,
                  SshEapTokenType token_type,
                  SshUInt8 *buf,
                  unsigned long len)
{
  SshPppAuthProtocol auth;

  auth = ssh_ppp_prepare_get(gdata, auth_ctx);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("requesting token from user"));

  if (auth == NULL)
    return;

  switch (ssh_ppp_auth_get_mode(auth))
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:
      if (gdata->get_server_eap_token_cb != NULL_FNPTR)
        {
          SSH_PPP_CB(gdata,
                     gdata->get_server_eap_token_cb(gdata,
                                                    auth_type,
                                                    auth_protocol,
                                                    token_type,
                                                    gdata->ctx,
                                                    auth_ctx,
                                                    buf,
                                                    len));
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("get_server_eap_token_cb not configured! "
                     "cannot request token"));
          SSH_NOTREACHED;
        }
      break;
    case SSH_PPP_AUTH_PEER:
      if (gdata->get_client_eap_token_cb != NULL_FNPTR)
        {
          SSH_PPP_CB(gdata,
                     gdata->get_client_eap_token_cb(gdata,
                                                    auth_type,
                                                    auth_protocol,
                                                    token_type,
                                                    gdata->ctx,
                                                    auth_ctx,
                                                    buf,len));
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("get_client_eap_token_cb not configured! "
                     "cannot request token"));
          SSH_NOTREACHED;
        }
      break;
    }
}
#endif /* SSHDIST_EAP */

void
ssh_ppp_get_secret(SshPppState gdata,
                   void *auth_ctx,
                   SshPppAuthType auth_type,
                   SshUInt8 *buf,
                   unsigned long len)
{
  SshPppAuthProtocol auth;

  auth = ssh_ppp_prepare_get(gdata, auth_ctx);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("requesting secret from user"));

  if (auth == NULL)
    return;

  switch (ssh_ppp_auth_get_mode(auth))
    {
    case SSH_PPP_AUTH_AUTHENTICATOR:

      if (gdata->get_server_secret_cb != NULL_FNPTR)
        {
          SSH_PPP_CB(gdata,
                     gdata->get_server_secret_cb(gdata,
                                                 auth_type,
                                                 gdata->ctx,
                                                 auth_ctx,
                                                 buf,
                                                 len));
        }
      break;
    case SSH_PPP_AUTH_PEER:
      if (gdata->get_client_secret_cb != NULL_FNPTR)
        {
          SSH_PPP_CB(gdata,
                     gdata->get_client_secret_cb(gdata,
                                                 auth_type,
                                                 gdata->ctx,
                                                 auth_ctx,
                                                 buf,
                                                 len));
        }

      break;
    }
}

void
ssh_ppp_return_secret(SshPPPHandle ppp, void* ctx,
                      SshUInt8 *buf, SshUInt32 length)
{
  SshPppState gdata;
  struct SshPppLinkRec *link;

  SSH_ASSERT(ppp != NULL);
  SSH_ASSERT(ctx != NULL);

  gdata = (SshPPPHandle)ppp;

  link = &gdata->link;

  if (ctx == (void*)link->auth_server.ctx)
    {
      ssh_ppp_auth_return_secret(gdata,&link->auth_server, buf, length);
    }

  if (ctx == (void*)link->auth_client.ctx)
    {
      ssh_ppp_auth_return_secret(gdata,&link->auth_client,buf,length);
    }
}

#ifdef SSHDIST_EAP
void
ssh_ppp_return_token(SshPPPHandle ppp,
                     SshUInt8 eap_type,
                     void *ctx,
                     SshEapToken token)
{
  SshPppState gdata;
  struct SshPppLinkRec *link;

  SSH_ASSERT(ppp != NULL);
  SSH_ASSERT(ctx != NULL);

  gdata = (SshPPPHandle)ppp;

  if (ctx == NULL)
    {
      SSH_NOTREACHED;
      return;
    }

  link = &gdata->link;

  if (ctx == (void*)link->auth_server.ctx)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("returning token to authentication server"));

      ssh_ppp_auth_return_token(gdata,&link->auth_server, eap_type, token);
    }

  if (ctx == (void*)link->auth_client.ctx)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("returning token to authentication client"));

      ssh_ppp_auth_return_token(gdata,&link->auth_client, eap_type, token);
    }
}
#endif /* SSHDIST_EAP */

char*
ssh_ppp_pid_to_string(SshUInt16 pid)
{
  switch (pid)
    {
    case SSH_PPP_PID_IPCP:
      return "IPCP";
    case SSH_PPP_PID_IP:
      return "IP";
    case SSH_PPP_PID_LCP:
      return "LCP";
    case SSH_PPP_PID_PAP:
      return "PAP";
    case SSH_PPP_PID_CHAP:
      return "CHAP";
    case SSH_PPP_PID_EAP:
      return "EAP";
    }
  return "UNKNOWN";
}
