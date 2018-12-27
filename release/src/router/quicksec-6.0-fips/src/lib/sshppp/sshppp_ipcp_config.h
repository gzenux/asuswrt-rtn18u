/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_IPCP_CONFIG_H

#define SSH_PPP_IPCP_CONFIG_H 1

typedef struct SshIpcpConfigStruct
{
  struct SshPppConfigOptionRec ip;
#ifdef SSHDIST_RADIUS
  struct SshPppConfigOptionRec radius_ip;
#endif /* SSHDIST_RADIUS */
  struct SshPppConfigOptionRec dns_primary;
  struct SshPppConfigOptionRec dns_secondary;
  struct SshPppConfigOptionRec nbns_primary;
  struct SshPppConfigOptionRec nbns_secondary;

#ifdef SSHDIST_RADIUS
  unsigned int use_radius_ip:1;
#endif /* SSHDIST_RADIUS */
} *SshIpcpConfig, SshIpcpConfigStruct;

/* Init the structure */

Boolean
ssh_ppp_ipcp_config_init(SshIpcpConfig ipcp_config, SshUInt8 max_iters);
void ssh_ppp_ipcp_config_free(SshIpcpConfig ipcp_config);

Boolean
ssh_ppp_ipcp_config_init_supported(SshIpcpConfig ipcp_config);

#ifdef SSHDIST_RADIUS
void ssh_ppp_ipcp_use_radius(SshIpcpConfig ipcp_config, Boolean useit);
Boolean ssh_ppp_ipcp_is_radius(SshIpcpConfig ipcp_config);
#endif /* SSHDIST_RADIUS */

/* Misc. utility */

struct SshPppConfigOptionRec*
ssh_ppp_ipcp_config_get_option(SshIpcpConfig ipcp_config,
                               SshUInt8 opt_type);


struct SshPppConfigOptionRec*
ssh_ppp_ipcp_config_iter_option(SshIpcpConfig ipcp_config, int iter_val);


/* Implementation of required SshPppProtocol callbacks */

struct SshPppConfigOptionRec*
ssh_ppp_ipcp_config_get_option_input(SshPppState gdata,
                                     void *ipcp_config,
                                     SshUInt8 opt_type);

struct SshPppConfigOptionRec*
ssh_ppp_ipcp_config_get_option_output(SshPppState gdata,
                                      void *ipcp_config,
                                      SshUInt8 opt_type);

struct SshPppConfigOptionRec*
ssh_ppp_ipcp_config_iter_option_input(SshPppState gdata,
                                      void *ipcp_config,
                                      int opt_type);

struct SshPppConfigOptionRec*
ssh_ppp_ipcp_config_iter_option_output(SshPppState gdata,
                                       void *ipcp_config,
                                       int opt_type);

#endif /* SSH_PPP_IPCP_CONFIG_H */

