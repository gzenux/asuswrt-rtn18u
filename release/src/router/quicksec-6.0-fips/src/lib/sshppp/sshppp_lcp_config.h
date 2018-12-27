/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_LCP_CONFIG_H

#define SSH_PPP_LCP_CONFIG_H 1

typedef struct SshLcpConfigRec
{
  struct SshPppConfigOptionRec maximum_receive_unit;
  struct SshPppConfigOptionRec authentication_protocol;
  struct SshPppConfigOptionRec magic_number;
  struct SshPppConfigOptionRec protocol_field_compression;
  struct SshPppConfigOptionRec address_and_control_field_compression;
  struct SshPppConfigOptionRec accm;
} *SshLcpConfig, SshLcpConfigStruct;


/* Init structure */

Boolean ssh_ppp_lcp_config_init(SshLcpConfig foo, SshUInt8);
void ssh_ppp_lcp_config_uninit(SshLcpConfig);

/* Misc. Utility */

struct SshPppConfigOptionRec*
ssh_ppp_lcp_config_get_option(SshLcpConfig lcp_config, SshUInt8 type);

struct SshPppConfigOptionRec*
ssh_ppp_lcp_config_iter_option(SshLcpConfig lcp_config, int opt_iter);


/* Implementations of some funcs required by protocol interface */

struct SshPppConfigOptionRec*
ssh_ppp_lcp_config_get_option_input(SshPppState gdata,
                                    void *lcp_config,
                                    SshUInt8 opt_type);

struct SshPppConfigOptionRec*
ssh_ppp_lcp_config_get_option_output(SshPppState gdata,
                                     void *lcp_config,
                                     SshUInt8 opt_type);

struct SshPppConfigOptionRec*
ssh_ppp_lcp_config_iter_option_input(SshPppState gdata,
                                     void *ipcp_config,
                                     int opt_iter);

struct SshPppConfigOptionRec*
ssh_ppp_lcp_config_iter_option_output(SshPppState gdata,
                                      void *ipcp_config,
                                      int opt_iter);

#endif /* SSH_PPP_LCP_CONFIG_H */
