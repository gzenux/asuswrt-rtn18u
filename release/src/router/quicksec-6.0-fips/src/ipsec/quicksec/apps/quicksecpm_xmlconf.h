/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   XML configuration for QuickSec policy manager.
*/

#ifndef SSHQUICKSECPM_XMLCONF_H
#define SSHQUICKSECPM_XMLCONF_H

#include "ipsec_params.h"

#include "quicksec_pm.h"
#include "common_xmlconf.h"

/*************************** Types and definitions ***************************/

/** Static configuration parameters for the policy manager.  These are
   specified from the command line. */
struct SshIpmParamsRec
{
  /** The name of the policy manager executable. */
  const unsigned char *program;
  unsigned char hostname[256];               /** Hostname. */
  void *machine_context;                     /** -e */
  const unsigned char *config_file;          /** -f */
  unsigned char *http_proxy_url;             /** -H */
  unsigned char *socks_url;                  /** -S */
  const unsigned char *kernel_debug_level;   /** -K */
  unsigned char *debug_level;                /** -D */
  Boolean print_interface_info;              /** -i */
  Boolean pass_unknown_ipsec;                /** -u */
  Boolean no_dns_pass_rule;
  Boolean disable_dhcp_client_pass_rule;
  Boolean enable_dhcp_server_pass_rule;
  const unsigned char *appgw_addr;           /** -B */
  unsigned char *ike_addr;                   /** -b */
  SshUInt16 num_ike_ports;
  SshUInt16 local_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];       /** --ike-ports */
  SshUInt16 local_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];  /** --ike-ports */
  SshUInt16 remote_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];      /** --ike-ports */
  SshUInt16 remote_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS]; /** --ike-ports */
  unsigned char *bootstrap_traffic_selector; /** -a */



  Boolean dhcp_ras_enabled;                           /** -R */
  const unsigned char *enable_key_restrictions;             /** -N */
};

typedef struct SshIpmParamsRec SshIpmParamsStruct;

#endif /* not SSHQUICKSECPM_XMLCONF_H */
