/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   dhcp_options.h
*/

#ifndef DHCP_OPTIONS_H
#define DHCP_OPTIONS_H

#include "sshdhcp.h"

/* Structure to return default options from DHCP packet. */
typedef struct {
  SshUInt32 t1;
  SshUInt32 t2;

  SshUInt32 server_ip;
  size_t server_ip_len;
  SshUInt32 netmask;

  SshUInt32 *gateway_ip;
  size_t gateway_ip_count;

  SshUInt32 *dns_ip;
  size_t dns_ip_count;

  SshUInt32 *wins_ip;
  size_t wins_ip_count;

  unsigned char hostname[256];
  unsigned char dns_name[256];
  unsigned char file[128];
  unsigned char nis_name[256];
} *SshDHCPOptionsDefault;

/* This function can be used to free the SshDHCPOptionsDefault structure. */
void ssh_dhcp_free_options_default(SshDHCPOptionsDefault def);

#endif /* DHCP_OPTIONS_H */
