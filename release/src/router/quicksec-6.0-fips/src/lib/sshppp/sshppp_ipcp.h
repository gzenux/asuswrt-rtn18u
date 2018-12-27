/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_IPCP_H

#define SSH_PPP_IPCP_H 1

typedef struct SshIpcpLocalRec {
  SshPppProtocol protocol;

  SshIpcpConfigStruct config_input;
  SshIpcpConfigStruct config_output;
} *SshIpcpLocal, SshIpcpLocalStruct;

SshPppEvents
ssh_ppp_ipcp_get_eventq(SshIpcpLocal);

void
ssh_ppp_ipcp_destroy(SshIpcpLocal);

SshIpcpLocal
ssh_ppp_ipcp_create(SshPppState state,
                    SshLcpLocal lcp);

#endif /* SSH_PPP_IPCP_H */
