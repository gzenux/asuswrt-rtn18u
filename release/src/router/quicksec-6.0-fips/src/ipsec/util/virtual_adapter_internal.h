/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   virtual_adapter_internal.h
*/

#ifndef VIRTUAL_ADAPTER_INTERNAL_H
#define VIRTUAL_ADAPTER_INTERNAL_H

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

/* Engine-internal virtual adapter instance data structure.
   It is allocated before virtual_adapter_create(), and destroyed
   by the destruction callback. */
typedef struct SshEngineVirtualAdapterContextRec
{
  void *dummy;
} *SshEngineVirtualAdapterContext, SshEngineVirtualAdapterContextStruct;

/* Constructor for the structure */
void *ssh_virtual_adapter_context_create(SshInterceptor interceptor,
                                         SshInterceptorIfnum adapter_ifnum,
                                         const unsigned char *adapter_name);

/* Destructor for the structure */
void
ssh_virtual_adapter_context_destroy(void *context);

/* Updates virtual adapter context. */
Boolean
ssh_virtual_adapter_context_update(void *adapter_context,
                                   SshVirtualAdapterParams params,
                                   SshIpAddr dhcp_client_ip,
                                   const unsigned char *dhcp_option_data,
                                   size_t dhcp_option_data_len);

/* An SshVirtualAdapterPacketCB function that is capable of handling
   ARP and IPv6 Neighborhood Discovery requests.  The context data,
   passed in `context', must be of type SshEngineVirtualAdapterContext. */
void ssh_virtual_adapter_arp_packet_callback(SshInterceptor interceptor,
                                             SshInterceptorPacket pp,
                                             void *context);

/* An SshVirtualAdapterPacketCB function that is capable of
   dispatching packet to be handled either by
   ssh_virtual_adapter_arp_packet_callback or by
   ssh_virtual_adapter_dhcp_packet_callback. The context data, passed
   in `context', must be of type SshEngineVirtualAdapterContext. */
void ssh_virtual_adapter_packet_callback(SshInterceptor interceptor,
                                         SshInterceptorPacket pp,
                                         void *context);

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
#endif /* VIRTUAL_ADAPTER_INTERNAL_H */
