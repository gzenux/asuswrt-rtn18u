/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This layer is used to send one query to name servers (given as
   a list of name servers and their ip-addresses).
   It will wait for the reply, or until the timeout expires.
*/

#ifndef SSHDNSQUERY_H
#define SSHDNSQUERY_H

/* Query layer context structure. */
typedef struct SshDNSQueryLayerRec *SshDNSQueryLayer;

/* Callback to be called when the reply packet is received
   in query layer, or after the request times out. The
   return_packet is only valid during this call. */
typedef void (*SshDNSQueryCallback)(SshDNSResponseCode error,
                                    SshDNSNameServer name_server,
                                    const unsigned char *return_packet,
                                    size_t packet_length,
                                    void *context);

/**********************************************************************/
/* DNS-query level. This level does single query to
   dns-server list. It will try each dns-server and each
   ip-addresses of each server before failing. It will also
   automatically retransmit data. */

/* Query layer configuration structure. */
typedef struct SshDNSQueryLayerConfigRec {
  Boolean enable_udp;
  SshDNSTransportConfigStruct udp_config;
  Boolean enable_tcp;
  SshDNSTransportConfigStruct tcp_config;
  /* Initial retransmit timer in microseconds. If 0, then default is 1 second.
     This is doubled every time we start over using the same name server again,
     and it is also multiplied by 1.125 for each different name server. I.e.
     the first name server uses this, next name server uses 1.125 times this,
     next again 1.125 times the previous value, and when we go back to the
     first name server and try another IP-address there the value is
     doubled. */
  SshUInt32 initial_retransmit_time_us;

  /* Maximum retransmit timer in microseconds. If 0, then default is 10
     seconds. */
  SshUInt32 max_retransmit_time_us;
} *SshDNSQueryLayerConfig, SshDNSQueryLayerConfigStruct;

/* Allocate query layer. This will not automatically
   allocate any transports, thus you need to call
   ssh_dns_query_layer_configure to configure and allocate
   the transport layers. This will return NULL if out of
   memory. */
SshDNSQueryLayer
ssh_dns_query_layer_allocate(void);

/* Configure the query layer and udp and tcp transports.
   This returns true if the operation was successful, and
   FALSE if it run out of memory during the configure. In
   case of memory error some of the operations might have
   been done, and some may still be using old values. The
   query layer will still be usable even if memory error is
   received (provided it has managed to allocate at least
   one transport). */
Boolean
ssh_dns_query_layer_configure(SshDNSQueryLayer query_layer,
                              SshDNSQueryLayerConfig config);

/* Signal the query layer to shut down udp and tcp transports.
   This function signals underlying layers to close any idle sockets
   so that ssh_event_loop_run() can return. It is safe to call this
   function multiple times.*/
void
ssh_dns_query_layer_shutdown(SshDNSQueryLayer query_layer);

/* Free query layer. There must not be any operations in
   active when this is called. */
void
ssh_dns_query_layer_free(SshDNSQueryLayer query_layer);

/* Set transport specific paramaters. */
Boolean
ssh_dns_query_layer_set_transport_params(SshDNSQueryLayer query_layer,
                                         void *udp_params,
                                         void *tcp_params);

/* Do query to the given array of name servers. The
   array_of_nameservers is the array of pointers to the name
   servers and its size is number_of_nameservers entries.
   The packet is already formatted suitable for the DNS
   query to the packet buffer, and the ID field in the
   packet must be 0. If no reply is received before the
   timeout then the operation is aborted with error code
   SSH_DNS_TIMEOUT. The upper layer must make sure that the
   actual SshDNSNameServer entries are not freed during this
   operation (i.e. they must be locked to the cache).

   This function will copy the array itself and the packet,
   so they can be freed or modified immediately after
   this call. */
SshOperationHandle
ssh_dns_query_layer_query(SshDNSQueryLayer query_layer,
                          SshUInt32 number_of_nameservers,
                          SshDNSNameServer *array_of_nameservers,
                          const unsigned char *packet,
                          size_t packet_length,
                          SshUInt32 timeout_in_us,
                          SshUInt32 flags,
                          SshDNSQueryCallback callback,
                          void *context);


/* Register random number generator to the DNS library. By default the dns
   library uses ssh_rand (which needs to be seeded externally before dns
   library is used), but that is not safe enough for high security
   applications. High security applications needs to initialize the
   cryptolibrary and register the ssh_random_get_uint32 as random number
   function to the dns library. */
void ssh_dns_query_layer_register_random_func(SshDNSQueryLayer query_layer,
                                              SshUInt32 (*rand_func)(void));

#endif /* SSHDNSQUERY_H */
