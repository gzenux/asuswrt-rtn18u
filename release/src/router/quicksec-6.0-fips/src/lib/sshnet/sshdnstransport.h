/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS Transport layer
   This layer will send one packet using specified transport. It does not
   retransmit packets. It will wait reply for specified time and call
   callback when reply is received.
*/

#ifndef SSHDNSTRANSPORT_H
#define SSHDNSTRANSPORT_H

/* Transport layer context. */
typedef struct SshDNSTransportRec *SshDNSTransport;

/* Transport host context. */
typedef struct SshDNSTransportHostRec *SshDNSTransportHost;

#include "sshdnstransportimpl.h"

/* Callback to be called when the reply packet is received
   in transport layer, or after the request times out. The
   return_packet is only valid during this call. */
typedef void (*SshDNSTransportCallback)(SshDNSResponseCode error,
                                        const unsigned char *return_packet,
                                        size_t packet_length,
                                        void *context);

/**********************************************************************/
/* Transport layer. This layer takes care of the transport
   protocols TCP/UDP. There is only one transport per each
   protocol allocated for given application. */

/* Allocate transport handle. This operation is normally
   done only once during the initialization of the library.
   The caches etc are allocated using default sizes, and
   normally application will call ssh_dns_transport_configure
   immediately after this to configure the caches sizes.
   This will return NULL if out of memory. */
SshDNSTransport
ssh_dns_transport_allocate(const SshDNSTransportSpecStruct *specification);

/* TCP transport specification. */
extern const SshDNSTransportSpecStruct *ssh_dns_transport_spec_tcp;

/* UDP transport specification. */
extern const SshDNSTransportSpecStruct *ssh_dns_transport_spec_udp;

/* Transport configuration structure. */
typedef struct SshDNSTransportConfigRec {
  SshUInt32 close_timeout_us;   /* How long keep the connection open and idle
                                   after operation in useconds. Default is
                                   30 000 000 us = 30 seconds. */
  size_t max_memory;            /* Maximum number of total memory used by
                                   transport. Default is 16 kB. This
                                   includes memory used for host structures
                                   and queued packets waiting to be sent.
                                   It does not include some ADT overhead used
                                   for internal structures. It also does
                                   not include the memory used by the lower
                                   layer transport hooks (tcp, udp etc). */
  SshUInt32 prealloc_hosts;     /* Number of hosts to preallocate.
                                   Default is 0. */
  SshUInt32 keep_hosts;         /* Number of hosts to keep even when not used
                                   (will not affect at all if smaller than
                                   prealloc). Default is 4. */
  SshUInt32 max_hosts;          /* Maximum number of hosts. Default is 64. */
} *SshDNSTransportConfig, SshDNSTransportConfigStruct;

/* Reconfigure cache etc information for the transport. This
   can be called at any time, and this will clear all the
   caches and automatically abort all active operations
   (with timeout). This returns true if the operation was
   successful, and FALSE if it run out of memory during the
   configure. In case of memory error some of the operations
   might have been done, and some may still be using old
   values. The transport will still be usable even if memory
   error is received. */
Boolean
ssh_dns_transport_configure(SshDNSTransport transport,
                            SshDNSTransportConfig config);

/* Signal the transport layer to shut down. This function closes
   any idle sockets so that ssh_event_loop_run() can return.
   It is safe to call this function multiple times. */
void ssh_dns_transport_shutdown(SshDNSTransport transport);

/* Free transport. There MUST not be any host structures
   allocated when this is called. */
void ssh_dns_transport_free(SshDNSTransport transport);

/* Allocate unique ID for the request. This will be global
   to the transport protocol. */
SshUInt16 ssh_dns_transport_id(SshDNSTransport transport);

/* Free unique ID. */
void
ssh_dns_transport_id_free(SshDNSTransport transport, SshUInt16 id);

/* Register random number generator to the DNS library. By default the dns
   library uses ssh_rand (which needs to be seeded externally before dns
   library is used), but that is not safe enough for high security
   applications. High security applications needs to initialize the
   cryptolibrary and register the ssh_random_get_uint32 as random number
   function to the dns library. */
void ssh_dns_transport_register_random_func(SshDNSTransport transport,
                                            SshUInt32 (*rand_func)(void));

/* Return random number using configure random number function. */
SshUInt32 ssh_dns_transport_random_number(SshDNSTransportHost host);

/*********************************************************************/

Boolean
ssh_dns_transport_set_udp_listener_param(SshDNSTransport transport,
                                         void *udp_param);

Boolean
ssh_dns_transport_set_tcp_connect_param(SshDNSTransport transport,
                                        void *tcp_params);

void *
ssh_dns_transport_get_transport_param(SshDNSTransportHost host);

/**********************************************************************/
/* Transport host layer. This is the host specific structure
   allocated from the pool of host structures. The DNS
   should only keep minimum amount of hosts allocated at one
   time, i.e. it should free the host immediately when not
   needed any more. The hosts structures are reference
   counted, thus there is no need to try to combine the
   hosts in the upper layer, instead allocate new host for
   each packet. Even when the reference count goes to zero,
   the host is not immediately freed, but only after some
   time, so if the same host is needed again soon, the old
   entry is reused. */

/* Fetch host entry for the pool, or if not found allocate
   new one. This will allocate reference to the entry. The
   port number is implicit to the transport layer, and is
   not given here. This will return NULL if out of memory.
   If from_ip is NULL then IP_ADDR_ANY is used. The source
   port is always any port. */
SshDNSTransportHost
ssh_dns_transport_host_get(SshDNSTransport transport,
                           SshIpAddr from_ip,
                           SshIpAddr to_ip);

/* Return host back to the pool and deallocate reference. */
void
ssh_dns_transport_host_put(SshDNSTransportHost host);

/* Take a refernce to the host. */
void
ssh_dns_transport_host_lock(SshDNSTransportHost host);

/* Unlock reference. */
void
ssh_dns_transport_host_unlock(SshDNSTransportHost host);

/* Send packet using transport protocol to destination host
   tied to the transport host. If no reply is received after
   timeout_in_us microseconds then the operation times out.
   The callback is always called (unless operation is
   canceled). The first 16 bits of the packet is the DNS ID,
   and it is used to tie the return packets to this reply.
   Unique DNS ID is allocated with ssh_dns_transport_id
   function. The ID is global to the transport protocol, and
   will stay same for retransmissions to same and other
   hosts. */
SshOperationHandle
ssh_dns_transport_host_send(SshDNSTransportHost host,
                            const unsigned char *packet,
                            size_t packet_length,
                            SshUInt32 timeout_in_us,
                            SshUInt32 flags,
                            SshDNSTransportCallback callback,
                            void *context);

/* Return name. This is valid as long as the host structure is valid. */
const unsigned char *ssh_dns_transport_host_name(SshDNSTransportHost host);

/* Return implementation data for the lower level transport. */
void *ssh_dns_transport_implementation_data(SshDNSTransportHost host);

#endif /* SSHDNSTRANSPORT_H */
