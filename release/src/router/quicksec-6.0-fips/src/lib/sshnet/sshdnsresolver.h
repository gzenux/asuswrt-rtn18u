/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is the toplevel resolver function interface. This layer allows
   fetching data from the DNS. It will automatically use and fill in
   the cache, and it will follow CNAMEs and NS pointers if needed.
*/

#ifndef SSHDNSRESOLVER_H
#define SSHDNSRESOLVER_H

#include "sshglobals.h"

/* Resolver context structure. */
typedef struct SshDNSResolverRec *SshDNSResolver;

/**********************************************************************/
/* DNS-resolver layer. This will do the actual full resolver
   query, and return the information back in the parsed
   format. It might do multiple queries to the query layer,
   and use the cached data if available. */

/* Allocate resolver layer. This will not automatically
   allocate any transportsetc, thus you need to call
   ssh_dns_resolver_configure to configure and allocate the
   transport layers. This will return NULL if out of memory. */
SshDNSResolver
ssh_dns_resolver_allocate(void);

/* Resolver configuration structure. */
typedef struct SshDNSResolverConfigRec {
  /* Query layer config, this includes the tcp and udp
     transport config. */
  SshDNSQueryLayerConfigStruct query_layer_config;

  /* Name server cache configuration. */
  SshDNSNameServerCacheConfigStruct name_server_cache_config;

  /* Resource record set cache configuration. */
  SshDNSRRsetCacheConfigStruct rrset_config;

  /* Negative cache ttl. If set to 0, then default is 120 seconds. */
  SshUInt32 negative_cache_ttl;
} *SshDNSResolverConfig, SshDNSResolverConfigStruct;

/* Configure the resolver, name server cache, cache and udp
   and tcp transports. This returns true if the operation
   was successful, and FALSE if it run out of memory during
   the configure. In case of memory error some of the
   operations might have been done, and some may still be
   using old values. The resolver will still be usable even
   if memory error is received (provided it has managed to
   allocate at least one transport). */
Boolean
ssh_dns_resolver_configure(SshDNSResolver resolver,
                           SshDNSResolverConfig config);

/* Signal the resolver to shut down. This function signals
   underlying layers to close any idle sockets so that ssh_event_loop_run()
   can return. It is safe to call this function multiple times. */
void ssh_dns_resolver_shutdown(SshDNSResolver resolver);

/* Free resolver. There must not be any operations in active
   when this is called. */
void
ssh_dns_resolver_free(SshDNSResolver resolver);

/* Clear safety belt information, this will decrement references away
   from the safety belt servers, thus after some time, they can be
   removed from the name server cache. */
void ssh_dns_resolver_safety_belt_clear(SshDNSResolver resolver);

/* Add name server to the safety belt server list. Note, that safety belt name
   servers do not have name associated to them, only IP-addresses. This
   function is used to insert the list of IP-addresses of the name servers
   which are used if we do not have anything better yet. I.e. these servers are
   used to get the NS-records of the root name servers etc. */
SshDNSNameServer
ssh_dns_resolver_safety_belt_add(SshDNSResolver resolver,
                                 SshUInt32 number_of_ip_addresses,
                                 SshIpAddr array_of_ip_addresses);

/* Callback to be called when the resolver returns reply, or
   after the request times out. The RRset is locked in the
   cache during this callback, but it will be unlock immediately
   after this call returns. */
typedef void (*SshDNSResolverCallback)(SshDNSResponseCode error,
                                       SshDNSRRset rrset,
                                       void *context);

/* Find the given RRtype from the name server and call
   callback when the data is available. Note, that the name
   is in the dns-format, i.e. it has 1-byte label length, then
   label and then next 1-byte label length, and next label etc.
   It is terminated by having zero-length label, i.e. root label.
   This will also make it nul-terminated. */
SshOperationHandle
ssh_dns_resolver_find(SshDNSResolver resolver,
                      const unsigned char *name,
                      SshDNSRRType type,
                      SshUInt32 timeout_in_us,
                      SshUInt32 flags,
                      SshDNSResolverCallback callback,
                      void *context);

/* Allow lookup to return non-authorative data also. */
#define SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE          0x00000001
/* Always start from the safety belt. If combined with the
   SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE, and with the
   SSH_DNS_RESOLVER_REQUEST_RECURSIVE, and the safety belt
   resolvers allow recursive queries, it will do one
   recursive query to the safety belt name server and return
   that. This kind of setup can be used behind the firewalls
   etc. */
#define SSH_DNS_RESOLVER_START_FROM_SBELT               0x00000002
/* Set the RECURSION DESIRED flag in the query.If combined
   with the SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE, and with
   the SSH_DNS_RESOLVER_START_FROM_SBELT, and the safety
   belt resolvers allow recursive queries, it will do one
   recursive query to the safety belt name server and return
   that. This kind of setup can be used behind the firewalls
   etc. */
#define SSH_DNS_RESOLVER_RECURSIVE_REQUEST              0x00000004
/* Ignore the cache in the initial search, so we always do
   the real query to network at least for the first name. If
   we hit cname later we might end up using cache entries again. */
#define SSH_DNS_RESOLVER_IGNORE_CACHE                   0x00000008
/* Use TCP to do the query.  */
#define SSH_DNS_RESOLVER_USE_TCP                        0x00000010

/* Return the query layer handle. */
SshDNSQueryLayer
ssh_dns_resolver_query_layer(SshDNSResolver resolver);

/* Return the name server cache handle. */
SshDNSNameServerCache
ssh_dns_resolver_name_server_cache(SshDNSResolver resolver);

/* Return the rrset cache handle. */
SshDNSRRsetCache
ssh_dns_resolver_rrset_cache(SshDNSResolver resolver);

/* Do we want to pretty print debug prints. */
SSH_GLOBAL_DECLARE(int, ssh_dns_debug_pretty_print);
#define ssh_dns_debug_pretty_print \
  SSH_GLOBAL_USE_INIT(ssh_dns_debug_pretty_print)

/* Register random number generator to the DNS library. By default the dns
   library uses ssh_rand (which needs to be seeded externally before dns
   library is used), but that is not safe enough for high security
   applications. High security applications needs to initialize the
   cryptolibrary and register the ssh_random_get_uint32 as random number
   function to the dns library. */
void ssh_dns_resolver_register_random_func(SshDNSResolver resolver,
                                           SshUInt32 (*rand_func)(void));

/* Set transport methods for the resolver. This is needed in case
   the default connection methods need to be overwritten */
Boolean
ssh_dns_resolver_set_transport_params(SshDNSResolver resolver,
                                      void * udp_params,
                                      void * tcp_params);

#endif /* SSHDNSRESOLVER_H */
