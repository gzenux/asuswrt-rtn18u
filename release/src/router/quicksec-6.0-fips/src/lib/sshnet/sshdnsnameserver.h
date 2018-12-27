/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS name server cache layer
   This layer is used to keep track of name server and their ip-addresses.
   It also keeps track of the round-trip-time for each ip-address, so that
   can be used when selecting which ip-address to use.
*/

#ifndef SSHDNSNAMESERVER_H
#define SSHDNSNAMESERVER_H

/* One entry from the name server cache. All items here are only for the
   reading, DO NOT MODIFY ANYTHING. */
typedef struct SshDNSNameServerRec {
  /* Bag and list headers for name bag. DO NOT USE. The name_server_bag_header
     must be first item in the structure. */
  SshADTBagHeaderStruct name_server_bag_header;
  SshADTListHeaderStruct free_list_header;

  /* Reference count. This should always be >1 if you see this structure. */
  SshUInt32 ref_cnt;

  /* Name of the name server. This is in dns-format, i.e nul-terminated, as
     there is the root-label at the end. */
  unsigned char *name_server;

  /* Is this entry authorative. */
  Boolean authorative;

  /* Number of IP-addresses. */
  SshUInt32 number_of_ip_addresses;

  /* Array of the IP-addresses. The size of this array is given in the
     number_of_ip_addresses. */
  SshIpAddr array_of_ip_addresses;

  /* Array of round-trip-times of the ip-addresses. The size of this array is
     given in the number_of_ip_addresses. */
  SshUInt32 *array_of_round_trip_times_us;

  /* Time when the item can be removed from the cache. */
  SshTime first_remove_time;

  /* Failure count. If the failure count >>
     number_of_ip_addresses it means that this name server
     haven't been able to get any successfull operations in
     a while, thus it should not be counted as working name
     server. This is reset to 0 every time a successfull
     result is returned. */
  SshUInt32 failure_count;

  /* Data pointer. This pointer is used to allocate all dynamic data needed,
     i.e. array_of_ip_addresses, and array_of_round_trip_times. The
     name_server name is always allocated so that it is after the nameserver
     structure itself. */
  void *allocated_data;
} *SshDNSNameServer, SshDNSNameServerStruct;

/* Name server cache layer context. */
typedef struct SshDNSNameServerCacheRec *SshDNSNameServerCache;

/**********************************************************************/
/* Nameserver cache layer. This cache contains list of
   nameserver entries, and the IP-addresses for nameserver.
   It also includes the roundtrip times for each
   IP-address. */

/* Allocate the cache. The cache is initialized to default
   values. This will return NULL if out of memory. */
SshDNSNameServerCache
ssh_dns_name_server_cache_allocate(void);

/* Name server configuration structure. */
typedef struct SshDNSNameServerCacheConfigRec {
  /* Maximum number of total memory used by cache. Default
     is 128 kB. This includes memory used for name server
     structures and ip-addresses. */
  size_t max_memory;

  /* Number of hosts to keep even when not used. Default is
     200. Note, that the cache is cleared only when some
     query is finished, thus the cache size might
     temporarely go over this. */
  SshUInt32 keep_name_servers;

  /* Maximum number of hosts. Default is 512. */
  SshUInt32 max_name_servers;

  /* Each name server entry will be in the cache at least
     this many seconds. Default is 10 seconds. This is
     trying to make sure that the entries needed to finish
     the name resolution process are not cleared from the
     cache too early. */
  SshUInt32 minimum_lifetime;
} *SshDNSNameServerCacheConfig, SshDNSNameServerCacheConfigStruct;

/* Configure the cache to given values. It the cache size is
   made smaller, then the actual size may shrink only after
   enough data items have been freed from the cache. This
   returns true if the operation was successful, and FALSE
   if it run out of memory during the configure. In case of
   memory error some of the operations might have been done,
   and some may still be using old values. The name server
   cache will still be usable even if memory error is
   received. */
Boolean
ssh_dns_name_server_cache_configure(SshDNSNameServerCache cache,
                                    SshDNSNameServerCacheConfig config);

/* Free the name server. Note, that there must not be any SshDNSNameServer
   entries out when this is called. */
void
ssh_dns_name_server_cache_free(SshDNSNameServerCache cache);

/* Find name server from the cache and allocate reference to it. The
   name_server name is in dns-format. This will allocate one
   reference to the name server. */
SshDNSNameServer
ssh_dns_name_server_cache_get(SshDNSNameServerCache cache,
                              const unsigned char *name_server);

/* Return name server to the cache and deallocate reference to it. */
void
ssh_dns_name_server_cache_unlock(SshDNSNameServerCache cache,
                                 SshDNSNameServer name_server);

/* Allocate new name server entry and insert it to the
   cache. This will automatically take one reference to
   the entry which must be freed by calling the
   ssh_dns_name_server_cache_unlock. .

   This will automatically combine the entries, in case the
   entry is already in the cache. This should be called every
   time new name-server information is received. If the name
   server information was authorative then set the `authorative'
   to TRUE. Non-authorative entry does not overwrite the
   authorative entry. The name_server name is in dns-format. */
SshDNSNameServer
ssh_dns_name_server_cache_add(SshDNSNameServerCache cache,
                              const unsigned char *name_server,
                              SshUInt32 number_of_ip_addresses,
                              SshIpAddr array_of_ip_addresses,
                              Boolean authorative);

#define SSH_DNS_NAME_SERVER_FIRST (SshUInt32) ~0L

/* Get next IP-address to be used. The `ip_index' must have the previously
   used index, or SSH_DNS_NAME_SERVER_FIRST if this is first time this
   function is called for this name server for this packet. This function
   will then set the `ip_index' to new value, and fillin the `ip_addr' and
   `round_trip_in_us' times of the current name server. The `round_trip_in_us'
   should be used to estimate how long to wait for the reply. */
void
ssh_dns_name_server_cache_get_ip(SshDNSNameServer name_server,
                                 SshUInt32 *ip_index,
                                 SshIpAddr ip_addr,
                                 SshUInt32 *round_trip_in_us);

/* Set back the round trip time information. The ip_index is the value returned
   by the ssh_dns_name_server_cache_get_ip, and the ip_addr is the ip_address
   from where the response was received. The round_trip_in_us is the time how
   long the answer was waited (successful or not), and the successful tells
   whether the response was received or not. */
void
ssh_dns_name_server_cache_put_stats(SshDNSNameServer name_server,
                                    SshUInt32 ip_index,
                                    SshIpAddr ip_addr,
                                    SshUInt32 round_trip_in_us,
                                    Boolean successful);

/* Get best name server to be used in the array, or return -1 if no name
   servers found in the array (all entries are NULL). Note, that this will
   update round trip time at the same time (i.e. the first name server will
   keep its old round trip time, and others will have lower round trip time
   next, so they will be retried after some time). */
int
ssh_dns_name_server_cache_get_server(SshUInt32 number_of_nameservers,
                                     SshDNSNameServer *array_of_nameservers);

#endif /* SSHDNSNAMESERVER_H */
