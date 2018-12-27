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

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"

#define SSH_DEBUG_MODULE "SshDnsNameServer"

/* Name server cache layer context. */
struct SshDNSNameServerCacheRec {
  /* Maximum number of total memory used by cache. Default
     is 16 kB. This includes memory used for name server
     structures and ip-addresses. */
  size_t max_memory;
  size_t memory_used;

  /* Number of hosts to keep even when not used. Default is
     200. Note, that the cache is cleared only when some
     query is finished, thus the cache size might
     temporarely go over this. */
  SshUInt32 keep_name_servers;

  /* Maximum number of hosts. Default is 512. */
  SshUInt32 max_name_servers;

  /* Total number of allocated name servers. */
  SshUInt32 total_name_servers;

  /* Each name server entry will be in the cache at least
     this many seconds. Default is 60 seconds. This is
     trying to make sure that the entries needed to finish
     the name resolution process are not cleared from the
     cache too early. */
  SshUInt32 minimum_lifetime;

  /* Container containing the mapping from the name server name to the
     SshDNSNameServer. */
  SshADTContainer name_server_bag;

  /* List of free entries in the name_server_bag. These entries are still
     valid, but they can be reused at will. */
  SshADTContainer free_list;
};

void
ssh_dns_name_server_free(SshDNSNameServerCache cache,
                         SshDNSNameServer name_server);

/* Hash function for name_servers. */
SshUInt32 ssh_dns_name_server_adt_hash(void *ptr, void *ctx)
{
  SshDNSNameServer name_server = ptr;
  SshUInt32 hash;
  const unsigned char *c;
  unsigned char d;

  c = name_server->name_server;
  hash = 0;
  while (*c)
    {
      d = *c++;
      if (isupper(d))
        d = tolower(d);
      hash += d;
      hash += hash << 10;
      hash ^= hash >> 6;
    }

  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;

  return hash;
}

/* Compare function for name_servers. */
int ssh_dns_name_server_adt_cmp(void *ptr1, void *ptr2, void *ctx)
{
  SshDNSNameServer name_server1 = ptr1;
  SshDNSNameServer name_server2 = ptr2;
  return ssh_ustrcasecmp(name_server1->name_server, name_server2->name_server);
}

/**********************************************************************/
/* Nameserver cache layer. This cache contains list of
   nameserver entries, and the IP-addresses for nameserver.
   It also includes the roundtrip times for each
   IP-address. */

/* Allocate the cache. The cache is initialized to default
   values. This will return NULL if out of memory. */
SshDNSNameServerCache
ssh_dns_name_server_cache_allocate(void)
{
  SshDNSNameServerCache cache;

  cache = ssh_calloc(1, sizeof(*cache));
  if (cache == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Out of memory while allocating name server cache"));
      return NULL;
    }
  SSH_DEBUG(SSH_D_HIGHSTART, ("Name server cache allocated"));

  cache->max_memory = 131072;
  cache->keep_name_servers = 200;
  cache->max_name_servers = 512;
  cache->total_name_servers = 0;
  cache->minimum_lifetime = 10;

  cache->memory_used = sizeof(*cache);

  cache->name_server_bag =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HASH,
                           ssh_dns_name_server_adt_hash,
                           SSH_ADT_COMPARE,
                           ssh_dns_name_server_adt_cmp,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSNameServerStruct,
                                             name_server_bag_header),
                           SSH_ADT_ARGS_END);

  cache->free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSNameServerStruct,
                                             free_list_header),
                           SSH_ADT_ARGS_END);

  if (cache->name_server_bag == NULL ||
      cache->free_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Out of memory while allocating name server cache"));
      ssh_dns_name_server_cache_free(cache);
      return NULL;
    }
  return cache;
}

/* Allocate name_server. */
SshDNSNameServer
ssh_dns_name_server_allocate(SshDNSNameServerCache cache,
                             const unsigned char *name_server_name,
                             SshUInt32 number_of_ip_addresses,
                             SshIpAddr array_of_ip_addresses,
                             Boolean authorative)
{
  SshDNSNameServer name_server;
  SshADTHandle h;
  size_t len1, len2;
  SshUInt32 i;

  if (cache->total_name_servers >= cache->max_name_servers)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Max name server limit reached while trying to allocate"
                 " entry %@",
                 ssh_dns_name_render,
                 name_server_name));
      return NULL;
    }
  len1 = sizeof(*name_server) + ssh_ustrlen(name_server_name) + 1;
  len2 = number_of_ip_addresses *
    (sizeof(SshUInt32) + sizeof(SshIpAddrStruct));

  if (cache->memory_used + len1 + len2 > cache->max_memory)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Max memory limit %zd reached while trying to "
                 "allocate %@ (%zd), memory used = %zd",
                 cache->max_memory,
                 ssh_dns_name_render,
                 name_server_name,
                 len1 + len2, cache->memory_used));
      return NULL;
    }

  name_server = ssh_calloc(1, len1);
  if (name_server == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating %@",
                             ssh_dns_name_render,
                             name_server_name));
      return NULL;
    }
  name_server->allocated_data = ssh_malloc(len2);
  if (name_server->allocated_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating %@",
                             ssh_dns_name_render,
                             name_server_name));
      ssh_free(name_server);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Allocating name server entry %@, "
                             "memory left = %zd",
                             ssh_dns_name_render,
                             name_server_name,
                             cache->max_memory - cache->memory_used));

  name_server->ref_cnt = 1;
  name_server->authorative = authorative;
  name_server->number_of_ip_addresses = number_of_ip_addresses;
  name_server->first_remove_time = ssh_time() + cache->minimum_lifetime;

  /* Copy the ip_address array after the name_server structure. */
  name_server->array_of_ip_addresses = name_server->allocated_data;
  memcpy(name_server->array_of_ip_addresses,
         array_of_ip_addresses,
         number_of_ip_addresses * sizeof(SshIpAddrStruct));

  /* Create round trip times array after the ip-addresses array. */
  name_server->array_of_round_trip_times_us = (void *)
    ((unsigned char *) name_server->allocated_data +
     number_of_ip_addresses * sizeof(SshIpAddrStruct));
  /* Set them to 0 seconds, so we will try all of them in order. */
  for (i = 0; i < name_server->number_of_ip_addresses; i++)
    name_server->array_of_round_trip_times_us[i] = 0;

  /* Copy the name. */
  name_server->name_server = (unsigned char *) name_server +
    sizeof(*name_server);
  ssh_ustrcpy(name_server->name_server, name_server_name);

  h = ssh_adt_insert(cache->name_server_bag, name_server);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("adt insert failed for %@",
                             ssh_dns_name_render,
                             name_server_name));
      ssh_free(name_server);
      return NULL;
    }
  cache->total_name_servers++;
  cache->memory_used += len1 + len2;

  return name_server;
}

/* Free name server. */
void
ssh_dns_name_server_free(SshDNSNameServerCache cache,
                         SshDNSNameServer name_server)
{
  size_t len1, len2;

  ssh_adt_detach_object(cache->name_server_bag, name_server);
  len1 = sizeof(*name_server) + ssh_ustrlen(name_server->name_server) + 1;
  len2 = name_server->number_of_ip_addresses *
    (sizeof(SshUInt32) + sizeof(SshIpAddrStruct));
  cache->memory_used -= len1 + len2;
  cache->total_name_servers--;
  ssh_free(name_server->allocated_data);
  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing name server entry %@, "
                             "memory left = %zd",
                             ssh_dns_name_render,
                             name_server->name_server,
                             cache->max_memory - cache->memory_used));
  ssh_free(name_server);
}

/* Verify that limits are matched, i.e. free extra name server items etc. */
void
ssh_dns_name_server_verify_limits(SshDNSNameServerCache cache,
                                  Boolean check_time)
{
  SshDNSNameServer name_server;
  SshTime t;

  SSH_DEBUG(SSH_D_LOWSTART, ("Verifying limits"));

  if (check_time)
    t = ssh_time();
  else
    t = 0;

  if ((cache->total_name_servers > cache->keep_name_servers * 9 / 10 ||
       cache->memory_used > cache->max_memory * 9 / 10) &&
      ssh_adt_num_objects(cache->free_list) > 0)
    {
      while((cache->total_name_servers > cache->keep_name_servers * 8 / 10 ||
             cache->memory_used > cache->max_memory * 8 / 10) &&
            ssh_adt_num_objects(cache->free_list) > 0)
        {
          name_server = ssh_adt_detach_from(cache->free_list,
                                            SSH_ADT_BEGINNING);
          /* No more entries in the free list, we cannot
             free more entries now. Must wait until there
             are more free entries before we can fullfill
             the new max_name_server limit. */
          SSH_ASSERT(name_server != NULL);
          /* We cannot remove this because its
             first_remove_time is too small. */
          if (t != 0 && name_server->first_remove_time > t)
            {
              /* Insert it back to the list at the end. */
              ssh_adt_insert(cache->free_list, name_server);
              /* Stop the process now. */
              break;
            }
          ssh_dns_name_server_free(cache, name_server);
        }
    }
}

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
                                    SshDNSNameServerCacheConfig config)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Reconfiguring name server cache"));
  if (config == NULL)
    {
      cache->max_memory = 0;
      cache->keep_name_servers = 0;
      cache->max_name_servers = 0;
      cache->minimum_lifetime = 0;
    }
  else
    {
      cache->max_memory = config->max_memory;
      cache->keep_name_servers = config->keep_name_servers;
      cache->max_name_servers = config->max_name_servers;
      cache->minimum_lifetime = config->minimum_lifetime;
    }

  if (cache->keep_name_servers == 0)
    cache->keep_name_servers = 200;
  if (cache->max_name_servers == 0)
    cache->max_name_servers = 512;
  if (cache->max_memory == 0)
    cache->max_memory = 131072;
  if (cache->minimum_lifetime == 0)
    cache->minimum_lifetime = 10;

  if (cache->keep_name_servers >= cache->max_name_servers)
    cache->keep_name_servers = cache->max_name_servers;

  ssh_dns_name_server_verify_limits(cache, TRUE);
  return TRUE;
}

/* Free the name server. Note, that there must not be any SshDNSNameServer
   entries out when this is called. */
void
ssh_dns_name_server_cache_free(SshDNSNameServerCache cache)
{
  /* This will free everything on the free list, as we move everything there.
     Note, that we cannot have any requests out when this is called, thus after
     this the total_name_servers should be 0. */
  if (cache->name_server_bag != NULL && cache->free_list != NULL)
    {
      cache->keep_name_servers = 0;
      ssh_dns_name_server_verify_limits(cache, FALSE);
    }
  if (cache->name_server_bag != NULL)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle h;
      SshDNSNameServer name_server;

      h = ssh_adt_enumerate_start(cache->name_server_bag);
      while (h != SSH_ADT_INVALID)
        {
          name_server = ssh_adt_get(cache->name_server_bag, h);
          SSH_DEBUG(SSH_D_ERROR, ("Entry name %@ reference = %d",
                                  ssh_dns_name_render,
                                  name_server->name_server,
                                  (int) name_server->ref_cnt));
          h = ssh_adt_enumerate_next(cache->name_server_bag, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(cache->name_server_bag) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(cache->name_server_bag);
    }
  if (cache->free_list != NULL)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle h;
      SshDNSNameServer name_server;

      h = ssh_adt_enumerate_start(cache->free_list);
      while (h != SSH_ADT_INVALID)
        {
          name_server = ssh_adt_get(cache->free_list, h);
          SSH_DEBUG(SSH_D_ERROR, ("Entry name %@ still in bag",
                                  ssh_dns_name_render,
                                  name_server->name_server));
          h = ssh_adt_enumerate_next(cache->free_list, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(cache->free_list) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(cache->free_list);
    }
  SSH_ASSERT(cache->total_name_servers == 0);
  SSH_ASSERT(cache->memory_used == sizeof(*cache));
  ssh_free(cache);
  SSH_DEBUG(SSH_D_HIGHSTART, ("Name server cache freed"));
}

/* Find name server from the cache and allocate reference to it. */
SshDNSNameServer
ssh_dns_name_server_cache_get(SshDNSNameServerCache cache,
                              const unsigned char *name_server_name)
{
  SshDNSNameServerStruct name_server[1];
  SshDNSNameServer name_server_ptr;
  SshADTHandle h;

  memset(name_server, 0, sizeof(*name_server));
  name_server->name_server = (unsigned char *) name_server_name;
  h = ssh_adt_get_handle_to_equal(cache->name_server_bag, name_server);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Trying to find name server entry %@",
                                 ssh_dns_name_render,
                                 name_server_name));
      return NULL;
    }
  SSH_DEBUG(SSH_D_LOWSTART, ("Found name server entry %@",
                             ssh_dns_name_render,
                             name_server_name));
  name_server_ptr = ssh_adt_get(cache->name_server_bag, h);
  if (name_server_ptr->ref_cnt == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Removing entry %@ from free list",
                              ssh_dns_name_render,
                              name_server_name));
      /* Remove it from the free list. */
      ssh_adt_detach_object(cache->free_list, name_server_ptr);
    }
  name_server_ptr->ref_cnt++;
  return name_server_ptr;
}

/* Return name server to the cache and deallocate reference to it. */
void
ssh_dns_name_server_cache_unlock(SshDNSNameServerCache cache,
                                 SshDNSNameServer name_server)
{
  name_server->ref_cnt--;
  if (name_server->ref_cnt == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Unlocking entry %@ and adding it to free list",
                              ssh_dns_name_render,
                              name_server->name_server));
      ssh_adt_insert(cache->free_list, name_server);
      ssh_dns_name_server_verify_limits(cache, TRUE);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Unlocking entry %@",
                              ssh_dns_name_render,
                              name_server->name_server));
    }
}

/* Allocate new name server entry and insert it to the
   cache. This will not automatically take any reference to
   the entry, but the entry will stay in the cache for the
   minimum lifetime seconds. If this would add duplicate
   entry to the cache, the entries are duplicated, i.e. if
   the IP-addresses etc are identical the minimum lifetime
   is updated, if there are differences in the ip-address,
   then the old statistics from the old entry is copied to
   this new one, and old is marked to be freed immediately
   when it does not have any more references. */
SshDNSNameServer
ssh_dns_name_server_cache_add(SshDNSNameServerCache cache,
                              const unsigned char *name_server,
                              SshUInt32 number_of_ip_addresses,
                              SshIpAddr array_of_ip_addresses,
                              Boolean authorative)
{
  SshDNSNameServer entry;
  SshIpAddr array_of_ip_addresses_copy;
  SshUInt32 *array_of_round_trip_times_us;
  void *allocated_data;
  size_t len1, len2;
  SshUInt32 i, j;

  SSH_DEBUG(SSH_D_LOWSTART, ("Adding entry %@, num_ip_addrs = %d",
                             ssh_dns_name_render,
                             name_server,
                             (int) number_of_ip_addresses));
  /* Try to find the entry. */
  entry = ssh_dns_name_server_cache_get(cache, name_server);
  if (entry == NULL)
    {
      /* Not found, verify limits, and allocate new item. */
      ssh_dns_name_server_verify_limits(cache, TRUE);
      return ssh_dns_name_server_allocate(cache, name_server,
                                          number_of_ip_addresses,
                                          array_of_ip_addresses,
                                          authorative);
    }
  /* Item found, set the first_remove_time. */
  entry->first_remove_time = ssh_time() + cache->minimum_lifetime;

  /* Verify if the items are same. */
  if (number_of_ip_addresses == entry->number_of_ip_addresses)
    {






      for (i = 0; i < number_of_ip_addresses; i++)
        {
          for (j = 0; j < entry->number_of_ip_addresses; j++)
            if (SSH_IP_CMP(&(array_of_ip_addresses[i]),
                           &(entry->array_of_ip_addresses[j])) == 0)
              break;
          if (j == entry->number_of_ip_addresses)
            goto changed;
        }
      /* The entries are identical, thus we can simply return the old
         entry. */
      SSH_DEBUG(SSH_D_LOWSTART, ("Using old entry %@",
                                 ssh_dns_name_render,
                                 name_server));

      /* Check if the old entry was not authorative and this is, if so set the
         entry to authorative. */
      if (!entry->authorative && authorative)
        entry->authorative = authorative;
      return entry;
    }
 changed:
  /* Check if the old entry was authorative, and we try to overwrite it with
     non-authorative entry. If so, return old entry. */
  if (entry->authorative && !authorative)
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Old more authorative entry %@ found",
                                 ssh_dns_name_render,
                                 name_server));
      return entry;
    }

  /* Item has changed, so we need to create new entry. */
  len1 = number_of_ip_addresses *
    (sizeof(SshUInt32) + sizeof(SshIpAddrStruct));
  len2 = entry->number_of_ip_addresses *
    (sizeof(SshUInt32) + sizeof(SshIpAddrStruct));

  /* We cannot allocate more memory. Return old entry. */
  if (cache->memory_used + len1 - len2 > cache->max_memory)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Trying to overwrite entry %@ but memory limit reached",
                 ssh_dns_name_render, name_server));
      return entry;
    }

  allocated_data = ssh_malloc(len1);
  if (allocated_data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Trying to overwrite entry %@ but out of memory",
                 ssh_dns_name_render, name_server));
      return entry;
    }

  /* Adjust memory_used count. */
  cache->memory_used += len1;
  cache->memory_used -= len2;

  /* Copy the information. */
  array_of_ip_addresses_copy = allocated_data;
  memcpy(array_of_ip_addresses_copy,
         array_of_ip_addresses,
         number_of_ip_addresses * sizeof(SshIpAddrStruct));

  /* Create round trip times array after the ip-addresses array. */
  array_of_round_trip_times_us = (void *)
    ((unsigned char *) allocated_data +
     number_of_ip_addresses * sizeof(SshIpAddrStruct));

  /* Find the real round trip times for new ip-addresses. */
  for (i = 0; i < number_of_ip_addresses; i++)
    {
      for (j = 0; j < entry->number_of_ip_addresses; j++)
        if (SSH_IP_CMP(&(array_of_ip_addresses_copy[i]),
                       &(entry->array_of_ip_addresses[j])) == 0)
          break;
      if (j != entry->number_of_ip_addresses)
        {
          /* Found entry. */
          array_of_round_trip_times_us[i] =
            entry->array_of_round_trip_times_us[j];

          /* Make sure we do not use this entry again, i.e. even if there is
             multiple identical ip-addresses in the list we only use each round
             trip time once. */
          SSH_IP_UNDEFINE(&(entry->array_of_ip_addresses[j]));
        }
      else
        {
          /* Not found, set them to 0 seconds, so we will next try this new
             address. */
          array_of_round_trip_times_us[i] = 0;
        }
    }

  /* Free the old data. */
  ssh_free(entry->allocated_data);

  /* Set new data in. */
  entry->allocated_data = allocated_data;
  entry->array_of_ip_addresses = array_of_ip_addresses_copy;
  entry->array_of_round_trip_times_us = array_of_round_trip_times_us;
  entry->authorative = authorative;
  entry->number_of_ip_addresses = number_of_ip_addresses;
  return entry;
}

/* Get best name server to be used in the array, or return -1 if no name
   servers found in the array (all entries are NULL). Note, that this will
   update round trip time at the same time (i.e. the first name server will
   keep its old round trip time, and others will have lower round trip time
   next, so they will be retried after some time). */
int
ssh_dns_name_server_cache_get_server(SshUInt32 number_of_nameservers,
                                     SshDNSNameServer *array_of_nameservers)
{
  int i, j, shortest, selected;
  SshDNSNameServer name_server;
  SshUInt32 round_trip;

  selected = -1;
  round_trip = ~0;
  for(i = 0; i < number_of_nameservers; i++)
    {
      name_server = array_of_nameservers[i];
      if (name_server != NULL)
        {
          shortest = 0;
          for (j = 1; j < name_server->number_of_ip_addresses; j++)
            {
              if (name_server->array_of_round_trip_times_us[j] <
                  name_server->array_of_round_trip_times_us[shortest])
                shortest = j;
            }
          if (name_server->array_of_round_trip_times_us[shortest] <
              round_trip)
            {
              selected = i;
              round_trip = name_server->
                array_of_round_trip_times_us[shortest];
            }
        }
    }
  for(i = 0; i < number_of_nameservers; i++)
    {
      name_server = array_of_nameservers[i];
      if (name_server != NULL && i != selected)
        {
          for (j = 0; j < name_server->number_of_ip_addresses; j++)
            {
              /* Multiple by 0.9375 */
              name_server->array_of_round_trip_times_us[j] -=
                (name_server->array_of_round_trip_times_us[j] >> 4);
            }
        }
    }
  return selected;
}

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
                                 SshUInt32 *round_trip_in_us)
{
  SshUInt32 i;

  if (*ip_index == SSH_DNS_NAME_SERVER_FIRST)
    {
      *ip_index = 0;
      for (i = 1; i < name_server->number_of_ip_addresses; i++)
        if (name_server->array_of_round_trip_times_us[i] <
            name_server->array_of_round_trip_times_us[*ip_index])
          *ip_index = i;
      SSH_DEBUG(SSH_D_LOWOK, ("Getting first IP %d from %@",
                              (int) *ip_index,
                              ssh_dns_name_render,
                              name_server->name_server));
    }
  else
    {
      (*ip_index)++;
      if (*ip_index >= name_server->number_of_ip_addresses)
        *ip_index = 0;
      SSH_DEBUG(SSH_D_LOWOK, ("Getting next IP %d from %@",
                              (int) *ip_index,
                              ssh_dns_name_render,
                              name_server->name_server));
    }
  *ip_addr = name_server->array_of_ip_addresses[*ip_index];
  *round_trip_in_us = name_server->array_of_round_trip_times_us[*ip_index];
  /* If the round_trip_in_us is 0, then return it as 2 seconds, so we will
     wait for the reply at least some time. */
  if (*round_trip_in_us == 0)
    *round_trip_in_us = 2000000;
  return;
}

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
                                    Boolean successful)
{
  /* Check if the entry has changed since the last time, i.e. number of
     ip-addresses or the order has changed. If so, ignore the information. */
  if (ip_index >= name_server->number_of_ip_addresses ||
      SSH_IP_CMP(&(name_server->array_of_ip_addresses[ip_index]),
                 ip_addr) != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Tried to put stats %d us back for %@, but entry has changed",
                 (int) round_trip_in_us,
                 ssh_dns_name_render,
                 name_server->name_server));
      return;
    }

  /* Ok, the information is valid, set the round trip time. */
  if (successful)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Putting back successful stats %d us for IP %d in %@",
                 (int) round_trip_in_us, (int) ip_index,
                 ssh_dns_name_render, name_server->name_server));
      /* If the response was successful, use slow decay version. */
      name_server->array_of_round_trip_times_us[ip_index] =
        (SshUInt32) (name_server->array_of_round_trip_times_us[ip_index]
                     * 0.875);
      name_server->array_of_round_trip_times_us[ip_index] +=
        round_trip_in_us / 8;
      name_server->failure_count = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Putting back unsuccessful stats %d us for IP %d in %@",
                 (int) round_trip_in_us, (int) ip_index,
                 ssh_dns_name_render, name_server->name_server));
      /* Packet lost, double the round_trip_time unless it goes over the
         timeout value. If it goes over then take average of the times. */
      if (name_server->array_of_round_trip_times_us[ip_index] * 2 >
          round_trip_in_us)
        {
          name_server->array_of_round_trip_times_us[ip_index] +=
            round_trip_in_us;
          name_server->array_of_round_trip_times_us[ip_index] /= 2;
        }
      else
        {
          name_server->array_of_round_trip_times_us[ip_index] *= 2;
        }
      name_server->failure_count++;
    }
  return;
}
