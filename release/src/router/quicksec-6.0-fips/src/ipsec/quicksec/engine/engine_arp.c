/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements ARP, and generally the common code for using ethernet
   (rfc894, rfc1112) and IEEE 802 (rfc1042, rfc1469) encapsulation for
   media headers.  Services provided by this file are used by both the
   ethernet and IEEE 802 code.

   This source also implements rfc4861 "Neighbor Discovery for IP
   Version 6 (IPv6)". Most of the ARP cache shared code with both
   IPv4/IPv6, except at
   ssh_engine_arp_send_(solicitation|request).

   Note: this implementation of the ARP protocol assumes that the
   following data be entered to the arp cache as permanent entries on
   startup (this is done in ssh_engine_arp_update_interface): - IP
   addresses of all interfaces of this type, and their ethernet
   addresses - directed broadcast addreses of the networks connected
   to each interface, and a broadcast ethernet address for each of
   them.

   This data is entered in the cache by
   ssh_engine_arp_update_interface.
*/

#include "sshincludes.h"
#include "engine_internal.h"




#include "engine_arp.h"

#define SSH_DEBUG_MODULE "SshEngineArp"


/***************** Internal defines and forward declarations *****************/

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* The interceptor operates at IP level only.  ARP code not needed. */

#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* The interceptor may provide or require packets with media headers.
   Include this code. */

static const unsigned char ssh_engine_arp_ethernet_broadcast_addr[] =
  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };




static const unsigned char ssh_engine_arp_token_ring_multicast_addr[6] =
  { 0x03, 0x00, 0x00, 0x20, 0x00, 0x00 };

static const unsigned char ssh_engine_arp_hdr_ipv4_reply[] =
  { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02 };

static const unsigned char ssh_engine_arp_hdr_ipv4_request[] =
  { 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01 };

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
/* Array of arp cache entries. */
SshEngineArpCacheEntryStruct
  ssh_engine_arp_entry_table[SSH_ENGINE_ARP_CACHE_SIZE];
/* Freelist for arp cache entries.  This list is protected by
   engine->interface_lock. */
SshEngineArpCacheEntry ssh_engine_arp_entry_freelist;
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

void engine_arp_complete_pc(SshEngine engine,
                            SshEngineArpLookupStatus status,
                            SshEnginePacketContext pc, SshIpAddr ip,
                            const unsigned char *hw);

void engine_arp_entry_set_expiry_timeout(SshEngine engine,
                                         SshEngineArpCacheEntry entry,
                                         SshTime now);

void engine_arp_request_timeout_schedule(SshEngine engine,
                                         SshTime retry_timeout_sec,
                                         SshUInt32 retry_timeout_usec,
                                         SshTime now_sec,
                                         SshUInt32 now_usec);

void ssh_engine_arp_request_timeout(void *context);

void ssh_engine_arp_cache_timeout(void *context);


/*********************** Internal utility functions **************************/

/* Round time in microseconds down to ARP timer resolution. */
#define SSH_ENGINE_ARP_TIME_USEC_ROUND(usec)                            \
  (((long) (usec) / SSH_ENGINE_ARP_TIMER_RESOLUTION)                    \
   * SSH_ENGINE_ARP_TIMER_RESOLUTION)

/* Compare two times. */
#define SSH_ENGINE_ARP_TIME_CMP(a_sec, a_usec, b_sec, b_usec)           \
  ((a_sec) < (b_sec) ? -1 :                                             \
   ((a_sec) == (b_sec) ?                                                \
    ((SSH_ENGINE_ARP_TIME_USEC_ROUND(a_usec) -                          \
      (SSH_ENGINE_ARP_TIME_USEC_ROUND(b_usec)))) : 1))

/* Compare entrys retry timeout to time_sec and time_usec with the ARP
   timer resolution. */
#define SSH_ENGINE_ARP_ENTRY_RETRY_TIME_CMP(entry, time_sec, time_usec) \
  SSH_ENGINE_ARP_TIME_CMP((entry)->retry_timeout_sec,                   \
                          (entry)->retry_timeout_usec,                  \
                          (time_sec),                                   \
                          (time_usec))

/* Calculate hash slot value for cache entry for 'ip_addr'. */
#define SSH_ENGINE_ARP_CACHE_HASH(ip_addr)              \
  (SSH_IP_HASH((ip_addr)) % SSH_ENGINE_ARP_HASH_SIZE)

#ifdef DEBUG_LIGHT
/* Render an ethernet media address to a buffer.  This is used as
   a render function to the %@ syntax. */
int ssh_engine_arp_render_eth_mac(unsigned char *buf, int buf_size,
                                  int precision, void *datum)
{
  int len;
  unsigned char *hw_addr = datum;

  if (hw_addr != NULL)
    ssh_snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
                 hw_addr[0], hw_addr[1], hw_addr[2],
                 hw_addr[3], hw_addr[4], hw_addr[5]);
  else
    ssh_snprintf(buf, buf_size, "<null>");

  len = ssh_ustrlen(buf);
  if (precision >= 0 && len > precision)
    len = precision;

  return len;
}

/* Render an ARP cache entry. */
int ssh_engine_arp_entry_render(unsigned char *buf, int buf_size,
                                int precision, void *datum)
{
  int len;
  SshEngineArpCacheEntry entry = datum;

  if (entry == NULL)
    {
      ssh_snprintf(buf, buf_size, "<null>");
      len = ssh_ustrlen(buf);
      if (precision >= 0 && len > precision)
        len = precision;
      return len;
    }

  ssh_snprintf(buf, buf_size, "IP %@ HW %@ ifnum %u flags 0x%x status %s",
               ssh_ipaddr_render, &entry->ip_addr,
               ssh_engine_arp_render_eth_mac, entry->ethernet_addr,
               entry->ifnum, entry->flags,
               (entry->status == SSH_ENGINE_ARP_INCOMPLETE ? "incomplete" :
                (entry->status == SSH_ENGINE_ARP_FAILED ? "failed" :
                 (entry->status == SSH_ENGINE_ARP_COMPLETE ? "complete" :
                  (entry->status == SSH_ENGINE_ARP_PERMANENT ? "permanent" :
                   (entry->status == SSH_ENGINE_ARP_STALE ? "stale" :
                    (entry->status == SSH_ENGINE_ARP_PROBE ? "probe" :
                     "unknown")))))));
  len = ssh_ustrlen(buf);
  if (precision >= 0 && len > precision)
    len = precision;

  return len;
}
#endif /* DEBUG_LIGHT */

/* Insert the entry to hash table. This asserts that the entry must
   not be in the hash table. */
static void engine_arp_hash_insert(SshEngine engine,
                                   SshEngineArpCacheEntry entry)
{
  SshUInt32 hash;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(entry != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(&entry->ip_addr));
  SSH_ASSERT((entry->flags & SSH_ENGINE_ARP_F_IN_HASH) == 0);

  hash = SSH_ENGINE_ARP_CACHE_HASH(&entry->ip_addr);
  entry->next = engine->arp_cache.hash[hash];
  engine->arp_cache.hash[hash] = entry;

  entry->flags |= SSH_ENGINE_ARP_F_IN_HASH;
}

/* Remove the entry from the hash table if it is in the table. */
static void engine_arp_hash_remove(SshEngine engine,
                                   SshEngineArpCacheEntry entry)
{
  SshUInt32 hash;
  SshEngineArpCacheEntry prev_entry;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(entry != NULL);

  if ((entry->flags & SSH_ENGINE_ARP_F_IN_HASH) == 0)
    return;

  SSH_ASSERT(SSH_IP_DEFINED(&entry->ip_addr));
  hash = SSH_ENGINE_ARP_CACHE_HASH(&entry->ip_addr);

  /* Remove the entry from the hash table. */
  if (engine->arp_cache.hash[hash] == entry)
    {
      engine->arp_cache.hash[hash] = entry->next;
    }
  else
    {
      for (prev_entry = engine->arp_cache.hash[hash];
           prev_entry != NULL;
           prev_entry = prev_entry->next)
        {
          if (prev_entry->next == entry)
            {
              prev_entry->next = entry->next;
              break;
            }
        }

      /* Assert that entry was found in the retry list. */
      SSH_ASSERT(prev_entry != NULL);
    }

  entry->next = NULL;
  entry->flags &= ~SSH_ENGINE_ARP_F_IN_HASH;
}

/* Insert the entry to retry list. This asserts that the entry is not
   already on the retry list. */
static void engine_arp_retry_list_insert(SshEngine engine,
                                         SshEngineArpCacheEntry entry)
{
  SSH_ASSERT(entry != NULL);
  SSH_ASSERT((entry->flags & SSH_ENGINE_ARP_F_ON_RETRY_LIST) == 0);

  entry->retry_list_next = engine->arp_cache.retry_list;
  engine->arp_cache.retry_list = entry;

  entry->flags |= SSH_ENGINE_ARP_F_ON_RETRY_LIST;
}

/* If the entry is on the retry list, remove it. */
static void engine_arp_retry_list_remove(SshEngine engine,
                                         SshEngineArpCacheEntry entry)
{
  SshEngineArpCacheEntry prev_entry;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(entry != NULL);

  if ((entry->flags & SSH_ENGINE_ARP_F_ON_RETRY_LIST) == 0)
    return;

  if (engine->arp_cache.retry_list == entry)
    {
      engine->arp_cache.retry_list = entry->retry_list_next;
    }
  else
    {
      for (prev_entry = engine->arp_cache.retry_list;
           prev_entry != NULL;
           prev_entry = prev_entry->retry_list_next)
        {
          if (prev_entry->retry_list_next == entry)
            {
              prev_entry->retry_list_next = entry->retry_list_next;
              break;
            }
        }

      /* Assert that entry was found in the retry list. */
      SSH_ASSERT(prev_entry != NULL);
    }

  entry->retry_list_next = NULL;
  entry->flags &= ~SSH_ENGINE_ARP_F_ON_RETRY_LIST;
}

/* Moves the given entry to the beginning of the arp cache lru.  This
   should be called whenever the cache entry is used to map something.
   This can also be used to initially insert the entry on the list,
   provided that its lru_prev and lru_next fields are first
   initialized to NULL.  The engine->interface_lock must be held
   when this is called. */
void engine_arp_lru_bump(SshEngine engine,
                         SshEngineArpCacheEntry entry,
                         Boolean new_entry)
{
  SshEngineArpCache cache = &engine->arp_cache;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(entry != NULL);

  SSH_DEBUG(SSH_D_LOWOK,
            ("entry %p %@ cache head %p tail %p entry next %p prev %p",
             entry,
             ssh_engine_arp_entry_render, entry,
             cache->lru_head, cache->lru_tail,
             entry->lru_next, entry->lru_prev));

  /* Permanent entries are not on the LRU.  Do nothing if permanent. */
  if (entry->status == SSH_ENGINE_ARP_PERMANENT)
    return;

  /* Require that new entries are not on the list */
  SSH_ASSERT(new_entry == FALSE || cache->lru_head != entry);
  SSH_ASSERT(new_entry == FALSE || cache->lru_tail != entry);

  /* If already at head of list, do nothing.  This may actually be a
     fairly frequent case as most traffic is probably to a single
     server on the local network or to the external gateway. */
  if (cache->lru_head == entry)
    return;

  /* Remove the entry from the list if it is not new. */
  if (new_entry == FALSE)
    {
      /* Assert that we're on the list */
      SSH_ASSERT(entry->flags & SSH_ENGINE_ARP_F_ON_LRU_LIST);
      SSH_ASSERT(entry->lru_next != NULL || entry == cache->lru_tail);
      SSH_ASSERT(entry->lru_prev != NULL || entry == cache->lru_head);

      /* Remove the entry from the lru list (if it is on the list). */

      /* If not last, update prev pointer from next node; if last,
         update tail pointer of the list. */
      if (entry->lru_next)
        entry->lru_next->lru_prev = entry->lru_prev;
      else
        cache->lru_tail = entry->lru_prev;

      /* We know it is not the first (was checked above).
         And since we are not a new entry, we must be on the list. */
      SSH_ASSERT(entry->lru_prev != NULL);
      entry->lru_prev->lru_next = entry->lru_next;
    }
  else
    {
      /* Assert that entry is actually in pristine condition.. */
      SSH_ASSERT(entry->lru_next == NULL);
      SSH_ASSERT(entry->lru_prev == NULL);
    }

  /* Insert the entry at the head of the list. */
  if (cache->lru_head != NULL)
    cache->lru_head->lru_prev = entry;

  entry->lru_prev = NULL;
  entry->lru_next = cache->lru_head;
  cache->lru_head = entry;

  if (cache->lru_tail == NULL)
    cache->lru_tail = entry;

  /* Mark entry for removal from list */
  entry->flags |= SSH_ENGINE_ARP_F_ON_LRU_LIST;
}

/* Calls the completion function for any packets that are on the
   cache->packets_waiting_completion list.  This will take
   engine->interface_lock momentarily to access the list. */

void engine_arp_call_pending_completions(SshEngine engine)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEnginePacketContext pc;

  /* Keep looping until there are no more packets waiting for their
     completion function to be called. */
  for (;;)
    {
      /* Protect access to the list using engine->interface_lock. */
      ssh_kernel_mutex_lock(engine->interface_lock);

      /* Get the first packet from the list (and remove it from the list). */
      pc = cache->packets_waiting_completion;
      if (pc != NULL)
        {
          cache->packets_waiting_completion = pc->next;
          pc->next = NULL;
        }

      /* Release the lock. */
      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* If there are no more packets, stop. */
      if (pc == NULL)
        break;

      /* Call the completion function for the packet to signal failure to
         higher-level code. */
      engine_arp_complete_pc(engine, SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR,
                             pc, NULL, NULL);
    }
}


/* Removes the given entry from the arp cache (hash and lru), and
   frees it.  The engine lock must be held when this is called. */
void engine_arp_free_entry(SshEngine engine, SshEngineArpCacheEntry entry)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEnginePacketContext pc;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(entry != NULL);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Deleting entry %p %@ from the ARP cache",
             entry, ssh_engine_arp_entry_render, entry));

  /* Remove the entry from the lru list. */
  if (entry->flags & SSH_ENGINE_ARP_F_ON_LRU_LIST)
    {
      /* If not last, update prev pointer from next node; if last,
         update tail pointer of the list. */
      if (entry->lru_next != NULL)
        entry->lru_next->lru_prev = entry->lru_prev;
      else
        cache->lru_tail = entry->lru_prev;

      /* If not first, update next pointer of prev node; if first, update
         the head pointer of the list. */
      if (entry->lru_prev != NULL)
        entry->lru_prev->lru_next = entry->lru_next;
      else
        cache->lru_head = entry->lru_next;

      entry->flags &= ~SSH_ENGINE_ARP_F_ON_LRU_LIST;
    }

  /* Decrement the count of entries in the arp cache. */
  cache->num_entries--;

  /* Remove the entry from the hash lists. */
  engine_arp_hash_remove(engine, entry);

  /* If the entry is on the retry list, remove it. */
  engine_arp_retry_list_remove(engine, entry);

  /* Free all queued packets. */
  if (entry->queued_packet != NULL)
    {
      pc = entry->queued_packet;

      /* Put the packet on the list of packets waiting for their completion
         function to be called to indicate failure.  We cannot call the
         completion function directly from here, because we are holding
         the lock and the completion function expects to be called
         without the lock held.  The engine_arp_call_pending_completions
         function should be called after the lock is released after a
         call here. */
      pc->next = cache->packets_waiting_completion;
      cache->packets_waiting_completion = pc;
    }

  entry->queued_packet = NULL;
  entry->queued_packet_nh_index = SSH_IPSEC_INVALID_INDEX;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  entry->status = 0x7a; /* magic */
  entry->next = ssh_engine_arp_entry_freelist;
  ssh_engine_arp_entry_freelist = entry;

#else /* SSH_IPSEC_PREALLOCATE_TABLES */
  /* Free the entry data structure itself. */
  memset(entry, 'F', sizeof(*entry));
  ssh_free(entry);
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */
}

/* Allocates a new arp cache entry.  This also checks if the arp cache is
   full, and if so, removes the least recently accessed entry from the cache
   (and returns it for reuse).  Anyway, this returns an arp cache entry
   that should be added to the appropriate hash table slot.  This will
   not automatically add the entry to the lru list; engine_arp_lru_bump
   should be called for the entry to do that.  The engine lock must be
   held when this is called.

   This function may return NULL if no memory could be allocated. */

SshEngineArpCacheEntry engine_arp_cache_new_entry(SshEngine engine)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;
#ifdef DEBUG_LIGHT
  Boolean deleted = FALSE;
#endif /* DEBUG_LIGHT */

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Check if the cache is already full. */
  while (cache->num_entries >= SSH_ENGINE_ARP_CACHE_SIZE)
    {
      /* Reuse the least recently used entry from the cache. */
      entry = cache->lru_tail;
      if (entry == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not vacate an ARP entry due to all space"
                     " consumed by `permanent' entries. Increase"
                     " SSH_ENGINE_ARP_CACHE_SIZE"));

#ifdef SSH_IPSEC_STATISTICS
          engine->stats.out_of_arp_cache_entries++;
#endif /* SSH_IPSEC_STATISTICS */
          return NULL;
        }

      /* It should be impossible to have permanent entries in the
         lru list, permanent entries are not put there */
      SSH_ASSERT(entry->status != SSH_ENGINE_ARP_PERMANENT);

      /* We are the last entry, therefore the lru_next must be NULL */
      SSH_ASSERT(entry->lru_next == NULL);

      /* Free the arp cache entry.  We do it this way instead of reusing
         to reduce the probability of dangling timeouts and other
         unfortunate side effects. */
      engine_arp_free_entry(engine, entry);

#ifdef DEBUG_LIGHT
      deleted = TRUE;
#endif /* DEBUG_LIGHT */
    }

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  /* Get an available entry from the freelist. */
  if (ssh_engine_arp_entry_freelist == NULL)
    {
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.out_of_arp_cache_entries++;
#endif /* SSH_IPSEC_STATISTICS */
      return NULL;
    }

  entry = ssh_engine_arp_entry_freelist;
  SSH_ASSERT(entry->status == 0x7a); /* magic */
  ssh_engine_arp_entry_freelist = entry->next;
  memset(entry, 0, sizeof(*entry));
#else /* SSH_IPSEC_PREALLOCATE_TABLES */
  /* Allocate a new arp cache entry. */
  entry = ssh_calloc(1, sizeof(*entry));
  if (entry == NULL)
    {
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.out_of_arp_cache_entries++;
#endif /* SSH_IPSEC_STATISTICS */
      return NULL;
    }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

  entry->status = SSH_ENGINE_ARP_FAILED;
  entry->queued_packet_nh_index = SSH_IPSEC_INVALID_INDEX;

  /* Increment the number of arp cache entries. */
  cache->num_entries++;
  SSH_DEBUG(SSH_D_LOWSTART, ("Creating new ARP cache entry %s(%p)",
                             deleted ? "(deleted old to make space) ": "",
                             entry));

  return entry;
}

/* This function is called when a reply is received to an arp request.
   This will update the packet as appropriate, and if all arp lookups
   for the packet are complete, this will send the packet.  This will
   save the hardware address in the packet.  This function can be
   called concurrently (but not for the same packet).  If `ip' and `hw'
   are NULL, then the ARP lookup is considered to have failed.  The engine
   lock must not be held by the caller when this is called. */

void engine_arp_complete_pc(SshEngine engine,
                            SshEngineArpLookupStatus status,
                            SshEnginePacketContext pc,
                            SshIpAddr ip, const unsigned char *hw)
{
  SshUInt16 ethertype;
  unsigned char ownhw[6];
  SshInterceptorInterface *iface;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(engine != NULL);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("arp complete: pc %p IP %@ hw %@ pp flags 0x%lx status %s",
             pc,
             ssh_ipaddr_render, ip,
             ssh_engine_arp_render_eth_mac, hw,
             (pc->pp ? (long) pc->pp->flags : (long) 0),
             (status == SSH_ENGINE_ARP_LOOKUP_STATUS_OK ? "ok" :
              (status == SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR ? "error" :
               "dequeue"))));

  /* Check if the lookup failed. */
  if (status != SSH_ENGINE_ARP_LOOKUP_STATUS_OK)
    {
      (*pc->arp_callback)(pc, status, NULL, NULL, 0);
      return;
    }

  /* Determine ethertype. */
  if (SSH_IP_IS6(ip))
    ethertype = SSH_ETHERTYPE_IPv6;
  else
    ethertype = SSH_ETHERTYPE_IP;

  /* Obtain our own hardware address for the relevant network interface.
     We also sanity check the interface number to make sure it is within
     the allowed range and that it is still valid (it is possible that the
     interface could have gone down while we were not holding the lock). */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Sanity check ifnum. */
  iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, pc->arp_ifnum);
  if (iface == NULL ||
      iface->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      /* Invalid ifnum or nonexistent interface. */
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum %d or nonexistent interface",
                             (int)pc->arp_ifnum));
      (*pc->arp_callback)(pc, SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR, NULL, NULL,
                          0);
      return;
    }

  memcpy(ownhw, iface->media_addr, sizeof(ownhw));
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Pass the result to the callback. */
  (*pc->arp_callback)(pc, status, ownhw, hw, ethertype);
}

/* Lookup the IP address `ip_addr' from the ARP cache.  The function
   store the IP's hardware address in `hw' and returns TRUE if the IP
   address is know and we have a complete entry for it.  If the IP
   address is unknown, the function returns FALSE. */

static SshEngineArpCacheEntry
engine_arp_lookup_entry(SshEngine engine,
                        SshIpAddr ip_addr,
                        SshEngineIfnum ifnum)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;

  SSH_DEBUG(SSH_D_LOWSTART, ("Lookup address %@ ifnum %u from ARP cache",
                             ssh_ipaddr_render, ip_addr, ifnum));

  /* The ARP cache is protected by the interface lock. */
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Compute the hash. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(ip_addr);

  /* Find the entry from the hash table slot. */
  for (entry = cache->hash[hash]; entry != NULL; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr)
          && (entry->ifnum == ifnum
              || (entry->flags & SSH_ENGINE_ARP_F_GLOBAL)))
        break;
    }

  /* Did we find an entry? */
  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Address not found in ARP cache"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found matching ARP cache entry %@",
                          ssh_engine_arp_entry_render, entry));

  /* Process the packet depending on the status of the entry. */
  switch (entry->status)
    {
    case SSH_ENGINE_ARP_STALE:
    case SSH_ENGINE_ARP_PROBE:
    case SSH_ENGINE_ARP_COMPLETE:
      /* Bump the ARP entry to the beginning of the list. */
      engine_arp_lru_bump(engine, entry, FALSE);
      /* FALLTHROUGH */

    case SSH_ENGINE_ARP_PERMANENT:
      return entry;

    default:
      SSH_DEBUG(SSH_D_UNCOMMON, ("ARP lookup for some other entry"));
      return NULL;
    }
  /* NOTREACHED */
}


/* Looks up the hardware address for the given network interface.
   The interface lock must be held when this is called. */
Boolean
engine_arp_get_hwaddr(SshEngine engine, SshUInt32 ifnum, unsigned char *hw)
{
  SshInterceptorInterface *ifp;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Get a pointer to the interface data structure. */
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);

  /* Make sure it exists. */
  if (ifp == NULL ||
      ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed to get local media address, ifp %p", ifp));
      memset(hw, 0, SSH_ETHERH_ADDRLEN);

      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found media address %@ for interface %u",
                          ssh_engine_arp_render_eth_mac, ifp->media_addr,
                          ifnum));

  /* Copy the interface's media address. */
  memcpy(hw, ifp->media_addr, SSH_ETHERH_ADDRLEN);
  return TRUE;
}


/************************** ARP/IPv4 ****************************************/

/* Add an entry to the ARP cache, but only if there was an request
   entry present. req_required variable tells if request has to be
   present or not. */
void ssh_engine_arp_add_ipv4_address(SshEngine engine,
                                     SshIpAddr ip_addr,
                                     SshEngineIfnum ifnum,
                                     const unsigned char *hw)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;
  SshEnginePacketContext queued_pc;
  SshTime now;
  Boolean from_incomplete = FALSE;

  ssh_interceptor_get_time(&now, NULL);

  SSH_ASSERT(SSH_IP_IS6(ip_addr) == FALSE);

  /* Compute the hash value. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(ip_addr);

  /* Take the engine lock to access protected data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  SSH_DEBUG(SSH_D_LOWOK, ("Looking up ARP cache entry for address %@ ifnum %u",
                          ssh_ipaddr_render, ip_addr, ifnum));

  for (entry = cache->hash[hash]; entry != NULL; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
        break;
    }

  /* Ignore the arp reply if there is no corresponding entry in our
     arp cache. */
  if (entry == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No cache entry found for address %@ ifnum %u buck %u",
                 ssh_ipaddr_render, ip_addr, ifnum, (unsigned int) hash));
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found matching entry %@",
                          ssh_engine_arp_entry_render, entry));

  /* Process the packet, depending on the status of the entry. */
  switch (entry->status)
    {
    case SSH_ENGINE_ARP_INCOMPLETE:
    case SSH_ENGINE_ARP_FAILED:
    case SSH_ENGINE_ARP_STALE:
    case SSH_ENGINE_ARP_PROBE:

      SSH_DEBUG(SSH_D_MIDOK, ("arp input for incomplete/failed entry"));

      /* We didn't previously have a hardware address for this entry.
         Set the time-to-live field to a higher value to keep the
         entry in the cache for reasonably long. */
      engine_arp_entry_set_expiry_timeout(engine, entry, now);
      entry->retry_timeout_sec = 0;
      entry->retry_timeout_usec = 0;
      entry->arp_retry_count = 0;

      /* Mark that we now have complete information for the entry. */
      SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status complete"));
      entry->status = SSH_ENGINE_ARP_COMPLETE;

      /* Remove the packet from the retry list. */
      engine_arp_retry_list_remove(engine, entry);

      from_incomplete = TRUE;
      goto complete;

    case SSH_ENGINE_ARP_COMPLETE:
      SSH_DEBUG(SSH_D_MIDOK, ("arp input for already complete entry"));

    complete:
      /* In each of these cases, we can accept the arp reply and update
         both the hardware address and the status.  Note that we do not
         update the time-to-live of the entry, to make it harder for
         someone to flush important entries from the arp cache by
         arp flooding.  The time-to-live will get updated if the entry
         is used for sending a packet a second time. If we are actually
         already complete ARP entry, the MAC address might be changing
         later on. Compare and update if needed. */
      memcpy(entry->ethernet_addr, hw, SSH_ETHERH_ADDRLEN);

      /* Bump the ARP entry to the beginning of the list. */
      engine_arp_lru_bump(engine, entry, FALSE);

      /* Continue processing of the queued packet (if any). */
      queued_pc = entry->queued_packet;
      entry->queued_packet = NULL;
      entry->queued_packet_nh_index = SSH_IPSEC_INVALID_INDEX;

      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* Update matching next hop nodes. */
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      if (!from_incomplete
          && memcmp(entry->ethernet_addr, hw, SSH_ETHERH_ADDRLEN))
        ssh_engine_update_nh_node_mac(engine, ip_addr, ifnum, hw);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      if (queued_pc != NULL)
        engine_arp_complete_pc(engine, SSH_ENGINE_ARP_LOOKUP_STATUS_OK,
                               queued_pc, ip_addr, hw);

      return;

    case SSH_ENGINE_ARP_PERMANENT:
      ssh_kernel_mutex_unlock(engine->interface_lock);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Received arp reply for a permanent arp entry"));

      return;

    default:
      ssh_kernel_mutex_unlock(engine->interface_lock);

      ssh_fatal("ssh_engine_arp_add_ipv4_address: bad entry status %d",
                entry->status);
    }

  ssh_fatal("ssh_engine_arp_add_ipv4_address: Should not have gotten here!");
}

/* Sends an arp reply with the given addresses. */
void ssh_engine_arp_send_reply(SshEngine engine,
                               Boolean outgoing,
                               SshEngineIfnum ifnum_out,
                               SshVriId routing_instance_id,
                               SshIpAddr target_ip,
                               const unsigned char *target_hw,
                               SshIpAddr sender_ip,
                               const unsigned char *sender_hw,
                               const unsigned char *source_hw)
{
  SshInterceptorPacket pp;
  unsigned char *ucp;

  SSH_ASSERT(SSH_IP_IS4(target_ip) && SSH_IP_IS4(sender_ip));

  if (routing_instance_id < 0)
    return;

  /* Allocate a new packet for the specified interface. */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    (outgoing ? SSH_PACKET_FROMPROTOCOL
                                     : SSH_PACKET_FROMADAPTER),
                                    SSH_PROTOCOL_ETHERNET,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    ifnum_out, 28);
  if (pp == NULL)
    return;

  /* Set routing instance */
  pp->routing_instance_id = routing_instance_id;

  SSH_DEBUG(SSH_D_MIDOK, ("Sending ARP reply to interface %d",
                          (int) pp->ifnum_out));

  /* Get a pointer to the packet data. */
  ucp = ssh_interceptor_packet_pullup(pp, 28);
  if (ucp == NULL)
    return;

  /* Build the ARP reply. */
  memcpy(ucp, ssh_engine_arp_hdr_ipv4_reply, 8);

  /* Store sender information. */
  memcpy(ucp + 8, sender_hw, SSH_ETHERH_ADDRLEN);
  SSH_IP4_ENCODE(sender_ip, ucp + 8 + 6);

  /* Store target information. */
  memcpy(ucp + 8 + 6 + 4, target_hw, SSH_ETHERH_ADDRLEN);
  SSH_IP4_ENCODE(target_ip, ucp + 8 + 6 + 4 + 6);

  /* Encapsulate the packet in an ethernet header.  We send the packet
     as an ethernet unicast to the target hardware address. */
  ssh_engine_encapsulate_and_send(engine, pp, source_hw, target_hw,
                                  SSH_ETHERTYPE_ARP);
}

/* Sends an arp request for the IP address in the arp cache entry.
   The function must not be called with engine lock held, as it will
   send packet to the interceptor (that may indicate packet to engine
   while engine_send is still executing. */

void ssh_engine_arp_send_request(SshEngine engine, SshIpAddr targetaddr,
                                 SshEngineIfnum ifnum_out, SshIpAddr ownaddr,
                                 SshVriId routing_instance_id,
                                 unsigned char *ownhw)
{
  unsigned char *ucp;
  SshInterceptorPacket pp;

  SSH_ASSERT(SSH_IP_IS4(targetaddr));
  SSH_DEBUG(SSH_D_MIDSTART, ("arp send request for %@",
                             ssh_ipaddr_render, targetaddr));

  if (routing_instance_id < 0)
    return;

  /* Allocate a new packet for the specified interface.  We reserve
     28 bytes for the packet (the size of an IPv4 ethernet arp
     request). */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    SSH_PACKET_FROMPROTOCOL,
                                    SSH_PROTOCOL_ETHERNET,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    ifnum_out, 28);
  if (pp == NULL)
    return;

  /* Set routing_instance */
  pp->routing_instance_id = routing_instance_id;

  /* Get a pointer to the packet data. */
  ucp = ssh_interceptor_packet_pullup(pp, 28);
  if (ucp == NULL)
    return;

  /* Build the arp request.  First copy the header. */
  memcpy(ucp, ssh_engine_arp_hdr_ipv4_request, 8);

  /* Store our own IP address. */
  if (SSH_IP_IS4(ownaddr))
    SSH_IP4_ENCODE(ownaddr, ucp + 14);
  else
    memset(ucp + 14, 0, 4);

  memcpy(ucp + 8, ownhw, SSH_ETHERH_ADDRLEN);

  /* Set the target hardware address  to zero. */
  memset(ucp + 18, 0, SSH_ETHERH_ADDRLEN);

  /* Set the target address being queried. */
  SSH_IP4_ENCODE(targetaddr, ucp + 24);

  /* Encapsulate the packet in an ethernet header.  We send the packet as
     an ethernet broadcast. */
  ssh_engine_encapsulate_and_send(engine, pp, ownhw,
                                  ssh_engine_arp_ethernet_broadcast_addr,
                                  SSH_ETHERTYPE_ARP);
}


/* Processes the incoming gratuitous ARP request from another
   machine. */
void ssh_engine_gratuitous_arp(SshEngine engine,
                               SshIpAddr sender_ip,
                               SshEngineIfnum ifnum,
                               const unsigned char *sender_hw)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Lookup address %@ ifnum %u from ARP cache for gratuitous ARP",
             ssh_ipaddr_render, sender_ip, ifnum));

  /* Compute the hash value. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(sender_ip);

  /* Take the engine lock to access protected data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  for (entry = cache->hash[hash]; entry != NULL; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, sender_ip) && entry->ifnum == ifnum)
        break;
    }

  if (entry == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No cache entry found for gratuitous ARP addr %@",
                 ssh_ipaddr_render, sender_ip));
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Found matching ARP cache entry %@",
                          ssh_engine_arp_entry_render, entry));

  switch (entry->status)
    {
    case SSH_ENGINE_ARP_INCOMPLETE:
    case SSH_ENGINE_ARP_FAILED:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Gratuitous ARP request for incomplete/failed entry"));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;

    case SSH_ENGINE_ARP_COMPLETE:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Updating ARP and next hop table cache according to "
                 "gratuitous ARP request, "
                 "HW addr changed for %@ from %@ to %@",
                 ssh_ipaddr_render, sender_ip,
                 ssh_engine_arp_render_eth_mac, entry->ethernet_addr,
                 ssh_engine_arp_render_eth_mac, sender_hw));

      memcpy(entry->ethernet_addr, sender_hw, SSH_ETHERH_ADDRLEN);
      ssh_kernel_mutex_unlock(engine->interface_lock);

      /* Update matching next hop nodes. */
      ssh_kernel_mutex_lock(engine->flow_control_table_lock);
      ssh_engine_update_nh_node_mac(engine, sender_ip, ifnum, sender_hw);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;

    case SSH_ENGINE_ARP_PERMANENT:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Gratuitous ARP request for permanent entry. Doing "
                 "nothing."));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;

    default:
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Gratuitous ARP request for entry %@, doing nothing",
                 ssh_engine_arp_entry_render, entry));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;
    }
}

/* Process incoming ARP request. */
Boolean ssh_engine_arp_request(SshEngine engine,
                               SshInterceptorPacket pp,
                               const unsigned char *ucp)

{
  SshEngineArpCacheEntry entry;
  SshIpAddrStruct sender_ip;
  SshIpAddrStruct target_ip;
  unsigned char sender_hw[SSH_ETHERH_ADDRLEN];
  unsigned char target_hw[SSH_ETHERH_ADDRLEN];
  unsigned char source_hw[SSH_ETHERH_ADDRLEN];
  Boolean ret;

  /* Got an IPv4 ARP request. Extract information from the packet. */
  memcpy(sender_hw, ucp + 8, SSH_ETHERH_ADDRLEN);
  SSH_IP4_DECODE(&sender_ip, ucp + 8 + 6);
  SSH_IP4_DECODE(&target_ip, ucp + 8 + 16);
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("arp request from interface %d (pp flags %x); who-has %@ tell %@",
             (int) pp->ifnum_in, pp->flags,
             ssh_ipaddr_render, &target_ip,
             ssh_ipaddr_render, &sender_ip));

  if (SSH_IP_IS_NULLADDR(&sender_ip))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Request is an ARP Probe, no action needed"));
      return TRUE;
    }

  /* Lookup the IP address from the ARP cache. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  entry = engine_arp_lookup_entry(engine, &target_ip, pp->ifnum_in);
  if (entry != NULL)
    {
      memcpy(target_hw, entry->ethernet_addr, SSH_ETHERH_ADDRLEN);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("%s; %@ is-at %@: flags=0x%x",
                 SSH_IP_EQUAL(&sender_ip, &target_ip) ?
                 "gratuitous arp request"
                 : "arp request",
                 ssh_ipaddr_render, &target_ip,
                 ssh_engine_arp_render_eth_mac, target_hw,
                 (unsigned int) entry->flags));

      /* Reply to arp requests from local stack except gratuitous arp
         requests, which are sent out. Or if we do proxy arp for the IP.
      */
      if (((pp->flags & SSH_PACKET_FROMPROTOCOL) &&
           !SSH_IP_EQUAL(&sender_ip, &target_ip))
          || (entry->flags & SSH_ENGINE_ARP_F_PROXY))
        {
          /* If we are doing proxy ARP, reply with our interface's
             address. */
          if (entry->flags & SSH_ENGINE_ARP_F_PROXY)
            {
              /* Fetch our interface's hardware address. */
              ret = engine_arp_get_hwaddr(engine, pp->ifnum_in, source_hw);
              memcpy(target_hw, source_hw, SSH_ETHERH_ADDRLEN);
            }
          else
            {
              ret = TRUE;
              memcpy(source_hw, target_hw, SSH_ETHERH_ADDRLEN);
            }

          ssh_kernel_mutex_unlock(engine->interface_lock);

          /* Reply for this ARP request. */
          if (ret == TRUE)
            /* ARP reply, argument swapping is intentional. */
            /* coverity[swapped_arguments] */
            ssh_engine_arp_send_reply(engine,
                                      ((pp->flags & SSH_PACKET_FROMADAPTER)
                                       ? TRUE : FALSE),
                                      pp->ifnum_in,
                                      pp->routing_instance_id,
                                      &sender_ip, sender_hw,
                                      &target_ip, target_hw,
                                      source_hw);

          /* Done with the packet. */
          ssh_interceptor_packet_free(pp);
          return FALSE;
        }
      else if ((pp->flags & SSH_PACKET_FROMADAPTER) &&
               (SSH_IP_EQUAL(&sender_ip, &target_ip)))
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);

          /* Gratuitous ARP case.  */
          ssh_engine_gratuitous_arp(engine, &sender_ip, pp->ifnum_in,
                                    sender_hw);
          return TRUE;
        }
      else if ((pp->flags & SSH_PACKET_FROMADAPTER) &&
               memcmp(sender_hw, target_hw, SSH_ETHERH_ADDRLEN))
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);

          /* Update sender hw address in cache. */
          ssh_engine_arp_add_ipv4_address(engine, &sender_ip, pp->ifnum_in,
                                          sender_hw);
          return TRUE;
        }
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  return TRUE;
}

/* Process incoming ARP reply. */
Boolean ssh_engine_arp_reply(SshEngine engine,
                             SshInterceptorPacket pp,
                             const unsigned char *ucp)
{
  SshIpAddrStruct target_ip;
  const unsigned char *target_hw;

  /* Got an IPv4 ARP reply.  Extract the ip and hardware addresses. */
  SSH_IP4_DECODE(&target_ip, ucp + 8 + 6);
  target_hw = ucp + 8;

  /* Check if it is an ethernet broadcast or multicast address.
     We do not want to accept arp replies that specify an ethernet
     broadcast or multicast address. */
  if (SSH_ETHER_IS_MULTICAST(target_hw))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Got multicast hw address %@ in ARP reply, "
                 "ignoring ARP reply",
                 ssh_engine_arp_render_eth_mac, target_hw));
      return TRUE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("ARP reply for IP %@ hw %@",
                          ssh_ipaddr_render, &target_ip,
                          ssh_engine_arp_render_eth_mac, target_hw));
  ssh_engine_arp_add_ipv4_address(engine, &target_ip, pp->ifnum_in, target_hw);
  return TRUE;
}


/* Processes an incoming arp packet.  This function will update the
   arp table as appropriate, and will cause the SshEngineArpComplete
   callback to be called for any pending requests completed by this
   packet.  The packet in `pp' should not contain media header, but
   the media header should be saved in pd->mediahdr.  Normally, this
   will not free `pp' and returns TRUE, because the packet will
   normally also be passed to the host TCP/IP stack.  If an error
   causes the packet to be freed, this returns FALSE.

   This function can be called concurrently.  This will momentarily lock
   the engine lock to modify the cache data structures. */

Boolean ssh_engine_arp_input(SshEngine engine, SshInterceptorPacket pp)
{
  const unsigned char *ucp;

  SSH_DEBUG(SSH_D_HIGHSTART, ("ARP input"));

  /* Make sure arp header and standard fields are all there. */
  if (ssh_interceptor_packet_len(pp) < 28)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Got arp packet that is too short"));
      return TRUE;
    }

  /* Get a pointer to the data. */
  ucp = ssh_interceptor_packet_pullup_read(pp, 28);
  if (ucp == NULL)
    return FALSE;

  /* Check if it is an IPv4 arp reply with 48 bit hw address. */
  if (memcmp(ucp, ssh_engine_arp_hdr_ipv4_reply, 8) == 0)
    {
      return ssh_engine_arp_reply(engine, pp, ucp);
    }

  /* Check if it is an IPv4 arp request with 48 bit hw address. */
  if (memcmp(ucp, ssh_engine_arp_hdr_ipv4_request, 8) == 0)
    {
      return ssh_engine_arp_request(engine, pp, ucp);
    }

  /* We did not recognize the arp packet or do not want to process it. */
  SSH_DEBUG(SSH_D_UNCOMMON,
            ("Packet was some other ARP packet, no action taken"));

  return TRUE;
}


#if defined(WITH_IPV6)
/*************************** IPv6 Neighbor discovery *************************/

/* Verify ICMPv6 checksum. */
Boolean engine_arp_ipv6_verify_cksum(SshEnginePacketContext pc)
{
  unsigned char pseudo_hdr[SSH_IP6_PSEUDOH_HDRLEN];
  unsigned char pullup_buf[SSH_IPH6_HDRLEN];
  const unsigned char *ucp;
  SshUInt16 segsum, cksum;
  SshUInt32 sum;

  SSH_ASSERT(pc->media_hdr_len == 0);

  /* Construct and calculate checksum over IPv6 pseudo header. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH6_HDRLEN, pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      return FALSE;
    }

  memset(pseudo_hdr, 0, sizeof(pseudo_hdr));
  memcpy(pseudo_hdr + SSH_IP6_PSEUDOH_OFS_SRC, ucp + SSH_IPH6_OFS_SRC,
         SSH_IPH6_ADDRLEN);
  memcpy(pseudo_hdr + SSH_IP6_PSEUDOH_OFS_DST, ucp + SSH_IPH6_OFS_DST,
         SSH_IPH6_ADDRLEN);
  SSH_IP6_PSEUDOH_SET_LEN(pseudo_hdr, pc->packet_len - pc->hdrlen);
  SSH_IP6_PSEUDOH_SET_NH(pseudo_hdr, pc->ipproto);

  segsum = ~ssh_ip_cksum(pseudo_hdr, SSH_IP6_PSEUDOH_HDRLEN);
  sum = segsum;

  /* Calculate checksum over ICMPv6 header and payload. */
  segsum = ~ssh_ip_cksum_packet(pc->pp, pc->hdrlen,
                                pc->packet_len - pc->hdrlen);
  sum += segsum;

  /* Fold 32-bit sum to 16 bits. */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  cksum = (SshUInt16)~sum;

  if (cksum == 0)
    return TRUE;
  else
    return FALSE;
}

/* Send an IPv6 Neighbor Solicitation ICMP (the IPv6 equivalent of ARP).
   If 'dst_addr' and 'dst_hw' are NULL, then the NS is sent to the standard
   multicast group, otherwise it is sent to the given unicast address. */
void ssh_engine_arp_send_solicitation(SshEngine engine,
                                      SshIpAddr dst_addr,
                                      unsigned char *dst_hw,
                                      SshIpAddr target_addr,
                                      SshEngineIfnum ifnum_out,
                                      SshVriId routing_instance_id,
                                      SshIpAddr own_addr,
                                      unsigned char *own_hw)
{
  SshInterceptorPacket pp;
  unsigned char *ucp, *icmp, *opt;
  unsigned char addr[16], media_addr[SSH_ETHERH_ADDRLEN];
  SshUInt16 checksum;
  SshIpAddrStruct dst;

  SSH_ASSERT(SSH_IP_IS6(target_addr));
  SSH_DEBUG(SSH_D_MIDSTART,
            ("NS for target %@ requested (we are %@, %@)",
             ssh_ipaddr_render, target_addr,
             ssh_ipaddr_render, own_addr,
             ssh_engine_arp_render_eth_mac, own_hw));

  if (routing_instance_id < 0)
    return;

  /* Allocate a packet for the neighbor solicitation. Reserve space for
     IPv6 header, ICMPv6 neighbor advertisement and 8 bytes of options. */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    SSH_PACKET_FROMPROTOCOL,
                                    SSH_PROTOCOL_ETHERNET,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    ifnum_out,
                                    SSH_IPH6_HDRLEN
                                    + SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN
                                    + 8);
  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate packet for solicitation message."));
      return;
    }

  /* Set routing instance */
  pp->routing_instance_id = routing_instance_id;

  ucp = ssh_interceptor_packet_pullup(pp,
                                      SSH_IPH6_HDRLEN
                                      + SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN
                                      + 8);
  if (ucp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed pullup of solicitation message"));
      return;
    }

  /* Use solicited-node multicast address for target address. */
  memset(addr, 0, 16);
  if (dst_addr == NULL)
    {
      addr[0] = 0xff;
      addr[1] = 0x02;
      addr[11] = 0x01;
      addr[12] = 0xff;
      addr[13] = SSH_IP6_BYTE14(target_addr);
      addr[14] = SSH_IP6_BYTE15(target_addr);
      addr[15] = SSH_IP6_BYTE16(target_addr);
      SSH_IP6_DECODE(&dst, addr);
    }

  /* Use unicast. */
  else
    {
      dst = *dst_addr;
    }

  /* Use the ethernet multicast group for the above constructed IP address */
  if (dst_hw == NULL)
    {
      media_addr[0] = 0x33;
      media_addr[1] = 0x33;
      media_addr[2] = addr[12];
      media_addr[3] = addr[13];
      media_addr[4] = addr[14];
      media_addr[5] = addr[15];
    }

  /* Use unicast ethernet address. */
  else
    {
      memcpy(media_addr, dst_hw, SSH_ETHERH_ADDRLEN);
    }

  /* Construct the IPv6 pseudo-header. */
  memset(ucp, 0, SSH_IP6_PSEUDOH_HDRLEN);
  SSH_IP6_PSEUDOH_SET_SRC(own_addr, ucp);
  SSH_IP6_PSEUDOH_SET_DST(&dst, ucp);
  SSH_IP6_PSEUDOH_SET_LEN(ucp, SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN + 8);
  SSH_IP6_PSEUDOH_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);

  /* ICMPv6 header */
  icmp = ucp + SSH_IPH6_HDRLEN;
  SSH_ICMP6H_SET_TYPE(icmp, SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION);
  SSH_ICMP6H_SET_CODE(icmp, 0);
  SSH_ICMP6H_SET_CHECKSUM(icmp, 0);

  /* Neighbor solicitation */
  SSH_ICMP6H_NS_SET_RES(icmp, 0); /* reserved, must be set to 0 */
  SSH_ICMP6H_NS_SET_TARGETADDR(target_addr, icmp); /* target address */

  /* Source link address option */
  opt = icmp + SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN;
  SSH_ICMP6H_ND_OPTION_SET_TYPE(opt,
                                SSH_ICMP6_NEIGHDISC_OPT_SOURCE_LINK_ADDRESS);
  SSH_ICMP6H_ND_OPTION_SET_LEN(opt, 1); /* 8 bytes */
  memcpy(opt + SSH_ICMP6H_ND_OPTION_LLADDR_OFS_ADDR, own_hw,
         SSH_ETHERH_ADDRLEN); /* hw address */

  /* Calculate checksum */
  checksum = ssh_ip_cksum_packet(pp, 0,
                                 SSH_IPH6_HDRLEN
                                 + SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN
                                 + 8);
  SSH_ICMP6H_SET_CHECKSUM(icmp, checksum);

  /* Now construct the real IPv6 headers */
  SSH_IPH6_SET_VERSION(ucp, 6);
  SSH_IPH6_SET_CLASS(ucp, 0);
  SSH_IPH6_SET_FLOW(ucp, 0);
  SSH_IPH6_SET_LEN(ucp, SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN + 8);
  SSH_IPH6_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);
  SSH_IPH6_SET_HL(ucp, 255);
  SSH_IPH6_SET_SRC(own_addr, ucp);
  SSH_IPH6_SET_DST(&dst, ucp);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Sending neighbor solicitation message: IP from %@ to %@"
             " ether from %@ to %@",
             ssh_ipaddr_render, own_addr,
             ssh_ipaddr_render, &dst,
             ssh_engine_arp_render_eth_mac, own_hw,
             ssh_engine_arp_render_eth_mac, media_addr));
  SSH_DUMP_PACKET(SSH_D_LOWSTART, "NS packet", pp);

  /* Encapsulate the packet in an ethernet header. We send the packet as
     ethernet multicast. */
  ssh_engine_encapsulate_and_send(engine, pp, own_hw, media_addr,
                                  SSH_ETHERTYPE_IPv6);
}

/* Send an IPv6 Neighbor Advertisement ICMP
   (the IPv6 equivalent of ARP reply). */
void ssh_engine_arp_send_advertisement(SshEngine engine,
                                       Boolean outgoing,
                                       SshEngineIfnum ifnum_out,
                                       SshVriId routing_instance_id,
                                       SshIpAddr dst_ip,
                                       unsigned char *dst_hw,
                                       SshIpAddr target_ip,
                                       unsigned char *target_hw,
                                       SshIpAddr own_ip,
                                       unsigned char *own_hw,
                                       Boolean router,
                                       Boolean solicited,
                                       Boolean override)
{
  SshInterceptorPacket pp;
  unsigned char *ucp, *icmp, *opt;
  SshUInt16 checksum;
  SshUInt8 flags;

  SSH_ASSERT(SSH_IP_IS6(target_ip) == TRUE);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("NA for target %@ hw %@ to %@ hw %@",
             ssh_ipaddr_render, target_ip,
             ssh_engine_arp_render_eth_mac, target_hw,
             ssh_ipaddr_render, dst_ip,
             ssh_engine_arp_render_eth_mac, dst_hw));

  if (routing_instance_id < 0)
    return;

  /* Allocate a packet for the neighbor advertisement. Reserve space for
     IPv6 header, ICMPv6 neighbor advertisement and 8 bytes of options. */
  pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                    (outgoing ?
                                     SSH_PACKET_FROMPROTOCOL :
                                     SSH_PACKET_FROMADAPTER),
                                    SSH_PROTOCOL_ETHERNET,
                                    SSH_INTERCEPTOR_INVALID_IFNUM,
                                    ifnum_out,
                                    SSH_IPH6_HDRLEN
                                    + SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN
                                    + 8);
  if (pp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not allocate packet for advertisement message."));
      return;
    }

  /* Set routing_instance_id */
  pp->routing_instance_id = routing_instance_id;

  ucp = ssh_interceptor_packet_pullup(pp,
                                      SSH_IPH6_HDRLEN
                                      + SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN
                                      + 8);
  if (ucp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed pullup of advertisement message"));
      return;
    }

  /* Construct the IPv6 pseudo-header. */
  memset(ucp, 0, SSH_IP6_PSEUDOH_HDRLEN);
  SSH_IP6_PSEUDOH_SET_SRC(own_ip, ucp);
  SSH_IP6_PSEUDOH_SET_DST(dst_ip, ucp);
  SSH_IP6_PSEUDOH_SET_LEN(ucp, SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN + 8);
  SSH_IP6_PSEUDOH_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);

  /* ICMPv6 header */
  icmp = ucp + SSH_IPH6_HDRLEN;
  SSH_ICMP6H_SET_TYPE(icmp, SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT);
  SSH_ICMP6H_SET_CODE(icmp, 0);
  SSH_ICMP6H_SET_CHECKSUM(icmp, 0);

  /* Neighbor advertisement */
  flags = 0;
  if (router)
    flags |= SSH_ICMP6H_NA_FLAG_ROUTER;
  if (solicited)
    flags |= SSH_ICMP6H_NA_FLAG_SOLICITED;
  if (override)
    flags |= SSH_ICMP6H_NA_FLAG_OVERRIDE;

  SSH_ICMP6H_NA_SET_FLAGS(icmp, flags); /* Includes 5 bits of reserved. */
  SSH_ICMP6H_NA_SET_RES(icmp, 0); /* reserved, must be set to 0 */
  SSH_ICMP6H_NA_SET_TARGETADDR(target_ip, icmp);

  /* Target link address option */
  opt = icmp + SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN;
  SSH_ICMP6H_ND_OPTION_SET_TYPE(opt,
                                SSH_ICMP6_NEIGHDISC_OPT_TARGET_LINK_ADDRESS);
  SSH_ICMP6H_ND_OPTION_SET_LEN(opt, 1); /* 8 bytes */
  memcpy(opt + SSH_ICMP6H_ND_OPTION_LLADDR_OFS_ADDR, target_hw,
         SSH_ETHERH_ADDRLEN); /* hw addr */

  /* Calculate checksum */
  checksum = ssh_ip_cksum_packet(pp, 0,
                                 SSH_IPH6_HDRLEN
                                 + SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN
                                 + 8);
  SSH_ICMP6H_SET_CHECKSUM(icmp, checksum);

  /* Now construct the real IPv6 header. */
  SSH_IPH6_SET_VERSION(ucp, 6);
  SSH_IPH6_SET_CLASS(ucp, 0);
  SSH_IPH6_SET_FLOW(ucp, 0);
  SSH_IPH6_SET_LEN(ucp, SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN + 8);
  SSH_IPH6_SET_NH(ucp, SSH_IPPROTO_IPV6ICMP);
  SSH_IPH6_SET_HL(ucp, 255);
  SSH_IPH6_SET_SRC(own_ip, ucp);
  SSH_IPH6_SET_DST(dst_ip, ucp);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Sending neighbor advertisement message, ether from %@ to %@",
             ssh_engine_arp_render_eth_mac, own_hw,
             ssh_engine_arp_render_eth_mac, dst_hw));
  SSH_DUMP_PACKET(SSH_D_LOWSTART, "NA packet", pp);

  /* Encapsulate the packet in an ethernet header.  We send the packet to
     destination hw address. */
  ssh_engine_encapsulate_and_send(engine, pp, own_hw, dst_hw,
                                  SSH_ETHERTYPE_IPv6);
}


/* Add an entry to the ARP cache, but only if there was an request
   entry present. req_required variable tells if request has to be
   present or not. */
void engine_arp_process_neighbor_advertisement(SshEngine engine,
                                               SshIpAddr ip_addr,
                                               SshEngineIfnum ifnum,
                                               const unsigned char *hw,
                                               SshUInt8 na_flags)
{
  SshUInt32 hash;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry;
  SshEnginePacketContext queued_pc = NULL;
  SshTime now;
  Boolean reroute_nh = FALSE, complete = FALSE, update_nh = FALSE,
    remove_from_retry_list = FALSE;

  ssh_interceptor_get_time(&now, NULL);

  SSH_ASSERT(SSH_IP_IS6(ip_addr) == TRUE);
  SSH_ASSERT(hw != NULL);

  /* Compute the hash value. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(ip_addr);

  /* Take the interface lock to access protected data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  for (entry = cache->hash[hash]; entry != NULL; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
        break;
    }

  /* Ignore the neigbor advertisement if there is no corresponding
     entry in our ND cache. */
  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("No cache entry found for %ssolicited NA for address %@",
                 ((na_flags & SSH_ICMP6H_NA_FLAG_SOLICITED) ?
                  "" : "un"),
                 ssh_ipaddr_render, ip_addr));
      goto drop;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Cache entry %@ found for NA",
                          ssh_engine_arp_entry_render, entry));

  /* Check if neighbor advertisement matched a permanent entry. */
  if (entry->status == SSH_ENGINE_ARP_PERMANENT)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Ignoring NA that matched a permanent ARP entry"));
      goto drop;
    }

  /* Neighbor advertisement matched an incomplete entry. */
  else if (entry->status == SSH_ENGINE_ARP_INCOMPLETE)
    {
      /* Store the received link address to entry. */
      SSH_DEBUG(SSH_D_LOWOK, ("Updating hw addr %@ to entry",
                              ssh_engine_arp_render_eth_mac, hw));
      memcpy(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr));
      complete = TRUE;

      if (na_flags & SSH_ICMP6H_NA_FLAG_ROUTER)
        entry->flags |= SSH_ENGINE_ARP_F_ROUTER;

      if (na_flags & SSH_ICMP6H_NA_FLAG_SOLICITED)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to complete"));
          entry->status = SSH_ENGINE_ARP_COMPLETE;
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to stale"));
          entry->status = SSH_ENGINE_ARP_STALE;
          reroute_nh = TRUE;
        }

      goto out;
    }

  /* Neighbor advertisement matched a non-incomplete entry. */

  /* NA did not have the override flag set but advertised a different
     link address. */
  if ((na_flags & SSH_ICMP6H_NA_FLAG_OVERRIDE) == 0
      && memcmp(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr)) != 0)
    {
      /* Move entry status from complete to stale. */
      if (entry->status == SSH_ENGINE_ARP_COMPLETE)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Non-overriding NA for different hw address, "
                     "changing entry status to stale"));
          entry->status = SSH_ENGINE_ARP_STALE;
          remove_from_retry_list = TRUE;
          reroute_nh = TRUE;
        }

      /* Ignore NA for non-complete entries. */
      else
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Ignoring non-overriding NA for entry %@",
                                  ssh_engine_arp_entry_render, entry));
          goto drop;
        }
    }

  /* NA had the override flag set or link address has not changed. */
  else
    {
      if (memcmp(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr)) != 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Updating hw addr %@ to entry",
                                  ssh_engine_arp_render_eth_mac, hw));
          memcpy(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr));

          /* Update nh nodes. */
          update_nh = TRUE;

          if ((na_flags & SSH_ICMP6H_NA_FLAG_SOLICITED) == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to stale"));
              entry->status = SSH_ENGINE_ARP_STALE;
              remove_from_retry_list = TRUE;
              reroute_nh = TRUE;
            }
          else
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to complete"));
              entry->status = SSH_ENGINE_ARP_COMPLETE;
              complete = TRUE;
            }
        }
      else
        {
          if (na_flags & SSH_ICMP6H_NA_FLAG_SOLICITED)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to complete"));
              entry->status = SSH_ENGINE_ARP_COMPLETE;
              complete = TRUE;
            }
        }

      if (na_flags & SSH_ICMP6H_NA_FLAG_ROUTER)
        entry->flags |= SSH_ENGINE_ARP_F_ROUTER;
    }

 out:
  if (remove_from_retry_list == TRUE)
    engine_arp_retry_list_remove(engine, entry);

  if (complete == TRUE)
    {
      /* Set expiry time. */
      engine_arp_entry_set_expiry_timeout(engine, entry, now);
      entry->retry_timeout_sec = 0;
      entry->retry_timeout_usec = 0;
      entry->arp_retry_count = 0;

      /* Remove from retry list. */
      engine_arp_retry_list_remove(engine, entry);

      /* Bump the ARP entry to the beginning of the list. */
      engine_arp_lru_bump(engine, entry, FALSE);

      /* Continue processing of the queued packet (if any). */
      queued_pc = entry->queued_packet;
      entry->queued_packet = NULL;
      entry->queued_packet_nh_index = SSH_IPSEC_INVALID_INDEX;
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Mark matching next hop nodes for rerouting. */
  if (reroute_nh == TRUE)
    ssh_engine_nh_node_reroute(engine, ip_addr, 8 * SSH_IP_ADDR_LEN(ip_addr),
                               ifnum);

  /* Update matching next hop nodes. */
  if (update_nh == TRUE)
    ssh_engine_update_nh_node_mac(engine, ip_addr, ifnum, hw);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (queued_pc != NULL)
    engine_arp_complete_pc(engine, SSH_ENGINE_ARP_LOOKUP_STATUS_OK,
                           queued_pc, ip_addr, hw);
  return;

 drop:
  ssh_kernel_mutex_unlock(engine->interface_lock);
}


/* Processes an incoming IPv6 neighbor advertisement packet.  This
   function will update the arp table as appropriate, and will cause
   the SshEngineArpComplete callback to be called for any pending
   requests completed by this packet.  The packet in `pp' should not
   contain media header, but the media header should be saved in
   pd->mediahdr.  Normally, this will not free `pp' and returns TRUE,
   because the packet will normally also be passed to the host TCP/IP
   stack.  If an error causes the packet to be freed, this returns
   FALSE.

   This function can be called concurrently.  This will momentarily lock
   the engine lock to modify the cache data structures. */

Boolean ssh_engine_arp_recv_neighbor_advertisement(SshEngine engine,
                                                   SshEnginePacketContext pc)
{
  const unsigned char *ucp;
  size_t offset, optlen;
  unsigned char opthdr[4], target_hw[SSH_ETHERH_ADDRLEN];
  SshIpAddrStruct target_ip;
  Boolean link_address_found = FALSE;
  SshEnginePacketData pd;
  SshUInt8 na_flags = 0;
  unsigned char pullup_buf[SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN];

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Neighbor advertisement input (protocol %d pp flags 0x%lx)",
             pc->pp->protocol, (unsigned long) pc->pp->flags));

  /* Do sanity checks that the packet is of proper type, comes from
     the network, and that it is long enough to contain the IPv6
     Neighbor advertisement ICMP header, which is at least
     SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN (=24) bytes long. */
  if (pc->pp->protocol != SSH_PROTOCOL_IP6
      || pc->packet_len < pc->hdrlen + SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("NA not IPv6 or too short: protocol %d length %d",
                 (int) pc->pp->protocol, (int) pc->packet_len));
      return TRUE;
    }

  /* Pullup neighbor advertisement. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen,
                            SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN,
                            pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
      return FALSE;
    }

  /* Check that this ICMPv6 is a neighbor advertisement. */
  if (SSH_ICMP6H_TYPE(ucp) != SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT
      || SSH_ICMP6H_CODE(ucp) != 0)
    {
      SSH_DEBUG(SSH_D_MIDRESULT,
                ("Not handled because ICMPv6 type %d code %d not NA",
                 SSH_ICMP6H_TYPE(ucp), SSH_ICMP6H_CODE(ucp)));
      return TRUE;
    }

  /* Decode and sanity check target address. */
  SSH_ICMP6H_NA_TARGETADDR(&target_ip, ucp);
  if (SSH_IP_IS_MULTICAST(&target_ip) || pc->u.rule.ttl != 255)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("NA fails checks: target %@ hoplimit %d",
                 ssh_ipaddr_render, &target_ip, (int) pc->u.rule.ttl));
      return TRUE;
    }

  /* Decode and sanity check flags. */
  na_flags = SSH_ICMP6H_NA_FLAGS(ucp);
  if (na_flags & ~SSH_ICMP6H_NA_FLAGMASK)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("NA reserved field not zero: %x",
                                (na_flags & ~SSH_ICMP6H_NA_FLAGMASK)));
      na_flags &= SSH_ICMP6H_NA_FLAGMASK;
    }

  if (SSH_IP_IS_MULTICAST(&pc->dst) == TRUE
      && (na_flags & SSH_ICMP6H_NA_FLAG_SOLICITED))
    {
      SSH_DEBUG(SSH_D_MIDRESULT,
                ("Ignoring solicited NA sent to multicast destination %@",
                 ssh_ipaddr_render, &pc->dst));
      return TRUE;
    }

  /* Verify ICMPv6 cksum. */
  if (engine_arp_ipv6_verify_cksum(pc) == FALSE)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("NA ICMPv6 checksum failure"));

      /* Drop packet. */
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  /* There are two possibilities regarding the media address. Either
     there is ICMPv6 Target link-layer Address option (which is
     preferred), or if that is not present then we should have cached
     media address (in packet data). If neither requirement can be
     satisfied, then we will not process the packet further. */
  for (offset = (pc->hdrlen + SSH_ICMP6_NEIGHBOR_ADVERTISEMENT_MINLEN);
       (offset + 2) < pc->packet_len;
       offset += optlen)
    {
      /* Fetch option header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_ICMP6H_ND_OPTION_HDRLEN,
                                opthdr);
      if (ucp == NULL)
        {
          pc->pp = NULL;
          SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
          return FALSE;
        }

      /* Decode and sanity check option length. */
      optlen = SSH_ICMP6H_ND_OPTION_LENB(ucp);
      if (optlen == 0 || (offset + optlen > pc->packet_len))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("NA with bad optlen %d", (int) optlen));
          return TRUE;
        }

      /* We are only interested in the target link address option. */
      if (SSH_ICMP6H_ND_OPTION_TYPE(ucp)
          == SSH_ICMP6_NEIGHDISC_OPT_TARGET_LINK_ADDRESS)
        {
          /* Sanity check that the link-level address length is correct. */
          if ((optlen - SSH_ICMP6H_ND_OPTION_HDRLEN) != SSH_ETHERH_ADDRLEN)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("NA with invalid link layer address length %d",
                         optlen - SSH_ICMP6H_ND_OPTION_HDRLEN));
              return TRUE;
            }

          /* Copy out the target link address. */
          ssh_interceptor_packet_copyout(pc->pp,
                                         offset + SSH_ICMP6H_ND_OPTION_HDRLEN,
                                         target_hw, SSH_ETHERH_ADDRLEN);
          link_address_found = TRUE;

          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Target link address option found, target %@",
                     ssh_engine_arp_render_eth_mac, target_hw));
          break;
        }
    }

  /* RFC4861, 4.4: "When responding to unicast solicitations, the option
     can be omitted since the sender of the solicitation has the correct
     link-layer address". Thus if no target link address option was found
     in the advertisement message, then take the target link address from
     the cached media header. */
  pd = SSH_INTERCEPTOR_PACKET_DATA(pc->pp, SshEnginePacketData);
  if (link_address_found == FALSE &&
      pd->mediatype == SSH_INTERCEPTOR_MEDIA_ETHERNET)
    {
      memcpy(target_hw, pd->mediahdr + SSH_ETHERH_OFS_SRC, SSH_ETHERH_ADDRLEN);
      link_address_found = TRUE;

      SSH_DEBUG(SSH_D_MIDSTART, ("NA with cached target media address %@",
                                 ssh_engine_arp_render_eth_mac, target_hw));
    }

  /* If the NA is from local stack and no link address was found from
     the target link address option or cached media header, then take
     the link address from the interface. */
  if (link_address_found == FALSE && (pc->pp->flags & SSH_PACKET_FROMPROTOCOL))
    {
      ssh_kernel_mutex_lock(engine->interface_lock);
      if (engine_arp_get_hwaddr(engine, pc->pp->ifnum_in, target_hw) == TRUE)
        {
          SSH_DEBUG(SSH_D_MIDSTART,
                    ("Taking target hw address %@ from interface %u",
                     ssh_engine_arp_render_eth_mac, target_hw,
                     pc->pp->ifnum_in));
          link_address_found = TRUE;
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);
    }

  /* If no link media address found, nor cached, do not continue. */
  if (link_address_found == FALSE)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("No link level address or cached media address found "
                 "for ICMPv6 NA message, passing unhandled."));
      return TRUE;
    }

  /* Sanity check that the media address is not a multicast/broadcast
     address. */
  if (SSH_ETHER_IS_MULTICAST(target_hw))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("NA for target multicast hw addr %@",
                                ssh_engine_arp_render_eth_mac, target_hw));
      return TRUE;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Neighbor advertisement for target %@ hw %@ ifnum %u flags 0x%x "
             "[%s%s%s]",
             ssh_ipaddr_render, &target_ip,
             ssh_engine_arp_render_eth_mac, target_hw,
             pc->pp->ifnum_in, na_flags,
             ((na_flags & SSH_ICMP6H_NA_FLAG_ROUTER) ? "router " : ""),
             ((na_flags & SSH_ICMP6H_NA_FLAG_SOLICITED) ? "solicited " : ""),
             ((na_flags & SSH_ICMP6H_NA_FLAG_OVERRIDE) ? "override" : "")));

  /* Add the received address to the cache.  This will cause the callback to
     be called, if there is any, and update the cache if there is an entry for
     it. */
  engine_arp_process_neighbor_advertisement(engine, &target_ip,
                                            pc->pp->ifnum_in, target_hw,
                                            na_flags);
  return TRUE;
}

void engine_arp_process_neighbor_solicitation(SshEngine engine,
                                              SshIpAddr ip_addr,
                                              SshEngineIfnum ifnum,
                                              const unsigned char *hw)
{
  SshEngineArpCacheEntry entry;
  SshUInt32 hash;
  SshTime now;
  Boolean reroute_nh;
  SshEnginePacketContext queued_pc;

  reroute_nh = FALSE;
  queued_pc = NULL;
  ssh_interceptor_get_time(&now, NULL);

  /* Compute the hash value. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(ip_addr);

  /* Take the interface lock to access protected data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Find the entry from the hash table slot. */
  for (entry = engine->arp_cache.hash[hash];
       entry != NULL;
       entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
        break;
    }

  /* No ARP entry found, create a new one. */
  if (entry == NULL)
    {
      entry = engine_arp_cache_new_entry(engine);
      if (entry == NULL)
        {

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Could not allocate a new ARP entry from incoming NS for "
                     "IP %@ HW %@ ifnum %u",
                     ssh_ipaddr_render, ip_addr,
                     ssh_engine_arp_render_eth_mac, hw,
                     ifnum));
          ssh_kernel_mutex_unlock(engine->interface_lock);
          return;
        }

      /* Initialize the arp cache entry. */
      entry->ip_addr = *ip_addr;
      memcpy(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr));
      entry->ifnum = ifnum;

      entry->status = SSH_ENGINE_ARP_STALE;
      entry->arp_retry_count = 0;

      entry->expires = now + SSH_ENGINE_ARP_INCOMPLETE_LIFETIME;

      /* Add the entry into the hash table and lru list. */
      engine_arp_hash_insert(engine, entry);
      engine_arp_lru_bump(engine, entry, TRUE);

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Created entry %@",
                                   ssh_engine_arp_entry_render, entry));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;
    }

  /* An existing ARP entry was found. */
  SSH_DEBUG(SSH_D_LOWOK, ("Found matching ARP entry %@",
                          ssh_engine_arp_entry_render, entry));

  /* Check entry status. Ignore NS for permanent entries and for incomplete
     entries (that is require that a valid NA is received for completing the
     entry). */
  if (entry->status == SSH_ENGINE_ARP_PERMANENT)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;
    }

  /* Check if the link address differs from the entry's link address. */
  if (memcmp(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr)) == 0)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return;
    }

  /* Update entry's link address. */
  SSH_DEBUG(SSH_D_LOWOK, ("Updating link address in ARP entry"));
  memcpy(entry->ethernet_addr, hw, sizeof(entry->ethernet_addr));

  /* Stop retransmits or probes. */
  if (entry->status == SSH_ENGINE_ARP_INCOMPLETE
      || entry->status == SSH_ENGINE_ARP_PROBE)
    {
      entry->arp_retry_count = 0;
      engine_arp_retry_list_remove(engine, entry);
      entry->retry_timeout_sec = 0;
      entry->retry_timeout_usec = 0;
    }
  SSH_ASSERT((entry->flags & SSH_ENGINE_ARP_F_ON_RETRY_LIST) == 0);
  SSH_ASSERT(entry->flags & SSH_ENGINE_ARP_F_IN_HASH);

  /* Continue processing of the queued packet. */
  queued_pc = entry->queued_packet;
  entry->queued_packet = NULL;
  entry->queued_packet_nh_index = SSH_IPSEC_INVALID_INDEX;

  /* Change entry status to stale. */
  if (entry->status != SSH_ENGINE_ARP_STALE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to stale"));
      entry->status = SSH_ENGINE_ARP_STALE;
      entry->expires = now + SSH_ENGINE_ARP_INCOMPLETE_LIFETIME;
      reroute_nh = TRUE;
    }

  /* Bump the ARP entry to the beginning of the list. */
  engine_arp_lru_bump(engine, entry, FALSE);

  /* Release the engine lock. */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Mark matching next hops for rerouting. */
  if (reroute_nh == TRUE)
    ssh_engine_nh_node_reroute(engine, ip_addr, 8 * SSH_IP_ADDR_LEN(ip_addr),
                               ifnum);

  /* Update link address in matching next hop nodes. */
  ssh_engine_update_nh_node_mac(engine, ip_addr, ifnum, hw);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (queued_pc != NULL)
    engine_arp_complete_pc(engine, SSH_ENGINE_ARP_LOOKUP_STATUS_OK, queued_pc,
                           ip_addr, hw);
}

/* Processes an IPv6 neighbor solicitation packet. This
   function will update the arp table as appropriate, and reply to
   the solicitation if it is an neighbor discovery. The packet
   in `pp' should not contain media header, but the media header
   should be saved in pd->mediahdr.  Normally, this will not free
   `pp' and returns TRUE, because the packet will normally also be
   passed to the host TCP/IP stack.  If an error causes the packet
   to be freed, this returns FALSE.

   This function can be called concurrently.  This will momentarily lock
   the engine lock to modify the cache data structures. */

Boolean ssh_engine_arp_recv_neighbor_solicitation(SshEngine engine,
                                                  SshEnginePacketContext pc)
{
  const unsigned char *ucp;
  size_t offset, optlen;
  unsigned char opthdr[4], src_hw[SSH_ETHERH_ADDRLEN];
  unsigned char target_hw[SSH_ETHERH_ADDRLEN];
  SshIpAddrStruct target_ip;
  Boolean src_address_option = FALSE, src_address_cached = FALSE;
  SshEnginePacketData pd;
  unsigned char pullup_buf[SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN];
  SshIpAddrStruct own_ip;
  unsigned char own_hw[SSH_ETHERH_ADDRLEN];
  Boolean ret;
  Boolean solicited = TRUE;
  Boolean override = TRUE;
  Boolean outgoing = TRUE;
  SshEngineArpCacheEntry entry;
  SshTime now_sec;
  SshUInt32 now_usec;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->pp != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Neighbor solicitation input (protocol %d pp flags 0x%lx)",
             pc->pp->protocol, (unsigned long) pc->pp->flags));

  /* Do sanity checks that the packet is of proper type and that it
     is long enough to contain the IPv6 Neighbor solicitation ICMP
     header, which is at least 24 bytes long. */
  if (pc->pp->protocol != SSH_PROTOCOL_IP6
      || pc->packet_len < pc->hdrlen + SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("NS not IPv6 or too short: protocol %d length %d",
                 (int) pc->pp->protocol, (int) pc->packet_len));
      return TRUE;
    }

  /* Pullup neighbor solicitation. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen,
                            SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN,
                            pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
      return FALSE;
    }

  /* Check that this ICMPv6 is a neighbor advertisement. */
  if (SSH_ICMP6H_TYPE(ucp) != SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION
      || SSH_ICMP6H_CODE(ucp) != 0)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("ICMPv6 type %d code %d not NS",
                 SSH_ICMP6H_TYPE(ucp), SSH_ICMP6H_CODE(ucp)));
      return TRUE;
    }

  /* Decode and sanity check target address, sanity check NS hoplimit. */
  SSH_ICMP6H_NS_TARGETADDR(&target_ip, ucp);
  if (SSH_IP_IS_MULTICAST(&target_ip) || pc->u.rule.ttl != 255)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("NA fails checks: target %@ hoplimit %d",
                 ssh_ipaddr_render, &target_ip, (int) pc->u.rule.ttl));
      return TRUE;
    }

  /* Verify ICMPv6 cksum. */
  if (engine_arp_ipv6_verify_cksum(pc) == FALSE)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("NS ICMPv6 checksum failure"));

      /* Drop packet. */
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  /* There are two possibilities regarding the media address. Either
     there is ICMPv6 Source link-layer Address option (which is
     preferred), or if that is not present then we should have cached
     media address (in packet data). If neither requirement can be
     satisfied, then we will not process the packet further. */
  for (offset = pc->hdrlen + SSH_ICMP6_NEIGHBOR_SOLICITATION_MINLEN;
       offset + 2 < pc->packet_len;
       offset += optlen)
    {
      /* Fetch option header from the packet. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_ICMP6H_ND_OPTION_HDRLEN,
                                opthdr);
      if (ucp == NULL)
        {
          pc->pp = NULL;
          SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
          return FALSE;
        }

      /* Decode and sanity check option length. */
      optlen = SSH_ICMP6H_ND_OPTION_LENB(ucp);
      if (optlen == 0 || offset + optlen > pc->packet_len)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("NS with bad optlen %d", (int) optlen));
          return TRUE;
        }

      /* We are only interested in source link address options. */
      if (SSH_ICMP6H_ND_OPTION_TYPE(ucp)
          == SSH_ICMP6_NEIGHDISC_OPT_SOURCE_LINK_ADDRESS)
        {
          /* Sanity check that the link-level address is not too long. */
          if ((optlen - SSH_ICMP6H_ND_OPTION_HDRLEN) != SSH_ETHERH_ADDRLEN)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("NS with invalid link layer address length %d",
                         optlen - SSH_ICMP6H_ND_OPTION_HDRLEN));
              return TRUE;
            }
          SSH_DEBUG(SSH_D_MIDSTART, ("Source link address option found"));

          /* Copy out the source link address. */
          ssh_interceptor_packet_copyout(pc->pp,
                                         offset + SSH_ICMP6H_ND_OPTION_HDRLEN,
                                         src_hw, SSH_ETHERH_ADDRLEN);
          src_address_option = TRUE;
          break;
        }
    }

  /* Take source link-layer address from the cached media header. */
  pd = SSH_INTERCEPTOR_PACKET_DATA(pc->pp, SshEnginePacketData);
  if (!src_address_option && pd->mediatype == SSH_INTERCEPTOR_MEDIA_ETHERNET)
    {
      memcpy(src_hw, pd->mediahdr + SSH_ETHERH_OFS_SRC, sizeof(src_hw));
      src_address_cached = TRUE;

      SSH_DEBUG(SSH_D_MIDSTART, ("NS with cached media address %@",
                                 ssh_engine_arp_render_eth_mac, src_hw));
    }

  /* If no link media address found, nor cached, do not continue. */
  if (!src_address_option && !src_address_cached)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("No link level address or cached media address found "
                 "for ICMPv6 NS message, passing unhandled."));
      return TRUE;
    }

  /* Sanity check that the media address is not a multicast/broadcast
     address. */
  if (SSH_ETHER_IS_MULTICAST(src_hw))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("NS for source multicast hw address %@",
                 ssh_engine_arp_render_eth_mac, src_hw));
      return TRUE;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("Neighbor solicitation for target %@ ifnum %u "
             "source address %@ hw %@",
             ssh_ipaddr_render, &target_ip,
             pc->pp->ifnum_in,
             ssh_ipaddr_render, &pc->src,
             ssh_engine_arp_render_eth_mac, src_hw));

  /* Add source address to neighbor cache if solicitation came from network.
     Note: ssh_engine_arp_add() does not call the completition callbacks
     for pending ARP entries. A full neigh sol - neigh adv pair is needed
     for a compeleted ARP resolution. */

  /* RFC4861:

     If the Source Address is not the unspecified
     address and, on link layers that have addresses, the solicitation
     includes a Source Link-Layer Address option, then the recipient
     SHOULD create or update the Neighbor Cache entry for the IP Source
     Address of the solicitation.  If an entry does not already exist, the
     node SHOULD create a new one and set its reachability state to STALE
     as specified in Section 7.3.3.  If an entry already exists, and the
     cached link-layer address differs from the one in the received Source
     Link-Layer option, the cached address should be replaced by the
     received address, and the entry's reachability state MUST be set to
     STALE. */
  if ((pc->pp->flags & SSH_PACKET_FROMADAPTER) &&
      !SSH_IP_IS_NULLADDR(&pc->src) &&
      src_address_option)
    {
      engine_arp_process_neighbor_solicitation(engine, &pc->src,
                                               pc->pp->ifnum_in, src_hw);
    }

  /* Let duplicate address detection neighbor solicitations from local
     stack go through. DAD packets have solicited node multicast IPv6 dst,
     undefined IPv6 src, and local ICMPv6 neighbor solicitation target.

     Implementation note: The interceptor might have not yet sent the
     interface information to engine. In such case ssh_engine_ip_is_local()
     returns FALSE. But so does engine_arp_lookup_entry(), as the
     local addresses are added to ARP cache when receiving interface
     information. The result is that the solicitation will go through
     unmodified. */

  if ((pc->pp->flags & SSH_PACKET_FROMPROTOCOL) &&
      SSH_IP_IS_NULLADDR(&pc->src) &&
      SSH_IP_IS_MULTICAST(&pc->dst) &&
      ssh_engine_ip_is_local(engine, &target_ip))
    {
      SSH_DEBUG(SSH_D_MIDOK, ("NS for address %@ is DAD",
                              ssh_ipaddr_render, &target_ip));
      return TRUE;
    }

  /* Lookup the IP address from the ARP cache. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  entry = engine_arp_lookup_entry(engine, &target_ip, pc->pp->ifnum_in);
  if (entry != NULL)
    {
      /* Reply to neigh sols from local stack to multicast addresses
         or from network with a target address we are proxy arping. */
      if (((pc->pp->flags & SSH_PACKET_FROMPROTOCOL) &&
           SSH_IP6_IS_MULTICAST(&pc->dst))
          || (entry->flags & SSH_ENGINE_ARP_F_PROXY))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Sending NA for target %@ hw %@ flags 0x%x",
                     ssh_ipaddr_render, &target_ip,
                     ssh_engine_arp_render_eth_mac, entry->ethernet_addr,
                     (unsigned int) entry->flags));

          /* Fetch our interface's IP address */

          /* Try looking first with the destination address (pc->src here).
             So prefer addresses with same scope. */
          ret = ssh_engine_get_ipaddr(engine, pc->pp->ifnum_in,
                                      SSH_PROTOCOL_IP6, &pc->src, &own_ip);
          if (ret == FALSE)
            ret = ssh_engine_get_ipaddr(engine, pc->pp->ifnum_in,
                                        SSH_PROTOCOL_IP6, NULL, &own_ip);

          /* Fetch our interface's hw address */
          ret &= engine_arp_get_hwaddr(engine, pc->pp->ifnum_in, own_hw);

          /* If we are doing proxy ARP, reply with our interface's
             address. */
          if (entry->flags & SSH_ENGINE_ARP_F_PROXY)
            {
              memcpy(target_hw, own_hw, SSH_ETHERH_ADDRLEN);
              override = FALSE;
            }
          else
            {
              memcpy(target_hw, entry->ethernet_addr, SSH_ETHERH_ADDRLEN);
            }

          /* If the entry is stale, start probing the known hw address. */
          if (entry->status == SSH_ENGINE_ARP_STALE)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to probe"));
              entry->status = SSH_ENGINE_ARP_PROBE;
              entry->arp_retry_count = SSH_ENGINE_ARP_IPV6_MAX_UCAST_RETRIES;

              /* Add entry to retry list. */
              engine_arp_retry_list_insert(engine, entry);

              /* Schedule retry timeout to immediate future, the probe is
                 sent from the retry timeout. */
              ssh_interceptor_get_time(&now_sec, &now_usec);
              entry->retry_timeout_sec = now_sec;
              entry->retry_timeout_usec = now_usec;
              engine_arp_request_timeout_schedule(engine,
                                                  entry->retry_timeout_sec,
                                                  entry->retry_timeout_usec,
                                                  now_sec, now_usec);
            }

          ssh_kernel_mutex_unlock(engine->interface_lock);

          /* RFC4861:
             If the source of the solicitation is the unspecified address,
             the node MUST set the Solicited flag to zero and multicast the
             advertisement to the all-nodes address.Otherwise, the node MUST
             set the Solicited flag to one and unicast the advertisement to
             the Source Address of the solicitation. */
          solicited = TRUE;
          if (SSH_IP_IS_NULLADDR(&pc->src))
            {
              unsigned char addr[16];

              memset(addr, 0, 16);
              addr[0] = 0xff;
              addr[1] = 0x02;
              addr[15] = 0x01;

              SSH_IP6_DECODE(&pc->src, addr);
              src_hw[0] = 0x33;
              src_hw[1] = 0x33;
              src_hw[2] = addr[12];
              src_hw[3] = addr[13];
              src_hw[4] = addr[14];
              src_hw[5] = addr[15];

              solicited = FALSE;
            }

          if (pc->pp->flags & SSH_PACKET_FROMPROTOCOL)
            outgoing = FALSE;

          /* Reply for this neighbour advertisement. */
          if (ret == TRUE)
            ssh_engine_arp_send_advertisement(engine,
                                              outgoing,
                                              pc->pp->ifnum_in,
                                              pc->pp->routing_instance_id,
                                              &pc->src, src_hw,
                                              &target_ip, target_hw,
                                              &own_ip, own_hw,
                                              FALSE, /* router flag */
                                              solicited,
                                              override);

          /* Done with the packet. */
          ssh_interceptor_packet_free(pc->pp);
          pc->pp = NULL;

          /* Drop the solicitation */
          return FALSE;
        }
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Let the solicitation continue to network / protocol. */
  return TRUE;
}


/****************** Default router and prefix lists **************************/

SshEngineArpRouterInfo
engine_arp_router_info_lookup(SshEngine engine,
                              SshEngineIfInfo if_info,
                              SshIpAddr router_addr)
{
  SshEngineArpRouterInfo router_info;

  SSH_ASSERT(SSH_IP_IS6(router_addr));
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  for (router_info = if_info->router_list;
       router_info != NULL;
       router_info = router_info->next)
    {
      if (SSH_IP_EQUAL(&router_info->router_addr, router_addr))
        return router_info;
    }

  return NULL;
}

SshEngineArpRouterInfo
engine_arp_router_info_create(SshEngine engine,
                              SshEngineIfInfo if_info,
                              SshIpAddr router_addr,
                              SshEngineIfnum ifnum)
{
  SshEngineArpRouterInfo router_info;

  SSH_ASSERT(SSH_IP_IS6(router_addr));
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  router_info = ssh_calloc(1, sizeof(*router_info));
  if (router_info == NULL)
    return NULL;

  router_info->router_addr = *router_addr;
  router_info->ifnum = ifnum;

  router_info->next = if_info->router_list;
  if_info->router_list = router_info;

  return router_info;
}

void
engine_arp_router_info_free(SshEngine engine,
                            SshEngineArpRouterInfo router_info)
{
  /* Assert that the interface lock is taken (in case router_info
     objects are freelisted sometime in the future). */
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing router info"));
  ssh_free(router_info);
}


SshEngineArpPrefixInfo
engine_arp_prefix_info_lookup(SshEngine engine,
                              SshEngineIfInfo if_info,
                              SshIpAddr prefix,
                              SshIpAddr router_addr)
{
  SshEngineArpPrefixInfo prefix_info;

  SSH_ASSERT(SSH_IP_IS6(router_addr));
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  for (prefix_info = if_info->prefix_list;
       prefix_info != NULL;
       prefix_info = prefix_info->next)
    {
      if (SSH_IP_EQUAL(&prefix_info->prefix, prefix)
          && SSH_IP_MASK_LEN(&prefix_info->prefix) == SSH_IP_MASK_LEN(prefix)
          && SSH_IP_EQUAL(&prefix_info->router_addr, router_addr))
        return prefix_info;
    }

  return NULL;
}

SshEngineArpPrefixInfo
engine_arp_prefix_info_create(SshEngine engine,
                              SshEngineIfInfo if_info,
                              SshIpAddr prefix,
                              SshIpAddr router_addr,
                              SshEngineIfnum ifnum)
{
  SshEngineArpPrefixInfo prefix_info;

  SSH_ASSERT(SSH_IP_IS6(prefix));
  SSH_ASSERT(SSH_IP_IS6(router_addr));
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  prefix_info = ssh_calloc(1, sizeof(*prefix_info));
  if (prefix_info == NULL)
    return NULL;

  prefix_info->prefix = *prefix;
  prefix_info->prefix = *router_addr;
  prefix_info->ifnum = ifnum;

  prefix_info->next = if_info->prefix_list;
  if_info->prefix_list = prefix_info;

  return prefix_info;
}

void
engine_arp_prefix_info_free(SshEngine engine,
                            SshEngineArpPrefixInfo prefix_info)
{
  /* Assert that the interface lock is taken (in case prefix_info
     objects are freelisted sometime in the future). */
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  SSH_DEBUG(SSH_D_LOWOK, ("Freeing prefix info"));
  ssh_free(prefix_info);
}

void
engine_arp_router_info_timeout(SshEngine engine,
                               SshEngineIfInfo if_info,
                               SshEngineArpRouterInfo *router_destroy_list,
                               SshTime now)
{
  SshEngineArpRouterInfo router_info, prev_router_info, next_router_info;
  int num_routers = 0;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(router_destroy_list != NULL);

  /* Process default router list. */
  prev_router_info = NULL;
  for (router_info = if_info->router_list;
       router_info != NULL;
       router_info = next_router_info)
    {
      next_router_info = router_info->next;
      if (router_info->ra_received + router_info->lifetime <= now)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Timing out default router %@ ifnum %u lifetime %lu "
                     "now %lu",
                     ssh_ipaddr_render, &router_info->router_addr,
                     router_info->ifnum,
                     router_info->ra_received + router_info->lifetime,
                     now));

          /* Remove from router list. */
          if (prev_router_info == NULL)
            {
              SSH_ASSERT(if_info->router_list == router_info);
              if_info->router_list = router_info->next;
            }
          else
            {
              prev_router_info->next = router_info->next;
            }

          /* Add router to destroy list. */
          router_info->next = *router_destroy_list;
          *router_destroy_list = router_info;
        }
      else
        {
          num_routers++;
          prev_router_info = router_info;
        }
    }

  /* Save only SSH_ENGINE_ARP_MAX_IPV6_PREFIXES and free any overflowing
     prefixes from the tail of prefix list. */
  if (num_routers > SSH_ENGINE_ARP_MAX_IPV6_ROUTERS)
    {
      num_routers = 0;
      for (router_info = if_info->router_list;
           router_info != NULL;
           router_info = router_info->next)
        {
          if (++num_routers > SSH_ENGINE_ARP_MAX_IPV6_ROUTERS)
            break;
        }

      SSH_ASSERT(router_info != NULL);
      next_router_info = router_info->next;
      router_info->next = NULL;

      for (router_info = next_router_info;
           router_info != NULL;
           router_info = next_router_info)
        {
          next_router_info = router_info->next;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Freeing default router %@ ifnum %u lifetime %lu now %lu",
                     ssh_ipaddr_render, &router_info->router_addr,
                     router_info->ifnum,
                     router_info->ra_received + router_info->lifetime,
                     now));

          /* Add prefix to destroy list. */
          router_info->next = *router_destroy_list;
          *router_destroy_list = router_info;
        }
    }
}


void
engine_arp_prefix_info_timeout(SshEngine engine,
                               SshEngineIfInfo if_info,
                               SshEngineArpPrefixInfo *prefix_destroy_list,
                               SshTime now)
{
  SshEngineArpPrefixInfo prefix_info, prev_prefix_info, next_prefix_info;
  int num_prefixes = 0;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
  SSH_ASSERT(prefix_destroy_list != NULL);

  /* Process prefix list. */
  prev_prefix_info = NULL;
  for (prefix_info = if_info->prefix_list;
       prefix_info != NULL;
       prefix_info = next_prefix_info)
    {
      next_prefix_info = prefix_info->next;
      if (prefix_info->ra_received + prefix_info->validity_time <= now)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Timing out prefix %@ ifnum %u validity time %lu now %lu",
                     ssh_ipaddr_render, &prefix_info->prefix,
                     prefix_info->ifnum,
                     prefix_info->ra_received + prefix_info->validity_time,
                     now));

          /* Remove from prefix list. */
          if (prev_prefix_info == NULL)
            {
              SSH_ASSERT(if_info->prefix_list == prefix_info);
              if_info->prefix_list = prefix_info->next;
            }
          else
            {
              prev_prefix_info->next = prefix_info->next;
            }

          /* Add prefix to destroy list. */
          prefix_info->next = *prefix_destroy_list;
          *prefix_destroy_list = prefix_info;
        }
      else
        {
          num_prefixes++;
          prev_prefix_info = prefix_info;
        }
    }

  /* Save only SSH_ENGINE_ARP_MAX_IPV6_PREFIXES and free any overflowing
     prefixes from the tail of prefix list. */
  if (num_prefixes > SSH_ENGINE_ARP_MAX_IPV6_PREFIXES)
    {
      num_prefixes = 0;
      for (prefix_info = if_info->prefix_list;
           prefix_info != NULL;
           prefix_info = prefix_info->next)
        {
          if (++num_prefixes > SSH_ENGINE_ARP_MAX_IPV6_PREFIXES)
            break;
        }

      SSH_ASSERT(prefix_info != NULL);
      next_prefix_info = prefix_info->next;
      prefix_info->next = NULL;

      for (prefix_info = next_prefix_info;
           prefix_info != NULL;
           prefix_info = next_prefix_info)
        {
          next_prefix_info = prefix_info->next;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Freeing prefix %@ ifnum %u validity time %lu now %lu",
                     ssh_ipaddr_render, &prefix_info->prefix,
                     prefix_info->ifnum,
                     prefix_info->ra_received + prefix_info->validity_time,
                     now));

          /* Add prefix to destroy list. */
          prefix_info->next = *prefix_destroy_list;
          *prefix_destroy_list = prefix_info;
        }
    }
}


/********************** Receiving router advertisements **********************/

/* Processes an IPv6 router advertisement packet. This
   function will update the arp parameters as appropriate.

   If FALSE is returned on error and pc->pp has been freed. PC remains
   valid after this call. */
Boolean ssh_engine_arp_router_advertisement(SshEngine engine,
                                            SshEnginePacketContext pc)
{
  const unsigned char *ucp;
  SshInterceptorInterface *iface;
  SshEngineArpPrefixInfo prefix_info, prefix_destroy_list;
  SshEngineArpRouterInfo router_info, router_destroy_list;
  SshEngineIfInfo if_info;
  size_t offset;
  SshUInt32 optlen;
  SshUInt8 opttype;
  unsigned char pullup_buf[SSH_ICMP6H_ND_OPTION_PREFIX_HDRLEN];
  SshUInt8 ra_flags;
  SshUInt16 ra_router_lifetime_sec;
  SshUInt32 ra_reachable_time_msec;
  SshUInt32 ra_retrans_timer_msec;
  SshTime now;
  SshUInt8 prefix_len;
  SshUInt8 prefix_flags;
  SshUInt32 prefix_validity_time;
  SshUInt32 prefix_preferred_lifetime;
  SshIpAddrStruct prefix;

  SSH_ASSERT(engine != NULL);
  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->pp != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Router advertisement input: flags 0x%lx ifnum %d",
             (unsigned long) pc->pp->flags, (int) pc->pp->ifnum_in));

  /* Do sanity checks that the packet is of proper type and that it
     is long enough to contain the IPv6 Neighbor solicitation ICMP
     header, which is at least 24 bytes long. */
  if (pc->pp->protocol != SSH_PROTOCOL_IP6 ||
      SSH_IP_IS6(&pc->src) == FALSE ||
      SSH_IP6_IS_LINK_LOCAL(&pc->src) == FALSE ||
      pc->packet_len < pc->hdrlen + SSH_ICMP6_ROUTER_ADVERTISEMENT_MINLEN)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("RA not IPv6 or too short: protocol %d src %@ length %d",
                 (int) pc->pp->protocol,
                 ssh_ipaddr_render, &pc->src,
                 (int) pc->packet_len));
      return TRUE;
    }

  /* Look at the ICMP header, SSH_ICMP6_ROUTER_ADVERTISEMENT_MINLEN
     bytes from RA header is enough for now. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen,
                            SSH_ICMP6_ROUTER_ADVERTISEMENT_MINLEN, pullup_buf);
  if (ucp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
      pc->pp = NULL;
      return FALSE;
    }

  if (SSH_ICMP6H_TYPE(ucp) != SSH_ICMP6_TYPE_ROUTER_ADVERTISEMENT
      || SSH_ICMP6H_CODE(ucp) != 0
      || pc->u.rule.ttl != 0xff)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Not handled because ICMPv6 type %d code %d hoplimit %d "
                 "not RA",
                 SSH_ICMP6H_TYPE(ucp), SSH_ICMP6H_CODE(ucp), pc->u.rule.ttl));
      return TRUE;
    }

  /* Decode RA message. */
  ra_flags = SSH_ICMP6H_RA_FLAGS(ucp);
  if (ra_flags & ~SSH_ICMP6H_RA_FLAGMASK)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("RA reserved field not zero: %x",
                 (ra_flags & ~SSH_ICMP6H_RA_FLAGMASK)));
      ra_flags &= SSH_ICMP6H_RA_FLAGMASK;
    }
  ra_router_lifetime_sec = SSH_ICMP6H_RA_ROUTER_LIFETIME(ucp);
  ra_reachable_time_msec = SSH_ICMP6H_RA_REACHABLE_TIME(ucp);
  ra_retrans_timer_msec = SSH_ICMP6H_RA_RETRANS_TIMER(ucp);

  /* Verify ICMPv6 cksum. */
  if (engine_arp_ipv6_verify_cksum(pc) == FALSE)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("RA ICMPv6 checksum failure"));

      /* Drop packet. */
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("RA: router_lifetime %lus reachable_time %lums "
             "retrans_timer %lums",
             (unsigned long) ra_router_lifetime_sec,
             (unsigned long) ra_reachable_time_msec,
             (unsigned long) ra_retrans_timer_msec));

  /* Sanity check ifnum as we need to store this information based on the
     interface. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, pc->pp->ifnum_in);
  if (iface == NULL ||
      iface->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      /* Invalid ifnum or nonexistent interface. */
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum %d or nonexistent interface",
                             (int) pc->pp->ifnum_in));

      /* Let the packet still continue to the stack. We were just unable
         to dig out the information we are interested in. */
      return TRUE;
    }
  if_info = iface->ctx_user;

  ssh_interceptor_get_time(&now, NULL);

  /* Do we have router advertisement options? */
  for (offset = pc->hdrlen + SSH_ICMP6_ROUTER_ADVERTISEMENT_MINLEN;
       (offset + SSH_ICMP6H_ND_OPTION_HDRLEN) <= pc->packet_len;
       offset += optlen)
    {
      /* Fetch option header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_ICMP6H_ND_OPTION_HDRLEN,
                                pullup_buf);
      if (ucp == NULL)
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          pc->pp = NULL;
          SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
          return FALSE;
        }

      /* Decode option type and length. */
      opttype = SSH_ICMP6H_ND_OPTION_TYPE(ucp);
      optlen = SSH_ICMP6H_ND_OPTION_LENB(ucp);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Router advertisement option type %u length %u",
                 opttype, optlen));

      /* Invalid case. RFC4861 states that this packet needs to be dropped
         if optlen is zero. We still let this packet to continue to stack.*/
      if (optlen == 0)
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          SSH_DEBUG(SSH_D_NETGARB, ("Invalid option in RA, ignoring packet"));
          return TRUE;
        }

      /* We are only interested in prefix information option. */
      if (opttype == SSH_ICMP6_NEIGHDISC_OPT_PREFIX_INFORMATION)
        {
          /* RFC 4861 states that router advertisement prefix information
             is exactly 32 bytes. */
          if (optlen != SSH_ICMP6H_ND_OPTION_PREFIX_HDRLEN)
            {
              ssh_kernel_mutex_unlock(engine->interface_lock);
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Invalid prefix information option length %u",
                         optlen));

              /* And still let the packet continue to the stack. */
              return TRUE;
            }

          /* Parse prefix information. */
          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, optlen, pullup_buf);
          if (ucp == NULL)
            {
              ssh_kernel_mutex_unlock(engine->interface_lock);
              pc->pp = NULL;
              SSH_DEBUG(SSH_D_ERROR, ("Packet dropped because pullup failed"));
              return FALSE;
            }

          /* Prefix length. */
          prefix_len = SSH_ICMP6H_ND_OPTION_PREFIX_PREFIXLEN(ucp);

          /* Prefix flags. */
          prefix_flags = SSH_ICMP6H_ND_OPTION_PREFIX_FLAGS(ucp);
          if (prefix_flags & ~SSH_ICMP6H_ND_OPTION_PREFIX_FLAGMASK)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("RA prefix information option reserved field "
                         "not zero: %x",
                         (prefix_flags
                          & ~SSH_ICMP6H_ND_OPTION_PREFIX_FLAGMASK)));
              prefix_flags &= SSH_ICMP6H_ND_OPTION_PREFIX_FLAGMASK;
            }

          /* Prefix valid lifetime. */
          prefix_validity_time =
            SSH_ICMP6H_ND_OPTION_PREFIX_VALID_LIFETIME(ucp);

          /* Prefix preferred lifetime. */
          prefix_preferred_lifetime =
            SSH_ICMP6H_ND_OPTION_PREFIX_PREF_LIFETIME(ucp);

          /* 4 byte hole and then the IPv6 address prefix. */
          SSH_ICMP6H_ND_OPTION_PREFIX_PREFIX(&prefix, ucp);

          SSH_IP_MASK_LEN(&prefix) = prefix_len;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Prefix information option: prefix %@ validity time %lu "
                     "preferred lifetime %lu router addr %@",
                     ssh_ipaddr_render, &prefix,
                     prefix_validity_time, prefix_preferred_lifetime,
                     ssh_ipaddr_render, &pc->src));

          /* No need to store information about prefixes that are not
             onlink. */
          if ((prefix_flags & SSH_ICMP6H_ND_OPTION_PREFIX_FLAG_ONLINK) == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Prefix %@ is not link, ignoring prefix",
                                      ssh_ipaddr_render, &prefix));
              continue;
            }

          /* Lookup this prefix from prefix list. */
          prefix_info = engine_arp_prefix_info_lookup(engine, if_info,
                                                      &prefix, &pc->src);
          if (prefix_info == NULL)
            {
              /* Note that a new prefix entry is created on purpose also
                 for prefixes with zero validity time. This is done to
                 ensure that next hops will get properly rerouted. */
              SSH_DEBUG(SSH_D_LOWOK, ("Creating a new prefix entry"));
              prefix_info = engine_arp_prefix_info_create(engine, if_info,
                                                          &prefix, &pc->src,
                                                          pc->pp->ifnum_in);
            }
          else
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Updating existing prefix entry"));
            }

          if (prefix_info != NULL)
            {
              prefix_info->validity_time = prefix_validity_time;
              prefix_info->preferred_lifetime = prefix_preferred_lifetime;
              prefix_info->ra_received = now;
            }
        }
    }

  /* Lookup router info from default router list. */
  router_info = engine_arp_router_info_lookup(engine, if_info, &pc->src);

  /* Router address was not found in default router list, create
     a new router info object. */
  if (router_info == NULL)
    {
      /* Note that a new default router entry is created on purpose also
         for routers with zero lifetime. This is done to ensure that next
         hops will get properly rerouted. */
      SSH_DEBUG(SSH_D_LOWOK, ("Creating a new default router entry"));
      router_info = engine_arp_router_info_create(engine, if_info, &pc->src,
                                                  pc->pp->ifnum_in);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Updating existing default router entry"));
    }

  /* Store received values in router info. */
  if (router_info != NULL)
    {
      router_info->ra_received = now;
      router_info->lifetime = ra_router_lifetime_sec;
      if (ra_reachable_time_msec > 0)
        router_info->reachable_time_msec = ra_reachable_time_msec;
      if (ra_retrans_timer_msec > 0)
        router_info->retrans_timer_msec = ra_retrans_timer_msec;
    }

  /* Check default router and prefix lists. */
  router_destroy_list = NULL;
  engine_arp_router_info_timeout(engine, if_info, &router_destroy_list, now);
  prefix_destroy_list = NULL;
  engine_arp_prefix_info_timeout(engine, if_info, &prefix_destroy_list, now);

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Mark matching next hop nodes for rerouting. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (router_info = router_destroy_list;
       router_info != NULL;
       router_info = router_info->next)
    {
      ssh_engine_nh_node_reroute(engine, &router_info->router_addr,
                                 8*SSH_IP_ADDR_LEN(&router_info->router_addr),
                                 router_info->ifnum);
    }

  for (prefix_info = prefix_destroy_list;
       prefix_info != NULL;
       prefix_info = prefix_info->next)
    {
      ssh_engine_nh_node_reroute(engine, &prefix_info->prefix,
                                 8 * SSH_IP_MASK_LEN(&prefix_info->prefix),
                                 prefix_info->ifnum);
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Free destroyed default routers and prefixes. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  while (router_destroy_list != NULL)
    {
      router_info = router_destroy_list;
      router_destroy_list = router_destroy_list->next;
      engine_arp_router_info_free(engine, router_info);
    }
  while (prefix_destroy_list != NULL)
    {
      prefix_info = prefix_destroy_list;
      prefix_destroy_list = prefix_destroy_list->next;
      engine_arp_prefix_info_free(engine, prefix_info);
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  return TRUE;
}

#endif  /* defined(WITH_IPV6) */


/************************** ARP/IPv6 ND timeouts *****************************/

/* Compute and set expiry timeout for an ARP entry. */
void engine_arp_entry_set_expiry_timeout(SshEngine engine,
                                         SshEngineArpCacheEntry entry,
                                         SshTime now)
{
#ifdef WITH_IPV6
  SshInterceptorInterface *iface;
  SshEngineIfInfo if_info;
  SshEngineArpRouterInfo router_info;
  SshUInt32 expiry_timeout;
#endif /* WITH_IPV6 */

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

#ifdef WITH_IPV6
  if (SSH_IP_IS6(&entry->ip_addr) == TRUE)
    {
      /* Lookup interface. */
      iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, entry->ifnum);
      if (iface == NULL ||
          iface->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          /* Invalid ifnum or nonexistent interface. */
          SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum %d or nonexistent interface",
                                 (int) entry->ifnum));

          /* Set expiry to default lifetime. */
          entry->expires = now + SSH_ENGINE_ARP_IPV6_MAX_COMPLETE_LIFETIME;
          return;
        }
      if_info = iface->ctx_user;

      /* Lookup smallest reachable time from known default routers. */
      expiry_timeout = 0;
      for (router_info = if_info->router_list;
           router_info != NULL;
           router_info = router_info->next)
        {
          if (router_info->reachable_time_msec == 0)
            continue;

          if (expiry_timeout == 0
              || expiry_timeout > router_info->reachable_time_msec)
            expiry_timeout = router_info->reachable_time_msec;
        }

      /* Use maximum reachable time if no router solicitations have been
         received. */
      if (expiry_timeout == 0)
        expiry_timeout = SSH_ENGINE_ARP_IPV6_MAX_COMPLETE_LIFETIME * 1000;

      /* Limit the maximum reachable time, so that the rendomization below
         produces sane results. */
      else if (expiry_timeout > 0x0fffffff)
        expiry_timeout = 0x0fffffff;

      /* Randomize reachablity time like RFC4861 says. */
      expiry_timeout =
        (expiry_timeout *
         ((ssh_rand() %
           (SSH_ENGINE_ARP_IPV6_REACHABLE_TIME_MAX_FACTOR
            - SSH_ENGINE_ARP_IPV6_REACHABLE_TIME_MIN_FACTOR))
          + SSH_ENGINE_ARP_IPV6_REACHABLE_TIME_MIN_FACTOR)) / 100;

      /* Convert reachable time to seconds and enforce limits. */
      if (expiry_timeout % 1000 != 0)
        {
          expiry_timeout /= 1000;
          expiry_timeout += 1;
        }
      else
        expiry_timeout /= 1000;

      if (expiry_timeout > SSH_ENGINE_ARP_IPV6_MAX_COMPLETE_LIFETIME)
        expiry_timeout = SSH_ENGINE_ARP_IPV6_MAX_COMPLETE_LIFETIME;
      else if (expiry_timeout < SSH_ENGINE_ARP_IPV6_MIN_COMPLETE_LIFETIME)
        expiry_timeout = SSH_ENGINE_ARP_IPV6_MIN_COMPLETE_LIFETIME;

      /* Convert to wallclock time. */
      entry->expires = now + expiry_timeout;
    }
  else
#endif /* WITH_IPV6 */
    {
      entry->expires = now + SSH_ENGINE_ARP_COMPLETE_LIFETIME;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Entry %@ expires in %lus at %lu",
                          ssh_engine_arp_entry_render, entry,
                          (unsigned long) (entry->expires - now),
                          (unsigned long) entry->expires));
}

void engine_arp_entry_set_request_timeout(SshEngine engine,
                                          SshEngineArpCacheEntry entry,
                                          SshTime now_sec,
                                          SshUInt32 now_usec)
{
#ifdef WITH_IPV6
  SshInterceptorInterface *iface;
  SshEngineIfInfo if_info;
  SshEngineArpRouterInfo router_info;
  SshUInt32 retry_timeout_sec, retry_timeout_usec;
#endif /* WITH_IPV6 */
#ifdef DEBUG_LIGHT
  SshUInt32 debug_retry_sec, debug_retry_usec;
#endif /* DEBUG_LIGHT */

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

#ifdef WITH_IPV6
  if (SSH_IP_IS6(&entry->ip_addr) == TRUE)
    {
      /* Lookup interface. */
      iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, entry->ifnum);
      if (iface == NULL ||
          iface->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
        {
          /* Invalid ifnum or nonexistent interface. */
          SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum %d or nonexistent interface",
                                 (int) entry->ifnum));
          entry->retry_timeout_sec =
            now_sec + SSH_ENGINE_ARP_IPV6_RESEND_MIN_TIMEOUT;
          entry->retry_timeout_usec = now_usec;
          return;
        }
      if_info = iface->ctx_user;

      /* Lookup smallest retrans timer in milliseconds from known default
         routers. */
      retry_timeout_sec = 0;
      for (router_info = if_info->router_list;
           router_info != NULL;
           router_info = router_info->next)
        {
          if (router_info->retrans_timer_msec == 0)
            continue;

          if (retry_timeout_sec == 0
              || retry_timeout_sec > router_info->retrans_timer_msec)
            retry_timeout_sec = router_info->retrans_timer_msec;
        }

      if (retry_timeout_sec == 0)
        {
          retry_timeout_sec = SSH_ENGINE_ARP_IPV6_RESEND_MIN_TIMEOUT;
          retry_timeout_usec = 0;
        }
      else
        {
          /* Convert from milliseconds to seconds and microseconds. */
          retry_timeout_usec = (retry_timeout_sec % 1000) * 1000;
          retry_timeout_sec /= retry_timeout_sec;
        }

      /* Enforce limits. */
      if (retry_timeout_sec < SSH_ENGINE_ARP_IPV6_RESEND_MIN_TIMEOUT)
        {
          retry_timeout_sec = SSH_ENGINE_ARP_IPV6_RESEND_MIN_TIMEOUT;
          retry_timeout_usec = 0;
        }
      else if (retry_timeout_sec >= SSH_ENGINE_ARP_IPV6_RESEND_MAX_TIMEOUT)
        {
          retry_timeout_sec = SSH_ENGINE_ARP_IPV6_RESEND_MAX_TIMEOUT;
          retry_timeout_usec = 0;
        }

      /* Convert to wallclock time. */
#ifdef DEBUG_LIGHT
      debug_retry_sec = retry_timeout_sec;
      debug_retry_usec = retry_timeout_usec;
#endif /* DEBUG_LIGHT */
      entry->retry_timeout_sec = now_sec + retry_timeout_sec;
      entry->retry_timeout_usec = now_usec + retry_timeout_usec;
    }
  else
#endif /* WITH_IPV6 */
    {
#ifdef DEBUG_LIGHT
      debug_retry_sec = SSH_ENGINE_ARP_RESEND_TIMEOUT;
      debug_retry_usec = 0;
#endif /* DEBUG_LIGHT */
      entry->retry_timeout_sec = now_sec + SSH_ENGINE_ARP_RESEND_TIMEOUT;
      entry->retry_timeout_usec = now_usec;
    }

  if (entry->retry_timeout_usec > 1000000)
    {
      entry->retry_timeout_sec++;
      entry->retry_timeout_usec -= 1000000;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Entry %@ retry in %lu.%06lus at %lu.%06lu",
                          ssh_engine_arp_entry_render, entry,
                          (unsigned long) debug_retry_sec,
                          (unsigned long) debug_retry_usec,
                          (unsigned long) entry->retry_timeout_sec,
                          (unsigned long) entry->retry_timeout_usec));
}

void engine_arp_request_timeout_schedule(SshEngine engine,
                                         SshTime retry_timeout_sec,
                                         SshUInt32 retry_timeout_usec,
                                         SshTime now_sec,
                                         SshUInt32 now_usec)
{
  SshTime timeout_sec;
  SshUInt32 timeout_usec;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Check if previously registered timeout is before the requested timeout. */
  if ((engine->arp_cache.retry_timeout_sec != 0
       || engine->arp_cache.retry_timeout_usec != 0)
      && SSH_ENGINE_ARP_TIME_CMP(engine->arp_cache.retry_timeout_sec,
                                 engine->arp_cache.retry_timeout_usec,
                                 retry_timeout_sec, retry_timeout_usec) <= 0)
    return;

  /* Calculate offset from now to requested timeout. */
  timeout_sec = 0;
  timeout_usec = 0;
  if (SSH_ENGINE_ARP_TIME_CMP(retry_timeout_sec, retry_timeout_usec,
                              now_sec, now_usec) > 0)
    {
      SSH_ENGINE_TIME_SUB(timeout_sec, timeout_usec,
                          retry_timeout_sec, retry_timeout_usec,
                          now_sec, now_usec);
    }

  /* Sanity check that the timeout will not trigger too soon. */
  if (timeout_sec == 0 && timeout_usec < SSH_ENGINE_ARP_TIMER_RESOLUTION)
    timeout_usec = SSH_ENGINE_ARP_TIMER_RESOLUTION;

  SSH_ENGINE_TIME_ADD(retry_timeout_sec, retry_timeout_usec,
                      timeout_sec, timeout_usec,
                      now_sec, now_usec);

  /* Check if the sanity checked requested timeout is still before the
     previously registered timeout. */
  if ((engine->arp_cache.retry_timeout_sec == 0
       && engine->arp_cache.retry_timeout_usec == 0)
      || SSH_ENGINE_ARP_TIME_CMP(retry_timeout_sec,
                                 retry_timeout_usec,
                                 engine->arp_cache.retry_timeout_sec,
                                 engine->arp_cache.retry_timeout_usec) < 0)
    {
      /* Move the previously registered retry timeout to an earlier time
         or register a new timeout there was no old timeout. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Moving ARP retry timeout at %lu.%06lu to %lu.%06lus "
                 "at %lu.%06lu",
                 (unsigned long) engine->arp_cache.retry_timeout_sec,
                 (unsigned long) engine->arp_cache.retry_timeout_usec,
                 (unsigned long) timeout_sec,
                 (unsigned long) timeout_usec,
                 (unsigned long) retry_timeout_sec,
                 (unsigned long) retry_timeout_usec));
      if (ssh_kernel_timeout_move((SshUInt32) timeout_sec, timeout_usec,
                                  ssh_engine_arp_request_timeout, engine)
          == FALSE)
        {
          /* Register the new timeout. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Registering ARP retry timeout to %lu.%06lus "
                     "at %lu.%06lu",
                     (unsigned long) timeout_sec,
                     (unsigned long) timeout_usec,
                     (unsigned long) retry_timeout_sec,
                     (unsigned long) retry_timeout_usec));
          ssh_kernel_timeout_register((SshUInt32) timeout_sec,
                                      timeout_usec,
                                      ssh_engine_arp_request_timeout,
                                      engine);
        }

      /* Store the time of next timeout. */
      engine->arp_cache.retry_timeout_sec = retry_timeout_sec;
      engine->arp_cache.retry_timeout_usec = retry_timeout_usec;
    }
}

/* This function is called from a timeout if we don't get an answer
   for an arp request fast enough.  This will resend the request and
   reset the timer, until the maximum number of retries has been
   performed.  If there is still no reply, the entry is marked failed
   (but the packet queue is not yet freed, in case the reply is just
   delayed; the list will anyway will be freed when the arp cache
   entry times out).  This function is called from a timeout, possibly
   concurrently with other functions. */

void ssh_engine_arp_request_timeout(void *context)
{
  SshEngine engine = (SshEngine)context;
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry, *entryp, destroy_list;
#define MAX_RESENDS     5
  struct {
    SshIpAddrStruct target_addr;
    SshEngineIfnum ifnum;
    SshVriId routing_instance_id;
#ifdef WITH_IPV6
    SshEngineArpCacheEntryStatus status;
    unsigned char dst_hw[SSH_ETHERH_ADDRLEN];
#endif /* WITH_IPV6 */
  } resends[MAX_RESENDS], *r;
  SshIpAddrStruct own_addr;
  unsigned char own_hw[SSH_ETHERH_ADDRLEN];
  SshUInt32 num_resend, i;
  Boolean resend_full, restarted;
  SshTime now_sec, next_timeout_sec;
  SshUInt32 now_usec, next_timeout_usec;
#ifdef DEBUG_LIGHT
  SshUInt32 num_entries = 0;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_LOWSTART, ("ARP; request timeout"));

  ssh_interceptor_get_time(&now_sec, &now_usec);
  next_timeout_sec = 0;
  next_timeout_usec = 0;
  restarted = FALSE;

 restart:
  resend_full = FALSE;
  num_resend = 0;

  /* Take the engine lock. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Mark that retry timeout is running and no next retry timeout has been
     scheduled. */
  if (restarted == FALSE)
    {
      cache->retry_timeout_sec = 0;
      cache->retry_timeout_usec = 0;
    }

  /* Process all entries on the retry list. */
  destroy_list = NULL;
  for (entryp = &cache->retry_list; *entryp; )
    {
      entry = *entryp;

      /* If the retry count has been exhausted, fail the ARP lookup
         operation and free the ARP entry. */
      if (entry->arp_retry_count == 0)
        {
          SSH_ASSERT(entry->status == SSH_ENGINE_ARP_INCOMPLETE
                     || entry->status == SSH_ENGINE_ARP_PROBE);

          SSH_DEBUG(SSH_D_MIDOK,
                    ("ARP request failed for entry %@ queued packet %p",
                     ssh_engine_arp_entry_render, entry,
                     entry->queued_packet));

          /* Mark the entry as failed. */
          entry->status = SSH_ENGINE_ARP_FAILED;

          /* Remove the entry from the retry list.  This also moves us to
             the next entry on the list. */
          *entryp = entry->retry_list_next;
          entry->flags &= ~SSH_ENGINE_ARP_F_ON_RETRY_LIST;

          /* Add the entry to destroy list and destroy it later when all
             entries in the retry list have been iterated. */
          entry->retry_list_next = destroy_list;
          destroy_list = entry;

          continue;
        }

      /* Check if it is time to retransmit. */
      if (SSH_ENGINE_ARP_ENTRY_RETRY_TIME_CMP(entry, now_sec, now_usec) <= 0)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("ARP retry for entry %@ queued packet %p retries left %u",
                     ssh_engine_arp_entry_render, entry,
                     entry->queued_packet,
                     entry->arp_retry_count));

          /* Queue the ARP request to be sent when lock is no longer held
             (due to us not being allowed to interceptor-send with upper
             level lock held. */
          if (num_resend >= MAX_RESENDS)
            {
              /* If too many, abort now (we restart when these have been
                 sent). */
              resend_full = TRUE;
              break;
            }

          /* Decrement the remaining retry count. */
          entry->arp_retry_count--;

          resends[num_resend].ifnum = entry->ifnum;
          resends[num_resend].target_addr = entry->ip_addr;
          resends[num_resend].routing_instance_id = entry->routing_instance_id;
#ifdef WITH_IPV6
          resends[num_resend].status = entry->status;
          memcpy(resends[num_resend].dst_hw, entry->ethernet_addr,
                 SSH_ETHERH_ADDRLEN);
#endif /* WITH_IPV6 */
          num_resend++;

          /* Set next retry timeout. */
          engine_arp_entry_set_request_timeout(engine, entry, now_sec,
                                               now_usec);
        }

      /* Update next retry timeout. */
      if ((next_timeout_sec == 0 && next_timeout_usec == 0)
          || SSH_ENGINE_ARP_ENTRY_RETRY_TIME_CMP(entry, next_timeout_sec,
                                                 next_timeout_usec) < 0)
        {
          next_timeout_sec = entry->retry_timeout_sec;
          next_timeout_usec = entry->retry_timeout_usec;
        }

#ifdef DEBUG_LIGHT
      num_entries++;
#endif /* DEBUG_LIGHT */

      /* Move to next entry. */
      entryp = &entry->retry_list_next;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Processed %d entries from ARP retry list",
                          (int) num_entries));

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Loop through the failed entries in destroy list and mark matching
     next hop nodes for rerouting. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (entry = destroy_list; entry != NULL; entry = entry->retry_list_next)
    {
      ssh_engine_nh_node_reroute(engine, &entry->ip_addr,
                                 8 * SSH_IP_ADDR_LEN(&entry->ip_addr),
                                 entry->ifnum);
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Free ARP entries in the destroy list. This moves any queued packets
     to the pending completions list which is processed later in this
     function. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  while (destroy_list != NULL)
    {
      entry = destroy_list;
      destroy_list = entry->retry_list_next;
      engine_arp_free_entry(engine, entry);
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Send any pending requests (resends). */
  for (i = 0; i < num_resend; i++)
    {
      Boolean ret;

      r = &resends[i];

      /* Get our own addresses for the interface. */
      ssh_kernel_mutex_lock(engine->interface_lock);
      ret = engine_arp_get_hwaddr(engine, r->ifnum, own_hw);
      if (ret == TRUE)
        {
          ret = ssh_engine_get_ipaddr(engine, (SshEngineIfnum) r->ifnum,
                                      SSH_IP_IS6(&r->target_addr) ?
                                      SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                      &r->target_addr, &own_addr);
          if (ret == FALSE)
            ret = ssh_engine_get_ipaddr(engine, (SshEngineIfnum) r->ifnum,
                                        SSH_IP_IS6(&r->target_addr) ?
                                        SSH_PROTOCOL_IP6 : SSH_PROTOCOL_IP4,
                                        NULL, &own_addr);
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);

      if (ret == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not find local IP address %@ or hwaddr %@",
                     ssh_ipaddr_render, &own_addr,
                     ssh_engine_arp_render_eth_mac, own_hw));
          continue;
        }

      /* Send the ARP request or neighbor solicitation. */
#if defined(WITH_IPV6)
      if (SSH_IP_IS6(&r->target_addr) == TRUE)
        {
          /* Send NS probes to unicast address. */
          if (r->status == SSH_ENGINE_ARP_PROBE)
            ssh_engine_arp_send_solicitation(engine, &r->target_addr,
                                             r->dst_hw, &r->target_addr,
                                             r->ifnum, r->routing_instance_id,
                                             &own_addr, own_hw);

          /* Send to standard multicast group. */
          else
            ssh_engine_arp_send_solicitation(engine, NULL, NULL,
                                             &r->target_addr, r->ifnum,
                                             r->routing_instance_id,
                                             &own_addr, own_hw);
        }
      else
#endif /* WITH_IPV6 */
        ssh_engine_arp_send_request(engine, &r->target_addr, r->ifnum,
                                    &own_addr, r->routing_instance_id, own_hw);
    }

  /* Repeat if the resend list became full (until we no longer have more
     resends remaining). */
  if (resend_full == TRUE)
    {
      restarted = TRUE;
      goto restart;
    }

  /* Call the completion function for any packets waiting for it. This
     may result into recursive calls into the ARP module. */
  engine_arp_call_pending_completions(engine);

  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Schedule next retry timeout if there were entries in the retry list. */
  if (next_timeout_sec != 0 || next_timeout_usec != 0)
    engine_arp_request_timeout_schedule(engine,
                                        next_timeout_sec, next_timeout_usec,
                                        now_sec, now_usec);

  ssh_kernel_mutex_unlock(engine->interface_lock);
}

Boolean
ssh_engine_arp_update_packet_in_cache(SshEnginePacketContext pc,
                                      SshIpAddr next_hop,
                                      SshEngineIfnum ifnum,
                                      SshUInt32 pc_nh_index,
                                      SshEngineArpComplete callback)
{
  SshEngine engine = pc->engine;
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry;
  SshEnginePacketContext old_pc = NULL;
  SshEngineArpLookupStatus lookup_status;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Updating PC %p in ARP cache, IP dst %@ ifnum %d",
             pc, ssh_ipaddr_render, next_hop, (int) ifnum));

  /* Compute a hash value from the ip address. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(next_hop);

  /* Take the engine lock. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Check if the slot contains the address we are looking for. */
  for (entry = cache->hash[hash]; entry != NULL; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, next_hop)
          && (entry->ifnum == ifnum
              || (entry->flags & SSH_ENGINE_ARP_F_GLOBAL)))
        break;
    }

  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No entry found in ARP cache"));
      goto fail;
    }

  /* We have now found an arp cache entry for the desired IP address.
     Is the status correct? */
  switch (entry->status)
    {
    case SSH_ENGINE_ARP_INCOMPLETE:
      SSH_ASSERT(entry->queued_packet != pc);
      SSH_ASSERT(entry->queued_packet != NULL);
      old_pc = entry->queued_packet;

      SSH_ASSERT(pc != NULL && old_pc != pc);

      if (old_pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("ARP lookup currently in progress for IPsec flow "
                     "related event, could not update packet."));
          goto fail;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Updating PC %p to entry %p %@",
                 pc, entry, ssh_engine_arp_entry_render, entry));

      /* Update the callback and ifnum to this PC. */
      pc->arp_callback = callback;
      pc->arp_ifnum = old_pc->arp_ifnum;

      SSH_DEBUG(SSH_D_LOWOK, ("Failing ARP lookup for old pc %p", old_pc));

      /* Save the packet so that its processing will continue
         when the lookup is complete. */
      SSH_ASSERT(pc->pp != NULL);
      ssh_interceptor_packet_detach(pc->pp);
      if (entry->queued_packet_nh_index != pc_nh_index &&
          entry->queued_packet_nh_index != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Dequeueing packet with different NH index "
                     "old 0x%x, new 0x%x",
                     entry->queued_packet_nh_index, pc_nh_index));
          lookup_status = SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR;
        }
      else
        {
          lookup_status = SSH_ENGINE_ARP_LOOKUP_STATUS_PKT_DEQUEUED;
        }

      entry->queued_packet = pc;
      entry->queued_packet_nh_index = pc_nh_index;

      ssh_kernel_mutex_unlock(engine->interface_lock);

      engine_arp_complete_pc(engine,
                             lookup_status,
                             old_pc, NULL, NULL);

      return TRUE;

    default:
      SSH_DEBUG(SSH_D_LOWOK, ("Not updating packet to ARP entry %@",
                              ssh_engine_arp_entry_render, entry));
      break;
    }

 fail:
  ssh_kernel_mutex_unlock(engine->interface_lock);
  return FALSE;
}

/* Looks up the physical ethernet addresses for the next hop gateway
   'next_hop'. This calls the supplied callback (either immediately or at a
   later time) when done (with both source and destination physical addresses).
   This assumes that the pc and nh arguments will remain valid until the
   callback has been called.

   There are several possible methods that this function uses for obtaining
   the physical address:
     1. local broadcast address (255.255.255.255) is hardwired
     2. multicast addresses are hardwired to multicast ethernet addresses
        (rfc1112 or rfc1469)
     3. loopback address (127.x.x.x) is hardwired to fail
     4. otherwise, a lookup is performed.  The media address in arp cache,
        if found, is returned.  It is expected that the local
        addresses for each interface, and the per-network broadcast addresses
        are stored in the arp cache as permanent entries.
     5. The arp protocol is used to find out the hardware address.  An entry
        is added in the arp cache. */

void ssh_engine_arp_lookup(SshEnginePacketContext pc,
                           SshIpAddr next_hop,
                           SshEngineIfnum ifnum,
                           SshVriId routing_instance_id,
                           SshUInt32 pc_nh_index,
                           SshEngineArpComplete callback)
{
  SshEngine engine = pc->engine;
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry;
  unsigned char media_addr[SSH_ETHERH_ADDRLEN], own_hw[SSH_ETHERH_ADDRLEN];
  SshIpAddrStruct target_addr, own_addr;
  SshUInt16 ethertype;
  SshEnginePacketContext old_pc = NULL;
  SshTime now_sec;
  SshUInt32 now_usec;
  Boolean ret = FALSE;
  SshInterceptorProtocol protocol;
  SshEngineArpLookupStatus lookup_status =
    SSH_ENGINE_ARP_LOOKUP_STATUS_PKT_DEQUEUED;

  ssh_interceptor_get_time(&now_sec, &now_usec);

  SSH_DEBUG(SSH_D_MIDSTART,
            ("ARP lookup for pc %p IP dst %@ ifnum %d",
             pc, ssh_ipaddr_render, next_hop, (int) ifnum));

  /* Save the callback function and ifnum for re-tries. */
  pc->arp_callback = callback;
  pc->arp_ifnum = ifnum;

  /* We first check the arp cache, as normal addresses are most
     frequent.  We only check for special addresses if the entry is
     not found in the cache; it is guaranteed that special addresses
     never end up in the arp cache. */

#ifdef SSH_IPSEC_SMALL
  /* And very first, we cleanup the cache from expired addresses. */
  ssh_engine_arp_cache_timeout(engine);
#endif /* SSH_IPSEC_SMALL */

  /* Compute a hash value from the ip address. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(next_hop);

  /* Take the engine lock. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Obtain our own hardware address for the interface on which we will send
     the ARP request.  We want to do this before anything that can jump
     to "success". */
  if (engine_arp_get_hwaddr(engine, ifnum, own_hw) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to find hwaddr for interface %d",
                 (int) ifnum));
      /* fail: label releases the interface_lock */
      goto fail;
    }

  /* Check if the slot contains the address we are looking for. */
  for (entry = cache->hash[hash]; entry != NULL; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, next_hop)
          && (entry->ifnum == ifnum
              || (entry->flags & SSH_ENGINE_ARP_F_GLOBAL)))
        break;
    }

  if (entry != NULL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Found matching entry %@",
                              ssh_engine_arp_entry_render, entry));

      /* We have now found an arp cache entry for the desired IP address. */
      switch (entry->status)
        {
        case SSH_ENGINE_ARP_STALE:
          /* Ok, request for stale entry. Need to perform ARP lookup
             (or NS) for this entry, but still we may tell the rest
             of the engine this entry as valid. */

          protocol = SSH_PROTOCOL_IP4;
#ifdef WITH_IPV6
          if (SSH_IP_IS6(&entry->ip_addr))
            protocol = SSH_PROTOCOL_IP6;
#endif /* WITH_IPV6 */

          /* Fetch own IP address. */
          ret = ssh_engine_get_ipaddr(engine, (SshEngineIfnum) ifnum,
                                      protocol, &entry->ip_addr,
                                      &own_addr);
          if (ret == FALSE)
            ret = ssh_engine_get_ipaddr(engine, (SshEngineIfnum) ifnum,
                                        protocol, NULL, &own_addr);

          if (ret == FALSE)
            {
              /* Well, we cannot make stale entry into complete, so
                 let the engine know that this entry is not available.
                 In reality this should not ever happen if the interface
                 is present... */
              SSH_DEBUG(SSH_D_FAIL,
                        ("Could not find local IP address %@ for ifnum %u",
                         ssh_ipaddr_render, &own_addr, ifnum));

              ssh_kernel_mutex_unlock(engine->interface_lock);
              (*callback)(pc, SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR, NULL, NULL,
                          0);

              return;
            }

          /* Store the entry's IP and hardware addresses. */
          target_addr = entry->ip_addr;
          memcpy(media_addr, entry->ethernet_addr, SSH_ETHERH_ADDRLEN);

          engine_arp_lru_bump(engine, entry, FALSE);

          /* The status moved to probe according to RFC 4861. Note that
             the same is done for IPv4 also. */
          SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to probe"));
          entry->status = SSH_ENGINE_ARP_PROBE;
#ifdef WITH_IPV6
          if (protocol == SSH_PROTOCOL_IP6)
            entry->arp_retry_count = SSH_ENGINE_ARP_IPV6_MAX_UCAST_RETRIES;
          else
#endif /* WITH_IPV6 */
            entry->arp_retry_count = SSH_ENGINE_ARP_MAX_RETRIES;

          /* Add entry to retry list. */
          engine_arp_retry_list_insert(engine, entry);

          /* Schedule retry timeout to immediate future, the probe is sent
             from the retry timeout. */
          entry->retry_timeout_sec = now_sec;
          entry->retry_timeout_usec = now_usec;
          engine_arp_request_timeout_schedule(engine, entry->retry_timeout_sec,
                                              entry->retry_timeout_usec,
                                              now_sec, now_usec);

          ssh_kernel_mutex_unlock(engine->interface_lock);

          /* Mark matching next hop nodes for rerouting. */
          ssh_kernel_mutex_lock(engine->flow_control_table_lock);
          ssh_engine_nh_node_reroute(engine, &target_addr,
                                     8 * SSH_IP_ADDR_LEN(&target_addr),
                                     ifnum);
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

#ifdef WITH_IPV6
          if (protocol == SSH_PROTOCOL_IP6)
            ethertype = SSH_ETHERTYPE_IPv6;
          else
#endif /* WITH_IPV6 */
            ethertype = SSH_ETHERTYPE_IP;

          SSH_DEBUG(SSH_D_LOWOK, ("Returning synchronously"));

          (*callback)(pc, SSH_ENGINE_ARP_LOOKUP_STATUS_OK, own_hw, media_addr,
                      ethertype);
          return;

        case SSH_ENGINE_ARP_INCOMPLETE:

          SSH_DEBUG(6, (" ...request is for an incomplete entry."));

          /* Queue the packet in the entry. */

          /* Only one saved packet is kept per entry.  We keep the
             last packet; there is a reason for this, namely that the
             code in ssh_engine_arp_lookup assumes that the packet is
             not freed when returning SSH_ENGINE_ARP_IN_PROGRESS.  We
             must also watch out for the same packet already being
             queued. */



          if (entry->queued_packet != pc)
            {
              if (entry->queued_packet_nh_index != SSH_IPSEC_INVALID_INDEX &&
                  pc_nh_index != entry->queued_packet_nh_index)
                {
                  SSH_DEBUG(0,
                            ("Dequeuing packet with different nh index, "
                             "new 0x%x, old 0x%x",
                             pc_nh_index, entry->queued_packet_nh_index));
                  lookup_status = SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR;
                }
              else
                {
                  lookup_status = SSH_ENGINE_ARP_LOOKUP_STATUS_PKT_DEQUEUED;
                }
              old_pc = entry->queued_packet;
            }

          SSH_ASSERT(pc != NULL && old_pc != pc);
          SSH_ASSERT(pc->pp != NULL);

          /* If we had an old queued packet, call arp_complete for it now
             unless the old_pc was the packet context for an IPsec flow
             in which case we fail the current operation. */
          if (old_pc != NULL)
            {
              if (old_pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
                {
                  SSH_DEBUG(SSH_D_HIGHOK,
                            ("ARP lookup currently in progress for IPsec "
                             "flow related event, aborting this operation"));
                  goto fail;
                }
              else
                {
                  SSH_DEBUG(SSH_D_LOWOK, ("Failing ARP lookup for pc %p",
                                          old_pc));

                  /* Save the packet so that its processing will continue
                     when the lookup is complete. Note that pc->pp may be
                     NULL in rerouting flows. */
                  ssh_interceptor_packet_detach(pc->pp);

                  entry->queued_packet = pc;
                  entry->queued_packet_nh_index = pc_nh_index;

                  ssh_kernel_mutex_unlock(engine->interface_lock);

                  engine_arp_complete_pc(engine,
                                         lookup_status,
                                         old_pc, NULL, NULL);
                }
            }
          return;

        case SSH_ENGINE_ARP_FAILED:
          SSH_DEBUG(SSH_D_MIDOK,
                    (" ...request is for recently failed address."));
          /* An arp request for the address has recently failed.  Just
             indicate failure. */
          goto fail;

        case SSH_ENGINE_ARP_COMPLETE:
        case SSH_ENGINE_ARP_PROBE:
          if ((pc->flags & SSH_ENGINE_PC_REROUTE_FLOW))
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("...request is for a completely mapped address %@ "
                         "but application requested fresh information.",
                         ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

              ssh_engine_arp_delete(engine, next_hop, ifnum);
              goto refresh;
            }
          else
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("...request is for a completely mapped address %@",
                         ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

              /* Move the entry to the beginning of the lru list. */
              engine_arp_lru_bump(engine, entry, FALSE);

              /* There is valid arp information for the address.  Copy the
                 hardware address, and return success.  Note that we must
                 copy the address to a local buffer to avoid race
                 conditions where the entry would be freed before
                 arp_complete does its job. */
              memcpy(media_addr, entry->ethernet_addr, SSH_ETHERH_ADDRLEN);
              goto success;
            }

        case SSH_ENGINE_ARP_PERMANENT:
          SSH_DEBUG(SSH_D_MIDOK,
                    ("...request for a permanently mapped address %@",
                     ssh_engine_arp_render_eth_mac, entry->ethernet_addr));

          memcpy(media_addr, entry->ethernet_addr, SSH_ETHERH_ADDRLEN);
          goto success;

        default:
          /* engine lock still held. */
          ssh_fatal("ssh_engine_arp_lookup: bad status %d", entry->status);
        }
      SSH_NOTREACHED;
      goto fail;
    }

 refresh:
  /* Local broadcast address 255.255.255.255 */
  if (SSH_IP_IS_BROADCAST(next_hop) ||
      (SSH_IP_IS4(next_hop) &&
       ssh_ip_get_interface_by_broadcast(&engine->ifs, next_hop,
                                         SSH_INTERCEPTOR_VRI_ID_ANY)))
    {
      memcpy(media_addr, ssh_engine_arp_ethernet_broadcast_addr,
             SSH_ETHERH_ADDRLEN);
      goto success;
    }

  /* IP multicast addresses */
  if (SSH_IP_IS_MULTICAST(next_hop))
    {
      if (cache->token_ring_multicast)
        {
          /* Use token ring multicast addresses. */
          memcpy(media_addr, ssh_engine_arp_token_ring_multicast_addr,
                 SSH_ETHERH_ADDRLEN);
        }
      else if (SSH_IP_IS6(next_hop))
        {
          /* Normal rfc2464 multicast. */
          media_addr[0] = 0x33;
          media_addr[1] = 0x33;
          media_addr[2] = SSH_IP6_BYTE13(next_hop);
          media_addr[3] = SSH_IP6_BYTE14(next_hop);
          media_addr[4] = SSH_IP6_BYTE15(next_hop);
          media_addr[5] = SSH_IP6_BYTE16(next_hop);
        }
      else
        {
          /* Normal rfc1112 multicast. */
          media_addr[0] = 0x01;
          media_addr[1] = 0x00;
          media_addr[2] = 0x5e;
          media_addr[3] = SSH_IP4_BYTE2(next_hop) & 0x7f;
          media_addr[4] = SSH_IP4_BYTE3(next_hop);
          media_addr[5] = SSH_IP4_BYTE4(next_hop);
        }
      goto success;
    }

  /* Loopback addresses. */
  if (SSH_IP_IS_LOOPBACK(next_hop))
    goto fail;

  /* If no luck so far, allocate new entry and initiate first ARP request */
  SSH_DEBUG(SSH_D_MIDOK, ("cached entries or special cases not found."));

  /* Obtain our own IP address. */
  protocol = SSH_PROTOCOL_IP4;
#ifdef WITH_IPV6
  if (SSH_IP_IS6(next_hop))
    protocol = SSH_PROTOCOL_IP6;
#endif /* WITH_IPV6 */

  if ((ssh_engine_get_ipaddr(engine, ifnum, protocol, next_hop, &own_addr)
       == FALSE) &&
      (ssh_engine_get_ipaddr(engine, ifnum, protocol, NULL, &own_addr)
       == FALSE))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not find local IP address %@"
                 " (next-hop gw %@ ifnum %u) of correct type",
                 ssh_ipaddr_render, &own_addr,
                 ssh_ipaddr_render, next_hop,
                 ifnum));
      goto fail;
    }

  /* There was no entry for this address and it is not one of the
     special addresses (local broadcasts and local addresses are
     always stored in the arp cache).  Allocate one (or reuse the old
     one).  Note that this may flush an old entry out of the cache if
     there are too many.  Note that the engine lock is still being
     held. */
  entry = engine_arp_cache_new_entry(engine);
  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not add ARP entry; memory allocation failure"));
      goto fail;
    }

  /* Initialize the arp cache entry. */
  memcpy(&entry->ip_addr, next_hop, sizeof(entry->ip_addr));
  memset(entry->ethernet_addr, 0, sizeof(entry->ethernet_addr));
  entry->ifnum = ifnum;
  entry->routing_instance_id = routing_instance_id;

  entry->status = SSH_ENGINE_ARP_INCOMPLETE;
#ifdef WITH_IPV6
  if (protocol == SSH_PROTOCOL_IP6)
    entry->arp_retry_count = SSH_ENGINE_ARP_IPV6_MAX_MCAST_RETRIES - 1;
  else
#endif /* WITH_IPV6 */
    entry->arp_retry_count = SSH_ENGINE_ARP_MAX_RETRIES - 1;

  /* Set initial expiry timeout. This will be updated when the entry
     status is changed to COMPLETE. */
  entry->expires = now_sec + SSH_ENGINE_ARP_INCOMPLETE_LIFETIME;

  /* Note that pc->pp may be NULL when rerouting flows. */
  if (pc->pp != NULL)
    {
      ssh_interceptor_packet_detach(pc->pp);
    }

  entry->queued_packet = pc;
  entry->queued_packet_nh_index = pc_nh_index;

  /* Add the entry into the list in the hash table. */
  engine_arp_hash_insert(engine, entry);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Created entry %@",
                               ssh_engine_arp_entry_render, entry));

  /* Add the entry to the arp cache lru list. */
  engine_arp_lru_bump(engine, entry, TRUE);

  /* Put the entry on the retry list so that retries will get processed.
     Also schedule a retry timeout if one hasn't been scheduled yet. */
  engine_arp_retry_list_insert(engine, entry);

  SSH_DEBUG(SSH_D_MIDOK, (" ...SSH_ENGINE_ARP_IN_PROGRESS now %p.",
                          cache->retry_list));

  /* Set and schedule retry timeout. */
  engine_arp_entry_set_request_timeout(engine, entry, now_sec, now_usec);
  engine_arp_request_timeout_schedule(engine, entry->retry_timeout_sec,
                                      entry->retry_timeout_usec,
                                      now_sec, now_usec);

  /* Release engine lock before sending packets. */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Send the request. */
#if defined(WITH_IPV6)
  /* Use multicast. */
  if (SSH_IP_IS6(next_hop))
    ssh_engine_arp_send_solicitation(engine, NULL, NULL, next_hop, ifnum,
                                     routing_instance_id, &own_addr, own_hw);
  else
#endif /* WITH_IPV6 */
    ssh_engine_arp_send_request(engine, next_hop, ifnum, &own_addr,
                                routing_instance_id, own_hw);

  /* Call the completion function for any packets waiting for it. */
  engine_arp_call_pending_completions(engine);

  return;

 fail:
  /* The ARP lookup failed immediately. */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Failed."));

  /* Call the completion function for any packets waiting for it. */
  engine_arp_call_pending_completions(engine);

  (*callback)(pc, SSH_ENGINE_ARP_LOOKUP_STATUS_ERROR, NULL, NULL, 0);
  return;

 success:
  /* The ARP lookup succeeded immediately. */
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  engine_arp_call_pending_completions(engine);

  if (SSH_IP_IS6(next_hop))
    ethertype = SSH_ETHERTYPE_IPv6;
  else
    ethertype = SSH_ETHERTYPE_IP;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Success."));

  (*callback)(pc, SSH_ENGINE_ARP_LOOKUP_STATUS_OK, own_hw, media_addr,
              ethertype);
  return;
}

#ifdef WITH_IPV6
/* Check if next_hop is known to be on link. */
Boolean engine_arp_on_link(SshEngine engine,
                           SshIpAddr next_hop,
                           SshEngineIfnum ifnum)
{
  SshEngineArpPrefixInfo prefix_info;
  SshEngineIfInfo if_info;
  SshInterceptorInterface *iface;

  SSH_ASSERT(SSH_IP_IS6(next_hop));
  SSH_ASSERT(!SSH_IP6_IS_LINK_LOCAL(next_hop));

  /* Lookup if_info. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (iface == NULL ||
      iface->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      /* Invalid ifnum or nonexistent interface. */
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum %d or nonexistent interface",
                             (int) ifnum));
      return FALSE;
    }
  if_info = iface->ctx_user;

  /* Prefix list is empty because we have not received any router
     advertisements recently. Therefore we can not decide on link
     status and we need to indicate that next hop is on link. */
  if (if_info->prefix_list == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return TRUE;
    }

  /* Lookup matching prefix from prefix list. */
  for (prefix_info = if_info->prefix_list;
       prefix_info != NULL;
       prefix_info = prefix_info->next)
    {
      if (SSH_IP_MASK_EQUAL(next_hop, &prefix_info->prefix))
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          return TRUE;
        }
    }

  /* We have prefixes in prefix list but none matched next hop.
     Indicate that next hop is not on link. */
  ssh_kernel_mutex_unlock(engine->interface_lock);
  return FALSE;
}
#endif /* WITH_IPV6 */

/* Check if next_hop is known to be on link and reachable. */
Boolean ssh_engine_arp_check_reachability(SshEngine engine,
                                          SshIpAddr next_hop,
                                          SshEngineIfnum ifnum)
{
  SshEngineArpCacheEntry entry;
  SshTime now_sec;
  SshUInt32 now_usec;

#ifdef WITH_IPV6
  /* Check if next_hop is known to be on link. */
  if (SSH_IP_IS6(next_hop) && !SSH_IP6_IS_LINK_LOCAL(next_hop))
    {
      if (engine_arp_on_link(engine, next_hop, ifnum) == FALSE)
        return FALSE;
    }
#endif /* WITH_IPV6 */

  /* Check if there is an ARP entry for next_hop. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  entry = engine_arp_lookup_entry(engine, next_hop, ifnum);
  if (entry == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return FALSE;
    }

  /* Trigger probe for stale entries. */
  if (entry->status == SSH_ENGINE_ARP_STALE)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Changing entry status to probe"));
      entry->status = SSH_ENGINE_ARP_PROBE;
#ifdef WITH_IPV6
      if (SSH_IP_IS6(&entry->ip_addr))
        entry->arp_retry_count = SSH_ENGINE_ARP_IPV6_MAX_UCAST_RETRIES;
      else
#endif /* WITH_IPV6 */
        entry->arp_retry_count = SSH_ENGINE_ARP_MAX_RETRIES;

      /* Add entry to retry list. */
      engine_arp_retry_list_insert(engine, entry);

      /* Schedule retry timeout to immediate future, the probe is sent from
         the retry timeout. */
      ssh_interceptor_get_time(&now_sec, &now_usec);
      entry->retry_timeout_sec = now_sec;
      entry->retry_timeout_usec = now_usec;
      engine_arp_request_timeout_schedule(engine, entry->retry_timeout_sec,
                                          entry->retry_timeout_usec,
                                          now_sec, now_usec);
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);
  return TRUE;
}


/* This function is called from a timeout every
   SSH_ENGINE_ARP_LIFETIME_CHECK_INTERVAL seconds.  This goes through
   all arp cache entries, and purges any entries whose lifetime has
   expired.  This may be called concurrently with other functions;
   this will momentarily take the engine lock to protect data
   structures. */

void ssh_engine_arp_cache_timeout(void *context)
{
  SshEngine engine = (SshEngine)context;
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 i;
  SshEngineArpCacheEntry entry, destroy_list;
  unsigned long num_arp = 0, num_reclaimed = 0;
  SshTime now;
  SshInterceptorInterface *iface;
  SshEngineIfInfo if_info;
#ifdef WITH_IPV6
  SshEngineArpRouterInfo router_info, router_destroy_list;
  SshEngineArpPrefixInfo prefix_info, prefix_destroy_list;
#endif /* WITH_IPV6 */
  SSH_DEBUG(SSH_D_LOWSTART, ("ARP; cache timeout"));

  ssh_interceptor_get_time(&now, NULL);

  /* Take the interface lock to protect data structures. */
  ssh_kernel_mutex_lock(engine->interface_lock);

  SSH_DEBUG(SSH_D_MIDSTART, ("Timing out ARP entries (%d elements in table)",
                             (int) cache->num_entries));

  /* Loop over the entire hash table. */
  destroy_list = NULL;
  for (i = 0; i < SSH_ENGINE_ARP_HASH_SIZE; i++)
    {
      /* Loop over all entries in the hash table slot. */
      for (entry = cache->hash[i]; entry != NULL; entry = entry->next)
        {
          num_arp++;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Checking entry %@ expires in %lus at %lu now %lu",
                     ssh_engine_arp_entry_render, entry,
                     (unsigned long) (entry->expires > now ?
                                      (entry->expires - now) : 0),
                     (unsigned long) entry->expires,
                     (unsigned long) now));

          /* Permanent entries never expire. */
          if (entry->status != SSH_ENGINE_ARP_PERMANENT)
            {
              /* The entry has expired if its lifetime is less than
                 the check interval. */
              if (entry->expires < now)
                {
                  if (entry->status == SSH_ENGINE_ARP_COMPLETE)
                    {
                      /* Ok, just move this as a stale entry and give a
                         bit more time for the entry. */
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Changing entry status to stale"));
                      entry->status = SSH_ENGINE_ARP_STALE;
                      entry->expires =
                        now + SSH_ENGINE_ARP_INCOMPLETE_LIFETIME;
                    }
                  else
                    {
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("  ...arp entry %@ timed out",
                                 ssh_engine_arp_entry_render, entry));
                      entry->status = SSH_ENGINE_ARP_FAILED;
                      num_reclaimed++;
                    }

                  /* Move entry to destroy list and free it when all
                     entries in the cache have been iterated. */
                  engine_arp_retry_list_remove(engine, entry);
                  entry->retry_list_next = destroy_list;
                  destroy_list = entry;
                }
            }
        }
    }

  /* Remove to be destroyed entries from hash table before the interface
     lock is released. */
  for (entry = destroy_list; entry != NULL; entry = entry->retry_list_next)
    {
      engine_arp_hash_remove(engine, entry);
    }

  /* Timeout default router and prefix lists. */
#ifdef WITH_IPV6
  router_destroy_list = NULL;
  prefix_destroy_list = NULL;
#endif /* WITH_IPV6 */
  for (i = 0; i < engine->ifs.nifs; i++)
    {
      iface = ssh_ip_get_interface_by_ifnum(&engine->ifs,
                                            engine->ifs.ifs[i].ifnum);
      if (iface == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Interface %u not found in the interface table",
                     engine->ifs.ifs[i].ifnum));
          continue;
        }

      SSH_DEBUG(SSH_D_LOWOK,
                ("Checking interface %s default router and prefix lists",
                 iface->name));

      if_info = iface->ctx_user;
      if (if_info != NULL)
        {
#ifdef WITH_IPV6
          engine_arp_router_info_timeout(engine, if_info,
                                         &router_destroy_list, now);
          engine_arp_prefix_info_timeout(engine, if_info,
                                         &prefix_destroy_list, now);
#endif /* WITH_IPV6 */
        }
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Mark matching next hop nodes for rerouting. */
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (entry = destroy_list; entry != NULL; entry = entry->retry_list_next)
    {
      ssh_engine_nh_node_reroute(engine, &entry->ip_addr,
                                 8 * SSH_IP_ADDR_LEN(&entry->ip_addr),
                                 entry->ifnum);
    }

#ifdef WITH_IPV6
  for (router_info = router_destroy_list;
       router_info != NULL;
       router_info = router_info->next)
    {
      ssh_engine_nh_node_reroute(engine, &router_info->router_addr,
                                 8*SSH_IP_ADDR_LEN(&router_info->router_addr),
                                 router_info->ifnum);
    }

  for (prefix_info = prefix_destroy_list;
       prefix_info != NULL;
       prefix_info = prefix_info->next)
    {
      ssh_engine_nh_node_reroute(engine, &prefix_info->prefix,
                                 8 * SSH_IP_MASK_LEN(&prefix_info->prefix),
                                 prefix_info->ifnum);
    }
#endif /* WITH_IPV6 */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Process destroyed entries. */
  while (destroy_list != NULL)
    {
      entry = destroy_list;
      destroy_list = destroy_list->retry_list_next;
      entry->retry_list_next = NULL;

      /* Remove the timed out entries from hash table
         and lists and free them. */
      if (entry->status == SSH_ENGINE_ARP_FAILED)
        {
          engine_arp_free_entry(engine, entry);
        }

      /* Add stale IPv6 cache entries back to hash table. */
      else
        {
          SSH_ASSERT(entry->status == SSH_ENGINE_ARP_STALE);
          engine_arp_hash_insert(engine, entry);
        }
    }

#ifdef WITH_IPV6
  /* Free destroyed routers. */
  while (router_destroy_list != NULL)
    {
      router_info = router_destroy_list;
      router_destroy_list = router_destroy_list->next;
      engine_arp_router_info_free(engine, router_info);
    }

  /* Free destroyed prefixes. */
  while (prefix_destroy_list != NULL)
    {
      prefix_info = prefix_destroy_list;
      prefix_destroy_list = prefix_destroy_list->next;
      engine_arp_prefix_info_free(engine, prefix_info);
    }
#endif /* WITH_IPV6 */

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  engine_arp_call_pending_completions(engine);

  SSH_DEBUG(SSH_D_MIDOK,
            ("ARP entries left %ld, reclaimed %ld", num_arp, num_reclaimed));

#ifndef SSH_IPSEC_SMALL
  /* Schedule the timeout to occur again after the lifetime check
     interval. */
  ssh_kernel_timeout_register((long)SSH_ENGINE_ARP_LIFETIME_CHECK_INTERVAL, 0L,
                              ssh_engine_arp_cache_timeout, (void *)engine);
#endif /* SSH_IPSEC_SMALL */
}

/* Initializes the data structures needed for arp lookups and the arp
   cache.  This is not called concurrently for the same engine and
   media context. */

void ssh_engine_arp_init(SshEngine engine, SshUInt32 flags)
{
  /* Initialize the arp cache field to zero. */
  memset(&engine->arp_cache, 0, sizeof(engine->arp_cache));




  engine->arp_cache.token_ring_multicast =
    (flags & SSH_ENGINE_ARP_RFC1469_MCAST) != 0;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  { /* Initialize arp entry freelist. */
    SshUInt32 i;
    ssh_engine_arp_entry_freelist = NULL;
    for (i = 0; i < SSH_ENGINE_ARP_CACHE_SIZE; i++)
      {
        ssh_engine_arp_entry_table[i].status = 0x7a; /* free magic */
        ssh_engine_arp_entry_table[i].next = ssh_engine_arp_entry_freelist;
        ssh_engine_arp_entry_freelist = &ssh_engine_arp_entry_table[i];
      }
  }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#ifndef SSH_IPSEC_SMALL
  /* Call the arp cache timeout once to start scheduling the timeouts. */
  ssh_engine_arp_cache_timeout((void *)engine);
#endif /* SSH_IPSEC_SMALL */
}

/* Clears the ARP cache.  All entries are dropped from the cache, and
   all pending ARP requests are gracefully completed (by calling their
   callbacks with failure indication). This will momentarily take
   engine->interface_lock to modify the cache data structures. */

void ssh_engine_arp_clear(SshEngine engine)
{
  SshUInt32 i;

  /* Loop over the arp cache hash table. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  for (i = 0; i < SSH_ENGINE_ARP_HASH_SIZE; i++)
    {
      /* Free all entries in the hash slot.  Freeing the entry will
         also remove it from the hash table. */
      while (engine->arp_cache.hash[i])
        engine_arp_free_entry(engine, engine->arp_cache.hash[i]);
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Call the completion function for any packets waiting for it. */
  engine_arp_call_pending_completions(engine);
}

/* Uninitializes (frees) the data structures allocated for the arp
   cache.  This is not called concurrently for the same engine and
   media context. */
void ssh_engine_arp_uninit(SshEngine engine)
{
  /* Clear the ARP cache and abort any pending ARP requests. */
  ssh_engine_arp_clear(engine);

  /* Cancel the arp cache timeout. */
  /* Note this call will also cancel the timeout for
     process_asynch_packets().
     If SEND_IS_SYNC then packets generated during
     ssh_engine_arp_clear() will never be sent out. */
  ssh_kernel_timeout_cancel(SSH_KERNEL_ALL_CALLBACKS, (void *)engine);
}

/* Removes any mapping for the given ip address, even if permanent.
   This function is called with the engine lock held. This must not
   release it even momentarily. */

void ssh_engine_arp_delete(SshEngine engine,
                           SshIpAddr ip_addr, SshEngineIfnum ifnum)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshUInt32 hash;
  SshEngineArpCacheEntry entry;

  SSH_DEBUG(SSH_D_HIGHSTART, ("arp delete %@", ssh_ipaddr_render, ip_addr));

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Compute a hash value from the ip address. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(ip_addr);

  /* Check if the slot contains the address we are looking for. */
  for (entry = cache->hash[hash]; entry; entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
        break;
    }

  /* If an entry matching the address was found, remove it now. */
  if (entry != NULL)
    engine_arp_free_entry(engine, entry);

  /* We should really call engine_arp_call_pending_completions here,
     but cannot since the API for this function specifies that this is
     called with the lock held.  However, not doing it here should not
     be a problem in real life; the completions will be called next time
     an entry is freed. */
}

/* Adds a permanent mapping for the given address in the arp cache
   as a permanent entry.  This function is called with the engine lock
   held; this must not release it even momentarily. */

Boolean ssh_engine_arp_add(SshEngine engine,
                           SshIpAddr ip_addr, SshEngineIfnum ifnum,
                           const unsigned char *hw_addr, Boolean permanent,
                           Boolean proxy_arp,
                           Boolean is_global)
{
  SshEngineArpCacheEntry entry;
  SshTime now;
#ifdef DEBUG_LIGHT
  SshUInt32 hash;
#endif /* DEBUG_LIGHT */

  ssh_interceptor_get_time(&now, NULL);

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("add %sip %@ media %@",
             permanent ? "permanent " : "",
             ssh_ipaddr_render, ip_addr,
             ssh_engine_arp_render_eth_mac, hw_addr));

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* Remove any old entry for the same IP that might be in the cache.
     This could potentially happen with dynamic IP addresses. */
  ssh_engine_arp_delete(engine, ip_addr, ifnum);

#ifdef DEBUG_LIGHT
  /* Compute a hash value from the ip address. */
  hash = SSH_ENGINE_ARP_CACHE_HASH(ip_addr);

  /* The entry should not be in the cache since we just deleted it. */
  for (entry = engine->arp_cache.hash[hash];
       entry != NULL;
       entry = entry->next)
    {
      if (SSH_IP_EQUAL(&entry->ip_addr, ip_addr) && entry->ifnum == ifnum)
        break;
    }
  SSH_ASSERT(entry == NULL);
#endif /* DEBUG_LIGHT */

  /* There was no entry for this address in the arp cache.  Allocate one.
     Note that this may flush an old entry out of the cache if there are
     too many.  Note that this call may put something on
     cache->packets_waiting_completion, and
     engine_arp_call_pending_completions should be called after the lock
     is released.  We don't specify that in our external interface, but
     that should not cause problems in real life. */
  entry = engine_arp_cache_new_entry(engine);
  if (entry == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not add ARP entry due to memory allocation failure"));
      return FALSE;
    }

  /* Initialize the arp cache entry. */
  memcpy(&entry->ip_addr, ip_addr, sizeof(entry->ip_addr));
  entry->ifnum = ifnum;

  if (permanent == TRUE)
    {
      entry->status = SSH_ENGINE_ARP_PERMANENT;
    }
  else
    {
      entry->status = SSH_ENGINE_ARP_COMPLETE;
      engine_arp_entry_set_expiry_timeout(engine, entry, now);
    }

  if (proxy_arp)
    entry->flags |= SSH_ENGINE_ARP_F_PROXY;
  if (is_global)
    entry->flags |= SSH_ENGINE_ARP_F_GLOBAL;

  memcpy(entry->ethernet_addr, hw_addr, sizeof(entry->ethernet_addr));

  /* Add the entry into the list in the hash table. */
  engine_arp_hash_insert(engine, entry);

  SSH_DEBUG(SSH_D_HIGHSTART, ("Arp added entry %@",
                              ssh_engine_arp_entry_render, entry));

  /* Note: the entry is NOT put on the arp cache lru list, if it is a
     permanent entry.  Permanent entries are however counted in
     num_entries.  (This makes the code more robust; on systems with a
     high number of IP aliases (e.g. web servers), there could be more
     local IP addresses than is the nominal size of the ARP cache.) */





  /* Add the entry to the arp cache lru list if not permanent. */
  if (permanent == FALSE)
    engine_arp_lru_bump(engine, entry, TRUE);

  return TRUE;
}

/* Removes given interfaces PERMANENT addresses from ARP cache. */

static void
ssh_engine_arp_remove_interface(SshEngine engine,
                                SshInterceptorInterface *ifp)
{
  SshUInt32 i;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* If the adapter does not have an ethernet-like media type in either
     direction, then do nothing. */
  if (ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_TOKENRING &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_TOKENRING)
    return;

  for (i = 0; i < ifp->num_addrs; i++)
    {
      if (ifp->addrs[i].protocol != SSH_PROTOCOL_IP4 &&
          ifp->addrs[i].protocol != SSH_PROTOCOL_IP6)
        continue;

      /* Add this mapping in the arp cache as a permanent entry. */
      ssh_engine_arp_delete(engine, &ifp->addrs[i].addr.ip.ip,
                            ifp->ifnum);

      if (ifp->addrs[i].protocol == SSH_PROTOCOL_IP4 &&
          SSH_IP_DEFINED(&ifp->addrs[i].addr.ip.broadcast))
        ssh_engine_arp_delete(engine, &ifp->addrs[i].addr.ip.broadcast,
                              ifp->ifnum);
    }
}

/* Adds given interfaces PERMANENT addresses to the ARP cache. */

static void
ssh_engine_arp_add_interface(SshEngine engine,
                             SshInterceptorInterface *ifp)
{
  SshUInt32 i;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* If the adapter does not have an ethernet-like media type in either
     direction, then do nothing. */
  if (ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_TOKENRING &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_TOKENRING)
    return;

  for (i = 0; i < ifp->num_addrs; i++)
    {
      if (ifp->addrs[i].protocol != SSH_PROTOCOL_IP4 &&
          ifp->addrs[i].protocol != SSH_PROTOCOL_IP6)
        continue;

      /* Add this mapping in the arp cache as a permanent entry. */
      (void) ssh_engine_arp_add(engine, &ifp->addrs[i].addr.ip.ip,
                                ifp->ifnum,
                                ifp->media_addr, TRUE, FALSE, FALSE);

      if (ifp->addrs[i].protocol == SSH_PROTOCOL_IP4 &&
          SSH_IP_DEFINED(&ifp->addrs[i].addr.ip.broadcast))
        (void) ssh_engine_arp_add(engine, &ifp->addrs[i].addr.ip.broadcast,
                                  ifp->ifnum,
                                  ssh_engine_arp_ethernet_broadcast_addr,
                                  TRUE, FALSE, FALSE);
    }
}

/* Flushes all ARP entries for the given interface. */

static
void ssh_engine_arp_flush_interface(SshEngine engine,
                                    SshInterceptorInterface *ifp)
{
  SshEngineArpCache cache = &engine->arp_cache;
  SshEngineArpCacheEntry entry, next;
  SshUInt32 i;

  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  /* If the adapter does not have an ethernet-like media type in either
     direction, then do nothing. */
  if (ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_adapter.media != SSH_INTERCEPTOR_MEDIA_TOKENRING &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_ETHERNET &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_FDDI &&
      ifp->to_protocol.media != SSH_INTERCEPTOR_MEDIA_TOKENRING)
    return;

  /* We are removing a interface. We flush all the entries related to
     the specific interface. */
  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Flushing all arp entries for ifnum %d", ifp->ifnum));

  for (i = 0; i < SSH_ENGINE_ARP_HASH_SIZE; i++)
    {
      /* Check if the slot contains the address we are looking for. */
      entry = cache->hash[i];
      while (entry != NULL)
        {
          next = entry->next;

          /* Do we have a match on the interface number? */
          if (entry->ifnum == ifp->ifnum)
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("Deleting arp entry %p for "
                                       "interface %d", entry, ifp->ifnum));
              engine_arp_free_entry(engine, entry);
            }

          entry = next;
        }
    }
}

/* A function of this type is called to inform the media-specific code
   about network interfaces of that type that are available.  For
   ethernet and ieee 802 networks, this registers the interface
   addresses in the arp cache as permanent entries.  Entries for the
   old interface structure will first be removed from the cache to
   handle updates correctly.  Either interface can be NULL.  This
   function is called with the engine lock held; this must not release
   it even momentarily. */
void ssh_engine_arp_update_interface(SshEngine engine,
                                     SshEngineIfnum ifnum,
                                     SshInterceptorInterface *oldif,
                                     SshInterceptorInterface *newif,
                                     SshUInt32 flags)
{
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  SSH_ASSERT(oldif != NULL || newif != NULL);

  /* Remove any addresses related to the old interface from the cache. */
  if (oldif != NULL && newif == NULL)
    ssh_engine_arp_remove_interface(engine, oldif);

  if (flags & SSH_ENGINE_ARP_UPDATE_FLAG_FLUSH)
    ssh_engine_arp_flush_interface(engine, oldif != NULL ? oldif : newif);

  /* Add any addresses related to the new interface to the cache. */
  if (newif != NULL)
    ssh_engine_arp_add_interface(engine, newif);
}

void
ssh_engine_arp_if_info_free(SshEngine engine, SshEngineIfInfo if_info)
{
#ifdef WITH_IPV6
  SshEngineArpRouterInfo router_info;
  SshEngineArpPrefixInfo prefix_info;

  SSH_ASSERT(if_info != NULL);
  while (if_info->router_list != NULL)
    {
      router_info = if_info->router_list;
      if_info->router_list = router_info->next;
      engine_arp_router_info_free(engine, router_info);
    }

  while (if_info->prefix_list != NULL)
    {
      prefix_info = if_info->prefix_list;
      if_info->prefix_list = prefix_info->next;
      engine_arp_prefix_info_free(engine, prefix_info);
    }
#endif /* WITH_IPV6 */
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
