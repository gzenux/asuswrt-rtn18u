/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS RRset cache layer
   This layer will cache RRsets received from the name server.
   It will be used first, and if data is not available here, then it is
   fetched from the real nameserver. This is also used to combine
   identical requests, and to create search history for the request.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshenum.h"

#define SSH_DEBUG_MODULE "SshDnsRRsetCache"


/* Cache context structure. */
struct SshDNSRRsetCacheRec {
  /* Maximum number of total memory used by cache. Default
     is 64 kB. This includes memory used for rrsets and
     other control structures. */
  size_t max_memory;
  size_t memory_used;

  /* Number of rrsets to keep even when not used. Default is
     256. Note, that the cache is cleared only when some
     query is finished, thus the cache size might
     temporarely go over this. */
  SshUInt32 keep_rrsets;

  /* Maximum number of rrsets. Default is 512. */
  SshUInt32 max_rrsets;

  /* Total number of rrsets. */
  SshUInt32 total_rrsets;

  /* Each rrset entry will be in the cache at least this
     many seconds. Default is 30 seconds. This is trying to
     make sure that the entries needed to finish the name
     resolution process are not cleared from the cache too
     early. */
  SshUInt32 minimum_lifetime;

  /* Maximum TTL which is allowed. Default is 864000 (10 days). */
  SshUInt32 maximum_ttl;

  /* Items which are valid are always in the rrset_bag. If the item is marked
     not to be valid (i.e. `valid' flag is set FALSE), then it is removed from
     the rrset_bag. This can happen, if the entry is overwritten with newer
     and different data, or if it expires.

     If the entry has reference count > 0 then it is not on the free_list.
     Otherwise it is there if it is valid. If it is not valid, then it is
     either removed immediately or removed when the references goes to zero. */

  /* Container containing the mapping from the name to the rrset structure.
     The key is the name in dns format (i.e 1-byte length, label, 1-byte
     length, label, terminated with the root (1-byte length of value 0 ==
     nul-terminated). */
  SshADTContainer rrset_bag;

  /* List of free entries in the rrset_bag. These entries are still valid
     but they can be freed if needed (unless they are less than
     minimum_lifetime seconds old). */
  SshADTContainer free_list;
};

/* Notification structure. */
struct SshDNSRRsetNotifyRec {
  struct SshDNSRRsetNotifyRec *next;
  SshOperationHandleStruct operation_handle[1];
  /* Back pointers. */
  SshDNSRRsetCache cache;
  SshDNSRRset rrset;
  SshDNSRRsetNotifyCB callback;
  void *context;
};

typedef struct SshDNSRRsetNotifyRec SshDNSRRsetNotifyStruct;

/* Hash function for rrsets. */
SshUInt32 ssh_dns_rrset_cache_adt_hash(void *ptr, void *ctx)
{
  SshDNSRRset rrset = ptr;
  SshUInt32 hash;
  const unsigned char *c;
  unsigned char d;

  c = rrset->name;
  hash = rrset->type;
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

/* Compare function for rrsets. */
int ssh_dns_rrset_cache_adt_cmp(void *ptr1, void *ptr2, void *ctx)
{
  SshDNSRRset rrset1 = ptr1;
  SshDNSRRset rrset2 = ptr2;
  int ret;

  ret = ssh_ustrcasecmp(rrset1->name, rrset2->name);
  if (ret == 0)
    return rrset2->type - rrset1->type;
  return ret;
}

void ssh_dns_rrset_cache_free(SshDNSRRsetCache rrset_cache);
void ssh_dns_rrset_free(SshDNSRRsetCache cache, SshDNSRRset rrset);

/* Allocate rrset cache. The cache will be allocated using
   default configuration. This will return NULL if out of
   memory. */
SshDNSRRsetCache
ssh_dns_rrset_cache_allocate(void)
{
  SshDNSRRsetCache cache;

  cache = ssh_calloc(1, sizeof(*cache));
  if (cache == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating rrset cache"));
      return NULL;
    }
  SSH_DEBUG(SSH_D_HIGHSTART, ("RRset cache allocated"));

  cache->max_memory = 65536;
  cache->keep_rrsets = 256;
  cache->max_rrsets = 512;
  cache->total_rrsets = 0;
  cache->minimum_lifetime = 5;
  cache->memory_used = sizeof(*cache);
  cache->maximum_ttl = 864000;

  cache->rrset_bag =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HASH,
                           ssh_dns_rrset_cache_adt_hash,
                           SSH_ADT_COMPARE,
                           ssh_dns_rrset_cache_adt_cmp,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSRRsetStruct,
                                             rrset_bag_header),
                           SSH_ADT_ARGS_END);

  cache->free_list =
    ssh_adt_create_generic(SSH_ADT_LIST,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshDNSRRsetStruct,
                                             free_list_header),
                           SSH_ADT_ARGS_END);

  if (cache->rrset_bag == NULL ||
      cache->free_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating rrset cache"));
      ssh_dns_rrset_cache_free(cache);
      return NULL;
    }
  return cache;

}

/* Allocate rrset. The entry allocated will have one reference. */
SshDNSRRset
ssh_dns_rrset_allocate(SshDNSRRsetCache cache,
                       const unsigned char *rrset_name,
                       SshDNSRRsetState state,
                       SshDNSRRType type,
                       SshUInt32 ttl,
                       SshUInt32 number_of_rrs,
                       size_t array_of_rdlengths[],
                       unsigned char **array_of_rdata,
                       SshDNSRRset parent)
{
  SshDNSRRset rrset;
  SshADTHandle h;
  size_t len1, len2;
  SshUInt32 i;
  unsigned char *ptr;

  if (cache->total_rrsets >= cache->max_rrsets)
    return NULL;

  len1 = sizeof(*rrset) +
    number_of_rrs * (sizeof(size_t) + sizeof(unsigned char *)) +
    ssh_ustrlen(rrset_name) + 1;
  for(len2 = 0, i = 0; i < number_of_rrs; i++)
    len2 += array_of_rdlengths[i];

  if (cache->memory_used + len1 + len2 > cache->max_memory)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory limit exceeded while allocating RRset"));
      return NULL;
    }

  rrset = ssh_calloc(1, len1 + len2);
  if (rrset == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating RRset"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Allocating RRset %p %@ of type %s (%d), parent = %p %@",
             rrset, ssh_dns_name_render, rrset_name,
             ssh_dns_rrtype_string(type), type,
             parent, ssh_dns_name_render, parent));

  rrset->state = state;
  rrset->type = type;
  rrset->ttl = (ttl < cache->minimum_lifetime ? cache->minimum_lifetime : ttl);
  if (rrset->ttl > cache->maximum_ttl)
    rrset->ttl = cache->maximum_ttl;
  rrset->number_of_rrs = number_of_rrs;
  rrset->array_of_rdlengths = (void *)
    ((unsigned char *) rrset + sizeof(*rrset));
  memcpy(rrset->array_of_rdlengths, array_of_rdlengths,
         number_of_rrs * sizeof(size_t));
  rrset->array_of_rdata = (void *)
    ((unsigned char *) rrset + sizeof(*rrset) +
     number_of_rrs * sizeof(size_t));
  ptr = (unsigned char *) rrset + sizeof(*rrset) +
    number_of_rrs * (sizeof(size_t) + sizeof(unsigned char *));
  rrset->name = ptr;
  ssh_ustrcpy(rrset->name, rrset_name);
  ptr += ssh_ustrlen(rrset_name) + 1;
  for(i = 0; i < number_of_rrs; i++)
    {
      rrset->array_of_rdata[i] = ptr;
      memcpy(rrset->array_of_rdata[i], array_of_rdata[i],
             array_of_rdlengths[i]);
      ptr += array_of_rdlengths[i];
    }
  rrset->reference_count = 1;
  rrset->valid = TRUE;
  rrset->cached_time = ssh_time();

  h = ssh_adt_insert(cache->rrset_bag, rrset);
  if (h == SSH_ADT_INVALID)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating RRset"));
      ssh_free(rrset);
      return NULL;
    }
  cache->total_rrsets++;
  cache->memory_used += len1 + len2;

  rrset->parent = parent;
  if (rrset->parent != NULL)
    {
      if (rrset->parent->childs == NULL)
        {
          /* No childs, add as first child. */
          rrset->parent->childs = rrset;
          /* Make the siblings list to circular. */
          rrset->next_sibling = rrset;
          rrset->prev_sibling = rrset;
        }
      else
        {
          /* There are already childs, add ourself to the ring. */
          rrset->next_sibling = rrset->parent->childs->next_sibling;
          rrset->prev_sibling = rrset->parent->childs;
          rrset->parent->childs->next_sibling->prev_sibling = rrset;
          rrset->parent->childs->next_sibling = rrset;
        }
    }
  return rrset;
}

/* Free name server. This assumes it is already removed from the free_list. */
void
ssh_dns_rrset_free(SshDNSRRsetCache cache,
                   SshDNSRRset rrset)
{
  size_t len1, len2;
  SshUInt32 i;

  /* Remove from the bag if it is still there. */
  if (rrset->valid)
    ssh_adt_detach_object(cache->rrset_bag, rrset);

  len1 = sizeof(*rrset) +
    rrset->number_of_rrs * (sizeof(size_t) + sizeof(unsigned char *)) +
    ssh_ustrlen(rrset->name) + 1;
  for(len2 = 0, i = 0; i < rrset->number_of_rrs; i++)
    len2 += rrset->array_of_rdlengths[i];

  cache->memory_used -= len1 + len2;
  cache->total_rrsets--;
  if (rrset->parent != NULL)
    {
      /* Are we the first child. If so, make next child the first
         child or set childs to NULL if no other childs. */
      if (rrset->parent->childs == rrset)
        {
          /* We are the first. */
          if (rrset->next_sibling == rrset)
            {
              /* No other childs */
              rrset->parent->childs = NULL;
            }
          else
            {
              rrset->parent->childs = rrset->next_sibling;
            }
        }

      /* Are we the only child. */
      if (rrset->next_sibling == rrset)
        {
          SSH_ASSERT(rrset->prev_sibling == rrset);
          /* No need to do anything. */
        }
      else
        {
          /* We do have siblings, we have already fixed the
             parent pointer, so we only need to remove us from the
             siblings lists. */
          rrset->next_sibling->prev_sibling = rrset->prev_sibling;
          rrset->prev_sibling->next_sibling = rrset->next_sibling;
        }
    }

  /* Now we need to fix our childs parent pointers. */
  if (rrset->childs != NULL)
    {
      SshDNSRRset sibling;

      sibling = rrset->childs;

      /* Fix all the siblings until we hit the sibling whose next pointer
         has already been set to NULL. Note. that all siblings must have
         same parent pointer. */
      while (sibling != NULL)
        {
          SSH_ASSERT(sibling->parent == rrset);
          sibling->parent = NULL;
          sibling->prev_sibling->next_sibling = NULL;
          sibling->prev_sibling = NULL;
          sibling = sibling->next_sibling;
        }
    }
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Freeing RRset %p %@ of type %s (%d), parent = %p %@",
             rrset, ssh_dns_name_render, rrset->name,
             ssh_dns_rrtype_string(rrset->type),
             rrset->type, rrset->parent, ssh_dns_name_render, rrset->parent));
  ssh_free(rrset);
}

/* Verify that limits are matched, i.e. free extra rrset items etc. */
void
ssh_dns_rrset_verify_limits(SshDNSRRsetCache cache,
                            Boolean check_time)
{
  SshDNSRRset rrset;
  SshTime t;

  SSH_DEBUG(SSH_D_LOWSTART, ("RRset cache verify limits"));

  if (check_time)
    t = ssh_time();
  else
    t = 0;

  if ((cache->total_rrsets > cache->keep_rrsets * 9 / 10 ||
       cache->memory_used > cache->max_memory * 9 / 10) &&
      ssh_adt_num_objects(cache->free_list) > 0)
    {
      while((cache->total_rrsets > cache->keep_rrsets * 8 / 10 ||
             cache->memory_used > cache->max_memory * 8 / 10) &&
            ssh_adt_num_objects(cache->free_list) > 0)
        {
          rrset = ssh_adt_detach_from(cache->free_list, SSH_ADT_BEGINNING);
          /* No more entries in the free list, we cannot
             free more entries now. Must wait until there
             are more free entries before we can fullfill
             the new max_rrset limit. */
          SSH_ASSERT(rrset != NULL);
          /* We cannot remove this because its
             first_remove_time is too small. */
          if (t != 0 && rrset->cached_time + cache->minimum_lifetime > t)
            {
              /* Insert it back to the list at the end. */
              ssh_adt_insert(cache->free_list, rrset);
              /* Stop the process now. */
              break;
            }
          ssh_dns_rrset_free(cache, rrset);
        }
      if (cache->total_rrsets >= cache->max_rrsets)
        {
          /* We didn't manage to free enough items to make one empty slot, lets
             force the cache cleanup now. */
          ssh_dns_rrset_cache_clean(cache);
        }
    }
}

/* Clean up cache. */
void ssh_dns_rrset_cache_clean(SshDNSRRsetCache rrset_cache)
{
  SshADTHandle h, next_h;
  SshDNSRRset rrset;
  SshTime t;

  SSH_DEBUG(SSH_D_LOWSTART, ("RRset cache clean"));

  t = ssh_time();
  h = ssh_adt_enumerate_start(rrset_cache->free_list);

  while (h != SSH_ADT_INVALID)
    {
      rrset = ssh_adt_get(rrset_cache->free_list, h);

      next_h = ssh_adt_enumerate_next(rrset_cache->free_list, h);

      /* See if the entry is expired. */
      if (SSH_DNS_RRSET_EXPIRED(rrset, t))
        {
          /* Check if it has references. */
          if (rrset->reference_count > 0)
            {
              /* Yes. Mark it not to be valid, and remove it from the bag. */
              ssh_adt_detach_object(rrset_cache->rrset_bag, rrset);

              /* Mark it not valid. */
              rrset->valid = FALSE;

              /* It cannot be in the free_list as it has references, so now we
                 are done. We cannot free it yet, until all references go
                 away. */
            }
          else
            {
              /* No references, we can free it immediately. */
              /* First remove it from the free_list. */
              ssh_adt_detach_object(rrset_cache->free_list, rrset);

              /* Free the object. */
              ssh_dns_rrset_free(rrset_cache, rrset);
            }
        }
      h = next_h;
    }
}

/* Configure rrset cache. This returns true if the operation
   was successful, and FALSE if it run out of memory during
   the configure. In case of memory error some of the
   operations might have been done, and some may still be
   using old values. The rrset cache will still be usable even
   if memory error is received. */
Boolean
ssh_dns_rrset_cache_configure(SshDNSRRsetCache cache,
                              SshDNSRRsetCacheConfig config)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Configuring rrset cache"));
  if (config == NULL)
    {
      cache->max_memory = 0;
      cache->keep_rrsets = 0;
      cache->max_rrsets = 0;
      cache->minimum_lifetime = 0;
      cache->maximum_ttl = 0;
    }
  else
    {
      cache->max_memory = config->max_memory;
      cache->keep_rrsets = config->keep_rrsets;
      cache->max_rrsets = config->max_rrsets;
      cache->minimum_lifetime = config->minimum_lifetime;
      cache->maximum_ttl = config->maximum_ttl;
    }

  if (cache->keep_rrsets == 0)
    cache->keep_rrsets = 256;
  if (cache->max_rrsets == 0)
    cache->max_rrsets = 512;
  if (cache->max_memory == 0)
    cache->max_memory = 65536;
  if (cache->minimum_lifetime == 0)
    cache->minimum_lifetime = 30;
  if (cache->maximum_ttl == 0)
    cache->maximum_ttl = 864000;

  if (cache->keep_rrsets >= cache->max_rrsets)
    cache->keep_rrsets = cache->max_rrsets;

  ssh_dns_rrset_verify_limits(cache, TRUE);
  return TRUE;

}

/* Free rrset cache. There must not be any locked entries
   when this is called. */
void
ssh_dns_rrset_cache_free(SshDNSRRsetCache cache)
{
  /* This will free everything on the free list, as we move everything there.
     Note, that we cannot have any requests out when this is called, thus after
     this the total_rrset should be 0. */
  if (cache->rrset_bag != NULL && cache->free_list != NULL)
    {
      cache->keep_rrsets = 0;
      ssh_dns_rrset_verify_limits(cache, FALSE);
    }
  if (cache->rrset_bag != NULL)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle h;
      SshDNSRRset rrset;

      h = ssh_adt_enumerate_start(cache->rrset_bag);
      while (h != SSH_ADT_INVALID)
        {
          rrset = ssh_adt_get(cache->rrset_bag, h);
          SSH_DEBUG(SSH_D_ERROR, ("Entry name %@ type %s (%d) still in bag "
                                  "reference = %d, state = %s",
                                  ssh_dns_name_render, rrset->name,
                                  ssh_dns_rrtype_string(rrset->type),
                                  rrset->type,
                                  (int) rrset->reference_count,
                                  ssh_dns_rrsetstate_string(rrset->state)));
          h = ssh_adt_enumerate_next(cache->rrset_bag, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(cache->rrset_bag) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(cache->rrset_bag);
    }
  if (cache->free_list != NULL)
    {
#ifdef DEBUG_LIGHT
      SshADTHandle h;
      SshDNSRRset rrset;

      h = ssh_adt_enumerate_start(cache->free_list);
      while (h != SSH_ADT_INVALID)
        {
          rrset = ssh_adt_get(cache->free_list, h);
          SSH_DEBUG(SSH_D_ERROR, ("Entry name %@ type %s (%d) still in bag",
                                  ssh_dns_name_render, rrset->name,
                                  ssh_dns_rrtype_string(rrset->type),
                                  rrset->type));
          h = ssh_adt_enumerate_next(cache->free_list, h);
        }
      SSH_ASSERT(ssh_adt_num_objects(cache->free_list) == 0);
#endif /* DEBUG_LIGHT */
      ssh_adt_destroy(cache->free_list);
    }
  SSH_ASSERT(cache->total_rrsets == 0);
  SSH_ASSERT(cache->memory_used == sizeof(*cache));
  SSH_DEBUG(SSH_D_HIGHSTART, ("RRset cache freed"));
  ssh_free(cache);
}

/* Find rrset from cache. This will automatically allocate
   reference to the rrset returned. Returns NULL if no item
   found from cache. */
SshDNSRRset
ssh_dns_rrset_cache_get(SshDNSRRsetCache rrset_cache,
                        const unsigned char *name,
                        SshDNSRRType type)
{
  SshDNSRRsetStruct rrset[1];
  SshDNSRRset rrset_ptr;
  SshADTHandle h;

  memset(rrset, 0, sizeof(*rrset));
  rrset->name = (unsigned char *) name;
  rrset->type = type;
  h = ssh_adt_get_handle_to_equal(rrset_cache->rrset_bag, rrset);
  if (h == SSH_ADT_INVALID)
    {
      /* Search for wildcard entry. */
      rrset->type = SSH_DNS_QUERY_ANY;
      h = ssh_adt_get_handle_to_equal(rrset_cache->rrset_bag, rrset);
      if (h == SSH_ADT_INVALID)
        {
          SSH_DEBUG(SSH_D_LOWSTART, ("Did not found RRset %@ of type %s (%d)",
                                     ssh_dns_name_render, name,
                                     ssh_dns_rrtype_string(type),
                                     type));
          return NULL;
        }
      SSH_DEBUG(SSH_D_LOWSTART, ("Found wildcard RRset %@ of type %s (%d)",
                                 ssh_dns_name_render, name,
                                 ssh_dns_rrtype_string(type),
                                 type));
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Found RRset %@ of type %s (%d)",
                                 ssh_dns_name_render, name,
                                 ssh_dns_rrtype_string(type),
                                 type));
    }
  rrset_ptr = ssh_adt_get(rrset_cache->rrset_bag, h);
  if (rrset_ptr->reference_count == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Removing it from the free list"));
      /* Remove it from the free list. */
      ssh_adt_detach_object(rrset_cache->free_list, rrset_ptr);
    }
  rrset_ptr->reference_count++;
  return rrset_ptr;
}

/* Notify was canceled, remove the notify from the list. */
void ssh_dns_rrset_cache_notify_abort(void *context)
{
  SshDNSRRsetNotify notify = context;
  SshDNSRRsetNotify *notify_ptr;

  SSH_DEBUG(SSH_D_MIDSTART, ("Aborting RRset %@ notify of type %s (%d)",
                             ssh_dns_name_render, notify->rrset->name,
                             ssh_dns_rrtype_string(notify->rrset->type),
                             notify->rrset->type));

  notify_ptr = &(notify->rrset->notify);
  while (*notify_ptr != NULL && *notify_ptr != notify)
    notify_ptr = &((*notify_ptr)->next);

  SSH_ASSERT(*notify_ptr != NULL);
  *notify_ptr = notify->next;
  if (notify->rrset->notify == NULL)
    {
      /* This was last notify, deallocate one reference. */
      ssh_dns_rrset_cache_unlock(notify->cache, notify->rrset);
    }
  ssh_free(notify);
}

/* Add notify callback to RRset. This can only be called if
   the RRset is in SSH_DNS_RRSET_IN_PROGRESS state. The
   callback will be called when the data is available in the
   cache (or the operation requesting data timed out). This
   returns TRUE if operation was successful. */
SshOperationHandle
ssh_dns_rrset_cache_add_notify(SshDNSRRsetCache cache,
                               SshDNSRRset rrset,
                               SshDNSRRsetNotifyCB callback,
                               void *context)
{
  SshDNSRRsetNotify notify;

  if (cache->memory_used + sizeof(*notify) > cache->max_memory)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Memory limit exceeded while allocating RRset notify"));
      return NULL;
    }
  notify = ssh_malloc(sizeof(*notify));
  if (notify == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating RRset notify"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("Adding RRset %@ notify of type %s (%d)",
                             ssh_dns_name_render, rrset->name,
                             ssh_dns_rrtype_string(rrset->type),
                             rrset->type));

  if (rrset->notify == NULL)
    {
      /* This is first notify, allocate one reference. */
      ssh_dns_rrset_cache_lock(cache, rrset);
    }
  notify->next = rrset->notify;
  rrset->notify = notify;
  notify->callback = callback;
  notify->context = context;
  notify->rrset = rrset;
  notify->cache = cache;
  ssh_operation_register_no_alloc(notify->operation_handle,
                                  ssh_dns_rrset_cache_notify_abort,
                                  notify);
  return notify->operation_handle;
}

/* Increment reference count for rrset. */
void
ssh_dns_rrset_cache_lock(SshDNSRRsetCache cache,
                         SshDNSRRset rrset)
{
  if (rrset->reference_count == 0)
    {
      SSH_DEBUG(SSH_D_LOWSTART,
                ("Locking RRset %@ of type %s (%d), from free list",
                 ssh_dns_name_render, rrset->name,
                 ssh_dns_rrtype_string(rrset->type),
                 rrset->type));
      /* Remove it from the free list. */
      ssh_adt_detach_object(cache->free_list, rrset);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Locking RRset %@ of type %s (%d)",
                                 ssh_dns_name_render, rrset->name,
                                 ssh_dns_rrtype_string(rrset->type),
                                 rrset->type));
    }
  rrset->reference_count++;
}

/* Decrement reference count for rrset. */
void
ssh_dns_rrset_cache_unlock(SshDNSRRsetCache cache,
                           SshDNSRRset rrset)
{
  rrset->reference_count--;
  if (rrset->reference_count == 0)
    {
      SSH_ASSERT(rrset->notify == NULL);
      /* Move item to the free_list, or if not valid, remove it completely. */
      if (rrset->valid)
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Unlocking RRset %@ of type %s (%d), to free list",
                     ssh_dns_name_render, rrset->name,
                     ssh_dns_rrtype_string(rrset->type),
                     rrset->type));
          ssh_adt_insert(cache->free_list, rrset);
          ssh_dns_rrset_verify_limits(cache, TRUE);
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWSTART,
                    ("Unlocking last reference to invalid RRset %@ of "
                     "type %s (%d)",
                     ssh_dns_name_render, rrset->name,
                     ssh_dns_rrtype_string(rrset->type),
                     rrset->type));
          ssh_dns_rrset_free(cache, rrset);
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWSTART, ("Unlocking RRset %@ of type %s (%d)",
                                 ssh_dns_name_render, rrset->name,
                                 ssh_dns_rrtype_string(rrset->type),
                                 rrset->type));
    }
}

/* Remove name with type from the cache. This is mainly used
   to clear out the IN_PROGRESS entries from the cache. */
void
ssh_dns_rrset_cache_remove(SshDNSRRsetCache rrset_cache,
                           const unsigned char *name,
                           SshDNSRRType type)
{
  SshDNSRRsetNotify next_notify, notify;
  SshDNSRRset rrset;

  SSH_DEBUG(SSH_D_MIDSTART, ("Removing RRset %@ of type %s (%d)",
                             ssh_dns_name_render, name,
                             ssh_dns_rrtype_string(type), type));

  /* Try to find the rrset. */
  rrset = ssh_dns_rrset_cache_get(rrset_cache, name, type);
  if (rrset == NULL)
    {
      /* No rrset found, so no need to do anything. */
      return;
    }
  /* Ok, there was an rrset in the cache. Check if it is already removed. */
  if (!rrset->valid)
    {
      /* Yes, no need to do anything. */
      return;
    }

  /* Take copy of the notifications from the old entry, they are called
     after data is in the cache. */
  notify = rrset->notify;
  rrset->notify = NULL;

  /* There was notifications, thus there must be the automatic reference in
     the entry, remove that. */
  if (notify != NULL)
    rrset->reference_count--;

  /* Free the old entry if it does not have any other references. */
  if (rrset->reference_count == 1)
    {
      /* This will free it any all cases. */
      ssh_dns_rrset_free(rrset_cache, rrset);
    }
  else
    {
      /* It does have external references, mark it as not
         valid, and remove it from the bag. */
      rrset->valid = FALSE;
      ssh_adt_detach_object(rrset_cache->rrset_bag, rrset);

      /* We cannot free it now, but it will be freed when the reference
         count goes to zero. In all cases we simply remove the reference we
         took earlier here. */
      ssh_dns_rrset_cache_unlock(rrset_cache, rrset);
    }

  /* Call the notifications, and indicate failure. */
  while (notify != NULL)
    {
      notify->callback(NULL, notify->context);
      next_notify = notify->next;
      ssh_operation_unregister(notify->operation_handle);
      ssh_free(notify);
      notify = next_notify;
    }
  return;
}

/* Allocate new rrset and put it to the cache. Return NULL
   in case of out of memory. The rdata must be uncompressed
   before inserted to the cache, but otherwise it is in
   plain dns wire format. If the item is already in the cache,
   then the entries are combined (i.e. if the entries are identical,
   then cached_time is updated, and ttl is copied). Note,
   more trusted entries overwrite the less trusted ones
   (i.e. *_DNSSEC overwrites everything without _DNSSEC,
   AUTHORATIVE overwrites NON_AUTHORATIVE, and everything
   overwrites IN_PROGRESS and FAILURE states. The entry
   returned will have one reference taken, so the caller
   must unlock it after it is no longer needed. */
SshDNSRRset
ssh_dns_rrset_cache_add(SshDNSRRsetCache rrset_cache,
                        const unsigned char *name,
                        SshDNSRRsetState state,
                        SshDNSRRType type,
                        SshUInt32 ttl,
                        SshUInt32 number_of_rrs,
                        size_t array_of_rdlengths[],
                        unsigned char **array_of_rdata,
                        SshDNSRRset parent)
{
  SshDNSRRsetNotify next_notify, notify;
  SshDNSRRset rrset;
  Boolean overwrite;
  SshTime t;

  /* Try to find the rrset. */
  rrset = ssh_dns_rrset_cache_get(rrset_cache, name, type);
  if (rrset == NULL)
    {
      SSH_DEBUG(SSH_D_MIDSTART,
                ("Adding new RRset %@ of type %s (%d) with state %s",
                 ssh_dns_name_render, name,
                 ssh_dns_rrtype_string(type),
                 type,
                 ssh_dns_rrsetstate_string(state)));

      /* No rrset found, verify limits, and allocate new rrset. */
      ssh_dns_rrset_verify_limits(rrset_cache, TRUE);
      return ssh_dns_rrset_allocate(rrset_cache, name, state, type,
                                    ttl, number_of_rrs, array_of_rdlengths,
                                    array_of_rdata, parent);
    }
  t = ssh_time();
  /* If it is going to be expire in next 60 seconds, overwrite the data. */
  if (SSH_DNS_RRSET_EXPIRED(rrset, t + 60))
    overwrite = TRUE;
  else
    overwrite = FALSE;

  /* If someone is starting new search, and putting this to IN_PROGRESS state,
     then we must overwrite the data. */
  if (state == SSH_DNS_RRSET_IN_PROGRESS)
    overwrite = TRUE;

  /* If we are overwriting with same state, then we can always
     overwrite. */
  if (state == rrset->state)
    overwrite = TRUE;

  /* Item already in the cache, first check whether we should overwrite the
     data. */
  switch (rrset->state)
    {
    case SSH_DNS_RRSET_IN_PROGRESS:
    case SSH_DNS_RRSET_FAILURE:
      /* Anything will overwrite the IN_PROGRESS and FAILURE modes. */
      overwrite = TRUE;
      break;
    case SSH_DNS_RRSET_NON_AUTHORATIVE:
      /* If we have any more authorative data, overwrite the entries. */
      if (state == SSH_DNS_RRSET_NODATA ||
          state == SSH_DNS_RRSET_NODATA_DNSSEC ||
          state == SSH_DNS_RRSET_AUTHORATIVE ||
          state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC)
        overwrite = TRUE;
      break;
    case SSH_DNS_RRSET_NODATA:
      /* If we have DNSSec data or authorative data, then we overwrite. */
      if (state == SSH_DNS_RRSET_NODATA_DNSSEC ||
          state == SSH_DNS_RRSET_AUTHORATIVE ||
          state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC)
        overwrite = TRUE;
      break;
    case SSH_DNS_RRSET_AUTHORATIVE:
      /* If we have DNSSec authenticated data we overwrite. We also overwrite
         if we have authorative NODATA. */
      if (state == SSH_DNS_RRSET_NODATA ||
          state == SSH_DNS_RRSET_NODATA_DNSSEC ||
          state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC)
        overwrite = TRUE;
      break;
    case SSH_DNS_RRSET_NODATA_DNSSEC:
      /* We will only overwrite DNSsec data with other DNSsec data. */
      if (state == SSH_DNS_RRSET_AUTHORATIVE_DNSSEC)
        overwrite = TRUE;
      break;
    case SSH_DNS_RRSET_AUTHORATIVE_DNSSEC:
      if (state == SSH_DNS_RRSET_NODATA_DNSSEC)
        overwrite = TRUE;
      break;
    }
  if (!overwrite)
    {
      /* We are not going to overwrite the data, as it is less trusted. We
         simply ignore the data, and return the old entry. */

      SSH_DEBUG(SSH_D_LOWOK,
                ("Tried to add new RRset %@ of type %s (%d) with state %s,"
                 "but the old was more authorative",
                 ssh_dns_name_render, name,
                 ssh_dns_rrtype_string(type),
                 type,
                 ssh_dns_rrsetstate_string(state)));
      return rrset;
    }
  SSH_DEBUG(SSH_D_MIDSTART,
                ("Overwriting entry RRset %@ of type %s (%d) with state %s",
                 ssh_dns_name_render, name,
                 ssh_dns_rrtype_string(type),
                 type,
                 ssh_dns_rrsetstate_string(state)));

  /* Take copy of the notifications from the old entry, they are called
     after data is in the cache. */
  notify = rrset->notify;
  rrset->notify = NULL;

  /* There was notifications, thus there must be the automatic reference in
     the entry, remove that. */
  if (notify != NULL)
    rrset->reference_count--;

  /* Check if the entries are identical (i.e. is it enough to combine the
     data). */
  if (rrset->number_of_rrs == number_of_rrs &&
      rrset->type == type)      /* If this was wildcard match then types might
                                   not be same. We always want to force
                                   copying in that case, as we need to reinsert
                                   the data to bag. */
    {
      int i, j;

      for(j = 0; j < number_of_rrs; j++)
        {
          for(i = 0; i < rrset->number_of_rrs; i++)
            {
              if (rrset->array_of_rdlengths[i] ==
                  array_of_rdlengths[j] &&
                  memcmp(rrset->array_of_rdata[i],
                         array_of_rdata[j], array_of_rdlengths[j]) == 0)
                {
                  /* Found, mark it so that we do not match this item again. */
                  rrset->array_of_rdlengths[i] |= 0x80000000;
                  break;
                }
            }
          if (i == rrset->number_of_rrs)
            {
              /* Not found, clear marks, and create new entry. */
              for(i = 0; i < rrset->number_of_rrs; i++)
                rrset->array_of_rdlengths[i] &= ~0x80000000;
              goto copy;
            }
        }
      /* Yes, all the items are identical, thus we do not need to allocate new
         copy. Clear the marks first. */
      for(i = 0; i < rrset->number_of_rrs; i++)
        rrset->array_of_rdlengths[i] &= ~0x80000000;

      /* Update the entry. */
      rrset->state = state;
      /* Allow ttl to be short for failure cases. */
      if (state == SSH_DNS_RRSET_FAILURE)
        rrset->ttl = ttl;
      else
        rrset->ttl = (ttl < rrset_cache->minimum_lifetime ?
                      rrset_cache->minimum_lifetime : ttl);
      if (rrset->ttl > rrset_cache->maximum_ttl)
        rrset->ttl = rrset_cache->maximum_ttl;
      rrset->cached_time = t;
      SSH_DEBUG(SSH_D_LOWOK, ("Overwriting old entry"));
    }
  else
    {
    copy:
      /* Ok. the old entry needs to be overwritten. */
      SSH_DEBUG(SSH_D_LOWOK, ("Copying entry, and marking old entry invalid"));

      /* Free the old entry if it does not have any other references. */
      if (rrset->reference_count == 1)
        {
          /* This will free it any all cases. */
          ssh_dns_rrset_free(rrset_cache, rrset);
        }
      else
        {
          /* It does have external references, mark it as overwritten (i.e. not
             valid), and remove it from the bag. */
          rrset->valid = FALSE;
          ssh_adt_detach_object(rrset_cache->rrset_bag, rrset);

          /* We cannot free it now, but it will be freed when the reference
             count goes to zero. In all cases we simply remove the reference we
             took earlier here. */
          ssh_dns_rrset_cache_unlock(rrset_cache, rrset);
        }

      /* Now we can allocate new rrset. */
      rrset = ssh_dns_rrset_allocate(rrset_cache, name, state, type,
                                     ttl, number_of_rrs, array_of_rdlengths,
                                     array_of_rdata, parent);
      /* Regardless whether it succeeded or failed, we simply call
         notifications and return the new rrset or NULL if allocation
         failed. */
    }
  /* Call the notifications. They will be called whenever the same rrset is
     inserted to the cache. */
  while (notify != NULL)
    {
      notify->callback(rrset, notify->context);
      next_notify = notify->next;
      ssh_operation_unregister(notify->operation_handle);
      ssh_free(notify);
      notify = next_notify;
    }
  return rrset;
}

/* Mapping between error codes and error strings. */
const SshKeywordStruct ssh_dns_rrsetstate_keywords[] = {
  { "Nodata", SSH_DNS_RRSET_NODATA },
  { "Nodata dnssec", SSH_DNS_RRSET_NODATA_DNSSEC },
  { "In progress", SSH_DNS_RRSET_IN_PROGRESS },
  { "Failure", SSH_DNS_RRSET_FAILURE },
  { "Non authorative", SSH_DNS_RRSET_NON_AUTHORATIVE },
  { "Authorative", SSH_DNS_RRSET_AUTHORATIVE },
  { "Authorative dnssec", SSH_DNS_RRSET_AUTHORATIVE_DNSSEC },
  { NULL, 0 }
};

/* Map state to string. */
const char *ssh_dns_rrsetstate_string(SshDNSRRsetState code)
{
  const char *str;

  str = ssh_find_keyword_name(ssh_dns_rrsetstate_keywords, code);
  if (str == NULL)
    str = "unknown";
  return str;
}

/* Enumerate the cache of valid host names. The return
   status is the handle of the item (or SSH_ADT_INVALID if
   last item), and the `rrset' is to the item itself (or
   NULL if last item). This function does not lock the
   entries in anyways, and during this there cannot be any
   calls to any of the dns library except rendering etc.
   */
SshADTHandle
ssh_dns_rrset_cache_enumerate_start(SshDNSRRsetCache rrset_cache,
                                    SshDNSRRset *rrset)
{
  SshADTHandle h;
  h = ssh_adt_enumerate_start(rrset_cache->rrset_bag);
  if (h == SSH_ADT_INVALID)
    {
      *rrset = NULL;
      return h;
    }
  *rrset = ssh_adt_get(rrset_cache->rrset_bag, h);
  return h;
}

SshADTHandle
ssh_dns_rrset_cache_enumerate_next(SshDNSRRsetCache rrset_cache,
                                   SshDNSRRset *rrset,
                                   SshADTHandle prev_handle)
{
  SshADTHandle h;

  h = ssh_adt_enumerate_next(rrset_cache->rrset_bag, prev_handle);
  if (h == SSH_ADT_INVALID)
    {
      *rrset = NULL;
      return h;
    }
  *rrset = ssh_adt_get(rrset_cache->rrset_bag, h);
  return h;
}
