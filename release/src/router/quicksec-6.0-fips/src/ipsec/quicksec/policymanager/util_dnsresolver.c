/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   DNS name resolution cache    for the use of  QuickSec   policy
   manager.  General  idea  is  to  store  mapping  from name  to
   address, and enable  application to  signal that some   (maybe
   all) of the names in the cache should refreshed.
   This module will   also keep track  of  the rules and  tunnels
   referencing   these names, so that  appropriate   rules can be
   changed during system reconfigure following the cache refresh.

   This module  knows what the rules and  tunnels  look like, and
   internally adjusts them.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "util_dnsresolver.h"

#define SSH_DEBUG_MODULE "SshPmDnsResolver"

#ifdef SSHDIST_IPSEC_DNSPOLICY

struct SshPmDnsReferenceRec
{
  union {
    SshPmRule rule;
    SshPmTunnel tunnel;
    void *generic;
  } u;

  SshPmDnsObjectClass name_type;
  SshPmDnsObject name;

  /* Doubly linked list, for fast reference removal. */
  SshPmDnsReference prev;
  SshPmDnsReference next;

  /* On externally inserted 'type none' refs kept by the cache */
  SshPmDnsReference internal_list;

  SshUInt16 refcnt;

  SshUInt32 flags;
};

/* Private flag values for bookkeeping */
#define SSH_IPM_DNS_REF_FLAG_SEEN 0x00010000
#define SSH_IPM_DNS_REF_FLAG_NEW  0x00020000

/* Maps dns name to ip address and objects using this particular address.
   Mapping is reference counted. */
struct SshPmDnsObjectRec
{
  SshUInt16 refcnt;

  /* DNS name and corresponding IP address, or undefined. */
  SshUInt16 name_len;
  char *name;

  /* Bag by canonicalized name */
  SshADTBagHeaderStruct bag_header;

  Boolean stale;
  SshTime last_modification;

  SshIpAddrStruct address;


  /* List of objects referencing this. The length of this list should
     be the same as refcnt. */
  SshPmDnsReference referers;

  /* This space contains piggypacked name */
};

static SshUInt32
pm_dns_cache_name_hash(const void *p, void *context)
{
  SshPmDnsObject o = (SshPmDnsObject)p;
  SshUInt32 h = 0;
  int i;

  for (i = 0; i < o->name_len; i++)
    {
      h += tolower(((unsigned char *) o->name)[i]);
      h += h << 10;
      h ^= h >> 6;
    }
  h += h << 3;
  h ^= h >> 11;
  h += h << 15;
  return h;
}

static int
pm_dns_cache_name_compare(const void *p1, const void *p2, void *context)
{
  SshPmDnsObject o1 = (SshPmDnsObject)p1;
  SshPmDnsObject o2 = (SshPmDnsObject)p2;
  int i;

  if (o1->name_len != o2->name_len)
    return o1->name_len - o2->name_len;

  for (i = 0; i < o1->name_len; i++)
    {
      if (tolower(((unsigned char *) o1->name)[i]) !=
          tolower(((unsigned char *) o2->name)[i]))
        return tolower(((unsigned char *) o1->name)[i]) !=
          tolower(((unsigned char *) o2->name)[i]);
    }
  return 0;
}

static void
pm_dns_cache_name_destroy(void *p, void *context)
{
#ifdef DEBUG_LIGHT
  SshPmDnsObject o = p;
#endif /* DEBUG_LIGHT */
  SSH_ASSERT(o->refcnt == 0);
  SSH_ASSERT(o->referers == NULL);

  ssh_free(p);
}

struct SshPmDnsCacheRec
{
  SshADTContainer by_name;
  SshPmDnsReference references;
};

SshPmDnsCache
ssh_pm_dns_cache_create(void)
{
  SshPmDnsCache cache;

  cache = ssh_calloc(1, sizeof(*cache));
  if (cache == NULL)
    return NULL;

  cache->by_name =
    ssh_adt_create_generic(SSH_ADT_BAG,
                           SSH_ADT_HASH, pm_dns_cache_name_hash,
                           SSH_ADT_COMPARE, pm_dns_cache_name_compare,
                           SSH_ADT_DESTROY, pm_dns_cache_name_destroy,
                           SSH_ADT_HEADER,
                           SSH_ADT_OFFSET_OF(SshPmDnsObjectStruct,
                                             bag_header),
                           SSH_ADT_ARGS_END);
  if (cache->by_name == NULL)
    {
      ssh_free(cache);
      return NULL;
    }
  cache->references = NULL;

  return cache;
}

void
ssh_pm_dns_cache_purge(SshPm pm, Boolean purge_old)
{
  if (pm->dnscache)
    {
      SshPmDnsReference ref, next;
      for (ref = pm->dnscache->references; ref; ref = next)
        {
          next = ref->internal_list;
          if (purge_old)
            {
              if (!(ref->flags & SSH_IPM_DNS_REF_FLAG_SEEN) &&
                  !(ref->flags & SSH_IPM_DNS_REF_FLAG_NEW))
                {
                  ssh_pm_dns_cache_remove(pm->dnscache, ref);
                  continue;
                }
            }
          else
            {
              if (!(ref->flags & SSH_IPM_DNS_REF_FLAG_NEW))
                {
                  ssh_pm_dns_cache_remove(pm->dnscache, ref);
                  continue;
                }
            }

          /* Clear _SEEN and _NEW flags */
          ref->flags &= ~(SSH_IPM_DNS_REF_FLAG_SEEN |
                          SSH_IPM_DNS_REF_FLAG_NEW);
        }
    }
}

void
ssh_pm_dns_cache_destroy(SshPmDnsCache cache)
{
  if (cache)
    {
      SshPmDnsReference ref, next;
      for (ref = cache->references; ref; ref = next)
        {
          next = ref->internal_list;
          ssh_pm_dns_cache_remove(cache, ref);
        }
      ssh_adt_destroy(cache->by_name);
      ssh_free(cache);
    }
}

static SshPmDnsObject
pm_dns_cache_find(SshPmDnsCache cache, const char *address)
{
  SshADTHandle handle;
  SshPmDnsObjectStruct probe;

  probe.name_len = strlen(address);
  probe.name = (char *)address;

  handle = ssh_adt_get_handle_to_equal(cache->by_name, &probe);
  if (handle != SSH_ADT_INVALID)
    return (SshPmDnsObject) ssh_adt_get(cache->by_name, handle);
  else
    return NULL;
}

SshPmDnsStatus
ssh_pm_dns_cache_status(SshPmDnsReference reference)
{
  if (reference)
    {
      if (reference->name->stale)
        return SSH_PM_DNS_STATUS_STALE;

      if (!SSH_IP_DEFINED(&reference->name->address))
        return SSH_PM_DNS_STATUS_ERROR;
    }
  return SSH_PM_DNS_STATUS_OK;
}

SshPmDnsReference
ssh_pm_dns_cache_insert(SshPmDnsCache cache,
                        const char *address,
                        SshPmDnsObjectClass name_type, void *object)
{
  SshPmDnsObject entry;
  SshPmDnsReference reference;

  reference = ssh_malloc(sizeof(*reference));
  if (reference == NULL)
    return NULL;

  reference->u.generic = object;
  reference->name_type = name_type;
  reference->name = NULL;
  reference->prev = NULL;
  reference->next = NULL;
  reference->internal_list = NULL;
  reference->refcnt = 1;
  reference->flags = 0;

  /* Maybe attach to existing */
  entry = pm_dns_cache_find(cache, address);
  if (entry == NULL)
    {
      size_t len;

      /* No such luck; create new entry and piggypack name into end of
         the structure to live with single malloc/free */
      len = strlen(address);
      entry = ssh_calloc(1, sizeof(*entry) + len + 1);
      if (entry == NULL)
        {
          ssh_free(reference);
          return NULL;
        }

      entry->refcnt = 0;
      entry->name = (char *)entry + sizeof(*entry);
      entry->name_len = len;
      strcpy(entry->name, address);

      SSH_IP_UNDEFINE(&entry->address);
      entry->last_modification = ssh_time();
      entry->referers = NULL;
      entry->stale = FALSE;

      ssh_adt_insert(cache->by_name, entry);
    }


  /* Attach reference to entry; make it first on the references list. */
  reference->name = entry;
  reference->prev = NULL;
  reference->next = entry->referers;
  if (reference->next != NULL)
    reference->next->prev = reference;

  entry->refcnt += 1;
  entry->referers = reference;

  return reference;
}

SshPmDnsReference
ssh_pm_dns_cache_copy(SshPmDnsCache cache, SshPmDnsReference reference,
                      void *object)
{
  SshPmDnsReference copy;

  copy = ssh_malloc(sizeof(*copy));
  if (copy == NULL)
    return NULL;

  copy->u.generic = object;
  copy->name_type = reference->name_type;
  copy->name = reference->name;
  copy->prev = NULL;
  copy->next = copy->name->referers;
  if (copy->next)
    copy->next->prev = copy;
  copy->name->referers = copy;
  copy->name->refcnt++;
  copy->internal_list = NULL;
  copy->refcnt = 1;
  copy->flags = 0;

  return copy;
}

Boolean
ssh_pm_dns_cache_compare(SshPmDnsReference r1, SshPmDnsReference r2)
{
  return strcasecmp(r1->name->name, r2->name->name) == 0;
}

void
ssh_pm_dns_cache_remove(SshPmDnsCache cache,
                        SshPmDnsReference reference)
{
  SshPmDnsObject entry;

  if (--reference->refcnt > 0)
    return;

  entry = reference->name;

  if (reference->prev)
    {
      reference->prev->next = reference->next;
      if (reference->next)
        reference->next->prev = reference->prev;
    }
  else
    {
      SSH_ASSERT(reference == entry->referers);
      entry->referers = reference->next;
      if (entry->referers)
        entry->referers->prev = NULL;
    }

  ssh_free(reference);

  entry->refcnt -= 1;
  if (entry->refcnt == 0)
    {
      ssh_adt_detach(cache->by_name,
                     ssh_adt_get_handle_to(cache->by_name, entry));
      ssh_free(entry);
    }
}

void ssh_pm_dns_cache_print(SshPm pm)
{
  SshADTHandle h;

  for (h = ssh_adt_enumerate_start(pm->dnscache->by_name);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(pm->dnscache->by_name, h))
    {
#ifdef DEBUG_LIGHT
      SshPmDnsObject entry = ssh_adt_get(pm->dnscache->by_name, h);

      SSH_DEBUG(SSH_D_ERROR,
                ("Obj %p: name %s/%d -> %@ refcnt %d %s %ld",
                 entry,
                 entry->name, entry->name_len,
                 ssh_ipaddr_render, &entry->address,
                 entry->refcnt,
                 entry->stale ? " stale" : "",
                 (long) entry->last_modification));
#endif /* DEBUG_LIGHT */
    }
}

SSH_FSM_STEP(pm_st_dns_qryupd_qry_start);
SSH_FSM_STEP(pm_st_dns_qryupd_upd_start);
SSH_FSM_STEP(pm_st_dns_qryupd_done);

/* Perform DNS resolution for name. End state will update information. */
SSH_FSM_STEP(pm_st_dns_query_start);
SSH_FSM_STEP(pm_st_dns_query_end);

typedef void (*SshPmDnsQueryCB)(SshUInt16 naddrs, SshIpAddr addrs,
                                void *context);


typedef struct SshPmDnsIteratorRec
{
  SshFSMThreadStruct thread[1];
  SshOperationHandleStruct operation;
  SshOperationHandle sub_operation;
  SshUInt16 success : 1;
  SshUInt16 aborted : 1;

  /* True if iterating over one entry given without DNS lookup. In
     this case the addresses for the entry are stored at naddress, and
     addresses respectively. */
  Boolean one_entry;
  SshUInt32 naddress;
  SshIpAddr addresses;

  SshADTHandle handle;
  SshPm pm;

  SshPmStatusCB callback;
  void *callback_context;

  /* Rules and tunnels changed during name indication */
  SshPmRule rules;
  SshPmTunnel tunnels;

} *SshPmDnsIterator, SshPmDnsIteratorStruct;

typedef struct SshPmDnsUpdateRec
{
  SshPm pm;

  /* Self */
  SshOperationHandleStruct operation;
  SshFSMThreadStruct thread[1];

  Boolean aborted;

  /* Entry being update */
  SshPmDnsObject entry;

  /* DNS query results. */
  SshUInt32 naddrs;
  SshIpAddr addrs;

  /* Entry's referer currently being updated */
  SshPmDnsReference referer;

  /* Result indication */
  SshPmStatusCB callback;
  void *callback_context;

  /* If non null, stores iterator for the update. */
  SshPmDnsIterator iterate;

  Boolean changed;

} *SshPmDnsUpdate, SshPmDnsUpdateStruct;

struct SshPmDnsQueryRec
{
  SshPm pm;

  /* Linked on the freelist */
  SshPmDnsQuery next;

  /* Thread running request */
  SshFSMThreadStruct thread[1];

  /* Entry this thread is updating. */
  SshPmDnsObject entry;

  /* Self */
  SshOperationHandle sub_operation;

  /* Sub operation, from dns library */
  SshOperationHandleStruct operation;

  /* Status flags */
  SshUInt16 pending : 1;
  SshUInt16 success : 1;

  /* If true, continue by performing update. */
  SshUInt16 update : 1;

  SshUInt16 aborted : 1;

  /* Array of resulting IP addresses. */
  SshUInt16 naddrs;
  SshIpAddrStruct *addrs;

  SshPmDnsQueryCB callback;
  void *callback_context;

  SshPmStatusCB status_callback;
  void *status_callback_context;

  /* If non null, stores iterator for the update. */
  SshPmDnsIterator iterate;
};

SshPmDnsQuery ssh_pm_dns_query_pool_allocate(SshUInt16 nentries)
{
  SshPmDnsQuery qry = NULL, head = NULL;

  while (nentries--)
    {
      qry = ssh_calloc(1, sizeof(*qry));
      if (qry != NULL)
        {
          qry->next = head;
          head = qry;
        }
    }

  return qry;
}

void ssh_pm_dns_query_pool_free(SshPmDnsQuery query)
{
  SshPmDnsQuery next;
  while (query)
    {
      next = query->next;

      if (query->addrs)
        ssh_free(query->addrs);
      ssh_free(query);

      query = next;
    }
}

static void
pm_dns_query_done_callback(SshTcpError error,
                           const unsigned char *result,
                           void *context)
{
  unsigned char tmp[512];
  SshPmDnsQuery query = context;
  int n;
  unsigned const char *comma, *start;

  switch (error)
    {
    case SSH_TCP_OK:
      if (result)
        {
          query->success = 0x1;
          /* count number of results */
          for (n = 1, comma = ssh_ustrchr(result, ',');
               comma;
               comma = ssh_ustrchr(comma, ','), n++)
            comma++;

          query->addrs = ssh_calloc(n, sizeof(query->addrs[0]));
          if (query->addrs != NULL)
            {
              query->naddrs = n;
              /* for each result, do */
              for (n = 0,
                     start = result,
                     comma = ssh_ustrchr(result, ',');
                   comma;
                   start = ++comma, comma = ssh_ustrchr(comma, ','))
                {
                  ssh_ustrncpy(tmp, start, comma - start);
                  tmp[comma - start] = '\0';
                  if (ssh_ipaddr_parse(&query->addrs[n], tmp))
                    n += 1;
                  else
                    query->naddrs -= 1;
                }
              ssh_ustrncpy(tmp, start, ssh_ustrlen(start));
              tmp[ssh_ustrlen(start)] = '\0';
              if (ssh_ipaddr_parse(&query->addrs[n], tmp) == FALSE)
                query->naddrs -= 1;
            }
        }
      else
        query->success = 0x0;

      break;

    case SSH_TCP_NO_ADDRESS:
      query->success = 0x1;
      query->naddrs = 0;
      query->addrs = NULL;
      break;

    default:
      query->success = 0x0;
      query->naddrs = 0;
      query->addrs = NULL;
      break;
    }

  query->sub_operation = NULL;
  query->pending = 0x0;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(query->thread);
}

SSH_FSM_STEP(pm_st_dns_query_start)
{
  SshPmDnsQuery query = thread_context;

  SSH_FSM_SET_NEXT(pm_st_dns_query_end);

  if (ssh_pm_get_status(query->pm) == SSH_PM_STATUS_DESTROYED)
    {
      query->success = FALSE;
      return SSH_FSM_CONTINUE;
    }

  SSH_FSM_ASYNC_CALL({
    query->success = 0x0;
    query->pending = 0x1;
    query->sub_operation =
      ssh_tcp_get_host_addrs_by_name(query->entry->name,
                                     pm_dns_query_done_callback,
                                     query);
  });
}

SSH_FSM_STEP(pm_st_dns_query_end)
{
  SshPmDnsQuery query = thread_context;

  if (query->success)
    {
      query->entry->stale = FALSE;
      if (query->naddrs == 0)
        SSH_IP_UNDEFINE(&query->entry->address);
      query->entry->last_modification = ssh_time();
    }
  else
    {
      query->entry->stale = TRUE;
    }

  if (query->update)
    {
      SSH_FSM_SET_NEXT(pm_st_dns_qryupd_upd_start);
      return SSH_FSM_CONTINUE;
    }
  else
    {
      if (query->callback)
        (*query->callback)(query->naddrs,
                           query->addrs,
                           query->callback_context);

      return SSH_FSM_FINISH;
    }

}

static void pm_dns_query_aborted(void *context)
{
  SshPmDnsQuery query = context;

  query->aborted = 1;
  if (query->sub_operation)
    {
      SSH_FSM_CONTINUE_AFTER_CALLBACK(query->thread);
      ssh_operation_abort(query->sub_operation);
      query->sub_operation = NULL;
    }
  query->status_callback = NULL_FNPTR;
  query->status_callback_context = NULL;
  query->callback = NULL_FNPTR;
  query->callback_context = NULL;
}

static void
pm_dns_query_thread_destructor(SshFSM fsm, void *context)
{
  SshPmDnsQuery query = context;
  SshPm pm = query->pm;

  ssh_free(query->addrs);
  if (!query->aborted)
    ssh_operation_unregister(&query->operation);

  /* Clear and putback */
  memset(query, 0, sizeof(*query));
  query->next = pm->dns_query_freelist;
  pm->dns_query_freelist = query;

}

/* Resolve single entry from DNS */
SshOperationHandle
pm_dns_query_start(SshPm pm,
                   SshPmDnsObject entry,
                   SshPmDnsQueryCB callback, void *callback_context)
{
  SshPmDnsQuery query;

  if ((query = pm->dns_query_freelist) != NULL)
    {
      query->pm = pm;
      query->entry = entry;

      query->pending = 0x1;
      query->success = 0x0;
      query->update = 0x1;
      query->sub_operation = NULL;
      query->aborted = 0;

      query->callback = callback;
      query->callback_context = callback_context;

      pm->dns_query_freelist = query->next;

      ssh_operation_register_no_alloc(&query->operation,
                                      pm_dns_query_aborted,
                                      query);
      ssh_fsm_thread_init(&pm->fsm,
                          query->thread, pm_st_dns_query_start,
                          NULL_FNPTR, pm_dns_query_thread_destructor,
                          query);
      ssh_fsm_set_thread_name(query->thread, "DNS query");
      return &query->operation;
    }
  else
    return NULL;
}

/*
  when name has been resolved:

  1. clone the rule referenced unless already cloned in this batch
  2. change the value in the clone, add clone.
  3. delete the template

  when commit, clean clone information.
*/

SSH_FSM_STEP(pm_st_dns_update_start);
SSH_FSM_STEP(pm_st_dns_update_next);
SSH_FSM_STEP(pm_st_dns_update_done);

static void pm_dns_update_get_route_done(SshPm pm,
                                         SshUInt32 flags,
                                         SshUInt32 ifnum,
                                         const SshIpAddr next_hop,
                                         size_t mtu, void *context)
{
  SshPmDnsUpdate update = context;
  SshInterceptorInterface *iface;

  iface = ssh_pm_find_interface_by_ifnum(pm, ifnum);
  if (iface != NULL)
    ssh_pm_rule_set_ifname(update->referer->u.rule, iface->name);

  update->referer = update->referer->next;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(update->thread);
}

SSH_FSM_STEP(pm_st_dns_update_start)
{
  SshPmDnsUpdate update = thread_context;

  SSH_FSM_SET_NEXT(pm_st_dns_update_next);

  update->referer = update->entry->referers;
  return SSH_FSM_CONTINUE;
}

/* Walk all objects (tunnels or rules) that reference to the name on
   currently processed entry. */
SSH_FSM_STEP(pm_st_dns_update_next)
{
  SshPmDnsUpdate update = thread_context;
  SshInterceptorRouteKeyStruct key;
  SshPmDnsReference referer;
  unsigned char peername[SSH_IP_ADDR_STRING_SIZE];
  SshPmRule rule;
  SshPmTunnel tunnel;
  int i;

  referer = update->referer;

  if (referer && (ssh_pm_get_status(update->pm) != SSH_PM_STATUS_DESTROYED))
    SSH_FSM_SET_NEXT(pm_st_dns_update_next);
  else
    {
      SSH_FSM_SET_NEXT(pm_st_dns_update_done);
      return SSH_FSM_CONTINUE;
    }

  if (!update->changed)
    {
      /* If the address behind name has not changed, check if this
         referer has the address defined. If so, we can optimize this
        assignment away. */
      if (referer->name_type == SSH_PM_DNS_OC_R_INTERFACE)
        if (referer->u.rule->side_from.ifname)
          goto next;
      if (referer->name_type == SSH_PM_DNS_OC_R_LOCAL)
        if (referer->u.rule->side_from.ts)
          goto next;
      if (referer->name_type == SSH_PM_DNS_OC_R_REMOTE)
        if (referer->u.rule->side_to.ts)
          goto next;
      if (referer->name_type == SSH_PM_DNS_OC_T_LOCAL)
        {
          /* If the local IP address has been updated to the tunnel
             and the DNS mapping has not changed, then continue without
             changing tunnel local dns addresses. */
          if (ssh_pm_tunnel_num_local_dns_addresses(referer->u.tunnel,
                                                    referer))
            goto next;
        }
      if (referer->name_type == SSH_PM_DNS_OC_T_PEER)
        {
          /* If all peer IP addresses have been updated to the tunnel
             and the DNS mapping has not changed, then continue without
             changing tunnel peers. */
          if (ssh_pm_tunnel_num_dns_peer_ips(referer->u.tunnel, referer)
              == update->naddrs)
            goto next;
        }
    }

  /* We need to remove and re-insert the rule object in order to get
     it properly committed. For rules this is easy, but for tunnels we
     need more magic to figure out the rules this tunnel is used
     at. */
  if (referer->name_type == SSH_PM_DNS_OC_R_INTERFACE ||
      referer->name_type == SSH_PM_DNS_OC_R_LOCAL ||
      referer->name_type == SSH_PM_DNS_OC_R_REMOTE)
    {
      if (!(referer->u.rule->flags & SSH_PM_RULE_I_CLONE)
          && !(referer->u.rule->flags & SSH_PM_RULE_I_DELETED))
        {
          rule = ssh_pm_rule_clone(update->pm, referer->u.rule);
          if (rule->side_to.dns_addr_sel_ref)
            {
              rule->side_to.dns_addr_sel_ref->u.rule = rule;
              rule->side_to.dns_addr_sel_ref->refcnt++;
            }
          if (rule->side_from.dns_addr_sel_ref)
            {
              rule->side_from.dns_addr_sel_ref->u.rule = rule;
              rule->side_from.dns_addr_sel_ref->refcnt++;
            }
          if (rule->side_to.dns_ifname_sel_ref)
            {
              rule->side_to.dns_ifname_sel_ref->u.rule = rule;
              rule->side_to.dns_ifname_sel_ref->refcnt++;
            }
          if (rule->side_from.dns_ifname_sel_ref)
            {
              rule->side_from.dns_ifname_sel_ref->u.rule = rule;
              rule->side_from.dns_ifname_sel_ref->refcnt++;
            }
          ssh_pm_rule_delete(update->pm, referer->u.rule->rule_id);
          referer->u.rule = rule;
          rule->nextp = update->iterate->rules;
          update->iterate->rules = rule;
        }
    }

  if (referer->name_type == SSH_PM_DNS_OC_T_PEER ||
      referer->name_type == SSH_PM_DNS_OC_T_LOCAL)
    {
      /* Store changed tunnel unless already stored */

      for (tunnel = update->iterate->tunnels; tunnel; tunnel = tunnel->next)
        if (referer->u.tunnel == tunnel)
          break;

      if (!tunnel)
        {
          /* not found, insert */
          tunnel = referer->u.tunnel;
          tunnel->next = update->iterate->tunnels;
          update->iterate->tunnels = tunnel;
        }
    }

  switch (referer->name_type)
    {
    case SSH_PM_DNS_OC_R_INTERFACE:
      /* Reference to interface by destination, Asynchronous. Route
         packet to get interface number. Continue from this function
         when done. Use global VRI since all DNS traffic should go
         through there. */
      ssh_pm_create_route_key(update->pm, &key,
                              NULL, &update->entry->address,
                              0, 0, 0, SSH_INVALID_IFNUM,
                              SSH_INTERCEPTOR_VRI_ID_GLOBAL);

      SSH_FSM_SET_NEXT(pm_st_dns_update_next);
      SSH_FSM_ASYNC_CALL({
        ssh_pme_route(update->pm->engine,
                      SSH_PME_ROUTE_F_SYSTEM,
                      &key,
                      pm_dns_update_get_route_done, update);
      });
      break;

    case SSH_PM_DNS_OC_R_LOCAL:
      ssh_ipaddr_print(&update->entry->address, peername, sizeof(peername));
      ssh_pm_rule_set_ip(referer->u.rule, SSH_PM_FROM, peername, peername);
      break;

    case SSH_PM_DNS_OC_R_REMOTE:
      ssh_ipaddr_print(&update->entry->address, peername, sizeof(peername));
      ssh_pm_rule_set_ip(referer->u.rule, SSH_PM_TO, peername, peername);
      break;

    case SSH_PM_DNS_OC_T_PEER:
      ssh_pm_tunnel_clear_dns_peers(referer->u.tunnel, referer);
      for (i = 0; i < update->naddrs; i++)
        ssh_pm_tunnel_add_dns_peer_ip(referer->u.tunnel, &update->addrs[i],
                                      referer);
      break;

    case SSH_PM_DNS_OC_T_LOCAL:
      ssh_pm_tunnel_update_local_dns_address(referer->u.tunnel,
                                             &update->entry->address,
                                             referer);
      break;

    case SSH_PM_DNS_OC_NONE:
      break;
    }

 next:

  /* Iterate over referers */
  update->referer = update->referer->next;
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_dns_update_done)
{
  SshPmDnsUpdate update = thread_context;

  if (update->callback)
    (*update->callback)(update->pm, TRUE, update->callback_context);

  return SSH_FSM_FINISH;
}

static void pm_dns_update_abort(void *context)
{
  SshPmDnsUpdate update = context;

  update->aborted = 1;
  update->callback = NULL_FNPTR;
  update->callback_context = NULL;
}

static void pm_dns_update_thread_destructor(SshFSM fsm, void *context)
{
  SshPmDnsUpdate update = context;

  if (!update->aborted)
    ssh_operation_unregister(&update->operation);
  ssh_free(update->addrs);
  ssh_free(update);
}

/* Perform DNS query result update for the entry. This uses the
   information on the entry to determine, what kind of operations must
   be done to satisfy needs of all references to this name. Operations
   are serialized. */
static SshOperationHandle
pm_dns_query_update_result(SshPm pm,
                           SshPmDnsIterator iterate,
                           SshPmDnsObject entry,
                           const unsigned char *dns,
                           SshUInt32 naddress, const SshIpAddr addresses,
                           SshPmStatusCB callback, void *callback_context)
{
  int i;
  SshPmDnsUpdate update;
  Boolean changed = TRUE;

  for (i = 0; i < naddress; i++)
    {
      if (SSH_IP_EQUAL(&addresses[i], &entry->address))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Address for the entry '%s' has not changed.", dns));
          changed = FALSE;
        }
    }
  entry->address = addresses[0];
  entry->last_modification = ssh_time();

  if ((update = ssh_calloc(1, sizeof(*update))) == NULL)
    {
    failed:
      ssh_free(update);
      (*callback)(pm, FALSE, callback_context);
      return NULL;
    }

  update->pm = pm;
  update->entry = entry;
  update->naddrs = naddress;
  update->iterate = iterate;
  update->changed = changed;

  if ((update->addrs =
       ssh_memdup(addresses, naddress * sizeof(*addresses))) == NULL)
    goto failed;

  update->callback = callback;
  update->callback_context = callback_context;

  ssh_operation_register_no_alloc(&update->operation,
                                  pm_dns_update_abort, update);

  ssh_fsm_thread_init(&pm->fsm,
                      update->thread, pm_st_dns_update_start,
                      NULL_FNPTR, pm_dns_update_thread_destructor,
                      update);
  ssh_fsm_set_thread_name(update->thread, "DNS update");
  return &update->operation;
}


SSH_FSM_STEP(pm_st_dns_qryupd_qry_start)
{
  /* We are already set up for DNS query state machine, and will
     return from that to update starting. */
  SSH_FSM_SET_NEXT(pm_st_dns_query_start);
  return SSH_FSM_CONTINUE;
}

static void
pm_dns_update_for_qryupd_done(SshPm pm, Boolean success, void *context)
{
  SshPmDnsQuery qryupd = context;

  qryupd->sub_operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(qryupd->thread);
}

SSH_FSM_STEP(pm_st_dns_qryupd_upd_start)
{
  SshPmDnsQuery qryupd = thread_context;

  /* DNS done, now check if we need to update (based on if query was
     successful. */

  SSH_FSM_SET_NEXT(pm_st_dns_qryupd_done);

  if (ssh_pm_get_status(qryupd->pm) == SSH_PM_STATUS_DESTROYED)
    return SSH_FSM_CONTINUE;

  if (qryupd->success && qryupd->naddrs)
    {
      SSH_DEBUG(SSH_D_MIDOK,
                ("starting update for name %s -> %@",
                 qryupd->entry->name,
                 ssh_ipaddr_render, &qryupd->addrs[0]));
      SSH_FSM_ASYNC_CALL({
        qryupd->sub_operation =
          pm_dns_query_update_result(qryupd->pm,
                                     qryupd->iterate,
                                     qryupd->entry, qryupd->entry->name,
                                     qryupd->naddrs, qryupd->addrs,
                                     pm_dns_update_for_qryupd_done, qryupd);
      });
    }
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_dns_qryupd_done)
{
  SshPmDnsQuery qryupd = thread_context;

  if (qryupd->status_callback)
    (*qryupd->status_callback)(qryupd->pm,
                               qryupd->success,
                               qryupd->status_callback_context);
  return SSH_FSM_FINISH;
}

static SshOperationHandle
pm_dns_query_and_update(SshPm pm,
                        SshPmDnsIterator iterate,
                        SshPmDnsObject entry,
                        const unsigned char *dns,
                        SshPmStatusCB callback, void *callback_context)
{
  SshPmDnsQuery qryupd;

  if ((qryupd = pm->dns_query_freelist) != NULL)
    {
      pm->dns_query_freelist = qryupd->next;

      qryupd->pm = pm;
      qryupd->entry = entry;

      qryupd->pending = 0x1;
      qryupd->success = 0x0;
      qryupd->update = 0x1;
      qryupd->aborted = 0;
      qryupd->sub_operation = NULL;

      qryupd->status_callback = callback;
      qryupd->status_callback_context = callback_context;
      qryupd->iterate = iterate;

      ssh_operation_register_no_alloc(&qryupd->operation,
                                      pm_dns_query_aborted,
                                      qryupd);
      ssh_fsm_thread_init(&pm->fsm,
                          qryupd->thread, pm_st_dns_query_start,
                          NULL_FNPTR, pm_dns_query_thread_destructor,
                          qryupd);
      ssh_fsm_set_thread_name(qryupd->thread, "DNS Query and Update");
      return &qryupd->operation;
    }
  else
    return NULL;
}


/* Iteration */
SSH_FSM_STEP(pm_st_dns_iterate_next);
SSH_FSM_STEP(pm_st_dns_iterate_done);


static void pm_dns_iterate_entry_done(SshPm pm, Boolean success, void *context)
{
  SshPmDnsIterator iterate = context;

  if (success)
    {
      iterate->success = 1;
    }
  else
    {
      iterate->success = 0;
    }

  iterate->sub_operation = NULL;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(iterate->thread);
}

SSH_FSM_STEP(pm_st_dns_iterate_next)
{
  SshPmDnsIterator iterate = thread_context;

  if (ssh_pm_get_status(iterate->pm) == SSH_PM_STATUS_DESTROYED)
    {
      SSH_FSM_SET_NEXT(pm_st_dns_iterate_done);
      return SSH_FSM_CONTINUE;
    }

  if (iterate->handle != SSH_ADT_INVALID)
    {
      SshPmDnsObject entry;
      SshADTHandle handle;

      if (iterate->one_entry)
        SSH_FSM_SET_NEXT(pm_st_dns_iterate_done);
      else
        SSH_FSM_SET_NEXT(pm_st_dns_iterate_next);

      handle = iterate->handle;
      entry = ssh_adt_get(iterate->pm->dnscache->by_name, handle);

      SSH_DEBUG(SSH_D_HIGHOK, ("Iterating entry; name=%s", entry->name));

      if (!iterate->one_entry && handle != SSH_ADT_INVALID)
        iterate->handle =
          ssh_adt_enumerate_next(iterate->pm->dnscache->by_name, handle);
      else
        iterate->handle = SSH_ADT_INVALID;

      if (entry)
        {
          if (iterate->one_entry && iterate->naddress > 0)
            SSH_FSM_ASYNC_CALL({
              iterate->sub_operation =
                pm_dns_query_update_result(iterate->pm,
                                           iterate,
                                           entry, entry->name,
                                           iterate->naddress,
                                           iterate->addresses,
                                           pm_dns_iterate_entry_done, iterate);
            });
          else
            SSH_FSM_ASYNC_CALL({
              iterate->sub_operation =
                pm_dns_query_and_update(iterate->pm,
                                        iterate,
                                        entry, entry->name,
                                        pm_dns_iterate_entry_done, iterate);
            });
        }
    }

  SSH_FSM_SET_NEXT(pm_st_dns_iterate_done);
  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_st_dns_iterate_done)
{
  SshPmDnsIterator iterate = thread_context;
  SshPm pm = iterate->pm;

  SSH_DEBUG(SSH_D_HIGHOK, ("Iteration done"));

  if (ssh_pm_get_status(pm) != SSH_PM_STATUS_DESTROYED)
    {
      SshPmRule rule, next;
      SshPmRule new_rule;
      SshADTHandle handle_rule, handle_next;
      SshPmTunnel tunnel;

      for (handle_rule = ssh_adt_enumerate_start(pm->rule_by_id);
           handle_rule != SSH_ADT_INVALID;
           handle_rule = handle_next)
        {
          handle_next = ssh_adt_enumerate_next(pm->rule_by_id, handle_rule);
          rule = ssh_adt_get(pm->rule_by_id, handle_rule);

          for (tunnel = iterate->tunnels; tunnel; tunnel = tunnel->next)
            {
              if (!(rule->flags & SSH_PM_RULE_I_CLONE) &&
                  !(rule->flags & SSH_PM_RULE_I_DELETED) &&
                  (rule->side_to.tunnel == tunnel ||
                   rule->side_from.tunnel == tunnel))
                {
                  /* Rule has not been cloned (e.g. its attributes
                     have not changed, but the tunnel it is refering
                     has changed. We need to reconfigure it now. */

                  SSH_DEBUG(SSH_D_LOWOK,
                            ("Rule %d; tunnel changed. Readding",
                             (int) rule->rule_id));

                  /* Find a previous clone, if available. */
                  for (new_rule = iterate->rules; new_rule; new_rule = next)
                    {
                      if (new_rule->rule_id == rule->rule_id)
                        break;
                      next = new_rule->nextp;
                    }

                  /* This rule already handled. */
                  if (new_rule)
                    {
                      SSH_DEBUG(SSH_D_LOWOK,
                                ("Rule %d; tunnel already handled",
                                 (int) rule->rule_id));
                      continue;
                    }

                  /* No clone made yet, make a new one. */
                  new_rule = ssh_pm_rule_clone(pm, rule);
                  if (new_rule->side_to.dns_addr_sel_ref)
                    {
                      new_rule->side_to.dns_addr_sel_ref->u.rule = new_rule;
                      new_rule->side_to.dns_addr_sel_ref->refcnt++;
                    }
                  if (new_rule->side_from.dns_addr_sel_ref)
                    {
                      new_rule->side_from.dns_addr_sel_ref->u.rule = new_rule;
                      new_rule->side_from.dns_addr_sel_ref->refcnt++;
                    }
                  if (new_rule->side_to.dns_ifname_sel_ref)
                    {
                      new_rule->side_to.dns_ifname_sel_ref->u.rule = new_rule;
                      new_rule->side_to.dns_ifname_sel_ref->refcnt++;
                    }
                  if (new_rule->side_from.dns_ifname_sel_ref)
                    {
                      new_rule->side_from.dns_ifname_sel_ref->u.rule =
                        new_rule;
                      new_rule->side_from.dns_ifname_sel_ref->refcnt++;
                    }
                  ssh_pm_rule_delete(pm, rule->rule_id);

                  new_rule->nextp = iterate->rules;
                  iterate->rules = new_rule;
                }
            }
        }

      for (rule = iterate->rules; rule; rule = next)
        {
          next = rule->nextp;
          if (ssh_pm_rule_add(pm, rule) == SSH_IPSEC_INVALID_INDEX)
            {
              rule->flags &= ~(SSH_PM_RULE_I_CLONE);
              ssh_pm_rule_free(pm, rule);
            }
        }
    }

  if (iterate->callback)
    (*iterate->callback)(pm,
                         (iterate->success == 1 ? TRUE : FALSE),
                         iterate->callback_context);

  return SSH_FSM_FINISH;
}

static void pm_dns_iterate_thread_destructor(SshFSM fsm, void *context)
{
  SshPmDnsIterator iterate = (SshPmDnsIterator) context;

  if (!iterate->aborted)
    ssh_operation_unregister(&iterate->operation);
  if (iterate->addresses)
    ssh_free(iterate->addresses);
  ssh_free(iterate);
}

static void pm_dns_iterate_aborted(void *context)
{
  SshPmDnsIterator iterate = context;

  iterate->aborted = 1;
  if (iterate->sub_operation)
    {
      ssh_fsm_set_next(iterate->thread, pm_st_dns_iterate_done);
      SSH_FSM_CONTINUE_AFTER_CALLBACK(iterate->thread);
      ssh_operation_abort(iterate->sub_operation);
      iterate->sub_operation = NULL;
    }
  iterate->callback = NULL_FNPTR;
  iterate->callback_context = NULL;
}

static SshPmDnsIterator
pm_dns_iterator_alloc(SshPm pm,
                      SshFSMStepCB start,
                      SshPmStatusCB callback, void *context)
{
  SshPmDnsIterator iterate;

  if ((iterate = ssh_calloc(1, sizeof(*iterate))) == NULL)
    {
      (*callback)(pm, FALSE, context);
      return NULL;
    }

  iterate->callback = callback;
  iterate->callback_context = context;
  iterate->pm = pm;
  iterate->success = 1;
  iterate->aborted = 0;
  iterate->handle = NULL;
  ssh_operation_register_no_alloc(&iterate->operation,
                                  pm_dns_iterate_aborted,
                                  iterate);
  if (start)
    {
      ssh_fsm_thread_init(&pm->fsm,
                          iterate->thread, start,
                          NULL_FNPTR, pm_dns_iterate_thread_destructor,
                          iterate);
    }

  return iterate;
}

SshOperationHandle
pm_dns_iterate(SshPm pm, SshPmStatusCB callback, void *callback_context)
{
  SshPmDnsIterator iterate;


  if ((iterate = pm_dns_iterator_alloc(pm,
                                       pm_st_dns_iterate_next,
                                       callback, callback_context))
      == NULL)
    {
      (*callback)(pm, FALSE, callback_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Iterator over all entries"));

  iterate->handle = ssh_adt_enumerate_start(pm->dnscache->by_name);
  iterate->one_entry = FALSE;
  return &iterate->operation;
}

SshOperationHandle
pm_dns_iterate_one(SshPm pm,
                   SshPmDnsObject entry,
                   const unsigned char *dns,
                   SshUInt32 naddress, const SshIpAddr addresses,
                   SshPmStatusCB callback, void *callback_context)
{
  SshPmDnsIterator iterate;

  if ((iterate = pm_dns_iterator_alloc(pm,
                                       pm_st_dns_iterate_next,
                                       callback, callback_context))
      == NULL)
    {
      (*callback)(pm, FALSE, callback_context);
      return NULL;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("Iterator over single entry"));

  iterate->handle = ssh_adt_get_handle_to(pm->dnscache->by_name, entry);
  iterate->one_entry = TRUE;
  iterate->naddress = naddress;
  iterate->addresses = ssh_memdup(addresses, naddress * sizeof(*addresses));

  return &iterate->operation;
}


SshOperationHandle
ssh_pm_indicate_dns_change(SshPm pm,
                           const unsigned char *dns,
                           const unsigned char *address,
                           SshPmStatusCB callback, void *context)
{
  SshPmDnsObject entry;
  SshIpAddrStruct ipaddr[1];
  SshPmDnsReference ref;

  /* Update address assigned for this name */
  if (dns)
    {
      if ((entry = pm_dns_cache_find(pm->dnscache, dns)) == NULL)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Indication for new name"));
        }

      if (!entry)
        {
          ref = ssh_pm_dns_cache_insert(pm->dnscache,
                                        dns, SSH_PM_DNS_OC_NONE, NULL);
          ref->internal_list = pm->dnscache->references;
          pm->dnscache->references = ref;
          ref->flags |= SSH_IPM_DNS_REF_FLAG_NEW;

          entry = pm_dns_cache_find(pm->dnscache, dns);
        }
      else
        {
          for (ref = entry->referers;
               ref;
               ref = ref->next)
            if (ref->name_type == SSH_PM_DNS_OC_NONE)
              ref->flags |= SSH_IPM_DNS_REF_FLAG_SEEN;
        }

      if (address)
        {
          if (ssh_ipaddr_parse(ipaddr, address))
            {
              return pm_dns_iterate_one(pm,
                                        entry, dns, 1, ipaddr,
                                        callback, context);
            }
          else
            {
              SSH_DEBUG(SSH_D_ERROR, ("Indication for invalid address"
                                      "could not parse address."));
              goto failed;
            }
        }
      else
        {
          return pm_dns_iterate_one(pm,
                                    entry, dns, 0, NULL,
                                    callback, context);
        }
    }
  else
    {
      return pm_dns_iterate(pm, callback, context);
    }

  SSH_NOTREACHED;

 failed:
  (*callback)(pm, FALSE, context);
  return NULL;
}

#endif /* SSHDIST_IPSEC_DNSPOLICY */
/* eof */
