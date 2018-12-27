/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is the toplevel resolver function interface. This layer allows
   fetching data from the DNS. It will automatically use and fill in
   the cache, and it will follow CNAMEs and NS pointers if needed.
*/

#include "sshincludes.h"
#include "sshoperation.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshobstack.h"
#include "sshinet.h"
#include "sshdns.h"
#include "sshfsm.h"

#define SSH_DEBUG_MODULE "SshDnsResolver"

SSH_GLOBAL_DEFINE_INIT(int, ssh_dns_debug_pretty_print) = 0;

/* Resolver context structure. */
struct SshDNSResolverRec {
  /* Lower layer structures. */
  SshDNSQueryLayer query_layer;
  SshDNSNameServerCache name_server_cache;
  SshDNSRRsetCache rrset_cache;

  /* FSM for operations. */
  SshFSMStruct fsm[1];

  /* Number of safety belt name servers. There can be at maximum 27 safety belt
     name servers, and they are inserted to the name server cache under
     lowercase letters 'a', 'b', ... 'z', with the trailing root label at end,
     without the length field in the beginning (a-z are not valid length
     fields, as the length fields are limited to the 63 characters). As each
     dns name must have length field in the beginning they cannot be
     overwritten by the data from any other source. The number here is needed
     to known how many of those to remove when clear is called, and what is the
     name for the next server. Note, that the name server cache must have at
     least this many name server slots reserved, as these are always locked. */
  unsigned char next_sbelt_name[2];

  /* Current time. This is updated by the timeout. */
  SshTime current_time;

  /* Current operations in progress. If this goes to zero then we stop updating
     the current time above (i.e. we do not install timers anymore, thus the
     event loop will eventually exit). */
  int operations_count;

  /* Timeout structure. */
  SshTimeoutStruct timeout[1];

  /* Negative cache ttl. If set to 0, then default is 120 seconds. */
  SshUInt32 negative_cache_ttl;

  /* Shutdown pending */
  Boolean shutdown_pending;
};

SSH_FSM_STEP(ssh_dns_resolver_start);
SSH_FSM_STEP(ssh_dns_resolver_check_if_in_cache);
SSH_FSM_STEP(ssh_dns_resolver_find_ancestor);
SSH_FSM_STEP(ssh_dns_resolver_set_sbelt);
SSH_FSM_STEP(ssh_dns_resolver_find_nameservers);
SSH_FSM_STEP(ssh_dns_resolver_find_next_step);
SSH_FSM_STEP(ssh_dns_resolver_find_cname);
SSH_FSM_STEP(ssh_dns_resolver_find_from_root);
SSH_FSM_STEP(ssh_dns_resolver_find_from_root_next);
SSH_FSM_STEP(ssh_dns_resolver_fetch_nameservers_start);
SSH_FSM_STEP(ssh_dns_resolver_fetch_nameservers);
SSH_FSM_STEP(ssh_dns_resolver_fetch_nameservers_end);
SSH_FSM_STEP(ssh_dns_resolver_finish);
SSH_FSM_STEP(ssh_dns_resolver_memory_error);
SSH_FSM_STEP(ssh_dns_resolver_limit_reached);

#ifdef DEBUG_LIGHT
SshFSMStateDebugStruct ssh_dns_resolver_fsm_names[] =
{
  SSH_FSM_STATE("resolver_start", "Start operation",
                ssh_dns_resolver_start)
  SSH_FSM_STATE("resolver_check", "Check if the item is in the cache",
                ssh_dns_resolver_check_if_in_cache)
  SSH_FSM_STATE("resolver_find_ancestor", "Find the ancestor NS records",
                ssh_dns_resolver_find_ancestor)
  SSH_FSM_STATE("resolver_set_sbelt", "Set to use the safety belt",
                ssh_dns_resolver_set_sbelt)
  SSH_FSM_STATE("resolver_find_nameservers",
                "Find the name servers for the request",
                ssh_dns_resolver_find_nameservers)
  SSH_FSM_STATE("resolver_find", "Do the actual search",
                ssh_dns_resolver_find_next_step)
  SSH_FSM_STATE("resolver_find_cname",
                "Search CNAME record for host",
                ssh_dns_resolver_find_from_root)
  SSH_FSM_STATE("resolver_find_from_root",
                "Search NS records starting from root",
                ssh_dns_resolver_find_from_root)
  SSH_FSM_STATE("resolver_find_from_root_next",
                "Search next NS records starting from root",
                ssh_dns_resolver_find_from_root_next)
  SSH_FSM_STATE("resolver_fetch_nameservers_start",
                "Start fetching the name server IP-addresses",
                ssh_dns_resolver_fetch_nameservers_start)
  SSH_FSM_STATE("resolver_fetch_nameservers",
                "Fetch the name server IP-addresses",
                ssh_dns_resolver_fetch_nameservers)
  SSH_FSM_STATE("resolver_fetch_nameservers_end",
                "Finish fetching the name server IP-addresses",
                ssh_dns_resolver_fetch_nameservers_end)
  SSH_FSM_STATE("resolver_finish", "Finish processing the request",
                ssh_dns_resolver_finish)
  SSH_FSM_STATE("resolver_memory_error", "Memory error occurred",
                ssh_dns_resolver_memory_error)
  SSH_FSM_STATE("resolver_limit_reached", "Search limit reached",
                ssh_dns_resolver_limit_reached)
};

const int ssh_dns_resolver_fsm_names_count =
  SSH_FSM_NUM_STATES(ssh_dns_resolver_fsm_names);
#endif /* DEBUG_LIGHT */

/* Resolver operation. */
typedef struct SshDNSResolverOpRec {
  /* Operation handle. */
  SshOperationHandleStruct operation_handle[1];

  /* Timeout structure. */
  SshTimeoutStruct timeout[1];

  /* Timeout time. */
  SshUInt32 timeout_time;

  /* Callback and context to return result. */
  SshDNSResolverCallback callback;
  void *context;

  /* Flags */
  SshUInt32 flags;
#define SSH_DNS_FLAG_RETRY_FIND_A_RECORDS       0x80000000

  /* Name to search in dns-name format. Note, this is mallocated, as it may
     changed during the search if we hit the cnames. */
  unsigned char *name;

  /* Matched tokens. This is the number of labels we have already been able to
     match. If we cannot get better match from the cache, then we must return
     error. */
  SshUInt32 matched_tokens;

  /* Type of the query. */
  SshDNSRRType type;

  /* Thread handle. */
  SshFSMThreadStruct thread[1];

  /* Lower layer operation handle. */
  SshOperationHandle handle;

  /* Operation count pointer. This is decremented every time some operation is
     done, and if this goes to zero, then the operation is aborted. It is
     initialized to 500 in the beginning. This is to prevent loops etc. This is
     pointer so child searches can share the count from the parent. */
  SshInt32 *operation_count;

  /* Have we restarted from the safety belt with this search already. If so we
     do not restart from there again. */
  Boolean restarted_from_sbelt;

  /* Cname count. This limits the number of cnames we might hit before we give
     up. This is initialized to 10 and counting down. */
  SshInt32 cname_count;

  /* Current NS record rrset. */
  SshDNSRRset ns_rrset;

  /* Array of name server pointers. Each entry here corresponds to the ns_rrset
     rdata entry with same index. If entry is NULL then it should be skipped,
     as no ip for name server was found, or the name server was found to be
     faulty. */
  SshDNSNameServer *name_servers;

  /* Name server count, this is the copy of the ns_rrset->number_of_rrs or
     number of safety belt name servers if we are searching from the safety
     belt. */
  int name_servers_count;

  /* Current name server search item. For from root search this lists how many
     tokens from the beginning we should be skipping. */
  int name_server_index;

} *SshDNSResolverOp, SshDNSResolverOpStruct;

#define SSH_DNS_RESOLVER_OPERATION_COUNT(operation) \
  if ((*operation->operation_count)-- <= 0) \
    { \
      SSH_FSM_SET_NEXT(ssh_dns_resolver_limit_reached); \
      return SSH_FSM_CONTINUE; \
    }

/**********************************************************************/
/* DNS-resolver layer. This will do the actual full resolver
   query, and return the information back in the parsed
   format. It might do multiple queries to the query layer,
   and use the cached data if available. */

/* Free resolver. There must not be any operations in active
   when this is called. */
void
ssh_dns_resolver_free(SshDNSResolver resolver)
{

  /* Cancel timeout. */
  ssh_cancel_timeout(resolver->timeout);

  if (resolver->query_layer)
    ssh_dns_query_layer_free(resolver->query_layer);
  if (resolver->rrset_cache)
    ssh_dns_rrset_cache_free(resolver->rrset_cache);
  if (resolver->name_server_cache)
    {
      ssh_dns_resolver_safety_belt_clear(resolver);
      ssh_dns_name_server_cache_free(resolver->name_server_cache);
    }
  ssh_free(resolver);
  SSH_DEBUG(SSH_D_HIGHSTART, ("Resolver freed"));
}

void ssh_dns_resolver_shutdown(SshDNSResolver resolver)
{
  if (resolver->operations_count != 0)
    resolver->shutdown_pending = TRUE;
  else
    ssh_dns_query_layer_shutdown(resolver->query_layer);
}

/* Timeout tick. */
void ssh_dns_resolver_tick(void *context)
{
  SshDNSResolver resolver = context;
  resolver->current_time = ssh_time();
  SSH_DEBUG(SSH_D_LOWOK, ("Resolver tick updating clock"));
  if (resolver->operations_count != 0)
    ssh_register_timeout(resolver->timeout, 1, 0, ssh_dns_resolver_tick,
                         resolver);
  else if (resolver->shutdown_pending == TRUE)
    {
      resolver->shutdown_pending = FALSE;
      ssh_dns_query_layer_shutdown(resolver->query_layer);
    }
}

/* Allocate resolver layer. This will not automatically
   allocate any transportsetc, thus you need to call
   ssh_dns_resolver_configure to configure and allocate the
   transport layers. This will return NULL if out of memory. */
SshDNSResolver
ssh_dns_resolver_allocate(void)
{
  SshDNSResolver resolver;

  resolver = ssh_calloc(1, sizeof(*resolver));
  if (resolver == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating resolver"));
      return NULL;
    }

  SSH_DEBUG(SSH_D_HIGHSTART, ("Resolver allocated"));

  resolver->query_layer = ssh_dns_query_layer_allocate();
  resolver->name_server_cache = ssh_dns_name_server_cache_allocate();
  resolver->rrset_cache = ssh_dns_rrset_cache_allocate();
  resolver->next_sbelt_name[0] = 'a';
  resolver->next_sbelt_name[1] = 0;
  resolver->negative_cache_ttl = 120;
  ssh_fsm_init(resolver->fsm, resolver);
#ifdef DEBUG_LIGHT
  ssh_fsm_register_debug_names(resolver->fsm,
                               ssh_dns_resolver_fsm_names,
                               ssh_dns_resolver_fsm_names_count);
#endif /* DEBUG_LIGHT */

  if (resolver->query_layer == NULL ||
      resolver->name_server_cache == NULL ||
      resolver->rrset_cache == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of memory while allocating resolver"));
      ssh_dns_resolver_free(resolver);
      return NULL;
    }

  resolver->current_time = ssh_time();

  resolver->operations_count = 0;
  return resolver;
}

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
                           SshDNSResolverConfig config)
{
  Boolean status;

  status = TRUE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Reconfiguring resolver"));
  if (config == NULL || config->negative_cache_ttl == 0)
    resolver->negative_cache_ttl = 120;
  else
    resolver->negative_cache_ttl = config->negative_cache_ttl;

  if (!ssh_dns_query_layer_configure(resolver->query_layer,
                                     config == NULL ? NULL :
                                     &(config->query_layer_config)))
    status = FALSE;
  if (!ssh_dns_name_server_cache_configure(resolver->name_server_cache,
                                           config == NULL ? NULL :
                                           &(config->
                                             name_server_cache_config)))
    status = FALSE;
  if (!ssh_dns_rrset_cache_configure(resolver->rrset_cache,
                                     config == NULL ? NULL :
                                     &(config->rrset_config)))
    status = FALSE;
  return status;
}

/* Return the query layer handle. */
SshDNSQueryLayer
ssh_dns_resolver_query_layer(SshDNSResolver resolver)
{
  return resolver->query_layer;
}

/* Return the name server cache handle. */
SshDNSNameServerCache
ssh_dns_resolver_name_server_cache(SshDNSResolver resolver)
{
  return resolver->name_server_cache;
}

/* Return the rrset cache handle. */
SshDNSRRsetCache
ssh_dns_resolver_rrset_cache(SshDNSResolver resolver)
{
  return resolver->rrset_cache;
}

/* Register random number generator to the DNS library. By default the dns
   library uses ssh_rand (which needs to be seeded externally before dns
   library is used), but that is not safe enough for high security
   applications. High security applications needs to initialize the
   cryptolibrary and register the ssh_random_get_uint32 as random number
   function to the dns library. */
void ssh_dns_resolver_register_random_func(SshDNSResolver resolver,
                                           SshUInt32 (*rand_func)(void))
{
  ssh_dns_query_layer_register_random_func(resolver->query_layer,
                                           rand_func);
}

/* Clear safety belt information, this will decrement references away
   from the safety belt servers, thus after some time, they can be
   removed from the name server cache. */
void ssh_dns_resolver_safety_belt_clear(SshDNSResolver resolver)
{
  SshDNSNameServer name_server;
  SSH_DEBUG(SSH_D_HIGHSTART, ("Clearing safety belt"));

  while (resolver->next_sbelt_name[0] != 'a')
    {
      /* Remove name server. */
      (resolver->next_sbelt_name[0])--;
      name_server =
        ssh_dns_name_server_cache_get(resolver->name_server_cache,
                                      resolver->next_sbelt_name);
      SSH_ASSERT(name_server != NULL);

      /* We unlock it here twice. One is to remove the reference made above,
         and another time is to remove the reference when the name server was
         put in to the system. */
      ssh_dns_name_server_cache_unlock(resolver->name_server_cache,
                                       name_server);
      ssh_dns_name_server_cache_unlock(resolver->name_server_cache,
                                       name_server);
    }
}

/* Add name server to the safety belt server list. Note, that safety belt name
   servers do not have name associated to them, only IP-addresses. This
   function is used to insert the list of IP-addresses of the name servers
   which are used if we do not have anything better yet. I.e. these servers are
   used to get the NS-records of the root name servers etc. */
SshDNSNameServer
ssh_dns_resolver_safety_belt_add(SshDNSResolver resolver,
                                 SshUInt32 number_of_ip_addresses,
                                 SshIpAddr array_of_ip_addresses)
{
  SshDNSNameServer name_server;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Adding %d ip-numbers to safety belt, first ip = %@",
             (int) number_of_ip_addresses,
             ssh_ipaddr_render, number_of_ip_addresses > 0 ?
             &(array_of_ip_addresses[0]) : NULL));

  name_server =
    ssh_dns_name_server_cache_add(resolver->name_server_cache,
                                  resolver->next_sbelt_name,
                                  number_of_ip_addresses,
                                  array_of_ip_addresses,
                                  TRUE);
  if (name_server)
    {
      /* The data will be locked to the cache, as we do not free the
         reference here. */
      /* Move to the next name server. */
      (resolver->next_sbelt_name[0])++;
    }
  return name_server;
}

/* Set transport methods for the resolver. This is needed in case
   the default connection methods need to be overwritten */
Boolean
ssh_dns_resolver_set_transport_params(SshDNSResolver resolver,
                                      void *udp_params,
                                      void *tcp_params)
{
  return
    ssh_dns_query_layer_set_transport_params(resolver->query_layer,
                                             udp_params,
                                             tcp_params);

}
/* Call return callback with error code. If error code is anything else than
   SSH_DNS_OK, then replace IN_PROGRESS entry to cache with FAILURE.
   The rrset is already locked when this is called. */
void ssh_dns_resolver_call_callback(SshDNSResolverOp operation,
                                    SshDNSResponseCode error,
                                    SshDNSRRset rrset)
{
  SshDNSRRset current_rrset;

  SSH_DEBUG(SSH_D_LOWOK, ("Calling result callback"));

  /* If this was wildcard NODATA entry, then remove the in progress entry we
     have there, also if we got error, then put the entry in the cache which
     will indicate failure. */
  if (error != SSH_DNS_OK ||
      (error == SSH_DNS_OK && rrset != NULL &&
       rrset->state == SSH_DNS_RRSET_NODATA &&
       rrset->type == SSH_DNS_QUERY_ANY))
    {
      SshDNSResolver resolver;

      /* It was error. Try to find the current rrset from the cache. */
      resolver = ssh_fsm_get_gdata(operation->thread);

      current_rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                              operation->name,
                                              operation->type);
      if (current_rrset != NULL)
        {
          if (current_rrset->state ==  SSH_DNS_RRSET_IN_PROGRESS)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Removing IN_PROGRESS entry"));
              /* Unlock the old entry. */
              ssh_dns_rrset_cache_unlock(resolver->rrset_cache,
                                         current_rrset);
              /* It is IN_PROGRESS state, set it to NODATA or FAILURE
                 state. */
              if (error == SSH_DNS_OK)
                {
                  /* Success, but no data, so set it to NODATA, This is can
                     happen on out of memory etc situations. */
                  current_rrset =
                    ssh_dns_rrset_cache_add(resolver->rrset_cache,
                                            operation->name,
                                            SSH_DNS_RRSET_NODATA,
                                            operation->type,
                                            0, 0, NULL, NULL, NULL);
                }
              else
                {
                  unsigned char data[4], *ptr;
                  size_t len;

                  len = 4;
                  SSH_PUT_32BIT(data, (unsigned long) error);
                  ptr = data;

                  /* Failure, store the error code in the first rr. */
                  current_rrset =
                    ssh_dns_rrset_cache_add(resolver->rrset_cache,
                                            operation->name,
                                            SSH_DNS_RRSET_FAILURE,
                                            operation->type,
                                            resolver->negative_cache_ttl,
                                            1, &len, &ptr, NULL);
                }
              /* Again, we do not care about errors, as this will always
                 succeed, if we overwrite IN_PROGRESS with FAILURE or NODATA,
                 and in all other cases it does not matter. */
              /* If it returned rrset we need to unlock it now. */
              if (current_rrset)
                ssh_dns_rrset_cache_unlock(resolver->rrset_cache,
                                           current_rrset);
            }
          else
            {
              /* Simply free entry. */
              ssh_dns_rrset_cache_unlock(resolver->rrset_cache,
                                         current_rrset);
            }
        }
      else
        {
          /* Do nothing. If we do not have anything in the cache, then we do
             not need to do anything, and if we have something else than
             IN_PROGRESS (i.e FAILURE or NON_AUTHORATIVE), then we simply keep
             that in the cache. */
        }
    }
  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);

  /* Call the callback. */
  operation->callback(error, rrset, operation->context);
}

/* Clear temporary data. */
void ssh_dns_resolver_clear_temporary_data(SshDNSResolver resolver,
                                           SshDNSResolverOp operation)
{
  int i;

  SSH_DEBUG(SSH_D_LOWOK, ("Clearing temporary data"));

  /* Free all data. */
  if (operation->ns_rrset != NULL)
    ssh_dns_rrset_cache_unlock(resolver->rrset_cache, operation->ns_rrset);
  operation->ns_rrset = NULL;

  for(i = 0; i < operation->name_servers_count; i++)
    {
      if (operation->name_servers[i] != NULL)
        {
          ssh_dns_name_server_cache_unlock(resolver->name_server_cache,
                                           operation->name_servers[i]);
        }
      operation->name_servers[i] = NULL;
    }
  ssh_free(operation->name_servers);
  operation->name_servers = NULL;
  operation->name_servers_count = 0;
}

/* Destructor for the thread. This will only free memory allocated to the
   operation, and unlock all the entries. */
void ssh_dns_resolver_thread_destructor(SshFSM fsm, void *context)
{
  SshDNSResolverOp operation = context;
  SshDNSResolver resolver;

  SSH_DEBUG(SSH_D_LOWOK, ("Destroying thread"));
  resolver = ssh_fsm_get_gdata_fsm(fsm);
  ssh_dns_resolver_clear_temporary_data(resolver, operation);

  resolver->operations_count--;
  /* Operation count goes to zero, no need to keep timer running. */
  if (resolver->operations_count == 0)
    {
    ssh_cancel_timeout(resolver->timeout);
      if (resolver->shutdown_pending == TRUE)
        {
          resolver->shutdown_pending = FALSE;
          ssh_dns_query_layer_shutdown(resolver->query_layer);
        }
    }
  ssh_free(operation->name);
  ssh_free(operation);
}

/* Abort the operation. */
void ssh_dns_resolver_abort(void *context)
{
  SshDNSResolverOp operation = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Aborting operation"));
  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);
  /* Abort lower level operations. */
  if (operation->handle != NULL)
    ssh_operation_abort(operation->handle);
  operation->handle = NULL;

  /* Kill thread. */
  ssh_fsm_kill_thread(operation->thread);
}

/* Operation timed out. */
void ssh_dns_resolver_timeout(void *context)
{
  SshDNSResolverOp operation = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Operation timed out"));
  /* Unregister the operation. */
  ssh_operation_unregister(operation->operation_handle);
  /* Abort lower level operations. */
  if (operation->handle != NULL)
    ssh_operation_abort(operation->handle);
  operation->handle = NULL;

  /* Call the callback. */
  ssh_dns_resolver_call_callback(operation, SSH_DNS_TIMEOUT, NULL);

  /* Kill thread. */
  ssh_fsm_kill_thread(operation->thread);
}

/* Find the given RRtype from the name server and call
   callback when the data is available. */
SshOperationHandle
ssh_dns_resolver_find_internal(SshDNSResolver resolver,
                               const unsigned char *name,
                               SshDNSRRType type,
                               SshUInt32 timeout_in_us,
                               SshUInt32 flags,
                               SshDNSResolverCallback callback,
                               void *context,
                               SshDNSResolverOp parent)
{
  SshDNSResolverOp operation;

  if (parent == NULL)
    operation = ssh_calloc(1, sizeof(*operation) + sizeof(SshUInt32));
  else
    operation = ssh_calloc(1, sizeof(*operation));

  if (operation == NULL)
    {
      callback(SSH_DNS_MEMORY_ERROR, NULL, context);
      return NULL;
    }

  operation->name = ssh_strdup(name);
  if (operation->name == NULL)
    {
      ssh_free(operation);
      callback(SSH_DNS_MEMORY_ERROR, NULL, context);
      return NULL;
    }

  ssh_operation_register_no_alloc(operation->operation_handle,
                                  ssh_dns_resolver_abort,
                                  operation);

  operation->callback = callback;
  operation->context = context;
  operation->type = type;
  operation->flags = flags;
  operation->timeout_time = timeout_in_us;
  if (parent == NULL)
    {
      operation->operation_count = (void *)
        ((unsigned char *) operation + sizeof(*operation));
      *operation->operation_count = 500;
    }
  else
    {
      /* Share the same operation count. */
      operation->operation_count = parent->operation_count;
    }

  /* Start the ticker if this was the first operation. */
  if (resolver->operations_count++ == 0)
    ssh_dns_resolver_tick(resolver);

  ssh_register_timeout(operation->timeout,
                       0, timeout_in_us,
                       ssh_dns_resolver_timeout,
                       operation);
  ssh_fsm_thread_init(resolver->fsm,
                      operation->thread,
                      ssh_dns_resolver_start,
                      NULL, ssh_dns_resolver_thread_destructor, operation);
#ifdef DEBUG_LIGHT
  ssh_fsm_set_thread_name(operation->thread, "ResolverThread");
#endif /* DEBUG_LIGHT */
  return operation->operation_handle;
}

/* Find the given RRtype from the name server and call
   callback when the data is available. */
SshOperationHandle
ssh_dns_resolver_find(SshDNSResolver resolver,
                      const unsigned char *name,
                      SshDNSRRType type,
                      SshUInt32 timeout_in_us,
                      SshUInt32 flags,
                      SshDNSResolverCallback callback,
                      void *context)
{
  return ssh_dns_resolver_find_internal(resolver, name, type, timeout_in_us,
                                        flags, callback, context, NULL);
}

/* Check if the rrset is expired, and if so remove it from cache.
   Returns the rrset or NULL in case it was removed from cache.
   This also unlocks the rrset in cache. */
SshDNSRRset ssh_dns_resolver_remove_if_expired(SshDNSResolver resolver,
                                               SshDNSRRset rrset)
{
  if (rrset != NULL &&
      rrset->state != SSH_DNS_RRSET_IN_PROGRESS &&
      SSH_DNS_RRSET_EXPIRED(rrset, resolver->current_time))
    {
      /* RRset is expired, remove it. */
      SSH_DEBUG(SSH_D_MIDOK, ("Removing expired %@",
                              ssh_dns_rrset_render, rrset));
      ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      ssh_dns_rrset_cache_remove(resolver->rrset_cache,
                                 rrset->name, rrset->type);
      return NULL;
    }
  return rrset;
}

/* Initialize the query. */
SSH_FSM_STEP(ssh_dns_resolver_start)
{
  SshDNSResolverOp operation = thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Starting search of %@, type = %s (%d)",
                          ssh_dns_name_render, operation->name,
                          ssh_dns_rrtype_string(operation->type),
                          operation->type));
  operation->cname_count = 10;
  operation->restarted_from_sbelt = FALSE;
  operation->matched_tokens = ~0;
  if (operation->flags & SSH_DNS_RESOLVER_IGNORE_CACHE)
    {
      if (operation->flags & SSH_DNS_RESOLVER_START_FROM_SBELT)
        SSH_FSM_SET_NEXT(ssh_dns_resolver_set_sbelt);
      else
        SSH_FSM_SET_NEXT(ssh_dns_resolver_find_ancestor);
    }
  else
    {
      SSH_FSM_SET_NEXT(ssh_dns_resolver_check_if_in_cache);
    }

  return SSH_FSM_CONTINUE;
}

/* Data is ready in the rrset cache. */
void ssh_dns_resolver_data_available_cb(SshDNSRRset rrset, void *context)
{
  SshDNSResolverOp operation = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Data should be available now"));
  operation->handle = NULL;
  /* Just continue the thread. */
  SSH_FSM_CONTINUE_AFTER_CALLBACK(operation->thread);
}

/* Follow CNAME and return TRUE if successfull and FALSE otherwise (in that
   case the next step of the thread is already set by this function). */
Boolean ssh_dns_resolver_follow_cname(SshDNSResolverOp operation,
                                      const unsigned char *cname_data)
{
  /* We found valid CNAME, follow it and try again. */
  if (operation->cname_count-- <= 0)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Cname loop, return error"));
      /* Cname_count limit exceeded, abort. */
      ssh_fsm_set_next(operation->thread, ssh_dns_resolver_limit_reached);
      return FALSE;
    }
  /* Free the old name. */
  ssh_free(operation->name);
  operation->name = ssh_strdup(cname_data);
  if (operation->name == NULL)
    {
      ssh_fsm_set_next(operation->thread, ssh_dns_resolver_memory_error);
      return FALSE;
    }
  SSH_DEBUG(SSH_D_MIDOK, ("Continue from new name %@",
                          ssh_dns_name_render,
                          operation->name));
  operation->restarted_from_sbelt = FALSE;
  operation->matched_tokens = ~0;
  return TRUE;
}

/* Check if the data we search for is already in the cache. */
SSH_FSM_STEP(ssh_dns_resolver_check_if_in_cache)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;
  SshDNSRRset rrset;

  SSH_DEBUG(SSH_D_LOWOK, ("Check if the data is in the cache"));
  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                  operation->name,
                                  operation->type);
  /* Remove it from cache if it was expired. */
  rrset = ssh_dns_resolver_remove_if_expired(resolver, rrset);

  if (rrset == NULL)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No, check for CNAME"));
      rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                      operation->name,
                                      SSH_DNS_RESOURCE_CNAME);
      /* Remove it from cache if it was expired. */
      rrset = ssh_dns_resolver_remove_if_expired(resolver, rrset);

      if (rrset == NULL)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("No cname, start search"));
          /* Not found, start real search. */
          if (operation->flags & SSH_DNS_RESOLVER_START_FROM_SBELT)
            SSH_FSM_SET_NEXT(ssh_dns_resolver_set_sbelt);
          else
            SSH_FSM_SET_NEXT(ssh_dns_resolver_find_ancestor);
          return SSH_FSM_CONTINUE;
        }
    }

  /* Found from cache, see if it is valid. */
  if ((SSH_DNS_RRSET_OK(rrset) ||
       ((operation->flags & SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE) &&
        SSH_DNS_RRSET_HINT_OK(rrset))))
    {
      if (rrset->type != operation->type &&
          rrset->type == SSH_DNS_RESOURCE_CNAME)
        {
          /* We ignore the error code, as we always continue after following
             the cname, either from error state set by the follow_cname
             function or from this state again. */
          ssh_dns_resolver_follow_cname(operation, rrset->array_of_rdata[0]);
          ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
          return SSH_FSM_CONTINUE;
        }
      SSH_DEBUG(SSH_D_MIDOK, ("Found data from cache, return it %@",
                              ssh_dns_rrset_render, rrset));
      /* Yes, this is something we can return to user. */
      ssh_dns_resolver_call_callback(operation, SSH_DNS_OK, rrset);
      ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      SSH_FSM_SET_NEXT(ssh_dns_resolver_finish);
      return SSH_FSM_CONTINUE;
    }

  /* Check if the entry in the cache is FAILURE, which is not yet expired. */
  if (rrset->state == SSH_DNS_RRSET_FAILURE)
    {
      /* Ok, return it as an error. */
      SSH_DEBUG(SSH_D_MIDOK, ("Found failure from cache, return it %@",
                              ssh_dns_rrset_render, rrset));
      SSH_ASSERT(rrset->number_of_rrs == 1);
      SSH_ASSERT(rrset->array_of_rdlengths[0] == sizeof(SshInt32));
      /* Yes, this is something we can return to user. */
      ssh_dns_resolver_call_callback(operation,
                                     SSH_GET_32BIT(rrset->array_of_rdata[0]),
                                     NULL);
      ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      SSH_FSM_SET_NEXT(ssh_dns_resolver_finish);
      return SSH_FSM_CONTINUE;
    }

  /* See if it is in progress, if so, we need to wait for that. */
  if (rrset->state == SSH_DNS_RRSET_IN_PROGRESS)
    {
      SSH_ASSERT(rrset->number_of_rrs == 1);
      SSH_ASSERT(rrset->array_of_rdlengths[0] == sizeof(SshInt32));
      if (SSH_GET_32BIT(rrset->array_of_rdata[0]) ==
          (((unsigned long) operation->operation_count) & 0xffffffffL))
        {
          SSH_DEBUG(SSH_D_UNCOMMON,
                    ("Found in progress data, this is deadlock"));
          ssh_dns_resolver_call_callback(operation, SSH_DNS_LIMIT_REACHED,
                                         NULL);
          ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
          SSH_FSM_SET_NEXT(ssh_dns_resolver_finish);
          return SSH_FSM_CONTINUE;
        }
      SSH_DEBUG(SSH_D_LOWOK,
                ("Found in progress data, waiting for it to be ready"));

      /* Attach the notification and wait for the data to be available.
         After the attach we continue from this same state. */
      SSH_FSM_ASYNC_CALL(
         operation->handle =
         ssh_dns_rrset_cache_add_notify(resolver->rrset_cache,
                                        rrset,
                                        ssh_dns_resolver_data_available_cb,
                                        operation);
         /* We can remove the reference now, as it is no longer needed. */
         ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
         );
    }

  /* The data was not authorative (and it that was not allowed), it was
     expired, or there was failure. We need to start real search. */
  SSH_DEBUG(SSH_D_LOWOK, ("The data was not valid, start search"));
  if (operation->flags & SSH_DNS_RESOLVER_START_FROM_SBELT)
    SSH_FSM_SET_NEXT(ssh_dns_resolver_set_sbelt);
  else
    SSH_FSM_SET_NEXT(ssh_dns_resolver_find_ancestor);
  ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
  return SSH_FSM_CONTINUE;
}

/* Fill in the name server cache if the information is available on the rrset
   cache. Return the new name server if everything ok, otherwise return
   NULL. */
SshDNSNameServer
ssh_dns_resolver_fill_name_server(SshDNSResolver resolver,
                                  const unsigned char *name)
{
  SshDNSNameServer name_server = NULL;
  SshDNSRRset rrset4, rrset6;

  SSH_DEBUG(SSH_D_LOWOK, ("Try to fill in the name server %@",
                          ssh_dns_name_render, name));
  rrset4 = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                   name, SSH_DNS_RESOURCE_A);
  /* Remove it from cache if it was expired. */
  rrset4 = ssh_dns_resolver_remove_if_expired(resolver, rrset4);

  rrset6 = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                   name, SSH_DNS_RESOURCE_AAAA);
  /* Remove it from cache if it was expired. */
  rrset6 = ssh_dns_resolver_remove_if_expired(resolver, rrset6);

  if ((rrset4 != NULL && SSH_DNS_RRSET_HINT_OK(rrset4) &&
       rrset4->number_of_rrs != 0) ||
      (rrset6 != NULL && SSH_DNS_RRSET_HINT_OK(rrset6) &&
       rrset6->number_of_rrs != 0))
    {
      /* There is some valid information add it to the name server cache. */
      int i, j, number_of_ip_addresses;
      SshIpAddr array_of_ip_addresses;
      Boolean authorative;

      number_of_ip_addresses = 0;
      if (rrset4 != NULL)
        number_of_ip_addresses += rrset4->number_of_rrs;
      if (rrset6 != NULL)
        number_of_ip_addresses += rrset6->number_of_rrs;

      array_of_ip_addresses = ssh_calloc(number_of_ip_addresses,
                                         sizeof(*array_of_ip_addresses));
      j = 0;
      authorative = TRUE;
      if (rrset4 != NULL)
        {
          for(i = 0; i < rrset4->number_of_rrs; i++)
            if (rrset4->array_of_rdlengths[i] == 4)
              {
                SSH_IP4_DECODE(&(array_of_ip_addresses[j]),
                               rrset4->array_of_rdata[i]);
                j++;
              }
          if (!SSH_DNS_RRSET_OK(rrset4))
            authorative = FALSE;
        }
      if (rrset6 != NULL)
        {
          for(i = 0; i < rrset6->number_of_rrs; i++)
            if (rrset6->array_of_rdlengths[i] == 16)
              {
                SSH_IP6_DECODE(&(array_of_ip_addresses[j]),
                               rrset6->array_of_rdata[i]);
                j++;
              }
          if (!SSH_DNS_RRSET_OK(rrset6))
            authorative = FALSE;
        }
      name_server =
        ssh_dns_name_server_cache_add(resolver->name_server_cache,
                                      name, j, array_of_ip_addresses,
                                      authorative);
      ssh_free(array_of_ip_addresses);
    }

  if (rrset4 != NULL)
    ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset4);
  if (rrset6 != NULL)
    ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset6);
  return name_server;
}

/* Fill in all name servers. Returns the number of name servers found. */
int ssh_dns_resolver_fill_name_servers(SshDNSResolverOp operation)
{
  SshDNSResolver resolver;
  int i, j;

  resolver = ssh_fsm_get_gdata(operation->thread);

  if (operation->ns_rrset == NULL)
    return 0;

  j = 0;
  for(i = 0; i < operation->ns_rrset->number_of_rrs; i++)
    {
      if (operation->name_servers[i] == NULL)
        {
          operation->name_servers[i] =
            ssh_dns_resolver_fill_name_server(resolver,
                                              operation->ns_rrset->
                                              array_of_rdata[i]);
        }
      if (operation->name_servers[i] != NULL &&
          operation->name_servers[i]->failure_count <
          operation->name_servers[i]->number_of_ip_addresses * 5)
        {
          /* We did find the NS-server entry */
          j++;
        }
    }
  return j;
}

/* Match if the operation is trying to find the IP address of the name server
   from the nameserver itself. */
Boolean ssh_dns_resolver_match_self(SshDNSResolverOp operation,
                                    SshDNSRRset rrset)
{
  int i;

  /* If we are trying to find something else than A or AAAA
     record, then it is ok. */
  if (operation->type != SSH_DNS_RESOURCE_A &&
      operation->type != SSH_DNS_RESOURCE_AAAA)
    return FALSE;
  /* We are trying to find IP number, so make sure we
     do not try to find it from ourself. */
  for(i = 0; i < rrset->number_of_rrs; i++)
    {
      if (ssh_ustrcasecmp(operation->name, rrset->array_of_rdata[i]) == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("We are trying to find info about me from myself"));
          /* Yes, so there is no point of trying to fetch the IP-addresses
             from the same server, thus we need to move up one ancestor. */
          return TRUE;
        }
    }
  return FALSE;
}

/* Find the closes ancestor of the name. */
SSH_FSM_STEP(ssh_dns_resolver_find_ancestor)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;
  unsigned char *name;
  SshDNSRRset rrset;
  SshUInt32 tokens;

  SSH_DEBUG(SSH_D_LOWOK, ("Find ancestor"));
  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  /* Clear old data away. */
  ssh_dns_resolver_clear_temporary_data(resolver, operation);

  /* Search for NS record of the the ancestor, which is already in
     the cache. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Try to find NS with A record of ancestor in cache"));
  name = operation->name;
  tokens = 0;
  while (1)
    {
      rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                      name, SSH_DNS_RESOURCE_NS);
      /* Remove it from cache if it was expired. */
      rrset = ssh_dns_resolver_remove_if_expired(resolver, rrset);

      if (rrset != NULL &&
          SSH_DNS_RRSET_HINT_OK(rrset))
        {
          int ns_cnt;

          SSH_DEBUG(SSH_D_LOWOK, ("Found possible NS record"));
          operation->ns_rrset = rrset;
          operation->name_servers_count =
            operation->ns_rrset->number_of_rrs;
          operation->name_servers =
            ssh_calloc(operation->name_servers_count,
                       sizeof(SshDNSNameServer));
          if (operation->name_servers == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_dns_resolver_memory_error);
              return SSH_FSM_CONTINUE;
            }
          ns_cnt = ssh_dns_resolver_fill_name_servers(operation);
          if (ns_cnt != 0)
            {
              operation->matched_tokens = tokens;
              SSH_DEBUG(SSH_D_LOWOK, ("Found usable name servers"));
              SSH_FSM_SET_NEXT(ssh_dns_resolver_find_next_step);
              return SSH_FSM_CONTINUE;
            }
          operation->ns_rrset = NULL;
          ssh_free(operation->name_servers);
          operation->name_servers = NULL;
          operation->name_servers_count = 0;
        }
      /* Not found or not valid, unlock the entry, and try the next
         ancestor. */
      if (rrset != NULL)
        ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      if (*name == 0)
        break;
      name += *name + 1;
      tokens++;
      if (tokens >= operation->matched_tokens)
        {
          /* We did already have better match for the name, but now we are
             trying to go backwards. */
          break;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("No usable NS server found"));

  /* We didn't find any name servers with IP addresses. Lets see if there was
     any NS records, and if so try to search IP-addresses for that NS
     record. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Try to find NS records of ancestor in cache"));
  name = operation->name;
  tokens = 0;
  while (1)
    {
      rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                      name, SSH_DNS_RESOURCE_NS);
      /* Remove it from cache if it was expired. */
      rrset = ssh_dns_resolver_remove_if_expired(resolver, rrset);

      if (rrset != NULL &&
          SSH_DNS_RRSET_HINT_OK(rrset))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Found NS record"));

          operation->ns_rrset = rrset;
          operation->name_servers_count =
            operation->ns_rrset->number_of_rrs;
          operation->name_servers =
            ssh_calloc(operation->name_servers_count,
                       sizeof(SshDNSNameServer));
          if (operation->name_servers == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_dns_resolver_memory_error);
              return SSH_FSM_CONTINUE;
            }

          if (!ssh_dns_resolver_match_self(operation, rrset))
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Didn't find IP addresses for name "
                         "servers, fetch them"));
              SSH_FSM_SET_NEXT(ssh_dns_resolver_find_nameservers);
              return SSH_FSM_CONTINUE;
            }
          SSH_DEBUG(SSH_D_LOWOK, ("Cannot use that NS, as we would be "
                                  "searching the IP from the host itself"));
          /* Ignore this NS, as we cannot get IP-address for it, as
             we would need to fetch them from the name server itself. */
          operation->ns_rrset = NULL;
          ssh_free(operation->name_servers);
          operation->name_servers = NULL;
          operation->name_servers_count = 0;
        }

      /* Not found or not valid, unlock the entry, and try the next
         ancestor. */
      if (rrset != NULL)
        ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      if (*name == 0)
        break;
      name += *name + 1;
      tokens++;
      if (tokens >= operation->matched_tokens)
        {
          /* We did already have better match for the name, but now we are
             trying to go backwards. */
          break;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Still no NS record, see if we can try parents"));
  name = operation->name;
  tokens = 0;
  while (1)
    {
      rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                      name, SSH_DNS_RESOURCE_NS);
      /* Remove it from cache if it was expired. */
      rrset = ssh_dns_resolver_remove_if_expired(resolver, rrset);

      if (rrset != NULL &&
          SSH_DNS_RRSET_HINT_OK(rrset))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Found NS record"));

          operation->ns_rrset = rrset;
          operation->name_servers_count =
            operation->ns_rrset->number_of_rrs;
          operation->name_servers =
            ssh_calloc(operation->name_servers_count,
                       sizeof(SshDNSNameServer));
          if (operation->name_servers == NULL)
            {
              SSH_FSM_SET_NEXT(ssh_dns_resolver_memory_error);
              return SSH_FSM_CONTINUE;
            }

          if (ssh_dns_resolver_match_self(operation, rrset))
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("This is matching us, we need to try from root"));
              SSH_FSM_SET_NEXT(ssh_dns_resolver_find_from_root);
              return SSH_FSM_CONTINUE;
            }
          /* Ignore this NS. */
          operation->ns_rrset = NULL;
          ssh_free(operation->name_servers);
          operation->name_servers = NULL;
          operation->name_servers_count = 0;
        }

      /* Not found or not valid, unlock the entry, and try the next
         ancestor. */
      if (rrset != NULL)
        ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      if (*name == 0)
        break;
      name += *name + 1;
      tokens++;
      if (tokens >= operation->matched_tokens)
        {
          /* We did already have better match for the name, but now we are
             trying to go backwards. Return limit exceeded error. */
          SSH_DEBUG(SSH_D_LOWOK, ("Going backwards"));
          SSH_FSM_SET_NEXT(ssh_dns_resolver_limit_reached);
          return SSH_FSM_CONTINUE;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("No NS record find, try from safety belt"));
  /* No NS record found, set name servers from safety belt. */
  SSH_FSM_SET_NEXT(ssh_dns_resolver_set_sbelt);
  return SSH_FSM_CONTINUE;
}

/* Set the name server information from the sbelt. */
SSH_FSM_STEP(ssh_dns_resolver_set_sbelt)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;
  unsigned char sbelt[2];
  int i;

  SSH_DEBUG(SSH_D_MIDOK, ("Start from safety belt"));
  if (operation->restarted_from_sbelt)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Already tried that, return error"));
      SSH_FSM_SET_NEXT(ssh_dns_resolver_limit_reached);
      return SSH_FSM_CONTINUE;
    }
  operation->restarted_from_sbelt = TRUE;

  ssh_dns_resolver_clear_temporary_data(resolver, operation);

  operation->matched_tokens = ~0;

  operation->name_servers_count = resolver->next_sbelt_name[0] - 'a';
  operation->name_servers =
    ssh_calloc(operation->name_servers_count,
               sizeof(SshDNSNameServer));

  if (operation->name_servers == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for name servers"));
      SSH_FSM_SET_NEXT(ssh_dns_resolver_memory_error);
      return SSH_FSM_CONTINUE;
    }

  for(sbelt[0] = 'a', sbelt[1] = 0, i = 0;
      sbelt[0] < resolver->next_sbelt_name[0];
      sbelt[0]++, i++)
    {
      operation->name_servers[i] =
        ssh_dns_name_server_cache_get(resolver->name_server_cache, sbelt);
      SSH_ASSERT(operation->name_servers[i] != NULL);
    }
  SSH_FSM_SET_NEXT(ssh_dns_resolver_find_next_step);
  return SSH_FSM_CONTINUE;
}

/* Find name server ip-addresses and store them to the name server cache. */
SSH_FSM_STEP(ssh_dns_resolver_find_nameservers)
{
  SshDNSResolverOp operation = thread_context;
  int ns_cnt;

  SSH_DEBUG(SSH_D_LOWOK, ("Find name servers"));
  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  ns_cnt = ssh_dns_resolver_fill_name_servers(operation);
  if (ns_cnt == 0)
    {
      /* No name servers found from the name server cache nor from the rrset
         cache. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("No name servers, Try to find some A records for them"));
      /* Try to fetch some of the A records for the name servers. */
      SSH_FSM_SET_NEXT(ssh_dns_resolver_fetch_nameservers_start);
      return SSH_FSM_CONTINUE;
    }
  SSH_DEBUG(SSH_D_LOWOK, ("Did find at least one name server"));
  /* Ok, we have name servers now, try to find the information. */
  SSH_FSM_SET_NEXT(ssh_dns_resolver_find_next_step);
  return SSH_FSM_CONTINUE;
}

/* Add rrsets from the records to the cache. */
void ssh_dns_resolver_add_rrsets(SshDNSResolver resolver,
                                 SshDNSRRset parent,
                                 unsigned char *qname,
                                 SshUInt16 record_count,
                                 SshDNSRecord records,
                                 Boolean authorative)
{
  unsigned char **array_of_rdata;
  size_t *array_of_rdlengths;
  SshDNSRecordStruct record;
  SshDNSRRsetState state;
  SshDNSRRset rrset;
  int i, j, k;

  if (record_count == 0)
    return;

  SSH_DEBUG(SSH_D_LOWOK, ("Add rrset to the cache."));

  array_of_rdlengths = ssh_malloc(record_count * sizeof(*array_of_rdlengths));
  if (array_of_rdlengths == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for rrsets lengths."));
      return;
    }

  array_of_rdata = ssh_malloc(record_count * sizeof(*array_of_rdata));
  if (array_of_rdata == NULL)
    {
      ssh_free(array_of_rdlengths);
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed for rrsets data."));
      return;
    }

  for(i = 0; i < record_count; )
    {
      /* Search all resource records. */
      k = 0;
      array_of_rdlengths[k] = records[i + k].rdlength;
      array_of_rdata[k] = records[i + k].rdata;
      k++;
      for(j = i + 1; j < record_count; j++)
        {
          if (records[i].type == records[j].type &&
              records[i].dns_class == records[j].dns_class &&
              ssh_ustrcasecmp(records[i].name, records[j].name) == 0)
            {
              record = records[j];
              records[j] = records[i + k];
              records[i + k] = record;
              array_of_rdlengths[k] = records[i + k].rdlength;
              array_of_rdata[k] = records[i + k].rdata;
              k++;
            }
        }
      if (ssh_ustrcasecmp(records[i].name, qname) == 0 && authorative)
        state = SSH_DNS_RRSET_AUTHORATIVE;
      else
        state = SSH_DNS_RRSET_NON_AUTHORATIVE;

      /* Ok, now we have all resource records of same type in the indexes
         from i to i + k. */
      rrset = ssh_dns_rrset_cache_add(resolver->rrset_cache, records[i].name,
                                      state, records[i].type, records[i].ttl,
                                      k, array_of_rdlengths, array_of_rdata,
                                      parent);
      if (rrset)
        ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
      i += k;
    }
  ssh_free(array_of_rdlengths);
  ssh_free(array_of_rdata);
}

/* Match tokens from the end. */
Boolean ssh_dns_resolver_is_subdomain(unsigned char *top_domain,
                                      unsigned char *sub_domain)
{
  size_t len1, len2;

  len1 = ssh_ustrlen(top_domain);
  len2 = ssh_ustrlen(sub_domain);
  if (len2 > len1 ||
      ssh_ustrcasecmp(sub_domain, top_domain + len1 - len2) != 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("The domain %@ is not subdomain of %@",
                              ssh_dns_name_render, sub_domain,
                              ssh_dns_name_render, top_domain));
      return FALSE;
    }
  return TRUE;
}

/* Reply from the name server. */
void ssh_dns_resolver_query_cb(SshDNSResponseCode error,
                               SshDNSNameServer name_server,
                               const unsigned char *return_packet,
                               size_t packet_length,
                               void *context)
{
  SshDNSResolverOp operation = context;
  SshDNSResolver resolver;
  SshDNSPacket packet = NULL;
  SshDNSRRset rrset = NULL;
  int i, ns_records;
  int soa_in_authority;

  operation->handle = NULL;

  resolver = ssh_fsm_get_gdata(operation->thread);

  if (error != SSH_DNS_OK || return_packet == NULL)
    {
      if (error == SSH_DNS_TIMEOUT &&
          (operation->flags & SSH_DNS_FLAG_RETRY_FIND_A_RECORDS) == 0)
        {
          operation->flags |= SSH_DNS_FLAG_RETRY_FIND_A_RECORDS;
          /* Try to start searching the name server A
             records again.  */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Timeout, Try to find some A records for them"));
          /* Try to fetch some of the A records for the name servers. */
          ssh_fsm_set_next(operation->thread,
                           ssh_dns_resolver_fetch_nameservers_start);
          SSH_FSM_CONTINUE_AFTER_CALLBACK(operation->thread);
          return;
        }

      /* No response from the other end, we need to return error to the
         upper layer. */
      SSH_DEBUG(SSH_D_MIDOK, ("Got error %s  back for our query",
                              ssh_dns_response_code_string(error)));
      goto finish;
    }

  /* Received return packet from the other end. */
  /* Parse the return packet. */
  packet = ssh_dns_packet_decode(return_packet, packet_length);
  if (packet == NULL ||
      !(packet->flags & SSH_DNS_FLAG_IS_RESPONSE) ||
      packet->op_code != SSH_DNS_OPCODE_QUERY ||
      (packet->response_code != SSH_DNS_OK &&
       packet->response_code != SSH_DNS_NONEXISTENT_DOMAIN))
    {
      if (packet == NULL)
        SSH_DEBUG(SSH_D_MIDOK, ("Error in packet parsing"));
      else
        SSH_DEBUG(SSH_D_MIDOK,
                  ("Invalid op code, flags or response code  %.*@",
                   ssh_dns_debug_pretty_print,
                   ssh_dns_packet_render, packet));
      /* Error parsing the return packet. Delete the name server from the list
         and try again. */
    remove_name_server:
      SSH_DEBUG(SSH_D_MIDOK, ("Removing offending name server"));
      for(i = 0; i < operation->name_servers_count; i++)
        {
          if (operation->name_servers[i] == name_server)
            break;
        }
      if (i == operation->name_servers_count)
        ssh_fatal("Internal error, name server returning value is not "
                  "in the query list.");

      /* Remove that to be used. */
      operation->name_servers[i] = NULL;

      /* Unlock the faulty name server. */
      ssh_dns_name_server_cache_unlock(resolver->name_server_cache,
                                       name_server);

      /* Check that we still have name servers. */
      for(i = 0; i < operation->name_servers_count; i++)
        {
          if (operation->name_servers[i] != NULL)
            break;
        }
      if (i == operation->name_servers_count)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("No more name servers, try from safety belt"));
          /* No more name servers, try to restart from the sbelt. */
          ssh_fsm_set_next(operation->thread, ssh_dns_resolver_set_sbelt);
        }
      goto exit;
    }

  /* We have return packet, now see what to do with it. */
  SSH_DEBUG(SSH_D_MIDOK, ("Got reply back for our query: %.*@",
                          ssh_dns_debug_pretty_print,
                          ssh_dns_packet_render, packet));

  /* First lets see this is really a response to our query, i.e. that the
     question name, class and name matches. */
  if (packet->question_count != 1 ||
      packet->question_array[0].qtype != operation->type ||
      packet->question_array[0].qclass != SSH_DNS_CLASS_INTERNET ||
      ssh_ustrcasecmp(packet->question_array[0].qname, operation->name) != 0)
    {
      /* It didn't match to our query, remove that name server and
         try again. */
      SSH_DEBUG(SSH_D_MIDOK, ("Reply didn't match our query"));
      goto remove_name_server;
    }

  soa_in_authority = -1;
  ns_records = 0;
  /* Check for the authorization section, but only if is there completely. */
  if (!(packet->flags & SSH_DNS_FLAG_TRUNCATED) ||
      packet->additional_count != 0)
    {
      for(i = 0; i < packet->authority_count; i++)
        {
          if (packet->authority_array[i].type == SSH_DNS_RESOURCE_SOA &&
              packet->authority_array[i].dns_class == SSH_DNS_CLASS_INTERNET)
            soa_in_authority = i;
          if (packet->authority_array[i].type == SSH_DNS_RESOURCE_NS &&
              packet->authority_array[i].dns_class == SSH_DNS_CLASS_INTERNET)
            ns_records++;
        }
    }

  /* Lets put the answer section to the rrset cache if it is complete. */
  if (!(packet->flags & SSH_DNS_FLAG_TRUNCATED) ||
      packet->authority_count != 0 ||
      packet->additional_count != 0)
    {
      ssh_dns_resolver_add_rrsets(resolver, operation->ns_rrset,
                                  operation->name, packet->answer_count,
                                  packet->answer_array,
                                  packet->flags & SSH_DNS_FLAG_AUTHORITATIVE);
    }

  /* Then check the authority section and put it to the cache if it is
     complete. */
  if (!(packet->flags & SSH_DNS_FLAG_TRUNCATED) ||
      packet->additional_count != 0)
    {
      ssh_dns_resolver_add_rrsets(resolver, operation->ns_rrset,
                                  operation->name, packet->authority_count,
                                  packet->authority_array,
                                  FALSE);
    }

  /* Finally check the additional section and put it to the cache if it is
     complete. */
  if (!(packet->flags & SSH_DNS_FLAG_TRUNCATED))
    {
      ssh_dns_resolver_add_rrsets(resolver, operation->ns_rrset,
                                  operation->name, packet->additional_count,
                                  packet->additional_array,
                                  FALSE);
    }

  /* Then lets check for the non-existing domains. */
  if (packet->response_code == SSH_DNS_NONEXISTENT_DOMAIN)
    {
      unsigned char *non_existent_name;

      if (packet->flags & SSH_DNS_FLAG_TRUNCATED)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Non existing domain, but truncated"));
          goto remove_name_server;
        }
      if (packet->flags & SSH_DNS_FLAG_AUTHORITATIVE)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Non existing domain and authorative, accepted"));
        }

      if (soa_in_authority == -1)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Non existing domain, but no SOA"));
          goto remove_name_server;
        }

      /* Check for which name the error is, is it for the name we are searching
         for or the cname? */
      /* Assume the name we are searching for first. */
      non_existent_name = operation->name;
      /* Check if we have CNAME answer (and we are not searching for the
         cname). */
      if (operation->type != SSH_DNS_RESOURCE_CNAME)
        {
          for(i = 0; i < packet->answer_count; i++)
            {
              if (packet->answer_array[i].type == SSH_DNS_RESOURCE_CNAME &&
                  packet->answer_array[i].dns_class ==
                  SSH_DNS_CLASS_INTERNET &&
                  ssh_ustrcasecmp(packet->answer_array[i].name,
                                  operation->name)
                  == 0)
                {
                  SSH_DEBUG(SSH_D_MIDOK, ("Non existent domain, Found cname"));
                  /* There was CNAME in the NONEXISTENT DOMAIN error answer
                     section.
                     That means that the NONEXISTENT DOMAIN is for the name
                     CNAME pointed to not to the data we are searching for
                     (there was the CNAME record). */
                  non_existent_name = packet->answer_array[i].rdata;
                  break;
                }
            }
          /* No cnames found. */
        }

      /* Check that SOA is for the ancestor of the the non existent domain. */
      if (!ssh_dns_resolver_is_subdomain(non_existent_name,
                                         packet->
                                         authority_array[soa_in_authority].
                                         name))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Non existing domain, but with wrong SOA"));
          goto remove_name_server;
        }

      SSH_DEBUG(SSH_D_MIDOK, ("Authorative non existing domain"));
      /* Seems to be valid negative answer, cache the NODATA status, and return
         it to the upper layer. Note, that we put this in the cache using
         wildcard type, so it will be found anyways. */
      rrset = ssh_dns_rrset_cache_add(resolver->rrset_cache,
                                      non_existent_name,
                                      SSH_DNS_RRSET_NODATA,
                                      SSH_DNS_QUERY_ANY,
                                      resolver->negative_cache_ttl,
                                      0, NULL, NULL, operation->ns_rrset);
      if (rrset == NULL)
        goto memory_error;
      goto finish;
    }

  /* Check if we have meaning full authorization data. */
  if ((packet->flags & SSH_DNS_FLAG_TRUNCATED) &&
      !(packet->flags & SSH_DNS_FLAG_AUTHORITATIVE) &&
      packet->additional_count == 0)
    {
      /* No, it is truncated, and as this is not an authorative packet. */
      if (operation->flags & SSH_DNS_RESOLVER_USE_TCP)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Truncated authorization section in non authorative "
                     "packet, and already using TCP"));
          goto remove_name_server;
        }
      else
        {
          /* Enable TCP, and try again. */
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Truncated packet, enabling TCP and trying again"));
          operation->flags |= SSH_DNS_RESOLVER_USE_TCP;
          goto exit;
        }
    }

  /* Check if it is answer with zero address sets. */
  if (((packet->answer_count == 0 &&
        (packet->flags & SSH_DNS_FLAG_AUTHORITATIVE)) ||
       ((operation->flags & SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE) &&
        ns_records == 0)) &&
       soa_in_authority != -1)
    {
      if (!ssh_dns_resolver_is_subdomain(operation->name,
                                         packet->
                                         authority_array[soa_in_authority].
                                         name))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("No data records, but with wrong SOA"));
          goto remove_name_server;
        }

      /* This is authorative answer, of no rrsets. */
      SSH_DEBUG(SSH_D_MIDOK, ("Authorative answer with no records"));
      rrset = ssh_dns_rrset_cache_add(resolver->rrset_cache,
                                      operation->name,
                                      (packet->flags &
                                       SSH_DNS_FLAG_AUTHORITATIVE) ?
                                      SSH_DNS_RRSET_AUTHORATIVE :
                                      SSH_DNS_RRSET_NON_AUTHORATIVE,
                                      operation->type,
                                      resolver->negative_cache_ttl,
                                      0, NULL, NULL, operation->ns_rrset);
      if (rrset == NULL)
        goto memory_error;
      goto finish;
    }


  /* First check if we have CNAME answer (and we are not searching for the
     cname). */
  if (packet->answer_count != 0 && operation->type != SSH_DNS_RESOURCE_CNAME)
    {
      for(i = 0; i < packet->answer_count; i++)
        {
          if (packet->answer_array[i].type == SSH_DNS_RESOURCE_CNAME &&
              packet->answer_array[i].dns_class ==
              SSH_DNS_CLASS_INTERNET &&
              ssh_ustrcasecmp(packet->answer_array[i].name,
                              operation->name) == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Found cname"));
              /* Check if it is authorative. */
              if ((packet->flags & SSH_DNS_FLAG_AUTHORITATIVE) ||
                  (operation->flags & SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE))
                {
                  /* Now we need to remove the IN_PROGRESS marker for the old
                     name before we follow the CNAME. */
                  ssh_dns_rrset_cache_remove(resolver->rrset_cache,
                                             operation->name,
                                             operation->type);
                  if (ssh_dns_resolver_follow_cname(operation,
                                                    packet->
                                                    answer_array[i].name))
                    {
                      /* Success. */
                      ssh_fsm_set_next(operation->thread,
                                       ssh_dns_resolver_check_if_in_cache);
                    }
                  goto exit;
                }
              else
                {
                  /* It is not authorative. Only way to get the authorative
                     CNAME might be to ask for it specifically. */
                  if (operation->cname_count-- <= 0)
                    {
                      SSH_DEBUG(SSH_D_MIDOK, ("Cname loop, return error"));
                      /* Cname_count limit exceeded, abort. */
                      ssh_fsm_set_next(operation->thread,
                                       ssh_dns_resolver_limit_reached);
                      goto exit;
                    }
                  ssh_fsm_set_next(operation->thread,
                                   ssh_dns_resolver_find_cname);
                  goto exit;
                }
            }
          /* Not a cname, so do normal processing. */
        }
    }

  /* Check for truncated answers. */
  if ((packet->flags & SSH_DNS_FLAG_TRUNCATED) &&
      packet->answer_count == 0 &&
      packet->authority_count == 0 &&
      packet->additional_count == 0)
    {
      /* The answer was truncated and was not put to the
         cache. Fall back to TCP. Some nameserver seems to
         return truncated answer even when answer would have
         been very short. */
      if (operation->flags & SSH_DNS_RESOLVER_USE_TCP)
        {
          /* We were already using the TCP, return error. */
          ssh_dns_resolver_call_callback(operation,
                                         SSH_DNS_SERVER_FAILURE,
                                         NULL);
          ssh_fsm_set_next(operation->thread, ssh_dns_resolver_finish);
        }
      else
        {
          /* Enable TCP, and try again. */
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Truncated packet, enabling TCP and trying again"));
          operation->flags |= SSH_DNS_RESOLVER_USE_TCP;
        }
      goto exit;
    }

  /* Lets see if this is authorative answer. */
  if (packet->answer_count != 0 &&
      ((packet->flags & SSH_DNS_FLAG_AUTHORITATIVE) ||
       (operation->flags & SSH_DNS_RESOLVER_ALLOW_NON_AUTHORATIVE)))
    {
      /* Yes, it is answer, we should have answer section which matches
         our query. */
      /* Check for truncated answers. */
      if ((packet->flags & SSH_DNS_FLAG_TRUNCATED) &&
          packet->authority_count == 0 &&
          packet->additional_count == 0)
        {
          /* The answer was truncated and was not put to the
             cache. As this is the authorative name server
             there is no other option than to fall back to
             TCP. */

          if (operation->flags & SSH_DNS_RESOLVER_USE_TCP)
            {
              /* We were already using the TCP, return error. */
              ssh_dns_resolver_call_callback(operation,
                                             SSH_DNS_SERVER_FAILURE,
                                             NULL);
              ssh_fsm_set_next(operation->thread, ssh_dns_resolver_finish);
            }
          else
            {
              /* Enable TCP, and try again. */
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Truncated packet, enabling TCP and trying again"));
              operation->flags |= SSH_DNS_RESOLVER_USE_TCP;
            }
          goto exit;
        }

      /* As we already put it in the cache earlier, we can search it
         now from the cache. */
      rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                      operation->name,
                                      operation->type);
      SSH_DEBUG(SSH_D_MIDOK, ("Found answer, return it %@",
                              ssh_dns_rrset_render, rrset));
      if (rrset == NULL)
        {
          /* We did got authorative answer, the rrset should not be null,
             unless there was memory error when we saved the data to the
             cache. Lets return memory error in this case. */
          goto memory_error;
        }
      /* Ok, we now have answer, return it. */
      goto finish;
    }

  /* So this was referreal, but first check if this referral
     is trying to make referral to ourselves, and if so mark
     this name server as bad, and try others. */
  for(i = 0; i < packet->authority_count; i++)
    {
      if (packet->authority_array[i].type == SSH_DNS_RESOURCE_NS &&
          packet->authority_array[i].dns_class == SSH_DNS_CLASS_INTERNET &&
          ssh_ustrcasecmp(packet->authority_array[i].rdata,
                     name_server->name_server) == 0)
        {
          /* Yes, didn't send authorative answer, but it
             claims to be one of the name servers, remove it
             from the list. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Got referral where %@ is trying to say it is "
                     "authorative name server for %@, but when asking it "
                     "it didn't return authorative answer.",
                     ssh_dns_name_render, name_server->name_server,
                     ssh_dns_name_render, operation->name));
          goto remove_name_server;
        }
    }

  /* So it was not authorative, it must be referral. The
     information has already been inserted to the cache, so
     we can simply find the cache again, and see if we can
     see longer match than previous time. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Got referral, try to from the ancestor search again "));
  ssh_fsm_set_next(operation->thread, ssh_dns_resolver_find_ancestor);

 exit:                          /* Free data, and continue */
  if (packet)
    ssh_dns_packet_free(packet);
  SSH_FSM_CONTINUE_AFTER_CALLBACK(operation->thread);
  return;

 memory_error:                  /* Continue to memory error state. */
  ssh_fsm_set_next(operation->thread, ssh_dns_resolver_memory_error);
  goto exit;

 finish:                        /* Call callback and finish */
  /* The rrset is already locked, either by add or by get. */
  ssh_dns_resolver_call_callback(operation, error, rrset);
  /* Unlock the reference. */
  if (rrset)
    ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);
  ssh_fsm_set_next(operation->thread, ssh_dns_resolver_finish);
  goto exit;
}

SshDNSRRset ssh_dns_rrset_add_in_progress(SshDNSResolver resolver,
                                          SshDNSResolverOp operation)
{
  SshDNSRRset rrset;
  size_t len;
  unsigned char data[4], *ptr;
  SSH_DEBUG(SSH_D_LOWOK, ("Add in progress item"));
  /* Make in progress entry to the cache, while we are fetching the
     data. Store the pointer to the operation_count to the data, so
     if we ever get same data when finding this, we know this is deadlock
     (i.e the same parent operation is doing this operation). */
  len = 4;
  SSH_PUT_32BIT(data, (unsigned long) operation->operation_count);
  ptr = data;
  rrset = ssh_dns_rrset_cache_add(resolver->rrset_cache,
                                  operation->name,
                                  SSH_DNS_RRSET_IN_PROGRESS,
                                  operation->type,
                                  operation->timeout_time,
                                  1, &len, &ptr,
                                  NULL);
  return rrset;
}

/* Find the next name server from the current one. */
SSH_FSM_STEP(ssh_dns_resolver_find_next_step)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;
  SshDNSPacket dns_packet;
  unsigned char *packet;
  int packet_length;
  SshDNSRRset rrset;

  SSH_DEBUG(SSH_D_LOWOK, ("Do the search"));
  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  packet = ssh_malloc(SSH_DNS_MAX_PACKET_SIZE);
  if (packet == NULL)
    {
      SSH_FSM_SET_NEXT(ssh_dns_resolver_memory_error);
      return SSH_FSM_CONTINUE;
    }

  dns_packet = ssh_dns_packet_allocate(1, 0, 0, 0);
  if (dns_packet == NULL)
    {
      ssh_free(packet);
      SSH_FSM_SET_NEXT(ssh_dns_resolver_memory_error);
      return SSH_FSM_CONTINUE;
    }

  /* The name is static, so we can simply use that, no need to copy it. */
  dns_packet->question_array[0].qname = operation->name;
  dns_packet->question_array[0].qtype = operation->type;
  dns_packet->question_array[0].qclass = SSH_DNS_CLASS_INTERNET;

  if (operation->flags & SSH_DNS_RESOLVER_RECURSIVE_REQUEST)
    dns_packet->flags |= SSH_DNS_FLAG_RECURSION_DESIRED;

  SSH_DEBUG(SSH_D_MIDOK, ("Sending query: %.*@",
                          ssh_dns_debug_pretty_print,
                          ssh_dns_packet_render, dns_packet));

  packet_length = ssh_dns_packet_encode(dns_packet, packet,
                                        SSH_DNS_MAX_PACKET_SIZE);
  ssh_dns_packet_free(dns_packet);

  if (packet_length < 0)
    {
      /* Didn't fit to the SSH_DNS_MAX_PACKET_SIZE buffer, something wrong,
         abort the query. */
      ssh_free(packet);
      ssh_dns_resolver_call_callback(operation, SSH_DNS_INTERNAL_ERROR, NULL);
      SSH_FSM_SET_NEXT(ssh_dns_resolver_finish);
      return SSH_FSM_CONTINUE;
    }

  rrset = ssh_dns_rrset_cache_get(resolver->rrset_cache,
                                  operation->name,
                                  operation->type);
  /* Remove it from cache if it was expired. */
  rrset = ssh_dns_resolver_remove_if_expired(resolver, rrset);

  if (rrset == NULL)
    {
      rrset = ssh_dns_rrset_add_in_progress(resolver, operation);
    }
  if (rrset)
    ssh_dns_rrset_cache_unlock(resolver->rrset_cache, rrset);

  /* We do not really care whether it succeeded or not, if we get answer back
     we will overwrite it, if we do not get answer back, then we will clear
     this out before we return (i.e. replace it with FAILURE). */

  SSH_DEBUG(SSH_D_LOWOK, ("Do the query"));
  SSH_FSM_ASYNC_CALL(
     operation->handle =
     ssh_dns_query_layer_query(resolver->query_layer,
                               operation->name_servers_count,
                               operation->name_servers,
                               packet,
                               packet_length,
                               operation->timeout_time / 2,
                               (operation->flags & SSH_DNS_RESOLVER_USE_TCP) ?
                               SSH_DNS_FLAGS_QUERY_USE_TCP : 0,
                               ssh_dns_resolver_query_cb,
                               operation);
     ssh_free(packet);
     );
}

/* CNAME query is ready. If we did get success, then continue, otherwise return
   error. */
void ssh_dns_resolver_find_cname_cb(SshDNSResponseCode error,
                                    SshDNSRRset rrset,
                                    void *context)
{
  SshDNSResolverOp operation = context;
  SshDNSResolver resolver;

  SSH_DEBUG(SSH_D_MIDOK, ("Result callback from CNAME %s (%d)",
                          ssh_dns_response_code_string(error), error));
  resolver = ssh_fsm_get_gdata(operation->thread);
  operation->handle = NULL;
  if (error != SSH_DNS_OK || rrset == NULL)
    {
      /* Error. */
      ssh_dns_resolver_call_callback(operation, error, rrset);
      ssh_fsm_set_next(operation->thread, ssh_dns_resolver_finish);
    }
  else
    {
      ssh_dns_rrset_cache_remove(resolver->rrset_cache,
                                 operation->name,
                                 operation->type);
      /* CNAME worked, now we should follow it. */
      if (ssh_dns_resolver_follow_cname(operation,
                                        rrset->array_of_rdata[0]))
        {
          /* Success. */
          /* As we might have fetched the cname from sbelt, we should
             clear that flag now, so in case we need to do future
             searches, we might end up going back to sbelt. */
          operation->restarted_from_sbelt = FALSE;
          ssh_fsm_set_next(operation->thread,
                           ssh_dns_resolver_check_if_in_cache);
        }
      /* In failure case the next step is already set. */
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(operation->thread);
}

/* Find CNAME record of name. */
SSH_FSM_STEP(ssh_dns_resolver_find_cname)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;

  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Fetch CNAME of %@", ssh_dns_name_render, operation->name));

  /* Try to fetch CNAME record this name. This is needed as if we search for
     the A record, the caching server can return CNAME and then the referrals
     are only for the name CNAME pointed to not to the CNAME itself, and we
     cannot get authorative answer from those name servers for the name
     itself. */
  SSH_FSM_ASYNC_CALL(
        operation->handle =
        ssh_dns_resolver_find_internal(resolver, operation->name,
                                       SSH_DNS_RESOURCE_CNAME,
                                       operation->timeout_time,
                                       operation->flags,
                                       ssh_dns_resolver_find_cname_cb,
                                       operation, operation);
        );
}

/* Query is ready. If we did get success, then continue, otherwise
   return error. */
void ssh_dns_resolver_find_from_root_cb(SshDNSResponseCode error,
                                     SshDNSRRset rrset,
                                     void *context)
{
  SshDNSResolverOp operation = context;

  SSH_DEBUG(SSH_D_MIDOK, ("Result callback from parent %s (%d)",
                          ssh_dns_response_code_string(error), error));
  operation->handle = NULL;
  if (error != SSH_DNS_OK || rrset == NULL)
    {
      ssh_dns_resolver_call_callback(operation, error, rrset);
      ssh_fsm_set_next(operation->thread, ssh_dns_resolver_finish);
    }
  else
    {
      /* Get next token. */
      operation->name_server_index--;
    }
  SSH_FSM_CONTINUE_AFTER_CALLBACK(operation->thread);
}

/* Find next NS record of the parent, starting from the root. */
SSH_FSM_STEP(ssh_dns_resolver_find_from_root_next)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;
  unsigned char *name;
  SshUInt32 tokens;

  if (operation->name_server_index == 0)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("We are done, returning"));
      /* We are done, now we can go back to the real work. */
      ssh_fsm_set_next(operation->thread, ssh_dns_resolver_find_ancestor);
    }

  tokens = 0;
  name = operation->name;
  while (tokens < operation->name_server_index)
    {
      name += *name + 1;
      tokens++;
    }

  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Fetch parent domain %@", ssh_dns_name_render, name));

  /* Try to fetch NS record this name server. The real reason for this is to
     fetch anything from the parent domain, and that will force the parent
     domain NS records to cache along with the IP addresses. This should work,
     as the parent domain is already in the dns. */
  SSH_FSM_ASYNC_CALL(
        operation->handle =
        ssh_dns_resolver_find_internal(resolver, name,
                                       SSH_DNS_RESOURCE_NS,
                                       operation->timeout_time,
                                       operation->flags |
                                       SSH_DNS_RESOLVER_IGNORE_CACHE |
                                       SSH_DNS_RESOLVER_START_FROM_SBELT,
                                       ssh_dns_resolver_find_from_root_cb,
                                       operation, operation);
        );
}


/* Find the NS record of the parent, starting from the root. */
SSH_FSM_STEP(ssh_dns_resolver_find_from_root)
{
  SshDNSResolverOp operation = thread_context;
  unsigned char *name;
  SshUInt32 tokens;

  tokens = 0;
  name = operation->name;
  while (*name != 0)
    {
      name += *name + 1;
      tokens++;
    }
  SSH_DEBUG(SSH_D_MIDOK, ("Start searching skipping %d tokens of %@",
                          (int) tokens,
                          ssh_dns_name_render, operation->name));

  operation->name_server_index = tokens;
  SSH_FSM_SET_NEXT(ssh_dns_resolver_find_from_root_next);
  return SSH_FSM_CONTINUE;
}

/* Find the name server IP address. */
SSH_FSM_STEP(ssh_dns_resolver_fetch_nameservers_start)
{
  SshDNSResolverOp operation = thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Start searching for name server IPs"));
  operation->name_server_index = 0;
  SSH_FSM_SET_NEXT(ssh_dns_resolver_fetch_nameservers);
  return SSH_FSM_CONTINUE;
}

/* IPv6 query is ready, insert data to name server cache. */
void ssh_dns_resolver_fetch_nameserver_ipv6(SshDNSResponseCode error,
                                            SshDNSRRset rrset,
                                            void *context)
{
  SshDNSResolverOp operation = context;

  SSH_DEBUG(SSH_D_LOWOK, ("AAAA result callback"));
  operation->handle = NULL;
  operation->name_server_index++;
  SSH_FSM_CONTINUE_AFTER_CALLBACK(operation->thread);
}

/* IPv4 query is ready, start IPv6 query. */
void ssh_dns_resolver_fetch_nameserver_ipv4(SshDNSResponseCode error,
                                            SshDNSRRset rrset,
                                            void *context)
{
  SshDNSResolverOp operation = context;
  SshDNSResolver resolver;

  SSH_DEBUG(SSH_D_LOWOK, ("A result callback"));
  /* The data is already in the cache, ignore the rrset, and error code, we
     simply continue searching for the IPv6 address. */
  resolver = ssh_fsm_get_gdata(operation->thread);

  operation->handle =
    ssh_dns_resolver_find_internal(resolver,
                                   operation->ns_rrset->
                                   array_of_rdata[operation->
                                                 name_server_index],
                                   SSH_DNS_RESOURCE_AAAA,
                                   operation->timeout_time,
                                   operation->flags,
                                   ssh_dns_resolver_fetch_nameserver_ipv6,
                                   operation, operation);
}

/* Find the name server IP address. */
SSH_FSM_STEP(ssh_dns_resolver_fetch_nameservers)
{
  SshDNSResolverOp operation = thread_context;
  SshDNSResolver resolver = fsm_context;

  SSH_DNS_RESOLVER_OPERATION_COUNT(operation);

  if (operation->name_server_index >= operation->name_servers_count
      || operation->ns_rrset == NULL)
    {
      /* We have tried each name server, see if we did find anything useful. */
      SSH_DEBUG(SSH_D_LOWOK, ("Didn't find any more IPs"));
      SSH_FSM_SET_NEXT(ssh_dns_resolver_fetch_nameservers_end);
      return SSH_FSM_CONTINUE;
    }
  SSH_DEBUG(SSH_D_MIDOK, ("Fetch name server %d %@",
                          operation->name_server_index,
                          ssh_dns_name_render,
                          operation->ns_rrset->
                          array_of_rdata[operation->
                                        name_server_index]));

  /* Try to fetch IPv4 and IPv6 for this name server. */
  SSH_FSM_ASYNC_CALL(
     operation->handle =
     ssh_dns_resolver_find_internal(resolver,
                                    operation->ns_rrset->
                                    array_of_rdata[operation->
                                                  name_server_index],
                                    SSH_DNS_RESOURCE_A,
                                    operation->timeout_time,
                                    operation->flags,
                                    ssh_dns_resolver_fetch_nameserver_ipv4,
                                    operation, operation);
     );
}

SSH_FSM_STEP(ssh_dns_resolver_fetch_nameservers_end)
{
  SshDNSResolverOp operation = thread_context;
  int ns_cnt;

  SSH_DEBUG(SSH_D_LOWOK, ("Name server IP end"));

  ns_cnt = ssh_dns_resolver_fill_name_servers(operation);

  if (ns_cnt == 0)
    {
      /* No more name servers, try to restart from the sbelt. */
      SSH_DEBUG(SSH_D_MIDOK,
                ("Didn't find any useful IPs, try from safety belt"));
      SSH_FSM_SET_NEXT(ssh_dns_resolver_set_sbelt);
      return SSH_FSM_CONTINUE;
    }
  /* Found at least one name server, try again. */
  SSH_DEBUG(SSH_D_LOWOK, ("Did find at least one name server, continue"));
  SSH_FSM_SET_NEXT(ssh_dns_resolver_find_next_step);
  return SSH_FSM_CONTINUE;
}

/* Out of memory error. */
SSH_FSM_STEP(ssh_dns_resolver_memory_error)
{
  SshDNSResolverOp operation = thread_context;

  SSH_DEBUG(SSH_D_FAIL, ("Out of memory"));
  ssh_dns_resolver_call_callback(operation, SSH_DNS_MEMORY_ERROR, NULL);
  SSH_FSM_SET_NEXT(ssh_dns_resolver_finish);
  return SSH_FSM_CONTINUE;
}

/* Operation count has been reached, return error and finish. */
SSH_FSM_STEP(ssh_dns_resolver_limit_reached)
{
  SshDNSResolverOp operation = thread_context;

  SSH_DEBUG(SSH_D_FAIL, ("Limit reached"));
  ssh_dns_resolver_call_callback(operation, SSH_DNS_LIMIT_REACHED, NULL);
  SSH_FSM_SET_NEXT(ssh_dns_resolver_finish);
  return SSH_FSM_CONTINUE;
}

/* Free the operation and finish the thread. The callback is already called at
   this point. */
SSH_FSM_STEP(ssh_dns_resolver_finish)
{
  SshDNSResolverOp operation = thread_context;

  SSH_DEBUG(SSH_D_MIDOK, ("Operation finished"));
  /* Cancel timeout. */
  ssh_cancel_timeout(operation->timeout);
  /* Unregister the operation. */
  ssh_operation_unregister(operation->operation_handle);

  /* Destructor will take care of the memory cleanup. */
  return SSH_FSM_FINISH;
}
