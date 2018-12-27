/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   An IP address pool.
*/

#include "sshincludes.h"
#include "ras_addrpool.h"
#include "ras_dhcp_addrpool.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmRemoteAccessDhcpAddrpool"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED


/************************** Types and definitions ***************************/
/* List of DHCP options per message. All message types should be configured,
   if standard defined default values are not used. */
static const unsigned char
dhcp_addresspool_dhcp_options_discover[] = {

  /* DHCPDISCOVERY */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcp_options_offer[] = {
  /* DHCPOFFER */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME,
  SSH_DHCP_OPTION_SUBNET_MASK,
  SSH_DHCP_OPTION_DOMAIN_NAME_SERVERS,
  SSH_DHCP_OPTION_NETBIOS_NAME_SERVERS,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcp_options_request[] = {
  /* DHCPREQUEST (initial) */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcp_options_decline[] = {
  /* DHCPDECLINE */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS,
  SSH_DHCP_OPTION_DHCP_MESSAGE,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcp_options_ack[] = {
  /* DHCPACK */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_SUBNET_MASK,
  SSH_DHCP_OPTION_DOMAIN_NAME_SERVERS,
  SSH_DHCP_OPTION_NETBIOS_NAME_SERVERS,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcp_options_nak[] = {
  /* DHCPNAK */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_MESSAGE,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcp_options_release[] = {
  /* DHCPRELEASE */
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER,
  SSH_DHCP_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcpv6_options_solicit[] = {
  /* DHCPV6_SOLICIT */
  SSH_DHCPV6_OPTION_RAPID_COMMIT,
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_ELAPSED_TIME,
  SSH_DHCPV6_OPTION_ORO,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcpv6_options_reply[] = {
  /* DHCPV6_REPLY */
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_IAADDR,
  SSH_DHCPV6_OPTION_RAPID_COMMIT,
  SSH_DHCPV6_OPTION_STATUS_CODE,
  SSH_DHCPV6_OPTION_DNS_SERVERS,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcpv6_options_decline[] = {
  /* DHCPV6_DECLINE */
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_IAADDR,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcpv6_options_renew[] = {
  /* DHCPV6_RELEASE */
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_IAADDR,
  SSH_DHCPV6_OPTION_ORO,
  SSH_DHCPV6_OPTION_END
};

static const unsigned char
dhcp_addresspool_dhcpv6_options_release[] = {
  /* DHCPV6_RELEASE */
  SSH_DHCPV6_OPTION_CLIENTID,
  SSH_DHCPV6_OPTION_SERVERID,
  SSH_DHCPV6_OPTION_IA_NA,
  SSH_DHCPV6_OPTION_IAADDR,
  SSH_DHCPV6_OPTION_END
};

/* Allocated address pointer, to be stored for address sanity check purposes */
typedef struct SshPmDhcpAddressPoolAllocListRec
{
  /* Allocated IP address  */
  SshIpAddrStruct addr;
  SshUInt32 reference_count;

  struct SshPmDhcpAddressPoolAllocListRec *hash_next;
} *SshPmDhcpAddressPoolAllocList, SshPmDhcpAddressPoolAllocListStruct;

/* Definition of an address pool object. */
typedef struct SshPmDhcpAddressPoolInternalRec
{
  /* Common part */
  SshPmAddressPoolStruct ap[1];

  /* Local IP address. */
  SshIpAddrStruct own_ip_addr;
  SshUInt16 own_listening_port;
  SshUInt16 own_private_port;

  /* Configured DHCP servers */
  SshUInt32 num_dhcps;
  struct {
    SshIpAddrStruct dhcp_ip;
    SshUInt16 dhcp_port;
  }dhcp[SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT];

  /* Hash table of the allocated IP addresses. */
  SshUInt32 num_allocated;
  SshPmDhcpAddressPoolAllocList allocated_hash_table[SSH_DHCP_ALLOC_MAX];

  /* Statistics */
  SshUInt32 total_num_allocated;
  SshUInt32 addresses_freed;
  SshUInt32 failed_allocations;

  /* Number of contexts refering to this address pool. */
  SshUInt32 reference_count;

  /* DHCP library fsm */
  SshFSM fsm;

} *SshPmDhcpAddressPoolInternal;

/* Context structure for remote access attribute allocation state machine. */
typedef struct SshPmRasDhcpAllocCtxRec
{
  /* Result callback and context. */
  SshPmRemoteAccessAttrsAllocResultCB result_cb;
  void *result_cb_context;

  /* Abort callback. */
  SshOperationHandleStruct operation;

  /* The index of the address pool. */
  SshUInt32 ap_id_index;

  /* The address pool id of the current address pool. */
  SshPmAddrPoolId id;

  /* Address pool structure related to this context */
  SshPmDhcpAddressPoolInternal addrpool;

  /* Requested attributes */
  SshPmRemoteAccessAttrs attrs;

  /* Parameters and info that are passed to the DHCP library. These must be
     stored with the tunnel to be accessible for subsequent library calls. */
  SshDHCPParams dhcp_params;

  /* DHCP library fsm context */
  SshDHCP dhcp;

  /* Flags */
  unsigned int declining : 1;
  unsigned int renewal : 1;

} *SshPmRasDhcpAllocCtx;

#define SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE        1
#define SSH_PM_RAS_DHCP_PARAMS_FLAG_DESTROYED    2

/*************************** Private functions *******************************/

/******************* Allocated addresses hash table handling *****************/

#define RAS_DHCP_ALLOC_HASH(ip) \
  ((ip) + 3 * ((ip) >> 8) + 7 * ((ip) >> 16) + 11 * ((ip) >> 24))

static SshUInt32
dhcp_address_pool_alloc_ptr_hash(SshIpAddr addr)
{
  SshUInt32 hash = 0;
  SshUInt32 mask = SSH_DHCP_ALLOC_MAX - 1;
  SshUInt32 tmp  = 0;
  SshUInt32 ip   = 0;

  if (SSH_IP_IS6(addr))
    {
      ip  = SSH_IP6_WORD0_TO_INT(addr);
      ip ^= SSH_IP6_WORD1_TO_INT(addr);
    }
  else if (SSH_IP_IS4(addr))
    {
      ip = SSH_IP4_TO_INT(addr);
    }

  tmp = ip;
  hash = RAS_DHCP_ALLOC_HASH(tmp);
  hash = hash & mask;

  return hash;
}

static SshPmDhcpAddressPoolAllocList
dhcp_address_pool_alloc_list_ptr_alloc(SshIpAddr addr)
{
  SshPmDhcpAddressPoolAllocList ptr = NULL;

  ptr = ssh_calloc(1, sizeof(SshPmDhcpAddressPoolAllocListStruct));
  if (ptr   == NULL)
    return NULL;

  memcpy(&ptr->addr, addr, sizeof(SshIpAddrStruct));
  ptr->hash_next = NULL;

  return ptr;
}

static void
dhcp_address_pool_alloc_list_add_reference(SshPmDhcpAddressPoolAllocList elem)
{
  if (elem == NULL)
    return;

  elem->reference_count++;
}

static SshUInt32
dhcp_address_pool_alloc_list_remove_reference(
                                           SshPmDhcpAddressPoolAllocList elem)
{
  if (elem == NULL)
    return 0;

  if (elem->reference_count > 0)
    elem->reference_count--;
  return elem->reference_count;
}

static SshPmDhcpAddressPoolAllocList
dhcp_address_pool_alloc_list_add(SshPmDhcpAddressPoolInternal ap,
                                 SshIpAddr addr)
{
  SshUInt32 hash                           = 0;
  SshPmDhcpAddressPoolAllocList alloc_ptr  = NULL;
  SshPmDhcpAddressPoolAllocList current    = NULL;
  SshPmDhcpAddressPoolAllocList prev       = NULL;

  if (addr == NULL)
    return NULL;

  alloc_ptr = dhcp_address_pool_alloc_list_ptr_alloc(addr);
  if (alloc_ptr == NULL)
    return NULL;
  alloc_ptr->reference_count++;

  hash = dhcp_address_pool_alloc_ptr_hash(addr);
  if (ap->allocated_hash_table[hash] == NULL)
    {
      ap->allocated_hash_table[hash] = alloc_ptr;
      return alloc_ptr;
    }

  current = ap->allocated_hash_table[hash];
  while (current != NULL)
    {
      prev = current;
      current = current->hash_next;
    }

  prev->hash_next = alloc_ptr;

  return alloc_ptr;
}

static SshPmDhcpAddressPoolAllocList
dhcp_address_pool_alloc_list_find(
                        SshPmDhcpAddressPoolAllocList allocated_hash_table[],
                        SshIpAddr addr)
{
  SshUInt32 hash                          = 0;
  SshPmDhcpAddressPoolAllocList alloc_ptr = NULL;

  if (addr == NULL)
    return NULL;

  hash = dhcp_address_pool_alloc_ptr_hash(addr);
  alloc_ptr = allocated_hash_table[hash];

  while (alloc_ptr != NULL)
    {
      if (SSH_IP_CMP(addr, &alloc_ptr->addr) == 0)
        break;
      alloc_ptr = alloc_ptr->hash_next;
    }

  return alloc_ptr;
}

static SshUInt32
dhcp_address_pool_alloc_list_remove(SshPmDhcpAddressPoolInternal ap,
                                    SshIpAddr addr)
{
  SshUInt32 hash                     = 0;
  SshPmDhcpAddressPoolAllocList curr = NULL;
  SshPmDhcpAddressPoolAllocList prev = NULL;
  SshUInt32 refcount                 = 0;

  if (addr == NULL)
    return 0;

  hash = dhcp_address_pool_alloc_ptr_hash(addr);
  curr = ap->allocated_hash_table[hash];

  while (curr != NULL)
    {
      if (SSH_IP_CMP(addr, &curr->addr) == 0)
        break;
      prev = curr;
      curr = curr->hash_next;
    }

  if (curr)
    {
      if ((refcount = dhcp_address_pool_alloc_list_remove_reference(curr)) > 0)
        return refcount;
      if (curr == ap->allocated_hash_table[hash])
        ap->allocated_hash_table[hash] = curr->hash_next;
      else if (prev)
        prev->hash_next = curr->hash_next;

      ssh_free(curr);
    }
  return 0;
}

/* ******************* Deleting address pool context *************************/
static void
dhcp_address_pool_free_params(SshDHCPParams params)
{
  int i = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Freeing DHCP parameters."));

  if (params != NULL)
    {
      if (params->info != NULL)
        ssh_dhcp_free_info(params->info);

      ssh_free(params->local_ip);

      for (i = 0; i < SSH_DHCP_MAX_SUPPORTED_SERVERS; i++)
          ssh_free(params->dhcp_servers[i].remote_ip);

      ssh_free(params->gateway);
      ssh_free(params->client_identifier);
      ssh_free(params->vendor_id);
      ssh_free(params->options);
      ssh_free(params);
    }
}

static void
dhcp_address_pool_delete_context(void *context)
{
  SshPmRasDhcpAllocCtx ctx = (SshPmRasDhcpAllocCtx)context;
  SshPmDhcpAddressPoolInternal pool = NULL;

  SSH_DEBUG(SSH_D_MIDSTART, ("Deleting DHCP context."));
  if (ctx == NULL)
    return;

  /* Unregister abort, but only if it has not been done yet. */
  if (ctx->result_cb != NULL)
    ssh_operation_unregister(&ctx->operation);

  if (ctx->dhcp_params != NULL)
    dhcp_address_pool_free_params(ctx->dhcp_params);

  ssh_pm_free_remote_access_attrs(ctx->attrs);

  /* Decrease pool reference count, and check if the pool should be
     destroyed.*/
  pool = ctx->addrpool;
  SSH_ASSERT(pool != NULL && pool->reference_count > 0);

  pool->reference_count--;
  if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DESTROYED) != 0 &&
      pool->reference_count == 0)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Removing DHCP address pool."));
      ssh_free(pool->ap->address_pool_name);
      ssh_free(pool);
    }

  ssh_free(ctx);
}

/* ************ Tunnel abort callback ***************************************/
static void
dhcp_address_pool_abort_cb(void *context)
{
  SshPmRasDhcpAllocCtx ctx = (SshPmRasDhcpAllocCtx)context;

  SSH_DEBUG(SSH_D_MIDSTART, ("Tunnel setup aborted, declining DHCP offers."));
  ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_NOTICE,
                "DHCP address allocation mechanism aborted.");
  ctx->result_cb = NULL;
}

/* ************* DHCP library callbacks **************************************/
/* ************** Thread destructor callback *********************************/
static void
dhcp_address_pool_destructor_cb(SshDHCP dhcp,
                                const SshDHCPInformation info,
                                SshDHCPStatus status, void *context)
{
  SSH_DEBUG(SSH_D_MIDSTART, ("DHCP destructor."));

  if (dhcp != NULL)
    ssh_dhcp_free(dhcp);
}

/* **************** Address release callback *********************************/
static void
dhcp_address_pool_release_cb(SshDHCP dhcp,
                             const SshDHCPInformation info,
                             SshDHCPStatus status, void *context)
{
  SshPmRasDhcpAllocCtx ctx = (SshPmRasDhcpAllocCtx)context;

  SSH_DEBUG(SSH_D_MIDSTART, ("RELEASE callback."));
  dhcp_address_pool_delete_context(ctx);
}

/* **************** Address alloc/renew callback *****************************/
static void
dhcp_address_pool_alloc_callback(SshDHCP dhcp,
                                 const SshDHCPInformation info,
                                 SshDHCPStatus status,
                                 void *context)
{
  SshPmRemoteAccessAttrsStruct attrs;
  SshIpAddrStruct ip;
  SshPmDhcpAddressPoolInternal pool  = NULL;
  SshPmDhcpAddressPoolAllocList elem = NULL;
  SshPmRasDhcpAllocCtx ctx           = (SshPmRasDhcpAllocCtx)context;
  int i                              = 0;

  SSH_DEBUG(SSH_D_MIDSTART, ("Callback from the DHCP machine."));

  SSH_ASSERT(ctx != NULL);

  /* The address has been declined */
  if (ctx->declining)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Address from DHCP server has been declined."));
      goto fail;
    }

  if (info == NULL || info->my_ip == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Did not receive an IP address from DHCP server."));
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "DHCP address allocation failed.");
      goto fail;
    }

  /* The DHCP message sequence has finished without receiving an address. */
  if (status != SSH_DHCP_STATUS_OK && status != SSH_DHCP_STATUS_BOUND)
    {
      SSH_DEBUG(SSH_D_FAIL, ("DHCP operation failed, status %d.", status));
      if (ctx->renewal)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "DHCP lease renewal failed, tunnel torn down.");
      else
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "DHCP address allocation failed.");
      goto fail;
    }

  if (ctx->dhcp_params == NULL)
    goto fail;

  /* Check if the operation has been aborted. */
  if (ctx->result_cb == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Tunnel setup aborted, send release."));
      ctx->declining = 1;
      ssh_dhcp_release(dhcp);
      return;
    }

  /* Check that the lease is at least of requested length. */
  if (ctx->dhcp_params->requested_lease_time)
    {
      if (info->lease_time < ctx->dhcp_params->requested_lease_time)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Too short lease, sending release."));
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "DHCP server granted too short lease, releasing "
                        "address.");
          ctx->declining = 1;
          ssh_dhcp_release(dhcp);
          return;
        }
    }

  /* Check that the requested address was indeed received. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Received address %s from DHCP server.",
                               info->my_ip));
  if (info->netmask != NULL)
    ssh_ipaddr_parse_with_mask(&ip, info->my_ip, info->netmask);
  else
    ssh_ipaddr_parse(&ip, info->my_ip);
  if (ctx->renewal && ctx->attrs && ctx->attrs->num_addresses > 0 &&
      !SSH_IP_IS_NULLADDR(&ctx->attrs->addresses[0]))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Asked address `%@'",
                                   ssh_ipaddr_render,
                                   &ctx->attrs->addresses[0]));
      if (SSH_IP_CMP(&ctx->attrs->addresses[0], &ip) != 0)
        {
          SSH_DEBUG(SSH_D_ERROR,
                ("Requested and received addresses do not match."));
          goto fail;
        }
    }

  pool = ctx->addrpool;

  if (!ctx->renewal)
    {
      if ((elem = dhcp_address_pool_alloc_list_find(pool->allocated_hash_table,
                                                    &ip))
          != NULL)
        {
          dhcp_address_pool_alloc_list_add_reference(elem);

          /* If IP check option is in use, check the IP before accepting */
          if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_ALLOC_CHECK_ENABLED)
              != 0)
            {
              /* this address is in use, decline */
              SSH_DEBUG(SSH_D_ERROR,
                        ("IP address already in use, sending decline."));
              ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                            "IP address conflict: Address received from DHCP "
                            "server is already in use. Declining address.");
              ctx->declining = 1;

              info->failure_reason = ssh_buffer_allocate();
              if (info->failure_reason != NULL)
                ssh_buffer_append(info->failure_reason,
                                  "IP address already in use",
                                  strlen("IP address already in use"));

              ssh_dhcp_decline(dhcp);
              return;
            }
        }
      /* Fresh address, add to the list */
      else
        {
          dhcp_address_pool_alloc_list_add(pool, &ip);
        }
    }
  if (!ctx->renewal)
    {
      pool->num_allocated++;
      SSH_ADDRESS_POOL_UPDATE_STATS(pool->total_num_allocated);
    }

  /* Mark that DHCP params is no longer in use. */
  ctx->dhcp_params->context_flags &= ~SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE;

  /* Copy address in the attributes */
  memset(&attrs, 0, sizeof(SshPmRemoteAccessAttrsStruct));
  memcpy(&attrs.addresses[0], &ip, sizeof(SshIpAddrStruct));
  attrs.num_addresses = 1;

  /* Borrow Server id */
  if (info->server_duid != NULL && info->server_duid_len != 0)
    {
      attrs.server_duid = info->server_duid;
      attrs.server_duid_len = info->server_duid_len;
    }

  /* Lease renewal time to be passed in attributes. Normally, Phase-1 rekey
     should happen before this time has passed. */
  if (info->renew_timeout > 0 && info->renew_timeout < 0xffffffff)
    attrs.lease_renewal = info->renew_timeout + 10;

  /* DNS server address(es) added in attributes. */
  if (info->dns_ip_count > 0 && info->dns_ip != NULL)
    {
      for (i = 0; i < info->dns_ip_count; i++)
        {
          if (ssh_ipaddr_parse(&ip, info->dns_ip[i]) == FALSE)
            continue;
          if (!SSH_IP_IS_NULLADDR(&ip))
              memcpy(&attrs.dns[attrs.num_dns++], &ip,
                     sizeof(SshIpAddrStruct));
          if (attrs.num_dns >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS)
            break;
        }
    }

  /* NetBios Name Server (WINS) address(es) added in attributes. */
  if (info->wins_ip_count > 0 && info->wins_ip != NULL)
    {
      for (i = 0; i < info->wins_ip_count; i++)
        {
          if (ssh_ipaddr_parse(&ip, info->wins_ip[i]) == FALSE)
            continue;
          if (!SSH_IP_IS_NULLADDR(&ip))
              memcpy(&attrs.wins[attrs.num_wins++], &ip,
                     sizeof(SshIpAddrStruct));
          if (attrs.num_wins >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS)
            break;
        }
    }

  /* Release the local and gateway addresses, to enable redundancy */
  if (ctx->dhcp_params->gateway)
    {
      ssh_free(ctx->dhcp_params->gateway);
      ctx->dhcp_params->gateway = NULL;
    }
  if (ctx->dhcp_params->local_ip)
    {
      ssh_free(ctx->dhcp_params->local_ip);
      ctx->dhcp_params->local_ip = NULL;
    }

  /* Release the old info and store the new info for the tunnel */
  if (ctx->dhcp_params->info)
    ssh_dhcp_free_info(ctx->dhcp_params->info);
  ctx->dhcp_params->info = ssh_dhcp_dup_info(info);
  if (ctx->dhcp_params->info == NULL)
    goto fail;

  attrs.address_context = (void*)ctx->dhcp_params;
  ctx->dhcp_params = NULL;

  (*(ctx->result_cb))(&attrs, ctx->result_cb_context);

  dhcp_address_pool_delete_context(ctx);
  return;

 fail:
  SSH_DEBUG(SSH_D_ERROR, ("DHCP address query failed."));
  SSH_ADDRESS_POOL_UPDATE_STATS(ctx->addrpool->failed_allocations);

  if (ctx->dhcp_params != NULL)
    {
      /* Mark that DHCP params is no longer in use. */
      ctx->dhcp_params->context_flags &= ~SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE;

      /* If this is a renewal, we are going to need the params for DHCPRELEASE,
         make sure they are not freed yet. */
      if (ctx->renewal
          && (ctx->dhcp_params->context_flags
              & SSH_PM_RAS_DHCP_PARAMS_FLAG_DESTROYED) == 0)
        {
          if (ctx->dhcp_params->gateway)
            {
              ssh_free(ctx->dhcp_params->gateway);
              ctx->dhcp_params->gateway = NULL;
            }
          if (ctx->dhcp_params->local_ip)
            {
              ssh_free(ctx->dhcp_params->local_ip);
              ctx->dhcp_params->local_ip = NULL;
            }
          ctx->dhcp_params = NULL;
        }
        }

  if (ctx->result_cb != NULL)
    (*(ctx->result_cb))(NULL, ctx->result_cb_context);

  dhcp_address_pool_delete_context(ctx);
}

/* ************* Setting parameters and options for the DHCP library *********/
static SshDHCPOptions
dhcp_address_pool_set_options(int version)
{
  SshDHCPOptions options;

  options = ssh_calloc(1, sizeof(SshDHCPOptionsStruct));
  if (options == NULL)
    return NULL;

  if (version == SSH_DHCP_PROTOCOL_VERSION_4)
    {
      options->discover = dhcp_addresspool_dhcp_options_discover;
      options->offer = dhcp_addresspool_dhcp_options_offer;
      options->request = dhcp_addresspool_dhcp_options_request;
      options->decline = dhcp_addresspool_dhcp_options_decline;
      options->ack = dhcp_addresspool_dhcp_options_ack;
      options->nak = dhcp_addresspool_dhcp_options_nak;
      options->release = dhcp_addresspool_dhcp_options_release;
      options->inform = NULL;
    }
  else if (version == SSH_DHCP_PROTOCOL_VERSION_6)
    {
      options->solicit = dhcp_addresspool_dhcpv6_options_solicit;
      options->reply = dhcp_addresspool_dhcpv6_options_reply;
      options->decline = dhcp_addresspool_dhcpv6_options_decline;
      options->renew = dhcp_addresspool_dhcpv6_options_renew;
      options->release = dhcp_addresspool_dhcpv6_options_release;
    }

  return options;
}

static Boolean
dhcp_address_pool_set_client_id(SshPmDhcpAddressPoolInternal pool,
                                SshDHCPParams params,
                                SshPmAuthData ad)
{
  unsigned char *client_id = NULL;
  size_t len;
  SshIkev2IDType id_type = 0;
  SshIkev2PayloadID remote_id = NULL;

  SSH_ASSERT(pool != NULL);
  SSH_ASSERT(ad != NULL);

  SSH_DEBUG(SSH_D_MIDSTART, ("Setting client id."));
  /* The client ID is the IKE ID. Client ID in an address pool case is never
     a hwaddr, so client ID type 0 should be used (RFC 2132). */

  /* Select the remote IKE identity */
  remote_id = ssh_pm_auth_get_remote_id(ad, 1);
  if (remote_id != NULL)
    {
      client_id = ssh_memdup(remote_id->id_data,
                             remote_id->id_data_size);
      len = remote_id->id_data_size;
      id_type = remote_id->id_type;
    }

  /* Check if we found client ID */
  if (client_id == NULL)
    goto error;

#ifdef SSHDIST_CERT
#ifdef SSHDIST_IKE_CERT_AUTH
  /* Check if the client ID should be an extracted CN */
  if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_EXTRACT_CN) != 0)
    {
      SshDNStruct dn[1];
      SshRDN rdn;

      if (id_type != SSH_IKEV2_ID_TYPE_ASN1_DN)
          goto error;

      ssh_dn_init(dn);
      if (ssh_dn_decode_der(client_id, len, dn, NULL))
        {
          /* Find the CN part, OID 2.5.4.3 */
          rdn = ssh_find_rdn_by_oid(dn, "2.5.4.3");
          if (rdn == NULL)
            {
              ssh_dn_clear(dn);
              SSH_DEBUG(SSH_D_MY,("No RDN matching the CN OID found"));
              goto error;
            }
          ssh_free(client_id);
          client_id = ssh_str_get(rdn->c, &len);
          if (client_id == NULL)
            {
              ssh_dn_clear(dn);
              goto error;
            }

          SSH_DEBUG(SSH_D_MY,("CN part %s", client_id));
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Extracting CN part of the IKE ID failed"));
          ssh_dn_clear(dn);
          goto error;
        }
      ssh_dn_clear(dn);
    }
#endif /* SSHDIST_IKE_CERT_AUTH */
#endif /* SSHDIST_CERT */

  params->client_identifier = client_id;
  params->client_identifier_len = len;
  if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL) != 0)
    params->client_identifier_type = INTERNAL_DUID_TYPE;
  else
    params->client_identifier_type = 0;

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_FAIL,("No Client ID available."));

  if (client_id != NULL)
    ssh_free(client_id);

  return FALSE;
}

static SshDHCPParams
dhcp_address_pool_set_params(SshPmDhcpAddressPoolInternal pool,
                             SshPmAuthData ad)
{
  SshDHCPParams params    = NULL;
  SshTime suggested_lease = 0;
  SshTime lifetime        = 0;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_MIDSTART, ("Setting DHCP parameters."));

  /* Set DHCP params */
  params = ssh_calloc(1, sizeof(SshDHCPParamsStruct));
  if (params == NULL)
    return NULL;

  if (ad != NULL && dhcp_address_pool_set_client_id(pool, params, ad) == FALSE)
    goto error;

  /* Remote IP is the configured DHCP server ID (except for DHCPv6, in that
     case server ID is extracted from the Reply message.) */
  for (i = 0; i < pool->num_dhcps; i++)
    {
      if ((params->dhcp_servers[i].remote_ip
           = ssh_calloc(1, SSH_IP_ADDR_STRING_SIZE)) == NULL)
        goto error;
      ssh_ipaddr_print(&pool->dhcp[i].dhcp_ip,
                       params->dhcp_servers[i].remote_ip,
                       SSH_IP_ADDR_STRING_SIZE);
      if (pool->dhcp[i].dhcp_port == 0)
        {
          if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL) != 0)
            params->dhcp_servers[i].remote_port = SSH_DHCPV6_SERVER_PORT;
          else
            params->dhcp_servers[i].remote_port = SSH_DHCP_SERVER_PORT;
        }
      else
        {
          params->dhcp_servers[i].remote_port = pool->dhcp[i].dhcp_port;
        }
    }

  /* set requested lease and total timeout */
  params->max_total_timeout = SSH_PM_DHCP_MAX_TOTAL_TIMEOUT;

  suggested_lease = 0xffffffff;
  if (ad != NULL)
    {
      lifetime = ssh_pm_auth_get_lifetime(ad);
      if (lifetime < (0xffffffff / 2))
        suggested_lease = (lifetime * 2);
    }

  if (suggested_lease > SSH_PM_DHCP_MIN_REQUESTED_LEASE_TIME)
    {
      params->requested_lease_time = (SshUInt32)suggested_lease;
    }
  else
    {
      if (SSH_PM_DHCP_MIN_REQUESTED_LEASE_TIME < 0xffffffff)
        params->requested_lease_time = SSH_PM_DHCP_MIN_REQUESTED_LEASE_TIME;
      else
        params->requested_lease_time = 0xffffffff;
    }

  /* Option 60, Vendor class identifier. Assumed not to change, thus a
     hardcoded value is used. */
  params->vendor_id = ssh_strdup(VENDOR_ID);
  if (params->vendor_id == NULL)
    goto error;
  params->vendor_id_len = strlen(VENDOR_ID);

  /* Enterprise number for constructing the client DUID.  Assumed not to
     change, thus a hardcoded value is used. */
  if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL) != 0)
    {
      params->enterprise_number = ENTERPRISE_NUMBER;
    }

  /* Options per DHCP message. If the options are not set, DHCP library will
     use a default set. */
  if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL) != 0)
    params->options =
      dhcp_address_pool_set_options(SSH_DHCP_PROTOCOL_VERSION_6);
  else
    params->options =
      dhcp_address_pool_set_options(SSH_DHCP_PROTOCOL_VERSION_4);
  if (params->options == NULL)
    goto error;

  return params;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("Setting DHCP parameters failed."));
  dhcp_address_pool_free_params(params);

  return NULL;
}

static Boolean
dhcp_address_pool_set_local_ips(SshPmDhcpAddressPoolInternal pool,
                                SshDHCPParams params)
{
  SSH_ASSERT(pool != NULL);
  SSH_ASSERT(params != NULL);

  /* Own IP address is both the local IP and giaddr. */
  params->gateway = ssh_calloc(1, SSH_IP_ADDR_STRING_SIZE);
  if (params->gateway == NULL)
    goto error;

  ssh_ipaddr_print(&pool->own_ip_addr, params->gateway,
                   SSH_IP_ADDR_STRING_SIZE);

  params->local_ip = ssh_calloc(1, SSH_IP_ADDR_STRING_SIZE);
  if (params->local_ip == NULL)
    goto error;

  ssh_ipaddr_print(&pool->own_ip_addr, params->local_ip,
                   SSH_IP_ADDR_STRING_SIZE);

  return TRUE;

 error:
  return FALSE;
}

static Boolean
dhcp_address_pool_parse_ip_and_port(const unsigned char *value,
                                    SshIpAddr ip,
                                    SshUInt16 *out_port,
                                    SshUInt16 *in_port)
{
  SshUInt8 *ptr = NULL, *pptr = NULL;
  unsigned char tmp[128];
  size_t len = 0;

  if (value == NULL || ip == NULL)
    return FALSE;

  SSH_DEBUG(SSH_D_LOWSTART, ("Parsing address and port, %s", value));

  ptr = ssh_ustrchr(value, ',');
  if (ptr)
      len = ptr - value;
  else
    len = ssh_ustrlen(value);

  if (len + 1 > sizeof(tmp))
    return FALSE;

  memcpy(tmp, value, len);
  tmp[len] = '\0';
  if (!ssh_ipaddr_parse(ip, tmp))
    return FALSE; /* No IP address detected */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Detected address %@",
                               ssh_ipaddr_render,
                               ip));
  if (ptr)
    {
      ptr++;
      pptr = ssh_ustrchr(ptr, ',');
      if (pptr)
          len = pptr - ptr;
      else
        len = ssh_ustrlen(value) - (ptr - value);

      if (len + 1 > sizeof(tmp))
        return FALSE;

      memcpy(tmp, ptr, len);
      tmp[len] = '\0';
      if (out_port != NULL)
        {
          *out_port = atoi(tmp);
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Detected port %d", *out_port));
        }
      if (pptr)
        {
          pptr++;
          len = ssh_ustrlen(value) - (pptr - ptr);
          if (len + 1 > sizeof(tmp))
            return FALSE;

          memcpy(tmp, pptr, len);
          tmp[len] = '\0';
          if (in_port != NULL)
            {
              *in_port = atoi(tmp);
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Detected port %d", *in_port));
            }
        }
    }

  return TRUE;
}
/* ************************* Public functions ********************************/

/* ********** Creating and destroying Address Pool Objects *******************/

SshPmAddressPool
ssh_pm_dhcp_address_pool_create(void)
{
  SshPmDhcpAddressPoolInternal pool;

  SSH_DEBUG(SSH_D_MIDSTART, ("Creating a new address pool"));

  pool = ssh_calloc(1, sizeof(*pool));
  if (pool == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate address pool"));
      return NULL;
    }

  pool->ap->next = NULL;
  pool->ap->address_pool_name = NULL;

  pool->num_allocated = 0;
  pool->reference_count = 0;

  return pool->ap;
}


void
ssh_pm_dhcp_address_pool_destroy(SshPmAddressPool addrpool)
{
  SshPmDhcpAddressPoolInternal pool = (SshPmDhcpAddressPoolInternal) addrpool;
  SshPmDhcpAddressPoolAllocList curr, next = NULL;
  int i = 0;

  if (addrpool == NULL)
    return;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Destroying address pool, name %s (id %d)",
                               addrpool->address_pool_name,
                               addrpool->address_pool_id));

  /* Removing entries from tunnel pointer hash table */
  for (i = 0; i < SSH_DHCP_ALLOC_MAX; i++)
    {
      if (pool->allocated_hash_table[i] != NULL)
        {
          curr = pool->allocated_hash_table[i];

          while (curr != NULL)
            {
              next = curr->hash_next;
              dhcp_address_pool_alloc_list_remove(pool, &curr->addr);
              curr = next;
            }
        }
    }

  ssh_dhcp_library_uninit((void *)pool->fsm);
  if (pool->reference_count > 0)
    {
      pool->ap->flags |= SSH_PM_RAS_DHCP_ADDRPOOL_DESTROYED;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing DHCP address pool."));
      ssh_free(pool->ap->address_pool_name);
      ssh_free(pool);
    }
}

/* *************** Configuring attributes to Address Pool ********************/
Boolean
ssh_pm_dhcp_address_pool_set_attributes(SshPmAddressPool addrpool,
                                   const unsigned char *own_ip_addr,
                                   const unsigned char *dns,
                                   const unsigned char *wins,
                                   const unsigned char *dhcp)
{
  SshPmDhcpAddressPoolInternal pool = (SshPmDhcpAddressPoolInternal) addrpool;
  char *temp                        = NULL;
  char *dhcp_copy                   = NULL;
  SshUInt8 num_of_servers           = 0;
  int i                             = 0;
  SshUInt8 version                  = 0;
  unsigned char local_ip[SSH_IP_ADDR_STRING_SIZE] = {'\0'};

  SSH_DEBUG(SSH_D_MY1, ("Pool flags %d", pool->ap->flags));

  if (own_ip_addr == NULL || (strlen(own_ip_addr) == 0))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Malformed own IP address `%s'",
                              own_ip_addr));
      return FALSE;
    }

  for (i = 0; i < strlen(own_ip_addr); i++)
    {
      if (own_ip_addr[i] == ';')
        {
          SSH_DEBUG(SSH_D_ERROR, ("More than one own IP address '%s'",
                                  own_ip_addr));
          return FALSE;
        }
    }

  /* For a DHCP relay agent default local listening port is DHCP
     server port. Out port is optionally configured. If it is not set,
     the DHCP protocol machine will use the listening port also for sending.
  */
  if (!dhcp_address_pool_parse_ip_and_port(own_ip_addr,
                                           &pool->own_ip_addr,
                                           &pool->own_private_port,
                                           &pool->own_listening_port))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Parsing own IP address failed"));
      return FALSE;
    }

  if (pool->own_listening_port == 0)
    {
      if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL) != 0)
          pool->own_listening_port = SSH_DHCPV6_SERVER_PORT;
      else
        pool->own_listening_port = SSH_DHCP_SERVER_PORT;
    }

  ssh_ipaddr_print(&pool->own_ip_addr, local_ip,
                   SSH_IP_ADDR_STRING_SIZE);

  if ((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL) != 0)
    version = SSH_DHCP_PROTOCOL_VERSION_6;
  else
    version = SSH_DHCP_PROTOCOL_VERSION_4;

  /* Check for correct address family */
  if (!((version == SSH_DHCP_PROTOCOL_VERSION_6 &&
         SSH_IP_IS6(&pool->own_ip_addr)) ||
      (version == SSH_DHCP_PROTOCOL_VERSION_4 &&
         SSH_IP_IS4(&pool->own_ip_addr))))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Wrong address family for own IP address"));
      return FALSE;
    }

  pool->fsm = ssh_dhcp_library_init(version, local_ip,
                                    pool->own_private_port,
                                    pool->own_listening_port);
  if (pool->fsm == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("DHCP library initialization failed"));
      return FALSE;
    }

  num_of_servers = 0;
  if (dhcp)
    {
      if (strlen(dhcp) == 0)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Malformed DHCP address `%s'", dhcp));
          return FALSE;
        }
      dhcp_copy = ssh_strdup((const char *)dhcp);
      if (dhcp_copy == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Parsing DHCP address failed", dhcp));
          return FALSE;
        }

      temp = strtok(dhcp_copy, ";");
      while (dhcp_address_pool_parse_ip_and_port(
                                  temp,
                                  &pool->dhcp[num_of_servers].dhcp_ip,
                                  &pool->dhcp[num_of_servers].dhcp_port,
                                  NULL)
             == TRUE)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Configuring DHCP address `%s'",
                                       temp));

          /* Check for correct address family */
          if (!((version == SSH_DHCP_PROTOCOL_VERSION_6 &&
                 SSH_IP_IS6(&pool->dhcp[num_of_servers].dhcp_ip)) ||
              (version == SSH_DHCP_PROTOCOL_VERSION_4 &&
                 SSH_IP_IS4(&pool->dhcp[num_of_servers].dhcp_ip))))
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Wrong address family for server IP address"));
              ssh_free(dhcp_copy);
              return FALSE;
            }

          /* Same server reconfigured. Better check this, as it will cause
             a lot of redundand DHCP messages. */
          for (i = 0; i < num_of_servers; i++)
            {
              if (SSH_IP_CMP(&pool->dhcp[num_of_servers].dhcp_ip,
                             &pool->dhcp[i].dhcp_ip) == 0)
                {
                  SSH_DEBUG(SSH_D_ERROR,
                            ("Same DHCP server configured more than once"));
                  ssh_free(dhcp_copy);
                  return FALSE;
                }
            }

          num_of_servers++;

          /* No more addresses. */
          temp = strtok(NULL, ";");
          if (temp == NULL)
            break;

          /* Too many DHCP servers. */
          if (num_of_servers >= SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Too many DHCP servers, only %d supported",
                         SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT ));
              ssh_free(dhcp_copy);
              return FALSE;
            }
        }

      ssh_free(dhcp_copy);
      pool->num_dhcps = num_of_servers;
    }

  return TRUE;
}

/** Compare two Address Pools. */
Boolean
ssh_pm_dhcp_address_pool_compare(SshPmAddressPool ap1, SshPmAddressPool ap2)
{
  SshPmDhcpAddressPoolInternal pool1 = (SshPmDhcpAddressPoolInternal) ap1;
  SshPmDhcpAddressPoolInternal pool2 = (SshPmDhcpAddressPoolInternal) ap2;

  if (ap1 == NULL || ap2 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid address pool arguments ap1 %p ap2 %p",
                             ap1, ap2));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Comparing address pools: '%s' <<>> '%s'",
             ap1->address_pool_name, ap2->address_pool_name));

  if (SSH_IP_CMP(&pool1->own_ip_addr, &pool2->own_ip_addr))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("own_ip_addr mismatch"));
      return FALSE;
    }

  if ((pool1->own_listening_port != pool2->own_listening_port) ||
      (pool1->own_private_port != pool2->own_private_port))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("local port mismatch"));
      return FALSE;
    }

  if ((pool1->num_dhcps != pool2->num_dhcps)
      || memcmp(pool1->dhcp, pool2->dhcp,
                sizeof(*pool1->dhcp) * pool1->num_dhcps))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("dhcp mismatch"));
      return FALSE;
    }

  if (ap1->flags != ap2->flags)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("flags mismatch"));
      return FALSE;
    }

  return TRUE;
}

/* ****************** Allocating an IP address from the DHCP server **********/
SshOperationHandle
ssh_pm_dhcp_address_pool_alloc_address(
                  SshPmAddressPool addrpool,
                  SshPmAuthData ad,
                  SshUInt32 flags,
                  SshPmRemoteAccessAttrs requested_attributes,
                  SshPmRemoteAccessAttrsAllocResultCB result_cb,
                  void *result_cb_context)
{
  SshPmDhcpAddressPoolInternal pool = (SshPmDhcpAddressPoolInternal) addrpool;
  SshPmRasDhcpAllocCtx dhcp_ctx     = NULL;
  SshDHCPParams params              = NULL;
  SshDHCPInformation info           = NULL;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("Launching DHCP protocol machine to allocate IP address."));

  /* Allocate context for DHCP thread */
  dhcp_ctx = ssh_calloc(1, sizeof(struct SshPmRasDhcpAllocCtxRec));
  if (dhcp_ctx == NULL)
    goto error;

  /* Take a reference to the address pool. */
  dhcp_ctx->addrpool = pool;
  dhcp_ctx->addrpool->reference_count++;

  dhcp_ctx->result_cb = result_cb;
  dhcp_ctx->result_cb_context = result_cb_context;
  dhcp_ctx->attrs = ssh_pm_dup_remote_access_attrs(requested_attributes);

  if ((flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW) != 0)
    {
      SSH_ASSERT(requested_attributes != NULL);
      dhcp_ctx->renewal = 1;

      params = (SshDHCPParams) requested_attributes->address_context;
      SSH_ASSERT(params != NULL);
      if ((params->context_flags & SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE) != 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("DHCP address pool params in use"));
          goto error;
        }
    }
  else
    {
      params = dhcp_address_pool_set_params(pool, ad);
    }

  if (params == NULL)
    goto error;

  dhcp_ctx->dhcp_params = params;

  /* Add a flag for DHCPv6 */
  if ((dhcp_ctx->addrpool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL)
      != 0)
    params->flags |= SSH_DHCP_CLIENT_FLAG_DHCPV6;

  /* If this is SA import, set the IP address to make sure only DHCPREQUEST
     or RENEW is sent. */
  if ((flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_IMPORT) != 0)
    {
      if (params->info != NULL)
        ssh_dhcp_free_info(params->info);

      params->info = ssh_calloc(1, sizeof(*params->info));
      if (params->info == NULL)
        goto error;

      params->info->my_ip = ssh_calloc(1, SSH_IP_ADDR_STRING_SIZE);
      if (params->info->my_ip == NULL)
        goto error;

      ssh_ipaddr_print(&requested_attributes->addresses[0],
                       params->info->my_ip, SSH_IP_ADDR_STRING_SIZE);

      /* Add server DUID if available */
      if (requested_attributes->server_duid != NULL &&
          requested_attributes->server_duid_len > 0)
        {
          params->info->server_duid =
            ssh_memdup(requested_attributes->server_duid,
                       requested_attributes->server_duid_len);
          if (params->info->server_duid == NULL)
            goto error;
          params->info->server_duid_len =
            requested_attributes->server_duid_len;
        }
    }


  /* Own IP address is both the local IP and giaddr.*/
  if (dhcp_address_pool_set_local_ips(pool, dhcp_ctx->dhcp_params) == FALSE)
    goto error;

  /* A standby node should not request address from DHCP server when SA is
     imported, call the alloc callback directly with allocated info
     structure. */
  if (((pool->ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_STANDBY) != 0) &&
      ((flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_IMPORT) != 0))
    {
      info = ssh_dhcp_dup_info(dhcp_ctx->dhcp_params->info);
      if (info == NULL)
        goto error;

      /* Lease time is 2 * IKE lifetime, IKE rekey will take care of lease
         renewal. */
      info->lease_time = dhcp_ctx->dhcp_params->requested_lease_time;

      /* Mark that DHCP params are in use. */
      dhcp_ctx->dhcp_params->context_flags |=
        SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE;

      /* Initialize operation handle for aborting the alloc thread. */
      ssh_operation_register_no_alloc(&dhcp_ctx->operation,
                                      dhcp_address_pool_abort_cb, dhcp_ctx);

      dhcp_address_pool_alloc_callback(NULL, info,
                                       SSH_DHCP_STATUS_OK, (void *)dhcp_ctx);

      ssh_dhcp_free_info(info);

      return NULL;
    }

  dhcp_ctx->dhcp = ssh_dhcp_allocate(pool->fsm,
                                     dhcp_ctx->dhcp_params,
                                     dhcp_address_pool_alloc_callback,
                                     dhcp_address_pool_destructor_cb,
                                     (void *)dhcp_ctx);
  if (dhcp_ctx->dhcp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("DHCP allocation failed."));
      goto error;
    }

  if (ssh_dhcp_run(dhcp_ctx->dhcp) != SSH_DHCP_STATUS_OK)
    {
      /* Thread has not started. */
      ssh_dhcp_free(dhcp_ctx->dhcp);
      dhcp_ctx->dhcp = NULL;
      goto error;
    }

  /* Mark that DHCP params are in use. */
  dhcp_ctx->dhcp_params->context_flags |= SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE;

  /* Initialize operation handle for aborting the alloc thread. */
  ssh_operation_register_no_alloc(&dhcp_ctx->operation,
                                  dhcp_address_pool_abort_cb, dhcp_ctx);

  return &dhcp_ctx->operation;

 error:
  SSH_DEBUG(SSH_D_ERROR,
            ("Could not allocate address from DHCP address pool"));
  (*(result_cb))(NULL, result_cb_context);

  /* If this is a renewal, we are going to need the params for DHCPRELEASE,
     make sure they are not freed yet. */
  if (dhcp_ctx != NULL && dhcp_ctx->renewal)
    {
      if (dhcp_ctx->dhcp_params != NULL && dhcp_ctx->dhcp_params->gateway)
        {
          ssh_free(dhcp_ctx->dhcp_params->gateway);
          dhcp_ctx->dhcp_params->gateway = NULL;
        }
      if (dhcp_ctx->dhcp_params != NULL && dhcp_ctx->dhcp_params->local_ip)
        {
          ssh_free(dhcp_ctx->dhcp_params->local_ip);
          dhcp_ctx->dhcp_params->local_ip = NULL;
        }
      dhcp_ctx->dhcp_params = NULL;
    }

  dhcp_address_pool_delete_context(dhcp_ctx);
  return NULL;
}

/* ****************** Number of currently allocated addresses ****************/
SshUInt32
ssh_pm_dhcp_address_pool_num_allocated_addresses(SshPmAddressPool addrpool)
{
  SshPmDhcpAddressPoolInternal pool = (SshPmDhcpAddressPoolInternal) addrpool;

  return pool->num_allocated;
}


/******************** Freeing address to Address Pool ***********************/

Boolean
ssh_pm_dhcp_address_pool_free_address(SshPmAddressPool addrpool,
                                      const SshIpAddr address, void *data)
{
  SshPmDhcpAddressPoolInternal pool = (SshPmDhcpAddressPoolInternal) addrpool;
  SshPmRasDhcpAllocCtx dhcp_ctx     = NULL;





  SSH_DEBUG(SSH_D_MIDSTART,
            ("Sending release for address %@ to the DHCP server.",
             ssh_ipaddr_render, address));

  pool->num_allocated--;
  SSH_ADDRESS_POOL_UPDATE_STATS(pool->addresses_freed);

    /* Allocate context for DHCP thread */
  dhcp_ctx = ssh_calloc(1, sizeof(struct SshPmRasDhcpAllocCtxRec));
  if (dhcp_ctx == NULL)
    goto error;

  /* Take a reference to the address pool. */
  dhcp_ctx->addrpool = pool;
  dhcp_ctx->addrpool->reference_count++;

  /* Steal the data pointer */
  if (data != NULL)
    {
      dhcp_ctx->dhcp_params = (SshDHCPParams) data;
      data = NULL;
    }
  else
    {
      goto error; /* No data available for the DHCPRELEASE */
    }

  /* Check if there are any ongoing operations using the DHCP params. */
  if ((dhcp_ctx->dhcp_params->context_flags &
       SSH_PM_RAS_DHCP_PARAMS_FLAG_INUSE) != 0)
    {
      /* Mark that DHCP params should be freed when ongoing operation
         completes. */
      SSH_DEBUG(SSH_D_HIGHOK, ("Marking DHCP params to be freed"));
      dhcp_ctx->dhcp_params->context_flags
        |= SSH_PM_RAS_DHCP_PARAMS_FLAG_DESTROYED;
      dhcp_ctx->dhcp_params = NULL;
      goto error;
    }

  if (dhcp_address_pool_set_local_ips(pool, dhcp_ctx->dhcp_params) == FALSE)
    goto error;

  /* Remove from allocated_addresses list */
  if (dhcp_address_pool_alloc_list_remove(pool, address) > 0 )
    {
      dhcp_address_pool_release_cb(NULL, NULL, SSH_DHCP_STATUS_OK,
                                   (void *)dhcp_ctx);
      return TRUE;
    }

  dhcp_ctx->dhcp = ssh_dhcp_allocate(pool->fsm, dhcp_ctx->dhcp_params,
                                     dhcp_address_pool_release_cb,
                                     dhcp_address_pool_destructor_cb,
                                     (void *)dhcp_ctx);
  if (dhcp_ctx->dhcp == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate DHCP."));
      goto error;
    }

  if (ssh_dhcp_release(dhcp_ctx->dhcp) != SSH_DHCP_STATUS_OK)
    {
      /* Thread has not started. */
      ssh_dhcp_free(dhcp_ctx->dhcp);
      dhcp_ctx->dhcp = NULL;
      goto error;
    }

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("Could not send DHCPRELEASE for address %@ .",
                          ssh_ipaddr_render, address));
  if (data != NULL)
    dhcp_address_pool_free_params((SshDHCPParams) data);
  dhcp_address_pool_delete_context(dhcp_ctx);

  return FALSE;
}

Boolean ssh_pm_dhcp_address_pool_get_statistics(SshPmAddressPool addrpool,
                                                SshPmAddressPoolStats stats)
{
  SshDHCPStats statistics = NULL;
  SshPmDhcpAddressPoolInternal pool = (SshPmDhcpAddressPoolInternal) addrpool;

  stats->current_num_allocated_addresses =
    ssh_pm_dhcp_address_pool_num_allocated_addresses(addrpool);
  stats->total_num_allocated_addresses = pool->total_num_allocated;
  stats->num_freed_addresses = pool->addresses_freed;
  stats->num_failed_address_allocations = pool->failed_allocations;

  statistics = ssh_dhcp_get_statistics(pool->fsm);
  if (statistics == NULL)
    return FALSE;

  stats->dhcp.packets_transmitted = statistics->packets_transmitted;
  stats->dhcp.packets_received = statistics->packets_received;
  stats->dhcp.packets_dropped = statistics->packets_dropped;
  stats->dhcp.discover = statistics->discover;
  stats->dhcp.offer = statistics->offer;
  stats->dhcp.request = statistics->request;
  stats->dhcp.ack = statistics->ack;
  stats->dhcp.nak = statistics->nak;
  stats->dhcp.decline = statistics->decline;
  stats->dhcp.release = statistics->release;
  stats->dhcp.dhcpv6_relay_forward = statistics->dhcpv6_relay_forward;
  stats->dhcp.dhcpv6_relay_reply = statistics->dhcpv6_relay_reply;
  stats->dhcp.dhcpv6_solicit = statistics->dhcpv6_solicit;
  stats->dhcp.dhcpv6_reply = statistics->dhcpv6_reply;
  stats->dhcp.dhcpv6_decline = statistics->dhcpv6_decline;
  stats->dhcp.dhcpv6_renew = statistics->dhcpv6_renew;
  stats->dhcp.dhcpv6_release = statistics->dhcpv6_release;

  return TRUE;
}
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
