/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   High-level remote access server functionality.  This file
   implements the attribute allocation functions of the high-level
   remote access server.  This uses the low-level functions and
   callbacks, defined in the `ras_addrpool.h' API.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "ras_dhcp_addrpool.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

#define SSH_DEBUG_MODULE "SshPmRemoteAccessServer"


/*************************** Types and Definitions **************************/

/*************************** Utility Functions *******************************/
/** Return address pool by id. This returns also the removed address pools. */
static SshPmAddressPool
pm_ras_get_address_pool_by_id(SshPm pm,
                              SshPmAddrPoolId id)
{
  SshPmAddressPool ap;

  for (ap = pm->addrpool; ap != NULL; ap = ap->next)
    {
      if (ap->address_pool_id == id)
        return ap;
    }

  return NULL;
}

/** Return address pool by name. This does not return removed address pools. */
static SshPmAddressPool
pm_ras_get_address_pool_by_name(SshPm pm,
                                const unsigned char *name)
{
  SshPmAddressPool ap;

  for (ap = pm->addrpool; ap != NULL; ap = ap->next)
    {
      /* Skip removed address pools. */
      if (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED)
        continue;

      if (strcmp(ap->address_pool_name, name) == 0)
        return ap;
    }

  return NULL;
}

/** Map address pool name to id. This does not consider removed address
    pools. */
Boolean
ssh_pm_address_pool_get_id(SshPm pm,
                           const unsigned char *name,
                           SshPmAddrPoolId *id)
{
  SshPmAddressPool ap;

  SSH_ASSERT(id != NULL);
  ap = pm_ras_get_address_pool_by_name(pm, name);
  if (ap != NULL)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Found address pool '%s' (id %d)",
                 ap->address_pool_name, ap->address_pool_id));
      *id = ap->address_pool_id;
      return TRUE;
    }

  return FALSE;
}

/** Return default address pool id. This does not consider removed address
    pools. */
Boolean
ssh_pm_address_pool_get_default_id(SshPm pm,
                                   SshPmAddrPoolId *id)
{
  SshPmAddressPool ap;

  SSH_ASSERT(id != NULL);
  ap = pm_ras_get_address_pool_by_name(pm, ADDRPOOL_DEFAULT_NAME);
  if (ap != NULL)
    {
      /* DHCP address pool cannot be the default pool, but must always be
         tied to a tunnel */
      if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
        return FALSE;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Found address pool '%s' (id %d)",
                 ap->address_pool_name, ap->address_pool_id));
      *id = ap->address_pool_id;
      return TRUE;
    }

  return FALSE;
}

/** Remove an address pool from pm and destroy it. */
static void
pm_ras_delete_addrpool(SshPm pm,
                       SshPmAddressPool ap)
{
  SshPmAddressPool ap_prev;

  /* Remove address pool from pm list. */
  if (ap == pm->addrpool)
    {
      pm->addrpool = ap->next;
    }
  else
    {
      for (ap_prev = pm->addrpool;
           ap_prev != NULL && ap_prev->next != NULL;
           ap_prev = ap_prev->next)
        {
          if (ap_prev->next == ap)
            {
              ap_prev->next = ap->next;
              break;
            }
        }
    }

  /* Destroy address pool. */
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
  if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
    ssh_pm_dhcp_address_pool_destroy(ap);
  else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
  ssh_pm_address_pool_destroy(ap);
  pm->num_address_pools--;
}

/** Mark an address pool removed. If the address pool has no active address
    leases then remove address pool from pm and destroy it. Otherwise the
    address pool is left in pm, but no new address are allocated from it. */
static void
pm_ras_remove_addrpool(SshPm pm,
                       SshPmAddressPool ap)
{
  SshUInt32 num_allocated = 0;
  /* Delete immediately all address pools that have no address leases. */
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
  if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
    num_allocated = ssh_pm_dhcp_address_pool_num_allocated_addresses(ap);
  else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
    num_allocated = ssh_pm_address_pool_num_allocated_addresses(ap);
  if (num_allocated == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Deleting address pool, name '%s' (id %d)",
                 ap->address_pool_name, ap->address_pool_id));

      /* Remove from pm list and destroy addrpool. */
      pm_ras_delete_addrpool(pm, ap);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Marking address pool removed, name '%s' (id %d)",
                 ap->address_pool_name, ap->address_pool_id));

      /* Mark address pool removed. */
      ap->flags |= SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED;
    }
}


/***************** Default Allocate callback for RAS *************************/

/* Context structure for remote access attribute allocation state machine. */
typedef struct SshPmRasAllocCtxRec
{
  /* Thread and operation handle for the alloc operation. */
  SshFSMThreadStruct thread;
  SshOperationHandleStruct operation;

  /* Operation handle of the address pool alloc operation. */
  SshOperationHandle sub_operation;

  /* Input parameters. */
  SshPmAuthData ad;
  SshUInt32 flags;
  SshPmRemoteAccessAttrs requested_attributes;

  /* Result callback and context. */
  SshPmRemoteAccessAttrsAllocResultCB result_cb;
  void *result_cb_context;

  /* The tunnel or NULL if allocating from global pool. */
  SshPmTunnel tunnel;

  /* The index of the address pool. */
  SshUInt32 ap_id_index;

  /* The address pool id of the current address pool. */
  SshPmAddrPoolId id;

  /* DHCP specific data required for subsequent message exchange */
  SshPmAddressPoolData address_pool_data;

} *SshPmRasAllocCtx;

static void
pm_ras_addrpool_alloc_thread_destructor(SshFSM fsm, void *context)
{
  SshPm pm = ssh_fsm_get_gdata_fsm(fsm);
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) context;

  /* Release our reference to the tunnel. */
  SSH_ASSERT(ctx->tunnel != NULL);
  SSH_PM_TUNNEL_DESTROY(pm, ctx->tunnel);

  /* Cleanup context. */
  if (ctx->ad != NULL)
    ssh_pm_auth_data_free(ctx->ad);

  /* Free the address_pool_data only if this is not arenewal operation.
     In renewal ctx->address_pool_data is the context from the original
     RAS attribute allocation and it is freed when the RAS attributes
     are freed. */
  if ((ctx->flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW) == 0
      && ctx->address_pool_data != NULL)
    ssh_free(ctx->address_pool_data);

  if (ctx->requested_attributes)
    ssh_pm_free_remote_access_attrs(ctx->requested_attributes);

  ssh_free(ctx);
}

void
pm_ras_addrpool_alloc_abort(void *context)
{
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) context;

  /* Abort sub operation. */
  if (ctx->sub_operation != NULL)
    ssh_operation_abort(ctx->sub_operation);

  /* Continue thread to terminal state. */
  ssh_fsm_set_next(&ctx->thread, pm_ras_addrpool_alloc_done);
  if (ssh_fsm_get_callback_flag(&ctx->thread))
    SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
  else
    ssh_fsm_continue(&ctx->thread);
}

void
pm_ras_addrpool_alloc_result_cb(SshPmRemoteAccessAttrs attributes,
                                void *context)
{
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) context;
#ifdef DEBUG_LIGHT
  int i;
#endif /* DEBUG_LIGHT */

  /* Mark sub operation completed. */
  ctx->sub_operation = NULL;

  if (attributes != NULL)
    {
      /* Store address pool id, low level address context and
         number of address to address_context. The address context
         is shared among all addresses in the allocated attributes
         and it is freed when all RAS addresses have been freed. */
      ctx->address_pool_data->id = ctx->id;
      ctx->address_pool_data->data = attributes->address_context;
      SSH_ASSERT(attributes->num_addresses > 0);
      ctx->address_pool_data->num_addresses = attributes->num_addresses;

      /* Replace address context in the returned attributes. */
      attributes->address_context = (void *)(ctx->address_pool_data);
      ctx->address_pool_data = NULL;

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Allocated remote access attributes from pool id %d:",
                 (unsigned long) ctx->id));
#ifdef DEBUG_LIGHT
      for (i = 0; i < attributes->num_addresses; i++)
        SSH_DEBUG(SSH_D_HIGHOK,
                  ("Allocated address `%@'",
                   ssh_ipaddr_render, &attributes->addresses[i]));
#endif /* DEBUG_LIGHT */

      /* Pass attributes to caller. */
      (*ctx->result_cb)(attributes, ctx->result_cb_context);

      /* Unregister abort. */
      ssh_operation_unregister(&ctx->operation);

      /* Finish thread. */
      ssh_fsm_set_next(&ctx->thread, pm_ras_addrpool_alloc_done);
    }
  else
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Remote access attribute allocation failed from pool id %d",
                 (unsigned long) ctx->id));

      /* Try next address pool. */
      ctx->ap_id_index++;
    }

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&ctx->thread);
}

SSH_FSM_STEP(pm_ras_addrpool_alloc)
{
  SshPm pm = (SshPm) fsm_context;
  SshPmRasAllocCtx ctx = (SshPmRasAllocCtx) thread_context;
  SshPmAddressPool ap  = NULL;

  SSH_FSM_SET_NEXT(pm_ras_addrpool_alloc);

  /* Try to renew attributes only from the address pool where
     they were originally allocated from. */
  if (ctx->flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW)
    {
      /* Attribute renewal from address pool failed. */
      if (ctx->ap_id_index > 0)
        goto fail;

      /* Find the address pool where the attributes were originally
         allocated from. */
      if (ctx->address_pool_data != NULL)
        ap = pm_ras_get_address_pool_by_id(pm, ctx->address_pool_data->id);
      if (ap == NULL || (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED))
        goto fail;
    }

  /* Try allocating from one of the tunnel's address pools. */
  else
    {
      /* Find an Address Pool that this tunnel is configured to use. */
      while (ctx->ap_id_index < ctx->tunnel->num_address_pool_ids)
        {
          ap =
            pm_ras_get_address_pool_by_id(pm,
                                          ctx->tunnel->
                                         address_pool_ids[ctx->ap_id_index]);
          if (ap != NULL
              && (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED) == 0)
            break;

          /* Address pool is not valid, try next address pool. */
          ap = NULL;
          ctx->ap_id_index++;
        }

      /* No valid address pools found, fail. */
      if (ctx->ap_id_index >= ctx->tunnel->num_address_pool_ids)
        goto fail;
    }

  SSH_ASSERT(ap != NULL
             && (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED) == 0);

  /* Attempt to allocate an address from the Address Pool. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Tunnel '%s': Allocating attributes from "
             "address pool '%s' (id %d)",
             ctx->tunnel->tunnel_name,
             ap->address_pool_name, ap->address_pool_id));

  /* Store the address pool id to alloc context. */
  ctx->id = ap->address_pool_id;

  /* Replace address_context in tthe requested attributes to the low level
     context data. */
  if (ctx->requested_attributes != NULL)
    ctx->requested_attributes->address_context = ctx->address_pool_data->data;

#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
  if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
    {
      SSH_FSM_ASYNC_CALL({
          ctx->sub_operation =
            ssh_pm_dhcp_address_pool_alloc_address(
                                               ap,
                                               ctx->ad,
                                               ctx->flags,
                                               ctx->requested_attributes,
                                               pm_ras_addrpool_alloc_result_cb,
                                               ctx);
          });
    }
  else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
    {
      SSH_FSM_ASYNC_CALL({
          ctx->sub_operation =
            ssh_pm_address_pool_alloc_address(
                                        ap,
                                        ctx->ad,
                                        ctx->flags,
                                        ctx->requested_attributes,
                                        pm_ras_addrpool_alloc_result_cb,
                                        ctx);
        });
    }
  SSH_NOTREACHED;

 fail:
  /* No address pools found. Indicate allocation failure. */
  SSH_DEBUG(SSH_D_FAIL, ("Remote access attribute allocation failed"));
  ssh_operation_unregister(&ctx->operation);
  (*ctx->result_cb)(NULL, ctx->result_cb_context);

  return SSH_FSM_FINISH;
}

SSH_FSM_STEP(pm_ras_addrpool_alloc_done)
{
  /* The thread is finished. */
  return SSH_FSM_FINISH;
}

/** Remote access attribute allocation callback. */
SshOperationHandle
ssh_pm_ras_alloc_address(SshPm pm,
                         SshPmAuthData ad,
                         SshUInt32 flags,
                         SshPmRemoteAccessAttrs requested_attributes,
                         SshPmRemoteAccessAttrsAllocResultCB result_cb,
                         void *result_cb_context,
                         void *context)
{
  SshPmTunnel tunnel;
  SshPmRasAllocCtx ctx = NULL;
  SshUInt32 tunnel_id;

  /* Lookup tunnel. */
  tunnel_id = SSH_PM_PTR_TO_UINT32(context);
  tunnel = ssh_pm_tunnel_get_by_id(pm, tunnel_id);
  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No tunnel found for tunnel id %d", tunnel_id));
      goto error;
    }

  /* Allocate context for the remote access attribute alloc thread. */
  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    goto error;
  ctx->flags = flags;

  /* Duplicate authentication data as it is needed after this function
     returns. */
  if (ad != NULL)
    {
      ctx->ad = ssh_pm_auth_data_dup(ad);
      if (ctx->ad == NULL)
        goto error;
    }

  /* Allocate memory for address context, if needed. */
  if (flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW)
    {
      SSH_ASSERT(requested_attributes != NULL
                 && requested_attributes->address_context != NULL);
      ctx->address_pool_data =
        (SshPmAddressPoolData)requested_attributes->address_context;
    }
  else
    {
      ctx->address_pool_data =
        ssh_calloc(1, sizeof(SshPmAddressPoolDataStruct));
    }
  if (ctx->address_pool_data == NULL)
    goto error;

  /* Duplicate requested RAS attributes. */
  if (requested_attributes != NULL)
    {
      ctx->requested_attributes =
        ssh_pm_dup_remote_access_attrs(requested_attributes);
      if (ctx->requested_attributes == NULL)
        goto error;
    }

  ctx->result_cb = result_cb;
  ctx->result_cb_context = result_cb_context;
  SSH_ASSERT(tunnel != NULL);

  ctx->tunnel = tunnel;
  SSH_PM_TUNNEL_TAKE_REF(ctx->tunnel);

  /* Initialize operation handle for aborting the alloc thread. */
  ssh_operation_register_no_alloc(&ctx->operation,
                                  pm_ras_addrpool_alloc_abort, ctx);

  /* Start thread. The thread attempts to allocate remote access attributes
     from the address pools configured to a tunnel or from the global address
     pool. The thread finishes on first successful allocation. Otherwise the
     thread moves to the next address pool until all configured address pools
     are tried. */
  ssh_fsm_thread_init(&pm->fsm, &ctx->thread, pm_ras_addrpool_alloc,
                      NULL_FNPTR, pm_ras_addrpool_alloc_thread_destructor,
                      ctx);
  ssh_fsm_set_thread_name(&ctx->thread, "IKE RAS Address Pool");

  return &ctx->operation;

 error:
  if (ctx != NULL)
    {
      if (ctx->ad != NULL)
        ssh_pm_auth_data_free(ctx->ad);
      if ((flags & SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW) == 0
          && ctx->address_pool_data != NULL)
        ssh_free(ctx->address_pool_data);
      if (ctx->requested_attributes != NULL)
        ssh_pm_free_remote_access_attrs(ctx->requested_attributes);
      ssh_free(ctx);
    }

  /* Call result callback to indicate allocation failure. */
  (*result_cb)(NULL, result_cb_context);

  return NULL;
}


/********************** Default free callback for RAS ***********************/

/** Remote access address free callback. */
void
ssh_pm_ras_free_address(SshPm pm,
                        const SshIpAddr address,
                        void *address_context,
                        void *context)
{
  SshPmAddressPool ap;
  Boolean ret = FALSE;
  SshUInt32 num_allocated = 0;
  SshPmAddressPoolData ctx = (SshPmAddressPoolData)address_context;

  /* The address pool id is encoded in address_context pointer. */
  if (address_context == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Could not return address '%@' to address pool, invalid"
                 " address context",
                 ssh_ipaddr_render, address));
      return;
    }

  /* Lookup the address pool. */
  ap = pm_ras_get_address_pool_by_id(pm, ctx->id);
  if (ap != NULL)
    {
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
      if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
        {
          ret = ssh_pm_dhcp_address_pool_free_address(ap,
                                                      address,
                                                      ctx->data);
        }
      else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
        ret = ssh_pm_address_pool_free_address(ap, address);

      if (ret == TRUE)
        {
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Returned address '%@' to pool '%s' (id %d)",
                     ssh_ipaddr_render, address,
                     ap->address_pool_name, ap->address_pool_id));
        }
    }

  if (ret == FALSE)
    SSH_DEBUG(SSH_D_FAIL,
              ("Could not return address '%@' to address pool id %d",
               ssh_ipaddr_render, address,
               ctx->id));

  /* Free the shared address context when all addresses have been freed. */
  SSH_ASSERT(ctx->num_addresses > 0);
  ctx->num_addresses--;
  if (ctx->num_addresses == 0)
    ssh_free(ctx);

  /* Check if address pool deletion is pending and delete address pool
     if this was the last missing address from the pool. */
  if (ap != NULL
      && (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED))
    {
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
      if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
        num_allocated = ssh_pm_dhcp_address_pool_num_allocated_addresses(ap);
      else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
        num_allocated = ssh_pm_address_pool_num_allocated_addresses(ap);
      if (num_allocated == 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Deleting removed address pool '%s'(id %d)",
                                  ap->address_pool_name, ap->address_pool_id));
          pm_ras_delete_addrpool(pm, ap);
        }
    }
}


/*************** Adding and Removing Address Pools to/from PM ***************/

/** Remove an Address Pool from policy manager. */
void
ssh_pm_ras_remove_addrpool(SshPm pm,
                           const unsigned char *name)
{
  SshPmAddressPool ap, ap_next;

  /* Iterate through pools and remove pools that have a matching name. */
  for (ap = pm->addrpool; ap != NULL; ap = ap_next)
    {
      ap_next = ap->next;

      /* Skip non-matching address pools. */
      if (name != NULL && strcmp(name, ap->address_pool_name) != 0)
        continue;

      pm_ras_remove_addrpool(pm, ap);
    }

  return;
}

/** Create and configure an address pool. */
Boolean
ssh_pm_ras_add_addrpool(SshPm pm,
                        SshPmRemoteAccessParams ras)
{
  SshPmAddressPool ap = NULL;
  SshPmAddressPool api = NULL;

  if (ras->name && (strlen(ras->name) == 0
                    || strcmp(ras->name, ADDRPOOL_DEFAULT_NAME) == 0))

    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid address pool name"));
      return FALSE;
    }

#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
  /* DHCP address pool must have a name, and it is never used as the default
     pool. */
  if ((!ras->name || strlen(ras->name) == 0)
      && (ras->flags & SSH_PM_REMOTE_ACCESS_DHCP_POOL))
    {
      SSH_DEBUG(SSH_D_ERROR, ("DHCP address pool must have a name"));
      return FALSE;
    }

  /* if this is a dhcp address pool, add server IPs and local ports */
  if (ras->flags & SSH_PM_REMOTE_ACCESS_DHCP_POOL)
    {
      ap = ssh_pm_dhcp_address_pool_create();
      if (ap == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not create remote access address pool instance"));
          return FALSE;
        }
      ap->pm = pm;
      ap->flags = SSH_PM_RAS_DHCP_ADDRPOOL;

      /* IP address sanity check is enabled. This feature must not be
         enabled via reconfigure, it must require policymanager restart. */
      if (pm->params.dhcp_ras_enabled == TRUE)
        ap->flags |= SSH_PM_RAS_DHCP_ADDRPOOL_ALLOC_CHECK_ENABLED;

      if (ras->flags & SSH_PM_REMOTE_ACCESS_DHCP_EXTRACT_CN)
        ap->flags |= SSH_PM_RAS_DHCP_ADDRPOOL_EXTRACT_CN;

      if (ras->flags & SSH_PM_REMOTE_ACCESS_DHCPV6_POOL)
        ap->flags |= SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL;

      if (ras->flags & SSH_PM_REMOTE_ACCESS_DHCP_STANDBY)
        ap->flags |= SSH_PM_RAS_DHCP_ADDRPOOL_STANDBY;
    }
  else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
    {
      /* addresses input is mandatory */
      if ((!ras->addresses || strlen(ras->addresses) == 0)





          )
        {
          SSH_DEBUG(SSH_D_ERROR, ("Error, addresses cannot be empty"));
          return FALSE;
        }

      /* Create an address pool with passed params */
      ap = ssh_pm_address_pool_create();
      if (ap == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not create remote access address pool instance"));
          return FALSE;
        }

      ap->pm = pm;
      ap->flags = 0;
    }

  /* Name input should be there. If NULL, then assign default name for the
     address pool and returned the assigned in the RAS params. */
  if (!ras->name)
    {
      ap->address_pool_name = ssh_strdup(ADDRPOOL_DEFAULT_NAME);
      ras->name = ssh_strdup(ADDRPOOL_DEFAULT_NAME);
      if (ras->name == NULL)
        goto error;
    }
  else
    ap->address_pool_name = ssh_strdup(ras->name);

  if (ap->address_pool_name == NULL)
    goto error;

  ap->address_pool_id = pm->addrpool_id_next;

#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
  if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
    {
      if (!ssh_pm_dhcp_address_pool_set_attributes(ap,
                                                   ras->own_ip_addr,
                                                   ras->dns,
                                                   ras->wins,
                                                   ras->dhcp))
        goto error;
    }
  else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
    {
      /* Set attributes */
      if (!ssh_pm_address_pool_set_attributes(ap, ras->own_ip_addr, ras->dns,
                                              ras->wins, ras->dhcp))
        goto error;

      /* add subnets */
      if (ras->subnets)
        {
          const unsigned char *value;
          unsigned char *subnet_str;

          if ((subnet_str = ssh_strdup(ras->subnets)) == NULL)
            goto error;

          value = strtok(subnet_str, ";");
          while (value != NULL)
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("Adding subnet %s to address pool %s",
                                       value, ap->address_pool_name));
              if (ssh_pm_address_pool_add_subnet(ap, value) == FALSE)
                {
                  ssh_free(subnet_str);
                  goto error;
                }
              value = strtok(NULL, ";");
            }

          ssh_free(subnet_str);
        }

      /* add address ranges */
      if (ras->addresses)
        {
          char *value1, *address, *netmask, *addr_str;

          if ((addr_str = ssh_strdup(ras->addresses)) == NULL)
            goto error;

          value1 = strtok(addr_str, ";");

          while (value1)
            {
              address = value1;

              /* goto netmask part */
              for (netmask = value1;
                   (*netmask) && (*netmask != '/');
                   netmask++)
                ;

              if (!*netmask)
                {
                  ssh_free(addr_str);
                  goto error;
                }

              /* add null at end of address */
              *(netmask) = '\0';

              netmask = value1 + strlen(address) + 1;

              if (strlen(address) == 0 || strlen(netmask) == 0)
                {
                  ssh_free(addr_str);
                  goto error;
                }

              if (ssh_pm_address_pool_add_range(ap, address, netmask) == FALSE)
                {
                  ssh_free(addr_str);
                  goto error;
                }

              value1 = strtok(NULL, ";");
            }

          ssh_free(addr_str);
        }
    }











  /* Create afresh if there are no existing pool */
  if (!pm->addrpool)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("creating afresh"));
      pm->addrpool = ap;
    }

  /* if this is not first address pool, then check for duplicate */
  else
    {
      SshPmAddressPool prev_ap = pm->addrpool;

      /* check if address pool with same name exists or not */
      for(api = pm->addrpool; api != NULL; prev_ap = api, api = api->next)
        {
          /* Ignore removed address pools. */
          if (api->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED)
            continue;

          if (strcmp(api->address_pool_name, ap->address_pool_name) == 0)
            {
              Boolean compare;
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
              if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
                compare = ssh_pm_dhcp_address_pool_compare(api, ap);
              else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
                compare = ssh_pm_address_pool_compare(api, ap);
              /* compare two address pools */
              if (compare == TRUE)
                {
                  /* No change in addresspool, leave it as it is */
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Found matching unchanged addresspool, "
                             "name %s (id %d)",
                             api->address_pool_name, api->address_pool_id));

#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
                  if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
                    ssh_pm_dhcp_address_pool_destroy(ap);
                  else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
                    ssh_pm_address_pool_destroy(ap);
                  return TRUE;
                }
              else
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Found matching changed address pool, "
                             "name %s (id %d)",
                             api->address_pool_name, api->address_pool_id));

                  /* Insert new address pool before the old one. */
                  if (api == pm->addrpool)
                    {
                      pm->addrpool = ap;
                      ap->next = api;
                    }
                  else
                    {
                      prev_ap->next = ap;
                      ap->next = api;
                    }

                  /* Remove old addrpool. */
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Removing old address pool, "
                             "name %s (id %d)",
                             api->address_pool_name, api->address_pool_id));
                  pm_ras_remove_addrpool(pm, api);
                  goto out;
                }
            }
        }
      SSH_ASSERT(api == NULL && prev_ap != NULL);

      /* No matching addrpool found, create new one at the end of list*/
      prev_ap->next = ap;
    }

  /* Increment address pool count */
  pm->num_address_pools++;

 out:
  if (ap->address_pool_id == pm->addrpool_id_next)
    pm->addrpool_id_next++;

  SSH_DEBUG(SSH_D_HIGHOK, ("Created addrpool, name %s, (id %d)",
                           ap->address_pool_name,
                           ap->address_pool_id));

  return TRUE;

 error:
  if (ap)
    {
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
      if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
        ssh_pm_dhcp_address_pool_destroy(ap);
      else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
        ssh_pm_address_pool_destroy(ap);
    }

  /* Free the address pool name that this function has allocated
     because no name was given in params. */
  if (ras->name != NULL && strcmp(ras->name, ADDRPOOL_DEFAULT_NAME) == 0)
    {
      ssh_free(ras->name);
      ras->name = NULL;
    }

  return FALSE;
}

Boolean ssh_pm_address_pool_foreach_get_stats(SshPm pm,
                                     SshPmAddressPoolStatsCB callback,
                                     void *context)
{

  SshPmAddressPoolStatsStruct stats;
  unsigned char name[128] = {'\0'};
  SshPmAddressPool ap;

  if (callback == NULL)
    return FALSE;

  for (ap = pm->addrpool; ap != NULL; ap = ap->next)
    {
      /* Skip removed address pools. */
      if (ap->flags & SSH_PM_RAS_ADDRPOOL_FLAG_REMOVED)
        continue;

      memset(&stats , 0, sizeof(stats));
      memset(name, 0, sizeof(name));
      stats.name = name;
      ssh_strncpy(stats.name, ap->address_pool_name, sizeof(name));
#ifdef SSH_DHCP_ADDRESS_POOL_ENABLED
      if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL)
        {
          if (ap->flags & SSH_PM_RAS_DHCP_ADDRPOOL_DHCPV6_POOL)
            stats.type = SSH_PM_REMOTE_ACCESS_DHCPV6_POOL;
          else
            stats.type = SSH_PM_REMOTE_ACCESS_DHCP_POOL;
          if (ssh_pm_dhcp_address_pool_get_statistics(ap, &stats) == FALSE)
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not get DHCP statatistics for address pool "
                       "name %s", ap->address_pool_name));
        }
      else
#endif /* SSH_DHCP_ADDRESS_POOL_ENABLED */
        ssh_pm_address_pool_get_statistics(ap, &stats);

      if ((*callback)(pm, &stats, context) == FALSE)
        return FALSE;
    }

  return TRUE;
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
