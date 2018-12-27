/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Storage for active IKE configuration mode clients.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmCfgmodeClientStore"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_ISAKMP_CFG_MODE

/*************************** Pre-allocated tables ***************************/

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
static SshPmActiveCfgModeClientStruct
ssh_pm_active_cfgmode_clients[SSH_PM_MAX_CONFIG_MODE_CLIENTS];
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */

#define SSH_PM_CFGMODE_CLIENT_HASH(peer_handle) \
  ((peer_handle) % SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE)

static void
pm_cfgmode_client_store_timed_renew(void *context);

/************ Public function to manipulate CFGMODE client store ************/

Boolean
ssh_pm_cfgmode_client_store_init(SshPm pm)
{
  int i;

#ifdef SSH_IPSEC_PREALLOCATE_TABLES
  for (i = 0; i < SSH_PM_MAX_CONFIG_MODE_CLIENTS; i++)
    {
      ssh_pm_active_cfgmode_clients[i].peer_handle = SSH_IPSEC_INVALID_INDEX;
      ssh_pm_active_cfgmode_clients[i].next = pm->cfgmode_clients_freelist;
      pm->cfgmode_clients_freelist = &ssh_pm_active_cfgmode_clients[i];
    }
#else /* not SSH_IPSEC_PREALLOCATE_TABLES */
  for (i = 0; i < SSH_PM_MAX_CONFIG_MODE_CLIENTS; i++)
    {
      SshPmActiveCfgModeClient client = ssh_malloc(sizeof(*client));

      if (client == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not allocate client structures"));
          ssh_pm_cfgmode_client_store_uninit(pm);
          return FALSE;
        }
      client->peer_handle = SSH_IPSEC_INVALID_INDEX;
      client->next = pm->cfgmode_clients_freelist;
      pm->cfgmode_clients_freelist = client;
    }
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */

  return TRUE;
}


void
ssh_pm_cfgmode_client_store_uninit(SshPm pm)
{
  int i, j;
  SshPmActiveCfgModeClient client;

  /* Free hash table. */
  for (i = 0; i < SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE; i++)
    {
      while (pm->cfgmode_clients_hash[i])
        {
          client = pm->cfgmode_clients_hash[i];

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
          /* Call radius accounting to stop if it was on. */
          pm_ras_radius_acct_stop(pm, client);
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

          pm->cfgmode_clients_hash[i] = client->next;

          ssh_cancel_timeout(&client->lease_renewal_timer);

          /* Release IP address. */
          for (j = 0; j < client->num_addresses; j++)
            {
              if (client->addresses[j])
                {
                  (*client->free_cb)(pm, client->addresses[j],
                                     client->address_context,
                                     client->ras_cb_context);
                  ssh_free(client->addresses[j]);
                }
            }
#ifndef SSH_IPSEC_PREALLOCATE_TABLES
          ssh_free(client);
#endif /* not SSH_IPSEC_PREALLOCATE_TABLES */
        }
    }

#ifndef SSH_IPSEC_PREALLOCATE_TABLES
  /* Free freelist. */
  while (pm->cfgmode_clients_freelist)
    {
      client = pm->cfgmode_clients_freelist;
      pm->cfgmode_clients_freelist = client->next;

      ssh_free(client);
    }
#endif /* SSH_IPSEC_PREALLOCATE_TABLES */
}

SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_alloc(SshPm pm, SshPmP1 p1)
{
  SshPmActiveCfgModeClient client;
  SshUInt32 hash, peer_handle;

  /* Check if there are free cfgmode_clients left. */
  if (pm->cfgmode_clients_freelist == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of cgmode_clients"));
      return NULL;
    }

  /* Lookup IKE peer entry. */
  peer_handle = ssh_pm_peer_handle_by_p1(pm, p1);
  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      /* On success the created peer has been initialized with one
         reference for the p1 (if there was one) and one reference for
         the caller of the function. Use the latter reference to protect
         client->peer_handle. */
      peer_handle = ssh_pm_peer_create(pm,
                              p1->ike_sa->remote_ip,
                              p1->ike_sa->remote_port,
                              p1->ike_sa->server->ip_address,
                              SSH_PM_IKE_SA_LOCAL_PORT(p1->ike_sa),
                              p1, FALSE,
                              p1->ike_sa->server->routing_instance_id);
      if (peer_handle == SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not create IKE peer for p1 %p", p1));
          return NULL;
        }
    }
  else
    {
      /* Take a reference to protect client->peer_handle. */
      ssh_pm_peer_handle_take_ref(pm, peer_handle);
    }

  /* Allocate client. */
  client = pm->cfgmode_clients_freelist;
  pm->cfgmode_clients_freelist = client->next;

  /* Initialize the client */
  memset(client, 0, sizeof(*client));
  client->pm = pm;
  client->peer_handle = peer_handle;
  client->refcount = 1;
  client->status_cb = NULL_FNPTR;

  /* Link it to the hash table. */
  hash = SSH_PM_CFGMODE_CLIENT_HASH(client->peer_handle);
  client->next = pm->cfgmode_clients_hash[hash];
  pm->cfgmode_clients_hash[hash] = client;

  return client;
}

SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_lookup(SshPm pm, SshUInt32 peer_handle)
{
  SshUInt32 hash;
  SshPmActiveCfgModeClient c;

  SSH_ASSERT(peer_handle != SSH_IPSEC_INVALID_INDEX);
  hash = SSH_PM_CFGMODE_CLIENT_HASH(peer_handle);
  for (c = pm->cfgmode_clients_hash[hash]; c != NULL; c = c->next)
    {
      if (c->peer_handle == peer_handle)
        return c;
    }
  return NULL;
}

/************** Registering addresses to cfgmode client store ***************/

typedef struct SshPmCfgModeClientArpCtxRec
{
  SshPmActiveCfgModeClient client;
  SshUInt32 index;
  Boolean success;
  SshFSMThreadStruct thread;
} *SshPmCfgModeClientArpCtx;

static void
pm_ras_cfgmode_client_arp_abort(void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Aborting cfgmode client address registration"));

  SSH_ASSERT(client != NULL);
  SSH_ASSERT(client->state == SSH_PM_CFGMODE_CLIENT_STATE_ADDING_ARP);

  /* Clear status callback. Let the engine operation complete,
     because it cannot be aborted. */
  client->status_cb = NULL_FNPTR;
  client->flags |= SSH_PM_CFGMODE_CLIENT_ABORTED;
}

static void
pm_ras_cfgmode_client_arp_thread_destructor(SshFSM fsm, void *context)
{
  SshPmCfgModeClientArpCtx arp_ctx = context;
  ssh_free(arp_ctx);
}

static void
pm_cfgmode_client_arp_cb(SshPm pm, Boolean success, void *context)
{
  SshPmCfgModeClientArpCtx arp_ctx = context;

  SSH_ASSERT(arp_ctx != NULL);
  arp_ctx->success = success;

  SSH_DEBUG(SSH_D_LOWOK,
            ("ARP entry add for '%@' %s",
             ssh_ipaddr_render, arp_ctx->client->addresses[arp_ctx->index],
             (success ? "succeeded" : "failed")));

  SSH_FSM_CONTINUE_AFTER_CALLBACK(&arp_ctx->thread);
}

SSH_FSM_STEP(pm_ras_cfgmode_client_add_arp)
{
  SshPm pm = fsm_context;
  SshPmCfgModeClientArpCtx arp_ctx = thread_context;
  unsigned char media_addr[SSH_ETHERH_ADDRLEN];
  SshUInt32 value;
  SshUInt32 flags;
  int i;

  SSH_ASSERT(arp_ctx->index < arp_ctx->client->num_addresses);
  i = arp_ctx->index;

  /* Create a fake ethernet address. */
  memset(media_addr, 0, sizeof(media_addr));
  if (SSH_IP_IS4(arp_ctx->client->addresses[i]))
    {
      media_addr[1] = 2;
      SSH_IP4_ENCODE(arp_ctx->client->addresses[i], media_addr + 2);
      arp_ctx->client->flags |= SSH_PM_CFGMODE_CLIENT_IPV4_PROXY_ARP;
    }
  else
    {
      value = SSH_IP6_WORD0_TO_INT(arp_ctx->client->addresses[i]);
      value ^= SSH_IP6_WORD1_TO_INT(arp_ctx->client->addresses[i]);
      value ^= SSH_IP6_WORD2_TO_INT(arp_ctx->client->addresses[i]);
      value ^= SSH_IP6_WORD3_TO_INT(arp_ctx->client->addresses[i]);
      media_addr[1] = 2;
      SSH_PUT_32BIT(media_addr + 2, value);
      arp_ctx->client->flags |= SSH_PM_CFGMODE_CLIENT_IPV6_PROXY_ARP;
    }

  /* Flags for ARP entry. */
  flags = SSH_PME_ARP_PERMANENT | SSH_PME_ARP_GLOBAL | SSH_PME_ARP_PROXY;

  /* Add ARP entry. */
  SSH_DEBUG(SSH_D_LOWSTART,
            ("Adding ARP entry for '%@'",
             ssh_ipaddr_render, arp_ctx->client->addresses[i]));

  SSH_FSM_SET_NEXT(pm_ras_cfgmode_client_add_arp_result);
  SSH_FSM_ASYNC_CALL({
      ssh_pme_arp_add(pm->engine, arp_ctx->client->addresses[i], 0,
                      media_addr, sizeof(media_addr),
                      flags, pm_cfgmode_client_arp_cb, arp_ctx);
    });
  SSH_NOTREACHED;
}

SSH_FSM_STEP(pm_ras_cfgmode_client_add_arp_result)
{
  SshPm pm = fsm_context;
  SshPmCfgModeClientArpCtx arp_ctx = thread_context;
  int i;

  SSH_ASSERT(arp_ctx != NULL);
  SSH_ASSERT(arp_ctx->index < arp_ctx->client->num_addresses);
  arp_ctx->index++;

  if (arp_ctx->success == TRUE)
    {
      /* Continue to add an ARP entry for next client address. */
      if (arp_ctx->index < arp_ctx->client->num_addresses)
        SSH_FSM_SET_NEXT(pm_ras_cfgmode_client_add_arp);
      else
        SSH_FSM_SET_NEXT(pm_ras_cfgmode_client_add_arp_done);
    }
  else
    {
      /* Remove any added ARP entries from engine. */
      for (i = 0; i < arp_ctx->index; i++)
        ssh_pme_arp_remove(pm->engine, arp_ctx->client->addresses[i], 0);

      /* Clear registered addresses from client store entry. */
      for (i = 0; i < arp_ctx->client->num_addresses; i++)
        {
          ssh_free(arp_ctx->client->addresses[i]);
          arp_ctx->client->addresses[i] = NULL;
        }

      SSH_FSM_SET_NEXT(pm_ras_cfgmode_client_add_arp_done);
    }

  return SSH_FSM_CONTINUE;
}

SSH_FSM_STEP(pm_ras_cfgmode_client_add_arp_done)
{
  SshPm pm = fsm_context;
  SshPmCfgModeClientArpCtx arp_ctx = thread_context;

  /* Unregister abort callback, unless operation was aborted. */
  if ((arp_ctx->client->flags & SSH_PM_CFGMODE_CLIENT_ABORTED) == 0)
    ssh_operation_unregister(&arp_ctx->client->operation);

  /* Clear state. */
  arp_ctx->client->state = SSH_PM_CFGMODE_CLIENT_STATE_IDLE;

  /* Complete registration. */
  if (arp_ctx->client->status_cb != NULL_FNPTR)
    (*arp_ctx->client->status_cb)(pm, arp_ctx->success,
                                  arp_ctx->client->status_cb_context);
  arp_ctx->client->status_cb = NULL_FNPTR;

  /* Release the reference to cfgmode client. */
  SSH_PM_CFGMODE_CLIENT_FREE_REF(pm, arp_ctx->client);
  arp_ctx->client = NULL;

  return SSH_FSM_FINISH;
}

SshOperationHandle
ssh_pm_cfgmode_client_store_register(SshPm pm,
                                     SshPmTunnel tunnel,
                                     SshPmActiveCfgModeClient client,
                                     SshPmRemoteAccessAttrs attributes,
                                     SshPmRemoteAccessAttrsAllocCB renew_cb,
                                     SshPmRemoteAccessAttrsFreeCB free_cb,
                                     void *ras_cb_context,
                                     SshPmStatusCB status_cb,
                                     void *status_cb_context)
{
  int i = 0;
  SshPmCfgModeClientArpCtx arp_ctx;

  SSH_ASSERT(client != NULL);
  SSH_ASSERT(client->status_cb == NULL_FNPTR);

  if (client->state != SSH_PM_CFGMODE_CLIENT_STATE_IDLE)
    goto error;

  client->num_addresses = attributes->num_addresses;
  for (i = 0; i < attributes->num_addresses; i++)
    {
      if (!SSH_IP_DEFINED(&attributes->addresses[i]))
        goto error;

      SSH_DEBUG(SSH_D_LOWOK, ("Registering address `%@'",
                              ssh_ipaddr_render, &attributes->addresses[i]));
      client->addresses[i] = ssh_memdup(&attributes->addresses[i],
                                        sizeof(SshIpAddrStruct));
      if (client->addresses[i] == NULL)
        goto error;
    }
  client->address_context = attributes->address_context;

  client->renew_cb = renew_cb;
  client->free_cb = free_cb;
  client->ras_cb_context = ras_cb_context;
  client->lease_time = attributes->lease_renewal;

  if (client->lease_time > 0)
    ssh_register_timeout(&client->lease_renewal_timer, client->lease_time, 0,
                         pm_cfgmode_client_store_timed_renew, client);

  /* Check if we should add a proxy ARP entry for the remote access client. */
  if (tunnel->flags & SSH_PM_TR_PROXY_ARP)
    {
      /* Store status_cb. */
      client->status_cb = status_cb;
      client->status_cb_context = status_cb_context;

      arp_ctx = ssh_calloc(1, sizeof(*arp_ctx));
      if (arp_ctx == NULL)
        goto error;

      /* Take a reference to the client. */
      SSH_PM_CFGMODE_CLIENT_TAKE_REF(pm, client);
      arp_ctx->client = client;

      ssh_fsm_thread_init(&pm->fsm, &arp_ctx->thread,
                          pm_ras_cfgmode_client_add_arp,
                          NULL_FNPTR,
                          pm_ras_cfgmode_client_arp_thread_destructor,
                          arp_ctx);

      client->state = SSH_PM_CFGMODE_CLIENT_STATE_ADDING_ARP;

      /* Register an operation handle for aborting the arp thread. */
      ssh_operation_register_no_alloc(&client->operation,
                                      pm_ras_cfgmode_client_arp_abort,
                                      client);
      return &client->operation;
    }

  if (status_cb != NULL_FNPTR)
    (*status_cb)(pm, TRUE, status_cb_context);

  return NULL;

 error:
  for (i = 0; i < client->num_addresses; i++)
    {
      ssh_free(client->addresses[i]);
      client->addresses[i] = NULL;
    }

  if (status_cb != NULL_FNPTR)
    (*status_cb)(pm, FALSE, status_cb_context);

  return NULL;
}


/*************************** Address renewal ********************************/
static void
pm_cfgmode_client_store_timed_renew_status_cb(SshPm pm, Boolean success,
                                                  void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Client address renewal %s",
                          (success ? "succeeded" : "failed")));

  /* If DHCP lease renewal failed delete IKE and IPsec SAs, otherwise do
     nothing. */
  if (success == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Client address renewal failed, releasing"));
      ssh_cancel_timeout(&client->lease_renewal_timer);
      ssh_pm_delete_by_peer_handle(client->pm, client->peer_handle,
                                   0, NULL_FNPTR, NULL);
    }
}

static void
pm_cfgmode_client_store_timed_renew(void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Launching timer invoked address lease renewal."));
  ssh_pm_cfgmode_client_store_renew(
                           client->pm, client,
                           pm_cfgmode_client_store_timed_renew_status_cb,
                           client);

}

static void
pm_cfgmode_client_store_renew_abort(void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

  SSH_DEBUG(SSH_D_LOWOK, ("Aborting cfgmode client address renewal"));
  SSH_ASSERT(client->state == SSH_PM_CFGMODE_CLIENT_STATE_RENEWING);

  /* Abort the renewal sub operation, mark operation aborted and clear
     status_cb. */
  if (client->sub_operation != NULL)
    ssh_operation_abort(client->sub_operation);
  client->sub_operation = NULL;

  client->status_cb = NULL_FNPTR;
  client->flags |= SSH_PM_CFGMODE_CLIENT_ABORTED;

  /* Release the reference to cfgmode client. */
  SSH_PM_CFGMODE_CLIENT_FREE_REF(client->pm, client);
}

static void
pm_cfgmode_client_store_renew_cb(SshPmRemoteAccessAttrs attributes,
                                 void *context)
{
  SshPmActiveCfgModeClient client = (SshPmActiveCfgModeClient) context;

  /* Renewal sub operation has completed, clear sub operation handle
     and unregister our operation handle. */
  SSH_ASSERT(client->state == SSH_PM_CFGMODE_CLIENT_STATE_RENEWING);

  if (client->sub_operation != NULL
      && (client->flags & SSH_PM_CFGMODE_CLIENT_ABORTED) == 0)
    ssh_operation_unregister(&client->operation);

  client->sub_operation = NULL;
  client->state = SSH_PM_CFGMODE_CLIENT_STATE_IDLE;

  if (attributes == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cfgmode client address renewal failed"));
      if (client->status_cb != NULL_FNPTR)
        (*client->status_cb)(client->pm, FALSE, client->status_cb_context);
      client->status_cb = NULL_FNPTR;
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Cfgmode client address renewal succeeded"));
      client->lease_time = attributes->lease_renewal;
      if (client->status_cb != NULL_FNPTR)
        (*client->status_cb)(client->pm, TRUE, client->status_cb_context);
      client->status_cb = NULL_FNPTR;

      /* Set up a new timeout for lease renewal. */
      if (client->lease_time > 0)
        ssh_register_timeout(&client->lease_renewal_timer,
                             client->lease_time, 0,
                             pm_cfgmode_client_store_timed_renew, client);
    }

  /* Release the reference to cfgmode client. */
  SSH_PM_CFGMODE_CLIENT_FREE_REF(client->pm, client);
}

SshOperationHandle
ssh_pm_cfgmode_client_store_renew(SshPm pm,
                                  SshPmActiveCfgModeClient client,
                                  SshPmStatusCB status_cb,
                                  void *status_cb_context)
{
  SshPmAuthDataStruct ad[1];
  SshPmRemoteAccessAttrsStruct attrs[1];
  SshOperationHandle sub_operation;
  int i;

  if (client->state != SSH_PM_CFGMODE_CLIENT_STATE_IDLE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cfgmode client address renewal in progress"));
      if (status_cb != NULL_FNPTR)
        (*status_cb)(pm, FALSE, status_cb_context);
      return NULL;
    }

  if (client->num_addresses == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No cfgmode client addresses to renew"));
      if (status_cb != NULL_FNPTR)
        (*status_cb)(pm, TRUE, status_cb_context);
      return NULL;
    }

  if (client->renew_cb == NULL_FNPTR)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("No cfgmode client renew callback specified"));
      if (status_cb != NULL_FNPTR)
        (*status_cb)(pm, TRUE, status_cb_context);
      return NULL;
    }

  /* Cancel possible renewal timeouts, the renewal may be invoked by IKE rekey
     as well. */
  ssh_cancel_timeout(&client->lease_renewal_timer);

  /* Lookup p1 for authentication data. */
  memset(ad, 0x0, sizeof(*ad));
  ad->pm = pm;
  ad->p1 = ssh_pm_p1_by_peer_handle(pm, client->peer_handle);
  if (ad->p1 == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,("No IKE SA found for peer 0x%lx",
                            client->peer_handle));
    }

  /* Create remote access attributes from cfgmode client store
     addresses. */
  memset(&attrs, 0, sizeof(attrs));
  for (i = 0; i < client->num_addresses; i++)
    {
      if (client->addresses[i] != NULL)
        {
          memcpy(&attrs->addresses[attrs->num_addresses], client->addresses[i],
                 sizeof(SshIpAddrStruct));
          attrs->num_addresses++;
        }
    }
  attrs->address_context = client->address_context;

  SSH_ASSERT(attrs->num_addresses > 0);

  /* Take a reference to the client. */
  SSH_PM_CFGMODE_CLIENT_TAKE_REF(pm, client);

  client->status_cb = status_cb;
  client->status_cb_context = status_cb_context;
  client->state = SSH_PM_CFGMODE_CLIENT_STATE_RENEWING;

  /* Call remote access address alloc callback to renew attributes. */
  sub_operation =
    (*client->renew_cb)(pm, ad, SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW,
                        attrs, pm_cfgmode_client_store_renew_cb, client,
                        client->ras_cb_context);

  /* Renew operation completed synchronously. */
  if (sub_operation == NULL)
    return NULL;

  /* Register an abort callback for the renewal operation. */
  SSH_ASSERT(client->sub_operation == NULL);
  client->sub_operation = sub_operation;

  ssh_operation_register_no_alloc(&client->operation,
                                  pm_cfgmode_client_store_renew_abort,
                                  client);

  return &client->operation;
}


/*********************** Freeing cgfmode client store addresses **************/

static void
pm_cfgmode_client_store_free(SshPm pm, SshPmActiveCfgModeClient client)
{
  int i;

  for (i = 0; i < client->num_addresses; i++)
    {
      if (client->addresses[i] != NULL)
        {
          if ((SSH_IP_IS4(client->addresses[i]) &&
               (client->flags & SSH_PM_CFGMODE_CLIENT_IPV4_PROXY_ARP)) ||
              (SSH_IP_IS6(client->addresses[i]) &&
               (client->flags & SSH_PM_CFGMODE_CLIENT_IPV6_PROXY_ARP)))
            ssh_pme_arp_remove(pm->engine, client->addresses[i], 0);

          ssh_free(client->addresses[i]);
          client->addresses[i] = NULL;
        }
    }

  if (client->peer_handle != SSH_IPSEC_INVALID_INDEX)
    ssh_pm_peer_handle_destroy(pm, client->peer_handle);
  client->peer_handle = SSH_IPSEC_INVALID_INDEX;

  client->next = pm->cfgmode_clients_freelist;
  pm->cfgmode_clients_freelist = client;
}

void
ssh_pm_cfgmode_client_store_unreference(SshPm pm,
                                        SshPmActiveCfgModeClient client)
{
  SshUInt32 hash;
  SshPmActiveCfgModeClient *clientp;
  int j;

  /* Lookup the client. */
  SSH_ASSERT(client != NULL);
  SSH_ASSERT(client->peer_handle != SSH_IPSEC_INVALID_INDEX);
  hash = SSH_PM_CFGMODE_CLIENT_HASH(client->peer_handle);
  for (clientp = &pm->cfgmode_clients_hash[hash];
       *clientp;
       clientp = &(*clientp)->next)
    {
      if (*clientp == client)
        {
          if (--client->refcount > 0)
            /* This was not the last reference. */
            return;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
          /* Call radius accounting to stop if it was on. */
          pm_ras_radius_acct_stop(pm, client);
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

          /* Remove it from the hash table. */
          *clientp = client->next;

          /* Cancel renewal timeout */
          ssh_cancel_timeout(&client->lease_renewal_timer);

          /* Release the IP address. */
          for (j = 0; j < client->num_addresses; j++)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Releasing addresses `%@'",
                                      ssh_ipaddr_render,
                                      client->addresses[j]));
              if (client->free_cb != NULL_FNPTR)
                {
                  if (client->addresses[j] != NULL)
                    (*client->free_cb)(pm, client->addresses[j],
                                       client->address_context,
                                       client->ras_cb_context);
                }
            }

          /* And recycle the registry structure. */
          pm_cfgmode_client_store_free(pm, client);
          return;
        }
    }
}

void
ssh_pm_cfgmode_client_store_take_reference(SshPm pm,
                                           SshPmActiveCfgModeClient client)
{
  client->refcount++;
}
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
