/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common functions for virtual IP.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#define SSH_DEBUG_MODULE "SshPmVirtualIp"

/****************************** Static helper functions **********************/

/* If the IP address range from `addr_low' to `addr_high', inclusive,
   can be represented as an address prefix and mask, store that
   representation in `prefix' and return TRUE. */
static
Boolean ssh_pm_addr_range_to_prefix(SshIpAddr prefix,
                                    const SshIpAddr addr_low,
                                    const SshIpAddr addr_high)
{
  int bytes, mask_len, i, j;
  const unsigned char *adl = addr_low->addr_union._addr_data;
  const unsigned char *adh = addr_high->addr_union._addr_data;
  unsigned char bl, bh;

  if (SSH_IP_IS4(addr_low) && SSH_IP_IS4(addr_high))
    bytes = 4;
  else if (SSH_IP_IS6(addr_low) && SSH_IP_IS6(addr_high))
    bytes = 16;
  else
    return FALSE;

  /* Scan to first differing byte, if any. */
  for (i = 0; i < bytes; i++)
    if (adl[i] != adh[i])
      break;

  /* Return prefix with all-ones mask if no differences found. */
  if (i >= bytes)
    {
      memcpy(prefix, addr_low, sizeof *prefix);
      prefix->mask_len = bytes * 8;
      return TRUE;
    }

  bl = adl[i];
  bh = adh[i];

  /* Scan to first differing bit in the differing byte. */
  for (j = 0; j < 8; j++)
    {
      if (((bl ^ bh) & 0x80))
        break;
      bl <<= 1;
      bh <<= 1;
    }

  mask_len = i * 8 + j;

  /* The rest of the bits should be zero in the low address and one in
     the high address. */
  for (; j < 8; j++)
    {
      if ((bl & 0x80) && !(bh & 0x80))
        return FALSE;
      bl <<= 1;
      bh <<= 1;
    }
  for (i++; i < bytes; i++)
    {
      if (adl[i] != 0x00 || adh[i] != 0xff)
        return FALSE;
    }

  /* Return prefix. */
  memcpy(prefix, addr_low, sizeof *prefix);
  ssh_ipaddr_set_bits(prefix, addr_low, mask_len, 0);
  prefix->mask_len = mask_len;
  return TRUE;
}

/****************************** Vip Utility Functions ************************/

void
ssh_pm_vip_mark_unusable(SshPm pm, SshPmP1 p1)
{
  SshPmTunnel tunnel;

  /* Lookup tunnel for p1. */
  tunnel = ssh_pm_p1_get_tunnel(pm, p1);
  if (tunnel == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not find tunnel for IKE SA %p, tunnel_id %d",
                 p1->ike_sa, p1->tunnel_id));
      return;
    }

  if (tunnel->vip)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Marking virtual interface unusable"));
      tunnel->vip->unusable = 1;
      ssh_fsm_condition_broadcast(&pm->fsm, &tunnel->vip->cond);
    }
}

SshPmVirtualAdapter
ssh_pm_virtual_adapter_find_byifnum(SshPm pm, SshUInt32 adapter_ifnum)
{
  SshUInt32 i;

  for (i = 0; i < pm->num_virtual_adapters; i++)
    if (adapter_ifnum == pm->virtual_adapters[i].adapter_ifnum)
      return &pm->virtual_adapters[i];

  return NULL;
}

/* Callback function for ssh_pme_virtual_adapter_list, which is called
   asynchronously from thread context. Argument `context' is the SshFSMThread.
   This function will call SSH_FSM_CONTINUE_AFTER_CALLBACK. */
void
ssh_pm_vip_get_virtual_adapters_cb(SshPm pm,
                                   SshVirtualAdapterError error,
                                   SshUInt32 num_adapters,
                                   SshPmeVirtualAdapter adapters,
                                   void *context)
{
  SshUInt32 i;
  SshADTHandle handle;
  SshPmTunnel tunnel;

  if (error == SSH_VIRTUAL_ADAPTER_ERROR_OK)
    {
      /* Free old list of virtual adapters. */
      ssh_free(pm->virtual_adapters);
      pm->virtual_adapters = NULL;
      pm->num_virtual_adapters = 0;

      SSH_DEBUG(SSH_D_MIDOK, ("Got %d virtual adapters",
                              (int) num_adapters));

      /* Copy new virtual adapters. */
      if (num_adapters > 0)
        {
          pm->virtual_adapters = ssh_calloc(num_adapters,
                                            sizeof(pm->virtual_adapters[0]));
          if (pm->virtual_adapters == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("Could not allocate memory for virtual adapters"));
              goto out;
            }

          for (i = 0; i < num_adapters; i++)
            {
              SSH_DEBUG(SSH_D_MIDOK,
                        ("Virtual adapter %d [%s] state %s",
                         (int) adapters[i].adapter_ifnum,
                         adapters[i].adapter_name,
                         (adapters[i].adapter_state
                          == SSH_VIRTUAL_ADAPTER_STATE_UP ? "up" : "down")));

              pm->virtual_adapters[i].adapter_ifnum =
                adapters[i].adapter_ifnum;
              ssh_snprintf(pm->virtual_adapters[i].adapter_name,
                           SSH_INTERCEPTOR_IFNAME_SIZE,
                           "%s", adapters[i].adapter_name);
            }
          pm->num_virtual_adapters = num_adapters;
        }

      /* Iterate through tunnels and mark reserved adapters. */
      for (handle = ssh_adt_enumerate_start(pm->tunnels);
           handle != SSH_ADT_INVALID;
           handle = ssh_adt_enumerate_next(pm->tunnels, handle))
        {
          tunnel = (SshPmTunnel) ssh_adt_get(pm->tunnels, handle);
          if (tunnel != NULL)
            {
              /* This is ok, as num_adapters is a small interger. */
              for (i = 0; i < num_adapters; i++)
                {
                  if (strcmp(pm->virtual_adapters[i].adapter_name,
                             tunnel->vip_name) == 0)
                    {
                      pm->virtual_adapters[i].reserved = TRUE;
                      break;
                    }
                }
              if (i == num_adapters)
                SSH_DEBUG(SSH_D_FAIL,
                          ("Tunnel specifies non-existent "
                           "virtual adapter '%s'", tunnel->vip_name));
            }
        }
    }
  else
    SSH_DEBUG(SSH_D_FAIL, ("Could not get virtual adapters from engine"));

 out:
  SSH_FSM_CONTINUE_AFTER_CALLBACK((SshFSMThread) context);
}


/****************************** Interface Trigger ****************************/

/* This function is called from a timeout to destroy the virtual adapter. */
static void
ssh_pm_vip_destroy_timeout(void *context)
{
  SshPmVip vip = (SshPmVip) context;

  SSH_ASSERT(vip != NULL);
  SSH_PM_ASSERT_PM(vip->pm);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Received interface down timeout for virtual adapter %d [%s]",
             (int) vip->adapter_ifnum, vip->adapter_name));

  /* Signal vip object to start shutting down. */
  vip->shutdown = 1;
  ssh_fsm_condition_broadcast(&vip->pm->fsm, &vip->cond);
}

/* This function checks if a tunnel handles interface triggers and installs
   a timer to destroy the virtual IP context. If this returns TRUE, then the
   auto-start thread should start the virtual IP thread. If this returns FALSE,
   then the auto-start thread can ignore the rule. */
Boolean
ssh_pm_vip_rule_interface_trigger(SshPm pm, SshPmRule rule)
{
  SshInterceptorInterface *ifp = NULL;
  SshUInt32 ifnum;
  SshPmVip vip;
  SshUInt32 i;

  if (!SSH_PM_RULE_IS_VIRTUAL_IP(rule))
    return FALSE;

  SSH_ASSERT(rule->side_to.tunnel != NULL);
  vip = rule->side_to.tunnel->vip;

  if ((rule->side_to.tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER)
      && (rule->side_to.tunnel->flags & SSH_PM_TI_DELAYED_OPEN))
    {
      if (vip != NULL)
        {
          /* Lookup virtual adapter. */
          ifp = ssh_pm_find_interface_by_ifnum(pm, vip->adapter_ifnum);

          /* Interface is up. */
          if (ifp != NULL)
            {
              /* If the virtual adapter was configured down earlier and
                 is now waiting for destroy, then just cancel the destroy
                 timer. */
              if (vip->waiting_for_destroy)
                {
                  SSH_DEBUG(SSH_D_MIDOK,
                            ("Cancelled interface down timeout for "
                             "virtual adapter %d [%s]",
                             (int) vip->adapter_ifnum, vip->adapter_name));
                  ssh_cancel_timeout(&vip->timeout_struct);
                  vip->waiting_for_destroy = 0;

                  /* Reconfigure VIP addrs and routes. */
                  vip->reconfigure = 1;
                  ssh_fsm_condition_broadcast(&pm->fsm, &vip->cond);
                }

              /* The virtual adapter is up and running, check rule status. */

              /* Rule is up, nothing to do. */
              if (rule->side_to.as_up)
                return FALSE;

              /* Rule is not up, return TRUE to auto-start negotiation. */
              else
                return TRUE;
            }

          /* Interface is down. */

          /* Destroy timeout has already been registered, nothing to do. */
          if (vip->waiting_for_destroy)
            return FALSE;

          /* Virtual adapter is not yet up, no need to do anything,
             the adapter will either be brought up when it is configured
             or it will stay down. */
          if (vip->unusable)
            return FALSE;

          /* Register a timeout to delete the virtual IP thread,
             IKE SA, and IPsec SAs. */
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Registering timer to destroy virtual IP context."));
          ssh_register_timeout(&vip->timeout_struct,
                               SSH_PM_VIRTUAL_ADAPTER_DOWN_TIMEOUT, 0,
                               ssh_pm_vip_destroy_timeout, vip);
          vip->waiting_for_destroy = 1;

          /* Mark all VIP routes to be removed. */
          for (i = 0; i < vip->num_routes; i++)
            {
              if (vip->routes[i].added == 1)
                vip->routes[i].remove = 1;
            }

          /* Signal vip thread to remove marked routes. */
          vip->remove_routes = 1;
          vip->add_routes = 0;
          vip->reconfigure = 0;
          ssh_fsm_condition_broadcast(&pm->fsm, &vip->cond);
          return FALSE;
        }

      /* This tunnel does not have a virtual adapter context. */

      /* Tunnel defines the name of virtual adapter to use. */
      if (strlen(rule->side_to.tunnel->vip_name) > 0)
        {
          ifp = ssh_pm_find_interface(pm,
                                      rule->side_to.tunnel->vip_name,
                                      &ifnum);
        }
      /* There is only one virtual adapter in the system, use that. */
      else if (pm->num_virtual_adapters == 1
               && !pm->virtual_adapters[0].reserved
               && !pm->virtual_adapters[0].in_use)
        {
          ifp = ssh_pm_find_interface_by_ifnum(pm,
                                        pm->virtual_adapters[0].adapter_ifnum);
        }

      /* The virtual adapter is up. */
      if (ifp != NULL)
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Received interface trigger for virtual adapter %d [%s]",
                     (int) ifp->ifnum, ifp->name));
          return TRUE;
        }

      /* The virtual adapter is down, nothing to do. */
      return FALSE;
    }

  /* The tunnel is not triggered by interface events. */
  return FALSE;
}


/****************************** Creating / Deleting Routes *******************/

/* Create a route entry. */
static void
pm_vip_create_route(SshPmVip vip, SshIpAddr prefix, SshUInt32 trd_index,
                    SshPmRule rule)
{
  SshPmVipRoute r = NULL;
  SshUInt32 i;

  SSH_ASSERT(vip->num_routes <= SSH_PM_VIRTUAL_IP_MAX_ROUTES);

  /* Check if route already exists. */
  for (i = 0; i < vip->num_routes; i++)
    {
      r = &vip->routes[i];
      if (SSH_IP_EQUAL(&r->prefix, prefix) &&
          r->prefix.mask_len == prefix->mask_len &&
          r->trd_index == trd_index)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Route to network %@ already created",
                     ssh_ipaddr_render, prefix));
          return;
        }
    }

  /* Find a cleared entry. */
  for (i = 0; i < vip->num_routes; i++)
    {
      r = &vip->routes[i];
      if (!SSH_IP_DEFINED(&r->prefix))
        break;
    }

  if (i >= vip->num_routes)
    {
      if (vip->num_routes >= SSH_PM_VIRTUAL_IP_MAX_ROUTES)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Maximum number of virtual IP routes reached"));
          return;
        }

      r = &vip->routes[vip->num_routes];
      vip->num_routes++;
    }

  memset(r, 0, sizeof *r);
  memcpy(&r->prefix, prefix, sizeof r->prefix);

  r->trd_index = trd_index;
  r->rule = rule;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Created route to network %@", ssh_ipaddr_render, &r->prefix));

  /** Check if an equal transform route has already been added and if so
      then mark this route added as well. */
  for (i = 0; i < vip->num_routes; i++)
    {
      if (r == &vip->routes[i])
        continue;

      if (SSH_IP_EQUAL(&vip->routes[i].prefix, &r->prefix) &&
          vip->routes[i].prefix.mask_len == r->prefix.mask_len &&
          vip->routes[i].added == 1)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Equal route to network %@ "
                     "has already been added to system routing table",
                     ssh_ipaddr_render, &r->prefix));
          r->added = 1;
          break;
        }
    }
}

void
ssh_pm_vip_flush_sgw_routes(SshPmVip vip)
{
  SshUInt32 i;

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Flushing all VIP SGW routes."));

  /* Mark all the SGW routes to be removed. */
  for (i = 0; i < SSH_PM_VIRTUAL_IP_MAX_SGW_ADDRESSES; i++)
    {
      if (SSH_IP_DEFINED(&vip->sgw[i].sgw_address))
        vip->sgw[i].remove = 1;
    }
}

/* Create a SGW route placeholder entry. */
void
ssh_pm_vip_create_sgw_route(SshPmVip vip, SshIpAddr sgw_ip)
{
  SshUInt32 i, first_empty_slot = SSH_IPSEC_INVALID_INDEX;
  Boolean found = FALSE;

  SSH_ASSERT(vip != NULL);
  SSH_ASSERT(sgw_ip != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(sgw_ip));

  SSH_DEBUG(SSH_D_LOWOK, ("Adding SGW '%@' ip to SGW routes",
                          ssh_ipaddr_render, sgw_ip));

  /* Look in the table if we have this address already defined. */
  for (i = 0; i < SSH_PM_VIRTUAL_IP_MAX_SGW_ADDRESSES; i++)
    {
      /* Yes we have, mark it as valid. */
      if (SSH_IP_DEFINED(&vip->sgw[i].sgw_address) &&
          SSH_IP_EQUAL(&vip->sgw[i].sgw_address, sgw_ip))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Found existing route entry, marked valid"));
          found = TRUE;
          vip->sgw[i].remove = 0;
          return;
        }

      if (SSH_IP_DEFINED(&vip->sgw[i].sgw_address) == FALSE)
        first_empty_slot = i;
    }

  if (found == FALSE && first_empty_slot != SSH_IPSEC_INVALID_INDEX)
    {
      memset(&vip->sgw[first_empty_slot], 0x0, sizeof(SshPmVipSgwRouteStruct));
      vip->sgw[first_empty_slot].sgw_address = *sgw_ip;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Added SGW to slot %u", first_empty_slot));
}

/* Create a route entry to narrowed traffic selector. */
void
ssh_pm_vip_create_transform_route(SshPmVip vip, SshIkev2PayloadTSItem item,
                                  SshUInt32 trd_index)
{
  SshIpAddrStruct p;

  if (!ssh_pm_addr_range_to_prefix(&p, item->start_address, item->end_address))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot convert dst %@ to route prefix",
                             ssh_ikev2_ts_render_item, item));
      return;
    }

  pm_vip_create_route(vip, &p, trd_index, NULL);
}

void
ssh_pm_vip_create_rule_route(SshPmVip vip, SshIkev2PayloadTSItem item,
                             SshPmRule rule)
{
  SshIpAddrStruct p;

  if (!ssh_pm_addr_range_to_prefix(&p, item->start_address, item->end_address))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot convert dst %@ to route prefix",
                             ssh_ikev2_ts_render_item, item));
      return;
    }

  pm_vip_create_route(vip, &p, SSH_IPSEC_INVALID_INDEX, rule);
}

void
ssh_pm_vip_create_subnet_route(struct SshPmVipRec *vip, SshIpAddr prefix)
{
  pm_vip_create_route(vip, prefix, SSH_IPSEC_INVALID_INDEX, NULL);
}

static void
ssh_pm_vip_delete_routes(SshPm pm, SshUInt32 trd_index, SshPmTunnel tunnel)
{
  SshPmVip vip = tunnel->vip;
  SshPmVipRoute route;
  SshUInt32 i;

  SSH_ASSERT(vip != NULL);

  for (i = 0; i < vip->num_routes; i++)
    {
      route = &vip->routes[i];
      if (route->trd_index == trd_index && route->added == 1)
        {
          route->remove = 1;
          route->clear = 1;
          route->trd_index = SSH_IPSEC_INVALID_INDEX;
        }
    }

  /* Signal vip thread to remove marked routes. */
  vip->remove_routes = 1;
  ssh_fsm_condition_broadcast(&pm->fsm, &vip->cond);
}


/****************************** Vip Reference Counting ***********************/

Boolean
ssh_pm_virtual_ip_take_ref(SshPm pm, SshPmTunnel tunnel)
{
  if (!tunnel || !SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Bad tunnel for virtual IP"));
      return FALSE;
    }

  if (!tunnel->vip)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Virtual IP not started"));
      return FALSE;
    }

  if (tunnel->vip->t_l2tp)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Virtual adapter not incremented, since "
                              "using L2TP."));
      /* L2tp is not referenced for virtual adapter, since it is not needed
         as only one IPsec SA can exist. */
      return TRUE;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Incrementing virtual adapter refcount to %ld",
                             (long) tunnel->vip->refcnt + 1));

  tunnel->vip->refcnt++;

  return TRUE;
}

Boolean
ssh_pm_virtual_ip_free(SshPm pm, SshUInt32 trd_index, SshPmTunnel tunnel)
{
  if (!tunnel || !SSH_PM_TUNNEL_IS_VIRTUAL_IP(tunnel))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Bad tunnel for virtual IP"));
      return FALSE;
    }

  if (!tunnel->vip)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Virtual IP not started"));
      return FALSE;
    }

  if (tunnel->vip->t_l2tp)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Virtual adapter not decremented, since "
                              "using L2TP."));
      /* L2tp is not referenced for virtual adapter, since it is not needed
         as only one IPsec SA can exist. */
      return TRUE;
    }

  SSH_DEBUG(SSH_D_LOWSTART, ("Decrementing virtual adapter refcount to %ld",
                             (long) tunnel->vip->refcnt - 1));

  SSH_ASSERT(tunnel->vip->refcnt > 0);
  tunnel->vip->refcnt--;

  /* Remove and delete all routes for this IPsec SA. */
  if (trd_index != SSH_IPSEC_INVALID_INDEX)
    ssh_pm_vip_delete_routes(pm, trd_index, tunnel);

  /* Stop virtual adapter. */
  if (tunnel->vip->refcnt == 0)
    ssh_pm_stop_virtual_ip(pm, tunnel);

  return TRUE;
}

Boolean ssh_pm_address_is_virtual(SshPm pm, SshPmVip vip, SshIpAddr addr)
{
  int i;

  if (vip == NULL)
    return FALSE;

  for (i = 0; i < vip->num_selected_addresses; i++)
    {
      if (!SSH_IP_CMP(&vip->selected_address[i], addr))
        return TRUE;
    }

  return FALSE;
}

Boolean
ssh_pm_virtual_ip_set_peer(SshPm pm, SshPmTunnel tunnel, SshUInt32 peer_handle)
{
  if (tunnel == NULL || tunnel->vip == NULL)
    return FALSE;

  /* Free reference to old peer handle. */
  if (tunnel->vip->peer_handle != SSH_IPSEC_INVALID_INDEX)
    ssh_pm_peer_handle_destroy(pm, tunnel->vip->peer_handle);

  tunnel->vip->peer_handle = peer_handle;

  /* Take reference to new peer handle. */
  if (peer_handle != SSH_IPSEC_INVALID_INDEX)
    ssh_pm_peer_handle_take_ref(pm, peer_handle);

  return TRUE;
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
