/**
   @copyright
   Copyright (c) 2007 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Network interface configuration and routing table manipulation functions.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#define SSH_DEBUG_MODULE "SshPmUtilVirtualAdapter"

#ifndef INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE

/*************** Virtual Adapter Configure via Sshnetconfig ******************/

#include "sshnetconfig.h"

#define SSH_PM_NETCONFIG_MAX_IFACE_ADDRESSES 16

static void
pm_netconfig_virtual_adapter_configure(SshPm pm,
                                       SshUInt32 adapter_ifnum,
                                       SshVirtualAdapterState adapter_state,
                                       SshUInt32 num_addresses,
                                       SshIpAddr addresses,
                                       SshVirtualAdapterParams params,
                                       SshPmeVirtualAdapterStatusCB callback,
                                       void *context)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_OK;
  SshUInt32 i;
  SshUInt32 mtu = 0;
  SshNetconfigInterfaceAddrStruct
    existing_addresses[SSH_PM_NETCONFIG_MAX_IFACE_ADDRESSES];
  SshUInt32 num_existing_addresses = SSH_PM_NETCONFIG_MAX_IFACE_ADDRESSES;
  SshNetconfigInterfaceAddrStruct new_address;
  SshPmeVirtualAdapterStruct vip;

  /* Bring link up and set mtu. */
  if (adapter_state == SSH_VIRTUAL_ADAPTER_STATE_UP)
    {
      if (params)
        mtu = params->mtu;

      SSH_DEBUG(SSH_D_LOWOK, ("Configuring interface %d up, mtu %d",
                              adapter_ifnum, mtu));

      if (params)
        {
          error = ssh_netconfig_set_link_routing_instance(
                                                 adapter_ifnum,
                                                 params->routing_instance_id);
          if (error != SSH_NETCONFIG_ERROR_OK)
            goto fail;
        }

      error = ssh_netconfig_set_link_flags(adapter_ifnum,
                                           SSH_NETCONFIG_LINK_UP,
                                           SSH_NETCONFIG_LINK_UP);
      if (error != SSH_NETCONFIG_ERROR_OK)
        goto fail;

      error = ssh_netconfig_set_link_mtu(adapter_ifnum, mtu);
      if (error != SSH_NETCONFIG_ERROR_OK)
        goto fail;
    }

  /* Configure addresses. */
  if (addresses != NULL)
    {
      /* Fetch existing addresses. */
      SSH_DEBUG(SSH_D_LOWOK, ("Fetching interface addresses"));
      error = ssh_netconfig_get_addresses(adapter_ifnum,
                                          &num_existing_addresses,
                                          existing_addresses);
      if (error != SSH_NETCONFIG_ERROR_OK)
        goto fail;

      SSH_DEBUG(SSH_D_LOWOK, ("Got %d interface addresses",
                              num_existing_addresses));

      /* Check if existing interface addresses contain the configured
         virtual IP addresses. */
      for (i = 0; i < num_existing_addresses; i++)
        {
          /* Remove existing interface addresses from interface. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Removing address %@",
                     ssh_ipaddr_render, &existing_addresses[i].address));
          error = ssh_netconfig_del_address(adapter_ifnum,
                                            &existing_addresses[i]);
          if (error != SSH_NETCONFIG_ERROR_OK)
            goto fail;
        }

      /* Add configured virtual IP addresses to the interface. */
      SSH_DEBUG(SSH_D_LOWOK, ("Adding %d virtual IP addresses",
                              num_addresses));
      for (i = 0; i < num_addresses; i++)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Adding address %@",
                                  ssh_ipaddr_render, &addresses[i]));
          new_address.address = addresses[i];
          new_address.flags = 0;

          error = ssh_netconfig_add_address(adapter_ifnum, &new_address);
          if (error != SSH_NETCONFIG_ERROR_OK)
            goto fail;
        }
    }

  /* Bring link down */
  if (adapter_state == SSH_VIRTUAL_ADAPTER_STATE_DOWN)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Configuring interface %d down", adapter_ifnum));

      error = ssh_netconfig_set_link_flags(adapter_ifnum, 0,
                                           SSH_NETCONFIG_LINK_UP);
      if (error != SSH_NETCONFIG_ERROR_OK)
        goto fail;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Virtual adapter %d configuration completed",
                          adapter_ifnum));
  memset(&vip, 0, sizeof(vip));
  vip.adapter_ifnum = adapter_ifnum;
  vip.adapter_state = adapter_state;
  (*callback)(pm, SSH_VIRTUAL_ADAPTER_ERROR_OK, 1, &vip, context);
  return;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Configuration failed: netconfig error %d", error));
  (*callback)(pm, SSH_VIRTUAL_ADAPTER_ERROR_UNKNOWN_ERROR, 0, NULL, context);
}

#endif /* INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE */

#ifndef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY

/******************* Modifying Routes via Sshnetconfig **********************/

#include "sshnetconfig.h"

#define SSH_PM_NETCONFIG_MAX_ROUTES 128
#define SSH_LINUX_ROUTE_METRIC_PENALTY 20


















































static void
pm_netconfig_route_add(SshPm pm,
                       SshInterceptorRouteKey key,
                       const SshIpAddr gateway,
                       SshUInt32 ifnum,
                       SshRoutePrecedence precedence,
                       SshUInt32 flags,
                       SshPmeRouteSuccessCB callback, void *context)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_OK;
  SshNetconfigRouteStruct existing_routes[SSH_PM_NETCONFIG_MAX_ROUTES];
  SshUInt32 num_existing_routes = SSH_PM_NETCONFIG_MAX_ROUTES;
  SshUInt32 metric;
  SshUInt32 i;
  Boolean change_route_metric = FALSE;
  SshNetconfigRouteStruct new_route;

  metric = ssh_netconfig_route_metric(precedence, SSH_IP_IS6(&key->dst));
  switch (precedence)
    {
    case SSH_ROUTE_PREC_LOWEST:
    case SSH_ROUTE_PREC_BELOW_SYSTEM:
      break;
    case SSH_ROUTE_PREC_SYSTEM:
    case SSH_ROUTE_PREC_ABOVE_SYSTEM:
    case SSH_ROUTE_PREC_HIGHEST:
      change_route_metric = TRUE;
      break;
    }

  /* Fetch existing routes that match key->dst. */
  SSH_DEBUG(SSH_D_LOWOK, ("Fetching existing routes to %@",
                          ssh_ipaddr_render, &key->dst));
  error = ssh_netconfig_get_route(&key->dst, &num_existing_routes,
                                  existing_routes);
  if (error != SSH_NETCONFIG_ERROR_OK)
    goto fail;

  /* Check if metrics of existing routes need to be modified. */
  for (i = 0; i < num_existing_routes; i++)
    {
      if (SSH_IP_EQUAL(&key->dst, &existing_routes[i].prefix) &&
          ((int)key->routing_instance_id ==
           existing_routes[i].routing_instance_id) &&
          change_route_metric && (metric >= existing_routes[i].metric))
        {
          /* Duplicate existing route using modified metric. */
          new_route = existing_routes[i];
          new_route.metric = metric + SSH_LINUX_ROUTE_METRIC_PENALTY;
          new_route.routing_instance_id = (int)key->routing_instance_id;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Duplicating route to %@ via %@ dev %d metric %d, "
                     "new metric %d routing instance id %d",
                     ssh_ipaddr_render, &existing_routes[i].prefix,
                     ssh_ipaddr_render, &existing_routes[i].gateway,
                     existing_routes[i].ifnum, existing_routes[i].metric,
                     new_route.metric, new_route.routing_instance_id));

          error = ssh_netconfig_add_route(&new_route);
          if (error != SSH_NETCONFIG_ERROR_OK &&
              error != SSH_NETCONFIG_ERROR_EEXIST)
            goto fail;

          /* Delete original route. */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Deleting original route to %@ via %@ dev %d metric %d",
                     ssh_ipaddr_render, &existing_routes[i].prefix,
                     ssh_ipaddr_render, &existing_routes[i].gateway,
                     existing_routes[i].ifnum, existing_routes[i].metric));
          error = ssh_netconfig_del_route(&existing_routes[i]);
          if (error != SSH_NETCONFIG_ERROR_OK)
            goto fail;
        }
    }

  /* Install new route. */
  new_route.prefix = key->dst;
  if (gateway)
    new_route.gateway = *gateway;
  else
    SSH_IP_UNDEFINE(&new_route.gateway);
  new_route.ifnum = ifnum;
  new_route.metric = metric;
  new_route.flags = 0;
  new_route.routing_instance_id = (int)key->routing_instance_id;

  SSH_DEBUG(SSH_D_LOWOK, ("Installing route to %@ via %@ dev %d metric %d",
                          ssh_ipaddr_render, &new_route.prefix,
                          ssh_ipaddr_render, &new_route.gateway,
                          new_route.ifnum, new_route.metric));

  error = ssh_netconfig_add_route(&new_route);
  if (error != SSH_NETCONFIG_ERROR_OK)
    goto fail;

  SSH_DEBUG(SSH_D_LOWOK, ("Route addition completed"));
  (*callback)(pm, SSH_INTERCEPTOR_ROUTE_ERROR_OK, context);
  return;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Route addition failed: netconfig error %d", error));
  (*callback)(pm, SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED, context);
}

static void
pm_netconfig_route_remove(SshPm pm,
                          SshInterceptorRouteKey key,
                          const SshIpAddr gateway,
                          SshUInt32 ifnum,
                          SshRoutePrecedence precedence,
                          SshUInt32 flags,
                          SshPmeRouteSuccessCB callback, void *context)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_OK;
  SshNetconfigRouteStruct route;

  /* Delete route. */
  route.prefix = key->dst;
  if (gateway)
    route.gateway = *gateway;
  else
    SSH_IP_UNDEFINE(&route.gateway);
  route.ifnum = ifnum;
  route.metric = ssh_netconfig_route_metric(precedence, SSH_IP_IS6(&key->dst));
  route.flags = 0;
  route.routing_instance_id = (int)key->routing_instance_id;

  SSH_DEBUG(SSH_D_LOWOK, ("Removing route to %@ via %@ dev %d metric %d"
                          " routing_instance_id %d",
                          ssh_ipaddr_render, &route.prefix,
                          ssh_ipaddr_render, &route.gateway,
                          route.ifnum, route.metric,
                          route.routing_instance_id));

  error = ssh_netconfig_del_route(&route);
  if (error != SSH_NETCONFIG_ERROR_OK
      && error != SSH_NETCONFIG_ERROR_NON_EXISTENT)
    goto fail;

  if (error == SSH_NETCONFIG_ERROR_NON_EXISTENT
      && (flags & SSH_INTERCEPTOR_ROUTE_FLAG_IGNORE_NONEXISTENT) == 0)
    goto fail;

  SSH_DEBUG(SSH_D_LOWOK, ("Route removal completed"));
  (*callback)(pm, SSH_INTERCEPTOR_ROUTE_ERROR_OK, context);
  return;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Route removal failed: netconfig error %d", error));
  (*callback)(pm, SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED, context);
}

#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */


/************************ Virtual Adapter Configuration *******************/

void ssh_pm_virtual_adapter_configure(SshPm pm,
                                      SshUInt32 adapter_ifnum,
                                      SshVirtualAdapterState adapter_state,
                                      SshUInt32 num_addresses,
                                      SshIpAddr addresses,
                                      SshVirtualAdapterParams params,
                                      SshPmeVirtualAdapterStatusCB callback,
                                      void *context)
{
#ifndef INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE
  /* Use sshnetconfig */
  pm_netconfig_virtual_adapter_configure(pm, adapter_ifnum, adapter_state,
                                         num_addresses, addresses, params,
                                         callback, context);
#else /* INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE */
  /* Use Engine PM API */
  ssh_pme_virtual_adapter_configure(pm->engine, adapter_ifnum, adapter_state,
                                    num_addresses, addresses, params,
                                    callback, context);
#endif /* INTERCEPTOR_IMPLEMENTS_VIRTUAL_ADAPTER_CONFIGURE */
}


/************************ Routing table modification ************************/

void ssh_pm_route_add(SshPm pm,
                      SshInterceptorRouteKey key,
                      const SshIpAddr gateway,
                      SshUInt32 ifnum,
                      SshRoutePrecedence precedence,
                      SshUInt32 flags,
                      SshPmeRouteSuccessCB callback, void *context)
{
#ifndef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  /* Use sshnetconfig */
  pm_netconfig_route_add(pm, key, gateway, ifnum, precedence, flags,
                         callback, context);

#else /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
  /* Use Engine PM API */
  ssh_pme_route_add(pm->engine, key, gateway, ifnum, precedence, flags,
                    callback, context);
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
}

void ssh_pm_route_remove(SshPm pm,
                         SshInterceptorRouteKey key,
                         const SshIpAddr gateway,
                         SshUInt32 ifnum,
                         SshRoutePrecedence precedence,
                         SshUInt32 flags,
                         SshPmeRouteSuccessCB callback, void *context)
{
#ifndef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  /* Use sshnetconfig */
  pm_netconfig_route_remove(pm, key, gateway, ifnum, precedence, flags,
                            callback, context);

#else /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
  /* Use Engine PM API */
  ssh_pme_route_remove(pm->engine, key, gateway, ifnum, precedence, flags,
                       callback, context);
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
}

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
