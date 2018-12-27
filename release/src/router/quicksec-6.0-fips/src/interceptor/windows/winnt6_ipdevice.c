/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform dependent IP protocol stack information retrieval and
   configuration interface for Windows Vista (OS version 6.0) and later.
*/

#if (_WIN32_WINNT >= 0x0600)
#include "sshincludes.h"
#include "interceptor_i.h"
#include "ipdevice.h"
#include "ipdevice_internal.h"
#include <netioapi.h>

typedef struct SshIPDeviceContextRec
{
  /* AF_INET (IPv4) or AF_INET6 (IPV6) */
  ADDRESS_FAMILY family;

  /* "Context area" for IPv4 address find/set/clear */
  SshIpdevAddressInfoStruct addr_ctx;
} SshIPDeviceContextStruct, *SshIPDeviceContext;

/*--------------------------------------------------------------------------
  Local functions.
  --------------------------------------------------------------------------*/

static Boolean
ssh_ipdev_query_interfaces(SshIPDevice device,
                           SshIpdevInterfaceList if_list);

static Boolean
ssh_ipdev_query_addresses(SshIPDevice device,
                          SshIpdevAddressList addr_list);

static Boolean
ssh_ipdev_query_routes(SshIPDevice device,
                       SshIpdevRouteList route_list);

static Boolean
ssh_ipdev_ip4_find_first_address(SshIPDevice device,
                                 SshIFIndex system_idx, 
                                 SshAddressCtx *ctx_return);

static Boolean
ssh_ipdev_configure_i(SshIPDevice device, 
                      SshIFIndex system_idx,
                      SshUInt16 configure_type, 
                      void *configure_params);

static void
ssh_ipdev_ip4_set_address(SshIPDevice device,
                          SshAddressCtx addr_ctx,
                          SshIpAddr ip,
                          SshIPDeviceCompletionCB callback,
                          void *context);

static void
ssh_ipdev_ip_add_address(SshIPDevice device,
                         SshIFIndex system_idx,
                         SshInterceptorIfnum ifnum,
                         SshIpAddr ip,
                         SshAddressCtx *ctx_return,
                         SshIPDeviceCompletionCB callback,
                         void *context);

static void
ssh_ipdev_ip_delete_address(SshIPDevice device,
                            SshAddressCtx addr_ctx,
                            SshIPDeviceCompletionCB callback,
                            void *context);











static void
ssh_ipdev_ip_add_route(SshIPDevice device,
                       SshIPRoute route,
                       SshIPDeviceCompletionCB callback,
                       void *context);


static void
ssh_ipdev_ip_remove_route(SshIPDevice device,
                          SshIPRoute route,
                          SshIPDeviceCompletionCB callback,
                          void *context);

/*--------------------------------------------------------------------------
  Windows CE platform dependent functions for 'SshIPDevice' object.
  --------------------------------------------------------------------------*/

Boolean
ssh_ipdev_platform_init(SshIPDevice device)
{
  SshIPDeviceContext ctx;

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate context!"));
      return FALSE;
    }
  device->context = ctx;

  if (device->dev_id == SSH_DD_ID_IP4) 
    {
      ctx->family = AF_INET;
      device->query_interface_list = ssh_ipdev_query_interfaces;
      device->query_address_list = ssh_ipdev_query_addresses;
      device->query_route_list = ssh_ipdev_query_routes;
      device->find_first_address = ssh_ipdev_ip4_find_first_address;
      device->clear_address = ssh_ipdev_ip_delete_address;





      device->set_address = ssh_ipdev_ip4_set_address;
      device->add_address = ssh_ipdev_ip_add_address;
      device->delete_address = ssh_ipdev_ip_delete_address;
      device->add_route = ssh_ipdev_ip_add_route;
      device->remove_route = ssh_ipdev_ip_remove_route;
      device->configure = ssh_ipdev_configure_i;
    }
#if defined (WITH_IPV6)
  else if (device->dev_id == SSH_DD_ID_IP6)
    {
      ctx->family = AF_INET6;
      device->query_interface_list = ssh_ipdev_query_interfaces;
      device->query_address_list = ssh_ipdev_query_addresses;
      device->query_route_list = ssh_ipdev_query_routes;
      device->add_address = ssh_ipdev_ip_add_address;
      device->delete_address = ssh_ipdev_ip_delete_address;





      device->add_route = ssh_ipdev_ip_add_route;
      device->remove_route = ssh_ipdev_ip_remove_route;
      device->configure = ssh_ipdev_configure_i;
    }
#else
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Unsupported IPv6 device (ID = %d)", device->dev_id));
      ssh_free(device->context);
      device->context = NULL;
      return FALSE;
    }
#endif /* WITH_IPV6 */

  return TRUE;
}


void
ssh_ipdev_platform_uninit(SshIPDevice device)
{
  ssh_free(device->context);
}


Boolean
ssh_ipdev_platform_connect(SshIPDevice device)
{
  /* Nothing to do */

  return TRUE;
}


void 
ssh_ipdev_platform_disconnect(SshIPDevice device)
{
  /* Nothing to do */
}


static void
ssh_ipdev_decode_interface(SshIpdevInterfaceInfo if_info,
                           MIB_IPINTERFACE_ROW *if_row)
{
  /* We use 'static' variable here only for reducing the stack usage 
     (sizeof(if_row2) > 1300 bytes!). This is safe as long as we ensure 
     that this function will be called only from the IP config thread) */
  static MIB_IF_ROW2 if_row2; 

#ifdef DEBUG_LIGHT
  union 
  {
    NL_INTERFACE_OFFLOAD_ROD rod;
    ULONG flags;
  } dbg;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(if_info != NULL);
  SSH_ASSERT(if_row != NULL);

#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- IfLUID: 0x%08llx", if_row->InterfaceLuid));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- IfIndex: %u", if_row->InterfaceIndex));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- SitePrefixLength: %u", if_row->SitePrefixLength));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric: %u", if_row->Metric));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- NlMtu: %u", if_row->NlMtu));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- AdvertisingEnabled: %u", if_row->AdvertisingEnabled));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- ForwardingEnabled: %u", if_row->ForwardingEnabled));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- WeakHostSend: %u", if_row->WeakHostSend));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- WeakHostReceive: %u", if_row->WeakHostReceive));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- UseAutomaticMetric: %u", if_row->UseAutomaticMetric));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- UseNeighborUnreachabilityDetection: %u",
             if_row->UseNeighborUnreachabilityDetection));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- ManagedAddressConfigurationSupported: %u",
             if_row->ManagedAddressConfigurationSupported));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- OtherStatefulConfigurationSupported: %u",
             if_row->OtherStatefulConfigurationSupported));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- AdvertiseDefaultRoute: %u", if_row->AdvertiseDefaultRoute));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- RouterDiscoveryBehavior: %u", 
             if_row->RouterDiscoveryBehavior));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- DadTransmits: %u", if_row->DadTransmits));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- BaseReachableTime: %u", if_row->BaseReachableTime));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- RetransmitTime: %u", if_row->RetransmitTime));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- PathMtuDiscoveryTimeout: %u", 
             if_row->PathMtuDiscoveryTimeout));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- LinkLocalAddressBehavior: %u",
             if_row->LinkLocalAddressBehavior));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Connected: %u", if_row->Connected));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- SupportsWakeUpPatterns: %u", if_row->SupportsWakeUpPatterns));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- SupportsNeighborDiscovery: %u", 
             if_row->SupportsNeighborDiscovery));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- SupportsRouterDiscovery: %u", 
             if_row->SupportsRouterDiscovery));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- ReachableTime: %u", if_row->ReachableTime));
  dbg.rod = if_row->TransmitOffload;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- TransmitOffload: 0x%08X", dbg.flags));
  dbg.rod = if_row->ReceiveOffload;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- ReceiveOffload: 0x%08X", dbg.flags));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- DisableDefaultRoutes: %u", if_row->DisableDefaultRoutes));
#endif /* DEBUG_LIGHT */

  if (if_row->InterfaceLuid.Info.IfType == MIB_IF_TYPE_LOOPBACK)
    if_info->is_loopback = 1;

  if_info->system_idx = if_row->InterfaceIndex;
  if_info->id.u.luid = if_row->InterfaceLuid.Value;
  if_info->id.id_type = SSH_IF_ID_LUID;

  RtlZeroMemory(&if_row2, sizeof(if_row2));
  if_row2.InterfaceLuid = if_row->InterfaceLuid;
  if ((GetIfEntry2(&if_row2) == STATUS_SUCCESS)
      && (if_row2.PhysicalAddressLength <= sizeof(if_info->media_address)))
    {
      if_info->media_addr_len = (SshUInt16)if_row2.PhysicalAddressLength;
      RtlMoveMemory(if_info->media_address,
                    if_row2.PhysicalAddress,
                    if_row2.PhysicalAddressLength);
      if_info->has_media_address = 1;
    }
  else
    {
      if_info->has_media_address = 0;
    }

  if_info->has_mtu = 1;
  if_info->mtu = if_row->NlMtu;
}


static void
ssh_ipdev_decode_route(SshIpdevRouteInfo route,
                       MIB_IPFORWARD_ROW2 *ri)
{
  SOCKADDR_INET *destination;
  SOCKADDR_INET *next_hop;
  UCHAR mask[16];

  SSH_ASSERT(route != NULL);
  SSH_ASSERT(ri != NULL);

  /* Set destination, mask and next hop address */
  destination = &ri->DestinationPrefix.Prefix;
  next_hop = &ri->NextHop;
  route->nm_len = ri->DestinationPrefix.PrefixLength;
  if (destination->si_family == AF_INET)
    {
      SSH_IP4_DECODE(&route->dest, &destination->Ipv4.sin_addr.S_un);
      SSH_IP4_DECODE(&route->gw, &next_hop->Ipv4.sin_addr.S_un); 
      ssh_ip_net_mask_from_prefix_len(route->nm_len, mask, 4);
      SSH_IP4_DECODE(&route->nm, mask);
    }
#if defined(WITH_IPV6)
  else
    {
      SSH_IP6_DECODE(&route->dest, &destination->Ipv6.sin6_addr.u.Byte);
      SSH_IP6_DECODE(&route->gw, &next_hop->Ipv6.sin6_addr.u.Byte); 
      ssh_ip_net_mask_from_prefix_len(route->nm_len, mask, 16);
      SSH_IP6_DECODE(&route->nm, mask);
    }
#endif /* WITH_IPV6 */

  route->system_idx = ri->InterfaceIndex;

  /* This is direct route if no GW address is specified */
  if (SSH_IP_IS_NULLADDR(&route->gw))
    route->type = SSH_IP_ROUTE_DIRECT;
  else
    route->type = SSH_IP_ROUTE_INDIRECT;

  /* Metric */
  route->metric = ri->Metric;

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- Dest: %@", ssh_ipaddr_render, &route->dest));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Mask: %@", ssh_ipaddr_render, &route->nm));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- NextHop: %@", ssh_ipaddr_render, &route->gw));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- IfLUID: 0x%08llX", ri->InterfaceLuid));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- IfIndex: %u", route->system_idx));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- SitePrefixLength: %u", route->nm_len));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- ValidLifeTime: %u", ri->ValidLifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- PreferredLifeTime: %u", ri->PreferredLifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Metric: %u", route->metric));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Protocol: %u", ri->Protocol));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Loopback: %u", ri->Loopback));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Autoconfig: %u", ri->AutoconfigureAddress));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Publish: %u", ri->Publish));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Immortal: %u", ri->Immortal));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Age: %u", ri->Age));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- Origin: %u", ri->Origin));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("(- MTU: %u)", route->mtu));
}


void
ssh_ipdev_decode_address(SshIpdevAddressInfo addr,
                         MIB_UNICASTIPADDRESS_ROW *ai)
{
  unsigned char mask[16];

  SSH_ASSERT(addr != NULL);
  SSH_ASSERT(ai != NULL);

  if (ai->Address.si_family == AF_INET)
    {
      SshUInt32 ba, ip, netmask;

      addr->if_addr.protocol = SSH_PROTOCOL_IP4;

      SSH_IP4_DECODE(&addr->if_addr.addr.ip.ip, 
                     &ai->Address.Ipv4.sin_addr.S_un);

      ssh_ip_net_mask_from_prefix_len(ai->OnLinkPrefixLength, mask, 4);
      SSH_IP4_DECODE(&addr->if_addr.addr.ip.mask, mask);

      /* Generate broadcast address */
      ip = SSH_IP4_TO_INT(&addr->if_addr.addr.ip.ip);
      netmask = SSH_IP4_TO_INT(&addr->if_addr.addr.ip.mask);
      ba = (ip & netmask) | ~netmask;
      SSH_INT_TO_IP4(&addr->if_addr.addr.ip.broadcast, ba);
    }
#if defined(WITH_IPV6)
  else
    {
      addr->if_addr.protocol = SSH_PROTOCOL_IP6;

      SSH_IP6_DECODE(&addr->if_addr.addr.ip.ip, 
                     &ai->Address.Ipv6.sin6_addr.u.Byte);

      /* Take the scope id. */
      addr->if_addr.addr.ip.ip.scope_id.scope_id_union.ui32 = 
        ai->ScopeId.Value;

      ssh_ip_net_mask_from_prefix_len(ai->OnLinkPrefixLength, mask, 16);
      SSH_IP6_DECODE(&addr->if_addr.addr.ip.mask, mask); 

      /* Set broadcast address to IPv6 undefined address */
      SSH_IP6_DECODE(&addr->if_addr.addr.ip.broadcast, 
                     SSH_IP6_UNDEFINED_ADDR);
    }
#endif /* (WITH_IPV6) */

  addr->system_idx = ai->InterfaceIndex;
  /* Just fill something to address type... */
  addr->type = (SshUInt32)ai->InterfaceLuid.Info.IfType;  
  addr->dad_state = ai->DadState;
  addr->valid_lifetime = ai->ValidLifetime;
  addr->preferred_lifetime = ai->PreferredLifetime;
  addr->reasm_size = (SshUInt32)-1;  /* Not used */
  addr->timestamp = ai->CreationTimeStamp.QuadPart;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Address: %@", ssh_ipaddr_render, &addr->if_addr.addr.ip.ip));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- ScopeID: %u", ai->ScopeId));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Mask: %@", ssh_ipaddr_render, &addr->if_addr.addr.ip.mask));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- Broadcast address: %@", 
             ssh_ipaddr_render, &addr->if_addr.addr.ip.broadcast));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- IfLUID: 0x%08llx", ai->InterfaceLuid));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- IfIndex: %u", addr->system_idx));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- DADState: %u", addr->dad_state));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- ValidLifetime: %u", addr->valid_lifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("- PreferredLifetime: %u", addr->preferred_lifetime));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- PrefixOrigin: %u", ai->PrefixOrigin));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- SuffixOrigin: %u", ai->SuffixOrigin));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- OnLinkPrefixLength: %u", ai->OnLinkPrefixLength));
  SSH_DEBUG(SSH_D_NICETOKNOW, ("- SkipAsSource: %u", ai->SkipAsSource));
  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("- CreationTimeStamp: %08X %08X", 
             ai->CreationTimeStamp.HighPart, 
             ai->CreationTimeStamp.LowPart));
}


/*--------------------------------------------------------------------------
  Local platform specific functions.
  --------------------------------------------------------------------------*/

static Boolean
ssh_ipdev_query_interfaces(SshIPDevice device,
                           SshIpdevInterfaceList if_list)
{
  MIB_IPINTERFACE_TABLE *if_table; 
  SshIpdevInterfaceInfo decoded_copy;
  SshIPDeviceContext ctx;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(if_list != NULL);

  ctx = device->context;

  /* Query the interface table. */
  InterlockedIncrement(&device->requests_pending);
  if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) != 0)
      || !NETIO_SUCCESS(GetIpInterfaceTable(ctx->family, &if_table))
      || (if_table->NumEntries == 0))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to query IPv%u interface table",
                (ctx->family == AF_INET) ? 4 : 6));
      InterlockedDecrement(&device->requests_pending);
      return FALSE;
    }
  InterlockedDecrement(&device->requests_pending);

  /* Make a decoded copy of the interface table. (This one will be freed later 
     with ssh_free()). */
  decoded_copy = ssh_calloc(if_table->NumEntries, sizeof(*decoded_copy));
  if (decoded_copy == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate memory for IPv%u interface table",
                 (ctx->family == AF_INET) ? 4 : 6));
      FreeMibTable(if_table);
      return FALSE;
    }

  for (i = 0; i < if_table->NumEntries; i++)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("----- IPv%u interface %u: -----", 
                 (ctx->family == AF_INET) ? 4 : 6, i));

      ssh_ipdev_decode_interface(&decoded_copy[i], &if_table->Table[i]);
    }

  /* Ok, now we have the interface table */
  if_list->table = decoded_copy;
  if_list->num_items = if_table->NumEntries;

  FreeMibTable(if_table);

  return TRUE;
}


static Boolean
ssh_ipdev_query_addresses(SshIPDevice device,
                          SshIpdevAddressList addr_list)
{
  MIB_UNICASTIPADDRESS_TABLE *addr_table;
  SshIpdevAddressInfo decoded_copy;
  SshIPDeviceContext ctx;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(addr_list != NULL);

  ctx = device->context;

  /* Query unicast address table */
  InterlockedIncrement(&device->requests_pending);
  if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) != 0)
      || !NETIO_SUCCESS(GetUnicastIpAddressTable(ctx->family, &addr_table))
      || (addr_table->NumEntries == 0))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to query IPv%u address table",
                (ctx->family == AF_INET) ? 4 : 6));
      InterlockedDecrement(&device->requests_pending);
      return FALSE;
    }
  InterlockedDecrement(&device->requests_pending);

  /* Make a decoded copy of the address table. (This one will be freed later 
     with ssh_free()). */
  decoded_copy = ssh_calloc(addr_table->NumEntries, sizeof(*decoded_copy));
  if (decoded_copy == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate memory for IPv%u address table",
                 (ctx->family == AF_INET) ? 4 : 6));
      FreeMibTable(addr_table);
      return FALSE;
    }

  for (i = 0; i < addr_table->NumEntries; i++)
    {
      InterlockedIncrement(&device->requests_pending);
      if (InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
        {
          /* Refresh this IP address entry to get updated DAD (duplicate 
             address detection) state. It seems to be that 
             GetUnicastIpAddressTable() does not necessarily return 
             'up-to-date' DAD states. */
          if (NETIO_SUCCESS(GetUnicastIpAddressEntry(&addr_table->Table[i])))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("----- IPv%u address %u: -----", 
                         (ctx->family == AF_INET) ? 4 : 6, i));

              ssh_ipdev_decode_address(&decoded_copy[i], 
                                       &addr_table->Table[i]);
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Address table refresh interrupted by suspend!"));
          InterlockedDecrement(&device->requests_pending);
          FreeMibTable(addr_table);
          ssh_free(decoded_copy);
          return FALSE;
        }
      InterlockedDecrement(&device->requests_pending);
    }

  addr_list->table = decoded_copy;
  addr_list->num_items = addr_table->NumEntries;

  FreeMibTable(addr_table);
  
  return TRUE;
}


static Boolean
ssh_ipdev_query_routes(SshIPDevice device,
                       SshIpdevRouteList route_list)
{
  MIB_IPFORWARD_TABLE2 *routing_table;
  SshIpdevRouteInfo decoded_copy;
  SshIPDeviceContext ctx;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(route_list != NULL);

  ctx = device->context;

  /* Query unicast address table */
  InterlockedIncrement(&device->requests_pending);
  if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) != 0)
      || !NETIO_SUCCESS(GetIpForwardTable2(ctx->family, &routing_table))
      || (routing_table->NumEntries == 0))
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to query IPv%u route table",
                (ctx->family == AF_INET) ? 4 : 6));
      InterlockedDecrement(&device->requests_pending);
      return FALSE;
    }
  InterlockedDecrement(&device->requests_pending);

  /* Make a decoded copy of the routing table. (This one will be freed later 
     with ssh_free()). */
  decoded_copy = ssh_calloc(routing_table->NumEntries, sizeof(*decoded_copy));
  if (decoded_copy == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate memory for IPv%u route table",
                 (ctx->family == AF_INET) ? 4 : 6));
      FreeMibTable(routing_table);
      return FALSE;
    }

  for (i = 0; i < routing_table->NumEntries; i++)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("----- IPv%u route %u: -----", 
                 (ctx->family == AF_INET) ? 4 : 6, i));

      ssh_ipdev_decode_route(&decoded_copy[i], &routing_table->Table[i]);
    }

  route_list->table = decoded_copy;
  route_list->num_items = routing_table->NumEntries;

  FreeMibTable(routing_table);
  
  return TRUE;
}


static void
ssh_ipdev_init_address_row(MIB_UNICASTIPADDRESS_ROW *addr,
                           NET_LUID interface_luid,
                           SshIpAddr ip)
{
  InitializeUnicastIpAddressEntry(addr);

  if (SSH_IP_IS4(ip))
    {
      addr->Address.si_family = AF_INET;
      SSH_IP4_ENCODE(ip, &addr->Address.Ipv4.sin_addr.S_un);
    }
#if defined(WITH_IPV6)
  else
    {
      addr->Address.si_family = AF_INET6;
      SSH_IP6_ENCODE(ip, &addr->Address.Ipv6.sin6_addr.u.Byte);
    }
#endif /* WITH_IPV6 */
  addr->InterfaceLuid = interface_luid;
  addr->InterfaceIndex = 0; 
  addr->PrefixOrigin = IpPrefixOriginManual;
  addr->SuffixOrigin = IpSuffixOriginManual;
  addr->PreferredLifetime = -1; /* infinite */
  addr->ValidLifetime = -1; /* infinite */
  addr->SkipAsSource = 0;
  addr->DadState = IpDadStatePreferred;
  addr->OnLinkPrefixLength = ip->mask_len;
}


static void
ssh_ipdev_ip_add_address(SshIPDevice device,
                         SshIFIndex system_idx,
                         SshInterceptorIfnum ifnum,
                         SshIpAddr ip,
                         SshAddressCtx *ctx_return,
                         SshIPDeviceCompletionCB callback,
                         void *context)
{
  MIB_UNICASTIPADDRESS_ROW *addr;
  Boolean status = FALSE;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(ctx_return != NULL);
  SSH_ASSERT(device->context != NULL);

  ctx = device->context;

  addr = ssh_calloc(1, sizeof(*addr));
  if (addr != NULL)
    {
      SshNt6Adapter adapter;

      SSH_ASSERT(device->interceptor != NULL);

      adapter = 
        (SshNt6Adapter)ssh_adapter_ref_by_ifnum(device->interceptor, 
                                                ifnum);
      if (adapter != NULL)
        {
          NET_LUID luid;

          luid.Value = adapter->luid;
          ssh_ipdev_init_address_row(addr, luid, ip); 

          InterlockedIncrement(&device->interceptor->if_report_disable_count);
          InterlockedIncrement(&device->requests_pending);
          if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
              && NETIO_SUCCESS(CreateUnicastIpAddressEntry(addr)))
            {
              *ctx_return = addr;
              status = TRUE;
            }
          else
            {
              SSH_DEBUG(SSH_D_FAIL, 
                        ("Failed to create new IP address entry!"));

              ssh_free(addr);
            }
          InterlockedDecrement(&device->requests_pending);
          InterlockedDecrement(&device->interceptor->if_report_disable_count);

          ssh_adapter_release((SshAdapter)adapter);
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Non-existent interface (ifnum = %u)!", ifnum));
        }
    }

  if (callback != NULL_FNPTR)
    (*callback )(status, context);
}


static void
ssh_ipdev_ip_delete_address(SshIPDevice device,
                            SshAddressCtx addr_ctx,
                            SshIPDeviceCompletionCB callback,
                            void *context)
{
  MIB_UNICASTIPADDRESS_ROW *addr;
  SshIPDeviceContext ctx;
  Boolean status = FALSE;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->context != NULL);
  SSH_ASSERT(addr_ctx != NULL);

  addr = (MIB_UNICASTIPADDRESS_ROW *)addr_ctx;

  InterlockedIncrement(&device->requests_pending);
  if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
      && NETIO_SUCCESS(DeleteUnicastIpAddressEntry(addr)))
    status = TRUE;
  InterlockedDecrement(&device->requests_pending);

  ctx = device->context;
  if (addr_ctx != &ctx->addr_ctx)
    ssh_free(addr_ctx);

  if (callback != NULL_FNPTR)
    (*callback )(status, context);
}
























































static void 
ssh_ipdev_init_ipforward_row(MIB_IPFORWARD_ROW2 *fwrow,
                             ADDRESS_FAMILY family,
                             SshIPRoute route)
{
  InitializeIpForwardEntry(fwrow);
  fwrow->InterfaceLuid.Value = route->luid; 
  fwrow->DestinationPrefix.Prefix.si_family = family;
  fwrow->NextHop.si_family = family;
  if (family == AF_INET)
    {
      SSH_IP4_ENCODE(&route->dest, 
                   &fwrow->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b);
      fwrow->NextHop.Ipv4.sin_family = family;
      if (route->type == SSH_IP_ROUTE_INDIRECT)
        SSH_IP4_ENCODE(&route->gw, &fwrow->NextHop.Ipv4.sin_addr.S_un.S_un_b);
    }
#if defined(WITH_IPV6)
  else
    {
      SSH_IP6_ENCODE(&route->dest, 
                     &fwrow->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte);
      fwrow->NextHop.Ipv6.sin6_family = family;
      if (route->type == SSH_IP_ROUTE_INDIRECT)
        SSH_IP6_ENCODE(&route->gw, &fwrow->NextHop.Ipv6.sin6_addr.u.Byte);
    }
#endif /* WITH_IPV6 */
  fwrow->DestinationPrefix.PrefixLength = (SshUInt8)route->nm_len;
  fwrow->SitePrefixLength = 0;
  fwrow->PreferredLifetime = -1; /* Infinite */
  fwrow->ValidLifetime = -1;     /* Infinite */
  fwrow->Metric = route->metric;
  fwrow->Protocol = MIB_IPPROTO_OTHER;
  fwrow->Loopback = FALSE;
  fwrow->AutoconfigureAddress = FALSE;
  fwrow->Publish = FALSE;
  fwrow->Immortal = FALSE;
}


static void
ssh_ipdev_ip_add_route(SshIPDevice device,
                       SshIPRoute route,
                       SshIPDeviceCompletionCB callback,
                       void *context)
{
  MIB_IPFORWARD_ROW2 fwrow;
  Boolean status = FALSE;
  NTSTATUS api_status;
  SshIPDeviceContext ctx;
  Boolean retry = TRUE;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));
  SSH_ASSERT(device->context != NULL);

  ctx = device->context;

  InterlockedIncrement(&device->requests_pending);

 retry:
  ssh_ipdev_init_ipforward_row(&fwrow, ctx->family, route);
  if (InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
    {
      api_status = CreateIpForwardEntry2(&fwrow);
      if (NETIO_SUCCESS(api_status))
        {
          status = TRUE;
        }
      else if ((api_status == STATUS_DUPLICATE_OBJECTID) && (retry == TRUE))
        {
          if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
              && (NETIO_SUCCESS(DeleteIpForwardEntry2(&fwrow))))
            {
              retry = FALSE;
              goto retry;
            }
        }
    }
  InterlockedDecrement(&device->requests_pending);

  if (callback != NULL_FNPTR)
    (*callback )(status, context);
}


static void
ssh_ipdev_ip_remove_route(SshIPDevice device,
                          SshIPRoute route,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  MIB_IPFORWARD_ROW2 fwrow;
  Boolean status = FALSE;
  SshIPDeviceContext ctx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(route != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(&route->dest));
  SSH_ASSERT(device->context != NULL);

  ctx = device->context;
  ssh_ipdev_init_ipforward_row(&fwrow, ctx->family, route);

  InterlockedIncrement(&device->requests_pending);
  if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
      && NETIO_SUCCESS(DeleteIpForwardEntry2(&fwrow)))
    {
      status = TRUE;
    }
  InterlockedDecrement(&device->requests_pending);

  if (callback != NULL_FNPTR)
    (*callback )(status, context);
}

static Boolean
ssh_ipdev_ip4_find_first_address(SshIPDevice device,
                                 SshIFIndex system_idx, 
                                 SshAddressCtx *ctx_return)
{
  SshIpdevAddressInfo addr_table;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ctx_return != NULL);
  SSH_ASSERT(device->context != NULL);

  ssh_kernel_rw_mutex_lock_read(&device->addr_lock);
  addr_table = (SshIpdevAddressInfo)device->addrs;

  for (i = 0; i < device->caddr; i++)
    {
      SshIpdevAddressInfo addr = &addr_table[i];

      if (addr->system_idx == system_idx)
        {
          SshIPDeviceContext ctx = device->context;

          ctx->addr_ctx = *addr;
          *ctx_return = &ctx->addr_ctx;

          ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);
          return TRUE;
        }
    }
  ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

  return FALSE;
}


static Boolean
ssh_ipdev_configure_i(SshIPDevice device, 
                      SshIFIndex system_idx,
                      SshUInt16 configure_type, 
                      void *configure_params)
{
  MIB_IPINTERFACE_ROW ip_iface_row;
  Boolean status = FALSE;
  
  SSH_ASSERT(device != NULL);

  SSH_DEBUG(SSH_D_LOWOK, ("Ipdev configuration started"));

  InitializeIpInterfaceEntry(&ip_iface_row);
    
  /* Needed parameters for Get. */
  ip_iface_row.InterfaceIndex = system_idx;
  ip_iface_row.Family         = device->dev_id == SSH_DD_ID_IP4 ? 
                                AF_INET : AF_INET6;
      
  InterlockedIncrement(&device->requests_pending);
  switch(configure_type) 
    {
    case SSH_IPDEV_CONFIGURE_TYPE_DAD: 
      SSH_DEBUG(SSH_D_LOWOK, ("Configuring IPDev DAD to %u", 
                              *((SshUInt32 *)configure_params)));

      /* Set the DAD transmit count. */
      ip_iface_row.DadTransmits = *(SshUInt32 *)configure_params;

      if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
          && NETIO_SUCCESS(SetIpInterfaceEntry(&ip_iface_row)))
        {
          status = TRUE;
        }
      break;

    case SSH_IPDEV_CONFIGURE_TYPE_IFACE_METRIC: 
      SSH_DEBUG(SSH_D_LOWOK, ("Configuring IPDev Iface metric to %u", 
                              *((SshUInt32 *)configure_params)));

      /* Set the Iface Metric. */
      ip_iface_row.UseAutomaticMetric = FALSE;
      ip_iface_row.Metric = *(SshUInt32 *)configure_params;

      if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
          && NETIO_SUCCESS(SetIpInterfaceEntry(&ip_iface_row)))
        {
          status = TRUE;
        }
      break;

    case SSH_IPDEV_CONFIGURE_TYPE_MTU:
      SSH_DEBUG(SSH_D_LOWOK, ("Configuring IPDev MTU to %u", 
                              *((SshUInt32 *)configure_params)));

      /* Set the MTU. */
      ip_iface_row.NlMtu = (*(SshUInt32 *)configure_params);

      if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
          && NETIO_SUCCESS(SetIpInterfaceEntry(&ip_iface_row)))
        {
          status = TRUE;
        }
      break;
  
    case SSH_IPDEV_CONFIGURE_TYPE_LINK_LOCAL:
      SSH_DEBUG(SSH_D_LOWOK, ("Configuring Link local setting to %u", 
                              *((SshUInt32 *)configure_params)));

      /* Check for unsupported types in the conf request. */
      if ((*(SshUInt32 *)configure_params) <= 2)
        {
          /* Set the link local address behavior. */
          ip_iface_row.LinkLocalAddressBehavior = 
                            (*(SshUInt32 *)configure_params);

          if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
              && NETIO_SUCCESS(SetIpInterfaceEntry(&ip_iface_row)))
            {
              status = TRUE;
            }
        }
      break;
  
    default:
      break;
    }
  InterlockedDecrement(&device->requests_pending);

  return status;
}


static void
ssh_ipdev_ip4_set_address(SshIPDevice device,
                          SshAddressCtx addr_ctx,
                          SshIpAddr ip,
                          SshIPDeviceCompletionCB callback,
                          void *context)
{
  MIB_UNICASTIPADDRESS_ROW *addr;
  Boolean status = FALSE;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(addr_ctx != 0);
  SSH_ASSERT(ip != NULL);

  addr = addr_ctx;

  InterlockedIncrement(&device->requests_pending);
  if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
      && NETIO_SUCCESS(DeleteUnicastIpAddressEntry(addr)))
    {
      if (!SSH_IP_IS_NULLADDR(ip))
        {
          ssh_ipdev_init_address_row(addr, addr->InterfaceLuid, ip); 

          if ((InterlockedCompareExchange(&device->suspend_count, 0, 0) == 0)
              && NETIO_SUCCESS(CreateUnicastIpAddressEntry(addr)))
            status = TRUE;
        }
      else
        {
          status = TRUE;
        }
    }
  InterlockedDecrement(&device->requests_pending);

  if (callback != NULL_FNPTR) 
    (*callback)(status, context);
}

#endif /* _WIN32_WINNT >= 0x0600 */
