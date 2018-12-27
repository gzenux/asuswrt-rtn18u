/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode IP routing table retrieval and modification functions
   for Windows 2000, Windows XP and Windows Server 2003 packet interceptor
   drivers.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "win_ip_route.h"
#ifdef NDIS60
#include <netioapi.h>
#include "wan_interface.h"
#endif /* NDIS60 */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorIPRoute"


typedef struct SshRouteModifyContextRec
{
  /* Callback information */
  SshInterceptor interceptor;
  SshIPDeviceCompletionCB callback;
  void *context;

  /* Route */
  SshIpAddrStruct ip;
  SshIpAddrStruct gw_or_local_ip;

  /* Flags */
  Boolean addition;

} SshRouteModifyContextStruct, *SshRouteModifyContext;


/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

static void __fastcall
ssh_ip_routing_table_modification_complete(Boolean success,
                                           SshRouteModifyContext ctx)
{
  SSH_ASSERT(ctx != NULL);
  SSH_ASSERT(ctx->interceptor != NULL);

  if (success)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Route %@ -> %@ successfully %s.",
                 ssh_ipaddr_render, &ctx->ip,
                 ssh_ipaddr_render, &ctx->gw_or_local_ip,
                 ctx->addition ? "added" : "removed"));
      SSH_IP_REFRESH_REQUEST(ctx->interceptor);
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to %s route %@ -> %@!",
                 ctx->addition ? "add" : "remove",
                 ssh_ipaddr_render, &ctx->ip,
                 ssh_ipaddr_render, &ctx->gw_or_local_ip));
    }

  if (ctx->callback != NULL_FNPTR)
    (*(ctx->callback))(success, ctx->context);
}


static VOID
ssh_ip_route_list_exchange(LIST_ENTRY *dest,
                           LIST_ENTRY *src,
                           SshKernelRWMutex mutex)
{
  LIST_ENTRY old_list;
  PLIST_ENTRY entry = NULL;

  NdisInitializeListHead(&old_list);

  ssh_kernel_rw_mutex_lock_write(mutex);
  /* Copy the old destination list */
  while (!IsListEmpty(dest))
    {
      entry = RemoveHeadList(dest);
      InitializeListHead(entry);
      InsertTailList(&old_list, entry);
    }

  /* Move entries from the source list to the destination list */
  while (!IsListEmpty(src))
    {
      entry = RemoveHeadList(src);
      InitializeListHead(entry);
      InsertTailList(dest, entry);
    }
  ssh_kernel_rw_mutex_unlock_write(mutex);

  while (!IsListEmpty(&old_list))
    {
      SshIPRoute route;

      entry = RemoveHeadList(&old_list);
      route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);

      ssh_ipdev_route_free(route);
    }
}


#ifdef NDIS60

Boolean __fastcall
ssh_ip_best_route_get(SshInterceptor interceptor,
                      SshIpAddr src,
                      SshIpAddr dst,
                      SshInterceptorIfnum ifnum,
                      SshIPRoute best_route)
{
  SshNt6Adapter adapter = NULL;
  SOCKADDR_INET dst_addr;
  SOCKADDR_INET src_addr;
  SOCKADDR_INET best_src;
  SOCKADDR_INET *src_ptr = NULL;
  SshIPInterfaceIDStruct if_id;
  MIB_IPINTERFACE_ROW ifrow;
  MIB_IPFORWARD_ROW2 fwrow;
  unsigned char mask[16];
  NTSTATUS status;
  NET_LUID luid;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(dst != NULL);
  SSH_ASSERT(best_route != NULL);

  memset(&dst_addr, 0, sizeof(dst_addr));
  if (SSH_IP_IS4(dst))
    {
      dst_addr.si_family = AF_INET;
      SSH_IP4_ENCODE(dst, &dst_addr.Ipv4.sin_addr.S_un.S_un_b);
    }
#if defined(WITH_IPV6)
  else
    {
      dst_addr.si_family = AF_INET6;
      SSH_IP6_ENCODE(dst, &dst_addr.Ipv6.sin6_addr.u.Byte);
    }
#endif /* WITH_IPV6 */

  luid.Value = 0;
  if (ifnum < SSH_INTERCEPTOR_MAX_ADAPTERS)
    {
      adapter = (SshNt6Adapter)ssh_adapter_ref_by_ifnum(interceptor, 
                                                        ifnum);
      if (adapter != NULL)
        luid.Value = adapter->luid;  
    }

  if ((luid.Value != 0) && (src != NULL))
    {
      memset(&src_addr, 0, sizeof(src_addr));
      if (SSH_IP_IS4(src))
        {
          src_addr.si_family = AF_INET;
          SSH_IP4_ENCODE(src, &src_addr.Ipv4.sin_addr.S_un.S_un_b);
        }
#if defined(WITH_IPV6)
      else
        {
          src_addr.si_family = AF_INET6;
          SSH_IP6_ENCODE(src, &src_addr.Ipv6.sin6_addr.u.Byte);
        }
#endif /* WITH_IPV6 */
      src_ptr = &src_addr;
    }

 retry:
  status = GetBestRoute2(&luid, 0, src_ptr, &dst_addr, 0, &fwrow, &best_src);
  if (status != STATUS_SUCCESS)
    {
      if (adapter && ((adapter->media == NdisMediumWan)
       || (adapter->media == NdisMediumCoWan)))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Route not found; using default WAN interface"));

          memset(&fwrow, 0, sizeof(fwrow));
          fwrow.InterfaceLuid = luid;  
        }
      else if ((src_ptr != NULL) ||(luid.Value)) 
        {
          /* By default, Vista doesn't forward source routed IPv4 packets
             (see DisableIPSourceRouting TCP/IP configuration parameter). 
             In that case (i.e. when GetBestRoute() refuses to tell us
             the correct route), we can retry route lookup without source 
             selectors. */
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Route not found; "
                     "retrying without source IP and IF selectors"));
          src_ptr = NULL;
          luid.Value = 0;
          goto retry;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("GetBestRoute2() failed, status=%u (%08X)", 
                     status, status));

          if (adapter != NULL)
            ssh_adapter_release((SshAdapter)adapter);

          return FALSE;
        }
    }

  if (SSH_IP_IS4(dst))
    {
      SSH_IP4_DECODE(&best_route->gw, 
                     &fwrow.NextHop.Ipv4.sin_addr.S_un); 
      SSH_IP4_DECODE(&best_route->dest, 
                     &fwrow.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un);

      best_route->nm_len = fwrow.DestinationPrefix.PrefixLength;
      ssh_ip_net_mask_from_prefix_len(best_route->nm_len, mask, 4);
      SSH_IP4_DECODE(&best_route->nm, mask);

      best_route->system_idx = fwrow.InterfaceIndex;
    }
#if defined(WITH_IPV6)
  else
    {
      SSH_IP6_DECODE(&best_route->gw, 
                     &fwrow.NextHop.Ipv6.sin6_addr.u.Byte); 
      SSH_IP6_DECODE(&best_route->dest, 
                     &fwrow.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte);

      best_route->nm_len = fwrow.DestinationPrefix.PrefixLength;
      ssh_ip_net_mask_from_prefix_len(best_route->nm_len, mask, 16);
      SSH_IP6_DECODE(&best_route->nm, mask);

      best_route->system_idx = fwrow.InterfaceIndex;
    }
#endif /* WITH_IPV6 */

  /* This is direct route if no GW address is specified */
  if (SSH_IP_IS_NULLADDR(&best_route->gw))
    best_route->type = SSH_IP_ROUTE_DIRECT;
  else
    best_route->type = SSH_IP_ROUTE_INDIRECT;

  best_route->metric = fwrow.Metric;

  if (adapter)
    ssh_adapter_release((SshAdapter)adapter);

  if_id.id_type = SSH_IF_ID_LUID;
  if_id.u.luid = fwrow.InterfaceLuid.Value;
  adapter = (SshNt6Adapter)ssh_adapter_ref_by_ifnum(
                                         interceptor,
                                         ssh_adapter_ifnum_lookup(interceptor,
                                                                  NULL, 
                                                                  0, 
                                                                  &if_id));
  if (adapter == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Adapter lookup failed"));
      return FALSE;
    }

  best_route->luid = fwrow.InterfaceLuid.Value;

  memset(&ifrow, 0, sizeof(ifrow));
  ifrow.Family = dst_addr.si_family;
  ifrow.InterfaceLuid = fwrow.InterfaceLuid;

  status = GetIpInterfaceEntry(&ifrow);
  if (status != STATUS_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IP interface lookup failed!"));
      ssh_adapter_release((SshAdapter)adapter);
      return FALSE;
    }

  best_route->mtu = ifrow.NlMtu;
  best_route->ifnum = adapter->ifnum;
 
  if ((fwrow.InterfaceLuid.Info.IfType == IF_TYPE_PPP)
      && (adapter->luid != if_id.u.luid))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("This is PPP interface; searching connection specific MTU"));

      ssh_kernel_rw_mutex_lock_read(&adapter->wan_if_lock);
      if (adapter->wan_if_cnt > 0)
        {
          SshWanInterface wi;
          PLIST_ENTRY wi_entry;

          for (wi_entry = adapter->wan_if.Flink;
               wi_entry != &(adapter->wan_if);
               wi_entry = wi_entry->Flink)
            {
              wi = CONTAINING_RECORD(wi_entry, 
                                     SshWanInterfaceStruct, link);

              if (wi->luid == if_id.u.luid) 
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Connection specific MTU = %u", wi->link_mtu));
                  best_route->mtu = wi->link_mtu;
                  break;
                }
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&adapter->wan_if_lock);
    }

  ssh_adapter_release((SshAdapter)adapter);
 
  return TRUE;
}

#else /* !NDIS60 */

Boolean __fastcall
ssh_ip_best_route_get(SshInterceptor interceptor,
                      SshIpAddr src,
                      SshIpAddr dst,
                      SshInterceptorIfnum ifnum,
                      SshIPRoute best_route)
{
  PLIST_ENTRY entry;
  Boolean route_found = FALSE;
  SshKernelRWMutex route_lock;
  PLIST_ENTRY   route_list;

#if defined (WITH_IPV6)
  if (SSH_IP_IS6(dst))
    {
      route_lock = &interceptor->ip6_route_lock;
      route_list = &interceptor->ip6_route_list;
    }
  else
#endif /* WITH_IPV6 */
    {
      route_lock = &interceptor->ip4_route_lock;
      route_list = &interceptor->ip4_route_list;
    }

  ssh_kernel_rw_mutex_lock_read(route_lock);
  if (IsListEmpty(route_list))
    {
      ssh_kernel_rw_mutex_unlock_read(route_lock);
      /* No matching route found */
      SSH_DEBUG(SSH_D_NICETOKNOW, 
                ("Dest[%@]: Route list is empty",
                 ssh_ipaddr_render, dst)); 
      return FALSE;
    }

  /* Search through the route list to find matching route. 
     Use route that has the longest net_mask */
  for (entry = route_list->Flink; entry != route_list; entry = entry->Flink)
    {
      SshIPRoute route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);

      /* Compare destination addresses using mask. 
         Select route that has longest netmask and lowest metric */
      if (SSH_IP_WITH_MASK_EQUAL(dst, &route->dest, &route->nm))
        {
          *best_route = *route;

          route_found = TRUE;
          break;
        }
    }
  ssh_kernel_rw_mutex_unlock_read(route_lock);

  return route_found;
}

#endif /* !NDIS60 */


static Boolean
ssh_ip_route_gw_is_local_ip(SshInterceptor interceptor,
                            SshIpAddr gw_or_local_ip)
{
  PLIST_ENTRY if_entry;

  ssh_kernel_rw_mutex_lock_read(&interceptor->if_lock);

  if_entry = interceptor->if_list.Flink;
  while (if_entry != &interceptor->if_list)
    {
      SshIPInterface ip_if;
      unsigned int i;

      ip_if = CONTAINING_RECORD(if_entry, SshIPInterfaceStruct, link);
      if_entry = if_entry->Flink;

      if ((ip_if->num_addrs == 0) || (ip_if->addrs == NULL))
        continue;

      for (i = 0; i < ip_if->num_addrs; i++)
        {
          SshIpAddr local_ip = &ip_if->addrs[i].addr.ip.ip;

          if (SSH_IP_EQUAL(gw_or_local_ip, local_ip))
            {
              ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);
              return TRUE;
            }
        }
    }

  ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);

  return FALSE;
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean
ssh_ip_routing_table_refresh(SshInterceptor interceptor)
{
  PLIST_ENTRY entry;
  LIST_ENTRY ip4_route_list;
#if defined (WITH_IPV6)
  LIST_ENTRY ip6_route_list;
#endif /* WITH_IPV6 */
  ULONG rc;
  unsigned int i;

  struct SshRoutingConfigStruct
    {
      SshIPDevice ip_dev;
      PLIST_ENTRY route_list;
    } 
  config[] = 
    {{&interceptor->ip4_dev, &ip4_route_list}
#if defined (WITH_IPV6)
    ,{&interceptor->ip6_dev, &ip6_route_list}
#endif /* WITH_IPV6 */ 
    };
     
  SSH_ASSERT(interceptor != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_interceptor_ip_routing_changed()"));

  /* Get new route information */
  for (i = 0; i < sizeof(config) / sizeof(config[0]); i++)
    {
      SshIPInterface ip_if;
      SshIPRoute route = NULL;
      PLIST_ENTRY if_entry;     
      LIST_ENTRY  temp_list;
      PLIST_ENTRY dest_list = config[i].route_list;

      NdisInitializeListHead(&temp_list); 
      NdisInitializeListHead(dest_list);

      if (config[i].ip_dev == NULL)
        continue;

      if (!ssh_ipdev_get_route_list(config[i].ip_dev, &temp_list, &rc))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to read routing table!"));
          return FALSE;
        }

      /* Determine the corresponding network interface number for routes 
         using our interface list as a reference */
      entry = temp_list.Flink; 
      while (entry != &temp_list)
        {
          PLIST_ENTRY next = entry->Flink;
          Boolean found = FALSE;

          route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);
          route->ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

          ssh_kernel_rw_mutex_lock_read(&interceptor->if_lock);
          if_entry = interceptor->if_list.Flink;
          while (if_entry != &interceptor->if_list)
            {
              ip_if = CONTAINING_RECORD(if_entry, SshIPInterfaceStruct, link);

              /* Use system specific IF identifiers as match criteria */
              if (ip_if->system_idx == route->system_idx) 
                {
                  route->ifnum = ip_if->adapter_ifnum;
                  if ((ip_if->mtu > 0)
                      && (route->mtu > ip_if->mtu))
                    route->mtu = ip_if->mtu;

                  found = TRUE;
                  break;
                }

              if_entry = if_entry->Flink;
            }
          ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);

          /* Check if right network interface found */
          if (found)
            {
              SshAdapter adapter;

              adapter = ssh_adapter_ref_by_ifnum(interceptor, route->ifnum);
              if (adapter != NULL)
                {
                  if (!adapter->media_connected)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Ignoring route: dst[%@/%u], gw[%@], if[%u]: "
                                 "media disconnected!",
                                 ssh_ipaddr_render, &route->dest, 
				 route->nm_len, ssh_ipaddr_render, 
				 &route->gw, route->ifnum));

                      /* Remove route with disconnected if */
                      RemoveEntryList(&route->link);
                      ssh_ipdev_route_free(route);
                    }
                  else
                    {
#ifdef NDIS60
                      route->luid = ((SshNt6Adapter)adapter)->luid;
#endif /* NDIS60 */

                      SSH_ASSERT(route->mtu != 0);
                    }

                  ssh_adapter_release(adapter);
                }
              else
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("Ignoring route: dst[%@/%u], gw[%@], if[%u]: "
                             "interface already destroyed!",
                             ssh_ipaddr_render, &route->dest, route->nm_len,
                             ssh_ipaddr_render, &route->gw, route->ifnum));

                  /* Remove route with disconnected if */
                  RemoveEntryList(&route->link);
                  ssh_ipdev_route_free(route);
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Ignoring route: dst[%@/%u], gw[%@], if[%u]: "
                         "unknown interface!",
                         ssh_ipaddr_render, &route->dest, route->nm_len,
                         ssh_ipaddr_render, &route->gw, route->ifnum));

              /* Remove route with unknown if */
              RemoveEntryList(&route->link);
              ssh_ipdev_route_free(route);
            }

          entry = next;
        } 

#if defined (WITH_IPV6)
      /* We need to add local subnet routes for manually configured IPv6 
         addresses because Windows does not seem to add them to the exposed 
         routing table. (The routing is probably handled internally by the
         IPv6 driver). */
      if (config[i].ip_dev == &interceptor->ip6_dev)
        {
          ssh_kernel_rw_mutex_lock_read(&interceptor->if_lock);

          if_entry = interceptor->if_list.Flink;
          while (if_entry != &interceptor->if_list)
            {
              unsigned int j;

              ip_if = CONTAINING_RECORD(if_entry, SshIPInterfaceStruct, link);
              if_entry = if_entry->Flink;

              if ((ip_if->num_addrs == 0) || (ip_if->addrs == NULL))
                continue;

              for (j = 0; j < ip_if->num_addrs; j++)
                {
                  SshIpAddrStruct route_dest;
                  ULONG mask_len;
                  SshIpAddr ip = &ip_if->addrs[j].addr.ip.ip;
                  SshIpAddr mask = &ip_if->addrs[j].addr.ip.mask;
                  Boolean route_exists = FALSE;

                  /* Ignore IPv4 addresses. */
                  if (!SSH_IP_IS6(ip))
                    continue;

                  /* Ignore link-local addresses */
                  if (SSH_IP6_IS_LINK_LOCAL(ip))
                    continue;

                  mask_len = ssh_ip_net_mask_calc_prefix_len(mask);

                  /* Ignore IPv6 addresses having 128 bit subnet mask */
                  if (mask_len == 128)
                    continue;

                  /* Do not add duplicated route for this local subnet */
                  route_dest = *ip;
                  ssh_ipaddr_set_bits(&route_dest, ip, mask_len, 0);

                  entry = temp_list.Flink;
                  while (entry->Flink != &temp_list)
                    {
                      SshIPRoute existing_route;

                      existing_route = 
                        CONTAINING_RECORD(entry, SshIPRouteStruct, link);

                      if (route != NULL 
                        && (SSH_IP_EQUAL(&existing_route->dest, &route_dest)
                        && (existing_route->nm_len == route->nm_len)))
                        {
                          route_exists = TRUE;
                          break;
                        }

                      entry = entry->Flink;
                    }

                  if (route_exists)
                    continue;
                  
                  route = ssh_ipdev_route_alloc(&interceptor->ip6_dev);
                  if (route == NULL)
                    continue;

                  route->type = SSH_IP_ROUTE_DIRECT;
                  route->dest = route_dest;
                  route->gw = *ip;
                  route->ifnum = ip_if->adapter_ifnum;
                  route->system_idx = ip_if->system_idx;
                  route->metric = 512; 
                  route->mtu = ip_if->mtu;
                  route->nm = *mask;
                  route->nm_len = mask_len;

                  InitializeListHead(&route->link);
                  InsertTailList(&temp_list, &route->link);
                }
            }

          ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);
        }
#endif /* WITH_IPV6 */

      /* Arrange the route list according to the length of netmask/prefix
         and metric values */
      while (IsListEmpty(&temp_list) == FALSE)
        {
          entry = temp_list.Flink;
          route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);

          while (entry->Flink != &temp_list)
            {
              SshIPRoute next_route;

              entry = entry->Flink;

              next_route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);

              if ((next_route->nm_len > route->nm_len) ||
                  ((next_route->nm_len == route->nm_len) && 
                   (next_route->metric <= route->metric)))
                {
                  route = next_route;
                }
            }

          /* Move the route from temporary list to the destination list. */
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Adding route: dst[%@/%u], gw[%@], if[%u], mtu[%u], "
                     "type[%u], metric[%u]",
                     ssh_ipaddr_render, &route->dest, route->nm_len, 
                     ssh_ipaddr_render, &route->gw, 
                     route->ifnum, route->mtu, route->type, route->metric));

          RemoveEntryList(&route->link);
          InitializeListHead(&route->link);
          InsertTailList(dest_list, &route->link);
        } 
    } 

  /* Replace route lists with the new ones */
  ssh_ip_route_list_exchange(&interceptor->ip4_route_list, 
                             &ip4_route_list, 
                             &interceptor->ip4_route_lock);
#if defined (WITH_IPV6)
  ssh_ip_route_list_exchange(&interceptor->ip6_route_list,
                             &ip6_route_list,
                             &interceptor->ip6_route_lock);
#endif /* WITH_IPV6 */

  return TRUE;
}


void
ssh_ip_routing_table_free(SshInterceptor interceptor)
{
  LIST_ENTRY empty;
  
  NdisInitializeListHead(&empty);

#if defined (WITH_IPV6)
  ssh_ip_route_list_exchange(&interceptor->ip6_route_list,
                             &empty, &interceptor->ip6_route_lock);
#endif /* WITH_IPV6 */
  ssh_ip_route_list_exchange(&interceptor->ip4_route_list,
                             &empty, &interceptor->ip4_route_lock);
}

static void
ssh_ip_route_flush_queue(SshInterceptor interceptor, SshCpuContext cpu_ctx)
{
  if (cpu_ctx->in_route_queue_flush)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Ignoring recursive route queue "
				   "flush request"));
      return;
    }

  cpu_ctx->in_route_queue_flush = 1;
  while (cpu_ctx->packets_in_route_recv_queue
	 || cpu_ctx->packets_in_route_send_queue)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Flushing packets in route queue."));

      if (cpu_ctx->packets_in_route_send_queue)
	{
	  cpu_ctx->packets_in_route_send_queue = 0;
	  ssh_interceptor_flush_packet_queue(interceptor, 
					     cpu_ctx->route_send_queue,
					     TRUE);
	}
      
      if (cpu_ctx->packets_in_route_recv_queue)
	{
	  cpu_ctx->packets_in_route_recv_queue = 0;
	  ssh_interceptor_flush_packet_queue(interceptor, 
					     cpu_ctx->route_recv_queue,
					     FALSE);
	}
    }
  cpu_ctx->in_route_queue_flush = 0;
}

void __fastcall
ssh_ip_route_lookup(SshInterceptor interceptor,
                    SshInterceptorRouteKey key,
                    SshInterceptorRouteCompletion completion,
                    void *context)
{
  SshIPRouteStruct route;
  SSH_IRQL old_irql;
  SshInterceptorIfnum ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
  SshIpAddr src_ip = NULL;
  SshCpuContext cpu_ctx;

  SSH_PRECOND(interceptor != NULL);
  SSH_PRECOND(key != NULL);
  /* It is a fatal error to call ssh_interceptor_route with
     a routing key that does not specify the destination address. */
  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));

  if ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_OUT_IFNUM)
      || (key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IN_IFNUM))
    ifnum = key->ifnum; 

  if (key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
    src_ip = &key->src;

  /* Find the matching route */
  if (interceptor->asynch_interceptor_route &&
      (InterlockedCompareExchange(&interceptor->routing_disable_count,
                                  0, 0) != 0))
    {
      /* Asynchronous routing requests are currently disabled */
      SSH_DEBUG(SSH_D_FAIL, 
                ("Dest[%@]: Routing requests currently disabled!", 
                 ssh_ipaddr_render, &key->dst)); 

      SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);
      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
      cpu_ctx->in_route_cb = 1;

      (*completion)(FALSE, NULL, 0, 0, context);

      cpu_ctx->in_route_cb = 0;
      ssh_ip_route_flush_queue(interceptor, cpu_ctx);
      SSH_LOWER_IRQL(old_irql);
      ssh_free(key);
    }
  else if (!ssh_ip_best_route_get(interceptor, src_ip, 
                                  &key->dst, ifnum, &route))
    {
      /* No matching route found */
      SSH_DEBUG(SSH_D_FAIL, 
                ("Dest[%@]: No route found", ssh_ipaddr_render, &key->dst)); 
      if (interceptor->asynch_interceptor_route)
        {
          SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);
	  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
	  cpu_ctx->in_route_cb = 1;

          (*completion)(FALSE, NULL, 0, 0, context);

	  cpu_ctx->in_route_cb = 0;
	  ssh_ip_route_flush_queue(interceptor, cpu_ctx);
          SSH_LOWER_IRQL(old_irql);
          ssh_free(key);
        }
      else
        {
          (*completion)(FALSE, NULL, 0, 0, context);
        }
    }
  else
    {
      /* Matching route has been found */

      /* Check route type */
      if (route.type == SSH_IP_ROUTE_DIRECT)
        {
          /* Destination is on a local network */
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Dest[%@]: Direct route: if[%u], mtu[%u]", 
                     ssh_ipaddr_render, &key->dst, 
                     route.ifnum, route.mtu));
          if (interceptor->asynch_interceptor_route)
            {
              SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);
	      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
	      cpu_ctx->in_route_cb = 1;

              (*completion)(TRUE, &key->dst, route.ifnum, route.mtu, context);

	      cpu_ctx->in_route_cb = 0;
	      ssh_ip_route_flush_queue(interceptor, cpu_ctx);
              SSH_LOWER_IRQL(old_irql);
              ssh_free(key);
            }
          else
            {
              (*completion)(TRUE, &key->dst, route.ifnum, route.mtu, context);
            }
        }
      else
        {
          /* Destination is on a remote network */
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Dest[%@]: Indirect route: gw[%@], if[%u], mtu[%u]", 
                     ssh_ipaddr_render, &key->dst, 
                     ssh_ipaddr_render, &route.gw,
                     route.ifnum, route.mtu));
          if (interceptor->asynch_interceptor_route)
            {
              SSH_RAISE_IRQL(SSH_DISPATCH_LEVEL, &old_irql);
	      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
	      cpu_ctx->in_route_cb = 1;

              (*completion)(TRUE, &route.gw, route.ifnum, route.mtu, context);

	      cpu_ctx->in_route_cb = 0;
	      ssh_ip_route_flush_queue(interceptor, cpu_ctx);
              SSH_LOWER_IRQL(old_irql);
              ssh_free(key);
            }
          else
            {
              (*completion)(TRUE, &route.gw, route.ifnum, route.mtu, context);
            }
        }
    }
}


void
ssh_ip_route_add(SshInterceptor interceptor,
                 SshIpAddr ip,
                 SshIpAddr gw_or_local_ip,
                 SshInterceptorIfnum ifnum,
                 SshIPDeviceCompletionCB callback,
                 void *context)
{
  SshRouteModifyContext ctx = NULL;
  SshIPRouteStruct route;
  SshIpAddr lookup_ip;
  unsigned char mask[16];

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(gw_or_local_ip != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Adding route: %@ -> %@, ifnum = %u",
             ssh_ipaddr_render, ip,
             ssh_ipaddr_render, gw_or_local_ip,
             ifnum));

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create context"));
      goto failed;
    }

  ctx->addition = TRUE;
  ctx->interceptor = interceptor;
  ctx->ip = *ip;
  ctx->callback = callback;
  ctx->context = context;

  memset(&route, 0, sizeof(route));
  /* We need the operating system specific interface ID, so first task is
     to find the correct network interface. */
  if (SSH_IP_DEFINED(gw_or_local_ip))
    lookup_ip = gw_or_local_ip;
  else
    lookup_ip = ip;

  if (!ssh_ip_best_route_get(interceptor, NULL, 
                             lookup_ip, ifnum, &route))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get GW interface"));
      goto failed;
    }

  if (!SSH_IP_DEFINED(gw_or_local_ip)
      || ssh_ip_route_gw_is_local_ip(interceptor, gw_or_local_ip))
    route.type = SSH_IP_ROUTE_DIRECT;
  else
    route.type = SSH_IP_ROUTE_INDIRECT;

  route.dest = *ip;
  if (SSH_IP_IS4(ip))
    {
      ssh_ip_net_mask_from_prefix_len(ip->mask_len, mask, 4);
      SSH_IP4_DECODE(&route.nm, mask);
    }
  else
    {
      ssh_ip_net_mask_from_prefix_len(ip->mask_len, mask, 16);
      SSH_IP6_DECODE(&route.nm, mask);
    }
  route.nm_len = ip->mask_len;
  route.gw = *gw_or_local_ip;
  route.metric = 1;

  if (SSH_IP_IS4(ip))
    {
      ssh_ipdev_add_route(&interceptor->ip4_dev, &route, 
                          ssh_ip_routing_table_modification_complete, ctx);

      ssh_free(ctx);
      return;
    }
#if defined (WITH_IPV6)
  else if (SSH_IP_IS6(ip))
    {
      /* If IPv6 stack is not installed */
      if (&interceptor->ip6_dev == NULL)
        goto failed;
      
      /* If gw_or_local_ip contain a local IPv6 address, we must clear the 
         next hop address, otherwise protocol stack creates non-working 
         indirect route. */
      if (route.type == SSH_IP_ROUTE_DIRECT)
        SSH_IP6_DECODE(&route.gw, SSH_IP6_UNDEFINED_ADDR); 

      ssh_ipdev_add_route(&interceptor->ip6_dev, &route, 
                          ssh_ip_routing_table_modification_complete, ctx);

      ssh_free(ctx);
      return;
    }
#endif /* WITH_IPV6 */

failed:
  if (ctx != NULL)
    ssh_free(ctx);

  if (callback != NULL_FNPTR)
    (*callback)(FALSE, context);
}


void 
ssh_ip_route_remove(SshInterceptor interceptor,
                    SshIpAddr ip,
                    SshIpAddr gw_or_local_ip,
                    SshInterceptorIfnum ifnum,
                    SshIPDeviceCompletionCB callback,
                    void *context)
{
  SshRouteModifyContext ctx = NULL;
  SshIPRouteStruct route;
  SshIpAddr lookup_ip;
  unsigned char mask[16];

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(gw_or_local_ip != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("Removing route: %@ -> %@",
             ssh_ipaddr_render, ip,
             ssh_ipaddr_render, gw_or_local_ip));

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create context"));
      goto failed;
    }

  ctx->addition = FALSE;
  ctx->interceptor = interceptor;
  ctx->ip = *ip;
  ctx->callback = callback;
  ctx->context = context;

  memset(&route, 0, sizeof(route));

  /* We need the operating system specific interface ID, so first task is
     to find the correct network interface. */
  if (SSH_IP_DEFINED(gw_or_local_ip))
    lookup_ip = gw_or_local_ip;
  else
    lookup_ip = ip;
    
  if (ssh_ip_best_route_get(interceptor, NULL, 
                            lookup_ip, ifnum, &route) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get interface ID"));
      goto failed;
    }

  if (!SSH_IP_DEFINED(gw_or_local_ip)
      || ssh_ip_route_gw_is_local_ip(interceptor, gw_or_local_ip))
    route.type = SSH_IP_ROUTE_DIRECT;
  else
    route.type = SSH_IP_ROUTE_INDIRECT;

  route.dest = *ip;
  if (SSH_IP_IS4(ip))
    {
      ssh_ip_net_mask_from_prefix_len(ip->mask_len, mask, 4);
      SSH_IP4_DECODE(&route.nm, mask);
    }
  else
    {
      ssh_ip_net_mask_from_prefix_len(ip->mask_len, mask, 16);
      SSH_IP6_DECODE(&route.nm, mask);
    }
  route.nm_len = ip->mask_len;
  route.gw = *gw_or_local_ip;
  route.metric = 1;

  if (SSH_IP_IS4(ip))
    {
      ssh_ipdev_remove_route(&interceptor->ip4_dev, &route, 
                             ssh_ip_routing_table_modification_complete, ctx);

      ssh_free(ctx);
      return;
    }
#if defined (WITH_IPV6)
  else if (SSH_IP_IS6(ip))
    {
      /* If IPv6 stack is not installed */
      if (&interceptor->ip6_dev == NULL)
        goto failed;
      
      /* If gw_or_local_ip contain a local IPv6 address, we must clear the 
         next hop address, otherwise protocol stack creates non-working 
         indirect route. */
      if (route.type == SSH_IP_ROUTE_DIRECT)
        SSH_IP6_DECODE(&route.gw, SSH_IP6_UNDEFINED_ADDR); 

      ssh_ipdev_remove_route(&interceptor->ip6_dev, &route,
                             ssh_ip_routing_table_modification_complete, ctx);

      ssh_free(ctx);
      return;
    }
#endif /* WITH_IPV6 */

failed:
  if (ctx != NULL)
    ssh_free(ctx);

  if (callback != NULL_FNPTR)
    (*callback)(FALSE, context);
}

