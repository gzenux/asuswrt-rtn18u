/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains platfrom independent implementation for functions that
   are utilized to retrieve and modify the IP networking information (network
   interfaces, IP addresses, IP routing) of a local machine.
*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "ipdevice.h"
#include "ipdevice_internal.h"
#include <nldef.h>


unsigned char SSH_IP6_UNDEFINED_ADDR[SSH_MAX_IP6_ADDR_LEN] = 
  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

#define SSH_IPDEV_INVALID_SYSTEM_IDX   0xFFFFFFFF

/*--------------------------------------------------------------------------
  INTERNAL FUNCTIONS
  --------------------------------------------------------------------------*/

int 
ssh_ipdev_render(unsigned char *buf, 
                 int buf_size, 
                 int precision,
                 void *datum)
{
  SshIPDevice ipdev = (SshIPDevice)datum;
  int len;

  ssh_snprintf(buf, buf_size + 1, 
               "0x%p {IPv%u, connected=%u, suspend_count=%u}",
               ipdev,
               (ipdev->dev_id == SSH_DD_ID_IP4) ? 4 : 6,
               ipdev->connected,
               ipdev->suspend_count);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

/* Returns system specific interface number corresponding to the given
   SshAdapter object or SSH_IPDEV_INVALID_SYSTEM_IDX if the interface 
   is not found. */
static SshUInt32
ssh_ipdev_system_idx_lookup(SshIPDevice device,
                            SshAdapter adapter)
{
  SshInterceptor interceptor = adapter->interceptor;
  PLIST_ENTRY if_entry;

  ssh_kernel_rw_mutex_lock_read(&interceptor->if_lock);

  if_entry = interceptor->if_list.Flink;
  while (if_entry != &interceptor->if_list)
    {
      SshIPInterface ip_if;

      ip_if = CONTAINING_RECORD(if_entry, SshIPInterfaceStruct, link);

      if (ip_if->adapter_ifnum == adapter->ifnum)
        {
          SshUInt32 system_idx = ip_if->system_idx;

          if ((device->dev_id == ip_if->owner_device_id) &&
              (ip_if->media_addr_len == adapter->media_addr_len) &&
              (memcmp(ip_if->media_addr,
                      adapter->media_addr,
                      adapter->media_addr_len) == 0))
            {
              /* Return the system specific interface index */
              ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);
              return (system_idx);
            }
        }

      if_entry = if_entry->Flink;
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);

  return SSH_IPDEV_INVALID_SYSTEM_IDX;
}

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean 
ssh_ipdev_init(SshIPDevice device,
               SshInterceptor interceptor,
               SshIPDeviceID dev_id)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_ipdev_init(%u)", dev_id));

  /* Check device type that we are initializing */
  if ((dev_id != SSH_DD_ID_IP4) && (dev_id != SSH_DD_ID_IP6))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported device ID!"));
      return FALSE;
    }

#if !defined (WITH_IPV6)
  if (dev_id == SSH_DD_ID_IP6) 
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv6 support not included"));
      return FALSE;
    }
#endif /* WITH_IPV6 */

  memset(device, 0, sizeof(*device));
  device->dev_id = dev_id;
  device->interceptor = interceptor;
  InitializeListHead(&device->route_free_list);
  InitializeListHead(&device->ip_if_free_list);

  /* Initialize kernel mutexes for ensuring the integrity of data members */
  ssh_kernel_rw_mutex_init(&device->if_lock);
  ssh_kernel_rw_mutex_init(&device->addr_lock);
  ssh_kernel_rw_mutex_init(&device->route_lock);
  ssh_kernel_mutex_init(&device->free_list_lock);

  /* Init interface, address and routing information */
  device->suspend_count = 0L;
  device->requests_pending = 0L;
  device->cif = 0L;
  device->ifs = NULL;
  device->caddr = 0L;
  device->addrs = NULL;
  device->croute = 0L;
  device->routes = NULL;

  /* Last step: perform platform dependent initialization */
  if (!ssh_ipdev_platform_init(device))
    goto init_failed;

  return TRUE;

init_failed:
  /* Perform complete clean-up */
  ssh_ipdev_uninit(device);

  return FALSE;
}

void
ssh_ipdev_uninit(SshIPDevice device)
{
  PLIST_ENTRY entry;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_ipdev_uninit(0x%p)", device));

  /* First step: perform platform dependent uninitialization. */
  ssh_ipdev_platform_uninit(device);

  /* Platform independent code: */
  ssh_kernel_rw_mutex_uninit(&device->if_lock);
  ssh_kernel_rw_mutex_uninit(&device->addr_lock);
  ssh_kernel_rw_mutex_uninit(&device->route_lock);
  ssh_kernel_mutex_uninit(&device->free_list_lock);

  while (!IsListEmpty(&device->route_free_list))
    {
      entry = RemoveHeadList(&device->route_free_list);
      ssh_free(CONTAINING_RECORD(entry, SshIPRouteStruct, link));
    }

  while (!IsListEmpty(&device->ip_if_free_list))
    {
      entry = RemoveHeadList(&device->ip_if_free_list);
      ssh_free(CONTAINING_RECORD(entry, SshIPInterfaceStruct, link));
    }

  ssh_free(device->ifs);
  ssh_free(device->addrs);
  ssh_free(device->routes);
}


Boolean
ssh_ipdev_connect(SshIPDevice device)
{
  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->connected == FALSE);

  device->connected = ssh_ipdev_platform_connect(device);

  return device->connected;
}


void
ssh_ipdev_disconnect(SshIPDevice device)
{
  SSH_ASSERT(device != NULL);
  SSH_ASSERT(device->connected != FALSE);

  ssh_ipdev_platform_disconnect(device);
}


Boolean
ssh_ipdev_is_connected(SshIPDevice device)
{
  SSH_ASSERT(device != NULL);

  return device->connected;
}


void
ssh_ipdev_suspend(SshIPDevice device)
{
  ULONG suspend_count;

  SSH_ASSERT(device != NULL);

  suspend_count = InterlockedIncrement(&device->suspend_count);

  SSH_DEBUG(SSH_D_MIDSTART, 
            ("Suspending protocol stack interface %@", 
             ssh_ipdev_render, device));

  /* Wait for completion... */
  if (suspend_count == 1)
    {
      while (InterlockedCompareExchange(&device->requests_pending, 0, 0) != 0)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Protocol stack interface %@ waiting for "
                     "pending requests to complete...",
                     ssh_ipdev_render, device));

          if (SSH_GET_IRQL() >= SSH_DISPATCH_LEVEL)
            {
              SSH_ASSERT(ssh_kernel_num_cpus() > 1);
              NdisStallExecution(20);
            }
          else
            {
              NdisMSleep(1000);
            }
        };
    }
}

void
ssh_ipdev_resume(SshIPDevice device)
{
  ULONG suspend_count;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(InterlockedCompareExchange(&device->suspend_count, 0, 0) != 0);

  suspend_count = InterlockedDecrement(&device->suspend_count);

  SSH_DEBUG(SSH_D_MIDSTART, 
            ("Resuming protocol stack interface %@", 
             ssh_ipdev_render, device));
}


/*--------------------------------------------------------------------------
  ssh_ipdev_refresh()
  
  Refreshes IP interface, address and routing information of local machine.
  
  Arguments:
  device - SshIPDevice object
  
  Return:
  TRUE - refresh succeeded
  FALSE - otherwise
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_refresh(SshIPDevice device, 
                  SshUInt32 *changed)
{
  Boolean status = FALSE;
  SshIpdevInterfaceListStruct if_list;
  SshIpdevAddressListStruct addr_list;
  SshIpdevRouteListStruct route_list;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(changed != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, 
            ("ssh_ipdev_refresh(%@)", 
             ssh_ipdev_render, device));

  if ((device->query_interface_list == NULL_FNPTR)
       || (device->query_address_list == NULL_FNPTR)
       || (device->query_route_list == NULL_FNPTR))
    return FALSE;

  if (InterlockedCompareExchange(&device->suspend_count, 0, 0) != 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("IP refresh request failed! (IP device suspended)"));

      return FALSE;
    }

  memset(&if_list, 0, sizeof(if_list));
  memset(&addr_list, 0, sizeof(addr_list));
  memset(&route_list, 0, sizeof(route_list));

  status = 
    (*device->query_interface_list)(device, &if_list);
  status &= 
    (*device->query_address_list)(device, &addr_list);
  status &= 
    (*device->query_route_list)(device, &route_list);

  if (status != FALSE)
    {
      void *old_list;
      unsigned int i;

      /* Update route MTUs (in case the platform dependent route
         structures do not have MTU information) */
      for (i = 0; i < route_list.num_items; i++)
        {
          SshIpdevRouteInfo route = &route_list.table[i];

          if (route->mtu == 0)
            {
              unsigned int j;

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Route %@/%u -> %@ having zero MTU; "
                         "searching for interface MTU...",
                         ssh_ipaddr_render, &route->dest,
                         route->nm_len,
                         ssh_ipaddr_render, &route->gw));

              for (j = 0; j < if_list.num_items; j++)
                {
                  SshIpdevInterfaceInfo iface = &if_list.table[j];

                  if (route->system_idx == iface->system_idx)
                    {
                      route->mtu = iface->mtu;
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Adjusted route %@/%u -> %@ MTU to %u",
                                 ssh_ipaddr_render, &route->dest,
                                 route->nm_len,
                                 ssh_ipaddr_render, &route->gw,
                                 route->mtu));
                      break;
                    }
                }
            }
        }

      /* Record changes */
      ssh_kernel_rw_mutex_lock_read(&device->if_lock);
      if (if_list.num_items != device->cif)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Total number of IP interfaces has changed"));
          *changed |= SSH_IP_CHANGED_INTERFACES;
        }
      else
        {
          for (i = 0; i < if_list.num_items; i++)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Comparing interfaces (%u/%u)...", 
                        i+1, if_list.num_items));

              if (memcmp(&if_list.table[i], 
                         &(((SshIpdevInterfaceInfo)device->ifs)[i]),
                         sizeof(if_list.table[0])))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Decoded interfaces are NOT identical"));

                  *changed |= SSH_IP_CHANGED_INTERFACES;
                  break;
                }
              else
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Decoded interfaces are identical"));
                }            
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&device->if_lock);

      ssh_kernel_rw_mutex_lock_read(&device->addr_lock);
      if (addr_list.num_items != device->caddr)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Total number of IP addresses has changed"));
          *changed |= SSH_IP_CHANGED_ADDRESSES;
        }
      else
        {
          for (i = 0; i < addr_list.num_items; i++)
            {
	      size_t cmp_len = 0;

              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Comparing addresses (%u/%u)...", 
                        i+1, addr_list.num_items));

	      cmp_len = (size_t)&addr_list.table[0].valid_lifetime - 
		(size_t)&addr_list.table[0];

              if (memcmp(&addr_list.table[i], 
                         &(((SshIpdevAddressInfo)device->addrs)[i]),
                         cmp_len))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Decoded addresses are NOT identical"));

                  *changed |= SSH_IP_CHANGED_ADDRESSES;
                  break;
                }
              else
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Decoded addresses are identical"));
                }
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

      ssh_kernel_rw_mutex_lock_read(&device->route_lock);
      if (route_list.num_items != device->croute)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Total number of routes has changed"));
          *changed |= SSH_IP_CHANGED_ROUTES;
        }
      else
        {
          for (i = 0; i < route_list.num_items; i++)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Comparing routes (%u/%u)...", 
                        i+1, route_list.num_items));

              if (memcmp(&route_list.table[i], 
                         &(((SshIpdevRouteInfo)device->routes)[i]),
                         sizeof(route_list.table[0])))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Decoded routes are NOT identical"));

                  *changed |= SSH_IP_CHANGED_ROUTES;
                  break;
                }            
              else
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Decoded routes are identical"));
                }
            }
        }
      ssh_kernel_rw_mutex_unlock_read(&device->route_lock);

      if (*changed & SSH_IP_CHANGED_INTERFACES)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Saving new interface information"));
          ssh_kernel_rw_mutex_lock_write(&device->if_lock);
          old_list = device->ifs;
          device->cif = if_list.num_items;
          device->ifs = if_list.table;
          ssh_kernel_rw_mutex_unlock_write(&device->if_lock);
          ssh_free(old_list);
        }
      else
        {
          ssh_free(if_list.table);
        }

      if (*changed & SSH_IP_CHANGED_ADDRESSES)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Saving new IP address information"));
          ssh_kernel_rw_mutex_lock_write(&device->addr_lock);
          old_list = device->addrs;
          device->caddr = addr_list.num_items;
          device->addrs = addr_list.table;
          ssh_kernel_rw_mutex_unlock_write(&device->addr_lock);
          ssh_free(old_list);
        }
      else
        {
          ssh_free(addr_list.table);
        }

      if (*changed & SSH_IP_CHANGED_ROUTES)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Saving new IP routing information"));
          ssh_kernel_rw_mutex_lock_write(&device->addr_lock);
          old_list = device->routes;
          device->croute = route_list.num_items;
          device->routes = route_list.table;
          ssh_kernel_rw_mutex_unlock_write(&device->addr_lock);
          ssh_free(old_list);
        }
      else
        {
          ssh_free(route_list.table);
        }
    } 
  else
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to refresh %s stack information",
                 (device->dev_id == SSH_DD_ID_IP6) ? "IPv6" : "IPv4"));

      ssh_free(if_list.table);
      ssh_free(addr_list.table);
      ssh_free(route_list.table);
    }

  return status;
}


/*--------------------------------------------------------------------------
  ssh_ipdev_route_alloc()

  Allocates a new route structure. 

  Arguments:
  device - SshIPDevice object,

  Return:
  Pointer to SshIPRoute structure or NULL if route could not be allocated.
  --------------------------------------------------------------------------*/
SshIPRoute 
ssh_ipdev_route_alloc(SshIPDevice device)
{
  PLIST_ENTRY entry = NULL;
  SshIPRoute route;

  SSH_ASSERT(device != NULL);

  ssh_kernel_mutex_lock(&device->free_list_lock);
  if (!IsListEmpty(&device->route_free_list))
    entry = RemoveHeadList(&device->route_free_list);
  ssh_kernel_mutex_unlock(&device->free_list_lock);

  if (entry != NULL)
    {
      route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);
      memset(route, 0, sizeof(*route));
    }
  else
    {
      route = ssh_calloc(1, sizeof(*route));
      if (route == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate route"));
          return NULL;
        }
    }

  route->system_idx = 0L;
  route->mtu = 1500;
  route->owner = device;
  route->owner_device_id = device->dev_id;

  return route;
}


/*--------------------------------------------------------------------------
  ssh_ipdev_route_free()

  Frees a previously alloced route structure. 

  Arguments:
  route - route structure to be freed.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_route_free(SshIPRoute route)
{
  SshIPDevice owner;

  SSH_ASSERT(route != NULL);

  owner = route->owner;

  SSH_ASSERT(owner != NULL);

  ssh_kernel_mutex_lock(&owner->free_list_lock);
  InitializeListHead(&route->link);
  InsertTailList(&owner->route_free_list, &route->link);
  ssh_kernel_mutex_unlock(&owner->free_list_lock);
}


/*--------------------------------------------------------------------------
  ssh_ipdev_interface_alloc()

  Allocates a new IP interface structure. 

  Arguments:
  device - SshIPDevice object,

  Return:
  Pointer to SshIPInterface structure or NULL if interface could not be 
  allocated.
  --------------------------------------------------------------------------*/
SshIPInterface
ssh_ipdev_interface_alloc(SshIPDevice device)
{
  PLIST_ENTRY entry = NULL;
  SshIPInterface ip_if; 

  ssh_kernel_mutex_lock(&device->free_list_lock);
  if (!IsListEmpty(&device->ip_if_free_list))
    entry = RemoveHeadList(&device->ip_if_free_list);
  ssh_kernel_mutex_unlock(&device->free_list_lock);

  if (entry != NULL)
    {
      ip_if = CONTAINING_RECORD(entry, SshIPInterfaceStruct, link);
      memset(ip_if, 0, sizeof(*ip_if));
    }
  else
    {
      ip_if = ssh_calloc(1, sizeof(*ip_if));
      if (ip_if == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate IP interface"));
          return NULL;
        }
    }

  ip_if->system_idx = 0L;
  ip_if->media_addr_len = SSH_ETHERH_ADDRLEN;
  ip_if->owner = device;
  ip_if->owner_device_id = device->dev_id;

  return ip_if;
}


/*--------------------------------------------------------------------------
  ssh_ipdev_interface_free()

  Frees a previously alloced IP interface structure. 

  Arguments:
  ip_if - interface structure to be freed.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_interface_free(SshIPInterface ip_if)
{
  SshIPDevice owner;

  SSH_ASSERT(ip_if != NULL);

  ssh_free(ip_if->addrs);

  owner = ip_if->owner;

  SSH_ASSERT(owner != NULL);

  ssh_kernel_mutex_lock(&owner->free_list_lock);
  InitializeListHead(&ip_if->link);
  InsertTailList(&owner->ip_if_free_list, &ip_if->link);
  ssh_kernel_mutex_unlock(&owner->free_list_lock);
}


/*--------------------------------------------------------------------------
  ssh_ipdev_get_route_list()
  
  Returns the IP routing information.
  
  Arguments:
  device - SshIPDevice object,
  list - list for routing information,
  lock - route list lock
  
  Returns:
  Number of routing entries in IP routing table.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_get_route_list(SshIPDevice device,
                         PLIST_ENTRY list,
                         ULONG *route_cnt_return)
{
  SshUInt32 num_routes = 0;
  LIST_ENTRY free_list;
  LIST_ENTRY used_list;
  PLIST_ENTRY entry; 
  SshIPRoute route = NULL;
  Boolean success = TRUE;
  UINT i;
  
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_ipdev_get_route_list(0x%p)", device));

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(list != NULL);

  InitializeListHead(&free_list);
  InitializeListHead(&used_list);

  /* Pre-allocate route structures so we don't need to perform any memory 
     allocations after we have acquired the lock. */
allocate_more:
  for (; num_routes < device->croute; num_routes++)
    {
      route = ssh_ipdev_route_alloc(device);
      if (route == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate route structures!"));
          goto alloc_failed;
        }

      InitializeListHead(&route->link);
      InsertTailList(&free_list, &route->link);
    }

  ssh_kernel_rw_mutex_lock_read(&device->route_lock);

  /* It doesn't matter if new routes were added while we allocated and
     initialized the routes. We can always always try to allocate more... */
  if (num_routes < device->croute)
    {
      ssh_kernel_rw_mutex_unlock_read(&device->route_lock);
      goto allocate_more;
    }
  
  for (i = 0; i < device->croute; i++)
    {
      SshIpdevRouteInfo ri;

      ri = &(((SshIpdevRouteInfo)device->routes)[i]);

      if (ri->mtu == 0)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Discarding route with MTU size 0: %@/%u -> %@",
                     ssh_ipaddr_render, &route->dest,
                     route->nm_len,
                     ssh_ipaddr_render, &route->gw));
	  continue;
	}

      /* Skip possible loopback routes */
      if (SSH_IP_IS_LOOPBACK(&ri->gw))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, 
                    ("Discarding loopback route: %@/%u -> %@",
                     ssh_ipaddr_render, &route->dest,
                     route->nm_len,
                     ssh_ipaddr_render, &route->gw));
          continue;
        }

      /* Skip routes with zero MTU */
      if (ri->mtu == 0)
        continue;

      entry = RemoveHeadList(&free_list);
      route = CONTAINING_RECORD(entry, SshIPRouteStruct, link);

      route->system_idx = ri->system_idx;
      route->type = ri->type;       
      route->mtu = ri->mtu;
      route->dest = ri->dest;
      route->nm = ri->nm;
      route->nm_len = ri->nm_len;
      route->gw = ri->gw;
      route->metric = ri->metric;
      
      InitializeListHead(&route->link);
      InsertTailList(&used_list, &route->link);
    }
  ssh_kernel_rw_mutex_unlock_read(&device->route_lock);

  /* Move routes to destination list */
  while (!IsListEmpty(&used_list))
    {
      entry = RemoveHeadList(&used_list);
      /* Insert routes so that most specific are at the head of list */
      InitializeListHead(entry);
      InsertHeadList(list, entry);
    }

alloc_failed:

  /* Add 'extra', unused structures to free list */
  ssh_kernel_mutex_lock(&device->free_list_lock);
  while (!IsListEmpty(&free_list))
    {
      entry = RemoveHeadList(&free_list);
      InitializeListHead(entry);
      InsertTailList(&device->route_free_list, entry);

      num_routes--;
    }
  ssh_kernel_mutex_unlock(&device->free_list_lock);

  if (route_cnt_return != NULL)
    {
      if (success)
        *route_cnt_return = num_routes;
      else
        *route_cnt_return = 0;
    }

  return (success);
}


/*--------------------------------------------------------------------------
  ssh_ipdev_get_iface_list()
  
  Returns the IP interface information.
  
  Arguments:
  device - SshIPDevice object,
  list - List for IP interface information,
  lock - IP interface information list lock
  
  Returns:
  Number of IP interfaces.
  --------------------------------------------------------------------------*/
Boolean
ssh_ipdev_get_interface_list(SshIPDevice device,
                             PLIST_ENTRY list,
                             ULONG *if_cnt_return)
{
  LIST_ENTRY free_list;
  LIST_ENTRY temp_list1;
  LIST_ENTRY temp_list2;
  PLIST_ENTRY entry;
  SshIPInterface ip_if = NULL;
  BOOLEAN success = TRUE;
  ULONG num_ifs = 0L;
  ULONG i = 0L; 

  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_ipdev_get_iface_list(0x%p)", device));

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(list != NULL);

  /* Pre-allocate interface structures so we don't need to perform memory
     allocations after we take the lock. */
  InitializeListHead(&free_list);
  InitializeListHead(&temp_list1);
  InitializeListHead(&temp_list2);

allocate_ifs:

  for (; num_ifs < device->cif; num_ifs++)
    {
      ip_if = ssh_ipdev_interface_alloc(device);
      if (ip_if == NULL)
        goto alloc_failed;

      InitializeListHead(&ip_if->link);
      InsertTailList(&free_list, &ip_if->link);
    }

  ssh_kernel_rw_mutex_lock_read(&device->if_lock);

  if (num_ifs < device->cif)
    {
      ssh_kernel_rw_mutex_unlock_read(&device->if_lock);
      goto allocate_ifs;
    }

  /* Go through all network interfaces */
  for (i = 0; i < device->cif; i++)
    {
      SshIpdevInterfaceInfo ii = &(((SshIpdevInterfaceInfo)device->ifs)[i]);

      /* Skip possible loopback interface */
      if (ii->is_loopback)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Discarding loopback interface (%u, 0x%X)",
                     ii->system_idx, ii->system_idx));
          continue;
        }

      /* pick a pre-allocated interface structure */
      entry = RemoveHeadList(&free_list);
      ip_if = CONTAINING_RECORD(entry, SshIPInterfaceStruct, link);

      ip_if->system_idx = ii->system_idx;
      ip_if->mtu = ii->mtu;
      ip_if->media_addr_len = ii->media_addr_len;
      if (ip_if->media_addr_len)
        {
          SSH_ASSERT(ip_if->media_addr_len <= sizeof(ip_if->media_addr));

          memcpy(ip_if->media_addr, ii->media_address, ii->media_addr_len);
        }

      ip_if->id = ii->id;

      InitializeListHead(&ip_if->link);
      InsertTailList(&temp_list1, &ip_if->link);
    }
  ssh_kernel_rw_mutex_unlock_read(&device->if_lock);

  while (!IsListEmpty(&temp_list1))
    {
      SshIpdevAddressInfo ai;
      SshAdapter adapter = NULL;
      SshUInt32 num_addrs;

      entry = RemoveHeadList(&temp_list1);
      ip_if = CONTAINING_RECORD(entry, SshIPInterfaceStruct, link);

      /* Perform adapter lookup */
      adapter = 
        ssh_adapter_ref_by_ifnum(
                         device->interceptor,
                         ssh_adapter_ifnum_lookup(device->interceptor,
                                                  ip_if->media_addr,
                                                  ip_if->media_addr_len,
                                                  &ip_if->id));
      if (adapter)
        {
          ip_if->id.u.ifnum = adapter->ifnum;
          ip_if->id.id_type = SSH_IF_ID_ADAPTER_IFNUM;
          ip_if->adapter_ifnum = adapter->ifnum;

          ssh_adapter_release(adapter);

          InitializeListHead(&ip_if->link);
          InsertTailList(&temp_list2, &ip_if->link);
        }
      else
        {
#ifdef DEBUG_LIGHT
          if (ip_if->id.id_type == SSH_IF_ID_GUID)
            {
              GUID *guid = &(ip_if->id.u.guid);

              SSH_DEBUG(SSH_D_HIGHOK, 
                        ("Adapter lookup failed for interface GUID %@!",
                        ssh_guid_render, guid));
            }
          else if (ip_if->id.id_type == SSH_IF_ID_LUID)
            {
              SSH_DEBUG(SSH_D_HIGHOK,
                        ("Adapter lookup failed for interface LUID 0x%08llx",
                         ip_if->id.u.luid));
            }
          else if (ip_if->id.id_type == SSH_IF_ID_DESCRIPTION)
            {
              SSH_DEBUG(SSH_D_HIGHOK, 
                        ("Adapter lookup failed for '%s'!", 
                         ip_if->id.u.d.description));
            }
          else
            {
              SSH_DEBUG(SSH_D_HIGHOK, ("Adapter lookup failed!"));
            }
#endif /* DEBUG_LIGHT */

          InitializeListHead(&ip_if->link);
          InsertTailList(&free_list, &ip_if->link);
          continue;
        }

      ssh_kernel_rw_mutex_lock_read(&device->addr_lock);
      /* Calculate number of IP addresses belonging to this interface */
      num_addrs = 0;
      for (i = 0; i < device->caddr; i++)
        {
          ai = &(((SshIpdevAddressInfo)device->addrs)[i]);

          if (ai->system_idx == ip_if->system_idx)
            num_addrs++;
        }

      ip_if->addrs = ssh_calloc(num_addrs, sizeof(*(ip_if->addrs)));
      if (ip_if->addrs == NULL)
        {
          ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

          SSH_DEBUG(SSH_D_FAIL, 
                    ("Failed to allocate memory for IP addresses"));

          /* Move unused items to free list */
          while (!IsListEmpty(&temp_list1))
            {
              entry = RemoveHeadList(&temp_list1);
              InitializeListHead(entry);
              InsertTailList(&free_list, entry);
            }

          /* Clear temp_list2 */
          while (!IsListEmpty(&temp_list2))
            {
              entry = RemoveHeadList(&temp_list2);
              InitializeListHead(entry);
              InsertTailList(&free_list, entry);
              ip_if = CONTAINING_RECORD(entry, SshIPInterfaceStruct, link);
              ssh_free(ip_if->addrs);
            }

          success = FALSE;
          goto alloc_failed;
        }

      ip_if->num_addrs = 0;
      for (i = 0; i < device->caddr; i++)
        {
          ai = &(((SshIpdevAddressInfo)device->addrs)[i]);

          if (ai->system_idx == ip_if->system_idx)
            {
              if (!SSH_IP_DEFINED(&ai->if_addr.addr.ip.ip)
                  || SSH_IP_IS_NULLADDR(&ai->if_addr.addr.ip.ip))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW, 
                            ("Discarding invalid/undefined IP address!"));
                  continue;
                }

              if (SSH_IP_IS_LOOPBACK(&ai->if_addr.addr.ip.ip))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Discarding loopback address %@",
                             ssh_ipaddr_render, &ai->if_addr.addr.ip.ip));
                  continue;
                }

              if (SSH_IP_IS_MULTICAST(&ai->if_addr.addr.ip.ip))
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Discarding multicast address %@",
                             ssh_ipaddr_render, &ai->if_addr.addr.ip.ip));
                  continue;
                }

              if (ai->dad_state != IpDadStatePreferred)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Discarding tentative (or otherwise invalid) "
                             "address %@",
                             ssh_ipaddr_render, &ai->if_addr.addr.ip.ip));
                  continue;
                }

              ip_if->addrs[ip_if->num_addrs] = ai->if_addr;
              ip_if->num_addrs++;
            }
        }

      ssh_kernel_rw_mutex_unlock_read(&device->addr_lock);

      SSH_ASSERT(ip_if->num_addrs <= num_addrs);
    }

  /* All succeeded! Move items to the final destination list */
  while (!IsListEmpty(&temp_list2))
    {
      entry = RemoveHeadList(&temp_list2);
      InitializeListHead(entry);
      InsertTailList(list, entry);
    }
      
 alloc_failed:

  /* Add 'extra', unused structures to free list */
  ssh_kernel_mutex_lock(&device->free_list_lock);
  while (!IsListEmpty(&free_list))
    {
      entry = RemoveHeadList(&free_list);
      InsertTailList(&device->ip_if_free_list, entry);

      num_ifs--;
    }
  ssh_kernel_mutex_unlock(&device->free_list_lock);

  if (if_cnt_return != NULL)
    {
      if (success)
        *if_cnt_return = num_ifs;
      else
        *if_cnt_return = 0;
    }

  return (success);
}


void
ssh_ipdev_clear_address(SshIPDevice device,
                        SshAddressCtx addr_ctx,
                        SshIPDeviceCompletionCB callback,
                        void *context)
{
  SSH_ASSERT(device != NULL);

  if (device->clear_address == NULL_FNPTR)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  (*device->clear_address)(device, addr_ctx, callback, context);
}




























Boolean
ssh_ipdev_find_first_address(SshIPDevice device,
                             SshAdapter adapter,
                             SshAddressCtx *ctx_return)
{
  SshIFIndex system_idx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ctx_return != NULL);





  if (device->find_first_address == NULL_FNPTR)
    return FALSE;

  system_idx = ssh_ipdev_system_idx_lookup(device, adapter);
  if (system_idx == SSH_IPDEV_INVALID_SYSTEM_IDX)
    return FALSE;

  return ((*device->find_first_address)(device, system_idx, ctx_return));
}


Boolean 
ssh_ipdev_configure(SshIPDevice ip_dev,
                    SshAdapter adapter,
                    SshUInt16 configure_type,
                    void *configure_params)
{
  SshIFIndex system_idx;

  if (ip_dev->configure == NULL_FNPTR)
    return FALSE;

  system_idx = ssh_ipdev_system_idx_lookup(ip_dev, adapter);
  if (system_idx == SSH_IPDEV_INVALID_SYSTEM_IDX)
    return FALSE;

  return ((*ip_dev->configure)(ip_dev, system_idx, 
                               configure_type, configure_params));
}

void
ssh_ipdev_set_address(SshIPDevice device,
                      SshAddressCtx addr_ctx,
                      SshIpAddr ip,
                      SshIPDeviceCompletionCB callback,
                      void *context)
{
  SSH_ASSERT(device != NULL);
  SSH_ASSERT(ip != NULL);

  if (device->set_address == NULL_FNPTR)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  (*device->set_address)(device, addr_ctx, ip, callback, context);
}


/*--------------------------------------------------------------------------
  Adds the specified IP address (alias) to the interface specified by 
  'adapter'. Returns ID number of the created address in 'id_return'.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_add_address(SshIPDevice device,
                      SshAdapter adapter,
                      SshIpAddr ip,
                      SshAddressCtx *ctx_return,
                      SshIPDeviceCompletionCB callback,
                      void *context)
{
  SshIFIndex system_idx;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(ip) != FALSE);

  if (device->add_address == NULL_FNPTR)
    goto failed;

  system_idx = ssh_ipdev_system_idx_lookup(device, adapter);
  if (system_idx == SSH_IPDEV_INVALID_SYSTEM_IDX)
    goto failed;

  (*device->add_address)(device, 
                         system_idx, 
                         adapter->ifnum,
                         ip, 
                         ctx_return, 
                         callback, 
                         context);
  return;

failed:

  if (ctx_return)
    *ctx_return = NULL;        

  if (callback != NULL_FNPTR)
    (*callback)(FALSE, context);
}


/*--------------------------------------------------------------------------;
  Deletes the IP address (alias) specified by the ID number previously 
  returned by ssh_ipdev_add_address().
  --------------------------------------------------------------------------*/
void
ssh_ipdev_delete_address(SshIPDevice device,
                         SshAddressCtx addr_ctx,
                         SshIPDeviceCompletionCB callback,
                         void *context)
{
  SSH_ASSERT(device != NULL);

  if (device->delete_address == NULL_FNPTR)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  (*device->delete_address)(device, addr_ctx, callback, context);
}


/*--------------------------------------------------------------------------
  Adds the specified route into the routing table.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_add_route(SshIPDevice device,
                    SshIPRoute route,
                    SshIPDeviceCompletionCB callback,
                    void *context)
{
  SSH_ASSERT(device != NULL);
  SSH_ASSERT(route != NULL);

  if (device->add_route == NULL_FNPTR)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  (*device->add_route)(device, route, callback, context);
}


/*--------------------------------------------------------------------------
  Removes the specified route from the routing table.
  --------------------------------------------------------------------------*/
void
ssh_ipdev_remove_route(SshIPDevice device,
                       SshIPRoute route,
                       SshIPDeviceCompletionCB callback,
                       void *context)
{
  SshIpdevRouteInfo ri;
  unsigned int i;

  SSH_ASSERT(device != NULL);
  SSH_ASSERT(route != NULL);

  /* Search for a matching route */
  ssh_kernel_rw_mutex_lock_read(&device->route_lock);
  for (i = 0; i < device->croute; i++)
    {
      ri = &((SshIpdevRouteInfo)device->routes)[i];

      if (route->type == SSH_IP_ROUTE_INDIRECT)
        {
          if (ri->system_idx == route->system_idx &&
              SSH_IP_EQUAL(&ri->dest, &route->dest) &&
              SSH_IP_EQUAL(&ri->nm, &route->nm) &&
              SSH_IP_EQUAL(&ri->gw, &route->gw))
            break;
        }
      else
        {
          if (ri->system_idx == route->system_idx &&
              SSH_IP_EQUAL(&ri->dest, &route->dest) &&
              SSH_IP_EQUAL(&ri->nm, &route->nm))
            break;
        }
    }
  ssh_kernel_rw_mutex_unlock_read(&device->route_lock);

  if (i >= device->croute)
    {
      /* Not found. */
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  if (device->remove_route == NULL_FNPTR)
    {
      if (callback != NULL_FNPTR)
        (*callback)(FALSE, context);

      return;
    }

  (*device->remove_route)(device, route, callback, context); 
}


