/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Kernel mode IP interface information retrieval functions
   for Windows NT4, Windows 2000, Windows XP and Windows 2003 Server packet
   interceptor drivers.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

#include "sshincludes.h"
#include "interceptor_i.h"
#include "win_ip_interface.h"
#include "wan_interface.h"
#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef SSH_BUILD_IPSEC
#include "virtual_adapter_private.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/

#define SSH_DEBUG_MODULE "SshInterceptorIPInterfaces"


/*--------------------------------------------------------------------------
  LOCAL FUNCTIONS
  --------------------------------------------------------------------------*/

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
static Boolean __fastcall
ssh_media_addr_valid(SshAdapter adapter)
{
  unsigned int i;

  SSH_ASSERT(adapter != NULL);

  for (i = 0; i < adapter->media_addr_len; i++)
    {
      if (adapter->media_addr[i] != 0x00)
        return TRUE;
    }

  return FALSE;
}
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */


static void
ssh_ip_interface_list_exchange(LIST_ENTRY *dest,
                               LIST_ENTRY *src,
                               SshKernelRWMutex mutex)
{
  LIST_ENTRY old_list;
  PLIST_ENTRY entry = NULL;
  SshIPInterface ip_iface;

  NdisInitializeListHead(&old_list);

  /* This could be further optimized... */
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

  /* Free resources at the old destination list */
  while (!IsListEmpty(&old_list))
    {
      entry = RemoveHeadList(&old_list);
      ip_iface = CONTAINING_RECORD(entry, SshIPInterfaceStruct, link);
      ssh_ipdev_interface_free(ip_iface);
    }
}


static Boolean
ssh_ip_addresses_copy(SshInterceptorInterface *dest,
                      SshIPInterface src)
{
  ULONG i = 0, old_size = 0, new_size = 0;
  ULONG addr_size = sizeof(SshInterfaceAddressStruct);

  /* IP addresses */
  if (src->num_addrs > 0)
    {
      SshInterfaceAddress new_addrs;

      old_size = dest->num_addrs * addr_size;
      new_size = old_size + (src->num_addrs * addr_size);
      new_addrs = ssh_realloc(dest->addrs, old_size, new_size);
      if (new_addrs != NULL)
        {
          dest->addrs = new_addrs;

          for (i = 0; i < src->num_addrs; i++, dest->num_addrs++)
            *(dest->addrs + dest->num_addrs) = *(src->addrs + i);
          
          return TRUE;
        }
      else
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Failed to allocate memory for IP addresses!"));

          return FALSE;
        }
    }

  return TRUE;
}


/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

Boolean
ssh_ip_interface_list_refresh(SshInterceptor interceptor)
{
  PLIST_ENTRY entry;
  LIST_ENTRY ip_if_list;
  ULONG ip4_ic = 0;
  ULONG ip6_ic = 0;
  Boolean success = FALSE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("ssh_ip_interface_list_refresh()"));

  SSH_ASSERT(interceptor != NULL);

  /* Get new IP interface list */
  NdisInitializeListHead(&ip_if_list);

  success = ssh_ipdev_get_interface_list(&interceptor->ip4_dev, 
                                         &ip_if_list, &ip4_ic);
#if defined (WITH_IPV6)
  success &= ssh_ipdev_get_interface_list(&interceptor->ip6_dev, 
                                          &ip_if_list, &ip6_ic);
#endif /* WITH_IPV6 */

  if (success == FALSE)
    return FALSE;

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  
  for (entry = interceptor->adapter_list.Flink;
       entry != &interceptor->adapter_list; 
       entry = entry->Flink)
    {
      PLIST_ENTRY if_entry;

      SshAdapter adapter = CONTAINING_RECORD(entry, SshAdapterStruct, link);

      /* Go through all IP interfaces, identify the ones belonging to this
         adapter and fill the adapter specific portions of the IP interface
         structure. */
      if_entry = ip_if_list.Flink;
      while (if_entry != &ip_if_list)
        {
          SshIPInterface ip_if;

          ip_if = CONTAINING_RECORD(if_entry, SshIPInterfaceStruct, link);

          SSH_ASSERT(ip_if->id.id_type == SSH_IF_ID_ADAPTER_IFNUM);

          /* Check whether this IP interface belongs to this adapter */
          if (ip_if->id.u.ifnum == adapter->ifnum)
            {
              /* Fine-tune MTU for dial-up connections */
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

                      if ((wi->link_mtu > 0) 
                          && (wi->link_mtu < ip_if->mtu))
                        {
                          ip_if->mtu = wi->link_mtu;
                          ip_if->mtu = wi->link_mtu;
                        }
                    }
                }
              ssh_kernel_rw_mutex_unlock_read(&adapter->wan_if_lock);
            }

          if_entry = if_entry->Flink;
        }
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  /* Replace interface list with the new one */
  ssh_ip_interface_list_exchange(&interceptor->if_list, 
                                 &ip_if_list, &interceptor->if_lock);

  return TRUE;
}


static void
ssh_adapter_get_interface_info(SshAdapter adapter,
                               SshInterceptorInterface *ii)
{
  SshUInt32 n;

  SSH_ASSERT(adapter != NULL);
  SSH_ASSERT(ii != NULL);

  n = ssh_ustrlen(adapter->friendly_name);
  if (n >= sizeof ii->name)
    ii->name[0] = '\0';
  else
    memcpy(ii->name, adapter->friendly_name, n + 1);

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ii->media_addr[0] = 0;
  ii->media_addr_len = 0;
#else
  /* Set media address */
  if (adapter->media_addr_len > 0)
    {
      memcpy(ii->media_addr, adapter->media_addr, adapter->media_addr_len);
      ii->media_addr_len = adapter->media_addr_len;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Mark adapter to be Virtual Adapter. */
  if (adapter->va)
    {
      ii->flags |= SSH_INTERFACE_FLAG_VIP;
    }
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* Check if adapter is enabled */
  if ((adapter->state != SSH_ADAPTER_STATE_RUNNING) 
      || !adapter->media_connected)
    {
      ii->to_adapter.media = SSH_INTERCEPTOR_MEDIA_NONEXISTENT;
      ii->to_protocol.media = SSH_INTERCEPTOR_MEDIA_NONEXISTENT;
      ii->flags |= SSH_INTERFACE_FLAG_LINK_DOWN;
    }
  else
    {
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      ii->to_adapter.media = SSH_INTERCEPTOR_MEDIA_PLAIN;
      ii->to_protocol.media = SSH_INTERCEPTOR_MEDIA_PLAIN;
#else
      /* Set media type */
      switch (adapter->media)
        {
        default:
          SSH_NOTREACHED;
          break;

        case NdisMedium802_3:
          ii->to_adapter.media = SSH_INTERCEPTOR_MEDIA_ETHERNET;
          ii->to_protocol.media = SSH_INTERCEPTOR_MEDIA_ETHERNET;
          break;

        case NdisMediumWan:
        case NdisMediumCoWan:
        case NdisMediumWirelessWan:
          ii->to_adapter.media = SSH_INTERCEPTOR_MEDIA_PLAIN;
          ii->to_protocol.media = SSH_INTERCEPTOR_MEDIA_PLAIN;
          break;
        }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    }
}


Boolean
ssh_ip_interface_report_send(SshInterceptor interceptor)
{
  SshInterceptorInterface *if_list = NULL;
  SshUInt32 adapter_cnt;
  SshUInt32 valid_cnt;
  SshInterceptorIfnum i;







  while (InterlockedCompareExchange(&interceptor->if_report_disable_count,
                                    0, 0) != 0)
    NdisMSleep(1000);

  ssh_kernel_rw_mutex_lock_read(&interceptor->adapter_lock);
  adapter_cnt = SSH_INTERCEPTOR_MAX_ADAPTERS;
  while (adapter_cnt > 0 && 
         (interceptor->adapter_table[adapter_cnt - 1] == NULL))
    adapter_cnt--;
  ssh_kernel_rw_mutex_unlock_read(&interceptor->adapter_lock);

  if_list = ssh_calloc(adapter_cnt + 1, sizeof(*if_list));
  if (if_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate memory for interface list"));
      return FALSE;
    }

  ssh_kernel_rw_mutex_lock_read(&interceptor->if_lock);
  for (i = 0, valid_cnt = 0; i < adapter_cnt; i++)
    {
      SshInterceptorInterface *iface;
      SshAdapter adapter;

#ifdef SSH_IPSEC_SMALL
      iface = &if_list[i];
#else
      iface = &if_list[valid_cnt];
#endif /* SSH_IPSEC_SMALL */

      /* Initialize the interface with adapter specific information */
      adapter = ssh_adapter_ref_by_ifnum(interceptor, i);
      if (adapter != NULL)
        { 
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
          if (ssh_media_addr_valid(adapter))
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
            {
              /* If the adapter does not have a MAC address, we ignore it
                 (i.e. it's not included in the interface report) */
              PLIST_ENTRY if_entry;

              ssh_adapter_get_interface_info(adapter, iface);

              if_entry = interceptor->if_list.Flink;
              while (if_entry != &interceptor->if_list)
                {
                  SshIPInterface ip_if;

                  ip_if = CONTAINING_RECORD(if_entry, 
                                            SshIPInterfaceStruct, 
                                            link);

                  SSH_ASSERT(ip_if->id.id_type == SSH_IF_ID_ADAPTER_IFNUM);

                  if ((ip_if->id.u.ifnum == adapter->ifnum)
                      && (iface->to_adapter.media !=
                          SSH_INTERCEPTOR_MEDIA_NONEXISTENT))
                    {
                      if (ssh_ip_addresses_copy(iface, ip_if) == FALSE)
                        {
                          SSH_DEBUG(SSH_D_FAIL, 
                                    ("Failed to copy IP addresses!"));

                          for (i = 0; i < valid_cnt; i++)
                            ssh_free(if_list[i].addrs);
                          ssh_free(if_list);  

                          ssh_kernel_rw_mutex_unlock_read(
                                                       &interceptor->if_lock);
                          return FALSE;
                        }

                      if (ip_if->mtu != 0)
                        {
                          if (ip_if->owner_device_id == SSH_DD_ID_IP4)
                            {
                              iface->to_adapter.mtu_ipv4 = ip_if->mtu;
                              iface->to_protocol.mtu_ipv4 = ip_if->mtu;
                            }
#if defined(WITH_IPV6)
                          else
                            {






			      /* When an ipv6 interface starts, it begins
			         announcing mtu of zero. Converting this 
			         to minimum mtu of ipv6, since if we create
			         a flow when the interface is still reporting
			         0 mtu, the flows mtu ends up with 0. This is
			         obviously not a good thing? */
			      if (ip_if->mtu == 0)
			        {
			          iface->to_adapter.mtu_ipv6 = 1280;
			          iface->to_protocol.mtu_ipv6 = 1280;
			        }
			      else
			        {
			          iface->to_adapter.mtu_ipv6 = ip_if->mtu;
			          iface->to_protocol.mtu_ipv6 = ip_if->mtu;
			        }
                            }
#endif /* WITH_IPV6 */
                        }
                    }

                  if_entry = if_entry->Flink;
                }
#ifndef SSH_IPSEC_SMALL
              iface->ifnum = i; 
              valid_cnt++;
#endif /* !SSH_IPSEC_SMALL */
            }

          ssh_adapter_release(adapter);
        }
#ifdef SSH_IPSEC_SMALL
      else
        {
          iface->to_adapter.media = SSH_INTERCEPTOR_MEDIA_NONEXISTENT;
          iface->to_protocol.media = SSH_INTERCEPTOR_MEDIA_NONEXISTENT;
        }

      iface->ifnum = i; 
      valid_cnt++;
#endif /* SSH_IPSEC_SMALL */
    }
  ssh_kernel_rw_mutex_unlock_read(&interceptor->if_lock);

  /* Report interface information to the engine */
  if (interceptor->interfaces_cb != NULL_FNPTR)
    interceptor->interfaces_cb(valid_cnt, if_list, 
                               interceptor->engine_ctx);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
  /* Report the virtual adapters. */
  for (i = 0; i < valid_cnt; i++)
    {
      if (if_list[i].flags & SSH_INTERFACE_FLAG_VIP)
        {
          SshAdapter adapter = ssh_adapter_ref_by_ifnum(interceptor, 
                                                     if_list[i].ifnum);

          if (adapter)
            {
              /* In certain cases, this might already be disappeared. */
              if (adapter->va)
                ssh_virtual_adapter_report_addresses(adapter->va, 
                                                     if_list[i].addrs, 
                                                     if_list[i].num_addrs);

              ssh_adapter_release(adapter);
            }
        }
    }
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

  /* Dump interface information */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("network interface count = %d", valid_cnt));

  for (i = 0; i < valid_cnt; i++)
    {
      unsigned int j;      

#if defined(WITH_IPV6)   
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("if[%d, %s]: "
                 "to_adapter[flags(%u) media(%u) IPv4 MTU(%u) IPv6 MTU(%u)], " 
                 "to_protocol[flags(%u) media(%u) IPv4 MTU(%u) IPv6 MTU(%u)]",
                 if_list[i].ifnum, 
                 if_list[i].name,
                 if_list[i].to_adapter.flags, 
                 if_list[i].to_adapter.media,
                 if_list[i].to_adapter.mtu_ipv4,
                 if_list[i].to_adapter.mtu_ipv6,
                 if_list[i].to_protocol.flags, 
                 if_list[i].to_protocol.media,
                 if_list[i].to_protocol.mtu_ipv4,
                 if_list[i].to_protocol.mtu_ipv6));
#else
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("if[%d, %s]: ETHER_ADDRESS[%@], "
                 "to_adapter[flags(%u) media(%u) IPv4 MTU(%u) IPv6 MTU(%u)], " 
                 "to_protocol[flags(%u) media(%u) IPv4 MTU(%u) IPv6 MTU(%u)]",
                 if_list[i].ifnum, 
                 if_list[i].name,
                 ssh_etheraddr_render, if_list[i].media_addr,
                 if_list[i].to_adapter.flags, 
                 if_list[i].to_adapter.media,
                 if_list[i].to_adapter.mtu_ipv4,
                 if_list[i].to_adapter.mtu_ipv6,
                 if_list[i].to_protocol.flags, 
                 if_list[i].to_protocol.media,
                 if_list[i].to_protocol.mtu_ipv4,
                 if_list[i].to_protocol.mtu_ipv6));
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#else
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("if[%d, %s]: "
                 "to_adapter[flags(%u) media(%u) MTU(%u)], " 
                 "to_protocol[flags(%u) media(%u) MTU(%u)]",
                 if_list[i].ifnum, 
                 if_list[i].name,
                 if_list[i].to_adapter.flags, 
                 if_list[i].to_adapter.media,
                 if_list[i].to_adapter.mtu_ipv4,
                 if_list[i].to_protocol.flags, 
                 if_list[i].to_protocol.media,
                 if_list[i].to_protocol.mtu_ipv4));
#else
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("if[%d, %s]: ETHER_ADDRESS[%@], "
                 "to_adapter[flags(%u) media(%u) MTU(%u)], " 
                 "to_protocol[flags(%u) media(%u) MTU(%u)]",
                 if_list[i].ifnum, 
                 if_list[i].name,
                 ssh_etheraddr_render, if_list[i].media_addr,
                 if_list[i].to_adapter.flags, 
                 if_list[i].to_adapter.media,
                 if_list[i].to_adapter.mtu_ipv4,
                 if_list[i].to_protocol.flags, 
                 if_list[i].to_protocol.media,
                 if_list[i].to_protocol.mtu_ipv4));
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* WITH_IPV6 */

      for (j = 0; j < if_list[i].num_addrs; j++)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
             ("addr[%d, ip(%@), broadcast(%@), netmask(%@)]",
              j, 
              ssh_ipaddr_render, &(if_list[i].addrs[j].addr.ip.ip),
              ssh_ipaddr_render, 
                &(if_list[i].addrs[j].addr.ip.broadcast),
              ssh_ipaddr_render, 
                &(if_list[i].addrs[j].addr.ip.mask)));
        }
    }

  /* Free memory allocated for report */
  for (i = 0; i < adapter_cnt; i++)
    ssh_free(if_list[i].addrs);
  ssh_free(if_list);  

  return TRUE;
}


void
ssh_ip_interface_list_free(SshInterceptor interceptor)
{
  LIST_ENTRY empty;
  
  NdisInitializeListHead(&empty);

  ssh_ip_interface_list_exchange(&interceptor->if_list,
                                 &empty, &interceptor->if_lock);
}


