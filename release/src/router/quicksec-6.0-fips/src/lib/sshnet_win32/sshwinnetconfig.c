/**
   @copyright
   Copyright (c) 2008 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows implementation of the sshnetconfig.h API. This implementation
   uses the IP Helper functions.
*/









#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetconfig.h"
#include "netconfig_ioctl.h"

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi")

/*  As of now don't compile on Windows CE platform */
#ifdef WINDOWS

#define SSH_DEBUG_MODULE "SshWinNetConfig"

#ifdef Byte
#undef Byte
#endif /* Byte */

#define MAX_ADAPTER_NAME_LENGTH 256

static
SshNetconfigError winconfig_win_error_to_netconfig(SshUInt32 error)
{
#ifdef DEBUG_LIGHT
  void *error_msg = NULL;
  if ((error != ERROR_SUCCESS) ||
        (error != NO_ERROR))
    {
      if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                           FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL, error,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPTSTR)&error_msg, 0, NULL))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Error : %s", error_msg));
          LocalFree(error_msg);
        }
    }
#endif /* DEBUG_LIGHT */
  switch(error)
    {
    case NO_ERROR:
      return SSH_NETCONFIG_ERROR_OK;
    case ERROR_INSUFFICIENT_BUFFER:
      return SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
    case ERROR_INVALID_PARAMETER:
      return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
    case ERROR_NOT_SUPPORTED:
    default:
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}


/* Converts 255.255.255.0 type style to /24 */
static SshUInt8 winconfig_calculate_mask(SshUInt32 address)
{
  SshUInt8 count = 0;

  if (address == 0xffffffff)
    return 32;

  while (address != 0)
    {
      address = address << 1;
      count++;
    }

  return count;
}

#if 0
static Boolean winconfig_is_xp_or_later()
{
  OSVERSIONINFOEX version;

  memset(&version, 0, sizeof(OSVERSIONINFOEX));
  version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

  GetVersionEx(&version);

  if ((version.dwMajorVersion > 5) ||
        ((version.dwMajorVersion == 5) &&
           (version.dwMinorVersion >= 1)))
    return TRUE;
  return FALSE;
}
#endif

#define NET_ADAPTERS_KEY  "System\\CurrentControlSet\\Control\\Network\\" \
                          "{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
#define NET_CONNECTION_NAME_KEY "\\Connection"


static Boolean
winconfig_read_value_from_registry(HKEY root_key,
                                   const unsigned char *path,
                                   const unsigned char *value_name,
                                   unsigned char *value_data,
                                   size_t value_size)
{
  HKEY handle;
  SshUInt32 status;

  if ((status = RegOpenKeyExA(root_key, path,
                              0, KEY_QUERY_VALUE,&handle))
                                      == ERROR_SUCCESS)
    {
      DWORD size = (DWORD)value_size;

      status = RegQueryValueExA(handle, value_name,
                                NULL, NULL,
                                (LPBYTE)value_data, &size);
      RegCloseKey(handle);
      return ((status == ERROR_SUCCESS) ? TRUE : FALSE);
    }
  return FALSE;
}

typedef struct SshNetconfigAdapterInfoRec
{
  Boolean is_ifnum;
  char adapter_name[MAX_ADAPTER_NAME_LENGTH + 4];
  SshUInt32 ifnum;
}SshNetconfigAdapterInfoStruct, *SshNetconfigAdapterInfo;

static SshNetconfigError
winconfig_resolve_ifname(SshNetconfigAdapterInfo adapter_info)
{
  PIP_ADAPTER_INFO adapter_list;
  PIP_ADAPTER_INFO adapter;
  SshUInt32 size = 0;
  SshUInt32 ret = 0;
  Boolean found = FALSE;
  char buffer[MAX_ADAPTER_NAME_LENGTH];
  char regpath[1024];
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;

  if ((ret = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("GetAdaptersInfo() returned unexpected error code 0x%08X",
                 ret));
      return winconfig_win_error_to_netconfig(ret);
    }

  adapter_list = (PIP_ADAPTER_INFO) ssh_calloc(1,size);
  if (adapter_list == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
              ("Failed to allocate memory for IP_ADAPTER_INFO structures!"));
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }

  ret = GetAdaptersInfo(adapter_list, &size);

  if (ret != ERROR_SUCCESS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("GetAdaptersInfo() failed, error code 0x%08X", ret));
      status = winconfig_win_error_to_netconfig(ret);
      goto out;
    }
  for (adapter = adapter_list; adapter; adapter = adapter->Next)
    {
      ssh_snprintf(regpath, sizeof(regpath),
                   "%s%s%s", NET_ADAPTERS_KEY, adapter->AdapterName,
                   NET_CONNECTION_NAME_KEY);

      if (!winconfig_read_value_from_registry(HKEY_LOCAL_MACHINE,
                                              regpath, "Name",
                                              buffer,
                                              MAX_ADAPTER_NAME_LENGTH))
        continue;

      if (adapter_info->is_ifnum)
        {

          if (adapter->Index == adapter_info->ifnum)
            {
              memcpy(adapter_info->adapter_name, buffer,
                    sizeof(adapter_info->adapter_name));
              found = TRUE;
              break;
            }
        }
      else
        {
          if (ssh_ustrncmp(adapter_info->adapter_name,
                           buffer,
                           ssh_ustrlen(adapter_info->adapter_name)) == 0)
          {
            adapter_info->ifnum = adapter->Index;
            found = TRUE;
            break;
          }
        }
    }

  if (!found)
    status = SSH_NETCONFIG_ERROR_NON_EXISTENT;

out:
  ssh_free(adapter_list);
  return status;
}

static SshNetconfigError
winconfig_get_addresses_ipv4(SshUInt32 ifnum,
                             SshUInt32 *num_addresses,
                             SshNetconfigInterfaceAddr addresses)
{
  PMIB_IPADDRTABLE table = NULL;
  SshUInt32 size = 0;
  SshUInt32 ret = 0;
  SshUInt32 i, count = 0;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;

  if ((ret = GetIpAddrTable(NULL, &size, 0)) !=
                               ERROR_INSUFFICIENT_BUFFER)
    return winconfig_win_error_to_netconfig(ret);

  table = (MIB_IPADDRTABLE *) ssh_calloc(1,size);
  if (table == NULL)
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  ret = GetIpAddrTable(table, &size, 0);
  if (ret != NO_ERROR)
    {
      status = winconfig_win_error_to_netconfig(ret);
      goto out;
    }

  for (i = 0; i < table->dwNumEntries; i++)
    {
      SshNetconfigInterfaceAddr addr;
      SshUInt8 mask;
      if (ifnum != table->table[i].dwIndex)
        continue;

      if (count >= *num_addresses)
        {
          status = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
          goto out;
        }
      addr = &addresses[count];
      mask = winconfig_calculate_mask(ntohl(table->table[i].dwMask));

      SSH_IP_UNDEFINE(&addr->address);
      SSH_IP_UNDEFINE(&addr->broadcast);

      SSH_IP4_MASK_DECODE(&addr->address,
                          &table->table[i].dwAddr,
                          mask);
      ssh_ipaddr_set_bits(&addr->broadcast, &addr->address, mask, 1);

      /* Ignore 0.0.0.0/0 */
      if (!SSH_IP_IS_NULLADDR(&addr->address))
        count++;
    }
  *num_addresses = count;
  if (count == 0)
    status  = SSH_NETCONFIG_ERROR_NON_EXISTENT;
out:
    ssh_free(table);
    return status;
}

static SshNetconfigError
winconfig_add_address_ipv4(SshUInt32 ifnum,
                           SshNetconfigInterfaceAddr address)
{
  SshUInt32 nte_context;
  SshUInt32 nte_instance;
  SshIpAddrStruct ip;
  SshUInt32 ret;
  IPAddr addr, mask;

  /* Convert mask into in_addr */
  SSH_INT_TO_IP4(&ip, 0xffffffffUL);
  ssh_ipaddr_set_bits(&ip,
                      &ip,
                      SSH_IP_MASK_LEN(&address->address),
                      0);
  addr = htonl(SSH_IP4_TO_INT(&address->address));
  mask = htonl(SSH_IP4_TO_INT(&ip));
  ret = AddIPAddress(addr,
                     mask,
                     ifnum,
                     &nte_context,
                     &nte_instance);
  if (ret != NO_ERROR)
    return winconfig_win_error_to_netconfig(ret);

  return SSH_NETCONFIG_ERROR_OK;
}


static SshNetconfigError
winconfig_del_address_ipv4(SshUInt32 ifnum,
                           SshNetconfigInterfaceAddr address)
{
  PIP_ADAPTER_INFO adapter_list;
  PIP_ADAPTER_INFO adapter = NULL;
  SshUInt32 size;
  PIP_ADDR_STRING addr_string;
  SshUInt32 ret = 0;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_UNDEFINED;
  SshIpAddrStruct ip;

  if ((ret = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    return winconfig_win_error_to_netconfig(ret);

  adapter_list = (PIP_ADAPTER_INFO) ssh_calloc(1,size);
  if (adapter_list == NULL)
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  ret = GetAdaptersInfo(adapter_list, &size);

  if (ret != NO_ERROR)
    {
      status = winconfig_win_error_to_netconfig(ret);
      goto out;
    }

  for (adapter = adapter_list; adapter; adapter = adapter_list->Next)
    {
      if (adapter->Index == ifnum)
        {
          addr_string = &adapter->IpAddressList;
          while (addr_string)
            {
              ssh_ipaddr_parse(&ip, addr_string->IpAddress.String);
              if (SSH_IP_EQUAL(&ip, &address->address))
                {
                  ret = DeleteIPAddress(addr_string->Context);
                  if (ret == NO_ERROR)
                    status = SSH_NETCONFIG_ERROR_OK;
                  else
                    status = winconfig_win_error_to_netconfig(ret);
                  goto out;
                }
              else
                {
                  addr_string = addr_string->Next;
                }
            }
          break;
        }
    }
out:
  ssh_free(adapter_list);
  return status;
}

#if WINVER >= 0x0600
#if 0
static SshNetconfigError
winconfig_get_addresses_all(SshUInt32 ifnum,
                            SshUInt32 *num_addresses,
                            SshNetconfigInterfaceAddr addresses)
{
  PIP_ADAPTER_ADDRESSES table;
  PIP_ADAPTER_UNICAST_ADDRESS unicast_list;
  PIP_ADAPTER_PREFIX prefix_list;
  SOCKET_ADDRESS socket_addr, prefix_addr;
  SshUInt32 size = 0;
  SshUInt32 ret = 0;
  SshUInt32 count = 0;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;

  if ((ret = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_INCLUDE_PREFIX |
                                  GAA_FLAG_SKIP_ANYCAST |
                                  GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_DNS_SERVER |
                                  GAA_FLAG_SKIP_FRIENDLY_NAME ,
                                  NULL,
                                  NULL,
                                  &size)) ==
                               ERROR_BUFFER_OVERFLOW)
    {
      table = (IP_ADAPTER_ADDRESSES *) ssh_calloc(1,size);
      if (table == NULL)
        return SSH_NETCONFIG_ERROR_UNDEFINED;
      ret = GetAdaptersAddresses(AF_UNSPEC,
                                 GAA_FLAG_INCLUDE_PREFIX |
                                 GAA_FLAG_SKIP_ANYCAST |
                                 GAA_FLAG_SKIP_MULTICAST |
                                 GAA_FLAG_SKIP_DNS_SERVER |
                                 GAA_FLAG_SKIP_FRIENDLY_NAME ,
                                 NULL, table, &size);
    }

  if (ret == NO_ERROR)
    {
      SshNetconfigInterfaceAddr addr;
      PIP_ADAPTER_ADDRESSES item = NULL;

      for (item = table; item != NULL; item = item->Next)
        {
          if (ifnum == item->IfIndex)
            break;
        }
      if (item == NULL)
        {
          *num_addresses = 0;
          ret = SSH_NETCONFIG_ERROR_NON_EXISTENT;
          goto out;
        }






      prefix_list = item->FirstPrefix;
      for (unicast_list = item->FirstUnicastAddress;
                           unicast_list;
                           unicast_list = unicast_list->Next)
        {
          if (count >= *num_addresses)
            {
              status = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
              goto out;
            }

          addr = &addresses[count];

          SSH_IP_UNDEFINE(&addr->address);
          SSH_IP_UNDEFINE(&addr->broadcast);

          socket_addr = unicast_list->Address;

          if ((((struct sockaddr *)socket_addr.lpSockaddr)->sa_family)
                                              == AF_INET)
            {



              prefix_addr = prefix_list->Address;
              SSH_ASSERT(((struct sockaddr *)prefix_addr.lpSockaddr)
                              ->sa_family == AF_INET);
              SSH_IP4_MASK_DECODE(&addr->address,
                                  &((PSOCKADDR_IN)socket_addr.lpSockaddr)
                                                        ->sin_addr.s_addr,
                                  prefix_list->PrefixLength);
              ssh_ipaddr_set_bits(&addr->broadcast, &addr->address,
                                               prefix_list->PrefixLength, 1);
            }
          else if ((((struct sockaddr *)socket_addr.lpSockaddr)->sa_family)
                                              == AF_INET6)
            {
              prefix_addr = prefix_list->Address;
              SSH_ASSERT(((struct sockaddr *)prefix_addr.lpSockaddr)
                              ->sa_family == AF_INET6);
              SSH_IP6_MASK_DECODE(&addr->address,
                                  &((PSOCKADDR_IN6)socket_addr.lpSockaddr)
                                                       ->sin6_addr.s6_addr,
                                  prefix_list->PrefixLength);
            }
          else
            {
              SSH_NOTREACHED;
            }

          if (prefix_list->Next != NULL)
            prefix_list = prefix_list->Next;

          /* Ignore 0.0.0.0/0 and ::/0 */
          if (!SSH_IP_IS_NULLADDR(&addr->address))
            count++;
        }

      *num_addresses = count;
    }
  else
    {
      status = winconfig_win_error_to_netconfig(ret);
    }
out:
    ssh_free(table);
    return status;
}
#endif

static SshNetconfigError
winconfig_get_addresses_all(SshUInt32 ifnum,
                            SshUInt32 *num_addresses,
                            SshNetconfigInterfaceAddr addresses)
{
  PMIB_UNICASTIPADDRESS_TABLE table;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;
  SshUInt32 ret;
  SshUInt32 i, count = 0;

  ret = GetUnicastIpAddressTable(AF_UNSPEC,
                                 &table);
  if (ret != NO_ERROR)
    return winconfig_win_error_to_netconfig(ret);

  for (i = 0; i < table->NumEntries; i++)
    {
      SshNetconfigInterfaceAddr addr;
      SshUInt8 mask;
      PMIB_UNICASTIPADDRESS_ROW row;

      row = &table->Table[i];

      if (ifnum != row->InterfaceIndex ||
            row->DadState != IpDadStatePreferred)
        continue;

      if (count >= *num_addresses)
        {
          status = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
          goto out;
        }
      addr = &addresses[count];
      mask = row->OnLinkPrefixLength;

      SSH_IP_UNDEFINE(&addr->address);
      SSH_IP_UNDEFINE(&addr->broadcast);

      if (row->Address.si_family == AF_INET)
        {
          SSH_IP4_MASK_DECODE(&addr->address,
                              &row->Address.Ipv4.sin_addr.s_addr,
                              mask);
          ssh_ipaddr_set_bits(&addr->broadcast, &addr->address, mask, 1);
        }
      else if (row->Address.si_family == AF_INET6)
        {
          SSH_IP6_MASK_DECODE(&addr->address,
                              row->Address.Ipv6.sin6_addr.s6_addr,
                              mask);
          ssh_ipaddr_set_bits(&addr->broadcast, &addr->address, mask, 1);
        }
      else
        {
          ; /* DO nothing */
        }
      if (!SSH_IP_IS_NULLADDR(&addr->address))
        count++;
    }
  *num_addresses = count;
out:
  FreeMibTable(table);
  return status;
}

static SshNetconfigError
winconfig_modify_address_all(Boolean add,
                             SshUInt32 ifnum,
                             SshNetconfigInterfaceAddr address)
{
  MIB_UNICASTIPADDRESS_ROW  row_entry;
  SshUInt32 ret;

  InitializeUnicastIpAddressEntry(&row_entry);
  row_entry.InterfaceIndex = ifnum;

  row_entry.OnLinkPrefixLength = SSH_IP_MASK_LEN(&address->address);
  if (SSH_IP_IS4(&address->address))
    {
      row_entry.Address.Ipv4.sin_family = AF_INET;
      SSH_IP4_ENCODE(&address->address,
                     &row_entry.Address.Ipv4.sin_addr.s_addr);
    }
  else
    {
      row_entry.Address.Ipv6.sin6_family = AF_INET6;
      SSH_IP6_ENCODE(&address->address,
                      &row_entry.Address.Ipv6.sin6_addr.s6_addr);
    }
  if (add)
    ret = CreateUnicastIpAddressEntry(&row_entry);
  else
    ret = DeleteUnicastIpAddressEntry(&row_entry);
  if (ret != NO_ERROR)
    return winconfig_win_error_to_netconfig(ret);

  return SSH_NETCONFIG_ERROR_OK;
}
#endif /* WINVER >= 0x0600 */


static SshNetconfigError
ssh_netconfig_get_route_ipv4(SshIpAddr prefix,
                             SshUInt32 *num_routes,
                             SshNetconfigRoute routes)
{
  PMIB_IPFORWARDTABLE table = NULL;
  SshUInt32 size = 0;
  SshUInt32 ret = 0;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;
  unsigned int i, count =0;

  if ((ret = GetIpForwardTable(NULL, &size, TRUE)) !=
                                ERROR_INSUFFICIENT_BUFFER)
    return winconfig_win_error_to_netconfig(ret);

  table = (MIB_IPFORWARDTABLE *) ssh_calloc(1,size);
  if (table == NULL)
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  ret = GetIpForwardTable(table, &size, TRUE);

  if (ret != NO_ERROR)
    {
      status = winconfig_win_error_to_netconfig(ret);
      goto out;
    }

  for (i = 0; i < table->dwNumEntries; i++)
    {
      SshNetconfigRoute route;
      SshUInt8 mask;




      if (table->table[i].dwForwardType &
                           MIB_IPROUTE_TYPE_INVALID)
        continue;

      if (count >= *num_routes)
        {
          status = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
          goto out;
        }

      route = &routes[count];

      SSH_IP_UNDEFINE(&route->prefix);
      SSH_IP_UNDEFINE(&route->gateway);

      mask =
         winconfig_calculate_mask(ntohl(table->table[i].dwForwardMask));
      SSH_IP4_MASK_DECODE(&route->prefix,
                          &table->table[i].dwForwardDest,
                          mask);
      SSH_IP4_DECODE(&route->gateway,
                          &table->table[i].dwForwardNextHop);
      route->ifnum = table->table[i].dwForwardIfIndex;
      route->metric = table->table[i].dwForwardMetric1;
      if (!SSH_IP_DEFINED(&route->prefix))
        {
          status = SSH_NETCONFIG_ERROR_UNDEFINED;
          goto out;
        }
      else if (prefix == NULL
          || SSH_IP_MASK_EQUAL(&route->prefix, prefix))
         count++;
    }
  *num_routes = count;
out:
  ssh_free(table);
  return status;
}

#if  WINVER >= 0x0600
SshNetconfigError
ssh_netconfig_get_route_all(SshIpAddr prefix,
                             SshUInt32 *num_routes,
                             SshNetconfigRoute routes)
{
  PMIB_IPFORWARD_TABLE2 table;
  SshUInt32 ret = 0;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;
  SshUInt32 i, count = 0;

  ret = GetIpForwardTable2(AF_UNSPEC,
                           &table);
  if (ret != NO_ERROR)
    return winconfig_win_error_to_netconfig(ret);

  for (i = 0; i < table->NumEntries; i++)
    {
      SshNetconfigRoute route;
      PMIB_IPFORWARD_ROW2 row;

      if (count >= *num_routes)
        {
          status = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
          goto out;
        }
      route = &routes[count];
      row = &table->Table[i];

      SSH_IP_UNDEFINE(&route->prefix);
      SSH_IP_UNDEFINE(&route->gateway);

      if (row->DestinationPrefix.Prefix.si_family == AF_INET)
        {
          SSH_IP4_MASK_DECODE(
                          &route->prefix,
                          &row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr,
                          row->DestinationPrefix.PrefixLength);
          SSH_IP4_DECODE(&route->gateway,
                          &row->NextHop.Ipv4.sin_addr.s_addr);

        }
      else if (row->DestinationPrefix.Prefix.si_family == AF_INET6)
        {
          SSH_IP6_MASK_DECODE(
                        &route->prefix,
                        row->DestinationPrefix.Prefix.Ipv6.sin6_addr.s6_addr,
                          row->DestinationPrefix.PrefixLength);
          SSH_IP6_DECODE(&route->gateway,
                          row->NextHop.Ipv6.sin6_addr.s6_addr);
        }
      else
        {
        }
      route->ifnum = row->InterfaceIndex;
      route->metric = row->Metric;
          count++;
    }
  *num_routes = count;
out:
  FreeMibTable(table);
  return status;
}
#endif /* WINVER >= 0x0600 */


SshNetconfigError ssh_netconfig_get_link(SshUInt32 ifnum,
                                         SshNetconfigLink link)
{
  MIB_IFROW if_row = { 0 };
  SshUInt32 size = 0;
  SshUInt32 ret;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if_row.dwIndex = ifnum;

  ret = GetIfEntry(&if_row);

  if (ret == NO_ERROR)
    {
      link->ifnum = if_row.dwIndex;
      link->iflink = if_row.dwIndex;
      SSH_ASSERT(if_row.dwMtu <= 0xFFFF);
      link->mtu = (SshUInt16)if_row.dwMtu;
      link->speed = if_row.dwSpeed/1000;
      size = if_row.dwPhysAddrLen < SSH_NETCONFIG_MEDIA_ADDRLEN ?
                    if_row.dwPhysAddrLen: SSH_NETCONFIG_MEDIA_ADDRLEN;
      memcpy(link->media_addr, &if_row.bPhysAddr, size);
      link->addr_len = size;



      memset(link->broadcast_addr, 0, SSH_NETCONFIG_MEDIA_ADDRLEN);
      link->flags = 0;
    }
  else
    {
      status = winconfig_win_error_to_netconfig(ret);
    }
  return status;
}


SshNetconfigError ssh_netconfig_set_link_flags(SshUInt32 ifnum,
                                               SshUInt32 flags,
                                               SshUInt32 mask)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}


SshNetconfigError ssh_netconfig_set_link_mtu(SshUInt32 ifnum,
                                             SshUInt16 mtu)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}


SshNetconfigError
ssh_netconfig_resolve_ifname(const unsigned char *ifname,
                             SshUInt32 *ifnum_ret)
{
  SshNetconfigAdapterInfoStruct adapter_info = {0};
  size_t len;
  SshNetconfigError status;

  len = ssh_ustrlen(ifname);
  if (len > MAX_ADAPTER_NAME_LENGTH + 3)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  adapter_info.is_ifnum = FALSE;
  ssh_ustrncpy(adapter_info.adapter_name, ifname, len);
  if ((status = winconfig_resolve_ifname(&adapter_info))
                  != SSH_NETCONFIG_ERROR_OK)
    return status;
  else
    *ifnum_ret = adapter_info.ifnum;

  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_resolve_ifnum(SshUInt32 ifnum,
                            unsigned char *ifname,
                            size_t ifname_len)
{
  SshNetconfigAdapterInfoStruct adapter_info = {0};
  SshNetconfigError status;
  size_t len;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  adapter_info.is_ifnum = TRUE;
  adapter_info.ifnum = ifnum;
  if ((status = winconfig_resolve_ifname(&adapter_info))
                  != SSH_NETCONFIG_ERROR_OK)
    {
      return status;
    }
  else
    {
      len = ssh_ustrlen(adapter_info.adapter_name);
      if (len >= ifname_len)
        return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
      ssh_ustrncpy(ifname, adapter_info.adapter_name, len);
      ifname[len] = '\0';
    }

  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_link_multicast_add_membership(SshUInt32 ifnum,
                                            unsigned char *mcast_addr,
                                            size_t mcast_addr_len)
{
  HANDLE handle;
  DWORD bytes_returned;
  SshNetconfigError error_code = SSH_NETCONFIG_ERROR_UNDEFINED;

  handle = CreateFile(SSH_NETCONFIG_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);

  if (handle == INVALID_HANDLE_VALUE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Can not access kernel-mode NETCONFIG library"));
    }
  else
    {
#if WINVER >= 0x0600
      MIB_IF_ROW2 if_row;

      memset(&if_row, 0, sizeof(if_row));
      if_row.InterfaceIndex = ifnum;

      if (GetIfEntry2(&if_row) != NO_ERROR)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to retrieve interface information!"));
        }
      else
#endif /* WINVER >= 0x0600 */
        {
          SshIoctlRequestAddMulticastStruct request;

          memset(&request, 0, sizeof(request));
#if WINVER >= 0x0600
          request.luid = if_row.InterfaceLuid.Value;
#else
          request.luid = (SshUInt64)ifnum;
#endif /* WINVER >= 0x0600 */
          request.mcast_addr_len = (SshUInt32)mcast_addr_len;

          if (mcast_addr_len <= sizeof(request.mcast_addr))
            {
              memcpy(request.mcast_addr, mcast_addr, mcast_addr_len);

              if (!DeviceIoControl(handle, SSH_IOCTL_NETCONFIG_ADD_MULTICAST,
                                   &request, sizeof(request), NULL, 0,
                                   &bytes_returned, NULL))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Failed to add multicast address!"));
                }
              else
                {
                  error_code = SSH_NETCONFIG_ERROR_OK;
                }
            }
          else
            {
              SSH_NOTREACHED;
            }
        }

      CloseHandle(handle);
    }

  return error_code;
}



SshNetconfigError
ssh_netconfig_link_multicast_drop_membership(SshUInt32 ifnum,
                                             unsigned char *mcast_addr,
                                             size_t mcast_addr_len)
{
  HANDLE handle;
  DWORD bytes_returned;
  SshNetconfigError error_code = SSH_NETCONFIG_ERROR_UNDEFINED;

  handle = CreateFile(SSH_NETCONFIG_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);

  if (handle == INVALID_HANDLE_VALUE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Can not access kernel-mode NETCONFIG library"));
    }
  else
    {
#if WINVER >= 0x0600
      MIB_IF_ROW2 if_row;

      memset(&if_row, 0, sizeof(if_row));
      if_row.InterfaceIndex = ifnum;

      if (GetIfEntry2(&if_row) != NO_ERROR)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to retrieve interface information!"));
        }
      else
#endif /* WINVER >= 0x0600 */
        {
          SshIoctlRequestAddMulticastStruct request;

          memset(&request, 0, sizeof(request));
#if WINVER >= 0x0600
          request.luid = if_row.InterfaceLuid.Value;
#else
          request.luid = (SshUInt64)ifnum;
#endif /* WINVER >= 0x0600 */
          request.mcast_addr_len = (SshUInt32)mcast_addr_len;

          if (mcast_addr_len <= sizeof(request.mcast_addr))
            {
              memcpy(request.mcast_addr, mcast_addr, mcast_addr_len);

              if (!DeviceIoControl(handle, SSH_IOCTL_NETCONFIG_DROP_MULTICAST,
                                   &request, sizeof(request), NULL, 0,
                                   &bytes_returned, NULL))
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Failed to drop multicast membership!"));
                }
              else
                {
                  error_code = SSH_NETCONFIG_ERROR_OK;
                }
            }
          else
            {
              SSH_NOTREACHED;
            }
        }

      CloseHandle(handle);
    }

  return error_code;
}


SshNetconfigError
ssh_netconfig_get_addresses(SshUInt32 ifnum,
                            SshUInt32 *num_addresses,
                            SshNetconfigInterfaceAddr addresses)
{
  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

#if WINVER >= 0x0600
  return winconfig_get_addresses_all(ifnum,
                                      num_addresses,
                                      addresses);
#else /* WINVER */
  return winconfig_get_addresses_ipv4(ifnum,
                                     num_addresses,
                                     addresses);

#endif /* WINVER */
}



SshNetconfigError
ssh_netconfig_add_address(SshUInt32 ifnum,
                          SshNetconfigInterfaceAddr address)
{
  if ((ifnum == SSH_INVALID_IFNUM) ||
         (address == NULL) ||
                 !SSH_IP_DEFINED(&address->address))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

#if WINVER >= 0x0600
  return winconfig_modify_address_all(TRUE,
                                      ifnum, address);
#else /* WINVER >= 0x0600 */
  if (SSH_IP_IS6(&address->address))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
  return winconfig_add_address_ipv4(ifnum, address);
#endif /* WINVER >= 0x0600 */
}


SshNetconfigError
ssh_netconfig_del_address(SshUInt32 ifnum,
                          SshNetconfigInterfaceAddr address)
{
  if ((ifnum == SSH_INVALID_IFNUM) ||
         (address == NULL) ||
                 !SSH_IP_DEFINED(&address->address))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
#if WINVER >= 0x0600
  return winconfig_modify_address_all(FALSE,
                                      ifnum, address);
#else /* WINVER >= 0x0600 */
  if (SSH_IP_IS6(&address->address))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
  return winconfig_del_address_ipv4(ifnum, address);
#endif /* WINVER >= 0x0601 */
}


SshNetconfigError
ssh_netconfig_flush_addresses(SshUInt32 ifnum)
{



  return SSH_NETCONFIG_ERROR_UNDEFINED;
}


SshNetconfigError
ssh_netconfig_get_route(SshIpAddr prefix,
                        SshUInt32 *num_routes,
                        SshNetconfigRoute routes)
{
#if WINVER >= 0x0600
  return ssh_netconfig_get_route_all(prefix,
                                      num_routes,
                                      routes);
#else /* WINVER*/
  return ssh_netconfig_get_route_ipv4(prefix,
                                      num_routes,
                                      routes);
#endif /* WINVER*/
}


SshNetconfigError
ssh_netconfig_add_route(SshNetconfigRoute route)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}


SshNetconfigError
ssh_netconfig_del_route(SshNetconfigRoute route)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}


SshUInt32
ssh_netconfig_route_metric(SshRoutePrecedence precedence, Boolean ipv6)
{
  return 1;
}

SshNetconfigError
ssh_netconfig_get_links(SshUInt32 *ifnums, SshUInt32 *num_ifnums)
{
  PIP_INTERFACE_INFO interface_info;
  SshUInt32 size = 0;
  SshUInt32 ret = 0;
  SshUInt32 i;
  SshNetconfigError status = SSH_NETCONFIG_ERROR_OK;

  if ((ret = GetInterfaceInfo(NULL, &size)) !=
                                       ERROR_INSUFFICIENT_BUFFER)
    return winconfig_win_error_to_netconfig(ret);

  interface_info = (PIP_INTERFACE_INFO) ssh_calloc(1,size);
  if (interface_info == NULL)
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  ret = GetInterfaceInfo(interface_info, &size);
  if (ret == NO_ERROR)
    {
      if (*num_ifnums < (SshUInt32)interface_info->NumAdapters)
        {
          status = SSH_NETCONFIG_ERROR_OUT_OF_MEMORY;
          goto out;
        }

      *num_ifnums = interface_info->NumAdapters;
      for(i = 0; i < *num_ifnums; i++)
        ifnums[i] = interface_info->Adapter[i].Index;
    }
  else
    {
      status = winconfig_win_error_to_netconfig(ret);
    }
out:
  ssh_free(interface_info);
  return status;
}
#endif /* WINDOWS */
