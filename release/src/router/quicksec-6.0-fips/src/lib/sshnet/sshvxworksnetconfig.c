/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   VxWorks implementation of the sshnetconfig.h API.
*/

#include "sshincludes.h"
#include "sshinet.h"
#include "sshnetconfig.h"

#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS

#include <version.h>
#include <endLib.h>
#include <strLib.h>

#define SSH_DEBUG_MODULE "SshVxworksNetconfig"

/*
 * Public functions.
 */

SshNetconfigError
ssh_netconfig_get_link(SshUInt32 ifnum, SshNetconfigLink link)
{
  END_OBJ *end;
  M2_PHYADDR *addr;

  if (!(end = (void *)ifnum))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  addr = &end->mib2Tbl.ifPhysAddress;
  if (addr->addrLength > SSH_NETCONFIG_MEDIA_ADDRLEN)
    {
      SSH_DEBUG(
        SSH_D_FAIL,
        ("Physical address of interface %s%d too long",
         end->devObject.name, end->devObject.unit));
      return SSH_NETCONFIG_ERROR_UNDEFINED;
    }

  memset(link, 0, sizeof *link);
  link->ifnum = (SshUInt32)end;
  link->iflink = (SshUInt32)end;
  memcpy(link->media_addr, addr->phyAddress, addr->addrLength);
  link->addr_len = addr->addrLength;
  link->mtu = end->mib2Tbl.ifMtu;

  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_set_link_flags(SshUInt32 ifnum, SshUInt32 flags, SshUInt32 mask)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

SshNetconfigError
ssh_netconfig_set_link_mtu(SshUInt32 ifnum, SshUInt16 mtu)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

SshNetconfigError
ssh_netconfig_resolve_ifname(const unsigned char *ifname, SshUInt32 *ifnum_ret)
{
  char name_buf[END_NAME_MAX + 1];
  size_t name_len;
  char *rest;
  long l;
  END_OBJ *end;
  int unit;

  if (!ifname)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  name_len = strcspn((const char *)ifname, "0123456789");
  if (name_len >= sizeof name_buf)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Interface name %s too long", ifname));
      return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
    }

  rest = (char *)ifname + name_len;
  if (!*rest || (l = strtol(rest, &rest, 10)) < 0 || l >= LONG_MAX || *rest)
    {
      SSH_DEBUG(SSH_D_FAIL, ("invalid interface name %s", ifname));
      return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;
    }
  unit = (int)l;

  memcpy(name_buf, ifname, name_len);
  name_buf[name_len] = '\0';

  if (!(end = endFindByName(name_buf, unit)))
    return SSH_NETCONFIG_ERROR_NON_EXISTENT;

  *ifnum_ret = (SshUInt32)end;
  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_resolve_ifnum(SshUInt32 ifnum, unsigned char *ifname,
                            size_t ifname_len)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

SshNetconfigError
ssh_netconfig_link_multicast_add_membership(SshUInt32 ifnum,
                                            unsigned char *mcast_addr,
                                            size_t mcast_addr_len)
{
  END_OBJ *end;

  if (!(end = (void *)ifnum))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if (!mcast_addr)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if (end->pFuncTable->mCastAddrAdd(end, mcast_addr) != OK)
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_link_multicast_drop_membership(SshUInt32 ifnum,
                                             unsigned char *mcast_addr,
                                             size_t mcast_addr_len)
{
  END_OBJ *end;

  if (!(end = (void *)ifnum))
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if (!mcast_addr)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  if (end->pFuncTable->mCastAddrDel(end, mcast_addr) != OK)
    return SSH_NETCONFIG_ERROR_UNDEFINED;

  return SSH_NETCONFIG_ERROR_OK;
}

SshNetconfigError
ssh_netconfig_get_addresses(SshUInt32 ifnum, SshUInt32 *num_addresses,
                            SshNetconfigInterfaceAddr addresses)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

SshNetconfigError
ssh_netconfig_add_address(SshUInt32 ifnum,
                          SshNetconfigInterfaceAddr address)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

SshNetconfigError
ssh_netconfig_del_address(SshUInt32 ifnum,
                          SshNetconfigInterfaceAddr address)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
}

#define SSH_VXWORKS_NETCONFIG_MAX_ADDRS 16

SshNetconfigError
ssh_netconfig_flush_addresses(SshUInt32 ifnum)
{
  SshNetconfigError error = SSH_NETCONFIG_ERROR_OK;
  SshNetconfigInterfaceAddrStruct addresses[SSH_VXWORKS_NETCONFIG_MAX_ADDRS];
  SshUInt32 num_addresses = SSH_VXWORKS_NETCONFIG_MAX_ADDRS;
  int i;

  if (ifnum == SSH_INVALID_IFNUM)
    return SSH_NETCONFIG_ERROR_INVALID_ARGUMENT;

  error = ssh_netconfig_get_addresses(ifnum, &num_addresses, addresses);
  if (error != SSH_NETCONFIG_ERROR_OK)
    return error;

  for (i = 0; i < num_addresses; i++)
    {
      error = ssh_netconfig_del_address(ifnum, &addresses[i]);
      if (error != SSH_NETCONFIG_ERROR_OK)
        return error;
    }

  return error;
}

SshNetconfigError
ssh_netconfig_get_route(SshIpAddr prefix,
                        SshUInt32 *num_routes,
                        SshNetconfigRoute routes)
{
  return SSH_NETCONFIG_ERROR_UNDEFINED;
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
   switch (precedence)
    {
    case SSH_ROUTE_PREC_LOWEST:
      if (ipv6)
        return 1044;
      else
        return 255;
      break;
    case SSH_ROUTE_PREC_BELOW_SYSTEM:
      if (ipv6)
        return 1024;
      else
        return 21;
      break;
    case SSH_ROUTE_PREC_SYSTEM:
      if (ipv6)
        return 256;
      else
        return 0;
      break;
    case SSH_ROUTE_PREC_ABOVE_SYSTEM:
      if (ipv6)
        return 20;
      else
        return 0;
      break;
    case SSH_ROUTE_PREC_HIGHEST:
      return 0;
      break;
    }

   return 0xffffffff;
}

#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */
