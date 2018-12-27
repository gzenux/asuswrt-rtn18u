/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Management utils for the IP interface table.
*/

#include "sshincludes.h"
#include "ipsec_params.h"
#include "interceptor.h"
#include "ip_interfaces.h"

#define SSH_DEBUG_MODULE "SshIpInterfaces"

/* Hash table related macros */

#define SSH_INTERFACE_IFNUM_HASH_SIZE 127
#define SSH_INTERFACE_IP_HASH_SIZE 1009

#define SSH_INTERFACE_IP_HASH(ip) \
  ((SSH_IP_HASH((ip))) % SSH_INTERFACE_IP_HASH_SIZE)

#define SSH_INTERFACE_IFNUM_HASH(ifnum) \
  ((ifnum) % SSH_INTERFACE_IFNUM_HASH_SIZE)

/* Forward declarations */

static Boolean
ssh_ip_add_interface_address_internal(SshIpInterfaces interfaces,
                                      SshInterceptorInterface *iface,
                                      const SshInterfaceAddress address);

static SshInterceptorInterface *
ssh_ip_add_interface_internal (SshIpInterfaces interfaces,
                               const SshInterceptorInterface *iface);

#ifndef SSH_IPSEC_SMALL
static void
ssh_ip_rebuild_interface_maps(SshIpInterfaces interfaces);
#endif /* SSH_IPSEC_SMALL */


/* Actual code */

Boolean
ssh_ip_init_interfaces(SshIpInterfaces interfaces)
{
  interfaces->nifs = 0;
  interfaces->ifs_size = 0;
  interfaces->ifs = NULL;

#ifndef SSH_IPSEC_SMALL
  interfaces->map_from_ifnum = ssh_calloc(sizeof(SshInterceptorInterface *),
                                          SSH_INTERFACE_IFNUM_HASH_SIZE);

  interfaces->map_from_ip = ssh_calloc(sizeof(SshInterceptorInterface *),
                                       SSH_INTERFACE_IP_HASH_SIZE);

  interfaces->map_from_broadcast =
    ssh_calloc(sizeof(SshInterceptorInterface *), SSH_INTERFACE_IP_HASH_SIZE);

  if (interfaces->map_from_ifnum == NULL
      || interfaces->map_from_ip == NULL
      || interfaces->map_from_broadcast == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed to allocate interface ifnum/ip maps!"));
      ssh_ip_uninit_interfaces(interfaces);
      return FALSE;
    }
#endif /* SSH_IPSEC_SMALL */

  return TRUE;
}

void
ssh_ip_uninit_interfaces(SshIpInterfaces interfaces)
{
  SshUInt32 idx;

  if (interfaces->ifs != NULL)
    {
      for (idx = 0; idx < interfaces->nifs; idx++)
        {
          ssh_free(interfaces->ifs[idx].addrs);
          interfaces->ifs[idx].addrs = NULL;
        }

      ssh_free(interfaces->ifs);
      interfaces->ifs = NULL;
      interfaces->nifs = 0;
      interfaces->ifs_size = 0;
    }
#ifndef SSH_IPSEC_SMALL
  if (interfaces->map_from_ifnum != NULL)
    {
      ssh_free(interfaces->map_from_ifnum);
      interfaces->map_from_ifnum = NULL;
    }

  if (interfaces->map_from_ip != NULL)
    {
      ssh_free(interfaces->map_from_ip);
      interfaces->map_from_ip = NULL;
    }

  if (interfaces->map_from_broadcast != NULL)
    {
      ssh_free(interfaces->map_from_broadcast);
      interfaces->map_from_broadcast = NULL;
    }

#endif /* SSH_IPSEC_SMALL */
}

Boolean
ssh_ip_init_interfaces_add(SshIpInterfaces interfaces,
                           const SshInterceptorInterface *iface)
{
  if (ssh_ip_add_interface_internal(interfaces, iface) == NULL)
    return FALSE;

  return TRUE;
}

Boolean
ssh_ip_init_interfaces_done(SshIpInterfaces interfaces)
{
#ifndef SSH_IPSEC_SMALL
  ssh_ip_rebuild_interface_maps(interfaces);
#endif /* SSH_IPSEC_SMALL */

  return TRUE;
}

Boolean
ssh_ip_init_interfaces_from_table(SshIpInterfaces interfaces,
                                  SshInterceptorInterface *table,
                                  SshUInt32 nifs)
{
  SshUInt32 idx;

  if (ssh_ip_init_interfaces(interfaces) == FALSE)
    return FALSE;

  for (idx = 0; idx < nifs; idx++)
    {
      if (ssh_ip_add_interface_internal(interfaces, &table[idx]) == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Failed to add interface %d/%d from table!",
                     (int) idx, (int) nifs));
          ssh_ip_uninit_interfaces(interfaces);
          return FALSE;
        }
    }

  if (ssh_ip_init_interfaces_done(interfaces) == FALSE)
    {
      ssh_ip_uninit_interfaces(interfaces);
      return FALSE;
    }

  return TRUE;
}

#ifndef SSH_IPSEC_SMALL
static void
ssh_ip_rebuild_interface_maps(SshIpInterfaces interfaces)
{
  SshInterceptorInterface *ifp;
  SshInterfaceAddress ifaddr;
  SshUInt32 idx1, idx2, hash;

  memset(interfaces->map_from_ifnum, 0,
         sizeof(SshInterceptorInterface *) * SSH_INTERFACE_IFNUM_HASH_SIZE);

  memset(interfaces->map_from_ip, 0,
         sizeof(SshInterfaceAddress) * SSH_INTERFACE_IP_HASH_SIZE);

  memset(interfaces->map_from_broadcast, 0,
         sizeof(SshInterfaceAddress) * SSH_INTERFACE_IP_HASH_SIZE);

  for (idx1 = 0; idx1 < interfaces->nifs; idx1++)
    {
      ifp = &interfaces->ifs[idx1];
      for (idx2 = 0; idx2 < ifp->num_addrs; idx2++)
        {
          ifaddr = &ifp->addrs[idx2];

          ifaddr->next_ip = NULL;
          ifaddr->next_broadcast = NULL;
          ifaddr->ctx_ifnum = (void *)ifp;

          if (ifaddr->protocol == SSH_PROTOCOL_IP4
              || ifaddr->protocol == SSH_PROTOCOL_IP6)
            {
              hash = SSH_INTERFACE_IP_HASH(&ifaddr->addr.ip.ip);
              ifaddr->next_ip = interfaces->map_from_ip[hash];
              interfaces->map_from_ip[hash] = ifaddr;

              hash = SSH_INTERFACE_IP_HASH(&ifaddr->addr.ip.broadcast);
              ifaddr->next_broadcast = interfaces->map_from_broadcast[hash];
              interfaces->map_from_broadcast[hash] = ifaddr;
            }
        }

      hash = SSH_INTERFACE_IFNUM_HASH(ifp->ifnum);
      ifp->ctx_ifnum = (void *) interfaces->map_from_ifnum[hash];
      interfaces->map_from_ifnum[hash] = ifp;
    }
  return;
}
#endif /* SSH_IPSEC_SMALL */

SshInterceptorInterface *
ssh_ip_add_interface(SshIpInterfaces interfaces,
                     const SshInterceptorInterface *iface)
{
  SshInterceptorInterface *ifp;

  ifp = ssh_ip_add_interface_internal(interfaces, iface);

#ifndef SSH_IPSEC_SMALL
  if (ifp != NULL)
    ssh_ip_rebuild_interface_maps(interfaces);
#endif /* SSH_IPSEC_SMALL */

  return ifp;
}

static SshInterceptorInterface *
ssh_ip_add_interface_internal (SshIpInterfaces interfaces,
                               const SshInterceptorInterface *iface)
{
  SshInterceptorInterface *newif, *new_table;
  SshInterfaceAddress addrs;
  SshUInt32 ifs_size;

  /* Check if interface table has space for new entry. */
  new_table = NULL;
  ifs_size = interfaces->ifs_size;
  if ((interfaces->nifs + 1) > interfaces->ifs_size)
    {
      /* Increase table size by 10 entries. */
      ifs_size += 10;
      new_table = ssh_malloc(sizeof(interfaces->ifs[0]) * ifs_size);
      if (new_table == NULL)
        return NULL;

      /* Copy entries from the old table. */
      if (interfaces->ifs)
        memcpy(new_table, interfaces->ifs,
               sizeof(interfaces->ifs[0]) * (interfaces->nifs));

      newif = &new_table[interfaces->nifs];
    }
  else
    {
      newif = &interfaces->ifs[interfaces->nifs];
    }

  /* Fill interface entry. */
  memset(newif, 0, sizeof(*newif));

  newif->to_protocol = iface->to_protocol;
  newif->to_adapter = iface->to_adapter;
  memcpy(newif->name, iface->name, sizeof(newif->name));
  newif->ifnum = iface->ifnum;
  memcpy(newif->media_addr, iface->media_addr, sizeof(newif->media_addr));
  newif->media_addr_len = iface->media_addr_len;
  newif->ctx_user = NULL;
  newif->flags = iface->flags;
  newif->routing_instance_id = iface->routing_instance_id;
  memcpy(newif->routing_instance_name, iface->routing_instance_name,
         sizeof(newif->routing_instance_name));

  addrs = NULL;
  if (iface->num_addrs)
    {
      if ((addrs = ssh_memdup(iface->addrs,
                              sizeof(iface->addrs[0]) * iface->num_addrs))
          == NULL)
        {
          ssh_free(new_table);
          return NULL;
        }
    }

  newif->addrs = addrs;
  newif->num_addrs = iface->num_addrs;
#ifndef SSH_IPSEC_SMALL
  newif->ctx_ifnum = NULL;
#endif /* SSH_IPSEC_SMALL */

  /* Replace interface table. */
  if (new_table != NULL)
    {
      ssh_free(interfaces->ifs);
      interfaces->ifs_size = ifs_size;
      interfaces->ifs = new_table;
    }

  interfaces->nifs++;

  return newif;
}

Boolean
ssh_ip_add_interface_address(SshIpInterfaces interfaces,
                             SshInterceptorInterface *iface,
                             const SshInterfaceAddress address)
{
  Boolean ret;
  ret = ssh_ip_add_interface_address_internal(interfaces, iface, address);

#ifndef SSH_IPSEC_SMALL
  if (ret)
    ssh_ip_rebuild_interface_maps(interfaces);
#endif /* SSH_IPSEC_SMALL */

  return ret;
}

static Boolean
ssh_ip_add_interface_address_internal(SshIpInterfaces interfaces,
                                      SshInterceptorInterface *iface,
                                      const SshInterfaceAddress address)
{
  SshInterfaceAddress table, newaddr;

  table = ssh_realloc(iface->addrs,
                      sizeof(iface->addrs[0])
                      * iface->num_addrs,
                      sizeof(iface->addrs[0])
                      * (iface->num_addrs + 1));

  if (table == NULL)
    return FALSE;

  newaddr = &table[iface->num_addrs];
  *newaddr = *address;
  iface->num_addrs = iface->num_addrs + 1;
  iface->addrs = table;

  return TRUE;
}

SshInterceptorInterface *
ssh_ip_get_interface_by_ifnum(SshIpInterfaces interfaces, SshUInt32 ifnum)
{
#ifdef SSH_IPSEC_SMALL
  SshUInt32 idx;

  for (idx = 0; idx < interfaces->nifs; idx++)
    {
      if (interfaces->ifs[idx].ifnum == ifnum)
        return &interfaces->ifs[idx];
    }
  return NULL;
#else /* SSH_IPSEC_SMALL */
  SshInterceptorInterface *iface;
  SshUInt32 hash;

  hash = SSH_INTERFACE_IFNUM_HASH(ifnum);

  if (interfaces->map_from_ifnum == NULL)
    return NULL;

  for (iface = interfaces->map_from_ifnum[hash];
       iface != NULL && iface->ifnum != ifnum;
       iface = (SshInterceptorInterface *) iface->ctx_ifnum);

  return iface;
#endif /* SSH_IPSEC_SMALL */
}

SshUInt32
ssh_ip_get_interface_flags_by_ifnum(SshIpInterfaces interfaces,
                                    SshUInt32 ifnum)
{
#ifdef SSH_IPSEC_SMALL
  SshUInt32 idx;

  for (idx = 0; idx < interfaces->nifs; idx++)
    {
      if (interfaces->ifs[idx].ifnum == ifnum)
        return interfaces->ifs[idx].flags;
    }
  return 0;
#else /* SSH_IPSEC_SMALL */
  SshInterceptorInterface *iface;
  SshUInt32 hash;

  hash = SSH_INTERFACE_IFNUM_HASH(ifnum);

  if (interfaces->map_from_ifnum == NULL)
    return 0;

  for (iface = interfaces->map_from_ifnum[hash];
       iface != NULL && iface->ifnum != ifnum;
       iface = (SshInterceptorInterface *) iface->ctx_ifnum);

  return iface ? iface->flags : 0;
#endif /* SSH_IPSEC_SMALL */
}

SshInterceptorInterface *
ssh_ip_get_interface_by_ip(SshIpInterfaces interfaces, const SshIpAddr ip,
                           SshVriId routing_instance_id)
{
#ifdef SSH_IPSEC_SMALL
  SshUInt32 idx1, idx2;

  for (idx1 = 0; idx1 < interfaces->nifs; idx1++)
    {
      SshInterceptorInterface *ifp = &interfaces->ifs[idx1];

      for (idx2 = 0; idx2 < ifp->num_addrs; idx2++)
        {
          SshInterceptorProtocol protocol;

          protocol = ifp->addrs[idx2].protocol;
          if (protocol == SSH_PROTOCOL_IP4 || protocol == SSH_PROTOCOL_IP6)
            {
              if (SSH_IP_EQUAL(&ifp->addrs[idx2].addr.ip.ip, ip) &&
                  (ifp->routing_instance_id == routing_instance_id ||
                   routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY))
                {
                  return ifp;
                }
            }
        }
    }
  return NULL;
#else /* SSH_IPSEC_SMALL */
  SshInterfaceAddress addr;

  if (interfaces->map_from_ip == NULL)
    return NULL;

  for (addr = interfaces->map_from_ip[SSH_INTERFACE_IP_HASH(ip)];
       addr != NULL;
       addr = addr->next_ip)
    {
      if (SSH_IP_EQUAL(ip, &addr->addr.ip.ip) &&
         (((SshInterceptorInterface *) addr->ctx_ifnum)->routing_instance_id ==
         routing_instance_id ||
         routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY))
        return (SshInterceptorInterface *) addr->ctx_ifnum;
    }
  return NULL;
#endif /* SSH_IPSEC_SMALL */
}

SshInterceptorInterface *
ssh_ip_get_interface_by_subnet(SshIpInterfaces interfaces, const SshIpAddr ip,
                               SshVriId routing_instance_id)
{
  SshUInt32 idx1, idx2;
  SshInterceptorProtocol protocol;
  SshInterfaceAddress ifaddr;

  for (idx1 = 0; idx1 < interfaces->nifs; idx1++)
    {
      SshInterceptorInterface *ifp = &interfaces->ifs[idx1];

      for (idx2 = 0; idx2 < ifp->num_addrs; idx2++)
        {
          ifaddr = &ifp->addrs[idx2];
          protocol = ifaddr->protocol;

          if (protocol == SSH_PROTOCOL_IP4 || protocol == SSH_PROTOCOL_IP6)
            {
              if (SSH_IP_WITH_MASK_EQUAL(ip,
                                         &ifaddr->addr.ip.ip,
                                         &ifaddr->addr.ip.mask) &&
                  (ifp->routing_instance_id == routing_instance_id ||
                   routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY))
                {
                  return ifp;
                }
            }
        }
    }
  return NULL;
}

SshInterceptorInterface *
ssh_ip_get_interface_by_broadcast(SshIpInterfaces interfaces,
                                  const SshIpAddr ip,
                                  SshVriId routing_instance_id)
{
#ifdef SSH_IPSEC_SMALL
  SshUInt32 idx1, idx2;
  SshInterceptorProtocol protocol;
  SshInterfaceAddress ifaddr;

  for (idx1 = 0; idx1 < interfaces->nifs; idx1++)
    {
      SshInterceptorInterface *ifp = &interfaces->ifs[idx1];

      for (idx2 = 0; idx2 < ifp->num_addrs; idx2++)
        {
          ifaddr = &ifp->addrs[idx2];
          protocol = ifaddr->protocol;

          if (protocol == SSH_PROTOCOL_IP4)
            {
              if (SSH_IP_EQUAL(ip, &ifaddr->addr.ip.broadcast) &&
                  (ifp->routing_instance_id == routing_instance_id ||
                   routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY))
                {
                  return ifp;
                }
            }
        }
    }
  return NULL;
#else /* SSH_IPSEC_SMALL */
  SshInterfaceAddress addr;

  if (interfaces->map_from_broadcast == NULL)
    return NULL;

  for (addr = interfaces->map_from_broadcast[SSH_INTERFACE_IP_HASH(ip)];
       addr != NULL;
       addr = addr->next_broadcast)
    {
      if (SSH_IP_IS4(ip) && SSH_IP_EQUAL(ip, &addr->addr.ip.broadcast) &&
         (((SshInterceptorInterface *) addr->ctx_ifnum)->routing_instance_id ==
         routing_instance_id ||
         routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY))
        return (SshInterceptorInterface *) addr->ctx_ifnum;
    }
  return NULL;
#endif /* SSH_IPSEC_SMALL */
}

SshUInt32
ssh_ip_enumerate_start(SshIpInterfaces interfaces)
{
#ifdef SSH_IPSEC_SMALL
  if (interfaces == NULL || interfaces->nifs == 0)
    return SSH_INVALID_IFNUM;

  return interfaces->ifs[0].ifnum;
#else /* SSH_IPSEC_SMALL */
  SshUInt32 hash;

  if (interfaces == NULL || interfaces->nifs == 0 ||
      interfaces->map_from_ifnum == NULL)
    return SSH_INVALID_IFNUM;

  for (hash = 0;
       hash < SSH_INTERFACE_IFNUM_HASH_SIZE
         && interfaces->map_from_ifnum[hash] == NULL;
       hash++)
    ;

  /* Assert that a slot with entries was found. */
  SSH_ASSERT(hash < SSH_INTERFACE_IFNUM_HASH_SIZE);

  /* Return the first entry of the slot. */
  return interfaces->map_from_ifnum[hash]->ifnum;
#endif /* SSH_IPSEC_SMALL */
}

SshUInt32
ssh_ip_enumerate_next(SshIpInterfaces interfaces, SshUInt32 ifnum)
{
#ifdef SSH_IPSEC_SMALL
  SshUInt32 i;

  if (interfaces == NULL || ifnum == SSH_INVALID_IFNUM)
    return SSH_INVALID_IFNUM;

  for (i = 0;
       i < interfaces->nifs && interfaces->ifs[i].ifnum <= ifnum;
       i++)
    ;

  if (i == interfaces->nifs)
    return SSH_INVALID_IFNUM;

  return interfaces->ifs[i].ifnum;
#else /* SSH_IPSEC_SMALL */
  SshInterceptorInterface *iface;
  SshUInt32 hash;

  if (interfaces == NULL || ifnum == SSH_INVALID_IFNUM ||
      interfaces->map_from_ifnum == NULL)
    return SSH_INVALID_IFNUM;

  /* Lookup 'ifnum' from hashtable. */
  hash = SSH_INTERFACE_IFNUM_HASH(ifnum);
  for (iface = interfaces->map_from_ifnum[hash];
       iface != NULL && iface->ifnum != ifnum;
       iface = (SshInterceptorInterface *) iface->ctx_ifnum)
    ;

  /* Return the following entry in the chain. */
  if (iface && iface->ctx_ifnum)
    return ((SshInterceptorInterface *) iface->ctx_ifnum)->ifnum;

  /* No more entries in the chain, go to next slot that has entries. */
  for (hash++;
       hash < SSH_INTERFACE_IFNUM_HASH_SIZE
         && interfaces->map_from_ifnum[hash] == NULL;
       hash++)
    ;

  /* Return the first entry of the slot. */
  if (hash < SSH_INTERFACE_IFNUM_HASH_SIZE)
    return interfaces->map_from_ifnum[hash]->ifnum;

  /* No more entries in the hashtable. */
  return SSH_INVALID_IFNUM;
#endif /* SSH_IPSEC_SMALL */
}



static Boolean ip_interface_address_compare(SshInterfaceAddress addr1,
                                            SshInterfaceAddress addr2)

{
  if (addr1->protocol != addr2->protocol)
    return FALSE;

  if ((addr1->protocol == SSH_PROTOCOL_IP4) ||
      (addr1->protocol == SSH_PROTOCOL_IP6))
    {
      if (SSH_IP_CMP(&addr1->addr.ip.ip, &addr2->addr.ip.ip))
          return FALSE;

      if (SSH_IP_CMP(&addr1->addr.ip.mask, &addr2->addr.ip.mask))
          return FALSE;

      if (SSH_IP_CMP(&addr1->addr.ip.broadcast, &addr2->addr.ip.broadcast))
          return FALSE;

    }
  else if (addr1->protocol == SSH_PROTOCOL_IPX)
    {
      if (addr1->addr.ns.net != addr2->addr.ns.net)
        return FALSE;

      if (memcmp(addr1->addr.ns.host, addr2->addr.ns.host,
                 sizeof(addr1->addr.ns.host)))
        return FALSE;

    }
  else
    return FALSE;

  return TRUE;
}


Boolean ssh_ip_interface_compare(SshInterceptorInterface *ifp1,
                                 SshInterceptorInterface *ifp2)
{
  int i;

  if (ifp1->to_protocol.media != ifp2->to_protocol.media)
    return FALSE;
  if (ifp1->to_protocol.flags != ifp2->to_protocol.flags)
    return FALSE;
  if (ifp1->to_protocol.mtu_ipv4 != ifp2->to_protocol.mtu_ipv4)
    return FALSE;
#ifdef WITH_IPV6
  if (ifp1->to_protocol.mtu_ipv6 != ifp2->to_protocol.mtu_ipv6)
    return FALSE;
#endif /* WITH_IPV6 */

  if (ifp1->to_adapter.media != ifp2->to_adapter.media)
    return FALSE;
  if (ifp1->to_adapter.flags != ifp2->to_adapter.flags)
    return FALSE;
  if (ifp1->to_adapter.mtu_ipv4 != ifp2->to_adapter.mtu_ipv4)
    return FALSE;
#ifdef WITH_IPV6
  if (ifp1->to_adapter.mtu_ipv6 != ifp2->to_adapter.mtu_ipv6)
    return FALSE;
#endif /* WITH_IPV6 */


  if (strcmp(ifp1->name, ifp2->name))
    return FALSE;

  if (ifp1->ifnum != ifp2->ifnum)
    return FALSE;

  if (ifp1->routing_instance_id != ifp2->routing_instance_id)
    return FALSE;

  if (ifp1->num_addrs != ifp2->num_addrs)
    return FALSE;

  for (i = 0; i < ifp1->num_addrs; i++)
    {
      if (!ip_interface_address_compare(&ifp1->addrs[i], &ifp2->addrs[i]))
        return FALSE;
    }

  if (ifp1->media_addr_len != ifp2->media_addr_len)
    return FALSE;

  if (memcmp(ifp1->media_addr, ifp2->media_addr, ifp1->media_addr_len))
    return FALSE;

  if (ifp1->flags != ifp2->flags)
    return FALSE;

  return TRUE;
}

const char *
ssh_ip_get_interface_vri_name(SshIpInterfaces interfaces,
                              int routing_instance_id)
{
  SshUInt32 idx;

  if (routing_instance_id == SSH_INTERCEPTOR_VRI_ID_GLOBAL)
    return SSH_INTERCEPTOR_VRI_NAME_GLOBAL;

  for (idx = 0; idx < interfaces->nifs; idx++)
    {
      if (interfaces->ifs[idx].routing_instance_id == routing_instance_id)
        return (const char *)&interfaces->ifs[idx].routing_instance_name;
    }
  return NULL;
}

int
ssh_ip_get_interface_vri_id(SshIpInterfaces interfaces,
                            const char *routing_instance_name)
{
  SshUInt32 idx;

  if (strcmp(routing_instance_name,
             SSH_INTERCEPTOR_VRI_NAME_GLOBAL) == 0)
    return SSH_INTERCEPTOR_VRI_ID_GLOBAL;

  for (idx = 0; idx < interfaces->nifs; idx++)
    {
      if (strcmp(interfaces->ifs[idx].routing_instance_name,
                 routing_instance_name) == 0)
        return interfaces->ifs[idx].routing_instance_id;
      }
  return SSH_INTERCEPTOR_VRI_ID_ANY;
}

