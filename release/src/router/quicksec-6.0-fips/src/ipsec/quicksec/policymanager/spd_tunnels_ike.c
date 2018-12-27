/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Tunnel object handling utilities that are  needed only if IKE is used.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"
#include "util_dnsresolver.h"

#define SSH_DEBUG_MODULE "SshPmTunnelsIke"

/************************** Types and definitions ***************************/

/* A shortcut to report an error if a manually keyed tunnel is
   configured for IKE parameters. */
#define SSH_PM_TUNNEL_LOG_NEED_IKE()                    \
ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,      \
              "Tunnel is already specified to be manually keyed");

/****************************************************************************/

/* Clears automatically added peers from the tunnel, leaves the
   default endpoint */
static Boolean
pm_tunnel_clear_peers(SshPmTunnel tunnel, SshUInt32 start_index,
                      SshUInt32 count)
{
  SshUInt32 i, end_index, num_peers;
  SshIpAddr peers = NULL;

  SSH_DEBUG(SSH_D_LOWOK, ("Clearing tunnel peers"));

  end_index = start_index + count;
  if (end_index > tunnel->num_peers)
    end_index = tunnel->num_peers;

  num_peers = 0;
  if (start_index > 0 || end_index < tunnel->num_peers)
    {
      /* Allocate memory for surviving peer IP addresses. */
      peers = ssh_calloc(start_index + (tunnel->num_peers - end_index),
                         sizeof(SshIpAddrStruct));
      if (peers == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not allocate memory for IKE peers."));
          return FALSE;
        }

      /* Copy surviving peer IP addresses. */
      for (i = 0; i < start_index; i++)
        peers[num_peers++] = tunnel->peers[i];
      for (i = end_index; i < tunnel->num_peers; i++)
        peers[num_peers++] = tunnel->peers[i];
    }

  ssh_free(tunnel->peers);
  tunnel->peers = peers;
  tunnel->num_peers = num_peers;

  return TRUE;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
Boolean
ssh_pm_tunnel_clear_dns_peers(SshPmTunnel tunnel, SshPmDnsReference ref)
{
  SshUInt32 i;
  SshPmDnsPeer dns_peer = NULL;

  /* Lookup DNS peer reference. */
  for (i = 0; i < tunnel->num_dns_peers; i++)
    {
      if (ref == tunnel->dns_peer_ip_ref_array[i].ref)
        {
          dns_peer = &tunnel->dns_peer_ip_ref_array[i];
          break;
        }
    }

  if (dns_peer == NULL)
    return FALSE;

  /* No peer IP addresses to delete. All done. */
  if (dns_peer->num_peers == 0)
    return TRUE;

  /* Delete peer IP addresses. */
  if (!pm_tunnel_clear_peers(tunnel, dns_peer->peer_index,
                             dns_peer->num_peers))
    return FALSE;

  /* Fix peer indexes for other DNS peer references. */
  for (i++; i < tunnel->num_dns_peers; i++)
    {
      SSH_ASSERT(tunnel->dns_peer_ip_ref_array[i].peer_index
                 > dns_peer->num_peers);
      tunnel->dns_peer_ip_ref_array[i].peer_index -= dns_peer->num_peers;
    }

  dns_peer->num_peers = 0;

  return TRUE;
}

SshUInt32
ssh_pm_tunnel_num_dns_peer_ips(SshPmTunnel tunnel, SshPmDnsReference ref)
{
  SshUInt32 i;

  for (i = 0; i < tunnel->num_dns_peers; i++)
    {
      if (ref == tunnel->dns_peer_ip_ref_array[i].ref)
        return tunnel->dns_peer_ip_ref_array[i].num_peers;
    }

  return 0;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

Boolean
ssh_pm_tunnel_clear_peers(SshPmTunnel tunnel)
{
  return pm_tunnel_clear_peers(tunnel, 0, tunnel->num_peers);
}

Boolean
ssh_pm_tunnel_set_local_port(SshPmTunnel tunnel,
                             SshUInt16 port)
{
  SshUInt32 i;

  if (port != 0)
    {
      for (i = 0; i < tunnel->pm->params.num_ike_ports; i++)
        if (tunnel->pm->params.local_ike_ports[i] == port)
          break;
      if (i == tunnel->pm->params.num_ike_ports)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Local Port %d is not a valid local IKE port", port));
          return FALSE;
        }
    }

  tunnel->local_port = port;

  return TRUE;
}

#ifdef SSHDIST_IPSEC_DNSPOLICY
SshUInt32
ssh_pm_tunnel_num_local_dns_addresses(SshPmTunnel tunnel,
                                      SshPmDnsReference ref)
{
  SshPmTunnelLocalDnsAddress local_dns = NULL;

  /* Lookup local DNS address entry from tunnel. */
  for (local_dns = tunnel->local_dns_address;
       local_dns != NULL;
       local_dns = local_dns->next)
    {
      if (local_dns->ref == ref)
        break;
    }
  if (local_dns == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not find local DNS address entry"));
      return 0;
    }

  return local_dns->num_ips;
}

Boolean
ssh_pm_tunnel_update_local_dns_address(SshPmTunnel tunnel,
                                       SshIpAddr ip,
                                       SshPmDnsReference ref)
{
  SshPmTunnelLocalDnsAddress local_dns = NULL;
  SshPmTunnelLocalIp local_ip, prev_ip, tmp_ip;

  /* Lookup local DNS address entry from tunnel. */
  for (local_dns = tunnel->local_dns_address;
       local_dns != NULL;
       local_dns = local_dns->next)
    {
      if (local_dns->ref == ref)
        break;
    }
  if (local_dns == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not find local DNS address entry"));
      return FALSE;
    }

  if (local_dns->ip != NULL)
    {
      /* Check if IP address is already up to date. */
      if (SSH_IP_EQUAL(ip, &local_dns->ip->ip))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("DNS mapping is up to date"));
          return TRUE;
        }

      /* Update old local IP object. */
      if (SSH_IP_DEFINED(ip))
        {
          local_dns->ip->ip = *ip;
          SSH_ASSERT(local_dns->ip->precedence == local_dns->precedence);
          goto out;
        }

      /* Remove old local IP object from tunnel. */
      for (prev_ip = NULL, local_ip = tunnel->local_ip;
           local_ip != NULL;
           prev_ip = local_ip, local_ip = local_ip->next)
        {
          if (local_ip == local_dns->ip)
            {
              if (prev_ip != NULL)
                prev_ip->next = local_ip->next;
              else
                tunnel->local_ip = local_ip->next;
              ssh_free(local_ip);
              local_dns->ip = NULL;
              goto out;
            }
        }
      /* Assert that the local IP was in the list. */
      SSH_NOTREACHED;
    }

  /* Allocate new local IP object. */
  local_ip = ssh_calloc(1, sizeof(*local_ip));
  if (local_ip == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate local IP address object"));
      return FALSE;
    }
  local_ip->ip = *ip;
  local_ip->precedence = local_dns->precedence;
  local_dns->ip = local_ip;
  local_dns->num_ips = 1;

  /* Add IP to tunnel local IP address list so that addresses are in
     order of precedence. */
  for (prev_ip = NULL, tmp_ip = tunnel->local_ip;
       tmp_ip != NULL;
       prev_ip = tmp_ip, tmp_ip = tmp_ip->next)
    {
      if (tmp_ip->precedence <= local_ip->precedence)
        {
          if (prev_ip != NULL)
            prev_ip->next = local_ip;
          else
            tunnel->local_ip = local_ip;
          local_ip->next = tmp_ip;
          break;
        }
    }
  if (tmp_ip == NULL)
    {
      /* There were no local IPs with lower precedence,
         add local IP to end of list. */
      if (prev_ip != NULL)
        prev_ip->next = local_ip;
      else
        tunnel->local_ip = local_ip;
      local_ip->next = NULL;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Added local IP for DNS address '%s'", local_dns->name));
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("  IP: %@", ssh_ipaddr_render, &local_ip->ip));

 out:
#ifdef SSHDIST_IPSEC_MOBIKE
  /* Mark that tunnel local IPs have changed. */
  tunnel->local_ip_changed = TRUE;
#endif /* SSHDIST_IPSEC_MOBIKE */
  return TRUE;
}

static Boolean
pm_tunnel_add_local_dns_address(SshPmTunnel tunnel,
                                const unsigned char *address,
                                SshUInt32 precedence)
{
  SshPmTunnelLocalDnsAddress local_dns;
  SshPmTunnelLocalIp local_ip, prev_ip, tmp_ip;

  for (local_dns = tunnel->local_dns_address;
       local_dns != NULL;
       local_dns = local_dns->next)
    {
      if (strcasecmp(address, local_dns->name) == 0)
        break;
    }

  /* DNS address not found, add new entry to local DNS address list. */
  if (local_dns == NULL)
    {
      if (SSH_PM_TUNNEL_NUM_LOCAL_ADDRS(tunnel)
          >= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES + 1)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Maximum number of local IP addresses reached"));
          return FALSE;
        }

      local_dns = ssh_calloc(1, sizeof(*local_dns));
      if (local_dns == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not allocate local DNS address object"));
          return FALSE;
        }

      if ((local_dns->ref =
           ssh_pm_dns_cache_insert(tunnel->pm->dnscache, address,
                                   SSH_PM_DNS_OC_T_LOCAL, tunnel)) == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Malformed local DNS address `%s'",
                                  address));
          ssh_free(local_dns);
          return FALSE;
        }

      local_dns->name = ssh_strdup(address);
      if (local_dns->name == NULL)
        {
          ssh_free(local_dns);
          return FALSE;
        }

      local_dns->next = tunnel->local_dns_address;
      tunnel->local_dns_address = local_dns;
      tunnel->num_local_dns_addresses++;
    }

  /* DNS address was found, but precedence has changed and the DNS
     address has already been resolved. */
  else if (precedence != local_dns->precedence
           && local_dns->ip != NULL)
    {
      /* Remove resolved IP address from list. */
      for (prev_ip = NULL, local_ip = tunnel->local_ip;
           local_ip != NULL;
           prev_ip = local_ip, local_ip = local_ip->next)
        {
          if (local_ip == local_dns->ip)
            {
              if (prev_ip != NULL)
                prev_ip->next = local_ip->next;
              else
                tunnel->local_ip = local_ip->next;
              break;
            }
        }
      /* Not found */
      if (local_ip == NULL)
          return FALSE;

      /* Update precedence. */
      local_dns->precedence = precedence;
      local_ip->precedence = precedence;

      /* Add address back to local IP address list so that addresses are
         in the order of precedence. */
      for (prev_ip = NULL, tmp_ip = tunnel->local_ip;
           tmp_ip != NULL;
           prev_ip = tmp_ip, tmp_ip = tmp_ip->next)
        {
          if (tmp_ip->precedence <= local_ip->precedence)
            {
              if (prev_ip != NULL)
                {
                  prev_ip->next = local_ip;
                  local_ip->next = tmp_ip;
                }
              else
                {
                  tunnel->local_ip = local_ip;
                  local_ip->next = tmp_ip;
                }
              break;
            }
        }
      if (tmp_ip == NULL)
        {
          /* There were no local IPs with lower precedence,
             add local IP to end of list. */
          if (prev_ip != NULL)
            prev_ip->next = local_ip;
          else
            tunnel->local_ip = local_ip;
          local_ip->next = NULL;
        }
    }

  return TRUE;
}

/* This function will check whether the local_ip and peer
   fields get resolved if given as DNS. If all local_ip fields
   and atleast one peer field is resolved then this will return
   SSH_PM_DNS_STATUS_OK, otherwise SSH_PM_DNS_STATUS_ERROR/STALE */
SshPmDnsStatus
ssh_pm_tunnel_get_dns_status(SshPm pm, SshPmTunnel tunnel)
{
  SshPmDnsStatus dnsstat, peer_dnsstat, status;
  SshUInt16 i;
  SshPmTunnelLocalDnsAddress local_dns;

  dnsstat = SSH_PM_DNS_STATUS_OK;

  /* Require the local DNS names to be valid. */
  for (local_dns = tunnel->local_dns_address;
       local_dns != NULL;
       local_dns = local_dns->next)
    {
      status = ssh_pm_dns_cache_status(local_dns->ref);
      if (status == SSH_PM_DNS_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("local-ip dns name resolved into %@",
                                  ssh_ipaddr_render, &local_dns->ip->ip));
        }
      if (status != SSH_PM_DNS_STATUS_ERROR
          && !SSH_IP_DEFINED(&local_dns->ip->ip))
        status = SSH_PM_DNS_STATUS_ERROR;
      dnsstat |= status;
    }

  /* Require atleast one tunnel peer DNS name to be valid */
  peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
  for (i = 0; i < tunnel->num_dns_peers; i++)
    {
      status = ssh_pm_dns_cache_status(tunnel->dns_peer_ip_ref_array[i].ref);
      if (status == SSH_PM_DNS_STATUS_OK)
        {
          SSH_DEBUG(SSH_D_MIDOK, ("peer dns name resolved into %@",
                                  ssh_ipaddr_render, &tunnel->peers[i]));
        }
      if (peer_dnsstat > status)
        peer_dnsstat = status;
    }
  if (i != 0)
    {
      for (i = 0; i < tunnel->num_peers; i++)
        if (SSH_IP_DEFINED(&tunnel->peers[i]))
          break;
      if (i == tunnel->num_peers)
        peer_dnsstat = SSH_PM_DNS_STATUS_ERROR;
      dnsstat |= peer_dnsstat;
    }

  if (dnsstat & SSH_PM_DNS_STATUS_ERROR)
    return SSH_PM_DNS_STATUS_ERROR;
  else if (dnsstat & SSH_PM_DNS_STATUS_STALE)
    return SSH_PM_DNS_STATUS_STALE;
  return dnsstat;
}
#endif /* SSHDIST_IPSEC_DNSPOLICY */

Boolean
ssh_pm_tunnel_add_local_ip(SshPmTunnel tunnel,
                           const unsigned char *address,
                           SshUInt32 precedence)
{
  SshIpAddrStruct ip;
  SshPmTunnelLocalIp local_ip, prev_ip, tmp_ip;
  Boolean unavailable = FALSE;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adding tunnel local IP '%s' precedence %lu",
             address, (unsigned long) precedence));

  if (!ssh_ipaddr_parse(&ip, address))
    {
#ifdef SSHDIST_IPSEC_DNSPOLICY
      return(pm_tunnel_add_local_dns_address(tunnel, address, precedence));
#else /* SSHDIST_IPSEC_DNSPOLICY */
      SSH_DEBUG(SSH_D_FAIL, ("Malformed local address '%s'", address));
      return FALSE;
#endif /* SSHDIST_IPSEC_DNSPOLICY */
    }

  /*  Make sure local-ip is not Multicast. */
  if (SSH_IP_IS_MULTICAST(&ip))
    {
      SSH_DEBUG(SSH_D_FAIL,("Local-ip cannot be Multicast"));
      return FALSE;
    }

#if defined (WITH_IPV6)
#ifdef SSHDIST_IPSEC_MOBIKE
  if ((tunnel->flags & SSH_PM_T_MOBIKE) && !ssh_pm_mobike_valid_address(&ip))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("%@ ip cannot be used with MobIKE enabled tunnel",
                 ssh_ipaddr_render, &ip));
      return FALSE;
    }
#endif /* SSHDIST_IPSEC_MOBIKE */

#else /* WITH_IPV6 */
  /* Check that no IPv6 addresses were specified. */
  if (SSH_IP_IS6(&ip))
    {
      SSH_DEBUG(SSH_D_ERROR, ("IPv6 support not compiled in"));
      return FALSE;
    }
#endif /* WITH_IPV6 */

  /* Check if the address exists. */
  if (ssh_pm_find_interface_by_address(tunnel->pm, &ip,
                                       tunnel->routing_instance_id, NULL) ==
                                       NULL)
    unavailable = TRUE;

  /* Lookup address from tunnel local ip addresses. */
  for (prev_ip = NULL, local_ip = tunnel->local_ip;
       local_ip != NULL;
       prev_ip = local_ip, local_ip = local_ip->next)
    {
      if (local_ip->static_ip && SSH_IP_EQUAL(&ip, &local_ip->ip))
        {
          /* Set availability. */
          local_ip->unavailable = (unavailable ? 1 : 0);

          /* Address was found and precedence has not changed, all done. */
          if (local_ip->precedence == precedence)
            return TRUE;

          /* Precedence has changed, remove address from list. */
          if (prev_ip != NULL)
            prev_ip->next = local_ip->next;
          else
            tunnel->local_ip = local_ip->next;
          break;
        }
    }

  /* Address not found, add new address. */
  if (local_ip == NULL)
    {
      if (SSH_PM_TUNNEL_NUM_LOCAL_ADDRS(tunnel)
          >= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES + 1)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Maximum number of local IP addresses reached"));
          return FALSE;
        }

      local_ip = ssh_calloc(1, sizeof(*local_ip));
      if (local_ip == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not allocate local IP object"));
          return FALSE;
        }
      local_ip->ip = ip;
      local_ip->static_ip = 1;

      tunnel->num_local_ips++;
      SSH_DEBUG(SSH_D_LOWOK, ("Tunnel %p has %d local ips",
                              tunnel, tunnel->num_local_ips));

    }

#ifdef SSHDIST_IPSEC_MOBIKE
  /* Mark tunnel local IPs changed. */
  tunnel->local_ip_changed = TRUE;
#endif /* SSHDIST_IPSEC_MOBIKE */

  /* Set address precedence. */
  local_ip->precedence = precedence;

  /* Set availability. */
  local_ip->unavailable = (unavailable ? 1 : 0);

  /* Add local address to local ip address list so that the addresses are
     in order of precedence. */
  for (prev_ip = NULL, tmp_ip = tunnel->local_ip;
       tmp_ip != NULL;
       prev_ip = tmp_ip, tmp_ip = tmp_ip->next)
    {
      if (tmp_ip->precedence <= local_ip->precedence)
        {
          if (prev_ip != NULL)
            {
              prev_ip->next = local_ip;
              local_ip->next = tmp_ip;
            }
          else
            {
              tunnel->local_ip = local_ip;
              local_ip->next = tmp_ip;
            }
          local_ip = NULL;
          break;
        }
    }
  if (local_ip != NULL)
    {
      /* There were no local IPs with lower precedence,
         add local IP to end of list. */
      if (prev_ip != NULL)
        prev_ip->next = local_ip;
      else
        tunnel->local_ip = local_ip;
      local_ip->next = NULL;
    }

  return TRUE;
}

Boolean
ssh_pm_tunnel_update_local_interface_addresses(SshPmTunnel tunnel)
{
  SshPmTunnelLocalInterface local_iface = NULL;
  SshPmTunnelLocalIp local_ip, prev_ip, last_ip, old_ip, tmp_ip;
  SshInterceptorInterface *iface;
  SshUInt32 i, num_old_ips;

  /* Lookup local interface entry from tunnel. */
  for (local_iface = tunnel->local_interface;
       local_iface != NULL;
       local_iface = local_iface->next)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Updating addresses from interface '%s'",
                                   local_iface->name));

      /* Remove old interface addresses. */
      old_ip = NULL;
      num_old_ips = 0;
      if (local_iface->num_ips > 0)
        {
          /* Find the start of this interface's address chain. All addresses
             belonging to one interface are in the list in one continous
             chain. */
          SSH_ASSERT(local_iface->ip != NULL);
          for (prev_ip = NULL, local_ip = tunnel->local_ip;
               local_ip != NULL;
               prev_ip = local_ip, local_ip = local_ip->next)
            {
              if (local_ip == local_iface->ip)
                {
                  /* Remove this interface's address chain. */
                  last_ip = NULL;
                  for (i = 0; i < local_iface->num_ips; i++)
                    {
                      last_ip = local_ip;
                      local_ip = local_ip->next;
                    }
                  SSH_ASSERT(last_ip != NULL);

                  /* Now: prev_ip points to the element preceding the first
                     element of the address chain. local_ip points to the
                     element following the last element of the address chain.
                     local_iface->ip points to first element and last_ip points
                     to the last element of the address chain. */

                  /* Remove address chain. */
                  last_ip->next = NULL;

                  if (prev_ip != NULL)
                    prev_ip->next = local_ip;
                  else
                    tunnel->local_ip = local_ip;
                  break;
                }
            }

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Removed %d addresses from interface %s",
                     (int) local_iface->num_ips, local_iface->name));

          /* Store old address chain for comparing it to new address chain. */
          old_ip = local_iface->ip;
          num_old_ips = local_iface->num_ips;

          local_iface->num_ips = 0;
          local_iface->ip = NULL;
        }

      /* Lookup interface. */
      iface = ssh_pm_find_interface(tunnel->pm, local_iface->name, NULL);

      /* If the routing instance of the interface is incorrect, ignore it.
         We do not enforce the interface to be in correct routing instance
         at configuration time... */
      if (iface != NULL &&
          iface->routing_instance_id != tunnel->routing_instance_id)
        iface = NULL;

      /* Add new interface addresses. */
      if (iface != NULL)
        {
          last_ip = NULL;
          for (i = 0; i < iface->num_addrs; i++)
            {
              SshInterfaceAddress addr = &iface->addrs[i];

              /* Sanity check interface addresses. */
              if (addr->protocol != SSH_PROTOCOL_IP4
#if defined (WITH_IPV6)
                  && addr->protocol != SSH_PROTOCOL_IP6
#endif /* (WITH_IPV6) */
                  )
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Skipping interface address; protocol %d",
                             addr->protocol));
                  continue;
                }
              if (SSH_IP_IS_NULLADDR(&addr->addr.ip.ip)
                  || SSH_IP_IS_BROADCAST(&addr->addr.ip.ip)
                  || SSH_IP_IS_MULTICAST(&addr->addr.ip.ip)
#ifdef SSHDIST_IPSEC_MOBIKE
#ifdef WITH_IPV6
                  || ((tunnel->flags & SSH_PM_T_MOBIKE) &&
                      !ssh_pm_mobike_valid_address(&addr->addr.ip.ip))
#endif /* WITH_IPV6 */
#endif /* SSHDIST_IPSEC_MOBIKE */
                  )
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Skipping interface address %@",
                             ssh_ipaddr_render, &addr->addr.ip.ip));
                  continue;
                }

              /* Add address to interface's address chain. */
              local_ip = ssh_calloc(1, sizeof(*local_ip));
              if (local_ip == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL,
                            ("Could not allocate local IP address object"));



                  return FALSE;
                }

              local_ip->ip = addr->addr.ip.ip;
              local_ip->precedence = local_iface->precedence;

              /* Remember the last element in the interface's address chain. */
              if (local_iface->ip == NULL)
                last_ip = local_ip;

              local_ip->next = local_iface->ip;
              local_iface->ip = local_ip;
              local_iface->num_ips++;

#ifdef SSHDIST_IPSEC_MOBIKE
              /* Check if new address was in the old address chain,
                 and mark tunnel changed if needed. */
              if (!tunnel->local_ip_changed)
                {
                  for (tmp_ip = old_ip;
                       tmp_ip != NULL;
                       tmp_ip = tmp_ip->next)
                    {
                      if (SSH_IP_EQUAL(&tmp_ip->ip, &local_iface->ip->ip))
                        break;
                    }

                  /* New address was not in old addresses,
                     mark tunnel local IPs changed. */
                  if (tmp_ip == NULL)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Marking tunnel local IPs changed, new IP"));
                      tunnel->local_ip_changed = TRUE;
                    }
                }
#endif /* SSHDIST_IPSEC_MOBIKE */
            }

          /* Add interface address chain to tunnel local IP address list
             so that addresses are in order of precedence. */
          if (local_iface->ip != NULL)
            {
              SSH_ASSERT(last_ip != NULL);
              /* Find point in the address list where to insert the chain. */
              for (prev_ip = NULL, tmp_ip = tunnel->local_ip;
                   tmp_ip != NULL;
                   prev_ip = tmp_ip, tmp_ip = tmp_ip->next)
                {
                  /* Found an entry with lower precedence,
                     insert address chain here. */
                  if (tmp_ip->precedence <= local_iface->precedence)
                    {
                      if (prev_ip != NULL)
                        prev_ip->next = local_iface->ip;
                      else
                        tunnel->local_ip = local_iface->ip;
                      last_ip->next = tmp_ip;
                      break;
                    }
                }
              if (tmp_ip == NULL)
                {
                  /* There were no local IPs with lower precedence,
                     add address chain to end of list. */
                  if (prev_ip != NULL)
                    prev_ip->next = local_iface->ip;
                  else
                    tunnel->local_ip = local_iface->ip;
                  last_ip->next = NULL;
                }
            }

#ifdef DEBUG_LIGHT
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Added %d addresses from interface %s",
                     (int) local_iface->num_ips, iface->name));
          tmp_ip = local_iface->ip;
          for (i = 0; i < local_iface->num_ips; i++)
            {
              SSH_ASSERT(tmp_ip != NULL);
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("  IP: %@ prec %d",
                         ssh_ipaddr_render, &tmp_ip->ip, tmp_ip->precedence));
              tmp_ip = tmp_ip->next;
            }
#endif /* DEBUG_LIGHT */
        }

#ifdef SSHDIST_IPSEC_MOBIKE
      /* Check if there were more old addresses than new addresses
         and mark tunnel local IPs changed if needed. */
      if (tunnel->local_ip_changed == FALSE
          && local_iface->num_ips != num_old_ips)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Marking tunnel local IPs changed, disappeared IP"));
          tunnel->local_ip_changed = TRUE;
        }
#endif /* SSHDIST_IPSEC_MOBIKE */

      /* Free old IPs. */
      while (old_ip != NULL)
        {
          tmp_ip = old_ip;
          old_ip = old_ip->next;
          ssh_free(tmp_ip);
        }
    }

  /* Check availability of statically configured local IPs. */
  for (local_ip = tunnel->local_ip;
       local_ip != NULL;
       local_ip = local_ip->next)
    {
      if (local_ip->static_ip)
        {
          if (ssh_pm_find_interface_by_address(tunnel->pm,
                                               &local_ip->ip,
                                               tunnel->routing_instance_id,
                                               NULL))
            {
#ifdef SSHDIST_IPSEC_MOBIKE
              if (local_ip->unavailable)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Marking tunnel local IPs changed, "
                             "reappeared static IP"));
                  tunnel->local_ip_changed = TRUE;
                }
#endif /* SSHDIST_IPSEC_MOBIKE */
              local_ip->unavailable = 0;
            }
          else
            {
#ifdef SSHDIST_IPSEC_MOBIKE
              if (!local_ip->unavailable)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Marking tunnel local IPs changed, "
                             "disappeared static IP"));
                  tunnel->local_ip_changed = TRUE;
                }
#endif /* SSHDIST_IPSEC_MOBIKE */
              local_ip->unavailable = 1;
            }
        }
    }

  return TRUE;
}

Boolean
ssh_pm_tunnel_add_local_interface(SshPmTunnel tunnel,
                                  const unsigned char *name,
                                  SshUInt32 precedence)
{
  SshPmTunnelLocalInterface local_iface = NULL;
  SshPmTunnelLocalIp local_ip, prev_ip, last_ip;
  SshUInt32 i;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Adding tunnel local interface '%s' precedence %lu",
             name, (unsigned long) precedence));

  /* Lookup local interface. */
  for (local_iface = tunnel->local_interface;
       local_iface != NULL;
       local_iface = local_iface->next)
    {
      if (strcasecmp(name, local_iface->name) == 0)
        break;
    }

  /* No local interface found, add new. */
  if (local_iface == NULL)
    {
      if (SSH_PM_TUNNEL_NUM_LOCAL_ADDRS(tunnel)
          >= SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES + 1)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Maximum number of local IP addresses reached"));
          return FALSE;
        }

      local_iface = ssh_calloc(1, sizeof(*local_iface));
      if (local_iface == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not allocate local interface object"));
          return FALSE;
        }

      local_iface->precedence = precedence;
      local_iface->name = ssh_strdup(name);
      if (local_iface->name == NULL)
        {
          ssh_free(local_iface);
          return FALSE;
        }

      local_iface->next = tunnel->local_interface;
      tunnel->local_interface = local_iface;
      tunnel->num_local_interfaces++;
    }

  /* Interface was found, but precedence has changed and the interface
     addresses have already been added to the local IP address list. */
  else if (precedence != local_iface->precedence
           && local_iface->num_ips > 0)
    {
      /* Remove the interfaces addresses. All addresses belonging to
         one interface are in the list adjacent to each other. */
      SSH_ASSERT(local_iface->ip != NULL);
      last_ip = NULL;
      for (prev_ip = NULL, local_ip = tunnel->local_ip;
           local_ip != NULL;
           prev_ip = local_ip, local_ip = local_ip->next)
        {
          /* Start of interfaces addresses found. */
          if (local_ip == local_iface->ip)
            {
              /* Go to end of interfaces addresses. */
              for (i = 0; i < local_iface->num_ips; i++)
                {
                  /* Update address precedence. */
                  local_ip->precedence = precedence;
                  last_ip = local_ip;
                  local_ip = local_ip->next;
                }
              /* Remove address chain from local IP address list. */
              if (prev_ip != NULL)
                prev_ip->next = local_ip;
              else
                tunnel->local_ip = local_ip;
              break;
            }
        }
      /* Now local_iface->ip points to start of address chain, and
         last_ip points to last address element. The precedence of
         of all local IPs in the chain have been updated. */
      SSH_ASSERT(last_ip != NULL);

      /* Update interface precedence. */
      local_iface->precedence = precedence;

      /* Add interface address chain back to local IP address list
         so that addresses are in the order of precedence. */
      for (prev_ip = NULL, local_ip = tunnel->local_ip;
           local_ip != NULL;
           prev_ip = local_ip, local_ip = local_ip->next)
        {
          if (local_ip->precedence <= local_iface->precedence)
            {
              if (prev_ip != NULL)
                prev_ip->next = local_iface->ip;
              else
                tunnel->local_ip = local_iface->ip;
              last_ip->next = local_ip;
              break;
            }
        }
      if (local_ip == NULL)
        {
          /* There were no local IPs with lower precedence,
             add local IP to end of list. */
          if (prev_ip != NULL)
            prev_ip->next = local_iface->ip;
          else
            tunnel->local_ip = local_iface->ip;
          last_ip->next = NULL;
        }

#ifdef SSHDIST_IPSEC_MOBIKE
      /* Mark tunnel local IPs changed. */
      tunnel->local_ip_changed = TRUE;
#endif /* SSHDIST_IPSEC_MOBIKE */
    }

  return TRUE;
}

Boolean
ssh_pm_tunnel_set_routing_instance(SshPmTunnel tunnel,
                                   const char *routing_instance_name)
{
  if (routing_instance_name == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Routing instance name not valid for tunnel."));
      return FALSE;
    }

  ssh_strncpy(tunnel->routing_instance_name, routing_instance_name,
              SSH_INTERCEPTOR_VRI_NAMESIZE);

  tunnel->routing_instance_id = ssh_ip_get_interface_vri_id(&tunnel->pm->ifs,
                                              tunnel->routing_instance_name);

  if (tunnel->routing_instance_id == SSH_INTERCEPTOR_VRI_ID_ANY)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Unavailable routing instance name '%s' for tunnel '%s' (%d)",
              tunnel->routing_instance_name,
              tunnel->tunnel_name,
              (int) tunnel->tunnel_id));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
              "Unavailable routing instance name '%s' for tunnel '%s' (%d)",
              tunnel->routing_instance_name,
              tunnel->tunnel_name,
              (int) tunnel->tunnel_id);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Set routing instance '%s' (%d) to tunnel '%s' (%d)",
                tunnel->routing_instance_name,
                tunnel->routing_instance_id,
                tunnel->tunnel_name,
                (int) tunnel->tunnel_id));

      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "Set routing instance '%s' (%d) to tunnel '%s' (%d)",
                    tunnel->routing_instance_name,
                    tunnel->routing_instance_id,
                    tunnel->tunnel_name,
                    (int) tunnel->tunnel_id);
    }

  return TRUE;
}

#ifdef SSHDIST_IKE_REDIRECT
Boolean
ssh_pm_tunnel_set_ike_redirect(SshPmTunnel tunnel,
                               const SshIpAddr ike_redirect)
{
  if(ike_redirect == NULL || !SSH_IP_DEFINED(ike_redirect))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE redirect address not valid for tunnel."));
      return FALSE;
    }

  /* Support implicit phase for now, if phase has not been set. */
  if ((tunnel->pm->ike_redirect_enabled & SSH_PM_IKE_REDIRECT_MASK) == 0)
    tunnel->pm->ike_redirect_enabled |= SSH_PM_IKE_REDIRECT_IKE_INIT;

  memcpy(tunnel->ike_redirect_addr, ike_redirect, sizeof(*ike_redirect));
  return TRUE;
}
#endif /* SSHDIST_IKE_REDIRECT */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
Boolean
ssh_pm_tunnel_set_remote_access_address(SshPmTunnel tunnel, const char *ip)
{
  SshIpAddrStruct irac_address;

  if (!ssh_ipaddr_parse(&irac_address, ip))
    return FALSE;

  if (SSH_IP6_IS_LINK_LOCAL(&irac_address))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Cannot define IPv6 link local addresses"));
      return FALSE;
    }

  if (tunnel->u.ike.num_irac_addresses >=
      SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot request more than %d address. Increase the "
                    "SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES parameter "
                    "and recompile",
                    SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES);
      return FALSE;
    }

  tunnel->u.ike.irac_address[tunnel->u.ike.num_irac_addresses] = irac_address;
  tunnel->u.ike.num_irac_addresses++;
  return TRUE;
}

Boolean
ssh_pm_tunnel_set_virtual_adapter(SshPmTunnel tunnel,
                                  const unsigned char *name)
{
  if (name == NULL || strlen(name) > SSH_INTERCEPTOR_IFNAME_SIZE)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid virtual adapter name"));
      return FALSE;
    }

  if (strlen(tunnel->vip_name) > 0)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Virtual adapter already defined for tunnel"));
      return FALSE;
    }

  ssh_snprintf(tunnel->vip_name, sizeof(tunnel->vip_name),
               "%s", name);

  return TRUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

Boolean
ssh_pm_tunnel_set_ike_groups(SshPmTunnel tunnel, SshUInt32 flags)
{
  SshUInt32 dh_groups;

  SSH_ASSERT(tunnel->refcount == 1);
  SSH_ASSERT(!tunnel->manual_tn);
  SSH_ASSERT((flags & 0xff000000) == 0);

  if ((flags & 0x00ffffff) == 0)
    /* Reset to our default groups. */
    flags |= SSH_PM_DEFAULT_DH_GROUPS;

  /* Check that 'flags' is sane */
  dh_groups = 0;
  if (!ssh_pm_ike_num_algorithms(tunnel->pm, 0, flags, NULL, NULL, &dh_groups)
      || dh_groups == 0)
    return FALSE;

  tunnel->ike_tn = 1;

  tunnel->u.ike.ike_groups = flags;

  /* Clear any previous configuration of groups with non-default preferences.*/
  tunnel->ike_dhgroup_modified = 0;
  tunnel->u.ike.num_tunnel_ike_groups = 0;

  if (tunnel->u.ike.tunnel_ike_groups)
    ssh_free(tunnel->u.ike.tunnel_ike_groups);
  tunnel->u.ike.tunnel_ike_groups = NULL;

  return TRUE;
}

Boolean
ssh_pm_tunnel_set_pfs_groups(SshPmTunnel tunnel, SshUInt32 flags)
{
  SshUInt32 pfs_groups;

  SSH_ASSERT(tunnel->refcount == 1);
  SSH_ASSERT(!tunnel->manual_tn);

  tunnel->ike_tn = 1;

  if ((flags & 0x00ffffff) == 0)
    /* Only Diffie-Hellman flags are set.  Use our default groups. */
    flags |= SSH_PM_DEFAULT_DH_GROUPS;

  /* Check that 'flags' is sane */
  pfs_groups = 0;
  if (!ssh_pm_ike_num_algorithms(tunnel->pm, 0, flags, NULL, NULL, &pfs_groups)
      || pfs_groups == 0)
    return FALSE;

  tunnel->u.ike.pfs_groups = flags;

  /* Clear any previous configuration of groups with non-default preferences.*/
  tunnel->pfs_dhgroup_modified = 0;
  tunnel->u.ike.num_tunnel_pfs_groups = 0;

  if (tunnel->u.ike.tunnel_pfs_groups)
    ssh_free(tunnel->u.ike.tunnel_pfs_groups);
  tunnel->u.ike.tunnel_pfs_groups = NULL;

  return TRUE;
}

void
ssh_pm_tunnel_set_life(SshPmTunnel tunnel, SshPmLifeType type, SshUInt32 value)
{
  SSH_ASSERT(tunnel->refcount == 1);

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return;
    }
  tunnel->ike_tn = 1;

  switch (type)
    {
    case SSH_PM_LIFE_SECONDS:
      if (value < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME)
        {
          tunnel->u.ike.life_seconds =
            2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME;
          ssh_warning("IPsec SA lifetime %d is too low, "
                      "setting lifetime to %d seconds.",
                      (unsigned long) value,
                      (unsigned long) tunnel->u.ike.life_seconds);
        }
      else
        {
          tunnel->u.ike.life_seconds = value;
        }
      break;

    case SSH_PM_LIFE_KB:
      if (value < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB)
        {
          tunnel->u.ike.life_kb =
            2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB;
          ssh_warning("IPsec SA kilobyte lifetime %d is too low, "
                      "setting kilobyte lifetime to %d kilobytes.",
                      (unsigned long) value,
                      (unsigned long) tunnel->u.ike.life_kb);
        }
      else
        {
          tunnel->u.ike.life_kb = value;
        }
      break;
    }
}

void
ssh_pm_tunnel_set_ike_life(SshPmTunnel tunnel, SshUInt32 seconds)
{
  SSH_ASSERT(tunnel->refcount == 1);

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return;
    }
  tunnel->ike_tn = 1;

  if (seconds < SSH_PM_IKE_SA_MIN_LIFETIME)
    {
      tunnel->u.ike.ike_sa_life_seconds = SSH_PM_IKE_SA_MIN_LIFETIME;
      ssh_warning("IKE SA lifetime %d is too low, "
                  "setting lifetime to %d seconds.",
                  (unsigned long) seconds,
                  (unsigned long) tunnel->u.ike.ike_sa_life_seconds);
    }
  else
    {
      tunnel->u.ike.ike_sa_life_seconds = seconds;
    }
}
#ifdef SSHDIST_IKE_CERT_AUTH
#ifdef SSHDIST_CERT

Boolean
ssh_pm_tunnel_set_cert(SshPmTunnel tunnel, const unsigned char *cert,
                       size_t cert_len)
{
  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return FALSE;
    }
  tunnel->ike_tn = 1;

  return ssh_pm_get_certificate_kid(tunnel->pm, cert, cert_len,
                                    &tunnel->u.ike.local_cert_kid,
                                    &tunnel->u.ike.local_cert_kid_len);
}
#endif /* SSHDIST_CERT */
#endif /* SSHDIST_IKE_CERT_AUTH */

Boolean
ssh_pm_tunnel_set_outer_tunnel(SshPmTunnel inner_tunnel,
                               const SshPmTunnel outer_tunnel,
                               SshUInt32 flags)
{
  SshADTHandle h;
  SshUInt32 nesting_level, inner_tunnel_count = 0;
  SshPmTunnel t;

  SSH_ASSERT(inner_tunnel->outer_tunnel == NULL);
  SSH_ASSERT(outer_tunnel != NULL);

  /* Count the number of inner tunnels referring to this outer tunnel. */
  for (h = ssh_adt_enumerate_start(inner_tunnel->pm->tunnels);
       h != SSH_ADT_INVALID;
       h = ssh_adt_enumerate_next(inner_tunnel->pm->tunnels, h))
    {
      t = (SshPmTunnel) ssh_adt_get(inner_tunnel->pm->tunnels, h);
      SSH_ASSERT(t != NULL);

      if (t->outer_tunnel == outer_tunnel)
        inner_tunnel_count++;
    }
  if (inner_tunnel_count >= SSH_PM_MAX_INNER_TUNNELS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Maximum number of inner tunnels per outer tunnel "
                 "reached (%d)", SSH_PM_MAX_INNER_TUNNELS));
      return FALSE;
    }

  /* Count the nesting level for this inner tunnel. */
  nesting_level = 1;
  for (t = outer_tunnel; t != NULL; t = t->outer_tunnel)
    nesting_level++;
  if (nesting_level > SSH_ENGINE_MAX_TUNNEL_NESTING)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Maximum level of tunnel nesting reached (%d)",
                             SSH_ENGINE_MAX_TUNNEL_NESTING));
      return FALSE;
    }

  /* Sanity check outer tunnel. */
  if (SSH_PM_TUNNEL_IS_VIRTUAL_IP(outer_tunnel)
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
      && (outer_tunnel->flags & SSH_PM_TI_INTERFACE_TRIGGER) == 0
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */
      && (outer_tunnel->flags & SSH_PM_TI_DELAYED_OPEN))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Cannot use packet triggered virtual IP tunnel"
                 " as outer tunnel"));
      return FALSE;
    }

  /* Inherit SSH_PM_T_NO_NATS_ALLOWED from outer tunnel. */
  if (outer_tunnel->flags & SSH_PM_T_NO_NATS_ALLOWED)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Inheriting SSH_PM_T_NO_NATS_ALLOWED from outer tunnel."));
      inner_tunnel->flags |= SSH_PM_T_NO_NATS_ALLOWED;
    }

  /* Store inner_tunnel flags. */
  /* None at the moment. */





  /* Take a reference to outer_tunnel, so it will not get destroyed. */
  inner_tunnel->outer_tunnel = outer_tunnel;
  SSH_PM_TUNNEL_TAKE_REF(inner_tunnel->outer_tunnel);

  return TRUE;
}

Boolean
ssh_pm_tunnel_set_extension(SshPmTunnel tunnel, SshUInt32 i,
                            SshUInt32 extension)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Setting inbound extension selector index %d to %d",
             (int) i, (int) extension));
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  if (i >= SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS)
    return FALSE;

  tunnel->extension[i] = extension;
  tunnel->flags |= SSH_PM_T_SET_EXTENSION_SELECTOR;
#endif /* SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0 */
  return TRUE;
}
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

void
ssh_pm_tunnel_set_remote_access(SshPmTunnel tunnel,
                                SshPmRemoteAccessAttrsAllocCB alloc_cb,
                                SshPmRemoteAccessAttrsFreeCB free_cb,
                                void *context)
{
  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return;
    }

  if ((tunnel->flags & SSH_PM_TR_ALLOW_CFGMODE) == 0
      && (tunnel->flags & SSH_PM_TR_ALLOW_L2TP) == 0)
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("No cfg or l2tp mode, "
                               "skip setting of address pool callbacks"));
      return;
    }

  tunnel->ike_tn = 1;

  tunnel->u.ike.remote_access_alloc_cb = alloc_cb;
  tunnel->u.ike.remote_access_free_cb = free_cb;
  tunnel->u.ike.remote_access_cb_context = context;
}

Boolean
ssh_pm_tunnel_add_address_pool(SshPmTunnel tunnel,
                               const unsigned char *name)
{
  SshPmAddressPoolId id = 0;

  SSH_ASSERT(tunnel != NULL && name !=NULL);

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return FALSE;
    }

  if ((tunnel->flags & SSH_PM_TR_ALLOW_CFGMODE) == 0
      && (tunnel->flags & SSH_PM_TR_ALLOW_L2TP) == 0)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
                ("No cfg or l2tp mode, Skip adding of address pool"));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Adding address pool '%s' to tunnel %s",
                               name, tunnel->tunnel_name));

  /* Remove the default address pool that was initially set in
     ssh_pm_tunnel_create(). */
  if (ssh_pm_address_pool_get_default_id(tunnel->pm, &id)
      && tunnel->num_address_pool_ids == 1
      && tunnel->address_pool_ids[0] == id)
    tunnel->num_address_pool_ids = 0;

  if (tunnel->num_address_pool_ids == SSH_PM_TUNNEL_MAX_ADDRESS_POOLS)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot configure more than "
                    "SSH_PM_TUNNEL_MAX_ADDRESS_POOLS (%d) address pools "
                    "to a tunnel.", SSH_PM_TUNNEL_MAX_ADDRESS_POOLS);
      return FALSE;
    }

  /* Check address pool in pm */
  if (!ssh_pm_address_pool_get_id(tunnel->pm, name, &id))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to locate address pool with name '%s' in PM. "
                 "Not setting address pools in tunnel", name));
      return FALSE;
    }

  tunnel->address_pool_ids[tunnel->num_address_pool_ids++] = id;

  /* Assert that remote access callbacks are properly set. */
  SSH_ASSERT(tunnel->u.ike.remote_access_alloc_cb != NULL_FNPTR);

  tunnel->ike_tn = 1;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Stored address pool id %d to tunnel %s",
                               id, tunnel->tunnel_name));
  return TRUE;
}
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */











































Boolean
ssh_pm_tunnel_set_ike_algorithms(SshPmTunnel tunnel, SshUInt32 algorithms)
{
  Boolean algorithms_defined;
  SshUInt32 num_ciphers;
  SshUInt32 num_hashes;

  SSH_ASSERT(!tunnel->manual_tn);

  /* Check that given algorithms are usable with IKE and that both
     cipher and mac has been provided. */
  algorithms_defined = ssh_pm_ike_num_algorithms(tunnel->pm, algorithms, 0,
                                                 &num_ciphers, &num_hashes,
                                                 NULL);
  if (algorithms_defined == FALSE)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Specified algorithm that is unavailable or "
                              "unusable with IKE"));
      return FALSE;
    }

#ifdef SSHDIST_IKEV1
  if ((tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1) != 0)
    {
      if ((algorithms & SSH_PM_CRYPT_AES_CTR) != 0)
        {
          SSH_DEBUG(SSH_D_ERROR, ("AES CTR mode cannot be used with IKEv1"));
          return FALSE;
        }

      if ((tunnel->pm->params.enable_key_restrictions &
           SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
        {
          if ((algorithms & (SSH_PM_MAC_HMAC_MD5 | SSH_PM_MAC_HMAC_SHA1)) != 0)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Specified algorithm that is not "
                                      "allowed by used key restrictions."));
              return FALSE;
            }
        }
    }

  if ((tunnel->u.ike.algorithms & SSH_PM_COMBINED_MASK) != 0
      && (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1) != 0)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Combined algorithm is forbidden as IKE algorithm "
                 "in IKEv1 tunnel"));
      return FALSE;
    }
#endif /* SSHDIST_IKEV1 */

  tunnel->u.ike.algorithms = algorithms;
  tunnel->ike_tn = 1;
  return TRUE;
}

Boolean
ssh_pm_tunnel_set_algorithm_properties(SshPmTunnel tunnel,
                                       SshUInt32 algorithm,
                                       SshUInt32 min_key_size,
                                       SshUInt32 max_key_size,
                                       SshUInt32 default_key_size)
{
  SshUInt32 num_ciphers;
  SshUInt32 num_macs;
  SshUInt32 num_compressions;
  SshUInt32 min_key_size_alg;
  SshUInt32 max_key_size_alg;
  SshUInt32 incr_key_size_alg;
  SshUInt32 i;
  SshPmAlgorithmProperties prop;
  Boolean ipsec_scope;

  /* Check the scope. */
  if (algorithm & SSH_PM_ALG_IPSEC_SA)
    ipsec_scope = TRUE;
  else if (algorithm & SSH_PM_ALG_IKE_SA)
    ipsec_scope = FALSE;
  else
    return FALSE;

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return FALSE;
    }

  /* Check the validity of the constraints. */
  if (min_key_size > max_key_size
      || default_key_size < min_key_size
      || default_key_size > max_key_size)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Invalid key sizes specified");
      return FALSE;
    }

  /* Check that we know all algorithms specified. */
  if (ipsec_scope)
    {
      if (!ssh_pm_ipsec_num_algorithms(tunnel->pm,
                                       algorithm & (SSH_PM_CRYPT_MASK
                                                    | SSH_PM_MAC_MASK
                                                    | SSH_PM_COMPRESS_MASK),
                                       0,
                                       &num_ciphers,
                                       &num_macs,
                                       &num_compressions,
                                       NULL))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Algorithm key sizes specified for unknown algorithm");
          return FALSE;
        }
    }
  else
    {
      if (!ssh_pm_ike_num_algorithms(tunnel->pm,
                                     algorithm & (SSH_PM_CRYPT_MASK
                                                  | SSH_PM_MAC_MASK
                                                  | SSH_PM_COMPRESS_MASK),
                                     0,
                                     &num_ciphers,
                                     &num_macs,
                                     NULL))
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Algorithm key sizes specified for unknown algorithm");
          return FALSE;
        }
    }

  /* Check that no constraints were specified for fixed size
     algorithms and that constraints are within correct ranges. */
  for (i = 0; i < num_ciphers; i++)
    {
      SshPmCipher cipher;

      if (ipsec_scope)
        cipher = ssh_pm_ipsec_cipher(tunnel->pm, i, algorithm);
      else
        cipher = ssh_pm_ike_cipher(tunnel->pm, i, algorithm);

      if (cipher->key_increment == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Key size limits specified for fixed key size "
                        "cipher %s", cipher->name);
          return FALSE;
        }

      /* Get keysize restrictions for the MAC. */
      ssh_pm_cipher_key_sizes(tunnel, cipher,
                              ipsec_scope? SSH_PM_ALG_IPSEC_SA:
                              SSH_PM_ALG_IKE_SA,
                              &min_key_size_alg,
                              &max_key_size_alg,
                              &incr_key_size_alg, NULL);

      if (min_key_size < min_key_size_alg ||
          max_key_size > max_key_size_alg)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Keysize limits specified are outside allowed range "
                        "%u-%u.",
                        (unsigned int) min_key_size_alg,
                        (unsigned int) max_key_size_alg);
          return FALSE;
        }

      if ((min_key_size % incr_key_size_alg) != 0 ||
          (max_key_size % incr_key_size_alg) != 0 ||
          (default_key_size % incr_key_size_alg) != 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Key sizes specified do not match available "
                        "key sizes of the algorithm.");
          return FALSE;
        }

      /* Check that the key limits are within our compile time maximum
         values. The nonce for counter modes is not included in the
         max_key_size. */
      if (max_key_size + cipher->nonce_size > SSH_IPSEC_MAX_ESP_KEY_BITS)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "The maximum cipher key size %u is bigger than "
                        "the built-in maximum %u",
                        (unsigned int) (max_key_size + cipher->nonce_size),
                        SSH_IPSEC_MAX_ESP_KEY_BITS);
          return FALSE;
        }
    }
  for (i = 0; i < num_macs; i++)
    {
      SshPmMac mac;

      if (ipsec_scope)
        mac = ssh_pm_ipsec_mac(tunnel->pm, i, algorithm);
      else
        mac = ssh_pm_ike_mac(tunnel->pm, i, algorithm);

      if (mac->key_increment == 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Key size limits specified for fixed key size "
                        "MAC %s", mac->name);
          return FALSE;
        }

      /* Get keysize restrictions for the MAC. */
      ssh_pm_mac_key_sizes(tunnel, mac,
                           ipsec_scope? SSH_PM_ALG_IPSEC_SA:
                           SSH_PM_ALG_IKE_SA,
                           &min_key_size_alg,
                           &max_key_size_alg,
                           &incr_key_size_alg, NULL);

      if (min_key_size < min_key_size_alg ||
          max_key_size > max_key_size_alg)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Keysize limits specified are outside allowed range "
                        "%u-%u.",
                        (unsigned int) min_key_size_alg,
                        (unsigned int) max_key_size_alg);
          return FALSE;
        }

      if ((min_key_size % incr_key_size_alg) != 0 ||
          (max_key_size % incr_key_size_alg) != 0 ||
          (default_key_size % incr_key_size_alg) != 0)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Key sizes specified do not match available "
                        "key sizes of the algorithm.");
          return FALSE;
        }

      /* Check that the key limits are within our compile time maximum
         values. */
      if (max_key_size > SSH_IPSEC_MAX_MAC_KEY_BITS)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "The maximum MAC key size %u is bigger than "
                        "the built-in maximum %u",
                        (unsigned int) max_key_size,
                        SSH_IPSEC_MAX_MAC_KEY_BITS);
          return FALSE;
        }
    }

  /* Add this constraint for the tunnel. */
  prop = ssh_calloc(1, sizeof(*prop));
  if (prop == NULL)
    return FALSE;

  prop->algorithm = algorithm;
  prop->min_key_size = min_key_size;
  prop->max_key_size = max_key_size;
  prop->default_key_size = default_key_size;

  prop->next = tunnel->algorithm_properties;
  tunnel->algorithm_properties = prop;

  return TRUE;
}

Boolean
ssh_pm_tunnel_get_algorithm_properties(SshPmTunnel tunnel,
                                       SshUInt32 algorithm,
                                       SshUInt32 *min_key_size_return,
                                       SshUInt32 *max_key_size_return,
                                       SshUInt32 *default_key_size_return)
{
  SshUInt32 num_ciphers = 0;
  SshUInt32 num_macs = 0;
  SshPmCipher cipher;
  SshPmMac mac;

  /* Check the scope. */
  if (algorithm & SSH_PM_ALG_IPSEC_SA)
    (void) ssh_pm_ipsec_num_algorithms(tunnel->pm, algorithm, 0,
                                       &num_ciphers, &num_macs, NULL, NULL);
  else if (algorithm & SSH_PM_ALG_IKE_SA)
    (void) ssh_pm_ike_num_algorithms(tunnel->pm, algorithm, 0,
                                     &num_ciphers, &num_macs, NULL);
  else
    return FALSE;

  /* Exactly one algorithm must be specified. */
  if (num_ciphers + num_macs != 1)
    return FALSE;

  /* Fetch the algorithm properties. */
  if (num_ciphers)
    {
      if (algorithm & SSH_PM_ALG_IPSEC_SA)
        cipher = ssh_pm_ipsec_cipher(tunnel->pm, 0, algorithm);
      else
        cipher = ssh_pm_ike_cipher(tunnel->pm, 0, algorithm);

      ssh_pm_cipher_key_sizes(tunnel, cipher, algorithm,
                              min_key_size_return,
                              max_key_size_return,
                              NULL,
                              default_key_size_return);
    }
  else
    {
      if (algorithm & SSH_PM_ALG_IPSEC_SA)
        mac = ssh_pm_ipsec_mac(tunnel->pm, 0, algorithm);
      else
        mac = ssh_pm_ike_mac(tunnel->pm, 0, algorithm);

      ssh_pm_mac_key_sizes(tunnel, mac, algorithm,
                           min_key_size_return,
                           max_key_size_return,
                           NULL,
                           default_key_size_return);
    }

  return TRUE;
}

/* Check whether the tunnel's IKE algorithms are acceptable to the SA
   payload 'sa_in', and if this is an IKEv1 exchange whether this tunnel
   can be used for IKEv1 negotiations. */
static Boolean
pm_tunnel_check_ike_version_and_payload(SshPm pm, SshPmTunnel tunnel,
                                        Boolean ikev1,
                                        SshIkev2PayloadSA sa_in,
                                        SshUInt32 *failure_mask,
                                        SshUInt32 *ike_failure_mask)
{
  SshIkev2PayloadTransform selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIkev2PayloadSA sa_policy;
  SshIkev2Error ike_error;
  int proposal_index;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Checking tunnel '%s' policy against IKE SA payload %@",
             tunnel->tunnel_name,
             ssh_ikev2_payload_sa_render, sa_in));

  ike_error = ssh_pm_build_ike_sa_from_tunnel(pm, tunnel, &sa_policy);

  if (ike_error != SSH_IKEV2_ERROR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to construct SA payload from tunnel"));
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IKE SA payload constructed from tunnel is %@",
                          ssh_ikev2_payload_sa_render, sa_policy));

  if (ssh_ikev2_sa_select(sa_in, sa_policy, &proposal_index,
                          selected_transforms, ike_failure_mask))
    {
      ssh_ikev2_sa_free(pm->sad_handle, sa_policy);

      /* Check the proposal index is as expected. */
      if (sa_in->protocol_id[proposal_index] != SSH_IKEV2_PROTOCOL_ID_IKE)
        {
          SSH_DEBUG(SSH_D_LOWOK*0, ("IKE SA proposal index is not correct: "
                                  "received %d (proposal index=%d), "
                                  "expected %d failure mask %x",
                                  sa_in->protocol_id[proposal_index],
                                  proposal_index,
                                  SSH_IKEV2_PROTOCOL_ID_IKE,
                                  *ike_failure_mask));
          return FALSE;
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("IKE SA selection failed failure mask %x",
                              *ike_failure_mask));
      ssh_ikev2_sa_free(pm->sad_handle, sa_policy);
      return FALSE;
    }

  /* The IKE version matching is left until the final check so that if it
     fails we know that the tunnel is acceptable apart from the IKE version
     and we can return the SSH_IKEV2_ERROR_USE_IKEV1 error code */
  if (ikev1 && (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_1) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("The supported IKE versions do not match"));
      (*failure_mask) |= SSH_PM_E_IKE_VERSION_MISMATCH;
      return FALSE;
    }

  if (!ikev1 && (tunnel->u.ike.versions & SSH_PM_IKE_VERSION_2) == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("The supported IKE versions do not match"));
      (*failure_mask) |= SSH_PM_E_IKE_VERSION_MISMATCH;
      return FALSE;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("IKE tunnel matches the SA payload"));
  return TRUE;
}

SshPmTunnel
ssh_pm_tunnel_lookup(SshPm pm, Boolean ikev1,
                     SshIkev2Server server,
                     SshIpAddr remote,
                     SshIkev2PayloadSA sa_in,
                     SshUInt32 *failure_mask,
                     SshUInt32 *ike_failure_mask)
{
  SshPmRule rule;
  SshPmTunnel tunnel;
  SshPmTunnel closest_match_tunnel = NULL;
  SshADTHandle handle;
  SshPmTunnelLocalIp local_ip;
  SshUInt32 match_type = 0;
  SshUInt32 match_this_iteration = 0;
  SshUInt32 i;
  Boolean recurse_to_tunnel = FALSE;
  SshIpAddr local = server->ip_address;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Search for a closest match tunnel for local "
                               "address %@ and remote address %@ "
                               "routing instance %d",
                               ssh_ipaddr_render, local,
                               ssh_ipaddr_render, remote,
                               server->routing_instance_id));

  SSH_DEBUG(SSH_D_LOWSTART,
            ("Enumerating tunnels based on the precedence of from-tunnel "
             "rules"));

  /* Iterate through the tunnel ADT and search for a tunnel that matches
     exactly local and remote */
  for (handle = ssh_adt_enumerate_start(pm->rule_by_precedence);
       handle != SSH_ADT_INVALID;
       handle = ssh_adt_enumerate_next(pm->rule_by_precedence, handle))
    {
      recurse_to_tunnel = FALSE;
      match_this_iteration = 0;
      rule = (SshPmRule) ssh_adt_get(pm->rule_by_precedence, handle);

      if (rule->side_from.tunnel)
        {
          tunnel = rule->side_from.tunnel;
          if (rule->side_to.tunnel)
            recurse_to_tunnel = TRUE;
        }
      else if (rule->side_to.tunnel)
        {
        lookup_to_tunnel:
          recurse_to_tunnel = FALSE;
          tunnel = rule->side_to.tunnel;
        }
      else
        {
          recurse_to_tunnel = FALSE;
          goto recursion_check;
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Considering tunnel '%s'", tunnel->tunnel_name));

      /* Can't use manually keyed tunnels for IKE... */
      if (tunnel->manual_tn)
        goto recursion_check;

      if (server->routing_instance_id != tunnel->routing_instance_id)
       {
         SSH_DEBUG(SSH_D_NICETOKNOW,
                   ("routing instance mismatch: server %d tunnel  %d",
                    server->routing_instance_id,
                    tunnel->routing_instance_id));
         goto recursion_check;
       }


      /* Look if we have local match. */
      for (local_ip = tunnel->local_ip;
           local_ip != NULL;
           local_ip = local_ip->next)
        {
          if (SSH_IP_EQUAL(local, &local_ip->ip))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("The local IP address matches."));
              match_this_iteration |= 0x1;
              break;
            }
        }

      /* If we have specified local ips for the tunnel and the remote
         did not match for these, we ignore this tunnel. */
      if ((tunnel->local_ip != NULL
           || tunnel->local_interface != NULL
#ifdef SSHDIST_IPSEC_DNSPOLICY
           || tunnel->local_dns_address != NULL
#endif /* SSHDIST_IPSEC_DNSPOLICY */
           )
          && !match_this_iteration)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Tunnel specifies local IP address, "
                                  "packet did not match it."));
          goto recursion_check;
        }

      /* Look if we have remote match. */
      for (i = 0; i < tunnel->num_peers; i++)
        {
          if (SSH_IP_EQUAL(remote, &tunnel->peers[i]))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("The peer IP address matches."));
              match_this_iteration |= 0x2;
              break;
            }
        }

      /* If we have specified peers for the tunnel and the remote
         did not match for these, we ignore it. */
      if (tunnel->num_peers && tunnel->num_peers == i)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Tunnel specifies peers, remote did not"
                                  " match."));
          goto recursion_check;
        }

      if (pm_tunnel_check_ike_version_and_payload(pm, tunnel,
                                                  ikev1, sa_in,
                                                  failure_mask,
                                                  ike_failure_mask))
        {
          /* We prefer remote match over local match. */
          if (!closest_match_tunnel ||
              (match_this_iteration > match_type))
            {
              closest_match_tunnel = tunnel;
              match_type = match_this_iteration;
            }

          /* Check if both local & remote matches. */
          if (match_type == 0x3)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Selected IKE tunnel %s (%p).",
                                           closest_match_tunnel->tunnel_name,
                                           closest_match_tunnel));
              return closest_match_tunnel;
            }
        }
      else
        {
          SSH_DEBUG(SSH_D_LOWOK, ("SA payloads or IKE version do not match"));
        }

    recursion_check:
      if (recurse_to_tunnel)
        goto lookup_to_tunnel;
    }

  if (closest_match_tunnel)
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Selected IKE tunnel %s (%p).",
                                 closest_match_tunnel->tunnel_name,
                                 closest_match_tunnel));
  else
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_INFORMATIONAL,
                    "No IKE tunnel found matching the local address %@ and "
                    "remote address %@",
                    ssh_ipaddr_render, local,
                    ssh_ipaddr_render, remote);
    }

  return closest_match_tunnel;

}

SshPmDHGroup
ssh_pm_tunnel_dh_group(SshPmTunnel tunnel, SshUInt32 index, Boolean pfs)
{
  if (pfs)
    {
      /* If we have local copies of the DH PFS groups in the tunnel, then use
         those. */
      if (tunnel->pfs_dhgroup_modified)
        {
          if (index < tunnel->u.ike.num_tunnel_pfs_groups)
            return &tunnel->u.ike.tunnel_pfs_groups[index];
          else
            return NULL;
        }
      else
        {
          /* Return the global DH PFS group. */
          return ssh_pm_dh_group(tunnel->pm, index, tunnel->u.ike.pfs_groups);
        }
    }
  else
    {
      /* If we have local copies of the DH IKE groups in the tunnel, then use
         those. */
      if (tunnel->ike_dhgroup_modified)
        {
          if (index < tunnel->u.ike.num_tunnel_ike_groups)
            return &tunnel->u.ike.tunnel_ike_groups[index];
          else
            return NULL;
        }
      else
        {
          /* Return the global DH IKE group. */
          return ssh_pm_dh_group(tunnel->pm, index, tunnel->u.ike.ike_groups);
        }
    }
}

static int pm_tunnels_dhgroup_cmp(const void *av, const void *bv)
{
  SshPmDHGroup a, b;

  a = (SshPmDHGroup) av;
  b = (SshPmDHGroup) bv;

  /* Sort on base of preference */
  if (a->preference < b->preference)
    return 1;
  if (a->preference > b->preference)
    return -1;
  return 0;
}

Boolean
ssh_pm_tunnel_set_ike_group_preference(SshPmTunnel tunnel,
                                       SshUInt32 group,
                                       SshUInt8 preference)
{
  SshPmDHGroup dhgroup;
  SshUInt32 i, num_groups = 0;

  tunnel->ike_tn = 1;

  SSH_DEBUG(SSH_D_LOWSTART, ("Setting preference of group with bit mask %x "
                             "to %d",
                             (unsigned int) group, preference));

  if (!ssh_pm_dh_group_is_known(group))
    {
      SSH_DEBUG(SSH_D_ERROR, ("The group %x is unknown",
                              (unsigned int) group));
      return FALSE;
    }

  (void) ssh_pm_ike_num_algorithms(tunnel->pm, 0,
                                   tunnel->u.ike.ike_groups,
                                   NULL, NULL, &num_groups);

  /* Copy the global groups to the tunnel if this is the first time we
     are modifying the preference of one of the IKE groups */
  if (tunnel->ike_dhgroup_modified == 0 && num_groups)
    {
      tunnel->u.ike.tunnel_ike_groups = ssh_calloc(num_groups,
                                                  sizeof(SshPmDHGroupStruct));
      if (!tunnel->u.ike.tunnel_ike_groups)
        return FALSE;

      tunnel->u.ike.num_tunnel_ike_groups = num_groups;

      for (i = 0; i < num_groups; i++)
        {
          dhgroup = ssh_pm_dh_group(tunnel->pm, i, tunnel->u.ike.ike_groups);
          SSH_ASSERT(dhgroup != NULL);
          memcpy(&tunnel->u.ike.tunnel_ike_groups[i], dhgroup,
                 sizeof(*dhgroup));
        }
    }

  SSH_ASSERT(num_groups == tunnel->u.ike.num_tunnel_ike_groups);

  /* Do we know this group ? */
  if ((group & tunnel->u.ike.ike_groups) == 0)
    {
      /* This is a new group, allocate a new entry for it. */
      tunnel->u.ike.ike_groups |= group;

      dhgroup = ssh_realloc(tunnel->u.ike.tunnel_ike_groups,
                            num_groups * sizeof(SshPmDHGroupStruct),
                            (num_groups + 1) * sizeof(SshPmDHGroupStruct));

      if (!dhgroup)
        return FALSE;

      tunnel->u.ike.num_tunnel_ike_groups++;
      tunnel->u.ike.tunnel_ike_groups = dhgroup;
      dhgroup = ssh_pm_dh_group(tunnel->pm, 0, group);
      SSH_ASSERT(dhgroup != NULL);

      memcpy(&tunnel->u.ike.tunnel_ike_groups[num_groups], dhgroup,
             sizeof(*dhgroup));

      /* And modify its preference to the user supplied value. */
      tunnel->u.ike.tunnel_ike_groups[num_groups].preference = preference;
    }
  else
    {
      /* Yes, we know this group, just change its preference. */
      for (i = 0; i < num_groups; i++)
        if (tunnel->u.ike.tunnel_ike_groups[i].mask_bits & group)
          tunnel->u.ike.tunnel_ike_groups[i].preference = preference;
    }

  /* Sort the groups in order of preference */
  qsort(tunnel->u.ike.tunnel_ike_groups,
        tunnel->u.ike.num_tunnel_ike_groups,
        sizeof(SshPmDHGroupStruct),
        pm_tunnels_dhgroup_cmp);

#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_MIDOK, ("Listing the IKE Diffie Hellman group preferences "
                          "%d groups",
                          (int) tunnel->u.ike.num_tunnel_ike_groups));
  for (i = 0; i < tunnel->u.ike.num_tunnel_ike_groups; i++)
    SSH_DEBUG(SSH_D_MIDOK, ("The IKE Diffie Hellman preference of group "
                            "%d is preference %d",
                            tunnel->u.ike.tunnel_ike_groups[i].group_desc,
                            tunnel->u.ike.tunnel_ike_groups[i].preference));
#endif /* DEBUG_LIGHT */

  /* Mark that the tunnel has a modified copy of the IKE DH groups. */
  tunnel->ike_dhgroup_modified = 1;
  return TRUE;
}

Boolean
ssh_pm_tunnel_set_pfs_group_preference(SshPmTunnel tunnel,
                                       SshUInt32 group,
                                       SshUInt8 preference)
{
  SshPmDHGroup dhgroup;
  SshUInt32 i, num_groups = 0;

  tunnel->ike_tn = 1;

  SSH_DEBUG(SSH_D_LOWSTART, ("Setting preference of group with bit mask %x "
                             "to %d",
                             (unsigned int) group, preference));

  if (!ssh_pm_dh_group_is_known(group))
    {
      SSH_DEBUG(SSH_D_ERROR, ("The group %x is unknown",
                              (unsigned int) group));
      return FALSE;
    }

  (void) ssh_pm_ipsec_num_algorithms(tunnel->pm, 0,
                                     tunnel->u.ike.pfs_groups,
                                     NULL, NULL, NULL, &num_groups);

  /* Copy the global groups to the tunnel if this is the first time we
     are modifying the preference of one of the PFS groups */
  if (tunnel->pfs_dhgroup_modified == 0 && num_groups)
    {
      tunnel->u.ike.tunnel_pfs_groups = ssh_calloc(num_groups,
                                                  sizeof(SshPmDHGroupStruct));
      if (!tunnel->u.ike.tunnel_pfs_groups)
        return FALSE;

      tunnel->u.ike.num_tunnel_pfs_groups = num_groups;

      for (i = 0; i < num_groups; i++)
        {
          dhgroup = ssh_pm_dh_group(tunnel->pm, i, tunnel->u.ike.pfs_groups);
          SSH_ASSERT(dhgroup != NULL);
          memcpy(&tunnel->u.ike.tunnel_pfs_groups[i], dhgroup,
                 sizeof(*dhgroup));
        }
    }

  SSH_ASSERT(num_groups == tunnel->u.ike.num_tunnel_pfs_groups);

  /* Do we know this group ? */
  if ((group & tunnel->u.ike.pfs_groups) == 0)
    {
      /* This is a new group, allocate a new entry for it. */
      tunnel->u.ike.pfs_groups |= group;

      dhgroup = ssh_realloc(tunnel->u.ike.tunnel_pfs_groups,
                            num_groups * sizeof(SshPmDHGroupStruct),
                            (num_groups + 1) * sizeof(SshPmDHGroupStruct));
      if (!dhgroup)
        return FALSE;

      tunnel->u.ike.num_tunnel_pfs_groups++;
      tunnel->u.ike.tunnel_pfs_groups = dhgroup;
      dhgroup = ssh_pm_dh_group(tunnel->pm, 0, group);
      SSH_ASSERT(dhgroup != NULL);

      memcpy(&tunnel->u.ike.tunnel_pfs_groups[num_groups], dhgroup,
             sizeof(*dhgroup));

      /* And modify its preference to the user supplied value. */
      tunnel->u.ike.tunnel_pfs_groups[num_groups].preference = preference;
    }
  else
    {
      /* Yes, we know this group, just change its preference. */
      for (i = 0; i < num_groups; i++)
        if (tunnel->u.ike.tunnel_pfs_groups[i].mask_bits & group)
          tunnel->u.ike.tunnel_pfs_groups[i].preference = preference;
    }

  /* Sort the groups in order of preference */
  qsort(tunnel->u.ike.tunnel_pfs_groups,
        tunnel->u.ike.num_tunnel_pfs_groups,
        sizeof(SshPmDHGroupStruct),
        pm_tunnels_dhgroup_cmp);

#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_MIDOK, ("Listing the PFS Diffie Hellman group preferences "
                          "%d groups",
                          (int) tunnel->u.ike.num_tunnel_pfs_groups));
  for (i = 0; i < tunnel->u.ike.num_tunnel_pfs_groups; i++)
    SSH_DEBUG(SSH_D_MIDOK, ("The PFS Diffie Hellman group preference of %d is "
                            "now group %d with preference %d", (int) i,
                            tunnel->u.ike.tunnel_pfs_groups[i].group_desc,
                            tunnel->u.ike.tunnel_pfs_groups[i].preference));
#endif /* DEBUG_LIGHT */

  /* Mark that the tunnel has a modified copy of the PFS DH groups. */
  tunnel->pfs_dhgroup_modified = 1;
  return TRUE;
}

#ifdef SSHDIST_IKEV1
Boolean
ssh_pm_tunnel_set_ike_versions(SshPmTunnel tunnel, SshUInt8 versions)
{
  if ((versions & (SSH_PM_IKE_VERSION_1 | SSH_PM_IKE_VERSION_2)) == 0)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Invalid IKE versions 0x%x", versions));
      return FALSE;
    }

  /* Check tunnel compatibility with IKEv1. */
  if (versions & SSH_PM_IKE_VERSION_1)
    {
#ifdef SSHDIST_CRYPT_XCBCMAC
      /* xcbc-aes cannot be used as IKE algorithm with IKEv1 . */
      if (tunnel->u.ike.algorithms & SSH_PM_MAC_XCBC_AES)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("xcbc-aes cannot be enabled as IKE algorithm "
                     "in IKEv1 tunnel"));
          return FALSE;
        }
#endif /* SSHDIST_CRYPT_XCBCMAC */
      if (tunnel->u.ike.algorithms & SSH_PM_CRYPT_AES_CTR)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("aes-ctr cannot be enabled as IKE algorithm "
                     "in IKEv1 tunnel"));
          return FALSE;
        }
      if (tunnel->u.ike.algorithms & SSH_PM_COMBINED_MASK)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Combined algorithm is forbidden as IKE algorithm "
                     "in IKEv1 tunnel"));
          return FALSE;
        }
#ifdef SSHDIST_IPSEC_MOBIKE
      /* Mobike cannot be enabled with IKEv1. */
      if (tunnel->flags & SSH_PM_T_MOBIKE)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Mobike cannot be enabled in IKEv1 tunnel"));
          return FALSE;
        }
#endif /* SSHDIST_IPSEC_MOBIKE */
      if ((tunnel->pm->params.enable_key_restrictions &
           SSH_PM_PARAM_ALGORITHMS_NIST_800_131A) != 0)
        {
          if ((tunnel->u.ike.algorithms &
              (SSH_PM_MAC_HMAC_MD5 | SSH_PM_MAC_HMAC_SHA1)) != 0)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Specified algorithm that is not "
                                      "allowed by used key restrictions."));
              return FALSE;
            }
        }
    }

  tunnel->u.ike.versions = versions;
  return TRUE;
}
#endif /* SSHDIST_IKEV1 */

static Boolean
ssh_pm_tunnel_set_identity_internal(SshPmTunnel tunnel,
                                    Boolean local,
                                    SshUInt32 flags,
                                    SshPmIdentityType id_type,
                                    SshPmSecretEncoding id_encoding,
                                    const unsigned char *identity,
                                    size_t identity_len,
                                    SshUInt32 order)
{
  SshIkev2PayloadID ike_id = NULL;
  Boolean malformed;
  unsigned char *idp = NULL;
  size_t idp_len;

  SSH_ASSERT(tunnel->refcount == 1);

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (order > 2)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Only two authentication rounds supported, unable to "
                    "set identity for authentication round %d", order);
      return FALSE;
    }
  if (order == 2 && (flags & SSH_PM_TUNNEL_IDENTITY_ENFORCE))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Unable to enforce identity for second authentication "
                    "round");
      return FALSE;
    }
#else /* SSH_IKEV2_MULTIPLE_AUTH */
  if (order != 1)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Invalid identity order, only one authentication "
                    "allowed and order should be '1'");
      return FALSE;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if ((identity == NULL || identity_len == 0) && !local)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "No tunnel identity specified");
      return FALSE;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("adding%sIKE %s identity %s, type %d to tunnel %s",
             (order == 2) ? " second " : " ",
             local ? "local": "remote" ,
             identity, id_type,
             tunnel->tunnel_name));

  if (local &&
      (order == 1) &&
      tunnel->local_identity)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot add more than one local identity to a tunnel %s",
                    tunnel->tunnel_name);
      return FALSE;
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if ((order == 2) && tunnel->second_local_identity)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot add more than one second local identity to a "
                    "tunnel %s",
                    tunnel->tunnel_name);
      return FALSE;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  if (!local && tunnel->remote_identity)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot add more than one remote identity to a tunnel %s",
                    tunnel->tunnel_name);
      return FALSE;
    }

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return FALSE;
    }
  tunnel->ike_tn = 1;

  if (identity == NULL || identity_len == 0)
    {
      SSH_ASSERT(local == TRUE);
      SSH_DEBUG(SSH_D_MIDOK, ("Setting identity type of %d to the tunnel",
                              id_type));
#ifdef SSH_IKEV2_MULTIPLE_AUTH
      if (order == 2)
        tunnel->second_id_type = id_type;
      else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
        tunnel->id_type = id_type;
      return TRUE;
    }

  if ((idp =
       ssh_pm_decode_secret(id_encoding,
                            identity, identity_len,
                            &idp_len,
                            &malformed)) == NULL)
    {
      if (malformed)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed encoding on IKE identity for tunnel %s",
                      tunnel->tunnel_name);
      goto error;
    }

  /* Decode identity if it is specified. */
  ike_id = ssh_pm_decode_identity(id_type, idp, idp_len, &malformed);
  ssh_free(idp);

  if (ike_id == NULL)
    {
      if (malformed)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed IKE identity for tunnel %s",
                      tunnel->tunnel_name);
      goto error;
    }

  if (local && (order == 1))
    {
      ssh_pm_ikev2_payload_id_free(tunnel->local_identity);
      tunnel->local_identity = ike_id;
    }
#ifdef SSH_IKEV2_MULTIPLE_AUTH
  else if (order == 2)
    {
      ssh_pm_ikev2_payload_id_free(tunnel->second_local_identity);
      tunnel->second_local_identity = ike_id;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
  else
    {
      ssh_pm_ikev2_payload_id_free(tunnel->remote_identity);
      tunnel->remote_identity = ike_id;
    }

  if (flags & SSH_PM_TUNNEL_IDENTITY_ENFORCE)
    {
      if (local)
        tunnel->enforce_local_id = 1;
      else
        tunnel->enforce_remote_id = 1;
    }
  return TRUE;


  /* Error handling. */

 error:
  ssh_pm_ikev2_payload_id_free(ike_id);
  return FALSE;
}

Boolean ssh_pm_tunnel_set_local_identity(SshPmTunnel tunnel,
                                         SshUInt32 flags,
                                         SshPmIdentityType id_type,
                                         SshPmSecretEncoding id_encoding,
                                         const unsigned char *identity,
                                         size_t identity_len,
                                         SshUInt32 order)
{
  return ssh_pm_tunnel_set_identity_internal(tunnel,
                                             TRUE,
                                             flags,
                                             id_type,
                                             id_encoding,
                                             identity,
                                             identity_len,
                                             order);
}

Boolean ssh_pm_tunnel_set_remote_identity(SshPmTunnel tunnel,
                                          SshUInt32 flags,
                                          SshPmIdentityType id_type,
                                          SshPmSecretEncoding id_encoding,
                                          const unsigned char *identity,
                                          size_t identity_len)
{
  return ssh_pm_tunnel_set_identity_internal(tunnel,
                                             FALSE,
                                             flags,
                                             id_type,
                                             id_encoding,
                                             identity,
                                             identity_len,
                                             1);
}

Boolean
ssh_pm_tunnel_set_auth_domain(SshPmTunnel tunnel,
                              char *auth_domain_name,
                              SshUInt32 order)
{
  SshPmAuthDomain ad;
  char *name_dup;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if ((order > 2) || (order == 0))
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Invalid authentication domain order %d", order);
      return FALSE;
    }
#else /* SSH_IKEV2_MULTIPLE_AUTH */
  if (order != 1)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Multiple authentications not supported, "
                    "order can be only '1'");
      return FALSE;
    }
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  if (tunnel == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "No tunnel specified");
      return FALSE;
    }

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return FALSE;
    }
  tunnel->ike_tn = 1;

  ad = ssh_pm_auth_domain_get_by_name(tunnel->pm,
                                      auth_domain_name);

  if (ad == NULL)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Invalid authentication domain name %s",
                    auth_domain_name);
      return FALSE;
    }

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  if (order == 2)
    {
      if (tunnel->second_auth_domain_name != NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Second authentication domain already "
                        "set for tunnel");
          return FALSE;
        }

      name_dup = ssh_memdup(auth_domain_name,
                            strlen(auth_domain_name));

      if (name_dup)
        tunnel->second_auth_domain_name = name_dup;
      else
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Out of memory while setting second "
                        "authentication domain");
          return FALSE;
        }
    }
  else
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
    {
      if (tunnel->auth_domain_name != NULL)
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Authentication domain already set for tunnel");
          return FALSE;
        }

      name_dup = ssh_memdup(auth_domain_name,
                            strlen(auth_domain_name));

      if (name_dup)
        tunnel->auth_domain_name = name_dup;
      else
        {
          ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                        "Out of memory while setting "
                        "authentication domain");
          return FALSE;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Setting authentication domain %s for tunnel %s with "
             "order %d",
             ad->auth_domain_name, tunnel->tunnel_name, order));

  return TRUE;
}

Boolean ssh_pm_tunnel_set_preshared_key(SshPmTunnel tunnel,
                                        SshUInt32 flags,
                                        SshPmSecretEncoding encoding,
                                        const unsigned char *secret,
                                        size_t secret_len,
                                        SshUInt32 order)
{
  SshPmPsk secrets;
  Boolean malformed;
  unsigned char *secret_copy;
  size_t copy_len;

  SSH_ASSERT(tunnel->refcount == 1);

  if (tunnel->manual_tn)
    {
      SSH_PM_TUNNEL_LOG_NEED_IKE();
      return FALSE;
    }
  tunnel->ike_tn = 1;

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("IKE secret (encoding %d)", encoding),
                    secret, secret_len);

  if (tunnel->u.ike.num_secrets)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot configure more than one secret for a tunnel");
      return FALSE;
    }

  /* Decode the IKE secret. */
  secret_copy = ssh_pm_decode_secret(encoding, secret, secret_len,
                                     &copy_len, &malformed);
  if (secret_copy == NULL)
    {
      if (malformed)
        ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                      "Malformed IKE secret for tunnel");
      else
        SSH_DEBUG(SSH_D_ERROR, ("Could not allocate IKE secret"));

      ssh_free(secret_copy);
      return FALSE;
    }

  secrets = ssh_calloc(1, sizeof(SshPmPskStruct));
  if (secrets == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not allocate memory for IKE secret"));
      ssh_free(secret_copy);
      return FALSE;
    }

  tunnel->u.ike.secrets = secrets;
  tunnel->u.ike.secrets[0].flags = flags;
  tunnel->u.ike.secrets[0].secret = secret_copy;
  tunnel->u.ike.secrets[0].secret_len = copy_len;
  tunnel->u.ike.num_secrets = 1;
  return TRUE;
}


Boolean
ssh_pm_tunnel_set_ike_window_size(SshPmTunnel tunnel, SshUInt32 window_size)
{
  if (window_size == 0 || window_size > PM_IKE_MAX_WINDOW_SIZE)
    {
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_ERROR,
                    "Cannot set IKE window size for this tunnel to 0 or "
                    "values larger than %d.",
                    PM_IKE_MAX_WINDOW_SIZE);
      return FALSE;
    }


  SSH_DEBUG(SSH_D_LOWOK, ("Setting tunnel IKE window size to %d (old %d)",
                          (int) window_size,
                          (int) tunnel->ike_window_size));

  tunnel->ike_window_size = window_size;
  return TRUE;
}
