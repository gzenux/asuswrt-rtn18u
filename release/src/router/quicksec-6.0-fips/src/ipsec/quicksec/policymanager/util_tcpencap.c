/**
   @copyright
   Copyright (c) 2007 - 2015, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmTcpEncaps"

#ifdef SSH_IPSEC_TCPENCAP

/*********************** IPsec over TCP Configuration ************************/

static Boolean
pm_tcp_encaps_add_configuration_internal(SshPm pm,
                                         SshIpAddr local_ip,
                                         SshUInt16 local_port,
                                         SshIpAddr peer_lo_addr,
                                         SshIpAddr peer_hi_addr,
                                         SshUInt16 peer_port,
                                         SshUInt16 local_ike_port)
{
  SshUInt32 port_index;
  SshIpAddrStruct peer_lo_ip, peer_hi_ip;

  SSH_ASSERT(local_ip != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(local_ip));

  /* Initialize peer address with match all range if not specified. */
  if (!SSH_IP_DEFINED(peer_lo_addr))
    {
      if (SSH_IP_IS6(local_ip))
        {
          ssh_ipaddr_parse(&peer_lo_ip, "::");
          ssh_ipaddr_parse(&peer_hi_ip,
                           "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
        }
      else
        {
          ssh_ipaddr_parse(&peer_lo_ip, "0.0.0.0");
          ssh_ipaddr_parse(&peer_hi_ip, "255.255.255.255");
        }
    }
  else if ((SSH_IP_IS6(peer_lo_addr) && !SSH_IP_IS6(local_ip))
           || (!SSH_IP_IS6(peer_lo_addr) && SSH_IP_IS6(local_ip)))
    {
      /* Skip */
      return TRUE;
    }
  else
    {
      peer_lo_ip = *peer_lo_addr;
      peer_hi_ip = *peer_hi_addr;
    }

  /* Add configuration entries for a single IKE port pair if local IKE port
     is specified, otherwise add entries for all port pairs. */
  for (port_index = 0; port_index < pm->params.num_ike_ports; port_index++)
    {
      if (local_ike_port == 0 ||
          pm->params.local_ike_ports[port_index] == local_port)
        {
          if (!ssh_pme_tcp_encaps_add_configuration(pm->engine, local_ip,
                                             local_port, &peer_lo_ip,
                                             &peer_hi_ip, peer_port,
                                             pm->params.
                                             local_ike_ports[port_index],
                                             pm->params.
                                             remote_ike_ports[port_index]))
            return FALSE;

          if (local_ike_port != 0)
            return TRUE;
        }
    }

  return TRUE;
}

Boolean
ssh_pm_tcp_encaps_add_configuration(SshPm pm,
                                    SshPmTunnel tunnel,
                                    SshIpAddr local_addr,
                                    SshUInt16 local_port,
                                    SshIpAddr peer_lo_addr,
                                    SshIpAddr peer_hi_addr,
                                    SshUInt16 peer_port,
                                    SshUInt16 local_ike_port)
{
  SshIpAddrStruct local_ip;

  /* Initiator configuration is stored in SshPmTunnel. */
  if (tunnel)
    {
      /* TCP encapsualtion must be configred only once. */
      if (tunnel->flags & SSH_PM_T_TCPENCAP)
        return FALSE;

      /* TCP encapsulation cannot be used with AH. */
      if (tunnel->transform & SSH_PM_IPSEC_AH)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Tcp encapsulation does not suport AH"));
          return FALSE;
        }

      /* Tunnel configuration is not allowed to include local and
         peer addresses. They are taken from tunnel. */
      if ((local_addr && SSH_IP_DEFINED(local_addr))
          || (peer_lo_addr && SSH_IP_DEFINED(peer_lo_addr))
          || (peer_hi_addr && SSH_IP_DEFINED(peer_hi_addr)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Addresses may not be specified."));
          return FALSE;
        }

      /* IKE port is taken from tunnel configuration. */
      if (local_ike_port != 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IKE port must not be specified."));
          return FALSE;
        }

      /* Atleast peer TCP port must be defined. */
      if (peer_port == 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Peer port must be specified."));
          return FALSE;
        }

      tunnel->tcp_encaps_config.local_port = local_port;
      tunnel->tcp_encaps_config.peer_port = peer_port;

      /* Enable TCP encapsulation for the tunnel. */
      tunnel->flags |= SSH_PM_T_TCPENCAP;

      return TRUE;
    }

  /* Global (responder) configuration is stored in engine. */

  /* Local address is optional.
     Sanity check local and peer address families. */
  if ((local_addr != NULL && SSH_IP_DEFINED(local_addr))
      && (peer_lo_addr != NULL && SSH_IP_DEFINED(peer_lo_addr))
      && ((SSH_IP_IS6(local_addr) && !SSH_IP_IS6(peer_lo_addr))
          || (!SSH_IP_IS6(local_addr) && SSH_IP_IS6(peer_lo_addr))))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Local and peer address family mismatch."));
      return FALSE;
    }

  /* Peer address is optional. Sanity check peer address range. */
  if (peer_lo_addr != NULL && SSH_IP_DEFINED(peer_lo_addr))
    {
      if (peer_hi_addr == NULL || !SSH_IP_DEFINED(peer_hi_addr))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid peer address range."));
          return FALSE;
        }

      if ((SSH_IP_IS6(peer_lo_addr) && !SSH_IP_IS6(peer_hi_addr))
          || (!SSH_IP_IS6(peer_lo_addr) && SSH_IP_IS6(peer_hi_addr)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Mismatching peer address range families."));
          return FALSE;
        }

      if (SSH_IP_CMP(peer_lo_addr, peer_hi_addr) > 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid peer address range."));
          return FALSE;
        }
    }

  /* Peer port is optional, local TCP port must be defined. */
  if (local_port == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Local port must be specified."));
      return FALSE;
    }

  /* Local address is undefined, add configuration entries
     for any local IPv4 and IPv6 address. */
  if (local_addr == NULL || !SSH_IP_DEFINED(local_addr))
    {
#if defined(WITH_IPV6)
      ssh_ipaddr_parse(&local_ip, SSH_IP6_NULLADDR);
      if (!pm_tcp_encaps_add_configuration_internal(pm, &local_ip, local_port,
                                                    peer_lo_addr, peer_hi_addr,
                                                    peer_port,
                                                    local_ike_port))
        return FALSE;
#endif /* WITH_IPV6 */

      ssh_ipaddr_parse(&local_ip, SSH_IP4_NULLADDR);
      return pm_tcp_encaps_add_configuration_internal(pm, &local_ip,
                                                      local_port, peer_lo_addr,
                                                      peer_hi_addr, peer_port,
                                                      local_ike_port);
    }

  /* Local address is specified. */
  else
    {
      return pm_tcp_encaps_add_configuration_internal(pm, local_addr,
                                                      local_port, peer_lo_addr,
                                                      peer_hi_addr, peer_port,
                                                      local_ike_port);
    }
  SSH_NOTREACHED;
}

#endif /* SSH_IPSEC_TCPENCAP */
