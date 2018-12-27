/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code in this file manipulates NAT domains and takes care of allocating
   NAT mappings (static or dynamic, port NAT or host NAT).  This file also
   implements the calls from the policy manager that are used to configure
   NAT domains.

   This code does not perform the actual NAT transformation.  That code
   is fully integrated into the flow processing fastpath.  The code in
   this file is only used when a new flow is created, not on a per-packet
   basis.  Flows must be created if NAT is used.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineNat"

#ifdef SSHDIST_IPSEC_NAT

/* Function for determining if a ip:port pair is registered */

static Boolean
ssh_engine_nat_is_registered(SshEngine engine,
                             const SshIpAddr nat_ip,
                             SshUInt32 port);









/* Specifies what kind of NAT, if any, is used for the given interface.
   This can be used to modify the setting later. */

void ssh_engine_pme_set_interface_nat(SshEngine engine,
                                      SshUInt32 ifnum,
                                      SshPmNatType type,
                                      SshPmNatFlags flags,
                                      const SshIpAddr host_nat_int_base,
                                      const SshIpAddr host_nat_ext_base,
                                      SshUInt32 host_nat_num_ips)
{
  SshInterceptorInterface *ifp;
  SshEngineIfInfo ifinfo;

  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);

  /* Make sure the interface number is correct. */
  if (ifp == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_ERROR, ("invalid interface number %d", (int)ifnum));
      return;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("setting ifnum %d NAT type to %d, flags=0x%02x",
             (int) ifnum, type, flags));

  /* Set the NAT type for the interface. */
  ifinfo = (SshEngineIfInfo) ifp->ctx_user;

  SSH_ASSERT (ifinfo != NULL);
  ifinfo->nat_type = type;
  ifinfo->nat_flags = flags;

  /* Store possible host nat internal address */
  if (host_nat_int_base)
    ifinfo->host_nat_int_base = *host_nat_int_base;
  else
    memset(&ifinfo->host_nat_int_base, 0,
           sizeof(ifinfo->host_nat_int_base));

  /* Store possible host nat external address */
  if (host_nat_ext_base)
    ifinfo->host_nat_ext_base = *host_nat_ext_base;
  else
    memset(&ifinfo->host_nat_ext_base, 0,
           sizeof(ifinfo->host_nat_ext_base));

  ifinfo->host_nat_num_ips = host_nat_num_ips;

  ssh_kernel_mutex_unlock(engine->interface_lock);
}

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/* Configures an IP address pool that is used in NAT-T internal NAT to
   make clients unique. */

void ssh_engine_pme_configure_internal_nat(SshEngine engine,
                                           const SshIpAddr first_ip,
                                           const SshIpAddr last_ip,
                                           SshPmeStatusCB callback,
                                           void *context)
{
  SshUInt32 first, last;

  if (!SSH_IP_DEFINED(first_ip) && !SSH_IP_DEFINED(last_ip))
    {
      first = 0;
      last = 0;
    }
  else
    {
      if (!SSH_IP_IS4(first_ip) || !SSH_IP_IS4(last_ip))
        goto error;

      first = SSH_IP4_TO_INT(first_ip);
      last = SSH_IP4_TO_INT(last_ip);

      if (first > last)
        goto error;
    }

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  engine->internal_nat_first_ip = first;
  engine->internal_nat_last_ip = last;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (callback)
    (*callback)(engine->pm, TRUE, context);

  return;

  /* Error handling. */

 error:

  if (callback)
    (*callback)(engine->pm, FALSE, context);
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */


/************** Dynamic Port NAT ********************************************/

/* Allocate a NAT mapping and return an index for it */

static SshUInt32 ssh_engine_hash_natport(const SshIpAddr ip,
                                         SshUInt16 port)
{
  unsigned char tmpbuf[16];
  size_t tmplen;
  SshUInt32 h;

  memset(tmpbuf,0,sizeof(tmpbuf));

  tmplen = sizeof(tmpbuf);
  SSH_IP_ENCODE(ip,tmpbuf,tmplen);

  tmpbuf[0] ^= tmpbuf[4] ^ tmpbuf[8] ^ tmpbuf[12] ^ ((port >> 8)&0xff);
  tmpbuf[1] ^= tmpbuf[5] ^ tmpbuf[9] ^ tmpbuf[13] ^ (port&0xff);
  tmpbuf[2] ^= tmpbuf[6] ^ tmpbuf[10] ^ tmpbuf[14] ^ ((port >>8)&0xff);
  tmpbuf[3] ^= tmpbuf[7] ^ tmpbuf[11] ^ tmpbuf[15] ^ (port&0xff);

  h = SSH_GET_32BIT(tmpbuf);

  return (h % SSH_ENGINE_FLOW_NAT_HASH_SIZE);
}

/* Check that address is of given type */
static Boolean
address_type_match_spec(const SshIpAddr addr,
                        Boolean is_ipv6,
                        Boolean ipv6_accept_link_local,
                        Boolean ipv6_accept_site_local)
{
  if (!addr)
    return FALSE;

  if (is_ipv6)
    {
      if (!SSH_IP_IS6(addr))
        return FALSE;

      if (SSH_IP6_IS_LINK_LOCAL(addr) && !ipv6_accept_link_local)
        return FALSE;

      if (SSH_IP6_IS_SITE_LOCAL(addr) && !ipv6_accept_site_local)
        return FALSE;
    }
  else
    return SSH_IP_IS4(addr);

  return TRUE; /* IPv6 address and of acceptable type. */
}

/* Fetch a IP address for interface with given address type.
   With IPv6 addresses it is possible to avoid link and/or site local
   addresses as well. */
static SshIpAddr
get_iface_address_with_hash(SshInterceptorInterface *iface,
                            SshUInt32 hash,
                            Boolean is_ipv6,
                            Boolean ipv6_accept_link_local,
                            Boolean ipv6_accept_site_local)
{
  SshUInt32 ip_index;
  SshIpAddr result;
  SshUInt32 num_addrs_type;
  int i;

  ip_index = ssh_rand() % iface->num_addrs;
  result = &(iface->addrs[ip_index].addr.ip.ip);

  /* If we immediately get proper address, then all is ok. */
  if (address_type_match_spec(result, is_ipv6, ipv6_accept_link_local,
                              ipv6_accept_site_local))
    return result;

  /* Address we got does not match the spec.
     We'll have to browse through interface addresses and check how many
     suitable addresses there is, and rehash only to set of addresses
     acceptable. */

  num_addrs_type = 0;
  for(i = 0; i < iface->num_addrs; i++)
    {
      if (address_type_match_spec(&(iface->addrs[i].addr.ip.ip),
                                  is_ipv6, ipv6_accept_link_local,
                                  ipv6_accept_site_local))
        num_addrs_type++;
    }

  if (num_addrs_type == 0)
    return NULL; /* No address of given type present. */

  ip_index = ssh_rand() % num_addrs_type;

  /* Pick (ip_index)th address that matches address spec. */
  for(i = 0; i < iface->num_addrs; i++)
    {
      result = &(iface->addrs[i].addr.ip.ip);
      if (address_type_match_spec(result, is_ipv6, ipv6_accept_link_local,
                                  ipv6_accept_site_local))
        {
          if (ip_index == 0)
            return result;
          else
            ip_index--;
        }
    }

  return NULL; /* Actually, this line should be unreachable. */
}

Boolean
ssh_engine_get_random_port(SshEngine engine,
                           Boolean get_free_port,
                           Boolean is_ipv6,
                           SshEngineIfnum ifnum,
                           const SshIpAddr ip_in,
                           const SshIpAddr ip_orig,
                           SshUInt16 port_in,
                           SshUInt16 port_orig,
                           const SshIpAddr ip_forbid,
                           SshUInt16 port_forbid,
                           SshIpAddr ip_return,
                           SshUInt16 *port_return)
{
  SshUInt32 tries;
  SshUInt16 port;
  SshUInt16 port_low;
  SshUInt16 port_range;
  SshIpAddr nat_ip;
  SshInterceptorInterface *iface;
  SshUInt32 tries_max;
  SshIpAddr ip = ip_in;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (ip == NULL)
    {
      /* Interface lock only required if ip is not given. */
      ssh_kernel_mutex_assert_is_locked(engine->interface_lock);
    }

#ifdef DEBUG_LIGHT
  if (ip != NULL)
    SSH_DEBUG(SSH_D_MY,
              ("ifnum=%d ip=%@ port=%u(%u)",
               (int) ifnum, ssh_ipaddr_render, ip, port_in,
               port_orig));
  else
    SSH_DEBUG(SSH_D_MY,
              ("ifnum=%d port=%u(%u)", (int) ifnum, port_in,
               port_orig));
#endif /* DEBUG_LIGHT */

  iface = NULL;

  if (ip == NULL)
    {
      iface = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
      if (iface == NULL)
        {
          return FALSE;
        }
      if (ip_orig)
        {
          SshUInt32 hash = SSH_IP_HASH(ip_orig);
          ip = get_iface_address_with_hash(iface, hash, is_ipv6, FALSE, FALSE);
        }
    }

  if (port_in == 0)
    {
      tries_max = 50;

      /* Choose whether to use range of unprivileged or
         privileged ports. */
      if (0 < port_orig && port_orig < 1024)
        {
          port_low = engine->nat_privileged_low_port;
          port_range = engine->nat_privileged_high_port -
                       engine->nat_privileged_low_port + 1;
        }
      else
        {
          port_low = engine->nat_normal_low_port;
          port_range = engine->nat_normal_high_port -
                       engine->nat_normal_low_port + 1;
        }
    }
  else
    {
      /* No randomization for port, pass in correct port
         with range of one port. */
      port_low = port_in;
      port_range = 1;

      if (ip == NULL)
        tries_max = 50;
      else
        tries_max = 1;
    }

  for (tries = 0; tries < tries_max; tries++)
    {
      /* Do we need to guarantee a uniform distribution here? */
      port = port_low;
      port += ssh_rand() % port_range;

      if (ip == NULL)
        {
          nat_ip = get_iface_address_with_hash(iface, ssh_rand(),
                                               is_ipv6, FALSE, FALSE);

          if (!nat_ip) return FALSE; /* No addr of suitable type available. */
        }
      else
        {
          nat_ip = ip;
        }

      /* Check whether this is a forbidden port. */
      if (ip_forbid != NULL && port_forbid != 0)
        {
          if (SSH_IP_EQUAL(ip_forbid, nat_ip) && port_forbid == port)
            continue;
        }

      /* Check whether this has been registered */
      if (get_free_port == TRUE
          && ssh_engine_nat_is_registered(engine, nat_ip, port) == TRUE)
        continue;

      /* Found an ipaddr:port which is not currently taken */
      if (ip_return)
        *ip_return = *nat_ip;
      if (port_return)
        *port_return = port;
      return TRUE;
    }
  return FALSE;
}

Boolean ssh_engine_nat_get_unused_map(SshEngine engine,
                                      Boolean is_ipv6,
                                      SshEngineIfnum src_ifnum,
                                      const SshIpAddr src_ip,
                                      const SshIpAddr src_ip_orig,
                                      SshUInt16 src_port,
                                      SshUInt16 src_port_orig,
                                      SshEngineIfnum dst_ifnum,
                                      const SshIpAddr dst_ip,
                                      SshUInt16 dst_port,
                                      SshIpAddr nat_src_ip_return,
                                      SshUInt16 *nat_src_port_return,
                                      SshIpAddr nat_dst_ip_return,
                                      SshUInt16 *nat_dst_port_return)
{
  SshIpAddrStruct nat_src_ip, nat_dst_ip;
  SshUInt16 nat_src_port, nat_dst_port;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);
  ssh_kernel_mutex_assert_is_locked(engine->interface_lock);

  memset(&nat_src_ip, 0, sizeof(nat_src_ip));
  memset(&nat_dst_ip, 0, sizeof(nat_dst_ip));
  nat_src_port = 0;
  nat_dst_port = 0;

  if (nat_src_ip_return != NULL || nat_src_port_return != NULL)
    {
      if (src_ip)
        nat_src_ip = *src_ip;
      nat_src_port = src_port;

      if (ssh_engine_get_random_port(engine, TRUE, is_ipv6, src_ifnum,
                                     src_ip, src_ip_orig,
                                     src_port,
                                     src_port_orig,
                                     NULL, 0,
                                     &nat_src_ip, &nat_src_port) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("failed to allocate NAT src map"));
          return FALSE;
        }
    }

  if (nat_dst_ip_return != NULL || nat_dst_port_return != NULL)
    {
      if (dst_ip)
        nat_dst_ip = *dst_ip;
      nat_dst_port = dst_port;

      if (ssh_engine_get_random_port(engine, TRUE, is_ipv6, dst_ifnum,
                                     dst_ip, dst_ip,
                                     dst_port, dst_port,
                                     &nat_src_ip, nat_src_port,
                                     &nat_dst_ip, &nat_dst_port) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("failed to allocate NAT dst map"));
          return FALSE;
        }
    }





  if (nat_src_ip_return != NULL)
    *nat_src_ip_return = nat_src_ip;
  if (nat_dst_ip_return != NULL)
    *nat_dst_ip_return = nat_dst_ip;
  if (nat_src_port_return != NULL)
    *nat_src_port_return = nat_src_port;
  if (nat_dst_port_return != NULL)
    *nat_dst_port_return = nat_dst_port;

#ifdef DEBUG_LIGHT
  if (src_ip)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("src nat: %@:%u -> %@:%u",
               ssh_ipaddr_render, src_ip, src_port,
               ssh_ipaddr_render, &nat_src_ip, nat_src_port));

  if (dst_ip)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("dst nat: %@:%u -> %@:%u",
               ssh_ipaddr_render, dst_ip, dst_port,
               ssh_ipaddr_render, &nat_dst_ip, nat_dst_port));

#endif /* DEBUG_LIGHT */
  return TRUE;
}

/* Helper function to combine nat flags from destination
   interface info and PacketContext (eg. from appgw settings) */
static SshPmNatFlags combine_nat_flags( SshUInt32 pc_flags,
                                        SshPmNatFlags nat_flags )
{
  if ((pc_flags & SSH_ENGINE_PC_NAT_KEEP_PORT))
    nat_flags |= SSH_PM_NAT_KEEP_PORT;

  if ((pc_flags & SSH_ENGINE_PC_NAT_SHARE_PORT))
    nat_flags |= SSH_PM_NAT_SHARE_PORT_SRC;

  return nat_flags;
}

SshUInt16
ssh_engine_nat_get_mapping(SshEngine engine,
                           SshUInt32 flags,
                           SshUInt8 ipproto,
                           SshUInt8 icmp_type,
                           Boolean outbound,
                           SshEngineIfnum ifnum_src,
                           SshEngineIfnum ifnum_dst,
                           const SshIpAddr src_ip,
                           const SshIpAddr dst_ip,
                           SshUInt16 src_port,
                           SshUInt16 dst_port,
                           SshIpAddr nat_src_ip_out,
                           SshUInt16 *nat_src_port_out,
                           SshIpAddr nat_dst_ip_out,
                           SshUInt16 *nat_dst_port_out)
{
  SshEngineIfInfo srcinfo, dstinfo;
  SshPmNatType type;
  SshIpAddrStruct nat_ip;
  SshUInt32 i;
  SshUInt16 pass_port;
  Boolean ok, is_ipv6;
  Boolean try_source;
  SshInterceptorInterface *ifp_dst, *ifp_src;

  if (src_ip == NULL || dst_ip == NULL)
    return 0xffff; /* Error */

  is_ipv6 = SSH_IP_IS6(src_ip);
  if (is_ipv6 != SSH_IP_IS6(dst_ip))
    return 0xffff; /* Error. */

  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Sanity check the interface numbers. */
  ifp_src = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum_src);
  ifp_dst = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum_dst);
  if (ifp_dst == NULL || ifp_src == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid ifnum_dst=%d ifnum_src=%d",
                             (int)ifnum_dst, (int)ifnum_src));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return 0xffff;
    }

  SSH_DEBUG(SSH_D_MY, ("flags=0x%08x ipproto=%d outbound=%d",
                       (unsigned int) flags, ipproto, outbound));

#ifdef DEBUG_LIGHT
  SSH_DEBUG(SSH_D_MY,
            ("ifnum_src=%u srcip=%@ srcport=%u",
             (unsigned int) ifnum_src,
             ssh_ipaddr_render, src_ip, src_port));

  SSH_DEBUG(SSH_D_MY,
            ("ifnum_dst=%u dstip=%@ dstport=%u",
             (unsigned int) ifnum_dst,
             ssh_ipaddr_render, dst_ip, dst_port));
#endif /* DEBUG_LIGHT */

  /* Get interface NAT information */
  srcinfo = (SshEngineIfInfo) ifp_src->ctx_user;
  dstinfo = (SshEngineIfInfo) ifp_dst->ctx_user;

  /* If the outbound flag is set, then NAT the source address
     as defined by the destination interface. If the outbound
     flag is clear, then NAT the destination address as
     defined by the source interface. */
  type = (outbound ? dstinfo->nat_type : srcinfo->nat_type);

  if (is_ipv6 &&
      ((outbound && !(dstinfo->nat_flags & SSH_PM_INTERFACE_NAT_IPV6)) ||
       (!outbound && !(srcinfo->nat_flags & SSH_PM_INTERFACE_NAT_IPV6))))
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_LOWOK, ("Not performing NAT for IPv6 addresses"));
      return 0;
    }

  if (type == SSH_PM_NAT_TYPE_NONE)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return 0;
    }

  /* We only handle TCP, UDP, and ICMP echo. */
  if (ipproto != SSH_IPPROTO_TCP
      && ipproto != SSH_IPPROTO_UDP
      && ipproto != SSH_IPPROTO_UDPLITE
      && ipproto != SSH_IPPROTO_ICMP
      && ipproto != SSH_IPPROTO_IPV6ICMP)
    {
      SSH_DEBUG(SSH_D_FAIL, ("NAT allocate failed for non TCP/UDP/ICMP"));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return 0xffff;
    }

  if (ipproto == SSH_IPPROTO_ICMP && icmp_type != SSH_ICMP_TYPE_ECHO)
    {
      SSH_DEBUG(SSH_D_FAIL, ("NAT allocate failed non-echo ICMP"));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return 0xffff;
    }
#if defined (WITH_IPV6)
  if (ipproto == SSH_IPPROTO_IPV6ICMP
      && icmp_type != SSH_ICMP6_TYPE_ECHOREQUEST)
    {
      SSH_DEBUG(SSH_D_FAIL, ("NAT allocate failed non-echo ICMPv6"));
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return 0xffff;
    }
#endif /* WITH_IPV6 */

  switch (type)
    {
      SshPmNatFlags nat_flags;
    case SSH_PM_NAT_TYPE_PORT:
      nat_flags = combine_nat_flags( flags, dstinfo->nat_flags );
      /* Do not port nat destination addresses except with static NAT */
      if (!outbound)
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          SSH_DEBUG(SSH_D_HIGHOK, ("Port NAT rejected inbound non-static"));
          return 0xffff; /* Error. */
        }
      /* Find a port:addr on the interface */
      pass_port = 0;
      if ((nat_flags & SSH_PM_NAT_KEEP_PORT))
        pass_port = src_port;

      try_source = !(nat_flags & SSH_PM_NAT_NO_TRY_KEEP_PORT);

      ok = FALSE;
      if (try_source)
        {
          Boolean reserve_port =
            !(nat_flags & SSH_PM_NAT_SHARE_PORT_SRC);

          ok = ssh_engine_get_random_port(engine, reserve_port,
                                          is_ipv6,
                                          ifnum_dst, NULL, src_ip,
                                          src_port, src_port,
                                          NULL, 0,
                                          nat_src_ip_out,
                                          nat_src_port_out);

        }
      /* Unique port not required.*/
      if (ok == FALSE &&
          (nat_flags & SSH_PM_NAT_SHARE_PORT_SRC))
        {
          ok = ssh_engine_get_random_port(engine, FALSE, is_ipv6,
                                          ifnum_dst, NULL, src_ip,
                                          pass_port, src_port,
                                          NULL, 0,
                                          nat_src_ip_out,
                                          nat_src_port_out);
        }
      else if (ok == FALSE)
        {
          ok = ssh_engine_nat_get_unused_map(engine, is_ipv6,
                                             ifnum_dst, NULL, src_ip,
                                             pass_port, src_port,
                                             0, NULL, 0,
                                             nat_src_ip_out,
                                             nat_src_port_out,
                                             NULL,
                                             NULL);
        }

      if (ok == FALSE)
        {
          ssh_kernel_mutex_unlock(engine->interface_lock);
          SSH_DEBUG(SSH_D_FAIL,
                    ("Allocation of NAT ip:port failed"));
          return 0xffff;
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);

#ifdef DEBUG_LIGHT
      if (nat_src_ip_out)
        SSH_DEBUG(SSH_D_NICETOKNOW,
                  ("allocated PORT NAT port %@:%u",
                   ssh_ipaddr_render, nat_src_ip_out,
                   *nat_src_port_out));
#endif /* DEBUG_LIGHT */
      return SSH_ENGINE_FLOW_D_NAT_SRC;
      break;

    case SSH_PM_NAT_TYPE_HOST_DIRECT:
      ssh_kernel_mutex_unlock(engine->interface_lock);
      if (outbound)
        { /* Source address can be NAT'd safely */
          i = ssh_engine_ipaddr_subtract(src_ip,
                                         &dstinfo->host_nat_int_base);

          if (i >= srcinfo->host_nat_num_ips)
            {
              SSH_DEBUG(SSH_D_FAIL, ("direct host NAT: not in range"));
              return 0xffff;
            }

          ssh_engine_ipaddr_add(&nat_ip, &dstinfo->host_nat_ext_base, i);

          if (nat_src_ip_out)
            *nat_src_ip_out = nat_ip;
          return SSH_ENGINE_FLOW_D_NAT_SRC;
        }
      /* Destination address can be NAT'd safely */
      i = ssh_engine_ipaddr_subtract(dst_ip,
                                     &srcinfo->host_nat_int_base);
      if (i >= srcinfo->host_nat_num_ips)
        {
          SSH_DEBUG(SSH_D_FAIL, ("direct host NAT: not in range"));
          return 0xffff;
        }
      ssh_engine_ipaddr_add(&nat_ip, &srcinfo->host_nat_ext_base, i);

      if (nat_dst_ip_out)
        *nat_dst_ip_out = nat_ip;

      return SSH_ENGINE_FLOW_D_NAT_DST;

    default:
      ssh_fatal("ssh_engine_nat_get_mapping: bad type %d", (int)type);
    }

  SSH_NOTREACHED;
  ssh_kernel_mutex_unlock(engine->interface_lock);
  return 0xffff;
}

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
Boolean ssh_engine_get_internal_nat_ip(SshEngine engine,
                                       SshIpAddr ip_return)
{
  SshUInt32 tries;
  SshUInt32 ip_int;
  SshIpAddrStruct ip;

  if (engine->internal_nat_first_ip == 0)
    return FALSE;

  for (tries = 0; tries < 50; tries++)
    {
      ip_int = engine->internal_nat_first_ip;
      ip_int += ssh_rand() % (engine->internal_nat_last_ip
                              - engine->internal_nat_first_ip + 1);
      SSH_INT_TO_IP4(&ip, ip_int);
      if (!ssh_engine_nat_is_registered(engine, &ip, 0))
        {
          /* This IP is free. */
          *ip_return = ip;
          return TRUE;
        }
    }

  /* No luck. */
  return FALSE;
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

static Boolean
ssh_engine_nat_is_registered(SshEngine engine,
                             const SshIpAddr nat_ip, SshUInt32 nat_port)
{
  SshEngineNatPort port;
  SshUInt32 hash;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Checking if the NAT port %@:%u is registered",
                               ssh_ipaddr_render, nat_ip,
                               (unsigned int) nat_port));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  hash = ssh_engine_hash_natport(nat_ip, (SshUInt16) nat_port);

  /* Check if port:ip is currently reserved */
  port = engine->nat_ports_hash[hash];
  while (port != NULL)
    {
      if (SSH_IP_EQUAL(&port->nat_ip, nat_ip) && nat_port == port->nat_port)
        break;
      port = port->next;
    }

  if (port != NULL)
    return TRUE;

  return FALSE;
}

void
ssh_engine_nat_unregister_port(SshEngine engine,
                               const SshIpAddr nat_ip, SshUInt16 nat_port)
{
  SshUInt32 hash;
  SshEngineNatPort curr, prev = NULL;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Unregistering NAT port %@:%u",
                               ssh_ipaddr_render, nat_ip, nat_port));

  if (SSH_IP_DEFINED(nat_ip))
    {
      hash = ssh_engine_hash_natport(nat_ip, nat_port);

      curr = engine->nat_ports_hash[hash];
      while (curr != NULL)
        {
          if (SSH_IP_EQUAL(&curr->nat_ip, nat_ip) &&
              curr->nat_port == nat_port)
            {
              SSH_IP_UNDEFINE(&curr->nat_ip);
              if (prev)
                prev->next = curr->next;
              else
                engine->nat_ports_hash[hash] = curr->next;

              curr->next = engine->nat_port_freelist;
              engine->nat_port_freelist = curr;
              return;
            }
          prev = curr;
          curr = curr->next;
        }
      SSH_DEBUG(SSH_D_MIDOK, ("No NAT port registered for %@:%u",
                              ssh_ipaddr_render, nat_ip, nat_port));
    }
}

void
ssh_engine_nat_unregister_ports(SshEngine engine,
                                const SshIpAddr nat_ip_low,
                                const SshIpAddr nat_ip_high,
                                SshUInt16 nat_port)
{
  SshIpAddrStruct ip_current;

  /* Test that there is something to register. */
  if (!SSH_IP_DEFINED(nat_ip_low)) return;

  /* Prevent very long loop on wrong arguments */
  SSH_VERIFY(SSH_IP_CMP(nat_ip_low,nat_ip_high) <= 0);
  ip_current = *nat_ip_low;
  for(;;)
    {
      /* Unregister one port at a time. */
      ssh_engine_nat_unregister_port(engine,&ip_current,
                                     nat_port);

      /* Test if we're done. */
      if (!SSH_IP_CMP(&ip_current, nat_ip_high)) break;
      ssh_ipaddr_increment(&ip_current);
    }
}

Boolean
ssh_engine_nat_register_ports(SshEngine engine,
                              const SshIpAddr nat_ip_low,
                              const SshIpAddr nat_ip_high,
                              SshUInt16 nat_port)
{
  SshIpAddrStruct ip_current;
  Boolean result;
  Boolean register_done = FALSE;

  /* Test that there is something to register. */
  if (!SSH_IP_DEFINED(nat_ip_low)) return TRUE;

  /* Prevent long loop on wrong arguments */
  SSH_VERIFY(SSH_IP_CMP(nat_ip_low,nat_ip_high) <= 0);
  ip_current = *nat_ip_low;
  for(;;)
    {
      /* Unregister one port at a time. */
      result = ssh_engine_nat_register_port(engine,&ip_current,
                                            nat_port);

      if (result == FALSE)
        {
          if (register_done)
            {
              /* Undo already done registrations. */
              ssh_ipaddr_decrement(&ip_current);
              ssh_engine_nat_unregister_ports(engine,
                                              nat_ip_low,
                                              &ip_current,
                                              nat_port);
            }
          break;
        }
      else
        register_done = TRUE;

      /* Test if we're done. */
      if (!SSH_IP_CMP(&ip_current, nat_ip_high)) break;
      ssh_ipaddr_increment(&ip_current);
    }

  return result;
}

Boolean
ssh_engine_nat_register_port(SshEngine engine,
                             const SshIpAddr nat_ip, SshUInt16 nat_port)
{
  SshEngineNatPort port;
  SshUInt32 hash;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (SSH_IP_DEFINED(nat_ip))
    {
      port = engine->nat_port_freelist;
      if (port == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Out of port NAT contexts"));
          return FALSE;
        }
      engine->nat_port_freelist = port->next;

      port->nat_ip = *nat_ip;
      port->nat_port = nat_port;

      hash = ssh_engine_hash_natport(nat_ip, nat_port);

      port->next = engine->nat_ports_hash[hash];
      engine->nat_ports_hash[hash] = port;

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Registering NAT port %@:%u",
                                   ssh_ipaddr_render, &port->nat_ip,
                                   port->nat_port));

    }
  return TRUE;
}
#endif /* SSHDIST_IPSEC_NAT */
