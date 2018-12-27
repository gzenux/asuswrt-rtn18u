/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Routing functionality for the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineRoute"



#ifndef SSH_IPSEC_INTERNAL_ROUTING
/* Internal context data structure that is used to pass certain needed
   data from ssh_engine_route to ssh_engine_route_cb when system
   routing tables are used. */
typedef struct SshEngineRouteCtxRec
{
  SshIpAddrStruct dst;
  SshEngine engine;
  SshEngineRouteCB callback;
  void *context;
} *SshEngineRouteCtx;

/* (internal function) Callback function that gets called when the
   routing operation using system routing tables completes. */

void ssh_engine_route_cb(Boolean reachable,
                         SshIpAddr next_hop_gw,
                         SshEngineIfnum ifnum,
                         SshVriId routing_instance_id,
                         size_t mtu,
                         void *context)
{
  SshEngineRouteCtx c = (SshEngineRouteCtx)context;
  SshEngine engine = c->engine;
  SshIpAddrStruct dst = c->dst;
  SshEngineRouteCB callback = c->callback;
  void *cb_context = c->context;

  SSH_INTERCEPTOR_STACK_MARK();

  /* Free the context and decrement the number of active lookups.  Note
     that we have already copied relevant data from the context to our
     own structures. */
  ssh_free(c);
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  SSH_ASSERT(engine->num_active_route_lookups > 0);
  engine->num_active_route_lookups--;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (reachable)
    (*callback)(engine, SSH_PME_ROUTE_REACHABLE,
                &dst, next_hop_gw, ifnum, routing_instance_id, mtu,
                cb_context);
  else
    (*callback)(engine, 0, &dst, NULL, 0, -1, 0, cb_context);
}
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

/* Simple utility function for fetching the MTU of an interface number */

static size_t
ssh_engine_route_get_mtu(SshEngine engine, SshEngineIfnum ifnum,
                         Boolean is_outgoing, Boolean is_ipv4)
{
  SshInterceptorInterface *ifp;
  size_t mtu = 0;

  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);

  if (ifp != NULL)
    {
      if (is_outgoing)
        mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter, !is_ipv4);
      else
        mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_protocol, !is_ipv4);
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);

  return mtu;
}


/* Fills in the SshInterceptorRouteKey `key' from the `pc'. */

void ssh_engine_create_route_key(SshEngine engine,
                                 SshInterceptorRouteKey key,
                                 SshEnginePacketContext pc,
                                 SshIpAddr src,
                                 SshIpAddr dst,
                                 SshUInt8 ipproto,
                                 SshUInt16 src_port,
                                 SshUInt16 dst_port,
                                 SshUInt32 spi,
                                 SshEngineIfnum ifnum,
                                 SshUInt32 route_flags,
                                 SshUInt32 *extension,
                                 SshVriId routing_instance_id)
{
  Boolean set_src, replace_src_with_local;
  SshInterceptorProtocol protocol;




  /* Assert that destination is valid. */
  SSH_ASSERT(dst != NULL);
  SSH_ASSERT(SSH_IP_DEFINED(dst));

  /* Initialize key and set destination address selector */
  SSH_INTERCEPTOR_ROUTE_KEY_INIT(key);

  if (SSH_IP_IS4(dst))
    protocol = SSH_PROTOCOL_IP4;
#ifdef WITH_IPV6
  else if (SSH_IP_IS6(dst))
    protocol = SSH_PROTOCOL_IP6;
#endif /* WITH_IPV6 */
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("Invalid destination %@",
                              ssh_ipaddr_render, dst));
      SSH_NOTREACHED;
      return;
    }

  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Check destination address */



  SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(key, dst);
  if (ssh_ip_get_interface_by_ip(&engine->ifs, dst, routing_instance_id))
    key->selector |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_DST;

  /* Check source address */
  set_src = TRUE;
  replace_src_with_local = FALSE;
  if (src == NULL || !SSH_IP_DEFINED(src))
    {
      set_src = FALSE;
    }
  else if (SSH_IP_IS_BROADCAST(src)
           || SSH_IP_IS_MULTICAST(src)
           || ssh_ip_get_interface_by_broadcast(&engine->ifs, src,
                                                routing_instance_id))
    {
      replace_src_with_local = TRUE;
    }
  else if (ssh_ip_get_interface_by_ip(&engine->ifs, src, routing_instance_id))
    {
      key->selector |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_SRC;
    }

  /* Always set routing instance id */
  SSH_INTERCEPTOR_ROUTE_KEY_SET_RIID(key, routing_instance_id);

  /* Set source address selector */
  if (set_src)
    {
      if (replace_src_with_local)
        {
          SshIpAddrStruct local_ip;

          if (ifnum != SSH_INTERCEPTOR_INVALID_IFNUM
              && (ssh_engine_get_ipaddr(engine, ifnum, protocol, dst,
                                        &local_ip)
                  || ssh_engine_get_ipaddr(engine, ifnum, protocol, NULL,
                                           &local_ip)))
            {
              SSH_INTERCEPTOR_ROUTE_KEY_SET_SRC(key, &local_ip);
              key->selector |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_LOCAL_SRC;
            }
          else
            {
              /* We might end up here, if the interface has just been
                 brought up, but no addresses have been configured to it.
                 In such case, we leave the source address unspecified. */
              SSH_DEBUG(SSH_D_UNCOMMON,
                        ("Unable to fetch local address for ifnum %d "
                         "protocol %d",
                         (int) ifnum, protocol));
            }
        }
      else
        {
          SSH_INTERCEPTOR_ROUTE_KEY_SET_SRC(key, src);
        }
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Set inbound / outbound interface selector */
  if (ifnum != SSH_INTERCEPTOR_INVALID_IFNUM)
    {













      if (route_flags & SSH_INTERCEPTOR_ROUTE_KEY_OUT_IFNUM)
        SSH_INTERCEPTOR_ROUTE_KEY_SET_OUT_IFNUM(key, ifnum);
      else
        SSH_INTERCEPTOR_ROUTE_KEY_SET_IN_IFNUM(key, ifnum);
    }

  /* Set IP protocol selector */
  SSH_INTERCEPTOR_ROUTE_KEY_SET_IPPROTO(key, ipproto);

  /* Set IPv4 TOS */
  if (protocol == SSH_PROTOCOL_IP4)
    {
      SSH_INTERCEPTOR_ROUTE_KEY_SET_IP4_TOS(key, pc->u.rule.tos);
    }
#if defined(WITH_IPV6)
  /* Set IPv6 priority and flowlabel */
  else if (protocol == SSH_PROTOCOL_IP6)
    {
      SSH_INTERCEPTOR_ROUTE_KEY_SET_IP6_PRIORITY(key, pc->u.rule.tos);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_IP6_FLOW(key, pc->audit.flowlabel);
    }
#endif /* WITH_IPV6 */
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("protocol %d", protocol));
      SSH_NOTREACHED;
    }

  /* Set transport layer selectors */
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_SCTP:
      SSH_INTERCEPTOR_ROUTE_KEY_SET_SRC_PORT(key, src_port);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_DST_PORT(key, dst_port);
      break;

    case SSH_IPPROTO_ICMP:
      SSH_INTERCEPTOR_ROUTE_KEY_SET_ICMP_TYPE(key, pc->icmp_type);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_ICMP_CODE(key, pc->u.rule.icmp_code);
      break;

    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
      SSH_INTERCEPTOR_ROUTE_KEY_SET_IPSEC_SPI(key, spi);
      break;
    }

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Set extension selectors */
  SSH_INTERCEPTOR_ROUTE_KEY_SET_EXTENSION(key, extension);
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  if (route_flags & SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED)
    key->selector |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED;




  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("route key: selector 0x%04x routing instance %d "
             "dst %@ src %@ ifnum %d ipproto %d "
             "ipv4 tos 0x%02x "
             "ipv6 prio 0x%02x flowlabel 0x%08lx "
             "tcp dst_port %d src_port %d "
             "icmp type %d code %d "
             "ipsec spi 0x%08lx %s",
             key->selector, routing_instance_id,
             ssh_ipaddr_render, &key->dst,
             ssh_ipaddr_render,
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC) ?
              &key->src : NULL),
             (int)
             ((key->selector & (SSH_INTERCEPTOR_ROUTE_KEY_IN_IFNUM |
                                 SSH_INTERCEPTOR_ROUTE_KEY_OUT_IFNUM)) ?
               key->ifnum : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IPPROTO) ?
              key->ipproto : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IP4_TOS) ?
              key->nh.ip4.tos : 0),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IP6_PRIORITY) ?
              key->nh.ip6.priority : 0),
             (unsigned long)
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IP6_FLOW) ?
              key->nh.ip6.flow : 0),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_TCP_DST_PORT) ?
              key->th.tcp.dst_port : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_TCP_SRC_PORT) ?
              key->th.tcp.src_port : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_ICMP_TYPE) ?
              key->th.icmp.type : -1),
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_ICMP_CODE) ?
              key->th.icmp.code : -1),
             (unsigned long)
             ((key->selector & SSH_INTERCEPTOR_ROUTE_KEY_IPSEC_SPI) ?
              key->th.ipsec.spi : 0),
             ((route_flags & SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED)
              ? "transform applied" : "")));
}

/* Performs routing for the given routing key `key'.  This calls `callback'
   either during this call or at some later time.  The results of the
   route lookup are passed to the callback.  It is guaranteed that this
   handles local interface addresses, directed broadcasts, and hosts on
   local subnets correctly (setting the appropriate flag bits).  Other hosts
   are routed according to the routing information, either in the engine
   internal routing tables (if SSH_IPSEC_INTERNAL_ROUTING is defined) or
   (otherwise) in system tables. */

void ssh_engine_route(SshEngine engine,
                      SshUInt32 flags,
                      SshInterceptorRouteKey key,
                      Boolean outgoing,
                      SshEngineRouteCB callback,
                      void *context)
{
  SshInterceptorInterface *ifp;
  size_t mtu;
  SshEngineIfnum packet_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  SshIpAddr best_route = NULL;
  SshEngineIfnum best_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
  SshInt32 i, best_bits;
  SshEngineRoute route;
#else /* SSH_IPSEC_INTERNAL_ROUTING */
  SshEngineRouteCtx c;
  SshUInt32 num_lookups;
#endif /* SSH_IPSEC_INTERNAL_ROUTING */
  Boolean dst_is_ipv4 = SSH_IP_IS4(&key->dst);

  SSH_INTERCEPTOR_STACK_MARK();

  /* It is a fatal error to call ssh_interceptor_route with
     a routing key that does not specify the destination address. */
  SSH_ASSERT(SSH_IP_DEFINED(&key->dst));

  if (key->selector &
      (SSH_INTERCEPTOR_ROUTE_KEY_IN_IFNUM |
       SSH_INTERCEPTOR_ROUTE_KEY_OUT_IFNUM))
    packet_ifnum = key->ifnum;

  /* Check if interceptor route operation should be performed. */
  if (flags & SSH_PME_ROUTE_F_SYSTEM)
    goto do_route;





  /* Check if it is an IPv4 broadcast address. */
  if (SSH_IP_IS_BROADCAST(&key->dst))
    {
      /* Ifnum must be defined for broadcast destinations. */
      if (packet_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
        {
          (*callback)(engine, 0, &key->dst, NULL, 0, -1, 0, context);
          return;
        }

      /* ssh_engine_route_get_mtu() grabs a lock for a short-while,
         which is the reason why it is not called directly at the
         top-level. The intention is to avoid an unnecessary grab
         of the lock. */
      mtu = ssh_engine_route_get_mtu(engine, packet_ifnum,
                                     outgoing, dst_is_ipv4);

      if (outgoing)
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE | SSH_PME_ROUTE_LINKBROADCAST,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      else
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE | SSH_PME_ROUTE_LOCAL |
                    SSH_PME_ROUTE_LINKBROADCAST,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      return;
    }

  /* Check if it is an IPv6 link-local address. */
  if (SSH_IP6_IS_LINK_LOCAL(&key->dst))
    {
      /* Resolve ifnum if source address selector is defined. */
      if (key->selector & SSH_INTERCEPTOR_ROUTE_KEY_SRC)
        {
          ssh_kernel_mutex_lock(engine->interface_lock);

          ifp = ssh_ip_get_interface_by_ip(&engine->ifs, &key->src,
                                           key->routing_instance_id);
          if (ifp)
            {
              packet_ifnum = ifp->ifnum;
              SSH_INTERCEPTOR_ROUTE_KEY_SET_OUT_IFNUM(key, packet_ifnum);
            }
          ssh_kernel_mutex_unlock(engine->interface_lock);
        }

      /* Ifnum must be defined for link-local destinations. */
      if (packet_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
        {
          (*callback)(engine, 0, &key->dst, NULL, 0, -1, 0, context);
          return;
        }

      mtu = ssh_engine_route_get_mtu(engine, packet_ifnum,
                                     outgoing, dst_is_ipv4);

      if (outgoing)
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      else
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE | SSH_PME_ROUTE_LOCAL,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      return;
    }

  /* Check if it is the null-address. */
  if (SSH_IP_IS_NULLADDR(&key->dst))
    {
      /* Ifnum must be defined for the undefined destination. */
      if (packet_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
        {
          (*callback)(engine, 0, &key->dst, NULL, 0, -1, 0, context);
          return;
        }

      mtu = ssh_engine_route_get_mtu(engine, packet_ifnum,
                                     outgoing, dst_is_ipv4);

      if (outgoing)
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      else
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE | SSH_PME_ROUTE_LOCAL,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      return;
    }

  /* Handle multicast addresses. */
  if (
#ifdef SSH_IPSEC_MULTICAST
      /* Do this only when a valid ifnum is given, otherwise let us
         look into system route table to look for destination ifnum
         for multicast destination ip. */
      packet_ifnum != SSH_INTERCEPTOR_INVALID_IFNUM &&
#endif /*SSH_IPSEC_MULTICAST */
      SSH_IP_IS_MULTICAST(&key->dst))
    {
      /* Ifnum must be defined for multicast destinations. */
      if (packet_ifnum == SSH_INTERCEPTOR_INVALID_IFNUM)
        {
          (*callback)(engine, 0, &key->dst, NULL, 0, -1, 0, context);
          return;
        }

      mtu = ssh_engine_route_get_mtu(engine, packet_ifnum,
                                     outgoing, dst_is_ipv4);

      if (outgoing)
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      else
        (*callback)(engine,
                    SSH_PME_ROUTE_REACHABLE | SSH_PME_ROUTE_LOCAL,
                    &key->dst, &key->dst, packet_ifnum,
                    key->routing_instance_id, mtu, context);
      return;
    }

  /* Check if it is going to one of our own IP addresses (i.e., a local
     address). */
  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp = ssh_ip_get_interface_by_ip(&engine->ifs, &key->dst,
                                   key->routing_instance_id);
  if (ifp != NULL)
    {
      /* The packet is destined to one of our own interfaces. */
      mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter, !dst_is_ipv4);

      ssh_kernel_mutex_unlock(engine->interface_lock);
      (*callback)(engine,
                  SSH_PME_ROUTE_REACHABLE |
                  SSH_PME_ROUTE_LOCAL,
                  &key->dst, &key->dst, ifp->ifnum,
                  key->routing_instance_id, mtu, context);
      return;
    }

  ifp = ssh_ip_get_interface_by_broadcast(&engine->ifs, &key->dst,
                                          key->routing_instance_id);
  if (ifp != NULL)
    {
      /* The packet is a directed broadcast to local network. */
      mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter, !dst_is_ipv4);

      ssh_kernel_mutex_unlock(engine->interface_lock);

      (*callback)(engine,
                  SSH_PME_ROUTE_REACHABLE
                  | SSH_PME_ROUTE_LINKBROADCAST
                  | (outgoing ? 0 : SSH_PME_ROUTE_LOCAL),
                  &key->dst, &key->dst, ifp->ifnum,
                  key->routing_instance_id, mtu, context);
      return;
    }


  if (engine->optimize_routing)
    {
      ifp = ssh_ip_get_interface_by_subnet(&engine->ifs, &key->dst,
                                           key->routing_instance_id);
      if (ifp != NULL)
        {
          mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter, !dst_is_ipv4);

          ssh_kernel_mutex_unlock(engine->interface_lock);
          (*callback)(engine,
                      SSH_PME_ROUTE_REACHABLE,
                      &key->dst, &key->dst, ifp->ifnum,
                      key->routing_instance_id, mtu, context);
          return;
        }
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* It is not one of our addresses.  Check if we had it on one of our local
     networks. */
 do_route:
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Consult the system routing table. */
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  /* See if we have a route configured for the destination in the engine. */
  best_bits = -1;
  for (i = 0; i < SSH_ENGINE_ROUTE_TABLE_SIZE; i++)
    {
      route = &engine->route_table[i];
      if (!(route->flags & SSH_PME_ROUTE_REACHABLE))
        continue;
      if ((SshInt32)SSH_IP_MASK_LEN(&route->dst_and_mask) < best_bits)
        continue;
      if (!SSH_IP_MASK_EQUAL(&key->dst, &route->dst_and_mask))
        continue;
      best_route = &route->next_hop;
      best_ifnum = route->ifnum;
      best_bits = SSH_IP_MASK_LEN(&route->dst_and_mask);
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (best_bits >= 0)
    {
#if 0
      SSH_ASSERT(best_ifnum < engine->nifs);
#endif
      ssh_kernel_mutex_lock(engine->interface_lock);
      ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, best_ifnum);
      if (ifp != NULL)
        {
          mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter, !dst_is_ipv4);

          ssh_kernel_mutex_unlock(engine->interface_lock);
          (*callback)(engine,
                      SSH_PME_ROUTE_REACHABLE,
                      &key->dst, best_route, best_ifnum,
                      key->routing_instance_id, mtu, context);
          return;
        }
      ssh_kernel_mutex_unlock(engine->interface_lock);
    }
  /* We had no route for the destination. */
  (*callback)(engine, 0, &key->dst, NULL, 0, -1, 0, context);
#else /* SSH_IPSEC_INTERNAL_ROUTING */
  /* Perform route lookup for dst.  Currently we always use the asynchronous
     routing interface provided by the interceptor. */
  num_lookups = engine->num_active_route_lookups;
  if (num_lookups < SSH_ENGINE_MAX_ACTIVE_ROUTE_LOOKUPS)
    engine->num_active_route_lookups++;

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (num_lookups >= SSH_ENGINE_MAX_ACTIVE_ROUTE_LOOKUPS)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Too many route lookups in progress"));
      c = NULL;
    }
  else
    c = ssh_malloc(sizeof(*c));
  if (c == NULL)
    {
      (*callback)(engine, 0, &key->dst, NULL, 0, -1, 0, context);
      return;
    }
  c->dst = key->dst;
  c->engine = engine;
  c->callback = callback;
  c->context = context;

  ssh_interceptor_route(engine->interceptor, key,
                        ssh_engine_route_cb, (void *)c);

#endif /* SSH_IPSEC_INTERNAL_ROUTING */
}

#ifdef SSH_IPSEC_INTERNAL_ROUTING
/* Adds a new route to the engine internal routing table.  The route does
   not automatically get added to system routing tables.  If a route already
   exists for the same `dst_and_mask', then the new route overrides the
   old route.  This returns TRUE if the route was successfully added, and
   FALSE if it could not be added (e.g., routing table full). */

Boolean ssh_engine_route_add(SshEngine engine,
                             const SshIpAddr dst_and_mask,
                             const SshIpAddr next_hop,
                             SshUInt32 ifnum)
{
  SshEngineRoute route;
  SshUInt32 i;

  /* Remove any old route for the same destination and mask. */
  ssh_engine_route_remove(engine, dst_and_mask);

  /* Find an empty slot from the routing table. */
  route = NULL;
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (i = 0; i < SSH_ENGINE_ROUTE_TABLE_SIZE; i++)
    {
      route = &engine->route_table[i];
      if (route->flags == 0)
        break;
    }
  /* If we had no available slots, fail. */
  if (!route)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return FALSE;
    }

  /* Add the route to the table. */
  route->flags = SSH_PME_ROUTE_REACHABLE;
  route->dst_and_mask = *dst_and_mask;
  route->next_hop = *next_hop;
  route->ifnum = ifnum;
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return TRUE;
}

/* Removes the given route from the engine internal routing table.  This does
   not automatically modify system routing tables.  This returns TRUE
   if the route was found and deleted, and FALSE if the route did not exist
   in the engine routing table. */

Boolean ssh_engine_route_remove(SshEngine engine, const SshIpAddr dst_and_mask)
{
  SshEngineRoute route;
  SshUInt32 i;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (i = 0; i < SSH_ENGINE_ROUTE_TABLE_SIZE; i++)
    {
      route = &engine->route_table[i];
      if (route->flags == 0)
        continue;
      if (SSH_IP_EQUAL(dst_and_mask, &route->dst_and_mask) &&
          SSH_IP_MASK_LEN(dst_and_mask) ==
          SSH_IP_MASK_LEN(&route->dst_and_mask))
        {
          route->flags = 0;
          ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
          return TRUE;
        }
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  return FALSE;
}

/* Clears all entries from the internal engine routing table.  Note
   that this does not affect system routing tables, and for packets
   originating from the local host the engine only sees them if the
   TCP/IP stack thinks it has some (any) route for them. */

void ssh_engine_pme_configure_route_clear(SshEngine engine)
{
  SshUInt32 i;
  SshEngineRoute route;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  for (i = 0; i < SSH_ENGINE_ROUTE_TABLE_SIZE; i++)
    {
      route = &engine->route_table[i];
      route->flags = 0;
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}

/* Adds a route to `dst_and_mask' to point to gateway `next_hop',
   reachable through interface `ifnum'.  Route lookups always
   return the most exact route (i.e., the route with the highest
   number of bits in the mask - host routes always taking precedence).
   This calls the callback either during this call or at some later
   time to indicate whether the route could be added. */

void ssh_engine_pme_configure_route_add(SshEngine engine,
                                        const SshIpAddr dst_and_mask,
                                        const SshIpAddr next_hop,
                                        SshUInt32 ifnum,
                                        SshPmeStatusCB callback,
                                        void *context)
{
  if (ssh_engine_route_add(engine, dst_and_mask, next_hop, ifnum))
    {
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, TRUE, context);
    }
  else
    {
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, FALSE, context);
    }
}

#endif /* SSH_IPSEC_INTERNAL_ROUTING */

typedef struct SshPmeRouteCtxRec
{
  SshPmeRouteCB callback;
  void *context;
} *SshPmeRouteCtx;

/* (internal function) This function is called when the engine routing
   operation completes during ssh_pme_route.  This calls the policy
   manager callback. */

void ssh_engine_pme_route_cb(SshEngine engine, SshUInt32 flags,
                             const SshIpAddr dst,
                             const SshIpAddr next_hop_gw,
                             SshEngineIfnum ifnum,
                             SshVriId routing_instance_id,
                             size_t mtu,
                             void *context)
{
  SshPmeRouteCtx c = (SshPmeRouteCtx)context;
  (*c->callback)(engine->pm, flags, ifnum, next_hop_gw, mtu, c->context);
  ssh_free(c);
}

/* Routes the given packet using the engine.  This is a function that
   can be called by the policy manager.  Calls the callback when done.
   The callback will have `reachable' TRUE if the destination is
   reachable, in which case `ifnum', `next_hop', `mtu', and `local'
   will also be valid.  `local' indicates that `dst' is one of our own
   addresses.  If `dst' is on the local network, then `next_hop' will
   have the same IP address as `dst'. */

void ssh_engine_pme_route(SshEngine engine, SshUInt32 flags,
                          SshInterceptorRouteKey key,
                          SshPmeRouteCB callback, void *context)
{
  SshPmeRouteCtx c;

  c = ssh_malloc(sizeof(*c));
  if (c == NULL)
    {
      (*callback)(engine->pm, 0, 0, NULL, 0, context);
      return;
    }
  c->callback = callback;
  c->context = context;

  ssh_engine_route(engine, flags, key, TRUE,
                   ssh_engine_pme_route_cb, (void *)c);
}

/* Context data for routing table modification operation. */
struct SshPmeRouteModifyCtxRec
{
  Boolean add;                  /* Route add, otherwise route remove. */
  SshIpAddrStruct ip;           /* Destination IP with netmask. */
  SshEngine engine;
  SshPmeRouteSuccessCB callback;
  void *context;
};

typedef struct SshPmeRouteModifyCtxRec SshPmeRouteModifyCtxStruct;
typedef struct SshPmeRouteModifyCtxRec *SshPmeRouteModifyCtx;

/* Status callback for interceptor routing table modification operation. */
static void
ssh_pme_route_modification_status_cb(SshInterceptorRouteError error,
                                     void *context)
{
  SshPmeRouteModifyCtx ctx = (SshPmeRouteModifyCtx) context;

#ifdef SSH_IPSEC_INTERNAL_ROUTING
  /* The system routing table modification failed.  Let's remove the
     route from the engine's internal routing table. */
  if (ctx->add && error != SSH_INTERCEPTOR_ROUTE_ERROR_OK)
    (void) ssh_engine_route_remove(ctx->engine, &ctx->ip);
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

  (*ctx->callback)(ctx->engine->pm, error, ctx->context);
  ssh_free(ctx);
}

/* Adds a route to `ip' through gateway `gateway_or_local_ip'.  The
   netmask of the destination network (or host) must be set to the
   mask length of the IP address `ip'.  The argument
   `gateway_or_local_ip' can either be a real gateway in a local
   network, or it can specify a local interface IP address.  The
   argument `ifnum' specifies the interface for which the route
   applies to.  The later case declares that the network `ip'
   (including netmask) is directly reachable in the network which
   interface address the gateway address is.  The mask length of the
   argument `gateway_or_local_ip' is ignored.  The success of the
   operation is notified by calling the callback function `callback'.

   The routes created with this function are at their own metrics
   level.  However, you can not specify the same route twice. */

void ssh_engine_pme_route_add(SshEngine engine,
                              SshInterceptorRouteKey key,
                              const SshIpAddr gateway,
                              SshUInt32 ifnum,
                              SshRoutePrecedence precedence,
                              SshUInt32 flags,
                              SshPmeRouteSuccessCB callback,
                              void *context)
{
  SshPmeRouteModifyCtx ctx;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  if (ifnum != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) ifnum;
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#ifdef SSH_IPSEC_INTERNAL_ROUTING
  /* Update the engine's internal routing table. */
  if (!ssh_engine_route_add(engine, &key->dst, gateway, ifnum))
    {
      (*callback)(engine->pm,
                  SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED,
                  context);
      return;
    }
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(engine->pm,
                  SSH_INTERCEPTOR_ROUTE_ERROR_OUT_OF_MEMORY,
                  context);
      return;
    }

  ctx->add = TRUE;
  ctx->ip = key->dst;
  ctx->engine = engine;
  ctx->callback = callback;
  ctx->context = context;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  /* Update the system routing table. */
  ssh_interceptor_add_route(engine->interceptor,
                            key, gateway, eng_ifnum, precedence, flags,
                            ssh_pme_route_modification_status_cb, ctx);
#else /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
  /* Interceptor does not implement kernel level routing table modify. Fail. */
  ssh_pme_route_modification_status_cb(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED,
                                       ctx);
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
#else /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
  /* No way to modify the system routing tables.  If we are using
     internal routing, we are done.  Otherwise the operation fails. */
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  ssh_pme_route_modification_status_cb(SSH_INTERCEPTOR_ROUTE_ERROR_OK, ctx);
#else /* SSH_IPSEC_INTERNAL_ROUTING */
  ssh_pme_route_modification_status_cb(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED,
                                       ctx);
#endif /* SSH_IPSEC_INTERNAL_ROUTING */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
}

/* Removes the route to `ip' (including netmask) through the gateway
   `gateway_or_local_ip'.  The success of the operation is notified by
   calling the callback function `callback'. */

void ssh_engine_pme_route_remove(SshEngine engine,
                                 SshInterceptorRouteKey key,
                                 const SshIpAddr gateway,
                                 SshUInt32 ifnum,
                                 SshRoutePrecedence precedence,
                                 SshUInt32 flags,
                                 SshPmeRouteSuccessCB callback,
                                 void *context)
{
  SshPmeRouteModifyCtx ctx;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  SshEngineIfnum eng_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;

  if (ifnum != SSH_INVALID_IFNUM)
    eng_ifnum = (SshEngineIfnum) ifnum;
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


#ifdef SSH_IPSEC_INTERNAL_ROUTING
  /* Update the engine's internal routing table. */
  (void) ssh_engine_route_remove(engine, &key->dst);
#endif /* SSH_IPSEC_INTERNAL_ROUTING */

  ctx = ssh_calloc(1, sizeof(*ctx));
  if (ctx == NULL)
    {
      (*callback)(engine->pm,
                  SSH_INTERCEPTOR_ROUTE_ERROR_OUT_OF_MEMORY,
                  context);
      return;
    }

  ctx->add = FALSE;
  ctx->ip = key->dst;
  ctx->engine = engine;
  ctx->callback = callback;
  ctx->context = context;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifdef INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY
  /* Update the system routing table. */
  ssh_interceptor_remove_route(engine->interceptor,
                               key, gateway, eng_ifnum, precedence, flags,
                               ssh_pme_route_modification_status_cb, ctx);
#else /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
  /* Interceptor does not implement kernel level routing table modify. Fail. */
  ssh_pme_route_modification_status_cb(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED,
                                       ctx);
#endif /* INTERCEPTOR_IMPLEMENTS_ROUTE_MODIFY */
#else /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
  /* No way to modify the system routing tables.  If we are using
     internal routing, we are done.  Otherwise the operation fails. */
#ifdef SSH_IPSEC_INTERNAL_ROUTING
  ssh_pme_route_modification_status_cb(SSH_INTERCEPTOR_ROUTE_ERROR_OK, ctx);
#else /* SSH_IPSEC_INTERNAL_ROUTING */
  ssh_pme_route_modification_status_cb(SSH_INTERCEPTOR_ROUTE_ERROR_UNDEFINED,
                                       ctx);
#endif /* SSH_IPSEC_INTERNAL_ROUTING */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
}
