/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Sending ICMP messages.  Code in this file also takes care of
   rate-limiting them.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineIcmp"

/* Context for asynch ICMP send. This structure contains the context
   required to form the ICMP error response after a suitable source
   address has been discovered for the ICMP packet. */
typedef struct SshEngineIcmpErrorRec
{
  /* Cached ICMP params */
  SshUInt8 type;
  SshUInt8 code;
  SshUInt32 extra;

  /* Cached/Stolen params from packetcontext */
  SshInterceptorPacket pp;
  SshUInt16 hdrlen;
  size_t packet_len;
  SshUInt32 prev_transform_index;
  SshIpAddrStruct src;

  /* The following fields are here to reduce runtime stack usage. */
#if defined (WITH_IPV6)
  unsigned char buf[SSH_IPH6_HDRLEN + 8];
#endif /* (WITH_IPV6) */
  SshInterceptorRouteKeyStruct key;
} SshEngineIcmpErrorStruct, *SshEngineIcmpError;

/* The latter part of ssh_engine_send_icmp_error(). This function
   is called either directly or via ssh_engine_route(). The
   function attempts to construct the ICMP error reply and
   send it as specified in (struct SshEngineIcmpErrorRec*)context. */
static void
ssh_engine_send_icmp_error_cb(SshEngine engine,
                              SshUInt32 flags,
                              const SshIpAddr dst,
                              const SshIpAddr next_hop_gw,
                              SshEngineIfnum ifnum,
                              SshVriId routing_instance_id,
                              size_t mtu,
                              void *context)
{
  SshEngineIcmpError rec;
  SshInterceptorPacket pp, new_pp;
  SshUInt32 len, hdrlen, icmp_flags, prev_transform_index;
  SshUInt16 ip_id, checksum;
  SshInterceptorProtocol protocol;

  SSH_INTERCEPTOR_STACK_MARK();

  rec = (SshEngineIcmpError) context;
  pp = rec->pp;
  new_pp = NULL;

  SSH_ASSERT(rec != NULL);
  SSH_ASSERT(pp != NULL);

  if (next_hop_gw == NULL || !(flags & SSH_PME_ROUTE_REACHABLE))
    goto dontsend;

  /* Determine how much data to include in the ICMP packet. */
  len = rec->packet_len;
#if defined (WITH_IPV6)
  if (SSH_IP_IS6(dst))
    {
      if (!SSH_IP_IS6(next_hop_gw))
        goto dontsend;
      hdrlen = SSH_IPH6_HDRLEN + 8;
      if (len >  1280 - hdrlen)
        len = 1280 - hdrlen;
      protocol = SSH_PROTOCOL_IP6;
    }
  else
#endif /* WITH_IPV6 */
    {
      if (!SSH_IP_IS4(next_hop_gw) || !SSH_IP_IS4(&rec->src))
        goto dontsend;
      hdrlen = 8 + SSH_IPH4_HDRLEN; /* ICMP header */
      /* Reserve space for ESP encapsulation and other miscellaneous
         padding which may occur in the packet (e.g. PPP+L2TP+IPsec+IPv4
         encapsulation). */
      if (len > 276 - hdrlen)
        len = 276 - hdrlen;
      protocol = SSH_PROTOCOL_IP4;
    }

  /* Allocate an IP packet ID for the new ICMP. */
  ip_id = ssh_engine_get_ip_id(engine);

  ssh_kernel_mutex_lock(engine->interface_lock);
  /* Check that ifnum is valid. */
  if (ssh_ip_get_interface_by_ifnum(&engine->ifs, pp->ifnum_in) == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto dontsend;
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Allocate a packet structure. */
  if ((pp->flags & SSH_PACKET_FROMPROTOCOL)
      && (pp->flags & SSH_ENGINE_P_FROMADAPTER) == 0)
    icmp_flags = SSH_PACKET_FROMADAPTER;
  else
    icmp_flags = SSH_PACKET_FROMPROTOCOL;

  /* Leave pp->ifnum_out unset, as the packet is going to be routed. */
  new_pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                        icmp_flags,
                                        protocol, pp->ifnum_in,
                                        SSH_INTERCEPTOR_INVALID_IFNUM,
                                        hdrlen + len);
  if (new_pp == NULL)
    goto dontsend;

  /* Set routing instance di */
  if (pp->routing_instance_id < 0)
    goto dontsend;
  new_pp->routing_instance_id = pp->routing_instance_id;

  memcpy(new_pp->extension, pp->extension, sizeof(new_pp->extension));

#if defined (WITH_IPV6)
  if (protocol == SSH_PROTOCOL_IP6)
    {
      unsigned char *buf = rec->buf;
      unsigned char *cp = rec->buf;

      /* Construct the IPv6 header in place of the real IPv6 header. */
      memset(buf, 0, SSH_IPH6_HDRLEN + 8);
      SSH_IP6_PSEUDOH_SET_SRC(next_hop_gw, cp);
      SSH_IP6_PSEUDOH_SET_DST(&rec->src, cp);
      SSH_IP6_PSEUDOH_SET_LEN(cp, len + 8);
      SSH_IP6_PSEUDOH_SET_NH(cp, SSH_IPPROTO_IPV6ICMP);

      /* Construct the ICMPv6 header. */
      cp += SSH_IPH6_HDRLEN;
      SSH_ICMP6H_SET_TYPE(cp, rec->type);
      SSH_ICMP6H_SET_CODE(cp, rec->code);
      /* The checksum is initially set to zero, and written over once
         we've created the packet and computed its checksum. */
      SSH_ICMP6H_SET_CHECKSUM(cp, 0);
      SSH_PUT_32BIT(cp + 4, rec->extra);

      if (!ssh_interceptor_packet_copyin(new_pp, 0, buf, SSH_IPH6_HDRLEN + 8))
        {
        copyin_failed:
          SSH_DEBUG(SSH_D_ERROR, ("ssh_interceptor_packet_copyin failed"));
          new_pp = NULL;
          goto dontsend;
        }

      /* Copy the rest of the packet to the "invoking packet" part of
         the ICMPv6 error message as possible. */
      if (!ssh_interceptor_packet_copy(pp, 0, len, new_pp,
                                       SSH_IPH6_HDRLEN + 8))
        {
          SSH_DEBUG(SSH_D_ERROR, ("ssh_interceptor_packet_copy failed"));
          new_pp = NULL;
          goto dontsend;
        }
      checksum = ssh_ip_cksum_packet(new_pp, 0, hdrlen + len);

      /* Now that we have the checksum, construct the real IPv6 header
         in place of the pseudo header. */
      SSH_IPH6_SET_VERSION(buf, 6);
      SSH_IPH6_SET_CLASS(buf, 0);
      SSH_IPH6_SET_FLOW(buf, 0);



      SSH_IPH6_SET_LEN(buf, len + 8);
      SSH_IPH6_SET_NH(buf, SSH_IPPROTO_IPV6ICMP);
      SSH_IPH6_SET_HL(buf, 200);
      SSH_IPH6_SET_SRC(next_hop_gw, buf);
      SSH_IPH6_SET_DST(&rec->src, buf);

      /* Store the checksum. */
      SSH_ICMP6H_SET_CHECKSUM(cp, checksum);

      /* Copy the `buf' back into the `new_pp' again. */
      if (!ssh_interceptor_packet_copyin(new_pp, 0, buf, SSH_IPH6_HDRLEN + 8))
          goto copyin_failed;
    }
  else
#endif /* WITH_IPV6 */
    {
      /* Construct the ICMP packet. */
      unsigned char *ucpw;

      ucpw = ssh_interceptor_packet_pullup(new_pp, SSH_IPH4_HDRLEN + 8);
      if (ucpw == NULL)
        {
          new_pp = NULL;
          goto dontsend;
        }

      memset(ucpw, 0, SSH_IPH4_HDRLEN + 8);
      SSH_IPH4_SET_VERSION(ucpw, 4);
      SSH_IPH4_SET_TOS(ucpw, 192);  /* Network control Type of Service */
      SSH_IPH4_SET_HLEN(ucpw, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucpw, SSH_IPH4_HDRLEN + 8 + len);
      SSH_IPH4_SET_ID(ucpw, ip_id);
      SSH_IPH4_SET_TTL(ucpw, 240);
      SSH_IPH4_SET_PROTO(ucpw, SSH_IPPROTO_ICMP);

      /* Set the IP addresses and compute IP header checksum. */
      SSH_IPH4_SET_SRC(next_hop_gw, ucpw);
      SSH_IPH4_SET_DST(&rec->src, ucpw);
      checksum = ssh_ip_cksum(ucpw, SSH_IPH4_HDRLEN);
      SSH_IPH4_SET_CHECKSUM(ucpw, checksum);

      /* Construct the ICMP payload. */
      ucpw += SSH_IPH4_HDRLEN;
      ucpw[0] = rec->type;
      ucpw[1] = rec->code;
      if (rec->type == SSH_ICMP_TYPE_UNREACH)
        SSH_PUT_16BIT(ucpw + 6, rec->extra);
      else
        if (rec->type == SSH_ICMP_TYPE_PARAMPROB)
          SSH_PUT_8BIT(ucpw + 4, rec->extra);

      /* Copy `len' bytes from the original packet. */
      if (!ssh_interceptor_packet_copy(pp, 0, len, new_pp,
                                       SSH_IPH4_HDRLEN + 8))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Copy failed, dropping packet"));
          new_pp = NULL;
          goto dontsend;
        }

      /* Compute and store ICMP checksum.  Note that ssh_ip_cksum only read
         iterates over the packet, and thus does not invalidate ucpw. */
      checksum = ssh_ip_cksum_packet(new_pp, SSH_IPH4_HDRLEN, len + 8);
      SSH_PUT_16BIT(ucpw + 2, checksum);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Sending ICMP error to %s: src %@ dst %@ transform idx 0x%08x",
             ((icmp_flags & SSH_PACKET_FROMPROTOCOL)?"network":"local stack"),
             ssh_ipaddr_render, next_hop_gw,
             ssh_ipaddr_render, &rec->src,
             (unsigned int) rec->prev_transform_index));

  prev_transform_index = rec->prev_transform_index;

  /* Send the packet out.  This will allocate a packet context for the
     new packet, and will perform any required route and ARP lookups
     for the packet.  This also arranges to apply the given transform
     on the packet if the packet arrived through a transform. */
#if defined (WITH_IPV6)
  if (protocol == SSH_PROTOCOL_IP6)
    ssh_engine_send_packet(engine, new_pp,
                           SSH_IPH6_HDRLEN,
                           prev_transform_index, next_hop_gw, &rec->src,
                           SSH_IPPROTO_IPV6ICMP,
                           SSH_IPH6_HDRLEN,
                           SSH_IPH6_OFS_NH,
                           TRUE);
  else
#endif /* WITH_IPV6 */
    ssh_engine_send_packet(engine, new_pp,
                           SSH_IPH4_HDRLEN,
                           prev_transform_index, next_hop_gw, &rec->src,
                           SSH_IPPROTO_ICMP, 0, 0,
                           TRUE);

  /* `ssh_engine_send_packet' freed the packet, therefore assign
     `new_pp' to NULL. */
  new_pp = NULL;

 dontsend:
  if (new_pp != NULL)
    ssh_interceptor_packet_free(new_pp);
  ssh_interceptor_packet_free(pp);
  ssh_free(rec);
  return;
}


/* This function initiates an asynchronous send of an ICMP error packet to
   the originator of the packet.  The send is asynchronous in the case
   that the packet has the SSH_PACKET_FROMPROTOCOL flag set, in which
   case the source address for the reply is fetched using
   ssh_engine_route().
   This function takes care of routing the packet appropriately,
   so that it gets sent out from the correct interface and
   possibly gets tunneled using the appropriate tunnel.  The sent ICMPs
   will be rate-limited so that the same ICMP will not be sent more than
   about once per second, and that the total number of ICMPs sent per
   second is limited.  This will also check for broadcast addresses,
   and will not send ICMPs to such addresses.  The function steals the
   packet "pc->pp" which is assumed to be the offending packet. */
void
ssh_engine_send_icmp_error(SshEngine engine,
                           SshEnginePacketContext pc,
                           SshUInt8 type,
                           SshUInt8 code,
                           SshUInt32 extra)
{
  SshInterceptorPacket pp;
  SshUInt16 rate_limit_id = 0;
  SshEngineIcmpError rec = NULL;
  const unsigned char *ucp;
  SshUInt16 offset;

  SSH_DEBUG(SSH_D_MY,
            ("send icmp error type=%d code=%d extra=%d prev_transform=0x%08x",
             type, code, (int) extra,
             (unsigned int) pc->prev_transform_index));

  pp = pc->pp;

  if (pp == NULL)
    return;

  /* Steal packet */
  pc->pp = NULL;

  /* For IPv4 use IPv4 header checksum as the packet identifier for
     rate limiting. */
  if (pp->protocol == SSH_PROTOCOL_IP4)
    {
      offset = pc->hdrlen;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      offset += pc->media_hdr_len;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ucp = ssh_interceptor_packet_pullup_read(pp, offset);
      if (ucp == NULL)
        {
          pp = NULL;
          goto dontsend;
        }
      rate_limit_id = SSH_IPH4_CHECKSUM(ucp);
    }

  /* Check violating packet IP addresses. */
#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      switch (type)
        {
          /* Ignore destination address multicast check for
             ICMPv6 type TIMEXCEED and ICMPv6 type PARAMPROB code 2.
             The calling code is responsible for performing this check. */
        case SSH_ICMP6_TYPE_TIMXCEED:
          break;

        case SSH_ICMP6_TYPE_PARAMPROB:
          if (code == 2)
            break;
          /* Fallthrough for codes 0 and 1. */

        default:
          /* RFC4443 2.4.e.e.3: check violating packet destination IP. */
          if (SSH_IP6_IS_MULTICAST(&pc->dst))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Violating packet dst %@ is multicast, "
                         "not sending ICMPv6 error type %d",
                         ssh_ipaddr_render, &pc->dst, type));
              goto dontsend;
            }

          /* RFC4443 2.4.e.e.4 & 5: check violating packet destination link
             address. */
          if ((pp->flags & SSH_PACKET_MEDIABCAST)
              || (pp->flags & SSH_ENGINE_P_BROADCAST))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Violating packet was sent to link %s, "
                         "not sending ICMPv6 error type %d",
                         ((pp->flags & SSH_ENGINE_P_BROADCAST) ?
                          "broadcast" : "multicast"),
                         type));
              goto dontsend;
            }
        }

      /* RFC4443 2.4.e.e.6: check violating packet source IP address. */
      if (SSH_IP_IS_NULLADDR(&pc->src)
          || SSH_IP6_IS_MULTICAST(&pc->src))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Violating packet src %@ is %s, "
                     "not sending ICMPv6 error type %d",
                     ssh_ipaddr_render, &pc->src,
                     (SSH_IP_IS_NULLADDR(&pc->src) ?
                      "undefined" : "multicast"),
                     type));
          goto dontsend;
        }

      if ((pp->flags & SSH_ENGINE_P_ISFRAG) != 0
          && (pp->flags & SSH_ENGINE_P_FIRSTFRAG) == 0)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Violating packet is non-first fragment, "
                     "not sending ICMPv6 error type %d",
                     type));
          goto dontsend;
        }
    }
  else
#endif /* WITH_IPV6 */
    {
      /* RFC1122 says one MUST NOT send ICMPs in response to packets
         from broadcast, multicast, or link-level broadcast addresses.
         RFC1812 says that one MUST NOT send ICMP messages in response
         to non-first fragments. */
      if ((pp->flags & SSH_ENGINE_P_BROADCAST) ||
          (pp->flags & SSH_PACKET_MEDIABCAST) ||
          ((pp->flags & (SSH_ENGINE_P_ISFRAG | SSH_ENGINE_P_FIRSTFRAG)) ==
           SSH_ENGINE_P_ISFRAG) ||
          SSH_IP_IS_BROADCAST(&pc->src) ||
          SSH_IP_IS_MULTICAST(&pc->src) ||
          SSH_IP_IS_LOOPBACK(&pc->src) ||
          SSH_IP_IS_BROADCAST(&pc->dst) ||
          SSH_IP_IS_MULTICAST(&pc->dst) ||
          SSH_IP_IS_LOOPBACK(&pc->dst))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("ICMP not sent (broadcast, multicast, "
                                    "loopback, or non-first frag, ICMP err)"));
          goto dontsend;
        }
    }

  if (pc->ipproto == SSH_IPPROTO_ICMP)
    {
      /* RFC1122 says one MUST NOT send ICMPs in response to ICMP
         errors and certain other ICMPs. */
      if (pc->icmp_type == SSH_ICMP_TYPE_UNREACH ||
          pc->icmp_type == SSH_ICMP_TYPE_REDIRECT ||
          pc->icmp_type == SSH_ICMP_TYPE_SOURCEQUENCH ||
          pc->icmp_type == SSH_ICMP_TYPE_TIMXCEED ||
          pc->icmp_type == SSH_ICMP_TYPE_PARAMPROB)
        goto dontsend;
    }

#if defined (WITH_IPV6)
  else if (pc->ipproto == SSH_IPPROTO_IPV6ICMP)
    {
      /* According to RFC4443, 2.4.e.1 & 2, one MUST NOT send an error
         message in response to an ICMPv6 error or redirect message. */
      if (pc->icmp_type == SSH_ICMP6_TYPE_UNREACH ||
          pc->icmp_type == SSH_ICMP6_TYPE_TOOBIG ||
          pc->icmp_type == SSH_ICMP6_TYPE_TIMXCEED ||
          pc->icmp_type == SSH_ICMP6_TYPE_PARAMPROB ||
          pc->icmp_type == SSH_ICMP6_TYPE_REDIRECT)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Violating packet is ICMP error type %d, "
                     "not sending ICMPv6 error type %d",
                     pc->icmp_type, type));
          goto dontsend;
        }
    }
#endif /* WITH_IPV6 */

  /* Violating packet passed sanity checks, continue with sending the
     ICMP error. */

  rec = ssh_calloc(1, sizeof(*rec));
  if (rec == NULL)
    goto dontsend;

  rec->type = type;
  rec->code = code;
  rec->extra = extra;
  rec->pp = pp;
  rec->hdrlen = pc->hdrlen;
  rec->packet_len = pc->packet_len;
  rec->prev_transform_index = pc->prev_transform_index;
  rec->src = pc->src;

  /* For IPv6 ICMP toobig we'll put the mtu size into rate limit hash
     to allow situations where we create one ICMP ourself, and other
     smaller after receiving ICMP from the route. */
  if (pp->protocol == SSH_PROTOCOL_IP6 && type == SSH_ICMP6_TYPE_TOOBIG)
    rate_limit_id = (SshUInt16) extra;















  /* Rate limit outgoing ICMP error messages. */
  if (ssh_engine_response_rate_limit(engine, &pc->src, &pc->dst,
                                     pc->ipproto, type, code, rate_limit_id))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("ICMP not sent; rate limited"));
      goto dontsend;
    }

  /* If the offending packet is from this host, then we perform a
     lookup and find the next hop gw and place this as the source
     address in the ICMP error packet. This works around problems with
     operating systems that do not expect to receive ICMP errors from
     he external network interfaces that have a local source
     address. */
  if ((pp->flags & SSH_PACKET_FROMPROTOCOL)
      && (pp->flags & SSH_ENGINE_P_FROMADAPTER) == 0)
    {
      /* If the packet is from the IP stack above, then the source
         address of the ICMP error must be the IP address of the next
         hop gw for all IP stacks to operate correctly. */





      SSH_INTERCEPTOR_ROUTE_KEY_INIT(&rec->key);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_DST(&rec->key, &pc->dst);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_OUT_IFNUM(&rec->key, pp->ifnum_in);
      SSH_INTERCEPTOR_ROUTE_KEY_SET_RIID(&rec->key, pp->routing_instance_id);

      ssh_interceptor_packet_detach(rec->pp);
      ssh_engine_route(engine, 0, &rec->key, TRUE,
                       ssh_engine_send_icmp_error_cb, rec);
    }
  else
    {
      SshIpAddrStruct src = pc->dst;
      Boolean rv;

      if (SSH_IP_IS6(&pc->dst))
        {
          SSH_IP_UNDEFINE(&src);

          ssh_kernel_mutex_lock(engine->interface_lock);
          rv = ssh_engine_get_ipaddr(engine, pp->ifnum_in,
                                     pp->protocol, &pc->dst, &src);
          if (rv == FALSE)
            rv = ssh_engine_get_ipaddr(engine, pp->ifnum_in,
                                       pp->protocol, NULL, &src);
          ssh_kernel_mutex_unlock(engine->interface_lock);

          if (!rv || !SSH_IP_DEFINED(&src))
            {
              SSH_DEBUG(SSH_D_ERROR,
                        ("ICMP not sent; "
                         "no address for ifnum %d proto %d.",
                         (int)pp->ifnum_in, (int)pp->protocol));
              goto dontsend;
            }
        }

      /* If the packet is from the network, the ICMP error is sent
         with a source address of the original destination. This is
         because the packet may have arrived via an ESP tunnel and the
         sender of the packet may think that the correct route is
         direct and will ignore any ICMP messages from us unless they
         have a sourceaddress of the original destination */
      ssh_engine_send_icmp_error_cb(engine, SSH_PME_ROUTE_REACHABLE,
                                    &pc->dst, &src, pp->ifnum_in,
                                    pp->routing_instance_id, pp->pmtu,
                                    rec);
    }
  return;

 dontsend:
  /* Free the packet that we stole and release any memory we
     allocated. */
  if (pp)
    ssh_interceptor_packet_free(pp);
  if (rec)
    ssh_free(rec);
}


#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Initializes ICMP tracking state of a flow.  This expects to be called
   with engine->flow_control_table_lock held protecting the tcpdata. */

void ssh_engine_icmp_init(SshEngine engine, SshEngineFlowData d_flow)
{
  SSH_DEBUG(SSH_D_LOWOK, ("initializing icmpdata"));
}


/* Uninitializes ICMP tracking state of a flow (freeing dynamically
   allocated memory, if any).  This gets called when the flow is being
   destroyed.  This expects to be called with engine->flow_control_table_lock
   held protecting the tcpdata. */

void ssh_engine_icmp_uninit(SshEngine engine, SshEngineFlowData d_flow)
{
  SSH_DEBUG(SSH_D_LOWOK, ("uninitializing icmpdata"));
}

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
