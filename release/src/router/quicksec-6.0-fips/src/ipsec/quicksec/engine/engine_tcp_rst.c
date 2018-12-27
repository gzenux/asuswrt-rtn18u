/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Sending TCP RST messages.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineTcpRst"

/* Context for asynch TCP RST send. This structure contains the context
   required to form the TCP RST response after a suitable source
   address has been discovered for the packet. */
struct SshEngineTcpRstRec
{
  /* Cached parameters from pp for constructing the TCP RST packet, (pp
     may already have been freed when ssh_engine_send_tcp_rst_cb gets
     called. */
  SshEngineIfnum ifnum;
  SshVriId routing_instance_id;
  SshUInt32 pp_flags;
  SshInterceptorProtocol protocol;
  SshUInt16 tcp_flags;
  SshUInt16 src_port;
  SshUInt16 dst_port;
  SshUInt32 ack_num;
  SshUInt32 seq_num;
  size_t new_hdrlen;
#if defined (WITH_IPV6)
  SshUInt32 ipv6_flow;
#endif /* WITH_IPV6 */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Cached/Stolen params from packetcontext */
  SshUInt32 prev_transform_index;
  SshIpAddrStruct src;
};


/* The latter part of ssh_engine_send_tcp_rst(). This function
   is called either directly or via ssh_engine_route(). The
   function attempts to construct the TCP RST packet and
   send it as specified in (struct SshEngineTcpRstRec*)context. */
static void
ssh_engine_send_tcp_rst_cb(SshEngine engine,
                           SshUInt32 flags,
                           const SshIpAddr dst,
                           const SshIpAddr next_hop_gw,
                           SshEngineIfnum ifnum,
                           size_t mtu,
                           void *context)
{
  struct SshEngineTcpRstRec *rec;
  unsigned char *ucpw, *cp;
  SshInterceptorPacket new_pp;
  SshUInt32 tcprst_flags, ip_id;
  SshUInt16 checksum;

  SSH_INTERCEPTOR_STACK_MARK();

  rec = (struct SshEngineTcpRstRec*) context;
  new_pp = NULL;

  SSH_ASSERT(rec != NULL);

  if (next_hop_gw == NULL || !(flags & SSH_PME_ROUTE_REACHABLE))
    {
      SSH_DEBUG(SSH_D_HIGHOK, ("TCP RST not sent as the destination is not "
                               "reachable"));
      goto dontsend;
    }

  ip_id = ssh_engine_get_ip_id(engine);

  ssh_kernel_mutex_lock(engine->interface_lock);

  /* Check that ifnum is valid. */
  if (ssh_ip_get_interface_by_ifnum(&engine->ifs, rec->ifnum) == NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      goto dontsend;
    }
  ssh_kernel_mutex_unlock(engine->interface_lock);


  /* Allocate a packet structure. */
  if (rec->pp_flags & SSH_PACKET_FROMPROTOCOL)
    tcprst_flags = SSH_PACKET_FROMADAPTER;
  else
    tcprst_flags = SSH_PACKET_FROMPROTOCOL;

  /* Leave pp->ifnum_out unset, as the packet is going to get routed. */
   new_pp = ssh_interceptor_packet_alloc(engine->interceptor,
                                         tcprst_flags,
                                         rec->protocol,
                                         rec->ifnum,
                                         SSH_INTERCEPTOR_INVALID_IFNUM,
                                         rec->new_hdrlen);
  if (new_pp == NULL)
    goto dontsend;

  /* Set routing instance id */
  if (rec->routing_instance_id < 0)
    goto dontsend;
  new_pp->routing_instance_id = rec->routing_instance_id;

  memcpy(new_pp->extension, rec->extension, sizeof(new_pp->extension));

  /* Construct the TCP RST packet. */
  ucpw = ssh_interceptor_packet_pullup(new_pp, rec->new_hdrlen);
  if (ucpw == NULL)
    {
      new_pp = NULL;
      goto dontsend;
    }
  memset(ucpw, 0, rec->new_hdrlen);

  /* Construct pseudo-header reusing IP header's space. */
#if defined (WITH_IPV6)
  if (rec->protocol == SSH_PROTOCOL_IP6)
    {
      SSH_IP6_PSEUDOH_SET_SRC(next_hop_gw, ucpw);
      SSH_IP6_PSEUDOH_SET_DST(&rec->src, ucpw);
      SSH_IP6_PSEUDOH_SET_LEN(ucpw, SSH_TCPH_HDRLEN);
      SSH_IP6_PSEUDOH_SET_NH(ucpw, SSH_IPPROTO_TCP);
      cp = ucpw + SSH_IPH6_HDRLEN;
    }
  else
#endif /* WITH_IPV6 */
    {
      cp = ucpw + 8;
      SSH_IP4_ENCODE(next_hop_gw, cp);
      SSH_IP4_ENCODE(&rec->src, cp + 4);
      cp[9] = SSH_IPPROTO_TCP;
      SSH_PUT_16BIT(cp + 10, SSH_TCPH_HDRLEN);
      cp = ucpw + SSH_IPH4_HDRLEN;
    }

  /* Construct the TCP header after the pseudo header. */
  SSH_TCPH_SET_SRCPORT(cp, rec->src_port);
  SSH_TCPH_SET_DSTPORT(cp, rec->dst_port);
  SSH_TCPH_SET_DATAOFFSET(cp, SSH_TCPH_HDRLEN / 4);
  SSH_TCPH_SET_SEQ(cp, rec->seq_num);
  if (rec->tcp_flags & SSH_TCPH_FLAG_ACK)
    {
      SSH_TCPH_SET_SEQ(cp, rec->seq_num);
      SSH_TCPH_SET_ACK(cp, 0);
      SSH_TCPH_SET_FLAGS(cp, SSH_TCPH_FLAG_RST);
    }
  else
    {
      SSH_TCPH_SET_SEQ(cp, 0);
      SSH_TCPH_SET_ACK(cp, rec->ack_num);
      SSH_TCPH_SET_FLAGS(cp, SSH_TCPH_FLAG_ACK | SSH_TCPH_FLAG_RST);
    }

  /* Compute TCP checksum over the pseudo-header and TCP header. */
#if defined (WITH_IPV6)
  if (rec->protocol == SSH_PROTOCOL_IP6)
    checksum = ssh_ip_cksum(ucpw, SSH_IP6_PSEUDOH_HDRLEN + SSH_TCPH_HDRLEN);
  else
#endif /* WITH_IPV6 */
    checksum = ssh_ip_cksum(ucpw + 8, 12 + SSH_TCPH_HDRLEN);
  SSH_TCPH_SET_CHECKSUM(cp, checksum);

  /* Construct the IP header. */
#if defined (WITH_IPV6)
  if (rec->protocol == SSH_PROTOCOL_IP6)
    {
      memset(ucpw, 0, SSH_IPH6_HDRLEN);
      SSH_IPH6_SET_VERSION(ucpw, 6);




      SSH_IPH6_SET_CLASS(ucpw, 0);
      SSH_IPH6_SET_FLOW(ucpw, rec->ipv6_flow);
      SSH_IPH6_SET_LEN(ucpw, SSH_TCPH_HDRLEN);
      SSH_IPH6_SET_NH(ucpw, SSH_IPPROTO_TCP);
      SSH_IPH6_SET_HL(ucpw, 240);
      SSH_IPH6_SET_SRC(next_hop_gw, ucpw);
      SSH_IPH6_SET_DST(&rec->src, ucpw);
    }
  else
#endif /* WITH_IPV6 */
    {
      memset(ucpw, 0, SSH_IPH4_HDRLEN);
      SSH_IPH4_SET_VERSION(ucpw, 4);
      SSH_IPH4_SET_HLEN(ucpw, SSH_IPH4_HDRLEN / 4);
      SSH_IPH4_SET_LEN(ucpw, SSH_IPH4_HDRLEN + SSH_TCPH_HDRLEN);
      SSH_IPH4_SET_ID(ucpw, ip_id);
      SSH_IPH4_SET_TTL(ucpw, 240);
      SSH_IPH4_SET_PROTO(ucpw, SSH_IPPROTO_TCP);
      SSH_IPH4_SET_SRC(next_hop_gw, ucpw);
      SSH_IPH4_SET_DST(&rec->src, ucpw);
      checksum = ssh_ip_cksum(ucpw, SSH_IPH4_HDRLEN);
      SSH_IPH4_SET_CHECKSUM(ucpw, checksum);
    }

  /* TCP RST constructed. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Sending TCP RST: %@.%u > %@.%u R %u:%u(0) ack %u win 0",
             ssh_ipaddr_render, next_hop_gw,
             rec->src_port,
             ssh_ipaddr_render, &rec->src,
             rec->dst_port,
             (unsigned int) rec->seq_num,
             (unsigned int) rec->seq_num,
             (unsigned int) rec->ack_num));

 /* Send the packet out.  This will allocate a packet context for the
     new packet, and will perform any required route and ARP lookups for
     the packet.  This also arranges to apply the given transform on the
     packet if the packet arrived through a transform.  This frees new_pp. */
#if defined (WITH_IPV6)
  if (rec->protocol == SSH_PROTOCOL_IP6)
    ssh_engine_send_packet(engine, new_pp,
                           SSH_IPH6_HDRLEN,
                           rec->prev_transform_index, next_hop_gw, &rec->src,
                           SSH_IPPROTO_TCP,
                           SSH_IPH6_HDRLEN,
                           SSH_IPH6_OFS_NH,
                           TRUE);
  else
#endif /* WITH_IPV6 */
    ssh_engine_send_packet(engine, new_pp,
                           SSH_IPH4_HDRLEN,
                           rec->prev_transform_index, next_hop_gw, &rec->src,
                           SSH_IPPROTO_TCP, 0, 0,
                           TRUE);

  /* `ssh_engine_send_packet' freed the packet, therefore assign
     `new_pp' to NULL. */
  new_pp = NULL;

 dontsend:
  if (new_pp != NULL)
    ssh_interceptor_packet_free(new_pp);
  ssh_free(rec);
  return;
}



/* Sends a TCP RST packet to the originator of the packet. The send is
   asynchronous in the case that the packet has the SSH_PACKET_FROMPROTOCOL
   flag set, in which case the source address for the reply is fetched using
   ssh_engine_route(). This will take care of routing the packet appropriately,
   so that it gets sent out from the correct interface and possibly gets
   tunneled using the appropriate tunnel.  This will also check for broadcast
   addresses, and will not send TCP RST to such addresses. */
void
ssh_engine_send_tcp_rst(SshEngine engine, SshEnginePacketContext pc)
{
  struct SshEngineTcpRstRec *rec = NULL;
  const unsigned char *ucp;
  unsigned char pullup_buf[40];
  SshInterceptorPacket pp;
  SshUInt32 new_hdrlen;
  SshUInt16 tcp_flags;
  SshUInt16 rate_limit_id;
  SshUInt16 src_port, dst_port;
  SshUInt32 ack_num, seq_num;
  SshInterceptorProtocol protocol;
#if defined (WITH_IPV6)
  SshUInt32 ipv6_flow = 0;
#endif /* WITH_IPV6 */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Entered TCP RST"));

  pp = pc->pp;
  if (pp == NULL)
    return;

  if (pc->ipproto != SSH_IPPROTO_TCP)
    goto dontsend;

  /* The TCP RST is to be send from `pc->dst' to `pc->src',
     i.e. addresses reversed.  The ports are reversed similarly. */

  /* Do not send response to packets from broadcast, multicast, or
     link-level broadcast addresses.  Also, ignore non-first
     fragments. */
  if ((pp->flags & SSH_ENGINE_P_BROADCAST)
      || (pp->flags & SSH_PACKET_MEDIABCAST)
      || ((pp->flags & (SSH_ENGINE_P_ISFRAG | SSH_ENGINE_P_FIRSTFRAG)) ==
          SSH_ENGINE_P_ISFRAG)
      || SSH_IP_IS_BROADCAST(&pc->src)
      || SSH_IP_IS_MULTICAST(&pc->src)
      || SSH_IP_IS_LOOPBACK(&pc->src)
      || SSH_IP_IS_BROADCAST(&pc->dst)
      || SSH_IP_IS_MULTICAST(&pc->dst)
      || SSH_IP_IS_LOOPBACK(&pc->dst))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("TCP RST not sent"));
      goto dontsend;
    }

  if (pc->packet_len < pc->hdrlen + SSH_TCPH_HDRLEN)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Packet too short to contain TCP header"));
      goto dontsend;
    }

  /* Take the interesting fields from the TCP header.  We take them in
     the order of the generated TCP RST packet (swapping source and
     destination, SEQ and ACK).

     It is unclear whether `pc->u.rule.{src,dst}_port' are valid here,
     so we better dig them out also in IPv6.  Particularly since we
     also have to dig out `tcp_flags' in any case. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_TCPH_HDRLEN, pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      goto dontsend;
    }

  src_port = SSH_TCPH_DSTPORT(ucp);
  dst_port = SSH_TCPH_SRCPORT(ucp);
  tcp_flags = SSH_TCPH_FLAGS(ucp);

  /* RFC 793: TCP RST's must NOT be sent in response to packets
     containing the RST bit */
  if (tcp_flags & SSH_TCPH_FLAG_RST)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("TCP RST not sent, as the original packet "
                              "has the RST bit set."));
      goto dontsend;
    }

  /* Construct ACK number: SEQ + number of data + SYN bit. */
  ack_num = SSH_TCPH_SEQ(ucp);
  ack_num += pc->packet_len - pc->hdrlen - (SSH_TCPH_DATAOFFSET(ucp) << 2);
  if (tcp_flags & SSH_TCPH_FLAG_SYN)
    ack_num++;
  seq_num = SSH_TCPH_ACK(ucp);

  protocol = pp->protocol;
#if defined (WITH_IPV6)
  if (protocol == SSH_PROTOCOL_IP6)
    {
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH6_HDRLEN, pullup_buf);
      if (ucp == NULL)
        {
          pc->pp = NULL;
          goto dontsend;
        }
      ipv6_flow = SSH_IPH6_FLOW(ucp);
      rate_limit_id = 0;
      new_hdrlen = SSH_IPH6_HDRLEN + SSH_TCPH_HDRLEN;
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH4_HDRLEN, pullup_buf);
      if (ucp == NULL)
        {
          pc->pp = NULL;
          goto dontsend;
        }
      rate_limit_id = SSH_IPH4_CHECKSUM(ucp);
      new_hdrlen = SSH_IPH4_HDRLEN + SSH_TCPH_HDRLEN;
    }

  /* Rate limit the responses to something sensible */
  if (ssh_engine_response_rate_limit(engine, &pc->src, &pc->dst,
                                     SSH_IPPROTO_TCP,
                                     dst_port, src_port,
                                     rate_limit_id))
    goto dontsend;

  rec = ssh_calloc(1, sizeof(*rec));
  if (rec == NULL)
    goto dontsend;

  rec->pp_flags = pp->flags;
  rec->ifnum = pp->ifnum_in;
  rec->routing_instance_id = pp->routing_instance_id;
  rec->protocol = protocol;
  rec->src = pc->src;
  rec->prev_transform_index = pc->prev_transform_index;
  rec->tcp_flags = tcp_flags;
  rec->src_port = src_port;
  rec->dst_port = dst_port;
  rec->ack_num = ack_num;
  rec->seq_num = seq_num;
  rec->new_hdrlen = new_hdrlen;
#if defined (WITH_IPV6)
  rec->ipv6_flow = ipv6_flow;
#endif /* WITH_IPV6 */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  memcpy(rec->extension, pp->extension, sizeof(rec->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* The TCP RST is sent with a source address of the original destination.
     This is because the packet may have arrived via an ESP tunnel and the
     sender of the packet may think that the correct route is direct and
     will ignore any TCP RST's from us unless they have a sourceaddress of
     the original destination */
  ssh_engine_send_tcp_rst_cb(engine, SSH_PME_ROUTE_REACHABLE,
                             &pc->dst, &pc->dst, pp->ifnum_in, pp->pmtu, rec);
  return;

 dontsend:
  SSH_DEBUG(SSH_D_HIGHOK, ("TCP RST not sent"));

  SSH_ASSERT(rec == NULL);
  return;
}
