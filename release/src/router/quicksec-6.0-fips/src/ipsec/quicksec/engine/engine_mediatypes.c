/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Media type handling for the engine.  This primarily handles media header
   construction.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineMediatypes"

/* Copy transform data to the packet context and submit the packet to the
   fastpath for transform execution. */
static void
engine_mediatypes_fastpath_execute(SshEngine engine,
                                   SshEnginePacketContext pc)
{
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  if (!ssh_engine_copy_transform_data(engine, pc))
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Execute any transforms for the packet now.  This will send it out. */
  engine_packet_continue(pc, SSH_ENGINE_RET_EXECUTE);
}

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* Keep broken compilers that don't like empty source files happy. */
int ssh_engine_mediatypes_dummy;

#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Constructs a media header for the given media type.  This returns the
   length of the media header (0 if no media header).  This also sets
   `*min_packet_len_return' to the minimum length of a packet when it is
   sent out (any packets shorter than that are padded with zeroes at the end
   to make them minimum length; 0 is returned if there is no minimum).
   The `mediahdr' buffer should be at least SSH_MAX_MEDIAHDR_SIZE bytes.
   When the media header is inserted on a packet, the resulting packet is
   of protocol `*protocol_return' (SSH_PROTOCOL_OTHER if it is not to be
   changed). */

size_t ssh_engine_make_media_header(SshInterceptorMedia mediatype,
                                    const unsigned char *src,
                                    const unsigned char *dst,
                                    SshUInt16 ethertype,
                                    unsigned char *mediahdr,
                                    size_t *min_packet_len_return,
                                    SshInterceptorProtocol *protocol_return)
{
  switch (mediatype)
    {
    case SSH_INTERCEPTOR_MEDIA_PLAIN:
      *protocol_return = SSH_PROTOCOL_OTHER;
      *min_packet_len_return = 0;
      return 0;
    case SSH_INTERCEPTOR_MEDIA_ETHERNET:
      *protocol_return = SSH_PROTOCOL_ETHERNET;
      *min_packet_len_return = 60;
      memcpy(mediahdr + SSH_ETHERH_OFS_DST, dst, SSH_ETHERH_ADDRLEN);
      memcpy(mediahdr + SSH_ETHERH_OFS_SRC, src, SSH_ETHERH_ADDRLEN);
      SSH_PUT_16BIT(mediahdr + SSH_ETHERH_OFS_TYPE, ethertype);
      return SSH_ETHERH_HDRLEN;



    default:
      SSH_DEBUG(SSH_D_ERROR, ("unsupported media type %d", (int)mediatype));
      *protocol_return = SSH_PROTOCOL_OTHER;
      *min_packet_len_return = 0;
      return 0;
    }
}

/* Updates a media header for the given media type.  This returns the
   length of the media header (0 if no media header).  This also sets
   `*min_packet_len_return' to the minimum length of a packet when it is
   sent out (any packets shorter than that are padded with zeroes at the end
   to make them minimum length; 0 is returned if there is no minimum).
   The `mediahdr' buffer should be at least SSH_MAX_MEDIAHDR_SIZE bytes.
   When the media header is inserted on a packet, the resulting packet is
   of protocol `*protocol_return' (SSH_PROTOCOL_OTHER if it is not to be
   changed). */

size_t ssh_engine_modify_media_header(SshInterceptorMedia mediatype,
                                      const unsigned char *src,
                                      const unsigned char *dst,
                                      SshUInt16 ethertype,
                                      unsigned char *mediahdr)
{
  switch (mediatype)
    {
    case SSH_INTERCEPTOR_MEDIA_PLAIN:
      return 0;

    case SSH_INTERCEPTOR_MEDIA_ETHERNET:
      if (dst)
        memcpy(mediahdr + SSH_ETHERH_OFS_DST, dst, SSH_ETHERH_ADDRLEN);

      if (src)
        memcpy(mediahdr + SSH_ETHERH_OFS_SRC, src, SSH_ETHERH_ADDRLEN);

      if (ethertype)
        SSH_PUT_16BIT(mediahdr + SSH_ETHERH_OFS_TYPE, ethertype);

      return SSH_ETHERH_HDRLEN;



    default:
      SSH_DEBUG(SSH_D_ERROR, ("unsupported media type %d", (int)mediatype));
      return 0;
    }
}

/* This function encapsulates the packet into an ethernet header, taking the
   source and destination ethernet addresses from `src' and `dst',
   respectively, and ethernet type field from `ethertype', and sends it
   out to the network (interface pp->ifnum_out, direction indicated by
   pp->flags).  This frees pp. */

void ssh_engine_encapsulate_and_send(SshEngine engine,
                                     SshInterceptorPacket pp,
                                     const unsigned char *src,
                                     const unsigned char *dst,
                                     SshUInt16 ethertype)
{
  SshEnginePacketContext pc;
  unsigned char *ucp;
  size_t pad, packet_len, min_packet_len, media_hdr_len;
  SshUInt32 ifnum;
  SshInterceptorMedia mediatype;
  SshInterceptorProtocol protocol;
  SshInterceptorInterface *ifp;
  unsigned char mediahdr[SSH_MAX_MEDIAHDR_SIZE];
  SshUInt16 mtu;

  ifnum = pp->ifnum_out;

  SSH_DEBUG(5, ("encapsulating ifnum=%d flags=0x%x type=%04x",
                (int) ifnum, (unsigned int) pp->flags,
                ethertype));

  /* Check ifnum and get the interface type. */



  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);

  if (ifp == NULL
      || ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("trying to send to invalid interface"));
      ssh_interceptor_packet_free(pp);
      return;
    }

  if (pp->flags & SSH_PACKET_FROMADAPTER)
    {
      mediatype = ifp->to_protocol.media;
      mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_protocol, FALSE);
    }
  else
    {
      mediatype = ifp->to_adapter.media;
      mtu = SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter, FALSE);
    }

  if (mtu == 0)
    {
      /* No point sending the packet anywhere, mtu is zero, we drop
         the packet. */
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("MTU 0 received from interface information."
                             "Dropping packet 0x%p.", pp));
      ssh_interceptor_packet_free(pp);
      return;
    }

  SSH_DEBUG(SSH_D_MIDOK,
            ("selected %d (to %d from %d",
             mediatype, ifp->to_protocol.media, ifp->to_adapter.media));

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Construct a media header for it. */
  media_hdr_len = ssh_engine_make_media_header(mediatype, src, dst, ethertype,
                                               mediahdr,
                                               &min_packet_len,
                                               &protocol);

  /* If the packet is too short, pad it to the minimum length. */
  packet_len = ssh_interceptor_packet_len(pp);
  if (packet_len + media_hdr_len < min_packet_len)
    {
      pad = min_packet_len - packet_len - media_hdr_len;
      ucp = ssh_interceptor_packet_insert(pp, packet_len, pad);
      if (ucp == NULL)
        return;
      memset(ucp, 0, pad);
      packet_len = min_packet_len;
    }

#ifdef DEBUG_LIGHT
  /* Check if the packet is oversized for ethernet.  This could indicate a
     problem in fragmentation or mtu code. */
  if (mediatype == SSH_INTERCEPTOR_MEDIA_ETHERNET && packet_len > 1500)
    {
      /* Display a warning about sending an oversized packet.  This should
         never happen in normal operation. */
      ssh_warning("Sending oversized ethernet packet of %d bytes",
                  (int)packet_len);
    }
#endif /* DEBUG_LIGHT */

  /* Add media header. */
  ucp = ssh_interceptor_packet_insert(pp, 0, media_hdr_len);
  if (ucp == NULL)
    return;
  memcpy(ucp, mediahdr, media_hdr_len);

  /* Change pp protocol to the media header protocol if a media header
     was added. */
  if (protocol != SSH_PROTOCOL_OTHER)
    {
      pp->protocol = protocol;
      SSH_ASSERT(media_hdr_len > 0);
    }

  /* Allocate and initialize a packet context. */
  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate a packet context"));
      ssh_interceptor_packet_free(pp);
      return;
    }
  ssh_engine_init_pc(pc, engine, pp, 0, NULL);

  /* Initialize the flow part of the pc. */
  memset(&pc->u.flow, 0, sizeof(pc->u.flow));
  pc->u.flow.ifnum = pc->pp->ifnum_out;
  pc->u.flow.mtu = mtu;
  pc->u.flow.media_hdr_len = (SshUInt8) media_hdr_len;
  pc->u.flow.media_protocol = protocol;

  /* Set packet length, protocol offset and media header length. */
  pc->flags = 0;
  pc->packet_len = packet_len;
  pc->media_hdr_len = (SshUInt8) media_hdr_len;

  /* Send the packet out.  This frees pp. */
  fastpath_packet_continue(engine->fastpath, pc, SSH_ENGINE_RET_SEND);
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* (internal function) This function is called when the ARP lookup
   being performed by ssh_engine_send_packet
   (ssh_engine_send_route_cb) completes. */
void ssh_engine_send_arp_cb(SshEnginePacketContext pc,
                            SshEngineArpLookupStatus status,
                            const unsigned char *src,
                            const unsigned char *dst,
                            SshUInt16 ethertype)
{
  size_t min_packet_len;
  SshInterceptorProtocol protocol;

  /* Check if the lookup failed. */
  if (status != SSH_ENGINE_ARP_LOOKUP_STATUS_OK)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      SSH_DEBUG(SSH_D_HIGHOK, ("ARP failed during send packet"));
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  SSH_ASSERT(src != NULL);
  SSH_ASSERT(dst != NULL);

  /* Construct a media header and save required information in the
     packet context. */

  pc->u.flow.media_hdr_len = (SshUInt8)
    ssh_engine_make_media_header(pc->u.flow.mediatype, src, dst, ethertype,
                                 pc->u.flow.mediahdr,
                                 &min_packet_len, &protocol);
  pc->u.flow.min_packet_len = (SshUInt8) min_packet_len;
  pc->u.flow.media_protocol = protocol;

  /* Send the packet out now. */
  engine_mediatypes_fastpath_execute(pc->engine, pc);
}


/* (internal function) This function is called when the source ARP
   lookup being performed by ssh_engine_send_packet
   (ssh_engine_send_src_route_cb) completes. */
void ssh_engine_send_src_arp_cb(SshEnginePacketContext pc,
                                SshEngineArpLookupStatus status,
                                const unsigned char *src,
                                const unsigned char *dst,
                                SshUInt16 ethertype)
{
  /* Swap 'src' and 'dst' (because we just performed ARP lookup for the
     source IP address) and let ssh_engine_send_arp_cb() rest of the
     processing. */
  ssh_engine_send_arp_cb(pc, status, dst, src, ethertype);
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* (internal function) This function is called when the route lookup being
   performed by ssh_engine_send_packet completes. */

void ssh_engine_send_route_cb(SshEngine engine, SshUInt32 flags,
                              const SshIpAddr dst,
                              const SshIpAddr next_hop_gw,
                              SshEngineIfnum ifnum,
                              SshVriId routing_instance_id,
                              size_t mtu,
                              void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshInterceptorInterface *ifp;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  Boolean dst_is_local;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* If the destination is not reachable, drop the packet. */
  if (!(flags & SSH_PME_ROUTE_REACHABLE))
    {
      SSH_DEBUG(SSH_D_FAIL, ("host not reachable"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  /* We never send broadcasts (a packet with source address being directed
     broadcast address could get us here). */
  if (flags & SSH_PME_ROUTE_LINKBROADCAST)
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      SSH_DEBUG(SSH_D_FAIL, ("will not send to link broadcast"));
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  ssh_kernel_mutex_lock(engine->interface_lock);
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (ifp != NULL)
    {
      size_t ifmtu = 0;

      /* Prefer always IPv4 in MTU selection
         (i.e. dst is not defined / does not exist). */
      if ((pc->pp->flags & SSH_PACKET_FROMADAPTER) == 0)
        {
          ifmtu =
            SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_protocol,
                                           (dst ? SSH_IP_IS6(dst) : FALSE));
        }
      else
        {
          ifmtu =
            SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_adapter,
                                           (dst ? SSH_IP_IS6(dst) : FALSE));
        }

      if (mtu == 0 || (ifmtu < mtu && ifmtu != 0))
        mtu = ifmtu;

    }
  ssh_kernel_mutex_unlock(engine->interface_lock);

  pc->u.flow.mtu = (SshUInt16) mtu;
  pc->u.flow.ifnum = ifnum;

  /* This packet is going to stack. */
  if (pc->pp->flags & SSH_PACKET_FROMADAPTER)
    pc->u.flow.local = 1;
  /* Packet destination is local, send to stack. */
  else if (flags & SSH_PME_ROUTE_LOCAL)
    pc->u.flow.local = 1;
  /* This packet is going to network. */
  else
    pc->u.flow.local = 0;

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR

  /* Send the packet out now. */
  engine_mediatypes_fastpath_execute(engine, pc);
  return;

#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (ssh_engine_ip_is_local(engine, dst)
      || ssh_engine_ip_is_broadcast(engine, dst))
    dst_is_local = TRUE;
  else
    dst_is_local = FALSE;

  /* Get the media type of the destination interface. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (ifp == NULL
      || ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("invalid destination interface %d",
                             (int)ifnum));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  if (dst_is_local)
    pc->u.flow.mediatype = ifp->to_protocol.media;
  else
    pc->u.flow.mediatype = ifp->to_adapter.media;

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* Check if this is a plain IP interface.  If so, don't do ARP lookup. */
  if (pc->u.flow.mediatype == SSH_INTERCEPTOR_MEDIA_PLAIN)
    {
      pc->u.flow.media_hdr_len = 0;
      pc->u.flow.min_packet_len = 0;
      pc->u.flow.media_protocol = SSH_PROTOCOL_OTHER;

      /* Send the packet out now. */
      engine_mediatypes_fastpath_execute(engine, pc);
      return;
    }

  /* Check if next hop cache contains a usable entry. */
  if (ssh_engine_get_nh_node_media_header(engine, &pc->src, &pc->dst,
                                          ifnum, SSH_ENGINE_NH_OUTBOUND,
                                          pc->u.flow.mediahdr,
                                          &pc->u.flow.media_hdr_len,
                                          &pc->u.flow.min_packet_len,
                                          &pc->u.flow.media_protocol) == TRUE)
    {
      /* Send the packet out now. */
      engine_mediatypes_fastpath_execute(engine, pc);
      return;
    }

  /* Perform ARP lookup for the packet's next-hop GW. */
  ssh_engine_arp_lookup(pc, next_hop_gw, ifnum, routing_instance_id,
                        SSH_IPSEC_INVALID_INDEX, ssh_engine_send_arp_cb);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
}


void ssh_engine_send_src_route_cb(SshEngine engine, SshUInt32 flags,
                                  const SshIpAddr dst,
                                  const SshIpAddr next_hop_gw,
                                  SshEngineIfnum ifnum,
                                  SshVriId routing_instance_id,
                                  size_t mtu,
                                  void *context)
{
  SshEnginePacketContext pc = (SshEnginePacketContext)context;
  SshInterceptorInterface *ifp;

  /* If the destination is not reachable, drop the packet. */
  if (!(flags & SSH_PME_ROUTE_REACHABLE))
    {
      SSH_DEBUG(SSH_D_FAIL, ("host not reachable"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  /* Get the interface mtu and mediatype. */
  ssh_kernel_mutex_lock(engine->interface_lock);
  ifp = ssh_ip_get_interface_by_ifnum(&engine->ifs, ifnum);
  if (ifp == NULL
      || ifp->to_adapter.media == SSH_INTERCEPTOR_MEDIA_NONEXISTENT)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      SSH_DEBUG(SSH_D_FAIL, ("invalid destination interface %d", (int)ifnum));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ROUTEDROP);
      engine_packet_continue(pc, SSH_ENGINE_RET_FAIL);
      return;
    }

  /* If the dst is not defined, prefer always IPv4. */
  pc->u.flow.mtu =
    SSH_INTERCEPTOR_MEDIA_INFO_MTU(&ifp->to_protocol,
                                   (dst ? SSH_IP_IS6(dst) : FALSE));

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Get the media type of the destination interface. */
  pc->u.flow.mediatype = ifp->to_protocol.media;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ssh_kernel_mutex_unlock(engine->interface_lock);

  pc->u.flow.ifnum = ifnum;
  pc->u.flow.local = 1; /* This packet is going to local stack */

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR

  /* Send the packet out now. */
  engine_mediatypes_fastpath_execute(engine, pc);
  return;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Check if this is a plain IP interface.  If so, don't do ARP lookup. */
  if (pc->u.flow.mediatype == SSH_INTERCEPTOR_MEDIA_PLAIN)
    {
      pc->u.flow.media_hdr_len = 0;
      pc->u.flow.min_packet_len = 0;
      pc->u.flow.media_protocol = SSH_PROTOCOL_OTHER;

      /* Send the packet out now. */
      engine_mediatypes_fastpath_execute(engine, pc);
      return;
    }

  /* Check if next hop cache contains a usable entry. */
  if (ssh_engine_get_nh_node_media_header(engine, &pc->src, &pc->dst,
                                          ifnum,
                                          SSH_ENGINE_NH_INBOUND
                                          | SSH_ENGINE_NH_LOCAL,
                                          pc->u.flow.mediahdr,
                                          &pc->u.flow.media_hdr_len,
                                          &pc->u.flow.min_packet_len,
                                          &pc->u.flow.media_protocol) == TRUE)
    {
      /* Send the packet out now. */
      engine_mediatypes_fastpath_execute(engine, pc);
      return;
    }

  /* Perform ARP lookup for the packet's "sender". */
  ssh_engine_arp_lookup(pc, next_hop_gw, ifnum, routing_instance_id,
                        SSH_IPSEC_INVALID_INDEX, ssh_engine_send_src_arp_cb);
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
}







/* Sends the given packet out using the engine.  This performs any required
   routing and ARP lookups for the packet, and applies the given transform
   on the packet before sending it (if transform_index is not
   SSH_IPSEC_INVALID_INDEX).  This frees pp.  `dst' must be the destination
   IP address of the packet.

   The `packet_len', `hdrlen' `ipproto', `ipsec_offset' and
   `ipsec_offset_prevnh' are copied into the generated
   SshEnginePacketContext and must correspond with the frame in 'pp'.
   The `ipsec_offset' and `ipsec_offset_prevnh' can safely be set to
   zero for IPv6 packets. */

void ssh_engine_send_packet(SshEngine engine,
                            SshInterceptorPacket pp,
                            SshUInt16 hdrlen,
                            SshUInt32 transform_index,
                            const SshIpAddr source,
                            const SshIpAddr target,
                            SshUInt8 ipproto,
                            SshUInt16 ipsec_offset,
                            SshUInt16 ipsec_offset_prevnh,
                            Boolean send_asynch)
{
  SshEnginePacketContext pc;
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  SshUInt16 src_port, dst_port;
  SshUInt32 spi, ifnum;
  SshInterceptorRouteKeyStruct key;
  SshUInt16 route_flags;
  SshUInt32 *extension;

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_ASSERT(source != NULL);
  SSH_ASSERT(target != NULL);

#ifdef SSH_IPSEC_SEND_IS_SYNC
  /* Break callstack and go through a 1 us timeout. This is important
     as e.g. on Linux tcp_synack_timer() holds the spinlock
     for the relevant socket when it sends a packet. If a TCP RST
     packet is sent in response by the engine the lock will be held
     when tcp_v4_rcv() tries to grab it and a deadlock follows. */
  if (send_asynch)
    {
      SshEngineAsynchPacketData data;

      ssh_kernel_mutex_lock(engine->pp_lock);
      data = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEngineAsynchPacketData);

      data->is_icept_send = FALSE;
      data->hdrlen = hdrlen;
      data->transform_index = transform_index;
      data->src = *source;
      data->dst = *target;
      data->ipproto = ipproto;
      data->ipsec_offset = ipsec_offset;
      data->ipsec_offset_prevnh = ipsec_offset_prevnh;

      /* Queue packet for the list of pending asynch packets. */
      pp->next = NULL;
      if (engine->asynch_packets_tail)
        engine->asynch_packets_tail->next = pp;
      else
        engine->asynch_packets_head = pp;
      engine->asynch_packets_tail = pp;

      if (!engine->asynch_timeout_scheduled)
        {
          engine->asynch_timeout_scheduled = TRUE;
          ssh_kernel_mutex_unlock(engine->pp_lock);
          ssh_kernel_timeout_register(0, 1,
                                      ssh_engine_process_asynch_packets,
                                      engine);
        }
      else
        {
          ssh_kernel_mutex_unlock(engine->pp_lock);
        }
      return;
    }
#endif /* SSH_IPSEC_SEND_IS_SYNC */

  pc = ssh_engine_alloc_pc(engine);
  if (pc == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return;
    }

  /* Initialize the new pc. */
  if (!ssh_engine_init_and_pullup_pc(pc, engine, pp, 0,
                                     SSH_IPSEC_INVALID_INDEX))
    {
      if (pc->pp)
        ssh_interceptor_packet_free(pc->pp);
      ssh_engine_free_pc(engine, pc);
      return;
    }

  src = *source;
  dst = *target;
  ipproto = pc->ipproto;
  src_port = pc->u.rule.src_port;
  dst_port = pc->u.rule.dst_port;
  spi = pc->u.rule.spi;

  /* This is the inbound ifnum of the violating packet. */
  ifnum = pc->pp->ifnum_in;
  route_flags = SSH_INTERCEPTOR_ROUTE_KEY_OUT_IFNUM;

  /* If the original packet arrived through a transform, apply the
     same transform to the new packet. Get the routing information to
     the actual destination (access this from the transform) */

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  pc->transform_index = transform_index;
  if (transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      SshEngineTransformData d_trd;

      route_flags |= SSH_INTERCEPTOR_ROUTE_KEY_FLAG_TRANSFORM_APPLIED;
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, transform_index);
      if (d_trd->transform & SSH_PM_IPSEC_TUNNEL)
        {
          dst = d_trd->gw_addr;
          src = d_trd->own_addr;
          ifnum = d_trd->own_ifnum;
        }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      if (d_trd->transform & SSH_PM_IPSEC_NATT)
        {
          ipproto = SSH_IPPROTO_UDP;
          src_port = d_trd->local_port;
          dst_port = d_trd->remote_port;
        }
      else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
      if (d_trd->transform & SSH_PM_IPSEC_ESP)
        {
          ipproto = SSH_IPPROTO_ESP;
          spi = d_trd->spis[SSH_PME_SPI_ESP_OUT];
        }
      else if (d_trd->transform & SSH_PM_IPSEC_AH)
        {
          ipproto = SSH_IPPROTO_AH;
          spi = d_trd->spis[SSH_PME_SPI_AH_OUT];
        }
      else if (d_trd->transform & SSH_PM_IPSEC_IPCOMP)
        {
          ipproto = SSH_IPPROTO_IPPCP;
          spi = d_trd->spis[SSH_PME_SPI_IPCOMP_OUT];
        }

      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  extension = pp->extension;
#else /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
  extension = NULL;
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* If the destination interface is local or all the packets are to
     be forwarded through local stack, we always go here. */
  if (ssh_engine_ip_is_local(engine, &dst) ||
      ((pc->pp->flags & SSH_PACKET_FROMADAPTER) &&
       (engine->flags & SSH_ENGINE_NO_FORWARDING)))
    {
      /* Perform route lookup for the source. */
      ssh_engine_create_route_key(engine, &key, pc, &dst, &src, ipproto,
                                  dst_port, src_port, spi,
                                  (SshEngineIfnum) ifnum, route_flags,
                                  extension, pc->pp->routing_instance_id);
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->route_selector = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_send_src_route_cb, (void *) pc);
    }
  else
    {
      /* Perform route lookup for the destination. */
      ssh_engine_create_route_key(engine, &key, pc, &src, &dst, ipproto,
                                  src_port, dst_port, spi,
                                  (SshEngineIfnum) ifnum, route_flags,
                                  extension, pc->pp->routing_instance_id);
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      pc->route_selector = key.selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ssh_interceptor_packet_detach(pc->pp);
      ssh_engine_route(engine, 0, &key, TRUE,
                       ssh_engine_send_route_cb, (void *) pc);
    }
}
