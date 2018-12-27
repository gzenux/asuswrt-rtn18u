/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Path MTU discovery for IPSec flows.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */

#define SSH_DEBUG_MODULE "SshEnginePmtu"

/* The default PMTU aging time-to-live in seconds. */
#define SSH_ENGINE_PMTU_DEFAULT_TTL     600

/* Information about a path MTU discovery ICMP message.  The following
   data is extracted from the offending packet which is included in
   the incoming ICMP packet.*/
struct SshEnginePmtuIcmpInfoRec
{
#ifdef DEBUG_LIGHT
  /* The source and destination addresses of the ICMP message. */
  SshIpAddrStruct icmp_src;
  SshIpAddrStruct icmp_dst;
#endif /* DEBUG_LIGHT */

  /* Flags. */
  unsigned int update_pmtu : 1;      /* Update PMTU based on this info. */
  unsigned int pass_to_stack : 1;    /* Let PMTU message continue to stack. */

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* UDP destination port. */
  SshUInt16 natt_dst_port;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Source address. */
  SshIpAddrStruct src;

  /* Destination address. */
  SshIpAddrStruct dst;

  /* IP Protocol. */
  SshInetIPProtocolID ipproto;

#ifdef DEBUG_LIGHT
  /* AH/ESP/IPPCP SPI value. */
  SshUInt32 spi;
#endif /* DEBUG_LIGHT */

  /* The next-hop MTU. */
  SshUInt32 mtu;

  /* The length of the packet. */
  size_t length;

  /* The header length of the packet. */
  size_t hlen;
};

typedef struct SshEnginePmtuIcmpInfoRec SshEnginePmtuIcmpInfoStruct;
typedef struct SshEnginePmtuIcmpInfoRec *SshEnginePmtuIcmpInfo;

/* The common MTU values in the Internet.  These `plateau' values are
   taken from the RFC 1191.  */
static const SshUInt16 ssh_engine_common_mtus[] =
{
  65535,
  32000,
  17914,
  8166,
  4352,
  2002,
  1492,
  1006,
  508,
  296,
  68,
  0,
};

/* Extract path MTU information from the IPv4 packet `pc'. */
SshEngineActionRet
ssh_engine_pmtu_extract_icmp_info(SshEngine engine,
                                  SshEnginePacketContext pc,
                                  SshEnginePmtuIcmpInfo info)
{
  size_t offending_packet_len;
  unsigned char *packet_start;
  unsigned char offending_packet_hdr[SSH_IPH4_HDRLEN];
  SshUInt8 icmp_code;
#ifdef DEBUG_LIGHT
  unsigned char offending_packet_payload[8];
  SshUInt8 ipproto;
  SshUInt8 icmp_type;
#endif /* DEBUG_LIGHT */

  SSH_ASSERT(pc->pp->protocol == SSH_PROTOCOL_IP4);

  SSH_ASSERT(pc->packet_len >= pc->hdrlen + 8);
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  info->update_pmtu = 0;
  info->pass_to_stack = 0;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  info->natt_dst_port = 0;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  packet_start = ssh_interceptor_packet_pullup(pc->pp, pc->hdrlen + 8);
  if (packet_start == NULL)
    {
      pc->pp = NULL;
      goto drop;
    }

#ifdef DEBUG_LIGHT
  /* It must be a valid PMTU ICMP packet.  This is already checked
     earlier. */
  ipproto = SSH_IPH4_PROTO(packet_start);
  SSH_ASSERT(ipproto == SSH_IPPROTO_ICMP);

  /* Save the source and destination addresses of the ICMP packet. */
  SSH_IPH4_SRC(&info->icmp_src, packet_start);
  SSH_IPH4_DST(&info->icmp_dst, packet_start);

  /* It must be a ICMP unreachable message. */
  icmp_type = SSH_ICMPH_TYPE(packet_start + pc->hdrlen);
  SSH_ASSERT(icmp_type == SSH_ICMP_TYPE_UNREACH);
#endif /* DEBUG_LIGHT */

  /* Check that the packet is a ICMP unreachable frag needed message. */
  icmp_code = SSH_ICMPH_CODE(packet_start + pc->hdrlen);
  if (icmp_code != SSH_ICMP_CODE_UNREACH_NEEDFRAG)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Message not PMTU: ICMP type %d code %d",
                              icmp_type, icmp_code));
      /* Nothing we should be concerned about. */
      return SSH_ENGINE_RET_OK;
    }

  /* Extract the reported MTU. */
  info->mtu = SSH_GET_16BIT(packet_start + pc->hdrlen + 6);

  /* Get the header of the included offending packet. */
  offending_packet_len = pc->packet_len - pc->hdrlen - 8;
  if (offending_packet_len < SSH_IPH4_HDRLEN)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("The included offending packet is too short to contain "
                 "IP header"));
      goto drop;
    }
  ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen + 8, offending_packet_hdr,
                                 SSH_IPH4_HDRLEN);

  /* Check the type of the included offending packet.  We just check
     the needed fields without any extra sanity checks.  The ICMP
     messages can be spoofed anyway so it does not help to calculate
     the checksums, etc. */
  info->hlen = SSH_IPH4_HLEN(offending_packet_hdr) << 2;
  info->length = SSH_IPH4_LEN(offending_packet_hdr);
  info->ipproto = (SshInetIPProtocolID) SSH_IPH4_PROTO(offending_packet_hdr);
  SSH_IPH4_SRC(&info->src, offending_packet_hdr);
  SSH_IPH4_DST(&info->dst, offending_packet_hdr);

  /* We are only interested in ESP, AH, IPPCP, and NAT-T UDP
     packets. */
  if (info->ipproto != SSH_IPPROTO_ESP && info->ipproto != SSH_IPPROTO_AH
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      && info->ipproto != SSH_IPPROTO_UDP
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSH_IPSEC_TCPENCAP
      && info->ipproto != SSH_IPPROTO_TCP
#endif /* SSH_IPSEC_TCPENCAP */
      && info->ipproto != SSH_IPPROTO_IPPCP)
    {
      /* Nothing we should be concerned about. */
      return SSH_ENGINE_RET_OK;
    }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (info->ipproto == SSH_IPPROTO_UDP)
    {
      SshUInt16 src_port;
      SshUInt16 dst_port;
      Boolean is_ike, is_ike_natt;
      int i;

      /* How much payload of the offending packet do we have?
         Depending on the NAT-T draft version, we need 4 or 8 bytes in
         addition to the UDP header. */
      if (offending_packet_len < info->hlen + SSH_UDPH_HDRLEN)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("The included offending packet is too short to contain "
                     "NAT-T UDP header"));
          goto drop;
        }

      /* Fetch UDP header. */
      ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen + 8 + info->hlen,
                                     offending_packet_hdr, SSH_UDPH_HDRLEN);

      /* Check if either of the ports gives us any hints about the
         NAT-T draft version. */

      src_port = SSH_UDPH_SRCPORT(offending_packet_hdr);
      dst_port = SSH_UDPH_DSTPORT(offending_packet_hdr);

      is_ike = is_ike_natt = FALSE;
      for (i = 0; i < engine->num_ike_ports; i++)
        {
          if (dst_port == engine->local_ike_ports[i]
              || src_port == engine->local_ike_ports[i])
            {
              is_ike = TRUE;
              break;
            }
          if (dst_port == engine->local_ike_natt_ports[i]
              || src_port == engine->local_ike_natt_ports[i])
            {
              is_ike_natt = TRUE;
              break;
            }
        }

      if (is_ike)
        {
          /* Pass PMTU message to local stack after updating transforms. */
          info->pass_to_stack = 1;

          /* Draft version 0 or 1.  We need 8 bytes of UDP payload. */
          if (offending_packet_len < info->hlen + SSH_UDPH_HDRLEN + 8)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Not enough offending packet data for checking the "
                         "non-ESP marker"));
            }
          else
            {
              ssh_interceptor_packet_copyout(pc->pp,
                                             (pc->hdrlen + 8 + info->hlen
                                              + SSH_UDPH_HDRLEN),
                                             offending_packet_hdr, 8);
              if (memcmp(offending_packet_hdr, "\0\0\0\0\0\0\0\0", 8) != 0)
                /* It was not a Non-IKE Marker. */
                goto natt_some_other_udp_pmtu;
            }
        }
      else if (is_ike_natt)
        {
          /* Pass PMTU message to local stack after updating transforms. */
          info->pass_to_stack = 1;

          /* Draft version 2, 3, or RFC.  We need 4 bytes of UDP
             payload. */
          if (offending_packet_len < info->hlen + SSH_UDPH_HDRLEN + 4)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Not enough offending packet data for checking the "
                         "non-ESP marker"));
            }
          else
            {
              ssh_interceptor_packet_copyout(pc->pp,
                                             (pc->hdrlen + 8 + info->hlen
                                              + SSH_UDPH_HDRLEN),
                                             offending_packet_hdr, 4);
              if (memcmp(offending_packet_hdr, "\0\0\0\0", 4) == 0)
                /* It was a Non-ESP Marker. */
                goto natt_some_other_udp_pmtu;
            }
        }
      else
        {
          /* We really can not say.  Let's assume that it is a PMTU
             ICMP for some other UDP traffic. */
        natt_some_other_udp_pmtu:
          return SSH_ENGINE_RET_OK;
        }

      /* Store UDP destination port. */
      info->natt_dst_port = dst_port;
    }
  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSH_IPSEC_TCPENCAP
  if (info->ipproto == SSH_IPPROTO_TCP)
    {
      SshUInt16 src_port;
      SshUInt16 dst_port;
      SshUInt32 conn_id;

      /* How much payload of the offending packet do we have?
         We need 4 bytes in addition to the TCP header. */
      if (offending_packet_len < (info->hlen + SSH_TCPH_HDRLEN + 4
                                  + SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN))
        {
          /* Not enough bytes, assume the PMTU ICMP
             was for some other TCP packet */
          goto tcp_encap_out;
        }

      /* Pullup TCP ports */
      ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen + 8 + info->hlen,
                                     offending_packet_hdr, SSH_TCPH_HDRLEN);
      src_port = SSH_TCPH_SRCPORT(offending_packet_hdr);
      dst_port = SSH_TCPH_DSTPORT(offending_packet_hdr);

      /* Lookup encapsulating TCP connection. */
      conn_id = ssh_engine_tcp_encaps_conn_by_pmtu_info(engine,
                                                        &info->dst,
                                                        &info->src,
                                                        dst_port,
                                                        src_port);
      if (conn_id == SSH_IPSEC_INVALID_INDEX)
        {
          /* The PMTU ICMP is not related to any of the active
             encapsulating TCP connections. */
        tcp_encap_out:
          return SSH_ENGINE_RET_OK;
        }
      /* Fall through */
    }
  else
#endif /* SSH_IPSEC_TCPENCAP */
    {
#ifdef DEBUG_LIGHT
      /* Fetch the 64 bits of the payload of the offending packet.
         The 64 bits is the minimum amount that must be included in
         the packet. */
      if (offending_packet_len < info->hlen + 8)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("The included offending packet does not contain the"
                     "first 64 bits of the payload"));
          goto drop;
        }
      ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen + 8 + info->hlen,
                                     offending_packet_payload, 8);

      /* Fetch the SPI value by type. */
      switch (info->ipproto)
        {
        case SSH_IPPROTO_ESP:
          info->spi = SSH_GET_32BIT(offending_packet_payload + 0);
          break;

        case SSH_IPPROTO_AH:
          info->spi = SSH_GET_32BIT(offending_packet_payload + 4);
          break;

        case SSH_IPPROTO_IPPCP:
          info->spi = (SshUInt32) SSH_GET_16BIT(offending_packet_payload + 2);
          break;

        default:
          SSH_NOTREACHED;
          goto drop;
        }
#endif /* DEBUG_LIGHT */
    }

  /* We managed to extract all necessary fields. */
  info->update_pmtu = 1;

  return SSH_ENGINE_RET_OK;


  /* Error handling. */

 drop:
  if (pc->pp)
    ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;
  return SSH_ENGINE_RET_ERROR;
}


#if defined (WITH_IPV6)
/* Extract path MTU information from the IPv6 packet `pc'. */
SshEngineActionRet
ssh_engine_pmtu_extract_icmpv6_info(SshEngine engine,
                                    SshEnginePacketContext pc,
                                    SshEnginePmtuIcmpInfo info)
{
  SshUInt32 offset;
  unsigned char buf[SSH_IPH6_HDRLEN];

  SSH_ASSERT(pc->pp->protocol == SSH_PROTOCOL_IP6);
  SSH_ASSERT(pc->ipproto == SSH_IPPROTO_IPV6ICMP);
  SSH_ASSERT(pc->icmp_type == SSH_ICMP6_TYPE_TOOBIG);

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  info->update_pmtu = 0;
  info->pass_to_stack = 0;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  info->natt_dst_port = 0;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  if (pc->packet_len < pc->hdrlen + 8)
    goto droptooshort;
  ssh_interceptor_packet_copyout(pc->pp, pc->hdrlen + 4, buf, 4);
  info->mtu = SSH_GET_32BIT(buf);

#ifdef DEBUG_LIGHT
  /* Save the source and destination addresses of the ICMP packet. */
  info->icmp_src = pc->src;
  info->icmp_dst = pc->dst;
#endif /* DEBUG_LIGHT */

  offset = pc->hdrlen + 8;
  if (offset + SSH_IPH6_HDRLEN >= pc->packet_len)
    goto droptooshort;
  ssh_interceptor_packet_copyout(pc->pp, offset, buf, SSH_IPH6_HDRLEN);
  info->length = SSH_IPH6_LEN(buf);
  SSH_IPH6_SRC(&info->src, buf);
  SSH_IPH6_DST(&info->dst, buf);
  info->ipproto = SSH_IPH6_NH(buf);
  offset += SSH_IPH6_HDRLEN;

 next_header:
  switch (info->ipproto)
    {
    case 0:             /* Hop-by-hop header. */
      if (offset + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN >= pc->packet_len)
        goto droptooshort;
      ssh_interceptor_packet_copyout(pc->pp, offset, buf, 2);
      info->ipproto = SSH_IP6_EXT_COMMON_NH(buf);
      offset += SSH_IP6_EXT_COMMON_LENB(buf);
      goto next_header;
      break;

    case SSH_IPPROTO_IPV6ROUTE: /* Routing header. */
      {
        SshUInt32 i, ext_hdr_len;

        if (offset + SSH_IP6_EXT_ROUTING_HDRLEN >= pc->packet_len)
          goto droptooshort;
        ssh_interceptor_packet_copyout(pc->pp, offset, buf,
                                       SSH_IP6_EXT_ROUTING_HDRLEN);
        info->ipproto = SSH_IP6_EXT_ROUTING_NH(buf);
        i = SSH_IP6_EXT_ROUTING_LEN(buf);
        if (i & 0x1)
          goto drop;
        ext_hdr_len = 8 + 8 * i;
        if (i != 0)
          {
            SshUInt32 n_addrs = i >> 1;
            SshUInt32 n_segs = SSH_IP6_EXT_ROUTING_SEGMENTS(buf);

            if (n_segs > n_addrs)
              goto drop;
            if (offset + 8 + n_addrs * 16 > pc->packet_len)
              goto droptooshort;
            ssh_interceptor_packet_copyout(pc->pp, offset + n_addrs * 16 - 8,
                                           buf, 16);
            SSH_IP6_DECODE(&info->dst, buf);
          }
        offset += ext_hdr_len;
      }
      goto next_header;
      break;

    case SSH_IPPROTO_IPV6FRAG:
      if (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN > pc->packet_len)
        goto drop;
      ssh_interceptor_packet_copyout(pc->pp, offset, buf,
                                     SSH_IP6_EXT_FRAGMENT_HDRLEN);
      if (SSH_IP6_EXT_FRAGMENT_OFFSET(buf) != 0)
        /* ICMPv6 for non-first fragment.  Drop the message. */
        goto drop;
      offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
      info->ipproto = SSH_IP6_EXT_FRAGMENT_NH(buf);
      goto next_header;
      break;

    case SSH_IPPROTO_IPV6OPTS: /* Destination options header. */
      if (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN > pc->packet_len)
        goto drop;
      ssh_interceptor_packet_copyout(pc->pp, offset, buf, 2);
      offset += SSH_IP6_EXT_DSTOPTS_LENB(buf);
      info->ipproto = SSH_IP6_EXT_DSTOPTS_NH(buf);
      goto next_header;
      break;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
    case SSH_IPPROTO_UDP:
      {
        SshUInt16 src_port;
        SshUInt16 dst_port;
        Boolean is_ike, is_ike_natt;
        int i;

        /* Fetch UDP header. */
        if (offset + SSH_UDPH_HDRLEN > pc->packet_len)
          {
            SSH_DEBUG(SSH_D_ERROR,
                      ("The included offending packet is too short to contain "
                       "NAT-T UDP header"));
            goto drop;
          }
        ssh_interceptor_packet_copyout(pc->pp, offset, buf, SSH_UDPH_HDRLEN);

        /* Check if either of the ports gives us any hints about the
           NAT-T draft version. */
        src_port = SSH_UDPH_SRCPORT(buf);
        dst_port = SSH_UDPH_DSTPORT(buf);

        is_ike = is_ike_natt = FALSE;
        for (i = 0; i < engine->num_ike_ports; i++)
          {
            if (dst_port == engine->local_ike_ports[i]
                || src_port == engine->local_ike_ports[i])
              {
                is_ike = TRUE;
                break;
              }
            if (dst_port == engine->local_ike_natt_ports[i]
                || src_port == engine->local_ike_natt_ports[i])
              {
                is_ike_natt = TRUE;
                break;
              }
          }

        if (is_ike)
          {
            /* Pass PMTU message to local stack after updating transforms. */
            info->pass_to_stack = 1;

            /* Draft version 0 or 1.  We need 8 bytes of UDP payload. */
            if (offset + SSH_UDPH_HDRLEN + 8 > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Not enough offending packet data for checking the "
                           "non-ESP marker"));
              }
            else
              {
                ssh_interceptor_packet_copyout(pc->pp,
                                               offset + SSH_UDPH_HDRLEN,
                                               buf, 8);
                if (memcmp(buf, "\0\0\0\0\0\0\0\0", 8) != 0)
                  /* It was not a Non-IKE Marker. */
                  goto natt_some_other_udp_pmtu;
              }
          }
        else if (is_ike_natt)
          {
            /* Pass PMTU message to local stack after updating transforms. */
            info->pass_to_stack = 1;

            /* Draft version 2, 3, or RFC.  We need 4 bytes of UDP
               payload. */
            if (offset + SSH_UDPH_HDRLEN + 4 > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Not enough offending packet data for checking the "
                           "non-ESP marker"));
              }
            else
              {
                ssh_interceptor_packet_copyout(pc->pp,
                                               offset + SSH_UDPH_HDRLEN + 8,
                                               buf, 4);
                if (memcmp(buf, "\0\0\0\0", 4) == 0)
                  /* It was a Non-ESP Marker. */
                  goto natt_some_other_udp_pmtu;
              }
          }
        else
          {
            /* We really can not say.  Let's assume that it is a PMTU
               ICMP for some other UDP traffic. */
          natt_some_other_udp_pmtu:
            return SSH_ENGINE_RET_OK;
          }

        /* Store UDP destination port. */
        info->natt_dst_port = dst_port;

        /* We managed to extract all necessary fields. */
        info->hlen = offset - pc->hdrlen;
        info->update_pmtu = 1;
        return SSH_ENGINE_RET_OK;
      }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#ifdef SSH_IPSEC_TCPENCAP
    case SSH_IPPROTO_TCP:
      {
        SshUInt16 src_port;
        SshUInt16 dst_port;
        SshUInt32 conn_id;

        /* Fetch UDP header. */
        if (offset + SSH_TCPH_HDRLEN > pc->packet_len)
          {
            /* Not enough bytes, assume the PMTU ICMP
               was for some other TCP packet */
            goto tcp_encap_out;
          }

        /* Pullup TCP ports */
        ssh_interceptor_packet_copyout(pc->pp, offset, buf, SSH_TCPH_HDRLEN);
        src_port = SSH_TCPH_SRCPORT(buf);
        dst_port = SSH_TCPH_DSTPORT(buf);

        /* Lookup encapsulating TCP connection. */
        conn_id = ssh_engine_tcp_encaps_conn_by_pmtu_info(engine,
                                                          &info->dst,
                                                          &info->src,
                                                          dst_port,
                                                          src_port);
        if (conn_id == SSH_IPSEC_INVALID_INDEX)
          {
            /* The PMTU ICMP is not related to any of the active
               encapsulating TCP connections. */
          tcp_encap_out:
            return SSH_ENGINE_RET_OK;
          }

        /* We managed to extract all necessary fields. */
        info->hlen = offset - pc->hdrlen;
        info->update_pmtu = 1;
        return SSH_ENGINE_RET_OK;
      }
#endif /* SSH_IPSEC_TCPENCAP */

    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
    case SSH_IPPROTO_IPPCP:
#ifdef DEBUG_LIGHT
      /* Fetch the 64 bits of the payload of the offending packet.
         The 64 bits is the minimum amount that must be included in
         the packet. */
      if (offset + 8 > pc->packet_len)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("The included offending packet does not contain the"
                     "first 64 bits of the payload"));
          goto drop;
        }
      ssh_interceptor_packet_copyout(pc->pp, offset, buf, 8);

      /* Fetch the SPI value by type. */
      switch (info->ipproto)
        {
        case SSH_IPPROTO_ESP:
          info->spi = SSH_GET_32BIT(buf);
          break;

        case SSH_IPPROTO_AH:
          info->spi = SSH_GET_32BIT(buf + 4);
          break;

        case SSH_IPPROTO_IPPCP:
          info->spi = (SshUInt32) SSH_GET_16BIT(buf + 2);
          break;

        default:
          SSH_NOTREACHED;
          goto drop;
        }
#endif /* DEBUG_LIGHT */
      /* We managed to extract all necessary fields. */
      info->hlen = offset - pc->hdrlen;
      info->update_pmtu = 1;
      return SSH_ENGINE_RET_OK;

    default:
      /* We are only interested in ESP, AH, IPPCP, and NAT-T UDP
         packets.  Do nothing for other packets. */
      info->hlen = offset - pc->hdrlen;
      return SSH_ENGINE_RET_OK;
      break;
    }

 droptooshort:
  SSH_DEBUG(SSH_D_NETGARB, ("Too short ICMPv6 TOOBIG msg"));
 drop:
  ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;
  return SSH_ENGINE_RET_ERROR;
}
#endif /* WITH_IPV6 */


#ifdef DEBUG_LIGHT
/* Find the name of the IP protocol `proto'.  The function returns the
   name of the protcol or "???" if the protocol is unknown. */
const char *
ssh_engine_pmtu_proto_name(long code)
{
  int i;

  for (i = 0; ssh_ip_protocol_id_keywords[i].name; i++)
    if (ssh_ip_protocol_id_keywords[i].code == code)
      return ssh_ip_protocol_id_keywords[i].name;

  return "???";
}
#endif /* DEBUG_LIGHT */

/* Adjust the flow MTU based on received PMTU message which is given
   in the PC as a input for this function. The pc flow_index needs to
   point into a valid flow. */
void
ssh_engine_pmtu_adjust_flow(SshEngine engine, SshEnginePacketContext pc)
{
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshEnginePmtuIcmpInfoStruct info;
  SshEngineActionRet ret;
  Boolean forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;

  SSH_ASSERT(pc->flow_index != SSH_IPSEC_INVALID_INDEX);

  SSH_DEBUG(SSH_D_MIDOK, ("Adjusting flow %d mtu", (int)pc->flow_index));

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

#ifdef WITH_IPV6
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    ret = ssh_engine_pmtu_extract_icmpv6_info(engine, pc, &info);
  else
#endif /* WITH_IPV6 */
    ret = ssh_engine_pmtu_extract_icmp_info(engine, pc, &info);

  if (ret != SSH_ENGINE_RET_OK)
    {
      pc->pp = NULL;
      SSH_DEBUG(SSH_D_MIDOK, ("ICMP info extraction failed."));

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      fastpath_packet_continue(engine->fastpath, pc, SSH_ENGINE_RET_DROP);
      return;
    }

  if (info.update_pmtu)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("New requested MTU is %u", info.mtu));

      c_flow = SSH_ENGINE_GET_FLOW(engine, pc->flow_index);
      d_flow = FASTPATH_GET_FLOW(engine->fastpath, pc->flow_index);
      if (d_flow->generation != pc->flow_generation
          || (c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID) == 0)
        {
          FASTPATH_RELEASE_FLOW(engine->fastpath, pc->flow_index);
          SSH_DEBUG(SSH_D_LOWOK, ("Flow disappeared"));
          goto out;
        }

      ssh_interceptor_get_time(&engine->run_time, &engine->run_time_usec);

      if (forward == FALSE)
        {
          if (d_flow->forward_pmtu == 0
              || d_flow->forward_pmtu > info.mtu)
            {
              d_flow->forward_pmtu = info.mtu;
              c_flow->forward_pmtu_expire_time =
                engine->run_time + SSH_ENGINE_FLOW_PMTU_EXPIRE_TIME;
            }
        }
      else
        {
          if (d_flow->reverse_pmtu == 0
              || d_flow->reverse_pmtu < info.mtu)
            {
              d_flow->reverse_pmtu = info.mtu;
              c_flow->reverse_pmtu_expire_time =
                engine->run_time + SSH_ENGINE_FLOW_PMTU_EXPIRE_TIME;
            }
        }

      FASTPATH_COMMIT_FLOW(engine->fastpath, pc->flow_index, d_flow);
    }

 out:
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  fastpath_packet_continue(engine->fastpath, pc, SSH_ENGINE_RET_EXECUTE);
}


/* Handle incoming ICMP Unreachable/Fragmentation Needed messages
   directed to one of our own IP addresses.  This should look up the
   appropriate transform and update its idea of the path MTU.  This
   returns SSH_ENGINE_RET_ERROR if an error occurs and causes pc->pp
   to be freed, SSH_ENGINE_RET_DEINITIALIZE if this processed the
   packet and it should not be sent forward (pc->pp has already been
   freed), and SSH_ENGINE_RET_OK if the packet should also be passed
   to normal rule-based processing. */
SshEngineActionRet
ssh_engine_handle_pmtu_icmp(SshEngine engine, SshEnginePacketContext pc)
{
  SshEnginePmtuIcmpInfoStruct info;
  SshEngineActionRet ret;
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshUInt32 hashvalue, i;
  SshUInt32 trd_index;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Extract PMTU information from the inbound ICMP message. */
  memset(&info, 0, sizeof(info));

#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    ret = ssh_engine_pmtu_extract_icmpv6_info(engine, pc, &info);
  else
#endif /* WITH_IPV6 */
    ret = ssh_engine_pmtu_extract_icmp_info(engine, pc, &info);

  if (!info.update_pmtu)
    {
      /* Enforce API */
      SSH_ASSERT(((ret == SSH_ENGINE_RET_ERROR
                   || ret == SSH_ENGINE_RET_DEINITIALIZE) && pc->pp == NULL)
                 || (ret == SSH_ENGINE_RET_OK && pc->pp != NULL));

      /* Let ICMP message continue to local stack. This is necessary for
         updating PMTU information in local stack for IKE datagrams. */
      if (info.pass_to_stack && pc->pp != NULL)
        pc->tunnel_id = 1;

      return ret;
    }

  /* Handle old-style PMTU messages which have zero as the Next-Hop
     MTU in the ICMP message. */
  if (info.mtu == 0)
    {
      /* Take a good initial guess based on the length of the
         offending packet. */
      info.mtu = info.length;

      /* RFC 1191, Page 8: `routers based on implementations derived
         from 4.2BSD Unix send an incorrect value for the Total Length
         of the original IP datagram.  The value sent by these routers
         is the sum of the original Total Length and the original
         Header Length (expressed in octets)'.  The RFC 1191 suggests
         that we assume this case and substract the Header Length from
         the returned Total Length. */
      info.mtu -= info.hlen;

      /* Determine the next smaller MTU value starting from our
         initial guess. */
      if (info.mtu > 0)
        {
          if (info.mtu > ssh_engine_common_mtus[0])
            i = 0;
          else
            {
              for (i = 0; i < 11 && ssh_engine_common_mtus[i] >= info.mtu; i++)
                ;
            }
          info.mtu = ssh_engine_common_mtus[i];
        }
    }

  /* Enforce minimum MTU values. */
#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      if (info.mtu < SSH_ENGINE_MIN_FIRST_FRAGMENT_V6)
        info.mtu = SSH_ENGINE_MIN_FIRST_FRAGMENT_V6;
    }
  else
#endif /* WITH_IPV6 */
    {
      if (info.mtu < SSH_ENGINE_MIN_FIRST_FRAGMENT_V4)
        info.mtu = SSH_ENGINE_MIN_FIRST_FRAGMENT_V4;
    }

  /* We managed to extract all necessary fields. */
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  if (info.ipproto == SSH_IPPROTO_UDP)
    SSH_DEBUG(SSH_D_HIGHOK,
              ("PMTU %@ > %@ [NAT-T %@ > %@.%d]: orig_len=%d, mtu=%d",
               ssh_ipaddr_render, &info.icmp_src,
               ssh_ipaddr_render, &info.icmp_dst,
               ssh_ipaddr_render, &info.src,
               ssh_ipaddr_render, &info.dst,
               (int) info.natt_dst_port,
               (int) info.length,
               (int) info.mtu));
  else
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
    SSH_DEBUG(SSH_D_HIGHOK,
              ("PMTU %@ > %@ [%s[%lx] %@ > %@]: orig_len=%d, mtu=%d",
               ssh_ipaddr_render, &info.icmp_src,
               ssh_ipaddr_render, &info.icmp_dst,
               ssh_engine_pmtu_proto_name(info.ipproto),
               (unsigned long) info.spi,
               ssh_ipaddr_render, &info.src,
               ssh_ipaddr_render, &info.dst,
               (int) info.length,
               (int) info.mtu));

  /* Update PMTUs of all SAs with the remote peer. */
  hashvalue = SSH_IP_HASH(&info.dst) % SSH_ENGINE_PEER_HASH_SIZE;

  for (trd_index = engine->peer_hash[hashvalue];
       trd_index != SSH_IPSEC_INVALID_INDEX;
       trd_index = c_trd->peer_next)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
      d_trd = FASTPATH_GET_TRD(engine->fastpath, trd_index);
      SSH_ASSERT(c_trd != NULL);
      SSH_ASSERT(d_trd->transform != 0);

      /* Check if PMTU message applies for this transform. Note that
         manually keyed SAs have remote_port set to 0, but we still
         want to update them if gw_addr matches the PMTU message.
         IKE keyed SAs have always remote_port set to the IKE port. */
      if (!SSH_IP_EQUAL(&d_trd->gw_addr, &info.dst)
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          || (d_trd->remote_port != 0
              && info.natt_dst_port != 0
              && info.natt_dst_port != d_trd->remote_port)
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          )
        {
          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
          continue;
        }

      /* We have a trd for the given peer.  Update its path MTU
         value. */
      if (d_trd->pmtu_received == 0 || info.mtu < d_trd->pmtu_received)
        {
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Updating PMTU of trd_index %u from %u to %u",
                     (unsigned int) trd_index,
                     (unsigned int) d_trd->pmtu_received,
                     (unsigned int) info.mtu));
          d_trd->pmtu_received = (SshUInt16) info.mtu;
          c_trd->pmtu_age_time =
            engine->run_time + SSH_ENGINE_PMTU_DEFAULT_TTL;
          FASTPATH_COMMIT_TRD(engine->fastpath, trd_index, d_trd);
        }
      else
        {
          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
        }
    }

  /* Let ICMP message continue to local stack. This is necessary for
     updating PMTU information in local stack for IKE datagrams. */
  if (info.pass_to_stack)
    {
      pc->tunnel_id = 1;
      return SSH_ENGINE_RET_OK;
    }

  /* ICMP message processed. */
  ssh_interceptor_packet_free(pc->pp);
  pc->pp = NULL;

  return SSH_ENGINE_RET_DEINITIALIZE;
}




void
ssh_engine_pmtu_init(void)
{
  return;
}
