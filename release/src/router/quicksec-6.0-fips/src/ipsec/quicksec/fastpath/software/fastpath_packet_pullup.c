/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Routines for inspecting packet headers, performing
   sanity checks on packets and caching fields from
   packet headers to the SshEnginePacketContext data
   structure.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathPacketPullup"

#if defined (WITH_IPV6)
static Boolean
fastpath_check_frag_hdr(SshEnginePacketContext pc,
                        SshUInt16 offset,
                        SshUInt8 *next_ext_hdr,
                        SshUInt16 *ext_hdr_len)
{
  unsigned char pullup_buf[SSH_IP6_EXT_FRAGMENT_HDRLEN];
  const unsigned char *ucp;
  SshUInt32 frag_data_len;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->pp != NULL);
  SSH_ASSERT(ext_hdr_len != NULL);

  /* Check that there is enough data for the fragment header. */
  if (pc->packet_len < (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated IPv6 fragment header"));
      pc->audit.corruption =
        SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data = offset;
      return FALSE;
    }

  /* Fetch fragment header. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_IP6_EXT_FRAGMENT_HDRLEN,
                            pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      return FALSE;
    }

  *ext_hdr_len = SSH_IP6_EXT_COMMON_LENB(ucp);
  *next_ext_hdr = SSH_IP6_EXT_COMMON_NH(ucp);

  pc->fragment_id = SSH_IP6_EXT_FRAGMENT_ID(ucp);
  pc->fragment_offset = SSH_IP6_EXT_FRAGMENT_OFFSET(ucp) * 8;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("IPv6 fragment header: id %08lx offset %d%s",
             (unsigned long) pc->fragment_id,
             (int) pc->fragment_offset,
             (SSH_IP6_EXT_FRAGMENT_M(ucp) == 0 ? " [last]" : "")));

  pc->pp->flags |= SSH_ENGINE_P_ISFRAG;

  if (pc->fragment_offset == 0)
    pc->pp->flags |= SSH_ENGINE_P_FIRSTFRAG;

  if (SSH_IP6_EXT_FRAGMENT_M(ucp) == 0)
    pc->pp->flags |= SSH_ENGINE_P_LASTFRAG;

  /* Verify that the length of non-last fragments is properly aligned. */
  if ((pc->pp->flags & SSH_ENGINE_P_LASTFRAG) == 0)
    {
      frag_data_len = pc->packet_len - (offset + SSH_IP6_EXT_FRAGMENT_HDRLEN);
      if ((frag_data_len % 8) != 0)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Invalid IPv6 non-last fragment: length %d",
                     (int) frag_data_len));
          pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
          pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
          pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
          pc->error_info.icmp_extra_data = SSH_IPH6_OFS_LEN;
          return FALSE;
        }
    }

  return TRUE;
}

static Boolean
fastpath_check_routing_hdr(SshEnginePacketContext pc,
                           SshUInt16 offset,
                           SshUInt8 *next_ext_hdr,
                           SshUInt16 *ext_hdr_len)
{
  unsigned char pullup_buf[SSH_IP6_EXT_ROUTING_HDRLEN];
  const unsigned char *ucp;
  SshUInt8 routing_type;
  SshUInt8 segments_left;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->pp != NULL);
  SSH_ASSERT(ext_hdr_len != NULL);

  /* Verify that there is enough data available for the fixed
     part of routing header. */
  if (pc->packet_len < (offset + SSH_IP6_EXT_ROUTING_HDRLEN))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated IPv6 routing header"));
      pc->audit.corruption =
        SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data = offset;
      return FALSE;
    }

  /* Fetch routing header. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_IP6_EXT_ROUTING_HDRLEN,
                            pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      return FALSE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("IPv6 routing header"));

  *ext_hdr_len = SSH_IP6_EXT_COMMON_LENB(ucp);
  *next_ext_hdr = SSH_IP6_EXT_COMMON_NH(ucp);
  routing_type = SSH_IP6_EXT_ROUTING_TYPE(ucp);
  segments_left = SSH_IP6_EXT_ROUTING_SEGMENTS(ucp);

  /* Drop packets with unknown Types in Routing header */
  switch (routing_type)
    {
    case 1:
    case 253:
    case 254:
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Accepted IPv6 routing header type %u",
                                   routing_type));
      break;

    case 2:
      /* RFC3775, 6.4.1: "Segments Left MUST be 1." */
      if (segments_left == 1)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Accepted IPv6 routing header type 2"));
          break;
        }

      SSH_DEBUG(SSH_D_NETGARB,
                ("Invalid IPv6 routing header type 2: segments left %d",
                 segments_left));
      pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
      pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data =
        offset + SSH_IP6_EXT_ROUTING_OFS_SEGMENTS;
      return FALSE;

    case 0:
    default:
      /* If there is a unknown routing header, but segments left is zero,
         the packet must be allowed to continue. */
      if (segments_left == 0)
        break;

      SSH_DEBUG(SSH_D_NETGARB,
                ("Unsupported IPv6 routing header type %d",
                 routing_type));
      pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
      pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data = offset + SSH_IP6_EXT_ROUTING_OFS_TYPE;
      return FALSE;
    }

  /* Sanity check routing header length. */
  if (*ext_hdr_len & 0x1)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("IPv6 routing hdr len is odd"));
      pc->audit.corruption = SSH_PACKET_CORRUPTION_UNALIGNED_OPTION;
      pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_extra_data = offset + SSH_IP6_EXT_COMMON_OFS_LEN;
      return FALSE;
    }

  /* Verify that there is enough data available for the complete routing
     header. */
  if (pc->packet_len < (*ext_hdr_len + offset))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated IPv6 routing header"));
      pc->audit.corruption = SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data = offset;
      return FALSE;
    }

  return TRUE;
}

static Boolean
fastpath_check_ext_hdr_options(SshEnginePacketContext pc,
                               SshUInt16 offset,
                               SshUInt16 length)
{
  unsigned char pullup_buf[SSH_IP6_EXT_HDR_OPTION_HDRLEN];
  const unsigned char *ucp;
  int pullup_len;
  SshInt32 remaining;
  SshUInt8 type;

  remaining = length;
  SSH_ASSERT(remaining >= 6);

  while (remaining > 0)
    {
      pullup_len = SSH_IP6_EXT_HDR_OPTION_HDRLEN;
      if (pullup_len > remaining)
        pullup_len = remaining;

      /* Fetch option TLV. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, pullup_len, pullup_buf);
      if (ucp == NULL)
        {
          pc->pp = NULL;
          return FALSE;
        }

      /* Check the options types. Check for unknown ones for us and
         process those according to RFC 2460. */
      type = SSH_IP6_EXT_HDR_OPTION_TYPE(ucp);

      /* PAD-1, simply continue to next TLV. */
      if (type == SSH_IP6_EXT_HDR_OPTION_TYPE_PAD1)
        {
          /* 1 byte padding. Needs to be ignored. */
          offset += 1;
          remaining -= 1;
          continue;
        }

      /* Not PAD-1, check that we have enough data for the common part of the
         extension header. */
      if (pullup_len < SSH_IP6_EXT_HDR_OPTION_HDRLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated IPv6 extension header option"));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT;

          /* We do send ICMP message if option type indicates so. */
          if (((type & SSH_IP6_EXT_HDR_OPTION_TYPE_SKIP_MASK) ==
               SSH_IP6_EXT_HDR_OPTION_TYPE_REJECT_UCAST
               && !SSH_IP_IS_MULTICAST(&pc->dst))
              || ((type & SSH_IP6_EXT_HDR_OPTION_TYPE_SKIP_MASK) ==
                  SSH_IP6_EXT_HDR_OPTION_TYPE_REJECT))
            {
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_OPTION;
              pc->error_info.icmp_extra_data = offset + 1;
            }
          return FALSE;
        }

      /* Not PAD-N, check high order bits for processing instructions. */
      if (type != SSH_IP6_EXT_HDR_OPTION_TYPE_PADN)
        {
          switch (type & SSH_IP6_EXT_HDR_OPTION_TYPE_SKIP_MASK)
            {
            case SSH_IP6_EXT_HDR_OPTION_TYPE_SKIP:
              /* Option with high order bits set to '00', this TLV can simply
                 be skipped after TLV length verification. */
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Skipping unknown IPv6 extension header option 0x%x",
                         type));
              break;

            case SSH_IP6_EXT_HDR_OPTION_TYPE_DISCARD:
              /* Unknown option with high order bits set to '01', discard
                 packet. */
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Discarding packet with unknown IPv6 extension "
                         "header option 0x%x",
                         type));
              pc->audit.corruption = SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION;
              return FALSE;

            case SSH_IP6_EXT_HDR_OPTION_TYPE_REJECT_UCAST:
              /* Unknown option with high order bits set to '11', send ICMPv6
                 param problem unless the packet destination was multicast. */
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Discarding packet with unknown IPv6 extension "
                         "header option 0x%x",
                         type));
              pc->audit.corruption = SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION;

              if (SSH_IP_IS_MULTICAST(&pc->dst))
                return FALSE;

              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_OPTION;
              pc->error_info.icmp_extra_data = offset;
              return FALSE;

            case SSH_IP6_EXT_HDR_OPTION_TYPE_REJECT:
              /* Unknown option with high order bits set to '10', send ICMPv6
                 param problem regardless whether the packet destination was
                 multicast or unicast. */
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Discarding packet with unknown IPv6 extension "
                         "header option 0x%x",
                         type));
              pc->audit.corruption = SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_OPTION;
              pc->error_info.icmp_extra_data = offset;
              return FALSE;
            }
        }

      /* Check option length for PAD-N and unknown skippable options. */
      remaining -= SSH_IP6_EXT_HDR_OPTION_LENB(ucp) + 2;
      if (remaining < 0)
        {
          /* Overflow of the options inside the extension header. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Invalid option length in IPv6 extension header option"));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_OPTION_OVERFLOW;

          /* We do not send ICMP message if the destination was multicast. */
          if (SSH_IP_IS_MULTICAST(&pc->dst))
            return FALSE;

          pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
          pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
          pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_OPTION;
          pc->error_info.icmp_extra_data = offset + 1;
          return FALSE;
        }
      offset += SSH_IP6_EXT_HDR_OPTION_LENB(ucp) + 2;
    }

  SSH_ASSERT(remaining == 0);
  return TRUE;
}

Boolean
fastpath_validate_dest_ops_hdr(SshEnginePacketContext pc)
{
  unsigned char pullup_buf[SSH_IP6_EXT_DSTOPTS_HDRLEN];
  const unsigned char *ucp;
  SshUInt16 ext_hdr_len;

  /* This function should never be called for packets that did not contain
     an IPv6 destination option header. */
  SSH_ASSERT(pc->dsth_offset > 0);

  /* Fetch destination option header. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->dsth_offset,
                            SSH_IP6_EXT_DSTOPTS_HDRLEN, pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      return FALSE;
    }

  /* Go through the options. Extension header length has been already
     validated against overflow when parsing the extension headers.
     Therefore as the packet did contain a destination option header,
     then there must be atleast 6 bytes of TLV encoded option data. */
  ext_hdr_len = SSH_IP6_EXT_DSTOPTS_LENB(ucp);
  SSH_ASSERT(ext_hdr_len >= 8);
  SSH_ASSERT((ext_hdr_len - SSH_IP6_EXT_DSTOPTS_HDRLEN) >= 6);

 return fastpath_check_ext_hdr_options(pc,
                                        pc->dsth_offset
                                        + SSH_IP6_EXT_DSTOPTS_HDRLEN,
                                        ext_hdr_len
                                        - SSH_IP6_EXT_DSTOPTS_HDRLEN);
}

static Boolean
fastpath_check_dest_ops_hdr(SshEnginePacketContext pc,
                            SshUInt16 offset,
                            SshUInt8 *next_ext_hdr,
                            SshUInt16 *ext_hdr_len)
{
  unsigned char pullup_buf[SSH_IP6_EXT_DSTOPTS_HDRLEN];
  const unsigned char *ucp;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->pp != NULL);
  SSH_ASSERT(ext_hdr_len != NULL);
  SSH_ASSERT(next_ext_hdr != NULL);

  /* Initial check, do we have enough data to even start processing the
     thing? Packet dropped + audited if necessary. */
  if (pc->packet_len < (offset + SSH_IP6_EXT_DSTOPTS_HDRLEN))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated IPv6 destination option header"));
      pc->audit.corruption =
        SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data = offset;
      return FALSE;
    }

  /* Fetch destination option header. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_IP6_EXT_DSTOPTS_HDRLEN,
                            pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      return FALSE;
    }

  *ext_hdr_len = SSH_IP6_EXT_COMMON_LENB(ucp);
  *next_ext_hdr = SSH_IP6_EXT_COMMON_NH(ucp);

  /* Second pass, validate the total length. */
  if (pc->packet_len < (*ext_hdr_len + offset))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated IPv6 destination option header"));
      pc->audit.corruption =
        SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
      pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
      pc->error_info.icmp_extra_data = offset + SSH_IP6_EXT_COMMON_OFS_LEN;
      return FALSE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("IPv6 destination option header: header length %d",
                           (int) *ext_hdr_len));
  return TRUE;
}

static Boolean
fastpath_check_hop_by_hop_hdr(SshEnginePacketContext pc,
                              SshUInt16 offset,
                              SshUInt8 *next_ext_hdr,
                              SshUInt16 *ext_hdr_len)
{
  unsigned char pullup_buf[SSH_IP6_EXT_HOP_BY_HOP_HDRLEN];
  const unsigned char *ucp;

  SSH_ASSERT(pc != NULL);
  SSH_ASSERT(pc->pp != NULL);
  SSH_ASSERT(next_ext_hdr != NULL);
  SSH_ASSERT(ext_hdr_len != NULL);

  /* Initial check, do we have enough data to even start processing the
     thing? Packet dropped + audited if necessary. */
  if (pc->packet_len < (offset + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN))
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Truncated packet IPv6 hop-by-hop option header"));
      pc->audit.corruption =
        SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      return FALSE;
    }

  /* Fetch hop-by-hop option header. */
  SSH_ENGINE_PC_PULLUP_READ(ucp, pc, offset, SSH_IP6_EXT_HOP_BY_HOP_HDRLEN,
                            pullup_buf);
  if (ucp == NULL)
    {
      pc->pp = NULL;
      return FALSE;
    }

  *next_ext_hdr = SSH_IP6_EXT_HOP_BY_HOP_NH(ucp);
  *ext_hdr_len = SSH_IP6_EXT_HOP_BY_HOP_LENB(ucp);

  /* Second pass, validate the total length. */
  if (pc->packet_len < (*ext_hdr_len + offset))
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Truncated IPv6 hop-by-hop option header"));
      pc->audit.corruption =
        SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
      return FALSE;
    }

  SSH_DEBUG(SSH_D_HIGHOK, ("IPv6 hop-by-hop option header: length %d",
                           *ext_hdr_len));

  /* Go through the options. Extension header length has been already
     validated against overflow when parsing the extension headers.
     Therefore as the packet did contain a hop-by-hop option header,
     then there must be atleast 6 bytes of TLV encoded option data. */
  SSH_ASSERT(*ext_hdr_len >= 8);
  SSH_ASSERT((*ext_hdr_len - SSH_IP6_EXT_HOP_BY_HOP_HDRLEN) >= 6);

  return fastpath_check_ext_hdr_options(pc,
                                        offset
                                        + SSH_IP6_EXT_HOP_BY_HOP_HDRLEN,
                                        *ext_hdr_len
                                        - SSH_IP6_EXT_HOP_BY_HOP_HDRLEN);
}
#endif /* WITH_IPV6 */


SSH_FASTTEXT
Boolean
fastpath_packet_parse(SshEngine engine,
                      SshEnginePacketContext pc,
                      SshEnginePacketData pd)
{
  unsigned char pullup_buf[40];
  const unsigned char *ucp;
  SshUInt16 ip_len, fragoff2;
  SshInterceptorPacket pp = pc->pp;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  SshUInt16 ethertype = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  size_t length;

  SSH_ASSERT(pp != NULL);

  pc->packet_len = ssh_interceptor_packet_len(pp);
  pc->min_packet_size = 0;
  pc->protocol_xid = 0;
  pc->u.rule.src_port = 0;
  pc->u.rule.dst_port = 0;
  pc->u.rule.spi = 0;
  pc->u.rule.tos = 0;
  pc->u.rule.icmp_code = 0;
  pc->icmp_type = 0;
  pc->hdrlen = 0;
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  pc->media_hdr_len = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Parse link layer protocols. */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  switch (pp->protocol)
    {
    case SSH_PROTOCOL_ETHERNET:
      SSH_DEBUG(SSH_D_LOWSTART, ("Parsing ethernet header"));

      /* Sanity check packet length. */
      if (pc->packet_len <= SSH_ETHERH_HDRLEN)
        {
          pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_MEDIA_HEADER;
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Frame too short for ethernet: length %d",
                     (int) pc->packet_len));
          goto drop;
        }

      /* Fetch ethernet header */
      ucp = ssh_interceptor_packet_pullup_read(pp, SSH_ETHERH_HDRLEN);
      if (ucp == NULL)
        goto error;

      /* Parse ethertype. */
      ethertype = SSH_ETHERH_TYPE(ucp);

      /* If the packet was received using a multicast destination address,
         set a flag to that effect. */
      if (SSH_ETHER_IS_MULTICAST(ucp + SSH_ETHERH_OFS_DST))
        pp->flags |= SSH_ENGINE_P_BROADCAST;

      SSH_DEBUG(SSH_D_LOWOK,
                ("Ethernet frame: ethertype 0x%x flags 0x%x [%s%s%s]",
                 (unsigned int)ethertype, (unsigned int) pp->flags,
                 (pp->flags & SSH_PACKET_FROMPROTOCOL ? "from protocol " : ""),
                 (pp->flags & SSH_PACKET_FROMADAPTER ? "from adapter " : ""),
                 (pp->flags & SSH_PACKET_MEDIABCAST ? "media bcast" : "")
                 ));

      /* Save the media header. */
      pd->media_hdr_len = SSH_ETHERH_HDRLEN;
      pd->media_protocol = SSH_PROTOCOL_ETHERNET;
      pd->mediatype = SSH_INTERCEPTOR_MEDIA_ETHERNET;
      memcpy(pd->mediahdr, ucp, SSH_ETHERH_HDRLEN);

#ifdef SSH_IPSEC_CONVERT_SNAP_TO_EII
      if (ethertype <= 1508
          && pc->packet_len >= (SSH_ETHERH_HDRLEN + SSH_LLCH_MIN_HDRLEN
                                + SSH_SNAPH_HDRLEN))
        {
          SSH_DUMP_PACKET(SSH_D_LOWOK,
                          ("Potential SNAP frame: ethertype %0x%x",
                           (unsigned int) ethertype), pp);

          /* Fetch LLC and SNAP headers */
          ucp = ssh_interceptor_packet_pullup_read(pp, SSH_ETHERH_HDRLEN
                                                   + SSH_LLCH_MIN_HDRLEN
                                                   + SSH_SNAPH_HDRLEN);
          if (ucp == NULL)
            goto error;

          /* Is this a SNAP frame? */
          if (SSH_LLCH_DSAP(ucp + SSH_ETHERH_HDRLEN) == 0xaa
              || SSH_LLCH_DSAP(ucp + SSH_ETHERH_HDRLEN) == 0xab)
            {
              ethertype =
                SSH_SNAPH_TYPE(ucp + SSH_ETHERH_HDRLEN + SSH_LLCH_MIN_HDRLEN);
              pc->media_hdr_len = SSH_LLCH_MINLEN + SSH_SNAPH_HDRLEN;
              SSH_DEBUG(SSH_D_LOWOK, ("SNAP: ethertype 0x%x",
                                      (unsigned int) ethertype));
            }

          /* Patch ethertype in the saved media header. */
          SSH_ETHERH_SET_TYPE(pd->mediahdr, ethertype);
        }
#endif /* SSH_IPSEC_CONVERT_SNAP_TO_EII */

      /* Media header is removed after packet headers have been parsed. */
      pc->media_hdr_len += SSH_ETHERH_HDRLEN;
      pc->packet_len -= pc->media_hdr_len;

      /* Set upper layer protocol according to ethertype */
      switch (ethertype)
        {
        case SSH_ETHERTYPE_IP: /* IPv4 datagram */
          pp->protocol = SSH_PROTOCOL_IP4;
          break;

        case SSH_ETHERTYPE_IPv6: /* IPv6 datagram */
          pp->protocol = SSH_PROTOCOL_IP6;
          break;

        case SSH_ETHERTYPE_ARP: /* ARP datagram */
          pp->protocol = SSH_PROTOCOL_ARP;
          break;

        default:
          pp->protocol = SSH_PROTOCOL_OTHER;
          break;
        }
      break;

      /* We currently only support ethernet media. Drop frames that have
         any other link layer protocol. */
    case SSH_PROTOCOL_FDDI:
      SSH_TRACE(SSH_D_NETGARB, ("Unsupported FDDI encapsulated packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_OTHER);
      goto drop;

    case SSH_PROTOCOL_TOKENRING:
      SSH_TRACE(SSH_D_NETGARB, ("Unsupported TOKENRING encapsulated packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_OTHER);
      goto drop;

      /* Continue parsing as network layer protocol for other protocols. */
    default:
      break;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  /* Parse network layer protocols. */
  pc->ipproto = SSH_IPPROTO_ANY;
  switch (pp->protocol)
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    case SSH_PROTOCOL_ARP:
      SSH_DEBUG(SSH_D_LOWSTART, ("ARP frame"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_ARP);
      goto out;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

    case SSH_PROTOCOL_IP4:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv4 packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_IP4);

      /* Check that there is enough data for an IPv4 header. */
      pc->min_packet_size = SSH_IPH4_HDRLEN;
      if (SSH_PREDICT_FALSE(pc->packet_len < pc->min_packet_size))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv4 packet shorter than IPv4 header: length %d",
                     (int) pc->packet_len));
          pc->hdrlen = (SshUInt16) pc->packet_len;
          pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
          goto corrupt;
        }

      /* Fetch IPv4 header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH4_HDRLEN, pullup_buf);
      if (ucp == NULL)
        goto error;

      /* Sanity check IP version. */
#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      if (SSH_PREDICT_FALSE(SSH_IPH4_VERSION(ucp) != 4))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("IPv4 invalid version: %d",
                                    (int) SSH_IPH4_VERSION(ucp)));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_NOT_IPV4;
          goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Sanity check header length. */
      pc->hdrlen = 4 * SSH_IPH4_HLEN(ucp);
#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      if (SSH_PREDICT_FALSE(pc->hdrlen < SSH_IPH4_HDRLEN))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("IPv4 header short: header length %d",
                                    (int) pc->hdrlen));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
          goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */
      pc->min_packet_size = pc->hdrlen;

      /* Parse IPv4 header. Ignore header checksum. */
      pc->u.rule.tos = SSH_IPH4_TOS(ucp);
      ip_len = SSH_IPH4_LEN(ucp);
      /* pc->net.ip.id = SSH_IPH4_ID(ucp); */
      pc->fragment_offset = SSH_IPH4_FRAGOFF(ucp);
      pc->u.rule.ttl = SSH_IPH4_TTL(ucp);
      pc->ipproto = SSH_IPH4_PROTO(ucp);
      SSH_IPH4_SRC(&pc->src, ucp);
      SSH_IPH4_DST(&pc->dst, ucp);

      /* Sanity check IP datagram length. */
#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      if (SSH_PREDICT_FALSE(ip_len < pc->hdrlen))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv4 packet too short for full IPv4 header: "
                     "packet length %d IP header length %d",
                     (int) ip_len, (int) pc->hdrlen));
          pc->hdrlen = ip_len;
          pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER;
          goto corrupt;
        }
      if (SSH_PREDICT_FALSE(pc->packet_len < ip_len))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv4 truncated packet: length %d IP total length %d",
                     (int) pc->packet_len, (int) ip_len));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
          goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Update packet length to IP datagram length. Trailing junk is
         removed after packet headers have been parsed. */
      pc->packet_len = ip_len;

      /* Check fragment offset. */
      fragoff2 = (pc->fragment_offset & SSH_IPH4_FRAGOFF_OFFMASK);
      if (SSH_PREDICT_FALSE(pc->fragment_offset &
                            (SSH_IPH4_FRAGOFF_OFFMASK | SSH_IPH4_FRAGOFF_MF)))
        {
          /* The packet is a fragment. */
          pp->flags |= SSH_ENGINE_P_ISFRAG;
          if ((pc->fragment_offset & SSH_IPH4_FRAGOFF_OFFMASK) == 0)
            pp->flags |= SSH_ENGINE_P_FIRSTFRAG;

          if ((pc->fragment_offset & SSH_IPH4_FRAGOFF_MF) == 0)
            {
              pp->flags |= SSH_ENGINE_P_LASTFRAG;
              pc->frag_packet_size = 8 * fragoff2 + ip_len - pc->hdrlen;
            }
        }

      SSH_DEBUG(SSH_D_LOWOK,
                ("IPv4%s: length %d ipproto %d src %@ dst %@",
                 ((pp->flags & SSH_ENGINE_P_ISFRAG) ? " fragment" : ""),
                 (int) pc->packet_len, (int) pc->ipproto,
                 ssh_ipaddr_render, &pc->src,
                 ssh_ipaddr_render, &pc->dst));

      /* Sanity check transport layer protocol */
      switch (pc->ipproto)
        {
          /* Drop IPv4 packets with IPv6 extension headers or ICMPv6. */
        case SSH_IPPROTO_HOPOPT:
        case SSH_IPPROTO_IPV6ROUTE:
        case SSH_IPPROTO_IPV6FRAG:
        case SSH_IPPROTO_IPV6ICMP:
        case SSH_IPPROTO_IPV6NONXT:
        case SSH_IPPROTO_IPV6OPTS:
        case SSH_IPPROTO_MOBILITY:
          SSH_DEBUG(SSH_D_NETGARB, ("Unsupported IPv4 IP protocol %d",
                                    (int) pc->ipproto));



          goto drop;

        default:
          break;
        }

      /* Do not parse further headers for non-first fragments. */
      if (SSH_PREDICT_FALSE(fragoff2 != 0))
        goto out;

      /* Continue parsing transport layer protocol headers for non-fragmented
         packets and for the first fragments of fragmented packets. */
      break;

#if defined (WITH_IPV6)
    case SSH_PROTOCOL_IP6:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv6 packet"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_IN_IP6);

      /* Check there is enough data for an IPv6 header. */
      pc->min_packet_size = SSH_IPH6_HDRLEN;
      if (SSH_PREDICT_FALSE(pc->packet_len < pc->min_packet_size))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv6 packet shorter than IPv6 header: length %d",
                     (int) pc->packet_len));
          pc->hdrlen = (SshUInt16) pc->packet_len;
          pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER;
          goto corrupt;
        }

      pc->hdrlen = SSH_IPH6_HDRLEN;

      /* Fetch IPv6 header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, 0, SSH_IPH6_HDRLEN, pullup_buf);
      if (ucp == NULL)
        goto error;

#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      /* Sanity check IPv6 header version. */
      if (SSH_PREDICT_FALSE(SSH_IPH6_VERSION(ucp) != 6))
        {
          SSH_DEBUG(SSH_D_NETGARB, ("IPv6 invalid version: %d",
                                    (int) SSH_IPH6_VERSION(ucp)));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_NOT_IPV6;
          goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Parse IPv6 header. */
      pc->u.rule.tos = SSH_IPH6_CLASS(ucp);
      pc->audit.flowlabel = SSH_IPH6_FLOW(ucp);
      ip_len = SSH_IPH6_LEN(ucp);
      pc->ipproto = SSH_IPH6_NH(ucp);
      pc->u.rule.ttl = SSH_IPH6_HL(ucp);
      SSH_IPH6_SRC(&pc->src, ucp);
      SSH_IPH6_DST(&pc->dst, ucp);

#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
      /* Sanity check IPv6 datagram length. */
      if (SSH_PREDICT_FALSE(pc->packet_len < ip_len + SSH_IPH6_HDRLEN))
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv6 truncated packet: length %d IPv6 payload length %d",
                     (int) pc->packet_len, (int) ip_len));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER;
          goto corrupt;
        }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

      /* Trailing junk is deleted after packet headers have been parsed. */
      pc->packet_len = ip_len + SSH_IPH6_HDRLEN;

      /* Next we iterate through possible IPv6 extension headers. */
      pc->fragh_offset_prevnh = SSH_IPH6_OFS_NH;
      pc->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;

      {
#define FASTPATH_SEEN_HOP_BY_HOP_HDR        0x01
#define FASTPATH_SEEN_DEST_OPT_HDR          0x02
#define FASTPATH_SEEN_ROUTING_HDR           0x04
#define FASTPATH_SEEN_FRAG_HDR              0x08
#define FASTPATH_SEEN_AH_HDR                0x10
#define FASTPATH_SEEN_ESP_HDR               0x20
#define FASTPATH_SEEN_DEST_OPT2_HDR         0x40
#define FASTPATH_SEEN_UPPER_HDR             0x80

#define FASTPATH_DEST_OPT_HDR_CHECK_MASK    0xfc
#define FASTPATH_ROUTING_HDR_CHECK_MASK     0xf8
#define FASTPATH_FRAG_HDR_CHECK_MASK        0xf0
#define FASTPATH_AH_HDR_CHECK_MASK          0xe0
#define FASTPATH_ESP_HDR_CHECK_MASK         0xc0
#define FASTPATH_DEST_OPT2_HDR_CHECK_MASK   0x80

        SshUInt16 ext_hdr_mask = 0;
        SshUInt16 ext_hdr_len;
        SshUInt8 next_ext_hdr;
        SshUInt16 offset = SSH_IPH6_HDRLEN;
        SshUInt16 prev_offset = 0;

        if (ip_len == 0)
          {
            SSH_DEBUG(SSH_D_FAIL, ("Jumbo payload option not supported"));
            pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
            goto corrupt;
          }

        if (pc->ipproto == SSH_IPPROTO_HOPOPT)
          {
            if (fastpath_check_hop_by_hop_hdr(pc, offset, &next_ext_hdr,
                                              &ext_hdr_len) == FALSE)
              {
                if (pc->pp == NULL)
                  goto error;
                goto corrupt;
              }

            ext_hdr_mask |= FASTPATH_SEEN_HOP_BY_HOP_HDR;
            pc->fragh_offset_prevnh = offset + SSH_IP6_EXT_COMMON_OFS_NH;
            pc->ipsec_offset_prevnh = offset + SSH_IP6_EXT_COMMON_OFS_NH;

            prev_offset = offset;
            offset += ext_hdr_len;
            pc->ipproto = next_ext_hdr;
            pc->hdrlen = offset;
          }
        pc->fragh_offset = offset;
        pc->ipsec_offset = offset;

      next_extension_header:
        switch (pc->ipproto)
          {
          case SSH_IPPROTO_HOPOPT: /* A hop-by-hop -header in wrong place. */
            SSH_DEBUG(SSH_D_NETGARB,
                      ("IPv6 hop-by-hop header in illegal place"));
            pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;

            pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
            pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
            pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_NH;

            pc->error_info.icmp_extra_data = prev_offset;
            goto corrupt;

          case SSH_IPPROTO_IPV6ROUTE: /* Routing extension header. */
            if ((ext_hdr_mask & FASTPATH_ROUTING_HDR_CHECK_MASK) ||
                (ext_hdr_mask & FASTPATH_SEEN_ROUTING_HDR))
              {
                /* Invalid order in the headers or multiple routing
                   headers. The order is free by the RFC and multiple
                   should not exist, but anyway allowed. Log this case. */

                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Multiple IPv6 routing headers or routing header "
                           "in incorrect place (%x)", ext_hdr_mask));
              }

            if (fastpath_check_routing_hdr(pc, offset, &next_ext_hdr,
                                           &ext_hdr_len) == FALSE)
              {
                if (pc->pp == NULL)
                  goto error;
                goto corrupt;
              }

            ext_hdr_mask |= FASTPATH_SEEN_ROUTING_HDR;

            pc->fragh_offset_prevnh = offset + SSH_IP6_EXT_COMMON_OFS_NH;
            pc->ipsec_offset_prevnh = offset + SSH_IP6_EXT_COMMON_OFS_NH;
            pc->ipproto = next_ext_hdr;

            prev_offset = offset;
            offset += ext_hdr_len;
            pc->fragh_offset = offset;
            pc->ipsec_offset = offset;
            pc->hdrlen = offset;
            goto next_extension_header;

          case SSH_IPPROTO_IPV6OPTS: /* Destination options header. */
            if (ext_hdr_mask & FASTPATH_SEEN_DEST_OPT_HDR)
              {
                /* This is the second destination header. */
                if ((ext_hdr_mask & FASTPATH_DEST_OPT2_HDR_CHECK_MASK)
                    || (ext_hdr_mask & FASTPATH_SEEN_DEST_OPT2_HDR))
                  {
                    /* This is not an error, just log. */
                    SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("Destination opt header 2 or mask failed (%x)",
                               ext_hdr_mask));
                  }
                ext_hdr_mask |= FASTPATH_SEEN_DEST_OPT2_HDR;
              }
            else if (ext_hdr_mask & FASTPATH_DEST_OPT_HDR_CHECK_MASK)
              {
                /* This is not an error, just log. */
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Destination opt header mask failed (%x)",
                           ext_hdr_mask));
              }
            else
              {
                ext_hdr_mask |= FASTPATH_SEEN_DEST_OPT_HDR;
              }

            if (fastpath_check_dest_ops_hdr(pc, offset, &next_ext_hdr,
                                            &ext_hdr_len) == FALSE)
              {
                if (pc->pp == NULL)
                  goto error;
                goto corrupt;
              }

            prev_offset = offset;
            pc->dsth_offset = offset;
            if (ext_hdr_mask & FASTPATH_SEEN_ROUTING_HDR)
              {
                /* Increment offset, but do NOT increase
                   `pc->ipsec_offset' since the ipsec headers shall be
                   inserted before this destination options header. */
                offset += ext_hdr_len;
              }
            else
              {
                pc->ipsec_offset_prevnh = offset + SSH_IP6_EXT_COMMON_OFS_NH;
                offset += ext_hdr_len;
                pc->ipsec_offset = offset;
              }

            pc->ipproto = next_ext_hdr;
            pc->hdrlen = offset;
            goto next_extension_header;

          case SSH_IPPROTO_IPV6FRAG: /* Fragment header. */
            if ((ext_hdr_mask & FASTPATH_FRAG_HDR_CHECK_MASK)
                || (ext_hdr_mask & FASTPATH_SEEN_FRAG_HDR))
              {
                /* This is not an error, just log. */
                SSH_DEBUG(SSH_D_NICETOKNOW,
                          ("Frag header multiple times or mask failed (%x)",
                           ext_hdr_mask));
              }

            if (fastpath_check_frag_hdr(pc, offset, &next_ext_hdr,
                                        &ext_hdr_len) == FALSE)
              {
                if (pc->pp == NULL)
                  goto error;
                goto corrupt;
              }

            pc->fragh_offset = offset;
            pc->fragh_offset_prevnh = pc->ipsec_offset_prevnh;

            ext_hdr_mask |= FASTPATH_SEEN_FRAG_HDR;

            pc->ipsec_offset_prevnh = offset + SSH_IP6_EXT_FRAGMENT_OFS_NH;
            prev_offset = offset;
            offset += SSH_IP6_EXT_FRAGMENT_HDRLEN;
            pc->ipsec_offset = offset;
            pc->ipproto = next_ext_hdr;
            pc->hdrlen = offset;










            /* Do not parse further headers for non-first fragments. */
            if ((pp->flags & SSH_ENGINE_P_FIRSTFRAG) == 0)
              {
                SSH_DEBUG(SSH_D_LOWOK,
                          ("IPv6 fragment: length %d IP proto %d src %@ "
                           "dst %@",
                           (int) pc->packet_len,
                           (int) pc->ipproto,
                           ssh_ipaddr_render, &pc->src,
                           ssh_ipaddr_render, &pc->dst));

                /* Calculate frag_packet_size for the reassembled packet. */
                if (pp->flags & SSH_ENGINE_P_LASTFRAG)
                  {
                    pc->frag_packet_size =
                      pc->fragment_offset + pc->packet_len - pc->hdrlen;
                  }
                goto out;
              }

            /* Otherwise continue parsing headers for first fragments. */
            goto next_extension_header;

          case SSH_IPPROTO_IPV6NONXT:
            SSH_DEBUG(SSH_D_LOWOK,
                      ("IPv6 packet: length %d IP proto %d (no next header) "
                       "src %@ dst %@",
                       (int) pc->packet_len,
                       (int) pc->ipproto,
                       ssh_ipaddr_render, &pc->src,
                       ssh_ipaddr_render, &pc->dst));
            goto out;

          case SSH_IPPROTO_MOBILITY:
            SSH_DEBUG(SSH_D_NETGARB, ("IPv6 mobility header not supported"));
            pc->audit.corruption = SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
            pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
            pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
            pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_NH;
            pc->error_info.icmp_extra_data = prev_offset;
            goto corrupt;

            /* Sanity check other transport layer protocol. */
          case SSH_IPPROTO_ICMP:
          case SSH_IPPROTO_IGMP:
            SSH_DEBUG(SSH_D_NETGARB, ("Unsupported IPv6 IP protocol %d",
                                      (int) pc->ipproto));



            goto drop;

            /* Continue parsing transport layer protocol headers for other
               next header values. */
          default:
            break;
          }
      }

      SSH_DEBUG(SSH_D_LOWOK,
                ("IPv6 packet: length %d IP proto %d src %@ dst %@",
                 (int) pc->packet_len,
                 (int) pc->ipproto,
                 ssh_ipaddr_render, &pc->src,
                 ssh_ipaddr_render, &pc->dst));
      break;
#endif /* WITH_IPV6 */

    case SSH_PROTOCOL_IPX:
      SSH_TRACE(SSH_D_NETGARB, ("Unsupported IPX frame"));
      goto drop;

    case SSH_PROTOCOL_OTHER:
    default:
      SSH_TRACE(SSH_D_NETGARB, ("Unsupported frame of unknown type %d",
                                (int) pp->protocol));
      goto drop;
    }

  /* IP fragments never end up here. */
  SSH_ASSERT((pp->flags & SSH_ENGINE_P_ISFRAG) == 0
             || (pp->flags & SSH_ENGINE_P_FIRSTFRAG));

  SSH_ASSERT(pc->packet_len >= pc->hdrlen);
  length = pc->packet_len - pc->hdrlen;

  /* Parse transport layer protocols. */
  switch (pc->ipproto)
    {
    case SSH_IPPROTO_TCP:
      if (length < SSH_TCPH_HDRLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated TCP packet: length %d needed %d",
                     (int) length, (int) SSH_TCPH_HDRLEN));
          pc->audit.corruption =
            SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
#ifdef WITH_IPV6
          if (pp->protocol == SSH_PROTOCOL_IP6)
            {
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_extra_data = pc->hdrlen;
            }
#endif /* WITH_IPV6 */
          goto corrupt;
        }

      /* Fetch TCP header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_TCPH_HDRLEN,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      /* Parse TCP header. */
      pc->u.rule.src_port = SSH_TCPH_SRCPORT(ucp);
      pc->u.rule.dst_port = SSH_TCPH_DSTPORT(ucp);
      pc->u.rule.header_cache.tcp_data_offset = SSH_TCPH_DATAOFFSET(ucp);
      pc->u.rule.header_cache.tcp_flags = SSH_TCPH_FLAGS(ucp);
      pc->u.rule.header_cache.tcp_urgent = SSH_TCPH_URGENT(ucp);

      SSH_DEBUG(SSH_D_LOWOK, ("TCP header: src %d dst %d",
                              (int) pc->u.rule.src_port,
                              (int) pc->u.rule.dst_port));
      break;

    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
      if (length < SSH_UDPH_HDRLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated UDP packet: length %d needed %d",
                     (int) length, (int) SSH_UDPH_HDRLEN));
          pc->audit.corruption =
            SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
#ifdef WITH_IPV6
          if (pp->protocol == SSH_PROTOCOL_IP6)
            {
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_extra_data = pc->hdrlen;
            }
#endif /* WITH_IPV6 */
          goto corrupt;
        }

      /* Fetch UDP header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_UDPH_HDRLEN,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      /* Parse UDP header. */
      pc->u.rule.src_port = SSH_UDPH_SRCPORT(ucp);
      pc->u.rule.dst_port = SSH_UDPH_DSTPORT(ucp);

      /* Parse UDPLite header. */
      if (pc->ipproto == SSH_IPPROTO_UDPLITE)
        pc->u.rule.header_cache.udplite_csum_cov =
          SSH_UDP_LITEH_CKSUM_COVERAGE(ucp);

      SSH_DEBUG(SSH_D_LOWOK,
                ("%s header: src %d dst %d",
                 (pc->ipproto == SSH_IPPROTO_UDP ? "UDP" : "UDPlite"),
                 (int) pc->u.rule.src_port,
                 (int) pc->u.rule.dst_port));
      break;

    case SSH_IPPROTO_SCTP:
      if (length < SSH_SCTPH_HDRLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated SCTP packet: length %d needed %d",
                     (int) length, (int) SSH_SCTPH_HDRLEN));
          pc->audit.corruption =
            SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
#ifdef WITH_IPV6
          if (pp->protocol == SSH_PROTOCOL_IP6)
            {
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_extra_data = pc->hdrlen;
            }
#endif /* WITH_IPV6 */
          goto corrupt;
        }

      /* Fetch SCTP header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_SCTPH_HDRLEN,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      /* Parse SCTP header. */
      pc->u.rule.src_port = SSH_SCTPH_SRCPORT(ucp);
      pc->u.rule.dst_port = SSH_SCTPH_DSTPORT(ucp);

      SSH_DEBUG(SSH_D_LOWOK, ("SCTP header: src %d dst %d",
                              (int) pc->u.rule.src_port,
                              (int) pc->u.rule.dst_port));
      break;

    case SSH_IPPROTO_AH:
      /* Require only minimum amount of AH header. */
      if (length < SSH_AHH_OFS_SPI + 4)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated AH packet: length %d needed %d",
                     (int) length, (int) SSH_AHH_OFS_SPI + 4));
          pc->audit.corruption =
            SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
#ifdef WITH_IPV6
          if (pp->protocol == SSH_PROTOCOL_IP6)
            {
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_extra_data = pc->hdrlen;
            }
#endif /* WITH_IPV6 */
          goto corrupt;
        }

      /* Fetch beginning of AH header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_AHH_OFS_SPI + 4,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      pc->u.rule.spi = SSH_AHH_SPI(ucp);

      SSH_DEBUG(SSH_D_LOWOK, ("AH header: SPI %08lx",
                              (unsigned long) pc->u.rule.spi));
      break;

    case SSH_IPPROTO_ESP:
      /* Require only minimum amount of ESP header. */
      if (length < SSH_ESPH_OFS_SPI + 4)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated ESP packet: length %d needed %d",
                     (int) length, (int) SSH_ESPH_OFS_SPI + 4));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
#ifdef WITH_IPV6
          if (pp->protocol == SSH_PROTOCOL_IP6)
            {
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_extra_data = pc->hdrlen;
            }
#endif /* WITH_IPV6 */
          goto corrupt;
        }

      /* Fetch beginning of ESP header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_ESPH_OFS_SPI + 4,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      pc->u.rule.spi = SSH_ESPH_SPI(ucp);

      SSH_DEBUG(SSH_D_LOWOK, ("ESP header: SPI %08lx",
                              (unsigned long) pc->u.rule.spi));
      break;

    case SSH_IPPROTO_ICMP:
      /* IPv4 and IPv6 header parsing has already sanity checked this. */
      SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP4);
      if (length < SSH_ICMPH_HEADER_MINLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("Truncated ICMP packet: length %d needed %d",
                     (int) length,
                     (int) SSH_ICMPH_HEADER_MINLEN));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
          goto corrupt;
        }

      /* Fetch beginning of ICMP header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_ICMPH_HEADER_MINLEN,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      pc->icmp_type = SSH_ICMPH_TYPE(ucp);
      pc->u.rule.icmp_code = SSH_ICMPH_CODE(ucp);

      if (pc->icmp_type == SSH_ICMP_TYPE_ECHO
          || pc->icmp_type == SSH_ICMP_TYPE_ECHOREPLY)
        {
          if (length < SSH_ICMPH_ECHO_LEN)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Truncated ICMP echo packet: length %d needed %d",
                         (int) length,
                         (int) SSH_ICMPH_ECHO_LEN));
              pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
              goto corrupt;
            }

          /* Fetch beginning of ICMP echo header. */
          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_ICMPH_ECHO_LEN,
                                    pullup_buf);
          if (ucp == NULL)
            goto error;

          pc->u.rule.src_port = SSH_ICMPH_ECHO_ID(ucp);
        }

      SSH_DEBUG(SSH_D_LOWOK, ("ICMP header: type %d code %d",
                              (int) pc->icmp_type,
                              (int) pc->u.rule.icmp_code));
      break;

#if defined (WITH_IPV6)
    case SSH_IPPROTO_IPV6ICMP:
      /* IPv4 and IPv6 header parsing has already sanity checked this. */
      SSH_ASSERT(pp->protocol == SSH_PROTOCOL_IP6);
      if (length < SSH_ICMP6H_HDRLEN)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Truncated ICMPv6 packet"));
          pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
          pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
          pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
          pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
          pc->error_info.icmp_extra_data = pc->hdrlen;
          goto corrupt;
        }

      /* Fetch the ICMPv6 header. */
      SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_ICMP6H_HDRLEN,
                                pullup_buf);
      if (ucp == NULL)
        goto error;

      pc->icmp_type = SSH_ICMP6H_TYPE(ucp);
      pc->u.rule.icmp_code = SSH_ICMP6H_CODE(ucp);

      if (pc->icmp_type == SSH_ICMP6_TYPE_ECHOREQUEST
          || pc->icmp_type == SSH_ICMP6_TYPE_ECHOREPLY)
        {
          if (length < SSH_ICMP6H_ECHO_LEN)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("Truncated ICMPv6 echo packet: length %d needed %d",
                         (int) length,
                         (int) SSH_ICMP6H_ECHO_LEN));
              pc->audit.corruption = SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
              pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
              pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
              pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
              pc->error_info.icmp_extra_data = pc->hdrlen;
              goto corrupt;
            }

          /* Fetch beginning of ICMP echo header. */
          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen, SSH_ICMP6H_ECHO_LEN,
                                    pullup_buf);
          if (ucp == NULL)
            goto error;

          pc->u.rule.src_port = SSH_ICMP6H_ECHO_ID(ucp);
        }

      SSH_DEBUG(SSH_D_LOWOK, ("ICMPv6 header: type %d code %d",
                              (int) pc->icmp_type,
                              (int) pc->u.rule.icmp_code));
      break;
#endif /* WITH_IPV6 */

    default:
      if ((pp->flags & SSH_ENGINE_P_FIRSTFRAG) == 0)
        goto drop;
      /* Leave transport layer unparsed for unknown IP protocols. */
      SSH_DEBUG(SSH_D_LOWOK, ("IP proto %d", (int) pc->ipproto));
      break;
    }

 out:
  return TRUE;

  /* Error handling. */

 corrupt:
  /* The packet was corrupted */
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
  return FALSE;

 drop:
  /* The packet should be dropped.  It is not freed yet. */
  ssh_interceptor_packet_free(pc->pp);
  /* FALLTHROUGH */

 error:
  /* The packet was freed by this function.  Clear the `pp' field from
     `pc' to indicate this. */
  pc->pp = NULL;
  return FALSE;
}

SSH_FASTTEXT
Boolean
fastpath_packet_context_pullup_xid(SshEngine engine,
                                   SshEnginePacketContext pc)
{
  unsigned char pullup_buf[4];
  const unsigned char *ucp;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  Boolean is_ike_natt;
  int i;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  SSH_ASSERT(pc->pp->protocol == SSH_PROTOCOL_IP4
             || pc->pp->protocol == SSH_PROTOCOL_IP6);

  switch (pc->ipproto)
    {
    case SSH_IPPROTO_UDP:
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Check if UDP destination port matches one of local IKE ports. */
      is_ike_natt = FALSE;
      for (i = 0; i < engine->num_ike_ports; i++)
        {
          if (((pc->pp->flags & SSH_PACKET_FROMADAPTER) &&
               pc->u.rule.dst_port == engine->local_ike_natt_ports[i]) ||
              ((pc->pp->flags & SSH_PACKET_FROMPROTOCOL) &&
               pc->u.rule.dst_port == engine->remote_ike_natt_ports[i]))
            {
              is_ike_natt = TRUE;
              break;
            }
        }

      /* Check if this is a NAT-T keepalive message (one byte of UDP payload
         and packet is directed to local stack). */
      if (is_ike_natt && pc->packet_len == (pc->hdrlen + SSH_UDPH_HDRLEN + 1))
        {
          if (ssh_engine_ip_is_local(engine, &pc->dst))
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Incoming NAT-T keepalive discarded"));
              return FALSE;
            }
        }

      /* Check if this is a UDP encapsulated ESP packet. */
      if (is_ike_natt && pc->packet_len >= (pc->hdrlen + SSH_UDPH_HDRLEN + 4))
        {
          /* Pullup SPI value from the ESP header after UDP and mark that
             flow lookup should be made assuming this packet is IPsec
             directed to us. */
          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen + SSH_UDPH_HDRLEN, 4,
                                    pullup_buf);
          if (ucp == NULL)
            {
              pc->pp = NULL;
              return FALSE;
            }
          pc->protocol_xid = SSH_GET_32BIT(ucp);
          pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
          break;
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* Pull-up DHCP xid */
      if (SSH_PREDICT_FALSE(pc->u.rule.dst_port == 67) ||
          SSH_PREDICT_FALSE(pc->u.rule.dst_port == 68))
        {
          /* Fetch transaction identifier. */
          if (pc->packet_len < (pc->hdrlen + SSH_UDPH_HDRLEN + 8))
            return FALSE;

          SSH_ENGINE_PC_PULLUP_READ(ucp, pc, pc->hdrlen + SSH_UDPH_HDRLEN + 4,
                                    4, pullup_buf);
          pc->protocol_xid = SSH_GET_32BIT(ucp);
        }
      break;

    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
      /* Copy AH and ESP SPI value to xid and mark that this is an IPsec
         packet directed to us. */
      pc->protocol_xid = pc->u.rule.spi;
      pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
      break;

    default:
      break;
    }

  return TRUE;
}

SSH_FASTTEXT
Boolean
fastpath_packet_context_pullup(SshEngine engine,
                               SshEnginePacketContext pc,
                               SshEnginePacketData pd)
{
  Boolean ret;
  size_t length;

  SSH_ASSERT(pc->pp != NULL);

  /* Initialize basic flags */
  pc->flags &= (SSH_ENGINE_PC_DONE | SSH_ENGINE_PC_OUTBOUND_CALL |
                SSH_ENGINE_PC_RESTARTED_OUT);

  /* This label starts or restarts processing of the packet.  We jump
     here when starting with the packet, and after decapsulating a
     packet from a tunnel in order to process the inner packet.
     tunnel_id will be set to 0 initially, and to some other value
     when a packet is decapsulated from a tunnel. */
  ret = fastpath_packet_parse(engine, pc, pd);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  /* Delete media header. */
  if (pc->pp != NULL && pc->media_hdr_len > 0)
    {
      if (ssh_interceptor_packet_delete(pc->pp, 0, pc->media_hdr_len)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Failed to delete media header from packet"));
          goto error;
        }
      pc->media_hdr_len = 0;
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  if (ret == FALSE)
    return FALSE;

  SSH_ASSERT(pc->pp != NULL);

  /* Delete trailing junk from packet. */
  length = ssh_interceptor_packet_len(pc->pp);
  SSH_ASSERT(pc->packet_len <= length);
  if (pc->packet_len < length)
    {
      if (ssh_interceptor_packet_delete(pc->pp, pc->packet_len,
                                        length - pc->packet_len) == FALSE)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Failed to delete packet trailer"));
          goto error;
        }
    }

  /* Pullup XID. */
  if (pc->pp->protocol == SSH_PROTOCOL_IP4
      || pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      if (fastpath_packet_context_pullup_xid(engine, pc) == FALSE)
        return FALSE;
    }

  /* If this packet was restarted after outbound transform execution,
     then clear the SSH_ENGINE_PC_IS_IPSEC flag to avoid matching incoming
     ipsec flows in the flow lookup. */
  if (pc->flags & SSH_ENGINE_PC_RESTARTED_OUT)
    pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;

  return TRUE;

 error:
  /* The packet was freed by this function.  Clear the `pp' field from
     `pc' to indicate this. */
  pc->pp = NULL;

  return FALSE;
}


/* Simple table for specifying handling of IP options */
struct SshIpOptReqsRec
{
  /* Option Id */
  SshUInt8 id;

  /* Minimum supported value for TLV encoded option.
     MUST be greater than 0 for TLV encoded options. */
  SshUInt8 min_length;

  /* Maximum supportde value for option. If 0, then
     assume the option is of the type-only encoding.
     If greater than 0, then assume option is TLV encoded. */
  SshUInt8 max_length;

  /* Require option to be aligned on a 4-byte boundary
     in packet. */
  Boolean force_alignment;

  /* Is option allowed in packet? If FALSE, then packets
     containing this option are dropped. */
  Boolean is_allowed;
};

/* Descriptions of individual IP options. Check
   http://www.iana.org/assignments/ip-options
   for a complete list. This description
   corresponds to the 2001-06-29 published/updated
   list.

   Unsupported options:
   - CIPSO (Commercial Security Option, WG terminated 95).
   - MTU Probe (IANA assignment obsolete)
   - MTU Reply (IANA assignment obsolete)
   - ZSU (Experimental Measurement, Proprietary)
   - FINN (Experimental Flow Control, Proprietary)
   - VISA (Experimental Access Control, Proprietary)
   - IMITD (IMI Traffic Descriptor, Proprietary)
   - ADDEXT (Address Extension, Proprietary)
   - SDB, NDAPA, DPS, UMP, ENCODE (Proprietary)
*/

SSH_RODATA
static const struct SshIpOptReqsRec ssh_ip_opt_reqs[] =
  {
    { 0, 0, 0, FALSE, TRUE },     /* End-Of-Options [RFC791]*/
    { 1, 0, 0, FALSE, TRUE },     /* Nop [RFC791]*/
    { 2, 3, 0xFF, FALSE, TRUE },  /* Security [RFC1108] */
    { 3, 2, 0xFF, FALSE, FALSE }, /* Loose-Source [RFC791] */
    { 5, 3, 0xFF, FALSE, TRUE },  /* Extended-Security [RFC1108] */
    { 7, 2, 0xFF, FALSE, TRUE },  /* Record-Route [RFC791] */
    { 8, 4, 4, FALSE, TRUE },     /* Stream-Id [RFC791] */
    { 9, 2, 0xFF, FALSE, FALSE }, /* Strict-Source [RFC791]  */
    {17, 2, 0xFF, FALSE, TRUE},   /* EIP [RFC1385] */
    {20, 4, 4, FALSE, TRUE },     /* Router-Alert [RFC2113] */
    {68, 2, 0xFF, TRUE, TRUE },   /* Time-Stamp [RFC791] */
    {82, 2, 0xFF, FALSE, TRUE },  /* Traceroute option [RFC1393] */
    { 0xFF, 0, 0, FALSE, FALSE }, /* Last option in the list */
    { 0, 2, 0xFF, FALSE, TRUE },  /* Unrecognized option. This
                                     MUST be after the previous
                                     "Last option" in this table. */
  };

static SshEnginePacketCorruption
fastpath_ipv4_option_is_sane(SshEngine engine,
                             SshInterceptorPacket pp,
                             const SshEnginePacketContext pc,
                             SshUInt32 *option_ret)
{
  const unsigned char *ucp;
  SshUInt16 checksum;
  int i, j;

#ifndef SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS
  if (pc->hdrlen > pc->packet_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 HLEN > packet len"));
      return SSH_PACKET_CORRUPTION_TRUNCATED_PACKET;
    }
#endif /* SSH_IPSEC_SKIP_LINUX_SANITY_CHECKS */

  SSH_DEBUG(SSH_D_LOWOK, ("ip options present"));

  /* Pullup packet header. */
  ucp = ssh_interceptor_packet_pullup_read(pp, pc->hdrlen);
  if (SSH_PREDICT_FALSE(ucp == NULL))
    {
      /* Is pc->pp the same as pp, if not drop also pc->pp, since
         the packet is somehow corrupted. */
      if (pc->pp != pp)
        ssh_interceptor_packet_free(pc->pp);

      pc->pp = NULL;
      SSH_DEBUG(SSH_D_FAIL, ("pullup read failed"));
      return SSH_PACKET_CORRUPTION_ERROR;
    }

  /* Calculate and verify IPv4 header checksum. */
  if ((pp->flags & SSH_PACKET_IP4HDRCKSUMOK) == 0)
    {
      checksum = ssh_ip_cksum(ucp, pc->hdrlen);
      if (checksum != 0)
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 checksum mismatch(w/opt)"));
          return SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH;
        }
    }

  /* Iterate IPv4 options. */
  for (i = SSH_IPH4_HDRLEN; i < pc->hdrlen;)
    {
      /* End-Of-Options list */
      if ((ucp[i] & 0x7f) == 0x0)
        break;

      for (j = 0; ssh_ip_opt_reqs[j].id < 0xF0; j++)
        {
          if ((ucp[i] & 0x7f) == ssh_ip_opt_reqs[j].id)
            break;
        }

      if (ssh_ip_opt_reqs[j].id >= 0xF0)
        {
          SSH_DEBUG(SSH_D_NETGARB,("Unknown IP option 0x%x",ucp[i]));

          if (SSH_IPSEC_ALLOW_UNKNOWN_IPV4_OPTIONS)
            {
              j++; /* Skip to the next option which is the
                      "default unrecognized option */
            }
          else
            {
              *option_ret = ucp[i] & 0x7f;
              return SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION;
            }
        }

      if (ssh_ip_opt_reqs[j].is_allowed == FALSE)
        {
          SSH_DEBUG(SSH_D_NETGARB,("policy: forbidden IP option 0x%x",
                                   ucp[i]));
          *option_ret = ucp[i] & 0x7f;
          return SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION;
        }

      if (ssh_ip_opt_reqs[j].force_alignment == TRUE
          && (i % 4) != 0)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("policy: option 0x%x is not aligned as required",
                     ucp[i]));
          *option_ret = ucp[i] & 0x7f;
          return SSH_PACKET_CORRUPTION_UNALIGNED_OPTION;
        }

      if (ssh_ip_opt_reqs[j].max_length == 0)
        {
          i++;
        }
      else if ((i + 1) >= pc->hdrlen)
        {
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv4 option 0x%x lacking required length field",
                     ucp[i]));
          *option_ret = ucp[i] & 0x7f;
          return SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT;
        }
      else
        {
          /* Prevent infinite loop. */
          SSH_ASSERT(ssh_ip_opt_reqs[j].min_length > 0);

          if ((ssh_ip_opt_reqs[j].min_length > ucp[i+1])
              || (ssh_ip_opt_reqs[j].max_length < ucp[i+1]))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("IPv4 option 0x%x length does not satisfy spec",
                         ucp[i]));
              *option_ret = ucp[i] & 0x7f;
              return SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT;
            }
          i += ucp[i+1];
        }
    }
  if (i > pc->hdrlen)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("IPv4 options incorrectly formatted"));
      return SSH_PACKET_CORRUPTION_OPTION_OVERFLOW;
    }

  return SSH_PACKET_CORRUPTION_NONE;
}

static SshEnginePacketCorruption
fastpath_ipv4_fragment_is_sane(SshEngine engine,
                               SshInterceptorPacket pp,
                               const SshEnginePacketContext pc)
{
  SshUInt16 fragoff;

  fragoff = 8 * (pc->fragment_offset & SSH_IPH4_FRAGOFF_OFFMASK);
  if (fragoff + pc->packet_len - pc->hdrlen > 65535)
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 fragment goes beyond 64k"));
      return SSH_PACKET_CORRUPTION_FRAGMENT_OVERFLOW_LENGTH;
    }

  if ((pp->flags & SSH_ENGINE_P_LASTFRAG) == 0)
    {
      if ((pc->packet_len - pc->hdrlen) % 8 != 0)
        {
          /* Non-last frag data len is not multiple of 8. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv4 non-last fragment has bad length"));

          return SSH_PACKET_CORRUPTION_FRAGMENT_BAD_LENGTH;
        }

      /* If this is not a last fragment, then there must be a minimum
         amount of data (in practice all links provide reasonable MTU;
         smaller fragments are almost certainly attacks).
         Theoretically minimum size is 8, but such fragments are never
         sent in practice). */
      if ((pc->packet_len < SSH_ENGINE_MIN_FIRST_FRAGMENT_V4) &&
          (pp->flags & SSH_ENGINE_P_FIRSTFRAG))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 policy: too small fragment"));
          return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
        }

      if (pc->packet_len < (pc->hdrlen + SSH_ENGINE_MIN_FRAGMENT_V4))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv4 policy: too small fragment"));
          return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
        }
    }

  /* Fragment cannot start earlier than the minimum offset. */
  if (fragoff != 0
      && (pc->hdrlen + fragoff < SSH_ENGINE_MIN_FIRST_FRAGMENT_V4))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 policy: frag starts early"));
      return SSH_PACKET_CORRUPTION_FRAGMENT_OFFSET_TOO_SMALL;
    }

  return SSH_PACKET_CORRUPTION_NONE;
}

/* This function sanity checks a packet. */
SSH_FASTTEXT static SshEnginePacketCorruption
fastpath_context_ipv4_is_sane(SshEngine engine,
                              SshInterceptorPacket pp,
                              const SshEnginePacketContext pc,
                              SshUInt32 *option_ret)
{
  SshUInt16 checksum;
  SshEnginePacketCorruption corrupt;
  SshInterceptorInterface *ifp;

  /* Check for traceroute TTL. */
  if (SSH_PREDICT_FALSE(pc->u.rule.ttl < engine->min_ttl_value))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv4 TTL %d < engine->min_ttl_value",
                             (int) pc->u.rule.ttl));
      return SSH_PACKET_CORRUPTION_TTL_SMALL;
    }

  /* Check for multicast/broadcast/anycast source address.
     Note that "0.0.0.0" is a valid IP source address used by
     e.g. DHCP. */
  if (SSH_PREDICT_FALSE(SSH_IP4_BYTE1(&pc->src) >= 0xe0))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid IPv4 source address %@",
                             ssh_ipaddr_render, &pc->src));
      return SSH_PACKET_CORRUPTION_MULTICAST_SOURCE;
    }

  /* Sanity check header length and checksum; check IP options. */
  if (SSH_PREDICT_TRUE(pc->hdrlen == SSH_IPH4_HDRLEN))
    {
      if (SSH_PREDICT_FALSE((pp->flags & SSH_PACKET_IP4HDRCKSUMOK) == 0))
        {
          checksum = ssh_ip_cksum_packet(pc->pp, 0, pc->hdrlen);
          if (SSH_PREDICT_FALSE(checksum != 0))
            {
              SSH_DEBUG(SSH_D_FAIL, ("IPv4 checksum mismatch"));
              return SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH;
            }
        }
    }
  else
    {
      /* Options are rare, thus have them checked on separate function
         to have less text on fastpath */
      corrupt = fastpath_ipv4_option_is_sane(engine, pp, pc, option_ret);
      if (SSH_PREDICT_FALSE(corrupt != SSH_PACKET_CORRUPTION_NONE))
        return corrupt;
    }

  /* Sanity check fragment information.  Cache whether the packet is a
     fragment. */
  if (SSH_PREDICT_FALSE(pp->flags & SSH_ENGINE_P_ISFRAG))
    {
      /* Fragment are rare, thus have them checked on separate function. */
      corrupt = fastpath_ipv4_fragment_is_sane(engine, pp, pc);
      if (SSH_PREDICT_FALSE(corrupt != SSH_PACKET_CORRUPTION_NONE))
        return corrupt;
    }

  /* Sanity check transport layer protocol header if packet is unfragmented
     or this is the first fragment. */
  if (SSH_PREDICT_TRUE((pp->flags & SSH_ENGINE_P_ISFRAG) == 0
                       || (pp->flags & SSH_ENGINE_P_FIRSTFRAG)))
    {
      switch (pc->ipproto)
        {
        case SSH_IPPROTO_TCP:
          {
            SshUInt32 tcphlen;

            /* Check that TCP header fits into first fragment */
            tcphlen = 4 * pc->u.rule.header_cache.tcp_data_offset;
            if (pc->hdrlen + tcphlen > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("TCP header fragmented"));
                return SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED;
              }

            /* Check for urgent pointer pointing outside of this
               packets boundary */
            if (pc->u.rule.header_cache.tcp_flags & SSH_TCPH_FLAG_URG)
              {
                pc->min_packet_size =
                  pc->hdrlen + tcphlen + pc->u.rule.header_cache.tcp_urgent;

                if (pc->min_packet_size > pc->packet_len)
                  {
                    SSH_DEBUG(SSH_D_NETGARB, ("Winnuke attack detected"));
                    return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
                  }
              }

            /* Check for LAND attack */
            if (SSH_IP_EQUAL(&pc->src, &pc->dst)
                && pc->u.rule.dst_port == pc->u.rule.src_port)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("LAND attack detected"));
                return SSH_PACKET_CORRUPTION_SRC_DST_SAME;
              }

            if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("Reserved TCP port detected"));
                return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
              }

            /* Check for all kinds of TCP scans */
            if ((pc->u.rule.header_cache.tcp_flags &
                 (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
                == (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
              {
                SSH_DEBUG(SSH_D_NETGARB, ("TCP xmas scan detected"));
                return SSH_PACKET_CORRUPTION_TCP_XMAS;
              }
          }
          break;

        case SSH_IPPROTO_UDPLITE:
          if (SSH_PREDICT_FALSE(pc->u.rule.header_cache.udplite_csum_cov != 0
                                && pc->u.rule.header_cache.udplite_csum_cov < 8
                                ))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("UDPLite checksum coverage field less than 8"));
              return SSH_PACKET_CORRUPTION_CHECKSUM_COVERAGE_TOO_SMALL;
            }
          /* Fall-through */
        case SSH_IPPROTO_UDP:
          if (SSH_PREDICT_FALSE(pc->u.rule.src_port == 0) ||
              SSH_PREDICT_FALSE(pc->u.rule.dst_port == 0))
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Reserved UDP port detected"));
              return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
            }
          break;

        case SSH_IPPROTO_SCTP:
          if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("Reserved SCTP port detected"));
              return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
            }
          break;
        case SSH_IPPROTO_ICMP:
          switch (pc->icmp_type)
            {
            case SSH_ICMP_TYPE_UNREACH:
            case SSH_ICMP_TYPE_SOURCEQUENCH:
            case SSH_ICMP_TYPE_TIMXCEED:
            case SSH_ICMP_TYPE_PARAMPROB:
              if (pc->packet_len < (pc->hdrlen + SSH_ICMP_MINLEN
                                    + SSH_IPH4_HDRLEN + 8))
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("ICMP unreachable too short"));
                  return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                }
              break;
            case SSH_ICMP_TYPE_ECHO:
            case SSH_ICMP_TYPE_ECHOREPLY:
              if (!engine->broadcast_icmp)
                {
                  ssh_kernel_mutex_lock(engine->interface_lock);
                  ifp = ssh_ip_get_interface_by_broadcast(&engine->ifs,
                                                          &pc->dst,
                                                  SSH_INTERCEPTOR_VRI_ID_ANY);
                  if (ifp != NULL || SSH_IP_IS_BROADCAST(&pc->dst))
                    {
                      SSH_DEBUG(SSH_D_NETGARB,
                                ("ICMP broadcast pkt received"));
                      ssh_kernel_mutex_unlock(engine->interface_lock);
                      return SSH_PACKET_CORRUPTION_ICMP_BROADCAST;
                    }
                  ssh_kernel_mutex_unlock(engine->interface_lock);
                }
              if (pc->packet_len < pc->hdrlen + SSH_ICMP_MINLEN)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("ICMP echo too short"));
                  return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                }
              break;
            default:
              break;
            }
          break;
        }
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IPv4 ipproto=%d packet seems sane",
                          (int)pc->ipproto));

  return SSH_PACKET_CORRUPTION_NONE;
}

#if defined (WITH_IPV6)

static SshEnginePacketCorruption
fastpath_ipv6_fragment_is_sane(SshEngine engine,
                               const SshEnginePacketContext pc)
{
  SshInterceptorPacket pp = pc->pp;
  SshUInt32 frag_data_len;
  SshUInt32 total_len;

  SSH_ASSERT(pp != NULL);

  frag_data_len = (pc->packet_len - (pc->fragh_offset +
                                     SSH_IP6_EXT_FRAGMENT_HDRLEN));
  total_len = pc->fragment_offset + frag_data_len;

  if (SSH_PREDICT_FALSE(total_len > 0xffff))
    {
      SSH_DEBUG(SSH_D_FAIL, ("IPv6 fragment goes beyond 64k"));
      return SSH_PACKET_CORRUPTION_FRAGMENT_OVERFLOW_LENGTH;
    }

  if (SSH_PREDICT_TRUE((pp->flags & SSH_ENGINE_P_LASTFRAG) == 0))
    {
      if ((frag_data_len % 8) != 0)
        { /* Non-last frag data len is not multiple of 8. */
          SSH_DEBUG(SSH_D_NETGARB,
                    ("IPv6 non-last fragment has bad length"));

          pc->error_info.flags |= SSH_ENGINE_SEND_ICMP_ERROR;
          pc->error_info.icmp_type = SSH_ICMP6_TYPE_PARAMPROB;
          pc->error_info.icmp_code = SSH_ICMP6_CODE_PARAMPROB_HEADER;
          pc->error_info.icmp_extra_data = SSH_IPH6_OFS_LEN;
          return SSH_PACKET_CORRUPTION_FRAGMENT_BAD_LENGTH;
        }

      /* If this is the first fragment, check our configured
         minimum size. */
      if ((pp->flags & SSH_ENGINE_P_FIRSTFRAG) &&
          (pc->packet_len < SSH_ENGINE_MIN_FIRST_FRAGMENT_V6))
        {
          SSH_DEBUG(SSH_D_FAIL, ("IPv6 policy: too small fragment"));
          return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
        }
    }

  return SSH_PACKET_CORRUPTION_NONE;
}

/* This function sanity checks a packet context. For IPv6 this means
   only sanity checks for the user protocol, as options (extension
   headers) have been checked during context pullup due to
   differencies on IPv4 and IPv6 option mechanisms. */
static SshEnginePacketCorruption
fastpath_context_ipv6_is_sane(SshEngine engine,
                              SshInterceptorPacket pp,
                              const SshEnginePacketContext pc,
                              SshUInt32 *option_ret)
{
  SshEnginePacketCorruption corrupt;

  if ((pp->flags & SSH_ENGINE_P_ISFRAG) == 0
      || (pp->flags & SSH_ENGINE_P_FIRSTFRAG))
    {
      switch (pc->ipproto)
        {
        case SSH_IPPROTO_TCP:
          {
            SshUInt32 tcphlen;

            /* Check that TCP header fits into first fragment */
            tcphlen = 4 * pc->u.rule.header_cache.tcp_data_offset;
            if (pc->hdrlen + tcphlen > pc->packet_len)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("IPv6 TCP header fragmented"));
                return SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED;
              }

            /* Check for urgent pointer pointing outside of this
               packets boundary */
            if (pc->u.rule.header_cache.tcp_flags & SSH_TCPH_FLAG_URG)
              {
                pc->min_packet_size =
                  pc->hdrlen + tcphlen + pc->u.rule.header_cache.tcp_urgent;

                if (pc->min_packet_size > pc->packet_len)
                  {
                    SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Winnuke attack detected"));
                    return SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL;
                  }
              }

            /* Check for LAND attack */
            if (SSH_IP_EQUAL(&pc->src, &pc->dst)
                && pc->u.rule.dst_port == pc->u.rule.src_port)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("IPv6 LAND attack detected"));
                return SSH_PACKET_CORRUPTION_SRC_DST_SAME;
              }

            if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
              {
                SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Reserved TCP port detected"));
                return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
              }

            /* Check for all kinds of TCP scans */
            if ((pc->u.rule.header_cache.tcp_flags &
                 (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
                == (SSH_TCPH_FLAG_URG|SSH_TCPH_FLAG_FIN|SSH_TCPH_FLAG_PSH))
              {
                SSH_DEBUG(SSH_D_NETGARB, ("IPv6 TCP xmas scan detected"));
                return SSH_PACKET_CORRUPTION_TCP_XMAS;
              }
          }
          break;
        case SSH_IPPROTO_UDPLITE:
          if (SSH_PREDICT_FALSE(pc->u.rule.header_cache.udplite_csum_cov != 0
                                && pc->u.rule.header_cache.udplite_csum_cov < 8
                                ))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("IPv6 UDPLite checksum coverage field less than 8"));
              return SSH_PACKET_CORRUPTION_CHECKSUM_COVERAGE_TOO_SMALL;
            }
          /* Fall-through */
        case SSH_IPPROTO_UDP:
          if (SSH_PREDICT_FALSE(pc->u.rule.src_port == 0
                                || pc->u.rule.dst_port == 0))
            {
              SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Reserved UDP port detected"));
              return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
            }
          break;
        case SSH_IPPROTO_SCTP:
          if (pc->u.rule.src_port == 0 || pc->u.rule.dst_port == 0)
            {
              SSH_DEBUG(SSH_D_NETGARB, ("IPv6 Reserved SCTP port detected"));
              return SSH_PACKET_CORRUPTION_RESERVED_VALUE;
            }
          break;
        case SSH_IPPROTO_IPV6ICMP:
          if (pc->icmp_type == SSH_ICMP6_TYPE_UNREACH)
            {
              if (pc->hdrlen + SSH_ICMP6H_UNREACH_LEN + SSH_IPH6_HDRLEN
                  >= pc->packet_len)
                {
                  SSH_DEBUG(SSH_D_NETGARB, ("ICMPv6 unreachable too short"));
                  return SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL;
                }
            }
          break;
        default:
          break;
        }
    }

  if (SSH_PREDICT_FALSE(pp->flags & SSH_ENGINE_P_ISFRAG))
    {
      /* Fragment are rare, thus have them checked on separate function. */
      corrupt = fastpath_ipv6_fragment_is_sane(engine, pc);
      if (corrupt != SSH_PACKET_CORRUPTION_NONE)
        return corrupt;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("IPv6 ipproto=%d packet seems sane",
                          (int)pc->ipproto));

  return SSH_PACKET_CORRUPTION_NONE;
}
#endif /* WITH_IPV6 */

SSH_FASTTEXT SshEnginePacketCorruption
fastpath_packet_context_is_sane(SshEngine engine,
                                SshInterceptorProtocol proto,
                                SshInterceptorPacket pp,
                                const SshEnginePacketContext pc,
                                SshUInt32 *option_ret)
{
  *option_ret = 0;

  if (SSH_PREDICT_TRUE(proto == SSH_PROTOCOL_IP4))
    goto ssh_protocol_ip4;

  /* Strip media header if the packet has one. */
  switch (proto)
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
    case SSH_PROTOCOL_ETHERNET:
      return SSH_PACKET_CORRUPTION_NONE;
      break;

    case SSH_PROTOCOL_FDDI:
      /* We currently only support ethernet media.  Drop the packet. */
      SSH_TRACE(SSH_D_FAIL, ("unsupported FDDI encapsulated packet"));
      return SSH_PACKET_CORRUPTION_ERROR;

    case SSH_PROTOCOL_TOKENRING:
      SSH_TRACE(SSH_D_FAIL, ("unsupported TOKENRING encapsulated packet"));
      return SSH_PACKET_CORRUPTION_ERROR;

    case SSH_PROTOCOL_ARP:
      SSH_DEBUG(SSH_D_LOWSTART, ("ARP packet received"));
      return SSH_PACKET_CORRUPTION_NONE;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

    ssh_protocol_ip4:
    case SSH_PROTOCOL_IP4:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv4 packet"));
      /* Perform basic sanity checks on the packet. */
      return fastpath_context_ipv4_is_sane(engine, pp, pc, option_ret);

#if defined (WITH_IPV6)
    case SSH_PROTOCOL_IP6:
      SSH_DEBUG(SSH_D_LOWSTART, ("IPv6 packet"));
      return fastpath_context_ipv6_is_sane(engine, pp, pc, option_ret);
#endif /* WITH_IPV6 */

    default:
      SSH_DEBUG(SSH_D_LOWOK, ("non-ip packet, protocol=%d - dropping",
                              (int)proto));
      return SSH_PACKET_CORRUPTION_ERROR;
    }
  /*NOTREACHED*/
}
