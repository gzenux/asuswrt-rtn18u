/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code to implement NAT transforms for packets.
*/

#include "sshincludes.h"
#include "engine_internal.h"


#define SSH_DEBUG_MODULE "SshEngineFastpathTransformNat"

#ifdef SSHDIST_IPSEC_NAT

/* Performs NAT on either source or destination address and port.  This
   basically just writes the respective IP address and port, and updates
   the header checksum accordingly.  This returns FALSE if an error occurs
   (in which case pc->pp has been freed). */

#define CHKOFFS_INVALID ((size_t)-1)

SSH_FASTTEXT
Boolean ssh_fastpath_execute_nat(SshEnginePacketContext pc,
                                 Boolean do_src,
                                 SshIpAddr new_ip,
                                 SshUInt16 new_port)
{
  unsigned char old_ip[16];
  size_t ip_ofs, port_ofs, hdr2len, hdr2cks_ofs, hdrlen, addr_len;
  size_t pseudo_hdrlen, ip_ofs_pseudohdr;
  size_t payload_iphdr_len, payload_protocolhdr_len, payload_ofs_cks;
  size_t icmp_len, pp_offset;
  SshUInt16 cks, old_port;
  SshUInt16 new_proto_cks, new_ip_cks, old_ip_cks, old_proto_cks;
  SshUInt8 icmp_type, port_proto;
  unsigned char *packet_hdr;
#if defined (WITH_IPV6)
  unsigned char protocol_hdr_buf[20];
#endif /* WITH_IPV6 */
  unsigned char *protocol_hdr;
  Boolean do_protocol_header;

  if (pc->pp->flags & SSH_PACKET_HWCKSUM)
    {
      /* If this packet does not have the TCP/UDP checksum computed, i.e. the
         checksum should be computed by the NIC device, then we compute the
         upper layer checksum here. */
      if (pc->pp->flags & SSH_PACKET_FROMPROTOCOL)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Computing TCP/UDP checksum for outbound packet"));

          if (!ssh_ip_cksum_packet_compute(pc->pp, 0, pc->hdrlen))
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Cannot compute checksum, dropping packet"));
              pc->pp = NULL;
              return FALSE;
            }
          pc->pp->flags &= ~SSH_PACKET_HWCKSUM;
        }

      /* If the packet TCP/UDP checksum has already been verified by
         hardware, then we clear the flag to indicate that protocol stack
         should re-verify the checksum. */
      else
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Clearing HW cksum flag from inbound packet"));
          pc->pp->flags &= ~SSH_PACKET_HWCKSUM;
        }
    }

  SSH_DEBUG(SSH_D_MIDSTART, ("nat: do_src=%d, new_ip=%@, new_port=%d",
                             (int)do_src,
                             ssh_ipaddr_render, new_ip,
                             (int)new_port));

  SSH_DUMP_PACKET(SSH_D_MY + 10, "BEFORE NAT:", pc->pp);

  /* Determine the offset for the packet and TCP/UDP checksum. */
  hdrlen = pc->hdrlen;
  payload_iphdr_len = 0; /* Mark that there is no payload packet */
  payload_protocolhdr_len = 0;
  payload_ofs_cks = 0; /* Mark that we only need update one checksum
                          for a port change */
  icmp_type = 0;
  pp_offset = 0;

#if defined (WITH_IPV6)
  if (SSH_PREDICT_FALSE(pc->pp->protocol == SSH_PROTOCOL_IP6))
    {
      SSH_ASSERT(SSH_IP_IS6(new_ip));
      addr_len = SSH_IPH6_ADDRLEN;
      pseudo_hdrlen = SSH_IP6_PSEUDOH_HDRLEN;
      if (do_src)
        {
          ip_ofs = SSH_IPH6_OFS_SRC;
          ip_ofs_pseudohdr = SSH_IP6_PSEUDOH_OFS_SRC;
        }
      else
        {
          ip_ofs = SSH_IPH6_OFS_DST;
          ip_ofs_pseudohdr = SSH_IP6_PSEUDOH_OFS_DST;
        }
    }
  else
#endif /* WITH_IPV6 */
    {
      SSH_ASSERT(SSH_IP_IS4(new_ip));
      addr_len = SSH_IPH4_ADDRLEN;
      pseudo_hdrlen = SSH_TCPH_PSEUDO_HDRLEN;
      if (do_src)
        {
          ip_ofs = SSH_IPH4_OFS_SRC;
          ip_ofs_pseudohdr = SSH_TCPH_PSEUDO_OFS_SRC;
        }
      else
        {
          ip_ofs = SSH_IPH4_OFS_DST;
          ip_ofs_pseudohdr = SSH_TCPH_PSEUDO_OFS_DST;
        }
    }

  /* Check how much data we really need.  We do full NAT for full
     packets and first fragments.  Non-first fragments get only NAT
     for IP header. */
  if ((pc->pp->flags & (SSH_ENGINE_P_ISFRAG|SSH_ENGINE_P_FIRSTFRAG)) !=
      SSH_ENGINE_P_ISFRAG)
    do_protocol_header = TRUE;
  else
    do_protocol_header = FALSE;

  port_proto = pc->ipproto;
  switch (pc->ipproto)
    {
    case SSH_IPPROTO_TCP:
      hdr2len = SSH_TCP_HEADER_LEN;
      hdr2cks_ofs = SSH_TCPH_OFS_CHECKSUM;
      if (do_src)
        port_ofs = 0;
      else
        port_ofs = 2;
      break;
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
      hdr2len = SSH_UDP_HEADER_LEN;
      hdr2cks_ofs = SSH_UDPH_OFS_CHECKSUM;
      if (do_src)
        port_ofs = 0;
      else
        port_ofs = 2;
      break;
    case SSH_IPPROTO_ICMP:
      hdr2len = 6;
      hdr2cks_ofs = SSH_ICMPH_OFS_CHECKSUM;
      port_ofs = 4;

      icmp_len = hdrlen + (do_protocol_header ? hdr2len : 0);
      if (pc->packet_len < icmp_len)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to NAT do to small packet/fragment!"));
          return FALSE;
        }

      packet_hdr = ssh_interceptor_packet_pullup(pc->pp, icmp_len + pp_offset);
      if (packet_hdr == NULL)
        {
          pc->pp = NULL;
          return FALSE;
        }
      icmp_type = packet_hdr[hdrlen + SSH_ICMPH_OFS_TYPE];
      if (icmp_type == (SshUInt8)SSH_ICMP_TYPE_UNREACH)
        {
          hdr2len = 8;

          if (do_protocol_header == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("NAT on fragmented ICMP unreachables "
                                     "not supported!"));
              return FALSE;
            }

          /* Grab IP header contained in datagram */
          if (pc->packet_len < hdrlen + hdr2len + SSH_IPH4_HDRLEN)
            return FALSE;
          packet_hdr = ssh_interceptor_packet_pullup(pc->pp,
                                                     pp_offset
                                                     + hdrlen + hdr2len
                                                     + SSH_IPH4_HDRLEN);
          if (packet_hdr == NULL)
            {
              pc->pp = NULL;
              return FALSE;
            }

          if (SSH_IPH4_VERSION(packet_hdr + hdrlen + hdr2len) != 4
              || (!SSH_IP_IS4(new_ip)))
            return FALSE;

          payload_iphdr_len = 4 * SSH_IPH4_HLEN(packet_hdr + hdrlen + hdr2len);
          port_proto = SSH_IPH4_PROTO(packet_hdr + hdrlen + hdr2len);
          payload_ofs_cks = SSH_ICMPH_OFS_CHECKSUM;

          if (port_proto == SSH_IPPROTO_TCP)
            {
              payload_protocolhdr_len = SSH_TCPH_HDRLEN;
              port_ofs = hdr2len + payload_iphdr_len;
              hdr2cks_ofs = hdr2len + payload_iphdr_len
                + SSH_TCPH_OFS_CHECKSUM;
              pseudo_hdrlen = SSH_TCPH_PSEUDO_HDRLEN;
            }
          else if (port_proto == SSH_IPPROTO_UDP ||
                   port_proto == SSH_IPPROTO_UDPLITE)
            {
              payload_protocolhdr_len = SSH_UDPH_HDRLEN;
              port_ofs = hdr2len + payload_iphdr_len;
              hdr2cks_ofs = hdr2len + payload_iphdr_len
                + SSH_UDPH_OFS_CHECKSUM;
              pseudo_hdrlen = SSH_TCPH_PSEUDO_HDRLEN;
            }
          else if (port_proto == SSH_IPPROTO_ICMP)
            {
              payload_protocolhdr_len = 6;
              port_ofs = hdr2len + payload_iphdr_len + 4;
              hdr2cks_ofs = hdr2len + payload_iphdr_len
                + SSH_ICMPH_OFS_CHECKSUM;
              pseudo_hdrlen = 0; /* Should not be used */
            }
          else
            return FALSE;

          /* Skip checksum adjustment if encapsulated TCP header is
             truncated. */
          if (pc->packet_len < hdrlen + hdr2len + payload_iphdr_len +
              payload_protocolhdr_len && port_proto == SSH_IPPROTO_TCP)
            {
              payload_protocolhdr_len = 8; /* Only first 8 bytes of TCP header
                                              are required to be available. */
              hdr2cks_ofs = CHKOFFS_INVALID;
            }

          if (pc->packet_len < hdrlen + hdr2len + payload_iphdr_len
              + payload_protocolhdr_len)
            return FALSE;
          packet_hdr = ssh_interceptor_packet_pullup(pc->pp,
                                                   pp_offset
                                                   + hdrlen + hdr2len
                                                   + payload_iphdr_len
                                                   + payload_protocolhdr_len);
          if (packet_hdr == NULL)
            {
              pc->pp = NULL;
              return FALSE;
            }
        }
      break;
#if defined (WITH_IPV6)
    case SSH_IPPROTO_IPV6ICMP:




      hdr2len = SSH_ICMP6H_HDRLEN + 2;
      hdr2cks_ofs = SSH_ICMP6H_OFS_CHECKSUM;
      port_ofs = 4;
      break;
#endif /* WITH_IPV6 */
    default:



      return TRUE;
    }

  if (SSH_PREDICT_FALSE(do_protocol_header == FALSE))
    hdr2len = 0;

  if (SSH_PREDICT_FALSE(pc->packet_len < hdrlen + hdr2len))
    {
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
      SSH_DEBUG(SSH_D_NETGARB, ("truncated TCP/UDP/ICMP packet in NAT"));
      ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;
      return FALSE;
    }

  /* Pullup the IP + TCP/UDP headers. */
#if defined (WITH_IPV6)
  if (SSH_PREDICT_FALSE(pc->pp->protocol == SSH_PROTOCOL_IP6))
    {
      packet_hdr = ssh_interceptor_packet_pullup(pc->pp, pp_offset
                                                 + SSH_IPH6_HDRLEN);
      if (SSH_PREDICT_FALSE(!packet_hdr))
        {
          pc->pp = NULL;
          return FALSE;
        }

      /* Copyout protocol header. */
      if (SSH_PREDICT_TRUE(hdr2len))
        {
          SSH_ASSERT(hdr2len <= sizeof(protocol_hdr_buf));
          ssh_interceptor_packet_copyout(pc->pp, pp_offset + hdrlen,
                                         protocol_hdr_buf,
                                         hdr2len);
        }
      protocol_hdr = protocol_hdr_buf;

      /* Replace IP. */
      memcpy(old_ip, packet_hdr + ip_ofs, addr_len);
      SSH_IP6_ENCODE(new_ip, packet_hdr + ip_ofs);
    }
  else
#endif /* WITH_IPV6 */
    {
      /* Pullup both IP + protocol headers. */
      packet_hdr = ssh_interceptor_packet_pullup(pc->pp,
                                                 pp_offset + hdrlen + hdr2len
                                                 + payload_iphdr_len
                                                 + payload_protocolhdr_len);
      if (SSH_PREDICT_FALSE(!packet_hdr))
        {
          pc->pp = NULL;
          return FALSE;
        }
      /* Set our pointer to the protocol header. */
      protocol_hdr = packet_hdr + hdrlen;

      /* Replace IP. */
      cks = SSH_IPH4_CHECKSUM(packet_hdr);
      memcpy(old_ip, packet_hdr + ip_ofs, addr_len);
      SSH_IP4_ENCODE(new_ip, packet_hdr + ip_ofs);

      /* Compute and store new IP checksum. */
      cks = ssh_ip_cksum_update_long(cks, ip_ofs,
                                     SSH_GET_32BIT(old_ip),
                                     SSH_GET_32BIT(packet_hdr + ip_ofs));
      SSH_IPH4_SET_CHECKSUM(packet_hdr, cks);
    }

  /* Update protocol-specific information only for full packets and first
     fragments. */
  if (SSH_PREDICT_TRUE(do_protocol_header))
    {
      /* If we have a payload IP header which must be fixed then fix it */
      if (SSH_PREDICT_FALSE(payload_iphdr_len > 0))
        {
          SshUInt32 ip2_ofs;
          unsigned char inner_old_ip[4];

          SSH_ASSERT(pc->pp->protocol == SSH_PROTOCOL_IP4);

          if (do_src)
            ip2_ofs = hdr2len + SSH_IPH4_OFS_DST;
          else
            ip2_ofs = hdr2len + SSH_IPH4_OFS_SRC;

          memcpy(inner_old_ip, protocol_hdr + ip2_ofs, 4);
          SSH_IP4_ENCODE(new_ip, protocol_hdr + ip2_ofs);

          /* Fix checksum in payload IP header */
          old_ip_cks = SSH_IPH4_CHECKSUM(protocol_hdr + hdr2len);
          new_ip_cks = ssh_ip_cksum_update_long(old_ip_cks, ip2_ofs,
                                         SSH_GET_32BIT(inner_old_ip),
                                         SSH_GET_32BIT(protocol_hdr+ip2_ofs));

          SSH_IPH4_SET_CHECKSUM(protocol_hdr + hdr2len, new_ip_cks);

          cks = SSH_GET_16BIT(protocol_hdr + payload_ofs_cks);

          /* Fix checksum in (ICMP) packet carrying IP header */
          SSH_ASSERT(payload_ofs_cks != 0);
          cks = ssh_ip_cksum_update_long(cks, ip2_ofs,
                                         SSH_GET_32BIT(inner_old_ip),
                                         SSH_GET_32BIT(protocol_hdr+ip2_ofs));

          SSH_PUT_16BIT(protocol_hdr + payload_ofs_cks, cks);
        }
      else
        {
          new_ip_cks = old_ip_cks = 0;
        }

      /* Replace port (or ICMP ECHO identification), unless zero */
      if (SSH_PREDICT_TRUE(new_port))
        {
          old_port = SSH_GET_16BIT(protocol_hdr + port_ofs);
          SSH_PUT_16BIT(protocol_hdr + port_ofs, new_port);
        }
      else
        {
          old_port = 0; /* to remove warning about uninitialized variable */
        }

      /* Compute and store new protocol-specific checksum, but don't
         update zero checksums. */
      if (hdr2cks_ofs != CHKOFFS_INVALID)
        old_proto_cks = SSH_GET_16BIT(protocol_hdr + hdr2cks_ofs);
      else
        old_proto_cks = 0;

      if (SSH_PREDICT_TRUE(old_proto_cks) || port_proto != SSH_IPPROTO_UDP)
        {
          cks = old_proto_cks;

          /* In ones complement arithmethic these are equal.
             This is incase somebody will make some assumptions regarding
             the encoding. */
          if (SSH_PREDICT_FALSE(cks == 0xFFFF) &&
              port_proto == SSH_IPPROTO_UDP)
            cks = 0;

          if (SSH_PREDICT_TRUE(port_proto != SSH_IPPROTO_ICMP))
            {
              size_t i;

              /* Update IP address change in the pseudo header. */
              for (i = 0; i < addr_len; i += 4)
                cks = ssh_ip_cksum_update_long(cks, ip_ofs_pseudohdr + i,
                                               SSH_GET_32BIT(old_ip + i),
                                               SSH_GET_32BIT(packet_hdr
                                                             + ip_ofs + i));
            }
          if (SSH_PREDICT_TRUE(new_port))
            cks = ssh_ip_cksum_update_short(cks, pseudo_hdrlen + port_ofs,
                                            old_port, new_port);

          /* RFC 768: an all zero checksum is transmitted as all ones. */
          if (SSH_PREDICT_FALSE(cks == 0) && port_proto == SSH_IPPROTO_UDP)
            cks = 0xFFFF;
          if (hdr2cks_ofs != CHKOFFS_INVALID)
            SSH_PUT_16BIT(protocol_hdr + hdr2cks_ofs, cks);
          new_proto_cks = cks;
        }
      else
        {
          new_proto_cks = old_proto_cks;
        }

      /* If another header checksum must be modified because
         of a port change do it here... */
      if (SSH_PREDICT_FALSE(payload_ofs_cks))
        {
          /* Here we assume that we are not modifying a UDP packet checksum. */
          cks = SSH_GET_16BIT(protocol_hdr + payload_ofs_cks);

          /* Update changes in ports and IP and protocol checksums */
          if (new_port)
            cks = ssh_ip_cksum_update_short(cks, port_ofs,
                                            old_port, new_port);
          if (hdr2cks_ofs != CHKOFFS_INVALID)
            cks = ssh_ip_cksum_update_short(cks, hdr2cks_ofs,
                                            old_proto_cks, new_proto_cks);
          cks = ssh_ip_cksum_update_short(cks, SSH_IPH4_OFS_CHECKSUM,
                                          old_ip_cks, new_ip_cks);

          SSH_PUT_16BIT(protocol_hdr + payload_ofs_cks, cks);
        }
#if defined (WITH_IPV6)
      if (SSH_PREDICT_FALSE(pc->pp->protocol == SSH_PROTOCOL_IP6))
        {
          /* Copy protocol header back to the packet. */
          if (!ssh_interceptor_packet_copyin(pc->pp, pp_offset + hdrlen,
                                             protocol_hdr_buf,
                                             hdr2len))
            {
              pc->pp = NULL;
              return FALSE;
            }
        }
#endif /* WITH_IPV6 */
    }

  SSH_DUMP_PACKET(SSH_D_MY + 10, "AFTER NAT:", pc->pp);
  return TRUE;
}

SSH_FASTTEXT Boolean
ssh_fastpath_transform_nat(SshFastpath fastpath,
                           SshEnginePacketContext pc,
                           Boolean forward)
{
  /* Perform NAT on the source address, if appropriate. */
  if (SSH_PREDICT_FALSE(pc->flags & SSH_ENGINE_FLOW_D_NAT_SRC))
    {
      if (!ssh_fastpath_execute_nat(pc, forward,
                                    &pc->u.flow.nat_src_ip,
                                    pc->u.flow.nat_src_port))
        {
          SSH_DEBUG(SSH_D_FAIL, ("source addr NAT failed!"));
          return FALSE;
        }
    }

  /* Mark source NAT as done */
  pc->flags &= ~SSH_ENGINE_FLOW_D_NAT_SRC;

  if (SSH_PREDICT_FALSE(pc->flags & SSH_ENGINE_FLOW_D_NAT_DST))
    {
      /* In ICMP case there is no separate "source port" and
         "destination port". Only the ICMP identifier, which is
         overloaded onto the "src port" field. */
      if (pc->ipproto == SSH_IPPROTO_ICMP
          || pc->ipproto == SSH_IPPROTO_IPV6ICMP)
        {
          if (!ssh_fastpath_execute_nat(pc, !forward,
                                        &pc->u.flow.nat_dst_ip,
                                        pc->u.flow.nat_src_port))
            {
              SSH_DEBUG(SSH_D_FAIL, ("ICMP destination addr NAT failed!"));
              return FALSE;
            }
        }
      else
        {
          if (!ssh_fastpath_execute_nat(pc, !forward,
                                        &pc->u.flow.nat_dst_ip,
                                        pc->u.flow.nat_dst_port))
            {
              SSH_DEBUG(SSH_D_FAIL, ("TCP/UDP destination addr NAT failed!"));
              return FALSE;
            }
        }
    }

  /* Mark destination NAT as done */
  pc->flags &= ~SSH_ENGINE_FLOW_D_NAT_DST;

  return TRUE;
}

#endif /* SSHDIST_IPSEC_NAT */
