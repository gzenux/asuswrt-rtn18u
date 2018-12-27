/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Media address resolution protocols (ARP, IPv6 Neighborhood
   Discovery) for virtual adapters.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "virtual_adapter.h"
#include "virtual_adapter_internal.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshVirtualAdapterArp"

/* ARP packet headers. */

static const unsigned char arp_hdr_ipv4_request[] =
{
  0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01
};

static const unsigned char arp_hdr_ipv4_reply[] =
{
  0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02
};

/********************* Virtual adapter packet callback **********************/

void
ssh_virtual_adapter_arp_packet_callback(SshInterceptor interceptor,
                                        SshInterceptorPacket pp, void *context)
{
  unsigned char ether_hdr[SSH_ETHERH_HDRLEN];
#if defined (WITH_IPV6)
  size_t offset = 0;
#endif /* WITH_IPV6 */
  size_t packet_len = ssh_interceptor_packet_len(pp);
  SshInterceptorPacket new_pp;

  SSH_DEBUG(SSH_D_MIDSTART, ("Packet callback: pp->protocol=%d, len=%d",
                             pp->protocol, packet_len));

  if (pp->protocol == SSH_PROTOCOL_ETHERNET)
    {
      SshUInt16 ethertype;

      if (packet_len < SSH_ETHERH_HDRLEN)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Ethernet packet too short for ethernet header: len=%d",
                     packet_len));
          goto out;
        }

      /* Copyout the ethernet header. */
      ssh_interceptor_packet_copyout(pp, 0, ether_hdr, SSH_ETHERH_HDRLEN);

      /* Fetch type of this ethernet packet. */
      ethertype = SSH_GET_16BIT(ether_hdr + SSH_ETHERH_OFS_TYPE);

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Ethernet packet dst=%@, src=%@, type=0x%x",
                 ssh_etheraddr_render, ether_hdr,
                 ssh_etheraddr_render, ether_hdr + SSH_ETHERH_OFS_SRC,
                 ethertype));

      if (ethertype == SSH_ETHERTYPE_ARP)
        {
          unsigned char arp_buf[28];
          SshIpAddrStruct src;
          SshIpAddrStruct dst;

          /* Check that the packet is long enought. */
          if (packet_len < SSH_ETHERH_HDRLEN + 28)
            {
              SSH_DEBUG(SSH_D_ERROR, ("ARP packet too short: len=%d",
                                      packet_len));
              goto out;
            }

          /* Fetch the ARP packet. */
          ssh_interceptor_packet_copyout(pp, SSH_ETHERH_HDRLEN,
                                         arp_buf, 28);

          /* Check that it is really an ARP request. */
          if (memcmp(arp_buf, arp_hdr_ipv4_request, 8) != 0)
            {
              SSH_DEBUG(SSH_D_NETFAULT,
                        ("ARP packet is not an IPv4 ARP request with 48 bit "
                         "hardware address: skipping"));
              goto out;
            }

          /* Extract all interesting fields. */
          SSH_IP4_DECODE(&src, arp_buf + 14);
          SSH_IP4_DECODE(&dst, arp_buf + 24);

          /* Don't reply to gratuitous ARP. */
          if (SSH_IP_IS_NULLADDR(&src) || SSH_IP_EQUAL(&src, &dst))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Will not reply to gratuitous ARP"));
              goto out;
            }

          SSH_DEBUG(SSH_D_NICETOKNOW, ("arp who-has %@ tell %@",
                                       ssh_ipaddr_render, &dst,
                                       ssh_ipaddr_render, &src));

          /* Start constructing ARP reply. */
          /* Flip the interface numbers */
          new_pp = ssh_interceptor_packet_alloc(interceptor,
                                                SSH_PACKET_FROMADAPTER,
                                                SSH_PROTOCOL_ETHERNET,
                                                pp->ifnum_out,
                                                pp->ifnum_in,
                                                SSH_ETHERH_HDRLEN + 28);
          if (new_pp == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Could not allocate ARP reply packet"));
              goto out;
            }

          /* Format the ethernet frame. */
          memcpy(ether_hdr + SSH_ETHERH_OFS_DST,
                 ether_hdr + SSH_ETHERH_OFS_SRC, SSH_ETHERH_ADDRLEN);

          /* Create a pseudo hardware address from the destination's
             IP address. */
          ssh_virtual_adapter_ip_ether_address(&dst,
                                               ether_hdr + SSH_ETHERH_OFS_SRC);

          /* Construct the ARP reply. */

          memcpy(arp_buf, arp_hdr_ipv4_reply, 8);

          memcpy(arp_buf + 8, ether_hdr + SSH_ETHERH_OFS_SRC,
                 SSH_ETHERH_ADDRLEN);
          SSH_IP4_ENCODE(&dst, arp_buf + 14);

          memcpy(arp_buf + 18, ether_hdr + SSH_ETHERH_OFS_DST,
                 SSH_ETHERH_ADDRLEN);
          SSH_IP4_ENCODE(&src, arp_buf + 24);

          /* Fill the packet. */
          if (!ssh_interceptor_packet_copyin(new_pp, 0, ether_hdr,
                                             SSH_ETHERH_HDRLEN))
            goto out;
          if (!ssh_interceptor_packet_copyin(new_pp, SSH_ETHERH_HDRLEN,
                                             arp_buf, 28))
            goto out;

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
          /* Not the right place for dist defs, but quickest way to
             make this compile. Mtr, please fix properly. -Jussi */
          /* Ok, we are ready to send the ARP reply. */
          ssh_virtual_adapter_send(interceptor, new_pp);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
        }
#if defined (WITH_IPV6)
      else if (ethertype == SSH_ETHERTYPE_IPv6)
        {
          offset = SSH_ETHERH_HDRLEN;
          goto handle_ipv6_packet;
        }
#endif /* WITH_IPV6 */
      else
        {
          /* Nothing interesting. */
          /* FALLTHROUGH */
        }
    }
#if defined (WITH_IPV6)
  else if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      unsigned char icmp6_buf[72];
      SshIpAddrStruct src;
      SshIpAddrStruct dst;
      size_t icmp6_offset;
      SshUInt16 hlen;
      unsigned char src_link_address[SSH_ETHERH_ADDRLEN];
      unsigned char dst_link_address[SSH_ETHERH_ADDRLEN];

    handle_ipv6_packet:

      /* Check that the packet is long enough.
         IPv6 header + ICMPv6 header + neighbor solicitation (+ options)
         = 64 (72) bytes. */
      if ((packet_len - offset) < 64)
        {
          SSH_DEBUG(SSH_D_ERROR, ("ICMPv6 packet too short: len=%d",
                                  packet_len));
          goto out;
        }

      /* Fetch the neighbor solicitation packet. */
      if (packet_len - offset >= 72)
        icmp6_offset = 72; /* Source address option present. */
      else
        icmp6_offset = 64;
      SSH_ASSERT(icmp6_offset <= sizeof(icmp6_buf));
      ssh_interceptor_packet_copyout(pp, offset, icmp6_buf, icmp6_offset);

      hlen = SSH_IPH6_LEN(icmp6_buf);
      /* Check that it is really a neighbor solicitation. */
      if (SSH_IPH6_NH(icmp6_buf) != SSH_IPPROTO_IPV6ICMP
          || (hlen != 24 && hlen != 32)
          || SSH_ICMP6H_TYPE(icmp6_buf + SSH_IPH6_HDRLEN)
          != SSH_ICMP6_TYPE_NEIGHBOR_SOLICITATION
          || SSH_ICMP6H_CODE(icmp6_buf + SSH_IPH6_HDRLEN) != 0)
        {
          SSH_DEBUG(SSH_D_NETFAULT,
                    ("Packet is not an IPv6 neighbor solicitation with "
                     "code 0, skipping"));
          goto out;
        }

      /* Extract all interesting fields. */
      SSH_IPH6_SRC(&src, icmp6_buf);
      SSH_IP6_DECODE(&dst, icmp6_buf + SSH_IPH6_HDRLEN + 8);

      /* Don't reply to DAD packets. */
      if (SSH_IP_IS_NULLADDR(&src))
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Will not reply to DAD neighbor solicitation."));
          goto out;
        }

      /* Extract source link-layer address, prefer option if present. */
      if (hlen == 32)
        {
          icmp6_offset = SSH_IPH6_HDRLEN + 24;
          /* Check option type, 1 is for source link-layer address option. */
          if (SSH_GET_8BIT(icmp6_buf + icmp6_offset) != 1)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Invalid ICMPv6 ND option."));
              goto out;
            }
          /* Check option lenght, should be 1 (= 8 octets) */
          if (SSH_GET_8BIT(icmp6_buf + icmp6_offset + 1) != 1)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("Invalid ICMPv6 source link-layer address length."));
              goto out;
            }
          memcpy(src_link_address, icmp6_buf + icmp6_offset + 2,
                 SSH_ETHERH_ADDRLEN);
        }
      /* Extract source link-layer address from ethernet header */
      else if (offset > 0)
        {
          memcpy(src_link_address, ether_hdr + SSH_ETHERH_OFS_SRC,
                 SSH_ETHERH_ADDRLEN);
        }
      /* Unable to extract source link-layer address. */
      else
        {






          SSH_DEBUG(SSH_D_FAIL,
                    ("Unable to extract source link-layer address"));
          goto out;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("neighbor solicitation who-has %@ tell %@",
                 ssh_ipaddr_render, &dst,
                 ssh_ipaddr_render, &src));

      /* Start constructing neighbor advertisement. */

      /* Flip the interface numbers */
      new_pp = ssh_interceptor_packet_alloc(interceptor,
                                            SSH_PACKET_FROMADAPTER,
                                            SSH_PROTOCOL_ETHERNET,
                                            pp->ifnum_out,
                                            pp->ifnum_in,
                                            offset + 72);
      if (new_pp == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not allocate neighbor advertisement packet"));
          goto out;
        }

      /* Create a pseudo hardware address from the destination's
         IP address. */
      ssh_virtual_adapter_ip_ether_address(&dst, dst_link_address);
      if (offset > 0)
        {
          /* Format the ethernet frame. */
          memcpy(ether_hdr + SSH_ETHERH_OFS_DST, src_link_address,
                 SSH_ETHERH_ADDRLEN);
          memcpy(ether_hdr + SSH_ETHERH_OFS_SRC, dst_link_address,
                 SSH_ETHERH_ADDRLEN);
        }

      /* Construct the neighbor solicitation. */

      /* IPv6 header */
      SSH_IPH6_SET_VERSION(icmp6_buf, 6);
      SSH_IPH6_SET_CLASS(icmp6_buf, 0);
      SSH_IPH6_SET_FLOW(icmp6_buf, 0);
      SSH_IPH6_SET_LEN(icmp6_buf, 32);
      SSH_IPH6_SET_NH(icmp6_buf, SSH_IPPROTO_IPV6ICMP);
      SSH_IPH6_SET_HL(icmp6_buf, 255);
      SSH_IPH6_SET_SRC(&dst, icmp6_buf);
      SSH_IPH6_SET_DST(&src, icmp6_buf);

      /* ICMPv6 header */
      icmp6_offset = SSH_IPH6_HDRLEN;
      SSH_ICMP6H_SET_TYPE(icmp6_buf + icmp6_offset,
                          SSH_ICMP6_TYPE_NEIGHBOR_ADVERTISEMENT);
      SSH_ICMP6H_SET_CODE(icmp6_buf + icmp6_offset, 0);
      SSH_ICMP6H_SET_CHECKSUM(icmp6_buf + icmp6_offset, 0);

      /* R, S, and O bits, and reserved. Set S bit. */
      icmp6_offset += SSH_ICMP6H_HDRLEN;
      SSH_PUT_32BIT(icmp6_buf + icmp6_offset, 0x40000000);

      /* Target address. */
      icmp6_offset += 4;
      SSH_IP6_ENCODE(&dst, icmp6_buf + icmp6_offset);

      /* Target link layer address option. */
      icmp6_offset += 16;
      SSH_PUT_8BIT(icmp6_buf + icmp6_offset, 2);              /* Option type */
      SSH_PUT_8BIT(icmp6_buf + icmp6_offset + 1, 1);          /* Length */
      memcpy(icmp6_buf + icmp6_offset + 2, dst_link_address,  /* Address */
             SSH_ETHERH_ADDRLEN);

      /* Fill the packet. */
      if (offset > 0)
        {
          if (!ssh_interceptor_packet_copyin(new_pp, 0, ether_hdr, offset))
            goto out;
        }
      if (!ssh_interceptor_packet_copyin(new_pp, offset, icmp6_buf, 72))
        goto out;

      /* Checksum packet. */
      if (!ssh_ip_cksum_packet_compute(new_pp, offset, SSH_IPH6_HDRLEN))
        {
          SSH_DEBUG(SSH_D_FAIL, ("ICMPv6 checksum computation failed"));
          goto out;
        }

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
      /* Not the right place for dist defs, but quickest way to
         make this compile. Mtr, please fix properly. -Jussi */
      /* Ok, we are ready to send the ARP reply. */
      ssh_virtual_adapter_send(interceptor, new_pp);
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
    }
#endif /* WITH_IPV6 */
  else
    {
      /* Nothing interesting. */
      /* FALLTHROUGH */
    }

 out:
  ssh_interceptor_packet_free(pp);
}

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */
