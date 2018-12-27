/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP header checksum computation for an IPSEC engine packet.
*/

#include "sshincludes.h"
#include "interceptor.h"
#include "ip_cksum.h"

#define SSH_DEBUG_MODULE "SshIpCksumPacket"

/* Computes the IP checksum over the specified range of the packet.
   The checksum is returned in host byte order. */

SshUInt16 ssh_ip_cksum_packet(SshInterceptorPacket pp, size_t offset,
                              size_t bytes)
{
  const unsigned char *seg;
  size_t seglen, segofs;
  SshUInt32 sum; /* kept in host order */
  SshUInt16 segsum;

  /* Iterate over the packet. */
  segofs = 0;
  sum = 0;
  ssh_interceptor_packet_reset_iteration(pp, offset, bytes);
  while (ssh_interceptor_packet_next_iteration_read(pp, &seg, &seglen))
    {
      segsum = ~ssh_ip_cksum(seg, seglen);
      if (segofs & 0x01)
        segsum = (SshUInt16)((segsum << 8) | (segsum >> 8));
      sum += segsum;
      segofs += seglen;
      ssh_interceptor_packet_done_iteration_read(pp, &seg, &seglen);
    }

  /*  Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (SshUInt16)~sum;
}

Boolean ssh_ip_cksum_packet_compute(SshInterceptorPacket pp,
                                    size_t media_hdrlen, size_t ip_hdrlen)
{
  unsigned char *ucp, pseudo_hdr[SSH_IP6_PSEUDOH_HDRLEN];
  size_t cksum_ofs, data_len, pseudo_hdrlen, cksum_len;
  SshUInt32 sum;
  SshUInt16 cksum, segsum;
  SshUInt8 ipproto;
  Boolean is_ipv6;

  /* Get the IP version */
  ucp = ssh_interceptor_packet_pullup(pp, media_hdrlen + ip_hdrlen);
  if (ucp == NULL)
    return FALSE;

  /* Skip over the media header */
  ucp += media_hdrlen;

  if (SSH_IPH4_VERSION(ucp) != 4 && SSH_IPH6_VERSION(ucp) != 6)
    {
      SSH_DEBUG(SSH_D_NETGARB, ("Invalid IP version %d",
                                SSH_IPH4_VERSION(ucp)));
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  is_ipv6 = (SSH_IPH4_VERSION(ucp) == 6) ? TRUE : FALSE;
  if (is_ipv6)
    {
      ipproto = SSH_IPH6_NH(ucp);
      pseudo_hdrlen =  SSH_IP6_PSEUDOH_HDRLEN;
    }
  else
    {
      ipproto = SSH_IPH4_PROTO(ucp);
      pseudo_hdrlen = 12;
    }

  SSH_ASSERT(ssh_interceptor_packet_len(pp) >= media_hdrlen + ip_hdrlen);

  /* data_len is the length of data beyond the IP header. */
  data_len = ssh_interceptor_packet_len(pp) - media_hdrlen - ip_hdrlen;

  /* We are only interested in TCP and UDP and ICMPV6. */
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
      cksum_ofs = SSH_TCPH_OFS_CHECKSUM;
      break;
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
      cksum_ofs = SSH_UDPH_OFS_CHECKSUM;
      break;
    case SSH_IPPROTO_IPV6ICMP:
      cksum_ofs = SSH_ICMP6H_OFS_CHECKSUM;
      break;
    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
    case SSH_IPPROTO_SCTP:
    case SSH_IPPROTO_ICMP:
    default:
      return TRUE;
    }

  SSH_ASSERT(ipproto == SSH_IPPROTO_TCP ||
             ipproto == SSH_IPPROTO_UDP ||
             ipproto == SSH_IPPROTO_UDPLITE ||
             ipproto == SSH_IPPROTO_IPV6ICMP);

  /* Construct the pseudo header */
  memset(pseudo_hdr, 0, sizeof(pseudo_hdr));

  if (is_ipv6)
    {
      memcpy(pseudo_hdr, ucp + SSH_IPH6_OFS_SRC, 16);
      memcpy(pseudo_hdr + 16, ucp + SSH_IPH6_OFS_DST, 16);
      SSH_IP6_PSEUDOH_SET_NH(pseudo_hdr, ipproto);
      SSH_IP6_PSEUDOH_SET_LEN(pseudo_hdr, data_len);
    }
  else
    {
      memcpy(pseudo_hdr, ucp + SSH_IPH4_OFS_SRC, 4);
      memcpy(pseudo_hdr + 4, ucp + SSH_IPH4_OFS_DST, 4);
      pseudo_hdr[9] = ipproto;
      SSH_PUT_16BIT(pseudo_hdr + 10, data_len);
    }

  /* Pullup the IP and TCP/UDP headers. */
  ucp = ssh_interceptor_packet_pullup(pp,
                                      media_hdrlen + ip_hdrlen +
                                      cksum_ofs + 2);
  if (ucp == NULL)
    return FALSE;

  /* Skip over the media amd IP headers */
  ucp += media_hdrlen + ip_hdrlen;

  /* Clear the exisiting checksum from the upper layer header. */
  cksum_len = data_len;
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
      SSH_TCPH_SET_CHECKSUM(ucp, 0);
      break;
    case SSH_IPPROTO_UDP:
      SSH_UDPH_SET_CHECKSUM(ucp, 0);
      break;
    case SSH_IPPROTO_UDPLITE:
      SSH_UDPH_SET_CHECKSUM(ucp, 0);
      if (SSH_UDP_LITEH_CKSUM_COVERAGE(ucp) != 0)
        cksum_len = SSH_UDP_LITEH_CKSUM_COVERAGE(ucp);
      break;
    case SSH_IPPROTO_IPV6ICMP:
      SSH_ICMP6H_SET_CHECKSUM(ucp, 0);
      break;
    }

 /* Compute the checksum. First do the pseudo header, and then the upper
    layer packect data. */
  segsum = ~ssh_ip_cksum(pseudo_hdr, pseudo_hdrlen);
  sum = segsum;

  segsum = ~ssh_ip_cksum_packet(pp, media_hdrlen + ip_hdrlen, cksum_len);
  sum += segsum;

  /*  Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  cksum = (SshUInt16)~sum;

  ucp = ssh_interceptor_packet_pullup(pp,
                                      media_hdrlen + ip_hdrlen +
                                      cksum_ofs + 2);
  if (ucp == NULL)
    return FALSE;

  /* Skip over the media amd IP headers */
  ucp += media_hdrlen + ip_hdrlen;

  /* Store the newly computed checksum to the packet. */
  switch (ipproto)
    {
    case SSH_IPPROTO_TCP:
      SSH_TCPH_SET_CHECKSUM(ucp, cksum);
      break;
    case SSH_IPPROTO_UDP:
    case SSH_IPPROTO_UDPLITE:
      SSH_UDPH_SET_CHECKSUM(ucp, cksum);
      break;
    case SSH_IPPROTO_IPV6ICMP:
      SSH_ICMP6H_SET_CHECKSUM(ucp, cksum);
      break;
    }
 return TRUE;
}


