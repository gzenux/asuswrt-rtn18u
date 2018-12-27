/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file implements outbound IPsec transform on SE fastpath.
*/

#include "octeon_se_fastpath_internal.h"
#include "octeon_se_fastpath_transform_i.h"
#include "octeon_se_fastpath_inline.h"

static inline SeFastpathRet
octeon_se_fastpath_transform_check_pmtu(SeFastpathPacketContext pc,
                                        size_t packet_out_len)
{
  if (cvmx_unlikely(packet_out_len > 65535))
    {
      OCTEON_SE_DEBUG(3, "Dropping packet because of overflow\n");
      return OCTEON_SE_FASTPATH_RET_DROP;
    }




  if (cvmx_unlikely((packet_out_len > pc->mtu)
#ifdef OCTEON_SE_FASTPATH_FRAGMENTATION
                    && (pc->s->ipv4_df || pc->s->ip_version_6)
#endif /* OCTEON_SE_FASTPATH_FRAGMENTATION */
                    ))
    {
      OCTEON_SE_DEBUG(5, "Need to send ICMP error message, "
                      "passing to slowpath\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  return OCTEON_SE_FASTPATH_RET_OK;
}

/** Execute outbound transforms */
SeFastpathRet
octeon_se_fastpath_transform_out(SeFastpathCoreContext core,
                                 SeFastpath fastpath,
                                 SeFastpathPacketContext pc)
{
  cvmx_buf_ptr_t packet_out;
  uint64_t packet_out_num_segs;
  size_t packet_out_len;
  SeFastpathTransformData se_trd;
  SeFastpathCombinedTransform combined;
  SeFastpathPacketBufferStruct src, dst;
  SeFastpathEspExtraInfoStruct extra_info[1];
  SeFastpathMacExtraInfoStruct mac_info[1];
  SeFastpathRet ret;
  uint8_t *header;
  uint32_t trd_i, tos, flow_label;
  uint64_t ipsec_seq;
  uint16_t csum, prefix_ofs;
  uint16_t esp_ah_ofs, prefix_len = 0, trailer_len = 0, pad_len = 0;
  uint8_t esp_ah_nh;
  uint64_t icv[OCTEON_SE_FASTPATH_MAX_HASH_WORDS] = { 0 };
  size_t i;
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AH
  size_t icv_pad_len = 0;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */
  uint32_t run_time;
  size_t alignment = 0;
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  size_t out_octets;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

  OCTEON_SE_DEBUG(9, "Execute transform out\n");

  packet_out.u64 = 0;

  OCTEON_SE_ASSERT(pc->transform_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
  trd_i = pc->transform_index & 0x00ffffff;
  OCTEON_SE_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);

  se_trd = OCTEON_SE_FASTPATH_TRD(fastpath, trd_i);
  OCTEON_SE_FASTPATH_TRD_READ_LOCK(fastpath, trd_i, se_trd);

  OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd);

  /* If transform is complex, pass packet to slowpath. */
  if (cvmx_unlikely(se_trd->is_special))
    {
      OCTEON_SE_DEBUG(9, "Special transform %08x, passing to slowpath\n",
                      se_trd->transform);
      goto slowpath;
    }

  combined = octeon_se_fastpath_get_combined_transform(se_trd->transform,
                                                   se_trd->mac_key_size);
  if (cvmx_unlikely(combined == NULL))
    {
      OCTEON_SE_DEBUG(9, "Unsupported transform %08x, passing to slowpath\n",
                      se_trd->transform);
      goto slowpath;
    }

  /* Update trd output timestamp. */
  run_time = cvmx_fau_fetch_and_add32(OCTEON_SE_FASTPATH_FAU_RUNTIME, 0);
  cvmx_atomic_set32((int32_t *) &se_trd->last_out_packet_time,
                    (int32_t) run_time);

  (*combined->init)(core->transform_context,
                    se_trd->keymat + OCTEON_MAX_KEYMAT_LEN /2,
                    se_trd->cipher_key_size,
                    se_trd->keymat + OCTEON_MAX_KEYMAT_LEN /2
                    + OCTEON_MAX_ESP_KEY_BITS /8,
                    se_trd->mac_key_size);

  prefix_ofs = pc->s->ip_offset;

  /* Check ttl. */
  if (cvmx_unlikely(pc->s->ttl == 0))
    {
      OCTEON_SE_DEBUG(3, "Zero TTL, dropping\n");
      goto corrupt;
    }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  if (cvmx_unlikely(!se_trd->tunnel_mode))
    {
      /* In transport mode insert the ESP/AH header between IP
         and transport headers. */
      prefix_ofs += pc->s->tr_offset;
      esp_ah_nh = pc->s->ipproto;
      prefix_len = 0;
    }
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */
    {
      /* In tunnel mode insert IP and ESP/AH headers before IP header. */
      if (se_trd->ip_version_6)
        prefix_len = OCTEON_SE_FASTPATH_IP6_HDRLEN;
      else
        prefix_len = OCTEON_SE_FASTPATH_IP4_HDRLEN;

      if (pc->s->ip_version_6)
        esp_ah_nh = OCTEON_SE_FASTPATH_IPPROTO_IPV6;
      else
        esp_ah_nh = OCTEON_SE_FASTPATH_IPPROTO_IPIP;
    }

  /* Calculate IPsec overhead. */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_NATT
  /* Reserve space for UDP NAT-T. */
  if (se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_NATT)
    prefix_len += OCTEON_SE_FASTPATH_UDP_HDRLEN;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_NATT */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AH
  if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_AH))
    {
      prefix_len += OCTEON_SE_FASTPATH_AH_HDRLEN + combined->icv_len;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA2




      if (cvmx_unlikely((se_trd->ip_version_6 == 1) &&
                        (se_trd->transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2))
          )
        {
          icv_pad_len = 4;
          prefix_len += 4; /* Align AH header to 64 bit boundary */
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA2 */

      trailer_len = 0;
      pad_len = 0;
    }
  else if (se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_ESP)
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */
    {
      prefix_len += (OCTEON_SE_FASTPATH_ESP_HDRLEN + combined->cipher_iv_len);
      trailer_len = 2 + combined->icv_len;

      pad_len = (pc->s->ip_len + pc->s->ip_offset - prefix_ofs
                 + 2) % combined->pad_boundary;
      if (pad_len != 0)
        pad_len = combined->pad_boundary - pad_len;
    }

  /* The actual length of the packet */
  packet_out_len = pc->s->ip_len + prefix_len + pad_len + trailer_len;
  OCTEON_SE_DEBUG(9, "Resultant packet len is %d\n", (int) packet_out_len);

  /* Check result packet length. */
  if (cvmx_unlikely(se_trd->pmtu_received && pc->mtu > se_trd->pmtu_received))
    pc->mtu = se_trd->pmtu_received;

  ret = octeon_se_fastpath_transform_check_pmtu(pc, packet_out_len);
  if (cvmx_unlikely(ret == OCTEON_SE_FASTPATH_RET_DROP))
    goto drop;
  else if (cvmx_unlikely(ret == OCTEON_SE_FASTPATH_RET_SLOWPATH))
    goto slowpath;

  /* In tunnel mode decrement ttl of inner header. */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  if (cvmx_likely(se_trd->tunnel_mode))
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */
    {
      header = cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + pc->s->ip_offset;

      if (pc->s->ip_version_6)
        {
          /* Assert that header is in the first packet segment */
          OCTEON_SE_ASSERT(pc->wqe->packet_ptr.s.size
                           >= OCTEON_SE_FASTPATH_IP6_HDRLEN);
          OCTEON_SE_FASTPATH_IPH6_SET_HL(header, pc->s->ttl - 1);
        }
      else
        {
          /* Assert that header is in the first packet segment */
          OCTEON_SE_ASSERT(pc->wqe->packet_ptr.s.size
                           >= OCTEON_SE_FASTPATH_IP4_HDRLEN);
          OCTEON_SE_FASTPATH_IPH4_SET_TTL(header, pc->s->ttl - 1);
          OCTEON_SE_FASTPATH_IPH4_CHECKSUM(header, csum);
          csum = octeon_se_fastpath_csum_update_byte(csum, SSH_IPH4_OFS_TTL,
                                                     pc->s->ttl,
                                                     pc->s->ttl - 1);
          OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, csum);
        }
    }

  /* Save df bit processing state */
  pc->s->df_bit_processing = se_trd->df_bit_processing;

  /* Allocate packet buffer chain for result packet.
     Request that crypto result offset is 8 byte aligned. */
  alignment =
    OCTEON_SE_ALIGN_64(prefix_ofs + prefix_len) - (prefix_ofs + prefix_len);

  packet_out.u64 =
    octeon_se_fastpath_alloc_packet_chain(packet_out_len + pc->s->ip_offset,
                                          alignment,
                                          &packet_out_num_segs);

  if (cvmx_unlikely(packet_out.u64 == 0))
    {
      OCTEON_SE_DEBUG(3, "Result packet allocation failed\n");
      goto drop;
    }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  /* In case of transport mode copy the l3 header.*/
  if (cvmx_unlikely(prefix_ofs > pc->s->ip_offset))
    {
      OCTEON_SE_DEBUG(9, "Copying headers to %p\n",
                      cvmx_phys_to_ptr(packet_out.s.addr) + pc->s->ip_offset);

      /* Assert that l3 headers are in the first packet segment. */
      OCTEON_SE_ASSERT(packet_out.s.size > prefix_ofs);
      memcpy(cvmx_phys_to_ptr(packet_out.s.addr) + pc->s->ip_offset,
             cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + pc->s->ip_offset,
             prefix_ofs - pc->s->ip_offset);
    }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */

  /* Prepare Source buffer */
  octeon_se_fastpath_packet_buffer_create(&src, pc->wqe->packet_ptr,
                                          prefix_ofs,
                                          pc->s->ip_len + pc->s->ip_offset
                                          - prefix_ofs,
                                          pc->wqe->word2.s.bufs);

  /* Count the number of bytes input to crypto processing. */
  OCTEON_SE_FASTPATH_STATS(out_octets =
                           pc->s->ip_len + pc->s->ip_offset - prefix_ofs);

  /* Build headers */

  header = ((uint8_t *) cvmx_phys_to_ptr(packet_out.s.addr)) + prefix_ofs;

  /* Build outer header for tunnel mode and modify IP header for
     transport mode.*/

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  if (cvmx_unlikely(!se_trd->tunnel_mode && pc->s->ip_version_6 == 0))
    {
      /* IPv4 transport mode. */
      OCTEON_SE_DEBUG(9, "Modifying IPv4 header at %p\n", header);

      /* Modify original IPv4 header and change IP protocol and len. */
      OCTEON_SE_FASTPATH_IPH4_SET_LEN(header, packet_out_len);
      OCTEON_SE_FASTPATH_IPH4_SET_PROTO(header, se_trd->nh);
      OCTEON_SE_FASTPATH_IPH4_CHECKSUM(header, csum);

      csum =
        octeon_se_fastpath_csum_update_byte(csum,
                                            OCTEON_SE_FASTPATH_IPH4_OFS_PROTO,
                                            pc->s->ipproto, se_trd->nh);
      csum =
        octeon_se_fastpath_csum_update_short(csum,
                                             OCTEON_SE_FASTPATH_IPH4_OFS_LEN,
                                             pc->s->ip_len, packet_out_len);

      OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, csum);
    }
  else if (cvmx_unlikely(!se_trd->tunnel_mode && pc->s->ip_version_6 == 1))
    {
      /* IPv6 transport mode. */
      OCTEON_SE_DEBUG(9, "Modifying IPv6 header at %p\n", header);
      OCTEON_SE_FASTPATH_IPH6_SET_LEN(header, packet_out_len -
                                      OCTEON_SE_FASTPATH_IP6_HDRLEN);
      OCTEON_SE_FASTPATH_IPH6_SET_NH(header, se_trd->nh);
    }
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */
    if (se_trd->ip_version_6 == 0)
      {
        OCTEON_SE_ASSERT(se_trd->tunnel_mode);

        /* IPv4 tunnel mode. */
        OCTEON_SE_DEBUG(9, "Building outer IPv4 header at %p\n", header);

        OCTEON_SE_ASSERT(packet_out.s.size >
                         prefix_ofs + OCTEON_SE_FASTPATH_IP4_HDRLEN);

        OCTEON_SE_FASTPATH_IPH4_SET_VERSION(header, 4);
        OCTEON_SE_FASTPATH_IPH4_SET_HLEN(header, 5);




        tos = 0;
        OCTEON_SE_FASTPATH_IPH4_SET_TOS(header, tos);

        OCTEON_SE_FASTPATH_IPH4_SET_LEN(header, packet_out_len);

        if (pc->s->df_bit_processing == OCTEON_SE_FASTPATH_DF_CLEAR
            || (pc->s->df_bit_processing == OCTEON_SE_FASTPATH_DF_KEEP
                && pc->s->ipv4_df == 0))
          {
            uint32_t id;

            OCTEON_SE_FASTPATH_GET_NEXT_IPV4_PACKET_ID(core, id);
            OCTEON_SE_FASTPATH_IPH4_SET_ID(header, id);
            OCTEON_SE_FASTPATH_IPH4_SET_FRAG(header, 0);
            pc->s->ipv4_df = 0;
          }
        else
          {
            OCTEON_SE_FASTPATH_IPH4_SET_ID(header, 0);
            OCTEON_SE_FASTPATH_IPH4_SET_FRAG(header,
                                           OCTEON_SE_FASTPATH_IPH4_FRAGOFF_DF);
            pc->s->ipv4_df = 1;
          }

        OCTEON_SE_FASTPATH_IPH4_SET_TTL(header,
                                       OCTEON_SE_FASTPATH_IP4_TUNNEL_MODE_TTL);
        OCTEON_SE_FASTPATH_IPH4_SET_PROTO(header, se_trd->nh);
        OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, 0);
        OCTEON_SE_FASTPATH_IPH4_SET_SRC(header, se_trd->own_addr_low);
        OCTEON_SE_FASTPATH_IPH4_SET_DST(header, se_trd->gw_addr_low);

        csum = octeon_se_fastpath_ip_cksum(header,
                                           OCTEON_SE_FASTPATH_IP4_HDRLEN);
        OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, csum);

        prefix_ofs += OCTEON_SE_FASTPATH_IP4_HDRLEN;
      }
    else if (se_trd->ip_version_6 == 1)
      {
        OCTEON_SE_ASSERT(se_trd->tunnel_mode);

        /* IPv6 tunnel mode. */
        OCTEON_SE_DEBUG(9, "Building outer IPv6 header at %p\n", header);

        OCTEON_SE_FASTPATH_IPH6_SET_VERSION(header, 6);




        tos = 0;
        OCTEON_SE_FASTPATH_IPH6_SET_CLASS(header, tos);




        flow_label = 0;
        OCTEON_SE_FASTPATH_IPH6_SET_FLOW(header, flow_label);

        OCTEON_SE_FASTPATH_IPH6_SET_LEN(header, packet_out_len -
                                        OCTEON_SE_FASTPATH_IP6_HDRLEN);
        OCTEON_SE_FASTPATH_IPH6_SET_NH(header, se_trd->nh);
        OCTEON_SE_FASTPATH_IPH6_SET_HL(header,
                                       OCTEON_SE_FASTPATH_IP6_TUNNEL_MODE_HL);
        OCTEON_SE_FASTPATH_IPH6_SET_SRC_LOW(header, se_trd->own_addr_low);
        OCTEON_SE_FASTPATH_IPH6_SET_SRC_HIGH(header, se_trd->own_addr_high);

        OCTEON_SE_FASTPATH_IPH6_SET_DST_LOW(header, se_trd->gw_addr_low);
        OCTEON_SE_FASTPATH_IPH6_SET_DST_HIGH(header, se_trd->gw_addr_high);
        prefix_ofs += OCTEON_SE_FASTPATH_IP6_HDRLEN;
      }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_NATT
  /* Should we add NATT header as well ? */
  if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_NATT))
    {
      header = ((uint8_t *) cvmx_phys_to_ptr(packet_out.s.addr)) + prefix_ofs;

      OCTEON_SE_DEBUG(9, "Building UDP NAT-T header at %p\n", header);

      OCTEON_SE_ASSERT(packet_out.s.size >
                       prefix_ofs + OCTEON_SE_FASTPATH_UDP_HDRLEN);
      OCTEON_SE_ASSERT((se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_AH) == 0);
      OCTEON_SE_ASSERT(se_trd->nh == OCTEON_SE_FASTPATH_IPPROTO_UDP);

      OCTEON_SE_FASTPATH_UDPH_SET_SRCPORT(header, se_trd->natt_local_port);
      OCTEON_SE_FASTPATH_UDPH_SET_DSTPORT(header, se_trd->natt_remote_port);
      OCTEON_SE_FASTPATH_UDPH_SET_LEN(header,
                                      packet_out_len -
                                      (prefix_ofs - pc->s->ip_offset));
      OCTEON_SE_FASTPATH_UDPH_SET_CHECKSUM(header, 0);

      prefix_ofs += OCTEON_SE_FASTPATH_UDP_HDRLEN;
    }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_NATT */

  /* Build ESP/AH */
  esp_ah_ofs = prefix_ofs;
  header = ((uint8_t *) cvmx_phys_to_ptr(packet_out.s.addr)) + prefix_ofs;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AH
  if (se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_AH)
    {
      uint32_t low_seq;

      OCTEON_SE_DEBUG(9, "Building AH header at %p\n", header);

      OCTEON_SE_ASSERT(packet_out.s.size >
                       prefix_ofs + OCTEON_SE_FASTPATH_AH_HDRLEN +
                       combined->icv_len + icv_pad_len);

      /* Get and increment next sequence atomically. Note that se_trd
         contains the last sequence number transmitted, thus sequence
         is incremented by one here. */
      ipsec_seq =
        (uint64_t) cvmx_atomic_fetch_and_add64((int64_t *)&se_trd->seq, 1);
      ipsec_seq++;

      OCTEON_SE_FASTPATH_AHH_SET_NH(header, esp_ah_nh);
      OCTEON_SE_FASTPATH_AHH_SET_LEN(header,
                                     (combined->icv_len + icv_pad_len + 12) / 4
                                     - 2);
      OCTEON_SE_FASTPATH_AHH_SET_RESERVED(header, 0);
      OCTEON_SE_FASTPATH_AHH_SET_SPI(header, se_trd->spi_out);
      CVMX_DEXT(low_seq, ipsec_seq, 0, 32);
      OCTEON_SE_FASTPATH_AHH_SET_SEQ(header, low_seq);

      prefix_ofs += OCTEON_SE_FASTPATH_AH_HDRLEN + combined->icv_len;

      /* ICV computation also needs ICV field initialized to zero. */
      memcpy(mac_info->prefix.u8, header, OCTEON_SE_FASTPATH_AH_HDRLEN);
      memset(mac_info->prefix.u8 + OCTEON_SE_FASTPATH_AH_HDRLEN, 0,
             combined->icv_len);

      mac_info->prefix_len = OCTEON_SE_FASTPATH_AH_HDRLEN + combined->icv_len;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA2
      if (cvmx_unlikely((se_trd->ip_version_6 == 1) &&
                        (se_trd->transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2))
          )
        {
          prefix_ofs += 4;
          mac_info->prefix_len += 4;

          /* Use IPsec seq as AH padding for making 64 bit aligned. */
          OCTEON_SE_PUT_32BIT_ALIGNED(mac_info->prefix.u8 +
                                      OCTEON_SE_FASTPATH_AH_HDRLEN +
                                      combined->icv_len,
                                      low_seq);
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA2 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
      if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
        {
          CVMX_DEXT(mac_info->suffix, ipsec_seq, 32, 32);
          mac_info->suffix_available = 1;
        }
      else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
        mac_info->suffix_available = 0;

      /* Assert that crypto offset is 8 byte aligned */
      OCTEON_SE_ASSERT(((uint64_t) (cvmx_phys_to_ptr(packet_out.s.addr)
                                    + prefix_ofs)) % 8 == 0);

      octeon_se_fastpath_packet_buffer_create(&dst, packet_out,
                                              prefix_ofs,
                                              packet_out_len
                                              + pc->s->ip_offset,
                                              packet_out_num_segs);

      if (se_trd->ip_version_6 == 1)
        octeon_se_fastpath_mac_add_ah_header6(packet_out,
                                              pc->s->ip_offset,
                                              combined->update,
                                              core->transform_context,
                                              0);
      else
        octeon_se_fastpath_mac_add_ah_header4(packet_out,
                                              pc->s->ip_offset,
                                              combined->update,
                                              core->transform_context,
                                              0);

      OCTEON_SE_DEBUG(9, "MAC prefix, len %d\n", mac_info->prefix_len);
      OCTEON_SE_HEXDUMP(9, mac_info->prefix.u8, mac_info->prefix_len);

      /* Do the actual transform */
      (*combined->encrypt)(core->transform_context,
                           &dst,
                           &src,
                           mac_info,
                           NULL, icv);

      /* Copy ICV to packet. */
      if (cvmx_likely(combined->icv_len % 4 == 0))
        {
          for (i = 0; i < combined->icv_len; i += 4)
            {
              OCTEON_SE_PUT_32BIT_ALIGNED(cvmx_phys_to_ptr(packet_out.s.addr)
                                          + esp_ah_ofs
                                          + OCTEON_SE_FASTPATH_AH_HDRLEN + i,
                                          *(uint32_t *)(((uint8_t *)icv) + i));
            }
        }
      else
        {
          memcpy(cvmx_phys_to_ptr(packet_out.s.addr)
                 + esp_ah_ofs + OCTEON_SE_FASTPATH_AH_HDRLEN,
                 icv, combined->icv_len);
        }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA2
      if (cvmx_unlikely((se_trd->ip_version_6 == 1) &&
                        (se_trd->transform & OCTEON_SE_FASTPATH_MAC_HMAC_SHA2))
          )
        {
          /* Use IPsec seq as AH padding for making 64 bit aligned. */
          OCTEON_SE_PUT_32BIT(cvmx_phys_to_ptr(packet_out.s.addr)
                              + esp_ah_ofs
                              + OCTEON_SE_FASTPATH_AH_HDRLEN
                              + combined->icv_len,
                              low_seq);
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA2 */
    }
  else if (cvmx_likely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_ESP))
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */
    {
      uint32_t low_seq;

      OCTEON_SE_DEBUG(9, "Building ESP header at %p\n", header);

      /* Assert that there is enough space for ESP */
      OCTEON_SE_ASSERT(packet_out.s.size >
                       prefix_ofs + OCTEON_SE_FASTPATH_ESP_HDRLEN);

      /* Get and increment next sequence atomically. Note that se_trd
         contains the last sequence number transmitted, thus sequence
         is incremented by one here. */
      ipsec_seq =
        (uint64_t) cvmx_atomic_fetch_and_add64((int64_t *)&se_trd->seq, 1);
      ipsec_seq++;

      /* Build ESP header. */
      OCTEON_SE_FASTPATH_ESPH_SET_SPI(header, se_trd->spi_out);
      CVMX_DEXT(low_seq, ipsec_seq, 0, 32);
      OCTEON_SE_FASTPATH_ESPH_SET_SEQ(header, low_seq);
      prefix_ofs += OCTEON_SE_FASTPATH_ESP_HDRLEN;

      /* Fill in extra info for transform. */
      extra_info->pad_len = pad_len;
      extra_info->nh = esp_ah_nh;

      /* Fill in extra data form MAC. */
      OCTEON_SE_PUT_32BIT_ALIGNED(mac_info->prefix.u8, se_trd->spi_out);

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
      if (cvmx_likely(combined->is_auth_cipher))
        {
          /* Extract cipher nonce. */
          OCTEON_SE_ASSERT(se_trd->cipher_nonce_size == 4);
          OCTEON_SE_GET_32BIT_ALIGNED(se_trd->keymat +
                                      OCTEON_MAX_KEYMAT_LEN /2 +
                                      se_trd->cipher_key_size,
                                      extra_info->cipher_nonce);

          /* Use IPsec seq# as counter. */
          extra_info->iv[0] = ipsec_seq;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
          if (cvmx_unlikely(se_trd->transform &
                            OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
            {
              OCTEON_SE_PUT_64BIT(&mac_info->prefix.u8[4], ipsec_seq);
              mac_info->prefix_len = 12;
            }
          else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
            {
              OCTEON_SE_PUT_32BIT_ALIGNED(&mac_info->prefix.u8[4], low_seq);
              mac_info->prefix_len = 8;
            }
        }
      else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */
        {
          for (i = 0; i < combined->cipher_iv_len / 8; i++)
            extra_info->iv[i] = cvmx_rng_get_random64();

          /* Prepare extra mac information */
          OCTEON_SE_PUT_32BIT_ALIGNED(&mac_info->prefix.u8[4], low_seq);
          mac_info->prefix_len = 8;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
          if (cvmx_unlikely(se_trd->transform &
                            OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
            {
              CVMX_DEXT(mac_info->suffix, ipsec_seq, 32, 32);
              mac_info->suffix_available = 1;
            }
          else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
            mac_info->suffix_available = 0;
        }

      /* Assert that crypto offset is 8 byte aligned */
      OCTEON_SE_ASSERT(((uint64_t) (cvmx_phys_to_ptr(packet_out.s.addr)
                                    + prefix_ofs)) % 8 == 0);

      octeon_se_fastpath_packet_buffer_create(&dst, packet_out,
                                              prefix_ofs,
                                              packet_out_len
                                              + pc->s->ip_offset
                                              - prefix_ofs,
                                              packet_out_num_segs);

      OCTEON_SE_DEBUG(9, "Performing crypto transform\n");

      /* Do the actual transform. */
      (*combined->encrypt)(core->transform_context,
                           &dst,
                           &src,
                           mac_info,
                           extra_info, icv);

      /* The trailer should be appended at the end of encrypted data.
         Write ptr is pointing to correct location which may be unaligned
         if aes-gcm is used. */
      OCTEON_SE_ASSERT(dst.total_bytes == combined->icv_len);

      OCTEON_SE_DEBUG(9, "Inserting ICV, len %d:\n", (int) combined->icv_len);
      OCTEON_SE_HEXDUMP(9, icv, combined->icv_len);

      octeon_se_fastpath_buffer_copy_in(&dst, icv, combined->icv_len);
    }

  /* Update trd statistics only after successful encryption. */
  OCTEON_SE_FASTPATH_STATS({
    cvmx_atomic_add64((int64_t *) &se_trd->out_octets, out_octets);
    cvmx_atomic_add64((int64_t *) &se_trd->out_packets, 1);
  });

  /* Update fields of pc that are required in later processing stages. */
  pc->s->ip_version_6 = se_trd->ip_version_6;

  /* Unlock transform data */
  OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_i, se_trd);

  /* Replace packet buffer pointer chain in wqe */
  cvmx_helper_free_packet_data(pc->wqe);

  pc->s->ip_len = packet_out_len;
  pc->wqe->packet_ptr = packet_out;
  pc->wqe->word2.s.bufs = packet_out_num_segs;

  OCTEON_SE_DEBUG(9, "Outbound transform execution successfully completed\n");

  return OCTEON_SE_FASTPATH_RET_OK;

 slowpath:
  OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_i, se_trd);
  OCTEON_SE_ASSERT(packet_out.u64 == 0);
  return OCTEON_SE_FASTPATH_RET_SLOWPATH;

 corrupt:
#ifdef OCTEON_SE_FASTPATH_AUDIT_CORRUPT
  OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_i, se_trd);
  OCTEON_SE_ASSERT(packet_out.u64 == 0);
  return OCTEON_SE_FASTPATH_RET_CORRUPT;
#endif /* OCTEON_SE_FASTPATH_AUDIT_CORRUPT */
  /* If AUDIT_CORRUPT is not defined, then fall through to drop. */

 drop:
  OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *) &se_trd->drop_packets,
                                             1));
  OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_i, se_trd);
  OCTEON_SE_ASSERT(packet_out.u64 == 0);
  return OCTEON_SE_FASTPATH_RET_DROP;
}
