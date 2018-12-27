/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements the fragmentation support in outbound
   direction. Currently all fragmented packets in the inbound
   direction are already sent to the slowpath.
*/

#include "octeon_se_fastpath_internal.h"
#include "octeon_se_fastpath_inline.h"

#ifdef OCTEON_SE_FASTPATH_FRAGMENTATION

static uint32_t
octeon_se_fastpath_fragc_helper_alloc(SeFastpathFragmentContext fragc,
                                      SeFastpathPacketContext orig_pc,
                                      SeFastpathPacketContext frag_pc,
                                      uint16_t data_len)
{
  cvmx_wqe_t *wqe;
  cvmx_buf_ptr_t fragment;
  uint64_t num_segments = 0;
  uint32_t len;
  size_t alignment;

  wqe = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
  if (cvmx_unlikely(wqe == NULL))
    {
      OCTEON_SE_DEBUG(3, "Out of memory while allocating wqe for fragment.\n");
      return 1;
    }

  len = data_len + fragc->frag_hlen;
  if (cvmx_unlikely(orig_pc->s->ip_version_6))
    alignment = (OCTEON_SE_ALIGN_64(orig_pc->s->ip_offset
                                    + OCTEON_SE_FASTPATH_IP6_HDRLEN
                                    + OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN)
                 - (orig_pc->s->ip_offset
                    + OCTEON_SE_FASTPATH_IP6_HDRLEN
                    + OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN));
  else
    alignment = (OCTEON_SE_ALIGN_64(orig_pc->s->ip_offset
                                    + OCTEON_SE_FASTPATH_IP4_HDRLEN)
                 - (orig_pc->s->ip_offset
                    + OCTEON_SE_FASTPATH_IP4_HDRLEN));

  fragment.u64 =
    octeon_se_fastpath_alloc_packet_chain(len + orig_pc->s->ip_offset,
                                          alignment, &num_segments);
  if (cvmx_unlikely(fragment.u64 == 0))
    {
      OCTEON_SE_DEBUG(3, "Out of memory while allocating fragments.\n");
      cvmx_fpa_free(wqe, CVMX_FPA_WQE_POOL, 0);
      return 1;
    }
  wqe->packet_ptr.u64 = fragment.u64;
  wqe->len = len + orig_pc->s->ip_offset;
  wqe->word2.s.bufs = num_segments;




  frag_pc->wqe = wqe;
  frag_pc->s->ip_offset = orig_pc->s->ip_offset;
  frag_pc->s->ip_len = len;
  frag_pc->s->ip_version_6 = orig_pc->s->ip_version_6;

  frag_pc->mtu = orig_pc->mtu;
  frag_pc->oport = orig_pc->oport;
  frag_pc->nh_index = orig_pc->nh_index;
  frag_pc->media_hdrlen = orig_pc->media_hdrlen;
  memcpy(frag_pc->media_hdr.data,
         orig_pc->media_hdr.data, frag_pc->media_hdrlen);

  return 0;
}

uint32_t
octeon_se_fastpath_fragc_init(SeFastpathCoreContext core,
                              SeFastpath fastpath,
                              SeFastpathFragmentContext fragc,
                              SeFastpathPacketContext pc,
                              size_t mtu,
                              uint8_t df_on_first_fragment)
{
  uint8_t * header;
  size_t packet_len = pc->s->ip_len;

  /* Initialize common fields in the fragment context. */
  fragc->pc = pc;
  fragc->mtu = mtu;
  fragc->offset = 0;

  /* Get a pointer to the packet to be fragmented. */
  header =
    (uint8_t *)cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + pc->s->ip_offset;

  if (pc->s->ip_version_6)
    {
      uint16_t frag_hlen;
      uint16_t frag_data_len;

      fragc->total_len = packet_len - OCTEON_SE_FASTPATH_IP6_HDRLEN;

      /* Compute fragments' header and data lengths. */
      frag_hlen =
        OCTEON_SE_FASTPATH_IP6_HDRLEN + OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN;
      frag_data_len = ((size_t) (mtu - frag_hlen)) & (size_t) ~7;
      OCTEON_SE_ASSERT((frag_data_len > 0) &&
                       (frag_data_len <= (65535 - frag_hlen)));

      /* Store that information into the fragmentation context. */
      fragc->frag_hlen = frag_hlen;
      fragc->frag_data_len = frag_data_len;

      OCTEON_SE_FASTPATH_GET_NEXT_IPV6_FRAG_ID(core, fragc->u.ipv6.id);
      memcpy(fragc->u.ipv6.frag_hdr, header, OCTEON_SE_FASTPATH_IP6_HDRLEN);
      octeon_se_fastpath_packet_buffer_create(fragc->original_pkt,
                                              pc->wqe->packet_ptr,
                                              pc->s->ip_offset +
                                              OCTEON_SE_FASTPATH_IP6_HDRLEN,
                                              fragc->total_len,
                                              pc->wqe->word2.s.bufs);
    }
  else
    {
      /* Check if the packet has DF bit set. */
      if (cvmx_unlikely(pc->s->ipv4_df))
        {
          OCTEON_SE_DEBUG(7, "Cannot fragment packet. DF bit is set\n");
          return 1;
        }

      fragc->total_len = packet_len - OCTEON_SE_FASTPATH_IP4_HDRLEN;
      fragc->frag_hlen = OCTEON_SE_FASTPATH_IP4_HDRLEN;

      /* Compute amount of data to go in fragments. */
      fragc->frag_data_len = ((size_t)(mtu - OCTEON_SE_FASTPATH_IP4_HDRLEN)) &
                                      (size_t) ~7;

      OCTEON_SE_ASSERT(fragc->frag_data_len > 0 &&
                       fragc->frag_data_len < 65535);

      fragc->u.ipv4.df_on_first_fragment = df_on_first_fragment;

      /* Store computed values into the fragmentation context. */
      memcpy(fragc->u.ipv4.frag_hdr, header, OCTEON_SE_FASTPATH_IP4_HDRLEN);
      octeon_se_fastpath_packet_buffer_create(fragc->original_pkt,
                                              pc->wqe->packet_ptr,
                                              pc->s->ip_offset +
                                              OCTEON_SE_FASTPATH_IP4_HDRLEN,
                                              fragc->total_len,
                                              pc->wqe->word2.s.bufs);
    }

  return 0;
}

SeFastpathPacketContext
octeon_se_fastpath_fragc_next(SeFastpathCoreContext core,
                              SeFastpath fastpath,
                              SeFastpathFragmentContext fragc)
{
  SeFastpathPacketContext frag;
  SeFastpathPacketBufferStruct fragment_buffer[1];
  uint8_t * header;
  cvmx_buf_ptr_t packet_out;
  uint16_t hlen, data_len, len, offset_orig;
  uint16_t fragoff_orig, fragoff, checksum;
  uint8_t is_last_frag;

  /* If an error caused pc to be freed, return NULL to indicate we are done. */
  if (fragc->pc == NULL || fragc->offset >= fragc->total_len)
    return NULL;

  hlen = fragc->frag_hlen;
  data_len = fragc->frag_data_len;

  /* Determine the length of the data section of the fragment. */
  if (fragc->offset + data_len < fragc->total_len)
    len = data_len;
  else
    len = fragc->total_len - fragc->offset;

  if (fragc->offset + len == fragc->total_len)
    is_last_frag = TRUE;
  else
    is_last_frag = FALSE;

  OCTEON_SE_DEBUG(7, "Sending fragment offset=%d, len=%d\n",
                  fragc->offset, len);

  /* Allocate packet context and state for the fragment. */
  frag = &core->fragment.s;
  memset(frag, 0, sizeof(SeFastpathPacketContextStruct));
  frag->s = &core->fragment_state.s;
  memset(frag->s, 0, sizeof(SeFastpathPacketStateStruct));

  /* Create a new Work Queue entry and then copy extra things in pc. */
  if (cvmx_unlikely(octeon_se_fastpath_fragc_helper_alloc(fragc,
                                                          fragc->pc,
                                                          frag,
                                                          len)))
    {
      OCTEON_SE_DEBUG(3, "Unable to create fragment\n");
      return NULL;
    }

  /* For local reference. */
  packet_out.u64 = frag->wqe->packet_ptr.u64;

  header =
    ((uint8_t *)cvmx_phys_to_ptr(packet_out.s.addr)) + frag->s->ip_offset;

  if (frag->s->ip_version_6)
    {
      uint8_t nh;
      OCTEON_SE_DEBUG(9, "Building IPv6 fragment\n");

      /* Assert that headers fit into the first segment. */
      OCTEON_SE_ASSERT(packet_out.s.size >
                       (frag->s->ip_offset +
                        OCTEON_SE_FASTPATH_IP6_HDRLEN +
                        OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN));

      memcpy(header, fragc->u.ipv6.frag_hdr, OCTEON_SE_FASTPATH_IP6_HDRLEN);

      OCTEON_SE_FASTPATH_IPH6_SET_LEN(header, len +
                                      OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN);
      OCTEON_SE_FASTPATH_IPH6_NH(header, nh);
      OCTEON_SE_FASTPATH_IPH6_SET_NH(header,
                                     OCTEON_SE_FASTPATH_IPPROTO_IPV6FRAG);

      /* Create the fragment header and copy it to its place. */
      header += OCTEON_SE_FASTPATH_IP6_HDRLEN;

      header[0] = nh;

      header[SSH_IP6_EXT_FRAGMENT_OFS_RESERVED1] = 0;
      OCTEON_SE_PUT_16BIT(header +
                          OCTEON_SE_FASTPATH_IP6_EXT_FRAGMENT_OFS_OFFSET,
                          (fragc->offset | (is_last_frag ? 0 : 1)));
      OCTEON_SE_PUT_32BIT(header +
                          OCTEON_SE_FASTPATH_IP6_EXT_FRAGMENT_OFS_ID,
                          fragc->u.ipv6.id);

      /* Finally, copy the payload. */
      octeon_se_fastpath_packet_buffer_create(fragment_buffer,
                                              packet_out,
                                              frag->s->ip_offset +
                                              OCTEON_SE_FASTPATH_IP6_HDRLEN +
                                       OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN,
                                              len,
                                              frag->wqe->word2.s.bufs);
      octeon_se_fastpath_buffer_copy(fragment_buffer,
                                     fragc->original_pkt,
                                     len);
    }
  else
    {
      /* Copy packet header to the fragment buffer. */
      OCTEON_SE_DEBUG(9, "Build IPv4 fragment\n");

      /* Asseet that header fits into the first segment. */
      OCTEON_SE_ASSERT(packet_out.s.size > (frag->s->ip_offset +
                                            OCTEON_SE_FASTPATH_IP4_HDRLEN));

      /* Copy in the IPv4 header first */
      memcpy(header, fragc->u.ipv4.frag_hdr,OCTEON_SE_FASTPATH_IP4_HDRLEN);

      /* Copy data from the original packet to the fragment data part. */
      octeon_se_fastpath_packet_buffer_create(fragment_buffer,
                                              packet_out,
                                              frag->s->ip_offset +
                                              OCTEON_SE_FASTPATH_IP4_HDRLEN,
                                              len,
                                              frag->wqe->word2.s.bufs);
      octeon_se_fastpath_buffer_copy(fragment_buffer,
                                     fragc->original_pkt,
                                     len);

      /* Compute new values for fragment offset and flag bits. */
      OCTEON_SE_FASTPATH_IPH4_FRAG(header, fragoff_orig);

      offset_orig = (fragoff_orig & OCTEON_SE_FASTPATH_IP4_FRAG_MASK) << 3;
      fragoff = fragoff_orig & OCTEON_SE_FASTPATH_IPH4_FRAGOFF_RF;
      if (fragc->offset + data_len < fragc->total_len ||
          (fragoff_orig & OCTEON_SE_FASTPATH_IPH4_FRAGOFF_MF))
        fragoff |= OCTEON_SE_FASTPATH_IPH4_FRAGOFF_MF;

      /* If df_on_first_fragment is set and this is the first fragment,
         set DF bit */
      if (fragc->offset == 0 && fragc->u.ipv4.df_on_first_fragment)
        fragoff |= OCTEON_SE_FASTPATH_IPH4_FRAGOFF_DF;

      OCTEON_SE_ASSERT((fragc->offset & 7) == 0);
      OCTEON_SE_FASTPATH_IPH4_SET_FRAG(header,
                           (fragoff | ((fragc->offset + offset_orig) >> 3)));
      OCTEON_SE_FASTPATH_IPH4_SET_LEN(header, hlen + len);
      OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, 0);

      checksum = octeon_se_fastpath_ip_cksum(header, hlen);
      OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, checksum);
    }

  /* Update next fragment offset. */
  fragc->offset += len;

  /* Return the fragment. */
  return frag;
}

void octeon_se_fastpath_fragc_uninit(SeFastpathCoreContext core,
                                     SeFastpath fastpath,
                                     SeFastpathFragmentContext fragc)
{
  if (cvmx_likely(fragc->pc))
    {
      cvmx_helper_free_packet_data(fragc->pc->wqe);
      cvmx_fpa_free(fragc->pc->wqe, CVMX_FPA_WQE_POOL, 0);
      fragc->pc->wqe = NULL;
    }
}

#endif /* OCTEON_SE_FASTPATH_FRAGMENTATION */
