/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file implements inbound IPsec transform on SE fastpath.
*/

#include "octeon_se_fastpath_internal.h"
#include "octeon_se_fastpath_transform_i.h"
#include "octeon_se_fastpath_inline.h"

static inline int
octeon_se_fastpath_transform_in_antireplay(SeFastpathPacketContext pc,
                                           SeFastpathTransformData se_trd,
                                           uint32_t sequence_number,
                                           uint32_t old)
{
  uint64_t *replay_window;
  uint64_t replay_offset, seq, max, diff;
  uint32_t bits_ofs;

  seq = sequence_number;

  OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd);

  OCTEON_SE_ASSERT(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_ANTIREPLAY);
  OCTEON_SE_FASTPATH_TRD_REPLAY_LOCK(se_trd);
  if (cvmx_unlikely(old))
    {
      replay_offset = se_trd->old_replay_offset;
      replay_window = se_trd->old_replay_mask;
    }
  else
    {
      replay_offset = se_trd->replay_offset;
      replay_window = se_trd->replay_mask;
    }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
  if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
    {
      uint32_t low, high, temp;
      CVMX_DEXT(low, replay_offset, 0, 32);
      CVMX_DEXT(high, replay_offset, 32, 32);

      /* Determine seq_high from seq_low and the present position
         of the antireplay window. */
      temp = (sequence_number >= low) ? high : high + 1;
      CVMX_DINS(seq, temp, 32, 32);
    }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */

  /* Check if seq is below start of replay window. */
  if (cvmx_unlikely(seq < replay_offset))
    {
      OCTEON_SE_DEBUG(3, "Replay prevention recheck fail\n");
      goto fail;
    }

  max = replay_offset +
    OCTEON_FASTPATH_REPLAY_WINDOW_BITS * OCTEON_FASTPATH_REPLAY_WINDOW_WORDS;

  /* Recheck that seq does not lie in the replay window bit field */
  if ((seq < max) || (replay_offset > max))
    {
      diff = seq - replay_offset;
      CVMX_DEXT(bits_ofs, diff, 0, 32);
      OCTEON_SE_ASSERT((bits_ofs / OCTEON_FASTPATH_REPLAY_WINDOW_BITS)
                       < OCTEON_FASTPATH_REPLAY_WINDOW_WORDS);
      if (cvmx_unlikely(
          replay_window[bits_ofs / OCTEON_FASTPATH_REPLAY_WINDOW_BITS] &
          ((uint64_t) 1 << (bits_ofs & (OCTEON_FASTPATH_REPLAY_WINDOW_BITS-1)))
          ))
        {
          OCTEON_SE_DEBUG(3, "Replay prevention recheck fail\n");
          goto fail;
        }
    }

  /* Check whether we need to shift the replay window. Note that
     we must check that replay_offset does not wrap around when
     we add to it. */
  if (seq >= max && replay_offset <= max)
    {
      uint32_t diff_words = 0;
      unsigned int words_to_keep, i;

      diff = seq - max;
      diff = diff + 1;

      if (diff >> 32)
        {
          words_to_keep = 0;
        }
      else
        {
          /* Compute the number of words the window is to move. */
          CVMX_DEXT(diff_words, diff, 0, 32);
          diff_words = ((diff_words + (OCTEON_FASTPATH_REPLAY_WINDOW_BITS-1))
                        / OCTEON_FASTPATH_REPLAY_WINDOW_BITS);
          /* Compute the number of words to keep in the window. */
          if (diff_words > OCTEON_FASTPATH_REPLAY_WINDOW_WORDS)
            words_to_keep = 0;
          else
            words_to_keep = OCTEON_FASTPATH_REPLAY_WINDOW_WORDS - diff_words;
        }

      /* Now update the window. */
      for (i = 0; i < words_to_keep; i++)
        {
          OCTEON_SE_ASSERT((i + diff_words)
                           < OCTEON_FASTPATH_REPLAY_WINDOW_WORDS);
          replay_window[i] = replay_window[i + diff_words];
        }
      for (i = words_to_keep; i < OCTEON_FASTPATH_REPLAY_WINDOW_WORDS; i++)
        {
          OCTEON_SE_ASSERT(i < OCTEON_FASTPATH_REPLAY_WINDOW_WORDS);
          replay_window[i] = 0;
        }

      replay_offset += OCTEON_FASTPATH_REPLAY_WINDOW_BITS * diff_words;
    }

  /* Set the appropriate bit in the replay window to indicate
     that the corresponding packet has been received. */
  diff = seq - replay_offset;
  CVMX_DEXT(bits_ofs, diff, 0, 32);

  OCTEON_SE_ASSERT((bits_ofs / OCTEON_FASTPATH_REPLAY_WINDOW_BITS)
                   < OCTEON_FASTPATH_REPLAY_WINDOW_WORDS);
  replay_window[bits_ofs / OCTEON_FASTPATH_REPLAY_WINDOW_BITS]
    |= ((uint64_t) 1 << (bits_ofs & (OCTEON_FASTPATH_REPLAY_WINDOW_BITS-1)));

  /* Update anti-replay information in trd. */
  if (cvmx_unlikely(old))
    {
      se_trd->old_replay_offset = replay_offset;
    }
  else
    {
      se_trd->replay_offset = replay_offset;
    }

  OCTEON_SE_FASTPATH_TRD_REPLAY_UNLOCK(se_trd);
  return 1;

 fail:
  OCTEON_SE_FASTPATH_TRD_REPLAY_UNLOCK(se_trd);
  return 0;
}


/** Execute inbound transforms */
SeFastpathRet
octeon_se_fastpath_transform_in(SeFastpathCoreContext core,
                                SeFastpath fastpath,
                                SeFastpathPacketContext pc)
{
  cvmx_buf_ptr_t packet_out;
  uint32_t packet_out_len; /* Length of decrypted IP packet */
  uint64_t packet_out_num_segment;
  SeFastpathTransformData se_trd;
  SeFastpathPacketBufferStruct src, dst;
  SeFastpathCombinedTransform combined = NULL;
  SeFastpathEspExtraInfoStruct extra_info[1];
  SeFastpathMacExtraInfoStruct mac_info[1];
  uint64_t icv[OCTEON_SE_FASTPATH_MAX_HASH_WORDS];
  uint64_t packet_icv_buffer[OCTEON_SE_FASTPATH_MAX_HASH_WORDS];
  uint8_t *packet_icv = NULL;
  size_t prefix_len, ah_esp_ofs = 0;
  size_t prefix_ofs, i;
  uint8_t ah_esp_nh = 0, trailer_len = 0; /* Next header specified by AH/ESP */
  uint32_t trd_i;
  uint8_t *ucpw;
  uint32_t old;
  uint8_t *keymat;
  uint32_t run_time;
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  size_t in_octets;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
  uint64_t replay_offset = 0;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AH
  uint64_t ah_pad[5];
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */

  OCTEON_SE_DEBUG(9, "Execute transform in\n");

  packet_out.u64 = 0;

  OCTEON_SE_ASSERT(pc->transform_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
  trd_i = pc->transform_index & 0x00ffffff;
  OCTEON_SE_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);

  se_trd = OCTEON_SE_FASTPATH_TRD(fastpath, trd_i);
  OCTEON_SE_FASTPATH_TRD_READ_LOCK(fastpath, trd_i, se_trd);

  OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd);

  OCTEON_SE_ASSERT(pc->flag_ipsec_incoming);

  /* If transform is complex, pass packet to slowpath. */
  if (cvmx_unlikely(se_trd->is_special))
    {
      OCTEON_SE_DEBUG(9, "Special transform %08x, passing to slwopath\n",
                      se_trd->transform);
      goto slowpath;
    }

  /* Recheck that SPI value matches the one in transform. Mismatch can
     occure during rekey, because incoming IPsec flow and trd are not
     updated atomically. */
  if (cvmx_unlikely((pc->s->forward == 0 && pc->s->ipsec_spi != se_trd->spi_in)
                    || (pc->s->forward == 1
                        && pc->s->ipsec_spi != se_trd->old_spi_in)))
    {
      OCTEON_SE_DEBUG(9, "Inbound SPI mismatch, passing to slowpath\n");
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

  /* Update trd input timestamp. */
  run_time = cvmx_fau_fetch_and_add32(OCTEON_SE_FASTPATH_FAU_RUNTIME, 0);
  cvmx_atomic_set32((int32_t *) &se_trd->last_in_packet_time,
                    (int32_t) run_time);

  if (cvmx_unlikely(pc->s->forward == 1))
    {
      /* Must be a packet matching old SPI before rekey */
      old = 1;
      keymat = se_trd->old_keymat;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
      if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
        {
          OCTEON_SE_FASTPATH_TRD_REPLAY_LOCK(se_trd);
          replay_offset = se_trd->old_replay_offset;
          OCTEON_SE_FASTPATH_TRD_REPLAY_UNLOCK(se_trd);
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
    }
  else
    {
      old = 0;
      keymat = se_trd->keymat;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
      if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
        {



          OCTEON_SE_FASTPATH_TRD_REPLAY_LOCK(se_trd);
          replay_offset = se_trd->replay_offset;
          OCTEON_SE_FASTPATH_TRD_REPLAY_UNLOCK(se_trd);
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
    }

  (*combined->init)(core->transform_context,
                    keymat,
                    se_trd->cipher_key_size,
                    keymat + OCTEON_MAX_ESP_KEY_BITS/8,
                    se_trd->mac_key_size);

  OCTEON_SE_ASSERT(pc->s->ipproto == se_trd->nh || pc->s->ipsec_natt == 1);

  prefix_ofs = pc->s->ip_offset;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  if (cvmx_unlikely(!se_trd->tunnel_mode))
    {
      prefix_ofs += pc->s->tr_offset;
      prefix_len = 0;
    }
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */
    {
      if (se_trd->ip_version_6)
        prefix_len = OCTEON_SE_FASTPATH_IP6_HDRLEN;
      else
        prefix_len = OCTEON_SE_FASTPATH_IP4_HDRLEN;
    }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_NATT
  /* Handle NAT-T UDP header. */
  if (pc->s->ipproto == OCTEON_SE_FASTPATH_IPPROTO_UDP)
    prefix_len += OCTEON_SE_FASTPATH_UDP_HDRLEN;
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_NATT */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AH
  if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_AH))
    {
      /* Calculate AH length in bytes and sanity check result.
         This takes care of any AH padding. SE fastpath supports
         minimum amount of AH padding because of performance reasons.
         If the packet has more AH padding as the SE fastpath can
         handle then the packet is sent to slowpath for auditing
         or dropped if auditing of corrupt packets is disabled. */
      pc->s->ipsec_len = (pc->s->ipsec_len + 2) * 4;
      if (cvmx_unlikely(pc->s->ipsec_len > sizeof(mac_info->prefix)))
        goto corrupt;

      ah_esp_ofs = prefix_ofs + prefix_len;
      prefix_len += pc->s->ipsec_len;
      trailer_len = 0;
    }
  if (cvmx_likely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_ESP))
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */
    {
      ah_esp_ofs = prefix_ofs + prefix_len;
      prefix_len += OCTEON_SE_FASTPATH_ESP_HDRLEN;
      trailer_len = 2 + combined->icv_len;
    }

  /* Allocate a packet chain of equal size.
     Align crypto result to 8 byte boundary. */
  packet_out.u64 =
    octeon_se_fastpath_alloc_packet_chain(pc->s->ip_len + pc->s->ip_offset,
                                          ((prefix_ofs + 7) & ~7)
                                          - prefix_ofs,
                                          &packet_out_num_segment);

  if (cvmx_unlikely(packet_out.u64 == 0))
    {
      OCTEON_SE_DEBUG(3, "Result packet allocation failed\n");
      goto drop;
    }

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  /* For transport mode copy out l3 data. */
  if (prefix_ofs > pc->s->ip_offset)
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

  /* Prepare result buffer. */
  octeon_se_fastpath_packet_buffer_create(&dst, packet_out,
                                          prefix_ofs,
                                          pc->s->ip_len + pc->s->ip_offset
                                          - prefix_ofs,
                                          packet_out_num_segment);

  /* Count the number of bytes input to crypto processing. */
  OCTEON_SE_FASTPATH_STATS(in_octets =
                           pc->s->ip_len + pc->s->ip_offset - prefix_ofs);

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AH
  if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_AH))
    {
      /* Assert that flow lookup matched the correct SPI */
      OCTEON_SE_ASSERT((pc->s->forward == 0
                        && pc->s->ipsec_spi == se_trd->spi_in)
                       || (pc->s->forward == 1
                           && pc->s->ipsec_spi == se_trd->old_spi_in));

      ah_esp_nh = pc->s->ipsec_nh;

      /* Copy AH header for HMAC calculation, set ICV to zero in copy. */
      prefix_ofs = ah_esp_ofs + OCTEON_SE_FASTPATH_AH_HDRLEN;
      OCTEON_SE_ASSERT(pc->wqe->packet_ptr.s.size > prefix_ofs);
      ucpw =
        (uint8_t *) cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + ah_esp_ofs;
      memcpy(mac_info->prefix.u8, ucpw, OCTEON_SE_FASTPATH_AH_HDRLEN);
      memset(mac_info->prefix.u8 + OCTEON_SE_FASTPATH_AH_HDRLEN, 0,
             combined->icv_len);
      mac_info->prefix_len = OCTEON_SE_FASTPATH_AH_HDRLEN + combined->icv_len;

      /* Copy AH padding. */
      if (cvmx_unlikely(pc->s->ipsec_len > mac_info->prefix_len))
        {
          memcpy(mac_info->prefix.u8 + OCTEON_SE_FASTPATH_AH_HDRLEN
                 + combined->icv_len,
                 ucpw + OCTEON_SE_FASTPATH_AH_HDRLEN + combined->icv_len,
                 pc->s->ipsec_len - mac_info->prefix_len);
          mac_info->prefix_len = pc->s->ipsec_len;
        }
      OCTEON_SE_ASSERT(mac_info->prefix_len <= sizeof(mac_info->prefix));

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
      if (cvmx_unlikely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
        {
          uint32_t low, high;

          CVMX_DEXT(low, replay_offset, 0, 32);
          CVMX_DEXT(high, replay_offset, 32, 32);
          high = (pc->s->ipsec_seq > low) ? high : high + 1;

          mac_info->suffix = high;
          mac_info->suffix_available = 1;
        }
      else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
        mac_info->suffix_available = 0;

      /* Prepare source buffer. Src is now at start of ICV. */
      octeon_se_fastpath_packet_buffer_create(&src, pc->wqe->packet_ptr,
                                              prefix_ofs,
                                              pc->s->ip_len + pc->s->ip_offset
                                              - prefix_ofs,
                                              pc->wqe->word2.s.bufs);

      /* Extract the original ICV from packet. */
      packet_icv =
        octeon_se_fastpath_buffer_pullup_read(&src, combined->icv_len,
                                              (uint8_t *) packet_icv_buffer);

      /* Skip AH padding, it is included in mac_info for MAC calculation. */
      if (cvmx_unlikely(pc->s->ipsec_len >
                        (OCTEON_SE_FASTPATH_AH_HDRLEN + combined->icv_len)))
        octeon_se_fastpath_buffer_pullup_read(&src,
                                              pc->s->ipsec_len
                                              - (OCTEON_SE_FASTPATH_AH_HDRLEN
                                                 + combined->icv_len),
                                              (uint8_t *) &ah_pad);

      /* Calculate HMAC over IP header. */
      if (se_trd->ip_version_6 == 1)
        octeon_se_fastpath_mac_add_ah_header6(pc->wqe->packet_ptr,
                                              pc->s->ip_offset,
                                              combined->update,
                                              core->transform_context,
                                              0);
      else
        octeon_se_fastpath_mac_add_ah_header4(pc->wqe->packet_ptr,
                                              pc->s->ip_offset,
                                              combined->update,
                                              core->transform_context,
                                              0);

      /* Calculate HMAC over payload data. Src is now at start of payload. */
      (*combined->decrypt)(core->transform_context, &dst, &src, mac_info,
                           NULL, icv);

      /* Assert that all bytes were transformed. */
      OCTEON_SE_ASSERT(src.total_bytes == 0);

      /* AH does not have extra padding. */
      extra_info->pad_len = 0;
    }

  else if (cvmx_likely(se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_ESP))
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */
    {
      /* Assert that flow lookup matched the correct SPI */
      OCTEON_SE_ASSERT((pc->s->forward == 0
                        && pc->s->ipsec_spi == se_trd->spi_in)
                       || (pc->s->forward == 1
                           && pc->s->ipsec_spi == se_trd->old_spi_in));

      /* Copy ESP header for HMAC calculation. */
      prefix_ofs = ah_esp_ofs + OCTEON_SE_FASTPATH_ESP_HDRLEN;
      ucpw =
        (uint8_t *)(cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + ah_esp_ofs);

      /* Prepare source buffer. Src is now at start of IV. */
      octeon_se_fastpath_packet_buffer_create(&src, pc->wqe->packet_ptr,
                                              prefix_ofs,
                                              pc->s->ip_len + pc->s->ip_offset
                                              - prefix_ofs - combined->icv_len,
                                              pc->wqe->word2.s.bufs);

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
      if (cvmx_likely(combined->is_auth_cipher))
        {
          /* Extract cipher nonce from key material. */
          OCTEON_SE_ASSERT(se_trd->cipher_nonce_size == 4);
          OCTEON_SE_GET_32BIT_ALIGNED(keymat + se_trd->cipher_key_size,
                                      extra_info->cipher_nonce);
          /* Extract IV from packet. */
          OCTEON_SE_ASSERT(combined->cipher_iv_len == 8);
          extra_info->iv[0] = octeon_se_fastpath_buffer_read_word(&src);

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
          if (cvmx_unlikely(se_trd->transform &
                            OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
            {
              uint32_t low, high;

              CVMX_DEXT(low, replay_offset, 0, 32);
              CVMX_DEXT(high, replay_offset, 32, 32);

              high = (pc->s->ipsec_seq > low) ? high : high + 1;

              OCTEON_SE_PUT_32BIT_ALIGNED(mac_info->prefix.u8,
                                          pc->s->ipsec_spi);
              OCTEON_SE_PUT_32BIT_ALIGNED(mac_info->prefix.u8 + 4, high);
              OCTEON_SE_PUT_32BIT_ALIGNED(mac_info->prefix.u8 + 8,
                                          pc->s->ipsec_seq);
              mac_info->prefix_len = OCTEON_SE_FASTPATH_ESP_HDRLEN + 4;
            }
          else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
            {
              memcpy(mac_info->prefix.u8, ucpw, OCTEON_SE_FASTPATH_ESP_HDRLEN);
              mac_info->prefix_len = OCTEON_SE_FASTPATH_ESP_HDRLEN;
            }
        }
      else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */
        {
          memcpy(mac_info->prefix.u8, ucpw, OCTEON_SE_FASTPATH_ESP_HDRLEN);
          mac_info->prefix_len = OCTEON_SE_FASTPATH_ESP_HDRLEN;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
          if (cvmx_unlikely(se_trd->transform &
                            OCTEON_SE_FASTPATH_IPSEC_LONGSEQ))
            {
              uint32_t low, high;

              CVMX_DEXT(low, replay_offset, 0, 32);
              CVMX_DEXT(high, replay_offset, 32, 32);
              high = (pc->s->ipsec_seq > low) ? high : high + 1;

              mac_info->suffix = high;
              mac_info->suffix_available = 1;
            }
          else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
            mac_info->suffix_available = 0;

          /* Extract IV from packet. */
          for (i = 0; i < combined->cipher_iv_len / 8; i++)
            extra_info->iv[i] = octeon_se_fastpath_buffer_read_word(&src);
        }

      /* Check that input length is a multiple of cipher block size. */
      if (combined->pad_boundary
          && (src.total_bytes % combined->pad_boundary) != 0)
        {
          OCTEON_SE_DEBUG(3, "Cryptotext length is not a multiple of "
                          "cipher block size\n");
          OCTEON_SE_DEBUG(7, "Cryptotext length %d cipher block size %d\n",
                          (int) src.total_bytes,
                          (int) combined->pad_boundary);
          octeon_se_fastpath_free_packet_chain(packet_out,
                                               packet_out_num_segment);
          packet_out.u64 = 0;

          /* Pass packet to slowpath for processing or auditing. Some
             implementations (including QuickSec backup fastpath) are
             able to receive ESP-NULL with 0 byte padding. */
          goto slowpath;
        }

      /* Transform payload data. */
      (*combined->decrypt)(core->transform_context, &dst, &src, mac_info,
                           extra_info, icv);

      /* Check ESP trailer fields. */
      if (cvmx_unlikely(extra_info->nh == 0))
        {
          OCTEON_SE_DEBUG(3, "Invalid ESP nexthdr 0\n");

          OCTEON_SE_DEBUG(9, "Packet in, IP len %d\n", (int) pc->s->ip_len);
          OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr),
                            pc->s->ip_len + pc->s->ip_offset);
          OCTEON_SE_DEBUG(9, "Packet out\n");
          OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(packet_out.s.addr),
                            pc->s->ip_len + pc->s->ip_offset);

          octeon_se_fastpath_free_packet_chain(packet_out,
                                               packet_out_num_segment);
          packet_out.u64 = 0;
          goto corrupt;
        }
      else if (cvmx_unlikely(extra_info->pad_len >
                             (pc->s->ip_len - prefix_len - trailer_len)))
        {
          OCTEON_SE_DEBUG(3, "Invalid ESP padding length %d\n",
                          (int) extra_info->pad_len);

          OCTEON_SE_DEBUG(9, "Packet in, IP len %d\n", (int) pc->s->ip_len);
          OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr),
                            pc->s->ip_len + pc->s->ip_offset);
          OCTEON_SE_DEBUG(9, "Packet out\n");
          OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(packet_out.s.addr),
                            pc->s->ip_len + pc->s->ip_offset);

          octeon_se_fastpath_free_packet_chain(packet_out,
                                               packet_out_num_segment);
          packet_out.u64 = 0;
          goto corrupt;
        }
      ah_esp_nh = extra_info->nh;

      /* Src is now at start of ICV. Update the src buffer length to reflect
         the actual length of data. */
      OCTEON_SE_ASSERT(src.total_bytes == 0);
      src.total_bytes = combined->icv_len;

      /* Extract the original ICV from packet. */
      packet_icv =
        octeon_se_fastpath_buffer_pullup_read(&src, combined->icv_len,
                                              (uint8_t *) packet_icv_buffer);

      /* Assert that all bytes were transformed. */
      OCTEON_SE_ASSERT(src.total_bytes == 0);
    }

  /* Compute the total length of the decrypted packet. */
  packet_out_len = (pc->s->ip_len - prefix_len - trailer_len
                    - extra_info->pad_len - combined->cipher_iv_len);

  /* Check the computed MAC value. */
  if (cvmx_unlikely(memcmp(icv, packet_icv, combined->icv_len) != 0))
    {
#ifdef OCTEON_SE_FASTPATH_DEBUG
      OCTEON_SE_DEBUG(3, "ICV check failed\n");

      OCTEON_SE_DEBUG(9, "ICV, len %d\n", (int) combined->icv_len);
      OCTEON_SE_HEXDUMP(9, icv, combined->icv_len);

      OCTEON_SE_DEBUG(9, "Packet ICV, len %d\n", (int) combined->icv_len);
      OCTEON_SE_HEXDUMP(9, packet_icv, combined->icv_len);

      OCTEON_SE_DEBUG(9, "MAC info, len %d\n", (int) mac_info->prefix_len);
      OCTEON_SE_HEXDUMP(9, mac_info->prefix.u8, mac_info->prefix_len);

      OCTEON_SE_DEBUG(9, "IV, len %d\n", (int) combined->cipher_iv_len);
      OCTEON_SE_HEXDUMP(9, extra_info->iv, combined->cipher_iv_len);

      OCTEON_SE_DEBUG(9, "Packet in, IP len %d\n", (int) pc->s->ip_len);
      OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr),
                        pc->s->ip_len + pc->s->ip_offset);

      OCTEON_SE_DEBUG(9, "Packet out, IP len %d\n", (int) (packet_out_len));
      OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(packet_out.s.addr),
                        packet_out_len + pc->s->ip_offset);
#endif /* OCTEON_SE_FASTPATH_DEBUG */

      /* Update mac failure statistics. */
      OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *)
                                                 &se_trd->num_mac_fails, 1));
      octeon_se_fastpath_free_packet_chain(packet_out,
                                           packet_out_num_segment);
      packet_out.u64 = 0;
      goto corrupt;
    }

  /* Perform antireplay check here */
  if (cvmx_unlikely((se_trd->transform & OCTEON_SE_FASTPATH_IPSEC_ANTIREPLAY)
                    && !octeon_se_fastpath_transform_in_antireplay(pc,
                                                              se_trd,
                                                              pc->s->ipsec_seq,
                                                              old)))
    {
      OCTEON_SE_DEBUG(3, "Failed in anti replay \n");
      octeon_se_fastpath_free_packet_chain(packet_out, packet_out_num_segment);
      packet_out.u64 = 0;
      goto corrupt;
    }

  /* Modify the headers of the decrypted and authenticated packet. */
  ucpw = (uint8_t *) cvmx_phys_to_ptr(packet_out.s.addr) + pc->s->ip_offset;

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  if (cvmx_unlikely(!se_trd->tunnel_mode))
    {
      uint16_t csum;

      /* In transport mode the transport header is 8 byte aligned.
         Here we know that there are no IPv4 options and that transport
         header is 8 byte aligned. Therefore it is guaranteed that IPv6
         header is 8 byte aligned and IPv4 header is 4 byte aligned. */

      if (pc->s->ip_version_6 == 0)
        {
          /* Fix lenght, IP proto and checksum. */
          OCTEON_SE_FASTPATH_IPH4_SET_LEN(ucpw, packet_out_len);
          OCTEON_SE_FASTPATH_IPH4_SET_PROTO(ucpw, ah_esp_nh);
          OCTEON_SE_FASTPATH_IPH4_CHECKSUM(ucpw, csum);

          csum =
            octeon_se_fastpath_csum_update_byte(csum,
                                             OCTEON_SE_FASTPATH_IPH4_OFS_PROTO,
                                             pc->s->ipproto, ah_esp_nh);
          csum =
            octeon_se_fastpath_csum_update_short(csum,
                                               OCTEON_SE_FASTPATH_IPH4_OFS_LEN,
                                               packet_out_len, pc->s->ip_len);

          OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(ucpw, csum);
        }
      else
        {
          /* Fix length and nextheader. */
          OCTEON_SE_FASTPATH_IPH6_SET_LEN(ucpw, packet_out_len -
                                          OCTEON_SE_FASTPATH_IP6_HDRLEN);
          OCTEON_SE_FASTPATH_IPH6_SET_NH(ucpw, ah_esp_nh);
        }
      pc->s->ipproto = ah_esp_nh;
    }
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */
    {
      /* In tunnel mode the IP header is 8 byte aligned.
         Parse IP protocol from inner header. */
      if (cvmx_likely(ah_esp_nh == OCTEON_SE_FASTPATH_IPPROTO_IPIP))
        {
          OCTEON_SE_FASTPATH_IPH4_PROTO(ucpw, pc->s->ipproto);
          pc->s->ip_version_6 = 0;
        }
      else if (cvmx_likely(ah_esp_nh == OCTEON_SE_FASTPATH_IPPROTO_IPV6))
        {
          OCTEON_SE_FASTPATH_IPH6_NH(ucpw, pc->s->ipproto);
          pc->s->ip_version_6 = 1;
        }
      else
        {
          OCTEON_SE_DEBUG(3, "Invalid IPsec next header %d\n", ah_esp_nh);

          OCTEON_SE_DEBUG(9, "Packet out, IP len %d\n",
                          (int) (packet_out_len));
          OCTEON_SE_HEXDUMP(9, cvmx_phys_to_ptr(packet_out.s.addr),
                            packet_out_len + pc->s->ip_offset);

          octeon_se_fastpath_free_packet_chain(packet_out,
                                               packet_out_num_segment);
          packet_out.u64 = 0;
          goto corrupt;
        }
    }

  /* Update pc only after successfull decryption */
  pc->s->tunnel_id = se_trd->inbound_tunnel_id;
  pc->s->prev_transform_index = pc->transform_index;

  /* Update trd statistics only after successful decryption. */
  OCTEON_SE_FASTPATH_STATS({
    cvmx_atomic_add64((int64_t *) &se_trd->in_octets, in_octets);
    cvmx_atomic_add64((int64_t *) &se_trd->in_packets, 1);
  });

  OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_i, se_trd);

  /* Fix up the length of the packet */
  pc->s->ip_len = packet_out_len;

  /* Replace packet buffer chain in work entry */
  cvmx_helper_free_packet_data(pc->wqe);
  pc->wqe->packet_ptr = packet_out;
  pc->wqe->word2.s.bufs = packet_out_num_segment;

  OCTEON_SE_DEBUG(9, "Inbound transform execution successfully completed\n");

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
  /* Update dropped packet statistics. */
  OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *) &se_trd->drop_packets,
                                             1));
  OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_i, se_trd);
  OCTEON_SE_ASSERT(packet_out.u64 == 0);
  return OCTEON_SE_FASTPATH_RET_DROP;
}
