/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file implements inline utility functions for SE fastpath.
*/

#ifndef OCTEON_SE_FASTPATH_INLINE_H
#define OCTEON_SE_FASTPATH_INLINE_H

#include "octeon_se_fastpath_internal.h"


/******************* Buffer manipulation funtions ************************/

/** Free packet buffer chain. This should be called only if the packet
    chain is not consumed by PKO. */
static inline void
octeon_se_fastpath_free_packet_chain(cvmx_buf_ptr_t packet,
                                     uint64_t num_bufs)
{
  cvmx_buf_ptr_t next_seg;

  while (num_bufs > 0)
    {
      OCTEON_SE_GET_64BIT(cvmx_phys_to_ptr(packet.s.addr) - 8, next_seg.u64);
      cvmx_fpa_free(cvmx_phys_to_ptr(((packet.s.addr>>7) - packet.s.back)<<7),
                    packet.s.pool, 0);
      packet = next_seg;
      num_bufs = num_bufs - 1;
    }
}

/** Allocate and build packet chain. This allocates a sufficient
    number of buffers to fit `size' bytes. The packet chain can be
    passed to PKO as such. The addr pointer of the first buffer in the chain
    is guaranteed to be 8 byte aligned. */
static inline uint64_t
octeon_se_fastpath_alloc_packet_chain(size_t size,
                                      size_t alignment,
                                      uint64_t *num_bufs)
{
  cvmx_buf_ptr_t packet;
  cvmx_buf_ptr_t seg_ptr;
  uint8_t *buf, *next_buf;

  *num_bufs = 0;

  packet.u64 = 0;
  packet.s.pool = CVMX_FPA_PACKET_POOL;
  packet.s.size = (CVMX_FPA_POOL_0_SIZE -
                   OCTEON_SE_FASTPATH_FIRST_MBUFF_SKIP - 8 - alignment);
  buf = cvmx_fpa_alloc(packet.s.pool);
  if (cvmx_unlikely(buf == NULL))
    goto error;

  buf += OCTEON_SE_FASTPATH_FIRST_MBUFF_SKIP + 8 + alignment;
  packet.s.addr = cvmx_ptr_to_phys(buf);
  OCTEON_SE_ASSERT((((uint64_t)(buf - alignment)) % 8) == 0);
  packet.s.back = (OCTEON_SE_FASTPATH_FIRST_MBUFF_SKIP + 8 + alignment) >> 7;
  if (cvmx_likely(size < packet.s.size))
    size = 0;
  else
    size -= packet.s.size;
  *num_bufs = 1;

  while (cvmx_unlikely(size > 0))
    {
      seg_ptr.u64 = 0;
      seg_ptr.s.pool = CVMX_FPA_PACKET_POOL;
      seg_ptr.s.size = (CVMX_FPA_POOL_0_SIZE -
                        OCTEON_SE_FASTPATH_NOT_FIRST_MBUFF_SKIP - 8);
      next_buf = cvmx_fpa_alloc(seg_ptr.s.pool);
      if (cvmx_unlikely(next_buf == NULL))
        goto error;

      next_buf += OCTEON_SE_FASTPATH_NOT_FIRST_MBUFF_SKIP + 8;
      seg_ptr.s.addr = cvmx_ptr_to_phys(next_buf);
      seg_ptr.s.back = (OCTEON_SE_FASTPATH_NOT_FIRST_MBUFF_SKIP + 8) >> 7;
      if (cvmx_likely(size < seg_ptr.s.size))
        size = 0;
      else
        size -= seg_ptr.s.size;
      *num_bufs = *num_bufs + 1;

      OCTEON_SE_PUT_64BIT(buf - 8, seg_ptr.u64);
      buf = next_buf;
    }
  OCTEON_SE_ASSERT(size == 0);

  /* Clear next buffer pointer in last segment. */
  OCTEON_SE_PUT_64BIT(buf - 8, 0);

  return packet.u64;

 error:
  octeon_se_fastpath_free_packet_chain(packet, *num_bufs);
  return 0;
}

static inline void
octeon_se_fastpath_packet_buffer_create(SeFastpathPacketBuffer buf,
                                        cvmx_buf_ptr_t packet_ptr,
                                        size_t offset,
                                        size_t total_len,
                                        size_t num_bufs)
{
  buf->packet = packet_ptr;
  buf->total_bytes = total_len;
  buf->total_num_bufs = num_bufs;

  buf->ptr = (uint8_t *) cvmx_phys_to_ptr(packet_ptr.s.addr) + offset;
  buf->bytes_available = packet_ptr.s.size - offset;
  buf->curr = packet_ptr;

  /* Prefetch data pointer as it will be used soon. Prefetch the
     following cache line too. */
  CVMX_PREFETCH0(buf->ptr);
  if (buf->bytes_available >= 128)
    CVMX_PREFETCH128(buf->ptr);
}

static inline void
octeon_se_fastpath_packet_buffer_load_next(SeFastpathPacketBuffer buf,
                                           uint8_t for_reading)
{
  cvmx_buf_ptr_t next;






  CVMX_LOADUNA_INT64(next.u64, cvmx_phys_to_ptr(buf->curr.s.addr) - 8, 0);
  OCTEON_SE_ASSERT(next.u64);
  buf->ptr = cvmx_phys_to_ptr(next.s.addr);
  buf->bytes_available = next.s.size;
  buf->curr = next;

  /* Prefetch data pointer as it will be used soon. Prefetch the
     following cache line too. */
  if (for_reading)
    {
      CVMX_PREFETCH0(buf->ptr);
      if (buf->bytes_available >= 128)
        CVMX_PREFETCH128(buf->ptr);
    }
}


/*********************** Buffer reading and writing functions *************/

static inline uint64_t
octeon_se_fastpath_buffer_read_partial_word(SeFastpathPacketBuffer buf,
                                            uint8_t num_bytes)
{
   register uint64_t word = 0;
   register uint64_t i;
   uint8_t count = 0;

   OCTEON_SE_ASSERT(buf->bytes_available >= num_bytes);
   OCTEON_SE_ASSERT(buf->total_bytes >= num_bytes);
   OCTEON_SE_ASSERT(num_bytes < 8);

   if (num_bytes >= 4)
     {
       i = 0;
       OCTEON_SE_GET_32BIT(buf->ptr, i);
       word = i << 32;
       count = 4;
     }

   if (num_bytes - count >= 2)
     {
       i = 0;
       OCTEON_SE_GET_16BIT(&buf->ptr[count], i);
       word |= i << (6 - count) * 8;
       count += 2;
     }

   if (num_bytes - count >= 1)
     {
       i = 0;
       OCTEON_SE_GET_8BIT(&buf->ptr[count], i);
       word |= i << (7 - count) * 8;
       count++;
     }

   OCTEON_SE_ASSERT(count == num_bytes);

   buf->ptr += num_bytes;
   buf->bytes_available -= num_bytes;
   buf->total_bytes -= num_bytes;

   return word;
}

static inline uint64_t
octeon_se_fastpath_buffer_read_word_across_seg(SeFastpathPacketBuffer buf)
{
  uint8_t bytes_left = 0;
  uint64_t word = 0, word1;
  uint8_t bytes_read = 0, now;

  OCTEON_SE_ASSERT(buf->bytes_available < 8);
  if (buf->bytes_available != 0)
    {
      word = octeon_se_fastpath_buffer_read_partial_word(buf,
                                                         buf->bytes_available);
      bytes_read += buf->bytes_available;
      bytes_left = 8 - bytes_read;
    }
  OCTEON_SE_ASSERT(bytes_read < 8);

  OCTEON_SE_ASSERT(bytes_left <= 8);
  while (bytes_left != 0)
    {
      octeon_se_fastpath_packet_buffer_load_next(buf, 1);
      now = (buf->bytes_available > bytes_left ? bytes_left :
             buf->bytes_available);
      word1 = octeon_se_fastpath_buffer_read_partial_word(buf, now);
      word |= (word1 >> (bytes_read * 8));
      bytes_left -= now;
      bytes_read += now;
    }
  OCTEON_SE_ASSERT(bytes_left == 0);
  OCTEON_SE_ASSERT(bytes_read == 8);

  return word;
}

static inline uint64_t
octeon_se_fastpath_buffer_read_word(SeFastpathPacketBuffer buf)
{
  register uint64_t word;

  OCTEON_SE_ASSERT(buf->total_bytes >= 8);

  /* Enough buffer available? */
  if (cvmx_likely(buf->bytes_available >= 8))
    {
      buf->bytes_available -= 8;
      CVMX_LOADUNA_INT64(word, buf->ptr, 0);
      buf->ptr += 8;

      /* Check if need to prefetch next cache line.
         Magic value 0x78 checks if the 8 byte read went
         over the cache line. */
      if (cvmx_unlikely((((uint64_t) buf->ptr) & 0x78) == 0
                        && buf->bytes_available >= 128))
        CVMX_PREFETCH128(buf->ptr);
    }
  else
    {
      word = octeon_se_fastpath_buffer_read_word_across_seg(buf);
    }

  buf->total_bytes -= 8;
  return word;
}

static inline void
octeon_se_fastpath_buffer_write_partial_word(SeFastpathPacketBuffer buf,
                                             uint64_t word,
                                             uint8_t num_bytes)
{
  uint8_t count = 0;

  OCTEON_SE_ASSERT(buf->bytes_available >= num_bytes);
  OCTEON_SE_ASSERT(buf->total_bytes >= num_bytes);
  OCTEON_SE_ASSERT(num_bytes < 8);

  if (num_bytes >= 4)
    {
      OCTEON_SE_PUT_32BIT(buf->ptr, (word >> 32) & 0xffffffff);
      count = 4;
    }

  if (num_bytes - count >= 2)
    {
      OCTEON_SE_PUT_16BIT(&buf->ptr[count],
                          (word >> (6 - count) * 8) & 0xffff);
      count += 2;
    }

  if (num_bytes - count >= 1)
    {
      OCTEON_SE_PUT_8BIT(&buf->ptr[count],
                         (word >> (7 - count) * 8) & 0xff);
      count += 1;
    }

  OCTEON_SE_ASSERT(count == num_bytes);

  buf->ptr += num_bytes;
  buf->bytes_available -= num_bytes;
  buf->total_bytes -= num_bytes;
}

static inline void
octeon_se_fastpath_buffer_write_word_across_seg(SeFastpathPacketBuffer buf,
                                                uint64_t word)
{
  uint8_t bytes_left = 0;
  uint8_t bytes_written = 0, now;

  OCTEON_SE_ASSERT(buf->bytes_available < 8);
  if (buf->bytes_available != 0)
    {
      octeon_se_fastpath_buffer_write_partial_word(buf, word,
                                                   buf->bytes_available);
      bytes_written += buf->bytes_available;
      bytes_left = 8 - bytes_written;
    }
  OCTEON_SE_ASSERT(bytes_written < 8);

  OCTEON_SE_ASSERT(bytes_left <= 8);
  while (bytes_left)
    {
      /* Here the assumption is that space for write operation has
       * already been created. */
       octeon_se_fastpath_packet_buffer_load_next(buf, 0);
       now = (buf->bytes_available > bytes_left ? bytes_left :
              buf->bytes_available);
       octeon_se_fastpath_buffer_write_partial_word(buf, word
                                                    << (bytes_written * 8),
                                                    now);
       bytes_left -= now;
       bytes_written += now;
    }
  OCTEON_SE_ASSERT(bytes_left == 0);
  OCTEON_SE_ASSERT(bytes_written == 8);
}

static inline void
octeon_se_fastpath_buffer_write_word(SeFastpathPacketBuffer buf,
                                     uint64_t word)
{
  OCTEON_SE_ASSERT(buf->total_bytes >= 8);

  if (cvmx_likely(buf->bytes_available >= 8))
    {
      OCTEON_SE_ASSERT((((uint64_t) buf->ptr) % 8) == 0);
      OCTEON_SE_PUT_64BIT_ALIGNED(buf->ptr, word);

      buf->bytes_available -= 8;
      buf->ptr += 8;
    }
  else
    {




      octeon_se_fastpath_buffer_write_word_across_seg(buf, word);
    }

  buf->total_bytes -= 8;
}

static inline void
octeon_se_fastpath_buffer_write_double_word(SeFastpathPacketBuffer buf,
                                            uint64_t word0,
                                            uint64_t word1)
{
  OCTEON_SE_ASSERT(buf->total_bytes >= 16);

  if (cvmx_likely(buf->bytes_available >= 16))
    {
      OCTEON_SE_ASSERT((((uint64_t) buf->ptr) % 8) == 0);
      OCTEON_SE_PUT_64BIT_ALIGNED(buf->ptr, word0);
      buf->ptr += 8;
      OCTEON_SE_PUT_64BIT_ALIGNED(buf->ptr, word1);
      buf->ptr += 8;

      buf->bytes_available -= 16;
    }
  else
    {
      octeon_se_fastpath_buffer_write_word(buf, word0);
      octeon_se_fastpath_buffer_write_word(buf, word1);
    }

  buf->total_bytes -= 16;
}

static inline void
octeon_se_fastpath_buffer_copy(SeFastpathPacketBuffer dst,
                               SeFastpathPacketBuffer src,
                               size_t len)
{
  uint64_t word;

  OCTEON_SE_ASSERT(dst->total_bytes >= len);
  OCTEON_SE_ASSERT(src->total_bytes >= len);

  while (len >= 8)
    {
      word = octeon_se_fastpath_buffer_read_word(src);
      octeon_se_fastpath_buffer_write_word(dst, word);
      len -= 8;
    }

  if (cvmx_unlikely(len > 0))
    {
      word = octeon_se_fastpath_buffer_read_partial_word(src, len);
      octeon_se_fastpath_buffer_write_partial_word(dst, word, len);
    }
}


/** Returns a read-pointer to linear packet data. If the requested data is
    already in one packet segment, then this returns a pointer to packet
    data. Otherwise this copies data from multiple segments to the provided
    buffer and returns a pointer to that. Due to this the resulting pointer
    must be considered read-only. */
static inline uint8_t *
octeon_se_fastpath_buffer_pullup_read(SeFastpathPacketBuffer buf,
                                      size_t len,
                                      uint8_t *buffer)
{
  uint64_t word;
  register size_t i;
  uint8_t *ptr;

  OCTEON_SE_ASSERT(len <= buf->total_bytes);

  /* Requested amount of data is already linear. */
  if (cvmx_likely(buf->bytes_available >= len))
    {
      ptr = buf->ptr;

      buf->bytes_available -= len;
      buf->ptr += len;
      buf->total_bytes -= len;

      return ptr;
    }

  /* Need to copy data from multiple segments. */
  else
    {
      i = 0;
      while (len >= 8)
        {
          word = octeon_se_fastpath_buffer_read_word(buf);
          OCTEON_SE_PUT_64BIT_ALIGNED(buffer + i, word);
          len -= 8;
          i += 8;
        }
      if (cvmx_likely(len > 0))
        {
          word = octeon_se_fastpath_buffer_read_partial_word(buf, len);
          memcpy(buffer + i, (void *) &word, len);
        }

      return buffer;
    }
}


/** Copies `data' to buffer `buf'. Buffer may be unaligned. This will
    assert that `length' is not larger than the total available space
    in the segments of this buffer and that `length' is not larger
    than packet segment size. */
static inline void
octeon_se_fastpath_buffer_copy_in(SeFastpathPacketBuffer buf,
                                  uint64_t *data,
                                  size_t length)
{
  size_t len = length;
  size_t offset = 0;
  OCTEON_SE_ASSERT(len <= buf->total_bytes);

  /* Requested amount of space is not available in one segment. */
  if (cvmx_unlikely(buf->bytes_available < length))
    {
      len = buf->bytes_available;
      memcpy(buf->ptr, (uint8_t *) data, len);

      buf->total_bytes -= len;
      octeon_se_fastpath_packet_buffer_load_next(buf, 0);

      offset = len;
      len = length - offset;
    }

  OCTEON_SE_ASSERT(buf->bytes_available >= len);
  memcpy(buf->ptr, ((uint8_t *) data) + offset, len);

  buf->ptr += len;
  buf->bytes_available -= len;
  buf->total_bytes -= len;
}


/************************** Checksum calculation ****************************/

/** Update csum to reflect a change of 1 byte value at offset `ofs'. */
static inline uint16_t
octeon_se_fastpath_csum_update_byte(uint16_t csum,
                                    size_t ofs,
                                    uint8_t old_value,
                                    uint8_t new_value)
{
  uint32_t sum;

  sum = (~csum) & 0xffff;

  /* Update the sum. */
  if (ofs & 0x01)
    {
      sum -= old_value;
      sum = (sum & 0xffff) + (sum >> 16);
      sum &= 0xffff;
      sum += new_value;
    }
  else
    {
      sum -= ((uint32_t) old_value << 8) & 0xff00;
      sum = (sum & 0xffff) + (sum >> 16);
      sum &= 0xffff;
      sum += ((uint32_t) new_value << 8);
    }

  /*  Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}

/** Update csum to reflect a change of 2 byte value at offset `ofs'. */
static inline uint16_t
octeon_se_fastpath_csum_update_short(uint16_t cks, size_t ofs,
                                     uint16_t old_value,
                                     uint16_t new_value)
{
  uint32_t sum;

  /* Byte-swap values if odd offset. */
  if (ofs & 0x01)
    {
      old_value = (((old_value & 0xff) << 8) | (old_value >> 8));
      new_value = (((new_value & 0xff) << 8) | (new_value >> 8));
    }

  /* Update the sum. */
  sum = (~cks) & 0xffff;
  sum -= old_value;
  sum = (sum & 0xffff) + (sum >> 16);
  sum &= 0xffff;
  sum += new_value;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}

/** Calculate checksum over `buf' */
static inline uint16_t
octeon_se_fastpath_ip_cksum(unsigned char *buf, size_t bytes)
{
  register uint32_t sum; /* possibly swapped */
  uint32_t leftover_sum; /* in network byte order */
  register const uint16_t *uptr;
  const void *end;

  /* Align buf. */
  if (((unsigned long)(size_t)buf & 0x01) != 0 && bytes != 0)
    {
      /* In network byte order, the first byte is always MSB. */
      leftover_sum = buf[0] << 8;
      uptr = (uint16_t *)(buf + 1);
    }
  else
    {
      leftover_sum = 0;
      uptr = (uint16_t *)buf;
    }

  /* Loop over the main part of the packet. */
  end = (void *)(buf + bytes);
  sum = 0;
  while ((void *)(uptr + 10) <= end)
    {
      sum += uptr[0];
      sum += uptr[1];
      sum += uptr[2];
      sum += uptr[3];
      sum += uptr[4];
      sum += uptr[5];
      sum += uptr[6];
      sum += uptr[7];
      sum += uptr[8];
      sum += uptr[9];
      uptr += 10;
    }
  while ((void *)(uptr + 1) <= end)
    sum += *uptr++;

  /* Add left-over byte, if any. */
  if ((unsigned char *)uptr < buf + bytes)
    leftover_sum += (bytes & 0x01) ? (buf[bytes - 1] << 8) : buf[bytes - 1];

  /*  Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  /* The sum is already in host byte order, but check if it needs to be
     swapped because of bad alignment. */
  if (((unsigned long)buf & 0x01) != 0)
    sum = (((sum & 0xff) << 8) | (sum >> 8));

  /* Add any leftover bytes, and fold again. */
  sum += leftover_sum;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);

  return (~sum) & 0xffff;
}


/********************* Utility functions for AH ******************************/

static inline void
octeon_se_fastpath_mac_add_ah_header4(cvmx_buf_ptr_t packet_ptr,
                                      size_t ip_offset,
                                      void (*mac_update)
                                      (void *context,
                                       const unsigned char *buf,
                                       size_t len),
                                      void *mac_context,
                                      uint16_t len_delta)
{
  unsigned char copy[OCTEON_SE_FASTPATH_IP4_HDRLEN];
  uint16_t len;

  memcpy(copy, (uint8_t *)cvmx_phys_to_ptr(packet_ptr.s.addr) + ip_offset,
         sizeof(copy));

  OCTEON_SE_FASTPATH_IPH4_SET_TOS(copy, 0);
  OCTEON_SE_FASTPATH_IPH4_SET_FRAG(copy, 0);
  OCTEON_SE_FASTPATH_IPH4_SET_TTL(copy, 0);
  OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(copy, 0);

  if (len_delta)
    {
      OCTEON_SE_FASTPATH_IPH4_LEN(copy, len);
      OCTEON_SE_FASTPATH_IPH4_SET_LEN(copy, len + len_delta);
    }

  OCTEON_SE_DEBUG(9, "IPv4 header for AH MAC calculation, len %d:\n",
                  OCTEON_SE_FASTPATH_IP4_HDRLEN);
  OCTEON_SE_HEXDUMP(9, copy, OCTEON_SE_FASTPATH_IP4_HDRLEN);

  (*mac_update)(mac_context, copy, OCTEON_SE_FASTPATH_IP4_HDRLEN);

#if 0




  uint8_t *header;
  uint32_t zero = 0;
  uint16_t len;

  OCTEON_SE_ASSERT(packet_ptr.s.size >
                   (ip_offset + OCTEON_SE_FASTPATH_IP4_HDRLEN));

  header = cvmx_phys_to_ptr(packet_ptr.s.addr) + ip_offset;

  (*mac_update)(mac_context, header, 1); /* Version, IHL */
  (*mac_update)(mac_context, (uint8_t *) &zero, 1); /* ToS */
  OCTEON_SE_FASTPATH_IPH4_LEN(header, len); /* Total len */
  len += len_delta;
  (*mac_update)(mac_context, (uint8_t *) &len, 2);
  (*mac_update)(mac_context, header + OCTEON_SE_FASTPATH_IPH4_OFS_ID, 2);/*ID*/
  (*mac_update)(mac_context, (uint8_t *) &zero, 3); /* Fragment offset, TTL */
  /* Proto */
  (*mac_update)(mac_context, &ipproto, 1);
  (*mac_update)(mac_context, (uint8_t *) &zero, 2); /* Checksum */
  /* Src, Dst */
  (*mac_update)(mac_context, header + OCTEON_SE_FASTPATH_IPH4_OFS_SRC, 8);
#endif /* 0 */
}

static inline void
octeon_se_fastpath_mac_add_ah_header6(cvmx_buf_ptr_t packet_ptr,
                                      size_t ip_offset,
                                      void (*mac_update)
                                      (void *context,
                                       const unsigned char *buf,
                                       size_t len),
                                      void *mac_context,
                                      uint16_t len_delta)
{
  unsigned char buf[OCTEON_SE_FASTPATH_IP6_HDRLEN];

  memcpy(buf, (uint8_t *) cvmx_phys_to_ptr(packet_ptr.s.addr) + ip_offset,
         sizeof buf);

  /* Clear the mutable fields. */
  OCTEON_SE_FASTPATH_IPH6_SET_CLASS(buf, 0);
  OCTEON_SE_FASTPATH_IPH6_SET_FLOW(buf, 0);
  OCTEON_SE_FASTPATH_IPH6_SET_HL(buf, 0);

  (*mac_update)(mac_context, buf, OCTEON_SE_FASTPATH_IP6_HDRLEN);

#if 0




  uint8_t version;
  uint8_t *header;
  uint32_t zero = 0;
  uint16_t len;

  OCTEON_SE_ASSERT(packet_ptr.s.size >
                   (ip_offset + OCTEON_SE_FASTPATH_IP6_HDRLEN));

  header = cvmx_phys_to_ptr(packet_ptr.s.addr) + ip_offset;

  version = 0x60;
  (*mac_update)(mac_context, &version, 1); /* Version, class */
  (*mac_update)(mac_context, (uint8_t *) &zero, 3); /* Flow */
  OCTEON_SE_FASTPATH_IPH6_LEN(header, len);
  len += len_delta;
  (*mac_update)(mac_context, (uint8_t *) &len, 2); /* Payload len */
  (*mac_update)(mac_context, &ipproto, 1); /* Next header */
  (*mac_update)(mac_context, (uint8_t *) &zero, 1); /* Hoplimit */
  /* Src, dst */
  (*mac_update)(mac_context, header + OCTEON_SE_FASTPATH_IPH6_OFS_SRC, 32);
#endif /* 0 */
}

#endif /* OCTEON_SE_FASTPATH_INLINE_H */
