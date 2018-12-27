/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file implements the packet manipulation functions for the
   usermode interceptor.
*/

#include "sshincludes.h"
#include "sshrand.h"
#include "sshcondition.h"
#include "sshthreadedmbox.h"
#include "usermodeinterceptor.h"
#include "usermodeinterceptor_internal.h"
#include "sshfdstream.h"
#if 0



#include <sys/mman.h>
#endif

#define SSH_DEBUG_MODULE "SshUserModeInterceptor"

#ifndef SSH_USERMODE_INTERCEPTOR_ENABLE_TESTS

typedef struct SshInterceptorInternalPacketRec *SshInterceptorInternalPacket;

struct SshInterceptorInternalPacketRec
{
  SshInterceptorPacketStruct pp[1];

  SshInterceptorInternalPacket packet_next;
  SshInterceptorInternalPacket packet_prev;

  /* Pointer to interceptor. */
  SshInterceptor interceptor;

  /* Interceptor packet internal data. */
  unsigned char *internal_data;
  size_t internal_data_len;

  /* Offset and length of packet iteration. */
  size_t iteration_offset;
  size_t iteration_bytes;

  /* Total length of allocated data. */
  size_t data_size;

  /* Start offset of packet data. */
  size_t data_offset;

  /* Length of packet data. */
  size_t data_len;

  /* If FALSE then data points to memory that follows this structure
     and which was allocated with the memory for this structure. If
     TRUE then data points to externally allocated memory which must
     be freed explicitly. */
  Boolean dynamic_data;

  /* Pointer to packet data. */
  unsigned char *data;
};

/* Amount of extra headroom and tailroom to allocate for a packet. */
#define SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM 128
#define SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_TAILROOM 128

/* Available headroom and tailroom in a packet. */
#define PACKET_HEADROOM(ipp) ((ipp)->data_offset)
#define PACKET_TAILROOM(ipp) \
  ((ipp)->data_size - (ipp)->data_offset - (ipp)->data_len)

SshInterceptorPacket
ssh_interceptor_packet_alloc(SshInterceptor interceptor,
                             SshUInt32 flags,
                             SshInterceptorProtocol proto,
                             SshInterceptorIfnum ifnum_in,
                             SshInterceptorIfnum ifnum_out,
                             size_t total_len)
{
  SshInterceptorInternalPacket ipp;
  size_t data_size;
  SshInterceptorPacketMgr pktmgr =
    ssh_usermodeinterceptor_get_pktmgr(interceptor);

  data_size = (total_len
               + SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM
               + SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_TAILROOM);

  ipp = ssh_malloc(sizeof(*ipp) + data_size);
  if (ipp == NULL)
    return NULL;

  memset(ipp, 0, sizeof(*ipp));

  ipp->pp->flags = flags;
  ipp->pp->protocol = proto;
  ipp->pp->ifnum_in = ifnum_in;
  ipp->pp->ifnum_out = ifnum_out;

  ipp->interceptor = interceptor;

  ipp->data = (unsigned char *) ipp + sizeof(*ipp);
  ipp->data_size = data_size;
  ipp->data_offset = SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM;
  ipp->data_len = total_len;

  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);

  /* Update the count of allocated packets. */
  pktmgr->num_packets++;

  /* Put to packet list */
  ipp->packet_next = (SshInterceptorInternalPacket) pktmgr->packet_head;
  if (ipp->packet_next != NULL)
    ipp->packet_next->packet_prev = ipp;
  pktmgr->packet_head = ipp;

  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Allocated packet %p of size %d bytes (allocated %d bytes)",
             ipp, (int) total_len, (int) ipp->data_size));

  return ipp->pp;
}

SshInterceptorPacket
ssh_interceptor_packet_alloc_and_copy_ext_data(SshInterceptor interceptor,
                                               SshInterceptorPacket pp,
                                               size_t total_len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  SshInterceptorInternalPacket new_ipp;

  new_ipp = (SshInterceptorInternalPacket)
    ssh_interceptor_packet_alloc(interceptor,
                                 pp->flags & (SSH_PACKET_FROMPROTOCOL
                                              | SSH_PACKET_FROMADAPTER
                                              | SSH_PACKET_HWCKSUM),
                                 pp->protocol, pp->ifnum_in, pp->ifnum_out,
                                 total_len);
  if (new_ipp == NULL)
    goto fail;

  memcpy(ipp->pp, pp, sizeof(*pp));

  if (ipp->internal_data != NULL)
    {
      new_ipp->internal_data = ssh_memdup(ipp->internal_data,
                                          ipp->internal_data_len);
      if (new_ipp->internal_data == NULL)
        goto fail;
    }

  return new_ipp->pp;

 fail:
  /* According to interceptor API, this function never frees the original
     packet 'pp'. */
  if (new_ipp != NULL)
    ssh_interceptor_packet_free(new_ipp->pp);
  return NULL;
}

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
Boolean
ssh_interceptor_packet_export_internal_data(SshInterceptorPacket pp,
                                            unsigned char **data_ret,
                                            size_t *len_return)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(data_ret != NULL);
  SSH_ASSERT(len_return != NULL);

  if (ipp->internal_data == NULL)
    {
      *data_ret = NULL;
      *len_return = 0;
      return TRUE;
    }

  *data_ret = ssh_memdup(ipp->internal_data, ipp->internal_data_len);
  if (*data_ret == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  *len_return = ipp->internal_data_len;
  return TRUE;
}

void
ssh_interceptor_packet_discard_internal_data(unsigned char *data,
                                             size_t data_len)
{
  SshInterceptor interceptor = ssh_usermode_interceptor;

  if (data == NULL || data_len == 0)
    return;

  /* Send notification to the kernel that this internal data has been
     discarded. */
  ssh_usermode_interceptor_send_encode(interceptor,
               SSH_ENGINE_IPM_FORWARDER_INTERNAL_DATA_DISCARDED,
               SSH_FORMAT_UINT32_STR, data, data_len,
               SSH_FORMAT_END);
}

void
ssh_interceptor_packet_free_internal_data(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  if (ipp->internal_data != NULL)
    {
      ssh_free(ipp->internal_data);
      ipp->internal_data = NULL;
      ipp->internal_data_len = 0;
    }
}

Boolean
ssh_interceptor_packet_import_internal_data(SshInterceptorPacket pp,
                                            const unsigned char *data,
                                            size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(ipp->internal_data == NULL);
  SSH_ASSERT(ipp->internal_data_len == 0);

  if (len == 0)
    return TRUE;

  SSH_ASSERT(data != NULL);
  SSH_ASSERT(len > 0);

  ipp->internal_data = ssh_memdup(data, len);
  if (ipp->internal_data == NULL)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  ipp->internal_data_len = len;
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

void ssh_interceptor_packet_free(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  SshInterceptorPacketMgr pktmgr =
    ssh_usermodeinterceptor_get_pktmgr(ipp->interceptor);

  SSH_USERMODE_INTERCEPTOR_LOCK(ipp->interceptor);

  SSH_ASSERT(pktmgr->num_packets > 0);
  pktmgr->num_packets--;

  if (ipp->packet_prev != NULL)
    ipp->packet_prev->packet_next = ipp->packet_next;
  else
    pktmgr->packet_head = ipp->packet_next;

  if (ipp->packet_next != NULL)
    ipp->packet_next->packet_prev = ipp->packet_prev;

  SSH_USERMODE_INTERCEPTOR_UNLOCK(ipp->interceptor);

  if (ipp->internal_data != NULL)
    {
#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
      ssh_interceptor_packet_discard_internal_data(ipp->internal_data,
                                                   ipp->internal_data_len);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */
      ssh_free(ipp->internal_data);
    }

  if (ipp->dynamic_data == TRUE)
    ssh_free(ipp->data);
  ssh_free(ipp);
}

size_t ssh_interceptor_packet_len(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  return ipp->data_len;
}

unsigned char *ssh_interceptor_packet_pullup(SshInterceptorPacket pp,
                                             size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  SSH_ASSERT(bytes <= ipp->data_len);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);
  return ipp->data + ipp->data_offset;
}

unsigned char *
ssh_interceptor_packet_insert(SshInterceptorPacket pp,
                              size_t offset,
                              size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  size_t len;
  unsigned char *data;

  SSH_DEBUG(SSH_D_LOWOK, ("Inserting %d bytes at offset %d to packet %p",
                          (int) bytes, (int) offset, ipp));

  SSH_ASSERT(offset <= ipp->data_len);

  /* Insert at head or close to head and there is enough headroom.
     Note that this handles the special case where bytes is zero. */
  if (offset < ipp->data_len - offset && bytes <= PACKET_HEADROOM(ipp))
    {
      /* Move portion of data that is before the point of insertion. */
      if (offset > 0 && bytes > 0)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Moving %d bytes towards head",
                                  (int) offset));
          memmove(ipp->data + ipp->data_offset - bytes,
                  ipp->data + ipp->data_offset,
                  offset);
        }
      ipp->data_offset -= bytes;
      ipp->data_len += bytes;
      SSH_ASSERT(ipp->data_offset + ipp->data_len <= ipp->data_size);
      return ipp->data + ipp->data_offset + offset;
    }

  /* Insert close to tail and there is enough tailroom. Note that this
     handles the special case where bytes is zero. */
  if (bytes <= PACKET_TAILROOM(ipp))
    {
      /* Move portion of data that is after the data to be inserted. */
      if (offset < ipp->data_len && bytes > 0)
        {
          SSH_ASSERT(ipp->data_offset + offset + bytes <= ipp->data_size);
          SSH_DEBUG(SSH_D_LOWOK, ("Moving %d bytes towards tail",
                                  (int) (ipp->data_len - offset)));
          memmove(ipp->data + ipp->data_offset + offset + bytes,
                  ipp->data + ipp->data_offset + offset,
                  ipp->data_len - offset);
        }
      ipp->data_len += bytes;
      SSH_ASSERT(ipp->data_offset + ipp->data_len <= ipp->data_size);
      return ipp->data + ipp->data_offset + offset;
    }

  /* There is enough room in the packet. Note that here bytes is always
     greater than zero. */
  SSH_ASSERT(bytes > 0);
  if (bytes <= PACKET_HEADROOM(ipp) + PACKET_TAILROOM(ipp))
    {
      /* Move existing data to end of buffer to maximize headroom. */
      len = PACKET_TAILROOM(ipp);
      SSH_ASSERT(bytes > len);
      SSH_DEBUG(SSH_D_LOWOK, ("Moving %d bytes towards tail", (int) len));
      memmove(ipp->data + ipp->data_offset + offset + len,
              ipp->data + ipp->data_offset + offset,
              len);
      bytes -= len;
      ipp->data_len += len;

      /* Move rest of data towards head of packet. */
      SSH_ASSERT(bytes > 0);
      SSH_ASSERT(bytes <= PACKET_HEADROOM(ipp));
      SSH_DEBUG(SSH_D_LOWOK, ("Moving %d bytes towards head", (int) offset));
      memmove(ipp->data + ipp->data_offset - bytes,
              ipp->data + ipp->data_offset,
              offset);
      ipp->data_offset -= bytes;
      ipp->data_len += bytes;

      return ipp->data + ipp->data_offset + offset;
    }

  /* No space left, need to reallocate the whole packet data. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Reallocating packet data: size %d required %d",
                               (int) ipp->data_size,
                               (int) ipp->data_len + bytes));

  len = (ipp->data_len + bytes
         + SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM
         + SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_TAILROOM);

  data = ssh_malloc(len);
  if (data == NULL)
    {
      ssh_interceptor_packet_free(ipp->pp);
      return NULL;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Copying %d bytes to head", (int) offset));
  memcpy(data + SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM,
         ipp->data + ipp->data_offset,
         offset);

  SSH_DEBUG(SSH_D_LOWOK, ("Copying %d bytes to head",
                          (int) (ipp->data_len - offset)));
  memcpy(data + SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM
         + offset + bytes,
         ipp->data + ipp->data_offset + offset,
         ipp->data_len - offset);

  ipp->dynamic_data = TRUE;
  ipp->data = data;
  ipp->data_size = len;
  ipp->data_offset = SSH_USERMODE_INTERCEPTOR_PACKET_ALLOC_HEADROOM;
  ipp->data_len += bytes;

  return ipp->data + ipp->data_offset + offset;
}

Boolean ssh_interceptor_packet_delete(SshInterceptorPacket pp, size_t offset,
                                      size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_DEBUG(SSH_D_LOWOK, ("Deleting %d bytes at offset %d from packet %p",
                          (int) bytes, (int) offset, ipp));

  SSH_ASSERT(bytes <= ipp->data_len);
  SSH_ASSERT(offset <= ipp->data_len);
  SSH_ASSERT((offset + bytes) <= ipp->data_len);

  /* Special case. */
  if (bytes == 0)
    return TRUE;

  /* Delete from head. */
  if (offset == 0)
    {
      ipp->data_offset += bytes;
      ipp->data_len -= bytes;
      return TRUE;
    }

  /* Delete from tail. */
  if (offset + bytes == ipp->data_len)
    {
      ipp->data_len -= bytes;
      return TRUE;
    }

  /* Delete near head. */
  if (offset < ipp->data_len - offset - bytes)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Moving %d bytes towards tail", (int) offset));
      memmove(ipp->data + ipp->data_offset + bytes,
              ipp->data + ipp->data_offset,
              offset);
      ipp->data_offset += bytes;
      ipp->data_len -= bytes;
      return TRUE;
    }

  /* Delete near tail. */
  SSH_DEBUG(SSH_D_LOWOK, ("Moving %d bytes towards head",
                          (int) (ipp->data_len - offset - bytes)));
  memmove(ipp->data + ipp->data_offset + offset,
          ipp->data + ipp->data_offset + offset + bytes,
          ipp->data_len - offset - bytes);
  ipp->data_len -= bytes;

  return TRUE;
}

#ifdef INTERCEPTOR_HAS_PACKET_COPYIN
Boolean ssh_interceptor_packet_copyin(SshInterceptorPacket pp, size_t offset,
                                      const unsigned char *buf, size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_DEBUG(SSH_D_LOWOK, ("Copying %d bytes at offset %d to packet %p",
                          (int) len, (int) offset, ipp));

  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(len <= ipp->data_len);
  SSH_ASSERT(offset <= ipp->data_len);
  SSH_ASSERT((offset + len) <= ipp->data_len);
  memcpy(ipp->data + ipp->data_offset + offset, buf, len);
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPYIN */

#ifdef INTERCEPTOR_HAS_PACKET_COPYOUT
void ssh_interceptor_packet_copyout(SshInterceptorPacket pp, size_t offset,
                                    unsigned char *buf, size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_DEBUG(SSH_D_LOWOK, ("Copying %d bytes at offset %d from packet %p",
                          (int) len, (int) offset, ipp));

  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(len <= ipp->data_len);
  SSH_ASSERT(offset <= ipp->data_len);
  SSH_ASSERT((offset + len) <= ipp->data_len);
  memcpy(buf, ipp->data + ipp->data_offset + offset, len);
}
#endif /* INTERCEPTOR_HAS_PACKET_COPYOUT */

#ifdef INTERCEPTOR_HAS_PACKET_COPY
Boolean ssh_interceptor_packet_copy(SshInterceptorPacket source_pp,
                                    size_t source_offset,
                                    size_t bytes_to_copy,
                                    SshInterceptorPacket destination_pp,
                                    size_t destination_offset)
{
  SshInterceptorInternalPacket sipp = (SshInterceptorInternalPacket) source_pp;
  SshInterceptorInternalPacket dipp =
    (SshInterceptorInternalPacket) destination_pp;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Copying %d bytes from offset %d packet %p "
             "to offset %d packet %p",
             (int) bytes_to_copy, (int) source_offset, sipp,
             (int) destination_offset, dipp));

  SSH_ASSERT(source_offset <= sipp->data_len);
  SSH_ASSERT(bytes_to_copy <= sipp->data_len);
  SSH_ASSERT((source_offset + bytes_to_copy) <= sipp->data_len);

  SSH_ASSERT(destination_offset <= dipp->data_len);
  SSH_ASSERT(bytes_to_copy <= dipp->data_len);
  SSH_ASSERT((destination_offset + bytes_to_copy) <= dipp->data_len);

  memcpy(dipp->data + dipp->data_offset + destination_offset,
         sipp->data + sipp->data_offset + source_offset,
         bytes_to_copy);

  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPY */

void ssh_interceptor_packet_reset_iteration(SshInterceptorPacket pp,
                                            size_t offset,
                                            size_t total_bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(offset <= ipp->data_len);
  SSH_ASSERT(total_bytes <= ipp->data_len);
  SSH_ASSERT((offset + total_bytes) <= ipp->data_len);

  ipp->iteration_offset = offset;
  ipp->iteration_bytes = total_bytes;
}

Boolean ssh_interceptor_packet_next_iteration(SshInterceptorPacket pp,
                                              unsigned char **data_ret,
                                              size_t *len_return)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(data_ret != NULL);
  SSH_ASSERT(len_return != NULL);

  if (ipp->iteration_bytes == 0)
    {
      *data_ret = NULL;
      *len_return = 0;
      return FALSE;
    }

  *data_ret = ipp->data + ipp->data_offset + ipp->iteration_offset;
  *len_return = ipp->iteration_bytes;
  ipp->iteration_bytes = 0;
  return TRUE;
}

Boolean ssh_interceptor_packet_done_iteration(SshInterceptorPacket pp,
                                              unsigned char **data_ret,
                                              size_t *len_return)
{
  return TRUE;
}

unsigned char *
ssh_usermode_interceptor_packet_ptr(SshInterceptorPacket pp,
                                    size_t *packet_len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  *packet_len = ssh_interceptor_packet_len(pp);

  return ipp->data + ipp->data_offset;
}

#else /* SSH_USERMODE_INTERCEPTOR_ENABLE_TESTS */

/* 1 divided by the probability a packet manipulation function will fail
   if the SSH_USERMODE_FAIL_PACKET_OP fag is set. */
#define SSH_USERMODE_FAIL_PACKET_OP_PROB 100

/* 1 divided by the probability the packet allocation function will fail
   if the SSH_USERMODE_FAIL_ALLOC fag is set. */
#define SSH_USERMODE_FAIL_ALLOC_PROB   100

/* Data structure for a contiguous segment of a packet.  The internal packet
   representation is a linked list of these. */
typedef struct SshFakePPNodeRec
{
  /* Pointer to contiguous data.  This actually points to one byte past
     the start of allocated memory; the first allocated byte is set to 0xee
     to detect it being overwritten.  The allocate data is actually two bytes
     more than `len'; the last byte is also set to 0xee. */
  unsigned char *data;

  /* Number of bytes of data in this segment. */
  size_t len;

  /* Pointer to next segment. */
  struct SshFakePPNodeRec *next;
} *SshFakePPNode;

/* Internal data structure for a packet. */
typedef struct SshFakePPRec
{
  /* The public packet structure.  The public packet object is just this first
     field.  Several places in this code assume that this is the first
     field. */
  struct SshInterceptorPacketRec pp;

  /* Total length of the packet in bytes. */
  size_t len;

  /* Linked list of contiguous segments. */
  SshFakePPNode nodes;

  /* Pointer to the interceptor to which this packet belongs.  Note that
     this field should not be accessed by higher-level code. */
  SshInterceptor interceptor;

  /* Data for the iteration functions. */
  SshFakePPNode iter_next;
  size_t iter_offset;
  size_t iter_remaining; /* 0xffffffff means iteration not in progress */

  /* Packet internal data representation, internal can be NULL. */
  unsigned char *internal;
  size_t internal_len;

  /* Doubly linked list of all allocated packets. The head is
     interceptor->packet_head */
  struct SshFakePPRec * packet_next, * packet_prev;
} *SshFakePP;

size_t ssh_interceptor_free_node_list(SshFakePPNode node);

/* Internal function to build a linked list of contiguous segments
   with the given total length.  The lengths of the segments are
   random. */

SshFakePPNode ssh_interceptor_build_node_list(size_t total_len)
{
  unsigned char *data;
  size_t len, list_len;
  SshFakePPNode list = NULL;
  SshFakePPNode node = NULL;

  if (ssh_usermode_interceptor_flags & SSH_USERMODE_MANY_NODES &&
      total_len > 0)
    {
      list_len = 0;
      while (list_len < total_len)
        {
          /* Decide on the segment length.  Most segments are reasonably long,
             but occasionally we allocate very short segments.  Some segments
             may also end up being zero bytes. */
          if (ssh_rand() % 5 == 0)
            len = ssh_rand() % 10;
          else
            len = ssh_rand() % 1024;
          /* Note: len may also be zero. */

          /* Limit to remaining length to allocate. */
          if (len > total_len - list_len)
            len = total_len - list_len;

          /* Allocate the node.  Note that the byte before and after data
             is set to 0xee. */
          node = ssh_calloc(1, sizeof(*node));
          if (node == NULL)
            goto fail;

          data = (unsigned char *) ssh_malloc(len + 5);
          if (data == NULL)
            {
              ssh_free(node);
              goto fail;
            }

          node->data = data + 4;
          node->data[-1] = 0xee;
          node->data[len] = 0xee;
#ifndef WITH_PURIFY
          memset(node->data, 'A', len);
#endif /* WITH_PURIFY */
          node->len = len;
          node->next = list;
          list = node;
          list_len += len;
        }

      SSH_ASSERT(list_len == total_len);
    }
  else
    {
      node = ssh_calloc(1, sizeof(*node));
      if (node == NULL)
        goto fail;

      data = (unsigned char *) ssh_malloc(total_len + 5);
      if (data == NULL)
        {
          ssh_free(node);
          goto fail;
        }

      node->data = data + 4;
      node->data[-1] = 0xee;
      node->data[total_len] = 0xee;
#ifndef WITH_PURIFY
      memset(node->data, 'A', total_len);
#endif /* WITH_PURIFY */
      node->len = total_len;
      node->next = NULL;
      list = node;
    }

  return list;

 fail:
  ssh_interceptor_free_node_list(list);
  return NULL;
}

/* Allocates a packet of at least the given size.  Packets can only be
   allocated using this function (either internally by the interceptor
   or by other code by calling this function).  Typically, this takes
   a packet header from a free list, stores a pointer to a
   platform-specific packet object, and returns the packet header.
   This should be re-entrant and support concurrent operations if the
   IPSEC engine is re-entrant on the target platform.  Other functions
   in this interface should be re-entrant for different packet
   objects, but only one operation will be in progress at any given
   time for a single packet object.  This returns NULL if no more
   packets can be allocated.  On systems that support concurrency,
   this can be called from multiple threads concurrently.

   This sets initial values for the mandatory fields of the packet that always
   need to be initialized.  However, any of these fields can be modified
   later. */

SshInterceptorPacket ssh_interceptor_packet_alloc(SshInterceptor interceptor,
                                                 SshUInt32 flags,
                                                 SshInterceptorProtocol proto,
                                                 SshInterceptorIfnum ifnum_in,
                                                 SshInterceptorIfnum ifnum_out,
                                                 size_t total_len)
{
  SshFakePP pp;
  SshInterceptorPacketMgr pktmgr =
    ssh_usermodeinterceptor_get_pktmgr(interceptor);

  /* Fail at random if requested by the flags. */
  if ((ssh_usermode_interceptor_flags & SSH_USERMODE_FAIL_ALLOC) &&
      ssh_rand() % SSH_USERMODE_FAIL_ALLOC_PROB == 0)
    {
      SSH_DEBUG(1, ("Failing in alloc as a test"));
      return NULL;
    }

  SSH_ASSERT(flags & SSH_PACKET_FROMADAPTER ||
             flags & SSH_PACKET_FROMPROTOCOL);

  /* Allocate and initialize a packet object. */
  pp = ssh_calloc(1, sizeof(*pp));

  if (!pp)
    return NULL;

  pp->pp.flags = flags;
  pp->pp.ifnum_in = ifnum_in;
  pp->pp.ifnum_out = ifnum_out;
  pp->pp.protocol = proto;
  pp->interceptor = interceptor;
  pp->len = total_len;
  pp->nodes = ssh_interceptor_build_node_list(total_len);
  pp->iter_next = NULL;
  pp->iter_remaining = 0xffffffff;
  pp->internal = NULL;
  pp->internal_len = 0;

  if (pp->nodes == NULL)
    {
      SSH_DEBUG(1, ("Failing packet alloc"));
      ssh_free(pp);
      return NULL;
    }

  SSH_USERMODE_INTERCEPTOR_LOCK(interceptor);

  /* Update the count of allocated packets. */
  pktmgr->num_packets++;

  /* Put to packet list */
  pp->packet_next = pktmgr->packet_head;
  if (pp->packet_next != NULL)
    pp->packet_next->packet_prev = pp;
  pktmgr->packet_head = pp;

  SSH_USERMODE_INTERCEPTOR_UNLOCK(interceptor);

  return (SshInterceptorPacket)pp;
}

SshInterceptorPacket ssh_interceptor_packet_alloc_and_copy_ext_data(
                                                SshInterceptor interceptor,
                                                SshInterceptorPacket pp,
                                                size_t total_len)
{
  SshFakePP new_ipp;

  /* Actually, only the `total_length' argument is interesting.
     Everything else will be reset when the public data is copied. */
  new_ipp = (SshFakePP)
    ssh_interceptor_packet_alloc(interceptor,
                                 pp->flags
                                 & (SSH_PACKET_FROMPROTOCOL
                                    | SSH_PACKET_FROMADAPTER),
                                 pp->protocol,
                                 pp->ifnum_in,
                                 pp->ifnum_out,
                                 total_len);

  if (new_ipp == NULL)
    return NULL;

  /* Copy all public data from the source packet. */
  memcpy(new_ipp, pp, sizeof(*pp));

  /* Copy internal data representation */
  if (new_ipp->internal)
    {
      if (!(new_ipp->internal =
            ssh_memdup(new_ipp->internal, new_ipp->internal_len)))
        {
          ssh_interceptor_packet_free((SshInterceptorPacket) new_ipp);
          return NULL;
        }
    }

  return (SshInterceptorPacket) new_ipp;
}

unsigned char *
ssh_usermode_interceptor_packet_copy_to_buf(SshInterceptorPacket pp,
                                            size_t *packet_len)
{
  unsigned char *packetbuf;

  /* Get length, allocate buffer and copy packet to it. */
  *packet_len = ssh_interceptor_packet_len(pp);

  packetbuf = ssh_malloc(*packet_len);
  if (packetbuf != NULL)
    {
      ssh_interceptor_packet_copyout(pp, 0, packetbuf, *packet_len);
      return packetbuf;
    }
  else
    {
      *packet_len = 0;
      return NULL;
    }
}

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
Boolean ssh_interceptor_packet_export_internal_data(SshInterceptorPacket pp,
                                                    unsigned char **data_ret,
                                                    size_t *len_return)
{
  SshFakePP ipp;

  ipp = (SshFakePP)pp;

  if (!ipp->internal)
    {
      *data_ret = NULL;
      *len_return = 0;
      return TRUE;
    }

  *data_ret = ssh_memdup(ipp->internal, ipp->internal_len);

  if (!*data_ret)
    return FALSE;

  *len_return = ipp->internal_len;
  return TRUE;
}

void
ssh_interceptor_packet_discard_internal_data(unsigned char *data,
                                             size_t data_len)
{
  SshInterceptor interceptor = ssh_usermode_interceptor;

  if (data == NULL || data_len == 0)
    return;

  /* Send notification to the kernel that this internal data has been
     discarded. */
  ssh_usermode_interceptor_send_encode(interceptor,
               SSH_ENGINE_IPM_FORWARDER_INTERNAL_DATA_DISCARDED,
               SSH_FORMAT_UINT32_STR, data, data_len,
               SSH_FORMAT_END);
}

void
ssh_interceptor_packet_free_internal_data(SshInterceptorPacket pp)
{
  SshFakePP ipp;

  ipp = (SshFakePP)pp;

  if (ipp->internal != NULL)
    {
      ssh_free(ipp->internal);
      ipp->internal = NULL;
      ipp->internal_len = 0;
    }
}

Boolean
ssh_interceptor_packet_import_internal_data(SshInterceptorPacket pp,
                                            const unsigned char *data,
                                            size_t len)
{
  SshFakePP ipp;

  ipp = (SshFakePP)pp;

  SSH_ASSERT(!ipp->internal);

  ipp->internal = ssh_memdup(data, len);

  if (!ipp->internal)
    {
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  ipp->internal_len = len;
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

/* An internal function that frees the list of contiguous segments. */

size_t ssh_interceptor_free_node_list(SshFakePPNode node)
{
  SshFakePPNode next_node;
  size_t len;

  len = 0;
  for (; node; node = next_node)
    {
      next_node = node->next;
      len += node->len;
      memset(node->data, 'F', node->len);
      SSH_ASSERT(node->data[-1] == 0xee);
      SSH_ASSERT(node->data[node->len] == 0xee);
      ssh_free(node->data - 4); /* First byte was used as special marker. */
      memset(node, 'F', sizeof(*node));
      ssh_free(node);
    }
  return len;
}

/* Frees the packet.  All packets allocated by
   ssh_interceptor_packet_alloc must eventually be freed using this
   function by either calling this explicitly or by passing the packet
   to the interceptor send function.  Typically, this calls a suitable
   function to free/release the platform-specific packet object, and
   puts the packet header on a free list.  This function should be
   re-entrant, so if a free list is used, it should be protected by a
   lock in systems that implement concurrency in the IPSEC Engine.
   Multiple threads may call this function concurrently for different
   packets, but not for the same packet. */

void ssh_interceptor_packet_free(SshInterceptorPacket pp)
{
  SshFakePP ipp = (SshFakePP)pp;
  size_t len;
  SshInterceptorPacketMgr pktmgr =
    ssh_usermodeinterceptor_get_pktmgr(ipp->interceptor);

  SSH_USERMODE_INTERCEPTOR_LOCK(ipp->interceptor);

  SSH_ASSERT(pktmgr->num_packets > 0);
  pktmgr->num_packets--;

  if (ipp->packet_prev != NULL)
    ipp->packet_prev->packet_next = ipp->packet_next;
  else
    pktmgr->packet_head = ipp->packet_next;

  if (ipp->packet_next != NULL)
    ipp->packet_next->packet_prev = ipp->packet_prev;

  SSH_USERMODE_INTERCEPTOR_UNLOCK(ipp->interceptor);

  if (ipp->nodes)
    {
      len = ssh_interceptor_free_node_list(ipp->nodes);
      SSH_ASSERT(len == ipp->len);
    }

  if (ipp->internal != NULL)
    {
#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
      ssh_interceptor_packet_discard_internal_data(ipp->internal,
                                                   ipp->internal_len);
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */
      ssh_free(ipp->internal);
    }

  ssh_free(ipp);
}

/* Returns the total length of the packet in bytes.  Multiple threads may
   call this function concurrently, but not for the same packet. */

size_t ssh_interceptor_packet_len(SshInterceptorPacket pp)
{
  SshFakePP ipp = (SshFakePP)pp;
  return ipp->len;
}

/* Makes sure the first `bytes' bytes of the packet are in a
   contiguous section of the buffer.  Returns a pointer to the first
   byte of the packet, or NULL (and frees pp) if an error occurs.  It
   is a fatal error to call this for `bytes' greater than 80 or the
   length of the packet.  Multiple threads may call this function
   concurrently, but not for the same packet. */

unsigned char *ssh_interceptor_packet_pullup(SshInterceptorPacket pp,
                                             size_t bytes)
{
  SshFakePP ipp = (SshFakePP)pp;
  SshFakePPNode node;
  unsigned char *cp, *data;

  /* Sanity checks. */
  SSH_ASSERT(bytes <= ipp->len);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);
  SSH_ASSERT(bytes > 0);
  SSH_ASSERT(ipp->nodes != NULL);

  /* If requested by flags, fail at random. */
  if ((ssh_usermode_interceptor_flags & SSH_USERMODE_FAIL_PACKET_OP) &&
      ssh_rand() % SSH_USERMODE_FAIL_PACKET_OP_PROB == 0)
    {
      SSH_DEBUG(1, ("Failing in pullup as a test"));
      ssh_interceptor_packet_free(pp);
      return NULL;
    }

  /* At every pullup, fully reshuffle the entire packet, if that is
    requested.  This increases the probability of incorrect
     assumptions about pointer remaining valid across pullups being
     detected early.  Copy packet data into linear memory. */

  if ((ssh_usermode_interceptor_flags & SSH_USERMODE_SHUFFLE_PULLUP))
    {
      cp = ssh_malloc(ipp->len);
      if (cp == NULL)
        goto fail;

      ssh_interceptor_packet_copyout(pp, 0, cp, ipp->len);

      /* Allocate a node for the first segment. */
      node = ssh_calloc(1, sizeof(*node));
      if (node == NULL)
        {
          ssh_free(cp);
          goto fail;
        }

      data = (unsigned char *) ssh_malloc(bytes + 5);
      if (data == NULL)
        {
          ssh_free(cp);
          ssh_free(node);
          goto fail;
        }

      node->data = data + 4;
      node->data[-1] = 0xee;
      node->data[bytes] = 0xee;
      node->len = bytes;

      /* Allocate rest of the packet. */
      if (ipp->len - bytes > 0)
        {
          node->next = ssh_interceptor_build_node_list(ipp->len - bytes);
          if (node->next == NULL)
            {
              ssh_interceptor_free_node_list(node);
              ssh_free(cp);
              goto fail;
            }
        }
      else
        node->next = NULL;

      /* Free old packet contents, and replace by the new list. */
      ssh_interceptor_free_node_list(ipp->nodes);
      ipp->nodes = node;

      /* Copy old data into the packet. */
      if (!ssh_interceptor_packet_copyin(pp, 0, cp, ipp->len))
        {
          ssh_free(cp);
          pp = NULL;
          goto fail;
        }

      ssh_free(cp);
    }
  else if (ipp->nodes->len < bytes)
    {
      /* Combine two first nodes until enough has been pulled up */
      while (ipp->nodes->len < bytes)
        {
          size_t len;

          SSH_ASSERT(ipp->nodes->next != NULL);

          len = ipp->nodes->len + ipp->nodes->next->len;

          node = ssh_calloc(1, sizeof(*node));
          if (node == NULL)
            goto fail;

          data = (unsigned char *) ssh_malloc(len + 5);
          if (data == NULL)
            {
              ssh_free(node);
              goto fail;
            }

          node->data = data + 4;
          node->data[-1] = 0xee;
          node->data[len] = 0xee;
          node->len = len;

          /* Now copy data there */
          memcpy(node->data, ipp->nodes->data, ipp->nodes->len);
          memcpy(node->data + ipp->nodes->len, ipp->nodes->next->data,
                 ipp->nodes->next->len);

          /* Free the two first nodes and replace them with the new one */
          node->next = ipp->nodes->next->next;
          ipp->nodes->next->next = NULL;
          ssh_interceptor_free_node_list(ipp->nodes);
          ipp->nodes = node;
        }
    }

  SSH_ASSERT(ipp->nodes->len >= bytes);

  /* Invalidate any iteration that might be in progress. */
  ipp->iter_remaining = 0xffffffff;




  SSH_ASSERT(((unsigned long) ipp->nodes->data & 3) == 0);

  return ipp->nodes->data;

 fail:
  if (pp)
    ssh_interceptor_packet_free(pp);
  return NULL;
}

/* Inserts data at the given offset in the packet.  Returns a pointer
   to the first inserted byte, or NULL (and frees pp) if an error
   occurs.  The space for the data is guaranteed to be contiguous,
   starting at the returned address.  At most 80 bytes can be
   inserted at a time.  Implementation note: most of the time, the
   insertion will take place near the start of the packet, and only
   twenty or so bytes are typically inserted.  Multiple threads may
   call this function concurrently, but not for the same packet. */

unsigned char *ssh_interceptor_packet_insert(SshInterceptorPacket pp,
                                             size_t offset,
                                             size_t bytes)
{
  SshFakePP ipp = (SshFakePP)pp;
  unsigned char *cp, *data;
  size_t len;
  SshFakePPNode node;
  SshFakePPNode *nodep = NULL;

  SSH_ASSERT(bytes <= 80);
  SSH_ASSERT(offset <= ipp->len);

  /* If requested by flags, fail at random. */
  if ((ssh_usermode_interceptor_flags & SSH_USERMODE_FAIL_PACKET_OP) &&
      ssh_rand() % SSH_USERMODE_FAIL_PACKET_OP_PROB == 0)
    {
      SSH_DEBUG(1, ("Failing in packet insert as a test"));
      ssh_interceptor_packet_free(pp);
      return NULL;
    }

  /* Save a linear copy of the packet data and insert new stuff. */
  cp = ssh_malloc(ipp->len + bytes);
  if (cp == NULL)
    goto fail;

  ssh_interceptor_packet_copyout(pp, 0, cp, ipp->len);
  memmove(cp + offset + bytes, cp + offset, ipp->len - offset);
#ifndef WITH_PURIFY
  memset(cp + offset, 'I', bytes);
#endif /* WITH_PURIFY */

  /* Free the old node list. */
  len = ssh_interceptor_free_node_list(ipp->nodes);
  SSH_ASSERT(len == ipp->len);

  /* Build a new node list that has a node the size of the inserted data
     in the middle. */
  ipp->nodes = ssh_interceptor_build_node_list(offset);
  if (ipp->nodes == NULL)
    goto fail;

  for (nodep = &ipp->nodes; *nodep; nodep = &(*nodep)->next)
    ;
  *nodep = node = ssh_calloc(1, sizeof(*node));
  if (node == NULL)
    goto fail;

  data = (unsigned char *) ssh_malloc(bytes + 5);
  if (data == NULL)
    goto fail;

  node->data = data + 4;
  node->data[-1] = 0xee;
  node->data[bytes] = 0xee;
  node->len = bytes;

  if (ipp->len - offset > 0)
    {
      node->next = ssh_interceptor_build_node_list(ipp->len - offset);
      if (node->next == NULL)
        goto fail;
    }

  /* Copy data into the new node list. */
  ipp->len += bytes;
  if (!ssh_interceptor_packet_copyin(pp, 0, cp, ipp->len))
    {
      pp = NULL;
      goto fail;
    }
  ssh_free(cp);

  /* Invalidate any iteration that might be in progress. */
  ipp->iter_remaining = 0xffffffff;

  return node->data;

 fail:
  if (cp)
    ssh_free(cp);
  if (pp)
    ssh_interceptor_packet_free(pp);
  return NULL;
}

/* Deletes data from the given offset in the packet.  It is a fatal error
   to delete more bytes than there are counting from that offset.
   Multiple threads may call this function concurrently, but not for the
   same packet. */

Boolean ssh_interceptor_packet_delete(SshInterceptorPacket pp, size_t offset,
                                      size_t bytes)
{
  SshFakePP ipp = (SshFakePP)pp;
  unsigned char *cp;
  size_t len;

  SSH_ASSERT(bytes <= ipp->len);
  SSH_ASSERT(bytes + offset <= ipp->len);
  SSH_ASSERT(offset <= ipp->len);

  /* If requested by flags, fail at random. */
  if ((ssh_usermode_interceptor_flags & SSH_USERMODE_FAIL_PACKET_OP) &&
      ssh_rand() % SSH_USERMODE_FAIL_PACKET_OP_PROB == 0)
    {
      SSH_DEBUG(1, ("Failing in packet delete as a test"));
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  /* Save a copy of the packet data and insert new stuff. */
  cp = ssh_malloc(ipp->len + bytes);
  if (cp == NULL)
    goto fail;

  ssh_interceptor_packet_copyout(pp, 0, cp, ipp->len);
  memmove(cp + offset, cp + offset + bytes, ipp->len - offset);

  /* Free the old node list. */
  len = ssh_interceptor_free_node_list(ipp->nodes);
  SSH_ASSERT(len == ipp->len);

  /* Build a new node list that has a node the size of the inserted data
     in the middle. */
  if (ipp->len - bytes > 0)
    {
      ipp->nodes = ssh_interceptor_build_node_list(ipp->len - bytes);
      if (ipp->nodes == NULL)
        goto fail;
    }

  ipp->len -= bytes;

  /* Copy data into the new node list. */
  if (!ssh_interceptor_packet_copyin(pp, 0, cp, ipp->len))
    {
      pp = NULL;
      goto fail;
    }
  ssh_free(cp);

  /* Invalidate any iteration that might be in progress. */
  ipp->iter_remaining = 0xffffffff;
  return TRUE;

 fail:
  if (cp)
    ssh_free(cp);
  if (pp)
    ssh_interceptor_packet_free(pp);
  return FALSE;
}

#ifdef INTERCEPTOR_HAS_PACKET_COPYIN
/* Copies data into the packet.  Space for the new data must already have
   been allocated.  It is a fatal error to attempt to copy beyond the
   allocated packet.  Multiple threads may call this function concurrently,
   but not for the same packet. */

Boolean ssh_interceptor_packet_copyin(SshInterceptorPacket pp, size_t offset,
                                      const unsigned char *buf, size_t len)
{
  SshFakePP ipp = (SshFakePP)pp;
  unsigned char *ucp;
  size_t segment_len, copied_len;

  /* Sanity checks. */
  SSH_ASSERT(offset <= ipp->len && len <= ipp->len &&
             offset + len <= ipp->len);

  /* If requested by flags, fail at random. */
  if ((ssh_usermode_interceptor_flags & SSH_USERMODE_FAIL_PACKET_OP) &&
      ssh_rand() % SSH_USERMODE_FAIL_PACKET_OP_PROB == 0)
    {
      SSH_DEBUG(1, ("Failing in packet copyin as a test"));
      ssh_interceptor_packet_free(pp);
      return FALSE;
    }

  /* Loop over all segments to copy data. */
  copied_len = 0;
  ssh_interceptor_packet_reset_iteration(pp, offset, len);
  while (ssh_interceptor_packet_next_iteration(pp, &ucp, &segment_len))
    {
      /* Sanity checks. */
      copied_len += segment_len;
      SSH_ASSERT(copied_len <= len);

      /* Copy data into this segment. */
      memcpy(ucp, buf, segment_len);
      buf += segment_len;
      ssh_interceptor_packet_done_iteration(pp, &ucp, &segment_len);
    }
  if (ucp != NULL)
    return FALSE;
  SSH_ASSERT(copied_len == len);

  /* Invalidate any iteration that might be in progress. */
  ipp->iter_remaining = 0xffffffff;
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPYIN */

#ifdef INTERCEPTOR_HAS_PACKET_COPYOUT
/* Copies data out from the packet.  Space for the new data must
   already have been allocated.  It is a fatal error to attempt to
   copy beyond the allocated packet. Multiple threads may call this
   function concurrently, but not for the same packet. */

void ssh_interceptor_packet_copyout(SshInterceptorPacket pp, size_t offset,
                                    unsigned char *buf, size_t len)
{
  SshFakePP ipp = (SshFakePP)pp;
  const unsigned char *ucp;
  size_t segment_len;

  /* Sanity checks. */
  SSH_ASSERT(offset <= ipp->len && len <= ipp->len &&
             offset + len <= ipp->len);

  /* Trivial special case that makes insert into empty packets work. */
  if (!len) return;

  /* Loop over all segments to copy data. */
  ssh_interceptor_packet_reset_iteration(pp, offset, len);
  while (ssh_interceptor_packet_next_iteration_read(pp, &ucp, &segment_len))
    {
      memcpy(buf, ucp, segment_len);
      buf += segment_len;
      ssh_interceptor_packet_done_iteration_read(pp, &ucp, &segment_len);
    }
  SSH_ASSERT(ucp == NULL);      /* next_iteration_read cannot fail. */

  /* Invalidate any iteration that might be in progress. */
  ipp->iter_remaining = 0xffffffff;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPYOUT */

#ifdef INTERCEPTOR_HAS_PACKET_COPY
/* Copy data from one packet to another. Start from the `source_offset' and
   copy `bytes_to_copy' bytes to `destination_offset' in the destination
   packet. If the destination packet cannot be written then return FALSE, and
   the destination packet has been freed by this function. The source packet is
   not freed even in case of error. If data copying was successfull then return
   TRUE.

   This function can also be implemented so that it will simply increment the
   reference counts in the source packet and share the actual data without
   copying it at all. There is a generic version of this function inside the
   engine, in case interceptor does not want to implement this. If interceptor
   implements this function it must define INTERCEPTOR_HAS_PACKET_COPY. */
Boolean ssh_interceptor_packet_copy(SshInterceptorPacket source_pp,
                                    size_t source_offset,
                                    size_t bytes_to_copy,
                                    SshInterceptorPacket destination_pp,
                                    size_t destination_offset)
{
  size_t segoff, seglen;
  const unsigned char *seg;

  /* Copy `bytes_to_copy' bytes from the original packet. */
  segoff = 0;
  ssh_interceptor_packet_reset_iteration(source_pp, source_offset,
                                         bytes_to_copy);
  while (ssh_interceptor_packet_next_iteration_read(source_pp, &seg, &seglen))
    {
      if (!ssh_interceptor_packet_copyin(destination_pp,
                                         destination_offset + segoff,
                                         seg, seglen))
        {
          SSH_DEBUG(SSH_D_ERROR, ("Could not copy packet"));
          ssh_interceptor_packet_done_iteration_read(source_pp,
                                                     &seg,
                                                     &seglen);
          return FALSE;
        }
      segoff += seglen;
      ssh_interceptor_packet_done_iteration_read(source_pp,
                                                 &seg,
                                                 &seglen);
    }
  SSH_ASSERT(seg == NULL);      /* next_iteration_read cannot fail. */
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPY */

/* These functions iterate over contiguous segments of the packet,
   starting from offset `offset', continuing for a total of
   `total_bytes' bytes.  It is guaranteed that `*len_return' will
   not be set to a value that would exceed `len' minus sum of previous
   lengths.  Also, previous pointers are guaranteed to stay valid if
   no other ssh_interceptor_packet_* functions are used during
   iteration for the same packet.  At each iteration, these functions
   return a pointer to the first byte of the contiguous segment inside
   the `*data_ret', and set `*len_return' to the number of bytes available at
   that address.

   The ssh_interceptor_packet_reset_iteration function will just reset the
   internal pointers to new offset and number of bytes without changing
   anything else. After that you need to call the
   ssh_interceptor_packet_next_iteration function to get the first block.
   After each call to ssh_interceptor_packet_next_iteration,
   one needs to call ssh_interceptor_packet_done_iteration.

   The loop ends when the iteration function returns FALSE, and then after the
   loop you need to check the value of the `*data_ret'. If it is NULL then the
   whole packet was processed and the operation was ended because there was no
   more data available. If it is not NULL then the there was an error and the
   underlaying packet buffer has already been freed and all the pointers
   pointing to that memory area (returned by previous calls to this function)
   are invalidated.

   These functions are used as follows:

     ssh_interceptor_packet_reset_iteration(pp, offset, total_bytes);
     while (ssh_interceptor_packet_next_iteration(pp, &ptr, &len))
       {
         code that uses ptr and len;
         ssh_interceptor_packet_done_iteration(pp, &ptr, &len);
       }
     if (ptr != NULL)
       {
         code that will clean up the state and return. Note that the pp has
         already been freed at this point.
         return ENOBUF;
       }

   Only one operation can be in progress on a single packet concurrently,
   but multiple iterations may be executed simultaneously for different
   packet buffers.  Thus, the implementation must keep any state in the
   packet object, not in global variables.

   Multiple threads may call these functions concurrently,
   but not for the same packet.

   There is two different versions of next_iteration function, one to get data
   that you can modify (ssh_interceptor_packet_next_iteration) and one to get
   read only version of the data (ssh_interceptor_packet_next_iteration_read).
   The read only version should be used in all cases where the packet is not
   modifed, so interceptor can optimize extra copying of the packets away.
   */
void ssh_interceptor_packet_reset_iteration(SshInterceptorPacket pp,
                                            size_t offset,
                                            size_t len)
{
  SshFakePP ipp = (SshFakePP)pp;
  SshFakePPNode node;

  /* Sanity checks. */
  SSH_ASSERT(offset <= ipp->len && len <= ipp->len &&
             offset + len <= ipp->len);

  /* Loop until we find the appropriate start node. */
  node = ipp->nodes;
  while (offset >= node->len)
    {
      offset -= node->len;
      node = node->next;
    }

  /* Initialize data for iteration. */
  ipp->iter_next = node;
  ipp->iter_offset = offset;
  ipp->iter_remaining = len;

  return;
}

Boolean ssh_interceptor_packet_next_iteration(SshInterceptorPacket pp,
                                              unsigned char **data_ret,
                                              size_t *len_return)
{
  SshFakePP ipp = (SshFakePP)pp;
  SshFakePPNode node;

  /* Sanity check that iteration is in progress. */
  SSH_ASSERT(ipp->iter_remaining != 0xffffffff);

  /* Check if there is still data left to iterate. */
  node = ipp->iter_next;
  if (node == NULL || ipp->iter_remaining == 0)
    {
      (*data_ret) = NULL;
      return FALSE;
    }

  /* Return the next segment.  Note that the length of the last segment is
     truncated to not exceed the number of bytes to be iterated. */
  (*data_ret) = node->data + ipp->iter_offset;
  if (ipp->iter_remaining < node->len - ipp->iter_offset)
    *len_return = ipp->iter_remaining;
  else
    *len_return = node->len - ipp->iter_offset;
  ipp->iter_next = node->next;
  ipp->iter_offset = 0;
  ipp->iter_remaining -= *len_return;

  return TRUE;
}

Boolean ssh_interceptor_packet_done_iteration(SshInterceptorPacket pp,
                                              unsigned char **data_ret,
                                              size_t *len_return)
{
  return TRUE;
}

#endif /* SSH_USERMODE_INTERCEPTOR_ENABLE_TESTS */

/* The ssh_interceptor_packet_cache() takes a reference to the packet
   SshInterceptorPacket that is valid over ssh_interceptor_packet_free() and
   ssh_interceptor_send(). The data in the publically accessed fields in
   SshInterceptorPacket is a copy of 'pp' at the time of the call. The
   actual contents of the packet may change after the call, as they
   may be referenced from the actual packet. It is upto the caller to
   provide concurrency control or protection for that.

   The function returns NULL if it fails. */
SshInterceptorPacket
ssh_interceptor_packet_cache(SshInterceptor interceptor,
                             SshInterceptorPacket pp)
{
  SshUInt32 flags;
  SshInterceptorPacket dst;
  size_t len = ssh_interceptor_packet_len(pp);

  flags = pp->flags & (SSH_PACKET_FROMPROTOCOL | SSH_PACKET_FROMADAPTER);
  dst = ssh_interceptor_packet_alloc(interceptor, flags,
                                     pp->protocol,
                                     pp->ifnum_in,
                                     pp->ifnum_out,
                                     len);
  if (dst == NULL)
    return NULL;

  dst->flags = pp->flags;

  if (ssh_interceptor_packet_copy(pp, 0, len, dst, 0) == FALSE)
    {
      ssh_interceptor_packet_free(dst);
      return NULL;
    }
  return dst;
}

#ifndef NEED_PACKET_READONLY_DEFINES
const unsigned char *
ssh_interceptor_packet_pullup_read(SshInterceptorPacket pp,
                                   size_t bytes)
{
  return ssh_interceptor_packet_pullup(pp, bytes);
}

Boolean
ssh_interceptor_packet_next_iteration_read(SshInterceptorPacket pp,
                                           const unsigned char **data_ret,
                                           size_t *len_return)
{
  return ssh_interceptor_packet_next_iteration(pp, (unsigned char **) data_ret,
                                               len_return);
}

Boolean
ssh_interceptor_packet_done_iteration_read(SshInterceptorPacket pp,
                                           const unsigned char **data_ret,
                                           size_t *len_return)
{
  return TRUE;
}
#endif /* not  NEED_PACKET_READONLY_DEFINES */
