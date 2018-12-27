/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   linux_packet_internal.h
*/

#ifndef LINUX_PACKET_INTERNAL_H
#define LINUX_PACKET_INTERNAL_H

#include "linux/skbuff.h"
#include "kernel_includes.h"
#include "linux_versions.h"

/* Internal packet structure, used to encapsulate the kernel structure
   for the generic packet processing engine. */
typedef struct SshInterceptorInternalPacketRec *SshInterceptorInternalPacket;

struct SshInterceptorInternalPacketRec
{
  /* Generic packet structure */
  struct SshInterceptorPacketRec packet;

  /* Backpointer to interceptor */
  SshInterceptor interceptor;

  /* Kernel skb structure. */
  struct sk_buff *skb;

  /* The processor from which this packet was allocated from the freelist */
  unsigned int cpu;

  /* Packet segment iteration counters. */
  size_t iteration_offset;
  size_t iteration_bytes;
  unsigned char *iteration_mapped_fragment;

  /* These are SshUInt32's for export/import */
  SshUInt32 original_ifnum;

#ifndef SSH_IPSEC_SEND_IS_SYNC
  /* Media header length, needed for recursion elimination. */
  SshUInt32 media_header_len;
#endif /* !SSH_IPSEC_SEND_IS_SYNC */

#ifdef DEBUG_LIGHT
  /* List status flags, used for asserting that the packet is not put to
     multiple lists. */
#define SSH_INTERCEPTOR_PACKET_IN_FREELIST         0x01
#define SSH_INTERCEPTOR_PACKET_IN_ASYNC_SEND_QUEUE 0x02
#define SSH_INTERCEPTOR_PACKET_IN_SEND_QUEUE       0x04
#define SSH_INTERCEPTOR_PACKET_IN_ENGINE_QUEUE     0x08
  SshUInt8 list_status;
#endif /* DEBUG_LIGHT */

  /* Buffer for pullup read. */
  unsigned char pullup_buffer[SSH_INTERCEPTOR_MAX_PULLUP_LEN];
};

/* Typical needed tailroom: ESP trailer (worstcase ~27B).
   Typical needed headroom: media, IPIP, ESP (~60B for IPv4, ~80B for IPv6)
   Worstcase headroom:      media, UDP(8), NAT-T(12), IPIP(~20), ESP(22)  */

/* The amount of headroom reserved for network interface processing. The
   interceptor ensures that all packets passed to NIC driver will have atleast
   this much headroom. */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/* With media level interceptor the SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM
   includes the media header length. Let us use up the full skb if necessary.
   This is important for reducing overhead in the forwarding case. */
#define SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM 0
#else
/* Ensure that packet has always enough headroom for an aligned
   ethernet header. */
#define SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM 16
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */

#ifdef SSH_IPSEC_HWACCEL_CONFIGURED
/* Amount of head- and tailroom to reserve when allocating or duplicating
   a packet. These values are optimised for IPsec processing. */
#define SSH_INTERCEPTOR_PACKET_HEAD_ROOM \
  (SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM+128)
#define SSH_INTERCEPTOR_PACKET_TAIL_ROOM (128)

/* Some hw accelerators require DMA memory. */
#define SSH_LINUX_ALLOC_SKB_GFP_MASK   (GFP_ATOMIC)

#else /* !SSH_IPSEC_HWACCEL_CONFIGURED */

/* Amount of head- and tailroom to reserve when allocating or duplicating
   a packet. These values are optimised for IPsec processing. */
#define SSH_INTERCEPTOR_PACKET_HEAD_ROOM      (80)
#define SSH_INTERCEPTOR_PACKET_TAIL_ROOM      (30)

#define SSH_LINUX_ALLOC_SKB_GFP_MASK (GFP_ATOMIC)
#endif /* SSH_IPSEC_HWACCEL_CONFIGURED */

/* Macro to check if sk_buff's first _len bytes are writable. This macro is
   used in the packet accessor inline functions in platform_interceptor.h.
   skb_clone_writable() was introduced in 2.6.23. */
#define SSH_SKB_WRITABLE(_skb, _len)                            \
  (!skb_cloned((_skb)) || skb_clone_writable((_skb), (_len)))

#endif /* LINUX_PACKET_INTERNAL_H */
