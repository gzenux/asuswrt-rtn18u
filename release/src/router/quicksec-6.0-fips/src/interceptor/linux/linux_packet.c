/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Packet manipulation functions, all ssh_interceptor_packet* functions.
*/

#include "linux_internal.h"
#include "linux_packet_internal.h"
#include "linux_vrf.h"

#include <linux/highmem.h>

#define SSH_DEBUG_MODULE "SshInterceptorPacket"

typedef struct SshInterceptorInternalPacketRec
SshInterceptorInternalPacketStruct;

extern SshInterceptor ssh_interceptor_context;

/************************ Packet freelist ***********************************/

#ifdef DEBUG_LIGHT
/* Format packet freelist statistics into buf. */
int ssh_interceptor_packet_freelist_stats(SshInterceptor interceptor,
                                          char *buf, int maxsize)
{
  int len;

  ssh_kernel_mutex_lock(interceptor->packet_lock);
  len = ssh_snprintf(buf, maxsize,
                     "Packet freelist - reused:%d allocated:%d\n",
                     interceptor->packet_freelist->reused,
                     interceptor->packet_freelist->allocated);

  ssh_kernel_mutex_unlock(interceptor->packet_lock);
  return len;
}
#endif /* DEBUG_LIGHT */









































/* Map the fragment on address fragment->page. */
static inline void *
ssh_skb_kmap_frag(const skb_frag_t *fragment)
{
#ifdef CONFIG_HIGHMEM
  local_bh_disable();
#endif /* CONFIG_HIGHMEM */

#ifdef LINUX_KMAP_ATOMIC_HAS_NO_ARG
  return kmap_atomic(SSH_SKB_FRAG_PAGE(fragment));
#else /* LINUX_KMAP_ATOMIC_HAS_NO_ARG */
  return kmap_atomic(SSH_SKB_FRAG_PAGE(fragment), KM_SKB_DATA_SOFTIRQ);
#endif /* LINUX_KMAP_ATOMIC_HAS_NO_ARG */
}

/* Release the fragment on address addr. */
static inline void
ssh_skb_krel_frag(void *addr)
{
#ifdef LINUX_KMAP_ATOMIC_HAS_NO_ARG
  kunmap_atomic(addr);
#else /* LINUX_KMAP_ATOMIC_HAS_NO_ARG */
  kunmap_atomic(addr, KM_SKB_DATA_SOFTIRQ);
#endif /* LINUX_KMAP_ATOMIC_HAS_NO_ARG */

#ifdef CONFIG_HIGHMEM
  local_bh_enable();
#endif /* CONFIG_HIGHMEM */
}

/* Helper function for mallocating packets. */
static inline SshInterceptorInternalPacket
linux_interceptor_packet_alloc(void)
{














  return ssh_malloc(sizeof(SshInterceptorInternalPacketStruct));

}

/* Helper function for freeing mallocated packets. */
static inline void
linux_interceptor_packet_free(SshInterceptorInternalPacket ipp)
{
















  ssh_free(ipp);

}

/* Get packet from freelist. */
static inline SshInterceptorInternalPacket
ssh_freelist_packet_get(SshInterceptor interceptor)
{





  SshInterceptorInternalPacket ipp;
  unsigned int cpu;

  icept_preempt_disable();
  cpu = smp_processor_id();

  if (likely(interceptor->packet_freelist->head[cpu]))
    {
      ipp = interceptor->packet_freelist->head[cpu];
      interceptor->packet_freelist->head[cpu] =
        (SshInterceptorInternalPacket) ipp->packet.next;
      ipp->cpu = cpu;
#ifdef DEBUG_LIGHT
      SSH_ASSERT(ipp->list_status == SSH_INTERCEPTOR_PACKET_IN_FREELIST);
      ipp->list_status &= ~SSH_INTERCEPTOR_PACKET_IN_FREELIST;

      ssh_kernel_mutex_lock(interceptor->packet_lock);
      interceptor->packet_freelist->reused++;
      ssh_kernel_mutex_unlock(interceptor->packet_lock);
#endif /* DEBUG_LIGHT */
    }
  else
    {
      /* Try getting a packet from the shared freelist */
      ssh_kernel_mutex_lock(interceptor->packet_lock);

      if (likely(interceptor->packet_freelist->
                 head[SSH_LINUX_INTERCEPTOR_NR_CPUS]))
        {
          ipp =
            interceptor->packet_freelist->head[SSH_LINUX_INTERCEPTOR_NR_CPUS];
          interceptor->packet_freelist->head[SSH_LINUX_INTERCEPTOR_NR_CPUS] =
            (SshInterceptorInternalPacket) ipp->packet.next;
          ipp->cpu = cpu;

          SSH_ASSERT(interceptor->packet_freelist->shared_list_length > 0);
          interceptor->packet_freelist->shared_list_length--;
#ifdef DEBUG_LIGHT
          interceptor->packet_freelist->reused++;

          SSH_ASSERT(ipp->list_status == SSH_INTERCEPTOR_PACKET_IN_FREELIST);
          ipp->list_status &= ~SSH_INTERCEPTOR_PACKET_IN_FREELIST;
#endif /* DEBUG_LIGHT */

          ssh_kernel_mutex_unlock(interceptor->packet_lock);
          goto done;
        }

      /* No packets in the shared freelist. Mallocate a new packet. */
      ipp = linux_interceptor_packet_alloc();
      if (ipp == NULL)
        {
          ssh_kernel_mutex_unlock(interceptor->packet_lock);
          goto done;
        }

      ipp->cpu = cpu;

#ifdef DEBUG_LIGHT
      interceptor->packet_freelist->allocated++;
      ipp->list_status = 0;
#endif /* DEBUG_LIGHT */
      ssh_kernel_mutex_unlock(interceptor->packet_lock);
    }

 done:
#ifdef DEBUG_LIGHT









#endif /* DEBUG_LIGHT */

  icept_preempt_enable();

  return ipp;
}

/* Return packet to freelist. */
static inline void
ssh_freelist_packet_put(SshInterceptor interceptor,
                        SshInterceptorInternalPacket ipp)
{
  unsigned int cpu;

  icept_preempt_disable();

  cpu = ipp->cpu;
  SSH_ASSERT(cpu < SSH_LINUX_INTERCEPTOR_NR_CPUS);

#ifdef DEBUG_LIGHT
  SSH_ASSERT(ipp->list_status == 0);
  memset(ipp, 'F', sizeof(*ipp));
  ipp->list_status = SSH_INTERCEPTOR_PACKET_IN_FREELIST;
#endif /* DEBUG_LIGHT */

  /* Return packet to the original CPU's freelist. */
  if (likely(cpu == smp_processor_id()))
    {
      ipp->packet.next =
        (SshInterceptorPacket) interceptor->packet_freelist->head[cpu];
      interceptor->packet_freelist->head[cpu] = ipp;
    }

  /* The executing CPU is not the same as when the packet was
     allocated. Return the packet to the shared freelist. */
  else
    {
      /* SSH_LINUX_INTERCEPTOR_NR_CPUS is configurable compile time, and thus
         may vary, making the following code reachable in some cases. */
      /* coverity[dead_error_begin] */
      cpu = SSH_LINUX_INTERCEPTOR_NR_CPUS;

      ssh_kernel_mutex_lock(interceptor->packet_lock);

      if (interceptor->packet_freelist->shared_list_length >
          SSH_LINUX_INTERCEPTOR_PACKET_FREELIST_SIZE)
        {
          linux_interceptor_packet_free(ipp);
        }
      else
        {
          ipp->packet.next =
            (SshInterceptorPacket) interceptor->packet_freelist->head[cpu];
          interceptor->packet_freelist->head[cpu] = ipp;
          interceptor->packet_freelist->shared_list_length++;
        }
      ssh_kernel_mutex_unlock(interceptor->packet_lock);
    }

  icept_preempt_enable();
}

/* Initialize packet freelist. */
Boolean
ssh_interceptor_packet_freelist_init(SshInterceptor interceptor)
{
  unsigned int i;

  for (i = 0; i < SSH_LINUX_INTERCEPTOR_NR_CPUS + 1; i++)
    interceptor->packet_freelist->head[i] = NULL;

  interceptor->packet_freelist->shared_list_length = 0;
#ifdef DEBUG_LIGHT
  interceptor->packet_freelist->allocated = 0;
  interceptor->packet_freelist->reused = 0;
#endif /* DEBUG_LIGHT */

  return TRUE;
}

/* Uninitialize packet freelist. */
void
ssh_interceptor_packet_freelist_uninit(SshInterceptor interceptor)
{
  SshInterceptorInternalPacket ipp;
  unsigned int i;

  ssh_kernel_mutex_lock(interceptor->packet_lock);

  for (i = 0; i < SSH_LINUX_INTERCEPTOR_NR_CPUS + 1; i++)
    {
      /* Traverse freelist and free all packets. */
      while (interceptor->packet_freelist->head[i] != NULL)
        {
          ipp = interceptor->packet_freelist->head[i];
          interceptor->packet_freelist->head[i] =
            (SshInterceptorInternalPacket) ipp->packet.next;
          linux_interceptor_packet_free(ipp);
#ifdef DEBUG_LIGHT
          interceptor->packet_freelist->allocated--;
#endif /* DEBUG_LIGHT */
        }
    }

#ifdef DEBUG_LIGHT
  /* Packet leak detection. */
  if (interceptor->packet_freelist->allocated != 0)
    {
      printk("<3> WARNING: %d SshInterceptorPackets are missing "
             "from the freelist!\n",
             interceptor->packet_freelist->allocated);















































    }
#endif /* DEBUG_LIGHT */

  ssh_kernel_mutex_unlock(interceptor->packet_lock);
}


/********************** General packet allocation ***************************/

/* Allocates a packet header wrapping the given skbuff. Packet headers can
   be allocated only using this function. This function returns NULL if the
   packet header cannot be allocated. */
SshInterceptorInternalPacket
ssh_interceptor_packet_alloc_header(SshInterceptor interceptor,
                                    SshUInt32 flags,
                                    SshInterceptorProtocol protocol,
                                    SshUInt32 ifnum_in,
                                    SshUInt32 ifnum_out,
                                    struct sk_buff *skb,
                                    SshUInt32 alloc_flags)
{
  SshInterceptorInternalPacket ipp;

  /* Allocate a wrapper structure */
  ipp = ssh_freelist_packet_get(interceptor);

  if (ipp == NULL)
    {
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_failed_allocs++; });
      return NULL;
    }

  /* Initialize all the fields */
  ipp->packet.flags = flags;

  /* Assert that the interface number fits into SshInterceptorIfnum.
     Note that both interface numbers may be equal to
     SSH_INTERCEPTOR_INVALID_IFNUM. */
  SSH_LINUX_ASSERT_IFNUM(ifnum_in);
  SSH_LINUX_ASSERT_IFNUM(ifnum_out);

  ipp->packet.ifnum_in = ifnum_in;
  ipp->packet.ifnum_out = ifnum_out;
  ipp->original_ifnum = ifnum_in;

#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  ipp->packet.route_selector = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  ipp->packet.pmtu = 0;
  ipp->packet.protocol = protocol;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Clear extension selectors. */
  memset(ipp->packet.extension, 0, sizeof(ipp->packet.extension));
#ifdef SSH_LINUX_FWMARK_EXTENSION_SELECTOR
  /* Copy the linux fwmark to the extension slot indexed by
     SSH_LINUX_FWMARK_EXTENSION_SELECTOR. */
  if (skb)
    ipp->packet.extension[SSH_LINUX_FWMARK_EXTENSION_SELECTOR] =
      SSH_SKB_MARK(skb);
#endif /* SSH_LINUX_FWMARK_EXTENSION_SELECTOR */
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  ipp->interceptor = interceptor;
  ipp->skb = skb;
  ipp->packet.routing_instance_id = SSH_INTERCEPTOR_VRI_ID_GLOBAL;

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_allocated_packets++;
    interceptor->stats.num_allocated_packets_total++;
  });

  if (ipp->skb)
    {
      /* If the packet is of media-broadcast persuasion, add it to the
         flags. */
      if (ipp->skb->pkt_type == PACKET_BROADCAST)
        ipp->packet.flags |= SSH_PACKET_MEDIABCAST;
      if (ipp->skb->pkt_type == PACKET_MULTICAST)
        ipp->packet.flags |= SSH_PACKET_MEDIABCAST;

      if (ipp->skb->ip_summed == CHECKSUM_COMPLETE         /* inbound */
          || ipp->skb->ip_summed == CHECKSUM_UNNECESSARY   /* inbound */
          || ipp->skb->ip_summed == CHECKSUM_PARTIAL)      /* outbound */
        ipp->packet.flags |= SSH_PACKET_HWCKSUM;

      ipp->packet.routing_instance_id = ssh_skb_get_vrf_id(ipp->skb);

      /* For fragmented skb's skb_tailroom() returns always zero, but
         the skb header may still have tailroom in it. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Alloc packet header: skb length %d headlen %d headroom %d "
                 "header tailroom %d %s%s%s%s rid %d",
                 (int) ipp->skb->len,
                 (int) skb_headlen(ipp->skb),
                 (int) skb_headroom(ipp->skb),
                 (int) (ipp->skb->end - ipp->skb->tail),
                 (skb_shared(ipp->skb) ? "shared " : ""),
                 (skb_cloned(ipp->skb) ? "cloned " : ""),
                 (skb_shinfo(ipp->skb)->frag_list!=NULL ? "fragmented " : ""),
                 (skb_is_nonlinear(ipp->skb) ? "non-linear" : ""),
                 ipp->packet.routing_instance_id
                 ));
    }

  return ipp;
}


/* Allocates a packet of at least the given size.  Packets can only be
   allocated using this function (either internally by the interceptor or
   by other code by calling this function).  This returns NULL if no more
   packets can be allocated. */
SshInterceptorPacket
ssh_interceptor_packet_alloc(SshInterceptor interceptor,
                             SshUInt32 flags,
                             SshInterceptorProtocol protocol,
                             SshInterceptorIfnum ifnum_in,
                             SshInterceptorIfnum ifnum_out,
                             size_t total_len)
{
  SshInterceptorInternalPacket ipp;
  size_t len;

  /* Allocate SshInterceptorPacket structure. */
  ipp = (SshInterceptorInternalPacket)
    ssh_interceptor_packet_alloc_header(interceptor,
                                        flags,
                                        protocol,
                                        ifnum_in,
                                        ifnum_out,
                                        NULL,
                                        0);
  /* Header allocation failed. */
  if (ipp == NULL)
    return NULL;

  /* Allocate actual kernel packet. Note that some overhead is calculated
     so that media headers etc. fit without additional allocations or
     copying. The allocated skb is always linear. */
  len = (total_len + SSH_INTERCEPTOR_PACKET_HEAD_ROOM +
         SSH_INTERCEPTOR_PACKET_TAIL_ROOM);
  ipp->skb = alloc_skb(len, SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (ipp->skb == NULL)
    {
      SSH_LINUX_STATISTICS(interceptor,
                           { interceptor->stats.num_failed_allocs++; });
      ssh_freelist_packet_put(interceptor, ipp);
      return NULL;
    }

  /* Set data area inside the packet. Ensure the IP header
     offset is 16 byte aligned for ethernet frames. */
  if (protocol == SSH_PROTOCOL_ETHERNET)
    skb_reserve(ipp->skb, SSH_INTERCEPTOR_PACKET_HEAD_ROOM + 2);
  else
    skb_reserve(ipp->skb, SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

  skb_put(ipp->skb, total_len);
  skb_dst_set(ipp->skb, NULL);

  if (flags & SSH_PACKET_HWCKSUM)
    {
      if (flags & SSH_PACKET_FROMADAPTER)
        ipp->skb->ip_summed = CHECKSUM_COMPLETE;
      else if (flags & SSH_PACKET_FROMPROTOCOL)
        ipp->skb->ip_summed = CHECKSUM_PARTIAL;
    }

  /* If support for other than IPv6, IPv4 and ARP
     inside the engine on Linux are to be supported, their
     protocol types must be added here. */
  switch(protocol)
    {
#ifdef SSH_LINUX_INTERCEPTOR_IPV6
    case SSH_PROTOCOL_IP6:
      ipp->skb->protocol = __constant_htons(ETH_P_IPV6);
      break;
#endif /* SSH_LINUX_INTERCEPTOR_IPV6 */

    case SSH_PROTOCOL_ARP:
      ipp->skb->protocol = __constant_htons(ETH_P_ARP);
      break;

    case SSH_PROTOCOL_IP4:
    default:
      ipp->skb->protocol = __constant_htons(ETH_P_IP);
      break;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Alloc packet: skb len %d headroom %d tailroom %d",
             (int) ipp->skb->len,
             (int) skb_headroom(ipp->skb),
             (int) skb_tailroom(ipp->skb)));

  return (SshInterceptorPacket) ipp;
}

/* Frees the given packet. All packets allocated by
   ssh_interceptor_packet_alloc must eventually be freed using this
   function by either calling this explicitly or by passing the packet
   to the interceptor send function. */

void
ssh_interceptor_packet_free(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing packet %p: skb %p", ipp, ipp->skb));

  /* Free the packet buffer first */
  if (ipp->skb)
    {




      kfree_skb(ipp->skb);
      ipp->skb = NULL;
    }

  SSH_LINUX_STATISTICS(ipp->interceptor,
  { ipp->interceptor->stats.num_allocated_packets--; });

  /* Free the wrapper */
  ssh_freelist_packet_put(ipp->interceptor, ipp);
}


/***************** Packet data access and modification ***********************/

/* Returns amount of headroom that is aligned to requested word boundary. */
#define SSH_LINUX_SKB_HEADROOM_ALIGN(alignment, headroom)       \
  (((alignment) & (sizeof(int *) - 1)) + headroom)

static inline void
interceptor_packet_segment_operation_done(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  if (ipp->iteration_mapped_fragment != NULL)
    ssh_skb_krel_frag(ipp->iteration_mapped_fragment);

  ipp->iteration_mapped_fragment = NULL;
}

/* Internal function for iterating possibly non-contiguous segments of a
   packet. This function checks that the packet segments are writable and
   linearizes the packet if necessary. */
static inline Boolean
interceptor_packet_segment_write(SshInterceptorPacket pp,
                                 size_t offset,
                                 size_t bytes,
                                 unsigned char **data_ret,
                                 size_t *len_ret)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  size_t len, frag_offset, headroom;
  int frag_index;
  struct skb_shared_info *shinfo;
  struct sk_buff *skb;
  unsigned char *vaddr;

  SSH_ASSERT(data_ret != NULL);
  SSH_ASSERT(len_ret != NULL);

  /* We have already iterated all data. */
  if (unlikely(bytes == 0))
    {
      (*data_ret) = NULL;
      (*len_ret) = 0;
      return FALSE;
    }

  SSH_ASSERT(ipp->skb->len >= (offset + bytes));

  /* All requested data is in skb header. */
  if (likely((offset + bytes) <= skb_headlen(ipp->skb)))
    {
      /* Copy the skb header if it is shared or cloned. */
      if (unlikely(skb_shared(ipp->skb)
                   || !SSH_SKB_WRITABLE(ipp->skb, offset + bytes)))
        {
          /* Preserve skb data alignment. */
          headroom =
            SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                         SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

          /* The skb is shared or cloned, copy the skb header. */
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Reallocating %s skb header: header length %d "
                     "resulting headroom %d tailroom %d",
                     (skb_shared(ipp->skb) ? "shared" : "cloned"),
                     (int) skb_headlen(ipp->skb),
                     (int) headroom,
                     (int) SSH_INTERCEPTOR_PACKET_TAIL_ROOM));

          /* Clone skb header if it is shared. */
          ipp->skb = skb_share_check(ipp->skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
          if (ipp->skb == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("skb_share_check() failed"));
              goto fail;
            }

          /* Copy skb header and reserve enough headroom and tailroom. */
          if (pskb_expand_head(ipp->skb,
                               headroom,
                               SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                               SSH_LINUX_ALLOC_SKB_GFP_MASK))
            {
              SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
              goto fail;
            }
        }

      /* Now the skb header data can be freely modified. */
      len = skb_headlen(ipp->skb) - offset;
      if (len > bytes)
        len = bytes;

      (*data_ret) = ipp->skb->data + offset;
      (*len_ret) = len;

      return TRUE;
    }

  /* The requested data starts at skb header and continues
     to paged fragments or next skb in fragment chain. */
  else if (offset < skb_headlen(ipp->skb))
    {
      /* Linearize the skb if it is shared or cloned
         or it has a fragment chain. */
      if (likely(skb_shared(ipp->skb) || skb_cloned(ipp->skb)
                 || skb_shinfo(ipp->skb)->frag_list != NULL))
        {
        linearize_skb:
          /* Preserve skb data alignment. */
          headroom =
            SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                         SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

          /* The skb is shared or cloned, copy the skb header and data. */
          SSH_DEBUG(SSH_D_HIGHOK,
                    ("Linearizing %s skb: length %d "
                     "resulting headroom %d tailroom %d",
                     (skb_shared(ipp->skb) ? "shared" :
                      (skb_shinfo(ipp->skb)->frag_list!=NULL ? "fragmented" :
                       (skb_cloned(ipp->skb) ? "cloned" :
                        (skb_is_nonlinear(ipp->skb) ? "non-linear" : "")))),
                     (int) ipp->skb->len,
                     (int) headroom,
                     (int) SSH_INTERCEPTOR_PACKET_TAIL_ROOM));

          skb = skb_copy_expand(ipp->skb,
                                headroom,
                                SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                                SSH_LINUX_ALLOC_SKB_GFP_MASK);
          if (skb == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("skb_copy_expand() failed"));
              goto fail;
            }

          /* Free original skb and replace ipp->skb. */
          kfree_skb(ipp->skb);
          ipp->skb = skb;
        }

      /* Now the skb header data can be freely modified. */
      SSH_ASSERT(skb_headlen(ipp->skb) > offset);
      len = skb_headlen(ipp->skb) - offset;
      if (len > bytes)
        len = bytes;

      (*data_ret) = ipp->skb->data + offset;
      (*len_ret) = len;

      return TRUE;
    }

  /* The requested data is in the paged fragments or in the fragment chain. */
  else
    {
      shinfo = skb_shinfo(ipp->skb);

      /* The skb is shared or cloned or it has a fragment chain,
         need to linearize the skb. */
      if (likely(skb_shared(ipp->skb) || skb_cloned(ipp->skb)
                 || shinfo->frag_list != NULL))
        {
          goto linearize_skb;
        }

      /* Ok, the paged fragments can be freely modified. Find the paged
         fragment where the requested iteration range starts. */
      len = skb_headlen(ipp->skb);
      for (frag_index = 0; frag_index < shinfo->nr_frags; frag_index++)
        {
          if (offset < (len + shinfo->frags[frag_index].size))
            break;
          len += shinfo->frags[frag_index].size;
        }
      SSH_ASSERT(frag_index < shinfo->nr_frags);

      /* Calculate the data offset and data length within the fragment. */
      SSH_ASSERT(offset >= len);
      frag_offset = offset - len;

      SSH_ASSERT(shinfo->frags[frag_index].size > frag_offset);
      len = shinfo->frags[frag_index].size - frag_offset;
      if (len > bytes)
        len = bytes;

      vaddr = ssh_skb_kmap_frag(&shinfo->frags[frag_index]);
      SSH_ASSERT(vaddr != NULL);
      SSH_ASSERT(ipp->iteration_mapped_fragment == NULL);
      ipp->iteration_mapped_fragment = vaddr;

      /* Return the data in this fragment. */
      (*data_ret) = vaddr + shinfo->frags[frag_index].page_offset
        + frag_offset;
      SSH_ASSERT(*data_ret != NULL);

      (*len_ret) = len;

      return TRUE;
    }

 fail:
  SSH_DEBUG(SSH_D_LOWOK, ("Packet segment write, freeing packet %p", pp));
  ssh_interceptor_packet_free(pp);

  /* The API specifies that on error *data_ret != NULL and
     return code is FALSE. */
  (*data_ret) = (unsigned char *) 42;
  (*len_ret) = 0;
  return FALSE;
}

/* Internal function for iterating possibly non-contiguous segments of a
   packet. The caller is not allowed to modify the returned packet segments. */
static inline Boolean
interceptor_packet_segment_read(SshInterceptorPacket pp,
                                size_t offset,
                                size_t bytes,
                                const unsigned char **data_ret,
                                size_t *len_ret)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  size_t len, frag_len, frag_offset;
  int frag_index = 0;
  struct skb_shared_info *shinfo = NULL;
  struct sk_buff *skb = NULL;
  unsigned char *vaddr;

  SSH_ASSERT(data_ret != NULL);
  SSH_ASSERT(len_ret != NULL);

  /* We have already iterated all data. */
  if (unlikely(bytes == 0))
    {
      (*data_ret) = NULL;
      (*len_ret) = 0;
      return FALSE;
    }

  SSH_ASSERT(ipp->skb->len >= (offset + bytes));

  frag_len = 0;
  skb = ipp->skb;

 next_frag:
  /* Iteration is at skb header. */
  if (likely(offset < (frag_len + skb_headlen(skb))))
    {
      len = frag_len + skb_headlen(skb) - offset;
      if (len > bytes)
        len = bytes;

      /* Return the skb header data. */
      (*data_ret) = skb->data + offset - frag_len;
      (*len_ret) = len;

      return TRUE;
    }

  /* Iteration is at paged fragment of current skb. */
  else if (offset < (frag_len + skb_pagelen(skb)))
    {
      /* Find the paged fragment where the requested iteration range starts. */
      frag_len += skb_headlen(skb);

      shinfo = skb_shinfo(skb);
      for (frag_index = 0; frag_index < shinfo->nr_frags; frag_index++)
        {
          if (offset < (frag_len + shinfo->frags[frag_index].size))
            break;
          frag_len += shinfo->frags[frag_index].size;
        }
      SSH_ASSERT(frag_index < shinfo->nr_frags);

      /* Calculate the data offset and data length within the fragment. */
      SSH_ASSERT(offset >= frag_len);
      frag_offset = offset - frag_len;

      SSH_ASSERT(shinfo->frags[frag_index].size > frag_offset);
      len = shinfo->frags[frag_index].size - frag_offset;
      if (len > bytes)
        len = bytes;

      vaddr = ssh_skb_kmap_frag(&shinfo->frags[frag_index]);
      SSH_ASSERT(vaddr != NULL);
      SSH_ASSERT(ipp->iteration_mapped_fragment == NULL);
      ipp->iteration_mapped_fragment = vaddr;

      /* Return the data in this fragment. */
      (*data_ret) = vaddr +
        shinfo->frags[frag_index].page_offset + frag_offset;
      (*len_ret) = len;

      return TRUE;
    }

  /* Iteration is at next skb in fragment chain. */

  /* Count the bytes in current skb. */
  frag_len += skb_pagelen(skb);

  shinfo = skb_shinfo(skb);
  if (skb == ipp->skb)
    {
      if (shinfo->frag_list != NULL)
        {
          skb = shinfo->frag_list;
          goto next_frag;
        }
    }
  else if (skb->next != NULL)
    {
      skb = skb->next;
      goto next_frag;
    }

  SSH_DEBUG(SSH_D_ERROR,
            ("Requested iteration range goes past the fragmented data: "
             "ipp->skb %p length %d "
             "skb %p length %d data length %d page length %d nr_frags %d "
             "requested offset %d bytes %d fragment offset %d",
             ipp->skb,
             (int) ipp->skb->len,
             skb,
             (int) skb->len,
             (int) skb->data_len,
             (int) skb_pagelen(skb),
             (int) shinfo->nr_frags,
             (int) offset,
             (int) bytes,
             (int) frag_len));

  SSH_NOTREACHED;
  ssh_interceptor_packet_free(pp);

  /* The API specifies that on error *data_ret != NULL and
     return code is FALSE. */
  (*data_ret) = (unsigned char *) 42;
  (*len_ret) = 0;
  return FALSE;
}

#ifdef KERNEL_INTERCEPTOR_USE_FUNCTIONS
/* Returns the length of the data packet. This function is replaced by an
   inline variant (in platform_interceptor.h) when
   KERNEL_INTERCEPTOR_USE_FUNCTIONS is not defined. */
size_t
ssh_interceptor_packet_len(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  return ipp->skb->len;
}
#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */

/* Returns a pointer to the first byte of the packet that can be modified.
   The function is split into two parts: This functions is the common
   workhorse for complex pullup operations, the function below handles the
   most common and simple case and it is replaced by an inline variant
   (in platform_interceptor.h) when KERNEL_INTERCEPTOR_USE_FUNCTIONS is
   not defined. */
unsigned char *
interceptor_packet_pullup(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  struct sk_buff *skb;
  size_t headroom;

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= bytes);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);

  /* Pullup requests data from skb header. */
  if (likely(skb_headlen(ipp->skb) >= bytes))
    {
      /* The skb must be shared or cloned when this code path is entered. */
      SSH_ASSERT(skb_shared(ipp->skb)
                 || !SSH_SKB_WRITABLE(ipp->skb, bytes));

      /* Preserve skb data alignment. */
      headroom =
        SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                     SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Reallocating %s skb header: skb header length %d "
                 "resulting headroom %d",
                 (skb_shared(ipp->skb) ? "shared" : "cloned"),
                 (int) skb_headlen(ipp->skb),
                 (int) headroom));

      /* Clone skb header if it is shared, then copy skb header
         and reserve enough headroom and tailroom. */
      ipp->skb = skb_share_check(ipp->skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
      if (unlikely(ipp->skb == NULL
                   || pskb_expand_head(ipp->skb,
                                       headroom,
                                       SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                                       SSH_LINUX_ALLOC_SKB_GFP_MASK)))
        {
          SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
          goto fail;
        }

      return ipp->skb->data;
    }

  /* Pullup requests data from the fragmented part of the skb. */
  SSH_ASSERT(ipp->skb->len >= bytes);

  /* Need to make a copy of the skb and data. Copying the skb results
     into a linearized skb. */

  /* Preserve skb data alignment. */
  headroom = SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                          SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Linearizing %s skb: length %d "
             "resulting headroom %d tailroom %d",
             (skb_shared(ipp->skb) ? "shared" : "cloned"),
             (int) ipp->skb->len,
             (int) headroom,
             (int) SSH_INTERCEPTOR_PACKET_TAIL_ROOM));

  skb = skb_copy_expand(ipp->skb,
                        headroom,
                        SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                        SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("skb_copy_expand() failed"));
      goto fail;
    }

  /* Free original skb and replace ipp->skb. */
  kfree_skb(ipp->skb);
  ipp->skb = skb;

  /* Now the skb can be freely modified. */
  SSH_ASSERT(!skb_cloned(ipp->skb));
  return ipp->skb->data;

 fail:
  SSH_DEBUG(SSH_D_LOWOK, ("Pullup failed, freeing packet %p", pp));
  ssh_interceptor_packet_free(pp);
  return NULL;
}

#ifdef KERNEL_INTERCEPTOR_USE_FUNCTIONS
unsigned char *
ssh_interceptor_packet_pullup(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= bytes);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);


  /* Pullup requests data from the header of a writable skb. */
  if (likely(skb_headlen(ipp->skb) >= bytes
             && !skb_shared(ipp->skb) && SSH_SKB_WRITABLE(ipp->skb, bytes)))
    return ipp->skb->data;

  else
    return interceptor_packet_pullup(pp, bytes);
}
#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */

/* Returns a pointer to the first byte of the packet for read-only access.
   The function is split into two parts: This functions is the common
   workhorse for complex pullup operations, the function below handles the
   most common and simple case and it is replaced by an inline variant
   (in platform_interceptor.h) when KERNEL_INTERCEPTOR_USE_FUNCTIONS is
   not defined. */
const unsigned char *
interceptor_packet_pullup_read(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  const unsigned char *segment;
  size_t segment_len, offset;

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= bytes);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);

  /* The requested data must be in the fragmented part of skb when
     this code path is entered. */
  SSH_ASSERT(skb_headlen(ipp->skb) < bytes);

  /* Copy the requested data to ipp->pullup_buffer. */
  offset = 0;

  ipp->iteration_offset = offset;
  ipp->iteration_bytes = bytes;
  ipp->iteration_mapped_fragment = NULL;

  while (interceptor_packet_segment_read(pp, offset, bytes, &segment,
                                         &segment_len))
    {
      SSH_ASSERT((offset + segment_len) <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);
      memcpy(ipp->pullup_buffer + offset, segment, segment_len);
      offset += segment_len;
      bytes -= segment_len;

      interceptor_packet_segment_operation_done(pp);
    }

  if (segment == NULL)
    interceptor_packet_segment_operation_done(pp);

  return ipp->pullup_buffer;
}

#ifdef KERNEL_INTERCEPTOR_USE_FUNCTIONS
const unsigned char *
ssh_interceptor_packet_pullup_read(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= bytes);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);

  /* Requested data is in the skb header, return pointer to skb data. */
  if (likely(skb_headlen(ipp->skb) >= bytes))
    return ipp->skb->data;

  else
    return interceptor_packet_pullup_read(pp, bytes);
}
#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */

static inline struct sk_buff *
interceptor_packet_expand_head(struct sk_buff *skb,
                               size_t offset,
                               size_t bytes)
{
  size_t headroom;
  struct sk_buff *cloned_skb;
  unsigned char *copy_from, *copy_to;

  /* The skb is shared or cloned, need to copy skb header. Preserve
     skb data alignment. */
  headroom = SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(skb),
                                          SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Reallocating %s skb header: header length %d "
             "expansion %d resulting headroom %d tailroom %d",
             (skb_shared(skb) ? "shared " :
              (skb_cloned(skb) ? "cloned " :
               (skb_is_nonlinear(skb) ? "non-linear" : ""))),
             (int) skb_headlen(skb),
             (int) bytes,
             (int) headroom,
             (int) SSH_INTERCEPTOR_PACKET_TAIL_ROOM));

  /* First clone the original skb. Modify the clone. */
  cloned_skb = skb_clone(skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (cloned_skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("skb_clone() failed"));
      return NULL;
    }

  /* Remove the portion of code that needs to be moved so that
     pskb_expand_head() does not copy it. */
  if (offset > 0)
    skb_pull(cloned_skb, offset);

  /* Expand the cloned skb header. This copies the data in the cloned
     skb header and reserves the headroom and tailroom in the copy. */
  if (pskb_expand_head(cloned_skb,
                       headroom + offset + bytes,
                       SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                       SSH_LINUX_ALLOC_SKB_GFP_MASK))
    {
      SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
      return NULL;
    }

  /* Insert the requested amount of bytes and the moved data portion. */
  copy_to = skb_push(cloned_skb, bytes + offset);
  SSH_ASSERT(copy_to != NULL);

  /* Copy the portion of data before the offset of insertion. */
  if (offset > 0)
    {
      copy_from = skb->data;
      memcpy(copy_to, copy_from, offset);
    }

  return cloned_skb;
}

static inline struct sk_buff *
interceptor_packet_expand_tail(struct sk_buff *skb,
                               size_t offset,
                               size_t bytes)
{
  size_t headroom, copy_len;
  struct sk_buff *cloned_skb;
  unsigned char *copy_from, *copy_to;

  /* Preserve skb data alignment. */
  headroom = SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(skb),
                                          SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Reallocating %sskb header: header length %d "
             "expansion %d resulting headroom %d tailroom %d",
             (skb_shared(skb) ? "shared " :
              (skb_cloned(skb) ? "cloned " :
               (skb_is_nonlinear(skb) ? "non-linear" : ""))),
             (int) skb_headlen(skb),
             (int) bytes,
             (int) headroom,
             (int) SSH_INTERCEPTOR_PACKET_TAIL_ROOM));

  /* First clone the original skb. Modify the clone. */
  cloned_skb = skb_clone(skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (cloned_skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("skb_clone() failed"));
      return NULL;
    }

  /* Remove the portion of code that needs to be moved so
     that pskb_expand_head() does not copy it. */
  copy_len = skb_headlen(skb) - offset;
  cloned_skb->tail -= copy_len;
  cloned_skb->len -= copy_len;

  /* Expand the cloned skb header. */
  if (pskb_expand_head(cloned_skb,
                       headroom,
                       SSH_INTERCEPTOR_PACKET_TAIL_ROOM + copy_len + bytes,
                       SSH_LINUX_ALLOC_SKB_GFP_MASK))
    {
      SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
      return NULL;
    }

  /* Insert the requested amount of bytes to tail of skb header. */
  cloned_skb->tail += bytes;
  cloned_skb->len += bytes;

  /* Copy the portion of data after the inserted data */
  if (copy_len > 0)
    {
      copy_from = skb->data + offset;
      copy_to = SSH_SKB_GET_TAIL(cloned_skb);
      memcpy(copy_to, copy_from, copy_len);
      cloned_skb->tail += copy_len;
      cloned_skb->len += copy_len;
    }

  return cloned_skb;
}

/* Inserts space for the given number of bytes in the packet. This
   doesn't copy any actual data into the packet. Implementation note: most
   of the time, the insertion will take place near the start of the packet,
   and only twenty or so bytes are typically inserted.

   The function is split into two parts: This functions is the common
   workhorse for complex insert operations, the function below handles the
   most common and simple case and it is replaced by an inline variant
   (in platform_interceptor.h) when KERNEL_INTERCEPTOR_USE_FUNCTIONS is
   not defined. */
unsigned char *
interceptor_packet_insert(SshInterceptorPacket pp,
                          size_t offset, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  size_t headroom, tailroom, copy_len;
  struct sk_buff *skb;
  unsigned char *copy_from, *copy_to;

  SSH_DEBUG(SSH_D_LOWSTART, ("Packet insert: pp %p offset %d bytes %d",
                             pp, (int) offset, (int) bytes));

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= offset);

  /* This code path should never be entered for the most common case
     (insertion into head of skb when there is enough headroom. */
  SSH_ASSERT(!(offset == 0
               && (skb_headroom(ipp->skb) >=
                   (bytes + SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM))
               && !skb_shared(ipp->skb)
               && SSH_SKB_WRITABLE(ipp->skb, 0)));

 restart_linearized:
  /* Now insertion modifies only the skb header. */
  headroom = skb_headroom(ipp->skb);
  tailroom = ipp->skb->end - ipp->skb->tail;

  /* Insertion is closer to head, there is enough headroom and skb is not
     shared or cloned. */
  if (likely((skb_headlen(ipp->skb) / 2) >= offset
             && (headroom - SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM) >= bytes
             && !skb_shared(ipp->skb)
             && SSH_SKB_WRITABLE(ipp->skb, offset)))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Insert to skb header: %d bytes at offset %d "
                 "moved bytes %d",
                 (int) bytes, (int) offset, (int) offset));

      copy_from = ipp->skb->data;

      /* Prepend the inserted data to skb header. */
      copy_to = skb_push(ipp->skb, bytes);
      SSH_ASSERT(copy_to != NULL);

      /* Move data before the offset of insertion. */
      if (offset > 0)
        memmove(copy_to, copy_from, offset);

      /* Return a pointer to offset of insertion. */
      return ipp->skb->data + offset;
    }

  /* Insertion is closer to tail of skb header or there is not enough
     headroom for inserting near the head of skb header or skb is shared
     or cloned. */
  else if (likely(skb_headlen(ipp->skb) >= offset))
    {
      /* There is enough available tailroom and the skb is not shared or
         cloned. */
      if (likely(tailroom >= bytes
                 && !skb_shared(ipp->skb) && !skb_cloned(ipp->skb)))
        {
          /* Calculate the portion of data that needs to be moved. */
          copy_from = ipp->skb->data + offset;
          copy_len = SSH_SKB_GET_TAIL(ipp->skb) - copy_from;
          copy_to = ipp->skb->data + offset + bytes;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Insert to tail of skb header: %d bytes at offset %d "
                     "moved bytes %d",
                     (int) bytes, (int) offset, (int) copy_len));

          /* Advance tail of skb header. */
          ipp->skb->tail += bytes;
          ipp->skb->len += bytes;

          /* Move data after inserted data. */
          if (copy_len > 0)
            memmove(copy_to, copy_from, copy_len);

          /* Return a pointer to offset of insertion. */
          return ipp->skb->data + offset;
        }

      /* The skb is shared or cloned or there is not enough combined head and
         tailroom, need to copy skb header. */
      if ((skb_headlen(ipp->skb) / 2) >= offset)
        skb = interceptor_packet_expand_head(ipp->skb, offset, bytes);
      else
        skb = interceptor_packet_expand_tail(ipp->skb, offset, bytes);

      if (skb == NULL)
        goto fail;

      /* Release the reference to the original skb and replace ipp->skb. */
      kfree_skb(ipp->skb);
      ipp->skb = skb;

      /* Return a pointer to offset of insertion. */
      return ipp->skb->data + offset;
    }

  /* Insertion modifies the fragmented part of skb. */
  SSH_ASSERT(skb_is_nonlinear(ipp->skb));

  /* Calculate the amount of headroom and tailroom to allocate for
     the copied skb. Preserve skb data alignment. */
  headroom =
    SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                 SSH_INTERCEPTOR_PACKET_HEAD_ROOM);
  tailroom = SSH_INTERCEPTOR_PACKET_TAIL_ROOM;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Linearizing %s skb: length %d "
             "resulting headroom %d tailroom %d",
             (skb_shared(ipp->skb) ? "shared" : "cloned"),
             (int) ipp->skb->len,
             (int) headroom,
             (int) tailroom));

  if ((ipp->skb->len / 2) >= offset)
    headroom += bytes;
  else
    tailroom += bytes;

  /* Copy and expand the skb. This also linearizes the skb. */
  skb = skb_copy_expand(ipp->skb, headroom, tailroom,
                        SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("skb_copy_expand() failed"));
      goto fail;
    }

  /* Free the original skb and replace ipp->skb. */
  kfree_skb(ipp->skb);
  ipp->skb = skb;

  SSH_ASSERT(!skb_cloned(ipp->skb));
  SSH_ASSERT(skb_headlen(ipp->skb) >= offset);
  SSH_ASSERT((skb_headroom(ipp->skb) + skb_tailroom(ipp->skb)) >= bytes);

  goto restart_linearized;

 fail:
  SSH_DEBUG(SSH_D_LOWOK, ("Insert failed, freeing packet %p", pp));
  ssh_interceptor_packet_free(pp);
  return NULL;
}

#ifdef KERNEL_INTERCEPTOR_USE_FUNCTIONS
unsigned char *
ssh_interceptor_packet_insert(SshInterceptorPacket pp,
                              size_t offset, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= offset);

  /* Most common case: insertion at offset 0 and there is enough headroom. */
  if (likely(offset == 0
             && (skb_headroom(ipp->skb) >=
                 (bytes + SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM))
             && !skb_shared(ipp->skb) && SSH_SKB_WRITABLE(ipp->skb, 0)))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Insert to beginning of skb header: %d bytes at offset 0",
                 (int) bytes));

      return skb_push(ipp->skb, bytes);
    }

  /* Second most simple case: insertion of packet trailer to a linear skb
     that is not shared or cloned when there is enough tailroom. */
  else if (likely(offset == ipp->skb->len && !skb_is_nonlinear(ipp->skb)
                  && skb_tailroom(ipp->skb) >= bytes
                  && !skb_shared(ipp->skb) && !skb_cloned(ipp->skb)))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Insert to end of skb: %d bytes at offset %d",
                 (int) bytes, (int) offset));

      /* Advance skb tail. */
      ipp->skb->tail += bytes;
      ipp->skb->len += bytes;
      SSH_ASSERT(ipp->skb->tail <= ipp->skb->end);

      return ipp->skb->data + offset;
    }

  else
    return interceptor_packet_insert(pp, offset, bytes);
}
#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */

/* Deletes the specified number of bytes from the buffer. */
Boolean
interceptor_packet_delete(SshInterceptorPacket pp, size_t offset,
                          size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  struct sk_buff *skb;
  unsigned char *copy_from, *copy_to;
  size_t copy_len, headroom, tailroom;

  SSH_DEBUG(SSH_D_LOWSTART, ("Packet delete: pp %p offset %d bytes %d",
                             pp, (int) offset, (int) bytes));

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= (offset + bytes));
  SSH_ASSERT(bytes > 0);

  /* Deletion modifies the fragmented part of skb. */
  if (unlikely((offset + bytes) > skb_headlen(ipp->skb)))
    {
      /* Calculate the amount of headroom and tailroom to allocate
         for the copied skb. Preserve skb data alignment. */
      headroom =
        SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                     SSH_INTERCEPTOR_PACKET_HEAD_ROOM);
      tailroom = SSH_INTERCEPTOR_PACKET_TAIL_ROOM;

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Linearizing %s %sskb: length %d "
                 "resulting headroom %d tailroom %d",
                 (skb_is_nonlinear(ipp->skb) ? "non-linear" : "fragmented"),
                 (skb_shared(ipp->skb) ? "shared " :
                  (skb_cloned(ipp->skb) ? "cloned " : "")),
                 (int) ipp->skb->len,
                 (int) headroom,
                 (int) tailroom));

      /* Copy and expand the skb. This also linearizes the skb. */
      skb = skb_copy_expand(ipp->skb, headroom, tailroom,
                            SSH_LINUX_ALLOC_SKB_GFP_MASK);
      if (skb == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("skb_copy_expand() failed"));
          goto fail;
        }

      /* Free the original skb and replace ipp->skb. */
      kfree_skb(ipp->skb);
      ipp->skb = skb;
    }

  /* Now deletion modifies only the skb header. */

  /* Deletion is closer to head. */
  if (likely((skb_headlen(ipp->skb) / 2) >= offset))
    {
      /* The skb header is not shared or cloned. */
      if (likely(!skb_shared(ipp->skb)
                 && SSH_SKB_WRITABLE(ipp->skb, offset + bytes)))
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Delete from skb header: %d bytes at offset %d "
                     "moved bytes %d",
                     (int) bytes, (int) offset, (int) offset));

          /* Copy data before the offset of deletion. */
          if (offset > 0)
            {
              copy_from = ipp->skb->data;
              copy_to = ipp->skb->data + bytes;
              memmove(copy_to, copy_from, offset);
            }

          /* Remove amount of deleted bytes from head of skb header. */
          copy_to = skb_pull(ipp->skb, bytes);
          SSH_ASSERT(copy_to != NULL);

          return TRUE;
        }

      /* Need to copy skb header. */
      SSH_DEBUG(SSH_D_HIGHOK,
                ("Reallocating %s skb header: header length %d moved bytes %d",
                 (skb_shared(ipp->skb) ? "shared" : "cloned"),
                 (int) skb_headlen(ipp->skb),
                 (int) offset));

      /* First clone the original skb. Modify the clone. */
      skb = skb_clone(ipp->skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
      if (skb == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("skb_clone() failed"));
          goto fail;
        }

      /* Calculate the amount of headroom. Preserve skb data alignment. */
      if (offset != 0)
        headroom =
          SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                       SSH_INTERCEPTOR_PACKET_HEAD_ROOM);
      else
        {
          headroom =
            SSH_LINUX_SKB_HEADROOM_ALIGN(0, SSH_INTERCEPTOR_PACKET_HEAD_ROOM);
        }

      /* Remove the portion of code that needs to be moved so
         that pskb_expand_head() does not copy it. */
      skb_pull(skb, offset + bytes);

      /* Expand the cloned skb header. This copies the data in the cloned
         skb header and reserves the headroom and tailroom in the copy. */
      if (pskb_expand_head(skb,
                           headroom + offset,
                           SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                           SSH_LINUX_ALLOC_SKB_GFP_MASK))
        {
          SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
          goto fail;
        }

      /* Copy the portion of data before the offset of deletion. */
      if (offset > 0)
        {
          copy_from = ipp->skb->data;
          copy_to = skb_push(skb, offset);
          SSH_ASSERT(copy_to != NULL);
          memcpy(copy_to, copy_from, offset);
        }

      /* Release the reference to the original skb and replace ipp->skb. */
      kfree_skb(ipp->skb);
      ipp->skb = skb;

      return TRUE;
    }

  /* Deletion is closer to tail of skb header. */
  else
    {
      SSH_ASSERT(offset > 0);

      /* The skb header is not shared or cloned. */
      if (likely(!skb_shared(ipp->skb) && !skb_cloned(ipp->skb)))
        {
          /* Calculate the portion of data that needs to be moved. */
          copy_from = ipp->skb->data + offset + bytes;
          copy_len = SSH_SKB_GET_TAIL(ipp->skb) - copy_from;
          copy_to = ipp->skb->data + offset;

          SSH_DEBUG(SSH_D_LOWOK,
                    ("Delete from tail of skb header: %d bytes at offset %d "
                     "moved bytes %d",
                     (int) bytes, (int) offset, (int) copy_len));

          /* Remove amount of deleted bytes from tail of skb header. */
          ipp->skb->tail -= bytes;
          ipp->skb->len -= bytes;

          /* Move data after inserted data. */
          if (copy_len > 0)
            memmove(copy_to, copy_from, copy_len);

          return TRUE;
        }

      /* Need to copy skb header. */
      copy_len = skb_headlen(ipp->skb) - offset - bytes;

      SSH_DEBUG(SSH_D_HIGHOK,
                ("Reallocating %s skb header: header length %d moved bytes %d",
                 (skb_shared(ipp->skb) ? "shared" : "cloned"),
                 (int) skb_headlen(ipp->skb),
                 (int) copy_len));

      /* First clone the original skb. Modify the clone. */
      skb = skb_clone(ipp->skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
      if (skb == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("skb_clone() failed"));
          goto fail;
        }

      /* Calculate the amount of headroom. Preserve skb data alignment. */
      headroom =
        SSH_LINUX_SKB_HEADROOM_ALIGN(skb_headroom(ipp->skb),
                                     SSH_INTERCEPTOR_PACKET_HEAD_ROOM);

      /* Remove the portion of code that needs to be moved so
         that pskb_expand_head() does not copy it. */
      skb->tail -= copy_len;
      skb->len -= copy_len;

      /* Expand the cloned skb header. This copies the data in the cloned
         skb header and reserves the headroom and tailroom in the copy. */
      if (pskb_expand_head(skb,
                           headroom,
                           SSH_INTERCEPTOR_PACKET_TAIL_ROOM + copy_len,
                           SSH_LINUX_ALLOC_SKB_GFP_MASK))
        {
          SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
          goto fail;
        }

      /* Copy the portion of data after the offset of deletion. */
      if (copy_len > 0)
        {
          copy_from = ipp->skb->data + offset;
          copy_to = SSH_SKB_GET_TAIL(skb);
          memcpy(copy_to, copy_from, copy_len);
          skb->tail += copy_len;
          skb->len += copy_len;
        }

      /* Release the reference to the original skb and replace ipp->skb. */
      kfree_skb(ipp->skb);
      ipp->skb = skb;

      return TRUE;
    }

 fail:
  SSH_DEBUG(SSH_D_LOWOK, ("Delete failed, freeing packet %p", pp));
  ssh_interceptor_packet_free(pp);
  return FALSE;
}

#ifdef KERNEL_INTERCEPTOR_USE_FUNCTIONS
Boolean
ssh_interceptor_packet_delete(SshInterceptorPacket pp,
                              size_t offset, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  SSH_ASSERT(ipp->skb != NULL);
  SSH_ASSERT(ipp->skb->len >= offset);

  /* Most simple case: deletion of packet head from a skb that is not
     shared or cloned. */
  if (likely(offset == 0 && skb_headlen(ipp->skb) >= bytes
             && !skb_shared(ipp->skb) && SSH_SKB_WRITABLE(ipp->skb, bytes)))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Delete from start of skb: %d bytes at offset %d",
                 (int) bytes, (int) offset));

      /* Remove amount of deleted bytes from head of skb. */
      skb_pull(ipp->skb, bytes);
      return TRUE;
    }

  /* Second most simple case: deletion of packet trailer from a linear skb
     that is not shared or cloned. */
  else if (likely((offset + bytes) == ipp->skb->len
                  && !skb_is_nonlinear(ipp->skb)
                  && !skb_shared(ipp->skb) && !skb_cloned(ipp->skb)))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Delete from end of skb: length %d %d bytes at offset %d",
                 (int) ipp->skb->len, (int) bytes, (int) offset));

      /* Remove amount of deleted bytes from tail of skb. */
      ipp->skb->tail -= bytes;
      ipp->skb->len -= bytes;

      return TRUE;
    }

  else
    return interceptor_packet_delete(pp, offset, bytes);
}
#endif /* KERNEL_INTERCEPTOR_USE_FUNCTIONS */

/* Copies data into the packet.  Space for the new data must already have
   been allocated.  It is a fatal error to attempt to copy beyond the
   allocated packet.  Multiple threads may call this function concurrently,
   but not for the same packet.  This does not change the length of the
   packet. */
Boolean
ssh_interceptor_packet_copyin(SshInterceptorPacket pp, size_t offset,
                              const unsigned char *buf, size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  unsigned char *segment;
  size_t segment_len = 0;

  ipp->iteration_offset = offset;
  ipp->iteration_bytes = len;
  ipp->iteration_mapped_fragment = NULL;

  while (interceptor_packet_segment_write(pp, offset, len, &segment,
                                          &segment_len))
    {
      SSH_ASSERT(segment_len <= len);
      memcpy(segment, buf, segment_len);
      buf += segment_len;
      offset += segment_len;
      len -= segment_len;

      interceptor_packet_segment_operation_done(pp);
    }

  if (segment == NULL)
    interceptor_packet_segment_operation_done(pp);

  if (unlikely(segment != NULL))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Packet copyin failed"));
      return FALSE;
    }

  SSH_ASSERT(len == 0);

  return TRUE;
}

/* Copies data out from the packet.  Space for the new data must
   already have been allocated.  It is a fatal error to attempt to
   copy beyond the allocated packet. Multiple threads may call this
   function concurrently, but not for the same packet. */
void
ssh_interceptor_packet_copyout(SshInterceptorPacket pp, size_t offset,
                               unsigned char *buf, size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  const unsigned char *segment;
  size_t segment_len = 0;

  ipp->iteration_offset = offset;
  ipp->iteration_bytes = len;
  ipp->iteration_mapped_fragment = NULL;

  while (interceptor_packet_segment_read(pp, offset, len, &segment,
                                         &segment_len))
    {
      SSH_ASSERT(segment_len <= len);
      memcpy(buf, segment, segment_len);
      buf += segment_len;
      offset += segment_len;
      len -= segment_len;

      interceptor_packet_segment_operation_done(pp);
    }

  if (segment == NULL)
    interceptor_packet_segment_operation_done(pp);

  SSH_ASSERT(segment == NULL);
}

/** These functions iterate over contiguous segments of the packet,
    starting from offset `offset', continuing for a total of
    `total_bytes' bytes.  It is guaranteed that `*len_return' will not
    be set to a value that would exceed `len' minus sum of previous
    lengths.  Also, previous pointers are guaranteed to stay valid if
    no other ssh_interceptor_packet_* functions are used during
    iteration for the same packet.  At each iteration, these functions
    return a pointer to the first byte of the contiguous segment
    inside the `*data_ret', and set `*len_return' to the number of
    bytes available at that address.

    The ssh_interceptor_packet_reset_iteration function will just
    reset the internal pointers to new offset and number of bytes
    without changing anything else. After that you need to call the
    ssh_interceptor_packet_next_iteration function to get the first
    block. For each block acquited with
    ssh_interceptor_packet_next_iteration(_read),
    ssh_interceptor_packet_done_iteration MUST follow.

    The loop ends when the iteration function returns FALSE, and then
    after the loop you need to check the value of the `*data_ret'. If
    it is NULL then the whole packet was processed and the operation
    was ended because there was no more data available. If it is not
    NULL then the there was an error and the underlaying packet buffer
    has already been freed and all the pointers pointing to that
    memory area (returned by previous calls to this function) are
    invalidated.

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

    Only one operation can be in progress on a single packet
    concurrently, but multiple iterations may be executed
    simultaneously for different packet buffers.  Thus, the
    implementation must keep any state in the packet object, not in
    global variables.

    Multiple threads may call these functions concurrently, but not
    for the same packet.

    There is two different versions of next_iteration function, one to
    get data that you can modify
    (ssh_interceptor_packet_next_iteration) and one to get read only
    version of the data (ssh_interceptor_packet_next_iteration_read).
    The read only version should be used in all cases where the packet
    is not modifed, so interceptor can optimize extra copying of the
    packets away.

    The next_iteration_read function will not copy data away, and it
    cannot fail and free the packet buffer. Note, that if
    next_iteration_read is defined to be same as next_iteration, then
    next_iteration function cannot fail either. */
void
ssh_interceptor_packet_reset_iteration(SshInterceptorPacket pp,
                                       size_t offset, size_t total_bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  ipp->iteration_offset = offset;
  ipp->iteration_bytes = total_bytes;
  ipp->iteration_mapped_fragment = NULL;
}

Boolean
ssh_interceptor_packet_next_iteration(SshInterceptorPacket pp,
                                      unsigned char **data_ret,
                                      size_t *len_return)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  if (unlikely(interceptor_packet_segment_write(pp,
                                                ipp->iteration_offset,
                                                ipp->iteration_bytes,
                                                data_ret, len_return)
               == FALSE))
    return FALSE;

  SSH_ASSERT(*len_return <= ipp->iteration_bytes);
  ipp->iteration_offset += *len_return;
  ipp->iteration_bytes -= *len_return;

  return TRUE;
}

Boolean
ssh_interceptor_packet_next_iteration_read(SshInterceptorPacket pp,
                                           const unsigned char **data_ret,
                                           size_t *len_return)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  if (unlikely(interceptor_packet_segment_read(pp,
                                               ipp->iteration_offset,
                                               ipp->iteration_bytes,
                                               data_ret, len_return)
               == FALSE))
    return FALSE;

  SSH_ASSERT(*len_return <= ipp->iteration_bytes);
  ipp->iteration_offset += *len_return;
  ipp->iteration_bytes -= *len_return;

  return TRUE;
}

Boolean
ssh_interceptor_packet_done_iteration(SshInterceptorPacket pp,
                                      unsigned char **data_ret,
                                      size_t *len_return)
{
  interceptor_packet_segment_operation_done(pp);
  return TRUE;
}

Boolean
ssh_interceptor_packet_done_iteration_read(SshInterceptorPacket pp,
                                           const unsigned char **data_ret,
                                           size_t *len_return)
{
  interceptor_packet_segment_operation_done(pp);
  return TRUE;
}

#ifdef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
#define SSH_PACKET_IDATA_IFNUM_OFFSET          0
#define SSH_PACKET_IDATA_DST_CACHE_ID_OFFSET   sizeof(SshUInt32)
#define SSH_PACKET_IDATA_PKT_TYPE_OFFSET       (2 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_TRHDR_OFFSET          (3 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_CP_OFFSET             (4 * sizeof(SshUInt32))
#define SSH_PACKET_IDATA_MINLEN                SSH_PACKET_IDATA_CP_OFFSET

void
ssh_interceptor_packet_discard_internal_data(unsigned char *data,
                                             size_t data_len)
{
  SshUInt32 dst_cache_id;

  if (data_len == 0)
    return;

  if (data == NULL || data_len < SSH_PACKET_IDATA_MINLEN)
    {
      /* Attempt to import corrupted data. */
      SSH_DEBUG(SSH_D_FAIL, ("Unable to import internal packet data"));
      return;
    }

  dst_cache_id = SSH_GET_32BIT(data + SSH_PACKET_IDATA_DST_CACHE_ID_OFFSET);

  ssh_interceptor_packet_return_dst_entry(ssh_interceptor_context,
                                          dst_cache_id, NULL, TRUE);
}


Boolean
ssh_interceptor_packet_export_internal_data(SshInterceptorPacket pp,
                                            unsigned char **data_ret,
                                            size_t *len_return)
{
  unsigned char *data;
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  SshUInt32 dst_cache_id = 0;
  SshUInt32 transport_offset = 0;

  if (ipp->skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to export internal packet data, sk buff"));
      *data_ret = NULL;
      *len_return = 0;
      return FALSE;
    }

  data = ssh_calloc(1, SSH_PACKET_IDATA_MINLEN + sizeof(ipp->skb->cb));
  if (data == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Unable to export internal packet data"));
      *data_ret = NULL;
      *len_return = 0;
      return FALSE;
    }

  SSH_PUT_32BIT(data, SSH_PACKET_IDATA_IFNUM_OFFSET);

  dst_cache_id =
    ssh_interceptor_packet_cache_dst_entry(ssh_interceptor_context, pp);
  SSH_PUT_32BIT(data + SSH_PACKET_IDATA_DST_CACHE_ID_OFFSET, dst_cache_id);

  SSH_PUT_8BIT(data + SSH_PACKET_IDATA_PKT_TYPE_OFFSET, ipp->skb->pkt_type);

  transport_offset = (SshUInt32)(SSH_SKB_GET_TRHDR(ipp->skb) - ipp->skb->data);

  SSH_PUT_32BIT(data + SSH_PACKET_IDATA_TRHDR_OFFSET, transport_offset);
  memcpy(data + SSH_PACKET_IDATA_CP_OFFSET, ipp->skb->cb,
         sizeof(ipp->skb->cb));

  *data_ret = data;
  *len_return = SSH_PACKET_IDATA_MINLEN + sizeof(ipp->skb->cb);

  return TRUE;
}

Boolean
ssh_interceptor_packet_import_internal_data(SshInterceptorPacket pp,
                                            const unsigned char *data,
                                            size_t len)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;
  SshUInt32 orig_ifnum;
  SshUInt32 dst_cache_id;
  SshUInt32 transport_offset;
  Boolean remove_only = FALSE;

  if (ipp->skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to import internal packet data, no skb"));
      return FALSE;
    }

  if (len == 0)
    {
      /* No data to import, i.e. packet created by engine. */
      ipp->original_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
      ipp->skb->pkt_type = PACKET_HOST;
      return TRUE;
    }

  if (data == NULL || len < (SSH_PACKET_IDATA_MINLEN + sizeof(ipp->skb->cb)))
    {
      /* Attempt to import corrupted data. */
      SSH_DEBUG(SSH_D_FAIL, ("Unable to import internal packet data"));
      return FALSE;
    }

  orig_ifnum = SSH_GET_32BIT(data + SSH_PACKET_IDATA_IFNUM_OFFSET);
  ipp->original_ifnum = orig_ifnum;

  dst_cache_id = SSH_GET_32BIT(data + SSH_PACKET_IDATA_DST_CACHE_ID_OFFSET);

  if (pp->flags & SSH_PACKET_UNMODIFIED)
    remove_only = FALSE;
  ssh_interceptor_packet_return_dst_entry(ssh_interceptor_context,
                                          dst_cache_id, pp, remove_only);

  ipp->skb->pkt_type = SSH_GET_8BIT(data + SSH_PACKET_IDATA_PKT_TYPE_OFFSET);
  transport_offset = SSH_GET_32BIT(data + SSH_PACKET_IDATA_TRHDR_OFFSET);

  SSH_SKB_SET_TRHDR(ipp->skb, ipp->skb->data + transport_offset);

  memcpy(ipp->skb->cb, data + SSH_PACKET_IDATA_CP_OFFSET,
         sizeof(ipp->skb->cb));

  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */

#ifdef INTERCEPTOR_HAS_PACKET_CACHE
SshInterceptorPacket
ssh_interceptor_packet_cache(SshInterceptor interceptor,
                             SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket src = (SshInterceptorInternalPacket) pp;
  SshInterceptorInternalPacket dst;

  /* Allocate a wrapper structure */
  dst = ssh_freelist_packet_get(interceptor, TRUE);
  if (dst == NULL)
    {
      SSH_LINUX_STATISTICS(interceptor,
      { interceptor->stats.num_failed_allocs++; });
      return NULL;
    }

  dst->interceptor = src->interceptor;
  dst->packet = src->packet;
  dst->packet.next = NULL;

  dst->original_ifnum = src->original_ifnum;

  SSH_LINUX_STATISTICS(interceptor,
  {
    interceptor->stats.num_allocated_packets++;
    interceptor->stats.num_allocated_packets_total++;
  });

  if (src->skb)
    dst->skb = skb_get(src->skb);

  return (SshInterceptorPacket) dst;
}
#endif /* INTERCEPTOR_HAS_PACKET_CACHE */

#ifdef INTERCEPTOR_HAS_PACKET_DETACH
void
ssh_interceptor_packet_detach(SshInterceptorPacket packet)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) packet;

#ifdef KERNEL
  /* If the packet has an associated SKB and that SKB is associated
     with a socket, orphan the skb from it's owner. */
  if (ipp->skb != NULL)
    skb_orphan(ipp->skb);
#endif /* KERNEL */
}
#endif /* INTERCEPTOR_HAS_PACKET_DETACH */


/********************* Internal packet utility functions *********************/

/* Align requested offset of packet data to word boundary. This may
   reallocate packet data. */
Boolean
ssh_interceptor_packet_align(SshInterceptorPacket pp, size_t offset)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  unsigned long addr;
  size_t word_size, bytes;
  size_t tailroom;

  word_size = sizeof(int *);
  SSH_ASSERT(word_size < SSH_INTERCEPTOR_PACKET_TAIL_ROOM);

  addr = (unsigned long) (ipp->skb->data + offset);

  bytes = (size_t)((((addr + word_size - 1) / word_size) * word_size) - addr);
  if (bytes == 0)
    return TRUE;

  if (!skb_shared(ipp->skb) && !skb_cloned(ipp->skb))
    {
      /* Move skb header data towards tail. */
      tailroom = ipp->skb->end - ipp->skb->tail;
      if (tailroom >= bytes)
        {
          memmove(ipp->skb->data + bytes, ipp->skb->data, ipp->skb->len);
          ipp->skb->data += bytes;

          /* This works for both pointers and offsets. */
          ipp->skb->tail += bytes;

          tailroom = ipp->skb->end - ipp->skb->tail;
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Aligning skb->data %p at offset %d to word "
                     "boundary (word_size %d), headroom %d tailroom %d",
                     ipp->skb->data, (int) offset, (int) word_size,
                     (int) skb_headroom(ipp->skb), (int) tailroom));

          return TRUE;
        }

      /* Move skb header data towards head. */
      else if (skb_headroom(ipp->skb) >= (word_size - bytes))
        {
          bytes = word_size - bytes;

          memmove(ipp->skb->data - bytes, ipp->skb->data, ipp->skb->len);
          ipp->skb->data -= bytes;
          ipp->skb->tail -= bytes;

          tailroom = ipp->skb->end - ipp->skb->tail;
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Aligning skb->data %p at offset %d to word "
                     "boundary (word_size %d), headroom %d tailroom %d",
                     ipp->skb->data, (int) offset, (int) word_size,
                     (int) skb_headroom(ipp->skb), (int) tailroom));

          return TRUE;
        }
    }

  /* No headroom or tailroom, reallocate skb header. */
  SSH_DEBUG(SSH_D_HIGHOK,
            ("Reallocating %sskb header: header length %d "
             "resulting headroom %d tailroom %d",
             (skb_shared(ipp->skb) ? "shared " :
              (skb_cloned(ipp->skb) ? "cloned " : "")),
             (int) skb_headlen(ipp->skb),
             (int) SSH_INTERCEPTOR_PACKET_HEAD_ROOM + bytes,
             (int) SSH_INTERCEPTOR_PACKET_TAIL_ROOM));

  ipp->skb = skb_share_check(ipp->skb, SSH_LINUX_ALLOC_SKB_GFP_MASK);
  if (ipp->skb == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("skb_share_check() failed"));
      goto fail;
    }

  /* Copy skb header and reserve enough headroom and tailroom. */
  if (pskb_expand_head(ipp->skb,
                       SSH_INTERCEPTOR_PACKET_HEAD_ROOM + bytes,
                       SSH_INTERCEPTOR_PACKET_TAIL_ROOM,
                       SSH_LINUX_ALLOC_SKB_GFP_MASK))
    {
      SSH_DEBUG(SSH_D_FAIL, ("pskb_expand_head() failed"));
      goto fail;
    }

  return TRUE;

 fail:
  SSH_DEBUG(SSH_D_LOWOK, ("Packet align failed, freeing packet %p", pp));
  ssh_interceptor_packet_free(pp);
  return FALSE;
}

/* Verify that packet has enough headroom. */
struct sk_buff *
ssh_interceptor_packet_verify_headroom(struct sk_buff *skbp,
                                       size_t media_header_len)
{
  SshUInt32 required_headroom;
  struct sk_buff *skbp2;

  SSH_ASSERT(skbp != NULL);
  SSH_ASSERT(skbp->dev != NULL);

  required_headroom = LL_RESERVED_SPACE(skbp->dev);
#if (SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM > 0)
  if (required_headroom < SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM)
    required_headroom = SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM;
#endif /* (SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM > 0) */

  if (unlikely(required_headroom > media_header_len &&
               skb_headroom(skbp) < (required_headroom - media_header_len)))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("skb does not have enough headroom for device %d, "
                 "reallocating skb headroom",
                 skbp->dev->ifindex));
      skbp2 = skb_realloc_headroom(skbp,
                                   (required_headroom - media_header_len));
      kfree_skb(skbp);

      return skbp2;
    }

  return skbp;
}

#ifdef DEBUG_LIGHT
/* Dump packet data using SSH_DEBUG_HEXDUMP(). */
Boolean
ssh_interceptor_packet_hexdump(SshInterceptorInternalPacket ipp)
{
  const unsigned char *segment;
  size_t segment_len;

  SSH_DEBUG(SSH_D_PCKDMP,
            ("Packet %p skb %p length %d flags 0x%08x%s",
             ipp,
             ipp->skb,
             (ipp->skb != NULL ? ipp->skb->len : 0),
             ipp->packet.flags,
             (ipp->packet.flags & SSH_PACKET_HWCKSUM) ? " [hwcsum]" : ""));

  ssh_interceptor_packet_reset_iteration(&ipp->packet, 0,
                                     ssh_interceptor_packet_len(&ipp->packet));
  while (ssh_interceptor_packet_next_iteration_read(&ipp->packet, &segment,
                                                    &segment_len))
    {
    SSH_DEBUG_HEXDUMP(SSH_D_PCKDMP,
                      ("Segment length %d", (int) segment_len),
                      segment, segment_len);
      ssh_interceptor_packet_done_iteration_read(&ipp->packet, &segment,
                                                 &segment_len);
    }
  if (segment != NULL)
    return FALSE;

  return TRUE;
}
#endif /* DEBUG_LIGHT */
