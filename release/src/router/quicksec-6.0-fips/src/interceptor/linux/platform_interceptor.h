/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Additional platform-dependent things. This file is included from
   engine-interface/interceptor.h, provided that autoconfig has set
   INTERCEPTOR_HAS_PLATFORM_INCLUDE preprocessor macro.
*/

#ifndef SSH_PLATFORM_INTERCEPTOR_H
#define SSH_PLATFORM_INTERCEPTOR_H 1

#ifndef KERNEL_INTERCEPTOR_USE_FUNCTIONS
#include "linux_packet_internal.h"

/* Declarations of worker functions for more complex packet operations. */
unsigned char *
interceptor_packet_pullup(SshInterceptorPacket pp, size_t bytes);
const unsigned char *
interceptor_packet_pullup_read(SshInterceptorPacket pp, size_t bytes);
unsigned char *
interceptor_packet_insert(SshInterceptorPacket pp,
                          size_t offset, size_t bytes);
Boolean
interceptor_packet_delete(SshInterceptorPacket pp,
                          size_t offset, size_t bytes);

/* Static inline functions for most common simple packet operations. */
static inline size_t
ssh_interceptor_packet_len_i(SshInterceptorPacket pp)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;
  return ipp->skb->len;
}
#define ssh_interceptor_packet_len(pp) ssh_interceptor_packet_len_i(pp)

static inline unsigned char *
ssh_interceptor_packet_pullup_i(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  /* Pullup requests data from the header of a writable skb. */
  if (likely(skb_headlen(ipp->skb) >= bytes
             && !skb_shared(ipp->skb) && SSH_SKB_WRITABLE(ipp->skb, bytes)))
    return ipp->skb->data;

  else
    return interceptor_packet_pullup(pp, bytes);
}
#define ssh_interceptor_packet_pullup(pp, bytes) \
  ssh_interceptor_packet_pullup_i(pp, bytes)

static inline const unsigned char *
ssh_interceptor_packet_pullup_read_i(SshInterceptorPacket pp, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  /* Requested data is in the skb header, return pointer to skb data. */
  if (likely(skb_headlen(ipp->skb) >= bytes))
    return ipp->skb->data;

  else
    return interceptor_packet_pullup_read(pp, bytes);
}
#define ssh_interceptor_packet_pullup_read(pp, bytes) \
  ssh_interceptor_packet_pullup_read_i(pp, bytes)

static inline unsigned char *
ssh_interceptor_packet_insert_i(SshInterceptorPacket pp,
                                size_t offset, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  /* Most common case: insertion at offset 0 and there is enough headroom. */
  if (likely(offset == 0
             && (skb_headroom(ipp->skb) >=
                 (bytes + SSH_INTERCEPTOR_PACKET_HARD_HEAD_ROOM))
             && !skb_shared(ipp->skb) && SSH_SKB_WRITABLE(ipp->skb, 0)))
    {
      return skb_push(ipp->skb, bytes);
    }

  /* Second most simple case: insertion of packet trailer to a linear skb
     that is not shared or cloned when there is enough tailroom. */
  else if (likely(offset == ipp->skb->len && !skb_is_nonlinear(ipp->skb)
                  && skb_tailroom(ipp->skb) >= bytes
                  && !skb_shared(ipp->skb) && !skb_cloned(ipp->skb)))
    {
      /* Advance skb tail. */
      ipp->skb->tail += bytes;
      ipp->skb->len += bytes;
      return ipp->skb->data + offset;
    }

  else
    return interceptor_packet_insert(pp, offset, bytes);
}
#define ssh_interceptor_packet_insert(pp, offset, bytes) \
  ssh_interceptor_packet_insert_i(pp, offset, bytes)

static inline Boolean
ssh_interceptor_packet_delete_i(SshInterceptorPacket pp,
                                size_t offset, size_t bytes)
{
  SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket) pp;

  /* Most simple case: deletion of packet head from a skb that is not
     shared or cloned. */
  if (likely(offset == 0 && skb_headlen(ipp->skb) >= bytes
             && !skb_shared(ipp->skb) && SSH_SKB_WRITABLE(ipp->skb, bytes)))
    {
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
      /* Remove amount of deleted bytes from tail of skb. */
      ipp->skb->tail -= bytes;
      ipp->skb->len -= bytes;
      return TRUE;
    }

  else
    return interceptor_packet_delete(pp, offset, bytes);
}
#define ssh_interceptor_packet_delete(pp, bytes, offset) \
  ssh_interceptor_packet_delete_i(pp, bytes, offset)

#endif /* !KERNEL_INTERCEPTOR_USE_FUNCTIONS */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef PLATFORM_OCTEON_LINUX
#include "linux_octeon_interceptor.h"
#endif /* PLATFORM_OCTEON_LINUX */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#endif /* SSH_PLATFORM_INTERCEPTOR_H */
