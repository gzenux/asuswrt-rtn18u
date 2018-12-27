/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic interceptor packet modification routines.  These functions
   are implemented using the packet interation functions.  It might be
   more efficient to re-implement these in the platform specific code.
*/

#include "sshincludes.h"
#include "interceptor.h"

#define SSH_DEBUG_MODULE "SshEnginePacket"

/* Since all functions of this file might be implemented in platform
   specific interceptor files, this file can end up being empty.  This
   declaration is here to prevent any warnings from that empty file.
   It is not used for anything. */
typedef enum
{
  SSH_EMPTY1
} SshToMakeThisFileNotEmpty;

#ifndef INTERCEPTOR_HAS_PACKET_COPYIN
/* Copies data into the packet. Space for the new data must already have been
   allocated. It is a fatal error to attempt to copy beyond the allocated
   packet. Multiple threads may call this function concurrently, but not for
   the same packet. Returns TRUE if successfull and FALSE otherwise. If error
   occurs then the pp is already freed by this function, and the caller must
   not refer to it anymore.

   There is a generic version of this function inside the engine, in case
   interceptor does not want to implement this. If interceptor implements this
   function it must define INTERCEPTOR_HAS_PACKET_COPYIN from the
   ipsec/configure.in.inc. */
Boolean ssh_interceptor_packet_copyin(SshInterceptorPacket pp, size_t offset,
                                      const unsigned char *buf, size_t len)
{
  unsigned char *ucp;
  size_t segment_len;

  SSH_DEBUG(SSH_D_MIDSTART, ("copyin pp 0x%lx, ofs %ld, buf 0x%lx, len %ld",
                (long)pp, (long)offset, (long)buf, (long)len));

  ssh_interceptor_packet_reset_iteration(pp, offset, len);
  while (ssh_interceptor_packet_next_iteration(pp, &ucp, &segment_len))
    {
      memcpy(ucp, buf, segment_len);
      buf += segment_len;
      ssh_interceptor_packet_done_iteration(pp, &ucp, &segment_len);
    }
  if (ucp != NULL)
    return FALSE;
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPYIN */

#ifndef INTERCEPTOR_HAS_PACKET_COPYOUT
/* Copies data out from the packet.  Space for the new data must
   already have been allocated.  It is a fatal error to attempt to
   copy beyond the allocated packet. Multiple threads may call this
   function concurrently, but not for the same packet.

   There is a generic version of this function inside the engine, in case
   interceptor does not want to implement this. If interceptor implements this
   function it must define INTERCEPTOR_HAS_PACKET_COPYOUT from the
   ipsec/configure.in.inc. */
void ssh_interceptor_packet_copyout(SshInterceptorPacket pp, size_t offset,
                                    unsigned char *buf, size_t len)
{
  const  unsigned char *ucp;
  size_t segment_len;

  SSH_DEBUG(SSH_D_MIDSTART,
            ("copyout pp 0x%lx, ofs %ld, buf 0x%lx, len %ld",
             (long)pp, (long)offset, (long)buf, (long)len));

  ssh_interceptor_packet_reset_iteration(pp, offset, len);
  while (ssh_interceptor_packet_next_iteration_read(pp, &ucp, &segment_len))
    {
      memcpy(buf, ucp, segment_len);
      buf += segment_len;
      ssh_interceptor_packet_done_iteration_read(pp, &ucp, &segment_len);
    }
  SSH_ASSERT(ucp == NULL);      /* next_iteration_read cannot fail. */
}
#endif /* INTERCEPTOR_HAS_PACKET_COPYOUT */

#ifndef INTERCEPTOR_HAS_PACKET_COPY
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
   implements this function it must define INTERCEPTOR_HAS_PACKET_COPY from the
   ipsec/configure.in.inc. */
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
          ssh_interceptor_packet_done_iteration_read(source_pp, &seg, &seglen);
          return FALSE;
        }
      segoff += seglen;
      ssh_interceptor_packet_done_iteration_read(source_pp, &seg, &seglen);
    }
  SSH_ASSERT(seg == NULL);      /* next_iteration_read cannot fail. */
  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_COPY */

#ifndef INTERCEPTOR_HAS_PACKET_ALLOC_AND_COPY_EXT_DATA
SshInterceptorPacket ssh_interceptor_packet_alloc_and_copy_ext_data(
                                                SshInterceptor interceptor,
                                                SshInterceptorPacket pp,
                                                size_t total_len)
{
  SshInterceptorPacket new_pp;

  /* Actually, only the `total_length' argument is interesting.
     Everything else will be reset when the public data is copied. */
  new_pp = ssh_interceptor_packet_alloc(interceptor,
                                        pp->flags
                                        & (SSH_PACKET_FROMPROTOCOL
                                           | SSH_PACKET_FROMADAPTER
                                           | SSH_PACKET_HWCKSUM),
                                        pp->protocol,
                                        pp->ifnum_in,
                                        pp->ifnum_out,
                                        total_len);
  if (new_pp == NULL)
    return NULL;

  /* Copy all public data from the source packet. */
  memcpy(new_pp, pp, sizeof(*pp));

  return new_pp;
}
#endif /* INTERCEPTOR_HAS_PACKET_ALLOC_AND_COPY_EXT_DATA */

#ifndef INTERCEPTOR_HAS_PACKET_CACHE
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

  flags = pp->flags & (SSH_PACKET_FROMPROTOCOL | SSH_PACKET_FROMADAPTER
                       | SSH_PACKET_HWCKSUM);
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
#endif /* INTERCEPTOR_HAS_PACKET_CACHE */


#ifndef INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES
Boolean ssh_interceptor_packet_export_internal_data(SshInterceptorPacket pp,
                                                    unsigned char **data_ret,
                                                    size_t *len_return)
{
  SSH_ASSERT(data_ret && len_return);

  *len_return = 0;
  *data_ret = NULL;

  return TRUE;
}

Boolean ssh_interceptor_packet_import_internal_data(SshInterceptorPacket pp,
                                                    const unsigned char *data,
                                                    size_t len)
{
  /* notice: data might be non-NULL, don't assert that */
  SSH_ASSERT(!len);

  return TRUE;
}
#endif /* INTERCEPTOR_HAS_PACKET_INTERNAL_DATA_ROUTINES */
