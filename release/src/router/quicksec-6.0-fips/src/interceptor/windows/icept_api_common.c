/**
   @copyright
   Copyright (c) 2009 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the platform/interceptor independent implementation of
   interceptor API functions for Windows operating systems.

   The description of these functions can be found at interceptor.h.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/
#include "sshincludes.h"
#include "interceptor.h"
#include "interceptor_i.h"
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
#include "win_ip_route.h"
#include "wan_interface.h"
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */

/*--------------------------------------------------------------------------
  DEFINITIONS
  --------------------------------------------------------------------------*/
#define SSH_DEBUG_MODULE "SshInterceptorAPI"

/*--------------------------------------------------------------------------
  EXTERNALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  GLOBALS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL VARIABLES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  LOCAL FUNCTION PROTOTYPES
  --------------------------------------------------------------------------*/

Boolean
ssh_interceptor_packet_done_iteration_read(SshInterceptorPacket ip,
  const UCHAR** buf,
  size_t* len);

/*--------------------------------------------------------------------------
  EXPORTED FUNCTIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  ssh_interceptor_get_api_version()
  
  Return API version implemented by the interceptor. 
  --------------------------------------------------------------------------*/
SshUInt32
ssh_interceptor_get_api_version(void)
{
  return 1;
}


/*--------------------------------------------------------------------------
  ssh_interceptor_create()
  
  Initializes the interceptor object.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_create(PVOID machine_context,
		       SshInterceptor* interceptor_return)
{
  /* Fill in interceptor_return and return success. */
  *interceptor_return = (SshInterceptor) machine_context;
  return TRUE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_set_packet_cb()
  
  Sets the packet callback.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_set_packet_cb(SshInterceptor interceptor,
			      SshInterceptorPacketCB packet_cb,
			      void *callback_context)
{
  SSH_ASSERT(interceptor != NULL);

  /* Fill in packet callback and context, and return success. */
  interceptor->packet_cb = packet_cb;
  interceptor->packet_cb_ctx = callback_context;

  return TRUE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_open()
  
  Enables engine - interceptor communication.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_open(SshInterceptor interceptor,
                     SshInterceptorPacketCB packet_cb,
                     SshInterceptorInterfacesCB interfaces_cb,
                     SshInterceptorRouteChangeCB route_change_cb,
                     PVOID context)
{
  SSH_ASSERT(interceptor != NULL);

  /* Initialize the callback functions */
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  SSH_ASSERT(interfaces_cb != NULL_FNPTR);
  SSH_ASSERT(route_change_cb != NULL_FNPTR);

  interceptor->interfaces_cb = interfaces_cb;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
  interceptor->engine_ctx = context;

  if (packet_cb != NULL_FNPTR)
    {
      interceptor->packet_cb = packet_cb;
      interceptor->packet_cb_ctx = context;
    }
  SSH_ASSERT(interceptor->packet_cb != NULL_FNPTR);

  return TRUE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_stop()
  
  Disables SSH Interceptor object.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_stop(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);

  return TRUE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_close()
  
  Deinitialize engine - interceptor communication.
  --------------------------------------------------------------------------*/
VOID
ssh_interceptor_close(SshInterceptor interceptor)
{
  SSH_ASSERT(interceptor != NULL);

  /* Clear attributes for engine communication */
  interceptor->engine_ctx = NULL;
#ifdef SSHDIST_IPSEC
#ifdef SSH_BUILD_IPSEC
  interceptor->interfaces_cb = NULL;
#endif /* SSH_BUILD_IPSEC */
#endif /* SSHDIST_IPSEC */
  interceptor->packet_cb = NULL;
}


/*--------------------------------------------------------------------------
  ssh_interceptor_get_time()
  
  Fills current wall clock time to 'seconds' and 'microseconds'. Either or 
  both of the provided pointers may be NULL. The epoch of wall clock is 
  system specific. The Windows implementation use midnight 1.1.1601 as 
  epoch.  The time is guaranteed to be monotonically increasing. The time 
  must not leap forwards or backwards when DST is taken into use. 
  --------------------------------------------------------------------------*/
void 
ssh_interceptor_get_time(SshTime *seconds, SshUInt32 *microseconds)
{
  LARGE_INTEGER system_time;
  KeQuerySystemTime(&system_time);

  system_time.QuadPart /= 10; /* Convert to microseconds */

  if (seconds)
    *seconds = system_time.QuadPart / 1000000;

  if (microseconds)
    *microseconds = (SshUInt32)(system_time.QuadPart % 1000000);
}


#ifdef SSH_BUILD_IPSEC
/*--------------------------------------------------------------------------
  ssh_interceptor_route()
  
  Retrieves routing information for a given routing key and
  then calls the completion routine.

  This ssh_interceptor_route implementation uses only the 'dst' field
  of the SshInterceptorRouteKey. It is a fatal error to call this
  function with a routing key that does not specify the destination
  address.

  --------------------------------------------------------------------------*/
VOID
ssh_interceptor_route(SshInterceptor interceptor,
                      SshInterceptorRouteKey key,
                      SshInterceptorRouteCompletion completion,
                      PVOID context)
{
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(key != NULL);

  if (interceptor->asynch_interceptor_route)
    {
      SshInterceptorRouteKey copied_key;

      copied_key = ssh_calloc(1, sizeof(*copied_key));
      if (copied_key)
        {
          *copied_key = *key;

          SSH_ASSERT(interceptor->routing_queue != NULL);

          if (ssh_ndis_wrkqueue_queue_raw_item(interceptor->routing_queue,
                                               ssh_ip_route_lookup,
                                               SSH_WORKQUEUE_FN_4_ARGS,
                                               interceptor, 
                                               copied_key, 
                                               completion, 
                                               context))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, 
                        ("Successfully scheduled work item for "
                         "asynchronous route lookup"));
              return;
            }

          ssh_free(copied_key);
        }
      
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed!"));
      (*completion)(FALSE, NULL, 0, 0, context);
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Executing route lookup synchronously"));
      ssh_ip_route_lookup(interceptor, key, completion, context);
    }
}
#endif /* SSH_BUILD_IPSEC */


/*--------------------------------------------------------------------------
  ssh_interceptor_packet_alloc()
  
  Allocates new network data packet.
  --------------------------------------------------------------------------*/
SshInterceptorPacket
ssh_interceptor_packet_alloc(SshInterceptor interceptor,
                             SshUInt32 flags,
                             SshInterceptorProtocol proto,
                             SshInterceptorIfnum ifnum_in,
                             SshInterceptorIfnum ifnum_out,
                             size_t total_len)
{
  SshCpuContext cpu_ctx;
  SshNetDataPacket packet;

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("ssh_interceptor_packet_alloc("
             "interceptor=0x%p, flags=0x%08x, proto=%u, "
             "ifnum_in=%d, ifnum_out=%d, total_len=%u)", 
             interceptor, flags, proto, 
             ifnum_in, ifnum_out, total_len));

  /* Ensure that the calling cpu is at IRQL DISPATCH_LEVEL. If not, we have
     concurrency problem with the packet pool! */
  SSH_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(total_len > 0);
  SSH_ASSERT((flags & SSH_PACKET_FROMADAPTER)
             != (flags & SSH_PACKET_FROMPROTOCOL));

  cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
  packet = ssh_packet_alloc(interceptor, 
                            &cpu_ctx->packet_pool, 
                            (SshUInt32)total_len);
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate packet!"));
      return NULL;
    }

  packet->ip.flags = flags;
  packet->ip.protocol = proto;
  packet->ip.ifnum_in = ifnum_in;
  packet->ip.ifnum_out = ifnum_out;




  packet->f.flags.packet_copied = 1; 
  packet->f.flags.allocated_packet = 1;
#ifdef DEBUG_LIGHT
  packet->f.flags.in_engine = 1;
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_HIGHOK, ("Allocated packet 0x%p", packet));

  return (&packet->ip);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_free()
  
  Deallocates network data packet.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_packet_free(SshInterceptorPacket ip)
{
  SshCpuContext cpu_ctx;
  SshNetDataPacket packet;
  SshInterceptor interceptor;

  SSH_ASSERT(ip != NULL);

  SSH_DEBUG(SSH_D_HIGHSTART, 
            ("ssh_interceptor_packet_free(ip=0x%p)", ip));

  SSH_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);
#ifdef DEBUG_LIGHT
  packet->f.flags.in_engine = 0;
#endif /* DEBUG_LIGHT */
  interceptor = packet->interceptor;
  SSH_ASSERT(interceptor != NULL);

  if (packet->complete_cb)
    {
      packet->complete_cb(packet->complete_cb_handle, 
                          packet->np, 
                          packet->complete_cb_param);
    }
  else
    {
      cpu_ctx = &interceptor->cpu_ctx[ssh_kernel_get_cpu()];
      ssh_packet_free(packet, &cpu_ctx->packet_pool);

#ifdef HAS_DELAYED_SEND_THREAD
      if (interceptor->delayed_sends)
        ssh_task_notify(&interceptor->delayed_send_thread, 
                        SSH_TASK_SIGNAL_NOTIFY);
#endif /* HAS_DELAYED_SEND_THREAD */
    }
}


/*--------------------------------------------------------------------------
  ssh_interceptor_packet_len()
  
  Returns length of given network packet.
  --------------------------------------------------------------------------*/
size_t
ssh_interceptor_packet_len(SshInterceptorPacket ip)
{
  SshNetDataPacket packet;

  SSH_ASSERT(ip != NULL);
  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  return packet->packet_len;
}


/*--------------------------------------------------------------------------
  ssh_interceptor_packet_pullup()
  
  Allocates contiguos memory region into the head of network packet.
  --------------------------------------------------------------------------*/
unsigned char *
ssh_interceptor_packet_pullup(SshInterceptorPacket ip,
                              size_t bytes)
{
  SshNetDataPacket packet;
  unsigned char *buf_addr;

  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("ssh_packet_pullup(pkt=0x%p, bytes=%u)", ip, bytes));

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  /* Check pullup request length against total packet length and adjust
     pullup length if necessary ie. pull-up length is never longer than 
     total packet len */
  bytes = MIN(bytes, packet->packet_len);

  SSH_ASSERT(packet->packet_len >= bytes);

  /* Ensure that returned data is in one continuous buffer. Make buffer 
     chain rearrangements if necessary. */
  buf_addr = ssh_packet_get_contiguous_data(packet, 0, 
                                            (SshUInt32)bytes, FALSE);
  if (buf_addr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to rearrange buffer chain of packet 0x%p "
                 "(requested continuous buffer: index=0, bytes=%u)",
                 packet, bytes));
      ssh_interceptor_packet_free(ip);
    }

  return buf_addr;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_pullup_read()
  
  Allocates contiguous memory region into the head of network packet.
  (read-only).
  --------------------------------------------------------------------------*/
#ifndef NEED_PACKET_READONLY_DEFINES
const unsigned char*
ssh_interceptor_packet_pullup_read(SshInterceptorPacket ip,
                                   size_t bytes)
{
  SshNetDataPacket packet;
  unsigned char *buf_addr;

  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(bytes <= SSH_INTERCEPTOR_MAX_PULLUP_LEN);

  SSH_DEBUG(SSH_D_LOWSTART,
            ("ssh_packet_pullup_read(pkt=0x%p, bytes=%u)", ip, bytes));

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  /* Check pullup request length against total packet length and adjust
     pullup length if necessary ie. pull-up length is never longer than 
     total packet len */
  bytes = MIN(bytes, packet->packet_len);

  /* Ensure that returned data is in one continuous buffer. Make buffer 
     chain rearrangements if necessary. */
  buf_addr = ssh_packet_get_contiguous_data(packet, 0, 
                                            (SshUInt32)bytes, TRUE);
  if (buf_addr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to rearrange buffer chain of packet 0x%p "
                 "(requested continuous buffer: index=0, bytes=%u)",
                 packet, bytes));
      ssh_interceptor_packet_free(ip);
    }

  return buf_addr;
}
#endif /* !NEED_PACKET_READONLY_DEFINES */

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_insert()
  
  Inserts space for new data into a given position of network packet.
  --------------------------------------------------------------------------*/
unsigned char *
ssh_interceptor_packet_insert(SshInterceptorPacket ip,
                              size_t offset,
                              size_t bytes)
{
  unsigned char *ret_ptr = NULL;
  SshNetDataPacket packet;
  SshUInt32 space_needed;
  Boolean move_head = TRUE;

  SSH_ASSERT(ip != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, 
            ("ssh_interceptor_packet_insert(ip=0x%p, offset=%u, bytes=%u)",
             ip, offset, bytes));

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  SSH_DUMP_PACKET(SSH_D_MY5, "Packet before insert", packet);

  if ((packet->ip.protocol != SSH_PROTOCOL_ETHERNET)
      && (offset == 0) && (bytes == SSH_ETHERH_HDRLEN)
      && (packet->f.flags.media_header_deleted)
      && (packet->backfill_space >= bytes))
    {
      SSH_DEBUG(SSH_D_MY5, ("Inserting media header to packet 0x%p", packet));

      if (!ssh_packet_retreat_data_start(packet, (SshUInt16)bytes, &ret_ptr))
        goto failed;

      packet->f.flags.media_header_deleted = 0;

      SSH_DUMP_PACKET(SSH_D_MY5, "Packet after insert", packet);

      return (ret_ptr);
    }





  if (packet->f.flags.packet_copied == 0)
    {
      /* It's time to copy the original data. */
      if (!ssh_packet_copy_original_data(packet))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to copy data!"));
          ssh_interceptor_packet_free(&packet->ip);
          return NULL;
        }
    }

  /* Calculate whether it's more efficient to move head or tail of the 
     packet. Tail is moved also in case when there is not enough backfill 
     space left (this will never happen in real life, assuming that we have 
     allocated enough backfill space in packet). */
  if ((offset > (packet->packet_len / 2))
      || (packet->backfill_space < bytes))
    {
      space_needed = packet->packet_len + (SshUInt32)bytes;
      move_head = FALSE;
    }
  else
    {
      space_needed = packet->packet_len;
    }

  /* Check whether the buffer chain is long enough. */
  if (packet->data_space < space_needed)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Too long packet!"));
      ssh_interceptor_packet_free(&packet->ip);
      return NULL;
    }

  /* Append? */
  if (offset == packet->packet_len)
    {
      SSH_DEBUG(SSH_D_MY5, ("Inserting padding..."));
      if (!ssh_packet_resize(packet, 
                             packet->packet_len + (SshUInt32)bytes))
        goto failed;
    }
  else
    {
      if (move_head)
        {
          SSH_DEBUG(SSH_D_MY5, ("Moving HEAD of packet..."));
          if (!ssh_packet_move_head(packet, 
                                    (SshUInt32)offset, 
                                    0 - (SshInt32)bytes))
            goto failed;
        }
      else 
        {
          SSH_DEBUG(SSH_D_MY5, ("Moving TAIL of packet..."));
          if (!ssh_packet_move_tail(packet, 
                                    (SshUInt32)offset, 
                                    (SshInt32)bytes))
            goto failed;
        }
    }

  ret_ptr = ssh_packet_get_contiguous_data(packet, 
                                           (SshUInt32)offset, 
                                           (SshUInt32)bytes,
                                           FALSE);
  if (ret_ptr == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to rearrange buffer chain of packet 0x%p "
                 "(requested continuous buffer: offset=%u, bytes=%u)",
                 packet, offset, bytes));
      ssh_interceptor_packet_free(&packet->ip);
      return NULL;
    }

  SSH_DUMP_PACKET(SSH_D_MY5, "Packet after insert", packet);

  return ret_ptr;

 failed:
  SSH_DEBUG(SSH_D_FAIL,
            ("ssh_interceptor_packet_insert() failed"));
  ssh_interceptor_packet_free(&packet->ip);
  return NULL;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_delete()
  
  Deletes data from a given position of network packet.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_packet_delete(SshInterceptorPacket ip,
                              size_t offset,
                              size_t bytes)
{
  SshNetDataPacket packet;
  Boolean move_head = TRUE;

  SSH_ASSERT(ip != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, 
            ("ssh_interceptor_packet_delete(ip=0x%p, offset=%u, bytes=%u",
             ip, offset, bytes));

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  SSH_DUMP_PACKET(SSH_D_MY5, "Packet before delete", packet);

  if ((packet->ip.protocol == SSH_PROTOCOL_ETHERNET)
      && (offset == 0) && (bytes == SSH_ETHERH_HDRLEN)
      && (packet->f.flags.media_header_deleted == 0))
    {
      if (!ssh_packet_advance_data_start(packet, (SshUInt16)bytes, NULL))
        goto failed;

      packet->f.flags.media_header_deleted = 1;

      SSH_DUMP_PACKET(SSH_D_MY5, "Packet after delete", packet);

      SSH_DEBUG(SSH_D_LOWOK, 
                ("Ethernet header deleted from packet 0x%p", packet));

      return TRUE;
    }

  /* Calculate whether it's more efficient to move head or tail of the 
     packet. */
  if (offset > (packet->packet_len / 2))
    move_head = FALSE;

  if ((packet->f.flags.packet_copied == 0)
      && (packet->f.flags.from_local_stack))
    {
      /* Time to copy the data from original packet */
      if (!ssh_packet_copy_original_data(packet))
        goto failed;
    }

  if (offset + bytes == packet->packet_len)
    {
      SSH_DEBUG(SSH_D_MY5, ("Removing padding..."));
      if (!ssh_packet_resize(packet, packet->packet_len - (SshUInt32)bytes))
        goto failed;
    }
  else
    {
      if (move_head)
        {
          SSH_DEBUG(SSH_D_MY5, ("Moving HEAD of packet..."));
          if (!ssh_packet_move_head(packet, 
                                    (SshUInt32)offset, 
                                    (SshInt32)bytes))
            goto failed;
        }
      else 
        {
          SSH_DEBUG(SSH_D_MY5, ("Moving TAIL of packet..."));
          if (!ssh_packet_move_tail(packet, 
                                    (SshUInt32)(offset + bytes), 
                                    0 - (SshInt32)bytes))
            goto failed;
        }
    }

  SSH_DUMP_PACKET(SSH_D_MY5, "Packet after delete", packet);
  return TRUE;

 failed:
  SSH_DEBUG(SSH_D_FAIL, ("ssh_interceptor_packet_delete() failed"));
  ssh_interceptor_packet_free(&packet->ip);
  return FALSE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_copyin()
  
  Copies data from buffer into the network packet.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_packet_copyin(SshInterceptorPacket ip,
                              size_t offset,
                              const unsigned char *buf,
                              size_t len)
{
  SshNetDataPacket packet;

  SSH_ASSERT(ip != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, 
            ("ssh_interceptor_packet_copyin("
             "ip=0x%p, offset=%u, buf=0x%p, len=%u)",
             ip, offset, buf, len));

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  if (!ssh_packet_copyin(packet, (SshUInt32)offset, buf, (SshUInt32)len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to copy data!"));
      ssh_interceptor_packet_free(ip);
      return FALSE;
    }

  return TRUE;
}


/*--------------------------------------------------------------------------
  ssh_interceptor_packet_copyout()
  
  Copies data from network packet into a buffer.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_packet_copyout(SshInterceptorPacket ip,
                               size_t offset,
                               unsigned char *buf,
                               size_t len)
{
  SshNetDataPacket packet;

  SSH_ASSERT(ip != NULL);

  SSH_DEBUG(SSH_D_LOWSTART, 
            ("ssh_interceptor_packet_copyout("
             "ip=0x%p, offset=%u, buf=0x%p, len=%u)",
             ip, offset, buf, len));

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  ssh_packet_copyout(packet, (SshUInt32)offset, buf, (SshUInt32)len);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_reset_iteration()
  
  Resets internal packet iterator.
  --------------------------------------------------------------------------*/
void
ssh_interceptor_packet_reset_iteration(SshInterceptorPacket ip,
                                       size_t offset,
                                       size_t total_bytes)
{
  SshNetDataPacket packet;
  SshNetDataBufferHeader buf_hdr;

  SSH_ASSERT(ip != NULL);

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  if (total_bytes == 0)
    {
      packet->iter_remaining = 0;
      return;
    }

  SSH_ASSERT(offset + total_bytes <= packet->packet_len);

  packet->iter_next = NULL;
  packet->iter_offset = 0;
  if (!ssh_packet_get_buffer(packet, (SshUInt32)offset, 
                             &buf_hdr, 
                             &packet->iter_next,
                             &packet->iter_offset))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get buffer"));
      return;
    }

  packet->iter_remaining = (SshUInt32)total_bytes;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_next_iteration()
  
  Retrieves next data segment from network packet.
  --------------------------------------------------------------------------*/
Boolean 
ssh_interceptor_packet_next_iteration(SshInterceptorPacket ip,
                                      unsigned char **buf,
                                      size_t *len)
{
  SshNetDataPacket packet;

  SSH_ASSERT(ip != NULL);
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(len != NULL);

  packet = CONTAINING_RECORD(ip, SshNetDataPacketStruct, ip);

  if (packet->iter_remaining == 0)
    {
      *buf = NULL;
      *len = 0;
      return FALSE;
    }
  else if (packet->iter_next == NULL)
    {
      goto failed;
    }
  else
    {
      SshUInt32 data_len;

      if (!ssh_query_data_block(packet->iter_next, buf, &data_len))
        goto failed;

      SSH_ASSERT(packet->iter_offset < data_len);

      if (packet->iter_offset)
        {
          data_len -= (SshUInt32)packet->iter_offset;
          *buf += packet->iter_offset;
          packet->iter_offset = 0;
        }

      *len = data_len;
      if (*len > packet->iter_remaining)
        *len = packet->iter_remaining;

      packet->iter_remaining -= (SshUInt32)*len;

      packet->iter_next = ssh_get_next_data_block(packet->iter_next);

#ifdef DEBUG_LIGHT
      if (packet->iter_remaining 
          && (packet->iter_next == NULL))
        {
          SSH_NOTREACHED;
        }
#endif /* DEBUG_LIGHT */
    }

  return TRUE;

 failed:
  *buf = (unsigned char *)-1;
  *len = 0;
  ssh_interceptor_packet_free(&packet->ip);
  return FALSE;
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_done_iteration()
  
  Releases the segment acquired with ssh_interceptor_packet_next_iteration().
  --------------------------------------------------------------------------*/
Boolean 
ssh_interceptor_packet_done_iteration(SshInterceptorPacket ip,
                                      unsigned char **buf,
                                      size_t *len)
{
  return TRUE;
}

#ifndef NEED_PACKET_READONLY_DEFINES
/*--------------------------------------------------------------------------
  ssh_interceptor_packet_reset_iteration_read()
  
  Resets internal packet iterator.
  --------------------------------------------------------------------------*/
VOID
ssh_interceptor_packet_reset_iteration_read(SshInterceptorPacket ip,
                                            size_t offset,
                                            size_t total_bytes)
{
  ssh_interceptor_packet_reset_iteration(ip, offset, total_bytes);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_next_iteration_read()
  
  Retrieves next data segment from network packet.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_packet_next_iteration_read(SshInterceptorPacket ip,
                                           const UCHAR** buf,
                                           size_t* len)
{
  return ssh_interceptor_packet_next_iteration(ip, (unsigned char **)buf, len);
}

/*--------------------------------------------------------------------------
  ssh_interceptor_packet_done_iteration_read()
  
  Releases data segment.
  --------------------------------------------------------------------------*/
Boolean
ssh_interceptor_packet_done_iteration_read(SshInterceptorPacket ip,
                                           const UCHAR** buf,
                                           size_t* len)
{
  return TRUE;
}
#endif /* NEED_PACKET_READONLY_DEFINES */

#ifdef INTERCEPTOR_HAS_USER_MODE_FORWARDER

Boolean 
ssh_interceptor_packet_export_internal_data(SshInterceptorPacket pp,
                                            unsigned char **data_ret,
                                            size_t *len_return)
{
  *data_ret = NULL;
  *len_return = 0;
  return TRUE;
}

Boolean 
ssh_interceptor_packet_import_internal_data(SshInterceptorPacket pp,
                                            const unsigned char *data,
                                            size_t len)
{
  return TRUE;
}

#endif /* INTERCEPTOR_HAS_USER_MODE_FORWARDER */


