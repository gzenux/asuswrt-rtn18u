/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS 5.x compatible packet pool functions for Windows
   2K/XP/2K3 interceptor object.
*/

void SSH_PACKET_POOL_API 
ssh_packet_query_media_header(PNDIS_PACKET pkt,
                              SshMediaHeader *media_hdr)
{
  PNDIS_BUFFER buf;
  unsigned char *buf_addr;
  unsigned int buf_len;
  unsigned int pkt_len;

  SSH_ASSERT(pkt != NULL);
  SSH_ASSERT(media_hdr != NULL);

  *media_hdr = NULL;

  /* Get media header from the 1st not-empty buffer */
  NdisGetFirstBufferFromPacketSafe(pkt, &buf, &buf_addr, &buf_len, 
                                   &pkt_len, LowPagePriority);

  /* Skip possible zero length segments at the beginning */
  while (buf != NULL && buf_len == 0)
    {
      NdisGetNextBuffer(buf, &buf);
      if (buf != NULL)
        NdisQueryBufferSafe(buf, &buf_addr, &buf_len, NormalPagePriority);
      if (buf_addr == NULL)
        return;
    }

  /* Sanity checks */
  if (buf_len >= SSH_MEDIA_HDR_LEN)
    *media_hdr = (SshMediaHeader) buf_addr;
}


Boolean SSH_PACKET_POOL_API 
ssh_query_data_block(SshNativeDataBlock dblk, 
                     unsigned char **data,
                     SshUInt32 *data_len)
{
  SSH_ASSERT(dblk != NULL);
  SSH_ASSERT(data != NULL);
  SSH_ASSERT(data_len != NULL);

  NdisQueryBufferSafe(dblk, data, data_len, LowPagePriority);

  if (*data != NULL)
    return TRUE;
  else
    return FALSE;
}


SshNativeDataBlock SSH_PACKET_POOL_API 
ssh_get_first_data_block(SshNetDataBufferHeader buf_hdr)
{
  return (buf_hdr->nb);
}


SshNativeDataBlock SSH_PACKET_POOL_API 
ssh_get_next_data_block(SshNativeDataBlock dblk)
{
  NdisGetNextBuffer(dblk, &dblk);

  return dblk;
}


Boolean SSH_PACKET_POOL_API
ssh_advance_data_start(SshNetDataBufferHeader buf_hdr,
                       SshUInt32 bytes)
{
  buf_hdr->nb->ByteCount -= bytes;
  buf_hdr->nb->ByteOffset += bytes;
  buf_hdr->nb->MappedSystemVa = 
    (unsigned char *)buf_hdr->nb->MappedSystemVa + bytes;
  
  return TRUE;
}


Boolean SSH_PACKET_POOL_API
ssh_retreat_data_start(SshNetDataBufferHeader buf_hdr,
                       SshUInt32 bytes)
{
  buf_hdr->nb->ByteCount += bytes;
  buf_hdr->nb->ByteOffset -= bytes;
  buf_hdr->nb->MappedSystemVa = 
    (unsigned char *)buf_hdr->nb->MappedSystemVa - bytes;

  return TRUE;
}


void SSH_PACKET_POOL_API
ssh_refresh_packet(SshNativeNetDataPacket np,
                   SshUInt32 packet_len)
{
#ifdef DEBUG_LIGHT
  SshUInt32 new_size;
#endif /* DEBUG_LIGHT */
  
  np->Private.ValidCounts = FALSE;
#ifdef DEBUG_LIGHT
  NdisQueryPacket(np, NULL, NULL, NULL, &new_size);
  SSH_ASSERT(new_size == packet_len);
#endif /* DEBUG_LIGHT */
}


void SSH_PACKET_POOL_API 
SSH_RESET_BUFFER(SshNetDataBuffer nb,
                 SshUInt32 backfill)
{
  SshNdisBuffer buffer = (SshNdisBuffer)nb;

  /* Reset the platform independent data members */
  SSH_RESET_NET_BUFFER((SshNetDataBuffer)buffer, backfill); 

  /* Hint: NDIS_BUFFER == MDL (see NDIS.H) */
  buffer->nb = buffer->copy.mdl;
  buffer->nb->Next = NULL;
  buffer->nb->ByteCount -= backfill;
  buffer->nb->ByteOffset += backfill;
  buffer->nb->MappedSystemVa = 
    (unsigned char *)buffer->nb->MappedSystemVa + backfill;
}


void SSH_PACKET_POOL_API 
SSH_RESET_PACKET(SshNetDataPacket np,
                 SshNetDataBuffer nb)
{
  PNDIS_PACKET_OOB_DATA oob;
  SshNdisBuffer buff;
  UINT length;
  SshNdisPacket packet = (SshNdisPacket)np;
  SshNdisBuffer buff_chain = (SshNdisBuffer)nb;

  if (packet->clone_buffers_in_use)
    {
      SshUInt32 i;

      for (i = 0; i < packet->clone_buffers_in_use; i++)
        {
          SshNdisBufferHeader buf_hdr = &packet->clone_buffers[i];

          SSH_ASSERT(buf_hdr->nb != NULL);
          NdisFreeBuffer(buf_hdr->nb);
          buf_hdr->nb = NULL;
        }

      packet->clone_buffers_in_use = 0;
    }

  /* Reset the platform independent data members */
  SSH_RESET_NET_PACKET((SshNetDataPacket)packet, 
                       (SshNetDataBuffer)buff_chain);

  packet->vlan_tag_count = 0;

  /* Reinitialize NDIS packet, clear NDIS_PACKET buffer pointers */
  NdisReinitializePacket(packet->np);
  packet->np->Private.Head = NULL;
  packet->np->Private.Tail = NULL;

  /* Clear NDIS Wrapper reserved fields.  

     NOTE:
     This is required to get some PCMCIA cards operate properly. 
     NDIS uses WrapperReserved field for internal reference counting and 
     for some unknown reason (bug?) this field is not cleared by NDIS 
     when returning from NdisMIndicateReceivePacket() function. Therefore 
     we must clear it here to avoid NDIS.SYS crash when NDIS_PACKET is
     reused. */
  NdisZeroMemory(packet->np->WrapperReserved, 
                 sizeof(packet->np->WrapperReserved));
  NdisZeroMemory(packet->np->WrapperReservedEx, 
                 sizeof(packet->np->WrapperReservedEx));

  /* Clear OOB memory block if it exists */
  oob = NDIS_OOB_DATA_FROM_PACKET(packet->np);
  if (oob != NULL)
    NdisZeroMemory(oob, sizeof(NDIS_PACKET_OOB_DATA));

  /* Clear all packet flags */
  NdisClearPacketFlags(packet->np, ~0L);

  /* Clear media specific info */
  NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO(packet->np, NULL, 0);

  /* Add buffers to destination packet's buffer chain */
  buff = buff_chain;
  while (buff)
    {
      if (buff->data_len)
        {
          NdisChainBufferAtBack(packet->np, buff->nb);
        }
      buff = buff->next;
    }

  /* Force-update packet counts */
  NdisRecalculatePacketCounts(packet->np);
  NdisQueryPacket(packet->np, NULL, NULL, NULL, &length);
}


Boolean SSH_PACKET_POOL_API 
ssh_packet_get_buffer(SshNetDataPacket packet,
                      SshUInt32 offset,
                      SshNetDataBufferHeader *buf_return,
                      SshNativeDataBlock *data_return,
                      SshUInt32 *data_offset_return)
{
  SshNativeNetDataBuffer ndis_buf;
  SshNetDataBuffer buffer = NULL;
  unsigned char *buf_addr;
  ULONG buf_len;
  ULONG buf_offset;
  ULONG pkt_len;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(buf_return != NULL);
  SSH_ASSERT(offset <= packet->packet_len);

  NdisGetFirstBufferFromPacketSafe(packet->np, &ndis_buf, &buf_addr, 
                                   &buf_len, &pkt_len, NormalPagePriority);

  buf_offset = offset;
  while (ndis_buf && (buf_offset >= buf_len))
    {
      buf_offset -= buf_len;

      if ((buf_offset == 0) && (ndis_buf->Next == NULL))
        break;

      NdisGetNextBuffer(ndis_buf, &ndis_buf);
      if (ndis_buf == NULL)
        goto failed;
      
      NdisQueryBufferSafe(ndis_buf, &buf_addr, &buf_len, NormalPagePriority);
      if (buf_addr == NULL)
        goto failed;
    }

  SSH_ASSERT(ndis_buf != NULL);
  buffer = SSH_NB_DESCRIPTOR(ndis_buf);
  SSH_ASSERT(buffer != NULL);

  *buf_return = (SshNdisBufferHeader)buffer;
  if (data_return)
    *data_return = buffer->nb;
  if (data_offset_return)
    *data_offset_return = buf_offset;
  return TRUE;

 failed:
  *buf_return = NULL;
  if (data_return)
    *data_return = NULL;
  if (data_offset_return)
    *data_offset_return = 0;
  return FALSE;
}


Boolean SSH_PACKET_POOL_API 
ssh_packet_advance_data_start(SshNetDataPacket packet,
                              SshUInt32 bytes,
                              unsigned char **buffer_addr)
{
  SshNetDataBufferHeader buf_hdr;
  SshUInt32 offset;
  Boolean status = FALSE;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(bytes <= packet->packet_len);

  if (ssh_packet_get_buffer(packet, 0, &buf_hdr, NULL, &offset))
    { 
      SshUInt32 bytes_left = bytes;
 
      SSH_ASSERT(offset == 0);

      while (bytes_left)
        {
          SshUInt32 bytes_moved;

          bytes_moved = MIN(buf_hdr->data_len, bytes_left);

          if (!ssh_advance_data_start(buf_hdr, bytes_moved))
            goto failed;

          buf_hdr->offset += bytes_moved;
          buf_hdr->data_len -= bytes_moved;
          if (buf_hdr->data_len == 0)
            {
              SshNativeNetDataBuffer unchained_buf;

              NdisUnchainBufferAtFront(packet->np, &unchained_buf);
              SSH_ASSERT(buf_hdr->nb == unchained_buf);
            }

          packet->packet_len -= bytes_moved;
          packet->data_space -= bytes_moved;
          packet->backfill_space += bytes_moved;

          bytes_left -= bytes_moved;
          if (bytes_left)
            {
              buf_hdr = buf_hdr->next;
              if (buf_hdr == NULL)
                goto failed;
            }
        }

      if (buffer_addr)
        *buffer_addr = buf_hdr->nb->MappedSystemVa;

      status = TRUE;
    }

  ssh_refresh_packet(packet->np, packet->packet_len);

  return status;

 failed:
  SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
  return FALSE;
}


Boolean SSH_PACKET_POOL_API 
ssh_packet_retreat_data_start(SshNetDataPacket packet,
                              SshUInt32 bytes,
                              unsigned char **buffer_addr)
{
  SshNetDataBufferHeader buf_hdr;
  SshUInt32 offset;
  Boolean status = FALSE;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(packet->backfill_space >= bytes);

  if (ssh_packet_get_buffer(packet, 0, &buf_hdr, NULL, &offset))
    {  
      SshUInt32 bytes_left = bytes;
 
      SSH_ASSERT(offset == 0);

      while (bytes_left)
        {
          SshUInt32 bytes_moved;

          bytes_moved = MIN(buf_hdr->offset, bytes_left);

          if (!ssh_retreat_data_start(buf_hdr, bytes_moved))
            goto failed;

          buf_hdr->offset -= bytes_moved;
          buf_hdr->data_len += bytes_moved;

          packet->packet_len += bytes_moved;
          packet->data_space += bytes_moved;
          packet->backfill_space -= bytes_moved;

          bytes_left -= bytes_moved;

          if (bytes_left)
            {
              buf_hdr = buf_hdr->prev;
              if (buf_hdr == NULL)
                goto failed;

              NdisChainBufferAtFront(packet->np, buf_hdr->nb);
            }
        }

      if (buffer_addr)
        *buffer_addr = buf_hdr->nb->MappedSystemVa;

      status = TRUE;
    }

  ssh_refresh_packet(packet->np, packet->packet_len);

  return status;

 failed:
  SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
  return FALSE;
}

#if 0
Boolean SSH_PACKET_POOL_API 
ssh_packet_move_data(SshNetDataPacket packet,
                     SshUInt32 from_offset,
                     SshUInt32 to_offset,
                     SshUInt32 length)
{
  SshNetDataBufferHeader src_buf;
  SshNetDataBufferHeader dst_buf;
  SshNativeDataBlock src_dblk;
  SshNativeDataBlock dst_dblk;
  SshUInt32 move_len;
  SshUInt32 src_buf_len;
  SshUInt32 dst_buf_len;
  SshUInt32 src_buf_offset;
  SshUInt32 dst_buf_offset;
  unsigned char *src_addr;
  unsigned char *dst_addr;

  SSH_ASSERT(packet != NULL);

  if (length == 0)
    return TRUE;

  if (from_offset > to_offset)
    {
      if (from_offset + length > packet->packet_len)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid move request!"));
          return FALSE;
        }

next_block_normal:
      if (!ssh_packet_get_buffer(packet, from_offset, 
                                 &src_buf, NULL, &src_buf_offset))
        return FALSE;

      if (!ssh_packet_get_buffer(packet, to_offset,
                                 &dst_buf, NULL, &dst_buf_offset))
        return FALSE;

      if (((src_dblk = ssh_get_first_data_block(src_buf)) == NULL)
          || !ssh_query_data_block(src_dblk, &src_addr, &src_buf_len))
        return FALSE;

      if (((dst_dblk = ssh_get_first_data_block(dst_buf)) == NULL)
          || !ssh_query_data_block(dst_dblk, &dst_addr, &dst_buf_len))
        return FALSE;

      src_addr += src_buf_offset;
      src_buf_len -= src_buf_offset;
      dst_addr += dst_buf_offset;
      dst_buf_len -= dst_buf_offset;

      while (length)
        {
          move_len = length;

          if (move_len > src_buf_len)
            move_len = src_buf_len;
          if (move_len > dst_buf_len)
            move_len = dst_buf_len;

          memmove(dst_addr, src_addr, move_len);

          length -= move_len;

          if (length)
            {
              from_offset += move_len;
              to_offset += move_len;

              goto next_block_normal;
            }
        }
    }
  else
    {
      if (to_offset + length > packet->packet_len)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid move request!"));
          return FALSE;
        }

      to_offset += (length - 1);
      from_offset += (length - 1);

 next_block_reversed:
      if (!ssh_packet_get_buffer(packet, to_offset, 
                                 &dst_buf, NULL, &dst_buf_offset))
        return FALSE;

      if (!ssh_packet_get_buffer(packet, from_offset,
                                 &src_buf, NULL, &src_buf_offset))
        return FALSE;

      if (((src_dblk = ssh_get_first_data_block(src_buf)) == NULL)
          || !ssh_query_data_block(src_dblk, &src_addr, &src_buf_len))
        return FALSE;

      if (((dst_dblk = ssh_get_first_data_block(dst_buf)) == NULL)
          || !ssh_query_data_block(dst_dblk, &dst_addr, &dst_buf_len))
        return FALSE;

      src_addr += src_buf_offset;
      src_buf_len = src_buf_offset + 1;
      dst_addr += dst_buf_offset;
      dst_buf_len = dst_buf_offset + 1;

      while (length)
        {
          SshUInt32 bytes_left;

          move_len = length;

          if (move_len > src_buf_len)
            move_len = src_buf_len;
          if (move_len > dst_buf_len)
            move_len = dst_buf_len;





          /* "reverse memcpy()": */
          bytes_left = move_len;
          while (bytes_left)
            {
              *dst_addr = *src_addr;
              dst_addr--;
              src_addr--;
              bytes_left--;
            };

          if (length > move_len)
            {
              from_offset -= move_len;
              to_offset -= move_len;
              length -= move_len;

              goto next_block_reversed;
            }

          length -= move_len;
          SSH_ASSERT(length == 0);
        }
    }

  return TRUE;
}
#endif /* 0 */

Boolean SSH_PACKET_POOL_API 
ssh_packet_resize(SshNetDataPacket packet,
                  SshUInt32 new_size)
{
  SshNetDataBufferHeader buf_hdr;
  SshUInt32 offset;
  SshUInt32 adjust_offset;
  SshInt32 adjust_left;
  
  SshUInt32 new_buf_size;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(packet->data_space >= new_size);

  if (new_size > packet->packet_len)
    {
      adjust_offset = packet->packet_len;
      adjust_left = new_size - packet->packet_len;
    }
  else
    {
      adjust_offset = new_size;
      adjust_left = 0;
    }

  if (adjust_offset)
    adjust_offset--;

  if (!ssh_packet_get_buffer(packet, adjust_offset, &buf_hdr, NULL, &offset))
    return FALSE;

 next_buffer:
  if (adjust_left == 0)
    {
      new_buf_size = (offset + 1);
    }
  else
    {
      new_buf_size = buf_hdr->data_len + adjust_left;
      new_buf_size = MIN(new_buf_size, buf_hdr->total_size - buf_hdr->offset);
      adjust_left -= new_buf_size - buf_hdr->data_len;
    }

  if (new_buf_size != 0)
    {
      buf_hdr->data_len = new_buf_size;
      NdisAdjustBufferLength(buf_hdr->nb, new_buf_size);
      if (adjust_left)
        {
          buf_hdr = buf_hdr->next;
          if (buf_hdr == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Failed to resize packet!"));
              return FALSE;
            }
          NdisChainBufferAtBack(packet->np, buf_hdr->nb);
          buf_hdr->data_len = 0;
          goto next_buffer;
        }

      buf_hdr = buf_hdr->next;
    }
  
  /* Set the sizes of following buffers (if any) to zero. */
  while (buf_hdr)
    {
      SshNetDataBufferHeader last_buf = buf_hdr;
      SshNativeNetDataBuffer nb;

      while ((last_buf->next != NULL) 
             && (last_buf->nb != packet->np->Private.Tail))
        last_buf = last_buf->next;

      if (last_buf->nb != packet->np->Private.Tail)
        break;
        
      last_buf->data_len = 0;
      NdisAdjustBufferLength(last_buf->nb, 0);
      NdisUnchainBufferAtBack(packet->np, &nb);
      SSH_ASSERT(nb == last_buf->nb);

      if (last_buf == buf_hdr)
        buf_hdr = NULL;
    }

  packet->packet_len = new_size;
  ssh_refresh_packet(packet->np, new_size);

  return TRUE;
}


SshNetDataBuffer SSH_PACKET_POOL_API 
ssh_buffer_chain_alloc(SshInterceptor interceptor,
                       SshPacketPool pool,
                       SshUInt32 requested_len,
                       SshUInt32 *allocated_len,
                       SshUInt32 *backfill_len)
{
  SshNetDataBuffer buff_chain = NULL;
  SshNetDataBuffer prev = NULL;
  SshUInt32 data_bytes_left = requested_len;
  SshUInt32 total_len = requested_len + SSH_NET_PACKET_PADDING_SIZE;
  SshUInt32 backfill = 0;
  SshUInt32 allocated = 0;

  if (allocated_len)
    *allocated_len = 0;

  if (backfill_len)
    *backfill_len = 0;

  while (data_bytes_left || (allocated < total_len))
    {
      SshNetDataBuffer buffer;
      SshNativeNetDataBuffer nb = NULL;
      SshUInt32 offset;
      SshUInt32 buffer_length;

      buffer = ssh_net_buffer_alloc(interceptor, pool);
      if (buffer == NULL)
        {
          ssh_net_buffer_chain_free(interceptor, pool, 
                                    (SshNetDataBuffer)buff_chain);
          return NULL;
        }

      nb = buffer->nb;

      if (prev == NULL)
        {
          buffer_length = SSH_NET_PACKET_DATA_SIZE;
          offset = SSH_NET_PACKET_BACKFILL_SIZE;
          buff_chain = buffer;
        }
      else
        {
          buffer_length = SSH_NET_PACKET_BUFFER_SIZE;
          offset = 0;
          prev->next = buffer;
        }

      buffer->prev = prev;
      buffer->next = NULL;

      backfill += offset;
      allocated += buffer_length;

      if (data_bytes_left < buffer_length)
        buffer_length = data_bytes_left;

      SSH_RESET_BUFFER(buffer, offset);

      NdisAdjustBufferLength(nb, buffer_length);
      buffer->data_len = buffer_length;

      data_bytes_left -= buffer_length;
      prev = buffer;
    }

  if (allocated_len)
    *allocated_len = allocated;

  if (backfill_len)
    *backfill_len = backfill;

  return buff_chain;
}


void SSH_PACKET_POOL_API 
ssh_packet_free(SshNetDataPacket net_packet, 
                SshPacketPool pool)  
{
  SshNdisPacket packet = (SshNdisPacket)net_packet;
#if (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0)
  SshUInt32 i;
#endif /* (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0) */

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(packet->interceptor != NULL);
  SSH_ASSERT(packet->parent_complete_cb == NULL_FNPTR);

#if (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0)
  for (i = 0; i < packet->clone_buffers_in_use; i++)
    {
      SshNdisBufferHeader buf_hdr = &packet->clone_buffers[i];

      SSH_ASSERT(buf_hdr->nb != NULL);
      NdisFreeBuffer(buf_hdr->nb);
      buf_hdr->nb = NULL;
    }
  packet->clone_buffers_in_use = 0;
#endif /* (SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET > 0) */

  ssh_net_packet_free((SshNetDataPacket)packet, pool);
}

SshNetDataPacket SSH_PACKET_POOL_API 
ssh_packet_alloc(SshInterceptor interceptor,
                 SshPacketPool pool,
                 SshUInt32 total_len)
{
  SshNetDataPacket packet;
  SshNetDataBuffer buff_chain;

  packet = ssh_net_packet_alloc(interceptor, pool, total_len);
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Error: ssh_packet_alloc(): "
                 "Cannot allocate destination packet[len=%d]",
                 total_len));
      return NULL;  
    }

  buff_chain = ssh_buffer_chain_alloc(interceptor, pool, total_len,
                                      &packet->data_space, 
                                      &packet->backfill_space);
  if (buff_chain == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of buffer pool!"));
      ssh_packet_free(packet, pool);
      return NULL;
    }

  SSH_RESET_PACKET(packet, buff_chain);
  packet->packet_len = total_len;

  return packet;
}


Boolean SSH_PACKET_POOL_API 
ssh_packet_copy_original_data(SshNetDataPacket net_packet)
{
  SshNdisPacket packet = (SshNdisPacket)net_packet;
  ULONG bytes_copied;
  ULONG length;
  SshNdisBuffer buff;
  NDIS_PACKET src_pkt;

  /* Make a temporary copy of the buffer descriptors. */
  src_pkt = *(packet->np);

  /* Replace packet's buffer chain... */
  packet->np->Private.Head = NULL;
  packet->np->Private.Tail = NULL;
  buff = (SshNdisBuffer)packet->buff;
  while (buff)
    {
      NdisChainBufferAtBack(packet->np, buff->nb);
      buff = buff->next;
    }
  /* ...force-update counts */
  NdisRecalculatePacketCounts(packet->np);
  NdisQueryPacket(packet->np, NULL, NULL, NULL, &length);
  /* ...update backfill and data sizes... */
  packet->backfill_space = packet->buf_chain_backfill;
  packet->data_space = packet->buf_chain_data_space;
  /* ...resize the destination packet if necessary. (we most probably have
     changed its size by removing e.g. media header) */
  if (length != packet->packet_len)
    {
      SshUInt32 new_size = packet->packet_len;

      packet->packet_len = length;
      if (!ssh_packet_resize((SshNetDataPacket)packet, new_size))
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Failed to resize packet 0x%p (%u -> %u)", 
                     packet, packet->packet_len, new_size));
          return FALSE;
        }
    }
    
  /* ... and finally let NDIS to handle the raw data copying. */
  NdisCopyFromPacketToPacket(packet->np, 0, packet->packet_len, 
                             &src_pkt, 0, &bytes_copied);
  if (bytes_copied != packet->packet_len)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Failed to copy original data to packet 0x%p "
                 "(len=%u, bytes_copied=%u)",
                 packet, packet->packet_len, bytes_copied));
      return FALSE;
    }
  /* done! */
  packet->f.flags.packet_copied = 1;

  return TRUE;
}


#include "packet_pool_impl.c"


PUCHAR SSH_PACKET_POOL_API 
ssh_packet_get_contiguous_data(SshNetDataPacket packet,
                               SshUInt32 offset,
                               SshUInt32 bytes,
                               Boolean read_only)
{
  SshNetDataBufferHeader buf_hdr;
  SshNativeDataBlock src_dblk;
  SshNativeDataBlock dst_dblk;
  unsigned char *buf_addr;
  ULONG buf_len;
  SshUInt32 buf_offset;

  /* Query packet buffer information */
 retry:
  if (!ssh_packet_get_buffer(packet, offset, 
                             &buf_hdr, &src_dblk, &buf_offset))
    return NULL;

  if ((buf_offset + bytes) > buf_hdr->data_len)
    {
      if (read_only && (bytes <= sizeof(packet->pullup_buffer)))
        {
          /* We don't need to copy the whole packet, because the caller
             has requested read only access (and thus we don't need to
             give access to original data buffer)... */
          ssh_packet_copyout(packet, offset, packet->pullup_buffer, bytes);
          return packet->pullup_buffer;
        }
      else
        {
          SshNetDataBufferHeader next = buf_hdr->next;

          if ((next != NULL) &&
              ((next->total_size - next->data_len) >= bytes))
            {
              unsigned char *src_addr;
              unsigned char *dst_addr;
              SshUInt16 bytes_moved;
              ULONG len;

              /* Next buffer has enough space so we can simply move data
                 from the current buffer to the next one */

              /* Add space for the moved data */
              bytes_moved = buf_hdr->data_len - buf_offset;
              dst_dblk = ssh_get_first_data_block(next);
              if ((dst_dblk == NULL)
                   || !ssh_query_data_block(dst_dblk, &src_addr, &len))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
                  return NULL;
                }
              src_addr += next->offset + next->data_len;
              dst_addr = src_addr + bytes_moved;
              len = next->data_len;
              while (len)
                {
                  len--;
                  *(dst_addr + len) = *(src_addr + len);
                }

              /* Copy data to the beginning of next buffer */
              if (!ssh_query_data_block(src_dblk, &src_addr, &len)
                  || !ssh_query_data_block(dst_dblk, &dst_addr, &len))
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
                  return NULL;
                }
              memcpy(dst_addr, src_addr + buf_offset, bytes_moved);

              /* Adjust buffer lengths */
              next->data_len += bytes_moved;
              NdisAdjustBufferLength(next->nb, next->data_len);
              buf_hdr->data_len -= bytes_moved;
              NdisAdjustBufferLength(buf_hdr->nb, buf_hdr->data_len);
              if (buf_hdr->data_len == 0)
                {
                  SshNativeNetDataBuffer unchained_buf;

                  NdisUnchainBufferAtFront(packet->np, &unchained_buf);
                  SSH_ASSERT(buf_hdr->nb == unchained_buf);
                }

              ssh_refresh_packet(packet->np, packet->packet_len);

              buf_hdr = next;
              buf_offset = 0;
            }
          else 
            {
              if (packet->f.flags.packet_copied == 0)
                {
                  if (ssh_packet_copy_original_data(packet))
                    goto retry;
                }

              return NULL; 
            }
        }
    }
  else
    {
      dst_dblk = src_dblk;
    }

  if (ssh_query_data_block(dst_dblk, &buf_addr, &buf_len))
    {
      buf_addr += buf_offset;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
      buf_addr = NULL;
    }

  return (buf_addr);
}


SshNdisPacket SSH_PACKET_POOL_API 
ssh_packet_clone(SshInterceptor interceptor,
                 SshPacketPool pool,
                 SshInterceptorProtocol protocol,
                 SshNativeNetDataPacket src,
                 Boolean copy_data)
{
  SshMediaHeader media_hdr;
  SshNdisPacket packet;
  SshNdisBuffer buff_chain;
  SshUInt32 total_len;
  SshUInt32 bytes_copied = 0;
  void *media_info;
  SshUInt32 media_info_len;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(pool != NULL);
  SSH_ASSERT(src != NULL);

  /* Query source packet len */
  NdisQueryPacket(src, NULL, NULL, NULL, &total_len);

  /* Allocate new packet for copying */
  packet = (SshNdisPacket)ssh_net_packet_alloc(interceptor, pool, total_len);
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Error: ssh_packet_clone(): "
                 "Cannot allocate destination packet[len=%d]",
                 total_len));
      return NULL;  
    }

  buff_chain = (SshNdisBuffer)ssh_buffer_chain_alloc(interceptor, pool, 
                                                     total_len,
                                                     &packet->data_space, 
                                                     &packet->backfill_space);
  if (buff_chain == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of buffer pool!"));
      ssh_packet_free((SshNetDataPacket)packet, pool);
      return NULL;
    }

  if (copy_data) 
    {
 copy_packet:
      SSH_RESET_PACKET((SshNetDataPacket)packet, 
                       (SshNetDataBuffer)buff_chain);

      /* Copy packet contents */
      NdisCopyFromPacketToPacket(packet->np, 0, total_len, 
                                 src, 0, &bytes_copied);
      if (bytes_copied != total_len)
        {
          SSH_DEBUG(SSH_D_FAIL, 
                    ("Packet[0x%p, %d, %d] copy failed",
                     packet, total_len, bytes_copied));
          ssh_packet_free((SshNetDataPacket)packet, pool);
          return NULL;
        }
      packet->f.flags.packet_copied = 1;
    }
  else
    {
      SshNdisBufferHeader prev = NULL;
      NDIS_BUFFER *ndis_buf;
      unsigned char *buf_addr;
      UINT buf_len;
      UINT pkt_len;

      SSH_RESET_PACKET((SshNetDataPacket)packet, NULL);

      packet->buff = (SshNetDataBuffer)buff_chain;
      /* Copy buffer descriptors (so we don't need to revert changes in
         original packet before returning it back to miniport/protocol). */
      NdisGetFirstBufferFromPacketSafe(src, &ndis_buf, &buf_addr,  &buf_len, 
                                       &pkt_len, NormalPagePriority);      
      if (ndis_buf == NULL)
        {
          ssh_packet_free((SshNetDataPacket)packet, pool);
          return NULL;
        }

      while (ndis_buf)
        {
          SshNdisBufferHeader buf_hdr;
          NDIS_STATUS status;

          NdisQueryBufferSafe(ndis_buf, &buf_addr, &buf_len, 
                              NormalPagePriority);
          if (buf_addr == NULL)
            {
              ssh_packet_free((SshNetDataPacket)packet, pool);
              return NULL;
            }

          /* Skip zero-length buffers */
          if (buf_len > 0)
            {
              if (packet->clone_buffers_in_use 
                                      == SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET)
                goto copy_packet;

              buf_hdr = &packet->clone_buffers[packet->clone_buffers_in_use];

              SSH_ASSERT(buf_hdr->nb == NULL);
              NdisCopyBuffer(&status, &buf_hdr->nb, pool->buffer_list_context, 
                             ndis_buf, 0, ndis_buf->ByteCount);
              if (status != NDIS_STATUS_SUCCESS)
                {
                  ssh_packet_free((SshNetDataPacket)packet, pool);
                  return NULL;
                }

              SSH_ASSERT(buf_hdr->nb->Next == NULL);

              buf_hdr->total_size = ndis_buf->ByteCount;
              buf_hdr->data_len = buf_hdr->total_size;
              buf_hdr->offset = 0;
              SSH_NB_DESCRIPTOR(buf_hdr->nb) = buf_hdr;

              buf_hdr->prev = prev;
              buf_hdr->next = NULL;
              if (prev)
                prev->next = buf_hdr;
              prev = buf_hdr;

              NdisChainBufferAtBack(packet->np, buf_hdr->nb);

              packet->clone_buffers_in_use++;
            }

          NdisGetNextBuffer(ndis_buf, &ndis_buf);
        }

      packet->buf_chain_backfill = packet->backfill_space;
      packet->buf_chain_data_space = packet->data_space;
      packet->backfill_space = 0;
      packet->data_space = pkt_len;

      /* Force-update packet counts */
      NdisRecalculatePacketCounts(packet->np);
      NdisQueryPacket(packet->np, NULL, NULL, NULL, &pkt_len);
    }

  /* Set OOB information */
  RtlCopyMemory(NDIS_OOB_DATA_FROM_PACKET(packet->np),
                NDIS_OOB_DATA_FROM_PACKET(src),
                sizeof(NDIS_PACKET_OOB_DATA));

  /* Set media specific information */
  NDIS_GET_PACKET_MEDIA_SPECIFIC_INFO(src, &media_info, &media_info_len);
  NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO(packet->np, 
                                      media_info, media_info_len);

  /* Copy IEEE802.1p priority value */
  NDIS_PER_PACKET_INFO_FROM_PACKET(packet->np, Ieee8021pPriority) =
    NDIS_PER_PACKET_INFO_FROM_PACKET(src, Ieee8021pPriority);

  /* Copy packet flags */
  NdisSetPacketFlags(packet->np, NdisGetPacketFlags(src));

  /* Set packet header size */
  NDIS_SET_PACKET_HEADER_SIZE(packet->np, 
                              NDIS_GET_PACKET_HEADER_SIZE(src));

  packet->packet_len = total_len;

  ssh_packet_query_media_header(packet->np, &media_hdr);
  if (media_hdr != NULL)
    {
      if (protocol == SSH_PROTOCOL_ETHERNET)
        {
          if (SSH_ETHER_IS_MULTICAST(media_hdr->dst))
            packet->ip.flags |= SSH_PACKET_MEDIABCAST;
        }
      packet->eth_type = SSH_GET_16BIT(media_hdr->type);
    }

  return packet;
}

