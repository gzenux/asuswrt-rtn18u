/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS 6.0 (and later) compatible packet pool functions
   for Windows Vista and Windows Server 2008 Interceptor object.
*/

Boolean SSH_PACKET_POOL_API
ssh_query_data_block(SshNativeDataBlock dblk, 
                     unsigned char **data,
                     SshUInt32 *data_len)
{
  SSH_ASSERT(dblk != NULL);
  SSH_ASSERT(data != NULL);
  SSH_ASSERT(data_len != NULL);

  NdisQueryMdl(dblk, data, data_len, LowPagePriority);
  
  if (*data != NULL)
    return TRUE;
  else
    return FALSE;
}


SshNativeDataBlock SSH_PACKET_POOL_API
ssh_get_first_data_block(SshNetDataBufferHeader buf_hdr)
{
  return (NET_BUFFER_CURRENT_MDL(buf_hdr->nb));
}


SshNativeDataBlock SSH_PACKET_POOL_API
ssh_get_next_data_block(SshNativeDataBlock dblk)
{
  /* Skip zero-length MDLs */
  do
    {
      NdisGetNextMdl(dblk, &dblk);
    }
  while (dblk && (dblk->ByteCount == 0));

  return dblk;
}


void SSH_PACKET_POOL_API
ssh_adjust_data_block_length(SshNativeDataBlock dblk,
                             SshUInt32 length)
{
  dblk->ByteCount = length;
}


Boolean SSH_PACKET_POOL_API
ssh_advance_data_start(SshNetDataBufferHeader buf_hdr,
                       SshUInt32 bytes)
{
  NdisAdvanceNetBufferDataStart(buf_hdr->nb, bytes, 0, NULL);
  
  return TRUE;
}

Boolean SSH_PACKET_POOL_API
ssh_retreat_data_start(SshNetDataBufferHeader buf_hdr,
                       SshUInt32 bytes)
{
  NDIS_STATUS status;

  status = NdisRetreatNetBufferDataStart(buf_hdr->nb, bytes, 0, NULL);
  if (status != NDIS_STATUS_SUCCESS)
    return FALSE;
  else
    return TRUE;
}

void SSH_PACKET_POOL_API
ssh_unchain_first_data_block(SshNetDataBufferHeader buf_hdr)
{
  /* Nothing to do! (NdisAdvanceNetBufferDataStart() changes the current MDL
     when needed) */
}


void SSH_PACKET_POOL_API
ssh_chain_at_front(SshNetDataBufferHeader buf_hdr,
                   SshNativeDataBlock new_first_dblk)
{
  /* Nothing to do! (NdisRetreatNetBufferDataStart() changed the current MDL
     when needed) */
}


void SSH_PACKET_POOL_API
ssh_refresh_packet(SshNativeNetDataPacket np,
                   SshUInt32 packet_len)
{
  NET_BUFFER *nb;

  SSH_ASSERT(np != NULL);
  nb = NET_BUFFER_LIST_FIRST_NB(np);
  SSH_ASSERT(nb != NULL);
  NET_BUFFER_DATA_LENGTH(nb) = packet_len;
}


void SSH_PACKET_POOL_API
SSH_RESET_BUFFER(SshNetDataBuffer nb,
                 SshUInt32 backfill)
{
  SshNdisBuffer buffer = (SshNdisBuffer)nb;

  /* Reset the platform independent data members */
  SSH_RESET_NET_BUFFER((SshNetDataBuffer)buffer, backfill);

  NET_BUFFER_NEXT_NB(buffer->nb) = NULL;

  NET_BUFFER_CURRENT_MDL(buffer->nb) =
    NET_BUFFER_FIRST_MDL(buffer->nb) = buffer->copy.mdl;

  NET_BUFFER_CURRENT_MDL_OFFSET(buffer->nb) =
    NET_BUFFER_DATA_OFFSET(buffer->nb) = 0;

  NET_BUFFER_DATA_LENGTH(buffer->nb) = backfill;
  NdisAdvanceNetBufferDataStart(buffer->nb, backfill, 0, NULL);

  SSH_ASSERT(NET_BUFFER_DATA_LENGTH(buffer->nb) == 0);
}


void SSH_PACKET_POOL_API
SSH_RESET_PACKET(SshNetDataPacket np,
                 SshNetDataBuffer buff_chain)
{
  SshNdisPacket packet = (SshNdisPacket)np;
  SshUInt32 i;
 
  SSH_ASSERT(packet != NULL);

  /* Reset the platform independent data members */
  SSH_RESET_NET_PACKET((SshNetDataPacket)packet, 
                       (SshNetDataBuffer)buff_chain);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  packet->transfer_flags = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  packet->np->ParentNetBufferList = NULL;
  packet->np->ChildRefCount = 0;
  packet->np->Scratch = NULL;

  /* Clear NetBufferListInfo (except WfpNetBufferListInfo field which we
     must NOT touch!) */
  for (i = 0; i < MaxNetBufferListInfo; i++)
    {
      if (i != WfpNetBufferListInfo)
        packet->np->NetBufferListInfo[i] = NULL;
    }
}


Boolean SSH_PACKET_POOL_API
ssh_packet_get_buffer(SshNetDataPacket packet,
                      SshUInt32 offset,
                      SshNetDataBufferHeader *buf_return,
                      SshNativeDataBlock *data_return,
                      SshUInt32 *data_offset_return)
{
  SshNetDataBufferHeader buf_hdr;
  SshNativeDataBlock dblk;
  unsigned char *buffer_ptr;
  SshUInt32 data_len;
  SshUInt32 skip_bytes = offset;

  if (packet->f.flags.packet_copied)
    buf_hdr = (SshNetDataBufferHeader)packet->buff;
  else
    buf_hdr = (SshNetDataBufferHeader)&packet->clone_buffers[0];

  while (skip_bytes >= buf_hdr->data_len)
    {
      skip_bytes -= buf_hdr->data_len;
      buf_hdr = buf_hdr->next;
    }
  skip_bytes += buf_hdr->offset;

  dblk = ssh_get_first_data_block(buf_hdr);
  if ((dblk == NULL)
       || !ssh_query_data_block(dblk, &buffer_ptr, &data_len))
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_query_data_block() failed!"));
      return FALSE;
    }

  if (data_offset_return)
    *data_offset_return = skip_bytes;
    
  if (buf_return)
    *buf_return = buf_hdr;

  if (data_return)
    *data_return = dblk;

  return TRUE;
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
 
      while (bytes_left)
        {
          SshUInt32 bytes_moved;

          bytes_moved = MIN(buf_hdr->data_len, bytes_left);

          if (!ssh_advance_data_start(buf_hdr, bytes_moved))
            goto failed;

          buf_hdr->offset += bytes_moved;
          buf_hdr->data_len -= bytes_moved;
          if (buf_hdr->data_len == 0)
            ssh_unchain_first_data_block(buf_hdr);

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
        {
          SshNativeDataBlock dblk;
          SshUInt32 len;

          if (((dblk = ssh_get_first_data_block(buf_hdr)) == NULL)
              || !ssh_query_data_block(dblk, buffer_addr, &len))
            goto failed;

          *buffer_addr += buf_hdr->offset;
        }

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
              SshNativeDataBlock dblk;

              buf_hdr = buf_hdr->prev;
              if ((buf_hdr == NULL)
                  || ((dblk = ssh_get_first_data_block(buf_hdr)) == NULL))
                goto failed;

              ssh_chain_at_front(buf_hdr, dblk);
            }
        }

      if (buffer_addr)
        {
          SshNativeDataBlock dblk;
          SshUInt32 len;

          if (((dblk = ssh_get_first_data_block(buf_hdr)) == NULL)
              || !ssh_query_data_block(dblk, buffer_addr, &len))
            goto failed;

          *buffer_addr += buf_hdr->offset;
        }

      status = TRUE;
    }

  ssh_refresh_packet(packet->np, packet->packet_len);

  return status;

failed:
  SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
  return FALSE;
}


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

      if (adjust_left)
        {
          buf_hdr = buf_hdr->next;
          if (buf_hdr == NULL)
            {
              SSH_DEBUG(SSH_D_FAIL, ("Failed to resize packet!"));
              return FALSE;
            }
          buf_hdr->data_len = 0;
          goto next_buffer;
        }

      buf_hdr = buf_hdr->next;
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
  MDL *prev_mdl = NULL;
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

      NET_BUFFER_DATA_LENGTH(nb) = buffer_length;
      buffer->data_len = buffer_length;

      data_bytes_left -= buffer_length;
      prev = buffer;

      /* Add MDLs to the first NET_BUFFER (so we can prevent some extra 
         complexity in packet manipulation functions.) */
      if (prev_mdl == NULL)
        {
          prev_mdl = NET_BUFFER_CURRENT_MDL(nb);
        }
      else
        {
          PMDL mdl = NET_BUFFER_CURRENT_MDL(nb);

          prev_mdl->Next = mdl;
          prev_mdl = mdl;
        }
    }

  if (allocated_len)
    *allocated_len = allocated;

  if (backfill_len)
    *backfill_len = backfill;

  return buff_chain;
}


void SSH_PACKET_POOL_API
ssh_packet_free(SshNetDataPacket packet,
                SshPacketPool current_pool)
{
  ssh_net_packet_free(packet, current_pool);
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
                ("Cannot allocate packet [len=%u]", total_len));
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

  NET_BUFFER_LIST_FIRST_NB(packet->np) = buff_chain->nb;

  packet->packet_len = total_len;
  ssh_refresh_packet(packet->np, total_len);

  return packet;
}


Boolean SSH_PACKET_POOL_API
ssh_packet_copy_original_data(SshNetDataPacket packet)
{
  ULONG bytes_copied;
  SshNdisBuffer buff;
  NET_BUFFER src_nb;

  /* Make a temporary copy of the buffer descriptors. */
  src_nb = *(packet->np->FirstNetBuffer);

  buff = (SshNdisBuffer)packet->buff;
  packet->backfill_space = packet->buf_chain_backfill;
  packet->data_space = packet->buf_chain_data_space;

  NET_BUFFER_LIST_FIRST_NB(packet->np) = buff->nb;
  NET_BUFFER_DATA_LENGTH(buff->nb) = (SshUInt32)packet->packet_len;
  NdisCopyFromNetBufferToNetBuffer(buff->nb, 0, 
                                   (SshUInt32)packet->packet_len,
                                   &src_nb, 0, &bytes_copied);
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




  if ((buf_offset + bytes) > buf_hdr->total_size)
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
              bytes_moved = buf_hdr->data_len + buf_hdr->offset - buf_offset;
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
              buf_hdr->data_len -= bytes_moved;
              ssh_adjust_data_block_length(src_dblk, 
                                           buf_hdr->data_len 
                                           + buf_hdr->offset);
              if (buf_hdr->data_len == 0)
                ssh_unchain_first_data_block(buf_hdr);

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
                 PNET_BUFFER_LIST src_nbl,
                 Boolean copy_data)
{
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  NET_BUFFER_LIST *clone_nbl = NULL;
#else
  unsigned char temp[SSH_ETHERH_HDRLEN];  
  const unsigned char *media_header = NULL;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  SshNetDataBuffer buff_chain;
  SshNdisPacket packet;
  SshUInt32 total_len;
  NET_BUFFER *src;
  NET_BUFFER *next;

  SSH_ASSERT(interceptor != NULL);
  SSH_ASSERT(pool != NULL);
  SSH_ASSERT(src_nbl != NULL);
  
  src = NET_BUFFER_LIST_FIRST_NB(src_nbl);
  next = NET_BUFFER_NEXT_NB(src);
  NET_BUFFER_NEXT_NB(src) = NULL;

  if (copy_data)
    {
      SSH_DEBUG(SSH_D_MIDSTART, ("Copying original packet"));
    }
  else
    {
      SSH_DEBUG(SSH_D_MIDSTART, 
                ("Cloning packet descriptors (data not copied)"));
    }

  total_len = NET_BUFFER_DATA_LENGTH(src);

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (protocol == SSH_PROTOCOL_ETHERNET)
    {
      if ((total_len < SSH_ETHERH_HDRLEN)
          || ((media_header = 
               NdisGetDataBuffer(src, SSH_ETHERH_HDRLEN, temp, 1, 0)) == NULL))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid NET_BUFFER!"));
          return NULL;
        }
    }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

  packet = (SshNdisPacket)ssh_net_packet_alloc(interceptor, pool, total_len);
  if (packet == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, 
                ("Error: ssh_packet_clone(): "
                 "Cannot allocate destination packet[len=%d]",
                 total_len));
      goto failed;
    }

  buff_chain = ssh_buffer_chain_alloc(interceptor, pool, total_len,
                                      &packet->data_space,
                                      &packet->backfill_space);
  if (buff_chain == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Out of buffer pool!"));
      goto failed;
    }







  if (copy_data || buff_chain->next)
    {
      ULONG bytes_copied;

 copy_packet:
      SSH_RESET_PACKET((SshNetDataPacket)packet, buff_chain);

      NET_BUFFER_LIST_FIRST_NB(packet->np) = buff_chain->nb;
      NET_BUFFER_DATA_LENGTH(buff_chain->nb) = total_len;

      NdisCopyFromNetBufferToNetBuffer(buff_chain->nb, 0, total_len,
                                       src, 0, &bytes_copied);
      packet->f.flags.packet_copied = 1;
    }
  else
    {
      SshNdisBufferHeader prev = NULL;
      SshNdisBufferHeader first = NULL;
      SshUInt32 data_bytes_left = total_len;
      SshUInt32 data_offset = NET_BUFFER_DATA_OFFSET(src);
      MDL *src_mdl;
      MDL *prev_mdl = NULL;

      SSH_RESET_PACKET((SshNetDataPacket)packet, NULL);

      packet->buff = buff_chain;

      /* Copy MDLs */
      src_mdl = NET_BUFFER_FIRST_MDL(src);
      if (src_mdl == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Invalid packet!"));
          goto failed;
        }

      packet->buf_chain_backfill = packet->backfill_space;
      packet->buf_chain_data_space = packet->data_space;
      packet->data_space = total_len;

      while (src_mdl)
        {
          SshNdisBufferHeader buf_hdr;

          if (packet->clone_buffers_in_use 
                                  == SSH_CLONE_BUF_DESCRIPTORS_PER_PACKET)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Out of clone descriptos; copying packet."));
              packet->data_space = packet->buf_chain_data_space;
              goto copy_packet;
            }

          buf_hdr = &packet->clone_buffers[packet->clone_buffers_in_use];

          buf_hdr->prev = prev;
          buf_hdr->next = NULL;
          if (prev)
            prev->next = buf_hdr;
          else
            first = buf_hdr;
          prev = buf_hdr;

          if (prev_mdl == NULL)
            {
              NET_BUFFER_LIST_FIRST_NB(packet->np) = buf_hdr->nb;
              packet->backfill_space = data_offset;
              prev_mdl = src_mdl;
            }
          NET_BUFFER_FIRST_MDL(buf_hdr->nb) = src_mdl;
          NET_BUFFER_CURRENT_MDL(buf_hdr->nb) = src_mdl;
          NET_BUFFER_DATA_LENGTH(buf_hdr->nb) = data_bytes_left;
          NET_BUFFER_DATA_OFFSET(buf_hdr->nb) = data_offset;
          buf_hdr->total_size = src_mdl->ByteCount;

          if (data_offset)
            {
              NET_BUFFER_CURRENT_MDL(first->nb) = src_mdl;
              NET_BUFFER_CURRENT_MDL_OFFSET(first->nb) = data_offset;
            }

          if (buf_hdr->total_size < data_offset)
            buf_hdr->offset = buf_hdr->total_size;
          else
            buf_hdr->offset = data_offset;
          data_offset -= buf_hdr->offset;

          NET_BUFFER_CURRENT_MDL_OFFSET(buf_hdr->nb) = buf_hdr->offset;

          buf_hdr->data_len = buf_hdr->total_size - buf_hdr->offset;
          if (buf_hdr->data_len > data_bytes_left)
            buf_hdr->data_len = data_bytes_left;

          data_bytes_left -= buf_hdr->data_len;

          packet->clone_buffers_in_use++;

          src_mdl = ssh_get_next_data_block(src_mdl);
        }
    }
  packet->packet_len = total_len;
  packet->ip.protocol = protocol;

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (protocol == SSH_PROTOCOL_ETHERNET)
    {
      if (SSH_ETHER_IS_MULTICAST(media_header + SSH_ETHERH_OFS_DST))
        packet->ip.flags |= SSH_PACKET_MEDIABCAST;
          
      packet->eth_type = SSH_GET_16BIT(media_header + SSH_ETHERH_OFS_TYPE);
    }
  else
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
    {
      packet->eth_type = 0;
    }

  NET_BUFFER_NEXT_NB(src) = next;

  return packet;

 failed:
  NET_BUFFER_NEXT_NB(src) = next;

  if (packet)
    ssh_packet_free((SshNetDataPacket)packet, pool);

  return NULL;
}


SshNdisPacket SSH_PACKET_POOL_API
ssh_packet_list_clone(SshInterceptor interceptor,
                      SshPacketPool pool,
                      SshUInt32 flags,
                      SshInterceptorProtocol protocol,
                      PNET_BUFFER_LIST nbl,
                      Boolean copy_data)
{
  NET_BUFFER *first_nb = NET_BUFFER_LIST_FIRST_NB(nbl);
  NET_BUFFER *src = first_nb;
  SshNdisPacket packet = NULL;
  SshNdisPacket prev_packet = NULL;

  while (src != NULL)
    { 
      SshNdisPacket p;

      /* Skip previous (already copied) NBL */
      NET_BUFFER_LIST_FIRST_NB(nbl) = src;

      p = ssh_packet_clone(interceptor, pool, protocol, nbl, copy_data);
      if (p != NULL)
        {
          NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO cksum_info;

          NET_BUFFER_LIST_FLAGS(p->np) = NET_BUFFER_LIST_FLAGS(nbl);
          NET_BUFFER_LIST_NBL_FLAGS(p->np) = NET_BUFFER_LIST_NBL_FLAGS(nbl);

          p->ip.flags |= flags;

          cksum_info.Value = 
            NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

          if (flags & SSH_PACKET_FROMADAPTER)
            {
              p->f.flags.from_local_stack = 0;
              NdisCopyReceiveNetBufferListInfo(p->np, nbl);

              if (cksum_info.Value)
                {
                  if (cksum_info.Receive.IpChecksumSucceeded)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
                                ("Packet 0x%p: IPv4 checksum verified by HW",
                                 p));
		      
                      p->ip.flags |= SSH_PACKET_IP4HDRCKSUMOK;
                    }

                  if (cksum_info.Receive.TcpChecksumSucceeded ||
                      cksum_info.Receive.UdpChecksumSucceeded)
                    p->ip.flags |= SSH_PACKET_HWCKSUM;
                }
            }
          else
            {
              p->f.flags.from_local_stack = 1;
              NdisCopySendNetBufferListInfo(p->np, nbl);

              if (cksum_info.Value)
                {
                  /* Checksum calculation of the first IP header is done 
                     by NIC hardware? Consider the packets ip header
                     checksum as valid, since it's going to be calculated
                     only in send. */
                  if (cksum_info.Transmit.IsIPv4 &&
                      cksum_info.Transmit.IpHeaderChecksum)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW, 
	                        ("Packet 0x%p: "
                                 "Requesting HW checksum for IPv4",
                                 p));

                      /* This flag well have to set in order to 
                         ensure that fastpath does not drop this packet, 
                         because of invalid IPv4 header checksum. */
                      p->ip.flags |= SSH_PACKET_IP4HDRCKSUMOK;
                      
                      /* And this is just indication that we'll have 
                         to calculate the checksum in HW later on. */
                      p->ip.flags |= SSH_PACKET_IP4HHWCKSUM;
                    }
		      
                  if (cksum_info.Transmit.TcpChecksum || 
                      cksum_info.Transmit.UdpChecksum)
                    p->ip.flags |= SSH_PACKET_HWCKSUM;
                }
            }

          if (prev_packet == NULL)
            packet = p;
          else
            prev_packet->next = p;

          prev_packet = p;
        }      

      src = NET_BUFFER_NEXT_NB(src);
    }

  /* Restore original NBL structure */
  NET_BUFFER_LIST_FIRST_NB(nbl) = first_nb;

  return packet;
}

