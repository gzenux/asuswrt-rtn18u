/**
   @copyright
   Copyright (c) 2006 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains NDIS version independent packet pool functions
   for Windows Interceptor objects.
*/

/*--------------------------------------------------------------------------
  INCLUDE FILES
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  TYPE DEFINITIONS
  --------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------
  MACROS AND FUNCTIONS
  --------------------------------------------------------------------------*/

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


Boolean SSH_PACKET_POOL_API
ssh_packet_move_head(SshNetDataPacket packet,
                     SshUInt32 len,
                     SshInt32 move)
{
  SSH_ASSERT(packet != NULL);

  if (move == 0)
    return TRUE;

  if (move < 0)
    {
      if (!ssh_packet_retreat_data_start(packet, 0 - move, NULL))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Retreat failed!"));
          return FALSE;
        }

      if (!ssh_packet_move_data(packet, 0 - move, 0, len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Move failed!"));
          return FALSE;
        }
    }
  else
    {
      if (!ssh_packet_move_data(packet, 0, move, len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Move failed!"));
          return FALSE;
        }

      if (!ssh_packet_advance_data_start(packet, move, NULL))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Advance failed!"));
          return FALSE;
        }
    }

  return TRUE;
}


Boolean SSH_PACKET_POOL_API
ssh_packet_move_tail(SshNetDataPacket packet,
                     SshUInt32 offset,
                     SshInt32 move)
{
  SshUInt32 len;

  SSH_ASSERT(packet != NULL);

  if (move == 0)
    return TRUE;

  len = packet->packet_len - offset;

  if (move < 0)
    {
      if (!ssh_packet_move_data(packet, offset, offset + move, len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Move failed!"));
          return FALSE;
        }

      if (!ssh_packet_resize(packet, packet->packet_len + move))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Resize failed!"));
          return FALSE;
        }
    }
  else
    {
      if (!ssh_packet_resize(packet, packet->packet_len + move))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Resize failed!"));
          return FALSE;
        }

      if (!ssh_packet_move_data(packet, offset, offset + move, len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Move failed!"));
          return FALSE;
        }
    }

  return TRUE;
}


Boolean SSH_PACKET_POOL_API
ssh_packet_copyin(SshNetDataPacket packet,
                  SshUInt32 offset,
                  const unsigned char *buf,
                  SshUInt32 len)
{
  SshUInt32 dst_offset;
  SshNativeDataBlock dblk;
  SshNetDataBufferHeader buf_hdr;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(buf != NULL);

  if (!ssh_packet_get_buffer(packet, offset, &buf_hdr, NULL, &dst_offset))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get buffer at offset %lu", offset));
      return FALSE;
    }

  dblk = ssh_get_first_data_block(buf_hdr);

  while (len && dblk)
    {
      unsigned char *dst;
      SshUInt32 dst_len;
      SshUInt32 copy_len = len;

      if (!ssh_query_data_block(dblk, &dst, &dst_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to query data block!"));
          return FALSE;
        }

      if (dst_offset)
        {
          dst += dst_offset;
          dst_len -= dst_offset;
          dst_offset = 0;
        }

      if (dst_len < copy_len)
        copy_len = dst_len;

      memcpy(dst, buf, copy_len);

      len -= copy_len;
      buf += copy_len;

      dblk = ssh_get_next_data_block(dblk);
    }

  if (len != 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to copy data (%u bytes left)", len));
      return FALSE;
    }
  
  return TRUE;
}


Boolean SSH_PACKET_POOL_API 
ssh_packet_copyout(SshNetDataPacket packet,
                   SshUInt32 offset,
                   unsigned char *buf,
                   SshUInt32 len)
{
  SshNetDataBufferHeader buf_hdr;
  SshNativeDataBlock dblk;
  SshUInt32 src_offset;

  SSH_ASSERT(packet != NULL);
  SSH_ASSERT(buf != NULL);

  if (!ssh_packet_get_buffer(packet, offset, &buf_hdr, NULL, &src_offset))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get buffer at offset %lu", offset));
      return FALSE;
    }

  dblk = ssh_get_first_data_block(buf_hdr);

  while (len && dblk)
    {
      unsigned char *src;
      SshUInt32 src_len;
      SshUInt32 copy_len = len;

      if (!ssh_query_data_block(dblk, &src, &src_len))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to query data block!"));
          return FALSE;
        }

      if (src_offset)
        {
          src += src_offset;
          src_len -= src_offset;
          src_offset = 0;
        }

      if (src_len < copy_len)
        copy_len = src_len;

      memcpy(buf, src, copy_len);

      len -= copy_len;
      buf += copy_len;

      dblk = ssh_get_next_data_block(dblk);
    }

  if (len != 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to copy data (%u bytes left)", len));
      return FALSE;
    }
  
  return TRUE;
}
