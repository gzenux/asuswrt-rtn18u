/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#define SSH_DEBUG_MODULE "SshPppLinkPkt"

#include "sshincludes.h"
#include "sshppp_linkpkt.h"

Boolean
ssh_ppp_pkt_buffer_init(SshPppPktBuffer buf,
                        unsigned long size)
{
  buf->nbytes = 0;
  buf->offset = 0;
  buf->maxbytes = 0;

  buf->buffer = ssh_malloc(size);

  if (buf->buffer == NULL)
    return FALSE;

  buf->maxbytes = size;
  return TRUE;;
}

Boolean
ssh_ppp_pkt_buffer_isinit(SshPppPktBuffer buf)
{
  SSH_ASSERT(buf != NULL);

  if (buf->buffer != NULL && buf->maxbytes > 0)
    return TRUE;

  return FALSE;
}

SshPppPktBuffer
ssh_ppp_pkt_buffer_create(unsigned long size)
{
  SshPppPktBuffer r;

  r = ssh_malloc(sizeof(SshPppPktBufferStruct));

  if (r == NULL)
    return NULL;

  if (ssh_ppp_pkt_buffer_init(r,size) == FALSE)
    {
      ssh_free(r);
      return NULL;
    }

  return r;
}

Boolean
ssh_ppp_pkt_buffer_set_size(SshPppPktBuffer buf, unsigned long size)
{
  SshUInt8 *tmp;

  if (buf->buffer == NULL)
    return ssh_ppp_pkt_buffer_init(buf,size);

  if (size == buf->maxbytes)
    return TRUE;

  tmp = ssh_malloc(size);

  if (tmp == NULL)
    return FALSE;

  memcpy(tmp, buf->buffer, buf->maxbytes);
  ssh_free(buf->buffer);

  buf->buffer = tmp;
  buf->maxbytes = size;

  /* If truncate, then truncate everything */

  if (buf->maxbytes < buf->nbytes + buf->offset)
    {
      buf->nbytes = 0;
      buf->offset = 0;
    }

  return TRUE;
}

void
ssh_ppp_pkt_buffer_free(SshPppPktBuffer buf)
{
  if (buf->buffer != NULL)
    {
      SSH_DEBUG(SSH_D_MY,("Freeing buffer %p size %ld",
                          buf->buffer,buf->maxbytes));

      ssh_free(buf->buffer);
    }

  ssh_ppp_pkt_buffer_uninit(buf);
}

void
ssh_ppp_pkt_buffer_copy(SshPppPktBuffer dst, SshPppPktBuffer src,
                        unsigned long offset1, unsigned long offset2,
                        unsigned long len)
{
  SSH_ASSERT(dst->buffer != NULL);
  SSH_ASSERT(src->buffer != NULL);
  SSH_ASSERT(offset2 + len <= src->nbytes);

  if (dst->offset + offset1 + len > dst->maxbytes)
    {
      SSH_ASSERT(0);
      return;
    }

  memmove(&dst->buffer[offset1+dst->offset],
          &src->buffer[offset2+src->offset],
          len);

  if (len + offset1 > dst->nbytes)
    {
      dst->nbytes = len + offset1;
    }
}

void
ssh_ppp_pkt_buffer_uninit(SshPppPktBuffer buf)
{
  SSH_ASSERT(buf != NULL);

  buf->buffer = NULL;
  buf->maxbytes = 0;
  buf->nbytes = 0;
  buf->offset = 0;
}

Boolean
ssh_ppp_pkt_buffer_isempty(SshPppPktBuffer buf)
{
  return (buf->nbytes == 0);
}

unsigned long
ssh_ppp_pkt_buffer_get_size(SshPppPktBuffer buf)
{
  if (buf->buffer == NULL)
    return 0;

  return buf->maxbytes;
}

void
ssh_ppp_pkt_buffer_clear(SshPppPktBuffer buf)
{
  buf->nbytes = 0;
  buf->offset = 0;
}

Boolean
ssh_ppp_pkt_buffer_isfull(SshPppPktBuffer buf)
{
  SSH_ASSERT(buf->offset + buf->nbytes <= buf->maxbytes);

  return (buf->offset + buf->nbytes) >= buf->maxbytes;
}

unsigned long
ssh_ppp_pkt_buffer_get_header(SshPppPktBuffer buf)
{
  SSH_ASSERT(buf->offset + buf->nbytes <= buf->maxbytes);

  return buf->offset;
}

unsigned long
ssh_ppp_pkt_buffer_get_trailer(SshPppPktBuffer buf)
{
  SSH_ASSERT(buf->offset + buf->nbytes <= buf->maxbytes);

  return buf->maxbytes - buf->offset - buf->nbytes;
}

unsigned long
ssh_ppp_pkt_buffer_get_contentlen(SshPppPktBuffer buf)
{
  return buf->nbytes;
}

SshUInt8
ssh_ppp_pkt_buffer_get_uint8(SshPppPktBuffer buf, unsigned long i)
{
  SSH_ASSERT(i < buf->nbytes);
  SSH_ASSERT(buf->offset + buf->nbytes <= buf->maxbytes);

  return buf->buffer[buf->offset+i];
}

SshUInt16
ssh_ppp_pkt_buffer_get_uint16(SshPppPktBuffer buf, unsigned long i)
{
  SshUInt16 hi,lo;

  hi = ssh_ppp_pkt_buffer_get_uint8(buf,i);
  lo = ssh_ppp_pkt_buffer_get_uint8(buf,i+1);

  return (hi << 8) | lo;
}

SshUInt32
ssh_ppp_pkt_buffer_get_uint32(SshPppPktBuffer buf, unsigned long i)
{
  SshUInt32 hi,lo;

  hi = ssh_ppp_pkt_buffer_get_uint16(buf,i);
  lo = ssh_ppp_pkt_buffer_get_uint16(buf,i+2);

  return (hi << 16) | lo;
}


void
ssh_ppp_pkt_buffer_set_uint8(SshPppPktBuffer buf, unsigned long i,
                             SshUInt8 val)
{
  SSH_ASSERT(i < buf->nbytes);
  SSH_ASSERT(buf->offset + buf->nbytes <= buf->maxbytes);

  buf->buffer[buf->offset+i] = val;
}

void
ssh_ppp_pkt_buffer_insert(SshPppPktBuffer buf, unsigned long i,
                          unsigned long count)
{
  SSH_ASSERT(i < buf->nbytes);

  if (count + buf->offset + buf->nbytes > buf->maxbytes)
    {
      SSH_ASSERT(0);
      return;
    }

  memmove(&buf->buffer[buf->offset+i+count],
          &buf->buffer[buf->offset+i],buf->nbytes - i);

  buf->nbytes += count;
}

void
ssh_ppp_pkt_buffer_insert_uint8(SshPppPktBuffer buf, unsigned long i,
                                SshUInt8 val)
{
  ssh_ppp_pkt_buffer_insert(buf,i,1);
  ssh_ppp_pkt_buffer_set_uint8(buf,i,val);
}

void
ssh_ppp_pkt_buffer_prepend_uint8(SshPppPktBuffer buf, SshUInt8 val)
{
  if (buf->offset == 0)
    {
      SSH_ASSERT(0);
      return;
    }

  buf->offset--;
  buf->nbytes++;
  buf->buffer[buf->offset] = val;
}

void
ssh_ppp_pkt_buffer_prepend_uint16(SshPppPktBuffer buf, SshUInt16 val)
{
  ssh_ppp_pkt_buffer_prepend_uint8(buf,(SshUInt8)(val & 0xff));
  ssh_ppp_pkt_buffer_prepend_uint8(buf,(SshUInt8)((val >> 8) & 0xff));
}

void
ssh_ppp_pkt_buffer_prepend_uint32(SshPppPktBuffer buf, SshUInt32 val)
{
  ssh_ppp_pkt_buffer_prepend_uint16(buf, (SshUInt8)(val & 0xffff));
  ssh_ppp_pkt_buffer_prepend_uint16(buf, (SshUInt8)((val >> 16) & 0xffff));
}

void
ssh_ppp_pkt_buffer_append_uint8(SshPppPktBuffer buf,SshUInt8 val)
{
  /* In case of heap overflow */

  if (buf->offset + buf->nbytes >= buf->maxbytes)
    {
      SSH_ASSERT(0);
      return;
    }

  buf->buffer[buf->offset+buf->nbytes] = val;
  buf->nbytes++;
}

void
ssh_ppp_pkt_buffer_append_buf(SshPppPktBuffer pkt,
                              SshUInt8 *buf,
                              unsigned long len)
{
  unsigned long i;

  /* In case of heap overflow */

  if (pkt->offset + pkt->nbytes + len > pkt->maxbytes)
    {
      SSH_ASSERT(0);
      return;
    }

  for (i = 0; i < len; i++)
    {
      ssh_ppp_pkt_buffer_append_uint8(pkt,buf[i]);
    }
}

void
ssh_ppp_pkt_buffer_get_buf(SshPppPktBuffer pkt,unsigned long offset,
                           SshUInt8 *buf, unsigned long len)
{
  unsigned long i;

  for (i = 0; i < len; i++)
    {
      buf[i] = ssh_ppp_pkt_buffer_get_uint8(pkt,offset+i);
    }
}


void
ssh_ppp_pkt_buffer_append_uint16(SshPppPktBuffer buf, SshUInt16 val)
{
  ssh_ppp_pkt_buffer_append_uint8(buf,(SshUInt8)((val >> 8) & 0xff));
  ssh_ppp_pkt_buffer_append_uint8(buf,(SshUInt8)(val & 0xff));
}

void
ssh_ppp_pkt_buffer_append_uint32(SshPppPktBuffer buf, SshUInt32 val)
{
  ssh_ppp_pkt_buffer_append_uint16(buf, (SshUInt16)((val >> 16) & 0xffff));
  ssh_ppp_pkt_buffer_append_uint16(buf, (SshUInt16)(val & 0xffff));
}

void
ssh_ppp_pkt_buffer_offset(SshPppPktBuffer buf, unsigned long i)
{
  SSH_ASSERT(buf->nbytes == 0);
  SSH_ASSERT(i + buf->offset < buf->maxbytes);

  buf->offset += i;
}

void
ssh_ppp_pkt_buffer_skip(SshPppPktBuffer buf, unsigned long i)
{
  SSH_ASSERT(i <= buf->nbytes);

  buf->offset += i;
  buf->nbytes -= i;
}

void
ssh_ppp_pkt_buffer_truncate_rel(SshPppPktBuffer buf, unsigned long i)
{
  SSH_ASSERT(i <= buf->nbytes);
  buf->nbytes -= i;
}

void
ssh_ppp_pkt_buffer_truncate_abs(SshPppPktBuffer buf, unsigned long i)
{
  SSH_ASSERT(i <= buf->nbytes);
  buf->nbytes = i;
}


SshPppPktBuffer
ssh_ppp_pkt_buffer_save(SshPppPktBuffer dst, SshPppPktBuffer src)
{
  dst->buffer = src->buffer;
  dst->maxbytes = src->maxbytes;
  dst->nbytes = src->nbytes;
  dst->offset = src->offset;

  return dst;
}

SshPppPktBuffer
ssh_ppp_pkt_buffer_dup(SshPppPktBuffer src)
{
  SshPppPktBuffer dst;

  dst = ssh_ppp_pkt_buffer_create(src->maxbytes);
  memcpy(dst->buffer,src->buffer,src->maxbytes);
  dst->nbytes = src->nbytes;
  dst->offset = src->offset;

  return dst;
}

SshUInt8*
ssh_ppp_pkt_buffer_get_ptr(SshPppPktBuffer buf, unsigned long offset,
                           unsigned long len)
{
  SSH_ASSERT(offset + len <= buf->nbytes);
  SSH_ASSERT(buf->offset + offset + len <= buf->maxbytes);

  return &buf->buffer[offset+buf->offset];
}

void
ssh_ppp_pkt_buffer_consume_header(SshPppPktBuffer buf)
{
  memmove(&buf->buffer[0],&buf->buffer[buf->offset],buf->nbytes);
  buf->offset = 0;

}

void
ssh_ppp_pkt_buffer_consume(SshPppPktBuffer buf,
                           unsigned long offset,
                           unsigned long len)
{
  SSH_ASSERT(offset+len <= buf->nbytes);

  memmove(&buf->buffer[buf->offset+offset],
          &buf->buffer[buf->offset+offset+len],
          buf->nbytes - offset - len);

  buf->nbytes -= len;
}

