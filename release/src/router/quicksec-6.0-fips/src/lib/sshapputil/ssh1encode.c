/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Decode ssh1 type stuff from buffer.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshmp.h"
#include "ssh1encode.h"

Boolean ssh1_decode_byte(SshBuffer buffer, SshUInt8 *b)
{
  if (ssh_buffer_len(buffer) < 1)
    return FALSE;
  if (b != NULL)
    *b = (SshUInt8)(*(ssh_buffer_ptr(buffer)));
  ssh_buffer_consume(buffer, 1);
  return TRUE;
}

Boolean ssh1_decode_int(SshBuffer buffer, SshUInt32 *n)
{
  unsigned char b0, b1, b2, b3;

  if (ssh_buffer_len(buffer) < 4)
    return FALSE;
  if (n != NULL) {
    b0 = *(ssh_buffer_ptr(buffer));
    b1 = *(ssh_buffer_ptr(buffer) + 1);
    b2 = *(ssh_buffer_ptr(buffer) + 2);
    b3 = *(ssh_buffer_ptr(buffer) + 3);
    *n = (SshUInt32)((((SshUInt32)b0) << 24) |
                     (((SshUInt32)b1) << 16) |
                     (((SshUInt32)b2) << 8) |
                     (((SshUInt32)b3)));
  }
  ssh_buffer_consume(buffer, 4);
  return TRUE;
}

Boolean ssh1_decode_mp(SshBuffer buffer, SshMPInteger n)
{
  SshUInt32 len;
  unsigned char *len_buf;
  size_t num_buf_len;

  if (ssh_buffer_len(buffer) < 2)
    return FALSE;
  len_buf = ssh_buffer_ptr(buffer);
  len = (len_buf[0] * 0x100) + len_buf[1];
  num_buf_len = ((len + 7) >> 3) & 0xffff;
  if (ssh_buffer_len(buffer) < (2 + num_buf_len))
    return FALSE;
  ssh_mprz_set_buf(n, &(len_buf[2]), num_buf_len);
  ssh_buffer_consume(buffer, num_buf_len + 2);
  return TRUE;
}

Boolean ssh1_decode_string(SshBuffer buffer,
                           char **str,
                           size_t *str_len)
{
  size_t len;
  unsigned char b0, b1, b2, b3;

  if (ssh_buffer_len(buffer) < 4)
    return FALSE;
  b0 = *(ssh_buffer_ptr(buffer));
  b1 = *(ssh_buffer_ptr(buffer) + 1);
  b2 = *(ssh_buffer_ptr(buffer) + 2);
  b3 = *(ssh_buffer_ptr(buffer) + 3);
  len = (size_t)((((SshUInt32)b0) << 24) |
                 (((SshUInt32)b1) << 16) |
                 (((SshUInt32)b2) << 8) |
                 (((SshUInt32)b3)));
  if ((len + 4) > ssh_buffer_len(buffer))
    return FALSE;
  if (str)
    *str = ssh_xmemdup(ssh_buffer_ptr(buffer) + 4, len);
  if (str_len)
    *str_len = len;
  ssh_buffer_consume(buffer, len + 4);
  return TRUE;
}

Boolean ssh1_decode_data(SshBuffer buffer, unsigned char **data, size_t len)
{
  if (ssh_buffer_len(buffer) < len)
    return FALSE;
  if (data)
    *data = ssh_xmemdup(ssh_buffer_ptr(buffer), len);
  ssh_buffer_consume(buffer, len);
  return TRUE;
}

void ssh1_encode_byte(SshBuffer buffer, SshUInt8 b)
{
  unsigned char c = (unsigned char)b;

  ssh_xbuffer_append(buffer, &c, 1);
  return;
}

void ssh1_encode_int(SshBuffer buffer, SshUInt32 n)
{
  unsigned char buf[4];

  buf[0] = (unsigned char)((n >> 24) & 0xff);
  buf[1] = (unsigned char)((n >> 16) & 0xff);
  buf[2] = (unsigned char)((n >> 8) & 0xff);
  buf[3] = (unsigned char)(n & 0xff);
  ssh_xbuffer_append(buffer, buf, 4);
  return;
}

void ssh1_encode_mp(SshBuffer buffer, SshMPInteger n)
{
  SshUInt32 len;
  unsigned char len_buf[2];
  unsigned char *num_buf;
  size_t num_buf_len;

  len = ssh_mprz_get_size(n, 2);
  len_buf[0] = (len >> 8) & 0xff;
  len_buf[1] = len & 0xff;
  num_buf_len = ((len + 7) >> 3) & 0xffff;
  num_buf = ssh_xmalloc(num_buf_len);
  ssh_mprz_get_buf(num_buf, num_buf_len, n);
  ssh_xbuffer_append(buffer, len_buf, 2);
  ssh_xbuffer_append(buffer, num_buf, num_buf_len);
  ssh_xfree(num_buf);
  return;
}

void ssh1_encode_string(SshBuffer buffer, const char *str, size_t len)
{
  ssh1_encode_int(buffer, (SshUInt32)len);
  ssh_xbuffer_append(buffer, (unsigned char *)str, (size_t)len);
  return;
}

void ssh1_encode_data(SshBuffer buffer,
                      const unsigned char *data,
                      size_t len)
{
  ssh_xbuffer_append(buffer, data, len);
  return;
}
