/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshinetencode.h"

#define SSH_DEBUG_MODULE "SshInetEncode"

/* Special formatter for the ssh_encode function to encode IP-address. Note,
   that this never returns 0, but this returns the number of bytes required
   from the buffer. */
int ssh_encode_ipaddr_encoder(unsigned char *buf, size_t len,
                              const void *datum)
{
  size_t desired_len;
  SshIpAddr ip = (SshIpAddr) datum;

  if (!ip || ip->type == SSH_IP_TYPE_NONE)
    {
      ssh_encode_array(buf, len,
                       SSH_ENCODE_CHAR(SSH_IP_TYPE_NONE),
                       SSH_FORMAT_END);
      return 1;
    }

#ifdef WITH_IPV6
  desired_len = 1 + 8 + SSH_IP_ADDR_LEN(ip);
#else  /* WITH_IPV6 */
  desired_len = 1 + 4 + SSH_IP_ADDR_LEN(ip);
#endif /* WITH_IPV6 */

  SSH_ASSERT(desired_len <= SSH_MAX_IPADDR_ENCODED_LENGTH);
  ssh_encode_array(buf, len,
                   SSH_ENCODE_CHAR(ip->type),
                   SSH_ENCODE_UINT32(ip->mask_len),
                   SSH_ENCODE_DATA(ip->addr_data,
                                   SSH_IP_ADDR_LEN(ip)),
#ifdef WITH_IPV6
                   SSH_ENCODE_UINT32(ip->scope_id.scope_id_union.ui32),
#endif /* WITH_IPV6 */
                   SSH_FORMAT_END);
  return desired_len;
}

size_t ssh_encode_ipaddr_array(unsigned char *buf, size_t bufsize,
                               const SshIpAddr ip)
{
  if (!ip || ip->type == SSH_IP_TYPE_NONE)
    return ssh_encode_array(buf, bufsize,
                            SSH_ENCODE_CHAR(SSH_IP_TYPE_NONE),
                            SSH_FORMAT_END);
  return ssh_encode_array(buf, bufsize,
                          SSH_ENCODE_CHAR(ip->type),
                          SSH_ENCODE_UINT32(ip->mask_len),
                          SSH_ENCODE_DATA(ip->addr_data,
                                          SSH_IP_ADDR_LEN(ip)),
#ifdef WITH_IPV6
                          SSH_ENCODE_UINT32(ip->scope_id.scope_id_union.ui32),
#endif /* WITH_IPV6 */
                          SSH_FORMAT_END);
}

size_t ssh_encode_ipaddr_array_alloc(unsigned char **buf_return,
                                     const SshIpAddr ip)
{
  size_t req, got;

  if (ip->type == SSH_IP_TYPE_NONE)
    req = 1;
  else
#ifdef WITH_IPV6
    req = 1 + 8 + SSH_IP_ADDR_LEN(ip);
#else  /* WITH_IPV6 */
    req = 1 + 4 + SSH_IP_ADDR_LEN(ip);
#endif /* WITH_IPV6 */

  if (buf_return == NULL)
    return req;

  if ((*buf_return = ssh_malloc(req)) == NULL)
    return 0;

  got = ssh_encode_ipaddr_array(*buf_return, req, ip);

  if (got != req)
    {
      ssh_free(*buf_return);
      *buf_return = NULL;
      return 0;
    }

  return got;
}

int ssh_decode_ipaddr_array(const unsigned char *buf, size_t len,
                            void * ipaddr)
{
  size_t point, got;
  SshUInt32 mask_len;
#ifdef WITH_IPV6
  SshUInt32 scope_id;
#endif /* WITH_IPV6 */
  unsigned int type;
  SshIpAddr ip = (SshIpAddr)ipaddr;
  point = 0;

  if ((got = ssh_decode_array(buf + point, len - point,
                              SSH_DECODE_CHAR(&type),
                              SSH_FORMAT_END)) != 1)
      return 0;

  /* Make sure scope-id (that is not present at the kernel) is
     zeroed */
  memset(ip, 0, sizeof(*ip));

  ip->type = (SshUInt8) type;

  point += got;

  if (ip->type == SSH_IP_TYPE_NONE)
    return point;

  if ((got = ssh_decode_array(buf + point, len - point,
                              SSH_DECODE_UINT32(&mask_len),
                              SSH_DECODE_DATA(ip->addr_data,
                                              SSH_IP_ADDR_LEN(ip)),
#ifdef WITH_IPV6
                              SSH_DECODE_UINT32(&scope_id),
                              SSH_FORMAT_END)) != ((2 * sizeof(SshUInt32))
                                                   + SSH_IP_ADDR_LEN(ip)))
#else  /* WITH_IPV6 */
                              SSH_FORMAT_END)) != (4 + SSH_IP_ADDR_LEN(ip)))
#endif /* WITH_IPV6 */
      return 0;

  /* Sanity check */
  if (mask_len > 255)
          return 0;

  ip->mask_len = (SshUInt8) mask_len;

  point += got;

#ifdef WITH_IPV6
  ip->scope_id.scope_id_union.ui32 = scope_id;
#endif /* WITH_IPV6 */

  /* Sanity check */
  if (!SSH_IP_IS4(ip) && !SSH_IP_IS6(ip))
    return 0;

  return point;
}

#if !(defined(_KERNEL) || defined(KERNEL))
int ssh_encode_ipaddr_buffer(SshBuffer buffer, const SshIpAddr ip)
{
  size_t got;
  unsigned char tmpbuf[SSH_MAX_IPADDR_ENCODED_LENGTH];

  got = ssh_encode_ipaddr_array(tmpbuf, sizeof(tmpbuf), ip);
  if (got == 0)
    return 0;

  if (ssh_buffer_append(buffer, tmpbuf, got) == SSH_BUFFER_OK)
    return got;
  else
    return 0;

}

int ssh_ipaddr_decode_buffer(SshBuffer buffer, SshIpAddr ip)
{
  size_t got;

  if ((got = ssh_decode_ipaddr_array(ssh_buffer_ptr(buffer),
                                     ssh_buffer_len(buffer),
                                     ip)) == 0)
    return 0;

  ssh_buffer_consume(buffer, got);

  return got;
}
#endif
