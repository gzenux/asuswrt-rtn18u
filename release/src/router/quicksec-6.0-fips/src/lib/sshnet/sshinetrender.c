/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP Renderer related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetRender"

/* Render function to render IP addresses for %@ format string for
   ssh_e*printf */
int ssh_ipaddr_render(unsigned char *buf, int buf_size, int precision,
                      void *datum)
{
  const SshIpAddr ip = (SshIpAddr) datum;
  int len;

  if (ip == NULL)
    ssh_snprintf(buf, buf_size + 1, "<null>");
  else if (ip->type == SSH_IP_TYPE_NONE)
    ssh_snprintf(buf, buf_size + 1, "<none>");
  else if (SSH_IP_ADDR_LEN(ip) * 8 == SSH_IP_MASK_LEN(ip))
    (void) ssh_ipaddr_print(ip, buf, buf_size + 1);
  else
    (void) ssh_ipaddr_print_with_mask(ip, buf, buf_size + 1);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

int ssh_ipaddr4_uint32_render(unsigned char *buf, int buf_size, int precision,
                              void *datum)
{
  int len;
  unsigned char tmp[4];
  /* This small kludge is here to avoid compilation warnings on 64-bit
     platforms. */
  unsigned long tmp_num = (unsigned long)(size_t)datum;

  SSH_PUT_32BIT(tmp, (SshUInt32) tmp_num);
  ssh_ipaddr_ipv4_print(tmp, buf, buf_size + 1);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

int ssh_ipaddr6_byte16_render(unsigned char *buf, int buf_size, int precision,
                              void *datum)
{
  int len;

  /* This does not print out scope id (not present at the input) */
  ssh_ipaddr_ipv6_print((unsigned char*) datum, buf, buf_size + 1, 0);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}



/* Renders an IP address mask. */
int ssh_ipmask_render(unsigned char *buf, int buf_size, int precision,
                      void *datum)
{
  const SshIpAddr ip = (SshIpAddr) datum;
  int i, j;
  int bits = 0;
  int len;

  /* The non-IPv6 masks are printed just like IP addresses. */
  if (!SSH_IP_IS6(ip))
    return ssh_ipaddr_render(buf, buf_size, precision, datum);

  /* The IPv6 masks are rendered as number describing the prefix
     len. */

  for (i = 0; i < SSH_IP_ADDR_LEN(ip); i++)
    for (j = 7; j >= 0; j--)
      if (ip->addr_data[i] & (1 << j))
        bits++;

  ssh_snprintf(buf, buf_size + 1, "%d", bits);
  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}
