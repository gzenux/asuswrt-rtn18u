/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP Ethernet related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetEther"

/* Rendering function for Ethernet MAC addresses. */
int ssh_etheraddr_render(unsigned char *buf, int buf_size, int precision,
                         void *datum)
{
  int len;
  unsigned char *hw_addr = datum;

  ssh_snprintf(buf, buf_size + 1, "%02x:%02x:%02x:%02x:%02x:%02x",
               hw_addr[0], hw_addr[1], hw_addr[2],
               hw_addr[3], hw_addr[4], hw_addr[5]);

  len = ssh_ustrlen(buf);

  if (precision >= 0 && len > precision)
    len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

