/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP Hash related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetHash"

/* Produces a value that can (modulo a prime) be used as a hash value for
   the ip address.  The value is suitable for use with a prime-sized hash
   table. */

unsigned long ssh_ipaddr_hash(SshIpAddr ip)
{
  unsigned long value;
  size_t len;
  unsigned int i;

  if (SSH_IP_DEFINED(ip))
    {
      len = SSH_IP_IS6(ip) ? 16 : 4;
      for (i = 0, value = len; i < len; i++)
        value = 257 * value + ip->addr_data[i] + 3 * (value >> 23);
    }
  else
    {
      /* Random number to make it distinct from others. */
      value = 42;
    }
  return value;
}
