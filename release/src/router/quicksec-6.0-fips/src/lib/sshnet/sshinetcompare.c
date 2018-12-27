/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address comparison related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetCompare"

#define MAX_IP_ADDR_LEN 16

/* Compares two IP addresses, and returns <0 if address1 is smaller
   (in some implementation-defined sense, usually numerically), 0 if
   they denote the same address (though possibly written differently),
   and >0 if address2 is smaller (in the implementation-defined
   sense).  The result is zero if either address is invalid. */

int ssh_inet_ip_address_compare(const unsigned char *address1,
                                const unsigned char *address2)
{
  unsigned char a1[MAX_IP_ADDR_LEN], a2[MAX_IP_ADDR_LEN];
  size_t len;
  int ret;

  len = MAX_IP_ADDR_LEN;
  if (!ssh_inet_strtobin(address1, a1, &len))
    return 0;

  if (len == 4)
    {
      memmove(a1 + 12, a1, 4);
      memset(a1, 0, 12);
    }

  len = MAX_IP_ADDR_LEN;
  if (!ssh_inet_strtobin(address2, a2, &len))
    return 0;

  if (len == 4)
    {
      memmove(a2 + 12, a2, 4);
      memset(a2, 0, 12);
    }

  ret = memcmp(a1, a2, 16);
  if (ret < 0)
    return -1;
  else if (ret > 0)
    return 1;
  else
    return 0;
}
