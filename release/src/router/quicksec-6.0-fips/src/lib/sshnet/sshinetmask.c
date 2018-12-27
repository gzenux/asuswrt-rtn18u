/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP mask related related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetMask"

#define MAX_IP_ADDR_LEN 16


/* Compares two IP addresses in the internal representation and returns
   TRUE if they are equal. */

Boolean ssh_ipaddr_with_mask_equal(SshIpAddr ip1, SshIpAddr ip2,
                                   SshIpAddr mask)
{
  unsigned int i;
  unsigned char i1[MAX_IP_ADDR_LEN], i2[MAX_IP_ADDR_LEN], m[MAX_IP_ADDR_LEN];

  if ((ip1->type != ip2->type) || (ip2->type != mask->type))
    return FALSE;

  memset(i1, 0, 16);
  memset(i2, 0, 16);
  memset(m, 255, 16);

  if (SSH_IP_IS4(ip1))
    memcpy(i1 + 12, ip1->addr_data, 4);
  else
    memcpy(i1, ip1->addr_data, 16);

  if (SSH_IP_IS4(ip2))
    memcpy(i2 + 12, ip2->addr_data, 4);
  else
    memcpy(i2, ip2->addr_data, 16);

  if (SSH_IP_IS4(mask))
    memcpy(m + 12, mask->addr_data, 4);
  else
    memcpy(m, mask->addr_data, 16);

  for (i = 0; i < 16; i++)
    if ((i1[i] & m[i]) != (i2[i] & m[i]))
      return FALSE;

  return TRUE;
}

Boolean ssh_ipaddr_mask_equal(SshIpAddr ip, SshIpAddr masked_ip)
{
  register SshUInt32 *a1, *a2;
  register int ml;
#ifndef WORDS_BIGENDIAN
  register unsigned char *c1, *c2;
#endif

  /* Different type? */
  if (ip->type != masked_ip->type)
    return FALSE;

  a1 = (SshUInt32 *) ip->addr_data;
  a2 = (SshUInt32 *) masked_ip->addr_data;
  ml = masked_ip->mask_len;

  /* Chuck away ml in full 32-bit words */
  for (; ml > 31; ml -= 32)
    {
      if (*a1++ != *a2++)
        return FALSE;
    }

  if (ml == 0)
    return TRUE;

  /* Then we have only <32 bit part left */
#ifdef WORDS_BIGENDIAN
  if ((*a1 ^ *a2) & (0xffffffff << (32 - ml)))
    return FALSE;

  return TRUE;
#else
  c1 = (unsigned char *) a1;
  c2 = (unsigned char *) a2;

  for (; ml > 7; ml -= 8)
    {
      if (*c1++ != *c2++)
        return FALSE;
    }

  if (ml == 0)
    return TRUE;

  if ((*c1 ^ *c2) & (0xff  << (8 - ml)))
    return FALSE;

  return TRUE;
#endif
}
