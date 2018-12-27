/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address merge related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetMerge"

/* Merges two ip addresses (left_ip and right_ip) so that leftmost
   keep_bits are from left_ip and rightmost bits are from right_ip.

   Mask length of the result is set to 0. */

void ssh_ipaddr_merge_bits(SshIpAddr result, SshIpAddr left_ip,
                           unsigned int left_bits, SshIpAddr right_ip)
{
  unsigned int total_bits, i;

  total_bits = (SSH_IP_IS6(left_ip) ? 128 : 32);

  SSH_ASSERT(left_bits <= (SSH_IP_IS6(left_ip) ? 128 : 32));
  SSH_ASSERT(left_ip->type == right_ip->type);

  result->type = left_ip->type;
  result->mask_len = 0;

  /* Copy whole left bytes */
  for (i = 0; (i + 7) < left_bits; i += 8)
    result->addr_data[i / 8] = left_ip->addr_data[i / 8];

  /* If on non-byte boundary, do bit fiddling */
  if ((left_bits - i) != 0) {
    result->addr_data[i / 8] =
      (left_ip->addr_data[i / 8] & (0xff << (8 - left_bits % 8))) |
      (right_ip->addr_data[i / 8] & ~(0xff << (8 - left_bits % 8)));

#if 0
    fprintf(stderr,
            "i=%d left_bits=%d left_bytes=%d total_bits=%d shift=%d left=%d "
            "right=%d\n",
            i, left_bits, left_bits / 8, total_bits,
            (8 - left_bits % 8),
            (left_ip->addr_data[i / 8] & (0xff << (8 - left_bits % 8))),
            (right_ip->addr_data[i / 8] & ~(0xff << (8 - left_bits % 8))));
#endif
    i += 8;
  }

  /* Copy whole right bytes */
  for (; i < total_bits; i += 8)
    result->addr_data[i / 8] = right_ip->addr_data[i / 8];
}

