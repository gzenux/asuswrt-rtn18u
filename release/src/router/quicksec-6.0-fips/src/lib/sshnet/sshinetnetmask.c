/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address netmaks related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetNetMask"

#define MAX_IP_ADDR_LEN 16


/* Compares comma separated list of ip nets and ip-address. Returns
   TRUE if ip-address is inside one of the nets given in
   net-address/netmask-bits format. */

Boolean ssh_inet_compare_netmask(const unsigned char *netmask,
                                 const unsigned char *ip_in)
{
  unsigned char net[MAX_IP_ADDR_LEN], mask[MAX_IP_ADDR_LEN],
    ip[MAX_IP_ADDR_LEN];
  size_t len;
  unsigned char temp_buffer[256], *p, *p2, *next;
  int mask_bits;

  memset(net, 0, MAX_IP_ADDR_LEN);
  memset(ip, 0, MAX_IP_ADDR_LEN);

  len = MAX_IP_ADDR_LEN;
  if (!ssh_inet_strtobin(ip_in, ip, &len))
    return FALSE;

  if (len == 4)
    {
      memmove(ip + 12, ip, 4);
      memset(ip, 0, 4);
    }
  do {
    p = ssh_ustrchr(netmask, ',');
    if (p != NULL)
      {
        next = p + 1;
        if (p - netmask < (int)sizeof(temp_buffer))
          {
            ssh_ustrncpy(temp_buffer, netmask, (size_t)(p - netmask));
            temp_buffer[p - netmask] = '\0';
          }
        else
          {
            ssh_ustrncpy(temp_buffer, netmask, sizeof(temp_buffer));
            temp_buffer[sizeof(temp_buffer) - 1] = '\0';
          }
      }
    else
      {
        next = NULL;
        ssh_ustrncpy(temp_buffer, netmask, sizeof(temp_buffer));
        temp_buffer[sizeof(temp_buffer) - 1] = '\0';
      }

    /* Basically this is strrchr. */
    for (p = NULL, p2 = temp_buffer; *p2; p2++)
      if (*p2 == (unsigned char)'/')
        p = p2;

    if (p == NULL)
      {
        mask_bits = MAX_IP_ADDR_LEN * 8;
      }
    else
      {
        *p++ = '\0';
        if (*p < '0' || *p > '9')
          mask_bits = -1;
        else
          {
            for (mask_bits = 0; *p >= '0' && *p <= '9'; p++)
              mask_bits = 10 * mask_bits + *p - '0';
          }
      }
    len = MAX_IP_ADDR_LEN;
    if (ssh_inet_strtobin(temp_buffer, net, &len) && mask_bits != -1)
      {
        if (len == 4)
          {
            memmove(net + 12, net, 4);
            memset(net, 0, 4);
            mask_bits += 96;
          }
        if (mask_bits > 128)
          mask_bits = 128;

        memset(mask, 0, MAX_IP_ADDR_LEN);
        memset(mask, 255, (size_t)(mask_bits / 8));
        if (mask_bits % 8 != 0)
          {
            SSH_ASSERT(mask_bits < 128);
            mask[mask_bits / 8] =
              "\000\200\300\340\360\370\374\376"[mask_bits % 8];
          }
        for (len = 0; len < MAX_IP_ADDR_LEN; len++)
          {
            if ((ip[len] & mask[len]) != (net[len] & mask[len]))
              break;
          }
        if (len == MAX_IP_ADDR_LEN)
          return TRUE;
      }
    netmask = next;
  } while (netmask != NULL);
  return FALSE;
}
