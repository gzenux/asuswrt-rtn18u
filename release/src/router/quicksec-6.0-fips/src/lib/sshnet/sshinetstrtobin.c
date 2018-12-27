/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP address string to bin related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetStrToBin"


/* Convert ip number string to binary format. The binary format is
   unsigned character array containing the ip address in network byte
   order. If the ip address is ipv4 address then this fills 4 bytes to
   the buffer, if it is ipv6 address then this will fills 16 bytes to
   the buffer. The buffer length is modified accordingly. This returns
   TRUE if the address is valid and conversion is successful (the
   buffer is large enough) and FALSE otherwise.  */

Boolean ssh_inet_strtobin(const unsigned char *ip_address,
                          unsigned char *out_buffer,
                          size_t *out_buffer_len_in_out)
{
  SshIpAddrStruct ipaddr;

  /* Parse the IP address.  Return FALSE on error.*/
  if (!ssh_ipaddr_parse(&ipaddr, ip_address))
    return FALSE;

  /* Convert the IP address to binary. */
  if (SSH_IP_IS6(&ipaddr))
    {
      if (*out_buffer_len_in_out < 16)
        return FALSE;
      SSH_IP6_ENCODE(&ipaddr, out_buffer);
      *out_buffer_len_in_out = 16;
    }
  else
    {
      if (*out_buffer_len_in_out < 4)
        return FALSE;
      SSH_IP4_ENCODE(&ipaddr, out_buffer);
      *out_buffer_len_in_out = 4;
    }
  return TRUE;
}

