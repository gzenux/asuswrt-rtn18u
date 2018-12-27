/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IP calculation related functions and definitions.
*/

#include "sshincludes.h"
#include "sshinet.h"

#define SSH_DEBUG_MODULE "SshInetCalc"

/* Increment IP address by one. Return TRUE if success and
   FALSE if the IP address wrapped. */
Boolean ssh_ipaddr_increment(SshIpAddr ip)
{
  if (SSH_IP_IS4(ip))
    {
      SshUInt32 temp;

      temp = SSH_IP4_TO_INT(ip);
      temp++;
      temp &= 0xffffffffL;
      SSH_INT_TO_IP4(ip, temp);
      if (temp == 0)
        return FALSE;
      return TRUE;
    }
#if defined(WITH_IPV6)
  else
    {
      SshUInt8 temp;
      int i;

      for(i = 15; i >= 0; i--)
        {
          temp = SSH_IP6_BYTEN(ip, i);
          temp++;
          temp &= 0xff;
          SSH_IP6_BYTEN(ip, i) = temp;
          if (temp != 0)
            return TRUE;
        }
      return FALSE;
    }
#endif /* WITH_IPV6 */
  return FALSE;
}

/* Decrement IP address by one. Return TRUE if success and
   FALSE if the IP address wrapped. */
Boolean ssh_ipaddr_decrement(SshIpAddr ip)
{
  if (SSH_IP_IS4(ip))
    {
      SshUInt32 temp;

      temp = SSH_IP4_TO_INT(ip);
      temp--;
      temp &= 0xffffffffL;
      SSH_INT_TO_IP4(ip, temp);
      if (temp == 0xffffffff)
        return FALSE;
      return TRUE;
    }
#if defined(WITH_IPV6)
  else
    {
      SshUInt8 temp;
      int i;

      for(i = 15; i >= 0; i--)
        {
          temp = SSH_IP6_BYTEN(ip, i);
          temp--;
          temp &= 0xff;
          SSH_IP6_BYTEN(ip, i) = temp;
          if (temp != 0xff)
            return TRUE;
        }
      return FALSE;
    }
#endif /* WITH_IPV6 */
  return FALSE;
}
