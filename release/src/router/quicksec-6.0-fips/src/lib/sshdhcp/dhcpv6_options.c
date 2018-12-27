/**
   @copyright
   Copyright (c) 2013 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshtcp.h"

#include "sshdhcp.h"
#include "dhcp_internal.h"

#define SSH_DEBUG_MODULE "SshDHCPV6Options"

/*****************************************************************************

                           DHCP Option encoding

 *****************************************************************************/

/* Put new option to the DHCP options. The order of the option data in
   the options buffer will be {option code, option length, option
   data} as defined by the protocol. */
void ssh_dhcpv6_option_put(SshDHCPv6Message message,
                           SshDHCPv6Option option,
                           size_t len, unsigned char *data)
{
  int i;

  i = message->options_len;

  SSH_ASSERT ((i + len + 4) < sizeof(message->options));

  SSH_PUT_16BIT(&message->options[i], (SshUInt16)option);
  SSH_PUT_16BIT(&message->options[i + 2], (SshUInt16)len);

  if (len > 0)
    {
      memcpy(&message->options[i + 4], data, len);
    }

  message->options_len += 4 + len;
}

