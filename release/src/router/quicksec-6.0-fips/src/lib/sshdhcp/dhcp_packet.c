/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshtcp.h"

#include "sshdhcp.h"
#include "dhcp_packet.h"

#define SSH_DEBUG_MODULE "SshDHCPPacket"

size_t
ssh_dhcp_message_encode(SshDHCPMessage message, unsigned char *buffer,
                        size_t buffer_size)
{
  unsigned char secs[2], flags[2];
  size_t len;
  unsigned int tmp_op, tmp_htype, tmp_hlen, tmp_hops;

  SSH_PUT_16BIT(secs, message->secs);
  SSH_PUT_16BIT(flags, message->flags);

  tmp_op = message->op;
  tmp_htype = message->htype;
  tmp_hlen = message->hlen;
  tmp_hops = message->hops;

  len = ssh_encode_array(buffer, buffer_size,
                         SSH_ENCODE_CHAR(tmp_op),
                         SSH_ENCODE_CHAR(tmp_htype),
                         SSH_ENCODE_CHAR(tmp_hlen),
                         SSH_ENCODE_CHAR(tmp_hops),
                         SSH_ENCODE_UINT32(message->xid),
                         SSH_ENCODE_DATA(secs, 2),
                         SSH_ENCODE_DATA(flags, 2),
                         SSH_ENCODE_UINT32(message->ciaddr),
                         SSH_ENCODE_UINT32(message->yiaddr),
                         SSH_ENCODE_UINT32(message->siaddr),
                         SSH_ENCODE_UINT32(message->giaddr),
                         SSH_ENCODE_DATA(message->chaddr, 16),
                         SSH_ENCODE_DATA(message->sname, 64),
                         SSH_ENCODE_DATA(message->file, 128),
                         SSH_ENCODE_DATA(message->options,
                                         message->options_len),
                         SSH_FORMAT_END);
  if (len)
    SSH_DEBUG_HEXDUMP(5, ("packet"), buffer, len);
  return len;
}

Boolean
ssh_dhcp_message_decode(SshDHCPMessage message, unsigned char *p, size_t p_len)
{
  unsigned char secs[2], flags[2];
  size_t off;
  unsigned int tmp_op, tmp_htype, tmp_hlen, tmp_hops;

  SSH_DEBUG(9, ("ssh_dhcp_message_decode"));
  if (p == NULL || p_len == 0 || message == NULL)
    return FALSE;

  off = ssh_decode_array(p, p_len,
                         SSH_DECODE_CHAR(&tmp_op),
                         SSH_DECODE_CHAR(&tmp_htype),
                         SSH_DECODE_CHAR(&tmp_hlen),
                         SSH_DECODE_CHAR(&tmp_hops),
                         SSH_DECODE_UINT32(&message->xid),
                         SSH_DECODE_DATA(secs, 2),
                         SSH_DECODE_DATA(flags, 2),
                         SSH_DECODE_UINT32(&message->ciaddr),
                         SSH_DECODE_UINT32(&message->yiaddr),
                         SSH_DECODE_UINT32(&message->siaddr),
                         SSH_DECODE_UINT32(&message->giaddr),
                         SSH_DECODE_DATA(message->chaddr,
                                         sizeof(message->chaddr)),
                         SSH_DECODE_DATA(message->sname,
                                         sizeof(message->sname)),
                         SSH_DECODE_DATA(message->file,
                                         sizeof(message->file)),
                         SSH_FORMAT_END);
  if (off == 0)
    return FALSE;

  message->op = (SshUInt8) tmp_op;
  message->htype = (SshUInt8) tmp_htype;
  message->hlen = (SshUInt8) tmp_hlen;
  message->hops = (SshUInt8) tmp_hops;

  message->options_len = p_len - off;
  if (message->options_len > sizeof(message->options))
    message->options_len = sizeof(message->options);

  if (message->options_len)
    {
      unsigned char *cp;

      memcpy(message->options, p + off, message->options_len);
      cp = &message->options[message->options_len - 1];

      /* Ignore NULL's at the end of options */
      while (*cp != SSH_DHCP_OPTION_END && cp > message->options)
        {
          cp -= 1;
          message->options_len--;
        }
      if (*cp == SSH_DHCP_OPTION_END)
        message->options_end = TRUE;
    }

  message->secs = SSH_GET_16BIT(secs);
  message->flags = SSH_GET_16BIT(flags);
  return TRUE;
}
