/**
   @copyright
   Copyright (c) 2013 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshtcp.h"

#include "dhcp_internal.h"
#include "dhcp_packet.h"

#define SSH_DEBUG_MODULE "SshDHCPv6Packet"

/* Create the DHCPv6 relay forward header and actual content inside the
   relay forward packet. */
size_t
ssh_dhcpv6_relay_message_encode(SshDHCPv6Message message,
                                unsigned char *buffer,
                                size_t buffer_size)
{
  size_t len, encoded_len;
  size_t a_size = SSH_IP_ADDR_SIZE;
  unsigned char peer[SSH_IP_ADDR_SIZE], link[SSH_IP_ADDR_SIZE];
  unsigned int relay_type = SSH_DHCPV6_RELAY_FORW;
  SshUInt16 packet_len;
  SshUInt16 relay_msg_type = SSH_DHCPV6_OPTION_RELAY_MSG;

  /* DHCPv6 packet msg_type (1), xid (3), options */
  packet_len = 1 + 3 + message->options_len;

  SSH_IP6_ENCODE(&message->link_address, link);
  SSH_IP6_ENCODE(&message->peer_address, peer);

  /* Add relay header */
  len = ssh_encode_array(buffer, buffer_size,
                         SSH_FORMAT_CHAR, relay_type,
                         SSH_FORMAT_CHAR, message->hop_count,
                         SSH_FORMAT_DATA, link, a_size,
                         SSH_FORMAT_DATA, peer, a_size,
                         SSH_FORMAT_UINT16, relay_msg_type,
                         SSH_FORMAT_UINT16, packet_len,
                         SSH_FORMAT_END);

  if (len)
    {
      /* Add the actual message in the buffer as an option */
      SSH_DEBUG_HEXDUMP(SSH_D_MY, ("Relay header"), buffer, len);
      encoded_len = ssh_dhcpv6_message_encode(message,
                                              buffer + len,
                                              buffer_size - len);

      /* Something went wrong */
      if (encoded_len != packet_len)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Instead of expected packet len %d we got %d",
                                packet_len, encoded_len));
          /* Broken packet, don't try to send */
          len = 0;
        }
      else
        {
          len += encoded_len;
          SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("Relay packet"), buffer, len);
        }
    }

  return len;
}

/* Create the DHCPv6 message. */
size_t
ssh_dhcpv6_message_encode(SshDHCPv6Message message, unsigned char *buffer,
                          size_t buffer_size)
{
  size_t len, xid_len;
  unsigned char xid[4];

  SSH_PUT_32BIT(xid, message->xid);
  SSH_DEBUG(SSH_D_MY, ("encode XID: %d", message->xid));

  xid_len = 3;

  /* Make the message */
  len = ssh_encode_array(buffer, buffer_size,
                         SSH_FORMAT_CHAR, message->msg_type,
                         SSH_FORMAT_DATA, &xid[1], xid_len,
                         SSH_FORMAT_DATA, message->options,
                         message->options_len,
                         SSH_FORMAT_END);

  SSH_DEBUG_HEXDUMP(SSH_D_DATADUMP, ("DHCPv6 packet"), buffer, len);

  return len;
}

/* Decode the relay reply header and the relay message. */
Boolean
ssh_dhcpv6_relay_message_decode(SshDHCPv6Message message, unsigned char *p,
                                size_t p_len)

{
  size_t off;
  unsigned int msg_type, hop_count;
  unsigned char peer_address[SSH_IP_ADDR_SIZE];
  unsigned char link_address[SSH_IP_ADDR_SIZE];
  SshUInt16 opt_len, o_type, o_len;
  unsigned char *op;
  unsigned char *end;
  Boolean retval = FALSE;

  size_t a_size = SSH_IP_ADDR_SIZE;
  opt_len = o_type = o_len = 0;

  /* Decode Relay Agent Message header */
  off = ssh_decode_array(p, p_len,
                         SSH_FORMAT_CHAR, &msg_type,
                         SSH_FORMAT_CHAR, &hop_count,
                         SSH_FORMAT_DATA, &link_address, a_size,
                         SSH_FORMAT_DATA, &peer_address, a_size,
                         SSH_FORMAT_END);

  /* Relay header length should be 34 (type 1, hop count 1, address 16) */
  if (off != 34 || msg_type != SSH_DHCPV6_RELAY_REPL)
    {
      return FALSE;
    }

  SSH_IP_DECODE(&message->peer_address, peer_address, SSH_IP_ADDR_SIZE);
  SSH_IP_DECODE(&message->link_address, link_address, SSH_IP_ADDR_SIZE);
  message->hop_count = hop_count;

  /* Go throught Relay Agent Message options to find relayed message */
  op = p + off;
  end = p + p_len;
  while (op + 4 <= end && retval == FALSE)
    {
      o_type = SSH_GET_16BIT(op);
      o_len = SSH_GET_16BIT(op + 2);
      op += 4;

      if (o_type == SSH_DHCPV6_OPTION_RELAY_MSG)
        {
          opt_len = o_len;
          retval = TRUE;
          break;
        }

      op += o_len;
    }

  /* Decode the relayed message if one is found */
  if(retval)
    {
      retval = ssh_dhcpv6_message_decode(message, op, opt_len);
    }

  return retval;
}

/* Decode the DHCPv6 message. */
Boolean
ssh_dhcpv6_message_decode(SshDHCPv6Message message, unsigned char *p,
                          size_t p_len)
{
  size_t off, xid_len;
  unsigned int msg_type;
  unsigned char xid[5];

  SSH_DEBUG(SSH_D_LOWOK, ("ssh_dhcpv6_message_decode"));
  SSH_ASSERT (p != NULL && p_len != 0 && message != NULL);

  xid[0] = 0;
  xid_len = 3;

  off = ssh_decode_array(p, p_len,
                         SSH_FORMAT_CHAR, &msg_type,
                         SSH_FORMAT_DATA, &xid[1], xid_len,
                         SSH_FORMAT_END);

  if (off != 4)
    {
      return FALSE;
    }

  message->msg_type = msg_type;
  message->options_len = p_len - off;
  message->xid = SSH_GET_32BIT(xid);
  SSH_DEBUG(SSH_D_MY, ("decode XID: %d", message->xid));

  if (message->options_len > sizeof(message->options))
    message->options_len = sizeof(message->options);

  if (message->options_len > 0)
    {
      memcpy(message->options, p + off, message->options_len);
    }

  return TRUE;
}

