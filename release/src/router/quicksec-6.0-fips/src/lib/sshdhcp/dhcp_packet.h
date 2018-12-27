/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   dhcp_packet.h
*/

#ifndef DHCP_PACKET_H
#define DHCP_PACKET_H

/*
   DHCP Message packet.

   All DHCP packets are sent using the same packet. Only opcode and the
   fields change when sending different packets.

*/
struct SshDHCPMessageRec {
  unsigned char op;             /* 1 = BOOTREQUEST, 2 = BOOTREPLY */
  unsigned char htype;          /* HW address type */
  unsigned char hlen;           /* HW address length */
  unsigned char hops;           /* Used by GW/relays */
  SshUInt32 xid;                /* Transaction ID */
  SshUInt16 secs;               /* Seconds elapsed since client started */
  SshUInt16 flags;              /* Flags */
  SshUInt32 ciaddr;             /* Client's IP address */
  SshUInt32 yiaddr;             /* Assigned IP address (for client) */
  SshUInt32 siaddr;             /* Next server's IP */
  SshUInt32 giaddr;             /* Gateway/relay IP address */
  unsigned char chaddr[16];     /* Client's HW address */
  char sname[64];               /* Optional server host name */
  char file[128];               /* Boot file name */
  unsigned char options[1236];  /* Variable list of options.  We
                                   should be prepared to receive 312
                                   bytes of options but this is the
                                   maximum about of options that fit
                                   into one unfragmented ethernet UDP
                                   datagram. */

  /* Internal data. They are not part of packet and are used only
     internally by DHCP routines. */
  size_t options_len;           /* current options length */
  Boolean options_end;          /* Have we END mark at the end of options? */
};

typedef struct SshDHCPMessageRec SshDHCPMessageStruct;
typedef struct SshDHCPMessageRec *SshDHCPMessage;

/*
   DHCPv6 Message packet.
*/
struct SshDHCPv6MessageRec {
  unsigned int msg_type;        /* DHCPv6 message type */
  SshUInt32 xid;                /* Transaction ID */
  unsigned int hop_count;       /* Number of relay agents */
  SshIpAddrStruct link_address; /* Address identifying the link client is on */
  SshIpAddrStruct peer_address; /* Relay agent address */
  unsigned char options[1236];  /* Variable list of options.  We
                                   should be prepared to receive 312
                                   bytes of options but this is the
                                   maximum about of options that fit
                                   into one unfragmented ethernet UDP
                                   datagram. */

  /* Internal data. They are not part of packet and are used only
     internally by DHCP routines. */
  size_t options_len;           /* current options length */
};

typedef struct SshDHCPv6MessageRec SshDHCPv6MessageStruct;
typedef struct SshDHCPv6MessageRec *SshDHCPv6Message;

/* DHCP Packet manipulation (for client and relayer) */

/* Encodes the DHCP message indicated by `message' into the `buffer'
   of size of `buffer_size' bytes. Function returns number of bytes
   actually encoded, or zero on failure. */
size_t ssh_dhcp_message_encode(SshDHCPMessage message,
                               unsigned char *buffer, size_t buffer_size);

size_t ssh_dhcpv6_message_encode(SshDHCPv6Message message,
                                 unsigned char *buffer, size_t buffer_size);

size_t ssh_dhcpv6_relay_message_encode(SshDHCPv6Message message,
                                       unsigned char *buffer,
                                       size_t buffer_size);


/* Decodes the DHCP message indicated by `p' of size of `p_len' bytes
   into the `message' pointer.  Return FALSE if the message is
   malformed. */
Boolean ssh_dhcp_message_decode(SshDHCPMessage message,
                                unsigned char *p, size_t p_len);

Boolean ssh_dhcpv6_message_decode(SshDHCPv6Message message,
                                  unsigned char *p, size_t p_len);

Boolean ssh_dhcpv6_relay_message_decode(SshDHCPv6Message message,
                                        unsigned char *p,
                                        size_t p_len);
#endif
