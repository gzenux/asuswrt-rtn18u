/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SSH DHCP interface for DHCP client and DHCP Relayer.
*/

#ifndef DHCP_INTERNAL_H
#define DHCP_INTERNAL_H

#include "sshudp.h"
#include "sshdhcp.h"
#include "dhcp_options.h"
#include "dhcp_packet.h"
#include "sshfsm.h"

/* Types and definitions */

/* Define, if the message option set should be validated against the defined
   option set. */
/* #define SSH_DHCP_VALIDATE_OPTION_SET 1 */

/* Default broadcast address */
#define SSH_DHCP_BROADCAST "255.255.255.255"

/* Maximum length for DHCPv6 client ID */
#define SSH_DHCPV6_CLIENT_ID_MAX_LEN 122

/* DHCP message types */
#define SSH_DHCPDISCOVER        1
#define SSH_DHCPOFFER           2
#define SSH_DHCPREQUEST         3
#define SSH_DHCPDECLINE         4
#define SSH_DHCPACK             5
#define SSH_DHCPNAK             6
#define SSH_DHCPRELEASE         7
#define SSH_DHCPINFORM          8

/* DHCPv6 message types */
#define SSH_DHCPV6_SOLICIT             1
#define SSH_DHCPV6_ADVERTISE           2
#define SSH_DHCPV6_REQUEST             3
#define SSH_DHCPV6_CONFIRM             4
#define SSH_DHCPV6_RENEW               5
#define SSH_DHCPV6_REBIND              6
#define SSH_DHCPV6_REPLY               7
#define SSH_DHCPV6_RELEASE             8
#define SSH_DHCPV6_DECLINE             9
#define SSH_DHCPV6_RECONFIGURE         10
#define SSH_DHCPV6_INFORMATION_REQUEST 11
#define SSH_DHCPV6_RELAY_FORW          12
#define SSH_DHCPV6_RELAY_REPL          13

/* DHCP opcode */
#define SSH_DHCP_BOOTREQUEST    1
#define SSH_DHCP_BOOTREPLY      2

/* DUID types */
#define SSH_DUID_LLT    1
#define SSH_DUID_EN     2
#define SSH_DUID_LL     3
#define SSH_DUID_UUID   4

/* Packet flags */
#define SSH_DHCP_FLAG_BROADCAST    128

/* Interface identifiers (from Assigned Numbers RFC) */
#define DH_IFACE_NETROM   0     /* from KA9Q: NET/ROM pseudo    */
#define DH_IFACE_ETHER    1     /* Ethernet 10Mbps              */
#define DH_IFACE_EETHER   2     /* Experimental Ethernet        */
#define DH_IFACE_AX25     3     /* AX.25 Level 2                */
#define DH_IFACE_PRONET   4     /* PROnet token ring            */
#define DH_IFACE_CHAOS    5     /* Chaosnet                     */
#define DH_IFACE_IEEE802  6     /* IEEE 802.2 Ethernet/TR/TB    */
#define DH_IFACE_ARCNET   7     /* ARCnet                       */
#define DH_IFACE_APPLETLK 8     /* APPLEtalk                    */
#define DH_IFACE_DLCI     15    /* Frame Relay DLCI             */
#define DH_IFACE_METRICOM 23    /* Metricom STRIP (new IANA id) */
#define DH_IFACE_IPSEC    31    /* DHCP Over IPSEC virtual adapter type */
#define DH_IFACE_TBD      99    /* Backward compatibility for DHCPoIPSEC */

/* Default retransmit values */
#define SSH_DHCP_RETRANSMIT_COUNT          3
#define SSH_DHCP_RETRANSMIT_INTERVAL       4
#define SSH_DHCP_RETRANSMIT_INTERVAL_USEC  0
#define SSH_DHCP_OFFER_TIMEOUT             2
#define SSH_DHCP_OFFER_TIMEOUT_USEC        0
#define SSH_DHCP_TIMEOUT_RANDOMIZER        2         /* timeout += rnd % 2 */
#define SSH_DHCP_TIMEOUT_MULTIPLIER        2         /* timeout growth */
#define SSH_DHCP_TIMEOUT_MAX               30        /* max timeout */


/* DHCP Client session structure. This is internal structure and application
   must not directly access the fields in this structure. */
struct SshDHCPRec {
  /* Parameters */
  SshDHCPParamsStruct params;

  /* Current status of DHCP session */
  SshDHCPStatus status;

  /* Data returned by the server */
  SshDHCPInformation info;

  /* Unique session identifier */
  SshUInt32 xid;
  SshDHCP xid_hash_next;

  /* Flags */
  unsigned int got_offer  : 1;  /* Set when selected offer from server */
  unsigned int wait_offer : 1;  /* Set when waiting from preferred server */
  unsigned int got_ack    : 1;  /* Set when ACK received from server */
  unsigned int retransmit_count : 29; /* Current retransmit */

  SshUInt16 secs;               /* Time since session started */
  SshUInt16 discover_secs;      /* Seconds from our DHCPDISCOVER */
  SshDHCPMessageStruct offer;   /* First DHCPOFFER received from server */

  /* Last packet received from network ( decoded) */
  SshDHCPMessageStruct message;

  /* Last DHCPv6 packet received from network ( decoded) */
  SshDHCPv6MessageStruct dhcpv6_message;

  /* User callback and context */
  SshDHCPCallback callback;
  void *context;

  /* Backpointer to the DHCP FSM.*/
  SshFSM fsm;

  /* FSM thread running the current DHCP conversation. */
  SshFSMThread thread;

  /* Application callback invoked by the thread destructor. */
  SshDHCPCallback destructor_cb;

  /* Retransmit timeout. */
  SshTimeoutStruct timeout;

  /* Total DHCP conversation timeout. */
  SshTimeoutStruct total_timeout;
};

/* DHCP library main context for the FSM. */
typedef struct SshDHCPMainCtxRec
{
  SshUdpListener listener;
  SshUdpListener sender;

  /* Packet received from the network */
  unsigned char *p;
  size_t p_len;

  /* Listener IP address and port */
  unsigned char *local_ip;
  SshUInt16 local_listening_port;
  SshUInt16 local_private_port;

  /* Hash table for the DHCP negotiation threads, xid as a hash key. */
  SshDHCP thread_hash_table[DHCP_THREAD_HASH_TABLE_SIZE];

  /* Thread count for the DHCP FSM */
  SshUInt32 fsm_reference_count;

  /* Timeout for waiting the threads to finish before uninitializing FSM. */
  SshTimeoutStruct uninit_timeout;

  /* Statistics of sent and received DHCP messages. */
  SshDHCPStatsStruct stats;
} *SshDHCPMainCtx, SshDHCPMainCtxStruct;

/* This structure is used as a temporary storage while extracting data
   from an DHCPv6 packet. THe contents of the sturcture is checked for
   validity and the information needed is then moved to a
   SshDHCPInformationStruct for safekeeping. */
typedef struct SshDHCPv6ExtractRec
{
  unsigned char *clientid;      /* Client identification */
  size_t clientid_len;          /* Length of client id */
  unsigned char *server_duid;   /* Server DUID for server identification */
  size_t server_duid_len;       /* Server DUID length */
  SshUInt32 renew_timeout;
  SshUInt32 rebind_timeout;
  SshUInt32 lease_time;
  unsigned char *my_ip;         /* Assigned IP address */
  SshUInt16 status_code;        /* Returned status code */
  unsigned char *status_message;
  Boolean rapid_commit;
  Boolean parsing_successful;
  unsigned char **dns_ip;       /* Available domain name server(s) */
  size_t dns_ip_count;
} *SshDHCPv6Extract, SshDHCPv6ExtractStruct;

/* Prototypes */

/* Put new option to the DHCP options. The order of the option data in
   the options buffer will be {option code, option length, option data} as
   defined by the protocol. */
void ssh_dhcp_option_put(SshDHCPMessage message,
                         SshDHCPOption option, size_t len,
                         unsigned char *data);

void ssh_dhcpv6_option_put(SshDHCPv6Message message,
                           SshDHCPv6Option option, size_t len,
                           unsigned char *data);

/* Adds buffers `options' of length `options_len' to the message's
   options. The `options' must be already a encoded buffer containing
   the DHCP options and their parameters. The `options' must no include
   the SSH_DHCP_OPTION_END option. */
void ssh_dhcp_options_put(SshDHCPMessage message,
                          unsigned char *options, size_t options_len);

/* Returns TRUE and the option data if it exists. Same options that were
   encoded can be attempted to decode. Return FALSE if such option does not
   exist in the packet. If data exists it and its length are returned. Note,
   that `data' must have already memory allocated for the data. */
Boolean ssh_dhcp_option_get(SshDHCPMessage message,
                            SshDHCPOption option,
                            unsigned char *data, size_t data_len,
                            size_t *ret_len);

Boolean ssh_dhcpv6_option_get(SshDHCPv6Message message,
                              SshDHCPv6Option option,
                              unsigned char *data, size_t data_len,
                              size_t *ret_len);

Boolean ssh_dhcp_option_check(SshDHCPMessage message, SshDHCPOption option);

Boolean ssh_dhcpv6_option_check(SshDHCPv6Message message,
                                SshDHCPv6Option option);

/* Compares the received and configured option sets for message type 'type'*/
Boolean ssh_dhcp_compare_option_set(SshDHCP dhcp, SshDHCPMessage message,
                                    unsigned char type);

Boolean ssh_dhcpv6_compare_option_set(SshDHCP dhcp, SshDHCPv6Message message,
                                      unsigned char type);

/* Removes the specified option from the DHCP message. If it option does
   not exist this returns FALSE. */
Boolean ssh_dhcp_option_remove(SshDHCPMessage message, SshDHCPOption option);

/* Explicitly sets `message_type' as the packet's message type. If the type
   is already set, this will replace the old type. */
void ssh_dhcp_option_set_message_type(SshDHCPMessage message,
                                      unsigned char message_type);

void ssh_dhcpv6_option_set_message_type(SshDHCPv6Message message,
                                        unsigned char message_type);

/* Put the magic cookie. This must presede all options. */
void ssh_dhcp_option_put_cookie(SshDHCPMessage message);

/* Returns TRUE if cookie is correct */
Boolean ssh_dhcp_option_check_cookie(SshDHCPMessage message);

/* Returns most common options (or at least attempts to return all of them)
   from the DHCP message. */
SshDHCPOptionsDefault ssh_dhcp_option_default_get(SshDHCP dhcp,
                                                  SshDHCPMessage message);

SshDHCPOptionsDefault ssh_dhcp_get_dhcp_options(SshDHCP dhcp,
                                                  SshDHCPMessage message);

SshDHCPv6Extract ssh_dhcpv6_get_options(SshDHCPv6Message message);


/* Puts default options for DHCP client. These should be quite good for
   any normal usage of DHCP. */
void ssh_dhcp_option_default_set(SshDHCP dhcp, SshDHCPMessage message,
                                 SshDHCPInformation info,
                                 unsigned char *cid, size_t cid_len);

void ssh_dhcp_set_dhcp_options(SshDHCP dhcp, SshDHCPMessage message,
                               SshDHCPInformation info, unsigned char type);

void ssh_dhcpv6_set_dhcp_options(SshDHCP dhcp, SshDHCPv6Message message,
                                 SshDHCPInformation info, unsigned char type);

void ssh_dhcp_make_message(SshDHCP dhcp, SshDHCPMessage message,
                           SshDHCPInformation info);
void
ssh_dhcp_statistics_buffer_append(SshDHCPStats statistics,
                                  unsigned char *buf, unsigned int buf_len);

Boolean ssh_dhcpv6_populate_info(SshDHCP dhcp, SshDHCPv6Extract data);
void ssh_dhcpv6_free_extract_data(SshDHCPv6Extract data);


/* Statistics macros */
#define SSH_DHCP_UPDATE_STATS(a)  \
do                                \
  {                               \
    if (a < 0xffffffff)           \
      a++;                        \
    else                          \
      a = 1;                      \
  }                               \
 while (0)


/* DHCPv6 specific handling */
void ssh_dhcpv6_make_message(SshDHCP dhcp, SshDHCPv6Message message,
                             SshDHCPInformation info, unsigned char type);

#endif
