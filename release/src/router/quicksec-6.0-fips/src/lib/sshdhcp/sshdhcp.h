/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   DHCP interface for client and relayer.
*/

#ifndef SSHDHCP_H
#define SSHDHCP_H

#include "sshbuffer.h"
#include "sshfsm.h"

/* DHCP Client types and definitions */

/* Forward declarations */
typedef struct SshDHCPRec SshDHCPStruct;
typedef struct SshDHCPRec *SshDHCP;
typedef struct SshDHCPInformationRec *SshDHCPInformation;

/* DHCP session status types */
typedef enum {
  /* Normal status. Also status when DHCP session has finished and all data
     has been freed. */
  SSH_DHCP_STATUS_OK = 0,

  /* Normal status when IP address has been assigned to the client. The
     user callback is called but DHCP session is still active. DHCP session
     has re-new and re-bind timeouts that it will handle. User callback MUST
     NOT call ssh_dhcp_free when in this status. */
  SSH_DHCP_STATUS_BOUND,

  /* Session is in re-new state where client must re-issue the IP address from
     the server. User callback is called to notify this situation. Note that
     user callback is also called after the session is again in BOUND state. */
  SSH_DHCP_STATUS_RENEW,

  /* Session is in re-bind state where client must re-issue the IP address
     by re-starting the session. User callback is called to notify this
     situation. Note that user callback is also called after the session is
     again in BOUND state. */
  SSH_DHCP_STATUS_REBIND,

  /* We have received DHCPACK from server but we wanted it only to gather
     configuration information. This status is set in that case and user
     callback is called after receiving the data. Note that this does NOT
     receive IP address or any re-new or re-bind timeouts. */
  SSH_DHCP_STATUS_INFORM,

  /* Solicit message sent. Waiting for reply with rapid commit option. */
  SSH_DHCP_STATUS_SOLICIT,

  /* Decline message sent. Waiting for reply. */
  SSH_DHCP_STATUS_DECLINE,

  /* Release message sent. Waiting for reply. */
  SSH_DHCP_STATUS_RELEASE,

  /* All retransmits and timeouts has expired and no successful DHCP session
     completed. User callback is called and DHCP session is stopped. */
  SSH_DHCP_STATUS_TIMEOUT,

  /* External process aborted DHCP session. */
  SSH_DHCP_STATUS_ABORTED,

  /* No more memory available. */
  SSH_DHCP_STATUS_OUT_OF_MEMORY,

  /* Unknown error occurred, DHCP session is stopped. */
  SSH_DHCP_STATUS_ERROR
} SshDHCPStatus;

/* Server and Client UDP ports */
#define SSH_DHCP_SERVER_PORT 67
#define SSH_DHCP_CLIENT_PORT 68
#define SSH_DHCPV6_SERVER_PORT 547
#define SSH_DHCPV6_CLIENT_PORT 546

/* DHCP flags for DHCP client sessions */
#define SSH_DHCP_CLIENT_FLAG_NONE         0x0000
#define SSH_DHCP_CLIENT_FLAG_IPSEC        0x0001        /* DHCP over IPSEC */
#define SSH_DHCP_CLIENT_FLAG_DHCPV6       0x0002        /* DHCPv6 server */

/* DHCP protocol version */
#define SSH_DHCP_PROTOCOL_VERSION_UNDEFINED 0
#define SSH_DHCP_PROTOCOL_VERSION_4         1
#define SSH_DHCP_PROTOCOL_VERSION_6         2

#define SSH_DHCP_NUM_SUPPORTED_MESSAGES 8
#define SSH_DHCP_MAX_SUPPORTED_SERVERS 2

/* The hash table size for ongoing message exchange threads. Select the size
   relative to the expected number of simultaneous DHCP conversations. */
#define DHCP_THREAD_HASH_TABLE_SIZE 256

/* User callback that is called to indicate the current status of the
   DHCP session. This is called also when an error occurs. The `info'
   is the structure holding the data server has returned. The `status'
   indicates the current status of the session. */
typedef void (*SshDHCPCallback)(SshDHCP dhcp, const SshDHCPInformation info,
                                SshDHCPStatus status, void *context);


/* Using this structure the application can define sets of options that will
   be used or accepted for each type of DHCP messages. */
typedef struct SshDHCPOptionsRec
{
  const unsigned char *discover;
  const unsigned char *offer;
  const unsigned char *request;
  const unsigned char *decline;
  const unsigned char *ack;
  const unsigned char *nak;
  const unsigned char *release;
  const unsigned char *inform;
  const unsigned char *solicit;
  const unsigned char *reply;
  const unsigned char *renew;
} *SshDHCPOptions, SshDHCPOptionsStruct;

/* This structure is allocated if previous DHCP configuration data
   exists.  All fields that are available should be allocated before
   starting the DHCP session. The DHCP will attempt to request these
   parameters from the server.

   The DHCP session also returns this structure in the user callback
   that will contain the data server has returned to the client.  The
   client should save the data for future use or save at least data
   that has changed since previous DHCP sessions. Note that some of
   the fields may be NULL when server did not return all of the
   requested parameters. */

typedef struct SshDHCPInformationRec
{
  unsigned char *my_ip;         /* Assigned IP address */
  unsigned char *server_ip;     /* Server IP address (preferred DHCP server) */
  unsigned char *server_duid;   /* Server DUID for server identification */
  size_t server_duid_len;       /* Server DUID length */
  unsigned char *netmask;       /* Netmask */
  unsigned char **gateway_ip;   /* Gateway address(es) */
  size_t gateway_ip_count;
  unsigned char **dns_ip;       /* Available domain name server(s) */
  size_t dns_ip_count;
  unsigned char **wins_ip;      /* Available WINS (or NBNS) server(s) */
  size_t wins_ip_count;
  unsigned char *hostname;      /* Hostname for the assigned IP address */
  unsigned char *domain;        /* The domain name to be used */
  unsigned char *file;          /* Path to mount as root */
  unsigned char *nis;           /* NIS domain name (not DNS domain) */
  SshBuffer failure_reason;     /* Option 56 failure reason message. */


  /* Timeout (in seconds) when client must re-new and re-bind its IP
     address. */
  SshUInt32 renew_timeout;
  SshUInt32 rebind_timeout;

  /* Lease time given by the DHCP server. */
  SshUInt32 lease_time;

  /* List of requested parameters that application may set. These are normal
     DHCP options that are allocated into this buffer. They will be added
     as parameter request list to the packet.

     When this structure is returned in the user callback this buffer
     will hold the parameters server returned. The application may set
     parameters using the ssh_dhcp_option_put_params and retrieve them
     by using the ssh_dhcp_option_get_param functions. */
  SshBuffer params;

} SshDHCPInformationStruct;


/* DHCP client parameters structure. This structure is filled and sent
   as argument to the ssh_dhcp_allocate function. */
typedef struct SshDHCPParamsRec
{
  /* Listener IP address and port */
  unsigned char *local_ip;
  SshUInt16 local_listening_port;
  SshUInt16 local_private_port;
  unsigned char *remote_ip;

  /* Remote IP address and port. If remote host is not known this can
     be omitted. In that case the packet will be broadcasted to the
     255.255.255.255 broadacst address. */
  struct {
  unsigned char *remote_ip;
    SshUInt16 remote_port;
  } dhcp_servers[SSH_DHCP_MAX_SUPPORTED_SERVERS];

  /* Gateway. If set DHCP messages will be relayed through this server. */
  unsigned char *gateway;

  /* Session flags */
  SshUInt32 flags;

  /* Previous configuration data, if exists. This structure may be
     filled before starting the DHCP session to request specific
     parameters (such as some specific IP address) from the server. If
     this is provided at the configuration, the pointer is stolen by
     the DHCP library. */
  SshDHCPInformation info;

  /* The hardware address of the interface to use. In case there is no
     LAN interface FQDN may be used. */
  unsigned char *hw_addr;
  unsigned int hw_addr_len;
  unsigned int hw_addr_type;

  unsigned char *vendor_id;     /* Vendor ID option value */
  size_t vendor_id_len;

  /* Private enterprise number. Used for constructing the client DUID. */
  SshUInt32 enterprise_number;

  /* Unique client identifier. This should be for example FQDN. It is
     recommended that this field is always allocated with proper
     value.  Server uses this value to uniquely identify clients. If
     not provided server will use the HW address of the interface. */
  unsigned char *client_identifier;
  size_t client_identifier_len;
  int client_identifier_type;

  /* The maximum number of retransmits that DHCP session will perform
     in case of error or timeout. If zero, default value will be
     used. */
  unsigned int retransmit_count;

  /* The interval to perform the retransmit in case of error or
     timeout.  This is an "about value" and will be randomized
     according exponential backoff algorithm. This value will grow
     when retransmissions are being executed. If both zero, default
     values will be used. */
  SshUInt32 retransmit_interval;
  SshUInt32 retransmit_interval_usec;

  /* Maximum timeout that is allowed to be generated by the
     exponential backoff algorithm. The length of timeouts grows when
     retransmission count grows. If zero, default value will be
     used. The value is in seconds. */
  SshUInt32 max_timeout;

  /* Maximum total timeout before which the DHCP negotiation should be
     completed. This should not be longer than IKE retry timeout, to
     avoid outdated DHCPDISCOVERY resends. */
  SshUInt32 max_total_timeout;

  /* The application may request a lease time. The requested value is
     treated as an acceptable minimum. */
  SshUInt32 requested_lease_time;

  /* User can have preferred server it wants to send an offer. In case
     that server does not send the offer in this time period we'll use
     the offer we received first. If both zero, default values will be
     used. */
  SshUInt32 offer_timeout;
  SshUInt32 offer_timeout_usec;

  /* This can be set to TRUE if you do not want the DHCP library to
     perform backwards compatibility with old servers. If FALSE DHCP
     library will support old servers (implemented according RFC1541)
     and new servers (implemented according RFC2131). */
  Boolean no_compatibility;

  /* List of options to be added in the DHCP messages. Only the options
     listed in this field are put or accepted in the message. If none are
     given, a default set will be used. */
  SshDHCPOptions options;

  /* Flags for the application. These are not used by the DHCP library. */
  SshUInt32 context_flags;

} *SshDHCPParams, SshDHCPParamsStruct;


/* DHCP Client interface */
/* Initializes the FSM in the DHCP library. */
SshFSM ssh_dhcp_library_init(SshUInt8 version,
                             unsigned char *local_ip,
                             SshUInt16 local_private_port,
                             SshUInt16 local_listening_port);

/* Uninitializes the DHCP library FSM. */
void ssh_dhcp_library_uninit(void *context);

/* Allocates new DHCP context. The `params' may be provided to define
   parameters for the DHCP session. The `callback' will be called during
   the DHCP session when the status changes.  It is called in case of
   error as well. */
SshDHCP ssh_dhcp_allocate(SshFSM fsm,
                          SshDHCPParams params,
                          SshDHCPCallback callback,
                          SshDHCPCallback destructor_cb,
                          void *context);

/* Frees DHCP context. The application must call ssh_dhcp_abort before
   freeing the DHCP context (or the session must be in ERROR or TIMEOUT
   state). */
void ssh_dhcp_free(SshDHCP dhcp);

/* This function can be used to change the DHCP parameters on running
   DHCP session.  This could for example to change the listener to
   different interface or similar. */
SshDHCPStatus ssh_dhcp_change_params(SshDHCP dhcp, SshDHCPParams params);

/* The main DHCP runner. This function is called to start the DHCP session.
   The user callback will be called during the session when the status
   of the session changes. */
SshDHCPStatus ssh_dhcp_run(SshDHCP dhcp);

/* Requests only configuration parameters from the server. This does not
   run the actual DHCP session and ssh_dhcp_run must not be called when
   using this function. After receiving the configuration data from the
   server the user callback is called. The DHCP context may be freed
   after receiving the configuration data. */
SshDHCPStatus ssh_dhcp_request_configuration(SshDHCP dhcp);

/* Gracefully release the bound IP address. External process can call this
   to release the IP address. After that client must not use the IP address
   anymore. The `dhcp' is the current DHCP session in BOUND state. */
SshDHCPStatus ssh_dhcp_release(SshDHCP dhcp);

/* Decline to use the IP address server bound to us. External process can
   call this for example after detecting that the IP address server sent
   is already in use. This will cause restart of the DHCP session from the
   begin to receive a new IP address. Servers may return addresses that
   are in use. It is the client's responsibility to check whether the given
   address is already in use in the network. The `dhcp' is the current
   DHCP session in BOUND state. */
SshDHCPStatus ssh_dhcp_decline(SshDHCP dhcp);

/* Abort DHCP session. User callback will be called after abortion. The
   DHCP session must be aborted before it can be freed using the
   ssh_dhcp_free function. This function can be called in any state of
   the session. */
void ssh_dhcp_abort(SshDHCP dhcp);

/* DHCP options. All DHCP options that the client may request from the
   server and the server may reply to the client. The options are from
   the RFC2132 DHCP Options and BOOTP Vendor Extensions. */
typedef enum {
  SSH_DHCP_OPTION_PAD                              = 0,
  SSH_DHCP_OPTION_SUBNET_MASK                      = 1,
  SSH_DHCP_OPTION_TIME_OFFSET                      = 2,
  SSH_DHCP_OPTION_ROUTERS                          = 3,
  SSH_DHCP_OPTION_TIME_SERVERS                     = 4,
  SSH_DHCP_OPTION_NAME_SERVERS                     = 5,
  SSH_DHCP_OPTION_DOMAIN_NAME_SERVERS              = 6,
  SSH_DHCP_OPTION_LOG_SERVERS                      = 7,
  SSH_DHCP_OPTION_COOKIE_SERVERS                   = 8,
  SSH_DHCP_OPTION_LPR_SERVERS                      = 9,
  SSH_DHCP_OPTION_IMPRESS_SERVERS                  = 10,
  SSH_DHCP_OPTION_RESOURCE_LOCATION_SERVERS        = 11,
  SSH_DHCP_OPTION_HOST_NAME                        = 12,
  SSH_DHCP_OPTION_BOOT_SIZE                        = 13,
  SSH_DHCP_OPTION_MERIT_DUMP                       = 14,
  SSH_DHCP_OPTION_DOMAIN_NAME                      = 15,
  SSH_DHCP_OPTION_SWAP_SERVER                      = 16,
  SSH_DHCP_OPTION_ROOT_PATH                        = 17,
  SSH_DHCP_OPTION_EXTENSIONS_PATH                  = 18,
  SSH_DHCP_OPTION_IP_FORWARDING                    = 19,
  SSH_DHCP_OPTION_NON_LOCAL_SOURCE_ROUTING         = 20,
  SSH_DHCP_OPTION_POLICY_FILTER                    = 21,
  SSH_DHCP_OPTION_MAX_DGRAM_REASSEMBLY             = 22,
  SSH_DHCP_OPTION_DEFAULT_IP_TTL                   = 23,
  SSH_DHCP_OPTION_PATH_MTU_AGING_TIMEOUT           = 24,
  SSH_DHCP_OPTION_PATH_MTU_PLATEAU_TABLE           = 25,
  SSH_DHCP_OPTION_INTERFACE_MTU                    = 26,
  SSH_DHCP_OPTION_ALL_SUBNETS_LOCAL                = 27,
  SSH_DHCP_OPTION_BROADCAST_ADDRESS                = 28,
  SSH_DHCP_OPTION_PERFORM_MASK_DISCOVERY           = 29,
  SSH_DHCP_OPTION_MASK_SUPPLIER                    = 30,
  SSH_DHCP_OPTION_ROUTER_DISCOVERY                 = 31,
  SSH_DHCP_OPTION_ROUTER_SOLICITATION_ADDRESS      = 32,
  SSH_DHCP_OPTION_STATIC_ROUTES                    = 33,
  SSH_DHCP_OPTION_TRAILER_ENCAPSULATION            = 34,
  SSH_DHCP_OPTION_ARP_CACHE_TIMEOUT                = 35,
  SSH_DHCP_OPTION_IEEE802_3_ENCAPSULATION          = 36,
  SSH_DHCP_OPTION_DEFAULT_TCP_TTL                  = 37,
  SSH_DHCP_OPTION_TCP_KEEPALIVE_INTERVAL           = 38,
  SSH_DHCP_OPTION_TCP_KEEPALIVE_GARBAGE            = 39,
  SSH_DHCP_OPTION_NIS_DOMAIN                       = 40,
  SSH_DHCP_OPTION_NIS_SERVERS                      = 41,
  SSH_DHCP_OPTION_NTP_SERVERS                      = 42,
  SSH_DHCP_OPTION_VENDOR_ENCAPSULATED_OPTIONS      = 43,
  SSH_DHCP_OPTION_NETBIOS_NAME_SERVERS             = 44,
  SSH_DHCP_OPTION_NETBIOS_DD_SERVER                = 45,
  SSH_DHCP_OPTION_NETBIOS_NODE_TYPE                = 46,
  SSH_DHCP_OPTION_NETBIOS_SCOPE                    = 47,
  SSH_DHCP_OPTION_FONT_SERVERS                     = 48,
  SSH_DHCP_OPTION_X_DISPLAY_MANAGER                = 49,
  SSH_DHCP_OPTION_DHCP_REQUESTED_ADDRESS           = 50,
  SSH_DHCP_OPTION_DHCP_LEASE_TIME                  = 51,
  SSH_DHCP_OPTION_DHCP_OPTION_OVERLOAD             = 52,
  SSH_DHCP_OPTION_DHCP_MESSAGE_TYPE                = 53,
  SSH_DHCP_OPTION_DHCP_SERVER_IDENTIFIER           = 54,
  SSH_DHCP_OPTION_DHCP_PARAMETER_REQUEST_LIST      = 55,
  SSH_DHCP_OPTION_DHCP_MESSAGE                     = 56,
  SSH_DHCP_OPTION_DHCP_MAX_MESSAGE_SIZE            = 57,
  SSH_DHCP_OPTION_DHCP_RENEWAL_TIME                = 58,
  SSH_DHCP_OPTION_DHCP_REBINDING_TIME              = 59,
  SSH_DHCP_OPTION_DHCP_CLASS_IDENTIFIER            = 60,
  SSH_DHCP_OPTION_DHCP_CLIENT_IDENTIFIER           = 61,
  SSH_DHCP_OPTION_DHCP_USER_CLASS_ID               = 77,
  SSH_DHCP_OPTION_DHCP_RELAY_AGENT_INFORMATION     = 82, /* RFC 3046 */

  /* Rest currently undefined */
  SSH_DHCP_OPTION_END                              = 255
} SshDHCPOption;

/* DHCPv6 options. All DHCP options that the client may request from the
   server and the server may reply to the client. The options are from
   the RFC3315. */
typedef enum {
  SSH_DHCPV6_OPTION_CLIENTID                       = 1,
  SSH_DHCPV6_OPTION_SERVERID                       = 2,
  SSH_DHCPV6_OPTION_IA_NA                          = 3,
  SSH_DHCPV6_OPTION_IA_TA                          = 4,
  SSH_DHCPV6_OPTION_IAADDR                         = 5,
  SSH_DHCPV6_OPTION_ORO                            = 6,
  SSH_DHCPV6_OPTION_PREFERENCE                     = 7,
  SSH_DHCPV6_OPTION_ELAPSED_TIME                   = 8,
  SSH_DHCPV6_OPTION_RELAY_MSG                      = 9,
  SSH_DHCPV6_OPTION_AUTH                           = 11,
  SSH_DHCPV6_OPTION_UNICAST                        = 12,
  SSH_DHCPV6_OPTION_STATUS_CODE                    = 13,
  SSH_DHCPV6_OPTION_RAPID_COMMIT                   = 14,
  SSH_DHCPV6_OPTION_USER_CLASS                     = 15,
  SSH_DHCPV6_OPTION_VENDOR_CLASS                   = 16,
  SSH_DHCPV6_OPTION_VENDOR_OPTS                    = 17,
  SSH_DHCPV6_OPTION_INTERFACE_ID                   = 18,
  SSH_DHCPV6_OPTION_RECONF_MSG                     = 19,
  SSH_DHCPV6_OPTION_RECONF_ACCEPT                  = 20,
  SSH_DHCPV6_OPTION_SIP_SERVER_D                   = 21,
  SSH_DHCPV6_OPTION_SIP_SERVER_A                   = 22,
  SSH_DHCPV6_OPTION_DNS_SERVERS                    = 23,
  SSH_DHCPV6_OPTION_DOMAIN_LIST                    = 24,
  SSH_DHCPV6_OPTION_END                            = 255
} SshDHCPv6Option;

/* DHCPv6 status codes. DHCPv6 reply messages may include a status code
   to indicate the status of the operation. If status code is allowed
   but not included, the status is assumed to be succcess. The status
   codes are from the RFC3315. */
typedef enum {
  SSH_DHCPV6_STATUS_CODE_SUCCESS                   = 0,
  SSH_DHCPV6_STATUS_CODE_UNSPECFAIL                = 1,
  SSH_DHCPV6_STATUS_CODE_NOADDRSAVAIL              = 2,
  SSH_DHCPV6_STATUS_CODE_NOBINDING                 = 3,
  SSH_DHCPV6_STATUS_CODE_NOTONLINK                 = 4,
  SSH_DHCPV6_STATUS_CODE_USEMULTICAST              = 5,
  SSH_DHCPV6_STATUS_CODE_UNAVAILABLE               = 255
} SshDHCPv6StatusCode;

/* Add variable amount of parameters to be requested from the DHCP server.
   The caller may request various session parameters from the server by
   setting the preferred options using this function. The options will
   be added as parameters request list into the DHCP packet. The variable
   arguments are SshDHCPOption and is terminated by SSH_DHCP_OPTION_END.
   These options will be added as parameter request list into the DHCP
   packet. This function is called before running the DHCP session. If
   this is not called then the library use some default options that
   suites for normal DHCP sessions. This fuction returns TRUE if the
   addition was successful and FALSE otherwise. */
Boolean ssh_dhcp_option_put_params(SshDHCPInformation info, ...);

/* Get the requested parameter. This function may be used to get the
   requested parameters that has been received from the server. Note that
   the server may not return the paramters that was requested using
   ssh_dhcp_option_put_params. This function returns TRUE and the data
   associated to the parameter if it was returned by the server and FALSE
   otherwise. Note that `data' must have already memory allocated for the
   data. The `option' is the option that is being searched from the
   returned parameters. */
SshDHCPStatus ssh_dhcp_option_get_param(SshDHCPInformation info,
                                        SshDHCPOption option,
                                        size_t *ret_len, unsigned char *data,
                                        size_t data_len);

/* Duplicates the data found in `info' and returns new allocated info
   structure. This function can be used by application to copy the
   information structure if it needs to do so. */
SshDHCPInformation ssh_dhcp_dup_info(const SshDHCPInformation info);

/* This function can be used to free the duplicated info structure. */
void ssh_dhcp_free_info(SshDHCPInformation info);

/* DHCP statistics structure. */
typedef struct SshDHCPStatsRec
{
  SshUInt32 packets_transmitted;
  SshUInt32 packets_received;
  SshUInt32 packets_dropped;
  SshUInt32 discover;
  SshUInt32 offer;
  SshUInt32 request;
  SshUInt32 ack;
  SshUInt32 nak;
  SshUInt32 decline;
  SshUInt32 release;
  SshUInt32 dhcpv6_relay_forward;
  SshUInt32 dhcpv6_relay_reply;
  SshUInt32 dhcpv6_solicit;
  SshUInt32 dhcpv6_reply;
  SshUInt32 dhcpv6_decline;
  SshUInt32 dhcpv6_renew;
  SshUInt32 dhcpv6_release;
} *SshDHCPStats, SshDHCPStatsStruct;

/* Function for retrieving statistics information. */
SshDHCPStats ssh_dhcp_get_statistics(SshFSM fsm);

#endif /* SSHDHCP_H */
