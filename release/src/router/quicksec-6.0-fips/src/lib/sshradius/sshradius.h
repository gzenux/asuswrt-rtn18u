/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Remote Authentication Dial In User Service (RADIUS) client library.

   This library implements the RADIUS protocol client operations as
   described by the RFC 2865 and the RFC 2866 documents. The RADIUS
   and configuration information between Network Access Server (NAS)
   and a shared Authentication Server.

   The RADIUS accounting protocol extends the RADIUS protocol to cover
   delivery of accounting information from the Network Access Server
   to a RADIUS accounting server.

   References:

     - RFC 2548   Microsoft Vendor-specific RADIUS Attributes
     - RFC 2865   Remote Authentication Dial In User Service (RADIUS)
     - RFC 2866   RADIUS Accounting
     - RFC 2867   RADIUS Accounting Modifications for Tunnel Protocol Support
     - RFC 2868   RADIUS Attributes for Tunnel Protocol Support
     - RFC 2869   RADIUS Extensions
     - RFC 3162   RADIUS and IPv6.
*/

#ifndef SSHRADIUS_H
#define SSHRADIUS_H

#include "sshoperation.h"
#include "sshenum.h"

/*--------------------------------------------------------------------*/
/* Types and definitions */
/*--------------------------------------------------------------------*/

/** A RADIUS client object handle. */
typedef struct SshRadiusClientRec *SshRadiusClient;

/** A RADIUS client request object handle. */
typedef struct SshRadiusClientRequestRec *SshRadiusClientRequest;

/** RADIUS operation codes. */
typedef enum
{
  /** RADIUS access request. */
  SSH_RADIUS_ACCESS_REQUEST             = 1,
  /** RADIUS access acceptance. */
  SSH_RADIUS_ACCESS_ACCEPT              = 2,
  /** RADIUS access rejection. */
  SSH_RADIUS_ACCESS_REJECT              = 3,
  /** RADIUS accounting request - see RFC 2866. */
  SSH_RADIUS_ACCOUNTING_REQUEST         = 4,
  /** RADIUS accounting response - see RFC 2866. */
  SSH_RADIUS_ACCOUNTING_RESPONSE        = 5,
  /** RADIUS access challenge. */
  SSH_RADIUS_ACCESS_CHALLENGE           = 11,
  /** RADIUS status server - experimental feature. */
  SSH_RADIUS_STATUS_SERVER              = 12,
  /** RADIUS status client - experimental feature. */
  SSH_RADIUS_STATUS_CLIENT              = 13
} SshRadiusOperationCode;

/** RADIUS attribute types. */
typedef enum
{
  /* Attribute types from the RFC 2865 document. */
  /** user name (see RFC 2865). */
  SSH_RADIUS_AVP_USER_NAME                      = 1,
  /** user password (see RFC 2865). */
  SSH_RADIUS_AVP_USER_PASSWORD                  = 2,
  /** CHAP password (see RFC 2865). */
  SSH_RADIUS_AVP_CHAP_PASSWORD                  = 3,
  /** Network Address Server IP address (see RFC 2865). */
  SSH_RADIUS_AVP_NAS_IP_ADDRESS                 = 4,
  /** Network Address Server port number (see RFC 2865). */
  SSH_RADIUS_AVP_NAS_PORT                       = 5,
  /** Service type (see RFC 2865). */
  SSH_RADIUS_AVP_SERVICE_TYPE                   = 6,
  /** Framed protocol (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_PROTOCOL                = 7,
  /** Framed IP address (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_IP_ADDRESS              = 8,
  /** Framed IP netmask (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_IP_NETMASK              = 9,
  /** Framed routing (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_ROUTING                 = 10,
  /** Filter ID (see RFC 2865). */
  SSH_RADIUS_AVP_FILTER_ID                      = 11,
  /** Framed Maximum Transmission Unit (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_MTU                     = 12,
  /** Framed compression (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_COMPRESSION             = 13,
  /** Login IP host (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_IP_HOST                  = 14,
  /** Login service (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_SERVICE                  = 15,
  /** Login TCP port (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_TCP_PORT                 = 16,
  /** Reply message (see RFC 2865). */
  SSH_RADIUS_AVP_REPLY_MESSAGE                  = 18,
  /** Callback number (see RFC 2865). */
  SSH_RADIUS_AVP_CALLBACK_NUMBER                = 19,
  /** Callback IP address (see RFC 2865). */
  SSH_RADIUS_AVP_CALLBACK_ID                    = 20,
  /** Framed route (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_ROUTE                   = 22,
  /** Framed IPX network (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_IPX_NETWORK             = 23,
  /** State (see RFC 2865). */
  SSH_RADIUS_AVP_STATE                          = 24,
  /** Class (see RFC 2865). */
  SSH_RADIUS_AVP_CLASS                          = 25,
  /** Vendor-specific attribute (see RFC 2865). */
  SSH_RADIUS_AVP_VENDOR_SPECIFIC                = 26,
  /** Session timeout (see RFC 2865). */
  SSH_RADIUS_AVP_SESSION_TIMEOUT                = 27,
  /** Idle timeout (see RFC 2865). */
  SSH_RADIUS_AVP_IDLE_TIMEOUT                   = 28,
  /** Termination action (see RFC 2865). */
  SSH_RADIUS_AVP_TERMINATION_ACTION             = 29,
  /** Called station ID (see RFC 2865). */
  SSH_RADIUS_AVP_CALLED_STATION_ID              = 30,
  /** Calling station ID (see RFC 2865). */
  SSH_RADIUS_AVP_CALLING_STATION_ID             = 31,
  /** Network Access Server identifier (see RFC 2865). */
  SSH_RADIUS_AVP_NAS_IDENTIFIER                 = 32,
  /** Proxy state (see RFC 2865). */
  SSH_RADIUS_AVP_PROXY_STATE                    = 33,
  /** Login LAT service (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_LAT_SERVICE              = 34,
  /** Login LAT node (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_LAT_NODE                 = 35,
  /** Login LAT group (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_LAT_GROUP                = 36,
  /** Framed Appletalk link (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_APPLETALK_LINK          = 37,
  /** Framed Appletalk network (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_APPLETALK_NETWORK       = 38,
  /** Framed Appletalk zone (see RFC 2865). */
  SSH_RADIUS_AVP_FRAMED_APPLETALK_ZONE          = 39,
  /** CHAP challenge (see RFC 2865). */
  SSH_RADIUS_AVP_CHAP_CHALLENGE                 = 60,
  /** NAS port type (see RFC 2865). */
  SSH_RADIUS_AVP_NAS_PORT_TYPE                  = 61,
  /** Port limit (see RFC 2865). */
  SSH_RADIUS_AVP_PORT_LIMIT                     = 62,
  /** Login LAT port (see RFC 2865). */
  SSH_RADIUS_AVP_LOGIN_LAT_PORT                 = 63,

  /* Attribute types from the RFC 2866 document. */
  /** RADIUS accounting status type (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_STATUS_TYPE               = 40,
  /** RADIUS accounting delay time (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_DELAY_TIME                = 41,
  /** RADIUS accounting input octets (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_INPUT_OCTETS              = 42,
  /** RADIUS accounting output octets (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_OUTPUT_OCTETS             = 43,
  /** RADIUS accounting session ID (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_SESSION_ID                = 44,
  /** RADIUS accounting authentic (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_AUTHENTIC                 = 45,
  /** RADIUS accounting session time (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_SESSION_TIME              = 46,
  /** RADIUS accounting input packets (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_INPUT_PACKETS             = 47,
  /** RADIUS accounting output packets (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_OUTPUT_PACKETS            = 48,
  /** RADIUS accounting terminate cause (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_TERMINATE_CAUSE           = 49,
  /** RADIUS accounting multisession ID (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_MULTI_SESSION_ID          = 50,
  /** RADIUS accounting link count (see RFC 2866). */
  SSH_RADIUS_AVP_ACCT_LINK_COUNT                = 51,

  /* Attribute types from the RFC 2867 document.  */
  /** RADIUS accounting tunnel connection (see RFC 2867). */
  SSH_RADIUS_AVP_ACCT_TUNNEL_CONNECTION         = 68,
  /** RADIUS accounting tunnel packets lost (see RFC 2867). */
  SSH_RADIUS_AVP_ACCT_TUNNEL_PACKETS_LOST       = 86,

  /* Attribute types from the RFC 2868 document. */
  /** Tunnel type (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_TYPE                    = 64,
  /** Tunnel medium type (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_MEDIUM_TYPE             = 65,
  /** Tunnel client endpoint (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_CLIENT_ENDPOINT         = 66,
  /** Tunnel server endpoint (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_SERVER_ENDPOINT         = 67,
  /** Tunnel password (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_PASSWORD                = 69,
  /** Tunnel private group ID (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_PRIVATE_GROUP_ID        = 81,
  /** Tunnel assignment (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_ASSIGNMENT_ID           = 82,
  /** Tunnel preference (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_PREFERENCE              = 83,
  /** Tunnel client authorization ID (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_CLIENT_AUTH_ID          = 90,
  /** Tunnel server authorization ID (see RFC 2868). */
  SSH_RADIUS_AVP_TUNNEL_SERVER_AUTH_ID          = 91,

  /* Attribute types from the RFC 2869 document. */
  /** Acct input gigawords (see RFC 2869). */
  SSH_RADIUS_AVP_ACCT_INPUT_GIGAWORDS           = 52,
  /** Acct output gigawords (see RFC 2869). */
  SSH_RADIUS_AVP_ACCT_OUTPUT_GIGAWORDS          = 53,
  /** Event timestamp (see RFC 2869). */
  SSH_RADIUS_AVP_EVENT_TIMESTAMP                = 55,
  /** Apple Remote Access Protocol password (see RFC 2869). */
  SSH_RADIUS_AVP_ARAP_PASSWORD                  = 70,
  /** Apple Remote Access Protocol features (see RFC 2869). */
  SSH_RADIUS_AVP_ARAP_FEATURES                  = 71,
  /** Apple Remote Access Protocol zone access (see RFC 2869). */
  SSH_RADIUS_AVP_ARAP_ZONE_ACCESS               = 72,
  /** Apple Remote Access Protocol security (see RFC 2869). */
  SSH_RADIUS_AVP_ARAP_SECURITY                  = 73,
  /** Apple Remote Access Protocol security data (see RFC 2869). */
  SSH_RADIUS_AVP_ARAP_SECURITY_DATA             = 74,
  /** Password retry (see RFC 2869). */
  SSH_RADIUS_AVP_PASSWORD_RETRY                 = 75,
  /** Prompt (see RFC 2869). */
  SSH_RADIUS_AVP_PROMPT                         = 76,
  /** Connect info (see RFC 2869). */
  SSH_RADIUS_AVP_CONNECT_INFO                   = 77,
  /** Configuration token (see RFC 2869). */
  SSH_RADIUS_AVP_CONFIGURATION_TOKEN            = 78,
  /** EAP message (see RFC 2869). */
  SSH_RADIUS_AVP_EAP_MESSAGE                    = 79,
  /** Message authenticator (see RFC 2869). */
  SSH_RADIUS_AVP_MESSAGE_AUTHENTICATOR          = 80,
  /** Apple Remote Access Protocol challenge response (see RFC 2869). */
  SSH_RADIUS_AVP_ARAP_CHALLENGE_RESPONSE        = 84,
  /** Acct interim interval (see RFC 2869). */
  SSH_RADIUS_AVP_ACCT_INTERIM_INTERVAL          = 85,
  /** Network Access Server port ID (see RFC 2869). */
  SSH_RADIUS_AVP_NAS_PORT_ID                    = 87,
  /** Framed pool (see RFC 2869). */
  SSH_RADIUS_AVP_FRAMED_POOL                    = 88,

  /* Attribute types from the RFC 3162 document. */
  /** Network Access Server IPv6 address (see RFC 3162). */
  SSH_RADIUS_AVP_NAS_IPV6_ADDRESS               = 95,
  /** Framed interface ID (see RFC 3162). */
  SSH_RADIUS_AVP_FRAMED_INTERFACE_ID            = 96,
  /** Framed IPv6 prefix (see RFC 3162). */
  SSH_RADIUS_AVP_FRAMED_IPV6_PREFIX             = 97,
  /** Login IPv6 host (see RFC 3162). */
  SSH_RADIUS_AVP_LOGIN_IPV6_HOST                = 98,
  /** Framed IPv6 route (see RFC 3162). */
  SSH_RADIUS_AVP_FRAMED_IPV6_ROUTE              = 99,
  /** Framed IPv6 pool (see RFC 3162). */
  SSH_RADIUS_AVP_FRAMED_IPV6_POOL               = 100,

  /* Non-RFC attribute types, defined by IANA/RADIUS. */
  /** Originating line info, defined by IANA/RADIUS
      (see Nenad Trifunovic, (Nenad.Trifunovic@mci.com), October 1998). */
  SSH_RADIUS_AVP_ORIGINATING_LINE_INFO          = 94,

  /* Attributes types from the RFC 2865 document. */
  /** Experimental start (see RFC 2865). */
  SSH_RADIUS_AVP_EXPERIMENTAL_START             = 192,
  /** Implementation-specific start (see RFC 2865). */
  SSH_RADIUS_AVP_IMPLEMENTATION_SPECIFIC_START  = 224,
  /** Reserved start (see RFC 2865). */
  SSH_RADIUS_AVP_RESERVED_START                 = 241
} SshRadiusAvpType;

/** Values for Vendor-Type field of Vendor-Specific AVP. */
typedef enum
{
  SSH_RADIUS_VENDOR_ID_NONE                    = 0,
  SSH_RADIUS_VENDOR_ID_MS                      = 311
} SshRadiusVendorId;

/** Microsoft Vendor-Specific RADIUS types (RFC 2548). */
typedef enum
{
  SSH_RADIUS_VENDOR_MS_CHAP_RESPONSE            = 1,
  SSH_RADIUS_VENDOR_MS_CHAP_ERROR               = 2,
  SSH_RADIUS_VENDOR_MS_CHAP_PW_1                = 3,
  SSH_RADIUS_VENDOR_MS_CHAP_PW_2                = 4,
  SSH_RADIUS_VENDOR_MS_CHAP_LM_ENC_PW           = 5,
  SSH_RADIUS_VENDOR_MS_CHAP_NT_ENC_PW           = 6,
  SSH_RADIUS_VENDOR_MS_MPPE_ENCRYPTION_POLICY   = 7,
  SSH_RADIUS_VENDOR_MS_MPPE_ENCRYPTION_TYPES    = 8,
  SSH_RADIUS_VENDOR_MS_RAS_VENDOR               = 9,
  SSH_RADIUS_VENDOR_MS_CHAP_DOMAIN              = 10,
  SSH_RADIUS_VENDOR_MS_CHAP_CHALLENGE           = 11,
  SSH_RADIUS_VENDOR_MS_MPPE_KEYS                = 12,
  SSH_RADIUS_VENDOR_MS_BAP_USAGE                = 13,
  SSH_RADIUS_VENDOR_MS_LINK_UTILIZATION_THRESHOLD = 14,
  SSH_RADIUS_VENDOR_MS_LINK_DROP_TIME_LIMIT     = 15,
  SSH_RADIUS_VENDOR_MS_MPPE_SEND_KEY            = 16,
  SSH_RADIUS_VENDOR_MS_MPPE_RECV_KEY            = 17,
  SSH_RADIUS_VENDOR_MS_RAS_VERSION              = 18,
  SSH_RADIUS_VENDOR_MS_OLD_ARAP_PASSWORD        = 19,
  SSH_RADIUS_VENDOR_MS_NEW_ARAP_PASSWORD        = 20,
  SSH_RADIUS_VENDOR_MS_ARAP_PASSWORD_CHANGE_REASON = 21,
  SSH_RADIUS_VENDOR_MS_FILTER                   = 22,
  SSH_RADIUS_VENDOR_MS_ACCT_AUTH_TYPE           = 23,
  SSH_RADIUS_VENDOR_MS_ACCT_EAP_TYPE            = 24,
  SSH_RADIUS_VENDOR_MS_CHAP2_RESPONSE           = 25,
  SSH_RADIUS_VENDOR_MS_CHAP2_SUCCESS            = 26,
  SSH_RADIUS_VENDOR_MS_CHAP2_CPW                = 27,
  SSH_RADIUS_VENDOR_MS_PRIMARY_DNS_SERVER       = 28,
  SSH_RADIUS_VENDOR_MS_SECONDARY_DNS_SERVER     = 29,
  SSH_RADIUS_VENDOR_MS_PRIMARY_NBNS_SERVER      = 30,
  SSH_RADIUS_VENDOR_MS_SECONDARY_NBNS_SERVER    = 31,
  SSH_RADIUS_VENDOR_MS_ARAP_CHALLENGE           = 33
} SshRadiusVendorMsType;

/** Values for RADIUS NAS-Port-Type attribute. */
typedef enum
{
  /* Attribute values from the RFC 2865 document. */
  SSH_RADIUS_NAS_PORT_TYPE_ASYNC                 = 0,
  SSH_RADIUS_NAS_PORT_TYPE_SYNC                  = 1,
  SSH_RADIUS_NAS_PORT_TYPE_ISDN_SYNC             = 2,
  SSH_RADIUS_NAS_PORT_TYPE_ISDN_ASYNC_V120       = 3,
  SSH_RADIUS_NAS_PORT_TYPE_ISDN_ASYNC_V110       = 4,
  SSH_RADIUS_NAS_PORT_TYPE_VIRTUAL               = 5,
  SSH_RADIUS_NAS_PORT_TYPE_PIAFS                 = 6,
  SSH_RADIUS_NAS_PORT_TYPE_HDLC_CLEAR            = 7,
  SSH_RADIUS_NAS_PORT_TYPE_X25                   = 8,
  SSH_RADIUS_NAS_PORT_TYPE_X75                   = 9,
  SSH_RADIUS_NAS_PORT_TYPE_G3FAX                 = 10,
  SSH_RADIUS_NAS_PORT_TYPE_SDSL                  = 11,
  SSH_RADIUS_NAS_PORT_TYPE_ADSL_CAP              = 12,
  SSH_RADIUS_NAS_PORT_TYPE_ADSL_DMT              = 13,
  SSH_RADIUS_NAS_PORT_TYPE_ADSL_IDSL             = 14,
  SSH_RADIUS_NAS_PORT_TYPE_ETHERNET              = 15,
  SSH_RADIUS_NAS_PORT_TYPE_XDSL                  = 16,
  SSH_RADIUS_NAS_PORT_TYPE_CABLE                 = 17,
  SSH_RADIUS_NAS_PORT_TYPE_WIRELESS_OTHER        = 18,
  SSH_RADIUS_NAS_PORT_TYPE_WIRELESS_IEEE_802_11  = 19
} SshRadiusNasPortRype;

/** Values for RADIUS Service-Type attribute */
typedef enum {
  /* Magic value yet not used in any spec */
  SSH_RADIUS_SERVICE_TYPE_NONE                    = 0,
  /* RFC 2865 */
  SSH_RADIUS_SERVICE_TYPE_LOGIN                   = 1,
  SSH_RADIUS_SERVICE_TYPE_FRAMED                  = 2,
  SSH_RADIUS_SERVICE_TYPE_CALLBACK_LOGIN          = 3,
  SSH_RADIUS_SERVICE_TYPE_CALLBACK_FRAMED         = 4,
  SSH_RADIUS_SERVICE_TYPE_OUTBOUND                = 5,
  SSH_RADIUS_SERVICE_TYPE_ADMINISTRATIVE          = 6,
  SSH_RADIUS_SERVICE_TYPE_NAS_PROMPT              = 7,
  SSH_RADIUS_SERVICE_TYPE_AUTHENTICATE_ONLY       = 8,
  SSH_RADIUS_SERVICE_TYPE_CALLBACK_NAS_PROMPT     = 9,
  SSH_RADIUS_SERVICE_TYPE_CALL_CHECK              = 10,
  SSH_RADIUS_SERVICE_TYPE_CALLBACK_ADMINISTRATIVE = 11
} SshRadiusServiceType;

/** Values for RADIUS Framed-Protocol attribute. */
typedef enum {
  /* Magic value not yet used in any specification */
  SSH_RADIUS_FRAMED_PROTOCOL_NONE                 = 0,
  /* RFC 2865 */
  SSH_RADIUS_FRAMED_PROTOCOL_PPP                  = 1,
  SSH_RADIUS_FRAMED_PROTOCOL_SLIP                 = 2,
  SSH_RADIUS_FRAMED_PROTOCOL_ARAP                 = 3,
  SSH_RADIUS_FRAMED_PROTOCOL_GANDALF              = 4,
  SSH_RADIUS_FRAMED_PROTOCOL_XYLOGICS_IPX_SLIP    = 5,
  SSH_RADIUS_FRAMED_PROTOCOL_X75_SYNC             = 6
} SshRadiusFramedProtocolType;


/** Value for Accounting-Status-Type attribute*/
typedef enum {
  /* RFC 2866 */
  SSH_RADIUS_ACCT_STATUS_START                    = 1,
  SSH_RADIUS_ACCT_STATUS_STOP                     = 2,
  SSH_RADIUS_ACCT_STATUS_INTERIM_UPDATE           = 3,
  SSH_RADIUS_ACCT_STATUS_ON                       = 7,
  SSH_RADIUS_ACCT_STATUS_OFF                      = 8
} SshRadiusAccountingStatusType;

/** Configuration parameters for RADIUS clients. */
struct SshRadiusClientParamsRec
{
  /** The local IP address for the UDP listener.  The default value is
      SSH_IPADDR_ANY. */
  unsigned char *address;

  /** The local UDP port for the UDP listener.  As a default the system picks
      an unprivileged port. */
  unsigned char *port;

  /** The identification of this NAS (Network Access Server).  If you
      specify either one of these (or both) they will be automatically
      included in the request unless you have already set them with
      the ssh_radius_client_request_add_attribute() function.  Note
      that the request must contain one (or both) of these. */
  unsigned char *nas_ip_address;
  unsigned char *nas_identifier;

  /** The physical port and the type of port on the NAS the request is
      associated to. The 'boolean _isvalid' fields indicate whether to
      automatically add these to a RADIUS Access-Request.

      RFC 2865 states that at least one of these SHOULD be included in every
      Access-Request. */
  SshUInt32 nas_port;
  SshUInt32 nas_port_type;

  unsigned int nas_port_isvalid : 1;
  unsigned int nas_port_type_isvalid : 1;

  /** The maximum retransmit timer value in seconds.  The default
      value is 8.  The retransmission timer start from 1 seconds and
      doubles in every retransmission up to this value. */
  SshUInt32 max_retransmit_timer;

  /** The maximum number of retransmissions for a RADIUS request.  The
      default value is 4. */
  SshUInt32 max_retransmissions;
};

typedef struct SshRadiusClientParamsRec SshRadiusClientParamsStruct;
typedef struct SshRadiusClientParamsRec *SshRadiusClientParams;

/** Status codes for packet attribute adding and retrieving. */
typedef enum
{
  /** The operation was successful. */
  SSH_RADIUS_AVP_STATUS_SUCCESS,

  /** The length of the attribute is too long.  This is returned when adding
      attributes to a packet. */
  SSH_RADIUS_AVP_STATUS_VALUE_TOO_LONG,

  /** Too many attributes for a RADIUS packet.  There is a fixed amount of
      attributes (in bytes) that can be added for a single radius packet. */
  SSH_RADIUS_AVP_STATUS_TOO_MANY,

  /** No memory to add new attribute. */
  SSH_RADIUS_AVP_STATUS_OUT_OF_MEMORY,

  /** The AVP already exists in the requests and it may not be included more
      than once. */
  SSH_RADIUS_AVP_STATUS_ALREADY_EXISTS,

  /** The attribute was not found from the packet.  This is returned when
      fetching attributes from a reply packet. */
  SSH_RADIUS_AVP_STATUS_NOT_FOUND
} SshRadiusAvpStatus;

/* Mapping between SshRadiusAvpStatus and their names. */
extern const SshKeywordStruct ssh_radius_avp_status_codes[];

/*--------------------------------------------------------------------*/
/* Creating and destroying radius clients                             */
/*--------------------------------------------------------------------*/

/** Create a new RADIUS client.  The argument `params' specify
    optional parameters for the client.  If the argument `params' is
    NULL or any of its values have the value 0 or NULL, the default
    values will be used for those parameters.  The function returns a
    radius client object or NULL of the client creation fails. */
SshRadiusClient ssh_radius_client_create(SshRadiusClientParams params);

/** Destroy the radius client `client'.  The client must not have any active
    or pending requests. */
void ssh_radius_client_destroy(SshRadiusClient client);

/*--------------------------------------------------------------------*/
/* Configuring RADIUS servers                                         */
/*--------------------------------------------------------------------*/

/** A RADIUS server info object. */
typedef struct SshRadiusClientServerInfoRec *SshRadiusClientServerInfo;

/** Create a new RADIUS server info object.  The function returns a radius
    server info object or NULL if the creation failed. */
SshRadiusClientServerInfo ssh_radius_client_server_info_create(void);

/** Destroy the RADIUS server info object `info'.  If this was the last
    reference to the object, it will be freed.  Otherwise the function simply
    removes one reference and the actual deletion is done when the last
    reference goes away. */
void ssh_radius_client_server_info_destroy(SshRadiusClientServerInfo info);

/** Configure a radius server `server_addr' into the server info
    `info'.  The argument `server_port' specifies the RADIUS server
    port.  If it has the value NULL, the default port 1812 will be
    used.

    The argument `server_acct_port' specifies the RADIUS server
    accounting port. If the argument has the value NULL, the default
    port 1813 will be used. Note that the old RADIUS RFCs use the UDP
    ports 1645 and 1646 for authentication and accounting so you might
    have to specify the ports explicitly.

    The arguments `secret', `secret_len' specify the shared secret
    between RADIUS client and server.  The function returns TRUE if
    the server was added and FALSE otherwise. */
Boolean ssh_radius_client_server_info_add_server(
                                        SshRadiusClientServerInfo info,
                                        const unsigned char *server_addr,
                                        const unsigned char *server_port,
                                        const unsigned char *server_acct_port,
                                        const unsigned char *secret,
                                        size_t secret_len);


/*--------------------------------------------------------------------*/
/* Client requests                                                    */
/*--------------------------------------------------------------------*/

/** Create a new RADIUS client request of type `code'.  The argument
    `code' must have the value `SSH_RADIUS_ACCESS_REQUEST' or
    `SSH_RADIUS_ACCOUNTING_REQUEST'.  The function returns a request
    handle or NULL if the library could not allocate new request. */
SshRadiusClientRequest ssh_radius_client_request_create(
                                                SshRadiusClient radius_client,
                                                SshRadiusOperationCode code);

/** Destroy the radius client request `request' and free all its resources.
    The request must not be active when it is destroyed. */
void ssh_radius_client_request_destroy(SshRadiusClientRequest request);

/** Add a new attribute to the client request `request'.  The argument `type'
    specifies the type of the attribute and its value is given in the
    arguments `value', `value_len'.  The function returns an
    SshRadiusAvpStatus which describes the success of the operation. */
SshRadiusAvpStatus ssh_radius_client_request_add_attribute(
                                        SshRadiusClientRequest request,
                                        SshRadiusAvpType type,
                                        const unsigned char *value,
                                        size_t value_len);

/** Add a new vendor specific attribute to the client request `request'.

    The 'vendor_id' parameter specifies the vendor-id'. The argument
    `vs_type' specifies the vendor-type of the attribute and its value
    is given in the arguments `value', `value_len'. If 'vendor_id' is
    SSH_RADIUS_VENDOR_ID_NONE, then the call is equivalent to
    ssh_radius_client_request_add_attribute(request,vs_type,value,value_len).

    The function returns an SshRadiusAvpStatus which describes the success of
    the operation. */
SshRadiusAvpStatus ssh_radius_client_request_add_vs_attribute(
                                        SshRadiusClientRequest request,
                                        SshRadiusVendorId vendor_id,
                                        unsigned int vs_type,
                                        const unsigned char *value,
                                        size_t value_len);

/** Get index of current server of request.  On success this returns TRUE
    and fills in server_index. */
Boolean ssh_radius_client_request_get_server(SshRadiusClientRequest request,
                                             int *server_index);

/** Bind request to a server.  On success this returns TRUE. */
Boolean ssh_radius_client_request_set_server(SshRadiusClientRequest request,
                                             SshRadiusClientServerInfo servers,
                                             int server_index);

/** Return number of retransmits on this request.
 */
unsigned int ssh_radius_client_request_get_retranmit_count(
                                        SshRadiusClientRequest request);

/** Status codes for RADIUS client requests. */
typedef enum
{
  /** The request was successful. */
  SSH_RADIUS_CLIENT_REQ_SUCCESS,

  /** The request was malformed. */
  SSH_RADIUS_CLIENT_REQ_MALFORMED_REQUEST,

  /** Insufficient resources to perform the request. */
  SSH_RADIUS_CLIENT_REQ_INSUFFICIENT_RESOURCES,

  /** The request timed out. */
  SSH_RADIUS_CLIENT_REQ_TIMEOUT,

  /** The server reply was malformed. */
  SSH_RADIUS_CLIENT_REQ_MALFORMED_REPLY,

  /** Request was cancelled. */
  SSH_RADIUS_CLIENT_REQ_CANCELLED

} SshRadiusClientRequestStatus;

/** Mapping between SshRadiusClientRequestStatus and their names. */
extern const SshKeywordStruct ssh_radius_client_request_status_codes[];

/** A callback function of this type is called to notify the status of the
    ssh_radius_client_request() function.

    The argument `status' specifies the status of the request.  If the
    request was successful, the argument `reply_code' is valid and it
    specifies the type of the response packet.

    The attributes of the response packet remain valid as long as the control
    remains in the callback function.  You can use the reply processing
    functions to fetch the attribute values from the response packet. */
typedef void (*SshRadiusClientRequestCB)(SshRadiusClientRequestStatus status,
                                         SshRadiusClientRequest request,
                                         SshRadiusOperationCode reply_code,
                                         void *context);

/** Execute the RADIUS client request `request' with the RADIUS servers,
    specified by the server info `servers'.  The callback function `callback'
    will be called to notify about the success of the request. */
SshOperationHandle ssh_radius_client_request(SshRadiusClientRequest request,
                                             SshRadiusClientServerInfo servers,
                                             SshRadiusClientRequestCB callback,
                                             void *context);

/**
   Iterate through and cancel all active requests, i.e. requests
   passed to ssh_radius_client_request() but not yet called back
   for.

   Each cancelled requests callback is called with request status of
   SSH_RADIUS_CLIENT_REQ_CANCELLED. The operation handles of the
   requests become invalid.
 */
void ssh_radius_client_cancel_all_requests(SshRadiusClient client);


/*--------------------------------------------------------------------*/
/* Reply processing functions                                         */
/*--------------------------------------------------------------------*/

/** A structure for traversing the AVP's in RADIUS responses. Please do not
    access the fields in this structure directly. The definition of this
    structure is given explicitly so it can be placed on the stack for
    convenience. */
struct SshRadiusClientReplyEnumeratorRec
{
  /** The request we are associated with. */
  SshRadiusClientRequest req;

  /** The current type to enumerate. */
  SshRadiusVendorId vendor_selector;
  unsigned int type_selector;

  /** Current Vendor id */
  SshRadiusVendorId vendor_id;

  /** The current attribute enumerate position */
  size_t current_offset;

  /** The next attribute enumerate position. */
  size_t avp_offset;

  /** The endpoint of this list of AVP's in the request (offset of first byte
      not part of the list). */
  size_t current_length;

  /** Total length */
  size_t prev_length;
};

typedef
struct SshRadiusClientReplyEnumeratorRec SshRadiusClientReplyEnumeratorStruct;

typedef
struct SshRadiusClientReplyEnumeratorRec *SshRadiusClientReplyEnumerator;

/** You can use these functions only from an SshRadiusClientRequestCB
    function. */

/** Reset the reply attribute enumeration for the attribute type `type'.

    If the argument `type' has the value 0, the enumeration will match
    all attribute types. If 'type' is not 0 and 'vendor_id' is
    SSH_RADIUS_VENDOR_ID_NONE, then the enumeration will match the
    attributes of 'type' If 'type' is not 0 and 'vendor_id' is not
    SSH_RADIUS_VENDOR_ID_NONE, then the enumeration will assume that
    the Vendor-Specific types from vendor 'vendor_id' follow RFC 2865
    and the enumeration will match vendor sub-types with type
    'type'. */
void ssh_radius_client_reply_enumerate_init(
                                        SshRadiusClientReplyEnumerator e,
                                        SshRadiusClientRequest request,
                                        SshRadiusVendorId vendor_id,
                                        unsigned int type);

/** If ssh_radius_client_reply_enumerate_next() returned a RADIUS AVP
    of VENDOR_SPECIFIC type, then the
    ssh_radius_client_reply_enumerate_get_vendor() function can be
    used to query the vendor id in the AVP. */
SshRadiusVendorId
ssh_radius_client_reply_enumerate_get_vendor(SshRadiusClientReplyEnumerator e);

/** If ssh_radius_client_reply_enumerate_next() returned a RADIUS AVP
    of VENDOR_SPECIFIC type, then the
    ssh_radius_client_reply_enumerate_subtypes() function can be
    called to trigger the enumeration of the vendor-specific
    subtypes. They will otherwise be skipped. */
Boolean
ssh_radius_client_reply_enumerate_subtypes(SshRadiusClientReplyEnumerator e);

/** Return the value of the next reply attribute of the given type.

    The function retuns a status code which describes whether the
    reply has more attributes of the given type or not.  If the reply
    contains an attribute, its type is returned in `type_return'. The
    vendor of the type is returned in 'vendor_id_return' and it is
    SSH_RADIUS_VENDOR_ID_NONE if the AVP is of standard type.

    The arguments 'vendor_id_return' and `type_return' can have
    the value NULL in which case the relevant information is not returned.
    The value of the attribute is returned in `value_return' and
    `value_len_return'. */
SshRadiusAvpStatus ssh_radius_client_reply_enumerate_next(
                                        SshRadiusClientReplyEnumerator e,
                                        SshRadiusVendorId *vendor_id_return,
                                        SshRadiusAvpType *type_return,
                                        unsigned char **value_return,
                                        size_t *value_len_return);

/*--------------------------------------------------------------------*/
/* A Higher Level Interface                                           */
/*--------------------------------------------------------------------*/

/** This interface is based on the use of URL's of the form
    radius://nas-id[:passwd]@host[:port][/type[?attr=val[&...]]]

   - nas-id is the value of the NAS-Identifier attribute.
   - passwd is the shared secret. The default is the empty string.
   - host is the address of the server
   - port is the port of the radius server. The default is 1812.
   - type is the type of the radius request. The default is Access-Request.
   - attr is a RADIUS attribute name and val is it's desired value.

   Currently only attributes with values of the type INTEGER, ADDRESS,
   TIME or TEXT are supported. The names of attributes is taken from
   sshradius_tables.c, which co-incides with the names in the RADIUS
   RFC's. */

/** Return codes for functions parsing radius:// URL's */

typedef enum {
  /** Magic value, not in use */
  SSH_RADIUS_URL_STATUS_NONE = 0,

  /** OK. */
  SSH_RADIUS_URL_STATUS_SUCCESS = 1,

  /** An AVP attribute value was not recognized */
  SSH_RADIUS_URL_UNKNOWN_AVP_TYPE = 2,

  /** Out of memory */
  SSH_RADIUS_URL_OUT_OF_MEMORY = 3,

  /** An AVP attribute value could not be parsed */
  SSH_RADIUS_URL_INVALID_AVP_VALUE = 4,

  /** Invalid scheme in RADIUS:// URL */
  SSH_RADIUS_URL_INVALID_SCHEME = 5,

  /** NAS-identifier missing from URL */
  SSH_RADIUS_URL_EXPECTING_NAS_ID = 6,

  /** AVP list in URL invalid */
  SSH_RADIUS_URL_AVPLIST_MALFORMED = 7,

  /** URL malformed. sshurl.h could not parse it. */
  SSH_RADIUS_URL_MALFORMED = 8

} SshRadiusUrlStatus;

/** Mapping of the above values to human readable explanations */
extern const SshKeywordStruct ssh_radius_url_status_codes[];


/** The ssh_radius_url_init_params() function initializes the parameters from
    the radius:// URL for a SshRadiusClient object. The structure should later
    be uninitialized using ssh_radius_url_uninit_params().

    It is safe to uninit_params() a memset(..0,..)  SshRadiusClientParams
    structure.

    The main purpose of the function is to fetch the NAS identifier for the
    client from the URL. */
SshRadiusUrlStatus
ssh_radius_url_init_params(SshRadiusClientParams params, unsigned char *url);

void
ssh_radius_url_uninit_params(SshRadiusClientParams params);

/** Handle sets of RADIUS AVP's specified in URL's or otherwise.  This
    is mainly to provide some convenience in handling sets of AVP's,
    but still be a relatively light solution (which is why ADT's where
    not used). */

typedef struct SshRadiusUrlAvpRec *SshRadiusUrlAvp;
typedef struct SshRadiusUrlAvpSetRec *SshRadiusUrlAvpSet;

/** Do not manipulate this structure directly. The definition is
    provided so that it can be easily embedded into other structures
    or placed on the stack. */
typedef struct SshRadiusUrlAvpSetRec
{
  SshRadiusUrlAvp avp;
  size_t navps;
} SshRadiusUrlAvpSetStruct;

/** Init a SshRadiusUrlAvpSetStruct to contain the AVP's specified in url
    parameter. Passing NULL as url initializes the object as empty. */
SshRadiusUrlStatus
ssh_radius_url_init_avpset(SshRadiusUrlAvpSet set, unsigned char *url);

/** Uninit the parameter object. Freeing any memory allocated for it (except
    the stucture itself, obviously). */
void
ssh_radius_url_uninit_avpset(SshRadiusUrlAvpSet set);

/** Allocate and init a SshRadiusUrlAvpSet object. A pointer to the
    object is placed in *result. */
SshRadiusUrlStatus
ssh_radius_url_create_avpset(SshRadiusUrlAvpSet *result, unsigned char *url);

/** Destroy and uninit a SshRadiusUrlAvpSet object */
void
ssh_radius_url_destroy_avpset(SshRadiusUrlAvpSet avp);

/** Remove a AVP with avp_type type from a AVP set */
void
ssh_radius_url_remove_avpset_avp(SshRadiusUrlAvpSet avp_set,
                                 SshRadiusAvpType avp_type);

/** Add an AVP (avp_type, buf, len) to avp_set. If it is already present in
    the avp_set, then set it's value to the one specified.

    The function returns FALSE if it runs ouf of memory and TRUE if it
    succeeds. */
Boolean
ssh_radius_url_set_avpset_avp(SshRadiusUrlAvpSet avp_set,
                              SshRadiusAvpType avp_type,
                              SshUInt8 *buf,
                              SshUInt8 len);

/** Allocate a SshRadiusUrlAvpSet and place in it the union of
    set_super and set_sub. If an AVP is contained in both set_super
    and set_sub, the one from set_sub is chosen.

    The function returns NULL if it runs out of memory. */
SshRadiusUrlAvpSet
ssh_radius_url_add_avpset(SshRadiusUrlAvpSet set_super,
                          SshRadiusUrlAvpSet set_sub);

/** Marshal a set of AVP's from avp_set into req.

    The function returns TRUE if succesfull.  */
Boolean
ssh_radius_url_add_avps(SshRadiusClientRequest req,
                        SshRadiusUrlAvpSet avp_set);

/** Add RADIUS server to a SshRadiusClientServerInfo from a RADIUS URL */
SshRadiusUrlStatus
ssh_radius_url_add_server(SshRadiusClientServerInfo s_info,
                          unsigned char *url);

/** Parse a radius:// URL and see if it is in valid format */
SshRadiusUrlStatus
ssh_radius_url_isok(unsigned char *url);

/** The ssh_radius_url_create_request() is a one-stop convenience API for
    performing simple RADIUS requests from a radius:// URL.

    The varargs format is a bit ugly, but it allows one to handle he common
    case with one easy function call.

    The parameters are passed in the format (callback, NULL-terminated
    sequence of URL's, NULL-terminated sequence of ptr, length, AVP_TYPE),

    If the function returns SSH_RADIUS_URL_STATUS_SUCCESS, then a valid
    SshOperationHandle has been placed in *result. Otherwise a status code
    describing the error in the creation of the asynchronous operation is
    placed.

    All resources associated with the request will be freed by aborting the
    operation.

    Example:

    <CODE>
    oh = ssh_radius_url_create_request(radius_cb, context_ptr,
        "radius://nasname:naspw@rad_serv?service-type=login",
         NULL,
         "ssh", strlen("ssh"), SSH_RADIUS_AVP_USER_NAME,
         "foobar", strlen("foobar"), SSH_RADIUS_AVP_USER_PASSWORD,
         NULL);
   </CODE>

   Please note that the RADIUS on-the-wire representation of packets limits
   the length of an AVP-value to be at most to 255 bytes. */
SshRadiusUrlStatus
ssh_radius_url_create_request(SshOperationHandle *result,
                              SshRadiusClientRequestCB cb, void *ctx, ...);

/*--------------------------------------------------------------------*/
/* Information about attributes                                       */
/*--------------------------------------------------------------------*/

/** Attribute value types. */
typedef enum
{
  /** UTF-8 encoded ISO 10646 characters. */
  SSH_RADIUS_AVP_VALUE_TEXT,

  /** Binary data. */
  SSH_RADIUS_AVP_VALUE_STRING,

  /** 32 bit address value, most significant octet first. */
  SSH_RADIUS_AVP_VALUE_ADDRESS,

  /** 128 bit address value, most significant octet first. */
  SSH_RADIUS_AVP_VALUE_IPV6_ADDRESS,

  /** 32 bit unsigned value, most significant octet first. */
  SSH_RADIUS_AVP_VALUE_INTEGER,

  /** 32 bit unsigned value, most significant octet first.  The value
      is seconds since 00:00:00 UTC, January 1, 1970. */
  SSH_RADIUS_AVP_VALUE_TIME,

  /** 8 bit tag followed by binary data. */
  SSH_RADIUS_AVP_VALUE_TAG_STRING,

  /** 8 bit tag followed by 32 bit unsigned value, most significant
      octet first. */
  SSH_RADIUS_AVP_VALUE_TAG_INTEGER
} SshRadiusAvpValueType;

/* Information about attributes. */
struct SshRadiusAvpInfoRec
{
  /** The attribute type. */
  SshRadiusAvpType type;

  /** The name of the attribute. */
  char *name;

  /** The type of the attribute value. */
  SshRadiusAvpValueType value_type;
};

typedef struct SshRadiusAvpInfoRec SshRadiusAvpInfoStruct;
typedef struct SshRadiusAvpInfoRec *SshRadiusAvpInfo;

/** Information about known attributes. */
extern const SshRadiusAvpInfoStruct ssh_radius_avp_info_table[];

/* Return information about attribute type `type'.

   The function returns an information structure or NULL if the
   attribute type `type' is unknown. */
const SshRadiusAvpInfoStruct *ssh_radius_avp_info(SshRadiusAvpType type);

/* Return information about attribute `name'.

   The function returns an information structure or NULL if the
   attribute `name' is unknown. */
const SshRadiusAvpInfoStruct *ssh_radius_avp_info_name(const char *name);

/* SshKeyword table containing mapping between RADIUS codes and
   their names. */
extern const SshKeywordStruct ssh_radius_operation_codes[];

/* SshKeyword table containing mapping from `Acct-Status-Type' names
   to their values. */
extern const SshKeywordStruct ssh_radius_acct_status_types[];

/* SshKeyword table containing mapping from NAS-Port-Type AVP
   (SSH_RADIUS_NAS_PORT_TYPE_*) values to names. */
extern const SshKeywordStruct ssh_radius_nas_port_types[];

/* SshKeyword table for mapping between Framed-Protocol AVP values
   and names */

extern const SshKeywordStruct ssh_radius_framed_protocols[];

/* SshKeyword table for mapping between Service-Type AVP values
   and names */
extern const SshKeywordStruct ssh_radius_service_types[];

#endif /* not SSHRADIUS_H */
