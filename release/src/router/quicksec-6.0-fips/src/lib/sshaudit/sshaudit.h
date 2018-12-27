/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Audit event handling.

   @description
   The sshaudit.h header file defines functions for inserting audit
   entries in a log file and also different events that may be audited.

   <keywords auditing, logging, event/auditing>
*/

#ifndef SSHAUDIT_H
#define SSHAUDIT_H

#include "sshenum.h"
#include "sshbuffer.h"


/* ************************ Types ***********************************/

/** List of auditable events. These identify the event that is being
    audited. */
typedef enum
{
  /* The following events are for IPsec Engine. */

  /** An attempt to transmit a packet that would result in Sequence Number
      overflow if anti-replay is enabled - the audit log entry SHOULD include
      the SPI value, date/time, Source Address, Destination Address
      (and, in IPv6, the Flow ID). */
  SSH_AUDIT_AH_SEQUENCE_NUMBER_OVERFLOW = 1,

  /** Whether a packet offered to AH for processing appears to be an IP
      fragment - the audit log entry for this event SHOULD include
      the SPI value, date/time, Source Address, Destination Address
      (and, in IPv6, the Flow ID). */
  SSH_AUDIT_AH_IP_FRAGMENT = 2,

  /** When mapping the IP datagram to the appropriate SA, the SA
      lookup fails - the audit log entry for this event SHOULD include
      the SPI value, date/time, Source Address, Destination Address
      (and, in IPv6, the cleartext Flow ID). */
  SSH_AUDIT_AH_SA_LOOKUP_FAILURE = 3,

  /** If a received packet does not fall within the receivers sliding
      window, the receiver MUST discard the received IP datagram as
      invalid - the audit log entry for this event SHOULD include the
      SPI value, date/time, Source Address, Destination Address, the
      Sequence Number (and, in IPv6, the Flow ID). */
  SSH_AUDIT_AH_SEQUENCE_NUMBER_FAILURE = 4,

  /** If the computed and received ICV's do not match, the receiver
      MUST discard the received IP datagram as invalid -
      the audit log entry SHOULD include the SPI value, date/time
      received, Source Address, Destination Address (and, in IPv6,
      the Flow ID).*/
  SSH_AUDIT_AH_ICV_FAILURE = 5,

  /** An attempt to transmit a packet that would result in Sequence Number
      overflow if anti-replay is enabled. The audit log entry SHOULD include
      the SPI value, date/time, Source Address, Destination Address,
      and (in IPv6) the Flow ID.*/
  SSH_AUDIT_ESP_SEQUENCE_NUMBER_OVERFLOW = 6,

  /** If a packet offered to ESP for processing appears to be an IP
      fragment. The audit log entry for this event SHOULD include
      the SPI value, date/time, Source Address, Destination Address,
      and (in IPv6) the Flow ID.*/
  SSH_AUDIT_ESP_IP_FRAGMENT = 7,

  /** When mapping the IP datagram to the appropriate SA, the SA
      lookup fails. The audit log entry for this event SHOULD include
      the SPI value, date/time, Source Address, Destination Address,
      and (in IPv6) the cleartext Flow ID.*/
  SSH_AUDIT_ESP_SA_LOOKUP_FAILURE = 8,

  /** If a received packet does not fall within the receivers sliding
      window, the receiver MUST discard the received IP datagram as
      invalid; The audit log entry for this event SHOULD include the
      SPI value, date/time, Source Address, Destination Address, the
      Sequence Number, and (in IPv6) the Flow ID.*/
  SSH_AUDIT_ESP_SEQUENCE_NUMBER_FAILURE = 9,

  /** If the computed and received ICV's do not match, then the receiver
      MUST discard the received IP datagram as invalid.
      The audit log entry SHOULD include the SPI value, date/time
      received, Source Address, Destination Address, and (in IPv6)
      the Flow ID.*/
  SSH_AUDIT_ESP_ICV_FAILURE = 10,


  /* The following events are for IPsec Policy Manager. */

  /** The other IKE peer tried to negotiate ESP SA with both a NULL
      encryption and a NULL authentication algorithm. */
  SSH_AUDIT_PM_ESP_NULL_NULL_NEGOTIATION = 30,


  /* The following events are for IKE (ISAKMP and IKEV2). */

  /** The message retry limit is reached when transmitting IKE (ISAKMP)
      messages.*/
  SSH_AUDIT_IKE_RETRY_LIMIT_REACHED = 60,

  /** When ISAKMP message is received and the cookie validation fails. */
  SSH_AUDIT_IKE_INVALID_COOKIE = 61,

  /** If the Version field validation fails.*/
  SSH_AUDIT_IKE_INVALID_VERSION = 62,
  /** If the Exchange Type field validation fails. */
  SSH_AUDIT_IKE_INVALID_EXCHANGE_TYPE = 63,

  /** If the Flags field validation fails.*/
  SSH_AUDIT_IKE_INVALID_FLAGS = 64,

  /** If the Message ID validation fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_MESSAGE_ID = 65,

  /** When any of the ISAKMP Payloads are received and if the NextPayload
     field validation fails.*/
  SSH_AUDIT_IKE_INVALID_NEXT_PAYLOAD = 66,

  /** If the value in the RESERVED field is not zero.*/
  SSH_AUDIT_IKE_INVALID_RESERVED_FIELD = 67,

  /**  If the DOI determination fails.*/
  SSH_AUDIT_IKE_INVALID_DOI = 68,

  /** If the Situation determination fails.*/
  SSH_AUDIT_IKE_INVALID_SITUATION = 69,

  /** If the Security Association Proposal is not accepted.*/
  SSH_AUDIT_IKE_INVALID_PROPOSAL = 70,

  /** If the SPI is invalid.*/
  SSH_AUDIT_IKE_INVALID_SPI = 71,

  /*If the proposals are not formed correctly.*/
  SSH_AUDIT_IKE_BAD_PROPOSAL_SYNTAX = 72,

  /** If the Transform-ID field is invalid. (not used)*/
  SSH_AUDIT_IKE_INVALID_TRANSFORM = 73,

  /** If the transforms are not formed correctly. (not used)*/
  SSH_AUDIT_IKE_INVALID_ATTRIBUTES = 74,

  /** If the Key Exchange determination fails. */
  SSH_AUDIT_IKE_INVALID_KEY_INFORMATION = 75,

  /** If the Identification determination fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_ID_INFORMATION = 76,

  /** If the Certificate Data is invalid or improperly formatted. (not
     used)*/
  SSH_AUDIT_IKE_INVALID_CERTIFICATE = 77,

  /** If the Certificate Encoding is invalid. (not used)*/
  SSH_AUDIT_IKE_INVALID_CERTIFICATE_TYPE = 78,

  /** If the Certificate Encoding is not supported. (not used)*/
  SSH_AUDIT_IKE_CERTIFICATE_TYPE_UNSUPPORTED = 79,

  /** If the Certificate Authority is invalid or improperly
     formatted. (not used)*/
  SSH_AUDIT_IKE_INVALID_CERTIFICATE_AUTHORITY = 80,

  /** If a requested Certificate Type with the specified Certificate
     Authority is not available. (not used)*/
  SSH_AUDIT_IKE_CERTIFICATE_UNAVAILABLE = 81,

  /** If the Hash determination fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_HASH_INFORMATION = 82,

  /** If the Hash function fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_HASH_VALUE = 83,

  /** If the Signature determination fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_SIGNATURE_INFORMATION = 84,

  /** If the Signature function fails. (not used)*/
  SSH_AUDIT_IKE_INVALID_SIGNATURE_VALUE = 85,

  /** When receivers notification payload check fails. (not used)*/
  SSH_AUDIT_IKE_NOTIFICATION_PAYLOAD_RECEIVED = 86,

  /** If the Protocol-Id determination fails. */
  SSH_AUDIT_IKE_INVALID_PROTOCOL_ID = 87,

  /** If the Notify Message Type is invalid. (not used)*/
  SSH_AUDIT_IKE_INVALID_MESSAGE_TYPE = 88,

  /** If receiver detects an error in Delete Payload. */
  SSH_AUDIT_IKE_DELETE_PAYLOAD_RECEIVED = 89,

  /** If receiver detects an error in payload lengths.*/
  SSH_AUDIT_IKE_UNEQUAL_PAYLOAD_LENGTHS = 90,

  /** If the Transform-type field is invalid. */
  SSH_AUDIT_IKE_INVALID_TRANSFORM_TYPE = 91,

  /** Traffic selectors do not match */
  SSH_AUDIT_IKE_INVALID_TRAFFIC_SELECTORS = 92,

  /** Invalid authentication method */
  SSH_AUDIT_IKE_INVALID_AUTHETICATION_METHOD = 93,

  /** Generic error for malformed IKE payloads */
  SSH_AUDIT_IKE_BAD_PAYLOAD_SYNTAX = 94,

  /** Invalid IKE key type. */
  SSH_AUDIT_IKE_INVALID_KEY_TYPE = 95,

  /** IKE packet received on unexpected port */
  SSH_AUDIT_IKE_PACKET_INVALID_PORT = 96,

  /** Unsupported critical payload in received packet */
  SSH_AUDIT_IKE_UNSUPPORTED_CRITICAL_PAYLOAD = 97,

  /** The following events are for packet processing engine. */

  /** Start of a new session. */
  SSH_AUDIT_ENGINE_SESSION_START = 120,

  /** End of a session. */
  SSH_AUDIT_ENGINE_SESSION_END = 121,

  /** Suspicious packet received and dropped */
  SSH_AUDIT_CORRUPT_PACKET = 122,

  /** Audit message rate limit hit */
  SSH_AUDIT_FLOOD = 123,

  /** Rule match */
  SSH_AUDIT_RULE_MATCH = 124,

  /** New configuration */
  SSH_AUDIT_NEW_CONFIGURATION = 125,

  /** Appgw session start/end */
  SSH_AUDIT_APPGW_SESSION_START = 126,
  SSH_AUDIT_APPGW_SESSION_END = 127,

  /** HTTP request */
  SSH_AUDIT_HTTP_REQUEST = 128,

  /** Protocol parse error. */
  SSH_AUDIT_PROTOCOL_PARSE_ERROR = 129,

  /** This indicates that a number of audit messages were lost and cannot
      be audited due to resource shortages. */
  SSH_AUDIT_RESOURCE_FAILURE = 132,

  /** The checksum coverage file in a UDP Lite packet is invalid */
  SSH_AUDIT_CHECKSUM_COVERAGE_FIELD_INVALID = 133,

  /** Misc. warning/notify events. Please use this only if there
      is NO point in defining a separate event which is the cause
      of the warning (e.g. it would be specific to the implementation
      and not the problem domain). */
  SSH_AUDIT_WARNING = 150,
  SSH_AUDIT_NOTICE = 151,

  /** CIFS session start/end */
  SSH_AUDIT_CIFS_SESSION_START = 180,
  SSH_AUDIT_CIFS_SESSION_STOP = 181,

  /** A CIFS file operation (open, close, rename, etc..) took place */
  SSH_AUDIT_CIFS_OPERATION = 182,

  /** FTP protocol did try to change the client or server IP in a data
     channel opening. */
  SSH_AUDIT_FTP_IP_CHANGE = 190,

  /** Hardware accelerator has been initialized */
  SSH_AUDIT_HWACCEL_INITIALIZED = 200,

  /** Hardware accelerator initialized failed */
  SSH_AUDIT_HWACCEL_INITIALIZATION_FAILED = 201,

  /** This must be the last item in the list marking the maximum
     defined audit event. */
  SSH_AUDIT_MAX_VALUE
} SshAuditEvent;


/** Mapping from SshAuditEvent to their names. */
extern const SshKeywordStruct ssh_audit_event_names[];

/** Enum types that are used when passing parameters to audit
    function. Audit function takes a variable number of
    arguments. First is the type of the auditable event
    (SshAuditEvent). Following that is listed additional information
    which is inserted to the audit log too. Additional arguments starts
    with type specified here. After that is a couple of parameters
    depending on the type of argument. Needed parameters is commented
    here. List must always end with a SSH_AUDIT_ARGUMENT_END. */
typedef enum
{
  /** Contains the SPI for the packet which caused an auditable event,
      for IKE this is the initiator and responder cookies - if the
      length is zero, then this value is ignored - unsigned char *,
      size_t. */
  SSH_AUDIT_SPI = 1,

  /** Contains the source address for the packet that caused the
      auditable event, for IKE this is local ip address - if the length
      is zero, then this value is ignored - unsigned char *, size_t. */
  SSH_AUDIT_SOURCE_ADDRESS = 2,

  /** Contains the destination address for the packet which caused the
      auditable event, for IKE this is remote ip address - if the length
      is zero, then this value is ignored - unsigned char *, size_t. */
  SSH_AUDIT_DESTINATION_ADDRESS = 3,

  /** Contains the source address for the packet which caused the
      auditable event, for IKE this is local ip address - if the pointer
      is NULL, then this value is ignored; this contains the source
      address in text format - unsigned char *. */
  SSH_AUDIT_SOURCE_ADDRESS_STR = 4,

  /** Contains the destination address for the packet which caused the
      auditable event, for IKE this is remote ip address - if the
      pointer is NULL, then this value is ignored; this contains the
      destination address in text format - unsigned char *. */
  SSH_AUDIT_DESTINATION_ADDRESS_STR = 5,

  /** Contains the Flow ID for the packet which caused the auditable
      event (this conserns only IPv6 addresses) - if the length is zero,
      then this value is ignored - unsigned char *, size_t. */
  SSH_AUDIT_IPV6_FLOW_ID = 6,

  /** Contains the sequence number for the packet which caused the
      auditable event - if the length is zero then, this value is
      ignored - unsigned char *, size_t. */
  SSH_AUDIT_SEQUENCE_NUMBER = 7,

  /** Describing text for the event - if the pointer is NULL, then this
      value is ignored - unsigned char *. */
  SSH_AUDIT_TXT = 8,

  /** IP protocol ID - SshUInt32. */
  SSH_AUDIT_IPPROTO = 9,

  /** Source port number - unsigned char *, size_t. */
  SSH_AUDIT_SOURCE_PORT = 10,

  /** Destination port number - unsigned char *, size_t. */
  SSH_AUDIT_DESTINATION_PORT = 11,

  /** Reason packet is corrupted - unsigned char*. */
  SSH_AUDIT_PACKET_CORRUPTION = 12,

  /** Packet attack id - unsigned char *. */
  SSH_AUDIT_PACKET_ATTACK = 13,

  /** Source interface name - unsigned char. */
  SSH_AUDIT_SOURCE_INTERFACE = 14,

  /** Destination interface name - unsigned char *. */
  SSH_AUDIT_DESTINATION_INTERFACE = 15,

  /** IPv4 option name - unsigned char *, size_t *. */
  SSH_AUDIT_IPV4_OPTION = 16,

  /** ICMP type and code - unsigned char *, size_t *. */
  SSH_AUDIT_ICMP_TYPECODE = 17,

  /** IPv6 ICMP type and code - unsigned char *, size_t *. */
  SSH_AUDIT_IPV6ICMP_TYPECODE = 18,

  /** TCP flags - unsigned char *, size_t *. */
  SSH_AUDIT_TCP_FLAGS = 19,

  /** Audit event source - unsigned char *. */
  SSH_AUDIT_EVENT_SOURCE = 20,

  /** HTTP method - unsigned char *. */
  SSH_AUDIT_HTTP_METHOD = 21,

  /** Request URL/URI - unsigned char *. */
  SSH_AUDIT_REQUEST_URI = 22,

  /** HTTP version - unsigned char *. */
  SSH_AUDIT_HTTP_VERSION = 23,

  /** A rule identifier - unsigned char *. */
  SSH_AUDIT_RULE_NAME = 24,

  /** A rule action - unsigned char *. */
  SSH_AUDIT_RULE_ACTION = 25,

  /** Source host - unsigned char *. */
  SSH_AUDIT_SOURCE_HOST = 26,
  /** Destination host - unsigned char *. */
  SSH_AUDIT_DESTINATION_HOST = 27,

  /** CIFS domain - unsigned char *. */
  SSH_AUDIT_CIFS_DOMAIN = 28,
  /** CIFS account - unsigned char *. */
  SSH_AUDIT_CIFS_ACCOUNT = 29,
  /** CIFS command - unsigned char *. */
  SSH_AUDIT_CIFS_COMMAND = 30,
  /** CIFS dialect - unsigned char *. */
  SSH_AUDIT_CIFS_DIALECT = 31,

  /** Key length in bits - unsigned char *, size_t. */
  SSH_AUDIT_KEY_LENGTH = 32,

  /** NetBIOS source name - unsigned char *. */
  SSH_AUDIT_NBT_SOURCE_HOST = 33,
  /** NetBIOS destination name - unsigned char *. */
  SSH_AUDIT_NBT_DESTINATION_HOST = 34,

  /** CIFS subcommand - unsigned char *. */
  SSH_AUDIT_CIFS_SUBCOMMAND = 35,

  /** FTP command - unsigned char *, size_t. */
  SSH_AUDIT_FTP_COMMAND = 36,

  /** SOCKS version - unsigned char *, size_t. */
  SSH_AUDIT_SOCKS_VERSION = 37,
  /** SOCKS server IP address - unsigned char *, size_t. */
  SSH_AUDIT_SOCKS_SERVER_IP = 38,
  /** SOCKS server port. */
  SSH_AUDIT_SOCKS_SERVER_PORT = 39,

  /** Generic username - unsigned char *. */
  SSH_AUDIT_USERNAME = 40,

  /** Target IP/Host for various operations - not the actual TCP connection. */
  SSH_AUDIT_TARGET_IP = 41,

  /** Target port for various operations - not the actual TCP connection. */
  SSH_AUDIT_TARGET_PORT = 42,

  /** Bytes transmitted - unsigned char *, size_t. */
  SSH_AUDIT_TRANSMIT_BYTES = 43,

  /** Information about data transmitted - unsigned char *, size_t. */
  SSH_AUDIT_TRANSMIT_DIGEST = 44,

  /** Local username - unsigned char *. */
  SSH_AUDIT_USER = 50,

  /** Remote username - unsigned char *. */
  SSH_AUDIT_REMOTE_USER = 51,

  /** Session identifier - unsigned char *, size_t. */
  SSH_AUDIT_SESSION_ID = 52,

  /** Session sub identifier (channel id, file handle id etc)
      - unsigned char *, size_t. */
  SSH_AUDIT_SUB_ID = 53,

  /** Error code (remote error code, local error code etc)
      - unsigned char *, size_t. */
  SSH_AUDIT_ERROR_CODE = 54,

  /** File name - unsigned char *, size_t. */
  SSH_AUDIT_FILE_NAME = 55,

  /** Command - unsigned char *, size_t. */
  SSH_AUDIT_COMMAND = 56,

  /** Length of data - unsigned char *, size_t. */
  SSH_AUDIT_TOTAL_LENGTH = 57,

  /** Length of data written - unsigned char *, size_t. */
  SSH_AUDIT_DATA_WRITTEN = 58,

  /** Length of data read - unsigned char *, size_t. */
  SSH_AUDIT_DATA_READ = 59,

  /** Quicksec tunnel id as an integer (as provided by Engine). */
  SSH_AUDIT_TOTUNNEL_ID = 60,

  /** Quicksec tunnel id as a readable string (as provided by PM). */
  SSH_AUDIT_FROMTUNNEL_ID = 61,

  /** Ethernet source address - unsigned char *, size_t. */
  SSH_AUDIT_ETH_SOURCE_ADDRESS = 62,

  /** Ethernet destination address - unsigned char *, size_t. */
  SSH_AUDIT_ETH_DESTINATION_ADDRESS = 63,

  /** Ethernet type - unsigned char *, size_t. */
  SSH_AUDIT_ETH_TYPE = 64,

  /* SNORT-specific argument types. */
  SSH_AUDIT_SNORT_SIG_GENERATOR      = 65,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_SIG_ID             = 66,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_SIG_REV            = 67,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_CLASSIFICATION     = 68,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_CLASSIFICATION_STR = 69,     /** unsigned char. *          */
  SSH_AUDIT_SNORT_PRIORITY           = 70,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_EVENT_ID           = 71,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_EVENT_REFERENCE    = 72,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_PACKET_FLAGS       = 73,     /** unsigned char *, size_t. */
  SSH_AUDIT_SNORT_ACTION_TYPE        = 74,     /** unsigned char. *          */
  SSH_AUDIT_SNORT_REFERENCE          = 75,     /** unsigned char. *          */

  /** Packet data - unsigned char *, size_t. */
  SSH_AUDIT_PACKET_DATA = 76,

  /** Actual packet length, may be larger than the number of bytes encoded
      in the SSH_AUDIT_PACKET_DATA argument - unsigned char *, size_t. */
  SSH_AUDIT_PACKET_LEN = 77,

  /*  Marks end of the argument list. */
  SSH_AUDIT_ARGUMENT_END = -1
} SshAuditArgumentType;

/** An audit argument. */
struct SshAuditArgumentRec
{
  /** The type of the argument. */
  SshAuditArgumentType type;

  /** Argument value and its length.  The field 'data_len' is always
      valid, also for arguments taking a null-terminated string.  For
      those strings, it holds the strlen() of the value. */
  unsigned char *data;
  size_t data_len;
};

typedef struct SshAuditArgumentRec SshAuditArgumentStruct;
typedef struct SshAuditArgumentRec *SshAuditArgument;


/** A callback function of this type is called when an audit event is
    logged from the system.  The argument `event' specifies the audit
    event.  The argument `argc' specifies the number of argument the
    event has.  The argument `argv' is an array containing the
    arguments.  The values, pointed by the fields in the `argv' array,
    remain valid as long as the control remains in the callback
    function. */
typedef void (*SshAuditCB)(SshAuditEvent event, SshUInt32 argc,
                           SshAuditArgument argv, void *context);


/** A callback function of this type is called when the audit context
    is destroyed via a call to ssh_audit_destroy. 'context' is the
    context parameter that is given to ssh_audit_create. */
typedef void (*SshAuditDestroyCB)(void *context);


/** Context structure which is created with the ssh_audit_create
    function. */
typedef struct SshAuditContextRec *SshAuditContext;


/* **************** Creating and destroying audit contexts ******************/

/** Creates an audit context.  The argument `audit_callback' is a callback
    function that will be called when an audit event is logged with the
    ssh_audit_event function. 'destroy_callback' will be called when the
    audit context is destroyed via ssh_audit_destroy. The function returns
    NULL if the operation fails in which case the 'destroy_callback' will
    already be called. */
SshAuditContext ssh_audit_create(SshAuditCB audit_callback,
                                 SshAuditDestroyCB destroy_callback,
                                 void *context);

/** Destroys the audit context `context'. This calls the 'destroy_callback'
    that was supplied to ssh_audit_create. */
void ssh_audit_destroy(SshAuditContext context);


/* ************************ Handling audit events ***************************/

/** Inserts specified event into log file.  The event parameter
    specifies the audited event. Each element after that must start
    with a SshAuditformat type, followed by arguments of the
    appropriate type, and the list must end with
    SSH_AUDIT_FORMAT_END. If context is NULL then this call is
    ignored. */
void ssh_audit_event(SshAuditContext context, SshAuditEvent event, ...);

void ssh_audit_event_va(SshAuditContext context,
                        SshAuditEvent event, va_list va);

/** Like the ssh_audit_event function but the event arguments are given
    as an array `argv' having `argc' elements.

    If the `data_len' field of an argument in the `argv' array has the
    value 0 and the argument value is a null-terminated string, the
    function will set the `data_len' field to correct value.  For
    other argument value types, the `data_len' field must have valid
    value.

   */
void ssh_audit_event_array(SshAuditContext context, SshAuditEvent event,
                           SshUInt32 argc, SshAuditArgument argv);

/** Enables audit event 'event'.  As a default all events are enabled
    and they will make a call to the audit context's SshAuditCB
    callback. */
void ssh_audit_event_enable(SshAuditContext context, SshAuditEvent event);

/** Disables audit event 'event'.  The audit system will ignore all
    disabled events; it will not call the SshAuditCB for disabled
    events. */
void ssh_audit_event_disable(SshAuditContext context, SshAuditEvent event);

/** Queries the state of the audit event `event'.

    @return
    The function returns TRUE if the event is enabled,
    and FALSE otherwise. */
Boolean ssh_audit_event_query(SshAuditContext context, SshAuditEvent event);


/* ************** Help functions for formatting audit events ****************/

/** The type specifies how the audit message should be formatted. */
typedef enum
{
  /** Default internal formatting. This type should be used in all cases
      except where compatibility with a specific format is required. */
  SSH_AUDIT_FORMAT_DEFAULT = 1

} SshAuditFormatType;

/** Format audit event 'event' with the 'argc' number of arguments in
    'argv' into a human readable string to the buffer 'buffer'.

    @return
    The function returns TRUE if the event was formatted,
    and FALSE if the system ran out of memory. */
Boolean ssh_audit_format(SshBuffer buffer, SshAuditFormatType type,
                         SshAuditEvent event, SshUInt32 argc,
                         SshAuditArgument argv);

#endif /* not SSHAUDIT_H */
