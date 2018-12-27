/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public header file for the L2TP library.  The L2TP library
   implements the L2TP control connection and session establishment.
   The PPP level operations, for example LCP, IPCP, authentication,
   and datagram encapsulation and decapsulation, are implemented using
   separate PPP libary.

   References:

     RFC 2661   Layer Two Tunneling Protocol "L2TP"
     RFC 1994   PPP Challenge Handshake Authentication Protocol (CHAP)
*/

#ifndef SSHL2TP_H
#define SSHL2TP_H

#include "sshenum.h"
#include "sshinet.h"
#include "sshoperation.h"
#include "sshudp.h"

/*********************** Common types and definitions ***********************/

/* Tunnel ID. */
typedef SshUInt16 SshL2tpTunnelID;

/* Session ID. */
typedef SshUInt16 SshL2tpSessionID;

/* Tunnel termination reason codes. */
typedef enum
{
  /* Reserved.  This should not be sent. */
  SSH_L2TP_TUNNEL_RESULT_RESERVED,

  /* General request to clear control connection. */
  SSH_L2TP_TUNNEL_RESULT_TERMINATED,

  /* General error - Error Code indicates the problem. */
  SSH_L2TP_TUNNEL_RESULT_ERROR,

  /* Control channel already exists. */
  SSH_L2TP_TUNNEL_RESULT_ALREADY_EXISTS,

  /* Requester is not authorized to establish a control channel. */
  SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED,

  /* The protocol version of the requester is not supported.  Error
     Code indicates highest version supported. */
  SSH_L2TP_TUNNEL_RESULT_UNSUPPORTED_PROTOCOL,

  /* Requester is being shut down. */
  SSH_L2TP_TUNNEL_RESULT_SHUT_DOWN,

  /* Finite State Machine error. */
  SSH_L2TP_TUNNEL_RESULT_FSM_ERROR
} SshL2tpTunnelResultCode;

/* Mapping from tunnel result codes to ASCII descriptions. */
extern const SshKeywordStruct ssh_l2tp_tunnel_result_codes[];

/* Session termination reason codes. */
typedef enum
{
  /* Reserved.  This should not be sent. */
  SSH_L2TP_SESSION_RESULT_RESERVED,

  /* Call disconnected due to loss of carrier. */
  SSH_L2TP_SESSION_RESULT_CARRIER_LOST,

  /* Call disconnected for the reason indicated in Error Code. */
  SSH_L2TP_SESSION_RESULT_ERROR,

  /* Call disconnected for administrative reasons. */
  SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE,

  /* Call failed due to lack of appropriate facilities being available
     (temporary condition). */
  SSH_L2TP_SESSION_RESULT_TEMPORARY_UNAVAILABLE,

  /* Call failed due to lack of appropriate facilities being available
     (permanent condition). */
  SSH_L2TP_SESSION_RESULT_PERMANENTLY_UNAVAILABLE,

  /* Invalid destination. */
  SSH_L2TP_SESSION_RESULT_INVALID_DESTINATION,

  /* Call failed due to no carrier detected. */
  SSH_L2TP_SESSION_RESULT_NO_CARRIER,

  /* Call failed due to detection of a busy signal. */
  SSH_L2TP_SESSION_RESULT_BUSY,

  /* Call failed due to lack of a dial tone. */
  SSH_L2TP_SESSION_RESULT_NO_DIAL_TONE,

  /* Call was not established within time allowed by LAC. */
  SSH_L2TP_SESSION_RESULT_TIMEOUT,

  /* Call was connected but no appropriate framing was detected. */
  SSH_L2TP_SESSION_RESULT_INVALID_FRAMING
} SshL2tpSessionResultCode;

/* Mapping from session result codes to ASCII descriptions. */
extern const SshKeywordStruct ssh_l2tp_session_result_codes[];

/* Error codes for tunnel or session termination.  These are valid for
   SSH_L2TP_TUNNEL_RESULT_ERROR and SSH_L2TP_SESSION_RESULT_ERROR
   result codes. */
typedef enum
{
  /* No general error. */
  SSH_L2TP_ERROR_NO_GENERAL_ERROR,

  /* No control connection exists yet for this LAC-LNS pair. */
  SSH_L2TP_ERROR_NO_CONTROL_CONNECTION,

  /* Length is wrong. */
  SSH_L2TP_ERROR_LENGTH_IS_WRONG,

  /* One of the field values was out of range or reserved field was
     non-zero. */
  SSH_L2TP_ERROR_INVALID_VALUE,

  /* Insuffucient resources to handle this operation now. */
  SSH_L2TP_ERROR_INSUFFICIENT_RESOURCES,

  /* The Session ID is invalid in this context. */
  SSH_L2TP_ERROR_INVALID_SESSION_ID,

  /* A generic vendor-specific error occurred in the LAC. */
  SSH_L2TP_ERROR_GENERIC,

  /* Try another.  If LAC is aware of other possible LNS destinations,
     it should try one of them.  This can be used to guide an LAC
     based of LNS policy, for instance, the existence of multilink PPP
     bundles. */
  SSH_L2TP_ERROR_TRY_ANOTHER,

  /* Session or tunnel was shutdown due to receipt of an unknown AVP
     with the Mandatory-bit set.  The Error Message SHOULD contain the
     attribute of the offending AVP in (human readable) text form. */
  SSH_L2TP_ERROR_UNKNOWN_MANDATORY_AVP
} SshL2tpErrorCode;

/* Mapping from error codes to ASCII descriptions. */
extern const SshKeywordStruct ssh_l2tp_error_codes[];

/* A forward declaration for an L2TP session object. */
typedef struct SshL2tpSessionInfoRec *SshL2tpSessionInfo;


/**************************** Tunnel management *****************************/

/* Tunnel attributes. */
struct SshL2tpTunnelAttributesRec
{
  SshUInt32 framing_capabilities;
  SshUInt32 bearer_capabilities;
  SshUInt16 firmware_revision;
  unsigned char *host_name;
  size_t host_name_len;
  unsigned char *vendor_name;
  size_t vendor_name_len;

  /* SSH private attribute values. */
  SshUInt32 ssh_transform_index;
};

typedef struct SshL2tpTunnelAttributesRec SshL2tpTunnelAttributesStruct;
typedef struct SshL2tpTunnelAttributesRec *SshL2tpTunnelAttributes;

/* Public information about an L2TP tunnel. */
struct SshL2tpTunnelInfoRec
{
  /* The tunnel ID allocated by this peer for this tunnel. */
  SshL2tpTunnelID local_id;

  /* The tunnel ID allocated by the remote peer for this session. */
  SshL2tpTunnelID remote_id;

  /* Flags for the tunnel. */
  unsigned int initiator : 1;

  /* Tunnel end points. */

  unsigned char *remote_addr;
  unsigned char *remote_port;

  unsigned char *local_addr;
  unsigned char *local_port;

  /* Tunnel send window state. */

  SshUInt32 send_window_size;
  SshUInt32 cwnd;
  SshUInt32 sstresh;
  SshUInt32 retransmit_timer;

  /* Tunnel attributes. */
  SshL2tpTunnelAttributesStruct attributes;

  /* Reason for tunnel termination. */

  SshL2tpTunnelResultCode result_code;
  SshL2tpErrorCode error_code;

  unsigned char *error_message;
  size_t error_message_len;

  /* Pointer to upper-level data.  The L2TP library does not touch,
     modify, or free this field.  The upper-level code (the user of
     this libary) can store here its application data.  The data will
     remain valid until the tunnel's status callback is called with
     the status code `SSH_L2TP_TUNNEL_TERMINATED'.  After that status
     notification the user has no way to retrieve this data. */
  void *upper_level_data;

  /* Statistics. */
  /* TODO: tunnel statistics */
};

typedef struct SshL2tpTunnelInfoRec SshL2tpTunnelInfoStruct;
typedef struct SshL2tpTunnelInfoRec *SshL2tpTunnelInfo;

/* A callback function of this type is called to accept or reject a
   new L2TP tunnel establishment.

   The argument `shared_secret' specifies the shared secret between
   this LAC-LNS pair.  The argument `shared_secret_len' specifies the
   length of the shared secret.  If the argument `shared_secret' has
   the value NULL, this LAC-LNS pair does not have a shared secret.
   If the shared secret is specified, it is used to authenticate the
   remote L2TP peer and it is also used for hiding and unhiding AVP
   values.  The shared secret might be needed for both accepted and
   rejected tunnels since the initiator's first message can contain
   hided attribute values.

   If the argument `accept' is TRUE, the tunnel is accepted and the
   tunnel establishment is continued.  If the argument `local_port' is
   not NULL, it specifies new local port to be used for this tunnel.
   The L2TP server will create a new UPD listener (if one is not
   already running on the new port) and it uses it for this tunnel.

   If the argument `accept' is FALSE, the tunnel is terminated.  The
   arguments `result', `error', and `error_message',
   `error_message_len' can be used to specify the status code for the
   tunnel termination.  If the status and error codes are not
   specified, the tunnel is rejected for the
   SSH_L2TP_TUNNEL_RESULT_UNAUTHORIZED reason. */
typedef void (*SshL2tpTunnelRequestCompletionCB)(
                                        Boolean accept,
                                        const unsigned char *shared_secret,
                                        size_t shared_secret_len,
                                        const unsigned char *local_port,
                                        SshL2tpTunnelResultCode result,
                                        SshL2tpErrorCode error,
                                        const unsigned char *error_message,
                                        size_t error_message_len,
                                        void *completion_cb_context);

/* A callback function of this type is called when a new L2TP tunnel
   is initiated to this L2TP server.  The argument `info' gives public
   information about the new tunnel.  The function must call the
   callback function `completion_cb' to accept or reject the new
   tunnel request. */
typedef SshOperationHandle (*SshL2tpTunnelRequestCB)(
                                SshL2tpTunnelInfo info,
                                SshL2tpTunnelRequestCompletionCB completion_cb,
                                void *completion_cb_context,
                                void *callback_context);

/* L2TP tunnel status values. */
typedef enum
{
  /* The opening failed before the tunnel reached established state
     (you never got the SSH_L2TP_TUNNEL_OPENED for this tunnel).  No
     more callbacks will be called for this tunnel. */
  SSH_L2TP_TUNNEL_OPEN_FAILED,

  /* The tunnel is opened and ready to establish sessions. */
  SSH_L2TP_TUNNEL_OPENED,

  /* The tunnel is terminated.  No more callbacks will be called for
     this tunnel or for any of its sessions.  All sessions have
     already been terminated by calling their status function with
     SSH_L2TP_SESSION_TERMINATED value. */
  SSH_L2TP_TUNNEL_TERMINATED
} SshL2tpTunnelStatus;

/* A callback function of this type is called to notify about status
   changes of L2TP tunnels.  This is called both for initiator and
   responder tunnels. */
typedef void (*SshL2tpTunnelStatusCB)(SshL2tpTunnelInfo info,
                                      SshL2tpTunnelStatus status,
                                      void *callback_context);


/**************************** Session management ****************************/

/* A callback function of this type is called to indicate a new data
   message that arrived from the L2TP session `session'. */
typedef void (*SshL2tpSessionDataCB)(SshL2tpSessionInfo session,
                                     const unsigned char *data,
                                     size_t data_len);

/* Proxy Authen Type AVP values. */
typedef enum
{
  SSH_L2TP_PROXY_AUTHEN_RESERVED0               = 0,

  SSH_L2TP_PROXY_AUTHEN_USERNAME_PASSWORD       = 1,
  SSH_L2TP_PROXY_AUTHEN_PPP_CHAP                = 2,
  SSH_L2TP_PROXY_AUTHEN_PPP_PAP                 = 3,
  SSH_L2TP_PROXY_AUTHEN_NO_AUTHENTICATION       = 4,
  SSH_L2TP_PROXY_AUTHEN_MSCHAPV1                = 5,

  SSH_L2TP_PROXY_AUTHEN_NUM_TYPES
} SshL2tpProxyAuthenType;

/* Mapping from Proxy Authen types to their names. */
extern const SshKeywordStruct ssh_l2tp_proxy_authen_types[];


/* Session attributes. */
struct SshL2tpSessionAttributesRec
{
  /* Attributes for incoming and outgoing calls.  The comments in the
     right column describe the following:

       - Automatic      this value is automatically set for ICRQ and OCRQ
       - IC             this value is valid for incoming calls
       - OC             this value is valid for outgoing calls

     As a responder, the fields describe the attributes received or
     negotiated during the session establishment.  The `IC' and `OC'
     comments describe which values are valid.

     As an initiator, the `IC' and `OC' fields describe which
     information you must give for the library.  The fields marked
     with the `*' character are optional.  You do not have to specify
     a value for those. */

  SshUInt32 call_serial_number;                 /* Automatic    IC      OC  */
  SshUInt32 minimum_bps;                        /*                      OC  */
  SshUInt32 maximum_bps;                        /*                      OC  */
  SshUInt32 bearer_type;                        /*              IC*     OC  */
  SshUInt32 framing_type;                       /*              IC      OC  */

  unsigned char *called_number;                 /*              IC*     OC  */
  size_t called_number_len;

  unsigned char *calling_number;                /*              IC*         */
  size_t calling_number_len;

  unsigned char *sub_address;                   /*              IC*     OC* */
  size_t sub_address_len;

  SshUInt32 tx_connect_speed;                   /*              IC      OC  */
  SshUInt32 rx_connect_speed;                   /*              IC*     OC* */
  SshUInt32 physical_channel_id;                /*              IC*     OC* */

  unsigned char *private_group_id;              /*              IC*         */
  size_t private_group_id_len;

  Boolean sequencing_required;                  /*              IC*     OC* */

  unsigned char *initial_rcvd_lcp_confreq;      /*              IC*         */
  size_t initial_rcvd_lcp_confreq_len;

  unsigned char *last_sent_lcp_confreq;         /*              IC*         */
  size_t last_sent_lcp_confreq_len;

  unsigned char *last_rcvd_lcp_confreq;         /*              IC*         */
  size_t last_rcvd_lcp_confreq_len;

  SshL2tpProxyAuthenType proxy_authen_type;     /*              IC*         */

  unsigned char *proxy_authen_name;             /*              IC*         */
  size_t proxy_authen_name_len;

  unsigned char *proxy_authen_challenge;        /*              IC*         */
  size_t proxy_authen_challenge_len;

  SshUInt16 proxy_authen_id;                    /*              IC*         */

  unsigned char *proxy_authen_response;         /*              IC*         */
  size_t proxy_authen_response_len;
};

typedef struct SshL2tpSessionAttributesRec SshL2tpSessionAttributesStruct;
typedef struct SshL2tpSessionAttributesRec *SshL2tpSessionAttributes;


/* Call errors. */
struct SshL2tpCallErrorsRec
{
  SshUInt32 crc_errors;
  SshUInt32 framing_errors;
  SshUInt32 hardware_overruns;
  SshUInt32 buffer_overruns;
  SshUInt32 time_out_errors;
  SshUInt32 alignment_errors;
};

typedef struct SshL2tpCallErrorsRec SshL2tpCallErrorsStruct;
typedef struct SshL2tpCallErrorsRec *SshL2tpCallErrors;


/* ACCM (Asynchronous Control Character Map). */
struct SshL2tpAccmRec
{
  SshUInt32 send_accm;
  SshUInt32 receive_accm;
};

typedef struct SshL2tpAccmRec SshL2tpAccmStruct;
typedef struct SshL2tpAccmRec *SshL2tpAccm;


/* Public information about an L2TP session. */
struct SshL2tpSessionInfoRec
{
  /* The L2TP tunnel to which this session belongs. */
  SshL2tpTunnelInfo tunnel;

  /* The session ID allocated by this peer for this session. */
  SshL2tpSessionID local_id;

  /* The session ID allocated by the remote peer for this session. */
  SshL2tpSessionID remote_id;

  /* Flags for the session. */

  /* Is this end the LAC for this session.  If unset, this end is
     the LNS. */
  unsigned int lac : 1;

  /* Did this end initiate this session. */
  unsigned int initiator : 1;

  /* A callback function that is called when new data frames arrive
     from this tunnel.  The upper-level code (the user of this
     library) can set the callback funtion here.  If the callback
     function is not set, the data frames are silently dropped. */
  SshL2tpSessionDataCB data_cb;

  /* Session attributes. */
  SshL2tpSessionAttributesStruct attributes;

  /* Call errors, reported by LAC to LNS.  This is set if this end is
     the LNS and LAC has reported call errors. */
  SshL2tpCallErrors call_errors;

  /* The ACCM for LAC. */
  SshL2tpAccmStruct accm;

  /* Reason for session termination. */

  SshL2tpSessionResultCode result_code;
  SshL2tpErrorCode error_code;

  unsigned char *error_message;
  size_t error_message_len;

  SshUInt16 q931_cause_code;
  SshUInt8 q931_cause_msg;
  unsigned char *q931_advisory_message;
  size_t q931_advisory_message_len;

  /* Pointer to upper-level data.  The L2TP library does not touch,
     modify, or free this field.  The upper-level code (the user of
     this libary) can store here its application data.  The data will
     remain valid until the session's status callback is called with
     the status code `SSH_L2TP_SESSION_TERMINATED' or
     `SSH_L2TP_SESSION_OPEN_FAILED'.  After that status notification
     the user has no way to retrieve this data. */
  void *upper_level_data;

  /* Statistics. */
  /* TODO: session statistics */
};

typedef struct SshL2tpSessionInfoRec SshL2tpSessionInfoStruct;

/* A callback function of this type is called to accept or reject a
   new L2TP session establishment.

   If the argument `accept' is TRUE, the session is accepted and the
   session establishment is continued.

   If the argument `accept' is FALSE, the session is terminated.  The
   arguments `result', `error', and `error_message',
   `error_message_len' can be used to specify the status code for the
   session termination.  If the status and error codes are not
   specified, the session is rejected for the
   SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE reason. */
typedef void (*SshL2tpSessionRequestCompletionCB)(
                                        Boolean accept,
                                        SshL2tpSessionResultCode result,
                                        SshL2tpErrorCode error,
                                        const unsigned char *error_message,
                                        size_t error_message_len,
                                        void *copletion_cb_context);

/* A callback function of this type is called when a new L2TP session
   is initiated to this L2TP server.  The argument `info' gives public
   information about the new session.  The function must call the
   callback function `completion_cb' to accept or reject the new
   tunnel request. */
typedef SshOperationHandle (*SshL2tpSessionRequestCB)(
                        SshL2tpSessionInfo info,
                        SshL2tpSessionRequestCompletionCB completion_cb,
                        void *completion_cb_context,
                        void *callback_context);

/* L2TP session status values. */
typedef enum
{
  /* The session opening failed.  No more callbacks will be called for
     this session. */
  SSH_L2TP_SESSION_OPEN_FAILED,

  /* The session is opened and ready transmit data. */
  SSH_L2TP_SESSION_OPENED,

  /* The session is terminated.  No more callbacks will be called for
     this session. */
  SSH_L2TP_SESSION_TERMINATED,

  /* This session received a WAN Error Notify message.  The error
     counters are pointed by the session info structure's
     `call_errors' field. */
  SSH_L2TP_SESSION_WAN_ERROR_NOTIFY,

  /* The session received a Set Link Info message.  The link ACCM is
     at the session info structure's `accm' field. */
  SSH_L2TP_SESSION_SET_LINK_INFO
} SshL2tpSessionStatus;

/* A callback function of this type is called to notify about the
   status changes of L2TP sessions.  This is called both for initiator
   and responder sessions. */
typedef void (*SshL2tpSessionStatusCB)(SshL2tpSessionInfo info,
                                       SshL2tpSessionStatus status,
                                       void *callback_context);

/* Result status of an LAC outgoing call operation. */
struct SshL2tpLacOutgoingCallStatusRec
{
  /* Error reporting. */
  SshL2tpSessionResultCode result_code;
  SshL2tpErrorCode error_code;
  unsigned char *error_message;
  size_t error_message_len;

  /* Q.931 Cause Code. */
  SshUInt16 q931_cause_code;
  SshUInt8 q931_cause_msg;
  unsigned char *q931_advisory_message;
  size_t q931_advisory_message_len;

  /* Parameters of a successful operation. */

  /* Mandatory values. */
  SshUInt32 tx_connect_speed;
  SshUInt32 framing_type;

  /* Optional values. */
  SshUInt32 rx_connect_speed;
  Boolean sequencing_required;
};

typedef struct
SshL2tpLacOutgoingCallStatusRec SshL2tpLacOutgoingCallStatusStruct;
typedef struct SshL2tpLacOutgoingCallStatusRec *SshL2tpLacOutgoingCallStatus;

/* A callback function of this type is called to report success of
   placing an outgoing call from LAC.  The argument `success'
   describes whether the outoing calls was established or not.  If the
   operation was successful, the argument `status' gives the
   properties of the call.  If the outgoing call failed, the argument
   `status' gives the status and error code of the failed
   operation. */
typedef void (*SshL2tpLacOutgoingCallCompletionCB)(
                                        Boolean success,
                                        SshL2tpLacOutgoingCallStatus status,
                                        void *completion_cb_context);

/* A callback function of this type is called to start an outgoing
   call from LAC.  The function must call the completion function
   `completion_cb' with appropriate arguments to notify about the
   success of placing the call. */
typedef SshOperationHandle (*SshL2tpLacOutgoingCallCB)(
                        SshL2tpSessionInfo info,
                        SshL2tpLacOutgoingCallCompletionCB completion_cb,
                        void *completion_cb_context,
                        void *callback_context);


/******************* Creating and destroying L2TP servers *******************/

/* An L2TP context. */
typedef struct SshL2tpRec *SshL2tp;

/* An L2TP server handle. */
typedef struct SshL2tpServerRec *SshL2tpServer;

#define SSH_L2TP_FRAMING_SYNCHRONOUS    0x00000001
#define SSH_L2TP_FRAMING_ASYNCHRONOUS   0x00000002

#define SSH_L2TP_BEARER_DIGITAL         0x00000001
#define SSH_L2TP_BEARER_ANALOG          0x00000002

/* An infinite Hello keepalive timer interval. */
#define SSH_L2TP_HELLO_TIMER_INFINITE   0xffffffff

/* Parameters for L2TP server.  An L2TP server can be an LAC, LNS, or
   it can be them both. */
struct SshL2tpParamsRec
{
  /* The maximum number of L2TP tunnels (control connections) allowed.
     The default value is unlimited. */
  SshUInt32 max_tunnels;

  /* Our receive window size.  This limits how many concurrent packets
     the server processes.  The default value is 16. */
  SshUInt32 receive_window_size;

  /* The maximum send window size we use for a tunnel.  This is used
     to limit the other end's receive window size that is notified in
     Receive Window Size AVP.  The default value is 32. */
  SshUInt32 max_send_window_size;

  /* The maximum retransmit timer value in seconds.  The default value
     is 30. */
  SshUInt32 max_retransmit_timer;

  /* The keepalive timer in seconds.  If the server does not receive
     any messages in this amout of time, it will send a Hello message
     to the tunnel's remote peer. The default value is 60.  If the
     value is set to SSH_L2TP_HELLO_TIMER_INFINITE, the Hello messages
     are not sent. */
  SshUInt32 hello_timer;

  /* The maximum allowed tunnel outage.  If we can not send any data
     with the tunnel during this time (seconds), the tunnel will be
     destroyed due to lost of connection to its peer.  The default
     values is 120. */
  SshUInt32 max_tunnel_outage;

  /* The of length of the challenge in the CHAP-style L2TP tunnel
     authentication.  The default is 32 bytes. */
  size_t challenge_len;

  /* Do not hide AVPs even if the shared secret between LAC and LNS is
     known.  As a default, all hidable AVPs are hidden if the secret
     is known. */
  Boolean dont_hide;

  /* Use a separate random vector for each hidden AVP.  As a default,
     only one random vector is included in each message. */
  Boolean separate_random_vectors;

  /* The length of the random vector.  The default value is 32
     bytes. */
  size_t random_vector_len;

  /* Properties. */

  /* Framing capabilities.  The default value is
     SSH_L2TP_FRAMING_SYNCHRONOUS. */
  SshUInt32 framing_capabilities;

  /* Bearer capabilities.  The default value is 0 meaning that this
     node can act as LAC but it does not have any physical
     connection to place the calls. */
  SshUInt32 bearer_capabilities;

  /* The name of this host. */
  unsigned char *hostname;
  size_t hostname_len;

  /* UDP methods */
  SshUdpListenerParamsStruct udp_params;
};

typedef struct SshL2tpParamsRec SshL2tpParamsStruct;
typedef struct SshL2tpParamsRec *SshL2tpParams;

/* Create an L2TP context with the configuration parameters `params'.
   If the argument `params' is NULL or any of its fields have the
   value 0, the default values will be used instead.

   The argument `tunnel_request_cb' specifies a callback function that
   is called when a new L2TP tunnel establishment negotiation is
   initiated to this server (this peer is the responder for the
   establishment).  The callback function can decide whether the
   tunnel is accepted or not.  If the argument `tunnel_request_cb' has
   the value NULL, the server automatically accepts new tunnels.

   The argument `tunnel_status_cb' specifies a callback function that
   is called to give status information about L2TP tunnels.

   The argument `session_request_cb' specifies a callback function
   that is called when a new L2TP session (incoming or outgoing call)
   is initiated to this server (this peer is the responder).  The
   callback function can deside whether the new session is accepted or
   not.  If the argument `session_request_cb' has the value NULL, the
   server automatically accepts new sessions.

   The argument `session_status_cb' specifies a callback function that
   is called to give status information about L2TP sessions.  It is
   called for those sessions for which this peer is the responder.

   The argument `lac_outgoing_call_cb' specifies a callback function
   that is called when this peer acts as an LAC and the LNS wants to
   make an outgoing call.  If the argument `lac_outgoing_call_cb' is
   NULL, the server make a virtual call (the LAC and PPP stack are
   located in the same machine) and returns default values for LNS.

   The argument `callback_context' is passes as context data for all
   the above callback functions.

   The function returns an L2TP handle if the creation was successfull
   or NULL otherwise. */
SshL2tp ssh_l2tp_create(SshL2tpParams params,
                        SshL2tpTunnelRequestCB tunnel_request_cb,
                        SshL2tpTunnelStatusCB tunnel_status_cb,
                        SshL2tpSessionRequestCB session_request_cb,
                        SshL2tpSessionStatusCB session_status_cb,
                        SshL2tpLacOutgoingCallCB lac_outgoing_call_cb,
                        void *callback_context);

/* Start an L2TP server to the L2TP context `l2tp'.  The argument
   `address' specifies the local IP address to bind to.  The default
   value for the address is SSH_IPADDR_ANY.  The argument `port'
   specifies the local UDP port to use.  The default value for the
   port is 1701. The argument `interface_index' speficies the
   interface index to use or -1 if it is not used. The argument
   `routing_instance_id' speficies the routing instance id to use. */
SshL2tpServer ssh_l2tp_server_start(SshL2tp l2tp,
                                    const unsigned char *address,
                                    const unsigned char *port,
                                    int interface_index,
                                    int routing_instance_id);

/* Start an L2TP server to the L2TP context `l2tp'.  The argument
   `address' specifies the local IP address to bind to.  The argument
   `port' specifies the local UDP port to use. The argument
   `interface_index' speficies the interface index to use or -1 if
   it is not used. The argument `routing_instance_id' speficies the
   routing instance id to use. */
SshL2tpServer ssh_l2tp_server_start_ip(SshL2tp l2tp,
                                       SshIpAddr address,
                                       SshUInt16 port,
                                       int interface_index,
                                       int routing_instance_id);

/* Stop the L2TP server `server'.  The L2TP servers do not have to be
   stopped manually.  When the L2TP context is destroyed with the
   ssh_l2tp_shutdown or ssh_l2tp_destroy functions, they will
   automatically stop all active servers. */
void ssh_l2tp_server_stop(SshL2tpServer server);

/* A callback function of this type is called when the L2TP server has
   been destroyed or shut down. */
typedef void (*SshL2tpFinishedCB)(void *context);

/* Shutdown the L2TP server `l2tp'.  The function will close all
   sessions and send appropriate notifications to their remote peers.
   When the tunnels have been closed, it will close the L2TP server
   `l2tp' and free all resources it has allocated.  You must not call
   any functions for the L2TP server `l2tp' after this call.  The
   function will call the callback function `callback' when the
   shutdown operation is complete. */
void ssh_l2tp_shutdown(SshL2tp l2tp, SshL2tpFinishedCB callback,
                       void *context);

/* Destroy the L2TP server `l2tp'.  This will tear down all tunnels
   without sending any notifications and free all allocated resources.
   The function closes the L2TP server `l2tp' and free all resources
   it has allocated.  You must not call any functions for the L2TP
   server `l2tp' after this call.  The function will call the callback
   function `callback' when the destroy operation is complete. */
void ssh_l2tp_destroy(SshL2tp l2tp, SshL2tpFinishedCB callback, void *context);


/***************************** Tunnel handling ******************************/

/* Close the L2TP tunnel `local_id'.  This terminates the tunnel
   without closing each session individually.  The function will close
   the tunnel `tunnel_id' and send notification `result', `error', and
   `error_message' to its peer.  The L2TP server `l2tp' will call the
   appropriate status callbacks of each session and tunnel before they
   are freed.

   The arguments `error_message', and `error_message_len' are optional
   and can have the value NULL or 0. */
void ssh_l2tp_tunnel_close(SshL2tp l2tp, SshL2tpTunnelID tunnel_id,
                           SshL2tpTunnelResultCode result,
                           SshL2tpErrorCode error,
                           const unsigned char *error_message,
                           size_t error_message_len);

/* Destroy the L2TP tunnel `local_id'.  This terminates the tunnel
   without closing each session individually.  The function will not
   send any close notifications to its remote peer.  The L2TP server
   `l2tp' will call the appropriate status callbacks of each session
   and tunnel before they are freed. */
void ssh_l2tp_tunnel_destroy(SshL2tp l2tp, SshL2tpTunnelID tunnel_id);

/* Return the L2TP server that is used with the tunnel `tunnel_id'. */
SshL2tpServer ssh_l2tp_tunnel_get_server(SshL2tp l2tp,
                                         SshL2tpTunnelID tunnel_id);

/***************************** Session handling *****************************/

/* Send the data frame `data', `data_len' using the L2TP session
   `session'. */
void ssh_l2tp_session_send(SshL2tp l2tp, SshL2tpSessionInfo session,
                           const unsigned char *data, size_t data_len);

/* Close the L2TP session, identified by the arguments `tunnel_id' and
   `session_id'.  This terminates the session and sends notification
   `result', `error', `error_message', `q931_cause_code',
   `q931_cause_msg', and `q931_advisory_message' for the session's
   remote peer.

   The arguments `result', `error', `error_message',
   `error_message_len', `q931_cause_code', `q931_cause_msg',
   `q931_advisory_message', and `q931_advisory_message_len' are
   optional and they can have the value NULL or 0.  If you do not
   specify a status code for the session termination, the session is
   terminated for SSH_L2TP_SESSION_RESULT_ADMINISTRATIVE reason. */
void ssh_l2tp_session_close(SshL2tp l2tp, SshL2tpTunnelID tunnel_id,
                            SshL2tpSessionID session_id,
                            SshL2tpSessionResultCode result,
                            SshL2tpErrorCode error,
                            const unsigned char *error_message,
                            size_t error_message_len,
                            SshUInt16 q931_cause_code,
                            SshUInt8 q931_cause_msg,
                            const unsigned char *q931_advisory_message,
                            size_t q931_advisory_message_len);

/* Destroy the L2TP session, identified by the arguments `tunnel_id'
   and `session_id'.  This terminates the session without sending any
   notifications for the session's remote peer. */
void ssh_l2tp_session_destroy(SshL2tp l2tp, SshL2tpTunnelID tunnel_id,
                              SshL2tpSessionID session_id);


/**************************** LAC functionality *****************************/

/* Open a new L2TP session for L2TP server `l2tp'.  If the argument
   `tunnel_id' is not zero, the function uses the existing tunnel
   `tunnel_id' for this session.  If the tunnel `tunnel_id' does not
   exist, or the argument `tunnel_id' is zero, the function creates a
   new L2TP tunnel to the L2TP server running at host `remote_addr' on
   port `remote_port' using the local L2TP server `server'.  The
   arguments `shared_secret', `shared_secret_len' specify the shared
   secret between this host (LAC) and the remote hos (LNS).  The
   argument `attributes' specifies attributes for this LAC incoming
   call.  If the argument `attributes' is NULL, default values will be
   used for the session.  The function calls the `status_cb' function
   to notify about the success of the operation. */
SshOperationHandle ssh_l2tp_lac_session_open(
                                        SshL2tp l2tp,
                                        SshL2tpServer server,
                                        SshL2tpTunnelID tunnel_id,
                                        const unsigned char *remote_addr,
                                        const unsigned char *remote_port,
                                        const unsigned char *shared_secret,
                                        size_t shared_secret_len,
                                        SshL2tpSessionAttributes attributes,
                                        SshL2tpSessionStatusCB status_cb,
                                        void *callback_context);

/* Send a WAN error notify message to the LNS.  The reported error
   counters are cumulative.  This error notify should be send when new
   errors are encountered. */
void ssh_l2tp_lac_wan_error_notify(SshL2tp l2tp,
                                   SshL2tpTunnelID tunnel_id,
                                   SshL2tpSessionID session_id,
                                   SshL2tpCallErrors call_errors);


/**************************** LNS functionality *****************************/

/* Open a new L2TP session for L2TP server `l2tp'.  If the argument
   `tunnel_id' is not zero, the function uses the existing tunnel
   `tunnel_id' for this session.  If the tunnel `tunnel_id' does not
   exist, or the argument `tunnel_id' is zero, the function creates a
   new L2TP tunnel to the L2TP server running at host `remote_addr' on
   port `remote_port' using the L2TP server `server'.  The arguments
   `shared_secret', `shared_secret_len' specify the shared secret
   between this host (LAC) and the remote hos (LNS).  The argument
   `attributes' specifies attributes for this LNS outgoing call.  If
   the argument `attributes' is NULL, default values will be used for
   the session.  The function calls the `status_cb' function to notify
   about the success of the operation. */
SshOperationHandle ssh_l2tp_lns_session_open(
                                        SshL2tp l2tp,
                                        SshL2tpServer server,
                                        SshL2tpTunnelID tunnel_id,
                                        const unsigned char *remote_addr,
                                        const unsigned char *remote_port,
                                        const unsigned char *shared_secret,
                                        size_t shared_secret_len,
                                        SshL2tpSessionAttributes attributes,
                                        SshL2tpSessionStatusCB status_cb,
                                        void *callback_context);

/* Send an ACCM message to the LAC. */
void ssh_l2tp_lns_set_link_info(SshL2tp l2tp,
                                SshL2tpTunnelID tunnel_id,
                                SshL2tpSessionID session_id,
                                SshL2tpAccm accm);

#endif /* not SSHL2TP_H */
