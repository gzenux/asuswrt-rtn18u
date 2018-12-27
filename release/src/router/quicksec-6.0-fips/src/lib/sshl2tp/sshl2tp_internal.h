/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal definitions for L2TP library.
*/

#ifndef SSHL2TP_INTERNAL_H
#define SSHL2TP_INTERNAL_H

#include "sshgetput.h"
#include "sshenum.h"
#include "sshcrypt.h"
#include "sshinet.h"
#include "sshudp.h"
#include "sshtimeouts.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_list.h"
#include "sshfsm.h"

#include "sshl2tp.h"
#include "sshl2tp_parse.h"

#include "sshl2tp_transport.h"
#include "sshl2tp_st_cc_initiator.h"
#include "sshl2tp_st_cc_responder.h"
#include "sshl2tp_st_lac_ic.h"
#include "sshl2tp_st_lac_oc.h"
#include "sshl2tp_st_lns_ic.h"
#include "sshl2tp_st_lns_oc.h"
#include "sshl2tp_st_session.h"
#include "sshl2tp_st_tunnel.h"

/* Be pedantic about message formats. */
#define SSH_L2TP_PEDANTIC 1

/************************** L2TP protocol entities **************************/

/* The supported protocol version number. */
#define SSH_L2TP_PROTOCOL_VERSION       1
#define SSH_L2TP_PROTOCOL_REVISION      0

/* Control message types. */
typedef enum
{
  /* Control Connection Management. */
  SSH_L2TP_CTRL_MSG_RESERVED0   = 0,
  SSH_L2TP_CTRL_MSG_SCCRQ       = 1,
  SSH_L2TP_CTRL_MSG_SCCRP       = 2,
  SSH_L2TP_CTRL_MSG_SCCCN       = 3,
  SSH_L2TP_CTRL_MSG_STOPCCN     = 4,
  SSH_L2TP_CTRL_MSG_RESERVED5   = 5,
  SSH_L2TP_CTRL_MSG_HELLO       = 6,

  /* Call Management. */
  SSH_L2TP_CTRL_MSG_OCRQ        = 7,
  SSH_L2TP_CTRL_MSG_OCRP        = 8,
  SSH_L2TP_CTRL_MSG_OCCN        = 9,
  SSH_L2TP_CTRL_MSG_ICRQ        = 10,
  SSH_L2TP_CTRL_MSG_ICRP        = 11,
  SSH_L2TP_CTRL_MSG_ICCN        = 12,
  SSH_L2TP_CTRL_MSG_RESERVED13  = 13,
  SSH_L2TP_CTRL_MSG_CDN         = 14,

  /* Error Reporting. */
  SSH_L2TP_CTRL_MSG_WEN         = 15,

  /* PPP Session Control. */
  SSH_L2TP_CTRL_MSG_SLI         = 16,

  SSH_L2TP_CTRL_MSG_NUM_MESSAGES,

  /* Used to create Zero-Length Body (ZLB) message. */
  SSH_L2TP_CTRL_MSG_ZLB         = -1
} SshL2tpControlMsgType;

/* Mapping from control messages types to their names. */
extern const SshKeywordStruct ssh_l2tp_control_msg_types[];


/* AVP (Attribute Value Pair) types. */
typedef enum
{
  SSH_L2TP_AVP_MESSAGE_TYPE                     = 0,
  SSH_L2TP_AVP_RESULT_CODE                      = 1,
  SSH_L2TP_AVP_PROTOCOL_VERSION                 = 2,
  SSH_L2TP_AVP_FRAMING_CAPABILITIES             = 3,
  SSH_L2TP_AVP_BEARER_CAPABILITIES              = 4,
  SSH_L2TP_AVP_TIE_BREAKER                      = 5,
  SSH_L2TP_AVP_FIRMWARE_REVISION                = 6,
  SSH_L2TP_AVP_HOST_NAME                        = 7,
  SSH_L2TP_AVP_VENDOR_NAME                      = 8,
  SSH_L2TP_AVP_ASSIGNED_TUNNEL_ID               = 9,
  SSH_L2TP_AVP_RECEIVE_WINDOW_SIZE              = 10,
  SSH_L2TP_AVP_CHALLENGE                        = 11,
  SSH_L2TP_AVP_Q931_CAUSE_CODE                  = 12,
  SSH_L2TP_AVP_CHALLENGE_RESPONSE               = 13,
  SSH_L2TP_AVP_ASSIGNED_SESSION_ID              = 14,
  SSH_L2TP_AVP_CALL_SERIAL_NUMBER               = 15,
  SSH_L2TP_AVP_MINIMUM_BPS                      = 16,
  SSH_L2TP_AVP_MAXIMUM_BPS                      = 17,
  SSH_L2TP_AVP_BEARER_TYPE                      = 18,
  SSH_L2TP_AVP_FRAMING_TYPE                     = 19,

  SSH_L2TP_AVP_UNSPECIFIED20                    = 20,

  SSH_L2TP_AVP_CALLED_NUMBER                    = 21,
  SSH_L2TP_AVP_CALLING_NUMBER                   = 22,
  SSH_L2TP_AVP_SUB_ADDRESS                      = 23,
  SSH_L2TP_AVP_CONNECT_SPEED                    = 24, /* (TX) */
  SSH_L2TP_AVP_PHYSICAL_CHANNEL_ID              = 25,
  SSH_L2TP_AVP_INITIAL_RECEIVED_LCP_CONFREQ     = 26,
  SSH_L2TP_AVP_LAST_SENT_LCP_CONFREQ            = 27,
  SSH_L2TP_AVP_LAST_RESEIVED_LCP_CONFREQ        = 28,
  SSH_L2TP_AVP_PROXY_AUTHEN_TYPE                = 29,
  SSH_L2TP_AVP_PROXY_AUTHEN_NAME                = 30,
  SSH_L2TP_AVP_PROXY_AUTHEN_CHALLENGE           = 31,
  SSH_L2TP_AVP_PROXY_AUTHEN_ID                  = 32,
  SSH_L2TP_AVP_PROXY_AUTHEN_RESPONSE            = 33,
  SSH_L2TP_AVP_CALL_ERRORS                      = 34,
  SSH_L2TP_AVP_ACCM                             = 35,
  SSH_L2TP_AVP_RANDOM_VECTOR                    = 36,
  SSH_L2TP_AVP_PRIVATE_GROUP_ID                 = 37,
  SSH_L2TP_AVP_RX_CONNECT_SPEED                 = 38,
  SSH_L2TP_AVP_SEQUENCING_REQUIRED              = 39,

  SSH_L2TP_AVP_NUM_TYPES,

  /* Used in encoding messages to indicate the end of AVPs. */
  SSH_L2TP_AVP_END = -1
} SshL2tpAvpType;

/* Mapping from AVP types to their names. */
extern const SshKeywordStruct ssh_l2tp_avp_types[];

/* Mapping from SSH AVP types to their names. */
extern const SshKeywordStruct ssh_l2tp_ssh_avp_types[];


/************************** Types and definitions ***************************/

/* The default receive window size for remote end if it did not send
   Receive Window Size AVP. */
#define SSH_L2TP_DEFAULT_RECEIVE_WINDOW_SIZE            4

/* The default Tx Connect Speed. */
#define SSH_L2TP_DEFAULT_TX_CONNECT_SPEED               10000000

/* The recommended value to wait before terminating tunnel.  This is
   the minimum value we will accept. */
#ifdef SSHDIST_VPNCLIENT
#define SSH_L2TP_RECOMMENDED_RETRANSMISSION_CYCLE       1
#else /* SSHDIST_VPNCLIENT */
#define SSH_L2TP_RECOMMENDED_RETRANSMISSION_CYCLE       31
#endif /* SSHDIST_VPNCLIENT */

/* Set result code to the L2TP server `l2tp'. */
#define SSH_L2TP_SET_STATUS(l2tp, result, error, message, message_len)  \
  ssh_l2tp_set_status((l2tp), (result), (error), (message), (message_len))

/* Clear the status code from the L2TP server `l2tp'. */
#define SSH_L2TP_CLEAR_STATUS(l2tp)     \
  ssh_l2tp_set_status((l2tp), 0, 0, NULL, 0)

/* Copy result code, error code and error message from `source' to
   `target'. */
#define SSH_L2TP_COPY_STATUS(target, source)                            \
do                                                                      \
  {                                                                     \
    (target)->result_code = (source)->result_code;                      \
    (target)->error_code = (source)->error_code;                        \
    if ((source)->error_message)                                        \
      {                                                                 \
        ssh_free((target)->error_message);                              \
        (target)->error_message_len = 0;                                \
                                                                        \
        /* Copy the error message but if the operation fails, just      \
           ignore the message part. */                                  \
        (target)->error_message                                         \
          = ssh_memdup((source)->error_message,                         \
                       (source)->error_message_len);                    \
        if ((target)->error_message)                                    \
          (target)->error_message_len = (source)->error_message_len;    \
      }                                                                 \
    else                                                                \
      {                                                                 \
        ssh_free((target)->error_message);                              \
        (target)->error_message = NULL;                                 \
        (target)->error_message_len = 0;                                \
      }                                                                 \
  }                                                                     \
while (0)

#define SSH_L2TP_COPY_Q931_STATUS(target, source)                       \
do                                                                      \
  {                                                                     \
    (target)->q931_cause_code = (source)->q931_cause_code;              \
    (target)->q931_cause_msg = (source)->q931_cause_msg;                \
    if ((source)->q931_advisory_message)                                \
      {                                                                 \
        ssh_free((target)->q931_advisory_message);                      \
        (target)->q931_advisory_message_len = 0;                        \
                                                                        \
        /* Copy the advisory message but if the operation failes, just  \
           ignore the message part. */                                  \
        (target)->q931_advisory_message                                 \
          = ssh_memdup((source)->q931_advisory_message,                 \
                       (source)->q931_advisory_message_len);            \
        if ((target)->q931_advisory_message)                            \
          (target)->q931_advisory_message_len                           \
            = (source)->q931_advisory_message_len;                      \
      }                                                                 \
  }                                                                     \
while (0)

/* Check whether sequence number `seq' is less than the current
   sequence number `current'. */
#define SSH_L2TP_SEQ_LT(seq, current)   \
(((seq) < (current))                    \
 ? (current) - (seq) <= 32767           \
 : (seq) - (current) > 32768)

/* A decoded L2TP control message. */
struct SshL2tpControlMessageRec
{
  /* For queuing messages in freelist and in tunnels and sessions. */
  struct SshL2tpControlMessageRec *next;

  /* The destination of this message. */
  SshL2tpServer server;

  /* The source of this message. */
  SshIpAddrStruct remote_addr;
  SshUInt16 remote_port;

  /* Header bits. */
  unsigned int f_type : 1;
  unsigned int f_length : 1;
  unsigned int f_sequence : 1;
  unsigned int f_offset : 1;
  unsigned int f_priority : 1;

  /* Protocol version. */
  SshUInt8 version;

  /* Tunnel ID. */
  SshUInt16 tunnel_id;

  /* Session ID. */
  SshUInt16 session_id;

  /* The sequence number of the message. */
  SshUInt16 ns;

  /* The next expected sequence number. */
  SshUInt16 nr;

  /* Number of AVPs in the message. */
  SshUInt16 avp_count;

  /* If we receive hidden AVPs in the initiator's first CCE message,
     the packet decoding saves the packet here.  Later, the FSM will
     re-enter the packet decoding with this data. */
  unsigned char *suspended_packet;
  size_t suspended_packet_len;

  /* Values parsed from the AVPs. */

  /* Type of the control message. */
  SshL2tpControlMsgType type;

  /* From the Result Code AVP. */
  int result_code;
  int error_code;
  char *error_message;
  size_t error_message_len;

  /* Buffer to hold error messages. */
  char error_message_buf[1024];

  /* From the Q.931 Cause Code. */
  SshUInt16 q931_cause_code;
  SshUInt8 q931_cause_msg;
  unsigned char *q931_advisory_message;
  size_t q931_advisory_message_len;

  /* Buffer to hold Q.931 advisory messages. */
  char q931_advisory_message_buf[1024];

  unsigned char tie_breaker[8];

  SshUInt16 assigned_tunnel_id;
  SshUInt16 receive_window_size;

  unsigned char *challenge;
  size_t challenge_len;

  unsigned char *challenge_response;
  size_t challenge_response_len;

  SshL2tpTunnelAttributesStruct tunnel_attributes;

  SshUInt16 assigned_session_id;

  SshL2tpSessionAttributesStruct session_attributes;

  /* WAN Error Notify (WEN). */
  SshL2tpCallErrorsStruct call_errors;

  /* Set Link Info (SLI). */
  SshL2tpAccmStruct accm;

  unsigned char *random_vector;
  size_t random_vector_len;
};

typedef struct SshL2tpControlMessageRec SshL2tpControlMessageStruct;
typedef struct SshL2tpControlMessageRec *SshL2tpControlMessage;

/* A queued output packet. */
struct SshL2tpPacketRec
{
  /* Link field for tunnel's send window. */
  struct SshL2tpPacketRec *next;

  /* Flags. */
  unsigned int sent : 1;

  SshUInt16 sequence_number;

  unsigned char *data;
  size_t data_len;
};

typedef struct SshL2tpPacketRec SshL2tpPacketStruct;
typedef struct SshL2tpPacketRec *SshL2tpPacket;

/* A message queue. */
struct SshL2tpMessageQueueRec
{
  SshL2tpControlMessage head;
  SshL2tpControlMessage tail;
};

typedef struct SshL2tpMessageQueueRec SshL2tpMessageQueueStruct;
typedef struct SshL2tpMessageQueueRec *SshL2tpMessageQueue;

/* A forward declaration for an L2TP session. */
typedef struct SshL2tpSessionRec *SshL2tpSession;

/* An L2TP tunnel. */
struct SshL2tpTunnelRec
{
  SshADTBagHeaderStruct adt_header_id;
  SshADTBagHeaderStruct adt_header_addr_port_id;

  /* For transport level use.  The tunnel is put to several lists when
     it is being shut down.  But it is in one list at a time. */
  SshADTListHeaderStruct list;

  /* The L2TP module to which this tunnel belongs to. */
  SshL2tp l2tp;

  /* The local L2TP UDP server of this tunnel. */
  SshL2tpServer server;

  /* The remote peer of this tunnel in handy format. */
  SshIpAddrStruct remote_addr;
  SshUInt16 remote_port;

  /* Shared secret between LAC and LNS. */
  unsigned char *shared_secret;
  size_t shared_secret_len;

  /* The challenge we sent to our remote peer. */
  unsigned char *sent_challenge;
  size_t sent_challenge_len;

  /* A challenge, received from our remote peer. */
  unsigned char *received_challenge;
  size_t received_challenge_len;

  /* FSM thread handling this tunnel. */
  SshFSMThread thread;

  /* If the thread is performing an asynchronous call, this is the
     call's operation handle. */
  SshOperationHandle operation_handle;

  /* Flags. */
  unsigned int fast_shutdown : 1;   /* Don't wait retransmission cycle */
  unsigned int established : 1;     /* Control connection established */
  unsigned int on_destroy_list : 1; /* Tunnel on TR thread's destroy list */
  unsigned int destroyed : 1;       /* Destroyed, waiting for termination */
  unsigned int terminated : 1;      /* Terminated, can be reclaimed */
  unsigned int stopccn_sent : 1;    /* Shutdown via `tunnel-clean-up'
                                        instead of `tunnel-closed' */
  unsigned int dont_hide : 1;       /* Do not hide AVPs */

  /* Protocol compatibility flags. */
  SshUInt32 compat_flags;

  /* How long time (in seconds) we have failed to send messages with
     the tunnel.  If the `outage_secs' reaches configured limit, the
     tunnel will be destroyed. */
  SshUInt32 outage_secs;

  /* Public tunnel info. */
  SshL2tpTunnelInfoStruct info;

  /* The sessions of this tunnel. */
  SshL2tpSession sessions;

  /* Sequence numbers. */

  /* This is the sequence number we expect to receive next. */
  SshUInt16 seq_nr;

  /* This is the sequence number of the next message we are going to
     send using this tunnel.  This packet is not yet in our queue
     below. */
  SshUInt16 seq_ns;

  /* Send window.  Some of its variables are in the public tunnel
     info. */

  /* The physical send window queue. */
  SshL2tpPacket send_window_head;
  SshL2tpPacket send_window_tail;

  /* ACK count in congestion avoidance. */
  SshUInt32 ack_count;

  /* Queue of incoming messages for this tunnel. */
  SshL2tpMessageQueueStruct message_queue;
  SshFSMCondition message_queue_cond;

  /* Condition variable where sessions of this tunnel synchronize with
     the thread of this tunnel.  When the tunnel is created, the
     pending sessions wait on this condition that the tunnel gets up
     (tunnel->established).  When the tunnel is destroyed, the tunnel
     thread waits on this condition that all its sessions clean up
     (tunnel->sessions is empty). */
  SshFSMCondition condition;
};

typedef struct SshL2tpTunnelRec SshL2tpTunnelStruct;
typedef struct SshL2tpTunnelRec *SshL2tpTunnel;

/* An L2TP session. */
struct SshL2tpSessionRec
{
  SshADTBagHeaderStruct adt_header;

  /* For transport level use.  The session is put on destroy list
     using this header. */
  SshADTListHeaderStruct list;

  /* The L2TP tunnel to which this session belongs to. */
  SshL2tpTunnel tunnel;

  /* Link fields for tunnel's `sessions' list. */
  SshL2tpSession sessions_next;
  SshL2tpSession sessions_prev;

  /* FSM thread handling this session. */
  SshFSMThread thread;

  /* If the thread is performing an asynchronous call, this is the
     call's operation handle. */
  SshOperationHandle operation_handle;

  /* Flags. */
  unsigned int established : 1;     /* Call established */
  unsigned int on_destroy_list : 1; /* Session on TR thread's destroy list */
  unsigned int destroyed : 1;       /* Destroyed, waiting for termination */

  /* Public session info. */
  SshL2tpSessionInfoStruct info;

  /* Completion callback for sessions for which we are the initiator
     (LAC incoming call, LNS outgoing call). */
  SshL2tpSessionStatusCB initiator_status_cb;
  void *initiator_status_cb_context;

  /* The operation handle, returned to user who initiated this session
     establishment. */
  SshOperationHandle initiator_handle;

  /* Queue of incoming messages for this session. */
  SshL2tpMessageQueueStruct message_queue;
  SshFSMCondition message_queue_cond;
};

typedef struct SshL2tpSessionRec SshL2tpSessionStruct;

/* An L2TP server handle. */
struct SshL2tpServerRec
{
  /* ADT header for listener bag.  This is used when looking up UDP
     listeners by their local address and port. */
  SshADTBagHeaderStruct adt_header_lookup;

  /* ADT header for listeners which have some incoming messages.  */
  SshADTBagHeaderStruct adt_header_incoming;

  /* Number of references to this server. */
  SshUInt32 refcount;

  /* The local identification for the listener. */
  SshIpAddrStruct address;
  SshUInt16 port;

  /* Interface index. */
  int interface_index;

  /* Routing instance id. */
  int routing_instance_id;

  /* The real UDP listener. */
  SshUdpListener listener;

  /* Pointer to the L2TP server. */
  SshL2tp l2tp;
};

typedef struct SshL2tpServerRec SshL2tpServerStruct;

/* An L2TP module handle. */
struct SshL2tpRec
{
  /* Configuration parameters. */
  SshL2tpParamsStruct params;

  /* Flags. */
  unsigned int destroyed : 1;
  unsigned int fast_shutdown : 1; /* Shutdown as fast as possible. */
  unsigned int random_vector_set : 1;

  /* FSM. */
  SshFSM fsm;

  /* Hash function, used in CHAP-like authentication and in AVP
     hiding. */
  SshHash hash;
  size_t hash_digest_length;

  /* Buffer to hold incoming datagrams.  This is just used when
     parsing the incoming packets. */
  unsigned char datagram[65535];

  /* The source of the current message in the `datagram' field.  These
     are NULL when we do not have a valid datagram.  These are not
     dynamically allocated.  When these are non-NULL, they point to
     stack variables. */
  const unsigned char *datagram_addr;
  const unsigned char *datagram_port;

  /* Decode error code and description. */
  int result_code;              /* Either for tunnel or session. */
  SshL2tpErrorCode error_code;
  unsigned char *error_message; /* Points to `error_message_buf' or is NULL. */
  size_t error_message_len;
  unsigned char error_message_buf[1024];

  /* A control message, parsed from the `datagram' buffer above. */
  SshL2tpControlMessage message;

  /* Buffer to hold the current random vector.  This is valid if the
     flag `random_vector_set' is set. */
  unsigned char random_vector[1017];

  /* A temporary buffer to hold one encoded AVP. */
  unsigned char avp_buf[1023];

  /* Valid when LAC is sending WAN Error Notify message.  The field is
     NULL otherwise. */
  SshL2tpCallErrors call_errors;

  /* Valid when LNS is sending ACCM message.  The field is NULL
     otherwise. */
  SshL2tpAccm accm;

  /* A pool containing pre-allocated messages.  In the beginning, this
     has `receive_window_size' entries. */
  SshL2tpMessageQueueStruct message_pool;
  SshFSMCondition message_pool_cond;

  /* L2TP tunnels known for this peer. The first bag is indexed by the
     local tunnel ID.  The second is indexed by the remote address,
     port, and the remote end's tunnel ID. */
  SshADTContainer tunnels_id;
  SshADTContainer tunnels_addr_port_id;

  /* L2TP sessions known by this peer.  The sessions are indexed their
     tunnel and session IDs. */
  SshADTContainer sessions;

  /* Sessions, waition for clean shutdown. */
  SshADTContainer session_close_list;

  /* Sessions, waiting for immediate destruction. */
  SshADTContainer session_destroy_list;

  /* Tunnels, waiting for clean shutdown. */
  SshADTContainer tunnel_close_list;

  /* Tunnels, waiting for immediate destruction. */
  SshADTContainer tunnel_destroy_list;

  /* Destroyed tunnels, waiting for full retransmission cycle before
     reclaiming.  These have only the reliable transmission channel
     but no threads, etc. */
  SshADTContainer tunnel_retransmission_wait_list;

  /* Destroyed tunnels, ready to be reclaimed. */
  SshADTContainer tunnel_reclaim_list;

  /* Known L2TP servers. */
  SshADTContainer servers;

  /* UDP listeners having some incoming messages. */
  SshADTContainer incoming_messages;

  /* Responder side callbacks. */
  SshL2tpTunnelRequestCB tunnel_request_cb;
  SshL2tpTunnelStatusCB tunnel_status_cb;
  SshL2tpSessionRequestCB session_request_cb;
  SshL2tpSessionStatusCB session_status_cb;
  SshL2tpLacOutgoingCallCB lac_outgoing_call_cb;
  void *callback_context;

  /* Transport thread. */
  SshFSMThread transport_thread;

  /* The next call serial number to take. */
  SshUInt32 call_serial_number;

  /* The destroy callback that is called when the destroy or shutdown
     operation is complete. */
  SshL2tpFinishedCB destroy_callback;
  void *destroy_callback_context;
};


/* Exceptions, used in inter-thread communication. */
typedef enum
{
  /* Shutdown the tunnel or the session the thread is controlling.
     The shutdown operation is a clean way to close the thread.  The
     thread sends its close notification to its remote peer before
     dying. */
  SSH_L2TP_THREAD_EXCEPTION_SHUTDOWN,

  /* Destroy the thread without sending any messages to threads remote
     peers.  The thread does not wait for any acknowledgments from its
     remote peer. */
  SSH_L2TP_THREAD_EXCEPTION_DESTROY,

  /* Clean up the tunnel or session.  The thread moves to clean-up
     state and does a normal shutdown operation and waits for
     appropriate acknowledgements from its remote peer.  The thread
     does not send any error or stop message to its remote peer.  The
     stop messages are assumed to be sent beforehand. */
  SSH_L2TP_THREAD_EXCEPTION_CLEAN_UP
} SshL2tpThreadException;

/* Mapping from thread exceptions to their names. */
extern const SshKeywordStruct ssh_l2tp_thread_exceptions[];


/******************** Encoding and decoding L2TP packets ********************/

/* Decode the L2TP packet `packet', `packet_len' which came from
   `remote_addr', `remote_port'.  The message is parsed into
   `message'.  The optional argument `tunnel' specifies the L2TP
   tunnel to which the message belongs to.  This is used in suspended
   message parsing.  The function returns TRUE if the parsed message
   `message' is valid and should be processed.  Otherwise the packet
   must be ignored.  If the packet was a data packet, the start offset
   of the payload data is returned in `data_offset_return' and the
   data length in `data_len_return'. */
Boolean ssh_l2tp_decode_packet(SshL2tp l2tp, SshL2tpControlMessage message,
                               SshL2tpTunnel tunnel,
                               unsigned char *packet, size_t packet_len,
                               const unsigned char *remote_addr,
                               const unsigned char *remote_port,
                               size_t *data_offset_return,
                               size_t *data_len_return);

/* Encode a packet for the message type `message_type'.  The
   attributes of the message are in `l2tp', `tunnel', and `session'.
   The function encodes the result packet to the buffer `datagram'
   which has `datagram_len' bytes of space.  The length of the encoded
   datagram is returned in `datagram_len_return'.  The function
   returns TRUE if the operation was successful and FALSE
   otherwise. */
Boolean ssh_l2tp_encode_packet(SshL2tp l2tp, SshL2tpTunnel tunnel,
                               SshL2tpSession session,
                               unsigned char *datagram, size_t datagram_len,
                               size_t *datagram_len_return,
                               SshL2tpControlMsgType message_type);


/************************** Tunnel authentication ***************************/

/* Compute a response for the challenge `challenge' using
   `message_type' and `secret'.  The response is stored to the buffer,
   pointed by `response_return'.  It must be long enough to hold the
   response (MD5 digest length). */
void ssh_l2tp_tunnel_authentication_compute(SshL2tp l2tp,
                                            SshL2tpControlMsgType message_type,
                                            const unsigned char *challenge,
                                            size_t challenge_len,
                                            const unsigned char *secret,
                                            size_t secret_len,
                                            unsigned char *response_return);

/* Check whether the challenge response `response' is a valid response
   for `message_type', `challenge', and `secret'.  The function
   returns a boolean success value. */
Boolean ssh_l2tp_tunnel_authenticate(SshL2tp l2tp,
                                     SshL2tpControlMsgType message_type,
                                     const unsigned char *challenge,
                                     size_t challenge_len,
                                     const unsigned char *secret,
                                     size_t secret_len,
                                     const unsigned char *response,
                                     size_t response_len);

/************************* Tunnel utility functions *************************/

/* Steal tunnel attributes from `src' to `dst'.  After this, the
   source structure `src' is cleared. */
void ssh_l2tp_tunnel_attributes_steal(SshL2tpTunnelAttributes dst,
                                      SshL2tpTunnelAttributes src);

/* Allocate an unique Tunnel ID for tunnel `tunnel'. */
void ssh_l2tp_tunnel_id_alloc(SshL2tp l2tp, SshL2tpTunnel tunnel);

/* Allocate and initialize a new L2TP tunnel using the server
   `server'. */
SshL2tpTunnel ssh_l2tp_tunnel_create(SshL2tpServer server, Boolean initiator);

/* Free the tunnel `tunnel' and all its resources.  The tunnel must
   not be used after this. */
void ssh_l2tp_tunnel_free(SshL2tpTunnel tunnel);

/* Return the local IP address of the tunnel as a string.  The
   argument `params_addr' is the address, given in the L2TP parameters
   structure.  The argument `remote_addr' is the remote peer's IP
   address. */
unsigned char *ssh_l2tp_tunnel_local_addr(SshL2tpTunnel tunnel,
                                          const unsigned char *remote_addr);


/************************ Session utility functions *************************/

/* Allocate and initialize a new L2TP session for tunnel `tunnel'. */
SshL2tpSession ssh_l2tp_session_create(SshL2tp l2tp, SshL2tpTunnel tunnel,
                                       SshL2tpControlMessage message,
                                       Boolean lac, Boolean initiator);

/* Free the session `session' and all its resources.  The session must
   not be used after this. */
void ssh_l2tp_session_free(SshL2tpSession session);


/********************** L2TP server utility functions ***********************/

/* Free the L2TP server `l2tp'. */
void ssh_l2tp_free(SshL2tp l2tp);


/******************** Control message utility functions *********************/

/* Queue the control message `message' to the message queue `queue'. */
void ssh_l2tp_message_queue(SshL2tpMessageQueue queue,
                            SshL2tpControlMessage message);

/* Get the first message from the message queue `queue'.  The message
   queue must have a message. */
SshL2tpControlMessage ssh_l2tp_message_get(SshL2tpMessageQueue queue);

/* Remove the first message from the message queue `queue' and put it
   back to the L2TP server `l2tp's message pool.  The argument
   `thread' is the thread that handled this message. */
void ssh_l2tp_message_handled(SshL2tp l2tp, SshFSMThread thread,
                              SshL2tpMessageQueue queue);

/* Return the first message from the message queue `queue'.  This does
   not remove the message from the queue.  You must call
   ssh_l2tp_message_handled() when you have handled the returned
   message. */
SshL2tpControlMessage ssh_l2tp_message(SshL2tpMessageQueue queue);

/* Free all dynamically allocate fields from the message `message'.
   This does not free the actual message structure `message'. */
void ssh_l2tp_message_fields_free(SshL2tpControlMessage message);


/***************************** Transport level ******************************/

/* Send message `message_type' to the remote peer of the tunnel
   `tunnel'.  The system encodes the message using information from
   `l2tp', `tunnel', and `session'.  The argument `session' can be
   NULL.  In that case the message will not contain any session
   specific information.  If the argument `tunnel' is NULL, then the
   `server' argument must be specified.  In this case the message does
   not have local tunnel object allocated and the message
   `message_type' is send using the server object `server' which is
   the server to which the triggering message arrived.  If the
   argument `tunnel' is specified, the value of the `server' argument
   is not used. */
void ssh_l2tp_send(SshL2tp l2tp, SshL2tpServer server,
                   SshL2tpTunnel tunnel, SshL2tpSession session,
                   SshL2tpControlMsgType message_type);

/* Send the data message `data', `data_len' to the remote peer of the
   session `session'.  The message is already formatted to the data
   buffer. */
void ssh_l2tp_send_data(SshL2tp l2tp, SshL2tpSession session,
                        const unsigned char *data, size_t data_len);

/* Send a Zero-Length Body (ZLB) message to the remote peer of the
   tunnel `tunnel'.  The ZLB message are used to acknowledge messages
   seen so far.  The ZLB is not sent if there are any pending messages
   in the send window of the tunnel `tunnel'. */
void ssh_l2tp_zlb(SshL2tp l2tp, SshL2tpTunnel tunnel);

/* The tunnel `tunnel' is now terminated and it can be reclaimed
   whenever the transport level is finished with it. */
void ssh_l2tp_tunnel_terminated(SshL2tpTunnel tunnel);

/* Destroy all tunnels from the L2TP server's retransmission wait
   list. */
void ssh_l2tp_flush_retransmission_wait_list(SshL2tp l2tp);

/***************************** Error status ******************************/

/* Set the l2tp error status. */
void ssh_l2tp_set_status(SshL2tp l2tp,
                         int result_code,
                         SshL2tpErrorCode error_code,
                         const unsigned char *message,
                         size_t message_len);

#endif /* not SSHL2TP_INTERNAL_H */
