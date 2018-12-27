/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_EAPI_H

#define SSH_EAPI_H 1

/*--------------------------------------------------------------------*/
/* EAP assigned Numbers                                               */
/*--------------------------------------------------------------------*/

/* EAP PPP packet codes */

#define SSH_EAP_CODE_REQUEST 1
#define SSH_EAP_CODE_REPLY 2
#define SSH_EAP_CODE_SUCCESS 3
#define SSH_EAP_CODE_FAILURE 4


/*--------------------------------------------------------------------*/
/* Internal functions                                                 */
/*--------------------------------------------------------------------*/

/*
  Callback "signals" which will be passed back once a message has been
  sent or a timeout has occurred.

  The EAP machine will guarantee that a message can be sent, before
  the message is freed.
*/

typedef enum {
  /* Reset protocol state and abort all operations */
  SSH_EAP_PROTOCOL_RESET = 1,

  /* Begin authentication round */
  SSH_EAP_PROTOCOL_BEGIN = 2,

  /* A message was received */
  SSH_EAP_PROTOCOL_RECV_MSG = 3,

  /* Secret is being passed back */
  SSH_EAP_PROTOCOL_RECV_TOKEN = 4,

  /* The identification this instance is sending to the
     authenticator. */
  SSH_EAP_PROTOCOL_PEER_IDENTIFICATION = 5,

  /* Receive a params struct */
  SSH_EAP_PROTOCOL_RECV_PARAMS = 6

} SshEapProtocolSignalEnum;

/* Signal an event related to a connection and/or a message */

struct SshEapProtocolRec;

typedef SshEapOpStatus (*SshEapProtocolSignalCB)(SshEapProtocolSignalEnum,
                                       struct SshEapRec *eap,
                                       struct SshEapProtocolRec *proto,
                                       SshBuffer);

typedef void* (*SshEapProtocolCreateCB)(struct SshEapProtocolRec *proto,
                                        struct SshEapRec *eap,
                                        SshUInt8 type);

typedef void (*SshEapProtocolDestroyCB)(struct SshEapProtocolRec *proto,
                                        SshUInt8 type,
                                        void *ctx);

typedef SshEapOpStatus (*SshEapProtocolKeyCB)(struct SshEapProtocolRec *proto,
                                              struct SshEapRec *eap,
                                              SshUInt8 type);

/* Flags for the SshEapProtocolImpl */

/* The protocol is only supported as pass-through authenticator*/
#define SSH_EAP_PASS_THROUGH_ONLY               0x00000001

/* The method provides mutual authentication of peers, is key-generating and
   is resistant to dictionary attacks. (reference: RFC 5998)*/
#define SSH_EAP_MUTUAL_AUTHENTICATION_SUPPORTED 0x00000002

typedef struct SshEapProtocolImplRec
{
  SshUInt8 id;
  SshUInt32 flags;
  SshEapProtocolCreateCB  create;
  SshEapProtocolDestroyCB destroy;
  SshEapProtocolSignalCB  handler;
  SshEapProtocolKeyCB     key;
} *SshEapProtocolImpl, SshEapProtocolImplStruct;

/* Connection abstraction */

#define SSH_EAP_MODE_CB 1
#define SSH_EAP_MODE_STREAM 2

typedef struct SshEapConnectionRec
{
  /* MRU for outbound frames */
  unsigned long mru;

  /* flags */
  int flags;

  /* mode */
  int mode;

  /* callbacks */
  SshEapConnectionOutputCB output_cb;

  /* context var for callbacks */
  void* ctx;

  /* Eap instance input is directed to */
  SshEap eap;
} SshEapConnectionStruct;

/* An aggregate of protocol id, implementation of a protocol
   and the associated state */

typedef struct SshEapProtocolRec
{
  /* Priority */
  SshUInt8 preference;

  /* Has this protocol been NAK'd ? */
  SshUInt8 is_nak;

  /* Pointer to a protocol specific structure containing parameters */
  void *params;

  /* Pointer to a protocol specific structure containing state */
  void *state;

  /* Block of function pointers */
  SshEapProtocolImpl impl;
} *SshEapProtocol, SshEapProtocolStruct;

/* The Eap multiplexor, message router, etc */

#define SSH_EAP_CB(eap,x)           \
do {                                \
(eap)->callback_count++;            \
x;                                  \
(eap)->callback_count--;            \
if ((eap)->callback_count == 0)     \
  ssh_eap_delayed_token(eap);       \
} while(0);

typedef struct SshEapRec
{
  /* Connection we are using */
  SshEapConnection con;

  /* Parameters we are operating under */
  SshEapConfiguration params;

  /* Callbacks stacked up */
  int callback_count;

  /* Server or client ? */
  unsigned int is_authenticator:1;
  unsigned int destroy_pending:1;
  unsigned int waiting_for_callback:1;
  unsigned int id_isrecv:1; /* Has this identifier been received in a reply?*/
  unsigned int id_isinit:1; /* Is the identifier valid? */
  unsigned int auth_timeout_active:1;
  unsigned int retransmit_timer_active:1;
  unsigned int method_done:1;
  unsigned int method_ok:1;

  /* Last id and length received */
  SshUInt8 id;
  SshUInt16 len;

  /* Last EAP code and type, which has been received */
  SshUInt8 previous_eap_code;
  SshUInt8 previous_eap_type;

  /* Delayed token type */
  SshUInt8 delayed_token_type;

  /* EAP protocols we are supporting. Note that 99.9% of
     the time, only one EAP protocol is running
     and instantiated. */
  struct SshEapProtocolRec **protocols;
  int nprotocols;

  /* Previous packet we have received or sent */
  SshBuffer prev_pkt;

  /* Retransmissions */
  int num_retransmit;

  /* callback signal */
  void *ctx;

  SshEapToken delayed_token;

  /* Key material */
  unsigned char *mppe_send_key, *mppe_recv_key;
  size_t mppe_send_keylen, mppe_recv_keylen;

  /* Derived Master Session Key. */
  unsigned char *msk;
  size_t msk_len;

  /* Derived Session Id. */
  unsigned char *session_id;
  size_t session_id_len;

  /* EAP/Radius integration state */
#ifdef SSHDIST_RADIUS
  SshEapRadiusConfiguration radius_config;

  SshUInt8 *radius_state_buf;
  unsigned long radius_state_len;

  SshUInt8 *radius_user_id_buf;
  unsigned long radius_user_id_len;

  SshUInt8 *radius_pkt;
  unsigned long radius_pkt_len;

  SshOperationHandle radius_handle;
  SshRadiusClientRequest radius_req;

  SshUInt32 radius_session_timeout;
  int radius_server_index;
#endif /* SSHDIST_RADIUS */
} SshEapStruct;

/*--------------------------------------------------------------------*/
/* Get protocol for a type                                            */
/*--------------------------------------------------------------------*/

SshEapProtocol ssh_eap_get_protocol(SshEap eap, SshUInt8 code);

void
ssh_eap_send_signal(SshEap, SshUInt8, SshEapSignal, SshBuffer);


/*--------------------------------------------------------------------*/
/* Get parameter values                                               */
/*--------------------------------------------------------------------*/

typedef enum {
  SSH_EAP_PARAM_MAX_RETRANSMIT = 1,
  SSH_EAP_PARAM_RETRANSMIT_DELAY_SEC = 2,
  SSH_EAP_PARAM_AUTH_TIMEOUT_SEC = 5
} SshEapParamId;

unsigned long
ssh_eap_config_get_ulong(SshEapConfiguration params, SshEapParamId id);

/*--------------------------------------------------------------------*/
/* Functions for protocols                                            */
/*--------------------------------------------------------------------*/

/* Send message */

SshBuffer ssh_eap_create_request(SshEap eap, SshUInt16 len, SshUInt8 type);
SshBuffer ssh_eap_create_reply(SshEap eap, SshUInt16 len, SshUInt8 type);

void* ssh_eap_protocol_get_state(SshEapProtocol proto);
void ssh_eap_protocol_set_state(SshEapProtocol proto, void*state);

void* ssh_eap_protocol_get_params(SshEapProtocol);
void ssh_eap_protocol_set_params(SshEapProtocol, void*state);

void ssh_eap_protocol_master_session_key(SshEap,
                                         const unsigned char *session_key,
                                         size_t session_key_len);

unsigned long
ssh_eap_get_token_secret_len(SshEapToken t);

SshUInt8*
ssh_eap_get_token_secret_ptr(SshEapToken t);

/* Signaling */

void ssh_eap_delayed_token(SshEap eap);

void
ssh_eap_protocol_request_token_with_args(SshEap eap,
                                         SshUInt8 eap_type,
                                         SshEapTokenType type,
                                         unsigned char *input,
                                         SshUInt16 input_len);

void ssh_eap_protocol_request_token(SshEap eap,
                                    SshUInt8 eap_type,
                                    SshEapTokenType type);

void ssh_eap_protocol_auth_ok(SshEapProtocol proto,
                              SshEap eap,
                              SshEapSignal sig,
                              SshBuffer buf);

void ssh_eap_protocol_auth_fail(SshEapProtocol proto,
                                SshEap eap,
                                SshEapSignal sig,
                                SshBuffer buf);

void ssh_eap_fatal(SshEap eap,
                   SshEapProtocol protocol,
                   char *cause_str);

void ssh_eap_async_fatal(SshEap eap,
                         char *cause_str);


void ssh_eap_discard_packet(SshEap eap,
                            SshEapProtocol protocol,
                            SshBuffer buf,
                            char *cause_str);

void ssh_eap_discard_token(SshEap eap,
                            SshEapProtocol protocol,
                            SshBuffer buf,
                            char *cause_str);


/* Send request / reply */

void
ssh_eap_protocol_send_request(SshEapProtocol protocol,
                              SshEap eap,
                              SshBuffer req);

void
ssh_eap_protocol_send_request_random_delay(SshEapProtocol protocol,
                                           SshEap eap, SshBuffer req,
                                           unsigned long max_delay_sec);

void
ssh_eap_protocol_send_response(SshEapProtocol protocol,
                               SshEap eap,
                               SshBuffer resp);

void
ssh_eap_protocol_send_response_random_delay(SshEapProtocol protocol,
                                            SshEap eap,
                                            SshBuffer resp,
                                            unsigned long max_delay_sec);

Boolean
ssh_eap_send_id_reply(SshEap eap,
                      const char *buffer,
                      unsigned long len);


/* Configuration */

unsigned long
ssh_eap_protocol_get_mru(SshEapProtocol protocol, SshEap eap);

Boolean
ssh_eap_isauthenticator(SshEap eap);

/* Misc */

void
ssh_eap_input_packet(SshEap eap, SshBuffer pkt);

void
ssh_eap_send_packet(SshEap eap, SshBuffer pkt);

void
ssh_eap_build_and_send_request(SshEap eap, SshUInt8 type,
                               const SshUInt8 *ptr,
                               unsigned long len);

void
ssh_eap_build_and_send_request_buf(SshEap eap,
                                   SshUInt8 type,
                                   const SshBuffer req);

void
ssh_eap_build_and_send_reply(SshEap eap, SshUInt8 type,
                             const SshUInt8 *ptr,
                             SshUInt16 len);

void
ssh_eap_build_and_send_reply_buf(SshEap eap,
                                 SshUInt8 type, const SshBuffer buf);

void
ssh_eap_set_resend_timeout(SshEap eap);

void
ssh_eap_cancel_resend_timeout(SshEap eap);

void
ssh_eap_auth_timeout_cb(void *ctx);

void
ssh_eap_begin_auth_timeout(SshEap eap);

void
ssh_eap_cancel_auth_timeout(SshEap eap);

void
ssh_eap_remember_packet(SshEap eap, SshBuffer buf);

void
ssh_eap_free_identification(SshEap eap);


void
ssh_eap_set_status(SshEap eap, SshEapStatus stat);

void
ssh_eap_commit_status(SshEap eap);

#ifdef SSHDIST_RADIUS

void
ssh_eap_radius_reset(SshEap eap);

void
ssh_eap_radius_init(SshEap eap);

Boolean
ssh_eap_radius_continue(SshEap eap, Boolean free_pkt);

void
ssh_eap_radius_input_reply(SshEap eap, SshBuffer buf);

Boolean
ssh_eap_radius_send_start(SshEap eap, SshEapToken token);

void
ssh_eap_radius_input_identity_reply(SshEap eap,
                                    SshBuffer buf,
                                    Boolean signal_sent);
#endif /* SSHDIST_RADIUS */

#endif /* not SSH_EAPI_H */
