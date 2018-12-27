/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_PPP_PROTOCOL_H

#define SSH_PPP_PROTOCOL_H 1

/* Protocol state */

#define SSH_PPP_LCP_UP 1
#define SSH_PPP_LCP_STARTED 2
#define SSH_PPP_LCP_DOWN 3
#define SSH_PPP_LCP_FAILED 4
#define SSH_PPP_LCP_INITIAL 5
#define SSH_PPP_LCP_HALT 6

typedef SshUInt8 SshPppProtocolStatus;

/* Protocols for handling */

#define SSH_PPP_PROTOCOL_FLAG_VENDOR_EXT 1
#define SSH_PPP_PROTOCOL_FLAG_CONFIG_REQ 2
#define SSH_PPP_PROTOCOL_FLAG_CONFIG_ACK 4
#define SSH_PPP_PROTOCOL_FLAG_CONFIG_NAK 8
#define SSH_PPP_PROTOCOL_FLAG_CONFIG_REJ 16
#define SSH_PPP_PROTOCOL_FLAG_TERMINATE_REQ 32
#define SSH_PPP_PROTOCOL_FLAG_TERMINATE_ACK 64
#define SSH_PPP_PROTOCOL_FLAG_CODE_REJ 128
#define SSH_PPP_PROTOCOL_FLAG_PROTOCOL_REJ 256

#define SSH_PPP_COUNTER_CONFIGURE_REQ_RESEND 1
#define SSH_PPP_COUNTER_TERMINATE_REQ_RESEND 2
#define SSH_PPP_COUNTER_NAKS 3
#define SSH_PPP_COUNTER_OPTION_NAKS 4
#define SSH_PPP_COUNTER_NEUTRAL_ACKS 5

/* Interface negotiation protocols must (selectively) implement */

/* The default values for input options (proposed by us) should be
   in use untill further notice, after this callback has been called. */
typedef void (*SshPppProtocolDefaultInputCB)(SshPppState gdata, void *ctx);

/* The default values for output options (proposed by peer) should be
   in use untill further notice, after this callback has been called. */
typedef void (*SshPppProtocolDefaultOutputCB)(SshPppState gdata, void *ctx);

/* The options currently negotiated and proposed by us should be taken into
   use. */
typedef void (*SshPppProtocolApplyInputCB)(SshPppState gdata, void *ctx);

/* The options currently negotiated and proposed by peer should be taken
   into use. */
typedef void (*SshPppProtocolApplyOutputCB)(SshPppState gdata, void *ctx);

/* Signal that this layer is gong up, but the last state transform
   "delayed". See sshppp_protocol_fsm.c for more information */
typedef void (*SshPppProtocolTlDelayCB)(SshPppState gdata, void *ctx);

/* Signal that this layer has reached the "UP" state */
typedef void (*SshPppProtocolTlUpCB)(SshPppState gdata, void *ctx);

/* Signal that this layer has gone "DOWN" */
typedef void (*SshPppProtocolTlDownCB)(SshPppState gdata, void *ctx);

/* Signal that this layer has "STARTED" */
typedef void (*SshPppProtocolTlStartedCB)(SshPppState gdata, void *ctx);

/* Signal that this layer has "FAILED" */
typedef void (*SshPppProtocolTlFailedCB)(SshPppState gdata, void *ctx);

/* Signal that a protocol reject message was received for protocol pid */
typedef void (*SshPppProtocolRejectCB)(SshPppState gdata, void *ctx,
                                       SshUInt16 pid);

/* Get options by type or index */
typedef struct SshPppConfigOptionRec*
(*SshPppProtocolGetInputOptionCB)(SshPppState gdata, void *ctx,
                                  SshUInt8 opt_type);

typedef struct SshPppConfigOptionRec*
(*SshPppProtocolGetOutputOptionCB)(SshPppState gdata, void *ctx,
                                   SshUInt8 opt_type);


typedef struct SshPppConfigOptionRec*
(*SshPppProtocolIterInputOptionCB)(SshPppState gdata, void *ctx,
                                   int opt_iter);

typedef struct SshPppConfigOptionRec*
(*SshPppProtocolIterOutputOptionCB)(SshPppState gdata, void *ctx,
                                    int opt_iter);

/* Get maximum value for a counter identified by the SSH_PPP_COUNTER_*
   names above. */
typedef SshPppCounter (*SshPppProtocolGetCounterMaxCB)(void *ctx,
                                                       int counter_id);
/* Destroy any instance related data */
typedef void (*SshPppProtocolDestructorCB)(void *ctx);

typedef struct SshPppProtocolInterfaceRec
{
  /* Name of instance for trace/debug messages */
  char *debug_name;

  /* Protocol ID */
  SshUInt16 pid;

  SshPppProtocolDefaultInputCB default_input_config_cb;
  SshPppProtocolDefaultOutputCB default_output_config_cb;
  SshPppProtocolApplyInputCB apply_input_config_cb;
  SshPppProtocolApplyOutputCB apply_output_config_cb;

  SshPppProtocolTlDelayCB this_layer_delay_cb;
  SshPppProtocolTlUpCB this_layer_up_cb;
  SshPppProtocolTlDownCB this_layer_down_cb;
  SshPppProtocolTlStartedCB this_layer_started_cb;
  SshPppProtocolTlFailedCB this_layer_failed_cb;

  SshPppProtocolRejectCB protocol_reject_cb;

  SshPppProtocolGetInputOptionCB get_config_option_input_cb;
  SshPppProtocolGetOutputOptionCB get_config_option_output_cb;
  SshPppProtocolIterInputOptionCB iter_config_option_input_cb;
  SshPppProtocolIterOutputOptionCB iter_config_option_output_cb;

  SshPppProtocolGetCounterMaxCB get_counter_max;

  SshPppProtocolDestructorCB destructor_cb;
} *SshPppProtocolInterface, SshPppProtocolInterfaceStruct;

typedef struct SshPppIdentifierRec {
  SshUInt8 code;
  SshUInt8 id;
} SshPppIdentifierStruct, *SshPppIdentifier;

#define SSH_PPP_MAX_QUEUES 16

typedef struct SshPppProtocolRec
{
  /* Magic box which wakes us up from time to time */
  SshPppThread ppp_thread;

  /* This identifier is used to circumvent unnecessary
     recording of resent NAK's as "bad" */
  SshPppIdentifierStruct identifier_input;

  /* Identifier for matching replies to requests */
  SshPppIdentifierStruct identifier_output;

  /* Identifier for code rejects, protocol rejects, etc. */
  SshPppIdentifierStruct identifier_protocol_reject;

  /* Configuration regarding counters */
  SshPppCounter counter_max;

  SshPppCounter counter_current;
  SshPppCounter counter_naks_current;

  /* If option config is invalid, this is true */
  SshUInt8 option_config_invalid;

  /* Delay between the "Opening" states and the "Open" state */
  unsigned long boot_delay_usecs;

  /* Magic Numbers */
  unsigned long magic_input;
  unsigned long magic_output;

  /* Instantiated handling of protocol id specific stuff */
  SshPppProtocolInterface iface;

  /* Protocol specific state for callbacks */
  void* ctx;

  /* Status of protocol */
  SshPppProtocolStatus protocol_status;
} *SshPppProtocol, SshPppProtocolStruct;

/* Macros for building states for the negotiation protocol */

#define SSH_PPP_PROTOCOL_ENTRY() \
SSH_FSM_DATA(SshPppState, SshPppProtocol);\
ssh_ppp_thread_enter_state(gdata, tdata->ppp_thread);\
ssh_ppp_protocol_fsm_handle_events(gdata, tdata);

#define SSH_PPP_PROTOCOL_EXIT() \
return ssh_ppp_thread_leave_state(gdata,tdata->ppp_thread);

#define SSH_PPP_PROTOCOL_JUMP_STATE(ppp_thread, x) \
do {\
ssh_fsm_set_next((ppp_thread)->thread, (x));\
return SSH_FSM_CONTINUE;\
} while(0)

/* Prototypes */

SshPppEvents
ssh_ppp_protocol_get_eventq(SshPppProtocol pro);

void
ssh_ppp_protocol_destroy(SshPppProtocol pro);

SshPppProtocol
ssh_ppp_protocol_create(SshPppState gdata,
                        SshPppEvents eventq,
                        SshPppFlush flush,
                        void* ctx,
                        SshPppProtocolInterface iface);

void
ssh_ppp_protocol_boot(SshPppState gdata,
                      SshPppProtocol tdata);

SshIterationStatus
ssh_ppp_protocol_frame_isvalid(SshPppPktBuffer pkt);

SshIterationStatus
ssh_ppp_protocol_frame_isprotocol(SshPppProtocol tdata,
                                  SshPppPktBuffer pkt);

SshUInt8
ssh_ppp_protocol_frame_get_code(SshPppPktBuffer pkt);

SshUInt8
ssh_ppp_protocol_frame_get_id(SshPppPktBuffer pkt);

SshUInt16
ssh_ppp_protocol_frame_get_len(SshPppPktBuffer pkt);

void
ssh_ppp_protocol_frame_strip_pad(SshPppPktBuffer pkt);

void
ssh_ppp_protocol_frame(SshPppPktBuffer pkt,
                       SshUInt8 type,SshUInt8 id);

void
ssh_ppp_protocol_skip_hdr(SshPppPktBuffer pkt);

void
ssh_ppp_protocol_skip_hldc(SshPppPktBuffer pkt);

SshIterationStatus
ssh_ppp_protocol_option_isvalid(SshPppPktBuffer pkt);


SshUInt8
ssh_ppp_protocol_option_get_type(SshPppPktBuffer pkt);

SshUInt8
ssh_ppp_protocol_option_get_length(SshPppPktBuffer pkt);

void
ssh_ppp_protocol_option_skip(SshPppPktBuffer pkt);


SshPppEvent
ssh_ppp_protocol_input(SshPppState state, SshPppProtocol local);

void
ssh_ppp_protocol_output_configure_req(SshPppState state,
                                      SshPppProtocol local);

void
ssh_ppp_protocol_output_configure_ack(SshPppState state,
                                      SshPppProtocol local);

void
ssh_ppp_protocol_output_configure_nak(SshPppState state,
                                      SshPppProtocol local);

void
ssh_ppp_protocol_output_terminate_req(SshPppState state,
                                      SshPppProtocol local);

void
ssh_ppp_protocol_output_terminate_ack(SshPppState state,
                                      SshPppProtocol local);

void
ssh_ppp_protocol_output_echo_reply(SshPppState state,
                                   SshPppProtocol local);

void
ssh_ppp_protocol_output_code_reject(SshPppState state,
                                    SshPppProtocol local);

void
ssh_ppp_protocol_output_protocol_reject(SshPppState state,
                                        SshPppProtocol local);

void
ssh_ppp_protocol_apply_output_config(SshPppState state,
                                     SshPppProtocol tdata);

void
ssh_ppp_protocol_apply_input_config(SshPppState state,
                                    SshPppProtocol tdata);

void
ssh_ppp_protocol_default_output_config(SshPppState gdata,
                                       SshPppProtocol tdata);

void
ssh_ppp_protocol_default_input_config(SshPppState gdata,
                                      SshPppProtocol tdata);

void
ssh_ppp_protocol_tlf(SshPppState gdata, SshPppProtocol tdata);

void
ssh_ppp_protocol_tld(SshPppState gdata,SshPppProtocol tdata);

void
ssh_ppp_protocol_delay(SshPppState gdata, SshPppProtocol tdata);

void
ssh_ppp_protocol_tlu(SshPppState gdata, SshPppProtocol tdata);

void
ssh_ppp_protocol_tls(SshPppState gdata, SshPppProtocol tdata);

void
ssh_ppp_protocol_tlhalt(SshPppState gdata, SshPppProtocol tdata);


SshPppProtocolStatus
ssh_ppp_protocol_get_status(SshPppProtocol tdata);

void
ssh_ppp_protocol_set_output_mru(SshPppProtocol tdata, unsigned long mru);

unsigned long
ssh_ppp_protocol_get_output_mru(SshPppProtocol tdata);

unsigned long
ssh_ppp_protocol_get_input_mru(SshPppProtocol tdata);

void
ssh_ppp_protocol_set_bootdelay(SshPppProtocol tdata, unsigned long ms);

SshUInt8
ssh_ppp_identifier_get(SshPppIdentifier id, SshUInt8 code);

Boolean
ssh_ppp_identifier_ismatch(SshPppIdentifier id,
                           SshUInt8 code,
                           SshUInt8 val);

void
ssh_ppp_identifier_inc(SshPppIdentifier id);

void
ssh_ppp_identifier_mark(SshPppIdentifier id,
                        SshUInt8 code,
                        SshUInt8 val);

void
ssh_ppp_identifier_init(SshPppState gdata,
                        SshPppIdentifier id);

SshPppCounter
ssh_ppp_protocol_get_counter_max(SshPppProtocol tdata, int i);

SshPppThread
ssh_ppp_protocol_get_thread(SshPppProtocol tdata);

void
ssh_ppp_protocol_options_invalid_set(SshPppProtocol tdata, Boolean b);

void
ssh_ppp_protocol_options_reset(SshPppState gdata, SshPppProtocol tdata);

#endif /* SSH_PPP_PROTOCOL_H */
