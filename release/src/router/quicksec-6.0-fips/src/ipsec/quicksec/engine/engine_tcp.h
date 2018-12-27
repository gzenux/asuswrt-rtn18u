/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   TCP state tracking for the flow engine.
*/

#ifndef ENGINE_TCP_H
#define ENGINE_TCP_H

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/** TCP state. */
typedef enum {
  SSH_ENGINE_TCP_INITIAL,       /** Initial. */
  SSH_ENGINE_TCP_SYN,           /** Syn. */
  SSH_ENGINE_TCP_SYN_ACK,       /** Syn ACK. */
  SSH_ENGINE_TCP_SYN_ACK_ACK,   /** Syn ACK ACK. */
  SSH_ENGINE_TCP_ESTABLISHED,   /** Established. */
  SSH_ENGINE_TCP_FIN_FWD,       /** FIN FWD. */
  SSH_ENGINE_TCP_FIN_REV,       /** FIN REV. */
  SSH_ENGINE_TCP_FIN_FIN,       /** FIN FIN. */
  SSH_ENGINE_TCP_CLOSE_WAIT,    /** Close wait. */
  SSH_ENGINE_TCP_CLOSED         /** Closed. */
} SshEngineTcpState;


/** TCP data structure. */
typedef struct SshEngineTcpDataRec
{
  SshUInt8 state; /** SshEngineTcpState */
#ifdef SSH_IPSEC_TCP_SEQUENCE_MONITOR
  SshUInt8 win_scale_i_to_r;  /** Shift count, as specified in RFC 1323. */
  SshUInt8 win_scale_r_to_i;  /** Shift count, as specified in RFC 1323. */
  SshUInt32 seq_i_to_r; /** Sequence number sent by initiator. */
  SshUInt32 seq_r_to_i; /** Sequence number sent by responder. */

  SshUInt32 data_i_to_r; /** Amount of data sent by initiator. */
  SshUInt32 data_r_to_i; /** Amount of data sent by responder. */
#endif /* SSH_IPSEC_TCP_SEQUENCE_MONITOR */
#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
  SshUInt32 delta_i_to_r;
  SshUInt32 delta_r_to_i;
#endif /* SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER */
} SshEngineTcpDataStruct, *SshEngineTcpData;

/** Initialize TCP/IP tracking state of a flow.  This expects to be called
    with engine->flow_table_lock held protecting the tcpdata. */
void ssh_engine_tcp_init(SshEngine engine, SshEngineFlowData flow);

/** Uninitialize TCP/IP tracking state of a flow (freeing dynamically
    allocated memory, if any).  This gets called when the flow is being
    destroyed.  This expects to be called with engine->flow_table_lock
    held protecting the tcpdata. */
void ssh_engine_tcp_uninit(SshEngine engine, SshEngineFlowData flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

/** Return appropriate idle timeout for TCP flow based on TCP state. */
SshUInt32
ssh_engine_tcp_get_idle_timeout(SshEngine engine, SshUInt32 flow_index,
                                SshEngineFlowData d_flow);
#endif /* ENGINE_TCP_H */
