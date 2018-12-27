/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ICMP state tracking for the flow engine.
*/

#ifndef ENGINE_ICMP_H
#define ENGINE_ICMP_H

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

typedef struct SshEngineIcmpDataRec
{
#ifdef WINDOWS
  /* Microsoft's compiler doesn't accept empty data structures. */
  SshUInt8 not_used;
#endif /* WINDOWS */
} SshEngineIcmpDataStruct, *SshEngineIcmpData;

/** Initialize ICMP tracking state of a flow.  This expects to be called
    with engine->flow_table_lock held protecting the udpdata. */
void ssh_engine_icmp_init(SshEngine engine, SshEngineFlowData d_flow);

/** Uninitialize ICMP tracking state of a flow (freeing dynamically
    allocated memory, if any).  This gets called when the flow is being
    destroyed.  This expects to be called with engine->flow_table_lock
    held protecting the udpdata. */
void ssh_engine_icmp_uninit(SshEngine engine, SshEngineFlowData flow);
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#endif /* ENGINE_UDP_H */
