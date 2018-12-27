/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   UDP state tracking utils for the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineUdp"

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Initializes UDP tracking state of a flow.  This expects to be called
   with engine->flow_control_table_lock held protecting the tcpdata. */

void ssh_engine_udp_init(SshEngine engine, SshEngineFlowData d_flow)
{
  SSH_DEBUG(SSH_D_LOWOK, ("initializing udpdata"));
}


/* Uninitializes UDP tracking state of a flow (freeing dynamically
   allocated memory, if any).  This gets called when the flow is being
   destroyed.  This expects to be called with engine->flow_control_table_lock
   held protecting the tcpdata. */

void ssh_engine_udp_uninit(SshEngine engine, SshEngineFlowData d_flow)
{
  SSH_DEBUG(SSH_D_LOWOK, ("uninitializing udpdata"));
}

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
