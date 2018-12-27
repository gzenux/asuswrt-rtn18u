/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   TCP/IP state tracking utils for the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineTcp"

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Initializes TCP/IP tracking state of a flow.  This expects to be called
   with engine->flow_control_table_lock held protecting the tcpdata. */

void ssh_engine_tcp_init(SshEngine engine, SshEngineFlowData flow)
{
#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
  SshUInt8 tmp[4];
#endif /* SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER */

  SSH_DEBUG(SSH_D_LOWOK, ("initializing tcpdata"));

  flow->u.tcp.state = SSH_ENGINE_TCP_INITIAL;
#ifdef SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER
  if (flow->data_flags & (SSH_ENGINE_FLOW_D_LOCAL_ENDPNT))
    {
      SSH_DEBUG(SSH_D_MY,
                ("flow has local endpoint: not randomizing sequence numbers"));
      flow->u.tcp.delta_i_to_r = 0;
      flow->u.tcp.delta_r_to_i = 0;
    }
  else
    {
      SSH_DEBUG(SSH_D_MY,
                ("flow has remote endpoints: setting random sequence deltas"));

      tmp[0] = ssh_engine_random_get_byte(engine);
      tmp[1] = ssh_engine_random_get_byte(engine);
      tmp[2] = ssh_engine_random_get_byte(engine);
      tmp[3] = ssh_engine_random_get_byte(engine);
      flow->u.tcp.delta_i_to_r = SSH_GET_32BIT(tmp);

      tmp[0] = ssh_engine_random_get_byte(engine);
      tmp[1] = ssh_engine_random_get_byte(engine);
      tmp[2] = ssh_engine_random_get_byte(engine);
      tmp[3] = ssh_engine_random_get_byte(engine);
      flow->u.tcp.delta_r_to_i = SSH_GET_32BIT(tmp);
    }
#endif /* SSH_IPSEC_TCP_SEQUENCE_RANDOMIZER */
}


/* Uninitializes TCP/IP tracking state of a flow (freeing dynamically
   allocated memory, if any).  This gets called when the flow is being
   destroyed.  This expects to be called with engine->flow_control_table_lock
   held protecting the tcpdata. */

void ssh_engine_tcp_uninit(SshEngine engine, SshEngineFlowData flow)
{
  SSH_DEBUG(SSH_D_LOWOK, ("uninitializing tcpdata"));
}

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

SshUInt32
ssh_engine_tcp_get_idle_timeout(SshEngine engine, SshUInt32 flow_idx,
                                SshEngineFlowData d_flow)
{
  SshEngineFlowControl c_flow;
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  SshEngineTcpData tcpdata;

  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_idx);

  /* If flow is designated to "never" timeout,
     then do not consider TCP state */
  if (c_flow->idle_timeout == 0xFFFFFFFF)
    return c_flow->idle_timeout;




  tcpdata = &d_flow->u.tcp;
  SSH_ASSERT(d_flow->ipproto == SSH_IPPROTO_TCP);




  if (tcpdata->state == SSH_ENGINE_TCP_CLOSE_WAIT ||
      tcpdata->state == SSH_ENGINE_TCP_CLOSED)
    c_flow->idle_timeout = SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;

  switch (tcpdata->state)
    {
    case SSH_ENGINE_TCP_INITIAL:
    case SSH_ENGINE_TCP_SYN:
    case SSH_ENGINE_TCP_SYN_ACK:
      return SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
    case SSH_ENGINE_TCP_SYN_ACK_ACK:
    case SSH_ENGINE_TCP_ESTABLISHED:
      return c_flow->idle_timeout;
    case SSH_ENGINE_TCP_FIN_FWD:
    case SSH_ENGINE_TCP_FIN_REV:
      return 900; /* Wait max. 15 minutes (idle time) in half-closed state. */
    case SSH_ENGINE_TCP_FIN_FIN:
    case SSH_ENGINE_TCP_CLOSE_WAIT:
    case SSH_ENGINE_TCP_CLOSED:
    default:
      return SSH_ENGINE_DEFAULT_IDLE_TIMEOUT;
    }
  /*NOTREACHED*/
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */

#ifndef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
  c_flow = SSH_ENGINE_GET_FLOW(engine, flow_idx);
  if (c_flow->control_flags
      & (SSH_ENGINE_FLOW_C_TRIGGER|SSH_ENGINE_FLOW_C_UNDEFINED))
    return c_flow->idle_timeout;
  return SSH_ENGINE_DEFAULT_TCP_IDLE_TIMEOUT;
#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
}
