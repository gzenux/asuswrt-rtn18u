/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ICMP state tracking for the flow engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathIcmp"

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Processes a ICMP packet for a flow. */
SshEngineProtocolMonitorRet
ssh_engine_icmp_packet(SshEngineFlowData flow, SshEnginePacketContext pc)
{
  SshUInt16 icmp_data_offset = 0;
  Boolean forward;

  SSH_DEBUG(SSH_D_LOWOK, ("icmp state processing"));

  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));
  SSH_ASSERT(flow != NULL);

  pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;

  /* Let all but first fragments through */
  if ((pc->pp->flags & SSH_ENGINE_P_ISFRAG)
      && (pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG) == 0)
    {
      icmp_data_offset = 0;
      goto pass;
    }

  /* Sanity check packet length. We expect the ICMP header to reside
     in the first packet completely. */
  if (pc->packet_len < pc->hdrlen + SSH_ICMP_HEADER_MINLEN)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("DROP; packet too short to contain ICMP header, len=%d",
                 pc->packet_len));
      return SSH_ENGINE_MRET_DROP;
    }
  icmp_data_offset = SSH_ICMP_HEADER_MINLEN;

 pass:

  /* Dispatch based on the state of the session. */
  forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;

  SSH_DEBUG(SSH_D_LOWOK,
            ("icmp: flow_flags=0x%04x forward=%u",
             (int)flow->data_flags, (unsigned int)forward));

  return SSH_ENGINE_MRET_PASS;
}

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
