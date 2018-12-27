/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   UDP state tracking for the flow engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathUdp"

#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS

/* Processes a UDP packet for a flow. */
SshEngineProtocolMonitorRet
ssh_engine_udp_packet(SshEngineFlowData flow, SshEnginePacketContext pc)
{
  SshUInt16 udp_data_offset;
  Boolean forward = FALSE;

  SSH_DEBUG(SSH_D_LOWOK, ("udp state processing"));

  SSH_ASSERT(pc->packet_len == ssh_interceptor_packet_len(pc->pp));
  SSH_ASSERT(flow != NULL);

  pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;

  /* Check IP header.  The flow mechanism also associates ICMP
     Destination Unreachable packets to this flow. */
  if (pc->ipproto != SSH_IPPROTO_UDP && pc->ipproto != SSH_IPPROTO_UDPLITE)
    return SSH_ENGINE_MRET_PASS;

  /* Let all but first fragments through */
  if ((pc->pp->flags & SSH_ENGINE_P_ISFRAG)
      && (pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG) == 0)
    {
      udp_data_offset = 0;
      goto pass;
    }

  /* Sanity check packet length, we expect the UDP header to reside in
     the first packet completely. */
  if (pc->packet_len < pc->hdrlen + SSH_UDP_HEADER_LEN)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("DROP; packet too short to contain UDP header, len=%d",
                 pc->packet_len));
      return SSH_ENGINE_MRET_DROP;
    }
  udp_data_offset = SSH_UDP_HEADER_LEN;

 pass:

  /* Dispatch based on the state of the session. */
  forward = (pc->flags & SSH_ENGINE_PC_FORWARD) != 0;

  SSH_DEBUG(SSH_D_LOWOK,
            ("udp: flow_flags=0x%04x forward=%u len=%lu (approx)",
             (int)flow->data_flags, (unsigned int)forward,
             pc->packet_len - pc->hdrlen - udp_data_offset));


  return SSH_ENGINE_MRET_PASS;
}

#endif /* SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS */
