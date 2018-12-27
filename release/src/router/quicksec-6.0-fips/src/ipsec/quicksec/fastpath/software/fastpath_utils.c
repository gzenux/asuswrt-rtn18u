/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Utility routines used by the fastpath.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_accel.h"
#include "fastpath_impl.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathUtils"


/********************* Packet context utilities *****************************/

/* Public function for allocating packet context objects. */
SSH_FASTTEXT
SshEnginePacketContext ssh_engine_alloc_pc(SshEngine engine)
{
#ifdef SSH_IPSEC_STATISTICS
  SshFastpath fastpath = engine->fastpath;
#endif /* SSH_IPSEC_STATISTICS */
  SshEnginePacketContext pc;
  unsigned int cpu;

  ssh_kernel_critical_section_start(engine->engine_critical_section);

  cpu = ssh_kernel_get_cpu();
  SSH_ASSERT(cpu < engine->num_cpus);

  pc = engine->pc_freelist[cpu];
  if (SSH_PREDICT_TRUE(pc))
    {
      engine->pc_freelist[cpu] = pc->next;
      pc->engine = engine;
      pc->cpu = cpu;



      pc->on_freelist = FALSE;
#ifdef DEBUG_LIGHT
      pc->recursed_ret = SSH_ENGINE_PC_RECURSED_RET_UNDEFINED;
      pc->recursed_error = SSH_ENGINE_PC_RECURSED_ERROR_UNDEFINED;
#endif /* DEBUG_LIGHT */
#ifdef SSH_IPSEC_STATISTICS
      fastpath->stats[cpu].active_packet_contexts++;
#endif /* SSH_IPSEC_STATISTICS */
      pc->next = NULL;
      ssh_kernel_critical_section_end(engine->engine_critical_section);
      return pc;
    }

  /* Try getting a packet from the shared freelist */
  ssh_kernel_mutex_lock(engine->pc_lock);

  pc = engine->pc_freelist[engine->num_cpus];
  if (SSH_PREDICT_FALSE(!pc))
    {
#ifdef SSH_IPSEC_STATISTICS
      fastpath->stats[cpu].out_of_packet_contexts++;
#endif /* SSH_IPSEC_STATISTICS */
    }
  else
    {
      engine->pc_freelist[engine->num_cpus] = pc->next;
      pc->engine = engine;
      pc->cpu = cpu;



      pc->on_freelist = FALSE;
#ifdef DEBUG_LIGHT
      pc->recursed_ret = SSH_ENGINE_PC_RECURSED_RET_UNDEFINED;
      pc->recursed_error = SSH_ENGINE_PC_RECURSED_ERROR_UNDEFINED;
#endif /* DEBUG_LIGHT */
#ifdef SSH_IPSEC_STATISTICS
     fastpath->stats[cpu].active_packet_contexts++;
#endif /* SSH_IPSEC_STATISTICS */
     pc->next = NULL;
    }

  ssh_kernel_mutex_unlock(engine->pc_lock);
  ssh_kernel_critical_section_end(engine->engine_critical_section);

  return pc;
}


/* Initializes the packet context for starting the processing of a new
   packet. pc->engine, pc->pp, pc->tunnel_id and pc->pending_packets
   are initialized based on the arguments provided. This function is internal
   to the software fastpath and engine. */
SSH_FASTTEXT
void ssh_engine_init_pc(SshEnginePacketContext pc,
                        SshEngine engine,
                        SshInterceptorPacket pp,
                        SshUInt32 tunnel_id,
                        SshInterceptorPacket pending_packets)
{
  pc->engine = engine;
  pc->pp = pp;
  pc->tunnel_id = tunnel_id;
  pc->pending_packets = pending_packets;

  pc->next = NULL;
  pc->comp_savings = 0;
  pc->rule = NULL;
  pc->flow_index = SSH_IPSEC_INVALID_INDEX;
  pc->transform_index = SSH_IPSEC_INVALID_INDEX;
  pc->transform = 0;
  pc->transform_counter = 0;
  if (SSH_PREDICT_TRUE(pc->pp))
    pc->orig_len = ssh_interceptor_packet_len(pc->pp);
  else
    pc->orig_len = 0;

  /* Initialize the port numbers to default zero - this saves a number
     of tests on the proto later. */
  pc->u.rule.dst_port = 0;
  pc->u.rule.src_port = 0;
#ifdef SSH_IPSEC_STATISTICS
  memset(pc->stat_vec, 0, sizeof(pc->stat_vec));
#endif /* SSH_IPSEC_STATISTICS */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  if (SSH_PREDICT_TRUE(pc->pp))
    {
      SshEnginePacketData pd;
      pd = SSH_INTERCEPTOR_PACKET_DATA(pc->pp, SshEnginePacketData);
      pd->media_hdr_len = 0;
    }
  pc->media_hdr_len = 0;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#ifdef WITH_IPV6
  pc->fragh_offset = pc->ipsec_offset = SSH_IPH6_HDRLEN;
  pc->fragh_offset_prevnh = pc->ipsec_offset_prevnh = SSH_IPH6_OFS_NH;
  pc->dsth_offset = 0;
#endif /* WITH_IPV6 */

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  /* By default, process the packet in software until the flow execution
     state is reached. */
  pc->fastpath_accel_ret = SSH_ENGINE_RET_EXECUTE;
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

  /* Clear auditing information */
  pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;
  pc->audit.ip_option = 0;
  pc->audit.spi = 0;
  pc->audit.seq = 0;
  pc->audit.flowlabel = 0;

  pc->error_info.flags = 0;
}

/* Initializes the packet context for starting the processing of a new
   packet. pc->engine, pc->pp, and pc->tunnel_id are initialized based
   on the arguments provided. In addition this function pulls up the packet
   headers in pp and stores relevant information to the packet context
   pc. Returns  FALSE if an error occurred and TRUE otherwise. This function
   is public. */
Boolean ssh_engine_init_and_pullup_pc(SshEnginePacketContext pc,
                                      SshEngine engine,
                                      SshInterceptorPacket pp,
                                      SshUInt32 tunnel_id,
                                      SshUInt32 prev_transform_index)
{
  SshEnginePacketData pd;

  /* Initialize the new pc. */
  ssh_engine_init_pc(pc, engine, pp, tunnel_id, NULL);
  pc->flags = 0;
  pc->prev_transform_index = prev_transform_index;
  pd = SSH_INTERCEPTOR_PACKET_DATA(pc->pp, SshEnginePacketData);

  /* Pullup packet context */
  return fastpath_packet_context_pullup(engine, pc, pd);
}

/* Simple utility function for putting packets back on the freelist. This
   function is public. */
SSH_FASTTEXT void
ssh_engine_free_pc(SshEngine engine, SshEnginePacketContext pc)
{
#ifdef SSH_IPSEC_STATISTICS
  SshFastpath fastpath = engine->fastpath;
#endif /* SSH_IPSEC_STATISTICS */
  unsigned int cpu, pc_cpu;

  SSH_ASSERT(engine != NULL && pc != NULL);

  SSH_DEBUG(SSH_D_MY, ("placing pc=%p on freelist", pc));

  ssh_kernel_critical_section_start(engine->engine_critical_section);

  cpu = ssh_kernel_get_cpu();
  SSH_ASSERT(cpu < engine->num_cpus);
  pc_cpu = pc->cpu;

#ifdef SSH_IPSEC_STATISTICS
  fastpath->stats[cpu].active_packet_contexts--;
#endif /* SSH_IPSEC_STATISTICS */





#ifdef DEBUG_LIGHT
  memset(pc, 'S', sizeof(*pc));
#endif /* DEBUG_LIGHT */

  pc->on_freelist = TRUE;

  if (pc_cpu == cpu)
    {
      pc->next = engine->pc_freelist[cpu];
      engine->pc_freelist[cpu] = pc;
    }
  else
    {
      ssh_kernel_mutex_lock(engine->pc_lock);

      pc->next = engine->pc_freelist[engine->num_cpus];
      engine->pc_freelist[engine->num_cpus] = pc;

      ssh_kernel_mutex_unlock(engine->pc_lock);
    }
  ssh_kernel_critical_section_end(engine->engine_critical_section);
}

void ssh_engine_copy_pc_data(SshEnginePacketContext dst_pc,
                             SshEnginePacketContext src_pc)
{
  SSH_ASSERT(src_pc != NULL);
  SSH_ASSERT(dst_pc != NULL);

  /* Copy only the data related to the packet, flow and routing.
     Leave pc state alone, this includes fields:
     - recursed_ret
     - recursed_error
     - pp
     - pending_packets
     - next
     - cpu
     - on_freelist
  */

  dst_pc->flags = src_pc->flags;
#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  dst_pc->fastpath_accel_ret = src_pc->fastpath_accel_ret;
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  dst_pc->media_hdr_len = src_pc->media_hdr_len;
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  dst_pc->tunnel_id = src_pc->tunnel_id;
#ifdef SSH_IPSEC_STATISTICS
  memcpy(dst_pc->stat_vec, src_pc->stat_vec, sizeof(dst_pc->stat_vec));
#endif /* SSH_IPSEC_STATISTICS */
  memcpy(dst_pc->flow_id, src_pc->flow_id, sizeof(dst_pc->flow_id));
  dst_pc->orig_len = src_pc->orig_len;
  dst_pc->packet_len = src_pc->packet_len;
#if defined (WITH_IPV6)
  dst_pc->ipsec_offset = src_pc->ipsec_offset;
  dst_pc->ipsec_offset_prevnh = src_pc->ipsec_offset_prevnh;
  dst_pc->fragh_offset = src_pc->fragh_offset;
  dst_pc->fragh_offset_prevnh = src_pc->fragh_offset_prevnh;
  dst_pc->dsth_offset = src_pc->dsth_offset;
#endif /* WITH_IPV6 */
  dst_pc->fragment_id = src_pc->fragment_id;
  dst_pc->fragment_offset = src_pc->fragment_offset;
  dst_pc->hdrlen = src_pc->hdrlen;
  dst_pc->comp_savings = src_pc->comp_savings;
  dst_pc->frag_packet_size = src_pc->frag_packet_size;
  dst_pc->min_packet_size = src_pc->min_packet_size;
  dst_pc->ipproto = src_pc->ipproto;
  dst_pc->icmp_type = src_pc->icmp_type;
  dst_pc->protocol_xid = src_pc->protocol_xid;
  dst_pc->dst = src_pc->dst;
  dst_pc->src = src_pc->src;
  dst_pc->flow_index = src_pc->flow_index;
  dst_pc->flow_generation = src_pc->flow_generation;
  dst_pc->transform_index = src_pc->transform_index;
  dst_pc->transform = src_pc->transform;
  dst_pc->prev_transform_index = src_pc->prev_transform_index;
  dst_pc->rule = src_pc->rule;
  dst_pc->transform_counter = src_pc->transform_counter;
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  dst_pc->route_selector = src_pc->route_selector;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  memcpy(&dst_pc->u.flow, &src_pc->u.flow, sizeof(dst_pc->u.flow));
  memcpy(&dst_pc->audit, &src_pc->audit, sizeof(dst_pc->audit));
  memcpy(&dst_pc->error_info, &src_pc->error_info, sizeof(dst_pc->error_info));
}

/********************* Public packet context accessor functions **************/

/** This accessor function sets 'pp' in pc. */
void
ssh_engine_pc_set_pp(SshEnginePacketContext pc, SshInterceptorPacket pp)
{
  pc->pp = pp;
}

/** This accessor function sets 'flags' in pc. */
void
ssh_engine_pc_set_flags(SshEnginePacketContext pc, SshUInt32 flags)
{
  pc->flags = flags;
}

/** This accessor function sets 'flow_index' in pc. */
void
ssh_engine_pc_set_flow_index(SshEnginePacketContext pc, SshUInt32 flow_index)
{
  pc->flow_index = flow_index;
}

/** This accessor function returns a pointer to 'pp' in pc. */
SshInterceptorPacket
ssh_engine_pc_get_pp(SshEnginePacketContext pc)
{
  return pc->pp;
}

/** This accessor function returns 'flags' in pc. */
SshUInt32
ssh_engine_pc_get_flags(SshEnginePacketContext pc)
{
  return pc->flags;
}

/** This accessor function returns 'tunnel_id' in pc. */
SshUInt32
ssh_engine_pc_get_tunnel_id(SshEnginePacketContext pc)
{
  return pc->tunnel_id;
}

/** This accessor function returns 'prev_transform_index' in pc. */
SshUInt32
ssh_engine_pc_get_prev_transform_index(SshEnginePacketContext pc)
{
  return pc->prev_transform_index;
}

/** This accessor function returns a pointer to 'flow_id' in pc. */
unsigned char *
ssh_engine_pc_get_flow_id(SshEnginePacketContext pc)
{
  return pc->flow_id;
}

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
/** This accessor function returns the length of the media header that the
    software fastpath has added to the packet. */
size_t
ssh_engine_pc_get_media_header_length(SshEnginePacketContext pc)
{
  return pc->media_hdr_len;
}
#endif /* !SSH_IPSEC_IP_ONLY_INTERCEPTOR */


/************* Internal software fastpath and engine utilities ***************/

SSH_FASTTEXT
void fastpath_copy_flow_data(SshFastpath fastpath,
                             SshEngineFlowData flow,
                             SshEnginePacketContext pc)
{
#ifdef SSHDIST_IPSEC_NAT
  if (flow != NULL)
    {
      if ((flow->data_flags & SSH_ENGINE_FLOW_D_NAT_SRC) &&
          (flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING))
        {
          pc->u.flow.internal_nat_ip = flow->nat_src_ip;
          pc->u.flow.internal_nat_port = flow->nat_src_port;
          return;
        }
    }
  SSH_IP_UNDEFINE(&pc->u.flow.internal_nat_ip);
  return;
#endif /* SSHDIST_IPSEC_NAT */
}


/* Copies enough data from the transform indicated by pc->transform_index
   into pc, so that the transform can be executed.  This also allocates
   IP packet ids, increments outgoing packet count, etc as needed.
   Engine->flow_table_lock must be held when this is called.
   If the transform index (cached from flow) does not indicate valid
   transform, this returns FALSE, else TRUE. */
SSH_FASTTEXT
Boolean
fastpath_copy_transform_data(SshFastpath fastpath, SshEnginePacketContext pc)
{
  SshEngineTransformRun trr;
  SshEngineTransformData trd;

  if (pc->transform_index == SSH_IPSEC_INVALID_INDEX)
    {
      pc->transform = 0;
      return TRUE;
    }

  trd = FP_GET_TRD(fastpath, pc->transform_index);
  SSH_ASSERT(trd != NULL);

  if (trd->transform == 0)
    {
      FP_RELEASE_TRD(fastpath, pc->transform_index);
      return FALSE;
    }

  pc->transform = trd->transform;

  trr = &pc->u.flow.tr;

  /* Copy basic data for the transform. */
  trr->gw_addr = trd->gw_addr;
  trr->local_addr = trd->own_addr;
  trr->local_port = trd->local_port;
  trr->local_ifnum = trd->own_ifnum;
  trr->tr_index = trd->tr_index;
  trr->nesting_level = trd->nesting_level;
  trr->restart_tunnel_id = trd->inbound_tunnel_id;
  trr->restart_after_tre = trd->restart_after_tre;
  trr->df_bit_processing = trd->df_bit_processing;
  trr->myipid = 0;

  /* Update PMTU if it is known in the transform. */
  if (trd->pmtu_received && trd->pmtu_received < pc->u.flow.mtu)
    pc->u.flow.mtu = trd->pmtu_received;

  trr->packet_enlargement = trd->packet_enlargement;
  trr->cipher_key_size = trd->cipher_key_size;
  trr->cipher_iv_size = trd->cipher_iv_size;
  trr->cipher_nonce_size = trd->cipher_nonce_size;
  trr->mac_key_size = trd->mac_key_size;

#ifdef SSHDIST_L2TP
  /* Ignore L2TP encapsulation from the L2TP control traffic. */
  if (SSH_PREDICT_FALSE(pc->flags & SSH_ENGINE_FLOW_D_IGNORE_L2TP))
    pc->transform &= ~SSH_PM_IPSEC_L2TP;

  /* Copy L2TP data. */
  if (SSH_PREDICT_FALSE(trd->transform & SSH_PM_IPSEC_L2TP))
    {
      trr->l2tp_local_port = trd->l2tp_local_port;
      trr->l2tp_remote_port = trd->l2tp_remote_port;
      trr->l2tp_local_tunnel_id = trd->l2tp_local_tunnel_id;
      trr->l2tp_local_session_id = trd->l2tp_local_session_id;
      trr->l2tp_remote_tunnel_id = trd->l2tp_remote_tunnel_id;
      trr->l2tp_remote_session_id = trd->l2tp_remote_session_id;
      trr->l2tp_flags = trd->l2tp_flags;
      if (trd->l2tp_flags & SSH_ENGINE_L2TP_SEQ)
        {
          trr->l2tp_seq_ns = trd->l2tp_seq_ns++;
          trr->l2tp_seq_nr = trd->l2tp_seq_nr;
        }
      /* Fragment packet before applying outbound transform. */
      if ((pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0)
        pc->flags |= SSH_ENGINE_FLOW_D_FRAG_TRANSFORM;
    }
#endif /* SSHDIST_L2TP */
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Copy NAT-T data. */
  trr->remote_port = trd->remote_port;
  trr->natt_flags = trd->natt_flags;
  if (SSH_PREDICT_FALSE(trd->natt_flags & SSH_ENGINE_NATT_OA_L))
    memcpy(trr->natt_oa_l, trd->natt_oa_l, sizeof(trd->natt_oa_l));
  if (SSH_PREDICT_FALSE(trd->natt_flags & SSH_ENGINE_NATT_OA_R))
    memcpy(trr->natt_oa_r, trd->natt_oa_r, sizeof(trd->natt_oa_r));
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /* Copy SPI/key material.  Note that what we copy depends on whether
     we are doing inbound or outbound processing, and whether
     we are accepting incoming packets for the old rekeyed transform. */
  if (SSH_PREDICT_FALSE((pc->flags
                         & (SSH_ENGINE_FLOW_D_IPSECINCOMING
                            | SSH_ENGINE_PC_FORWARD))
                        == (SSH_ENGINE_FLOW_D_IPSECINCOMING
                            | SSH_ENGINE_PC_FORWARD)))
    {
      /* Incoming using old SPI from before rekey. */
      trr->myspis[0] = trd->old_spis[0];
      trr->myspis[1] = trd->old_spis[1];
      trr->myspis[2] = trd->old_spis[2];
      memcpy(trr->mykeymat, trd->old_keymat, sizeof(trr->mykeymat));
      trr->mycount_high = trd->old_replay_offset_high;
      trr->mycount_low = trd->old_replay_offset_low;
      memcpy(trr->myreplaymask, trd->old_replay_mask,
             sizeof(trr->myreplaymask));
    }
  else
    {
      /* Use current SPIs and keymat. */
      if (pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
        { /* Incoming using current SPI. */
          trr->myspis[0] = trd->spis[0];
          trr->myspis[1] = trd->spis[1];
          trr->myspis[2] = trd->spis[2];
          memcpy(trr->mykeymat, trd->keymat, sizeof(trr->mykeymat));
          trr->mycount_high = trd->replay_offset_high;
          trr->mycount_low = trd->replay_offset_low;
          memcpy(trr->myreplaymask, trd->replay_mask,
                 sizeof(trr->myreplaymask));

          /* Overwrite extension selector */
#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
          if (trd->decapsulate_extension)
            memcpy(pc->pp->extension, trd->extension,
                   sizeof(pc->pp->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
        }
      else
        { /* Outgoing using current SPI. */
          trr->myspis[0] = trd->spis[3];
          trr->myspis[1] = trd->spis[4];
          trr->myspis[2] = trd->spis[5];
          memcpy(trr->mykeymat,
                 trd->keymat + (SSH_IPSEC_MAX_KEYMAT_LEN / 2),
                 sizeof(trr->mykeymat));

          /* Get packet counter value for outgoing replay
             prevention. Do not let it wrap. */
          if ((pc->transform & SSH_PM_IPSEC_ANTIREPLAY)
              && !(pc->transform & SSH_PM_IPSEC_LONGSEQ)
              && trd->out_packets_low == 0xffffffff)
            ;
          else
            SSH_UINT64_INC(trd->out_packets_low, trd->out_packets_high);

          trr->mycount_high = trd->out_packets_high;
          trr->mycount_low = trd->out_packets_low;

          /* Generate new outgoing packet id if appropriate. */
          if (pc->transform & (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP))
            trr->myipid = ssh_engine_get_ip_id(fastpath->engine);

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
          if (trd->decapsulate_extension)
            memset(pc->pp->extension, 0, sizeof(pc->pp->extension));
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */
        }
    }
  trr->statflags = 0;

  /* Mark when the transform has last been used. */
  /* Update certain transform statistics. */
  if (!(pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING))
    {
      trd->last_out_packet_time = fastpath->engine->run_time;
#ifdef SSH_IPSEC_STATISTICS
      trd->stats.out_octets += pc->packet_len;
      trd->stats.out_packets++;
#endif /* SSH_IPSEC_STATISTICS */
    }
  else
    {
      /* When we receive packet for inbound transform we restart
         worrying about idleness. However we do not update the last
         packet in time if the packet was received on an address pair
         different to that of the IPsec SA endpoints
         (RFC 4555 Section 3.12). */
      if (!SSH_IP_CMP(&pc->dst, &trd->own_addr) &&
          !SSH_IP_CMP(&pc->src, &trd->gw_addr))
        {
          trd->last_in_packet_time = fastpath->engine->run_time;
        }
      else
        {
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Received IPsec packet on address pair src=%@, dst=%@ "
                     "different to that of the SA remote=%@, local=%@",
                     ssh_ipaddr_render, &pc->src,
                     ssh_ipaddr_render, &pc->dst,
                     ssh_ipaddr_render, &trd->gw_addr,
                     ssh_ipaddr_render, &trd->own_addr));
        }
#ifdef SSH_IPSEC_STATISTICS
      /* Subtract the transform headers when computing the amount of
         bytes processing by the inbound transform. */
      if (pc->packet_len > trd->packet_enlargement)
        trd->stats.in_octets += (pc->packet_len - trd->packet_enlargement);
      trd->stats.in_packets++;
#endif /* SSH_IPSEC_STATISTICS */
    }

#ifdef SSH_IPSEC_TCPENCAP
  trr->tcp_encaps_conn_id = trd->tcp_encaps_conn_id;
  SSH_DEBUG(SSH_D_LOWOK,
            ("tcp_encaps_conn_id 0x%lx", trr->tcp_encaps_conn_id));
#endif /* SSH_IPSEC_TCPENCAP */

  FP_COMMIT_TRD(fastpath, pc->transform_index, trd);

  /* Prefer fragmenting the packet before outbound transform, if IPsec
     encapsulation is in tunnel mode and the stack has indicated that the
     packet may be fragmented or if packet is IPv4 without a DF-bit. This
     is the most optimal mode of operation, except when IPcomp is used.

     Note RFC4301, section "4.1. Definition and Scope":

     Note: AH and ESP cannot be applied using transport mode to IPv4
     packets that are fragments.  Only tunnel mode can be employed in such
     cases.  For IPv6, it would be feasible to carry a plaintext fragment
     on a transport mode SA; however, for simplicity, this restriction
     also applies to IPv6 packets.
  */
  if (SSH_PREDICT_FALSE((pc->flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0
                        && (pc->transform &
                            (SSH_PM_IPSEC_TUNNEL | SSH_PM_IPSEC_L2TP)) != 0
                        && ((pc->pp->flags & SSH_PACKET_FRAGMENTATION_ALLOWED)
                            != 0
                            || (pc->pp->protocol == SSH_PROTOCOL_IP4
                                && (pc->fragment_offset & SSH_IPH4_FRAGOFF_DF)
                                == 0))))
    pc->flags |= SSH_ENGINE_FLOW_D_FRAG_TRANSFORM;

  return TRUE;
}

/* Decrement the packet time to live field. Returns FALSE if packet should
   be dropped. */
Boolean fastpath_decrement_ttl(SshEnginePacketContext pc)
{
  unsigned char *ucpw;
  SshUInt16 cks;
  unsigned char ttl;

  if ((pc->flags & SSH_ENGINE_PC_DECREMENT_TTL) == 0)
    return TRUE;

  ucpw = ssh_interceptor_packet_pullup(pc->pp, 12);
  if (!ucpw)
    {
      SSH_DEBUG(SSH_D_FAIL, ("pullup failed"));
      SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_ERRORDROP);
      pc->pp = NULL;
      return FALSE;
    }

#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      ttl = SSH_IPH6_HL(ucpw);
      ttl--;
      if (ttl == 0)
        {
          SSH_DEBUG(SSH_D_NETGARB, ("Hop limit reached zero"));
          SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
          return FALSE;
        }
      SSH_IPH6_SET_HL(ucpw, ttl);
    }
    else
#endif /* WITH_IPV6 */
      {
        ttl = SSH_IPH4_TTL(ucpw);
        ttl--;
        if (ttl == 0)
          {
            SSH_DEBUG(SSH_D_NETGARB, ("TTL reached zero"));
            SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_CORRUPTDROP);
            return FALSE;
          }
        SSH_IPH4_SET_TTL(ucpw, ttl);
        cks = SSH_IPH4_CHECKSUM(ucpw);
        cks = ssh_ip_cksum_update_byte(cks, SSH_IPH4_OFS_TTL,
                                           ttl + 1, ttl);
        SSH_IPH4_SET_CHECKSUM(ucpw, cks);
      }
  return TRUE;
}

/* Returns TRUE if the given address is a local IP address of this
   host, and FALSE otherwise. `engine->flow_table_lock' must be held
   when this is called. */
Boolean
ssh_engine_ip_is_local(SshEngine engine, const SshIpAddr dst)
{
  SshInterceptorInterface *ifp;

  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp = ssh_ip_get_interface_by_ip(&engine->ifs, dst,
                                   SSH_INTERCEPTOR_VRI_ID_ANY);

  if (ifp != NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return TRUE;
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* No address matched `dst'.  It is not our local address. */
  return FALSE;
}

/* Returns TRUE if the given address is link broadcast, directed
   subnet broadcast or multicast addresses e.g. if the destination
   address is a valid broadcast address to this host, the function
   returns TRUE. `engine->flow_table_lock' must be held when this is
   called. */
Boolean
ssh_engine_ip_is_broadcast(SshEngine engine, const SshIpAddr dst)
{
  SshInterceptorInterface *ifp;

  /* Check link-local broadcast addresses. */
  if (SSH_IP_IS_BROADCAST(dst))
    return TRUE;

  /* Check multicast addresses. */
  if (SSH_IP_IS_MULTICAST(dst))
    return TRUE;

  if (SSH_IP_IS6(dst))
    return FALSE;

  ssh_kernel_mutex_lock(engine->interface_lock);

  ifp = ssh_ip_get_interface_by_broadcast(&engine->ifs, dst,
                                          SSH_INTERCEPTOR_VRI_ID_ANY);
  if (ifp != NULL)
    {
      ssh_kernel_mutex_unlock(engine->interface_lock);
      return TRUE;
    }

  ssh_kernel_mutex_unlock(engine->interface_lock);

  /* No address matched `dst'. It is not broadcast. */
  return FALSE;
}

#if defined(WITH_IPV6)
/* Returns next value for IPv6 fragment header identification field. */
SshUInt32
fastpath_get_ipv6_frag_id(SshFastpath fastpath)
{
  SshUInt32 frag_id;

  ssh_kernel_mutex_assert_is_locked(fastpath->frag_lock);

  frag_id = fastpath->frag_id_ctr;

  if (fastpath->frag_id_ctr == FASTPATH_ENGINE_IPV6_FRAG_ID_MAX)
    fastpath->frag_id_ctr = FASTPATH_ENGINE_IPV6_FRAG_ID_MIN;
  else
    fastpath->frag_id_ctr++;

  return frag_id;
}
#endif /* WITH_IPV6 */

#ifdef SSH_IPSEC_STATISTICS
/* Update counters (both global engine counters and flow counters) as
   indicated by pc->stat_vec. */
void
fastpath_update_statistics_counters(SshFastpath fastpath,
                                    SshEnginePacketContext pc)
{
  SshUInt32 i;
  SshEngineTransformData trd;
  SshEngineFlowData flow;
  SshFastpathGlobalStats stats;

  ssh_kernel_critical_section_start(fastpath->stats_critical_section);

  stats = &fastpath->stats[ssh_kernel_get_cpu()];

  /* Update global packet statistics. */
  if (SSH_PREDICT_TRUE(pc->flags & SSH_ENGINE_PC_FORWARDED))
    {
      stats->forwarded_octets_comp += pc->orig_len - pc->comp_savings;
      stats->forwarded_octets_uncomp += pc->orig_len;
      stats->forwarded_packets++;
    }
  else if (pc->flags & SSH_ENGINE_PC_OUTBOUND)
    {
      stats->out_octets_comp += pc->orig_len - pc->comp_savings;
      stats->out_octets_uncomp += pc->orig_len;
      stats->out_packets++;
    }
  else
    {
      stats->in_octets_comp += pc->orig_len;
      stats->in_octets_uncomp += pc->orig_len + pc->comp_savings;
      stats->in_packets++;
    }

  /* Update global counters. */
  for (i = 0; i < SSH_ENGINE_NUM_GLOBAL_STATS; i++)
    {
      if (SSH_PREDICT_FALSE(pc->stat_vec[i / 32] & (1 << (i % 32))))
        stats->counters[i]++;
    }

  ssh_kernel_critical_section_end(fastpath->stats_critical_section);

  FP_LOCK_WRITE(fastpath);

  /* Update transform statistics. */
  if (pc->transform_index != SSH_IPSEC_INVALID_INDEX)
    {
      trd = FP_GET_TRD(fastpath, pc->transform_index);
      if (trd)
        {
          if (pc->u.flow.tr.statflags & SSH_ENGINE_STAT_T_MAC_FAIL)
            trd->stats.num_mac_fails++;
          if (pc->u.flow.tr.statflags & SSH_ENGINE_STAT_T_DROP)
            trd->stats.drop_packets++;
        }
      FP_COMMIT_TRD(fastpath, pc->transform_index, trd);
    }

  /* Update flow statistics. */
  if (SSH_PREDICT_TRUE(pc->flow_index != SSH_IPSEC_INVALID_INDEX))
    {
      SSH_ASSERT(pc->flow_index < fastpath->flow_table_size);
      if (SSH_PREDICT_FALSE(pc->stat_vec[SSH_ENGINE_STAT_DROP / 32] &
                            (1 << (SSH_ENGINE_STAT_DROP % 32))))
        {
          flow = FP_GET_FLOW(fastpath, pc->flow_index);

          flow->stats.drop_packets++;

          FP_COMMIT_FLOW(fastpath, pc->flow_index, flow);
        }
    }
  FP_UNLOCK_WRITE(fastpath);
}
#endif /* SSH_IPSEC_STATISTICS */

