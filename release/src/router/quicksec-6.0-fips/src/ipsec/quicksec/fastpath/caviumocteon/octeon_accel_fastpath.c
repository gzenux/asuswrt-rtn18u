/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon fastpath for QuickSec.
   This file implements the QuickSec Accelerated Fastpath API functions.
*/

#include "octeon_accel_fastpath_internal.h"


/************************ Internal defines **********************************/

#define SSH_DEBUG_MODULE "OcteonAccelFastpath"




#ifdef DEBUG_LIGHT
#define OCTEON_DEBUG_RUN(block) \
do         \
  {        \
    block; \
  }        \
while (0)
#else
#define OCTEON_DEBUG_RUN(block)
#endif /* DEBUG_LIGHT */


/*********************** Sanity check configuration *************************/

/* SE fastpath cannot work with SSH_IPSEC_IP_ONLY_INTERCEPTOR. */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
#error "SSH_IPSEC_IP_ONLY_INTERCEPTOR is not supported."
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Protocol monitors are not implemented on SE fastpath. */
#ifdef SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS
#error "SSH_IPSEC_EXECUTE_PROTOCOL_MONITORS is not implemented."
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/* Compiling a minimal engine does not make sense on a typical Octeon system.*/
#ifdef SSH_IPSEC_SMALL
#error "SSH_IPSEC_SMALL is not supported."
#endif /* SSH_IPSEC_SMALL */

/* IPsec over TCP support is not implemented. */
#ifdef SSH_IPSEC_TCPENCAP
#error "TCP encaps is not supported"
#endif /* SSH_IPSEC_TCPENCAP */

/* Check that the value of define OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS
   is in sync with SSH_ENGINE_NUM_RX_TRANSFORMS (in engine_fastpath_types.h
   which cannot be included in SE fastpath). */
#if OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS != SSH_ENGINE_NUM_RX_TRANSFORMS
#error "OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS has mismatching value!"
#endif /* OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS != ... */


/************************ Tick Timer ****************************************/

static void octeon_accel_fastpath_tick_timer(void *context)
{
  SshFastpathAccel accel = context;

  /* Update runtime on se fastpath. */
  cvmx_fau_atomic_write32(OCTEON_SE_FASTPATH_FAU_RUNTIME,
                          accel->engine->run_time);

  ssh_kernel_timeout_register(1, 0, octeon_accel_fastpath_tick_timer, accel);
}


/****************************** Flow Management *****************************/

static void
octeon_accel_fastpath_init_d_flow(SshFastpathAccel accel,
                                  SshEngineFlowData d_flow)
{
  int i;

  memset(d_flow, 0, sizeof(*d_flow));

  d_flow->forward_nh_index = SSH_IPSEC_INVALID_INDEX;
  d_flow->reverse_nh_index = SSH_IPSEC_INVALID_INDEX;

  d_flow->forward_transform_index = SSH_IPSEC_INVALID_INDEX;
  d_flow->reverse_transform_index = SSH_IPSEC_INVALID_INDEX;

  for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
    {
      d_flow->forward_rx_transform_index[i] = SSH_IPSEC_INVALID_INDEX;
      d_flow->reverse_rx_transform_index[i] = SSH_IPSEC_INVALID_INDEX;
    }

  d_flow->incoming_forward_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
  d_flow->incoming_reverse_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
}

static SshUInt32
octeon_accel_fastpath_se_flow_flags_to_d_flow_flags(SeFastpathFlowData se_flow)
{
  return (SshUInt32) se_flow->upper_flags;
}

static void
octeon_accel_fastpath_d_flow_flags_to_se_flow_flags(SeFastpathFlowData se_flow,
                                                    SshUInt32 flags)
{
  if (flags & SSH_ENGINE_FLOW_D_IGNORE_IFNUM)
    se_flow->flag_ignore_iport = 1;
  else
    se_flow->flag_ignore_iport = 0;

  if (flags & SSH_ENGINE_FLOW_D_IPSECINCOMING)
    se_flow->flag_ipsec_incoming = 1;
  else
    se_flow->flag_ipsec_incoming = 0;

  /* Just store rest of the flags */
  se_flow->upper_flags = flags;
}

static Boolean
octeon_accel_fastpath_flow_is_slow(SshEngineFlowData d_flow)
{
  if ((d_flow->data_flags & SSH_ENGINE_FLOW_D_LOCAL_ENDPNT)
      || (d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING)
      || (d_flow->data_flags & SSH_ENGINE_FLOW_D_VALID) == 0
      || (d_flow->data_flags & SSH_ENGINE_FLOW_D_SPECIAL_FLOW))
    return TRUE;

#ifdef SSHDIST_IPSEC_NAT
  if (d_flow->data_flags
      & (SSH_ENGINE_FLOW_D_NAT_SRC | SSH_ENGINE_FLOW_D_NAT_DST))
    return TRUE;
#endif /* SSHDIST_IPSEC_NAT */

  switch (d_flow->ipproto)
    {
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_UDP:
      break;

    case SSH_IPPROTO_ESP:
    case SSH_IPPROTO_AH:
#ifndef OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY
      /* Process passby IPsec on slowpath */
      if ((d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0)
        return TRUE;
#endif /* !OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY */
      break;

    default:
      return TRUE;
    }

  /* Check that flow is well defined. */
  if ((d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING) == 0
      && (d_flow->forward_nh_index == SSH_IPSEC_INVALID_INDEX
          || d_flow->reverse_nh_index == SSH_IPSEC_INVALID_INDEX))
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Flow is not well defined, marking as slow"));
      return TRUE;
    }

  /* If this is an incoming IPsec flow, then also the transform could be
     checked here. For now detect slow transforms when starting transform
     execution. Adding the check here would save some cycles on the SE
     fastpath. However using special transforms should not be a common case. */

  return FALSE;
}

static void
octeon_accel_fastpath_d_flow_to_se_flow(SshFastpathAccel accel,
                                        SshEngineFlowData d_flow,
                                        SeFastpathFlowData se_flow,
                                        SshOcteonInternalFlowData i_flow)
{
  int i;
  unsigned char addr_buf[16];

  memcpy((unsigned char *) se_flow->fwd_flow_id.raw, d_flow->forward_flow_id,
         SSH_ENGINE_FLOW_ID_SIZE);
  memcpy((unsigned char *) se_flow->rev_flow_id.raw, d_flow->reverse_flow_id,
         SSH_ENGINE_FLOW_ID_SIZE);

  if (SSH_IP_IS6(&d_flow->src_ip))
    {
      SSH_IP6_ENCODE(&d_flow->src_ip, addr_buf);
      se_flow->src_ip_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      se_flow->src_ip_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);

      SSH_IP6_ENCODE(&d_flow->dst_ip, addr_buf);
      se_flow->dst_ip_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      se_flow->dst_ip_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);

      se_flow->flag_ip_version_6 = 1;
    }
  else if (SSH_IP_IS4(&d_flow->src_ip))
    {
      SSH_IP4_ENCODE(&d_flow->src_ip, addr_buf);
      se_flow->src_ip_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      se_flow->src_ip_high = 0;

      SSH_IP4_ENCODE(&d_flow->dst_ip, addr_buf);
      se_flow->dst_ip_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      se_flow->dst_ip_high = 0;

      se_flow->flag_ip_version_6 = 0;
    }
  else
    {
      se_flow->src_ip_low = 0;
      se_flow->src_ip_high = 0;
      se_flow->dst_ip_low = 0;
      se_flow->dst_ip_high = 0;

      se_flow->flag_ip_version_6 = 0;
    }

  octeon_accel_fastpath_d_flow_flags_to_se_flow_flags(se_flow,
                                                      d_flow->data_flags);

  se_flow->fwd_nh_index =
    OCT_ENGINE_INDEX_TO_SE_INDEX(d_flow->forward_nh_index);
  se_flow->rev_nh_index =
    OCT_ENGINE_INDEX_TO_SE_INDEX(d_flow->reverse_nh_index);

  se_flow->fwd_transform_index =
    OCT_ENGINE_INDEX_TO_SE_INDEX(d_flow->forward_transform_index);
  se_flow->rev_transform_index =
    OCT_ENGINE_INDEX_TO_SE_INDEX(d_flow->reverse_transform_index);

  for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
    {
      se_flow->fwd_rx_transform_index[i] =
        OCT_ENGINE_INDEX_TO_SE_INDEX(d_flow->forward_rx_transform_index[i]);
      se_flow->rev_rx_transform_index[i] =
        OCT_ENGINE_INDEX_TO_SE_INDEX(d_flow->reverse_rx_transform_index[i]);
    }

  se_flow->last_packet_time = d_flow->last_packet_time;

  switch (d_flow->ipproto)
    {
    case SSH_IPPROTO_UDP:
      if (d_flow->dst_port == 67 || d_flow->dst_port == 68)
        se_flow->u.protocol_xid = d_flow->protocol_xid;
      /* Fallthrough */

    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_SCTP:
      se_flow->src_port = d_flow->src_port;
      se_flow->dst_port = d_flow->dst_port;
      break;

    case SSH_IPPROTO_ICMP:
    case SSH_IPPROTO_IPV6ICMP:
      se_flow->u.icmp.id = d_flow->src_port;
      se_flow->u.icmp.type = (d_flow->dst_port & 0xff00) >> 8;
      se_flow->u.icmp.code = (d_flow->dst_port & 0x00ff);
      break;

    case SSH_IPPROTO_AH:
    case SSH_IPPROTO_ESP:
      se_flow->u.spi = d_flow->protocol_xid;
      break;

    default:
      break;
    }

  se_flow->ipproto = d_flow->ipproto;

  se_flow->fwd_iport =
    ssh_interceptor_octeon_ifnum_to_port(accel->interceptor,
                                         d_flow->incoming_forward_ifnum);
  se_flow->rev_iport =
    ssh_interceptor_octeon_ifnum_to_port(accel->interceptor,
                                         d_flow->incoming_reverse_ifnum);

  se_flow->generation = d_flow->generation;
  se_flow->flow_lru_level = d_flow->flow_lru_level;

  i_flow->nat_src_ip = d_flow->nat_src_ip;
  i_flow->nat_dst_ip = d_flow->nat_dst_ip;
  i_flow->nat_src_port = d_flow->nat_src_port;
  i_flow->nat_dst_port = d_flow->nat_dst_port;

  if (octeon_accel_fastpath_flow_is_slow(d_flow))
    se_flow->flag_slow = 1;
  else
    se_flow->flag_slow = 0;

#ifdef SSH_IPSEC_STATISTICS
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  se_flow->fwd_octets = d_flow->stats.forward_octets;
  se_flow->rev_octets = d_flow->stats.reverse_octets;
  se_flow->fwd_packets = d_flow->stats.forward_packets;
  se_flow->rev_packets = d_flow->stats.reverse_packets;
  se_flow->dropped_packets = d_flow->stats.drop_packets;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
#endif /* SSH_IPSEC_STATISTICS */
}

static void
octeon_accel_fastpath_se_flow_to_d_flow(SshFastpathAccel accel,
                                        SeFastpathFlowData se_flow,
                                        SshOcteonInternalFlowData i_flow,
                                        SshEngineFlowData d_flow)

{
  int i;
  unsigned char addr_buf[16];

  memset(d_flow, 0, sizeof(*d_flow));

  memcpy(d_flow->forward_flow_id, (unsigned char *) se_flow->fwd_flow_id.raw,
         SSH_ENGINE_FLOW_ID_SIZE);
  memcpy(d_flow->reverse_flow_id, (unsigned char *) se_flow->rev_flow_id.raw,
         SSH_ENGINE_FLOW_ID_SIZE);

  if (se_flow->flag_ip_version_6 == 1)
    {
      SSH_PUT_64BIT(addr_buf, se_flow->src_ip_high);
      SSH_PUT_64BIT(addr_buf + 8, se_flow->src_ip_low);
      SSH_IP6_DECODE(&d_flow->src_ip, addr_buf);

      SSH_PUT_64BIT(addr_buf, se_flow->dst_ip_high);
      SSH_PUT_64BIT(addr_buf + 8, se_flow->dst_ip_low);
      SSH_IP6_DECODE(&d_flow->dst_ip, addr_buf);
    }
  else
    {
      SSH_PUT_32BIT(addr_buf, se_flow->src_ip_low);
      SSH_IP4_DECODE(&d_flow->src_ip, addr_buf);

      SSH_PUT_32BIT(addr_buf, se_flow->dst_ip_low);
      SSH_IP4_DECODE(&d_flow->dst_ip, addr_buf);
    }

  d_flow->data_flags =
    octeon_accel_fastpath_se_flow_flags_to_d_flow_flags(se_flow);

  d_flow->forward_nh_index =
    OCT_SE_INDEX_TO_ENGINE_INDEX(se_flow->fwd_nh_index);
  d_flow->reverse_nh_index =
    OCT_SE_INDEX_TO_ENGINE_INDEX(se_flow->rev_nh_index);

  d_flow->forward_transform_index =
    OCT_SE_INDEX_TO_ENGINE_INDEX(se_flow->fwd_transform_index);
  d_flow->reverse_transform_index =
    OCT_SE_INDEX_TO_ENGINE_INDEX(se_flow->rev_transform_index);

  for (i = 0; i < SSH_ENGINE_NUM_RX_TRANSFORMS; i++)
    {
      d_flow->forward_rx_transform_index[i] =
        OCT_SE_INDEX_TO_ENGINE_INDEX(se_flow->fwd_rx_transform_index[i]);
      d_flow->reverse_rx_transform_index[i] =
        OCT_SE_INDEX_TO_ENGINE_INDEX(se_flow->rev_rx_transform_index[i]);
    }

  d_flow->last_packet_time = se_flow->last_packet_time;

  switch (se_flow->ipproto)
    {
    case SSH_IPPROTO_UDP:
      if (se_flow->fwd_flow_id.id.flags | OCTEON_SE_FASTPATH_FLOW_ID_FLAG_DHCP)
        d_flow->protocol_xid = se_flow->u.protocol_xid;
      /* Fallthrough */

    case SSH_IPPROTO_UDPLITE:
      d_flow->src_port = se_flow->src_port;
      d_flow->dst_port = se_flow->dst_port;
      d_flow->type = SSH_ENGINE_FLOW_TYPE_UDP;
      break;

    case SSH_IPPROTO_TCP:
      d_flow->src_port = se_flow->src_port;
      d_flow->dst_port = se_flow->dst_port;
      d_flow->type = SSH_ENGINE_FLOW_TYPE_TCP;
      break;

    case SSH_IPPROTO_SCTP:
      d_flow->src_port = se_flow->src_port;
      d_flow->dst_port = se_flow->dst_port;
      d_flow->type = SSH_ENGINE_FLOW_TYPE_RAW;
      break;

    case SSH_IPPROTO_ICMP:
    case SSH_IPPROTO_IPV6ICMP:
      d_flow->src_port = se_flow->u.icmp.id;
      d_flow->dst_port = ((se_flow->u.icmp.type << 8) | se_flow->u.icmp.code);
      d_flow->type = SSH_ENGINE_FLOW_TYPE_ICMP;
      break;

    case SSH_IPPROTO_AH:
    case SSH_IPPROTO_ESP:
      d_flow->protocol_xid = se_flow->u.spi;
      d_flow->type = SSH_ENGINE_FLOW_TYPE_RAW;
      break;

    default:
      break;
    }

  d_flow->ipproto = se_flow->ipproto;

  d_flow->incoming_forward_ifnum =
    ssh_interceptor_octeon_port_to_ifnum(accel->interceptor,
                                         se_flow->fwd_iport);
  d_flow->incoming_reverse_ifnum =
    ssh_interceptor_octeon_port_to_ifnum(accel->interceptor,
                                         se_flow->rev_iport);

  d_flow->generation = se_flow->generation;
  d_flow->flow_lru_level = se_flow->flow_lru_level;

  d_flow->nat_src_ip = i_flow->nat_src_ip;
  d_flow->nat_dst_ip = i_flow->nat_dst_ip;
  d_flow->nat_src_port = i_flow->nat_src_port;
  d_flow->nat_dst_port = i_flow->nat_dst_port;

#ifdef SSH_IPSEC_STATISTICS
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  d_flow->stats.forward_octets = se_flow->fwd_octets;
  d_flow->stats.reverse_octets = se_flow->rev_octets;
  d_flow->stats.forward_packets = se_flow->fwd_packets;
  d_flow->stats.reverse_packets = se_flow->rev_packets;
  d_flow->stats.drop_packets = se_flow->dropped_packets;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
#endif /* SSH_IPSEC_STATISTICS */
}

/** Add flow to flow hash table */
static void
octeon_accel_fastpath_flow_hash_add(SeFastpath fastpath,
                                    SeFastpathFlowData se_flow,
                                    uint32_t flow_index,
                                    uint32_t fwd_hash_bucket,
                                    uint32_t rev_hash_bucket)
{
  SSH_DEBUG(SSH_D_LOWOK,
            ("Adding flow to hash: flow_index %d hash_bucket fwd %d rev %d",
             flow_index, fwd_hash_bucket, rev_hash_bucket));

  SSH_ASSERT(flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);

  if (fwd_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
    {
      SSH_ASSERT(fwd_hash_bucket < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE);
      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, fwd_hash_bucket);
      se_flow->fwd_flow_index_next =
        fastpath->flow_id_hash[fwd_hash_bucket].fwd_flow_index;
      fastpath->flow_id_hash[fwd_hash_bucket].fwd_flow_index = flow_index;
      se_flow->in_fwd_hash = 1;
      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, fwd_hash_bucket);
    }

  if (rev_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
    {
      SSH_ASSERT(rev_hash_bucket < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE);
      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, rev_hash_bucket);
      se_flow->rev_flow_index_next =
        fastpath->flow_id_hash[rev_hash_bucket].rev_flow_index;
      fastpath->flow_id_hash[rev_hash_bucket].rev_flow_index = flow_index;
      se_flow->in_rev_hash = 1;
      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, rev_hash_bucket);
    }
}

/** Remove flow from flow hash table */
static void
octeon_accel_fastpath_flow_hash_remove(SeFastpath fastpath,
                                       SeFastpathFlowData se_flow,
                                       uint32_t fwd_hash_bucket,
                                       uint32_t rev_hash_bucket)
{
  uint32_t prev_flow_index, flow_index;
  SeFastpathFlowData flow;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Removing flow from hash: "
             "flow_index %d hash_bucket fwd %d rev %d",
             OCTEON_SE_FASTPATH_FLOW_INDEX(fastpath, se_flow),
             fwd_hash_bucket, rev_hash_bucket));

  /* Remove from forward flow id hash */
  if (fwd_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
    {
      SSH_ASSERT(fwd_hash_bucket < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE);
      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, fwd_hash_bucket);

      flow_index = fastpath->flow_id_hash[fwd_hash_bucket].fwd_flow_index;
      SSH_ASSERT(flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
      SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
      flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);
      if (se_flow == flow)
        {
          fastpath->flow_id_hash[fwd_hash_bucket].fwd_flow_index =
            se_flow->fwd_flow_index_next;
          se_flow->in_fwd_hash = 0;
        }
      else
        {
          prev_flow_index = flow_index;
          for (flow_index = flow->fwd_flow_index_next;
               flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX;
               flow_index = flow->fwd_flow_index_next)
            {
              SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
              flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);
              if (se_flow == flow)
                {
                  flow = OCTEON_SE_FASTPATH_FLOW(fastpath, prev_flow_index);
                  flow->fwd_flow_index_next = se_flow->fwd_flow_index_next;
                  se_flow->in_fwd_hash = 0;
                  break;
                }
              prev_flow_index = flow_index;
            }
        }

      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, fwd_hash_bucket);
    }

  /* Assert that flow is no longer in forward flow hash table */
  SSH_ASSERT(se_flow->in_fwd_hash == 0);

  /* Remove from reverse flow id hash */
  if (rev_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
    {
      SSH_ASSERT(rev_hash_bucket < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE);
      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, rev_hash_bucket);

      flow_index = fastpath->flow_id_hash[rev_hash_bucket].rev_flow_index;
      SSH_ASSERT(flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
      SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
      flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);
      if (se_flow == flow)
        {
          fastpath->flow_id_hash[rev_hash_bucket].rev_flow_index =
            se_flow->rev_flow_index_next;
          se_flow->in_rev_hash = 0;
        }
      else
        {
          prev_flow_index = flow_index;
          for (flow_index = flow->rev_flow_index_next;
               flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX;
               flow_index = flow->rev_flow_index_next)
            {
              SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
              flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);
              if (se_flow == flow)
                {
                  flow = OCTEON_SE_FASTPATH_FLOW(fastpath, prev_flow_index);
                  flow->rev_flow_index_next = se_flow->rev_flow_index_next;
                  se_flow->in_rev_hash = 0;
                  break;
                }
              prev_flow_index = flow_index;
            }
        }

      OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, rev_hash_bucket);
    }

  /* Assert that flow is no longer in reverse flow hash table */
  SSH_ASSERT(se_flow->in_rev_hash == 0);
}


/** FASTPATH_INIT_FLOW(fastpath, flow_index) */
SshEngineFlowData
fastpath_accel_init_flow(SshFastpathAccel accel, SshUInt32 flow_index)
{
  SeFastpathFlowData se_flow;

  SSH_DEBUG(SSH_D_LOWSTART, ("init_flow %d", flow_index));

  ssh_kernel_mutex_lock(accel->flow_lock);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
  se_flow = OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index);

  OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(accel->se, flow_index, se_flow);

  /* Initialize flow. */
  SSH_ASSERT(accel->flow->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->flow->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
  SSH_ASSERT(accel->flow->flow_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->flow->flow_index = flow_index);
  octeon_accel_fastpath_init_d_flow(accel, accel->flow->data);

  return accel->flow->data;
}

/** FASTPATH_GET_FLOW(fastpath, flow_index) */
SshEngineFlowData
fastpath_accel_get_flow(SshFastpathAccel accel, SshUInt32 flow_index)
{
  SeFastpathFlowData se_flow;
  SshOcteonInternalFlowData i_flow;

  SSH_DEBUG(SSH_D_LOWSTART, ("get_flow %d", flow_index));

  ssh_kernel_mutex_lock(accel->flow_lock);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
  se_flow = OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index);
  i_flow = OCTEON_ACCEL_FASTPATH_IFLOW(accel, flow_index);

  OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(accel->se, flow_index, se_flow);

  OCTEON_SE_FASTPATH_PREFETCH_FLOW(se_flow);

  /* Convert to d_flow */
  SSH_ASSERT(accel->flow->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->flow->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
  SSH_ASSERT(accel->flow->flow_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->flow->flow_index = flow_index);
  octeon_accel_fastpath_se_flow_to_d_flow(accel, se_flow, i_flow,
                                          accel->flow->data);

  return accel->flow->data;
}

/** FASTPATH_GET_READ_ONLY_FLOW(fastpath, flow_index) */
SshEngineFlowData
fastpath_accel_get_read_only_flow(SshFastpathAccel accel,
                                  SshUInt32 flow_index)
{
  SeFastpathFlowData se_flow;
  SshOcteonInternalFlowData i_flow;

  SSH_DEBUG(SSH_D_LOWSTART, ("get_read_only_flow %d", flow_index));

  ssh_kernel_mutex_lock(accel->flow_lock);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
  se_flow = OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index);
  i_flow = OCTEON_ACCEL_FASTPATH_IFLOW(accel, flow_index);

  OCTEON_SE_FASTPATH_FLOW_READ_LOCK(accel->se, flow_index, se_flow);

  OCTEON_SE_FASTPATH_PREFETCH_FLOW(se_flow);

  /* Convert to d_flow */
  SSH_ASSERT(accel->flow->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->flow->locked = OCTEON_ACCEL_LOCK_READ_LOCKED;
  SSH_ASSERT(accel->flow->flow_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->flow->flow_index = flow_index);
  octeon_accel_fastpath_se_flow_to_d_flow(accel, se_flow, i_flow,
                                          accel->flow->data);

  return accel->flow->data;
}

/** FASTPATH_COMMIT_FLOW(fastpath, flow_index, flow) */
void
fastpath_accel_commit_flow(SshFastpathAccel accel, SshUInt32 flow_index,
                           SshEngineFlowData data)
{
  SeFastpathFlowData se_flow;
  SshOcteonInternalFlowData i_flow;
  uint32_t old_fwd_hash_bucket, old_rev_hash_bucket;
  uint32_t new_fwd_hash_bucket, new_rev_hash_bucket;

  SSH_DEBUG(SSH_D_LOWSTART, ("commit_flow %d", flow_index));

  OCTEON_SE_FASTPATH_PREFETCH_FLOW(OCTEON_SE_FASTPATH_FLOW(accel->se,
                                                           flow_index));

  ssh_kernel_mutex_assert_is_locked(accel->flow_lock);

  SSH_ASSERT(accel->flow->data == data);
  SSH_ASSERT(accel->flow->flow_index == flow_index);
  OCTEON_DEBUG_RUN(accel->flow->flow_index = OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(accel->flow->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED);
  OCTEON_DEBUG_RUN(accel->flow->locked = OCTEON_ACCEL_LOCK_UNLOCKED);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
  se_flow = OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index);
  i_flow = OCTEON_ACCEL_FASTPATH_IFLOW(accel, flow_index);

  /* Store old hash buckets. */
  old_fwd_hash_bucket = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
  old_rev_hash_bucket = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
  if (se_flow->in_fwd_hash)
    old_fwd_hash_bucket =
      OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(accel->se,
                                          se_flow->fwd_flow_id.id.hash_id);
  if (se_flow->in_rev_hash)
    old_rev_hash_bucket =
      OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(accel->se,
                                          se_flow->rev_flow_id.id.hash_id);

  /* Convert to se_flow */
  octeon_accel_fastpath_d_flow_to_se_flow(accel, data, se_flow, i_flow);

  /* Mark flow in-use */
  se_flow->flag_in_use = 1;

  /* Check new hash buckets */
  new_fwd_hash_bucket = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
  new_rev_hash_bucket = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
  if (se_flow->fwd_flow_id.raw[0] != 0 || se_flow->fwd_flow_id.raw[1] != 0)
    new_fwd_hash_bucket =
      OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(accel->se,
                                          se_flow->fwd_flow_id.id.hash_id);
  if (se_flow->rev_flow_id.raw[0] != 0 || se_flow->rev_flow_id.raw[1] != 0)
    new_rev_hash_bucket =
      OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(accel->se,
                                          se_flow->rev_flow_id.id.hash_id);

  /* Re-add to flow hash table if hash buckets have changed. */
  if (old_fwd_hash_bucket != new_fwd_hash_bucket
      || old_rev_hash_bucket != new_rev_hash_bucket)
    {
      /* Mark flow invalid. Se fastpath will deschedule and retry later */
      se_flow->flag_invalid = 1;
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(accel->se, flow_index, se_flow);

      if (old_fwd_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE
          || old_rev_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
        {
          octeon_accel_fastpath_flow_hash_remove(accel->se, se_flow,
                                                 old_fwd_hash_bucket,
                                                 old_rev_hash_bucket);
        }

      if (new_fwd_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE
          || new_rev_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
        {
          octeon_accel_fastpath_flow_hash_add(accel->se, se_flow, flow_index,
                                              new_fwd_hash_bucket,
                                              new_rev_hash_bucket);
        }

      OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(accel->se, flow_index, se_flow);
    }

  /* Mark flow valid */
  se_flow->flag_invalid = 0;
  OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(accel->se, flow_index, se_flow);
  ssh_kernel_mutex_unlock(accel->flow_lock);
}

/** FASTPATH_UNINIT_FLOW(fastpath, flow_index, flow) */
void
fastpath_accel_uninit_flow(SshFastpathAccel accel, SshUInt32 flow_index,
                           SshEngineFlowData data)
{
  SeFastpathFlowData se_flow;
  SshOcteonInternalFlowData i_flow;
  uint32_t old_fwd_hash_bucket, old_rev_hash_bucket;

  SSH_DEBUG(SSH_D_LOWSTART, ("uninit_flow %d", flow_index));

  OCTEON_SE_FASTPATH_PREFETCH_FLOW(OCTEON_SE_FASTPATH_FLOW(accel->se,
                                                           flow_index));

  ssh_kernel_mutex_assert_is_locked(accel->flow_lock);

  SSH_ASSERT(accel->flow->data == data);
  SSH_ASSERT(accel->flow->flow_index == flow_index);
  OCTEON_DEBUG_RUN(accel->flow->flow_index = OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(accel->flow->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED);
  OCTEON_DEBUG_RUN(accel->flow->locked = OCTEON_ACCEL_LOCK_UNLOCKED);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
  se_flow = OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index);
  i_flow = OCTEON_ACCEL_FASTPATH_IFLOW(accel, flow_index);

  /* Store old hash buckets. */
  old_fwd_hash_bucket = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
  if (se_flow->in_fwd_hash)
    old_fwd_hash_bucket =
      OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(accel->se,
                                          se_flow->fwd_flow_id.id.hash_id);

  old_rev_hash_bucket = OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE;
  if (se_flow->in_rev_hash)
    old_rev_hash_bucket =
      OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(accel->se,
                                          se_flow->rev_flow_id.id.hash_id);

  /* Convert to se_flow */
  octeon_accel_fastpath_d_flow_to_se_flow(accel, data, se_flow, i_flow);

  /* Mark flow unused */
  se_flow->flag_in_use = 0;

  /* Remove from flow hash table. */
  if (old_fwd_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE
      || old_rev_hash_bucket != OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)
    {
      se_flow->flag_invalid = 1;
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(accel->se, flow_index, se_flow);

      octeon_accel_fastpath_flow_hash_remove(accel->se, se_flow,
                                             old_fwd_hash_bucket,
                                             old_rev_hash_bucket);
    }
  else
    OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(accel->se, flow_index, se_flow);

  ssh_kernel_mutex_unlock(accel->flow_lock);
}

/** FASTPATH_RELEASE_FLOW(fastpath, flow_index) */
void
fastpath_accel_release_flow(SshFastpathAccel accel, SshUInt32 flow_index)
{
  SeFastpathFlowData se_flow;

  SSH_DEBUG(SSH_D_LOWSTART, ("release_flow %d", flow_index));

  ssh_kernel_mutex_assert_is_locked(accel->flow_lock);

  SSH_ASSERT(accel->flow->flow_index == flow_index);
  OCTEON_DEBUG_RUN(accel->flow->flow_index =
                   OCTEON_SE_FASTPATH_INVALID_INDEX);

  SSH_ASSERT(flow_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
  se_flow = OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index);

  SSH_ASSERT(accel->flow->locked != OCTEON_ACCEL_LOCK_UNLOCKED);
  if (accel->flow->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED)
    {
      OCTEON_DEBUG_RUN(accel->flow->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(accel->se, flow_index, se_flow);
    }
  else if (accel->flow->locked == OCTEON_ACCEL_LOCK_READ_LOCKED)
    {
      OCTEON_DEBUG_RUN(accel->flow->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
      OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(accel->se, flow_index, se_flow);
    }
  else
    SSH_NOTREACHED;

  ssh_kernel_mutex_unlock(accel->flow_lock);
}

/** FASTPATH_REKEY_FLOW(fastpath, flow_index) */
void
fastpath_accel_rekey_flow(SshFastpathAccel accel, SshUInt32 flow_index)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("rekey_flow %d", flow_index));
  /* There's nothing the accelerated fastpath needs to do here. */
}


/****************************** Transform Management ************************/

static void
octeon_accel_fastpath_init_d_trd(SshFastpathAccel accel,
                                 SshEngineTransformData d_trd,
                                 SshUInt32 tr_index)
{
  memset(d_trd, 0, sizeof(*d_trd));
  d_trd->tr_index = tr_index;
  d_trd->own_ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
}

static Boolean
octeon_accel_fastpath_trd_is_special(SshFastpathAccel accel,
                                     SshEngineTransformData d_trd)
{

  /* Check if any unsupported transforms are defined. */
  if (d_trd->transform & (SSH_PM_CRYPT_EXT1
                          | SSH_PM_CRYPT_EXT2
                          | SSH_PM_CRYPT_DES
                          | SSH_PM_CRYPT_AES_CTR
#ifndef OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM
                          | SSH_PM_CRYPT_AES_GCM
                          | SSH_PM_CRYPT_AES_GCM_8
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */
                          | SSH_PM_CRYPT_AES_GCM_12
                          | SSH_PM_CRYPT_NULL_AUTH_AES_GMAC
                          | SSH_PM_CRYPT_AES_CCM
                          | SSH_PM_CRYPT_AES_CCM_8
                          | SSH_PM_CRYPT_AES_CCM_12
                          | SSH_PM_MAC_EXT1
                          | SSH_PM_MAC_EXT2
                          | SSH_PM_MAC_XCBC_AES
#ifndef OCTEON_SE_FASTPATH_TRANSFORM_AH
                          | SSH_PM_IPSEC_AH
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_AH */
#ifndef OCTEON_SE_FASTPATH_TRANSFORM_NATT
                          | SSH_PM_IPSEC_NATT
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_NATT */
                          | SSH_PM_IPSEC_IPCOMP
                          | SSH_PM_IPSEC_INT_NAT
#ifdef SSHDIST_IPSEC_NAT
                          | SSH_PM_IPSEC_PORT_NAT
#endif /* SSHDIST_IPSEC_NAT */
#ifdef SSHDIST_L2TP
                          | SSH_PM_IPSEC_L2TP
#endif /* SSHDIST_L2TP */
#ifndef OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ
                          | SSH_PM_IPSEC_LONGSEQ
#endif /* !OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */
                          ))
    return TRUE;

#ifndef OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE
  if ((d_trd->transform & SSH_PM_IPSEC_TUNNEL) == 0)
    return TRUE;
#endif /* !OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */

#ifndef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
  if ((d_trd->transform & SSH_PM_MAC_HMAC_SHA2)
      && d_trd->mac_key_size == 32)
    return TRUE;
#endif /* !OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

#ifndef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
  if ((d_trd->transform & SSH_PM_MAC_HMAC_SHA2)
      && (d_trd->mac_key_size == 48 || d_trd->mac_key_size == 64))
    return TRUE;
#endif /* !OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Extension selectors are not implemented */
  if (d_trd->decapsulate_extension)
    return TRUE;
#endif /** (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /* Nested tunneling is not implemented */
  if (d_trd->restart_after_tre)
    return TRUE;

  return FALSE;
}

static SshUInt32
octeon_accel_fastpath_d_transform_to_se_transform(SshPmTransform d_transform)
{
  SshUInt32 se_transform = 0;

  /* Map supported transforms from engine format to SE format. Note that
     any unsupported transforms are not converted here. The engine transforms
     are stored as such in the i_trd. */
  if (d_transform & SSH_PM_CRYPT_NULL)
    se_transform |= OCTEON_SE_FASTPATH_CRYPT_NULL;
  if (d_transform & SSH_PM_CRYPT_3DES)
    se_transform |= OCTEON_SE_FASTPATH_CRYPT_3DES;
  if (d_transform & SSH_PM_CRYPT_AES)
    se_transform |= OCTEON_SE_FASTPATH_CRYPT_AES;
  if (d_transform & SSH_PM_CRYPT_AES_GCM)
    se_transform |= OCTEON_SE_FASTPATH_CRYPT_AES_GCM;
  if (d_transform & SSH_PM_CRYPT_AES_GCM_8)
    se_transform |= OCTEON_SE_FASTPATH_CRYPT_AES_GCM_8;
  if (d_transform & SSH_PM_MAC_HMAC_MD5)
    se_transform |= OCTEON_SE_FASTPATH_MAC_HMAC_MD5;
  if (d_transform & SSH_PM_MAC_HMAC_SHA1)
    se_transform |= OCTEON_SE_FASTPATH_MAC_HMAC_SHA1;
  if (d_transform & SSH_PM_MAC_HMAC_SHA2)
    se_transform |= OCTEON_SE_FASTPATH_MAC_HMAC_SHA2;
  if (d_transform & SSH_PM_IPSEC_ESP)
    se_transform |= OCTEON_SE_FASTPATH_IPSEC_ESP;
  if (d_transform & SSH_PM_IPSEC_AH)
    se_transform |= OCTEON_SE_FASTPATH_IPSEC_AH;
  if (d_transform & SSH_PM_IPSEC_ANTIREPLAY)
    se_transform |= OCTEON_SE_FASTPATH_IPSEC_ANTIREPLAY;
  if (d_transform & SSH_PM_IPSEC_NATT)
    se_transform |= OCTEON_SE_FASTPATH_IPSEC_NATT;
  if (d_transform & SSH_PM_IPSEC_LONGSEQ)
    se_transform |= OCTEON_SE_FASTPATH_IPSEC_LONGSEQ;

  return se_transform;
}

static void
octeon_accel_fastpath_d_trd_to_se_trd(SshFastpathAccel accel,
                                      SshEngineTransformData d_trd,
                                      SeFastpathTransformData se_trd,
                                      SshOcteonInternalTransformData i_trd)
{
  unsigned char addr_buf[16];

  /* Fill se_trd with data that is relevant to SE fastpath. */

  se_trd->transform =
    octeon_accel_fastpath_d_transform_to_se_transform(d_trd->transform);

  if (SSH_IP_IS6(&d_trd->gw_addr))
    {
      SSH_IP6_ENCODE(&d_trd->gw_addr, addr_buf);
      se_trd->gw_addr_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      se_trd->gw_addr_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);
      se_trd->ip_version_6 = 1;
      i_trd->gw_addr_undefined = 0;
    }
  else if (SSH_IP_IS4(&d_trd->gw_addr))
    {
      SSH_IP4_ENCODE(&d_trd->gw_addr, addr_buf);
      se_trd->gw_addr_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      se_trd->gw_addr_high = 0;
      se_trd->ip_version_6 = 0;
      i_trd->gw_addr_undefined = 0;
    }
  else
    {
      se_trd->gw_addr_high = 0;
      se_trd->gw_addr_low = 0;
      se_trd->ip_version_6 = 0;
      i_trd->gw_addr_undefined = 1;
    }

  if (SSH_IP_IS6(&d_trd->own_addr))
    {
      SSH_IP6_ENCODE(&d_trd->own_addr, addr_buf);
      se_trd->own_addr_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      se_trd->own_addr_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);
      i_trd->own_addr_undefined = 0;
    }
  else if (SSH_IP_IS4(&d_trd->own_addr))
    {
      SSH_IP4_ENCODE(&d_trd->own_addr, addr_buf);
      se_trd->own_addr_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      se_trd->own_addr_high = 0;
      i_trd->own_addr_undefined = 0;
    }
  else
    {
      se_trd->own_addr_high = 0;
      se_trd->own_addr_low = 0;
      i_trd->own_addr_undefined = 1;
    }

  se_trd->port = ssh_interceptor_octeon_ifnum_to_port(accel->interceptor,
                                                      d_trd->own_ifnum);
  se_trd->natt_local_port = d_trd->local_port;
  se_trd->natt_remote_port = d_trd->remote_port;

  se_trd->inbound_tunnel_id = d_trd->inbound_tunnel_id;

  if (d_trd->transform & SSH_PM_IPSEC_TUNNEL)
    se_trd->tunnel_mode = 1;
  else
    se_trd->tunnel_mode = 0;

  if (d_trd->transform & SSH_PM_IPSEC_ESP)
    {
      se_trd->nh = SSH_IPPROTO_ESP;
      se_trd->spi_out = d_trd->spis[SSH_PME_SPI_ESP_OUT];
      se_trd->spi_in = d_trd->spis[SSH_PME_SPI_ESP_IN];
      se_trd->old_spi_out = d_trd->old_spis[SSH_PME_SPI_ESP_OUT];
      se_trd->old_spi_in = d_trd->old_spis[SSH_PME_SPI_ESP_IN];
    }
  if (d_trd->transform & SSH_PM_IPSEC_AH)
    {
      se_trd->nh = SSH_IPPROTO_AH;
      se_trd->spi_out = d_trd->spis[SSH_PME_SPI_AH_OUT];
      se_trd->spi_in = d_trd->spis[SSH_PME_SPI_AH_IN];
      se_trd->old_spi_out = d_trd->old_spis[SSH_PME_SPI_AH_OUT];
      se_trd->old_spi_in = d_trd->old_spis[SSH_PME_SPI_AH_IN];
    }

  if (d_trd->transform & SSH_PM_IPSEC_NATT)
    se_trd->nh = SSH_IPPROTO_UDP;

  se_trd->packet_enlargement = d_trd->packet_enlargement;

  se_trd->seq = d_trd->out_packets_high;
  se_trd->seq = (se_trd->seq << 32) | d_trd->out_packets_low;

  memcpy(se_trd->keymat, d_trd->keymat, sizeof(d_trd->keymat));

  se_trd->cipher_key_size = d_trd->cipher_key_size;
  se_trd->cipher_iv_size = d_trd->cipher_iv_size;
  se_trd->cipher_nonce_size = d_trd->cipher_nonce_size;
  se_trd->mac_key_size = d_trd->mac_key_size;

  if (octeon_accel_fastpath_trd_is_special(accel, d_trd))
    se_trd->is_special = 1;
  else
    se_trd->is_special = 0;

  se_trd->last_in_packet_time = d_trd->last_in_packet_time;
  se_trd->last_out_packet_time = d_trd->last_out_packet_time;

  memcpy(se_trd->old_keymat, d_trd->old_keymat, sizeof(d_trd->old_keymat));

  se_trd->replay_offset = d_trd->replay_offset_high;
  se_trd->replay_offset = ((se_trd->replay_offset << 32) |
                           d_trd->replay_offset_low);

  SSH_ASSERT(sizeof(se_trd->replay_mask) == sizeof(d_trd->replay_mask));
  memcpy(se_trd->replay_mask, d_trd->replay_mask, sizeof(se_trd->replay_mask));

  se_trd->old_replay_offset = d_trd->old_replay_offset_high;
  se_trd->old_replay_offset = ((se_trd->old_replay_offset << 32) |
                               d_trd->old_replay_offset_low);
  memcpy(se_trd->old_replay_mask, d_trd->old_replay_mask,
         sizeof(se_trd->old_replay_mask));

  se_trd->pmtu_received = d_trd->pmtu_received;

  switch (d_trd->df_bit_processing)
    {
    case SSH_ENGINE_DF_KEEP:
      se_trd->df_bit_processing = OCTEON_SE_FASTPATH_DF_KEEP;
      break;
    case SSH_ENGINE_DF_SET:
      se_trd->df_bit_processing = OCTEON_SE_FASTPATH_DF_SET;
      break;
    case SSH_ENGINE_DF_CLEAR:
      se_trd->df_bit_processing = OCTEON_SE_FASTPATH_DF_CLEAR;
      break;
    default:
      SSH_NOTREACHED;
    }

#ifdef SSH_IPSEC_STATISTICS
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  se_trd->in_octets = d_trd->stats.in_octets;
  se_trd->out_octets = d_trd->stats.out_octets;
  se_trd->in_packets = d_trd->stats.in_packets;
  se_trd->out_packets = d_trd->stats.out_packets;
  se_trd->drop_packets = d_trd->stats.drop_packets;
  se_trd->num_mac_fails = d_trd->stats.num_mac_fails;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
#endif /* SSH_IPSEC_STATISTICS */

  /* Following fields are not used in SE fastpath. Store these internally
     to i_trd. */

  i_trd->transform = d_trd->transform;

#ifdef SSHDIST_L2TP
  i_trd->l2tp_local_port = d_trd->l2tp_local_port;
  i_trd->l2tp_remote_port = d_trd->l2tp_remote_port;
  i_trd->l2tp_local_tunnel_id = d_trd->l2tp_local_tunnel_id;
  i_trd->l2tp_local_session_id = d_trd->l2tp_local_session_id;
  i_trd->l2tp_remote_tunnel_id = d_trd->l2tp_remote_tunnel_id;
  i_trd->l2tp_remote_session_id = d_trd->l2tp_remote_session_id;
  i_trd->l2tp_seq_ns = d_trd->l2tp_seq_ns;
  i_trd->l2tp_seq_nr = d_trd->l2tp_seq_nr;
  i_trd->l2tp_flags = d_trd->l2tp_flags;
#endif /* SSHDIST_L2TP */

  memcpy(i_trd->spis, d_trd->spis, sizeof(i_trd->spis));
  memcpy(i_trd->old_spis, d_trd->old_spis, sizeof(i_trd->old_spis));

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* SE fastpath does not use NAT-T OAs */
  i_trd->natt_flags = d_trd->natt_flags;
  memcpy(i_trd->natt_oa_l, d_trd->natt_oa_l, sizeof(i_trd->natt_oa_l));
  memcpy(i_trd->natt_oa_r, d_trd->natt_oa_r, sizeof(i_trd->natt_oa_r));
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Extension selectors are not implemented on SE fastpath. */
  memcpy(i_trd->extension, d_trd->extension, sizeof(i_trd->extension));
  i_trd->decapsulate_extension = d_trd->decapsulate_extension;
#endif /** (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  i_trd->restart_after_tre = d_trd->restart_after_tre;
  i_trd->nesting_level = d_trd->nesting_level;
  i_trd->tr_index = d_trd->tr_index;
}

static void
octeon_accel_fastpath_se_trd_to_d_trd(SshFastpathAccel accel,
                                      SeFastpathTransformData se_trd,
                                      SshOcteonInternalTransformData i_trd,
                                      SshEngineTransformData d_trd)
{
  unsigned char addr_buf[16];

  /* Fill d_trd from data in se_trd. */

  if (se_trd->ip_version_6 == 1)
    {
      SSH_PUT_64BIT(addr_buf, se_trd->gw_addr_high);
      SSH_PUT_64BIT(addr_buf + 8, se_trd->gw_addr_low);
      SSH_IP6_DECODE(&d_trd->gw_addr, addr_buf);

      SSH_PUT_64BIT(addr_buf, se_trd->own_addr_high);
      SSH_PUT_64BIT(addr_buf + 8, se_trd->own_addr_low);
      SSH_IP6_DECODE(&d_trd->own_addr, addr_buf);
    }
  else
    {
      if (i_trd->gw_addr_undefined)
        SSH_IP_UNDEFINE(&d_trd->gw_addr);
      else
        {
          SSH_PUT_32BIT(addr_buf, se_trd->gw_addr_low);
          SSH_IP4_DECODE(&d_trd->gw_addr, addr_buf);
        }

      if (i_trd->own_addr_undefined)
        SSH_IP_UNDEFINE(&d_trd->own_addr);
      else
        {
          SSH_PUT_32BIT(addr_buf, se_trd->own_addr_low);
          SSH_IP4_DECODE(&d_trd->own_addr, addr_buf);
        }
    }

  d_trd->own_ifnum = ssh_interceptor_octeon_port_to_ifnum(accel->interceptor,
                                                          se_trd->port);

  d_trd->local_port = se_trd->natt_local_port;
  d_trd->remote_port = se_trd->natt_remote_port;

  d_trd->inbound_tunnel_id = se_trd->inbound_tunnel_id;

  d_trd->packet_enlargement = se_trd->packet_enlargement;

  d_trd->out_packets_high = (se_trd->seq >> 32) & 0xffffffff;
  d_trd->out_packets_low = se_trd->seq & 0xffffffff;

  memcpy(d_trd->keymat, se_trd->keymat, sizeof(d_trd->keymat));

  d_trd->cipher_key_size = se_trd->cipher_key_size;
  d_trd->cipher_iv_size = se_trd->cipher_iv_size;
  d_trd->cipher_nonce_size = se_trd->cipher_nonce_size;
  d_trd->mac_key_size = se_trd->mac_key_size;

  d_trd->last_in_packet_time = se_trd->last_in_packet_time;
  d_trd->last_out_packet_time = se_trd->last_out_packet_time;

  memcpy(d_trd->old_keymat, se_trd->old_keymat, sizeof(d_trd->old_keymat));

  d_trd->replay_offset_high = (se_trd->replay_offset >> 32) & 0xffffffff;
  d_trd->replay_offset_low = se_trd->replay_offset & 0xffffffff;

  memcpy(d_trd->replay_mask, se_trd->replay_mask, sizeof(d_trd->replay_mask));

  d_trd->old_replay_offset_high =
    (se_trd->old_replay_offset >> 32) & 0xffffffff;
  d_trd->old_replay_offset_low = se_trd->old_replay_offset & 0xffffffff;

  memcpy(d_trd->old_replay_mask, se_trd->old_replay_mask,
         sizeof(d_trd->old_replay_mask));

  d_trd->pmtu_received = se_trd->pmtu_received;

  switch (se_trd->df_bit_processing)
    {
    case OCTEON_SE_FASTPATH_DF_KEEP:
      d_trd->df_bit_processing = SSH_ENGINE_DF_KEEP;
      break;
    case OCTEON_SE_FASTPATH_DF_SET:
      d_trd->df_bit_processing = SSH_ENGINE_DF_SET;
      break;
    case OCTEON_SE_FASTPATH_DF_CLEAR:
      d_trd->df_bit_processing = SSH_ENGINE_DF_CLEAR;
      break;
    default:
      SSH_NOTREACHED;
    }

#ifdef SSH_IPSEC_STATISTICS
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  d_trd->stats.in_octets = se_trd->in_octets;
  d_trd->stats.out_octets = se_trd->out_octets;
  d_trd->stats.in_packets = se_trd->in_packets;
  d_trd->stats.out_packets = se_trd->out_packets;
  d_trd->stats.drop_packets = se_trd->drop_packets;
  d_trd->stats.num_mac_fails = se_trd->num_mac_fails;
#else /* OCTEON_SE_FASTPATH_STATISTICS */
  memset(&d_trd->stats, 0, sizeof(d_trd->stats));
#endif /* OCTEON_SE_FASTPATH_STATISTICS */
#endif /* SSH_IPSEC_STATISTICS */

  /* Following fields are not modified/used by SE fastpath. Fill these
     fields to d_trd from internal i_trd. */

  d_trd->transform = i_trd->transform;

#ifdef SSHDIST_L2TP
  d_trd->l2tp_local_port = i_trd->l2tp_local_port;
  d_trd->l2tp_remote_port = i_trd->l2tp_remote_port;
  d_trd->l2tp_local_tunnel_id = i_trd->l2tp_local_tunnel_id;
  d_trd->l2tp_local_session_id = i_trd->l2tp_local_session_id;
  d_trd->l2tp_remote_tunnel_id = i_trd->l2tp_remote_tunnel_id;
  d_trd->l2tp_remote_session_id = i_trd->l2tp_remote_session_id;
  d_trd->l2tp_seq_ns = i_trd->l2tp_seq_ns;
  d_trd->l2tp_seq_nr = i_trd->l2tp_seq_nr;
  d_trd->l2tp_flags = i_trd->l2tp_flags;
#endif /* SSHDIST_L2TP */

  memcpy(d_trd->spis, i_trd->spis, sizeof(d_trd->spis));
  memcpy(d_trd->old_spis, i_trd->old_spis, sizeof(d_trd->old_spis));

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* SE fastpath does not use NAT-T OAs */
  d_trd->natt_flags = i_trd->natt_flags;
  memcpy(d_trd->natt_oa_l, i_trd->natt_oa_l, sizeof(d_trd->natt_oa_l));
  memcpy(d_trd->natt_oa_r, i_trd->natt_oa_r, sizeof(d_trd->natt_oa_r));
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /* Extension selectors are not implemented on SE fastpath. */
  memcpy(d_trd->extension, i_trd->extension, sizeof(d_trd->extension));
  d_trd->decapsulate_extension = i_trd->decapsulate_extension;
#endif /** (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  d_trd->restart_after_tre = i_trd->restart_after_tre;
  d_trd->nesting_level = i_trd->nesting_level;
  d_trd->tr_index = i_trd->tr_index;
}

static void
octeon_accel_fastpath_uninit_se_trd(SshFastpathAccel accel,
                                    SeFastpathTransformData se_trd,
                                    SshOcteonInternalTransformData i_trd)
{
  /* Memset key material to zero */
  memset(se_trd->keymat, 0, sizeof(se_trd->keymat));
  memset(se_trd->old_keymat, 0, sizeof(se_trd->old_keymat));
}

/** FASTPATH_INIT_TRD(fastpath, trd_index) */
SshEngineTransformData
fastpath_accel_init_trd(SshFastpathAccel accel, SshUInt32 trd_index)
{
  SeFastpathTransformData se_trd;
  SshUInt32 trd_i = trd_index & 0x00ffffff;

  SSH_DEBUG(SSH_D_LOWSTART, ("init_trd %d (generation %d)",
                             0x00ffffff & trd_index, trd_index >> 24));

  ssh_kernel_mutex_lock(accel->trd_lock);

  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);
  se_trd = OCTEON_SE_FASTPATH_TRD(accel->se, trd_i);

  OCTEON_SE_FASTPATH_TRD_WRITE_LOCK(accel->se, trd_i, se_trd);

  /* Initialize d_trd. */
  SSH_ASSERT(accel->trd->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->trd->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
  SSH_ASSERT(accel->trd->trd_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->trd->trd_index = trd_index);
  octeon_accel_fastpath_init_d_trd(accel, accel->trd->data, trd_index);

  return accel->trd->data;
}

/** FASTPATH_GET_TRD(fastpath, trd_index) */
SshEngineTransformData
fastpath_accel_get_trd(SshFastpathAccel accel, SshUInt32 trd_index)
{
  SeFastpathTransformData se_trd;
  SshOcteonInternalTransformData i_trd;
  SshUInt32 trd_i = trd_index & 0x00ffffff;

  SSH_DEBUG(SSH_D_LOWSTART, ("get_trd %d (generation %d)",
                             0x00ffffff & trd_index, trd_index >> 24));

  ssh_kernel_mutex_lock(accel->trd_lock);

  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);
  se_trd = OCTEON_SE_FASTPATH_TRD(accel->se, trd_i);
  i_trd = OCTEON_ACCEL_FASTPATH_ITRD(accel, trd_i);

  OCTEON_SE_FASTPATH_TRD_WRITE_LOCK(accel->se, trd_i, se_trd);

  OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd);

  SSH_ASSERT(accel->trd->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->trd->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
  SSH_ASSERT(accel->trd->trd_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->trd->trd_index = trd_index);

  /* Convert to d_trd. */
  octeon_accel_fastpath_se_trd_to_d_trd(accel, se_trd, i_trd,
                                        accel->trd->data);

  return accel->trd->data;
}

/** FASTPATH_GET_READ_ONLY_TRD(fastpath, trd_index) */
SshEngineTransformData
fastpath_accel_get_read_only_trd(SshFastpathAccel accel, SshUInt32 trd_index)
{
  SeFastpathTransformData se_trd;
  SshOcteonInternalTransformData i_trd;
  SshUInt32 trd_i = trd_index & 0x00ffffff;

  SSH_DEBUG(SSH_D_LOWSTART, ("get_read_only_trd %d (generation %d)",
                             0x00ffffff & trd_index, trd_index >> 24));

  ssh_kernel_mutex_lock(accel->trd_lock);

  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);
  se_trd = OCTEON_SE_FASTPATH_TRD(accel->se, trd_i);
  i_trd = OCTEON_ACCEL_FASTPATH_ITRD(accel, trd_i);

  OCTEON_SE_FASTPATH_TRD_READ_LOCK(accel->se, trd_i, se_trd);

  OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd);

  SSH_ASSERT(accel->trd->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->trd->locked = OCTEON_ACCEL_LOCK_READ_LOCKED;
  SSH_ASSERT(accel->trd->trd_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->trd->trd_index = trd_index);

  /* Convert to d_trd. */
  octeon_accel_fastpath_se_trd_to_d_trd(accel, se_trd, i_trd,
                                        accel->trd->data);

  return accel->trd->data;
}

/** FASTPATH_COMMIT_TRD(fastpath, trd_index, trd) */
void
fastpath_accel_commit_trd(SshFastpathAccel accel, SshUInt32 trd_index,
                          SshEngineTransformData data)
{
  SeFastpathTransformData se_trd;
  SshOcteonInternalTransformData i_trd;
  SshUInt32 trd_i = trd_index & 0x00ffffff;

  SSH_DEBUG(SSH_D_LOWSTART, ("commit_trd %d (generation %d)",
                             0x00ffffff & trd_index, trd_index >> 24));

  OCTEON_SE_FASTPATH_PREFETCH_TRD(OCTEON_SE_FASTPATH_TRD(accel->se, trd_i));

  ssh_kernel_mutex_assert_is_locked(accel->trd_lock);

  SSH_ASSERT(accel->trd->data == data);
  SSH_ASSERT(accel->trd->trd_index == trd_index);
  OCTEON_DEBUG_RUN(accel->trd->trd_index = OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(accel->trd->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED);

  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);
  se_trd = OCTEON_SE_FASTPATH_TRD(accel->se, trd_i);
  i_trd = OCTEON_ACCEL_FASTPATH_ITRD(accel, trd_i);

  /* Convert to se_trd */
  octeon_accel_fastpath_d_trd_to_se_trd(accel, data, se_trd, i_trd);

  OCTEON_DEBUG_RUN(accel->trd->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
  OCTEON_SE_FASTPATH_TRD_WRITE_UNLOCK(accel->se, trd_i, se_trd);
  ssh_kernel_mutex_unlock(accel->trd_lock);
}

/** FASTPATH_UNINIT_TRD(fastpath, trd_index, trd) */
void
fastpath_accel_uninit_trd(SshFastpathAccel accel, SshUInt32 trd_index,
                          SshEngineTransformData data)
{
  SeFastpathTransformData se_trd;
  SshOcteonInternalTransformData i_trd;
  SshUInt32 trd_i = trd_index & 0x00ffffff;

  SSH_DEBUG(SSH_D_LOWSTART, ("uninit_trd %d (generation %d)",
                             0x00ffffff & trd_index, trd_index >> 24));

  ssh_kernel_mutex_assert_is_locked(accel->trd_lock);

  SSH_ASSERT(accel->trd->data == data);
  SSH_ASSERT(accel->trd->trd_index == trd_index);
  OCTEON_DEBUG_RUN(accel->trd->trd_index = OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(accel->trd->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED);

  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);
  se_trd = OCTEON_SE_FASTPATH_TRD(accel->se, trd_i);
  i_trd = OCTEON_ACCEL_FASTPATH_ITRD(accel, trd_i);

  /* Convert to se_trd */
  octeon_accel_fastpath_d_trd_to_se_trd(accel, data, se_trd, i_trd);

  /* Clear sensitive fields from se_trd */
  octeon_accel_fastpath_uninit_se_trd(accel, se_trd, i_trd);

  OCTEON_DEBUG_RUN(accel->trd->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
  OCTEON_SE_FASTPATH_TRD_WRITE_UNLOCK(accel->se, trd_i, se_trd);
  ssh_kernel_mutex_unlock(accel->trd_lock);
}

/** FASTPATH_RELEASE_TRD(fastpath, trd_index) */
void
fastpath_accel_release_trd(SshFastpathAccel accel, SshUInt32 trd_index)
{
  SeFastpathTransformData se_trd;
  SshUInt32 trd_i = trd_index & 0x00ffffff;

  SSH_DEBUG(SSH_D_LOWSTART, ("release_trd %d (generation %d)",
                             0x00ffffff & trd_index, trd_index >> 24));

  ssh_kernel_mutex_assert_is_locked(accel->trd_lock);

  SSH_ASSERT(accel->trd->trd_index == trd_index);
  OCTEON_DEBUG_RUN(accel->trd->trd_index = OCTEON_SE_FASTPATH_INVALID_INDEX);

  SSH_ASSERT(trd_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(trd_i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE);
  se_trd = OCTEON_SE_FASTPATH_TRD(accel->se, trd_i);

  SSH_ASSERT(accel->trd->locked != OCTEON_ACCEL_LOCK_UNLOCKED);
  if (accel->trd->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED)
    {
      OCTEON_DEBUG_RUN(accel->trd->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
      OCTEON_SE_FASTPATH_TRD_WRITE_UNLOCK(accel->se, trd_i, se_trd);
    }
  else if (accel->trd->locked == OCTEON_ACCEL_LOCK_READ_LOCKED)
    {
      OCTEON_DEBUG_RUN(accel->trd->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
      OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(accel->se, trd_i, se_trd);
    }
  else
    SSH_NOTREACHED;

  ssh_kernel_mutex_unlock(accel->trd_lock);
}


/****************************** NextHop Management **************************/

static Boolean
octeon_accel_fastpath_nh_is_slow(SshEngineNextHopData d_nh)
{
  if (d_nh->flags & (SSH_ENGINE_NH_REROUTE | SSH_ENGINE_NH_EMBRYONIC))
    return TRUE;

  return FALSE;
}

static void
octeon_accel_fastpath_init_d_nh(SshFastpathAccel accel,
                                SshEngineNextHopData d_nh)
{
  memset(d_nh, 0, sizeof(*d_nh));

  d_nh->ifnum = SSH_INTERCEPTOR_INVALID_IFNUM;
}

static void
octeon_accel_fastpath_d_nh_to_se_nh(SshFastpathAccel accel,
                                    SshEngineNextHopData d_nh,
                                    SeFastpathNextHopData se_nh,
                                    SshOcteonInternalNextHopData i_nh)
{
  se_nh->mtu = d_nh->mtu;
  se_nh->port = ssh_interceptor_octeon_ifnum_to_port(accel->interceptor,
                                                     d_nh->ifnum);
  se_nh->media_hdrlen = d_nh->media_hdr_len;
  SSH_ASSERT(d_nh->media_hdr_len <= sizeof(se_nh->media_hdr.data));
  memcpy(se_nh->media_hdr.data, d_nh->mediahdr, d_nh->media_hdr_len);
  se_nh->min_packet_len = d_nh->min_packet_len;

  i_nh->src = d_nh->src;
  i_nh->dst = d_nh->dst;
  i_nh->flags = d_nh->flags;
  i_nh->mediatype = d_nh->mediatype;
  i_nh->media_protocol = d_nh->media_protocol;

  if (octeon_accel_fastpath_nh_is_slow(d_nh))
    se_nh->flag_slow = 1;
  else
    se_nh->flag_slow = 0;
}


static void
octeon_accel_fastpath_se_nh_to_d_nh(SshFastpathAccel accel,
                                    SeFastpathNextHopData se_nh,
                                    SshOcteonInternalNextHopData i_nh,
                                    SshEngineNextHopData d_nh)
{
  memset(d_nh, 0, sizeof(*d_nh));

  d_nh->src = i_nh->src;
  d_nh->dst = i_nh->dst;
  d_nh->ifnum = ssh_interceptor_octeon_port_to_ifnum(accel->interceptor,
                                                     se_nh->port);
  d_nh->flags = i_nh->flags;
  d_nh->mediatype = i_nh->mediatype;
  d_nh->media_hdr_len = se_nh->media_hdrlen;
  d_nh->min_packet_len = se_nh->min_packet_len;
  d_nh->media_protocol = i_nh->media_protocol;
  SSH_ASSERT(se_nh->media_hdrlen <= sizeof(d_nh->mediahdr));
  memcpy(d_nh->mediahdr, se_nh->media_hdr.data, se_nh->media_hdrlen);
  d_nh->mtu = se_nh->mtu;
}

/** FASTPATH_INIT_NH(fastpath, nh_index) */
SshEngineNextHopData
fastpath_accel_init_nh(SshFastpathAccel accel, SshUInt32 nh_index)
{
  SeFastpathNextHopData se_nh;

  SSH_DEBUG(SSH_D_LOWSTART, ("init_nh %d", nh_index));

  ssh_kernel_mutex_lock(accel->nh_lock);

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);
  se_nh = OCTEON_SE_FASTPATH_NH(accel->se, nh_index);

  OCTEON_SE_FASTPATH_NH_WRITE_LOCK(accel->se, nh_index, se_nh);

  /* Initialize d_nh */
  SSH_ASSERT(accel->nh->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->nh->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
  SSH_ASSERT(accel->nh->nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->nh->nh_index = nh_index);
  octeon_accel_fastpath_init_d_nh(accel, accel->nh->data);

  return accel->nh->data;
}

/** FASTPATH_GET_NH(fastpath, nh_index) */
SshEngineNextHopData
fastpath_accel_get_nh(SshFastpathAccel accel, SshUInt32 nh_index)
{
  SeFastpathNextHopData se_nh;
  SshOcteonInternalNextHopData i_nh;

  SSH_DEBUG(SSH_D_LOWSTART, ("get_nh %d", nh_index));

  ssh_kernel_mutex_lock(accel->nh_lock);

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);
  se_nh = OCTEON_SE_FASTPATH_NH(accel->se, nh_index);
  i_nh = OCTEON_ACCEL_FASTPATH_INH(accel, nh_index);

  OCTEON_SE_FASTPATH_NH_WRITE_LOCK(accel->se, nh_index, se_nh);

  /* Convert to d_nh. */
  SSH_ASSERT(accel->nh->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->nh->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
  SSH_ASSERT(accel->nh->nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->nh->nh_index = nh_index);
  octeon_accel_fastpath_se_nh_to_d_nh(accel, se_nh, i_nh, accel->nh->data);

  return accel->nh->data;
}

/** FASTPATH_GET_READ_ONLY_NH(fastpath, nh_index) */
SshEngineNextHopData
fastpath_accel_get_read_only_nh(SshFastpathAccel accel, SshUInt32 nh_index)
{
  SeFastpathNextHopData se_nh;
  SshOcteonInternalNextHopData i_nh;

  SSH_DEBUG(SSH_D_LOWSTART, ("get_read_only_nh %d", nh_index));

  ssh_kernel_mutex_lock(accel->nh_lock);

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);
  se_nh = OCTEON_SE_FASTPATH_NH(accel->se, nh_index);
  i_nh = OCTEON_ACCEL_FASTPATH_INH(accel, nh_index);

  OCTEON_SE_FASTPATH_NH_READ_LOCK(accel->se, nh_index, se_nh);

  /* Convert to d_nh. */
  SSH_ASSERT(accel->nh->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
  accel->nh->locked = OCTEON_ACCEL_LOCK_READ_LOCKED;
  SSH_ASSERT(accel->nh->nh_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_DEBUG_RUN(accel->nh->nh_index = nh_index);
  octeon_accel_fastpath_se_nh_to_d_nh(accel, se_nh, i_nh, accel->nh->data);

  return accel->nh->data;
}

/** FASTPATH_COMMIT_NH(fastpath, nh_index, nh) */
void
fastpath_accel_commit_nh(SshFastpathAccel accel, SshUInt32 nh_index,
                         SshEngineNextHopData data)
{
  SeFastpathNextHopData se_nh;
  SshOcteonInternalNextHopData i_nh;

  SSH_DEBUG(SSH_D_LOWSTART, ("commit_nh %d", nh_index));

  ssh_kernel_mutex_assert_is_locked(accel->nh_lock);

  SSH_ASSERT(accel->nh->data == data);
  SSH_ASSERT(accel->nh->nh_index == nh_index);
  OCTEON_DEBUG_RUN(accel->nh->nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(accel->nh->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED);

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);
  se_nh = OCTEON_SE_FASTPATH_NH(accel->se, nh_index);
  i_nh = OCTEON_ACCEL_FASTPATH_INH(accel, nh_index);

  /* Convert to se_nh */
  octeon_accel_fastpath_d_nh_to_se_nh(accel, data, se_nh, i_nh);

  OCTEON_DEBUG_RUN(accel->nh->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
  OCTEON_SE_FASTPATH_NH_WRITE_UNLOCK(accel->se, nh_index, se_nh);
  ssh_kernel_mutex_unlock(accel->nh_lock);
}

/** FASTPATH_UNINIT_NH(fastpath, nh_index, nh) */
void
fastpath_accel_uninit_nh(SshFastpathAccel accel, SshUInt32 nh_index,
                         SshEngineNextHopData data)
{
  SeFastpathNextHopData se_nh;
  SshOcteonInternalNextHopData i_nh;

  SSH_DEBUG(SSH_D_LOWSTART, ("uninit_nh %d", nh_index));

  ssh_kernel_mutex_assert_is_locked(accel->nh_lock);

  SSH_ASSERT(accel->nh->data == data);
  SSH_ASSERT(accel->nh->nh_index == nh_index);
  OCTEON_DEBUG_RUN(accel->nh->nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX);
  SSH_ASSERT(accel->nh->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED);

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);
  se_nh = OCTEON_SE_FASTPATH_NH(accel->se, nh_index);
  i_nh = OCTEON_ACCEL_FASTPATH_INH(accel, nh_index);

  /* Convert to se_nh */
  octeon_accel_fastpath_d_nh_to_se_nh(accel, data, se_nh, i_nh);

  OCTEON_DEBUG_RUN(accel->nh->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
  OCTEON_SE_FASTPATH_NH_WRITE_UNLOCK(accel->se, nh_index, se_nh);
  ssh_kernel_mutex_unlock(accel->nh_lock);
}

/** FASTPATH_RELEASE_NH(fastpath, nh_index) */
void
fastpath_accel_release_nh(SshFastpathAccel accel, SshUInt32 nh_index)
{
  SeFastpathNextHopData se_nh;

  SSH_DEBUG(SSH_D_LOWSTART, ("release %d", nh_index));

  ssh_kernel_mutex_assert_is_locked(accel->nh_lock);

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);
  SSH_ASSERT(nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);
  se_nh = OCTEON_SE_FASTPATH_NH(accel->se, nh_index);

  SSH_ASSERT(accel->nh->nh_index == nh_index);
  OCTEON_DEBUG_RUN(accel->nh->nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX);

  SSH_ASSERT(accel->nh->locked != OCTEON_ACCEL_LOCK_UNLOCKED);
  if (accel->nh->locked == OCTEON_ACCEL_LOCK_WRITE_LOCKED)
    {
      OCTEON_DEBUG_RUN(accel->nh->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
      OCTEON_SE_FASTPATH_NH_WRITE_UNLOCK(accel->se, nh_index, se_nh);
    }
  else if (accel->nh->locked == OCTEON_ACCEL_LOCK_READ_LOCKED)
    {
      OCTEON_DEBUG_RUN(accel->nh->locked = OCTEON_ACCEL_LOCK_UNLOCKED);
      OCTEON_SE_FASTPATH_NH_READ_UNLOCK(accel->se, nh_index, se_nh);
    }
  else
    SSH_NOTREACHED;

  ssh_kernel_mutex_unlock(accel->nh_lock);
}


/************************ Flow ID Callback **********************************/

static Boolean
octeon_accel_fastpath_flow_id_cb(SshFastpathAccel accel,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 SshUInt32 tunnel_id,
                                 unsigned char *flow_id);


/* On error this frees `pp' and returns FALSE. */



static Boolean
octeon_accel_fastpath_pullup_icmp_echo_id(SshInterceptorPacket pp,
                                          SshEnginePacketContext pc,
                                          uint32_t *protocol_xid_high)
{
  unsigned char *ucp;

  if (pc->packet_len < pc->hdrlen + 8)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Truncated ICMP packet"));
      goto error;
    }
  if (pc->hdrlen + 8 > SSH_INTERCEPTOR_MAX_PULLUP_LEN)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot pullup ICMP payload"));
      goto error;
    }
  ucp = ssh_interceptor_packet_pullup(pp, pc->hdrlen + 8);
  if (ucp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ICMP payload pullup failed"));
      pp = NULL;
      goto error;
    }

  *protocol_xid_high = SSH_GET_16BIT(ucp + pc->hdrlen + 4);
  return TRUE;

 error:
  if (pp)
    ssh_interceptor_packet_free(pp);
  return FALSE;
}

/* On error this frees `pp' and returns FALSE. */
static Boolean
octeon_accel_fastpath_calculate_icmp_error_flow_id(SshFastpathAccel accel,
                                                   SshEnginePacketContext pc,
                                                   SshInterceptorPacket pp,
                                                   SshUInt32 tunnel_id,
                                                   unsigned char *flow_id)
{
  SshEnginePacketContext inner_pc = NULL;

  inner_pc = ssh_engine_alloc_pc(accel->engine);
  if (inner_pc == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate packet context"));
      goto error;
    }

  inner_pc->pp = ssh_engine_icmp_get_inner_packet(accel->engine, pp);
  if (inner_pc->pp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract ICMP payload packet"));
      pp = NULL;
      goto error;
    }

  /* This function may fail in two different ways: If failure reason is
     packet corruption, then `pp' is not freed. On any other error `pp'
     is freed. In both cases `inner_pc->pp' is set correctly. */
  if (ssh_engine_init_and_pullup_pc(inner_pc, accel->engine, inner_pc->pp,
                                    tunnel_id, pc->prev_transform_index)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not pullup packet context"));
      goto error;
    }

  if (octeon_accel_fastpath_flow_id_cb(accel, inner_pc, inner_pc->pp,
                                       tunnel_id, flow_id) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not compute flow id for ICMP payload"));
      /* flow_id_cb() has already freed `inner_pc->pp'. */
      inner_pc->pp = NULL;
      goto error;
    }

  SSH_ASSERT(inner_pc->pp != NULL);
  ssh_interceptor_packet_free(inner_pc->pp);
  ssh_engine_free_pc(accel->engine, inner_pc);

  return TRUE;

 error:
  if (pp != NULL)
    ssh_interceptor_packet_free(pp);

  if (inner_pc != NULL)
    {
      if (inner_pc->pp != NULL)
        ssh_interceptor_packet_free(inner_pc->pp);
      ssh_engine_free_pc(accel->engine, inner_pc);
    }

  return FALSE;
}

/* On error this frees `pp' and returns FALSE. */
static Boolean
octeon_accel_fastpath_flow_id_cb(SshFastpathAccel accel,
                                 SshEnginePacketContext pc,
                                 SshInterceptorPacket pp,
                                 SshUInt32 tunnel_id,
                                 unsigned char *flow_id)
{
  SeFastpathFlowIdUnion flow_id_union;
  uint32_t protocol_xid_high;
  uint16_t protocol_xid_low;
  unsigned char addr_buf[16];
  uint64_t src_ip_high, src_ip_low;
  uint64_t dst_ip_high, dst_ip_low;
  uint8_t ipproto;
  uint8_t flow_id_flags = 0;

  /* Expect that pc is always well defined */
  SSH_ASSERT(pc != NULL);

  if (SSH_IP_IS4(&pc->src))
    {
      SSH_IP4_ENCODE(&pc->src, addr_buf);
      src_ip_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      src_ip_high = 0;

      SSH_IP4_ENCODE(&pc->dst, addr_buf);
      dst_ip_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      dst_ip_high = 0;
    }
  else
    {
      SSH_IP6_ENCODE(&pc->src, addr_buf);
      src_ip_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      src_ip_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);

      SSH_IP6_ENCODE(&pc->dst, addr_buf);
      dst_ip_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      dst_ip_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);

      flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IP6;
    }

  ipproto = (uint8_t) pc->ipproto;
  protocol_xid_high = 0;
  protocol_xid_low = 0;

  switch (ipproto)
    {
    case SSH_IPPROTO_UDP:
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
          /* Use proto and SPI if this packet is directed to us. */
          protocol_xid_high = pc->protocol_xid;
          ipproto = SSH_IPPROTO_ESP;
          src_ip_high = 0;
          src_ip_low = 0;
          dst_ip_high = 0;
          dst_ip_low = 0;
          flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING;
          break;
        }
      else if (pc->u.rule.dst_port == 67 || pc->u.rule.dst_port == 68)
        {
          flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_DHCP;
          protocol_xid_high = pc->protocol_xid;
          src_ip_high = 0;
          src_ip_low = 0;
          dst_ip_high = 0;
          dst_ip_low = 0;
          break;
        }
      /* else fallthrough and grab ports. */

    case SSH_IPPROTO_UDPLITE:
    case SSH_IPPROTO_TCP:
    case SSH_IPPROTO_SCTP:
      protocol_xid_high = pc->u.rule.src_port;
      protocol_xid_low = pc->u.rule.dst_port;
      break;

    case SSH_IPPROTO_AH:
    case SSH_IPPROTO_ESP:
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
          /* Use proto and SPI if this packet is directed to us. */
          protocol_xid_high = pc->protocol_xid;
          src_ip_high = 0;
          src_ip_low = 0;
          dst_ip_high = 0;
          dst_ip_low = 0;
          flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING;
        }
      /* Use proto and addresses if this packet is not to us. */
      break;

    case SSH_IPPROTO_ICMP:
      switch (pc->icmp_type)
        {
        case SSH_ICMP_TYPE_ECHO:
        case SSH_ICMP_TYPE_ECHOREPLY:
          if (octeon_accel_fastpath_pullup_icmp_echo_id(pp, pc,
                                                        &protocol_xid_high)
              == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("ICMP payload pullup failed"));
              pp = NULL;
              goto error;
            }
          break;

        case SSH_ICMP_TYPE_UNREACH:
        case SSH_ICMP_TYPE_SOURCEQUENCH:
        case SSH_ICMP_TYPE_TIMXCEED:
        case SSH_ICMP_TYPE_PARAMPROB:
          if (octeon_accel_fastpath_calculate_icmp_error_flow_id(accel,
                                                                 pc, pp,
                                                                 tunnel_id,
                                                                 flow_id)
              == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("ICMP error packet flow id calculation failed"));
              pp = NULL;
              goto error;
            }
          return TRUE;

        default:
          break;
        }
      /* End of case SSH_IPPROTO_ICMP */
      break;

    case SSH_IPPROTO_IPV6ICMP:
      switch (pc->icmp_type)
        {
        case SSH_ICMP6_TYPE_ECHOREQUEST:
        case SSH_ICMP6_TYPE_ECHOREPLY:
          /* Use proto + ICMP id for ICMP echo flows. */
          if (octeon_accel_fastpath_pullup_icmp_echo_id(pp, pc,
                                                        &protocol_xid_high)
              == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL, ("ICMPv6 payload pullup failed"));
              pp = NULL;
              goto error;
            }
          break;

        case SSH_ICMP6_TYPE_UNREACH:
        case SSH_ICMP6_TYPE_TOOBIG:
        case SSH_ICMP6_TYPE_TIMXCEED:
        case SSH_ICMP6_TYPE_PARAMPROB:
          /* Calculate flow id from ICMP payload packet. */
          if (octeon_accel_fastpath_calculate_icmp_error_flow_id(accel,
                                                                 pc, pp,
                                                                 tunnel_id,
                                                                 flow_id)
              == FALSE)
            {
              SSH_DEBUG(SSH_D_FAIL,
                        ("ICMPv6 error packet flow id calculation failed"));
              pp = NULL;
              goto error;
            }
          return TRUE;

        default:
          break;
        }
      /* End of case SSH_IPPROTO_IPV6ICMP */
      break;

    default:
      /* Only use IP addresses, IP protocol, tunnel_id and flags. */
      break;
    }

  if (pp->flags & SSH_PACKET_FROMADAPTER)
    flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_FROMADAPTER;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Flow id input: tunnel_id %d xid high %d low %d proto %d "
             "flags 0x%x src 0x%lx 0x%lx dst 0x%lx 0x%lx",
             tunnel_id, protocol_xid_high, protocol_xid_low, ipproto,
             flow_id_flags, src_ip_high, src_ip_low, dst_ip_high, dst_ip_low));

  octeon_se_fastpath_flow_id_hash(&flow_id_union,
                                  accel->se->salt,
                                  (uint32_t) tunnel_id,
                                  protocol_xid_high, protocol_xid_low,
                                  ipproto, flow_id_flags,
                                  src_ip_high, src_ip_low,
                                  dst_ip_high, dst_ip_low);

  SSH_DEBUG(SSH_D_LOWOK, ("Flow id output: 0x%lx 0x%lx",
                          flow_id_union.raw[0], flow_id_union.raw[1]));

  SSH_PUT_64BIT(flow_id, flow_id_union.raw[0]);
  SSH_PUT_64BIT(flow_id + 8, flow_id_union.raw[1]);

  return TRUE;

 error:
  if (pp != NULL)
    ssh_interceptor_packet_free(pp);

  return FALSE;
}


/****************************** Flow Lookup *********************************/

static SshEngineFlowData
fastpath_accel_lookup_icmp_error_flow(SshFastpathAccel accel,
                                      SshEnginePacketContext pc)
{
  SshEnginePacketContext inner_pc = NULL;
  SshEngineFlowData d_flow;

  SSH_DEBUG(SSH_D_LOWSTART, ("lookup_icmp_error_flow: pc %p", pc));

  inner_pc = ssh_engine_alloc_pc(accel->engine);
  if (inner_pc == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate packet context"));
      goto error;
    }

  inner_pc->pp = ssh_engine_icmp_get_inner_packet(accel->engine, pc->pp);
  if (inner_pc->pp == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract ICMP payload packet"));
      pc->pp = NULL;
      goto error;
    }

  /* This function may fail in two different ways: If failure reason is
     packet corruption, then `pp' is not freed. On any other error `pp'
     is freed. In both cases `inner_pc->pp' is set correctly. */
  if (ssh_engine_init_and_pullup_pc(inner_pc, accel->engine, inner_pc->pp,
                                    pc->tunnel_id, pc->prev_transform_index)
      == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not pullup packet context"));
      goto error;
    }

  memcpy(inner_pc->flow_id, pc->flow_id, sizeof(inner_pc->flow_id));

  /* Lookup flow for inner packet. */
  d_flow = fastpath_accel_lookup_flow(accel, inner_pc);

  if (d_flow != NULL)
    {
      /* Update pc fields */
      pc->flow_index = inner_pc->flow_index;
      SSH_ASSERT(pc->flow_index != SSH_IPSEC_INVALID_INDEX);

      if (inner_pc->flags & SSH_ENGINE_PC_FORWARD)
        pc->flags |= SSH_ENGINE_PC_FORWARD;
      else
        pc->flags &= ~SSH_ENGINE_PC_FORWARD;

      if (inner_pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        pc->flags |= SSH_ENGINE_PC_IS_IPSEC;
      else
        pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;

      memcpy(pc->flow_id, inner_pc->flow_id, sizeof(pc->flow_id));
    }

  SSH_ASSERT(inner_pc->pp != NULL);
  ssh_interceptor_packet_free(inner_pc->pp);
  ssh_engine_free_pc(accel->engine, inner_pc);

  return d_flow;

 error:
  if (inner_pc != NULL)
    {
      if (inner_pc->pp != NULL)
        ssh_interceptor_packet_free(inner_pc->pp);
      ssh_engine_free_pc(accel->engine, inner_pc);
    }

  pc->flow_index = SSH_IPSEC_INVALID_INDEX;
  return NULL;
}

SshEngineFlowData
fastpath_accel_lookup_flow(SshFastpathAccel accel,
                           SshEnginePacketContext pc)
{
  SeFastpathFlowData se_flow;
  SshOcteonInternalFlowData i_flow;
  uint32_t flow_index;
  uint64_t src_ip_low, src_ip_high;
  uint64_t dst_ip_low, dst_ip_high;
  unsigned char addr_buf[16];
  SeFastpathFlowIdUnion flow_id;
  uint8_t flow_lookup_flags = 0;
  uint8_t iport;

  SSH_DEBUG(SSH_D_LOWSTART, ("lookup_flow: pc %p", pc));

  /* Handle ICMP error flow lookup. For these packets the flow ID has
     been already calculated from ICMP payload packet but here we need
     to extract again the IP addresses from the ICMP payload packet.
     This is obviously non-optimal, but acceptable as ICMP error flow
     lookup is a rare exception case. */
  if ((pc->ipproto == SSH_IPPROTO_ICMP
       && (pc->icmp_type == SSH_ICMP_TYPE_UNREACH
           || pc->icmp_type == SSH_ICMP_TYPE_SOURCEQUENCH
           || pc->icmp_type == SSH_ICMP_TYPE_TIMXCEED
           || pc->icmp_type == SSH_ICMP_TYPE_PARAMPROB))
      || (pc->ipproto == SSH_IPPROTO_IPV6ICMP
          && (pc->icmp_type == SSH_ICMP6_TYPE_UNREACH
              || pc->icmp_type == SSH_ICMP6_TYPE_TOOBIG
              || pc->icmp_type == SSH_ICMP6_TYPE_TIMXCEED
              || pc->icmp_type == SSH_ICMP6_TYPE_PARAMPROB)))
    return fastpath_accel_lookup_icmp_error_flow(accel, pc);

  /* Lookup flow for all other packet types. */

  SSH_ASSERT(SSH_IP_DEFINED(&pc->src));
  SSH_ASSERT(SSH_IP_DEFINED(&pc->dst));

  /* Copy flow id to ensure 64bit alignment */
  memcpy(flow_id.raw, pc->flow_id, sizeof(flow_id.raw));

 relookup:

  if (SSH_IP_IS6(&pc->src))
    {
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
          /* Use dst address only if this is IPsec traffic directed to us. */
          src_ip_high = 0;
          src_ip_low = 0;
        }
      else
        {
          SSH_IP6_ENCODE(&pc->src, addr_buf);
          src_ip_high = (uint64_t) SSH_GET_64BIT(addr_buf);
          src_ip_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);
        }

      SSH_IP6_ENCODE(&pc->dst, addr_buf);
      dst_ip_high = (uint64_t) SSH_GET_64BIT(addr_buf);
      dst_ip_low = (uint64_t) SSH_GET_64BIT(addr_buf + 8);
    }
  else if (SSH_IP_IS4(&pc->src))
    {
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
          /* Use dst address only if this is IPsec traffic directed to us. */
          src_ip_low = 0;
        }
      else
        {
          SSH_IP4_ENCODE(&pc->src, addr_buf);
          src_ip_low = (uint64_t) SSH_GET_32BIT(addr_buf);
        }
      src_ip_high = 0;

      SSH_IP4_ENCODE(&pc->dst, addr_buf);
      dst_ip_low = (uint64_t) SSH_GET_32BIT(addr_buf);
      dst_ip_high = 0;
    }
  else
    {
      SSH_NOTREACHED;

      src_ip_high = 0;
      src_ip_low = 0;
      dst_ip_high = 0;
      dst_ip_low = 0;
    }

  iport = ssh_interceptor_octeon_ifnum_to_port(accel->interceptor,
                                               pc->pp->ifnum_in);

  SSH_DEBUG(SSH_D_LOWOK,
            ("flow_id 0%lx 0x%lx src 0x%lx 0x%lx dst 0x%lx 0x%lx iport %d",
             flow_id.raw[0], flow_id.raw[1], src_ip_high, src_ip_low,
             dst_ip_high, dst_ip_low, iport));

  /* Take the accelerated fastpath flow lock. */
  ssh_kernel_mutex_lock(accel->flow_lock);

  se_flow = octeon_se_fastpath_lookup_flow(accel->se, &flow_id,
                                           src_ip_high, src_ip_low,
                                           dst_ip_high, dst_ip_low,
                                           iport, &flow_lookup_flags);

  if (se_flow != NULL)
    {
      flow_index = OCTEON_SE_FASTPATH_FLOW_INDEX(accel->se, se_flow);
      SSH_ASSERT(flow_index < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE);
      SSH_ASSERT(flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
      SSH_ASSERT(se_flow == OCTEON_SE_FASTPATH_FLOW(accel->se, flow_index));
      i_flow = OCTEON_ACCEL_FASTPATH_IFLOW(accel, flow_index);

      SSH_ASSERT(accel->flow->locked == OCTEON_ACCEL_LOCK_UNLOCKED);
      accel->flow->locked = OCTEON_ACCEL_LOCK_WRITE_LOCKED;
      SSH_ASSERT(accel->flow->flow_index == OCTEON_SE_FASTPATH_INVALID_INDEX);
      OCTEON_DEBUG_RUN(accel->flow->flow_index = flow_index);

      /* Convert se fastpath flow to engine flow */
      octeon_accel_fastpath_se_flow_to_d_flow(accel, se_flow, i_flow,
                                              accel->flow->data);

      /* Fill pc fields */
      pc->flow_index = flow_index;
      SSH_ASSERT(pc->flow_index != SSH_IPSEC_INVALID_INDEX);

      if (flow_lookup_flags & OCTEON_SE_FASTPATH_FLOW_LOOKUP_FLAG_FORWARD)
        pc->flags |= SSH_ENGINE_PC_FORWARD;
      else
        pc->flags &= ~SSH_ENGINE_PC_FORWARD;

      SSH_DEBUG(SSH_D_LOWOK, ("Flow %d found", flow_index));

      /* Keep the accelerated fastpath flow lock. It will be released
         in FASTPATH_COMMIT_FLOW(), FASTPATH_RELEASE_FLOW() or
         FASTPATH_UNINIT_FLOW(). */

      return accel->flow->data;
    }

  /* Release the accelerated fastpath flow lock. */
  ssh_kernel_mutex_unlock(accel->flow_lock);

  if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
    {
      /* No flow found under the assumption that this was IPsec traffic
         directed to us. Relookup assuming this is passby IPsec traffic. */
      pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;

      if (octeon_accel_fastpath_flow_id_cb(accel, pc, pc->pp, pc->tunnel_id,
                                           (unsigned char *) flow_id.raw)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Flow ID calculation for passby IPsec flow lookup "
                     "failed"));
          pc->pp = NULL;
          pc->flow_index = SSH_IPSEC_INVALID_INDEX;
          return NULL;
        }

      /* Update the new flow id into pc. */
      memcpy(pc->flow_id, flow_id.raw, sizeof(flow_id.raw));

      goto relookup;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("No flow found"));
  pc->flow_index = SSH_IPSEC_INVALID_INDEX;
  return NULL;
}

/************************ Packet handler ************************************/

/** Implementation of Accelerated Fastpath API packet handler function.
    The software fastpath passes packets to accelerated fastpath via
    this function. */
void
fastpath_accel_packet_continue(SshFastpathAccel accel,
                               SshEnginePacketContext pc,
                               SshEngineActionRet ret)
{
  /* Send packets out via interceptor. We always send the packet out via
     the interceptor regardless if it is destined to network or up to
     local stack. */
  if (ret == SSH_ENGINE_RET_SEND)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Sending packet out via interceptor: pc %p",
                              pc));
      ssh_interceptor_send(accel->interceptor, pc->pp, pc->media_hdr_len);
      ssh_engine_free_pc(accel->engine, pc);
    }

  /* For other packet processing stages, return the packet to software
     fastpath. Here we could do some early checks for the packet and pass
     it to the SE fastpath for processing if the packet is suitable for SE
     fastpath processing. This would offload the packet processing to the
     subset of cores running the SE fastpath and also potentially speed up
     processing of packets to/from local stack. As the current Octeon support
     is optimized for the forwarding scenario we do this the simple way and
     always continue packet processing on the software fastpath. */
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Returning packet to the software fastpath: pc %p ret %d",
                 pc, (int) ret));
      (*accel->software_fastpath_packet_handler)(accel->engine, pc, ret, 0);
    }
}

/** Packet handler callback for exception packets from SE fastpath. */
void
octeon_accel_fastpath_packet_handler(SshInterceptorPacket pp,
                                     SshUInt32 tunnel_id,
                                     SshUInt32 prev_transform_index,
                                     void *context)
{
  SshFastpathAccel accel = (SshFastpathAccel) context;
  SshEnginePacketContext pc;

  /* Allocate and initialize a packet context. */
  pc = ssh_engine_alloc_pc(accel->engine);
  if (pc == NULL)
    goto error;

  if (ssh_engine_init_and_pullup_pc(pc, accel->engine, pp, tunnel_id,
                                    prev_transform_index) == FALSE)
    {
      pp = NULL;
      goto error;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Passing packet to software fastpath: pc %p pp %p",
                          pc, pp));

  /* Pass packet to software fastpath. */
  (*accel->software_fastpath_packet_handler)(accel->engine, pc,
                                             SSH_ENGINE_RET_RESTART, 0);

  return;

 error:
  SSH_DEBUG(SSH_D_FAIL, ("Packet dropped"));
  if (pp)
    ssh_interceptor_packet_free(pp);

  if (pc)
    {
      if (pc->pp != NULL)
        ssh_interceptor_packet_free(pc->pp);
      pc->pp = NULL;

      ssh_engine_free_pc(accel->engine, pc);
    }
}

/** Interceptor packet callback. The interceptor passes all normally
    intercepted packets via this callback, that is all packets sent out
    from the local stack and all packets from network and SE fastpath
    that were not decapsulated from a tunnel. */
void
octeon_accel_fastpath_packet_callback(SshInterceptorPacket pp,
                                      void *context)
{
  SshFastpathAccel accel = (SshFastpathAccel) context;

  /* Pass the packet to the software fastpath. */
  octeon_accel_fastpath_packet_handler(pp, 0, SSH_IPSEC_INVALID_INDEX, accel);
}

/************************ Init / uninit *************************************/

void
octeon_accel_fastpath_free_2d_table(void **table,
                                    size_t nelems,
                                    size_t elems_per_block)
{
  size_t i, nblocks;

  if (table == NULL)
    return;

  nblocks = (nelems + elems_per_block - 1) / elems_per_block;
  for (i = 0; i < nblocks; i++)
    {
      if (table[i] != NULL)
        ssh_free(table[i]);
    }
  ssh_free(table);
}

void **
octeon_accel_fastpath_calloc_2d_table(size_t nelems,
                                      size_t elems_per_block,
                                      size_t elem_size)
{
  void **ptr;
  size_t nblocks, block_size, i;

  nblocks = (nelems + elems_per_block - 1) / elems_per_block;

  ptr = (void **) ssh_calloc_flags(nblocks, sizeof(void *),
                                   SSH_KERNEL_ALLOC_WAIT);
  if (ptr == NULL)
    goto error;

  for (i = 0; i < nblocks; i++)
    {
      /* Allocate full blocks except possibly for the last block. */
      if (i == nblocks - 1)
        {
          block_size = nelems % elems_per_block;
          if (block_size == 0)
            block_size = elems_per_block;
        }
      else
        block_size = elems_per_block;

      ptr[i] = ssh_calloc_flags(block_size, elem_size, SSH_KERNEL_ALLOC_WAIT);
      if (ptr[i] == NULL)
        goto error;
    }

  return ptr;

 error:
  if (ptr != NULL)
    {
      for (i = 0; i < nblocks; i++)
        {
          if (ptr[i] != NULL)
            ssh_free(ptr[i]);
        }
      ssh_free(ptr);
    }

  return NULL;
}

static void octeon_accel_fastpath_free(SshFastpathAccel accel)
{
  if (accel != NULL)
    {
      if (accel->i_flow_table != NULL)
        octeon_accel_fastpath_free_2d_table((void **) accel->i_flow_table,
                                 SSH_ENGINE_FLOW_TABLE_SIZE,
                                 OCTEON_ACCEL_FASTPATH_IFLOW_TABLE_BLOCK_SIZE);
      if (accel->i_trd_table != NULL)
        octeon_accel_fastpath_free_2d_table((void **) accel->i_trd_table,
                                  SSH_ENGINE_TRANSFORM_TABLE_SIZE,
                                  OCTEON_ACCEL_FASTPATH_ITRD_TABLE_BLOCK_SIZE);
      if (accel->i_nh_table != NULL)
        octeon_accel_fastpath_free_2d_table((void **) accel->i_nh_table,
                                   SSH_ENGINE_NEXT_HOP_HASH_SIZE,
                                   OCTEON_ACCEL_FASTPATH_INH_TABLE_BLOCK_SIZE);
    }

  ssh_free(accel);
}

static SshFastpathAccel
octeon_accel_fastpath_alloc(SshEngine engine,
                            SshInterceptor interceptor)
{
  SshFastpathAccel accel;

  accel = ssh_calloc_flags(1, sizeof(*accel), SSH_KERNEL_ALLOC_WAIT);
  if (accel == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Failed to allocate accelerated fastpath, size %dB",
                 (int) sizeof(*accel)));
      goto error;
    }

  if (ssh_kernel_mutex_init(accel->flow_lock) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize flow lock"));
      goto error;
    }
  if (ssh_kernel_mutex_init(accel->trd_lock) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize transform lock"));
      goto error;
    }
  if (ssh_kernel_mutex_init(accel->nh_lock) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize next hop lock"));
      goto error;
    }

  accel->i_flow_table = (SshOcteonInternalFlowDataStruct **)
    octeon_accel_fastpath_calloc_2d_table(SSH_ENGINE_FLOW_TABLE_SIZE,
                                  OCTEON_ACCEL_FASTPATH_IFLOW_TABLE_BLOCK_SIZE,
                                  sizeof(SshOcteonInternalFlowDataStruct));
  if (accel->i_flow_table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate internal flow table, size %luB",
                 (unsigned long) (SSH_ENGINE_FLOW_TABLE_SIZE
                                  * sizeof(SshOcteonInternalFlowDataStruct))));
      goto error;
    }

  accel->i_trd_table = (SshOcteonInternalTransformDataStruct **)
    octeon_accel_fastpath_calloc_2d_table(SSH_ENGINE_TRANSFORM_TABLE_SIZE,
                                 OCTEON_ACCEL_FASTPATH_ITRD_TABLE_BLOCK_SIZE,
                                 sizeof(SshOcteonInternalTransformDataStruct));
  if (accel->i_trd_table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate internal transform table, size %luB",
                 (unsigned long) (SSH_ENGINE_TRANSFORM_TABLE_SIZE *
                                  sizeof(SshOcteonInternalTransformDataStruct))
                 ));
      goto error;
    }

  accel->i_nh_table = (SshOcteonInternalNextHopDataStruct **)
    octeon_accel_fastpath_calloc_2d_table(SSH_ENGINE_NEXT_HOP_HASH_SIZE,
                                  OCTEON_ACCEL_FASTPATH_INH_TABLE_BLOCK_SIZE,
                                  sizeof(SshOcteonInternalNextHopDataStruct));
  if (accel->i_nh_table == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to allocate internal next hop table, size %luB",
                 (unsigned long) (OCTEON_ACCEL_FASTPATH_INH_TABLE_BLOCK_SIZE *
                                  sizeof(SshOcteonInternalNextHopDataStruct))
                 ));
      goto error;
    }

  accel->engine = engine;
  accel->interceptor = interceptor;

  /* Initialize rest */
  accel->flow->flow_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
  accel->flow->locked = OCTEON_ACCEL_LOCK_UNLOCKED;
  accel->trd->trd_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
  accel->trd->locked = OCTEON_ACCEL_LOCK_UNLOCKED;
  accel->nh->nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
  accel->nh->locked = OCTEON_ACCEL_LOCK_UNLOCKED;

  return accel;

 error:
  if (accel != NULL)
    octeon_accel_fastpath_free(accel);
  return NULL;
}

static void
octeon_accel_fastpath_free_shared(SshFastpathAccel accel,
                                  SeFastpath fastpath)
{
  if (fastpath != NULL && accel->accel_allocated_bootmem)
    {
      cvmx_bootmem_free_named(OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
      accel->accel_allocated_bootmem = FALSE;
    }
}

static SeFastpath
octeon_accel_fastpath_alloc_shared(SshFastpathAccel accel)
{
  SeFastpath fastpath;
  int i, j;
  SeFastpathFlowData se_flow;
  SeFastpathTransformData se_trd;
  SeFastpathNextHopData se_nh;
  cvmx_bootmem_named_block_desc_t *named_block;

  SSH_ASSERT(accel != NULL);

  /** First sanity check sizes of shared objects */
  if (sizeof(SeFastpathFlowIdHashStruct) % 8 != 0)
    {
      ssh_warning("SeFastpathFlowIdHashStruct is not padded to 8 byte "
                  "boundary");
      return NULL;
    }
  if (sizeof(SeFastpathFlowDataUnion) % 128 != 0)
    {
      ssh_warning("SeFastpathFlowDataUnion is not padded to 128 byte "
                  "boundary, size %d",
                  sizeof(SeFastpathFlowDataStruct));
      return NULL;
    }
  if (sizeof(SeFastpathTransformDataUnion) % 128 != 0)
    {
      ssh_warning("SeFastpathTransformDataUnion is not padded to 128 byte "
                  "boundary, size %d",
                  sizeof(SeFastpathTransformDataStruct));
      return NULL;
    }

  /* Allocate named memory block from shared memory. */
  fastpath = cvmx_bootmem_alloc_named(sizeof(*fastpath), 16,
                                      OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
  if (fastpath == NULL)
    {
      /* Allocation failed. Check if the named block has already been
         allocated by bootloader. */
      named_block =
        cvmx_bootmem_find_named_block(OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);
      if (named_block == NULL || named_block->size < sizeof(*fastpath))
        {
          ssh_warning("Could not allocate %d byte bootmem block at \"%s\"",
                      sizeof(*fastpath), OCTEON_SE_FASTPATH_BOOTMEM_BLOCK);

          return NULL;
        }

      /* Named block for fastpath was found and it was large enough. */
      fastpath = cvmx_phys_to_ptr(named_block->base_addr);
      SSH_ASSERT(fastpath != NULL);
    }
  else
    {
      accel->accel_allocated_bootmem = TRUE;
    }

  /* Initialize shared fastpath object */
  memset(fastpath, 0, sizeof(*fastpath));

  /* Allocate flow hash locks */
  for (i = 0; i < OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS; i++)
    cvmx_rwlock_wp_init(&fastpath->flow_hash_lock[i].lock);

  /* Initialize flow hash table */
  for (i = 0; i < OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE; i++)
    {
      fastpath->flow_id_hash[i].fwd_flow_index =
        OCTEON_SE_FASTPATH_INVALID_INDEX;
      fastpath->flow_id_hash[i].rev_flow_index =
        OCTEON_SE_FASTPATH_INVALID_INDEX;
      fastpath->flow_id_hash[i].lock =
        &fastpath->
        flow_hash_lock[i % OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS].lock;
    }

  /* Initialize flow table */
  for (i = 0; i < OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE; i++)
    {
      se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, i);
      memset(se_flow, 0, sizeof(*se_flow));
      OCTEON_SE_FASTPATH_FLOW_LOCK_INIT(se_flow->lock);
      se_flow->fwd_flow_index_next = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->rev_flow_index_next = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->fwd_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->rev_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->fwd_nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      se_flow->rev_nh_index = OCTEON_SE_FASTPATH_INVALID_INDEX;
      for (j = 0; j < OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS; j++)
        {
          se_flow->fwd_rx_transform_index[i] =
            OCTEON_SE_FASTPATH_INVALID_INDEX;
          se_flow->rev_rx_transform_index[i] =
            OCTEON_SE_FASTPATH_INVALID_INDEX;
        }
      se_flow->fwd_iport = OCTEON_SE_FASTPATH_INVALID_PORT;
      se_flow->rev_iport = OCTEON_SE_FASTPATH_INVALID_PORT;
    }

  /* Initialize trd table */
  for (i = 0; i < OCTEON_SE_FASTPATH_TRD_TABLE_SIZE; i++)
    {
      se_trd = OCTEON_SE_FASTPATH_TRD(fastpath, i);
      memset(se_trd, 0, sizeof(*se_trd));
      cvmx_rwlock_wp_init(se_trd->lock);
      OCTEON_SE_FASTPATH_TRD_REPLAY_LOCK_INIT(se_trd);
      se_trd->port = OCTEON_SE_FASTPATH_INVALID_PORT;
    }

  /* Initialize nexthop table */
  for (i = 0; i < OCTEON_SE_FASTPATH_NH_TABLE_SIZE; i++)
    {
      se_nh = OCTEON_SE_FASTPATH_NH(fastpath, i);
      memset(se_nh, 0, sizeof(*se_nh));
      cvmx_rwlock_wp_init(se_nh->lock);
      se_nh->port = OCTEON_SE_FASTPATH_INVALID_PORT;
    }

  /* Set salt. */
  cvmx_rng_enable();
  fastpath->salt = cvmx_rng_get_random32();

  SSH_DEBUG(SSH_D_LOWOK, ("Allocated SE fastpath %p, size %d bytes",
                          fastpath, sizeof(*fastpath)));

  return fastpath;
}

Boolean
fastpath_accel_init(SshEngine engine,
                    SshInterceptor interceptor,
                    SshFastpathAccelPacketCB packet_handler,
                    SshFastpathAccelFlowIDCB *flow_id_return,
                    SshFastpathAccel *fastpath_return)
{
  SshFastpathAccel accel;

  /* Allocate accelerated fastpath object. */
  accel = octeon_accel_fastpath_alloc(engine, interceptor);
  if (accel == NULL)
    goto error;

  /* Allocate shared SE fastpath object. */
  accel->se = octeon_accel_fastpath_alloc_shared(accel);
  if (accel->se == NULL)
    goto error;

  /* Save packet handler callback. */
  SSH_ASSERT(packet_handler != NULL_FNPTR);
  accel->software_fastpath_packet_handler = packet_handler;

  /* Set the return value parameters before registering packet callbacks. */
  *flow_id_return = octeon_accel_fastpath_flow_id_cb;
  *fastpath_return = accel;

  /* Register packet callback to interceptor. It is guaranteed that the
     interceptor does not call the callback until ssh_interceptor_open()
     is called and that happens only after this function has returned. */
  ssh_interceptor_set_packet_cb(interceptor,
                                octeon_accel_fastpath_packet_callback,
                                accel);

  /* Register exception packet handler callback to octeon interceptor. It is
     guaranteed that the interceptor does not call the callback until
     ssh_interceptor_open() is called. */
  ssh_interceptor_octeon_set_packet_cb(interceptor,
                                       octeon_accel_fastpath_packet_handler,
                                       accel);

  /* Start tick timer. */
  octeon_accel_fastpath_tick_timer(accel);

  SSH_DEBUG(SSH_D_LOWOK, ("Accelerated fastpath initialized"));

  return TRUE;

 error:
  SSH_DEBUG(SSH_D_ERROR, ("Accelerated fastpath initialization failed!"));
  if (accel != NULL)
    {
      if (accel->se)
        octeon_accel_fastpath_free_shared(accel, accel->se);
      octeon_accel_fastpath_free(accel);
    }
  return FALSE;
}

void
fastpath_accel_uninit(SshFastpathAccel accel)
{
  /* Cancel tick timer. */
  ssh_kernel_timeout_cancel(octeon_accel_fastpath_tick_timer,
                            SSH_KERNEL_ALL_CONTEXTS);

  /* Free shared SE fastpath. */
  if (accel != NULL)
    octeon_accel_fastpath_free_shared(accel, accel->se);

  /* Free accelerated fastpath object. */
  octeon_accel_fastpath_free(accel);

  SSH_DEBUG(SSH_D_LOWOK, ("Accelerated fastpath uninitialized"));
}

static void
fastpath_accel_send_control_cmd(SshFastpathAccel accel,
                                uint8_t command)
{
  cvmx_wqe_t *wqe;
  SeFastpathControlCmd cmd;
  uint8_t num_se_fastpaths, i;

  num_se_fastpaths =
    ssh_interceptor_octeon_get_num_fastpaths(accel->interceptor);

  if (num_se_fastpaths > OCTEON_SE_FASTPATH_MAX_NUM_CPUS)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Maximum number of supported SE fastpaths is %d",
                 OCTEON_SE_FASTPATH_MAX_NUM_CPUS));
      num_se_fastpaths = OCTEON_SE_FASTPATH_MAX_NUM_CPUS;
    }

  for (i = 0; i < num_se_fastpaths; i++)
    {
      wqe = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
      if (wqe == NULL)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Could not allocate work queue entry for control "
                     "command to SE fastpath %d", i));
          return;
        }
      memset(wqe, 0, sizeof(*wqe));

      switch (i)
        {
        case 0:
          wqe->grp = OCTEON_SE_FASTPATH_CONTROL_GROUP;
          break;
#if (OCTEON_SE_FASTPATH_MAX_NUM_CPUS >= 2)
        case 1:
          wqe->grp = OCTEON_SE_FASTPATH_CONTROL_GROUP1;
          break;
#endif /* (OCTEON_SE_FASTPATH_MAX_NUM_CPUS >= 2) */
        default:
          SSH_NOTREACHED;
        }

      cmd = (SeFastpathControlCmd) wqe->packet_data;
      cmd->cmd = command;

      /* Submit work to control group via the high priority queue
         with zero tag value. */
      SSH_DEBUG(SSH_D_LOWOK,
                ("Submitting control work queue entry to SE fastpath %d", i));
      cvmx_pow_work_submit(wqe, 0, CVMX_POW_TAG_TYPE_ATOMIC,
                           OCTEON_SE_FASTPATH_HIGH_PRIO_QUEUE, wqe->grp);
    }
}

void
fastpath_accel_notify_open(SshFastpathAccel accel)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Entered"));

  fastpath_accel_send_control_cmd(accel,
                                  OCTEON_SE_FASTPATH_CONTROL_CMD_ENABLE);
}

void
fastpath_accel_notify_close(SshFastpathAccel accel)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Entered"));

  fastpath_accel_send_control_cmd(accel,
                                  OCTEON_SE_FASTPATH_CONTROL_CMD_DISABLE);
}

Boolean
fastpath_accel_stop(SshFastpathAccel accel)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Entered"));

  fastpath_accel_send_control_cmd(accel, OCTEON_SE_FASTPATH_CONTROL_CMD_STOP);
  return TRUE;
}

void
fastpath_accel_set_params(SshFastpathAccel accel,
                          const SshEngineParams params)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Entered"));

  /* Yell loud if unsupported parameters are defined. */

  /* SE fastpath always decrements IPv4 TTL/IPv6 HL when forwarding a packet.*/
  if (params->do_not_decrement_ttl)
    ssh_warning("SE fastpath does not support setting the "
                "'do_not_decrement_ttl' engine parameter!");

  /* Minimum TTL is always 1 on SE fastpath. */
  if (params->min_ttl_value != 1)
    ssh_warning("SE fastpath does not support setting the 'min_ttl_value' "
                "engine parameter!");

#ifndef OCTEON_SE_FASTPATH_AUDIT_CORRUPT
  /* SE fastpath drops corrupted packets silently. */
  if (params->audit_corrupt)
    ssh_warning("SE fastpath does not support 'audit_corrupt' engine "
                "parameter. Corrupted packets are dropped silently.");
#endif /* OCTEON_SE_FASTPATH_AUDIT_CORRUPT */

  /* 'drop_if_cannot_audit' is always on, as any auditable exceptions packets
     are dropped if they cannot be passed to slowpath for auditing. */

  /* Set local IKE NAT-T port to SE fastpath. This is not really the correct
     way to set this (accel fastpath should not really need to know about
     engine internals). Anyway the local_ike_natt_port is defined in engine
     when this function is called. */
  accel->se->local_ike_natt_port = accel->engine->local_ike_natt_ports[0];
}

void
fastpath_accel_set_salt(SshFastpathAccel accel, const unsigned char *salt,
                        size_t salt_len)
{
  /* This function is deprecated. SE fastpath creates its own salt. */
}

void
fastpath_accel_suspend(SshFastpathAccel accel)
{
  ssh_warning("Suspend is not supported");
}

void
fastpath_accel_resume(SshFastpathAccel accel)
{
  ssh_warning("Resume is not supported");
}

#ifdef SSH_IPSEC_STATISTICS
void fastpath_accel_get_global_stats(SshFastpathAccel accel,
                                     SshFastpathAccelGlobalStatsCB callback,
                                     void *context)
{
  ssh_warning("Statistics retrieval is not implemented");
  (*callback)(accel->engine, NULL, context);
}
#endif /* SSH_IPSEC_STATISTICS */
