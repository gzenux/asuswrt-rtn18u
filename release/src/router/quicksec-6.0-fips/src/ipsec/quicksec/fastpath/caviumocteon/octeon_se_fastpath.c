/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file implements the SE fastpath packet processing.
*/

#include "octeon_se_fastpath_internal.h"
#include "octeon_se_fastpath_inline.h"

/******************** Packet context ****************************************/

/** Initialize packet context from wqe */
static inline SeFastpathPacketContext
octeon_se_fastpath_init_pc(SeFastpathCoreContext core,
                           cvmx_wqe_t *wqe)
{
  SeFastpathPacketContext pc;

  if (wqe->grp == OCTEON_SE_FASTPATH_PKT_GROUP)
    {
      /* Initialize packet context */
      core->pc.padding[OCTEON_SE_FASTPATH_PACKET_CONTEXT_CRITICAL_WORD] = 0;
      pc = &core->pc.s;
      pc->wqe = wqe;

      /* Initialize packet state */
      core->state.padding[OCTEON_SE_FASTPATH_PACKET_STATE_CRITICAL_WORD] = 0;
      pc->s = &core->state.s;
      pc->s->prev_transform_index = OCTEON_SE_FASTPATH_INVALID_INDEX;

      OCTEON_SE_CORE_STATS(core->stats->pkt_rx++);
      OCTEON_SE_CYCLE_COUNT_START(pc, core);
      return pc;
    }
  else if (wqe->grp == OCTEON_SE_FASTPATH_DESCHED_GROUP)
    {
      /* Re-initialize packet context */
      core->pc.padding[OCTEON_SE_FASTPATH_PACKET_CONTEXT_CRITICAL_WORD] = 0;
      pc = &core->pc.s;
      pc->wqe = wqe;
      pc->flag_rescheduled = 1;

      /* Get packet state from wqe->packet_data */
      pc->s = (SeFastpathPacketState) pc->wqe->packet_data;

      OCTEON_SE_CORE_STATS(core->stats->pkt_resched++);
      OCTEON_SE_CYCLE_COUNT_CONT(pc, core);
      return pc;
    }

  OCTEON_SE_DEBUG(3, "Packet scheduled from unknown group %d\n", wqe->grp);
  return NULL;
}

/** Encode packet state to wqe->packet_data. */
static inline void
octeon_se_fastpath_encode_pc(SeFastpathCoreContext core,
                             SeFastpathPacketContext pc)
{
  if (cvmx_likely(((void *) pc->s) != ((void *) pc->wqe->packet_data)))
    {
      OCTEON_SE_ASSERT(sizeof(pc->wqe->packet_data)
                       >= sizeof(SeFastpathPacketStateStruct));
      memcpy(pc->wqe->packet_data, pc->s, sizeof(SeFastpathPacketStateStruct));
    }
}


/******************** Packet pullup *****************************************/

/** Parse packet headers. This functions handles packets from hw. Before this
    step the hw has already made some checks, so header parsing is done here
    only partially. */
static inline SeFastpathRet
octeon_se_fastpath_packet_pullup(SeFastpathCoreContext core,
                                 SeFastpath fastpath,
                                 SeFastpathPacketContext pc,
                                 uint8_t *pullup_data,
                                 size_t pullup_data_len,
                                 uint8_t ip_version_6,
                                 uint8_t check_sanity)
{
  register size_t pullup_offset = 0;
  uint32_t data;

  if (ip_version_6)
    {
      if (cvmx_unlikely(pullup_data_len < OCTEON_SE_FASTPATH_IP6_HDRLEN))
        {
          OCTEON_SE_DEBUG(3, "Truncated IPv6 packet, len %d\n",
                          (int) pullup_data_len);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }

      if (check_sanity)
        {
          OCTEON_SE_FASTPATH_IPH6_VERSION(pullup_data, data);
          if (cvmx_unlikely(data != 6))
            {
              OCTEON_SE_DEBUG(3, "Invalid IPv6 version %d\n", (int) data);
              return OCTEON_SE_FASTPATH_RET_CORRUPT;
            }
        }

      pc->s->tr_offset = OCTEON_SE_FASTPATH_IP6_HDRLEN;

      OCTEON_SE_FASTPATH_IPH6_LEN(pullup_data, pc->s->ip_len);
      pc->s->ip_len += OCTEON_SE_FASTPATH_IP6_HDRLEN;
      OCTEON_SE_FASTPATH_IPH6_NH(pullup_data, pc->s->ipproto);
      OCTEON_SE_FASTPATH_IPH6_HL(pullup_data, pc->s->ttl);
      OCTEON_SE_FASTPATH_IPH6_SRC_HIGH(pullup_data, pc->s->src_ip_high);
      OCTEON_SE_FASTPATH_IPH6_SRC_LOW(pullup_data, pc->s->src_ip_low);
      OCTEON_SE_FASTPATH_IPH6_DST_HIGH(pullup_data, pc->s->dst_ip_high);
      OCTEON_SE_FASTPATH_IPH6_DST_LOW(pullup_data, pc->s->dst_ip_low);
    }
  else
    {
      if (cvmx_unlikely(pullup_data_len < OCTEON_SE_FASTPATH_IP4_HDRLEN))
        {
          OCTEON_SE_DEBUG(3, "Truncated IPv4 packet, len %d\n",
                          (int) pullup_data_len);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }

      OCTEON_SE_FASTPATH_IPH4_HLEN(pullup_data, pc->s->tr_offset);

      OCTEON_SE_FASTPATH_IPH4_FRAG(pullup_data, data);
      if (data & OCTEON_SE_FASTPATH_IPH4_FRAGOFF_DF)
        pc->s->ipv4_df = 1;
      else
        pc->s->ipv4_df = 0;

      if (check_sanity)
        {
          if (cvmx_unlikely(data &
                            (OCTEON_SE_FASTPATH_IP4_FRAG_MASK
                             | OCTEON_SE_FASTPATH_IPH4_FRAGOFF_MF)) != 0)
            {
              OCTEON_SE_DEBUG(5, "IPv4 fragment\n");
              return OCTEON_SE_FASTPATH_RET_SLOWPATH;
            }

          if (cvmx_unlikely(pc->s->tr_offset < OCTEON_SE_FASTPATH_IP4_HDRLEN))
            {
              OCTEON_SE_DEBUG(3, "Invalid IPv4 header length, %d\n",
                              pc->s->tr_offset);
              return OCTEON_SE_FASTPATH_RET_CORRUPT;
            }

          OCTEON_SE_FASTPATH_IPH4_VERSION(pullup_data, data);
          if (cvmx_unlikely(data != 4))
            {
              OCTEON_SE_DEBUG(3, "Invalid IPv4 version %d\n", (int) data);
              return OCTEON_SE_FASTPATH_RET_CORRUPT;
            }
        }

      /* Pass IPv4 packets with options to slowpath. */
      if (cvmx_unlikely(pc->s->tr_offset != OCTEON_SE_FASTPATH_IP4_HDRLEN))
        {
          OCTEON_SE_DEBUG(5, "IPv4 options\n");
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }

      OCTEON_SE_FASTPATH_IPH4_LEN(pullup_data, pc->s->ip_len);
      OCTEON_SE_FASTPATH_IPH4_TTL(pullup_data, pc->s->ttl);
      OCTEON_SE_FASTPATH_IPH4_PROTO(pullup_data, pc->s->ipproto);
      OCTEON_SE_FASTPATH_IPH4_SRC(pullup_data, pc->s->src_ip_low);
      pc->s->src_ip_high = 0;
      OCTEON_SE_FASTPATH_IPH4_DST(pullup_data, pc->s->dst_ip_low);
      pc->s->dst_ip_high = 0;
    }
  pullup_offset += pc->s->tr_offset;

  switch (pc->s->ipproto)
    {
    case OCTEON_SE_FASTPATH_IPPROTO_UDP:
      if (cvmx_unlikely(pullup_data_len <
                        (pullup_offset + OCTEON_SE_FASTPATH_UDP_HDRLEN)))
        {
          OCTEON_SE_DEBUG(3, "Truncated UDP packet, len %d\n",
                          (int) pullup_data_len);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }

      OCTEON_SE_FASTPATH_UDPH_SRCPORT(&pullup_data[pullup_offset],
                                      pc->s->src_port);
      OCTEON_SE_FASTPATH_UDPH_DSTPORT(&pullup_data[pullup_offset],
                                      pc->s->dst_port);

      /* UDP NAT-T handling */
      if (cvmx_unlikely(pc->s->src_port == 0 || pc->s->dst_port == 0))
        {
          OCTEON_SE_DEBUG(3, "Invalid UDP ports: %d %d\n",
                          pc->s->src_port, pc->s->dst_port);
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_NATT
      else if (cvmx_unlikely((pullup_data_len >=
                              (pullup_offset + OCTEON_SE_FASTPATH_UDP_HDRLEN
                               + OCTEON_SE_FASTPATH_ESP_HDRLEN))
                             && (pc->s->dst_port
                                 == fastpath->local_ike_natt_port)))
        {
          pullup_offset += OCTEON_SE_FASTPATH_UDP_HDRLEN;
          OCTEON_SE_FASTPATH_ESPH_SPI(&pullup_data[pullup_offset],
                                      pc->s->ipsec_spi);
          OCTEON_SE_FASTPATH_ESPH_SEQ(&pullup_data[pullup_offset],
                                      pc->s->ipsec_seq);
          if (cvmx_unlikely(pc->s->ipsec_spi == 0))
            {
              OCTEON_SE_DEBUG(5, "UDP NAT-T with non-ESP marker\n");
              return OCTEON_SE_FASTPATH_RET_SLOWPATH;
            }
          pc->s->ipsec_natt = 1;
        }
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_NATT */
      break;

    case OCTEON_SE_FASTPATH_IPPROTO_TCP:
      if (cvmx_unlikely(pullup_data_len <
                        (pullup_offset + OCTEON_SE_FASTPATH_TCP_HDRLEN)))
        {
          OCTEON_SE_DEBUG(3, "Truncated TCP packet, len %d\n",
                          (int) pullup_data_len);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }

      OCTEON_SE_FASTPATH_TCPH_SRCPORT(&pullup_data[pullup_offset],
                                      pc->s->src_port);
      OCTEON_SE_FASTPATH_TCPH_DSTPORT(&pullup_data[pullup_offset],
                                      pc->s->dst_port);

      if (cvmx_unlikely(pc->s->src_port == 0 || pc->s->dst_port == 0))
        {
          OCTEON_SE_DEBUG(3, "Invalid TCP ports: %d %d\n",
                          pc->s->src_port, pc->s->dst_port);
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }
      break;

    case OCTEON_SE_FASTPATH_IPPROTO_ESP:
      if (cvmx_unlikely(pullup_data_len <
                        (pullup_offset + OCTEON_SE_FASTPATH_ESP_HDRLEN)))
        {
          OCTEON_SE_DEBUG(3, "Truncated ESP packet, len %d\n",
                          (int) pullup_data_len);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }

      OCTEON_SE_FASTPATH_ESPH_SPI(&pullup_data[pullup_offset],
                                  pc->s->ipsec_spi);
      OCTEON_SE_FASTPATH_ESPH_SEQ(&pullup_data[pullup_offset],
                                  pc->s->ipsec_seq);

      if (cvmx_unlikely(pc->s->ipsec_spi == 0))
        {
          OCTEON_SE_DEBUG(5, "Zero ESP spi\n");
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }
      break;

    case OCTEON_SE_FASTPATH_IPPROTO_AH:
      if (cvmx_unlikely(pullup_data_len <
                        (pullup_offset + OCTEON_SE_FASTPATH_AH_HDRLEN)))
        {
          OCTEON_SE_DEBUG(3, "Truncated AH packet, len %d\n",
                          (int) pullup_data_len);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }

      OCTEON_SE_FASTPATH_AHH_NH(&pullup_data[pullup_offset], pc->s->ipsec_nh);
      OCTEON_SE_FASTPATH_AHH_LEN(&pullup_data[pullup_offset],
                                 pc->s->ipsec_len);
      OCTEON_SE_FASTPATH_AHH_SPI(&pullup_data[pullup_offset],
                                 pc->s->ipsec_spi);
      OCTEON_SE_FASTPATH_AHH_SEQ(&pullup_data[pullup_offset],
                                 pc->s->ipsec_seq);

      if (cvmx_unlikely(pc->s->ipsec_spi == 0))
        {
          OCTEON_SE_DEBUG(3, "Invalid AH spi: %x\n", pc->s->ipsec_spi);
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }
      break;

    case OCTEON_SE_FASTPATH_IPPROTO_IPV6ICMP:



      pc->flag_high_prio = 1;

    case OCTEON_SE_FASTPATH_IPPROTO_ICMP:
      OCTEON_SE_DEBUG(5, "ICMP %d\n", pc->s->ipproto);
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;

    default:
      OCTEON_SE_DEBUG(5, "Unknown protocol %d\n", pc->s->ipproto);
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  pc->s->state = OCTEON_SE_FASTPATH_PACKET_STATE_PULLUP;

  return OCTEON_SE_FASTPATH_RET_OK;
}

static inline SeFastpathRet
octeon_se_fastpath_initial_packet_pullup(SeFastpathCoreContext core,
                                         SeFastpath fastpath,
                                         SeFastpathPacketContext pc)
{
  size_t pd_len;

  OCTEON_SE_DEBUG(9, "Packet pullup\n");

  /* Assert that descheduled packets never return here. */
  OCTEON_SE_ASSERT(pc->flag_rescheduled == 0);

  /* Assert that packet is always in buffers, not in packet_data */
  OCTEON_SE_ASSERT(pc->wqe->word2.s.bufs > 0);

  /* Pass all non-IP packets to slowpath */
  if (cvmx_unlikely(pc->wqe->word2.snoip.not_IP == 1))
    {
      /* Drop all error packets immediately. */
      if (cvmx_unlikely(pc->wqe->word2.snoip.rcv_error == 1))
        {
          OCTEON_SE_DEBUG(3, "Non-IP recv error: %d\n",
                          pc->wqe->word2.snoip.err_code);
          return OCTEON_SE_FASTPATH_RET_DROP;
        }

      OCTEON_SE_DEBUG(5, "Not IP\n");

      /* Pass ARP to slowpath via the high priority queue. */
      if (pc->wqe->word2.snoip.is_arp)
        {
          OCTEON_SE_DEBUG(5, "ARP\n");
          pc->flag_high_prio = 1;
        }

      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  /* Drop all error and exception packets */
  if (cvmx_unlikely(pc->wqe->word2.s.rcv_error == 1
                    || pc->wqe->word2.s.IP_exc == 1))
    {
      /* If packet has
         - zero IPv4 TTL / IPv6 HL (5)
         - IPv4 options (6)
         then pass packet to slowpath. */
      if (cvmx_unlikely(pc->wqe->word2.s.rcv_error == 0
                        && (pc->wqe->word2.s.err_code == 5
                            || pc->wqe->word2.s.err_code == 6)))
        {
          OCTEON_SE_DEBUG(5, "IP recv exception: %d\n",
                          pc->wqe->word2.s.err_code);
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }

      /* Else drop&audit the packet as it has either:
          - L2 receive error
          - invalid IP version number (1)
          - incorrect IPv4 header checksum (2)
          - not enough bytes to contain a full IP header (3)
          - truncated IP packet (not enough payload bytes) (4)
      */
      else
        {
          OCTEON_SE_DEBUG(3, "IP recv error/exception: %d\n",
                          pc->wqe->word2.s.err_code);
          return OCTEON_SE_FASTPATH_RET_CORRUPT;
        }
    }

  /* Pass all IP fragments to slowpath */
  if (cvmx_unlikely(pc->wqe->word2.s.is_frag))
    {
      OCTEON_SE_DEBUG(5, "IP fragment\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  pc->s->ip_offset = pc->wqe->word2.s.ip_offset;
  pd_len = sizeof(pc->wqe->packet_data);

  if (pc->wqe->word2.s.is_v6)
    {
      /* IPv6 is always aligned */
      if ((size_t) (pc->wqe->len - pc->wqe->word2.s.ip_offset) < pd_len)
        pd_len = pc->wqe->len - pc->wqe->word2.s.ip_offset;

      pc->s->ip_version_6 = 1;

      return octeon_se_fastpath_packet_pullup(core, fastpath, pc,
                                              pc->wqe->packet_data,
                                              pd_len, 1, 0);
    }
  else
    {
      /* IPv4 has 4 bytes alignment padding prefix */
      pd_len -= 4;
      if ((size_t) (pc->wqe->len - pc->wqe->word2.s.ip_offset) < pd_len)
        pd_len = pc->wqe->len - pc->wqe->word2.s.ip_offset;

      pc->s->ip_version_6 = 0;

      return octeon_se_fastpath_packet_pullup(core, fastpath, pc,
                                              &pc->wqe->packet_data[4],
                                              pd_len, 0, 0);
    }
}

static inline SeFastpathRet
octeon_se_fastpath_packet_restart(SeFastpathCoreContext core,
                                  SeFastpath fastpath,
                                  SeFastpathPacketContext pc)
{
  uint8_t *ptr;
  size_t len;

  OCTEON_SE_DEBUG(9, "Packet restart\n");

  /* Assert that inbound transform execution has set
     prev_transform_index and tunnel_id. */
  OCTEON_SE_ASSERT(pc->s->tunnel_id != 0);
  OCTEON_SE_ASSERT(pc->s->prev_transform_index
                   != OCTEON_SE_FASTPATH_INVALID_INDEX);

  /* Clear some flags */
  pc->s->ipsec_natt = 0;
  pc->s->forward = 0;
  pc->flag_ipsec_incoming = 0;
  pc->flag_high_prio = 0;

  /* Decapsulated packet does not have media_hdr */
  ptr = cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + pc->s->ip_offset;
  len = pc->s->ip_len;
  if (len > (size_t) (pc->wqe->packet_ptr.s.size - pc->s->ip_offset))
    len = pc->wqe->packet_ptr.s.size - pc->s->ip_offset;

  /* Assert that header is properly aligned */
  OCTEON_SE_ASSERT((pc->s->ip_version_6 && (((uint64_t) ptr) % 8) == 0)
                   || (!pc->s->ip_version_6 && (((uint64_t) ptr) % 4) == 0));

  /* Perform sanity checks on packet headers during packet pullup*/
  return octeon_se_fastpath_packet_pullup(core, fastpath, pc,
                                          ptr, len, pc->s->ip_version_6, 1);
}


/******************** Flow ID calculation ***********************************/

/** Calculates flow id from packet context. This function never causes
    deschedule. */
static inline SeFastpathRet
octeon_se_fastpath_calculate_flow_id(SeFastpathCoreContext core,
                                     SeFastpathPacketContext pc)
{
  uint8_t ipproto;
  uint8_t flow_id_flags;

  OCTEON_SE_DEBUG(9, "Calculate Flow ID\n");

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_NATT
  if (cvmx_unlikely(pc->s->ipsec_natt))
    ipproto = OCTEON_SE_FASTPATH_IPPROTO_ESP;
  else
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_NATT */
    ipproto = pc->s->ipproto;

  flow_id_flags = OCTEON_SE_FASTPATH_FLOW_ID_FLAG_FROMADAPTER;
  if (pc->s->ip_version_6 == 1)
    flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IP6;

  switch (ipproto)
    {
    case OCTEON_SE_FASTPATH_IPPROTO_UDP:




    case OCTEON_SE_FASTPATH_IPPROTO_TCP:
      octeon_se_fastpath_flow_id_hash(&pc->s->flow_id,
                                      core->salt, pc->s->tunnel_id,
                                      pc->s->src_port, pc->s->dst_port,
                                      ipproto, flow_id_flags,
                                      pc->s->src_ip_high, pc->s->src_ip_low,
                                      pc->s->dst_ip_high, pc->s->dst_ip_low);
      break;

    case OCTEON_SE_FASTPATH_IPPROTO_ESP:
    case OCTEON_SE_FASTPATH_IPPROTO_AH:
#ifdef OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY
      if (cvmx_unlikely(pc->s->ipsec_passby == 1))
        {
          /* For passby IPsec packets specify the addresses and IP proto. */
          octeon_se_fastpath_flow_id_hash(&pc->s->flow_id,
                                          core->salt, pc->s->tunnel_id,
                                          0, 0, ipproto, flow_id_flags,
                                          pc->s->src_ip_high,
                                          pc->s->src_ip_low,
                                          pc->s->dst_ip_high,
                                          pc->s->dst_ip_low);
        }
      else
#endif /* OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY */
        {
          /* For incoming IPsec packets specify the IPSEC_INCOMING flag
             and leave the addresses undefined. */
          flow_id_flags |= OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING;
          octeon_se_fastpath_flow_id_hash(&pc->s->flow_id,
                                          core->salt, pc->s->tunnel_id,
                                          pc->s->ipsec_spi, 0,
                                          ipproto, flow_id_flags,
                                          0, 0, 0, 0);
        }
      break;

    default:
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  pc->s->state = OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_ID_HASH;

  /* Always deschedule to allow atomic access to flow object */
  return OCTEON_SE_FASTPATH_RET_DESCHEDULE;
}


/******************** Flow lookup *******************************************/

/** Check that packet matches flow state. This function never causes
    deschedule. */
static inline SeFastpathRet
octeon_se_fastpath_post_flow_lookup_check(SeFastpathPacketContext pc)
{
  int i;

  if (pc->s->prev_transform_index == OCTEON_SE_FASTPATH_INVALID_INDEX)
    return OCTEON_SE_FASTPATH_RET_OK;

  else if (pc->s->forward == 1 &&
           (pc->s->prev_transform_index == pc->se_flow->rev_transform_index))
    return OCTEON_SE_FASTPATH_RET_OK;

  else if (pc->s->forward == 0 &&
           (pc->s->prev_transform_index == pc->se_flow->fwd_transform_index))
    return OCTEON_SE_FASTPATH_RET_OK;

  for (i = 0; i < OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS; i++)
    {
      if (pc->s->forward == 1
          && (pc->s->prev_transform_index ==
              pc->se_flow->fwd_rx_transform_index[i]))
        break;
      else if (pc->s->forward == 0
               && (pc->s->prev_transform_index ==
                   pc->se_flow->rev_rx_transform_index[i]))
        break;
    }
  if (cvmx_likely(i < OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS))
    return OCTEON_SE_FASTPATH_RET_OK;

  return OCTEON_SE_FASTPATH_RET_SLOWPATH;
}

/** Lookup flow for packet. This function never causes deschedule. If this
    succeeds then the flow is in pc->se_flow and it is read locked. If this
    causes slowpath processing, then pc->flow_index is set but
    pc->se_flow is undefined and pc->flow_index is used for creating the pow
    tag. */
static inline SeFastpathRet
octeon_se_fastpath_flow_lookup(SeFastpath fastpath,
                               SeFastpathCoreContext core,
                               SeFastpathPacketContext pc)
{
  uint8_t flow_lookup_flags = 0;
  uint64_t iport;

  OCTEON_SE_DEBUG(9, "Flow lookup\n");

  if (pc->s->tunnel_id != 0)
    iport = OCTEON_SE_FASTPATH_INVALID_PORT;
  else
    iport = pc->wqe->ipprt;

  if (pc->s->flow_id.id.flags & OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING)
    {
      /* For incoming IPsec packets compare only destination address */
      pc->se_flow =
        octeon_se_fastpath_lookup_flow(fastpath, &pc->s->flow_id,
                                       0, 0,
                                       pc->s->dst_ip_high, pc->s->dst_ip_low,
                                       iport, &flow_lookup_flags);
    }
  else
    {
      pc->se_flow =
        octeon_se_fastpath_lookup_flow(fastpath, &pc->s->flow_id,
                                       pc->s->src_ip_high, pc->s->src_ip_low,
                                       pc->s->dst_ip_high, pc->s->dst_ip_low,
                                       iport, &flow_lookup_flags);
    }

  pc->s->flow_index = OCTEON_SE_FASTPATH_FLOW_INDEX(fastpath, pc->se_flow);

  if (cvmx_unlikely(pc->se_flow == NULL))
    {
#ifdef OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY
      if (cvmx_unlikely(pc->s->flow_id.id.flags
                        & OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING))
        {
          /* Treat packet as passby IPsec and relookup flow */
          OCTEON_SE_DEBUG(9, "Relookup flow for passby IPsec\n");
          pc->s->ipsec_passby = 1;
          return octeon_se_fastpath_calculate_flow_id(core, pc);
        }
      else
#endif /* OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY */
        {
          OCTEON_SE_DEBUG(5, "No flow found\n");
          return OCTEON_SE_FASTPATH_RET_SLOWPATH;
        }
    }

  else if (cvmx_unlikely(pc->se_flow->flag_slow == 1))
    {
      OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, pc->s->flow_index,
                                          pc->se_flow);
      OCTEON_SE_DEBUG(5, "Slow flow found\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  if (flow_lookup_flags & OCTEON_SE_FASTPATH_FLOW_LOOKUP_FLAG_FORWARD)
    pc->s->forward = 1;
  else
    pc->s->forward = 0;

  /* Check that the packet matches the flow */
  if (cvmx_unlikely(octeon_se_fastpath_post_flow_lookup_check(pc)
                    != OCTEON_SE_FASTPATH_RET_OK))
    {
      OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, pc->s->flow_index,
                                          pc->se_flow);
      OCTEON_SE_DEBUG(3, "Flow does not pass post transform check\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  /* Assert that tag type is atomic. This stage is always entered after
     a deschedule so atomic access to the flow table has already been
     requested. */
  OCTEON_SE_ASSERT(pc->wqe->tag_type == CVMX_POW_TAG_TYPE_ATOMIC);

  /* Update last packet time stamp */
#ifdef OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS
  pc->se_flow->last_packet_time =
    cvmx_fau_fetch_and_add32(OCTEON_SE_FASTPATH_FAU_RUNTIME, 0);
#else /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */
  {
    uint32_t run_time;
    run_time = cvmx_fau_fetch_and_add32(OCTEON_SE_FASTPATH_FAU_RUNTIME, 0);
    cvmx_atomic_set32((int32_t *) &pc->se_flow->last_packet_time,
                      (int32_t) run_time);
  }
#endif /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */

  pc->s->state = OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_LOOKUP;

  return OCTEON_SE_FASTPATH_RET_OK;
}


/******************** Flow, transform and nexthop data caching ***************/

static inline SeFastpathRet
octeon_se_fastpath_copy_flow_data(SeFastpath fastpath,
                                  SeFastpathPacketContext pc)
{
  OCTEON_SE_ASSERT(pc != NULL);
  OCTEON_SE_ASSERT(pc->se_flow != NULL);

  OCTEON_SE_DEBUG(9, "Copy flow data\n");

  pc->flag_ipsec_incoming = pc->se_flow->flag_ipsec_incoming;

  if (pc->s->forward || pc->flag_ipsec_incoming)
    {
      pc->transform_index = pc->se_flow->fwd_transform_index;
      pc->nh_index = pc->se_flow->fwd_nh_index;
#ifdef OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS
      OCTEON_SE_FASTPATH_STATS(pc->se_flow->fwd_packets++);
      OCTEON_SE_FASTPATH_STATS(pc->se_flow->fwd_octets += pc->s->ip_len);
#else /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */
      OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *)
                                                 &pc->se_flow->fwd_packets,
                                                 1));
      OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *)
                                                 &pc->se_flow->fwd_octets,
                                                 pc->s->ip_len));
#endif /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */
    }
  else
    {
      pc->transform_index = pc->se_flow->rev_transform_index;
      pc->nh_index = pc->se_flow->rev_nh_index;
#ifdef OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS
      OCTEON_SE_FASTPATH_STATS(pc->se_flow->rev_packets++);
      OCTEON_SE_FASTPATH_STATS(pc->se_flow->rev_octets += pc->s->ip_len);
#else /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */
      OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *)
                                                 &pc->se_flow->rev_packets,
                                                 1));
      OCTEON_SE_FASTPATH_STATS(cvmx_atomic_add64((int64_t *)
                                                 &pc->se_flow->rev_octets,
                                                 pc->s->ip_len));
#endif /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */
    }

  if (cvmx_likely(pc->nh_index != OCTEON_SE_FASTPATH_INVALID_INDEX))
    OCTEON_SE_FASTPATH_PREFETCH_NH(OCTEON_SE_FASTPATH_NH(fastpath,
                                                         pc->nh_index));

  return OCTEON_SE_FASTPATH_RET_OK;
}

static inline SeFastpathRet
octeon_se_fastpath_copy_nh_data(SeFastpath fastpath,
                                SeFastpathPacketContext pc)
{
  SeFastpathNextHopData se_nh;

  OCTEON_SE_DEBUG(9, "Copy next hop data\n");

  OCTEON_SE_ASSERT(pc->nh_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
  OCTEON_SE_ASSERT(pc->nh_index < OCTEON_SE_FASTPATH_NH_TABLE_SIZE);

  se_nh = OCTEON_SE_FASTPATH_NH(fastpath, pc->nh_index);

  OCTEON_SE_FASTPATH_NH_READ_LOCK(fastpath, pc->nh_index, se_nh);

  if (cvmx_unlikely(se_nh->flag_slow == 1))
    {
      OCTEON_SE_FASTPATH_NH_READ_UNLOCK(fastpath, pc->nh_index, se_nh);
      OCTEON_SE_DEBUG(5, "Slow next hop found\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  pc->oport = se_nh->port;
  pc->mtu = se_nh->mtu;
  pc->min_packet_len = se_nh->min_packet_len;

  pc->media_hdrlen = se_nh->media_hdrlen;
  pc->media_hdr.raw[0] = se_nh->media_hdr.raw[0];
  pc->media_hdr.raw[1] = se_nh->media_hdr.raw[1];

  OCTEON_SE_FASTPATH_NH_READ_UNLOCK(fastpath, pc->nh_index, se_nh);

  return OCTEON_SE_FASTPATH_RET_OK;
}


/******************** Packet forwarding *************************************/

/** Forward packet. This function processes packets that are forwarded
    without any outbound transforms. */
static inline SeFastpathRet
octeon_se_fastpath_forward(SeFastpathPacketContext pc)
{
  uint8_t *header;
  uint16_t csum;

  OCTEON_SE_DEBUG(9, "Forward\n");

  OCTEON_SE_ASSERT(pc->transform_index == OCTEON_SE_FASTPATH_INVALID_INDEX);

  /* Check ttl */
  if (cvmx_unlikely(pc->s->ttl == 0))
    {
      OCTEON_SE_DEBUG(3, "Zero TTL, dropping\n");
      return OCTEON_SE_FASTPATH_RET_CORRUPT;
    }

  /* If SE fastpath does fragmenting, check if this packet is fragmentable
     and pass to slowpath if packet is too large and cannot be fragmented.
     Otherwise pass all over-MTU sized packets to slowpath. */
  if (cvmx_unlikely(
#ifdef OCTEON_SE_FASTPATH_FRAGMENTATION
                    (pc->s->ip_version_6 || pc->s->ipv4_df) &&
#endif /* !OCTEON_SE_FASTPATH_FRAGMENTATION */
                    pc->s->ip_len > pc->mtu))
    {
      OCTEON_SE_DEBUG(5, "Packet size exceeds MTU, passing to slowpath\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  CVMX_PREFETCH0(pc->wqe->packet_ptr.s.addr);

  /* From OCTEON SDK:
     Errata PKI-100 fix. We need to fix chain pointers on segmented
     packets. Although the size is also wrong on a single buffer packet,
     PKO doesn't care so we ignore it */
  if (cvmx_unlikely(pc->wqe->word2.s.bufs > 1))
    cvmx_helper_fix_ipd_packet_chain(pc->wqe);

  OCTEON_SE_ASSERT(pc->wqe->word2.s.bufs > 0);

  header = cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr) + pc->s->ip_offset;

  if (pc->s->ip_version_6)
    {
      /* Assert that header is in the first packet segment */
      OCTEON_SE_ASSERT(pc->wqe->packet_ptr.s.size
                       >= OCTEON_SE_FASTPATH_IP6_HDRLEN);

      /* No need to care about hoplimit alignment. */
      OCTEON_SE_FASTPATH_IPH6_SET_HL(header, pc->s->ttl - 1);
    }
  else
    {
      /* Assert that header is in the first packet segment */
      OCTEON_SE_ASSERT(pc->wqe->packet_ptr.s.size
                       >= OCTEON_SE_FASTPATH_IP4_HDRLEN);

      /* No need to care about ttl alignment. */
      OCTEON_SE_FASTPATH_IPH4_SET_TTL(header, pc->s->ttl - 1);

      /* These macros assert that checksum is 2 byte aligned.
         This should always be the case. */
      OCTEON_SE_FASTPATH_IPH4_CHECKSUM(header, csum);
      csum = octeon_se_fastpath_csum_update_byte(csum, SSH_IPH4_OFS_TTL,
                                                 pc->s->ttl, pc->s->ttl - 1);
      OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(header, csum);
    }

  return OCTEON_SE_FASTPATH_RET_OK;
}


/******************** Packet sending ****************************************/

/** Send packet out */
static inline SeFastpathRet
octeon_se_fastpath_send(SeFastpathCoreContext core,
                        SeFastpath fastpath,
                        SeFastpathPacketContext pc)
{
  uint8_t *media_hdr;
  uint64_t port;
  uint64_t queue;
  cvmx_pko_command_word0_t pko_command;

  OCTEON_SE_CORE_STATS(core->stats->pkt_tx++);

  OCTEON_SE_DEBUG(9, "Send\n");

  /* Prepare to send the packet. */
  OCTEON_SE_ASSERT(pc->oport != OCTEON_SE_FASTPATH_INVALID_PORT);
  port = pc->oport;
  queue = cvmx_pko_get_base_queue(port);
  cvmx_pko_send_packet_prepare(port, queue, CVMX_PKO_LOCK_CMD_QUEUE);

  /* Copy media header to packet. */
  OCTEON_SE_ASSERT(pc->nh_index != OCTEON_SE_FASTPATH_INVALID_INDEX);

  /* Assert that media header is always in the first packet segment. */
  OCTEON_SE_ASSERT(pc->wqe->packet_ptr.s.size > pc->media_hdrlen);

  /* Assert that there is enough headroom for media header. */
  OCTEON_SE_ASSERT(pc->s->ip_offset >= pc->media_hdrlen);
  media_hdr = cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr);
  if (cvmx_unlikely(pc->s->ip_offset > pc->media_hdrlen))
    {
      media_hdr += (pc->s->ip_offset - pc->media_hdrlen);
      pc->wqe->packet_ptr.s.addr = cvmx_ptr_to_phys(media_hdr);
      pc->wqe->packet_ptr.s.size -= (pc->s->ip_offset - pc->media_hdrlen);
      pc->s->ip_offset -= pc->media_hdrlen;
    }

  memcpy(media_hdr, pc->media_hdr.data, pc->media_hdrlen);

  /* Build PKO command */
  pko_command.u64 = 0;
  pko_command.s.total_bytes = pc->s->ip_offset + pc->s->ip_len;
  pko_command.s.segs = pc->wqe->word2.s.bufs;

  OCTEON_SE_CYCLE_COUNT_DONE(pc, core);

  /* Wait for the tag switch to complete. */
  cvmx_pow_tag_sw_wait();

  /* Send packet to PKO. */
  if (cvmx_unlikely(cvmx_pko_send_packet_finish(port, queue, pko_command,
                                                pc->wqe->packet_ptr,
                                                CVMX_PKO_LOCK_CMD_QUEUE)
                    != CVMX_PKO_SUCCESS))
    {
      OCTEON_SE_DEBUG(3, "PKO send failed: "
                      "port %lu queue %lu pko command 0x%lx\n",
                      port, queue, pko_command.u64);
      OCTEON_SE_DUMP_PACKET(7, pc);
      cvmx_helper_free_packet_data(pc->wqe);
    }

  cvmx_fpa_free(pc->wqe, CVMX_FPA_WQE_POOL, 0);

  return OCTEON_SE_FASTPATH_RET_OK;
}

#ifdef OCTEON_SE_FASTPATH_FRAGMENTATION

static inline SeFastpathRet
octeon_se_fastpath_fragment(SeFastpathCoreContext core,
                            SeFastpath fastpath,
                            SeFastpathPacketContext pc)
{
  SeFastpathFragmentContextStruct fragc;
  SeFastpathPacketContext frag;
  uint8_t df_on_first_fragment;
  size_t mtu = pc->mtu;

  OCTEON_SE_DEBUG(9, "Fragmenting packet\n");

  /* Enforce minimum fragment size. */
  if (pc->transform_index != OCTEON_SE_FASTPATH_INVALID_INDEX)
    {
      df_on_first_fragment =
        (pc->s->df_bit_processing != OCTEON_SE_FASTPATH_DF_CLEAR);
    }
  else
    {
      /* No IPSec processing.  Do not do PMTU discovery with the first
         fragment. */
      df_on_first_fragment = 0;
    }

  if (cvmx_likely(!pc->s->ip_version_6))
    {
      /* Enforce minimum fragment size for IPv4. */
      if (mtu < OCTEON_SE_FASTPATH_MIN_FIRST_FRAGMENT_V4)
        {
          mtu = OCTEON_SE_FASTPATH_MIN_FIRST_FRAGMENT_V4;
          df_on_first_fragment = 0;
        }
    }
  else
    {
      /* Enforce minimum fragment size for IPv6. */
      if (mtu < OCTEON_SE_FASTPATH_MIN_FIRST_FRAGMENT_V6)
        {
          mtu = OCTEON_SE_FASTPATH_MIN_FIRST_FRAGMENT_V6;
          df_on_first_fragment = 0;
        }
    }

  /* Initialize the fragmentation context. */
  if (cvmx_unlikely(octeon_se_fastpath_fragc_init(core, fastpath,
                                                  &fragc, pc, mtu,
                                                  df_on_first_fragment)))
    {
      /* The packet has DF set, and cannot be fragmented. For now
         send it to slowpath. */



      OCTEON_SE_DEBUG(5, "Cannot fragment packet with DF bit set, "
                      "passing to slowpath\n");
      return OCTEON_SE_FASTPATH_RET_SLOWPATH;
    }

  /* Get each fragment in turn and call the callback. */
  while ((frag = octeon_se_fastpath_fragc_next(core,
                                               fastpath,
                                               &fragc)) != NULL)
    {
      octeon_se_fastpath_send(core, fastpath, frag);
    }

  /* Deinitialize te fragmentation context. This frees the
     original  work queue entry and associate packet chain. */
  octeon_se_fastpath_fragc_uninit(core, fastpath, &fragc);

  return OCTEON_SE_FASTPATH_RET_OK;
}

#endif /* OCTEON_SE_FASTPATH_FRAGMENTATION */


/******************** Descheduling / Passing to slowpath ********************/

static inline void
octeon_se_fastpath_deschedule(SeFastpathCoreContext core,
                              SeFastpath fastpath,
                              SeFastpathPacketContext pc)
{
  OCTEON_SE_CORE_STATS(core->stats->pkt_desched++);
  OCTEON_SE_CYCLE_COUNT_DESCHED(pc, core);

  OCTEON_SE_DEBUG(9, "Deschedule\n");

  /* Encode packet state to wqe */
  octeon_se_fastpath_encode_pc(core, pc);

  OCTEON_SE_ASSERT(pc->s->state
                   == OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_ID_HASH);

  OCTEON_SE_ASSERT(pc->s->flow_id.raw[0] != 0 || pc->s->flow_id.raw[1] != 0);

  /* Deschedule to _DESCHED_GROUP with ATOMIC tag */
  pc->wqe->grp = OCTEON_SE_FASTPATH_DESCHED_GROUP;
  pc->wqe->tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
  cvmx_pow_tag_sw_desched(OCTEON_SE_FASTPATH_FLOW_LOOKUP_TAG
                          (pc->s->flow_id.id.hash_id),
                          CVMX_POW_TAG_TYPE_ATOMIC,
                          OCTEON_SE_FASTPATH_DESCHED_GROUP, 0);
}

static void
octeon_se_fastpath_drop(SeFastpathCoreContext core,
                        SeFastpath fastpath,
                        SeFastpathPacketContext pc)
{
  OCTEON_SE_DEBUG(7, "Drop\n");
  OCTEON_SE_DUMP_PACKET(7, pc);

  /* Wait for the tag switch to complete. */
  cvmx_pow_tag_sw_wait();

#ifdef OCTEON_SE_FASTPATH_STATISTICS
  /* Fix flow statistics */
  switch (pc->s->state)
    {
    case OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_LOOKUP:
    case OCTEON_SE_FASTPATH_PACKET_STATE_TR_EXECUTION:
    case OCTEON_SE_FASTPATH_PACKET_STATE_FINISH:
      OCTEON_SE_ASSERT(pc->s->flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
      pc->se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, pc->s->flow_index);
      OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, pc->s->flow_index,
                                         pc->se_flow);
      OCTEON_SE_FASTPATH_STATS(pc->se_flow->dropped_packets++);
      if (pc->s->forward || pc->se_flow->flag_ipsec_incoming)
        {
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->fwd_packets--);
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->fwd_octets -= pc->s->ip_len);
        }
      else
        {
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->rev_packets--);
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->rev_octets -= pc->s->ip_len);
        }
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, pc->s->flow_index,
                                           pc->se_flow);
      break;

    default:
      break;
    }
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

  OCTEON_SE_CORE_STATS(core->stats->pkt_drop++);

  cvmx_helper_free_packet_data(pc->wqe);
  cvmx_fpa_free(pc->wqe, CVMX_FPA_WQE_POOL, 0);
}

static void
octeon_se_fastpath_slowpath(SeFastpathCoreContext core,
                            SeFastpath fastpath,
                            SeFastpathPacketContext pc)
{
  SeFastpathControlCmd ctrl;
  uint64_t queue;
  uint32_t tag;
  cvmx_pow_iq_cntx_t pow_iq_cntx;
  uint32_t tunnel_id, prev_transform_index;

  OCTEON_SE_DEBUG(9, "Slowpath\n");

  /* Wait for the tag switch to complete. */
  cvmx_pow_tag_sw_wait();

  /* Put high priority packets to queue 0. */
  if (cvmx_likely(pc->flag_high_prio))
    {
      tag = OCTEON_SE_FASTPATH_SLOWPATH_TAG(OCTEON_SE_FASTPATH_INVALID_PORT);
      queue = OCTEON_SE_FASTPATH_HIGH_PRIO_QUEUE;
    }
  /* Put rest of the packets to the queue indexed by input port. */
  else
    {
      tag = OCTEON_SE_FASTPATH_SLOWPATH_TAG(pc->wqe->ipprt);
      queue = OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MIN
        + pc->wqe->ipprt % (OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MAX
                            - OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MIN + 1);
    }

  /* Check input queue length, drop packet if length exceeds the hard limit.
     The length here is the actual hardware queue length, thus it includes
     packets from all cores. */
  pow_iq_cntx.u64 = cvmx_read_csr(CVMX_POW_IQ_CNTX(queue));
  if (cvmx_unlikely(queue == OCTEON_SE_FASTPATH_HIGH_PRIO_QUEUE &&
                    pow_iq_cntx.s.iq_cnt >= OCTEON_SE_FASTPATH_HIGH_PRIO_QLEN))
    {
      OCTEON_SE_DEBUG(9, "Slowpath high prio queue %d full, dropping packet\n",
                      (int) queue);
      goto drop;
    }
  else if (cvmx_unlikely(queue != OCTEON_SE_FASTPATH_HIGH_PRIO_QUEUE
                         && (pow_iq_cntx.s.iq_cnt
                             >= OCTEON_SE_FASTPATH_NORMAL_PRIO_QLEN)))
    {
#ifdef OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING
      /* Do not allow more packets to this queue and only allow the guaranteed
         packet rate for other queues during this rate limit interval. */
      core->slowpath_pkt_count[OCTEON_SE_FASTPATH_RATE_LIMIT_BUCKET(queue)]
        = OCTEON_SE_FASTPATH_RATE_LIMIT_PKT;
      core->slowpath_total_pkt_count
        = OCTEON_SE_FASTPATH_RATE_LIMIT_TOTAL_PKT;
#endif /* OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING */

      OCTEON_SE_DEBUG(9, "Slowpath queue %d full, dropping packet\n",
                      (int) queue);
      goto drop;
    }

#ifdef OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING
  /* Check if need to rate limit. The rate limiting is done per core. */
  if (cvmx_unlikely(queue != OCTEON_SE_FASTPATH_HIGH_PRIO_QUEUE))
    {
      uint64_t cycles = cvmx_get_cycle();

      /* Zero packet counters if rate limit interval cycles have gone since
         last zeroing. */
      if (cvmx_unlikely((cycles - core->slowpath_cycle_count)
                        >= OCTEON_SE_FASTPATH_RATE_LIMIT_CYCLES))
        {
          core->slowpath_cycle_count = cycles;
          core->slowpath_pkt_count[OCTEON_SE_FASTPATH_RATE_LIMIT_BUCKET(queue)]
            = 0;
          core->slowpath_total_pkt_count = 0;
        }

      /* Check if packet can be passed to slowpath. This algorithm checks
         first the packet count for this queue and allows packet through
         if the packet count has not reached the guaranteed packet limit.
         Otherwise this checks the total packet count and allows packet
         through if total packet count has not reached the hard limit. */
      if (cvmx_unlikely((core->slowpath_pkt_count
                         [OCTEON_SE_FASTPATH_RATE_LIMIT_BUCKET(queue)]
                         >= OCTEON_SE_FASTPATH_RATE_LIMIT_PKT)
                        && (core->slowpath_total_pkt_count
                            >= OCTEON_SE_FASTPATH_RATE_LIMIT_TOTAL_PKT)))
        {
          OCTEON_SE_DEBUG(9,
                          "Slowpath rate limiting kicked in, dropping packet");
          goto drop;
        }

      /* Update per queue and total packet counts. */
      core->slowpath_total_pkt_count++;
      core->slowpath_pkt_count[OCTEON_SE_FASTPATH_RATE_LIMIT_BUCKET(queue)]++;
    }
#endif /* OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING */

#ifdef OCTEON_SE_FASTPATH_STATISTICS
  /* Fix flow statistics */
  switch (pc->s->state)
    {
    case OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_LOOKUP:
    case OCTEON_SE_FASTPATH_PACKET_STATE_TR_EXECUTION:
    case OCTEON_SE_FASTPATH_PACKET_STATE_FINISH:
      OCTEON_SE_ASSERT(pc->s->flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX);
      pc->se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, pc->s->flow_index);
      OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, pc->s->flow_index,
                                         pc->se_flow);
      if (pc->s->forward || pc->se_flow->flag_ipsec_incoming)
        {
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->fwd_packets--);
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->fwd_octets -= pc->s->ip_len);
        }
      else
        {
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->rev_packets--);
          OCTEON_SE_FASTPATH_STATS(pc->se_flow->rev_octets -= pc->s->ip_len);
        }
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, pc->s->flow_index,
                                           pc->se_flow);
      break;

    default:
      break;
    }
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

  OCTEON_SE_CORE_STATS(core->stats->pkt_slow++);

  /* Build a dummy media hdr to decapsulated packets so that cavium ethernet
     driver can put a meaningful value to skb->protocol. */
  if (pc->s->tunnel_id > 0)
    {
      uint8_t *media_hdr;

      OCTEON_SE_ASSERT(pc->s->ip_offset > 0);
      media_hdr = cvmx_phys_to_ptr(pc->wqe->packet_ptr.s.addr);

      memset(media_hdr, 0, pc->s->ip_offset - 2);

      if (pc->s->ip_version_6)
        OCTEON_SE_PUT_16BIT((media_hdr + pc->s->ip_offset - 2), 0x86dd);
      else
        OCTEON_SE_PUT_16BIT((media_hdr + pc->s->ip_offset - 2), 0x0800);
    }

  /* Encode tunnel_id and previous_transform_index to wqe */
  tunnel_id = pc->s->tunnel_id;
  prev_transform_index = pc->s->prev_transform_index;
  ctrl = (SeFastpathControlCmd) pc->wqe->packet_data;
  memset(ctrl, 0, sizeof(*ctrl));
  ctrl->cmd = OCTEON_SE_FASTPATH_CONTROL_CMD_SLOW;
  ctrl->tunnel_id = tunnel_id;
  ctrl->prev_transform_index = prev_transform_index;

  /* Submit to _SLOWPATH_GROUP */
  cvmx_pow_work_submit(pc->wqe, tag, CVMX_POW_TAG_TYPE_ORDERED, queue,
                       OCTEON_SE_FASTPATH_SLOWPATH_GROUP);

  return;

 drop:
  octeon_se_fastpath_drop(core, fastpath, pc);
}

/******************** Fastpath main function ********************************/

void
octeon_se_fastpath_packet_callback(SeFastpathCoreContext core,
                                   SeFastpath fastpath,
                                   cvmx_wqe_t *wqe)
{
  SeFastpathRet ret = OCTEON_SE_FASTPATH_RET_OK;
  SeFastpathPacketContext pc;

  /* Initialize packet context */
  pc = octeon_se_fastpath_init_pc(core, wqe);
  OCTEON_SE_ASSERT(pc != NULL);

  /* Step to next step. */
  if (pc->s->state == OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_ID_HASH)
    {
      OCTEON_SE_ASSERT(pc->s->flow_id.raw[0] != 0
                       && pc->s->flow_id.raw[1] != 0);
      goto lookup_flow;
    }
  else if (cvmx_unlikely(pc->s->state != OCTEON_SE_FASTPATH_PACKET_STATE_INIT))
    {
      /* This should never be reached. */
      OCTEON_SE_ASSERT(pc->s->state == OCTEON_SE_FASTPATH_PACKET_STATE_INIT);
      goto exception_packet;
    }

  /* Start of packet processing path. */

  /* Parse headers */
  ret = octeon_se_fastpath_initial_packet_pullup(core, fastpath, pc);
  if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
    goto exception_packet;

 calculate_flow_id:
  /* Calculate flow id */
  ret = octeon_se_fastpath_calculate_flow_id(core, pc);
  if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
    goto exception_packet;

 lookup_flow:
  /* Lookup flow */
  ret = octeon_se_fastpath_flow_lookup(fastpath, core, pc);
  if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
    goto exception_packet;

  /* Flow lookup locks the flow if one is found. */
  OCTEON_SE_ASSERT(pc->se_flow != NULL);

  /* Copy flow data */
  octeon_se_fastpath_copy_flow_data(fastpath, pc);

  /* Unlock flow. */
  OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, pc->s->flow_index,
                                      pc->se_flow);

  /* Execute transform. */
  if (pc->transform_index != OCTEON_SE_FASTPATH_INVALID_INDEX)
    {
      /* Do a tag switch to transform tag to allow other packets of
         this flow to enter processing. */
      cvmx_pow_tag_sw(OCTEON_SE_FASTPATH_TRD_TAG(pc->transform_index,
                                                 pc->flag_ipsec_incoming),
                      CVMX_POW_TAG_TYPE_ORDERED);

      /* Execute inbound transforms and restart packet. */
      if (pc->flag_ipsec_incoming)
        {
          ret = octeon_se_fastpath_transform_in(core, fastpath, pc);
          if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
            goto exception_packet;

          /* Prepare decapsulated packet for restart. */
          ret = octeon_se_fastpath_packet_restart(core, fastpath, pc);
          if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
            goto exception_packet;

          /* Restart packet processing. */
          goto calculate_flow_id;
        }

      /* Execute outbound transforms and forward packet. */
      else
        {
          /* Copy nh data. */
          ret = octeon_se_fastpath_copy_nh_data(fastpath, pc);
          if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
            goto exception_packet;

          ret = octeon_se_fastpath_transform_out(core, fastpath, pc);
          if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
            goto exception_packet;
        }
    }
  else
    {
      OCTEON_SE_ASSERT(pc->flag_ipsec_incoming == 0);

      /* Do a tag switch to processing stage to allow other packets of
         this flow to enter flow lookup stage. */
      cvmx_pow_tag_sw(OCTEON_SE_FASTPATH_FLOW_PROCESS_TAG(pc->s->flow_index,
                                                          pc->s->forward),
                      CVMX_POW_TAG_TYPE_ORDERED);

      /* Copy nh data. */
      ret = octeon_se_fastpath_copy_nh_data(fastpath, pc);
      if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
        goto exception_packet;

      /* Forward packet. */
      ret = octeon_se_fastpath_forward(pc);
      if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
        goto exception_packet;
    }

  /* Send packet out */
#ifdef OCTEON_SE_FASTPATH_FRAGMENTATION
  if (cvmx_unlikely(pc->s->ip_len > pc->mtu))
    {
      OCTEON_SE_DEBUG(9, "Packet needs fragmentation\n");
      ret = octeon_se_fastpath_fragment(core, fastpath, pc);
    }
  else
#endif /* OCTEON_SE_FASTPATH_FRAGMENTATION */
    {
      OCTEON_SE_ASSERT(pc->s->ip_len <= pc->mtu);
      ret = octeon_se_fastpath_send(core, fastpath, pc);
    }

  if (cvmx_unlikely(ret != OCTEON_SE_FASTPATH_RET_OK))
    goto exception_packet;

  return;

  /* Exception packet handling */
 exception_packet:

  /* Save packet state and deschedule (continue processing later) */
  if (cvmx_likely(ret == OCTEON_SE_FASTPATH_RET_DESCHEDULE))
    octeon_se_fastpath_deschedule(core, fastpath, pc);

  /* Pass packet to slowpath */
  else if (ret == OCTEON_SE_FASTPATH_RET_SLOWPATH)
    octeon_se_fastpath_slowpath(core, fastpath, pc);

  /* Drop packet */
  else
    octeon_se_fastpath_drop(core, fastpath, pc);

  return;
}
