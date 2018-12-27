/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon fastpath for QuickSec.
   This file implements flow id calculation and flow lookup.
   This code is shared between SE fastpath and accelerated fastpath.
*/

#include "octeon_se_fastpath_shared.h"


/****************************** Flow ID calculation **************************/

void
octeon_se_fastpath_flow_id_hash(SeFastpathFlowIdUnion *flow_id,
                                uint32_t salt,
                                uint32_t tunnel_id,
                                uint32_t protocol_xid_high,
                                uint16_t protocol_xid_low,
                                uint8_t ipproto,
                                uint8_t flags,
                                uint64_t src_ip_high,
                                uint64_t src_ip_low,
                                uint64_t dst_ip_high,
                                uint64_t dst_ip_low)
{
  /* Fill in flow_id structure */
  flow_id->id.tunnel_id = tunnel_id;
  flow_id->id.protocol_xid_high = protocol_xid_high;
  flow_id->id.protocol_xid_low = protocol_xid_low;
  flow_id->id.ipproto = ipproto;
  flow_id->id.flags = flags;

  /* Create hash bucket index from the flow 5-tuple and salt. */
  flow_id->id.hash_id =
    protocol_xid_high ^
    (protocol_xid_low << 3) ^
    ((src_ip_low << 7) | (src_ip_low >> 25)) ^
    ((dst_ip_low << 13) | (dst_ip_low >> 19)) ^
    ipproto ^
    salt;

  /* Xor the high order bytes with the low order bytes to ensure that
     all fields of the 5-tuple affect the value of hash bucket index
     when flow hash table size is small (the hash bucket index is
     flow_id->id.hash_id % OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE). */
#if ((OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE) < 0xff)
  flow_id->id.hash_id ^= (flow_id->id.hash_id >> 24) & 0xff;
  flow_id->id.hash_id ^= (flow_id->id.hash_id >> 16) & 0xff;
  flow_id->id.hash_id ^= (flow_id->id.hash_id >> 8);
#elseif ((OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE) < 0xffff)
  flow_id->id.hash_id ^= (flow_id->id.hash_id >> 16);
#endif

  /* The hash bucket index  must always be non-zero to ensure that the
     whole flow_id never matches the reserved all-zeros flow id. */
  flow_id->id.hash_id |= (1 << 31);
}


/****************************** Flow lookup *********************************/

SeFastpathFlowData
octeon_se_fastpath_lookup_flow(SeFastpath fastpath,
                               SeFastpathFlowIdUnion *flow_id,
                               uint64_t src_ip_high,
                               uint64_t src_ip_low,
                               uint64_t dst_ip_high,
                               uint64_t dst_ip_low,
                               uint64_t iport,
                               uint8_t *flags)
{
  uint32_t hash_bucket;
  uint32_t flow_index, flow_index_next;
  SeFastpathFlowData se_flow = NULL;

  hash_bucket = OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(fastpath,
                                                    flow_id->id.hash_id);

  OCTEON_SE_FASTPATH_FLOW_HASH_READ_LOCK(fastpath, hash_bucket);

  /* Lookup flow in reverse direction. Flow lookup is done first in reverse
     direction to speed up lookup of incoming IPsec flows (which use primarly
     the reverse flow_id field). */
  for (flow_index = fastpath->flow_id_hash[hash_bucket].rev_flow_index;
       flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX;
       flow_index = flow_index_next)
    {
      se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);

#ifdef OCTEON_SE_FASTPATH_BUILD_SE
      /* Compare flow_id (tunnel_id, ports, ip version, ip protocol).
         This is deliberately done without having the flow locked. The
         flow_id is rechecked when the flow is locked. */
      if (cvmx_unlikely(flow_id->raw[0] != se_flow->rev_flow_id.raw[0]
                        || flow_id->raw[1] != se_flow->rev_flow_id.raw[1]))
        {
          goto next_reverse_unlocked;
        }

      /* Lock the flow. Note that we should have semi-exclusive access
         to the flow. Only a packet in forward direction might compete
         here. */
      OCTEON_SE_FASTPATH_FLOW_READ_LOCK(fastpath, flow_index, se_flow);

      /* Pass packet to slowpath immediately if flow is being removed */
      if (cvmx_unlikely(se_flow->flag_invalid == 1))
        {
          OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, flow_index, se_flow);
          se_flow = NULL;
          goto out;
        }
#else /* OCTEON_SE_FASTPATH_BUILD_SE */
      /* Lock the flow */
      OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, flow_index, se_flow);
#endif /* OCTEON_SE_FASTPATH_BUILD_SE */

      /* Compare flow_id (tunnel_id, ports, ip version, ip protocol) */
      if (cvmx_unlikely(flow_id->raw[0] != se_flow->rev_flow_id.raw[0]
                        || flow_id->raw[1] != se_flow->rev_flow_id.raw[1]))
        {
          goto next_reverse;
        }

      /* Compare addresses */
      if (cvmx_unlikely((flow_id->id.flags
                         & OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING) == 0
                        && (dst_ip_high != se_flow->src_ip_high
                            || dst_ip_low != se_flow->src_ip_low
                            || src_ip_high != se_flow->dst_ip_high
                            || src_ip_low != se_flow->dst_ip_low)))
        {
          goto next_reverse;
        }
      else if (cvmx_unlikely((flow_id->id.flags
                              & OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING)
                             && (dst_ip_high != se_flow->dst_ip_high
                                 || dst_ip_low != se_flow->dst_ip_low)))
        {
          goto next_reverse;
        }

      /* Check incoming port */
      if (cvmx_unlikely(iport != OCTEON_SE_FASTPATH_INVALID_PORT
                        && se_flow->flag_ignore_iport == 0
                        && iport != se_flow->rev_iport))
        {
          goto next_reverse;
        }

      /* Found exact match */
      *flags &= ~OCTEON_SE_FASTPATH_FLOW_LOOKUP_FLAG_FORWARD;
      CVMX_PREFETCH128(se_flow);
      goto out;

    next_reverse:
#ifdef OCTEON_SE_FASTPATH_BUILD_SE
      OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, flow_index, se_flow);
    next_reverse_unlocked:
#else /* OCTEON_SE_FASTPATH_BUILD_SE */
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, flow_index, se_flow);
#endif /* OCTEON_SE_FASTPATH_BUILD_SE */

      /* The rev_flow_index_next is protected by the hash bucket lock. */
      flow_index_next = se_flow->rev_flow_index_next;
    }
  se_flow = NULL;

  /* Lookup flow in forward direction. */
  for (flow_index = fastpath->flow_id_hash[hash_bucket].fwd_flow_index;
       flow_index != OCTEON_SE_FASTPATH_INVALID_INDEX;
       flow_index = flow_index_next)
    {
      se_flow = OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index);

#ifdef OCTEON_SE_FASTPATH_BUILD_SE
      /* Compare flow_id (tunnel_id, ports, ip version, ip protocol).
         This is deliberately done without having the flow locked. The
         flow_id is rechecked when the flow is locked. */
      if (cvmx_unlikely(flow_id->raw[0] != se_flow->fwd_flow_id.raw[0]
                        || flow_id->raw[1] != se_flow->fwd_flow_id.raw[1]))
        {
          goto next_forward_unlocked;
        }

      /* Lock the flow. Note that we should have semi-exclusive access
         to the flow. Only a packet in reverse direction might compete
         for the lock here. */
      OCTEON_SE_FASTPATH_FLOW_READ_LOCK(fastpath, flow_index, se_flow);

      /* Pass packet to slowpath immediately if flow is being removed */
      if (cvmx_unlikely(se_flow->flag_invalid == 1))
        {
          OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, flow_index, se_flow);
          se_flow = NULL;
          goto out;
        }
#else /* OCTEON_SE_FASTPATH_BUILD_SE */
      /* Lock the flow */
      OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, flow_index, se_flow);
#endif /* OCTEON_SE_FASTPATH_BUILD_SE */

      /* Compare flow_id (tunnel_id, ports, ip version, ip protocol) */
      if (cvmx_unlikely(flow_id->raw[0] != se_flow->fwd_flow_id.raw[0]
                        || flow_id->raw[1] != se_flow->fwd_flow_id.raw[1]))
        {
          goto next_forward;
        }

      /* Compare addresses */
      if (cvmx_unlikely((flow_id->id.flags
                         & OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING) == 0
                        && (src_ip_high != se_flow->src_ip_high
                            || src_ip_low != se_flow->src_ip_low
                            || dst_ip_high != se_flow->dst_ip_high
                            || dst_ip_low != se_flow->dst_ip_low)))
        {
          goto next_forward;
        }
      else if (cvmx_unlikely((flow_id->id.flags
                              & OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING)
                             && (dst_ip_high != se_flow->dst_ip_high
                                 || dst_ip_low != se_flow->dst_ip_low)))
        {
          goto next_forward;
        }

      /* Check incoming port */
      if (cvmx_unlikely(iport != OCTEON_SE_FASTPATH_INVALID_PORT
                        && se_flow->flag_ignore_iport == 0
                        && iport != se_flow->fwd_iport))
        {
          goto next_forward;
        }

      /* Found exact match */
      *flags |= OCTEON_SE_FASTPATH_FLOW_LOOKUP_FLAG_FORWARD;
      CVMX_PREFETCH128(se_flow);
      goto out;

    next_forward:
#ifdef OCTEON_SE_FASTPATH_BUILD_SE
      OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, flow_index, se_flow);
    next_forward_unlocked:
#else /* OCTEON_SE_FASTPATH_BUILD_SE */
      OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, flow_index, se_flow);
#endif /* OCTEON_SE_FASTPATH_BUILD_SE */

      /* The fwd_flow_index_next is protected by the hash bucket lock. */
      flow_index_next = se_flow->fwd_flow_index_next;
    }
  se_flow = NULL;

 out:
  OCTEON_SE_FASTPATH_FLOW_HASH_READ_UNLOCK(fastpath, hash_bucket);

  return se_flow;
}
