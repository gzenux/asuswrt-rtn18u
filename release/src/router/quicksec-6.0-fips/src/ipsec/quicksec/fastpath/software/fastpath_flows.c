/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Software implementation of fastpath flow management functions.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathFlows"

#ifndef FASTPATH_PROVIDES_FLOW

/* A zero flow ID containing all zeroes. */
static const unsigned char
ssh_fastpath_flow_zeroid[SSH_ENGINE_FLOW_ID_SIZE] = {0};












#ifdef DEBUG_LIGHT
#define FP_GET_FLOW_ID(fastpath, table, flow_id_hash)                      \
(((flow_id_hash) >= (fastpath)->flow_id_hash_size                          \
  ? ssh_fatal("flow id hash out of bounds")                                \
    , (SshUInt32*)NULL                                                     \
  : &((fastpath)->table[(flow_id_hash) / SSH_ENGINE_FLOW_HASH_BLOCK_SIZE]  \
                     [(flow_id_hash) % SSH_ENGINE_FLOW_HASH_BLOCK_SIZE])))
#else /* DEBUG_LIGHT */
#define FP_GET_FLOW_ID(fastpath, table, flow_id_hash)                        \
(&((fastpath)->table[(flow_id_hash) / SSH_ENGINE_FLOW_HASH_BLOCK_SIZE]       \
                  [(flow_id_hash) % SSH_ENGINE_FLOW_HASH_BLOCK_SIZE]))
#endif /* DEBUG_LIGHT */

#define FP_GET_FLOW_BY_FORWARD_ID(fastpath, flow_id_hash) \
(*(FP_GET_FLOW_ID(fastpath, flow_forward_hash_root, flow_id_hash)))

#define FP_GET_FLOW_BY_REVERSE_ID(fastpath, flow_id_hash) \
(*(FP_GET_FLOW_ID(fastpath, flow_reverse_hash_root, flow_id_hash)))


#define FP_SET_FLOW_FORWARD_ID(fastpath, flow_id_hash, x) \
do {\
*(FP_GET_FLOW_ID(fastpath, flow_forward_hash_root, flow_id_hash)) = (x);\
} while(0)

#define FP_SET_FLOW_REVERSE_ID(fastpath, flow_id_hash, x) \
do {\
*(FP_GET_FLOW_ID(fastpath, flow_reverse_hash_root, flow_id_hash)) = (x);\
} while(0)

/* Returns a 32-bit hash value for the flow id.  Note that since we
   assume that a relatively good hash function is used, it is
   sufficient to just take enough bits from the beginning of the hash
   value.  Byte order does not matter here.  So we just read a 32-bit
   integer from the flow id. */
#define FP_FLOW_ID_HASH(flow_id) SSH_GET_32BIT(flow_id)


SshEngineFlowData
swi_fastpath_get_flow_lock(SshFastpath fastpath,
                           SshUInt32 flow_index,
                           Boolean lock_flow,
                           Boolean lock_hash_table)
{
  SshFastpathFlowData flow;

  flow = (SshFastpathFlowData)SSH_FASTPATH_GET_FLOW_DATA(fastpath, flow_index);
  SSH_ASSERT(flow != NULL);

  if (lock_hash_table)
    ssh_kernel_rw_mutex_lock_write(fastpath->flow_id_hash_table_lock);

  if (lock_flow)
    ssh_kernel_mutex_lock(&flow->lock);

  return flow->data;
}


/* This function implements a flow record replacement heuristic: the
   higher value it returns, the more important it is that the flow is
   not replaced. */
SSH_FASTTEXT static int
fastpath_sw_flow_lru_level(SshFastpath fastpath, SshUInt32 flow_index)
{
  /* Currently this function returns values in the range from 0 to 3,
     bounds included.  Assert that we indeed have that many LRU
     levels. */
  SSH_ASSERT(SSH_ENGINE_N_FLOW_LRU_LEVELS >= 4);

  if (SSH_PREDICT_TRUE(flow_index != SSH_IPSEC_INVALID_INDEX))
    {
      SshEngineFlowData d_flow;

      d_flow = swi_fastpath_get_flow_lock(fastpath, flow_index, FALSE, FALSE);

      if (SSH_PREDICT_FALSE(
            d_flow->data_flags & SSH_ENGINE_FLOW_D_IPSECINCOMING))
        /* Inbound IPSEC traffic is valued the highest. */
        return 3;

      if (d_flow->ipproto == SSH_IPPROTO_TCP)
        return ssh_engine_tcp_lru_level(d_flow);

      /* Give flows from local stack relatively high priority,
         as they may be e.g. DNS requests related to the operation
         of local services. */
#ifdef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      if (d_flow->reverse_local)
        return 2;
#else /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
      if (d_flow->reverse_nh_index != SSH_IPSEC_INVALID_INDEX)
        {
          SshEngineNextHopData nh_src;
          nh_src = FP_GET_NH(fastpath, d_flow->reverse_nh_index);

          SSH_ASSERT(nh_src != NULL);
          if (SSH_PREDICT_FALSE(nh_src->flags & SSH_ENGINE_NH_LOCAL))
            {
              return 2;
            }
        }
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      if (SSH_PREDICT_FALSE(d_flow->reverse_transform_index !=
                            SSH_IPSEC_INVALID_INDEX)
          || SSH_PREDICT_FALSE(d_flow->forward_transform_index !=
                               SSH_IPSEC_INVALID_INDEX))
        return 1;
    }

  return 0;
}


/* Adds the flow to the flow hash by both of its flow ids.
   The fastpath lock must be held when this is called.*/
static Boolean
sw_fastpath_add_to_flow_hash(SshFastpath fastpath, SshFastpathFlowData flow,
                             SshUInt32 flow_index)
{
  SshUInt32 hashvalue;
  Boolean is_available = FALSE;

  /* Add the flow to the flow hash table by the forward flow id.  But
     ignore flows with zero flow ID. */
  if (memcmp(flow->data->forward_flow_id, ssh_fastpath_flow_zeroid,
             SSH_ENGINE_FLOW_ID_SIZE) != 0)
    {
      hashvalue = FP_FLOW_ID_HASH(flow->data->forward_flow_id) %
        fastpath->flow_id_hash_size;
      flow->forward_next = FP_GET_FLOW_BY_FORWARD_ID(fastpath, hashvalue);
      FP_SET_FLOW_FORWARD_ID(fastpath, hashvalue, flow_index);

      SSH_DEBUG(SSH_D_MY, ("flow %d forward hash value %d",
                           (int) flow_index, (int) hashvalue));
      is_available = TRUE;
    }

  /* Add the flow to the flow hash table by the reverse flow id if
     the flow is not dangling and the id is not a zeroid. */
  if (memcmp(flow->data->reverse_flow_id, ssh_fastpath_flow_zeroid,
             SSH_ENGINE_FLOW_ID_SIZE) != 0)
    {
      hashvalue = FP_FLOW_ID_HASH(flow->data->reverse_flow_id) %
        fastpath->flow_id_hash_size;
      flow->reverse_next = FP_GET_FLOW_BY_REVERSE_ID(fastpath, hashvalue);
      FP_SET_FLOW_REVERSE_ID(fastpath, hashvalue, flow_index);

      SSH_DEBUG(SSH_D_MY, ("flow %d reverse hash value %d",
                           (int) flow_index, (int) hashvalue));
      is_available = TRUE;
    }

  return is_available;
}

/* Removes the flow from the flow hash (both of its flow ids).
   The fastpath lock must be held when this is called. */
static void
sw_fastpath_remove_from_flow_hash(SshFastpath fastpath,
                                  SshFastpathFlowDataCache cache,
                                  SshUInt32 flow_index)
{
  SshUInt32 hashvalue, *flowp;

  /* Remove the forward flow id from the forward flow id chain if it
     is there. */
  if (memcmp(cache->forward_flow_id, ssh_fastpath_flow_zeroid,
             SSH_ENGINE_FLOW_ID_SIZE) != 0)
    {
      SshFastpathFlowData tmp = NULL;

      hashvalue = FP_FLOW_ID_HASH(cache->forward_flow_id) %
        fastpath->flow_id_hash_size;
      for (flowp = &(FP_GET_FLOW_BY_FORWARD_ID(fastpath, hashvalue));
           *flowp != SSH_IPSEC_INVALID_INDEX;)
        {
          /* Not locking the flow as the forward_next field is protected
             by the flow_id_hash_table lock */
          tmp = (SshFastpathFlowData) swi_fastpath_get_flow_lock(fastpath,
                                                                 *flowp,
                                                                 FALSE, FALSE);
          if (*flowp == flow_index)
            break;
          flowp = &tmp->forward_next;
        }
      SSH_ASSERT(tmp != NULL);
      SSH_ASSERT(*flowp == flow_index);
      *flowp = tmp->forward_next;
#ifdef DEBUG_LIGHT
      tmp->forward_next = SSH_IPSEC_INVALID_INDEX;
#endif /* DEBUG_LIGHT */
    }

  /* Remove the reverse flow id from the reverse flow id chain if it
     is there. */
  if (memcmp(cache->reverse_flow_id, ssh_fastpath_flow_zeroid,
             SSH_ENGINE_FLOW_ID_SIZE) != 0)
    {
      SshFastpathFlowData tmp = NULL;

      hashvalue = FP_FLOW_ID_HASH(cache->reverse_flow_id) %
        fastpath->flow_id_hash_size;
      for (flowp = &(FP_GET_FLOW_BY_REVERSE_ID(fastpath, hashvalue));
           *flowp != SSH_IPSEC_INVALID_INDEX;)
        {
          /* Not locking the flow as the reverse_next field is protected
             by the flow_id_hash_table lock */
          tmp = (SshFastpathFlowData) swi_fastpath_get_flow_lock(fastpath,
                                                                 *flowp,
                                                                 FALSE, FALSE);
          if (*flowp == flow_index)
            break;
          flowp = &tmp->reverse_next;
        }

      SSH_ASSERT(tmp != NULL);
      SSH_ASSERT(*flowp == flow_index);
      *flowp = tmp->reverse_next;
#ifdef DEBUG_LIGHT
      tmp->reverse_next = SSH_IPSEC_INVALID_INDEX;
#endif /* DEBUG_LIGHT */
    }
}


SshEngineFlowData
sw_fastpath_get_flow(SshFastpath fastpath, SshUInt32 flow_index, Boolean ronly)
{
  SshEngineFlowData d_flow;

  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);

  SSH_ASSERT(SSH_ENGINE_FLOW_UNWRAP_GENERATION(flow_index) == 0);







  /* Get the flow element, lock the flow and flow hash table */
  d_flow = swi_fastpath_get_flow_lock(fastpath, flow_index, TRUE, TRUE);

  if (!ronly)
    {
      memcpy(fastpath->flow_cache->forward_flow_id, d_flow->forward_flow_id,
             sizeof(fastpath->flow_cache->forward_flow_id));
      memcpy(fastpath->flow_cache->reverse_flow_id, d_flow->reverse_flow_id,
             sizeof(fastpath->flow_cache->reverse_flow_id));
      fastpath->flow_cache->flow_lru_level = d_flow->flow_lru_level;
    }






  return d_flow;
}


void
sw_fastpath_commit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                        SshEngineFlowData data)
{
  SshEngineFlowData d_flow;
  Boolean is_available = FALSE;

  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);







  SSH_ASSERT(SSH_ENGINE_FLOW_UNWRAP_GENERATION(flow_index) == 0);

  d_flow = swi_fastpath_get_flow_lock(fastpath, flow_index, FALSE, FALSE);
  SSH_ASSERT(data == d_flow);

  if ((memcmp(fastpath->flow_cache->forward_flow_id,
              data->forward_flow_id,
              sizeof(fastpath->flow_cache->forward_flow_id)) != 0)
      || (memcmp(fastpath->flow_cache->reverse_flow_id,
                 data->reverse_flow_id,
                 sizeof(fastpath->flow_cache->reverse_flow_id)) != 0))
    {
      /* Remove flow from table based on old flow_id's */
      sw_fastpath_remove_from_flow_hash(fastpath, fastpath->flow_cache,
                                        flow_index);

      /* Add flow back using new flow_id's */
      is_available = sw_fastpath_add_to_flow_hash(fastpath,
                                                  (SshFastpathFlowData) d_flow,
                                                  flow_index);

      if (is_available)
          SSH_ASSERT(data->data_flags & SSH_ENGINE_FLOW_D_VALID);
    }

  /* Update the flow's LRU level */
  d_flow->flow_lru_level = fastpath_sw_flow_lru_level(fastpath, flow_index);

  /* If a flow is left dangling, it must not reference any transforms
     (e.g. no transform should have a refcnt because of a dangling flow). */
  SSH_ASSERT((d_flow->forward_transform_index == SSH_IPSEC_INVALID_INDEX
              && d_flow->reverse_transform_index == SSH_IPSEC_INVALID_INDEX)
             || (d_flow->data_flags & SSH_ENGINE_FLOW_D_DANGLING) == 0);

  /* Release the lock on the flow hash table and the flow table element */
  FP_COMMIT_FLOW_UNLOCK_HASH(fastpath, flow_index, d_flow);
}


void
sw_fastpath_uninit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                        SshEngineFlowData data)
{
  SshEngineFlowData d_flow;

  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);







  SSH_ASSERT(SSH_ENGINE_FLOW_UNWRAP_GENERATION(flow_index) == 0);

  d_flow = swi_fastpath_get_flow_lock(fastpath, flow_index, FALSE, FALSE);
  SSH_ASSERT(data == d_flow);

  /* Remove flow from table based on old flow_id's */
  sw_fastpath_remove_from_flow_hash(fastpath, fastpath->flow_cache,
                                    flow_index);

  SSH_DEBUG(SSH_D_MY,
            ("flow=%d lru level=%d", (int) flow_index,
             (int) d_flow->flow_lru_level));

  memset(d_flow->forward_flow_id, 0, sizeof(d_flow->forward_flow_id));
  memset(d_flow->reverse_flow_id, 0, sizeof(d_flow->reverse_flow_id));
  d_flow->flow_lru_level = SSH_ENGINE_N_FLOW_LRU_LEVELS;
  d_flow->data_flags = 0;

#ifdef DEBUG_LIGHT
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
  d_flow->forward_nh_index = SSH_IPSEC_INVALID_INDEX;
  d_flow->reverse_nh_index = SSH_IPSEC_INVALID_INDEX;
#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
  d_flow->forward_transform_index = SSH_IPSEC_INVALID_INDEX;
  d_flow->reverse_transform_index = SSH_IPSEC_INVALID_INDEX;
#endif /* DEBUG_LIGHT*/

  /* Release the lock on the flow hash table and the flow table element */
  FP_COMMIT_FLOW_UNLOCK_HASH(fastpath, flow_index, d_flow);
}


void
sw_fastpath_release_flow(SshFastpath fastpath, SshUInt32 flow_index)
{






  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);














  /* Release the lock on the flow hash table and the flow table element */
  FP_RELEASE_FLOW_UNLOCK_HASH(fastpath, flow_index);
}

SSH_FASTTEXT
Boolean fastpath_check_forward_flow_matches(SshEnginePacketContext pc,
                                            SshEngineFlowData d_flow)
{
  if (SSH_PREDICT_FALSE(pc->pp->routing_instance_id !=
                        d_flow->routing_instance_id))
    return FALSE;

  /* Compare packet and flow interface numbers unless ifnum filtering
     is disabled for the flow or if the packet has come from a tunnel. */
  if (memcmp(pc->flow_id, d_flow->forward_flow_id, sizeof(pc->flow_id)) == 0
      && (pc->pp->ifnum_in == d_flow->incoming_forward_ifnum
          || (d_flow->data_flags & SSH_ENGINE_FLOW_D_IGNORE_IFNUM)
          || pc->tunnel_id != 0))
    {
      /* For inbound IPsec packets we do not include the destination address
         in the flow id computation. So check here the destination address
         agrees with that in the flow. If not, then this is an IPsec packet
         not directed to us and flow lookup should be recomputed with the
         SSH_ENGINE_PC_IS_IPSEC flag cleared. */
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
#ifdef DEBUG_LIGHT
          if (SSH_IP_CMP(&pc->dst, &d_flow->dst_ip))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("IPsec flow lookup fails: dst address does not "
                         "match: packet=%@, flow=%@",
                         ssh_ipaddr_render, &pc->dst,
                         ssh_ipaddr_render, &d_flow->dst_ip));
            }
#endif /* DEBUG_LIGHT */

          return SSH_IP_CMP(&pc->dst, &d_flow->dst_ip) ? FALSE : TRUE;
        }

      return TRUE;
    }

#ifdef DEBUG_LIGHT
  if (memcmp(pc->flow_id, d_flow->forward_flow_id, sizeof(pc->flow_id)) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Forward flow lookup fails due to non-matching interface "
                 "numbers: packet=%d flow=%d",
                 pc->pp->ifnum_in,
                 d_flow->incoming_forward_ifnum));
    }
#endif /* DEBUG_LIGHT */

  return FALSE;
}

SSH_FASTTEXT
Boolean fastpath_check_reverse_flow_matches(SshEnginePacketContext pc,
                                            SshEngineFlowData d_flow)
{
  if (SSH_PREDICT_FALSE(pc->pp->routing_instance_id !=
                        d_flow->routing_instance_id))
    return FALSE;

  /* Compare packet and flow interface numbers unless ifnum filtering
     is disabled for the flow or if the packet has come from a tunnel. */
  if (memcmp(pc->flow_id, d_flow->reverse_flow_id, sizeof(pc->flow_id)) == 0
#ifdef SSH_IPSEC_REVERSE_IFNUM_FILTERING
      && (pc->pp->ifnum_in == d_flow->incoming_reverse_ifnum
          || (d_flow->data_flags & SSH_ENGINE_FLOW_D_IGNORE_IFNUM)
          || pc->tunnel_id != 0)
#endif /* SSH_IPSEC_REVERSE_IFNUM_FILTERING */
      )
    {
      /* For inbound IPsec packets we do not include the destination address
         in the flow id computation. So check here the destination address
         agrees with that in the flow. If not, then this is an IPsec packet
         not directed to us and flow lookup should be recomputed with the
         SSH_ENGINE_PC_IS_IPSEC flag cleared. */
      if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
        {
#ifdef DEBUG_LIGHT
          if (SSH_IP_CMP(&pc->dst, &d_flow->dst_ip))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("IPsec flow lookup fails: dst address does not "
                         "match: packet=%@, flow=%@",
                         ssh_ipaddr_render, &pc->dst,
                         ssh_ipaddr_render, &d_flow->dst_ip));
            }
#endif /* DEBUG_LIGHT */
#ifdef SSH_IPSEC_MULTICAST
          /* If flow has multicast peer, then compare source IP in reverse flow
           * with destination ip in packet.
           */
          if (SSH_IP_IS_MULTICAST(&d_flow->src_ip)) {
            SSH_DEBUG(SSH_D_LOWOK,(" Reverse flow with multicast peer: "
                          "Comparing pc->dst and d_flow->src_ip"));
            return SSH_IP_CMP(&pc->dst, &d_flow->src_ip) ? FALSE : TRUE;
          }
          else
#endif /* SSH_IPSEC_MULTICAST */
            return SSH_IP_CMP(&pc->dst, &d_flow->dst_ip) ? FALSE : TRUE;
        }

      return TRUE;
    }

#ifdef DEBUG_LIGHT
  if (memcmp(pc->flow_id, d_flow->reverse_flow_id, sizeof(pc->flow_id)) == 0)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Reverse flow lookup fails due to non-matching interface "
                 "numbers: packet=%d flow=%d",
                 pc->pp->ifnum_in,
                 d_flow->incoming_reverse_ifnum));
    }
#endif /* DEBUG_LIGHT */

  return FALSE;
}

SSH_FASTTEXT SshEngineFlowData
fastpath_sw_lookup_flow(SshFastpath fastpath, SshEnginePacketContext pc)
{
  SshUInt32 i, hashvalue;
  SshFastpathFlowData flow;

  ssh_kernel_rw_mutex_lock_read(fastpath->flow_id_hash_table_lock);

  /* Use the first 32 bits of the flow id as the hash value. */
  hashvalue = FP_FLOW_ID_HASH(pc->flow_id) % fastpath->flow_id_hash_size;

  SSH_DEBUG(SSH_D_MY, ("flow id hash %d", (int) hashvalue));

  /* First try to find the flow using the forward flow id. */
  for (i = FP_GET_FLOW_BY_FORWARD_ID(fastpath, hashvalue);
       i != SSH_IPSEC_INVALID_INDEX; i = flow->forward_next)
    {
      flow = (SshFastpathFlowData) swi_fastpath_get_flow_lock(fastpath, i,
                                                              TRUE, FALSE);

      SSH_DEBUG(SSH_D_MY, ("considering flow %d: %@->%@",
                           (int) i,
                           ssh_ipaddr_render, &flow->data->src_ip,
                           ssh_ipaddr_render, &flow->data->dst_ip));

      if (fastpath_check_forward_flow_matches(pc, flow->data))
        {
          pc->flags |= SSH_ENGINE_PC_FORWARD;
          pc->flow_index = i;
          return flow->data;
        }

      FP_RELEASE_FLOW(fastpath, i);
    }
  /* We did not found the flow using the forward flow id.  Try the reverse
     flow id. */
  for (i = FP_GET_FLOW_BY_REVERSE_ID(fastpath, hashvalue);
       i != SSH_IPSEC_INVALID_INDEX; i = flow->reverse_next)
    {
      flow = (SshFastpathFlowData) swi_fastpath_get_flow_lock(fastpath, i,
                                                              TRUE, FALSE);

      SSH_DEBUG(SSH_D_MY,("considering flow %d: %@->%@",
                          (int) i,
                          ssh_ipaddr_render, &flow->data->src_ip,
                          ssh_ipaddr_render, &flow->data->dst_ip));

      if (fastpath_check_reverse_flow_matches(pc, flow->data))
        {
          pc->flow_index = i;
          return flow->data;
        }
      FP_RELEASE_FLOW(fastpath, i);
    }

  ssh_kernel_rw_mutex_unlock_read(fastpath->flow_id_hash_table_lock);

  /* Have we made the assumption that this is an incoming ipsec flow.
     Apparently it is not, since a flow was not found.
     Mark that this packet is not an incoming IPSec flow and redo
     flow computation and flow lookup. */
  if (pc->flags & SSH_ENGINE_PC_IS_IPSEC)
    {
      pc->flags &= ~SSH_ENGINE_PC_IS_IPSEC;

      if (!(*fastpath->engine->flow_id_hash)(fastpath,
                                             pc, pc->pp, pc->tunnel_id,
                                             pc->flow_id))
        return NULL;

      return fastpath_sw_lookup_flow(fastpath, pc);
    }

  pc->flow_index = SSH_IPSEC_INVALID_INDEX;
  return NULL;
}


Boolean fastpath_sw_init_flows(SshFastpath fastpath)
{
  SshUInt32 i;

  for (i = 0; i < fastpath->flow_id_hash_size; i++)
    {
      FP_SET_FLOW_FORWARD_ID(fastpath, i, SSH_IPSEC_INVALID_INDEX);
      FP_SET_FLOW_REVERSE_ID(fastpath, i, SSH_IPSEC_INVALID_INDEX);
    }

  for (i = 0; i < SSH_ENGINE_N_FLOW_LRU_LEVELS; i++)
    {
      fastpath->flow_lru[i].head = SSH_IPSEC_INVALID_INDEX;
      fastpath->flow_lru[i].tail = SSH_IPSEC_INVALID_INDEX;
    }

  for (i = 0; i < fastpath->flow_table_size; i++)
    {
      SshFastpathFlowData flow;

      flow = (SshFastpathFlowData) swi_fastpath_get_flow_lock(fastpath, i,
                                                              FALSE, FALSE);

      flow->data->data_flags = 0;
      flow->data->generation = 0;
      flow->data->flow_lru_level = SSH_ENGINE_N_FLOW_LRU_LEVELS;
      memset(flow->data->forward_flow_id, 0,
             sizeof(flow->data->forward_flow_id));
      memset(flow->data->reverse_flow_id, 0,
             sizeof(flow->data->reverse_flow_id));

      if (!ssh_kernel_mutex_init(&flow->lock))
        return FALSE;
    }

  return TRUE;
}

void fastpath_sw_uninit_flows(SshFastpath fastpath)
{
  SshUInt32 i;

  for (i = 0; i < fastpath->flow_table_size; i++)
    {
      SshFastpathFlowData flow;
      flow = (SshFastpathFlowData) swi_fastpath_get_flow_lock(fastpath, i,
                                                              FALSE, FALSE);
      ssh_kernel_mutex_uninit(&flow->lock);
    }
}
#endif /* !FASTPATH_PROVIDES_FLOW */
