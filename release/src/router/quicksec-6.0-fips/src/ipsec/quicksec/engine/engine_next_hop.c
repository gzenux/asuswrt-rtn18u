/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Next hop manipulation functions for the engine.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineNextHop"

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* Mask of next-hop flags that is used for comparing flags in next-hop lookup.
 */
#define ENGINE_NH_NODE_FLAG_MASK                                          \
  (SSH_ENGINE_NH_LOCAL | SSH_ENGINE_NH_INBOUND | SSH_ENGINE_NH_OUTBOUND | \
   SSH_ENGINE_NH_TRANSFORM_APPLIED | SSH_ENGINE_NH_FORWARD)

static void
engine_nh_node_hash_insert(SshEngine engine,
                           SshUInt32 nh_index,
                           SshIpAddr next_hop_gw,
                           SshEngineIfnum ifnum)
{
  SshEngineNextHopControl c_nh;
  SshUInt32 hash;

  c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
  SSH_ASSERT(c_nh != NULL);

  /* Insert nh entry to next_hop_addr_hash. */
  SSH_ASSERT(next_hop_gw != NULL);
  hash = SSH_IP_HASH(next_hop_gw);
  hash %= engine->next_hop_hash_size;

  c_nh->next = engine->next_hop_addr_hash[hash];
  engine->next_hop_addr_hash[hash] = nh_index;

  /* Insert nh entry to ifnum_hash. */
  SSH_ASSERT(ifnum != SSH_INTERCEPTOR_INVALID_IFNUM);
  hash = ifnum % SSH_ENGINE_NH_C_IFNUM_HASH_SIZE;

  c_nh->ifnum_hash_next = engine->next_hop_ifnum_hash[hash];
  engine->next_hop_ifnum_hash[hash] = nh_index;
}

static void
engine_nh_node_hash_remove(SshEngine engine,
                           SshUInt32 nh_index,
                           SshIpAddr next_hop_gw,
                           SshEngineIfnum ifnum)
{
  SshEngineNextHopControl c_nh, prev_c_nh;
  SshUInt32 prev_nh_index;
  SshUInt32 hash;

  SSH_ASSERT(nh_index != SSH_IPSEC_INVALID_INDEX);

  c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
  SSH_ASSERT(c_nh != NULL);

  /* Remove nh entry from next_hop_addr_hash. */
  SSH_ASSERT(next_hop_gw != NULL);
  hash = SSH_IP_HASH(next_hop_gw);
  hash %= engine->next_hop_hash_size;

  if (engine->next_hop_addr_hash[hash] == nh_index)
    {
      engine->next_hop_addr_hash[hash] = c_nh->next;
      c_nh->next = SSH_IPSEC_INVALID_INDEX;
    }
  else
    {
      for (prev_nh_index = engine->next_hop_addr_hash[hash];
           prev_nh_index != SSH_IPSEC_INVALID_INDEX;
           prev_nh_index = prev_c_nh->next)
        {
          prev_c_nh = SSH_ENGINE_GET_NH(engine, prev_nh_index);
          SSH_ASSERT(prev_c_nh != NULL);
          if (prev_c_nh->next == nh_index)
            {
              prev_c_nh->next = c_nh->next;
              c_nh->next = SSH_IPSEC_INVALID_INDEX;
              break;
            }
        }
      SSH_ASSERT(prev_nh_index != SSH_IPSEC_INVALID_INDEX);
    }

  /* Remove nh entry from ifnum_hash. */
  SSH_ASSERT(ifnum != SSH_INTERCEPTOR_INVALID_IFNUM);
  hash = ifnum % SSH_ENGINE_NH_C_IFNUM_HASH_SIZE;

  if (engine->next_hop_ifnum_hash[hash] == nh_index)
    {
      engine->next_hop_ifnum_hash[hash] = c_nh->ifnum_hash_next;
      c_nh->ifnum_hash_next = SSH_IPSEC_INVALID_INDEX;
    }
  else
    {
      for (prev_nh_index = engine->next_hop_ifnum_hash[hash];
           prev_nh_index != SSH_IPSEC_INVALID_INDEX;
           prev_nh_index = prev_c_nh->ifnum_hash_next)
        {
          prev_c_nh = SSH_ENGINE_GET_NH(engine, prev_nh_index);
          SSH_ASSERT(prev_c_nh != NULL);
          if (prev_c_nh->ifnum_hash_next == nh_index)
            {
              prev_c_nh->ifnum_hash_next = c_nh->ifnum_hash_next;
              c_nh->ifnum_hash_next = SSH_IPSEC_INVALID_INDEX;
              break;
            }
        }
      SSH_ASSERT(prev_nh_index != SSH_IPSEC_INVALID_INDEX);
    }
}


/* Lookup a next-hop node for the next-hop gateway `next_hop_gw' with
   flags `nh_node_flags'.  If there is no matching next-hop node, the
   function will allocate a new one with the attributes `ifnum',
   `mediatype', and `mtu'.  The function returns the next-hop node and
   its index in `index_return' or NULL and SSH_IPSEC_INVALID_INDEX in
   `index_return' if the allocation or lookup operation fails.  If the
   operation is successful, the function adds a reference to the
   returned next-hop node.  The function must be called holding
   `flow_table_lock'. If the next hop creation is ongoing, this
   function indicates it with optional argument nh_creation_ongoing.
   If this argument is defined and NULL is returned, the reference
   count of the next hop index in 'index_return' is increased. */
SshEngineNextHopControl
ssh_engine_lookup_nh_node(SshEngine engine,
                          SshIpAddr src_ip,
                          SshIpAddr next_hop_gw,
                          SshUInt32 nh_node_flags,
                          SshEngineIfnum ifnum,
                          SshInterceptorMedia mediatype,
                          size_t mtu,
                          SshUInt32 *index_return,
                          Boolean *nh_creation_ongoing)
{
  SshUInt32 nh_index, hashvalue;
  SshEngineNextHopData d_nh = NULL;
  SshEngineNextHopControl c_nh = NULL;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  *index_return = SSH_IPSEC_INVALID_INDEX;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Looking up next hop for src ip %@ next hop %@ flags 0x%x "
             "ifnum %u",
             ssh_ipaddr_render, src_ip, ssh_ipaddr_render, next_hop_gw,
             nh_node_flags, ifnum));

  if (nh_creation_ongoing != NULL)
    *nh_creation_ongoing = FALSE;

  /* Check if we have an existing entry for this node in the next hop table. */
  hashvalue = SSH_IP_HASH(next_hop_gw);
  hashvalue %= engine->next_hop_hash_size;
  nh_index = engine->next_hop_addr_hash[hashvalue];
  while (nh_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
      d_nh = FASTPATH_GET_READ_ONLY_NH(engine->fastpath, nh_index);
      SSH_ASSERT(c_nh != NULL);
      SSH_ASSERT(d_nh != NULL);
      SSH_ASSERT(d_nh->flags != 0);

      if (SSH_IP_EQUAL(&d_nh->dst, next_hop_gw)
          && (src_ip == NULL || SSH_IP_EQUAL(&d_nh->src, src_ip))
          && (d_nh->flags & ENGINE_NH_NODE_FLAG_MASK) == nh_node_flags
          && ifnum == d_nh->ifnum)
        {
          /* Found an entry */
          SSH_DEBUG(SSH_D_LOWOK, ("Found next hop node %d", (int) nh_index));

          /* But it is still being initialized. */
          if (d_nh->flags & SSH_ENGINE_NH_EMBRYONIC)
            {
              SSH_DEBUG(SSH_D_MIDOK, ("nh %d initialization ongoing",
                                      (int) nh_index));
              FASTPATH_RELEASE_NH(engine->fastpath, nh_index);

              if (nh_creation_ongoing != NULL)
                {
                  /* We need to return the nh index and increment ref count. */
                  *index_return = nh_index;
                  SSH_ENGINE_NH_NODE_TAKE_REF(c_nh);
                  *nh_creation_ongoing = TRUE;
                }

              return NULL;
            }

          /* How about failed? */
          if (d_nh->flags & SSH_ENGINE_NH_FAILED)
            {
              SSH_DEBUG(SSH_D_MIDOK, ("nh %d has failed!",
                                      (int) nh_index));
              FASTPATH_RELEASE_NH(engine->fastpath, nh_index);

              return NULL;
            }

          /* Ok, this nh entry is usable. */
          FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
          break;
        }

      FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
      nh_index = c_nh->next;
    }

  /* No usable next hop entry found. */
  if (nh_index == SSH_IPSEC_INVALID_INDEX)
    {
      /* Allocate a new nh entry from the freelist. */
      nh_index = engine->next_hop_hash_freelist;
      if (nh_index == SSH_IPSEC_INVALID_INDEX)
        {
#ifdef SSH_IPSEC_STATISTICS
          engine->stats.out_of_nexthops++;
#endif /* SSH_IPSEC_STATISTICS */

          SSH_DEBUG(SSH_D_FAIL, ("Out of next hop gateway nodes"));
          return NULL;
        }

      c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
      SSH_ASSERT(c_nh != NULL);
      SSH_ASSERT(c_nh->refcnt == 0);
      engine->next_hop_hash_freelist = c_nh->next;

      SSH_DEBUG(SSH_D_LOWOK, ("Creating next hop node %d", (int) nh_index));

      /* Initialize new nh entry. */
      d_nh = FASTPATH_INIT_NH(engine->fastpath, nh_index);

      d_nh->flags = SSH_ENGINE_NH_EMBRYONIC;
      d_nh->flags |= nh_node_flags;
      if (src_ip != NULL)
        d_nh->src = *src_ip;
      else
        SSH_IP_UNDEFINE(&d_nh->src);
      d_nh->dst = *next_hop_gw;
      d_nh->ifnum = ifnum;
      d_nh->mediatype = mediatype;
      d_nh->mtu = mtu;
      d_nh->media_hdr_len = 0;
      d_nh->min_packet_len = 0;
      d_nh->media_protocol = SSH_PROTOCOL_NUM_PROTOCOLS;

#ifdef SSH_IPSEC_STATISTICS
      engine->stats.active_nexthops++;
      engine->stats.total_nexthops++;
#endif /* SSH_IPSEC_STATISTICS */

      FASTPATH_COMMIT_NH(engine->fastpath, nh_index, d_nh);

      c_nh->refcnt = 0;

      /* Insert nh entry to hash tables. */
      engine_nh_node_hash_insert(engine, nh_index, next_hop_gw, ifnum);

      if (nh_creation_ongoing)
        *nh_creation_ongoing = TRUE;
    }

  /* Return node's index. */
  *index_return = nh_index;

  /* Add a reference. */
  SSH_ENGINE_NH_NODE_TAKE_REF(c_nh);

  return c_nh;
}

Boolean
ssh_engine_get_nh_node_media_header(SshEngine engine,
                                    SshIpAddr src_ip,
                                    SshIpAddr next_hop_gw,
                                    SshEngineIfnum ifnum,
                                    SshUInt8 nh_node_flags,
                                    unsigned char *media_header,
                                    SshUInt8 *media_header_len,
                                    SshUInt8 *min_packet_len,
                                    SshUInt8 *media_protocol)
{
  SshEngineNextHopData d_nh = NULL;
  SshEngineNextHopControl c_nh = NULL;
  SshUInt32 hashvalue, nh_index;
  Boolean ret;

  SSH_ASSERT(media_header != NULL);
  SSH_ASSERT(media_header_len != NULL);
  SSH_ASSERT(min_packet_len != NULL);
  SSH_ASSERT(media_protocol != NULL);

  SSH_DEBUG(SSH_D_LOWOK,
            ("Looking up media header for src %@ dst %@ flags 0x%x [%s%s%s] "
             "ifnum %u",
             ssh_ipaddr_render, src_ip,
             ssh_ipaddr_render, next_hop_gw,
             nh_node_flags,
             ((nh_node_flags & SSH_ENGINE_NH_LOCAL) ? "local " : ""),
             ((nh_node_flags & SSH_ENGINE_NH_OUTBOUND) ? "outbound " : ""),
             ((nh_node_flags & SSH_ENGINE_NH_INBOUND) ? "inbound" : ""),
             ifnum));

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Check if we have an existing entry for this node in the next hop table. */
  hashvalue = SSH_IP_HASH(next_hop_gw);
  hashvalue %= engine->next_hop_hash_size;
  nh_index = engine->next_hop_addr_hash[hashvalue];
  ret = FALSE;
  while (nh_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
      d_nh = FASTPATH_GET_READ_ONLY_NH(engine->fastpath, nh_index);
      SSH_ASSERT(c_nh != NULL);
      SSH_ASSERT(d_nh != NULL);
      SSH_ASSERT(d_nh->flags != 0);

      if (SSH_IP_EQUAL(&d_nh->dst, next_hop_gw)
          && (src_ip == NULL || SSH_IP_EQUAL(&d_nh->src, src_ip))
          && (d_nh->flags & ENGINE_NH_NODE_FLAG_MASK) == nh_node_flags
          && ifnum == d_nh->ifnum
          && d_nh->media_protocol == SSH_PROTOCOL_ETHERNET)
        {
          /* Found an entry */
          SSH_DEBUG(SSH_D_LOWOK, ("Found next hop node %d", (int) nh_index));
          ret = TRUE;
          memcpy(media_header, d_nh->mediahdr, d_nh->media_hdr_len);
          *media_header_len = (SshUInt8) d_nh->media_hdr_len;
          *min_packet_len = (SshUInt8) d_nh->min_packet_len;
          *media_protocol = (SshUInt8) d_nh->media_protocol;
          FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
          break;
        }

      FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
      nh_index = c_nh->next;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  return ret;
}

/* Update next-hop nodes MAC for the destination IP.  If there is no
   matching next-hop node, nothing is done. The function must be called
   holding `flow_table_lock'. */
void ssh_engine_update_nh_node_mac(SshEngine engine,
                                   SshIpAddr next_hop_gw,
                                   const SshEngineIfnum ifnum,
                                   const unsigned char *target_hw)
{
  SshUInt32 nh_index, hashvalue;
  SshEngineNextHopData d_nh = NULL;
  SshEngineNextHopControl c_nh = NULL;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_DEBUG(SSH_D_MIDOK,
            ("Next hop node update requested for addr %@ ifnum %u",
             ssh_ipaddr_render, next_hop_gw, ifnum));
  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Target link address:"),
                    target_hw, SSH_ETHERH_ADDRLEN);

  /* Check if we have an existing entry for this node in the next hop table. */
  SSH_ASSERT(ifnum != SSH_INTERCEPTOR_INVALID_IFNUM);
  hashvalue = ifnum % SSH_ENGINE_NH_C_IFNUM_HASH_SIZE;
  nh_index = engine->next_hop_ifnum_hash[hashvalue];
  while (nh_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
      d_nh = FASTPATH_GET_NH(engine->fastpath, nh_index);
      SSH_ASSERT(d_nh->flags != 0);

      if (SSH_IP_EQUAL(&d_nh->dst, next_hop_gw)
          && ifnum == d_nh->ifnum)
        {
          /* Found an entry */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Updating next hop node %d", (int) nh_index));
          if (d_nh->media_hdr_len == SSH_ETHERH_HDRLEN)
            SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Old destination link address:"),
                              d_nh->mediahdr + SSH_ETHERH_OFS_DST,
                              SSH_ETHERH_ADDRLEN);
          ssh_engine_modify_media_header(d_nh->mediatype, NULL, target_hw,
                                         0, d_nh->mediahdr);
          FASTPATH_COMMIT_NH(engine->fastpath, nh_index, d_nh);
        }
      else if (SSH_IP_EQUAL(&d_nh->src, next_hop_gw)
               && ifnum == d_nh->ifnum)
        {
          /* Found an entry */
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Updating next hop node %d", (int) nh_index));
          if (d_nh->media_hdr_len == SSH_ETHERH_HDRLEN)
            SSH_DEBUG_HEXDUMP(SSH_D_LOWOK, ("Old source link address:"),
                              d_nh->mediahdr + SSH_ETHERH_OFS_SRC,
                              SSH_ETHERH_ADDRLEN);
          ssh_engine_modify_media_header(d_nh->mediatype, target_hw, NULL,
                                         0, d_nh->mediahdr);
          FASTPATH_COMMIT_NH(engine->fastpath, nh_index, d_nh);
        }
      else
        {
          FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
        }

      nh_index = c_nh->next;
    }
}

void ssh_engine_nh_node_reroute(SshEngine engine,
                                SshIpAddr prefix,
                                SshUInt8 prefix_len,
                                SshEngineIfnum ifnum)
{
  SshUInt32 hash, nh_index;
  SshEngineNextHopControl c_nh;
  SshEngineNextHopData d_nh;
  SshIpAddrStruct prefix_with_mask;

  SSH_ASSERT(prefix != NULL);
  SSH_ASSERT(prefix_len <= (8 * SSH_IP_ADDR_LEN(prefix)));
  prefix_with_mask = *prefix;
  SSH_IP_MASK_LEN(&prefix_with_mask) = prefix_len;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  SSH_ASSERT(ifnum != SSH_INTERCEPTOR_INVALID_IFNUM);
  hash = ifnum % SSH_ENGINE_NH_C_IFNUM_HASH_SIZE;

  for (nh_index = engine->next_hop_ifnum_hash[hash];
       nh_index != SSH_IPSEC_INVALID_INDEX;
       nh_index = c_nh->ifnum_hash_next)
    {
      c_nh = SSH_ENGINE_GET_NH(engine, nh_index);
      d_nh = FASTPATH_GET_NH(engine->fastpath, nh_index);
      SSH_ASSERT(c_nh != NULL);
      SSH_ASSERT(d_nh != NULL);

      if ((d_nh->flags & SSH_ENGINE_NH_INBOUND) == 0
          && d_nh->ifnum == ifnum
          && SSH_IP_MASK_EQUAL(&d_nh->dst, &prefix_with_mask))
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Marking nh node %d for rerouting",
                                  (int) nh_index));
          d_nh->flags |= SSH_ENGINE_NH_REROUTE;
          FASTPATH_COMMIT_NH(engine->fastpath, nh_index, d_nh);
        }
      else
        FASTPATH_RELEASE_NH(engine->fastpath, nh_index);
    }
}

/* Decrements the reference count of the given next hop node, and frees it
   if the reference count becomes zero.  This must be called with
   engine->flow_control_table_lock held. */

void ssh_engine_decrement_next_hop_refcnt(SshEngine engine,
                                          SshUInt32 next_hop_index)
{
  SshEngineNextHopControl c_nh = NULL;
  SshEngineNextHopData d_nh;
  SshEngineIfnum ifnum;
  SshIpAddrStruct next_hop_gw;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Decrement the reference count of the node. */
  SSH_ASSERT(next_hop_index < engine->next_hop_hash_size);
  c_nh = SSH_ENGINE_GET_NH(engine, next_hop_index);

  SSH_ASSERT(c_nh->refcnt > 0);
  c_nh->refcnt--;

  SSH_DEBUG(SSH_D_LOWOK, ("Decrementing next hop node %d refcnt to %d",
                          (int) next_hop_index, c_nh->refcnt));

  /* If the reference count reaches zero, free the node. */
  if (c_nh->refcnt == 0)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("freeing next hop node %d",
                              (int)next_hop_index));

      /* Uninitialize next hop data object. */
      d_nh = FASTPATH_GET_NH(engine->fastpath, next_hop_index);

      next_hop_gw = d_nh->dst;
      ifnum = d_nh->ifnum;

      FASTPATH_UNINIT_NH(engine->fastpath, next_hop_index, d_nh);

      /* Remove nh entry from hash tables. */
      engine_nh_node_hash_remove(engine, next_hop_index, &next_hop_gw, ifnum);

      /* Return nh entry to freelist. */
      c_nh->next = engine->next_hop_hash_freelist;
      engine->next_hop_hash_freelist = next_hop_index;
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.active_nexthops--;
#endif /* SSH_IPSEC_STATISTICS */
    }
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
