/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Reassembly and fragment matching code for the fastpath.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_accel.h"
#include "fastpath_impl.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathFragmentReassembly"

/* This adds the packet 'to be freed' list. ssh_interceptor_packet_free
   is not safe to be called inside locks, since otherwise we might end
   up in dead-lock type of situation. */

static void
ssh_fastpath_fragmagic_packet_free(SshInterceptorPacket input,
                                   SshInterceptorPacket *frag_free_list)
{
  SshInterceptorPacket pp = *frag_free_list;

  SSH_ASSERT(input != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Inserting packet %p to fragmagic free list.",
                               pp));

  /* Make sure we end the list. This modification should be ok,
     since we are freeing the packet. */
  input->next = NULL;

  /* Is the list empty, if is, insert as first.*/
  if (!(*frag_free_list))
    {
      *frag_free_list = input;
      return;
    }

  /* Go to the last entry on frag_free_list*/
  while (pp->next)
    pp = pp->next;

  pp->next = input;
}

/* Called in the end of ssh_fastpath_fragmagic() and
   ssh_fastpath_fragmagic_timeout() to really free the packets from
   interceptor. This function is not to be called inside locks!!! */

static void
ssh_fastpath_fragmagic_free_packet_list(SshInterceptorPacket frag_free_list)
{
  SshInterceptorPacket pp;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Removing fragmagic free list %p.",
                               frag_free_list));

  while (frag_free_list)
    {
      pp = frag_free_list;
      frag_free_list = pp->next;
      ssh_interceptor_packet_free(pp);
    }
}

/* Adds the given fragmagic entry to the LRU list of all fragmagic entries. */

void ssh_fastpath_fragmagic_add_all_lru(SshFastpath fastpath,
                                        SshFastpathFragEntry fe)
{
  fe->all_lru_prev = NULL;
  fe->all_lru_next = fastpath->frag_all_lru_head;
  fastpath->frag_all_lru_head = fe;
  if (fe->all_lru_next)
    fe->all_lru_next->all_lru_prev = fe;
  if (fastpath->frag_all_lru_tail == NULL)
    fastpath->frag_all_lru_tail = fe;
}

/* Removes the given fragmagic entry from the LRU list of all fragmagic
   entries. */

void ssh_fastpath_fragmagic_remove_all_lru(SshFastpath fastpath,
                                         SshFastpathFragEntry fe)
{
  if (fe == fastpath->frag_all_lru_head)
    fastpath->frag_all_lru_head = fe->all_lru_next;
  else
    fe->all_lru_prev->all_lru_next = fe->all_lru_next;
  if (fe == fastpath->frag_all_lru_tail)
    fastpath->frag_all_lru_tail = fe->all_lru_prev;
  else
    fe->all_lru_next->all_lru_prev = fe->all_lru_prev;
#ifdef DEBUG_LIGHT
  fe->all_lru_next = (SshFastpathFragEntry)(size_t)0xdeadbeef;
  fe->all_lru_prev = (SshFastpathFragEntry)(size_t)0xdeadbeef;
#endif /* DEBUG_LIGHT */
}

/* Adds the given fragmagic entry to the LRU list of fragmagic entries with
   fragments.  This does nothing if the entry has no fragments queued. */

void ssh_fastpath_fragmagic_add_data_lru(SshFastpath fastpath,
                                         SshFastpathFragEntry fe)
{
  /* Do nothing if we don't have any data. */
  if (fe->pp_chain == NULL)
    {
#ifdef DEBUG_LIGHT
      fe->data_lru_next = (SshFastpathFragEntry)(size_t)0xdeadbeef;
      fe->data_lru_prev = (SshFastpathFragEntry)(size_t)0xdeadbeef;
#endif /* DEBUG_LIGHT */
      return;
    }

  /* Add this entry to the data LRU. */
  fe->data_lru_prev = NULL;
  fe->data_lru_next = fastpath->frag_data_lru_head;
  fastpath->frag_data_lru_head = fe;
  if (fe->data_lru_next)
    fe->data_lru_next->data_lru_prev = fe;
  if (fastpath->frag_data_lru_tail == NULL)
    fastpath->frag_data_lru_tail = fe;
}

/* Removes the given fragmagic entry from the LRU list of fragmagic
   entries with fragments. This does nothing if the entry has no
   fragments queued. */

void ssh_fastpath_fragmagic_remove_data_lru(SshFastpath fastpath,
                                          SshFastpathFragEntry fe)
{
  /* Do nothing if we don't have any data. */
  if (fe->pp_chain)
    {
      /* Remove this entry from the data LRU. */
      if (fe == fastpath->frag_data_lru_head)
        fastpath->frag_data_lru_head = fe->data_lru_next;
      else
        fe->data_lru_prev->data_lru_next = fe->data_lru_next;
      if (fe == fastpath->frag_data_lru_tail)
        fastpath->frag_data_lru_tail = fe->data_lru_prev;
      else
        fe->data_lru_next->data_lru_prev = fe->data_lru_prev;
    }
#ifdef DEBUG_LIGHT
  fe->data_lru_next = (SshFastpathFragEntry)(size_t)0xdeadbeef;
  fe->data_lru_prev = (SshFastpathFragEntry)(size_t)0xdeadbeef;
#endif /* DEBUG_LIGHT */
}

/* Calculate a hashvalue for a frag id. */
#define SSH_ENGINE_FRAG_ID_HASH(fid)            \
  (ssh_ipaddr_hash(&(fid)->src) ^ (fid)->id)

/* Test if two frag ids are equal. */
#define SSH_ENGINE_FRAG_ID_EQUAL(fida, fidb)    \
  ( ((fida)->id == (fidb)->id)                  \
    && ((fida)->ipproto == (fidb)->ipproto)     \
    && SSH_IP_EQUAL(&(fida)->src, &(fidb)->src) \
    && SSH_IP_EQUAL(&(fida)->dst, &(fidb)->dst) )

/* Adds the entry to the fragmagic hash table. */

void ssh_fastpath_fragmagic_add_hash(SshFastpath fastpath,
                                     SshFastpathFragEntry fe)
{
  SshUInt32 hashvalue;

  hashvalue = SSH_ENGINE_FRAG_ID_HASH(fe->frag_id);
  hashvalue %= SSH_ENGINE_FRAGMENT_HASH_SIZE;
  fe->hash_next = fastpath->frag_hash[hashvalue];
  fastpath->frag_hash[hashvalue] = fe;
}

/* Removes the entry from the fragmagic hash table. */

void ssh_fastpath_fragmagic_remove_hash(SshFastpath fastpath,
                                        SshFastpathFragEntry fe)
{
  SshUInt32 hashvalue;
  SshFastpathFragEntry *fep;

  hashvalue = SSH_ENGINE_FRAG_ID_HASH(fe->frag_id);
  hashvalue %= SSH_ENGINE_FRAGMENT_HASH_SIZE;
  for (fep = &fastpath->frag_hash[hashvalue];
       *fep && *fep != fe;
       fep = &(*fep)->hash_next)
    ;
  SSH_ASSERT(*fep == fe);
  *fep = fe->hash_next;
#ifdef DEBUG_LIGHT
  fe->hash_next = (SshFastpathFragEntry)(size_t)0xdeadbeef;
#endif /* DEBUG_LIGHT */
}

/* Computes fragpacketid (hash of information that identifies the packet).
   The hashed fragpacketid is stored in frag_id.  This returns TRUE on
   success, and FALSE if an error occurs (in which case pc->pp is freed). */
Boolean ssh_fastpath_fragmagic_compute_id(SshFastpath fastpath,
                                          SshEnginePacketContext pc,
                                          SshFastpathFragId frag_id)
{
  const unsigned char *ucp;

  frag_id->src = pc->src;
  frag_id->dst = pc->dst;

#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    {
      frag_id->id = pc->fragment_id;
      frag_id->ipproto = 0;
      /* Note that `frag_id->ipproto' is deliberately left unassigned. */
    }
  else
#endif /* WITH_IPV6 */
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ucp = ssh_interceptor_packet_pullup_read(pc->pp, SSH_IPH4_HDRLEN);
      if (!ucp)
        {
          pc->pp = NULL;
          return FALSE;
        }
      frag_id->id = SSH_IPH4_ID(ucp);
      frag_id->ipproto = SSH_IPH4_PROTO(ucp);
    }

  return TRUE;
}

/* Frees any packets queued in the entry, and adjusts global statistics
   about fragments. */
void ssh_fastpath_fragmagic_clear_entry(SshFastpath fastpath,
                                        SshFastpathFragEntry fe,
                                        SshInterceptorPacket *frag_free_list)
{
  SshInterceptorPacket pp;

  ssh_kernel_mutex_assert_is_locked(fastpath->frag_lock);

  /* Free all queued packets. */
  while (fe->pp_chain)
    {
      pp = fe->pp_chain;
      fe->pp_chain = pp->next;
      ssh_fastpath_fragmagic_packet_free(pp, frag_free_list);
    }

  /* Update global statistics. */
  fastpath->frag_num_fragments -= fe->num_frags;
  fastpath->frag_num_bytes -= fe->total_bytes;
  fe->num_frags = 0;
  fe->total_bytes = 0;
  fe->total_bytes = 0;
  fe->packet_size = 0;
}

/* Drops the least recently used packet that has data associated with it.
   This returns the number of fragments that were freed.  If there are
   no more packets in queue with data, then this returns NULL.  This must
   be called with fastpath->frag_lock held. */

SshUInt32 ssh_fastpath_fragmagic_drop_data(SshFastpath fastpath,
                                          SshInterceptorPacket *frag_free_list)
{
  SshFastpathFragEntry fe;
  SshUInt32 num_frags;

  ssh_kernel_mutex_assert_is_locked(fastpath->frag_lock);
  /* Get the oldest entry from the data LRU. */
  fe = fastpath->frag_data_lru_tail;
  if (!fe)
    return 0;
  /* Sanity check that it has data. */
  SSH_ASSERT(fe->num_frags > 0);
  /* Clear the entry. */
  fe->flags |= SSH_ENGINE_FRAG_REJECT;
  num_frags = fe->num_frags;
  ssh_fastpath_fragmagic_remove_data_lru(fastpath, fe);
  ssh_fastpath_fragmagic_clear_entry(fastpath, fe, frag_free_list);
  /* "Add" the entry on the data LRU.  This does not actually add it, but
     instead may prepare it for sanity checks. */
  ssh_fastpath_fragmagic_add_data_lru(fastpath, fe);
  return num_frags;
}

/* Drops all fragments currently held in fastpath fragmagic.
   This returns the number of fragments that were freed. This cannot
   be called with fastpath->frag_lock held. */

SshUInt32 ssh_fastpath_fragmagic_drop_all(SshFastpath fastpath)
{
  SshInterceptorPacket frag_free_list = NULL;
  SshUInt32 freed_packets = 0, num = 0;

  SSH_ASSERT(fastpath != NULL);

  ssh_kernel_mutex_lock(fastpath->frag_lock);
  freed_packets += num = ssh_fastpath_fragmagic_drop_data(fastpath,
                                                          &frag_free_list);
  while (num)
    freed_packets += num = ssh_fastpath_fragmagic_drop_data(fastpath,
                                                            &frag_free_list);

  ssh_kernel_mutex_unlock(fastpath->frag_lock);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Dropping all fragments (%u dropped).",
                               freed_packets));

  ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
  return freed_packets;
}


/* This function is called periodically from a timeout.  This clears all
   expired entries from the end of the data LRU.  The purpose of this is
   to cause the reassembly data structures to become empty with time if
   previously there were a lot of packets with missing fragments (often
   a result of an attack attempt), and such fragments are no longer being
   received.  This basically just causes the packet buffers to be released
   for other uses. */

void ssh_fastpath_fragmagic_timeout(void *context)
{
  SshFastpath fastpath = (SshFastpath)context;
  SshFastpathFragEntry fe;
  SshUInt32 num_frags;
  SshTime now;
  SshInterceptorPacket frag_free_list = NULL;

  ssh_interceptor_get_time(&now, NULL);

  SSH_DEBUG(SSH_D_MIDOK, ("Fragmagic timer; tick at %ld",
                          (long) now));

  ssh_kernel_mutex_lock(fastpath->frag_lock);

  fastpath->frag_timeout_scheduled = 0;
  num_frags = fastpath->frag_num_fragments;

  /* Keep looping as long as the last packet on the data LRU has expired.
     Note that it might not be strictly the oldest, but soon will be. */
  for (;;)
    {
      fe = fastpath->frag_data_lru_tail;
      if (!fe || fe->expiration > now)
        break;

      /* OK, consider sending ICMP time exceeded message. This is only
         done for IPv6 at the current. First fragment is needed as it
         needs to be sent to the peer as information. */
      if (fe->flags & SSH_ENGINE_FRAG_QUEUED_FIRST)
        {
          SshInterceptorPacket ipp = fe->pp_chain;
          SshInterceptorPacket npp;
          SshInterceptor interceptor = fastpath->engine->interceptor;

          SSH_ASSERT(ipp != NULL);
          SSH_ASSERT(ipp->flags & SSH_ENGINE_P_ISFRAG);

          /* First fragment and IPv6 to non-multicast destination. */
          if ((ipp->flags & SSH_ENGINE_P_FIRSTFRAG)
              && ipp->protocol == SSH_PROTOCOL_IP6
              && !SSH_IP6_IS_MULTICAST(&fe->frag_id->dst))
            {
              SshEnginePacketContext ipc;

              npp =
                ssh_interceptor_packet_alloc_and_copy_ext_data(
                                              interceptor, ipp,
                                              ssh_interceptor_packet_len(ipp));

              if (npp == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Could not allocate pp for sending"
                                         "ICMP time exceeded."));
                  goto drop;
                }

              if (ssh_interceptor_packet_copy(ipp, 0,
                                              ssh_interceptor_packet_len(ipp),
                                              npp, 0) == FALSE)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Packet data copying failed, cannot "
                                         "send ICMP time exceeded."));
                  goto drop;
                }


              ipc = ssh_engine_alloc_pc(fastpath->engine);
              if (ipc == NULL)
                {
                  SSH_DEBUG(SSH_D_FAIL, ("Could not allocate PC for sending"
                                         "ICMP time exceeded."));
                  ssh_interceptor_packet_free(npp);
                  goto drop;
                }

              if (!ssh_engine_init_and_pullup_pc(ipc, fastpath->engine,
                                                 npp, fe->tunnel_id,
                                                 SSH_IPSEC_INVALID_INDEX))
                {
                  if (ipc->pp != NULL)
                    ssh_interceptor_packet_free(ipc->pp);
                  ipc->pp = NULL;

                  ssh_engine_free_pc(fastpath->engine, ipc);
                  SSH_DEBUG(SSH_D_FAIL, ("Init PC failed."));
                  goto drop;
                }

              /* Were done, generate the ICMP message. */
              ssh_engine_send_icmp_error(fastpath->engine, ipc,
                                         SSH_ICMP6_TYPE_TIMXCEED,
                                         SSH_ICMP_CODE_TIMXCEED_REASS, 0);

              /* Free the temporary packet context. */
              ssh_engine_free_pc(fastpath->engine, ipc);
            }
        }

    drop:
      /* Drop the oldest packet on the data LRU.  We now know that it has
         already expired. */
      ssh_fastpath_fragmagic_drop_data(fastpath, &frag_free_list);
    }
  num_frags -= fastpath->frag_num_fragments;

  /* Possibly reschedule a timeout to this function. */
  if (fastpath->frag_num_fragments)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Fragmagic timer; %d frags left - reschedule",
                              (int) fastpath->frag_num_fragments));
      fastpath->frag_timeout_scheduled = 1;
      ssh_kernel_timeout_register(5, 0,
                                  ssh_fastpath_fragmagic_timeout, fastpath);
    }
  ssh_kernel_mutex_unlock(fastpath->frag_lock);

#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].counters[SSH_ENGINE_STAT_FRAGDROP]
    += num_frags;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

  ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
}

/* Returns a fragmagic entry that we can reuse.  The returned entry is
   not in the hash table, not in all_lru, and not in data_lru. */

SshFastpathFragEntry ssh_fastpath_fragmagic_get_entry(SshFastpath fastpath,
                                        SshInterceptorPacket *frag_free_list)
{
  SshFastpathFragEntry fe;

  fe = fastpath->frag_all_lru_tail;
  ssh_fastpath_fragmagic_remove_data_lru(fastpath, fe);
  ssh_fastpath_fragmagic_remove_all_lru(fastpath, fe);
  ssh_fastpath_fragmagic_clear_entry(fastpath, fe, frag_free_list);
  ssh_fastpath_fragmagic_remove_hash(fastpath, fe);
  return fe;
}

/* Returns TRUE if the entry contains a full packet just waiting to be
   merged, and FALSE if more fragments are still needed. */

Boolean ssh_fastpath_fragmagic_full_packet(SshFastpathFragEntry fe)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("packet size %u total bytes %u flags 0x%08x",
             fe->packet_size, fe->total_bytes, fe->flags));

  return (fe->flags & SSH_ENGINE_FRAG_QUEUED_FIRST) &&
    (fe->flags & SSH_ENGINE_FRAG_QUEUED_LAST) &&
    fe->packet_size == fe->total_bytes;
}

/* Pullup information from a packetcontext which has been
   either sent or or queued to the fragentry fe */
static void
ssh_fastpath_fragmagic_pullup(SshFastpath fastpath,
                              SshFastpathFragEntry fe,
                              SshEnginePacketContext pc)
{
  if (pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG)
    memcpy(fe->flow_id, pc->flow_id, sizeof(fe->flow_id));

  if (pc->pp->flags & SSH_ENGINE_P_LASTFRAG)
    fe->packet_size = pc->frag_packet_size;

  if (pc->min_packet_size > fe->min_packet_size)
    fe->min_packet_size = pc->min_packet_size;
}

/* Pullup information from a packetcontext which has been
   sent to the fragentry fe. */
static void
ssh_fastpath_fragmagic_sent(SshFastpath fastpath,
                          SshFastpathFragEntry fe,
                          SshEnginePacketContext pc)
{
  const unsigned char *ucp;
  SshUInt32 fragoff, next_off;

  ssh_fastpath_fragmagic_pullup(fastpath,fe,pc);

  if (pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG)
    {
      /* Indicate that we have received the first fragment, and save
         the flow id. The HAVE_LAST flag will be set in
         ssh_fastpath_fragmagic_enqueue. */
      fe->flags |= SSH_ENGINE_FRAG_SENT_FIRST;
    }

  if (pc->pp->flags & SSH_ENGINE_P_LASTFRAG)
    {
      /* If SSH_ENGINE_P_LASTFRAG is set then ssh_fastpath_context_pullup()
         must have initialized frag_packet_size. */
      fe->packet_size = pc->frag_packet_size;
      fe->flags |= SSH_ENGINE_FRAG_SENT_LAST;
    }

#if defined (WITH_IPV6)
  if (pc->pp->protocol == SSH_PROTOCOL_IP6)
    fragoff = pc->fragment_offset;
  else
#endif /* WITH_IPV6 */
    {
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ucp = ssh_interceptor_packet_pullup_read(pc->pp, SSH_IPH4_HDRLEN);
      if (!ucp)
        {
          pc->pp = NULL;
          SSH_DEBUG(SSH_D_FAIL,
                    ("ssh_interceptor_packet_pullup_read failed"));
          return;
        }

      fragoff = 8 * (SSH_IPH4_FRAGOFF(ucp) & SSH_IPH4_FRAGOFF_OFFMASK);
    }

  next_off = fragoff + (SshUInt32) (pc->packet_len - pc->hdrlen);
  /* This should be guaranteed by sanity checks. */

  SSH_ASSERT(next_off <= 0xFFFF);
  fe->next_offset = (SshUInt16) next_off;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("sending fragment offset %u length %u",
             (unsigned int) fragoff,
             pc->packet_len - pc->hdrlen));
}

/* Inserts the given packet into the fragmagic queue.  This may also
   free the packet or some other packet if they overlap.  This updates
   bookkeeping in the fastpath object and in the fe object.  This maintains
   the fragments in ascending order, and makes sure we only have one
   first and one last fragment in the queue.  This returns TRUE on success,
   and FALSE if an error occurred (in which case pp has been freed). */

static void
ssh_fastpath_fragmagic_enqueue(SshFastpath fastpath,
                               SshFastpathFragEntry fe,
                               SshEnginePacketContext pc,
                               SshInterceptorPacket *frag_free_list)
{
  const unsigned char *ucp;
  SshEnginePacketData pd, pd2;
  SshInterceptorPacket pp, *ppp;
  SshInterceptorPacket newfrag;

  ssh_kernel_mutex_assert_is_locked(fastpath->frag_lock);

  newfrag = pc->pp;

#if defined (WITH_IPV6)
  if (newfrag->protocol == SSH_PROTOCOL_IP6)
    {
      pd = SSH_INTERCEPTOR_PACKET_DATA(newfrag, SshEnginePacketData);
      pd->frag_ofs = pc->fragment_offset;
      pd->frag_hdrlen = pc->fragh_offset;
      pd->frag_offset_prevnh = pc->fragh_offset_prevnh;
      /* The fragment's payload is from after the fragmentation header
         to the end of the packet. */
      pd->frag_len =
        pc->packet_len - (pc->fragh_offset + SSH_IP6_EXT_FRAGMENT_HDRLEN);
    }
  else
#endif /* WITH_IPV6 */
    {
      if (fastpath->frag_policy == SSH_IPSEC_FRAGS_NO_FRAGS)
        {
          pc->pp = NULL;
          ssh_fastpath_fragmagic_packet_free(newfrag, frag_free_list);
          return;
        }

#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR
      SSH_ASSERT(pc->media_hdr_len == 0);
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */

      ucp = ssh_interceptor_packet_pullup(newfrag, SSH_IPH4_HDRLEN);
      if (!ucp)
        {
          pc->pp = NULL;
          return;
        }

      SSH_ASSERT(pc->packet_len == SSH_IPH4_LEN(ucp));
      pd = SSH_INTERCEPTOR_PACKET_DATA(newfrag, SshEnginePacketData);
      pd->frag_ofs = 8 * (SSH_IPH4_FRAGOFF(ucp) & SSH_IPH4_FRAGOFF_OFFMASK);
      pd->frag_hdrlen = pc->hdrlen;
      pd->frag_len = pc->packet_len - pc->hdrlen;
    }
  pd->pending_tunnel_id = pc->tunnel_id;

    pd->frag_flags = 0;
  if (newfrag->flags & SSH_ENGINE_P_FIRSTFRAG)
    pd->frag_flags |= SSH_ENGINE_FRAG_QUEUED_FIRST;
  if (newfrag->flags & SSH_ENGINE_P_LASTFRAG)
    pd->frag_flags |= SSH_ENGINE_FRAG_QUEUED_LAST;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("enqueueing fragment offset %d len %d hdrlen %d flags 0x%08x",
             pd->frag_ofs, pd->frag_len, pd->frag_hdrlen, pd->frag_flags));

  pd->frag_overlap = 0;

  /* Detach fragment from any operating system context data */
  ssh_interceptor_packet_detach(newfrag);

  /* Remove all fragments which overlap with the current fragment */
  for (ppp = &fe->pp_chain; *ppp != NULL;)
    {
      pp = *ppp;
      pd2 = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);

      if ((pd2->frag_ofs + pd2->frag_len <= pd->frag_ofs)
          && ((pd2->frag_flags & SSH_ENGINE_FRAG_QUEUED_LAST) == 0))
        {
          ppp = &pp->next;
          continue;
        }

      if (pd2->frag_ofs >= pd->frag_len + pd->frag_ofs
          && ((pd->frag_flags & SSH_ENGINE_FRAG_QUEUED_LAST) == 0))
        break;

      fe->flags &= ~pd2->frag_flags;
      fastpath->frag_num_bytes -= pd2->frag_len;
      fe->total_bytes -= pd2->frag_len;

      *ppp = pp->next;
      ssh_fastpath_fragmagic_packet_free(pp, frag_free_list);
    }

  /* Find the place to insert the new packet. */
  pp = NULL;
  pd2 = NULL;
  for (ppp = &fe->pp_chain; *ppp; ppp = &pp->next)
    {
      pp = *ppp;
      pd2 = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);
      if (pd->frag_ofs <= pd2->frag_ofs)
        break;
    }

  /* Just insert the packet */
  newfrag->next = *ppp;
  *ppp = newfrag;
  fe->total_bytes += pd->frag_len;
  fastpath->frag_num_bytes += pd->frag_len;
  fe->num_frags++;
  fastpath->frag_num_fragments++;

  if (!fastpath->frag_timeout_scheduled)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("Fragmagic timer; scheduled"));
      fastpath->frag_timeout_scheduled = 1;
      ssh_kernel_timeout_register(5, 0,
                                  ssh_fastpath_fragmagic_timeout, fastpath);
    }

  fe->flags |= pd->frag_flags;
  ssh_fastpath_fragmagic_pullup(fastpath,fe,pc);
  return;
}

/* Merges the fragments in pp_chain into a full packet of size packet_size. */

SshInterceptorPacket ssh_fastpath_fragmagic_merge(SshFastpath fastpath,
                                         SshUInt32 packet_size,
                                         SshInterceptorPacket pp_chain,
                                         SshInterceptorPacket *frag_free_list)
{
  SshInterceptor interceptor = fastpath->engine->interceptor;
  SshInterceptorPacket pp, frag;
  SshEnginePacketData pd, new_pd;
  SshUInt16 hdrlen, cks, fragoff;
  unsigned char *ucpw;

  SSH_DEBUG(SSH_D_LOWOK, ("fragmagic_merge: packet_size=%d",
                          (int)packet_size));

  /* Read header length from the first fragment. */
  pd = SSH_INTERCEPTOR_PACKET_DATA(pp_chain, SshEnginePacketData);
  SSH_ASSERT(pd->frag_flags & SSH_ENGINE_FRAG_QUEUED_FIRST);
  hdrlen = pd->frag_hdrlen;

  /* Add the header from the first fragment into the packet size. */
  packet_size += hdrlen;
  if (packet_size > 65535)
    {
      SSH_DEBUG(SSH_D_NETGARB,
                ("Received fragment that continues beyond 64k"));
      pp = NULL;
      goto fail;
    }

  /* XXX Following should copy the VRF information in. */
  /* Allocate a packet just large enough to contain the combined data. */
  pp = ssh_interceptor_packet_alloc_and_copy_ext_data(interceptor,
                                                      pp_chain,
                                                      packet_size);
  if (!pp)
    {
      SSH_DEBUG(SSH_D_ERROR, ("failed to allocate packet"));
    fail:
      while (pp_chain)
        {
          pp = pp_chain;
          pp_chain = pp->next;
          ssh_fastpath_fragmagic_packet_free(pp, frag_free_list);
        }
      return NULL;
    }

  /* Set tunnel id from first fragment. */
  new_pd = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);
  new_pd->pending_tunnel_id = pd->pending_tunnel_id;

  /* Copy each fragment into the packet. */
  while (pp_chain)
    {
      frag = pp_chain;
      pp_chain = frag->next;
      pd = SSH_INTERCEPTOR_PACKET_DATA(frag, SshEnginePacketData);
      SSH_ASSERT(pd->frag_len + pd->frag_ofs + hdrlen <= packet_size);

      /* If this is the first fragment, copy packet header from there. */
      if (pd->frag_flags & SSH_ENGINE_FRAG_QUEUED_FIRST)
        {
          if (!ssh_interceptor_packet_copy(frag, 0, pd->frag_hdrlen, pp, 0))
            {
            copy_failed:
              pp = NULL;
              ssh_fastpath_fragmagic_packet_free(frag, frag_free_list);
              goto fail;
            }
#if defined (WITH_IPV6)
          if (pp->protocol == SSH_PROTOCOL_IP6)
            /* If we're merging an IPv6 packet, we are dropping the
               fragmentation extension headers.  This means we will
               also have to update the last next-hop field of the
               unfragmentable part. */
            if (!ssh_interceptor_packet_copy(
                        frag,
                        pd->frag_hdrlen + SSH_IP6_EXT_FRAGMENT_OFS_NH,
                        1,
                        pp,
                        pd->frag_offset_prevnh))
              goto copy_failed;
#endif /* WITH_IPV6 */
        }

      SSH_DEBUG(SSH_D_LOWOK, ("merge: frag hdrlen=%d, ofs=%d, len=%d",
                              (int)pd->frag_hdrlen, (int)pd->frag_ofs,
                              (int)pd->frag_len));

      /* Copy the payload from the fragment. */
#if defined (WITH_IPV6)
      if (pp->protocol == SSH_PROTOCOL_IP6)
        {
          if (!ssh_interceptor_packet_copy(
                                frag,
                                pd->frag_hdrlen + SSH_IP6_EXT_FRAGMENT_HDRLEN,
                                pd->frag_len,
                                pp,
                                hdrlen + pd->frag_ofs))
            goto copy_failed;
        }
      else
#endif /* WITH_IPV6 */
        {
          if (!ssh_interceptor_packet_copy(frag, pd->frag_hdrlen,
                                           pd->frag_len, pp,
                                           hdrlen + pd->frag_ofs))
            goto copy_failed;
        }

      ssh_fastpath_fragmagic_packet_free(frag, frag_free_list);
    }

  /* Adjust packet headers. */
#if defined (WITH_IPV6)
  if (pp->protocol == SSH_PROTOCOL_IP6)
    {
      /* Adjust packet length.  All other fields (flow, traffic class,
         etc.) were copied from the first fragment. */
      ucpw = ssh_interceptor_packet_pullup(pp, SSH_IPH6_HDRLEN);
      if (!ucpw)
        return NULL;
      SSH_IPH6_SET_LEN(ucpw, packet_size - SSH_IPH6_HDRLEN);
    }
  else
#endif /* WITH_IPV6 */
    {
      SshUInt32 header_len;

      /* In case of IPv4 we adjust the defragmented packet's length,
         set the fragment reserved-field, and recompute the IP header
         checksum. */
      ucpw = ssh_interceptor_packet_pullup(pp, SSH_IPH4_HDRLEN);
      if (!ucpw)
        return NULL;
      header_len = 4 * SSH_IPH4_HLEN(ucpw);
      /* This is guaranteed by packet sanity checks */
      SSH_ASSERT(header_len >= SSH_IPH4_HDRLEN);
      ucpw = ssh_interceptor_packet_pullup(pp, header_len);
      if (!ucpw)
        return NULL;
      SSH_IPH4_SET_LEN(ucpw, packet_size);
      fragoff = SSH_IPH4_FRAGOFF(ucpw);
      fragoff &= SSH_IPH4_FRAGOFF_RF;
      SSH_IPH4_SET_FRAGOFF(ucpw, fragoff);
      SSH_IPH4_SET_CHECKSUM(ucpw, 0);
      cks = ssh_ip_cksum(ucpw, header_len);
      SSH_IPH4_SET_CHECKSUM(ucpw, cks);
    }

  /* Clear certain other data maintained by the fastpath. */
  pp->flags &= ~(SSH_ENGINE_P_ISFRAG | SSH_ENGINE_P_FIRSTFRAG |
                 SSH_ENGINE_P_LASTFRAG);

  /* Knowing whether a packet was reassembled is important in
     deciding whether to heed the PMTU discovery "hints". */
  pp->flags |= SSH_ENGINE_P_WASFRAG;

  /* Merge complete.  The chain has been freed.  Return the full packet. */
  return pp;
}


static Boolean
ssh_fastpath_fragmagic_is_sane(SshFastpath fastpath,
                             SshFastpathFragEntry fe,
                             SshEnginePacketContext pc)
{
  SshUInt32 seen_last;

  /* Obey ipsec_params.h limit */
  if (fe->num_frags >= SSH_ENGINE_MAX_FRAGS_PER_PACKET)
    return FALSE;

  /* If we have a minimum packet size set from a first
     fragment packet context, then obey this restriction */
  if ((pc->frag_packet_size < fe->min_packet_size)
      && (pc->pp->flags & SSH_ENGINE_P_LASTFRAG))
    return FALSE;

  /* If we have a total packet size computed from
     a previous last fragment and now receive a first
     fragment with a larger required packet size
     then obey this latter restriction */
  seen_last = (fe->flags&(SSH_ENGINE_FRAG_QUEUED_LAST
                          |SSH_ENGINE_FRAG_SENT_LAST));
  if ((fe->packet_size < pc->min_packet_size) && seen_last != 0)
    return FALSE;

  return TRUE;
}

/* Should we dequeue fragments from the fragentry to
   the packetcontext pending_packets list */
static Boolean
ssh_fastpath_fragmagic_is_dequeue(SshFastpath fastpath,
                                SshFastpathFragEntry fe,
                                SshEnginePacketContext pc)
{
  /* If reassembly is required, then do not pass */
  if (fe->flags & SSH_ENGINE_FRAG_REASSEMBLE)
    return FALSE;

  /* If there is no policy for forwarding fragments then
     forward all fragments as soon as they can be associated
     to a policy (or flow) */
  if ((fastpath->frag_policy == SSH_IPSEC_FRAGS_NO_POLICY)
      && ((pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG)
          || (fe->flags & SSH_ENGINE_FRAG_SENT_FIRST))
      && ((fe->flags & SSH_ENGINE_FRAG_REASSEMBLE) == 0))
    return TRUE;

  /* If there is loose monitoring, then require that
     fragments traverse us in order and in a no-overlapping
     mode. */
  if ((fastpath->frag_policy == SSH_IPSEC_FRAGS_LOOSE_MONITOR)
      && ((pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG)
          || (fe->flags & SSH_ENGINE_FRAG_SENT_FIRST))
      && ((fe->flags & SSH_ENGINE_FRAG_REASSEMBLE) == 0))
    {
      SshUInt16 fragoff;

#if defined (WITH_IPV6)
      if (pc->pp->protocol == SSH_PROTOCOL_IP6)
        fragoff = pc->fragment_offset;
      else
#endif /* WITH_IPV6 */
        {
          const unsigned char *ucp;

          ucp = ssh_interceptor_packet_pullup_read(pc->pp, SSH_IPH4_HDRLEN);
          if (!ucp)
            {
              pc->pp = NULL;
              return FALSE;
            }
          fragoff = 8 * (SSH_IPH4_FRAGOFF(ucp) & SSH_IPH4_FRAGOFF_OFFMASK);
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("loose monitor: expected offset %u got offset %u",
                 fe->next_offset, fragoff));

      if (fragoff == fe->next_offset)
        return TRUE;
    }

  /* If strict policy is set or reassembly requested, then
     do not do this. */
  return FALSE;
}

/* Performs fragment magic on a fragment.  This may queue the packet,
   reassemble, or process the packet according to a previously defined
   flow.  If `reassemble' is TRUE (significant for first frags only),
   that indicates that the packet should be reassembled before
   processing.  If `reassemble' is FALSE, that means that the packet
   should not be reassembled, but that all fragments should be
   processed as if their flow id was pc->flow_id.  This returns
   SSH_ENGINE_RET_DEINITIALIZE if processing of the packet is now
   complete, and SSH_ENGINE_RET_RESTART_FLOW_LOOKUP if processing of
   the packet should continue as a fragment.  If this successfully
   completes reassembly, this returns SSH_ENGINE_RET_RESTART, in which
   case processing the packet should be restarted (i.e., it should
   again go through sanity checks).  This may also return
   SSH_ENGINE_RET_ERROR if an error causes pc->pp to be freed, and
   SSH_ENGINE_RET_DROP if it should be dropped. */
SshEngineActionRet
ssh_fastpath_fragmagic(SshFastpath fastpath, SshEnginePacketContext pc,
                       Boolean needs_reassembly)
{
  SshEngine engine = fastpath->engine;
  SshFastpathFragIdStruct frag_id[1];
  SshUInt32 hashvalue, num_frags, chain_len;
  SshFastpathFragEntry fe;
  SshInterceptorPacket pp_chain, *ppp, pp, frag_free_list = NULL;
  SshEnginePacketData pd;
  SshUInt16 packet_size;
  SshTime now;

  SSH_ASSERT(pc->pp != NULL);

  chain_len = 0;
  pc->audit.corruption = SSH_PACKET_CORRUPTION_NONE;

#ifdef TGX_PACKET_LIMIT
  /* On tilegx never reassemble. */
  needs_reassembly = FALSE;
#endif /* TGX_PACKET_LIMIT */

  SSH_DEBUG(SSH_D_MIDOK, ("fragmagic reassemble=%d%s%s",
                          (int)needs_reassembly,
                          (pc->pp->flags & SSH_ENGINE_P_FIRSTFRAG) ?
                          " FIRSTFRAG" : "",
                          (pc->pp->flags & SSH_ENGINE_P_LASTFRAG) ?
                          " LASTFRAG" : ""));
  SSH_ASSERT(pc->pp->flags & SSH_ENGINE_P_ISFRAG);

  /* Initialize number of previously queued fragments freed. */
  num_frags = 0;

  /* Compute fragpacketid for the packet. */
  if (!ssh_fastpath_fragmagic_compute_id(fastpath, pc, frag_id))
    return SSH_ENGINE_RET_ERROR;

  hashvalue = SSH_ENGINE_FRAG_ID_HASH(frag_id);
  hashvalue %= SSH_ENGINE_FRAGMENT_HASH_SIZE;

  ssh_interceptor_get_time(&now, NULL);
  ssh_kernel_mutex_lock(fastpath->frag_lock);

  /* If policy forbids fragments. discard them */
  if (fastpath->frag_policy == SSH_IPSEC_FRAGS_NO_FRAGS)
    {
      ssh_kernel_mutex_unlock(fastpath->frag_lock);
      return SSH_ENGINE_RET_DROP;
    }

  /* Find the fragment entry from the hash table. */
  for (fe = fastpath->frag_hash[hashvalue];
       fe != NULL
         && (fe->ifnum != pc->pp->ifnum_in
             || fe->tunnel_id != pc->tunnel_id
             || !SSH_ENGINE_FRAG_ID_EQUAL(frag_id, fe->frag_id));
       fe = fe->hash_next)
    ;
  /* If no such entry exists, create one now. */
  if (fe == NULL)
    {
      /* Allocate a fragment magic entry.  This will take one from the
         freelist. */
      SSH_DEBUG(SSH_D_LOWOK, ("Allocating new fragentry"));
      fe = ssh_fastpath_fragmagic_get_entry(fastpath, &frag_free_list);
      memcpy(fe->frag_id, frag_id, sizeof(fe->frag_id));
      fe->expiration = now + SSH_ENGINE_FRAGMENT_TIMEOUT;
      fe->flags = 0;
      fe->min_packet_size = 0;
      fe->next_offset = 0;
      fe->ifnum = pc->pp->ifnum_in;
      fe->tunnel_id = pc->tunnel_id;
      ssh_fastpath_fragmagic_add_hash(fastpath, fe);
      ssh_fastpath_fragmagic_add_all_lru(fastpath, fe);
      SSH_ASSERT(fe->pp_chain == NULL);
    }
  else if ((fe->expiration < engine->run_time)
           || (fastpath->frag_policy != SSH_IPSEC_FRAGS_STRICT_MONITOR
               && (fe->flags & SSH_ENGINE_FRAG_SENT_LAST)))
    {
      /* The fragment entry has expired.  Re-initialize it with new
         data. If fragment policy is "no policy" then allow fragment
         contexts to be reused immediately. */
      SSH_DEBUG(SSH_D_LOWOK, ("Reusing expired/unnecessary fragentry"));
      ssh_fastpath_fragmagic_remove_data_lru(fastpath, fe);
      ssh_fastpath_fragmagic_remove_all_lru(fastpath, fe);
      ssh_fastpath_fragmagic_clear_entry(fastpath, fe, &frag_free_list);
      fe->expiration = now + SSH_ENGINE_FRAGMENT_TIMEOUT;
      fe->flags = 0;
      fe->min_packet_size = 0;
      fe->next_offset = 0;
      fe->ifnum = pc->pp->ifnum_in;
      fe->tunnel_id = pc->tunnel_id;
      ssh_fastpath_fragmagic_add_all_lru(fastpath, fe);
      SSH_ASSERT(fe->pp_chain == NULL);
    }
  else
    {
      if ((fastpath->frag_policy == SSH_IPSEC_FRAGS_LOOSE_MONITOR)
          || (fastpath->frag_policy == SSH_IPSEC_FRAGS_STRICT_MONITOR))
        {
          if (fe->flags & SSH_ENGINE_FRAG_REJECT)
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("fragment id collision within reject time window"));
              pc->audit.corruption
                = SSH_PACKET_CORRUPTION_FRAGMENT_ID_COLLISION;
              goto reject;
            }

          if ((fe->flags & SSH_ENGINE_FRAG_SENT_LAST)
              && (fastpath->frag_policy == SSH_IPSEC_FRAGS_LOOSE_MONITOR))
            {
              SSH_DEBUG(SSH_D_NETGARB,
                        ("discarding late extra fragment"));
              pc->audit.corruption =
                SSH_PACKET_CORRUPTION_FRAGMENT_LATE_AND_EXTRA;
              goto reject;
            }
        }
    }

  /* If any fragments require reassembly, mark fragmentation context
     for reassembly */
  if (needs_reassembly)
    fe->flags |= SSH_ENGINE_FRAG_REASSEMBLE;

  /* If the packet is not sane then mark the whole fragmentation
     context to be rejected */
  if (ssh_fastpath_fragmagic_is_sane(fastpath, fe, pc) == FALSE)
    goto reject;

  /* Should we dequeue fragments into the pending packets context
     from the fragmentation context. (E.g. do we now have enough
     information to process them better and does the policy
     allow it). */
  if (fe->pp_chain != NULL && ssh_fastpath_fragmagic_is_dequeue(fastpath,
                                                                fe, pc))
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Dequeing fragments into pending packets"));

      /* Grab relevant state from the dequeued packet, because
         a return value of SSH_ENGINE_RET_RESTART_FLOW_LOOKUP
         signals that the packetcontext can be passed directly. */
      ssh_fastpath_fragmagic_sent(fastpath, fe, pc);
      /* Check if the above function freed pc->pp */
      if (pc->pp == NULL)
        goto error;

      /* Find the end of the pc->pending_packets list (normally it is
         empty, unless we have just added something there). */
      for (ppp = &pc->pending_packets; *ppp; ppp = &(*ppp)->next)
        ;
      /* Move the fragments from the fe chain to the end of the
         pending_packets chain. */
      ssh_fastpath_fragmagic_remove_data_lru(fastpath, fe);
      *ppp = fe->pp_chain;
      fe->pp_chain = NULL;
      /* Update values in each fragment. */
      for (pp = *ppp; pp; pp = pp->next)
        {
          pd = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEnginePacketData);
          memcpy(pd->pending_flow_id, fe->flow_id,
                 sizeof(pd->pending_flow_id));
          pd->pending_ret = SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
          SSH_DEBUG(SSH_D_MIDOK,
                    ("Dequeued pending fragment offset %u len %u "
                     "flags 0x%08x",
                     pd->frag_ofs, pd->frag_len, pd->frag_flags));
        }

      /* Update bookkeeping in the entry. */
      fastpath->frag_num_fragments -= fe->num_frags;
      fastpath->frag_num_bytes -= fe->total_bytes;
      fe->num_frags = 0;
      fe->total_bytes = 0;
      ssh_fastpath_fragmagic_add_data_lru(fastpath, fe);
      memcpy(pc->flow_id, fe->flow_id, sizeof(pc->flow_id));
      ssh_kernel_mutex_unlock(fastpath->frag_lock);

      ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
      return SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
    }
  /* Check if pc->pp got freed by ssh_fastpath_fragmagic_is_dequeue() */
  if (pc->pp == NULL)
    goto error;






  /* Should we pass the fragment in this packet context through
     without reassembly? */
  if (ssh_fastpath_fragmagic_is_dequeue(fastpath, fe, pc))
    {
      /* Grab relevant state from the dequeued packet */
      ssh_fastpath_fragmagic_sent(fastpath, fe, pc);
      if (pc->pp == NULL)
        goto error;

      SSH_DEBUG(SSH_D_LOWOK,
                ("Passing fragment to flow lookup"));
      SSH_ASSERT(fe->pp_chain == NULL);
      memcpy(pc->flow_id, fe->flow_id, sizeof(pc->flow_id));
      ssh_kernel_mutex_unlock(fastpath->frag_lock);

      ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
      return SSH_ENGINE_RET_RESTART_FLOW_LOOKUP;
    }
  /* Check if pc->pp got freed by ssh_fastpath_fragmagic_is_dequeue() */
  if (pc->pp == NULL)
    goto error;

  /* Remove this packet from the LRU lists so that we don't accidentally free
     it from under us. */
  ssh_fastpath_fragmagic_remove_all_lru(fastpath, fe);
  ssh_fastpath_fragmagic_remove_data_lru(fastpath, fe);

  SSH_ASSERT(fastpath->frag_num_fragments <= SSH_ENGINE_FRAGMENT_MAX_PACKETS);
  SSH_ASSERT(fastpath->frag_num_bytes <= SSH_ENGINE_FRAGMENT_MAX_BYTES);

  /* Drop excess old fragments */
  while (fastpath->frag_num_fragments + 1 >=
         SSH_ENGINE_FRAGMENT_MAX_PACKETS ||
         fastpath->frag_num_bytes + pc->packet_len >=
         SSH_ENGINE_FRAGMENT_MAX_BYTES)
    {
      SshUInt32 frags_dropped;
      SSH_DEBUG(SSH_D_LOWOK, ("Dropping oldest packet with data"));
      frags_dropped = ssh_fastpath_fragmagic_drop_data(fastpath,
                                                       &frag_free_list);
      if (frags_dropped == 0)
        {
          /* If ssh_fastpath_fragmagic_drop_data() could not drop any data,
             it means that value of either SSH_ENGINE_FRAGMENT_MAX_PACKETS
             or SSH_ENGINE_FRAGMENT_MAX_BYTES (configured in ipsec_params.h)
             is too small to contain even this fragmented packet. In that case
             we can only reject this (current packet). */

          ssh_fastpath_fragmagic_add_data_lru(fastpath, fe);
          ssh_fastpath_fragmagic_add_all_lru(fastpath, fe);
          goto reject;
        }
      num_frags += frags_dropped;
    }

  /* Add the fragment into the queue. This will also put it on the data
     LRU if it is not already there and set flags in fe for _is_dequeue() */
  ssh_fastpath_fragmagic_enqueue(fastpath, fe, pc, &frag_free_list);

  pc->pp = NULL;
  pp_chain = NULL;
  chain_len = 0;
  packet_size = 0;

  /* If we have a full packet, take the fragment chain from the entry,
     mark the entry so that it will reject everything, and update global
     counters. */
  if (ssh_fastpath_fragmagic_full_packet(fe))
    {
      packet_size = fe->packet_size;
      SSH_DEBUG(SSH_D_MIDOK, ("Got full packet, size=%d", (int)packet_size));
      pp_chain = fe->pp_chain;
      chain_len = fe->num_frags;
      fe->pp_chain = NULL;
      fe->flags |= SSH_ENGINE_FRAG_REJECT;
      fastpath->frag_num_bytes -= fe->total_bytes;
      fastpath->frag_num_fragments -= fe->num_frags;
      fe->total_bytes = 0;
      fe->num_frags = 0;
      fe->packet_size = 0;
    }

  /* Re-insert the packet at the head of the LRU lists. */
  ssh_fastpath_fragmagic_add_data_lru(fastpath, fe);
  ssh_fastpath_fragmagic_add_all_lru(fastpath, fe);

  /* Unlock the fragment data structures. */
  ssh_kernel_mutex_unlock(fastpath->frag_lock);

  if (pp_chain)
    {
      /* Merge the fragments into a full chain.  This frees pp_chain. */
      SSH_DEBUG(SSH_D_LOWOK, ("Merging fragments into full packet"));
      pc->pp =
        ssh_fastpath_fragmagic_merge(fastpath, packet_size,
                                     pp_chain, &frag_free_list);
      if (pc->pp == NULL)
        {
#ifdef SSH_IPSEC_STATISTICS
          SshFastpathGlobalStats stats;

          ssh_kernel_critical_section_start(fastpath->stats_critical_section);
          stats = &fastpath->stats[ssh_kernel_get_cpu()];
          stats->counters[SSH_ENGINE_STAT_FRAGDROP] += num_frags;
          stats->counters[SSH_ENGINE_STAT_RESOURCEDROP] += chain_len;
          ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */
          SSH_DEBUG(SSH_D_MIDOK, ("Merge failed"));

          ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
          return SSH_ENGINE_RET_ERROR;
        }
    }

  ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
  if (pc->pp)
    return SSH_ENGINE_RET_RESTART;
  else
    return SSH_ENGINE_RET_DEINITIALIZE;

 reject:
  /* Reject this packet, free queued packets, and cause this entry to
     reject any further packets (until it times out).  The packet should
     be on all LRU lists when we come here. */
  SSH_DEBUG(SSH_D_MIDOK, ("Fragmentation rejecting packet"));
  ssh_kernel_mutex_assert_is_locked(fastpath->frag_lock);
  /* Cause this entry to reject all future packets. */
  fe->flags |= SSH_ENGINE_FRAG_REJECT;
  ssh_fastpath_fragmagic_remove_all_lru(fastpath, fe);
  ssh_fastpath_fragmagic_remove_data_lru(fastpath, fe);
  num_frags += fe->num_frags;
  ssh_fastpath_fragmagic_clear_entry(fastpath, fe, &frag_free_list);
  ssh_fastpath_fragmagic_add_all_lru(fastpath, fe);
  ssh_fastpath_fragmagic_add_data_lru(fastpath, fe);
  ssh_kernel_mutex_unlock(fastpath->frag_lock);
  SSH_ENGINE_MARK_STAT(pc, SSH_ENGINE_STAT_FRAGDROP);
#ifdef SSH_IPSEC_STATISTICS
  /* Count the previously queued packets that we are dropping. */
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].counters[SSH_ENGINE_STAT_FRAGDROP] +=
    num_frags;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

  ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
  return SSH_ENGINE_RET_DROP;

error:
  ssh_kernel_mutex_assert_is_locked(fastpath->frag_lock);
  ssh_kernel_mutex_unlock(fastpath->frag_lock);
#ifdef SSH_IPSEC_STATISTICS
  ssh_kernel_critical_section_start(fastpath->stats_critical_section);
  fastpath->stats[ssh_kernel_get_cpu()].counters[SSH_ENGINE_STAT_FRAGDROP]
    += num_frags;
  fastpath->stats[ssh_kernel_get_cpu()].counters[SSH_ENGINE_STAT_RESOURCEDROP]
    += chain_len;
  ssh_kernel_critical_section_end(fastpath->stats_critical_section);
#endif /* SSH_IPSEC_STATISTICS */

  ssh_fastpath_fragmagic_free_packet_list(frag_free_list);
  return SSH_ENGINE_RET_ERROR;
}

void fastpath_fragmagic_uninit(SshFastpath fastpath)
{
  SshFastpathFragEntry frag;

  /* Cancel any registered fragmagic timeouts. */
  ssh_kernel_timeout_cancel(ssh_fastpath_fragmagic_timeout,
                            (void *)fastpath);

  ssh_kernel_mutex_lock(fastpath->frag_lock);
  fastpath->frag_timeout_scheduled = 0;

  /* Free fragments. */
  for (frag = fastpath->frag_data_lru_head; frag; frag = frag->data_lru_next)
    {
      SshInterceptorPacket pp, pp_next;

      for (pp = frag->pp_chain; pp; pp = pp_next)
        {
          pp_next = pp->next;

          /* An exeption for using ssh_fastpath_fragmagic_packet_free.
             We are uninitialising here and we don't receive any more
             packets. */
          ssh_interceptor_packet_free(pp);
        }
      frag->pp_chain = NULL;
    }

  ssh_kernel_mutex_unlock(fastpath->frag_lock);
}
