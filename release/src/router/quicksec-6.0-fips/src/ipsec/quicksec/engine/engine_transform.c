/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of IPSEC and other transforms on packets.  This file
   contains IPsec transform control functionality.
*/

#include "sshincludes.h"
#include "engine_internal.h"

#define SSH_DEBUG_MODULE "SshEngineTransform"

#ifdef SSH_IPSEC_TCPENCAP
#include "engine_tcp_encaps.h"
#endif /* SSH_IPSEC_TCPENCAP */


/* Remove the transform from the engine->peer_handle_hash. The flow
   control lock must be held when this is called. */
static void
engine_transform_remove_peer_handle_hash(SshEngine engine,
                                         SshUInt32 transform_index,
                                         SshEngineTransformControl c_trd)
{
  SshEngineTransformControl c_trd2;
  SshUInt32 hashvalue;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (c_trd->peer_handle == SSH_IPSEC_INVALID_INDEX)
    return;

  if (c_trd->peer_handle_next != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_handle_next);
      SSH_ASSERT(c_trd2 != NULL);
      c_trd2->peer_handle_prev = c_trd->peer_handle_prev;
    }
  if (c_trd->peer_handle_prev != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_handle_prev);
      SSH_ASSERT(c_trd2 != NULL);
      c_trd2->peer_handle_next = c_trd->peer_handle_next;
    }
  else
    {
      hashvalue = ((SshUInt32)c_trd->peer_handle / 8) %
        SSH_ENGINE_PEER_HANDLE_HASH_SIZE;

      SSH_ASSERT(engine->peer_handle_hash[hashvalue] == transform_index);
      engine->peer_handle_hash[hashvalue] = c_trd->peer_handle_next;
    }

  c_trd->peer_handle_prev = SSH_IPSEC_INVALID_INDEX;
  c_trd->peer_handle_next = SSH_IPSEC_INVALID_INDEX;
}


/* Insert the transform to the engine->peer_handle_hash. The flow control
   lock must be held when this is called. */
static void
engine_transform_insert_peer_handle_hash(SshEngine engine,
                                         SshUInt32 transform_index,
                                         SshEngineTransformControl c_trd)
{
  SshEngineTransformControl c_trd2;
  SshUInt32 hashvalue;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  if (c_trd->peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      c_trd->peer_handle_prev = SSH_IPSEC_INVALID_INDEX;
      c_trd->peer_handle_next = SSH_IPSEC_INVALID_INDEX;
      return;
    }

  hashvalue =
    ((SshUInt32)c_trd->peer_handle / 8) % SSH_ENGINE_PEER_HANDLE_HASH_SIZE;

  c_trd->peer_handle_prev = SSH_IPSEC_INVALID_INDEX;
  c_trd->peer_handle_next = engine->peer_handle_hash[hashvalue];
  if (c_trd->peer_handle_next != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_handle_next);
      SSH_ASSERT(c_trd2 != NULL);
      SSH_ASSERT(c_trd2->peer_handle_prev == SSH_IPSEC_INVALID_INDEX);
      c_trd2->peer_handle_prev = transform_index;
    }
  engine->peer_handle_hash[hashvalue] = transform_index;
}


/* Puts the transform `unwrapped_index' to the transform object
   freelist of the engine `engine'.  The transform index must be given
   as un unwrapped transform index.  The transform object must be
   freed and all references to and from it must have been removed.
   Engine->flow_table_lock must be held when this is called. */

void ssh_engine_transform_freelist_put(SshEngine engine,
                                       SshUInt32 unwrapped_index)
{
  SshEngineTransformControl c_trd;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, unwrapped_index);
  SSH_ASSERT(c_trd != NULL);
  SSH_ASSERT(c_trd->rules == SSH_IPSEC_INVALID_INDEX);

  if (engine->transform_table_freelist_tail == SSH_IPSEC_INVALID_INDEX)
    {
      engine->transform_table_freelist = unwrapped_index;
      engine->transform_table_freelist_tail = unwrapped_index;
    }
  else
    {
      SshUInt32 tail_index;
      SshEngineTransformControl trd_tail;

      tail_index = engine->transform_table_freelist_tail;
      trd_tail = SSH_ENGINE_GET_TR_UNWRAPPED(engine, tail_index);

      /* Sanity check the freelist. */
      SSH_ASSERT(trd_tail != NULL);
      SSH_ASSERT(trd_tail->rules == SSH_IPSEC_INVALID_INDEX);

      trd_tail->rules = unwrapped_index;
      engine->transform_table_freelist_tail = unwrapped_index;
    }

#ifdef SSH_IPSEC_STATISTICS
  engine->stats.active_transforms--;
#endif /* SSH_IPSEC_STATISTICS */

#ifdef DEBUG_LIGHT
  c_trd->peer_prev = 0xdeadbeef;
  c_trd->peer_next = 0xdeadbeef;
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  c_trd->natt_keepalive_next = 0xdeadbeef;
  c_trd->natt_keepalive_prev = 0xdeadbeef;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* DEBUG_LIGHT */
}

/* Decrements the reference count of the transform.  If the reference
   count becomes zero, frees the transform and releases its SPIs.
   Engine->flow_table_lock must be held when this is called. The
   transform reference count should be incremented by using the
   SSH_ENGINE_INCREMENT_TRD_REFCNT() macro */

void ssh_engine_decrement_transform_refcnt(SshEngine engine,
                                           SshUInt32 transform_index)
{
  SshEngineTransformControl c_trd, c_trd2;
  SshUInt32 hashvalue, unwrapped_index;

  SSH_DEBUG(SSH_D_HIGHOK,
            ("decrement transform 0x%lx", (unsigned long) transform_index));

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Decrement the transform reference count. */
  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  SSH_ASSERT(c_trd != NULL);
  SSH_ASSERT(c_trd->refcnt != 0);
  c_trd->refcnt--;

  /* If the reference count reached zero, free it now. */
  if (c_trd->refcnt == 0)
    {
      SshEngineTransformData d_trd;

      /* Last reference just went away.  Free the transform record now. */
      SSH_DEBUG(SSH_D_HIGHOK, ("freeing transform 0x%lx",
                               (unsigned long) transform_index));
      SSH_ASSERT(c_trd->rules == SSH_IPSEC_INVALID_INDEX);
      SSH_ASSERT(c_trd->norule_flows == SSH_IPSEC_INVALID_INDEX);

      d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);

#ifdef SSH_IPSEC_TCPENCAP
      /* Remove SPIs from TCP encapsulating connection entry. */
      if (d_trd->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
        d_trd->tcp_encaps_conn_id =
          ssh_engine_tcp_encaps_remove_spi_mapping(engine,
                                          d_trd->tcp_encaps_conn_id,
                                          d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                          d_trd->spis[SSH_PME_SPI_AH_OUT]);
#endif /* SSH_IPSEC_TCPENCAP */

      /* Remove the trd from engine->peer_hash. */
      if (c_trd->peer_next != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_next);
          SSH_ASSERT(c_trd2 != NULL);
          c_trd2->peer_prev = c_trd->peer_prev;
        }
      if (c_trd->peer_prev != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_prev);
          SSH_ASSERT(c_trd2 != NULL);
          c_trd2->peer_next = c_trd->peer_next;
        }
      else
        {
          hashvalue = SSH_IP_HASH(&d_trd->gw_addr) % SSH_ENGINE_PEER_HASH_SIZE;
          SSH_ASSERT(engine->peer_hash[hashvalue] == transform_index);
          engine->peer_hash[hashvalue] = c_trd->peer_next;
        }

      if (c_trd->peer_handle != SSH_IPSEC_INVALID_INDEX)
        {
          /* Remove the trd from engine->peer_handle_hash. */
          engine_transform_remove_peer_handle_hash(engine, transform_index,
                                                   c_trd);
        }
      else
        {
          SSH_ASSERT(c_trd->peer_handle_next == SSH_IPSEC_INVALID_INDEX);
          SSH_ASSERT(c_trd->peer_handle_prev == SSH_IPSEC_INVALID_INDEX);
          SSH_DEBUG(SSH_D_LOWOK, ("This trd has no associated IKE SA, "
                                  "it must be an manually keyed SA."));
        }

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      /* Remove the trd from the engine's NAT-T keepalive list if it
         is on that list. */
      if (c_trd->control_flags & SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED)
        {
          if (c_trd->natt_keepalive_next != SSH_IPSEC_INVALID_INDEX)
            {
              c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->natt_keepalive_next);
              SSH_ASSERT(c_trd2 != NULL);
              c_trd2->natt_keepalive_prev = c_trd->natt_keepalive_prev;
            }
          if (c_trd->natt_keepalive_prev != SSH_IPSEC_INVALID_INDEX)
            {
              c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->natt_keepalive_prev);
              SSH_ASSERT(c_trd2 != NULL);
              c_trd2->natt_keepalive_next = c_trd->natt_keepalive_next;
            }
          else
            {
              engine->natt_keepalive = c_trd->natt_keepalive_next;
            }
        }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

      /* The transform record should no longer have rules referencing it */
      SSH_ASSERT(c_trd->rules == SSH_IPSEC_INVALID_INDEX);

      /* Increment transform data's generation. */
      c_trd->generation++;

      /* The transform indexes on the freelist and on the destroy
         notify list are unwrapped ones without the generation
         information. */
      unwrapped_index = SSH_ENGINE_UNWRAP_TRD_INDEX(transform_index);

      /* Is the Engine-PM channel open? */
      if (engine->ipm_open)
        {
          /* Yes.  Put it on the destroy notify list. */
          if (engine->transform_destroy_notify_list_tail
              == SSH_IPSEC_INVALID_INDEX)
            {
              engine->transform_destroy_notify_list = unwrapped_index;
              engine->transform_destroy_notify_list_tail = unwrapped_index;
            }
          else
            {
              SshUInt32 tail_index;
              SshEngineTransformControl trd_tail;

              tail_index = engine->transform_destroy_notify_list_tail;
              trd_tail = SSH_ENGINE_GET_TR_UNWRAPPED(engine, tail_index);

              /* Sanity check the freelist. */
              SSH_ASSERT(trd_tail != NULL);
              SSH_ASSERT(trd_tail->rules == SSH_IPSEC_INVALID_INDEX);

              trd_tail->rules = unwrapped_index;
              engine->transform_destroy_notify_list_tail = unwrapped_index;
            }
          FASTPATH_COMMIT_TRD(engine->fastpath, transform_index, d_trd);
#ifdef SSH_IPSEC_SMALL
          /* Schedule a engine age timeout to run immediately. */
          ssh_engine_age_timeout_schedule_trd(engine, engine->run_time);
#endif /* SSH_IPSEC_SMALL */
        }
      else
        {
          /* Put the trd on the freelist. */
          ssh_engine_transform_freelist_put(engine, unwrapped_index);
          d_trd->transform = 0;
          FASTPATH_UNINIT_TRD(engine->fastpath, transform_index, d_trd);
        }
    }
}

/* Deletes a transform record from the engine.  Note that this should
   only be called if creating a rule using the transform index fails;
   normally the record is freed automatically when its reference count
   decrements to zero. */

void ssh_engine_pme_delete_transform(SshEngine engine,
                                     SshUInt32 transform_index)
{
  SshEngineTransformControl c_trd;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL)
    {
      /* Transform generation mismatch. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;
    }

  /* Since this should only be called when it is not yet part of a rule,
     it should not have any references (except from the incoming flow). */
  SSH_ASSERT(c_trd->refcnt == 0);

  /* Temporarily increment the reference count so that it will reach zero
     when we decrement it. */
  SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);
  ssh_engine_decrement_transform_refcnt(engine, transform_index);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}

/* Creates a transform record in the engine.  The `params' argument
   selects algorithms and key material for AH, ESP, and IPCOMP
   transforms.  Engine run-time fields need not be initialized.

   The transform record can be used in rules added by
   ssh_engine_pme_add_rule.  The same transform data can be used in both
   directions (for all rules/flows created by a bundle).  Normally the
   system will automatically free transform records when they are no
   longer referenced from ipsec flows or rules; however, if creating
   the flow and rule fails, then the ssh_engine_pme_delete_transform
   function should be used to free it.

   The `trd' structure should be initialized to describe the
   transform.  This will copy it to internal data structures.  `life_seconds'
   and `life_kilobytes' specify the maximum lifetime of the SA in seconds
   and in transferred kilobytes.  Valid values must always be specified for
   them; the engine has no defaults for these.  The kilobyte-based lifetime
   is ignored if SSH_IPSEC_STATISTICS is not defined.

   This calls `callback' with `context' and transform index if successful,
   and with SSH_IPSEC_INVALID_INDEX on error.  This call consumes the
   inbound SPIs in trd->spis (regardless of whether this succeeds). */

void ssh_engine_pme_create_transform(SshEngine engine,
                                     SshEngineTransform params,
                                     SshUInt32 life_seconds,
                                     SshUInt32 life_kilobytes,
                                     SshPmeIndexCB callback, void *context)
{
  SshUInt32 unwrapped_tr_index, tr_index, hashvalue;
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd, c_trd2;
  SshUInt8 generation;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  ssh_interceptor_get_time(&engine->run_time, &engine->run_time_usec);

  SSH_ASSERT(engine->ipm_open == TRUE);

  /* Allocate a transform table node.  Note that the transform indexes
     on the freelist are in the unwrapped form.  They do not contain
     the generation part. */
  tr_index = engine->transform_table_freelist;
  if (tr_index == SSH_IPSEC_INVALID_INDEX)
    {
#ifdef SSH_IPSEC_STATISTICS
      engine->stats.out_of_transforms++;
#endif /* SSH_IPSEC_STATISTICS */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_FAIL, ("allocating transform failed"));

      (*callback)(engine->pm, SSH_IPSEC_INVALID_INDEX, context);
      return;
    }

  /* Initialize the transform table record from the params. */
  SSH_ASSERT(tr_index < engine->transform_table_size);
  c_trd = SSH_ENGINE_GET_TR_UNWRAPPED(engine, tr_index);

  d_trd = FASTPATH_INIT_TRD(engine->fastpath, tr_index);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("creating transform index=%d, generation=%d, transform=0x%08lx",
             (int)tr_index, (int) c_trd->generation,
             (long)params->data.transform));

  engine->transform_table_freelist = c_trd->rules;
  if (engine->transform_table_freelist == SSH_IPSEC_INVALID_INDEX)
    engine->transform_table_freelist_tail = SSH_IPSEC_INVALID_INDEX;

  /* Copy parameters preserving some internal fields. */
  generation = c_trd->generation;

  *d_trd = params->data;
  *c_trd = params->control;
  c_trd->generation = generation;

  /* Create a wrapped transform index. */
  unwrapped_tr_index = tr_index;
  tr_index = SSH_ENGINE_WRAP_TRD_INDEX(tr_index, generation);

  SSH_ASSERT(d_trd->transform != 0);
  c_trd->refcnt = 0;
  c_trd->rules = SSH_IPSEC_INVALID_INDEX;
  c_trd->norule_flows = SSH_IPSEC_INVALID_INDEX;
  c_trd->pmtu_age_time = 0;

  d_trd->old_spis[0] = 0;
  d_trd->old_spis[1] = 0;
  d_trd->old_spis[2] = 0;
  d_trd->old_spis[3] = 0;
  d_trd->old_spis[4] = 0;
  d_trd->old_spis[5] = 0;
  d_trd->tr_index = tr_index;

  d_trd->last_in_packet_time = engine->run_time;
  d_trd->last_out_packet_time = engine->run_time;
  d_trd->pmtu_received = 0;

  /* Clear internal status flags. */
  c_trd->control_flags &= ~SSH_ENGINE_TR_C_INTERNAL_FLAG_MASK;
  c_trd->worry_metric_notified = 0;

#ifdef SSH_IPSEC_TCPENCAP
  if (memcmp(c_trd->tcp_encaps_conn_spi, "\x00\x00\x00\x00\x00\x00\x00\x00",
             SSH_ENGINE_IKE_COOKIE_LENGTH) != 0)
    {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
      SSH_ASSERT((d_trd->transform & SSH_PM_IPSEC_NATT) == 0);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
      d_trd->tcp_encaps_conn_id =
        ssh_engine_tcp_encaps_create_spi_mapping(engine,
                                             &d_trd->own_addr, &d_trd->gw_addr,
                                             c_trd->tcp_encaps_conn_spi,
                                             d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                             d_trd->spis[SSH_PME_SPI_AH_OUT]);
    }
  else
    d_trd->tcp_encaps_conn_id = SSH_IPSEC_INVALID_INDEX;

  /* Update the packet enlargement here when we know if IPsec over TCP
     is being used. */
  if (d_trd->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
    d_trd->packet_enlargement += (SSH_TCPH_HDRLEN +
                                  SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);
#endif /* SSH_IPSEC_TCPENCAP */

#ifdef SSH_IPSEC_HWACCEL_CONFIGURED
#ifdef SSH_IPSEC_HWACCEL_16_BYTE_PADDING
  /* EIP-94 (potentially other EIP-XX's as well, but) handles padding as
     max as 16 bytes instead of our 4. We need to be prepared for this. */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Increased enlargement for transform by 12."));
  d_trd->packet_enlargement += 12;
#endif /* SSH_IPSEC_HWACCEL_16_BYTE_PADDING */
#endif /* SSH_IPSEC_HWACCEL_CONFIGURED */

  /* Insert the transform in the peer hash. */
  hashvalue = SSH_IP_HASH(&d_trd->gw_addr) % SSH_ENGINE_PEER_HASH_SIZE;
  c_trd->peer_prev = SSH_IPSEC_INVALID_INDEX;
  c_trd->peer_next = engine->peer_hash[hashvalue];
  if (c_trd->peer_next != SSH_IPSEC_INVALID_INDEX)
    {
      c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_next);
      SSH_ASSERT(c_trd2 != NULL);
      SSH_ASSERT(c_trd2->peer_prev == SSH_IPSEC_INVALID_INDEX);
      c_trd2->peer_prev = tr_index;
    }
  engine->peer_hash[hashvalue] = tr_index;

  /* Insert the transform in the IKE SA hash. */
  engine_transform_insert_peer_handle_hash(engine, tr_index, c_trd);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /* Insert the transform in the NAT-T keepalive list if keepalives
     are required for the transform. */
  if (c_trd->control_flags & SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED)
    {
      c_trd->natt_keepalive_prev = SSH_IPSEC_INVALID_INDEX;
      c_trd->natt_keepalive_next = engine->natt_keepalive;
      if (c_trd->natt_keepalive_next != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->natt_keepalive_next);
          SSH_ASSERT(c_trd2 != NULL);
          SSH_ASSERT(c_trd2->natt_keepalive_prev == SSH_IPSEC_INVALID_INDEX);
          c_trd2->natt_keepalive_prev = tr_index;
        }
      engine->natt_keepalive = tr_index;
    }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#ifdef SSH_IPSEC_STATISTICS
  memset(&c_trd->stats, 0, sizeof(c_trd->stats));
  memset(&d_trd->stats, 0, sizeof(d_trd->stats));
  /* Set the kilobyte-based lifetime limit.  First adjust it for grace
     periods, and enforce a sane minimum value. */
  if (life_kilobytes)
    {
      if (life_kilobytes < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB)
        life_kilobytes = SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB;
      else
        life_kilobytes -=
          (SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB + life_kilobytes / 20);
      c_trd->life_bytes = (SshUInt64)life_kilobytes * 1024;
    }
  else
    /* No kilobyte-based lifetime specified. */
    c_trd->life_bytes = ~(SshUInt64)0;
#endif /* SSH_IPSEC_STATISTICS */

  /* Store the transform life time in seconds, used when the incoming
     ipsec flow is created during ssh_engine_pme_add_rule() after this
     transform has been created succesfully */
  c_trd->life_seconds = life_seconds;

#ifdef DEBUG_LIGHT
  if ((d_trd->out_packets_high != SSH_IPSEC_INVALID_INDEX
       && d_trd->out_packets_high > 0)
      || d_trd->out_packets_low > 0)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Initial outbound sequence number 0x%08lx 0x%08lx",
               (unsigned long) d_trd->out_packets_high,
               (unsigned long) d_trd->out_packets_low));

  if (d_trd->replay_offset_high > 0
      || d_trd->replay_offset_low > 0)
    SSH_DEBUG(SSH_D_NICETOKNOW,
              ("Initial replay window low 0x%08lx high 0x%08lx",
               (unsigned long) d_trd->replay_offset_low,
               (unsigned long) d_trd->replay_offset_high));
#endif /* DEBUG_LIGHT */

#ifdef SSH_IPSEC_STATISTICS
  engine->stats.active_transforms++;
  engine->stats.total_transforms++;
#endif /* SSH_IPSEC_STATISTICS */

  FASTPATH_COMMIT_TRD(engine->fastpath, unwrapped_tr_index, d_trd);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Return the tranform index to the policy manager. */
  (*callback)(engine->pm, tr_index, context);
}

/* Activate new outbound SPI and key material. */
static void
engine_rekey_activate_outbound_transform(SshEngine engine,
                                        SshEngineTransformData d_trd,
                                        const SshUInt32 new_out_spis[3],
                                        const unsigned char
                                        keymat_out[SSH_IPSEC_MAX_KEYMAT_LEN/2],
                                        SshUInt32 flags)
{
  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Save old outbound SPIs unless we replacing the new SPI values
     and keying material. */
  if ((flags & SSH_PME_REKEY_OUTBOUND_REPLACE) == 0)
    {
      d_trd->old_spis[SSH_PME_SPI_ESP_OUT] = d_trd->spis[SSH_PME_SPI_ESP_OUT];
      d_trd->old_spis[SSH_PME_SPI_AH_OUT] = d_trd->spis[SSH_PME_SPI_AH_OUT];
      d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT] =
        d_trd->spis[SSH_PME_SPI_IPCOMP_OUT];
    }

  /* Copy the new outbound SPIs and key material into the transform. */
  d_trd->spis[SSH_PME_SPI_ESP_OUT] = new_out_spis[0];
  d_trd->spis[SSH_PME_SPI_AH_OUT] = new_out_spis[1];
  d_trd->spis[SSH_PME_SPI_IPCOMP_OUT] = new_out_spis[2];
  memcpy(d_trd->keymat + (SSH_IPSEC_MAX_KEYMAT_LEN/2), keymat_out,
         SSH_IPSEC_MAX_KEYMAT_LEN / 2);

  /* Reset the outbound sequence number. */
  d_trd->out_packets_low = 0;
  d_trd->out_packets_high = 0;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Activated new outbound SPIs 0x%08lx 0x%08lx 0x%08lx "
             "old outbound SPIs 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) d_trd->spis[SSH_PME_SPI_ESP_OUT],
             (unsigned long) d_trd->spis[SSH_PME_SPI_AH_OUT],
             (unsigned long) d_trd->spis[SSH_PME_SPI_IPCOMP_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_ESP_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_AH_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT]));
}

/* Remove rules that were not re-installed during rekey and activate rules
   that were added during rekey. */
static void
engine_rekey_activate_outbound_rules(SshEngine engine,
                                     SshEngineTransformControl c_trd,
                                     SshPmTransform transform)
{
  SshUInt32 rule_index;
  SshEnginePolicyRule rule;
  SshEngineFlowControl c_flow;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  /* Delete any rules that have not been re-installed by the policy manager */
  for (rule_index = c_trd->rules;
       rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = rule->trd_next)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);

      SSH_ASSERT(rule != NULL);

      /* If the rule is marked as still pending then delete the given rule
         and all of its subordinate rules, and their flows. */
      if ((rule->flags & SSH_ENGINE_RULE_DELETED) == 0
          && (rule->flags & SSH_PM_ENGINE_RULE_SA_OUTBOUND))
        {
          if ((rule->flags & SSH_ENGINE_RULE_REKEY_PENDING)
              && (transform & SSH_PM_IPSEC_L2TP) == 0)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Deleting rule %d", (int) rule_index));
              ssh_engine_delete_rule(engine, rule_index);
            }
          else if (rule->flags & SSH_ENGINE_RULE_INSTALL_PENDING)
            {
              SSH_DEBUG(SSH_D_LOWOK, ("Activating rule %d", (int) rule_index));
              rule->flags &= ~SSH_ENGINE_RULE_INSTALL_PENDING;
            }
        }
    }

  /* Get all flows that use this transform and send the rekeyed flow event
     to the fastpath. Check that a primary incoming IPsec flow exists and
     if not then mark one incoming IPsec flow primary. */
  for (rule_index = c_trd->rules;
       rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = rule->trd_next)
    {
      SshUInt32 flow_index;

      rule = SSH_ENGINE_GET_RULE(engine, rule_index);
      SSH_ASSERT(rule != NULL);

      flow_index = rule->flows;
      while (flow_index != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Rekeying rule flow index=%d",
                                  (int) flow_index));
          c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
          FASTPATH_REKEY_FLOW(engine->fastpath, flow_index);

          flow_index = c_flow->rule_next;
        }

      flow_index = c_trd->norule_flows;
      while (flow_index != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Rekeying No rule flow index=%d",
                                  (int) flow_index));
          c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
          FASTPATH_REKEY_FLOW(engine->fastpath, flow_index);

          flow_index = c_flow->control_next;
        }

      if ((c_trd->control_flags & SSH_ENGINE_TR_C_PRIMARY_IPSEC_FLOW_CREATED)
          == 0
          && rule->incoming_ipsec_flow != SSH_IPSEC_INVALID_INDEX)
        {
          SSH_DEBUG(SSH_D_LOWOK,
                    ("Setting primary flag in incoming IPsec flow index %d",
                     (int) rule->incoming_ipsec_flow));
          c_flow = SSH_ENGINE_GET_FLOW(engine, rule->incoming_ipsec_flow);
          c_trd->control_flags |= SSH_ENGINE_TR_C_PRIMARY_IPSEC_FLOW_CREATED;
          c_flow->control_flags |= SSH_ENGINE_FLOW_C_PRIMARY;
        }
    }
}

/** Installs new inbound parameters for the transform record during a rekey.
    This also updates the flow table hash so that the flow will accept the new
    SPIs.  The old incoming SPIs will remain valid for a while (approximately
    half a minute), after which a SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED
    event is sent using ssh_pmp_transform_event.

    'transform_index' identifies the transform to be rekeyed, `new_in_spis' is
    new inbound SPI values (SSH_PME_SPI_*_IN can be used as indexes to the
    array), and `keymat_in' is new inbound key material for the transform
    (i.e., the first half of full key material). `flags' is a bitmask of
    SSH_PME_REKEY_INBOUND_* flags.

    The transform will ignore delete_by_spi() calls for outbound spi's until
    ssh_pme_rekey_transform_outbound() has been called. This sets the
    SSH_ENGINE_TR_C_REKEY_PENDING flag. */
void
ssh_engine_pme_rekey_transform_inbound(SshEngine engine,
                                       SshUInt32 transform_index,
                                       const SshUInt32 new_in_spis[3],
                                       const unsigned char
                                       keymat_in[SSH_IPSEC_MAX_KEYMAT_LEN/2],
                                       SshUInt32 life_seconds,
                                       SshUInt32 life_kilobytes,
                                       SshUInt32 flags,
                                       SshPmeTransformCB callback,
                                       void *context)
{
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt32 rule_index;
  SshEnginePolicyRule rule;
  Boolean spis_destroyed = FALSE;
  SshEngineTransformStruct tr;
  SshUInt32 new_out_spis[3];
  int i;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);
  ssh_interceptor_get_time(&engine->run_time, &engine->run_time_usec);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL || (c_trd->control_flags & SSH_ENGINE_TR_C_REKEY_PENDING))
    {
      /* Transform generation mismatch. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, context);
      return;
    }

  d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);

  /* There is a possible race condition if the policy manager is too
     slow to perform the rekey, and timeout deletes the trd from under
     it and the generation number wraps around.  This should cover
     that case, though still leaves a small possibility that we rekey
     the wrong transform.  Nevertheless, the probability is small and
     should never happen under normal operation, and at least this way
     it will not crash. */
  if (d_trd->transform == 0 || (d_trd->transform & SSH_PM_IPSEC_MANUAL))
    {
      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, NULL, context);
      return;
    }

  /* If we are replacing the current SPI values and keying material, then
     mark that the current SPIs are destroyed during this call and they
     must be passed to policymanager in the completion callback. */
  if (flags & SSH_PME_REKEY_INBOUND_REPLACE)
    spis_destroyed = TRUE;

  /* If the old SPI has not been invalidated yet, mark that the old
     inbound SPIs are destroyed during this call and they must be passed
     to the policymanager in the completion callback. */
  else if (d_trd->old_spis[SSH_PME_SPI_ESP_IN] != 0
           || d_trd->old_spis[SSH_PME_SPI_AH_IN] != 0
           || d_trd->old_spis[SSH_PME_SPI_IPCOMP_IN] != 0)
    spis_destroyed = TRUE;

  /* Activate new outbound SPI and new outbound key material of the
     previous rekey. */
  if (c_trd->control_flags & SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE)
    {
      new_out_spis[0] = d_trd->old_spis[SSH_PME_SPI_ESP_OUT];
      new_out_spis[1] = d_trd->old_spis[SSH_PME_SPI_AH_OUT];
      new_out_spis[2] = d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT];

      engine_rekey_activate_outbound_transform(engine,
                                               d_trd, new_out_spis,
                                               c_trd->rekeyed_keymat, 0);
      /* Now the SPI values are pairwise valid. */
    }
  c_trd->control_flags &= ~SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE;

  /* Take a copy of the transform for the completion callback before
     updating new parameters to the transform. */
  tr.data = *d_trd;
  tr.control = *c_trd;

  /* Move current SPI values to old_spis, unless we are replacing the current
     SPI values. */
  if (flags & SSH_PME_REKEY_INBOUND_REPLACE)
    {
      /* Mark that the current outbound SPI has already been freed
         from the policymanager. */
      c_trd->control_flags |= SSH_ENGINE_TR_C_OUTBOUND_SPI_INVALID;
    }
  else
    {
      /* Clear old outbound SPI values (if there were any). */
      d_trd->old_spis[SSH_PME_SPI_ESP_OUT] = 0;
      d_trd->old_spis[SSH_PME_SPI_AH_OUT] = 0;
      d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT] = 0;

      /* Save old SPI values, keying material and replay window. */
      d_trd->old_spis[SSH_PME_SPI_ESP_IN] = d_trd->spis[SSH_PME_SPI_ESP_IN];
      d_trd->old_spis[SSH_PME_SPI_AH_IN] = d_trd->spis[SSH_PME_SPI_AH_IN];
      d_trd->old_spis[SSH_PME_SPI_IPCOMP_IN] =
        d_trd->spis[SSH_PME_SPI_IPCOMP_IN];

      d_trd->old_replay_offset_high = d_trd->replay_offset_high;
      d_trd->old_replay_offset_low = d_trd->replay_offset_low;
      memcpy(d_trd->old_replay_mask, d_trd->replay_mask,
             sizeof(d_trd->old_replay_mask));

      memcpy(d_trd->old_keymat, d_trd->keymat, sizeof(d_trd->old_keymat));
    }

  /* Copy new inbound SPI values and keying material into the transform
     and clear current replay window. */
  d_trd->spis[SSH_PME_SPI_ESP_IN] = new_in_spis[0];
  d_trd->spis[SSH_PME_SPI_AH_IN] = new_in_spis[1];
  d_trd->spis[SSH_PME_SPI_IPCOMP_IN] = new_in_spis[2];

  d_trd->replay_offset_high = 0;
  d_trd->replay_offset_low = 0;
  memset(d_trd->replay_mask, 0, sizeof(d_trd->replay_mask));

  memcpy(d_trd->keymat, keymat_in, SSH_IPSEC_MAX_KEYMAT_LEN / 2);

  /* Now the SPI values may be pairwise invalid, that is the spis[]
     array contains new SPI values for inbound and old SPI values
     for outbound. */

#ifdef SSH_IPSEC_STATISTICS
  /* Set the kilobyte-based lifetime limit.  First adjust it for grace
     periods, and encorce a sane minimum value.  We also add the
     current value of the byte counter to it. */
  if (life_kilobytes)
    {
      if (life_kilobytes < 2 * SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB)
        life_kilobytes = SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB;
      else
        life_kilobytes -=
          (SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB + life_kilobytes / 20);
      /* Note: our semantics for kilobyte-based expirations is that it
         is from the sum of the number of bytes transferred in each
         direction.  This way it is the number of bytes encrypted
         using the same [master] keys. */
      c_trd->life_bytes = (SshUInt64)life_kilobytes * 1024 +
        d_trd->stats.in_octets + d_trd->stats.out_octets;
    }
  else
    {
      /* No kilobyte-based lifetime specified. */
      c_trd->life_bytes = ~(SshUInt64)0;
    }
#endif /* SSH_IPSEC_STATISTICS */

  SSH_DEBUG(SSH_D_LOWOK,
            ("Rekeying inbound direction of transform 0x%lx %s",
             (unsigned long) transform_index,
             ((flags & SSH_PME_REKEY_INBOUND_REPLACE) ? "[replace]" : "")));
  SSH_DEBUG(SSH_D_LOWOK,
            ("new SPIs in 0x%08lx 0x%08lx 0x%08lx out 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) d_trd->spis[SSH_PME_SPI_ESP_IN],
             (unsigned long) d_trd->spis[SSH_PME_SPI_AH_IN],
             (unsigned long) d_trd->spis[SSH_PME_SPI_IPCOMP_IN],
             (unsigned long) d_trd->spis[SSH_PME_SPI_ESP_OUT],
             (unsigned long) d_trd->spis[SSH_PME_SPI_AH_OUT],
             (unsigned long) d_trd->spis[SSH_PME_SPI_IPCOMP_OUT]));
  SSH_DEBUG(SSH_D_LOWOK,
            ("old SPIs in 0x%08lx 0x%08lx 0x%08lx out 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_ESP_IN],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_AH_IN],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_IPCOMP_IN],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_ESP_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_AH_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT]));

  /* Commit trd to fastpath */
  FASTPATH_COMMIT_TRD(engine->fastpath, transform_index, d_trd);

  /* Set the rekeyed timestamp. This is used for scheduling the
     REKEY_INBOUND_INVALIDATED event. */
  if (c_trd->rekeyed_time == 0)
    c_trd->rekeyed_time = engine->run_time;

  /* Adjust lifetime for the soft event grace periods.  This also enforces
     certain sane minimum values for them. */
  life_seconds = SSH_ENGINE_IPSEC_HARD_EXPIRE_TIME(life_seconds);
  c_flow = NULL;

  /* Reset the idle worry metric counter, as this rekey operation is enough
     proof that the peer is alive. Set c_trd->last_in_packet_time to time of
     rekey so that the next idle event is sent after c_flow->metric seconds
     have passed since rekey. */
  c_trd->worry_metric_notified = 0;
  c_trd->last_in_packet_time = engine->run_time;

  /* Do the rekey for inbound transforms foreach trd->rules list with
     a valid incoming_ipsec_flow */
  for (rule_index = c_trd->rules; rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = rule->trd_next)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);

      SSH_ASSERT(rule != NULL);

      /* Only mark rules that were installed from the policy manager's SA
         handler as pending reinstallation. There may exist other rules
         using the transform such as L2tp control rules but they do not get
         reinstalled on rekey. */
      if (rule->flags & SSH_PM_ENGINE_RULE_SA_OUTBOUND)
        rule->flags |= SSH_ENGINE_RULE_REKEY_PENDING;

      /* Update the flow ids. */
      if (rule->incoming_ipsec_flow != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow = SSH_ENGINE_GET_FLOW(engine, rule->incoming_ipsec_flow);
          d_flow = FASTPATH_GET_FLOW(engine->fastpath,
                                     rule->incoming_ipsec_flow);

          SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID);

          if ((flags & SSH_PME_REKEY_INBOUND_REPLACE) == 0)
            {
              /* Store previous flow id as forward flow id. */
              memcpy(d_flow->forward_flow_id, d_flow->reverse_flow_id,
                     SSH_ENGINE_FLOW_ID_SIZE);

              /* Mark that the flow currently contains an old IPSEC flow
                 id in flow->forward_flow_id. */
              c_flow->control_flags |= SSH_ENGINE_FLOW_C_REKEYOLD;

              /* Invalidate old SPI values in near future. */
              c_flow->idle_timeout = SSH_ENGINE_IPSEC_REKEY_INVALIDATE_TIMEOUT;
            }

          /* Compute new SPI flow id into reverse flow id. */
          ssh_engine_flow_compute_flow_id_from_flow(engine,
                                                    rule->incoming_ipsec_flow,
                                                    d_flow,
                                                    FALSE,
                                                    d_flow->reverse_flow_id);

          /* Clear the flag indicating that we have already sent rekey
             request for this flow (we shouldn't be sending another
             one too soon anyway because we just reset the limits). */
          c_flow->control_flags &= ~SSH_ENGINE_FLOW_C_IPSECSOFTSENT;
          c_flow->rekey_attempts = 0;

          /* Adjust expiration time. */
          c_flow->hard_expire_time =
            (life_seconds == 0) ? 0 : (engine->run_time + life_seconds);

          FASTPATH_COMMIT_FLOW(engine->fastpath, rule->incoming_ipsec_flow,
                               d_flow);

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Rekeying inbound IPsec flow %d",
                                       (int) rule->incoming_ipsec_flow));

          FASTPATH_REKEY_FLOW(engine->fastpath, rule->incoming_ipsec_flow);
        }
    }

#ifdef SSH_IPSEC_STATISTICS
  /* Update statistics. */
  c_trd->stats.num_rekeys++;
  engine->stats.total_rekeys++;
#endif /* SSH_IPSEC_STATISTICS */

  /* Mark this transform as waiting for
     ssh_engine_pme_rekey_transform_outbound() */
  c_trd->control_flags |= SSH_ENGINE_TR_C_REKEY_PENDING;

#ifdef SSH_IPSEC_SMALL
  /* Schedule a engine age timeout to the next soft expiry of the transform. */
  if (c_flow)
    ssh_engine_age_timeout_schedule_trd(engine,
                                        SSH_ENGINE_IPSEC_SOFT_EVENT_TIME
                                        (engine, c_flow, c_trd, 0));
#endif /* SSH_IPSEC_SMALL */

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (spis_destroyed == TRUE)
    {
      /* If the current SPI and keying material were replaced, then
         clear the still valid old inbound SPIs from the event. */
      if (flags & SSH_PME_REKEY_INBOUND_REPLACE)
        {
          for (i = 0; i < 6; i++)
            tr.data.old_spis[i] = 0;
        }

      /* Otherwise clear the current SPI to indicate that the old SPI
         values were destroyed. */
      else
        {
          for (i = 0; i < 6; i++)
            tr.data.spis[i] = 0;
        }
    }
  else
    {
      /* Indicate that no SPI values were destroyed from the engine. */
      for (i = 0; i < 6; i++)
        {
          tr.data.old_spis[i] = 0;
          tr.data.spis[i] = 0;
        }
    }

  /* Do not export the keying material from engine. */
  memset(tr.data.keymat, 0, sizeof(tr.data.keymat));
  memset(tr.data.old_keymat, 0, sizeof(tr.data.old_keymat));
  memset(tr.control.rekeyed_keymat, 0, sizeof(tr.control.rekeyed_keymat));

  (*callback)(engine->pm, &tr, context);
}

/** Installs new outbound parameters for the transform record during a rekey.

    If `flags' contains SSH_PME_REKEY_OUTBOUND_ACTIVATE_IMMEDIATELY then this
    causes all outbound traffic using the transform record (any number of
    flows) to immediately start using the new outbound SPI and new key
    material. Otherwise the new outbound SPI and key material is stored for
    later activation. `new_out_spis' contains the new outbound SPI values
    (note: indexed using the SSH_PME_SPI_*_IN values - the policy manager may
    depend on this being the SPIs from the second half of the full spis[6]
    array. `keymat_out' is the new outbound key material for the transform
    (the second half of the full keymat[] array).

    It is mandatory to call ssh_pme_rekey_transform_inbound before calling
    this. */
void
ssh_engine_pme_rekey_transform_outbound(SshEngine engine,
                                        SshUInt32 transform_index,
                                        const SshUInt32 new_out_spis[3],
                                        const unsigned char
                                        keymat_out[SSH_IPSEC_MAX_KEYMAT_LEN/2],
#ifdef SSH_IPSEC_TCPENCAP
                                        unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                        SshUInt32 flags,
                                        SshPmeStatusCB callback, void *context)
{
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;
  SshPmTransform transform;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL
      || (c_trd->control_flags & SSH_ENGINE_TR_C_REKEY_PENDING) == 0)
    {
      /* Transform generation mismatch. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);

  /* There is a possible race condition if the policy manager is too
     slow to perform the rekey, and timeout deletes the trd from under
     it and the generation number wraps around.  This should cover
     that case, though still leaves a small possibility that we rekey
     the wrong transform.  Nevertheless, the probability is small and
     should never happen under normal operation, and at least this way
     it will not crash. */
  if (d_trd->transform == 0 || (d_trd->transform & SSH_PM_IPSEC_MANUAL))
    {
      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, FALSE, context);
      return;
    }

  /* Mark this transform to have completed it's rekey */
  c_trd->control_flags &= ~SSH_ENGINE_TR_C_REKEY_PENDING;

  /* Active new outbound SPI value and new outbound key material immediately.*/
  if (flags & SSH_PME_REKEY_OUTBOUND_ACTIVATE_IMMEDIATELY)
    {
      c_trd->control_flags &= ~SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE;
      /* Mark that outbound SPI value is now valid. */
      if (flags & SSH_PME_REKEY_OUTBOUND_REPLACE)
        c_trd->control_flags &= ~SSH_ENGINE_TR_C_OUTBOUND_SPI_INVALID;
      engine_rekey_activate_outbound_transform(engine, d_trd, new_out_spis,
                                               keymat_out, flags);
    }

  /* Copy new outbound SPI and key material for later activation. */
  else
    {
      /* Mark that new SPI values and new outbound key material has not yet
         been activated. */
      c_trd->control_flags |= SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE;

      /* Store new SPI values into old_spis to ensure that they will get
         properly freed in all error cases. */
      SSH_ASSERT(d_trd->old_spis[SSH_PME_SPI_ESP_OUT] == 0
                 && d_trd->old_spis[SSH_PME_SPI_AH_OUT] == 0
                 && d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT] == 0);
      d_trd->old_spis[SSH_PME_SPI_ESP_OUT] = new_out_spis[0];
      d_trd->old_spis[SSH_PME_SPI_AH_OUT] = new_out_spis[1];
      d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT] = new_out_spis[2];

      /* Store new key material for later activation. */
      memcpy(c_trd->rekeyed_keymat, keymat_out, SSH_IPSEC_MAX_KEYMAT_LEN / 2);
    }

#ifdef SSH_IPSEC_TCPENCAP
  {
    SshUInt32 old_tcp_encaps_conn_id = d_trd->tcp_encaps_conn_id;

    /* Set new SPIs to connection entry. */
    if (tcp_encaps_conn_spi != NULL
        && memcmp(tcp_encaps_conn_spi, "\x00\x00\x00\x00\x00\x00\x00\x00",
                  SSH_ENGINE_IKE_COOKIE_LENGTH) != 0)
      {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
        SSH_ASSERT((d_trd->transform & SSH_PM_IPSEC_NATT) == 0);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
        d_trd->tcp_encaps_conn_id =
          ssh_engine_tcp_encaps_create_spi_mapping(engine,
                                             &d_trd->own_addr, &d_trd->gw_addr,
                                             tcp_encaps_conn_spi,
                                             d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                             d_trd->spis[SSH_PME_SPI_AH_OUT]);
        memcpy(c_trd->tcp_encaps_conn_spi, tcp_encaps_conn_spi,
               SSH_ENGINE_IKE_COOKIE_LENGTH);
      }
    else
      {
        d_trd->tcp_encaps_conn_id = SSH_IPSEC_INVALID_INDEX;
        memset(c_trd->tcp_encaps_conn_spi, 0, SSH_ENGINE_IKE_COOKIE_LENGTH);
      }

    /* Remove old SPIs from the connection entry. */
    if (old_tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
      ssh_engine_tcp_encaps_remove_spi_mapping(engine,
                                      old_tcp_encaps_conn_id,
                                      d_trd->old_spis[SSH_PME_SPI_ESP_OUT],
                                      d_trd->old_spis[SSH_PME_SPI_AH_OUT]);

    /* Update the packet enlargement here when we know if IPsec over TCP
       is being used. */
    if (d_trd->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX
        && old_tcp_encaps_conn_id == SSH_IPSEC_INVALID_INDEX)
      d_trd->packet_enlargement += (SSH_TCPH_HDRLEN +
                                    SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);

    else if (d_trd->tcp_encaps_conn_id == SSH_IPSEC_INVALID_INDEX
             && old_tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
      d_trd->packet_enlargement -= (SSH_TCPH_HDRLEN +
                                    SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);
  }
#endif /* SSH_IPSEC_TCPENCAP */
  transform = d_trd->transform;

  SSH_DEBUG(SSH_D_LOWOK,
            ("Rekeying outbound direction of transform 0x%lx [%s%s]",
             (unsigned long) transform_index,
             ((flags & SSH_PME_REKEY_OUTBOUND_ACTIVATE_IMMEDIATELY) ?
              "activate_immediately " : ""),
             ((flags & SSH_PME_REKEY_OUTBOUND_REPLACE) ? "replace" : "")));
  SSH_DEBUG(SSH_D_LOWOK,
            ("new SPIs in 0x%08lx 0x%08lx 0x%08lx out 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) d_trd->spis[SSH_PME_SPI_ESP_IN],
             (unsigned long) d_trd->spis[SSH_PME_SPI_AH_IN],
             (unsigned long) d_trd->spis[SSH_PME_SPI_IPCOMP_IN],
             (unsigned long) d_trd->spis[SSH_PME_SPI_ESP_OUT],
             (unsigned long) d_trd->spis[SSH_PME_SPI_AH_OUT],
             (unsigned long) d_trd->spis[SSH_PME_SPI_IPCOMP_OUT]));
  SSH_DEBUG(SSH_D_LOWOK,
            ("old SPIs in 0x%08lx 0x%08lx 0x%08lx out 0x%08lx 0x%08lx 0x%08lx",
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_ESP_IN],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_AH_IN],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_IPCOMP_IN],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_ESP_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_AH_OUT],
             (unsigned long) d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT]));

  FASTPATH_COMMIT_TRD(engine->fastpath, transform_index, d_trd);

  /* Delete rules that were not reinstalled and activate new rules.
     Also send the rekeyed event to all flows using this transform. */
  if (flags & SSH_PME_REKEY_OUTBOUND_ACTIVATE_IMMEDIATELY)
    engine_rekey_activate_outbound_rules(engine, c_trd, transform);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  (*callback)(engine->pm, TRUE, context);
}

/* Activate new outbound SPI and key material, delete any rules that were
   not re-installed during rekey and activate rules that were added during
   rekey. */
void ssh_engine_rekey_activate_outbound(SshEngine engine,
                                        SshUInt32 transform_index)
{
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshUInt32 new_out_spis[3];
  SshPmTransform transform;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Transform 0x%lx has disappeared",
                                 (unsigned long) transform_index));
      return;
    }

  if (c_trd->control_flags & SSH_ENGINE_TR_C_REKEY_PENDING)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Transform 0x%lx is being rekeyed",
                                 (unsigned long) transform_index));
      return;
    }

  if ((c_trd->control_flags & SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE)
      == 0)
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Transform 0x%lx is has no inactive outbound SPI params",
                 (unsigned long) transform_index));
      return;
    }

  /* Activate new outbound SPI value and key material. */
  SSH_DEBUG(SSH_D_LOWOK,
            ("Activating new SPI and key material for transform 0x%lx",
             (unsigned long) transform_index));

  d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);

  new_out_spis[0] = d_trd->old_spis[SSH_PME_SPI_ESP_OUT];
  new_out_spis[1] = d_trd->old_spis[SSH_PME_SPI_AH_OUT];
  new_out_spis[2] = d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT];

  engine_rekey_activate_outbound_transform(engine, d_trd, new_out_spis,
                                           c_trd->rekeyed_keymat, 0);

  transform = d_trd->transform;

  FASTPATH_COMMIT_TRD(engine->fastpath, transform_index, d_trd);

  /* Delete rules that were not reinstalled and activate new rules.
     Also send the rekeyed event to all flows using this transform. */
  engine_rekey_activate_outbound_rules(engine, c_trd, transform);

  c_trd->control_flags &= ~SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE;
}

/* Clears old SPI value from transform and resets old flow id from all
   related incoming IPsec flows. */
void
ssh_engine_pme_transform_invalidate_old_inbound(SshEngine engine,
                                                SshUInt32 transform_index,
                                                SshUInt32 inbound_spi,
                                                SshPmeTransformCB callback,
                                                void *context)
{
  SshEngineTransformStruct tr;
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshEngineFlowControl c_flow;
  SshEngineFlowData d_flow;
  SshUInt32 rule_index;
  SshEnginePolicyRule rule;
  Boolean activate = FALSE;
  SshUInt32 new_out_spis[3];

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL)
    {
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_LOWOK, ("Transform 0x%lx has disappeared",
                              (unsigned long) transform_index));
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, NULL, context);
      return;
    }

  d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);

  /* Check that the SPI values match. */
  if (d_trd->old_spis[SSH_PME_SPI_ESP_IN] != inbound_spi
      && d_trd->old_spis[SSH_PME_SPI_AH_IN] != inbound_spi)
    {
      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      SSH_DEBUG(SSH_D_LOWOK,
                ("Old inbound SPI %lx has already been invalidated from "
                 "transform 0x%lx",
                 (unsigned long) inbound_spi,
                 (unsigned long) transform_index));

      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, NULL, context);
      return;
    }

  SSH_DEBUG(SSH_D_LOWOK, ("Clearing old SPI values from transform 0x%lx",
                          (unsigned long) transform_index));

  /* Activate new outbound SPI and new outbound key material. */
  c_trd->rekeyed_time = 0;
  if (c_trd->control_flags & SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE)
    {
      activate = TRUE;
      c_trd->control_flags &= ~SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE;

      new_out_spis[0] = d_trd->old_spis[SSH_PME_SPI_ESP_OUT];
      new_out_spis[1] = d_trd->old_spis[SSH_PME_SPI_AH_OUT];
      new_out_spis[2] = d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT];

      engine_rekey_activate_outbound_transform(engine,
                                               d_trd, new_out_spis,
                                               c_trd->rekeyed_keymat, 0);
    }

  /* Copy transform with old SPI values for callback. */
  tr.control = *c_trd;
  tr.data = *d_trd;

  /* Clear old inbound SPI values from transform. */
  d_trd->old_spis[SSH_PME_SPI_ESP_IN] = 0;
  d_trd->old_spis[SSH_PME_SPI_AH_IN] = 0;
  d_trd->old_spis[SSH_PME_SPI_IPCOMP_IN] = 0;

  /* Clear old outbound SPI values from transform. */
  d_trd->old_spis[SSH_PME_SPI_ESP_OUT] = 0;
  d_trd->old_spis[SSH_PME_SPI_AH_OUT] = 0;
  d_trd->old_spis[SSH_PME_SPI_IPCOMP_OUT] = 0;

  FASTPATH_COMMIT_TRD(engine->fastpath, transform_index, d_trd);

  for (rule_index = c_trd->rules;
       rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = rule->trd_next)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);
      SSH_ASSERT(rule != NULL);

      /* Reset old flow IDs from incoming IPsec flows. */
      if (rule->incoming_ipsec_flow != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow = SSH_ENGINE_GET_FLOW(engine, rule->incoming_ipsec_flow);

          SSH_ASSERT(c_flow->control_flags & SSH_ENGINE_FLOW_C_VALID);

          /* Clear old flow ID. */
          if (c_flow->control_flags & SSH_ENGINE_FLOW_C_REKEYOLD)
            {
              SSH_DEBUG(SSH_D_LOWOK,
                        ("Clearing old flow ID from incoming IPsec flow %d",
                         (int) rule->incoming_ipsec_flow));

              c_flow->idle_timeout = 0xffffffff;
              c_flow->control_flags &= ~SSH_ENGINE_FLOW_C_REKEYOLD;

              d_flow = FASTPATH_GET_FLOW(engine->fastpath,
                                         rule->incoming_ipsec_flow);
              memset(d_flow->forward_flow_id, 0, SSH_ENGINE_FLOW_ID_SIZE);
              FASTPATH_COMMIT_FLOW(engine->fastpath, rule->incoming_ipsec_flow,
                                   d_flow);
            }
        }
    }

  /* Delete rules that were not reinstalled and activate new rules.
     Also send the rekeyed event to all flows using this transform. */
  if (activate)
    engine_rekey_activate_outbound_rules(engine, c_trd, tr.data.transform);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Clear the current SPI values from the transform passed to the callback
     to indicate that only the old SPI values were destroyed from engine. */
  tr.data.spis[SSH_PME_SPI_ESP_IN] = 0;
  tr.data.spis[SSH_PME_SPI_AH_IN] = 0;
  tr.data.spis[SSH_PME_SPI_IPCOMP_IN] = 0;
  tr.data.spis[SSH_PME_SPI_ESP_OUT] = 0;
  tr.data.spis[SSH_PME_SPI_AH_OUT] = 0;
  tr.data.spis[SSH_PME_SPI_IPCOMP_OUT] = 0;

  /* Do not export the keying material from engine. */
  memset(tr.data.keymat, 0, sizeof(tr.data.keymat));
  memset(tr.data.old_keymat, 0, sizeof(tr.data.old_keymat));
  memset(tr.control.rekeyed_keymat, 0, sizeof(tr.control.rekeyed_keymat));

  if (callback != NULL_FNPTR)
    (*callback)(engine->pm, &tr, context);
}

#ifdef SSHDIST_L2TP
/* Updates L2TP parameters for the transform `transform_index'.  The
   argument `flags' is a bitmap of the `SSH_ENGINE_L2TP_*' flags.  The
   arguments `tunnel_id' and `session_id' specify the L2TP tunnel and
   session IDs respectively. */

void ssh_engine_pme_update_transform_l2tp_info(SshEngine engine,
                                               SshUInt32 transform_index,
                                               SshUInt8 flags,
                                               SshUInt16 local_tunnel_id,
                                               SshUInt16 local_session_id,
                                               SshUInt16 remote_tunnel_id,
                                               SshUInt16 remote_session_id)
{
  SshEngineTransformData d_trd;
  SshEngineTransformControl c_trd;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, transform_index);
  if (c_trd == NULL)
    {
      /* Transform generation mismatch. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;
    }

  d_trd = FASTPATH_GET_TRD(engine->fastpath, transform_index);

  /* There is a possible race condition if the policy manager is too
     slow to perform the rekey, and timeout deletes the trd from under
     it and the generation wraps around.  This should cover that case,
     though still leaves a small possibility that we rekey the wrong
     transform.  Nevertheless, the probability is small and should
     never happen under normal operation, and at least this way it
     will not crash. */
  if ((d_trd->transform & SSH_PM_IPSEC_L2TP) == 0
      || (d_trd->l2tp_local_tunnel_id
          && d_trd->l2tp_local_tunnel_id != local_tunnel_id)
      || (d_trd->l2tp_local_session_id
          && d_trd->l2tp_local_session_id != local_session_id)
      || (d_trd->l2tp_remote_tunnel_id
          && d_trd->l2tp_remote_tunnel_id != remote_tunnel_id)
      || (d_trd->l2tp_remote_session_id
          && d_trd->l2tp_remote_session_id != remote_session_id))
    {
      FASTPATH_RELEASE_TRD(engine->fastpath, transform_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      return;
    }

  /* Insert new L2TP information into the transform. */
  d_trd->l2tp_flags = flags;
  d_trd->l2tp_local_tunnel_id = local_tunnel_id;
  d_trd->l2tp_local_session_id = local_session_id;
  d_trd->l2tp_remote_tunnel_id = remote_tunnel_id;
  d_trd->l2tp_remote_session_id = remote_session_id;

  FASTPATH_COMMIT_TRD(engine->fastpath, transform_index, d_trd);
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
}
#endif /* SSHDIST_L2TP */

/* Deletes all rules and flows referencing the trd.  This means the
   trd will be deleted (either immediately or when its reference count
   reaches zero).  This must be called with engine->flow_control_table_lock
   held.  Engine->flow_table_lock must be held when this is called. */

void ssh_engine_clear_and_delete_trd(SshEngine engine, SshUInt32 trd_index)
{
  SshUInt32 rule_index, next_rule_index;
  SshEngineTransformControl c_trd;
  SshEnginePolicyRule rule;

  ssh_kernel_mutex_assert_is_locked(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
  SSH_ASSERT(c_trd != NULL);

  /* Temporarily increment the reference count of the trd so that it does
     not disappear from under us. */
  SSH_ENGINE_INCREMENT_TRD_REFCNT(c_trd);

  c_trd->control_flags |= SSH_ENGINE_TR_C_DELETE_PENDING;

  /* Remove all rules that reference the trd.  Note that some of them
     could be deleted in a delayed fashion, e.g. if rule execution is
     currently in progress on a rule. */
  for (rule_index = c_trd->rules; rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = next_rule_index)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);
      next_rule_index = rule->trd_next;

      /* Delete the given rule and all of its subordinate rules, and their
         flows. */
      if ((rule->flags & SSH_ENGINE_RULE_DELETED) == 0)
        ssh_engine_delete_rule(engine, rule_index);
    }

  /* Remove all flows that might reference the transform without being
     created by one of the rules that created it. */
  while (c_trd->norule_flows != SSH_IPSEC_INVALID_INDEX)
    {
#ifdef SSH_ENGINE_DANGLE_FLOWS
      if (ssh_engine_flow_dangle(engine, c_trd->norule_flows) == FALSE)
#endif /* SSH_ENGINE_DANGLE_FLOWS */
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Failed to dangle flow. Freeing flow %d.",
                     (int) c_trd->norule_flows));
          ssh_engine_free_flow(engine, c_trd->norule_flows);
        }
    }

  /* Decrement the reference count of the trd, deleting it.  At this
     point there should only be the reference we just took above, plus
     references from rules that were not yet actually deleted above
     because they had references from rule execution.  The code
     calling this function may also hold a reference.  The transform
     should get deleted as soon as all rules referencing it have been
     deleted. */
  ssh_engine_decrement_transform_refcnt(engine, trd_index);
}

/* Called by the policy manager when a delete notification is received
   for a SPI value. */
void ssh_engine_pme_delete_by_spi(SshEngine engine, SshUInt32 trd_ind,
                                  SshPmeTransformCB callback, void *context)
{
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshEngineTransformStruct tr;

  SSH_INTERCEPTOR_STACK_MARK();

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  c_trd = SSH_ENGINE_GET_TRD(engine, trd_ind);

  if (c_trd == NULL)
    {
      /* Transform generation mismatch. */
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, NULL, context);
      return;
    }

  d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, trd_ind);

  /* Ingore manually keyed SAs. */
  if (d_trd->transform & SSH_PM_IPSEC_MANUAL)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("ignoring manually keyed trd"));

      FASTPATH_RELEASE_TRD(engine->fastpath, trd_ind);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, NULL, context);
      return;
    }

  if (c_trd->control_flags & SSH_ENGINE_TR_C_REKEY_PENDING)
    {
      SSH_DEBUG(SSH_D_MIDOK, ("ignoring trd as rekey pending"));
      FASTPATH_RELEASE_TRD(engine->fastpath, trd_ind);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, NULL, context);
      return;
    }

  /* Copy trd for callback. */
  if (callback != NULL_FNPTR)
    {
      tr.control = *c_trd;
      tr.data = *d_trd;
    }

  FASTPATH_RELEASE_TRD(engine->fastpath, trd_ind);

  /* Found a matching transform.  Delete all rules referencing it, which
     will also delete all flows referencing it. */
  ssh_engine_clear_and_delete_trd(engine, trd_ind);

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Notify user about the success of the operation. */
  if (callback != NULL_FNPTR)
    {
      ssh_engine_transform_event_normalize_spis(&tr);
      (*callback)(engine->pm, &tr, context);
    }
  return;
}


static void
engine_update_trd_flows(SshEngine engine, SshEngineTransformControl c_trd,
                        SshIpAddr local_ip, SshIpAddr remote_ip,
                        SshUInt8 ipproto, SshUInt16 local_port,
                        SshUInt16 remote_port)
{
  unsigned char engine_flow_zeroid[SSH_ENGINE_FLOW_ID_SIZE];
  SshUInt32 rule_index, flow_index;
  SshEnginePolicyRule rule;
  SshEngineFlowData d_flow;
  SshEngineFlowControl c_flow;

  SSH_INTERCEPTOR_STACK_MARK();

  memset(engine_flow_zeroid, 0, sizeof(engine_flow_zeroid));

  for (rule_index = c_trd->rules;
       rule_index != SSH_IPSEC_INVALID_INDEX;
       rule_index = rule->trd_next)
    {
      rule = SSH_ENGINE_GET_RULE(engine, rule_index);

      SSH_ASSERT(rule != NULL);

      /* Update the flow ids. */
      if (rule->incoming_ipsec_flow != SSH_IPSEC_INVALID_INDEX)
        {
          d_flow = FASTPATH_GET_FLOW(engine->fastpath,
                                     rule->incoming_ipsec_flow);

          /* Update critical fields. */
          d_flow->src_ip = *remote_ip;
          d_flow->dst_ip = *local_ip;

          /* Update IP protocol and ports for flow consistency. */
          d_flow->ipproto = ipproto;
          d_flow->src_port = remote_port;
          d_flow->dst_port = local_port;

          /* Compute new SPI flow id into forward flow id if it
             is non-zero (i.e. a rekey has occurred recently). */
          if (memcmp(d_flow->forward_flow_id, engine_flow_zeroid,
                     SSH_ENGINE_FLOW_ID_SIZE))
            ssh_engine_flow_compute_flow_id_from_flow(
                                                engine,
                                                rule->incoming_ipsec_flow,
                                                d_flow,
                                                TRUE,
                                                d_flow->forward_flow_id);

          /* Compute new SPI flow id into reverse flow id. */
          ssh_engine_flow_compute_flow_id_from_flow(engine,
                                                    rule->incoming_ipsec_flow,
                                                    d_flow,
                                                    FALSE,
                                                    d_flow->reverse_flow_id);

          FASTPATH_COMMIT_FLOW(engine->fastpath,
                               rule->incoming_ipsec_flow, d_flow);
        }

      /* Reroute the rule's flows */
      flow_index = rule->flows;
      while (flow_index != SSH_IPSEC_INVALID_INDEX)
        {
          c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
          d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
          d_flow->data_flags |= SSH_ENGINE_FLOW_D_SPECIAL_FLOW;
          FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);
          c_flow->control_flags |= SSH_ENGINE_FLOW_C_REROUTE_PENDING;
          flow_index = c_flow->rule_next;
        }
    }

  /* Reroute the transform's no rule flows */
  flow_index = c_trd->norule_flows;
  while (flow_index != SSH_IPSEC_INVALID_INDEX)
    {
      c_flow = SSH_ENGINE_GET_FLOW(engine, flow_index);
      d_flow = FASTPATH_GET_FLOW(engine->fastpath, flow_index);
      d_flow->data_flags |= SSH_ENGINE_FLOW_D_SPECIAL_FLOW;
      FASTPATH_COMMIT_FLOW(engine->fastpath, flow_index, d_flow);
      c_flow->control_flags |= SSH_ENGINE_FLOW_C_REROUTE_PENDING;
      flow_index = c_flow->control_next;
    }
}


void ssh_engine_pme_update_by_peer_handle(SshEngine engine,
                                          SshUInt32 peer_handle,
                                          Boolean enable_natt,
                                          SshVriId routing_instance_id,
                                          SshIpAddr local_ip,
                                          SshIpAddr remote_ip,
                                          SshUInt16 remote_port,
#ifdef SSH_IPSEC_TCPENCAP
                                          unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                          SshPmeStatusCB callback,
                                          void *callback_context)
{
  SshEngineTransformControl c_trd, c_trd2;
  SshUInt32 hash, trd_index, next_trd_index, old_peer_hash, new_peer_hash;
  SshEngineTransformData d_trd;
  Boolean update_flows;
  SshUInt16 src_port, dst_port;
  SshUInt8 ipproto;
#ifdef SSH_IPSEC_TCPENCAP
  SshUInt32 old_tcp_encaps_conn_id;
#endif /* SSH_IPSEC_TCPENCAP */

  SSH_INTERCEPTOR_STACK_MARK();

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Updating peer handle 0x%lx to existing transforms",
             (unsigned long) peer_handle));

  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, TRUE, callback_context);
      return;
    }
  hash = ((SshUInt32) peer_handle / 8) % SSH_ENGINE_PEER_HANDLE_HASH_SIZE;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  for (trd_index = engine->peer_handle_hash[hash];
       trd_index != SSH_IPSEC_INVALID_INDEX;
       trd_index = next_trd_index)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
      SSH_ASSERT(c_trd != NULL);

      next_trd_index = c_trd->peer_handle_next;

      if (c_trd->peer_handle != peer_handle)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("hash collision %d/%d",
                                  (int) c_trd->peer_handle,
                                  (int) peer_handle));
          continue;
        }

      /* Found a target, now perform updates */
      update_flows = FALSE;
      src_port = 0;
      dst_port = 0;
      ipproto = 0;

      d_trd = FASTPATH_GET_TRD(engine->fastpath, trd_index);

      if (d_trd->transform & SSH_PM_IPSEC_AH)
        {
          src_port = 0;
          dst_port = 0;
          ipproto = SSH_IPPROTO_AH;
        }
      else if (d_trd->transform & SSH_PM_IPSEC_ESP)
        {
          src_port = 0;
          dst_port = 0;
          ipproto = SSH_IPPROTO_ESP;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          /* Update the NAT-T status of the transform if ESP is present */




          if (enable_natt)
            {
              if ((d_trd->transform & SSH_PM_IPSEC_NATT) == 0)
                update_flows = TRUE;

              d_trd->transform |= SSH_PM_IPSEC_NATT;
              src_port = remote_port;
              dst_port = d_trd->local_port;
              ipproto = SSH_IPPROTO_UDP;
            }
          else
            {
              if (d_trd->transform & SSH_PM_IPSEC_NATT)
                update_flows = TRUE;

              d_trd->transform &= ~SSH_PM_IPSEC_NATT;
            }
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
        }

      if (d_trd->remote_port != remote_port)
        update_flows = TRUE;
      d_trd->remote_port = remote_port;

#ifdef SSH_IPSEC_TCPENCAP
      old_tcp_encaps_conn_id = d_trd->tcp_encaps_conn_id;
      if (tcp_encaps_conn_spi != NULL
          && memcmp(tcp_encaps_conn_spi, "\x00\x00\x00\x00\x00\x00\x00\x00",
                    SSH_ENGINE_IKE_COOKIE_LENGTH) != 0)
        {
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
          SSH_ASSERT((d_trd->transform & SSH_PM_IPSEC_NATT) == 0);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
          d_trd->tcp_encaps_conn_id =
            ssh_engine_tcp_encaps_create_spi_mapping(engine,
                                              local_ip, remote_ip,
                                              tcp_encaps_conn_spi,
                                              d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                              d_trd->spis[SSH_PME_SPI_AH_OUT]);
          memcpy(c_trd->tcp_encaps_conn_spi, tcp_encaps_conn_spi,
                 SSH_ENGINE_IKE_COOKIE_LENGTH);
        }
      else
        {
          d_trd->tcp_encaps_conn_id = SSH_IPSEC_INVALID_INDEX;
          memset(c_trd->tcp_encaps_conn_spi, 0, SSH_ENGINE_IKE_COOKIE_LENGTH);
        }

      if (old_tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
        ssh_engine_tcp_encaps_remove_spi_mapping(engine,
                                              old_tcp_encaps_conn_id,
                                              d_trd->spis[SSH_PME_SPI_ESP_OUT],
                                              d_trd->spis[SSH_PME_SPI_AH_OUT]);

      /* Update the packet enlargement here when we know if IPsec over TCP
         is being used. */
      if (d_trd->tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX
          && old_tcp_encaps_conn_id == SSH_IPSEC_INVALID_INDEX)
        d_trd->packet_enlargement += (SSH_TCPH_HDRLEN +
                                      SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);

      else if (d_trd->tcp_encaps_conn_id == SSH_IPSEC_INVALID_INDEX
               && old_tcp_encaps_conn_id != SSH_IPSEC_INVALID_INDEX)
        d_trd->packet_enlargement -= (SSH_TCPH_HDRLEN +
                                      SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN);
#endif /* SSH_IPSEC_TCPENCAP */

      /* Calculate hash for old gw_addr */
      old_peer_hash = SSH_IP_HASH(&d_trd->gw_addr) % SSH_ENGINE_PEER_HASH_SIZE;

      if (!SSH_IP_EQUAL(&d_trd->gw_addr, remote_ip) ||
          !SSH_IP_EQUAL(&d_trd->own_addr, local_ip))
        {
          SshInterceptorInterface *ifp;

          ssh_kernel_mutex_lock(engine->interface_lock);

          ifp = ssh_ip_get_interface_by_ip(&engine->ifs, local_ip,
                                           routing_instance_id);
          if (ifp == NULL)
            {
              ssh_kernel_mutex_unlock(engine->interface_lock);

              FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);

              ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

              if (callback != NULL_FNPTR)
                (*callback)(engine->pm, FALSE, callback_context);
              return;
            }

          d_trd->own_ifnum = ifp->ifnum;
          c_trd->control_flags |= SSH_ENGINE_TR_C_IPSEC_FLOW_REROUTE_ONGOING;

          update_flows = TRUE;

          ssh_kernel_mutex_unlock(engine->interface_lock);
        }

      d_trd->own_addr = *local_ip;
      d_trd->gw_addr = *remote_ip;

      if (routing_instance_id >= 0)
        c_trd->routing_instance_id = routing_instance_id;

      /* Calculate hash for new gw_addr */
      new_peer_hash = SSH_IP_HASH(&d_trd->gw_addr) % SSH_ENGINE_PEER_HASH_SIZE;

      FASTPATH_COMMIT_TRD(engine->fastpath, trd_index, d_trd);

      /* IP address or UDP encapsulation information has changed, now
         we need to update the flows related to this transform. */
      if (update_flows)
        engine_update_trd_flows(engine, c_trd, local_ip, remote_ip, ipproto,
                                src_port, dst_port);

      /* Update also engine->peer_hash as d_trd->gw_addr has changed */

      /* Remove trd_index from old hash slot */
      if (c_trd->peer_next != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_next);
          SSH_ASSERT(c_trd2 != NULL);
          c_trd2->peer_prev = c_trd->peer_prev;
        }
      if (c_trd->peer_prev != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_prev);
          SSH_ASSERT(c_trd2 != NULL);
          c_trd2->peer_next = c_trd->peer_next;
        }
      else
        {
          SSH_ASSERT(engine->peer_hash[old_peer_hash] == trd_index);
          engine->peer_hash[old_peer_hash] = c_trd->peer_next;
        }

      /* Add trd_index to new hash slot */
      c_trd->peer_prev = SSH_IPSEC_INVALID_INDEX;
      c_trd->peer_next = engine->peer_hash[new_peer_hash];
      if (c_trd->peer_next != SSH_IPSEC_INVALID_INDEX)
        {
          c_trd2 = SSH_ENGINE_GET_TRD(engine, c_trd->peer_next);
          SSH_ASSERT(c_trd2 != NULL);
          c_trd2->peer_prev = trd_index;
        }
      engine->peer_hash[new_peer_hash] = trd_index;
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (callback != NULL_FNPTR)
    (*callback)(engine->pm, TRUE, callback_context);
  return;
}


/* This frees all SSH_ENGINE_RULE_APPLY rules and all flows with a
   transform that have their trc->peer_handle equal to `peer_handle'.
   This function should be called whenever an IKEv2 SA is destroyed, it
   will remove all IPSec SA's created by that IKE SA.

   This is designed to work iteratively: the policy manager
   should call this to delete transforms belonging to the IKE SA, and
   this will call `callback' back. ssh_engine_pme_delete_by_peer_handle
   should be called repeatedly until `done' becomes TRUE. See the
   documentation for the SshPmeDeleteTransformCB callback for more
   information. */
void ssh_engine_pme_delete_by_peer_handle(SshEngine engine,
                                          SshUInt32 peer_handle,
                                          SshPmeDeleteTransformCB callback,
                                          void *context)
{
  SshEngineTransformControl c_trd;
  SshEngineTransformData d_trd;
  SshEngineTransformStruct tr_ret;
  SshUInt32 hashvalue, trd_index, next_trd_index;
  SshUInt32 rule_index;
  SshEnginePolicyRule rule;
  void *policy_context = NULL;

  if (peer_handle == SSH_IPSEC_INVALID_INDEX)
    {
      if (callback != NULL_FNPTR)
        (*callback)(engine->pm, TRUE, SSH_IPSEC_INVALID_INDEX, NULL, NULL,
                    context);
      return;
    }

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Deleting transforms by peer handle 0x%lx",
             (unsigned long)peer_handle));

  /* We will loop here until we find no more trds with this peer. */
 loop:
  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  hashvalue = ((SshUInt32) peer_handle / 8) % SSH_ENGINE_PEER_HANDLE_HASH_SIZE;

  for (trd_index = engine->peer_handle_hash[hashvalue];
       trd_index != SSH_IPSEC_INVALID_INDEX;
       trd_index = next_trd_index)
    {
      c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, trd_index);
      SSH_ASSERT(c_trd != NULL);
      SSH_ASSERT(d_trd->transform != 0);

      next_trd_index = c_trd->peer_handle_next;

      if ((c_trd->control_flags & SSH_ENGINE_TR_C_DELETE_PENDING)
          || c_trd->peer_handle != peer_handle)
        {
          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
          continue;
        }

      if (callback != NULL_FNPTR)
        {
          /* Copy transform data for passing to the completion callback. */
          tr_ret.data = *d_trd;
          tr_ret.control = *c_trd;

          /* Search for a rule that has a policy context */
          for (rule_index = c_trd->rules;
               rule_index != SSH_IPSEC_INVALID_INDEX;
               rule_index = rule->trd_next)
            {
              rule = SSH_ENGINE_GET_RULE(engine, rule_index);
              SSH_ASSERT(rule != NULL);

              if (rule->policy_context != NULL)
                {
                  policy_context = rule->policy_context;
                  break;
                }
            }
        }

      FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);

      /* We have a trd for the given peer.  Delete all rules for the
         given trd and the trd itself. */
      ssh_engine_clear_and_delete_trd(engine, trd_index);

      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

      /* Pass information about the transform to the user callback. */
      if (callback != NULL_FNPTR)
        {
          ssh_engine_transform_event_normalize_spis(&tr_ret);
          (*callback)(engine->pm, FALSE, peer_handle, &tr_ret, policy_context,
                      context);
          return;
        }
      else
        {
          goto loop;
        }
    }

  /* If we get here, there are no rules left with the given peer. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  if (callback != NULL_FNPTR)
    (*callback)(engine->pm, TRUE, peer_handle, NULL, NULL, context);
  return;
}

/* Determines whether we have a transform that specifies the given
   `ip_addr' (and remote IKE port in remote_ike_port) as the address
   of the peer.  This intended for determining whether to send initial
   contact notifications or not when creating a new Phase 1 IKE SA.
   This calls the callback with TRUE if such a transform exists, and
   with FALSE if one does not exist (either during this call or at
   some later time). */

void ssh_engine_pme_have_transform_with_peer(SshEngine engine,
                                             const SshIpAddr ip_addr,
                                             SshUInt16 remote_ike_port,
                                             SshPmeStatusCB callback,
                                             void *context)
{
  SshEngineTransformControl c_trd;
  SshUInt32 hashvalue, trd_index, next_trd_index;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  hashvalue = SSH_IP_HASH(ip_addr) % SSH_ENGINE_PEER_HASH_SIZE;
  for (trd_index = engine->peer_hash[hashvalue];
       trd_index != SSH_IPSEC_INVALID_INDEX;
       trd_index = next_trd_index)
    {
      SshEngineTransformData d_trd;

      c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, trd_index);
      SSH_ASSERT(c_trd != NULL);
      SSH_ASSERT(d_trd != NULL);
      SSH_ASSERT(d_trd->transform != 0);
      next_trd_index = c_trd->peer_next;

      if (d_trd->transform & SSH_PM_IPSEC_MANUAL)
        {
          SSH_DEBUG(SSH_D_MY, ("transform 0x%08x is manual",
                               (unsigned int) trd_index));
          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
          continue;
        }

      if (!SSH_IP_EQUAL(&d_trd->gw_addr, ip_addr))
        {
          SSH_DEBUG(SSH_D_MY,
                    ("transform 0x%08x gw %@ does not match %@",
                     (unsigned int) trd_index,
                     ssh_ipaddr_render, &d_trd->gw_addr,
                     ssh_ipaddr_render, ip_addr));
          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
          continue;
        }

      if (d_trd->remote_port != remote_ike_port)
        {
          SSH_DEBUG(SSH_D_MY,
                    ("transform 0x%08x port %u does not match %u",
                     (unsigned int) trd_index,
                     d_trd->remote_port, remote_ike_port));

          FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
          continue;
        }

      /* We have a trd for the given peer. */
      FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
      ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
      (*callback)(engine->pm, TRUE, context);
      return;
    }
  /* If we get here, there are no transforms with the given peer. */
  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);
  (*callback)(engine->pm, FALSE, context);
}

/* Retrieves the transform object of the given transform index from
   the engine.  The callback function `callback' will be called with
   `context' and `trd' either during this call or later.  If the
   transform index is invalid, then `trd' will be NULL.  The callback
   should copy all relevant fields of the returned transform object if
   they are needed after this call. */

void ssh_engine_pme_get_transform(SshEngine engine, SshUInt32 trd_index,
                                  SshPmeTransformCB callback, void *context)
{
  SshEngineTransformControl c_trd;
  SshEngineTransformStruct trddata;
  SshEngineTransform tr;

  ssh_kernel_mutex_lock(engine->flow_control_table_lock);

  /* Fetch the transform, identified by the transform index. */
  tr = NULL;
  c_trd = SSH_ENGINE_GET_TRD(engine, trd_index);
  if (c_trd)
    {
      SshEngineTransformData d_trd;

      d_trd = FASTPATH_GET_READ_ONLY_TRD(engine->fastpath, trd_index);
      /* The transform index is valid.  Copy its data into our local
         variable and set `trd' to point to it. */
      tr = &trddata;
      trddata.control = *c_trd;
      trddata.data = *d_trd;
      FASTPATH_RELEASE_TRD(engine->fastpath, trd_index);
    }

  ssh_kernel_mutex_unlock(engine->flow_control_table_lock);

  /* Pass information about the transform to the user callback. */
  (*callback)(engine->pm, tr, context);
}

/********************** Transform utility functions **************************/

/* Calculates the time for transform soft event. */
SshTime ssh_engine_transform_soft_event_time(SshEngine engine,
                                             SshEngineFlowControl c_flow,
                                             SshEngineTransformControl c_trd,
                                             SshUInt32 rekey_attempt)
{
  SshUInt32 soft_expire_time;

  SSH_ASSERT(c_flow != NULL);
  SSH_ASSERT(c_trd != NULL);

  /* First calculate time of first soft event relative to hard expiry. */
  soft_expire_time = c_trd->life_seconds / 20;
  if (soft_expire_time < SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME)
    soft_expire_time = SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME;
  if (soft_expire_time > SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME_MAX)
    soft_expire_time = SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME_MAX;

  /* Then calculate time of the rekey_attempt'th soft event. */
  if (rekey_attempt > SSH_ENGINE_MAX_REKEY_ATTEMPTS)
    rekey_attempt = SSH_ENGINE_MAX_REKEY_ATTEMPTS;

  soft_expire_time =
    (soft_expire_time * (SSH_ENGINE_MAX_REKEY_ATTEMPTS - rekey_attempt))
    / SSH_ENGINE_MAX_REKEY_ATTEMPTS;

  /* Convert to absolute time */
  if (c_flow->hard_expire_time < (SshTime) soft_expire_time)
    return 0;
  return c_flow->hard_expire_time - (SshTime) soft_expire_time;
}

/* Return the correct pairwise order of SPI values in the transform object
   that is passed to the policymanager in the transform deletion callbacks. */
void ssh_engine_transform_event_normalize_spis(SshEngineTransform tr)
{
  SshUInt32 spi;
  int i;

  /* If rekey is pending, then the new inbound SPI values have been set
     but the outbound SPI values are still the old ones. */
  if (tr->control.control_flags & SSH_ENGINE_TR_C_REKEY_PENDING)
    {
      /* If the rekey operation replaced current SPI values, then the
         current SPIs values have already been destroyed from the
         policymanager. The new inbound SPI has been set in the transform
         but it is freed in the policymanager when the rekey of outbound
         direction fails. */
      if (tr->control.control_flags & SSH_ENGINE_TR_C_OUTBOUND_SPI_INVALID)
        {
          /* Clear the new inbound and outbound SPI values */
          for (i = 0; i < 6; i++)
            tr->data.spis[i] = 0;
          tr->control.control_flags &= ~SSH_ENGINE_TR_C_OUTBOUND_SPI_INVALID;
        }

      /* Otherwise the transform has the new inbound SPI values set, but not
         the outbound SPI values. Need to restore the old inbound SPI values.
         The new SPI values are freed in the policymanager when the rekey of
         outbound direction fails. */
      else
        {
          tr->data.spis[SSH_PME_SPI_ESP_IN] =
            tr->data.old_spis[SSH_PME_SPI_ESP_IN];
          tr->data.spis[SSH_PME_SPI_AH_IN] =
            tr->data.old_spis[SSH_PME_SPI_AH_IN];
          tr->data.spis[SSH_PME_SPI_IPCOMP_IN] =
            tr->data.old_spis[SSH_PME_SPI_IPCOMP_IN];

          tr->data.old_spis[SSH_PME_SPI_ESP_IN] = 0;
          tr->data.old_spis[SSH_PME_SPI_AH_IN] = 0;
          tr->data.old_spis[SSH_PME_SPI_IPCOMP_IN] = 0;
        }
    }

  /* Ok, no rekey pending. Check if the transform has inactive outbound
     SPI values installed and activate them if so. */
  else if (tr->control.control_flags
           & SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE)
    {
      for (i = SSH_PME_SPI_ESP_OUT; i <= SSH_PME_SPI_IPCOMP_OUT; i++)
        {
          spi = tr->data.spis[i];
          tr->data.spis[i] = tr->data.old_spis[i];
          tr->data.old_spis[i] = spi;
        }

      tr->control.control_flags &=
        ~SSH_ENGINE_TR_C_REKEYED_OUTBOUND_SPI_INACTIVE;
    }
}
