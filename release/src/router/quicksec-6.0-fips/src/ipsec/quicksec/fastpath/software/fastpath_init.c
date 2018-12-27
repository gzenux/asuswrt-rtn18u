/**
   @copyright
   Copyright (c) 2004 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Fastpath setup/teardown.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "fastpath_accel.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathInit"

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
Boolean
software_fastpath_compute_flow_id(SshFastpath fastpath,
                                  SshEnginePacketContext pc,
                                  SshInterceptorPacket pp,
                                  SshUInt32 tunnel_id,
                                  unsigned char *flow_id)
{
  return (*fastpath->accel_flow_id_cb)(fastpath->accel,
                                       pc, pp, tunnel_id, flow_id);
}
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

SshEngineFlowData
fastpath_lookup_flow(SshFastpath fastpath, SshEnginePacketContext pc)
{
#ifdef FASTPATH_PROVIDES_FLOW
  return fastpath_accel_lookup_flow(fastpath->accel, pc);
#else /* FASTPATH_PROVIDES_FLOW */
  return fastpath_sw_lookup_flow(fastpath, pc);
#endif /* FASTPATH_PROVIDES_FLOW */
}

#ifdef FASTPATH_PROVIDES_LRU_FLOWS
void
fastpath_bump_lru_flow(SshFastpath fastpath, SshUInt32 flow_index)
{
  fastpath_accel_bump_lru_flow(fastpath->accel, flow_index);
}

SshUInt32
fastpath_get_lru_flow(SshFastpath fastpath, SshUInt32 lru_level)
{
  return fastpath_accel_get_lru_flow(fastpath->accel, lru_level);
}
#endif /* FASTPATH_PROVIDES_LRU_FLOWS */


Boolean
fastpath_stop(SshFastpath fastpath)
{
  SshUInt32 i;

  for (i = 0; i < SSH_ENGINE_MAX_TRANSFORM_CONTEXTS; i++)
    {
      SshFastpathTransformContext tc = SSH_FASTPATH_GET_TRC(fastpath, i);

      if (tc && (tc->refcnt > 0))
        return FALSE;
    }

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  if (fastpath_accel_stop(fastpath->accel) == FALSE)
    return FALSE;
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

  /* Get rid of all fragments now. */
  fastpath_fragmagic_uninit(fastpath);

  return TRUE;
}

Boolean
fastpath_init(SshEngine engine,
              SshInterceptor interceptor,
              SshFastpathPacketCB packet_handler,
              SshFastpathPacketCB address_resolution,
              SshFastpathFlowIDCB *flow_id_return,
              SshFastpath *fastpath_return)
{
  SshFastpathFragEntry fe;
  SshFastpath fastpath;
  SshUInt32 i;

  /* Allocate fastpath object. */
  fastpath = ssh_fastpath_alloc(engine);
  if (fastpath == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate fastpath object"));
      return FALSE;
    }

  engine->fastpath = fastpath;

#ifndef FASTPATH_PROVIDES_FLOW
  /* Initialize flow table. */
  if (!fastpath_sw_init_flows(fastpath))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize flow objects"));
      goto fail;
    }
#endif /* !FASTPATH_PROVIDES_FLOW */

#ifndef FASTPATH_PROVIDES_TRD
  /* Initialize transform table. */
  for (i = 0; i < fastpath->transform_table_size; i++)
    {
      SshFastpathTransformData trd;

      trd = (SshFastpathTransformData) FP_GET_TRD_UNLOCKED(fastpath, i);
      trd->data->transform = 0;
      if (!ssh_kernel_mutex_init(&trd->lock))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize transform objects"));
          goto fail;
        }
    }
#endif /* !FASTPATH_PROVIDES_TRD */

  /* Initialize fragment magic / reassembly data structures. */

  /* SSH_ENGINE_MAX_SESSIONS is configurable compile time, and may be
     different from SSH_ENGINE_FRAGMENT_TABLE_SIZE */
  /* coverity[same_on_both_sides] */
  for (i = 0; i < SSH_ENGINE_FRAGMENT_HASH_SIZE; i++)
    fastpath->frag_hash[i] = NULL;

  /* SSH_ENGINE_MAX_SESSIONS is configurable compile time, and may be
     different from SSH_ENGINE_FRAGMENT_TABLE_SIZE */
  /* coverity[same_on_both_sides] */
  for (i = 0; i < SSH_ENGINE_FRAGMENT_TABLE_SIZE; i++)
    {
      fe = &fastpath->frag_table[i];
      memset(fe, 0, sizeof(*fe));
      SSH_PUT_32BIT(fe->frag_id, i); /* Split to all hash slots. */
      fe->expiration = 0;
      ssh_fastpath_fragmagic_add_all_lru(fastpath, fe);
      ssh_fastpath_fragmagic_add_hash(fastpath, fe);
      /* We don't put it on data_lru because it has no data. */
    }
  fastpath->frag_timeout_scheduled = 0;

#if defined (WITH_IPV6)
  /* Randomize initial value of IPv6 fragment identification counter. */
#if (FASTPATH_ENGINE_IPV6_FRAG_ID_MAX == 0xffffffff) && \
    (FASTPATH_ENGINE_IPV6_FRAG_ID_MIN == 0)
  fastpath->frag_id_ctr = (SshUInt32) ssh_rand();
#else
  fastpath->frag_id_ctr = (FASTPATH_ENGINE_IPV6_FRAG_ID_MIN +
                           ((SshUInt32) ssh_rand() %
                            (FASTPATH_ENGINE_IPV6_FRAG_ID_MAX
                             - FASTPATH_ENGINE_IPV6_FRAG_ID_MIN + 1)));
#endif
#endif /* WITH_IPV6 */

#ifdef SSH_IPSEC_STATISTICS
  /* Store table size information in fastpath->stats[0] */
  fastpath->stats[0].packet_context_table_size
    = SSH_ENGINE_MAX_PACKET_CONTEXTS;
  fastpath->stats[0].active_transform_contexts = 0;
  fastpath->stats[0].transform_context_table_size =
    SSH_ENGINE_MAX_TRANSFORM_CONTEXTS;

  fastpath->stats[0].transform_context_struct_size
    = sizeof(SshFastpathTransformContextStruct);
#endif /* SSH_IPSEC_STATISTICS */

  *fastpath_return = fastpath;
  *flow_id_return = NULL_FNPTR;

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  /* Initialize accelerated fastpath. */
  if (!fastpath_accel_init(engine,
                           interceptor,
                           software_fastpath_packet_handler,
                           &fastpath->accel_flow_id_cb,
                           &fastpath->accel))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to initialize accelerated fastpath"));
      goto fail;
    }
  SSH_ASSERT(fastpath->accel != NULL);
#else /* FASTPATH_ACCELERATOR_CONFIGURED */
  /* Register packet callback to interceptor. */
  if (!ssh_interceptor_set_packet_cb(interceptor,
                                     fastpath_packet_callback,
                                     engine))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to set interceptor packet callback"));
      goto fail;
    }
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  if (fastpath->accel_flow_id_cb != NULL_FNPTR)
    *flow_id_return = software_fastpath_compute_flow_id;
  else
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */
    *flow_id_return = fastpath_compute_flow_id;

  fastpath_crypto_init();

  return TRUE;

 fail:
#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  /* Stop and unitialize accelerated fastpath. */
  if (fastpath->accel)
    {
      while (!fastpath_accel_stop(fastpath->accel));
      fastpath_accel_uninit(fastpath->accel);
    }
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */
  if (fastpath)
    fastpath_uninit(fastpath);
  *fastpath_return = NULL;
  engine->fastpath = NULL;
  return FALSE;
}

void
fastpath_suspend(SshFastpath fastpath)
{
#ifdef FASTPATH_PROVIDES_SUSPEND
  fastpath_accel_suspend(fastpath->accel);
#endif /* FASTPATH_PROVIDES_SUSPEND */

  /* Uninitialise fragmagic, essentially free all
     pending fragments and cancel the timer. */
  fastpath_fragmagic_uninit(fastpath);
}

void
fastpath_resume(SshFastpath fastpath)
{
  /* Nothing needs to be done here. Even though the fragmagic
     has been uninitialised, actually only all packets has been
     freed and timer cancelled. Fragmagic is still ready to
     go. */

#ifdef FASTPATH_PROVIDES_SUSPEND
  fastpath_accel_resume(fastpath->accel);
#endif /* FASTPATH_PROVIDES_SUSPEND */

  return;
}

void
fastpath_uninit(SshFastpath fastpath)
{
  SshUInt32 i;
#ifdef SSH_IPSEC_SEND_IS_SYNC
  SshEngine engine;
  engine = fastpath->engine;
#endif /* SSH_IPSEC_SEND_IS_SYNC */

  SSH_DEBUG(SSH_D_NICETOKNOW, ("uninitializing fastpath!"));

  if (fastpath->frag_lock)
    {
      fastpath_fragmagic_uninit(fastpath);

      ssh_kernel_mutex_lock(fastpath->frag_lock);
      if (fastpath->frag_timeout_scheduled)
        {
          ssh_kernel_timeout_cancel(ssh_fastpath_fragmagic_timeout,
                                    (void *)fastpath);
          fastpath->frag_timeout_scheduled = 0;
        }
      ssh_kernel_mutex_unlock(fastpath->frag_lock);
    }

  /* Free any data structures that may have been cached inside
     the fastpath. */
#ifndef FASTPATH_PROVIDES_TRD
   for (i = 0; i < fastpath->transform_table_size; i++)
    {
      SshFastpathTransformData trd;

      trd = (SshFastpathTransformData) FP_GET_TRD_UNLOCKED(fastpath, i);
      ssh_kernel_mutex_uninit(&trd->lock);
    }
#endif /* FASTPATH_PROVIDES_TRD */

  /* Clear transform contexts. */
  for (i = 0; i < SSH_ENGINE_MAX_TRANSFORM_CONTEXTS; i++)
    {
      SshFastpathTransformContext tc = SSH_FASTPATH_GET_TRC(fastpath, i);

      ssh_fastpath_uninit_transform_context(tc);
    }

#ifdef SSH_IPSEC_SEND_IS_SYNC
  /* Free all queued packets from recursive
     ssh_engine_packet_handler() calls. */
  while (fastpath->recursive_packets_head)
    {
      SshInterceptorPacket pp = fastpath->recursive_packets_head;

      fastpath->recursive_packets_head = pp->next;
      ssh_interceptor_packet_free(pp);
    }
  fastpath->recursive_packets_tail = NULL;

  /* Free all queued packets from asynchronous ssh_engine_send_packet
     operations. */
  while (engine->asynch_packets_head)
    {
      SshInterceptorPacket pp = engine->asynch_packets_head;

      engine->asynch_packets_head = pp->next;
      ssh_interceptor_packet_free(pp);
    }
  engine->asynch_packets_tail = NULL;

  while (fastpath->send_packets_head)
    {
      SshInterceptorPacket pp = fastpath->send_packets_head;
      SshEngineAsynchPacketData data;

      data = SSH_INTERCEPTOR_PACKET_DATA(pp, SshEngineAsynchPacketData);

      fastpath->send_packets_head = data->next;

      ssh_interceptor_packet_free(pp);
    }
  fastpath->send_packets_tail = NULL;
#endif /* SSH_IPSEC_SEND_IS_SYNC */

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  fastpath_accel_uninit(fastpath->accel);
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

#ifndef FASTPATH_PROVIDES_FLOW
  fastpath_sw_uninit_flows(fastpath);
#endif /* !FASTPATH_PROVIDES_FLOW */

  ssh_fastpath_free(fastpath);
  return;
}

void
fastpath_set_salt(SshFastpath fastpath, const unsigned char *salt,
                  size_t salt_len)
{
#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  fastpath_accel_set_salt(fastpath->accel, salt, salt_len);
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */
}

void
fastpath_notify_open(SshFastpath fastpath)
{
#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  fastpath_accel_notify_open(fastpath->accel);
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */
  return;
}

void
fastpath_notify_close(SshFastpath fastpath)
{
#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  fastpath_accel_notify_close(fastpath->accel);
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

  ssh_fastpath_fragmagic_drop_all(fastpath);

  return;
}

void
fastpath_set_params(SshFastpath fastpath, const SshEngineParams params)
{
  SSH_ASSERT(params != NULL);

#ifdef FASTPATH_ACCELERATOR_CONFIGURED
  fastpath_accel_set_params(fastpath->accel, params);
#endif /* FASTPATH_ACCELERATOR_CONFIGURED */

  ssh_kernel_mutex_lock(fastpath->frag_lock);
  fastpath->frag_policy = params->fragmentation_policy;
  ssh_kernel_mutex_unlock(fastpath->frag_lock);
}


#ifdef SSH_IPSEC_STATISTICS
void
fastpath_get_global_stats(SshFastpath fastpath,
                          SshFastpathGlobalStatsCB callback, void *context)
{
  SshFastpathGlobalStatsStruct stats, *statp;
  SshInt32 active_pc = 0, active_tc = 0; /* The number of active items can
                                            be negative on some CPU's ... */
 int i, j;

  memset(&stats, 0, sizeof(stats));

  /* Iterate over per-CPU statistics */
  for (i = 0; i < fastpath->num_cpus; i++)
    {
  stats.in_octets_comp += fastpath->stats[i].in_octets_comp;
  stats.in_octets_uncomp += fastpath->stats[i].in_octets_uncomp;
  stats.out_octets_comp += fastpath->stats[i].out_octets_comp;
  stats.out_octets_uncomp += fastpath->stats[i].out_octets_uncomp;
  stats.forwarded_octets_comp += fastpath->stats[i].forwarded_octets_comp;
  stats.forwarded_octets_uncomp += fastpath->stats[i].forwarded_octets_uncomp;
  stats.in_packets += fastpath->stats[i].in_packets;
  stats.out_packets += fastpath->stats[i].out_packets;
  stats.forwarded_packets += fastpath->stats[i].forwarded_packets;
  stats.total_transform_contexts +=
    fastpath->stats[i].total_transform_contexts;
  stats.out_of_transform_contexts +=
    fastpath->stats[i].out_of_transform_contexts;
  stats.out_of_packet_contexts += fastpath->stats[i].out_of_packet_contexts;

  active_tc += (SshInt32)fastpath->stats[i].active_transform_contexts;
  active_pc += (SshInt32)fastpath->stats[i].active_packet_contexts;

  for (j = 0; j < SSH_ENGINE_NUM_GLOBAL_STATS; j++)
    stats.counters[j] += fastpath->stats[i].counters[j];
    }

  /* The sum of active items over all CPU's must not be negative */
  SSH_ASSERT(active_pc >= 0);
  SSH_ASSERT(active_tc >= 0);
  stats.active_packet_contexts = (SshUInt32) active_pc;
  stats.active_transform_contexts = (SshUInt32) active_tc;

  /* Table sizes are stored in fastpath->stats[0] */
  statp = &fastpath->stats[0];
  stats.transform_context_struct_size = statp->transform_context_struct_size;
  stats.transform_context_table_size = statp->transform_context_table_size;
  stats.packet_context_table_size = statp->packet_context_table_size;





  /* Note: we ignore locking when retrieving statistics. */
  if (callback)
    (*callback)(fastpath->engine, &stats, context);
}
#endif /* SSH_IPSEC_STATISTICS */
