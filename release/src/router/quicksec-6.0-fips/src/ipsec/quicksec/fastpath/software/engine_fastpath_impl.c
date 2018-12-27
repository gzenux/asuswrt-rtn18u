/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementations of the functions and other supporting material
   described in engine_fastpath.h.
*/

#include "sshincludes.h"
#include "engine_internal.h"
#include "engine_fastpath.h"
#include "engine_fastpath_impl.h"
#include "fastpath_swi.h"

#define SSH_DEBUG_MODULE "SshEngineFastpathImpl"

#ifndef FASTPATH_PROVIDES_TRD










SshEngineTransformData
swi_fastpath_get_trd_lock(SshFastpath fastpath, SshUInt32 trd_index,
                          Boolean lock)
{
  SshFastpathTransformData trd;

  trd = (SshFastpathTransformData)
    SSH_FASTPATH_GET_TRD_UNWRAPPED(fastpath, trd_index & 0xffffff);
  SSH_ASSERT(trd != NULL);
  if (lock)
    ssh_kernel_mutex_lock(&trd->lock);

  return trd->data;
}


SshEngineTransformData
sw_fastpath_get_trd(SshFastpath fastpath, SshUInt32 trd_index,
                    Boolean ronly, Boolean init)
{
  SshEngineTransformData trd;

  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);







  SSH_ASSERT((trd_index & 0xffffff) < fastpath->transform_table_size);

  /* Get the trd element and lock it */
  trd = swi_fastpath_get_trd_lock(fastpath, trd_index, TRUE);

  if (init)
    {
      trd->transform = 0;
      memset(&trd->spis, 0, sizeof(trd->spis));
      memset(&trd->old_spis, 0, sizeof(trd->old_spis));
      SSH_IP_UNDEFINE(&trd->own_addr);
      SSH_IP_UNDEFINE(&trd->gw_addr);
    }

  if (!ronly)
    {
      fastpath->trd_cache->transform = trd->transform;
      fastpath->trd_cache->own_addr = trd->own_addr;
      fastpath->trd_cache->gw_addr = trd->gw_addr;
      fastpath->trd_cache->remote_port = trd->remote_port;

      memcpy(fastpath->trd_cache->spis, trd->spis,
             sizeof(fastpath->trd_cache->spis));
      memcpy(fastpath->trd_cache->old_spis, trd->old_spis,
             sizeof(fastpath->trd_cache->old_spis));
      memcpy(fastpath->trd_cache->keymat, trd->keymat,
             sizeof(fastpath->trd_cache->keymat));
      memcpy(fastpath->trd_cache->old_keymat, trd->old_keymat,
             sizeof(fastpath->trd_cache->old_keymat));
      fastpath->trd_cache->is_ipv6 = SSH_IP_IS6(&trd->own_addr);
    }




  return trd;
}


void
sw_fastpath_commit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                       SshEngineTransformData data)
{
  SshEngineTransformData trd;

  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);







  trd = swi_fastpath_get_trd_lock(fastpath, trd_index, FALSE);
  SSH_ASSERT(data == trd);

  SSH_ASSERT((trd_index & 0xffffff) < fastpath->transform_table_size);

  /* SA addresses and/or NAT-T remote port has been updated */
  if (SSH_IP_DEFINED(&fastpath->trd_cache->own_addr) &&
      SSH_IP_DEFINED(&fastpath->trd_cache->gw_addr) &&
      (SSH_IP_CMP(&data->own_addr, &fastpath->trd_cache->own_addr) ||
       SSH_IP_CMP(&data->gw_addr, &fastpath->trd_cache->gw_addr)
       || data->remote_port != fastpath->trd_cache->remote_port
       ))
    {
      ssh_fastpath_update_sa_tc(fastpath, fastpath->trd_cache->transform,
                                fastpath->trd_cache->old_keymat,
                                fastpath->trd_cache->
                                old_spis[SSH_PME_SPI_AH_IN],
                                fastpath->trd_cache->
                                old_spis[SSH_PME_SPI_ESP_IN],
                                FALSE, /* for_output */
                                fastpath->trd_cache->is_ipv6,
                                &data->own_addr,
                                &data->gw_addr,
                                data->remote_port);

      ssh_fastpath_update_sa_tc(fastpath, fastpath->trd_cache->transform,
                                fastpath->trd_cache->keymat,
                                fastpath->trd_cache->spis[SSH_PME_SPI_AH_IN],
                                fastpath->trd_cache->spis[SSH_PME_SPI_ESP_IN],
                                FALSE, /* for_output */
                                fastpath->trd_cache->is_ipv6,
                                &data->own_addr,
                                &data->gw_addr,
                                data->remote_port);

      ssh_fastpath_update_sa_tc(fastpath, fastpath->trd_cache->transform,
                                fastpath->trd_cache->keymat +
                                (SSH_IPSEC_MAX_KEYMAT_LEN / 2),
                                fastpath->trd_cache->spis[SSH_PME_SPI_AH_OUT],
                                fastpath->trd_cache->spis[SSH_PME_SPI_ESP_OUT],
                                TRUE, /* for_output */
                                fastpath->trd_cache->is_ipv6,
                                &data->own_addr,
                                &data->gw_addr,
                                data->remote_port);
    }

  /* Inbound SPI was rekeyed */
  if ((data->spis[SSH_PME_SPI_ESP_IN]
       != fastpath->trd_cache->spis[SSH_PME_SPI_ESP_IN]) ||
      (data->spis[SSH_PME_SPI_AH_IN]
       != fastpath->trd_cache->spis[SSH_PME_SPI_AH_IN]))
    {
      /* If we still have previous old SA around, free any transform
         contexts relating to it now. */
      if (fastpath->trd_cache->old_spis[SSH_PME_SPI_AH_IN] != 0 ||
          fastpath->trd_cache->old_spis[SSH_PME_SPI_ESP_IN] != 0)
        ssh_fastpath_destroy_sa_tc(fastpath, fastpath->trd_cache->transform,
                                   fastpath->trd_cache->old_keymat,
                                   fastpath->trd_cache->
                                   old_spis[SSH_PME_SPI_AH_IN],
                                   fastpath->trd_cache->
                                   old_spis[SSH_PME_SPI_ESP_IN],
                                   FALSE, /* for_output */
                                   fastpath->trd_cache->is_ipv6);
    }

  /* Old inbound SPI's are invalidated */
  if ((data->old_spis[SSH_PME_SPI_ESP_IN]
       != fastpath->trd_cache->old_spis[SSH_PME_SPI_ESP_IN] &&
       data->old_spis[SSH_PME_SPI_ESP_IN] == 0) ||
      (data->old_spis[SSH_PME_SPI_AH_IN]
       != fastpath->trd_cache->old_spis[SSH_PME_SPI_AH_IN] &&
       data->old_spis[SSH_PME_SPI_AH_IN] == 0))

    {
      ssh_fastpath_destroy_sa_tc(fastpath, fastpath->trd_cache->transform,
                                 fastpath->trd_cache->old_keymat,
                                 fastpath->trd_cache->
                                 old_spis[SSH_PME_SPI_AH_IN],
                                 fastpath->trd_cache->
                                 old_spis[SSH_PME_SPI_ESP_IN],
                                 FALSE, /* for_output */
                                 fastpath->trd_cache->is_ipv6);
    }

  /* Outbound SA was rekeyed */
  if ((data->spis[SSH_PME_SPI_ESP_OUT]
       != fastpath->trd_cache->spis[SSH_PME_SPI_ESP_OUT]) ||
      (data->spis[SSH_PME_SPI_AH_OUT]
       != fastpath->trd_cache->spis[SSH_PME_SPI_AH_OUT]))
    {
      /* Outbound SA was rekeyed. Destroy any old transform contexts for
         the outbound SA. */
      ssh_fastpath_destroy_sa_tc(fastpath, fastpath->trd_cache->transform,
                                 fastpath->trd_cache->keymat +
                                 (SSH_IPSEC_MAX_KEYMAT_LEN / 2),
                                 fastpath->trd_cache->spis[SSH_PME_SPI_AH_OUT],
                                 fastpath->trd_cache->
                                 spis[SSH_PME_SPI_ESP_OUT],
                                 TRUE, /* for_output */
                                 fastpath->trd_cache->is_ipv6);
    }

  /* Release the lock on the transform table element */
  FP_COMMIT_TRD(fastpath, trd_index, trd);
}

void
sw_fastpath_uninit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                       SshEngineTransformData data)
{
  SshEngineTransformData trd;

  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);






  SSH_ASSERT((trd_index & 0xffffff) < fastpath->transform_table_size);

  /* Fetch the trd element. trd is already locked. */
  trd = swi_fastpath_get_trd_lock(fastpath, trd_index, FALSE);
  SSH_ASSERT(data == trd);

  if (fastpath->trd_cache->old_spis[SSH_PME_SPI_AH_IN] != 0 ||
      fastpath->trd_cache->old_spis[SSH_PME_SPI_ESP_IN] != 0)
    ssh_fastpath_destroy_sa_tc(fastpath, fastpath->trd_cache->transform,
                               fastpath->trd_cache->old_keymat,
                               fastpath->trd_cache->
                               old_spis[SSH_PME_SPI_AH_IN],
                               fastpath->trd_cache->
                               old_spis[SSH_PME_SPI_ESP_IN],
                               FALSE, /* for_output */
                               fastpath->trd_cache->is_ipv6);

  ssh_fastpath_destroy_sa_tc(fastpath, fastpath->trd_cache->transform,
                             fastpath->trd_cache->keymat,
                             fastpath->trd_cache->spis[SSH_PME_SPI_AH_IN],
                             fastpath->trd_cache->spis[SSH_PME_SPI_ESP_IN],
                             FALSE, /* for_output */
                             fastpath->trd_cache->is_ipv6);

  ssh_fastpath_destroy_sa_tc(fastpath, fastpath->trd_cache->transform,
                             fastpath->trd_cache->keymat +
                             (SSH_IPSEC_MAX_KEYMAT_LEN / 2),
                             fastpath->trd_cache->spis[SSH_PME_SPI_AH_OUT],
                             fastpath->trd_cache->spis[SSH_PME_SPI_ESP_OUT],
                             TRUE, /* for_output */
                             fastpath->trd_cache->is_ipv6);

  /* Release the lock on the transform table element */
  FP_RELEASE_TRD(fastpath, trd_index);
}

void
sw_fastpath_release_trd(SshFastpath fastpath, SshUInt32 trd_index)
{






  ssh_kernel_mutex_assert_is_locked(fastpath->engine->flow_control_table_lock);













  /* Release the lock on the transform table element */
  FP_RELEASE_TRD(fastpath, trd_index);
}

#endif /* !FASTPATH_PROVIDES_TRD */

#ifndef FASTPATH_PROVIDES_NH
#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR









SshEngineNextHopData
sw_fastpath_get_nh(SshFastpath fastpath, SshUInt32 nh_index, Boolean ronly)
{
  SshFastpathNextHopData nh =
    (SshFastpathNextHopData) FP_GET_NH(fastpath, nh_index);







  return nh->data;
}

void
sw_fastpath_commit_nh(SshFastpath fastpath, SshUInt32 nh_index,
                   SshEngineNextHopData nh)
{






  return;
}

void
sw_fastpath_release_nh(SshFastpath fastpath, SshUInt32 nh_index)
{





}
#endif /* not SSH_IPSEC_IP_ONLY_INTERCEPTOR */
#endif /* !FASTPATH_PROVIDES_NH */



/************************ Fastpath API implementation. **********************/

/** Flow accessor macros. If fastpath accelerator provides flow management,
    then the function variant from Fastpath Accel API is called. Otherwise
    the software function variant is called. */

SshEngineFlowData
fastpath_init_flow(SshFastpath fastpath, SshUInt32 flow_index)
{
#ifdef FASTPATH_PROVIDES_FLOW
  return fastpath_accel_init_flow(fastpath->accel, flow_index);
#else /* FASTPATH_PROVIDES_FLOW */
  return sw_fastpath_get_flow(fastpath, flow_index, FALSE);
#endif /* !FASTPATH_PROVIDES_FLOW */
}

SshEngineFlowData
fastpath_get_flow(SshFastpath fastpath, SshUInt32 flow_index)
{
#ifdef FASTPATH_PROVIDES_FLOW
  return fastpath_accel_get_flow(fastpath->accel, flow_index);
#else /* FASTPATH_PROVIDES_FLOW */
  return sw_fastpath_get_flow(fastpath, flow_index, FALSE);
#endif /* !FASTPATH_PROVIDES_FLOW */
}

SshEngineFlowData
fastpath_get_read_only_flow(SshFastpath fastpath, SshUInt32 flow_index)
{
#ifdef FASTPATH_PROVIDES_FLOW
  return fastpath_accel_get_read_only_flow(fastpath->accel, flow_index);
#else /* FASTPATH_PROVIDES_FLOW */
  return sw_fastpath_get_flow(fastpath, flow_index, TRUE);
#endif /* !FASTPATH_PROVIDES_FLOW */
}

void
fastpath_commit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                     SshEngineFlowData flow)
{
#ifdef FASTPATH_PROVIDES_FLOW
  fastpath_accel_commit_flow(fastpath->accel, flow_index, flow);
#else /* FASTPATH_PROVIDES_FLOW */
  sw_fastpath_commit_flow(fastpath, flow_index, flow);
#endif /* !FASTPATH_PROVIDES_FLOW */
}

void
fastpath_uninit_flow(SshFastpath fastpath, SshUInt32 flow_index,
                     SshEngineFlowData flow)
{
#ifdef FASTPATH_PROVIDES_FLOW
  fastpath_accel_uninit_flow(fastpath->accel, flow_index, flow);
#else /* FASTPATH_PROVIDES_FLOW */
  sw_fastpath_uninit_flow(fastpath, flow_index, flow);
#endif /* !FASTPATH_PROVIDES_FLOW */
}

void
fastpath_release_flow(SshFastpath fastpath, SshUInt32 flow_index)
{
#ifdef FASTPATH_PROVIDES_FLOW
  fastpath_accel_release_flow(fastpath->accel, flow_index);
#else /* FASTPATH_PROVIDES_FLOW */
  sw_fastpath_release_flow(fastpath, flow_index);
#endif /* !FASTPATH_PROVIDES_FLOW */
}

void
fastpath_rekey_flow(SshFastpath fastpath, SshUInt32 flow_index)
{
#ifdef FASTPATH_PROVIDES_FLOW
  fastpath_accel_rekey_flow(fastpath->accel, flow_index);
#else /* FASTPATH_PROVIDES_FLOW */
  return;
#endif /* !FASTPATH_PROVIDES_FLOW */
}



/** Transform accessor macros. If fastpath accelerator provides transform
    management, then the function variant from Fastpath Accel API is called.
    Otherwise the software function variant is called. */

SshEngineTransformData
fastpath_init_trd(SshFastpath fastpath, SshUInt32 trd_index)
{
#ifdef FASTPATH_PROVIDES_TRD
  return fastpath_accel_init_trd(fastpath->accel, trd_index);
#else /* FASTPATH_PROVIDES_TRD */
  return sw_fastpath_get_trd(fastpath, trd_index, FALSE, TRUE);
#endif /* !FASTPATH_PROVIDES_TRD */
}

SshEngineTransformData
fastpath_get_trd(SshFastpath fastpath, SshUInt32 trd_index)
{
#ifdef FASTPATH_PROVIDES_TRD
  return fastpath_accel_get_trd(fastpath->accel, trd_index);
#else /* FASTPATH_PROVIDES_TRD */
  return sw_fastpath_get_trd(fastpath, trd_index, FALSE, FALSE);
#endif /* !FASTPATH_PROVIDES_TRD */
}

SshEngineTransformData
fastpath_get_read_only_trd(SshFastpath fastpath, SshUInt32 trd_index)
{
#ifdef FASTPATH_PROVIDES_TRD
  return fastpath_accel_get_read_only_trd(fastpath->accel, trd_index);
#else /* FASTPATH_PROVIDES_TRD */
  return sw_fastpath_get_trd(fastpath, trd_index, TRUE, FALSE);
#endif /* !FASTPATH_PROVIDES_TRD */
}

void
fastpath_commit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                    SshEngineTransformData trd)
{
#ifdef FASTPATH_PROVIDES_TRD
  fastpath_accel_commit_trd(fastpath->accel, trd_index, trd);
#else /* FASTPATH_PROVIDES_TRD */
  sw_fastpath_commit_trd(fastpath, trd_index, trd);
#endif /* !FASTPATH_PROVIDES_TRD */
}

void
fastpath_uninit_trd(SshFastpath fastpath, SshUInt32 trd_index,
                    SshEngineTransformData trd)
{
#ifdef FASTPATH_PROVIDES_TRD
  fastpath_accel_uninit_trd(fastpath->accel, trd_index, trd);
#else /* FASTPATH_PROVIDES_TRD */
  sw_fastpath_uninit_trd(fastpath, trd_index, trd);
#endif /* !FASTPATH_PROVIDES_TRD */
}

void
fastpath_release_trd(SshFastpath fastpath, SshUInt32 trd_index)
{
#ifdef FASTPATH_PROVIDES_TRD
  fastpath_accel_release_trd(fastpath->accel, trd_index);
#else /* FASTPATH_PROVIDES_TRD */
  sw_fastpath_release_trd(fastpath, trd_index);
#endif /* !FASTPATH_PROVIDES_TRD */
}


#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/** Nexthop accessor macros. If fastpath accelerator provides nexthop
    management, then the function variant from Fastpath Accel API is called.
    Otherwise the software function variant is called. */

SshEngineNextHopData
fastpath_init_nh(SshFastpath fastpath, SshUInt32 nh_index)
{
#ifdef FASTPATH_PROVIDES_NH
  return fastpath_accel_init_nh(fastpath->accel, nh_index);
#else /* FASTPATH_PROVIDES_NH */
  return sw_fastpath_get_nh(fastpath, nh_index, FALSE);
#endif /* !FASTPATH_PROVIDES_NH */
}

SshEngineNextHopData
fastpath_get_nh(SshFastpath fastpath, SshUInt32 nh_index)
{
#ifdef FASTPATH_PROVIDES_NH
  return fastpath_accel_get_nh(fastpath->accel, nh_index);
#else /* FASTPATH_PROVIDES_NH */
  return sw_fastpath_get_nh(fastpath, nh_index, FALSE);
#endif /* !FASTPATH_PROVIDES_NH */
}

SshEngineNextHopData
fastpath_get_read_only_nh(SshFastpath fastpath, SshUInt32 nh_index)
{
#ifdef FASTPATH_PROVIDES_NH
  return fastpath_accel_get_read_only_nh(fastpath->accel, nh_index);
#else /* FASTPATH_PROVIDES_NH */
  return sw_fastpath_get_nh(fastpath, nh_index, TRUE);
#endif /* !FASTPATH_PROVIDES_NH */
}

void
fastpath_commit_nh(SshFastpath fastpath, SshUInt32 nh_index,
                   SshEngineNextHopData nh)
{
#ifdef FASTPATH_PROVIDES_NH
  fastpath_accel_commit_nh(fastpath->accel, nh_index, nh);
#else /* FASTPATH_PROVIDES_NH */
  sw_fastpath_commit_nh(fastpath, nh_index, nh);
#endif /* !FASTPATH_PROVIDES_NH */
}

void
fastpath_uninit_nh(SshFastpath fastpath, SshUInt32 nh_index,
                   SshEngineNextHopData nh)
{
#ifdef FASTPATH_PROVIDES_NH
  fastpath_accel_uninit_nh(fastpath->accel, nh_index, nh);
#else /* FASTPATH_PROVIDES_NH */
  sw_fastpath_commit_nh(fastpath, nh_index, nh);
#endif /* !FASTPATH_PROVIDES_NH */
}

void
fastpath_release_nh(SshFastpath fastpath, SshUInt32 nh_index)
{
#ifdef FASTPATH_PROVIDES_NH
  fastpath_accel_release_nh(fastpath->accel, nh_index);
#else /* FASTPATH_PROVIDES_NH */
  sw_fastpath_release_nh(fastpath, nh_index);
#endif /* !FASTPATH_PROVIDES_NH */
}

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */
