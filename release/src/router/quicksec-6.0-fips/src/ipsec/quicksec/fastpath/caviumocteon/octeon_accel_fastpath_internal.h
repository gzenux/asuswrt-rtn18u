/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon accelerated fastpath for QuickSec.
   This file includes internal defines for accelerated
   fastpath.
*/

#ifndef OCTEON_ACCEL_FASTPATH_INTERNAL_H
#define OCTEON_ACCEL_FASTPATH_INTERNAL_H 1

#include "sshincludes.h"
#include "ipsec_params.h"
#include "engine.h"
#include "interceptor.h"

#include "engine_internal.h"
#include "fastpath_accel.h"

#include "octeon_se_fastpath_shared.h"

#include "cvmx.h"
#include "cvmx-app-init.h"
#include "cvmx-fau.h"
#include "cvmx-fpa.h"
#include "cvmx-bootmem.h"
#include "cvmx-wqe.h"
#include "cvmx-pow.h"
#include "cvmx-rng.h"


#define OCT_ENGINE_INDEX_TO_SE_INDEX(i) \
  ((i) == SSH_IPSEC_INVALID_INDEX ? OCTEON_SE_FASTPATH_INVALID_INDEX : (i))
#define OCT_SE_INDEX_TO_ENGINE_INDEX(i) \
  ((i) == OCTEON_SE_FASTPATH_INVALID_INDEX ? SSH_IPSEC_INVALID_INDEX : (i))


/** Lock status */
typedef enum
{
  OCTEON_ACCEL_LOCK_UNLOCKED       = 0x0,
  OCTEON_ACCEL_LOCK_WRITE_LOCKED   = 0x1,
  OCTEON_ACCEL_LOCK_READ_LOCKED    = 0x2
} SshOcteonLockState;


/** Macros for fetching SshOcteonInternalFlowData from a 2d table. */
#define OCTEON_ACCEL_FASTPATH_IFLOW_TABLE_BLOCK_SIZE \
  (SSH_ENGINE_MAX_MALLOC / sizeof(SshOcteonInternalFlowDataStruct))
#define OCTEON_ACCEL_FASTPATH_IFLOW_BLOCK(flow_index) \
  ((flow_index) / OCTEON_ACCEL_FASTPATH_IFLOW_TABLE_BLOCK_SIZE)
#define OCTEON_ACCEL_FASTPATH_IFLOW_SLOT(flow_index) \
  ((flow_index) % OCTEON_ACCEL_FASTPATH_IFLOW_TABLE_BLOCK_SIZE)
#define OCTEON_ACCEL_FASTPATH_IFLOW(accel, flow_index)  \
  (&(accel)->i_flow_table                               \
   [OCTEON_ACCEL_FASTPATH_IFLOW_BLOCK(flow_index)]      \
   [OCTEON_ACCEL_FASTPATH_IFLOW_SLOT(flow_index)])

typedef struct SshOcteonInternalFlowDataRec
{
  SshIpAddrStruct nat_src_ip;
  SshIpAddrStruct nat_dst_ip;
  SshUInt16 nat_src_port;
  SshUInt16 nat_dst_port;
} SshOcteonInternalFlowDataStruct, *SshOcteonInternalFlowData;

typedef struct SshOcteonAccelFlowCacheRec
{
  SshEngineFlowDataStruct data[1];

  /** Private fields */
  SshOcteonLockState locked;
  SshUInt32 flow_index;
} SshOcteonAccelFlowCacheStruct, *SshOcteonAccelFlowCache;


/** Macros for fetching SshOcteonInternalTransformData from a 2d table. */
#define OCTEON_ACCEL_FASTPATH_ITRD_TABLE_BLOCK_SIZE \
  (SSH_ENGINE_MAX_MALLOC / sizeof(SshOcteonInternalTransformDataStruct))
#define OCTEON_ACCEL_FASTPATH_ITRD_BLOCK(trd_index) \
  ((trd_index) / OCTEON_ACCEL_FASTPATH_ITRD_TABLE_BLOCK_SIZE)
#define OCTEON_ACCEL_FASTPATH_ITRD_SLOT(trd_index) \
  ((trd_index) % OCTEON_ACCEL_FASTPATH_ITRD_TABLE_BLOCK_SIZE)
#define OCTEON_ACCEL_FASTPATH_ITRD(accel, trd_index)    \
  (&(accel)->i_trd_table                                \
   [OCTEON_ACCEL_FASTPATH_ITRD_BLOCK(trd_index)]        \
   [OCTEON_ACCEL_FASTPATH_ITRD_SLOT(trd_index)])

typedef struct SshOcteonInternalTransformDataRec
{
  SshPmTransform transform;

#ifdef SSHDIST_L2TP
  SshUInt16 l2tp_local_port;
  SshUInt16 l2tp_remote_port;
  SshUInt16 l2tp_local_tunnel_id;
  SshUInt16 l2tp_local_session_id;
  SshUInt16 l2tp_remote_tunnel_id;
  SshUInt16 l2tp_remote_session_id;
  SshUInt16 l2tp_seq_ns;
  SshUInt16 l2tp_seq_nr;
  SshUInt8 l2tp_flags;
#endif /* SSHDIST_L2TP */

  SshUInt32 spis[6];
  SshUInt32 old_spis[6];

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  SshUInt8 natt_flags;
  unsigned char natt_oa_l[SSH_IP_ADDR_SIZE];
  unsigned char natt_oa_r[SSH_IP_ADDR_SIZE];
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  SshUInt32 extension[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /** (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SshUInt8 decapsulate_extension : 1;
  SshUInt8 restart_after_tre : 1;
  SshUInt8 gw_addr_undefined : 1;
  SshUInt8 own_addr_undefined : 1;
  SshUInt8 unused_flags : 4;

  SshUInt8 nesting_level;
  SshUInt32 tr_index;

} SshOcteonInternalTransformDataStruct, *SshOcteonInternalTransformData;

typedef struct SshOcteonAccelTransformCacheRec
{
  SshEngineTransformDataStruct data[1];

  /** Private fields */
  SshOcteonLockState locked;
  SshUInt32 trd_index;
} SshOcteonAccelTransformCacheStruct, *SshOcteonAccelTransformCache;


/** Macros for fetching SshOcteonInternalNextHopData from a 2d table. */
#define OCTEON_ACCEL_FASTPATH_INH_TABLE_BLOCK_SIZE                      \
  (SSH_ENGINE_MAX_MALLOC / sizeof(SshOcteonInternalNextHopDataStruct))
#define OCTEON_ACCEL_FASTPATH_INH_BLOCK(nh_index)               \
  ((nh_index) / OCTEON_ACCEL_FASTPATH_INH_TABLE_BLOCK_SIZE)
#define OCTEON_ACCEL_FASTPATH_INH_SLOT(nh_index)                \
  ((nh_index) % OCTEON_ACCEL_FASTPATH_INH_TABLE_BLOCK_SIZE)
#define OCTEON_ACCEL_FASTPATH_INH(accel, nh_index)      \
  (&(accel)->i_nh_table                                 \
   [OCTEON_ACCEL_FASTPATH_INH_BLOCK(nh_index)]          \
   [OCTEON_ACCEL_FASTPATH_INH_SLOT(nh_index)])

typedef struct SshOcteonInternalNextHopDataRec
{
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  SshUInt8 flags;
  SshUInt8 mediatype;
  SshUInt8 media_protocol;
} SshOcteonInternalNextHopDataStruct, *SshOcteonInternalNextHopData;

typedef struct SshOcteonAccelNextHopCacheRec
{
  SshEngineNextHopDataStruct data[1];

  /** Private fields */
  SshOcteonLockState locked;
  SshUInt32 nh_index;
} SshOcteonAccelNextHopCacheStruct, *SshOcteonAccelNextHopCache;

typedef struct SshFastpathAccelRec
{
  SshEngine engine;
  SshInterceptor interceptor;

  SshFastpathAccelPacketCB software_fastpath_packet_handler;

  SeFastpath se;
  Boolean accel_allocated_bootmem;

  SshOcteonAccelFlowCacheStruct flow[1];
  SshOcteonAccelTransformCacheStruct trd[1];
  SshOcteonAccelNextHopCacheStruct nh[1];

  SshKernelMutexStruct flow_lock[1];
  SshKernelMutexStruct trd_lock[1];
  SshKernelMutexStruct nh_lock[1];

  SshOcteonInternalFlowData *i_flow_table;
  SshOcteonInternalTransformData *i_trd_table;
  SshOcteonInternalNextHopData *i_nh_table;

} SshFastpathAccelStruct;

#endif /* OCTEON_ACCEL_FASTPATH_INTERNAL_H */
