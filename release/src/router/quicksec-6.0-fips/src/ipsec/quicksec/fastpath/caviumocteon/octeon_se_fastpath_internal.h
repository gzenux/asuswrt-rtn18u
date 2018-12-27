/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file includes internal defines for SE fastpath.
*/

#ifndef OCTEON_SE_FASTPATH_INTERNAL_H
#define OCTEON_SE_FASTPATH_INTERNAL_H 1

#include "cvmx-config.h"
#include "cvmx.h"

#include "cvmx-helper.h"
#include "cvmx-helper-util.h"

#include "cvmx-spinlock.h"
#include "cvmx-rwlock.h"
#include "cvmx-wqe.h"
#include "cvmx-pow.h"
#include "cvmx-pko.h"
#include "cvmx-pip.h"
#include "cvmx-sysinfo.h"
#include "cvmx-bootmem.h"
#include "cvmx-coremask.h"
#include "cvmx-packet.h"
#include "cvmx-csr.h"
#include "cvmx-rng.h"

#include "octeon_se_fastpath_shared.h"

#include "sshincludes.h"
#include "sshinet.h"

/** Return value codes for SE fastpath functions */
typedef enum
{
  OCTEON_SE_FASTPATH_RET_OK = 0,         /* Success */
  OCTEON_SE_FASTPATH_RET_DROP = 1,       /* Drop packet */
  OCTEON_SE_FASTPATH_RET_SLOWPATH = 2,   /* Pass packet to slowpath */
  OCTEON_SE_FASTPATH_RET_DESCHEDULE = 3  /* Deschedule work entry */
} SeFastpathRet;

/** Map packet corruption return code. */
#ifdef OCTEON_SE_FASTPATH_AUDIT_CORRUPT
#define OCTEON_SE_FASTPATH_RET_CORRUPT OCTEON_SE_FASTPATH_RET_SLOWPATH
#else /* OCTEON_SE_FASTPATH_AUDIT_CORRUPT */
#define OCTEON_SE_FASTPATH_RET_CORRUPT OCTEON_SE_FASTPATH_RET_DROP
#endif /* OCTEON_SE_FASTPATH_AUDIT_CORRUPT */


/** Packet processing state */
#define OCTEON_SE_FASTPATH_PACKET_STATE_INIT          0
#define OCTEON_SE_FASTPATH_PACKET_STATE_PULLUP        1
#define OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_ID_HASH  2
#define OCTEON_SE_FASTPATH_PACKET_STATE_FLOW_LOOKUP   3
#define OCTEON_SE_FASTPATH_PACKET_STATE_TR_EXECUTION  4
#define OCTEON_SE_FASTPATH_PACKET_STATE_FINISH        5


/** Packet state object. This is used to store packet processing state for
    descheduled work entries. This has to fit into wqe->packet_data (96B) */
#define OCTEON_SE_FASTPATH_PACKET_STATE_CRITICAL_WORD 10
typedef struct SeFastpathPacketStateRec
{
  /* words 1-2 */
  SeFastpathFlowIdUnion flow_id;

  /* word 3 */
  uint32_t flow_index;
  uint32_t prev_transform_index;

  /* word 4 */
  uint16_t ip_len;
  uint16_t ip_offset;
  uint8_t ipproto;
  uint8_t ttl;
  uint16_t src_port;

  /* word 5 */
  uint16_t dst_port;
  uint8_t tr_offset;  /* Transport header offset */
  uint8_t ipsec_nh;
  uint32_t ipsec_spi;

  /* word 6 */
  uint32_t ipsec_seq;
  uint32_t ipsec_len;

  /* word 7-10 */
  uint64_t src_ip_low;
  uint64_t src_ip_high;
  uint64_t dst_ip_low;
  uint64_t dst_ip_high;

  /* word 11 */

  /* This word contains all the critical fields of packet state that
     must be zeroed when recycling the packet state. */

  uint32_t tunnel_id;
  uint8_t state;

  uint8_t ip_version_6 : 1; /** Packet is IPv6 */
  uint8_t forward : 1;      /** Packet matches flow in forward direction */
  uint8_t ipsec_natt : 1;   /** Packet is NAT-T encapsulated ESP */
  uint8_t ipv4_df : 1;      /** IPv4 df bit value */
  uint8_t df_bit_processing : 2; /** Should DF bit be set in outbound dir. */
  uint8_t ipsec_passby : 1; /** Packet is IPsec passby traffic */
  uint8_t flag_debug : 1;   /** Reserved for debugging */
  uint16_t unused16;

#ifdef OCTEON_SE_FASTPATH_COUNT_CYCLES
  /* word 12 */
  uint64_t cycles_total;
#endif /* OCTEON_SE_FASTPATH_COUNT_CYCLES */

} SeFastpathPacketStateStruct, *SeFastpathPacketState;


/** Packet context object. This is used for caching data needed during packet
    processing. This object is not stored over deschedule/reschedule. */
#define OCTEON_SE_FASTPATH_PACKET_CONTEXT_CRITICAL_WORD 2
typedef struct SeFastpathPacketContextRec
{
  /* word 1 */
  SeFastpathPacketState s;

  /* word 2 */
  uint32_t transform_index;
  uint32_t nh_index;

  /* word 3 */

  /* This word contains all the critical fields of packet context that
     must be zeroed when recycling the packet context. */

  uint8_t flag_rescheduled : 1;    /* wqe was rescheduled and packet_data
                                      contains cached packet state. */
  uint8_t flag_ipsec_incoming : 1; /* Packet belongs to incoming IPsec flow */
  uint8_t flag_high_prio : 1;      /* Packet needs high priority qos */
  uint8_t unused_flags : 5;

  uint8_t oport;

  /* Cached nexthop data */
  uint16_t mtu;
  uint16_t min_packet_len;
  uint8_t media_hdrlen;
  uint8_t unused8;

  /* word 4-5 */
  union
  {
    uint64_t raw[2];
    uint8_t data[OCTEON_SE_FASTPATH_MEDIA_HDR_SIZE];
  } media_hdr;

  /* word 6-7 */
  cvmx_wqe_t *wqe;
  SeFastpathFlowData se_flow;

} SeFastpathPacketContextStruct, *SeFastpathPacketContext;


/** Number of slowpath queues for normal priority. */
#define OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUES   \
  (OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MAX -   \
   OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MIN + 1)

/** Threshold values for POW queue lengths. If POW queue length exceeds these
    values then the packet is dropped (instead of passed to slowpath). */
/* High prio slowpath (queue 0) */
#define OCTEON_SE_FASTPATH_HIGH_PRIO_QLEN \
  (300 / (OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUES))
/* Normal slowpath (queues 1-6) */
#define OCTEON_SE_FASTPATH_NORMAL_PRIO_QLEN \
  (300 / (OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUES))

/** Map input port to normal prio slowpath queue. */
#define OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE(ipprt) \
  (OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MIN \
   + (ipprt) % OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUES)

#ifdef OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING
/** Slowpath rate limiting. These rate limiting variables are optimized for
    Cavium EBT-5800 with CN-5860 running at 700MHz. You may need to fine tune
    the rate limiting variables to match your Octeon setup and core clock
    freqeuncy.

    Allow atleast total of 30 normal priority packets every 10 million cycles
    per queue. Allow each queue to send additional packets until the total
    packet count for all normal priority queues reaches 450 packets. These
    total values are divided among all cores running SE fastpath.

    High priority packets are not rate limited, but there is still the maximum
    queue length defined above. */

/* Rate limit interval in cycles. */
#define OCTEON_SE_FASTPATH_RATE_LIMIT_CYCLES 10000000

/* Per core guaranteed packet count for a single normal prio queue. */
#define OCTEON_SE_FASTPATH_RATE_LIMIT_PKT \
  ((30 / (OCTEON_SE_FASTPATH_SLOWPATH_RATIO)) + 1)

/* Per core hardlimit for total packet count of all normal prio queues. */
#define OCTEON_SE_FASTPATH_RATE_LIMIT_TOTAL_PKT 130

/* Map queue to rate limit bucket. */
#define OCTEON_SE_FASTPATH_RATE_LIMIT_BUCKET(queue) \
  ((queue) - OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MIN)

#endif /* OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING */

/** Maximum size for transform context. Wide mode algorithms require
    more space for the scratch buffer. */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
#define OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE 264
#else /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */
#define OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE 168
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

/** Internal define for enabling code shared by SHA256 and SHA384/512. */
#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_512
#define OCTEON_SE_FASTPATH_TRANSFORM_SHA2
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

#ifdef OCTEON_SE_FASTPATH_TRANSFORM_SHA_256
#undef OCTEON_SE_FASTPATH_TRANSFORM_SHA2
#define OCTEON_SE_FASTPATH_TRANSFORM_SHA2
#endif /* OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

/** Static core local object. This is used for storing any core local
    information, like the packet context object and statistics. */
typedef struct SeFastpathCoreContextRec
{
  union
  {
    uint64_t padding[16];
    SeFastpathPacketContextStruct s;
  } pc;

  union
  {
    uint64_t padding[16];
    SeFastpathPacketStateStruct s;
  } state;

  union
  {
    uint64_t padding[16];
    SeFastpathPacketContextStruct s;
  } fragment;

  union
  {
    uint64_t padding[16];
    SeFastpathPacketStateStruct s;
  } fragment_state;

  /* Space for allocating transform contexts */
  uint8_t transform_context[OCTEON_SE_FASTPATH_TRANSFORM_CONTEXT_SIZE];

  /* Id used for generating next sequence number for IPv4 packets */
  uint64_t next_packet_id;

  /* Id used for generating next fragment id for IPv6 packets. */
  uint64_t next_frag_id;

#ifdef OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING
  /* Slowpath rate limiting */
  uint64_t slowpath_cycle_count;
  uint32_t slowpath_pkt_count[OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUES];
  uint32_t slowpath_total_pkt_count;
#endif /* OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING */

  uint32_t core_num;
  uint32_t salt;
  uint64_t control_grp;

#ifdef OCTEON_SE_FASTPATH_COLLECT_CORE_STATS
  /* Internal statistic counters */
  SeFastpathCoreStats stats;
#endif /* OCTEON_SE_FASTPATH_COLLECT_CORE_STATS */

#ifdef OCTEON_SE_FASTPATH_COUNT_CYCLES
  /* Cpu cycle counters */
  uint64_t cycles_start;
  uint64_t cycles_done;
  uint64_t packet_count;
#endif /* OCTEON_SE_FASTPATH_COUNT_CYCLES */
} SeFastpathCoreContextStruct, *SeFastpathCoreContext;

/** IPv4 identification */
#define OCTEON_SE_FASTPATH_GET_NEXT_IPV4_PACKET_ID(_core, _pid) \
do \
  { \
    (_pid) = (_core)->next_packet_id++; \
    (_core)->next_packet_id = ((_core)->next_packet_id & 0x0fff) \
                               | (((_core)->core_num & 0xf) << 12); \
  } \
while (0)

/** IPv6 fragment ID */
#define OCTEON_SE_FASTPATH_GET_NEXT_IPV6_FRAG_ID(_core, _fid) \
do \
  { \
    (_fid) = (_core)->next_frag_id++; \
    (_core)->next_frag_id = ((_core)->next_frag_id & 0x0fffffff) \
                             | (((_core)->core_num & 0xf) << 28); \
  } \
while (0)

/** IPv4 TTL for outer header in tunnel mode */
#define OCTEON_SE_FASTPATH_IP4_TUNNEL_MODE_TTL 64

/** IPv6 HL for outer header in tunnel mode */
#define OCTEON_SE_FASTPATH_IP6_TUNNEL_MODE_HL 240

/** POW tags */
#define OCTEON_SE_FLOW_TAG_SUBGROUP_DESCHED (CVMX_TAG_SUBGROUP_PKO + 1)
#define OCTEON_SE_FLOW_TAG_SUBGROUP_PROCESS_FWD (CVMX_TAG_SUBGROUP_PKO + 2)
#define OCTEON_SE_FLOW_TAG_SUBGROUP_PROCESS_REV (CVMX_TAG_SUBGROUP_PKO + 3)
#define OCTEON_SE_FLOW_TAG_SUBGROUP_SLOWPATH (CVMX_TAG_SUBGROUP_PKO + 4)
#define OCTEON_SE_TRD_TAG_SUBGROUP_OUT          (CVMX_TAG_SUBGROUP_PKO + 5)
#define OCTEON_SE_TRD_TAG_SUBGROUP_IN           (CVMX_TAG_SUBGROUP_PKO + 6)

#define OCTEON_SE_FASTPATH_FLOW_LOOKUP_TAG(flow_hash_id) \
  ((CVMX_TAG_SW_BITS_INTERNAL << CVMX_TAG_SW_SHIFT) \
   | (OCTEON_SE_FLOW_TAG_SUBGROUP_DESCHED  << CVMX_TAG_SUBGROUP_SHIFT) \
   | (CVMX_TAG_SUBGROUP_MASK & (flow_hash_id)))

#define OCTEON_SE_FASTPATH_FLOW_PROCESS_TAG(flow_index, forward) \
  ((CVMX_TAG_SW_BITS_INTERNAL << CVMX_TAG_SW_SHIFT) \
   | ((forward) ? \
      (OCTEON_SE_FLOW_TAG_SUBGROUP_PROCESS_FWD << CVMX_TAG_SUBGROUP_SHIFT) : \
      (OCTEON_SE_FLOW_TAG_SUBGROUP_PROCESS_REV << CVMX_TAG_SUBGROUP_SHIFT)) \
   | (CVMX_TAG_SUBGROUP_MASK & (flow_index)))

#define OCTEON_SE_FASTPATH_SLOWPATH_TAG(ipprt) \
  ((CVMX_TAG_SW_BITS_INTERNAL << CVMX_TAG_SW_SHIFT) \
   | (OCTEON_SE_FLOW_TAG_SUBGROUP_SLOWPATH  << CVMX_TAG_SUBGROUP_SHIFT) \
   | (CVMX_TAG_SUBGROUP_MASK & (ipprt)))

#define OCTEON_SE_FASTPATH_TRD_TAG(trd_index, incoming) \
  ((CVMX_TAG_SW_BITS_INTERNAL << CVMX_TAG_SW_SHIFT) \
   | ((incoming) ? \
      (OCTEON_SE_TRD_TAG_SUBGROUP_IN << CVMX_TAG_SUBGROUP_SHIFT) : \
      (OCTEON_SE_TRD_TAG_SUBGROUP_OUT << CVMX_TAG_SUBGROUP_SHIFT)) \
   | (CVMX_TAG_SUBGROUP_MASK & (trd_index)))


/** Statistics collection */
#ifdef OCTEON_SE_FASTPATH_STATISTICS
#define OCTEON_SE_FASTPATH_STATS(X) \
do \
  { \
    X; \
  } \
while (0)
#else /* OCTEON_SE_FASTPATH_STATISTICS */
#define OCTEON_SE_FASTPATH_STATS(X)
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

/** Protection against the compiler optimizing too much. */
#define OCTEON_SE_FASTPATH_ASM_NOREORDER() asm volatile (".set noreorder \n")
#define OCTEON_SE_FASTPATH_ASM_REORDER() asm volatile (".set reorder \n")

/** Debug macros */
#ifdef OCTEON_SE_FASTPATH_DEBUG

static inline void octeon_se_abort(void)
{
  uint64_t val = 0x20;     /* pulse MCD1 */
  asm volatile ("dmtc0 %[rt],$22,0" : : [rt] "d" (val));
  CVMX_BREAK;        /* break self as int doesn't trigger self */
}

/** Print a warning and abort if asserted condition fails */
#define OCTEON_SE_ASSERT(_cond)                                  \
do                                                               \
  {                                                              \
    if (!(_cond))                                                \
      {                                                          \
        fprintf(stderr, "Assertion failed at %s:%d: '%s'\n",     \
                __FILE__, __LINE__, #_cond);                     \
        octeon_se_abort();                                       \
      }                                                          \
  }                                                              \
while (0)


/** Print debug message prefixed with source file name and line number */
#define _TOSTRING(_s) #_s
#define _LINETOSTRING(_l) _TOSTRING(_l)
#define _LOCATION __FILE__ ":" _LINETOSTRING(__LINE__) ": "
#define OCTEON_SE_DEBUG(_level, X...)               \
do                                                  \
  {                                                 \
    if ((_level) <= OCTEON_SE_FASTPATH_DEBUG_LEVEL) \
      fprintf(stderr, _LOCATION X);                 \
  }                                                 \
while (0)

/** Hexdump */
#define OCTEON_SE_HEXDUMP(_level, _ptr, _len)                           \
do                                                                      \
  {                                                                     \
    if ((_level) <= OCTEON_SE_FASTPATH_DEBUG_LEVEL)                     \
      {                                                                 \
        size_t _i;                                                      \
        for (_i = 0; _i + 8 <= (_len); _i += 8)                         \
           fprintf(stderr, "%02x %02x %02x %02x %02x %02x %02x %02x\n", \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1),                            \
              *((uint8_t*) (_ptr) + _i + 2),                            \
              *((uint8_t*) (_ptr) + _i + 3),                            \
              *((uint8_t*) (_ptr) + _i + 4),                            \
              *((uint8_t*) (_ptr) + _i + 5),                            \
              *((uint8_t*) (_ptr) + _i + 6),                            \
              *((uint8_t*) (_ptr) + _i + 7));                           \
        if ((_len) - _i == 7)                                           \
          fprintf(stderr, "%02x %02x %02x %02x %02x %02x %02x\n",       \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1),                            \
              *((uint8_t*) (_ptr) + _i + 2),                            \
              *((uint8_t*) (_ptr) + _i + 3),                            \
              *((uint8_t*) (_ptr) + _i + 4),                            \
              *((uint8_t*) (_ptr) + _i + 5),                            \
              *((uint8_t*) (_ptr) + _i + 6));                           \
        if ((_len) - _i == 6)                                           \
          fprintf(stderr, "%02x %02x %02x %02x %02x %02x\n",            \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1),                            \
              *((uint8_t*) (_ptr) + _i + 2),                            \
              *((uint8_t*) (_ptr) + _i + 3),                            \
              *((uint8_t*) (_ptr) + _i + 4),                            \
              *((uint8_t*) (_ptr) + _i + 5));                           \
        if ((_len) - _i == 5) \
          fprintf(stderr, "%02x %02x %02x %02x %02x\n",                 \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1),                            \
              *((uint8_t*) (_ptr) + _i + 2),                            \
              *((uint8_t*) (_ptr) + _i + 3),                            \
              *((uint8_t*) (_ptr) + _i + 4));                           \
        if ((_len) - _i == 4)                                           \
          fprintf(stderr, "%02x %02x %02x %02x\n",                      \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1),                            \
              *((uint8_t*) (_ptr) + _i + 2),                            \
              *((uint8_t*) (_ptr) + _i + 3));                           \
        if ((_len) - _i == 3)                                           \
          fprintf(stderr, "%02x %02x %02x\n",                           \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1),                            \
              *((uint8_t*) (_ptr) + _i + 2));                           \
        if ((_len) - _i == 2)                                           \
          fprintf(stderr, "%02x %02x\n",                                \
              *((uint8_t*) (_ptr) + _i),                                \
              *((uint8_t*) (_ptr) + _i + 1));                           \
        if ((_len) - _i == 1)                                           \
          fprintf(stderr, "%02x\n",                                     \
              *((uint8_t*) (_ptr) + _i));                               \
      }                                                                 \
  }                                                                     \
while (0)

/** Dumps raw packet data */
#define OCTEON_SE_DUMP_PACKET(_level, _pc)                             \
do                                                                     \
  {                                                                    \
    OCTEON_SE_DEBUG((_level), "Packet length %d bytes\n",              \
                    (int) (_pc)->s->ip_len + (_pc)->s->ip_offset);     \
    OCTEON_SE_HEXDUMP((_level),                                        \
                      cvmx_phys_to_ptr((_pc)->wqe->packet_ptr.s.addr), \
                      (_pc)->s->ip_len + (_pc)->s->ip_offset);         \
  }                                                                    \
while (0)

/** Dumps the packet context using OCTEON_SE_DEBUG */
#define OCTEON_SE_DUMP_PC(_level, _pc)                                        \
  OCTEON_SE_DEBUG((_level), "pc: flow id 0x%016lx %016lx\n"                   \
         "hash_id %x tunnel_id %d xid high %d low %d ipproto %d flags 0x%u\n" \
         "flow_index %d prev_transform_index %d tunnel_id %d\n"               \
         "ipproto %d ttl %d src_port %d dst_port %d spi %d sec %d\n"          \
         "src_ip 0x%016lx %016lx dst_ip 0x%016lx %016lx\n"                    \
         "transform_index %d nh_index %d oport %d\n"                          \
         "ip offset %d len %d\n",                                             \
          (_pc)->s.flow_id.raw[0], (_pc)->s.flow_id.raw[1],                   \
          (_pc)->s.flow_id.id.hash_id, (_pc)->s.flow_id.id.tunnel_id,         \
          (_pc)->s.flow_id.id.protocol_xid_high,                              \
          (_pc)->s.flow_id.id.protocol_xid_low, (_pc)->s.flow_id.id.ipproto,  \
          (_pc)->s.flow_id.id.flags,                                          \
          (_pc)->s.flow_index, (_pc)->s.prev_transform_index,                 \
          (_pc)->s.tunnel_id,                                                 \
          (_pc)->s.ipproto, (_pc)->s.ttl, (_pc)->s.src_port,                  \
          (_pc)->s.dst_port, (_pc)->s.ipsec_spi, (_pc)->s.ipsec_seq,          \
          (_pc)->s.src_ip_high, (_pc)->s.src_ip_low,                          \
          (_pc)->s.dst_ip_high, (_pc)->s.dst_ip_low,                          \
          (_pc)->transform_index, (_pc)->nh_index, (_pc)->oport,              \
          (_pc)->s.ip_offset, (_pc)->s.ip_len)

#else /* OCTEON_SE_FASTPATH_DEBUG */
#define OCTEON_SE_ASSERT(_cond) \
do \
  { \
  } \
while (0)
#define OCTEON_SE_DEBUG(_level, X...) \
do \
  { \
  } \
while (0)
#define OCTEON_SE_HEXDUMP(_level, _ptr, _len) \
do \
  { \
  } \
while (0)
#define OCTEON_SE_DUMP_PACKET(_level, _pc) \
do \
  { \
  } \
while (0)
#define OCTEON_SE_DUMP_PC(_level, _pc) \
do \
  { \
  } \
while (0)
#endif /* OCTEON_SE_FASTPATH_DEBUG */

/** Forced debugging. This can be used for limited debugging during
    performance testing. */
#define OCTEON_SE_FORCE_DEBUG(X...) fprintf(stderr, X)

/** Cpu cycle counting on SE fastpath */
#ifdef OCTEON_SE_FASTPATH_COUNT_CYCLES
#define OCTEON_SE_CYCLE_COUNT_PKT_INTERVAL 123
#define OCTEON_SE_CYCLE_COUNT_START(_pc, _core) \
do \
  { \
    (_core)->packet_count++; \
    if (cvmx_likely(((_core)->packet_count \
                     % OCTEON_SE_CYCLE_COUNT_PKT_INTERVAL) == 0)) \
      { \
        (_pc)->s->flag_debug = 1; \
        (_pc)->s->cycles_total = 0; \
        (_core)->cycles_start = cvmx_get_cycle(); \
      } \
  } \
while (0)
#define OCTEON_SE_CYCLE_COUNT_CONT(_pc, _core) \
do \
  { \
    if (cvmx_likely((_pc)->s->flag_debug)) \
      (_core)->cycles_start = cvmx_get_cycle(); \
  } \
while (0)
#define OCTEON_SE_CYCLE_COUNT_DESCHED(_pc, _core) \
do \
  { \
    if (cvmx_likely((_pc)->s->flag_debug)) \
      { \
        (_core)->cycles_done = cvmx_get_cycle(); \
        (_pc)->s->cycles_total += (_core)->cycles_done-(_core)->cycles_start;\
      } \
  } \
while (0)
#define OCTEON_SE_CYCLE_COUNT_DONE(_pc, _core) \
do \
  { \
    if ((_pc)->s->flag_debug) \
      { \
        (_core)->cycles_done = cvmx_get_cycle(); \
        fprintf(stderr, "prev %ld step %ld total %ld\n", \
                (_pc)->s->cycles_total, \
                (_core)->cycles_done - (_core)->cycles_start, \
                (_core)->cycles_done - (_core)->cycles_start \
                + (_pc)->s->cycles_total); \
      } \
  } \
while (0)
#else /* OCTEON_SE_FASTPATH_COUNT_CYCLES */
#define OCTEON_SE_CYCLE_COUNT_START(_pc, _core) \
do  \
  { \
  } \
while (0)
#define OCTEON_SE_CYCLE_COUNT_CONT(_pc, _core) \
do  \
  { \
  } \
while (0)
#define OCTEON_SE_CYCLE_COUNT_DESCHED(_pc, _core) \
do  \
  { \
  } \
while (0)
#define OCTEON_SE_CYCLE_COUNT_DONE(_pc, _core) \
do  \
  { \
  } \
while (0)
#endif /* OCTEON_SE_FASTPATH_COUNT_CYCLES */

/** Core statistics collecting */
#ifdef OCTEON_SE_FASTPATH_COLLECT_CORE_STATS
#define OCTEON_SE_CORE_STATS(X) \
do \
  { \
    X; \
  } \
while (0)
#else /* OCTEON_SE_FASTPATH_COLLECT_CORE_STATS */
#define OCTEON_SE_CORE_STATS(X) \
do  \
  { \
  } \
while (0)
#endif /* OCTEON_SE_FASTPATH_COLLECT_CORE_STATS */

typedef struct SeFastpathPacketBufferRec
{
  /* Total bytes that can be read or written to in this packet
     chain. This need not be equal to the packet length. */
  uint16_t total_bytes;

  /* Bytes that can be read/written in this particular segment. */
  uint16_t bytes_available;

  /* Number of buffers in the packet chain. */
  uint16_t total_num_bufs;

  /* Pointer to current read/write offset. */
  uint8_t *ptr;

  /* Packet chain head. */
  cvmx_buf_ptr_t packet;

  /* Current buffer being read/written. */
  cvmx_buf_ptr_t curr;
} SeFastpathPacketBufferStruct, *SeFastpathPacketBuffer;


/** Function prototypes */
void
octeon_se_fastpath_packet_callback(SeFastpathCoreContext core,
                                   SeFastpath fastpath,
                                   cvmx_wqe_t *wqe);

SeFastpathRet
octeon_se_fastpath_transform_in(SeFastpathCoreContext core,
                                SeFastpath fastpath,
                                SeFastpathPacketContext pc);

SeFastpathRet
octeon_se_fastpath_transform_out(SeFastpathCoreContext core,
                                 SeFastpath fastpath,
                                 SeFastpathPacketContext pc);


/** Skip values for first and non-first buffer in a packet buffer chain. */
#define OCTEON_SE_FASTPATH_FIRST_MBUFF_SKIP CVMX_HELPER_FIRST_MBUFF_SKIP
#define OCTEON_SE_FASTPATH_NOT_FIRST_MBUFF_SKIP \
  CVMX_HELPER_NOT_FIRST_MBUFF_SKIP

/** Get/put macros for 16, 32 and 64 bit aligned datatypes. These macros should
    be used only when proper alignment is guaranteed. */

#define OCTEON_SE_GET_64BIT_ALIGNED(p, r) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(p)) % 8 == 0); \
    ((r) = *((uint64_t *) (p))); \
  } \
while (0)
#define OCTEON_SE_GET_32BIT_ALIGNED(p, r) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(p)) % 4 == 0); \
    ((r) = *((uint32_t *) (p))); \
  } \
while (0)
#define OCTEON_SE_GET_16BIT_ALIGNED(p, r) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(p)) % 2 == 0); \
    ((r) = *((uint16_t *) (p))); \
  } \
while (0)
#define OCTEON_SE_GET_8BIT(p, r) ((r) = *((uint8_t *) (p)))

#define OCTEON_SE_PUT_64BIT_ALIGNED(p, v) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(p)) % 8 == 0); \
    (*((uint64_t *) (p))) = ((uint64_t) (v)); \
  } \
while (0)
#define OCTEON_SE_PUT_32BIT_ALIGNED(p, v) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(p)) % 4 == 0); \
    (*((uint32_t *) (p))) = ((uint32_t) (v)); \
  } \
while (0)
#define OCTEON_SE_PUT_16BIT_ALIGNED(p, v) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(p)) % 2 == 0); \
    (*((uint16_t *) (p))) = ((uint16_t) (v)); \
  } \
while (0)
#define OCTEON_SE_PUT_8BIT(p, v) ((*((uint8_t *) (p))) = ((uint8_t) (v)))

/** Get/put macros. These should be used when alignment is not guaranteed. */
#define OCTEON_SE_GET_64BIT(p, r) \
do \
  { \
    CVMX_LOADUNA_INT64((r), (p), 0); \
  } \
while (0)
#define OCTEON_SE_GET_32BIT(p, r) \
do \
  { \
    CVMX_LOADUNA_INT32((r), (p), 0); \
  } \
while (0)
#define OCTEON_SE_GET_16BIT(p, r) \
do \
  { \
    CVMX_LOADUNA_UINT16((r), (p), 0); \
  } \
while (0)

#define OCTEON_SE_PUT_64BIT(p, v) \
do \
  { \
    CVMX_STOREUNA_INT64((v), (p), 0); \
  } \
while (0)
#define OCTEON_SE_PUT_32BIT(p, v) \
do \
  { \
    CVMX_STOREUNA_INT32((v), (p), 0); \
  } \
while (0)
#define OCTEON_SE_PUT_16BIT(p, v) \
do \
  { \
    CVMX_STOREUNA_INT16((v), (p), 0); \
  } \
while (0)

/** Copy 64bits from s to d. This should be used when the alignment of both
    s and d is guaranteed. */
#define OCTEON_SE_COPY_64BIT_ALIGNED(d, s) \
do \
  { \
    OCTEON_SE_ASSERT(((uint64_t)(s)) % 8 == 0); \
    OCTEON_SE_ASSERT(((uint64_t)(d)) % 8 == 0); \
    *((uint64_t *) (d)) = *((uint64_t *) (s)); \
  } \
while (0)

/** Copy 64bits from s to d. This should be used when alignment is not
    guaranteed. */
#define OCTEON_SE_COPY_64BIT(d, s) \
do \
  { \
    memcpy((void *) (d), (void *) (s), 8); \
  } \
while (0)

/** Align value to next 8 byte boundary. */
#define OCTEON_SE_ALIGN_64(v) (((v) + 7) & ~7)

/** Macros for parsing and building IP and transport headers.

    The parser macros are used for parsing wqe->packet_data (which is always
    8 byte aligned) and packet data of decapsulated packets (which are
    allocated to 8 byte boundary). Note also that TCP/UDP headers are also
    guaranteed to be 8 byte aligned as any packet with IPv4 options is thrown
    immediately to slowpath.

    The builder macros are used for modifying actual packet data which is not
    guaranteed to be 8 byte or 4 byte aligned.
*/


/** IPv6 */

#define OCTEON_SE_FASTPATH_IP6_HDRLEN 40

#define OCTEON_SE_FASTPATH_IPH6_OFS_VERSION SSH_IPH6_OFS_VERSION
#define OCTEON_SE_FASTPATH_IPH6_OFS_CLASS SSH_IPH6_OFS_CLASS
#define OCTEON_SE_FASTPATH_IPH6_OFS_FLOW SSH_IPH6_OFS_FLOW
#define OCTEON_SE_FASTPATH_IPH6_OFS_LEN SSH_IPH6_OFS_LEN
#define OCTEON_SE_FASTPATH_IPH6_OFS_NH SSH_IPH6_OFS_NH
#define OCTEON_SE_FASTPATH_IPH6_OFS_HL SSH_IPH6_OFS_HL
#define OCTEON_SE_FASTPATH_IPH6_OFS_SRC SSH_IPH6_OFS_SRC
#define OCTEON_SE_FASTPATH_IPH6_OFS_DST SSH_IPH6_OFS_DST

/** IPv6 parsing */
#define OCTEON_SE_FASTPATH_IPH6_VERSION(p, r) \
do \
  { \
    OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_VERSION, r); \
    (r) = ((r) >> 4); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH6_CLASS(p, r) \
do \
  { \
    uint16_t _x; \
    OCTEON_SE_GET_16BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_CLASS, _x); \
    (r) = (uint8_t) ((_x >> 4) & 0xff); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH6_FLOW(p, r) \
do \
  { \
    OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH6_OFS_FLOW-1, r); \
    (r) = ((r) & 0x000fffff); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH6_LEN(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH6_OFS_LEN, r)
#define OCTEON_SE_FASTPATH_IPH6_NH(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_NH, r)
#define OCTEON_SE_FASTPATH_IPH6_HL(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_HL, r)
#define OCTEON_SE_FASTPATH_IPH6_SRC_HIGH(p, r) \
  OCTEON_SE_GET_64BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH6_OFS_SRC, r)
#define OCTEON_SE_FASTPATH_IPH6_SRC_LOW(p, r) \
  OCTEON_SE_GET_64BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH6_OFS_SRC + 8, r)
#define OCTEON_SE_FASTPATH_IPH6_DST_HIGH(p, r) \
  OCTEON_SE_GET_64BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH6_OFS_DST, r)
#define OCTEON_SE_FASTPATH_IPH6_DST_LOW(p, r) \
  OCTEON_SE_GET_64BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH6_OFS_DST + 8, r)

/** IPv6 building */
#define OCTEON_SE_FASTPATH_IPH6_SET_VERSION(p, v) \
do \
  { \
    uint8_t _x; \
    OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_VERSION, _x);\
    _x = ((v) << 4) | (_x & 0x0f); \
    OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_VERSION, _x); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH6_SET_CLASS(p, v) \
do \
  { \
    uint16_t _x; \
    OCTEON_SE_GET_16BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_CLASS, _x);\
    _x = ((v) & 0x0ff0) | (_x & 0xf00f); \
    OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_CLASS, _x); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH6_SET_FLOW(p, v) \
do \
  { \
    uint32_t _x; \
    OCTEON_SE_GET_32BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_FLOW-1, _x);\
    _x = ((v) & 0x000fffff) | (_x & 0xfff00000); \
    OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_FLOW-1, _x);\
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH6_SET_LEN(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_LEN, v)
#define OCTEON_SE_FASTPATH_IPH6_SET_NH(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_NH, v)
#define OCTEON_SE_FASTPATH_IPH6_SET_HL(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_HL, v)
#define OCTEON_SE_FASTPATH_IPH6_SET_SRC_HIGH(p, v) \
  OCTEON_SE_PUT_64BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_SRC, v)
#define OCTEON_SE_FASTPATH_IPH6_SET_SRC_LOW(p, v) \
  OCTEON_SE_PUT_64BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_SRC + 8, v)
#define OCTEON_SE_FASTPATH_IPH6_SET_DST_HIGH(p, v) \
  OCTEON_SE_PUT_64BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_DST, v)
#define OCTEON_SE_FASTPATH_IPH6_SET_DST_LOW(p, v) \
  OCTEON_SE_PUT_64BIT((p) + OCTEON_SE_FASTPATH_IPH6_OFS_DST + 8, v)

#define OCTEON_SE_FASTPATH_IP6_EXT_FRAG_HDRLEN SSH_IP6_EXT_FRAGMENT_HDRLEN

#define OCTEON_SE_FASTPATH_IP6_EXT_FRAGMENT_OFS_NH \
                                SSH_IP6_EXT_FRAGMENT_OFS_NH
#define OCTEON_SE_FASTPATH_IP6_EXT_FRAGMENT_OFS_RESERVED1 \
                                SSH_IP6_EXT_FRAGMENT_OFS_RESERVED1
#define OCTEON_SE_FASTPATH_IP6_EXT_FRAGMENT_OFS_OFFSET \
                                SSH_IP6_EXT_FRAGMENT_OFS_OFFSET
#define OCTEON_SE_FASTPATH_IP6_EXT_FRAGMENT_OFS_ID \
                                SSH_IP6_EXT_FRAGMENT_OFS_ID


/** IPv4 */

#define OCTEON_SE_FASTPATH_IP4_HDRLEN 20

#define OCTEON_SE_FASTPATH_IPH4_OFS_VERSION SSH_IPH4_OFS_VERSION
#define OCTEON_SE_FASTPATH_IPH4_OFS_HLEN SSH_IPH4_OFS_HLEN
#define OCTEON_SE_FASTPATH_IPH4_OFS_TOS SSH_IPH4_OFS_TOS
#define OCTEON_SE_FASTPATH_IPH4_OFS_LEN SSH_IPH4_OFS_LEN
#define OCTEON_SE_FASTPATH_IPH4_OFS_ID SSH_IPH4_OFS_ID
#define OCTEON_SE_FASTPATH_IPH4_OFS_FRAGOFF SSH_IPH4_OFS_FRAGOFF
#define OCTEON_SE_FASTPATH_IPH4_OFS_TTL SSH_IPH4_OFS_TTL
#define OCTEON_SE_FASTPATH_IPH4_OFS_PROTO SSH_IPH4_OFS_PROTO
#define OCTEON_SE_FASTPATH_IPH4_OFS_CHECKSUM SSH_IPH4_OFS_CHECKSUM
#define OCTEON_SE_FASTPATH_IPH4_OFS_SRC SSH_IPH4_OFS_SRC
#define OCTEON_SE_FASTPATH_IPH4_OFS_DST SSH_IPH4_OFS_DST

/* Flags and offset mask for the fragoff field. */
#define OCTEON_SE_FASTPATH_IPH4_FRAGOFF_RF SSH_IPH4_FRAGOFF_RF
#define OCTEON_SE_FASTPATH_IPH4_FRAGOFF_DF SSH_IPH4_FRAGOFF_DF
#define OCTEON_SE_FASTPATH_IPH4_FRAGOFF_MF SSH_IPH4_FRAGOFF_MF
#define OCTEON_SE_FASTPATH_IP4_FRAG_MASK SSH_IPH4_FRAGOFF_OFFMASK


/** IPv4 parsing */
#define OCTEON_SE_FASTPATH_IPH4_VERSION(p, r) \
do \
  { \
    OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_VERSION, r); \
    (r) = ((r) >> 4); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH4_HLEN(p, r) \
do \
  { \
    OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_HLEN, r); \
    (r) = ((r) & 0x0f) * 4; \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH4_TOS(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_TOS, r)
#define OCTEON_SE_FASTPATH_IPH4_LEN(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH4_OFS_LEN, r)
#define OCTEON_SE_FASTPATH_IPH4_ID(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH4_OFS_ID, r)
#define OCTEON_SE_FASTPATH_IPH4_FRAG(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH4_OFS_FRAGOFF, r)
#define OCTEON_SE_FASTPATH_IPH4_TTL(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_TTL, r)
#define OCTEON_SE_FASTPATH_IPH4_PROTO(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_PROTO, r)
#define OCTEON_SE_FASTPATH_IPH4_CHECKSUM(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH4_OFS_CHECKSUM, r)
#define OCTEON_SE_FASTPATH_IPH4_SRC(p, r) \
  OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH4_OFS_SRC, r)
#define OCTEON_SE_FASTPATH_IPH4_DST(p, r) \
  OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_IPH4_OFS_DST, r)

/** IPv4 building */
#define OCTEON_SE_FASTPATH_IPH4_SET_VERSION(p, v) \
do \
  { \
    uint8_t _x; \
    OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_VERSION, _x);\
    _x = ((v) << 4) | (_x & 0x0f); \
    OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_VERSION, _x); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH4_SET_HLEN(p, v) \
do \
  { \
    uint8_t _x; \
    OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_HLEN, _x);\
    _x = ((v) & 0x0f) | (_x & 0xf0); \
    OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_HLEN, _x); \
  } \
while (0)
#define OCTEON_SE_FASTPATH_IPH4_SET_TOS(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_TOS, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_LEN(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_LEN, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_ID(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_ID, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_FRAG(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_FRAGOFF, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_TTL(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_TTL, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_PROTO(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_PROTO, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_CHECKSUM(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_CHECKSUM, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_SRC(p, v) \
  OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_SRC, v)
#define OCTEON_SE_FASTPATH_IPH4_SET_DST(p, v) \
  OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_IPH4_OFS_DST, v)


/** UDP */

#define OCTEON_SE_FASTPATH_UDP_HDRLEN 8

#define OCTEON_SE_FASTPATH_UDPH_OFS_SRCPORT SSH_UDPH_OFS_SRCPORT
#define OCTEON_SE_FASTPATH_UDPH_OFS_DSTPORT SSH_UDPH_OFS_DSTPORT
#define OCTEON_SE_FASTPATH_UDPH_OFS_LEN SSH_UDPH_OFS_LEN
#define OCTEON_SE_FASTPATH_UDPH_OFS_CHECKSUM SSH_UDPH_OFS_CHECKSUM

/** UDP parsing */
#define OCTEON_SE_FASTPATH_UDPH_SRCPORT(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_UDPH_OFS_SRCPORT, r)
#define OCTEON_SE_FASTPATH_UDPH_DSTPORT(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_UDPH_OFS_DSTPORT, r)
#define OCTEON_SE_FASTPATH_UDPH_LEN(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_UDPH_OFS_LEN, r)
#define OCTEON_SE_FASTPATH_UDPH_CHECKSUM(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_UDPH_OFS_CHECKSUM, r)

/** UDP building */
#define OCTEON_SE_FASTPATH_UDPH_SET_SRCPORT(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_UDPH_OFS_SRCPORT, v)
#define OCTEON_SE_FASTPATH_UDPH_SET_DSTPORT(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_UDPH_OFS_DSTPORT, v)
#define OCTEON_SE_FASTPATH_UDPH_SET_LEN(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_UDPH_OFS_LEN, v)
#define OCTEON_SE_FASTPATH_UDPH_SET_CHECKSUM(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_UDPH_OFS_CHECKSUM, v)


/** TCP */

#define OCTEON_SE_FASTPATH_TCP_HDRLEN 20

#define OCTEON_SE_FASTPATH_TCPH_OFS_SRCPORT SSH_TCPH_OFS_SRCPORT
#define OCTEON_SE_FASTPATH_TCPH_OFS_DSTPORT SSH_TCPH_OFS_DSTPORT

/** TCP parsing */
#define OCTEON_SE_FASTPATH_TCPH_SRCPORT(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_TCPH_OFS_SRCPORT, r)
#define OCTEON_SE_FASTPATH_TCPH_DSTPORT(p, r) \
  OCTEON_SE_GET_16BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_TCPH_OFS_DSTPORT, r)


/** ESP */

#define OCTEON_SE_FASTPATH_ESP_HDRLEN 8

#define OCTEON_SE_FASTPATH_ESPH_OFS_SPI SSH_ESPH_OFS_SPI
#define OCTEON_SE_FASTPATH_ESPH_OFS_SEQ SSH_ESPH_OFS_SEQ

/** ESP parsing */
#define OCTEON_SE_FASTPATH_ESPH_SPI(p, r) \
  OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_ESPH_OFS_SPI, r)
#define OCTEON_SE_FASTPATH_ESPH_SEQ(p, r) \
  OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_ESPH_OFS_SEQ, r)

/** ESP building */
#define OCTEON_SE_FASTPATH_ESPH_SET_SPI(p, v) \
  OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_ESPH_OFS_SPI, v)
#define OCTEON_SE_FASTPATH_ESPH_SET_SEQ(p, v) \
  OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_ESPH_OFS_SEQ, v)


/** AH */

#define OCTEON_SE_FASTPATH_AH_HDRLEN 12

#define OCTEON_SE_FASTPATH_AHH_OFS_NH SSH_AHH_OFS_NH
#define OCTEON_SE_FASTPATH_AHH_OFS_LEN SSH_AHH_OFS_LEN
#define OCTEON_SE_FASTPATH_AHH_OFS_RES (SSH_AHH_OFS_LEN + 1)
#define OCTEON_SE_FASTPATH_AHH_OFS_SPI SSH_AHH_OFS_SPI
#define OCTEON_SE_FASTPATH_AHH_OFS_SEQ SSH_AHH_OFS_SEQ

/** AH parsing */
#define OCTEON_SE_FASTPATH_AHH_NH(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_NH, r)
#define OCTEON_SE_FASTPATH_AHH_LEN(p, r) \
  OCTEON_SE_GET_8BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_LEN, r)
#define OCTEON_SE_FASTPATH_AHH_SPI(p, r) \
  OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_AHH_OFS_SPI, r)
#define OCTEON_SE_FASTPATH_AHH_SEQ(p, r) \
  OCTEON_SE_GET_32BIT_ALIGNED((p) + OCTEON_SE_FASTPATH_AHH_OFS_SEQ, r)

/** AH building */
#define OCTEON_SE_FASTPATH_AHH_SET_NH(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_NH, v)
#define OCTEON_SE_FASTPATH_AHH_SET_LEN(p, v) \
  OCTEON_SE_PUT_8BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_LEN, v)
#define OCTEON_SE_FASTPATH_AHH_SET_RESERVED(p, v) \
  OCTEON_SE_PUT_16BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_RES, v)
#define OCTEON_SE_FASTPATH_AHH_SET_SPI(p, v) \
  OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_SPI, v)
#define OCTEON_SE_FASTPATH_AHH_SET_SEQ(p, v) \
  OCTEON_SE_PUT_32BIT((p) + OCTEON_SE_FASTPATH_AHH_OFS_SEQ, v)

/** IP protocol values used on the SE fastpath */
#define OCTEON_SE_FASTPATH_IPPROTO_ICMP     SSH_IPPROTO_ICMP
#define OCTEON_SE_FASTPATH_IPPROTO_IPIP     SSH_IPPROTO_IPIP
#define OCTEON_SE_FASTPATH_IPPROTO_TCP      SSH_IPPROTO_TCP
#define OCTEON_SE_FASTPATH_IPPROTO_UDP      SSH_IPPROTO_UDP
#define OCTEON_SE_FASTPATH_IPPROTO_IPV6     SSH_IPPROTO_IPV6
#define OCTEON_SE_FASTPATH_IPPROTO_ESP      SSH_IPPROTO_ESP
#define OCTEON_SE_FASTPATH_IPPROTO_AH       SSH_IPPROTO_AH
#define OCTEON_SE_FASTPATH_IPPROTO_IPV6ICMP SSH_IPPROTO_IPV6ICMP
#define OCTEON_SE_FASTPATH_IPPROTO_IPV6FRAG SSH_IPPROTO_IPV6FRAG


/* The following macros define the minimum fragment length for ipv4 and v6
 * packets */
#define OCTEON_SE_FASTPATH_MIN_FIRST_FRAGMENT_V4  160
#define OCTEON_SE_FASTPATH_MIN_FIRST_FRAGMENT_V6  1280


/** Fragmentation context.  This is used to contain state while a packet
    is being fragmented. This does not handle any ip options since such
    packets are anyways passed to the slowpath */
typedef struct SeFastpathFragmentContextRec
{
  SeFastpathPacketContext pc;
  SeFastpathPacketBufferStruct original_pkt[1];
  uint32_t mtu;
  uint32_t offset;
  uint32_t total_len;
  uint16_t frag_hlen;
  uint16_t frag_data_len;
  union
  {
    struct
    {
      uint8_t df_on_first_fragment;
      uint8_t frag_hdr[OCTEON_SE_FASTPATH_IP4_HDRLEN];
    } ipv4;
    struct
    {
      /* Since we are not handling any extension headers, the fragmentation
         header would be inserted just after IPv6 Header. Hence we can
         keep a copy of the original header. */
      uint8_t frag_hdr[OCTEON_SE_FASTPATH_IP6_HDRLEN];
      uint32_t id;
    } ipv6;
  } u;
} SeFastpathFragmentContextStruct, *SeFastpathFragmentContext;

uint32_t octeon_se_fastpath_fragc_init(SeFastpathCoreContext core,
                                       SeFastpath fastpath,
                                       SeFastpathFragmentContext fragc,
                                       SeFastpathPacketContext pc,
                                       size_t mtu,
                                       uint8_t df_on_first_fragment);

SeFastpathPacketContext
octeon_se_fastpath_fragc_next(SeFastpathCoreContext core,
                              SeFastpath fastpath,
                              SeFastpathFragmentContext fragc);

void octeon_se_fastpath_fragc_uninit(SeFastpathCoreContext core,
                                     SeFastpath fastpath,
                                     SeFastpathFragmentContext fragc);

#endif /* OCTEON_SE_FASTPATH_INTERNAL_H */
