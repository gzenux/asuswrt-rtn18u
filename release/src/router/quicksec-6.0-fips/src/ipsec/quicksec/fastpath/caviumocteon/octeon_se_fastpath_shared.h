/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file includes internal defines for SE and accelerated
   SW fastpath.
*/

#ifndef OCTEON_SE_FASTPATH_SHARED_H
#define OCTEON_SE_FASTPATH_SHARED_H 1

#include "cvmx-config.h"
#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-rwlock.h"

#include "sshincludes.h"
#include "ipsec_params.h"

#include "octeon_se_fastpath_params.h"

/** Bootmem block name */
#define OCTEON_SE_FASTPATH_BOOTMEM_BLOCK "quicksec_se_fastpath"

/** POW groups */
#define OCTEON_SE_FASTPATH_PKT_GROUP      1   /* Inbound packet processing */
#define OCTEON_SE_FASTPATH_SLOWPATH_GROUP 2   /* Exception packet processing */
#define OCTEON_SE_FASTPATH_DESCHED_GROUP  3   /* Descheduled wqe processing */
#define OCTEON_SE_FASTPATH_CONTROL_GROUP  4   /* Control wqe processing */
#define OCTEON_SE_FASTPATH_CONTROL_GROUP1 5   /* Control wqe processing */


/** POW queues */

/* Queues for passing packets to/from slowpath. */
#define OCTEON_SE_FASTPATH_HIGH_PRIO_QUEUE 0
#define OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MIN 1
#define OCTEON_SE_FASTPATH_NORMAL_PRIO_QUEUE_MAX 6

/* Queue for packets from IPD/PIP. */
#define OCTEON_SE_FASTPATH_INPUT_QUEUE 7

/** FAU register for engine run time */
#define OCTEON_SE_FASTPATH_FAU_RUNTIME \
  ((cvmx_fau_reg_32_t)(CVMX_FAU_REG_AVAIL_BASE + 0))

/** Control commands */
#define OCTEON_SE_FASTPATH_CONTROL_CMD_ENABLE  1
#define OCTEON_SE_FASTPATH_CONTROL_CMD_DISABLE 2
#define OCTEON_SE_FASTPATH_CONTROL_CMD_STOP    3
#define OCTEON_SE_FASTPATH_CONTROL_CMD_SLOW    4

typedef struct SeFastpathControlCmdRec
{
  uint8_t cmd;

  uint8_t unused8;
  uint16_t unused16;

  uint32_t tunnel_id;
  uint32_t prev_transform_index;
} SeFastpathControlCmdStruct, *SeFastpathControlCmd;


/** Reserved values for invalid index and port */
#define OCTEON_SE_FASTPATH_INVALID_INDEX 0xddffffff
#define OCTEON_SE_FASTPATH_INVALID_PORT  0xfe


/** Flow ID */
/** Flag values for flow ID */
#define OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IP6            0x01
#define OCTEON_SE_FASTPATH_FLOW_ID_FLAG_FROMADAPTER    0x02
#define OCTEON_SE_FASTPATH_FLOW_ID_FLAG_DHCP           0x04
#define OCTEON_SE_FASTPATH_FLOW_ID_FLAG_IPSEC_INCOMING 0x08

typedef struct SeFastpathFlowIdRec
{
  /* word 0 */
  uint32_t hash_id;
  uint32_t tunnel_id;

  /* word 1 */
  uint32_t protocol_xid_high;
  uint16_t protocol_xid_low;
  uint8_t ipproto;
  uint8_t flags;
} SeFastpathFlowIdStruct, *SeFastpathFlowId;

typedef union
{
  SeFastpathFlowIdStruct id;
  uint64_t raw[2];
} SeFastpathFlowIdUnion;

/** Flow ID hash table */
typedef struct SeFastpathFlowIdHashRec
{
  /* word 0 */
  cvmx_rwlock_wp_lock_t *lock;

  /* word 1 */
  uint32_t fwd_flow_index;
  uint32_t rev_flow_index;
} SeFastpathFlowIdHashStruct, *SeFastpathFlowIdHash;

typedef union
{
  cvmx_rwlock_wp_lock_t lock;
  uint64_t pad[2];
} SeFastpathFlowIdHashLockUnion;


/** Flow data object */
#define OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS

#ifdef OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS
typedef union
{
  uint64_t pad;
  cvmx_spinlock_t l;
} SeFastpathFlowLockUnion;
#else /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */
typedef union
{
  uint64_t pad[2];
  cvmx_rwlock_wp_lock_t l;
} SeFastpathFlowLockUnion;
#endif /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */

#define OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS 1

typedef struct SeFastpathFlowDataRec
{
  /* Word 1 */
  /** Flow lock, 1 or 2 words. */
  SeFastpathFlowLockUnion lock;

  /* Word 2-5 */
  /** Flow IDs */
  SeFastpathFlowIdUnion fwd_flow_id;
  SeFastpathFlowIdUnion rev_flow_id;

  /* Word 6-9 */
  /** IP addresses, IPv4 uses only low bits */
  uint64_t src_ip_high;
  uint64_t src_ip_low;
  uint64_t dst_ip_high;
  uint64_t dst_ip_low;

  /* Word 10 */
  /** Ports and upper protocol identifiers */
  uint16_t src_port;
  uint16_t dst_port;

  union
  {
    uint32_t spi;
    uint32_t protocol_xid;
    struct
    {
      uint8_t code;
      uint8_t type;
      uint16_t id;
    } icmp;
  } u;

  /* Word 11 */
  uint8_t ipproto;
  uint8_t fwd_iport;
  uint8_t rev_iport;
  uint8_t generation;
  uint32_t tunnel_id;

  /* Word 12 */
  uint32_t last_packet_time;
  uint32_t flow_lru_level;

  /* Word 13 */
  /** Flow flags */
  uint16_t flag_invalid : 1;        /** Flow state is invalid */
  uint16_t flag_in_use : 1;         /** Flow is in use */
  uint16_t flag_slow : 1;           /** Process always on slowpath */
  uint16_t flag_ip_version_6 : 1;   /** 0 = IPv4, 1 = IPv6 */
  uint16_t flag_ignore_iport : 1;   /** _FLOW_D_IGNORE_IFNUM */
  uint16_t flag_ipsec_incoming : 1; /** _FLOW_D_IPSEC_INCOMING */

  uint16_t in_fwd_hash : 1; /** Protected by flow id hash bucket lock. */
  uint16_t in_rev_hash : 1; /** Protected by flow id hash bucket lock. */

  uint16_t unused_flags : 8;

  uint16_t padding16;

  uint32_t fwd_nh_index;

  /* Word 14-16 */
  uint32_t rev_nh_index;
  uint32_t fwd_transform_index;

  uint32_t rev_transform_index;
  uint32_t fwd_rx_transform_index[OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS];

  uint32_t rev_rx_transform_index[OCTEON_SE_FASTPATH_NUM_RX_TRANSFORMS];
  uint32_t upper_flags; /* Upper layer flags. Not used by SE fastpath */

  /* Word 17 */
  uint32_t fwd_flow_index_next; /** Protected by flow id hash bucket lock. */
  uint32_t rev_flow_index_next; /** Protected by flow id hash bucket lock. */

  /* Word 18-22 */
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  /** Statistics */
  uint64_t fwd_octets;
  uint64_t rev_octets;
  uint64_t fwd_packets;
  uint64_t rev_packets;
  uint64_t dropped_packets;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

} SeFastpathFlowDataStruct, *SeFastpathFlowData;

typedef union
{
  /** Pad to multiple of cache line size */
  uint64_t padding[32];
  SeFastpathFlowDataStruct s;
} SeFastpathFlowDataUnion;


/** Transform data object */

#define OCTEON_MAX_ESP_KEY_BITS SSH_IPSEC_MAX_ESP_KEY_BITS
#define OCTEON_MAX_MAC_KEY_BITS SSH_IPSEC_MAX_MAC_KEY_BITS

/** Max 200B (= 25 words) */
#define OCTEON_MAX_KEYMAT_LEN \
  ((2 * (OCTEON_MAX_ESP_KEY_BITS + OCTEON_MAX_MAC_KEY_BITS)) / 8)

#define OCTEON_FASTPATH_REPLAY_WINDOW_WORDS (SSH_ENGINE_REPLAY_WINDOW_WORDS/2)
#define OCTEON_FASTPATH_REPLAY_WINDOW_BITS  64


/** Macros for denting transform properties */
#define OCTEON_SE_FASTPATH_CRYPT_NULL       0x00000004 /** Allow no encryption.
                                                        */
#define OCTEON_SE_FASTPATH_CRYPT_DES        0x00000008 /** 56 bit key. */
#define OCTEON_SE_FASTPATH_CRYPT_3DES       0x00000010 /** 168 bit key. */
#define OCTEON_SE_FASTPATH_CRYPT_AES        0x00000020 /** 128 bit key. */
#define OCTEON_SE_FASTPATH_CRYPT_AES_CTR    0x00000040 /** AES counter mode,
                                                           128 bit key. */
#define OCTEON_SE_FASTPATH_CRYPT_AES_GCM    0x00000080 /** AES GCM mode,
                                                           128 bit key,
                                                           128 bit digest. */
#define OCTEON_SE_FASTPATH_CRYPT_AES_GCM_8  0x10000000 /** AES GCM mode,
                                                           128 bit key,
                                                           64 bit digest. */
/* Bit mask of supported ciphers. */
#define OCTEON_SE_FASTPATH_CRYPT_MASK       0x100000fc

/* Bit masks for MAC and hash algorithms. */
#define OCTEON_SE_FASTPATH_MAC_HMAC_MD5     0x00000400 /** 128 bit key. */
#define OCTEON_SE_FASTPATH_MAC_HMAC_SHA1    0x00000800 /** 160 bit key. */
#define OCTEON_SE_FASTPATH_MAC_HMAC_SHA2    0x00002000 /** 256-512 bit key.*/

/* Bit mask of supported HMACs. */
#define OCTEON_SE_FASTPATH_MAC_MASK         0x00002c00

/* Bit mask for IPsec transforms */
#define OCTEON_SE_FASTPATH_IPSEC_ESP        0x00040000 /** Perform ESP. */
#define OCTEON_SE_FASTPATH_IPSEC_IPCOMP     0x00080000 /** Perform IPPCP. */
#define OCTEON_SE_FASTPATH_IPSEC_AH         0x00100000 /** Perform AH. */
#define OCTEON_SE_FASTPATH_IPSEC_MASK       0x003c0000 /** Mask for transforms.
                                                        */


/*  Additional transforms / transforms options. */
#define OCTEON_SE_FASTPATH_IPSEC_ANTIREPLAY 0x01000000 /* enable anti-replay.*/
#define OCTEON_SE_FASTPATH_IPSEC_NATT       0x04000000 /* NAT-T UDP encap. */
#define OCTEON_SE_FASTPATH_IPSEC_LONGSEQ    0x20000000 /* Use 64 bit
                                                          sequence number. */

#define OCTEON_SE_FASTPATH_DF_KEEP 0
#define OCTEON_SE_FASTPATH_DF_SET  1
#define OCTEON_SE_FASTPATH_DF_CLEAR 2


typedef struct SeFastpathTransformDataRec
{
  /* word 1-4 */

  /** Peer IP address, IPv4 uses only low bits */
  uint64_t gw_addr_high;
  uint64_t gw_addr_low;

  /** Own IP address, IPv4 uses only low bits */
  uint64_t own_addr_high;
  uint64_t own_addr_low;

  /* word 5 */
  /* Transform description */
  uint32_t transform;

  uint32_t inbound_tunnel_id;

  /* word 6 */
  uint32_t spi_out;
  uint32_t spi_in;

  /* word 7 */
  uint8_t port;
  uint8_t packet_enlargement;
  uint8_t nh;

  uint8_t cipher_key_size;
  uint8_t cipher_iv_size;
  uint8_t cipher_nonce_size;
  uint8_t mac_key_size;

  uint8_t ip_version_6 : 1; /* 0 = IPv4, 1 = IPv6 */
  uint8_t tunnel_mode : 1;
  uint8_t df_bit_processing : 2;
  uint8_t is_special: 1;
  uint8_t unused_flags : 3;

  /* word 8  Packet counter for outbound traffic */
  uint64_t seq;

  /* word 9 */
  uint32_t last_in_packet_time;
  uint32_t last_out_packet_time;

  /* word 10 */
  uint32_t old_spi_in;
  uint32_t old_spi_out;

  /* word 11-12 */
  /** Trd lock */
  cvmx_rwlock_wp_lock_t lock[1];

  /* Word 13 */
  uint64_t replay_offset;

  /* Word 14 */
  uint16_t natt_local_port;
  uint16_t natt_remote_port;
  uint16_t natt_flags;
  uint16_t pmtu_received;

  /* This will go into next cache line */
  /** Key material */
  /* Word 15-22 */
  uint8_t keymat[OCTEON_MAX_KEYMAT_LEN];
  /* Word 23 - 39 This goes into third cache line*/

  /* Word 40-41 */
  uint64_t replay_mask[OCTEON_FASTPATH_REPLAY_WINDOW_WORDS];

  /* word 42-47 */
#ifdef OCTEON_SE_FASTPATH_STATISTICS
  /** Statistics */
  uint64_t in_octets;
  uint64_t out_octets;
  uint64_t in_packets;
  uint64_t out_packets;
  uint64_t drop_packets;
  uint64_t num_mac_fails;
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

  /* Information before rekey. This is in fourth cache line. */
  /* Work 48 */
  uint64_t old_replay_offset;

 /* Word 49-50 */
  uint64_t old_replay_mask[OCTEON_FASTPATH_REPLAY_WINDOW_WORDS];

/* Word 51 */
  cvmx_spinlock_t replay_lock[1];

  /* Word 52-64 */
  uint8_t old_keymat[OCTEON_MAX_KEYMAT_LEN / 2];
} SeFastpathTransformDataStruct, *SeFastpathTransformData;

/* Calculate padding length. */
#ifdef OCTEON_SE_FASTPATH_STATISTICS
#define OCTEON_SE_FASTPATH_TRD_SIZE \
  (22 * 8 + OCTEON_MAX_KEYMAT_LEN + OCTEON_MAX_KEYMAT_LEN / 2 \
   + 2 * OCTEON_FASTPATH_REPLAY_WINDOW_WORDS * 8)
#else /* OCTEON_SE_FASTPATH_STATISTICS */
#define OCTEON_SE_FASTPATH_TRD_SIZE \
  (16 * 8 + OCTEON_MAX_KEYMAT_LEN + OCTEON_MAX_KEYMAT_LEN / 2 \
   + 2 * OCTEON_FASTPATH_REPLAY_WINDOW_WORDS * 8)
#endif /* OCTEON_SE_FASTPATH_STATISTICS */

#if (OCTEON_SE_FASTPATH_TRD_SIZE <= 512)
#define OCTEON_SE_FASTPATH_TRD_CACHE_LINES 4

#elif (OCTEON_SE_FASTPATH_TRD_SIZE <= 640)
#define OCTEON_SE_FASTPATH_TRD_CACHE_LINES 5

#else
#error "Size of SeFastpathTransformDataStruct is too big!"
#endif

typedef union
{
  /** Pad to multiple of cache line size */
  uint64_t padding[OCTEON_SE_FASTPATH_TRD_CACHE_LINES * 16];
  SeFastpathTransformDataStruct s;
} SeFastpathTransformDataUnion;

/** NextHop data object */
#define OCTEON_SE_FASTPATH_MEDIA_HDR_SIZE 14
typedef struct SeFastpathNextHopDataRec
{
  /* word 1 */
  uint16_t mtu;
  uint16_t min_packet_len;
  uint8_t port;
  uint8_t media_hdrlen;

  /** Next Hop flags */
  uint16_t flag_slow : 1;     /* Process always on slowpath. */

  uint16_t unused_flags : 15;

  /* word 2-3 */
  union
  {
    uint64_t raw[2];
    uint8_t data[OCTEON_SE_FASTPATH_MEDIA_HDR_SIZE];
  } media_hdr;

  /* word 4-5 */
  /** NextHop lock */
  cvmx_rwlock_wp_lock_t lock[1];

} SeFastpathNextHopDataStruct, *SeFastpathNextHopData;

typedef union
{
  /** Pad so that even number of nexthops fits to one cache line */
  uint64_t padding[8];
  SeFastpathNextHopDataStruct s;
} SeFastpathNextHopDataUnion;

/** Per core statistics */
typedef struct SeFastpathCoreStatsRec
{
  uint64_t pkt_rx;
  uint64_t pkt_tx;
  uint64_t pkt_drop;
  uint64_t pkt_slow;
  uint64_t pkt_desched;
  uint64_t pkt_resched;
} SeFastpathCoreStatsStruct, *SeFastpathCoreStats;

typedef union
{
  uint64_t padding[16];
  SeFastpathCoreStatsStruct s;
} SeFastpathCoreStatsUnion;

/** Shared fastpath object */

#define OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE SSH_ENGINE_FLOW_TABLE_SIZE
#define OCTEON_SE_FASTPATH_TRD_TABLE_SIZE SSH_ENGINE_TRANSFORM_TABLE_SIZE
#define OCTEON_SE_FASTPATH_NH_TABLE_SIZE SSH_ENGINE_NEXT_HOP_HASH_SIZE
#define OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE SSH_ENGINE_FLOW_ID_HASH_SIZE

#define OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS \
  ((OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE / 16) + 1)
#if ((OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS) < CVMX_MAX_CORES)
#undef OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS
#define OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS CVMX_MAX_CORES
#endif


/* Default to 1 Octeon cpu. */
#ifndef OCTEON_SE_FASTPATH_MAX_NUM_CPUS
#define OCTEON_SE_FASTPATH_MAX_NUM_CPUS 1
#endif /* OCTEON_SE_FASTPATH_MAX_NUM_CPUS */

typedef struct SeFastpathRec
{
  /** Local IKE NAT-T UDP port */
  uint16_t local_ike_natt_port;
  uint16_t unused16;
  uint32_t salt;

  /** Flow hash table */
  SeFastpathFlowIdHashStruct
  flow_id_hash[OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE];

  SeFastpathFlowIdHashLockUnion
  flow_hash_lock[OCTEON_SE_FASTPATH_NUM_FLOW_HASH_LOCKS];

  /** Flow object table */
  SeFastpathFlowDataUnion flow_table[OCTEON_SE_FASTPATH_FLOW_TABLE_SIZE];

  /** Transform object table */
  SeFastpathTransformDataUnion trd_table[OCTEON_SE_FASTPATH_TRD_TABLE_SIZE];

  /** NextHop object table */
  SeFastpathNextHopDataUnion nh_table[OCTEON_SE_FASTPATH_NH_TABLE_SIZE];

  SeFastpathCoreStatsUnion core_stats[(CVMX_MAX_CORES *
                                       OCTEON_SE_FASTPATH_MAX_NUM_CPUS)];
} SeFastpathStruct, *SeFastpath;


/** Flow table access */
#define OCTEON_SE_FASTPATH_FLOW(fastpath, flow_index) \
  (&(fastpath)->flow_table[(flow_index)].s)
#define OCTEON_SE_FASTPATH_FLOW_INDEX(fastpath, se_flow)             \
  ((se_flow) == NULL ?                                               \
   OCTEON_SE_FASTPATH_INVALID_INDEX :                                \
   (((SeFastpathFlowDataUnion *)(se_flow)) - (fastpath)->flow_table))
#define OCTEON_SE_FASTPATH_PREFETCH_FLOW(se_flow) \
do \
  { \
    CVMX_PREFETCH(se_flow, 0); \
    CVMX_PREFETCH(se_flow, 128); \
  } \
while (0)


/** Trd table access */
#define OCTEON_SE_FASTPATH_TRD(fastpath, trd_index) \
  (&(fastpath)->trd_table[(trd_index)].s)
#define OCTEON_SE_FASTPATH_TRD_INDEX(fastpath, se_trd)                  \
  ((se_trd) == NULL ?                                                   \
   OCTEON_SE_FASTPATH_INVALID_INDEX :                                   \
   (((SeFastpathTransformDataUnion *)(se_trd)) - (fastpath)->trd_table))

#if OCTEON_SE_FASTPATH_TRD_CACHE_LINES == 4
#define OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd) \
do \
  { \
    CVMX_PREFETCH(se_trd, 0); \
    CVMX_PREFETCH(se_trd, 128); \
    CVMX_PREFETCH(se_trd, 256); \
    CVMX_PREFETCH(se_trd, 384); \
  } \
while (0)
#else /* OCTEON_SE_FASTPATH_TRD_CACHE_LINES == 4 */
#define OCTEON_SE_FASTPATH_PREFETCH_TRD(se_trd) \
do \
  { \
    CVMX_PREFETCH(se_trd, 0); \
    CVMX_PREFETCH(se_trd, 128); \
    CVMX_PREFETCH(se_trd, 256); \
    CVMX_PREFETCH(se_trd, 384); \
    CVMX_PREFETCH(se_trd, 512); \
  } \
while (0)
#endif /* OCTEON_SE_FASTPATH_TRD_CACHE_LINES == 4 */


/** NextHop table access */
#define OCTEON_SE_FASTPATH_NH(fastpath, nh_index) \
  (&(fastpath)->nh_table[(nh_index)].s)
#define OCTEON_SE_FASTPATH_NH_INDEX(fastpath, se_nh)               \
  ((se_nh) == NULL ?                                               \
   OCTEON_SE_FASTPATH_INVALID_INDEX :                              \
   (((SeFastpathNextHopDataUnion *)(se_nh)) - (fastpath)->nh_table))
#define OCTEON_SE_FASTPATH_PREFETCH_NH(se_nh) CVMX_PREFETCH0((se_nh))


/** Flow hashtable locking macros */
#define OCTEON_SE_FASTPATH_FLOW_HASH_BUCKET(fastpath, hash_id) \
  ((hash_id) % OCTEON_SE_FASTPATH_FLOW_ID_HASH_SIZE)

#define OCTEON_SE_FASTPATH_FLOW_HASH_READ_LOCK(fastpath, bucket) \
  cvmx_rwlock_wp_read_lock((fastpath)->flow_id_hash[(bucket)].lock)
#define OCTEON_SE_FASTPATH_FLOW_HASH_READ_UNLOCK(fastpath, bucket) \
  cvmx_rwlock_wp_read_unlock((fastpath)->flow_id_hash[(bucket)].lock)
#define OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_LOCK(fastpath, bucket) \
  cvmx_rwlock_wp_write_lock((fastpath)->flow_id_hash[(bucket)].lock)
#define OCTEON_SE_FASTPATH_FLOW_HASH_WRITE_UNLOCK(fastpath, bucket) \
  cvmx_rwlock_wp_write_unlock((fastpath)->flow_id_hash[(bucket)].lock)


/** Flow object locking macros */
#ifdef OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS

/** Spinlock implementation */
#define OCTEON_SE_FASTPATH_FLOW_LOCK_INIT(lock) \
  cvmx_spinlock_init(&(lock).l)
#define OCTEON_SE_FASTPATH_FLOW_READ_LOCK(fastpath, flow_index, se_flow) \
  cvmx_spinlock_lock(&(se_flow)->lock.l)
#define OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, flow_index, se_flow) \
  cvmx_spinlock_unlock(&(se_flow)->lock.l)
#define OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, flow_index, se_flow) \
  cvmx_spinlock_lock(&(se_flow)->lock.l)
#define OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, flow_index, se_flow) \
  cvmx_spinlock_unlock(&(se_flow)->lock.l)

#else /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */

/** RWlock implementation */
#define OCTEON_SE_FASTPATH_FLOW_LOCK_INIT(lock) \
  cvmx_rwlock_wp_init(&(lock).l)
#define OCTEON_SE_FASTPATH_FLOW_READ_LOCK(fastpath, flow_index, se_flow) \
  cvmx_rwlock_wp_read_lock(&(se_flow)->lock.l)
#define OCTEON_SE_FASTPATH_FLOW_READ_UNLOCK(fastpath, flow_index, se_flow) \
  cvmx_rwlock_wp_read_unlock(&(se_flow)->lock.l)
#define OCTEON_SE_FASTPATH_FLOW_WRITE_LOCK(fastpath, flow_index, se_flow) \
  cvmx_rwlock_wp_write_lock(&(se_flow)->lock.l)
#define OCTEON_SE_FASTPATH_FLOW_WRITE_UNLOCK(fastpath, flow_index, se_flow) \
  cvmx_rwlock_wp_write_unlock(&(se_flow)->lock.l)

#endif /* OCTEON_SE_FASTPATH_USE_SPINLOCK_FOR_FLOWS */


/** Transform object locking macros */
#define OCTEON_SE_FASTPATH_TRD_READ_LOCK(fastpath, trd_index, se_trd) \
  cvmx_rwlock_wp_read_lock((se_trd)->lock)
#define OCTEON_SE_FASTPATH_TRD_READ_UNLOCK(fastpath, trd_index, se_trd) \
  cvmx_rwlock_wp_read_unlock((se_trd)->lock)
#define OCTEON_SE_FASTPATH_TRD_WRITE_LOCK(fastpath, trd_index, se_trd) \
  cvmx_rwlock_wp_write_lock((se_trd)->lock)
#define OCTEON_SE_FASTPATH_TRD_WRITE_UNLOCK(fastpath, trd_index, se_trd) \
  cvmx_rwlock_wp_write_unlock((se_trd)->lock)

/** Transform replay information lockstat */
#define OCTEON_SE_FASTPATH_TRD_REPLAY_LOCK_INIT(se_trd) \
  cvmx_spinlock_init((se_trd)->replay_lock)
#define OCTEON_SE_FASTPATH_TRD_REPLAY_LOCK(se_trd) \
  cvmx_spinlock_lock((se_trd)->replay_lock)
#define OCTEON_SE_FASTPATH_TRD_REPLAY_UNLOCK(se_trd) \
  cvmx_spinlock_unlock((se_trd)->replay_lock)

/** NextHop object locking macros */
#define OCTEON_SE_FASTPATH_NH_READ_LOCK(fastpath, nh_index, se_nh) \
  cvmx_rwlock_wp_read_lock((se_nh)->lock)
#define OCTEON_SE_FASTPATH_NH_READ_UNLOCK(fastpath, nh_index, se_nh) \
  cvmx_rwlock_wp_read_unlock((se_nh)->lock)
#define OCTEON_SE_FASTPATH_NH_WRITE_LOCK(fastpath, nh_index, se_nh) \
  cvmx_rwlock_wp_write_lock((se_nh)->lock)
#define OCTEON_SE_FASTPATH_NH_WRITE_UNLOCK(fastpath, nh_index, se_nh) \
  cvmx_rwlock_wp_write_unlock((se_nh)->lock)


/** Flow id calculation */
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
                                uint64_t dst_ip_low);


/** Flow lookup.
    Lookup a matching flow from flow table. The fields `flow_id',
    `src_ip_*' and `dst_ip_*' are used for matching flows. The value of
    parameter `flags' controls whether the flow lookup should return
    immediately if the matching flow is locked or in invalid state.
    This function sets the value of `flags' to indicate flow lookup
    result. */
#define OCTEON_SE_FASTPATH_FLOW_LOOKUP_FLAG_FORWARD          0x01

SeFastpathFlowData
octeon_se_fastpath_lookup_flow(SeFastpath fastpath,
                               SeFastpathFlowIdUnion *flow_id,
                               uint64_t src_ip_high,
                               uint64_t src_ip_low,
                               uint64_t dst_ip_high,
                               uint64_t dst_ip_low,
                               uint64_t iport,
                               uint8_t *flags);

#endif /* OCTEON_SE_FASTPATH_SHARED_H */
