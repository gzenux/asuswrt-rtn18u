/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Shared definitions between the QuickSec Engine and Policy Manager.

   <keywords definition/shared, shared definition>
*/

#ifndef CORE_PM_SHARED_H
#define CORE_PM_SHARED_H

/*--------------------------------------------------------------------*/
/* Data types                                                         */
/*--------------------------------------------------------------------*/

/** Data type for Policy Manager. Typically there is only one
    Policy Manager object in a system. The internals of the data
    type are private and should not be accessed directly.

    @see SshPmTunnel
    @see SshPmService
    @see SshPmRule
    @see ssh_pm_create
    @see ssh_pm_destroy
    @see ssh_pm_set_kernel_debug_level
    @see ssh_pm_get_number_of_interfaces
    @see ssh_pm_set_default_ike_algorithms
    @see ssh_pm_set_ldap_servers
    @see ssh_pm_get_externalkey
    @see ssh_pm_set_externalkey_notify_callback
    @see ssh_pm_add_cert
    @see ssh_pm_add_crl
    @see ssh_pm_set_interface_nat
    @see ssh_pm_rule_add
    @see ssh_pm_rule_delete
    @see ssh_pm_commit
    @see ssh_pm_abort

  */

typedef struct SshPmRec *SshPm;


/*--------------------------------------------------------------------*/
/* Engine parameters                                                  */
/*--------------------------------------------------------------------*/

/** Different policies for fragment handling.

    @see SshEngineParamsStruct
    @see ssh_pm_set_engine_params

 */
typedef enum
{
  /** Invalid magic value - no fragment handling policy has been set. */
  SSH_IPSEC_FRAGS_INVALID_POLICY = 0,

  /** No specified policy - this value describes a policy of forwarding
      fragments as fast as possible; as little sanity checking as
      allowed by Engine is performed; this is the recommended
      setting for a router system that does NOT intend to do
      firewalling. */
  SSH_IPSEC_FRAGS_NO_POLICY = 1,

  /** Disallow all fragments - all fragmented packets are discarded. */
  SSH_IPSEC_FRAGS_NO_FRAGS = 2,

  /** Loose monitoring of fragments - this means that fragments
      are forwarded in order and without overlap; if the fragments
      arrive out-of-order then these fragments will be buffered until
      they are discarded or forwarded; this is the recommended setting
      for a firewall system. */

  SSH_IPSEC_FRAGS_LOOSE_MONITOR = 3,

  /** Strict monitoring - all fragments are collected and buffered
      before forwarding; packets may be reassembled because of
      this. */
  SSH_IPSEC_FRAGS_STRICT_MONITOR = 4
} SshEngineFragmentPolicy;


/** Operating parameters for Engine, set via the
    ssh_pm_set_engine_params function; for default values to be set,
    memset() this structure to 0; any field that is 0 or its
    appropriate flag value "[name]_set" (if such exists) is 0, will
    have a default value used in its place.

    @see ssh_pm_set_engine_params

*/
struct SshEngineParamsRec
{
  /** A boolean flag describing whether time-to-live (TTL) values of
      IP packets should be decremented - if set, TTL values are not
      decremented. */
  Boolean do_not_decrement_ttl;

  /** A boolean flag describing whether corrupted packets should be
      audited with the ssh_audit_event function - if set, corrupt
      packets cause audit events. */
  Boolean audit_corrupt;

  /** A boolean flag describing whether packets should be dropped if the
      packet has generated an auditable event which cannot be audited
      (due to lack of resources in the auditing framework). */
  Boolean drop_if_cannot_audit;

  /** broadcast_icmp flag is to drop all the icmp broadcast packet;
      by default it should not allow forwarding of ICMP broadcast
      packets. */
  Boolean broadcast_icmp;

  /** If this is set to TRUE, then the interface network addresses
      will be considered when making routing decisions prior to the
      routing table. */
  Boolean optimize_routing;

  /** The minimum value required for a time-to-live (TTL) field in an
      IP header. */
  SshUInt32 min_ttl_value;

  /** Rate limit for all audit events, expressed as events/second;
      Engine can rate limit audit event generation - audit events
      have the following rate limits defined for them:

      - all generated audit events.

      */
  SshUInt32 audit_total_rate_limit;

  /** Engine can rate limit flow creation, flow create rate
      limitation is done for "slots" in a hash table

      Rate limitation of flow creates is keyed by the source network
      address (upper 24 bits for IPv4, upper 64 bits for IPv6); this
      field specifies the maximum amount of flow creates a single key
      in the flow rate limitation table is allowed to own without it
      ever being considered for rate limitation

      The rate limitation is controlled by the following parameters:

      - allow_threshold: If this threshold is not exceeded by a slot,
      then rate limitation is never triggered

      - limit_threshold: This is a percentage limit of the max
      flows; if more than this threshold of the max flows are in use,
      then the next parameter will be used, otherwise it will be
      inactive

      - max_share: The total amount of flow creates in percentages a
      single slot is allowed to have of all flow creates; if this
      value is exceeded, then flow creation will be rejected

      Each flow create increases the value of a slot; these values
      are decremented by 10% each second

       */
  SshUInt32 flow_rate_allow_threshold;

  /** Rate limitation expressed in percentage; if more than this
      threshold of max flows are in use, then the rate limitation
      below will be used. */
  SshUInt32 flow_rate_limit_threshold;

  /** The number of flow creates over the total requested that is
      allowed from a single hash slot. */
  SshUInt32 flow_rate_max_share;

  /* Idle timeout for IPSec transforms: after this number of seconds
     a idle event for that transform will be sent to Policy Manager if
     DPP is enabled for that transform; this event will trigger a DPD
     negotiation at Policy Manager. */
  SshUInt32 transform_dpd_timeout;

  /** Fragmentation handling policy. */
  SshEngineFragmentPolicy fragmentation_policy;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /** How often (in seconds) NAT-T keepalives (NAT-mapping keepalives)
      are sent. */
  SshUInt32 natt_keepalive_interval;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
};

typedef struct SshEngineParamsRec SshEngineParamsStruct;
typedef struct SshEngineParamsRec *SshEngineParams;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/* Default parameters for Engine */
#define ENGINE_DEFAULT_PARAMETERS \
{                                 \
  FALSE,                          \
  TRUE,                           \
  FALSE,                          \
  TRUE,                           \
  FALSE,                          \
  1,                              \
  SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS,  \
  SSH_ENGINE_FLOW_RATE_ALLOW_THRESHOLD, \
  SSH_ENGINE_FLOW_RATE_LIMIT_THRESHOLD, \
  SSH_ENGINE_FLOW_RATE_MAX_SHARE,       \
  15,                                   \
  SSH_IPSEC_DEFAULT_FRAG_POLICY,        \
  SSH_IPSEC_NATT_KEEPALIVE_INTERVAL     \
}
#else /* SSHDIST_IPSEC_NAT_TRAVERSAL */

/* Default parameters for Engine */
#define ENGINE_DEFAULT_PARAMETERS \
{                                 \
  FALSE,                          \
  TRUE,                           \
  FALSE,                          \
  TRUE,                           \
  FALSE,                          \
  1,                              \
  SSH_ENGINE_MAX_PENDING_AUDIT_EVENTS,  \
  SSH_ENGINE_FLOW_RATE_ALLOW_THRESHOLD, \
  SSH_ENGINE_FLOW_RATE_LIMIT_THRESHOLD, \
  SSH_ENGINE_FLOW_RATE_MAX_SHARE,       \
  15,                                   \
  SSH_IPSEC_DEFAULT_FRAG_POLICY         \
}
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */


#ifdef SSHDIST_IPSEC_NAT
/*--------------------------------------------------------------------*/
/* Parameters for NAT transform                                       */
/*--------------------------------------------------------------------*/

/* NAT type. */
typedef enum
{
  /** Don't do NAT. */
  SSH_PM_NAT_TYPE_NONE,
  /** Do port NAT and static NAT. */
  SSH_PM_NAT_TYPE_PORT,
  /** Direct 1-to-1 host NAT. */
  SSH_PM_NAT_TYPE_HOST_DIRECT
} SshPmNatType;

/* For convenience. */
#define SSH_PM_NAT_FLAGS_EMPTY                   0x0000
/** Perform NAT also for IPv6 addresses. */
#define SSH_PM_INTERFACE_NAT_IPV6                0x0001
/** Do not attempt to keep original SRC port. */
#define SSH_PM_NAT_NO_TRY_KEEP_PORT              0x0002
/** Keep original SRC port or fail. */
#define SSH_PM_NAT_KEEP_PORT                     0x0004
/** Attempt to share SRC port (ie. do not make NAT allocation to detect port
    allocation conflicts). */
#define SSH_PM_NAT_SHARE_PORT_SRC                0x0008
/** Dest NAT is sharing port by default. This inhibits
    port sharing behaviour. */
#define SSH_PM_NAT_NO_SHARE_PORT_DST             0x0010
/** NAT mapping is one-to-one. */
#define SSH_PM_NAT_ONE_TO_ONE_SRC                0x0020
#define SSH_PM_NAT_ONE_TO_ONE_DST                0x0040
/** Alias for port overloading behavior. */
#define SSH_PM_NAT_OVERLOAD_PORT (SSH_PM_NAT_KEEP_PORT | \
                                  SSH_PM_NAT_SHARE_PORT_SRC)
typedef SshUInt16 SshPmNatFlags;
#endif /* SSHDIST_IPSEC_NAT */

/*--------------------------------------------------------------------*/
/* Parameters for IPsec tunnels                                       */
/*--------------------------------------------------------------------*/

/*  These bit masks define the characteristics of IPsec tunnels
    (transforms and algorithms).  The bit masks for encryption
    algorithms, MAC algorithms, compression algorithms and transforms
    are designed to be non-overlapping so that they can be stored in
    the same 64-bit variable. */

typedef SshUInt64 SshPmTransform;

/*  Bit masks for encryption algorithms. */
#define SSH_PM_CRYPT_EXT1       0x00000001
#define SSH_PM_CRYPT_EXT2       0x00000002
#define SSH_PM_CRYPT_NULL       0x00000004 /** Allow no encryption. */
#define SSH_PM_CRYPT_DES        0x00000008 /** 56 bit key. */
#define SSH_PM_CRYPT_3DES       0x00000010 /** 168 bit key. */
#define SSH_PM_CRYPT_AES        0x00000020 /** 128 bit key. */
#define SSH_PM_CRYPT_AES_CTR    0x00000040 /** AES counter mode,
                                               128 bit key. */
#define SSH_PM_CRYPT_AES_GCM    0x00000080 /** AES GCM mode, 128 bit key,
                                               128 bit digest. */
#define SSH_PM_CRYPT_AES_GCM_8  0x00000100 /** AES GCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_AES_GCM_12 0x00000200 /** AES GCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_NULL_AUTH_AES_GMAC \
                                0x00000400 /** AES GCM-GMAC, no encryption. */
#define SSH_PM_CRYPT_AES_CCM    0x00000800 /** AES CCM mode, 128 bit key,
                                               128 bit digest. */
#define SSH_PM_CRYPT_AES_CCM_8  0x00001000 /** AES CCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_AES_CCM_12 0x00002000 /** AES CCM mode, 128 bit key,
                                               64 bit digest. */
#define SSH_PM_CRYPT_MASK       0x00003fff /** Mask for ciphers. */
#define SSH_PM_COMBINED_MASK    0x00003f80 /** Mask for combined algorithms. */

/*  Bit masks for MAC and hash algorithms. */
#define SSH_PM_MAC_EXT1         0x00004000
#define SSH_PM_MAC_EXT2         0x00008000
#define SSH_PM_MAC_HMAC_MD5     0x00010000 /** 128 bit key. */
#define SSH_PM_MAC_HMAC_SHA1    0x00020000 /** 160 bit key. */
#define SSH_PM_MAC_XCBC_AES     0x00040000 /** 128 bit key. */
#define SSH_PM_MAC_HMAC_SHA2    0x00080000 /** 256-512 bit key. */
#define SSH_PM_MAC_MASK         0x000fc000 /** Mask for MACs. */

/*  Bit masks for compression algorithms. */
#define SSH_PM_COMPRESS_DEFLATE 0x00100000 /** Compress using deflate. */
#define SSH_PM_COMPRESS_LZS     0x00200000 /** Compress using LZS. */
#define SSH_PM_COMPRESS_MASK    0x00300000 /** Mask for compressions. */

/*  Bit masks for IPSec transforms. */
#define SSH_PM_IPSEC_ESP        0x00400000 /** Perform ESP. */
#define SSH_PM_IPSEC_IPCOMP     0x00800000 /** Perform IPPCP. */
#define SSH_PM_IPSEC_AH         0x01000000 /** Perform AH. */
#define SSH_PM_IPSEC_MASK       0x01c00000 /** Mask for transforms. */

/*  Additional transforms / transforms options. */
#define SSH_PM_IPSEC_TUNNEL     0x02000000 /** Use tunnel mode (IP-in-IP). */
#define SSH_PM_IPSEC_MANUAL     0x04000000 /*  (int) disable life notify. */
#define SSH_PM_IPSEC_ANTIREPLAY 0x08000000 /*  (int) enable anti-replay. */
#define SSH_PM_IPSEC_INT_NAT    0x10000000 /** Make incoming clients unique. */
#define SSH_PM_IPSEC_NATT       0x20000000 /*  (int) NAT-T UDP encap. */
#define SSH_PM_IPSEC_L2TP       0x40000000 /*  (int) L2TP UDP+PPP encap. */
#define SSH_PM_IPSEC_LONGSEQ    0x80000000 /** Use 64 bit sequence number. */
/* (LL is added to following values to make them long long, otherwise they are
 * just long and failing on some 32 bit systems) */
#define SSH_PM_IPSEC_SHORTSEQ  0x100000000LL /** Use 32 bit sequence number. */

#ifdef SSHDIST_IPSEC_NAT
/* Port NAT decapsulated traffic. */
#define SSH_PM_IPSEC_PORT_NAT  0x200000000LL
#endif /* SSHDIST_IPSEC_NAT */

/*--------------------------------------------------------------------*/
/* Constants                                                          */
/*--------------------------------------------------------------------*/

/** Value used to indicate an invalid 32-bit index (of any kind) used
    in QuickSec.  This is guaranteed to be a very large number. */
#define SSH_IPSEC_INVALID_INDEX         ((SshUInt32)0xddffffff)

/*--------------------------------------------------------------------*/
/* Statistics                                                         */
/*--------------------------------------------------------------------*/

/* Statistics counter number definitions. */
/* Total packets = ip4 + ip6 + arp + other. */
#define SSH_ENGINE_STAT_IN_IP4          0 /* # IPv4 packets. */
#define SSH_ENGINE_STAT_IN_IP6          1 /* # IPv6 packets. */
#define SSH_ENGINE_STAT_IN_ARP          2 /* # ARP packets. */
#define SSH_ENGINE_STAT_IN_OTHER        3 /* # Other (non-IP) packets. */
#define SSH_ENGINE_STAT_ESP_IN          4 /* # ESP incoming. */
#define SSH_ENGINE_STAT_ESP_OUT         5 /* # ESP outgoing. */
#define SSH_ENGINE_STAT_AH_IN           6 /* # AH incoming. */
#define SSH_ENGINE_STAT_AH_OUT          7 /* # AH outgoing. */
#define SSH_ENGINE_STAT_IPCOMP_IN       8 /* # IPCOMP incoming. */
#define SSH_ENGINE_STAT_IPCOMP_OUT      9 /* # IPCOMP outgoing compressed. */
#define SSH_ENGINE_STAT_NOIPCOMP_OUT    10 /* # IPCOMP out left plain. */
#define SSH_ENGINE_STAT_NOLOOKUP        11 /* # Policy lookup disabled. */
#define SSH_ENGINE_STAT_DROP            12 /* # Dropped for any reason. */
#define SSH_ENGINE_STAT_CORRUPTDROP     13 /* # Corrupt packets received. */
#define SSH_ENGINE_STAT_OPTIONSDROP     14 /* # Dropped due to IP options. */
#define SSH_ENGINE_STAT_RESOURCEDROP    15 /* # Dropped when out of memory. */
#define SSH_ENGINE_STAT_ROUTEDROP       16 /* # Packets with no route. */
#define SSH_ENGINE_STAT_RULEDROP        17 /* # Packets dropped by a rule. */
#define SSH_ENGINE_STAT_RULEREJECT      18 /* # Packets dropped(reject rule).*/
#define SSH_ENGINE_STAT_ESPMACDROP      19 /* # Dropped due to ESP MAC. */
#define SSH_ENGINE_STAT_AHMACDROP       20 /* # Dropped due to AH MAC. */
#define SSH_ENGINE_STAT_REPLAYDROP      21 /* # Dropped due to anti-replay. */
#define SSH_ENGINE_STAT_ERRORDROP       22 /* # Dropped, internal error.*/
#define SSH_ENGINE_STAT_FRAGDROP        23 /* # Dropped in reassembly. */
#define SSH_ENGINE_STAT_HWACCELDROP     24 /* # Dropped by hwaccel. */
#define SSH_ENGINE_STAT_TRANSFORMDROP   25 /* # Dropped due to transform. */
#define SSH_ENGINE_STAT_NORULE          26 /* # No rule found. */
#define SSH_ENGINE_STAT_TRIGGER         27 /* # Packets causing trigger. */
#define SSH_ENGINE_STAT_NOTRIGGER       28 /* # Triggers rate-limited. */
#define SSH_ENGINE_STAT_MONITORDROP     29 /* # Dropped by protocol monitor. */

#define SSH_ENGINE_NUM_GLOBAL_STATS     38 /* Number of used stat counters. */
#define SSH_ENGINE_NUM_STATS            64 /* --- Total number of stat bits. */

typedef struct SshFastpathGlobalStatsRec
{
  /** Total octets in before decompression. */
  SshUInt64 in_octets_comp;

  /** Total octets in after decompression. */
  SshUInt64 in_octets_uncomp;

  /** Total octets out after compression. */
  SshUInt64 out_octets_comp;

  /** Total octets out before compression. */
  SshUInt64 out_octets_uncomp;

  /** Total octets forwarded after compression. */
  SshUInt64 forwarded_octets_comp;

  /** Total octets forwarded before compression. */
  SshUInt64 forwarded_octets_uncomp;

  /** Total packets in. */
  SshUInt64 in_packets;

  /** Total packets out. */
  SshUInt64 out_packets;

  /** Total packets forwarded. */
  SshUInt64 forwarded_packets;

  /** Number of currently active transform contexts. */
  SshUInt32 active_transform_contexts;

  /** Total number of transform contexts created. */
  SshUInt32 total_transform_contexts;

  /** Number of packets dropped due to no available transform context. */
  SshUInt32 out_of_transform_contexts;

  /** Number of currently in use packet contexts. */
  SshUInt32 active_packet_contexts;

  /** Number of packets dropped due to no available packet context. */
  SshUInt32 out_of_packet_contexts;

  /** Global statistics counters. */
  SshUInt32 counters[SSH_ENGINE_NUM_GLOBAL_STATS];

  /** The size of transform context table in FastPath - this is not
      really statistics, but information that may be useful for
      querying further information from FastPath. */
  SshUInt32 transform_context_table_size;

  /** The size of packet context table in FastPath - this is not
      really statistics, but information that may be useful for
      querying further information from FastPath. */
  SshUInt32 packet_context_table_size;

  /** Sizes of key objects in FastPath. */
  SshUInt32 transform_context_struct_size;

} SshFastpathGlobalStatsStruct, *SshFastpathGlobalStats;


typedef struct SshEngineGlobalStatsRec
{
  /** Number of currently active next hop records - this field is
      protected by engine->flow_control_table_lock. */
  SshUInt32 active_nexthops;

  /** Total number of next hop records available - this field is
      protected by engine->flow_control_table_lock. */
  SshUInt32 total_nexthops;

  /** Number of packets dropped due to no available next hop
      object - this field is protected by
      engine->flow_control_table_lock. */
  SshUInt32 out_of_nexthops;

  /** Number of currently active flows - this field is protected by
      engine->flow_control_table_lock. */
  SshUInt32 active_flows;

  /** Total number of flows created - this field is protected by
      engine->flow_control_table_lock. */
  SshUInt32 total_flows;

  /** Number of packets dropped due to no available flow object - this
      field is protected by engine->flow_control_table_lock. */
  SshUInt32 out_of_flows;

  /** Number of currently active transforms - this field is protected
      by engine->flow_table_lock. */
  SshUInt32 active_transforms;

  /** Total number of transform records created - this field is
      protected by engine->flow_table_lock. */
  SshUInt32 total_transforms;

  /** Number of packets dropped due to no available transform
      object. This field is protected by engine->flow_table_lock. */
  SshUInt32 out_of_transforms;

  /** Number of packets dropped due to no available ARP cache
      entries. This field is protected by engine->interface_lock. */
  SshUInt32 out_of_arp_cache_entries;

  /** Total number of rekeys performed - this field is protected by
      engine->flow_table_lock. */
  SshUInt32 total_rekeys;

  /** Number of Engine policy rules currently active - this field is
      protected by engine->flow_control_table_lock. */
  SshUInt32 active_rules;

  /** Total number of Engine policy rules created - this field is
      protected by engine->flow_control_table_lock. */
  SshUInt32 total_rules;

  /** The size of flow table in Engine - this is not really
      statistics, but information that may be useful for querying
      further information from Engine. */
  SshUInt32 flow_table_size;

  /** The size of transform table in Engine - this is not really
      statistics, but information that may be useful for querying
      further information from Engine. */
  SshUInt32 transform_table_size;

  /** The size of rule table in Engine - this is not really
      statistics, but information that may be useful for querying
      further information from Engine. */
  SshUInt32 rule_table_size;

  /** The size of next hop table in Engine - this is not really
      statistics, but information that may be useful for querying
      further information from Engine. */
  SshUInt32 next_hop_table_size;

  /** The size of policy rule object in Engine. */
  SshUInt32 policy_rule_struct_size;

  /** The size of transform data object in Engine. */
  SshUInt32 transform_data_struct_size;

  /** The size of flow object in Engine. */
  SshUInt32 flow_struct_size;

  /** Timeout granularity. */
  SshUInt32 age_callback_interval;

  /** Timeout granularity. */
  SshUInt32 age_callback_flows;

} SshEngineGlobalStatsStruct, *SshEngineGlobalStats;

typedef struct SshPmGlobalStatsRec
{
  /* Current operational statistics. */
  SshUInt32 num_p1_active;
  SshUInt32 num_qm_active;

  /* Cumulative statistics. */
  SshUInt32 num_p1_done;
  SshUInt32 num_p1_failed;
  SshUInt32 num_p1_rekeyed;

  SshUInt32 num_qm_done;
  SshUInt32 num_qm_failed;

  /** The size of rule object in Policy Manager. */
  SshUInt32 rule_struct_size;

  /** The size of tunnel object in Policy Manager. */
  SshUInt32 tunnel_struct_size;

  /** The size of service object in Policy Manager. */
  SshUInt32 service_struct_size;
} SshPmGlobalStatsStruct, *SshPmGlobalStats;


/** Engine flow statistics. */
typedef struct SshEngineFlowStatsRec
{
  /** Total octets in forward direction of flow. */
  SshUInt64 forward_octets;

  /** Total octets in reverse direction of flow. */
  SshUInt64 reverse_octets;

  /** Total packets in forward direction of flow. */
  SshUInt64 forward_packets;

  /** Total packets in reverse direction of flow. */
  SshUInt64 reverse_packets;

  /** Total packets dropped. */
  SshUInt64 drop_packets;
} SshEngineFlowStatsStruct, *SshEngineFlowStats;

/** Protocol monitor states for the statistics interface. */
typedef enum
{
  SSH_ENGINE_FLOW_PROTOCOL_NONE = 0,

  /* TCP Protocol monitor states */
  SSH_ENGINE_FLOW_TCP_INITIAL = 1,
  SSH_ENGINE_FLOW_TCP_SYN_ACK = 2,
  SSH_ENGINE_FLOW_TCP_SYN_ACK_ACK = 3,
  SSH_ENGINE_FLOW_TCP_ESTABLISHED = 4,
  SSH_ENGINE_FLOW_TCP_FIN_FWD = 5,
  SSH_ENGINE_FLOW_TCP_FIN_REV = 6,
  SSH_ENGINE_FLOW_TCP_FIN_FIN = 7,
  SSH_ENGINE_FLOW_TCP_CLOSE_WAIT = 8,
  SSH_ENGINE_FLOW_TCP_CLOSED = 9

} SshEngineFlowProtocolState;


/** Flow information for collecting flow statistics. */
typedef struct SshEngineFlowInfoRec
{
  /* Flow endpoints */
  SshIpAddrStruct src;
  SshIpAddrStruct dst;
  SshUInt16 src_port;
  SshUInt16 dst_port;
  SshUInt8 ipproto;

#ifdef SSHDIST_IPSEC_NAT
  SshIpAddrStruct nat_src;      /** Flow NAT source. */
  SshIpAddrStruct nat_dst;      /** Flow NAT destination. */
  SshUInt16 nat_src_port;       /** Flow NAT source port. */
  SshUInt16 nat_dst_port;       /** Flow NAT destination port. */
#endif /* SSHDIST_IPSEC_NAT */

  /** Forward transform index for the flow. */
  SshUInt32 forward_transform_index;

  /** Reverse transform index for the flow. */
  SshUInt32 reverse_transform_index;

  /** The rule the flow is currently attached to. */
  SshUInt32 rule_index;

  /** SshEngineFlowProtocolState describing protocol state - the value
      of this field is independent of 'ipproto' when accessing, but
      meaningless 'protocol_state','ipproto' pairs should obviously
      not happen. */
  SshUInt32 protocol_state;

  /** LRU level of the flow in Engine. */
  SshUInt32 lru_level;

  /** Idle time. */
  SshUInt32 idle_time;

  /** Is the flow dangling? */
  Boolean is_dangling;

  /** Is this a temporary trigger flow? */
  Boolean is_trigger;

  int routing_instance_id;
  char routing_instance_name[64];
} SshEngineFlowInfoStruct, *SshEngineFlowInfo;

typedef struct SshEngineTransformDataStatsRec
{
  /** Total octets in. */
  SshUInt64 in_octets;

  /** Total octets out. */
  SshUInt64 out_octets;

  /** Number of inbound packets processed using this transform. */
  SshUInt64 in_packets;

  /** Number of outbound packets processed using this transform. */
  SshUInt64 out_packets;

  /** Number of packets dropped using this transform. */
  SshUInt64 drop_packets;

  /** Number of MAC failures for this transform. */
  SshUInt64 num_mac_fails;
} SshEngineTransformDataStatsStruct, *SshEngineTransformDataStats;

typedef struct SshEngineTransformControlStatsRec
{
  /** Number of rekeys performed for this transform. */
  SshUInt32 num_rekeys;

  /** Number of flows currently active using this transform. */
  SshUInt32 num_flows_active;
} SshEngineTransformControlStatsStruct, *SshEngineTransformControlStats;

typedef struct SshEngineTransformStatsRec
{
  SshEngineTransformDataStatsStruct data;
  SshEngineTransformControlStatsStruct control;
} SshEngineTransformStatsStruct, *SshEngineTransformStats;

typedef struct SshEngineTransformInfoRec
{
  SshPmTransform transform;
  SshIpAddrStruct gw_addr;
  SshIpAddrStruct own_addr;
  SshUInt32 tunnel_id;
  SshUInt32 spi_esp_in;
  SshUInt32 spi_esp_out;
  SshUInt32 spi_ah_in;
  SshUInt32 spi_ah_out;
  SshUInt16 cpi_ipcomp_in;
  SshUInt16 cpi_ipcomp_out;
  SshUInt8 cipher_key_size;
  SshUInt8 mac_key_size;
  char routing_instance_name[64];
  int routing_instance_id;
} SshEngineTransformInfoStruct, *SshEngineTransformInfo;


typedef struct SshEngineRuleStatsRec
{
  /** Number of times this rule has been used. */
  SshUInt32 times_used;
  /** Number of currently active flows by this rule - this value is protected
      by engine->flow_table_lock. */
  SshUInt32 num_flows_active;
  /** Total number of flows ever created using this rule - this value is
      protected by engine->flow_table_lock. */
  SshUInt32 num_flows_total;
} SshEngineRuleStatsStruct, *SshEngineRuleStats;

/* Flags for Engine rule info. */
#define SSH_PM_ENGINE_RULE_SEL_IFNUM    0x00000001
#define SSH_PM_ENGINE_RULE_SEL_ICMPTYPE 0x00000002
#define SSH_PM_ENGINE_RULE_SEL_ICMPCODE 0x00000004

/* Engine rule types. */
typedef enum
{
  SSH_PM_ENGINE_RULE_DROP       = 1,
  SSH_PM_ENGINE_RULE_REJECT     = 2,
  SSH_PM_ENGINE_RULE_PASS       = 3,
  SSH_PM_ENGINE_RULE_APPLY      = 4,
#ifndef SSH_IPSEC_SMALL
  SSH_PM_ENGINE_RULE_DORMANT_APPLY = 6,
#endif /* SSH_IPSEC_SMALL */
  SSH_PM_ENGINE_RULE_TRIGGER    = 5
} SshPmEngineRuleType;

typedef struct SshEngineRuleInfoRec
{
  SshUInt32 flags;
  SshPmEngineRuleType type;
  SshUInt32 precedence;
  SshUInt32 tunnel_id;
  SshIpAddrStruct src_ip_low;
  SshIpAddrStruct src_ip_high;
  SshIpAddrStruct dst_ip_low;
  SshIpAddrStruct dst_ip_high;
  SshUInt32 ifnum;
  int routing_instance_id;
  char routing_instance_name[64];
  SshUInt16 src_port_low;
  SshUInt16 src_port_high;
  SshUInt16 dst_port_low;
  SshUInt16 dst_port_high;
  SshUInt8 ipproto;
  SshUInt8 icmp_type;
  SshUInt8 icmp_code;
  SshUInt32 transform_index;
  SshUInt32 depends_on;
} SshEngineRuleInfoStruct, *SshEngineRuleInfo;


/*--------------------------------------------------------------------*/
/* Packet corruption                                                  */
/*--------------------------------------------------------------------*/

/** SshEnginePacketCorruption specifies the packet corruption reasons
    recognized */
typedef enum
{
  /** Packet is not corrupt */
  SSH_PACKET_CORRUPTION_NONE = 0,

  /** Short media header */
  SSH_PACKET_CORRUPTION_SHORT_MEDIA_HEADER,

  /** Reserved value in packet received */
  SSH_PACKET_CORRUPTION_RESERVED_VALUE,

  /** IPv4/IPv6 header is too short (less than minumum or header length
     specified value */
  SSH_PACKET_CORRUPTION_SHORT_IPV4_HEADER,

  SSH_PACKET_CORRUPTION_SHORT_IPV6_HEADER,

  /** Packet is not IPv4 (or IPv6) as expected. */
  SSH_PACKET_CORRUPTION_NOT_IPV4,
  SSH_PACKET_CORRUPTION_NOT_IPV6,

  /** Header checksum does not match packet */
  SSH_PACKET_CORRUPTION_CHECKSUM_MISMATCH,

  /** Packet is truncated (specified length is longer than packet) */
  SSH_PACKET_CORRUPTION_TRUNCATED_PACKET,

  /** packet too small to contain next protocol pdu */
  SSH_PACKET_CORRUPTION_TOO_SMALL_FOR_NEXT_PROTOCOL,

  /** IP TTL less than required */
  SSH_PACKET_CORRUPTION_TTL_ZERO,

  /** IP 0 < ttl < engine->min_ttl_required */
  SSH_PACKET_CORRUPTION_TTL_SMALL,

  /** Multicast source address */
  SSH_PACKET_CORRUPTION_MULTICAST_SOURCE,

  /** IP Options (also used for IPv6 extension headers) */

  /** Unknown IP option spotted */
  SSH_PACKET_CORRUPTION_UNKNOWN_IP_OPTION,

  /** A forbidden IP option spotted */
  SSH_PACKET_CORRUPTION_FORBIDDEN_OPTION,

  /** Unaligned IP option for which alignment required (e.g. timestamp) */
  SSH_PACKET_CORRUPTION_UNALIGNED_OPTION,

  /** Options overflow IP header length */
  SSH_PACKET_CORRUPTION_OPTION_OVERFLOW,

  /** Option format incorrect (correct format in RFC791) */
  SSH_PACKET_CORRUPTION_OPTION_FORMAT_INCORRECT,


  /** last fragment length creates a packet longer than 65k */
  SSH_PACKET_CORRUPTION_FRAGMENT_OVERFLOW_LENGTH,

  /** non-last fragment length is not multiple of 8 */
  SSH_PACKET_CORRUPTION_FRAGMENT_BAD_LENGTH,

  /** fragment is too small (minimum length specified
     in ipsec_params.h ) */
  SSH_PACKET_CORRUPTION_FRAGMENT_TOO_SMALL,

  /** fragment offset too small (less than minimum length) */
  SSH_PACKET_CORRUPTION_FRAGMENT_OFFSET_TOO_SMALL,

  /** Overlapping fragment id's */
  SSH_PACKET_CORRUPTION_FRAGMENT_ID_COLLISION,

  /** Overlapping fragments */
  SSH_PACKET_CORRUPTION_FRAGMENT_LATE_AND_EXTRA,

  /** next protocol header fragmented */
  SSH_PACKET_CORRUPTION_NEXT_PROTOCOL_HEADER_FRAGMENTED,


  /** LAND attack (src and dst addressses are same) */
  SSH_PACKET_CORRUPTION_SRC_DST_SAME,

  /** ICMP Smurf attack*/
  SSH_PACKET_CORRUPTION_ICMP_BROADCAST,

  /** TCP flags that are always not allowed. */
  SSH_PACKET_CORRUPTION_TCP_XMAS,

  /** No TCP flags set and no TCP session established. */
  SSH_PACKET_CORRUPTION_TCP_NULL,

  /** FIN-flag set in state where it is not allowed. */
  SSH_PACKET_CORRUPTION_TCP_FIN,

  /** Bad sequence number */
  SSH_PACKET_CORRUPTION_TCP_BAD_SEQUENCE,

  /** Transmitting this packet would result in sequence number overflow  */
  SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_OVERFLOW,

  /** Input AH packet is an IP fragment */
  SSH_PACKET_CORRUPTION_AH_IP_FRAGMENT,

  /** Input packet cannot be mapped to an SA i.e. unknown SPI. */
  SSH_PACKET_CORRUPTION_AH_SA_LOOKUP_FAILURE,

  /** AH packet is a replay or is outside the receivers' sliding window */
  SSH_PACKET_CORRUPTION_AH_SEQ_NUMBER_FAILURE,

  /** AH ICV check fails */
  SSH_PACKET_CORRUPTION_AH_ICV_FAILURE,

  /** Transmitting this packet would result in sequence number overflow  */
  SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_OVERFLOW,

  /** Input ESP packet is an IP fragment. */
  SSH_PACKET_CORRUPTION_ESP_IP_FRAGMENT,

  /** Input packet cannot be mapped to an SA i.e. unknown SPI. */
  SSH_PACKET_CORRUPTION_ESP_SA_LOOKUP_FAILURE,

  /** ESP packet is a replay or is outside the receivers' sliding window. */
  SSH_PACKET_CORRUPTION_ESP_SEQ_NUMBER_FAILURE,

  /** ESP ICV check fails. */
  SSH_PACKET_CORRUPTION_ESP_ICV_FAILURE,

  /** Flow rate limitation. */
  SSH_PACKET_CORRUPTION_FLOW_RATE_LIMITED,

  /** Dropping audit events due to rate limit. */
  SSH_PACKET_CORRUPTION_AUDIT_RATE_LIMITED,

  /** Packet forbidden by policy-rule "DROP" */
  SSH_PACKET_CORRUPTION_POLICY_DROP,

  /** Packet forbidden by policy-rule "REJECT" */
  SSH_PACKET_CORRUPTION_POLICY_REJECT,

  /** Packet allowed by policy-rule */
  SSH_PACKET_CORRUPTION_POLICY_PASS,

  /** Packet is unsoliticed ICMP error message. */
  SSH_PACKET_CORRUPTION_UNSOLICITED_ICMP_ERROR,

  /** Checksum coverage file in UDPLite header too small. */
  SSH_PACKET_CORRUPTION_CHECKSUM_COVERAGE_TOO_SMALL,

  /** Decapsulated packet does not match SA selectors. */
  SSH_PACKET_CORRUPTION_IPSEC_INVALID_SELECTORS,

  /** amount of corruptions recognized */
  SSH_PACKET_CORRUPTION_MAX,

  /** Internal error */
  SSH_PACKET_CORRUPTION_ERROR = 255

} SshEnginePacketCorruption;

#endif /* CORE_PM_SHARED_H */
