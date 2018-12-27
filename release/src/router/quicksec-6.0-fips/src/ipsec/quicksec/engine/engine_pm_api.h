/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file defines the API used in the interface between Policy
   Manager and Engine.

   @description
   This file contains functions implemented by Engine.  All
   operations are designed so that they can fail.

   Path MTU discovery for IPsec packets is implemented internally by
   the engine without interaction from Policy Manager.

   On most systems the interface describe here compiles into code
   that encodes requests into packets, passes them between kernel and
   user space using e.g. a device file, decodes the packets on the
   receiving side, and calls the appropriate function on the other
   side.  However, if SSH_IPSEC_UNIFIED_ADDRESS_SPACE
   (quicksec_params.h) is defined, then the function on the other
   side is called directly (see below for locking requirements).

   One should note that the engine and Policy Manager use different
   concurrency control paradigms.  Engine is multithreaded, whereas
   Policy Manager is single-threaded.  This API is designed so that
   Policy Manager can be written without having to worry about
   concurrency control issues, and Engine takes care to preserve the
   semantics that Policy Manager cannot be called concurrently.
   However, additional care will be required to prevent timeouts, UDP
   callbacks, TCP callbacks, etc (basically any callback) from
   creating concurrent calls to Policy Manager.  Basically all entry
   paths to Policy Manager must ensure that no concurrent entry is
   possible.

   Engine will never call Policy Manager directly.  Instead, if it
   needs to call Policy Manager (one of the ssh_pm_pmp_* functions),
   it schedules a zero-length timeout (using ssh_timeout_register, as
   opposed to ssh_kernel_timeout_register) to issue the call through
   whatever mechanisms are used by the system to protect Policy
   Manager from concurrent execution.  (This implies that the
   implementation of ssh_timeout_register itself must be MT-safe.)

   All incoming packets (either from the network or from the local
   stack) enter with tunnel id 0.  Transforms specify what tunnel id
   will be used for reprocessing incoming packets entering from the
   tunnel.

   Tunnel id 1 is reserved; packets coming in at NAT-T enabled
   transforms that are not valid NAT-T packets (i.e., are IKE
   packets) are reprocessed with tunnel id 1.  Also, incoming L2TP
   control packets are decapsulated into L2TP UDP packets and
   reprocessed using tunnel id 1.

   The following default rules should be created in order to make
   this work:

   - IKE pass rules should be marked with the SSH_ENGINE_NO_FLOW flag.

   - Incoming IKE pass rules should be entered twice, once with tunnel id 0
     and another time with tunnel id 1.

   - For L2TP, a default rule should be created with tunnel id 1 for
     incoming UDP L2TP traffic to local host.

   Note: The API defined in this header is internal and may change
   between versions.
*/

#ifndef ENGINE_PM_API_H
#define ENGINE_PM_API_H

#include "ipsec_params.h"
#include "engine.h"
#include "interceptor.h"
#include "quicksec_pm_shared.h"
#include "sshaudit.h"

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#include "virtual_adapter.h"
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#include "engine_fastpath_types.h"

/** A simple structure for storing an [ip:port] in a hash-table. */
typedef struct SshEngineNatPortRec
{
  /** Pointer to the next structure with the same key. */
  struct SshEngineNatPortRec *next;

  /** IP Address. */
  SshIpAddrStruct nat_ip;

  /** Port. */
  SshUInt16 nat_port;
} *SshEngineNatPort, SshEngineNatPortStruct;


/* *********************************************************************
 * Rule data type definition.
 * *********************************************************************/


/** Due to some silliness in the statistics API, these must
    correspond to the values in quicksec_pm_shared.h. */
typedef enum {
  /** The policy rule is on the freelist. */
  SSH_ENGINE_RULE_NONEXISTENT = 0,

  /** Silently drop any such packets. */
  SSH_ENGINE_RULE_DROP = 1,

  /** Drop any such packets, but try to be "friendly".  This will try
      to send back TCP RST and/or ICMP Administratively Prohibited as
      applicable (both will be rate-limited). */
  SSH_ENGINE_RULE_REJECT = 2,

  /** Pass such packets through.  This creates a stateful session which
      allows packets to go through bidirectionally (unless
      SSH_ENGINE_NO_FLOW is specified, in which case the rule will be
      unidirectional and no flow will be created).  This will
      automatically perform NAT on the packets if appropriate.  If any
      kind of NAT is to be performed, a flow must be created (i.e.,
      SSH_ENGINE_NO_FLOW must not be specified). */
  SSH_ENGINE_RULE_PASS = 3,

  /** Apply transform. The transform index is stored in the
     'transform_index' field.  This creates a stateful session which
      allows packets to go through bidirectionally (unless
      SSH_ENGINE_NO_FLOW is specified, in which case the rule will be
      unidirectional and no flow will be created).  This will
      automatically perform NAT on the packets if appropriate. If any
      kind of NAT is to be performed, a flow must be created (i.e.,
      SSH_ENGINE_NO_FLOW must not have been specified). */
  SSH_ENGINE_RULE_APPLY = 4,

#ifndef SSH_IPSEC_SMALL
  /** Dormant APPLY rule placeholder. */
  SSH_ENGINE_RULE_DORMANT_APPLY = 6,
#endif /** SSH_IPSEC_SMALL */

  /** Triggers to Policy Manager.  Triggers are automatically rate-limited.
      Note that it is explicitly legal to specify a transform_index for
      a trigger rule, even though the transform index is not used by
      the trigger rule.  The engine will then count the trigger rule as
      referencing the transform.  This is useful for application gateways. */
  SSH_ENGINE_RULE_TRIGGER = 5

} SshEnginePolicyRuleType;


/* Bit masks for the selectors field in a rule. */

/* Flags indicating which fields of the selector are present in a
   rule.  Note: always use symbolic values; numeric constants are
   subject to change. */

/** Flag: the ifnum field of the selector is present in a rule. */
#define SSH_SELECTOR_IFNUM           0x0001

/** Flag: the ipproto field of the selector is present in a rule. */
#define SSH_SELECTOR_IPPROTO         0x0002

/** Flag: the destination IP field of the selector is present in a rule. */
#define SSH_SELECTOR_DSTIP           0x0004

/** Flag: the source IP field of the selector is present in a rule. */
#define SSH_SELECTOR_SRCIP           0x0008

/** Flag: the source port field of the selector is present in a rule. */
#define SSH_SELECTOR_SRCPORT         0x0010

/** Flag: the destination port field of the selector is present in a rule. */
#define SSH_SELECTOR_DSTPORT         0x0020

/** Flag: the ICMP type field of the selector is present in a rule. */
#define SSH_SELECTOR_ICMPTYPE        0x0040

/** Flag: the ICMP code field of the selector is present in a rule. */
#define SSH_SELECTOR_ICMPCODE        0x0080

#define SSH_SELECTOR_FROMLOCAL       0x0100 /** Packet from local stack. */
#define SSH_SELECTOR_TOLOCAL         0x0200 /** Packet to local stack. */
#define SSH_SELECTOR_EXTENSIONS      0x0400 /** Extension selectors used. */

/** Routing instance id as a selector */
#define SSH_SELECTOR_RIID            0x0800


/* Bit masks for the flags field in a rule.

   Flags indicating which fields of the selector are present in a rule.
   Note: always use symbolic values; numeric constants are subject to
   change. */
#define SSH_ENGINE_RULE_USE_ONCE     0x00000001 /** Use the rule only once. */
#define SSH_ENGINE_RULE_USED         0x00000002 /** (internal) Has been used.*/
#ifdef SSHDIST_IPSEC_NAT
#define SSH_ENGINE_RULE_FORCE_NAT_DST 0x00000004 /** NAT dst - new_dst_port. */
#define SSH_ENGINE_RULE_FORCE_NAT_SRC 0x00000008 /** NAT src - new_src_port. */
#endif /* SSHDIST_IPSEC_NAT */
#define SSH_ENGINE_RULE_DELETED      0x00000010 /** (int) Rule is deleted. */
#define SSH_ENGINE_RULE_INACTIVE     0x00000020 /** Rule is inactive, see
                                                    ssh_pme_find_transform_rule
                                                    for more info. */
#define SSH_ENGINE_RULE_PM_REFERENCE 0x00000040 /** PM has one extra reference
                                                    to the rule - it is
                                                    removed with an explicit
                                                    ssh_pme_delete_rule
                                                    call. */
#define SSH_ENGINE_LOG_CONNECTIONS   0x00000080 /** Log all connections. */
#define SSH_ENGINE_RATE_LIMIT        0x00000100 /** Enable rate limiter. */

#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
#define SSH_ENGINE_RULE_SCTP_MULTIHOME 0x00000200 /** Rule has SCTP multi-homed
                                                      addresses. */
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

#define SSH_ENGINE_RULE_UNDEFINED    0x00000400 /** This rule is not well
                                                    defined - its forward
                                                    transform index field is
                                                    meaningless. */
#define SSH_ENGINE_NO_FLOW           0x00000800 /** Don't create flow. */
#define SSH_ENGINE_RULE_PLACEHOLDER  0x00001000 /** Make apply rule dormant
                                                    again instead of deletion
                                                    in certain cases. */
#define SSH_ENGINE_RULE_NO_IPSEC_FLOW 0x00002000 /** Don't create an IPsec
                                                     flow for such rules. */
#define SSH_ENGINE_RULE_REKEY_PENDING   0x00004000 /** The rule is pending a
                                                       reinstallion after a
                                                       IPSec rekey. */
#define SSH_ENGINE_RULE_INSTALL_PENDING 0x00008000 /** The rule is pending a
                                                       installion after a
                                                       IPSec rekey. */
#define SSH_ENGINE_RULE_PASS_UNMODIFIED 0x00010000 /** Packets matching this
                                                       rule must be passed
                                                       without any
                                                       modification. */

/* Flags, reserved for Policy Manager. */
#define SSH_PM_ENGINE_RULE_SLAVE     0x00020000 /** Appgw slave connection. */
#define SSH_PM_ENGINE_RULE_CR        0x00040000 /** Crash-recovery trigger. */
#define SSH_PM_ENGINE_RULE_FORWARD   0x00080000 /** Direction of PM rule;
                                                    currently this can be
                                                    considered to be valid for
                                                    TRIGGER and SA handler
                                                    rules. */
#define SSH_PM_ENGINE_RULE_REPORT    0x00100000 /** Pass back a copy of the
                                                    provided rule */
#define SSH_PM_ENGINE_RULE_FLOW_REF  0x00200000 /** All flows created using
                                                    this rule and only those
                                                    flows, must be
                                                    referencable via
                                                    rule - this has also the
                                                    additionlal semantic that
                                                    any APPLY rules with this
                                                    flag create flows attached
                                                    to their parent
                                                    "depends_on". */
#define SSH_PM_ENGINE_RULE_APPGW     0x00400000 /** Appgw mapping rule. */
#define SSH_PM_ENGINE_RULE_TOTUNNEL  0x00800000 /** Trigger rule has to-tunnel
                                                    aspect... */
#define SSH_PM_ENGINE_RULE_TT_NAT    0x01000000 /** The transform which will
                                                    be installed after this
                                                    trigger requires NAT be
                                                    performed for encapsulated
                                                    traffic. */
#define SSH_PM_ENGINE_RULE_SA_OUTBOUND 0x04000000 /** IPSec SA outbound rule.*/

/** Data structure for a policy rule.  */
typedef struct SshEnginePolicyRuleRec
{
  /*  Selectors for the rule.  All rules must have at least the protocol and
      tunnelid fields set.  If other selectors are set, the corresponding bits
      are set in the flags field.  (Note that the selectors have been ordered
      here so that values smaller than 32 bits are grouped together, so that
      the data structure becomes smaller.  There can be MANY of these rules,
      so this can be a significant space saving. */
  SshUInt32 precedence; /** Precedence. */
  SshUInt32 tunnel_id; /** 0=initial, 1=tr pass, 2+: PM can use. */
  unsigned char dst_ip_low[SSH_IP_ADDR_SIZE], dst_ip_high[SSH_IP_ADDR_SIZE];
  unsigned char src_ip_low[SSH_IP_ADDR_SIZE], src_ip_high[SSH_IP_ADDR_SIZE];
  SshUInt16 dst_port_low, dst_port_high; /** Also contains ICMP type/code. */
  SshUInt16 src_port_low, src_port_high;

  SshUInt16 is_src_point_rule:1;      /** src_ip_low == src_ip_high. */
  SshUInt16 is_src_point_port_rule:1; /** src_port_low == src_port_high. */
  SshUInt16 is_dst_point_rule:1;
  SshUInt16 is_dst_point_port_rule:1;
  SshUInt16 is_src_wildcard_rule:1;
  SshUInt16 is_src_wildcard_port_rule:1;
  SshUInt16 is_dst_wildcard_rule:1;
  SshUInt16 is_dst_wildcard_port_rule:1;

  SshUInt16 protocol:4; /** SshInterceptorProtocol */

  SshUInt16 ipproto;

  /** Selectors for the policy rule.  Protected by engine->flow_table_lock. */
  SshUInt16 selectors;

  /** Next and previous rules in the list of policy rules. Engine will set
      this when the rule is installed. These field are only used in
      engine_rule_lookup_[tree|list].c. */
  struct SshEnginePolicyRuleRec *next;
  struct SshEnginePolicyRuleRec *prev;

  /*
   * End of fixed preamble
   */

  /** Flags for the policy rule.  Protected by engine->flow_table_lock. */
  SshUInt32 flags;

  /** Rule index. */
  SshUInt32 rule_index;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /** Extension selectors.  If a certain extension selector is not
     used, assign it's low value to be higher than it's high value.
     If no extension selectors are used, prefer clearing the
     corresponding 'flags'-bit. */
  SshUInt32 extension_selector_low[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
  SshUInt32 extension_selector_high[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  SshEngineIfnum selector_ifnum;

  /** VRF routing instance identifier. */
  SshVriId routing_instance_id;

#ifdef SSHDIST_IPSEC_NAT
 /** Allocate a port on nat_selector_dst_ip and set this ip:port as the
      destination selector.

      This is used in dynamic application gateway flows opened using
      ssh_appgw_open_port when going inbound through NAT. If
      nat_selector_dst_ip is defined, then upon adding the rule to the
      engine, a suitable port is allocated and stored in nat_dst_port for
      the lifetime of the rule.  This is also used in L2tp NAT traversal.

      This port can be acquired by setting the SSH_PM_ENGINE_RULE_REPORT
      flag. */
  SshIpAddrStruct nat_selector_dst_ip;

  /** New dst port and ip address to NAT any flows to; this is meaningful only
      if SSH_ENGINE_RULE_FORCE_NAT_SRC is specified. */
  SshIpAddrStruct nat_src_ip_low;

  /** New dst port and ip address to NAT any flows to; this is meaningful only
      if SSH_ENGINE_RULE_FORCE_NAT_SRC is specified. */
  SshIpAddrStruct nat_src_ip_high;

  /** New src port and ip address to NAT any flows to; this is meaningful only
      if SSH_ENGINE_RULE_FORCE_NAT_DST is specified. */
  SshIpAddrStruct nat_dst_ip_low;

  /** New src port and ip address to NAT any flows to; this is meaningful only
      if SSH_ENGINE_RULE_FORCE_NAT_DST is specified. */
  SshIpAddrStruct nat_dst_ip_high;

  /* Ports introduced here to align the structure better. */
  SshUInt16 nat_dst_port;
  SshUInt16 nat_src_port;
  SshUInt16 nat_selector_dst_port;

  SshPmNatFlags nat_flags;
#endif /* SSHDIST_IPSEC_NAT */

  /** Transform index for SSH_ENGINE_RULE_APPLY rules and for application
      gateway trigger rules.  This should be set to a valid transform index
      for APPLY rules and should be set to SSH_IPSEC_INVALID_INDEX for all
      other rules.  When the rule is on the freelist, this is the next pointer
      on the freelist. */
  SshUInt32 transform_index;

  /** When adding a rule, this must either be set to SSH_IPSEC_INVALID_INDEX
      or to a previously returned rule index.  If set to a rule index, that
      means that the new rule depends on the old rule identified by this
      field; if the old rule is later deleted, any rules that depend on it
      (and flows created by those rules) will be automatically deleted as well
      (as well as any rules that may depend on them in turn).  */
  SshUInt32 depends_on;

  /** Idle timeouts for any flows created using this rule (in seconds).  This
      must be set for all rules.  Zero means forever.  The timeout chosen is
      based on the type of flow created. UDP flows choose the
      flow_idle_datagram_timeout. */
  SshUInt32 flow_idle_datagram_timeout;

  /** Idle timeouts for any flows created using this rule (in seconds).  This
      must be set for all rules.  Zero means forever.  The timeout chosen is
      based on the type of flow created. TCP flows choose the
      flow_idle_session_timeout. */
  SshUInt32 flow_idle_session_timeout;

  /** Maximum lifetime for any flows created using this rule (in seconds).
      This must be set for all rules.  Zero means forever. */
  SshUInt32 flow_max_lifetime;

#ifdef SSH_IPSEC_STATISTICS
  /** Statistics information for the rule.  The engine will zero this when
      the rule is installed. */
  SshEngineRuleStatsStruct stats;
#endif /** SSH_IPSEC_STATISTICS */

  /** Context pointer for Policy Manager.  The value assigned to this when
      the rule is installed is copied into the engine, and will be supplied to
      the policy manager whenever the rule is returned to the policy manager
      (e.g., for rekey). There is no way for the policy manager to modify this
      value after the rule has been installed. */
  void *policy_context;

  /* Internal fields for use by Engine. ************************/

  /** Reference count for this rule.  If this is greater than zero and the
      rule is to be freed, the freeing must be delayed until the reference
      count reaches zero.  This is used e.g. during rule execution to make
      sure that the rule object remains valid even though
      engine->flow_table_lock is not held during e.g. arp lookups.  The engine
      will initialize this to one when the rule is installed; deleting a rule
      basically just means removing it from the rule data structures and
      decrementing the reference count. */
  SshUInt32 refcnt;

  /** Head pointer of a doubly linked list containing all rules that depend
     on this rule (i.e., set their depends_on field to the index of this
     rule).  This is SSH_IPSEC_INVALID_INDEX if there are no such rules. */
  SshUInt32 dependent_rules;

  /** The next point for the doubly linked list of nodes that depend
      on the 'depends_on' node.  The last next pointer of the list
      is SSH_IPSEC_INVALID_INDEX. */
  SshUInt32 dep_next;

  /** The previous point for the doubly linked list of nodes that depend
      on the 'depends_on' node.  The first prev pointer of the list
      is SSH_IPSEC_INVALID_INDEX. */
  SshUInt32 dep_prev;

  /** Head pointer for the doubly linked list of all flows created by this
      rule.  The list is linked by the flow->rule_next and flow->rule_prev
      fields.  The prev link of the first and next link of the last node are
      SSH_IPSEC_INVALID_INDEX.  This field is SSH_IPSEC_INVALID_INDEX if no
      flows have been created by the rule.

      Unlike most other fields of the rule, this field is protected by
      engine->flow_table_lock.  This field can only be accessed if the caller
      is holding a reference (refcnt) on this rule. */
  SshUInt32 flows;

  /** Index of the flow for incoming ipsec packets using the transform
      referenced by this rule's `transform_index' parameter. */
  SshUInt32 incoming_ipsec_flow;

  /** Pointer to the next rule of the trd->rules list of all rules referencing
      a trd.  This list is singly linked, with the last element being
      SSH_IPSEC_INVALID_INDEX.  Unlike most fields of the rule, this field is
      protected by engine->flow_table_lock.  This field can only be accessed
      if the caller is holding a reference (refcnt) on this rule. */
  SshUInt32 trd_next;

  /** The type of the rule.  This defines the principal action on the packets.
      This field must be set in all rules. */
  SshUInt8 type; /* SshEnginePolicyRuleType */
} SshEnginePolicyRuleStruct, *SshEnginePolicyRule;

/*
 * Transform data type definition.  Transform define the characteristics of an
 * IKE SA bundle, containing up to six SPIs (ESP in, AH in, IPCOMP in, ESP
 * out, AH out, IPCOMP out), plus tunnel mode, NAT-T, and L2TP encapsulation.
 * Normal NAT processing is part of the flow and is not described in the
 * transform record.
 */

/* Indexes to the 'spis' six-tuple. */
#define SSH_PME_SPI_ESP_IN      0       /** ESP in. */
#define SSH_PME_SPI_AH_IN       1       /** AH in. */
#define SSH_PME_SPI_IPCOMP_IN   2       /** IPComp in. */
#define SSH_PME_SPI_ESP_OUT     3       /** ESP out. */
#define SSH_PME_SPI_AH_OUT      4       /** AH out. */
#define SSH_PME_SPI_IPCOMP_OUT  5       /** IPComp out. */

/** Transform controls. */

/** Flag values for Transform control flags. */
#define SSH_ENGINE_TR_C_DPD_ENABLED                    0x0001
#define SSH_ENGINE_TR_C_IKEV1_SA                       0x0002
#define SSH_ENGINE_TR_C_RECOVERED_SA                   0x0004
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
#define SSH_ENGINE_TR_C_NATT_KEEPALIVE_ENABLED         0x0008
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

/* Mask for internal flags used by Engine. */
#define SSH_ENGINE_TR_C_INTERNAL_FLAG_MASK      0xffff0000

typedef struct SshEngineTransformControlRec
{
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  unsigned char peer_id[SSH_ENGINE_PEER_ID_SIZE];
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /** Tunnel identifier. This value is not used or modified by the engine;
      its initialization, use, and semantics are entirely up to the policy
      manager.  It can be used for example to look up the appropriate policy
      rule when a flow event is received from the transform. */
  SshUInt32 tunnel_id;

  /** Outer tunnel identifier for this transform.  All inbound IPsec packets
      for this transform are expected to arrive from this outer tunnel. The
      engine will use this value for creating the incoming IPsec flow for the
      transform.  This is set to 0 if there is no outer tunnel. */
  SshUInt32 outer_tunnel_id;

#ifdef SSH_IPSEC_STATISTICS
  /** Maximum lifetime of the transform in bytes.  This is kilobytes until a
      soft notification should be sent.  After the notification a time limit
      (SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME) only is enforced before hard
      expiration.  Note that kilobyte-based lifetime is only enforced if
      statistics are enabled. */
  SshUInt64 life_bytes;
#endif /** SSH_IPSEC_STATISTICS */

  /** Routing instance id */
  SshVriId routing_instance_id;

  /** The peer handle (policy manager managed) for the peer used when
      this was allocated. */
  SshUInt32 peer_handle;

  /** These two fields are used to implement a doubly linked hash list for the
      engine->peer_handle_hash hash table.  The peer handle hash is used to
      find all transforms/SAs that were created with the same peer handle.  The
      peer_handle_next value of the last node on the list is
      SSH_IPSEC_INVALID_INDEX, as is the peer_handle_prev value of the first
      node on the list. */
  SshUInt32 peer_handle_next;
  SshUInt32 peer_handle_prev;

  /** These two fields are used to implement a doubly linked hash list for the
      engine->peer_hash hash table.  The peer hash is used in IKE initial
      contact processing to find all transforms/SAs with the given peer.  This
      list is doubly linked to eliminate a worst case (or potential denial
      service attack) where a single peer establishes e.g.  100.000 SAs with
      us, and without a doubly linked list deleting each SA from that list
      would be a linear operation.  The peer_next value of the last node on
      the list is SSH_IPSEC_INVALID_INDEX, as is the peer_prev value of the
      first node on the list. */
  SshUInt32 peer_next;
  SshUInt32 peer_prev;

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
  /** These two fields are used to implement a doubly linked list of
      transforms requiring NAT-T keepalive messages.  The transform is linked
      to the engine's keepalive list if the `natt_flags' have the
      SSH_ENGINE_NATT_KEEPALIVE flag set.  The `natt_keepalive_next' value of
      the last node on the list is SSH_IPSEC_INVALID_INDEX, as is the
      `natt_keepalive_prev' value of the first node on the list. */
  SshUInt32 natt_keepalive_next;
  SshUInt32 natt_keepalive_prev;
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */

  /** Head pointer for a (singly) linked list of all rules referencing this
      trd.  This is SSH_IPSEC_INVALID_INDEX if there are no rules referencing
      this trd.  This list contains both those rules that have this trd as
      their first trd, and those that use a trd that chains to this trd.  This
      list is protected by engine->flow_table_lock. Note, when the transform
      is on the freelist, this is the pointer to the next node on the
      freelist. */
  SshUInt32 rules;

  /** Head pointer for a (doubly) linked list of all flows that reference this
      trd but whose rule does not reference this trd.  Note that a flow may
      reference a trd even if the rule doesn't (e.g., when the flow is created
      by the ingress filter of a tunnel). */
  SshUInt32 norule_flows;

  /** Reference count of this transform (number of flows or rules referencing
      this). A transform has references from the following sources: each rule
      referencing the transform, each flow referencing the transform, each
      packet being processed that uses the transform. This transform reference
      count should be incremented using the SSH_ENGINE_INCREMENT_TRD_REFCNT()
      macro, and decremented using the ssh_engine_decrement_transform_refcnt()
      function, and never manipulated directly. */
  SshUInt32 refcnt;

  /** Life of the transform in seconds. */
  SshUInt32 life_seconds;

#ifdef SSH_IPSEC_STATISTICS
  /** Statistics counters for the transform. */
  SshEngineTransformControlStatsStruct stats;
#endif /** SSH_IPSEC_STATISTICS */

  /** This timestamp is used for aging received path MTU information in
      transform. When SSH_ENGINE_PMTU_DEFAULT_TTL seconds have passed since
      a PMTU value was set for the transform, the 'd_trd->pmtu_received' is
      zeroed and the path MTU discovery can rediscover the value. */
  SshTime pmtu_age_time;

#ifdef SSH_IPSEC_TCPENCAP
  unsigned char tcp_encaps_conn_spi[8];
#endif /* SSH_IPSEC_TCPENCAP */

  /** Control flags. */
  SshUInt32 control_flags;

  /** The generation of this transform data object.  Every time the transform
      object is freed, its generation is incremented. */
  SshUInt8 generation;

  /** Worry metric notification has been send. Set to 0x7 on engine timeout
      handler when dpd is started, cleared when packet arrives to inbound
      processing, decremented by 1 unless zero on each timeout for the
      transform */
  SshUInt8 worry_metric_notified : 3;

  /** This timestamp is used for detecting if any packets have arrived
      for the transform since it was last time checked in engine_timeout().
      If this equals to the inbound timestamp in the d_trd then we start
      worrying about peer idleness. */
  SshTime last_in_packet_time;

  /** This timestamp is set to the time when the transform was rekeyed. It
      is used to detect when the SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED
      event should be sent to the policy manager. */
  SshTime rekeyed_time;

  /** The new outbound key material that is pending for activation. */
  unsigned char rekeyed_keymat[SSH_IPSEC_MAX_KEYMAT_LEN / 2];

} SshEngineTransformControlStruct, *SshEngineTransformControl;


typedef struct SshEngineTransformRec
{
  SshEngineTransformDataStruct data;
  SshEngineTransformControlStruct control;
} SshEngineTransformStruct, *SshEngineTransform;


/** Flag values for ssh_pme_rekey_transform_inbound(). */
/** Replace current inbound SPI value and keymaterial, do not touch old SPI. */
#define SSH_PME_REKEY_INBOUND_REPLACE               0x0001

/** Flag values for ssh_pme_rekey_transform_outbound(). */
/** Replace current outbound SPI value and keymaterial, do not
    touch old SPI. */
#define SSH_PME_REKEY_OUTBOUND_REPLACE              0x0001
/** Activate outbound SPI value and keying material immediately. */
#define SSH_PME_REKEY_OUTBOUND_ACTIVATE_IMMEDIATELY 0x0002

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
/** Virtual adapter object. Used for passing information about a virtual
    adapter in SshPmeVirtualAdapterStatusCB. */
typedef struct SshPmeVirtualAdapterRec
{
  /** Name of the virtual adapter */
  unsigned char adapter_name[SSH_INTERCEPTOR_IFNAME_SIZE];
  /** Unique interface index of the virtual adapter */
  SshUInt32 adapter_ifnum;
  /** State of the virtual adapter */
  SshVirtualAdapterState adapter_state;
} SshPmeVirtualAdapterStruct, *SshPmeVirtualAdapter;
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/* *********************************************************************
 * Callback function definitions.
 * *********************************************************************/

/** Callback function for returning completion status.  `status' is TRUE if
    the operation was successful and FALSE if it failed. */
typedef void (*SshPmeStatusCB)(SshPm pm, Boolean status,
                               void *context);

/** Callback function for returning completion status and possible allocations
    made for ssh_pme_add_rule(). If SSH_PM_ENGINE_RULE_REPORT flag was set,
    then "rule" is a pointer to the instantiated rule. If
    SSH_PM_ENGINE_RULE_REPORT was set and rule is NULL, then there was not
    enough memory to report the rule across the engine/pm interface. */
typedef void (*SshPmeAddRuleCB)(SshPm pm, SshUInt32 ind,
                                const SshEnginePolicyRule rule,
                                void *context);

/** Callback function for returning completion status and an index.  `ind' is
    the returned index on success, and SSH_IPSEC_INVALID_INDEX on failure. */
typedef void (*SshPmeIndexCB)(SshPm pm, SshUInt32 ind, void *context);

/** Callback function for returning completion status and SA rule and
    transform indexes.  The arguments `rule_index', `transform_index'
    and 'outbound_spi' are returned on success.  They have the value
    SSH_IPSEC_INVALID_INDEX on failure. */
typedef void (*SshPmeSAIndexCB)(SshPm pm,
                                const SshEnginePolicyRule rule,
                                SshUInt32 transform_index,
                                SshUInt32 outbound_spi,
                                void *context);

/** Callback function for returning rule information.  The argument `rule'
    points to a rule object if the operation was successful and has the value
    NULL if the operation failed. */
typedef void (*SshPmeRuleCB)(SshPm pm, const SshEnginePolicyRule rule,
                             void *context);

/** Callback function for returning transform data information.  The argument
    `trd' points to a transform object if the operation was successful and has
    the value NULL if the operation failed. Note that depending on the called
    function, `trd' may be only partially valid. */
typedef void (*SshPmeTransformCB)(SshPm pm, const SshEngineTransform trd,
                                  void *context);

/** Callback function for returning global statistics.  `e_stats' are the
    engine statistics, or NULL on failure, f_stats are the fastpath
    statistics or NULL on failure. The callback must copy `stats' if they
    are needed after this call. */
typedef void (*SshPmeGlobalStatsCB)(SshPm pm,
                                    const SshEngineGlobalStats e_stats,
                                    const SshFastpathGlobalStats f_stats,
                                    void *context);

/** Callback function for returning public per-flow information.  `info' is
    the information, or NULL on failure (e.g., if the flow does not exist).
    The callback must copy `info' if they are needed after this call. */
typedef void (*SshPmeFlowInfoCB)(SshPm pm, const SshEngineFlowInfo info,
                                 void *context);

/** Callback function for returning per-flow statistics.  `stats' is the
    statistics, or NULL on failure (e.g., if the flow does not exist).  The
    callback must copy `stats' if they are needed after this call. */
typedef void (*SshPmeFlowStatsCB)(SshPm pm, const SshEngineFlowStats stats,
                                  void *context);

/** Callback function for returning per-transform statistics.  `stats' is the
    statistics, or NULL on failure (e.g., if the rule does not exist).  The
    callback must copy `stats' if they are needed after this call. */
typedef void (*SshPmeTransformStatsCB)(SshPm pm,
                                       const SshEngineTransformStats stats,
                                       void *context);

/** Callback function for returning per-rule statistics.  `stats' is the
    statistics, or NULL on failure (e.g., if the rule does not exist).  The
    callback must copy `stats' if they are needed after this call. */
typedef void (*SshPmeRuleStatsCB)(SshPm pm, const SshEngineRuleStats stats,
                                  void *context);


/** Callback function that is called when ssh_pme_delete_rule completes.  If
    the rule has now been deleted and no flows or dependent rules remain,
    `done' is TRUE.  If `done' is false, that means that the rule has not yet
    been deleted, and one or more flows and/or dependent rules remain.

    When the callback is called (regardless of whether `done' is TRUE or
    FALSE), the argument `tr' provides information that can be used to
    send a delete notification to the peer. If `tr' is NULL, then no
    notifications should be sent for this call.

    Ssh_pme_delete_rule should be called repeatedly until `done' becomes TRUE;
    `rule_index' is the rule index that was supplied to ssh_pme_delete_rule,
    and can be used to continue the deletion process.

    If an internal error occurs in ssh_pme_delete_rule then this function is
    called with `rule_index' and `peer_handle' set to SSH_IPSEC_INVALID_INDEX.
*/
typedef void (*SshPmeDeleteCB)(SshPm pm, Boolean done,
                               SshUInt32 rule_index,
                               SshUInt32 peer_handle,
                               SshEngineTransform tr,
                               void *context);

/** Callback function that is called when ssh_pme_delete_by_peer_handle
    completes.  If all transforms have now been deleted `done' is TRUE.
    If `done' is FALSE, that means that not all transforms have yet been
    deleted.

    When the callback is called (regardless of whether `done' is TRUE or
    FALSE), the argument `tr' provides information that can be used to
    send a delete notification to the peer. If `tr' is NULL, then no
    notifications should be sent for this call.

    Ssh_pme_delete_by_peer_handle should be called repeatedly until `done'
    becomes TRUE; `policy_context' can be used by the policy manager to find
    the policy level rule corresponding to the transform which has been
    deleted.

    If an internal error occurs in ssh_pme_delete_by_peer_handle then this
    function is called with `peer_handle' set to SSH_IPSEC_INVALID_INDEX. */
typedef void (*SshPmeDeleteTransformCB)(SshPm pm, Boolean done,
                                        SshUInt32 peer_handle,
                                        SshEngineTransform tr,
                                        void *policy_context,
                                        void *context);

/*  Bit masks for the SshPmeRouteCB 'flags' argument. */
#define SSH_PME_ROUTE_REACHABLE         0x01 /** Some route applies. */
#define SSH_PME_ROUTE_LOCAL             0x02 /** dst is our own IP address. */
#define SSH_PME_ROUTE_LINKBROADCAST     0x08 /** Link-local broadcast. */

/** Callback function that is called when ssh_pme_route completes.  flags &
    SSH_PME_ROUTE_REACHABLE is set if a route exists for the destination.
    `ifnum' will be set to its interface number, `next_hop' to the IP address
    of the next hop gateway, `mtu' to the MTU to the destination (link MTU or
    possibly Path MTU if known). */
typedef void (*SshPmeRouteCB)(SshPm pm, SshUInt32 flags,
                              SshUInt32 ifnum, const SshIpAddr next_hop,
                              size_t mtu, void *context);

/** Callback function that is called when ssh_pme_route_add or
    ssh_pme_route_remove completes. */
typedef void (*SshPmeRouteSuccessCB)(SshPm pm,
                                     SshInterceptorRouteError error,
                                     void *context);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

/** Callback function that is called when either ssh_pme_virtual_adapter_list
    or ssh_pme_virtual_adapter_configure completes. The argument `error'
    describes the success of the operation.
    If `error' is SSH_VIRTUAL_ADAPTER_ERROR_OK, the argument `adapters'
    contains `num_adapters' SshPmeVirtualAdapter objects. All arguments
    are valid only for the duration of the callback. */
typedef void (*SshPmeVirtualAdapterStatusCB)(SshPm pm,
                                             SshVirtualAdapterError error,
                                             SshUInt32 num_adapters,
                                             SshPmeVirtualAdapter adapters,
                                             void *context);

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

/* *********************************************************************
 * Opening the engine from the policy manager.  These functions are
 * implemented in the policy manager, and are called from the policy
 * manager only.  No special locking is needed in/for these functions.
 * *********************************************************************/

/** Try to open the connection to the Engine.  If successful, then this
    calls 'callback' with TRUE; otherwise this calls the callback with FALSE.

    This function sets pm->engine if successful.

    @param machine_context
    Specifies which engine to connect (e.g., "/dev/sshengine",
    "/proc/sshipsec/sshengine" or "/tmp/sshengine").  For UNIX, it is
    the path name of the device or socket used to communicate with the
    Engine.  For other platforms it can be anything defined by the
    platform; its semantics are completely platform-specific.

    @param flags
    Flags to the Engine (as defined for ssh_engine_start in engine.h).

    */
void ssh_pm_connect_engine(SshPm pm, void *machine_context, SshUInt32 flags,
                           SshUInt16 nat_port_range_low,
                           SshUInt16 nat_port_range_high,
                           SshUInt16 nat_privileged_port_range_low,
                           SshUInt16 nat_privileged_port_range_high,
                           SshUInt16 num_ike_ports,
                           SshUInt16 *local_ike_ports,
                           SshUInt16 *local_ike_natt_ports,
                           SshUInt16 *remote_ike_ports,
                           SshUInt16 *remote_ike_natt_ports,
                           SshPmeStatusCB callback, void *context);

/** Close the connection to the Engine.  This starts closing the engine, the
    engine connection is closed when the callback gets called. This may hapen
    from call invocation or any time later.  */
void ssh_pm_disconnect_engine(SshPm pm,
                              SshPmeStatusCB callback, void *context);

/** Sends the random salt to the Engine. */
void ssh_pm_salt_to_engine(SshPm pm, SshUInt32 salt[4]);

/* *********************************************************************
 * Functions in the engine that can be called from the policy manager.
 * The engine assumes that only one call at a time is executing one of
 * these functions in the engine (however, packet processing and
 * timeouts may be executing concurrently with that call).  The
 * implementation of these functions is not allowed to call the
 * ssh_pm_pmp_* functions directly.  It is illegal to call any one of
 * these functions from the callback function of another one of these
 * functions.
 * *********************************************************************/

/*  Flags for ssh_pme_process_packet().*/
#define SSH_PME_PACKET_NOTRIGGER        0x00000001 /** Don't trigger on this.*/
#define SSH_PME_PACKET_MEDIABCAST       0x00000002 /** Was media bcast. */
#define SSH_PME_PACKET_LOCAL            0x00000004 /** From local stack. */
#define SSH_PME_PACKET_SESSION_TRIGGER  0x00000008 /** Generated by "dangling"
                                                       non-appgw trigger
                                                       flow. */
#define SSH_PME_PACKET_APPGW_TRIGGER    0x00000010 /** Generated by appgw
                                                       trigger flow. */
#define SSH_PME_PACKET_WASFRAG          0x00000020 /** copy of the flag
                                                       SSH_ENGINE_P_WASFRAG. */
#define SSH_PME_PACKET_DONT_REPROCESS   0x00000040 /** If set, then
                                                       ssh_pme_process_packet
                                                       is a no-op. */
#define SSH_PME_PACKET_HWCKSUM          0x00000080 /** Checksum done in HW. */
#define SSH_PME_PACKET_RESTARTED_OUT    0x00000100 /** Copy of the pc flag
                                                SSH_ENGINE_PC_RESTARTED_OUT. */
#define SSH_PME_PACKET_IP4HDRCKSUMOK    0x00000200 /** Checksum for IPv4 hdr
                                                       is ok. */
#define SSH_PME_PACKET_IP4HHWCKSUM      0x00000400 /** Checksum for IPv4 hdr
                                                       is computed in HW. */
#define SSH_PME_PACKET_FRAG_ALLOWED     0x00000800 /** Fragmentation was
                                                       allowed for this
                                                       packet. */

/*  Flags for ssh_pme_find_transform_rule(). */
#define SSH_PME_TRANSFORM_PER_PORT_SRC  0x00000001 /** Require per-port src. */
#define SSH_PME_TRANSFORM_PER_PORT_DST  0x00000002 /** Require per-port dst. */
#define SSH_PME_MATCH_INACTIVE_RULES    0x00000004 /** Match inactive rules. */
#define SSH_PME_MATCH_TRIGGER_RULES     0x00000008 /** Match trigger rules. */
#define SSH_PME_REQUIRE_POLICY_CONTEXT  0x00000010 /** Require policy ctx. */
#define SSH_PME_MATCH_PEER_ID           0x00000020 /** Internal engine flag. */
#define SSH_PME_TRANSFORM_L2TP_PEER     0x00000040 /** L2TP rule search. */

/*  Flags for ssh_pme_find_matching_transform_rule(). */
#define SSH_PME_RULE_MATCH_ANY_IFNUM      0x00000001 /** Don't match ifnum. */
#define SSH_PME_RULE_MATCH_IKEV1          0x00000002 /** Match only IKEv1 SAs*/
/** Internal Engine flag. */
#define SSH_PME_RULE_MATCH_PEER_ID        0x00000004

/*  Flags for ssh_pme_route(). */
#define SSH_PME_ROUTE_F_SYSTEM  0x00000001 /** Use system routing table. */

/*  Flags for ssh_pme_arp_add(). */
#define SSH_PME_ARP_PERMANENT   0x00000001 /** Add a permanent entry. */
#define SSH_PME_ARP_PROXY       0x00000002 /** Do proxy ARP for the address. */
#define SSH_PME_ARP_GLOBAL      0x00000004 /** Mapping is active on all
                                               interfaces. */
/** Parameter type for ssh_pme_flow_set_status(). */
typedef enum
{
  /** Pass packets through */
  SSH_PME_FLOW_PASS = 0,

  /** Drop all */
  SSH_PME_FLOW_DROP = 1,

  /** Reject inbound */
  SSH_PME_FLOW_REJECT_INBOUND = 2,

  /** Drop all and set expiry */
  SSH_PME_FLOW_DROP_EXPIRE = 3
} SshPmeFlowStatus;

/** Currently recognized packet level attacks */
typedef enum
{
  SSH_ENGINE_ATTACK_LAND = 0,                   /** Land. */
  SSH_ENGINE_ATTACK_FRAGMENT_DEATH = 1,         /** Fragment death. */
  SSH_ENGINE_ATTACK_SMURF = 2,                  /** Smurf. */
  SSH_ENGINE_ATTACK_FRAGGLE = 3,                /** Fraggle. */
  SSH_ENGINE_ATTACK_TRACEROUTE = 4,             /** Traceroute. */
  SSH_ENGINE_ATTACK_XMAS_SCAN = 5,              /** Christmas Scan. */
  SSH_ENGINE_ATTACK_NULL_SCAN = 6,              /** NULL scan. */
  SSH_ENGINE_ATTACK_FIN_SCAN = 7,               /** FIN scan. */

  SSH_ENGINE_ATTACK_POD = 4,                    /** Pod. */
  SSH_ENGINE_ATTACK_NESTEA = 5,                 /** Nestea. */
  SSH_ENGINE_ATTACK_TEARDROP = 6,               /** Teardrop. */
  SSH_ENGINE_ATTACK_BONK = 7,                   /** Bonk. */
  SSH_ENGINE_ATTACK_BOINK = 8,                  /** Boink. */
  SSH_ENGINE_ATTACK_MAX = 9,                    /** Max. */
  SSH_ENGINE_ATTACK_NONE = 10,                  /** None. */


  SSH_ENGINE_ATTACK_INTERNAL_ERROR = 255        /** Internal error. */
} SshEngineAttackPacketType;


/* Flag values for validity_flags in SshEngineAuditEvent. */
#define SSH_ENGINE_AUDIT_NONVALID_PORTS    0x01 /** Port info is not valid. */
#define SSH_ENGINE_AUDIT_NONVALID_TCPFLAGS 0x02 /** TCP flags are not valid. */

/** Structure for containing relevant state related to audit events. */
typedef struct SshEngineAuditEventRec
{
  /** Engine pointer. */
  SshEngine engine;

  /** The id of this audit event, this value is incremented for every
      audit event the engine sends to the PM. */
  SshUInt32 audit_id;

  /** From-tunnel id. */
  SshUInt32 from_tunnel_id;

  /** To-tunnel id. */
  SshUInt32 to_tunnel_id;

  /** Packet corruption reason. */
  SshUInt32 packet_corruption;

  /** Packet attack. */
  SshUInt32 packet_attack;

  /** SPI. */
  SshUInt32 spi;

  /** Sequence number. */
  SshUInt32 seq;

  /** Flow label for IPv6, 0 if not set. */
  SshUInt32 flowlabel;

  /** Actual event. */
  SshAuditEvent event;

  /** Flow ifnum: source. */
  SshEngineIfnum src_ifnum;

  /** Flow ifnum: destination. */
  SshEngineIfnum dst_ifnum;

  /** Flow IP: source. */
  SshIpAddrStruct src_ip;

  /** Flow IP: destination. */
  SshIpAddrStruct dst_ip;

  /** Flow port: source. */
  SshUInt16 src_port;

  /** Flow port: destination. */
  SshUInt16 dst_port;

  /** Space for related timeout instance. */
  SshTimeoutStruct tmout_struct;

  /** Media header. */
  unsigned char mediahdr[SSH_MAX_MEDIAHDR_SIZE];
  size_t mediahdr_len;

  /** Packet data. */
  unsigned char *packet;

  /** Packet length. */
  size_t packet_len;

  /** Real length of the packet, can be larger than packet_len. */
  size_t real_packet_len;

  /** Flow ipproto. */
  SshUInt8 ipproto;

  /** Flags indicating whether certain information in the audit event is not
      valid, a bit mask of the SSH_ENGINE_AUDIT_NONVALID_ flags. */
  SshUInt8 validity_flags;

  /** ICMP stuff: type. */
  SshUInt8 icmp_type;

  /** ICMP stuff: code. */
  SshUInt8 icmp_code;

  /** TCP flags */
  SshUInt8 tcp_flags;

  /** IPv4 option */
  SshUInt8 ipv4_option;
} *SshEngineAuditEvent, SshEngineAuditEventStruct;


/*  Flags for the SshPmeAuditCB callback. These flags give other information
    to the policy manager about the engine audit subsystem which do not
    correspond to actual audit events, such as the failure of the engine to
    audit a certain event. */

#define SSH_ENGINE_AUDIT_RATE_LIMITED_EVENT     0x00000001  /** Audit rate
                                                                limiting has
                                                                been seen. */
#define SSH_ENGINE_AUDIT_EVENT_FAILURE          0x00000004 /** The engine could
                                                               not audit an
                                                               event (resource
                                                               shortage). */

/** Callback function that is called when ssh_pme_get_audit_events
    completes. If 'more_events' is TRUE then the engine has more audit events
    that it can deliver to the policy manager, however the engine will not
    deliver them unless explicitly requested to, via another call from the
    policy manager to ssh_pme_get_audit_events(). 'flags' contains other
    auditing information of interest to the policy manager besides the actual
    audit events. 'num_events' is the number of events that the engine is
    returning to the policy manager. The audit events are returned in
    'events', which points to an array of 'num_events'
    SshEngineAuditEventStruct objects. */
typedef void (*SshPmeAuditCB)(SshPm pm, Boolean more_events,
                              SshUInt32 flags,
                              SshUInt32 num_events,
                              const SshEngineAuditEvent events,
                              void *context);

#ifdef SSH_IPSEC_TCPENCAP
/** The length of the IPsec over TCP encapsulation trailer. */
#define SSH_ENGINE_TCP_ENCAPS_TRAILER_LEN 16
#endif /* SSH_IPSEC_TCPENCAP */

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

/** Configure certain parameters that control the behaviour of the engine. If
    params == NULL, then default parameters are set. */
void ssh_pme_set_engine_params(SshEngine engine,
                               const SshEngineParams pm_params);

/** Prevents the creation of new flows until ssh_pme_enable_policy_lookup is
    called.  This may either drop or delay all packets that would result in a
    policy rule lookup.  This can be used by the policy manager to implement
    semi-atomic policy update by disabling policy lookups while the policy is
    being updated, re-enabling it after all new rules have been added and old
    rules deleted. It is not recommended to disable policy lookups for any
    extended periods of time. Callback is called with the updated status.
    I.e. after this call is successful, the status is 0, meaning disabled. */
void ssh_pme_disable_policy_lookup(SshEngine engine,
                                   SshPmeStatusCB callback,
                                   void *context);

/** Re-enables policy lookups after ssh_pme_disable_policy_lookup has been
    used.  If the engine implemented queuing for the packets, this causes the
    queued packets to be processed. Callback is called with the updated status.
    I.e. after this call is successful, the status is 0, meaning disabled.*/
void ssh_pme_enable_policy_lookup(SshEngine engine,
                                  SshPmeStatusCB callback,
                                  void *context);

/** Sets debug level in the engine.  Debugging messages will be passed
   to the policy manager.  The format of `level_string' is that
   expected by ssh_debug_set_level_string.  This may set engine debug
   level globally for all engines in the system. */
void ssh_pme_set_debug_level(SshEngine engine, const char *level_string);

/** Sends the packet to the engine for reprocessing. The engine processes the
    packet as if it had just arrived from the network (or local TCP/IP stack).
    This function may operate unreliably (i.e., the engine may not actually
    get the call).  This will copy `data' if this needs it after returning.
    This function is primarily inteded for use with trigger for submitting the
    triggering packet back to processing after the trigger has been
    handled. */
void ssh_pme_process_packet(SshEngine engine,
                            SshUInt32 tunnel_id,
                            SshInterceptorProtocol protocol,
                            SshUInt32 ifnum,
                            SshVriId routing_instance_id,
                            SshUInt32 flags,
                            SshUInt32 prev_transform_index,
                            const unsigned char *data,
                            size_t len);

#ifdef SSHDIST_IPSEC_NAT
/* ************* Creating and configuring NAT domains ***************/

/** Specifies what kind of NAT, if any, is used for the given interface.  This
    can be used to modify the setting later. */
void ssh_pme_set_interface_nat(SshEngine engine,
                               SshUInt32 ifnum,
                               SshPmNatType type,
                               SshPmNatFlags flags,
                               const SshIpAddr host_nat_int_base,
                               const SshIpAddr host_nat_ext_base,
                               SshUInt32 host_nat_num_ips);

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/** Configures an IP address pool that is used in NAT-T internal NAT to make
    clients unique. */
void ssh_pme_configure_internal_nat(SshEngine engine,
                                    const SshIpAddr first_ip,
                                    const SshIpAddr last_ip,
                                    SshPmeStatusCB callback, void *context);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

/* ********************* Manipulating transform objects **********************/

/** Creates a transform record in the engine.  The `params' argument selects
    algorithms and key material for AH, ESP, and IPCOMP transforms.  Engine
    run-time fields need not be initialized.

    The transform record can be used in rules added by ssh_pme_add_rule.  The
    same transform data can be used in both directions (for all rules/flows
    created by a bundle).  Normally the system will automatically free
    transform records when they are no longer referenced from ipsec flows or
    rules; however, if creating the flow and rule fails, then the
    ssh_pme_delete_transform function should be used to free it.

    The `params' structure should be initialized to describe the transform.
    This will copy it to internal data structures.  `life_seconds' and
    `life_kilobytes' specify the maximum lifetime of the SA in seconds and in
    transferred kilobytes.  Valid values must always be specified for them;
    the engine has no defaults for these. The kilobyte-based lifetime
    is ignored if SSH_IPSEC_STATISTICS is not defined.

    This calls `callback' with `context' and transform index if successful,
    and with SSH_IPSEC_INVALID_INDEX on error. If SSH_PM_ENGINE_RULE_REPORT is
    set, then the instantiated rule is passed also. */
void ssh_pme_create_transform(SshEngine engine,
                              SshEngineTransform params,
                              SshUInt32 life_seconds,
                              SshUInt32 life_kilobytes,
                              SshPmeIndexCB callback, void *context);

/** Deletes a transform record from the engine.  Note that this should only
   be called if creating flow/rule using the transform index fails; normally
   the record is freed automatically when its reference count decrements
   to zero.  When the transform is created with ssh_pme_create_transform, its
   reference count is set to one.  That reference gets transferred to the
   rule when ssh_pme_add_rule is called. */
void ssh_pme_delete_transform(SshEngine engine, SshUInt32 transform_index);

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
    SSH_ENGINE_TR_C_REKEY_PENDING flag.

    On error this calls `callback' with argument `trd' set to NULL. On
    success the argument `trd' contains a partially valid transform data.
    If the engine was forced to destroy any SPIs to accommodate the new
    values, then `trd->spis' or `trd->old_spis' contains the values.
    Otherwise both SPI arrays are zeroed. */
void ssh_pme_rekey_transform_inbound(SshEngine engine,
                                     SshUInt32 transform_index,
                                     const SshUInt32 new_in_spis[3],
                                     const unsigned char
                                     keymat_in[SSH_IPSEC_MAX_KEYMAT_LEN / 2],
                                     SshUInt32 life_seconds,
                                     SshUInt32 life_kilobytes,
                                     SshUInt32 flags,
                                     SshPmeTransformCB callback,
                                     void *context);

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
    this.

    On success this calls `callback' with `status' set to TRUE. */
void ssh_pme_rekey_transform_outbound(SshEngine engine,
                                      SshUInt32 transform_index,
                                      const SshUInt32 new_out_spis[3],
                                      const unsigned char
                                      keymat_out[SSH_IPSEC_MAX_KEYMAT_LEN/2],
#ifdef SSH_IPSEC_TCPENCAP
                                      unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                      SshUInt32 flags,
                                      SshPmeStatusCB callback, void *context);

/** Clears old SPI value from transform and resets old flow id from all
    related incoming IPsec flows.

    On error this calls `callback' with argument `trd' set to NULL. On
    success the argument `trd' contains a partially valid transform data
    with the destroyed SPI values set in `trd->old_spis'. The current SPI
    values in `trd->spis' are zeroed. */
void ssh_pme_transform_invalidate_old_inbound(SshEngine engine,
                                              SshUInt32 transform_index,
                                              SshUInt32 inbound_spi,
                                              SshPmeTransformCB callback,
                                              void *context);

#ifdef SSHDIST_L2TP
/** Updates L2TP parameters for the transform `transform_index'.  The argument
    `flags' is a bitmap of the `SSH_ENGINE_L2TP_*' flags.  The arguments
    `local_tunnel_id', `local_session_id', `remote_tunnel_id', and
    `remote_session_id' specify the local and remote L2TP tunnel and session
    IDs respectively. */
void ssh_pme_update_transform_l2tp_info(SshEngine engine,
                                        SshUInt32 transform_index,
                                        SshUInt8 flags,
                                        SshUInt16 local_tunnel_id,
                                        SshUInt16 local_session_id,
                                        SshUInt16 remote_tunnel_id,
                                        SshUInt16 remote_session_id);
#endif /* SSHDIST_L2TP */

/* ******************** Creating and manipulating rules **********************/

/** This adds the rule `pm_rule' in the engine.

    Any information in `pm_rule' is copied to internal data structures.  If
    the rule is a SSH_ENGINE_RULE_APPLY rule for a transform, then this also
    creates an inbound flow for processing inbound packets
    (pm_rule->transform_index must be valid, and the `inbound_tunnel_id' field
    of the transform record is used to specify tunnel id for inbound firewall
    processing for packets coming in from the tunnel).  The `dependency' field
    of the rule should be set to either SSH_IPSEC_INVALID_INDEX or to a valid
    rule index returned by a previous call to ssh_pme_add_rule.  If set to a
    rule index, that means that the new rule will depend on the old rule, and
    will be deleted as well if the old rule is later deleted.  If 'rekey' is
    TRUE then this rule is being installed as a result of an IPSec rekey
    operation.

    This calls `callback' with `context' and the rule index is successful, and
    with SSH_IPSEC_INVALID_INDEX if the rule could not be added. */
void ssh_pme_add_rule(SshEngine engine, Boolean rekey,
                      const SshEnginePolicyRule rule,
                      SshPmeAddRuleCB callback, void *context);

/** This frees the specified rule and any flows created by it from the
    engine.

    If there are any other rules that depend on the rule (i.e., rules that set
    their `depends_on' field to `rule_index'), those rules (and any flows
    created by them) are removed from the engine. If the callback function
    `callback' is specified, it is called to notify when the rule deletion is
    complete.

    If the callback function has the value NULL_FNPTR, the function silently
    deletes the rule, its flows, and rules depending on it. */
void ssh_pme_delete_rule(SshEngine engine,
                         SshUInt32 rule_index,
                         SshPmeDeleteCB callback, void *context);

/** Tries to find an SSH_ENGINE_RULE_APPLY rule that would match a packet with
    the given tunnel id, interface number, source address, destination
    address, IP protocol, and port numbers (port numbers are ignored if the
    protocol does not have them).

    Furthermore, rules with the SSH_ENGINE_NO_FLOW flag are ignored.  If the
    `impl_tunnel_id' is non-zero, the function matches only rules which apply
    a transform, implementing the tunnel ID `impl_tunnel_id'.  If the
    `trd_index' has a valid transform index value (not
    SSH_IPSEC_INVALID_INDEX), the function matches only rules which apply the
    specified transform.  The argument `flags' specify additional match
    criteria for the transform rule.

    If a matching APPLY rule is found, this calls the callback with the rule
    and transform data indexes of the highest precedence rule that matches.
    If no rule matches, then this calls the callback with
    SSH_IPSEC_INVALID_INDEX as the index arguments.

    The call to the callback may occur either during the call to this function
    or some time later. */
void ssh_pme_find_transform_rule(SshEngine engine,
                                 SshUInt32 tunnel_id,
                                 SshUInt32 ifnum,
                                 const SshIpAddr src_ip,
                                 const SshIpAddr dst_ip,
                                 SshUInt8 ipproto,
                                 SshUInt16 src_port,
                                 SshUInt16 dst_port,
                                 SshUInt32 impl_tunnel_id,
                                 SshUInt32 trd_index,
                                 SshUInt32 flags,
                                 SshPmeSAIndexCB callback, void *context);

/** Determines whether we have a matching apply rule already in the engine.

    The rule must match the same selectors and have the same precedence value.
    The argument `transform' specifies on optional transform specification for
    the apply rule's transform.  If it is non-null, the transform bits in the
    apply rule's transform must match exactly to `transform'. If 'peer_ip' is
    non-null and defined, then this is matched against the transform
    'gw_addr'. If 'peer_id' is non-null and defined, then it is matched
    against the transform 'peer_id' (requires NAT_TRAVERSAL support). This
    function is intended for determining whether a Quick-Mode responder
    negotiation is a rekey or it establishes a new SA.

    This calls the callback with the rule and transform data indexes of the
    matching rule or with the value SSH_IPSEC_INVALID_INDEX if there is no
    matching rule.  The call to the callback may occur either during the call
    to this function or some time later. */
void ssh_pme_find_matching_transform_rule(SshEngine engine,
                                          const SshEnginePolicyRule rule,
                                          SshPmTransform transform,
                                          SshUInt32 cipher_key_size,
                                          const SshIpAddr peer_ip,
                                          const SshIpAddr local_ip,
                                          SshUInt16 local_port,
                                          SshUInt16 remote_port,
                                          const unsigned char *peer_id,
                                          SshUInt32 flags,
                                          SshPmeSAIndexCB callback,
                                          void *context);

/** Determines whether we have a transform that specifies the given `ip_addr'
    (and remote IKE port in remote_ike_port) as the address of the peer.

    This intended for determining whether to send initial contact
    notifications or not when creating a new Phase 1 IKE SA.  This calls the
    callback with TRUE if such a transform exists, and with FALSE if one does
    not exist (either during this call or at some later time). */
void ssh_pme_have_transform_with_peer(SshEngine engine,
                                      const SshIpAddr ip_addr,
                                      SshUInt16 remote_ike_port,
                                      SshPmeStatusCB callback, void *context);

/** Deletes a transform record from the engine. This is called by the policy
    manager after receiving a delete notification message from an IKE peer.
    This frees the transform and all flows and rules referencing it, and
    all of their dependent rules and flows.

    If the callback function `callback' is set, the function calls the
    callback to notify the success of the operation. If the callback argument
    `trd' is non-NULL, the SA was found from the engine and it was deleted.
    The argument `trd' contains a partially valid transform data with the
    destroyed SPI values set.

    If the `trd' is NULL, the SA did not exist in the engine or the SA could
    not be deleted because of a parallel ongoing engine operation. */
void ssh_pme_delete_by_spi(SshEngine engine, SshUInt32 transform_index,
                           SshPmeTransformCB callback, void *context);

/** This frees all SSH_ENGINE_RULE_APPLY rules and all flows with a transform
    that have their trc->peer_handle equal to `peer_handle'.  This
    function should be called whenever an IKEv2 SA is destroyed, it will
    remove all IPSec SA's created by that IKE SA.

    This is designed to work iteratively: the policy manager should call this
    to delete transforms belonging to the IKE SA, and this will call
    `callback' back. Ssh_pme_delete_by_peer_handle should be called repeatedly
    until `done' becomes TRUE. See the documentation for the
    SshPmeDeleteTransformCB callback for more information. */
void ssh_pme_delete_by_peer_handle(SshEngine engine,
                                   SshUInt32 peer_handle,
                                   SshPmeDeleteTransformCB callback,
                                   void *context);

/** This function updates the IPsec SA's that were created using
    'peer_handle'. The IPsec SA's are updated to use new the IP
    addresses and NAT-T remote port supplied by this call. The 'local_ip'
    and 'remote_ip' parameters must be defined. If the 'natt_port'
    parameter is zero this implies that NAT-T UDP encapsulation is not to
    be performed for the updated IPsec SA's. This calls the 'callback' when
    all the SA's have been processed. */
void ssh_pme_update_by_peer_handle(SshEngine engine,
                                   SshUInt32 peer_handle,
                                   Boolean enable_natt,
                                   SshVriId routing_instance_id,
                                   SshIpAddr local_ip,
                                   SshIpAddr remote_ip,
                                   SshUInt16 remote_port,
#ifdef SSH_IPSEC_TCPENCAP
                                   unsigned char *tcp_encaps_conn_spi,
#endif /* SSH_IPSEC_TCPENCAP */
                                   SshPmeStatusCB callback, void *context);

/** Retrieves the rule object of the give rule index from the engine.  The
    callback function `callback' will be called with `context' and `rule'
    either during this call or later.  If the rule index is invalid, then
    `rule' will be NULL.  The callback should copy all relevant fields of the
    returned rule object if they are needed after the call. */
void ssh_pme_get_rule(SshEngine engine, SshUInt32 rule_index,
                      SshPmeRuleCB callback, void *context);

/** Retrieves the transform object of the given transform index from the
    engine.  The callback function `callback' will be called with `context'
    and `trd' either during this call or later.  If the transform index is
    invalid, then `trd' will be NULL.  The callback should copy all relevant
    fields of the returned transform object if they are needed after this
    call. */
void ssh_pme_get_transform(SshEngine engine, SshUInt32 trd_index,
                           SshPmeTransformCB callback, void *context);

/** Adds one extra reference to the rule `rule_index' from the policy manager.
    This has the same effect as setting the SSH_ENGINE_RULE_PM_REFERENCE when
    the rule is created.  When the extra reference is added, the rule will not
    be deleted from the engine (by delete or initial contact notifications)
    until policy manager explicitly deletes the rule by calling
    ssh_pme_delete_rule for the rule.  If the argument `transform_index' is
    valid (not SSH_IPSEC_INVALID_INDEX), then the funtion will make an extra
    check that the rule index `rule_index' points to a valid apply rule
    applying the transform `transform_index'.  The function calls the callback
    function `callback' to notify the success of the operation.  If the
    `status' is TRUE, the rule (and optional transform) were valid and an
    extra reference was added.  If the `status' is FALSE, then the operation
    failed, either because the `rule_index' and `transform_index' specified an
    invalid rule or the rule already had an extra reference from the policy
    manager. */
void ssh_pme_add_reference_to_rule(SshEngine engine, SshUInt32 rule_index,
                                   SshUInt32 transform_index,
                                   SshPmeStatusCB callback, void *context);

#ifdef SSH_IPSEC_STATISTICS

/* ************ Querying statistics information from the engine **************/

/** Retrieves global statistics information from the engine. `callback' will
    be called with `context' and `stats' either during this call or later; if
    the statistics could not be retrieved, then `stats' will be NULL.  The
    callback should copy the statistics if they are needed after the call. */
void ssh_pme_get_global_stats(SshEngine engine,
                              SshPmeGlobalStatsCB callback, void *context);

/** Retrieves the index of the next valid flow following the flow
    `flow_index'.  If the `flow_index' has the value SSH_IPSEC_INVALID_INDEX,
    the function returns the index of the first valid flow in the engine.  The
    function returns the flow index by calling the callback function
    `callback' during this call or later. */
void ssh_pme_get_next_flow_index(SshEngine engine,
                                 SshUInt32 flow_index,
                                 SshPmeIndexCB callback,
                                 void *context);

/** Retrieves public information about the given flow from the engine.
    `callback' will be called with `context' and `info' either during this
    call or later; if the flow index is invalid, then `info' will be NULL.
    The callback should copy the info if they are needed after the call. The
    flow_index may be wrapped, but it does not have to be. */
void ssh_pme_get_flow_info(SshEngine engine, SshUInt32 flow_index,
                           SshPmeFlowInfoCB callback, void *context);

/** Retrieves statistics information for the given flow from the engine.
    `callback' will be called with `context' and `stats' either during this
    call or later; if the flow index is invalid, then `stats' will be NULL.
    The callback should copy the statistics if they are needed after the
    call. */
void ssh_pme_get_flow_stats(SshEngine engine, SshUInt32 flow_index,
                            SshPmeFlowStatsCB callback, void *context);

/** Retrieves the index of the next valid transform following the transform
    `transform_index'.  If the `transform_index' has the value
    SSH_IPSEC_INVALID_INDEX, the function returns the index of the first valid
    transform in the engine.  The function returns the transform index by
    calling the callback function `callback' during this call or later. */
void ssh_pme_get_next_transform_index(SshEngine engine,
                                      SshUInt32 transform_index,
                                      SshPmeIndexCB callback,
                                      void *context);

/** Retrieves statistics information for the given transform from the engine.
    `callback' will be called with `context' and `stats' either during this
    call or later; if the transform index is invalid, then `stats' will be
    NULL.  The callback should copy the statistics if they are needed after
    the call. */
void ssh_pme_get_transform_stats(SshEngine engine, SshUInt32 transform_index,
                                 SshPmeTransformStatsCB callback,
                                 void *context);

/** Retrieves the index of the next valid rule following the rule
    `rule_index'.  If the `rule_index' has the value SSH_IPSEC_INVALID_INDEX,
    the function returns the index of the first valid rule in the engine.  The
    function returns the rule index by calling the callback function
    `callback' during this call or later. */
void ssh_pme_get_next_rule_index(SshEngine engine,
                                 SshUInt32 rule_index,
                                 SshPmeIndexCB callback,
                                 void *context);

/** Retrieves statistics information for the given rule from the engine.
    `callback' will be called with `context' and `stats' either during this
    call or later; if the rule_index is invalid, then `stats' will be NULL.
    The callback should copy the statistics if they are needed after the
    call. */
void ssh_pme_get_rule_stats(SshEngine engine, SshUInt32 rule_index,
                            SshPmeRuleStatsCB callback, void *context);
#endif /** SSH_IPSEC_STATISTICS */

/* ********************* Routing information functions ***********************/

/** Routes to the destination IP address using `key' as input for the engine.

    The argument `flags' specifies optional arguments for the route operation.
    The argument `key' specifies the routing key selectors by what the
    route lookup is performed. */
void ssh_pme_route(SshEngine engine, SshUInt32 flags,
                   SshInterceptorRouteKey key,
                   SshPmeRouteCB callback, void *context);

/** Adds a route to `key->dst' through interface `ifnum' or gateway `gateway'.

    The netmask of the destination network (or host) must be set to the mask
    length of the IP address `key->dst'.

    The argument `key' specifies the route prefix and routing key selectors.

    The argument `ifnum' specifies the outbound interface for interface
    routes. It can have the value SSH_INVALID_IFNUM, in which
    case the interface is ignored ignored and a gateway route is created.
    In the former case, the argument `gateway' is ignored.

    The argument `gateway' can either be a real gateway in a local network,
    or it can specify a local interface IP address. The later case declares
    that the network `ip' (including netmask) is directly reachable in the
    network which interface address the gateway address is. The mask length
    of the argument `gateway' is ignored.

    The argument `precedence' defines the precedence of the route in the
    routing table. The engine sets the route metric such that this route and
    the existing system routes are handled in the order of the specified
    precedence when performing route lookups either from Quicksec or external
    any program.

    The argument `flags' specifies flags for the route add operation.
    See `interceptor.h' for defined flag values (SSH_INTERCEPTOR_ROUTE_FLAG_*).

    The success of the operation is notified by calling the callback function
    `callback'.

    The routes created with this function are at their own metrics
    level.  However, you can not specify the same route twice. */
void ssh_pme_route_add(SshEngine engine,
                       SshInterceptorRouteKey key,
                       const SshIpAddr gateway,
                       SshUInt32 ifnum,
                       SshRoutePrecedence precedence,
                       SshUInt32 flags,
                       SshPmeRouteSuccessCB callback, void *context);

/** Removes the route to `key->dst' (including netmask) through the interface
    `ifnum' or gateway `gateway'.  The success of the operation is notified by
    calling the callback function `callback'. */
void ssh_pme_route_remove(SshEngine engine,
                          SshInterceptorRouteKey key,
                          const SshIpAddr gateway,
                          SshUInt32 ifnum,
                          SshRoutePrecedence precedence,
                          SshUInt32 flags,
                          SshPmeRouteSuccessCB callback, void *context);

#ifdef SSH_IPSEC_INTERNAL_ROUTING

/** Clears all entries from the internal engine routing table.  Note that this
    does not affect system routing tables, and for packets originating from
    the local host the engine only sees them if the TCP/IP stack thinks it has
    some (any) route for them. */
void ssh_pme_configure_route_clear(SshEngine engine);

/** Adds a route to `dst_and_mask' to point to gateway `next_hop', reachable
    through interface `ifnum'.  Route lookups always return the most exact
    route (i.e., the route with the highest number of bits in the mask - host
    routes always taking precedence).  This calls the callback either during
    this call or at some later time to indicate whether the route could be
    added. */
void ssh_pme_configure_route_add(SshEngine engine,
                                 const SshIpAddr dst_and_mask,
                                 const SshIpAddr next_hop,
                                 SshUInt32 ifnum,
                                 SshPmeStatusCB callback, void *context);
#endif /** SSH_IPSEC_INTERNAL_ROUTING */

/* ***************************** ARP  functions ******************************/

/** Adds an ARP entry for the IP address `ip' and media address `media_addr',
    `media_addr_len'.  This calls the callback either during this call or at
    some later time to inidicate whether the ARP entry could be added. */
void ssh_pme_arp_add(SshEngine engine,
                     const SshIpAddr ip,
                     SshUInt32 ifnum,
                     const unsigned char *media_addr,
                     size_t media_addr_len,
                     SshUInt32 flags,
                     SshPmeStatusCB callback, void *context);

/** Removes the ARP entry of the IP address `ip', if one exists.  This
   has no effect if there is no ARP entry for the IP address. */
void ssh_pme_arp_remove(SshEngine engine,
                        const SshIpAddr ip,
                        SshUInt32 ifnum);

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS
/* *********************** Virtual adapter functions *************************/

/** Configures the virtual adapter `adapter_ifnum' with `state', `addresses',
    and `params'. The argument `adapter_ifnum' must be the valid interface
    index of a virtual adapter that has been reported by the engine as a
    result of a call to ssh_pme_virtual_adapter_list().

    The argument `state' specifies the state to configure for the virtual
    adapter.

    The arguments `num_addresses' and `addresses' specify the IP addresses
    for the virtual adapter. The addresses must also specify the netmask. If
    `addresses' is NULL, the address configuration will not be changed.
    Otherwise the existing addresses will be removed from the virtual adapter
    and specified addresses will be added. To clear all addresses from the
    virtual adapter, specify `addresses' as non-NULL and `num_addresses' as 0.

    The argument `params' specifies optional parameters for the virtual
    adapter. If `params' is non-NULL, then the existing params will be cleared
    and the specified params will be set for the virtual adapter. */
void
ssh_pme_virtual_adapter_configure(SshEngine engine,
                                  SshUInt32 adapter_ifnum,
                                  SshVirtualAdapterState state,
                                  SshUInt32 num_addresses,
                                  SshIpAddr addresses,
                                  SshVirtualAdapterParams params,
                                  SshPmeVirtualAdapterStatusCB callback,
                                  void *context);

/** Lists a virtual adapter that has been attached to the engine and that
    matches the argument `adapter_ifnum'. If `adapter_ifnum' is
    SSH_INVALID_IFNUM, then this function will list all virtual
    adapters that have been attached to the engine. */
void
ssh_pme_virtual_adapter_list(SshEngine engine,
                             SshUInt32 adapter_ifnum,
                             SshPmeVirtualAdapterStatusCB callback,
                             void *context);

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */


/* ********************** Flow manipulation functions ************************/

/** Switch flow status between "pass/drop packets". The flow_index
   must be 'wrapped' for detecting race conditions. */
void ssh_pme_flow_set_status(SshEngine engine,
                             SshUInt32 flow_index,
                             SshPmeFlowStatus flow_status,
                             SshPmeStatusCB callback, void *context);

/** Reroute and evaluate all existing flows against current policy
   and routing state. */
void ssh_pme_redo_flows(SshEngine engine);


/* *********************************************************************
 * Corrupt packet classification.
 * *********************************************************************/

/** Request 'num_events' audit events from the engine. The engine will return
    the audit events in the 'audit_callback'. The engine may return less audit
    events than the policy manager has asked for. The callback function gets
    'callback_context' as its context argument. */
void
ssh_pme_get_audit_events(SshEngine engine, SshUInt32 num_events,
                         SshPmeAuditCB audit_callback,
                         void *callback_context);


#ifdef SSH_IPSEC_TCPENCAP
/**
   Bind IKE initiator cookie to a connection entry. Create a new
   connection entry if needed. This should be called when initiating
   IKE negotiation and during IKEv2 IKE SA rekey.

   This creates a new connection entry between endpoints specified by
   arguments `local_addr', `local_port', `peer_addr' and `peer_port',
   and binds `ike_initiator_cookie' to it.

   This calls `callback' with the connection id for the connection or
   SSH_IPSEC_INVALID_INDEX if an error occured.
   XXX add vrf? seems to be tcpencap dependent*/
void
ssh_pme_tcp_encaps_create_ike_mapping(SshEngine engine,
                                      SshIpAddr local_addr,
                                      SshIpAddr peer_addr,
                                      SshUInt16 local_port,
                                      SshUInt16 peer_port,
                                      unsigned char *ike_initiator_cookie,
                                      SshUInt16 local_ike_port,
                                      SshUInt16 remote_ike_port,
                                      SshPmeIndexCB callback,
                                      void *callback_context);

/** Looks up connection entry between `local_addr' and `peer_addr' that is
    bound to `ike_initiator_cookie'. This calls `callback' with the connection
    id or SSH_IPSEC_INVALID_INDEX if no connection was found. */
void
ssh_pme_tcp_encaps_get_ike_mapping(SshEngine engine,
                                   SshIpAddr local_addr,
                                   SshIpAddr peer_addr,
                                   unsigned char *ike_initiator_cookie,
                                   SshPmeIndexCB callback,
                                   void *callback_context);

/** Updates `new_ike_initiator_cookie' to connection entry IKE mapping for
    connections matching `ike_initiator_cookie', `local_addr' and
    `remote_addr'. If `local_addr' or `remote_addr' are NULL then they are not
    used in matching. If `new_ike_initiator_cookie' is NULL, then this will
    remove the connection entry IKE mapping, and if there are no SPI mappings,
    then also close the connection and free the connection entry. If
    `keep_address_matches' is TRUE, then the connections matching `local_addr',
    `peer_addr' and `ike_initiator_cookie' are ignored and any other
    connections matching `ike_initiator_cookie' are updated. This calls
    `callback' with the connection id of the updated connection entry or
    SSH_IPSEC_INVALID_INDEX if either no connection was found or if the
    connection mapping was removed. */
void
ssh_pme_tcp_encaps_update_ike_mapping(SshEngine engine,
                                      Boolean keep_address_matches,
                                      SshIpAddr local_addr,
                                      SshIpAddr peer_addr,
                                      unsigned char *ike_initiator_cookie,
                                      unsigned char *new_ike_initiator_cookie,
                                      SshPmeIndexCB callback,
                                      void *callback_context);

/** This call installs a TCP encapsulation configuration to the
    engine.

    IP address parameters (local_addr, peer_lo_addr, peer_hi_addr)
    MUST be given and they MUST be of same type (IPv4/IPv6).

    Port parameters (local_port, peer_port, local_ike_port and
    peer_ike_port) may be left zero, in which case default values are
    used. In a gateway configuration local_port MUST be defined. In a
    client configuration peer_port MUST be defined. */
Boolean
ssh_pme_tcp_encaps_add_configuration(SshEngine engine,
                                     SshIpAddr local_addr,
                                     SshUInt16 local_port,
                                     SshIpAddr peer_lo_addr,
                                     SshIpAddr peer_hi_addr,
                                     SshUInt16 peer_port,
                                     SshUInt16 local_ike_port,
                                     SshUInt16 remote_ike_port);

/** This call removes all TCP encapsulation configurations from the
    engine. */
void
ssh_pme_tcp_encaps_clear_configurations(SshEngine engine);
#endif /* SSH_IPSEC_TCPENCAP */


#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#include "engine_pme.h"

#define ssh_pme_set_engine_params(engine, \
                pm_params) \
        ssh_engine_pme_set_engine_params(engine, \
                pm_params)

#define ssh_pme_disable_policy_lookup(engine, callback, context)  \
        ssh_engine_pme_disable_policy_lookup(engine, callback, context)

#define ssh_pme_enable_policy_lookup(engine, callback, context) \
        ssh_engine_pme_enable_policy_lookup(engine, callback, context)

#define ssh_pme_set_debug_level(engine, level_string) \
        ssh_engine_pme_set_debug_level(engine, level_string)

#define ssh_pme_process_packet(engine, \
                tunnel_id, \
                protocol, \
                ifnum, \
                routing_instance_id, \
                flags, \
                prev_transform_index, \
                data, \
                len) \
        ssh_engine_pme_process_packet(engine, \
                tunnel_id, \
                protocol, \
                ifnum, \
                routing_instance_id, \
                flags, \
                prev_transform_index, \
                data, \
                len)

#ifdef SSHDIST_IPSEC_NAT
#define ssh_pme_set_interface_nat(engine, \
                ifnum, \
                type, \
                nat_flags, \
                host_nat_int_base, \
                host_nat_ext_base, \
                host_nat_num_ips) \
        ssh_engine_pme_set_interface_nat(engine, \
                ifnum, \
                type, \
                nat_flags, \
                host_nat_int_base, \
                host_nat_ext_base, \
                host_nat_num_ips)

#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
#define ssh_pme_configure_internal_nat(engine, \
                first_ip, \
                last_ip, \
                callback, context) \
        ssh_engine_pme_configure_internal_nat(engine, \
                first_ip, \
                last_ip, \
                callback, context)
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */

#define ssh_pme_create_transform(engine, \
                params, \
                life_seconds, \
                life_kilobytes, \
                callback, context) \
        ssh_engine_pme_create_transform(engine, \
                params, \
                life_seconds, \
                life_kilobytes, \
                callback, context)

#define ssh_pme_delete_transform(engine, transform_index) \
        ssh_engine_pme_delete_transform(engine, transform_index)

#define ssh_pme_rekey_transform_inbound(engine, \
                transform_index, \
                new_in_spis, \
                keymat_in, \
                life_seconds, \
                life_kilobytes, \
                flags, \
                callback, context) \
        ssh_engine_pme_rekey_transform_inbound(engine, \
                transform_index, \
                new_in_spis, \
                keymat_in, \
                life_seconds, \
                life_kilobytes, \
                flags, \
                callback, context)

#ifndef SSH_IPSEC_TCPENCAP
#define ssh_pme_rekey_transform_outbound(engine, \
                transform_index, \
                new_out_spis, \
                keymat_out, \
                flags, \
                callback, context) \
        ssh_engine_pme_rekey_transform_outbound(engine, \
                transform_index, \
                new_out_spis, \
                keymat_out, \
                flags, \
                callback, context)
#else /* SSH_IPSEC_TCPENCAP */
#define ssh_pme_rekey_transform_outbound(engine, \
                transform_index, \
                new_out_spis, \
                keymat_out, \
                tcp_encaps_conn_spi, \
                flags, \
                callback, context) \
        ssh_engine_pme_rekey_transform_outbound(engine, \
                transform_index, \
                new_out_spis, \
                keymat_out, \
                tcp_encaps_conn_spi, \
                flags, \
                callback, context)
#endif /* SSH_IPSEC_TCPENCAP */

#define ssh_pme_transform_invalidate_old_inbound(engine, \
                transform_index, \
                inbound_spi, \
                callback, \
                context) \
        ssh_engine_pme_transform_invalidate_old_inbound(engine, \
                transform_index, \
                inbound_spi, \
                callback, \
                context)

#ifdef SSHDIST_L2TP
#define ssh_pme_update_transform_l2tp_info(engine, \
                transform_index, \
                flags, \
                local_tunnel_id, \
                local_session_id, \
                remote_tunnel_id, \
                remote_session_id) \
        ssh_engine_pme_update_transform_l2tp_info(engine, \
                transform_index, \
                flags, \
                local_tunnel_id, \
                local_session_id, \
                remote_tunnel_id, \
                remote_session_id)
#endif /* SSHDIST_L2TP */

#define ssh_pme_add_rule(engine, rekey, \
                rule, \
                callback, context) \
        ssh_engine_pme_add_rule(engine, rekey, \
                rule, \
                callback, context)

#define ssh_pme_delete_rule(engine, \
                rule_index, \
                callback, context) \
        ssh_engine_pme_delete_rule(engine, \
                rule_index, \
                callback, context)

#define ssh_pme_find_transform_rule(engine, \
                tunnel_id, \
                ifnum, \
                src_ip, \
                dst_ip, \
                ipproto, \
                src_port, \
                dst_port, \
                impl_tunnel_id, \
                trd_index, \
                flags, \
                callback, context) \
        ssh_engine_pme_find_transform_rule(engine, \
                tunnel_id, \
                ifnum, \
                src_ip, \
                dst_ip, \
                ipproto, \
                src_port, \
                dst_port, \
                impl_tunnel_id, \
                trd_index, \
                flags, \
                callback, context)

#define ssh_pme_find_matching_transform_rule(engine, \
                rule, \
                transform, \
                cipher_key_size, \
                peer_ip, \
                local_ip, \
                local_port, \
                remote_port, \
                peer_id, \
                flags, \
                callback, \
                context) \
        ssh_engine_pme_find_matching_transform_rule(engine, \
                rule, \
                transform, \
                cipher_key_size, \
                peer_ip, \
                local_ip, \
                local_port, \
                remote_port, \
                peer_id, \
                flags, \
                callback, \
                context)

#define ssh_pme_have_transform_with_peer(engine, \
                ip_addr, \
                remote_ike_port, \
                callback, context) \
        ssh_engine_pme_have_transform_with_peer(engine, \
                ip_addr, \
                remote_ike_port, \
                callback, context)

#define ssh_pme_delete_by_spi(engine, transform_index, \
                callback, context) \
        ssh_engine_pme_delete_by_spi(engine, transform_index, \
                callback, context)

#define ssh_pme_delete_by_peer_handle(engine, \
                peer_handle, \
                callback, \
                context) \
        ssh_engine_pme_delete_by_peer_handle(engine, \
                peer_handle, \
                callback, \
                context)

#ifdef SSH_IPSEC_TCPENCAP
#define ssh_pme_update_by_peer_handle(engine, \
                peer_handle, \
                enable_natt, routing_instance_id, local_ip, \
                remote_ip, remote_port, tcp_encaps_conn_spi, \
                callback, context) \
        ssh_engine_pme_update_by_peer_handle(engine, \
                peer_handle, \
                enable_natt, routing_instance_id, local_ip, \
                remote_ip, remote_port, tcp_encaps_conn_spi, \
                callback, context)
#else /* SSH_IPSEC_TCPENCAP */
#define ssh_pme_update_by_peer_handle(engine, \
                peer_handle, \
                enable_natt, routing_instance_id, local_ip, \
                remote_ip, remote_port, \
                callback, context) \
        ssh_engine_pme_update_by_peer_handle(engine, \
                peer_handle, \
                enable_natt, routing_instance_id, local_ip, \
                remote_ip, remote_port, \
                callback, context)
#endif /* SSH_IPSEC_TCPENCAP */

#define ssh_pme_get_rule(engine, rule_index, \
                callback, context) \
        ssh_engine_pme_get_rule(engine, rule_index, \
                callback, context)

#define ssh_pme_get_transform(engine, trd_index, \
                callback, context) \
        ssh_engine_pme_get_transform(engine, trd_index, \
                callback, context)

#define ssh_pme_add_reference_to_rule(engine, rule_index, \
                transform_index, \
                callback, context) \
        ssh_engine_pme_add_reference_to_rule(engine, rule_index, \
                transform_index, \
                callback, context)

#ifdef SSH_IPSEC_STATISTICS

#define ssh_pme_get_global_stats(engine, \
                callback, context) \
        ssh_engine_pme_get_global_stats(engine, \
                callback, context)

#define ssh_pme_get_next_flow_index(engine, \
                flow_index, \
                callback, \
                context) \
        ssh_engine_pme_get_next_flow_index(engine, \
                flow_index, \
                callback, \
                context)

#define ssh_pme_get_flow_info(engine, flow_index, \
                callback, context) \
        ssh_engine_pme_get_flow_info(engine, flow_index, \
                callback, context)

#define ssh_pme_get_flow_stats(engine, flow_index, \
                callback, context) \
        ssh_engine_pme_get_flow_stats(engine, flow_index, \
                callback, context)

#define ssh_pme_get_next_transform_index(engine, \
                transform_index, \
                callback, \
                context) \
        ssh_engine_pme_get_next_transform_index(engine, \
                transform_index, \
                callback, \
                context)

#define ssh_pme_get_transform_stats(engine, transform_index, \
                callback, \
                context) \
        ssh_engine_pme_get_transform_stats(engine, transform_index, \
                callback, \
                context)

#define ssh_pme_get_next_rule_index(engine, \
                rule_index, \
                callback, \
                context) \
        ssh_engine_pme_get_next_rule_index(engine, \
                rule_index, \
                callback, \
                context)

#define ssh_pme_get_rule_stats(engine, rule_index, \
                callback, context) \
        ssh_engine_pme_get_rule_stats(engine, rule_index, \
                callback, context)
#endif /** SSH_IPSEC_STATISTICS */

#define ssh_pme_route(engine, flags, \
                key, \
                callback, context) \
        ssh_engine_pme_route(engine, flags, \
                key, \
                callback, context)

#define ssh_pme_route_add(engine, key, \
                gateway, ifnum, precedence, flags, \
                callback, context) \
        ssh_engine_pme_route_add(engine, key, \
                gateway, ifnum, precedence, flags, \
                callback, context)

#define ssh_pme_route_remove(engine, key, \
                gateway, ifnum, precedence, flags, \
                callback, context) \
        ssh_engine_pme_route_remove(engine, key, \
                gateway, ifnum, precedence, flags, \
                callback, context)

#ifdef SSH_IPSEC_INTERNAL_ROUTING

#define ssh_pme_configure_route_clear(engine) \
        ssh_engine_pme_configure_route_clear(engine)

#define ssh_pme_configure_route_add(engine, \
                dst_and_mask, \
                next_hop, \
                ifnum, \
                callback, context) \
        ssh_engine_pme_configure_route_add(engine, \
                dst_and_mask, \
                next_hop, \
                ifnum, \
                callback, context)
#endif /** SSH_IPSEC_INTERNAL_ROUTING */

#define ssh_pme_arp_add(engine, \
                ip, \
                ifnum, \
                media_addr, \
                media_addr_len, \
                flags, \
                callback, context) \
        ssh_engine_pme_arp_add(engine, \
                ip, \
                ifnum, \
                media_addr, \
                media_addr_len, \
                flags, \
                callback, context)

#define ssh_pme_arp_remove(engine, \
                ip, \
                ifnum) \
        ssh_engine_pme_arp_remove(engine, \
                ip, \
                ifnum)

#ifdef SSHDIST_IPSEC_VIRTUAL_ADAPTERS

#define ssh_pme_virtual_adapter_configure(engine, \
                adapter_ifnum, state, num_addresses, addresses, params, \
                callback, context) \
        ssh_engine_pme_virtual_adapter_configure(engine, \
                adapter_ifnum, state, num_addresses, addresses, params, \
                callback, context)

#define ssh_pme_virtual_adapter_list(engine, \
                adapter_ifnum, \
                callback, context) \
        ssh_engine_pme_virtual_adapter_list(engine, \
                adapter_ifnum, \
                callback, context)

#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#define ssh_pme_flow_set_status(engine, \
                flow_index, \
                flow_status, \
                callback, context) \
        ssh_engine_pme_flow_set_status(engine, \
                flow_index, \
                flow_status, \
                callback, context)

#define ssh_pme_redo_flows(engine) \
        ssh_engine_pme_redo_flows(engine)

#define ssh_pme_get_audit_events(engine, num_events, \
                audit_callback, \
                callback_context) \
        ssh_engine_pme_get_audit_events(engine, num_events, \
                audit_callback, \
                callback_context)


#ifdef SSH_IPSEC_TCPENCAP

#define ssh_pme_tcp_encaps_add_configuration(engine, \
                local_addr, \
                local_port, \
                peer_lo_addr, \
                peer_hi_addr, \
                peer_port, \
                local_ike_port, \
                remote_ike_port) \
        ssh_engine_pme_tcp_encaps_add_configuration(engine, \
                local_addr, \
                local_port, \
                peer_lo_addr, \
                peer_hi_addr, \
                peer_port, \
                local_ike_port, \
                remote_ike_port)

#define ssh_pme_tcp_encaps_clear_configurations(engine) \
        ssh_engine_pme_tcp_encaps_clear_configurations(engine)

#define ssh_pme_tcp_encaps_create_ike_mapping(engine, \
                local_addr, \
                peer_addr, \
                local_port, \
                peer_port, \
                ike_initiator_cookie, \
                local_ike_port, \
                remote_ike_port, \
                callback, \
                callback_context) \
        ssh_engine_pme_tcp_encaps_create_ike_mapping(engine, \
                local_addr, \
                peer_addr, \
                local_port, \
                peer_port, \
                ike_initiator_cookie, \
                local_ike_port, \
                remote_ike_port, \
                callback, \
                callback_context)

#define ssh_pme_tcp_encaps_get_ike_mapping(engine, \
                local_addr, \
                peer_addr, \
                ike_initiator_cookie, \
                callback, \
                callback_context) \
        ssh_engine_pme_tcp_encaps_get_ike_mapping(engine, \
                local_addr, \
                peer_addr, \
                ike_initiator_cookie, \
                callback, \
                callback_context)

#define ssh_pme_tcp_encaps_update_ike_mapping(engine, \
                keep_address_matches, local_addr, peer_addr, \
                ike_initiator_cookie, new_ike_initiator_cookie, \
                callback, \
                callback_context) \
        ssh_engine_pme_tcp_encaps_update_ike_mapping(engine, \
                keep_address_matches, local_addr, peer_addr, \
                ike_initiator_cookie, new_ike_initiator_cookie, \
                callback, \
                callback_context)

#endif /* SSH_IPSEC_TCPENCAP */

#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

/*--------------------------------------------------------------------*/
/*  Functions in Policy Manager that can be called from Engine.
    Engine is not allowed to call these functions
    directly (because that could result in concurrent calls to
    Policy Manager, and Policy Manager is designed to be
    single-threaded).  Instead, Engine should schedule a
    zero-length timeout (via ssh_timeout_register, as opposed to
    ssh_kernel_timeout_register) to schedule the call from Policy
    Manager event loop, which needs to implement suitable protections
    anyway.  This assumes that the implementation of
    ssh_timeout_register is MT-safe in unified address space
    environments where Engine is multithreaded. */
/*--------------------------------------------------------------------*/

/** Forward reference. */
struct SshIpInterfacesRec;

/** Parameter type for ssh_pmp_transform_event(). */
typedef enum {
  /** The flow is close to expiration.  This is a soft notification which
      indicates that it still has some lifetime left (well enough to negotiate
      a new security association).  This notification is only sent for
      primary incoming IPsec flows (there can only be one per
      transform object). The timing of this event is not very
      deterministic; it will arrive before expiration, but there may
      be variance of even several minutes in some
      configurations on exactly when it is delievered. */
  SSH_ENGINE_EVENT_REKEY_REQUIRED,

  /** This event will be received some time after
      ssh_engine_pme_rekey_transform_inbound has been called (unless
      the flow has been deleted in the meanwhile).  This is sent when
      a timer causes the old inbound SAs to be invalidated
      (approximately half a minute after the rekey). This event may be
      useful for sending delete notifications for the old inbound SAs.
      The spis that just expired can be found from the trd->old_spis
      array.  The spis are not freed when called.  The policymanager
      must call ssh_pme_transform_invalidate_old_inbound do this
      after it has completed sending any delete notifications. This
      notification is only sent for incoming primary IPsec flows
      (there can only be one per transform object). */
  SSH_ENGINE_EVENT_REKEY_INBOUND_INVALIDATED,

  /** The flow has expired.  This event is delivered when a flow has been
      deleted because e.g. its transform expired (reached the hard limit).
      This is only delivered for those flows that have transform_index
      associated with them (i.e., only for flows created by an APPLY rule).
      Cases when this is delivered include e.g. if the policy manager chooses
      not to perform rekey when it receives SSH_ENGINE_EVENT_REKEY_REQUIRED or
      is too slow to perform the rekey.  The flow index is invalid when this
      event is delivered.  This event is not delivered if a rule is explicitly
      deleted by the policy manager, e.g. by one of the ssh_pme_delete_rule,
      ssh_pme_delete_by_peer, and ssh_pme_delete_by_spi functions.  This
      notification is only sent for primary incoming IPsec flows (there can
      only be one per transform object). */
  SSH_ENGINE_EVENT_EXPIRED,

  /** The transform object has been destroyed. */
  SSH_ENGINE_EVENT_DESTROYED,

  /** The incoming flow has been found being idle for more than its configured
      worry metric value. This notification is only sent for primary incoming
      IPsec flows (there can only be one per transform object). */
  SSH_ENGINE_EVENT_IDLE
} SshPmeFlowEvent;

#ifndef SSH_IPSEC_UNIFIED_ADDRESS_SPACE

/** This is called by the engine whenever the interceptor informs the engine
    that the interface list has changed.  This needs to copy the interface
    array if this needs it after this call.  This is also called during or
    shortly after the call to ssh_pm_connect_engine.  The engine never calls
    this function directly; it schedules a zero-length timeout in the unified
    address space mode. */
void ssh_pmp_interface_change(SshPm pm,
                              const struct SshIpInterfacesRec *ifs);

/** This is called by the engine whenever a trigger rule is encountered.  This
    function must free data using ssh_xfree when it is no longer needed.  When
    the engine calls this function, there is no guarantee that the policy
    manager function will actually get called; if that happens, then `data' is
    freed automatically by this function.  The policy manager may later call
    ssh_pme_process_packet to reprocess the packet (but not from this function
    directly).  `policy_rule' is a copy of the policy rule that created the
    trigger (it is illegal to modify it in any way - it may be a copy or a
    direct reference depending on configuration; it is only valid until this
    call returns).  Note that the tunnel id, interface number, and protocol of
    the triggering packet can be determined from the policy rule.  The engine
    never calls this function directly; it schedules a zero-length timeout in
    the unified address space mode.  The `prev_transform_index' value
    indicates the transform through which the packet was received; it should
    be passed to ssh_pme_process_packet unmodified.

    data contains the linearized packet that caused this trigger to occur.
    It may be parsed to obtain information such as packet headers, however
    data may contain extra information appeded to the end of the packet
    and it cannot not be assumed to be identical to the triggering packet.
    data should be passed unchanged to ssh_pme_process_packet if returning
    the trigger packet to the engine.

    The flow_index provided to this call is 'wrapped'. */
void ssh_pmp_trigger(SshPm pm,
                     const SshEnginePolicyRule policy_rule,
                     SshUInt32 flow_index,
                     const SshIpAddr nat_src_ip,
                     SshUInt16 nat_src_port,
                     const SshIpAddr nat_dst_ip,
                     SshUInt16 nat_dst_port,
                     SshUInt32 tunnel_id,
                     SshVriId routing_instance_id,
                     SshUInt32 prev_transform_index,
                     SshUInt32 ifnum,
                     SshUInt32 flags, /** Same as in ssh_pme_process_packet */
                     unsigned char *data, size_t len);

/** Notifies the policy manager of an event related to a transform
    record. This call is not reliable.  This returns TRUE if the policy
    manager actually got the call, and FALSE if it did not (the policy manager
    implementation of this function can also return FALSE if it does not have
    resources to handle the event).  The engine must copy any information it
    wishes to keep.  The `transform_index' and `trd' arguments specify the
    index and parameters of the transform triggering the event.  `rule_index'
    and `rule' are a policy rule that references the transform record as its
    (first) transform.  Since multiple engine rules can refer to the same
    transform data as their first transform, the engine uses the following
    order in selecting the rule that is passed as the `rule' argument:

    - a rule with non-null `policy_context'
    - a rule with null `policy_context'
    - if a no matching policy rule is found, a dummy rule is passed as
      the `rule' argument and its `type' field is set to
      SSH_ENGINE_RULE_NONEXISTENT

    Rule and trd are valid only until this call returns; if their contents are
    needed later, the information must be copied.  Note that the IKE phase 2
    proxy ids can be determined from the policy rule. `run_time' is the
    approximate number of seconds since the engine was started; it can be
    compared against trd->last_packet_time. */
Boolean ssh_pmp_transform_event(SshPm pm, SshPmeFlowEvent event,
                                SshUInt32 transform_index,
                                const SshEngineTransform tr,
                                SshUInt32 rule_index,
                                const SshEnginePolicyRule rule,
                                SshTime run_time);

/* ********************** Flow manipulation functions ************************/

/** Notifies the policy manager of the event that the flow with index
    'flow_index'. This 'flow_index' is wrapped. */
void ssh_pmp_flow_free_notification(SshPm pm, SshUInt32 flow_index);

#else /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

#include "eng_pm_api_pm.h"

#define ssh_pmp_interface_change(pm, ifs) \
        ssh_pm_pmp_interface_change(pm, ifs)

#define ssh_pmp_trigger(pm, \
                policy_rule, \
                flow_index, \
                nat_src_ip, \
                nat_src_port, \
                nat_dst_ip, \
                nat_dst_port, \
                tunnel_id, \
                routing_instance_id, \
                prev_transform_index, \
                ifnum, \
                flags, \
                data, len) \
        ssh_pm_pmp_trigger(pm, \
                policy_rule, \
                flow_index, \
                nat_src_ip, \
                nat_src_port, \
                nat_dst_ip, \
                nat_dst_port, \
                tunnel_id, \
                routing_instance_id, \
                prev_transform_index, \
                ifnum, \
                flags, \
                data, len)

#define ssh_pmp_transform_event(pm, event, \
                transform_index, \
                tr, \
                rule_index, \
                rule, \
                run_time) \
        ssh_pm_pmp_transform_event(pm, event, \
                transform_index, \
                tr, \
                rule_index, \
                rule, \
                run_time)

#define ssh_pmp_flow_free_notification(pm, flow_index) \
        ssh_pm_pmp_flow_free_notification(pm, flow_index)

#endif /* SSH_IPSEC_UNIFIED_ADDRESS_SPACE */

/* **************************** Misc. ******************************/

/** Uninitializes the engine, as if the PM connection had been closed.  The
    purpose of this function is to basically do a last sanity check on the
    state when shutting down the usermode engine. This should only be called
    from the policy manager if a unified-usermode engine is being used. */
void ssh_engine_notify_pm_close(SshEngine engine);










void ssh_pm_audit_get_engine_events(SshPm pm);

#endif /* ENGINE_PM_API_H */
