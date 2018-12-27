/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for the Quicksec SPD (rules and services)
   Policy Manager.
*/

#ifndef SPD_INTERNAL_H
#define SPD_INTERNAL_H

#include "sshincludes.h"

/* Includes for traffic selector functions. */
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "sad_ike.h"

/** The precedence level of the high-level system rules.  These are
    created by the policy manager. */
#define SSH_PM_RULE_PRI_HIGH                    0xfffffffa

/** The precedence level of the high-level policy rules.  These are
    created from user configured rules to override system default rules
    at precedence level SSH_PM_RULE_PRI_SYSTEM_DEFAULT. */
#define SSH_PM_RULE_PRI_USER_HIGH               0xfffffff1

/** The precedence level of the second highest system rules.  These are
    created by the policy manager but these can be be overridden with
    the high-level rules. */
#define SSH_PM_RULE_PRI_SYSTEM_DEFAULT          0xfffffff0

/** The engine rule priority value difference between high-level rules.
    The system might need up to four priority levels to implement one
    high-level rule. */
#define SSH_PM_RULE_PRI_STEP                    4

/** The SSH_PM_RULE_PRI_LOW_RESERVED lowest precedence values are
    reserved for the system. */
#define SSH_PM_RULE_PRI_LOW_RESERVED            10

/** Compute low-level filter rule precedence for the PM API level rule
    'rule'.  The system rules go to the same precedence slot but at
    higher precedence. */
#define SSH_PM_RULE_PRECEDENCE(rule)            \
(SSH_PM_RULE_PRI_LOW_RESERVED                   \
 + (rule)->precedence * SSH_PM_RULE_PRI_STEP    \
 + (((rule)->flags & SSH_PM_RULE_I_SYSTEM)      \
    ? 2                                         \
    : 0))

/** Compute low-level SA rule precedence for the PM API level rule
    'rule'. */
#define SSH_PM_SA_PRECEDENCE(rule)      \
(SSH_PM_RULE_PRECEDENCE(rule) + 1)

/* Status codes describing failures in policy rule selection. */
#define SSH_PM_E_NO_RULES                          0x00000001
#define SSH_PM_E_PEER_IP_MISMATCH                  0x00000002
#define SSH_PM_E_LOCAL_IP_MISMATCH                 0x00000004
#define SSH_PM_E_CA_NOT_TRUSTED                    0x00000010
#define SSH_PM_E_ACCESS_GROUP_MISMATCH             0x00000020
#define SSH_PM_E_LOCAL_TS_MISMATCH                 0x00000040
#define SSH_PM_E_REMOTE_TS_MISMATCH                0x00000080
#define SSH_PM_E_LOCAL_ID_MISMATCH                 0x00000100
#define SSH_PM_E_REMOTE_ID_MISMATCH                0x00000200
#define SSH_PM_E_SIMULTANEUS_LOSER                 0x00000400
#define SSH_PM_E_IKE_VERSION_MISMATCH              0x00000800
#define SSH_PM_E_PROTOCOL_MISMATCH_NATT            0x00001000
#define SSH_PM_E_ALGORITHM_MISMATCH                0x00002000
#define SSH_PM_E_ALGORITHM_UNSUPPORTED             0x00004000
#define SSH_PM_E_AUTH_METHOD_MISMATCH              0x00008000
#define SSH_PM_E_AUTH_METHOD_UNSUPPORTED           0x00010000
#define SSH_PM_E_ENCAPSULATION_MISMATCH            0x00020000
#define SSH_PM_E_ERROR_MEMORY                      0x00040000

/** Selectors for rule's 'from' and 'to' sides. */
struct SshPmRuleSideSpecificationRec
{
  /** Traffic selector. */



  SshIkev2PayloadTS ts;

#ifdef SSHDIST_IPSEC_DNSPOLICY
  SshPmDnsReference dns_addr_sel_ref;
  SshPmDnsReference dns_ifname_sel_ref;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  char *ifname;







  /* Flags. */
  unsigned int local_stack : 1;   /** Packet from / to local stack. */
  unsigned int auto_start : 1;    /** Auto-start option available. */
  unsigned int as_up : 1;         /** Auto-start tunnel up. */
  unsigned int as_active : 1;     /** Auto-start rule negotiation active. */
  unsigned int as_fail_retry : 8; /** Auto-start failure retry timer. */
  unsigned int as_fail_limit : 8; /** The next value for `as_fail_retry'. */
  unsigned int default_ts : 1;    /** 'ts' is a default ts set by system. */

  /** IPSec processing at this side. */
  SshPmTunnel tunnel;
};

typedef struct SshPmRuleSideSpecificationRec SshPmRuleSideSpecificationStruct;
typedef struct SshPmRuleSideSpecificationRec *SshPmRuleSideSpecification;

/** Internal service flags. */
#define SSH_PM_SERVICE_I_ICMP_TYPE      0x01000000
#define SSH_PM_SERVICE_I_ICMP_CODE      0x02000000

/** Service object. */
struct SshPmServiceRec
{
  /** Back-pointer to our policy manager. */
  SshPm pm;

  /** An unique service identifier. */
  SshUInt32 unique_id;

  /** A human-readable name for service, may be NULL. */
  char *service_name;

  /** The number of references to this service object. */
  SshUInt32 refcount;

  /** The identification of the service. */
  SshUInt32 flags;

  /** Application gateway handling. */
  char *appgw_ident;

  /** The currently active application gateway configuration data. */
  unsigned char *appgw_config;
  size_t appgw_config_len;

  /** The new application gateway configuration data that will be the
      current one with the new ssh_pm_commit() call. */
  unsigned char *new_appgw_config;
  size_t new_appgw_config_len;
};

typedef struct SshPmServiceRec SshPmServiceStruct;

/* Internal rule flags.
   Values upto 0x000fffff are used for public rule flags in 'core_pm.h'. */
#define SSH_PM_RULE_I_SYSTEM    0x00100000 /** System rule. */
#define SSH_PM_RULE_I_IN_BATCH  0x00200000 /** Rule in current commit batch. */
#define SSH_PM_RULE_I_DELETED   0x00400000 /** Rule is deleted (in batch). */
#define SSH_PM_RULE_I_BATCH_F   0x00800000 /** Commit batch failed. */
#ifdef SSHDIST_L2TP
#define SSH_PM_RULE_I_L2TP      0x01000000 /** Use L2TP proxy IDs. */
#endif /* SSHDIST_L2TP */
#define SSH_PM_RULE_I_DHCP      0x02000000 /** Use DHCP over IPSEC selector. */

#define SSH_PM_RULE_I_CLONE     0x04000000 /** clone, when add, inherit id */
#define SSH_PM_RULE_I_IKE_ABORT 0x08000000 /** IKE aborted */
#define SSH_PM_RULE_I_NO_TRIGGER 0x10000000/** Create inactive trigger rule.*/

#define SSH_PM_RULE_I_IKE_TRIGGER 0x20000000 /** Inner IKE trigger rule. */
#define SSH_PM_RULE_I_VIP         0x40000000 /** Vip system rule. */

#define SSH_PM_RULE_IS_L2TP(rule) 0
#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
#ifdef SSHDIST_L2TP
#undef SSH_PM_RULE_IS_L2TP
#define SSH_PM_RULE_IS_L2TP(rule) \
((rule)->side_to.tunnel \
 && ((rule)->side_to.tunnel->flags & SSH_PM_TI_L2TP) \
 && (rule)->side_to.ts \
 && (rule)->side_to.ts->number_of_items_used == 1 \
 && (rule)->side_to.ts->items[0].proto == SSH_IPPROTO_UDP \
 && (rule)->side_to.ts->items[0].start_port == 1701 \
 && (rule)->side_to.ts->items[0].end_port == 1701)
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

/** A predicate to check whether the high-level rule `rule' requires a
    virtual IP. */
#define SSH_PM_RULE_IS_VIRTUAL_IP(rule) \
(((rule)->flags & SSH_PM_RULE_I_IKE_TRIGGER) == 0 \
 && ((rule)->flags & SSH_PM_RULE_PASS) \
 && (rule)->side_to.tunnel \
 && !SSH_PM_RULE_IS_L2TP(rule) \
 && SSH_PM_TUNNEL_IS_VIRTUAL_IP((rule)->side_to.tunnel))

#define SSH_PM_RULE_INACTIVE_I(pm, rule)                                \
((((rule)->flags & (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED))    \
  == SSH_PM_RULE_I_IN_BATCH)                                            \
 || ((rule)->flags & SSH_PM_RULE_I_DELETED                              \
     && (pm)->batch_active))


/*  A predicate SSH_PM_RULE_INACTIVE checks if the rule 'rule' is not
    active and therefore can not be used for new negotiations.  This
    means that the rule is added by the current policy update
    operation (which might not be committing yet) or it is deleted by
    a modification batch that is currently committing.  In other
    words, additions are active after the batch is committed and
    deletions are removed from the configuration during the commit
    batch but not before. */

#ifdef SSHDIST_IPSEC_DNSPOLICY
/** Consider OK and stale DNS rules as active, only error status is
    inactive. */
#define SSH_PM_RULE_INACTIVE(pm, rule)                                  \
  (SSH_PM_RULE_INACTIVE_I((pm), (rule))                                 \
   || (pm_rule_get_dns_status((pm), (rule)) == SSH_PM_DNS_STATUS_ERROR))
#else /* SSHDIST_IPSEC_DNSPOLICY */
#define SSH_PM_RULE_INACTIVE(pm, rule) (SSH_PM_RULE_INACTIVE_I((pm), (rule)))
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/** Lock the rule from being deleted. */
#define SSH_PM_RULE_LOCK(rule)  \
do                              \
  {                             \
    (rule)->refcount++;         \
  }                             \
while (0)

/** Unlock the rule 'rule'.  We are not using it anymore so it can be
    deleted if needed. */
#define SSH_PM_RULE_UNLOCK(pm, rule)                            \
do                                                              \
  {                                                             \
    SSH_ASSERT((rule)->refcount > 0);                           \
    (rule)->refcount--;                                         \
    if (SSH_PM_RULE_INACTIVE(pm, rule))                         \
      ssh_fsm_condition_signal(&(pm)->fsm,                      \
                               &(pm)->main_thread_cond);        \
  }                                                             \
while (0)

/** Maximum number of inner tunnels referring to an outer tunnel. */
#define SSH_PM_MAX_INNER_TUNNELS 3

/** The maximum number of engine level rules needed to implement each engine
    rule derived from a high-level policy rule. For each pair traffic selector
    items, there are two rules, one  for the policy implementation and one for
    the policy enforcement. */
#define SSH_PM_RULE_MAX_ENGINE_RULES                       \
  ((2 + SSH_PM_MAX_INNER_TUNNELS) *                        \
   SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS * SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS)

/* Indices for Engine-level rules. */
#define SSH_PM_RULE_ENGINE_IMPLEMENT    0 /** Policy implementation rule. */
#define SSH_PM_RULE_ENGINE_ENFORCE      1 /** Policy enforcement rule. */

/** A macro to compute the index into the SshPmRule's rule->rules array when
    adding engine rules from the different traffic selectors items of a
    top-level policy rule. */
#define SSH_PM_CURRENT_RULE_INDEX(pm) \
        (((SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS * pm->to_ts_index) + \
        pm->from_ts_index) * 2)

/** A high-level policy rule object. */
struct SshPmRuleRec
{
  /** Rules are kept in linked list while they are processed at DNS
      resolution */
  struct SshPmRuleRec *nextp;

  /** Rules are kept in two ADT containers when waiting for commit
      batch or while at the active configuration. */
  SshADTBagHeaderStruct rule_by_index_add_hdr;
  SshADTBagHeaderStruct rule_by_index_del_hdr;

  /* The rule_by_index is used for hashed access by rule id and
     rule_by_precedence is used  for by-precedence iteration for
     responder side rule lookup. */
  SshADTBagHeaderStruct rule_by_index_hdr;
  SshADTHeaderStruct rule_by_precedence_hdr;

  /* The rule_ike_trigger is used for system created inner tunnel
     IKE trigger rules.  These rules have the SSH_PM_RULE_I_IKE_TRIGGER
     and SSH_PM_RULE_I_SYSTEM flags set, and they are stored only in
     rule_ike_trigger and rule_by_id ADTs. */
  SshADTBagHeaderStruct rule_ike_trigger_hdr;

  /** ADT header for autostart rules. Autostart rules are kept on a
      separate container to reduce the number of rules considered by the
      autostart timer. */
  SshADTHeaderStruct rule_by_autostart_hdr;

  /** System created sub-rules which help implementing this high-level
      rule.  When the master high-level rule is deleted, also these
      sub-rules are deleted.  All the sub-rules can be found by
      following this field from the master rule.  They all have the
      SSH_PM_RULE_I_SYSTEM flag set. */
  struct SshPmRuleRec *sub_rule;

  /** Master-rule of this sub-rule.  This field is set only for system
      created sub-rules.  When a sub-rule is deleted, then it must be
      removed from its master-rule's sub-rule list. */
  struct SshPmRuleRec *master_rule;

  /** The number of references to this rule in addition of the SPD
      reference.  The SPD has one implicit reference through the `next'
      pointer.  This reference count is the number of other references
      (threads doing negotiations) currently using this rule.  The main
      thread will not delete the thread until this reference count
      reaches zero.  When a thread removes a reference from a rule, and
      the rule was deleted, it must signal `pm->main_thread_cond'. */
  SshUInt32 refcount;

  /** An unique ID for this rule.  Policy manager allocates this when
      the rule is added to the active configuration. */
  SshUInt32 rule_id;

  /** Indexes of the engine-level rules, implementing this high-level
      rule. */
  SshUInt32 rules[SSH_PM_RULE_MAX_ENGINE_RULES];

  /** High-level (policy management API level) precedence for the
      rule. */
  SshUInt32 precedence;

  /** Flags controlling the rule. */
  SshUInt32 flags;

  /** Service of this rule. */
  SshPmService service;

#ifdef SSHDIST_IPSEC_NAT
  /** Forced NAT source. */
  SshIpAddrStruct nat_src_low;
  SshIpAddrStruct nat_src_high;
  SshUInt16 nat_src_port;
  SshPmNatFlags nat_flags;
  /** Forced NAT destination. */
  SshIpAddrStruct nat_dst_low;
  SshIpAddrStruct nat_dst_high;
  SshUInt16 nat_dst_port;
#endif /* SSHDIST_IPSEC_NAT */

  unsigned int ike_in_progress : 1; /** The rule is in use by IKE */
  unsigned int in_auto_start_adt : 1; /** The rule is in rule by
                                          autostart ADT. */

  /** Rule's sides. */
  SshPmRuleSideSpecificationStruct side_from;
  SshPmRuleSideSpecificationStruct side_to;

#if (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0)
  /** Extension selectors. */
  SshUInt32 extsel_low[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
  SshUInt32 extsel_high[SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS];
#endif /* (SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS > 0) */

  /** Allowed access groups. */
  SshUInt32 num_access_groups;
  SshUInt32 *access_groups;

#ifdef SSHDIST_IPSEC_SA_EXPORT
  /** Application specific identifier. */
  unsigned char *application_identifier;
  size_t application_identifier_len;
#endif /* SSHDIST_IPSEC_SA_EXPORT */

  /** A condition variables for synchronizing with threads using this
      rule.  When the rule is being deleted and its has references, the
      main thread will wake up the waiters of this condition
      variable. */
  SshFSMConditionStruct cond;

  /** Back pointer to policymanager this rule is assigned to */
  SshPm pm;

  /** VRF routing instance identifier. */
  char routing_instance_name[SSH_INTERCEPTOR_VRI_NAMESIZE];
  int routing_instance_id;
};

typedef struct SshPmRuleRec SshPmRuleStruct;


/** Allocate a policy rule. */
SshPmRule ssh_pm_rule_alloc(SshPm pm);

/** Allocate a service object. */
SshPmService ssh_pm_service_alloc(SshPm pm);

/** Free the service object `tunnel'. */
void ssh_pm_service_free(SshPm pm, SshPmService service);


/** Render function for high-level rule. */
int ssh_pm_rule_render(unsigned char *buf, int buf_size,
                       int precision, void *datum);

/** Create a high-level policy rule but does not link it to the policy
    manager's list of user configuration changes.  This can be used
    internally to create high-level system rules, for example, in the
    virtual IP. */
SshPmRule ssh_pm_rule_create_internal(SshPm pm, SshUInt32 precedence,
                                      SshUInt32 flags,
                                      SshPmTunnel from_tunnel,
                                      SshPmTunnel to_tunnel,
                                      SshPmService service);

SshPmRule ssh_pm_rule_clone(SshPm pm, SshPmRule rule);

/** Adds an IP address constraint to the given rule.

This constrains which packets the rule applies to.  The IP
addresses can be either IPv4 or IPv6 addresses.  Only one address
range can be specified for each side of the rule (it is a fatal
error to try to add more).  If multiple addresses are to be used,
separate rules must be created for each of them.  The function
returns TRUE on success and FALSE if the IP addresses could not be
parsed or they do not specify a valid IP range. */
Boolean
ssh_pm_rule_set_ip(SshPmRule rule, SshPmRuleSide side,
                   const unsigned char *ip_low,
                   const unsigned char *ip_high);

int ssh_pm_rule_hash_adt(void *ptr, void *context);
int ssh_pm_rule_compare_adt(void *ptr1, void *ptr2, void *context);
int ssh_pm_rule_prec_compare_adt(void *ptr1, void *ptr2, void *context);
void ssh_pm_rule_destroy_adt(void *ptr, void *context);


/** Set the extension selectors of the high-level policy rule `rule'
    for the engine rule `erule'.  The function sets the extension
    selector constraints and sets appropriate engine rule flags. */
void ssh_pm_set_extension_selectors(SshPmRule rule, SshEnginePolicyRule erule);


typedef enum {
  PM_ENGINE_RULE_OK = 0,
  PM_ENGINE_RULE_NO_INTERFACE = 1,
  PM_ENGINE_RULE_FAILED = 2
} SshPmMakeEngineRuleStatus;

/** Convert the high-level rule `rule' into an engine rule. The rule is
    created to `erule' which is allocated by the caller. The argument
    `enforcement' specifies whether this rule is the policy enforcement
    rule (trigger's reverse drop rule) or implementation rule. If 'enforcement'
    is FALSE, 'local_ts' is the traffic selector of the from side of the rule,
    and 'remote_ts' is the traffic selector of the to side of the rule.
    This is reversed when 'enforcement' is TRUE, i.e. 'local_ts' is the rule's
    to side traffic selector. 'local_index' is the index of the traffic
    selector item in 'local_ts' and 'remote_index' is the index of the traffic
    selector item in 'remote_ts'.

    The function returns PM_ENGINE_RULE_OK if the engine rule could be created,
    PM_ENGINE_RULE_NO_INTERFACE if the system did not have enough information
    (interface information is unavailable or a required interface is missing),
    and PM_ENGINE_RULE_FAILED in the case of error. */
SshPmMakeEngineRuleStatus
ssh_pm_make_engine_rule(SshPm pm, SshEnginePolicyRule erule, SshPmRule rule,
                        SshIkev2PayloadTS local_ts, size_t local_index,
                        SshIkev2PayloadTS remote_ts, size_t remote_index,
                        Boolean enforcement);

/** Log responder policy rule selection failure `failure_mask' with
    ssh_log_event with log `facility' and `severity'.  The function
    logs only the reasons, defined by the `failure_mask'.  A call to
    this function should be preceded by another ssh_log_event call
    which describes the failed responder policy rule selection. */
void ssh_pm_log_rule_selection_failure(SshLogFacility facility,
                                       SshLogSeverity severity,
                                       SshPmP1 p1,
                                       SshUInt32 failure_mask);

/** Init free list of traffic selectors. Return TRUE if successful. */
Boolean
ssh_ikev2_ts_freelist_create(SshSADHandle sad_handle);

/** Destroy free list of traffic selectors.  */
void
ssh_ikev2_ts_freelist_destroy(SshSADHandle sad_handle);


#ifdef SSHDIST_IPSEC_DNSPOLICY
/** Fetch DNS status of rule's and referred tunnel's DNS selectors. */
SshPmDnsStatus pm_rule_get_dns_status(SshPm pm, SshPmRule rule);

/** Add a DNS resolved peer IP address to a tunnel. */
Boolean ssh_pm_tunnel_add_dns_peer_ip(SshPmTunnel tunnel, SshIpAddr ip,
                                      SshPmDnsReference ref);
/** Remove all DNS reolved peer IP addresses from a tunnel. */
Boolean ssh_pm_tunnel_clear_dns_peers(SshPmTunnel tunnel,
                                      SshPmDnsReference ref);
/** Return number of configured peer IP addresses for this DNS reference. */
SshUInt32 ssh_pm_tunnel_num_dns_peer_ips(SshPmTunnel tunnel,
                                         SshPmDnsReference ref);
/** Return number of configured local IP addresses for this DNS reference. */
SshUInt32
ssh_pm_tunnel_num_local_dns_addresses(SshPmTunnel tunnel,
                                      SshPmDnsReference ref);
#endif /* SSHDIST_IPSEC_DNSPOLICY */

/** Move rule additions/deletions made by ssh_pm_rule_add() and
    ssh_pm_rule_delete() to the `pending' containers. */
void
ssh_pm_config_make_pending(SshPm pm);

/** Move rule additions/deletions from the `pending' containers to the
    final containers consumed by the configuration batch thread. */
void
ssh_pm_config_pending_to_batch(SshPm pm);

#endif /* not SPD_INTERNAL_H */
