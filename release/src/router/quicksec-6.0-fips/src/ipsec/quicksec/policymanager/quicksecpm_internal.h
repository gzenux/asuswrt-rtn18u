/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for the Quicksec Policy Manager.

   @description
   This header defines the Policy Manager data structure and auditing
   related data structures.
*/

#ifndef QUICKSEC_INTERNAL_H
#define QUICKSEC_INTERNAL_H


#include "sshtcp.h"
#include "sshadt.h"
#include "sshadt_bag.h"
#include "sshadt_avltree.h"
#include "sshfsm.h"
#include "sshtimeouts.h"
#include "sshencode.h"
#include "sshinetencode.h"
#include "sshnameserver.h"
#include "sshmiscstring.h"
#ifdef SSHDIST_DIRECTORY_HTTP
#include "sshhttp.h"
#endif /* SSHDIST_DIRECTORY_HTTP */
#include "interceptor.h"
#include "ip_interfaces.h"
#include "quicksec_pm.h"
#include "quicksec_pm_low.h"
#include "engine_pm_api.h"
#include "eng_pm_api_pm.h"

#include "spd_main_st.h"
#include "util_dnsresolver.h"
#include "util_internal.h"
#include "sshadt_list.h"
#include "sshikev2-payloads.h"

#include "spd_internal.h"

#include "ipsec_internal.h"

#ifdef SSHDIST_IPSEC_NAT
#include "nat_internal.h"
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_CRYPTO_RANDOM_POLL
#include "sshcryptoaux.h"
#endif /* SSHDIST_CRYPTO_RANDOM_POLL */

#include "sshape_mark.h"

/* ************************************************************************ */

/** Forward declarations for some Policy Manager data structures. */
typedef struct SshPmFreelistItemRec *SshPmFreelistItem;


/** Audit module context. */
struct SshPmAuditModuleRec
{
  struct SshPmAuditModuleRec *next;

  SshUInt32 audit_subsystems;

  /** An unique ID for this audit module. Policy Manager allocates
      this when the audit module is created. */
  SshUInt32 audit_id;

  SshAuditContext context;
};

typedef struct SshPmAuditModuleRec SshPmAuditModuleStruct;
typedef struct SshPmAuditModuleRec *SshPmAuditModule;

/** Global auditing information. */
struct SshPmAuditRec
{
  /** IKE audit context. */
  SshAuditContext ike_audit;

  /** Linked list of active audit modules. */
  SshPmAuditModule modules;

  /** Timers for audit module. */
  SshTimeoutStruct timer;
  SshTimeoutStruct retry_timer;

  /** Interval (microseconds) how ofter the PM polls for audit events
      from the Engine. If this is zero, the Engine will request audit
      events to be polled by the Policy Manager. This feature is useful
      at systems thad do want to save power and avoid keeping high
      granularity timers running. */
  long request_interval;

  /** The last time an audit resource failure message was received. */
  SshTime last_resource_failure_time;
  /** The last time an audit flood message was received. */
  SshTime last_flood_time;
};

typedef struct SshPmAuditRec SshPmAuditStruct;

/** Generic structure for storing completion callbacks and context
    in a list. */
typedef struct SshPmCallbacksRec *SshPmCallbacks;
struct SshPmCallbacksRec
{
  union
  {
    SshPmStatusCB status_cb;
  } u;
  void *context;
  SshPmCallbacks next;
};

typedef enum {
  SSH_PM_STATUS_ACTIVE  = 1,
  SSH_PM_STATUS_SUSPENDING = 2,
  SSH_PM_STATUS_SUSPENDED = 3,
  SSH_PM_STATUS_DESTROYED = 4
} SshPmStatus;


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
/** RADIUS Accounting context */
typedef struct SshPmRadiusAcctRec *SshPmRadiusAcct;
struct SshPmRadiusAcctRec
{
  SshPm                     pm;
  SshTime                   radius_acct_start_time;
  SshUInt32                 radius_acct_next_session;
  SshRadiusClient           radius_acct_client;
  SshRadiusClientServerInfo radius_acct_servers;
  Boolean                   radius_acct_enabled;
  Boolean                   radius_acct_shutdown;
  int                       radius_acct_refcount;

#ifdef SSH_IPSEC_STATISTICS
  SshPmRadiusAcctStats      stat;
#endif /* SSH_IPSEC_STATISTICS */
};

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

/** The Policy Manager context. */
struct SshPmRec
{
#ifdef DEBUG_LIGHT
  SshUInt32 magic;
#endif /* DEBUG_LIGHT */

  /** Initialization parameters, cannot be changed at runtime. */
  SshPmParamsStruct params;

  /** Run time flags */
  SshUInt32 flags;

  /** Connection to the packet processing engine. */
  SshEngine engine;

  /** FSM (Finite State Machine) instance. */
  SshFSMStruct fsm;

  /** Global audit information. */
  SshPmAuditStruct audit;

  /** Create notification callback and its context.  This is the
      user-supplied callback that is called to notify about the success
      of creating policy manager object and connecting to the packet
      processing engine. */
  SshPmCreateCB create_cb;
  void *create_cb_context;

  /** Destroy callback and its context. */
  SshPmDestroyCB destroy_callback;
  void *destroy_callback_context;

  /** The interface list received from the engine. */
  SshIpInterfacesStruct ifs;

  /** Interface change callback. */
  SshPmInterfaceChangeCB interface_callback;
  void *interface_callback_context;

  /** The current enumeration position in the interfaces array. */
  SshUInt32 ifs_enumerate;

  /** Interface change retry timer. */
  SshUInt8 interface_change_retry;

  /** Policy manager suspend counter. */
  SshUInt8 policy_suspend_count;

  /** Suspend completion callback and context. */
  SshPmCallbacks policy_suspend_cb;

  /** Pointer to the asynchronous operations handler. */
  void *asyncop;

  /** A hash function to be used in various hash operations in the
     policy manager.  This is guaranteed to be a SHA-1 hash.*/
  SshHash hash;

  /** Counters to create unique IDs for different PM API objects. */
  SshUInt32 next_service_id;
  SshUInt32 next_tunnel_id;
  SshUInt32 next_rule_id;
  SshUInt32 next_ek_key_id;
  SshUInt32 next_ca_id;
  SshUInt32 next_audit_id;

  /* Flags. */
  unsigned int connected : 1;           /** Connected to the Engine. */
  unsigned int destroyed : 1;           /** Policy Manager is destroyed. */
  unsigned int config_active : 1;       /** User's configuration thread
                                            active. */
  unsigned int policy_suspended : 1;    /** PM policy is suspended via PM API.
                                         */
  unsigned int policy_suspending : 1;    /** PM policy is suspending. */
  unsigned int batch_deleted_rules : 1; /** Policy reconfiguration deleted
                                            rules. */
  unsigned int batch_active : 1;        /** Rule commit batch active. */
  unsigned int batch_failed : 1;        /** Rule commit batch failed. */
  unsigned int batch_changes : 1;       /** At least one rule commited at
                                            batch. */
  unsigned int iface_change : 1;        /** Interface information changed. */
  unsigned int iface_change_ok : 1;     /** Interface information change
                                            done. */
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
  unsigned int cfgmode_rules : 1;          /** Update config mode rules. */
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */
  unsigned int auto_start : 1;          /** Check auto-start rules. */
#ifdef SSHDIST_EXTERNALKEY
  unsigned int ek_thread_ok : 1;        /** Externalkey thread running. */
  unsigned int ek_key_change : 1;       /** Externalkey key changed. */
#endif /* SSHDIST_EXTERNALKEY */
#ifdef SSHDIST_IKE_CERT_AUTH
  unsigned int cm_auto_rules : 1;       /** Create access rules for validator*/
#endif /* SSHDIST_IKE_CERT_AUTH */
  unsigned int ike_sa_half_timer_registered : 1; /** IKE SA half timer status*/
  unsigned int nested_tunnels : 1;      /** Policy contains nested tunnels. */

  /** Current SPD modification batch.  This is valid if
      'batch_active' is set. */
  struct
  {
    /** Additions to the current commit batch. */
    SshADTContainer additions;

    /** Deletions to the current commit batch. */
    SshADTContainer deletions;

    /** Status callback and context for the current SPD modification
        batch. */
    SshPmStatusCB status_cb;
    void *status_cb_context;

    /** Index into `rule->rules' */
    SshUInt32 current_index;

    /** IKE trigger/pass rule under processing. */
    SshPmRule ike_rule;

    /** Temporary traffic selectors for inner tunnel IKE triggers. */
    SshIkev2PayloadTS ike_triggers_to_ts;
    SshIkev2PayloadTS ike_triggers_from_ts;

    /** IKE ports of processed inner tunnels. */
    SshUInt16 inner_local_ike_ports[SSH_PM_MAX_INNER_TUNNELS];
    SshUInt16 inner_local_ike_natt_ports[SSH_PM_MAX_INNER_TUNNELS];
    SshUInt16 inner_remote_ike_ports[SSH_PM_MAX_INNER_TUNNELS];
    SshUInt16 inner_remote_ike_natt_ports[SSH_PM_MAX_INNER_TUNNELS];
    unsigned int nested_tunnels : 1; /** Configuration batch contains nested
                                         tunnels. */
  } batch;

  /* Active rule containers. */
  SshADTContainer rule_by_id;
  SshADTContainer rule_by_precedence;
  SshADTContainer rule_by_autostart;
  SshADTContainer rule_ike_trigger;

  /** A timeout structure used by main thread during pm initialization
      and shutdown. */
  SshTimeoutStruct main_thread_timeout;

  /** A timeout struct for delaying interface change */
  SshTimeoutStruct interface_change_timeout;
  SshTimeoutStruct auto_start_timeout[1];
  Boolean auto_start_timeout_registered;

  /** Main thread and its synchronization variables. */

  SshFSMThreadStruct main_thread;
  SshFSMConditionStruct main_thread_cond;

  SshFSMConditionStruct resume_cond;

  /** The rule or object the main thread is currently processing. */
  struct
  {
    SshADTContainer container;
    SshADTHandle handle;
    SshUInt32 index;
    SshUInt32 sub_index;
  } mt_current;

  /** Index of an engine rule that the main thread is currently
     processing, or an index result argument from main thread's last
     async engine operation. */
  SshUInt32 mt_index;

  /** Current index of the local TS items of the rule
      the main thread is currently processing. */
  size_t from_ts_index;

  /** Current index of the local and remote TS items of the rule
      the main thread is currently processing. */
  size_t to_ts_index;

  /** Number of active sub-threads the main thread must wait for
      before exiting. */
  SshUInt32 mt_num_sub_threads;

  /** Thread for handling user's configuration requests. */
  SshFSMThreadStruct config_thread;

  /** User requested rule additions. */
  SshADTContainer config_additions;

  /** User requested rule deletions. */
  SshADTContainer config_deletions;

  /** Rule additions waiting for previous batch completion. */
  SshADTContainer config_pending_additions;

  /** Rule deletions waiting for previous batch completion. */
  SshADTContainer config_pending_deletions;

  /** Rules which are waiting for an interface to come up before they
      can be converted to engine rules.*/
  SshADTContainer iface_pending_additions;

  /** Completion callback. */
  SshPmStatusCB config_callback;

  /** Completion callback's context. */
  void *config_callback_context;

  /** Statistics. */
  SshPmGlobalStatsStruct stats;

  /** Freelists for various structures. */
  SshPmFreelistItem rule_freelist;

  /** Freelists for various structures. */
  SshPmFreelistItem service_freelist;

#ifdef SSHDIST_IPSEC_DNSPOLICY
  /** DNS names on the policy cache. */
  SshPmDnsCache dnscache;
  SshPmDnsQuery dns_query_freelist;
#endif /* SSHDIST_IPSEC_DNSPOLICY */

  /** NAT specific data structures follow from here */
#ifdef SSHDIST_IPSEC_NAT
  /** Interface NATs. */
  SshPmIfaceNat iface_nat_list;

  /** Interface NATs. */
  SshPmFreelistItem iface_nat_freelist;
#endif /* SSHDIST_IPSEC_NAT */

  /** SAD handle is used for traffic selector functions. */
  SshSADHandle sad_handle;

  /** IPsec specific data structures follow from here */

  /** IKE parameters. */
  struct SshIkev2ParamsRec ike_params;

  /** IKE UDP parameters. */
  SshUdpListenerParamsStruct ike_udp_params;

  /** IKE local context structure. */
  SshIkev2 ike_context;

#ifdef SSHDIST_IKE_REDIRECT
  /* IKEv2 redirect address */
  SshIpAddrStruct ike_redirect_addr;
  SshUInt8 ike_redirect_enabled;
#endif /* SSHDIST_IKE_REDIRECT */

  /** SAD interface. */
  SshSADInterface sad_interface;

  /** Timer for rekeying or deleting IKE SAs. */
  SshTimeoutStruct ike_sa_timer;

  /** Timer for deleting half open IKE SAs. */
  SshTimeoutStruct ike_sa_half_timer;

  /** Hash index of the ike_sa_hash table to check for IKE rekeys or
      deletions on the next IKE SA timer callback. */
  SshUInt32 ike_sa_hash_element_next;

  /** Hash index of the ike_sa_hash table to check for IKE rekeys or
      deletions on the next IKE SA timer callback. */
  SshUInt32 ike_sa_hash_index_next;

  /** Active Phase-1 initiator and responder negotiations. */
  SshPmP1 active_p1_negotiations;

  /** Active Phase-1 initiator and responder negotiations. */
  SshUInt32 num_active_p1_negotiations;

  /** IKE SA's needing attention after policymanager resume. */
  SshPmP1 resume_queue;

  /** Decaying counter for new IKE connection rate. */
  struct {
    SshUInt32 average_value;    /** Average value. */
    SshUInt32 current_value;    /** Current value. */
    SshUInt32 alpha;            /** Alpha. */
  } ike_connection_rate;

  /** Hash table for completed Phase-1 SAs.  The hash table is indexed
      with IKE peer IP and port. */
  SshPmP1 ike_sa_hash[SSH_PM_IKE_SA_HASH_TABLE_SIZE];

  /** Hash table for completed Phase-1 SAs.  The hash table is indexed
      with IKE remote ID . */
  SshPmP1 ike_sa_id_hash[SSH_PM_IKE_SA_HASH_TABLE_SIZE];

  /** Default IKE SA algorithms. */
  SshUInt32 default_ike_algorithms;

  /** Low-level callback function for finding pre-shared keys for
      IKE Phase-1 negotiations. */
  SshPmIkePreSharedKeyCB ike_preshared_keys_cb;
  void *ike_preshared_keys_cb_context;

  /** Authorization callback. */
  SshPmAuthorizationCB authorization_callback;
  void *authorization_callback_context;

  /** DPD's application notification function. */
  SshPmDpdStatusCB dpd_status_callback;
  void *dpd_status_callback_context;

  SshUInt16 dpd_worry_metric;
  SshUInt16 dpd_dead_ttl;
  SshADTContainer dpd_dead_bag;
  SshTimeoutStruct dpd_timer;

  /** Timer used to abort pending IKE SA delete operations during shutdown. */
  SshTimeoutStruct delete_timer;
  SshUInt8 delete_timer_count;

  /** IKE SA notification callbacks. */
  SshPmIkeSACB ike_sa_callback;
  void *ike_sa_callback_context;

  /** An ADT bag containing servers. */
  SshADTContainer servers;
  Boolean delete_server_timeout_registered;
  /** Timer used to delete servers. */
  SshTimeoutStruct delete_server_timer;

  /** Active QuickMode intitiator and responder negotiations */
  SshPmQm active_qm_negotiations;

  /** Active Quick-Mode negotiations for responder */
  SshADTContainer qm_store_by_peer;

  /** All instantiated tunnels. Used for tunnel_id->tunnel_name lookup. */
  SshADTContainer tunnels;

  /* SPIs. */

  /** Inbound SPIs. */
  SshADTContainer inbound_spis;

  /** Unknown SPIs. */
  SshADTContainer unknown_spis;

  SshPmSpiOut spi_out_spi_hash[SSH_PM_SPI_OUT_HASH_TABLE_SIZE];
  SshPmSpiOut spi_out_address_hash[SSH_PM_SPI_OUT_HASH_TABLE_SIZE];

  /** Peer information database. */
  SshPmPeer peer_handle_hash[SSH_PM_PEER_HANDLE_HASH_TABLE_SIZE];
  SshPmPeer peer_sa_hash[SSH_PM_PEER_IKE_SA_HASH_TABLE_SIZE];
  SshPmPeer peer_local_addr_hash[SSH_PM_PEER_ADDR_HASH_TABLE_SIZE];
  SshPmPeer peer_remote_addr_hash[SSH_PM_PEER_ADDR_HASH_TABLE_SIZE];
  SshUInt32 next_peer_handle;

  /** Flags for server shutdown */
  SshUInt32 servers_stop_flags;

  /** Completion callback for servers shutdown. */
  SshPmServersStopDoneCB servers_stop_done_cb;
  void *servers_stop_done_cb_context;

  /** Completion callback for servers interface change. */
  SshPmServersIfaceChangeDoneCB server_iface_change_done_cb;
  void *server_iface_change_done_cb_context;

  /** IPSEC SA notification callback. */
  SshPmIpsecSACB ipsec_sa_callback;

  /** IPSEC SA notification callback context. */
  void *ipsec_sa_callback_context;

  /** Authentication domains. */
  SshADTContainer auth_domains;

  /** Default authentication domain. */
  SshPmAuthDomain default_auth_domain;

#ifdef SSHDIST_IKE_EAP_AUTH
  /** Static EAP and EAP with radius backed configuration. The
      callbacks on configuration are set by appropriate backends. */
  SshEapConfiguration eap_config;
#endif /* SSHDIST_IKE_EAP_AUTH */

#ifdef SSHDIST_IKE_CERT_AUTH
  /** Certificate manager. */
  /*  SshCMContext cm;*/
#if 0
  SshCMNotifyEventsStruct notify_events;
#endif
  SshADTContainer cm_access_list;

  /** Trusted CA certificates */
  /*  SshUInt32 num_cas; */
  /*  SshPmCa *cas; */

  struct {
    SshUInt16 server_port;
#ifdef SSHDIST_DIRECTORY_HTTP
    SshHttpServerContext server;
#endif /* SSHDIST_DIRECTORY_HTTP */
    SshADTContainer server_db;
    SshTimeoutStruct timeout;
    Boolean send_certificate_bundles;
  } cert_access;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IPSEC_MOBIKE




  SshUInt32 mobike_rrc_policy;
#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_EXTERNALKEY
  /** The externalkey module, used in the policy manager. */
  SshExternalKey externalkey;

  /** The user-supplied externalkey notification callback. */
  SshEkNotifyCB ek_user_notify_cb;
  void *ek_user_notify_cb_context;

  /** Keys, retrieved from the `externalkey'. */
  SshADTContainer externalkey_keys;

  /** The short name of the acclerator we are using */
  char *accel_short_name;

  /** Information about different externalkeys which are usable for
     IPSec.  Note that externalkeys without valid certificate are not
     computed here. */
  SshUInt32 externalkey_num_rsa;
  SshUInt32 externalkey_num_dss;
#ifdef SSHDIST_CRYPT_ECP
  SshUInt32 externalkey_num_ecdsa;
#endif /* SSHDIST_CRYPT_ECP */

  /** Externalkey thread and its synchronization variables. */

  SshFSMThreadStruct ek_thread;
  SshFSMConditionStruct ek_thread_cond;

  /** The current key that the externalkey thread is processing. */
  SshPmEk ek_thread_key;

  /** Index for various externalkey operations. */
  SshUInt32 ek_thread_index;

  /** Status from the last externalkey operation. */
  SshEkStatus ek_thread_status;
#endif /* SSHDIST_EXTERNALKEY */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /** Implementation of the high-level remote access server
     functionality. */

  /** Allocating remote access attributes and IP addresses. */
  SshPmAddressPool addrpool;

  /** Number of address pools in pm. */
  SshUInt32 num_address_pools;

  /** Next id for address pool */
  SshUInt32 addrpool_id_next;

  /** Implementation of the low-level remote access server
     functionality. */

  /** The default remote access responder. */
  SshPmRemoteAccessAttrsAllocCB remote_access_alloc_cb;
  SshPmRemoteAccessAttrsFreeCB remote_access_free_cb;
  void *remote_access_cb_context;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  /** Active CFGMODE clients. */
  SshPmActiveCfgModeClient cfgmode_clients_hash[
                                        SSH_PM_CFGMODE_CLIENT_HASH_TABLE_SIZE];
  SshPmActiveCfgModeClient cfgmode_clients_freelist;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  SshUInt32 num_virtual_adapters;
  SshPmVirtualAdapter virtual_adapters;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
  /** XAUTH server parameters. */
  struct
  {
    Boolean enabled;
    SshIkeXauthType type;
    SshPmXauthFlags flags;
  } xauth;
#endif /* SSHDIST_IPSEC_XAUTH_SERVER */

  /** Password authentication server callback and context. */
  SshPmPasswdAuthCB passwd_auth_callback;
  void *passwd_auth_callback_context;

#ifdef SSHDIST_IKE_REDIRECT
  /** IKE redirect decision callbacks. */
  SshPmIkeRedirectDecisionCB ike_redirect_decision_cb;
  void *ike_redirect_decision_cb_context;
#endif /* SSHDIST_IKE_REDIRECT */

  /** Legacy authentication client callbacks. */
  SshPmLegacyAuthClientQueryCB la_client_query_cb;
  SshPmLegacyAuthClientResultCB la_client_result_cb;
  void *la_client_context;

  /** The operation ID for legacy authentication client. */
  SshUInt32 la_client_next_operation_id;

#ifdef SSHDIST_L2TP
  /** L2TP server. */
  SshL2tp l2tp;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
  /** Number of active L2TP LNS threads. */
  SshUInt32 num_l2tp_lns_threads;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_RADIUS
#ifdef SSHDIST_IKE_EAP_AUTH
  SshEapRadiusConfigurationStruct l2tp_eap_radius;
#endif /* SSHDIST_IKE_EAP_AUTH */
  SshPppRadiusConfigurationStruct l2tp_radius;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_L2TP */

#ifdef SSH_GLOBALS_EMULATION
  SshPmP1Struct *ssh_pm_p1;
#endif /* SSH_GLOBALS_EMULATION */
  /* Freelists for various structures */
  SshPmFreelistItem tunnel_freelist;
  SshPmFreelistItem p1_freelist;
  SshPmFreelistItem p1_rekey_freelist;
  SshPmFreelistItem p1_negotiation_freelist;

  SshPmFreelistItem spi_in_freelist;
  SshPmFreelistItem spi_out_freelist;
  SshPmFreelistItem spi_unknown_freelist;

  SshPmFreelistItem peer_freelist;

#ifdef SSHDIST_IPSEC_MOBIKE
  SshPmFreelistItem mobike_freelist;
#endif /* SSHDIST_IPSEC_MOBIKE */

  /** Freelist of QM structures, reserved for rekeys.  The system tries
     to keep this full as long as possible to keep active SAs alive.*/
  SshPmFreelistItem qm_rekey_freelist;
  SshUInt32 qm_rekey_freelist_allocated;

  /** Freelist of QM structures, reserved for triggers and responder
     negotiations. */
  SshPmFreelistItem qm_freelist;

  /** Amount of memory currently used by stored packets with unknwon SPIs */
  SshUInt32 unknown_spi_bytes;

  /** Timer for unknown SPI handling */
  SshTimeoutStruct unknown_spi_timer;

  /** Debug configuration. */
  SshPdbgConfigStruct debug_config;

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_L2TP
  /** Freelists for L2TP tunnel and session objects. */
  SshPmFreelistItem lns_tunnel_freelist;
  SshPmFreelistItem lns_tunnel_negotiation_freelist;
  SshPmFreelistItem lns_session_freelist;
#endif /* SSHDIST_L2TP */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
  /** Freelist for vip objects. */
  SshPmFreelistItem vip_freelist;
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#ifdef SSH_PM_BLACKLIST_ENABLED
  /** Blacklist database cotaining all active IKE IDs. */
  SshADTContainer active_blacklist;

  /** Blacklist database used in re-configuration. */
  SshADTContainer pending_blacklist;
#endif /* SSH_PM_BLACKLIST_ENABLED */





#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  /** RADIUS Accounting context */
  SshPmRadiusAcct radius_acct;

#ifdef SSH_IPSEC_STATISTICS
  SshPmRadiusAcctStats radius_acct_stats;
#endif /* SSH_IPSEC_STATISTICS */

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

};

typedef struct SshPmRec SshPmStruct;


/* ************************** Utilities *********************************/

/* Convert SshUInt32 value `value' into a `void *' pointer. 'ptr' */
#define SSH_PM_UINT32_TO_PTR(value)   ((void *)(size_t)(value))

/* Convert `void *' pointer `pointer' into SshUInt32 value. */
#define SSH_PM_PTR_TO_UINT32(pointer)  ((SshUInt32)(size_t)(pointer))


/* ************************** Auditing **********************************/


/** Initialize the policy manager's audit framework. */
Boolean ssh_pm_audit_init(SshPm pm);

/** Uninitialize the audit modules from the policy manager `pm'. */
void ssh_pm_audit_uninit(SshPm pm);

/** Audit the audit event 'event' belonging to the audit subsystem specified
   by 'audit_subsystem' (a bitmask of the SSH_PM_AUDIT_* flags) to the
   policymanager's configured audit modules. */
void
ssh_pm_audit_event(SshPm pm, SshUInt32 audit_subsystem,
                   SshAuditEvent event, ...);

/* ********************* Policy Manager object *****************************/

/** Allocate a new policy manager object.  This also initializes
   various freelists of objects used by the policy manager. */
SshPm ssh_pm_alloc(void);

/** Free policy manager object `pm' and all resouces it has
   allocated. */
void ssh_pm_free(SshPm pm);

/** A timeout function that does the final destruction for the policy
   manager `context'. */
void ssh_pm_destructor_timeout(void *context);

/** Get the current status of policy manager. */
SshPmStatus ssh_pm_get_status(SshPm pm);

/** Suspend policy manager and IKEv2 library. */
void ssh_pm_policy_suspend(SshPm pm, SshPmStatusCB callback, void *context);

/** Resume policy manager and IKEv2 library. */
Boolean ssh_pm_policy_resume(SshPm pm);

/** IKE SA timer. */
void ssh_pm_ike_sa_timer(void *context);

/** IKE SA timer. */
void ssh_pm_ike_sa_timer_event(SshPm pm, void *context,
                               SshTime comparison_time);
/** IKE SA timer. */
void ssh_pm_ike_sa_half_timer(void *context);

/* ********************* Routing stuff *****************************/

/** Fills in the SshInterceptorRouteKey structure using the input parameters.

    The argument 'src' specifies the source address to be used.
    This is an optional argument.

    The argument 'dst' specifies the destination address for the route lookup.
    This argument is mandatory.

    The argument 'ipproto' specifies the IP protocol used. May be left
    undefined.

    The arguments 'src_port' and 'dst_port' define the TCP/UDP ports used
    for communication. Value '0' is undefined.

    The argument 'ifnum' specified the interface that must be used for
    communication with the 'dst' address. */
void ssh_pm_create_route_key(SshPm pm,
                             SshInterceptorRouteKey key,
                             SshIpAddr src,
                             SshIpAddr dst,
                             SshUInt8 ipproto,
                             SshUInt16 src_port,
                             SshUInt16 dst_port,
                             SshUInt32 ifnum,
                             SshVriId routing_instance_id);

#endif /* QUICKSEC_INTERNAL_H */
