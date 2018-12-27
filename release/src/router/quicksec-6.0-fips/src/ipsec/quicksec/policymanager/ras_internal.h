/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for Remote Access Server functionality.
*/

#ifndef RAS_INTERNAL_H
#define RAS_INTERNAL_H

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#include "sshincludes.h"
#include "ras_addrpool.h"
#include "ras_dhcp_addrpool.h"

#ifdef SSHDIST_L2TP
#include "sshl2tp.h"
#include "sshppp.h"
#endif /* SSHDIST_L2TP */

/** An active configuration mode client */
struct SshPmActiveCfgModeClientRec
{
  /** Link field for hash table and freelist. */
  struct SshPmActiveCfgModeClientRec *next;

  SshPm pm;

  /* Peer handle. */
  SshUInt32 peer_handle;

  /* Reference count on this structure, each transform and IKE SA with
     the peer has one reference.  */
  SshUInt16 refcount;

  /** The remote access client's leased IP address, one can have
      either one, or both ipv4 and ipv6 addresses. These addresses
      here are dynamically allocated to save some space, as Address
      structures are pretty large. */
  SshIpAddr addresses[SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES];
  SshUInt8 num_addresses;
  void *address_context;

  /** Internal state. */
#define SSH_PM_CFGMODE_CLIENT_STATE_IDLE        0
#define SSH_PM_CFGMODE_CLIENT_STATE_ADDING_ARP  1
#define SSH_PM_CFGMODE_CLIENT_STATE_RENEWING    2
  SshUInt8 state;

  /** Internal flags. */
#define SSH_PM_CFGMODE_CLIENT_IPV4_PROXY_ARP     0x01
#define SSH_PM_CFGMODE_CLIENT_IPV6_PROXY_ARP     0x02
#define SSH_PM_CFGMODE_CLIENT_ABORTED            0x04
  SshUInt8 flags;

  /** Alloc callback that is called to renew the leases for IP addresses
      registered to this cfgmode client. */
  SshPmRemoteAccessAttrsAllocCB renew_cb;

  /** Free callback that is called to release the IP address `address'
      back to its allocation storage. */
  SshPmRemoteAccessAttrsFreeCB free_cb;

  /** Context for `renew_cb' and `free_cb'. */
  void *ras_cb_context;

  /** Status callback for the ssh_pm_cfgmode_client_store_register(). */
  SshPmStatusCB status_cb;
  void *status_cb_context;

  /** Operation handle for aborting ssh_pm_cfgmode_client_store_register()
      and ssh_pm_cfgmode_client_store_renew(). */
  SshOperationHandleStruct operation;

  /** Operation handle to `renew_cb' sub-operation. */
  SshOperationHandle sub_operation;

  /* Client reference count for ARP operations. */
  SshUInt8 num_arp_operations;

  /* DHCP lease renewal timer. */
  SshUInt32 lease_time;
  SshTimeoutStruct lease_renewal_timer;


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS
  void *radius_acct_context;
#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
};

typedef struct SshPmActiveCfgModeClientRec SshPmActiveCfgModeClientStruct;
typedef struct SshPmActiveCfgModeClientRec *SshPmActiveCfgModeClient;

#ifdef SSHDIST_L2TP
/** A forward declaration for L2TP LNS tunnel negotiation. */
typedef struct SshPmLnsTunnelNegotiationRec *SshPmLnsTunnelNegotiation;

/** An L2TP LNS tunnel context.  This can be found from the
   `upper_level_data' field of the SshL2tpTunnelInfo structure. */
struct SshPmLnsTunnelRec
{
  /* Flags and refcount. */
  unsigned int refcount : 8;    /** Number of references to this object. */
  unsigned int proxy_arp : 1;   /** Do proxy ARP for clients in private net. */

  /** Local interface towards tunnel's remote peer. */
  SshUInt32 local_ifnum;

  /** The implementation rule of the high-level L2TP rule.  The
     outbound L2TP rules depend on this rule. */
  SshUInt32 l2tp_rule_index;

  /** Rule and transform protecting this L2TP tunnel. */
  SshUInt32 sa_rule_index;
  SshUInt32 trd_index;

  /** Index of the control rule which protects the L2tp traffic. */
  SshUInt32 control_rule_index;

  /** PM tunnel definition we are using */
  SshPmTunnel tunnel;
  SshPmRule rule;

  /** Precedence value for the outbound rules of this L2TP session. */
  SshUInt32 outbound_rule_precedence;

  /** Tunnel ID for the tunnel to/from the packets from the L2TP
     session go. */
  SshUInt32 reverse_tunnel_id;

#ifdef SSHDIST_IPSEC_NAT
  SshIpAddrStruct dst_nat_ip_low;
  SshIpAddrStruct dst_nat_ip_high;
  SshUInt16 dst_nat_port;
  SshPmNatFlags dst_nat_flags;

  SshIpAddrStruct dst_nat_selector_ip;
  SshUInt16 dst_nat_selector_port;
#endif /* SSHDIST_IPSEC_NAT */

  /** A timeout placeholder for delays in state transitions */
  SshTimeoutStruct tunnel_timeout;

  /** Thread handling the tunnel negotiation, up and down. */
  SshFSMThreadStruct thread;

  /** Tunnel negotiation.  This field is set as long as the tunnel
     negotiation is active.  When the tunnel is established, this
     field is cleared. */
  SshPmLnsTunnelNegotiation n;
};

typedef struct SshPmLnsTunnelRec SshPmLnsTunnelStruct;
typedef struct SshPmLnsTunnelRec *SshPmLnsTunnel;

/** An L2TP LNS tunnel establishment context.  This is valid as long as
   the tunnel negotiation is active.  When the tunnel is established,
   this context is recycled. */
struct SshPmLnsTunnelNegotiationRec
{
  /* Flags. */
  unsigned int aborted : 1;      /** Tunnel request aborted. */
  unsigned int route_ok : 1;     /** Route destination reachable. */
  unsigned int get_rule_ok : 1;  /** IPSec SA rule retrieved. */
  unsigned int l2tp_rule_ok : 1; /** L2TP control traffic rule created. */

  /** An SshOperationHandle for the tunnel request. */
  SshOperationHandleStruct operation_handle;

  /** The L2TP tunnel object of this tunnel. */
  SshL2tpTunnelInfo info;

  /** Error message for rejected tunnel requests. */
  char *error_message;

  /** Completion callback and its context for tunnel request. */
  SshL2tpTunnelRequestCompletionCB req_completion_cb;
  void *req_completion_cb_context;
};

typedef struct SshPmLnsTunnelNegotiationRec SshPmLnsTunnelNegotiationStruct;

/** An L2TP session context.  This can be found from the
    'upper_level_data' field of the SshL2tpSessionInfo structure. */
struct SshPmLnsSessionRec
{
  /* Flags. */
  unsigned int ppp_up : 1;      /** PPP link up. */
  unsigned int terminated : 1;  /** Session terminated. */
  unsigned int output_acfc : 1; /** ACFC in PPP. */
  unsigned int output_pfc : 1;  /** PFC in PPP. */
  unsigned int arp_ok : 1;      /** Status of ARP add operation. */
#ifdef SSHDIST_RADIUS
  unsigned int uses_radius : 1; /** Session uses RADIUS for authentication. */
#endif /* SSHDIST_RADIUS */

  /** Number of references to this object. */
  SshUInt8 refcount;

#ifdef SSHDIST_IKE_EAP_AUTH
  SshUInt8 ppp_eap_type;              /** EAP protocol */
#endif /* SSHDIST_IKE_EAP_AUTH */

  /** The PPP authentication type. */
  SshPppAuthType ppp_auth_type;

  /** The L2TP session object of this session. */
  SshL2tpSessionInfo info;

  /** User-name and password.  These can be NULL for example for the
     RADIUS authentication. */

  unsigned char *user_name;
  size_t user_name_len;

  unsigned char *user_password;
  size_t user_password_len;

  /** PPP library's context data for the `get secret' operation. */
  SshPppAuthType auth_type;
  void *ppp_get_secret_context;

  /** Dynamically allocate IP address, proposed for the LAC.  This can
      be overridden by some authentication methods (RADIUS). */
  SshIpAddrStruct dynamic_lac_ip;
  void *dynamic_lac_ip_context;

  /** Id of the SshPmTunnel that was used for dynamic IP address allocation.
      This is used for looking up the tunnel when freeing the dynamic IP
      address to the tunnel's address pool. */
  SshUInt32 dynamic_lac_ip_tunnel_id;

  /** Operation handle for async sub operations. */
  SshOperationHandle sub_operation;

  /** LAC's IP address. */
  SshIpAddrStruct lac_ip;

  /** Index of the outbound rule. */
  SshUInt32 outbound_rule_index;

  /** Thread handling the session. */
  SshFSMThreadStruct thread;

  /** Condition variable for signaling the thread. */
  SshFSMConditionStruct cond;

  /** Parameters for PPP.  These are set only when the LNS is starting
      PPP.  This will be freed after the PPP instance `ppp' is
      started. */
  SshPppParams ppp_params;

  /** PPP instace of this session. */
  SshPPPHandle ppp;
};

typedef struct SshPmLnsSessionRec SshPmLnsSessionStruct;
typedef struct SshPmLnsSessionRec *SshPmLnsSession;
#endif /* SSHDIST_L2TP */

/* ************************* RAS Statemachine ********************************/

typedef struct SshPmIkev2ConfQueryRec
{
  SshPmP1 p1;
  SshIkev2ExchangeData ed;
  SshPmTunnel tunnel;
  SshIkev2Error error;

  /* Thread for the RAS attribute allocation. */
  SshFSMThreadStruct thread;

  /* Operation handle for RAS allocate callback. */
  SshOperationHandle sub_operation;

  /* Conf payload constructed from the attribute list. */
  SshIkev2PayloadConf conf_payload;

  /* Attributes requested by client */
  SshPmRemoteAccessAttrs client_attributes;

  /* An index to the array of returned client addresses. */
  int index;

  /* Flag denoting IKE SA import. */
  Boolean ike_sa_import;

  /* Terminal state for the cfgmode thread */
  SshFSMStepCB fsm_st_done;

} SshPmIkev2ConfQueryStruct, *SshPmIkev2ConfQuery;

/* ************************* Active CFGMODE clients **************************/

/** Initialize the CFGMODE client storage of the policy manager `pm'. */
Boolean ssh_pm_cfgmode_client_store_init(SshPm pm);

/** Uninitialize the CFGMODE client storage of the policy manager `pm'. */
void ssh_pm_cfgmode_client_store_uninit(SshPm pm);

/** Allocate a client object from the CFGMODE client store of `pm'.
    The function returns NULL if there are no client objects available. */
SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_alloc(SshPm pm, SshPmP1 p1);

/** Lookup a client by peer_handle. */
SshPmActiveCfgModeClient
ssh_pm_cfgmode_client_store_lookup(SshPm pm, SshUInt32 peer_handle);

/** Take a reference to 'client'. */
void
ssh_pm_cfgmode_client_store_take_reference(SshPm pm,
                                           SshPmActiveCfgModeClient client);

/** Give up a reference to 'client'. */
void
ssh_pm_cfgmode_client_store_unreference(SshPm pm,
                                        SshPmActiveCfgModeClient client);

/** Macro for grabbing references to SshPmActiveCfgModeClient. */
#define SSH_PM_CFGMODE_CLIENT_TAKE_REF(_pm, _cm)                        \
  do {                                                                  \
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Taking reference to client 0x%p "     \
                                 "current refcount %u new %u", (_cm),   \
                                 (_cm)->refcount, (_cm)->refcount + 1)); \
    ssh_pm_cfgmode_client_store_take_reference(_pm, _cm);               \
  } while (0)

/** Macro for releasing references to SshPmActiveCfgModeClient. */
#define SSH_PM_CFGMODE_CLIENT_FREE_REF(_pm, _cm)                        \
  do {                                                                  \
    SSH_DEBUG(SSH_D_NICETOKNOW, ("Releasing reference to client 0x%p "  \
                                 "current refcount %u new %u", (_cm),   \
                                 (_cm)->refcount, (_cm)->refcount - 1)); \
    ssh_pm_cfgmode_client_store_unreference(_pm, _cm);                  \
  } while (0)

/** Register a new CFGMODE client IP address `address' to the storage.
    The argument `client' specifies a client object that must be
    allocated with ssh_pm_cfgmode_client_store_alloc(). The arguments
    `renew_cb', `free_cb' and `ras_cb_context' specify callback functions
    and context that should be called when the address `address' lease is
    renewed or when the address has no more references.
    The argument `address_context' is the address specific context that
    is passed to `free_cb' with the address and the `free_cb_context'.
    When the IP address `address' is registered it will have one
    reference. If the tunnel has the SSH_PM_TR_PROXY_ARP flag set, a
    proxy ARP entry will be added for the address 'address'. This function
    calls 'status_cb' when done to inform about the success of this
    operation. It is a fatal error to call this function again for the same
    client storage object before the previous call has completed. If the
    operation failed then the address has not been added to the storage and
    the caller is responsible for freeing it. This returns an operation
    handle for aborting this operation. */
SshOperationHandle
ssh_pm_cfgmode_client_store_register(SshPm pm,
                                     SshPmTunnel tunnel,
                                     SshPmActiveCfgModeClient client,
                                     SshPmRemoteAccessAttrs attributes,
                                     SshPmRemoteAccessAttrsAllocCB renew_cb,
                                     SshPmRemoteAccessAttrsFreeCB free_cb,
                                     void *ras_cb_context,
                                     SshPmStatusCB status_cb,
                                     void *status_cb_context);

SshOperationHandle
ssh_pm_cfgmode_client_store_renew(SshPm pm,
                                  SshPmActiveCfgModeClient client,
                                     SshPmStatusCB status_cb,
                                  void *status_cb_context);

/* *********************** Internal Address Pool Functions *******************/

/* Default address pool name. This is used internally by the RAS. */
#define ADDRPOOL_DEFAULT_NAME "DEFAULT-AP"

/** Get id of address pool with given name
    @param name
    name of the address pool

    @param len
    length of the name passed

    @param SshPmAddrPoolId*
    id of the address pool is filled in this param

    @return Boolean
    TRUE if id is found
    FALSE if address pool with given name is not found. */
Boolean
ssh_pm_address_pool_get_id(SshPm pm,
                           const unsigned char *name,
                           SshPmAddrPoolId *id);

/** Get id of default address pool

    @param len
    length of the name passed

    @param SshPmAddrPoolId*
    id of the address pool is filled in this param

    @return Boolean
    TRUE if id is found
    FALSE if default address pool is not found. */

Boolean
ssh_pm_address_pool_get_default_id(SshPm pm,
                                   SshPmAddrPoolId *id);

/** Default remote access attribute allocation callback. This function
    attempts to allocate remote access attributes from the address pools
    configured to a tunnel. The argument `context' contains the tunnel_id
    of the tunnel in encoded format. This calls `result_cb' callback
    asynchronously to pass the allocated remote access attributes. On
    immediate error this calls `result_cb' synchronously and returns NULL. */
SshOperationHandle
ssh_pm_ras_alloc_address(SshPm pm,
                         SshPmAuthData ad,
                         SshUInt32 flags,
                         SshPmRemoteAccessAttrs requested_attributes,
                         SshPmRemoteAccessAttrsAllocResultCB result_cb,
                         void *result_cb_context,
                         void *context);

/** Default remote access attribute free callback. This function returns the
    address to the address pool it was allocated from. This functions also
    performs delayed address pool deletion if the address pool has been
    removed from PM and the freed address was the last active lease from
    the address pool. The argument `address_context' contains the address
    pool id in encoded format. */
void
ssh_pm_ras_free_address(SshPm pm,
                        const SshIpAddr address,
                        void *address_context,
                        void *context);

#ifdef SSHDIST_L2TP
/* ********************************* L2TP Stuff *****************************/

/** Allocate a new LNS tunnel object. */
SshPmLnsTunnel ssh_pm_lns_tunnel_alloc(SshPm pm);

/** Free the LNS tunnel object `tunnel'. */
void ssh_pm_lns_tunnel_free(SshPm pm, SshPmLnsTunnel tunnel);

/** Allocate a new LNS tunnel negotiation object. */
SshPmLnsTunnelNegotiation ssh_pm_lns_tunnel_negotiation_alloc(SshPm pm);

/** Free the LNS tunnel negotiation object `n'. */
void ssh_pm_lns_tunnel_negotiation_free(SshPm pm,
                                        SshPmLnsTunnelNegotiation n);

/** Allocate a new LNS session object. */
SshPmLnsSession ssh_pm_lns_session_alloc(SshPm pm);

/** Free the LNS session object `session'. */
void ssh_pm_lns_session_free(SshPm pm, SshPmLnsSession session);
#endif /* SSHDIST_L2TP */

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */
#endif /* not RAS_INTERNAL_H */
