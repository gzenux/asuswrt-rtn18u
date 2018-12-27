/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for Remote Access Client Virtual IP handling.
*/

#ifndef RAC_VIRTUAL_IP_INTERNAL_H
#define RAC_VIRTUAL_IP_INTERNAL_H

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT

#include "sshincludes.h"

/** Maximum number of simultaneous virtual IP sessions. */
#define SSH_PM_VIRTUAL_IP_MAX_VIP_SESSIONS 2

/** Virtual IP destroy timeout. If the tunnel specifies the interface-trigger
    flags, the the virtual IP context (and IKE and IPsec SAs) will be
    destroyed after this many seconds after the virtual adapter has been
    configured down. */
#define SSH_PM_VIRTUAL_ADAPTER_DOWN_TIMEOUT 10

/** Maximum number of routes configured to a virtual adapter. */
#if (SSH_PM_MAX_CHILD_SAS < 10)
#define SSH_PM_VIRTUAL_IP_MAX_ROUTES SSH_PM_MAX_CHILD_SAS
#else
#define SSH_PM_VIRTUAL_IP_MAX_ROUTES 10
#endif

/** A predicate to check whether the virtual IP thread 'vip' should die
    because the system is shutting down or because its rule is
    deleted, or because virtual IP interface shutdown is requested.  */
#define SSH_PM_VIP_SHUTDOWN(pm, vip)    \
((pm)->destroyed || !vip->rules || vip->shutdown)

/** A predicate to check whether the virtual IP established for tunnel
    'tunnel'. */
#define SSH_PM_VIP_READY(tunnel) \
((tunnel)->vip != NULL && (tunnel)->vip->unusable == FALSE)

#ifdef SSHDIST_L2TP
/** State codes for L2TP LAC thread. */
typedef enum
{
  SSH_PM_VIP_LAC_CONNECTING,
  SSH_PM_VIP_LAC_CONNECTED,
  SSH_PM_VIP_LAC_TERMINATED
} SshPmVipLacState;
#endif /* SSHDIST_L2TP */

#define SSH_PM_VIRTUAL_IP_MAX_SGW_ADDRESSES 20

/** A SGW route entry. */
typedef struct SshPmVipSgwRouteRec
{
  /* Flags. */
  unsigned int route_found : 1; /** Route found from routing table. */
  unsigned int added : 1;       /** Route added. */
  unsigned int ignore : 1;      /** Ignore this route. */
  unsigned int remove : 1;      /** Route to be removed. */

  /** Route prefix. Undefined for invalidated routes.*/
  SshIpAddrStruct sgw_address;

  /** Route interface index. */
  SshUInt32 ifnum;

  /** MTU towards the peer. */
  SshUInt32 mtu;

  /** Route nexthop. */
  SshIpAddrStruct nexthop;
} SshPmVipSgwRouteStruct, *SshPmVipSgwRoute;

/** A host route entry. */
typedef struct SshPmVipRouteRec
{
  /* Flags. */
  unsigned int added : 1;     /** Route added. */
  unsigned int remove : 1;    /** Route to be removed. */
  unsigned int clear : 1;     /** Route to be cleared after removal.*/

  /** Route prefix. Undefined for invalidated routes.*/
  SshIpAddrStruct prefix;

  /** Route interface index. */
  SshUInt32 ifnum;

  /** Route nexthop. */
  SshIpAddrStruct nexthop;

  /** Transform index, or SSH_IPSEC_INVALID_INDEX for subnet/rule routes. */
  SshUInt32 trd_index;
  /** Rule pointer, or NULL for subnet/SA routes.*/
  SshPmRule rule;
} SshPmVipRouteStruct, *SshPmVipRoute;

typedef struct SshPmVipRuleRec SshPmVipRuleStruct, *SshPmVipRule;
struct SshPmVipRuleRec
{
  SshPmVipRule next;
  SshPmRule rule;
};

/** Context data for virtual IP threads.  There is one structure of
    this type for each virtual IP initiator rule in the system.  The
    context data remains valid as long as the virtual IP operation is
    pending, including the time the virtual IP is assigned for the
    host. */
struct SshPmVipRec
{
  /* Flags. */
  unsigned int successful : 1;         /** Status of virtual IP setup. */
  unsigned int timeout : 1;            /** Operation timed out. */
  unsigned int shutdown : 1;           /** Virtual IP shutdown requested. */
  unsigned int reconfigure : 1;        /** Reconfigure VIP addrs and routes. */
  unsigned int add_routes : 1;         /** Add VIP routes requested. */
  unsigned int remove_routes : 1;      /** Remove VIP routes requested. */
  unsigned int add_sgw_routes : 1;     /** Add VIP SGW routes requested. */
  unsigned int remove_sgw_routes : 1;  /** Remove VIP SGW routes requested. */
  unsigned int reconfigure_routes : 1; /** Reconfigure VIP routes requested. */
  unsigned int t_cfgmode : 1;          /** Virtual IP type: IKE CFGMODE. */
  unsigned int t_l2tp : 1;             /** Virtual IP type: L2TP. */
  unsigned int adapter_configured : 1; /** Virtual interface configured. */
  unsigned int name_servers_added : 1; /** Nameserver(s) added */
  unsigned int waiting_for_destroy : 1; /** Destroy timeout is registered. */
  unsigned int unusable : 1;           /** Virtual IP is not ready; either
                                           setup or shutdown is ongoing. */
  unsigned int rule_deleted: 1;        /** One of the rules using this vip
                                           has been deleted */

  /** SGW's IP address. */
  SshPmVipSgwRouteStruct sgw[SSH_PM_VIRTUAL_IP_MAX_SGW_ADDRESSES];

  /** Flags from the first rule using this VIP. */
  SshUInt32 rule_flags;

  /** FSM thread, executing this operation. */
  SshFSMThreadStruct thread;

  /** Condition variable for waking up vip thread. */
  SshFSMConditionStruct cond;

  /** List of rules using this VIP record. */
  SshPmVipRule rules;

  /** Pointer to pm. */
  SshPm pm;

  /** A shortcut to the tunnel.  This is taken from 'rule' and is valid
      for the lifetime of the vip object. */
  SshPmTunnel tunnel;

  /** Phase-1 negotiation used to protect the virtual IP obtaining. */
  SshPmP1 p1;

  /** IKE peer handle. The vip object takes one reference to peer_handle
      when it is set and releases it when peer_handle is reset or the
      vip shuts down. */
  SshUInt32 peer_handle;

  /** Virtual adapter ID, name, routing instance ID, and interface number. */
  char adapter_name[SSH_INTERCEPTOR_IFNAME_SIZE];
  SshUInt32 adapter_ifnum;
  SshVriId routing_instance_id;

  /** A timeout structure. */
  SshTimeoutStruct timeout_struct;

  /** An index used in various iterations in the virtual IP
      implementations. */
  SshUInt32 index;

  /** Routes that must be / have been added by this virtual IP thread. */
  SshUInt32 num_routes;
  SshPmVipRouteStruct routes[SSH_PM_VIRTUAL_IP_MAX_ROUTES];

#ifdef SSHDIST_IKE_REDIRECT
  /** IKE is redirected to another gateway redirect_count times. */
  SshIpAddrStruct redirect_addr[1];
  SshUInt8 redirect_count;
#endif /* SSHDIST_IKE_REDIRECT */

  /** Which state to continue from after adding or deleting routes. */
  SshFSMStepCB add_routes_next;
  SshFSMStepCB remove_routes_next;

  /** Type dependent data for obtaining the virtual IP. */
  union
  {
#ifdef SSHDIST_ISAKMP_CFG_MODE
    struct
    {
      /* Flags. */
      unsigned int done : 1;     /** IKE CFGMODE done. */
      SshIkev2Error ike_error;   /** Error code form the IKE negotiation. */
    } cfgmode;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_L2TP
    struct
    {
      /* Flags. */
      unsigned int route_ok : 1;    /** Route destination reachable. */
      unsigned int auth_ok : 1;     /** Status of authentication info query. */
      unsigned int auth_cb_fail : 1;/** AuthCB failed / out of memory. */
      unsigned int lac_state : 8;   /** SshPmVipLacState. */
      unsigned int l2tp_status : 1; /** L2TP session status valid. */
      unsigned int ppp_signal : 1;  /** PPP signal valid. */
      unsigned int ppp_halt : 1;    /** PPP halt. */
      unsigned int output_acfc : 1; /** ACFC in PPP. */
      unsigned int output_pfc : 1;  /** PFC in PPP. */
      unsigned int ref_to_sa_rule : 1;  /** Reference added to SA rule. */

      /** Index to tunnel's peers. */
      SshUInt32 peer_index;

      /** Local interface number towards our peer. */
      SshUInt32 local_ifnum;

      /** Local IP address used in the L2TP negotiation. */
      SshIpAddrStruct local_ip;

      /** Index of the legacy authentication operation. */
      SshUInt32 operation_id;

      /** Authentication information. */

      unsigned char *user_name;
      size_t user_name_len;

      unsigned char *user_password;
      size_t user_password_len;

      /** Indexes of the IPSec SA rule and transform which protect the
         L2TP traffic. */
      SshUInt32 sa_rule_index;
      SshUInt32 trd_index;

      /** The L2TP tunnel implementation rule index. */
      SshUInt32 tunnel_index;

      /** Sub-thread for handling the L2TP negotiation. */
      SshFSMThreadStruct thread;

      /** Abortable L2TP operation. */
      SshOperationHandle operation;

      /** L2TP session status. */
      SshL2tpSessionInfo info;
      SshL2tpSessionStatus status;

      /** PPP signal. */
      SshPppSignal signal;

      /** A condition variable that is signalled when the L2TP and PPP
         session statuses change. */
      SshFSMConditionStruct status_cond;

      /** PPP instance. */
      SshPPPHandle ppp;
    } l2tp;
#endif /* SSHDIST_L2TP */

    /* Dummy data. */
    void *dummy;
  } t;

  /** Virtual IP attributes and the address selected to be used. */
  SshPmRemoteAccessAttrsStruct attrs;
  SshUInt32 num_selected_addresses;
  SshIpAddrStruct selected_address[SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES];

  /** Virtual IP type dependent attributes.  The flags
     `t_{cfgmode,l2tp}' specify which of these fields is valid. */
  union
  {
#ifdef SSHDIST_ISAKMP_CFG_MODE
    /** Nothing extra for CFGMODE. */
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_L2TP
    /** L2TP */
    struct
    {
      /** PPP link's peer IP address. */
      SshIpAddrStruct peer_address;
    } l2tp;
#endif /* SSHDIST_L2TP */

    /* Dummy data. */
    void *dummy;
  } u;

  /** Client authentication operation */
  SshOperationHandle la_auth_operation;

  /** Reference count. */
  SshUInt32 refcnt;
};

typedef struct SshPmVipRec SshPmVipStruct;
typedef struct SshPmVipRec *SshPmVip;

typedef struct SshPmVirtualAdapterRec
{
  SshUInt32 adapter_ifnum;
  unsigned char adapter_name[SSH_INTERCEPTOR_IFNAME_SIZE];
  Boolean reserved;            /* Virtual adapter is reserved for a tunnel. */
  Boolean in_use;              /* Virtual adapter is used by a tunnel. */
} SshPmVirtualAdapterStruct, *SshPmVirtualAdapter;

/** Callback function for ssh_pme_virtual_adapter_list, which is called
    asynchronously from thread context. Argument `context' is the SshFsmThread.
    This function will process the virtual adapters and call
    SSH_FSM_CONTINUE_AFTER_CALLBACK for the thread. */
void
ssh_pm_vip_get_virtual_adapters_cb(SshPm pm,
                                   SshVirtualAdapterError error,
                                   SshUInt32 num_adapters,
                                   SshPmeVirtualAdapter adapters,
                                   void *context);

/** This function checks if a tunnel handles interface triggers and installs
    a timer to destroy the virtual IP context. If this returns TRUE, then the
    auto-start thread should start the virtual IP thread. If this returns
    FALSE, then the auto-start thread can ignore the rule. */
Boolean
ssh_pm_vip_rule_interface_trigger(SshPm pm, SshPmRule rule);

/** This function checks if IKE SA `p1->ike_sa' is using a vip tunnel and
    marks the virtual interface unusable.  All triggers to an unusable vip
    tunnel will be dropped. */
void
ssh_pm_vip_mark_unusable(SshPm pm, SshPmP1 p1);

/** Find virtual adapter matching `adapter_ifnum'. */
SshPmVirtualAdapter
ssh_pm_virtual_adapter_find_byifnum(SshPm pm, SshUInt32 adapter_ifnum);

/** Flush route entries for SGW addresses. */
void
ssh_pm_vip_flush_sgw_routes(SshPmVip vip);


/** Create a route entry for SGW address. */
void
ssh_pm_vip_create_sgw_route(SshPmVip vip, SshIpAddr sgw_ip);


/** Create a route entry to narrowed traffic selector item
    `item'. Argument `trd_index' identifies the transform to which
    this route is related to. This function is called from SA handler
    to create routes to negotiated IPsec SA traffic selectors. Route
    is not created if there is another route with the same destination
    prefix. */
void
ssh_pm_vip_create_transform_route(struct SshPmVipRec *vip,
                                  SshIkev2PayloadTSItem item,
                                  SshUInt32 trd_index);

/** Create a route entry to the destination corresponding to the
    traffic selector item `item'. Argument `rule' identifies the rule
    to which this route is related to. Route is not created if there
    is another route with the same destination prefix. */
void
ssh_pm_vip_create_rule_route(struct SshPmVipRec *vip,
                             SshIkev2PayloadTSItem item,
                             SshPmRule rule);

/** Create a route entry to the destination corresponding to the
    address/mask `prefix'. This function is called to create routes
    corresponding to internal subnet information received from the
    gateway. Route is not created if there is another route with the
    same destination prefix. */
void
ssh_pm_vip_create_subnet_route(struct SshPmVipRec *vip, SshIpAddr prefix);

/** Configure virtual adapter. This wrapper functions calls platform dependent
    functions to do the actual configuration. */
void
ssh_pm_virtual_adapter_configure(SshPm pm,
                                 SshUInt32 adapter_ifnum,
                                 SshVirtualAdapterState adapter_state,
                                 SshUInt32 num_addresses,
                                 SshIpAddr addresses,
                                 SshVirtualAdapterParams params,
                                 SshPmeVirtualAdapterStatusCB callback,
                                 void *context);

/** Add a route. This wrapper functions calls platform dependent functions
    to do the actual addition. */
void
ssh_pm_route_add(SshPm pm,
                 SshInterceptorRouteKey key,
                 const SshIpAddr gateway,
                 SshUInt32 ifnum,
                 SshRoutePrecedence precedence,
                 SshUInt32 flags,
                 SshPmeRouteSuccessCB callback, void *context);

/** Remove a route. This wrapper functions calls platform dependent functions
    to do the actual removal. */
void
ssh_pm_route_remove(SshPm pm,
                    SshInterceptorRouteKey key,
                    const SshIpAddr gateway,
                    SshUInt32 ifnum,
                    SshRoutePrecedence precedence,
                    SshUInt32 flags,
                    SshPmeRouteSuccessCB callback, void *context);


/** Allocate vip object. */
SshPmVip ssh_pm_vip_alloc(SshPm pm);

/** Free vip object. */
void ssh_pm_vip_free(SshPm pm, SshPmVip vip);

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */

#endif /* not RAC_VIRTUAL_IP_INTERNAL_H */
