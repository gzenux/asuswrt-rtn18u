/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
       Top-level policy management API for QuickSec.

       @description
       This API defines means for the following operations:

       - Creating, configuring and destroying the Policy Manager object:
         ssh_pm_create, ssh_pm_destroy, ssh_pm_redo_flows,
         ssh_pm_set_params, ssh_pm_set_engine_params, etc. (ssh_pm_set_*)
       - Accessing network interfaces at the system:
         - ssh_pm_interface_get_address, ssh_pm_interface_get_broadcast,
           ssh_pm_interface_get_netmask, ssh_pm_interface_enumerate_start,
           etc. (ssh_pm_interface_*, ssh_pm_get_interface*)
         - ssh_pm_get_interface_name, ssh_pm_get_interface_number
       - Processing of top level policy objects:
         - rules: ssh_pm_rule_create, ssh_pm_rule_add,
           ssh_pm_rule_delete, etc. (ssh_pm_rule*)
         - services: ssh_pm_service_create, ssh_pm_service_compare,
           ssh_pm_service_destroy, etc. (ssh_pm_service*)
         - use of new policy: ssh_pm_commit, ssh_pm_abort
       - Configuring system information into the Policy Manager:
         ssh_pm_configure_interface, ssh_pm_configure_route,
         etc. (ssh_pm_configure*)
       - Configuring auditing:
         ssh_pm_create_audit_module, ssh_pm_attach_audit_module,
         SSH_PM_AUDIT_ALL, SSH_PM_AUDIT_ENGINE, SSH_PM_AUDIT_POLICY,
         etc. (ssh_pm_*audit*)
       - Accessing flow information:
         ssh_pm_get_flow_info, ssh_pm_get_flow_stats,
         etc. (ssh_pm_get_flow*)
       - Accessing rule information:
         ssh_pm_get_rule_info, ssh_pm_get_rule_stats,
         etc. (ssh_pm_get_rule*)
       - Using DNS name resolution for policies:
         ssh_pm_indicate_dns_change, ssh_pm_rule_get_dns_status.

   Note: This header file is not intented to be included directly.
   The quicksecpm.h header file should be included instead.
*/

#ifndef CORE_PM_H
#define CORE_PM_H

#include "sshaudit.h"
#include "sshoperation.h"
#include "sshpdbg.h"
#include "sshikev2-initiator.h"
#include "sshikev2-payloads.h"

/*--------------------------------------------------------------------*/
/* Data types.                                                        */
/*--------------------------------------------------------------------*/

/** Data type for a top level policy tunnel object handle. A tunnel
    object specifies IKE and IPSec algorithms, peers and other
    tunneling parameters. */
typedef struct SshPmTunnelRec *SshPmTunnel;

/** Data type for a service specification handle. Services are used
    application gateways and ICMP types/codes. */
typedef struct SshPmServiceRec *SshPmService;

/** Data type for a top level policy rule object handle.  A rule binds
    together optional from and to tunnels, service, and rule selectors
    (IP addresses, DNS names, interfaces, etc). */
typedef struct SshPmRuleRec *SshPmRule;

typedef struct SshPmAuthDomainRec *SshPmAuthDomain;


/*--------------------------------------------------------------------*/
/* Callback types.                                                    */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called to report success of
    opening the Packet Processing Engine.  If the argument 'pm' is
    NULL, the engine opening failed.  Otherwise, it specifies a Policy
    Manager object that is used to configure IPsec policy. */
typedef void (*SshPmCreateCB)(SshPm pm, void *context);

/** A callback function of this type is called when a Policy Manager
    object is destroyed. */
typedef void (*SshPmDestroyCB)(void *context);

/** Callback function used to indicate whether an operation was
    successful or not.

    @return
    The value of 'success' is TRUE on success, and FALSE on failure. */
typedef void (*SshPmStatusCB)(SshPm pm, Boolean success, void *context);

/** Callback function used to return indices.

    @param index
    The 'index' argument has the value SSH_IPSEC_INVALID_INDEX on
    error and a valid index otherwise. */
typedef void (*SshPmIndexCB)(SshPm pm, SshUInt32 index, void *context);


/*--------------------------------------------------------------------*/
/* Top-level functions.                                               */
/*--------------------------------------------------------------------*/

/** Parameters for ssh_pm_create; the parameters are static so that
    you cannot change them after Policy Manager has been created. */
struct SshPmParamsRec
{
  /** Sets the SOCKS server URL to be used when accessing directories
      using LDAP or HTTP; the URL specifies the SOCKS host, port,
      username, and socks network exceptions - if the port number is
      not specified, the default SOCKS port 1080 will be used; if the
      field is unset, connections will be made without SOCKS. */
  unsigned char *socks;

  /** Sets the HTTP proxy to be used when accessing directories using
      HTTP; the URL specifies the HTTP proxy server and port
      number. */
  unsigned char *http_proxy;

  /** The name of the host - this is used, for example, in L2TP to
      identify the host; this should be a human readable name for the
      machine (DNS name, etc.); if the hostname is unset, no hostname
      is send to remote machines. */
  unsigned char *hostname;

  /** If this parameter is set, inbound IPsec packets to the local host
      whose SPI is not in the SAD will be forwarded to the local stack;
      this parameter may be set if QuickSec needs to co-exist with
      other IPsec implementations running on the same host. */
  Boolean pass_unknown_ipsec_packets;

  /** Only bind IKE sockets to these IP addresses; this means IKE will
      only respond to requests at these addresses. */
  size_t ike_addrs_count;

  /** An array containing 'ike_addrs_count' elements each containing
  one IP address structure; it must be dynamic memory allocated with
  ssh_malloc(); Policy Manager steals that pointer and frees it upon
  exit. */
  SshIpAddrStruct *ike_addrs;

  /** Optional parameters for the IKE library. The 'externalkey' and
      'accelerator_short_name' parameters cannot be set in this manner,
      they are overwritten by the Policy Manager. */
  SshIkev2Params ike_params;

  /** The number of IKE ports. */
  SshUInt16 num_ike_ports;

  /** Local port number to use for IKE; an IKE server
      will be started for each specified port on each local
      address. */
  SshUInt16 local_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];

  /** Port number to use for IKE NAT Traversal; an IKE server
      will be started for each specified port on each local
      address. */
  SshUInt16 local_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];

  /** Remote port number to use for IKE. */
  SshUInt16 remote_ike_ports[SSH_IPSEC_MAX_IKE_PORTS];

  /** Remote port number to use for IKE NAT Traversal. */
  SshUInt16 remote_ike_natt_ports[SSH_IPSEC_MAX_IKE_PORTS];

#ifdef SSHDIST_IPSEC_NAT
  /** Port range start address used for port numbers generated by NAT
      on this platform; this should be configured for each platform (it
      typically does not need to be configurable from the management
      system) - default: 40000. */
  SshUInt16 nat_port_range_low;
  /** Port range end address used for port numbers generated by NAT on
      this platform; this should be configured for each platform (it
      typically does not need to be configurable from the management
      system) - default: 65535. */
  SshUInt16 nat_port_range_high;
  /** Port range start address used for privileged port numbers
      generated by NAT on this platform; this should be
      configured for each platform (it typically does not need to
      be configurable from the management system) - default: 770. */
  SshUInt16 nat_privileged_port_range_low;
  /** Port range end address used for privileged port numbers
      generated by NAT on this platform; this should be
      configured for each platform (it typically does not need to
      be configurable from the management system) - default: 869. */
  SshUInt16 nat_privileged_port_range_high;
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_EXTERNALKEY
  /** Externalkey accelerator, type. */
  char *ek_accelerator_type;
  /** Externalkey accelerator, initialization information. */
  char *ek_accelerator_init_info;
#endif /* SSHDIST_EXTERNALKEY */

  /** Do not install default pass rules for DNS traffic originating
      from the local host. If this flag is set, the application using
      this API must configure suitable rules for handling DNS traffic
      from the local host. */

#define SSH_PM_PARAM_FLAG_NO_DNS_FROM_LOCAL_PASS_RULE     0x0001

  /** Disable default DHCP client pass-by rule. */
#define SSH_PM_PARAM_FLAG_DISABLE_DHCP_CLIENT_PASSBY_RULE 0x0002

  /** Enable default DHCP server pass-by rule. */
#define SSH_PM_PARAM_FLAG_ENABLE_DHCP_SERVER_PASSBY_RULE  0x0004

/** Always request an cookie when acting as an IKEv2 responder */
#define SSH_PM_FLAG_REQUIRE_COOKIE                         0x0008

  /** Global Policy Manager flags. */
  SshUInt32 flags;

  /** DHCP address pool enabled */
  Boolean dhcp_ras_enabled;

  /** NIST 800-131A key and algorithm restrictions */
#define SSH_PM_PARAM_ALGORITHMS_NIST_800_131A             0x0001

  /** Key strength requirements and algorithm set restrictions enforced.
      Currently NIST 800-131A key and algorithm restrictions supported. */
  SshUInt32 enable_key_restrictions;
};

typedef struct SshPmParamsRec SshPmParamsStruct;
typedef struct SshPmParamsRec *SshPmParams;

/** This function initializes libraries needed by policy manager.
    This function must be called after the event loop has been
    initialized and before it is started.

    */
void ssh_pm_library_init();

/** This function uninitializes libraries needed by policy manager.
    This function must be called after the event loop has returned
    and it is uninitialized.

    */
void ssh_pm_library_uninit();

/** This function creates a Policy Manager object.

    @param machine_context
    The Policy Manager passes the 'machine_context' argument to
    ssh_ipm_machine_open() to connect to the Packet Processing Engine.

    This calls the callback function 'callback' to report the success
    of opening Engine.

    @param params

    The argument 'params' specifies optional configuration parameters
    for the Policy Manager.  These parameters are static by nature.
    You cannot change them after Policy Manager is created.

    The argument 'params' can have the value NULL or any field in the
    parameters structure can have the value 0 or NULL.  In that case
    sane default values will be used.  The values of the `params'
    structure must remain valid as long as the control remains the
    ssh_pm_create function.

    @param callback
    The callback function 'callback' is called after the interface
    information is received from the packet processing Engine.

    */

void ssh_pm_create(void *machine_context, SshPmParams params,
                   SshPmCreateCB callback, void *context);

/** This function destroys the Policy Manager object, frees any memory
    it has allocated, and closes the connection to the Engine.

    Note that any policy objects created by the user must be freed by
    the user.

    @param callback
    The function will call the callback function 'callback' when the
    destroy operation is complete.  The callback may also be NULL.

    */
void ssh_pm_destroy(SshPm pm, SshPmDestroyCB callback, void *context);

/** Disable high-level policy lookups in Policy Manager.
    While the high-level policy lookups are disabled, Policy Manager
    ignores any events from Engine and libraries that would require
    a high-level policy lookup (for example trigger and rekey events
    from Engine or policy calls from the IKE library).

    Note: It is an error to call this multiple times without calling
    ssh_pm_enable_policy_lookups in between.

    @param callback
    The function will call the callback function 'callback' when the
    high-level policy lookups are disabled.  The callback may also be
    NULL.

    */
void ssh_pm_disable_policy_lookups(SshPm pm, SshPmStatusCB callback,
                                   void *context);

/** Enables high-level policy lookups in Policy Manager.

    Note: It is an error to call this before the previous
    ssh_pm_disable_policy_lookups has completed.

    @param callback
    The function will call the callback function 'callback' when the
    high-level policy lookups are enabled.  The callback may also be
    NULL.

    */
void ssh_pm_enable_policy_lookups(SshPm pm, SshPmStatusCB callback,
                                  void *context);

/** Sets the debug level for the packet processing engine in the kernel.
    The debug messages from the kernel are forwarded to the debug callback
    set for the policy manager process.  (In environments where the engine
    and the policy manager reside in the same address space this may
    set the level for both the engine and the policy manager.) */
Boolean ssh_pm_set_kernel_debug_level(SshPm pm, const char *level_string);

/** Set misc. engine parameters. If params is NULL, then default
    values for all parameters will be used. See the description of
    SshEngineParamsRec for a description of the parameters. */
void ssh_pm_set_engine_params(SshPm pm, SshEngineParams params);

/** Set the Policy Manager flags during runtime. */
void ssh_pm_set_flags(SshPm pm, SshUInt32 flags);

/** Start certificate access server to provide hash-and-url IKEv2
    services on given 'port'. Reconfiguration to different port can
    be done without stopping the server. The caller of this needs to
    make sure that the current policy allows access to this service
    (preferrably without IPSEC protection). A rule that allows access
    SRC: (ANY) <-> DST: (TCP:PORT:TO-LOCAL) is recommended. */
Boolean
ssh_pm_cert_access_server_start(SshPm pm, SshUInt16 port, SshUInt32 flags);

/** Send certificate chains as a single bundle as defined by
    RFC 4306 Section 3.6 */
#define SSH_PM_CERT_ACCESS_SERVER_FLAGS_SEND_BUNDLES 0x0001

/** Stop the certificate access server for providing hash-and-url IKEv2
    services. */
void
ssh_pm_cert_access_server_stop(SshPm pm);

/** Call ssh_pme_redo_flows() in the engine.

    This forces a re-evaluation of all flows against current policy
    and routing state. Active flows may be destroyed or left dangling,
    or they may change (if it is feasible) from one policy rule/tunnel
    to another policy rule/tunnel. */
void ssh_pm_redo_flows(SshPm pm);

/** Function returns the number of network interfaces managed by the
    engine. */
SshUInt32 ssh_pm_get_number_of_interfaces(SshPm pm);


/** Starts the iteration of interfaces.

    The function returns TRUE if there are any interfaces to iterate
    and sets 'ifnum_return' to the first interface index. Otherwise
    the function returns FALSE and does not set 'ifnum_return'. */
Boolean ssh_pm_interface_enumerate_start(SshPm pm, SshUInt32 *ifnum_return);


/** Continues the iteration of interfaces from the interface following
    the interface identified by 'ifnum'.

    The function returns TRUE if there are interfaces following
    interface 'ifnum' and sets 'ifnum_return' to the index of the
    following interface. Otherwise the function returns FALSE and
    does not set 'ifnum_return'. */
Boolean ssh_pm_interface_enumerate_next(SshPm pm,
                                        SshUInt32 ifnum,
                                        SshUInt32 *ifnum_return);


/** Returns the name of the interface identified by number `ifnum'.

    The function returns TRUE if there are an interface at the index
    `ifnum' and FALSE if the interface number was out of range.  The
    function sets `ifname_return' to point to the name of the
    interface or NULL if the interface is not currently active.  The
    value, pointed by `ifname_return' is valid until the control
    returns to the event loop. */
Boolean ssh_pm_get_interface_name(SshPm pm, SshUInt32 ifnum,
                                  char **ifname_return);

/** Returns the number of IP addresses, configured for the interface
    identified by `ifnum'.

    The function returns TRUE if the interface index `ifnum' is valid
    and FALSE otherwise.  The function return the address count in
    `addr_count_return'. */
Boolean ssh_pm_interface_get_number_of_addresses(SshPm pm, SshUInt32 ifnum,
                                                 SshUInt32 *addr_count_return);

/** Returns the IP address at the index `addrnum' of the interface
    identified by `ifnum'.

    The function returns TRUE if the interface number `ifnum' and
    address number `addrnum' were valid and FALSE otherwise.  The
    function copies the IP address into the variable, pointed by the
    argument `addr'. */
Boolean ssh_pm_interface_get_address(SshPm pm, SshUInt32 ifnum,
                                     SshUInt32 addrnum, SshIpAddr addr);

/** Returns the IP netmask at the index `addrnum' of the interface
    identified by `ifnum'.

    The function returns TRUE if the interface number `ifnum' and
    address number `addrnum' were valid and FALSE otherwise.  The
    function copies the IP netmask into the variable, pointed by the
    argument `netmask'. */
Boolean ssh_pm_interface_get_netmask(SshPm pm, SshUInt32 ifnum,
                                     SshUInt32 addrnum, SshIpAddr netmask);

/** Returns the broadcast address at the index `addrnum' of the
    interface idetified by `ifnum'.

    The function returns TRUE if the interface number `ifnum' and
    address number `addrnum' were valid and FALSE otherwise.  The
    function copies the broadcast address into the variable, pointed
    by the argument `broadcast'. */
Boolean ssh_pm_interface_get_broadcast(SshPm pm, SshUInt32 ifnum,
                                       SshUInt32 addrnum, SshIpAddr broadcast);

/** Returns the routing instance id of the interface idetified by `ifnum'.

    The function returns TRUE if the interface number `ifnum' is
    valid and FALSE otherwise.  The function copies the routing instance
    id into the variable, pointed by the argument `id_return'. */
Boolean
ssh_pm_interface_get_routing_instance_id(SshPm pm, SshUInt32 ifnum,
                                         SshVriId *id_return);

/** Returns the routing instance name of the interface idetified by `ifnum'.

    The function returns TRUE if the interface number `ifnum' is
    valid and FALSE otherwise.  The function sets `riname_return' to
    point to the name of the interface.  The value, pointed by
    `ifname_return' is valid until the control returns to the event loop. */
Boolean
ssh_pm_get_interface_routing_instance_name(SshPm pm, SshUInt32 ifnum,
                                           const char **riname_return);


/** Finds interface number when given interface name.

    Returns true, if name maps into existing interface. If so, fills
    interface number into ifnum_return, unless it is a NULL
    pointer. The returned 'ifnum_return' can then be used as argument
    to functions ssh_pm_interface_* functions. */
Boolean
ssh_pm_get_interface_number(SshPm pm, const char *ifname,
                            SshUInt32 *ifnum_return);

#ifdef SSHDIST_IKE_REDIRECT

/** Definitions for IKEv2 Redirect phases */

/** IKEv2 Redirect done at phase IKE_INIT */
#define SSH_PM_IKE_REDIRECT_IKE_INIT 0x0001

/** IKEv2 Redirect done at phase IKE_AUTH */
#define SSH_PM_IKE_REDIRECT_IKE_AUTH 0x0002

/** Mask for IKEv2 Redirect phases */
#define SSH_PM_IKE_REDIRECT_MASK     0x0003

/** Disables the global IKE redirect functionality. */
void ssh_pm_clear_ike_redirect(SshPm pm);

/** Enables the global IKE redirect functionality.

    @param redirect_addr
    The address of the alternative gateway.

    @param phase
    IKEv2 Redirect phase
*/
Boolean ssh_pm_set_ike_redirect(SshPm pm, SshIpAddr redirect_addr,
                                SshUInt8 phase);
#endif /* SSHDIST_IKE_REDIRECT */

#ifdef SSHDIST_IPSEC_NAT

/** Configures address translation on packets from the internal
   interface `ifname'.  Any previously configured NAT information for
   `ifname' is removed. This returns TRUE on success, and FALSE on
   error. If SSH_PM_NAT_TYPE_HOST_DIRECT NAT-type is specified,
   then the ssh_pm_set_interface_nat_host_nat() call must be
   used to configure the IP ranges in addition to the NAT type. */
Boolean ssh_pm_set_interface_nat(SshPm pm,
                                 SshPmNatFlags flags,
                                 const char *ifname,
                                 SshPmNatType type);

/** Clears all configured interface network address translations from
    policymanager `pm'. */
Boolean ssh_pm_clear_interface_nat(SshPm pm);

#endif /* SSHDIST_IPSEC_NAT */

/* A callback function of this type is called when the policy manager has
   received and processed an interface change notification. */
typedef void (*SshPmInterfaceChangeCB)(SshPm pm,
                                       void *context);

/** Sets a callback function that is called whenever there are changes in
    interface information. */
void ssh_pm_set_interface_callback(SshPm pm,
                                   SshPmInterfaceChangeCB callback,
                                   void *context);


/*--------------------------------------------------------------------*/
/* Service object manipulation functions. The service object specifies
   a network service.  Typically this is a constraint on the TCP or UDP
   destination port number, but the source port(s) can also be
   constrained.  The IP protocol number can also be used as a
   constraint. */
/*--------------------------------------------------------------------*/

/** Creates a service object.  By default the service object
    corresponds to no service (NULL can be used as the "all services"
    value). */
SshPmService ssh_pm_service_create(SshPm pm, const char *name);

/** Frees the given service object. */
void ssh_pm_service_destroy(SshPmService service);

/** Specifies that the service should go through an application
    gateway identified by `ident'.  The maximum length of the `ident'
    string is SSH_APPGW_MAX_IDENT_LEN.  This returns TRUE on success
    and FALSE on error. */
Boolean ssh_pm_service_set_appgw(SshPmService service, const char *ident);

/** Sets configuration data for the application gateway of the service
    `service'.  The service object `service' must already be
    configured to use application gateway with the
    ssh_pm_service_set_appgw() function.  This function can be called
    at any time for the same service object `service' to reconfigure
    all application gateway instances using the service.  The new
    configure data will be passed to the application gateways when the
    current policy modification operation is completed by calling the
    ssh_pm_commit() function.  The function returns TRUE if the new
    configuration data could be stored into the service object and
    FALSE otherwise. */
Boolean ssh_pm_service_set_appgw_config(SshPmService service,
                                        const unsigned char *config,
                                        size_t config_len);

/** Compares the services `service1' and `service2' for equality.  The
    function does not compare application gateway configuration data.
    You can reconfigure the application gateway configuration data
    simply by calling ssh_pm_service_set_appgw_config() with the new
    configuration data without recreating the service object.  The
    function returns TRUE if the service objects are equal and FALSE
    otherwise. */
Boolean ssh_pm_service_compare(SshPm pm,
                               SshPmService service1,
                               SshPmService service2);

/*--------------------------------------------------------------------*/
/* Policy rule manipulation functions.                                */
/*--------------------------------------------------------------------*/


/*  Public rule flags.
    Values above 0x000fffff are reserved for internal rule flags. */
#define SSH_PM_RULE_PASS                0x00000001 /** Passby. */
#define SSH_PM_RULE_REJECT              0x00000002 /** Drop with ICMP/RST. */
#define SSH_PM_RULE_LOG                 0x00000004 /** Log all connections. */
#define SSH_PM_RULE_RATE_LIMIT          0x00000008 /** Enable rate limiter. */
#define SSH_PM_RULE_NO_FLOW             0x00000010 /** Do not create flow. */
#ifdef SSHDIST_IPSEC_SCTP_MULTIHOME
#define SSH_PM_RULE_MULTIHOME           0x00000020  /** Rule has SCTP
                                                        multihomed addrs. */
#endif /* SSHDIST_IPSEC_SCTP_MULTIHOME */

#define SSH_PM_RULE_DF_SET              0x00000040  /** Set the DF bit on
                                                        encapsulation. */
#define SSH_PM_RULE_DF_CLEAR            0x00000080  /** Clear the DF bit on
                                                        encapsulation. */
#define SSH_PM_RULE_MATCH_LOCAL_IKE     0x00000100  /** Match local IKE
                                                        traffic. */
#define SSH_PM_RULE_ADJUST_LOCAL_ADDRESS 0x00000200 /** Use IKE address or
                                                        internal address
                                                        acquired by IKEv1
                                                        config mode to
                                                        override address of
                                                        local traffic
                                                        selector. */
#define SSH_PM_RULE_PASS_UNMODIFIED     0x00000400  /** Set the DF bit on
                                                        encapsulation. */
#ifdef SSHDIST_ISAKMP_CFG_MODE_RULES
#define SSH_PM_RULE_CFGMODE_RULES       0x00000800  /** Don't make an IPsec
                                                        SA from this rule.
                                                        Create rules from
                                                        received internal
                                                        subnets. */
#endif /* SSHDIST_ISAKMP_CFG_MODE_RULES */

/** Create a new policy rule object. The rule is not automatically
    inserted into Policy Manager data structures; instead,
    ssh_pm_rule_add must be called to add the rule, and ssh_pm_commit
    must be called to actually make the rule effective.

    The code that calls this API should attempt to group all rules
    using an identical tunnel to use the same tunnel object; this will
    improve efficiency and may result in fewer IPSec SAs between the
    two hosts/gateways.

    @param pm
    The Policy Manager object to which the rule will be added.

    @param precedence
    Precedence value for the rule.  This argument must be in the range
    0..99 999 999 (10^8 - 1).  Rules with higher precedence values
    take priority over rules with lower preference values (i.e., a
    rule with higher numeric value is considered before any rules with
    a lower precedence value).

    @param flags
    Flags that specify the type of the rule and various actions
    performed by the rule (a rule with no flags is an implicit drop
    rule). This field is a bitmask.

    Specifying PASS means that access from (initiating connections
    from) the SSH_PM_FROM side of the rule is allowed.

    REJECT means that dropped packets/connections should be dropped
    gracefully (sending ICMP or TCP RST back to the sender, with
    automatic rate limitation).  If no PASS or REJECT are specified,
    packets are silently dropped.

    LOG means that every new connection should be logged. 

    NO_FLOW means that no flows should be created for the rule in the
    Engine; this is slower than flow-based processing and prevents
    most firewall functionality, application gateways, NAT and
    logging, but consumes no memory per TCP connection in the Engine.

    @param from_tunnel
    Can be NULL. If non-NULL, this rule will only apply to packets
    arriving from this tunnel (and to return packets on their way to
    that tunnel).

    @param to_tunnel
    Can be NULL. If non-NULL, packets matching this rule will be
    tunneled as indicated by this tunnel. The rule will also apply to
    return packets coming from that tunnel.

    If both 'from_tunnel' and 'to_tunnel' are specified, then
    traffic will be routed between the two remote networks as
    permitted by the rule. The same tunnel objects can be shared
    among many objects.

    @param service
    Specifies which services (protocols) this rule applies to.  This
    can also be NULL to match all protocols (ipproto values) and
    ports.

    @return
    Returns the created rule object, or NULL if an error occurs (e.g.,
    if no more rule objects can be created).

    @see SshPmRule
    @see ssh_pm_rule_add
    @see ssh_pm_rule_free

*/

SshPmRule ssh_pm_rule_create(SshPm pm,
                             SshUInt32 precedence,
                             SshUInt32 flags,
                             SshPmTunnel from_tunnel, /* Can be NULL. */
                             SshPmTunnel to_tunnel,   /* Can be NULL. */
                             SshPmService service);

SshPmRule ssh_pm_rule_copy(SshPm pm, SshPmRule rule);

/** This type is used to select which side of the rule ("from" or "to"
    side) is being constrainted. */
typedef enum
{
  SSH_PM_FROM,
  SSH_PM_TO
} SshPmRuleSide;


/** This function adds a traffic selector constraint to the given
    rule.

    This constrains which packets the rule applies to. Only one
    traffic selector can be specified for each side of the rule (it is
    a fatal error to try to add more). This function returns TRUE on
    success and FALSE if the traffic selector could not be parsed. */
Boolean ssh_pm_rule_set_traffic_selector(SshPmRule rule,
                                         SshPmRuleSide side,
                                         const char *traffic_selector);

/** This function adds a traffic selector constraint to the given
    rule. This function behaves exactly as ssh_pm_rule_set_traffic_selector
    execpt the traffic selector is input as a SshIkev2PayloadTS type.
    After this function is called the user must not touch or free "ts",
    it is owned by the policy manager application. The ssh_pm_ts_
    routines can be used to construct the traffic selector 'ts'. */
Boolean ssh_pm_rule_set_ts(SshPmRule rule,
                           SshPmRuleSide side,
                           SshIkev2PayloadTS ts);

/** This function sets the VRF routing instance identifier for the rule.

    When the rule is created, its VRF routing instance name is set to
    same value as the tunnel it is attached to. If the rule is not attached
    to a tunnel, the name will default to "global", meaning it belongs to
    the default routing instance. In order to set a name other than the
    default values, this function is used.
    It is not possible to update the rule VRF routing instance identifier
    after the rule has been committed to Policy Manager. Nor is it possible
    to set a name that differs from the name of the attached tunnel.

    @param routing_instance_name
    The VRF routing instance name. This must be valid for the duration
    of the function call.

    @return
    On success this returns TRUE, otherwise FALSE.
*/
Boolean
ssh_pm_rule_set_routing_instance(SshPmRule rule,
                                 const char *routing_instance_name);

/** Adds an address constraint to the given rule.  This constrains
   which packets the rule applies to. The address must be a DNS name
   resolving to IPv4 or IPv6 address, or an IP address. Only one
   address can be specified on each side of the rule. If multiple
   addresses are to be used, separate rules must be created for each
   of them. This API does not allow for adding port or protocol selectors
   to policy rules which use DNS addresses.

   The function returns TRUE on success and FALSE, if it
   runs out of memory. It is legal for name to be NULL. This clears
   rules dependency from previously assigned DNS name. */
Boolean ssh_pm_rule_set_dns(SshPmRule rule,
                            SshPmRuleSide side,
                            const unsigned char *name);

/** This function adds an interface name constraint to the given rule.

    This means that for the rule to apply, the packets must be coming
    from the given interface.  This only constrains the incoming
    interface, not the outgoing interface. */
Boolean ssh_pm_rule_set_ifname(SshPmRule rule,
                               const char *ifname);

/** This function adds an interface name constraint to the given rule.

    This means that for the rule to apply, the packets must be coming
    from the interface indicated by routing to given 'remote' IP
    address or DNS name. This will eventually perform the same as
    ssh_pm_rule_set_ifname() */
Boolean
ssh_pm_rule_set_interface_from_route(SshPmRule rule,
                                     const unsigned char *remote);

/** Adds a local stack constraint to the given rule.

    This means that for the rule to apply, the packets must be coming
    from or going to the local stack. */
void ssh_pm_rule_set_local_stack(SshPmRule rule, SshPmRuleSide side);

/** Sets an extension selector for the rule.

    The value of the extension selector `i' must be in between `low'
    and `high' inclusively.  The function returns TRUE if the
    extension selector was set and FALSE if the extension selector
    index `i' was invalid. */
Boolean ssh_pm_rule_set_extension(SshPmRule rule, SshUInt32 i,
                                  SshUInt32 low, SshUInt32 high);

#ifdef SSHDIST_IPSEC_NAT
/** Sets the rule `rule' to NAT the packet's source IP address to
    `nat_src' and the source port number to `nat_src_aport', and
    destination IP address to `nat_dst' and the destination port
    number to `nat_dst_aport'.

    The values given as NULL's or zeros are not changed from their
    existing values.  */
void ssh_pm_rule_set_forced_nat(SshPmRule rule,
                                const SshIpAddr nat_src_low,
                                const SshIpAddr nat_src_high,
                                SshUInt16 nat_src_port,
                                const SshIpAddr nat_dst_low,
                                const SshIpAddr nat_dst_high,
                                SshUInt16 nat_dst_port,
                                SshPmNatFlags nat_flags);
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_IPSEC_SA_EXPORT

/** Maximum length of application specific identifier data. */
#define SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH 64

/** Sets the application specific identifier 'id' of length 'id_len' for
    'rule'. `id_len' must not be larger than
    SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH. The contents of 'id' are
    completely application-specific and Policy Manager does not use it for
    anything (not even for ssh_pm_rule_compare()).

    @return
    On failure this returns FALSE, and otherwise TRUE.

    */
Boolean ssh_pm_rule_set_application_identifier(SshPmRule rule,
                                               const unsigned char *id,
                                               size_t id_len);

/** Returns the application-specific identifier for 'rule' in return
    value parameters 'id' and 'id_len'. When this function is called,
    the value of '*id_len' contains the length of buffer pointed by
    'id'.

    @return
    If the buffer length is too short for the rule's application
    identifier, this fails and returns FALSE. Otherwise this copies the
    rule's application identifier to 'id', sets '*id_len' and returns
    TRUE.

    */
Boolean ssh_pm_rule_get_application_identifier(SshPmRule rule,
                                               unsigned char *id,
                                               size_t *id_len);
#endif /* SSHDIST_IPSEC_SA_EXPORT */

/** This function deletes a policy rule.

    This function should be called to delete a rule that has not been
    added to the policy manager databases (i.e. if ssh_pm_rule_add()
    hash not been called for the rule). If the rule has been added to
    the policy manager databases the rule should be freed using
    ssh_pm_rule_delete(). */
void ssh_pm_rule_free(SshPm pm, SshPmRule rule);

/** This function adds the given rule to the policy manager databases.

    This returns a handle for the rule that can be used later to
    delete the rule.  This returns SSH_IPSEC_INVALID_INDEX if adding
    the rule failed.  The new rule will not take effect until
    ssh_pm_commit is called. */
SshUInt32 ssh_pm_rule_add(SshPm pm, SshPmRule rule);

/** Lookup PM rule handle by rule id. */
SshPmRule ssh_pm_rule_lookup(SshPm pm, SshUInt32 id);

/** This function deletes a policy rule with the given index.

    The index must have
    been previously returned by ssh_pm_add_rule.  The deletion will
    not take effect until ssh_pm_commit is called. */
void ssh_pm_rule_delete(SshPm pm, SshUInt32 rule_id);

/** This function compares the rules `rule1' and `rule2' for equality.

    The function returns TRUE if the rules are equal and FALSE
    otherwise. Function is intented to be used */
Boolean ssh_pm_rule_compare(SshPm pm, SshUInt32 rule1, SshUInt32 rule2);

/** This function commits added and deleted rules to the policy
    manager and takes them into use for packet processing.

    This will call the callback when done; if the operation is
    successful, then `success' argument to the callback will be TRUE.
    If adding failed, `success' will be FALSE, in which case
    ssh_pm_abort will have been automatically called. It is illegal to
    call this function a second time before the callback has been
    received. */
void ssh_pm_commit(SshPm pm, SshPmStatusCB callback, void *context);

/** This function cancels any calls to ssh_pm_rule_{add,delete} since
    the last commit.

    Call restores the configuration to the state where it was
    immediately after the last commit.  Note that the function also
    frees all rules created with the ssh_pm_rule_create() function but
    which have not yet been added to the policy manager with the
    ssh_pm_rule_add() function. */
void ssh_pm_abort(SshPm pm);


/** Iterates through rule objects in ascending order of rule id.

    @param previous_rule
    The argument 'previous_rule' should be the return value of the
    previous call to this function, or NULL to retrieve the first
    rule.

    @return
    This function returns the next rule after 'previous_rule', or
    the first rule if 'previous_rule' is NULL. If no more rules
    are available, the function returns NULL. */
SshPmRule
ssh_pm_rule_get_next(SshPm pm, SshPmRule previous_rule);

/*--------------------------------------------------------------------*/
/* Standalone gateway configuration functions.                        */
/*--------------------------------------------------------------------*/

/** This function clears the system routing tables.

    This should be called first, and then ssh_pm_configure_route can
    be called one or more times. */
void ssh_pm_configure_clear_routes(SshPm pm);

/** This function adds a new route to the system.

    Arguments 'ipmask' is the IP address and mask of the net (or host)
    to route in the format "ip/mask", where ip is the IP address of
    the network (or host; IPv4 or IPv6), and mask is the number of
    significant bits in the network mask (it can also be a netmask in
    dotted format in the IPv4 case).

    A best match policy is used to prioritize the specified routes
    (i.e., the most specific route will always be used).  This calls
    the callback function 'callback' to report the success of the
    operation.

    @param nexthopip
    The IP address that the packets destined to the given subnet
    should be routed to.

    */
void ssh_pm_configure_route(SshPm pm,
                            const unsigned char *ipmask,
                            const unsigned char *nexthopip,
                            SshUInt32 ifnum,
                            SshPmStatusCB callback, void *context);


#ifndef SSH_IPSEC_IP_ONLY_INTERCEPTOR

/* ***********  Media/IP address mapping functionality ****************/

/** Adds an media address mapping entry for the IP address `ip' and media
    address `media_addr', `media_addr_len'.  'ifnum' specifies the interface
    for which this mapping should be valid for, if 'ifnum' is
    SSH_INVALID_IFNUM the mapping is valid for all interfaces.
    The mapping is added permanently to the media address mapping cache, and
    can be removed only by calling ssh_pm_media_address_mapping_remove. This
    calls the callback either during this call or at some later time to
    inidicate whether the media address mapping entry could be added. */
void
ssh_pm_media_address_mapping_add(SshPm pm,
                                 const SshIpAddr ip,
                                 SshUInt32 ifnum,
                                 const unsigned char *media_addr,
                                 size_t media_addr_len,
                                 SshUInt32 flags,
                                 SshPmStatusCB callback, void *context);

/** Removes the media address mapping entry of the IP address `ip', if
    one exists.  This has no effect if there is no media address mapping
    entry for the IP address. */
void
ssh_pm_media_address_mapping_remove(SshPm pm,
                                    const SshIpAddr ip,
                                    SshUInt32 ifnum);

#endif /* SSH_IPSEC_IP_ONLY_INTERCEPTOR */

/*--------------------------------------------------------------------*/
/* Auditing.                                                          */
/*--------------------------------------------------------------------*/

/*  Flags for ssh_pm_attach_audit_module. Audit events from the given
    subsystems are of interest. */
#define SSH_PM_AUDIT_IKE           0x00000001 /** Audit IKE module */
#define SSH_PM_AUDIT_ENGINE        0x00000010 /** Audit Forwarding Element */
#define SSH_PM_AUDIT_POLICY        0x00000020 /** Audit Controlling Element */
#define SSH_PM_AUDIT_APPGW         0x00000040 /** Audit Application GW's */
#define SSH_PM_AUDIT_ALL           0xffffffff /** Audit all modules */

/** This function creates an audit module from the parameters 'format'
    with name 'audit_name'.

    If 'audit_name' is NULL or "syslog" audit events are sent to the
    syslog, otherwise they are sent to a file name specified by
    'audit_name'.  'format' specifies the formatting which is used for
    logging the audit events, see sshaudit.h for the different
    possible format types. This function returns an audit context or
    NULL on failure. The policymanager will not begin auditing to the
    returned audit module until ssh_pm_attach_audit_module is called
    for the returned audit context. */
SshAuditContext ssh_pm_create_audit_module(SshPm pm,
                                           SshAuditFormatType format,
                                           const char *audit_name);

/** This function enables auditing to the given audit context.

    Argument 'audit_systems' is a bitmask of the SSH_PM_AUDIT_* flags
    which determines which subsystem of audit events this audit module
    should condider for auditing. After this function call, 'audit'
    belongs to the policymanager and the using application must not
    alter 'audit' in any way. This returns TRUE if attaching the audit
    context succeeds and FALSE otherwise in which case
    ssh_audit_destroy will already have been called for 'audit'. */
Boolean ssh_pm_attach_audit_module(SshPm pm,
                                   SshUInt32 audit_subsystems,
                                   SshAuditContext audit);

/*--------------------------------------------------------------------*/
/* Statistics functions.                                              */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called to return global
    statistics for the engine and the policy manager. */
typedef void (*SshPmGlobalStatsCB)(SshPm pm,
                                   const SshPmGlobalStats pm_stats,
                                   const SshEngineGlobalStats engine_stats,
                                   const SshFastpathGlobalStats fastpath_stats,
                                   void *context);

/** This function reads the global statistics counters for the engine
    and the policy manager. */
void ssh_pm_get_global_stats(SshPm pm, SshPmGlobalStatsCB callback,
                             void *context);

/*--------------------------------------------------------------------*/
/* Enumerating active flows                                           */
/*--------------------------------------------------------------------*/

/** This function retrieves the index of the next valid flow following
    the flow `flow_index'.

    If the `flow_index' has the value SSH_IPSEC_INVALID_INDEX, the
    function returns the index of the first valid flow in the engine.
    The function returns the flow index by calling the callback
    function `callback' during this call or later. */
void ssh_pm_get_next_flow_index(SshPm pm, SshUInt32 flow_index,
                                SshPmIndexCB callback, void *context);

/** A callback function of this type is called to return public
    information about flow objects.  The argument `info' points to the
    flow information or has the value NULL if the operation failed.
    The flow information remains valid as long as control remains in
    the callback function. */
typedef void (*SshPmFlowInfoCB)(SshPm pm,
                                const SshEngineFlowInfo info,
                                void *context);

/** This function retrieves public information about the flow object
    `flow_index'.

    The information is returned by calling the callback function
    `callback' either during this call or later. */
void ssh_pm_get_flow_info(SshPm pm, SshUInt32 flow_index,
                          SshPmFlowInfoCB callback, void *context);

/** A callback function of this type is called to return flow
    statistics.  The argument `stats' points to the statistics
    structure or has the value NULL if the operation failed.  The
    statistics information remains valid as long as control remains in
    the callback function. */
typedef void (*SshPmFlowStatsCB)(SshPm pm,
                                 const SshEngineFlowStats stats,
                                 void *context);

/** This function retrieves statistics of the flow object identified by
   `flow_index'.

   The statistics information is returned by calling the callback
   function `callback' either during this call or later. */
void ssh_pm_get_flow_stats(SshPm pm, SshUInt32 flow_index,
                           SshPmFlowStatsCB callback, void *context);

/*--------------------------------------------------------------------*/
/* Enumerating active rules                                           */
/*--------------------------------------------------------------------*/

/** This function retrieves the index of the next valid rule following
    the rule `rule_index'.

    If the `rule_index' has the value SSH_IPSEC_INVALID_INDEX, the
    function returns the index of the first valid rule in the engine.
    The function returns the rule index by calling the callback
    function `callback' during this call or later. */
void ssh_pm_get_next_rule_index(SshPm pm, SshUInt32 rule_index,
                                SshPmIndexCB callback, void *context);

/** A callback function of this type is called to return public
    information about rule objects.  The argument `info' points to the
    rule information or has the value NULL if the operation failed.
    The rule information remains valid as long as control remains in
    the callback function. */
typedef void (*SshPmRuleInfoCB)(SshPm pm,
                                const SshEngineRuleInfo info,
                                void *context);

/** This function retrieves public information about the rule object
    identified by `rule_index'.

    The information is returned by calling the callback function
    `callback' either during this call or later. */
void ssh_pm_get_rule_info(SshPm pm, SshUInt32 rule_index,
                          SshPmRuleInfoCB callback, void *context);

/** A callback function of this type is called to return rule
    statistics.  The argument `stats' points to the statistics
    structure or has the value NULL if the operation failed.  The
    statistics information remains valid as long as control remains in
    the callback function. */
typedef void (*SshPmRuleStatsCB)(SshPm pm,
                                 const SshEngineRuleStats stats,
                                 void *context);

/** This function retrieves statistics of the rule object identified
    by `rule_index'.

    The statistics information is returned by calling the callback
    function `callback' either during this call or later. */
void ssh_pm_get_rule_stats(SshPm pm, SshUInt32 rule_index,
                           SshPmRuleStatsCB callback, void *context);

#ifdef SSHDIST_IPSEC_DNSPOLICY
/*--------------------------------------------------------------------*/
/* Rule and tunnel DNS name resolution functions.                     */
/*--------------------------------------------------------------------*/

/** This function is used for indicating changes on DNS.

    If both 'dnsname' and 'ip' are NULL, then this will start
    resolution of all dns names referenced at the current policy. If
    'dnsname' is given, and 'ip' is NULL, then only that name is
    resolved. If both 'dnsname' and 'ip' are given, then names IP
    address assignment is changed directly without additional DNS
    lookup (providing means for optimization and indepence of DNS
    availability).

    The callback will be called when name resolution for all indicated
    by 'dnsname' on current policy has been tried (either success or
    failure).

    The function obeys standard SshOperation semantics on its return
    value. */
SshOperationHandle
ssh_pm_indicate_dns_change(SshPm pm,
                           const unsigned char *dnsname,
                           const unsigned char *ip,
                           SshPmStatusCB callback, void *context);

typedef enum {
  /* Rule has all the DNS names resolved. */
  SSH_PM_DNS_STATUS_OK    = 0,
  /* Rule has all the DNS names resolved, but the information might not
     be fresh, as last DNS query for them failed. */
  SSH_PM_DNS_STATUS_STALE = 1,
  /* Rule has unresolved DNS names, and is not usable */
  SSH_PM_DNS_STATUS_ERROR = 2
} SshPmDnsStatus;

/** This function returns information if all DNS names required by the
    rule have been resolved.

    Value SSH_PM_RULE_DNS_STATUS_OK, indicates the names have been
    resolved, and are fresh. Value SSH_PM_RULE_DNS_STATUS_STALE,
    indicates the addresses have been resolved, but the latest attempt
    to resolve them failed, and value SSH_PM_RULE_DNS_STATUS_ERROR
    indicates the rule can not be used as there are unresolved
    addresses.

    This function also checks the local and peer DNS names of any tunnels
    referenced by this rule. It is required to have atleast one valid
    and resolved DNS peer name per tunnel. */
SshPmDnsStatus ssh_pm_rule_get_dns_status(SshPm pm, SshUInt32 rule);

/* This function will check whether the local_ip and peer
   fields get resolved if given as DNS. If all local_ip fields
   and atleast one peer field is resolved then this will return
   SSH_PM_DNS_STATUS_OK, otherwise SSH_PM_DNS_STATUS_ERROR/STALE */
SshPmDnsStatus ssh_pm_tunnel_get_dns_status(SshPm pm, SshPmTunnel tunnel);

/** This function is used for removing old DNS names from the cache
    after reconfiguration, and for removing newly added DNS names
    from the cache after a failed configuration.

    If 'purge_old' is TRUE then those names that were added to cache
    with ssh_pm_indicate_dns_change() before the last call to
    ssh_pm_dns_cache_purge() are removed. Otherwise the DNS names
    added to cache after the last are removed. */
void
ssh_pm_dns_cache_purge(SshPm pm, Boolean purge_old);

#endif /* SSHDIST_IPSEC_DNSPOLICY */


































/*--------------------------------------------------------------------*/
/* These functions are used on a system that is fully configured
   through the Policy Manager API.  This includes the configuration of
   things like network interface IP addresses (or use of DHCP client),
   routing, DNS server addresses, and acting as a DHCP server. */
/*--------------------------------------------------------------------*/

/** Configures an IP address and netmask for the given interface, and
    brings the interface up.

    @param ip_and_mask
    The `ip_and_mask' argument should be of the format "ip/mask",
    where ip is the IP address in the customary string format (IPv4 or
    IPv6), and mask is the number of significant bits in the netmask.
    For IPv4 the mask can also be a netmask in dotted format.

    @param extra
    If the `extra' argument is not NULL, it may be interpreted in
    an interface-specific manner by the system to further
    configure the interface (it might be used e.g. to set
    parameters of wireless interfaces).  Any previously configured
    information for the interface is removed.

    @return
    This returns TRUE on success and FALSE on error. */

Boolean ssh_pm_configure_interface(SshPm pm,
                                   const char *ifname,
                                   const unsigned char *ip_and_mask,
                                   const char *extra);

#define SSH_PM_DHCP_CONFIGURE_DNS       0x00000001
/** Causes the interface to discover its address using DHCP.
    The DHCP lookup starts immediately, but will not complete until
    later.  Any previously configured information for the interface is
    removed, except that if it is already configured to use DHCP with
    the same parameters, then this call has no effect and no new DHCP
    query is started.

    @return
    This returns TRUE on success and FALSE on failure.  Note that
    this function returning success is not related to whether the
    DHCP lookup will be successful; it simply indicates that the
    configuration request was accepted.
*/
Boolean ssh_pm_configure_interface_dhcp(SshPm pm,
                                        const char *ifname,
                                        SshUInt32 flags);

/** Configures DNS servers for the device.
    This call removes any previously configured DNS information.

    @param ips
    `ips' is a comma-separated list of IP addresses (IPv4 or IPv6) of
    the DNS servers to be used, in the order of preference.

    @return
    This returns TRUE on success and FALSE on failure. */

Boolean ssh_pm_configure_dns(SshPm pm, const unsigned char *ips);












#endif /* CORE_PM_H */
