/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Top-level policy management API for flow-based IPsec implementation.

   @description

   The essential top-level functions in this API are
   ssh_pm_get_externalkey and ssh_pm_set_externalkey_notify_callback.

   *Note*: Do not include this header file directly. Use instead the
   quicksec_pm.h header file.


   * Tunnel Object Manipulation *

   Tunnel objects basically correspond to IPsec tunnels.  They contain
   all parameters for IKE phase 1.  IKE phase 2 paramters are taken from
   the domains specified in the policy rule.  Manual security
   associations are also configured using tunnel objects.

   Note that a tunnel object does not necessarily imply IPsec tunnel
   mode.  The selection between tunnel mode and transport mode is
   performed automatically by the system (or can be forced by the
   SSH_PM_TUNNEL_TUNNEL flag).
*/

#ifndef IPSEC_PM_H
#define IPSEC_PM_H

/* Include the common Quicksec definitions. */
#include "core_pm.h"

#ifdef SSHDIST_EXTERNALKEY
#include "sshexternalkey.h"
#endif /* SSHDIST_EXTERNALKEY */

/*--------------------------------------------------------------------*/
/* Data types.                                                        */
/*--------------------------------------------------------------------*/

/** Data type for an IKE SA handle. */
typedef struct SshPmP1Rec *SshPmP1;

/** Data type for an IPsec SA handle. */
typedef struct SshPmQmRec *SshPmQm;

/** Data type for an authentication data object handle.  This object
    can be used to fetch authentication information about an IKE
    SA. */
typedef struct SshPmAuthDataRec *SshPmAuthData;


/*--------------------------------------------------------------------*/
/* Top-level functions.                                               */
/*--------------------------------------------------------------------*/

#ifdef SSHDIST_EXTERNALKEY

/** This function returns a handle to the Policy Manager externalkey
    module.

    The caller can add providers to the externalkey module, and set
    the authentication callback.  It is also possible to fetch trusted
    certificates from the registered externalkey providers, and
    configure them using the ssh_pm_add_ca function.  Policy Manager
    sets the externalkey notify callback.  It must not be set by the
    user.  The ssh_pm_set_externalkey_notify_callback function can be
    used to register custom notification callbacks to receive
    notifications about externalkey events.

    Policy Manager uses the externalkey module to fetch tunnel
    authentication keys and certificates.  Policy Manager will try
    all keys automatically in the tunnel authentication.  If any of
    the externalkey providers support hardware acceleration,
    Policy Manager will accelerate private key, public key and
    Diffie-Hellman operations using the accelerators. */
SshExternalKey ssh_pm_get_externalkey(SshPm pm);

/** This function sets a notification callback for the externalkey
    module of the Policy Manager `pm'.  The notification callback
    `callback' is called when any events occur in the externalkey
    module. */
void ssh_pm_set_externalkey_notify_callback(SshPm pm, SshEkNotifyCB callback,
                                            void *context);

/** Clear all externalky providers configured to system */
void
ssh_pm_clear_externalkey_providers(SshPm pm);
#endif /* SSHDIST_EXTERNALKEY */

/*--------------------------------------------------------------------*/
/* Policy Manager configuration functions.                            */
/*--------------------------------------------------------------------*/

#ifdef SSHDIST_IKE_CERT_AUTH
/** This function adds a trusted root certificate to an authentication
    domain.

    The certificate should be in PEM-encoded ascii format or in raw
    binary format (this function tries to parse both formats).

    @param ad
    Authentication domain to be used. If NULL the ca is added to
    default authentication domain.

    @param flags
    Specifies properties of the CA certificate.

    @return
    This returns TRUE on success, and FALSE if an error occurs
    (for example if the certificate cannot be parsed or memory
    allocation fails). */
Boolean ssh_pm_auth_domain_add_ca(SshPm pm,
                                  SshPmAuthDomain ad,
                                  const unsigned char *cert,
                                  size_t cert_len,
                                  SshUInt32 flags);



#define SSH_PM_CA_NO_CRL   0x00000001 /** The CA cert doesn't issue
                                          CRLs, therefore they are not
                                          required for the path below
                                          this certificate */

/** This function adds a certificate revocation list (CRL) to
    an authentication domain.

    Typically this function is used to configure CRLs for CAs that do
    not publish their revocation lists using other methods.  The CRL
    can be in either PEM-encoded ASCII format or in raw binary format
    (this function will try to parse both formats).  Multiple CRLs can
    be added to the system in this way.  CRLs added using this
    function are kept permanently in the cache as long as they are
    valid.

    @param ad
    Authentication domain to be used. If NULL the CRL is added to
    default authentication domain.

    @return
    Returns TRUE if the CRL was successfully added, and FALSE if
    an error occurred (for xample if the CRL could not be parsed or
    memory allocation failed). */
Boolean
ssh_pm_auth_domain_add_crl(SshPm pm, SshPmAuthDomain ad,
                           const unsigned char *crl, size_t crl_len);


#ifdef SSHDIST_LDAP

/** This function configures LDAP servers for Policy Manager.

     The LDAP servers can be changed dynamically when Policy
     Manager is running.  When this function is called, the new LDAP
     server list will replace the previously configured LDAP servers.

     @param servers
     The argument `servers' is a comma separated list of names of LDAP
     servers in format:

     name1:port1,name2:port2,...

     If the argument `servers' has the value NULL, LDAP servers are
     disabled. */
Boolean ssh_pm_set_ldap_servers(SshPm pm, const unsigned char *servers);
#endif /* SSHDIST_LDAP */
#endif /* SSHDIST_IKE_CERT_AUTH */

/** This is the DPD notification callback function pointer type.

    The callback of this type will be called once when peer 'deadpeer'
    has been found dead. Peer is no longer considered as dead when it
    timeouts from DPD failure cache. This event is not signalled to
    the application. */
typedef void (*SshPmDpdStatusCB)(SshPm pm,
                                 const unsigned char *deadpeer,
                                 void *context);

/** This function sets DPD callback function.

    If the 'callback' is set, it will be called (with given 'context')
    when either:

    1. Setup of configured tunnel fails with all configured peers.

    2. An IPsec tunnel with DPD enabled has not received traffic (or
       other evidence of liveliness) from the peer within 'metric' 10's
       of seconds and the dead peer detection polling mechanism can not
       establish this evidence, even after trying to renegotiate Phase-1
       security association.

   @param ttl
   The 'ttl' argument describes how long time (in 10's of seconds) the
   peer remains in failure cache. The failure cache is cleared at
   reconfiguration, or call of this function with zero 'ttl'. */
Boolean ssh_pm_set_dpd(SshPm pm,
                       SshUInt16 metric,
                       SshUInt16 ttl,
                       SshPmDpdStatusCB callback, void *context);

















#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_NAT_TRAVERSAL
/** This function configures an IP address range that is used for
    making NAT-T clients unique.

    There can be only one address range configured at a time.

    @return
    Function returns FALSE if a parameter error was detected
    immediately, and TRUE otherwise. The callback function,
    if defined, will be called in either case. */
Boolean
ssh_pm_configure_internal_nat(SshPm pm,
                              const unsigned char *first_ip,
                              const unsigned char *last_ip,
                              SshPmStatusCB callback, void *context);
#endif /* SSHDIST_IPSEC_NAT_TRAVERSAL */
#endif /* SSHDIST_IPSEC_NAT */


/*--------------------------------------------------------------------*/
/* Tunnel object manipulation functions.                              */
/*--------------------------------------------------------------------*/

/** This function creates a tunnel object.

    Characteristics of the tunnel are specified by arguments to this
    function and by calling other ssh_pm_tunnel_* functions.

    @param transform
    The 'transform' argument is a combination of the SSH_PM_CRYPT_*,
    SSH_PM_HASH_*, SSH_PM_HMAC, SSH_PM_COMPRESS_* and SSH_PM_IPSEC_*
    flags, specifying the parameters for the tunnel. Any number of
    encryption and hash algorithms can be specified. The same hash
    algorithms are used for both AH and ESP (there is no way to
    specify different algorithms for AH and ESP message authentication
    code if both are used on the same tunnel); IKE uses an internally
    defined set of algorithms which is not constrained by this.  If no
    algorithm of a particular type is specified, then none is assumed
    (for ESP).  A very typical configuration would be to specify one
    or more encryption algorithms, one of SSH_PM_MAC_HMAC_MD5 and
    SSH_PM_MAC_HMAC_SHA1, and SSH_PM_ESP.

    @param flags
    The 'flags' argument contains additional parameters affecting how
    Policy Manager handles the tunnel.  For IPsec tunnels, it is a
    combination of the SSH_PM_{T,TI,TR}_* values.  It can be zero to
    use default values, which are suitable for basic IPsec tunnels.

    @param name
    The 'name' parameter is a human-readable name for the tunnel,
    which will be used in audit events.

    @return
    This function returns the new tunnel object, or NULL if an error
    occurs.  The tunnel object should be explicitly freed when no
    longer needed. */
SshPmTunnel
ssh_pm_tunnel_create(SshPm pm, SshPmTransform transform, SshUInt32 flags,
                     const char *tunnel_name);

/** This function frees the given tunnel object. */
void ssh_pm_tunnel_destroy(SshPm pm, SshPmTunnel tunnel);

/** This function iterates through tunnel objects.

    @param previous_tunnel
    The argument 'previous_tunnel' should be the return value of the
    previous call to this function, or NULL to retrieve the first
    tunnel.

    @return
    This function returns the next tunnel after 'previous_tunnel', or
    the first tunnel if 'previous_tunnel' is NULL. If no more tunnels
    are available, the function returns NULL. */
SshPmTunnel
ssh_pm_tunnel_get_next(SshPm pm, SshPmTunnel previous_tunnel);

/** This function gets the flags of a tunnel object.

    @return
    This function returns the tunnel flags (see the 'flags' argument
    of ssh_pm_tunnel_create()). */
SshUInt32
ssh_pm_tunnel_get_flags(SshPmTunnel tunnel);













/** This function sets the address of the gateway at the other end of
    the tunnel.

    If the peer address is not set, then the tunnel can only be used
    in transport mode and in responder negotiations.  The address can
    be either IPv4 or IPv6 address, or a DNS name resolving to such.
    More than one address can be specified per tunnel; in that case,
    it is assumed that all such addresses refer to the same logical
    gateway, and that they can all be used equally well and load can
    be shared between them.

    If DNS name resolves to multiple addresses, the system will add
    peer for each of these addresses (as if the call was called
    multiple times).

    Combinations where some peers are expressed as IP addresses and
    some as DNS names are not supported.

    @return
    This function returns TRUE on success and FALSE on failure.
    */

Boolean ssh_pm_tunnel_add_peer(SshPmTunnel tunnel,
                               const unsigned char *address);

/** This function sets the tunnels local IKE port.  You need to call this
    function only if you wish to run IKE protocol over a non-standard port. */
Boolean ssh_pm_tunnel_set_local_port(SshPmTunnel tunnel,
                                     SshUInt16 port);

/** This function adds a local address for the tunnel.

    Normally you don't have to add the local address.  Policy
    Manager will automatically select one when it is initiating an IKE
    negotiation with tunnel's peer.  However, if local addresses are
    specified, the address with highest precedence will be used when
    initiating IKE negotiations and one of the addresses must match when
    selecting policy as an IKE responder.

    @param precedence
    The argument 'precedence' defines the precedence of the address, value
    of 0xffffffff being the highest precedence value. */
Boolean ssh_pm_tunnel_add_local_ip(SshPmTunnel tunnel,
                                   const unsigned char *address,
                                   SshUInt32 precedence);

/** This function adds a local interface for the tunnel.  The interface's
    addresses will be updated to the tunnel's list of local IP addresses
    whenever an interface change event occurs.

    Once the interface's addresses have been updated to the tunnel, they will
    be used like the addresses added with ssh_pm_tunnel_add_local_ip().

    @param precedence
    The argument `precedence' specifies the precedence for the
    interface's addresses.
    */
Boolean ssh_pm_tunnel_add_local_interface(SshPmTunnel tunnel,
                                          const unsigned char *name,
                                          SshUInt32 precedence);

/** This function sets the VRF routing instance identifier for the tunnel.

    When the tunnel is created, its VRF routing instance name is
    initialized to "global", meaning it belongs to the default routing
    instance.
    It is not possible to update the tunnel VRF routing instance identifier
    after the tunnel has been committed to Policy Manager.

    @param routing_instance_name
    The VRF routing instance name. This must be valid for the duration
    of the function call.

    @return
    On success this returns TRUE, otherwise FALSE.
*/
Boolean
ssh_pm_tunnel_set_routing_instance(SshPmTunnel tunnel,
                                   const char *routing_instance_name);
#ifdef SSHDIST_IKE_REDIRECT
/** Enables the IKE redirect functionality per tunnel.

    Overrides the global IKE redirect setting for given tunnel.
*/
Boolean
ssh_pm_tunnel_set_ike_redirect(SshPmTunnel tunnel,
                               const SshIpAddr ike_redirect);
#endif /* SSHDIST_IKE_REDIRECT */

#ifdef SSHDIST_IPSEC_MOBIKE
/** This function re-evaluates paths of all MOBIKE enabled IKE SAs.  Normally
    this should be called after receiving an external event indicating that
    some paths may not be connected, or after tunnel local IP or local
    interface precedences have changed. */
void ssh_pm_mobike_reevaluate(SshPm pm,
                              SshPmStatusCB callback,
                              void *context);
#endif /* SSHDIST_IPSEC_MOBIKE */

/* Flags for the supported IKE versions. */
#define SSH_PM_IKE_VERSION_1 0x1            /** IKEv1. */
#define SSH_PM_IKE_VERSION_2 0x2            /** IKEv2, the default. */

/**  This function set the supported IKE versions for the tunnel 'tunnel'.

     This function can be used to force a tunnel to use a specific IKE
     version. If multiple IKE versions are specified for a tunnel,
     Policy Manager will negotiate IPsec SA's using the highest
     available IKE version number. The default version, if this
     function is not called, is to use IKE version 2.

     @param versions
     Argument 'versions' is a bitmask of SSH_PM_IKEV1_VERSION and
     SSH_PM_IKEV2_VERSION defines.

     */
Boolean
ssh_pm_tunnel_set_ike_versions(SshPmTunnel tunnel, SshUInt8 versions);


/** Set the IKE window size. */
Boolean
ssh_pm_tunnel_set_ike_window_size(SshPmTunnel tunnel, SshUInt32 window_size);



/* Flags for Diffie-Hellman operations of Phase-1 and for Quick-Mode PFS. */
#define SSH_PM_DH_GROUP_0       0x00800000 /** Allow group 0   (no group). */

#define SSH_PM_DH_GROUP_1       0x00000001 /** Allow group 1   (768 bits). */
#define SSH_PM_DH_GROUP_2       0x00000002 /** Allow group 2  (1024 bits). */
#define SSH_PM_DH_GROUP_5       0x00000004 /** Allow group 5  (1536 bits). */
#define SSH_PM_DH_GROUP_14      0x00000008 /** Allow group 14 (2048 bits). */
#define SSH_PM_DH_GROUP_15      0x00000010 /** Allow group 15 (3072 bits). */
#define SSH_PM_DH_GROUP_16      0x00000020 /** Allow group 16 (4096 bits). */
#define SSH_PM_DH_GROUP_17      0x00000040 /** Allow group 17 (6144 bits). */
#define SSH_PM_DH_GROUP_18      0x00000080 /** Allow group 18 (8192 bits). */
#ifdef SSHDIST_CRYPT_ECP
#define SSH_PM_DH_GROUP_19      0x00000100 /** Allow ECP grp 19 (256 bits). */
#define SSH_PM_DH_GROUP_20      0x00000200 /** Allow ECP grp 20 (384 bits). */
#define SSH_PM_DH_GROUP_21      0x00000400 /** Allow ECP grp 21 (521 bits). */
#endif /* SSHDIST_CRYPT_ECP  */
#define SSH_PM_DH_GROUP_22      0x00000800 /** Allow group 22 (1024 bits). */
#define SSH_PM_DH_GROUP_23      0x00001000 /** Allow group 23 (2048 bits). */
#define SSH_PM_DH_GROUP_24      0x00002000 /** Allow group 24 (2048 bits). */
#ifdef SSHDIST_CRYPT_ECP
#define SSH_PM_DH_GROUP_25      0x00004000 /** Allow ECP grp 25 (192 bits). */
#define SSH_PM_DH_GROUP_26      0x00008000 /** Allow ECP grp 26 (224 bits). */
#endif /* SSHDIST_CRYPT_ECP  */

/** This function sets the Diffie-Hellman groups for IKE SAs.

    This function clears all previous information on Diffie-Hellman
    IKE groups for this tunnel. If the IKE groups are not set,
    Policy Manager will use the system-wide default groups.

    @param flags
    The argument 'flags' specifies the groups that are allowed.  It can
    contain one or more of the SSH_PM_DH_GROUP_* flags.

    @return
    If 'flags' does not specify a usable set of IKE groups, this
    function returns FALSE and does not set the default IKE
    groups.
    */
Boolean ssh_pm_tunnel_set_ike_groups(SshPmTunnel tunnel, SshUInt32 flags);

/** This function sets the PFS groups and level for IPsec SAs.

    This function clears all previous information on Diffie-Hellman
    PFS groups for this tunnel. If the PFS properties are not set,
    no PFS is done in Quick-Mode negotiations with the tunnel
    'tunnel'.

    @param flags
    The argument 'flags' can contain one or more of the SSH_PM_DH_*
    flags (at least one group must be specified).

    @return
    If the 'flags' argument does not specify a usable set of PFS
    groups, this function returns FALSE and does not set the
    default PFS groups.
    */
Boolean ssh_pm_tunnel_set_pfs_groups(SshPmTunnel tunnel, SshUInt32 flags);

/** This function sets the preference of the Diffie-Hellman group for
    IKE SA's.

    The preference of the group is used when deciding which of the
    tunnel's configured groups should be used in Diffie-Hellman
    operations for IKE initiators. The preference is an integer value
    between 0 and 255, the initiator will choose the group with the
    highest configured preference.

    @param group
    The argument `group' must specify exactly one of the
    SSH_PM_DH_GROUP_* values. If the group 'group' has not previously
    been configured for the tunnel (by a call to
    ssh_pm_tunnel_set_ike_groups) then this function will add 'group'
    to the configured IKE groups.

    @return
    The function returns TRUE if the preference for the group was set,
    and FALSE otherwise.

    */
Boolean ssh_pm_tunnel_set_ike_group_preference(SshPmTunnel tunnel,
                                               SshUInt32 group,
                                               SshUInt8 preference);

/** This function sets the preference of the Diffie-Hellman PFS group
    for IPsec SA's.

    The preference of the group is used in deciding which of the
    tunnel's configured groups should be used in Diffie-Hellman
    operations for IKE initiators. The preference is an integer value
    between 0 and 255. The initiator will choose the group with the
    highest configured preference.

    @param group
    The argument 'group' must specify exactly one of the
    SSH_PM_DH_GROUP_* values. If the group 'group' has not previously
    been configured for the tunnel (by a call to
    ssh_pm_tunnel_set_pfs_groups) then this function will add 'group'
    to the configured PFS groups.

    @return
    The function returns TRUE if the preference for the group was set,
    and FALSE otherwise.

    */
Boolean ssh_pm_tunnel_set_pfs_group_preference(SshPmTunnel tunnel,
                                               SshUInt32 group,
                                               SshUInt8 preference);

/** Possible life time types for tunnels. The values are
    approximations, as they are enforced on the Engine timeout
    handler. The SA is not refreshed before it has transferred
    requested amount/time. It will be refreshed shortly after the
    condition is fullfilled. */
typedef enum
{
  /** SA life expressed on seconds. */
  SSH_PM_LIFE_SECONDS,
  /** SA life expressed in kilobytes. */
  SSH_PM_LIFE_KB
} SshPmLifeType;

/** This function sets a life time constraint for the given
    tunnel.

    The lifetime given is an approximation, and the shortest lifetime
    possible depends on the values of
    SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_TIME (for seconds) and
    SSH_ENGINE_IPSEC_SOFT_EVENT_GRACE_KB (for kB) being always twice
    these values.

    The time based expiration is performed when the IPsec incoming
    flow happens to receive timeout at the engine (approximately once
    per SSH_ENGINE_AGE_FULL_SECONDS).

    On IKEv1 the lifetime attributes were agreed, but for IKEv2 they
    are a local matter. */
void ssh_pm_tunnel_set_life(SshPmTunnel tunnel, SshPmLifeType type,
                            SshUInt32 value);

/** This function sets the IKE SA lifetime for the tunnel 'tunnel'.

    The lifetime given is an approximation, and the shortest lifetime
    possible depends on the value of SSH_PM_IKE_SA_SOFT_GRACE_TIME,
    being always twice this value.

    The IKE SA expiration is performed when the periodic IKE SA timer
    detects that the IKE SA has expired (this check is done approximately
    one or more times in a minute).

    @param seconds
    The argument `seconds' specifies the lifetime in seconds.  If no
    IKE SA lifetime is specified, the system will use global default
    value. */
void ssh_pm_tunnel_set_ike_life(SshPmTunnel tunnel, SshUInt32 seconds);

#ifdef SSHDIST_IKE_CERT_AUTH

/** This function sets the certificate that must be used to
    authenticate this host when using the tunnel 'tunnel' for IKE SA
    negotiation.

    If the certificate is set with this function, this function will
    also select the private key that is used in authentication.
    Normally both the certificate and the private key are selected
    automatically based on remote peer's certificate request payloads.

    @return
    The function returns TRUE if the certificate was configured, and
    FALSE on error. */

Boolean ssh_pm_tunnel_set_cert(SshPmTunnel tunnel,
                               const unsigned char *cert,
                               size_t cert_len);
#endif /* SSHDIST_IKE_CERT_AUTH */

/** Identity type definitions. */
typedef enum
{
  SSH_PM_IDENTITY_ANY,        /** Unspecified identity type. */
  SSH_PM_IDENTITY_DN,         /** Distinguished name. */
  SSH_PM_IDENTITY_IP,         /** IP address (v4 or v6). */
  SSH_PM_IDENTITY_FQDN,       /** Fully qualified domain name (DNS name). */
  SSH_PM_IDENTITY_RFC822,     /** E-mail address (RFC 822 name). */
  SSH_PM_IDENTITY_KEY_ID      /** Key ID. */
#ifdef SSHDIST_IKE_ID_LIST
  , SSH_PM_IDENTITY_ID_LIST   /**  IKE ID_LIST RFC 3554 */
#endif /* SSHDIST_IKE_ID_LIST */
} SshPmIdentityType;

/** Encoding types for IKE secrets and manual keys.  Engine will
    automatically convert from these to the appropriate internal
    type. */
typedef enum
{
  SSH_PM_ENCODING_UNKNOWN, /** Unspecified encoding. */
  SSH_PM_BINARY,           /** Raw binary encoding. */
  SSH_PM_HEX               /** Hexadecimal encoding. */
} SshPmSecretEncoding;

/*  Flags for the ssh_pm_tunnel_set_identity function. */

/** When 'local' is FALSE then the IKE peer's identity must match the
    tunnel's remote identity. When 'local' is TRUE then our local
    identity must match any identity proposed by the IKE peer. */
#define SSH_PM_TUNNEL_IDENTITY_ENFORCE 0x00000001

/** This function sets a local identity to the tunnel.

    If the tunnel has no local identity set, the system will use the
    local outbound IP address towards the peer as the identity when
    acting as an IKE initiator. It is allowed to specify 'id_type' and
    set 'identity' as NULL. This is used as a hint to the type of
    identity to select when the identity is specified with the
    ssh_pm_tunnel_set_cert function.

    @param id_type
    'id_type' indicates type of identity given as 'identity' with
    a length of 'identity_len' octets and transport armoring give with
    'id_encoding'.

    @param flags
    'flags' is a bitmask of the SSH_PM_TUNNEL_IDENTITY_* values.

    @param order
    Order of the authentication this identity should be used if
    multiple IKEv2 authentications are used. Else this value
    should always be 1.

    @return
    The function returns TRUE if the identity could be decoded and
    added to Policy Manager, and FALSE otherwise.

*/

Boolean ssh_pm_tunnel_set_local_identity(SshPmTunnel tunnel,
                                         SshUInt32 flags,
                                         SshPmIdentityType id_type,
                                         SshPmSecretEncoding id_encoding,
                                         const unsigned char *identity,
                                         size_t identity_len,
                                         SshUInt32 order);

/** This function sets a remote identity for a tunnel.

    As an initiator this identity is sent to negotiation peer and
    as a responder this can be used in the tunnel selection
    matching initiator ID in IKEv2.

    Only one remote identity can be set to a tunnel.

    @param id_type
    'id_type' indicates type of identity given as 'identity' with
    a length of 'identity_len' octets and transport armoring give with
    'id_encoding'.

     @param flags
    'flags' is a bitmask of the SSH_PM_TUNNEL_IDENTITY_* values.

    @return
    The function returns TRUE if the identity could be decoded and
    added to Policy Manager, and FALSE otherwise.

*/

Boolean ssh_pm_tunnel_set_remote_identity(SshPmTunnel tunnel,
                                          SshUInt32 flags,
                                          SshPmIdentityType id_type,
                                          SshPmSecretEncoding id_encoding,
                                          const unsigned char *identity,
                                          size_t identity_len);

/** This function sets an authentication domain to be used with the
    defined tunnel authentications. If this function is not called
    for tunnel, the default authentication domain is used.

    @param tunnel
    Specifies the target tunnel

    @param auth_domain_name
    Specifies name of the authentication domain.

    @param order
    The IKE-authentication round this authentication domain should
    be used in.

*/

Boolean
ssh_pm_tunnel_set_auth_domain(SshPmTunnel tunnel,
                              char *auth_domain_name,
                              SshUInt32 order);


/** This function sets a pre-shared key to be used in IKE SA
    negotiations with the tunnel's local identity.

    @param flags
    Flags to be used with this preshared key.

    @param encoding
    Describes how the pre-shared key is encoded.

    @param secret
    Specifies the pre-shared key.

    @param secret_len
    The length of the pre-shared key.

    @param order
    IKE-authentication number this preshared key should be used in.
    This can be only 1 if multiple authentications are not supported.

    @return
    The function returns TRUE if the secret could be decoded and added
    to Policy Manager, and FALSE otherwise.
*/

Boolean ssh_pm_tunnel_set_preshared_key(SshPmTunnel tunnel,
                                        SshUInt32 flags,
                                        SshPmSecretEncoding encoding,
                                        const unsigned char *secret,
                                        size_t secret_len,
                                        SshUInt32 order);



/** This function sets a private key to be used in IKEv2
    negotiations to the authentication domain. The key must be an RSA private
    key. This will use the raw RSA key certificate encoding when sending
    certificate payloads in IKE. This function has no effect for IKEv1
    tunnels, where raw RSA keys cannot be used as an authentication method. */
Boolean ssh_pm_auth_domain_set_private_key(SshPmAuthDomain ad,
                                           SshPrivateKey private_key);

/** This function sets an public key to be used in IKEv2 SA
    negotiations to the authentication domain. The key must be an RSA public
    key. This should be used for verifiying raw RSA key that an IKE peer
    uses for authentication. This function has no effect for IKEv1 tunnels,
    where raw RSA keys cannot be used as an authentication method.  */
Boolean ssh_pm_auth_domain_set_public_key(SshPmAuthDomain ad,
                                          SshPublicKey public_key);

/** This function specifies that the tunnel will use manual keying.

    Manual keying implies that no IKE negotiation will be performed,
    and the tunnel will be assumed to be valid immediately.  The
    `transform' argument of the ssh_pm_tunnel_create function
    specifies the transform to be used.  The arguments `esp_spi_in',
    `esp_spi_out', `ah_spi_in', and `ah_spi_out' specify the inbound
    and outbound ESP and AH SPIs respectively.  The arguments
    `ipcomp_cpi_in' and `ipcomp_cpi_out' specify the inbound and
    outbound IPComp CPIs.

    The arguments `key' and `key_len' specify the key material for the
    transform (the transform will split this into subkeys as needed).
    The key material must be in the following order: encryption key
    in, authentication key in, encryption key out, authentication key
    out.

    This copies the values into internal storage.  If the tunnel is
    used in gateway mode, its remote peer must be specified with the
    ssh_pm_tunnel_add_peer function.  Only one "manual" specification
    can be given per tunnel.  This returns TRUE on success and FALSE
    on error. */
Boolean ssh_pm_tunnel_set_manual(SshPmTunnel tunnel,
                                 SshUInt32 esp_spi_in,
                                 SshUInt32 esp_spi_out,
                                 SshUInt32 ah_spi_in,
                                 SshUInt32 ah_spi_out,
                                 SshUInt16 ipcomp_cpi_in,
                                 SshUInt16 ipcomp_cpi_out,
                                 SshPmSecretEncoding encoding,
                                 const unsigned char *key,
                                 size_t key_len);

/** Flag values for ssh_pm_tunnel_set_outer_tunnel(). */

/* None at the moment. */






/** This functions sets the outer tunnel for a tunnel object.

    The system imposes a limit (SSH_ENGINE_MAX_TUNNEL_NESTING in
    the ipsec_params.h file) on the number of tunnels that can be
    nested.

    @param outer_tunnel
    Specifies the outer tunnel object to use.

    @param flags
    Configures how tunnel nesting is performed.

    */
Boolean ssh_pm_tunnel_set_outer_tunnel(SshPmTunnel tunnel,
                                       const SshPmTunnel outer_tunnel,
                                       SshUInt32 flags);

/** This function sets the extension selector value for the packets
    arriving from the tunnel.

    If SSH_INTERCEPTOR_NUM_EXTENSION_SELECTORS is greater than 0, then
    all packets decapsulated from 'tunnel' will have their extension
    selector value at index 'index' overriden with the specified
    extension selector value 'extension'.

    @return
    The function returns TRUE if the extension selector was set and
    FALSE if the extension selector index 'index' was invalid. */
Boolean
ssh_pm_tunnel_set_extension(SshPmTunnel tunnel, SshUInt32 index,
                            SshUInt32 extension);

/** This function compares the tunnels 'tunnel1' and 'tunnel2' for
    equality.

    When comparing tunnels, the 'ike_window_size' parameter is not
    considered. In addition the preferences of local IP addresses or
    the preferences of local interfaces are not considered.

    @return
    The function returns TRUE if the tunnels are equal, and
    FALSE otherwise.

    */
Boolean ssh_pm_tunnel_compare(SshPm pm,
                              SshPmTunnel tunnel1,
                              SshPmTunnel tunnel2);
























#ifdef SSHDIST_IPSEC_SA_EXPORT
/** Sets the application specific identifier `id' of length `id_len' for
    `tunnel'. `id_len' must not be larger than
    SSH_PM_APPLICATION_IDENTIFIER_MAX_LENGTH (defined in core_pm.h). The
    contents of `id' are completely application specific and
    the policy manager does not use it for anything (not even for
    ssh_pm_tunnel_compare()). On failure this returns FALSE and otherwise
    TRUE. */
Boolean ssh_pm_tunnel_set_application_identifier(SshPmTunnel tunnel,
                                                 const unsigned char *id,
                                                 size_t id_len);

/** Returns the application specific identifier for `tunnel' in return value
    parameters `id' and `id_len'. When this function is called the value
    of `*id_len' contains the length of buffer pointed by `id'. If the
    buffer length is too short for the tunnel's application identifier
    this fails and returns FALSE. Otherwise this copies the tunnel's
    application identifier to `id', sets `*id_len' and returns TRUE. */
Boolean ssh_pm_tunnel_get_application_identifier(SshPmTunnel tunnel,
                                                 unsigned char *id,
                                                 size_t *id_len);
#endif /* SSHDIST_IPSEC_SA_EXPORT */


#ifdef SSHDIST_IKE_EAP_AUTH
/*--------------------------------------------------------------------*/
/* Legacy authentication for tunnels using EAP.                       */
/*--------------------------------------------------------------------*/

/** This function specifies that the authentication domain 'ad' will
    accept EAP authentication method with type 'eap_type'.

    This function may be called multiple times for
    different EAP types.

    @param eap_type
    The EAP type of the authentication method. The supported options
    are listed in the ssheap.h file. Setting the type to
    SSH_EAP_TYPE_NONE indicates that EAP authentication is
    supported for this tunnel without any specific authentication
    method. This may be used if EAP is used in a pass-through
    mode.

    @param preference
    Used when Policy Manager acts as an EAP authenticator.
    It  determines the order in which to try all the authentication
    methods Policy Manager knows, until it finds a suitable
    one. Methods with higher preferences are tried before methods with
    lower preferences.

    @param transform
    This parameter specifies the transform used by the eap_type.
    Moreover, it specifies the capability of supporting the Key derivation
    function for eap_type (AKA, AKA'). For rest of the eap_types this
    transform is not effective.

    @return
    This function returns TRUE if successful, and FALSE if the EAP
    type 'eap_type' is not supported by the EAP library. */
Boolean
ssh_pm_auth_domain_accept_eap_auth(SshPmAuthDomain ad,
                                   SshUInt8 eap_type, SshUInt8 preference,
                                   SshUInt32 transform);
#endif /* SSHDIST_IKE_EAP_AUTH */


/*--------------------------------------------------------------------*/
/* Fine-grained tunnel configuration                                  */
/*--------------------------------------------------------------------*/

/** This function sets the IKE algorithms for the tunnel 'tunnel'.

    @param algorithms
    The argument 'algorithms' specify the algorithms to use for the
    IKE SA negotiation.  It is a combination of the SSH_PM_CRYPT_* and
    SSH_PM_MAC_* flags.  If the IKE algorithms are not set, the system
    uses the algorithms from the tunnel's 'transform' specification
    and from the default IKE algorithms, set with the
    ssh_pm_set_default_ike_algorithms function.

    @return
    The function returns TRUE if the algorithm constraint was set, and
    FALSE otherwise.

    */
Boolean ssh_pm_tunnel_set_ike_algorithms(SshPmTunnel tunnel,
                                         SshUInt32 algorithms);

/*  Flags for algorithm key sizes. */
#define SSH_PM_ALG_IKE_SA    0x01000000 /** Properties apply to IKE SAs. */
#define SSH_PM_ALG_IPSEC_SA  0x02000000 /** Properties apply to IPsec SAs. */

/** This function specifies algorithm properties for the tunnel 'tunnel'.

    @param algorithm
    The argument `algorithm' can contain one or more encryption
    (SSH_PM_CRYPT_*) and MAC (SSH_PM_MAC_*) algorithms which have
    variable key sizes.  The argument `algorithm' must also contain
    one or more SSH_PM_ALG_* flags describing the IKE negotiations for
    which the key size constraints apply.

    @return
    The function returns TRUE if the algorithm constraint was set, and
    FALSE otherwise.

    */
Boolean ssh_pm_tunnel_set_algorithm_properties(SshPmTunnel tunnel,
                                               SshUInt32 algorithm,
                                               SshUInt32 min_key_size,
                                               SshUInt32 max_key_size,
                                               SshUInt32 default_key_size);

/** This function fetches the algorithm properties for the algorithm
    'algorithm' from the tunnel 'tunnel'.

    @param algorithm
    The argument 'algorithm' must specify exactly one encryption
    (SSH_PM_CRYPT_*) and MAC (SSH_PM_MAC_*) algorithm.  The argument
    `algorithm' must also contain one SSH_PM_ALG_* flag describing the
    use case of the algorithm.

    @return
    The function returns TRUE if the algorithm was configured for the
    tunnel and its properties were retrieved, and FALSE otherwise.

    */
Boolean ssh_pm_tunnel_get_algorithm_properties(
                                        SshPmTunnel tunnel,
                                        SshUInt32 algorithm,
                                        SshUInt32 *min_key_size_return,
                                        SshUInt32 *max_key_size_return,
                                        SshUInt32 *default_key_size_return);

/* ********************** Global default SA parameters ***********************/


/** Sets the default IKE SA algorithms.  The default algorithms are
    used for IKE SAs if the tunnel does not specify necessary
    algorithms - for example, if the tunnel specifies only ESP
    encryption without authentication.

    @param algorithms
    The argument 'algorithms' is a bitmask of the SSH_PM_CRYPT_*
    and SSH_PM_MAC_* values.  The default value for this setting
    is 'SSH_PM_CRYPT_3DES | SSH_PM_CRYPT_AES | SSH_PM_MAC_HMAC_MD5
    | SSH_PM_MAC_HMAC_SHA1'.

    @return
    If the algorithm bitmask does not specify a usable set of
    algorithms, this function returns FALSE and does not set the
    default IKE SA algorithms.

    */
Boolean ssh_pm_set_default_ike_algorithms(SshPm pm, SshUInt32 algorithms);



/*--------------------------------------------------------------------*/
/* IKE Pre-Shared                                                     */
/*--------------------------------------------------------------------*/

/*  High-level API for resolving pre-shared keys to IKE identities for
    IKE SA negotiations.  The IKE identities and their pre-shared keys
    are configured with the following functions for Policy
    Manager.  Policy Manager will automatically resolve the
    pre-shared keys based on the remote peer's IKE Phase-1 identities.

    If a more sophisticated method is needed for resolving the
    pre-shared keys, for example by querying a directory,
    appropriate callbacks must be implemented using the low-level API,
    defined in the 'quicksec_pm_low.h' header file. */

/** This function adds a new pre-shared key to be used in IKE SA
    negotiation with the remote identity 'remote_id', whose length is
    'remote_id_len' octets.

    @param auth_domain_name
    The argument 'auth_domain_name' specifies the name of the target
    authentication domain. This can be left NULL, in which case the
    key is added to default authentication domain.

    @param remote_id_type
    The argument `remote_id_type' specifies the type of the remote ID.

    @param remote_id_encoding
    Value of 'remote_id_encoding' will be used to determine if the
    identity is transport armored with hexadecimal encoding.

    @param encoding
    The argument 'encoding' describes how the pre-shared key is
    transport armored (encoded).

    @param secret
    Specifies the pre-shared key.

    @param secret_len
    The length of the pre-shared key.

    @return
    The function returns TRUE if the remote ID and the secret could be
    decoded and added to Policy Manager, and FALSE otherwise.

    */
Boolean ssh_pm_add_ike_preshared_key(SshPm pm,
                                     SshPmAuthDomain ad,
                                     SshPmIdentityType remote_id_type,
                                     SshPmSecretEncoding remote_id_encoding,
                                     const unsigned char *remote_id,
                                     size_t remote_id_len,
                                     SshPmSecretEncoding encoding,
                                     const unsigned char *secret,
                                     size_t secret_len);

/** This function removes a pre-shared key from the remote ID
    'remote_id' with given 'remote_id_encoding' and length.

    @param auth_domain_name
    The argument 'auth_domain_name' specifies the name of the target
    authentication domain. This can be left NULL, in which case the
    key is removed from default authentication domain.

    @return
    The function returns TRUE if the pre-shared key was known, and FALSE
    otherwise. */
Boolean ssh_pm_remove_ike_preshared_key(SshPm pm,
                                        SshPmAuthDomain ad,
                                        SshPmIdentityType remote_id_type,
                                        SshPmSecretEncoding remote_id_encoding,
                                        const unsigned char *remote_id,
                                        size_t remote_id_len);


/*--------------------------------------------------------------------*/
/* IKE Redirect                                                       */
/*--------------------------------------------------------------------*/
#ifdef SSHDIST_IKE_REDIRECT

/** A callback function of this type is called to complete a client
    redirection.

    @param redirect_address
    The argument contains the address of the gateway the client should be
    redicted to. NULL if none.

    @param context
    The argument 'context' is the context data given to the decision
    callback.

    */
typedef void (*SshPmIkeRedirectResultCB)(const char *redirect_address,
                                         void *context);

/** A callback function of this type is called to query redirection
    information from external policy module.

    @param client_id
    The argument contais the IKE ID of the client connecting to the gateway.
    Might not necessarily be a null terminated string.

    @param client_id_len
    Length in bytes of the client_id.

    @param result_callback
    The argument contains a function pointer to the callback function that is
    called once the decision is made.

    @param result_cb_context
    The argument 'context' is the context data for the result
    callback.

    @param context
    The argument contains the context data set by
    ssh_pm_set_ike_redirect_decision_callback.

    */
typedef void
(*SshPmIkeRedirectDecisionCB)(unsigned char *client_id,
                              size_t client_id_len,
                              SshPmIkeRedirectResultCB result_cb,
                              void *result_cb_context,
                              void *context);

/** This function sets the client auth redirect callback for the
    Policy Manager 'pm'.

    @param decision_cb
    The argument contains a function pointer to the callback function that
    makes the decision about redirection.

    @param context
    Specifies context data for the decision_cb function.

    */
void ssh_pm_set_ike_redirect_decision_callback(
                                      SshPm pm,
                                      SshPmIkeRedirectDecisionCB decision_cb,
                                      void *context);



#endif /* SSHDIST_IKE_REDIRECT */

/*--------------------------------------------------------------------*/
/* Legacy authentication client functionality                         */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called to complete a legacy
    authentication client query.

    The arguments 'user_name', 'user_name_len', 'user_password',
    'user_password_len', 'passcode', 'passcode_len', 'next_pin',
    'next_pin_len', 'answer', and 'answer_len' specify replies for the
    attributes being queried with the SshPmLegacyAuthClientQueryCB
    function. When non-NULL attributes are returned they should not be
    NUL terminated.

    @param success
    Specifies whether the query could be answered or not. If the
    argument 'success' has the value FALSE, the authentication
    will be failed and all attribute arguments are ignored.

    @param context
    The argument 'context' is the context data for the result
    callback.

    */
typedef void
(*SshPmLegacyAuthClientQueryResultCB)(Boolean success,
                                      const unsigned char *user_name,
                                      size_t user_name_len,
                                      const unsigned char *user_password,
                                      size_t user_password_len,
                                      const unsigned char *passcode,
                                      size_t passcode_len,
                                      const unsigned char *next_pin,
                                      size_t next_pin_len,
                                      const unsigned char *answer,
                                      size_t answer_len,
                                      void *context);

/*  Bit masks specifying the type of the legacy authentication. */
#define SSH_PM_LA_XAUTH                 0x00000001 /** IKE XAUTH. */
#define SSH_PM_LA_L2TP                  0x00000002 /** L2TP PPP. */
#define SSH_PM_LA_EAP                   0x00000004 /** EAP for IKEv2. */
/** Defining authentication round if multiple auth is used */
#define SSH_PM_LA_FIRST_ROUND           0x00000010
#define SSH_PM_LA_SECOND_ROUND          0x00000020

/*  Bit masks for legacy authentication client attributes being
    queried.  These bit mask values specify the attributes the legacy
    authentication access client must specify for the
    authentication. */
#define SSH_PM_LA_ATTR_USER_NAME        0x00000100 /** User name. */
#define SSH_PM_LA_ATTR_USER_PASSWORD    0x00000200 /** User password. */
#define SSH_PM_LA_ATTR_PASSCODE         0x00000400 /** Token card passcode. */
#define SSH_PM_LA_ATTR_NEXT_PIN         0x00000800 /** New pin number. */
#define SSH_PM_LA_ATTR_ANSWER           0x00001000 /** Answer to the
                                                       question in the
                                                       argument
                                                       'message'. */

/** A callback function of this type is called to query authentication
    information from a legacy authentication client.

    @param operation_id

    A unique identifier for the authentication query.  Some
    authentication types (Xauth) may require multiple
    authentication queries before the operation is complete.  In
    this case, all the SshPmLegacyAuthClientQueryCB calls will
    have the same 'operation_id'.  Also, the result of the
    authentication is notified by calling the
    SshPmLegacyAuthClientResultCB with the same 'operation_id' value.

    @param gateway_ip
    Specifies the IP address of the gateway that is doing the
    authentication for the client.

    @param domain
    The arguments 'domain' and 'domain_len' specify the domain to
    which the client is authenticating in.  The argument 'domain' can
    have the value NULL, when 'domain' is not NULL it should not be NUL
    terminated.

    @param message
    The arguments 'message' and 'message_len' specify a message from
    the gateway to the client.  This may contain additional
    information for the authentication.  It should be shown to the
    user.  The argument `message' can have the value NULL, when 'message'
    is not NULL it should not be NUL terminated.

    @param flags
    Specifies the type of the authentication and the attributes being
    queried from the client. This is a bitmask of the SSH_PM_LA_ flags
    defined above.

    @param xauth_type
    Meaningful only for SSH_PM_LA_XAUTH authentications.  Specifies
    the type of the Xauth authentication. The possible types are specified
    in Section 6.3 of draft-beaulieu-ike-xauth-02.

    @param result_cb
    A callback function that must be called to complete the
    authentication query. This callback must always be called even in case
    of error or if the returned operation handle is aborted.

    @param result_cb_context
    Specifies context data for the `result_cb' callback function.

    */
typedef SshOperationHandle
(*SshPmLegacyAuthClientQueryCB)(SshUInt32 operation_id,
                                const SshIpAddr gateway_ip,
                                const unsigned char *domain,
                                size_t domain_len,
                                const unsigned char *message,
                                size_t message_len,
                                SshUInt32 flags,
                                SshUInt32 xauth_type,
                                SshPmLegacyAuthClientQueryResultCB result_cb,
                                void *result_cb_context,
                                void *context);

/** A callback function of this type is called to complete a legacy
    client authentication.

    @param operation_id
    Identifies the authentication operation being completed.  It has
    the same value that was in the 'operation_id' argument of the
    preceding SshPmLegacyAuthClientQueryResultCB call.

    @param success
    Specifies whether the authentication was successful or not.

    @param message
    The arguments `message' and 'message_len' specify an optional
    message describing the status of the authentication.  The message
    should be shown to the user.

    */
typedef void (*SshPmLegacyAuthClientResultCB)(SshUInt32 operation_id,
                                              Boolean success,
                                              const unsigned char *message,
                                              size_t message_len,
                                              void *context);

/** This function sets the legacy authentication client authentication
    callbacks for the Policy Manager 'pm'.

    @param query_cb
    Specifies a callback function that is called to query the client
    authentication information from the user.

    @param result_cb
    Specifies a callback function that is called to notify the success
    of the authentication operations.

    @param context
    Specifies context data for the 'query_cb' and 'result_cb'
    functions.

    */
void ssh_pm_set_legacy_auth_client_callbacks(
                                SshPm pm,
                                SshPmLegacyAuthClientQueryCB query_cb,
                                SshPmLegacyAuthClientResultCB result_cb,
                                void *context);

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

/*--------------------------------------------------------------------*/
/* Legacy authentication methods                                      */
/*--------------------------------------------------------------------*/

/** High-level API for legacy authentication.  The authentication is
    configured by setting one authentication method for a Policy
    Manager object.

    The supported authentication methods are the following:

    - RADIUS:
    authentication using Remote Authentication Dial In User Service
    (RADIUS)

    - user-name password list:
    authentication using user-name - password list.

    Only one authentication method can be configured for a Policy
    Manager object.  If the authentication should be done using
    multiple authentication methods, an appropriate authentication
    module should be implemented using the low-level authentication
    API, defined in the 'quicksec_pm_low.h' header file. */

#ifdef SSHDIST_RADIUS
/** Authentication and remote access attributes with RADIUS.  The
    RADIUS authentication provides both authentication and retrieving
    of remote access client attributes from the RADIUS servers. */

#include "sshradius.h"

/** This function configures RADIUS servers which are used for
    authenticating remote access clients.

    Setting the RADIUS authentication for Policy Manager automatically
    applies for all applicable remote access methods (such as L2TP and
    IKE configuration mode).

    The objects, pointed by the 'client' and 'servers' arguments must
    remain valid as long as the policy manager 'pm' is active.

    @param client
    Specifies a RADIUS client that is used in RADIUS operations.

    @param servers
    Specifies one or more RADIUS servers that can be used for
    authentication.

    */
Boolean ssh_pm_set_radius_servers(SshPm pm, SshPmAuthDomain ad,
                                  SshRadiusClient client,
                                  SshRadiusClientServerInfo servers);
#endif /* SSHDIST_RADIUS */

/*  Password list authentication.  The password list authentication
    provides only client authentication. */

/** This function adds a new remote access user 'user_name' with
    password 'password' for the policy manager 'pm'.

    When the first user is added for a policy manager, the function
    automatically enables the password-based remote access client
    authentication.

    @return
    The function returns TRUE if the user was added, and FALSE
    otherwise.

    */
Boolean ssh_pm_add_user(SshPm pm,
                        SshPmAuthDomain ad,
                        const unsigned char *user_name,
                        size_t user_name_len,
                        SshPmSecretEncoding user_name_encoding,
                        const unsigned char *password,
                        size_t password_len,
                        SshPmSecretEncoding password_encoding);

/** This function removes the user 'user_name' from the list of
    allowed remote access users in the policy manager 'pm'.

    @return
    The function returns TRUE if the user was known, and FALSE
    otherwise. */
Boolean ssh_pm_remove_user(SshPm pm,
                           SshPmAuthDomain ad,
                           const unsigned char *user_name,
                           size_t user_name_len,
                           SshPmSecretEncoding user_name_encoding);

/*--------------------------------------------------------------------*/
/* Attributes and IP address pools for remote access clients          */
/*--------------------------------------------------------------------*/
#define SSH_PM_REMOTE_ACCESS_DHCP_POOL          0x0001
#define SSH_PM_REMOTE_ACCESS_DHCP_EXTRACT_CN    0x0002
#define SSH_PM_REMOTE_ACCESS_DHCP_STANDBY       0x0004
#define SSH_PM_REMOTE_ACCESS_DHCPV6_POOL        0x0008

/** Structure to pass remote access information for creating an address pool.

    @param addresses
    This is mandatory parameter. It cannot be NULL. It passes virtual ip
    address information. Format is:
    <ip1>/<mask1>;<ip2>/<mask2> ....
    e.g.
    192.168.0.20-192.168.0.30/255.255.255.0;192.168.100.0/255.255.255.254
    It is a string of semi-colon separated ip/mask pairs

    @param name
    This is optional and represents a name for the address pool. If passed
    NULL then name will be set as "DEFAULT-AP".

    @param own_ip_addr
    Specifies the gateway's own IP address used in PPP links.  It
    can be left unspecified in which case the own IP address is
    not notified for PPP peers.
    own_ip_addr

    @param dns wins dhcp
    The arguments 'dns', 'wins', and 'dhcp' specify the addresses of
    the DNS, NetBios name server (WINS), and DHCP servers at the
    private network, protected by the gateway 'pm'.  Any of the
    attributes can be left unspecified in which case the attribute is
    not sent for clients.

    @param subnets
    This specifies a senmi-colon separated list of protected subnets.
*/










typedef struct SshPmRemoteAccessParamsRec
{
  unsigned char *name;
  unsigned char *addresses;
  unsigned char *own_ip_addr;
  unsigned char *dns;
  unsigned char *wins;
  unsigned char *dhcp;
  unsigned char *subnets;



  SshUInt32 flags;
} SshPmRemoteAccessParamsStruct, *SshPmRemoteAccessParams;

/** Add a new address pool to the policymanager. If an address pool already
    exists with same name, this removes the existing address pool and
    recreates a new address pool. The address pool contains the information
    about remote access parameters.

    Policy Manager will send these attributes for all remote access clients,
    unless the attributes are received from the authentication method (RADIUS).

    @param params
    This is instance of SshPmRemoteAccessParams and should at least contain
    'addresses'. Other members of this structure may be set to NULL if
    desired. If 'name' is NULL then this will assign the default address
    pool name. This name is returned in 'params->name' and the caller is
    responsible for freeing it. The 'name' member is used when deleting the
    address pool and when setting the address pool to a tunnel.

    @return
    The function returns TRUE if address pool is created or updated, and
    FALSE if the operation failed due to:
     - memory exhaustion
     - addresses member of 'params' is empty
*/
Boolean ssh_pm_ras_add_addrpool(SshPm pm, SshPmRemoteAccessParams params);

/** Removes an address pool with given the name from the policy manager.
    After the address pool is removed no addresses are allocated from this
    address pool. The address pool is destroyed after all currently allocated
    addresses have been returned to the address pool. If 'name' is NULL then
    all address pools are removed.

    @param pm
    policy manager instance

    @param name
    Address pool name
*/
void ssh_pm_ras_remove_addrpool(SshPm pm, const unsigned char* name);

/* The maxiumum number of address pools that may be configured to a tunnel. */
#define SSH_PM_TUNNEL_MAX_ADDRESS_POOLS 1

/** Set an address pool to the list of address pools to the tunnel. Only
    SSH_PM_TUNNEL_MAX_ADDRESS_POOLS address pools may be set to any given
    tunnel. It is allowed for an address pool to be set to more than one
    tunnel.

    @param tunnel

    @param name
    Address pool name

    @return
    Returns FALSE if the address pool corresponding to name is not
    configured to the policymanager or the tunnel already has
    SSH_PM_TUNNEL_MAX_ADDRESS_POOLS address pools assigned to it,
    otherwise this returns TRUE. */
Boolean
ssh_pm_tunnel_add_address_pool(SshPmTunnel tunnel, const unsigned char *name);

/** Statistics for Remote Access address pools. */
typedef struct SshPmAddressPoolStatsRec {

  /** Name of the address pool. */
  unsigned char *name;

  /** Address pool type: Value is either SSH_PM_REMOTE_ACCESS_DHCP_POOL, or
      0 meaning a generic address pool. */
  SshUInt8 type;

  /** Current number of allocated addresses. */
  SshUInt32 current_num_allocated_addresses;

  /** Total number of address allocations. */
  SshUInt32 total_num_allocated_addresses;

  /** Number of addresses freed. */
  SshUInt32 num_freed_addresses;

  /** Number of address allocation failures. */
  SshUInt32 num_failed_address_allocations;

  /** The DHCP message statistics. If the address pool type is not DHCP, the
      fields in the structure do not contain valid values. */
  struct
  {
    SshUInt32 packets_transmitted; /** Total number of transmitted packets. */
    SshUInt32 packets_received;    /** Total number of received packets. */
    SshUInt32 packets_dropped;     /** Total number of dropped packets. */
    SshUInt32 discover;  /** Number of DHCPDISCOVER messages sent. */
    SshUInt32 offer;     /** Number of DHCPOFFER messages received. */
    SshUInt32 request;   /** Number of DHCPREQUEST messages sent. */
    SshUInt32 ack;       /** Number of DHCPACK messages received. */
    SshUInt32 nak;       /** Number of DHCPNAK messages received. */
    SshUInt32 decline;   /** Number of DHCPDECLINE messages sent. */
    SshUInt32 release;   /** Number of DHCPRELEASE messages sent. */
    SshUInt32 dhcpv6_relay_forward; /** Number of RELAY_FORWARD messages sent.
                                     */
    SshUInt32 dhcpv6_relay_reply;/** Number of RELAY_REPLY messages received.
                                     */
    SshUInt32 dhcpv6_solicit;  /** Number of SOLICIT messages sent. */
    SshUInt32 dhcpv6_reply;    /** Number of REPLY messages received. */
    SshUInt32 dhcpv6_decline;  /** Number of DECLINE messages sent. */
    SshUInt32 dhcpv6_renew;    /** Number of RENEW messages received. */
    SshUInt32 dhcpv6_release;  /** Number of DHCPRELEASE messages sent. */
  } dhcp;

} *SshPmAddressPoolStats, SshPmAddressPoolStatsStruct;

/** A callback function of this type is called once for each address pool on
    the policy manager 'pm'.

    @return
    The callback function returns a Boolean status describing whether
    the enumeration should be continued or not. */
typedef Boolean (*SshPmAddressPoolStatsCB)(SshPm pm,
                                         const SshPmAddressPoolStats stats,
                                         void *context);

/** This function calls the callback function 'callback' once for each
    Remote Access address pool on the policy manager 'pm'.

    The enumeration is continued as long as the callback function
    'callback' returns TRUE.

    @return
    The function returns TRUE if all address pools on the server were
    enumerated, and FALSE if the enumeration was cancelled by the
    callback.

    */
Boolean ssh_pm_address_pool_foreach_get_stats(SshPm pm,
                                     SshPmAddressPoolStatsCB callback,
                                     void *context);


#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSH_IPSEC_TCPENCAP
/*--------------------------------------------------------------------*/
/* IPsec over TCP configuration                                       */
/*--------------------------------------------------------------------*/

/** This function installs a TCP encapsulation configuration.

    @param local_addr
    The argument 'local_addr' (CG) specifies the local IP number to
    use. This is optional for gateway. Client must set this to NULL,
    as the local address information is taken from the `tunnel'.

    @param local_port
    The argument 'local_port' (G) is the local TCP port to receive TCP
    encapsulated packets. Gateway must specify this. Client may specify
    this if it wishes to use a predefined local port instead of random
    local port.

    @param peer_lo_addr
    The arguments 'peer_lo_addr' and 'peer_hi_addr' define the
    address range for the peer. For a client this must be unicast
    address (e.g. range of one address), and for a gateway it is optional
    and it is the range of allowed client addresses (default any).

    @param peer_port
    The argument 'peer_port' (C) defines the remote TCP port of the
    server.

    @param local_ike_port
    The argument 'local_ike_port' is optional and specifies the local port
    used by the IKE protocol.

    */
Boolean
ssh_pm_tcp_encaps_add_configuration(SshPm pm,
                                    SshPmTunnel tunnel,
                                    SshIpAddr local_addr,
                                    SshUInt16 local_port,
                                    SshIpAddr peer_lo_addr,
                                    SshIpAddr peer_hi_addr,
                                    SshUInt16 peer_port,
                                    SshUInt16 local_ike_port);

#endif /* SSH_IPSEC_TCPENCAP */


/*--------------------------------------------------------------------*/
/* Statistics functions.                                              */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called once for each IKE
    server context of the policy manager 'pm' when enumerating the
    servers.

    @return
    The callback function returns a Boolean status describing whether
    the enumeration should be continued or not.

    */
typedef Boolean (SshPmIkeServerCB)(SshPm pm, SshIkev2Server server,
                                   void *context);

/** This function calls the callback function 'callback' once for each
    IKE server context that is running on the policy manager 'pm'.

    The enumeration is continued as long as the callback function
    'callback' returns TRUE.

    @return
    The function returns TRUE if all server contexts were enumerated,
    and FALSE if the enumeration was cancelled by the callback.

    */
Boolean ssh_pm_foreach_ike_server(SshPm pm, SshPmIkeServerCB callback,
                                  void *context);

/** Statistics for IKE SA's. */
typedef struct SshPmIkeSaStatsRec {

  SshPmAuthData auth; /** Authentication data, use the utility functions in
                          the ipsec_pm_low.h file to retrieve authentication
                          data. */

  const char *encrypt_algorithm; /** Name of the encryption algorithm. */
  const char *mac_algorithm;     /** Name of the Mac algorithm. */
  const char *prf_algorithm;     /** Name of the PRF algorithm. */

  SshTime created;               /** When the IKE SA was created. */

  /** The total number of child SA's created using this SA, and the number
      of currently active. */
  SshUInt32 num_child_sas;
  int routing_instance_id;
  char routing_instance_name[64];
} *SshPmIkeSaStats, SshPmIkeSaStatsStruct;

/** A callback function of this type is called once for each IKE SA on
    the server.

    @return
    The callback function returns a Boolean status describing whether
    the enumeration should be continued or not. */
typedef Boolean (*SshPmIkeServerSaCB)(SshPm pm,
                                      const SshPmIkeSaStats stats,
                                      void *context);

/** This function calls the callback function 'callback' once for each
    completed IKE SA on the server 'server'.

    The enumeration is continued as long as the callback function
    'callback' returns TRUE.

    @return
    The function returns TRUE if all SA's on the server were
    enumerated, and FALSE if the enumeration was cancelled by the
    callback.

    */
Boolean ssh_pm_ike_foreach_ike_sa(SshPm pm, SshIkev2Server server,
                                  SshPmIkeServerSaCB callback,
                                  void *context);

/*--------------------------------------------------------------------*/
/* Enumerating active transforms                                      */
/*--------------------------------------------------------------------*/

/** This function retrieves the index of the next valid transform
    following the transform 'transform_index'.

    The function returns the transform index by calling the
    callback function 'callback' during this call or later.

    @return
    If 'transform_index' has the value SSH_IPSEC_INVALID_INDEX,
    the function returns the index of the first valid transform in the
    engine.

    */
void ssh_pm_get_next_transform_index(SshPm pm, SshUInt32 transform_index,
                                     SshPmIndexCB callback, void *context);

/** This function sets a callback function of this type is called to
    return public information about transform objects.

    @param info
    Points to the transform information, or has the value NULL if the
    operation failed.  The transform information remains valid as long
    as control remains in the callback function.

    */
typedef void (*SshPmTransformInfoCB)(SshPm pm,
                                     const SshEngineTransformInfo info,
                                     void *context);

/** This function retrieves public information about the transform
    object 'transform_index'.

    The information is returned by calling the callback function
    'callback' either during this call or later. */
void ssh_pm_get_transform_info(SshPm pm, SshUInt32 transform_index,
                               SshPmTransformInfoCB callback, void *context);

/** A callback function of this type is called to return transform
    statistics.

    @param stats
    The argument 'stats' points to the statistics structure or has the
    value NULL if the operation failed.  The statistics information
    remains valid as long as control remains in the callback function.

    */
typedef void (*SshPmTransformStatsCB)(SshPm pm,
                                      const SshEngineTransformStats stats,
                                      void *context);

/** Retrieves statistics of the transform object `transform_index'.
    The statistics information is returned by calling the callback
    function 'callback' either during this call or later. */
void ssh_pm_get_transform_stats(SshPm pm, SshUInt32 transform_index,
                                SshPmTransformStatsCB callback, void *context);

#ifdef SSHDIST_IPSEC_MOBIKE

/*--------------------------------------------------------------------*/
/* MOBIKE Return Routability Module API                               */
/*--------------------------------------------------------------------*/

/** Do RRC (Return Routability Check) before updating IPsec SAs. */
#define SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE     0x1
/** Do RRC (Return Routability Check) after updating IPsec SAs. */
#define SSH_PM_MOBIKE_POLICY_RRC_AFTER_SA_UPDATE      0x2
/** Disable RRC (Return Routability Check). */
#define SSH_PM_MOBIKE_POLICY_NO_RRC                   0x4

/** Sets the default PM MOBIKE return routability policy, which is used if no
    Return Routability Check callback is defined for the PM.

    @param flags
    The argument `flags' may include one or both of
    SSH_PM_MOBIKE_POLICY_RRC_BEFORE_SA_UPDATE and
    SSH_PM_MOBIKE_POLICY_RRC_AFTER_SA_UPDATE, or it may equal to
    SSH_PM_MOBIKE_POLICY_NO_RRC.

    @return
    This function sanity checks the RRC policy and returns FALSE if
    the RRC policy is invalid.

    */
Boolean ssh_pm_set_mobike_default_rrc_policy(SshPm pm,
                                             SshUInt32 rrc_policy_flags);































































#endif /* SSHDIST_IPSEC_MOBIKE */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER
#ifdef SSHDIST_RADIUS

/** Sets the policy manager 'pm' to use new radius client
    'radius_client'. If pm already has a radius client set, it will be
    destroyed and replaced with the new one. Setting radius_client to
    NULL can be used to remove a radius client and servers from the pm.

    When configuring RADIUS Accounting to pm the client struct must be
    set first.

    The PM will take over the RADIUS client structure and destroy it
    when no longer needed.

    Setting a new RADIUS client over existing does not affect pending
    requests.

    After setting new RADIUS client the RADIUS accounting in PM will
    disabled until enabled by a call to
    ssh_pm_ras_set_radius_acct_enabled().

    @param radius_client

    A RADIUS client pointer returned by ssh_radius_client_create
    function or NULL.
*/
void ssh_pm_ras_set_radius_acct_client(SshPm pm,
                                   SshRadiusClient radius_client);


/** Sets the policy manager 'pm' to use new list of radius servers
    'radius_servers'. If pm already has a list of radius servers set,
    it will be destroyed and replaced with the new one. Setting
    radius_servers to NULL can be use to remove a radius servers from
    the pm.

    Before setting radius servers the radius client must be set.

    The PM will take over the server info and destroy it when no
    longer needed, when the call is successful. If the call fails then
    the caller is resposible for destroying the server info.

    Setting new list of servers does not affect pending requests.

    @param radius_servers

    A RADIUS servers pointers returned by
    ssh_radius_client_server_info_create function or NULL.

    @return
    TRUE on success.
    FALSE on failure. The call fails when the radius a client is not set.

*/
Boolean ssh_pm_ras_set_radius_acct_servers(SshPm pm,
                                   SshRadiusClientServerInfo radius_servers);


/** Enables radius accounting in the policy manager 'pm'. Triggers
    sending of Accounting-On RADIUS Accounting request when requested.

    @param flags
    Set to SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_ON to trigger sending of
    Accounting-On message.

    @return
    TRUE on success, FALSE if RADIUS Accounting not configured.
*/
#define SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_ON 1

Boolean ssh_pm_ras_set_radius_acct_enabled(SshPm pm, SshUInt32 flags);


/** Disables radius accounting in the policy manager 'pm'. Triggers
    sending of Accounting-Off RADIUS Accounting request when
    requested. If send_accounting_off is set all pending requests are
    cancelled before sending the Accounting-Off request.

    If send_accounting_off is not set any outstanding requests shall
    finish normally.

    Disabling RADIUS Accounting does not trigger generation of
    Accounting-Stop requests for existing Accounting sessions.

    @param flags
    Set to SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_OFF to trigger sending of
    Accounting-Off message.

    @return
    TRUE on success, FALSE if RADIUS Accounting not configured.
*/
#define SSH_PM_RAS_RADIUS_SEND_ACCOUNTING_OFF 2

Boolean ssh_pm_ras_set_radius_acct_disabled(SshPm pm, SshUInt32 flags);




/** Statistics for RADIUS Accounting. */
typedef struct SshPmRadiusAcctStatsRec
{
  /** Number of accounting requests sent. */
  SshUInt32 acct_request_count;

  /** Number of Accounting-On requests sent. */
  SshUInt32 acct_request_on_count;

  /** Number of Accounting-Off requests sent. */
  SshUInt32 acct_request_off_count;

  /** Number of Accounting-Start requests sent. */
  SshUInt32 acct_request_start_count;

  /** Number of Accounting-Stop requests sent. */
  SshUInt32 acct_request_stop_count;

  /** Number of accounting responses on requests received. */
  SshUInt32 acct_request_response_count;

  /** Number of invalid responses received. */
  SshUInt32 acct_request_response_invalid_count;

  /** Number of requests failed. */
  SshUInt32 acct_request_failed_count;

  /** Number of requests failed. */
  SshUInt32 acct_request_too_long_ike_id_count;

  /** Number of requests timeouted. */
  SshUInt32 acct_request_timeout_count;

  /** Number of retransmissions. */
  SshUInt32 acct_request_retransmit_count;

  /** Number of requests cancelled */
  SshUInt32 acct_request_cancelled_count;
}
*SshPmRadiusAcctStats, SshPmRadiusAcctStatsStruct;

/** A callback function of this type is called once delivering RADIUS
    Accounting statistics.
*/
typedef void (*SshPmRadiusAcctStatsCB)(SshPm pm,
                                   const SshPmRadiusAcctStats stats,
                                   void *context);


/** This function calls the callback function 'callback' once
    delivering RADIUS Accounting statistics.
*/
void ssh_pm_radius_acct_get_stats(SshPm pm, SshPmRadiusAcctStatsCB callback,
                                  void *context);

#endif /* SSHDIST_RADIUS */
#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */


/** Add a new IKE debug configuration entry.

    @param pm
    The policy manager object to which the new entry is added.

    @param entry
    Debug configuration entry containing criteria for IKE peer
    matching and debug level. Data is copied from the entry to the
    policy manager object.

    @return
    Return TRUE on success, FALSE if no more debug configuration
    entries are allowed. Entries with duplicate or overlapping
    addresses are allowed.
*/
Boolean
ssh_pm_ike_debug_insert(SshPm pm, SshPdbgConstConfigEntry entry);

/** Remove an IKE debug configuration entry.

    @param pm
    The policy manager object from which an entry is removed.

    @param entry
    Debug configuration entry containing criteria for IKE peer
    matching and debug level. These must match an existing entry
    exactly.

    @return
    Return TRUE if a matching entry was removed, FALSE if there was no
    matching entry. If more than one entry matches only one is
    removed.
*/
Boolean
ssh_pm_ike_debug_remove(SshPm pm, SshPdbgConstConfigEntry entry);

/** Get an existing IKE debug configuration entry.

    @param pm
    The policy manager object containing the entries.

    @param previous
    If NULL then return pointer to any of the existing debug
    configuration entries.  If not NULL, assume it is a previously
    returned pointer and return pointer to another entry so that
    pointers to all entries will be eventually returned.

    @return
    Return pointer to an debug configuration entry. The pointer
    directly points to data in the policy manager object and should be
    used for reading only. If there are no more entries return
    NULL. The order in which entries are returned is unspecified.
*/
SshPdbgConstConfigEntry
ssh_pm_ike_debug_get(SshPm pm, SshPdbgConstConfigEntry previous);

#endif /* IPSEC_PM_H */
