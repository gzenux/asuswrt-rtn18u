/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Low-level policy management API for flow-based IPsec implementation.

   @description

   For main functionality, see the following:

        - SshPmAuthMethod

   * Fetching attributes from authentication data:
        - ssh_pm_auth_get_local_ip
        - ssh_pm_auth_get_local_port
        - ssh_pm_auth_get_remote_ip
        - ssh_pm_auth_get_remote_port
        - ssh_pm_auth_get_local_ifnum
        - ssh_pm_auth_get_local_id
        - ssh_pm_auth_get_remote_id
        - ssh_pm_auth_get_ike_version
        - ssh_pm_auth_get_auth_method_local
        - ssh_pm_auth_get_auth_method_remote
        - ssh_pm_auth_get_certificate
        - ssh_pm_auth_get_ca_certificate

   * Attributes for remote access client (iRAC)
        - SSH_PM_REMOTE_ACCESS_NUM_SUBNETS
        - SSH_PM_REMOTE_ACCESS_NUM_SERVERS 3
        - SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT 2
        - SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES 2
        - SshPmRemoteAccessAttrsRec
        - SshPmRemoteAccessAttrsStruct;

   * Remote access gateway
        - SshPmRemoteAccessAttrsAllocResultCB
        - SshPmRemoteAccessAttrsAllocCB
        - SshPmRemoteAccessAttrsFreeCB

   * Remote access responder (server) (iRAS) for IPSec tunnels
        - ssh_pm_tunnel_set_remote_access

   * Default remote access responder
        - ssh_pm_set_remote_access

   * Remote access initiator (client) (iRAC) for IPSec tunnels
        - ssh_pm_tunnel_set_remote_access_address

   * Password authentication server:
        - SshPmPasswdAuthResultCB
        - SshPmPasswdAuthCB
        - ssh_pm_passwd_auth_server
   Configuring Policy Manager to act as generic password authentication
   server. The password authentication is needed in some PPP
   authentications, occurring within L2TP connections.

   * SA import and export
        - SshPmSAEvent
        - SshPmIkeSAEventHandle
        - SshPmIkeSACB
        - ssh_pm_set_ike_sa_callback
        - SshPmSAImportStatus
        - SshPmIkeSAImportStatusCB
        - SshPmIpsecSAImportStatusCB
        - SshPmIkeSAPreImportCB
        - ssh_pm_ike_sa_import
        - ssh_pm_ike_sa_export
        - SshPmIPsecSAEventHandle
        - SshPmIpsecSACB
        - ssh_pm_set_ipsec_sa_callback
        - SshPmIpsecSAPreImportCB
        - ssh_pm_ipsec_sa_import
        - ssh_pm_ipsec_sa_export
        - ssh_pm_ipsec_sa_export_update_ike_sa
        - ssh_pm_ipsec_sa_export_update
           - ssh_pm_import_finalize
        - ssh_pm_ike_id_render

   * Pre-shared key selection
        - SshPmIkePreSharedKeyResultCB
        - SshPmIkePreSharedKeyCB
        - ssh_pm_set_ike_preshared_key_callback
*/

#ifndef IPSEC_PM_LOW_H
#define IPSEC_PM_LOW_H

#include "ipsec_pm.h"

#ifdef SSHDIST_IKEV1
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-fallback.h"
#endif /* SSHDIST_IKEV1 */

#include "spd_ike_blacklist.h"

/*--------------------------------------------------------------------*/
/* Rule  object manipulation functions for authorization              */
/*--------------------------------------------------------------------*/

/** This function sets an access group ID constraint for the rule.

    The remote peer must have access group ID `group_id' in order to
    use the rule for IPSec SA negotiations.  You can call this
    function multiple times for the same rule object.  Each call adds
    a new access group ID that is accepted.  If the rule does not have
    any access group ID constraints, it can be used for all
    negotiations. The function returns TRUE if the group was added and
    FALSE otherwise. */
Boolean ssh_pm_rule_add_authorization_group_id(SshPm pm, SshPmRule rule,
                                               SshUInt32 group_id);

/*--------------------------------------------------------------------*/
/* Authorization and access control                                   */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called to notify the
    authorization group of a IKE negotiation.  This is the completion
    callback for an SshPmAuthorizationCB operation. */
typedef void (*SshPmAuthorizationResultCB)(SshUInt32 *group_ids,
                                           SshUInt32 num_group_id,
                                           void *context);

/** A callback function of this type is called to authorize the remote
    peer of a Phase-1 negotiation.  The argument `auth_data' gives
    authentication data of the remote peer.  The argument `result_cb'
    specifies a callback function that must be called to return
    authorization group.  The callback can be called immeditately or
    after some time.  The argument `result_cb_context' specifies
    context data for the result callback. */
typedef void (*SshPmAuthorizationCB)(SshPmAuthData auth_data,
                                     SshPmAuthorizationResultCB result_cb,
                                     void *result_cb_context,
                                     void *context);

/** This function sets an authorization callback for the policy
    manager `pm'.

    The callback function `callback' will be called when a new Phase-1
    negotiation is completed.  The callback function can access the
    authentication information of the remote peer and decide its
    authorization group.  The authorization group is used in selecting
    policy rules for IKE and IPSec SAs.  The authorization group
    constraints are set with the
    ssh_pm_tunnel_add_authorization_group_id function. */
void ssh_pm_set_authorization_callback(SshPm pm,
                                       SshPmAuthorizationCB callback,
                                       void *context);

/** The different IKE authentication methods. */
typedef enum
{
  /** No authentication (error) */
  SSH_PM_AUTH_NONE,
  /** Pre-shared keys. */
  SSH_PM_AUTH_PSK
#ifdef SSHDIST_IKE_CERT_AUTH
  /** RSA signatures. */
  , SSH_PM_AUTH_RSA
  /** DSA signatures. */
  , SSH_PM_AUTH_DSA
#ifdef SSHDIST_CRYPT_ECP
  /** DSA signatures using Elliptic curves over prime fields */
  , SSH_PM_AUTH_ECP_DSA
#endif /* SSHDIST_CRYPT_ECP */
#endif /* SSHDIST_IKE_CERT_AUTH */
#ifdef SSHDIST_IKE_EAP_AUTH
  /** EAP MD5 challenge */
  , SSH_PM_AUTH_EAP_MD5_CHALLENGE
  , SSH_PM_AUTH_EAP_MSCHAP_V2




  /** 2G networks EAP SIM */
  , SSH_PM_AUTH_EAP_SIM
  /** 3G networks EAP AKA */
  , SSH_PM_AUTH_EAP_AKA




  , SSH_PM_AUTH_EAP_TLS
#endif /* SSHDIST_IKE_EAP_AUTH */
} SshPmAuthMethod;

/*--------------------------------------------------------------------*/
/* Fetching attributes from authentication data                       */
/*--------------------------------------------------------------------*/

/** Get the local IKE server IP address. */
void ssh_pm_auth_get_local_ip(SshPmAuthData data, SshIpAddr addr_return);

/** Get the local IKE server port number. */
SshUInt16 ssh_pm_auth_get_local_port(SshPmAuthData data);

/** Get the remote IKE server IP address. */
void ssh_pm_auth_get_remote_ip(SshPmAuthData data, SshIpAddr addr_return);

/** Get the remote IKE server port number. */
SshUInt16 ssh_pm_auth_get_remote_port(SshPmAuthData data);

/** Get the local interface number. */
SshUInt32 ssh_pm_auth_get_local_ifnum(SshPmAuthData data);

/** Get the local IKE SA ID. */
SshIkev2PayloadID
ssh_pm_auth_get_local_id(SshPmAuthData data, SshUInt32 order);

/** Get the remote IKE SA ID. */
SshIkev2PayloadID
ssh_pm_auth_get_remote_id(SshPmAuthData data, SshUInt32 order);

/** Get the IKE version used for this IKE SA. */
SshUInt32 ssh_pm_auth_get_ike_version(SshPmAuthData data);

/** Get the IKE SA lifetime */
SshTime ssh_pm_auth_get_lifetime(SshPmAuthData data);

/** Get the IKE SA authentication method used by the local end.*/
SshPmAuthMethod ssh_pm_auth_get_auth_method_local(SshPmAuthData data);

/** Get the IKE SA authentication method used by the remote end.*/
SshPmAuthMethod ssh_pm_auth_get_auth_method_remote(SshPmAuthData data);

#ifdef SSHDIST_IKE_CERT_AUTH
/** Get the remote peer's end-user certificate.  This returns NULL if
    the authentication was done with pre-shared keys. */
const unsigned char *ssh_pm_auth_get_certificate(SshPmAuthData data,
                                                 size_t *cert_len_return);

/** Get the trusted CA certificate that certified the remote peer's
    end-user certificate.  This returns NULL if the authentication was
    done with pre-shared keys. */
const unsigned char *ssh_pm_auth_get_ca_certificate(SshPmAuthData data,
                                                    size_t *cert_len_return);

#endif /* SSHDIST_IKE_CERT_AUTH */

/*--------------------------------------------------------------------*/
/** Duplicate the authentication data object for the short duration of an
    asynchronous operation. The caller must free the duplicate using
    ssh_pm_auth_data_free(). */
SshPmAuthData ssh_pm_auth_data_dup(SshPmAuthData data);

/** Free one reference to the authentication data object. */
void ssh_pm_auth_data_free(SshPmAuthData data);

/* Attributes for remote access client (iRAC)                         */
/*--------------------------------------------------------------------*/

/** Number of server addresses available for remote access
    attributes. */
#define SSH_PM_REMOTE_ACCESS_NUM_SERVERS 3

/**  Number of WINS/DNS server addresses requested by Client or set by the
     server */
#define SSH_PM_REMOTE_ACCESS_NUM_SERVERS_EXT 2

/** The maximum number of addresses that can be assigned to a client. The
    maximum supported value for this parameter is two. It is a fatal
    error if if more than a single address of the same family
    (IPv4 or IPv6) is returned from a call to SshPmRemoteAccessAttrsAllocCB.
*/
#define SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES 2

/** The maximum number of subnets that can be passed to the client. */
#define SSH_PM_REMOTE_ACCESS_NUM_SUBNETS  SSH_MAX_RULE_TRAFFIC_SELECTORS_ITEMS

/** Attributes for a remote access client. */
struct SshPmRemoteAccessAttrsRec
{
  /** Own IP address for PPP links. */
  SshIpAddrStruct own_address;

  /** IP address and netmask. */
  SshUInt8 num_addresses;
  SshIpAddrStruct addresses[SSH_PM_REMOTE_ACCESS_NUM_CLIENT_ADDRESSES];

  /** Address context. This pointer is passed to the remote access free
      callback when the addresses are freed. */
  void *address_context;

  /** The number of seconds that the internal addresses `addresses[]' are
      valid. The client must renew the addresses within this period. Note
      that RFC5996 instructs to ignore this value, thus it must not be
      used with IKEv2 configuration payloads. */
  SshUInt32 address_expiry;

  /** A boolean flag describing whether the `address_expiry' field is
      set for each assigned client address. */
  Boolean address_expiry_set;

  /** DHCPv6 server identifier */
  SshUInt16 server_duid_len;
  unsigned char *server_duid;

  /** The number of seconds within what the internal addresses `addresses[]'
      lease should be renewed from a DHCP server. */
  SshUInt32 lease_renewal;

  /** DNS server address. */
  SshUInt32 num_dns;
  SshIpAddrStruct dns[SSH_PM_REMOTE_ACCESS_NUM_SERVERS];

  /** NetBios Name Server (WINS) address. */
  SshUInt32 num_wins;
  SshIpAddrStruct wins[SSH_PM_REMOTE_ACCESS_NUM_SERVERS];

  /** DHCP server address. */
  SshUInt32 num_dhcp;
  SshIpAddrStruct dhcp[SSH_PM_REMOTE_ACCESS_NUM_SERVERS];

  /** Additional sub-networks, protected by the gateway. */
  SshUInt32 num_subnets;
  SshIpAddrStruct subnets[SSH_PM_REMOTE_ACCESS_NUM_SUBNETS];
};

typedef struct SshPmRemoteAccessAttrsRec SshPmRemoteAccessAttrsStruct;
typedef struct SshPmRemoteAccessAttrsRec *SshPmRemoteAccessAttrs;


/** Duplicate the remote access attributes `attributes'.  The function
    returns NULL if the system ran out of memory. */
SshPmRemoteAccessAttrs
ssh_pm_dup_remote_access_attrs(SshPmRemoteAccessAttrs attributes);

/** Free the dynamically allocate remote access attributes
    `attributes'. */
void
ssh_pm_free_remote_access_attrs(SshPmRemoteAccessAttrs attributes);


#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_SERVER

/*--------------------------------------------------------------------*/
/* Remote access gateway                                              */
/*--------------------------------------------------------------------*/

#define SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_RENEW   0x01
#define SSH_PM_REMOTE_ACCESS_ALLOC_FLAG_IMPORT  0x02

/** A callback function of this type is called to notify success of
    allocation remote access attributes.

    If the operation was successful, the argument `attributes' is
    non-null and it must specify at least IP address of the remote
    access client.  If the argument `attributes' has the value NULL,
    the allocation failed.

    Note that the remote access attributes will be freed by freeing
    the client IP address. If you dynamically associate other
    attributes for the IP address, you must maintain the mapping from
    the IP address to the attributes yourself. The policy manager
    will only notify about the freeing of the IP address by calling
    the SshPmRemoteAccessAttrsFreeCB. */
typedef void
(*SshPmRemoteAccessAttrsAllocResultCB)(SshPmRemoteAccessAttrs attributes,
                                       void *context);

/** A callback function of this type is called to allocate remote
    access attributes for a remote access client as part of an IKE
    negotiation with exchange data 'ike_exchange_data'.

    If 'requested_attributes' is not NULL, it contains the remote
    access attributes that the client is requesting. The callback
    function can use this as a hint when allocating attributes for the
    client, although the implementation may choose to ignore the
    client's requested values. The function must report the success
    of the operation by calling the completion callback `result_cb'.
    The argument `result_cb_context' specifies context data for the
    result callback.  The argument `context' is the user-supplied
    context data for the allocation function. */
typedef SshOperationHandle
(*SshPmRemoteAccessAttrsAllocCB)(SshPm pm,
                                 SshPmAuthData ad,
                                 SshUInt32 flags,
                                 SshPmRemoteAccessAttrs requested_attributes,
                                 SshPmRemoteAccessAttrsAllocResultCB result_cb,
                                 void *result_cb_context,
                                 void *context);

/** A callback function of this type is called to free the remote
    access client IP address `address'.

    The address has been previously allocated with the
    SshPmRemoteAccessAttrsAllocCB. The argument `address_context' is the
    `attributes->address_context' from the allocated attributes. When an
    address is freed, it means that the remote access client does not use the
    address anymore and it can be reused for another client. */
typedef void
(*SshPmRemoteAccessAttrsFreeCB)(SshPm pm,
                                const SshIpAddr address,
                                void *address_context,
                                void *context);

/*--------------------------------------------------------------------*/
/* Remote access responder (server) (iRAS) for IPSec tunnels          */
/*--------------------------------------------------------------------*/

/** This function Sets the remote access callbacks for the tunnel
    `tunnel'.

    The tunnel remote access callbacks are used in the IKE CFGMODE
    negotiations, initiated by the gateway.  The allocate callback
    `alloc_cb' is called to allocate attributes for a new remote
    access attributes.  The free callback `free_cb' is called to free
    remote access attributes, earlier allocated with the
    `alloc_cb'. */
void ssh_pm_tunnel_set_remote_access(SshPmTunnel tunnel,
                                     SshPmRemoteAccessAttrsAllocCB alloc_cb,
                                     SshPmRemoteAccessAttrsFreeCB free_cb,
                                     void *context);

/*--------------------------------------------------------------------*/
/* Default remote access responder                                    */
/*--------------------------------------------------------------------*/

/** This function sets the default remote access callbacks for the
    policy manager `pm'.

    The default remote access callbacks are used for IKE CFGMODE
    negotiations, initiated by the remote access client, and in L2TP
    incoming calls.  The allocate callback `alloc_cb' is called to
    allocate attributes for a new remote access attributes.  The free
    callback `free_cb' is called to free remote access attributes,
    earlier allocated with the `alloc_cb'. */
void ssh_pm_set_remote_access(SshPm pm,
                              SshPmRemoteAccessAttrsAllocCB alloc_cb,
                              SshPmRemoteAccessAttrsFreeCB free_cb,
                              void *context);

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_SERVER */

#ifdef SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT
/*--------------------------------------------------------------------*/
/* Remote access initiator (client) (iRAC) for IPSec tunnels          */
/*--------------------------------------------------------------------*/

/** This function sets an address that a remote access client will specify
    as its requested address to the remote access server when performing
    IKE configuration mode. */
Boolean ssh_pm_tunnel_set_remote_access_address(SshPmTunnel tunnel,
                                                const char *address);

/** This function sets a virtual adapter that this tunnel will configure
    after performing IKE configuration mode. */
Boolean ssh_pm_tunnel_set_virtual_adapter(SshPmTunnel tunnel,
                                          const unsigned char *name);

#endif /* SSHDIST_IPSEC_REMOTE_ACCESS_CLIENT */


/*--------------------------------------------------------------------*/
/* Password authentication server                                     */
/*--------------------------------------------------------------------*/

/** Configuring policy manager to act as generic password
    authentication server.  The password authentication is needed in
    some PPP authentications, occurring within L2TP connections. */

/** A callback function of this type is called to complete a password
    authentication query.  The arguments `user_password',
    `user_password_len' specify the user's plain-text password.  If
    the argument `user_password' has the value NULL, the user password
    is unknown and the authentication will fail. */
typedef void (*SshPmPasswdAuthResultCB)(const unsigned char *user_password,
                                        size_t user_password_len,
                                        void *context);

/** A callback function of this type is called to fetch the password of
    the user `user_name', `user_name_len'.  The callback function must
    call the completion callback `result_callback' to complete the query. */
typedef void (*SshPmPasswdAuthCB)(const unsigned char *user_name,
                                  size_t user_name_len,
                                  SshPmPasswdAuthResultCB result_callback,
                                  void *result_callback_context,
                                  void *context);

/** Set a callback to handle password authentication server queries.
    Whenever a new password based authentication is requirred, the
    policy manager will call the callback function `callback' to fetch
    the user's password. */
void ssh_pm_passwd_auth_server(SshPm pm, SshPmPasswdAuthCB callback,
                               void *context);


/*--------------------------------------------------------------------*/
/** IKE and IPsec SA events. */
/*--------------------------------------------------------------------*/

typedef enum
{
  /** SA created. */
  SSH_PM_SA_EVENT_CREATED,

  /** SA updated. */
  SSH_PM_SA_EVENT_UPDATED,

  /** SA rekeyed. */
  SSH_PM_SA_EVENT_REKEYED,

  /** SA deleted. */
  SSH_PM_SA_EVENT_DELETED

} SshPmSAEvent;

/** Handles for accessing IKE SA and IPsec SA event data. */
typedef struct SshPmIkeSAEventHandleRec *SshPmIkeSAEventHandle;
typedef struct SshPmIPsecSAEventHandleRec *SshPmIPsecSAEventHandle;

/** A callback function of this type is called when an event occurs
    for the IKE SA `ike_sa'.  The argument `event' describes the event.
    The SSH_PM_SA_EVENT_REKEYED event is only delivered for IKEv2 SA's.

    The 'ike_sa' is valid only for the duration of this call. */
typedef void (*SshPmIkeSACB)(SshPm pm,
                             SshPmSAEvent event,
                             SshPmIkeSAEventHandle ike_sa,
                             void *context);

/** This function sets a callback that is called when events occur on
    IKE SAs.

    IKE SA events include creation as part of completed auth-exchange,
    rekey as part of create-child exchange and delete.
*/
void
ssh_pm_set_ike_sa_callback(SshPm pm,
                           SshPmIkeSACB callback,
                           void *callback_context);

/** A callback function of this type is called when an event occurs
    for the IPsec SA `ipsec_sa'.  The argument `event' describes the
    event.

    The 'ipsec_sa' is valid only for the duration of this call.

    For the delete event only SPI and protocol values of the
    'ipsec_sa' have been filled. */
typedef void (*SshPmIpsecSACB)(SshPm pm,
                               SshPmSAEvent event,
                               SshPmIPsecSAEventHandle ipsec_sa,
                               void *context);

/** Sets a callback function that is called when events occur on IPsec
    SAs. */
void
ssh_pm_set_ipsec_sa_callback(SshPm pm,
                             SshPmIpsecSACB callback,
                             void *callback_context);

/*--------------------------------------------------------------------*/
/* API for accessing information from the IKE SA represented by the   */
/* SshPmIkeSAEventHandle                                              */
/*--------------------------------------------------------------------*/

/** Fills in the buffers 'ike_spi_i' and 'ike_spi_r' with the IKE SPI's
    from the IKE SA 'ike_sa'. 'ike_spi_i' and 'ike_spi_r' should each point
    to an 8 byte buffer. */
void
ssh_pm_ike_sa_get_cookies(SshPm pm,
                          SshPmIkeSAEventHandle ike_sa,
                          unsigned char *ike_spi_i,
                          unsigned char *ike_spi_r);

/** Fills in the buffers 'old_ike_spi_i' and 'old_ike_spi_r' with the
    old IKE SPI's from the IKE SA 'ike_sa', i.e. if 'ike_sa' is an IKEv2
    SA that has rekeyed a previous SA, then this returns the IKE SPI's of
    the previous IKE SA (before the rekey). This function may be used when
    updating exported IPsec SA's after an IKE SA rekey.

    'old_ike_spi_i' and 'old_ike_spi_r' should each point to an 8 byte
    buffer. If the IKE SA has not rekeyed a previous IKE SA then
    'old_ike_spi_i' and 'old_ike_spi_r' are returned as zeroed memory. */
void
ssh_pm_ike_sa_get_old_cookies(SshPm pm,
                              SshPmIkeSAEventHandle ike_sa,
                              unsigned char *old_ike_spi_i,
                              unsigned char *old_ike_spi_r);

/*--------------------------------------------------------------------*/
/* API for accessing and modifying information from the IPsec SA      */
/* represented by the the SshPmIPsecSAEventHandle                     */
/*--------------------------------------------------------------------*/

/** Fills in the buffers 'ike_spi_i' and 'ike_spi_r' with the IKE SPI's
    from the parent IKE SA that was used for negotiating the IPsec SA
    'ipsec_sa'. 'ike_spi_i' and 'ike_spi_r' should each point to an 8 byte
    buffer. This function may be used for ensuring that all IPsec SA's
    belonging to the same parent IKE SA are stored locally when exported.
    This will reduce the effort in updating IPsec SA's after IKE SA rekey
    (the function ssh_pm_ipsec_sa_export_update_ike_sa needs to be called
    for all IPsec SA's belonging to the old rekeyed IKE SA). */
void
ssh_pm_ipsec_sa_get_ike_cookies(SshPm pm,
                                SshPmIPsecSAEventHandle ipsec_sa,
                                unsigned char *ike_spi_i,
                                unsigned char *ike_spi_r);

/** Returns the protocol of the IPsec SA 'ipsec_sa'. The returned protocol
    is either SSH_IPPROTO_ESP or SSH_IPPROTO_AH. */
SshInetIPProtocolID
ssh_pm_ipsec_sa_get_protocol(SshPm pm,
                             SshPmIPsecSAEventHandle ipsec_sa);

/** Returns the inbound SPI of the IPsec SA 'ipsec_sa'. */
SshUInt32
ssh_pm_ipsec_sa_get_inbound_spi(SshPm pm,
                                SshPmIPsecSAEventHandle ipsec_sa);

/** Returns the outbound SPI of the IPsec SA 'ipsec_sa'. */
SshUInt32
ssh_pm_ipsec_sa_get_outbound_spi(SshPm pm,
                                 SshPmIPsecSAEventHandle ipsec_sa);

/** Returns the old inbound SPI of the IPsec SA 'ipsec_sa', the inbound
    SPI before the last rekey. */
SshUInt32
ssh_pm_ipsec_sa_get_old_inbound_spi(SshPm pm,
                                    SshPmIPsecSAEventHandle ipsec_sa);

/** Returns negotiatiated lifetime in seconds of the IPsec SA 'ipsec_sa'. */
SshUInt32
ssh_pm_ipsec_sa_get_life_seconds(SshPm pm,
                                 SshPmIPsecSAEventHandle ipsec_sa);

/** Returns remaining lifetime in seconds of the IPsec SA 'ipsec_sa'. */
SshUInt32
ssh_pm_ipsec_sa_get_remaining_life_seconds(SshPm pm,
                                           SshPmIPsecSAEventHandle ipsec_sa);

/** Returns negotiatiated lifetime in kilobytes of the IPsec SA 'ipsec_sa'. */
SshUInt32
ssh_pm_ipsec_sa_get_life_kilobytes(SshPm pm,
                                   SshPmIPsecSAEventHandle ipsec_sa);

/** Returns the outbound sequence number of the IPsec SA 'ipsec_sa'.
    'seq_high' is returned as SSH_IPSEC_INVALID_INDEX if 64 bit sequence
   numbers are not in use for this SA. */
void
ssh_pm_ipsec_sa_get_outbound_sequence_number(SshPm pm,
                                             SshPmIPsecSAEventHandle ipsec_sa,
                                             SshUInt32 *seq_low,
                                             SshUInt32 *seq_high);

/** Returns the replay window of the IPsec SA 'ipsec_sa'. The contents of
    'replay_offset_low' and 'replay_offset_high' are set to the replay window
    offset. 'replay_mask' must be a SshUInt32 array of size
    SSH_ENGINE_REPLAY_WINDOW_WORDS and its contents is filled with the actual
    replay window bit mask. */
void
ssh_pm_ipsec_sa_get_replay_window(SshPm pm,
                                  SshPmIPsecSAEventHandle ipsec_sa,
                                  SshUInt32 *replay_offset_low,
                                  SshUInt32 *replay_offset_high,
                                  SshUInt32 *replay_mask);

#ifdef SSHDIST_IPSEC_SA_EXPORT
/*--------------------------------------------------------------------*/
/* SA import and export                                               */
/*--------------------------------------------------------------------*/

typedef enum
{
  /** SA imported successfully. */
  SSH_PM_SA_IMPORT_OK,

  /** SA import failed because SA has expired. */
  SSH_PM_SA_IMPORT_ERROR_SA_EXPIRED,

  /** SA import failed because invalid input buffer format. */
  SSH_PM_SA_IMPORT_ERROR_INVALID_FORMAT,

  /** SA import failed because parent IKE SA was not found or was unusable. */
  SSH_PM_SA_IMPORT_ERROR_NO_IKE_SA_FOUND,

  /** SA import failed because no suitable IKE server was found. */
  SSH_PM_SA_IMPORT_ERROR_NO_SERVER_FOUND,

  /** SA import failed because no suitable policy rule or tunnel was found. */
  SSH_PM_SA_IMPORT_ERROR_POLICY_MISMATCH,

  /** SA import failed because out of memory. */
  SSH_PM_SA_IMPORT_ERROR_OUT_OF_MEMORY

} SshPmSAImportStatus;

/*--------------------------------------------------------------------*/
/* IKE SA import and export                                           */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called before an imported IKE
    SA is installed. The application must indicate whether to install or
    reject this IKE SA using the 'accept_cb'. */
typedef void
(*SshPmIkeSAPreImportCB)(SshPm pm,
                         SshPmIkeSAEventHandle ike_sa,
                         SshIpAddr remote_ip,
                         SshPmStatusCB accept_cb,
                         void *accept_context,
                         void *context);

/** A callback function of this type is called to indicate status of an
    IKE SA import operation. On success `status' is SSH_PM_IMPORT_OK and
    `ike_sa' is a handle to the imported IKE SA which can be used for
    re-exporting the SA data. On error `ike_sa' is undefined. */
typedef void
(*SshPmIkeSAImportStatusCB)(SshPm pm,
                            SshPmSAImportStatus status,
                            SshPmIkeSAEventHandle ike_sa,
                            void *context);

/** Import an IKE SA from the buffer `buffer' to the policy manager
    `pm'.

    The function returns TRUE if the SA was imported and FALSE
    otherwise.  In either case, the function might consume some data
    from the buffer `buffer'. The `buffer' must be valid until this asynch
    operation completes by calling `status_callback'.

    A SSH_PM_SA_EVENT_CREATED event is triggered for the imported IKE SA
    immediately after the import operation completes. */
SshOperationHandle
ssh_pm_ike_sa_import(SshPm pm,
                     SshBuffer buffer,
                     SshPmIkeSAPreImportCB import_callback,
                     void *import_callback_context,
                     SshPmIkeSAImportStatusCB status_callback,
                     void *status_callback_context);

/** Decode a serialized IKE SA deleted event from the buffer `buffer'.
    This function fills in the return value parameters `ike_version_ret',
    `ike_initiator_ret', `ike_spi_i_ret' and `ike_spi_r_ret'. The parameters
    `ike_spi_i_ret' and `ike_spi_r_ret' must point to valid memory each of
    size of 8 bytes allocated by the caller. This function may consume bytes
    from `buffer'. On success this returns SSH_PM_SA_IMPORT_OK. On error the
    returned status code indicates the reason of failure and the values of
    the return parameter values are undefined. */
SshPmSAImportStatus
ssh_pm_ike_sa_decode_deleted_event(SshBuffer buffer,
                                   SshUInt32 *ike_version_ret,
                                   unsigned char *ike_spi_i_ret,
                                   unsigned char *ike_spi_r_ret);

/** Export the IKE SA `ike_sa' into the buffer `buffer'.

    The function returns the number of bytes appended to the buffer or
    0 if the export operation failed. The input buffer must be
    initialized. */
size_t
ssh_pm_ike_sa_export(SshPm pm,
                     SshPmIkeSAEventHandle ike_sa,
                     SshBuffer buffer);

/** Returns the IKE SA's tunnel application identifier. This function may be
    called only from SshPmIkeSAPreImportCB when the IKE SA is imported. */
Boolean
ssh_pm_ike_sa_get_tunnel_application_identifier(SshPm pm,
                                                SshPmIkeSAEventHandle ike_sa,
                                                unsigned char *id,
                                                size_t *id_len);

/** Sets the 'tunnel' for IKE SA 'ike_sa'. This function may be called
    only from SshPmIkeSAPreImportCB when the IKE SA is imported. */
void
ssh_pm_ike_sa_set_tunnel(SshPm pm,
                         SshPmIkeSAEventHandle ike_sa,
                         SshPmTunnel tunnel);

/*--------------------------------------------------------------------*/
/* IPsec SA import and export                                         */
/*--------------------------------------------------------------------*/

/** A callback function of this type is called before an imported
    IPsec SA is installed. The application must accept or reject the
    SA. It indicates this decision by calling the
    'accept_callback'. If the SA is accepted, the data structure 'ipsec_sa'
    will be used to install the SA. The application may modify the
    contents of the 'ipsec_sa' (for example set the outbound sequence number
    to a proper value). */
typedef void
(*SshPmIpsecSAPreImportCB)(SshPm pm,
                           SshPmIPsecSAEventHandle ipsec_sa,
                           SshPmStatusCB accept_callback,
                           void *accept_context,
                           void *context);

/** A callback function of this type is called to indicate status of an
    IPsec SA import operation. On success `status' is SSH_PM_IMPORT_OK and
    `ipsec_sa' is a handle to the imported IPsec SA which can be used for
    re-exporting the SA data. On error `ipsec_sa' is undefined. */
typedef void
(*SshPmIpsecSAImportStatusCB)(SshPm pm,
                            SshPmSAImportStatus status,
                            SshPmIPsecSAEventHandle ipsec_sa,
                            void *context);

/** Import serialized IPSEC SA into the policy manager.

    The imported IPSEC SA has its outbound sequence number initialized
    with the value of the sequence number when the IPSEC SA was exported
    and inbound replay window initialized with zero. The integrator
    (you, that is) needs to provide mechanisms to synchronize this run-time
    information within the cluster/HA platform.

    One could consider sending tuples containing (spi,seqno)
    periodically via cluster management channel or via
    external/internal network interfaces (authenticated).

    The provided callback is called when SA has been imported, and the
    next SA import can be started. A SSH_PM_SA_EVENT_CREATED event is
    triggered for the imported IPsec SA immediately after the import
    operation completes. */
SshOperationHandle
ssh_pm_ipsec_sa_import(SshPm pm,
                       SshBuffer buffer,
                       SshPmIpsecSAPreImportCB pre_import_callback,
                       void *pre_import_context,
                       SshPmIpsecSAImportStatusCB callback,
                       void *callback_context);

/** Decode a serialized IPsec SA deleted event from the buffer `buffer'.
    This function fills in the return value parameters `ipproto_ret',
    `inbound_spi_ret' and  `outbound_spi_ret'. This function may consume bytes
    from `buffer'. On success this returns SSH_PM_SA_IMPORT_OK. On error the
    returned status code indicates the reason of failure and the values of
    the return parameter values are undefined. */
SshPmSAImportStatus
ssh_pm_ipsec_sa_decode_deleted_event(SshBuffer buffer,
                                     SshInetIPProtocolID *ipproto_ret,
                                     SshUInt32 *inbound_spi_ret,
                                     SshUInt32 *outbound_spi_ret);

/** Export the IPsec SA `ipsec_sa' into the buffer `buffer'.

    The function returns the number of bytes appended to the buffer or
    0 if the export operation failed. The input buffer must be
    initialized. */
size_t
ssh_pm_ipsec_sa_export(SshPm pm,
                       SshPmIPsecSAEventHandle ipsec_sa,
                       SshBuffer buffer);

/** Update a previously exported IPsec SA encoded in the buffer
    `buffer'. This must be called for all exported IPsec SA's whose
    IKEv2 SA has been rekeyed by 'ike_sa'. The SPI's of the IKE SA
    that 'ike_sa' has rekeyed may be found using the
    ssh_pm_ike_sa_get_old_cookies function.

    This function has no effect on the exported IPsec SA in 'buffer' if
    the IKE SA of the IPsec SA is not the IKE SA which 'ike_sa' has rekeyed.

    The function returns the number of bytes in the buffer after the update
    or 0 if the update operation failed. The input buffer must contain a
    previously exported IPsec SA. */
size_t
ssh_pm_ipsec_sa_export_update_ike_sa(SshPm pm,
                                     SshBuffer buffer,
                                     SshPmIkeSAEventHandle ike_sa);

/** Update exported IPsec SA. The application should call this whenever it
    receives a SSH_PM_SA_EVENT_UPDATED for an IPsec SA. This updates the
    IPsec SA in `buffer' according to the changes in `ipsec_sa' event handle.
*/
size_t
ssh_pm_ipsec_sa_export_update(SshPm pm,
                              SshBuffer buffer,
                              SshPmIPsecSAEventHandle ipsec_sa);

/** Returns the IPsec SA's tunnel application identifier. This function
    may be called only from SshPmIpsecSAPreImportCB when the IPsec SA is
    imported. */
Boolean
ssh_pm_ipsec_sa_get_tunnel_application_identifier(SshPm pm,
                                              SshPmIPsecSAEventHandle ipsec_sa,
                                              unsigned char *id,
                                              size_t *id_len);

/** Sets the 'tunnel' for IPsec SA 'ipsec_sa'. This function may be
    called only from SshPmIpsecSAPreImportCB when the IPsec SA is imported. */
void
ssh_pm_ipsec_sa_set_tunnel(SshPm pm,
                           SshPmIPsecSAEventHandle ipsec_sa,
                           SshPmTunnel tunnel);

/** Returns the IPsec SA's outer tunnel application identifier. This function
    may be called only from SshPmIpsecSAPreImportCB when the IPsec SA is
    imported. */
Boolean
ssh_pm_ipsec_sa_get_outer_tunnel_application_identifier(SshPm pm,
                                              SshPmIPsecSAEventHandle ipsec_sa,
                                              unsigned char *id,
                                              size_t *id_len);

/** Sets the 'outer_tunnel' for IPsec SA 'ipsec_sa'. This function may be
    called only from SshPmIpsecSAPreImportCB when the IPsec SA is imported. */
void
ssh_pm_ipsec_sa_set_outer_tunnel(SshPm pm,
                                 SshPmIPsecSAEventHandle ipsec_sa,
                                 SshPmTunnel outer_tunnel);

/** Returns the IPsec SA's rule application identifier. This function may be
    called only from SshPmIpsecSAPreImportCB when the IPsec SA is imported. */
Boolean
ssh_pm_ipsec_sa_get_rule_application_identifier(SshPm pm,
                                              SshPmIPsecSAEventHandle ipsec_sa,
                                              unsigned char *id,
                                              size_t *id_len);

/** Sets the 'rule' for IPsec SA 'ipsec_sa'. This function may be called only
    from SshPmIpsecSAPreImportCB when the IPsec SA is imported. */
void
ssh_pm_ipsec_sa_set_rule(SshPm pm,
                         SshPmIPsecSAEventHandle ipsec_sa,
                         SshPmRule rule);

/** Sets the kilobyte lifetime for IPsec SA 'ipsec_sa'. */
void
ssh_pm_ipsec_sa_set_life_kilobytes(SshPm pm,
                                   SshPmIPsecSAEventHandle ipsec_sa,
                                   SshUInt32 life_kilobytes);

/** Sets the outbound sequence number of the IPsec SA 'ipsec_sa'.
    'seq_high' is ignored if 64 bit sequence numbers are not in use
    for this SA. */
void
ssh_pm_ipsec_sa_set_outbound_sequence_number(SshPm pm,
                                             SshPmIPsecSAEventHandle ipsec_sa,
                                             SshUInt32 seq_low,
                                             SshUInt32 seq_high);

/** Sets the replay window for the IPsec SA 'ipsec_sa'. 'replay_offset_low'
    and 'replay_offset_high' specify the replay window offset. 'replay_mask'
    must be a SshUInt32 array of size SSH_ENGINE_REPLAY_WINDOW_WORDS and its
    contents is the actual replay window bit mask. */
void
ssh_pm_ipsec_sa_set_replay_window(SshPm pm,
                                  SshPmIPsecSAEventHandle ipsec_sa,
                                  SshUInt32 replay_offset_low,
                                  SshUInt32 replay_offset_high,
                                  SshUInt32 *replay_mask);

/** Perform housekeeping after all IKE and IPsec SAs have been imported.
    This function must be called after importing one or more IKE or
    IPsec SA's. */
void
ssh_pm_import_finalize(SshPm pm);

#endif /* SSHDIST_IPSEC_SA_EXPORT */


/** Render function for IKEv2 payload ID. */
int
ssh_pm_ike_id_render(unsigned char *buf, int buf_size,
                     int precision, void *datum);
































/* ************** Pre-shared key selection **************************/

/** A callback function of this type is called to complete an
    pre-shared key query operation.  The arguments `key', `key_len'
    describe the pre-shared key to be used.  If the pre-shared key
    could not be found, the argument `key' must be set to NULL. */
typedef void (*SshPmIkePreSharedKeyResultCB)(const unsigned char *key,
                                             size_t key_len,
                                             void *context);

/** A callback function of this type is called to query a pre-shared
    key for an IKE negotiation with exchange data 'ike_exchange_data',
    for use in authenticating the peer in IKE SA negotiations. The
    principal selector for resolving the pre-shared key is the
    identity of the remote IKE peer, obtained from
    'ike_exchange_data->ike_ed'. The callback must call the result
    callback `result_cb' to complete the query. */
typedef void (*SshPmIkePreSharedKeyCB)(SshIkev2ExchangeData ike_exchange_data,
                                       SshPmIkePreSharedKeyResultCB result_cb,
                                       void *result_cb_context,
                                       void *context);

/** Set a callback to query pre-shared keys for IKE SA negotiations. */
void ssh_pm_set_ike_preshared_key_callback(SshPm pm,
                                           SshPmIkePreSharedKeyCB callback,
                                           void *context);

#ifdef SSHDIST_IKE_XAUTH
/* ***************** Extended authentication ************************/

/** Features that do not require any specific processing have
    been lumped together as Generic in xauth draft. This would
    tell us which "Generic" method has been used actually. */
typedef enum
{
  /** Generic method user-name and password. */
  SSH_PM_XAUTH_GENERIC_USER_NAME_PASSWORD,

  /** Generic method user name and passcode. */
  SSH_PM_XAUTH_GENERIC_SECURID

} SshPmXauthFlags;

#ifdef SSHDIST_IPSEC_XAUTH_SERVER
/** Sets the xauth method type for Policy Manager. The Policy Manager
    requests the user to perform the xauth mode using the method type
    value in the the XAUTH_TYPE attribute in the XAUTH request.

    This is used to fill in the respective fields of the
    SshPmXauthMethodRec structure.

    Arguments

    pm: The Policy Manager context

    method: The Xauth type. Possible XAUTH_TYPE values are the
    following: Generic, Radius CHAP, OTP, S_KEY.

    flag: This argument provides additional information that might be
    needed for specifying the Xauth method. */
Boolean ssh_pm_set_xauth_method(SshPm pm,
                                SshIkeXauthType method,
                                SshPmXauthFlags flag);

#endif /* SSHDIST_IPSEC_XAUTH_SERVER */
#endif /* SSHDIST_IKE_XAUTH */

#endif /* not IPSEC_PM_LOW_H */
