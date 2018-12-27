/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 initialization and initiator interface.

   Description:

   *Basic Concepts*

   The IKEv2 library provides IKEv2 protocol. The library outsources SA
   handling to SAD, authentication to PAD and security policy decisions
   to SPD modules.

   * <B>SAD</B>:
        Security association database. This entity provides storage
        for IKE and IPsec SA's, as described on header file
        sshikev2-sad.h. The application using this library needs to
        implement functionality required by this interface. The IKE
        library does not provide any SA storage.

   * <B>PAD</B>:
        Peer authentication database. This entity provides peer
        authentication information, like shared secrets, private keys
        and certificates, as described at header file
        sshikev2-pad.h. The application needs to implement the API
        described there.

   * <B>SPD</B>:
        Security policy database. This entity provides answers to
        questions if connections are allowed, SA proposal processing
        and traffic selectors. It is described at header file
        sshikev2-spd.h.


   This library also provides optional IKEv1 fallback functionality using
   the IKEv2 API (some issues need to be considered at the application
   (Policy Manager) related to the fallback). This feature (if enabled at
   your distribution) may be disabled by turning off SSHDIST_IKEV1 from
   sshdistdefs.h.


   *Basic Data Structures*

   * <B>SshIkev2</B>:
        A global IKEv2 specific state. The SshIkev2 structure itself
        contains global information like auditing context, state
        machine, freelists for packets, DH group information,
        statistics, and common configuration information. Normally
        there is exactly one SshIkev2 structure. The SshIkev2Server
        contexts are also tied into one SshIkev2 context (a list or
        similar).


   * <B>SshIkev2Server</B>:
        An IKEv2 server specific state. The IKEv2 server is bound to a
        specific IP address and ports (to known which
        address/interface received packet to this server). Each
        SshIkev2Server structure normally has two ports associated, a
        normal and a NAT-T port. The IKEv2 SAs created by the server
        are not bound to a specific server - it can process requests
        from any server, but each request/reply pair is bound to one
        specific server (i.e one IKEv2 request/reply packet
        exchange). In normal cases there is a separate SshIkev2Server
        structure for each interface or IP number the server is bound
        to listen. Using SSH_IPADDR_ANY is not recommended, as it
        disturbs Nat-T functionality. If this address is to be used,
        one should know from other source which interface received the
        packet.

        Each SshIkev2Server structure can have a separate policy
        (i.e. a pointer to the SAD interface functions) and
        statistics. The SAD interface function structure pointed by
        this structure is normally shared between multiple or all
        SshIkev2Server structures.

        There is a pointer back to the SshIkev2 structure
        from this context.

   * <B>SshIkev2Sa</B>:
        Each IKEv2 SA is expressed as one SshIkev2Sa structure. The
        actual SshIkev2Sa objects are stored in the Security
        Association Database (SAD), and it takes care of allocating
        and freeing them. It is allocated from the SAD when the SA
        creation starts, and it remains the same until the IKE SA is
        deleted.  If the IKE SA is rekeyed, then the new SshIkev2Sa
        object is allocated, and IPsec SAs from the old IKE SA are
        moved to this new SA.

        It is deleted when requested either by this or the other end
        or if the other end times out. Each IPsec SA is bound to
        exactly one SshIkev2Sa structure, and when the SshIkev2Sa
        structure is deleted, all IPsec SAs bound to it are also
        deleted.

        Each SshIkev2Sa structure has a pointer to one SshIkev2Server
        structure, which is used to find the source IP and port to
        use when sending new exchanges. It does not have a back
        pointer pointing back to the SshIkev2 context, as that can be
        reached through the SshIkev2Server context. The default
        destination addresses of the exchanges are stored in the
        SshIkev2Sa context, but each request packet being processed
        has a separate set of addresses (SshIkev2Server, the other
        end\'s IP and port) that are used when replies are sent back
        (i.e. replies are never sent to the default addresses stored
        in the SshIkev2Sa structure, but always back to the address
        where we got the request).

        These items are reference counted, and in a normal case if
        any callback has this as an argument, the reference is only
        kept during the execution of the callback - thus if callback
        wants to do something more for the structure, it needs to
        take its own reference to object.

   * <B>SshIkev2ExchangeData</B>:
        When an exchange is running, all data related to the exchange
        is stored to this structure. This is actually an obstack, and
        all exchange data pointed from here is also allocated from
        the obstack. This is given to the most of the Policy Manager
        functions, and it can be used to reach ike_sa and other
        required information.
*/

#ifndef SSH_IKEV2_INITIATOR_H
#define SSH_IKEV2_INITIATOR_H
#include "sshaudit.h"
#include "sshudp.h"
#include "sshinet.h"
#include "sshcrypt.h"
#ifdef SSHDIST_EXTERNALKEY
#include "sshexternalkey.h"
#endif /* SSHDIST_EXTERNALKEY */
#include "sshpdbg.h"

#ifdef SSHDIST_IKEV1
#include "isakmp.h"
#endif /* SSHDIST_IKEV1 */


/** Error codes returned by some functions. The error codes
    below 65536 must match the notify message types for the
    notify payload. */
typedef enum {
  SSH_IKEV2_ERROR_OK                    = 0,            /** OK. */
  SSH_IKEV2_ERROR_UNSUPPORTED_CRITICAL_PAYLOAD = 1, /** Unsupported payload. */
  SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION = 5,    /** Invalid major version. */
  SSH_IKEV2_ERROR_INVALID_SYNTAX        = 7,    /** Invalid syntax. */
  SSH_IKEV2_ERROR_NO_PROPOSAL_CHOSEN    = 14,   /** No proposal chosen. */
  SSH_IKEV2_ERROR_INVALID_KE_PAYLOAD    = 17,   /** Invalid KE payload. */
  SSH_IKEV2_ERROR_AUTHENTICATION_FAILED = 24,   /** Authentication failure. */
  SSH_IKEV2_ERROR_INTERNAL_ADDRESS_FAILURE = 36, /** Internal address fail.*/
  SSH_IKEV2_ERROR_TS_UNACCEPTABLE       = 38,          /** TS unacceptable. */
  SSH_IKEV2_ERROR_UNEXPECTED_NAT_DETECTED = 41,        /** Unexpected NAT. */
  SSH_IKEV2_ERROR_TEMPORARY_FAILURE       = 43,        /** Temporary failure.*/
  SSH_IKEV2_ERROR_CHILD_SA_NOT_FOUND      = 44,        /** Child SA not
                                                           found. */
  SSH_IKEV2_ERROR_OUT_OF_MEMORY         = 0x10001,     /** Out of memory. */
  SSH_IKEV2_ERROR_INVALID_ARGUMENT      = 0x10002,     /** Invalid argument.*/
  SSH_IKEV2_ERROR_CRYPTO_FAIL           = 0x10003,     /** Crypto fail. */
  SSH_IKEV2_ERROR_TIMEOUT               = 0x10004,     /** Timeout. */
  SSH_IKEV2_ERROR_XMIT_ERROR            = 0x10005,     /** Xmit error. */
  SSH_IKEV2_ERROR_COOKIE_REQUIRED       = 0x10006,     /** Cookie required. */
  SSH_IKEV2_ERROR_DISCARD_PACKET        = 0x10007,     /** Discard packet. */
  SSH_IKEV2_ERROR_USE_IKEV1             = 0x10008,     /** Use IKEv1. */
  SSH_IKEV2_ERROR_GOING_DOWN            = 0x10009,     /** Error going down.*/
  SSH_IKEV2_ERROR_WINDOW_FULL           = 0x10010,     /** Window full. */
  SSH_IKEV2_ERROR_SA_UNUSABLE           = 0x10011,     /** SA unusable. */
  SSH_IKEV2_ERROR_SUSPENDED             = 0x10012,     /** Policy manager is
                                                           suspended state. */
#ifdef SSHDIST_IKE_REDIRECT
  SSH_IKEV2_ERROR_REDIRECT_LIMIT        = 0x10013,     /** IKE redirect loop
                                                           prevention. */
#endif /* SSHDIST_IKE_REDIRECT */
} SshIkev2Error;

#ifdef SSHDIST_IKE_REDIRECT
typedef enum {
  SSH_IKEV2_REDIRECT_GW_IDENT_IPV4 = 1,
  SSH_IKEV2_REDIRECT_GW_IDENT_IPV6 = 2,
  SSH_IKEV2_REDIRECT_GW_IDENT_FQDN = 3
} SshIkev2RedirectGWIdentType;

#define SSH_IKEV2_REDIRECT_LIMIT 5
#endif /* SSHDIST_IKE_REDIRECT */

/*----------------------------------------------------------------------*/
/** Ikev2 context. */
typedef struct SshIkev2Rec *SshIkev2;

/*----------------------------------------------------------------------*/
/** Server context. */
typedef struct SshIkev2ServerRec *SshIkev2Server;

/*----------------------------------------------------------------------*/
/** IKEv2 SA. */
typedef struct SshIkev2SaRec *SshIkev2Sa;

/*----------------------------------------------------------------------*/
/** Exchange data. */
typedef struct SshIkev2ExchangeDataRec *SshIkev2ExchangeData;

/*----------------------------------------------------------------------*/
/** Packet context. */
typedef struct SshIkev2PacketRec *SshIkev2Packet;

#include "sshsad.h"

/*----------------------------------------------------------------------*/
/** Ikev2 parameters given to the ssh_ikev2_init function and
    copied to the SshIkev2 context structure. */
typedef struct SshIkev2ParamsRec {

  /** UDP context for normal IKE . This is used when creating
      normal UDP sockets. This must stay valid until the
      ssh_ikev2_destroy function is called. */
  SshUdpListenerParams normal_udp_params;

  /** Optional UDP context for NAT-T. This is used when creating
      NAT-T UDP sockets when UDP context for NAT-T is given in
      configuration. Otherwise UDP context for normal IKE is used
      also for NAT-T. This must stay valid until the ssh_ikev2_destroy
      function is called. */
  SshUdpListenerParams nat_t_udp_params;

  /** Forced NAT-T enabled setting. This can be used when an initiator
      wants that a responder always sees a NAT along the path between
      the initiator and the responder. */
  Boolean forced_nat_t_enabled;

  /** Audit context. This used to send audit information. If
      this is NULL then no auditing is done. The audit
      context must stay valid until the ssh_ikev2_destroy
      function is called. */
  SshAuditContext audit_context;

  /** Retry counter limit. Send this many retransmissions before
      timing out. If this is 0, then use the default value of
      10. */
  SshUInt32 retry_limit;

  /** Base retry timer in milliseconds. The base timer is
      doubled after each retransmission until it reaches the
      max timer and then max timer is used for the rest of
      the retransmissions. If this is 0, then use the default
      value of 500 ms. */
  SshUInt32 retry_timer_msec;

  /** Max retry timer in milliseconds. If this is 0, then use
      the default value of 10000 ms. */
  SshUInt32 retry_timer_max_msec;

#ifdef SSHDIST_IKE_MOBIKE
  /** When MobIKE is enabled for a negotiation, the number of
      retransmissions to send before the IKE library requests a new
      address pair. If this is 0, then use the default value of 2. */
  SshUInt32 mobike_worry_counter;
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSHDIST_EXTERNALKEY
  /** External key handle, or NULL if not available. The
      external key context must stay valid until the
      ssh_ikev2_destroy function is called. */
  SshExternalKey external_key;

  /** Short name of the hardware accelerator to be used, or
      NULL if not available. This must stay valid until the
      ssh_ikev2_destroy function is called. */
  const char *accelerator_short_name;
#endif /* SSHDIST_EXTERNALKEY */

  /** Number of packets the system will keep reserved. There
      is no lower/upper limit for packets allocated. Value of
      zero means that the system never frees allocated
      packets, but keeps them all in freelist. */
  SshUInt32 packet_cache_size;

  /** Number of packets the system will allocate on initialization. A
      value of zero means that the system doesa no packet preallocation.
      This value should not be larger than 'packet_cache_size' */
  SshUInt32 packet_preallocate_size;

  /** How often cookie secret is generated in seconds. Default value
      is 5 seconds. Cookie secret should be regenerated every now and
      then to limit DoS attacks, but it should be long enough so that
      peers have time to come back within 2 cookie secret generations
      for their initial IKE_SA_INIT exchange (i.e. round trip time * 2 +
      Diffie-Hellman calculation time). */
  SshUInt32 cookie_secret_timer;

  /** Pointer to debug configuration. */
  SshPdbgConfig debug_config;

#ifdef SSHDIST_IKEV1
  /** Indication that fallback to IKEv1 is desired (e.g. one can
      initiate using v1 and accepts v1 packets as responder (e.g. if
      IKEv1 is attached to the servers) */
  Boolean v1_fallback;
  struct SshIkeParamsRec v1_params[1];

  /** IKEv1 base expire timer in milliseconds. */
  SshUInt32 expire_timer_msec;
#endif /* SSHDIST_IKEV1 */

} SshIkev2ParamsStruct, *SshIkev2Params;

/*----------------------------------------------------------------------*/
/** Initializations */

/** Initialize the IKEv2 library. Return NULL if the
    allocation of the structures fails. If the params is NULL
    (or memset to zero) then use the default parameters. This
    does not allocate the SAD or anything else. */
SshIkev2
ssh_ikev2_create(SshIkev2Params params);

/** Uninitialize the IKEv2 library. This can only be called
    when all servers have been successfully stopped. This
    will free all the data structures associated with the
    IKEv2 library. */
void
ssh_ikev2_destroy(SshIkev2 context);

/*----------------------------------------------------------------------*/
/** Add a new server tied to the ip_address and port values
    to be listened in the IKEv2 library. if ip_address is
    NULL, then tie to IP_ADDR_ANY (this is not recommended).
    If nat_t_*_port is 0, then NAT-T support is disabled. */
SshIkev2Server
ssh_ikev2_server_start(SshIkev2 context,
                       SshIpAddr ip_address,
                       SshUInt16 normal_local_port,
                       SshUInt16 nat_t_local_port,
                       SshUInt16 normal_remote_port,
                       SshUInt16 nat_t_remote_port,
                       int interface_index,
                       int routing_instance_id,
                       SshSADInterface sad_interface,
                       SshSADHandle sad_handle);

/** Close and attempt to reopen UDP listeners for `server'.
    Returns TRUE on success. If this returns FALSE, then this should be
    called again later. */
Boolean
ssh_ikev2_server_restart(SshIkev2Server server,
                         int interface_index);

/*----------------------------------------------------------------------*/
/** Callback to inform that the server has successfully
    stopped itself (i.e. deleted all IKE SA etc) and that
    SshIkev2Server is now deleted from the SshIkev2
    context. */
typedef void (*SshIkev2ServerStoppedCB)(SshIkev2Error error,
                                        void *context);

/** Stop the server. The callback will be called when the
    server has been successfully stopped. Note, that this
    does not send any delete notifications to the other end.
    It simply deletes the SAs locally, and the other end will
    delete the IKE SAs when the DPD notices they are dead. */
void
ssh_ikev2_server_stop(SshIkev2Server server,
                      SshUInt32 flags,
                      SshIkev2ServerStoppedCB server_stopped_cb,
                      void *server_stopped_context);

/*----------------------------------------------------------------------*/
/*  Initiator API for IKE SAs */

/** Callback to return the allocated IKE SA. The reference to
    ike_sa is only valid during the call. You need to take
    your own reference using SSH_IKEV2_IKE_SA_TAKE_REF if you
    need it after this call. */
typedef void
(*SshIkev2IkeSaAllocatedCB)(SshIkev2Error error,
                            SshIkev2Sa ike_sa,
                            void *context);

/** Create IKEv2 SA structure. This does NOT do any
    exchanges, it only allocates the IKEv2 structure, and
    initially binds it to the given remote_ip value. The
    server is used to send outgoing packets (input packets
    are accepted from any server). The algorithms etc. (SA
    information) are requested by the ike_fill_sa policy
    manager function when needed. */
SshOperationHandle
ssh_ikev2_ike_sa_allocate(SshIkev2Server server,
                          SshIpAddr remote_ip,
                          SshUInt32 flags,
                          SshIkev2IkeSaAllocatedCB callback,
                          void *context);

/** If this flag is used in the flags field of
    ssh_ikev2_ike_sa_allocate, then the IKE SA is started directly to
    the NAT-T port instead of the normal port.  This will change the
    format of the packet to be sent (i.e. use non-ESP marker is added)
    and the port to be used. This is not normally needed even when
    working behind NAT, because the IKE library will automatically
    detect the NAT and switch to NAT-T port after detection. */
#define SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_START_WITH_NAT_T        0x0001

/** Disable NAT-T support. */
#define SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_DISABLE_NAT_T           0x0002

#ifdef SSHDIST_IKE_MOBIKE
/** Indicates that the initiator is prepared to support MOBIKE for
    this IKE SA. This will cause a MOBIKE_SUPPORTED notification to be
    sent to the peer in the IKE_AUTH exchange. The resulting IKE SA will
    support MOBIKE if the responder includes the same notification in the
    IKE_AUTH exchange. */
#define SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_USE_MOBIKE              0x0004

/** If NAT-T is disabled, then add the NO_NATS_ALLOWED notification. */
#define SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_NO_NATS_ALLOWED         0x0008
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSHDIST_IKEV1
/** Start SA with IKEv1 */
#define SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1                   0x8000
#endif /* SSHDIST_IKEV1 */

/*----------------------------------------------------------------------*/
/** Generic notify callback. This is called when the
    operation is done. This is used for both IKE SA rekeys,
    IPsec SA create and informational send. */
typedef void
(*SshIkev2NotifyCB)(SshSADHandle sad_handle,
                    SshIkev2Sa ike_sa,
                    SshIkev2ExchangeData ed,
                    SshIkev2Error error);

/*----------------------------------------------------------------------*/
/** Rekey the current IKEv2 SA. The rekey_callback function is called
    when the rekey operation is finished. The algorithms and other SA
    information is requested by the ike_fill_sa Policy Manager
    function when needed. This will take reference to the IKE SA if
    needed, so the caller can free its reference immediately after
    this returns.

    *Note*: this will NOT automatically delete the old IKE SA after it
    has been successfully rekeyed, but the old IKE SA is deleted by
    Policy Manager when IKE library calls the Policy Manager function
    SadIkeSaRekey during this process.

    The IKEv1 SA rekey requires reauthentication, which may need
    Policy Manager intervention - therefore instead of doing rekey one
    should negotiate new IKE and IPsec SA with ssh_ikev2_ipsec_send().

    @param sa
    If 'sa' is IKEv1, this call will fail with error
    SSH_IKEV2_ERROR_INVALID_MAJOR_VERSION.

    */

SshOperationHandle
ssh_ikev2_ike_sa_rekey(SshIkev2Sa sa,
                       SshUInt32 flags,
                       SshIkev2NotifyCB callback);

#define SSH_IKEV2_IKE_REKEY_FLAGS_RESERVED              0x0000

/** Delete the IKEv2 SA. This will call the delete_callback function
    after the SA is actually deleted. This will automatically take
    the references needed to finish the operation.

    @param sa
    If 'sa' is an IKEv1 SA, this will post one delete notification for
    the IKE SA and call the callback. It does not retransmit this
    notify nor will it wait it to be acknowledged. */
SshOperationHandle
ssh_ikev2_ike_sa_delete(SshIkev2Sa sa,
                        SshUInt32 flags,
                        SshIkev2NotifyCB callback);
/** Reserved. */
#define SSH_IKEV2_IKE_DELETE_FLAGS_RESERVED                 0x0000
/** Do not send a delete notification to the other end. */
#define SSH_IKEV2_IKE_DELETE_FLAGS_NO_NOTIFICATION          0x0001

/*----------------------------------------------------------------------*/
#ifdef SSHDIST_IKEV1
/** Force immediate SA deletion */
#define SSH_IKEV2_IKE_DELETE_FLAGS_FORCE_DELETE_NOW         0x0002
#endif /* SSHDIST_IKEV1 */
/*----------------------------------------------------------------------*/

/** Initiator API for IPsec SAs */

/** The information from the packet triggering the creation of the
    IPsec SA. The selectors from here are automatically prepended to
    the actual traffic selectors that are sent to the other end. */
typedef struct SshIkev2TriggeringPacketRec {
  SshIpAddr source_ip;          /** Source IP address. */
  SshIpAddr destination_ip;     /** Destination IP address. */
  SshInetIPProtocolID protocol; /** Protocol. */
  SshUInt16 source_port;        /** Source port. */
  SshUInt16 destination_port;   /** Destination port. */
} *SshIkev2TriggeringPacket, SshIkev2TriggeringPacketStruct;

/** Create an IPsec exchange. This just allocates memory
    structures to store the payloads - the actual operation
    takes place in the ipsec_send function.

    This will take its own reference to the IKE SA, so the caller can
    free his own reference immediately after this returns (or if this
    is called directly from SshIkev2IkeSaAllocatedCB, then there is no
    need to take an extra reference).

    @return
    This will return NULL in case the server is going down or running
    out of memory. */
SshIkev2ExchangeData
ssh_ikev2_ipsec_create_sa(SshIkev2Sa ike_sa,
                          SshUInt32 flags);
#define SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_RESERVED        0x0000

/** Rekey an old SA. This will tell the other end that this exchange
    is a rekey of the old IPsec SA.

    Note that this does not do anything else than store the old SPI
    in the ed->ipsec_ed->rekeyed_spi, and automatically add a
    REKEY_SA notification to be sent to the other end. It does not
    delete the old SA.

    The triggering packet of the ipsec_send will most likely be NULL,
    and the traffic selectors should include everything that was
    included in the old IPsec SA (unless policy has changed). The
    traffic selectors can be wider than from the old SA. The old SPI
    MUST be negotiated using this same IKE SA. */
void ssh_ikev2_ipsec_rekey(SshIkev2ExchangeData ed,
                           SshUInt32 old_spi);

/** Negotiate IPsec SA with the remote host. This will also create
    the IKE SA if it is not yet ready (and this will be the first
    Child SA created at the initial exchange).

    Traffic selector structures must remain constant during the
    exchange and the caller can modify them only after the callback
    done is called. This function does take reference to them, and
    does NOT modify them. Because of its own reference, the caller
    can immediately release its reference if it is not needed
    anymore.

    Use the ssh_ikev2_ts_allocate / ssh_ikev2_ts_item_add /
    ssh_ikev2_ts_free functions to work with traffic selectors.

    The triggering_packet value should contain information from the
    actual packet triggering the creation of this IPsec SA, or NULL
    in case there is no such packet. The information from
    triggering_packet is copied out during this call.

    This call will fail with the SSH_IKEV2_ERROR_WINDOW_FULL error if
    there is no space in the window to start new negotiations
    now. This error will always occur during this call

    @param ed
    If the 'ed' is attached to an IKEv1 SA which needs rekey before
    use, the call will fail with error
    SSH_IKEV2_ERROR_SA_UNUSABLE. */
SshOperationHandle
ssh_ikev2_ipsec_send(SshIkev2ExchangeData ed,
                     SshIkev2TriggeringPacket triggering_packet,
                     SshIkev2PayloadTS tsi_local,
                     SshIkev2PayloadTS tsi_remote,
                     SshIkev2NotifyCB callback);

/** Free the IPsec SA exchange data without starting the
    exchange. */
void
ssh_ikev2_ipsec_exchange_destroy(SshIkev2ExchangeData ed);

/*----------------------------------------------------------------------*/
/** Initiator API for information exchanges */

/** Create informational exchange. This just allocates memory
    structures to store the payloads - the actual operation
    takes place in the info_send function. */
SshIkev2ExchangeData
ssh_ikev2_info_create(SshIkev2Sa ike_sa,
                      SshUInt32 flags);
#define SSH_IKEV2_INFO_CREATE_FLAGS_RESERVED            0x0000

#ifdef SSHDIST_IKE_MOBIKE
/** This info-notify flag is used in MOBIKE to perform return routability
    checks. The IKE library will request the addresses for sending
    the notify using the SshIkev2PadGetAddressPairCB policy call and
    not the address in the IKE SA. */
#define SSH_IKEV2_INFO_CREATE_FLAGS_PROBE_MESSAGE       0x0001

/** This info-notify flag is used in MOBIKE to request additional addresses
    from the policy. The IKE library will request the additional addresses
    for sending the notify using the SshIkev2PadGetAdditionalAddressList
    policy call. */
#define SSH_IKEV2_INFO_CREATE_FLAGS_REQUEST_ADDRESSES   0x0002
#endif /* SSHDIST_IKE_MOBIKE */

/** Add the IPsec SA SPI to be deleted. To delete IKE SAs use
    the ssh_ikev2_ike_sa_delete function. This can be called
    as many times as liked, and it will create necessary
    delete payloads having all SPIs. The spi_array value is
    copied during this call. */
SshIkev2Error
ssh_ikev2_info_add_delete(SshIkev2ExchangeData ed,
                          SshIkev2ProtocolIdentifiers protocol_id,
                          int number_of_spis,
                          const SshUInt32 *spi_array,
                          SshUInt32 flags);

/** Add notification payload to informational exchange. All
    data is copied during this call. */
SshIkev2Error
ssh_ikev2_info_add_n(SshIkev2ExchangeData ed,
                     SshIkev2ProtocolIdentifiers protocol_id,
                     const unsigned char *spi,
                     size_t spi_size,
                     SshIkev2NotifyMessageType
                     notify_message_type,
                     const unsigned char *notification_data,
                     size_t notification_data_size);

/** Add configuration payload to informational exchange. You
    can only send one of these during the exchange. This call
    will take the reference to the conf_payload value, and
    free the reference when it is no longer needed. */
SshIkev2Error
ssh_ikev2_info_add_conf(SshIkev2ExchangeData ed,
                        SshIkev2PayloadConf conf_payload);

#ifdef SSHDIST_IKE_MOBIKE
/** Force the informational exchange to use the specified server, remote IP
    address and remote port. */
void
ssh_ikev2_info_use_addresses(SshIkev2ExchangeData ed,
                             SshIkev2Server server,
                             Boolean use_natt,
                             SshIpAddr remote_ip,
                             SshUInt16 remote_port);
#endif /* SSHDIST_IKE_MOBIKE */

#ifdef SSHDIST_IKE_XAUTH

/** Add IKEv1 extented authentication request to informational
    exchange. This exchange will be executed when the actual IKEv1 SA
    has been completed. */
SshIkev2Error
ssh_ikev2_info_add_xauth(SshIkev2ExchangeData ed);

#endif /* SSHDIST_IKE_XAUTH */

/** Encode and send the informational exchange. The notification
    callback will be called when the other end replies (or with an
    error code if it times out). This will also free the exchange
    data when the operation is done.

    @param ed
    If 'ed' is attached to an IKEv1 SA this will send the
    notification once and call the callback, except when the
    notification payload is empty. In this case DPD with natural
    retransmissions is performed, followed by optional trial to
    create new IKE SA with the peer. */
SshOperationHandle
ssh_ikev2_info_send(SshIkev2ExchangeData ed,
                    SshIkev2NotifyCB callback);

/** Free the exchange data without sending the informational
    notification. */
void
ssh_ikev2_info_destroy(SshIkev2ExchangeData ed);

#ifdef SSHDIST_IKE_MOBIKE
/*  Initiator API for Mobike IKE exchanges. */

/** Sets the server, remote_ip, remote_port in the IKE SA 'sa'. This
    clears the address_index counter in 'sa', which means the next
    time an address is needed it is taken from the IKE SA and the
    policy function SshIkev2PadGetAddressPair will not be called. */
SshIkev2Error
ssh_ikev2_ike_sa_change_addresses(SshIkev2Sa sa,
                                  SshIkev2Server server,
                                  SshIpAddr remote_ip,
                                  SshUInt16 remote_port,
                                  SshUInt32 flags);

/** This flag indicates that the local end of the updated IKE SA is
    behind NAT. */
#define SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_LOCAL_BEHIND_NAT  0x0001

/** This flag indicates that the remote end of the updated IKE SA is
    behind NAT. */
#define SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REMOTE_BEHIND_NAT 0x0002

/** This flag indicates that the next exchange should request addresses
    from policy manager. When this flag is specified the arguments `server',
    `remote_ip' and `remote_port' are ignored in
    ssh_ikev2_ike_sa_change_addresses(). */
#define SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_REQUEST_ADDRESSES 0x0004

/** This flag indicates that the next exchange should request addresses
    from policy manager start using the next address pair index. When this
    flag is specified the arguments `server', `remote_ip' and `remote_port'
    are ignored in ssh_ikev2_ike_sa_change_addresses(). */
#define SSH_IKEV2_IKE_SA_CHANGE_ADDRESSES_FLAGS_NEXT_ADDRESS_PAIR 0x0008

#endif /* SSHDIST_IKE_MOBIKE */


/** Takes a reference to an exchange data structure with the IKE
    library. On a typical case the initiator application allocates
    the exchange data and gives its reference to the IKEv2
    library. If the application wishes to abort this exchange, it
    needs to take a reference for the abort operation for itself.
    If it does not store a copy of exchange data, there is no need
    for taking a reference either.

    Aborting the operation consumes the taken reference. If the
    operation is not aborted, the application needs to give up the
    reference.

    @see ssh_ikev2_exchange_data_free

    */
void ssh_ikev2_exchange_data_take_ref(SshIkev2ExchangeData ed);

/** Frees a reference to an exchange data strucure with the IKE
    library.

    @see ssh_ikev2_exchange_data_take_ref

    */
void ssh_ikev2_exchange_data_free(SshIkev2ExchangeData ed);


/*----------------------------------------------------------------------*/
/** Callback to inform that the library has successfully
    suspended itself. */
typedef void (*SshIkev2SuspendedCB)(void *context);

/** Suspends IKEv2 library. This makes it so that it does not
    process incoming packets anymore, and it also suspends
    internal processing of the ike library. The main reason is
    try to limit number of policy calls library might make to the
    policy manager. It does not prevent them completely, as
    timeouts, asyncronous crypto operations or CMI operations,
    etc are suspended, meaning if those return then ike library
    might call policy manager still. As most of the calls will be
    suspended, that means those few calls that might be called
    can safely be failed with SSH_IKEV2_ERROR_SUSPENDED, which
    will cause those few IKE SAs to fail.

    This will call the callback when suspend is done (this is
    fast operation, but it wants to make sure there is no IKEv2
    operations in the call stack and calls the callback from the
    bottom of event loop. This call cannot be called if ikev2
    library is already in suspended state (i.e. it cannot be
    called twice without the library being resumed between. */

void ssh_ikev2_suspend(SshIkev2 context,
                       SshUInt32 flags,
                       SshIkev2SuspendedCB suspended_cb,
                       void *suspended_context);

/** Resume IKEv2 library after suspend. This can only be called
    when library has first been suspended and suspended callback
    has been called. After this library is again in normal
    running state. This will also start processing all of the
    packets which were queued during the suspend. */

void ssh_ikev2_resume(SshIkev2 context);

#endif /* SSH_IKEV2_INITIATOR_H */
