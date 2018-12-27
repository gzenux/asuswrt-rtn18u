/**
   @copyright
   Copyright (c) 2005 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 exchange structures.
*/

#ifndef SSH_IKEV2_EXCHANGE_H
#define SSH_IKEV2_EXCHANGE_H

#include "sshobstack.h"
#include "sshfsm.h"
#include "sshadt_bag.h"

#ifdef SSHDIST_IKEV1
/** The handle to Policy Manager that implements IKEv1
    fallback functionality. */
typedef struct SshIkev2FbRec *SshIkev2Fb;

#ifdef SSHDIST_IKE_XAUTH
typedef void (*SshIkev2FbXauthServerDone)(SshIkev2Error status,
                                          void *callback_context);
#endif /* SSHDIST_IKE_XAUTH */
#endif /* SSHDIST_IKEV1 */

/** The length of the cookie secret. */
#define IKEV2_COOKIE_SECRET_LEN 32

/** Keep IKE SAs after IKE SA delete for this many seconds. */
#define IKEV2_SA_KEEP_TIME      30

#ifdef SSHDIST_EXTERNALKEY
/** Contexts for the ssh_ek_generate_accelerated_group
    operation. */
typedef struct SshIkev2EkGroupContextRec *SshIkev2EkGroupContext;
#endif /* SSHDIST_EXTERNALKEY */

/*----------------------------------------------------------------------*/
/** SshIkev2 context structure.                                         */
/*----------------------------------------------------------------------*/
struct SshIkev2Rec {
  /** Parameters given to ssh_ikev2_init. */
  SshIkev2ParamsStruct params;

  /** List of SshIkev2Servers. */
  SshADTContainer server_list;

  /** Intmap from group id to SshPkGroup - this map can be
      updated by adding new entries to it, and replacing old
      entries with accelerated ones, but all entries that have ever
      been here MUST stay valid as long as the IKEv2 context
      is valid. */
  SshADTContainer group_intmap;

  /** Map from the initiator SPI to the full SPI - the
      structures in this container are of type
      SshIkev2Half. */
  SshADTContainer sa_half_by_spi;

  /** Packet storage - this is kept in freelist, and has a preferred
      maximum size (e.g. one may have more, but the system will keep
      the preferred number on freelist after the peak goes over). */
  SshADTContainer packets_free;
  /** Packet storage - this is kept in freelist, and has a preferred
      maximum size (e.g. one may have more, but the system will keep
      the preferred number on freelist after the peak goes over). */
  SshADTContainer packets_used;

  /** The version number of the cookie. */
  SshUInt32 cookie_version_number;
  /** Cookie generation secret. */
  unsigned char cookie_secret[IKEV2_COOKIE_SECRET_LEN];
  SshUInt32 cookie_secret_use_counter;
  unsigned char cookie_secret_prev[IKEV2_COOKIE_SECRET_LEN];
  SshUInt32 cookie_secret_use_counter_prev;
  /** Counter to specify if the cookie needs to be regenerated. */
  SshTime cookie_secret_created;

  /** Global FSM structure used by the IKE library. */
  SshFSMStruct fsm[1];

  /** Hash used in the window code to calculate the packet
      hashes used when comparing if this is retransmission. */
  SshHash hash;

#ifdef SSHDIST_EXTERNALKEY
  /** Group contexts for the acceleration process. */
  SshIkev2EkGroupContext ek_group_contexts;
#endif /* SSHDIST_EXTERNALKEY */

  /** Timeout to handle various issues that might require low
      granularity timers (cleanups and such). */
  SshTimeoutStruct timeout[1];

#ifdef SSHDIST_IKEV1
  /** IKEv1 fallback policy manager */
  SshIkev2Fb fallback;
#endif /* SSHDIST_IKEV1 */

  /** IKEv2 library is in suspended state. */
  Boolean ikev2_suspended;
};
typedef struct SshIkev2Rec SshIkev2Struct;


/*-------------------------------------------------------------------------*/
/** SshIkev2GlobalStatistics structure. All statistics are since the IKE   */
/** server was started.                                                    */
/** This needs to be kept in sync with SshIkeGlobalStatistics at IKEv1 lib.*/
/*-------------------------------------------------------------------------*/

typedef struct SshIkev2GlobalStatisticsRec {
  /** The total number of successful IKE SAs since the server was
      started - the IKE SA is attributed to whichever server it is on
      when the exchange finishes. */
  SshUInt32 total_ike_sas;
  SshUInt32 total_ike_sas_initiated;  /** Total number of IKE SAs, initiated.*/
  SshUInt32 total_ike_sas_responded;  /** Total number of IKE SAs, responded.*/

  /*  Attempts (includes failures and attempts in progress) -
      this records the server where the negotiation started,
      and also includes retries with cookie, and proper group
      as new attempts for the responded case (as the
      responder forgets everything about those attempt). */
  SshUInt32 total_attempts;            /** Total number attempted. */
  SshUInt32 total_attempts_initiated;  /** Total number attempted, initiated.*/
  SshUInt32 total_attempts_responded;  /** Total number attempted, responded.*/

  /* Total packet counts, including retransmissions. */
  SshUInt32 total_packets_in;          /** Total number of packets in. */
  SshUInt32 total_packets_out;         /** Total number of packets out. */
  SshUInt32 total_octets_in;           /** Total number of octets in. */
  SshUInt32 total_octets_out;          /** Total number of octets out. */
  SshUInt32 total_retransmits;         /** Total number of
                                           retransmitted packets.  */
  SshUInt32 total_discarded_packets;   /** Total number of packets
                                           discarded because IKEv2 library
                                           was suspended when it was
                                           received. */
  /* Failures, no responses etc. */

  SshUInt32 total_init_failures;       /** The total number of
                                           negotiations we
                                           initiated, that failed
                                           because of an error. */
  SshUInt32 total_init_no_response;    /** The total number of
                                           negotiations we
                                           initiated, that
                                           failed because of an
                                           initial timeout. */
  SshUInt32 total_resp_failures;       /** The total number of
                                           negotiations we
                                           responded to, that
                                           failed because of
                                           an error. */

  /* Current number of IKE SAs. */

  SshUInt32 current_ike_sas;            /** The number of IKE SAs. */
  SshUInt32 current_ike_sas_initiated;  /** The number of IKE SAs, initiated.*/
  SshUInt32 current_ike_sas_responded;  /** The number of IKE SAs, responded.*/

} *SshIkev2GlobalStatistics, SshIkev2GlobalStatisticsStruct;

/*----------------------------------------------------------------------*/
/** SshIkev2Server context structure.                                   */
/** This needs to be kept in sync with SshIkeServerContext at IKEv1 lib.*/
/*----------------------------------------------------------------------*/

struct SshIkev2ServerRec {
  /** ADT list header for server_list. */
  SshADTListHeaderStruct server_list_header;

  /** Routing instance id. */
  int routing_instance_id;
  /** Interface index. */
  int interface_index;
  /** IP address. */
  SshIpAddrStruct ip_address[1];
  /** Normal local port. */
  SshUInt16 normal_local_port;
  /** NAT-T local port. */
  SshUInt16 nat_t_local_port;
  /** Normal remote port. */
  SshUInt16 normal_remote_port;
  /** NAT-T remote port. */
  SshUInt16 nat_t_remote_port;
  /** Original normal local port. */
  SshUInt16 original_normal_local_port;
  /** Original NAT-T local port. */
  SshUInt16 original_nat_t_local_port;

  /** Interface function pointer structure. */
  SshSADInterface sad_interface;

  /** SAD handle. */
  void *sad_handle;

  /** Statistics. */
  SshIkev2GlobalStatisticsStruct statistics[1];

  /** Back pointer to the SshIkev2 and IKEv2 context. */
  SshIkev2 context;
  void *isakmp_context;

  /** UDP listener for normal IKE SA packets. */
  SshUdpListener normal_listener;

  /** UDP listener for NAT-T IKE SA packets. */
  SshUdpListener nat_t_listener;

  /** Forced NAT-T enabled. */
  Boolean forced_nat_t_enabled;

  /** Callback for stopping - this is here so that we do not need
      to allocate anything that could cause the stop to fail
      when a stop is called. */
  SshIkev2ServerStoppedCB server_stopped_cb;
  void *server_stopped_context;

#define SSH_IKEV2_SERVER_STOPPED_1    0x4000000L
#define SSH_IKEV2_SERVER_STOPPED_2    0x8000000L

  SshUInt32 server_stopped_flags;
  int server_stopped_counter;

  /* v1 only */
  void *pm;           /* SAD handle. */
  void *sa_callback;
  void *sa_callback_context;
};
typedef struct SshIkev2ServerRec SshIkev2ServerStruct;

#ifdef SSHDIST_IKE_EAP_AUTH
/** EAP state. */
typedef enum {
  SSH_IKEV2_NO_EAP  = 0,       /** EAP not enabled. */
  SSH_IKEV2_EAP_STARTED = 1,   /** EAP initialized. */
  SSH_IKEV2_EAP_1ST_DONE = 2,  /** First packet with EAP payload sent. */
  SSH_IKEV2_EAP_DONE = 3       /** EAP library has signalled completion. */
} SshIkev2EapState;
#endif /* SSHDIST_IKE_EAP_AUTH */


/*----------------------------------------------------------------------*/
/** SshIkev2SaExchangeData structure -
    this is the IKEv2 IKE SA specific exchange data, only
    needed when IKE_SA_INIT or IKE_AUTH exchanges are in
    progress.                                                           */
/*----------------------------------------------------------------------*/
typedef struct SshIkev2SaExchangeDataRec {
  /* Some fields that might be useful to Policy Manager. */
  /** Initiator ID payload from the IKE_AUTH (from obstack). */
  SshIkev2PayloadID id_i;
  /** Responder ID payload from the IKE_AUTH (from obstack). */
  SshIkev2PayloadID id_r;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /** Responder ID payload from the IKE_AUTH (from obstack). */
  SshIkev2PayloadID second_id_i;

  /** Boolean to indicate if we are running the second EAP-authentication */
  Boolean second_eap_auth;
  /* Our negotiation peer supports multiple authentications */
  unsigned int peer_supports_multiple_auth : 1;
  /* We have verified our IKE-peer's first auth payload */
  unsigned int first_auth_verified : 1;
  /* First authentication is completely done */
  unsigned int first_auth_done : 1;

  /* As responder, require second IKE-authentication */
  unsigned int resp_require_another_auth : 1;
  /* As initiator, prepare to initiate second IKE-authentication */
  unsigned int init_another_auth_follows : 1;

  /** Counter for the multiple authentications. First authentication
      is marked 1. */
  SshUInt32 authentication_round;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /** The original SA payload we sent to the other end (initiator
      only) - this is a reference count and not allocated from
      obstack. */
  SshIkev2PayloadSA sa_i;

#ifdef SSHDIST_IKE_CERT_AUTH
  /** The end entity certificate for the remote peer (from
      obstack) - the IKEv2 library does not need this, it is
      stored here for Policy Manager. */
  SshIkev2PayloadCert ee_cert;
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_IKEV1
  /** IKEv1 IKE SA lifetime in seconds - this is not used for IKEv2 SA;
      value 0 indicates the default of 8 hours. */
  SshUInt32 sa_life_seconds;

  /** IKEv1 exchange type - for initiator filled by Policy Manager,
      and for the responder filled by the fallback module. */
  SshIkeExchangeType exchange_type;

  /** IKEv1 authentication method, filled by the IKEv1 fallback
      module - used by Policy Manager to select the proper private key
      to authenticate this end, and the proper public key to authenticate
      the peer.  */
  SshIkeAttributeAuthMethValues auth_method;
#endif /* SSHDIST_IKEV1 */


  /*----------------------------------------------------------------------*/
  /* The rest of the fields are mostly IKE library internals, so of
     no interest to Policy Manager.                                      */
  /*----------------------------------------------------------------------*/

  /*  The local part of the Diffie-Hellman secret. */
  SshPkGroup group;             /** A pointer to a global group. */
  SshUInt16 group_number;       /** The number of the group above. */
  SshPkGroupDHSecret dh_secret;

  /** Exchange buffer from obstack. */
  const unsigned char *exchange_buffer;
  /** Exchange buffer length. */
  size_t exchange_buffer_len;

#ifdef SSHDIST_IKE_CERT_AUTH
  /** Private key of the local end. */
  SshPrivateKey private_key;

  /** Public key of the remote end. */
  SshPublicKey public_key;
#endif /* SSHDIST_IKE_CERT_AUTH */

  /** Authentication payload for the remote peer (from obstack). */
  SshIkev2PayloadAuth auth_remote;

#ifdef SSH_IKEV2_MULTIPLE_AUTH
  /** Second authentication payload from the remote peer */
  SshIkev2PayloadAuth second_auth_remote;
#endif /* SSH_IKEV2_MULTIPLE_AUTH */

  /** Temporary data used while waiting for the signature operation to
      finish; mallocated. */
  unsigned char *data_to_signed;
  /** The length of the data to be signed. */
  size_t data_to_signed_len;

#ifdef SSHDIST_IKE_EAP_AUTH
  /** EAP state information. */
  SshIkev2EapState eap_state;
#endif /* SSHDIST_IKE_EAP_AUTH */

  /** Local authenticated packet, meaning that the last IKE_SA_INIT
      packet we sent out, and which will be included in the
      AUTH payload (from obstack). */
  unsigned char *local_ike_sa_init;
  /** The length of the local authenticated packet. */
  size_t local_ike_sa_init_len;

  /** Remote authenticated packet, meaning that the last IKE_SA_INIT
      packet the other end has sent to us - it will be incldued in
      the remote end's AUTH payload (from obstack). */
  unsigned char *remote_ike_sa_init;
  /** The length of the remote authenticated packet. */
  size_t remote_ike_sa_init_len;

  /** Nonce payload from the IKE_SA_INIT (from obstack). */
  SshIkev2PayloadNonce ni;
  /** Nonce payload from the IKE_SA_INIT (from obstack). */
  SshIkev2PayloadNonce nr;

  /** Cookie we have sent/received to/from the other end
      (allocated from the obstack). */
  unsigned char *cookie;
  /** The length of the transmitted cookie. */
  size_t cookie_len;

  /** Reply from the select_ike_sa call. */
  SshIkev2PayloadTransform ike_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];

} *SshIkev2SaExchangeData, SshIkev2SaExchangeDataStruct;

/*----------------------------------------------------------------------*/
/** SshIkev2SaIPsecSaExchangeData structure.
    This is the IKEv2 IPsec SA specific exchange data, only
    needed when IKE_IKE_AUTH exchanges or CREATE_CHILD_SA are
    in progress.  */
typedef struct SshIkev2IPsecSaExchangeDataRec {
  /* Some fields that might be useful to Policy Manager. */
  /** Inbound SPI for this connection - Policy Manager should use
      this when installing the SA. */
  SshUInt32 spi_inbound;
  /** Outbound SPI for this connection - Policy Manager should use
      this when installing the SA. */
  SshUInt32 spi_outbound;

  /** SPI of the rekeyed old SA - if set to 0, then no rekey is made;
      this is the old SPI that this SA is replacing; for the
      initiator this is the SPI we are sending out
      (initiator's inbound_spi); for the responder it is what
      we received from the other end, meaning the initiator's
      inbound SPI (the responder's outbound SPI). */
  SshUInt32 rekeyed_spi;

  /** Protocol identifier of rekeyed old SPI. To be ignored when
      rekeyed_spi is 0.
   */
  SshIkev2ProtocolIdentifiers rekeyed_protocol;

  /** Local TS payload for the local end for the IKE_AUTH or
      CREATE_CHILD - these are reference counted, and not
      allocated from obstack; when we are initiating, they
      first contain our proposals, and when we get the final
      narrowed traffic selectors, they are replaced with the
      final traffic selectors; for the responder these are
      the final traffic selectors after they have been
      narrowed; this should be used by Policy Manager
      to get the final traffic selectors. */
  SshIkev2PayloadTS ts_local;
  /** Remote TS payload. */
  SshIkev2PayloadTS ts_remote;

  /** Reply from the select_ipsec_sa call - these are the final
      algorithms selected in both ends, and Policy Manager
      should use this to get the algorithms when installing
      the SA. */
  SshIkev2PayloadTransform ipsec_sa_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];
  SshIkev2ProtocolIdentifiers ipsec_sa_protocol;

#ifdef SSHDIST_IKEV1
  /** IKEv1 IPsec SA lifetime value in seconds - this is not used with
      IKEv2; value zero indicates the default of 8 hours. */
  SshUInt32 sa_life_seconds;
  /** IKEv1 IPsec SA lifetime values in kilobytes - this is not used with
      IKEv2; value zero indicates that life attribute is not sent. */
  SshUInt32 sa_life_kbytes;
#endif /* SSHDIST_IKEV1 */

  /*----------------------------------------------------------------------*/
  /*  The rest of the fields are internal to the IKE library, so of
      no interest to Policy Manager. */

  /** Original SA payload we sent to the other end (initiator
      only) - this is reference counted and not allocated from
      obstack. */
  SshIkev2PayloadSA sa_i;

  /** SA payload from the responder - this will contain the
      actual algorithms; this is only used by the IKE
      library - Policy Manager should not use this, but use
      ipsec_sa_transforms instead when getting the algorithms. */
  SshIkev2PayloadSA sa;

  /*  The local part of the Diffie-Hellman secret - only used in
      the CREATE_CHILD_SA exchange. */
  SshPkGroup group;             /** Pointer to global group. */
  SshUInt16 group_number;       /** Number of the global group. */
  SshPkGroupDHSecret dh_secret;

  /** Exchange buffer from obstack. */
  const unsigned char *exchange_buffer;
  size_t exchange_buffer_len;

  /** Final shared secret from obstack. */
  unsigned char *shared_secret_buffer;
  /** Length of shared secret. */
  size_t shared_secret_buffer_len;

  /** Nonce payload from CREATE_CHILD_SA (from obstack). */
  SshIkev2PayloadNonce ni;
  /** Nonce payload from CREATE_CHILD_SA (from obstack). */
  SshIkev2PayloadNonce nr;

  /** TS payload from the remote end for IKE_AUTH or
      CREATE_CHILD - these are reference counted, and not
      allocated from obstack; these are used during the
      exchange to store the traffic selectors received;
      only the IKE library should touch these. */
  SshIkev2PayloadTS ts_i;
  /** TS payload. */
  SshIkev2PayloadTS ts_r;

  /** IPsec flags. */
  SshUInt32 flags;
#define SSH_IKEV2_IPSEC_CREATE_SA_FLAGS_INITIATOR (0x0001 << 16)
#define SSH_IKEV2_IPSEC_REKEY_IKE (0x0002 << 16)
#define SSH_IKEV2_IPSEC_OPERATION_REGISTERED (0x0004 << 16)
#define SSH_IKEV2_IPSEC_USE_TRANSPORT_MODE_TS (0x0008 << 16)

  /** Top level operation handle. If this is registerered, then
      there is also one reference to the IKE SA and the flags
      have SSH_IKEV2_IPSEC_OPERATION_REGISTERED bit on. When
      operation is unregistered and reference freed, then the
      SSH_IKEV2_IPSEC_OPERATION_REGISTERED bit is cleared from the
      flags.*/
  SshOperationHandleStruct operation_handle[1];

  /** Triggering packet source IP - data is allocated from obstack. */
  SshIpAddr source_ip;
  /** Triggering packet destination IP - data is allocated from obstack. */
  SshIpAddr destination_ip;
  /** Triggering packet protocol - data is allocated from obstack. */
  SshInetIPProtocolID protocol;
  /** Triggering packet source port - data is allocated from obstack. */
  SshUInt16 source_port;
  /** Triggering packet destination port - data is allocated from obstack. */
  SshUInt16 destination_port;

  /** NAT-T original addresses. */
  SshIpAddrStruct natt_oa_l;
  SshIpAddrStruct natt_oa_r;

  /** New IKE SA for this IKE SA rekey - otherwise this is NULL. */
  SshIkev2Sa new_ike_sa;

  /** Error code of the initial IPsec SA creation inside the
      initial IKE SA creation - we have a separate error code
      here, so we will succeed creating the IKE SA but fail
      the child SA. */
  SshIkev2Error error;

#ifdef SSHDIST_IKEV1
  /** IKEv1 generated keying material. */
  unsigned char *ikev1_keymat;
  /** Keying material length. */
  size_t ikev1_keymat_len;
#endif /* SSHDIST_IKEV1 */

} *SshIkev2IPsecSaExchangeData, SshIkev2IPsecSaExchangeDataStruct;

/*----------------------------------------------------------------------*/
/* SshIkev2InfoSaExchangeDataRec structure.                             */

/** This is the IKEv2 Info exchange specific exchange data, only
    needed when an INFORMATIONAL exchange is in progress.  */
typedef struct SshIkev2InfoSaExchangeDataRec {
  /** Info flags. */
  SshUInt32 flags;
#define SSH_IKEV2_INFO_CREATE_FLAGS_INITIATOR (0x0001 << 16)
#ifdef SSHDIST_IKE_XAUTH
#define SSH_IKEV2_INFO_CREATE_FLAGS_XAUTH     (0x0002 << 16)
#endif /* SSHDIST_IKE_XAUTH */
#define SSH_IKEV2_INFO_OPERATION_REGISTERED   (0x0004 << 16)
#define SSH_IKEV2_INFO_EMPTY_RESPONSE         (0x0008 << 16)
#define SSH_IKEV2_INFO_COOKIE2_ADDED          (0x0010 << 16)
#define SSH_IKEV2_INFO_NAT_D_ADDED            (0x0020 << 16)
#define SSH_IKEV2_INFO_NO_NATS_ALLOWED_ADDED  (0x0040 << 16)

  /** Top-level operation handle. If this is registerered, then
      there is also one reference to the IKE SA and the flags
      have SSH_IKEV2_INFO_OPERATION_REGISTERED bit on. When
      operation is unregistered and reference freed, then the
      SSH_IKEV2_INFO_OPERATION_REGISTERED bit is cleared from the
      flags. */
  SshOperationHandleStruct operation_handle[1];

  /** Configuration payload to be added - this is reference
      counted, and not allocated from obstack. */
  SshIkev2PayloadConf conf;

  /** Linked list of notify payloads to be sent out,
      allocated from obstack. */
  SshIkev2PayloadNotify notify;

  /** Linked list of delete payloads to be sent out,
      allocated from obstack. */
  SshIkev2PayloadDelete del;

#ifdef SSHDIST_IKE_MOBIKE
  /** Forced server, remote IP and remote port for informational exchange. */
  SshIpAddrStruct forced_remote_ip[1];
  SshUInt16 forced_remote_port;
  SshIkev2Server forced_server;
  unsigned int forced_use_natt : 1;

  /** For MobIKE enabled SA's this parameter indicates if a NAT
      has been detected between the address pair used for the exchange. This
      parameter only indicates the presence of NAT between the address pair
      used for this exchange, and not for the addresses in the IKE SA. */
  unsigned int  local_end_behind_nat : 1;

  /** For MobIKE enabled SA's this parameter indicates if a NAT
      has been detected between the address pair used for the exchange. This
      parameter only indicates the presence of NAT between the address pair
      used for this exchange, and not for the addresses in the IKE SA. */
  unsigned int remote_end_behind_nat : 1;

  /** For MobIKE enabled SA's this parameter indicates that on responder
      the NO_NATS_ALLOWED notify verification resulted into
      UNEXPECTED_NAT_DETECTED, and thus the UPDATE_SA_ADDRESSES notify
      should be ignored. */
  unsigned int unexpected_nat_detected : 1;

  /** The number of octets sent by the initiator in COOKIE2 payloads. */
#define IKEV2_INFO_COOKIE2_SIZE 32
  unsigned char cookie2[IKEV2_INFO_COOKIE2_SIZE];

#endif /* SSHDIST_IKE_MOBIKE */
} *SshIkev2InfoSaExchangeData, SshIkev2InfoSaExchangeDataStruct;

/** Current state of the exchange, i.e. what packet we are processing. */
typedef enum {
  SSH_IKEV2_STATE_IKE_INIT_SA,
  SSH_IKEV2_STATE_IKE_AUTH_1ST,
#ifdef SSHDIST_IKE_EAP_AUTH
  SSH_IKEV2_STATE_IKE_AUTH_EAP,
#endif /* SSHDIST_IKE_EAP_AUTH */
  SSH_IKEV2_STATE_IKE_AUTH_LAST,
  SSH_IKEV2_STATE_CREATE_CHILD,
  SSH_IKEV2_STATE_REKEY_IKE,
  SSH_IKEV2_STATE_INFORMATIONAL,
  SSH_IKEV2_STATE_INFORMATIONAL_DELETING
} SshIkev2State;

/*----------------------------------------------------------------------*/
/** SshIkev2ExchangeData structure.
    This structure is associated with each exchange. It is
    allocated in the initiator when the exchange is started,
    and it is stored to the packet during the processing of
    an outgoing packet. When the reply packet comes in, the same
    exchange data is associated with the incoming packet that
    was given out with the outgoing packet.

    For the responder side this is allocated when the packet
    is received, and it is freed after the packet is sent out
    (if still set in the packet structure). In this structure
    there is an exchange-specific data structure (allocated from
    obstack), which is used for storing the exchange-specific
    information. */
struct SshIkev2ExchangeDataRec {
#ifdef DEBUG_LIGHT
  SshUInt32 magic;
#define SSH_IKEV2_ED_MAGIC 0x012d857a
#endif /* DEBUG_LIGHT */

  SshUInt8 ref_cnt;

  /*  Some fields that might be useful to Policy Manager. */

  /** Obstack used to store all information related to
      the exchange, including this structure. */
  SshObStackContext obstack;

  /** Generic state of the exchange. */
  SshIkev2State state;

  /** Pointer back to the IKE SA. */
  SshIkev2Sa ike_sa;

#ifdef SSHDIST_IKE_MOBIKE
  /** The IP addresses in the header of the last received packet.
      These should be used by the policy application for updating the
      IKE SA when an ADDRESS_UPDATE notification is received. The application
      can also use these addresses for detecting if an IKE packet is received
      on an address pair other than that currently used by the IKE SA. */
  SshIpAddrStruct remote_ip[1];
  /** The ports in the header of the last received packet. */
  SshUInt16 remote_port;
  SshIkev2Server server;

  /** Set if this exchange has used more than one different address pair
      for sending packets. When sending each new packet it is checked
      if the addresses are the same as the previous addresses used to
      send on this exchange. If the addresses have changed, the
      multiple_addresses_used field is set.

      The field must be checked by the application after the
      exchange is completed and if set, an ADDRESS_UPDATE
      informational exchange should be initiated. */
  unsigned int multiple_addresses_used : 1;
#endif /* SSHDIST_IKE_MOBIKE */

  /** IKE_SA_INIT and IKE_AUTH specific exchange data. */
  SshIkev2SaExchangeData ike_ed;

  /** CREATE_CHILD_SA or the initial IPsec SA specific exchange
     data. */
  SshIkev2IPsecSaExchangeData ipsec_ed;

  /** INFORMATIONAL exchange-specific exchange data. */
  SshIkev2InfoSaExchangeData info_ed;

  /** Application context pointer - the application using the library
      may use this for its own purposes; the IKEv2 library does not
      access this resource; exchange data allocate and free are
      supposed to handle memory management for this. */
  void *application_context;

  /** Notification payloads received for this exchange - all
      notification payloads associated with the exchange are
      collected here as a list (from obstack). */
  SshIkev2PayloadNotify notify;

  /** The number of notify payloads in the last inbound packet -
      the notifications are in the beginning of the notify
      list; this is used to distinguish the notifies received
      in the last packet from the ones received before. */
  SshUInt32 notify_count;

  /** Delete payloads received for this exchange - all delete
      payloads associated with the exchange are collected
      here as a list (from obstack). */
  SshIkev2PayloadDelete delete_payloads;

  /** Vendor ID payloads received for this exchange - all VID
      payloads associated with the exchange are collected
      here as a list (from obstack). */
  SshIkev2PayloadVendorID vid;

  /** Configuration payload for this exchange - this is reference
      counted, and not allocated from obstack. */
  SshIkev2PayloadConf conf;

  /*----------------------------------------------------------------------*/
  /*  The rest of the fields are internal to the IKE library, so of
      no interest to Policy Manager. */

  /** Packet waiting to be processed after async call. */
  SshIkev2Packet packet_to_process;

  /** Operation handle for the operation currently in progress. */
  SshOperationHandle operation;

  /** Zero timeout used to delete the IKE SA and skeyseed calculation
      - one at a time. */
  SshTimeoutStruct timeout[1];

  /** Next payload offset (-1 == first_payload). */
  int next_payload_offset;

  /** Buffer where to encode packet. */
  SshBuffer buffer;

  /** Remote SA payload received inside IKE_AUTH or
      CREATE_CHILD_SA - this is reference counted, and not
      allocated from obstack. */
  SshIkev2PayloadSA sa;

  /** Remote key exchange payloads from the CREATE_CHILD
      (from obstack). */
  SshIkev2PayloadKE ke;

  /** Received nonce payload (from obstack). */
  SshIkev2PayloadNonce nonce;

#ifdef SSHDIST_IKE_REDIRECT
  SshIpAddrStruct redirect_addr[1]; /* used by both initiator and responder */
  Boolean         redirect_supported; /* Redirect support announced */
  Boolean         redirect;         /* responder will redirect */
#endif /* SSHDIST_IKE_REDIRECT */

  /** Done callback, shared for ike_sa rekey, informational
      exchange, IPsec create child and IKE SA delete. This is
      set if we are initiator and there is callback to be called.
      After we call this we set it to NULL_FNPTR so it will not
      get called twice even if there is some error after that. */
  SshIkev2NotifyCB callback;

  /** Back pointer to response packet when initiator. */
  SshIkev2Packet response_packet;

#ifdef SSHDIST_IKE_MOBIKE
  /** The remote IP address of the last packet sent on this exchange. */
  SshIpAddrStruct last_packet_remote_ip;
  /** The local IP address of the last packet sent on this exchange. */
  SshIpAddrStruct last_packet_local_ip;
#endif /* SSHDIST_IKE_MOBIKE */
};

typedef struct SshIkev2ExchangeDataRec SshIkev2ExchangeDataStruct;

/** IKEv2 packet from the network - this is allocated from the
    freelist, and returned there when it is no longer needed;
    there is only one of these per IKE SA active at one time. */
struct SshIkev2PacketRec {
  SshADTListHeaderStruct freelist_header[1];

  /** Decoded from 'encoded_packet' */
  unsigned char ike_spi_i[8];
  /** Decoded from 'encoded_packet' */
  unsigned char ike_spi_r[8];

  SshIkev2PayloadType first_payload;
  SshUInt8 major_version;
  SshUInt8 minor_version;
  SshIkev2ExchangeType exchange_type;

#define SSH_IKEV2_PACKET_FLAG_INITIATOR 0x08
#define SSH_IKEV2_PACKET_FLAG_VERSION   0x10
#define SSH_IKEV2_PACKET_FLAG_RESPONSE  0x20
  SshUInt8 flags;

  SshUInt32 message_id;

  /** Linearized packet. */
  size_t encoded_packet_len;
  unsigned char *encoded_packet;

  /** MD5 HASH over linearized packet, for fast drop of received
      packets (if we have received this packet before, without storing
      the actual encoded packet). */
  unsigned char hash[16];


  /** Thread where this packet is run. */
  SshFSMThreadStruct thread[1];

  /** These are used to send the packet out, and also to
      indicate where the packet came from. */
  SshIpAddrStruct remote_ip[1];
  SshUInt16 remote_port;

  /** Server that received this packet, or where to send the
      packet. */
  SshIkev2Server server;

  /** Pointer to the IKE SA of this packet. */
  SshIkev2Sa ike_sa;

  /** Pointer to the exchange data of the packet, or NULL if
      such is not yet allocated. */
  SshIkev2ExchangeData ed;

  /** Set if received or to be sent on NAT-T listener. */
  unsigned int use_natt : 1;
  unsigned int received : 1;

  /** Error was received from net. */
  unsigned int error_from_notify : 1;

  /*--------------------------------------------------------------------*/
  /*  The following fields are only general purpose fields used
      in multiple modules.                                              */
  SshOperationHandle operation;

  /** Error code if an error has occurred. */
  SshIkev2Error error;

  /*--------------------------------------------------------------------*/
  /* The following fields are only used by the UDP receiver.            */
  unsigned int allocate_sa : 1;
  unsigned int response_received : 1;
  unsigned int retransmit : 1;
  unsigned int in_window : 1;
  unsigned int thread_started : 1; /** Set if thread is started. */
  unsigned int destroyed : 1; /** Set if the thread is completed. */
  unsigned int sent : 1;

  /*--------------------------------------------------------------------*/
  /*  The following fields are only used by the UDP sender.             */
  /** Retransmit timer */
  SshTimeoutStruct timeout[1];
  SshUInt32 timeout_msec_prev;
  SshUInt32 timeout_msec;
  SshUInt16 retransmit_counter;

  /** Pointer to next packet on the same window slot (meaning the next
      packet received for this SA with the same message ID) - these are
      typically stored momentarily and then discarded, unless the
      first packet on the slot is discarded, in which case these are
      sent. */
  SshIkev2Packet next;

  /** Pointer to next packet in transmit and receive window lists. */
  SshIkev2Packet window_next;
};

typedef struct SshIkev2PacketRec SshIkev2PacketStruct;

/* The IKEv2 Transmit Window */
typedef struct SshIkev2TransmitWindowRec *SshIkev2TransmitWindow;
typedef struct SshIkev2TransmitWindowRec SshIkev2TransmitWindowStruct;
struct SshIkev2TransmitWindowRec
{
  SshUInt32        next_message_id;
  SshUInt32        window_size;
  SshIkev2Packet   packets_head;
  SshIkev2Packet   packets_tail;
};

/* The IKEv2 Receive window */
typedef struct SshIkev2ReceiveWindowRec *SshIkev2ReceiveWindow;
typedef struct SshIkev2ReceiveWindowRec SshIkev2ReceiveWindowStruct;
struct SshIkev2ReceiveWindowRec
{
  SshUInt32        expected_id;
  SshUInt32        window_size;
  SshIkev2Packet   packets_head;
  SshIkev2Packet   packets_tail;
};

typedef struct SshIkev2SaDeleteRec {
  /** Top-level operation handle. */
  SshOperationHandleStruct operation_handle[1];
  SshIkev2SadDeleteCB delete_callback;
  void *delete_callback_context;
} *SshIkev2SaDelete, SshIkev2SaDeleteStruct;

/** IKE SA rekey context. */
typedef struct SshIkev2SaRekeyRec {
  SshIkev2Sa initiated_new_sa;
  SshIkev2Sa responded_new_sa;
  unsigned char *initiated_smaller_nonce;
  size_t initiated_smaller_nonce_len;
  unsigned char *responded_smaller_nonce;
  size_t responded_smaller_nonce_len;
} *SshIkev2SaRekey, SshIkev2SaRekeyStruct;

/** Maximum number of additional IP addresses stored at each IKE SA. */
#define SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES   10

/*----------------------------------------------------------------------*/
/** SshIkev2Sa context structure.                                       */
/*----------------------------------------------------------------------*/
struct SshIkev2SaRec {

  /*  Some fields that might be useful to Policy Manager. */

  /** Pointer to the default server used when initiating
      exchanges. */
  SshIkev2Server server;

  /** The remote end's IP address. */
  SshIpAddrStruct remote_ip[1];

  /** The port used by the remote end - this is modified when the port
      changes because of NAT-T being enabled. */
  SshUInt16 remote_port;

#ifdef SSHDIST_IKE_MOBIKE
  /** Additional addresses of the IKE peer. */
  SshUInt32 num_additional_ip_addresses;
  SshIpAddrStruct
    additional_ip_addresses[SSH_IKEV2_SA_MAX_ADDITIONAL_ADDRESSES];
#endif /* SSHDIST_IKE_MOBIKE */

  /** Flags for this connection. */
  SshUInt32 flags;

  /** This flag means that we have floated to a new port and are
      using the NAT-T packet format. */
#define SSH_IKEV2_IKE_SA_FLAGS_NAT_T_FLOAT_DONE         (0x0001 << 16)

  /** This flag means that we are the original inititator of the
      exchange. */
#define SSH_IKEV2_IKE_SA_FLAGS_INITIATOR                (0x0002 << 16)

  /** Require cookie from the other end. */
#define SSH_IKEV2_IKE_SA_FLAGS_REQUIRE_COOKIE           (0x0004 << 16)

  /** This flag means that we have finished the IKE SA creation. */
#define SSH_IKEV2_IKE_SA_FLAGS_IKE_SA_DONE              (0x0008 << 16)

  /** The other end is behind NAT - this means we should enable
      automatic IP and port updating. */
#define SSH_IKEV2_IKE_SA_FLAGS_OTHER_END_BEHIND_NAT     (0x0010 << 16)

  /** We are behind NAT - this means we should enable heartbeats. */
#define SSH_IKEV2_IKE_SA_FLAGS_THIS_END_BEHIND_NAT      (0x0020 << 16)

  /** We are waiting for the retransmissions from the other end - if
      this is set and the server is shut down then, simply free one
      reference. */
#define SSH_IKEV2_IKE_SA_FLAGS_RESPONDER_DELETED        (0x0040 << 16)

  /** Some operations have been aborted, thus this IKE SA is now
      waiting for delete, and is in unusable state. We want to destroy
      packets starting to be processed as soon as possible. */
#define SSH_IKEV2_IKE_SA_FLAGS_ABORTED                  (0x0080 << 16)

#ifdef SSHDIST_IKEV1
  /** RFC 3947 NAT-T used. */
#define SSH_IKEV2_FB_IKE_NAT_T_RFC3947                  (0x0100 << 16)

  /** IETF NAT-T Draft 01-03 used. */
#define SSH_IKEV2_FB_IKE_NAT_T_IETF_DRAFT               (0x0200 << 16)

  /** IKEv1 Aggressive mode used */
#define SSH_IKEV2_FB_IKE_AGGRESSIVE_MODE                (0x0400 << 16)
#endif /* SSHDIST_IKEV1 */

  /** NAT-T is disabled for this IKE SA, i.e.  */
#define SSH_IKEV2_IKE_SA_FLAGS_NAT_T_DISABLED           (0x0800 << 16)

#ifdef SSHDIST_IKE_MOBIKE
  /** MOBIKE is enabled for this IKE SA. */
#define SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_ENABLED           (0x1000 << 16)

  /** This flag means that we are the initiator of the IKE SA in
      in the sense used by MOBIKE, i.e. means the party who
      originally initiated the first IKE_SA (in a series of possibly
      several rekeyed IKE_SAs) */
#define SSH_IKEV2_IKE_SA_FLAGS_MOBIKE_INITIATOR         (0x2000 << 16)
#endif /* SSHDIST_IKE_MOBIKE */
  /** IKE SA uses IPsec over TCP encapsulation. This flag is managed by
      the policy manager. */
#define SSH_IKEV2_IKE_SA_FLAGS_TCPENCAP                 (0x4000 << 16)

#ifdef SSHDIST_IKE_REDIRECT
  /** This is the initiator and has been redirected from the original
      GW. Needed for rekey */
#define SSH_IKEV2_IKE_SA_FLAGS_REDIRECTED               (0x8000 << 16)
#endif /* SSHDIST_IKE_REDIRECT */

  /** SPI for this connection. */
  unsigned char ike_spi_i[8];
  unsigned char ike_spi_r[8];

  /*----------------------------------------------------------------------*/
  /*  The rest of the fields are internal to the IKE library,
      so of no interest to Policy Manager. */
  /*----------------------------------------------------------------------*/

  /* Keying material for each cipher or MAC. */
  unsigned char *sk_d;          /* This is the mallocated
                                   data, all others are just
                                   pointers into this
                                   buffer, meaning that
                                   freeing this will free
                                   them all. */
  size_t sk_d_len;
  unsigned char *sk_ai;
  unsigned char *sk_ar;
  size_t sk_a_len;
  unsigned char *sk_ei;
  unsigned char *sk_er;
  size_t sk_e_len;
  unsigned char *sk_ni; /* Nonce for CTR and combined ciphers */
  unsigned char *sk_nr;
  size_t sk_n_len;
  unsigned char *sk_pi;
  unsigned char *sk_pr;
  size_t sk_p_len;

  /** Encryption algorithm for the IKE SA. */
  const unsigned char *encrypt_algorithm;
  /** PRF algorithm for the IKE SA. */
  const unsigned char *prf_algorithm;
  /** MAC algorithm for the IKE SA. */
  const unsigned char *mac_algorithm;

  /** Preferred group for the child SAs. */
  SshUInt16 dh_group;

  /** Pointer to the initial IKE SA creation exchange data of
      the packet. */
  SshIkev2ExchangeData initial_ed;

  /** IKE SA rekey context. */
  SshIkev2SaRekey rekey;

  /** Transmit and receive windows. */
  SshIkev2TransmitWindowStruct transmit_window[1];
  SshIkev2ReceiveWindowStruct receive_window[1];

#ifdef SSHDIST_IKE_MOBIKE
  /** The address index used when requesting addresses in the
      SshIkev2PadGetAddressPair policy call. */
  SshUInt32 address_index;

  /** The number of packets sent on this SA using the address
      address_index. When this value reaches the value of
      mobike_worry_counter in SshIkev2Params, address_index gets
      incremented. */
  SshUInt32 address_index_count;

  /** The largest message id received so far with an UPDATE_SA_ADDRESS
       notification. */
  SshUInt32 max_update_address_mid;
  /** The largest message id received so far with an ADDITIONAL_*_ADDRESS
       notification. */
  SshUInt32 max_additional_address_mid;

  /** Whether to request address from the policy call
      SshIkev2PadGetAddressPair when sending request packets on this
      SA. */
  unsigned int request_address_from_policy : 1;
#endif /* SSHDIST_IKE_MOBIKE */

  /** Debuggable object data. */
  SshPdbgObjectStruct debug_object;

  /** Local debug address. */
  SshIpAddrStruct debug_local[1];

  /** Remote debug address. */
  SshIpAddrStruct debug_remote[1];

  /*------------------------------------------------------------------*/
  /* The rest of the fields are internal to Policy Manager.           */
  /*------------------------------------------------------------------*/

  /** Reference count. */
  SshUInt32 ref_cnt;

  /** Security Association Database (SAD). */
  SshADTBagHeaderStruct sa_header;

  /** If we are waiting for the delete, this will be set. */
  SshIkev2SaDelete waiting_for_delete;

  /** An unauthenticated IKEv1 INVALID_MAJOR_VERSION notification has been
      received for this IKEv2 SA. This is used as a hint so that when the
      initial IKEv2 exchange times out the error is set to USE_IKEV1 instead
      of TIMEOUT causing fallback to IKEv1 if policy allows this. */
  unsigned int invalid_major_version_received : 1;


  /** An unauthenticated error notification has been received for this IKEv2
      SA. This is used as a hint so that when the initial IKEv2 exchange
      times out this error is returned instead of TIMEOUT. This is used for
      handling IKEv1 fallback (Ikev1 INVALID_MAJOR_VERSION) and for
      unauthenticated AUTHENTICATION_FAILED and UNEXPECTED_NAT_DETECTED
      IKEv2 errors. */
  SshIkev2Error received_unprotected_error;

  /** Last input packet for IKEv2 */
  SshTime last_input_packet_time;

#ifdef SSHDIST_IKEV1
  /** Handle to IKEv1 SA - valid if flags indicate. */
  SshIkeNegotiation v1_sa;

  /** Handle to IKEv1 CFGmode negotiation - valid if not NULL. */
  SshIkeNegotiation v1_cfg_negotiation;

  /** Dead Peer Detection - input stamp for the last received
      packet. */
  SshTime last_input_stamp;
  /** Dead Peer Detection - input stamp for the last received
      cookie. */
  SshUInt32 dpd_cookie;
  /** Dead Peer Detection - input stamp for the last received
      initiator context. */
  void *dpd_context;
  /** Handle to negotiation context used by the fallback code when
      negotiating the IKE SA. This is cleared after the IKE is negotiated. */
  void *p1_negotiation_context;

  /** *********** Remote access client flags ***********/

  /* CFG mode attributes received during XAUTH. Used to decide whether
     it is necessary to initiate CFG mode after XAUTH is completed. */
  unsigned int cfg_attrs_received : 1;

  /** *********** Remote access client and server flags *********/

  /* Server : Initiate CFG mode SET/ACK to the client.
     Client : Do not initiate CFG mode, wait for the server to do so. */
  unsigned int server_cfg_pending : 1;
  /* Support for hybrid authentication has been indicated by use of
     hybrid method types. */
  unsigned int hybrid_enabled : 1;
  /* Support for XAUTH has been indicated by use of XAUTH method types. */
  unsigned int xauth_enabled : 1;
  /* Xauth mode negotiation has started. */
  unsigned int xauth_started : 1;
  /* Xauth is completed */
  unsigned int xauth_done : 1;
#endif /* SSHDIST_IKEV1 */

  /* Ike Fragmentation enabled */
  unsigned int ikev2_fragmentation_enabled : 1;

};

typedef struct SshIkev2SaRec SshIkev2SaStruct;

#endif /* SSH_IKEV2_EXCHANGE_H */
