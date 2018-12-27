/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp module.
*/

#ifndef ISAKMP_H
#define ISAKMP_H

/*                                                              shade{0.9}
 *
 * Some forward declarations.
 *                                                              shade{1.0}
 */

/* Isakmp or ipsec negotiation struct/union */
typedef struct SshIkeNegotiationRec *SshIkeNegotiation;
/* Group attributes, read in by ssh_ike_read_grp_attrs. */
typedef struct SshIkeGrpAttributesRec *SshIkeGrpAttributes;
/* IKE attributes, read in by ssh_ike_read_isakmp_attrs. */
typedef struct SshIkeAttributesRec *SshIkeAttributes;
/* Ipsec attributes, read in by isakmp_read_ipsec_attrs. */
typedef struct SshIkeIpsecAttributesRec *SshIkeIpsecAttributes;
/* Isakmp server context. */
typedef struct SshIkeServerContextRec  *SshIkeServerContext;
/* Global isakmp context structure. Common data for all isakmp functions */
typedef struct SshIkeContextRec *SshIkeContext;
/* Policy manager data structures */
typedef struct SshIkePMContextRec *SshIkePMContext;
/* Policy manager phase I information structure. This is given to policy
   manager, and must be kept as long as the isakmp sa is valid. */
typedef struct SshIkePMPhaseIRec *SshIkePMPhaseI;
/* Policy manager phase II Qm information structure. This is given to policy
   manager, and must be kept as long as the negotiation is valid. */
typedef struct SshIkePMPhaseQmRec *SshIkePMPhaseQm;
/* Policy manager phase II information structure. This is given to policy
   manager, and must be kept as long as the negotiation is valid. */
typedef struct SshIkePMPhaseIIRec *SshIkePMPhaseII;
/* Generic isakmp payload packet */
typedef struct SshIkePayloadRec *SshIkePayload;
/* Isakmp cookies */
typedef struct SshIkeCookiesRec *SshIkeCookies;
/* Selected protocols given to policy manager */
typedef struct SshIkeIpsecSelectedSARec *SshIkeIpsecSelectedSA;
/* Selected proposal and transforms returned by Policy Manager */
typedef struct SshIkeIpsecSelectedSAIndexesRec *SshIkeIpsecSelectedSAIndexes;
/* Group descriptor mapping */
typedef struct SshIkeGroupMapRec *SshIkeGroupMap;
/* Keymat struct given to ipsec */
typedef struct SshIkeIpsecKeymatRec *SshIkeIpsecKeymat;
/* Isakmp SA used for isakmp message encryption etc */
typedef struct SshIkeSARec *SshIkeSA;
/* Isakmp packet */
typedef struct SshIkePacketRec *SshIkePacket;
/* Isakmp state machine description structure */
typedef const struct SshIkeStateMachineRec *SshIkeStateMachine;

#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshmp.h"
#include "sshudp.h"
#include "isakmp_defaults.h"
#include "isakmp_doi.h"
#include "isakmp_policy.h"
#include "sshaudit.h"
#ifdef SSHDIST_EXTERNALKEY
#include "sshexternalkey.h"
#endif /* SSHDIST_EXTERNALKEY */
#include "sshpdbg.h"

/*
 * Naming convention.
 *
 * External isakmp library functions have ssh_ike_* prefix.
 * External isakmp library types have SshIke* prefix
 * External policy manager functions have ssh_policy_* prefix
 * External policy manager types have SshIkePM* prefix
 * Interal isakmp library functions have ike_* prefix
 * External ipsec quick mode types have SshIkeIpsec prefix
 * DOI defined ipsec defines have IPSEC_* prefix
 * DOI defined ipsec enums have Ipsec* prefix
 */

/*                                                              shade{0.9}
 *
 * Functions and their datatypes
 *                                                              shade{1.0}
 */

/* Group descriptor to SshPkGroup mapping */
struct SshIkeGroupMapRec {
  SshIkeContext isakmp_context;
  SshIkeAttributeGrpDescValues descriptor;
  SshPkGroup group;
#ifdef SSHDIST_EXTERNALKEY
  SshPkGroup old_group;
  SshOperationHandle accelerator_handle;
#endif /* SSHDIST_EXTERNALKEY */
};

struct SshIkeCookiesRec {
  unsigned char initiator_cookie[SSH_IKE_COOKIE_LENGTH];
  unsigned char responder_cookie[SSH_IKE_COOKIE_LENGTH];
};

/* Parameter block given to ssh_isakmp_init function. */

typedef struct SshIkeParamsRec {
  int length_of_local_secret;           /* OBSOLETE, set this to zero. */
  const char *token_hash_type;          /* OBSOLETE, set this to NULL. */
  Boolean ignore_cr_payloads;           /* Ignore CR payloads */
  Boolean no_key_hash_payload;          /* Do not send key hash payload */
  Boolean no_cr_payloads;               /* Do not certificate request
                                           payloads */
  Boolean do_not_send_crls;             /* Do not send certificate payloads
                                           containing crls */
  Boolean do_not_send_cert_chains;      /* Never send intermediate certs, just
                                           end entity certificates.
                                           (Alcatel's old box is BROKEN and
                                           therefore we need this option
                                           to interoperate with it). */
  Boolean send_full_chains;             /* Do not remove duplicate certificates
                                           from the chains, but send full
                                           chains from the ca to the end user
                                           certificate. */
  Boolean trust_icmp_messages;          /* Trust ICMP host unreachable and port
                                           unreachable messages, and abort
                                           negotiation immediately. */
  const char *default_ip;               /* Default IP */
  const char *default_port;             /* Default port */

  /* There are two differnet retransmission timer settings, base and extended.
     Base is for normal use and extended is for those operations that may take
     long time (require user interaction etc, like extended authentication).

     The selection between base and extended retry timers are done using the
     flags given to the negotiation. If the SSH_IKE_FLAGS_USE_EXTENDED_TIMERS
     is set then the negotiation uses extended timers.

     The retry_limit is the maximum number of retransmission packets the
     library will send. When it reaches zero the negotiation is aborted.

     The retry timer (seconds and microseconds) specify the base interval for
     the retransmission packets. The first retransmission packet is sent after
     the that time. The next packet is sent 2^(retransmission packet number) *
     retry_timer etc. So if the retry limit is 10, and retry_timer is 0.5
     seconds (0 seconds, and 500 000 microseconds), first retransmission
     packet is sent out after 0.5 seconds, second packet after 1 second, and
     nexts after 2, 4, 8, 16, 32, 64, 128, and 256 seconds, and after that the
     negotiation times out.

     Another parameter that will affect retransmission timer is the
     retry_timer_max, that will specify the maximum time in seconds between to
     retrasmission packets. So if it is set to 30 seconds, and we are using
     retry_timer of 0.5 seconds, and retry limit is 10, then the retransmission
     packets are sent after 0.5, 1, 2, 4, 8, 16, 30, 30, 30, and 30 seconds.

     For the whole negotiation there is also a expire_timer that will specify
     the maximum time for the whole negotiation. After that timer expires the
     negotiation is immediately aborted. */
  SshInt32 base_retry_limit;            /* Number of retries */
  SshInt32 base_retry_timer;            /* Base retry timer (in seconds) */
  SshInt32 base_retry_timer_usec;       /* Base retry timer (in useconds) */
  SshInt32 base_retry_timer_max;        /* Max time of the retry timer (in
                                           seconds). */
  SshInt32 base_retry_timer_max_usec;   /* Max time of the retry timer (in
                                           useconds). */
  SshInt32 base_expire_timer;           /* Expire timer (in seconds) */
  SshInt32 base_expire_timer_usec;      /* Expire timer (in useconds) */

  SshInt32 extended_retry_limit;        /* Number of retries using extended
                                           timers */
  SshInt32 extended_retry_timer;        /* Extended retry timer (in seconds) */
  SshInt32 extended_retry_timer_usec;   /* Extended retry timer (in useconds)*/
  SshInt32 extended_retry_timer_max;    /* Max time of the extended retry timer
                                           (in seconds). */
  SshInt32 extended_retry_timer_max_usec;/* Max time of the ext. retry timer
                                           (in useconds). */
  SshInt32 extended_expire_timer;       /* Extended expire timer (in seconds)*/
  SshInt32 extended_expire_timer_usec;  /* Extended expire timer(in useconds)*/

  int secret_recreate_timer;            /* Secret recreation timer (in secs) */
  int spi_size;                         /* Size of zeros to use if zero_spi is
                                           set. */
  Boolean zero_spi;                     /* Use zeros as spi */
  int max_key_length;                   /* Max key length in bits */
  int max_isakmp_sa_count;              /* Max number of isakmp_sa entries
                                           allowed in mapping */
  int randomizers_default_cnt;          /* Number of randomizers for default
                                           groups calculated once */
  int randomizers_default_max_cnt;      /* Max number of randomizers for
                                           default groups */
  int randomizers_private_cnt;          /* Number of randomizers for private
                                           groups calcucalted once */
  int randomizers_private_max_cnt;      /* Max number of randomizers for
                                           private groups */
  int randomizers_default_retry;        /* Idle timeout retry timer (secs),
                                           default groups */
  int randomizers_private_retry;        /* Idle timeout retry timer (secs),
                                           private groups */

#ifdef SSHDIST_EXTERNALKEY
  SshExternalKey external_key;          /* External key handle, or NULL if not
                                           available. */
  const char *accelerator_short_name;
                                        /* Short name of the hardware
                                           accelerator to be used, or NULL if
                                           not available. */
#endif /* SSHDIST_EXTERNALKEY */
  /* Default private payload policy manager functions. These functions will be
     used if negotiation doesn't have its own handers. */
  SshIkePrivatePayloadPhaseICheck private_payload_phase_1_check;
  SshIkePrivatePayloadPhaseIIn private_payload_phase_1_input;
  SshIkePrivatePayloadPhaseIOut private_payload_phase_1_output;
  SshIkePrivatePayloadPhaseIICheck private_payload_phase_2_check;
  SshIkePrivatePayloadPhaseIIIn private_payload_phase_2_input;
  SshIkePrivatePayloadPhaseIIOut private_payload_phase_2_output;
  SshIkePrivatePayloadPhaseQmCheck private_payload_phase_qm_check;
  SshIkePrivatePayloadPhaseQmIn private_payload_phase_qm_input;
  SshIkePrivatePayloadPhaseQmOut private_payload_phase_qm_output;
  void *private_payload_context;

  /* Pointer to debug configuration. */
  SshPdbgConfig debug_config;
} *SshIkeParams;

/* Compat flags. The default_compat_flags in the SshIkeContextRec and the
   compat_flags given to SshPolicyNewConnectionCB use these. */
#define SSH_IKE_FLAGS_IGNORE_CR_PAYLOADS                0x0000020
#define SSH_IKE_FLAGS_USE_ZERO_SPI                      0x0000080
#define SSH_IKE_FLAGS_DO_NOT_SEND_CRLS                  0x0000100
#define SSH_IKE_FLAGS_SEND_FULL_CHAINS                  0x0000200
#define SSH_IKE_FLAGS_DO_NOT_SEND_CERT_CHAINS           0x0000400

#ifdef SSHDIST_IKEV2
/* Initiate negotiation with NAT-T ports */
#define SSH_IKE_FLAGS_START_WITH_NAT_T                  0x0002000
#endif /* SSHDIST_IKEV2 */

/* Use extended timers */
#define SSH_IKE_FLAGS_USE_EXTENDED_TIMERS               0x0004000

/* This means that use the default values for the rest of the compat flags */
#define SSH_IKE_FLAGS_USE_DEFAULTS                      0x0008000

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Callback to be called when configuration mode negotiation is finished, after
 * this callback all data related to negotiation can be freed by any time by
 * isakmp layer (some data may be left around for some time to respond possible
 * retransmit requests). If the error code is not
 * SSH_IKE_NOTIFY_MESSAGE_CONNECTED then all the other fields are NULL. */
typedef void (*SshIkeCfgNotify)(SshIkeNegotiation negotiation,
                                SshIkePMPhaseII pm_info,
                                SshIkeNotifyMessageType error_code,
                                int number_of_attr_payloads,
                                SshIkePayloadAttr *attributes,
                                void *notify_callback_context);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* This function is used to notify the caller that isakmp sa negotiation is
   finished. If error is SSH_IKE_NOTIFY_MESSAGE_CONNECTED then the
   isakmp sa negotiation was successfull and the the isakmp_sa can be used
   to create ipsec security assosiations. If the error field is something else
   then error occured during isakmp negotiation and the isakmp sa will be freed
   after retransmit timer expires. */
typedef void (*SshIkeNotify)(SshIkeNotifyMessageType error,
                             SshIkeNegotiation negotiation,
                             void *callback_context);

/*
 * Attribute structures
 */

/* Group attributes, read in by ssh_ike_read_grp_attrs. */
struct SshIkeGrpAttributesRec {
  SshIkeAttributeGrpDescValues group_descriptor; /* Group descriptor number */
  SshIkeAttributeGrpTypeValues group_type; /* Group type */
  SshIkeAttributePrimeValues p; /* Prime */
  SshIkeAttributeGen1Values g1; /* Generator 1 */
  SshIkeAttributeGen2Values g2; /* Generator 2 */
  SshIkeAttributeCurveaValues ca; /* Curve A */
  SshIkeAttributeCurvebValues cb; /* Curve B */
  SshIkeAttributeOrderValues order; /* order */
  SshIkeAttributeCardinalityValues cardinality; /* cardinality */
};

/* IKE attributes, read in by ssh_ike_read_isakmp_attrs. */
struct SshIkeAttributesRec {
  /* Encryption algorithm */
  SshIkeAttributeEncrAlgValues encryption_algorithm;
  /* Hash algorithm */
  SshIkeAttributeHashAlgValues hash_algorithm;
  /* Authentication method */
  SshIkeAttributeAuthMethValues auth_method;
  /* Group information */
  SshIkeGroupMap group_desc;
  Boolean group_parameters;     /* Attributes have group parameters */
  /* PRF algorithm */
  SshIkeAttributePrfValues prf_algorithm; /* 0 means use hmac-hash as prf */
  /* Life duration information */
  SshIkeAttributeLifeDurationValues life_duration_kb; /* Life duration in
                                                         kilobytes. 0 = not
                                                         given */
  SshIkeAttributeLifeDurationValues life_duration_secs; /* Life duration in
                                                           seconds. 0 = not
                                                           given */
  /* Key length */
  SshIkeAttributeKeyLenValues key_length;
};

/* Ipsec attributes, read in by isakmp_read_ipsec_attrs. */
struct SshIkeIpsecAttributesRec {
  /* Life duration information */
  SshIkeAttributeLifeDurationValues life_duration_kb; /* Life duration in
                                                         kilobytes. 0 = not
                                                         given */
  SshIkeAttributeLifeDurationValues life_duration_secs; /* Life duration in
                                                           seconds. 0 = not
                                                           given */
  /* Group descriptor number */
  SshIkeIpsecAttributeGrpDescValues group_desc;

  /* Encapsulation mode */
  SshIkeIpsecAttributeEncapsulationModeValues encapsulation_mode;

  /* AH algorithm */
  SshIkeIpsecAttributeAuthAlgorithmValues auth_algorithm;

  /* Extended sequence size */
  SshIkeIpsecAttributeLongSequenceValues longseq_size;

  /* Key length and rounds */
  int key_length;
  int key_rounds;
};

/* Selected protocol */
typedef struct SshIkeIpsecSelectedProtocolRec {
  SshIkeProtocolIdentifiers protocol_id; /* Protocol id */
  size_t spi_size_in;
  unsigned char *spi_in;        /* Mallocated by pm, freed by isakmp */
  size_t spi_size_out;
  unsigned char *spi_out;       /* Mallocated by pm, freed by isakmp */
  union SshIkeTransformIdentifiersUnion transform_id;
  struct SshIkeIpsecAttributesRec attributes;
} *SshIkeIpsecSelectedProtocol;

/* Selected protocols given to policy manager */
struct SshIkeIpsecSelectedSARec {
  int number_of_protocols;         /* Number of protocols in this SA */
  SshIkeIpsecSelectedProtocol protocols; /* Protocols in this SA (one
                                            mallocated array) */

  /* Life duration information from the policy manager or from the responder
     lifetime notification. If these values are non zero ipsec engine should
     use them. */
  SshIkeAttributeLifeDurationValues life_duration_kb; /* Life duration in
                                                         kilobytes. 0 = not
                                                         given */
  SshIkeAttributeLifeDurationValues life_duration_secs; /* Life duration in
                                                           seconds. 0 = not
                                                           given */
};

/* Callback to be called when any ipsec quick mode key negotiation is finished,
 * after this callback returns all data related to ipsec sa negotiation can be
 * freed by any time by isakmp layer (some data may be left around for some
 * time to respond possible retransmit requests). */
typedef void (*SshIkeIpsecSAHandler)(SshIkeNegotiation negotiation,
                                     SshIkePMPhaseQm pm_info,
                                     int number_of_sas,
                                     SshIkeIpsecSelectedSA sas,
                                     SshIkeIpsecKeymat keymat,
                                     void *sa_callback_context);

/* ssh_ike_connect error codes */
typedef enum {
  SSH_IKE_ERROR_OK = 0,         /* No error */
  SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND = 1,
                                /* No isakmp sa found when starting to
                                   negotiate ipsec sa. Call ssh_ike_connect
                                   first to create isakmp sa. */
  SSH_IKE_ERROR_ISAKMP_SA_NEGOTIATION_IN_PROGRESS = 2,
                                /* There is already isakmp sa negotiation in
                                   progress, but it is not yet finished when
                                   ipsec or ngm negotiation was started. Retry
                                   later when isakmp sa negotiation has
                                   finished. */
  SSH_IKE_ERROR_INVALID_ARGUMENTS = 3,
                                /* Arguments given to function are invalid, for
                                   example the sa_proposal contains unsupported
                                   or inconsistent values. */
  SSH_IKE_ERROR_INTERNAL = 4,   /* Internal error in isakmp module, should not
                                   happen. */
  SSH_IKE_ERROR_OUT_OF_MEMORY = 5 /* Out of memory. */
} SshIkeErrorCode;

/*                                                              shade{0.9}
 *
 * isakmp.c prototypes
 *                                                              shade{1.0}
 */

/* Initialize isakmp local data. Can return NULL if it runs out of memory. */
SshIkeContext ssh_ike_init(SshIkeParams params,
                           SshAuditContext audit_context);

/* Attach the audit context specified by 'audit' to the IKE context. This
   enables auditing of IKE events to this audit context. It is legal to
   call this function multiple times for different audit contexts, in
   which case audit events will be sent to each attached audit context.
   Returns TRUE on success and FALSE on memory allocation error. */
Boolean ssh_ike_attach_audit_context(SshIkeContext context,
                                     SshAuditContext audit);

/* Uninitialize isakmp local data */
void ssh_ike_uninit(SshIkeContext context);

/* Calculate ipsec key (of given size (in bits)) for given spi and protocol.
   Returns SSH_CRYPTO_OK on success. On combined transforms key_len is sum
   of all keying material needed. It is up to the caller to break resulting
   key to subkeys needed. */
SshCryptoStatus ssh_ike_ipsec_keys(SshIkeNegotiation negotiation,
                                   SshIkeIpsecKeymat keymat,
                                   size_t spi_size,
                                   unsigned char *spi,
                                   SshIkeProtocolIdentifiers protocol_id,
                                   size_t key_len,
                                   unsigned char *key_out);

/* Start isakmp/oakley server. This will return server context that can be used
   later to destroy server. All server share security assosiations, but there
   can be several servers each on separate ip/port pair. Returns NULL on
   failure. If server_name or server_port are null, then use defaults. */
SshIkeServerContext ssh_ike_start_server(SshIkeContext context,
                                         const unsigned char *server_name,
                                         const unsigned char *server_port,
                                         int interface_index,
                                         int routing_instance_id,
                                         SshIkePMContext pm,
                                         SshIkeIpsecSAHandler sa_callback,
                                         void *sa_callback_context);

#ifdef SSHDIST_IKEV2
/* Configure contexts and callbacks to ikev2 server context represented by
   server. */
void ssh_ike_attach_server(SshIkeServerContext server,
                           SshIkeContext ike,
                           SshIkePMContext pm,
                           SshIkeIpsecSAHandler sa_callback,
                           void *sa_callback_context);
void ssh_ike_detach_server(SshIkeServerContext server);
#endif /* SSHDIST_IKEV2 */

/* Stop isakmp/oakley server. */
void ssh_ike_stop_server(SshIkeServerContext server_context);

/* Get the isakmp/oakley server used for the negotiation. */
SshIkeServerContext
ssh_ike_get_server_by_negotiation(SshIkeNegotiation negotiation);

/* Get the policy manager Phase-1 information from the IKE negotiation
   `negotiation'.  The function returns a pointer to the IKE info or
   NULL if the `negotiation' is not a valid IKE SA. */
SshIkePMPhaseI
ssh_ike_get_pm_phase_i_info_by_negotiation(SshIkeNegotiation negotiation);

/* Wire Phase-1 negotiation (and thus the SA it reprensents) into
   memory. After this call, the SA will not be removed unless the
   wiring application unwires it, removes it, or the SA receives
   delete notification from the peer. Application may wish to wire
   negotiations it expects to use later for phase-2 negotiations,
   sending notifications, or similar purposes. Wiring does not
   guarantee, the remote has this SA UP, therefore the application
   still must prepare for doing Phase-1 from beginning. */
void ssh_ike_wire_negotiation(SshIkeNegotiation negotiation);

/* Unwire Phase-1 negotiation. After this call, the negotiation is
   again subject to library internal house keeping functions. */
void ssh_ike_unwire_negotiation(SshIkeNegotiation negotiation);

/* Change the SshIkeServer and destination ip and port numbers to new ones.
   This should be called when doing the NAT-T port floating etc. The
   SshIkeServer is used to select the listener when sending the packet out, i.e
   it selects the source port and address of the packet. Note, that this
   changes the SshIkeServerContext of the whole IKE SA, including all
   negotiation in progress, but the new_remote_ip and port are per negotiation,
   If new_remote_ip and port are NULL then do not change them.

   If you want to change the IKE SA remote ip and port use IKE SA negotiation
   pointer with this function. That pointer is can be found from
   pm_info->phase_i->negotiation.

   If change is successfull return TRUE otherwise return FALSE, and the
   negotiation is not modified. */
Boolean ssh_ike_sa_change_server(SshIkeNegotiation negotiation,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port);

/* Establish isakmp SA with some other host. Returns error code if error occurs
   when sending first packet, and does NOT call notify callback, or allocate or
   free anything. Otherwise return allocated IsakmpNegotiation structure in
   negotiation parameter that can be used to clear state later. If the error
   occurs when sending the first packet but after it has already changed the
   data given to it, it will call the callback, free the data, return
   SSH_IKE_ERROR_OK, but set returned negotiation pointer to NULL.

   If error occurs later the notify_callback function is called and context is
   added to freelist (it will be automatically freed later when retransmit
   timeout is expired, and other end cannot send more packets).

   The remote_name, and remote_port are used to send packet. They are not freed
   in the ISAKMP library, and caller is allowed to free them immediately when
   this call returns.

   Local_id is used as isakmp identity given to other end. The sa_proposal is
   our proposal for sa negotiation. They are both freed by ISAKMP code after
   they are not needed anymore. Note that this code assumes that if the id is
   fqdn, user_fqdn, der_asn1_dn or der_asn1_gn then the memory used is
   mallocated.

   Also the sa proposal sa_attributes are assumed to be allocated with one
   malloc so freeing sa_attributes table will free both the tables and the
   data. If the spi is given it is used (the data is freed). If spi pointers
   are NULL then they are filled with either zeros or our initiator cookie,
   depending on the zero_spi parameter to ssh_isakmp_init.

   The exchange_type must be either SSH_IKE_XCHG_TYPE_IP
   (identity protection == oakley main mode), or SSH_IKE_XCHG_TYPE_AGGR
   (aggressive == oakley aggressive).

   When isakmp sa negotiation is done, the notify_callback will be called with
   value SSH_IKE_NOTIFY_MESSAGE_CONNECTED as error code.

   The policy_manager_data pointer is stored in the policy manager information
   structure in the policy_manager_data field.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*) or'ed
   together. */
SshIkeErrorCode ssh_ike_connect(SshIkeServerContext context,
                                SshIkeNegotiation *negotiation,
                                /* Destination address */
                                const unsigned char *remote_name,
                                /* May be NULL == use default (500) */
                                const unsigned char *remote_port,
                                SshIkePayloadID local_id,
                                SshIkePayloadSA sa_proposal,
                                SshIkeExchangeType exchange_type,
                                const unsigned char *initiator_cookie,
                                void *policy_manager_data,
                                SshUInt32 connect_flags,
                                SshIkeNotify notify_callback,
                                void *notify_callback_context);

#define SSH_IKE_IKE_FLAGS_SEND_INITIAL_CONTACT          0x00010000
#define SSH_IKE_IKE_FLAGS_TRUST_ICMP_MESSAGES           0x00020000
#define SSH_IKE_IKE_FLAGS_AGGR_ENCRYPT_LAST_PACKET      0x00040000
#define SSH_IKE_IKE_FLAGS_MAIN_ALLOW_CLEAR_TEXT_CERTS   0x00080000

/* Create ipsec SA with some other host. Returns error code if error occurs
   when sending first packet, and does NOT call notify callback, or allocate or
   free anything. Otherwise return allocated SshIkeNegotiation structure in
   negotiation parameters that can be used to clear state later. If there is no
   Isakmp SA already negotiated with other end this function will return
   SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND and does not do anything. If the error
   occurs when sending the first packet but after it has already changed the
   data given to it, it will call the callback, free the data, return
   SSH_IKE_ERROR_OK, but set returned negotiation pointer to NULL.

   If error occurs later the notify_callback function is called and context is
   added to freelist (it will be automatically freed later when retransmit
   timeout is expired, and other end cannot send more packets).

   If isakmp_sa_negotiation is given then it is assumed to be ISAKMP SA
   negotiation pointer returned by previous ssh_ike_connect call. If that
   pointer is no longer valid SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
   returned.

   If isakmp_sa_negotiation is NULL, then the remote_name, and remote_port are
   used to find matching isakmp SA. They are not freed in the ISAKMP library,
   and caller is allowed to free them immediately when this call returns.

   Local_id and remote_id are used as isakmp identities given to other end
   (they can be NULL, in which case no identity is given to other end).

   The number_of_sa_proposals parameters identifies the count of ipsec security
   associations to negotiate with other end. The sa_proposals contains a table
   of our proposals for each sa negotiation (note that all those sa
   negotiations are send as one quick mode negotiation, so they all must use
   same group for pfs, if they dont have consistent group for each sa /
   proposal / transform a SSH_IKE_ERROR_INVALID_ARGUMENTS error code is
   returned).

   They are all freed by isakmp code after they are not needed anymore. Note
   that this code assumes that if the id is fqdn, user_fqdn, der_asn1_dn or
   der_asn1_gn then the memory used is mallocated.

   Also the sa proposal sa_attributes are assumed to be allocated with
   one malloc so freeing sa_attributes table will free both the tables and the
   data. The spi value is also freed.

   The policy_manager_data pointer is stored in the policy manager information
   structure in the policy_manager_data field.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*) or'ed
   together. If the connect_flags has SSH_IKE_IPSEC_FLAGS_WANT_PFS set then
   quick mode will use perfect forward secrecy.

   When quick mode negotiation is done, the notify_callback will be called with
   value SSH_IKE_NOTIFY_MESSAGE_CONNECTED as error code.

   Note, that isakmp routines automatically also call SshIkeIpsecSAHandler
   associated with SshIkeServerContext when any new ipsec sa is created, so you
   can set notify callback to NULL, or use it as extra notification that this
   specific negotiation is now finished. Keying material etc are given only to
   SshIkeIpsecSAHandler. */

SshIkeErrorCode ssh_ike_connect_ipsec(SshIkeServerContext context,
                                      SshIkeNegotiation *negotiation,
                                      SshIkeNegotiation isakmp_sa_negotiation,
                                      /* Destination address */
                                      const unsigned char *remote_name,
                                      /* May be NULL == use default (500) */
                                      const unsigned char *remote_port,
                                      SshIkePayloadID local_id,
                                      SshIkePayloadID remote_id,
                                      int number_of_sa_proposals,
                                      SshIkePayloadSA *sa_proposals,
                                      void *policy_manager_data,
                                      SshUInt32 connect_flags,
                                      SshIkeNotify notify_callback,
                                      void *notify_callback_context);

#define SSH_IKE_IPSEC_FLAGS_WANT_PFS                    0x00010000

/* Create new group with some other host. Returns error code if error occurs
   when sending first packet, and does NOT call notify callback, or allocate or
   free anything. Otherwise return allocated SshIkeNegotiation structure in
   negotiation parameter that can be used to clear state later. If there is no
   Isakmp SA already negotiated with other end this function will return
   SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND and does not do anything. If the error
   occurs when sending the first packet but after it has already changed the
   data given to it, it will call the callback, free the data, return
   SSH_IKE_ERROR_OK, but set returned negotiation pointer to NULL.

   If error occurs later the notify_callback function is called and context is
   added to freelist (it will be automatically freed later when retransmit
   timeout is expired, and other end cannot send more packets).

   If isakmp_sa_negotiation is given then it is assumed to be ISAKMP SA
   negotiation pointer returned by previous ssh_ike_connect call. If that
   pointer is no longer valid SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
   returned.

   If isakmp_sa_negotiation is NULL, then the remote_name, and remote_port are
   used to find matching isakmp SA. They are not freed in the ISAKMP library,
   and caller is allowed to free them immediately when this call returns.

   The sa_proposals contains our proposals. It is freed by isakmp code after
   they are not needed anymore.

   The sa proposal sa_attributes are assumed to be allocated with one malloc so
   freeing sa_attributes table will free both the tables and the data. If the
   spi is given it is used (the data is freed). If spi pointers are NULL then
   they are filled with either zeros or our initiator cookie, depending on the
   zero_spi parameter to ssh_isakmp_init.

   When ngm negotiation is done, the notify_callback will be called with
   value SSH_IKE_NOTIFY_MESSAGE_CONNECTED as error code.

   The policy_manager_data pointer is stored in the policy manager information
   structure in the policy_manager_data field.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*) or'ed
   together. */

SshIkeErrorCode ssh_ike_connect_ngm(SshIkeServerContext context,
                                    SshIkeNegotiation *negotiation,
                                    SshIkeNegotiation isakmp_sa_negotiation,
                                    /* Destination address */
                                    const unsigned char *remote_name,
                                    /* May be NULL == use default (500) */
                                    const unsigned char *remote_port,
                                    SshIkePayloadSA sa_proposal,
                                    void *policy_manager_data,
                                    SshUInt32 connect_flags,
                                    SshIkeNotify notify_callback,
                                    void *notify_callback_context);

/* Send notification to other end. Returns error code if error occurs when
   sending message. If there is a isakmp sa established, use that to send the
   message, otherwise the message is sent is not authenticated.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*) or'ed
   together. If the connect_flags has SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA set
   then notify is always sent using the existing ISAKMP SA.

   If no ISAKMP SA is established and connect_flags is
   SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA then SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is
   returned.

   If isakmp_sa_negotiation is given then it is assumed to be ISAKMP SA
   negotiation pointer returned by previous ssh_ike_connect call. If that
   pointer is no longer valid SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
   returned.

   If isakmp_sa_negotiation is NULL, then the remote_name, and remote_port are
   used to find matching isakmp SA. They are not freed in the ISAKMP library,
   and caller is allowed to free them immediately when this call returns.

   The doi, protocol_id, spi_size, spi, notify_message_type, notification_data
   and notification_data_size are used to create notification message. */
SshIkeErrorCode ssh_ike_connect_notify(SshIkeServerContext context,
                                       SshIkeNegotiation isakmp_sa_negotiation,
                                       /* Destination address */
                                       const unsigned char *remote_name,
                                       /* May be NULL == use default (500) */
                                       const unsigned char *remote_port,
                                       SshUInt32 connect_flags,
                                       SshIkeDOI doi,
                                       SshIkeProtocolIdentifiers protocol_id,
                                       unsigned char *spi,
                                       size_t spi_size,
                                       SshIkeNotifyMessageType
                                       notify_message_type,
                                       unsigned char *notification_data,
                                       size_t notification_data_size);

#define SSH_IKE_NOTIFY_FLAGS_WANT_ISAKMP_SA             0x00010000

/* Send delete notify to other end. Returns error code if error occurs when
   sending message. If there is a isakmp sa established, use that to send the
   message, otherwise the message is sent is not authenticated.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*) or'ed
   together. If the connect_flags has SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA set
   then notify is always sent using the existing ISAKMP SA.

   If no isakmp sa is established and connect_flags is
   SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA then SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is
   returned.

   If isakmp_sa_negotiation is given then it is assumed to be ISAKMP SA
   negotiation pointer returned by previous ssh_ike_connect call. If that
   pointer is no longer valid SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
   returned.

   If isakmp_sa_negotiation is NULL, then the remote_name, and remote_port are
   used to find matching isakmp SA. They are not freed in the ISAKMP library,
   and caller is allowed to free them immediately when this call returns.

   The doi, protocol_id, spi_size, number_of_spis, and spis are used to create
   delete message. */
SshIkeErrorCode ssh_ike_connect_delete(SshIkeServerContext context,
                                       SshIkeNegotiation isakmp_sa_negotiation,
                                       /* Destination address */
                                       const unsigned char *remote_name,
                                       /* May be NULL == use default (500) */
                                       const unsigned char *remote_port,
                                       SshUInt32 connect_flags,
                                       SshIkeDOI doi,
                                       SshIkeProtocolIdentifiers protocol_id,
                                       int number_of_spis,
                                       unsigned char **spis,
                                       size_t spi_size);

#define SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA             0x00010000

/* Create delete notify which can be send to the other end. Returns
   error code if error occurs when creating message. If there is a
   isakmp sa established, use that to encrypt the message, otherwise
   the message is created unauthenticated.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*)
   or'ed together. If the connect_flags has
   SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA set then notify is always
   created using the existing isakmp sa.

   If no isakmp sa is established and connect_flags is
   SSH_IKE_DELETE_FLAGS_WANT_ISAKMP_SA then
   SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND is returned.

   If isakmp_sa_negotiation is given then it is assumed to be ISAKMP
   SA negotiation pointer returned by previous ssh_ike_connect
   call. If that pointer is no longer valid
   SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is returned.

   If isakmp_sa_negotiation is NULL, then the remote_name, and
   remote_port are used to find matching isakmp SA.

   The doi, protocol_id, spi_size, number_of_spis, and spis are used
   to create delete message. */
SshIkeErrorCode ssh_ike_create_delete(SshBuffer buffer,
                                      SshIkeServerContext context,
                                      SshIkeNegotiation isakmp_sa_negotiation,
                                      const unsigned char *remote_name,
                                      const unsigned char *remote_port,
                                      SshUInt32 connect_flags,
                                      SshIkeDOI doi,
                                      SshIkeProtocolIdentifiers protocol_id,
                                      int number_of_spis,
                                      unsigned char **spis,
                                      size_t spi_size);

/* Mark negotiation to be aborted. This does not delete the negotiation
   immediately, but inserts immediate timer to remove the negotiation. This can
   be safely called anywhere. No flags defined. */
SshIkeErrorCode ssh_ike_abort_negotiation(SshIkeNegotiation negotiation,
                                          SshUInt32 connect_flags);

/* Mark ISAKMP SA of given negotiation to be deleted. This does not delete the
   ISAKMP SA immediately, but inserts immediate timer to remove the
   negotiation, it also marks the SA so that it will not be selected by
   ssh_ike_connect_* routines anymore. This can be safely called anywhere. If
   connect_flags is SSH_IKE_REMOVE_FLAGS_SEND_DELETE then it will send delete
   notification to remote end. */
SshIkeErrorCode ssh_ike_remove_isakmp_sa(SshIkeNegotiation negotiation,
                                         SshUInt32 connect_flags);

#define SSH_IKE_REMOVE_FLAGS_SEND_DELETE                0x0001
#define SSH_IKE_REMOVE_FLAGS_FORCE_DELETE_NOW           0x0002
#define SSH_IKE_REMOVE_FLAGS_MATCH_OTHER_BY_REMOTE_ID   0x0004

/* Mark ISAKMP SA of given negotiation in given ip address and port to be
   deleted. This does not delete the ISAKMP SA immediately, but inserts
   immediate timer to remove the negotiation, it also marks the SA so that it
   will not be selected by ssh_ike_connect_* routines anymore. This can be
   safely called anywhere. If ip address is NULL then it means all ip
   addresses, and if port number is NULL then it means all port addresses. If
   connect_flags is SSH_IKE_REMOVE_FLAGS_SEND_DELETE then it will send delete
   notification to remote end. */
SshIkeErrorCode
ssh_ike_remove_isakmp_sa_by_address(SshIkeContext context,
                                    const unsigned char *local_name,
                                    const unsigned char *local_port,
                                    const unsigned char *remote_name,
                                    const unsigned char *remote_port,
                                    SshUInt32 connect_flags);

/* Delete all other ISAKMP SA's than the given ISAKMP SA connected to the same
   host. This can be used by the policy code to clear out old ISAKMP SA's when
   INITIAL CONTACT notification is received. If connect_flags is
   SSH_IKE_REMOVE_FLAGS_SEND_DELETE then it will send delete notification to
   remote end.

   If the SSH_IKE_REMOVE_FLAGS_MATCH_OTHER_BY_REMOTE_ID is used then the match
   whether the host are same is detected by comparing the remote_id's instead
   of ip- and port-numbers. This works even when the hosts are behind NAT and
   the ip- and port-numbers might have changed. */
SshIkeErrorCode ssh_ike_remove_other_isakmp_sas(SshIkeNegotiation negotiation,
                                                SshUInt32 connect_flags);

/* Convert error code to string. */
const char *ssh_ike_error_code_to_string(SshIkeNotifyMessageType code);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Start configuration exchange with some other host. Returns error code if
   error occurs when sending first packet, and does NOT call notify callback,
   or allocate or free anything. Otherwise return allocated SshIkeNegotiation
   structure in negotiation parameter that can be used to clear state later. If
   there is no isakmp SA already negotiated and
   SSH_IKE_CFG_FLAGS_WANT_ISAKMP_SA is given then this function will return
   SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND and does not do anything. If the error
   occurs when sending the first packet but after it has already changed the
   data given to it, it will call the callback, free the data, return
   SSH_IKE_ERROR_OK, but set returned negotiation pointer to NULL.

   If error occurs later the notify_callback function is called and context is
   added to freelist (it will be automatically freed later when retransmit
   timeout is expired, and other end cannot send more packets).

   If isakmp_sa_negotiation is given then it is assumed to be ISAKMP SA
   negotiation pointer returned by previous ssh_ike_connect call. If that
   pointer is no longer valid SSH_IKE_ERROR_NO_ISAKMP_SA_FOUND error is
   returned.

   If isakmp_sa_negotiation is NULL, then the remote_name, and remote_port are
   used to find matching isakmp SA. They are not freed in the ISAKMP library,
   and caller is allowed to free them immediately when this call returns.

   The attributes contains attribute payload to send to other end. It is freed
   by isakmp code after they are not needed anymore.

   The attribute table is assumed to be allocated with one malloc so freeing
   that table will free both the tables and the data.

   When configuration mode negotiation is done, the notify_callback will be
   called with returned attributes, or with error code if the negotiation
   failed.

   The policy_manager_data pointer is stored in the policy manager information
   structure in the policy_manager_data field.

   Flags can be any combination of the compat flags (SSH_IKE_FLAGS_*) or'ed
   together. */
SshIkeErrorCode ssh_ike_connect_cfg(SshIkeServerContext context,
                                    SshIkeNegotiation *negotiation,
                                    SshIkeNegotiation isakmp_sa_negotiation,
                                    /* Destination address */
                                    const unsigned char *remote_name,
                                    /* May be NULL == use default (500) */
                                    const unsigned char *remote_port,
                                    int number_of_attr_payloads,
                                    SshIkePayloadAttr *attributes,
                                    void *policy_manager_data,
                                    SshUInt32 connect_flags,
                                    SshIkeCfgNotify notify_callback,
                                    void *notify_callback_context);

#define SSH_IKE_CFG_FLAGS_WANT_ISAKMP_SA                0x00010000

#endif /* SSHDIST_ISAKMP_CFG_MODE */

/*                                                              shade{0.9}
 *
 * isakmp_da.c prototypes
 *                                                              shade{1.0}
 */

/* Decode data attribute length. Returns number of bytes used by this
   attribute. Assumes the buffer have at least 4 bytes. */
size_t ssh_ike_decode_data_attribute_size(const unsigned char *buffer,
                                          SshUInt32 flags);

/* Decode data attribute, and fill attribute_filled structure with pointer
   to buffer given to it. Note this doesn't allocate buffer for data, nor
   it copies data anywhere, it will just return pointer to buffer given to it.
   The attribute value is valid as long as the buffer given to this function is
   valid. Return false if error occured (not enough data in buffer etc).
   If used_bytes is non null the number of used bytes is stored there. */
Boolean ssh_ike_decode_data_attribute(unsigned char *buffer,
                                      size_t buffer_len,
                                      size_t *used_bytes,
                                      SshIkeDataAttribute attribute_filled,
                                      SshUInt32 flags);

/* Decode data attribute, sets the value_return to data value and returns
   true. If the value cannot be represented in 32 bit integer, return
   false. */
Boolean ssh_ike_decode_data_attribute_int(const unsigned char *buffer,
                                          size_t buffer_len,
                                          SshUInt16 *type_return,
                                          SshUInt32 *value_return,
                                          SshUInt32 flags);

/* Read 32 bit integer from data attribute. If the value cannot be represented
 * in 32 bit integer, return false. */
Boolean ssh_ike_get_data_attribute_int(SshIkeDataAttribute da,
                                       SshUInt32 *value_return,
                                       SshUInt32 flags);

/* Encode data attribute and append it to buffer. Returns number of bytes
   appended to buffer. Returns -1 in case of error. */
size_t ssh_ike_encode_data_attribute(SshBuffer buffer,
                                     SshIkeDataAttribute attribute,
                                     SshUInt32 flags);

/* Encode integer as data attribute and append it to buffer. Returns number of
   bytes appended to buffer. If use_16_bits is true then value is encoded as 16
   bit number, otherwise it is encoded as 32 bit number. Returns -1 in case of
   error (value to big to be represented as 16 bit value). */
size_t ssh_ike_encode_data_attribute_int(SshBuffer buffer,
                                         SshUInt16 type,
                                         Boolean use_16_bits,
                                         SshUInt32 attribute,
                                         SshUInt32 flags);

/*                                                              shade{0.9}
 *
 * isakmp_id.c prototypes
 *                                                              shade{1.0}
 */

/* Convert id-structure to string. The function returns pointer to
 * buffer (that is guaranteed to be C string */
char *ssh_ike_id_to_string(char *buffer,
                           size_t buflen,
                           SshIkePayloadID id);

/* Convert string to id-structure. The function allocates the new id
   from heap. */
SshIkePayloadID ssh_ike_string_to_id(unsigned char *string);

/* Renderer function for an id-structure.  This can be used with the
   ssh_snprintf and ssh_vsnprintf functions to render an
   SshIkePayloadID to a print buffer. */
int ssh_ike_id_render(unsigned char *buf, int buf_size, int precision,
                      void *datum);

/* Renderer function for an id-structure.  This works like
   ssh_ike_id_render but it only prints the textual presentation of
   the id.  it does not print the type of the ID or its length.  This
   can be used with the ssh_snprintf and ssh_vsnprintf functions to
   render an SshIkePayloadID to a print buffer. */
int ssh_ike_id_render_short(unsigned char *buf, int buf_size,
                            int precision, void *datumn);

/* Decode ID from `id' into subfields.

   Upon successful return the `name1' will contain printed copy of the
   address for fields of ip-address types, or the domain name for
   fqdn, or user-name for user-fqdn, or the ASN1 data for DN, and GN
   types, or key-id.

   The `name2' will contain subnet or end or range addresses for
   ip-types and the domain-name for user-fqdn type.

   The arguments `name1_len' and `name2_len' indicate the space
   reserved by the upper level, and they will be set to indicate the
   space actually used.

   The function returns TRUE on success. Even in case of failure the
   function may modify values pointed by arguments. */
Boolean ssh_ike_id_decode(SshIkePayloadID id,
                          SshIkeIpsecIdentificationType *type,
                          SshIkeIpsecIPProtocolID *proto,
                          SshUInt16 *port,
                          SshUInt16 *port_range_end,
                          unsigned char *name1, size_t *name1_len,
                          unsigned char *name2, size_t *name2_len);

/* Function fills the given id with given arguments. The base ID must
   have been allocated by the caller. The subfields will be allocated
   by this function.
   Arguments `name1' and `name2' are treated as on function
   ssh_ike_id_decode().  The input `name1' for ASN1 types or KEY-ID's
   must be a hexadecimal string and it will be decoded into binary
   blob used internally */
Boolean ssh_ike_id_encode(SshIkePayloadID id,
                          SshIkeIpsecIdentificationType type,
                          SshIkeIpsecIPProtocolID proto,
                          SshUInt16 port,
                          SshUInt16 port_range_end,
                          const unsigned char *name1,
                          const unsigned char *name2);

/* Function returns hash of the given ID. */
SshUInt32 ssh_ike_id_hash(SshIkePayloadID id);

/* Compares two ID's. Returns true if they print the same. */
Boolean ssh_ike_id_compare(SshIkePayloadID id1,
                           SshIkePayloadID id2);

/* Copy id `from' to user reserved space provided at `to'. The
   subfield (if any) will be allocated by this function, only the base
   id at `to' must be allocated by the caller. Return TRUE if successfull and
   FALSE if it runs out of memory or some other error occurs. */
Boolean ssh_ike_id_copy(SshIkePayloadID from, SshIkePayloadID to);

/* Function returns a ssh_malloc()'d copy of id given as argument */
SshIkePayloadID ssh_ike_id_dup(SshIkePayloadID id);

/* Deallocate ID and its subfields. The ID must reside on mallocated
   address space */
void
ssh_ike_id_free(SshIkePayloadID id);


/* Free sa payload. */
void ssh_ike_free_sa_payload(SshIkePayloadSA sa);

/* Check that spi value is ok. */
SshIkeNotifyMessageType ssh_ike_check_isakmp_spi(size_t spi_size,
                                                 unsigned char *spi,
                                                 unsigned char *cookie);

/* Reset SshIkeAttributes to default values. */
void ssh_ike_clear_isakmp_attrs(SshIkeAttributes attrs);

/* Read SshIkeAttributes from data attributes of the transform payload and fill
 * attrs structure. Return FALSE if error (== unsupported values in the data
 * attributes). */
Boolean ssh_ike_read_isakmp_attrs(SshIkeNegotiation negotiation,
                                  SshIkePayloadT trans,
                                  SshIkeAttributes attrs);

/* Reset SshIpsecAttributes to default values. */
void ssh_ike_clear_ipsec_attrs(SshIkeIpsecAttributes attrs);


/* Read SshIkeIpsecAttributes from data attributes of the transform payload and
 * fill attrs structure. Return FALSE if error (== unsupported values in the
 * data attributes). */
Boolean ssh_ike_read_ipsec_attrs(SshIkeNegotiation negotiation,
                                 SshIkePayloadT trans,
                                 SshIkeIpsecAttributes attrs);

/* Reset SshIkeGrpAttributes to default values. */
void ssh_ike_clear_grp_attrs(SshIkeGrpAttributes attrs);

/* Free SshIkeGrpAttributes structure. */
void ssh_ike_free_grp_attrs(SshIkeGrpAttributes attrs);

/* Read SshIkeGrpAttributes from data attributes of the transform payload and
 * fill attrs structure. Return FALSE if error (== unsupported values in the
 * data attributes). */
Boolean ssh_ike_read_grp_attrs(SshIkeNegotiation negotiation,
                               SshIkePayloadT trans,
                               SshIkeGrpAttributes attrs);

/* Add new group to the group table as predefined one. */
Boolean ike_add_default_group(SshIkeContext isakmp_context, int descriptor,
                              SshPkGroup group);

/*                                                              shade{0.9}
 * Isakmp tables external variables                             shade{1.0}
 */
extern const SshKeywordStruct ssh_ike_status_keywords[];
extern const SshKeywordStruct ssh_ike_encryption_key_lengths_keywords[];
extern const SshKeywordStruct ssh_ike_encryption_weak_key_check_keywords[];
extern const SshKeywordStruct ssh_ike_encryption_algorithms[];
extern const SshKeywordStruct ssh_ike_hash_algorithms[];
extern const SshKeywordStruct ssh_ike_hmac_prf_algorithms[];
extern const SshKeywordStruct ssh_ike_prf_algorithms[];

extern const SshKeywordStruct ssh_ike_ipsec_encapsulation_modes[];
extern const SshKeywordStruct ssh_ike_ipsec_auth_algorithms[];
extern const SshKeywordStruct ssh_ike_ipsec_ah_transforms[];
extern const SshKeywordStruct ssh_ike_ipsec_esp_transforms[];
extern const SshKeywordStruct ssh_ike_ipsec_ipcomp_transforms[];
extern const SshKeywordStruct ssh_ike_ipsec_longseq_values[];

extern const SshKeywordStruct ssh_ike_id_type_keywords[];
extern const SshKeywordStruct ssh_ike_xchg_type_keywords[];
#ifdef DEBUG_LIGHT
extern const SshKeywordStruct ssh_ike_state_name_keywords[];
extern const SshKeywordStruct ssh_ike_state_input_funcs_keywords[];
extern const SshKeywordStruct ssh_ike_state_output_funcs_keywords[];
#endif /* DEBUG_LIGHT */

/* Statistics interface */
typedef struct SshIkeSAStatisticsRec {
  SshUInt32 packets_in;         /* Packets in, including retransmissions */
  SshUInt32 packets_out;        /* Packets out, including retransmissions */
  SshUInt32 octects_in;         /* Bytes in, including retransmissions */
  SshUInt32 octects_out;        /* Bytes out, including retransmissions */

  SshUInt32 created_suites;     /* Number of IPsec SAs created using this SA */
  SshUInt32 deleted_suites;     /* Number of IPsec SAs deleted using this SA,
                                   actually number of delete payloads
                                   received. */
} *SshIkeSAStatistics, SshIkeSAStatisticsStruct;

typedef struct SshIkeStatisticsRec {
  SshIkePMPhaseI pm_info;       /* Policy manager informational structure */
  Boolean phase_1_done;         /* Is the phase 1 negotiation done */
  int number_of_negotiations;   /* Number of negotiations in progress */
  int private_groups_count;     /* Number of private groups defined */
  unsigned long byte_count;     /* Byte count of data transmitted using this
                                   ISAKMP SA */
  SshTime created_time;          /* When was this sa created */
  SshTime last_use_time;         /* When was this sa last used */
  SshIkeSAStatisticsStruct statistics; /* Global SA statistics */

  const unsigned char *encryption_algorithm_name;
                                /* Name of the encryption algorithm */
  SshUInt32 encryption_key_length; /* Key length in bytes. */
  const unsigned char *hash_algorithm_name; /* Name of the hash algorithm */
  const unsigned char *prf_algorithm_name; /* Name of the PRF algorithm */

  /* Defaults for this SA */
  SshInt32 default_retry_limit; /* Number of retries */
  SshInt32 default_retry_timer; /* Retry timer (in seconds) */
  SshInt32 default_retry_timer_usec; /* Retry timer (in useconds) */
  SshInt32 default_retry_timer_max; /* Max retry timer (in seconds) */
  SshInt32 default_retry_timer_max_usec; /* Max retry timer (in useconds) */
  SshInt32 default_expire_timer; /* Expire timer (in seconds) */
  SshInt32 default_expire_timer_usec; /* Expire timer (in useconds) */

  Boolean caller_notification_sent; /* Is the caller program callback already
                                       done. */
  Boolean waiting_for_done;     /* If this is set, then the negotiation is
                                   done, and the library is waiting the other
                                   ends retransmission timers to expire. */
  Boolean waiting_for_remove;   /* If this is set, then the negotiation is
                                   failed, and the library is waiting the other
                                   ends retransmission timers to expire before
                                   removing this negotiation. */
  Boolean waiting_for_policy_manager; /* If this is set, then the negotiation
                                         is waiting for the responce from the
                                         policymanager, and cannot do anything
                                         before that. */
} *SshIkeStatistics, SshIkeStatisticsStruct;

/* This function is called for each Phase I SA. The statistics is filled with
   the statistics information of the Phase I (ISAKMP) SA. If this function
   returns FALSE, then the whole ssh_ike_foreach_isakmp_sa operation is
   aborted. This function can also be used to abort / remove given negotiation.
   */
typedef Boolean (*SshIkeStatisticsCB)(SshIkeNegotiation negotiation,
                                      SshIkeStatistics statistics,
                                      void *context);

/* ssh_ike_foreach_isakmp_sa will call given callback for each ISAKMP SA. */
void ssh_ike_foreach_isakmp_sa(SshIkeServerContext server_context,
                               SshIkeStatisticsCB callback,
                               void *context);

typedef struct SshIkeNegotiationStatisticsRec {
  Boolean quick_mode;           /* If this is true, then the negotiation is
                                   quick mode, and the qm_pm_info is valid,
                                   otherwise the phaseii_pm_info is valid.  */
  SshIkePMPhaseQm quick_mode_pm_info; /* Policy mgr. informational structure */
  SshIkePMPhaseII phaseii_pm_info; /* Policy manager informational structure */

  Boolean caller_notification_sent; /* Is the caller program callback already
                                       done. */
  Boolean waiting_for_done;     /* If this is set, then the negotiation is
                                   done, and the library is waiting the other
                                   ends retransmission timers to expire. */
  Boolean waiting_for_remove;   /* If this is set, then the negotiation is
                                   failed, and the library is waiting the other
                                   ends retransmission timers to expire before
                                   removing this negotiation. */
  Boolean waiting_for_policy_manager; /* If this is set, then the negotiation
                                         is waiting for the responce from the
                                         policymanager, and cannot do anything
                                         before that. */
} *SshIkeNegotiationStatistics;

/* This function is called for each negotiation inside Phase I SA. The
   statistics is filled with the statistics information of the Phase II (QM,
   NGM or Informational) negotiation. If this function returns FALSE, then the
   whole ssh_ike_foreach_negotiation operation is aborted. */
typedef Boolean (*SshIkeNegotiationStatisticsCB)(SshIkeNegotiation negotiation,
                                                 SshIkeNegotiationStatistics
                                                 statistics,
                                                 void *context);

/* ssh_ike_foreach_isakmp_sa will call given callback for each negotiation
   inside one ISAKMP SA. */
void ssh_ike_foreach_negotiation(SshIkeNegotiation negotiation,
                                 SshIkeNegotiationStatisticsCB callback,
                                 void *context);

/* Finds ISAKMP SA related to given negotiation and fills in the
   SshIkeStatistics structure for it. */
SshIkeErrorCode ssh_ike_isakmp_sa_statistics(SshIkeNegotiation negotiation,
                                             SshIkeStatistics statistics);


/* Global IKE statistics, for server, all statistics are since the IKE server
   was started.

   This needs to be kept in sync with SshIkev2GlobalStatistics at IKEv2
   library. */
typedef struct SshIkeGlobalStatisticsRec {
  /* Total number of successful IKE SAs since server was started, the IKE SA is
     counted to the server where it is when the it finishes. */
  SshUInt32 total_ike_sas;              /* Total number of IKE SAs */
  SshUInt32 total_ike_sas_initiated;    /* Total number of IKE SAs,initiated */
  SshUInt32 total_ike_sas_responded;    /* Total number of IKE SAs,responded */

  /* Attempts (includes failures and those in progress). */
  SshUInt32 total_attempts;             /* Total number attempted */
  SshUInt32 total_attempts_initiated;   /* Total number attempted, initiated */
  SshUInt32 total_attempts_responded;   /* Total number attempted, responded */

  /* Total packet counts, includes retransmissions */
  SshUInt32 total_packets_in;           /* Total number of packets in */
  SshUInt32 total_packets_out;          /* Total number of packets out */
  SshUInt32 total_octets_in;            /* Total number of octets in */
  SshUInt32 total_octets_out;           /* Total number of octets out */
  SshUInt32 total_retransmits;         /** Total number of
                                           retransmitted packets.  */
  SshUInt32 total_discarded_packets;   /** Total number of packets
                                           discarded because IKEv2 library
                                           was suspended when it was
                                           received. */
  /* Failures, no responses etc. */
  SshUInt32 total_init_failures;        /* Total number of negotiations, which
                                           we initiated, that failed because of
                                           error. */
  SshUInt32 total_init_no_response;     /* Total number of negotiations, which
                                           we initiated, that failed, because
                                           of initial timeout. */
  SshUInt32 total_resp_failures;        /* Total number of negotiations, which
                                           we responded to, that failed because
                                           of error. */
  /* Current number of IKE SAs */
  SshUInt32 current_ike_sas;            /* Number of IKE SAs */
  SshUInt32 current_ike_sas_initiated;  /* Number of IKE SAs, initiated */
  SshUInt32 current_ike_sas_responded;  /* Number of IKE SAs, responded */

} *SshIkeGlobalStatistics, SshIkeGlobalStatisticsStruct;

/* Fills statistics with current ike library global statistics. */
void ssh_ike_global_statistics(SshIkeServerContext server,
                               SshIkeGlobalStatistics statistics);

/* Sets private payload handlers for IKE SA, used in the negotiation. These
   handers will be inherited to all new negotiations for that SA. */
void ssh_ike_sa_private_payload_handlers(SshIkeNegotiation negotiation,
                                         SshIkePrivatePayloadPhaseICheck
                                         private_payload_phase_1_check,
                                         SshIkePrivatePayloadPhaseIIn
                                         private_payload_phase_1_in,
                                         SshIkePrivatePayloadPhaseIOut
                                         private_payload_phase_1_out,
                                         SshIkePrivatePayloadPhaseIICheck
                                         private_payload_phase_2_check,
                                         SshIkePrivatePayloadPhaseIIIn
                                         private_payload_phase_2_in,
                                         SshIkePrivatePayloadPhaseIIOut
                                         private_payload_phase_2_out,
                                         SshIkePrivatePayloadPhaseQmCheck
                                         private_payload_phase_qm_check,
                                         SshIkePrivatePayloadPhaseQmIn
                                         private_payload_phase_qm_in,
                                         SshIkePrivatePayloadPhaseQmOut
                                         private_payload_phase_qm_out,
                                         void *private_payload_context);

/* Sets private payload handlers for phase 1 negotiation. */
void ssh_ike_phase_i_private_payload_handlers(SshIkeNegotiation negotiation,
                                              SshIkePrivatePayloadPhaseICheck
                                              private_payload_phase_1_check,
                                              SshIkePrivatePayloadPhaseIIn
                                              private_payload_phase_1_in,
                                              SshIkePrivatePayloadPhaseIOut
                                              private_payload_phase_1_out,
                                              void *private_payload_context);


/* Sets private payload handlers for phase 2 negotiation. */
void ssh_ike_phase_ii_private_payload_handlers(SshIkeNegotiation negotiation,
                                               SshIkePrivatePayloadPhaseIICheck
                                               private_payload_phase_2_check,
                                               SshIkePrivatePayloadPhaseIIIn
                                               private_payload_phase_2_in,
                                               SshIkePrivatePayloadPhaseIIOut
                                               private_payload_phase_2_out,
                                               void *private_payload_context);

/* Sets private payload handlers for quick mode negotiation. */
void ssh_ike_qm_private_payload_handlers(SshIkeNegotiation negotiation,
                                         SshIkePrivatePayloadPhaseQmCheck
                                         private_payload_phase_qm_check,
                                         SshIkePrivatePayloadPhaseQmIn
                                         private_payload_phase_qm_in,
                                         SshIkePrivatePayloadPhaseQmOut
                                         private_payload_phase_qm_out,
                                         void *private_payload_context);

#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
/* This structure contains all the policy manager functions. See the
   isakmp_policy.h for the documentation of each function. */

typedef struct SshIkePolicyFunctionsRec {
  void (*new_connection)(SshIkePMPhaseI pm_info,
                         SshPolicyNewConnectionCB callback_in,
                         void *callback_context_in);
  void (*new_connection_phase_ii)(SshIkePMPhaseII pm_info,
                                  SshPolicyNewConnectionCB callback_in,
                                  void *callback_context_in);
  void (*new_connection_phase_qm)(SshIkePMPhaseQm pm_info,
                                  SshPolicyNewConnectionCB callback_in,
                                  void *callback_context_in);
  void (*find_pre_shared_key)(SshIkePMPhaseI pm_info,
                              SshPolicyFindPreSharedKeyCB callback_in,
                              void *callback_context_in);
#ifdef SSHDIST_IKE_CERT_AUTH
  void (*find_public_key)(SshIkePMPhaseI pm_info,
                          SshPolicyKeyType key_type_in,
                          const unsigned char *hash_alg_in,
                          SshPolicyFindPublicKeyCB callback_in,
                          void *callback_context_in);
  void (*find_private_key)(SshIkePMPhaseI pm_info,
                           SshPolicyKeyType key_type,
                           const unsigned char *hash_alg_in,
                           const unsigned char *hash_in,
                           size_t hash_len_in,
                           SshPolicyFindPrivateKeyCB callback_in,
                           void *callback_context_in);
  void (*new_certificate)(SshIkePMPhaseI pm_info,
                          SshIkeCertificateEncodingType cert_encoding,
                          unsigned char *certificate_data,
                          size_t certificate_data_len);
  void (*request_certificates)(SshIkePMPhaseI pm_info,
                               int number_of_cas,
                               SshIkeCertificateEncodingType
                               *ca_encodings,
                               unsigned char **certificate_authorities,
                               size_t *certificate_authority_lens,
                               SshPolicyRequestCertificatesCB
                               callback_in,
                               void *callback_context_in);
  void (*get_certificate_authorities)(SshIkePMPhaseI pm_info,
                                      SshPolicyGetCAsCB callback_in,
                                      void *callback_context_in);
#endif /* SSHDIST_IKE_CERT_AUTH */
  void (*isakmp_nonce_data_len)(SshIkePMPhaseI pm_info,
                                SshPolicyNonceDataLenCB callback_in,
                                void *callback_context_in);
  void (*isakmp_id)(SshIkePMPhaseI pm_info,
                    SshPolicyIsakmpIDCB callback_in,
                    void *callback_context_in);
  void (*isakmp_vendor_id)(SshIkePMPhaseI pm_info,
                           unsigned char *vendor_id,
                           size_t vendor_id_len);
  void (*isakmp_request_vendor_ids)(SshIkePMPhaseI pm_info,
                                    SshPolicyRequestVendorIDsCB
                                    callback_in,
                                    void *callback_context_in);
  void (*isakmp_select_sa)(SshIkePMPhaseI pm_info,
                           SshIkeNegotiation negotiation,
                           SshIkePayload sa_in,
                           SshPolicySACB callback_in,
                           void *callback_context_in);
  void (*ngm_select_sa)(SshIkePMPhaseII pm_info,
                        SshIkeNegotiation negotiation,
                        SshIkePayload sa_in,
                        SshPolicySACB callback_in,
                        void *callback_context_in);
  void (*qm_select_sa)(SshIkePMPhaseQm pm_info,
                       SshIkeNegotiation negotiation,
                       int number_of_sas_in,
                       SshIkePayload *sa_table_in,
                       SshPolicyQmSACB callback_in,
                       void *callback_context_in);
  void (*qm_nonce_data_len)(SshIkePMPhaseQm pm_info,
                            SshPolicyNonceDataLenCB callback_in,
                            void *callback_context_in);
  void (*qm_local_id)(SshIkePMPhaseQm pm_info,
                      SshPolicyIsakmpIDCB callback_in,
                      void *callback_context_in);
  void (*qm_remote_id)(SshIkePMPhaseQm pm_info,
                       SshPolicyIsakmpIDCB callback_in,
                       void *callback_context_in);
#ifdef SSHDIST_ISAKMP_CFG_MODE
  void (*cfg_fill_attrs)(SshIkePMPhaseII pm_info,
                         int number_of_attrs,
                         SshIkePayloadAttr *return_attributes,
                         SshPolicyCfgFillAttrsCB callback_in,
                         void *callback_context_in);
  void (*cfg_notify_attrs)(SshIkePMPhaseII pm_info,
                           int number_of_attrs,
                           SshIkePayloadAttr *return_attributes);
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  void (*delete_notification)(SshIkePMPhaseII pm_info,
                              Boolean authenticated,
                              SshIkeProtocolIdentifiers protocol_id,
                              int number_of_spis,
                              unsigned char **spis,
                              size_t spi_size);
  void (*notification)(SshIkePMPhaseII pm_info,
                       Boolean authenticated,
                       SshIkeProtocolIdentifiers protocol_id,
                       unsigned char *spi,
                       size_t spi_size,
                       SshIkeNotifyMessageType notify_message_type,
                       unsigned char *notification_data,
                       size_t notification_data_size);
  void (*phase_i_notification)(SshIkePMPhaseI pm_info,
                               Boolean encrypted,
                               SshIkeProtocolIdentifiers protocol_id,
                               unsigned char *spi,
                               size_t spi_size,
                               SshIkeNotifyMessageType
                               notify_message_type,
                               unsigned char *notification_data,
                               size_t notification_data_size);
  void (*phase_qm_notification)(SshIkePMPhaseQm pm_info,
                                SshIkeProtocolIdentifiers protocol_id,
                                unsigned char *spi,
                                size_t spi_size,
                                SshIkeNotifyMessageType
                                notify_message_type,
                                unsigned char *notification_data,
                                size_t notification_data_size);
  void (*isakmp_sa_freed)(SshIkePMPhaseI pm_info);
  void (*qm_sa_freed)(SshIkePMPhaseQm pm_info);
  void (*phase_ii_sa_freed)(SshIkePMPhaseII pm_info);
  void (*negotiation_done_isakmp)(SshIkePMPhaseI pm_info,
                                  SshIkeNotifyMessageType code);
  void (*negotiation_done_qm)(SshIkePMPhaseQm pm_info,
                              SshIkeNotifyMessageType code);
  void (*negotiation_done_phase_ii)(SshIkePMPhaseII pm_info,
                                    SshIkeNotifyMessageType code);
#ifdef SSHDIST_IKE_CERT_AUTH
  void (*certificate_request)(SshIkePMPhaseI pm_info,
                              SshIkeCertificateEncodingType cert_encoding,
                              unsigned char *certificate_data,
                              size_t certificate_data_len);
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. If the was encrypted it is decrypted first. This is called before
   any authentication checks is done, thus it might be better to postpone the
   actual changing of the server to the private_payload_phase_1_{input,output}
   function. */
  void (*phase_i_server_changed)(SshIkePMPhaseI pm_info,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port);

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. This is called before any authentication checks is done, thus it
   might be better to postpone the actual changing of the server to the
   private_payload_phase_qm_output function.

   This is not called if new quick mode exchange initially starts using
   different ip or port than the IKE SA. This is called if the initial quick
   mode exchange initially starts using different server than the IKE SA. In
   that case this is called after the new_connection callback. */
  void (*phase_qm_server_changed)(SshIkePMPhaseQm pm_info,
                                  SshIkeServerContext new_server,
                                  const unsigned char *new_remote_ip,
                                  const unsigned char *new_remote_port);

/* Policy manager function called when source and destination ip or ports does
   not match the ones stored to the negotiation. Note, that any of the
   new_server, new_remote_ip, new_remote_port can stay same, but at least one
   of them has been changed when this is called. This call should call the
   ssh_ike_sa_change_server if it wants the change to new address to take
   effect. Note, that this information is never really authenticated, the ip
   address and port numbers are not covered by the any authentication inside
   the IKE. This is called before any authentication checks is done.

   This is not called if new phase ii exchange initially starts using different
   ip or port than the IKE SA. This is called if the initial phase ii exchange
   initially starts using different server than the IKE SA. In that case this
   is called after the new_connection callback. */
  void (*phase_ii_server_changed)(SshIkePMPhaseII pm_info,
                                  SshIkeServerContext new_server,
                                  const unsigned char *new_remote_ip,
                                  const unsigned char *new_remote_port);

} *SshIkePolicyFunctions, SshIkePolicyFunctionsStruct;

/* Register policy manager functions to the isakmp_library. This will take
   reference to the `functions' structure, and that structure must be valid
   as long as the ike server is in use (i.e until the ssh_ike_uninit function
   is called. This function must be called before the any ssh_ike_start_server
   functions are called. */
void ssh_ike_register_policy_functions(SshIkeContext ike_context,
                                       SshIkePolicyFunctions functions);
#endif /*  SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */

/* Update the IKE responder cookie for the ISAKMP negotiation
   'negotiation' with the value supplied in 'ike_spi_r'. 'ike_spi_r'
   points to a buffer of SSH_IKE_COOKIE_LENGTH bytes. This may not be
   called by the policy implementation after the ISAKMP has responded
   to the intitial ISAKMP packet from the initiator. Returns TRUE on success
   and FALSE otherwise. */
Boolean
ssh_isakmp_update_responder_cookie(SshIkeNegotiation negotiation,
                                   const unsigned char *ike_spi_r);

#endif /* ISAKMP_H */
