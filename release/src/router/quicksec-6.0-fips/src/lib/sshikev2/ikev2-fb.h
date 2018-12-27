/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ikev2-fb.h
*/

#ifndef IKEV2_FB_H
#define IKEV2_FB_H

#include "sshincludes.h"

#include "isakmp.h"
#include "isakmp_policy.h"
#include "isakmp_doi.h"

#include "sshikev2-sad.h"
#include "sshikev2-pad.h"
#include "sshikev2-spd.h"
#include "sshikev2-exchange.h"
#include "sshikev2-fallback.h"

#include "ikev2-internal.h"

/* This is the handle to the single ISAKMP negotiation within the
   SshIkev2Fallback policy manager */
typedef struct SshIkev2FbNegotiationRec *SshIkev2FbNegotiation;

struct SshIkev2FbRec
{
  /* Pointer to the IKEv1 global context */
  SshIkeContext ikev1;

  /* Policy manager context, only the upper context is used, and it points
     to the fallback structure. */
  struct SshIkePMContextRec pm[1];

  /* Parameters set by the IKEv2 policy manager */
  SshIkev2FallbackParamsStruct params;

  /* Freelist of negotiation structures */
  SshIkev2FbNegotiation negotiation_freelist;

  /* Number of active aggressive mode responder negotiations.
     Used for limiting the rate of simultaneous responder
     aggressive mode negotiations. */
  SshUInt32 num_aggr_mode_responder_active;

  /* Ikev1 retry limit values. These are copied from SshIkeContext
     after isakmp library is initialized and they are not reconfigurable. */
  SshUInt32 base_retry_limit; /* Retransmit count limit. */
  SshUInt32 base_expire_timer_msec; /* Negotiation expiry timer. */
  SshUInt32 base_retry_timer_msec; /* Initial retransmit interval. */
  SshUInt32 base_retry_timer_max_msec; /* Maximum retransmit interval. */

  /* Fallback Policy Manager has its own FSM to increase
     modularity. We could easily share the FSM with IKEv2, but this
     way we can more easily assert that all our threads are gone when
     shutting down, and possibly later prioritize IKEv2 operations
     over IKEv1 */
  SshFSMStruct fsm[1];

#ifdef SSHDIST_IKE_XAUTH
  /* Extented authentication for server. */
  SshIkev2FbXauth xauth_callback;
  void *xauth_callback_context;

  /* Extented authentication for client. */
  SshIkev2FbXauthRequest xauth_client_request_callback;
  SshIkev2FbXauthSet xauth_client_set_callback;
  void *xauth_client_callback_context;
#endif /* SSHDIST_IKE_XAUTH */
};


struct SshIkev2FbCallbacksRec
{
  union {
    SshPolicyNewConnectionCB new_connection;
    SshPolicyRequestVendorIDsCB request_vid;
    SshPolicySACB sa;
    SshPolicyFindPreSharedKeyCB find_pre_shared_key;
    SshPolicyIsakmpIDCB id;
#ifdef SSHDIST_IKE_CERT_AUTH
    SshPolicyFindPublicKeyCB find_public_key;
    SshPolicyFindPrivateKeyCB find_private_key;
    SshPolicyRequestCertificatesCB request_certs;
    SshPolicyGetCAsCB get_cas;
#endif /* SSHDIST_IKE_CERT_AUTH */
    SshPolicyQmSACB qm_sa;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    SshPolicyCfgFillAttrsCB cfg_fill_attrs;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
    SshPolicyPrivatePayloadOutCB private_out;
  } u;
  void *callback_context;
  SshOperationHandleStruct operation[1];
};

typedef struct SshIkev2FbCallbacksRec *SshIkev2FbCallbacks;
typedef struct SshIkev2FbCallbacksRec  SshIkev2FbCallbacksStruct;

typedef enum
{
  SSH_IKEV2_FB_NAT_D_STATE_LOCAL = 0,
  SSH_IKEV2_FB_NAT_D_STATE_REMOTE = 1
} SshIkev2FbNatDState;

struct SshIkev2FbNatTInfoRec
{
  SshIkeServerContext server;
  Boolean use_natt;
  SshIpAddrStruct remote_ip;
  SshUInt16 remote_port;
};

typedef struct SshIkev2FbNatTInfoRec *SshIkev2FbNatTInfo;
typedef struct SshIkev2FbNatTInfoRec  SshIkev2FbNatTInfoStruct;

struct SshIkev2FbNegotiationRec
{
  SshIkev2Fb fb;

  /* Reference count. One reference is taken for the negotiation main thread,
     one reference for each negotiation sub thread, and one reference for the
     isakmp library (in `pm_info->policy_manager_data'). */
  SshUInt8 ref_count;

  SshIkev2Server server;

  SshIkev2Sa ike_sa;
  SshIkev2Sa old_ike_sa; /* Used during rekeys initiated by
                            ipsec_connect() */

  SshIkev2ExchangeData ed;

  /* Return error code from IKEv2 policy calls */
  SshIkev2Error ike_error;

  /* IKEv1 notification for logging purposes */
  SshIkeNotifyMessageType v1_error;

  /* The main thread for this negotiation */
  SshFSMThreadStruct thread[1];

  /* A sub-thread for handling specific IKE policy calls */
  SshFSMThreadStruct sub_thread[1];
  SshOperationHandle sub_operation;

  SshTimeoutStruct dpd_timeout[1];
  SshUInt16 dpd_timer_msec;
  SshUInt8 dpd_timer_retries;
  SshTime dpd_timer_start;

  /* Extra data extracted from IKEv1 SA payloads that are not
     expressible in IKEv2 SA payloads */
  SshIkeIpsecAttributeEncapsulationModeValues encapsulation;

  /* Selected transforms for SA handler. */
  SshIkev2PayloadTransformStruct transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX];

  /* Context data for the request vendor ID operation */
  unsigned int num_vendor_ids;
  unsigned char **vendor_ids;
  size_t *vendor_id_lens;

  /* SA payloads for the IKE/IPSec select SA operations */
  SshIkev2PayloadSA sav2;
  SshIkePayload sav1;

  /* Delayed callbacks. */
  SshIkev2FbCallbacksStruct callbacks;

  /* Next pointer on freelist */
  SshIkev2FbNegotiation next;

  /* Set if user aborted this negotiation. */
  unsigned int aborted : 1;
  unsigned int initiator : 1;
  /* Set if the IPSEC operation has been completed */
  unsigned int completed : 1;
  /* Fields specifically for Phase-I negotiations */

  /* Pointer to the IKE's Phase-1 info. */
  SshIkePMPhaseI p1_info;
  /* Pointer to the IKE's Phase-2 info. */
  SshIkePMPhaseII p2_info;

  /* Local IKEv1 identity payload */
  SshIkePayloadID ikev1_id;

  /* IKEv1 preshared key */
  unsigned char *psk;
  size_t psk_len;

#ifdef SSHDIST_IKE_CERT_AUTH
  /* Public key */
  SshPublicKey public_key;

  /* Context data for the find private key and get certificates policy calls */
  unsigned int find_private_key_op : 1;
  SshPrivateKey private_key;
  int number_of_cas;
  int number_of_certificates;
  SshIkeCertificateEncodingType *cert_encodings;
  unsigned char **certs;
  size_t *cert_lengths;
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Context data for the select IKE SA operation */
  int proposal_index;
  int *transform_index;

  unsigned int ikev1_sa_unallocated : 1; /* Set when isakmp IKE SA has not yet
                                            been allocated, but a IKEv2 SA
                                            reference is held */
  unsigned int ike_sa_done : 1; /* Set when the Phase-I is done */
  unsigned int initial_contact : 1; /* Send initial contact */
  unsigned int aggr_mode_responder : 1; /* Aggressive mode responder */

  /* The IKE SA lifetime proposed by the initiator as received by the
     responder. Not used for the initiator. */
  SshUInt32 ike_sa_life_seconds;

#ifdef SSHDIST_ISAKMP_CFG_MODE
  /****** Fields specifically for Cfg-Mode negotiations **********/
  SshIkePayloadAttr v1_conf;
  SshUInt32 v1_conf_id;
  SshIkev2PayloadConf v2_conf;
  SshIkeNegotiation cfg_negotiation;
  SshTimeoutStruct cfgmode_timeout[1];
  int cfgmode_ticks;

  unsigned int cfgmode_ticks_updated : 1;
  unsigned int cfg_done : 1;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

#ifdef SSHDIST_IKE_XAUTH
  SshIkeCfgMessageType xauth_type;
  SshIkev2FbXauthStatus xauth_status_cb;
  void *xauth_status_cb_context;

  SshIkev2FbXauthAttributes attrs;
  SshIkePayloadAttr *v1_attrs; /* the above as IKEv1 attribute payload */
#endif /* SSHDIST_IKE_XAUTH */

  /* Fields specifically for Quick-Mode negotiations */


  /* Pointer to the IKE's Phase QM info. */
  SshIkePMPhaseQm qm_info;

  /* IPCOMP SPI and algorithm ID */
  SshUInt8  ipcomp_num; /* 0-7 */
  SshUInt16 ipcomp_cpi_in;
  SshUInt16 ipcomp_cpi_out[8];
  SshUInt8  ipcomp_algs[8];
  /* Set if the QM responder selects IPComp */
  Boolean ipcomp_selected;
  /* Used as a parameter when converting IKEv1 SA paylaods to IKEv2 format. */
  Boolean ipcomp_proposals;

  SshUInt32 inbound_spi;

  unsigned int ipsec_sa_done : 1;
  unsigned int ipsec_sa_installed : 1;
  unsigned int send_responder_lifetime : 1;

  /* Context data for the QM select SA operation */
  int number_of_sas_in;
  SshIkePayload *sa_table_in;
  SshIkeIpsecSelectedSAIndexes selected;

  SshIkeNegotiation qm_negotiation;

  /* The SA lifetimes proposed by the initiator as received by the
     responder. Not used for the initiator. */
  SshUInt32 sa_life_seconds;
  SshUInt32 sa_life_kbytes;

  /* Fields specifically for Ikev1 NAT-T */
  SshIkev2FbNatTInfoStruct ike_float;
  SshIkev2FbNatDState nat_d_state;
};


/* Call Policy Manager and wait for reply. */
#define SSH_IKEV2_FB_V2_CALL(neg, func)                                 \
  SSH_DEBUG(SSH_D_LOWSTART, ("FB; Calling v2 policy function " #func)); \
  (neg)->sub_operation = (*((neg)->server->sad_interface->func))

/* Clear sub operation handle after call has completed */
#define SSH_IKEV2_FB_V2_COMPLETE_CALL(neg)                              \
  (neg)->sub_operation = NULL

/* Call Policy Manager and notify it about something, for example of
   no reply callback. */
#define SSH_IKEV2_FB_V2_NOTIFY(neg, func)                               \
  SSH_DEBUG(SSH_D_LOWSTART, ("FB; Calling v2 policy function " #func)); \
  (*((neg)->server->sad_interface->func))

/* Log IKEv1 notification */
#define SSH_IKEV2_FB_LOG_V1_ERROR(error)                                \
  if (error != SSH_IKE_NOTIFY_MESSAGE_RESERVED &&                       \
      error != SSH_IKE_NOTIFY_MESSAGE_CONNECTED)                        \
    {                                                                   \
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_INFORMATIONAL,      \
                    "  IKEv1 Error : %s",                               \
                    ssh_ike_error_code_to_string(error));               \
    }

/* Get the fallback negotiation from pm_info. */
SshIkev2FbNegotiation
ssh_ikev2_fb_p1_get_p1_negotiation(SshIkePMPhaseI pm_info);

/* Get p1_negotiation from SshPMQmInfo. */
#define SSH_IKEV2_FB_QM_GET_P1_NEGOTIATION(pm_info)                         \
  ((pm_info)->policy_manager_data == NULL ? NULL :                          \
   ((SshIkev2FbNegotiation) (pm_info)->policy_manager_data)->aborted == 1 ? \
    NULL : (SshIkev2FbNegotiation) (pm_info)->policy_manager_data)

/*--------------------------------------------------------------------*/
/* Allocation and freeing of negotiation contexts                     */
/*--------------------------------------------------------------------*/

SshIkev2FbNegotiation
ikev2_fallback_negotiation_alloc(SshIkev2Fb fb);

void ikev2_fallback_negotiation_free(SshIkev2Fb fb,
                                     SshIkev2FbNegotiation negotiation);


/*--------------------------------------------------------------------*/
/* Fallback initiator                                                 */
/*--------------------------------------------------------------------*/

/* */
SshOperationHandle
ikev2_fb_initiate_ipsec_sa(SshIkev2ExchangeData ed);

SshOperationHandle
ikev2_fb_initiate_info(SshIkev2ExchangeData ed);

/* NOTE: Just a stub for sending delete notification */
SshIkev2Error
ikev2_fb_info_send(SshIkev2ExchangeData ed);

/*--------------------------------------------------------------------*/
/* Fallback implemented IKEv1 policy function prototypes
   These are for the fallback modules internal use                    */
/*--------------------------------------------------------------------*/

void
ikev2_fb_sa_handler(SshIkeNegotiation negotiation,
                    SshIkePMPhaseQm pm_info,
                    int number_of_sas, SshIkeIpsecSelectedSA sas,
                    SshIkeIpsecKeymat keymat,
                    void *sa_callback_context);

void
ikev2_fb_new_connection(SshIkePMPhaseI pm_info,
                        SshPolicyNewConnectionCB callback_in,
                        void *callback_context_in);
void
ikev2_fb_new_connection_phase_ii(SshIkePMPhaseII pm_info,
                                 SshPolicyNewConnectionCB callback_in,
                                 void *callback_context_in);
void
ikev2_fb_new_connection_phase_qm(SshIkePMPhaseQm pm_info,
                                 SshPolicyNewConnectionCB callback_in,
                                 void *callback_context_in);
void
ikev2_fb_isakmp_nonce_data_len(SshIkePMPhaseI pm_info,
                               SshPolicyNonceDataLenCB callback_in,
                               void *callback_context_in);
void
ikev2_fb_isakmp_id(SshIkePMPhaseI pm_info,
                   SshPolicyIsakmpIDCB callback_in,
                   void *callback_context_in);
void
ikev2_fb_isakmp_vendor_id(SshIkePMPhaseI pm_info,
                          unsigned char *vendor_id,
                          size_t vendor_id_len);
void
ikev2_fb_isakmp_request_vendor_ids(SshIkePMPhaseI pm_info,
                                   SshPolicyRequestVendorIDsCB callback_in,
                                   void *callback_context_in);
void
ikev2_fb_find_pre_shared_key(SshIkePMPhaseI pm_info,
                             SshPolicyFindPreSharedKeyCB callback_in,
                             void *callback_context_in);
#ifdef SSHDIST_IKE_CERT_AUTH
void
ikev2_fb_find_public_key(SshIkePMPhaseI pm_info,
                         SshPolicyKeyType key_type_in,
                         const unsigned char *hash_alg_in,
                         SshPolicyFindPublicKeyCB callback_in,
                         void *callback_context_in);
void
ikev2_fb_find_private_key(SshIkePMPhaseI pm_info,
                          SshPolicyKeyType key_type,
                          const unsigned char *hash_alg_in,
                          const unsigned char *hash_in,
                          size_t hash_len_in,
                          SshPolicyFindPrivateKeyCB callback_in,
                          void *callback_context_in);
void
ikev2_fb_new_certificate(SshIkePMPhaseI pm_info,
                         SshIkeCertificateEncodingType cert_encoding,
                         unsigned char *certificate_data,
                         size_t certificate_data_len);
void
ikev2_fb_certificate_request(SshIkePMPhaseI pm_info,
                             SshIkeCertificateEncodingType cert_encoding,
                             unsigned char *certificate_data,
                             size_t certificate_data_len);
void
ikev2_fb_request_certificates(SshIkePMPhaseI pm_info,
                              int number_of_cas,
                              SshIkeCertificateEncodingType
                              *ca_encodings,
                              unsigned char **certificate_authorities,
                              size_t *certificate_authority_lens,
                              SshPolicyRequestCertificatesCB
                              callback_in,
                              void *callback_context_in);
void
ikev2_fb_get_certificate_authorities(SshIkePMPhaseI pm_info,
                                     SshPolicyGetCAsCB callback_in,
                                     void *callback_context_in);
#endif /* SSHDIST_IKE_CERT_AUTH */

void
ikev2_fb_isakmp_select_sa(SshIkePMPhaseI pm_info,
                          SshIkeNegotiation negotiation,
                          SshIkePayload sa_in,
                          SshPolicySACB callback_in,
                          void *callback_context_in);
void ikev2_fb_ngm_select_sa(SshIkePMPhaseII pm_info,
                            SshIkeNegotiation negotiation,
                            SshIkePayload sa_in,
                            SshPolicySACB callback_in,
                            void *callback_context_in);
void
ikev2_fb_qm_nonce_data_len(SshIkePMPhaseQm pm_info,
                           SshPolicyNonceDataLenCB callback_in,
                           void *callback_context_in);
void
ikev2_fb_qm_local_id(SshIkePMPhaseQm pm_info,
                     SshPolicyIsakmpIDCB callback_in,
                     void *callback_context_in);
void
ikev2_fb_qm_remote_id(SshIkePMPhaseQm pm_info,
                      SshPolicyIsakmpIDCB callback_in,
                      void *callback_context_in);
void
ikev2_fb_qm_select_sa(SshIkePMPhaseQm pm_info,
                      SshIkeNegotiation negotiation,
                      int number_of_sas_in,
                      SshIkePayload *sa_table_in,
                      SshPolicyQmSACB callback_in,
                      void *callback_context_in);
#ifdef SSHDIST_ISAKMP_CFG_MODE
SshIkev2FbNegotiation
ikev2_fb_alloc_cfgmode_negotiation(SshIkePMPhaseII pm_info);

void
ikev2_fb_cfg_fill_attrs(SshIkePMPhaseII pm_info,
                        int number_of_attrs,
                        SshIkePayloadAttr *return_attributes,
                        SshPolicyCfgFillAttrsCB callback_in,
                        void *callback_context_in);
void
ikev2_fb_cfg_notify_attrs(SshIkePMPhaseII pm_info,
                          int number_of_attrs,
                          SshIkePayloadAttr *return_attributes);
#endif /* SSHDIST_ISAKMP_CFG_MODE */
void
ikev2_fb_delete(SshIkePMPhaseII pm_info,
                Boolean authenticated,
                SshIkeProtocolIdentifiers protocol_id,
                int number_of_spis,
                unsigned char **spis,
                size_t spi_size);
void
ikev2_fb_notification(SshIkePMPhaseII pm_info,
                      Boolean authenticated,
                      SshIkeProtocolIdentifiers protocol_id,
                      unsigned char *spi,
                      size_t spi_size,
                      SshIkeNotifyMessageType notify_message_type,
                      unsigned char *notification_data,
                      size_t notification_data_size);
void
ikev2_fb_phase_i_notification(SshIkePMPhaseI pm_info,
                              Boolean encrypted,
                              SshIkeProtocolIdentifiers protocol_id,
                              unsigned char *spi,
                              size_t spi_size,
                              SshIkeNotifyMessageType
                              notify_message_type,
                              unsigned char *notification_data,
                              size_t notification_data_size);
void
ikev2_fb_phase_qm_notification(SshIkePMPhaseQm pm_info,
                               SshIkeProtocolIdentifiers protocol_id,
                               unsigned char *spi,
                               size_t spi_size,
                               SshIkeNotifyMessageType
                               notify_message_type,
                               unsigned char *notification_data,
                               size_t notification_data_size);
void ikev2_fb_isakmp_sa_freed(SshIkePMPhaseI pm_info);
void ikev2_fb_qm_sa_freed(SshIkePMPhaseQm pm_info);
void ikev2_fb_phase_ii_sa_freed(SshIkePMPhaseII pm_info);
void
ikev2_fb_negotiation_done_isakmp(SshIkePMPhaseI pm_info,
                                 SshIkeNotifyMessageType code);
void
ikev2_fb_negotiation_done_qm(SshIkePMPhaseQm pm_info,
                             SshIkeNotifyMessageType code);
void
ikev2_fb_negotiation_done_phase_ii(SshIkePMPhaseII pm_info,
                                   SshIkeNotifyMessageType code);



/*--------------------------------------------------------------------*/
/* Error code conversion functions                                    */
/*--------------------------------------------------------------------*/

SshIkev2Error
ikev2_fb_v1_notify_message_type_to_v2_error_code(SshIkeNotifyMessageType code);

SshIkev2NotifyMessageType
ikev2_fb_v1_notify_type_to_v2_notify_type(SshIkeNotifyMessageType code);

#ifdef SSHDIST_IKE_CERT_AUTH
SshIkeCertificateEncodingType
ikev2_fb_v1_cert_encoding_to_v2(SshIkev2CertEncoding encoding);

SshIkev2CertEncoding
ikev2_fb_v2_cert_encoding_to_v1(SshIkeCertificateEncodingType encoding);
#endif /* SSHDIST_IKE_CERT_AUTH */


/* Mapping between SshIkeProtocolIdentifiers and their names. */
extern const SshKeywordStruct ikev2_fb_ike_protocol_identifiers[];

/* Mapping between SshIkeAttributeAuthMethValues and their names. */
extern const SshKeywordStruct ikev2_fb_ike_authentication_methods[];


/*--------------------------------------------------------------------*/
/* Rendering functions                                                */
/*--------------------------------------------------------------------*/
int
ikev2_fb_render_ike_cookie(unsigned char *buf, int buf_size,
                           int precision, void *datum);

int
ikev2_fb_ike_port_render(unsigned char *buf, int buf_size, int precision,
                         void *datum);

char *
ikev2_fb_util_data_to_hex(char *buf, size_t buflen,
                          const unsigned char *data, size_t datalen);


#define SSH_IKE_FB_DEFAULT_IPSEC_SA_LIFE_SECONDS (8 * 60 * 60)
#define SSH_IKE_FB_DEFAULT_IPSEC_SA_LIFE_KB (0)


/*--------------------------------------------------------------------*/
/* Conversion functions between IKEv1 payloads and IKEv2 payloads     */
/*--------------------------------------------------------------------*/

SshIkev2PayloadTS
ikev2_fb_tsv1_to_tsv2(SshSADHandle sad_handle, SshIkePayloadID id);

SshIkePayloadID
ikev2_fb_tsv2_to_tsv1(SshIkev2PayloadTS ts);

SshIkePayloadID
ikev2_fb_tsv2_to_fqdnv1(SshIkev2PayloadTS ts);

SshIkePayloadID
ikev2_fb_idv2_to_idv1(SshIkev2PayloadID idv2);

SshIkev2PayloadID
ikev2_fb_idv1_to_idv2(SshIkev2ExchangeData ed, SshIkePayloadID idv1);

SshIkev2PayloadSA
ikev2_fb_ikesav1_to_ikesav2(
        SshSADHandle sad_handle,
        SshIkeNegotiation negotiation,
        SshIkePayloadSA sav1,
        SshIkeAttributeAuthMethValues *ike_auth_method,
        SshUInt32 *life_seconds);

SshIkev2PayloadSA
ikev2_fb_sav1_to_sav2(SshSADHandle sad_handle,
                      SshIkeNegotiation negotiation,
                      SshIkePayloadSA sav1,
                      Boolean only_ipcomp_proposals,
                      SshIkeAttributeAuthMethValues *ike_auth_method,
                      SshUInt32 *life_seconds,
                      SshUInt32 *life_kbytes,
                      SshIkeIpsecAttributeEncapsulationModeValues
                      *encapsulation,
                      SshUInt8 max_ipcomp_num,
                      SshUInt8 *ipcomp_num_return,
                      SshUInt8 *ipcomp_algs, /* Array of IPcomp alg id's */
                      SshUInt16 *ipcomp_cpis); /* Array of IPcomp CPI's */

SshIkePayloadSA
ikev2_fb_sav2_to_sav1(SshIkev2PayloadSA sav2,
                      SshIkeAttributeAuthMethValues ike_auth_method,
                      SshUInt32 life_seconds,
                      SshUInt32 life_kbytes,
                      Boolean tunnel_mode,
                      SshUInt32 sa_flags,
                      SshUInt32 spi,
                      SshUInt8 num_ipcomp,
                      SshUInt8 *ipcomp_algs, SshUInt16 ipcomp_cpi);

#ifdef SSHDIST_ISAKMP_CFG_MODE
SshIkePayloadAttr
ikev2_fb_cfgv2_to_cfgv1(SshSADHandle sad_handle, SshIkev2PayloadConf conf);

SshIkev2PayloadConf
ikev2_fb_cfgv1_to_cfgv2(SshSADHandle sad_handle, SshIkePayloadAttr attrs);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

SshIkeAttributeEncrAlgValues
ikev2_fb_v2_id_to_v1_encr_id(SshIkev2TransformID transform_id);

SshIkeAttributeHashAlgValues
ikev2_fb_v2_id_to_v1_hash_id(SshIkev2TransformID transform_id);

SshIkeAttributeGrpDescValues
ikev2_fb_v2_id_to_v1_group_id(SshIkev2TransformID transform_id);

SshIkeIpsecAttributeAuthAlgorithmValues
ikev2_fb_v2_id_to_v1_auth_id(SshIkev2TransformID transform_id);

SshIkeIpsecAHTransformIdentifiers
ikev2_fb_v2_id_to_v1_ah_id(SshIkev2TransformID transform_id);

SshIkeIpsecESPTransformIdentifiers
ikev2_fb_v2_id_to_v1_esp_id(SshIkev2TransformID transform_id);

SshIkev2TransformID
ikev2_fb_v1_auth_id_to_v2_id(SshIkeIpsecAttributeAuthAlgorithmValues
                             auth_id);
SshIkev2TransformID
ikev2_fb_v1_ah_id_to_v2_id(SshIkeIpsecAHTransformIdentifiers ah_id);
SshIkev2TransformID
ikev2_fb_v1_esp_id_to_v2_id(SshIkeIpsecESPTransformIdentifiers esp_id);

SshIkev2TransformID
ikev2_fb_v1_encr_id_to_v2_id(SshIkeAttributeEncrAlgValues encr_id);

SshIkev2TransformID
ikev2_fb_v1_group_id_to_v2_id(SshIkeAttributeGrpDescValues group_id);

SshIkev2TransformID
ikev2_fb_v1_hash_id_to_v2_integ_id(SshIkeAttributeHashAlgValues hash_id);

SshIkev2TransformID
ikev2_fb_v1_hash_id_to_v2_prf_id(SshIkeAttributeHashAlgValues hash_id);

/* A predicate to check where an IKEv1 encryption algorithm has fixed key
   length or not. */
Boolean
ikev2_fb_cipher_is_fixed_key_length(const unsigned char *algorithm_name);


/*--------------------------------------------------------------------*/

/* Free a dynamically allocated IPSec selected SA indexes `indexes'
   containing `number_of_sas' SAs. */
void
ikev2_fb_free_sa_indexes(SshIkeIpsecSelectedSAIndexes selected,
                         int number_of_sas);


/* Select the first transform index from the ISAKMP SA payload 'sav1' with
   the proposal index 'proposal_index' which matches transforms specified
   in the IKEv2 transform array 'transforms'. Returns FALSE if no such
   transform could be found, otherwise returns TRUE and the transform in
   returned in 'transform_index' */
Boolean
ikev2_fb_select_ike_transform_index(
                           SshIkev2PayloadTransform
                           transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                           SshIkeNegotiation negotiation,
                           SshIkePayloadSA sav1,
                           int *transform_index);

/* Select the first transform index from the ISAKMP SA payload 'sav1' with
   the proposal index 'proposal_index' which matches transforms specified
   in the IKEv2 transform array 'transforms'. Returns FALSE if no such
   transform could be found, otherwise returns TRUE and the transform in
   returned in 'ipsec_transform_index'. IPComp transforms are matched again
   'allow_ipcomp' and 'ipcomp_algorithm' parameters. The selected IPComp
   transform index is returned in 'ipcomp_transform_index'. */
Boolean
ikev2_fb_select_ipsec_transform_index(SshIkev2PayloadTransform
                                      transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                                      SshIkev2ProtocolIdentifiers
                                      selected_sa_protocol,
                                      SshIkeNegotiation negotiation,
                                      SshIkePayloadSA sav1,
                                      Boolean allow_ipcomp,
                                      SshUInt8 ipcomp_algorithm,
                                      int *proposal_index,
                                      int *ipsec_transform_index,
                                      int *ipcomp_transform_index);

/* Generate keying material for the IPsec SA. The keymat is
   filled with the keying material. */
Boolean ikev2_fb_fill_keymat(SshIkev2ExchangeData ed,
                             SshIkeNegotiation negotiation,
                             SshIkeIpsecSelectedSA sas,
                             SshIkeIpsecKeymat keymat);


/* This function is called by Quick-Mode responders to see whether a
   responder lifetime notification should be sent to the Initiator. It
   compares the proposed SA lifetimes sent by the initiator
   'proposed_life_sec' and 'proposed_life_kb' to the policy lifetimes as
   set in the IPSec exchange data in 'ed'. Returns TRUE if a responder
   lifetime notification should be sent and FALSE otherwise.

   The policy lifetimes in the IPSec exchange data 'ed' are modified if
   either of the proposed lifetimes is less than the policy lifetimes. */
Boolean
ikev2_fb_check_ipsec_responder_lifetimes(SshIkev2ExchangeData ed,
                                         SshUInt32 proposed_life_sec,
                                         SshUInt32 proposed_life_kb);

/* NAT-T specific functions */

/* Set the NAT-T private payload handlers */
void
ikev2_fb_natt_set_private_payload_handlers(SshIkeParams ike_params);

/* Check received Ikev1 NAT-T vendor IDs.
   Called from ikev2_fb_isakmp_vendor_id */
void ikev2_fb_check_recvd_natt_vendor_id(SshIkev2FbNegotiation neg,
                                         const unsigned char *vendor_id,
                                         size_t vendor_id_len);

/* Check sent Ikev1 NAT-T vendor IDs.
   Called from ikev2_fb_isakmp_vendor_id */
void ikev2_fb_check_sent_natt_vendor_ids(SshIkev2FbNegotiation neg);

/* Server changed notifications */
void
ikev2_fb_phase_i_server_changed(SshIkePMPhaseI pm_info,
                                SshIkeServerContext new_server,
                                const unsigned char *new_remote_ip,
                                const unsigned char *new_remote_port);

void
ikev2_fb_phase_qm_server_changed(SshIkePMPhaseQm pm_info,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port);

void
ikev2_fb_phase_ii_server_changed(SshIkePMPhaseII pm_info,
                                 SshIkeServerContext new_server,
                                 const unsigned char *new_remote_ip,
                                 const unsigned char *new_remote_port);

/* Handle pending NAT-T operations for notifications */
void
ikev2_fb_ike_float_free(SshIkev2FbNatTInfo ike_float);

void
ikev2_fb_phase1_pending_natt_operations(SshIkev2FbNegotiation neg);

void
ikev2_fb_phase_ii_pending_natt_operations(SshIkev2Sa ike_sa,
                                          SshIkev2ExchangeData ed,
                                          SshIkev2FbNatTInfo ike_float);

#ifdef SSHDIST_IKE_XAUTH

SshIkev2FbXauthAttributes
ikev2_fb_xauth_decode_attributes(SshIkePayloadAttr attrs);


SshIkePayloadAttr *
ikev2_fb_xauth_encode_attributes(SshIkev2FbXauthAttributes attributes,
                                 SshIkeCfgMessageType type,
                                 Boolean success,
                                 Boolean xauth_enabled,
                                 const unsigned char *message,
                                 size_t message_len);

void ikev2_fb_xauth_free_attributes(SshIkev2FbXauthAttributes attributes);

void ikev2_fb_xauth_free_v1_attributes(SshIkePayloadAttr *attributes);

#endif /* SSHDIST_IKE_XAUTH */


void
ikev2_fb_ipsec_spi_allocate_cb(SshIkev2Error error_code,
                               SshUInt32 spi,
                               void *context);

void ikev2_fb_p1_negotiation_destructor(SshFSM fsm, void *context);
void ikev2_fb_qm_negotiation_destructor(SshFSM fsm, void *context);

void
ikev2_fb_id_request_cb(SshIkev2Error error_code,
                       Boolean local,
#ifdef SSH_IKEV2_MULTIPLE_AUTH
                       Boolean another_auth_follows,
#endif /* SSH_IKEV2_MULTIPLE_AUTH */
                       const SshIkev2PayloadID id_payload,
                       void *context);
void
ikev2_fb_find_pre_shared_key_cb(SshIkev2Error error_code,
                                const unsigned char *key_out,
                                size_t key_out_len,
                                void *context);

#ifdef SSHDIST_IKE_CERT_AUTH
void ikev2_fb_request_certificates_cb(SshIkev2Error error_code,
                                      SshPrivateKey private_key_out,
                                      int number_of_certificates,
                                      SshIkev2CertEncoding *cert_encs,
                                      const unsigned char **certs,
                                      size_t *cert_lengths,
                                      void *context);
#endif /* SSHDIST_IKE_CERT_AUTH */

void
ikev2_fb_notify_request_cb(SshIkev2Error error_code,
                           SshIkev2ProtocolIdentifiers protocol_id,
                           unsigned char *spi,
                           size_t spi_size,
                           SshIkev2NotifyMessageType notify_message_type,
                           unsigned char *notification_data,
                           size_t notification_data_size,
                           void *context);

void ikev2_fb_sa_request_cb(SshIkev2Error error,
                            SshIkev2PayloadSA sa,
                            void *context);


#ifdef SSHDIST_ISAKMP_CFG_MODE
void ikev2_fb_conf_cb(SshIkev2Error error,
                      SshIkev2PayloadConf conf_payload,
                      void *context);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* terminate initiator ipsec negotiation. */
void ikev2_fb_ipsec_complete(SshIkev2FbNegotiation neg);


/* Functions for setting `policy_manager_data' in isakmp library `pm_info'
   structure. These functions take/release a reference to fallback negotiation
   structure. */
void
ikev2_fb_phase_qm_set_pm_data(SshIkePMPhaseQm pm_info,
                              SshIkev2FbNegotiation neg);

void
ikev2_fb_phase_qm_clear_pm_data(SshIkePMPhaseQm pm_info,
                                SshIkev2FbNegotiation neg);

void
ikev2_fb_phase_ii_set_pm_data(SshIkePMPhaseII pm_info,
                              SshIkev2FbNegotiation neg);

void
ikev2_fb_phase_ii_clear_pm_data(SshIkePMPhaseII pm_info,
                                SshIkev2FbNegotiation neg);

/* This function checks if `neg' has `qm_info' or `p2_info' set and
   clears the `policy_manager_data' from both of them. */
void
ikev2_fb_negotiation_clear_pm_data(SshIkev2FbNegotiation neg);


SshIkePMPhaseQm
ikev2_fb_get_qm_info(SshIkeNegotiation ike_negotiation);

#ifdef SSHDIST_IKE_XAUTH
SshIkePMPhaseII
ikev2_fb_get_cfg_pm_info(SshIkeNegotiation ike_negotiation);
#endif /* SSHDIST_IKE_XAUTH */

void
ikev2_fb_ike_sa_uninit(SshIkev2Sa ike_sa);

/* References to fallback negotiation must always be taken with this macro.
   References are released with ikev2_fallback_negotiation_free(). */
#define IKEV2_FB_NEG_TAKE_REF(neg) \
do \
  { \
    (neg)->ref_count++; \
    SSH_DEBUG(SSH_D_LOWOK, \
              ("Taking reference to fallback negotiation %p " \
               "(now %d references)", (neg), (neg)->ref_count)); \
  } \
while (0)

#endif /* IKEV2_FB_H */
