/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Isakmp library internal prototypes and variables.
*/

#ifndef ISAKMP_INTERNAL_H
#define ISAKMP_INTERNAL_H

#include "isakmp.h"
#include "isakmp_state.h"
#include "sshgetput.h"
#include "sshenum.h"
#include "sshtimemeasure.h"
#include "sshadt.h"
#include "sshadt_map.h"
#include "sshadt_list.h"
#include "sshglobals.h"

/*                                                              shade{0.9}
 *
 * Types.
 *                                                              shade{1.0}
 */

/* Isakmp packet structure (from isakmp) */
struct SshIkePacketRec {
  struct SshIkeCookiesRec cookies;
  int major_version;
  int minor_version;
  SshIkeExchangeType exchange_type;
  unsigned int flags;
  SshUInt32 message_id;
  size_t length;                /* Automatically calculated when
                                   encoding, does not include
                                   encryption padding, nor any other
                                   paddings. */
  SshUInt32 number_of_payload_packets;
  SshUInt32 number_of_payload_packets_allocated;
  SshIkePayload *payloads;

  /* Pointer to various payloads. */
  SshIkePayload first_sa_payload;
  SshIkePayload first_ke_payload;
  SshIkePayload first_id_payload;
  SshIkePayload first_cert_payload;
  SshIkePayload first_cr_payload;
  SshIkePayload first_hash_payload;
  SshIkePayload first_sig_payload;
  SshIkePayload first_nonce_payload;
  SshIkePayload first_n_payload;
  SshIkePayload first_d_payload;
  SshIkePayload first_vid_payload;
#ifdef SSHDIST_ISAKMP_CFG_MODE
  SshIkePayload first_attr_payload;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  SshIkePayload first_private_payload;

  unsigned char *encoded_packet; /* Encoded packet data, always in
                                    clear text */
  size_t encoded_packet_len;    /* Length of the encoded packet, including the
                                   padding etc. */
  unsigned char **packet_data_items; /* Array of mallocated packet data
                                        items */
  SshUInt32 packet_data_items_cnt;    /* Number of packet data items */
  SshUInt32 packet_data_items_alloc;  /* Number of entries allocated in
                                   packet_data_items array. */
};

typedef struct SshIkeAuditContextRec {

  struct SshIkeAuditContextRec *next;

  SshAuditContext audit;
} *SshIkeAuditContext;


/* Global isakmp context structure. Common data for all isakmp functions,
   returned by ssh_isakmp_init function.  */
struct SshIkeContextRec {

  /* Linked list of configured audit contexts. */
  SshIkeAuditContext ike_audit_contexts;

  SshUInt32 time_val;           /* Time value for cookie generation. Starting
                                   from 0 when the server is started, and
                                   incrementing by 1 for each negotiation. */

  SshADTContainer isakmp_sa_mapping; /* Mappings from cookies to sa */
  SshADTContainer isakmp_cookie_mapping; /* Mappings from initiator cookie
                                            to sa */
  SshADTContainer prime_mapping;     /* Mappings prime numbers */
  int number_of_primes_in_table; /* Number of primes in mapping */
  SshUInt32 default_compat_flags; /* Default compat flags, see
                                     SSH_IKE_FLAGS_*. */

  Boolean no_key_hash_payload;          /* Do not send key hash payload */
  Boolean no_cr_payloads;               /* Do not certificate request
                                           payloads */
  Boolean trust_icmp_messages;          /* Trust ICMP port or host unreachable
                                           messages. */
  unsigned char *default_ip;            /* Default IP */
  unsigned char *default_port;          /* Default port */

  /* Default values */
  SshInt32 base_retry_limit;            /* Number of retries */
  SshInt32 base_retry_timer;            /* Retry timer (in seconds) */
  SshInt32 base_retry_timer_usec;       /* Retry timer (in useconds) */
  SshInt32 base_retry_timer_max;        /* Max time of the retry timer (in
                                           seconds). */
  SshInt32 base_retry_timer_max_usec;   /* Max time of the retry timer (in
                                           useconds). */
  SshInt32 base_expire_timer;           /* Expire timer (in seconds) */
  SshInt32 base_expire_timer_usec;      /* Expire timer (in useconds) */

  SshInt32 extended_retry_limit;        /* Number of retries */
  SshInt32 extended_retry_timer;        /* Retry timer (in seconds) */
  SshInt32 extended_retry_timer_usec;   /* Retry timer (in useconds) */
  SshInt32 extended_retry_timer_max;    /* Max time of the retry timer (in
                                           seconds). */
  SshInt32 extended_retry_timer_max_usec;/* Max time of the retry timer (in
                                           useconds). */
  SshInt32 extended_expire_timer;       /* Expire timer (in seconds) */
  SshInt32 extended_expire_timer_usec;  /* Expire timer (in useconds) */

  int secret_recreate_timer;            /* Secret recreation timer (in secs) */
  int spi_size;                         /* Spi size to use in isakmp sa */
  int max_key_length;                   /* Max key length in bits */
  int max_isakmp_sa_count;              /* Max number of isakmp_sa entries
                                           allowed in mapping */
  int isakmp_sa_count;                  /* Number of isakmp_sa entries in
                                           mapping */
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
  const char *accelerator_short_name; /* Short name of the hardware
                                           accelerator to be used, or NULL if
                                           not available. */
#endif /* SSHDIST_EXTERNALKEY */

  /* Default private payload handlers */
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
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  SshIkePolicyFunctions policy_functions;
#endif /*  SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */
  unsigned char udp_input_packet[SSH_IKE_MAX_UDP_PACKET];

  SshPdbgConfig debug_config;      /* Pointer to debug configuration. */
};

/*
 * Group information data
 */

/* Global isakmp groups */
SSH_GLOBAL_DECLARE(SshIkeGroupMap *, ssh_ike_groups);
#define ssh_ike_groups SSH_GLOBAL_USE(ssh_ike_groups)
SSH_GLOBAL_DECLARE(int, ssh_ike_groups_count);
#define ssh_ike_groups_count SSH_GLOBAL_USE(ssh_ike_groups_count)

/*
 * Phase I key information data structure (SkeyID data)
 */
typedef struct SshIkeSASKeyIDRec {
  Boolean initialized;          /* Is this structure initialized */
  size_t dh_size;               /* Size of Diffie-Hellman */
  unsigned char *dh;            /* Output of Diffie-Hellman */

  /* base SKEYID mac */
  size_t skeyid_size;
  unsigned char *skeyid;
  SshMac skeyid_mac;

  /* Key derivation SKEYID_d mac */
  size_t skeyid_d_size;
  unsigned char *skeyid_d;

  /* Authorization SKEYID_a mac */
  size_t skeyid_a_size;
  unsigned char *skeyid_a;
  SshMac skeyid_a_mac;

  /* Encryption SKEYID_e mac */
  size_t skeyid_e_size;
  unsigned char *skeyid_e;
  SshMac skeyid_e_mac;

} *SshIkeSASKeyID;

/* Macro to set notification data to the exchange data. Note, this will strdup
   the error text if not NULL. */

#define SSH_IKE_NOTIFY_DATA(neg,pl_type,pl_start,pl_len,offset,text)    \
  do {                                                                  \
    if ((neg) != NULL)                                                  \
      {                                                                 \
        (neg)->ed->offending_payload_type = (pl_type);                  \
        if ((pl_start) != NULL)                                         \
          {                                                             \
            ssh_free((neg)->ed->offending_payload);                     \
            (neg)->ed->offending_payload =                              \
              ssh_memdup((pl_start),(pl_len));                          \
            if ((neg)->ed->offending_payload == NULL)                   \
              (neg)->ed->offending_payload_len = 0;                     \
            else                                                        \
              (neg)->ed->offending_payload_len = (pl_len);              \
          }                                                             \
        (neg)->ed->offending_payload_offset = (offset);                 \
        if ((text) != NULL)                                             \
          {                                                             \
            ssh_free((neg)->ed->error_text);                            \
            (neg)->ed->error_text = ssh_strdup(text);                   \
          }                                                             \
       }                                                                \
  } while (0)

#define SSH_IKE_NOTIFY_TEXT(neg,text)                   \
  do {                                                  \
    if ((text) != NULL && (neg) != NULL)                \
      {                                                 \
        ssh_free((neg)->ed->error_text);                \
        (neg)->ed->error_text = ssh_strdup(text);       \
      }                                                 \
  } while (0)

/*
 *
 * Exchange data. This information is freed after
 * the negotiation ends. This information includes
 * copy of all packets received and sent, and
 * direct pointers to some payloads in the
 * packets
 *
 */

/* Common exchange data for all exchanges. */
typedef struct SshIkeExchangeDataRec {
  int number_of_packets_in;     /* Number of packets received in this
                                   exhange */
  int number_of_packets_out;    /* Number of packets sent in this exhange */
  /* Packets received in this exchange */
  SshIkePacket packets_in[SSH_IKE_MAX_NUMBER_OF_PACKETS];
  /* Packets sent in this exchange */
  SshIkePacket packets_out[SSH_IKE_MAX_NUMBER_OF_PACKETS];

  SshIkeNotify notify_callback; /* Notification callback */
  void *notify_callback_context; /* Notification callback context */

  /* Notification code for postponed callbacks */
  SshIkeNotifyMessageType code;
  SshIkePayloadType offending_payload_type; /* None if not set */
  unsigned char *offending_payload; /* Offending payload, mallocated */
  size_t offending_payload_len; /* Length of the offending payload */
  size_t offending_payload_offset; /* -1 if not set */
  unsigned char *error_text;    /* Text describing error, mallocated */
  SshUInt8 invalid_flags;       /* Invalid flags, 0 if not set */

  /* Cipher states */
  size_t cipher_block_length; /* En/decryption cipher block length */
  SshCipher encryption_cipher;  /* Packet encryption cipher */
  SshCipher decryption_cipher;  /* Packet decryption cipher */
  unsigned char *cipher_iv;     /* IV for next packet negotions, note that
                                   the only the encryption will change this, so
                                   when next packet is sent to network it gets
                                   iv from decryption cipher and copies it to
                                   encryption cipher and then it encrypts and
                                   gets iv and stores it here and to decryption
                                   chipher. This is so that if the decrypted
                                   packet is invalid, we do not update the
                                   iv. */

  SshInt32 retry_count;         /* Number of retries still left for
                                   this packet */

  unsigned char *last_sent_packet; /* Mallocated */
  size_t last_sent_packet_len;

  struct SshTimeMeasureRec last_packet_time[1]; /* Time when last packet ware
                                                   sent. */

  unsigned char *last_recv_packet; /* Mallocated */
  size_t last_recv_packet_len;

  /* Copy if connect_flags & 0xffff (== compat flags) */
  SshUInt32 compat_flags;

  /* Values for this negotiation */
  SshInt32 retry_limit;                 /* Number of retries */
  SshInt32 retry_timer;                 /* Retry timer (in seconds) */
  SshInt32 retry_timer_usec;            /* Retry timer (in useconds) */
  SshInt32 retry_timer_max;             /* Max retry timer (in seconds) */
  SshInt32 retry_timer_max_usec;        /* Max retry timer (in useconds) */
  SshInt32 expire_timer;                /* Expire timer (in seconds) */
  SshInt32 expire_timer_usec;           /* Expire timer (in useconds) */

  SshUInt32 message_id;         /* Message id */

  /* Private payload handlers for this negotiation */
  int packet_number;
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

  /* State machine info. */
  SshIkeProtocolState current_state; /* Current state machine state */
  int current_state_function;   /* If the processing of the state machine has
                                   been postponed, this is the internal
                                   function number where the processing of the
                                   current state should be restarted. If this
                                   is -1 then the state machine just advances,
                                   if this is number between 0..0xff then it is
                                   a index of the input function in table where
                                   we should continue, and if it is between
                                   0x100..0x1ff then it is index of the output
                                   function. */
  SshIkePacket isakmp_packet_out; /* Output packet is stored here when state
                                     machine processing is postponed in the
                                     middle of the output function calls.  */

  SshIkeAuthMeth auth_method_type; /* Current generic authentication method
                                      type. Used to match state machine. */
} *SshIkeExchangeData;

typedef enum {
  SSH_IKE_SIGNATURE_VERIFY_STATE_NOT_DONE,
  SSH_IKE_SIGNATURE_VERIFY_STATE_OK,
  SSH_IKE_SIGNATURE_VERIFY_STATE_FAILED
} SshIkeSignatureVerifyState;

/* Main mode / aggressive mode exchange data */
typedef struct SshIkeSAPacketDataRec {
  SshIkePayload sa_i;           /* Pointer to initiator's sa payload */
  SshIkePayload sa_r;           /* Pointer to responder's sa payload */
  SshIkePayload ke_i;           /* Pointer to initiator's ke payload */
  SshIkePayload ke_r;           /* Pointer to responder's ke payload */
  SshIkePayload nonce_i;        /* Pointer to initiator's nonce payload */
  SshIkePayload nonce_r;        /* Pointer to responder's nonce payload */
  SshPkGroupDHSecret secret;        /* Secret value */
  unsigned char *async_return_data; /* Asyncronous encrypt/decrypt public key
                                       or diffie-hellman operations returns
                                       data in this buffer */
  size_t async_return_data_len; /* Asyncronous encrypt/decrypt public key or
                                   diffie-hellman operations returns length of
                                   the data in this variable. */
  Boolean async_return_done;    /* The asynchronous operation has been done. */
  SshIkeSignatureVerifyState sig_verify_state; /* State of signature
                                                  verification.  */

#ifdef SSHDIST_IKE_CERT_AUTH
  /* Set by policy_reply_find_public_key (mallocated) */
  SshPublicKey public_key;      /* Public key used for encryption /
                                   signatures, NULL if no query done yet. */
  unsigned char *public_key_hash; /* Hash of public key, NULL if no hash to
                                     send. */
  size_t public_key_hash_len;   /* Length of public key hash */

  /* Set by policy_reply_find_private_key (mallocated)  */
  SshPrivateKey private_key;    /* Private key used for encryption /
                                   signatures, NULL if no query done yet. */
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Set by policy_reply_find_pre_shared_key (mallocated) */
  unsigned char *pre_shared_key; /* Pre shared key for the connection, NULL if
                                    no query done yet. */
  size_t pre_shared_key_len;

#ifdef SSHDIST_IKE_CERT_AUTH
  /* Set by policy_reply_request_certificates (mallocated) */
  int *number_of_certificates;  /* Table of number of certificates, NULL if
                                   error, or no certs to send. This table
                                   contains number_of_cas entries. */
  SshIkeCertificateEncodingType **cert_encodings; /* Table of certificate
                                                      encodings */
  unsigned char ***certs;       /* Table of certificates */
  size_t **cert_lengths;        /* Table of certificate lengths */

  /* CAs used in this connection (local CAs or the CAs the other end trust)
     (mallocated) */
  int number_of_cas;            /* Number of CAs, -1 if not initialized yet */
  SshIkeCertificateEncodingType *ca_encodings; /* CA encodings */
  unsigned char **certificate_authorities; /* CA names */
  size_t *certificate_authority_lens; /* CA name lengths */

  /* CAs used by this end (the CAs we trust), set by policy_reply_get_cas
     (mallocated) */
  int own_number_of_cas;        /* Number of CAs, -1 if no query done yet. */
  SshIkeCertificateEncodingType *own_ca_encodings; /* CA encodings */
  unsigned char **own_certificate_authorities; /* CA names */
  size_t *own_certificate_authority_lens; /* CA name lengths */
#endif /* SSHDIST_IKE_CERT_AUTH */

  /* Set by reply_isakmp_nonce_data_len */
  size_t nonce_data_len;        /* Nonce data len, -1 if not initialized
                                   yet. */

  /* Set by isakmp_sa_reply */
  struct SshIkeAttributesRec attributes; /* Isakmp/Oakley attributes */
  int selected_proposal;        /* Number of proposal selected (index to
                                   proposal table, not proposal id) */
  int selected_transform;       /* Number of transform selected (index to
                                   transforms table in protocol structure, not
                                   transform id). Only set if we are responder,
                                   otherwise set to -1. */
  SshIkeGroupMap group;         /* Group to use */

  /* Set by ike_connect */
  SshUInt32 connect_flags;      /* Connect flags */

  /* Set by ike_connect */
  SshIkePayloadSA local_sa_proposal;/* Local SA proposal, freed after used. */

  /* Set by ike_policy_reply_vendor_ids */
  int number_of_vids;           /* Number of vendor id payloads -1 if not
                                   initialized yet */
  unsigned char **vendor_ids;
  size_t *vendor_id_lens;

  /* Udp listener to used to send the message, or NULL if using default
     listener */
  SshUdpListener listener;
} *SshIkeSAPacketData;

/* Quick mode exchange data */
typedef struct SshIkeQmSAPacketDataRec {
  SshIkePayload *sas_i;         /* Pointers to initiator's sa payloads */
  SshIkePayload *sas_r;         /* Pointers to responder's sa payloads */
  SshIkePayload ke_i;           /* Pointer to initiator's ke payload */
  SshIkePayload ke_r;           /* Pointer to responder's ke payload */
  SshIkePayload nonce_i;        /* Pointer to initiator's nonce payload */
  SshIkePayload nonce_r;        /* Pointer to responder's nonce payload */
  SshPkGroupDHSecret secret;        /* Secret value */
  unsigned char *async_return_data; /* Asyncronous encrypt/decrypt public key
                                       or diffie-hellman operations returns
                                       data in this buffer */
  size_t async_return_data_len; /* Asyncronous encrypt/decrypt public key or
                                   diffie-hellman operations returns length of
                                   the data in this variable. */

  /* Set by reply_qm_nonce_data_len */
  size_t nonce_data_len;        /* Nonce data len, -1 if not initialized
                                   yet. */

  /* Set by reply_qm_local_id */
  Boolean no_local_id;          /* No local id to be send (only set if we are
                                   responder)  */

  /* Set by reply_qm_remote_id */
  Boolean no_remote_id;         /* No remote id to be send (only set if we are
                                   responder)  */

  /* Set by connect_ipsec or i_qm_sa_proposals */
  int number_of_sas;            /* Number of SA proposals in this qm
                                   exchange. */

  /* Set by qm_sa_reply */
  SshIkeIpsecSelectedSAIndexes indexes; /* proposal/transform indexes selected
                                           by policy manager. */
  SshIkeIpsecSelectedSA selected_sas;   /* Selected sa information. */

  /* Set by ike_st_o_qm_sa_values or connect_ipsec */
  SshIkeGroupMap group;         /* Group to use if PFS */

  /* Set by reply_new_connection, or connect_ipsec */
  SshUInt32 connect_flags;      /* Connect flags */

  /* Set by connect_ipsec */
  SshIkePayloadSA *local_sa_proposals; /* Local SA proposal. Freed, after used.
                                        */

} *SshIkeQmSAPacketData;

/* New group mode exchange data */
typedef struct SshIkeNgmSAPacketDataRec {
  SshIkePayload sa_i;           /* Pointer to initiator's sa payloads */
  SshIkePayload sa_r;           /* Pointer to responder's sa payloads */

  /* Set by ngm_sa_reply */
  struct SshIkeGrpAttributesRec attributes; /* New group mode attributes */
  int selected_proposal;        /* Number of proposal selected (index to
                                   proposal table, not proposal id) */
  int selected_transform;       /* Number of transform selected (index to
                                   transforms table in protocol structure, not
                                   transform id). Only set if we are responder,
                                   otherwise set to -1. */

  /* Set by new_connection_reply or connect_ngm */
  SshUInt32 connect_flags;      /* Connect flags */

  /* Set by connect_ngm */
  SshIkePayloadSA local_sa_proposal; /* Local SA proposal */
} *SshIkeNgmSAPacketData;

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Configuration mode exchange data */
typedef struct SshIkeCfgSAPacketDataRec {
  SshIkeCfgNotify notify_callback; /* Notify callback */
  void *notify_callback_context; /* Context */
  int number_of_local_attr_payloads;    /* Number of local attr payloads */
  SshIkePayloadAttr *local_attrs; /* Local attributes, either filled by
                                     caller if we are initiator or by policy
                                     manager if we are responder. */
  int number_of_remote_attr_payloads;   /* Number of remote attr payloads */
  SshIkePayloadAttr *remote_attrs; /* Remote attributes, filled by the isakmp
                                      packet handling code. */

  /* Set by new_connection_reply or connect_ngm */
  SshUInt32 connect_flags;      /* Connect flags */
} *SshIkeCfgSAPacketData;
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Notification function call status */
typedef enum {
  SSH_IKE_NOTIFICATION_STATE_NOT_SENT, /* notify callback not yet called */
  SSH_IKE_NOTIFICATION_STATE_SEND_NOW, /* call notify callback now */
  SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT /* notify callback already done */
} SshIkeNotificationState;

/* Isakmp or ipsec negotiation struct/union */
struct SshIkeNegotiationRec {
  SshIkeSA sa;                  /* Pointer back to main sa */
  int negotiation_index;        /* Index of this negotiation (mainly for
                                   debugging). For IsakmpSA negotiation it is
                                   -1. */

  /* State of the notify callback. The exchange data can be freed after the
     notification has been send, so if this is
     SSH_IKE_NOTIFICATION_STATE_ALREADY_SENT then the exchange data is not
     valid. */
  SshIkeNotificationState notification_state;

  SshUInt32 lock_flags;         /* Various locking flags, that will specify
                                   that the negotiation is not in the normal
                                   mode. Combination of SSH_IKE_NEG_LOCK_FLAG_*
                                   flags. */

  /* The negotiation has already been finished, but we must wait now for the
     maximal retransmit timeout to expire before we can be sure that the other
     end has received the last packet we sent there. The expire timer is used
     to call ike_state_restart_packet, and then it is used as life_duration
     timer cleared. If we receive retransmits during this stage we just resend
     our last packet. */
#define SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_DONE          0x0001

  /* The negotiation has already failed, but we must wait now for the maximal
     retransmit timeout to expire before we can be sure that the other end has
     received the last packet we sent there. Before setting this flag the error
     code must be stored to ed->code, or the error must already been send to
     other end. The expire time is used to call ike_remove_callback the
     negotiation when the maximal retransmit timeout is expired. If we receive
     retransmits during this stage we just ignore it our last packet. Note we
     do not go to this stage if we get internal error, that we dont send to
     other end, then we just remove the negotiation immediately. */
#define SSH_IKE_NEG_LOCK_FLAG_WAITING_FOR_REMOVE        0x0002

  /* This flag is set when the isakmp library makes a call to policy manager.
     If the policy manager calls the callback function immediately it can
     detect the case by checking this flag and knows that it must not call the
     restart function, but instead it just clears this flag to notify the
     isakmp library that the policy manager already gave the answer. If the
     policy manager does not call the callback function immediately but returns
     to isakmp library isakmp library will clear this flag and set the
     SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY flag. When the policy manager calls
     the callback it notices that this flag is not on, and stores the
     information and call the restart function that will restart the processing
     of the packet. */
#define SSH_IKE_NEG_LOCK_FLAG_PROCESSING_PM_QUERY       0x0004

  /* This flag will indicate that the negotiation is waiting reply from the
     policy manager. All the processing for the negotiation is forbidden, and
     all packets received to negotiation are just thrown away. If a expire
     timer expires during this time the negotiation is moved to
     SSH_IKE_ST_DELETED state, and most of the data is freed (exchange data,
     and the isakmp structure if this is a isakmp sa), but this negotiation
     structure is left because it is used as a context to restart function. */
#define SSH_IKE_NEG_LOCK_FLAG_WAITING_PM_REPLY          0x0008

  /* This flag will indicate that the policy manager has replied to the
     policy call and that the negotiation is waiting in a zero timeout to
     continue the processing. */
#define SSH_IKE_NEG_LOCK_FLAG_COMPLETING_PM_REPLY       0x0010

  SshIkeExchangeData ed;        /* Common exchange data */

  SshIkeExchangeType exchange_type; /* Exchange type, if this is Main Mode or
                                       Aggressive mode then it is ISAKMP SA
                                       negotiation, if this NGM then this is
                                       new group mode negotiation, if this is
                                       QM then this is ipsec quick mode
                                       negotiation.  */
  union IkeNegotiationIkeAndIpsecUnion {
    struct IkeNegotiationIkeRec {
      SshIkePMPhaseI pm_info;   /* Policy manager info (never freed) */
      SshIkeSAPacketData exchange_data; /* Isakmp SA exchange data, freed when
                                           the negotiation finishes. */
#define ike_pm_info u.i.pm_info
#define ike_ed u.i.exchange_data
    } i;
    struct IkeNegotiationQmRec {
      SshIkePMPhaseQm pm_info;  /* Policy manager info.  */
      SshIkeQmSAPacketData exchange_data;/* quick mode exchange data. */
#define qm_pm_info u.q.pm_info
#define qm_ed u.q.exchange_data
    } q;
    struct IkeNegotiationNgmRec {
      SshIkePMPhaseII pm_info;  /* Policy manager info. */
      SshIkeNgmSAPacketData exchange_data; /* new group mode  exchange data */
#define ngm_pm_info u.n.pm_info
#define ngm_ed u.n.exchange_data
    } n;
    struct IkeNegotiationInfoRec {
      SshIkePMPhaseII pm_info;  /* Policy manager info. */
#define info_pm_info u.info.pm_info
    } info;
#ifdef SSHDIST_ISAKMP_CFG_MODE
    struct IkeNegotiationCfgRec {
      SshIkePMPhaseII pm_info;  /* Policy manager info. */
      SshIkeCfgSAPacketData exchange_data; /* Configuration exchange data */
#define cfg_pm_info u.cfg.pm_info
#define cfg_ed u.cfg.exchange_data
    } cfg;
#endif /* SSHDIST_ISAKMP_CFG_MODE */
  } u;
#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS
  SshIkePolicyFunctions policy_functions;
#endif /*  SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */
};

/* Isakmp SA used for isakmp message encryption etc */
struct SshIkeSARec {
  SshIkeServerContext server_context; /* Server context */

  SshUInt32 lock_flags;         /* Various locking flags, that will specify
                                   that the isakmp sa is not in the normal
                                   mode. Combination of
                                   SSH_IKE_ISAKMP_LOCK_FLAG_* flags. */

  /* Uninitialized flag means that isakmp is partially unitialized, and its
     initialization will be completed in the decode_packet function. This flag
     is only valid when the first packet of the new isakmp sa negotiation is
     received from the network, but the packet is not yet processed, so we
     cannot fill in the version numbers etc. */
#define SSH_IKE_ISAKMP_LOCK_FLAG_UNINITIALIZED          0x0001

  /* The negotiation has already been deleted, and should not be used anymore.
     It is just waiting for timer to be removed.  */
#define SSH_IKE_ISAKMP_LOCK_FLAG_DELETED                0x0002

  /* The negotiation is being created, and should not be removed by the
     ssh_ike_remove_other_isakmp_sas function. */
#define SSH_IKE_ISAKMP_LOCK_FLAG_KEEP_THIS              0x0004

  struct SshIkeCookiesRec cookies; /* ISAKMP SA cookies from header */

  SshUInt8 phase_1_done : 1;   /* Phase 1 done */
  SshUInt8 wired        : 1;
  SshUInt8 use_natt     : 1;   /* Use server_context->nat_t_listener,
                                  used only in Ikev1 fallback */



  SshIkeNegotiation isakmp_negotiation; /* Isakmp SA negotiation. */
  int number_of_negotiations;   /* Number negotiations on progess */
  SshUInt32 allocated_negotiations; /* Number of allocated negotiations
                                       in array */
  SshIkeNegotiation *negotiations; /* Negotiations. */

  /* Private groups */
  SshIkeGroupMap *private_groups;
  SshUInt32 private_groups_count;
  SshUInt32 private_groups_alloc_count;

  unsigned long byte_count;     /* Byte count */
  unsigned long kbyte_limit;    /* Byte limit */
  SshTime created_time;          /* When was this sa created */
  SshTime last_use_time;         /* When was this sa last used */

  /* ISAKMP SA cipher key, and algorithm */
  unsigned char *cipher_key;
  size_t cipher_key_len;
  const unsigned char *encryption_algorithm_name; /* constant */
  const unsigned char *hash_algorithm_name; /* constant */
  const unsigned char *prf_algorithm_name; /* constant */
  struct SshIkeSASKeyIDRec skeyid; /* Isakmp SA Keymat material */

  unsigned char *cipher_iv;     /* IV for next packet negotions */
  size_t cipher_iv_len;         /* Length of IV for phase 2 negotiations */

  /* Defaults for this SA */
  SshInt32 retry_limit;                 /* Number of retries */
  SshInt32 retry_timer;                 /* Retry timer (in seconds) */
  SshInt32 retry_timer_usec;            /* Retry timer (in useconds) */
  SshInt32 retry_timer_max;             /* Max retry timer (in seconds) */
  SshInt32 retry_timer_max_usec;        /* Max retry timer (in useconds) */
  SshInt32 expire_timer;                /* Expire timer (in seconds) */
  SshInt32 expire_timer_usec;           /* Expire timer (in useconds) */

  /* Default private payload handlers */
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
  SshIkeSAStatisticsStruct statistics;

  /** Debuggable object data. */
  SshPdbgObjectStruct debug_object;

  /** Remote address for debugging purposes. */
  SshIpAddrStruct debug_remote_addr[1];

  /** Remote port for debugging purposes. */
  unsigned int debug_remote_port;
};

/* Keymat struct given to ipsec */
struct SshIkeIpsecKeymatRec {
  size_t skeyid_d_size;
  unsigned char *skeyid_d;
  const unsigned char *skeyid_d_mac_alg; /* Name of mac */
  size_t gqmxy_size;            /* May be 0 == no PFS */
  unsigned char *gqmxy;         /* Is NULL if gqmxy_size is 0 */
  size_t ni_size;
  unsigned char *ni;
  size_t nr_size;
  unsigned char *nr;
};

/* Isakmp server context, all servers share security associations, but there
   can be serveral servers on different ip/port combinations.

   This needs to be kept in sync with SshIkev2ServerContext at IKEv2 library.
*/
struct SshIkeServerContextRec {
  /* v2 only: ADT list header for server_list. */
  SshADTListHeaderStruct server_list_header;

  /* v1 and v2 */
  int routing_instance_id;
  int interface_index;
  SshIpAddrStruct ip_address[1];
  SshUInt16 normal_local_port;

  /* v2 only */
  SshUInt16 nat_t_local_port;
  SshUInt16 normal_remote_port;
  SshUInt16 nat_t_remote_port;
  SshUInt16 original_normal_local_port;
  SshUInt16 original_nat_t_local_port;

  /* v2 only Interface function pointer structure. */
  void * sad_interface;

  /* v2 only SAD handle. */
  void *sad_handle;

  /* v1 and v2 Statistics, need to keep size equal */
  SshIkeGlobalStatisticsStruct statistics[1];

  /* v1 and v2 have pointer here */
  void *context;
  SshIkeContext isakmp_context; /* global context */

  /* v1 and v2 UDP listener for normal IKE SA packets. */
  SshUdpListener normal_listener;

  /* v2 UDP listener for NAT-T IKE SA packets. */
  SshUdpListener nat_t_listener;

  /* v1 and v2 forced NAT-T enabled. */
  Boolean forced_nat_t_enabled;

  /* v2 only Callback for stopping. This is here so that we do not
     need to allocate anything that could cause the stop to fail when
     a stop is called. */
  void *server_stopped_cb;
  void *server_stopped_context;

  /* v2 only */
  SshUInt32 server_stopped_flags;
  int server_stopped_counter;

  /* v1 only */
  SshIkePMContext pm;           /* sad handle */
  SshIkeIpsecSAHandler sa_callback;
  void *sa_callback_context;
};

unsigned char *ike_ip_string(SshIpAddr ip,
                             unsigned char *space, size_t space_size);
unsigned char *ike_port_string(SshUInt16 port,
                               unsigned char *space, size_t space_size);

/* New connection CB context */
typedef struct SshIkeNewConnectionCBContextRec {
  SshIkeServerContext server;
  SshIkeNegotiation negotiation;
  SshUInt32 message_id;
  SshBuffer buffer;
  Boolean use_natt;
} *SshIkeNewConnectionCBContext;

/*                                                              shade{0.9}
 *
 * isakmp_state.c prototypes
 *                                                              shade{1.0}
 */

/* Isakmp state machine. Return 0 if everything ok. Return
   IsakmpNofifyMessageType error if any errors, in processing
   message. If error is returned then isakmp_packet_out is
   not allocated, but the state in isakmp_sa might still be
   updated. Note that packet is added to isakmp_sa state, so
   it must not be freed. */
SshIkeNotifyMessageType ike_state_step(SshIkeContext isakmp_context,
                                       SshIkePacket isakmp_packet_in,
                                       SshIkePacket *isakmp_packet_out,
                                       SshIkeSA isakmp_sa,
                                       SshIkeNegotiation negotiation);

/* Append mallocated item to packet data item array. */
Boolean ike_register_item(SshIkePacket packet, unsigned char *ptr);

/* Append memdup'ed copy to packet data item array. Return the copy or NULL in
   case of error. */
void *ike_register_copy(SshIkePacket packet, unsigned char *ptr, size_t len);

/* Append calloated new item of size len to packet data item array. Return the
   copy or NULL in case of error. */
void *ike_register_new(SshIkePacket packet, size_t len);

#ifdef SSHDIST_IKE_CERT_AUTH
/* Find public_key for the connection. If the hash_out_buffer is given then
 * hash of the key is stored there (only if multiple keys for host found). The
 * hash_out_buffer_len is in/out parameter, that will contain the allocated
 * length of hash_out_buffer (in) and this function will set it to match used
 * length of buffer. */
SshIkeNotifyMessageType ike_find_public_key(SshIkeContext isakmp_context,
                                            SshIkeSA isakmp_sa,
                                            SshIkeNegotiation negotiation,
                                            unsigned char *hash_out_buffer,
                                            size_t *hash_out_len,
                                            const unsigned char *hash_name);


/* Find private_key for the connection. */
SshIkeNotifyMessageType ike_find_private_key(SshIkeContext isakmp_context,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             unsigned char *hash,
                                             size_t hash_len,
                                             const unsigned char *hash_name);
#endif /* SSHDIST_IKE_CERT_AUTH */

#ifdef SSHDIST_EXTERNALKEY
/* This callback is called when the acceleration of a group has
 * terminated.
 */
void ssh_ike_get_acc_group_cb(SshEkStatus status,
                              SshPkGroup accelerated_group,
                              void *context);
#endif /* SSHDIST_EXTERNALKEY */

/* Find pre-shared key for the connection. */
SshIkeNotifyMessageType ike_find_pre_shared_key(SshIkeContext isakmp_context,
                                                SshIkeSA isakmp_sa,
                                                SshIkeNegotiation negotiation);

#ifdef SSHDIST_IKE_CERT_AUTH
/* Decrypt given data by private key. */
SshIkeNotifyMessageType ike_rsa_decrypt_data(SshIkeContext isakmp_context,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             unsigned char *data,
                                             size_t len,
                                             unsigned char **return_data,
                                             size_t *return_len);

/* Encrypt given data by public key. */
SshIkeNotifyMessageType ike_rsa_encrypt_data(SshIkeContext isakmp_context,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             unsigned char *data,
                                             size_t len,
                                             unsigned char **return_data,
                                             size_t *return_len);
#ifdef SSHDIST_CRYPT_ECP
Boolean ike_get_ecp_scheme_and_mac(SshIkeAttributeAuthMethValues auth_method,
                                   const char ** scheme,
                                   const unsigned char ** mac_name);
#endif /* SSHDIST_CRYPT_ECP */

#endif /* SSHDIST_IKE_CERT_AUTH */

/* Calculate skeyid data if not already done. */
SshIkeNotifyMessageType ike_calc_skeyid(SshIkeContext isakmp_context,
                                        SshIkeSA isakmp_sa,
                                        SshIkeNegotiation negotiation);

/* Check if number is prime, keep local cache. */
Boolean ike_check_prime(SshIkeContext ctx, SshMPInteger number);

/* Find group by group descriptor. Sa can be NULL. */
SshIkeGroupMap ike_find_group(SshIkeSA sa, int group);


/* Add private group to sa structure, return NULL on error. */
SshIkeGroupMap ike_add_group(SshIkeNegotiation negotiation,
                             SshIkeGrpAttributes attrs);

/* Remove private group to sa structure and free the grp. */
void ike_remove_group(SshIkeNegotiation negotiation, int group);

/* Compare two given transforms and return TRUE if they match. The first
 * transform is the one given by the initiator and the second one is the value
 * selected by the responder. */
Boolean ike_compare_transforms_isakmp(SshIkeNegotiation negotiation,
                                      SshIkePayloadT trans_i,
                                      SshIkePayloadT trans_r);

/* Compare two given transforms and return TRUE if they match. The first
 * transform is the one given by the initiator and the second one is the value
 * selected by the responder. */
Boolean ike_compare_transforms_ipsec(SshIkeNegotiation negotiation,
                                     SshIkePayloadT trans_i,
                                     SshIkePayloadT trans_r);

/* Compare two given transforms and return TRUE if they match. The first
 * transform is the one given by the initiator and the second one is the value
 * selected by the responder. */
Boolean ike_compare_transforms_ngm(SshIkeNegotiation negotiation,
                                   SshIkePayloadT trans_i,
                                   SshIkePayloadT trans_r);

/* Compare two given proposals and return TRUE if they match. The first
 * proposal is the one given by the initiator and the second one is the values
 * selected by the responder. */
Boolean ike_compare_proposals(SshIkeNegotiation negotiation,
                              SshIkePayloadP prop_i,
                              SshIkePayloadP prop_r,
                              Boolean (*trans_cmp)(SshIkeNegotiation
                                                   negotiation,
                                                   SshIkePayloadT trans_i,
                                                   SshIkePayloadT trans_r));

/* Calculate HASH_I or HASH_R. */
SshIkeNotifyMessageType ike_calc_mac(SshIkeContext isakmp_context,
                                     SshIkeSA isakmp_sa,
                                     SshIkeNegotiation negotiation,
                                     unsigned char *hash,
                                     size_t *hash_len,
                                     Boolean local,
                                     const unsigned char *mac_name);

/* Calculate quick mode authentication hash. Hash payload must be the first
 * payload. */
SshIkeNotifyMessageType ike_calc_qm_hash(SshIkeContext isakmp_context,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkePacket isakmp_packet,
                                         unsigned char *hash,
                                         size_t *hash_len,
                                         Boolean include_ni);

/* Calculate quick mode authentication hash 3. */
SshIkeNotifyMessageType ike_calc_qm_hash_3(SshIkeContext isakmp_context,
                                           SshIkeSA isakmp_sa,
                                           SshIkeNegotiation negotiation,
                                           SshIkePacket isakmp_packet,
                                           unsigned char *hash,
                                           size_t *hash_len);

/* Calculate genric authentication hash. Hash payload must be the first
 * payload. */
SshIkeNotifyMessageType ike_calc_gen_hash(SshIkeContext isakmp_context,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshIkePacket isakmp_packet,
                                          unsigned char *hash,
                                          size_t *hash_len);

/* Calculate pre-shared key hash for Cisco hybrid authentication. */
SshIkeNotifyMessageType ike_calc_psk_hash(SshIkeContext isakmp_context,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          unsigned char *hash,
                                          size_t *hash_len);

/* Append payload and return pointer to the payload structure. If it runs out
   of memory it returns NULL. Allocated payload is filled with zeros. */
SshIkePayload ike_append_payload(SshIkeContext isakmp_context,
                                 SshIkePacket isakmp_packet,
                                 SshIkeSA isakmp_sa,
                                 SshIkeNegotiation negotiation,
                                 SshIkePayloadType type);

/* Finalize qm hash_1. */
SshIkeNotifyMessageType ike_finalize_qm_hash_1(SshIkeContext context,
                                               SshIkeSA sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePacket isakmp_packet,
                                               int payload_index,
                                               SshIkePayload payload);

/* Finalize qm hash_2. */
SshIkeNotifyMessageType ike_finalize_qm_hash_2(SshIkeContext context,
                                               SshIkeSA sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePacket isakmp_packet,
                                               int payload_index,
                                               SshIkePayload payload);

/* Finalize qm hash_3. */
SshIkeNotifyMessageType ike_finalize_qm_hash_3(SshIkeContext context,
                                               SshIkeSA sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePacket isakmp_packet,
                                               int payload_index,
                                               SshIkePayload payload);

/* Add optional id. */
SshIkeNotifyMessageType ike_st_qm_optional_id(SshIkeContext isakmp_context,
                                              SshIkePacket isakmp_input_packet,
                                              SshIkePacket
                                              isakmp_output_packet,
                                              SshIkeSA isakmp_sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkeStateMachine state,
                                              SshIkePayloadID id);

/* Finalize Phase 1 authentication hash. */
SshIkeNotifyMessageType ike_finalize_mac(SshIkeContext isakmp_context,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkePacket isakmp_packet,
                                         int payload_index,
                                         SshIkePayload payload);

/* Finalize Phase 1 authentication sig. */
SshIkeNotifyMessageType ike_finalize_sig(SshIkeContext isakmp_context,
                                         SshIkeSA isakmp_sa,
                                         SshIkeNegotiation negotiation,
                                         SshIkePacket isakmp_packet,
                                         int payload_index,
                                         SshIkePayload payload);


/* Finalize genric authentication hash. */
SshIkeNotifyMessageType ike_finalize_gen_hash(SshIkeContext context,
                                              SshIkeSA sa,
                                              SshIkeNegotiation negotiation,
                                              SshIkePacket isakmp_packet,
                                              int payload_index,
                                              SshIkePayload payload);

/* Call SshSAHandler callback for created ipsec sa. */
SshIkeNotifyMessageType ike_qm_call_callback(SshIkeContext isakmp_context,
                                             SshIkePacket
                                             isakmp_input_packet,
                                             SshIkePacket
                                             isakmp_output_packet,
                                             SshIkeSA isakmp_sa,
                                             SshIkeNegotiation negotiation,
                                             SshIkeStateMachine state);

/*  Finds group information from sa proposal. */
SshIkeNotifyMessageType ike_find_group_from_sa(SshIkeContext isakmp_context,
                                               SshIkeSA isakmp_sa,
                                               SshIkeNegotiation negotiation,
                                               SshIkePayloadSA sa);

/* Duplicate identity payload. Extra data is registered to the
   isakmp_output_packet. */
SshIkeNotifyMessageType ike_copy_id(SshIkeContext isakmp_context,
                                    SshIkePacket isakmp_output_packet,
                                    SshIkeSA isakmp_sa,
                                    SshIkeNegotiation negotiation,
                                    SshIkePayloadID from,
                                    SshIkePayloadID to);


/*                                                              shade{0.9}
 *
 * isakmp_groups.c prototypes
 *                                                              shade{1.0}
 */

/* Create randomizers for group if needed. */
void ike_grp_randomizers(void *context);

/* Initialize default group data, return TRUE if successfull and false if runs
   out of memory, or some other error occurs. */
Boolean ike_default_groups_init(SshIkeContext isakmp_context);

/* Uninitialize default group data */
void ike_default_groups_uninit(SshIkeContext isakmp_context);

/*                                                              shade{0.9}
 *
 * isakmp_cookie.c prototypes
 *                                                              shade{1.0}
 */

/* Create isakmp cookie. Generate completely random cookie, as checking the
 * cookie from the hash table is about as fast or faster than hashing stuff
 * together. This also makes cookies movable against multiple machines (high
 * availability or checkpointing systems). The return_buffer must be
 * SSH_IKE_COOKIE_LENGTH bytes long. */
void ike_cookie_create(SshIkeContext isakmp_context,
                       unsigned char *cookie);

/*                                                              shade{0.9}
 *
 * isakmp_packet.c prototypes
 *                                                              shade{1.0}
 */

/* Encode isakmp packet from SshIkePacket structure and append it to
   buffer. */
SshIkeNotifyMessageType ike_encode_packet(SshIkeContext isakmp_context,
                                          SshIkePacket isakmp_packet,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshBuffer buffer);

/* Decode isakmp packet from buffer and allocate and fill in the
   isakmp_packet structure. If ok, consumes the packet from buffer, otherwise
   leave packet to buffer.
   Returns 0 if ok, otherwise return SshIkeNotifyMessageType error.
   SshBuffer length must be >= 28 (ISAKMP header). */
SshIkeNotifyMessageType ike_decode_packet(SshIkeContext isakmp_context,
                                          SshIkePacket
                                          *isakmp_packet_out,
                                          SshIkeSA isakmp_sa,
                                          SshIkeNegotiation negotiation,
                                          SshBuffer buffer);

/* Decode ID payload. Isakmp_context and negotiation may be NULL. */
SshIkeNotifyMessageType ike_decode_id(SshIkeContext isakmp_context,
                                      SshIkeNegotiation negotiation,
                                      SshIkePayload id,
                                      unsigned char *p,
                                      size_t len);

/* Encode ID payload. Isakmp_context and negotiation may be NULL. */
SshIkeNotifyMessageType ike_encode_id(SshIkeContext isakmp_context,
                                      SshIkeNegotiation negotiation,
                                      SshIkePayload id,
                                      unsigned char **return_p,
                                      size_t *return_len);

/* Free SshIkePacket stuff. Note this will only release the structure
   self, not the data pointed by those structure (unless those pointers
   point to SshIkePacket->packet_data structure which is freed, the
   isakmp_decode_packet allocates that buffer and all data
   it sets point to that buffer. */
void ike_free_packet(SshIkePacket isakmp_packet,
                     SshUInt32 compat_flags);


/*                                                              shade{0.9}
 *
 * isakmp_sa.c prototypes
 *                                                              shade{1.0}
 */

/* Find SA from the hash table by ip/port. Return NULL if no match. */
SshIkeSA ike_sa_find_ip_port(SshIkeContext context,
                             SshIkeNegotiation isakmp_sa_negotiation,
                             const unsigned char *local_ip,
                             const unsigned char *local_port,
                             const unsigned char *remote_ip,
                             const unsigned char *remote_port);

/* Find SA from the hash table */
SshIkeSA ike_sa_find(SshIkeContext context,
                     const unsigned char *initiator,
                     const unsigned char *responder);

/* Delete SA. */
void ike_sa_delete(SshIkeContext context, SshIkeSA sa);

/* Allocate new half SA. Return new SA or NULL if error. */
SshIkeSA ike_sa_allocate_half(SshIkeServerContext context,
                              const unsigned char *remote_ip,
                              const unsigned char *remote_port,
                              const unsigned char *cookie);

/* Allocate new SA. Return new SA or NULL if error. */
SshIkeSA ike_sa_allocate(SshIkeServerContext context,
                         const unsigned char *initiator,
                         const unsigned char *responder);

/* Get SA of isakmp exchange, either allocate new one or find the existing
   one, return notify message number in case of error or 0 for success. */
SshIkeNotifyMessageType ike_get_sa(SshIkeServerContext context,
                                   const unsigned char *remote_ip,
                                   const unsigned char *remote_port,
                                   SshIkeSA *isakmp_sa_return,
                                   SshIkeExchangeType *exchange_type,
                                   SshUInt32 *message_id,
                                   int *major_version,
                                   int *minor_version,
                                   SshBuffer buffer);

/*                                                              shade{0.9}
 *
 * isakmp_init.c prototypes
 *                                                              shade{1.0}
 */

/* Free common negotiation info. */
void ike_free_negotiation(SshIkeNegotiation negotiation);

/* Free isakmp sa negotiation. */
void ike_free_negotiation_isakmp(SshIkeNegotiation negotiation);

/* Free qm sa negotiation. */
void ike_free_negotiation_qm(SshIkeNegotiation negotiation);

/* Free new group mode sa negotiation. */
void ike_free_negotiation_ngm(SshIkeNegotiation negotiation);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Free configuration mode sa negotiation. */
void ike_free_negotiation_cfg(SshIkeNegotiation negotiation);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Free info mode sa negotiation. */
void ike_free_negotiation_info(SshIkeNegotiation negotiation);

/* Initialize isakmp sa structure. Return TRUE if successfull. */
Boolean ike_init_isakmp_sa(SshIkeSA sa,
                           const unsigned char *local_ip,
                           const unsigned char *local_port,
                           const unsigned char *remote_ip,
                           const unsigned char *remote_port,
                           int major_version, int minor_version,
                           SshIkeExchangeType exchange_type,
                           Boolean this_end_is_initiator,
                           Boolean use_extended_retry);

/* Allocate new negotiation. */
SshIkeNegotiation ike_alloc_negotiation(SshIkeSA sa);

/* Initialize info negotiation structure. */
Boolean ike_init_info_negotiation(SshIkeNegotiation negotiation,
                                  SshIkePMPhaseI phase_i_pm_info,
                                  const unsigned char *local_ip,
                                  const unsigned char *local_port,
                                  const unsigned char *remote_ip,
                                  const unsigned char *remote_port,
                                  int major_version, int minor_version,
                                  Boolean this_end_is_initiator,
                                  SshUInt32 message_id);

/* Create random message id. */
SshUInt32 ike_random_message_id(SshIkeSA sa,
                                SshIkeServerContext server_context);

/* Initialize quick mode negotiation structure. */
Boolean ike_init_qm_negotiation(SshIkeNegotiation negotiation,
                                SshIkePMPhaseI phase_i_pm_info,
                                const unsigned char *local_ip,
                                const unsigned char *local_port,
                                const unsigned char *remote_ip,
                                const unsigned char *remote_port,
                                SshIkeExchangeType exchange_type,
                                Boolean this_end_is_initiator,
                                SshUInt32 message_id,
                                Boolean use_extended_retry);

/* Initialize ngm negotiation structure. */
Boolean ike_init_ngm_negotiation(SshIkeNegotiation negotiation,
                                 SshIkePMPhaseI phase_i_pm_info,
                                 const unsigned char *local_ip,
                                 const unsigned char *local_port,
                                 const unsigned char *remote_ip,
                                 const unsigned char *remote_port,
                                 int major_version, int minor_version,
                                 SshIkeExchangeType exchange_type,
                                 Boolean this_end_is_initiator,
                                 SshUInt32 message_id,
                                 Boolean use_extended_retry);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Initialize configuration mode negotiation structure. */
Boolean ike_init_cfg_negotiation(SshIkeNegotiation negotiation,
                                 SshIkePMPhaseI phase_i_pm_info,
                                 const unsigned char *local_ip,
                                 const unsigned char *local_port,
                                 const unsigned char *remote_ip,
                                 const unsigned char *remote_port,
                                 int major_version, int minor_version,
                                 SshIkeExchangeType exchange_type,
                                 Boolean this_end_is_initiator,
                                 SshUInt32 message_id,
                                 Boolean use_extended_retry);

/* Restart configuration mode negotiation. */
Boolean ike_restart_cfg_negotiation(SshIkeNegotiation negotiation);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Free id payload. */
void ike_free_id_payload(SshIkePayloadID id, Boolean free_toplevel_struct);

/* Initialize info message. */
Boolean ike_init_info_exchange(SshIkeServerContext server,
                               SshIkeSA sa,
                               SshIkePacket *isakmp_packet_out,
                               SshIkeNegotiation *info_negotiation_out,
                               SshIkePayload *pl_out);

/* Delete negotiation, and if it is isakmp sa negotiation then the whole sa.
   This is called when retry timer expires or the expire timer for whole
   negotiation expires. */
void ike_delete_negotiation(SshIkeNegotiation negotiation);

/* Isakmp remove callback. Called from timer to remove whole negotiation. */
void ike_remove_callback(void *context);

/* Isakmp expire callback. Called from timer to expire whole negotiation. Sends
  a delete message to other end. */
void ike_expire_callback(void *context);

/*                                                              shade{0.9}
 *
 * isakmp_udp.c prototypes
 *                                                              shade{1.0}
 */

/* Call done callback of the policy manager, and send notification to caller if
   such callback is registered. */
void ike_call_callbacks(SshIkeNegotiation negotiation,
                        SshIkeNotifyMessageType ret);

/* Isakmp retransmit callback. Called from timer to retransmit packet. */
void ike_retransmit_callback(void *context);

/* New connection callback done. This is called when
   ssh_policy_isakmp_new_connection function is done. */
void ike_new_connection_cb_done(void *context);

/* Send isakmp packet. If retransmit is true then this is retransmit and we
   should not reset retry_count or last_sent_packet information. */
SshIkeNotifyMessageType ike_send_packet(SshIkeNegotiation negotiation,
                                        const unsigned char *p, size_t len,
                                        Boolean retransmit, Boolean no_timers);

/* ike_state_restart_packet will take last isakmp packet received and feed it
  again to state machine. If state machine step produces output packet that
  packet is sent and retransmission timers are initialized. If no packet is
  sent then this just returns. */
void ike_state_restart_packet(void *context);

/* Isakmp udp-packet handler. Called from udp-listerer when packet is received
  from that socket. */
void ike_udp_callback(SshUdpListener listener,
                      void *context);

/* Isakmp first packet udp-packet handler. Called from udp-listerer when packet
   is received from that socket. */
void ike_udp_callback_first(SshUdpListener listener,
                            void *context);

/* Isakmp common packet udp-packet handler. Called from udp-listerer when
   packet is received from that socket. */
void ike_udp_callback_common(SshIkeServerContext server,
                             Boolean use_natt,
                             unsigned char *remote_address,
                             unsigned char *remote_port,
                             SshBuffer buffer);

/* Call ike_remove_isakmp_sa. */
void ike_call_ike_remove_isakmp_sa(void *negotiation);

/* Send isakmp notify. */
void ike_send_notify(SshIkeServerContext server,
                     SshIkeNegotiation negotiation,
                     SshIkeNotifyMessageType ret);

/*                                                              shade{0.9}
 *
 * isakmp_reply.c prototypes
 *                                                              shade{1.0}
 */

/* Callback function to call when policy manager has the initial config data
   for isakmp sa negotiation. If allow_connection is false the whole connection
   is immediately dropped without any notification. If the integer parameters
   are < 0 then the defaults from the server is taken. */
/* See ISAKMP_FLAGS_* for compat_flags. */
void ike_policy_reply_new_connection(Boolean allow_connection,
                                     SshUInt32 compat_flags,
                                     SshInt32 retry_limit,
                                     SshInt32 retry_timer,
                                     SshInt32 retry_timer_usec,
                                     SshInt32 retry_timer_max,
                                     SshInt32 retry_timer_max_usec,
                                     SshInt32 expire_timer,
                                     SshInt32 expire_timer_usec,
                                     void *context);

#ifdef SSHDIST_IKE_CERT_AUTH
/* Callback function to call from find_public_key when the public key data is
   ready. If no key is found the public_key_out is NULL. The public_key is copy
   of the public key and the isakmp library will free it after the negotiation
   ends. The hash_out is freed by the isakmp library after isakmp library
   doesn't need it any more. */
void ike_policy_reply_find_public_key(SshPublicKey public_key_out,
                                      unsigned char *hash_out,
                                      size_t hash_len_out,
                                      void *context);

/* Callback function to call from find_private_key when the private key data is
   ready. If no key is found the private_key_out is NULL. The private_key is
   copy of the private key and the isakmp library will free it after the
   negotiation ends. */
void ike_policy_reply_find_private_key(SshPrivateKey private_key_out,
                                       void *context);
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Callback function to call from find_pre_shared_key when the preshared key
   data is ready. If no data is found the key_out is NULL. The key_out is a
   copy of pre shared key, and isakmp library will free it when it doesn't need
   it anymore. */
void ike_policy_reply_find_pre_shared_key(unsigned char *key_out,
                                          size_t key_out_len,
                                          void *context);

#ifdef SSHDIST_IKE_CERT_AUTH
/* Callback function to call from request_certificates when the certificate
   chain is ready. All the tables are arrays that have number_of_cas entries,
   and each entry in the tables correspons to reply to one CA request. If no
   data is found for that CA the number_of_certificates is 0. If non zero
   number of certificates is returned then certs and cert_lengths tables are
   allocated and the certs table contains mallocated pointers to certificates
   and cert_lengths table contains their size respectively. The isakmp library
   is responsible of freeing all tables and certificate data in them after it
   doesn't need them anymore. */
void ike_policy_reply_request_certificates(int *number_of_certificates,
                                           SshIkeCertificateEncodingType
                                           **cert_encodings,
                                           unsigned char ***certs,
                                           size_t **cert_lengths,
                                           void *context);

/* Callback function to call from get_certificate_authorities, when the list of
   certificate authorities is ready. If no certificate authorities is to be
   send to other end then set the number_of_cas to zero. If non zero number of
   ca's is returned then ca_encodings, ca_names, and ca_name_lens tables are
   allocated and contain the encoding type, ca distinguished name and ca
   distinguished name lengths. The isakmp library is responsible of freeing all
   tables, and the ca_name data after it doesn't need it anymore. */

void ike_policy_reply_get_cas(int number_of_cas,
                              SshIkeCertificateEncodingType *ca_encodings,
                              unsigned char **ca_names,
                              size_t *ca_name_lens,
                              void *context);
#endif /* SSHDIST_IKE_CERT_AUTH */

/* Callback function to call from the nonce_data_len when the data is
   available. */
void ike_policy_reply_isakmp_nonce_data_len(size_t nonce_data_len,
                                            void *context);

void ike_policy_reply_qm_nonce_data_len(size_t nonce_data_len,
                                        void *context);

/* Calback function to call from the isakmp_id when the identity data is ready.
   The payload will be freed by the isakmp code when it is not needed anymore.
   If id_payload is NULL then no identity payload is used. */
void ike_policy_reply_isakmp_id(SshIkePayloadID id_payload,
                                void *context);

void ike_policy_reply_qm_local_id(SshIkePayloadID id_payload,
                                  void *context);

void ike_policy_reply_qm_remote_id(SshIkePayloadID id_payload,
                                   void *context);

/* Callback to call when policy manager have the vendor id payloads ready. If
   number_of_vids is zero then no vendor id payloads is added. If non zero
   number of vendor id payload is returned then vendor_ids and vendor_id_lens
   tables are allocated and the vendor_ids table contains mallocated pointers
   to vendor_ids and vendor_id_lens table contains their size respectively. The
   isakmp library is responsible of freeing both vendor_ids data, vendor_id
   contents and vendor_id_lens tables after they doesn't need them anymore. */
void ike_policy_reply_isakmp_vendor_ids(int number_of_vids,
                                        unsigned char **vendor_ids,
                                        size_t *vendor_id_lens,
                                        void *context);

/* Function call when ssh_policy_{isakmp,ngm}_send_query wants to return data.
   When it is finished it will call this function and provide selected proposal
   and table of all transforms selected in proposal. If selected_proposal is -1
   then no proposal was chosen. The isakmp library will free transforms_indexes
   when it doesn't need it anymore. */
void ike_isakmp_sa_reply(int proposal_index, int number_of_protocols,
                         int *transforms_indexes, void *context);

void ike_ngm_sa_reply(int proposal_index, int number_of_protocols,
                      int *transforms_indexes, void *context);

/* Function call when ssh_policy_qm_send_query wants to return data. When it is
   finished it will call this function and provide mallocate structure
   containing reply to all sa queries. If return_values is NULL then any of the
   sas didn't have any suitable proposals. The isakmp library will free
   return_values data after it is no longer needed. */
void ike_qm_sa_reply(SshIkeIpsecSelectedSAIndexes return_values,
                     void *context);

#ifdef SSHDIST_ISAKMP_CFG_MODE
/* Function call when ssh_policy_cfg_fill_attrs wants to return data. When it
   is finished, it will call this function and provide mallocate structure
   containing reply to all attribute queries. If the number_of_attrs is zero
   then no attributes will be returned. The isakmp library will free
   return_attributes data after it is no longer needed. The values pointed by
   attributes are assumed to be combined with the table, so freeing the table
   should also free the values pointed by data attributes entries. */
void ike_cfg_attrs_reply(int number_of_attrs,
                         SshIkePayloadAttr *return_attributes,
                         void *context);
#endif /* SSHDIST_ISAKMP_CFG_MODE */

/* Process policy managers reply to add private payloads. */
void ike_policy_reply_private_payload_out(int private_payload_id,
                                          unsigned char *data,
                                          size_t data_len,
                                          void *context);

#define SSH_IKE_GET4L(b) SSH_GET_4BIT_HIGH(b)
#define SSH_IKE_GET4R(b) SSH_GET_4BIT_LOW(b)
#define SSH_IKE_GET8(b) SSH_GET_8BIT(b)
#define SSH_IKE_GET16(b) SSH_GET_16BIT(b)
#define SSH_IKE_GET24(b) \
     ((((unsigned long) *((unsigned char *) (b) + 0)) << 16) | \
      (((unsigned long) *((unsigned char *) (b) + 1)) << 8) | \
      ((unsigned long) *((unsigned char *)(b) + 2)))
#define SSH_IKE_GET32(b) SSH_GET_32BIT(b)
#define SSH_IKE_PUT4L(b,d) SSH_PUT_4BIT_HIGH(b,d)
#define SSH_IKE_PUT4R(b,d) SSH_PUT_4BIT_LOW(b,d)
#define SSH_IKE_PUT8(b,d) SSH_PUT_8BIT(b,d)
#define SSH_IKE_PUT16(b,d) SSH_PUT_16BIT(b,d)
#define SSH_IKE_PUT32(b,d) SSH_PUT_32BIT(b,d)

#ifdef DEBUG_LIGHT
#ifndef ssh_ike_logging_level
SSH_GLOBAL_DECLARE(int, ssh_ike_logging_level);
#define ssh_ike_logging_level SSH_GLOBAL_USE_INIT(ssh_ike_logging_level)
#endif /* ssh_ike_logging_level */

void ssh_ike_debug(int level, const char *file, int line,
                   const char *func,
                   SshIkeNegotiation negotiation,
                   unsigned char *description);
void ssh_ike_debug_buffer(int level, const char *file, int line,
                          const char *func,
                          SshIkeNegotiation negotiation,
                          const char *string, size_t len,
                          const unsigned char *buffer);

/* Max lenght of 32 bit integer as a string (9 digits + nul or 0x + 8 + nul =
   11) */
#define SSH_IKE_STR_INT32_LEN   11
/* Max length of ip number as a string (ipv4 = 3 * 4 + 3 + nul = 16,
   ipv6 = 4 * 8 + 7 + nul = 40 */
#define SSH_IKE_STR_IP_LEN      40
#ifdef __GNUC__
#define SSH_IKE_DEBUG_BUFFER(level,negotiation,string,length,buffer) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, __FUNCTION__, \
                              (negotiation), (string), (length), (buffer)); \
  } while(0)
#define SSH_IKE_DEBUG_PRINTF_BUFFER(level,negotiation,varcall,length,buffer) \
  do { \
    char *__tmp_buf; \
    if (ssh_ike_logging_level >= (level)) { \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, __FUNCTION__, \
                              (negotiation), \
                              (__tmp_buf = (ssh_debug_format varcall)), \
                              (length), (buffer)); \
      ssh_free(__tmp_buf); \
    } \
  } while(0)
#define SSH_IKE_DEBUG(level,negotiation,varcall) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug(level, __FILE__, __LINE__, __FUNCTION__, \
                       (negotiation), \
                       (unsigned char *) ssh_debug_format varcall); \
  } while(0)
#else /* __GNUC__ */
#define SSH_IKE_DEBUG_BUFFER(level,negotiation,string,length,buffer) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, NULL, (negotiation), \
                              (string), (length), (buffer)); \
  } while(0)
#define SSH_IKE_DEBUG_PRINTF_BUFFER(level,negotiation,varcall,length,buffer) \
  do { \
    char *__tmp_buf; \
    if (ssh_ike_logging_level >= (level)) { \
      ssh_ike_debug_buffer(level, __FILE__, __LINE__, NULL, (negotiation), \
                              (__tmp_buf = (ssh_debug_format varcall)), \
                              (length), (buffer)); \
      ssh_free(__tmp_buf); \
    } \
  } while(0)
#define SSH_IKE_DEBUG(level,negotiation,varcall) \
  do { \
    if (ssh_ike_logging_level >= (level)) \
      ssh_ike_debug(level, __FILE__, __LINE__, NULL, \
                       (negotiation), \
                       (unsigned char *) ssh_debug_format varcall); \
  } while(0)
#endif /* __GNUC__ */
#else /* DEBUG_LIGHT */
#define SSH_IKE_DEBUG_BUFFER(level,negotiation,string,length,buffer)
#define SSH_IKE_DEBUG_PRINTF_BUFFER(level,negotiation,varcall,length,buffer)
#define SSH_IKE_DEBUG(level,negotiation,varcall)
#endif /* DEBUG_LIGHT */

#define SSH_IKE_DEBUG_ENCODE(level, negotiation, ...) \
  do { \
    ike_debug_encode_printf(negotiation, __VA_ARGS__); \
    SSH_IKE_DEBUG(level, negotiation, (__VA_ARGS__)); \
  } while(0)

#define SSH_IKE_DEBUG_BUFFER_ENCODE( \
  level, negotiation, string, length, buffer) \
  do { \
    ike_debug_encode_buffer(negotiation, buffer, length, string); \
    SSH_IKE_DEBUG_BUFFER(level, negotiation, string, length, buffer); \
  } while(0)

#define SSH_IKE_DEBUG_PRINTF_BUFFER_ENCODE( \
  level, negotiation, length, buffer, ...) \
  do { \
    ike_debug_encode_printf_buffer(negotiation, buffer, length, __VA_ARGS__); \
    SSH_IKE_DEBUG_PRINTF_BUFFER( \
      level, negotiation, (__VA_ARGS__), length, buffer); \
  } while(0)

#define SSH_IKE_DEBUG_DECODE(level, negotiation, ...) \
  do { \
    ike_debug_decode(negotiation, __VA_ARGS__); \
    SSH_IKE_DEBUG(level, negotiation, (__VA_ARGS__)); \
  } while(0)

#define SSH_IKE_DEBUG_BUFFER_DECODE( \
  level, negotiation, string, length, buffer) \
  do { \
    ike_debug_decode_buffer(negotiation, buffer, length, string); \
    SSH_IKE_DEBUG_BUFFER(level, negotiation, string, length, buffer); \
  } while(0)

#define SSH_IKE_DEBUG_PRINTF_BUFFER_DECODE( \
  level, negotiation, length, buffer, ...) \
  do { \
    ike_debug_decode_printf_buffer(negotiation, buffer, length, __VA_ARGS__); \
    SSH_IKE_DEBUG_PRINTF_BUFFER( \
      level, negotiation, (__VA_ARGS__), length, buffer); \
  } while(0)

/* Audit an event to each of the configured audit modules */
void ssh_ike_audit_event(SshIkeContext isakmp_context,
                         SshAuditEvent event, ...);

/* Send audit event to audit log */
void ssh_ike_audit(SshIkeNegotiation negotiation, SshAuditEvent event,
                   const char *txt);

#ifdef SSHDIST_IKE_CERT_AUTH
void ike_st_o_sig_sign_cb(SshCryptoStatus status,
                          const unsigned char *signature_buffer,
                          size_t signature_buffer_len,
                          void *context);
#endif /* SSHDIST_IKE_CERT_AUTH */

void ikev1_list_packet_payloads(SshIkePacket packet,
                                SshIkePayload* payloads,
                                unsigned char* local_ip,
                                SshUInt16 local_port,
                                unsigned char* remote_ip,
                                SshUInt16 remote_port,
                                Boolean is_sending);

const char *
ssh_ikev1_notify_payload_to_string(SshIkeNotifyMessageType type);

const char *
ssh_ikev1_packet_payload_to_string(SshIkePayloadType type);

/* Report local failure of an IKE exchange. */
void ike_debug_exchange_fail_local(SshIkeNegotiation negotiation,
                                   SshIkeNotifyMessageType error);

/* Report remote failure of an IKE exchange. */
void ike_debug_exchange_fail_remote(SshIkeNegotiation negotiation,
                                    SshIkeNotifyMessageType error);

/* Report error associated with an IKE negotiation. */
void ike_debug_negotiation_error(SshIkeNegotiation negotiation,
                                 const char *text);

/* Report remote failure of an IKE exchange. */
void ike_debug_exchange_fail_remote(SshIkeNegotiation negotiation,
                                    SshIkeNotifyMessageType error);

/* Report start of an IKE exchange. */
void ike_debug_exchange_begin(SshIkeNegotiation negotiation);

/* Report successful completion of an IKE exchange. */
void ike_debug_exchange_end(SshIkeNegotiation negotiation);

/* Report establishment of an IKE SA. */
void ike_debug_ike_sa_open(SshIkeNegotiation negotiation);

/* Report termination of an IKE SA. */
void ike_debug_ike_sa_close(SshIkeNegotiation negotiation);

/* Report reception of a packet. */
void ike_debug_packet_in(SshIkeNegotiation negotiation, SshIkePacket packet);

/* Report transmission of a packet. */
void ike_debug_packet_out(SshIkeNegotiation negotiation, SshIkePacket packet);

/* Report start of packet encoding. */
void ike_debug_encode_start(SshIkeNegotiation negotiation);

/* Report encoding of packet payload or payload field with printf-like
   format string and variable arguments. */
void ike_debug_encode_printf(SshIkeNegotiation negotiation,
                             const char *fmt, ...);

/* Report encoding of packet payload or payload field. Buffer printed
   in hex and prefixed with string. */
void ike_debug_encode_buffer(SshIkeNegotiation negotiation,
                             const unsigned char *buf, size_t len,
                             const char *str);

/* Report encoding of packet payload or payload field. Buffer printed
   in hex and prefixed with printf-like output. */
void ike_debug_encode_printf_buffer(SshIkeNegotiation negotiation,
                                    const unsigned char *buf, size_t len,
                                    const char *fmt, ...);

/* Report start of packet decoding. */
void ike_debug_decode_start(SshIkeNegotiation negotiation);

/* Report encoding of packet payload or payload field. Printf-like. */
void ike_debug_decode(SshIkeNegotiation negotiation, const char *fmt, ...);

/* Report encoding of packet payload or payload field. Buffer printed
   in hex and prefixed with string. */
void ike_debug_decode_buffer(SshIkeNegotiation negotiation,
                             const unsigned char *buf, size_t len,
                             const char *str);

/* Report encoding of packet payload or payload field. Buffer printed
   in hex and prefixed with printf-like output. */
void ike_debug_decode_printf_buffer(SshIkeNegotiation negotiation,
                                    const unsigned char *buf, size_t len,
                                    const char *fmt, ...);

#ifdef SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS

#define IKE_PM_FUNC(pm_info,func_name) \
        (pm_info)->negotiation->policy_functions->func_name

#define ssh_policy_new_connection(pm_info,cb, cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,new_connection)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_new_connection_phase_ii(pm_info,cb, cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,new_connection_phase_ii)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_new_connection_phase_qm(pm_info,cb, cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,new_connection_phase_qm)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_find_public_key(pm_info,kt,ha,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,find_public_key)))((pm_info), \
                (kt), (ha), (cb), (cb_ctx))

#define ssh_policy_find_private_key(pm_info,kt,ha,h,hl,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,find_private_key)))((pm_info), \
                (kt), (ha), (h), (hl), (cb), (cb_ctx))

#define ssh_policy_find_pre_shared_key(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,find_pre_shared_key)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_new_certificate(pm_info,ce,c,cl) \
        (*(IKE_PM_FUNC(pm_info,new_certificate)))((pm_info), \
                (ce), (c), (cl))

#define ssh_policy_request_certificates(pm_info,ncas,ce,ca,cal,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,request_certificates)))((pm_info), \
                (ncas), (ce), (ca), (cal), (cb), (cb_ctx))

#define ssh_policy_get_certificate_authorities(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,get_certificate_authorities)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_isakmp_nonce_data_len(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,isakmp_nonce_data_len)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_isakmp_id(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,isakmp_id)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_isakmp_vendor_id(pm_info,vid,vidl) \
        (*(IKE_PM_FUNC(pm_info,isakmp_vendor_id)))((pm_info), \
                (vid), (vidl))

#define ssh_policy_isakmp_request_vendor_ids(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,isakmp_request_vendor_ids)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_isakmp_select_sa(pm_info,n,sa,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,isakmp_select_sa)))((pm_info), \
                (n), (sa), (cb), (cb_ctx))

#define ssh_policy_ngm_select_sa(pm_info,n,sa,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,ngm_select_sa)))((pm_info), \
                (n), (sa), (cb), (cb_ctx))

#define ssh_policy_qm_select_sa(pm_info,n,nsas,sa,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,qm_select_sa)))((pm_info), \
                (n), (nsas), (sa), (cb), (cb_ctx))

#define ssh_policy_qm_nonce_data_len(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,qm_nonce_data_len)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_qm_local_id(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,qm_local_id)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_qm_remote_id(pm_info,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,qm_remote_id)))((pm_info), \
                (cb), (cb_ctx))

#define ssh_policy_cfg_fill_attrs(pm_info,na,ra,cb,cb_ctx) \
        (*(IKE_PM_FUNC(pm_info,cfg_fill_attrs)))((pm_info), \
                (na), (ra), (cb), (cb_ctx))

#define ssh_policy_cfg_notify_attrs(pm_info,na,ra) \
        (*(IKE_PM_FUNC(pm_info,cfg_notify_attrs)))((pm_info), \
                (na), (ra))

#define ssh_policy_delete(pm_info,a,pi,nspi,spi,spis) \
        (*(IKE_PM_FUNC(pm_info,delete_notification)))((pm_info), \
                (a), (pi), (nspi), (spi), (spis))

#define ssh_policy_notification(pm_info,a,pi,spi,spis,nt,nd,nds) \
        (*(IKE_PM_FUNC(pm_info,notification)))((pm_info), \
                (a), (pi), (spi), (spis), (nt), (nd), (nds))

#define ssh_policy_phase_i_notification(pm_info,e,pi,spi,spis,nt,nd,nds) \
        (*(IKE_PM_FUNC(pm_info,phase_i_notification)))((pm_info), \
                (e), (pi), (spi), (spis), (nt), (nd), (nds))

#define ssh_policy_phase_qm_notification(pm_info,pi,spi,spis,nt,nd,nds) \
        (*(IKE_PM_FUNC(pm_info,phase_qm_notification)))((pm_info), \
                (pi), (spi), (spis), (nt), (nd), (nds))

#define ssh_policy_isakmp_sa_freed(pm_info) \
        (*(IKE_PM_FUNC(pm_info,isakmp_sa_freed)))((pm_info))

#define ssh_policy_qm_sa_freed(pm_info) \
        (*(IKE_PM_FUNC(pm_info,qm_sa_freed)))((pm_info))

#define ssh_policy_phase_ii_sa_freed(pm_info) \
        (*(IKE_PM_FUNC(pm_info,phase_ii_sa_freed)))((pm_info))

#define ssh_policy_negotiation_done_isakmp(pm_info,c) \
        (*(IKE_PM_FUNC(pm_info,negotiation_done_isakmp)))((pm_info), (c))

#define ssh_policy_negotiation_done_qm(pm_info,c) \
        (*(IKE_PM_FUNC(pm_info,negotiation_done_qm)))((pm_info), (c))

#define ssh_policy_negotiation_done_phase_ii(pm_info,c) \
        (*(IKE_PM_FUNC(pm_info,negotiation_done_phase_ii)))((pm_info), (c))

#define ssh_policy_phase_i_server_changed(pm_info,server,ip,port) \
        (*(IKE_PM_FUNC(pm_info,phase_i_server_changed)))((pm_info), (server), \
                                                         (ip), (port))

#define ssh_policy_phase_qm_server_changed(pm_info,server,ip,port) \
        (*(IKE_PM_FUNC(pm_info,phase_qm_server_changed)))((pm_info), (server),\
                                                         (ip), (port))

#define ssh_policy_phase_ii_server_changed(pm_info,server,ip,port) \
        (*(IKE_PM_FUNC(pm_info,phase_ii_server_changed)))((pm_info), (server),\
                                                         (ip), (port))

#endif /* SSH_IKE_USE_POLICY_MANAGER_FUNCTION_POINTERS */

#endif /* ISAKMP_INTERNAL_H */
