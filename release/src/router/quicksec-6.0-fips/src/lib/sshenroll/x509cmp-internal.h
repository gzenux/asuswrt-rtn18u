/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef X509CMPINTERNAL_H
#define X509CMPINTERNAL_H

#include "x509.h"
#include "sshpswbmac.h"
#include "sshglist.h"

typedef struct SshCmpProtectionInfoRec
{
  /* Password based mac. */
  SshPSWBMac pswbmac;

  /* The password. */
  unsigned char *key;
  size_t key_length;

  /* Signature key. */
  SshPrivateKey prv_key;

  /* Signature information, when private key is not present. */
  SshX509SignatureStruct signature;
} *SshCmpProtectionInfo;

typedef struct SshCmpHeaderRec
{
  /* Version number. */
  unsigned int pnvo;

  /* Transaction identifier. */
  unsigned char *transaction_id;
  size_t         transaction_id_len;

  /* Sender and Recipient names. */
  SshX509Name sender;
  SshX509Name recipient;
  /* Time of production of this message. */
  SshBerTimeStruct  message_time;
  /* Protection algorithm information. */
  struct SshCmpProtectionInfoRec protection_info;

  /* Key identifiers. */
  unsigned char *sender_kid;
  size_t         sender_kid_len;
  unsigned char *recip_kid;
  size_t         recip_kid_len;

  /* Nonces. */
  unsigned char *sender_nonce;
  size_t         sender_nonce_len;
  unsigned char *recip_nonce;
  size_t         recip_nonce_len;
  /* TODO: list of freetext. */
  SshStr         freetext;

  SshX509Attribute general_infos;
} *SshCmpHeader;

typedef struct SshCmpErrorMsgRec
{
  SshCmpStatusInfoStruct status;
  SshMPIntegerStruct error_code;
  SshStr details;
} *SshCmpErrorMsg, SshCmpErrorMsgStruct;

typedef struct SshCmpCertificateRec
{
  Boolean encrypted;
  unsigned char *cert, *prvkey;
  size_t cert_len, prvkey_len;
} *SshCmpCertificate, SshCmpCertificateStruct;

typedef struct SshCmpCertResponseNodeRec
{
  /* List of response nodes */
  struct SshCmpCertResponseNodeRec *next;

  /* The request id. */
  SshMPIntegerStruct request_id;

  /* The PKI status information. */
  SshCmpStatusInfoStruct pki_status;

  /* Certified key pair. */
  SshCmpCertificateStruct cert;

  /* Response info. */
  unsigned char *rsp_info;
  size_t rsp_info_len;

} *SshCmpCertResponseNode;

typedef struct SshCmpCertResponseRec
{
  /* Some published certificates. */
  SshGList ca_pubs;

  /* Certificate response node head. */
  SshCmpCertResponseNode list;

} *SshCmpCertResponse, SshCmpCertResponseStruct;

typedef struct SshCmpRecResponseRec
{
  SshCmpStatusInfoStruct pki_status;

  SshCmpCertificate newsigcert;

  /* Sequence of CmpCertificates */
  SshGList cacerts;
  /* Sequence of CertifiedKeyPairs */
  SshGList keypairhist;
} *SshCmpRecResponse , SshCmpRecResponseStruct;

typedef struct SshCmpRevRequestRec
{
  SshCmpCertificate cert_template;
  SshX509RevokedCerts crl_extensions;
} *SshCmpRevRequest, SshCmpRevRequestStruct;

typedef struct SshCmpRevResponseRec
{
  SshCmpStatusInfoStruct status;
  SshX509CertId id;
  unsigned char *crl;
  size_t crl_len;
  struct SshCmpRevResponseRec *next;
} *SshCmpRevResponse, SshCmpRevResponseStruct;

typedef struct SshCmpCKUAnnRec
{
  void *foo;
} *SshCmpCKUAnn, SshCmpCKUAnnStruct;

typedef struct SshCmpRevAnnRec
{
    void *foo;
} *SshCmpRevAnn, SshCmpRevAnnStruct;

typedef struct SshCmpCertConfRec
{
  Boolean request_id_set;
  SshMPIntegerStruct request_id;
  unsigned char *hash;
  size_t hash_len;
  SshCmpStatusInfoStruct pki_status;
} *SshCmpCertConf, SshCmpCertConfStruct;

typedef struct SshCmpPollMsgRec
{
  Boolean this_is_response;
  SshMPIntegerStruct request_id;
  SshUInt32 poll_when;
  SshStr reason;
} *SshCmpPollMsg, SshCmpPollMsgStruct;

typedef struct SshCmpBodyRec
{
  SshCmpBodyType type;

  /* List of requests. Must contain the requests in DER encoded
     form. These must be in the GList data and data_length fields.
     Depends upon the "type". The DER decodes into SshX509Certificate
     data type.  This is used by
         SSH_X509_CMP_INIT_REQUEST
         SSH_X509_CMP_CERT_REQUEST
         SSH_X509_CMP_KEY_UP_REQUEST
         SSH_X509_CMP_KEY_REC_REQUEST
         SSH_X509_CMP_CROSS_REQUEST
    */
  SshGList cert_requests;

  /* Certificate responses. This is used by
        SSH_X509_CMP_INIT_RESPONSE:
        SSH_X509_CMP_CERT_RESPONSE:
        SSH_X509_CMP_KEY_UP_RESPONSE:
        SSH_X509_CMP_CROSS_RESPONSE:
    */
  SshCmpCertResponseStruct cert_response;

  /* Pop challenge. List of Challenge structures. */
  SshGList pop_challenge;

  /* Pop response. List of integers. */
  SshGList pop_responses;

  /* Key recovery response. */
  SshCmpRecResponseStruct rec_response;

  /* Revocation request, list of SshCmpRevRequest */
  SshGList rev_requests;

  /* Revocation response. */
  SshCmpRevResponse rev_response;

  /* CA key update announcement. */
  SshCmpCKUAnnStruct  cku_announce;

  /* Certificate announcement. */
  SshCmpCertificateStruct cert_announce;

  /* Revocation announcement. */
  SshCmpRevAnnStruct  rev_announce;

  /* CRL announcement. This is a list of CRL's.  */
  SshGList crl_announce;

  /* General message. */
  /* General response. */
  SshX509Attribute general_infos;

  /* Error message. */
  SshCmpErrorMsgStruct error_msg;

  /* Certificate confirm is sequence of certificate status entries */
  SshGList cert_confirm;

  /* Certificate polling requests and responses. */
  SshGList poll_req_rep;

  /* Nested message payload. */
  SshGList nested_messages;
} *SshCmpBody;

struct SshCmpMessageRec
{
  struct SshCmpHeaderRec header;
  struct SshCmpBodyRec   body;

  /* A encoded DER of the header and body. Used for verification. */
  unsigned char *protection;
  size_t protection_len;

  /* A list of certificates. These are just the DER encoded
     certificates, they have not been decoded and parsed.  (No
     additional data structure used, the GList contains the DER in its
     data and data_length fields.) */
  SshGList certificates;

  SshX509ConfigStruct config;
};


/* From UTIL */
void cmp_pki_status_init(SshCmpStatusInfo pinfo);
void cmp_pki_status_clear(SshCmpStatusInfo pinfo);

void cmp_cert_response_node_init(SshCmpCertResponseNode r);
void cmp_cert_response_node_clear(SshCmpCertResponseNode r);
void cmp_cert_response_init(SshCmpCertResponse r);
void cmp_cert_response_clear(SshCmpCertResponse r);

void cmp_cert_init(SshCmpCertificate c);
void cmp_cert_clear(SshCmpCertificate c);
void cmp_cert_free_glist(SshGListNode node, void *context);

void cmp_error_msg_init(SshCmpErrorMsg e);
void cmp_error_msg_clear(SshCmpErrorMsg e);

void cmp_cert_confirm_init(SshCmpCertConf c);
void cmp_cert_confirm_clear(SshCmpCertConf c);
void cmp_cert_confirm_free_glist(SshGListNode node, void *context);

void cmp_protection_info_init(SshCmpProtectionInfo pinfo);
void cmp_protection_info_clear(SshCmpProtectionInfo pinfo);

void cmp_rec_response_init(SshCmpRecResponse r);
void cmp_rec_response_clear(SshCmpRecResponse r);
void cmp_rev_response_init(SshCmpRevResponse r);
void cmp_rev_response_clear(SshCmpRevResponse r);

void cmp_rev_announce_init(SshCmpRevAnn r);
void cmp_rev_announce_clear(SshCmpRevAnn r);

void cmp_cku_announce_init(SshCmpCKUAnn r);
void cmp_cku_announce_clear(SshCmpCKUAnn r);

void cmp_header_init(SshCmpHeader h);
void cmp_header_clear(SshCmpHeader h);
void cmp_body_init(SshCmpBody b);
void cmp_body_clear(SshCmpBody b);
void cmp_message_init(SshCmpMessage msg);
void cmp_message_clear(SshCmpMessage msg);

void cmp_poll_init(SshCmpPollMsg r);
void cmp_poll_clear(SshCmpPollMsg r);

SshUInt32 cmp_get_certs(SshGList list, SshCmpCertSet *certs);

SshX509Status
cmp_encode_protection_data(SshAsn1Context context,
                           SshAsn1Node header, SshAsn1Node body,
                           unsigned char **buf, size_t *buf_len);

#endif /* X509CMPINTERNAL_H */
