/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public interface for the PKIX CMP (Certificate Management Protocol)
   message construction API. This file implements structures from
   RFC2510 and RFC2510bis version 0 documents.
*/

#ifndef X509CMP_H
#define X509CMP_H

#include "x509.h"
#include "sshpswbmac.h"

/* The CA may return following status codes, execpt code
   SSH_CMP_STATUS_UNDES, as response to end entitys requests.  */
typedef enum
{
  SSH_CMP_STATUS_UNDEF                   = (-1),
  /* The request was granted as requested, without modifications to
     values provided by the requestor. The CA may have added some new
     values (like serial number). */
  SSH_CMP_STATUS_GRANTED                 =   0,
  /* The request was granted with some modifications to avoid
     overlapping values (e.g. the subject name may have been changed,
     or CA's policy may have removed some requested extensions. */
  SSH_CMP_STATUS_GRANTED_WITH_MODS       =   1,
  /* The CA rejected the requested for some reason. The request did
     not match CA's policy, or the requestor was not allowed to make
     the request. See failure information for more details. */
  SSH_CMP_STATUS_REJECTION               =   2,
  /* The request was not yet processed. */
  SSH_CMP_STATUS_WAITING                 =   3,
  /* Revocation is imminent. */
  SSH_CMP_STATUS_REVOCATION_WARNING      =   4,
  /* Revocation has occured. */
  SSH_CMP_STATUS_REVOCATION_NOTIFICATION =   5,
  /* For key update request response this indicates that the old
     certificate has already been update. */
  SSH_CMP_STATUS_KEY_UPDATE_WARNING      =   6
} SshCmpStatus;









/* These failure values are present when the status indicates
   rejection. For details, see rfc2510 and ID document
   draft-ietf-pkix-rfc2510bis-02.txt */
typedef enum
{
  SSH_CMP_FINFO_BAD_ALG                  = (1 <<  0),
  SSH_CMP_FINFO_BAD_MESSAGE_CHECK        = (1 <<  1),
  SSH_CMP_FINFO_BAD_REQUEST              = (1 <<  2),
  SSH_CMP_FINFO_BAD_TIME                 = (1 <<  3),
  SSH_CMP_FINFO_BAD_CERT_ID              = (1 <<  4),
  SSH_CMP_FINFO_BAD_DATA_FORMAT          = (1 <<  5),
  SSH_CMP_FINFO_WRONG_AUTHORITY          = (1 <<  6),
  SSH_CMP_FINFO_INCORRECT_DATA           = (1 <<  7),
  SSH_CMP_FINFO_MISSING_TIME_STAMP       = (1 <<  8),
  SSH_CMP_FINFO_BAD_POP                  = (1 <<  9),
  SSH_CMP_FINFO_CERT_REVOKED             = (1 << 10),
  SSH_CMP_FINFO_CERT_CONFIRMED           = (1 << 11),
  SSH_CMP_FINFO_WRONG_INTEGRITY          = (1 << 12),
  SSH_CMP_FINFO_BAD_RNONCE               = (1 << 13),
  SSH_CMP_FINFO_TIME_NOT_AVAILABLE       = (1 << 14),
  SSH_CMP_FINFO_UNACCEPTED_POLICY        = (1 << 15),
  SSH_CMP_FINFO_UNACCEPTED_EXTENSION     = (1 << 16),
  SSH_CMP_FINFO_ADDINFO_UNAVAILABLE      = (1 << 17),
  SSH_CMP_FINFO_BAD_SNONCE               = (1 << 18),
  SSH_CMP_FINFO_BAD_TEMPLATE             = (1 << 19),
  SSH_CMP_FINFO_SIGNER_NOTRUST           = (1 << 20),
  SSH_CMP_FINFO_TRANSACTION_INUSE        = (1 << 21),
  SSH_CMP_FINFO_BAD_VERSION              = (1 << 22),
  SSH_CMP_FINFO_NOT_AUTHORIZED           = (1 << 23),
  SSH_CMP_FINFO_SYSTEM_UNAVAIL           = (1 << 24),
  SSH_CMP_FINFO_SYSTEM_FAILURE           = (1 << 25),
  SSH_CMP_FINFO_DUPLICATE_REQUEST        = (1 << 26)
} SshCmpFailure;

/* This structure describes the result of a PKI request. */
typedef struct SshCmpStatusInfoRec
{
  SshCmpStatus status;
  SshCmpFailure failure;

  /* If present (and only if status indicates rejection) this is a
     string that describes verbally what went wrong). */
  SshStr freetext;
} *SshCmpStatusInfo, SshCmpStatusInfoStruct;

/* Protection types for CMP envelopes. The protection may be based on
   keyed MAC calculated over the request, or public key signature
   methods. The diffie-hellman keypair based system is not
   implemented. */
typedef enum
{
  SSH_CMP_PROT_SHARED_SECRET, /* OK; kid identifies shared secret */
  SSH_CMP_PROT_SIGNATURE,     /* OK; kid and sender identify certificate */
  SSH_CMP_PROT_DH_KEY_PAIR,   /* MISS; not supported by cryptolib */
  SSH_CMP_PROT_UNKNOWN
} SshCmpProtectionType;

/* These are the possible request types. */
typedef enum
{
  SSH_CMP_INIT_REQUEST     =  0,  /* OK; EE initialized into the PKI */
  SSH_CMP_INIT_RESPONSE    =  1,  /* OK */
  SSH_CMP_CERT_REQUEST     =  2,  /* OK; initialized EE gets more certs */
  SSH_CMP_CERT_RESPONSE    =  3,  /* OK */
  SSH_CMP_PKCS10_REQUEST   =  4,  /* OK; cert request with body type PKCS#10 */
  SSH_CMP_POP_CHALLENGE    =  5,  /* MISS; use indirect method */
  SSH_CMP_POP_RESPONSE     =  6,  /* MISS; use indirect method */
  SSH_CMP_KEY_UP_REQUEST   =  7,  /* OK; EE request key update for cert. */
  SSH_CMP_KEY_UP_RESPONSE  =  8,  /* OK */
  SSH_CMP_KEY_REC_REQUEST  =  9,  /* OK; EE recovers lost cert or key */
  SSH_CMP_KEY_REC_RESPONSE = 10,  /* OK */
  SSH_CMP_REVOC_REQUEST    = 11,  /* OK; EE revokes her certificate */
  SSH_CMP_REVOC_RESPONSE   = 12,  /* OK */
  SSH_CMP_CROSS_REQUEST    = 13,  /* OK; CA requests cross certificate. */
  SSH_CMP_CROSS_RESPONSE   = 14,  /* OK */
  SSH_CMP_CA_KEY_UP_ANN    = 15,  /* OK; CA announces her key update. */
  SSH_CMP_CERT_ANN         = 16,  /* MISS; use LDAP directory */
  SSH_CMP_REVOC_ANN        = 17,  /* MISS; don't see use for this. */
  SSH_CMP_CRL_ANN          = 18,  /* MISS; use LDAP directory */
  SSH_CMP_CONFIRM          = 19,  /* OK; see rfc2510bis sect 3.3.18 */
  SSH_CMP_NESTED           = 20,  /* OK */
  SSH_CMP_GEN_MESSAGE      = 21,  /* OK; EE asks CA parameters. */
  SSH_CMP_GEN_RESPONSE     = 22,  /* OK */
  SSH_CMP_ERROR_MESSAGE    = 23,  /* OK; EE or CA encounters error. */
  SSH_CMP_CERT_CONFIRM     = 24,  /* OK; see rfc2510bis sect 3.3.18 */
  SSH_CMP_POLL_REQUEST     = 25,  /* MISS */
  SSH_CMP_POLL_RESPONSE    = 26,  /* MISS */
  SSH_CMP_MSG_UNKNOWN      = (-1) /* Unknown message type. */
} SshCmpBodyType;

typedef struct SshCmpMessageRec *SshCmpMessage;

typedef enum {
  SSH_CMP_VERSION_1 = 1,          /* RFC2510 version. Do not use. */
  SSH_CMP_VERSION_2 = 2           /* rfc2510bis version 02 */
} SshCmpVersion;

/* Allocate CMP envelope of given version. All CMP messages in the PKI
   transaction shall use messages of the same version */
SshCmpMessage ssh_cmp_allocate(SshCmpVersion version);

/* Free CMP envelope. */
void ssh_cmp_free(SshCmpMessage message);

/* Get version number of a CMP message. */
SshCmpVersion ssh_cmp_version(SshCmpMessage message);


/* CMP header management functions. */

/* Set the message transaction identifier and nonces.  Either nonce
   pointer may be NULL in which case the corresponding nonce at the
   message is not present. This function copies the nonce values,
   therefore it is safe for the caller to free the values provided
   after this call returns.

   Transaction identifier is used to map subsequent messages into one
   PKI transaction. The nonces are used to prevent replay of messages.
   When EE receives a message as response to her message, she should
   check that the recipient nonce of the message matches the sender
   nonce value of the message she sent. */
void
ssh_cmp_header_set_transaction_id(SshCmpMessage message,
                                  const unsigned char *transaction_id,
                                  size_t transaction_id_len,
                                  const unsigned char *sender_nonce,
                                  size_t sender_nonce_len,
                                  const unsigned char *recip_nonce,
                                  size_t recip_nonce_len);

/* Get transaction identifier and nonce values from the `message'. The
   caller must not free any of the values, as they are pointers inside
   the message itself. The returned values are valid until the
   `message' is freed. */
void
ssh_cmp_header_get_transaction_id(SshCmpMessage message,
                                  const unsigned char **transaction_id,
                                  size_t *transaction_id_len,
                                  const unsigned char **sender_nonce,
                                  size_t *sender_nonce_len,
                                  const unsigned char **recip_nonce,
                                  size_t *recip_nonce_len);

/* Set the sender and recipient name fields to the header. This
   function steals the pointers. The caller must not access, nor free,
   sender or recipient after the function returns.

   If the EE does not know her own name, she can use NULL as sender
   name value. If she has a certificate she uses to authenticate the
   request, she should use the subject name of that certificate as
   sender name.

   The recipient name specifies the recipient of the message. End
   entity shall user the subject name of the CA here. This of course
   requires prior knowledge about the PKI, which shall be obtained
   using some out-of-band mechanism. Note; the CA certificate is not
   needed however. */
void
ssh_cmp_header_set_names(SshCmpMessage message,
                         SshX509Name sender,
                         SshX509Name recipient);

/* Get recipient and sender information from the message. The returned
   values are pointers inside the message and must not be freed by the
   caller. They remain valid until this message is freed. */
void
ssh_cmp_header_get_names(SshCmpMessage message,
                         SshX509Name * const sender,
                         SshX509Name * const recipient);

/* Set the message construction time. Setting this is completely
   optional and does not make any sense for slow transports. */
void
ssh_cmp_header_set_time(SshCmpMessage message, SshTime msg_time);

/* Get the message construction time. Function returns TRUE if the
   message has this optional attribute, and FALSE if attribute is not
   present. */
Boolean
ssh_cmp_header_get_time(SshCmpMessage message, SshTime *msg_time);

/* Determine the protection type used for the message. */
SshCmpProtectionType
ssh_cmp_header_protection_type(SshCmpMessage message);

/*************************************************************************
 * Either set pswbmac, or provide the signing key for the encode routine
 * if message authentication is required.
 *************************************************************************/

/* Set the password based MAC message authenticator. The `pswbmac'
   argument is stolen by the library, it must not be accessed, nor
   freed after this call returns. The `key' values are copied and must
   be freed by the caller. Key values given here are cleared from
   memory after the key has been used during call to
   ssh_cmp_encode. */
void
ssh_cmp_header_set_pswbmac(SshCmpMessage message,
                           SshPSWBMac pswbmac,
                           const unsigned char *key, size_t key_len);

/* Set the message key identifiers for the password based and
   signature authentication. The library copy the `sender_kid' and
   `recipient_kid'. If key id is a NULL pointer or corresponding
   length is zero, the message will not contain that key id.

   For the password based method the sender_kid shall be the reference
   number received from the CA.

   For signature based methods the sender_kid shall be the subject key
   identifier from the certificate that can be used to verify the
   message.

   The recipient_kid is only meaningful for messages that use DH
   keys. */

void
ssh_cmp_header_set_key_id(SshCmpMessage message,
                          const unsigned char *sender_kid,
                          size_t sender_kid_len,
                          const unsigned char *recipient_kid,
                          size_t recipient_kid_len);

/* Get the message key idenfiers. The values returned must not be
   freed by the caller. They remain valid until the message is
   freed. The values returned may be NULL pointers, in which case the
   values are not present. */
void
ssh_cmp_header_get_key_id(SshCmpMessage message,
                          const unsigned char **sender_kid,
                          size_t *sender_kid_len,
                          const unsigned char **recipient_kid,
                          size_t *recipient_kid_len);

/* This function verifies the password based mac protection from the
   `message' with given `key'. The function returns TRUE, if the
   authenticator matches, e.g. the message is genuine, and FALSE, if
   authentication fails.

   After decoding the message, the recipient shall use calls
   ssh_cmp_header_protection_type() to see how the message was
   protected, followed by call to ssh_cmp_header_get_key_id() to find
   out the key_id, which she shall map into key value using some
   external database. */
Boolean
ssh_cmp_header_verify_pswbmac(SshCmpMessage message,
                              const unsigned char *key, size_t key_len);

/* This function verifies the signature based authentication
   from the message. The signature is checked using the `issuer_key'
   public key. The `callback' is called when the public key operation
   completes.

   How the message headers's subject-name and sender-kid are mapped
   into the sender certificate is left for the application.

   The SSH CMi component can be used for this path verification. For
   client initializing this would require use of function
   ssh_cmp_get_extra_certs() to get the CA and intermediate CA
   certificates from the message. */
typedef void (*SshCmpVerifyCB)(SshX509Status status, void *context);

SshOperationHandle
ssh_cmp_header_verify_signature(SshCmpMessage message,
                                const SshPublicKey issuer_key,
                                SshCmpVerifyCB callback,
                                void *callback_context);

/* Access general info extensions from the message. The info's are
   lists of X509 Attribute records, that is they are arbitrary data
   identified by OID values. It is up to the application to
   construct/understand the attribute values. */

void
ssh_cmp_header_add_info(SshCmpMessage message, SshX509Attribute attr);

void
ssh_cmp_header_get_info(SshCmpMessage message,
                        SshX509Attribute * const attrs);

/* Extra certificates and revocation requests. */
typedef struct SshCmpCertSetRec
{
  const unsigned char *ber;
  size_t ber_len;
  /* This is only filled for the revocation case. */
  SshX509RevokedCerts extensions;
} *SshCmpCertSet, SshCmpCertSetStruct;

/* Add one encoded certificate to CMP messages extra-certs. These
   certificates may be used by the receiver to verify protection of
   the message.  Returns TRUE on success. */
Boolean
ssh_cmp_add_extra_cert(SshCmpMessage message,
                       const unsigned char *ber, size_t ber_len);

/* Get extra certs from the message. The value at `ncerts' indicates
   how many certificate were present. The array `certs' will contain
   each of these. If `ncerts' is greater than zero, the caller must
   free pointer `certs'. */
void
ssh_cmp_get_extra_certs(SshCmpMessage message,
                        SshUInt32 *ncerts, SshCmpCertSet *certs);

/* Set the message body type (that is the request type). The contents
   of the message depend on the body type as explained in comments of
   each function group. */
void ssh_cmp_body_set_type(SshCmpMessage message, SshCmpBodyType type);
SshCmpBodyType ssh_cmp_body_get_type(SshCmpMessage message);

/* Creating certificate request content. This function adds the
   BER/DER encoded certificate request to the message. The library
   will free `ber' when the message is freed. See
   ssh_cmp_get_extra_cert for details of get function.

   This function will be used for requests where body type is:
   SSH_CMP_INIT_REQUEST, SSH_CMP_CERT_REQUEST, SSH_CMP_KEY_UP_REQUEST,
   SSH_CMP_KEY_REC_REQUEST and SSH_CMP_CROSS_REQUEST.

   If key recovery is requested, the EE shall create an protocol
   encryption key pair, whose public key she shall add into CRMF (here
   ber) controls. */

void
ssh_cmp_set_cert_request(SshCmpMessage request,
                         const unsigned char *ber, size_t ber_len);

typedef struct SshCmpCertStatusSetRec
{
  SshMPInteger request_id;
  SshCmpStatusInfo info;
  Boolean encrypted;

  const unsigned char *cert;
  size_t cert_len;

  /* Private key is present only for key recovery case. It contains an
     encrypted value (see ssh_crmf_decode_encrypted_value()), which
     the requestor should be able to decode with the protocol
     encryption private keys she has generated for the key recovery
     purposes. */
  const unsigned char *prvkey;
  size_t prvkey_len;
} *SshCmpCertStatusSet, SshCmpCertStatusSetStruct;

/* Get certificate responses. The caller must free pointer resps, but
   not any of its contents, as they point to data that will be freed
   when the response is freed.

   This function can be used for responses whose body type is:
   SSH_CMP_INIT_RESPONSE, SSH_CMP_CERT_RESPONSE,
   SSH_CMP_KEY_UP_RESPONSE, SSH_CMP_KEY_REC_RESPONSE and
   SSH_CMP_CROSS_RESPONSE */

void
ssh_cmp_get_cert_response(SshCmpMessage response,
                          SshUInt32 *nresp, SshCmpCertStatusSet *resps);

void
ssh_cmp_get_recovery_response(SshCmpMessage message,
                              SshUInt32 *nreps, SshCmpCertStatusSet *resps,
                              SshCmpStatusInfo *info);

/* This function can be used to retries CA certificates from the
   certificate repsonse. */
void
ssh_cmp_get_cert_response_ca_certs(SshCmpMessage response,
                                   SshUInt32 *ncas, SshCmpCertSet *cas);

/* Create CMP errorMsg content payload. The error messages sent by
   CA's are always signed with senders private key. The client
   generated error messages may be protected with password-based MAC
   or signature method.

   Receiving of an error message always end the PKI transaction. */

void ssh_cmp_set_error_msg(SshCmpMessage message,
                           const SshCmpStatusInfo status,
                           SshMPIntegerConst error_code,
                           const SshStr details);

void ssh_cmp_get_error_msg(SshCmpMessage message,
                           SshCmpStatusInfo *info,
                           SshMPInteger error_code,
                           SshStr *details,
                           SshStr *instructions);

/* Creating revocation request. The `ber' is the CRMF certificate
   template that identifies the certificate to revoke, and the
   `extensions', if not NULL, may be put into the CA as
   crlEntryExtensions.

   Typically the CRMF for the request should contain at least the
   subject name and the serial number for the certificate to be
   revoked. This information will allow automatic processing of the
   revocation. Of course the CMP envelope should be protected.

   This function may be called many times to add multiple certificates
   for revocation request. */
void
ssh_cmp_add_revocation_request(SshCmpMessage request,
                               const unsigned char *ber, size_t ber_len,
                               SshX509RevokedCerts extensions);

typedef struct SshCmpRevokedSetRec
{
  SshCmpStatusInfo status;
  SshX509Name issuer;
  const SshMPIntegerStruct *serial;

  /* The revocation response may contain CRL's that contain the revoked
     certs. This is however optional, as the CA may not generate the CRL's
     at the exact time of revocation, but periodially. */
  const unsigned char *crl;
  size_t crl_len;
} *SshCmpRevokedSet, SshCmpRevokedSetStruct;

/* This function can be used for body types SSH_CMP_REVOC_RESPONSE to
   retrieve status for each revoked certificate in the request. */
void
ssh_cmp_get_revocation_response(SshCmpMessage response,
                                SshUInt32 *nrevoked,
                                SshCmpRevokedSet *revoked);

/* Creating CA Key Update Announcement. This may be put available into
   some well known location. Typically when this has been done, the CA
   would add CAKeyUpdAnnContent OID to the generalInfo header for the
   clients that contacted and used the old CA key. */
void
ssh_cmp_get_cku_announce(SshCmpMessage announce,
                         const unsigned char **oldnew, size_t *oldnew_len,
                         const unsigned char **newold, size_t *newold_len,
                         const unsigned char **newnew, size_t *newnew_len);


/* Creating GeneralMessage and GeneralResponse messages for getting
   CA/PKI parameters. Attribute at a time can be added to
   message/response, and a chain of attributes can be extracted from
   the message.

   The function ssh_cmp_add_gen_message will steal the `attrs'
   pointer, and will free it when no longer needed. The application
   calling this function must not access, nor free, the attributes. */
void
ssh_cmp_add_gen_message(SshCmpMessage message,
                        SshX509Attribute attrs);

void
ssh_cmp_get_gen_message(SshCmpMessage message,
                        SshX509Attribute * const attrs);

/* Creating Certificiate Confirmation message. The function can be
   used to add confirmation for certificate that was received with
   given `request_id' (from SshCmpCertStatusSet).  For encryption
   certificates with indirect PoP the fingerprint is to given in
   `hash' and `hash_len' (should be NULL, 0 for verification
   certificates). The hash is calculated with algorithm from the
   certificate issued.

   If the `status' is NULL, the certificate is confirmed. If it is not
   NULL, it may either reject the certificate or give some auditing
   information for the CA's purposes.

   As a shorthand Certificate Confirm message without body contents
   (that is ssh_cmp_set_body_type(CONF) and not calling this function)
   can be used to reject all certificates issued at the transaction
   this message belongs to.

   The certificate confimation message MUST be send after receiving
   certificates. If this is not send, the CA will revoke the
   certificates issued. */
void
ssh_cmp_add_cert_confirm(SshCmpMessage confirm,
                         SshMPIntegerConst request_id,
                         const unsigned char *hash, size_t hash_len,
                         const SshCmpStatusInfo status);

/* This function adds polling response for certificate specified by
   'request_id'. The receiver of this message should wait for
   'check_after_seconds' before issuing CMP polling request for the
   request. The 'optional_reason' can be used to pass information, why
   the request was not accepted right away. */
void
ssh_cmp_add_poll_response(SshCmpMessage response,
                          SshMPIntegerConst request_id,
                          SshUInt32 check_after_seconds,
                          const SshStr optional_reason);
void
ssh_cmp_get_poll_responses(SshCmpMessage response,
                           SshUInt32 *nresponses,
                           SshMPInteger **request_ids,
                           SshUInt32 **check_after_seconds,
                           SshStr **optional_reasons);

/* This function adds polling request for certificate request
   identified by 'request_id'. This request identifier was previously
   returned by CA using initialization, or certificate confimation
   messages, or polling response message. */
void
ssh_cmp_add_poll_request(SshCmpMessage request, SshMPIntegerConst request_id);

void
ssh_cmp_get_poll_requests(SshCmpMessage request,
                          SshUInt32 *nrequest_ids, SshMPInteger **request_ids);

/* Encode PKI message. Depending on the envelope authentication method
   this may yield up calling private key signature operation. Therefore
   the API is asynchronous. */

typedef void (*SshCmpEncodeCB)(SshX509Status status,
                               const unsigned char *ber, size_t ber_len,
                               void *context);

/* Encode and sign the CMP at `message'. This function calls
   `callback' when with `callback_context' as callbacks
   context-argument when the message has been encoded. If the message
   authentication method is public key based, the `signing_key'
   specifies the key to use.  This key must be valid until the
   callback gets called.  The function steals the `message'
   argument. It must not be freed, nor accessed after call to this
   function. */

SshOperationHandle
ssh_cmp_encode(SshCmpMessage message,
               SshPrivateKey signing_key,
               SshCmpEncodeCB callback, void *callback_context);


/* Decode the PKI message. This does not verify the message, but only
   deconstructs the BER and parses the content. */
SshX509Status
ssh_cmp_decode(const unsigned char *buf, size_t buf_len,
               SshCmpMessage *message);

/* Creating certificate response contents. The library will free the
   `ber' when the message is freed.  See ssh_cmp_get_extra_cert for
   details of get function.

   This function will be used for message types
   SSH_CMP_INIT_RESPONSE, SSH_CMP_CERT_RESPONSE, SSH_CMP_KEY_UP_RESPONSE,
   and SSH_CMP_CROSS_RESPONSE */

void
ssh_cmp_add_cert_response(SshCmpMessage response,
                          SshMPIntegerConst request_id,
                          const SshCmpStatusInfo status,
                          /* The rest constitutes the certified key pair. */
                          Boolean encrypted,
                          const unsigned char *cert, size_t cert_len,
                          const unsigned char *prvkey, size_t prvkey_len);


#endif /* X509CMP_H */
