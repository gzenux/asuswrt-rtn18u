/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   ocsp_internal.h
*/

#ifndef OCSP_INTERNAL_H
#define OCSP_INTERNAL_H

#include "sshglist.h"
#include "sshmp.h"

#include "sshocspclient.h"
#include "sshocspresponder.h"

#include "sshcrypt.h"
#include "sshasn1.h"

/* An oid for the basic OCSP message. */
#define SSH_OCSP_OID_RESPONSE_TYPE_BASIC "1.3.6.1.5.5.7.48.1.1"

/* OID for the nonce extension. */
#define SSH_OCSP_NONCE "1.3.6.1.5.5.7.48.1.2"

typedef struct SshOcspSingleRequestRec
{
  struct SshOcspCertIDRec cert_id;
  SshX509Attribute single_request_extensions;
} *SshOcspSingleRequest;

typedef struct SshOcspTbsRequestRec
{
  SshOcspVersion version;
  SshX509Name requestor_name;
  SshGList request_list;
  SshX509Attribute request_extensions;
} *SshOcspTbsRequest;


struct SshOcspRequestRec
{
  SshX509SignatureStruct sig;
  struct SshOcspTbsRequestRec tbs_request;

  unsigned char *optional_signature;
  size_t signature_len;

  /* certs in Signature */
  SshGList cert_list;
  /* When private key is not present, these are used. */
  /* signatureAlgorithm in Signature */
  const char *signature_algorithm;
  /* signature type */
  SshX509PkAlgorithm signature_type;

  /* An encoded DER of the tbsResponseData. Used for verification. */
  unsigned char *verification;
  size_t verification_len;

  /* Shall we sign the request */
  Boolean sign_request;
};

/***************** Response structs *******************/

typedef struct SshOcspSingleResponseRec
{
  SshX509Certificate issuer_certificate;
  struct SshOcspCertIDRec cert_id;
  struct SshOcspCertStatusRec status;
  SshBerTimeStruct this_update;
  SshBerTimeStruct next_update;
  SshX509Attribute single_extensions;
} *SshOcspSingleResponse, SshOcspSingleResponseStruct;

typedef struct SshOcspResponderIdRec {
  SshOcspResponderIDType type; /* byName = 1, byKey = 2 */
  union
  {
    struct
    {
      SshX509Name name;
    } ByName;
    struct
    {
      unsigned char *key_hash;
      size_t hash_len;
    } ByKey;
  } id;
} *SshOcspResponderId;

typedef struct SshOcspTbsResponseDataRec
{
  SshOcspVersion version;
  /* Is version information available. */
  Boolean version_available;
  struct SshOcspResponderIdRec responder_id;
  SshBerTimeStruct produced_at;
  SshGList response_list;
  SshX509Attribute response_extensions;
  /* Decode only! This is filled from the response received, to
     contain pointer to containing objects der encoding of data
     signed, and its length. This must not be freed. */
  unsigned char *data;
  size_t data_len;

} *SshOcspTbsResponseData;

typedef struct SshOcspBasicResponseRec {
  struct SshOcspTbsResponseDataRec tbs_response_data;
  const char *signature_algorithm;
  unsigned char *signature;
  size_t signature_len;
  SshGList cert_list;
} *SshOcspBasicResponse;

struct SshOcspResponseRec
{
  SshOcspResponseStatus response_status;
  SshOcspResponseType response_type;
  struct SshOcspBasicResponseRec response;

  /* response as bytes, calculated from SshOcspBasicResponse */
  unsigned char *response_bytes;
  size_t response_len;

  /* An encoded DER of the tbsResponseData. Used for verification. */
  unsigned char *verification;
  size_t verification_len;
};

/* functions from the ocsp_encode.c */
SshOcspStatus
ocsp_encode_optional_signature(SshAsn1Context context,
                               SshAsn1Node tbs_request,
                               unsigned char **buf, size_t *buf_len);

SshOcspStatus
ocsp_encode_tbs_response_data(SshAsn1Context context,
                              SshOcspTbsResponseData response_data,
                              SshAsn1Node *response_node);
SshOcspStatus
ocsp_encode_response_for_signing(SshAsn1Context context,
                                 SshAsn1Node response_data,
                                 unsigned char **buf, size_t *buf_len);

/* Functions needed only in debugging. */

/* Get the length of the signature in the request. */
int ssh_ocsp_request_get_signature_length(SshOcspRequest request);

/* Get the signature and algorithm from the request. */
void ssh_ocsp_request_get_signature(SshOcspRequest request,
                                    const char **signature_algorithm,
                                    const unsigned char **optional_signature,
                                    size_t *optional_signature_length);

/* Get the signature and algorithm from the response. */
void ssh_ocsp_response_get_signature(SshOcspResponse response,
                                     const char **signature_algorithm,
                                     const unsigned char **signature,
                                     size_t *signature_length);

/* Create nonce for the extension. Internal only. */
Boolean ssh_ocsp_extension_create_nonce(SshX509Attribute attr,
                                        SshMPInteger value);


/* Get nonce from the extensions. */
SshMPInteger ssh_ocsp_extension_get_nonce(const SshX509Attribute extensions);



SshOperationHandle
ocsp_verify_signature(const char *signature_algorithm,
                      unsigned char *signature,
                      size_t signature_len,
                      unsigned char *data,
                      size_t data_len,
                      const SshPublicKey public_key,
                      SshOcspVerifyCB callback,
                      void *callback_context);


SshOcspStatus
ocsp_create_cert_id(SshOcspCertID cert_id,
                    const char *hash_algorithm,
                    const SshX509Certificate issuer_certificate,
                    SshMPIntegerConst subject_serial);
SshOcspStatus
ocsp_decode_cert_id(SshAsn1Context context,
                    SshAsn1Node node,
                    SshOcspCertID cert_id);
SshOcspStatus
ocsp_encode_cert_id(SshAsn1Context context,
                    SshAsn1Node *node,
                    SshOcspCertID cert_id);

SshOcspStatus
ocsp_decode_extensions(SshAsn1Context context,
                       SshAsn1Node node,
                       SshX509Attribute *attrs);
SshOcspStatus
ocsp_encode_extensions(SshAsn1Context context,
                       SshX509Attribute extensions,
                       SshAsn1Node *extensions_node);

size_t ocsp_get_certs(SshGList list, SshOcspEncodedCert *certs);
SshOcspStatus ocsp_add_cert(SshGList cert_list,
                            const unsigned char *ber, size_t ber_len);

SshOcspStatus
ocsp_decode_cert_list(SshAsn1Context context,
                      SshAsn1Node node,
                      SshGList glist);

SshX509Status
ocsp_encode_cert_list(SshAsn1Context context,
                      SshGList glist,
                      SshAsn1Node *cert_list);

/* This structure holds the state during signature operation. */
typedef struct SshOcspEncodeContextRec
{
  SshOcspResponse response;
  SshOcspRequest request;
  SshAsn1Node tbs_message;        /* can be request or response */
  SshPrivateKey key;
  SshOcspEncodeCB callback;
  SshAsn1Context asn1context;
  SshOperationHandle signature_op;
  SshOperationHandle operation;
  void *callback_context;
} *SshOcspEncodeContext, SshOcspEncodeContextStruct;

#endif /* OCSP_INTERNAL_H */
