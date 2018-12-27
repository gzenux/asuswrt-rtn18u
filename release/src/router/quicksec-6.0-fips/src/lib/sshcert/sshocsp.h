/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A public interface for the PKIX OCSP (Online Certificate Status
   Protocol) message handling. The implemention is done according to
   the RFC2560.
*/

#ifndef SSHOCSP_H
#define SSHOCSP_H

#include "x509.h"

/* The id-kp-OCSPSigning object identifier for the extendedKeyUsage
   extension of the certificate. The oid can be used to denote the
   authority to sign OCSP responses on behalf of the issuer. */
#define SSH_OCSP_OID_ID_KP_OCSPSIGNING "1.3.6.1.5.5.7.3.9"

/* The id-pkix-ocsp-nocheck object identifier for a certificate extension.
   The oid can be used to specify that the client can trust a responder for
   the lifetime of the responder's certificate. */
#define SSH_OCSP_OID_ID_PKIX_OCSP_NOCHECK "1.3.6.1.5.5.7.48.1.5"

/* The id-ad-ocsp object identifier for the AuthorityInfoAccess
   extension of the certificate. It can be used to inform the location
   of the OCSP responder. */
#define SSH_OCSP_OID_ID_AD_OCSP "1.3.6.1.5.5.7.48.1"

/* Type definitions for the request and response messages. */
typedef struct SshOcspRequestRec *SshOcspRequest;
typedef struct SshOcspResponseRec *SshOcspResponse;


/* Version definition(s) for the requests and responses. The value
   is taken from the RFC. */
typedef enum
{
    SSH_OCSP_VERSION_V1 = 0
} SshOcspVersion;

/* Response type definition(s). At the moment there are only
   responses of one type. */
typedef enum
{
    SSH_OCSP_RESPONSE_TYPE_BASIC
} SshOcspResponseType;


/* Status values that the functions might return. */
typedef enum
{
    /* Everything OK */
    SSH_OCSP_STATUS_OK                       = 0,

    /* Passed argument has been invalid (probably NULL when
       NULL values are not allowed. */
    SSH_OCSP_STATUS_INVALID_OPERAND,

    /* Some internal error has occurred. The functions should
       not never return this status. */
    SSH_OCSP_STATUS_INTERNAL_ERROR,

    /* ASN1 encoding failed. */
    SSH_OCSP_STATUS_FAILED_ASN1_ENCODE,

    /* ASN1 decoding failed. */
    SSH_OCSP_STATUS_FAILED_ASN1_DECODE,

    /* Private key was not present when it was needed. */
    SSH_OCSP_STATUS_PRIVATE_KEY_NOT_FOUND,

    /* Private key operation failed. */
    SSH_OCSP_STATUS_FAILED_PRIVATE_KEY_OPS,

    /* Public key operation failed. */
    SSH_OCSP_STATUS_FAILED_PUBLIC_KEY_OPS,

    /* Signature did not match. */
    SSH_OCSP_STATUS_FAILED_SIGNATURE_CHECK,

    /* Someone tried to use hash algorithm that is not known. */
    SSH_OCSP_STATUS_UNKNOWN_HASH_ALGORITHM,

    /* Someone tried to use signature algorithm that is not known. */
    SSH_OCSP_STATUS_UNKNOWN_SIGNATURE_ALGORITHM,

    /* An unknown certificate status value was found.
       Don't confuse with SSH_OCSP_CERT_STATUS_UNKNOWN. */
    SSH_OCSP_STATUS_UNKNOWN_CERT_STATUS,

    /* An unknown responder ID type was found. */
    SSH_OCSP_STATUS_UNKNOWN_RESPONDERID_TYPE,

    /* An unknown response type was found. */
    SSH_OCSP_STATUS_UNKNOWN_RESPONSE_TYPE,

    /* A NULL pointer was offered as a certificate. */
    SSH_OCSP_STATUS_INVALID_CERTIFICATE,

    /* An invalid serial number was found. */
    SSH_OCSP_STATUS_INVALID_SERIAL_NUMBER,

    /* An HTTP operation has failed. */
    SSH_OCSP_STATUS_HTTP_ERROR
} SshOcspStatus;


/* Certificates can have three different statuses:
   Good, Revoked, Unknown. Values are used in the response to
   denote the status of the requested certificate. The values are
   taken from the RFC. */
typedef enum
{
    SSH_OCSP_CERT_STATUS_GOOD    = 0,
    SSH_OCSP_CERT_STATUS_REVOKED = 1,
    SSH_OCSP_CERT_STATUS_UNKNOWN = 2  /* The certificate is unknown. */
} SshOcspResponseCertStatus;


/* Is responder identified by name or by its public key hash. The
   values match with the values in the RFC. */
typedef enum
{
    SSH_OCSP_RESPONDER_BY_NAME = 1,
    SSH_OCSP_RESPONDER_BY_KEY  = 2
} SshOcspResponderIDType;


/* Statuses for the response messages according to the RFC.
   If everything goes fine on the responder side, responder sends the
   SSH_OCSP_SUCCESSFUL status and the actual response bytes.
   In other cases, something has gone wrong and only the error status
   is sent. */
typedef enum
{
    SSH_OCSP_SUCCESSFUL        = 0, /* Response has valid confirmations */
    SSH_OCSP_MALFORMED_REQUEST = 1, /* Illegal confirmation request */
    SSH_OCSP_INTERNAL_ERROR    = 2, /* Internal error on the responder side */
    SSH_OCSP_TRY_LATER         = 3, /* Try again later */
                                    /* (4) is not used */
    SSH_OCSP_SIG_REQUIRED      = 5, /* Must sign the request */
    SSH_OCSP_UNAUTHORIZED      = 6  /* Request unauthorized */
} SshOcspResponseStatus;


/* A structure that holds extra information about the status of a
   certificate. At the moment extra data exists only for revoked
   certificates. */
typedef struct SshOcspCertStatusRec
{
    SshOcspResponseCertStatus status; /* good, revoked or unknown */
    union
    {
        /* There is no data for ´good' or ´unknown' statuses. */
        struct
        {
            SshTime revocation_time;
            /* Does ´revocation_reason' contain valid information. */
            Boolean reason_available;
            /* The revocation reason code according to the RFC 2459. */
            SshX509CRLReasonCode revocation_reason;
        } revoked;
    } statusinfo;
} *SshOcspCertStatus, SshOcspCertStatusStruct;


/* A structure for the information about the certificates whose
   status is queried or replied. */
typedef struct SshOcspCertIDRec
{
    char *hash_algorithm;
    size_t hash_len;
    unsigned char *issuer_name_hash;
    unsigned char *issuer_key_hash;
    SshMPIntegerStruct serial_number;
} *SshOcspCertID, SshOcspCertIDStruct;


/* S structure for encoded certificates. */
typedef struct SshOcspEncodedCertRec
{
    unsigned char *ber;
    size_t ber_len;
} *SshOcspEncodedCert, SshOcspEncodedCertStruct;


/* A callback function type for the encoding routines. The function is
   called when operation is finished. ´der' contains the encoded message,
   ´der_len' tells the length of it and ´context' is a pointer that
   was passed to the encoding routine. */

typedef void(*SshOcspEncodeCB)(SshOcspStatus status,
                               const unsigned char *der, size_t der_len,
                               void *context);

/* A callback function type for the signature verification routines.
   The function is called when the operation is finished. ´context' points
   to the data that was passed to the verification function by the
   caller. ´status' tells whether the operation was successful. */

typedef void(*SshOcspVerifyCB)(SshOcspStatus status,
                               void *context);

/* A function to free requests that are created using the decoding
   function. Requests created using the ssh_ocsp_request_allocate
   function are freed typically by calling the function
   ssh_ocsp_http_send_request that internally frees the requests
   automatically. */

void ssh_ocsp_request_free(SshOcspRequest request);

/* A function to free response messages that were allocated by the
   decoding function. Responses created using the
   ssh_ocsp_response_allocate function are typically freed
   automatically when the ssh_ocsp_response_encode function is
   called. */

void ssh_ocsp_response_free(SshOcspResponse response);

#endif /* SSHOCSP_H */
