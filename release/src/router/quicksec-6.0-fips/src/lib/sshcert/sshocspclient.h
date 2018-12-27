/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A public interface for the client part of the PKIX OCSP
   (Online Certificate Status Protocol). The implemention is done
   according to the RFC2560.
*/

#ifndef SSHOCSPCLIENT_H
#define SSHOCSPCLIENT_H

#include "sshocsp.h"

/* A structure for the basic single responses. */
typedef struct SshOcspBasicSingleResponseRec
{
  SshOcspCertIDStruct cert_id;    /* identifies the certificate */
  SshOcspCertStatusStruct status; /* the status of the certificate */
  SshTime this_update;            /* when the status was updated. */
  Boolean next_update_available;  /* is next update time defined. */
  SshTime next_update;            /* when is the next update. (optional) */
  SshX509Attribute single_response_extensions; /* any extensions */
} *SshOcspBasicSingleResponse;

/******************** Request handling on client side *******************/

/* A function to allocate requests. Returned message is freed
   automatically when the ssh_ocsp_http_send_request function is called.
   The message can also be freed using the ´ssh_ocsp_request_free' function.
   ´requestor_name' is needed only in signed requests so it can be NULL
   in unsigned requests. Extensions are optional and should be handled
   outside this module. The ´extensions' parameter is freed when the request
   is freed and the pointer should be valid until that. Its value can be
   NULL if the extensions are not used. */

SshOcspRequest ssh_ocsp_request_allocate(SshOcspVersion version,
                                         const SshX509Name requestor_name,
                                         SshX509Attribute extensions);


/* Add a single request to the request message. This function can be
   called multiple times for one request.

   ´hash_algorithm' tells the algorithm that is used to calculate the
   hash of the issuer name and public key.

   ´issuer_certificate' should contain the certificate of the entity
   that issued the certificate whose serial number is defined by
   the parameter ´subject_serial'. If the certificate is not available,
   it can be easily constructed as only the subject name and the public
   key are used from it.

   The certificate whose status is to be queried is defined in
   the parameter ´subject_serial'. It can be freed after the function
   call.

   The ´single_request_extensions' variable can contain any extensions
   but they have to be handled outside this module. The memory reserved
   for the parameter ´single_request_extensions' is freed when
   the request is freed so the pointer should be valid until that.
*/
SshOcspStatus
ssh_ocsp_request_add_single(SshOcspRequest message,
                            const char *hash_algorithm,
                            const SshX509Certificate issuer_certificate,
                            SshMPIntegerConst subject_serial,
                            SshX509Attribute single_request_extensions);


/* Add one encoded certificate to the message. Certificates can
   be included to help the responder to verify the requestor's
   signature. */
SshOcspStatus
ssh_ocsp_request_add_cert(SshOcspRequest message,
                          const unsigned char *ber, size_t ber_len);


/*
   Encode the OCSP Request. This function does not have to be called
   if the request is sent to the responder using the
   ssh_ocsp_http_send_request function because it takes care of the
   encoding. But if for some reason the encoded request is needed,
   this function provides it.

   Private key is used to sign the message if the key is available.
   If it is NULL, the request will not be signed. If a key
   is passed, the corresponding requestor name should be set using
   the ssh_ocsp_request_allocate function. The key should be valid
   until the callback function is called.

   The request is freed after encoding so it can not be used after
   calling this function.

   ´callback' specifies the callback function that is called after
   the encoding has been done.

   ´callback_context' can hold any data that the caller wants to
   pass to the callback function.

   The function returns a handle to the operation if the callback
   function is not called directly.
*/
SshOperationHandle ssh_ocsp_request_encode(SshOcspRequest message,
                                           const SshPrivateKey key,
                                           SshOcspEncodeCB callback,
                                           void *callback_context);

/******************** Response handling on client side *******************/

/* This function does not have to be called if the request was sent using
   the function ssh_ocsp_http_send_request. It decodes the response
   automatically.

   The function decodes the byte block defined by ´der' and ´der_len' to
   an OCSP response. Function allocates memory for the message. The caller
   should free the memory using the ssh_cosp_request_free function. */
SshOcspStatus ssh_ocsp_response_decode(const unsigned char *der,
                                       size_t der_len,
                                       SshOcspResponse *message);

/* Get the version of the message. */
SshOcspVersion ssh_ocsp_response_get_version(SshOcspResponse response);

/* Get the status of the response. */
SshOcspResponseStatus ssh_ocsp_response_get_status(SshOcspResponse response);


/* Get the type of the response. */
SshOcspResponseType
ssh_ocsp_response_get_response_type(SshOcspResponse response);


/* Get the information that tells whether the responder is identified by
   the name or by the public key hash. The functions
   ssh_ocsp_response_get_responder_name() and
   ssh_ocsp_response_get_responder_key() are used to get the actual
   responder identification. You should call only the function that
   is denoted by the type returned by the function
   ssh_ocsp_response_get_responder_id_type(). */
SshOcspResponderIDType
ssh_ocsp_response_get_responder_id_type(SshOcspResponse response);

SshX509Name
ssh_ocsp_response_get_responder_name(SshOcspResponse response);

/* The returned public key hash is calculated using the SHA-1
   algorithm and its length is always 20 bytes. */
const unsigned char*
ssh_ocsp_response_get_responder_key(SshOcspResponse response,
                                    size_t *responder_key_len);


/* Get the time when the response was produced. */
SshTime ssh_ocsp_response_get_production_time(SshOcspResponse response);


/* Get extensions that were attached to the response. If there are
   no extensions available, the return value is NULL. */

SshX509Attribute
ssh_ocsp_response_get_extensions(SshOcspResponse response);


/* Get certs from the message. The value at `ncerts' indicates
   how many certificates were present. The array `certs' will contain
   the certificates. The returned array should be freed with the function
   ssh_xfree. Certificates can be used to check the signature of the
   responder and whether the responder can be trusted. */

void
ssh_ocsp_response_get_certs(SshOcspResponse message,
                            SshOcspEncodedCert *certs, size_t *ncerts);


/* ´public_key' defines the public key of the responder. It is used
   to check the signature found in the response.

   Function determined by the parameter ´callback' is called when
   the signature verification is completed. The pointer
   ´callback_context' is passed to the callback function.

   The function returns a handle to the operation if the callback
   function is not called directly.

   Before considering the response reliable, the caller should verify
   that the responder is authorized to sign OCSP responses. If the
   responder is not the CA who issued the certificate whose status
   was requested, the responder should have an id-kp-OCSPSigning oid
   in the extendedKeyUsage extension of the certificate. The
   information about authorized responders can also be configured
   locally when the oid is not needed. */

SshOperationHandle
ssh_ocsp_response_verify_signature(SshOcspResponse message,
                                   const SshPublicKey public_key,
                                   SshOcspVerifyCB callback,
                                   void *callback_context);


/* Get the responses from the message. The ´responses' parameter will
   contain an array of single responses. ´num_responses' will tell the
   number of the items in the array. The memory allocated for the array
   has to freed by the caller by using the function ssh_xfree. An array
   item will contain information about the certificate whose status was
   replied and optional extensions. The extensions have to be handled
   outside the OCSP module. */

SshOcspStatus
ssh_ocsp_response_get_responses(SshOcspResponse message,
                                SshOcspBasicSingleResponse *responses,
                                size_t *num_responses);

#endif /* SSHOCSPCLIENT_H */
