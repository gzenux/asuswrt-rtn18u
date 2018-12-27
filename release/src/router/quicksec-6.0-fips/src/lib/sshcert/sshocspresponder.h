/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A public interface for the responder part of the PKIX OCSP
   (Online Certificate Status Protocol). The implemention is done
   according to the RFC2560.
*/

#ifndef SSHOCSPRESPONDER_H
#define SSHOCSPRESPONDER_H

#include "sshocsp.h"

/* A structure that holds information for the basic single request. */
typedef struct SshOcspBasicSingleRequestRec
{
  /* Identifies the certificate. */
  SshOcspCertIDStruct cert_id;
  /* Optional single request extensions. If the value is NULL,
     extensions are not available. */
  SshX509Attribute single_request_extensions;
} *SshOcspBasicSingleRequest;

/***************** Request handling on responder side *****************/

/* Decode the byte block defined by ´der' and ´der_len' to an OCSP request.
   Function allocates memory for the message. The caller should free
   the memory using the ssh_cosp_request_free function. */

SshOcspStatus
ssh_ocsp_request_decode(const unsigned char *der, size_t der_len,
                        SshOcspRequest *message);


/* Gets the version of the message. */
SshOcspVersion ssh_ocsp_request_get_version(SshOcspRequest request);


/* Returns information about the availability of a signature.
   Returns TRUE if the request is signed, otherwise FALSE. */
Boolean ssh_ocsp_request_is_signed(SshOcspRequest request);


/* Get the name of the requestor. Can be NULL if the signature is
   not present. */
SshX509Name
ssh_ocsp_request_get_requestor_name(SshOcspRequest request);


/* Get certs from the message. The value at ´ncerts' indicates
   how many certificates were present. The array `certs' will contain
   each of these. The returned array should be freed with the function
   ssh_xfree. Returned certificates can be used to check whether the
   requestor can be trusted or not. */

void
ssh_ocsp_request_get_certs(SshOcspRequest message,
                           SshOcspEncodedCert *certs, int *ncerts);


/* The function verifies the contents of the request using the signature
   found in the message. The signature is checked using the public key.
   The ´callback' is called when the public key operation
   is completed. ´context' can carry any information that the caller
   wants to pass to the callback function.

   The functions return a handle to the operation if the callback
   function is not called directly. */

SshOperationHandle
ssh_ocsp_request_verify_signature(SshOcspRequest message,
                                  const SshPublicKey requestor_key,
                                  SshOcspVerifyCB callback,
                                  void *callback_context);


/* Get the extensions of the request. If extensions are not available,
   NULL pointer is returned. */
SshX509Attribute
ssh_ocsp_request_get_extensions(SshOcspRequest request);


/* Get the requests from the message. The ´requests' parameter will contain
   an array of single requests. ´num_requests' will tell the number of
   the requests in the array. The memory allocated for the array has
   to be freed by the caller by calling ssh_xfree. An array item will
   contain information about the certificate whose status is requested
   and optional extensions. The extensions has to be handled outside the
   OCSP module. */

SshOcspStatus
ssh_ocsp_request_get_requests(SshOcspRequest message,
                              SshOcspBasicSingleRequest *requests,
                              int *num_requests);


/***************** Response handling on responder side *****************/

/* A function to allocate response messages. Returned message should be
   freed using the ´ssh_ocsp_response_free' function. The parameter
   ´status' defines the status for the response (successful or some error),
   ´response_type' has to SSH_OCSP_RESPONSE_TYPE_BASIC at the moment
   and extensions are optional and they have to handled outside the
   module. The ´extensions' parameter is freed when the response is freed
   and the pointer should be valid until that. */

SshOcspResponse ssh_ocsp_response_allocate(SshOcspVersion version,
                                           SshOcspResponseStatus status,
                                           SshOcspResponseType response_type,
                                           SshX509Attribute extensions);

/* Sets the data for identifying the responder. Subject name or
   public key is fetched from the certificate, depending on the
   value of ´type'. If the whole certificate is not available,
   it can be easily constructed as only two of the parameters are
   needed. */

SshOcspStatus
ssh_ocsp_response_set_responder_id(SshOcspResponse message,
                                   SshOcspResponderIDType type,
                                   const SshX509Certificate certificate);


/* Adds a single response to the response message

   ´hash_algorithm' tells the algorithm that is used to take the
   hash of the issuer name and public key.

   ´issuer_certificate' should contain the certificate of the entity
   that issued the certificate whose serial number is defined by
   the parameter ´subject_serial'. If the certificate is not available,
   it can be easily constructed as only the subject name and the
   public key are needed.

   The certificate that identifies this single response is defined in
   the parameter ´subject_serial'. The parameter can be freed after the
   function call. The status of the certificate is defined in the
   ´status' parameter.

   ´this_update' tells the time when the status of the certificate was
   last time updated.

   ´next_update_available' determines whether the next_update contains
    valid time. ´next_update' is an optional parameter in the OCSP
    response.

   ´next_update' tells the time when the status of the certificate is
   next time updated. The time is only notified if the value of the
   ´next_update_available' parameter is TRUE. If ´next_update' is
   earlier than the current time, the response should be considered
   unreliable.

   Any extensions can be defined in the ´single_response_extensions'
   parameter. The pointer should be valid until the response is freed.
   Extensions are freed when the response is freed.
  */
SshOcspStatus
ssh_ocsp_response_add_single(SshOcspResponse response,
                             const char *hash_algorithm,
                             const SshX509Certificate issuer_certificate,
                             SshMPIntegerConst subject_serial,
                             const SshOcspCertStatus status,
                             SshTime this_update,
                             Boolean next_update_available,
                             SshTime next_update,
                             SshX509Attribute single_response_extensions);

/* Adds a single response to the response message. This' is similar
   to the ssh_ocsp_response_add_single function. The only difference
   is that issuer information and subject number are taken from
   the single request we are responding to. The single request is defined
   by the parameter 'single_request'. It should be one of the single
   requests that is got using the ssh_ocsp_request_get_requests function.

   All the other parameters are the same as in the
   ssh_ocsp_response_add_single function.
  */

SshOcspStatus
ssh_ocsp_response_add_single_reply(SshOcspResponse message,
                                   SshOcspBasicSingleRequest single_request,
                                   const SshOcspCertStatus status,
                                   SshTime this_update,
                                   Boolean next_update_available,
                                   SshTime next_update,
                                   SshX509Attribute response_extensions);


/* Add one encoded certificate to the message. The certificates can
   be included to help the receiver to verify the sender's
   signature. */

SshOcspStatus
ssh_ocsp_response_add_cert(SshOcspResponse message,
                           const unsigned char *ber, size_t ber_len);


/* Sets the time when the response was produced. */
SshOcspStatus
ssh_ocsp_response_set_production_time(SshOcspResponse message,
                                      SshTime produced_at);


/*
   Encode the OCSP Response.

   Private key is used to sign the message. In responses it is
   mandatory.  The key should be valid until the callback function has
   been called.

   The response is freed after the encoding so it can not be used after
   calling this function.

   ´callback' specifies the callback function that is called after
   the encoding has been done.

   ´callback_context' can hold any data that the caller wants to
   pass to the callback function.

   The function returns a handle to the operation if the callback
   function is not called directly.
*/
SshOperationHandle ssh_ocsp_response_encode(SshOcspResponse message,
                                            const SshPrivateKey key,
                                            SshOcspEncodeCB callback,
                                            void *callback_context);

#endif /* SSHOCSPRESPONDER_H */
