/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Construct SCEP certificate enrollment messages
*/

#ifndef X509SCEP_H
#define X509SCEP_H

typedef enum {
  SSH_SCEP_OK      = 0,
  SSH_SCEP_ERROR   = 1,
  SSH_SCEP_FAILURE = 2,
  SSH_SCEP_PENDING = 3
} SshScepStatus;

typedef enum {
  SSH_SCEP_FINFO_BAD_ALG   = 0,
  SSH_SCEP_FINFO_BAD_CHECK = 1,
  SSH_SCEP_FINFO_BAD_REQ   = 2,
  SSH_SCEP_FINFO_BAD_TIME  = 3,
  SSH_SCEP_FINFO_BAD_ID    = 4
} SshScepFailure;

/* Nonce and trasaction id are typically 16 bytes, but there are
   implementations with 32 bytes of data. Lets be prepared. */
typedef struct SshScepTransactionAndNonceRec
{
  unsigned char transaction_id[32];
  size_t transaction_id_len;
  unsigned char nonce[32];
  size_t nonce_len;
} *SshScepTransactionAndNonce, SshScepTransactionAndNonceStruct;

/* This function type is used for SCEP library to indicate it has
   completed constructing a message, or parsing an arrived message.

   If status is SSH_SCEP_OK, when constructing, the result_data, and
   result_data_len will be DER encoded SCEP messages that can be send
   on the wire. When parsing a received message at the client, they
   will indicate the end entity certificate received.

   For other status codes, the result_data, and result_data_len will
   be invalid, and the failure will indicate what might have went
   wrong.

   For all return values, the transaction_id and nonce will be valid
   for the current transaction. */

typedef void (*SshScepClientResultCB)(
  SshScepStatus status,
  SshScepFailure failure,
  const SshScepTransactionAndNonce txnonce,
  const unsigned char *result_data, size_t result_data_len,
  void *context);

/* Two function types used for searching external storage for CA
   certificate and subject private key for the request that has
   transaction identitifier `transaction_id' (that is a MD5 hash of
   the public key matching the private key to be found.

   The library will call user provided callback function of type
   SshScepClientCertAndKeyRequest when it is parsing the received
   SCEP message. From this function (or later when done), the user
   will call back the library provided function `result_callback' of
   type SshScepClientCertAndKeyResponse indicating the `ca_certificate'
   and the `subject_private_key' found. If either of these is NULL,
   the seach is considered a failure.

   The context given to SshScepClientCertAndKeyResponse is the
   `result_callback_context' that this callback received from the SCEP
   library. */

typedef void (*SshScepClientCertAndKeyRep)(
  const SshX509Certificate ca_certificate,
  const SshPrivateKey subject_private_key,
  void *result_callback_context);

typedef void (*SshScepClientCertAndKeyReq)(
  const SshScepTransactionAndNonce txnonce,
  SshScepClientCertAndKeyRep result_callback,
  void *result_callback_context,
  void *context);

/* Create SCEP certificate request message for `public_key', so that
   the request contains mandatory `dns', and optional `ipaddr' and
   `serial' as proposed subject names.  The password to be put inside
   the message is given as `challenge' (a printable string).

   This message will be destined to the `ca' and signed by the
   `private_key', that should be the signing key for the node. For now
   the `private_key' and `public_key' arguments have to be single key
   pair (even if the protocol does not require this).

   The public_key and the private key are contained in the resulting
   message, and must not be freed by the called while the message
   exists. */

SshScepStatus
ssh_scep_create_request(const SshPrivateKey private_key,
                        const SshX509Certificate req,
                        const SshX509Certificate cara_encryption,
                        SshScepClientResultCB result_callback,
                        void *context);

SshScepStatus
ssh_scep_create_poll(const SshPrivateKey private_key,
                     const SshX509Certificate req,
                     const SshX509Certificate cara_encryption,
                     SshScepClientResultCB result_callback,
                     void *context);

/* This function parses the certificate response received from the
   CA. When the parser has matched the transaction identifier, the
   function given as `request_cb' will be called to find the
   request matching this transaction. That function indicates
   this library the original request (from some external mapping
   between transaction identifiers and the requests sent).

   After finding a match, the nonces are verified, messages decrypted,
   and finally result_cb called to indicate if the CA granted,
   rejected, or postponed the request.

   The callback context given here will be given as context argument
   for both the callbacks. */

SshScepStatus
ssh_scep_parse_response(const unsigned char *response, size_t response_len,
                        SshScepClientCertAndKeyReq request_cb,
                        SshScepClientResultCB result_cb,
                        void *callback_context);

#endif /* X509SCEP_H */
/* eof */
