/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   PKCS#7 parsing and encoding with message construction, encryption
   decryption, signature constructrion and verification.
*/

#ifndef PKCS7_H
#define PKCS7_H

#include "sshmp.h"
#include "x509.h"

/* Following data structures define the PKCS 7 contents. */
typedef enum
{
  SSH_PKCS7_OK,
  SSH_PKCS7_ASN1_DECODING_FAILED,
  SSH_PKCS7_ASN1_ENCODING_FAILED,
  SSH_PKCS7_PKCS6_DECODING_FAILED,
  SSH_PKCS7_PKCS6_ENCODING_FAILED,
  SSH_PKCS7_PKCS6_CERT_NOT_ENCODED,
  SSH_PKCS7_PKCS6_CRL_NOT_ENCODED,
  SSH_PKCS7_CONTENT_DECODING_FAILED,
  SSH_PKCS7_CONTENT_TYPE_UNKNOWN,
  SSH_PKCS7_VERSION_UNKNOWN,
  SSH_PKCS7_ALGORITHM_UNKNOWN,
  SSH_PKCS7_CONTENT_UNDECLARED,

  /* Trying to create signed, enveloped, or signed_and_enveloped data
     without given appropriate keys. */
  SSH_PKCS7_SIGNERS_UNDECLARED,
  SSH_PKCS7_RECIPIENTS_UNDECLARED,

  /* Underlying private key mechanism did not allow they specified
     signature/decryption key to be used. Either the user decided she
     does not wish to sign/decrypt, or did not know PIN code or
     similar for the key. This is valid only if the key used is from
     external key mechanism. */
  SSH_PKCS7_KEY_OPERATION_CANCELLED,
  SSH_PKCS7_FAILURE
} SshPkcs7Status;

/* These are the content types of the PKCS 7 (v1.5). */
typedef enum
{
  SSH_PKCS7_UNKNOWN,
  SSH_PKCS7_DATA,
  SSH_PKCS7_SIGNED_DATA,
  SSH_PKCS7_ENVELOPED_DATA,
  SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA,
  SSH_PKCS7_DIGESTED_DATA,
  SSH_PKCS7_ENCRYPTED_DATA
} SshPkcs7ContentType;

typedef struct SshPkcs7Rec *SshPkcs7;
typedef struct SshPkcs7RecipientInfoRec *SshPkcs7RecipientInfo;
typedef struct SshPkcs7SignerInfoRec *SshPkcs7SignerInfo;

/* Free the PKCS #7 context, and free all related information. */
void ssh_pkcs7_free(SshPkcs7 pkcs7);

/* Creating SshPkcs7 Signer and Recipient entities. */

/* Create signer.

   Signer will sign the digest created using `digest_algorithm' with
   private key `key' and signature algorithm `signature_algorithm'.

   The certificate corresponding to the private key is given in
   `cert'. The certificate is NOT automatically added in the PKCS7
   when it is created using this signer. Instead functions
   ssh_pkcs7_add_certificate and ssh_pkcs7_add_crl must be used.

   The private key `key´ and certificate `cert' are not freed by the
   library. Instead the caller must free them only AFTER the signer
   has been used for calls to `ssh_pkcs7_create_signed_data', or
   `ssh_pkcs7_create_signed_and_enveloped_data', or signer created
   is explicitly freed using function `ssh_pkcs7_free_signer'.

   The `authenticated_attributes' contains attributes that are added
   in to the signed digest, and `unathenticated_attributes' contain
   other attributes. It is valid for either/both of these be NULL
   pointers.

   This signer will be added in the set of `other_signers' (if any) */

SshPkcs7SignerInfo
ssh_pkcs7_create_signer(const char *digest_algorithm,
                        const char *signature_algorithm,
                        const SshPrivateKey key,
                        const SshX509Certificate cert,
                        SshX509Attribute authenticate_attrs,
                        SshX509Attribute unauthenticate_attrs,
                        SshPkcs7SignerInfo other_signers);

SshPkcs7SignerInfo
ssh_pkcs7_create_detached_signer(const char *digest_algorithm,
                                 const unsigned char *digest,
                                 size_t digest_length,
                                 const char *signature_algorithm,
                                 const SshPrivateKey key,
                                 const SshX509Certificate cert,
                                 SshX509Attribute authenticate_attrs,
                                 SshX509Attribute unauthenticate_attrs,
                                 SshPkcs7SignerInfo other_signers);


SshPkcs7SignerInfo
ssh_pkcs7_copy_signer(SshPkcs7SignerInfo signer,
                      SshPkcs7SignerInfo other_signers);

/* Free signer in case it never gets used for creating an envelope. */

void ssh_pkcs7_free_signer_info(SshPkcs7SignerInfo signer);

/* Create recipient.

   Recipient public key from `cert' will be used to encrypt the
   session key with `key_encryption_algorithm'.

   The library will not free the certificate. It can be freed by the
   caller only after the recipient has been used to encrypt the
   envelope, or has been freed by a call to function
   `ssh_pkcs7_free_recipient'.

   The recipient is added in the set of other recipients. */
SshPkcs7RecipientInfo
ssh_pkcs7_create_recipient(const char *key_encryption_algorithm,
                           const SshX509Certificate cert,
                           SshPkcs7RecipientInfo other_recipients);

/* Free recipient in case it never gets used for creating an
   envelope. */

void ssh_pkcs7_free_recipient_info(SshPkcs7RecipientInfo recipient);

/* Creating SshPkcs7 objects. */

/* Create data content.

   The call assigns binary data block `data' whose length is `len' to
   the returned PKCS#7 descriptor. */
SshPkcs7
ssh_pkcs7_create_data(const unsigned char *data, size_t len);

/* Create encrypted data content.

   The call encrypts and pads `content' with
   `data_encryption_algorithm' (which is SSH cryptographic library
   name) with session key `key' whose length is `key_len'. Key and
   algorithm information is not freed by the library nor used after
   this call has returned.

   Note: if the data encryption algorithm is an OID number, this OID
   number shall specify PKCS#12 password based encryption algorithm.
   This is a special extension to allow reuse of the PKCS#7
   implementation with PKCS#12 specification (which definitely
   is the worst of PKCS). */
SshPkcs7
ssh_pkcs7_create_encrypted_data(SshPkcs7 content,
                                const unsigned char *data_encryption_algorithm,
                                const unsigned char *key, size_t key_len);

/* Create digested data content.

   The call digests the given content given as `content' with digest
   algorithm given at `algorithm' that is SSH cryptographic library
   name for a message digest (hash) algorithm. The algorithm name is
   not used by the library after this call has returned. */
SshPkcs7
ssh_pkcs7_create_digested_data(SshPkcs7 content, const char *algorithm);

/* Create enveloped data content.

   The call encrypts and pads `content' with
   `data_encryption_algorithm' (which is ssh-crypto library name). The
   session key used is generated by this call. The recipient
   certificates (and therefore public keys) are used to protect the
   session key. */
SshPkcs7
ssh_pkcs7_create_enveloped_data(SshPkcs7 content,
                                const char *data_encryption_algorithm,
                                SshPkcs7RecipientInfo recipients);

/* Create signed data content.

   The call signs the content independently for each signer specified
   at the signers. If the content is not of type data, signer
   authenticates two additional attributes, PCKS9 content info and
   PKCS9 message-digest. */
SshPkcs7
ssh_pkcs7_create_signed_data(SshPkcs7 content,
                             SshPkcs7SignerInfo signers);

/* This is the common callback for asynchronous content encryption,
   decryption, signing and verification routines.

   The `status' indicates if all the cryptographic operations for
   creating requested payload were successful. If status is
   SSH_PKCS7_OK, the `content' will be the resulting PKCS7 data
   structure (that needs to be encode for transport later with call to
   ssh_pkcs7_encode(). The `context' is the `done_callback_context'
   argument for functions usign this callback type. */

typedef void (*SshPkcs7AsyncCB)(SshPkcs7Status status,
                                SshPkcs7 content,
                                void *context);

/* This function performs the same operations as its syncronous
   counterpart, ssh_pkcs7_create_enveloped_data(), but it can use
   asynchrous keys (e.g.  cryptographic accelerators. The function
   will arrange `done_callback' function called when all cryptographic
   operations described by `recipients' have been performed. The
   `done_callback_context' is given as `context' argument for the
   `done_callback'. */

SshOperationHandle
ssh_pkcs7_create_enveloped_data_async(SshPkcs7 content,
                                      const char *data_encryption_algorithm,
                                      SshPkcs7RecipientInfo recipients,
                                      SshPkcs7AsyncCB done_callback,
                                      void *done_callback_context);
SshOperationHandle
ssh_pkcs7_create_signed_data_async(SshPkcs7 content,
                                   SshPkcs7SignerInfo signers,
                                   SshPkcs7AsyncCB done_callback,
                                   void *done_callback_context);

/* Create signed and encrypted data content.

   The call signs the `content' with each signer given at `signers',
   and then encrypts the result of this operation for each of the
   `recipients' using `data_encryption' as algorithm.

   Note; due to this being seldomly used functionality, the
   asynchronous interface is currently missing. This means that
   accelerated keys can't be used to construct PKCS7 sined and
   enveloped data content. */

SshPkcs7
ssh_pkcs7_create_signed_and_enveloped_data(
        SshPkcs7 content,
        const unsigned char *data_encryption,
        SshPkcs7RecipientInfo recipients,
        SshPkcs7SignerInfo signers);

/* These function will add certificates or crls to the envelope.  The
   envelope must be either of type SSH_PKCS7_SIGNED_DATA or
   SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA. This call will return
   SSH_PKCS7_FAILURE for other content types. */
SshPkcs7Status
ssh_pkcs7_add_certificate(SshPkcs7 envelope,
                          const unsigned char *ber, size_t ber_len);

SshPkcs7Status
ssh_pkcs7_add_crl(SshPkcs7 envelope,
                  const unsigned char *ber, size_t ber_len);

/* Encode PKCS7 object for transport. */
SshPkcs7Status
ssh_pkcs7_encode(SshPkcs7 pkcs7,
                 unsigned char **data, size_t *data_len);

/* Decode PKCS7 data object. This function allocates the resulting
   object `pkcs7'. It should be freed by the caller with call to
   function ssh_pkcs7_free. One should not free subtrees of this
   `pkcs7' */
SshPkcs7Status
ssh_pkcs7_decode(const unsigned char *data, size_t data_len,
                 SshPkcs7 *pkcs7);

/* Access contents of the PKCS7. */

/* Access content payload and its type inside the `envelope'. */
SshPkcs7 ssh_pkcs7_get_content(SshPkcs7 envelope);
SshPkcs7ContentType ssh_pkcs7_get_content_type(SshPkcs7 envelope);

/* Retrieve certificates or crls from the envelope. These functions
   will fail if the envelope type is not SSH_PKCS7_SIGNED_DATA or
   SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA.

   The caller must free `bers' and `ber_lens' pointers, but not the
   data elements on these arrays. The data is freed when the envelope
   is freed.

   One can use envelope to carry certificates only, or these
   certificates and crls can be used to verify signatures inside the
   envelope. */
SshUInt32
ssh_pkcs7_get_certificates(SshPkcs7 envelope,
                           unsigned char ***bers, size_t **ber_lens);

SshUInt32
ssh_pkcs7_get_crls(SshPkcs7 envelope,
                   unsigned char ***bers, size_t **ber_lens);


/* This function gets the payload from the content. If there is no
   payload it will return FALSE. The caller must not free the data, it
   is pointer to memory managed by the library. */
Boolean
ssh_pkcs7_content_data(SshPkcs7 envelope,
                       const unsigned char **data, size_t *len);


/* Return array of signers for this envelope. The caller must free
   `signers' after nonzero return. */
SshUInt32
ssh_pkcs7_get_signers(SshPkcs7 envelope, SshPkcs7SignerInfo **signers);

/* Get identification information from `signer'. Pointer `issuer_name'
   must be freed after the call, and the `serial_number' must be
   an multiple precision integer allocated and initialized by the
   caller. The function will copy value of serial number there. */
Boolean
ssh_pkcs7_signer_get_id(SshPkcs7SignerInfo signer,
                        char **issuer_name, SshMPInteger serial_number);

/* This is a convenience function for finding certificate used to sign
   the content from the certificates present at the content.  The
   function returns cert, or NULL if none present. The returned
   certificate must be freed by the caller. */
unsigned char *
ssh_pkcs7_signer_get_certificate(SshPkcs7 envelope,
                                 SshPkcs7SignerInfo signer,
                                 size_t *cert_len);


/* This function verifies one signature from the envelope using the
   `signer' information and the `public_key' for this signer.  The
   function returns TRUE if the signature could be verified, or FALSE,
   if the verification failed.

   Normal use is to
   - get signer from the envelope
   - find the key identification from the signer
   - find the certificate from external storage (or from the certificates
     list attached to this payload) and verify it
   - and finally call to this function.

   The function can be called for content types of
   SSH_PKCS7_SIGNED_DATA and SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA
   only. */

Boolean
ssh_pkcs7_content_verify(SshPkcs7 envelope,
                         SshPkcs7SignerInfo signer,
                         const SshPublicKey public_key);

SshOperationHandle
ssh_pkcs7_content_verify_async(SshPkcs7 envelope,
                               SshPkcs7SignerInfo signer,
                               const SshPublicKey public_key,
                               SshPkcs7AsyncCB done_callback,
                               void *done_callback_context);


/* Same as above, but with detached signature whose content digest is
   given at expected_digest, instead of being transported on the
   envelope. */
Boolean
ssh_pkcs7_content_verify_detached(const unsigned char *expected_digest,
                                  size_t expected_digest_len,
                                  SshPkcs7 envelope,
                                  SshPkcs7SignerInfo signer,
                                  const SshPublicKey public_key);

SshOperationHandle
ssh_pkcs7_content_verify_detached_async(const unsigned char *expected_digest,
                                        size_t expected_digest_len,
                                        SshPkcs7 envelope,
                                        SshPkcs7SignerInfo signer,
                                        const SshPublicKey public_key,
                                        SshPkcs7AsyncCB done_callback,
                                        void *done_callback_context);

/* Handling of attributes. This should be cleaned.

   This function returns the signature algorithms the given signer
   used to process data, and the attributes filled by the signer.

   The algorithms are useful when validating detached signatures,
   where the validation expects to receive validators view of the
   digested data, and she wishes to know, how the signer digested
   it. */

Boolean
ssh_pkcs7_signer_get_attributes(SshPkcs7SignerInfo signer,
                                const unsigned char **digest_algorithm,
                                const unsigned char **signature_algorithm,
                                SshX509Attribute *auth_attrs,
                                SshX509Attribute *unauth_attrs);

/* This function verifies the hash in the envelope. It can be called for
   content type SSH_PKCS7_DIGESTED_DATA only. */
Boolean
ssh_pkcs7_content_verify_data(SshPkcs7 envelope);


SshUInt32
ssh_pkcs7_get_recipients(SshPkcs7 envelope,
                         SshPkcs7RecipientInfo **recipients);

/* Get identification information from `recipient'. Pointer
   `issuer_name' must be freed after the call, and the `serial_number'
   must be an multiple precision integer allocated and initialized by
   the caller. The function will copy value of serial number there. */
Boolean
ssh_pkcs7_recipient_get_id(SshPkcs7RecipientInfo recipient,
                           char **issuer_name, SshMPInteger serial_number);

/* This function decrypts the payload and content of envelope of type
   SSH_PKCS7_ENVELOPED_DATA using the `recipient' information and the
   key given as `private_key'. Data encryption is done inplace (so the
   encrypted data inside the envelope gets replaced with decrypted. */
Boolean
ssh_pkcs7_content_decrypt(SshPkcs7 envelope,
                          SshPkcs7RecipientInfo recipient,
                          const SshPrivateKey key);

SshOperationHandle
ssh_pkcs7_content_decrypt_async(SshPkcs7 envelope,
                                SshPkcs7RecipientInfo recipient,
                                const SshPrivateKey key,
                                SshPkcs7AsyncCB done_callback,
                                void *done_callback_context);

/* This function does signature verification and decryption for
   SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA content type using the
   `private_key' of the `recipient' for decryption and `public_key' of
   `signer' for signature verification. */
Boolean
ssh_pkcs7_content_verify_and_decrypt(SshPkcs7 envelope,
                                     SshPkcs7SignerInfo signer,
                                     const SshPublicKey public_key,
                                     SshPkcs7RecipientInfo recipient,
                                     const SshPrivateKey private_key);

/* This function decrypts the payload of SSH_PKCS7_ENCRYPTED_DATA
   payload type using the session key specified using the algorithm
   given by the caller.  */
Boolean
ssh_pkcs7_content_decrypt_data(SshPkcs7 envelope,
                               const unsigned char *key, size_t key_len);

#endif /* PKCS7_H */
