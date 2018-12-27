/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Redundancy generating functions for public key cryptosystems.
*/

#ifndef SSHRGF_H
#define SSHRGF_H

#include "sshhash_i.h"
#ifdef SSHDIST_CRYPT_SHA512
#include "sha512.h"
#endif /* SSHDIST_CRYPT_SHA512 */

/* Redundancy functions are used in public key cryptosystems for two
   purposes. Firstly, to create cryptographically good padding for
   public and private key operations, and secondly, to hash input data
   to signature operations. These two operations are combined using
   the RGF functions defined here. */

/* An RGF definition structure, this determines which operations the
   resulting RGF object may perform. */
typedef struct SshRGFDefRec *SshRGFDef, SshRGFDefStruct;

/* An RGF object. */
typedef struct SshRGFRec *SshRGF;


/**************** Allocation and Freeing. ******************************/

SshRGF ssh_rgf_allocate(const SshRGFDefStruct *rgf_def);

void ssh_rgf_free(SshRGF hash);


/**************** Hash data into the RGF. ******************************/

/* Update the RGF function with data to be hashed. This works exactly
   like the SshHash update, but only with an RGF. */
SshCryptoStatus ssh_rgf_hash_update(SshRGF rgf,
                                    const unsigned char *data,
                                    size_t data_len);

/* Update the RGF with a previously hashed digest. This operation may
   fail if the mechanism does not allow setting the resulting digest.
   In such a case, this function returns FALSE. The digest needs to
   remain valid till the actual use of RGF (e.g call to
   ssh_rgf_for_verification, ssh_rgf_for_signature). */
SshCryptoStatus ssh_rgf_hash_update_with_digest(SshRGF rgf,
                                        const unsigned char *digest,
                                        size_t digest_len);


/*************************************************************************/
/* Padding functions appplied to data during public key operations. */

/* Pad the input data 'msg' of length 'msg_len' before encryption.
   'key_size_in_bits' is the key size in bits of the public key which
   will encrypt the data. The output padded data is allocated and returned in
   'output_msg', the length of the output data is returned in
   'output_msg_len'. Returns SSH_CRYPTO_OK on success. */
SshCryptoStatus ssh_rgf_for_encryption(SshRGF rgf,
                                       size_t key_size_in_bits,
                                       const unsigned char *msg,
                                       size_t msg_len,
                                       unsigned char **output_msg,
                                       size_t *output_msg_len);

/* Unpad the input data 'msg' of length 'msg_len' after decryption.
   'key_size_in_bits' is the key size in bits of the private key which
   will decrypt the data. The output padded data is allocated and returned
   in 'output_msg', the length of the output data is returned in
   'output_msg_len'. Returns SSH_CRYPTO_OK on success. */
SshCryptoStatus ssh_rgf_for_decryption(SshRGF rgf,
                                       size_t key_size_in_bits,
                                       const unsigned char *decrypted_msg,
                                       size_t decrypted_msg_len,
                                       unsigned char **output_msg,
                                       size_t *output_msg_len);

/* Output padded data from the RGF. Input data should have been previously
   hashed into the RGF by calling ssh_rgf_hash_update_with_digest or
   ssh_rgf_hash_update. 'key_size_in_bits' is the key size in bits of
   the private key which will sign the data. The output padded data is
   allocated and returned in 'output_msg', the length of the output data
   is returned in 'output_msg_len'. Returns SSH_CRYPTO_OK on success. */
SshCryptoStatus ssh_rgf_for_signature(SshRGF rgf,
                                      size_t key_size_in_bits,
                                      unsigned char **output_msg,
                                      size_t *output_msg_len);

/* Use the RGF for signature verification. Input data whose signature is
   to be verified should have been previously hashed into the RGF by
   calling ssh_rgf_hash_update_with_digest or ssh_rgf_hash_update.
   This function then verifies the signature with input 'rgf' and the
   decrypted signature buffer obtained from a public key operation on the
   received signature. 'key_size_in_bits' is the key size in bits of
   the public key which will verify the data. Returns SSH_CRYPTO_OK if
   the signature validates and SSH_CRYPTO_SIGNATURE_CHECK_FAILED if the
   signature is invalid. */
SshCryptoStatus
ssh_rgf_for_verification(SshRGF rgf,
                         size_t key_size_in_bits,
                         const unsigned char *decrypted_signature,
                         size_t decrypted_signature_len);


/******************** Utility Functions. ***************************/

size_t ssh_rgf_hash_digest_length(SshRGF rgf);

/* Derive a SSH hash function. This call may fail, and in such a case
   will return NULL. This means that the RGF update part cannot be
   separated into a "simple" hash function.

   Most public key mechanisms available use standard "simple" hash
   functions as a basis and hence this derivation is often possible. Please
   observe, that this is sensible mainly if you want to derive from the
   hash function e.g. a MAC or do similar complicated processing. Otherwise
   you can just use the ssh_rgf_hash_update. */
SshHash ssh_rgf_derive_hash(SshRGF rgf);

/* Returns TRUE if the data in the SshRGF object has already been hashed
   (the data has been input to the RGF using ssh_rgf_hash_update_with_digest)
   and FALSE otherwise (the data has been input using ssh_rgf_hash_update).
   This function is needed by the proxykey library: when delegating
   crypto operations to external devices, some devices insist on performing
   the RGF operation themselves. In this case, the proxykey library needs
   to know whether the data has been previously hashed so it can correctly
   inform the external device which RGF to apply. */
Boolean ssh_rgf_data_is_digest(SshRGF rgf);


/******************** Definition structures. ************************/

#ifdef SSHDIST_CRYPT_SHA256
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha256_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha256_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_sha256_def;
extern const SshRGFDefStruct ssh_rgf_std_sha256_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha256_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha256_no_hash_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha256_no_hash_def;

extern const SshRGFDefStruct ssh_rgf_pkcs1_sha224_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha224_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_sha224_def;
extern const SshRGFDefStruct ssh_rgf_std_sha224_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha224_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha224_no_hash_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha224_no_hash_def;
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha512_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha512_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_sha512_def;
extern const SshRGFDefStruct ssh_rgf_std_sha512_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha512_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha512_no_hash_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha512_no_hash_def;

extern const SshRGFDefStruct ssh_rgf_pkcs1_sha384_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha384_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_sha384_def;
extern const SshRGFDefStruct ssh_rgf_std_sha384_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha384_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha384_no_hash_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha384_no_hash_def;
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_SHA
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha1_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha1_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_sha1_def;
extern const SshRGFDefStruct ssh_rgf_std_sha1_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha1_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_sha1_no_hash_def;
extern const SshRGFDefStruct ssh_rgf_pss_sha1_no_hash_def;
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_MD5
extern const SshRGFDefStruct ssh_rgf_pkcs1_md5_def;
extern const SshRGFDefStruct ssh_rgf_pss_md5_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_md5_def;
extern const SshRGFDefStruct ssh_rgf_std_md5_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_nopad_md5_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_md5_no_hash_def;
extern const SshRGFDefStruct ssh_rgf_pss_md5_no_hash_def;
#endif /* SSHDIST_CRYPT_MD5 */

extern const SshRGFDefStruct ssh_rgf_pkcs1_implicit_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_restricted_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1_none_def;
extern const SshRGFDefStruct ssh_rgf_pkcs1v2_none_def;
extern const SshRGFDefStruct ssh_rgf_dummy_def;


/* This RGF behaves differently from all others in that the ssh_rgf_for_*
   functions do not allocate the return data but instead return pointers
   to the input data. */
extern const SshRGFDefStruct ssh_rgf_dummy_no_allocate_def;

#endif /* SSHRGF_H */
