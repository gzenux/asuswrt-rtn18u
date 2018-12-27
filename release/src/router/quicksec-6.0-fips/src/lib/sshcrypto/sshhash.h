/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   High-level interface to cryptographic hash functions.
*/

#ifndef SSHHASH_H
#define SSHHASH_H

/* ********************* Hash functions ***********************************/

typedef struct SshHashRec *SshHash;

/** The maximum digest length (in bytes) that may be output by any hash
    function. */
#define SSH_MAX_HASH_DIGEST_LENGTH   64

/** Returns a comma-separated list of supported hash functions names.
    The caller must free the returned value with ssh_crypto_free(). */
char *
ssh_hash_get_supported(void);

/** Returns TRUE or FALSE depending whether the hash function called
    "name" is supported with this version of the cryptographic
    library. */
Boolean
ssh_hash_supported(const char *name);

/** Get the ASN.1 Object Identifier of the hash, if available. Returns
    the OID in the 'standard' form, e.g. "1.2.3.4".

    @return
    Returns NULL if an OID is not available. The returned value points
    to internal constant data and must not be freed. The latter form
    returns the OID as DER encoded. */
const char *
ssh_hash_asn1_oid(const char *name);

size_t
ssh_hash_asn1_oid_compare(const char *name, const unsigned char *oid,
                          size_t max_len);

const unsigned char *
ssh_hash_asn1_oid_generate(const char *name, size_t *len);

/** Get the digest length in bytes of the hash. */
size_t
ssh_hash_digest_length(const char *name);

/** Get input block size in bytes (used for HMAC padding). */
size_t
ssh_hash_input_block_size(const char *name);

/** Allocates and initializes a hash. */
SshCryptoStatus
ssh_hash_allocate(const char *name, SshHash *hash);

/** Free a hash. This can also be called when the library is in
    an error state. */
void
ssh_hash_free(SshHash hash);

/** Resets the hash context to its initial state. */
void
ssh_hash_reset(SshHash hash);

/** Updates the hash context by adding the given text. If any internal error is
    encountered, it is noted and reported at ssh_hash_final. */
void
ssh_hash_update(SshHash hash, const unsigned char *buf, size_t len);

/** Outputs the hash digest. The user allocated digest buffer must be
    at least ssh_hash_digest_length(hash) bytes long.  */
SshCryptoStatus
ssh_hash_final(SshHash hash, unsigned char *digest);

/** Start comparing hash output. This is same as doing ssh_hash_reset
    for the hash. After this, call ssh_hash_update as normally
    to add more data there, and finally call ssh_hash_compare_result to
    get the result. Calling this again or ssh_hash_reset will reset the
    internal state of the hash function. */

SshCryptoStatus
ssh_hash_compare_start(SshHash hash,
                       const unsigned char *digest_to_be_verified,
                       size_t len);

/** Get the result of the hash comparison.

    @return
    Returns SSH_CRYPTO_OK if the hash comparison was successful, and
    SSH_CRYPTO_HASH_COMPARISON_FAILED if the hash comparison was
    not successful. */
SshCryptoStatus
ssh_hash_compare_result(SshHash hash);

/** Returns the name of the hash. The name is what was used in hash allocate.
    The name points to an internal data structure and should NOT be freed,
    modified, or used after ssh_hash_free. */
const char *
ssh_hash_name(SshHash hash);

/* Performs the SHA transfrom for given input. Uses the SHA-1 defined
   default initialisation state. This is used for performing PRF defined
   in FIPS186-2. */
void
ssh_sha_transform(SshUInt32 buf[5], const unsigned char in[64]);

/* Performs the SHA transfrom for given input. Uses the SHA-1 defined
   default initialisation state in reverse order. These are used for
   performing PRF defined in FIPS186-2. */
void
ssh_sha_permuted_transform(SshUInt32 buf[5], const unsigned char in[64]);

#endif /* SSHHASH_H */
