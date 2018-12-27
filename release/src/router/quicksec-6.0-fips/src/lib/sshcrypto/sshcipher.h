/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   High-level API for symmetric key encryption (cipher) operations.

   * Key Lengths *

   The following assertions will always be true:

   <CODE>
   min <= def && min <= max
   max == 0 || (def <= max)
   </CODE>

   If you want to know whether the cipher is a variable-length cipher,
   check whether min == max (and min != 0). If they differ, then it is
   a variable-length cipher. However you must realize that allocating a
   cipher based on this information might still fail on some key
   lengths.
*/

#ifndef SSHCIPHER_H
#define SSHCIPHER_H

/* *********************** Secret key cryptography ************************/

/** Type used to represent a cipher object.  The exact semantics of the
    cipher depend on the encryption algorithm used, but generally the
    cipher object will remember its context (initialization vector, current
    context for stream cipher) from one encryption to another. */
typedef struct SshCipherRec *SshCipher;

/** Maximum size of a cipher block for block ciphers, in bytes. */
#define SSH_CIPHER_MAX_BLOCK_SIZE       32

/** Maximum size of the IV (initialization vector) for block ciphers in chained
    modes, in bytes. */
#define SSH_CIPHER_MAX_IV_SIZE          32

/** Returns a comma-separated list of cipher names.  The name may be of
    the format "des-cbc" (etc.) for block ciphers.  The caller must
    free the returned list with ssh_crypto_free(). */
char *
ssh_cipher_get_supported(void);

/** Returns TRUE or FALSE depending on whether the cipher called "name" is
    supported with this version of cryptographic library. */
Boolean
ssh_cipher_supported(const char *name);

/** Allocates and initializes a cipher of the specified type and mode.
    The cipher is keyed with the given key.

    The initialization vector for block ciphers is set to zero.

    If the key is too long for the given cipher, the key will be
    truncated.  If the key is too short, SSH_CRYPTO_KEY_TOO_SHORT is
    returned.

    @param for_encryption
    'for_encryption' should be TRUE if the cipher is to be used for
    encrypting data, and FALSE if it is to be used for decrypting.

    @return
    This returns SSH_CRYPTO_OK on success. */
SshCryptoStatus
ssh_cipher_allocate(const char *type,
                    const unsigned char *key,
                    size_t keylen,
                    Boolean for_encryption,
                    SshCipher *cipher_ret);

/** Clears and frees the cipher from the main memory.  The cipher object
    becomes invalid, and any memory associated with it is freed. */
void
ssh_cipher_free(SshCipher cipher);

/** Returns the name of the cipher. The name is the same as that used
    in ssh_cipher_allocate. The name points to an internal data structure and
    should NOT be freed, modified, or used after ssh_cipher_free is called. */
const char *
ssh_cipher_name(SshCipher cipher);

/** Query for the key length in bytes needed for a cipher. If the cipher is a
    variable-length cipher, then this is some sensible "default" value to use.
    This never returns zero if `name' is a valid cipher. */
size_t
ssh_cipher_get_key_length(const char *name);

/** Query for the minimum key length (in bytes) needed for a cipher. */
size_t
ssh_cipher_get_min_key_length(const char *name);

/** Query for the maximum key length (in bytes) needed for a
    cipher. Note that this can be zero if the cipher does not limit the
    maximum key length. */
size_t
ssh_cipher_get_max_key_length(const char *name);

/** Checks whether a cipher is a variable-length cipher or not.

    @return
    It returns TRUE if the cipher corresponding to 'name'
    has a fixed key length (i.e. the cipher is not a variable-length cipher),
    otherwise returns FALSE. */

Boolean ssh_cipher_has_fixed_key_length(const char *name);

/** Returns the block length in bytes of the cipher, or 1 if it is a stream
    cipher. The returned value will be at most SSH_CIPHER_MAX_BLOCK_SIZE. */
size_t
ssh_cipher_get_block_length(const char *name);

/** Returns the length in bytes of the initialization vector of the cipher in
    bytes, or 1 if it is a stream cipher. The returned value will be at most
    SSH_CIPHER_MAX_IV_SIZE. */
size_t
ssh_cipher_get_iv_length(const char *name);

/** Sets the initialization vector (IV) of the cipher. This is only meaningful
    for block ciphers used in one of the feedback/chaining modes.

    The default initialization vector is zero (every bit 0); changing
    it is completely optional (although highly recommended). The IV
    buffer must be at least the size needed for the IV
    (ssh_cipher_get_iv_length). */

SshCryptoStatus
ssh_cipher_set_iv(SshCipher cipher,
                  const unsigned char *iv);

/** Starts the cryptography operation of the non-combined mode cipher. This
    must be called before processing a new packet/message with the non-combined
    mode cipher. */

SshCryptoStatus
ssh_cipher_start(SshCipher cipher);

/** Encrypts/decrypts data (depending on the for_encryption flag given when the
    SshCipher object was created).  Data is copied from src to dest while it
    is being encrypted/decrypted.  It is permissible that src and dest be the
    same buffer; however, partial overlap is not allowed.

    For block ciphers, len must be a multiple of the cipher block size
    (this is checked); for stream ciphers there is no such limitation.

    If the cipher is used in a chaining mode or it is a stream cipher, the
    updated initialization vector or context is passed from one
    encryption/decryption call to the next.  In other words, all blocks
    encrypted with the same context form a single data stream, as if they
    were all encrypted with a single call.  If you wish to encrypt each
    block with a separate context, you must create a new SshCipher object
    every time (or, for block ciphers, you can manually set the initialization
    vector before each encryption). */

SshCryptoStatus
ssh_cipher_transform(SshCipher cipher,
                     unsigned char *dest,
                     const unsigned char *src,
                     size_t len);

/** Encrypts/decrypts data (depending on the for_encryption flag given when the
    SshCipher object was created).  Data is copied from src to dest while it
    is being encrypted/decrypted.  It is permissible that src and dest be the
    same buffer; however, partial overlap is not allowed. dest buffer must have
    at least blocklen bytes available space that can be written, although only
    block size bytes may be read.

    This function allows you to process last few bytes remaining in the buffer
    even if they are not multiple of the cipher block size. This is only usable
    for few ciphers, such as aes-gcm.

    After calling this function, you're no longer allowed to call
    ssh_cipher_transform or ssh_cipher_transform_remaining.

    If the cipher is used in a chaining mode or it is a stream cipher, the
    updated initialization vector or context is passed from one
    encryption/decryption call to the next.
  */

SshCryptoStatus
ssh_cipher_transform_remaining(SshCipher cipher,
                               unsigned char *dest,
                               const unsigned char *src,
                               size_t len);

/** Returns TRUE if the cipher is a combined mode cipher, that can be used for
    both encryption and authentication. Returns FALSE if not a combined mode
    cipher. */
Boolean ssh_cipher_is_auth_cipher(const char *name);

/** Starts the cryptography operation of the combined mode cipher. This must be
    called before processing a new packet/message with the combined mode
    cipher.

    Optional Additional Authenticated Data and length can be gived whenever
    needed. */

SshCryptoStatus
ssh_cipher_auth_start(SshCipher cipher,
                      const unsigned char *aad,
                      size_t aad_len,
                      size_t crypt_len);

/** Continues (runs update for) the cryptographic operation */
SshCryptoStatus
ssh_cipher_auth_continue(SshCipher handle,
                        const unsigned char *data,
                        size_t len);

/** Get the resulting MAC digest. The user allocated digest buffer must be
    at least ssh_auth_cipher_length(mac) bytes long.  */
SshCryptoStatus
ssh_cipher_auth_final(SshCipher cipher, unsigned char *digest);

/** Verify the MAC digest. The user allocated digest buffer must be
    at least ssh_auth_cipher_length(mac) bytes long. This function
    must be called when combined mode cipher requires it. */
SshCryptoStatus
ssh_cipher_auth_final_verify(SshCipher cipher, unsigned char *digest);

/** Get the length in bytes of the MAC digest.  The maximum length is
    SSH_MAX_HASH_DIGEST_LENGTH. */
size_t
ssh_cipher_auth_digest_length(const char *name);
#endif /* SSHCIPHER_H */
