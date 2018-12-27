/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for auxillary routines related to crypto library but not
   essential for its operations. Eg. helper routines etc.
*/

#ifndef SSHCRYPTOAUX_H
#define SSHCRYPTOAUX_H

#ifdef SSHDIST_MATH
#include "sshmp.h"
#endif /* SSHDIST_MATH */

/******************** Crypto aliases ************************************/

/* Return a list of ciphers, including native names and aliases. The
   caller must free the returned string with ssh_free. */
char *ssh_cipher_alias_get_supported(void);

/* Is the cipher supported. Takes aliases into account, eg. both alias
   and the native name will return TRUE if they are supported. */
Boolean ssh_cipher_alias_supported(const char *name);

/* Return the native name of a cipher alias. If given native name,
   returns the native name. The returned value is static or the passed
   argument, and must not be modified or freed. Returns NULL if cipher
   `name' is not supported.

   Clarification: The returned value MAY be the same as what was
   passed as an argument. What this means that the following might be
   incorrect:

        char * x = ssh_strdup("des");
        char * y = ssh_cipher_alias_get_native(x);
        ssh_free(x);
        SshCipher z = ssh_cipher_allocate(y, ...);

   since after ssh_cipher_alias_get_native x could be equal to y, and
   after ssh_free(x) y would also be invalid. You should not modify x
   or invalidate it until after there is no need for y, or strdup y
   explicitly. */
const char *ssh_cipher_alias_get_native(const char *name);

/******************* Key expansion (from passhphrase) *******************/

/* Expand given passphrase (text, text_len) with pseudo-random
   function to be of length buf_len.

   Method used is a very simple expansion idea, that nevertheless seems
   very solid. The strength is based on rehashing (using the MD5 hash
   function) everything on every iteration. Now it seems that this infact
   isn't very efficient way, but we don't need efficient way because hashing
   is extremely fast. However, if faster expansion is needed I suggest
   something like:

     h_i = HASH(passphrase, f(i))

   where h_i are combined as h_0 | h_1 | h_2 ... to form the expanded
   key. The function f(i) should be some bijective function (maybe
   just f(x) = x ?). */

SshCryptoStatus
ssh_hash_expand_text_md5(const unsigned char *text, size_t text_len,
                         unsigned char *buf, size_t buf_len);


SshCryptoStatus
ssh_cipher_allocate_with_passphrase(const char *name,
                                    const char *passphrase,
                                    Boolean for_encryption,
                                    SshCipher *cipher);

SshCryptoStatus
ssh_private_key_import_with_passphrase(const unsigned char *buf, size_t len,
                                       const char *passphrase,
                                       SshPrivateKey *key);
SshCryptoStatus
ssh_private_key_export_with_passphrase(SshPrivateKey key,
                                       const char *cipher_name,
                                       const char *passphrase,
                                       unsigned char **bufptr,
                                       size_t *length_return);

/******************* Import/export compatibility API ********************/

/* Notice: All these functions are deprecated and will be removed in
   future releases. */

/* Constructs a private key object from its binary representation.
   The data will be decrypted by the passphrase. The function returns
   SSH_CRYPTO_OK, if everything went fine. Then *key will contain the
   imported private key. Otherways key might contain garbage. This
   routine is deprecated, use ssh_pk_import instead. */

SshCryptoStatus
ssh_private_key_import(const unsigned char *buf,
                       size_t len,
                       const unsigned char *cipher_key,
                       size_t cipher_keylen,
                       SshPrivateKey *key);

/* Constructs a key blob (binary representation) for a given private
   key. The sensitive parts of the blob will be encrypted. If
   everything went fine, the function returns SSH_CRYPTO_OK. Then
   *bufptr will point to the blob. Otherways *bufptr might point to
   anywhere. This routine is deprecated, use ssh_pk_export instead.*/

SshCryptoStatus
ssh_private_key_export(SshPrivateKey key,
                       const char *cipher_name,
                       const unsigned char *cipher_key,
                       size_t cipher_keylen,
                       unsigned char **bufptr,
                       size_t *length_return);

/* Allocates and initializes a public key object from the contents of
   the buffer.  The buffer has presumably been created by
   ssh_public_key_export. Returns SSH_CRYPTO_OK, if everything went
   fine. In such a case, the public key will be written to *key.
   Otherways *key might contain garbage. This routine is deprecated,
   use ssh_pk_import instead. */

SshCryptoStatus
ssh_public_key_import(const unsigned char *buf,
                      size_t len,
                      SshPublicKey *key);

/* Create a public key blob from an SshPublicKey. Returns
   SSH_CRYPTO_OK, if everything went fine. In such a case, *buf will
   be set to point to dynamically allocated memory which contains the
   blob, and *length_return to the length of the blob.  The caller must free
   buf with ssh_free(). This routine is deprecated, use ssh_pk_export
   instead. */

SshCryptoStatus
ssh_public_key_export(SshPublicKey key,
                      unsigned char **buf,
                      size_t *length_return);

/* Export group information. Groups contain no user specific
   information and can be distributed freely. This routine is
   deprecated, use ssh_pk_export instead. */

SshCryptoStatus
ssh_pk_group_export(SshPkGroup group,
                    unsigned char **buf,
                    size_t *buf_length);

/* Import a binary blob of group information. This routine is
   deprecated, use ssh_pk_import instead. */
SshCryptoStatus
ssh_pk_group_import(const unsigned char *buf,
                    size_t buf_length,
                    SshPkGroup *group);

/* Export randomizers of a group (all of them). Note that this
   information should be kept strictly secret. This routine is
   deprecated, use ssh_pk_export instead. */
SshCryptoStatus
ssh_pk_group_export_randomizers(SshPkGroup group,
                                unsigned char **buf,
                                size_t *buf_length);

/* Import a binary blob of randomizers. This blob cannot generate a
   group, and thus should be used only when the receiver is actually
   the same group. In some cases, e.g. in UNIX, some process handling
   mechanisms make this neccessary. This routine is deprecated, use
   ssh_pk_import instead. */
SshCryptoStatus
ssh_pk_group_import_randomizers(SshPkGroup group,
                                const unsigned char *buf,
                                size_t buf_length);

/******************* Conveniency functions for hashes *******************/

/* Hashes one buffer with selected hash type and returns the digest.
   This returns SSH_CRYPTO_UNSUPPORTED if called with an invalid
   type. */
SshCryptoStatus
ssh_hash_of_buffer(const char *hash, const void *buf, size_t len,
                   unsigned char *digest);


/******************* Pseudo random noise source ************************/

/** Minimum interval in seconds between noise additions. */
#define SSH_RANDOM_POLL_MIN_INTERVAL 1

/** Attach a noise source to crypto library. This noise source gathers pseudo
    random noise from the system environment. This function may only be called
    after the crypto library has been initialized.

    On initialization this module registers itself as a noise source to the
    crypto library. Whenever a noise request is received this module gathers
    pseudo random noise from the system environment and adds it to the crypto
    library's random number generator. After adding the noise this will ignore
    subsequent noise requests for SSH_RANDOM_POLL_MIN_INTERVAL seconds.

    The entropy of the noise obtained is highly dependent on the operating
    system and environment, applications should not rely on this mechanism
    alone to provide good randomness. On some platforms this function may
    do nothing. */
void ssh_random_noise_polling_init(void);

/** Detach the noise source from crypto library. Once this function has been
    called, the random number generator will no longer be supplied with
    noise obtained from the operating system. */
void ssh_random_noise_polling_uninit(void);


#ifdef SSHDIST_MATH

/******************* mprz **********************************************/

/* Modular invert with positive results. */
int ssh_mprz_aux_mod_invert(SshMPInteger op_dest, SshMPIntegerConst op_src,
                            SshMPIntegerConst modulo);

/* Random number with special modulus */
void ssh_mprz_aux_mod_random(SshMPInteger op, SshMPIntegerConst modulo);

/* Generate a random integer with entropy at most _bits_ bits. The atmost,
   means that the actual number of bits depends whether the modulus is
   smaller in bits than the _bits_.  */
void ssh_mprz_aux_mod_random_entropy(SshMPInteger op,
                                     SshMPIntegerConst modulo,
                                     unsigned int bits);
#endif /* SSHDIST_MATH */

/************************ Crypto system initialization **********************/

/** Initialize cryptographic subsystem. This initializes all built in
    crypto libraries.

    @return
    Returns SSH_CRYPTO_OK if cryptographic subsystem was properly
    initialized. Otherwise this returns an error code describing
    the reason of failure and leaves all built in crypto libraries
    uninitialized. */
SshCryptoStatus ssh_crypto_system_initialize(void);

/** Uninitialize cryptographic subsystem.

    @return
    Returns SSH_CRYPTO_OK if cryptographic subsystem was properly
    uninitialized. Otherwise this returns an error code describing
    the reason of failure, built in crypto libraries may be left to
    an undefined state. */
SshCryptoStatus ssh_crypto_system_uninitialize(void);

/**************** SafeZone FIPS library init/uninit ********************/

/* Initialize SafeZone FIPS library. */
SshCryptoStatus ssh_fl_init(void);

/* Uninitialize SafeZone FIP library. */
void ssh_fl_uninit(void);

char *ssh_crypto_system_get_ek_type();

char *ssh_crypto_system_get_ek_init_info();

#endif /* SSHCRYPTOAUX_H */
