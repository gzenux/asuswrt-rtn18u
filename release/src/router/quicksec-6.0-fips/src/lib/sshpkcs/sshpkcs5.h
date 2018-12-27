/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This implements PKCS#5 key derivation, encryption and decryption.
   Also PKCS#12 key derivation is done here, as it closely resembles
   what is done in PKCS#5 (why they are not the same is a good
   question).
*/

#ifndef SSH_PKCS5_H
#define SSH_PKCS5_H

/* Key derivation. Using given hash function `hash_name', iteration
   count `c' `password' and `salt', this derives a key whose length is
   given in `dk_len'. The `dk_len' must be lesser of equal to the hash
   digest length for the `hash_name'.

   The function returns an allocated pointer in case of success, and
   NULL, if hash was unknown, or dk_len is greater than hash digest
   length.

   This function provides backwards compatibility with PKCS#5 v1.5,
   and should not be used on new applications. */

unsigned char *
ssh_pkcs5_pbkdf1(const char *hash_name,
                 const unsigned char *passwd,
                 size_t passwd_len,
                 const unsigned char salt[8],
                 unsigned int c,
                 unsigned int dk_len);

/* Key derivation. Using given hash function `mac_name', iteration
   count `c' `password' and `salt', this derives a key whose length is
   given in `dk_len'. The key length requested may be arbitrarily
   large.

   The function returns an allocated pointer in case of success, and
   NULL, if mac was unknown, or dk_len is greater than hash digest
   length. */

unsigned char *
ssh_pkcs5_pbkdf2(const char *mac_name,
                 const unsigned char *passwd,
                 size_t passwd_len,
                 const unsigned char *salt,
                 size_t salt_len,
                 unsigned int c,
                 unsigned int dk_len);

unsigned char *
ssh_pkcs5_pbes1_encrypt(const unsigned char *cipher_name,
                        const char *hash_name,
                        const unsigned char *passwd,
                        size_t passwd_len,
                        const unsigned char salt[8],
                        unsigned int c,
                        const unsigned char *src,
                        size_t src_len,
                        size_t *ret_len);

unsigned char *
ssh_pkcs5_pbes1_decrypt(const char *cipher_name,
                        const char *hash_name,
                        const unsigned char *passwd,
                        size_t passwd_len,
                        const unsigned char salt[8],
                        unsigned int c,
                        const unsigned char *src,
                        size_t src_len,
                        size_t *ret_len);

unsigned char *
ssh_pkcs5_pbes2_encrypt(const char *cipher_name,
                        const char *mac_name,
                        const unsigned char *passwd,
                        size_t passwd_len,
                        const unsigned char *salt,
                        size_t salt_len,
                        const unsigned char *iv,
                        size_t iv_len,
                        unsigned int c,
                        const unsigned char *src,
                        size_t src_len,
                        size_t *ret_len);

unsigned char *
ssh_pkcs5_pbes2_decrypt(const char *cipher_name,
                        const char *mac_name,
                        const unsigned char *passwd,
                        size_t passwd_len,
                        const unsigned char *salt,
                        size_t salt_len,
                        const unsigned char *iv,
                        size_t iv_len,
                        unsigned int c,
                        const unsigned char *src,
                        size_t src_len,
                        size_t *ret_len);

/* PKCS#12 output diversifier.  This selects the intented purpose for
   key material generated. */
typedef enum {
  SSH_PKCS12_DIVERSIFY_KEY = 1,
  SSH_PKCS12_DIVERSIFY_IV  = 2,
  SSH_PKCS12_DIVERSIFY_MAC = 3
} SshPkcs12DiversifyID;

Boolean
ssh_pkcs12_derive_random(size_t amount,
                         SshPkcs12DiversifyID id,
                         const char *hash_name,
                         int iterations,
                         const unsigned char *passwd,
                         size_t passwd_len,
                         const unsigned char *salt,
                         size_t salt_len,
                         unsigned char *dest);


unsigned char *
ssh_pkcs12_pbe_decrypt(const char *cipher_name,
                       size_t key_len,
                       const char *hash_name,
                       int iterations,
                       const unsigned char *passwd,
                       size_t passwd_len,
                       const unsigned char *salt,
                       size_t salt_len,
                       const unsigned char *src,
                       size_t src_len,
                       size_t *dest_len_ret);

unsigned char *
ssh_pkcs12_pbe_encrypt(const char *cipher_name,
                       size_t key_len,
                       const char *hash_name,
                       int iterations,
                       const unsigned char *passwd,
                       size_t passwd_len,
                       const unsigned char *salt,
                       size_t salt_len,
                       const unsigned char *src,
                       size_t src_len,
                       size_t *dest_len_ret);



#endif /* SSH_PKCS5_H */
