/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   FL-HMAC - Public definitions for HMAC algorithms using FIPS Library.
*/

#ifndef FL_HMAC_H
#define FL_HMAC_H

/* Functions used for all algorithms. */
size_t fl_hmac_ctxsize(const SshHashDefStruct *unused);

void fl_hmac_uninit(void *context);

SshCryptoStatus fl_hmac_start(void *context);

void fl_hmac_update(void *context,
                    const unsigned char *buf,
                    size_t len);

SshCryptoStatus fl_hmac_final(void *context,
                              unsigned char *mac);

SshCryptoStatus fl_hmac_of_buffer(void *context,
                                  const unsigned char *buf,
                                  size_t len,
                                  unsigned char *mac);

/* HMAC-SHA-1 specific functions. */
SshCryptoStatus fl_hmac_sha1_init(void *context,
                                  const unsigned char *key,
                                  size_t key_len,
                                  const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha1_96_init(void *context,
                                     const unsigned char *key,
                                     size_t key_len,
                                     const SshHashDefStruct *unused);

/* HMAC-SHA-256 specific functions. */
SshCryptoStatus fl_hmac_sha256_init(void *context,
                                    const unsigned char *key,
                                    size_t key_len,
                                    const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha256_128_init(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha256_96_init(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       const SshHashDefStruct *unused);

/* HMAC-SHA-224 specific functions. */
SshCryptoStatus fl_hmac_sha224_init(void *context,
                                    const unsigned char *key,
                                    size_t key_len,
                                    const SshHashDefStruct *unuded);

SshCryptoStatus fl_hmac_sha224_128_init(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        const SshHashDefStruct *unused);

/* HMAC-SHA-512 specific functions. */
SshCryptoStatus fl_hmac_sha512_init(void *context,
                                    const unsigned char *key,
                                    size_t key_len,
                                    const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha512_256_init(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha512_128_init(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        const SshHashDefStruct *unused);

/* HMAC-SHA-384 specific functions. */
SshCryptoStatus fl_hmac_sha384_init(void *context,
                                    const unsigned char *key,
                                    size_t key_len,
                                    const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha384_192_init(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        const SshHashDefStruct *unused);

SshCryptoStatus fl_hmac_sha384_128_init(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        const SshHashDefStruct *unused);

#endif /* FL_HMAC_H */
