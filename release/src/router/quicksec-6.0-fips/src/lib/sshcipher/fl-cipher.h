/**
   @copyright
   Copyright (c) 2012 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   FL-Cipher - Public definitions for cipher algorithms using FIPS Library.
*/

#ifndef FL_CIPHER_H
#define FL_CIPHER_H

/* Functions used for 3DES-ECB/CBC algorithms. */

size_t fl_cipher_des3_ctxsize(void);

SshCryptoStatus fl_cipher_des3_init_ecb(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        Boolean for_encryption);

SshCryptoStatus fl_cipher_des3_init_cbc(void *context,
                                        const unsigned char *key,
                                        size_t key_len,
                                        Boolean for_encryption);

SshCryptoStatus
fl_cipher_des3_init_ecb_with_key_check(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption);

SshCryptoStatus
fl_cipher_des3_init_cbc_with_key_check(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption);

void fl_cipher_des3_uninit(void *context);

SshCryptoStatus fl_cipher_des3_start_ecb(void *context,
                                         const unsigned char *unused);

SshCryptoStatus fl_cipher_des3_start_cbc(void *context,
                                         const unsigned char *iv);

SshCryptoStatus fl_cipher_des3_transform_ecb(void *context,
                                             unsigned char *dest,
                                             const unsigned char *src,
                                             size_t len);

SshCryptoStatus fl_cipher_des3_transform_cbc(void *context,
                                             unsigned char *dest,
                                             const unsigned char *src,
                                             size_t len);

/* Functions used for AES-ECB/CBC/CTR algorithms. */

size_t fl_cipher_aes_ctxsize(void);

SshCryptoStatus fl_cipher_aes_init_ecb(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_init_cbc(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_init_ctr(void *context,
                                       const unsigned char *key,
                                       size_t key_len,
                                       Boolean for_encryption);

void fl_cipher_aes_uninit(void *context);

SshCryptoStatus fl_cipher_aes_start_ecb(void *context,
                                        const unsigned char *unused);

SshCryptoStatus fl_cipher_aes_start_cbc(void *context,
                                        const unsigned char *iv);

SshCryptoStatus fl_cipher_aes_start_ctr(void *context,
                                        const unsigned char *iv);

SshCryptoStatus fl_cipher_aes_transform_ecb(void *context,
                                            unsigned char *dest,
                                            const unsigned char *src,
                                            size_t len);

SshCryptoStatus fl_cipher_aes_transform_cbc(void *context,
                                            unsigned char *dest,
                                            const unsigned char *src,
                                            size_t len);

SshCryptoStatus fl_cipher_aes_transform_ctr(void *context,
                                            unsigned char *dest,
                                            const unsigned char *src,
                                            size_t len);

/* Function for AES-XCBC cipher use */
SshCryptoStatus
fl_aes_xcbc_mac(void *context, const unsigned char *src, size_t len,
                unsigned char *iv_arg);


/* Functions used for AES-GCM algorithm. */

size_t fl_cipher_aes_gcm_ctxsize(void);

void fl_cipher_aes_gcm_uninit(void *context);

SshCryptoStatus fl_cipher_aes_gcm_init_8(void *context,
                                         const unsigned char *key,
                                         size_t key_len,
                                         Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_gcm_init_12(void *context,
                                          const unsigned char *key,
                                          size_t key_len,
                                          Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_gcm_init_16(void *context,
                                          const unsigned char *key,
                                          size_t key_len,
                                          Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_gcm_start(void *context,
                                        const unsigned char *iv,
                                        const unsigned char *aad,
                                        size_t aad_len,
                                        size_t crypt_len);

SshCryptoStatus fl_cipher_aes_gcm_transform(void *context,
                                            unsigned char *dest,
                                            const unsigned char *src,
                                            size_t len);

SshCryptoStatus fl_cipher_aes_gcm_final(void *context,
                                        unsigned char *tag);

SshCryptoStatus fl_cipher_aes_gcm_final_verify(void *context,
                                               unsigned char *tag);

#ifdef SSHDIST_FIPSLIB_1_1
/* Functions used for AES-GMAC. */
SshCryptoStatus fl_cipher_aes_gmac_start(void *context,
                                         const unsigned char *iv,
                                         const unsigned char *aad,
                                         size_t aad_len,
                                         size_t crypt_len);

void fl_cipher_aes_gmac_update(void *cipher_context,
                               const unsigned char *buf,
                               size_t len);

SshCryptoStatus fl_cipher_aes_gmac_transform(void *context,
                                             unsigned char *dest,
                                             const unsigned char *src,
                                             size_t len);
#endif /* SSHDIST_FIPSLIB_1_1 */

/* Functions used for AES-CCM algorithm. */

size_t fl_cipher_aes_ccm_ctxsize(void);

void fl_cipher_aes_ccm_uninit(void *context);

SshCryptoStatus fl_cipher_aes_ccm_init_8(void *context,
                                         const unsigned char *key,
                                         size_t key_len,
                                         Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_ccm_init_12(void *context,
                                          const unsigned char *key,
                                          size_t key_len,
                                          Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_ccm_init_16(void *context,
                                          const unsigned char *key,
                                          size_t key_len,
                                          Boolean for_encryption);

SshCryptoStatus fl_cipher_aes_ccm_start(void *context,
                                        const unsigned char *iv,
                                        const unsigned char *aad,
                                        size_t aad_len,
                                        size_t crypt_len);

SshCryptoStatus fl_cipher_aes_ccm_transform(void *context,
                                            unsigned char *dest,
                                            const unsigned char *src,
                                            size_t len);

SshCryptoStatus fl_cipher_aes_ccm_final(void *context,
                                        unsigned char *tag);

SshCryptoStatus fl_cipher_aes_ccm_final_verify(void *context,
                                               unsigned char *tag);
#endif /* FL_CIPHER_H */
