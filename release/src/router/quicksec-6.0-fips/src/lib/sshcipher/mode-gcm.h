/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Combined encryption and authentication using GCM mode of operation.
*/

#ifndef GCM_H
#define GCM_H

size_t ssh_gcm_aes_ctxsize(void);
size_t ssh_gcm_aes_table_256_ctxsize(void);
size_t ssh_gcm_aes_table_4k_ctxsize(void);
size_t ssh_gcm_aes_table_8k_ctxsize(void);
size_t ssh_gcm_aes_table_64k_ctxsize(void);


SshCryptoStatus
ssh_gcm_aes_init(void *context, const unsigned char *key, size_t keylen,
                 Boolean for_encryption);

SshCryptoStatus
ssh_gcm_aes_table_256_init(void *context, const unsigned char *key,
                           size_t keylen, Boolean for_encryption);
SshCryptoStatus
ssh_gcm_aes_table_4k_init(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption);
SshCryptoStatus
ssh_gcm_aes_table_8k_init(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption);
SshCryptoStatus
ssh_gcm_aes_table_64k_init(void *context, const unsigned char *key,
                           size_t keylen, Boolean for_encryption);


SshCryptoStatus ssh_gcm_auth_start(void *context, const unsigned char *iv,
                                   const unsigned char *aad, size_t aad_len,
                                   size_t crypt_len);

void ssh_gcm_update(void *context, const unsigned char *buf, size_t len);

SshCryptoStatus ssh_gcm_final(void *context, unsigned char *digest);
SshCryptoStatus ssh_gcm_96_final(void *c, unsigned char *digest);
SshCryptoStatus ssh_gcm_64_final(void *c, unsigned char *digest);


SshCryptoStatus ssh_gcm_final_verify(void *context, unsigned char *digest);
SshCryptoStatus ssh_gcm_96_final_verify(void *context, unsigned char *digest);
SshCryptoStatus ssh_gcm_64_final_verify(void *context, unsigned char *digest);

SshCryptoStatus ssh_gcm_transform(void *context,
                                  unsigned char *dest,
                                  const unsigned char *src,
                                  size_t len);

SshCryptoStatus ssh_gmac_transform(void *context,
                                   unsigned char *dest,
                                   const unsigned char *src,
                                   size_t len);
#endif /* GCM_H */
