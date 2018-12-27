/**
   @copyright
   Copyright (c) 2013 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Combined encryption and authentication using CCM mode of operation.
*/


#ifndef MODE_CCM_H
#define MODE_CCM_H

size_t ssh_ccm_aes_ctxsize(void);

SshCryptoStatus
ssh_ccm_aes_init(void *context, const unsigned char *key, size_t keylen,
                 Boolean for_encryption);

SshCryptoStatus
ssh_ccm_64_aes_init(void *context, const unsigned char *key, size_t keylen,
                    Boolean for_encryption);

SshCryptoStatus
ssh_ccm_96_aes_init(void *context, const unsigned char *key, size_t keylen,
                    Boolean for_encryption);

SshCryptoStatus
ssh_ccm_64_2_aes_init(void *context, const unsigned char *key, size_t keylen,
                      Boolean for_encryption);

SshCryptoStatus
ssh_ccm_80_2_aes_init(void *context, const unsigned char *key, size_t keylen,
                      Boolean for_encryption);

SshCryptoStatus
ssh_ccm_auth_start(void *context, const unsigned char *iv,
                   const unsigned char *aad, size_t aad_len,
                   size_t crypt_len);

void ssh_ccm_update(void *context, const unsigned char *buf, size_t len);

SshCryptoStatus ssh_ccm_final(void *context, unsigned char *digest);
SshCryptoStatus ssh_ccm_final_verify(void *context, unsigned char *digest);

SshCryptoStatus ssh_ccm_transform(void *context,
                                  unsigned char *dest,
                                  const unsigned char *src,
                                  size_t len);
#endif /* MODE_CCM_H */
