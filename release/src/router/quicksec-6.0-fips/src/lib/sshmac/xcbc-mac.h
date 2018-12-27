/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   xcbc-mac.h
*/

#ifndef SSH_XCBCMAC_H
#define SSH_XCBCMAC_H


size_t ssh_xcbcmac_ctxsize(const SshCipherMacBaseDefStruct *cipher_def);

SshCryptoStatus
ssh_xcbcmac_init(void *context, const unsigned char *key, size_t keylen,
                 const SshCipherMacBaseDefStruct *cipher_def);

SshCryptoStatus ssh_xcbcmac_start(void *context);

void ssh_xcbcmac_update(void *context, const unsigned char *buf,
                        size_t len);

SshCryptoStatus ssh_xcbcmac_final(void *context, unsigned char *digest);

SshCryptoStatus ssh_xcbcmac_96_final(void *context, unsigned char *digest);

void ssh_xcbcmac_uninit(void *context);

#endif /* SSH_XCBCMAC_H */

