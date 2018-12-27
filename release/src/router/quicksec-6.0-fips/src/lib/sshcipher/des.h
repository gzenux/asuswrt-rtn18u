/**
   @copyright
   Copyright (c) 2010 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   des.h
*/

#ifndef SSHDES_H
#define SSHDES_H

/* Single des */
/* Returns the size of a des key context. */
size_t ssh_des_ctxsize(void);

Boolean ssh_des_init_is_weak_key(const unsigned char *key);

/* Initializes an already allocated des key context */
SshCryptoStatus ssh_des_init(void *context,
                             const unsigned char *key, size_t keylen,
                             Boolean for_encryption);

/* Initializes an already allocated des key context */
SshCryptoStatus ssh_des_init_with_key_check(void *context,
                                            const unsigned char *key,
                                            size_t keylen,
                                            Boolean for_encryption);

void ssh_des_uninit(void *context);

SshCryptoStatus ssh_des_start(void *context, const unsigned char *iv);

/* Encrypt in ecb/cbc/cfb/ofb modes. */
SshCryptoStatus ssh_des_ecb(void *context, unsigned char *dest,
             const unsigned char *src, size_t len);

SshCryptoStatus ssh_des_cbc(void *context, unsigned char *dest,
             const unsigned char *src, size_t len);

SshCryptoStatus ssh_des_cfb(void *context, unsigned char *dest,
             const unsigned char *src, size_t len);

SshCryptoStatus ssh_des_ofb(void *context, unsigned char *dest,
             const unsigned char *src, size_t len);

/* Triple des */

/* Returns the size of a 3des key context. */
size_t ssh_des3_ctxsize(void);

#ifndef KERNEL
/* Sets the des key for the context.  Initializes the context.  The least
   significant bit of each byte of the key is ignored as parity. */
void *ssh_des3_allocate(const unsigned char *key, size_t keylen,
                    Boolean for_encryption);
#endif /* !KERNEL */

/* Sets an already allocated 3des context. */
SshCryptoStatus ssh_des3_init(void *context,
                              const unsigned char *key, size_t keylen,
                              Boolean for_encryption);

SshCryptoStatus ssh_des3_init_with_key_check(void *ptr,
                                             const unsigned char *key,
                                             size_t keylen,
                                             Boolean for_encryption);

void ssh_des3_uninit(void *context);

/* Destroy any sensitive data in the context. */
void ssh_des3_free(void *context);

SshCryptoStatus ssh_des3_start(void *context, const unsigned char *iv);

/* Encrypt using ecb/cbc/cfb/ofb modes. */
SshCryptoStatus ssh_des3_ecb(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len);

SshCryptoStatus ssh_des3_cbc(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len);

SshCryptoStatus ssh_des3_cfb(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len);

SshCryptoStatus ssh_des3_ofb(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len);

#endif /* SSHDES_H */
