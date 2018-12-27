/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   rijndael.h
*/

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

/* Gets the size of Rijndael context. */
size_t ssh_rijndael_ctxsize(void);

/* Sets an already allocated Rijndael key */
SshCryptoStatus ssh_rijndael_init(void *context,
                                  const unsigned char *key,
                                  size_t keylen,
                                  Boolean for_encryption);

void ssh_rijndael_uninit(void *context);

/* Sets an already allocated Rijndael key (cfb or ofb mode) */
SshCryptoStatus ssh_rijndael_init_fb(void *context,
                                     const unsigned char *key,
                                     size_t keylen,
                                     Boolean for_encryption);

/* This is like `ssh_rijndael_init', except enforces AES key size limits */
SshCryptoStatus ssh_aes_init(void *context,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption);

/* This is like `ssh_rijndael_init_fb', except enforces AES key size limits */
SshCryptoStatus ssh_aes_init_fb(void *context,
                                const unsigned char *key,
                                size_t keylen,
                                Boolean for_encryption);

SshCryptoStatus ssh_rijndael_start(void *context, const unsigned char *iv);

void ssh_aes_uninit(void *context);

/* Encrypt/decrypt in electronic code book mode. */
SshCryptoStatus ssh_rijndael_ecb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len);

/* Encrypt/decrypt in cipher block chaining mode. */
SshCryptoStatus ssh_rijndael_cbc(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len);

/* Encrypt/decrypt in cipher feedback mode. */
SshCryptoStatus ssh_rijndael_cfb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len);

/* Encrypt/decrypt in output feedback mode. */
SshCryptoStatus ssh_rijndael_ofb(void *context, unsigned char *dest,
                      const unsigned char *src, size_t len);

/* Counter mode encryption. 'ctr', interpreted as a network byte
   order integer, is incremented by 1 after each block encryption. */
SshCryptoStatus ssh_rijndael_ctr(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len);

/* Rijndael CBC-MAC. */
SshCryptoStatus ssh_rijndael_cbc_mac(void *context, const unsigned char *src,
                                     size_t len, unsigned char *iv);

#endif /* RIJNDAEL_H */
