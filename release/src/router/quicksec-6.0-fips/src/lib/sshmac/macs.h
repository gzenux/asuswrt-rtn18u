/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of message authentication code routines.
*/

#ifndef MACS_H
#define MACS_H

/* Keyed MAC's. */

/* Generic interface. */

/* The basic key-data-key message authentication code routines. */

/* Remember to allocate the extra space for the key! */
size_t
ssh_kdk_mac_ctxsize(const SshHashDefStruct *hash_def);

SshCryptoStatus
ssh_kdk_mac_init(void *context, const unsigned char *key, size_t keylen,
                 const SshHashDefStruct *hash_def);

void ssh_kdk_mac_uninit(void *context);

SshCryptoStatus ssh_kdk_mac_start(void *context);

void ssh_kdk_mac_update(void *context, const unsigned char *buf,
                        size_t len);

SshCryptoStatus ssh_kdk_mac_final(void *context, unsigned char *digest);

SshCryptoStatus ssh_kdk_mac_of_buffer(void *context, const unsigned char *buf,
                           size_t len, unsigned char *digest);

#endif /* MACS_H */
