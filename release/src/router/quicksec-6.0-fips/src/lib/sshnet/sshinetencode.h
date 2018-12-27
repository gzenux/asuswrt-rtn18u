/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshinetencode.h
*/

#ifndef SSHINETENCODE_H
#define SSHINETENCODE_H

#include "sshinet.h"

/* Encode and decode SshIpAddr addresses */

#ifndef _KERNEL
#include "sshbuffer.h"
int ssh_encode_ipaddr_buffer(SshBuffer buffer, const SshIpAddr ip);
int ssh_decode_ipaddr_buffer(SshBuffer buffer, SshIpAddr ip);
#endif  /* _KERNEL */

/* Decode IP-address from array. */
int ssh_decode_ipaddr_array(const unsigned char *buf, size_t bufsize,
                            void *ip);

/* Encode IP-address to array. Return 0 in case it does not fit to the buffer.
   NOTE, this is NOT a SshEncodeDatum Encoder, as the return values are
   different. */
size_t ssh_encode_ipaddr_array(unsigned char *buf, size_t bufsize,
                               const SshIpAddr ip);
size_t ssh_encode_ipaddr_array_alloc(unsigned char **buf_return,
                                     const SshIpAddr ip);

/* Special formatter for the ssh_encode function to encode IP-address. Note,
   that this never returns 0, but this returns the number of bytes required
   from the buffer. */
int ssh_encode_ipaddr_encoder(unsigned char *buf, size_t len,
                              const void *datum);

#ifdef WITH_IPV6
/* type+mask+scopeid+content */
#define SSH_MAX_IPADDR_ENCODED_LENGTH (1+4+4+16)
#else  /* WITH_IPV6 */
/* type+mask+content */
#define SSH_MAX_IPADDR_ENCODED_LENGTH (1+4+16)
#endif /* WITH_IPV6 */

#endif /* SSHINETENCODE_H */
