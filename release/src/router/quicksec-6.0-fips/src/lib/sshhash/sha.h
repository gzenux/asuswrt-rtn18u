/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SHA - Secure Hash Algorithm
*/

#ifndef SSH_SHA_H
#define SSH_SHA_H

/* Returns the size of an SHA context. */
size_t ssh_sha_ctxsize(void);

/* Initializes an SHA context. */
SshCryptoStatus ssh_sha_init(void *context);

/* Unitializes an SHA context. */
void ssh_sha_uninit(void *context);

/* Resets the SHA context to its initial state. */
void ssh_sha_reset_context(void *context);

/* Add `len' bytes from the given buffer to the hash. */
void ssh_sha_update(void *context, const unsigned char *buf,
                    size_t len);

/* Finish hashing. Return the 20-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha_of_buffer(unsigned char digest[20],
                       const unsigned char *buf, size_t len);

/* Finish hashing. Return the 12-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha_96_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha_96_of_buffer(unsigned char digest[12],
                          const unsigned char *buf, size_t len);

/* Finish hashing. Return the 10-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha_80_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha_80_of_buffer(unsigned char digest[10],
                          const unsigned char *buf, size_t len);

/* Implements the internal SHA-1 transform. This is used in FIPS 186-2
   for generating DSA private keys. The internal state of the SHA-1
   computation is initialized to the usual initialization values and
   'in' is 64 bytes to be added to the internal state. The output value
   is stored in 'buf'. */
void ssh_sha_transform(SshUInt32 buf[5], const unsigned char in[64]);

/* Implements the internal SHA-1 transform. This is used in FIPS 186-2
   for generating DSA signatures. The internal state of the SHA-1
   computation is initialized to a permutation of the usual initialization
   values and 'in' is 64 bytes to be added to the internal state. The
   output value is stored in 'buf'. */
 void ssh_sha_permuted_transform(SshUInt32 buf[5], const unsigned char in[64]);

/* Make the defining structure visible everywhere. */
extern const SshHashDefStruct ssh_hash_sha_def;
extern const SshHashDefStruct ssh_hash_sha_96_def;
extern const SshHashDefStruct ssh_hash_sha_80_def;

#endif /* SSH_SHA_H */
