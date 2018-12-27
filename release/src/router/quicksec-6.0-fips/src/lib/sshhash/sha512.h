/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sha512.h
*/

#ifndef SSH_SHA512_H
#define SSH_SHA512_H

/* Returns the size of an SHA context. */
size_t ssh_sha512_ctxsize(void);

/* Resets the SHA context to its initial state. */
void ssh_sha512_reset_context(void *context);

/* Add `len' bytes from the given buffer to the hash. */
void ssh_sha512_update(void *context, const unsigned char *buf,
                    size_t len);

/* Finish hashing. Return the 64-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha512_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha512_of_buffer(unsigned char digest[64],
                          const unsigned char *buf, size_t len);

/* Make the defining structure visible everywhere. */
extern const SshHashDefStruct ssh_hash_sha512_def;

/* Resets the SHA context to its initial state. */
void ssh_sha384_reset_context(void *context);

/* Finish hashing. Return the 48-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha384_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha384_of_buffer(unsigned char digest[48],
                          const unsigned char *buf, size_t len);

/* Make the defining structure visible everywhere. */
extern const SshHashDefStruct ssh_hash_sha384_def;

#endif /* SSH_SHA512_H */
