/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sha256.h
*/

#ifndef SSH_SHA256_H
#define SSH_SHA256_H

/* Returns the size of an SHA context. */
size_t ssh_sha256_ctxsize(void);

/* Resets the SHA context to its initial state. */
void ssh_sha256_reset_context(void *context);

/* Add `len' bytes from the given buffer to the hash. */
void ssh_sha256_update(void *context, const unsigned char *buf,
                    size_t len);

/* Finish hashing. Return the 32-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha256_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha256_of_buffer(unsigned char digest[32],
                       const unsigned char *buf, size_t len);

/* Finish hashing. Return the 16-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha256_128_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha256_128_of_buffer(unsigned char digest[16],
                          const unsigned char *buf, size_t len);

/* Finish hashing. Return the 12-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha256_96_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha256_96_of_buffer(unsigned char digest[12],
                          const unsigned char *buf, size_t len);

/* Finish hashing. Return the 10-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha256_80_final(void *context, unsigned char *digest);

/* Compute SHA digest from the buffer. */
void ssh_sha256_80_of_buffer(unsigned char digest[10],
                          const unsigned char *buf, size_t len);

/* Resets the SHA context to its initial state. */
void ssh_sha224_reset_context(void *context);

/* Finish hashing. Return the 28-byte long digest to the
   caller-supplied buffer. */
SshCryptoStatus ssh_sha224_final(void *context, unsigned char *digest);

/* Make the defining structure visible everywhere. */
extern const SshHashDefStruct ssh_hash_sha256_def;
extern const SshHashDefStruct ssh_hash_sha256_128_def;
extern const SshHashDefStruct ssh_hash_sha256_96_def;
extern const SshHashDefStruct ssh_hash_sha256_80_def;
extern const SshHashDefStruct ssh_hash_sha224_def;

#endif /* SSH_SHA256_H */
