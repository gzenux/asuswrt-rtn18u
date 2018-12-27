/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Import ssh1 key blobs.
*/

#ifndef SSHKEYBLOB1_H
#define SSHKEYBLOB1_H 1

#include "sshmp.h"
#include "sshcrypt.h"

#define SSH1_PRIVATE_KEY_ID_STRING "SSH PRIVATE KEY FILE FORMAT 1.1\n"
#define SSH1_CIPHER_NONE         0 /* no encryption */
#define SSH1_CIPHER_IDEA         1 /* IDEA (CFB) */
#define SSH1_CIPHER_DES          2 /* DES (CBC) */
#define SSH1_CIPHER_3DES         3 /* 3DES (CBC) */
#define SSH1_CIPHER_ARCFOUR      5 /* Arcfour (stream cipher) */
#define SSH1_CIPHER_BLOWFISH     6 /* Bruce Schneier's Blowfish (CBC) */

#define SSH1_AUTH_RHOSTS         1 /* .rhosts or /etc/hosts.equiv */
#define SSH1_AUTH_RSA            2 /* pure RSA authentication */
#define SSH1_AUTH_PASSWORD       3 /* password authentication */
#define SSH1_AUTH_RHOSTS_RSA     4 /* .rhosts with RSA host authentication */

/* Decode ssh1 public key blob.  Key blob is the entire ssh1 public
   key file.  Be aware, that this call can fail also when the blob
   itself is ok, but there is no RSA support compiled in.  Returns the
   key on success and NULL otherwise.  If comment parameter is
   non-NULL, it is set to point to the comment string of the key.
   Caller must free the key and the comment. */
SshCryptoStatus
ssh1_decode_pubkeyblob(const unsigned char *buf, size_t len,
                       char **comment,
                       SshPublicKey *key);

/* Decode ssh1 private key blob with passphrase.  Key blob is the
   entire ssh1 private key file.  Be aware, that this call can fail
   also when the blob itself and passphrase is ok, but there is no RSA
   support compiled in.  Returns the key on success and NULL
   otherwise.  If comment parameter is non-NULL, it is set to point to
   the comment string of the key.  Caller must free the key and the
   comment. */
SshCryptoStatus
ssh1_decode_privkeyblob(const unsigned char *blob, size_t bloblen,
                        const char *passphrase,
                        char **comment,
                        SshPrivateKey *key);

#endif /* ! SSHKEYBLOB1_H */
