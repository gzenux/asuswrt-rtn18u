/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public header for reading and writing PKCS-8 encoded plaintext and
   encrypted private keys.
*/

#ifndef SSH_PKCS8_H
#define SSH_PKCS8_H

#include "sshcrypt.h"
#include "x509.h"

/* Plaintext private keys per PKCS8 version 1.2 section 6. */

/* Encode SSH format private key `key' into plaintext PKCS8 format.
   The private key is returned at DER encoded buffer `buf' whose
   length is `buf_len' bytes.  */
SshX509Status
ssh_pkcs8_encode_private_key(const SshPrivateKey key,
                             unsigned char **buf, size_t *buf_len);

/* Decode the plaintext PKCS-8 encoded private key from DER encoded
   binary buffer `buf', of length `buf_len' bytes into SSH format
   private key `key', which the function allocates. */
SshX509Status
ssh_pkcs8_decode_private_key(const unsigned char *buf, size_t buf_len,
                             SshPrivateKey *key);

/* Encrypted private keys per PKCS8 version 1.2 section 7. */

/* Encrypt private key into PKCS8 DER encoded encrypted private key.
   ciphername together with hashname identify the PKCS5 pbe1 to use
   for encryption. The password expansion is done with PKCS5 kdf1
   function.

   PKCS#12 usage. The ciphername is numeric oid that identifies the
   cipher and hash algorithms to use for PKCS#12 key expansion. The
   hashname may be NULL, or then it must be hash function defined by
   the PKCS#12 oid. In this case the password must be in 16bit unicode,
   a.k.a. SSH_CHARSET_BMP, and terminated with two NULs.
 */
SshX509Status
ssh_pkcs8_encrypt_private_key(const unsigned char *ciphername,
                              const char *hashname,
                              const unsigned char *password,
                              size_t password_len,
                              const SshPrivateKey key,
                              unsigned char **buf, size_t *len);

/* Decrypt the private key `key'from PKCS8 encoded encrypted private
   key from `buf' whose length is `len' bytes. The cipher key is
   derived from `password' with PKCS5 kdf1 function. The calling
   application has to know proper password to use with the block from
   out-of-band information.

   This function can also decrypt private keys where the key
   derivation is done with PKCS#12 functions. In that case the
   password must be in 16bit unicode, a.k.a. SSH_CHARSET_BMP, and
   terminated with two NULs.
*/

SshX509Status
ssh_pkcs8_decrypt_private_key(const unsigned char *password,
                              size_t password_len,
                              const unsigned char *buf, size_t len,
                              SshPrivateKey *key);
#endif /* SSH_PKCS8_H */
