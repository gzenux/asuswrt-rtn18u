/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Wrapper to read in and write out various private key formats.
*/

#ifndef SSHPRVKEY_H
#define SSHPRVKEY_H

#include "sshcrypt.h"

/* Supported private key formats. */
typedef enum
{
  /* Unknown type.  */
  SSH_SKB_UNKNOWN,
  /* 0 SSH proprietary encrypted private key format

   ekd = SSHENCODE(STR(ENCRYPT(PAD(keydata))))
   SSHENCODE(INT(magic) INT(v) STR(kind) STR(cipher) STR(ekd))

   where keydata depends on the key as below:
   RSA: SSHENCODE(MP(e) MP(d) MP(n) MP(u) MP(p) MP(q))
   DSA: SSHENCODE(MP(y) MP(x))
   MP = bits(32bit) || keydata
  */
  SSH_SKB_SSH_1,

  /* 1 SSH proprietary encrypted private key format, second revision
     Format is explainted in details on ssh-pk-export.c
  */
  SSH_SKB_SSH_2,

  /* 1 SSH1 client RSA key format
   "SSH PRIVATE KEY FILE FORMAT 1.1"
   BYTE(0) BYTE(cipher-id) INT(0) INT(keylen) MP1(n) MP1(e) STR(comment)
   ENCRYPTED(
     PAD(BYTE(r0) BYTE(r1) BYTE(r0) BYTE(r1) MP1(d) MP1(u) MP1(p) MP1(q)))
   MP1 = bits(16bit) || keydata
  */
  SSH_SKB_SECSH_1,

  /* 2 SSH2 client RSA/DSA key format
     SSH proprietary encrypted key format with armoring as below:
     "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
     Subject: login-name
     Comment: "anyting"
     BASE64(encoding of the key data)
     "---- END SSH2 ENCRYPTED PRIVATE KEY ----"
  */
  SSH_SKB_SECSH_2,

  /* 3 SSH Proprietary X509 plaintext key format (RSA and DSA)
     Asn.1 (sequence (sequence (oid) (params)) (key))
     where key depends on the PK oid and is:
     RSA: (sequence int(n) int(e) int(d) int(p) int(q) int(u))
     DSA: (sequence int(p) int(q) int(g) int(y) int(x))
  */
  SSH_SKB_SSH_X509,

  /* 4 PKCS#1 plaintext RSA key format
     RSA: (sequence
              int(v) int(n) int(e) int(d) int(p) int(q)
              int(d mod (p-1)) int(d mod (q-1))
              int(u))
  */
  SSH_SKB_PKCS1,

  /* 5 PKCS#8 plaintext key format (RSA and DSA)
     Asn.1 (sequence int(v=1) (sequence (oid)) (octet-string(key)))
     where key is octet string encoding depending on oid as below:
     RSA: PKCS1 private key
     DSA: (sequence int(v) int(p) int(q) int(g) int(y) int(x))
  */
  SSH_SKB_PKCS8,

  /* 6 PKCS#8 encrypted key format
     Asn.1 (sequence (sequence (oid) (params)) (octet-string(shroudedkey)))
     where shroudedkey is PKCS#5 PBE1 encrypted PKCS#8 private key.
     oid/params are PKCS#5 KDF1 parameters (hash and salt).
  */
  SSH_SKB_PKCS8_SHROUDED,

  /* PKCS#12 key as browsers store it. Decoding usually requires a
     passphrase. PKCS#12 may contain multiple keys. This key type
     takes the key browsers put to a PKCS#12 blob, and uses the same
     passhprase for both integrity protection and encryption. */
  SSH_SKB_PKCS12_BROWSER_KEY
} SshSKBType;


/* Get type of the private key from the keyblob given as `data' string
   whose length is `len' bytes. The call detects type of the private
   key and fills corresponding value into `kind'. If comment is not
   NULL, and the key format supports visible comments, a copy of
   comment string is returned in `comment'.

   The function returns SSH_CRYPTO_OK if the key format was
   determined, and SSH_CRYPTO_UNKNOWN_KEY_TYPE if not. */
SshCryptoStatus
ssh_skb_get_info(const unsigned char *data, size_t len,
                 char **cipher, char **hash,
                 unsigned char **unarmored_data, size_t *unarmored_len,
                 SshSKBType *kind, char **comment);


/* Returns information about the key type. *Needs_secret is set to
   TRUE if decoding if the blob requires some secret code.  A
   printable name of the type is returned in
   key_type_name_ret. Returns TRUE on success and FALSE otherwise. */
Boolean
ssh_skb_get_type_info(SshSKBType type,
                      Boolean *needs_secret,
                      const char **key_type_name_ret);

/* Get private key out from the data blob given as `data' and `len'.
   If the `kind' argument specifies an encrypted key format, the
   password (or passphares) needed to decrypt the key is given as
   `password' and `password_len'.

   The function returns SSH_CRYPTO_OK if the private key was
   successfully decoded from the data. If the password is incorrect,
   the return value shall be SSH_CRYPTO_INVALID_PASSPHRASE, and if the
   key blob is not of specified type, the return value shall be
   SSH_CRYPTO_CORRUPTED_KEY_FORMAT.
*/
SshCryptoStatus
ssh_skb_decode(SshSKBType kind,
               const unsigned char *data, size_t len,
               const char *cipher, const char *hash,
               const unsigned char *password, size_t password_len,
               SshPrivateKey *key);

/* Encodes the specified private key into given encoding `kind'. The
   key is encrypted using `cipher' with given `password' if the
   encoding supports encryption. If the encoding support subject names
   or comments strings these will be taken from `subject' and
   `comment' respectively. The encoded key will be returned at
   allocated memory blob `data' whose length is `len' bytes. */
SshCryptoStatus
ssh_skb_encode(SshSKBType kind,
               const SshPrivateKey key,
               const char *subject, const char *comment,
               const unsigned char *cipher,
               const unsigned char *password, size_t password_len,
               unsigned char **data, size_t *len);

/* Maps type identifier to canonical name that can be used in protocols. */
const char *ssh_skb_type_to_name(SshSKBType kind);

/* Maps canonical name to type identifier. */
SshSKBType ssh_skb_name_to_type(const char *name);

/* Decode plain key from buffer */
SshCryptoStatus
ssh_skb_decode_plain_key(unsigned char *key_buffer,
                         size_t key_buffer_len,
                         SshPrivateKey *key_output);

#endif /* SSHPRVKEY_H */
