/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic interface for decoding public keys and certificates from
   data blobs. The interface tries to decode the public keys and
   certificates from several formats, e.g PKCS#1, x509, ssh public key,
   etc...
*/

#ifndef SSHPUBKEY_H_INCLUDED
#define SSHPUBKEY_H_INCLUDED

#include "sshcrypt.h"

typedef enum
{
  /* Unknown format. */
  SSH_PKB_UNKNOWN,

  /* The SSH Crypto library format. */
  SSH_PKB_SSH,

  /* The SSH1 and SSH2 application file formats. */
  SSH_PKB_SSH_1,
  SSH_PKB_SSH_2,

  /* The public key derived from a X.509 cert. */
  SSH_PKB_FROM_X509,

  /* PKCS12 browser key */
  SSH_PKB_PKCS12_BROWSER_KEY,

  /* The OpenSSH SSH2 key format */
  SSH_PKB_OPENSSH_2,

  /* The OpenSSL format, same as X.509 SubjectPublicKeyInfo */
  SSH_PKB_SUBJECT_PKINFO
  /* More to come, stay tuned... */
} SshPKBType;


/* Get type of the public key from the keyblob given as `data' string
   whose length is `len' bytes. The call detects type of the public
   key and fills corresponding value into `kind'. If subject/comment is not
   NULL, and the key format supports visible subject names/comments, a copy of
   subject name/comment string is returned in 'subject'/`comment'.

   The function returns SSH_CRYPTO_OK if the key format was
   determined, and SSH_CRYPTO_UNKNOWN_KEY_TYPE if not. */
SshCryptoStatus
ssh_pkb_get_info(const unsigned char *data, size_t len,
                 unsigned char **unarmored_data, size_t *unarmored_len,
                 SshPKBType *kind,
                 char **subject, char **comment);

/* Returns information about the key type. *Needs_secret is set to
   TRUE if decoding if the blob requires some secret code.  A
   printable name of the type is returned in
   key_type_name_ret. Returns TRUE on success and FALSE otherwise. */
Boolean
ssh_pkb_get_type_info(SshPKBType type,
                      Boolean *needs_secret,
                      const char **key_type_name_ret);

/* Get public key out from the data blob given as `data' and `len'.
   If the `kind' argument specifies an encrypted key format, the
   password (or passphares) needed to decrypt the key is given as
   `password' and `password_len'.

   The function returns SSH_CRYPTO_OK if the public key was
   successfully decoded from the data. If the password is incorrect,
   the return value shall be SSH_CRYPTO_INVALID_PASSPHRASE, and if the
   key blob is not of specified type, the return value shall be
   SSH_CRYPTO_CORRUPTED_KEY_FORMAT.
*/
SshCryptoStatus
ssh_pkb_decode(SshPKBType kind,
               const unsigned char *data, size_t len,
               const unsigned char *password, size_t password_len,
               SshPublicKey *key);

/* Maps type identifier to canonical name that can be used in protocols. */
const char *ssh_pkb_type_to_name(SshPKBType kind);

/* Maps canonical name to type identifier. */
SshPKBType ssh_pkb_name_to_type(const char *name);

/* Get the SshPublicKey 'key' out as a data blob of the specified
   SshPKBType 'kind'.  If password and password_len are given, they
   are applied where needed.  The data returned in 'blob' is a null
   terminated string and it is ready to be written into a file, for
   example (not really if 'kind' is SSH_PKB_SSH!).  After a successful
   return, the caller must free the blob at some point.  If comment is
   not NULL, it will be set into the blob in an appropriate place, if
   such exists.  If subject is not NULL, it will be set into the blob
   in an appropriate place, if such exists.

   The function returns SSH_CRYPTO_OK if the public key was
   successfully encoded into a data blob.  If the 'kind' type is not
   supported or specified, the return value shall be
   SSH_CRYPTO_UNSUPPORTED.  If there are some trouble of other
   reasons, SSH_CRYPTO_OPERATION_FAILED will be returned.

   Supported types are:
   * SSH2 format (SSH_PKB_SSH_2)
   * OpenSSH's own format (SSH_PKB_OPENSSH_2)
   * crypto library's propiertary (?) format (SSH_PKB_SSH)
   */
SshCryptoStatus
ssh_pkb_encode(SshPKBType kind, unsigned char **blob,
               const unsigned char *subject, const unsigned char *comment,
               const unsigned char *password, size_t password_len,
               SshPublicKey key);

#endif /* SSHPUBKEY_H_INCLUDED */

/* eof */
