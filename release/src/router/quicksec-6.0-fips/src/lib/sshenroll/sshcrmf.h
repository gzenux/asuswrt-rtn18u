/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encrypted value handing (from CRMF)
*/

#include "sshcrypt.h"
#include "x509.h"

#ifndef SSHCRMF_H
#define SSHCRMF_H

SshX509EncryptedValue
ssh_crmf_create_encrypted_private_key(const char *cipher,
                                      const SshPrivateKey key);

SshX509EncryptedValue
ssh_crmf_create_encrypted_data(const char *ciphername,
                               const unsigned char *data, size_t len);

/* Conveniece functions for decrypting and encrypting CRMF encrypted
   value type. The function ssh_crmf_decrypt_encrypted_value()
   decrypts 'value'.

   When done, it calls the callback below in a way 'ciphered' contains
   encrypted 'value' and 'plaintext' contains value as decrypted. If
   'plaintext' is NULL, decryption failed. The application has to free
   both ciphered and plaintext when they are no longer needed.

   When encrypting, the same callback is called, the plaintext is what
   application provided to ssh_crmf_encrypt_encrypted_value() as value
   argument, and 'ciphered' is the result, if any */

typedef void (*SshCrmfDecryptCB)(SshX509EncryptedValue ciphered,
                                 SshX509EncryptedValue plaintext,
                                 void *context);

/* Decrypt encrypted value payload. Call 'callback' when complete.
   The private key has to remain valid until the callback gets called
   or the operation is cancelled. */
SshOperationHandle
ssh_crmf_decrypt_encrypted_value(SshX509EncryptedValue value,
                                 SshPrivateKey key,
                                 SshCrmfDecryptCB callback,
                                 void *context);

/* Encrypt encrypted value payload, this means encrypting the the
   transport key using given public key. The public key has to remain
   valid untill the callback gets called, or the operation is
   cancelled. */
SshOperationHandle
ssh_crmf_encrypt_encrypted_value(SshX509EncryptedValue value,
                                 const SshPublicKey recipient,
                                 SshCrmfDecryptCB callback,
                                 void *context);

/* Create password based autenticator into given 'crmf' message. This
   authencticator is basically hmac calculated using key derived from
   given key material 'key' over DER encoding of pyblic key in
   'crmf' */
SshX509Status
ssh_crmf_create_public_key_mac(SshX509Certificate crmf,
                               const unsigned char *key, size_t key_len);

#endif /* SSHCRMF_H */
