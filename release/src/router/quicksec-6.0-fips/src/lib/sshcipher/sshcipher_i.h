/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cipher internal definitions.
*/

#ifndef SSHCIPHER_I_H
#define SSHCIPHER_I_H


/* Definition structure for cipher functions. */
typedef struct SshCipherDefRec
{
  const char *name;

  /* Block length is 1 for stream ciphers. */
  size_t block_length;

  /* IV length is in most cases same as the block length */
  size_t iv_length;

  /* Key length is 0 if supports any length. This is adequate for
     most uses but possibly not suitable always. */
  struct {
    size_t min_key_len;
    size_t def_key_len;
    size_t max_key_len;
  } key_lengths;

  size_t (*ctxsize)(void);

  /* Basic initialization without explicit key checks. */
  SshCryptoStatus (*init)(void *context, const unsigned char *key,
                          size_t keylen, Boolean for_encryption);

  /* Initialization with key checks. */
  SshCryptoStatus (*init_with_check)(void *context, const unsigned char *key,
                                     size_t keylen, Boolean for_encryption);

  /* Start encryption or decryption. */
  SshCryptoStatus (*start)(void *context, const unsigned char *iv);

  /* Encryption and decryption. If src == dest, then this works
     inplace. */
  SshCryptoStatus (*transform)(void *context, unsigned char *dest,
                               const unsigned char *src, size_t len);

  void (*uninit)(void *context);

  /* TRUE if this cipher is a combined mode cipher capable of generating
   an authentication digest from its input. */
  Boolean is_auth_cipher;
  /* The length of the authentication digest */
  size_t digest_length;
  /* Start encryption or decryption for combined mode cipher. */
  SshCryptoStatus (*auth_start)(void *context, const unsigned char *iv,
                                const unsigned char *aad, size_t aad_len,
                                size_t crypt_len);
  /* MAC processing functionality for combined mode ciphers */
  void (*update)(void *context, const unsigned char *buf, size_t len);
  SshCryptoStatus (*final)(void *context, unsigned char *digest);
  SshCryptoStatus (*final_verify)(void *context, unsigned char *digest);

  /* Zeroization of all key and sensitive material (transform is never
     called after this). This can be NULL if the allocated context is
     all the state there is, since that is explicitly zeroized by the
     genciph layer itself (after call to this routine finishes). */
  void (*zeroize)(void *context);

} *SshCipherDef, SshCipherDefStruct;


typedef struct SshCipherObjectRec *SshCipherObject;

/* We need access to object-level functions for KAT tests */
SshCryptoStatus
ssh_cipher_object_allocate(const char *type,
                           const unsigned char *key,
                           size_t keylen,
                           Boolean for_encryption,
                           SshCipherObject *cipher_ret);

void
ssh_cipher_object_free(SshCipherObject cipher);

/* Get corresponding cipher def record by cipher name */
const SshCipherDefStruct *
ssh_cipher_get_cipher_def_internal(const char *name);

#endif /* SSH_CIPHER_I_H */
