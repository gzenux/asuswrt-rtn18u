/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal hash definitions.
*/

#ifndef SSHHASH_I_H
#define SSHHASH_I_H

/* Definition structure for hash functions. That is, by using this
   structure crypto library transparently is able to use "any"
   hash functions. */
typedef struct SshHashDefRec
{
  const char *name;

  const char *asn1_oid;

  unsigned char iso_identifier;
  size_t digest_length;
  size_t input_block_length;
  size_t (*ctxsize)(void);
  SshCryptoStatus (*init)(void *context);
  void (*uninit)(void *context);
  void (*reset_context)(void *context);
  void (*update)(void *context, const unsigned char *buf, size_t len);
  SshCryptoStatus (*final)(void *context, unsigned char *digest);
  /* Compares the given oid with max size of max_len to the oid
     defined for the hash. If they match, then return the number
     of bytes actually used by the oid. If they do not match, return
     0. */
  size_t (*compare_asn1_oid)(const unsigned char *oid, size_t max_len);
  /* Generate encoded asn1 oid. Returns the pointer to the staticly
     allocated buffer of the oid. Sets the len to be the length of the
     oid. */




  const unsigned char *(*generate_asn1_oid)(size_t *len);
} *SshHashDef, SshHashDefStruct;

SshCryptoStatus
ssh_hash_allocate_internal(const SshHashDefStruct *hash_def,
                           SshHash *hash_ret);

const SshHashDefStruct *
ssh_hash_get_definition_internal(const SshHash hash);

/* Expansion from a passphrase into a key. */
SshCryptoStatus
ssh_hash_expand_key_internal(unsigned char *buffer, size_t buffer_len,
                             const unsigned char *ps, size_t ps_len,
                             unsigned char *magic, size_t magic_len,
                             const SshHashDefStruct *hash);


typedef struct SshHashObjectRec *SshHashObject;

/* We need access to object-level functions for KAT tests */
SshCryptoStatus
ssh_hash_object_allocate_internal(const SshHashDefStruct *hash_def,
                                  SshHashObject *hash_ret);
SshCryptoStatus
ssh_hash_object_allocate(const char *name, SshHashObject *hash);

void
ssh_hash_object_reset(SshHashObject hash);

void
ssh_hash_object_free(SshHashObject hash);

void
ssh_hash_object_update(SshHashObject hash, const void *buf, size_t len);

SshCryptoStatus
ssh_hash_object_final(SshHashObject hash, unsigned char *digest);

/* Returns the name of the hash function whose encoded oid matches the input
   'encoded_oid' or NULL if no hash function matches the encoded oid.
   This returns the actual encoded oid length in 'actual_encoded_oid_len' */
const char *ssh_hash_get_hash_from_oid(const unsigned char *encoded_oid,
                                       size_t max_encoded_oid_len,
                                       size_t *actual_encoded_oid_len);

#endif /* SSHHASH_I_H */
