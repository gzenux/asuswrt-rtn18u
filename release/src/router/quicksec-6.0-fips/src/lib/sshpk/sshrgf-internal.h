/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Redundancy Generators
*/

#include "sshhash_i.h"
#include "sshrgf.h"


#ifndef SSHRGF_INTERNAL_H
#define SSHRGF_INTERNAL_H
/* The RGF allocation function. */
typedef SshRGF (*SshRGFAllocate)(const SshRGFDefStruct *def);

/* The RGF freeing function. */
typedef void (*SshRGFFree)(SshRGF rgf);


/********* Functions related to the hashing part of an RGF. ***********/


/* The RGF hash function update. By definition this function updates the
   rgf context by the input data. The data may be either usual update data,
   which should be handled by a hash function or the resulting digest
   computed "outside".

   In the latter case the 'for_digest' is set to TRUE. If such a case
   happens the update function may either reject the operation or
   function in a such a way that the resulting digest is equal to the
   input. */
typedef SshCryptoStatus (*SshRGFHashUpdate)(SshRGF rgf,
                                            Boolean for_digest,
                                    const unsigned char *data,
                                    size_t data_len);

/* Allocate and return the computed hashed digest. */
typedef SshCryptoStatus (*SshRGFHashFinalize)(SshRGF rgf,
                                              unsigned char **digest,
                                      size_t *digest_length);

/* Compares the given oid with max size of max_len to the oid
   defined for the hash. If they match, then return the number
   of bytes actually used by the oid. If they do not match, return
   0. */
typedef size_t (*SshRGFHashAsn1OidCompare)(SshRGF rgf,
                                           const unsigned char *oid,
                                           size_t max_len);
/* Generate encoded asn1 oid. Returns the pointer to the staticly
   allocated buffer of the oid. Sets the len to be the length
   of the oid. */




typedef const unsigned char *(*SshRGFHashAsn1OidGenerate)(SshRGF rgf,
                                                          size_t *len);

/********* Functions related to the padding part of an RGF. ***********/

/* The RGF encryption and decryption functions. */
typedef SshCryptoStatus (*SshRGFEncrypt)(SshRGF rgf,
                                         size_t key_size_in_bits,
                                         const unsigned char *msg,
                                         size_t msg_len,
                                         unsigned char **output_msg,
                                         size_t *output_msg_len);

typedef SshCryptoStatus (*SshRGFDecrypt)(SshRGF rgf,
                                         size_t key_size_in_bits,
                                         const unsigned char *decrypted_msg,
                                         size_t decrypted_msg_len,
                                         unsigned char **output_msg,
                                         size_t *output_msg_len);

/* The RGF signature and verification functions. */
typedef SshCryptoStatus (*SshRGFSign)(SshRGF rgf,
                                      size_t key_size_in_bits,
                                      unsigned char **output_msg,
                                      size_t *output_msg_len);

typedef
SshCryptoStatus (*SshRGFVerify)(SshRGF rgf,
                                size_t key_size_in_bits,
                                const unsigned char *decrypted_signature,
                                size_t decrypted_signature_len);


struct SshRGFDefRec
{
  SshRGFAllocate rgf_allocate;
  SshRGFFree rgf_free;

  /* Hashing related functions. */
  SshRGFHashUpdate               rgf_hash_update;
  SshRGFHashFinalize             rgf_hash_finalize;
  SshRGFHashAsn1OidCompare       rgf_hash_asn1_oid_compare;
  SshRGFHashAsn1OidGenerate      rgf_hash_asn1_oid_generate;

  /* The hash function name */
  const char *hash;

  /* Redundancy generation functions. */
  SshRGFEncrypt rgf_encrypt;
  SshRGFDecrypt rgf_decrypt;
  SshRGFSign    rgf_sign;
  SshRGFVerify  rgf_verify;
};


#define SSH_RGF_HASH_SHA1         0x0001
#define SSH_RGF_HASH_MD5          0x0002
#define SSH_RGF_HASH_MD4          0x0004
#define SSH_RGF_HASH_MD2          0x0008
#define SSH_RGF_HASH_RIPEMED128   0x0010
#define SSH_RGF_HASH_RIPEMD160    0x0020
#define SSH_RGF_HASH_SHA224       0x0040
#define SSH_RGF_HASH_SHA256       0x0080
#define SSH_RGF_HASH_SHA384       0x0100
#define SSH_RGF_HASH_SHA512       0x0200


/* The RGF function context. */
struct SshRGFRec
{
  /* The RGF method definition. */
  const SshRGFDefStruct *def;

  /* The area for storing a precomputed hash digest. */
  const unsigned char *precomp_digest;
  size_t precomp_digest_length;

  /* TRUE if the RGF has been updated with a digest, FALSE otherwise. */
  Boolean sign_digest;

  /* The hash algorithm, used only for the PKCS1 implicit scheme. */
  SshUInt16 hash_id;

  /* The state context. */
  void *context;
};

SshRGF
ssh_rgf_std_allocate(const SshRGFDefStruct *def);
SshCryptoStatus
ssh_rgf_std_hash_update(SshRGF rgf,
                        Boolean for_digest,
                        const unsigned char *data, size_t data_len);
SshCryptoStatus
ssh_rgf_ignore_hash_update(SshRGF rgf,
                           Boolean for_digest,
                           const unsigned char *data, size_t data_len);
SshCryptoStatus
ssh_rgf_std_hash_finalize(SshRGF rgf, unsigned char **digest,
                          size_t *digest_length);
void ssh_rgf_std_free(SshRGF rgf);


SshCryptoStatus
ssh_rgf_ignore_hash_update(SshRGF rgf,
                           Boolean for_digest,
                           const unsigned char *data, size_t data_len);
SshCryptoStatus
ssh_rgf_ignore_hash_finalize(SshRGF rgf,
                             unsigned char **digest, size_t *digest_length);


SshRGF ssh_rgf_none_allocate(const SshRGFDefStruct *def);
SshCryptoStatus
ssh_rgf_none_hash_update(SshRGF rgf, Boolean for_digest,
                         const unsigned char *data, size_t data_len);
SshCryptoStatus
ssh_rgf_none_hash_finalize(SshRGF rgf,
                           unsigned char **digest, size_t *digest_length);
SshCryptoStatus
ssh_rgf_none_hash_finalize_no_allocate(SshRGF rgf,
                                       unsigned char **digest,
                                       size_t *digest_length);
void ssh_rgf_none_free(SshRGF rgf);


SshCryptoStatus
ssh_rgf_pkcs1_sign(SshRGF rgf,
                   size_t key_size_in_bits,
                   unsigned char **output_msg, size_t *output_msg_len);
SshCryptoStatus ssh_rgf_pkcs1_verify(SshRGF rgf,
                                     size_t key_size_in_bits,
                                     const unsigned char *decrypted_signature,
                                     size_t decrypted_signature_len);
SshCryptoStatus
ssh_rgf_pkcs1_sign_nohash(SshRGF rgf, size_t key_size_in_bits,
                          unsigned char **output_msg, size_t *output_msg_len);
SshCryptoStatus
ssh_rgf_pkcs1_verify_nohash(SshRGF rgf,
                            size_t key_size_in_bits,
                            const unsigned char *decrypted_signature,
                            size_t decrypted_signature_len);

size_t
ssh_rgf_hash_asn1_oid_compare(SshRGF rgf,
                              const unsigned char *oid,
                              size_t max_len);

const unsigned char *
ssh_rgf_hash_asn1_oid_generate(SshRGF rgf, size_t *len);

#endif /* SSHRGF_INTERNAL_H */
