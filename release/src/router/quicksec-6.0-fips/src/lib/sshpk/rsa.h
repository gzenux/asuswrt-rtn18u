/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   RSA key generation, encryption and decryption.
*/

#ifndef RSA_H
#define RSA_H

#include "sshmp.h"

typedef struct
{
  size_t bits;
  SshMPIntegerStruct p, q, e, d, n, u, dp, dq;

  /* A random integer used in the CRT computation to prevent fault attacks.
     We always take r to be prime, so that Euler(r.p) and Euler(r.q) can be
     easily computed.   */
  SshMPIntegerStruct r;

  /* Blinding integers */
  SshMPIntegerStruct b_exp, b_inv;

} SshRSAPrivateKey;

typedef struct
{
  size_t bits;
  SshMPIntegerStruct n, e;
} SshRSAPublicKey;

typedef struct
{
  unsigned int bits;
  SshMPIntegerStruct n, p, q, e, d, u;
} SshRSAInitCtx;

/* Function interface to genpkcs.c */

/* action handling. */

/* Initialization function for generation. And function that will free it. */

SshCryptoStatus ssh_rsa_private_key_init_action(void **context);
SshCryptoStatus ssh_rsa_public_key_init_action(void **context);
void ssh_rsa_private_key_init_ctx_free(void *context);

/* Initialize the blinding integers, i.e. generate a random integer b,
   and compute b_exp = b^e mod n, and b_inv = b^(-1) mod n */
void ssh_rsa_private_key_init_blinding(SshMPInteger b_exp,
                                       SshMPInteger b_inv,
                                       SshMPIntegerConst n,
                                       SshMPIntegerConst e);

/* Generate a random short prime r, and compute the CRT
   exponents dp, dq from the private exponent d, and r.
   Since we choose r to be prime, this computes
   dp = d mod (r-1)(p-1) and dq = d mod (r-1)(q-1) */
void ssh_rsa_private_key_generate_crt_exponents(SshMPInteger dp,
                                                SshMPInteger dq,
                                                SshMPInteger r,
                                                SshMPIntegerConst p,
                                                SshMPIntegerConst q,
                                                SshMPIntegerConst d);

/* Function that makes the private key from information collected from
   vararg list. */
SshCryptoStatus ssh_rsa_private_key_make_action(void *context, void **key_ctx);
SshCryptoStatus ssh_rsa_private_key_define_action(void *context,
                                                  void **key_ctx);
SshCryptoStatus ssh_rsa_private_key_generate_action(void *context,
                                                    void **key_ctx);
SshCryptoStatus ssh_rsa_public_key_make_action(void *context, void **key_ctx);

/* Supported actions for RSA. Adding more actions is easy, but should be
   kept to minimum for ease of maintaining. And to clarity of usage. */

const char *
ssh_rsa_action_private_key_get(void *context, va_list ap,
                               void **output_context,
                               SshPkFormat format);
const char *
ssh_rsa_action_private_key_put(void *context, va_list ap,
                               void *input_context,
                               SshPkFormat format);

const char *
ssh_rsa_action_public_key_get(void *context, va_list ap,
                              void **output_context,
                              SshPkFormat format);
const char *
ssh_rsa_action_public_key_put(void *context, va_list ap,
                              void *input_context,
                              SshPkFormat format);

/* These functions import and export keys. */
SshCryptoStatus ssh_rsa_public_key_import(const unsigned char *buf,
                                          size_t len,
                                          void **public_key);

SshCryptoStatus ssh_rsa_public_key_export(const void *public_key,
                              unsigned char **buf,
                              size_t *length_return);

SshCryptoStatus ssh_rsa_private_key_import(const unsigned char *buf,
                               size_t len,
                               void **private_key);

SshCryptoStatus ssh_rsa_private_key_export(const void *private_key,
                               unsigned char **buf,
                               size_t *lenght_return);

/* Free keys */
void ssh_rsa_public_key_free(void *public_key);

void ssh_rsa_private_key_free(void *private_key);

/* Copying. */
SshCryptoStatus ssh_rsa_public_key_copy(void *op_src, void **op_dest);
SshCryptoStatus ssh_rsa_private_key_copy(void *op_src, void **op_dest);

/* Get maximum buffer lengths needed for specific operations. */
size_t ssh_rsa_public_key_max_encrypt_input_len(const void *public_key,
                                                SshRGF rgf);
size_t ssh_rsa_public_key_max_oaep_encrypt_input_len(const void *public_key,
                                                     SshRGF rgf);
size_t ssh_rsa_public_key_max_none_encrypt_input_len(const void *public_key,
                                                     SshRGF rgf);

size_t ssh_rsa_public_key_max_encrypt_output_len(const void *public_key,
                                                 SshRGF rgf);

size_t ssh_rsa_private_key_max_signature_input_len(const void *private_key,
                                                   SshRGF rgf);
size_t
ssh_rsa_private_key_max_signature_unhash_input_len(const void *private_key,
                                                   SshRGF rgf);

size_t ssh_rsa_private_key_max_signature_output_len(const void *private_key,
                                                    SshRGF rgf);

size_t ssh_rsa_private_key_max_decrypt_input_len(const void *private_key,
                                                 SshRGF rgf);

size_t ssh_rsa_private_key_max_decrypt_output_len(const void *private_key,
                                                  SshRGF rgf);

/* Derive public key from the private key. */
SshCryptoStatus
ssh_rsa_private_key_derive_public_key(const void *private_key,
                                      void **public_key);

/* Encrypt data. */
SshCryptoStatus
ssh_rsa_public_key_encrypt(const void *public_key,
                           const unsigned char *plaintext,
                           size_t plaintext_len,
                           unsigned char *ciphertext_buffer,
                           size_t ssh_buffer_len,
                           size_t *ciphertext_len_return,
                           SshRGF rgf);

SshCryptoStatus
ssh_rsa_private_key_decrypt(const void *private_key,
                            const unsigned char *ciphertext,
                            size_t ciphertext_len,
                            unsigned char *plaintext_buffer,
                            size_t plaintext_buffer_len,
                            size_t *plaintext_length_return,
                            SshRGF rgf);

/* Sign data. */
SshCryptoStatus
ssh_rsa_private_key_sign(const void *private_key,
                         SshRGF rgf,
                         unsigned char *signature_buffer,
                         size_t ssh_buffer_len,
                         size_t *signature_length_return);

/* Verify signature. */
SshCryptoStatus
ssh_rsa_public_key_verify(const void *public_key,
                          const unsigned char *signature,
                          size_t signature_len,
                          SshRGF rgf);

unsigned char *
ssh_rsa_pkcs1v2_default_explicit_param(const char *hash,
                                       size_t *param_len);

SshCryptoStatus
ssh_rsa_mgf1(const char *hash_name,
             const unsigned char *seed, size_t seed_len,
             unsigned char *mask, size_t mask_len);

SshCryptoStatus
ssh_rsa_oaep_decode_with_mgf1(const char *hash,
                              const unsigned char *emsg,
                              size_t emsg_len,
                              const unsigned char *param,
                              size_t param_len,
                              unsigned char **msg, size_t *msg_len);
SshCryptoStatus
ssh_rsa_oaep_encode_with_mgf1(const char *hash,
                              const unsigned char *msg,
                              size_t msg_len,
                              const unsigned char *param,
                              size_t param_len,
                              unsigned char *emsg, size_t emsg_len);


SshCryptoStatus
ssh_rsa_pss_encode_with_mgf1(const char *hash,
                             size_t salt_len,
                             size_t maximal_bit_length,
                             const unsigned char *msg_digest,
                             size_t msg_digest_len,
                             unsigned char *emsg, size_t emsg_len);

SshCryptoStatus
ssh_rsa_pss_decode_with_mgf1(const char *hash,
                             size_t salt_len,
                             size_t maximal_bit_length,
                             const unsigned char *msg_digest,
                             size_t msg_digest_len,
                             const unsigned char *emsg,
                             size_t emsg_len);

SshCryptoStatus
ssh_rsa_make_private_key_of_all(SshMPInteger p, SshMPInteger q,
                                SshMPInteger n, SshMPInteger e,
                                SshMPInteger d, SshMPInteger u,
                                void **key_ctx);

void ssh_rsa_private_key_init(SshRSAPrivateKey *private_key);

#define SSH_RSA_MINIMUM_PADDING 10
#define SSH_RSA_MAX_BYTES       65535

#endif /* RSA_H */
