/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Glue code for ecp functions.

   Note: this interface was not deviced to be called directly from
   applications. It is hard to use by standard applications. One should
   use the general interface, which is much more easier and as
   basically fast.
*/

#ifndef ECPGLUE_H
#define ECPGLUE_H

/********************* Action Routines **********************/

const char *
ssh_ecp_action_private_key_put(void *context, va_list ap,
                               void *input_context,
                               SshPkFormat format);
const char *
ssh_ecp_action_private_key_get(void *context, va_list ap,
                               void **output_context,
                               SshPkFormat format);

const char *
ssh_ecp_action_public_key_put(void *context, va_list ap,
                              void *input_context,
                              SshPkFormat format);
const char *
ssh_ecp_action_public_key_get(void *context, va_list ap,
                              void **output_context,
                              SshPkFormat format);

const char *
ssh_ecp_action_param_put(void *context, va_list ap,
                         void *input_context,
                         SshPkFormat format);
const char *
ssh_ecp_action_param_get(void *context, va_list ap,
                         void **output_context,
                         SshPkFormat format);

/* Control of the action context. */
SshCryptoStatus ssh_ecp_action_init(void **context);
SshCryptoStatus ssh_ecp_action_public_key_init(void **context);
SshCryptoStatus ssh_ecp_param_action_make(void *context, void **key_ctx);
SshCryptoStatus ssh_ecp_private_key_action_make(void *context, void **key_ctx);
SshCryptoStatus ssh_ecp_public_key_action_make(void *context, void **key_ctx);

void ssh_ecp_action_free(void *context);

/************** Discrete Logarithm Key Control **************/

SshCryptoStatus ssh_ecp_param_import(const unsigned char *buf,
                                     size_t len,
                                     void **parameters);

SshCryptoStatus ssh_ecp_param_export(const void *parameters,
                                     unsigned char **buf,
                                     size_t *length_return);

void ssh_ecp_param_free(void *parameters);
SshCryptoStatus ssh_ecp_param_copy(void *param_src, void **param_dest);
char *ssh_ecp_param_get_predefined_groups(void);

/* Randomizer control. */
unsigned int ssh_ecp_param_count_randomizers(void *parameters);
SshCryptoStatus ssh_ecp_param_generate_randomizer(void *parameters);
SshCryptoStatus ssh_ecp_param_export_randomizer(void *parameters,
                                                unsigned char **buf,
                                                size_t *length_return);
SshCryptoStatus ssh_ecp_param_import_randomizer(void *parameters,
                                                const unsigned char *buf,
                                                size_t length);

/* Import public key blob and get a valid public key. */

SshCryptoStatus ssh_ecp_public_key_import(const unsigned char *buf,
                                          size_t len,
                                          void **public_key);

/* Export a public key. Outputs a dynamically allocated blob that must be
   freed with ssh_xfree. */

SshCryptoStatus ssh_ecp_public_key_export(const void *public_key,
                                          unsigned char **buf,
                                          size_t *length_return);

/* Free initialized public key. */

void ssh_ecp_public_key_free(void *public_key);
SshCryptoStatus ssh_ecp_public_key_copy(void *key_src, void **key_dest);
SshCryptoStatus ssh_ecp_public_key_derive_param(void *public_key,
                                                void **parameters);

/* Import private key. Outputs the private key object. */

SshCryptoStatus ssh_ecp_private_key_import(const unsigned char *buf,
                                           size_t len,
                                           void **private_key);

/* Export private key. Given a private key object it output dynamically
   allocated blob that is to be freed with ssh_xfree. */

SshCryptoStatus ssh_ecp_private_key_export(const void *private_key,
                                           unsigned char **buf,
                                           size_t *lenght_return);

/* Free private key object. */

void ssh_ecp_private_key_free(void *private_key);
SshCryptoStatus ssh_ecp_private_key_copy(void *key_src, void **key_dest);
SshCryptoStatus ssh_ecp_private_key_derive_param(void *private_key,
                                                 void **parameters);

/* Derive public key from private key object. */

SshCryptoStatus ssh_ecp_private_key_derive_public_key(const void *private_key,
                                                      void **public_key);

/********************** Schemes ***********************/

/* DSA Signature only scheme */

/* Verify given signature. */
SshCryptoStatus
ssh_ecp_dsa_public_key_verify(const void *public_key,
                              const unsigned char *signature,
                              size_t signature_len,
                              SshRGF rgf);

/* Get the lengths of the signature input and output buffers. */

size_t
ssh_ecp_dsa_private_key_max_signature_input_len(const void *private_key,
                                                SshRGF rgf);

size_t
ssh_ecp_dsa_private_key_max_signature_output_len(const void *private_key,
                                                 SshRGF rgf);

/* Sign a given data buffer. */
SshCryptoStatus
ssh_ecp_dsa_private_key_sign(const void *private_key,
                             SshRGF rgf,
                             unsigned char *signature_buffer,
                             size_t ssh_buffer_len,
                             size_t *signature_length_return);

/* Diffie-Hellman. */

size_t
ssh_ecp_diffie_hellman_exchange_length(const void *parameters);
size_t
ssh_ecp_diffie_hellman_shared_secret_length(const void *parameters);

SshCryptoStatus
ssh_ecp_diffie_hellman_generate(const void *parameters,
                                SshPkGroupDHSecret *secret,
                                unsigned char *exchange,
                                size_t exchange_length,
                                size_t *return_length);
SshCryptoStatus
ssh_ecp_diffie_hellman_final(const void *parameters,
                             SshPkGroupDHSecret secret,
                             const unsigned char *exchange,
                             size_t exchange_length,
                             unsigned char *secret_buffer,
                             size_t secret_buffer_length,
                             size_t *return_length);


#endif /* ECPGLUE_H */
