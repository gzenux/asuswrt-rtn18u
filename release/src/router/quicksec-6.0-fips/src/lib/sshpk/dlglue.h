/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete logarithms based public key routines.

   Note: this interface was not deviced to be called directly from
   applications. It is hard to use by standard applications. One
   should use the general interface, which is much more easier and as
   basically fast.
*/

#ifndef DLGLUE_H
#define DLGLUE_H

/* Action routines. */
const char *
ssh_dlp_action_private_key_put(void *context, va_list ap,
                               void *input_context,
                               SshPkFormat format);
const char *
ssh_dlp_action_private_key_get(void *context, va_list ap,
                               void **output_context,
                               SshPkFormat format);

const char *
ssh_dlp_action_public_key_put(void *context, va_list ap,
                              void *input_context,
                              SshPkFormat format);
const char *
ssh_dlp_action_public_key_get(void *context, va_list ap,
                              void **output_context,
                              SshPkFormat format);

const char *
ssh_dlp_action_param_put(void *context, va_list ap,
                         void *input_context,
                         SshPkFormat format);
const char *
ssh_dlp_action_param_get(void *context, va_list ap,
                         void **output_context,
                         SshPkFormat format);

/* Control of the action context. */
SshCryptoStatus ssh_dlp_action_init(void **context);
SshCryptoStatus ssh_dlp_action_public_key_init(void **context);

SshCryptoStatus ssh_dlp_param_action_make(void *context, void **param_ctx);
SshCryptoStatus ssh_dlp_private_key_action_define(void *context,
                                                  void **key_ctx);
/* Generates a key with subgroup size 160 bits. */
SshCryptoStatus ssh_dlp_private_key_action_generate_dsa_std(void *context,
                                                            void **key_ctx);
SshCryptoStatus ssh_dlp_private_key_action_generate_dsa_fips(void *context,
                                                             void **key_ctx);

/* Generates a key with subgroup size half that of the group size. */
SshCryptoStatus ssh_dlp_private_key_action_generate_std(void *context,
                                                        void **key_ctx);
SshCryptoStatus ssh_dlp_public_key_action_make(void *context,
                                               void **key_ctx);

void ssh_dlp_action_free(void *context);

/* Handle parameters. */
SshCryptoStatus ssh_dlp_param_import(const unsigned char *buf, size_t len,
                                     void **parameters);
SshCryptoStatus ssh_dlp_param_export(const void *parameters,
                                     unsigned char **buf,
                                     size_t *length_return);
void ssh_dlp_param_free(void *parameters);
SshCryptoStatus ssh_dlp_param_copy(void *param_src, void **param_dest);
char *ssh_dlp_param_get_predefined_groups(void);

/* Precomputation. */
SshCryptoStatus ssh_dlp_param_precompute(void *context);
SshCryptoStatus ssh_dlp_public_key_precompute(void *context);
SshCryptoStatus ssh_dlp_private_key_precompute(void *context);

/* Randomizer control. */
unsigned int ssh_dlp_param_count_randomizers(void *parameters);
void ssh_dlp_param_return_randomizer(void *parameters,
                                     SshPkGroupDHSecret secret,
                                     const unsigned char *exchange_buf,
                                     size_t exchange_buf_len);
SshCryptoStatus ssh_dlp_param_generate_randomizer(void *parameters);
SshCryptoStatus ssh_dlp_param_export_randomizer(void *parameters,
                                                unsigned char **buf,
                                                size_t *length_return);
SshCryptoStatus ssh_dlp_param_import_randomizer(void *parameters,
                                                const unsigned char *buf,
                                                size_t length);

/* Basic public key functions. */
SshCryptoStatus ssh_dlp_public_key_import(const unsigned char *buf,
                                          size_t len,
                                          void **public_key);
SshCryptoStatus ssh_dlp_public_key_export(const void *public_key,
                                          unsigned char **buf,
                                          size_t *length_return);
void ssh_dlp_public_key_free(void *public_key);
SshCryptoStatus ssh_dlp_public_key_copy(void *key_src, void **key_dest);
SshCryptoStatus ssh_dlp_public_key_derive_param(void *public_key,
                                                void **parameters);

/* Basic private key functions. */
SshCryptoStatus ssh_dlp_private_key_import(const unsigned char *buf,
                                           size_t len,
                                           void **private_key);
SshCryptoStatus ssh_dlp_private_key_export(const void *private_key,
                                           unsigned char **buf,
                                           size_t *length_return);
void ssh_dlp_private_key_free(void *private_key);
SshCryptoStatus ssh_dlp_private_key_derive_public_key(const void *private_key,
                                                      void **public_key);
SshCryptoStatus ssh_dlp_private_key_copy(void *key_src, void **key_dest);
SshCryptoStatus ssh_dlp_private_key_derive_param(void *private_key,
                                                 void **parameters);

/* Signature methods. */

size_t
ssh_dlp_dsa_private_key_max_signature_input_len(const void *private_key,
                                                SshRGF rgf);
size_t
ssh_dlp_dsa_private_key_max_signature_output_len(const void *private_key,
                                                 SshRGF rgf);
SshCryptoStatus
ssh_dlp_dsa_private_key_sign_std(const void *private_key,
                                 SshRGF rgf,
                                 unsigned char *signature_buffer,
                                 size_t ssh_buffer_len,
                                 size_t *signature_length_return);
SshCryptoStatus
ssh_dlp_dsa_private_key_sign_fips(const void *private_key,
                                  SshRGF rgf,
                                  unsigned char *signature_buffer,
                                  size_t ssh_buffer_len,
                                  size_t *signature_length_return);

SshCryptoStatus
ssh_dlp_dsa_public_key_verify(const void *public_key,
                              const unsigned char *signature,
                              size_t signature_len,
                              SshRGF rgf);


/* Encryption methods. */

/* Diffie-Hellman. */

size_t
ssh_dlp_diffie_hellman_exchange_length(const void *parameters);
size_t
ssh_dlp_diffie_hellman_shared_secret_length(const void *parameters);
SshCryptoStatus
ssh_dlp_diffie_hellman_generate(const void *parameters,
                                SshPkGroupDHSecret *secret,
                                unsigned char *exchange,
                                size_t exchange_length,
                                size_t *return_length);
SshCryptoStatus
ssh_dlp_diffie_hellman_final(const void *parameters,
                             SshPkGroupDHSecret secret,
                             const unsigned char *exchange,
                             size_t exchange_length,
                             unsigned char *secret_buffer,
                             size_t secret_buffer_length,
                             size_t *return_length);


#endif /* DLGLUE.H */
