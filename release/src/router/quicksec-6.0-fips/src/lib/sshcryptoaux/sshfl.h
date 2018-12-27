/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_FL_H
#define SSH_FL_H

#include "sshincludes.h"
#include "sshproxykey.h"
#include <fl.h>

#define SSH_FL_ASSETALLOCATE(rv, w, x, y, z)                         \
  do                                                                 \
    {                                                                \
      rv = FL_AssetAllocate(w, x, y, z);                             \
      SSH_DEBUG(SSH_D_LOWOK, ("FL_AssetAllocate %x allocated", *z)); \
    } while(0);

#define SSH_FL_ASSETALLOCATEBASIC(rv, x, y, z)                              \
  do                                                                        \
    {                                                                       \
      rv = FL_AssetAllocateBasic(x, y, z);                                  \
      SSH_DEBUG(SSH_D_LOWOK, ("FL_AssetAllocateBasic %x allocated", *z));   \
    } while(0);

#define SSH_FL_ASSETFREE(x)                                 \
  do                                                        \
    {                                                       \
      SSH_DEBUG(SSH_D_LOWOK, ("FL_AssetFree %x", x));       \
      (void) FL_AssetFree(x);                               \
    } while(0);

#define SSH_FL_ASSETFREE2(rv, x)                            \
  do                                                        \
    {                                                       \
      SSH_DEBUG(SSH_D_LOWOK, ("FL_AssetFree %x", x));       \
      rv = FL_AssetFree(x);                                 \
    } while(0);

#define SSH_FL_ALLOCATE_STATE(rv, x)                                        \
  do                                                                        \
    {                                                                       \
      rv = FL_ALLOCATE_STATE(x);                                            \
      SSH_DEBUG(SSH_D_LOWOK, ("FL_AssetAllocateBasic %x allocated", *x));   \
    } while(0);

/* Return plaintext string describing the FIPS-library return
   value. */
const char *ssh_fl_rv_to_string(FL_RV rv);

/* Free private key context */
void ssh_fl_private_key_free(void *context);

/* Free public key context */
void ssh_fl_public_key_free(void *context);

/* Free group context */
void ssh_fl_group_free(void *context);

/* Return signature output size for this key context. */
size_t ssh_fl_signature_size(void *context);

/* Make RSA private key of given parameters. Returns a context
   pointer that should be used in key operations and NULL if
   operation failed. */
void *ssh_fl_rsa_private_key_make(unsigned char *p_buf,
                                  size_t p_size,
                                  unsigned char *q_buf,
                                  size_t q_size,
                                  unsigned char *dp_buf,
                                  size_t dp_size,
                                  unsigned char *dq_buf,
                                  size_t dq_size,
                                  unsigned char *q_inv_buf,
                                  size_t q_inv_size,
                                  unsigned int key_size_in_bits);

/* Make DSA private key of given parameters. Returns a context
   pointer that should be used in key operations and NULL if
   operation failed. */
void *ssh_fl_dsa_private_key_make(unsigned char *p_buf,
                                  size_t p_size,
                                  unsigned char *q_buf,
                                  size_t q_size,
                                  unsigned char *g_buf,
                                  size_t g_size,
                                  unsigned char *x_buf,
                                  size_t x_size,
                                  unsigned int key_size_in_bits);

/* Make ECDSA private key of given parameters. Returns a context
   pointer that should be used in key operations and NULL if
   operation failed. */
void *ssh_fl_ecdsa_private_key_make(unsigned char *x_buf,
                                    size_t x_size,
                                    unsigned int key_size_in_bits);

/* Make RSA public key of given parameters. Returns a context
   pointer that should be used in key operations and NULL if
   operation failed. */
void *ssh_fl_rsa_public_key_make(unsigned char *e_buf,
                                 size_t e_size,
                                 unsigned char *m_buf,
                                 size_t m_size,
                                 unsigned int e_size_in_bits,
                                 unsigned int m_size_in_bits);

/* Make DSA public key of given parameters. Returns a context
   pointer that should be used in key operations and NULL if
   operation failed. */
void *ssh_fl_dsa_public_key_make(unsigned char *p_buf,
                                 size_t p_size,
                                 unsigned char *q_buf,
                                 size_t q_size,
                                 unsigned char *g_buf,
                                 size_t g_size,
                                 unsigned char *y_buf,
                                 size_t y_size);

/* Make ECDSA public key of given parameters. Returns a context
   pointer that should be used in key operations and NULL if
   operation failed. */
void *ssh_fl_ecdsa_public_key_make(unsigned char *qx_buf,
                                   size_t qx_size,
                                   unsigned char *qy_buf,
                                   size_t qy_size,
                                   unsigned int key_size_in_bits);

/* Perform private key signing operation with key context. Required
   size of output_buffer is returned by ssh_fl_signature_size() */
SshCryptoStatus
ssh_fl_private_key_sign(SshProxyOperationId operation_id,
                        SshProxyRGFId rgf_id,
                        const unsigned char *input_data,
                        size_t input_data_len,
                        unsigned char *output_buffer,
                        size_t output_buffer_len,
                        void *context);

/* Perform public key verify operation with key context. */
SshCryptoStatus
ssh_fl_public_key_verify(SshProxyOperationId operation_id,
                         SshProxyRGFId rgf_id,
                         const unsigned char *input_data,
                         size_t input_data_len,
                         unsigned char *signature_data,
                         size_t signature_data_len,
                         void *context);

/* Make DL group of given parameters. Returns a context
   pointer that should be used in group operations and NULL if
   operation failed. */
void *ssh_fl_dl_group_make(unsigned char *p_buf,
                           size_t p_size,
                           unsigned char *q_buf,
                           size_t q_size,
                           unsigned char *g_buf,
                           size_t g_size);

/* Make EC group of given parameters. Returns a context
   pointer that should be used in group operations and NULL if
   operation failed. */
void *ssh_fl_ec_group_make(unsigned int group_bitlen);

/* Returns size of exchange buffer of this group */
size_t
ssh_fl_group_exchange_size(void *context);

/* Returns size of shared secret buffer of this group */
size_t
ssh_fl_group_shared_secret_size(void *context);

/* Setup group and set exchange_buffer value. Local secret is stored
   to the context */
SshCryptoStatus
ssh_fl_group_dh_setup(unsigned char *exchange_buffer,
                      size_t exchange_buffer_len,
                      void *context);

/* Run group operation and store the shared buffer.

   @local_exchange_buffer is used to find the correct local secret
   to be used in this agreement.
*/
SshCryptoStatus
ssh_fl_group_dh_agree(unsigned char *remote_exchange_buffer,
                      size_t remote_exchange_buffer_len,
                      unsigned char *local_exchange_buffer,
                      size_t local_exchange_buffer_len,
                      unsigned char *shared_buffer,
                      size_t shared_buffer_len,
                      void *context);

#endif /* SSH_FL_H */
