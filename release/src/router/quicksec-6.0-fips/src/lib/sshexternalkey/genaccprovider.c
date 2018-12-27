/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implemenation of a generic accelerator provider (only the modular
   exponentation operation is accelerated).
*/

#include "sshincludes.h"
#include "sshmiscstring.h"
#include "sshencode.h"
#include "sshtimeouts.h"
#include "genaccprovider.h"
#include "genaccprovideri.h"
#include "genaccdevicei.h"
#include "genaccprov.h"
#include "sshproxykey.h"
#include "sshcryptoaux.h"
#include "sshgenmp.h"

#define SSH_DEBUG_MODULE "SshEKGenaccProv"

#define KEY_SIZE_TO_BYTES(x) ((((x) + 7) >> 3))

/* *****************************************************************   */

/* Functions for reading key information into some context which will
   be passed to the accelerated key object. */

static Boolean
get_rsa_prvkey_info(SshPrivateKey key, SshRSAPrivateKeyInfo rsa_info)
{
  char *key_type = NULL;
  SshRSAPrivateKeyInfo rsa = rsa_info;

  SSH_ASSERT(rsa != NULL);

  /* Check that the key is really a RSA key.  */
  if ((ssh_private_key_get_info(key,
                                SSH_PKF_KEY_TYPE, &key_type,
                                SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the private key type"));
      return FALSE;
    }
  if (key_type == NULL)
    return FALSE;

  if (strcmp(key_type, "if-modn"))
    return FALSE;

  ssh_mprz_init(&rsa->d);
  ssh_mprz_init(&rsa->n);
  ssh_mprz_init(&rsa->p);
  ssh_mprz_init(&rsa->q);
  ssh_mprz_init(&rsa->u);
  ssh_mprz_init(&rsa->dp);
  ssh_mprz_init(&rsa->dq);

  if ((ssh_private_key_get_info(key,
                                SSH_PKF_PRIME_P,   &rsa->p,
                                SSH_PKF_PRIME_Q,   &rsa->q,
                                SSH_PKF_INVERSE_U, &rsa->u,
                                SSH_PKF_SECRET_D,  &rsa->d,
                                SSH_PKF_MODULO_N,  &rsa->n,
                                SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the private key info"));
      ssh_mprz_clear(&rsa->d);
      ssh_mprz_clear(&rsa->n);
      ssh_mprz_clear(&rsa->p);
      ssh_mprz_clear(&rsa->q);
      ssh_mprz_clear(&rsa->u);
      ssh_mprz_clear(&rsa->dp);
      ssh_mprz_clear(&rsa->dq);
      return FALSE;
    }

  /* Compute dp = d mod p-1. */
  ssh_mprz_sub_ui(&rsa->dp, &rsa->p, 1);
  ssh_mprz_mod(&rsa->dp, &rsa->d, &rsa->dp);

  /* Compute dq = d mod q-1. */
  ssh_mprz_sub_ui(&rsa->dq, &rsa->q, 1);
  ssh_mprz_mod(&rsa->dq, &rsa->d, &rsa->dq);

  return TRUE;
}

/* Read specific info about a SshPublicKey into the SshRSAPublicKeyInfo
   object. */
static Boolean
get_rsa_pubkey_info(SshPublicKey key, SshRSAPublicKeyInfo rsa_info)
{
  char *key_type = NULL;
  SshRSAPublicKeyInfo rsa = rsa_info;

  SSH_ASSERT(rsa != NULL);

  /* Check that the key is really a RSA key  */
  if ((ssh_public_key_get_info(key,
                               SSH_PKF_KEY_TYPE, &key_type,
                               SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the public key type"));
      return FALSE;
    }
  if (key_type == NULL)
    return FALSE;

  if (strcmp(key_type, "if-modn"))
    return FALSE;

  ssh_mprz_init(&rsa->e);
  ssh_mprz_init(&rsa->n);

  if ((ssh_public_key_get_info(key,
                               SSH_PKF_MODULO_N, &rsa->n,
                               SSH_PKF_PUBLIC_E, &rsa->e,
                               SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the public key info"));
      ssh_mprz_clear(&rsa->e);
      ssh_mprz_clear(&rsa->n);
      return FALSE;
    }

  return TRUE;
}

/* Read specific info about a SshPrivateKey into the SshDSAPrivateKeyInfo
   object. */
static Boolean
get_dsa_prvkey_info(SshPrivateKey key, SshDSAPrivateKeyInfo dsa_info)
{
  char *key_type = NULL;
  unsigned int entropy = 0;
  SshDSAPrivateKeyInfo dsa = dsa_info;

  SSH_ASSERT(dsa != NULL);

  /* Check that the key is really a DSA key.  */
  if ((ssh_private_key_get_info(key,
                                SSH_PKF_KEY_TYPE, &key_type,
                                SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the private key type"));
      return FALSE;
    }
  if (key_type == NULL)
    return FALSE;

  if (strcmp(key_type, "dl-modp"))
    return FALSE;

  ssh_mprz_init(&dsa->p);
  ssh_mprz_init(&dsa->q);
  ssh_mprz_init(&dsa->g);
  ssh_mprz_init(&dsa->x);

  if ((ssh_private_key_get_info(key,
                                SSH_PKF_PRIME_P,     &dsa->p,
                                SSH_PKF_PRIME_Q,     &dsa->q,
                                SSH_PKF_GENERATOR_G, &dsa->g,
                                SSH_PKF_SECRET_X,    &dsa->x,
                                SSH_PKF_RANDOMIZER_ENTROPY, &entropy,
                                SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the private key info"));
      ssh_mprz_clear(&dsa->p);
      ssh_mprz_clear(&dsa->q);
      ssh_mprz_clear(&dsa->g);
      ssh_mprz_clear(&dsa->x);

      return FALSE;
    }

  dsa->exponent_entropy = entropy;

  return TRUE;
}

/* Read specific info about a SshPublicKey into the
   SshDSAPublicKeyInfo object. */
static Boolean
get_dsa_pubkey_info(SshPublicKey key, SshDSAPublicKeyInfo dsa_info)
{
  char *key_type = NULL;
  unsigned int entropy = 0;
  SshDSAPublicKeyInfo dsa = dsa_info;

  SSH_ASSERT(dsa != NULL);

  /* Check that the key is really a DSA key.  */
  if ((ssh_public_key_get_info(key,
                               SSH_PKF_KEY_TYPE, &key_type,
                               SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the public key type"));
      return FALSE;
    }
  if (key_type == NULL)
    return FALSE;

  if (strcmp(key_type, "dl-modp"))
    return FALSE;

  ssh_mprz_init(&dsa->p);
  ssh_mprz_init(&dsa->q);
  ssh_mprz_init(&dsa->g);
  ssh_mprz_init(&dsa->y);

  if ((ssh_public_key_get_info(key,
                               SSH_PKF_PRIME_P,     &dsa->p,
                               SSH_PKF_PRIME_Q,     &dsa->q,
                               SSH_PKF_GENERATOR_G, &dsa->g,
                               SSH_PKF_PUBLIC_Y,    &dsa->y,
                               SSH_PKF_RANDOMIZER_ENTROPY, &entropy,
                               SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the public key info"));
      ssh_mprz_clear(&dsa->p);
      ssh_mprz_clear(&dsa->q);
      ssh_mprz_clear(&dsa->g);
      ssh_mprz_clear(&dsa->y);

      return FALSE;
    }

  dsa->exponent_entropy = entropy;

  return TRUE;
}

/* Read specific info about a SshPkGroup into the SshRSAGroupInfo object. */
static Boolean
get_pk_group_info(SshPkGroup group, SshDHGroupInfo dh_info)

{
  char *group_type = NULL;
  unsigned int group_size = 0, entropy = 0;
  SshMPIntegerStruct aux;
  SshDHGroupInfo dh = dh_info;

  SSH_ASSERT(dh != NULL);

  /* Check that the group is really a dl-modp group. */
  if ((ssh_pk_group_get_info(group,
                             SSH_PKF_KEY_TYPE, &group_type,
                             SSH_PKF_SIZE, &group_size,
                             SSH_PKF_RANDOMIZER_ENTROPY, &entropy,
                             SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the pk group type"));
      return FALSE;
    }
  if (group_type == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Group type not known"));
      return FALSE;
    }

  if (strcmp(group_type, "dl-modp"))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid group type '%s', expected 'dl-modp'", group_type));
      return FALSE;
    }

  /* Set the exponent entropy. */
  dh->exponent_entropy = entropy;

  /* We pass the SshMPInteger group  parameters. */
  dh->predefined = FALSE;
  dh->group_name = NULL;

  ssh_mprz_init(&aux);
  ssh_mprz_init(&dh->p);
  ssh_mprz_init(&dh->q);
  ssh_mprz_init(&dh->g);

  if ((ssh_pk_group_get_info(group,
                             SSH_PKF_PRIME_P,     &dh->p,
                             SSH_PKF_PRIME_Q,     &dh->q,
                             SSH_PKF_GENERATOR_G, &dh->g,
                             SSH_PKF_END))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not extract the group info"));
      ssh_mprz_clear(&dh->p);
      ssh_mprz_clear(&dh->q);
      ssh_mprz_clear(&dh->g);
      return FALSE;
    }

  dh->group_size = ssh_mprz_bit_size(&dh->p);

  /* Encode the integer p-1 to buffer. */
  ssh_mprz_sub_ui(&aux, &dh->p, 1);

  dh->p_minus1_len = ssh_mprz_byte_size(&dh->p);
  if ((dh->p_minus1 = ssh_calloc(1, dh->p_minus1_len)) == NULL)
    {
      ssh_mprz_clear(&dh->p);
      ssh_mprz_clear(&dh->q);
      ssh_mprz_clear(&dh->g);
      ssh_mprz_clear(&aux);

      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      return FALSE;
    }

  ssh_mprz_get_buf(dh->p_minus1, dh->p_minus1_len, &aux);
  ssh_mprz_clear(&aux);
  return TRUE;
}

/* The following callbacks are used to free the key material */

static void free_rsa_prv_info(SshRSAPrivateKeyInfo rsa_info)
{
  SshRSAPrivateKeyInfo rsa = rsa_info;

  ssh_mprz_clear(&rsa->d);
  ssh_mprz_clear(&rsa->n);
  ssh_mprz_clear(&rsa->p);
  ssh_mprz_clear(&rsa->q);
  ssh_mprz_clear(&rsa->u);
  ssh_mprz_clear(&rsa->dp);
  ssh_mprz_clear(&rsa->dq);
}

static void free_rsa_pub_info(SshRSAPublicKeyInfo rsa_info)
{
  SshRSAPublicKeyInfo rsa = rsa_info;

  ssh_mprz_clear(&rsa->e);
  ssh_mprz_clear(&rsa->n);
}

static void free_dsa_prv_info(SshDSAPrivateKeyInfo dsa_info)
{
  SshDSAPrivateKeyInfo dsa = dsa_info;

  ssh_mprz_clear(&dsa->p);
  ssh_mprz_clear(&dsa->q);
  ssh_mprz_clear(&dsa->g);
  ssh_mprz_clear(&dsa->x);
}

static void free_dsa_pub_info(SshDSAPublicKeyInfo dsa_info)
{
  SshDSAPublicKeyInfo dsa = dsa_info;

  ssh_mprz_clear(&dsa->p);
  ssh_mprz_clear(&dsa->q);
  ssh_mprz_clear(&dsa->g);
  ssh_mprz_clear(&dsa->y);
}

static void free_ecdsa_prv_info(SshECDSAPrivateKeyInfo ecdsa_info)
{
  SshECDSAPrivateKeyInfo ecdsa = ecdsa_info;

  ssh_mprz_clear(&ecdsa->px);
  ssh_mprz_clear(&ecdsa->py);
  ssh_mprz_clear(&ecdsa->x);
}

static void free_dh_group_info(SshDHGroupInfo dh_info)
{
  SshDHGroupInfo dh = dh_info;

  ssh_mprz_clear(&dh->p);
  ssh_mprz_clear(&dh->q);
  ssh_mprz_clear(&dh->g);
  ssh_free(dh->p_minus1);
}


/* The following callbacks are passed to the relevant proxykey create
   function, and are called by the crypto library when the key is freed.

   This is called in the crypto library, by ssh_private_key_free. */
void ssh_rsa_prvkey_free_op(void *context)
{
  SshAccKey key = context;

  if (!key)
    return;

  free_rsa_prv_info(&key->u.rsa_prv);
  ssh_free(key);
}

/* This is called in the crypto library, by ssh_public_key_free. */
void ssh_rsa_pubkey_free_op(void *context)
{
  SshAccKey key = context;

  if (!key)
    return;

  free_rsa_pub_info(&key->u.rsa_pub);
  ssh_free(key);
}

/* This callback is called in the crypto library,
   by ssh_private_key_free(). */
void ssh_dsa_prvkey_free_op(void *context)
{
  SshAccKey key = context;

  if (!key)
    return;

  free_dsa_prv_info(&key->u.dsa_prv);
  ssh_free(key);
}


/* This callback is called in the crypto library,
   by ssh_public_key_free(). */
void ssh_dsa_pubkey_free_op(void *context)
{
  SshAccKey key = context;

  if (!key)
    return;

  free_dsa_pub_info(&key->u.dsa_pub);
  ssh_free(key);
}

/* This callback is called in the crypto library,
   by ssh_private_key_free(). */
void ssh_ecdsa_prvkey_free_op(void *context)
{
  SshAccKey key = context;

  if (!key)
    return;

  free_ecdsa_prv_info(&key->u.ecdsa_prv);
  ssh_free(key);
}


/* This callback is called in the crypto library,
   by ssh_pk_group_free(). */
void ssh_dh_group_free_op(void *context)
{
  SshAccKey key = context;

  if (!key)
    return;

  free_dh_group_info(&key->u.dh_group);
  ssh_free(key);
}


/* Now define operation callbacks that do the public and private key
   operations and are passed as arguments to the proxykey create functions. */

/************** RSA private key operation with CRT ***************/

typedef struct
{
  Boolean sign_op;
  SshProxyRGFId rgf_id;
  size_t key_size;

  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;

  SshAccDevice device;
  SshRSAPrivateKeyInfo keyinfo;
  SshProxyReplyCB reply_cb;
  void *reply_context;

  SshMPIntegerStruct input;
  SshMPIntegerStruct p2;
  SshMPIntegerStruct q2;

  /* Set to TRUE when the operation is completed. */
  Boolean finished;

  /* TRUE if the RSA CRT operation is performed in the device. */
  Boolean crt_in_device;
} *SshRSAPrivateContext, SshRSAPrivateContextStruct;


void ssh_rsa_prvkey_op_continue(SshCryptoStatus status,
                                const unsigned char *operated_data,
                                size_t data_len,
                                void *reply_context);
void ssh_rsa_prvkey_op_done(SshCryptoStatus status,
                            const unsigned char *operated_data,
                            size_t data_len,
                            void *reply_context);

static void free_prvkey_operation(void *context)
{
  SshRSAPrivateContext rsa_ctx = context;
  ssh_free(rsa_ctx);
}

void ssh_rsa_prvkey_op_abort(void *context)
{
  SshRSAPrivateContext rsa_ctx = context;

  ssh_operation_abort(rsa_ctx->sub_op);
  ssh_mprz_clear(&rsa_ctx->input);

  if (rsa_ctx->crt_in_device == FALSE)
    {
      ssh_mprz_clear(&rsa_ctx->p2);
      ssh_mprz_clear(&rsa_ctx->q2);
    }

  /* Free the structure from a zero timeout to ensure that
     rsa_ctx->finished is still valid when referenced when returning
     from ssh_rsa_prvkey_op. */
  ssh_register_timeout(NULL, 0, 0, free_prvkey_operation, rsa_ctx);
}

void ssh_rsa_prvkey_op_free(void *context)
{
  SshRSAPrivateContext rsa_ctx = context;

  rsa_ctx->finished = TRUE;

  ssh_operation_unregister(rsa_ctx->op);
  ssh_rsa_prvkey_op_abort(rsa_ctx);
}

/* The ProxyKeyOpCB for RSA private key operations. */
SshOperationHandle
ssh_rsa_prvkey_op(Boolean sign_op,
                  SshProxyRGFId rgf_id,
                  const unsigned char *data,
                  size_t data_len,
                  SshProxyReplyCB reply_cb,
                  void *reply_context,
                  void *context)
{
  SshOperationHandle sub_op;
  SshRSAPrivateContext rsa_ctx;
  SshAccKey key;
  SshCryptoStatus status;
  unsigned char *digest = NULL;
  size_t digest_len;

  key = (SshAccKey)context;

  if ((rsa_ctx = ssh_calloc(1, sizeof(*rsa_ctx))) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* Hash and pad the data before signing. */
  if (sign_op)
    {
      if ((status = ssh_proxy_key_rgf_sign(SSH_RSA_PRV_SIGN,
                                           rgf_id,
                                           key->key_size,
                                           data,
                                           data_len,
                                           &digest,
                                           &digest_len)) != SSH_CRYPTO_OK)
        {
          (*reply_cb)(status, NULL, 0, reply_context);
          ssh_free(rsa_ctx);
          return NULL;
        }
    }

  rsa_ctx->rgf_id = rgf_id;
  rsa_ctx->sign_op = sign_op;
  rsa_ctx->key_size = key->key_size;
  rsa_ctx->keyinfo = &key->u.rsa_prv;
  rsa_ctx->device =  key->device;
  rsa_ctx->reply_cb = reply_cb;
  rsa_ctx->reply_context = reply_context;

  ssh_mprz_init(&rsa_ctx->p2);
  ssh_mprz_init(&rsa_ctx->q2);
  ssh_mprz_init(&rsa_ctx->input);

  if (digest)
    {
      ssh_mprz_set_buf(&rsa_ctx->input, digest, digest_len);
      ssh_free(digest);
    }
  else
    {
      ssh_mprz_set_buf(&rsa_ctx->input, data, data_len);
    }

  /* Try to do the full RSA CRT operation in hardware */
  rsa_ctx->crt_in_device = TRUE;
  ssh_operation_register_no_alloc(rsa_ctx->op,
                                  ssh_rsa_prvkey_op_abort, rsa_ctx);

  sub_op = ssh_acc_device_rsa_crt_op(rsa_ctx->device,
                                     &rsa_ctx->input,
                                     &rsa_ctx->keyinfo->p,
                                     &rsa_ctx->keyinfo->q,
                                     &rsa_ctx->keyinfo->dp,
                                     &rsa_ctx->keyinfo->dq,
                                     &rsa_ctx->keyinfo->u,
                                     ssh_rsa_prvkey_op_done,
                                     rsa_ctx);

  if (sub_op)

    rsa_ctx->sub_op = sub_op;

  return rsa_ctx->finished ? NULL: rsa_ctx->op;
}

void ssh_rsa_prvkey_op_continue(SshCryptoStatus status,
                                const unsigned char *operated_data,
                                size_t data_len,
                                void *reply_context)
{
  SshOperationHandle sub_op;
  SshRSAPrivateContext rsa_ctx = reply_context;

  rsa_ctx->sub_op = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      (*rsa_ctx->reply_cb)(status, NULL, 0, rsa_ctx->reply_context);

      ssh_rsa_prvkey_op_free(rsa_ctx);
      return;
    }

  ssh_mprz_set_buf(&rsa_ctx->p2, operated_data, data_len);

  /* Compute q2 = (input mod q) ^ dq mod q. */
  ssh_mprz_mod(&rsa_ctx->q2, &rsa_ctx->input, &rsa_ctx->keyinfo->q);

  sub_op = ssh_acc_device_modexp_op(rsa_ctx->device,
                                    &rsa_ctx->q2,
                                    &rsa_ctx->keyinfo->dq,
                                    &rsa_ctx->keyinfo->q,
                                    ssh_rsa_prvkey_op_done,
                                    rsa_ctx);
  if (sub_op)
    rsa_ctx->sub_op = sub_op;
}

void ssh_rsa_prvkey_op_done(SshCryptoStatus status,
                            const unsigned char *operated_data,
                            size_t data_len,
                            void *reply_context)
{
  SshRSAPrivateContext rsa_ctx = reply_context;
  SshCryptoStatus cret;
  SshMPIntegerStruct output, k;
  Boolean buf_allocated = FALSE;
  unsigned char *buf, *output_buf = NULL;
  size_t buf_len, output_buf_len;

  rsa_ctx->sub_op = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      /* If the CRT operation in the device has failed, then try to do the
       operation using modexp. */
      if (rsa_ctx->crt_in_device == TRUE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("The RSA CRT operation failed or is "
                                 "unsupported by the device, now attempting "
                                 "the operation using modexp"));
          rsa_ctx->crt_in_device = FALSE;

          /* Compute p2 = (input mod p) ^ dp mod p. */
          ssh_mprz_mod(&rsa_ctx->p2, &rsa_ctx->input, &rsa_ctx->keyinfo->p);

          rsa_ctx->sub_op =
            ssh_acc_device_modexp_op(rsa_ctx->device,
                                     &rsa_ctx->p2,
                                     &rsa_ctx->keyinfo->dp,
                                     &rsa_ctx->keyinfo->p,
                                     ssh_rsa_prvkey_op_continue,
                                     rsa_ctx);

          return;
        }
      else /* the modexp has also failed. No more that we can do. */
        {
          (*rsa_ctx->reply_cb)(status, NULL, 0, rsa_ctx->reply_context);
          ssh_rsa_prvkey_op_free(rsa_ctx);
          return;
        }
    }

  if (rsa_ctx->crt_in_device == FALSE)
    {
      ssh_mprz_set_buf(&rsa_ctx->q2, operated_data, data_len);

      ssh_mprz_init(&k);
      ssh_mprz_init(&output);

      /* Compute k = ((q2 - p2) mod q) * u mod q. */
      ssh_mprz_sub(&k, &rsa_ctx->q2, &rsa_ctx->p2);
      ssh_mprz_mul(&k, &k, &rsa_ctx->keyinfo->u);
      ssh_mprz_mod(&k, &k, &rsa_ctx->keyinfo->q);

      /* Compute output = p2 + p * k. */
      ssh_mprz_mul(&output, &rsa_ctx->keyinfo->p, &k);
      ssh_mprz_add(&output, &output, &rsa_ctx->p2);

      ssh_mprz_clear(&k);

      if (ssh_mprz_isnan(&output))
        {
          (*rsa_ctx->reply_cb)(SSH_CRYPTO_NO_MEMORY,
                               NULL, 0, rsa_ctx->reply_context);

          ssh_rsa_prvkey_op_free(rsa_ctx);
          ssh_mprz_clear(&output);
          return;
        }

      buf_len = KEY_SIZE_TO_BYTES(rsa_ctx->key_size);

      if ((buf = ssh_malloc(buf_len)) == NULL)
        {
          (*rsa_ctx->reply_cb)(SSH_CRYPTO_NO_MEMORY,
                               NULL, 0, rsa_ctx->reply_context);

          ssh_mprz_clear(&output);
          ssh_rsa_prvkey_op_free(rsa_ctx);
          return;
        }

      buf_allocated = TRUE;
      ssh_mprz_get_buf(buf, buf_len, &output);
      ssh_mprz_clear(&output);
    }
  else
    {
      buf_allocated = FALSE;
      buf = (unsigned char *)operated_data;
      buf_len = data_len;

      /* Ensure that the returned length is no longer than the RSA modulus
         byte size. This is possible since the RSA CRT operation return data
         length is p_len + q_len which may be larger than n_len. */
      if (buf_len > KEY_SIZE_TO_BYTES(rsa_ctx->key_size))
        {
          buf += (buf_len - KEY_SIZE_TO_BYTES(rsa_ctx->key_size));
          buf_len = KEY_SIZE_TO_BYTES(rsa_ctx->key_size);
        }
    }

  /* If decrypting, apply the RGF. */
  if (rsa_ctx->sign_op == FALSE)
    {
      if ((cret =
           ssh_proxy_key_rgf_decrypt(SSH_RSA_PRV_DECRYPT,
                                     rsa_ctx->rgf_id,
                                     rsa_ctx->key_size,
                                     buf,
                                     buf_len,
                                     &output_buf,
                                     &output_buf_len)) != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("The RGF drcrypt operation has failed"));

          (*rsa_ctx->reply_cb)(cret, NULL, 0, rsa_ctx->reply_context);

          if (buf_allocated)
            ssh_free(buf);
          ssh_rsa_prvkey_op_free(rsa_ctx);
          return;
        }
    }

  if (output_buf)
    {
       (*rsa_ctx->reply_cb)(SSH_CRYPTO_OK, output_buf, output_buf_len,
                           rsa_ctx->reply_context);
      ssh_free(output_buf);
    }
  else
    {

      (*rsa_ctx->reply_cb)(SSH_CRYPTO_OK, buf, buf_len,
                           rsa_ctx->reply_context);
    }

  if (buf_allocated)
    ssh_free(buf);

  ssh_rsa_prvkey_op_free(rsa_ctx);
  return;
}



/* The RSA public key signature verification callback operation. */

typedef struct
{
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;
  SshProxyReplyCB reply_cb;
  SshProxyRGFId rgf_id;
  void *reply_context;
  SshAccKey key;
  unsigned char *data;
  size_t data_len;

} *SshRSAPublicVerifyContext;

void ssh_rsa_pubkey_verify_modexp_abort(void *context)
{
  SshRSAPublicVerifyContext ctx = context;

  ssh_operation_abort(ctx->sub_op);

  ssh_free(ctx->data);
  ssh_free(ctx);
}


void ssh_rsa_pubkey_verify_modexp_free(void *context)
{
  SshRSAPublicVerifyContext ctx = context;

  ssh_operation_unregister(ctx->op);
  ssh_rsa_pubkey_verify_modexp_abort(ctx);
}

/* Verify the signature here. */
void ssh_rsa_pubkey_verify_modexp_done(SshCryptoStatus status,
                                       const unsigned char *operated_data,
                                       size_t operated_data_len,
                                       void *context)
{
  SshRSAPublicVerifyContext verify_ctx = context;

   verify_ctx->sub_op = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The RSA verify operation has failed."));

      (*verify_ctx->reply_cb)(status, NULL, 0, verify_ctx->reply_context);
      ssh_rsa_pubkey_verify_modexp_free(verify_ctx);
      return;
    }

  if ((status =
       ssh_proxy_key_rgf_verify(SSH_RSA_PUB_VERIFY,
                                verify_ctx->rgf_id,
                                verify_ctx->key->key_size,
                                verify_ctx->data,
                                verify_ctx->data_len,
                                operated_data,
                                operated_data_len)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The RGF hash verify operation has failed."));
      (*verify_ctx->reply_cb)(status, NULL, 0, verify_ctx->reply_context);
      ssh_rsa_pubkey_verify_modexp_free(verify_ctx);
      return;
    }

  (*verify_ctx->reply_cb)(SSH_CRYPTO_OK, NULL, 0, verify_ctx->reply_context);
  ssh_rsa_pubkey_verify_modexp_free(verify_ctx);
}


SshOperationHandle
ssh_rsa_pubkey_verify_modexp_op(SshProxyRGFId rgf_id,
                                const unsigned char *input_data,
                                size_t input_data_len,
                                SshProxyReplyCB reply_cb,
                                void *reply_context,
                                void *context)

{
  SshRSAPublicVerifyContext verify_ctx;
  SshMPIntegerStruct aux;
  SshOperationHandle sub_op;
  SshAccKey key;
  unsigned char *sig, *data;
  size_t sig_len, data_len;

  key = (SshAccKey)context;

  /* Allocate a Verify context */
  if ((verify_ctx = ssh_calloc(1, sizeof(*verify_ctx))) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* Decode the inupt data to get the data buffer and the signature buffer */
  if (ssh_decode_array(input_data, input_data_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&data, &data_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&sig, &sig_len),
                       SSH_FORMAT_END) != input_data_len)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      ssh_free(verify_ctx);
      return NULL;
    }

  verify_ctx->rgf_id = rgf_id;
  verify_ctx->key = key;
  verify_ctx->reply_cb = reply_cb;
  verify_ctx->reply_context = reply_context;
  verify_ctx->data = ssh_memdup(data, data_len);
  verify_ctx->data_len = data_len;

  if (verify_ctx->data == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      ssh_free(verify_ctx);
      return NULL;
    }

  /* Register the abort operation */
  ssh_operation_register_no_alloc(verify_ctx->op,
                                  ssh_rsa_pubkey_verify_modexp_abort,
                                  verify_ctx);

  ssh_mprz_init(&aux);
  ssh_mprz_set_buf(&aux, sig, sig_len);

  sub_op =
    ssh_acc_device_modexp_op(key->device,
                             &aux,
                             &key->u.rsa_pub.e,
                             &key->u.rsa_pub.n,
                             ssh_rsa_pubkey_verify_modexp_done,
                             verify_ctx);
  ssh_mprz_clear(&aux);

  if (sub_op)
    {
      verify_ctx->sub_op = sub_op;
      return verify_ctx->op;
    }
  return NULL;
}



/* The RSA public key encryption operation. */

typedef struct
{
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;
  SshProxyReplyCB reply_cb;
  void *reply_context;

} *SshRSAPublicEncryptContext;

void ssh_rsa_pubkey_encrypt_modexp_abort(void *context)
{
  SshRSAPublicEncryptContext ctx = context;

  ssh_operation_abort(ctx->sub_op);
  ssh_free(ctx);
}

void ssh_rsa_pubkey_encrypt_modexp_free(void *context)
{
  SshRSAPublicEncryptContext ctx = context;

  ssh_operation_unregister(ctx->op);
  ssh_rsa_pubkey_encrypt_modexp_abort(ctx);
}

void ssh_rsa_pubkey_encrypt_modexp_done(SshCryptoStatus status,
                                       const unsigned char *operated_data,
                                       size_t operated_data_len,
                                       void *context)
{
  SshRSAPublicEncryptContext encrypt_ctx = context;

  encrypt_ctx->sub_op = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("The RSA encrypt operation has failed."));
      (*encrypt_ctx->reply_cb)(status, NULL, 0, encrypt_ctx->reply_context);
      ssh_rsa_pubkey_encrypt_modexp_free(encrypt_ctx);

      return;
    }

  (*encrypt_ctx->reply_cb)(SSH_CRYPTO_OK, operated_data,
                           operated_data_len,
                           encrypt_ctx->reply_context);

  ssh_rsa_pubkey_encrypt_modexp_free(encrypt_ctx);
  return;
}


/* The ProxyKeyOpCB for RSA public key operations. */
SshOperationHandle
ssh_rsa_pubkey_encrypt_modexp_op(SshProxyRGFId rgf_id,
                                 const unsigned char *input_data,
                                 size_t input_data_len,
                                 SshProxyReplyCB reply_cb,
                                 void *reply_context,
                                 void *context)


{
  SshRSAPublicEncryptContext encrypt_ctx;
  SshMPIntegerStruct aux;
  SshAccKey key;
  SshOperationHandle sub_op;
  SshCryptoStatus status;
  unsigned char *data, *buf;
  size_t data_len, buf_len;

  key = (SshAccKey)context;
  data = NULL;

  /* Allocate a Encryption context */
  if ((encrypt_ctx = ssh_calloc(1, sizeof(*encrypt_ctx))) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  if ((status = ssh_proxy_key_rgf_encrypt(SSH_RSA_PUB_ENCRYPT,
                                          rgf_id,
                                          key->key_size,
                                          input_data,
                                          input_data_len,
                                          &data,
                                          &data_len)) != SSH_CRYPTO_OK)
    {
      (*reply_cb)(status, NULL, 0, reply_context);
      ssh_free(encrypt_ctx);
      return NULL;
    }

  encrypt_ctx->reply_cb = reply_cb;
  encrypt_ctx->reply_context = reply_context;

  if (data)
    {
      buf = data;
      buf_len = data_len;
    }
  else
    {
      buf = (unsigned char *) input_data;
      buf_len = input_data_len;
    }

  /* Register the abort operation */
  ssh_operation_register_no_alloc(encrypt_ctx->op,
                                  ssh_rsa_pubkey_encrypt_modexp_abort,
                                  encrypt_ctx);

  ssh_mprz_init(&aux);
  ssh_mprz_set_buf(&aux, buf, buf_len);

  sub_op =
    ssh_acc_device_modexp_op(key->device,
                             &aux,
                             &key->u.rsa_pub.e,
                             &key->u.rsa_pub.n,
                             ssh_rsa_pubkey_encrypt_modexp_done,
                             encrypt_ctx);
  ssh_mprz_clear(&aux);

  if (data)
    ssh_free(data);

  if (sub_op)
    {
      encrypt_ctx->sub_op = sub_op;
      return encrypt_ctx->op;
    }
  return NULL;
}


/*  ******************** The DSA Operation Callbacks *******************/

/* The DSA private key signature operation. */
typedef struct
{
  unsigned int len;
  SshMPIntegerStruct r, e, k, s;
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;

  SshAccDevice device;
  SshDSAPrivateKeyInfo keyinfo;

  SshProxyReplyCB reply_cb;
  void *reply_context;

} *DSASignContext, DSASignContextStruct;

/* Forward declarations. */
static SshOperationHandle ssh_dsa_modexp_sign_op_loop(void *context);
static void ssh_dsa_modexp_sign_op_loop_completion(SshCryptoStatus status,
                                                   const unsigned char *data,
                                                   size_t data_len,
                                                   void *reply_context);
static void ssh_dsa_modexp_sign_op_done(void *context);
static void ssh_dsa_modexp_sign_op_free(void *context);
static void ssh_dsa_modexp_sign_op_abort(void *context);

/* The ProxyDSASignOpCB for the DSA private key signature operation. */
SshOperationHandle
ssh_dsa_prvkey_modexp_sign_op(SshProxyRGFId rgf_id,
                              const unsigned char *data,
                              size_t data_len,
                              SshProxyReplyCB reply_cb,
                              void *reply_context,
                              void *context)
{
  SshOperationHandle sub_op;
  DSASignContext dsa_ctx;
  SshAccKey key;
  unsigned char *digest;
  size_t digest_len = 0;

  key = (SshAccKey)context;

  if ((dsa_ctx = ssh_calloc(1, sizeof(*dsa_ctx))) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  SSH_ASSERT(rgf_id == SSH_DSA_NIST_SHA1 || rgf_id == SSH_DSA_NONE_NONE);

  /* SHA-1 is the only possibility */
  digest = NULL;
  if (rgf_id == SSH_DSA_NIST_SHA1)
    {
      digest = ssh_malloc(20);
      if (digest != NULL)
        {
          (void)ssh_hash_of_buffer("sha1", data, data_len, digest);
          digest_len = 20;
        }
    }

  dsa_ctx->len = ssh_mprz_byte_size(&key->u.dsa_prv.q);
  dsa_ctx->device = key->device;
  dsa_ctx->keyinfo = &key->u.dsa_prv;
  dsa_ctx->reply_cb = reply_cb;
  dsa_ctx->reply_context = reply_context;

  ssh_mprz_init(&dsa_ctx->k);
  ssh_mprz_init(&dsa_ctx->e);
  ssh_mprz_init(&dsa_ctx->r);
  ssh_mprz_init(&dsa_ctx->s);

  /* Convert the digest to a MP integer. */
  if (digest)
    {
      ssh_mprz_set_buf(&dsa_ctx->e, digest, digest_len);
      ssh_free(digest);
    }
  else
    {
      ssh_mprz_set_buf(&dsa_ctx->e, data, data_len);
    }

  ssh_mprz_mod(&dsa_ctx->e, &dsa_ctx->e, &dsa_ctx->keyinfo->q);

  ssh_operation_register_no_alloc(dsa_ctx->op,
                                  ssh_dsa_modexp_sign_op_abort, dsa_ctx);

  SSH_DEBUG(SSH_D_LOWSTART, ("Entering the dsa_sign_loop function"));
  sub_op = ssh_dsa_modexp_sign_op_loop(dsa_ctx);

  if (sub_op)
    {
      dsa_ctx->sub_op = sub_op;
      return dsa_ctx->op;
    }
  return NULL;
}

static SshOperationHandle ssh_dsa_modexp_sign_op_loop(void *context)
{
  DSASignContext dsa_ctx = context;
  Boolean b = TRUE;

  /* Check we have a nonzero group. */
  SSH_ASSERT(ssh_mprz_cmp_ui(&dsa_ctx->keyinfo->p, 0) > 0);
  while (b)
    {
      if (dsa_ctx->keyinfo->exponent_entropy)
        ssh_mprz_aux_mod_random_entropy(&dsa_ctx->k,
                                  &dsa_ctx->keyinfo->q,
                                  dsa_ctx->keyinfo->exponent_entropy);

      else
        ssh_mprz_aux_mod_random(&dsa_ctx->k, &dsa_ctx->keyinfo->q);

      if (ssh_mprz_cmp_ui(&dsa_ctx->k, 0) != 0)
        b = FALSE;
    }
  SSH_DEBUG(SSH_D_LOWSTART, ("Have got a nonzero exponent"));

  return ssh_acc_device_modexp_op(dsa_ctx->device,
                                  &dsa_ctx->keyinfo->g,
                                  &dsa_ctx->k,
                                  &dsa_ctx->keyinfo->p,
                                  ssh_dsa_modexp_sign_op_loop_completion,
                                  dsa_ctx);
}

static void
ssh_dsa_modexp_sign_op_loop_completion(SshCryptoStatus status,
                                       const unsigned char *operated_data,
                                       size_t data_len,
                                       void *reply_context)
{
  SshMPIntegerStruct invk;
  SshOperationHandle sub_op;
  DSASignContext dsa_ctx = reply_context;

  if (status != SSH_CRYPTO_OK)
    {
      (*dsa_ctx->reply_cb)(status,
                           NULL, 0, dsa_ctx->reply_context);

      ssh_dsa_modexp_sign_op_free(dsa_ctx);
      return;
    }

  ssh_mprz_set_buf(&dsa_ctx->r, operated_data, data_len);

  /* Compute: r = (g^(k mod q) mod p) mod q */
  ssh_mprz_mod(&dsa_ctx->r, &dsa_ctx->r, &dsa_ctx->keyinfo->q);

  if (ssh_mprz_cmp_ui(&dsa_ctx->r, 0) == 0)
    {
      sub_op = ssh_dsa_modexp_sign_op_loop(dsa_ctx);
      if (sub_op)
        dsa_ctx->sub_op = sub_op;
      return;
    }

  /* Invert. */
  ssh_mprz_init(&invk);
  ssh_mprz_aux_mod_invert(&invk, &dsa_ctx->k, &dsa_ctx->keyinfo->q);

  /* Compute signature s = k^-1(e + xr). */
  ssh_mprz_mul(&dsa_ctx->s, &dsa_ctx->r, &dsa_ctx->keyinfo->x);
  ssh_mprz_add(&dsa_ctx->s, &dsa_ctx->s, &dsa_ctx->e);
  ssh_mprz_mul(&dsa_ctx->s, &dsa_ctx->s, &invk);
  ssh_mprz_mod(&dsa_ctx->s, &dsa_ctx->s, &dsa_ctx->keyinfo->q);
  ssh_mprz_clear(&invk);

  if (ssh_mprz_cmp_ui(&dsa_ctx->s, 0) == 0)
    {
      sub_op = ssh_dsa_modexp_sign_op_loop(dsa_ctx);
      if (sub_op)
        dsa_ctx->sub_op = sub_op;
      return;
    }

  ssh_dsa_modexp_sign_op_done(dsa_ctx);
}

/* No proxy key postpend operation necessary for signatures. */
static void ssh_dsa_modexp_sign_op_done(void *context)
{
  DSASignContext dsa_ctx = context;
  unsigned char *signature;

  dsa_ctx->sub_op = NULL;

  /* Linearize signature. */
  if ((signature = ssh_malloc(dsa_ctx->len * 2)) == NULL)
    {
      (*dsa_ctx->reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0,
                           dsa_ctx->reply_context);
      ssh_dsa_modexp_sign_op_free(dsa_ctx);
      return;
    }

  ssh_mprz_get_buf(signature, dsa_ctx->len, &dsa_ctx->r);
  ssh_mprz_get_buf(signature + dsa_ctx->len,
                   dsa_ctx->len, &dsa_ctx->s);

  (*dsa_ctx->reply_cb)(SSH_CRYPTO_OK,
                       signature, dsa_ctx->len * 2, dsa_ctx->reply_context);
   ssh_free(signature);

  ssh_dsa_modexp_sign_op_free(dsa_ctx);
}

static void ssh_dsa_modexp_sign_op_free(void *context)
{
  DSASignContext dsa_ctx = context;

  ssh_operation_unregister(dsa_ctx->op);
  ssh_dsa_modexp_sign_op_abort(dsa_ctx);
}

static void ssh_dsa_modexp_sign_op_abort(void *context)
{
  DSASignContext dsa_ctx = context;

  ssh_operation_abort(dsa_ctx->sub_op);

  ssh_mprz_clear(&dsa_ctx->k);
  ssh_mprz_clear(&dsa_ctx->e);
  ssh_mprz_clear(&dsa_ctx->r);
  ssh_mprz_clear(&dsa_ctx->s);

  ssh_free(dsa_ctx);
}

/* The DSA public key verification operation. */
typedef struct
{
  SshMPIntegerStruct v, w, u1, u2, r;
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;

  SshAccDevice device;
  SshDSAPublicKeyInfo keyinfo;

  SshProxyReplyCB reply_cb;
  void *reply_context;
} *DSAVerifyContext, DSAVerifyContextStruct;

/* Forward declarations. */
void ssh_dsa_modexp_verify_op_continue(SshCryptoStatus status,
                                       const unsigned char *operated_data,
                                       size_t data_len,
                                       void *reply_context);
void ssh_dsa_modexp_verify_op_done(SshCryptoStatus status,
                                   const unsigned char *operated_data,
                                   size_t data_len,
                                   void *reply_context);
void ssh_dsa_modexp_verify_op_free(void* ctx);
void ssh_dsa_modexp_verify_op_abort(void* ctx);


/* The ProxyDSAVerifyOpCB for the DSA public key verification operation. */
SshOperationHandle
ssh_dsa_pubkey_modexp_verify_op(SshProxyRGFId rgf_id,
                                const unsigned char *buffer,
                                size_t buffer_len,
                                SshProxyReplyCB reply_cb,
                                void *reply_context,
                                void *context)

{
  unsigned int vlen;
  SshMPIntegerStruct s, e, invs;
  SshOperationHandle sub_op;
  DSAVerifyContext dsa_ctx;
  unsigned char *data, *sig, *digest;
  size_t data_len, sig_len, digest_len = 0;
  SshAccKey key;

  key = (SshAccKey)context;

  if ((dsa_ctx = ssh_calloc(1, sizeof(*dsa_ctx))) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  /* Decode the inupt buffer to get the data buffer and the signature buffer */
  if (ssh_decode_array(buffer, buffer_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&data, &data_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&sig, &sig_len),
                       SSH_FORMAT_END) != buffer_len)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      ssh_free(dsa_ctx);
      return NULL;
    }

  if (sig_len != 2 * ssh_mprz_byte_size(&key->u.dsa_pub.q))
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      ssh_free(dsa_ctx);
      return NULL;
    }

  vlen = sig_len / 2 ;

  dsa_ctx->keyinfo = &key->u.dsa_pub;
  dsa_ctx->device = key->device;
  dsa_ctx->reply_cb = reply_cb;
  dsa_ctx->reply_context = reply_context;

  ssh_mprz_init(&dsa_ctx->v);
  ssh_mprz_init(&dsa_ctx->w);
  ssh_mprz_init(&dsa_ctx->r);
  ssh_mprz_init(&dsa_ctx->u1);
  ssh_mprz_init(&dsa_ctx->u2);

  ssh_mprz_init(&e);
  ssh_mprz_init(&s);
  ssh_mprz_init(&invs);

  SSH_ASSERT(rgf_id == SSH_DSA_NIST_SHA1 || rgf_id == SSH_DSA_NONE_NONE);

  /* SHA1 is the only possible hash function */
  digest = NULL;
  if (rgf_id == SSH_DSA_NIST_SHA1)
    {
      digest = ssh_malloc(20);
      if (digest != NULL)
        {
          (void)ssh_hash_of_buffer("sha1", data, data_len, digest);
          digest_len = 20;
        }
    }

  /* Reduce to correct length. */
  if (digest)
    {
      ssh_mprz_set_buf(&e, digest, digest_len);
      ssh_free(digest);
    }
  else
    {
      ssh_mprz_set_buf(&e, data, data_len);
    }

  ssh_mprz_mod(&e, &e, &dsa_ctx->keyinfo->q);

  /* Convert and reduce signature. */
  ssh_mprz_set_buf(&dsa_ctx->r, sig, vlen);

  if (ssh_mprz_cmp(&dsa_ctx->r, &dsa_ctx->keyinfo->q) >= 0 ||
      ssh_mprz_cmp_ui(&dsa_ctx->r, 0) <= 0)
    {
      goto failed;
    }

  ssh_mprz_set_buf(&s, sig + vlen, vlen);

  if (ssh_mprz_cmp(&s, &dsa_ctx->keyinfo->q) >= 0 ||
      ssh_mprz_cmp_ui(&s, 0) <= 0)
    {
      goto failed;
    }

  ssh_mprz_aux_mod_invert(&invs, &s, &dsa_ctx->keyinfo->q);
  ssh_mprz_mul(&dsa_ctx->u1, &invs, &e);
  ssh_mprz_mod(&dsa_ctx->u1, &dsa_ctx->u1, &dsa_ctx->keyinfo->q);
  ssh_mprz_mul(&dsa_ctx->u2, &invs, &dsa_ctx->r);
  ssh_mprz_mod(&dsa_ctx->u2, &dsa_ctx->u2, &dsa_ctx->keyinfo->q);

  ssh_mprz_clear(&e);
  ssh_mprz_clear(&s);
  ssh_mprz_clear(&invs);

  ssh_operation_register_no_alloc(dsa_ctx->op,
                                  ssh_dsa_modexp_verify_op_abort, dsa_ctx);

  sub_op = ssh_acc_device_modexp_op(dsa_ctx->device,
                                    &dsa_ctx->keyinfo->g,
                                    &dsa_ctx->u1,
                                    &dsa_ctx->keyinfo->p,
                                    ssh_dsa_modexp_verify_op_continue,
                                    dsa_ctx);

  if (sub_op)
    {
      dsa_ctx->sub_op = sub_op;
      return dsa_ctx->op;
    }
  return NULL;

 failed:
  {
    ssh_mprz_clear(&e);
    ssh_mprz_clear(&s);
    ssh_mprz_clear(&invs);

    (*dsa_ctx->reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0,
                         dsa_ctx->reply_context);
    ssh_dsa_modexp_verify_op_free(dsa_ctx);
    return NULL;
  }
}

void ssh_dsa_modexp_verify_op_continue(SshCryptoStatus status,
                                       const unsigned char *operated_data,
                                       size_t data_len,
                                       void *reply_context)
{
  SshOperationHandle sub_op;
  DSAVerifyContext dsa_ctx = reply_context;

  if (status != SSH_CRYPTO_OK)
    {
      (*dsa_ctx->reply_cb)(status, NULL, 0, dsa_ctx->reply_context);
      ssh_dsa_modexp_verify_op_free(dsa_ctx);
      return;
    }

  ssh_mprz_set_buf(&dsa_ctx->v, operated_data, data_len);

  sub_op = ssh_acc_device_modexp_op(dsa_ctx->device,
                                    &dsa_ctx->keyinfo->y,
                                    &dsa_ctx->u2,
                                    &dsa_ctx->keyinfo->p,
                                    ssh_dsa_modexp_verify_op_done,
                                    dsa_ctx);
  if (sub_op)
    dsa_ctx->sub_op = sub_op;
}

/* No proxy key postpend operation necessary for DSA verification. */
void ssh_dsa_modexp_verify_op_done(SshCryptoStatus status,
                                   const unsigned char *operated_data,
                                   size_t data_len,
                                   void *reply_context)
{
  DSAVerifyContext dsa_ctx = reply_context;

  dsa_ctx->sub_op = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      (*dsa_ctx->reply_cb)(status, NULL, 0, dsa_ctx->reply_context);
      ssh_dsa_modexp_verify_op_free(dsa_ctx);
      return;
    }

  ssh_mprz_set_buf(&dsa_ctx->w, operated_data, data_len);

  ssh_mprz_mul(&dsa_ctx->v, &dsa_ctx->v, &dsa_ctx->w);
  ssh_mprz_mod(&dsa_ctx->v, &dsa_ctx->v, &dsa_ctx->keyinfo->p);
  ssh_mprz_mod(&dsa_ctx->v, &dsa_ctx->v, &dsa_ctx->keyinfo->q);

  if (ssh_mprz_cmp(&dsa_ctx->v, &dsa_ctx->r) == 0)
    (*dsa_ctx->reply_cb)(SSH_CRYPTO_OK, NULL, 0, dsa_ctx->reply_context);
  else
    (*dsa_ctx->reply_cb)(SSH_CRYPTO_SIGNATURE_CHECK_FAILED, NULL, 0,
                         dsa_ctx->reply_context);

  ssh_dsa_modexp_verify_op_free(dsa_ctx);
}

void ssh_dsa_modexp_verify_op_free(void *context)
{
  DSAVerifyContext dsa_ctx = context;

  ssh_operation_unregister(dsa_ctx->op);
  ssh_dsa_modexp_verify_op_abort(dsa_ctx);
}

void ssh_dsa_modexp_verify_op_abort(void *context)
{
  DSAVerifyContext dsa_ctx = context;

  ssh_operation_abort(dsa_ctx->sub_op);

  ssh_mprz_clear(&dsa_ctx->v);
  ssh_mprz_clear(&dsa_ctx->w);
  ssh_mprz_clear(&dsa_ctx->u1);
  ssh_mprz_clear(&dsa_ctx->u2);
  ssh_mprz_clear(&dsa_ctx->r);

  ssh_free(dsa_ctx);
}



/*   ************ The Diffie-Hellman Operation Callbacks **********    */

typedef struct
{
  SshProxyReplyCB reply_cb;
  unsigned char *dh;
  size_t dh_len;
  void *reply_context;
} *DHSetupContext, DHSetupContextStruct;


void dh_modexp_setup_free(Boolean aborted, void *context)
{
  DHSetupContext setup = context;

  ssh_free(setup->dh);
  ssh_free(setup);
}

void ssh_dh_modexp_setup_reply_cb(SshCryptoStatus status,
                                  const unsigned char *data,
                                  size_t data_len,
                                  void *reply_context)
{
  unsigned char *buffer;
  size_t buffer_len;
  DHSetupContext setup = reply_context;

  if (status != SSH_CRYPTO_OK)
    {
      (*setup->reply_cb)(status, NULL, 0, setup->reply_context);
      return;
    }

  /* Encode the DH secret and data (the DH exchange value) to a buffer. */
  buffer_len =
    ssh_encode_array_alloc(&buffer,
                           SSH_ENCODE_UINT32_STR(data, data_len),
                           SSH_ENCODE_UINT32_STR(setup->dh, setup->dh_len),
                           SSH_FORMAT_END);
  /* no memory */
  if (!buffer)
    {
      (*setup->reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, setup->reply_context);
      return;
    }

  /* Call the reply callback with the encoded data. */
  (*setup->reply_cb)(SSH_CRYPTO_OK, buffer, buffer_len, setup->reply_context);

  /* Free the allocated buffers. */
  ssh_free(buffer);
}

/* The ProxyDHSetupOpCB for the Diffie-Hellman setup operation. */
SshOperationHandle
ssh_dh_modexp_setup_op(SshProxyRGFId rgf_id,
                       const unsigned char *input_data,
                       size_t input_data_len,
                       SshProxyReplyCB reply_cb,
                       void *reply_context,
                       void *context)

{
  SshOperationHandle op;
  DHSetupContext setup;
  SshMPIntegerStruct aux;
  SshDHGroupInfo dh_info;
  SshAccKey key;

  key = (SshAccKey)context;
  dh_info = &key->u.dh_group;

  SSH_ASSERT(rgf_id == SSH_DH_NONE_NONE);
  SSH_ASSERT(input_data == NULL);

  if ((setup = ssh_malloc(sizeof(*setup))) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      return NULL;
    }

  setup->reply_cb = reply_cb;
  setup->reply_context = reply_context;

  ssh_mprz_init(&aux);

  if (dh_info->exponent_entropy)
    ssh_mprz_mod_random_entropy(&aux, &dh_info->q,
                                dh_info->exponent_entropy);
  else
    ssh_mprz_mod_random(&aux, &dh_info->q);

  setup->dh_len = ssh_mprz_byte_size(&aux);

  if ((setup->dh = ssh_malloc(setup->dh_len)) == NULL)
    {
      (*reply_cb)(SSH_CRYPTO_NO_MEMORY, NULL, 0, reply_context);
      ssh_mprz_clear(&aux);
      ssh_free(setup);
      return NULL;
    }
  ssh_mprz_get_buf(setup->dh, setup->dh_len, &aux);

  op = ssh_acc_device_modexp_op(key->device,
                                &dh_info->g,
                                &aux,
                                &dh_info->p,
                                ssh_dh_modexp_setup_reply_cb,
                                setup);

  ssh_mprz_clear(&aux);
  ssh_operation_attach_destructor(op, dh_modexp_setup_free, (void *)setup);
  return op;
}

/* The ProxyDHAgreeOpCB for the Diffie-Hellman agree operation. */
SshOperationHandle
ssh_dh_modexp_agree_op(SshProxyRGFId rgf_id,
                       const unsigned char *buffer,
                       size_t buffer_len,
                       SshProxyReplyCB reply_cb,
                       void *reply_context,
                       void *context)

{
  SshAccKey key;
  SshOperationHandle op;
  SshDHGroupInfo dh_info;
  SshMPIntegerStruct aux1, aux2;
  unsigned char *exchange,*secret;
  size_t exchange_len, secret_len;

  key = (SshAccKey)context;
  dh_info = &key->u.dh_group;

  SSH_ASSERT(rgf_id == SSH_DH_NONE_NONE);

  /* Decode the input buffer to obtain the DH exchange and secret. */
  if (ssh_decode_array(buffer, buffer_len,
                       SSH_DECODE_UINT32_STR_NOCOPY(&exchange, &exchange_len),
                       SSH_DECODE_UINT32_STR_NOCOPY(&secret, &secret_len),
                       SSH_FORMAT_END) != buffer_len)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  /* Subgroup check for trivial order 2 subgroup. */
  if (exchange_len == dh_info->p_minus1_len &&
      memcmp(dh_info->p_minus1, exchange, exchange_len) == 0)
    {
      (*reply_cb)(SSH_CRYPTO_OPERATION_FAILED, NULL, 0, reply_context);
      return NULL;
    }

  ssh_mprz_init(&aux1);
  ssh_mprz_init(&aux2);

  ssh_mprz_set_buf(&aux1, exchange, exchange_len);
  ssh_mprz_set_buf(&aux2, secret, secret_len);

  op = ssh_acc_device_modexp_op(key->device,
                                &aux1,
                                &aux2,
                                &dh_info->p,
                                reply_cb,
                                reply_context);

  ssh_mprz_clear(&aux1);
  ssh_mprz_clear(&aux2);
  return op;
}


SshOperationHandle
ssh_genacc_modexp_key_op(SshProxyOperationId operation_id,
                         SshProxyRGFId rgf_id,
                         SshProxyKeyHandle handle,
                         const unsigned char *input_data,
                         size_t input_data_len,
                         SshProxyReplyCB reply_cb,
                         void *reply_context,
                         void *context)
{
  switch (operation_id)
    {

    case SSH_RSA_PRV_SIGN:
      return ssh_rsa_prvkey_op(TRUE, rgf_id, input_data,
                               input_data_len, reply_cb,
                               reply_context, context);

    case SSH_RSA_PRV_DECRYPT:
      return ssh_rsa_prvkey_op(FALSE, rgf_id, input_data,
                               input_data_len, reply_cb,
                               reply_context, context);

    case SSH_RSA_PUB_VERIFY:
      return ssh_rsa_pubkey_verify_modexp_op(rgf_id, input_data,
                                             input_data_len, reply_cb,
                                             reply_context, context);

    case SSH_RSA_PUB_ENCRYPT:
      return ssh_rsa_pubkey_encrypt_modexp_op(rgf_id, input_data,
                                              input_data_len, reply_cb,
                                              reply_context, context);


    case SSH_DSA_PRV_SIGN:
      return ssh_dsa_prvkey_modexp_sign_op(rgf_id, input_data,
                                           input_data_len, reply_cb,
                                           reply_context, context);

    case SSH_DSA_PUB_VERIFY:
      return ssh_dsa_pubkey_modexp_verify_op(rgf_id, input_data,
                                             input_data_len, reply_cb,
                                             reply_context, context);

    case SSH_DH_SETUP:
      return ssh_dh_modexp_setup_op(rgf_id, input_data,
                                      input_data_len, reply_cb,
                                      reply_context, context);

    case SSH_DH_AGREE:
      return ssh_dh_modexp_agree_op(rgf_id, input_data,
                                    input_data_len, reply_cb,
                                    reply_context, context);

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Invalid operation id %d",
                             (int) operation_id));
      (*reply_cb)(SSH_CRYPTO_UNSUPPORTED, NULL, 0, reply_context);
      return NULL;
    }
}

/* Now comes the provider glue code. */

/* Build an accelerated private key. The provider will convert the
   specified public key to an accelerated private key (if it can) and
   return the key in the callback. */
SshOperationHandle
ssh_genacc_provider_gen_acc_private_key(void *provider_context,
                                        SshPrivateKey source,
                                        SshEkGetPrivateKeyCB get_prvkey_cb,
                                        void *context)
{
  const char *key_type = NULL;
  const char *encrypt_scheme = NULL;
  const char *sign_scheme = NULL;
  unsigned int key_size = 0;
  SshAccKey acc_key = NULL;
  SshPrivateKey target = NULL;
  Boolean is_rsa_key = FALSE, is_dsa_key = FALSE, is_ecdsa_key = FALSE;
  SshMPIntegerStruct p;

  if (source == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("source key is NULL"));
      (*get_prvkey_cb)(SSH_EK_FAILED, target, context);
      return NULL;
    }

  /* First generate the key context. */
  if ((acc_key = ssh_calloc(1, sizeof(*acc_key))) == NULL)
    {
      (*get_prvkey_cb)(SSH_EK_NO_MEMORY, target, context);
      return NULL;
    }

  ssh_mprz_init(&p);

  /* Set the device. */
  acc_key->device = (SshAccDevice)provider_context;

  /* Get key size and scheme information. */
  if (ssh_private_key_get_info(source,
                               SSH_PKF_KEY_TYPE, &key_type,
                               SSH_PKF_SIGN, &sign_scheme,
                               SSH_PKF_ENCRYPT, &encrypt_scheme,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not read the private key scheme"));
      goto fail;
    }

  if (key_type == NULL)
    goto fail;
  else if (strstr(key_type, "if-modn"))
    is_rsa_key = TRUE;
  else if (strstr(key_type, "dl-modp"))
    is_dsa_key = TRUE;
  else if (strstr(key_type, "ec-modp"))
    is_ecdsa_key = TRUE;
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Unable to make proxy key from type '%s'", key_type));
      goto fail;
    }

  if (is_ecdsa_key)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Accelerated ECDSA keys are not supported"));
      goto fail;
    }

  /* Get key size information. */
  if (ssh_private_key_get_info(source,
                               SSH_PKF_SIZE, &key_size,
                               SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not read the private key size"));
      goto fail;
    }

  acc_key->key_size = (size_t)key_size;

  SSH_DEBUG(SSH_D_MIDOK, ("The key size is %d", key_size));

  /* If the source key is a RSA key */
  if (is_rsa_key)
    {
      if (get_rsa_prvkey_info(source, &acc_key->u.rsa_prv)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not get the private key info"));
          goto fail;
        }

      SSH_DEBUG(SSH_D_MIDOK, ("Now generating the proxy private key"));

      target =
        ssh_private_key_create_proxy(SSH_PROXY_RSA,
                                     (SshUInt32)key_size,
                                     ssh_genacc_modexp_key_op,
                                     ssh_rsa_prvkey_free_op,
                                     acc_key);
    }
  /* If the source key is a DSA key */
  else if (is_dsa_key)
      {
        if (get_dsa_prvkey_info(source, &acc_key->u.dsa_prv)
            == FALSE)
          {
            SSH_DEBUG(SSH_D_FAIL, ("Could not get the private key info"));
            goto fail;
          }

        SSH_DEBUG(SSH_D_MIDOK, ("Now generating the proxy private key"));

        target =
          ssh_private_key_create_proxy(SSH_PROXY_DSA,
                                       (SshUInt32)key_size,
                                       ssh_genacc_modexp_key_op,
                                       ssh_dsa_prvkey_free_op,
                                       acc_key);
      }
  else
    SSH_NOTREACHED;

  if (target == NULL)
    goto fail;

  acc_key = NULL;

 /* Set the scheme information of the generated key */
  if (sign_scheme &&
      ssh_private_key_select_scheme(target,
                                    SSH_PKF_SIGN, sign_scheme,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    goto fail;


  if (encrypt_scheme &&
      ssh_private_key_select_scheme(target,
                                    SSH_PKF_ENCRYPT, encrypt_scheme,
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    goto fail;

  ssh_mprz_clear(&p);

  SSH_DEBUG(SSH_D_MIDOK, ("Proxy Acc Key generated."));
  (*get_prvkey_cb)(SSH_EK_OK, target, context);
  return NULL;

 fail:
  /* Free allocated memory */
  if (target)
    ssh_private_key_free(target);

  if (acc_key)
    {
      if (is_rsa_key)
        free_rsa_prv_info(&acc_key->u.rsa_prv);
      if (is_dsa_key)
        free_dsa_prv_info(&acc_key->u.dsa_prv);
      if (is_ecdsa_key)
        free_ecdsa_prv_info(&acc_key->u.ecdsa_prv);
      ssh_free(acc_key);
    }

  ssh_mprz_clear(&p);

  (*get_prvkey_cb)(SSH_EK_FAILED, NULL, context);
  return NULL;
}

/* Build an accelerated public key. The provider will convert the
   specified public key to an accelerated public key (if it can) and
   return the key in the callback. */
SshOperationHandle
ssh_genacc_provider_gen_acc_public_key(void *provider_context,
                                       SshPublicKey source,
                                       SshEkGetPublicKeyCB
                                       get_public_key_cb,
                                       void *context)
{
  const char *encrypt_scheme = NULL;
  const char *sign_scheme = NULL;
  const char *key_type = NULL;
  unsigned int key_size = 0;
  SshAccKey acc_key = NULL;
  SshPublicKey target = NULL;
  Boolean is_rsa_key = FALSE, is_dsa_key = FALSE;

  if (source == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("acc: source key is NULL"));
      (*get_public_key_cb)(SSH_EK_FAILED, target, context);
      return NULL;
    }

  /* First generate the key context. */
  if ((acc_key = ssh_calloc(1, sizeof(*acc_key))) == NULL)
    {
      (*get_public_key_cb)(SSH_EK_NO_MEMORY, target, context);
      return NULL;
    }

  /* Set the device. */
  acc_key->device = (SshAccDevice)provider_context;

  /* Get the key size and scheme information. */
  if (ssh_public_key_get_info(source,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_SIZE, &key_size,
                              SSH_PKF_SIGN, &sign_scheme,
                              SSH_PKF_ENCRYPT, &encrypt_scheme,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not read the private key info"));
      goto fail;
    }

  acc_key->key_size = (size_t)key_size;

  if (key_type == NULL)
    goto fail;

  /* If the source key is a RSA key */
  if (strstr(key_type, "if-modn"))
    {
      if (get_rsa_pubkey_info(source, &acc_key->u.rsa_pub)
          == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not get the public key info"));
          goto fail;
        }
      is_rsa_key = TRUE;

      SSH_DEBUG(SSH_D_MIDOK, ("Now generating the proxy public key"));

      target = ssh_public_key_create_proxy(SSH_PROXY_RSA,
                                           (SshUInt32)key_size,
                                           ssh_genacc_modexp_key_op,
                                           ssh_rsa_pubkey_free_op,
                                           acc_key);
    }
  else
    /* If the source key is a DSA key */
    if (strstr(key_type, "dl-modp"))
      {
        if (get_dsa_pubkey_info(source, &acc_key->u.dsa_pub)
            == FALSE)
          {
            SSH_DEBUG(SSH_D_FAIL, ("Could not get the public key info"));
            goto fail;
          }
        is_dsa_key = TRUE;

        SSH_DEBUG(SSH_D_MIDOK, ("Now generating the proxy public key"));

        target =
          ssh_public_key_create_proxy(SSH_PROXY_DSA,
                                      (SshUInt32)key_size,
                                      ssh_genacc_modexp_key_op,
                                      ssh_dsa_pubkey_free_op,
                                      acc_key);
      }
    else
      /* Only if-modn (RSA) and dl-modp (DSA) key types supported. */
      goto fail;

  if (target == NULL)
    goto fail;

  acc_key = NULL;

  /* Set the scheme information of the generated key */
  if (sign_scheme &&
      ssh_public_key_select_scheme(target,
                                   SSH_PKF_SIGN, sign_scheme,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    goto fail;

  /* Set the scheme information of the generated key */
  if (encrypt_scheme &&
      ssh_public_key_select_scheme(target,
                                   SSH_PKF_ENCRYPT, encrypt_scheme,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    goto fail;

  SSH_DEBUG(SSH_D_MIDOK, ("Proxy Acc Key generated"));
  (*get_public_key_cb)(SSH_EK_OK, target, context);
  return NULL;

 fail:
  /* Free allocated memory */
  if (target)
    ssh_public_key_free(target);

  if (acc_key)
    {
      if (is_rsa_key)
        free_rsa_pub_info(&acc_key->u.rsa_pub);
      if (is_dsa_key)
        free_dsa_pub_info(&acc_key->u.dsa_pub);
      ssh_free(acc_key);
    }

  (*get_public_key_cb)(SSH_EK_FAILED, NULL, context);
  return NULL;
}

/* Build an accelerated group. The provider will convert the
   specified group to an accelerated group (if it can) and return
   the group in the callback. */
SshOperationHandle
ssh_genacc_provider_gen_acc_group(void *provider_context,
                                  SshPkGroup source,
                                  SshEkGetGroupCB get_pk_group_cb,
                                  void *context)
{
  size_t group_size;
  SshAccKey acc_key;
  SshPkGroup target = NULL;

  if (source == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("acc: source group is NULL"));
      (*get_pk_group_cb)(SSH_EK_FAILED, target, context);
      return NULL;
    }

  /* First generate the key context. */
  if ((acc_key = ssh_calloc(1, sizeof(*acc_key))) == NULL)
    {
      (*get_pk_group_cb)(SSH_EK_NO_MEMORY, NULL, context);
      return NULL;
    }

  /* Set the provider. */
  acc_key->device = (SshAccDevice)provider_context;

  if (get_pk_group_info(source, &acc_key->u.dh_group) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not get the group info"));
      goto fail;
    }

  group_size = acc_key->u.dh_group.group_size;
  acc_key->key_size = 0;

  SSH_DEBUG(SSH_D_MIDOK, ("Now generating the proxy pk group"));

  target = ssh_dh_group_create_proxy(SSH_PROXY_GROUP,
                                     group_size,
                                     ssh_genacc_modexp_key_op,
                                     ssh_dh_group_free_op,
                                     acc_key);

  SSH_DEBUG(SSH_D_MIDOK, ("Proxy Acc group generated"));
  if (target == NULL)
    {
      goto fail;
    }
  else
    {
      (*get_pk_group_cb)(SSH_EK_OK, target, context);
    }

  return NULL;

 fail:
  ssh_free(acc_key);
  (*get_pk_group_cb)(SSH_EK_FAILED, NULL, context);
  return NULL;
}

/* Returns the printable name of the Cryptographic Accelerator
   Provider. */
const char *ssh_genacc_provider_get_printable_name(void *provider_context)
{
  return "SSH Generic Cryptographic Accelerator Provider.";
}

/* Parse the initialization string. */
static Boolean
genacc_parse_init_string(const char *init_str,
                         char **name,
                         char **device_info,
                         Boolean *wait_for_message,
                         Boolean *rsa_crt)
{
  char *s;

  *name = NULL;
  *device_info = NULL;
  *wait_for_message = FALSE;
  *rsa_crt = TRUE;

  s = ssh_get_component_data_from_string(init_str, "device-info", 0);
  if (s != NULL)
    {
      *device_info = ssh_strdup(s);
      SSH_DEBUG(SSH_D_HIGHOK, ("The device_info is %s.", *device_info));
      ssh_free(s);

      if (*device_info == NULL)
        goto error;
    }

  if ((s = ssh_get_component_data_from_string(init_str,
                                              "name", 0)) != NULL)
    {
      *name = ssh_strdup(s);
      SSH_DEBUG(SSH_D_HIGHOK, ("The device name is %s.", *name));
      ssh_free(s);

      if (*name == NULL)
        goto error;
    }

  if ((s = ssh_get_component_data_from_string(init_str,
                                              "rsa-crt", 0))
      != NULL)
    {
      if (strcmp(s, "yes") == 0)
        *rsa_crt = TRUE;
      else if (strcmp(s, "no") == 0)
        *rsa_crt = FALSE;
      else
        {
          ssh_free(s);
          goto error;
        }
      ssh_free(s);
      SSH_DEBUG(SSH_D_HIGHOK, ("Using CRT for RSA operations: %s",
                               (*rsa_crt == TRUE) ? "YES" : "NO"));
    }


  if ((s = ssh_get_component_data_from_string(init_str,
                                              "initialize-using-message", 0))
      != NULL)
    {
      if (strcmp(s, "yes") == 0)
        *wait_for_message = TRUE;
      else if (strcmp(s, "no") == 0)
        *wait_for_message = FALSE;
      else
        {
          ssh_free(s);
          goto error;
        }
      ssh_free(s);
      SSH_DEBUG(SSH_D_HIGHOK, ("The initialize_from_message"
                               " variable is %d", *wait_for_message));
    }

  return TRUE;

 error:
  if (*name != NULL)
    {
      ssh_free(*name);
      *name = NULL;
    }

  if (*device_info != NULL)
    {
      ssh_free(*device_info);
      *device_info = NULL;
    }

  return FALSE;
}


/* Initializes the provider and allocates a context for it. */
SshEkStatus
ssh_genacc_provider_init(const char *initialization_info,
                         void *init_ptr,
                         SshEkNotifyCB notify_cb,
                         SshEkAuthenticationCB authentication_cb,
                         void *context,
                         void **provider_return)
{
  Boolean wait_for_message, rsa_crt;
  char *device_name = NULL, *device_info = NULL;
  SshAccDevice acc_device = NULL;

  *provider_return = NULL;

  if ((genacc_parse_init_string(initialization_info,
                                &device_name,
                                &device_info,
                                &wait_for_message,
                                &rsa_crt)) == FALSE)
    return SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID;

  if ((ssh_acc_device_allocate(device_name, device_info, init_ptr,
                               wait_for_message,
                               &acc_device))
      != SSH_ACC_DEVICE_OK)
    {
      ssh_free(device_name);
      ssh_free(device_info);
      return SSH_EK_PROVIDER_INITIALIZATION_INFO_INVALID;
    }

  ssh_free(device_name);
  ssh_free(device_info);
  *provider_return = acc_device;

  acc_device->rsa_crt = rsa_crt;
  acc_device->notify_cb = notify_cb;
  acc_device->notify_context = context;

  if (notify_cb)
    (*notify_cb)(SSH_EK_EVENT_PROVIDER_ENABLED, NULL,
                 "Genacc Provider Enabled", 0, context);

  return SSH_EK_OK;
}

/* Uninitialize the provider  */
void ssh_genacc_provider_uninit(void *provider_context)
{
  SshAccDevice acc_device = provider_context;

  /* Uninitialize and free the device. */
  if (acc_device)
    {
      if (acc_device->notify_cb)
        (*acc_device->notify_cb)(SSH_EK_EVENT_PROVIDER_DISABLED, NULL,
                                 "Genacc provider removed",
                                 0, acc_device->notify_context);

      ssh_acc_device_free(acc_device);
    }
}


/*****************************************************************/

static SshEkStatus map_crypto_status_to_ek_status(SshCryptoStatus status)
{
  if (status == SSH_CRYPTO_OK)
    return SSH_EK_OK;

  if (status == SSH_CRYPTO_NO_MEMORY)
    return SSH_EK_NO_MEMORY;

  if (status == SSH_CRYPTO_UNSUPPORTED)
    return SSH_EK_OPERATION_NOT_SUPPORTED;

  return SSH_EK_FAILED;
}


static SshEkStatus device_status_to_ek_status(SshAccDeviceStatus status)
{
  if (status == SSH_ACC_DEVICE_OK)
    return SSH_EK_OK;

  if (status == SSH_ACC_DEVICE_NO_MEMORY)
    return SSH_EK_NO_MEMORY;

  if (status == SSH_ACC_DEVICE_UNSUPPORTED)
    return SSH_EK_OPERATION_NOT_SUPPORTED;

  if (status == SSH_ACC_DEVICE_SLOTS_EXHAUSTED)
    return SSH_EK_TOKEN_ERROR;

  if (status == SSH_ACC_DEVICE_FAIL)
    return SSH_EK_TOKEN_ERROR;

  return SSH_EK_FAILED;
}

/* Context that is used for getting random bytes from the accelerator. */
typedef struct SshGenAccRandomCtxRec
{
  SshOperationHandleStruct op[1];
  SshOperationHandle sub_op;

  SshEkGetRandomBytesCB callback;
  void *context;
} *SshGenAccRandomCtx;


void ssh_genacc_random_op_abort(void *context)
{
  SshGenAccRandomCtx ctx= context;;

  ssh_operation_abort(ctx->sub_op);
  ssh_free(ctx);
}

void ssh_genacc_random_op_free(void *context)
{
  SshGenAccRandomCtx ctx= context;;

  ssh_operation_unregister(ctx->op);
  ssh_genacc_random_op_abort(ctx);
}

void ssh_genacc_random_op_done(SshCryptoStatus status,
                               const unsigned char *data,
                               size_t data_len,
                               void *context)
{
  SshEkStatus ek_status;
  SshGenAccRandomCtx ctx = context;

  ctx->sub_op = NULL;

  ek_status = map_crypto_status_to_ek_status(status);

  if (status == SSH_CRYPTO_OK)
    {
      if (ctx->callback)
        (*ctx->callback)(ek_status, data, data_len, ctx->context);
    }
  else
    {
      if (ctx->callback)
        (*ctx->callback)(ek_status, NULL, 0, ctx->context);
    }

  ssh_genacc_random_op_free(ctx);
}

/* Get random bytes. The accelerator will attempt to generate the requested
   number of random bytes and return them in the callback. The provider
   may return fewer than the requested number of random bytes in the
   callback.*/
SshOperationHandle
ssh_genacc_provider_get_random_bytes(void *provider_context,
                                     size_t bytes_requested,
                                     SshEkGetRandomBytesCB callback,
                                     void *context)
{
  SshGenAccRandomCtx random_ctx;
  SshOperationHandle sub_op;
  SshAccDevice device = provider_context;

  /* Allocate a context and pass it the callback.  */
  if ((random_ctx = ssh_calloc(1, sizeof(*random_ctx))) == NULL)
    {
      if (callback)
        (*callback)(SSH_EK_NO_MEMORY, NULL, 0, context);
      return NULL;
    }

  random_ctx->callback = callback;
  random_ctx->context = context;

  ssh_operation_register_no_alloc(random_ctx->op,
                                  ssh_genacc_random_op_abort, random_ctx);

  sub_op = ssh_acc_device_get_random_bytes(device,
                                           bytes_requested,
                                           ssh_genacc_random_op_done,
                                           random_ctx);
  if (sub_op)
    {
      random_ctx->sub_op = sub_op;
      return random_ctx->op;
    }

  return NULL;
}


SshOperationHandle
ssh_genacc_provider_send_message(void *provider_context,
                                 const char *message,
                                 void *message_arg,  size_t message_arg_len,
                                 SshEkSendMessageCB message_cb,
                                 void *context)
{
  SshAccDevice device = provider_context;

  if (!strcmp(message, "Initializing Message"))
    {
      SshEkStatus ek_status;
      SshAccDeviceStatus dev_status;

      dev_status = ssh_acc_device_initialize_from_message(device, message_arg);

      ek_status = device_status_to_ek_status(dev_status);

      if (message_cb)
        (*message_cb)(ek_status, NULL, 0, context);
    }
  else
    {
      if (message_cb)
        (*message_cb)(SSH_EK_UNKNOWN_MESSAGE, NULL, 0, context);
    }

  return NULL;
}


/* The ProviderOps structure. */
const
struct SshEkProviderOpsRec ssh_ek_gen_acc_ops =
{
  "genacc",
  ssh_genacc_provider_init,
  ssh_genacc_provider_uninit,
  NULL_FNPTR,
  NULL_FNPTR,
  NULL_FNPTR,
  NULL_FNPTR,
  NULL_FNPTR,
  ssh_genacc_provider_get_printable_name,
  ssh_genacc_provider_gen_acc_private_key,
  ssh_genacc_provider_gen_acc_public_key,
  ssh_genacc_provider_gen_acc_group,
  ssh_genacc_provider_get_random_bytes,
  ssh_genacc_provider_send_message
};
