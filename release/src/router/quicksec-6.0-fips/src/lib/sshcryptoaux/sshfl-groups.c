/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshproxykey.h"
#include "sshcryptoaux.h"
#include "sshfl.h"

#include "fl.h"

#define SSH_DEBUG_MODULE "SshCryptoAuxFlGroups"

typedef enum {
  SSH_FL_GROUP_TYPE_DSA_1024_160,
  SSH_FL_GROUP_TYPE_DSA_2048_224,
  SSH_FL_GROUP_TYPE_DSA_2048_256,
  SSH_FL_GROUP_TYPE_DSA_3072_256,
  SSH_FL_GROUP_TYPE_ECDSA_192,
  SSH_FL_GROUP_TYPE_ECDSA_224,
  SSH_FL_GROUP_TYPE_ECDSA_256,
  SSH_FL_GROUP_TYPE_ECDSA_384,
  SSH_FL_GROUP_TYPE_ECDSA_521,
} SshFlGroupType;


typedef struct SshFlGroupDHOperationStoreRec *SshFlGroupDHOperationStore;

typedef struct SshFlGroupDHOperationStoreRec
{
  FL_KeyAsset_t private_key;

  unsigned char *exchange;
  size_t exchange_len;

  SshFlGroupDHOperationStore next;
} SshFlGroupDHOperationStoreStruct;

typedef struct SshFlGroupContextRec
{
  SshFlGroupType group_type;

  size_t pubkey_asset_size;
  size_t prvkey_asset_size;

  size_t exchange_buffer_len;
  size_t shared_secret_len;

  FL_KeyAsset_t domain_parameters;
  FL_PolicyFullBits_t key_derive_policy;

  SshFlGroupDHOperationStore store;
} *SshFlGroupContext, SshFlGroupContextStruct;

/* ***************************** Util ********************************* */

static void
reverse_buffer(unsigned char *buffer,
               size_t buffer_len)
{
  int i;
  unsigned char temp;

  for (i = 0; i < (buffer_len / 2); i++)
    {
      temp = buffer[i];
      buffer[i] = buffer[buffer_len - 1 - i];
      buffer[buffer_len - 1 - i] = temp;
    }

}

/* ********************** Group creation **************************** */

void ssh_fl_group_free(void *context)
{
  SshFlGroupContext group_context = (SshFlGroupContext) context;
  SshFlGroupDHOperationStore temp;

  if (group_context->domain_parameters != FL_ASSET_INVALID)
    SSH_FL_ASSETFREE(group_context->domain_parameters);

  while (group_context->store != NULL)
    {
      temp = group_context->store;
      group_context->store = group_context->store->next;

      SSH_FL_ASSETFREE(temp->private_key);
      ssh_free(temp->exchange);
      ssh_free(temp);
    }

  ssh_free(group_context);

  return;
}

void *ssh_fl_dl_group_make(unsigned char *p_buf,
                           size_t p_size,
                           unsigned char *q_buf,
                           size_t q_size,
                           unsigned char *g_buf,
                           size_t g_size)
{
  SshFlGroupContext group_context = NULL;
  size_t pubkey_asset_size, prvkey_asset_size, exchange_buffer_len;
  unsigned char *key_asset_buffer = NULL;
  SshUInt32 p_bitlen, q_bitlen;
  SshFlGroupType group_type;

  FL_RV fl_rv;
  FL_KeyAsset_t domain_parameters = FL_ASSET_INVALID;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  group_context = ssh_malloc(sizeof (SshFlGroupContextStruct));

  if (group_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  if ((p_size == 128) && (q_size == 20))
    {
      pubkey_asset_size = sizeof(FL_DSAPublicKeyValidatable1024_160_t);
      prvkey_asset_size = sizeof(FL_DSAPrivateKey1024_160_t);
      exchange_buffer_len = 128;
      group_type = SSH_FL_GROUP_TYPE_DSA_1024_160;
    }
  else if ((p_size == 256) && (q_size == 28))
    {
      pubkey_asset_size = sizeof(FL_DSAPublicKeyValidatable2048_224_t);
      prvkey_asset_size = sizeof(FL_DSAPrivateKey2048_224_t);
      exchange_buffer_len = 256;
      group_type = SSH_FL_GROUP_TYPE_DSA_2048_224;
    }
  else if ((p_size == 256) && (q_size == 32))
    {
      pubkey_asset_size = sizeof(FL_DSAPublicKeyValidatable2048_256_t);
      prvkey_asset_size = sizeof(FL_DSAPrivateKey2048_256_t);
      exchange_buffer_len = 256;
      group_type = SSH_FL_GROUP_TYPE_DSA_2048_256;
    }
  else if ((p_size == 384) && (q_size == 32))
    {
      pubkey_asset_size = sizeof(FL_DSAPublicKeyValidatable3072_256_t);
      prvkey_asset_size = sizeof(FL_DSAPrivateKey3072_256_t);
      exchange_buffer_len = 384;
      group_type = SSH_FL_GROUP_TYPE_DSA_3072_256;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid DL public key prime size: %u/%u",
                 8 * p_size, 8 * q_size));
      goto fail;
    }

  key_asset_buffer = ssh_malloc(pubkey_asset_size);

  if (key_asset_buffer == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  SSH_FL_ASSETALLOCATE(fl_rv, FL_POLICY_ALGO_DH_DERIVE |
                           FL_POLICY_FLAG_PUBLIC_KEY,
                           pubkey_asset_size,
                           0,
                           &domain_parameters);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  /* Fill in the values in key asset buffer */
  p_bitlen = p_size * 8;
  q_bitlen = q_size * 8;

  memset(key_asset_buffer, 0x00, pubkey_asset_size);

  /* This encoding does not reach value y, which is left zeroed in
     domain parameters */
  if (ssh_encode_array(key_asset_buffer, pubkey_asset_size,
                       SSH_FORMAT_DATA, &q_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, &p_bitlen, sizeof(SshUInt32),
                       SSH_FORMAT_DATA, p_buf, p_size,
                       SSH_FORMAT_DATA, q_buf, q_size,
                       SSH_FORMAT_DATA, g_buf, g_size,
                       SSH_FORMAT_END) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Failed to encode DL group domain parameter asset"));
      goto fail;
    }

  fl_rv = FL_AssetLoadValue(domain_parameters,
                            key_asset_buffer,
                            pubkey_asset_size);

  if (fl_rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetLoadValue(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      SSH_FL_ASSETFREE(domain_parameters);
      goto fail;
    }

  SSH_ASSERT(domain_parameters != FL_ASSET_INVALID);

  group_context->group_type = group_type;

  group_context->pubkey_asset_size = pubkey_asset_size;
  group_context->prvkey_asset_size = prvkey_asset_size;

  group_context->exchange_buffer_len = exchange_buffer_len;
  group_context->shared_secret_len = exchange_buffer_len;

  group_context->domain_parameters = domain_parameters;
  group_context->key_derive_policy = FL_POLICY_ALGO_DH_DERIVE;

  group_context->store = NULL;

  /* Cleanup */
  ssh_free(key_asset_buffer);
  return group_context;

 fail:
  if (domain_parameters != FL_ASSET_INVALID)
    SSH_FL_ASSETFREE(domain_parameters);

  ssh_free(group_context);
  ssh_free(key_asset_buffer);
  return NULL;
}

void *ssh_fl_ec_group_make(unsigned int group_bitlen)
{
  SshFlGroupContext group_context = NULL;
  size_t pubkey_asset_size, prvkey_asset_size, exchange_buffer_len;
  SshFlGroupType group_type;

  SSH_ASSERT(FL_LibStatus() != FL_STATUS_INITIAL);

  group_context = ssh_malloc(sizeof (SshFlGroupContextStruct));

  if (group_context == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  if (group_bitlen == 192)
    {
      pubkey_asset_size = sizeof(FL_ECDSAPublicKey192_t);
      prvkey_asset_size = sizeof(FL_ECDSAPrivateKey192_t);
      exchange_buffer_len = 48;
      group_type = SSH_FL_GROUP_TYPE_ECDSA_192;
    }
  else if (group_bitlen == 224)
    {
      pubkey_asset_size = sizeof(FL_ECDSAPublicKey224_t);
      prvkey_asset_size = sizeof(FL_ECDSAPrivateKey224_t);
      exchange_buffer_len = 56;
      group_type = SSH_FL_GROUP_TYPE_ECDSA_224;
    }
  else if (group_bitlen == 256)
    {
      pubkey_asset_size = sizeof(FL_ECDSAPublicKey256_t);
      prvkey_asset_size = sizeof(FL_ECDSAPrivateKey256_t);
      exchange_buffer_len = 64;
      group_type = SSH_FL_GROUP_TYPE_ECDSA_256;
    }
  else if (group_bitlen == 384)
    {
      pubkey_asset_size = sizeof(FL_ECDSAPublicKey384_t);
      prvkey_asset_size = sizeof(FL_ECDSAPrivateKey384_t);
      exchange_buffer_len = 96;
      group_type = SSH_FL_GROUP_TYPE_ECDSA_384;
    }
  else if (group_bitlen == 521)
    {
      pubkey_asset_size = sizeof(FL_ECDSAPublicKey521_t);
      prvkey_asset_size = sizeof(FL_ECDSAPrivateKey521_t);
      exchange_buffer_len = 132;
      group_type = SSH_FL_GROUP_TYPE_ECDSA_521;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid EC group bitlen: %u", group_bitlen));
      goto fail;
    }

  group_context->pubkey_asset_size = pubkey_asset_size;
  group_context->prvkey_asset_size = prvkey_asset_size;

  group_context->group_type = group_type;

  group_context->exchange_buffer_len = exchange_buffer_len;
  group_context->shared_secret_len = exchange_buffer_len / 2;

  /* Used EC groups are fixed based on the curve length */
  group_context->domain_parameters = FL_ASSET_INVALID;
  group_context->key_derive_policy = FL_POLICY_ALGO_ECDH_DERIVE;

  group_context->store = NULL;

  return group_context;

 fail:
  ssh_free(group_context);
  return NULL;
}

/* ********************** Group operations **************************** */

size_t
ssh_fl_group_exchange_size(void *context)
{
  SshFlGroupContext group_context = (SshFlGroupContext) context;

  return group_context->exchange_buffer_len;
}

size_t
ssh_fl_group_shared_secret_size(void *context)
{
  SshFlGroupContext group_context = (SshFlGroupContext) context;

  return group_context->shared_secret_len;
}

static void
fl_public_key_buffer_read_exchange(unsigned char *pubkey_buffer,
                                   size_t pubkey_buffer_len,
                                   unsigned char *exchange_buffer,
                                   size_t exchange_buffer_len,
                                   SshFlGroupType group_type)
{
  FL_BigIntPart32_t *public_key_field = NULL, *public_key_x_field = NULL,
    *public_key_y_field = NULL;
  size_t public_key_field_len = 0;
  Boolean ecdsa_group = FALSE;

  switch (group_type)
    {
    case SSH_FL_GROUP_TYPE_DSA_1024_160:
      public_key_field =
        ((FL_DSAPublicKeyValidatable1024_160_t *)pubkey_buffer)->PublicKey;
      public_key_field_len = 128;
      break;
    case SSH_FL_GROUP_TYPE_DSA_2048_224:
      public_key_field =
        ((FL_DSAPublicKeyValidatable2048_224_t *)pubkey_buffer)->PublicKey;
      public_key_field_len = 256;
      break;
    case SSH_FL_GROUP_TYPE_DSA_2048_256:
      public_key_field =
        ((FL_DSAPublicKeyValidatable2048_256_t *)pubkey_buffer)->PublicKey;
      public_key_field_len = 256;
      break;
    case SSH_FL_GROUP_TYPE_DSA_3072_256:
      public_key_field =
        ((FL_DSAPublicKeyValidatable3072_256_t *)pubkey_buffer)->PublicKey;
      public_key_field_len = 384;
      break;
    case SSH_FL_GROUP_TYPE_ECDSA_192:
      public_key_x_field =
        ((FL_ECDSAPublicKey192_t *)pubkey_buffer)->PublicKey_P192_X;
      public_key_y_field =
        ((FL_ECDSAPublicKey192_t *)pubkey_buffer)->PublicKey_P192_Y;
      public_key_field_len = 24;
      ecdsa_group = TRUE;
      break;
    case SSH_FL_GROUP_TYPE_ECDSA_224:
      public_key_x_field =
        ((FL_ECDSAPublicKey224_t *)pubkey_buffer)->PublicKey_P224_X;
      public_key_y_field =
        ((FL_ECDSAPublicKey224_t *)pubkey_buffer)->PublicKey_P224_Y;
      public_key_field_len = 28;
      ecdsa_group = TRUE;
      break;
    case SSH_FL_GROUP_TYPE_ECDSA_256:
      public_key_x_field =
        ((FL_ECDSAPublicKey256_t *)pubkey_buffer)->PublicKey_P256_X;
      public_key_y_field =
        ((FL_ECDSAPublicKey256_t *)pubkey_buffer)->PublicKey_P256_Y;
      public_key_field_len = 32;
      ecdsa_group = TRUE;
      break;
    case SSH_FL_GROUP_TYPE_ECDSA_384:
      public_key_x_field =
        ((FL_ECDSAPublicKey384_t *)pubkey_buffer)->PublicKey_P384_X;
      public_key_y_field =
        ((FL_ECDSAPublicKey384_t *)pubkey_buffer)->PublicKey_P384_Y;
      public_key_field_len = 48;
      ecdsa_group = TRUE;
      break;
    case SSH_FL_GROUP_TYPE_ECDSA_521:
      public_key_x_field =
        ((FL_ECDSAPublicKey521_t *)pubkey_buffer)->PublicKey_P521_X;
      public_key_y_field =
        ((FL_ECDSAPublicKey521_t *)pubkey_buffer)->PublicKey_P521_Y;
      public_key_field_len = 66;
      ecdsa_group = TRUE;
      break;
    }

  if (ecdsa_group == FALSE)
    {
      SSH_ASSERT(exchange_buffer_len == public_key_field_len);
      SSH_ASSERT(public_key_field != NULL);
      memcpy(exchange_buffer, public_key_field, public_key_field_len);
      reverse_buffer(exchange_buffer, exchange_buffer_len);
    }
  else
    {
      /* For ECDSA append x and y values to create exchange buffer */
      SSH_ASSERT(exchange_buffer_len == 2 * public_key_field_len);
      SSH_ASSERT(public_key_x_field != NULL);
      SSH_ASSERT(public_key_y_field != NULL);

      memcpy(exchange_buffer,
             public_key_x_field,
             public_key_field_len);
      memcpy(exchange_buffer + public_key_field_len,
             public_key_y_field,
             public_key_field_len);
      reverse_buffer(exchange_buffer, public_key_field_len);
      reverse_buffer(exchange_buffer + public_key_field_len,
                     public_key_field_len);
    }

  return;
}

SshCryptoStatus
ssh_fl_group_dh_setup(unsigned char *exchange_buffer,
                      size_t exchange_buffer_len,
                      void *context)
{
  SshFlGroupContext group_context = (SshFlGroupContext) context;
  SshCryptoStatus status;
  unsigned char *pubkey_buffer = NULL;
  size_t pubkey_buffer_len;
  SshFlGroupDHOperationStore operationstore = NULL;

  FL_RV fl_rv;
  FL_KeyAsset_t private_key = FL_ASSET_INVALID;
  FL_KeyAsset_t public_key = FL_ASSET_INVALID;
  FL_AssetGenerateKeyPairArgs_t args;
  FL_U32_t pubkey_return_len;

  pubkey_buffer_len = group_context->pubkey_asset_size;

  pubkey_buffer = ssh_malloc(pubkey_buffer_len);

  if (pubkey_buffer == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  SSH_FL_ASSETALLOCATE(fl_rv, group_context->key_derive_policy |
                           FL_POLICY_FLAG_PUBLIC_KEY,
                           group_context->pubkey_asset_size,
                           0,
                           &public_key);

  if (fl_rv != FLR_OK)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  SSH_FL_ASSETALLOCATE(fl_rv, group_context->key_derive_policy,
                           group_context->prvkey_asset_size,
                           0,
                           &private_key);

  if (fl_rv != FLR_OK)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetAllocate(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  if (group_context->domain_parameters != FL_ASSET_INVALID)
    {
      /* In DSA use domain parameters */
      args.Algorithm.DSAKeyPairGeneration.DSADomainParameterAsset =
        group_context->domain_parameters;
      args.Algorithm.DSAKeyPairGeneration.gIndex = 'F';

      fl_rv = FL_AssetGenerateKeyPair(private_key, public_key, &args);
    }
  else
    {
      /* In ECDSA the curves are pre-set based on key size */
      fl_rv = FL_AssetGenerateKeyPair(private_key, public_key, NULL);
    }

  if (fl_rv != FLR_OK)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetGenerateKeyPair(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  fl_rv = FL_AssetShow(public_key, FL_EXAMINE_PUBLIC_KEY,
                       pubkey_buffer, pubkey_buffer_len,
                       &pubkey_return_len);

  if (fl_rv != FLR_OK)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_AssetShow(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  fl_public_key_buffer_read_exchange(pubkey_buffer,
                                     pubkey_buffer_len,
                                     exchange_buffer,
                                     exchange_buffer_len,
                                     group_context->group_type);


  operationstore = ssh_malloc(sizeof(SshFlGroupDHOperationStoreStruct));

  if (operationstore == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  operationstore->private_key = private_key;

  operationstore->exchange = ssh_malloc(exchange_buffer_len);

  if (operationstore->exchange == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
      goto fail;
    }

  memcpy(operationstore->exchange, exchange_buffer, exchange_buffer_len);
  operationstore->exchange_len = exchange_buffer_len;

  operationstore->next = group_context->store;
  group_context->store = operationstore;

  SSH_DEBUG(SSH_D_LOWOK, ("Successfully setup DH agreement"));

  /* Cleanup */
  ssh_free(pubkey_buffer);

  return SSH_CRYPTO_OK;

 fail:
  if (private_key != FL_ASSET_INVALID)
    SSH_FL_ASSETFREE(private_key);
  if (public_key != FL_ASSET_INVALID)
    SSH_FL_ASSETFREE(public_key);

  if (pubkey_buffer != NULL)
    ssh_free(pubkey_buffer);

  if (operationstore != NULL)
    {
      if (operationstore->exchange != NULL)
        ssh_free(operationstore->exchange);

      ssh_free(operationstore);
    }

  return status;
}

SshCryptoStatus
ssh_fl_group_dh_agree(unsigned char *remote_exchange_buffer,
                      size_t remote_exchange_buffer_len,
                      unsigned char *local_exchange_buffer,
                      size_t local_exchange_buffer_len,
                      unsigned char *shared_buffer,
                      size_t shared_buffer_len,
                      void *context)
{
  SshFlGroupContext group_context = (SshFlGroupContext) context;
  SshCryptoStatus status;
  SshFlGroupDHOperationStore operationstore, prev_store;

  FL_KeyAsset_t private_key = FL_ASSET_INVALID;
  FL_RV fl_rv;

  operationstore = group_context->store;
  prev_store = NULL;

  SSH_ASSERT(operationstore != NULL);
  SSH_ASSERT(operationstore->exchange != NULL);
  SSH_ASSERT(operationstore->exchange_len == local_exchange_buffer_len);

  /* Find the correct operationstore */
  while (memcmp(operationstore->exchange,
                local_exchange_buffer,
                local_exchange_buffer_len) != 0)
    {
      prev_store = operationstore;
      operationstore = operationstore->next;

      if (operationstore == NULL)
        {
          status = SSH_CRYPTO_OPERATION_FAILED;
          SSH_DEBUG(SSH_D_FAIL, ("Failed to find DH operation secret"));
          goto fail;
        }
    }

  /* Remove reference to the store */
  if (prev_store == NULL)
    {
      /* First one matched */
      group_context->store = group_context->store->next;
    }
  else
    {
      prev_store->next = operationstore->next;
    }

  /* Store private key and free everything else */
  private_key = operationstore->private_key;
  ssh_free(operationstore->exchange);
  ssh_free(operationstore);

  if (group_context->group_type != SSH_FL_GROUP_TYPE_ECDSA_521)
    {
      fl_rv = FL_DeriveDh(private_key,
                          remote_exchange_buffer, remote_exchange_buffer_len,
                          shared_buffer, shared_buffer_len);
    }
  else
    {
      /* 521-bit curve uses 4-byte blocks so buffer lengths must be
         divisible by 4 */
      unsigned char *temp_secret = NULL, *temp_exchange = NULL;

      SSH_ASSERT(shared_buffer_len == 66);
      SSH_ASSERT(remote_exchange_buffer_len == 132);

      temp_secret = ssh_malloc(68);
      temp_exchange = ssh_malloc(136);

      if ((temp_secret == NULL) || (temp_exchange == NULL))
        {
          if (temp_secret != NULL)
            ssh_free(temp_secret);

          if (temp_exchange != NULL)
            ssh_free(temp_exchange);

          SSH_DEBUG(SSH_D_FAIL, ("Memory allocation failed"));
          status = SSH_CRYPTO_NO_MEMORY;
          goto fail;
        }

      memset(temp_exchange, 0x00, 136);
      memset(temp_secret, 0x00, 68);

      memcpy(temp_exchange + 2, remote_exchange_buffer, 66);
      memcpy(temp_exchange + 2 + 68, remote_exchange_buffer + 66, 66);

      fl_rv = FL_DeriveDh(private_key,
                          temp_exchange, 136,
                          temp_secret, 68);

      memcpy(shared_buffer, temp_secret + 2, shared_buffer_len);

      ssh_free(temp_secret);
      ssh_free(temp_exchange);
    }

  if (fl_rv != FLR_OK)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      SSH_DEBUG(SSH_D_FAIL, ("Failed FL_DeriveDh(): %s",
                             ssh_fl_rv_to_string(fl_rv)));
      goto fail;
    }

  SSH_FL_ASSETFREE(private_key);

  SSH_DEBUG(SSH_D_LOWOK, ("Created DH agreement"));

  return SSH_CRYPTO_OK;

 fail:
  return status;
}
