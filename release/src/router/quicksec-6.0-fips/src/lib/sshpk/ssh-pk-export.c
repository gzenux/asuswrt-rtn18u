/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface code for exporting and importing public key objects.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshpk_i.h"
#include "sshrandom_i.h"
#include "crypto_tests.h"
#include "sshhash_i.h"

#define SSH_DEBUG_MODULE "SshPkExport"

/* Magic numbers used for validy checks in SSH public key
   exported octet formats. These are all version 1 formats. */
#define SSH_PK_GROUP_RANDOMIZER_MAGIC 0x4c9356fe
#define SSH_PK_GROUP_MAGIC            0x89578271
#define SSH_PUBLIC_KEY_MAGIC          0x65c8b28a
#define SSH_PRIVATE_KEY_MAGIC         0x3f6ff9eb

/* Consistent post-1 version format magic identifier. */
#define SSH_CRYPTO_COMMON_ENVELOPE_MAGIC   0xc4181f9e

/************************************************************************/

/* This is enumeration of values of the 32-bit field `type' in the
   common envelope format */
enum {
  SSH_CRYPTO_COMMON_ENVELOPE_TYPE_RESERVED = 0,
  SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PRIVATE_KEY = 1,
  SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PUBLIC_KEY = 2,
  SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PK_GROUP = 3,
  SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PK_GROUP_RANDOMIZERS = 4
};

typedef struct SshPkImportStateRec *SshPkImportState;

/* First init. All fields apart from the `init', `buf' and `buflen'
   are uninitialized. This routine is expected to look at the head of
   the buffer, and determine whether it is recognized format. If so,
   it must set further `state' callbacks to correct values and perform
   any required initialization on `prv' and return
   SSH_CRYPTO_OK. If the envelope format is not recognized, this must
   return SSH_CRYPTO_NO_MATCH. Any other return value terminates
   the import process. */
typedef SshCryptoStatus (*SshPkImportInitFunc)(SshPkImportState state);

typedef struct SshPkImportStateRec {
  /* Global state -- set by the master routine */

  /* Buffer, buffer length, current point in the buffer */
  const unsigned char *buf;
  size_t buf_len, point;

  /* Decryption key, and decryption key length */
  const unsigned char *decrypt_key;
  size_t decrypt_key_len;

  /* Randomizers are imported into this PK Group */
  SshPkGroupObject pk_group_randomizers;

  /* Global state -- set by the slave routine, read and freed by the
     master routine */

  /* Total length of this envelope */
  size_t envelope_length;

  /* Object type (pub/prv/grp) */
  SshPkFormat type;

  /* Object envelope version */
  SshUInt32 version;

  /* Cipher name */
  char *cipher_name;

  /* Cipher key length */
  size_t cipher_key_len;

  /* Hash name */
  char *hash_name;

  /* Union of different possible import data formats -- slave
     allocates this, but master is responsible for freeing it (under
     error conditions, under normal circumstances it is turned into a
     proper handle and passed to user).  */
  union {
    SshPrivateKeyObject private_key;
    SshPublicKeyObject public_key;
    SshPkGroupObject pk_group;
  } imported;

  /* Callbacks used by the master routine to call slace routine */

  /* Analyse phase (first/header pass). This is expected to fill the
     global variables that can be filled without accessing the actual
     data part of the envelope. After this call the `type', `version',
     `cipher_name', `cipher_key_len', `hash_name' fields should be
     set.

     Notice that if necessary, most of the work of `analyze' can also
     be done during `init'. */
  SshCryptoStatus (*analyze)(SshPkImportState state);

  /* Perform actual low-level import operation. Notice that one of
     `private_key', `public_key' or `pk_group' has at this point a
     valid object that can be used by the routine (`type' is used by
     the master routine which one is initialized). This routine is
     expected to perform the actual data import on the object
     level. */
  SshCryptoStatus (*import)(SshPkImportState state);

  /* Release all private resources. This terminates import
     process. This routine may modify only the `prv' contents. Only
     `type' and `version' are guaranteed to be still valid of the
     other fields. This routine is called also if `analyze' or
     `import' return an error code. */
  void (*release)(SshPkImportState state);

  /* Private data for the slave routines -- union of all requirements */
  union {
    struct {
      char *key_type;
      size_t data_len;
      unsigned char *decrypted_data;
    } v1_prv;
    struct {
      char *key_type;
      size_t data_len;
    } v1_pub;
    struct {
      char *key_type;
      size_t data_len;
    } v1_grp;
    struct {
      SshUInt32 type;
      SshUInt32 data_off, total_len;
    } v2;
  } prv;
} SshPkImportStateStruct;

/*******************  V1 private key format *****************************/

static SshCryptoStatus
ssh_pk_import_v1_prv_import(SshPkImportState state)
{
  const unsigned char *data;
  SshCipher cipher;
  SshUInt32 tmp_length;
  SshCryptoStatus status;
  int used;
  SshPrivateKeyObject private_key;
  size_t data_len;

  SSH_ASSERT(state->cipher_name != NULL);
  SSH_ASSERT(!state->hash_name);

  data_len = state->prv.v1_prv.data_len;

  /* Decrypt the block if necessary */
  if (strcmp(state->cipher_name, "none") != 0)
    {
      unsigned char *tmp;

      /* Need to allocate block for the decrypted data */
      if (!(tmp = ssh_crypto_malloc_i(data_len)))
        return SSH_CRYPTO_NO_MEMORY;

      /* state->prv.v1_prv.decrypted_data is freed in release routine */
      data = state->prv.v1_prv.decrypted_data = tmp;

      /* Allocate the cipher */
      status = ssh_cipher_allocate(state->cipher_name,
                                   state->decrypt_key, state->decrypt_key_len,
                                   FALSE, &cipher);

      if (status != SSH_CRYPTO_OK)
        return status;

      status = ssh_cipher_start(cipher);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          return status;
        }

      status = ssh_cipher_transform(cipher,
                                    state->prv.v1_prv.decrypted_data,
                                    state->buf + state->point, data_len);

      ssh_cipher_free(cipher);

      if (status != SSH_CRYPTO_OK)
        return status;
    }
  else
    data = state->buf + state->point;

  if ((used =
       ssh_decode_array(data, data_len,
                        SSH_DECODE_UINT32(&tmp_length),
                        SSH_FORMAT_END)) == 0)
    return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;

  /* If decryption failed, the first word eg. length might be corrupted */
  if (tmp_length > (data_len - used))
    return SSH_CRYPTO_INVALID_PASSPHRASE;

  if ((status = ssh_private_key_object_allocate(state->prv.v1_prv.key_type,
                                                &private_key))
      != SSH_CRYPTO_OK)
    return status;

  /* Set the scheme information from the key name. */
  status =
    ssh_private_key_set_scheme_from_key_name(private_key,
                                             state->prv.v1_prv.key_type);

  if (status != SSH_CRYPTO_OK)
    {
      ssh_private_key_object_free(private_key);
      return status;
    }

  /* Check whether this key type actually supports import */
  if (private_key->type->private_key_import == NULL_FNPTR)
    {
      ssh_private_key_object_free(private_key);
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Perform actual import */
  if ((status =
       (*private_key->type->private_key_import)(data + used, tmp_length,
                                                &(private_key->context)))
      != SSH_CRYPTO_OK)
    {
      ssh_private_key_object_free(private_key);
      return status;
    }

  state->imported.private_key = private_key;

  return SSH_CRYPTO_OK;
}

static void
ssh_pk_import_v1_prv_free(SshPkImportState state)
{
  ssh_crypto_free_i(state->prv.v1_prv.decrypted_data);
  ssh_free(state->prv.v1_prv.key_type);
}

static SshCryptoStatus
ssh_pk_import_v1_prv_init(SshPkImportState state)
{
  int used;
  SshUInt32 pk_magic, pk_length, data_len;
  char *key_type, *cipher_name;

  key_type = cipher_name = NULL;

  if ((used =
       ssh_decode_array(state->buf, state->buf_len,
                        SSH_DECODE_UINT32(&pk_magic),
                        SSH_DECODE_UINT32(&pk_length),
                        SSH_DECODE_UINT32_SSTR(&key_type, NULL),
                        SSH_DECODE_UINT32_SSTR(&cipher_name, NULL),
                        SSH_DECODE_UINT32(&data_len),
                        SSH_FORMAT_END)) == 0)
    return SSH_CRYPTO_NO_MATCH;

  if (pk_magic != SSH_PRIVATE_KEY_MAGIC)
    {
      ssh_free(key_type);
      ssh_free(cipher_name);
      return SSH_CRYPTO_NO_MATCH;
    }

  if (pk_length < 8 || data_len > (state->buf_len - used))
    {
      ssh_free(key_type);
      ssh_free(cipher_name);
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  state->envelope_length = pk_length;
  state->type = SSH_PKF_PRIVATE_KEY;
  state->version = SSH_CRYPTO_ENVELOPE_VERSION_1;

  state->cipher_name = cipher_name;

  state->analyze = NULL;
  state->import = ssh_pk_import_v1_prv_import;
  state->release = ssh_pk_import_v1_prv_free;

  state->prv.v1_prv.key_type = key_type;
  state->prv.v1_prv.data_len = data_len;
  state->prv.v1_prv.decrypted_data = NULL;

  state->point = used;

  return SSH_CRYPTO_OK;
}

/*******************  V1 public key format ******************************/

static SshCryptoStatus
ssh_pk_import_v1_pub_import(SshPkImportState state)
{
  const unsigned char *data;
  SshCryptoStatus status;
  SshPublicKeyObject public_key;

  SSH_ASSERT(!state->cipher_name);
  SSH_ASSERT(!state->hash_name);

  data = state->buf + state->point;

  if ((status = ssh_public_key_object_allocate(state->prv.v1_prv.key_type,
                                                &public_key))
      != SSH_CRYPTO_OK)
    return status;

  /* Set the scheme information from the key name. */
  status =
    ssh_public_key_set_scheme_from_key_name(public_key,
                                            state->prv.v1_pub.key_type);

  if (status != SSH_CRYPTO_OK)
    {
      ssh_public_key_object_free(public_key);
      return status;
    }

  /* Check whether this key type actually supports import */
  if (public_key->type->public_key_import == NULL_FNPTR)
    {
      ssh_public_key_object_free(public_key);
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Perform actual import */
  if ((status =
       (*public_key->type->public_key_import)(data,
                                              state->prv.v1_pub.data_len,
                                              &(public_key->context)))
      != SSH_CRYPTO_OK)
    {
      ssh_public_key_object_free(public_key);
      return status;
    }

  state->imported.public_key = public_key;

  return SSH_CRYPTO_OK;
}

static void
ssh_pk_import_v1_pub_free(SshPkImportState state)
{
  ssh_free(state->prv.v1_pub.key_type);
}

static SshCryptoStatus
ssh_pk_import_v1_pub_init(SshPkImportState state)
{
  int used;
  SshUInt32 pk_magic, pk_length, data_len;
  char *key_type;

  key_type = NULL;

  if ((used = ssh_decode_array(state->buf, state->buf_len,
                               SSH_DECODE_UINT32(&pk_magic),
                               SSH_DECODE_UINT32(&pk_length),
                               SSH_DECODE_UINT32_SSTR(&key_type, NULL),
                               SSH_DECODE_UINT32(&data_len),
                               SSH_FORMAT_END)) == 0)
    return SSH_CRYPTO_NO_MATCH;

  if (pk_magic != SSH_PUBLIC_KEY_MAGIC)
    {
      ssh_free(key_type);
      return SSH_CRYPTO_NO_MATCH;
    }

  if (pk_length < 8 || data_len > (state->buf_len - used))
    {
      ssh_free(key_type);
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  state->envelope_length = pk_length;
  state->type = SSH_PKF_PUBLIC_KEY;
  state->version = SSH_CRYPTO_ENVELOPE_VERSION_1;

  state->analyze = NULL;
  state->import = ssh_pk_import_v1_pub_import;
  state->release = ssh_pk_import_v1_pub_free;

  state->prv.v1_pub.key_type = key_type;
  state->prv.v1_pub.data_len = data_len;

  state->point = used;

  return SSH_CRYPTO_OK;
}

/*******************  V1 PK group format ********************************/

static SshCryptoStatus
ssh_pk_import_v1_grp_import(SshPkImportState state)
{
  const unsigned char *data;
  SshCryptoStatus status;
  SshPkGroupObject pk_group;

  SSH_ASSERT(!state->cipher_name);
  SSH_ASSERT(!state->hash_name);

  data = state->buf + state->point;

  if ((status = ssh_pk_group_object_allocate(state->prv.v1_grp.key_type,
                                             &pk_group)) != SSH_CRYPTO_OK)
    return status;

  /* Set the scheme information from the key name. */
  status =
    ssh_pk_group_set_scheme_from_key_name(pk_group,
                                          state->prv.v1_grp.key_type);

  if (status != SSH_CRYPTO_OK)
    {
      ssh_pk_group_object_free(pk_group);
      return status;
    }

  /* Check whether this key type actually supports import */
  if (pk_group->type->pk_group_import == NULL_FNPTR)
    {
      ssh_pk_group_object_free(pk_group);
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Perform actual import */
  if ((status =
       (*pk_group->type->pk_group_import)(data,
                                          state->prv.v1_pub.data_len,
                                          &(pk_group->context)))
      != SSH_CRYPTO_OK)
    {
      ssh_pk_group_object_free(pk_group);
      return status;
    }

  state->imported.pk_group = pk_group;

  return SSH_CRYPTO_OK;
}

static void
ssh_pk_import_v1_grp_free(SshPkImportState state)
{
  ssh_free(state->prv.v1_grp.key_type);
}

static SshCryptoStatus
ssh_pk_import_v1_grp_init(SshPkImportState state)
{
  int used;
  SshUInt32 pk_magic, pk_length, data_len;
  char *key_type;

  key_type = NULL;

  if ((used = ssh_decode_array(state->buf, state->buf_len,
                               SSH_DECODE_UINT32(&pk_magic),
                               SSH_DECODE_UINT32(&pk_length),
                               SSH_DECODE_UINT32_SSTR(&key_type, NULL),
                               SSH_DECODE_UINT32(&data_len),
                               SSH_FORMAT_END)) == 0)
    return SSH_CRYPTO_NO_MATCH;

  if (pk_magic != SSH_PK_GROUP_MAGIC)
    {
      ssh_free(key_type);
      return SSH_CRYPTO_NO_MATCH;
    }

  if (pk_length < 8 || data_len > (state->buf_len - used))
    {
      ssh_free(key_type);
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  state->envelope_length = pk_length;
  state->type = SSH_PKF_PK_GROUP;
  state->version = SSH_CRYPTO_ENVELOPE_VERSION_1;

  state->analyze = NULL;
  state->import = ssh_pk_import_v1_grp_import;
  state->release = ssh_pk_import_v1_grp_free;

  state->prv.v1_grp.key_type = key_type;
  state->prv.v1_grp.data_len = data_len;

  state->point = used;

  return SSH_CRYPTO_OK;
}

/*******************  V1 group randomizer import ************************/

static SshCryptoStatus
ssh_pk_import_v1_randomizer_import(SshPkImportState state)
{
  size_t total_length, used;
  SshPkGroupObject group;
  SshUInt32 length;
  SshCryptoStatus status;

  if (!state->pk_group_randomizers)
    return SSH_CRYPTO_UNSUPPORTED; /* Parameter problem */

  group = state->pk_group_randomizers;

  total_length = state->buf_len - state->point;

  while (total_length > 0)
    {
      if ((used =
           ssh_decode_array(state->buf + state->point,
                            state->buf_len - state->point,
                            SSH_DECODE_UINT32(&length),
                            SSH_FORMAT_END)) == 0)
        return SSH_CRYPTO_OPERATION_FAILED;

      state->point += used;

      status =
        (*group->type->pk_group_import_randomizer)(group->context,
                                                   state->buf + state->point,
                                                   length);

      if (status != SSH_CRYPTO_OK)
        return status;

      state->point += length;
      total_length -= (length + 4);
    }

  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
ssh_pk_import_v1_randomizer_init(SshPkImportState state)
{
  size_t used;
  SshUInt32 magic, total_length;

  if ((used = ssh_decode_array(state->buf, state->buf_len,
                               SSH_DECODE_UINT32(&magic),
                               SSH_DECODE_UINT32(&total_length),
                               SSH_FORMAT_END)) == 0)
    return SSH_CRYPTO_NO_MATCH;

  if (magic != SSH_PK_GROUP_RANDOMIZER_MAGIC)
    return SSH_CRYPTO_NO_MATCH;

  state->envelope_length = total_length;
  state->type = SSH_PKF_PK_GROUP_RANDOMIZERS;
  state->version = SSH_CRYPTO_ENVELOPE_VERSION_1;

  state->analyze = NULL;
  state->import = ssh_pk_import_v1_randomizer_import;
  state->release = NULL;

  state->point = used;

  return SSH_CRYPTO_OK;
}

/*******************  V2 common format handling *************************/







































































static SshCryptoStatus
ssh_pk_import_v2_import(SshPkImportState state)
{
  SshCryptoStatus status;
  const char *key_type;
  const unsigned char *data, *payload, *point, *header;
  const unsigned char *digest, *exported, *encrypted;
  unsigned char *decrypted;
  size_t payload_len, digest_len, iv_len, encrypted_len, header_len;
  size_t decrypted_len, exported_len;
  SshUInt32 data_len, randomizer_cnt;
  SshPrivateKeyObject private_key;
  SshPublicKeyObject public_key;
  SshPkGroupObject pk_group;
  int i;

  /* NB: I know there are a lot of variables that are just used for
     placeholding. This routine is long, and it is much better to use
     a single variable for a single purpose instead of littering the
     code with variable re-use or magic constants. This is a) not
     typically on critical code path and b) compiler should optimize
     most of the (through lifetime analysis or assignment folding)
     away. */

  /* Get pointer to start of encrypted part (it is not necessarily
     encrypted, but we use that name). Let us separate the header and
     header len for later convenience.  */
  encrypted = state->buf + state->prv.v2.data_off;
  encrypted_len = state->prv.v2.total_len - state->prv.v2.data_off;
  SSH_ASSERT(encrypted < (state->buf + state->buf_len));

  header = state->buf;
  header_len = state->prv.v2.data_off;

  /* First task, decrypt the combined payload and digest */
  if (strcmp(state->cipher_name, "none") != 0)
    {
      SshCipher cipher;
      size_t block_len;

      /* First allocate the cipher. This verifies its name. */
      status =
        ssh_cipher_allocate(state->cipher_name,
                            state->decrypt_key, state->decrypt_key_len,
                            FALSE, &cipher);

      if (status != SSH_CRYPTO_OK)
        return status;

      /* Cipher is ok, check that the `encrypted_len' is multiple of
         cipher block size */
      block_len = ssh_cipher_get_block_length(state->cipher_name);
      SSH_ASSERT(block_len > 0);

      if ((encrypted_len % block_len) != 0)
        {
          ssh_cipher_free(cipher);
          /*DUMP(state, "invalid block length", 0);*/
          return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
        }

      /* Allocate memory for decryption result */
      if (!(decrypted = ssh_crypto_malloc_i(encrypted_len)))
        {
          ssh_cipher_free(cipher);
          return SSH_CRYPTO_NO_MEMORY;
        }

      status = ssh_cipher_start(cipher);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          goto common_error;
        }

      status =
        ssh_cipher_transform(cipher, decrypted, encrypted, encrypted_len);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          goto common_error;
        }

      /* Cipher instance no longer needed */
      ssh_cipher_free(cipher);

      /* Set IV size based on the cipher block size */
      iv_len = block_len == 1 ? 0 : block_len;
    }
  else
    {
      iv_len = 0;
      decrypted = (unsigned char *)encrypted;
    }

  /* Always same */
  decrypted_len = encrypted_len;

  /* Digest size? */
  if (strcmp(state->hash_name, "none") != 0)
    digest_len = ssh_hash_digest_length(state->hash_name);
  else
    digest_len = 0;

  /* Sanity checks, there must be space for at least iv, digest and
     the 4-byte data size in the decrypted part */
  if (decrypted_len < (iv_len + digest_len + 4))
    {
      status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      /*DUMP(state, "sanity", 0);*/
      goto common_error;
    }

  /* Digest is at end of decrypted part */
  digest = decrypted + decrypted_len - digest_len;

  /* Now we have encrypted part neatly sorted out. Let's actually
     verify the hash digest now. */
  if (strcmp(state->hash_name, "none") != 0)
    {
      SshHash hash;

      status = ssh_hash_allocate(state->hash_name, &hash);

      if (status != SSH_CRYPTO_OK)
        goto common_error;

      /* Calculate over the whole plaintext message (except the digest
         part) */

      status = ssh_hash_compare_start(hash, digest, digest_len);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_hash_free(hash);
          goto common_error;
        }

      ssh_hash_update(hash, header, header_len);
      ssh_hash_update(hash, decrypted, decrypted_len - digest_len);

      status = ssh_hash_compare_result(hash);
      ssh_hash_free(hash);

      if (status != SSH_CRYPTO_OK)
        {
          status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
          goto common_error;
        }
    }

  /* Now separate digest from payload and iv */
  payload = decrypted + iv_len;
  payload_len = decrypted_len - digest_len - iv_len;

  /* Then separate data from payload and padding */
  data_len = SSH_GET_32BIT(payload);

  /* And of course, data may not be larger than there is space.. */
  if (data_len > (payload_len - 4))
    {
      status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      /*DUMP(state, "data length", 0);*/
      goto common_error;
    }

  /* Verify padding -- it should be 100... */
  for (i = 0; i < (payload_len - data_len - 4); i++)
    if (payload[data_len + 4 + i] !=
        (i == 0 ? 0x80 : 0x00))
      {
        status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
        /*DUMP(state, "padding", 0);*/
        goto common_error;
      }

  data = payload + 4;

  /* Signature has been verified. Let us now decode the actual data,
     eg. generate the underlying prv/pub/group object, or import the
     randomizers to an existing group. */
  if (state->type == SSH_PKF_PRIVATE_KEY ||
      state->type == SSH_PKF_PUBLIC_KEY ||
      state->type == SSH_PKF_PK_GROUP)
    {
      /* Extract key type (string) */
      for (point = data, key_type = (const char *)data;
           point < (data + data_len) && *point;
           point++);

      if ((point + 1) >= (data + data_len) || !*key_type)
        {
          status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
          /*DUMP(state, "key type", 0);*/
          goto common_error;
        }

      exported = point + 1;
      exported_len = data + data_len - exported;

      SSH_ASSERT(exported_len < data_len);

      switch (state->type)
        {
        case SSH_PKF_PRIVATE_KEY:
          if ((status =
               ssh_private_key_object_allocate(key_type, &private_key))
              != SSH_CRYPTO_OK)
            goto common_error;

          if ((status = (*private_key->type->private_key_import)
               (exported, exported_len, &(private_key->context)))
              != SSH_CRYPTO_OK)
            {
              ssh_private_key_object_free(private_key);
              /*DUMP(state, "private key", status);*/
              goto common_error;
            }

          state->imported.private_key = private_key;
          break;

        case SSH_PKF_PUBLIC_KEY:
          if ((status =
               ssh_public_key_object_allocate(key_type, &public_key))
              != SSH_CRYPTO_OK)
            goto common_error;

          if ((status = (*public_key->type->public_key_import)
               (exported, exported_len, &(public_key->context)))
              != SSH_CRYPTO_OK)
            {
              ssh_public_key_object_free(public_key);
              /*DUMP(state, "public key", status);*/
              goto common_error;
            }

          state->imported.public_key = public_key;
          break;

        case SSH_PKF_PK_GROUP:
          if ((status =
               ssh_pk_group_object_allocate(key_type, &pk_group))
              != SSH_CRYPTO_OK)
            goto common_error;

          if ((status = (*pk_group->type->pk_group_import)
               (exported, exported_len, &(pk_group->context)))
              != SSH_CRYPTO_OK)
            {
              ssh_pk_group_object_free(pk_group);
              /*DUMP(state, "group", status);*/
              goto common_error;
            }

          state->imported.pk_group = pk_group;
          break;

        default:
          SSH_NOTREACHED;
        }

      /* All is done! Success. */
    }
  else if (state->type == SSH_PKF_PK_GROUP_RANDOMIZERS)
    {
      int count;
      SshUInt32 len;

      pk_group = state->pk_group_randomizers;
      SSH_ASSERT(pk_group != NULL);
      SSH_ASSERT(pk_group->type->pk_group_import_randomizer != NULL_FNPTR);

      /* Extract randomizer count */
      if (data_len < 4)
        {
          status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
          /*DUMP(state, "randomizers total length", 0);*/
          goto common_error;
        }

      randomizer_cnt = SSH_GET_32BIT(data);

      data += 4;
      data_len -= 4;
      count = 0;

      while (data_len > 4)
        {
          len = SSH_GET_32BIT(data);

          if ((data_len - 4) < len)
            {
              status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
              /*DUMP(state, "randomizer length", 0);*/
              goto common_error;
            }

          status =
            (*pk_group->type->pk_group_import_randomizer)(pk_group->context,
                                                          data + 4, len);

          if (status != SSH_CRYPTO_OK)
            {
              /*DUMP(state, "randomizer", status);*/
              goto common_error;
            }

          data += 4 + len;
          data_len -= 4 + len;
          count++;
        }

      if (count != randomizer_cnt)
        {
          status = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
          /*DUMP(state, "randomizer count", 0);*/
          goto common_error;
        }

      /* Success. All done. */
    }
  else
    SSH_NOTREACHED;

  status = SSH_CRYPTO_OK;

 common_error:

  if (strcmp(state->cipher_name, "none") != 0)
    ssh_crypto_free_i(decrypted);

  return status;
}

static SshCryptoStatus
ssh_pk_import_v2_init(SshPkImportState state)
{
  SshUInt32 type, total_len, cipher_key_len;
  const char *cipher_name, *hash_name;
  const unsigned char *buf_end, *point;
  SshPkFormat envelope_type;

  /* At least minimum size header, 12 bytes */
  if (state->buf_len < 12 ||
      SSH_GET_32BIT(state->buf) != SSH_CRYPTO_COMMON_ENVELOPE_MAGIC)
    return SSH_CRYPTO_NO_MATCH;

  /* Verify length */
  total_len = SSH_GET_32BIT(state->buf + 4);

  if (total_len > state->buf_len)
    return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;

  /* Verify type */
  type = SSH_GET_32BIT(state->buf + 8);

  switch (type)
    {
    case SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PRIVATE_KEY:
      envelope_type = SSH_PKF_PRIVATE_KEY; break;
    case SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PUBLIC_KEY:
      envelope_type = SSH_PKF_PUBLIC_KEY; break;
    case SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PK_GROUP:
      envelope_type = SSH_PKF_PK_GROUP; break;
    case SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PK_GROUP_RANDOMIZERS:
      envelope_type = SSH_PKF_PK_GROUP_RANDOMIZERS; break;
    default:
      return SSH_CRYPTO_NO_MATCH;
    }

  /* Buffer end pointer */
  buf_end = state->buf + total_len;

  /* Decode all we can from the visible header */
  for (point = state->buf + 12, cipher_name = (const char *)point;
       point < buf_end && *point;
       point++);

  if (point >= buf_end)
    {
      /*state->type = envelope_type; DUMP(state, "cipher name", 0);*/
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  SSH_ASSERT(!*point);

  if ((point + 4) >= buf_end)
    {
      /*state->type = envelope_type; DUMP(state, "cipher key len", 0);*/
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  cipher_key_len = SSH_GET_32BIT(point); point += 4;

  for (point = point + 1, hash_name = (const char *)point;
       point < buf_end && *point;
       point++);

  if ((point + 1) >= buf_end)
    {
      /*state->type = envelope_type; DUMP(state, "hash name", 0);*/
      return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
    }

  SSH_ASSERT(!*point);

  /* Must be "none" if not used, eg. at least one character long */
  if (!*cipher_name || !*hash_name)
    return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;

  /* All the rest is payload, either encrypted or decrypted, but we
     don't look into it at this point. Set state variables. */

  state->envelope_length = total_len;
  state->type = envelope_type;
  state->version = SSH_CRYPTO_ENVELOPE_VERSION_2;

  state->analyze = NULL;
  state->import = ssh_pk_import_v2_import;
  state->release = NULL;

  state->cipher_name = ssh_strdup(cipher_name);
  state->cipher_key_len = cipher_key_len;
  state->hash_name = ssh_strdup(hash_name);

  if (!state->cipher_name || !state->hash_name)
    {
      ssh_free(state->cipher_name);
      ssh_free(state->hash_name);

      return SSH_CRYPTO_NO_MEMORY;
    }

  state->prv.v2.type = type;
  SSH_ASSERT((point - state->buf) <= total_len);
  state->prv.v2.data_off = (SshUInt32) (point - state->buf + 1);
  state->prv.v2.total_len = total_len;

  return SSH_CRYPTO_OK;
}

/************************************************************************/

/* Array of known import functions */
const
static SshPkImportInitFunc ssh_pk_import_init_functions[] =
  {
    ssh_pk_import_v1_prv_init,
    ssh_pk_import_v1_pub_init,
    ssh_pk_import_v1_grp_init,
    ssh_pk_import_v1_randomizer_init,
    ssh_pk_import_v2_init,
    NULL
  };

/* Perform prv/pub/grp import operation on a buffer `buf' of length
   `buflen'. Returns SSH_CRYPTO_OK if the data requested was
   successfully imported, otherwise returns some error code. On
   successfull operations the `*consumed_ret' will contain how many
   bytes were "used" from the buffer. Note that the `consumed_ret'
   value is guaranteed to be non-zero only if you are actually
   importing a key/group -- for envelope query operations it can be
   zero or non-zero (if it is non-zero, it is however the correct
   value).

   The variable length argument list contains list of import-specific
   SSH_PKF_* keywords terminated with SSH_PKF_END. For example the
   following will import a public key (and also return information
   about the public key encoding version):

   status = ssh_pk_import(buf, buflen, &used,
        SSH_PKF_PUBLIC_KEY, &pub,
                SSH_PKF_EXPORT_VERSION, &vers,
                SSH_PKF_END);

*/

SshCryptoStatus
ssh_pk_import(const unsigned char *buf, size_t buflen,
              size_t *consumed_ret, ...)
{
  SshPkImportStateStruct state;
  SshCryptoStatus status;
  int i;
  SshPrivateKey *private_key_ret, private_key;
  SshPublicKey *public_key_ret, public_key;
  SshPkGroup *pk_group_ret, pk_group, pk_group_randomizers;
  Boolean do_import;
  va_list ap;
  SshPkFormat format, import_type;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  private_key_ret = NULL;
  public_key_ret = NULL;
  pk_group_ret = NULL;
  private_key = NULL;
  public_key = NULL;
  pk_group = pk_group_randomizers = NULL;
  do_import = FALSE;

  memset(&state, 0, sizeof(state));
  state.buf = buf;
  state.buf_len = buflen;
  state.point = 0;

  for (i = 0; ssh_pk_import_init_functions[i] != NULL; i++)
    {
      status = (*ssh_pk_import_init_functions[i])(&state);

      if (status == SSH_CRYPTO_OK)
        break;

      if (status != SSH_CRYPTO_NO_MATCH)
        return status;
    }

  if (ssh_pk_import_init_functions[i] == NULL)
    return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;

  /* Perform analysis */
  if (state.analyze)
    {
      status = (*state.analyze)(&state);

      if (status != SSH_CRYPTO_OK)
        goto error_common;
    }

  /* Iterate through the argument list, fill all the data we can at
     this point */

  if (consumed_ret)
    *consumed_ret = state.envelope_length;

  va_start(ap, consumed_ret);
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      switch (format)
        {
          /* These are all data we can fill now */
        case SSH_PKF_ENVELOPE_CONTENTS:
          *va_arg(ap, SshPkFormat *) = state.type;
          break;

        case SSH_PKF_ENVELOPE_VERSION:
          *va_arg(ap, SshUInt32 *) = state.version;
          break;

        case SSH_PKF_CIPHER_NAME:
          if (state.cipher_name)
            *va_arg(ap, char **) = ssh_strdup(state.cipher_name);
          else
            *va_arg(ap, char **) = NULL;
          break;

        case SSH_PKF_CIPHER_KEY_LEN:
          *va_arg(ap, size_t *) = state.cipher_key_len;
          break;

        case SSH_PKF_HASH_NAME:
          if (state.hash_name)
            *va_arg(ap, char **) = ssh_strdup(state.hash_name);
          else
            *va_arg(ap, char **) = NULL;
          break;

          /* This argument we must stored for a while */
        case SSH_PKF_CIPHER_KEY:
          state.decrypt_key = va_arg(ap, const unsigned char *);
          state.decrypt_key_len = va_arg(ap, size_t);
          break;

          /* These require that we must do a full import */
        case SSH_PKF_PRIVATE_KEY:
          private_key_ret = va_arg(ap, SshPrivateKey *);
          import_type = SSH_PKF_PRIVATE_KEY;
          goto import_common;
          break;

        case SSH_PKF_PUBLIC_KEY:
          public_key_ret = va_arg(ap, SshPublicKey *);
          import_type = SSH_PKF_PUBLIC_KEY;
          goto import_common;
          break;

        case SSH_PKF_PK_GROUP:
          pk_group_ret = va_arg(ap, SshPkGroup *);
          import_type = SSH_PKF_PK_GROUP;
          goto import_common;
          break;

        case SSH_PKF_PK_GROUP_RANDOMIZERS:
          pk_group_randomizers = va_arg(ap, SshPkGroup);
          if (!(state.pk_group_randomizers =
                SSH_CRYPTO_HANDLE_TO_PK_GROUP(pk_group_randomizers)))
            {
              va_end(ap);
              status = SSH_CRYPTO_HANDLE_INVALID;
              goto error_common;
            }
          import_type = SSH_PKF_PK_GROUP_RANDOMIZERS;
          goto import_common;

        import_common:
          if (do_import)
            {
              va_end(ap);
              status = SSH_CRYPTO_KEY_INVALID;
              goto error_common;
            }
          do_import = TRUE;
          if (state.type != import_type)
            {
              va_end(ap);
              status = SSH_CRYPTO_KEY_INVALID;
              goto error_common;
            }
          break;

        default:
          va_end(ap);
          status = SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
          goto error_common;
        }
    }

  va_end(ap);

  /* If not doing full import, finish here */
  if (!do_import)
    {
      if (state.release)
        (*state.release)(&state);
      ssh_free(state.cipher_name);
      ssh_free(state.hash_name);
      return SSH_CRYPTO_OK;
    }

  /* Perform full import */
  status = (*state.import)(&state);

  if (status != SSH_CRYPTO_OK)
    goto error_common;

  /* Now, one of state.imported is non-NULL, perform handle conversion
     and value pointers. */

  switch (state.type)
    {
    case SSH_PKF_PRIVATE_KEY:
      if (!state.imported.private_key)
        break;

      /* Test the consistency of the key. The crypto library
         does not directly enter an error state on failure because the
         private key is an imported key and its inconsistency does not
         necessarily imply any problem in the crypto library. Instead run
         the self tests, if these fail, then the library will uninitialize,
         otherwise just free the public key and return an error. */

      if (ssh_crypto_test_pk_private_consistency(state.imported.private_key)
          != SSH_CRYPTO_OK)
        {
          ssh_private_key_object_free(state.imported.private_key);

          /* However, we must ensure the we're returning correct ERROR
             return code, if the crypto lib went into error state */
          status =
            (ssh_crypto_library_get_status()
             == SSH_CRYPTO_LIBRARY_STATUS_ERROR) ?
            SSH_CRYPTO_LIBRARY_ERROR :
            SSH_CRYPTO_OPERATION_FAILED;
          goto error_common;
        }

      if (!ssh_crypto_library_object_use(state.imported.private_key,
                                         SSH_CRYPTO_OBJECT_TYPE_PRIVATE_KEY))
        {
          ssh_private_key_object_free(state.imported.private_key);
          status = SSH_CRYPTO_NO_MEMORY;
          goto error_common;
        }
      else
        private_key =
          SSH_CRYPTO_PRIVATE_KEY_TO_HANDLE(state.imported.private_key);
      break;

    case SSH_PKF_PUBLIC_KEY:
      if (!state.imported.public_key)
        break;

      if (!ssh_crypto_library_object_use(state.imported.public_key,
                                         SSH_CRYPTO_OBJECT_TYPE_PUBLIC_KEY))
        {
          ssh_public_key_object_free(state.imported.public_key);
          status = SSH_CRYPTO_NO_MEMORY;
          goto error_common;
        }
      else
        public_key =
          SSH_CRYPTO_PUBLIC_KEY_TO_HANDLE(state.imported.public_key);
      break;

    case SSH_PKF_PK_GROUP:
      if (!state.imported.pk_group)
        break;

#ifdef SSHDIST_CRYPT_GENPKCS_DH
#ifdef SSHDIST_CRYPT_SELF_TESTS
      /* Test the consistency of the group. The crypto library
         does not directly enter an error state on failure because
         the group is imported and its inconsistency does not necessarily
         imply any problem in the crypto library. Instead run the
         self tests, if these fail, then the library will uninitialize,
         otherwise just free the imported group and return an error. */
      if (ssh_crypto_test_pk_group(state.imported.pk_group) != SSH_CRYPTO_OK)
        {
          ssh_pk_group_object_free(state.imported.pk_group);

          /* However, we must ensure the we're returning correct ERROR
             return code, if the crypto lib went into error state */
          status =
            (ssh_crypto_library_get_status()
             == SSH_CRYPTO_LIBRARY_STATUS_ERROR) ?
            SSH_CRYPTO_LIBRARY_ERROR :
            SSH_CRYPTO_OPERATION_FAILED;
          goto error_common;
        }
#endif /* SSHDIST_CRYPT_SELF_TESTS */
#endif /* SSHDIST_CRYPT_GENPKCS_DH */

      if (!ssh_crypto_library_object_use(state.imported.pk_group,
                                         SSH_CRYPTO_OBJECT_TYPE_PK_GROUP))
        {
          ssh_pk_group_object_free(state.imported.pk_group);
          status = SSH_CRYPTO_NO_MEMORY;
          goto error_common;
        }
      else
        pk_group =
          SSH_CRYPTO_PK_GROUP_TO_HANDLE(state.imported.pk_group);
      break;

    case SSH_PKF_PK_GROUP_RANDOMIZERS:
      /* Actually, we don't have anything to do... */
      break;

    default:
      ssh_fatal("Invalid data type");
    }

  if (private_key_ret)
    {
      *private_key_ret = private_key;
      private_key = NULL;
    }

  if (public_key_ret)
    {
      *public_key_ret = public_key;
      public_key = NULL;
    }

  if (pk_group_ret)
    {
      *pk_group_ret = pk_group;
      pk_group = NULL;
    }

  if (private_key)
    ssh_private_key_free(private_key);

  if (public_key)
    ssh_public_key_free(public_key);

  if (pk_group)
    ssh_pk_group_free(pk_group);

  if (state.release)
    (*state.release)(&state);

  ssh_free(state.cipher_name);
  ssh_free(state.hash_name);

  return SSH_CRYPTO_OK;

 error_common:

  if (state.release)
    (*state.release)(&state);

  if (state.cipher_name)
    ssh_free(state.cipher_name);

  if (state.hash_name)
    ssh_free(state.hash_name);

  return status;
}

/************************************************************************/

typedef struct SshPkExportStateRec {
  /* Global state -- set by the master routine */

  /* Object type (pub/prv/grp) */
  SshPkFormat type;

  /* Object envelope version (0 if unspecified) */
  SshUInt32 version;

  /* Cipher name, cipher key and key length. Notice that `cipher_name'
     is NULL if not given by caller. If the envelope does not support
     encryption, it should check that `cipher_name' is NULL, and if
     not, return an error. If envelope supports encryption, then it
     should take NULL and "none" as requesting no encryption. */
  const char *cipher_name;
  const unsigned char *cipher_key;
  size_t cipher_key_len;

  /* Hash name (see `cipher_name' comments above, they apply also to
     `hash_name') */
  const char *hash_name;

  /* Union of different export data formats */
  union {
    SshPrivateKeyObject private_key;
    SshPublicKeyObject public_key;
    SshPkGroupObject pk_group;
  } exporting;

  /* Minimum padding requested by the caller */
  SshUInt32 pad;

  /* Global state -- set by the slave routine */

  /* Encoded buffer, and its length */
  unsigned char *buf;
  size_t buf_len;
} *SshPkExportState, SshPkExportStateStruct;

typedef SshCryptoStatus (*SshPkExportFunc)(SshPkExportState state);

/************************************************************************/

static SshCryptoStatus
ssh_pk_export_v1_prv(SshPkExportState state)
{
  SshCipher cipher;
  SshPrivateKeyObject key;
  unsigned char *data;
  size_t data_len, cipher_block_len;
  SshBufferStruct encrypted, buffer;
  Boolean encrypt;
  SshCryptoStatus status;
  char *name;
  const char *cipher_name;

  if (state->type != SSH_PKF_PRIVATE_KEY ||
      state->version != SSH_CRYPTO_ENVELOPE_VERSION_1)
    return SSH_CRYPTO_NO_MATCH;

  /* V1 private key export format does not support integrity checks */
  if (state->hash_name)
    return SSH_CRYPTO_UNSUPPORTED;

  encrypt = FALSE;
  cipher_block_len = 1;

  /* Skip NULL and "none" ciphers */
  if (state->cipher_name && strcmp(state->cipher_name, "none") != 0)
    {
      encrypt = TRUE;

      /* Allocate cipher. */
      status = ssh_cipher_allocate(state->cipher_name,
                                   state->cipher_key, state->cipher_key_len,
                                   TRUE, &cipher);

      if (status != SSH_CRYPTO_OK)
        return status;

      cipher_block_len =
        ssh_cipher_get_block_length(state->cipher_name);
      cipher_name = state->cipher_name;
    }
  else
    cipher_name = "none";

  key = state->exporting.private_key;

  /* Generate private key blob. */
  if (key->type->private_key_export == NULL_FNPTR ||
      ((status = (*key->type->private_key_export)(key->context,
                                                  &data, &data_len))
       != SSH_CRYPTO_OK))
    {
      if (encrypt)
        ssh_cipher_free(cipher);

      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Use buffer to append data. */
  ssh_buffer_init(&encrypted);

  (void) ssh_encode_buffer(&encrypted,
                           SSH_ENCODE_UINT32_STR(data, data_len),
                           SSH_FORMAT_END);

  /* Free exact private key information. */
  ssh_crypto_zeroize(data, data_len);
  ssh_free(data);

  /* Encrypt the exported key */
  if (encrypt)
    {
      unsigned char byte;
      int min_pad;

      min_pad = state->pad;

      /* Add random padding, always to block len, but also to at least
         `min_pad' bytes */
      while ((ssh_buffer_len(&encrypted) % cipher_block_len) != 0 ||
             min_pad > 0)
        {
          byte = ssh_random_object_get_byte();
          ssh_buffer_append(&encrypted, &byte, 1);
          min_pad--;
        }

      /* Start encrypt. */
      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_buffer_uninit(&encrypted);
          ssh_cipher_free(cipher);
          return SSH_CRYPTO_OPERATION_FAILED;
        }

      /* Encrypt buffer. */
      if (ssh_cipher_transform(cipher, ssh_buffer_ptr(&encrypted),
                               ssh_buffer_ptr(&encrypted),
                               ssh_buffer_len(&encrypted)) != SSH_CRYPTO_OK)
        {
          ssh_buffer_uninit(&encrypted);
          ssh_cipher_free(cipher);
          return SSH_CRYPTO_OPERATION_FAILED;
        }

      /* Free cipher. */
      ssh_cipher_free(cipher);
    }

  /* Initialize the actual private key buffer. */
  ssh_buffer_init(&buffer);

  name = ssh_private_key_object_name(key);

  if (!name ||
      ssh_encode_buffer(&buffer,
                        SSH_ENCODE_UINT32(SSH_PRIVATE_KEY_MAGIC),
                        SSH_ENCODE_UINT32(0),
                        SSH_ENCODE_UINT32_SSTR(name, strlen(name)),
                        SSH_ENCODE_UINT32_SSTR(cipher_name,
                                              strlen(cipher_name)),
                        SSH_ENCODE_UINT32_STR(ssh_buffer_ptr(&encrypted),
                                              ssh_buffer_len(&encrypted)),
                        SSH_FORMAT_END) == 0)
    {
      ssh_buffer_uninit(&buffer);
      ssh_buffer_uninit(&encrypted);
      ssh_free(name);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  ssh_free(name);

  /* Free encrypted buffer. */
  ssh_buffer_uninit(&encrypted);

  /* Get the buffer information. */
  state->buf_len = ssh_buffer_len(&buffer);
  if ((state->buf =
       ssh_memdup(ssh_buffer_ptr(&buffer), state->buf_len)) != NULL)
    {
      SSH_PUT_32BIT(state->buf + 4, state->buf_len);
      status = SSH_CRYPTO_OK;
    }
  else
    {
      status = SSH_CRYPTO_NO_MEMORY;
    }

  /* Free buffer. */
  ssh_buffer_uninit(&buffer);

  return status;
}

/************************************************************************/

static SshCryptoStatus
ssh_pk_export_v1_pub(SshPkExportState state)
{
  SshCryptoStatus status;
  unsigned char *data = NULL, *buf = NULL;
  char *name;
  size_t data_len, len;

  if (state->type != SSH_PKF_PUBLIC_KEY ||
      state->version != SSH_CRYPTO_ENVELOPE_VERSION_1)
    return SSH_CRYPTO_NO_MATCH;

  /* V1 public key export format does not support encrypting or
     integrity checks */
  if (state->cipher_name || state->hash_name)
    return SSH_CRYPTO_UNSUPPORTED;

  /* Yep, it is public key, and v1 export is requested. Proceed. */
  status =
    (*state->exporting.public_key->type->public_key_export)
    (state->exporting.public_key->context, &data, &data_len);

  if (status != SSH_CRYPTO_OK)
    return status;

  name = ssh_public_key_object_name(state->exporting.public_key);

  len =
    ssh_encode_array_alloc(&buf,
                           SSH_ENCODE_UINT32(SSH_PUBLIC_KEY_MAGIC),
                           SSH_ENCODE_UINT32(0),
                           SSH_ENCODE_UINT32_SSTR(name, strlen(name)),
                           SSH_ENCODE_UINT32_STR(data, data_len),
                           SSH_FORMAT_END);

  /* `data' and `name' no longer needed, it is now in `buf' */
  ssh_free(data);
  ssh_free(name);

  if (len == 0)
    {
      SSH_ASSERT(buf == NULL);
      return SSH_CRYPTO_NO_MEMORY;
    }

  SSH_PUT_32BIT(buf + 4, len);

  state->buf = buf;
  state->buf_len = len;

  return SSH_CRYPTO_OK;
}

/************************************************************************/

static SshCryptoStatus
ssh_pk_export_v1_grp(SshPkExportState state)
{
  SshBufferStruct buffer;
  unsigned char *tmp;
  size_t tmplen;
  char *name;
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (state->type != SSH_PKF_PK_GROUP ||
      state->version != SSH_CRYPTO_ENVELOPE_VERSION_1)
    return SSH_CRYPTO_NO_MATCH;

  /* V1 group export format does not support encrypting or integrity
     checks */
  if (state->cipher_name || state->hash_name)
    return SSH_CRYPTO_UNSUPPORTED;

  group = state->exporting.pk_group;

  if (group->type->pk_group_export == NULL_FNPTR)
    return SSH_CRYPTO_UNSUPPORTED;

  status = SSH_CRYPTO_OPERATION_FAILED;

  ssh_buffer_init(&buffer);

  name = ssh_pk_group_object_name(group);

  if (!name ||
      ssh_encode_buffer(&buffer,
                        SSH_ENCODE_UINT32(SSH_PK_GROUP_MAGIC),
                        SSH_ENCODE_UINT32(0),
                        SSH_ENCODE_UINT32_SSTR(name, strlen(name)),
                        SSH_FORMAT_END) == 0)
    {
      ssh_buffer_uninit(&buffer);
      if (name)
          ssh_free(name);
      return status;
    }
  ssh_free(name);

  status = (*group->type->pk_group_export)(group->context, &tmp, &tmplen);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_buffer_uninit(&buffer);
      return status;
    }

  if (ssh_encode_buffer(&buffer,
                        SSH_ENCODE_UINT32_STR(tmp, tmplen),
                        SSH_FORMAT_END) == 0)
    {
      ssh_free(tmp);
      return status;
    }
  ssh_free(tmp);

  state->buf_len = ssh_buffer_len(&buffer);
  if ((state->buf =
       ssh_memdup(ssh_buffer_ptr(&buffer), state->buf_len)) != NULL)
    {
      SSH_PUT_32BIT(state->buf + 4, state->buf_len);
      status = SSH_CRYPTO_OK;
    }
  else
    {
      status = SSH_CRYPTO_NO_MEMORY;
    }

  ssh_buffer_uninit(&buffer);
  return status;
}


/************************************************************************/

static SshCryptoStatus
ssh_pk_export_v1_grp_randomizers(SshPkExportState state)
{
  SshBufferStruct buffer;
  unsigned char *tmp;
  size_t tmplen;
  SshCryptoStatus status;
  SshPkGroupObject group;

  if (state->type != SSH_PKF_PK_GROUP_RANDOMIZERS ||
      state->version != SSH_CRYPTO_ENVELOPE_VERSION_1)
    return SSH_CRYPTO_NO_MATCH;

  if (state->cipher_name || state->hash_name)
    return SSH_CRYPTO_UNSUPPORTED;

  group = state->exporting.pk_group;

  ssh_buffer_init(&buffer);

  /* Put magic and reserve space for total length */
  if (ssh_encode_buffer(&buffer,
                        SSH_ENCODE_UINT32(SSH_PK_GROUP_RANDOMIZER_MAGIC),
                        SSH_ENCODE_UINT32(0),
                        SSH_FORMAT_END) == 0)
    return SSH_CRYPTO_NO_MEMORY;

  while (TRUE)
    {
      status = (*group->type->pk_group_export_randomizer)(group->context,
                                                          &tmp, &tmplen);

      if (status == SSH_CRYPTO_OK)
        {
          if (ssh_encode_buffer(&buffer,
                                SSH_ENCODE_UINT32_STR(tmp, tmplen),
                                SSH_FORMAT_END) == 0)
            {
              ssh_free(tmp);
              ssh_buffer_uninit(&buffer);
              return status;
            }
          ssh_free(tmp);
        }
      else
        break;
    }

  state->buf_len = ssh_buffer_len(&buffer);
  state->buf = ssh_memdup(ssh_buffer_ptr(&buffer), state->buf_len);

  ssh_buffer_uninit(&buffer);

  if (state->buf == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  SSH_PUT_32BIT(state->buf + 4, state->buf_len);
  return SSH_CRYPTO_OK;
}


/************************************************************************/

/* The common v2 envelope export format is:

       type ui32 = 4 bytes, network byte order

       type bytes = bytes, not aligned or padded (size inferred from other
       sources)

       header = ui32 magic | ui32 length | ui32 subtype |
            str ciphername | ui32 keylen | str hashname

       payload = iv | ui32 datalen | bytes data | bytes pad

       digest = (nothing) | hash(header | payload)

       v2_envelope = header | encrypted

       encrypted = payload | digest             for cipher = "none"
       encrypted = encrypt(payload | digest)     for cipher != "none"

       data = str type | bytes export   for private key, public key, groups
       data = ui32 cnt | randomizers    for randomizers

       randomizers = ( ui32 len | bytes data )+

   Notice that we do not use ssh_encode/ssh_decode functions at all. */

static SshCryptoStatus
ssh_pk_export_v2_all(SshPkExportState state)
{
  unsigned char *data = NULL, *output = NULL;
  size_t payload_len = 0, data_len, pad_len, digest_len, total_len, iv_len;
  size_t encrypt_len, cipher_key_len, data_off, off;
  SshCryptoStatus status;
  const char *pk_type_name = NULL, *cipher_name, *hash_name;
  SshUInt32 type, randomizer_cnt = 0L;
  int i;

  /* We're the "current" export format, eg. recognize version 0 for
     exporting */
  if (state->version != 0 &&
      state->version != SSH_CRYPTO_ENVELOPE_VERSION_2)
    return SSH_CRYPTO_NO_MATCH;

  /* Hash & cipher name canonical */
  cipher_name = state->cipher_name ? state->cipher_name : "none";
  hash_name = state->hash_name ? state->hash_name : "none";

  /* Force a hash to be used when encrypting, always */
  if (strcmp(cipher_name, "none") != 0 && strcmp(hash_name, "none") == 0)
    hash_name = "sha1";

  /* Get digest len in advance */
  if (hash_name && strcmp(hash_name, "none") != 0)
    {
      digest_len = ssh_hash_digest_length(hash_name);
      SSH_ASSERT(digest_len > 0);
    }
  else
    digest_len = 0;

  /* First thing is that we must export the payload data and perform
     padding. */

  /* Note: ssh_pk_export checks that the type supports export
     operation itself, so we can proceed without checking it. */
  if (state->type == SSH_PKF_PRIVATE_KEY)
    {
      SshPrivateKeyObject key = state->exporting.private_key;
      pk_type_name = key->type->name;
      status =
        (*key->type->private_key_export)(key->context, &data, &data_len);
      type = SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PRIVATE_KEY;
    }
  else if (state->type == SSH_PKF_PUBLIC_KEY)
    {
      SshPublicKeyObject key = state->exporting.public_key;
      pk_type_name = key->type->name;
      status =
        (*key->type->public_key_export)(key->context, &data, &data_len);
      type = SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PUBLIC_KEY;
    }
  else if (state->type == SSH_PKF_PK_GROUP)
    {
      SshPkGroupObject key = state->exporting.pk_group;
      pk_type_name = key->type->name;
      status =
        (*key->type->pk_group_export)(key->context, &data, &data_len);
      type = SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PK_GROUP;
    }
  else if (state->type == SSH_PKF_PK_GROUP_RANDOMIZERS)
    {
      SshPkGroupObject key = state->exporting.pk_group;

      data = NULL;
      data_len = 0;
      randomizer_cnt = 0;

      do {
        unsigned char *tmp;
        size_t tmp_len;

        status = (key->type->pk_group_export_randomizer)(key->context,
                                                         &tmp, &tmp_len);

        /* Reallocate to data & extend */
        if (status == SSH_CRYPTO_OK)
          {
            data = ssh_realloc(data, data_len, data_len + tmp_len + 4);

            if (data == NULL)
              {
                ssh_free(data);
                ssh_free(tmp);
                return SSH_CRYPTO_NO_MEMORY;
              }

            /* put size, copy tmp, free tmp */
            SSH_PUT_32BIT(data + data_len, tmp_len);
            memcpy(data + data_len + 4, tmp, tmp_len);
            ssh_free(tmp);

            data_len += tmp_len + 4;
            randomizer_cnt++;
          }
      } while (status == SSH_CRYPTO_OK);

      if (randomizer_cnt == 0)
        return SSH_CRYPTO_OPERATION_FAILED;

      status = SSH_CRYPTO_OK;
      type = SSH_CRYPTO_COMMON_ENVELOPE_TYPE_VERSION_2_PK_GROUP_RANDOMIZERS;
    }
  else
    return SSH_CRYPTO_UNSUPPORTED;

  if (status != SSH_CRYPTO_OK)
    {
      if (data != NULL)
        ssh_free(data);

      return status;
    }

  /* Calculate true data length, eg. include the type name (for keys)
     or randomizer count (for randomizers) over export length. */
  if (state->type == SSH_PKF_PRIVATE_KEY ||
      state->type == SSH_PKF_PUBLIC_KEY || state->type == SSH_PKF_PK_GROUP)
    payload_len = data_len + strlen(pk_type_name) + 1;
  else if (state->type == SSH_PKF_PK_GROUP_RANDOMIZERS)
    payload_len = data_len + 4;

  /* What is known to be encrypted now (missing padding and iv):
     ui32 datalen | payload | digest */
  encrypt_len = 4 + payload_len + digest_len;

  /* Pad at least user requested amount */
  pad_len = state->pad;

  /* Calculate needed padding length */
  if (strcmp(cipher_name, "none") != 0)
    {
      size_t block_len;

      block_len = ssh_cipher_get_block_length(cipher_name);
      SSH_ASSERT(block_len > 0);

      /* Stream cipher? No use to pad nor use iv  */
      if (block_len == 1)
          iv_len = 0;
      else
        {
          iv_len = block_len;
          encrypt_len += iv_len;

          /* Iterate padding - could calculate as well but padding is
             short. */
          while (((encrypt_len + pad_len) % block_len) != 0 ||
                 pad_len == 0)
            pad_len++;

          /* Always pad -- note (len < payload_len) in loop ensures this */
          SSH_ASSERT(pad_len > 0);

          SSH_ASSERT((4 + iv_len + payload_len + pad_len + digest_len)
                     == (encrypt_len + pad_len));
          SSH_ASSERT(((4 + iv_len + payload_len + pad_len + digest_len)
                      % block_len) == 0);
        }

      cipher_key_len = state->cipher_key_len;
    }
  else
    {
      cipher_key_len = 0;
      iv_len = 0;
    }

  /* Calculate total length */

  total_len =
    /* (magic, length, subtype, keylen, datalen) * 4 bytes */
    20 +
    /* cipher & hash names including \0 termination */
    strlen(cipher_name) + strlen(hash_name) + 2 +
    /* IV length */
    iv_len +
    /* exported data */
    payload_len +
    /* padding */
    pad_len +
    /* digest length */
    digest_len;

  /* Encrypted part length: iv + datalen + data + pad + digest */
  encrypt_len = iv_len + 4 + payload_len + pad_len + digest_len;

  /* Allocate memory for the export data, put stuff in place as much
     as possible readying for digest calculation & in-place
     encryption */

  output = ssh_malloc(total_len);

  if (output == NULL)
    {
      ssh_free(data);
      return SSH_CRYPTO_NO_MEMORY;
    }

  off = 0;

  SSH_PUT_32BIT(output + off, SSH_CRYPTO_COMMON_ENVELOPE_MAGIC); off += 4;
  SSH_ASSERT(off < total_len);

  SSH_PUT_32BIT(output + off, total_len); off += 4;
  SSH_ASSERT(off < total_len);

  SSH_PUT_32BIT(output + off, type); off += 4;
  SSH_ASSERT(off < total_len);

  memcpy(output + off, cipher_name, strlen(cipher_name) + 1);
  off += strlen(cipher_name) + 1;
  SSH_ASSERT(off < total_len);

  SSH_PUT_32BIT(output + off, cipher_key_len); off += 4;
  SSH_ASSERT(off < total_len);

  memcpy(output + off, hash_name, strlen(hash_name) + 1);
  off += strlen(hash_name) + 1;
  SSH_ASSERT(off < total_len);

  /* Store current offset for encryption phase */
  data_off = off;

  /* Random IV */
  for (i = 0; i < iv_len; i++)
    {
      output[off++] = ssh_random_object_get_byte();
      SSH_ASSERT(off < total_len);
    }

  /* Internal payload data length */
  SSH_PUT_32BIT(output + off, payload_len); off += 4;
  SSH_ASSERT(off < total_len);

  if (state->type == SSH_PKF_PRIVATE_KEY ||
      state->type == SSH_PKF_PUBLIC_KEY || state->type == SSH_PKF_PK_GROUP)
    {
      memcpy(output + off, pk_type_name, strlen(pk_type_name) + 1);
      off += strlen(pk_type_name) + 1;
    }
  else if (state->type == SSH_PKF_PK_GROUP_RANDOMIZERS)
    {
      SSH_PUT_32BIT(output + off, randomizer_cnt); off += 4;
    }

  SSH_ASSERT(off < total_len);

  memcpy(output + off, data, data_len); off += data_len;
  SSH_ASSERT(off == 4 + data_off + iv_len + payload_len);
  SSH_ASSERT(off <= total_len);

  /* No longer needed */
  ssh_crypto_zeroize(data, data_len);
  ssh_free(data);
  data = NULL;

  /* Perform data padding, use 100... padding method */
  for (i = 0; i < pad_len; i++)
    output[off++] = i == 0 ? 0x80 : 0x00;

  SSH_ASSERT(off <= total_len);

  /* Digest, if enabled */
  if (strcmp(hash_name, "none") != 0)
    {
      SshHash hash;

      SSH_ASSERT(off + digest_len == total_len);

      status = ssh_hash_allocate(hash_name, &hash);

      if (status != SSH_CRYPTO_OK)
        goto common_error;

      /* Calculate over the whole plaintext message (except the digest
         part) */

      ssh_hash_update(hash, output, off);
      status = ssh_hash_final(hash, output + off);

      ssh_hash_free(hash);

      if (status != SSH_CRYPTO_OK)
          goto common_error;

      off += ssh_hash_digest_length(hash_name);
    }

  SSH_ASSERT(off == total_len);

  /* Now we can perform in-place encryption of the actual payload buffer */
  if (strcmp(cipher_name, "none") != 0)
    {
      SshCipher cipher;

      status = ssh_cipher_allocate(cipher_name,
                                   state->cipher_key, state->cipher_key_len,
                                   TRUE, &cipher);

      if (status != SSH_CRYPTO_OK)
        goto common_error;

      SSH_ASSERT(data_off + encrypt_len == total_len);
      SSH_ASSERT((encrypt_len%ssh_cipher_get_block_length(cipher_name)) == 0);

      status = ssh_cipher_start(cipher);
      if (status != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          goto common_error;
        }

      status = ssh_cipher_transform(cipher,
                                    output + data_off, output + data_off,
                                    encrypt_len);

      ssh_cipher_free(cipher);

      if (status != SSH_CRYPTO_OK)
        goto common_error;
    }

  /* Done. */
  state->buf = output;
  state->buf_len = total_len;

  return SSH_CRYPTO_OK;

 common_error:
  ssh_crypto_zeroize(output, total_len);
  ssh_free(output);

  return status;
}

/************************************************************************/

const
static SshPkExportFunc ssh_pk_export_functions[] =
  {
    ssh_pk_export_v1_prv,
    ssh_pk_export_v1_pub,
    ssh_pk_export_v1_grp,
    ssh_pk_export_v1_grp_randomizers,
    ssh_pk_export_v2_all,
    NULL
  };

/* Perform prv/pub/grp export operation. The result is written to
   `*buf_ret' and points to an allocate memory which must be freed by
   the caller. The variable length argument list is a list of
   export-specific SSH_PKF_* keywords terminated with a
   SSH_PKF_END. For example, to export a private key with encryption:

   status = ssh_pk_export(&buf, &buflen,
        SSH_PKF_PRIVATE_KEY, &prv,
        SSH_PKF_CIPHER_NAME, "aes-cbc",
        SSH_PKF_CIPHER_KEY, key_buf, key_len,
        SSH_PKF_END);
*/

SshCryptoStatus
ssh_pk_export(unsigned char **buf_ret, size_t *len_ret, ...)
{
  SshPkExportStateStruct state;
  SshCryptoStatus status;
  int i;
  SshPrivateKey private_key;
  SshPublicKey public_key;
  SshPkGroup pk_group;
  Boolean do_export, version_given;
  va_list ap;
  SshPkFormat format;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  memset(&state, 0, sizeof(state));

  state.version = 0; /* "newest" version -- exporters are supposed to
                        recognize the zero */
  do_export = FALSE;
  version_given = FALSE;

  va_start(ap, len_ret);
  while ((format = va_arg(ap, SshPkFormat)) != SSH_PKF_END)
    {
      switch (format)
        {
        case SSH_PKF_ENVELOPE_VERSION:
          state.version = va_arg(ap, SshUInt32);
          version_given = TRUE;
          break;

        case SSH_PKF_CIPHER_NAME:
          state.cipher_name = va_arg(ap, const char *);
          break;

        case SSH_PKF_CIPHER_KEY:
          state.cipher_key = va_arg(ap, const unsigned char *);
          state.cipher_key_len = va_arg(ap, size_t);
          break;

        case SSH_PKF_HASH_NAME:
          state.hash_name = va_arg(ap, const char *);
          break;

        case SSH_PKF_PRIVATE_KEY:
          private_key = va_arg(ap, SshPrivateKey);
          state.exporting.private_key =
            SSH_CRYPTO_HANDLE_TO_PRIVATE_KEY(private_key);
          if (state.exporting.private_key->type->private_key_export
              == NULL_FNPTR)
            {
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED;
            }
          state.type = SSH_PKF_PRIVATE_KEY;
          goto exporting_common;

        case SSH_PKF_PUBLIC_KEY:
          public_key = va_arg(ap, SshPublicKey);
          state.exporting.public_key =
            SSH_CRYPTO_HANDLE_TO_PUBLIC_KEY(public_key);
          if (state.exporting.public_key->type->public_key_export
              == NULL_FNPTR)
            {
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED;
            }
          state.type = SSH_PKF_PUBLIC_KEY;
          goto exporting_common;

        case SSH_PKF_PK_GROUP:
          pk_group = va_arg(ap, SshPkGroup);
          state.exporting.pk_group =
            SSH_CRYPTO_HANDLE_TO_PK_GROUP(pk_group);
          if (state.exporting.pk_group->type->pk_group_export
              == NULL_FNPTR)
            {
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED;
            }
          state.type = SSH_PKF_PK_GROUP;
          goto exporting_common;

        case SSH_PKF_PK_GROUP_RANDOMIZERS:
          pk_group = va_arg(ap, SshPkGroup);
          state.exporting.pk_group =
            SSH_CRYPTO_HANDLE_TO_PK_GROUP(pk_group);
          if (state.exporting.pk_group->type->pk_group_export_randomizer
              == NULL_FNPTR)
            {
              va_end(ap);
              return SSH_CRYPTO_UNSUPPORTED;
            }
          state.type = SSH_PKF_PK_GROUP_RANDOMIZERS;
          goto exporting_common;

        exporting_common:
          /* Nonsensical to export multiple key types in one export
             statement, check against that. */
          if (do_export)
            {
              va_end(ap);
              return SSH_CRYPTO_KEY_INVALID;
            }

          do_export = TRUE;
          break;

        case SSH_PKF_PAD:
          state.pad = va_arg(ap, size_t);
          break;

        default:
          va_end(ap);
          return SSH_CRYPTO_UNSUPPORTED_IDENTIFIER;
        }
    }
  va_end(ap);

  if (!do_export)
    return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  /* Iterate over exporter functions, and call them */
  for (i = 0; ssh_pk_export_functions[i] != NULL; i++)
    {
      status = (*ssh_pk_export_functions[i])(&state);

      if (status == SSH_CRYPTO_OK)
        break;

      if (status != SSH_CRYPTO_NO_MATCH)
        return status;
    }

  if (ssh_pk_export_functions[i] == NULL)
    {
      if (version_given)
        return SSH_CRYPTO_UNSUPPORTED_VERSION;

      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }

  *buf_ret = state.buf;
  *len_ret = state.buf_len;

  return SSH_CRYPTO_OK;
}
