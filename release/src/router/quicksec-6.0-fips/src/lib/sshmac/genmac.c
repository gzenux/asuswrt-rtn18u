/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Message authentication code calculation routines.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"

#define SSH_DEBUG_MODULE "GenMac"

#include "sshhash_i.h"
#include "sshcipher_i.h"
#include "sshmac_i.h"

#ifdef SSHDIST_CRYPT_RIJNDAEL
#include "rijndael.h"
#endif /* SSHDIST_CRYPT_RIJNDAEL */

#ifdef SSHDIST_CRYPT_SSHMACS
#include "macs.h"
#endif /* SSHDIST_CRYPT_SSHMACS */
#ifdef SSHDIST_CRYPT_HMAC
#include "hmac.h"
#endif /* SSHDIST_CRYPT_HMAC */

#ifdef SSHDIST_CRYPT_MD5
#include "md5.h"
#endif /* SSHDIST_CRYPT_MD5 */

#ifdef SSHDIST_CRYPT_SHA
#include "sha.h"
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
#include "sha256.h"
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
#include "sha512.h"
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_XCBCMAC
#include "xcbc-mac.h"
#endif /* SSHDIST_CRYPT_XCBCMAC */





/* Control structure. */
static const SshHashMacDefStruct ssh_mac_algorithms[] =
{
#ifdef SSHDIST_CRYPT_HMAC
#ifdef SSHDIST_CRYPT_MD5
  { "hmac-md5", 16, FALSE,
    &ssh_hash_md5_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  { "hmac-md5-96", 12, FALSE,
    &ssh_hash_md5_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_96_final,
    ssh_hmac_96_of_buffer },
#endif /* SSHDIST_CRYPT_MD5 */
#ifdef SSHDIST_CRYPT_SHA
  { "hmac-sha1", 20, FALSE,
    &ssh_hash_sha_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  { "hmac-sha1-96", 12, FALSE,
    &ssh_hash_sha_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_96_final,
    ssh_hmac_96_of_buffer },
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  {
    "hmac-sha256", 32, FALSE,
    &ssh_hash_sha256_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha256-96", 12, FALSE,
    &ssh_hash_sha256_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_96_final,
    ssh_hmac_96_of_buffer },
#endif /* SSHDIST_CRYPT_SHA256 */
#endif /* SSHDIST_CRYPT_HMAC */

#ifdef SSHDIST_CRYPT_SSHMACS
#ifdef SSHDIST_CRYPT_SHA
  { "sha1", 20, TRUE, &ssh_hash_sha_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init, ssh_kdk_mac_uninit,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_final,
    ssh_kdk_mac_of_buffer },
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_MD5
  { "md5", 16, TRUE, &ssh_hash_md5_def,
    ssh_kdk_mac_ctxsize, ssh_kdk_mac_init, ssh_kdk_mac_uninit,
    ssh_kdk_mac_start, ssh_kdk_mac_update, ssh_kdk_mac_final,
    ssh_kdk_mac_of_buffer },
#endif /* SSHDIST_CRYPT_MD5 */
#ifndef KERNEL
  /* These MACs can only be used in user-mode code.  See comments
     above for more information. */

#endif /* !KERNEL */

#endif /* SSHDIST_CRYPT_SSHMACS */
#ifdef SSHDIST_CRYPT_SHA256
  {
    "hmac-sha256-128", 16, FALSE,
    &ssh_hash_sha256_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_128_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha224", 28, FALSE,
    &ssh_hash_sha224_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha224-128", 16, FALSE,
    &ssh_hash_sha224_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_128_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  {
    "hmac-sha384", 48, FALSE,
    &ssh_hash_sha384_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha384-128", 16, FALSE,
    &ssh_hash_sha384_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_128_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha384-192", 24, FALSE,
    &ssh_hash_sha384_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_192_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha512", 64, FALSE,
    &ssh_hash_sha512_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha512-128", 16, FALSE,
    &ssh_hash_sha512_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_128_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
  {
    "hmac-sha512-256", 32, FALSE,
    &ssh_hash_sha512_def,
    ssh_hmac_ctxsize, ssh_hmac_init, ssh_hmac_uninit,
    ssh_hmac_start, ssh_hmac_update, ssh_hmac_256_final,
    ssh_hmac_of_buffer, ssh_hmac_zeroize },
#endif /* SSHDIST_CRYPT_SHA512 */
  { "none", 0, FALSE, NULL },
  { NULL }
};


#ifdef SSHDIST_CRYPT_RIJNDAEL
 const SshCipherMacBaseDefStruct ssh_ciphermac_base_rijndael_def =
   { 16, ssh_rijndael_ctxsize, ssh_rijndael_init, ssh_rijndael_uninit,
     ssh_rijndael_cbc_mac };
#endif /* SSHDIST_CRYPT_RIJNDAEL */

static const SshCipherMacDefStruct ssh_cipher_mac_algorithms[] =
{
#ifdef SSHDIST_CRYPT_RIJNDAEL
#ifdef SSHDIST_CRYPT_XCBCMAC
  /* AES XCBC-MAC*/
  { "xcbcmac-aes", 16, { 16, 16, 16},
    &ssh_ciphermac_base_rijndael_def,
    ssh_xcbcmac_ctxsize, ssh_xcbcmac_init, ssh_xcbcmac_uninit,
    ssh_xcbcmac_start, ssh_xcbcmac_update, ssh_xcbcmac_final },
  { "xcbcmac-rijndael", 16, { 16, 16, 16 },
    &ssh_ciphermac_base_rijndael_def,
    ssh_xcbcmac_ctxsize, ssh_xcbcmac_init, ssh_xcbcmac_uninit,
    ssh_xcbcmac_start, ssh_xcbcmac_update, ssh_xcbcmac_final },

  /*  96 bit output from AES XBC-MAC */
  { "xcbcmac-aes-96", 12, { 16, 16, 16 },
    &ssh_ciphermac_base_rijndael_def,
    ssh_xcbcmac_ctxsize, ssh_xcbcmac_init, ssh_xcbcmac_uninit,
    ssh_xcbcmac_start, ssh_xcbcmac_update, ssh_xcbcmac_96_final },
  { "xcbcmac-rijndael-96", 12, { 16, 16, 16 },
    &ssh_ciphermac_base_rijndael_def,
    ssh_xcbcmac_ctxsize, ssh_xcbcmac_init, ssh_xcbcmac_uninit,
    ssh_xcbcmac_start, ssh_xcbcmac_update, ssh_xcbcmac_96_final },
#endif /* SSHDIST_CRYPT_XCBCMAC */













#endif /* SSHDIST_CRYPT_RIJNDAEL */

  { NULL }
};


typedef enum
{
  SSH_MAC_TYPE_HASH,
  SSH_MAC_TYPE_CIPHER
} SshMacAlgType;

typedef struct SshMacObjectRec {
  SSH_CRYPTO_OBJECT_HEADER
  SshMacAlgType type;
  union {
    const SshHashMacDefStruct       *hash_ops;
    const SshCipherMacDefStruct *cipher_ops;
  } c;
  void *context;
  SshCryptoStatus error_status;
} SshMacObjectStruct;


/* Find internal */
static const SshHashMacDefStruct *ssh_mac_find_hash(const char *type)
{
  int i;
  /* Find the desired mac type from the array. */
  for (i = 0; ssh_mac_algorithms[i].name != NULL; i++)
    {
      if (strcmp(ssh_mac_algorithms[i].name, type) == 0)
        return &ssh_mac_algorithms[i];
    }

  return NULL;
}

static const SshCipherMacDefStruct *ssh_mac_find_cipher(const char *type)
{
  int i;

  for (i = 0; ssh_cipher_mac_algorithms[i].name != NULL; i++)
    {
      if (strcmp(ssh_cipher_mac_algorithms[i].name, type) == 0)
        return &ssh_cipher_mac_algorithms[i];
    }

  return NULL;
}

/* Returns a comma-separated list of supported mac types.  The caller
   must return the list with ssh_xfree(). */
char *
ssh_mac_get_supported(void)
{
  int i;
  unsigned char *list, *tmp;
  size_t offset, list_len;

  list = NULL;
  offset = list_len = 0;

  for (i = 0; ssh_mac_algorithms[i].name != NULL; i++)
    {
      size_t newsize;

      newsize = offset + 1 + !!offset + strlen(ssh_mac_algorithms[i].name);

      if (list_len < newsize)
        {
          newsize *= 2;

          if ((tmp = ssh_realloc(list, list_len, newsize)) == NULL)
            {
              ssh_free(list);
              return NULL;
            }
          list = tmp;
          list_len = newsize;
        }

      offset += ssh_snprintf(list + offset, list_len - offset, "%s%s",
                             offset ? "," : "",
                             ssh_mac_algorithms[i].name);

    }

  for (i = 0; ssh_cipher_mac_algorithms[i].name != NULL; i++)
    {
      size_t newsize;

      newsize = offset + 1 + !!offset +
        strlen(ssh_cipher_mac_algorithms[i].name);

      if (list_len < newsize)
        {
          newsize *= 2;

          if ((tmp = ssh_realloc(list, list_len, newsize)) == NULL)
            {
              ssh_free(list);
              return NULL;
            }

          list = tmp;
          list_len = newsize;
        }

      offset += ssh_snprintf(list + offset, list_len - offset, "%s%s",
                             offset ? "," : "",
                             ssh_cipher_mac_algorithms[i].name);

    }

  return (char *) list;
}

/* Check if given mac name belongs to the set of supported ciphers. */
Boolean
ssh_mac_supported(const char *name)
{
  if (name == NULL)
    return FALSE;

  if (ssh_mac_find_hash(name) != NULL ||
      ssh_mac_find_cipher(name) != NULL)
    return TRUE;

  return FALSE;
}

/* Allocate mac for use in session. */
SshCryptoStatus
ssh_mac_object_allocate(const char *type,
                        const unsigned char *key, size_t keylen,
                        SshMacObject *mac_return)
{
  SshMacObject mac;
  const SshHashMacDefStruct *mac_def;
  const SshCipherMacDefStruct *cipher_def;
  SshCryptoStatus status;

  *mac_return = NULL;

  mac_def = ssh_mac_find_hash(type);

  if (mac_def)
    {
      /* Found the specified mac type.  Initialize the data structure. */
      if (!(mac = ssh_calloc(1, sizeof(*mac))))
        return SSH_CRYPTO_NO_MEMORY;

      mac->type = SSH_MAC_TYPE_HASH;
      mac->c.hash_ops = mac_def;

      if (mac->c.hash_ops->ctxsize)
        {
          mac->context =
            ssh_crypto_calloc_i(1, (*mac->c.hash_ops->ctxsize)
                                (mac_def->hash_def) +
                                (mac->c.hash_ops->allocate_key == TRUE
                                 ? keylen : 0));

          if (!mac->context)
            {
              ssh_free(mac);
              return SSH_CRYPTO_NO_MEMORY;
            }

          status = (*mac->c.hash_ops->init)(mac->context, key, keylen,
                                   mac_def->hash_def);
          if (status != SSH_CRYPTO_OK)
            {
              ssh_mac_object_free(mac);
              return status;
            }
        }
      else
        mac->context = NULL;

      /* Return the MAC context. */
      *mac_return = mac;
      return SSH_CRYPTO_OK;
    }

  cipher_def = ssh_mac_find_cipher(type);

  if (cipher_def)
    {
      if (!(mac = ssh_calloc(1, sizeof(*mac))))
        return SSH_CRYPTO_NO_MEMORY;

      mac->type = SSH_MAC_TYPE_CIPHER;
      mac->c.cipher_ops = cipher_def;

      if (mac->c.cipher_ops->ctxsize)
        {
          mac->context =
            ssh_crypto_calloc_i(1, (*mac->c.cipher_ops->ctxsize)
                                (cipher_def->cipher_def));

          if (!mac->context)
            {
              ssh_free(mac);
              return SSH_CRYPTO_NO_MEMORY;
            }

          status = (*mac->c.cipher_ops->init)(mac->context, key, keylen,
                                              cipher_def->cipher_def);

          if (status != SSH_CRYPTO_OK)
            {
              ssh_mac_object_free(mac);
              return status;
            }
        }
      else
        {
          mac->context = NULL;
        }

      *mac_return = mac;
      return SSH_CRYPTO_OK;
    }

  return SSH_CRYPTO_UNSUPPORTED;
}

/* Allocate mac for use in session. */
SshCryptoStatus
ssh_mac_allocate(const char *type,
                 const unsigned char *key, size_t keylen,
                 SshMac *mac_return)
{
  SshMacObject mac;
  SshCryptoStatus status;

  *mac_return = NULL;

  if (!ssh_crypto_library_object_check_use(&status))
    return status;

  status = ssh_mac_object_allocate(type, key, keylen, &mac);

  if (status != SSH_CRYPTO_OK)
    return status;

  if (!ssh_crypto_library_object_use(mac, SSH_CRYPTO_OBJECT_TYPE_MAC))
    {
      ssh_mac_object_free(mac);
      return SSH_CRYPTO_NO_MEMORY;
    }

  status = ssh_mac_object_reset(mac);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_mac_object_free(mac);
      return status;
    }

  /* Return the MAC context. */
  *mac_return = SSH_CRYPTO_MAC_TO_HANDLE(mac);

  return SSH_CRYPTO_OK;
}


size_t ssh_mac_get_min_key_length(const char *type)
{
  const SshCipherMacDefStruct *cipher_def;

  /* If it is a HASH MAC, it's always 0, so look only for cipher defs */
  cipher_def = ssh_mac_find_cipher(type);

  if (!cipher_def)
    return 0;

  return cipher_def->key_lengths.min_key_length;
}

size_t ssh_mac_get_max_key_length(const char *type)
{
  const SshCipherMacDefStruct *cipher_def;

  /* If it is a HASH MAC, it's always 0, so look only for cipher defs */
  cipher_def = ssh_mac_find_cipher(type);

  if (!cipher_def)
    return 0;

  return cipher_def->key_lengths.max_key_length;
}

size_t ssh_mac_get_block_length(const char *type)
{
  const SshCipherMacDefStruct *cipher_def;

  /* If it is a HASH MAC, it's always 0, so look only for cipher defs */
  cipher_def = ssh_mac_find_cipher(type);

  if (!cipher_def)
    return 0;

  return cipher_def->cipher_def->block_length;
}


/* Free the mac. */
void
ssh_mac_object_free(SshMacObject mac)
{
  if (!mac)
    return;

  switch (mac->type)
    {
    case SSH_MAC_TYPE_HASH:
      if (mac->c.hash_ops && mac->c.hash_ops->uninit)
          (*mac->c.hash_ops->uninit)(mac->context);
      break;

    case SSH_MAC_TYPE_CIPHER:
      if (mac->c.cipher_ops && mac->c.cipher_ops->uninit)
          (*mac->c.cipher_ops->uninit)(mac->context);
      break;
    }


  ssh_crypto_free_i(mac->context);
  ssh_free(mac);
}

void
ssh_mac_free(SshMac handle)
{
  SshMacObject mac = SSH_CRYPTO_HANDLE_TO_MAC(handle);

  if (!mac)
    return;

  ssh_crypto_library_object_release(mac);
  ssh_mac_object_free(mac);
}

const char *
ssh_mac_name(SshMac handle)
{
  SshMacObject mac;

  if (!ssh_crypto_library_object_check_use(NULL))
    return NULL;

  if (!(mac = SSH_CRYPTO_HANDLE_TO_MAC(handle)))
    return NULL;

  switch (mac->type)
    {
    case SSH_MAC_TYPE_HASH:
      return mac->c.hash_ops->name;
    case SSH_MAC_TYPE_CIPHER:
      return mac->c.cipher_ops->name;
    }

  SSH_NOTREACHED;
  return NULL;
}

/* Get the length of mac digest */
size_t
ssh_mac_length(const char *name)
{
  const SshHashMacDefStruct *mac_def;
  const SshCipherMacDefStruct *cipher_def;

  if ((mac_def = ssh_mac_find_hash(name)) != NULL)
    return mac_def->digest_length;

  if ((cipher_def = ssh_mac_find_cipher(name)) != NULL)
    return cipher_def->digest_length;

  return 0;
}


/* Reset the mac to its initial state. This should be called before
   processing a new packet/message. */
SshCryptoStatus
ssh_mac_object_reset(SshMacObject mac)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;

  switch (mac->type)
    {
    case SSH_MAC_TYPE_HASH:
      if (mac->c.hash_ops && mac->c.hash_ops->start)
        {
          status = (*mac->c.hash_ops->start)(mac->context);
        }
      break;
    case SSH_MAC_TYPE_CIPHER:
      if (mac->c.cipher_ops && mac->c.cipher_ops->start)
        {
          status = (*mac->c.cipher_ops->start)(mac->context);
        }
      break;
    }

  return status;
}

/* Reset the mac to its initial state. This should be called before
   processing a new packet/message. */
void
ssh_mac_reset(SshMac handle)
{
  SshMacObject mac;

  if (!(mac = SSH_CRYPTO_HANDLE_TO_MAC(handle)))
    return;

  if (!ssh_crypto_library_object_check_use(&mac->error_status))
    return;

  (void) ssh_mac_object_reset(mac);
}

void
ssh_mac_object_update(SshMacObject mac, const unsigned char *data, size_t len)
{
  switch (mac->type)
    {
    case SSH_MAC_TYPE_HASH:
      if (mac->c.hash_ops && mac->c.hash_ops->update)
          {
            (*mac->c.hash_ops->update)(mac->context, data, len);
          }
      break;
    case SSH_MAC_TYPE_CIPHER:
      if (mac->c.cipher_ops && mac->c.cipher_ops->update)
          {
            (*mac->c.cipher_ops->update)(mac->context, data, len);
          }
      break;
    }
}

void
ssh_mac_update(SshMac handle, const unsigned char *data, size_t len)
{
  SshMacObject mac;

  if (!(mac = SSH_CRYPTO_HANDLE_TO_MAC(handle)))
    return;

  if (!ssh_crypto_library_object_check_use(&mac->error_status))
    return;

  ssh_mac_object_update(mac, data, len);
}

SshCryptoStatus
ssh_mac_object_final(SshMacObject mac, unsigned char *digest)
{
  switch (mac->type)
    {
    case SSH_MAC_TYPE_HASH:
      if (mac->c.hash_ops && mac->c.hash_ops->final)
          (*mac->c.hash_ops->final)(mac->context, digest);
      break;

    case SSH_MAC_TYPE_CIPHER:
      if (mac->c.cipher_ops && mac->c.cipher_ops->final)
          (*mac->c.cipher_ops->final)(mac->context, digest);
      break;
    }

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_mac_final(SshMac handle, unsigned char *digest)
{
  SshMacObject mac;

  if (!(mac = SSH_CRYPTO_HANDLE_TO_MAC(handle)))
    return SSH_CRYPTO_HANDLE_INVALID;

  if (!ssh_crypto_library_object_check_use(&mac->error_status))
    return mac->error_status;

  return ssh_mac_object_final(mac, digest);
}
