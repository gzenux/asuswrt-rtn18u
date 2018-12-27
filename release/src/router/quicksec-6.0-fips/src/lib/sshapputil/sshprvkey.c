/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Routines to decode and encode various private key formats
   understood by the SSH library.
*/

#include "sshincludes.h"


#ifdef SSHDIST_APPUTIL_KEYUTIL
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshprvkey.h"
#ifdef SSHDIST_CERT
#include "x509.h"

#include "sshpkcs1.h"
#include "sshpkcs8.h"
#include "sshpkcs12-conv.h"
#endif /* SSHDIST_CERT */
#include "sshkeyblob1.h"
#include "sshkeyblob2.h"

#define SSH_DEBUG_MODULE "SshSKB"

struct SshSkbTypeNameMap {
  SshSKBType type;
  char *name;
};

static const struct SshSkbTypeNameMap type_name_map[] = {
  { SSH_SKB_SSH_1,              "ssh-crypto-library-private-key-1@ssh.com" },
  { SSH_SKB_SSH_2,              "ssh-crypto-library-private-key-2@ssh.com" },
  { SSH_SKB_SECSH_1,            "secure-shell-1-private-key@ssh.com" },
  { SSH_SKB_SECSH_2,            "secure-shell-2-private-key@ssh.com" },
  { SSH_SKB_SSH_X509,           "x509-raw-private-key@ssh.com" },
  { SSH_SKB_PKCS1,              "pkcs1" },
  { SSH_SKB_PKCS8,              "pkcs8" },
  { SSH_SKB_PKCS8_SHROUDED,     "pkcs8-shrouded" },
  { SSH_SKB_PKCS12_BROWSER_KEY, "pkcs12" },
  { SSH_SKB_UNKNOWN,            NULL }
};

SshCryptoStatus
ssh_skb_get_info(const unsigned char *data, size_t len,
                 char **cipher, char **hash,
                 unsigned char **unarmored_data, size_t *unarmored_len,
                 SshSKBType *kind, char **comment)
{
  unsigned long magic;
  SshPrivateKey prv = NULL;
  unsigned char *blob = NULL, *tmp;
  size_t bloblen = 0;
  char *tmpcomment = NULL;
#ifdef SSHDIST_CERT
  SshX509Status status;
#endif /* SSHDIST_CERT */
  int version, type, keylen;

  if (hash) *hash = NULL;
  if (cipher) *cipher = NULL;
  if (comment) *comment = NULL;
#ifdef SSHDIST_CERT
  if ((prv = ssh_pkcs1_decode_private_key(data, len)) != NULL)
    {
      *kind = SSH_SKB_PKCS1;
      goto success;
    }

  if ((prv = ssh_x509_decode_private_key(data, len)) != NULL)
    {
      if (kind)
        *kind = SSH_SKB_SSH_X509;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      goto success;
    }

  if (ssh_pkcs8_decode_private_key(data, len, &prv) == SSH_X509_OK)
    {
      if (kind)
        *kind = SSH_SKB_PKCS8;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      goto success;
    }

  status = ssh_pkcs8_decrypt_private_key(NULL, 0, data, len, &prv);
  if (status == SSH_X509_OK  || status == SSH_X509_PASSPHRASE_NEEDED)
    {
      if (kind)
        *kind = SSH_SKB_PKCS8_SHROUDED;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      goto success;
    }
  if (ssh_pkcs12_pfx_decode(data, len, NULL, NULL) == SSH_PKCS12_OK)
    {
      if (kind)
        *kind = SSH_SKB_PKCS12_BROWSER_KEY;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      goto success;
    }
#endif /* SSHDIST_CERT */


  if ((tmp = ssh_memdup(data, len)) != NULL)
    {
      magic = ssh2_key_blob_decode(tmp, len, FALSE,
                                   NULL, &tmpcomment, &blob, &bloblen);

      if (magic == SSH_KEY_MAGIC_SSH1_PRIVATE ||
          magic == SSH_KEY_MAGIC_SSH1_PRIVATE_ENCRYPTED)
        {
          if (kind)
            *kind = SSH_SKB_SECSH_1;
          if (unarmored_len)
            *unarmored_len = bloblen;
          if (unarmored_data)
            {
              *unarmored_data = blob;
            }
          else
            {
              memset(blob, 0, bloblen);
              ssh_free(blob);
            }
          goto success;
        }

      if (magic == SSH_KEY_MAGIC_PRIVATE ||
          magic == SSH_KEY_MAGIC_PRIVATE_ENCRYPTED)
        {
          if (kind)
            *kind = SSH_SKB_SECSH_2;
          if (unarmored_len)
            *unarmored_len = bloblen;
          if (unarmored_data)
            {
              *unarmored_data = blob;
            }
          else
            {
              memset(blob, 0, bloblen);
              ssh_free(blob);
            }
          goto success;
        }
    }

  if (ssh_pk_import(data, len, NULL,
                    SSH_PKF_ENVELOPE_VERSION, &version,
                    SSH_PKF_ENVELOPE_CONTENTS, &type,
                    SSH_PKF_CIPHER_NAME, cipher,
                    SSH_PKF_CIPHER_KEY_LEN, &keylen,
                    SSH_PKF_HASH_NAME, hash,
                    SSH_PKF_END)
      == SSH_CRYPTO_OK)
    {
      if (version == 1)
        *kind = SSH_SKB_SSH_1;
      else
        *kind = SSH_SKB_SSH_2;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);

      if (type == SSH_PKF_PRIVATE_KEY)
        goto success;
    }

  if (ssh_private_key_import_with_passphrase(data, len, "", &prv)
      == SSH_CRYPTO_OK)
    {
      if (kind)
        *kind = SSH_SKB_SSH_1;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      goto success;
    }

  ssh_free(tmpcomment);
  ssh_free(blob);

  return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

 success:
  if (comment)
    *comment = tmpcomment;
  else
    ssh_free(tmpcomment);
  if (prv)
    ssh_private_key_free(prv);
  return SSH_CRYPTO_OK;
}

#ifdef SSHDIST_CERT

static SshStr
get_sshstr(const unsigned char *str, size_t len)
{
  SshStr passwd = NULL;
  unsigned char *p = ssh_memdup(str, len);

  if (p)
    passwd = ssh_str_make(SSH_CHARSET_ISO_8859_1, p, len);
  return passwd;
}

static SshPkcs12Status
ssh_skb_pkcs12_decode_private_key(const unsigned char *data,
                                  size_t len,
                                  const unsigned char *password,
                                  size_t pass_len,
                                  SshPrivateKey *key)
{
  SshPkcs12Status status;
  SshStr pass = get_sshstr(password, pass_len);
  if (pass == NULL)
    return SSH_PKCS12_ERROR;

  status =  ssh_pkcs12_conv_decode_private_key(data, len, pass, 0, key);
  ssh_str_free(pass);
  return status;
}

#endif /* SSHDIST_CERT */

SshCryptoStatus
ssh_skb_decode(SshSKBType kind,
               const unsigned char *data, size_t len,
               const char *cipher, const char *hash,
               const unsigned char *password, size_t password_len,
               SshPrivateKey *key)
{
  unsigned char *blob, *tmp;
  size_t bloblen;
  SshCryptoStatus ret;
#ifdef SSHDIST_CERT
  SshX509Status x509status;
#endif /* SSHDIST_CERT */

  switch (kind)
    {
    case SSH_SKB_SSH_1:
        return ssh_private_key_import_with_passphrase(data, len,
                                                      (password ?
                                                       (const char *)password :
                                                       ""),
                                                      key);
    case SSH_SKB_SSH_2:
      return ssh_pk_import(data, len, NULL,
                           SSH_PKF_PRIVATE_KEY, &key,
                           SSH_PKF_CIPHER_NAME, &cipher,
                           SSH_PKF_CIPHER_KEY, password, password_len,
                           SSH_PKF_HASH_NAME, &hash,
                           SSH_PKF_END);
#ifdef SSHDIST_APPUTIL_SSH1ENCODE
    case SSH_SKB_SECSH_1:
        return ssh1_decode_privkeyblob(data, len, password ?
                                       (const char *)password : "",
                                       NULL, key);
#endif /* SSHDIST_APPUTIL_SSH1ENCODE */
    case SSH_SKB_SECSH_2:
      if ((tmp = ssh_memdup(data, len)) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      switch (ssh2_key_blob_decode(tmp, len, FALSE,
                                   NULL, NULL, &blob, &bloblen))
        {
        case SSH_KEY_MAGIC_PRIVATE_ENCRYPTED:
          ret =  ssh_private_key_import_with_passphrase(blob, bloblen,
                                                        password ?
                                                        (const char *)password:
                                                        "",
                                                        key);
          ssh_free(blob);
          return ret;
        case SSH_KEY_MAGIC_PRIVATE:
          ret = ssh_private_key_import_with_passphrase(blob, bloblen,
                                                       "",
                                                       key);
          ssh_free(blob);
          return ret;
        default:
          /* It can still be unarmored key.  Let's try. */
          return ssh_private_key_import_with_passphrase(
                         data, len,
                         ((password) ? (const char *)password : ""),
                         key);
        }
      break;

    case SSH_SKB_SSH_X509:
#ifdef SSHDIST_CERT
      if ((*key = ssh_x509_decode_private_key(data, len)) != NULL)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS1:
#ifdef SSHDIST_CERT
      if ((*key = ssh_pkcs1_decode_private_key(data, len)) != NULL)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS8_SHROUDED:
#ifdef SSHDIST_CERT
      if ((x509status = ssh_pkcs8_decrypt_private_key(password,
                                                      password_len,
                                                      data, len,
                                                      key)) == SSH_X509_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS8:
#ifdef SSHDIST_CERT
      if (ssh_pkcs8_decode_private_key(data, len, key) == SSH_X509_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS12_BROWSER_KEY:
#ifdef SSHDIST_CERT

      if (ssh_skb_pkcs12_decode_private_key(data, len, password,
                                            password_len, key)
          == SSH_PKCS12_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#endif /* SSHDIST_CERT */

    default:
      break;
    }
  return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
}


SshCryptoStatus
ssh_skb_encode(SshSKBType kind,
               const SshPrivateKey key,
               const char *subject, const char *comment,
               const unsigned char *cipher,
               const unsigned char *password, size_t password_len,
               unsigned char **data, size_t *len)
{
  unsigned char *blob;
  size_t bloblen;

  switch (kind)
    {
    case SSH_SKB_SSH_1:



      return ssh_private_key_export_with_passphrase(key,
                                                    ssh_csstr(cipher),
                                                    password ?
                                                    (const char *)password :
                                                    "",
                                                    data, len);
    case SSH_SKB_SSH_2:
      return ssh_pk_export(data, len,
                           SSH_PKF_ENVELOPE_VERSION, 2,
                           SSH_PKF_PRIVATE_KEY, key,
                           SSH_PKF_CIPHER_NAME, cipher,
                           SSH_PKF_CIPHER_KEY, password, password_len,
                           SSH_PKF_HASH_NAME, "sha1",
                           SSH_PKF_END);

    case SSH_SKB_SECSH_1:
      return SSH_CRYPTO_UNSUPPORTED;

    case SSH_SKB_SECSH_2:



      if (ssh_private_key_export_with_passphrase(key,
                                                 ssh_csstr(cipher),
                                                 password ?
                                                 (const char *)password :
                                                 "",
                                                 &blob, &bloblen)
          == SSH_CRYPTO_OK)
        {
          if (ssh2_key_blob_encode(SSH_KEY_MAGIC_PRIVATE,
                                   subject, comment, blob, bloblen,
                                   data, len) == TRUE)
            return SSH_CRYPTO_OK;
        }
      return SSH_CRYPTO_INVALID_PASSPHRASE;

    case SSH_SKB_SSH_X509:
#ifdef SSHDIST_CERT
      if (ssh_x509_encode_private_key(key, data, len) == SSH_X509_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_UNSUPPORTED;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS1:
#ifdef SSHDIST_CERT
      if (ssh_pkcs1_encode_private_key(key, data, len))
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_UNSUPPORTED;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS8_SHROUDED:
#ifdef SSHDIST_CERT
      if (ssh_pkcs8_encrypt_private_key(cipher, "sha1",
                                        password, password_len,
                                        key, data, len) == SSH_X509_OK)
        {
          return SSH_CRYPTO_OK;
        }
      return SSH_CRYPTO_UNSUPPORTED;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS8:
#ifdef SSHDIST_CERT
      if (ssh_pkcs8_encode_private_key(key, data, len) == SSH_X509_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_UNSUPPORTED;
#endif /* SSHDIST_CERT */

    case SSH_SKB_PKCS12_BROWSER_KEY:
#ifdef SSHDIST_CERT
      return SSH_CRYPTO_UNSUPPORTED;
#endif /* SSHDIST_CERT */

    case SSH_SKB_UNKNOWN:
      break;
    }
  return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
}

/* Returns information about the key type. *Needs_secret is set to
   TRUE if decoding if the blob requires some secret code.  Returns
   TRUE on success and FALSE otherwise. */
Boolean ssh_skb_get_type_info(SshSKBType type,
                              Boolean *needs_secret,
                              const char **key_type_name_ret)
{
  /* Table of key types and their 'properties' */
  static const struct SshSKBPropertiesRec
    {
      SshSKBType type;
      Boolean needs_secret;
      const char *name;
    } ssh_skb_properties[] =
      {
        { SSH_SKB_UNKNOWN,              FALSE, "Unknown"},
        { SSH_SKB_SSH_1,                TRUE,  "SSH 1"},
        { SSH_SKB_SSH_2,                TRUE,  "SSH 2"},
        { SSH_SKB_SECSH_1,              TRUE,  "SecSH 1"},
        { SSH_SKB_SECSH_2,              TRUE,  "SecSH 2"},
        { SSH_SKB_SSH_X509,             FALSE, "SSH X.509"},
        { SSH_SKB_PKCS1,                FALSE, "PKCS#1"},
        { SSH_SKB_PKCS8,                FALSE, "PKCS#8"},
        { SSH_SKB_PKCS8_SHROUDED,       TRUE,  "Shrouded PKCS#8"},
        { SSH_SKB_PKCS12_BROWSER_KEY,   TRUE,  "PKCS#12"}
      };
  int i, l;
  /* Find the right type. */
  l = sizeof(ssh_skb_properties) / sizeof(struct SshSKBPropertiesRec);
  for (i = 0; i < l; i++)
    {
      if (type == ssh_skb_properties[i].type)
        {
          /* Type found. */
          if (needs_secret)
            *needs_secret = ssh_skb_properties[i].needs_secret;
          if (key_type_name_ret)
            *key_type_name_ret = ssh_skb_properties[i].name;
          return TRUE;
        }
    }
  /* Type was not found. */
  return FALSE;
}

/* Maps type identifier to canonical name that can be used in protocols. */
const char *ssh_skb_type_to_name(SshSKBType kind)
{
  int i;

  for (i = 0; type_name_map[i].name != NULL; i++)
    {
      if (kind == type_name_map[i].type)
        return type_name_map[i].name;
    }
  return NULL;
}

/* Maps canonical name to type identifier. */
SshSKBType ssh_skb_name_to_type(const char *name)
{
  int i;

  for (i = 0; type_name_map[i].name != NULL; i++)
    {
      if (strcasecmp(name, type_name_map[i].name) == 0)
        return type_name_map[i].type;
    }
  return SSH_SKB_UNKNOWN;
}

SshCryptoStatus ssh_skb_decode_plain_key(unsigned char *key_buffer,
                                         size_t key_buffer_len,
                                         SshPrivateKey *key_output)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  char *cipher = NULL, *hash = NULL;
  SshSKBType key_type;

  SSH_ASSERT(key_buffer != NULL);
  SSH_ASSERT(key_buffer_len != 0);
  SSH_ASSERT(key_output != NULL);

  SSH_DEBUG_HEXDUMP(SSH_D_LOWOK,
                    ("Attempting to decode private key from buffer:"),
                    key_buffer, key_buffer_len);

  status = ssh_skb_get_info(key_buffer, key_buffer_len,
                            &cipher, &hash,
                            NULL, NULL,
                            &key_type, NULL);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to get private key info"));
      return status;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Decoding private key of type: '%s'",
             ssh_skb_type_to_name(key_type)));

  status = ssh_skb_decode(key_type,
                          key_buffer, key_buffer_len,
                          NULL, NULL, NULL, 0, key_output);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed to decode key"));
      return status;
    }

  if (cipher != NULL)
    ssh_free(cipher);
  if (hash != NULL)
    ssh_free(hash);

  return status;
}
#endif /* SSHDIST_APPUTIL_KEYUTIL */
