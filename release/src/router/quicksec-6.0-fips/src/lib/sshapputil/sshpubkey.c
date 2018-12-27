/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"

#ifdef SSHDIST_APPUTIL_KEYUTIL
#include "sshcrypt.h"
#include "sshcryptoaux.h"
#include "sshpubkey.h"
#include "sshkeyblob1.h"
#include "sshkeyblob2.h"
#include "ssh2pubkeyencode.h"
#include "sshdsprintf.h"
#include "sshpem.h"

#ifdef SSHDIST_CERT
#include "x509.h"
#include "x509internal.h"
#include "sshpkcs12-conv.h"
#endif /* SSHDIST_CERT */

#define SSH_DEBUG_MODULE "SshPKB"

struct SshPkbTypeNameMap {
  SshPKBType type;
  char *name;
};

static const struct SshPkbTypeNameMap type_name_map[] = {
  { SSH_PKB_SSH, "ssh-crypto-library-public-key@ssh.com" },
  { SSH_PKB_SSH_1, "secure-shell-1-public-key@ssh.com" },
  { SSH_PKB_SSH_2, "secure-shell-2-public-key@ssh.com" },
  { SSH_PKB_FROM_X509, "x509-certificate" },
  { SSH_PKB_PKCS12_BROWSER_KEY , "pkcs12-pfx" },
  { SSH_PKB_SUBJECT_PKINFO, "x509-subject-pkinfo" },
  { SSH_PKB_UNKNOWN, NULL }
};

#ifdef SSHDIST_CERT
static SshCryptoStatus
ssh_decode_x509_subject_pkinfo_pubkey(const unsigned char *data,
                                      size_t data_len,
                                      SshPublicKey *pkey)
{
  unsigned char *buf;
  size_t buf_len;
  SshAsn1Context asn1context;
  SshAsn1Node node;
  SshX509PublicKeyStruct pkinfo;

  if ((buf =
       ssh_pem_decode_with_key(data, data_len, NULL, 0, &buf_len)) == NULL)
    {
      buf = ssh_memdup(data, data_len);
      buf_len = data_len;
    }

  if (buf == NULL)
    return SSH_CRYPTO_UNKNOWN_KEY_TYPE;

  if ((asn1context = ssh_asn1_init()) == NULL)
    {
    failure:
      ssh_free(buf);
      return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
    }

  if (ssh_asn1_decode_node(asn1context, buf, buf_len, &node)
      != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(asn1context);
      goto failure;
    }

  if (ssh_x509_decode_asn1_public_key(asn1context,
                                      node,
                                      &pkinfo)
      != SSH_X509_OK)
    {
      ssh_asn1_free(asn1context);
      goto failure;
    }

  if (pkey)
    *pkey = pkinfo.public_key;
  else
    ssh_public_key_free(pkinfo.public_key);

  ssh_free(buf);

  return SSH_CRYPTO_OK;
}
#endif /* SSHDIST_CERT */

/* Get type of the public key from the keyblob given as `data' string
   whose length is `len' bytes. The call detects type of the public
   key and fills corresponding value into `kind'. If comment is not
   NULL, and the key format supports visible comments, a copy of
   comment string is returned in `comment'.

   The function returns SSH_CRYPTO_OK if the key format was
   determined, and SSH_CRYPTO_UNKNOWN_KEY_TYPE if not. */
SshCryptoStatus
ssh_pkb_get_info(const unsigned char *data, size_t len,
                 unsigned char **unarmored_data, size_t *unarmored_len,
                 SshPKBType *kind, char **subject, char **comment)
{
#ifdef SSHDIST_CERT
  SshX509Certificate c;
#endif /* SSHDIST_CERT */
  SshPublicKey pk;
  unsigned long magic;
  unsigned char *tmp, *blob = NULL;
  char  *tmpsubject = NULL, *tmpcomment = NULL;
  size_t bloblen;

  /* Check for SSH public key. */



  if (ssh_public_key_import(data, len, &pk) == SSH_CRYPTO_OK)
    {
      ssh_public_key_free(pk);
      if (kind)
        *kind = SSH_PKB_SSH;
      if (comment)
        *comment = ssh_strdup("-");
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      return SSH_CRYPTO_OK;
    }

#ifdef SSHDIST_CERT
  /* Check for X.509 cert. */



  if ((c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) != NULL)
    {
      if (ssh_x509_cert_decode(data, len, c) == SSH_X509_OK)
        {
          if (kind)
            *kind = SSH_PKB_FROM_X509;
          if (comment)
            {
              if (ssh_x509_cert_get_subject_name(c, comment) == FALSE)
                *comment = ssh_strdup("-");
            }
          ssh_x509_cert_free(c);
          if (unarmored_len)
            *unarmored_len = len;
          if (unarmored_data)
            *unarmored_data = ssh_memdup(data, len);
          return SSH_CRYPTO_OK;
        }
      else
        {
          ssh_x509_cert_free(c);
        }
    }

  if (ssh_pkcs12_pfx_decode(data, len, NULL, NULL) == SSH_PKCS12_OK)
    {
      if (kind)
        *kind = SSH_PKB_PKCS12_BROWSER_KEY;
      if (unarmored_len)
        *unarmored_len = len;
      if (unarmored_data)
        *unarmored_data = ssh_memdup(data, len);
      return SSH_CRYPTO_OK;
    }
#endif /* SSHDIST_CERT */

  if ((tmp = ssh_memdup(data, len)) != NULL)
    {
      magic = ssh2_key_blob_decode(tmp, len, FALSE,
                                   &tmpsubject, &tmpcomment, &blob, &bloblen);

      if (magic == SSH_KEY_MAGIC_SSH1_PUBLIC)
        {
          if (kind)
            *kind = SSH_PKB_SSH_1;
          if (subject)
            *subject = tmpsubject;
          else
            ssh_free(tmpsubject);
          if (comment)
            *comment = tmpcomment;
          else
            ssh_free(tmpcomment);

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
          return SSH_CRYPTO_OK;
        }
      else if (magic == SSH_KEY_MAGIC_PUBLIC)
        {
          if (kind)
            *kind = SSH_PKB_SSH_2;

          if (comment)
            *comment = tmpcomment;
          else
            ssh_free(tmpcomment);
          if (subject)
            *subject = tmpsubject;
          else
            ssh_free(tmpsubject);

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
          return SSH_CRYPTO_OK;
        }
      else if (blob)
        {
          memset(blob, 0, bloblen);
          ssh_free(blob);

          if (tmpcomment != NULL)
            ssh_free(tmpcomment);
          tmpcomment = NULL;

          if (tmpsubject != NULL)
            ssh_free(tmpsubject);
          tmpsubject = NULL;
        }
    }

  if (tmpcomment != NULL)
    ssh_free(tmpcomment);
  tmpcomment = NULL;

  if (tmpsubject != NULL)
    ssh_free(tmpsubject);
  tmpsubject = NULL;

#ifdef SSHDIST_CERT
  if (ssh_decode_x509_subject_pkinfo_pubkey(data, len, NULL) == SSH_CRYPTO_OK)
    {
      if (kind)
        *kind = SSH_PKB_SUBJECT_PKINFO;
      return SSH_CRYPTO_OK;
    }
#endif /* SSHDIST_CERT */

  SSH_DEBUG(SSH_D_MIDOK, ("Could not deduce the public key type"));
  if (kind)
    *kind = SSH_PKB_UNKNOWN;
  return SSH_CRYPTO_UNKNOWN_KEY_TYPE;
}


/* Returns information about the key type. *Needs_secret is set to
   TRUE if decoding if the blob requires some secret code.  A
   printable name of the type is returned in
   key_type_name_ret. Returns TRUE on success and FALSE otherwise. */
Boolean
ssh_pkb_get_type_info(SshPKBType type,
                      Boolean *needs_secret,
                      const char **key_type_name_ret)
{



  /* Table of key types and their 'properties' */
  static const struct SshPKBPropertiesRec
  {
    SshPKBType type;
    Boolean needs_secret;
    const char *name;
  } ssh_pkb_properties[] =
    {
      { SSH_PKB_UNKNOWN, FALSE, "Unknown"},
      { SSH_PKB_SUBJECT_PKINFO, FALSE, "X.509 subjectPkInfo" },
      { SSH_PKB_SSH, FALSE, "SSH Key"},
      { SSH_PKB_SSH_2, FALSE, "SSH2 public key" }
#ifdef SSHDIST_CERT
      , { SSH_PKB_FROM_X509, FALSE, "Imported from X.509 cert"}
      , { SSH_PKB_PKCS12_BROWSER_KEY, TRUE, "PKCS12 Browser pfx"}
#endif /* SSHDIST_CERT */
    };
  int i, l;

  /* Find the right type. */
  l = sizeof(ssh_pkb_properties) / sizeof(struct SshPKBPropertiesRec);
  for (i = 0; i < l; i++)
    {
      if (type == ssh_pkb_properties[i].type)
        {
          /* Type found. */
          if (needs_secret)
            *needs_secret = ssh_pkb_properties[i].needs_secret;
          if (key_type_name_ret)
            *key_type_name_ret = ssh_pkb_properties[i].name;
          return TRUE;
        }
    }
  /* Type was not found. */
  return FALSE;
}

#ifdef SSHDIST_CERT
/* Extracts the public key from a binary certificate. */
static SshPublicKey
ssh_pkb_extract_public_key_from_certificate(const unsigned char *data,
                                            size_t data_len)
{
  SshX509Certificate cert;
  SshPublicKey key;

  if ((cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT)) == NULL)
    return NULL;

  if (ssh_x509_cert_decode(data, data_len, cert))
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("Could not decode certificate"));
      ssh_x509_cert_free(cert);
      return NULL;
    }

  if (!ssh_x509_cert_get_public_key(cert, &key))
    {
      SSH_DEBUG(SSH_D_UNCOMMON,
                ("Can not get the public key from certificate."));
      ssh_x509_cert_free(cert);
      return NULL;
    }
  ssh_x509_cert_free(cert);
  return key;
}

static SshStr
get_sshstr(const unsigned char *str, size_t len)
{
  SshStr passwd;
  passwd = ssh_str_make(SSH_CHARSET_ISO_8859_1,
                        ssh_memdup(str, len), len);
  return passwd;
}

static SshPkcs12Status
ssh_pkb_pkcs12_decode_public_key(const unsigned char *data,
                                 size_t len,
                                 const unsigned char *password,
                                 size_t pass_len,
                                 SshPublicKey *key)
{
  SshPkcs12Status status;
  SshStr pass = get_sshstr(password, pass_len);

  if (pass == NULL)
    return SSH_PKCS12_ERROR;

  status =  ssh_pkcs12_conv_decode_public_key(data, len, pass, 0, key);
  ssh_str_free(pass);
  return status;
}



#endif /* SSHDIST_CERT */

/* Get public key out from the data blob given as `data' and `len'.
   If the `kind' argument specifies an encrypted key format, the
   password (or passphares) needed to decrypt the key is given as
   `password' and `password_len'.

   The function returns SSH_CRYPTO_OK if the public key was
   successfully decoded from the data. If the password is incorrect,
   the return value shall be SSH_CRYPTO_INVALID_PASSPHRASE, and if the
   key blob is not of specified type, the return value shall be
   SSH_CRYPTO_CORRUPTED_KEY_FORMAT.
*/
SshCryptoStatus
ssh_pkb_decode(SshPKBType kind,
               const unsigned char *data, size_t len,
               const unsigned char *password, size_t password_len,
               SshPublicKey *key)
{
  size_t bloblen;
  unsigned char *tmp, *blob = NULL;
  SshPublicKey tmp_key;

  switch (kind)
    {
    case SSH_PKB_SSH:
      if (ssh_public_key_import(data, len, key) == SSH_CRYPTO_OK)
        return SSH_CRYPTO_OK;
      break;

    case SSH_PKB_SSH_1:
    case SSH_PKB_SSH_2:
      if ((tmp = ssh_memdup(data, len)) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      switch (ssh2_key_blob_decode(tmp, len, FALSE,
                                   NULL, NULL, &blob, &bloblen))
        {
        case SSH_KEY_MAGIC_PUBLIC:
          tmp_key = ssh_decode_pubkeyblob(blob, bloblen);
          ssh_free(blob);
          if (tmp_key)
            {
              *key = tmp_key;
              return SSH_CRYPTO_OK;
            }
          return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#ifdef SSHDIST_APPUTIL_SSH1ENCODE
        case SSH_KEY_MAGIC_SSH1_PUBLIC:
          {
            SshCryptoStatus status;
            char *comment;

            status = ssh1_decode_pubkeyblob(blob, bloblen, &comment, key);
            if (comment != NULL)
              ssh_free(comment);
            return status;
          }
#endif /* SSHDIST_APPUTIL_SSH1ENCODE */
        default:
          /* It may still be unarmored format.  Let's try. */
          tmp_key = ssh_decode_pubkeyblob(data, len);
          ssh_free(blob);
          if (tmp_key)
            {
              *key = tmp_key;
              return SSH_CRYPTO_OK;
            }
          return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
        }
      break;

#ifdef SSHDIST_CERT
    case SSH_PKB_FROM_X509:
      *key = ssh_pkb_extract_public_key_from_certificate(data, len);
      if (*key != NULL)
        return SSH_CRYPTO_OK;
      break;
    case SSH_PKB_PKCS12_BROWSER_KEY:
      if (ssh_pkb_pkcs12_decode_public_key(data, len, password,
                                           password_len, key)
          == SSH_PKCS12_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
#endif /* SSHDIST_CERT */

#ifdef SSHDIST_CERT
    case SSH_PKB_SUBJECT_PKINFO:
      if (ssh_decode_x509_subject_pkinfo_pubkey(data, len, key)
          == SSH_CRYPTO_OK)
        return SSH_CRYPTO_OK;
      break;
#endif /* SSHDIST_CERT */

    case SSH_PKB_UNKNOWN:
    default: SSH_DEBUG(SSH_D_FAIL, ("pkb decode with unknown key type"));
      break;
    }
  return SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
}

/* Maps type identifier to canonical name that can be used in protocols. */
const char *ssh_pkb_type_to_name(SshPKBType kind)
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
SshPKBType ssh_pkb_name_to_type(const char *name)
{
  int i;

  for (i = 0; type_name_map[i].name != NULL; i++)
    {
      if (strcasecmp(name, type_name_map[i].name) == 0)
        return type_name_map[i].type;
    }
  return SSH_PKB_UNKNOWN;
}


/* Get the SshPublicKey 'key' out as a data blob of the specified
   SshPKBType 'kind'.  If password and password_len are given, they
   are applied where needed.  The data returned in 'blob' is a null
   terminated string and it is ready to be written into a file, for
   example (not really in case of 'kind' being SSH_PKB_SSH!).  After a
   successful return, the caller must free the blob at some point.  If
   comment is not NULL, it will be set into the blob in an appropriate
   place, if such exists.  If subject is not NULL, it will be set into
   the blob in an appropriate place, if such exists.

   The function returns SSH_CRYPTO_OK if the public key was
   successfully encoded into a data blob.  If the 'kind' type is not
   supported or specified, the return value shall be
   SSH_CRYPTO_UNSUPPORTED.  If there are some trouble of other
   reasons, SSH_CRYPTO_OPERATION_FAILED will be returned.

   Supported types are:
   * SSH2 format (SSH_PKB_SSH_2)
   * crypto library's propiertary (?) format (SSH_PKB_SSH)

*/
SshCryptoStatus
ssh_pkb_encode(SshPKBType kind, unsigned char **blob,
               const unsigned char *subject, const unsigned char *comment,
               const unsigned char *password, size_t password_len,
               SshPublicKey key)
{

  unsigned char *key_blob = NULL, *tmp;
  size_t len, finished_len;
  Boolean success;

  len = 0;
  switch (kind)
    {

    case SSH_PKB_SSH_2:
      len = ssh_encode_pubkeyblob(key, &key_blob);
      if (len == 0)
        {
          if (key_blob != NULL)
            ssh_free(key_blob);
          return SSH_CRYPTO_OPERATION_FAILED;
        }
      success = ssh2_key_blob_encode(SSH_KEY_MAGIC_PUBLIC,
                                     (const char *)subject,
                                     (const char *)comment,
                                     key_blob, len, &tmp, &finished_len);
      ssh_xfree(key_blob);
      if (success)
        {
          ssh_dsprintf(blob, "%.*s", finished_len, tmp);
          ssh_xfree(tmp);
          return SSH_CRYPTO_OK;
        }
      else
          return SSH_CRYPTO_OPERATION_FAILED;

    case SSH_PKB_SSH:
      if (ssh_public_key_export(key, blob, &len) == SSH_CRYPTO_OK)
        return SSH_CRYPTO_OK;
      else
        return SSH_CRYPTO_OPERATION_FAILED;

    default:
      /* Not supported:
         - SSH_PKB_FROM_X509
         - SSH_PKB_PKCS12_BROWSER_KEY
         - SSH_PKB_SSH_1 */
      break;
    }
  return SSH_CRYPTO_UNSUPPORTED;
}
#endif /* SSHDIST_APPUTIL_KEYUTIL */
