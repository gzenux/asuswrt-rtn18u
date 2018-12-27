/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Convenience functions for using PKCS#12.
*/

#include "sshincludes.h"
#include "sshpkcs12-conv.h"
#include "sshcryptoaux.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPKCS12Conv"

/* Extracts the public key from a binary certificate. Duplicate
   from ek library */
static SshPublicKey
ssh_pkcs12_extract_public_key_from_certificate(const unsigned char *data,
                                               size_t data_len)
{
#ifdef SSHDIST_CERT
  SshX509Certificate cert;
  SshPublicKey key;

  cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (ssh_x509_cert_decode(data, data_len, cert))
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not decode certificate"));
      ssh_x509_cert_free(cert);
      return NULL;
    }

  if (!ssh_x509_cert_get_public_key(cert, &key))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Can not get the public key from certificate."));
      ssh_x509_cert_free(cert);
      return NULL;
    }
  ssh_x509_cert_free(cert);
  return key;
#else /* SSHDIST_CERT */
  return NULL;
#endif /* SSHDIST_CERT */
}


SshPrivateKey
ssh_pkcs12_conv_get_key_from_bag(SshPkcs12Safe safe,
                                 SshStr passwd,
                                 int index)
{
  SshPrivateKey key;
  SshPkcs12BagType bag_type;
  SshPkcs12Bag bag;

  ssh_pkcs12_safe_get_bag(safe, index, &bag_type, &bag);

  switch (bag_type)
    {
    case SSH_PKCS12_BAG_SHROUDED_KEY:
      /* Bag contains a shrouded private key key. We must use password
         to decrypt the key. */
      if (!ssh_pkcs12_bag_get_shrouded_key(bag, passwd, &key))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Got shrouded key from bag %d.", index));
          return key;
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Error getting shrouded key, bag %d.", index));
          return NULL;
        }
      break;
    case SSH_PKCS12_BAG_KEY:
      /* Bag contains plaintext private key. */
      if (!ssh_pkcs12_bag_get_key(bag, &key))
        {
          SSH_DEBUG(SSH_D_MIDOK, ("Got plaintext key from bag %d.", index));
          return key;
        }
      else
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("Error getting plaintext key, bag %d.", index));
          return NULL;
        }
      break;
    case SSH_PKCS12_BAG_CERT:
    default:
      SSH_DEBUG(SSH_D_MIDOK, ("No key in bag %d.", index));
      return NULL;
    }
}


Boolean
ssh_pkcs12_conv_get_cert_from_bag(SshPkcs12Safe safe,
                                  SshStr passwd,
                                  int index,
                                  unsigned char **cert,
                                  size_t *cert_len)
{
  SshPkcs12BagType bag_type;
  SshPkcs12Bag bag;
  const unsigned char *tmp_cert;

  ssh_pkcs12_safe_get_bag(safe, index, &bag_type, &bag);

  if (bag == NULL)
    return FALSE;

  switch (bag_type)
    {
    case SSH_PKCS12_BAG_CERT:
      if (ssh_pkcs12_bag_get_cert(bag, &tmp_cert, cert_len) == SSH_PKCS12_OK)
        {
          if ((*cert = ssh_memdup(tmp_cert, *cert_len)) != NULL)
            return TRUE;
          else
            return FALSE;
        }
      /* fallthrough */
    default:
      SSH_DEBUG(SSH_D_MIDOK, ("No cert in bag %d.", index));
      return FALSE;
    }
}


/* Decode the n:th public key from the PKCS#12 block. Use the
   passphrase for both integrity checks and the encryption (like the
   browser does.)  */
SshPkcs12Status
ssh_pkcs12_conv_decode_public_key(const unsigned char *data, size_t len,
                                  SshStr passwd,
                                  SshUInt32 n,
                                  SshPublicKey *key_ret)
{
  SshPkcs12PFX pfx;
  SshPkcs12Safe safe;
  SshPkcs12IntegrityMode type;
  int i, j, num_safes, num_bags;
  SshPrivateKey key = NULL;
  SshPublicKey pub = NULL;
  SshPkcs12SafeProtectionType prot;
  SshPkcs12Status status = SSH_PKCS12_OK;
  SshUInt32 occurance = 0;

  /* Decode data */
  if (ssh_pkcs12_pfx_decode(data, len, &type, &pfx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decoding of PKCS12 blob failed."));
      return SSH_PKCS12_FORMAT_ERROR;
    }

  if (type == SSH_PKCS12_INTEGRITY_PASSWORD)
    {
      if (ssh_pkcs12_pfx_verify_hmac(pfx, passwd))
        {
          status = SSH_PKCS12_FORMAT_ERROR;
          goto done;
        }
    }

  num_safes = ssh_pkcs12_pfx_get_num_safe(pfx);
  for (i = 0; i < num_safes; i++)
    {
      ssh_pkcs12_pfx_get_safe(pfx, i, &prot, &safe);

      switch(prot)
        {
        case SSH_PKCS12_SAFE_ENCRYPT_NONE:
          /* Safe is not encrypted, we can traverse bags immediately */
          num_bags = ssh_pkcs12_safe_get_num_bags(safe);
          for (j = 0; j < num_bags; j++)
            {
              key = ssh_pkcs12_conv_get_key_from_bag(safe, passwd, j);
              if (key)
                {
                  if (occurance == n)
                    goto done;
                  occurance++;
                }
            }
          break;

        case SSH_PKCS12_SAFE_ENCRYPT_PASSWORD:
          /* Safe is encrypted with password. WE must first decrypt the
             safe before we can access the bags. */
          if (!ssh_pkcs12_safe_decrypt_password(safe, passwd))
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Safe decrypted succesfully."));
              /* Traverse the bags */
              num_bags = ssh_pkcs12_safe_get_num_bags(safe);
              for (j = 0; j < num_bags; j++)
                {
                  key = ssh_pkcs12_conv_get_key_from_bag(safe, passwd, j);
                  if (key)
                    {
                      if (occurance == n)
                        goto done;
                      occurance++;
                    }
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_ERROR, ("Invalid password"));
              status = SSH_PKCS12_FORMAT_ERROR;
              goto done;
            }
          break;

        default:
          SSH_DEBUG(SSH_D_ERROR, ("Unkown protection type"));
          break;
        }
    }

  if (key == NULL)
    status = SSH_PKCS12_FORMAT_ERROR;

done:
  ssh_pkcs12_pfx_free(pfx);
  if (key &&
      ssh_private_key_derive_public_key(key, &pub) == SSH_CRYPTO_OK)
    *key_ret = pub;
  else
    *key_ret = NULL;

  if (key)
    ssh_private_key_free(key);

  return status;
}

/* Decode the n:th private key from the PKSC#12 block. Use the
   passphrase for both integrity checks and the encryption (like the
   browser does.)  */
SshPkcs12Status
ssh_pkcs12_conv_decode_private_key(const unsigned char *data, size_t len,
                                   SshStr passwd,
                                   SshUInt32 n,
                                   SshPrivateKey *key_ret)
{
  SshPkcs12PFX pfx;
  SshPkcs12Safe safe;
  SshPkcs12IntegrityMode type;
  int i, j, num_safes, num_bags;
  SshPrivateKey key = NULL;
  SshPkcs12SafeProtectionType prot;
  SshPkcs12Status status = SSH_PKCS12_OK;
  SshUInt32 occurance = 0;

  /* Decode data */
  if (ssh_pkcs12_pfx_decode(data, len, &type, &pfx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decoding of PKCS12 blob failed."));
      return SSH_PKCS12_FORMAT_ERROR;
    }

  if (type == SSH_PKCS12_INTEGRITY_PASSWORD)
    {
      if (ssh_pkcs12_pfx_verify_hmac(pfx, passwd))
        {
          status = SSH_PKCS12_FORMAT_ERROR;
          goto done;
        }
    }

  num_safes = ssh_pkcs12_pfx_get_num_safe(pfx);
  for (i = 0; i < num_safes; i++)
    {
      ssh_pkcs12_pfx_get_safe(pfx, i, &prot, &safe);

      switch(prot)
        {
        case SSH_PKCS12_SAFE_ENCRYPT_NONE:
          /* Safe is not encrypted, we can traverse bags immediately */
          num_bags = ssh_pkcs12_safe_get_num_bags(safe);
          for (j = 0; j < num_bags; j++)
            {
              key = ssh_pkcs12_conv_get_key_from_bag(safe, passwd, j);
              if (key)
                {
                  if (occurance == n)
                    goto done;
                  occurance++;
                }
            }
          break;

        case SSH_PKCS12_SAFE_ENCRYPT_PASSWORD:
          /* Safe is encrypted with password. WE must first decrypt the
             safe before we can access the bags. */
          if (!ssh_pkcs12_safe_decrypt_password(safe, passwd))
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Safe decrypted succesfully."));
              /* Traverse the bags */
              num_bags = ssh_pkcs12_safe_get_num_bags(safe);
              for (j = 0; j < num_bags; j++)
                {
                  key = ssh_pkcs12_conv_get_key_from_bag(safe, passwd, j);
                  if (key)
                    {
                      if (occurance == n)
                        goto done;
                      occurance++;
                    }
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_ERROR, ("Invalid password"));
              status = SSH_PKCS12_FORMAT_ERROR;
              goto done;
            }
          break;

        default:
          SSH_DEBUG(SSH_D_ERROR, ("Unkown protection type"));
          break;
        }
    }
  if (key == NULL)
    status = SSH_PKCS12_FORMAT_ERROR;

 done:
  ssh_pkcs12_pfx_free(pfx);
  *key_ret = key;

  return status;
}

static SshPkcs12Status
ssh_canonical_export_public_key(SshPublicKey key,
                                unsigned char **key_buf, size_t *key_buf_len)
{
  /* Select the scheme to export key */
  if (ssh_public_key_select_scheme(key,
                                   SSH_PKF_SIGN, NULL,
                                   SSH_PKF_ENCRYPT, NULL,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Couldn't change encrypt methods\n"));
      return SSH_PKCS12_FORMAT_ERROR;
    }

  if (ssh_public_key_export(key, key_buf, key_buf_len) != SSH_CRYPTO_OK)
    {
      return SSH_PKCS12_FORMAT_ERROR;
    }

  return SSH_PKCS12_OK;
}

static SshPkcs12Status
ssh_pkcs12_safe_get_cert(SshPkcs12Safe safe,
                         unsigned char *public_key_hint_buf,
                         int public_key_len,
                         SshUInt32 *occurance,
                         SshStr passwd,
                         unsigned char **cert_buf, size_t *cert_buf_len)
{
  Boolean success;
  SshPublicKey cert_pub_key;
  unsigned char *cert_pub_key_buf;
  size_t cert_key_len;
  int num_bags, j;
  SshPkcs12Status status;

  cert_pub_key_buf = NULL;
  cert_pub_key = NULL;
  status = SSH_PKCS12_OK;

  num_bags = ssh_pkcs12_safe_get_num_bags(safe);

  /* Traverse the bags */
  for (j = 0; j < num_bags; j++)
    {
      success = ssh_pkcs12_conv_get_cert_from_bag(safe,
                                                  passwd, j,
                                                  cert_buf, cert_buf_len);
      if (!success)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Couldn't get certificate from safe?"));
          goto free_locals;
        }

      /* Find the matching public key for certificate */
      if (public_key_hint_buf != NULL)
        {
          cert_pub_key =
            ssh_pkcs12_extract_public_key_from_certificate(*cert_buf,
                                                           *cert_buf_len);

          /* If cannot find the public key, no way to match keys */
          if (cert_pub_key == NULL)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Cannot return pub key for cert"));
              goto free_locals;
            }

          /* Export the certificate public key into locale buffer */
          if (ssh_canonical_export_public_key(cert_pub_key,
                                              &cert_pub_key_buf, &cert_key_len)
              == SSH_PKCS12_OK)
            {
              /* Compare now the keys for exact match */
              if (cert_key_len == public_key_len &&
                  memcmp(public_key_hint_buf, cert_pub_key_buf, cert_key_len)
                  == 0)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW, ("Public keys match!!"));
                  ssh_public_key_free(cert_pub_key);
                  ssh_xfree(cert_pub_key_buf);
                  cert_pub_key = NULL;
                  cert_pub_key_buf = NULL;
                  return SSH_PKCS12_OK;

                }
            }
        }
      else
        {
          if (*occurance == 0)
            goto done;
          else
            (*occurance)--;
        }

    free_locals:
      ssh_public_key_free(cert_pub_key);
      ssh_free(cert_pub_key_buf);
      ssh_free(*cert_buf);
      *cert_buf = NULL;
      cert_pub_key = NULL;
      cert_pub_key_buf = NULL;
    }
 done:
  if (*cert_buf == NULL && status == SSH_PKCS12_OK)
    {
      status = SSH_PKCS12_INVALID_INDEX;
    }
  return status;
}

/* Decode the n:th certificate from the PKSC#12 block. Use the
   passphrase for both integrity checks and the encryption (like the
   browser does. The private_key_hint argument is (if not NULL) the
   private_key whose certificate is to be fetched)  */

SshPkcs12Status ssh_pkcs12_conv_decode_cert(const unsigned char *data,
                                            size_t len,
                                            SshStr passwd,
                                            SshUInt32 n,
                                            SshPrivateKey private_key_hint,
                                            unsigned char **cert_buf,
                                            size_t *cert_buf_len)
{
  SshPkcs12PFX pfx;
  SshPkcs12Safe safe;
  SshPkcs12IntegrityMode type;
  int i, num_safes;
  SshPkcs12SafeProtectionType prot;
  SshPkcs12Status status;
  unsigned char *public_key_buf = NULL;
  size_t public_key_len = 0;
  SshPublicKey public_key;

  public_key_buf = NULL;

  *cert_buf = NULL;
  public_key = NULL;
  status = SSH_PKCS12_OK;

  if (private_key_hint != NULL)
    {
      if (ssh_private_key_derive_public_key(private_key_hint, &public_key)
          != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("Couldn't derive public key!\n"));
        }
      if (ssh_canonical_export_public_key(public_key,  &public_key_buf,
                                          &public_key_len)
          != SSH_PKCS12_OK)
        {
          SSH_DEBUG(SSH_D_ERROR, ("public key export failed"));
        };

      if (public_key != NULL)
        {
          ssh_public_key_free(public_key);
        }
    }

  /* Decode data */
  if (ssh_pkcs12_pfx_decode(data, len, &type, &pfx))
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decoding of PKCS12 blob failed."));
      return SSH_PKCS12_FORMAT_ERROR;
    }

  if (type == SSH_PKCS12_INTEGRITY_PASSWORD)
    {
      if (ssh_pkcs12_pfx_verify_hmac(pfx, passwd))
        {
          status = SSH_PKCS12_FORMAT_ERROR;
          goto done;
        }
    }

  num_safes = ssh_pkcs12_pfx_get_num_safe(pfx);

  for (i = 0; i < num_safes; i++)
    {
      ssh_pkcs12_pfx_get_safe(pfx, i, &prot, &safe);

      switch (prot)
        {
        case SSH_PKCS12_SAFE_ENCRYPT_NONE:
          /* Safe is not encrypted, we can traverse bags immediately */
          status = ssh_pkcs12_safe_get_cert(safe,
                                            public_key_buf, public_key_len,
                                            &n, passwd,
                                            cert_buf, cert_buf_len);
          if (status == SSH_PKCS12_OK)
            {
              if (n == 0) goto done;
            }
          break;

        case SSH_PKCS12_SAFE_ENCRYPT_PASSWORD:
          /* Safe is encrypted with password. We must first decrypt the
             safe before we can access the bags. */

          if (!ssh_pkcs12_safe_decrypt_password(safe, passwd))
            {
              SSH_DEBUG(SSH_D_MIDOK, ("Safe decrypted succesfully."));

              status = ssh_pkcs12_safe_get_cert(safe,
                                                public_key_buf, public_key_len,
                                                &n, passwd,
                                                cert_buf, cert_buf_len);
              if (status == SSH_PKCS12_OK)
                {
                  if (n == 0) goto done;
                }
            }
          else
            {
              SSH_DEBUG(SSH_D_ERROR, ("Invalid password"));

              status = SSH_PKCS12_FORMAT_ERROR;
              goto done;
            }
          break;

        default:
          SSH_DEBUG(SSH_D_ERROR, ("Unknown protection type"));
          status = SSH_PKCS12_FORMAT_ERROR;
          break;
        }
    }

 done:
  ssh_free(public_key_buf);
  ssh_pkcs12_pfx_free(pfx);

  return status;
}
#endif /* SSHDIST_CERT */
