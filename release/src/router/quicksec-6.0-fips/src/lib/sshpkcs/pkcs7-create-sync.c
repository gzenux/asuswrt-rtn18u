/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoding.

   This library can handle BER or DER encoded PKCS#7 messages, however,
   it produces DER messages. This is because the underlaying ASN.1
   BER/DER code is biased towards DER.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshasn1.h"
#include "sshber.h"
#include "sshgetput.h"
#include "sshglist.h"

#include "x509.h"
#include "x509internal.h"
#include "oid.h"
#include "sshpkcs5.h"
#include "pkcs6.h"
#include "sshpkcs7.h"
#include "pkcs7-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPkcs7Encode"

static size_t
pkcs7_get_default_cipher_key_length(const char *cipher_name)
{
  size_t key_length;

  if (!ssh_cipher_supported(cipher_name))
    return 0;

  if (ssh_cipher_has_fixed_key_length(cipher_name))
    key_length = ssh_cipher_get_key_length(cipher_name);
  else




    key_length = 16;

  return key_length;
}

static unsigned char *
pkcs7_digest_encrypt(unsigned char *algorithm,
                     unsigned char *key, size_t key_len,
                     unsigned char *iv, size_t iv_len,
                     unsigned char *digest, size_t digest_len,
                     size_t *digest_len_out)
{
  SshCipher cipher;
  size_t pad_len = 0, block_len, i;
  unsigned char *tmp;

  if (digest_len_out)
    *digest_len_out = 0;

  if (ssh_cipher_allocate(ssh_csstr(algorithm), key, key_len, TRUE, &cipher)
      == SSH_CRYPTO_OK)
    {
      if (ssh_cipher_set_iv(cipher, iv) != SSH_CRYPTO_OK)
        {
          ssh_free(digest);
          ssh_cipher_free(cipher);
          return NULL;
        }


      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_free(digest);
          ssh_cipher_free(cipher);
          return NULL;
        }

      block_len = ssh_cipher_get_block_length(ssh_cipher_name(cipher));
      SSH_ASSERT(block_len != 0);

      if (digest_len % block_len)
        {
          pad_len = block_len - (digest_len % block_len);
          if ((tmp = ssh_realloc(digest, digest_len, digest_len + pad_len))
              != NULL)
            {
              digest = tmp;
              for (i = 0; i < pad_len; i++)
                digest[i + digest_len] = pad_len;
              if (ssh_cipher_transform(cipher,
                                       digest, digest,
                                       digest_len + pad_len) != SSH_CRYPTO_OK)
                {
                  ssh_free(digest);
                  ssh_cipher_free(cipher);
                  return NULL;
                }
            }
          else
            {
              ssh_free(digest);
              ssh_cipher_free(cipher);
              return NULL;
            }
        }
      else
        {
          if (ssh_cipher_transform(cipher, digest, digest, digest_len) !=
              SSH_CRYPTO_OK)
            {
              ssh_free(digest);
              ssh_cipher_free(cipher);
              return NULL;
            }
        }

        if (digest_len_out)
          *digest_len_out = digest_len + pad_len;
      ssh_cipher_free(cipher);
    }
  return digest;
}

SshPkcs7
ssh_pkcs7_create_signed_data(SshPkcs7 content,
                             SshPkcs7SignerInfo signers)
{
  SshPkcs7SignerInfo signer;
  unsigned char *digest;
  size_t digest_len, i;
  SshPkcs7 c;
  Boolean failed = FALSE;

  c = pkcs7_create_signed_data(content);

  signer = signers;
  while (signer)
    {
      /* The implementation is suboptimal. Digest of the message is
         calculated multiple times even if the signers would use the
         same content digest algorithm. */
      ssh_glist_add_item(c->signer_infos, signer, SSH_GLIST_HEAD);
      if (signer->private_key)
        {
          digest = pkcs7_digest_content(c->content,
                                        signer->digest_algorithm, signer,
                                        &digest_len);
          /* Private key might be NULL pointer if adding signature. */
          if (digest)
            {
              ADDOID(c->digest_algorithms, signer->digest_algorithm);
              i =
                ssh_private_key_max_signature_output_len(signer->private_key);

              signer->encrypted_digest = ssh_malloc(i);
              if (signer->encrypted_digest == NULL ||
                  ssh_private_key_sign_digest(signer->private_key,
                                              digest, digest_len,
                                              signer->encrypted_digest,
                                              i,
                                              &signer->encrypted_digest_length)
                  != SSH_CRYPTO_OK)
                failed = TRUE;

              ssh_free(digest);
            }
        }
      signer = signer->next;
    }
  if (failed)
    {
      ssh_pkcs7_free(c);
      return NULL;
    }

  return c;
}

SshPkcs7
ssh_pkcs7_create_enveloped_data(SshPkcs7 content,
                                const char *data_encryption,
                                SshPkcs7RecipientInfo recipients)
{
  SshPkcs7 c;
  unsigned char *key;
  size_t key_len, i;
  SshPkcs7RecipientInfo recipient;

  key_len = pkcs7_get_default_cipher_key_length(data_encryption);
  if (key_len == 0)
    return NULL;

  if ((key = ssh_malloc(key_len)) == NULL)
    return NULL;

  for (i = 0; i < key_len; i++)
    key[i] = ssh_random_get_byte();

  c = pkcs7_create_enveloped_data(content, data_encryption, key, key_len);
  if (!c)
    {
      memset(key, 0, key_len);
      ssh_free(key);
      return NULL;
    }

  recipient = recipients;
  while (recipient)
    {
      ssh_glist_add_item(c->recipient_infos, recipient, SSH_GLIST_HEAD);
      if (ssh_public_key_select_scheme(recipient->public_key,
                                       SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                       SSH_PKF_END)
          == SSH_CRYPTO_OK)
        {
          /* We can encrypt using this recipients public key. */
          i = ssh_public_key_max_encrypt_output_len(recipient->public_key);
          recipient->encrypted_key = ssh_malloc(i);
          if (recipient->encrypted_key)
            {
              ssh_public_key_encrypt(recipient->public_key,
                                     key, key_len,
                                     recipient->encrypted_key, i,
                                     &recipient->encrypted_key_length);
            }
        }
      recipient = recipient->next;
    }

  memset(key, 0, key_len);
  ssh_free(key);
  return c;
}


SshPkcs7
ssh_pkcs7_create_signed_and_enveloped_data(
        SshPkcs7 content,
        const unsigned char *data_encryption,
        SshPkcs7RecipientInfo recipients,
        SshPkcs7SignerInfo signers)
{
  SshPkcs7 c;
  size_t key_len, digest_len, i;
  unsigned char *key, *digest;
  SshPkcs7SignerInfo signer;
  SshPkcs7RecipientInfo recipient;

  if (content == NULL)
    return NULL;

  c = ssh_pkcs7_allocate();
  if (!c)
    return NULL;

  c->content = content;
  c->type = SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA;
  c->version = 1;

  /* Content encryption (session) key. */
  key_len = ssh_cipher_get_key_length(ssh_csstr(data_encryption));
  c->content_encryption_key_len = key_len;

  if ((key = ssh_malloc(key_len)) == NULL)
    {
      ssh_pkcs7_free(c);
      return NULL;
    }

  for (i = 0; i < key_len; i++) key[i] = ssh_random_get_byte();

  c->encrypted_type = content->type;
  c->signer_infos = ssh_glist_allocate();
  c->recipient_infos = ssh_glist_allocate();
  c->digest_algorithms = ssh_glist_allocate();
  c->content_encryption_algorithm = ssh_strdup(data_encryption);
  c->content_encryption_iv =
    pkcs7_generate_iv(data_encryption,
                      key, key_len,
                      &c->cipher_info.hash, &c->cipher_info.rounds,
                      &c->content_encryption_salt,
                      &c->content_encryption_salt_len,
                      &c->content_encryption_iv_len);

  if (!c->signer_infos || !c->recipient_infos || !c->digest_algorithms ||
      !c->content_encryption_algorithm  || !c->content_encryption_iv)
    {
      ssh_pkcs7_free(c);
      memset(key, 0, key_len);
      ssh_free(key);
      return NULL;
    }

  signer = signers;
  while (signer)
    {
      ssh_glist_add_item(c->signer_infos, signer, SSH_GLIST_HEAD);
      digest = pkcs7_digest_content(c->content,
                                    signer->digest_algorithm, NULL,
                                    &digest_len);
      if (digest)
        {
          i = ssh_private_key_max_signature_output_len(signer->private_key);
          signer->encrypted_digest = ssh_malloc(i);
          if (signer->encrypted_digest != NULL)
            {
              ssh_private_key_sign_digest(signer->private_key,
                                          digest, digest_len,
                                          signer->encrypted_digest,
                                          i,
                                          &signer->encrypted_digest_length);

              signer->encrypted_digest =
                pkcs7_digest_encrypt(c->content_encryption_algorithm,
                                     key, key_len,
                                     c->content_encryption_iv,
                                     c->content_encryption_iv_len,
                                     signer->encrypted_digest,
                                     signer->encrypted_digest_length,
                                     &signer->encrypted_digest_length);
            }
          ssh_free(digest);
        }
      ADDOID(c->digest_algorithms, signer->digest_algorithm);
      signer = signer->next;
    }

  c->data = pkcs7_encrypt_content(c->content,
                                  c->content_encryption_algorithm,
                                  key, key_len,
                                  c->content_encryption_iv,
                                  c->content_encryption_iv_len,
                                  c->content_encryption_salt,
                                  c->content_encryption_salt_len,
                                  &c->data_length);

  if (c->data == NULL)
    {
      ssh_pkcs7_free(c);
      memset(key, 0, key_len);
      ssh_free(key);
      return NULL;
    }

  recipient = recipients;
  while (recipient)
    {
      ssh_glist_add_item(c->recipient_infos, recipient, SSH_GLIST_HEAD);
      (void) ssh_public_key_select_scheme(recipient->public_key,
                                   SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                   SSH_PKF_END);

      i = ssh_public_key_max_encrypt_output_len(recipient->public_key);
      recipient->encrypted_key = ssh_calloc(1, i);
      if (recipient->encrypted_key)
        {
          ssh_public_key_encrypt(recipient->public_key,
                                 key, key_len,
                                 recipient->encrypted_key, i,
                                 &recipient->encrypted_key_length);
        }
      else
        {
          recipient->encrypted_key_length = 0;
        }
      recipient = recipient->next;
    }

  memset(key, 0, key_len);
  ssh_free(key);

  return c;
}
#endif /* SSHDIST_CERT */
