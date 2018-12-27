/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoding
   and decoding, synchronous verification API.
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
#define SSH_DEBUG_MODULE "SshPkcs7Decode"

static unsigned char *
pkcs7_digest_decrypt(unsigned char *algorithm,
                     unsigned char *key, size_t key_len,
                     unsigned char *iv, size_t iv_len,
                     unsigned char *digest, size_t digest_len,
                     size_t *digest_len_out)
{
  SshCipher cipher;
  SshCryptoStatus status;

  if (ssh_cipher_allocate(ssh_csstr(algorithm), key, key_len, FALSE, &cipher)
      == SSH_CRYPTO_OK)
    {
      status = ssh_cipher_set_iv(cipher, iv);
      if (status == SSH_CRYPTO_OK)
        {
          status = ssh_cipher_start(cipher);
        }

      if (status == SSH_CRYPTO_OK)
        {
          status = ssh_cipher_transform(cipher, digest, digest, digest_len);
        }

      if (status == SSH_CRYPTO_OK)
        {
          *digest_len_out = digest_len;
          ssh_cipher_free(cipher);
        }
      else
        {
          *digest_len_out = 0;
          ssh_cipher_free(cipher);
        }
    }
  return digest;
}

Boolean
ssh_pkcs7_content_decrypt(SshPkcs7 envelope,
                          SshPkcs7RecipientInfo recipient,
                          const SshPrivateKey private_key)
{
  unsigned char *key;
  size_t key_len, i;

  if (envelope->type == SSH_PKCS7_ENVELOPED_DATA)
    {
      /* Decrypt the recipient session key with her private key,
         then decrypt content data with this session key. */

      if (ssh_private_key_select_scheme(private_key,
                                        SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                        SSH_PKF_END)
          == SSH_CRYPTO_OK)
        {
          i = ssh_private_key_max_decrypt_output_len(private_key);
          if ((key = ssh_malloc(i)) != NULL)
            {
              if (ssh_private_key_decrypt(private_key,
                                          recipient->encrypted_key,
                                          recipient->encrypted_key_length,
                                          key, i,
                                          &key_len)
                  == SSH_CRYPTO_OK)
                {
                  envelope->content =
                    pkcs7_decrypt_content(envelope->
                                          content_encryption_algorithm,
                                          key, key_len,
                                          envelope->content_encryption_iv,
                                          envelope->content_encryption_iv_len,
                                          envelope->data,
                                          envelope->data_length,
                                          envelope->encrypted_type);
                }
              memset(key, 0, key_len);
              ssh_free(key);
            }
        }
      if (envelope->content)
        {
          envelope->type = envelope->encrypted_type;
          return TRUE;
        }
      else
        return FALSE;
    }
  else
    return FALSE;
}

Boolean
ssh_pkcs7_content_verify_detached(const unsigned char *expected_digest,
                                  size_t expected_digest_len,
                                  SshPkcs7 envelope,
                                  SshPkcs7SignerInfo signer,
                                  const SshPublicKey public_key)
{
  unsigned char *digest;
  size_t digest_len;

  if (envelope->type == SSH_PKCS7_SIGNED_DATA)
    {
      digest = pkcs7_verify_content(envelope->content,
                                    signer->digest_algorithm, signer,
                                    expected_digest,
                                    &digest_len);

      /* Change scheme. */
      pkcs7_select_signature_scheme(signer, public_key);
      if (digest &&
          (ssh_public_key_verify_signature_with_digest(
                                      public_key,
                                      signer->encrypted_digest,
                                      signer->encrypted_digest_length,
                                      digest, digest_len)
           == SSH_CRYPTO_OK))
        {
          ssh_free(digest);
          return TRUE;
        }
      else
        {
          ssh_free(digest);
          return FALSE;
        }
    }
  else
    return FALSE;
}

Boolean
ssh_pkcs7_content_verify(SshPkcs7 envelope,
                         SshPkcs7SignerInfo signer,
                         const SshPublicKey public_key)
{
  return ssh_pkcs7_content_verify_detached(NULL, 0,
                                           envelope, signer, public_key);
}

Boolean
ssh_pkcs7_content_verify_and_decrypt(SshPkcs7 envelope,
                                     SshPkcs7SignerInfo signer,
                                     const SshPublicKey public_key,
                                     SshPkcs7RecipientInfo recipient,
                                     const SshPrivateKey private_key)
{
  unsigned char *key, *digest;
  size_t i, key_len, digest_len;

  if (envelope->type == SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA)
    {
      /* Get the session (data and digest encryption) key. */
      if (ssh_private_key_select_scheme(private_key,
                                        SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                        SSH_PKF_END)
          == SSH_CRYPTO_OK)
        {
          i = ssh_private_key_max_decrypt_output_len(private_key);
          if ((key = ssh_malloc(i)) != NULL)
            {
              if (ssh_private_key_decrypt(private_key,
                                          recipient->encrypted_key,
                                          recipient->encrypted_key_length,
                                          key, i, &key_len)
                  != SSH_CRYPTO_OK)
                {
                  ssh_free(key);
                  return FALSE;
                }

              /* Decrypt content and digest for this particular signer */
              envelope->content =
                pkcs7_decrypt_content(envelope->content_encryption_algorithm,
                                      key, key_len,
                                      envelope->content_encryption_iv,
                                      envelope->content_encryption_iv_len,
                                      envelope->data, envelope->data_length,
                                      envelope->encrypted_type);

              signer->encrypted_digest =
                pkcs7_digest_decrypt(envelope->content_encryption_algorithm,
                                     key, key_len,
                                     envelope->content_encryption_iv,
                                     envelope->content_encryption_iv_len,
                                     signer->encrypted_digest,
                                     signer->encrypted_digest_length,
                                     &signer->encrypted_digest_length);

              memset(key, 0, key_len);
              ssh_free(key);

              /* Verify digest */
              digest = pkcs7_verify_content(envelope->content,
                                            signer->digest_algorithm, signer,
                                            NULL,
                                            &digest_len);

              /* Change scheme. */
              pkcs7_select_signature_scheme(signer, public_key);
              if (digest
                  && (ssh_public_key_verify_signature_with_digest(
                                public_key,
                                signer->encrypted_digest,
                                signer->encrypted_digest_length,
                                digest, digest_len) == SSH_CRYPTO_OK))
                return TRUE;
              else
                return FALSE;
            }
        }
    }
  /* If successful we'd have returned earlier */
  return FALSE;
}
#endif /* SSHDIST_CERT */
