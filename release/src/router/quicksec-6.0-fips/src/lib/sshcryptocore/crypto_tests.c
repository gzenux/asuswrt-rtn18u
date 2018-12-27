/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "sshrandom_i.h"
#include "sshpk_i.h"
#include "sshhash_i.h"
#include "crypto_tests.h"

#if defined(HAVE_DL_H) && defined(HAVE_SHL_GET)
#include <dl.h>
#endif /* HAVE_DL_H */

#if defined(HAVE_SYS_LDR_H) && defined(HAVE_LOADQUERY)
#include <sys/ldr.h>
#endif /* HAVE_SYS_LDR_H */

#define SSH_DEBUG_MODULE "SshCryptoTests"

#ifdef SSHDIST_CRYPT_SELF_TESTS

#ifdef SSHDIST_CRYPT_GENPKCS_PUBLIC
#ifdef SSHDIST_CRYPT_GENPKCS_PRIVATE
/* Private/public key encryption/decryption test */
SshCryptoStatus
ssh_crypto_test_pk_encrypt(SshPublicKeyObject public_key,
                           SshPrivateKeyObject priv_key)
{
  int i;
  Boolean differ;
  unsigned char *a, *b, *c;
  size_t a_len, b_len, c_len, len;
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;

  /* Find the maximum encryption input buffer length. */
  a_len = ssh_public_key_object_max_encrypt_input_len(public_key);

  /* The key is not an encryption key, this test does not apply */
  if (a_len == 0)
    return SSH_CRYPTO_OK;

  /* Find the maximum encryption ouptut buffer length */
  b_len = ssh_public_key_object_max_encrypt_output_len(public_key);

  if (a_len == -1)
    a_len = 128;

  /* Allocate buffers for the plain text and ciphertext */
  a = ssh_malloc(a_len);
  b = ssh_malloc(b_len);

  if (!a || !b)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failure"));
      ssh_free(a);
      ssh_free(b);
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Give some value to the plaintext buffer */
  for (i = 0; i < a_len; i++)
    {
      a[i] = i & 0xff;
    }

  /* Encrypt to get the ciphertext b */
  if ((status = ssh_public_key_object_encrypt(public_key, a, a_len, b, b_len,
                                              &len)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Encrypt operation failed: %s (%d)",
                    ssh_crypto_status_message(status), status));
      goto fail;
    }

  /* Verify the plaintext is different to the ciphertext, otherwise
     the test fails (FIPS specification) */
  differ = FALSE;
  for (i = 0; i < len; i++)
    {
      if (b[i] != a[i])
        {
          differ = TRUE;
          break;
        }
    }

  if (differ == FALSE && len == a_len)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Ciphertext is identical to plaintext"));
      goto fail;
    }

  /* Check output length consistency */
  if (len > b_len ||
      len > ssh_private_key_object_max_decrypt_input_len(priv_key))
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Encryption output length is longer than excpected."));
      goto fail;
    }

  /* Allocate a buffer for the decrypted ciphertext */
  c_len = ssh_private_key_object_max_decrypt_output_len(priv_key);

  c = ssh_malloc(c_len);

  if (!c)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failure"));
      ssh_free(a);
      ssh_free(b);
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Decrypt the ciphertext we just encrypted */
  if ((status = ssh_private_key_object_decrypt(priv_key,
                                               b, b_len, c,
                                               c_len, &len)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Decrypt operation failed: %s (%d)",
                             ssh_crypto_status_message(status), status));

      ssh_free(c);
      goto fail;
    }

  /* Check output length consistency */
  if (len > c_len  || len != a_len)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Decryption output length is not what was excepted."));
      ssh_free(c);
      goto fail;
    }

   /* Check the decrypted ciphertext is identical to the original
     plaintext, if not the test fails */
  for (i = 0; i < len; i++)
    {
      if (c[i] != a[i])
        {
          SSH_DEBUG(SSH_D_ERROR, ("Plaintext and decrypted values differ "
                        "(index %d, values %02x and %02x).",
                        i, a[i], c[i]));
          ssh_free(c);
          goto fail;
        }
    }

  /* Free the buffers */
  ssh_free(b);
  ssh_free(a);
  ssh_free(c);
  return SSH_CRYPTO_OK;

  /* Test failed */
 fail:
  ssh_free(a);
  ssh_free(b);

  /* Never return 'status' (it may be SSH_CRYPTO_OK), always return
     an explicit error. Treat SSH_CRYPTO_NO_MEMORY as a special case,
     the library does not need to go into an error state due to this
     error. All other error status are treated as equivalent and can
     cause the library to enter an error state. */
  if (status == SSH_CRYPTO_NO_MEMORY)
    return SSH_CRYPTO_NO_MEMORY;

  return SSH_CRYPTO_OPERATION_FAILED;
}

/* Private/public key signature verification test */
SshCryptoStatus
ssh_crypto_test_pk_signature(SshPublicKeyObject public_key,
                             SshPrivateKeyObject priv_key)
{
  int i;
  unsigned char *a, *b;
  size_t a_len, b_len, len;
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;

  a_len = ssh_private_key_object_max_signature_input_len(priv_key);

  /* The key is not an signature key, this test does not apply. */
  if (a_len == 0)
    return SSH_CRYPTO_OK;

  if (a_len == -1)
    a_len = 128;

  /* Find the maximum signature output buffer length */
  b_len = ssh_private_key_object_max_signature_output_len(priv_key);

  /* Allocate buffers for the input buffer and signature buffer */
  a = ssh_malloc(a_len);
  b = ssh_malloc(b_len);

  if (!a || !b)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Memory allocation failure"));
      ssh_free(a);
      ssh_free(b);
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Give some value to the input buffer */
  for (i = 0; i < a_len; i++)
    {
      a[i] = i & 0xf;
    }

  /* Sign the buffer 'a', the signature is 'b'  */
  if ((status = ssh_private_key_object_sign(priv_key, a, a_len,
                                            b, b_len, &len)) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Sign operation failed: %s (%d)",
                             ssh_crypto_status_message(status), status));
      goto fail;
    }

  /* Check output length consistency */
  if (len > b_len)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Signature is longer than expected"));
      goto fail;
    }

  /* Verify the signature */
  if ((status = ssh_public_key_object_verify_signature(public_key,
                                                       b, len,
                                                       a, a_len))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("Signature verification operation failed: %s (%d)",
                 ssh_crypto_status_message(status), status));
      goto fail;
    }

  ssh_free(a);
  ssh_free(b);

  /* Signature has verified correctly, test passed */
  return SSH_CRYPTO_OK;

 fail:
  ssh_free(a);
  ssh_free(b);

  /* Never return 'status' (it may be SSH_CRYPTO_OK), always return
     an explicit error  */
  if (status == SSH_CRYPTO_NO_MEMORY)
    return SSH_CRYPTO_NO_MEMORY;

  return SSH_CRYPTO_OPERATION_FAILED;
}
#endif /* SSHDIST_CRYPT_GENPKCS_PRIVATE */
#endif /* SSHDIST_CRYPT_GENPKCS_PUBLIC */

#ifdef SSHDIST_CRYPT_GENPKCS_DH
SshCryptoStatus
ssh_crypto_test_pk_group(SshPkGroupObject pk_group)
{
  return  SSH_CRYPTO_OK;
}
#endif /* SSHDIST_CRYPT_GENPKCS_DH */

#ifdef SSHDIST_CRYPT_GENPKCS_PUBLIC
#ifdef SSHDIST_CRYPT_GENPKCS_PRIVATE
/* Key pair consistency check. Runs encrypt and signature tests on the
   key, and returns FALSE if either failed, and TRUE if both
   succeeded. */
SshCryptoStatus
ssh_crypto_test_pk_consistency(SshPublicKeyObject public_key,
                               SshPrivateKeyObject priv_key)
{
  SshCryptoStatus status;

  if ((status = ssh_crypto_test_pk_encrypt(public_key, priv_key))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed encryption test"));
      return status;
    }

  if ((status = ssh_crypto_test_pk_signature(public_key, priv_key))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed signature test"));
      return status;
    }

  return SSH_CRYPTO_OK;
}

/* Private key consistency test. This routine derives a public key
   from the private key, and runs encryption
   (ssh_crypto_test_pk_encrypt) and signature
   (ssh_crypto_test_pk_signature) tests on the private/public key
   pair. If either of the individual tests fail, or no public key can
   be derived, this test returns FALSE. Otherwise it returns TRUE. */
SshCryptoStatus
ssh_crypto_test_pk_private_consistency(SshPrivateKeyObject priv_key)
{
  SshCryptoStatus status;
  SshPublicKeyObject public_key;
  const char *sign, *encrypt;
  const char *temp_sign, *temp_encrypt;

  /* If no encryption or signature scheme is defined, test with a default
     scheme. */
  status = ssh_private_key_get_scheme_name(priv_key,
                                           SSH_PKF_SIGN, &sign);
  if (status != SSH_CRYPTO_OK)
    return status;

  status = ssh_private_key_get_scheme_name(priv_key,
                                           SSH_PKF_ENCRYPT, &encrypt);
  if (status != SSH_CRYPTO_OK)
    return status;

  if (sign == NULL)
    {
      temp_sign = ssh_private_key_find_default_scheme(priv_key,
                                                      SSH_PKF_SIGN);

      status = ssh_private_key_set_scheme(priv_key,
                                          SSH_PKF_SIGN, temp_sign);
      if (status != SSH_CRYPTO_OK)
        return status;
    }

  if (encrypt == NULL)
    {
      temp_encrypt = ssh_private_key_find_default_scheme(priv_key,
                                                         SSH_PKF_ENCRYPT);

      status = ssh_private_key_set_scheme(priv_key,
                                          SSH_PKF_ENCRYPT, temp_encrypt);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  /* Derive the public key. The internal derive function *does not* do
     consistency test */
  status = ssh_private_key_derive_public_key_internal(priv_key, &public_key);

  if (status == SSH_CRYPTO_UNSUPPORTED)
    return SSH_CRYPTO_OK;

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Could not derive public key"));
      return status;
    }

  /* Test key consistency */
  status = ssh_crypto_test_pk_consistency(public_key, priv_key);

  if (status != SSH_CRYPTO_OK)
    {
      ssh_public_key_object_free(public_key);
      return status;
    }

  /* If default schemes have been chosen, reset the scheme to its original
     value. */
  if (encrypt == NULL)
    {
      status = ssh_private_key_set_scheme(priv_key,
                                          SSH_PKF_ENCRYPT, NULL);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_public_key_object_free(public_key);
          return status;
        }
    }

  if (sign == NULL)
    {
      status = ssh_private_key_set_scheme(priv_key,
                                          SSH_PKF_SIGN, sign);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_public_key_object_free(public_key);
          return status;
        }
    }

  ssh_public_key_object_free(public_key);
  return SSH_CRYPTO_OK;
}

#endif /* SSHDIST_CRYPT_GENPKCS_PRIVATE */
#endif /* SSHDIST_CRYPT_GENPKCS_PUBLIC */
#endif /* SSHDIST_CRYPT_SELF_TESTS */
