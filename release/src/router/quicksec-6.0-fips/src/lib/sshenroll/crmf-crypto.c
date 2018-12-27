/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IETF RFC2511 CRMF encrypted data portion.
*/

#include "sshincludes.h"
#include "sshasn1.h"
#include "x509.h"
#include "sshpkcs8.h"
#include "x509internal.h"
#include "sshcrmf.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertCrmf"

struct CrmfWhileDecryptRec
{
  SshX509EncryptedValue result;
  SshX509EncryptedValue value;
  SshCrmfDecryptCB callback;
  void *context;
};

static void crmf_decrypt_abort(Boolean aborted, void *context)
{
  ssh_free(context);
}

static void
crmf_encrypt_done(SshCryptoStatus status,
                  const unsigned char *ciphertext, size_t ciphertext_len,
                  void *context)
{
  struct CrmfWhileDecryptRec *c = context;

  c->result->encrypted_sym_key = ssh_memdup(ciphertext, ciphertext_len);
  c->result->encrypted_sym_key_len = ciphertext_len;

  (*c->callback)(c->result, c->value, c->context);
}

SshOperationHandle
ssh_crmf_encrypt_encrypted_value(SshX509EncryptedValue value,
                                 const SshPublicKey recipient,
                                 SshCrmfDecryptCB callback,
                                 void *context)
{
  struct CrmfWhileDecryptRec *c = NULL;
  const SshX509PkAlgorithmDefStruct *algorithm;
  SshOperationHandle op = NULL;
  unsigned char cipherkey[128], iv[128];
  SshX509EncryptedValue r = NULL;
  size_t blocklen, keylen, i;
  SshCipher cipher;

  algorithm = ssh_x509_public_key_algorithm(recipient);
  if (algorithm)
    {
      if ((c = ssh_malloc(sizeof(*c))) == NULL)
        goto failed;
      if ((r = ssh_crmf_encrypted_value_allocate()) == NULL)
        goto failed;

      /* Copy contents from value (data, cipher, intented_alg, hint) */
      r->intended_alg = ssh_strdup(value->intended_alg);
      r->symmetric_alg = ssh_strdup(value->symmetric_alg);
      r->value_hint = ssh_memdup(value->value_hint, value->value_hint_len);
      r->value_hint_len = value->value_hint_len;
      r->encrypted_value_len = value->encrypted_value_len;
      if (r->symmetric_alg == NULL ||
          (r->encrypted_value =
           ssh_memdup(value->encrypted_value, value->encrypted_value_len))
          == NULL)
        goto failed;

      /* Set up key encryption algorithm */
      if ((r->key_alg = ssh_strdup(algorithm->known_name)) == NULL)
        goto failed;

      blocklen = ssh_cipher_get_block_length(value->symmetric_alg);
      keylen = ssh_cipher_get_key_length(value->symmetric_alg);
      for (i = 0; i < keylen; i++) cipherkey[i] = ssh_random_get_byte();
      if (ssh_cipher_allocate(value->symmetric_alg,
                              cipherkey, keylen, TRUE,
                              &cipher)
          == SSH_CRYPTO_OK)
        {
          r->symmetric_alg_iv_len = blocklen;
          if ((r->symmetric_alg_iv = ssh_malloc(blocklen)) == NULL)
            {
              ssh_cipher_free(cipher);
              goto failed;
            }
          for (i = 0; i < blocklen; i++)
            r->symmetric_alg_iv[i] = ssh_random_get_byte();
          memmove(iv, r->symmetric_alg_iv, blocklen);
          /* Encrypt content. */
          (void) ssh_cipher_set_iv(cipher, iv);
          (void) ssh_cipher_start(cipher);
          (void) ssh_cipher_transform(cipher,
                                     r->encrypted_value,
                                     r->encrypted_value,
                                     r->encrypted_value_len);

          ssh_cipher_free(cipher);

          c->callback = callback;
          c->context = context;
          c->result = r;
          c->value = value;

          op = ssh_public_key_encrypt_async(recipient,
                                            cipherkey, keylen,
                                            crmf_encrypt_done,
                                            c);
          ssh_operation_attach_destructor(op, crmf_decrypt_abort, c);
          return op;
        }
    }
 failed:
  ssh_crmf_encrypted_value_free(r);
  ssh_free(c);
  (*callback)(NULL, value, context);
  return NULL;
}

/* Create encrypted value from given octets.  The value returned will
   have symmetric alg and IV set, as well as the encrypted value with
   padding. However, the value is not encrypted, nor the symmetric key
   used for value encryption decided. Encoding such value for
   transport will thus fail, unless ssh_crmf_encrypt_encrypted_value
   is called. */
SshX509EncryptedValue
ssh_crmf_create_encrypted_data(const char *ciphername,
                               const unsigned char *data, size_t len)
{
  SshX509EncryptedValue value;
  size_t padlen, blocklen, i;

  if ((value = ssh_crmf_encrypted_value_allocate()) != NULL)
    {
      if ((value->symmetric_alg = ssh_strdup(ciphername)) == NULL)
        {
          ssh_crmf_encrypted_value_free(value);
          return NULL;
        }

      /* Calculate pkcs#5 padding length. */
      blocklen = ssh_cipher_get_block_length(ciphername);
      if (blocklen == 0)
        {
          ssh_crmf_encrypted_value_free(value);
          SSH_DEBUG(4, ("block length 0 for cipher '%s'.", ciphername));
          return NULL;
        }
      if (len % blocklen)
        padlen = blocklen - (len % blocklen);
      else
        padlen = blocklen;

      /* Copy value and pad .*/
      if ((value->encrypted_value = ssh_malloc(len + padlen)) == NULL)
        {
          ssh_crmf_encrypted_value_free(value);
          return NULL;
        }

      value->encrypted_value_len = len + padlen;
      memmove(value->encrypted_value, data, len);
      for (i = 0; i < padlen; i++)
        value->encrypted_value[len + i] = padlen;

    }
  return value;
}

SshX509EncryptedValue
ssh_crmf_create_encrypted_private_key(const char *cipher,
                                      const SshPrivateKey key)
{
  unsigned char *data;
  size_t len;
  SshX509EncryptedValue value = NULL;
  const SshX509PkAlgorithmDefStruct *algorithm;

  if (ssh_pkcs8_encode_private_key(key, &data, &len) == SSH_X509_OK)
    {
      value = ssh_crmf_create_encrypted_data(cipher, data, len);
      ssh_free(data);

      if (value)
        {
          algorithm = ssh_x509_private_key_algorithm(key);
          if (algorithm)
            value->intended_alg = ssh_strdup(algorithm->known_name);
        }
    }
  return value;

}

static void crmf_decrypt_done(SshCryptoStatus status,
                              const unsigned char *data,
                              size_t len,
                              void *context)
{
  struct CrmfWhileDecryptRec *c = context;
  SshX509EncryptedValue value = c->value, result;
  unsigned char *plaintext;
  size_t plaintext_len;
  SshCipher cipher;
  SshCryptoStatus ret;

  if (ssh_cipher_allocate(value->symmetric_alg, data, len, FALSE, &cipher)
      == SSH_CRYPTO_OK)
    {
      /* Decrypt content. */
      if ((plaintext = ssh_malloc(value->encrypted_value_len)) != NULL)
        {
          ret = ssh_cipher_set_iv(cipher, value->symmetric_alg_iv);

          if (ret == SSH_CRYPTO_OK)
            {
              ret = ssh_cipher_start(cipher);
            }
          if (ret == SSH_CRYPTO_OK)
            {
              ret = ssh_cipher_transform(cipher,
                                         plaintext,
                                         value->encrypted_value,
                                         value->encrypted_value_len);
            }
          if (ret == SSH_CRYPTO_OK)
            {
              /* Unpad and adjust length. */
              plaintext_len =
                value->encrypted_value_len -
                plaintext[value->encrypted_value_len - 1];

              if ((result = ssh_crmf_encrypted_value_allocate()) != NULL)
                {
                  if (value->intended_alg)
                    result->intended_alg = ssh_strdup(value->intended_alg);
                  result->encrypted_value = plaintext;
                  result->encrypted_value_len = plaintext_len;
                }
              ssh_cipher_free(cipher);

              (*c->callback)(value, result, c->context);
              return;
            }
          ssh_free(plaintext);
        }
      ssh_cipher_free(cipher);
    }
  (*c->callback)(value, NULL, c->context);
}

SshOperationHandle
ssh_crmf_decrypt_encrypted_value(SshX509EncryptedValue value,
                                 SshPrivateKey key,
                                 SshCrmfDecryptCB callback,
                                 void *context)
{
  struct CrmfWhileDecryptRec *c;
  SshOperationHandle op = NULL;

  if ((c = ssh_malloc(sizeof(*c))) != NULL)
    {
      c->callback = callback;
      c->context = context;
      c->value = value;

      op = ssh_private_key_decrypt_async(key,
                                         value->encrypted_sym_key,
                                         value->encrypted_sym_key_len,
                                         crmf_decrypt_done, c);

      ssh_operation_attach_destructor(op, crmf_decrypt_abort, c);
    }
  else
    (*callback)(value, NULL, context);

  return op;
}


/* Template must already have a public key set, or this will fail. */
SshX509Status
ssh_crmf_create_public_key_mac(SshX509Certificate crmf,
                               const unsigned char *key, size_t key_len)
{
  SshPSWBMac param;
  unsigned char *pk_der, *value;
  size_t pk_der_len, i, value_len;
  SshMac mac;

  if (crmf->subject_pkey.public_key == NULL)
    return SSH_X509_FAILED_PUBLIC_KEY_OPS;
  else
    {
      SshAsn1Context asn1context;
      SshAsn1Node node;

      if ((asn1context = ssh_asn1_init()) != NULL)
        {
          if ((node =
               ssh_x509_encode_public_key(asn1context, &crmf->subject_pkey))
              != NULL)
            {
              if (ssh_asn1_encode_node(asn1context, node)
                  != SSH_ASN1_STATUS_OK)
                {
                  ssh_asn1_free(asn1context);
                  return SSH_X509_FAILED_ASN1_ENCODE;
                }
              else
                {
                  ssh_asn1_node_get_data(node, &pk_der, &pk_der_len);
                  ssh_asn1_free(asn1context);
                  /* OK, continue from mac allocation. */
                }
            }
          else
            {
              ssh_asn1_free(asn1context);
              return SSH_X509_FAILED_PUBLIC_KEY_OPS;
            }
        }
      else
        {
          return SSH_X509_FAILURE;
        }
    }

  if ((param = ssh_calloc(1, sizeof(*param))) == NULL)
    {
      ssh_free(pk_der);
      return SSH_X509_FAILURE;
    }

  if ((param->salt = ssh_malloc(param->salt_length = 16)) != NULL)
    for (i = 0; i < 16; i++) param->salt[i] = ssh_random_get_byte();
  param->hash_name = ssh_strdup("sha1");
  param->iteration_count = 1536;
  param->mac_name = ssh_strdup("hmac-sha1");

  if (param->salt == NULL ||
      param->hash_name == NULL || param->mac_name == NULL)
    {
    failure:
      ssh_free(param->salt);
      ssh_free(param->hash_name);
      ssh_free(param->mac_name);
      ssh_free(param);
      ssh_free(pk_der);
      return SSH_X509_FAILURE;
    }

  if ((mac = ssh_pswbmac_allocate_mac(param, key, key_len)) == NULL)
    goto failure;

  value_len = ssh_mac_length(ssh_mac_name(mac));
  if ((value = ssh_malloc(value_len)) == NULL)
    {
      ssh_mac_free(mac);
      goto failure;
    }

  ssh_mac_update(mac, pk_der, pk_der_len);
  ssh_mac_final(mac, value);
  ssh_mac_free(mac);
  ssh_free(pk_der);

  crmf->pop.mac.value = value;
  crmf->pop.mac.value_len = value_len;
  crmf->pop.mac.pswbmac = param;
  return SSH_X509_OK;
}
#endif /* SSHDIST_CERT */
