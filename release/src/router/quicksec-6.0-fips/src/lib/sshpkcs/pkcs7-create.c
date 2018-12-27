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

/* Add messageDigest and contentType authenticated attributes based on
   arguments given for the signer. */
static void
pkcs7_digest_add_attributes(SshPkcs7SignerInfo info,
                            SshPkcs7ContentType type,
                            const unsigned char *digest, size_t digest_len)
{
  const SshOidStruct *oid, *oid0;
  SshX509Attribute d, t, tmp;
  SshAsn1Node node;
  SshAsn1Context context;
  SshGListNode gnode;

  if ((context = ssh_asn1_init()) == NULL)
    return;

  if (info->auth_attributes == NULL)
    if ((info->auth_attributes = ssh_glist_allocate()) == NULL)
      return;

  oid0 = ssh_oid_find_by_std_name_of_type("contentType", SSH_OID_PKCS9);
  if (oid0)
    {
      if ((t = ssh_malloc(sizeof(*t))) != NULL)
        {
          t->type = SSH_X509_ATTR_UNKNOWN;
          t->oid = ssh_strdup(oid0->oid);
          oid = ssh_oid_find_by_ext_ident_of_type(type, SSH_OID_PKCS7);
          if (oid && t->oid &&
              ssh_asn1_create_node(context, &node,
                                   "(set () (object-identifier ()))", oid->oid)
              == SSH_ASN1_STATUS_OK)
            {
              ssh_asn1_encode_node(context, node);
              ssh_asn1_node_get_data(node, &t->data, &t->len);

              for (gnode = info->auth_attributes->head;
                   gnode;
                   gnode = gnode->next)
                {
                  tmp = gnode->data;
                  if (!strcmp(tmp->oid, oid0->oid))
                    {
                      tmp->data = t->data;
                      tmp->len = t->len;
                      ssh_free(t->oid);
                      ssh_free(t);
                      goto out1;
                    }
                }
              ssh_glist_add_item(info->auth_attributes, t, SSH_GLIST_TAIL);
            }
          else
            {
              ssh_free(t->oid);
              ssh_free(t);
            }
        }
    }
 out1:

  oid = ssh_oid_find_by_std_name_of_type("messageDigest", SSH_OID_PKCS9);
  if (oid)
    {

      if ((d = ssh_malloc(sizeof(*d))) != NULL)
        {
          d->type = SSH_X509_ATTR_UNKNOWN;
          d->oid = ssh_strdup(oid->oid);

          if (d->oid &&
              ssh_asn1_create_node(context, &node,
                                   "(set () (octet-string ()))",
                                   digest, digest_len)
              == SSH_ASN1_STATUS_OK)
            {
              ssh_asn1_encode_node(context, node);
              ssh_asn1_node_get_data(node, &d->data, &d->len);

              for (gnode = info->auth_attributes->head;
                   gnode;
                   gnode = gnode->next)
                {
                  tmp = gnode->data;
                  if (!strcmp(tmp->oid, oid->oid))
                    {
                      tmp->data = d->data;
                      tmp->len = d->len;
                      ssh_free(d->oid);
                      ssh_free(d);
                      goto out2;
                    }
                }
              ssh_glist_add_item(info->auth_attributes, d, SSH_GLIST_TAIL);
            }
          else
            ssh_free(d);
        }
    }
 out2:
  ssh_asn1_free(context);
}



unsigned char *
pkcs7_encrypt_content(SshPkcs7 content,
                      const unsigned char *algorithm,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *salt, size_t salt_len,
                      size_t *encrypted_len)
{
  SshCipher cipher;
  unsigned char *ber, *data = NULL, *tmpkey;
  size_t ber_len, pad_len = 0, block_len, i, tmpkey_len;
  const unsigned char *ciphername = algorithm;
  const SshOidStruct *oid;

  if ((oid = ssh_oid_find_by_oid_of_type(algorithm, SSH_OID_PKCS12)))
    {
      const SshOidPkcs5Struct *extra = oid->extra;

      ciphername = ssh_ustr(extra->cipher);
      content->content_encryption_key_len = tmpkey_len = extra->keylen;
      if ((tmpkey = ssh_malloc(tmpkey_len)) != NULL)
        ssh_pkcs12_derive_random(extra->keylen,
                                 SSH_PKCS12_DIVERSIFY_KEY,
                                 extra->hash, 1024,
                                 key, key_len, salt, salt_len,
                                 tmpkey);
      else
        return NULL;
    }
  else
    {
      tmpkey_len = key_len;
      tmpkey = ssh_memdup(key, key_len);
    }

  if (tmpkey == NULL)
    return NULL;

  if (ssh_cipher_allocate(ssh_csstr(ciphername), tmpkey, tmpkey_len, TRUE,
                          &cipher) == SSH_CRYPTO_OK)
    {
      if (ssh_cipher_set_iv(cipher, iv) != SSH_CRYPTO_OK)
        {
              ssh_cipher_free(cipher);
              return NULL;
        }

      block_len = ssh_cipher_get_block_length(ssh_cipher_name(cipher));

      SSH_ASSERT(block_len != 0);

      if (content->type == SSH_PKCS7_DATA)
        {
          ber_len = content->data_length;
          if ((ber = ssh_memdup(content->data, ber_len)) == NULL)
            {
              ssh_cipher_free(cipher);
              return NULL;
            }
        }
      else
        /* Get rid of the identifier octets */
        ssh_pkcs7_encode_data(content, &ber, &ber_len);

      if (ber_len % block_len)
        pad_len = block_len - (ber_len % block_len);
      else
        pad_len = block_len;


      if ((data = ssh_malloc(ber_len + pad_len)) != NULL)
        {
          memmove(data, ber, ber_len);
          for (i = 0; i < pad_len; i++)
            data[i + ber_len] = pad_len;
          (void) ssh_cipher_start(cipher);
          (void) ssh_cipher_transform(cipher, data, data, ber_len + pad_len);
          ssh_free(ber);
          *encrypted_len = ber_len + pad_len;
          ssh_cipher_free(cipher);
        }
      else
        {
          ssh_free(ber);
          ssh_cipher_free(cipher);
        }
    }

  memset(tmpkey, 0, tmpkey_len);
  ssh_free(tmpkey);
  return data;
}


/* Calculate hash digest for content and signer authenticated
   attributes. */
unsigned char *
pkcs7_digest_content(SshPkcs7 content,
                     unsigned char *algorithm,
                     SshPkcs7SignerInfo signer,
                     size_t *digest_len)
{
  SshHash hash;
  unsigned char *digest = NULL, *ber, *data;
  size_t ber_len, data_len;

  if (algorithm &&
      ssh_hash_allocate(ssh_csstr(algorithm), &hash) == SSH_CRYPTO_OK)
    {
      *digest_len = ssh_hash_digest_length(ssh_hash_name(hash));

      if (!signer || (signer && !signer->detached))
        {
          if (ssh_pkcs7_encode_data(content, &ber, &ber_len) == SSH_PKCS7_OK)
            {
              if (ber)
                {
                  data = pkcs7_get_digested_data(ber, ber_len, &data_len);
                  if (data)
                    ssh_hash_update(hash, data, data_len);
                  else
                    {
                      ssh_free(ber);
                      goto failed;
                    }
                  ssh_free(ber);
                }
              else
                ssh_hash_update(hash, NULL, 0);
            }
          else
            goto failed;
        }

      if (signer && signer->auth_attributes)
        {
          /* If attributes are present, the resulting digest is
             actually digest of the attributes added with inner
             content type attribute and the digest of the inner
             content. */
          if (!signer->detached)
            {
              if ((digest = ssh_malloc(*digest_len)) != NULL)
                {
                  ssh_hash_final(hash, digest);
                  pkcs7_digest_add_attributes(signer,
                                              content->type,
                                              digest, *digest_len);
                  ssh_free(digest); digest = NULL;
                }
            }

          if (ssh_pkcs6_attr_encode(signer->auth_attributes, &ber, &ber_len)
              == SSH_PKCS6_OK)
            {
              ssh_hash_reset(hash);
              ssh_hash_update(hash, ber, ber_len);
              ssh_free(ber);
            }
          else
            goto failed;
        }


      if ((digest = ssh_malloc(*digest_len)) != NULL)
        ssh_hash_final(hash, digest);
    failed:
      ssh_hash_free(hash);
    }
  return digest;
}


SshPkcs7SignerInfo
ssh_pkcs7_create_signer(const char *digest_algorithm,
                        const char *signature_algorithm,
                        const SshPrivateKey key,
                        const SshX509Certificate cert,
                        SshX509Attribute authenticated_attrs,
                        SshX509Attribute unauthenticated_attrs,
                        SshPkcs7SignerInfo other_signers)
{
  SshPkcs7SignerInfo info;
  SshX509Attribute a;
  unsigned char sigscheme[32];

  if ((info = ssh_malloc(sizeof(*info))) == NULL)
    return NULL;
  ssh_pkcs7_signer_info_init(info);

  if ((info->digest_algorithm = ssh_strdup(digest_algorithm)) == NULL)
    {
    failure:
      ssh_pkcs7_free_signer_info(info);
      return NULL;
    }
  if ((info->digest_encryption_algorithm = ssh_strdup(signature_algorithm))
      == NULL)
    goto failure;

  info->private_key = key;




  ssh_snprintf(sigscheme, sizeof(sigscheme),
               "%s-pkcs1-%s",
               strcasecmp(signature_algorithm, "rsaencryption") == 0 ?
               "rsa" : "dsa",
               strcasecmp(digest_algorithm, "sha1") == 0 ? "sha1" : "md5");

  (void)ssh_private_key_select_scheme(key,
                                      SSH_PKF_SIGN, sigscheme,
                                      SSH_PKF_END);


  if ((info->issuer_name = ssh_x509_name_copy(cert->issuer_name)) == NULL)
    goto failure;
  ssh_x509_name_reset(info->issuer_name);

  ssh_x509_cert_get_serial_number(cert, &info->serial_number);

  a = authenticated_attrs;
  if (a)
    {
      if ((info->auth_attributes = ssh_glist_allocate()) != NULL)
        {
          while (a)
            {
              ssh_glist_add_item(info->auth_attributes, a, SSH_GLIST_TAIL);
              a = a->next;
            }
        }
      else
        {
          ssh_pkcs7_free_signer_info(info);
          return NULL;
        }
    }

  a = unauthenticated_attrs;
  if (a)
    {
      if ((info->unauth_attributes = ssh_glist_allocate()) != NULL)
        {
          while (a)
            {
              ssh_glist_add_item(info->unauth_attributes, a, SSH_GLIST_TAIL);
              a = a->next;
            }
        }
      else
        {
          ssh_pkcs7_free_signer_info(info);
          return NULL;
        }
    }

  if (other_signers)
    info->next = other_signers;

  return info;
}

SshPkcs7SignerInfo
ssh_pkcs7_create_detached_signer(const char *digest_algorithm,
                                 const unsigned char *digest,
                                 size_t digest_length,
                                 const char *signature_algorithm,
                                 const SshPrivateKey key,
                                 const SshX509Certificate cert,
                                 SshX509Attribute authenticated_attrs,
                                 SshX509Attribute unauthenticated_attrs,
                                 SshPkcs7SignerInfo other_signers)
{
  SshPkcs7SignerInfo signer;

  signer = ssh_pkcs7_create_signer(digest_algorithm,
                                   signature_algorithm,
                                   key, cert,
                                   authenticated_attrs, unauthenticated_attrs,
                                   other_signers);
  if (signer)
    {
      signer->detached = TRUE;
      pkcs7_digest_add_attributes(signer,
                                  SSH_PKCS7_DATA,
                                  digest, digest_length);
    }
  return signer;
}

#define COPYATTR(_f, _t)                                \
do {                                                    \
  if (((_t) = ssh_calloc(1, sizeof(*(_t)))) != NULL)    \
    {                                                   \
      (_t)->type = (_f)->type;                          \
      (_t)->oid = ssh_strdup((_f)->oid);                \
      (_t)->data = ssh_memdup((_f)->data, (_f)->len);   \
      (_t)->len = (_f)->len;                            \
    }                                                   \
} while(0)

SshPkcs7SignerInfo
ssh_pkcs7_copy_signer(SshPkcs7SignerInfo signer,
                      SshPkcs7SignerInfo other_signers)
{
  SshPkcs7SignerInfo info;
  SshX509Attribute a, c;

  if ((info = ssh_malloc(sizeof(*info))) == NULL)
    return NULL;
  ssh_pkcs7_signer_info_init(info);

  if (signer->private_key)
    (void)ssh_private_key_copy(signer->private_key, &info->private_key);
  info->issuer_name = ssh_x509_name_copy(signer->issuer_name);
  ssh_mprz_set(&info->serial_number, &signer->serial_number);

  if ((info->digest_algorithm =
       ssh_strdup(signer->digest_algorithm)) == NULL)
    {
      ssh_pkcs7_free_signer_info(info);
      return NULL;
    }
  if ((info->digest_encryption_algorithm =
       ssh_strdup(signer->digest_encryption_algorithm)) == NULL)
    {
      ssh_pkcs7_free_signer_info(info);
      return NULL;
    }


  if (signer->auth_attributes != NULL)
    {
      if ((info->auth_attributes = ssh_glist_allocate()) != NULL)
        {
          a = signer->auth_attributes->head->data;
          while (a)
            {
              COPYATTR(a, c);
              ssh_glist_add_item(info->auth_attributes, c, SSH_GLIST_TAIL);
              a = a->next;
            }
        }
    }


  if (signer->unauth_attributes != NULL)
    {
      if ((info->unauth_attributes = ssh_glist_allocate()) != NULL)
        {
          a = signer->unauth_attributes->head->data;
          while (a)
            {
              COPYATTR(a, c);
              ssh_glist_add_item(info->unauth_attributes, c, SSH_GLIST_TAIL);
              a = a->next;
            }
        }
    }

  if (other_signers)
    info->next = other_signers;

  info->detached = signer->detached;
  if (signer->encrypted_digest)
    info->encrypted_digest = ssh_memdup(signer->encrypted_digest,
                                        signer->encrypted_digest_length);
  info->encrypted_digest_length = signer->encrypted_digest_length;

  return info;
}



SshPkcs7RecipientInfo
ssh_pkcs7_create_recipient(const char *key_encryption_algorithm,
                           const SshX509Certificate cert,
                           SshPkcs7RecipientInfo other_recipients)
{
  SshPkcs7RecipientInfo info;

  if ((info = ssh_malloc(sizeof(*info))) == NULL)
    return NULL;
  ssh_pkcs7_recipient_info_init(info);

  if ((info->key_encryption_algorithm = ssh_strdup(key_encryption_algorithm))
      == NULL)
    {
    failure:
      ssh_pkcs7_free_recipient_info(info);
      return NULL;
    }

  if ((info->issuer_name = ssh_x509_name_copy(cert->issuer_name)) == NULL)
    goto failure;
  ssh_x509_name_reset(info->issuer_name);

  ssh_x509_cert_get_serial_number(cert, &info->serial_number);
  (void)ssh_x509_cert_get_public_key(cert, &info->public_key);

  if (other_recipients)
    info->next = other_recipients;
  return info;
}



SshPkcs7
ssh_pkcs7_create_data(const unsigned char *data, size_t len)
{
  SshPkcs7 c;

  if ((c = ssh_pkcs7_allocate()) != NULL)
    {
      c->type = SSH_PKCS7_DATA;
      c->encrypted_type = SSH_PKCS7_UNKNOWN;
      c->data_length = len;
      if ((c->data = ssh_memdup(data, len)) == NULL)
        c->data_length = 0;
    }
  return c;
}



unsigned char *
pkcs7_generate_iv(const unsigned char *ciphername,
                  const unsigned char *key, size_t key_len,
                  char **hash, SshUInt32 *rounds,
                  unsigned char **salt, size_t *salt_len,
                  size_t *len)
{
  size_t ivlen, i;
  unsigned char keybuf[128]; /* one kilobit key */
  unsigned char *iv;
  SshCipher cipher;
  const SshOidStruct *oid;

  /* For PKCS#12 generate iv and salt now. */
  if ((oid = ssh_oid_find_by_oid_of_type(ciphername, SSH_OID_PKCS12)))
    {
      const SshOidPkcs5Struct *extra = oid->extra;

      if (extra)
        {
          *rounds = 1024;
          if ((*hash = ssh_strdup(extra->hash)) == NULL)
            return NULL;

          *salt_len = 8;
          if ((*salt = ssh_malloc(*salt_len)) == NULL)
            {
              ssh_free(*hash); *hash = NULL;
              return NULL;
            }

          for (i = 0; i < *salt_len; i++) (*salt)[i] = ssh_random_get_byte();

          if (!ssh_pkcs12_derive_random(8,
                                        SSH_PKCS12_DIVERSIFY_IV,
                                        extra->hash, *rounds,
                                        key, key_len,
                                        *salt, *salt_len,
                                        keybuf))
            {
              ssh_free(*salt);
              return NULL;
            }
          *len = 8;
          return ssh_memdup(keybuf, 8);
        }
      else
        return NULL;
    }

  *hash = NULL;
  *salt = NULL;
  *salt_len = 0;
  *len = 0;

  if (ssh_cipher_allocate(ssh_csstr(ciphername), key, key_len, TRUE, &cipher)
      == SSH_CRYPTO_OK)
    {
      ivlen = ssh_cipher_get_iv_length(ssh_cipher_name(cipher));
      ssh_cipher_free(cipher);

      if ((iv = ssh_malloc(ivlen)) != NULL)
        {
          for (i = 0; i < ivlen; i++) iv[i]= ssh_random_get_byte();
          *len = ivlen;
        }
      return iv;
    }
  return NULL;
}

SshPkcs7
ssh_pkcs7_create_encrypted_data(SshPkcs7 content,
                                const unsigned char *data_encryption_algorithm,
                                const unsigned char *key, size_t key_len)
{
  SshPkcs7 c;
  unsigned char *data, *iv = NULL, *salt = NULL;
  size_t data_len, iv_len, salt_len;
  SshUInt32 rounds = 0;
  char *hash = NULL;

  iv = pkcs7_generate_iv(data_encryption_algorithm,
                         key, key_len,
                         &hash, &rounds, &salt, &salt_len, &iv_len);
  if (iv == NULL)
    {
      ssh_free(hash);
      ssh_free(salt);
      return NULL;
    }

  if ((c = ssh_pkcs7_allocate()) != NULL)
    {
      c->type = SSH_PKCS7_ENCRYPTED_DATA;
      c->encrypted_type = content->type;
      c->version = 0;
      c->content = content;
      c->content_encryption_key_len = key_len;
      c->content_encryption_algorithm = ssh_strdup(data_encryption_algorithm);

      /* PKCS#12 stuff. */
      c->content_encryption_salt = salt;
      c->content_encryption_salt_len = salt_len;
      c->cipher_info.rounds = rounds;
      c->cipher_info.hash = hash;

      c->content_encryption_iv_len = iv_len;
      c->content_encryption_iv = iv;

      data = pkcs7_encrypt_content(content, data_encryption_algorithm,
                                   key, key_len, iv, iv_len, salt, salt_len,
                                   &data_len);
      if (data == NULL)
        {
          ssh_pkcs7_free(c);
          return NULL;
        }

      c->data = data;
      c->data_length = data_len;
    }
  else
    {
      ssh_free(hash);
      ssh_free(salt);
      ssh_free(iv);
    }

  return c;
}


SshPkcs7
ssh_pkcs7_create_digested_data(SshPkcs7 content,
                               const char *digest_algorithm)
{
  SshPkcs7 c;

  if ((c = ssh_pkcs7_allocate()) != NULL)
    {
      c->type = SSH_PKCS7_DIGESTED_DATA;
      c->version = 0;
      c->content = content;
      c->content_digest_algorithm = ssh_strdup(digest_algorithm);
      c->content_digest = pkcs7_digest_content(c->content,
                                               c->content_digest_algorithm,
                                               NULL,
                                               &c->content_digest_length);
    }
  return c;
}

SshPkcs7
pkcs7_create_enveloped_data(SshPkcs7 content,
                            const char *data_encryption,
                            const unsigned char *key,
                            size_t key_len)
{
  SshPkcs7 c;

  if ((c = ssh_pkcs7_allocate()) != NULL)
    {
      c->type = SSH_PKCS7_ENVELOPED_DATA;
      c->encrypted_type = content->type;
      c->version = 0;
      c->content = content;
      if ((c->recipient_infos = ssh_glist_allocate()) == NULL)
        {
          ssh_pkcs7_free(c);
          return NULL;
        }

      c->content_encryption_key_len = key_len;
      c->content_encryption_algorithm = ssh_strdup(data_encryption);
      c->content_encryption_iv =
        pkcs7_generate_iv(c->content_encryption_algorithm,
                          key, key_len,
                          &c->cipher_info.hash, &c->cipher_info.rounds,
                          &c->content_encryption_salt,
                          &c->content_encryption_salt_len,
                          &c->content_encryption_iv_len);

      if (c->content_encryption_iv)
        c->data = pkcs7_encrypt_content(c->content,
                                        c->content_encryption_algorithm,
                                        key, key_len,
                                        c->content_encryption_iv,
                                        c->content_encryption_iv_len,
                                        c->content_encryption_salt,
                                        c->content_encryption_salt_len,
                                        &c->data_length);
      return c;
    }

  return NULL;
}


static void
pkcs7_async_encrypt_op_done(SshPkcs7AsyncOpContext opcontext)
{
  SSH_ASSERT(opcontext != NULL);
  SSH_ASSERT(opcontext->numops == 0);
  ssh_operation_unregister(opcontext->op);
  (*opcontext->done_callback)(opcontext->status,
                              opcontext->content,
                              opcontext->done_callback_context);
  ssh_free(opcontext);
}

/* Mark operation identified by context done, store the result and
   call the parent operation done callback if this was the last
   suboperation. */
static void
pkcs7_async_encrypt_done(SshCryptoStatus status,
                         const unsigned char *encrypted_key,
                         size_t encrypted_key_len,
                         void *context)
{
  SshPkcs7AsyncSubOpContext sub, prev, next, subcontext = context;
  SshPkcs7AsyncOpContext opcontext = subcontext->parentop;

  for (prev = NULL, sub = opcontext->subops; sub; sub = next)
    {
      next = sub->next;
      if (sub == subcontext)
        {
          SshPkcs7RecipientInfo r = sub->info;

          r->encrypted_key_length = 0;
          if (status == SSH_CRYPTO_OK)
            {
              if ((r->encrypted_key =
                   ssh_memdup(encrypted_key, encrypted_key_len)) != NULL)
                {
                  opcontext->numsuccess++;
                  opcontext->status = SSH_PKCS7_OK;
                  r->encrypted_key_length = encrypted_key_len;
                }
            }
          else
            {
              if (opcontext->numsuccess == 0)
                {
                  if (status == SSH_CRYPTO_OPERATION_CANCELLED)
                    opcontext->status = SSH_PKCS7_KEY_OPERATION_CANCELLED;
                  else
                    opcontext->status = SSH_PKCS7_FAILURE;
                }
              r->encrypted_key = NULL;
            }

          opcontext->numops--;
          if (prev)
            prev->next = next;
          else
            opcontext->subops = next;

          ssh_free(subcontext);
          subcontext = NULL;
        }
      else
        prev = sub;
    }

  if (opcontext->numops == 0)
    pkcs7_async_encrypt_op_done(opcontext);
}

SshOperationHandle
ssh_pkcs7_create_enveloped_data_async(SshPkcs7 content,
                                      const char *data_encryption,
                                      SshPkcs7RecipientInfo recipients,
                                      SshPkcs7AsyncCB done_callback,
                                      void *done_callback_context)
{
  SshPkcs7 c;
  unsigned char *key;
  size_t key_len, i;
  SshPkcs7RecipientInfo recipient, next;
  SshOperationHandle op, encrop;
  SshPkcs7AsyncSubOpContext subcontext = NULL;
  SshPkcs7AsyncOpContext opcontext = NULL;

  key_len = ssh_cipher_get_key_length(data_encryption);
  if ((key = ssh_malloc(key_len)) == NULL)
    {
      (*done_callback)(SSH_PKCS7_FAILURE, NULL, done_callback_context);
      return NULL;
    }

  for (i = 0; i < key_len; i++) key[i] = ssh_random_get_byte();

  c = pkcs7_create_enveloped_data(content, data_encryption, key, key_len);
  if (!c)
    {
    failure:
      memset(key, 0, key_len);
      ssh_free(key);
      if (c) ssh_pkcs7_free(c);
      if (opcontext) ssh_free(opcontext);

      (*done_callback)(SSH_PKCS7_FAILURE, NULL, done_callback_context);
      return NULL;
    }

  if ((opcontext = ssh_malloc(sizeof(*opcontext))) == NULL)
    goto failure;

  opcontext->content = c;
  opcontext->done_callback = done_callback;
  opcontext->done_callback_context = done_callback_context;
  opcontext->subops = NULL;
  opcontext->numops = 0;
  opcontext->numsuccess = 0;

  op = ssh_operation_register(pkcs7_async_abort, opcontext);
  opcontext->op = op;
  if (op == NULL)
    goto failure;

  for (recipient = recipients; recipient; recipient = recipient->next)
    opcontext->numops += 1;

  /* Increment numops temporarily by one to ensure that opcontext
     is not freed inside the while loop below. */
  opcontext->numops += 1;

  recipient = recipients;
  while (recipient)
    {
      next = recipient->next;

      ssh_glist_add_item(c->recipient_infos, recipient, SSH_GLIST_HEAD);
      if (ssh_public_key_select_scheme(recipient->public_key,
                                       SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                       SSH_PKF_END)
          == SSH_CRYPTO_OK)
        {
          /* Allocate context for suboperation. Add it to the head of
             main operation context. Store information needed for
             operation completion. If allocations happen to fail,
             failed recipients are dropped. */
          if ((subcontext = ssh_calloc(1, sizeof(*subcontext))) != NULL)
            {
              subcontext->parentop = opcontext;
              subcontext->info = recipient;
              subcontext->next = opcontext->subops;
              opcontext->subops = subcontext;

              encrop =
                ssh_public_key_encrypt_async(recipient->public_key,
                                             key, key_len,
                                             pkcs7_async_encrypt_done,
                                             subcontext);
              if (encrop)
                subcontext->op = encrop;
            }
        }
      else
        opcontext->numops -= 1;

      recipient = next;
    }

  ssh_free(key);

  opcontext->numops -= 1;
  if (opcontext->numops == 0)
    {
      pkcs7_async_encrypt_op_done(opcontext);
      op = NULL;
    }

  return op;
}



SshPkcs7
pkcs7_create_signed_data(SshPkcs7 content)
{
  SshPkcs7 c;

  c = ssh_pkcs7_allocate();
  if (c == NULL)
    return NULL;
  c->type = SSH_PKCS7_SIGNED_DATA;
  c->version = 1;
  if (content)
    c->content = content;
  else
    c->content = ssh_pkcs7_create_data(NULL, 0);

  c->signer_infos = ssh_glist_allocate();
  c->digest_algorithms = ssh_glist_allocate();

  return c;
}

static void
pkcs7_async_sign_op_done(SshPkcs7AsyncOpContext opcontext)
{
  SSH_ASSERT(opcontext != NULL);
  SSH_ASSERT(opcontext->numops == 0);

  ssh_operation_unregister(opcontext->op);
  (*opcontext->done_callback)(opcontext->status,
                              opcontext->content,
                              opcontext->done_callback_context);
  ssh_free(opcontext);
}

/* Mark operation identified by context done, store the result and
   call the parent operation done callback if this was the last
   suboperation. */
static void
pkcs7_async_sign_done(SshCryptoStatus status,
                      const unsigned char *signature,
                      size_t signature_len,
                      void *context)
{
  SshPkcs7AsyncSubOpContext sub, prev, next, subcontext = context;
  SshPkcs7AsyncOpContext opcontext = subcontext->parentop;

  for (prev = NULL, sub = opcontext->subops; sub; sub = next)
    {
      next = sub->next;
      if (sub == subcontext)
        {
          SshPkcs7SignerInfo s = sub->info;

          s->encrypted_digest_length = 0;
          if (status == SSH_CRYPTO_OK)
            {
              if ((s->encrypted_digest =
                   ssh_memdup(signature, signature_len)) != NULL)
                {
                  opcontext->numsuccess++;
                  opcontext->status = SSH_PKCS7_OK;
                  s->encrypted_digest_length = signature_len;
                }
            }
          else
            {
              if (opcontext->numsuccess == 0)
                {
                  if (status == SSH_CRYPTO_OPERATION_CANCELLED)
                    opcontext->status = SSH_PKCS7_KEY_OPERATION_CANCELLED;
                  else
                    opcontext->status = SSH_PKCS7_FAILURE;
                }
              s->encrypted_digest = NULL;
            }

          opcontext->numops--;
          if (prev)
            prev->next = next;
          else
            opcontext->subops = next;

          ssh_free(subcontext);
          subcontext = NULL;
        }
      else
        prev = sub;
    }

  if (opcontext->numops == 0)
    pkcs7_async_sign_op_done(opcontext);
}

SshOperationHandle
ssh_pkcs7_create_signed_data_async(SshPkcs7 content,
                                   SshPkcs7SignerInfo signers,
                                   SshPkcs7AsyncCB done_callback,
                                   void *done_callback_context)
{
  SshPkcs7SignerInfo signer, next;
  unsigned char *digest;
  size_t digest_len;
  SshPkcs7 c;
  SshOperationHandle op, signop;
  SshPkcs7AsyncSubOpContext subcontext;
  SshPkcs7AsyncOpContext opcontext;

  c = pkcs7_create_signed_data(content);

  opcontext = ssh_malloc(sizeof(*opcontext));
  if (!opcontext || !c)
    {
      if (opcontext) ssh_free(opcontext);
      if (c) ssh_pkcs7_free(c);
      (*done_callback)(SSH_PKCS7_FAILURE, NULL, done_callback_context);
      return NULL;
    }
  opcontext->content = c;
  opcontext->done_callback = done_callback;
  opcontext->done_callback_context = done_callback_context;
  opcontext->numops = 0;
  opcontext->subops = NULL;
  opcontext->numsuccess = 0;

  op = ssh_operation_register(pkcs7_async_abort, opcontext);
  opcontext->op = op;
  if (op == NULL)
    {
      ssh_pkcs7_free(c);
      ssh_free(opcontext);
      (*done_callback)(SSH_PKCS7_FAILURE, NULL, done_callback_context);
      return NULL;
    }

  for (signer = signers; signer; signer = signer->next)
    opcontext->numops += 1;

  /* Increment numops temporarily by one to ensure that opcontext
     is not freed inside the while loop below. */
  opcontext->numops += 1;

  signer = signers;
  while (signer)
    {
      next = signer->next;
      /* The implementation is suboptimal. Digest of the message is
         calculated multiple times even if the signers would use the
         same content digest algorithm. */
      ssh_glist_add_item(c->signer_infos, signer, SSH_GLIST_HEAD);
      digest = pkcs7_digest_content(c->content,
                                    signer->digest_algorithm, signer,
                                    &digest_len);
      if (digest)
        {
          ADDOID(c->digest_algorithms, signer->digest_algorithm);

           /* Allocate context for suboperation. Add it to the head of
              main operation context. Store information needed for
              operation completion. */
          subcontext = ssh_calloc(1, sizeof(*subcontext));
          if (subcontext)
            {
              subcontext->parentop = opcontext;
              subcontext->info = signer;
              subcontext->next = opcontext->subops;
              opcontext->subops = subcontext;

              signop =
                ssh_private_key_sign_digest_async(signer->private_key,
                                                  digest, digest_len,
                                                  pkcs7_async_sign_done,
                                                  subcontext);
              if (signop)
                subcontext->op = signop;
            }
          ssh_free(digest);
        }
      else
        opcontext->numops -= 1;

      signer = next;
    }

  opcontext->numops -= 1;
  if (opcontext->numops == 0)
    {
      pkcs7_async_sign_op_done(opcontext);
      op = NULL;
    }

  return op;
}


SshPkcs7Status
ssh_pkcs7_add_certificate(SshPkcs7 envelope,
                          const unsigned char *ber, size_t ber_len)
{
  SshPkcs6Cert pkcs6;

  if (!envelope ||
      ber_len == 0 || ber == NULL)
    return SSH_PKCS7_FAILURE;

  switch (envelope->type)
    {
    case SSH_PKCS7_SIGNED_DATA:
    case SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA:
      if (!envelope->certificates)
        envelope->certificates = ssh_glist_allocate();

      if (envelope->certificates &&
          (pkcs6 = ssh_malloc(sizeof(*pkcs6))) != NULL)
        {
          ssh_pkcs6_cert_init(pkcs6);
          pkcs6->ber_buf = ssh_memdup(ber, ber_len);
          pkcs6->ber_length = ber_len;
          ssh_glist_add_item(envelope->certificates, pkcs6, SSH_GLIST_TAIL);
          return SSH_PKCS7_OK;
        }
      /* FALLTHRU */
    default:
      return SSH_PKCS7_FAILURE;
    }
}

SshPkcs7Status
ssh_pkcs7_add_crl(SshPkcs7 envelope,
                  const unsigned char *ber, size_t ber_len)
{
  SshPkcs6Crl pkcs6;

  if (!envelope ||
      ber_len == 0 || ber == NULL)
    return SSH_PKCS7_FAILURE;

  switch (envelope->type)
    {
    case SSH_PKCS7_SIGNED_DATA:
    case SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA:
      if (!envelope->crls)
        envelope->crls = ssh_glist_allocate();

      if (envelope->crls && (pkcs6 = ssh_malloc(sizeof(*pkcs6))) != NULL)
        {
          ssh_pkcs6_crl_init(pkcs6);
          pkcs6->ber_buf = ssh_memdup(ber, ber_len);
          pkcs6->ber_length = ber_len;
          ssh_glist_add_item(envelope->crls, pkcs6, SSH_GLIST_TAIL);
          return SSH_PKCS7_OK;
        }
      /* FALLTHRU */
    default:
      return SSH_PKCS7_FAILURE;
    }
}

/* pkcs7.c */
#endif /* SSHDIST_CERT */
