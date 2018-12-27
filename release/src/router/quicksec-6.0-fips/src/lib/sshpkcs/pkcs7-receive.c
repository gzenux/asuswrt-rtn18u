/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoding
   and decoding.

   This library is low level one, meaning that knowledge of
   cryptography is kept in minimum, though PKCS #7 is very much tied to
   cryptography.  (This library may perform some conversion from SSH
   cryptographic names to ASN.1 OIDs defined in PKCS standards.)

   This library can handle BER or DER encoded PKCS #7 messages,
   however, it produces DER messages. This is because the underlaying
   ASN.1 BER/DER code is biased towards DER.
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

/* Some workers for verifying/decrypting/signing/encrypting. */

static Boolean
pkcs7_digest_chk_attributes(SshPkcs7SignerInfo info,
                            SshPkcs7ContentType type,
                            unsigned char *digest, size_t digest_len)
{
  const SshOidStruct *oid, *md, *ct;
  unsigned char *ctber, *digestber;
  size_t ctber_len, digestber_len;
  SshX509Attribute attr;
  Boolean mdfound = FALSE, ctfound = FALSE;
  SshGListNode g;
  SshAsn1Context context;
  SshAsn1Node node;

  /* Get oids for message digest and content type */
  md = ssh_oid_find_by_std_name_of_type("messageDigest", SSH_OID_PKCS9);
  ct = ssh_oid_find_by_std_name_of_type("contentType", SSH_OID_PKCS9);
  if (md == NULL || ct == NULL)
    return FALSE;

  /* Calculate expected values for digest and type content bers. */
  if ((oid = ssh_oid_find_by_ext_ident_of_type(type, SSH_OID_PKCS7)) == NULL)
    return FALSE;

  if ((context = ssh_asn1_init()) == NULL)
    return FALSE;

  (void) ssh_asn1_create_node(context, &node,
                       "(set () (object-identifier ()))", oid->oid);
  (void) ssh_asn1_encode_node(context, node);
  (void) ssh_asn1_node_get_data(node, &ctber, &ctber_len);
  (void) ssh_asn1_create_node(context, &node,
                       "(set () (octet-string ()))", digest, digest_len);
  (void) ssh_asn1_encode_node(context, node);
  (void) ssh_asn1_node_get_data(node, &digestber, &digestber_len);

  /* If good so far, compare. */
  for (g = info->auth_attributes->head; g; g = g->next)
    {
      attr = g->data;
      if ((strcmp(attr->oid, md->oid) == 0) &&
          (memcmp(attr->data, digestber, digestber_len) == 0))
         mdfound = TRUE;
      if ((strcmp(attr->oid, ct->oid) == 0) &&
          (memcmp(attr->data, ctber, ctber_len) == 0))
        ctfound = TRUE;
    }
  ssh_free(ctber);
  ssh_free(digestber);
  ssh_asn1_free(context);
  return ctfound && mdfound;
}

/* Verifies hash digest for content and signer authenticated
   attributes. */
unsigned char *
pkcs7_verify_content(SshPkcs7 content,
                     const unsigned char *algorithm,
                     SshPkcs7SignerInfo signer,
                     const unsigned char *expected_digest,
                     size_t *digest_len)
{
  SshHash hash;
  unsigned char *digest = NULL, *ber, *data;
  size_t ber_len, data_len;

  if (ssh_hash_allocate(ssh_csstr(algorithm), &hash) == SSH_CRYPTO_OK)
    {
      *digest_len = ssh_hash_digest_length(ssh_hash_name(hash));

      if (expected_digest == NULL)
        {
          if (content->type == SSH_PKCS7_DATA)
            {
              data = content->data;
              data_len = content->data_length;
            }
          else
            data = pkcs7_get_digested_data(content->ber,
                                           content->ber_length,
                                           &data_len);

          ssh_hash_reset(hash);
          ssh_hash_update(hash, data, data_len);
        }
      if (signer && signer->auth_attributes)
        {

          if ((digest = ssh_malloc(*digest_len)) != NULL)
            {
              if (expected_digest)
                memmove(digest, expected_digest, *digest_len);
              else
                ssh_hash_final(hash, digest);

              if (!pkcs7_digest_chk_attributes(signer,
                                               content->type,
                                               digest, *digest_len))
                {
                  ssh_free(digest);
                  digest = NULL;
                  goto failed;
                }
              ssh_free(digest);
            }
          else
            {
              goto failed;
            }

          if (ssh_pkcs6_attr_encode(signer->auth_attributes, &ber, &ber_len)
              == SSH_PKCS6_OK)
            {
              ssh_hash_reset(hash);
              ssh_hash_update(hash, ber, ber_len);
              ssh_free(ber);
            }
          else
            {
              digest = NULL;
              goto failed;
            }
        }


      if ((digest = ssh_malloc(*digest_len)) != NULL)
        ssh_hash_final(hash, digest);
    }
 failed:
  ssh_hash_free(hash);
  return digest;
}



SshPkcs7
pkcs7_decrypt_content(const unsigned char *data_encryption,
                      const unsigned char *key, size_t key_len,
                      const unsigned char *iv, size_t iv_len,
                      unsigned char *data, size_t data_len,
                      SshPkcs7ContentType subtype)
{
  SshCipher cipher;
  SshCryptoStatus status;

  if (ssh_cipher_allocate(ssh_csstr(data_encryption), key, key_len, FALSE,
                          &cipher) == SSH_CRYPTO_OK)
    {
      status = ssh_cipher_set_iv(cipher, iv);
      if (status == SSH_CRYPTO_OK)
        {
          status = ssh_cipher_start(cipher);
        }

      if (status == SSH_CRYPTO_OK)
        {
          status = ssh_cipher_transform(cipher, data, data, data_len);
        }

      if (status == SSH_CRYPTO_OK)
        {
          size_t new_data_len;

          new_data_len = data_len;
          ssh_cipher_free(cipher);
          /* Remove padding */
          new_data_len -= data[data_len - 1];
          if (new_data_len > data_len)
            {
              /* Overflow, return an error. */
              return NULL;
            }
          return ssh_pkcs7_create_data(data, new_data_len);
        }
      else
        {
          ssh_cipher_free(cipher);
          return NULL;
        }
    }
  else
    return NULL;
}

Boolean
ssh_pkcs7_content_decrypt_data(SshPkcs7 envelope,
                               const unsigned char *key, size_t key_len)
{
  unsigned char *tmpkey = NULL;
  size_t tmpkey_len;

  if (envelope->type == SSH_PKCS7_ENCRYPTED_DATA)
    {
      if (envelope->cipher_info.hash &&
          envelope->content_encryption_salt_len > 0)
        {
          tmpkey_len = envelope->content_encryption_key_len;
          if ((tmpkey = ssh_malloc(envelope->content_encryption_key_len))
              != NULL)
            ssh_pkcs12_derive_random(envelope->content_encryption_key_len,
                                     SSH_PKCS12_DIVERSIFY_KEY,
                                     envelope->cipher_info.hash,
                                     envelope->cipher_info.rounds,
                                     key, key_len,
                                     envelope->content_encryption_salt,
                                     envelope->content_encryption_salt_len,
                                     tmpkey);

          envelope->content_encryption_iv_len = 8;
          if ((envelope->content_encryption_iv =
               ssh_malloc(envelope->content_encryption_iv_len)) != NULL)
            ssh_pkcs12_derive_random(envelope->content_encryption_iv_len,
                                     SSH_PKCS12_DIVERSIFY_IV,
                                     envelope->cipher_info.hash,
                                     envelope->cipher_info.rounds,
                                     key, key_len,
                                     envelope->content_encryption_salt,
                                     envelope->content_encryption_salt_len,
                                     envelope->content_encryption_iv);
        }
      else
        {
          tmpkey = ssh_memdup(key, key_len);
          tmpkey_len = key_len;
        }

      if (tmpkey == NULL || envelope->content_encryption_iv == NULL)
        {
          ssh_free(tmpkey);
          ssh_free(envelope->content_encryption_iv);
          envelope->content_encryption_iv = NULL;
          return FALSE;
        }

      envelope->content =
        pkcs7_decrypt_content(envelope->content_encryption_algorithm,
                              tmpkey, tmpkey_len,
                              envelope->content_encryption_iv,
                              envelope->content_encryption_iv_len,
                              envelope->data, envelope->data_length,
                              envelope->encrypted_type);

      memset(tmpkey, 0, tmpkey_len);
      ssh_free(tmpkey);

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
ssh_pkcs7_content_verify_data(SshPkcs7 envelope)
{
  SshHash hash;
  unsigned char *ber, *data;
  size_t ber_len, data_len;

  if (envelope->type == SSH_PKCS7_DIGESTED_DATA)
    {
      if (ssh_hash_allocate(ssh_csstr(envelope->content_digest_algorithm),
                            &hash) == SSH_CRYPTO_OK)
        {
          if (ssh_pkcs7_encode_data(envelope->content, &ber, &ber_len)
              != SSH_PKCS7_OK)
            {
              ssh_hash_free(hash);
              return FALSE;
            }

          if (ssh_hash_compare_start(hash, envelope->content_digest,
                                     envelope->content_digest_length) !=
              SSH_CRYPTO_OK)
            {
              ssh_hash_free(hash);
              ssh_free(ber);
              return FALSE;
            }

          data = pkcs7_get_digested_data(ber, ber_len, &data_len);
          ssh_hash_update(hash, data, data_len);

          ssh_free(ber);
          if (ssh_hash_compare_result(hash) != SSH_CRYPTO_OK)
            {
              ssh_hash_free(hash);
              return FALSE;
            }
          else
            {
              ssh_hash_free(hash);
              return TRUE;
            }
        }
      else
        return FALSE;
    }
  else
    return FALSE;
}


SshUInt32
ssh_pkcs7_get_recipients(SshPkcs7 envelope, SshPkcs7RecipientInfo **recipients)
{
  SshUInt32 nrecs = 0, i = 0;
  SshGListNode node;

  if (envelope->recipient_infos == NULL)
    return 0;

  for (node = envelope->recipient_infos->head; node; node = node->next)
    nrecs++;
  if (nrecs)
    {
      if ((*recipients = ssh_calloc(nrecs, sizeof(**recipients))) != NULL)
        {
          for (node = envelope->recipient_infos->head; node; node = node->next)
            (*recipients)[i++] = node->data;
        }
      else
        nrecs = 0;
    }
  return nrecs;
}

static void
pkcs7_async_decrypt_done(SshCryptoStatus status,
                         const unsigned char *key,
                         size_t key_len,
                         void *context)
{
  SshPkcs7AsyncSubOpContext subcontext = context;
  SshPkcs7AsyncOpContext opcontext = subcontext->parentop;
  SshPkcs7 envelope = opcontext->content;

  if (status == SSH_CRYPTO_OK)
    envelope->content =
      pkcs7_decrypt_content(envelope->content_encryption_algorithm,
                            key, key_len,
                            envelope->content_encryption_iv,
                            envelope->content_encryption_iv_len,
                            envelope->data, envelope->data_length,
                            envelope->encrypted_type);

  ssh_operation_unregister(opcontext->op);
  if (envelope->content)
    {
      envelope->type = envelope->encrypted_type;
      (*opcontext->done_callback)(SSH_PKCS7_OK,
                                  envelope,
                                  opcontext->done_callback_context);
    }
  else
    (*opcontext->done_callback)(SSH_PKCS7_FAILURE,
                                envelope,
                                opcontext->done_callback_context);

  ssh_free(subcontext);
  ssh_free(opcontext);
}

SshOperationHandle
ssh_pkcs7_content_decrypt_async(SshPkcs7 envelope,
                                SshPkcs7RecipientInfo recipient,
                                const SshPrivateKey key,
                                SshPkcs7AsyncCB done_callback,
                                void *done_callback_context)
{
  SshOperationHandle op = NULL, encrop;
  SshPkcs7AsyncSubOpContext subcontext;
  SshPkcs7AsyncOpContext opcontext;

  if (envelope->type == SSH_PKCS7_ENVELOPED_DATA)
    {
      /* Decrypt the recipient session key with her private key,
         then decrypt content data with this session key. */
      if (ssh_private_key_select_scheme(key,
                                        SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                        SSH_PKF_END)
          == SSH_CRYPTO_OK)
        {
          if ((opcontext = ssh_malloc(sizeof(*opcontext))) != NULL)
            {
              if ((subcontext = ssh_calloc(1, sizeof(*subcontext))) == NULL)
                {
                  ssh_free(opcontext);
                  goto failed;
                }

              opcontext->content = envelope;
              opcontext->done_callback = done_callback;
              opcontext->done_callback_context = done_callback_context;
              opcontext->subops = NULL;
              opcontext->numops = 1;
              opcontext->numsuccess = 0;

              op = ssh_operation_register(pkcs7_async_abort, opcontext);
              opcontext->op = op;

              subcontext->parentop = opcontext;
              subcontext->info = NULL;
              subcontext->next = opcontext->subops;
              opcontext->subops = subcontext;

              encrop =
                ssh_private_key_decrypt_async(key,
                                              recipient->encrypted_key,
                                              recipient->encrypted_key_length,
                                              pkcs7_async_decrypt_done,
                                              subcontext);
              if (encrop)
                subcontext->op = encrop;
              else
                op = NULL;

              return op;
            }
        }
    failed:
      /* Failed due to allocation or scheme selection. */
      (*done_callback)(SSH_PKCS7_FAILURE,
                       NULL,
                       done_callback_context);
    }
  else
    (*done_callback)(SSH_PKCS7_CONTENT_TYPE_UNKNOWN,
                     NULL,
                     done_callback_context);
  return op;

}


SshUInt32
ssh_pkcs7_get_signers(SshPkcs7 envelope, SshPkcs7SignerInfo **signers)
{
  SshUInt32 nsigs = 0, i = 0;
  SshGListNode node;

  for (node = envelope->signer_infos->head; node; node = node->next)
    nsigs++;
  if (nsigs)
    {
      if ((*signers = ssh_calloc(nsigs, sizeof(**signers))) != NULL)
        {
          for (node = envelope->signer_infos->head; node; node = node->next)
            {
              if (i != 0)
                (*signers)[i-1]->next = node->data;
              (*signers)[i++] = node->data;
            }
        }
      else
        nsigs = 0;
    }
  return nsigs;
}

unsigned char *
ssh_pkcs7_signer_get_certificate(SshPkcs7 envelope,
                                 SshPkcs7SignerInfo signer,
                                 size_t *cert_len)
{
  SshX509Certificate c = NULL;
  SshPkcs6Cert p6c;
  char *issuer, *signer_issuer;
  SshMPIntegerStruct serial;
  SshGListNode node;

  if (envelope->certificates == NULL)
    return NULL;

  ssh_x509_name_reset(signer->issuer_name);
  if (!ssh_x509_name_pop_ldap_dn(signer->issuer_name, &signer_issuer))
    return NULL;

  for (node = envelope->certificates->head; node; node = node->next)
    {
      c = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);

      p6c = node->data;
      if (ssh_x509_cert_decode(p6c->ber_buf, p6c->ber_length, c)
          == SSH_X509_OK)
        {
          ssh_mprz_init(&serial);
          issuer = NULL;

          if (ssh_x509_cert_get_issuer_name(c, &issuer) &&
              ssh_x509_cert_get_serial_number(c, &serial))
            {
              if (strcmp(issuer, signer_issuer) == 0 &&
                  ssh_mprz_cmp(&serial, &signer->serial_number) == 0)
                {
                  ssh_free(issuer);
                  ssh_free(signer_issuer);
                  ssh_mprz_clear(&serial);
                  ssh_x509_cert_free(c);

                  *cert_len = p6c->ber_length;
                  return ssh_memdup(p6c->ber_buf, p6c->ber_length);
                }
            }
          if (issuer)
            ssh_free(issuer);
          ssh_mprz_clear(&serial);
        }
      ssh_x509_cert_free(c);
    }

  ssh_free(signer_issuer);
  return NULL;

}

#define ADDATTR(node, head, prev)                               \
do {                                                            \
  if ((head)) {                                                 \
    (prev)->next = (node)->data; (prev) = (prev)->next;         \
  } else                                                        \
    (head) = (prev) = (node)->data;                             \
 } while (0)

Boolean
ssh_pkcs7_signer_get_attributes(SshPkcs7SignerInfo signer,
                                const unsigned char **digest_algorithm,
                                const unsigned char **signature_algorithm,
                                SshX509Attribute *auth_attrs,
                                SshX509Attribute *unauth_attrs)
{
  SshGListNode node;
  SshX509Attribute attr_head = NULL, attr = NULL;

  if (digest_algorithm)
    *digest_algorithm = signer->digest_algorithm;
  if (signature_algorithm)
    *signature_algorithm = signer->digest_encryption_algorithm;

  if (auth_attrs)
    {
      if (signer->auth_attributes)
        {
          attr_head = NULL;
          for (node = signer->auth_attributes->head; node; node = node->next)
            ADDATTR(node, attr_head, attr);
          *auth_attrs = attr_head;
        }
      else
        *auth_attrs = NULL;
    }

  if (unauth_attrs)
    {
      if (signer->unauth_attributes)
        {
          attr_head = NULL;
          for (node = signer->unauth_attributes->head; node; node = node->next)
            ADDATTR(node, attr_head, attr);
          *unauth_attrs = attr_head;
        }
      else
        *unauth_attrs = NULL;
    }

  return TRUE;
}

static void
pkcs7_async_verify_done(SshCryptoStatus status,
                        void *context)
{
  SshPkcs7AsyncSubOpContext subcontext = context;
  SshPkcs7AsyncOpContext opcontext = subcontext->parentop;

  ssh_operation_unregister(opcontext->op);

  (*opcontext->done_callback)((status == SSH_CRYPTO_OK) ?
                               SSH_PKCS7_OK : SSH_PKCS7_FAILURE,
                              opcontext->content,
                              opcontext->done_callback_context);

  ssh_free(subcontext);
  ssh_free(opcontext);
}

SshOperationHandle
ssh_pkcs7_content_verify_detached_async(const unsigned char *expected_digest,
                                        size_t expected_digest_len,
                                        SshPkcs7 envelope,
                                        SshPkcs7SignerInfo signer,
                                        const SshPublicKey public_key,
                                        SshPkcs7AsyncCB done_callback,
                                        void *done_callback_context)
{
  unsigned char *digest;
  size_t digest_len;
  SshOperationHandle op = NULL, signop;
  SshPkcs7AsyncSubOpContext subcontext;
  SshPkcs7AsyncOpContext opcontext;

  if (envelope->type == SSH_PKCS7_SIGNED_DATA)
    {
      digest = pkcs7_verify_content(envelope->content,
                                    signer->digest_algorithm, signer,
                                    expected_digest,
                                    &digest_len);


      if (digest &&
          (opcontext = ssh_malloc(sizeof(*opcontext))) != NULL)
        {
          if ((subcontext = ssh_calloc(1, sizeof(*subcontext))) == NULL)
            {
              ssh_free(opcontext);
              goto failed;
            }

          opcontext->content = envelope;
          opcontext->done_callback = done_callback;
          opcontext->done_callback_context = done_callback_context;
          opcontext->subops = NULL;
          opcontext->numops = 1;
          opcontext->numsuccess = 0;

          op = ssh_operation_register(pkcs7_async_abort, opcontext);
          opcontext->op = op;

          subcontext->parentop = opcontext;
          subcontext->info = NULL;
          subcontext->next = opcontext->subops;
          opcontext->subops = subcontext;

          /* Change scheme. */
          pkcs7_select_signature_scheme(signer, public_key);

          signop =
            ssh_public_key_verify_digest_async(public_key,
                                               signer->encrypted_digest,
                                               signer->encrypted_digest_length,
                                               digest, digest_len,
                                               pkcs7_async_verify_done,
                                               subcontext);
          if (signop)
            subcontext->op = signop;
          else
            op = NULL;
        }
      else
        {
        failed:
          (*done_callback)(SSH_PKCS7_FAILURE,
                           NULL,
                           done_callback_context);
        }
      ssh_free(digest);
    }
  else
    (*done_callback)(SSH_PKCS7_CONTENT_TYPE_UNKNOWN,
                     NULL,
                     done_callback_context);
  return op;
}

SshOperationHandle
ssh_pkcs7_content_verify_async(SshPkcs7 envelope,
                               SshPkcs7SignerInfo signer,
                               const SshPublicKey public_key,
                               SshPkcs7AsyncCB done_callback,
                               void *done_callback_context)
{
  return ssh_pkcs7_content_verify_detached_async(NULL, 0,
                                                 envelope,
                                                 signer, public_key,
                                                 done_callback,
                                                 done_callback_context);
}
#endif /* SSHDIST_CERT */
