/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of PKCS#7 for cryptographic message syntax encoder
   and decoder common functionality.

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

#include "pkcs6.h"
#include "sshpkcs7.h"
#include "pkcs7-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshPkcs7Common"


void pkcs7_async_abort(void *context)
{
  SshPkcs7AsyncOpContext opcontext = context;
  SshPkcs7AsyncSubOpContext sub, next;

  for (sub = opcontext->subops; sub; sub = next)
    {
      next = sub->next;
      ssh_operation_abort(sub->op);
      ssh_free(sub);
    }
  ssh_free(opcontext);
}

void
pkcs7_select_signature_scheme(SshPkcs7SignerInfo signer,
                              SshPublicKey public_key)
{
  unsigned char s[64];
  if (signer->digest_algorithm)
    {
      ssh_snprintf(s, sizeof(s), "rsa-pkcs1-%s", signer->digest_algorithm);
      (void) ssh_public_key_select_scheme(public_key,
                                          SSH_PKF_SIGN, s, SSH_PKF_END);
    }
}

unsigned char *
pkcs7_get_digested_data(unsigned char *ber, size_t ber_len,
                        size_t *data_len)
{
  SshAsn1Class classp;
  SshAsn1Encoding encoding;
  SshAsn1Tag tagnum;
  SshAsn1LengthEncoding len_encoding;
  size_t tag_len;
  unsigned char *tag, *data = NULL;

  ssh_ber_open_element(ber, ber_len,
                       &classp, &encoding, &tagnum, &len_encoding,
                       &tag_len, &tag, data_len, &data);
  return data;
}

/* An OID list, actually this should be algorithm identifier list.
   Functions to decode, encode and free the result. */

void
ssh_pkcs7_glist_oid_free(SshGListNode node, void *context)
{
  char *oid = node->data;
  ssh_free(oid);
}

/* Certificates. Decode, Encode and Free */
void
ssh_pkcs7_glist_certificate_free(SshGListNode node, void *context)
{
  SshPkcs6Cert cert = node->data;

  ssh_pkcs6_cert_free(cert);
}

/* CRLs. */

void
ssh_pkcs7_glist_crl_free(SshGListNode node, void *context)
{
  SshPkcs6Crl crl = node->data;

  ssh_pkcs6_crl_free(crl);
}



/* Signer infos. */

void
ssh_pkcs7_signer_info_init(SshPkcs7SignerInfo info)
{
  info->next = NULL;
  info->issuer_name = NULL;
  ssh_mprz_init_set_ui(&info->serial_number, 0);
  info->digest_algorithm = NULL;
  info->auth_attributes = NULL;
  info->digest_encryption_algorithm = NULL;
  info->encrypted_digest = NULL;
  info->encrypted_digest_length = 0;
  info->unauth_attributes = NULL;
  info->private_key = NULL;
  info->detached = FALSE;
}

void
ssh_pkcs7_free_signer_info(SshPkcs7SignerInfo info)
{
  if (info)
    {
      ssh_x509_name_free(info->issuer_name);
      ssh_mprz_clear(&info->serial_number);
      ssh_free(info->digest_algorithm);
      ssh_free(info->digest_encryption_algorithm);
      ssh_glist_free_pkcs6_attr(info->auth_attributes);
      ssh_glist_free_pkcs6_attr(info->unauth_attributes);
      ssh_free(info->encrypted_digest);
      ssh_free(info);
    }
}

void
ssh_pkcs7_glist_signer_info_free(SshGListNode node, void *context)
{
  SshPkcs7SignerInfo info = node->data;

  ssh_pkcs7_free_signer_info(info);
}




/* Recipient infos. */
void
ssh_pkcs7_recipient_info_init(SshPkcs7RecipientInfo info)
{
  info->next = NULL;
  info->issuer_name = NULL;
  ssh_mprz_init_set_ui(&info->serial_number, 0);
  info->key_encryption_algorithm = NULL;
  info->public_key = NULL;
  info->encrypted_key = NULL;
  info->encrypted_key_length = 0;
}

void
ssh_pkcs7_free_recipient_info(SshPkcs7RecipientInfo info)
{
  if (info)
    {
      ssh_x509_name_free(info->issuer_name);
      ssh_mprz_clear(&info->serial_number);
      ssh_free(info->key_encryption_algorithm);
      ssh_free(info->encrypted_key);
      if (info->public_key)
        ssh_public_key_free(info->public_key);
      ssh_free(info);
    }
}

void
ssh_pkcs7_glist_recipient_info_free(SshGListNode node, void *context)
{
  SshPkcs7RecipientInfo info = node->data;

  ssh_pkcs7_free_recipient_info(info);
}



SshPkcs7 ssh_pkcs7_allocate(void)
{
  SshPkcs7 pkcs7 = ssh_calloc(1, sizeof(*pkcs7));

  SSH_DEBUG(5, ("Allocate PKCS-7 object."));

  if (pkcs7)
    {
      /* Clean. */
      pkcs7->type                         = SSH_PKCS7_UNKNOWN;
      pkcs7->version                      = 0;
      pkcs7->encrypted_type               = SSH_PKCS7_UNKNOWN;
      pkcs7->content                      = NULL;
      pkcs7->data                         = NULL;
      pkcs7->data_length                  = 0;
      pkcs7->certificates                 = NULL;
      pkcs7->crls                         = NULL;
      pkcs7->digest_algorithms            = NULL;
      pkcs7->signer_infos                 = NULL;
      pkcs7->recipient_infos              = NULL;
      pkcs7->content_encryption_iv        = NULL;
      pkcs7->content_encryption_iv_len    = 0;
      pkcs7->content_digest_algorithm     = NULL;
      pkcs7->content_digest               = NULL;
      pkcs7->content_digest_length        = 0;

      /* Return the allocated and cleared object. */
    }
  return pkcs7;
}

void ssh_pkcs7_free(SshPkcs7 pkcs7)
{
  /* Free the PKCS-7 data structure. */

  SSH_DEBUG(5, ("Free PKCS-7 object."));

  if (pkcs7 == NULL)
    return;

  /* First go through all the possible extensions. */
  SSH_DEBUG(5, ("Content free."));
  if (pkcs7->content)
    ssh_pkcs7_free(pkcs7->content);

  if (pkcs7->data)
    {
      SSH_DEBUG(5, ("Data free."));
      memset(pkcs7->data, 0, pkcs7->data_length);
      ssh_free(pkcs7->data);
    }

  if (pkcs7->certificates)
    {
      SSH_DEBUG(5, ("Certificate free."));
      ssh_glist_free_with_iterator(pkcs7->certificates,
                                   ssh_pkcs7_glist_certificate_free, NULL);
    }
  if (pkcs7->crls)
    {
      SSH_DEBUG(5, ("CRL free."));
      ssh_glist_free_with_iterator(pkcs7->crls,
                                   ssh_pkcs7_glist_crl_free, NULL);
    }

  if (pkcs7->digest_algorithms)
    {
      SSH_DEBUG(5, ("Digest algorithms free."));
      ssh_glist_free_with_iterator(pkcs7->digest_algorithms,
                                   ssh_pkcs7_glist_oid_free, NULL);
    }

  if (pkcs7->signer_infos)
    {
      SSH_DEBUG(5, ("Signer infos free."));
      ssh_glist_free_with_iterator(pkcs7->signer_infos,
                                   ssh_pkcs7_glist_signer_info_free, NULL);
    }

  if (pkcs7->recipient_infos)
    {
      SSH_DEBUG(5, ("Recipient infos free."));
      ssh_glist_free_with_iterator(pkcs7->recipient_infos,
                                   ssh_pkcs7_glist_recipient_info_free, NULL);
    }

  if (pkcs7->content_digest_algorithm)
    ssh_free(pkcs7->content_digest_algorithm);
  if (pkcs7->content_digest)
    {
      SSH_DEBUG(5, ("Content digest free."));
      ssh_free(pkcs7->content_digest);
    }

  if (pkcs7->content_encryption_iv)
    ssh_free(pkcs7->content_encryption_iv);

  if (pkcs7->content_encryption_algorithm)
    ssh_free(pkcs7->content_encryption_algorithm);

  if (pkcs7->content_encryption_salt)
    ssh_free(pkcs7->content_encryption_salt);

  if (pkcs7->cipher_info.hash)
    ssh_free(pkcs7->cipher_info.hash);

  if (pkcs7->ber) ssh_free(pkcs7->ber);
  /* Free the data structure. */
  ssh_free(pkcs7);
}

const char *
ssh_pkcs7_content_type_oids(SshPkcs7ContentType type)
{
  const SshOidStruct *oids;
  const char *name = NULL;

  switch (type)
    {
    case SSH_PKCS7_DATA:
      name = "data";
      break;
    case SSH_PKCS7_SIGNED_DATA:
      name = "signedData";
      break;
    case SSH_PKCS7_ENVELOPED_DATA:
      name = "envelopedData";
      break;
    case SSH_PKCS7_SIGNED_AND_ENVELOPED_DATA:
      name = "signedAndEnvelopedData";
      break;
    case SSH_PKCS7_DIGESTED_DATA:
      name = "digestedData";
      break;
    case SSH_PKCS7_ENCRYPTED_DATA:
      name = "encryptedData";
      break;
    default:
      ssh_fatal("ssh_pkcs7_recursive_encode: unknown type.");
    }

  SSH_DEBUG(5, ("Type %u = %s.", type, name));

  /* Find the OID. */
  oids = ssh_oid_find_by_std_name_of_type(name, SSH_OID_PKCS7);
  if (oids == NULL)
    ssh_fatal("ssh_pkcs7_content_type_oids: "
              "unknown content type to be encoded.");

  return oids->oid;
}

SshPkcs7 ssh_pkcs7_get_content(SshPkcs7 envelope)
{
  if (envelope)
    return envelope->content;
  else
    return NULL;
}

SshPkcs7ContentType ssh_pkcs7_get_content_type(SshPkcs7 envelope)
{
  if (envelope)
    return envelope->type;
  else
    return SSH_PKCS7_UNKNOWN;
}

SshPkcs7ContentType ssh_pkcs7_get_encrypted_type(SshPkcs7 envelope)
{
  if (envelope)
    return envelope->encrypted_type;
  else
    return SSH_PKCS7_UNKNOWN;
}

SshUInt32 ssh_pkcs7_get_syntax_version(SshPkcs7 envelope)
{
  if (envelope)
    return envelope->version;
  else
    return 0;
}

SshUInt32
ssh_pkcs7_get_certificates(SshPkcs7 envelope,
                           unsigned char ***bers, size_t **ber_lens)
{
  SshGListNode node;
  SshUInt32 n = 0;
  SshPkcs6Cert c;

  if (!envelope || !envelope->certificates)
    return 0;

  for (node = envelope->certificates->head; node; node = node->next)
    n++;
  if (n)
    {
      if ((*bers = ssh_calloc(n, sizeof(**bers))) != NULL &&
          (*ber_lens = ssh_calloc(n, sizeof(**ber_lens))) != NULL)
        {
          for (n = 0, node = envelope->certificates->head;
               node;
               node = node->next)
            {
              c = node->data;
              (*bers)[n] = c->ber_buf;
              (*ber_lens)[n] = c->ber_length;
              n++;
            }
        }
      else
        {
          ssh_free(*bers);
          ssh_free(*ber_lens);
          return 0;
        }
    }
  return n;
}

SshUInt32
ssh_pkcs7_get_crls(SshPkcs7 envelope,
                   unsigned char ***bers, size_t **ber_lens)
{
  SshGListNode node;
  SshUInt32 n = 0;
  SshPkcs6Crl c;

  if (!envelope->crls)
    return 0;

  for (node = envelope->crls->head; node; node = node->next)
    n++;
  if (n)
    {
      if ((*bers = ssh_calloc(n, sizeof(**bers))) != NULL &&
          (*ber_lens = ssh_calloc(n, sizeof(**ber_lens))) != NULL)
        {
          for (n = 0, node = envelope->crls->head; node; node = node->next)
            {
              c = node->data;
              (*bers)[n] = c->ber_buf;
              (*ber_lens)[n] = c->ber_length;
              n++;
            }
        }
      else
        {
          ssh_free(*bers);
          ssh_free(*ber_lens);
          return 0;
        }
    }
  return n;
}

Boolean
ssh_pkcs7_content_data(SshPkcs7 envelope,
                       const unsigned char **data, size_t *len)
{
  if (envelope->type == SSH_PKCS7_DATA)
    {
      *data = envelope->data;
      *len = envelope->data_length;
      return TRUE;
    }

  return FALSE;
}


Boolean
ssh_pkcs7_recipient_get_id(SshPkcs7RecipientInfo recipient,
                           char **issuer_name, SshMPInteger serial_number)
{
  ssh_x509_name_pop_ldap_dn(recipient->issuer_name, issuer_name);
  ssh_mprz_set(serial_number, &recipient->serial_number);
  return TRUE;
}

size_t
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



Boolean
ssh_pkcs7_signer_get_id(SshPkcs7SignerInfo signer,
                        char **issuer_name, SshMPInteger serial_number)
{
  ssh_x509_name_pop_ldap_dn(signer->issuer_name, issuer_name);
  ssh_mprz_set(serial_number, &signer->serial_number);
  return TRUE;
}

/****************************************************************************/
const char *
ssh_pkcs7_algorithm_oids(const unsigned char *name)
{
  const SshOidStruct *oid;

  oid = ssh_oid_find_by_std_name(ssh_csstr(name));
  if (oid)
    return oid->oid;
  else
    {
      oid = (const SshOidStruct *) ssh_oid_find_by_alt_name(ssh_csstr(name));
      if (oid)
        return oid->oid;
      else
        {
          oid = ssh_oid_find_by_oid_of_type(name, SSH_OID_PKCS12);
          if (oid)
            return oid->oid;
          else
            return NULL;
        }
    }
  /* SSH_NOTREACHED; */
}

/* pkcs7.c */
#endif /* SSHDIST_CERT */
