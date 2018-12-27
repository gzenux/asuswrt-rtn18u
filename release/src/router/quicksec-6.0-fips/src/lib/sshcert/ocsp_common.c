/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   OCSP (RFC2560) API functions.
*/

#include "sshincludes.h"
#include "sshocsp.h"
#include "ocsp_internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshOcsp"


typedef struct SshOcspVerifyContextRec
{
  SshOperationHandle signature_op;
  SshOperationHandle operation;
  SshPublicKey key;
  const char *sign;
  SshOcspVerifyCB callback;
  void *callback_context;
} *SshOcspVerifyContext, SshOcspVerifyContextStruct;

/* Nonce handling. */
Boolean
ssh_ocsp_extension_create_nonce(SshX509Attribute attr, SshMPInteger value)
{
  SshAsn1Status   status = SSH_ASN1_STATUS_OK;
  SshAsn1Context  context = NULL;
  SshAsn1Node     node = NULL;
  SshAsn1Tree     tree = NULL;
  unsigned char   *ber = NULL;
  size_t          ber_len = 0;

  if ((context = ssh_asn1_init()) == NULL)
    return FALSE;

  attr->type = SSH_X509_ATTR_UNKNOWN;
  attr->next = NULL;
  attr->oid = ssh_strdup(SSH_OCSP_NONCE);

  status = ssh_asn1_create_node(context, &node, "(integer ())", value);
  if (status != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(4, ("Couldn't create nonce node."));
      ssh_asn1_free(context);
      return FALSE;
    }

  if ((tree = ssh_asn1_init_tree(context, node, node)) == NULL ||
      (status = ssh_asn1_encode(context, tree)) != SSH_ASN1_STATUS_OK)
    {
      SSH_DEBUG(4, ("Couldn't create nonce tree."));
      ssh_asn1_free(context);
      return FALSE;
    }

  ssh_asn1_get_data(tree, &ber, &ber_len);
  attr->data = ber;
  attr->len = ber_len;

  ssh_asn1_free(context);
  return TRUE;
}


SshMPInteger ssh_ocsp_extension_get_nonce(const SshX509Attribute extensions)
{
  SshX509Attribute attr;
  SshAsn1Context  asn1_context = NULL;
  SshAsn1Tree     tree = NULL;
  SshAsn1Node     node = NULL;
  SshMPInteger    nonce = NULL;

  if ((asn1_context = ssh_asn1_init()) == NULL)
    return NULL;

  for (attr = extensions; attr; attr = attr->next)
    {
      SSH_DEBUG(9, ("    extension oid: %s", attr->oid));
      if (ssh_asn1_decode(asn1_context, attr->data, attr->len, &tree)
          != SSH_ASN1_STATUS_OK)
        {
          SSH_DEBUG(4, ("Couldn't decode extension"));
          ssh_asn1_free(asn1_context);
          return NULL;
        }

      node = ssh_asn1_get_root(tree);
      if (strcmp(attr->oid, SSH_OCSP_NONCE) == 0)
        {
          unsigned char *nonce_octets;
          size_t num_nonce_octets;
          int which;

          nonce = ssh_mprz_malloc();

          if (ssh_asn1_read_node(asn1_context, node,
                                 "(choice"
                                 " (integer ())"
                                 " (octet-string ()))",
                                 &which,
                                 nonce,
                                 &nonce_octets, &num_nonce_octets)
              != SSH_ASN1_STATUS_OK)
            {
              SSH_DEBUG(5, ("Couldn't read nonce node"));
              ssh_mprz_free(nonce);
              nonce = NULL;
            }
          else
            {
              if (which == 1)
                {
                  /* Convert to integer to retain API compatibility. */
                  ssh_mprz_set_buf(nonce, nonce_octets, num_nonce_octets);
                  ssh_free(nonce_octets);
                }
            }
        }
    }
  ssh_asn1_free(asn1_context);
  asn1_context = NULL;

  return nonce;
}

SshOcspStatus
ocsp_add_cert(SshGList cert_list, const unsigned char *ber, size_t ber_len)
{
  SshGListNode gnode = NULL;
  SshOcspEncodedCert c = NULL;

  if (ber == NULL || ber_len == 0)
    return SSH_OCSP_STATUS_INVALID_OPERAND;

  if ((c = ssh_calloc(1, sizeof(*c))) != NULL)
    {
      if ((c->ber = ssh_memdup(ber, ber_len)) != NULL)
        {
          c->ber_len = ber_len;

          if ((gnode = ssh_glist_allocate_n(cert_list)) != NULL)
            {
              gnode->data = c;
              gnode->data_length = sizeof(*c);
              ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
              return SSH_OCSP_STATUS_OK;
            }
          ssh_free(c->ber);
        }
      ssh_free(c);
    }
  return SSH_OCSP_STATUS_INTERNAL_ERROR;
}

size_t
ocsp_get_certs(SshGList list, SshOcspEncodedCert *certs)
{
  SshGListNode        gnode = NULL;
  size_t                 ncerts = 0;
  int                 i = 0;
  SshOcspEncodedCert  certificate = NULL;

  ncerts = list->num_n;
  *certs = NULL;

  if (ncerts > 0)
    {
      *certs = certificate = ssh_calloc(ncerts, sizeof(*certificate));

      if (certificate)
        {
          for (i = 0, gnode = list->head; gnode; i++, gnode = gnode->next)
            {
              SshOcspEncodedCert c = gnode->data;

              certificate[i].ber = c->ber;
              certificate[i].ber_len = c->ber_len;
            }
        }
      else
        ncerts = 0;
    }
  return ncerts;
}
/* Calculates the hash for the data.
   Notice that the caller should take care of freeing the memory. */
static unsigned char *
ocsp_hash(const char *algorithm,
          const void *buf, size_t len,
          unsigned int *hash_len)
{
  SshHash hash;
  unsigned char *digest;

  if (ssh_hash_allocate(algorithm, &hash) != SSH_CRYPTO_OK)
    return NULL;
  *hash_len = ssh_hash_digest_length(algorithm);

  if ((digest = ssh_malloc((unsigned long) *hash_len)) == NULL)
    {
      ssh_hash_free(hash);
      return NULL;
    }

  ssh_hash_update(hash, buf, len);
  ssh_hash_final(hash, digest);
  ssh_hash_free(hash);

  return digest;
}

SshOcspStatus
ocsp_create_cert_id(SshOcspCertID cert_id,
                    const char *hash_algorithm,
                    const SshX509Certificate issuer_certificate,
                    SshMPIntegerConst subject_serial)
{
  SshOcspStatus   status = SSH_OCSP_STATUS_OK;
  unsigned char   *name_hash = NULL;
  unsigned char   *key_hash = NULL;
  unsigned int    hash_len = 0;
  size_t          kid_len = 0;
  unsigned char   *der = NULL;
  size_t          der_len = 0;

  /* Get the DER encoded name. */

  cert_id->hash_algorithm = NULL;

  if (issuer_certificate->subject_name == NULL)
    {
      status = SSH_OCSP_STATUS_INTERNAL_ERROR;
      goto failed;
    }

  ssh_x509_name_reset(issuer_certificate->subject_name);
  if (!ssh_x509_name_pop_der_dn(issuer_certificate->subject_name,
                                &der, &der_len)
      || der == NULL)
    {
      status = SSH_OCSP_STATUS_INTERNAL_ERROR;
      ssh_x509_name_reset(issuer_certificate->subject_name);
      goto failed;
    }

  ssh_x509_name_reset(issuer_certificate->subject_name);

  if ((cert_id->hash_algorithm = ssh_strdup(hash_algorithm)) == NULL)
    {
      status = SSH_OCSP_STATUS_INTERNAL_ERROR;
      goto failed;
    }

  name_hash = ocsp_hash(hash_algorithm, der, der_len, &hash_len);
  ssh_free(der); der = NULL;

  if (name_hash == NULL)
    {
      status = SSH_OCSP_STATUS_UNKNOWN_HASH_ALGORITHM;
      goto failed;
    }

  /* hash of issuer's public key */
  if ((key_hash =
       ssh_x509_cert_compute_key_identifier(issuer_certificate,
                                            hash_algorithm, &kid_len))
      == NULL)
    {
    failed:
      ssh_free(cert_id->hash_algorithm);
      ssh_free(name_hash);
      ssh_free(der);
      return status;
    }

  ssh_mprz_init_set(&cert_id->serial_number, subject_serial);
  if (ssh_mprz_isnan(&cert_id->serial_number))
    goto failed;

  cert_id->issuer_name_hash = name_hash;
  cert_id->hash_len = hash_len;
  cert_id->issuer_key_hash = key_hash;

  return status;
}


SshOcspStatus
ocsp_decode_cert_id(SshAsn1Context context,
                    SshAsn1Node node,
                    SshOcspCertID cert_id)
{
  unsigned char       *hash_algorithm = NULL;
  SshAsn1Node         hash_params = NULL;
  Boolean             hash_params_found;
  const SshOidStruct *oids;
  /* Used only in decoding, same as cert_id->hash_len */
  size_t              key_hash_len = 0;

  ssh_mprz_init(&cert_id->serial_number);
  if (ssh_asn1_read_node(context, node,
                         "(sequence ()"
                         "  (sequence ()"
                         "    (object-identifier ())" /* hashAlgorithm */
                         "    (optional (any ())))"   /* params (NULL) */
                         "  (octet-string ())"        /* issuerNameHash */
                         "  (octet-string ())"        /* issuerKeyHash */
                         "  (integer ()))",           /* serialNumber */
                         &hash_algorithm,
                         &hash_params_found, &hash_params,
                         &cert_id->issuer_name_hash, &cert_id->hash_len,
                         &cert_id->issuer_key_hash, &key_hash_len,
                         &cert_id->serial_number)
      != SSH_ASN1_STATUS_OK)
    {
      ssh_mprz_clear(&cert_id->serial_number);
      return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
    }

  /* hashAlgorithm: get oid and then name for the algorithm using the
     object-identifier string */
  oids = ssh_oid_find_by_oid_of_type(hash_algorithm, SSH_OID_HASH);
  ssh_free(hash_algorithm);

  if (oids == NULL)
    {
      cert_id->hash_algorithm = NULL;
      return SSH_OCSP_STATUS_UNKNOWN_HASH_ALGORITHM;
    }
  else
    {
      if ((cert_id->hash_algorithm = ssh_strdup(oids->name)) == NULL)
        return SSH_OCSP_STATUS_UNKNOWN_HASH_ALGORITHM;
    }

  if (key_hash_len != cert_id->hash_len)
    {
      SSH_DEBUG(SSH_D_NETFAULT,
                ("OCSP Error: key hash and name hash lengths did not match."));
      return SSH_OCSP_STATUS_UNKNOWN_HASH_ALGORITHM;
    }

  return SSH_OCSP_STATUS_OK;
}

SshOcspStatus
ocsp_encode_cert_id(SshAsn1Context context,
                    SshAsn1Node *node,
                    SshOcspCertID cert_id)
{
  SshAsn1Node         hash_algorithm = NULL;
  const SshOidStruct  *oids;

  /* hashAlgorithm */
  if ((oids =
       ssh_oid_find_by_alt_name_of_type(cert_id->hash_algorithm,
                                        SSH_OID_HASH))
      == NULL)
    {
      if ((oids =
           ssh_oid_find_by_std_name_of_type(cert_id->hash_algorithm,
                                            SSH_OID_HASH))
          == NULL)
        return SSH_OCSP_STATUS_UNKNOWN_HASH_ALGORITHM;
    }

  if (ssh_asn1_create_node(context, &hash_algorithm,
                           "(sequence ()"
                           "  (object-identifier ())"
                           "  (null ()))",
                           oids->oid)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  if (ssh_asn1_create_node(context, node,
                           "(sequence ()"
                           "  (any ())"          /* hashAlgorithm */
                           "  (octet-string ())" /* issuerNameHash */
                           "  (octet-string ())" /* issuerKeyHash */
                           "  (integer ()))",    /* serialNumber */
                           hash_algorithm,
                           cert_id->issuer_name_hash, cert_id->hash_len,
                           cert_id->issuer_key_hash,  cert_id->hash_len,
                           &cert_id->serial_number)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  return SSH_OCSP_STATUS_OK;
}

SshOcspStatus
ocsp_decode_extensions(SshAsn1Context context,
                       SshAsn1Node node,
                       SshX509Attribute *attrs)
{
  SshAsn1Node         list = NULL;
  SshX509Attribute    head = NULL;
  SshX509Attribute    attr = NULL;
  char                *oid = NULL;
  Boolean             critical_found = FALSE;
  Boolean             critical = FALSE;
  unsigned char       *data = NULL;
  size_t              data_len = 0;

  if (ssh_asn1_read_node(context, node, "(sequence (*) (any ()))", &list)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  for (; list; list = ssh_asn1_node_next(list))
    {
      if (ssh_asn1_read_node(context, list,
                             "(sequence ()"
                             "  (object-identifier ())"
                             "  (optional (boolean ()))"
                             "  (octet-string ()))",
                             &oid,
                             &critical_found, &critical,
                             &data, &data_len)
          == SSH_ASN1_STATUS_OK)
        {
          if (head && attr)
            {
              attr->next = ssh_calloc(1, sizeof(*attr));
              attr = attr->next;
            }
          else
            head = attr = ssh_calloc(1, sizeof(*attr));

          if (attr)
            {
              attr->oid = oid;
              attr->data = data;
              attr->len = data_len;
            }
        }
      else
        {
          while (head != NULL)
            {
              SshX509Attribute tmp = head->next;
              ssh_free(head);
              head = tmp;
            }

          return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
        }
    }

  *attrs = head;
  return SSH_OCSP_STATUS_OK;
}

SshOcspStatus
ocsp_encode_extensions(SshAsn1Context context,
                       SshX509Attribute extensions,
                       SshAsn1Node *extensions_node)
{
  SshX509Attribute    attr = NULL;
  SshAsn1Node         ext_value = NULL;
  SshAsn1Node         ext_node = NULL;
  SshAsn1Node         extensions_list = NULL;

  *extensions_node = NULL;

  for (attr = extensions; attr; attr = attr->next)
    {
      /* Add extensions. First check the extension is proper Asn.1
         encoding. */
      if (ssh_asn1_decode_node(context, attr->data, attr->len, &ext_value)
          == SSH_ASN1_STATUS_OK)
        {
          if (ssh_asn1_create_node(context, &ext_node,
                                   "(sequence ()"
                                   "  (object-identifier ())"
                                   "  (octet-string ()))",
                                   attr->oid,
                                   attr->data, attr->len)
              == SSH_ASN1_STATUS_OK)
            extensions_list = ssh_asn1_add_list(extensions_list, ext_node);
        }
    }

  if (extensions_list)
    {
      if (ssh_asn1_create_node(context, extensions_node,
                               "(sequence () (any ()))",
                               extensions_list)
          != SSH_ASN1_STATUS_OK)
        return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;
    }
  return SSH_OCSP_STATUS_OK;
}

SshOcspStatus
ocsp_decode_cert_list(SshAsn1Context context,
                      SshAsn1Node node,
                      SshGList glist)
{
  SshGListNode        gnode = NULL;
  SshOcspEncodedCert  c = NULL;
  SshAsn1Node         list = NULL;

  if (ssh_asn1_read_node(context, node, "(sequence (*) (any ()))", &list)
      != SSH_ASN1_STATUS_OK)
    return SSH_OCSP_STATUS_FAILED_ASN1_ENCODE;

  for (; list; list = ssh_asn1_node_next(list))
    {
      if ((c = ssh_malloc(sizeof(*c))) != NULL)
        {
          c->ber = NULL;
          c->ber_len = 0;

          if (ssh_asn1_node_get_data(list, &c->ber, &c->ber_len)
              != SSH_ASN1_STATUS_OK)
            {
              ssh_free(c);
              return SSH_OCSP_STATUS_FAILED_ASN1_DECODE;
            }

          if ((gnode = ssh_glist_allocate_n(glist)) != NULL)
            {
              gnode->data = c;
              gnode->data_length = sizeof(*c);
              ssh_glist_add_n(gnode, NULL, SSH_GLIST_TAIL);
            }
          else
            {
              ssh_free(c);
              return SSH_OCSP_STATUS_INTERNAL_ERROR;
            }
        }
    }
  return SSH_OCSP_STATUS_OK;
}

SshX509Status
ocsp_encode_cert_list(SshAsn1Context context,
                      SshGList glist,
                      SshAsn1Node *cert_list)
{
  SshAsn1Node node, list;
  SshGListNode gnode;

  /* Check for trivial case where we have no certificates to add. */
  if (glist == NULL || glist->head == NULL)
    {
      *cert_list = NULL;
      return SSH_X509_OK;
    }

  list = NULL;
  for (gnode = glist->head; gnode; gnode = gnode->next)
    {
      SshOcspEncodedCert c = gnode->data;

      /* Open to ASN.1 */
      if (ssh_asn1_decode_node(context, c->ber, c->ber_len, &node)
          != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;

      list = ssh_asn1_add_list(list, node);
    }

  /* Encode the sequence. */
  if (list)
    {
      if (ssh_asn1_create_node(context, cert_list,
                               "(sequence () (any ()))", list)
          != SSH_ASN1_STATUS_OK)
        return SSH_X509_FAILED_ASN1_ENCODE;
    }

  return SSH_X509_OK;
}


static void
ocsp_verify_abort(void *ctx)
{
  SshOcspVerifyContext context = ctx;

  SSH_DEBUG(5, ("ocsp verify abort called."));

  ssh_operation_abort(context->signature_op);
  (void) ssh_public_key_select_scheme(context->key,
                               SSH_PKF_SIGN, context->sign,
                               SSH_PKF_END);
  ssh_free(context);
}

static void
ocsp_verify_done(SshCryptoStatus status,
                 void *ctx)
{
  SshOcspVerifyContext context = ctx;
  SshOcspStatus rv;

  rv = (status == SSH_CRYPTO_OK)
    ? SSH_OCSP_STATUS_OK : SSH_OCSP_STATUS_FAILED_SIGNATURE_CHECK;

  (void) ssh_public_key_select_scheme(context->key,
                               SSH_PKF_SIGN, context->sign,
                               SSH_PKF_END);

  ssh_operation_unregister(context->operation);
  context->operation = NULL;

  (*context->callback)(rv, context->callback_context);

  ssh_free(context);
}

SshOperationHandle
ocsp_verify_signature(const char *signature_algorithm,
                      unsigned char *signature,
                      size_t signature_len,
                      unsigned char *data,
                      size_t data_len,
                      const SshPublicKey public_key,
                      SshOcspVerifyCB callback,
                      void *callback_context)
{
  const char                  *sign;
  const char                  *key_type;
  const SshX509PkAlgorithmDefStruct *algorithm;
  SshOcspVerifyContext        context = NULL;
  SshOperationHandle          op = NULL;
  SshOperationHandle          op_temp = NULL;

  if ((public_key == NULL) ||
      (signature_algorithm == NULL) ||
      (ssh_public_key_get_info(public_key,
                               SSH_PKF_KEY_TYPE, &key_type,
                               SSH_PKF_SIGN, &sign,
                               SSH_PKF_END) != SSH_CRYPTO_OK))
    {
      (*callback)(SSH_OCSP_STATUS_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  if ((context = ssh_calloc(1, sizeof(*context))) == NULL)
    {
      (*callback)(SSH_OCSP_STATUS_INTERNAL_ERROR, callback_context);
      return NULL;
    }

  /* Check that this implementation supports the given algorithm and
     key type pair. */
  algorithm = ssh_x509_match_algorithm(key_type, signature_algorithm, NULL);
  if (algorithm == NULL)
    {
      ssh_free(context);
      (*callback)(SSH_OCSP_STATUS_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(public_key,
                                   SSH_PKF_SIGN, signature_algorithm,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_free(context);
      (*callback)(SSH_OCSP_STATUS_FAILED_PUBLIC_KEY_OPS, callback_context);
      return NULL;
    }

  context->callback = callback;
  context->callback_context = callback_context;
  context->key = public_key;
  context->sign = sign;

  op = ssh_operation_register(ocsp_verify_abort, context);
  context->operation = op;

  op_temp =
    ssh_public_key_verify_async(public_key,
                                signature, signature_len,
                                data, data_len,
                                ocsp_verify_done, context);

  if (op_temp == NULL)
    op = NULL;
  else
    context->signature_op = op_temp;

  return op;
}
#endif /* SSHDIST_CERT */
