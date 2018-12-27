/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate request (PKCS#10) encoding routines.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"
#include "oid.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCertReqEncode"

typedef struct SshX509PKCS10ContextRec
{
  SshX509CertEncodeContext encode_context;
  SshAsn1Tree request_tree;
  SshAsn1Node sig_alg;
  unsigned char *signed_data;
  const unsigned char *signature;
  size_t signature_len;
} *SshX509PKCS10Context;

static void
ssh_x509_pkcs10_encode_asn1_finalize(SshX509PKCS10Context pkcs10_context)
{
  SshAsn1Node request_node;
  unsigned char *bs_signature;
  size_t bs_signature_len;
  SshX509CertEncodeContext encode_context =
    pkcs10_context->encode_context;
  SshAsn1Status status;

  if (encode_context->rv != SSH_X509_OK)
    goto failed;

  /* Convert signature to correct format. */
  bs_signature =
    ssh_x509_encode_signature(encode_context->asn1_context,
                              pkcs10_context->signature,
                              pkcs10_context->signature_len,
                              encode_context->issuer_key,
                              &bs_signature_len);

  ssh_free(pkcs10_context->signed_data);

  if (bs_signature == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_SIGNATURE_OPS;
      goto failed;
    }

  request_node = ssh_asn1_get_root(pkcs10_context->request_tree);

  status =
    ssh_asn1_create_node(encode_context->asn1_context,
                         &encode_context->cert_node,
                         "(sequence ()"
                         "(any ())"      /* CertRequestInfo */
                         "(any ())"      /* signature algorithm */
                         "(bit-string ()))", /* signature */
                         request_node,
                         pkcs10_context->sig_alg,
                         bs_signature,
                         bs_signature_len);

  ssh_free(bs_signature);

  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  failed:

  ssh_free(pkcs10_context);

  ssh_x509_cert_finalize_encode(encode_context);
}


/* This is called when the sign completes. */
static void ssh_x509_pkcs10_sign_cb(SshCryptoStatus status,
                                    const unsigned char *signature_buffer,
                                    size_t signature_buffer_len,
                                    void *context)
{
  SshX509PKCS10Context pkcs10_context = context;

  pkcs10_context->encode_context->crypto_handle = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      pkcs10_context->encode_context->rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
    }
  else
    {
      pkcs10_context->signature = signature_buffer;
      pkcs10_context->signature_len = signature_buffer_len;
    }

  /* Finalize the certificate asn1 blob. */
  ssh_x509_pkcs10_encode_asn1_finalize(pkcs10_context);
}

SshX509Status
ssh_x509_encode_attribute(SshAsn1Context context,
                          SshX509ReqExtensionStyle style,
                          SshX509Attribute attr,
                          SshAsn1Node *attribute)
{
  SshAsn1Node node;
  SshAsn1Status status;

  switch (style)
    {
    case SSH_X509_REQ_EXTENSION_PKCS9_REQ:
      switch (attr->type)
        {
        case SSH_X509_ATTR_UNKNOWN:
          (void)ssh_asn1_decode_node(context, attr->data, attr->len, &node);
          status = ssh_asn1_create_node(context, attribute,
                                       "(sequence ()"
                                       "  (object-identifier ())"
                                       "  (set () (any ())))",
                                       attr->oid, node);

          if (status != SSH_ASN1_STATUS_OK)
            goto error;
          break;
        case SSH_X509_PKCS9_ATTR_UNSTRUCTURED_NAME:
          status = ssh_asn1_create_node(context, attribute,
                                       "(sequence ()"
                                       "  (object-identifier ())"
                                       "  (set () (ia5-string ())))",
                                       attr->oid,
                                       attr->data, attr->len);

          if (status != SSH_ASN1_STATUS_OK)
            goto error;
          break;

        case SSH_X509_PKCS9_ATTR_UNSTRUCTURED_ADDRESS:
        case SSH_X509_PKCS9_ATTR_CHALLENGE_PASSWORD:
          status = ssh_asn1_create_node(context, attribute,
                                       "(sequence ()"
                                       "  (object-identifier ())"
                                       "  (set () (printable-string ())))",
                                       attr->oid,
                                       attr->data, attr->len);

          if (status != SSH_ASN1_STATUS_OK)
            goto error;
          break;
        default:
          break;
        }
      break;

    default:
      return SSH_X509_FAILED_UNKNOWN_STYLE;
    }
  return SSH_X509_OK;

error:
  return SSH_X509_FAILURE;
}

SshX509AsyncCallStatus
ssh_x509_pkcs10_encode_asn1(void *context)
{
  SshX509CertEncodeContext encode_context = context;
  SshAsn1Node subject_pk_info,
    subject_dn_name, list, extensions, attributes,
    attr_list, version_node;
  size_t signed_data_len;
  SshAsn1Status status;
  const SshOidStruct *ext_cert_oid;
  SshMPIntegerStruct version;
  SshX509PKCS10Context pkcs10_context = NULL;
  SshOperationHandle crypto_handle;
  SshX509Certificate cert = encode_context->cert;
  SshX509Attribute attr;

  /* Encode extensions */
  if (ssh_x509_cert_encode_extension(encode_context->asn1_context,
                                     cert,
                                     &list)
      != SSH_X509_OK)
    {
      encode_context->rv = SSH_X509_FAILED_EXTENSION_ENCODE;
      goto failed;
    }

  extensions = NULL;
  attr_list  = NULL;

  /* And put them into appropriate attribute list (extensionReq or
     catExtension) depending on the style. */
  if (list)
    {
      ext_cert_oid =
          ssh_oid_find_by_std_name_of_type("extensionReq", SSH_OID_PKCS9);
      if (ext_cert_oid == NULL)
        {
          encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }

      status =
          ssh_asn1_create_node(encode_context->asn1_context, &extensions,
                               "(sequence ()"
                               " (object-identifier ())"
                               " (set () (any ())))",
                               ext_cert_oid->oid,
                               list);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }
    }

  /* Add extensions to attributes. */
  attr_list = ssh_asn1_add_list(attr_list, extensions);

  /* Then add other attributes from the certificate. */
  for (attr = cert->attributes; attr; attr = attr->next)
    {
      SshAsn1Node attribute;

      if (ssh_x509_encode_attribute(encode_context->asn1_context,
                                    SSH_X509_REQ_EXTENSION_PKCS9_REQ,
                                    attr,
                                    &attribute) == SSH_X509_OK)
        {
          attr_list = ssh_asn1_add_list(attr_list, attribute);
        }
    }

  attr_list = ssh_asn1_sort_list(encode_context->asn1_context, attr_list);
  /* Build the set of the attributes if available. */
  status =
    ssh_asn1_create_node(encode_context->asn1_context, &attributes,
                         "(set (0) (any ()))",
                         attr_list);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  /* Convert public key. */
  subject_pk_info =
    ssh_x509_encode_public_key(encode_context->asn1_context,
                               &cert->subject_pkey);
  if (subject_pk_info == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
      goto failed;
    }

  /* Convert distinguished names. This is little bit odd, maybe not
     useful. */
  subject_dn_name =
    ssh_x509_encode_dn_name(encode_context->asn1_context,
                            SSH_X509_NAME_DISTINGUISHED_NAME,
                            cert->subject_name,
                            &cert->config);
  if (subject_dn_name == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_DN_NAME_ENCODE;
      goto failed;
    }

  /* Wonderfully we cannot say but the PKCS #10 request is of version 1. */
  ssh_mprz_init_set_ui(&version, 0);

  /* This code was written to allow change to a version with version 0
     not explicitly encoded easily. However, it seems that always the
     version is encoded explicitly. It doesn't matter which way or another,
     but it would be nice to have standards which are followed. */
  status =
    ssh_asn1_create_node(encode_context->asn1_context, &version_node,
                         "(integer ())",
                         &version);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  if ((pkcs10_context = ssh_calloc(1, sizeof(*pkcs10_context))) == NULL)
    {
      encode_context->rv = SSH_X509_FAILURE;
      goto failed;
    }
  pkcs10_context->encode_context = encode_context;


  /* Signature algorithm handling. */
  pkcs10_context->sig_alg =
    ssh_x509_encode_sigalg(encode_context->asn1_context,
                           encode_context->issuer_key);

  if (pkcs10_context->sig_alg == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_ENCODE;
      goto failed;
    }


  /* Following code assumes that "any" is ignored if the pointer given is
     NULL. */
  status =
    ssh_asn1_create_tree(encode_context->asn1_context,
                         &pkcs10_context->request_tree,
                         "(sequence ()"
                         "(any ())" /* version */
                         "(any ())" /* subject name */
                         "(any ())" /* public key info */
                         "(any ()))", /* attributes */
                         version_node, subject_dn_name,
                         subject_pk_info, attributes);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  status = ssh_asn1_encode(encode_context->asn1_context,
                           pkcs10_context->request_tree);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  ssh_asn1_get_data(pkcs10_context->request_tree,
                    &pkcs10_context->signed_data, &signed_data_len);

  /* Sign asynchronously with the given issuer key. */
  crypto_handle = ssh_private_key_sign_async(encode_context->issuer_key,
                                             pkcs10_context->signed_data,
                                             signed_data_len,
                                             ssh_x509_pkcs10_sign_cb,
                                             pkcs10_context);

  /* If we are dealing with truly asynchronous signing, assert that
     this encode is asynchronous. */
  if (crypto_handle != NULL)
    {
      SSH_ASSERT(SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(encode_context));
      encode_context->crypto_handle = crypto_handle;
      return SSH_X509_ASYNC_CALL_PENDING;
    }

  /* The sign has called the callback that freed the pkcs10_context and the
     encode_context. */
  return SSH_X509_ASYNC_CALL_COMPLETED;


 failed:

  /* The operation failed. */
  ssh_free(pkcs10_context);

  return SSH_X509_ASYNC_CALL_ERROR;
}
#endif /* SSHDIST_CERT */
