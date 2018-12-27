/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate encode routines, not including specific extensions.
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshCertEncode"

/* This function is called by all of the different encoding routines
   (cert/req/crmf/crl). It is the finishing function that wil call the
   callbacks if we are in asynchronous mode. */
void ssh_x509_cert_finalize_encode(SshX509CertEncodeContext
                                   encode_context)
{

  SshAsn1Status status;
  SshAsn1Tree tree;

  if (encode_context->rv != SSH_X509_OK)
    goto failed;

  /* Construct a tree out of the certificate. */
  if ((tree =
       ssh_asn1_init_tree(encode_context->asn1_context,
                          encode_context->cert_node,
                          encode_context->cert_node)) == NULL)
    goto failed;

  /* Encode the tree. */
  status = ssh_asn1_encode(encode_context->asn1_context, tree);
  if (status != SSH_ASN1_STATUS_OK)
    {
      ssh_asn1_free(encode_context->asn1_context);
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
    }

  /* Get the now, hopefully correctly, encoded X.509 (v1 at the moment :(
     certificate/request. */
  ssh_asn1_get_data(tree,
                    &(encode_context->buf),
                    &(encode_context->buf_len));

  failed:

  /* If asynchronous case, call the callback with data and free the
     context and the data after the callback. */
  if (SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(encode_context))
    {
       (*encode_context->user_encode_cb)(encode_context->rv,
                                         encode_context->buf,
                                         encode_context->buf_len,
                                         encode_context->user_context);

       ssh_free(encode_context->buf);
       ssh_operation_abort(encode_context->operation_handle);
    }
  else
    {
      ssh_operation_unregister(encode_context->operation_handle);
    }

}

typedef struct SshX509CertEncodeCtxRec
{
  unsigned char *signed_data;
  SshX509CertEncodeContext encode_context;
  size_t signature_len;
  const unsigned char *signature;
  SshAsn1Node sig_alg;
  SshAsn1Tree certificate_tree;
} *SshX509CertEncodeCtx;


/* This is called when the asynchronous sign is done. */
static void
ssh_x509_cert_encode_asn1_finalize(SshX509CertEncodeCtx
                                   sign_context)
{
  SshX509CertEncodeContext encode_context = sign_context->encode_context;
  unsigned char *bs_signature;
  size_t bs_signature_len;
  SshAsn1Node tbs_certificate;
  SshAsn1Status status;

  /* We have failed already. Go to the end. */
  if (encode_context->rv != SSH_X509_OK)
    goto failed;

  /* Convert signature to correct format. */
  bs_signature =
    ssh_x509_encode_signature(encode_context->asn1_context,
                              sign_context->signature,
                              sign_context->signature_len,
                              encode_context->issuer_key,
                              &bs_signature_len);

  ssh_free(sign_context->signed_data);

  if (bs_signature == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_SIGNATURE_OPS;
      goto failed;
    }

  /* reset sig_alg as its parent/next pointers have previously been
     changed when the certificate was created. */
  sign_context->sig_alg = ssh_x509_encode_sigalg(encode_context->asn1_context,
                                                 encode_context->issuer_key);

  tbs_certificate = ssh_asn1_get_root(sign_context->certificate_tree);

  status =
    ssh_asn1_create_node(encode_context->asn1_context,
                         &encode_context->cert_node,
                         "(sequence ()"
                         "  (any ())"          /* TBSCertificate */
                         "  (any ())"          /* signature algorithm */
                         "  (bit-string ()))", /* signature */
                         tbs_certificate,
                         sign_context->sig_alg,
                         bs_signature,
                         bs_signature_len);

  ssh_free(bs_signature);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }
  failed:

  ssh_free(sign_context);

  ssh_x509_cert_finalize_encode(encode_context);

}

/* This is called when the sign completes. */
static void ssh_x509_cert_sign_cb(SshCryptoStatus status,
                           const unsigned char *signature_buffer,
                           size_t signature_buffer_len,
                           void *context)
{
  SshX509CertEncodeCtx sign_context= context;

  sign_context->encode_context->crypto_handle = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      sign_context->encode_context->rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
    }
  else
    {
      sign_context->signature = signature_buffer;
      sign_context->signature_len = signature_buffer_len;
    }

  /* Finalize the certificate asn1 blob. */
  ssh_x509_cert_encode_asn1_finalize(sign_context);
}

SshX509AsyncCallStatus
ssh_x509_cert_encode_asn1(void *context)
{
  SshX509CertEncodeContext encode_context = context;
  SshAsn1Node extensions,
    subject_pk_info, issuer_ui, subject_ui,
    validity, issuer_dn_name, subject_dn_name,
    version_node;
  unsigned char *signed_data;
  size_t signed_data_len;
  SshAsn1Status status;
  SshX509Name   ui_name;
  SshMPIntegerStruct version;
  SshX509CertEncodeCtx sign_context = NULL;
  SshOperationHandle crypto_handle;
  SshX509Certificate c = encode_context->cert;

  /* Encode all the extensions. */
  if (ssh_x509_cert_encode_extension(encode_context->asn1_context,
                                     c,
                                     &extensions) != SSH_X509_OK)
    {
      encode_context->rv = SSH_X509_FAILED_EXTENSION_ENCODE;
      goto failed;
    }

  /* Encode the public key. */
  subject_pk_info = ssh_x509_encode_public_key(encode_context->asn1_context,
                                               &c->subject_pkey);
  if (subject_pk_info == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_PUBLIC_KEY_OPS;
      goto failed;
    }

  /* Convert unique identifiers */

  /* Handle the issuer unique identifier. */
  ui_name = ssh_x509_name_find(c->issuer_name,
    SSH_X509_NAME_UNIQUE_ID);
  if (ui_name)
    {
      status =
        ssh_asn1_create_node(encode_context->asn1_context, &issuer_ui,
                             "(bit-string ())",
                             ui_name->data, ui_name->data_len*8);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_UNIQUE_ID_ENCODE;
          goto failed;
        }
    }
  else
    issuer_ui = NULL;

  /* Handle the subject unique identifier. */
  ui_name = ssh_x509_name_find(c->subject_name,
    SSH_X509_NAME_UNIQUE_ID);

  if (ui_name)
    {
      status =
        ssh_asn1_create_node(encode_context->asn1_context, &subject_ui,
                             "(bit-string ())",
                             ui_name->data, ui_name->data_len*8);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_UNIQUE_ID_ENCODE;
          goto failed;
        }
    }
  else
    subject_ui = NULL;

  /* Convert distinguished names.  */
  issuer_dn_name = ssh_x509_encode_dn_name(encode_context->asn1_context,
                                           SSH_X509_NAME_DISTINGUISHED_NAME,
                                           c->issuer_name,
                                           &c->config);
  if (issuer_dn_name == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_DN_NAME_ENCODE;
      goto failed;
    }

  /* Convert the subject DN name. */
  subject_dn_name =
    ssh_x509_encode_dn_name(encode_context->asn1_context,
                            SSH_X509_NAME_DISTINGUISHED_NAME,
                            c->subject_name,
                            &c->config);

  /* Quit if there is no alternative or subject names present. */
  if (subject_dn_name == NULL &&
      !ssh_x509_cert_ext_available(c,
                                   SSH_X509_EXT_SUBJECT_ALT_NAME,
                                   NULL))
    {
      encode_context->rv = SSH_X509_FAILED_DN_NAME_ENCODE;
      goto failed;
    }

  /* Force critical if not already. */
  if (subject_dn_name == NULL)
    ssh_x509_ext_info_set(&c->extensions.ext_available,
                          &c->extensions.ext_critical,
                          SSH_X509_EXT_SUBJECT_ALT_NAME,
                          TRUE);

  if ((sign_context = ssh_calloc(1, sizeof(*sign_context))) == NULL)
    {
      encode_context->rv = SSH_X509_FAILURE;
      goto failed;
    }

  sign_context->encode_context = encode_context;

  /* Signature algorithm handling. */
  sign_context->sig_alg = ssh_x509_encode_sigalg(encode_context->asn1_context,
                                                 encode_context->issuer_key);

  if (sign_context->sig_alg == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_ENCODE;
      goto failed;
    }

  /* Convert times. */
  validity = ssh_x509_encode_validity(encode_context->asn1_context,
    &c->not_before, &c->not_after);
  if (validity == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_VALIDITY_ENCODE;
      goto failed;
    }

  /* Set the version. The highest one needed. */
  if (extensions)
    ssh_mprz_init_set_ui(&version, 2);
  else
    if (issuer_ui || subject_ui)
      ssh_mprz_init_set_ui(&version, 1);
    else
      ssh_mprz_init_set_ui(&version, 0);

  if (ssh_mprz_cmp_ui(&version, 0) == 0)
    version_node = NULL;
  else
    {
      status =
        ssh_asn1_create_node(encode_context->asn1_context, &version_node,
                             "(integer ())",
                             &version);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_VERSION_ENCODE;
          goto failed;
        }
    }

  /* Free version. */
  ssh_mprz_clear(&version);

  /* Following code assumes that "any" is ignored if the pointer given is
     NULL. */
  status =
    ssh_asn1_create_tree(encode_context->asn1_context,
                         &sign_context->certificate_tree,
                         "(sequence ()"
                         "  (any (e 0))"       /* version */
                         "  (integer ())"      /* serial number */
                         "  (any ())"          /* signature algorithm */
                         "  (any ())"          /* issuer */
                         "  (any ())"          /* validity */
                         "  (any ())"          /* subject */
                         "  (any ())"          /* subject public key */
                         "  (any (1))"         /* issuer unique id */
                         "  (any (2))"         /* subject unique id */
                         "  (any (e 3)))",     /* extensions */
                         version_node, &c->serial_number,
                         sign_context->sig_alg, issuer_dn_name,
                         validity, subject_dn_name,
                         subject_pk_info,
                         issuer_ui, subject_ui, extensions);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  /* Encode the TBSCertificate. */
  status =
    ssh_asn1_encode(encode_context->asn1_context,
                    sign_context->certificate_tree);

  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  ssh_asn1_get_data(sign_context->certificate_tree,
                    &signed_data,
                    &signed_data_len);

  /* Use the asynchronous signing function. */
  sign_context->signed_data = signed_data;

  crypto_handle =
    ssh_private_key_sign_async(encode_context->issuer_key,
                               signed_data, signed_data_len,
                               ssh_x509_cert_sign_cb,
                               sign_context);

  /* If we are dealing with truly asynchronous signing, assert that
     this encode is asynchronous. */
  if (crypto_handle != NULL)
    {
      SSH_ASSERT(SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(encode_context));
      encode_context->crypto_handle = crypto_handle;
      return SSH_X509_ASYNC_CALL_PENDING;
    }

    /* The sign has called the callback that freed the sign_context and the
     encode_context. */
  return SSH_X509_ASYNC_CALL_COMPLETED;

  failed:

  ssh_free(sign_context);

  return SSH_X509_ASYNC_CALL_ERROR;
}
#endif /* SSHDIST_CERT */
