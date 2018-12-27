/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate revocation list encode routines (not including extensions).
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

#define SSH_DEBUG_MODULE "SshX509CrlEncode"

typedef struct SshX509CrlContextRec
{
  SshX509CertEncodeContext encode_context;
  SshAsn1Tree crl_tree;
  unsigned char *signed_data;
  const unsigned char *signature;
  size_t signature_len;
  SshAsn1Node sig_alg;
} *SshX509CrlContext;

static void
ssh_x509_crl_encode_asn1_finalize(SshX509CrlContext crl_context)
{
  SshAsn1Status status;
  unsigned char *bs_signature;
  size_t bs_signature_len;
  SshX509CertEncodeContext encode_context = crl_context->encode_context;
  SshAsn1Node tbs_crl;

  if (encode_context->rv != SSH_X509_OK)
    goto failed;

  /* Convert signature to correct format. */
  bs_signature =
    ssh_x509_encode_signature(encode_context->asn1_context,
                              crl_context->signature,
                              crl_context->signature_len,
                              encode_context->issuer_key,
                              &bs_signature_len);

  ssh_free(crl_context->signed_data);

  if (bs_signature == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_SIGNATURE_OPS;
      goto failed;
    }

  tbs_crl = ssh_asn1_get_root(crl_context->crl_tree);

  status =
    ssh_asn1_create_node(encode_context->asn1_context,
                         &encode_context->cert_node,
                         "(sequence ()"
                         "  (any ())"      /* TBS CRL */
                         "  (any ())"      /* signature algorithm */
                         "  (bit-string ()))", /* signature */
                         tbs_crl,
                         crl_context->sig_alg, bs_signature, bs_signature_len);
  ssh_free(bs_signature);

  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  failed:
    ssh_free(crl_context);

    ssh_x509_cert_finalize_encode(encode_context);
}

static void ssh_x509_crl_sign_cb(SshCryptoStatus status,
                                 const unsigned char *signature_buffer,
                                 size_t signature_buffer_len,
                                 void *context)
{
  SshX509CrlContext crl_context= context;

  crl_context->encode_context->crypto_handle = NULL;

  if (status != SSH_CRYPTO_OK)
    {
      crl_context->encode_context->rv = SSH_X509_FAILED_PRIVATE_KEY_OPS;
    }
  else
    {
      crl_context->signature = signature_buffer;
      crl_context->signature_len = signature_buffer_len;
    }

  /* Finalize the certificate asn1 blob. */
  ssh_x509_crl_encode_asn1_finalize(crl_context);
}


SshX509AsyncCallStatus
ssh_x509_crl_encode_asn1(SshX509CertEncodeContext encode_context)
{
  SshAsn1Status status;
  SshAsn1Node rl_list, node, prevnode, tmp, crl_extensions, rl_ext, revoked,
    issuer_name, version_node, this_update, next_update;
  size_t signed_data_len;
  SshX509RevokedCerts r;
  int version_flag;
  SshMPIntegerStruct version;
  SshX509CrlContext crl_context = NULL;
  SshOperationHandle crypto_handle;
  SshX509Crl crl = encode_context->crl;

  /* Initialize */
  ssh_mprz_init(&version);
  version_flag = 0;

  /* Encode revokedCertificates. If crlEntryExtensions are present,
     set version number properly. */
  for (prevnode = NULL, rl_list = NULL, r = crl->revoked; r; r = r->next)
    {
      /* crlEntryExtensions */
      if (ssh_x509_crl_rev_encode_extension(encode_context->asn1_context,
                                            r, &rl_ext,
                                            &crl->config)
          != SSH_X509_OK)
        {
          encode_context->rv = SSH_X509_FAILED_EXTENSION_ENCODE;
          goto failed;
        }
      if (rl_ext)
        version_flag = 1;

      /* revocationDate */
      tmp = ssh_x509_encode_time(encode_context->asn1_context,
                                 &r->revocation_date);

      status =
        ssh_asn1_create_node(encode_context->asn1_context,
                             &node,
                             "(sequence ()"
                             "  (integer ())" /* serial number */
                             "  (any ())"     /* revocation date */
                             "  (any ()))",   /* extensions */
                             &r->serial_number,
                             tmp, rl_ext);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }

      if (rl_list == NULL)
        rl_list = ssh_asn1_add_list(rl_list, node);
      else
        (void)ssh_asn1_add_list(prevnode, node);

      prevnode = node;
    }

  /* Finish up the revoked certificates list. */
  if (rl_list)
    {
      status =
        ssh_asn1_create_node(encode_context->asn1_context,
                             &revoked,
                             "(sequence () (any ()))", rl_list);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }
    }
  else
    revoked = NULL;

  /* Finish up the main CRL structure. */

  /* Encode the CRL extension */
  if (ssh_x509_crl_encode_extension(encode_context->asn1_context,
                                    crl,
                                    &crl_extensions) != SSH_X509_OK)
    {
      encode_context->rv = SSH_X509_FAILED_EXTENSION_ENCODE;
      goto failed;
    }

  if (crl_extensions != NULL)
    version_flag = 1;

  /* Choose suitable version number. Version node is only present at
     version2 CRL format (e.g. if version_flag is 1. */
  if (version_flag & 0x1)
    ssh_mprz_set_ui(&version, 1);
  else
    ssh_mprz_set_ui(&version, 0);

  if (ssh_mprz_cmp_ui(&version, 1) >= 0)
    {
      status =
        ssh_asn1_create_node(encode_context->asn1_context, &version_node,
                             "(integer ())", &version);
      if (status != SSH_ASN1_STATUS_OK)
        {
          encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
          goto failed;
        }
    }
  else
    version_node = NULL;

  /* Encode the necessary values. */
  issuer_name = ssh_x509_encode_dn_name(encode_context->asn1_context,
                                        SSH_X509_NAME_DISTINGUISHED_NAME,
                                        crl->issuer_name,
                                        &crl->config);
  if (issuer_name == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_DN_NAME_ENCODE;
      goto failed;
    }

  this_update = ssh_x509_encode_time(encode_context->asn1_context,
                                     &crl->this_update);
  if (this_update == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_TIME_ENCODE;
      goto failed;
    }

  if (crl->use_next_update)
    next_update = ssh_x509_encode_time(encode_context->asn1_context,
                                       &crl->next_update);
  else
    next_update = NULL;

  if ((crl_context = ssh_calloc(1, sizeof(*crl_context))) == NULL)
    {
      encode_context->rv = SSH_X509_FAILURE;
      goto failed;
    }
  crl_context->encode_context = encode_context;

  crl_context->sig_alg = ssh_x509_encode_sigalg(encode_context->asn1_context,
                                                encode_context->issuer_key);
  if (crl_context->sig_alg == NULL)
    {
      encode_context->rv = SSH_X509_FAILED_SIGNATURE_ALGORITHM_ENCODE;
      goto failed;
    }

  /* Create the TBS CRL. */
  status =
    ssh_asn1_create_tree(encode_context->asn1_context,
                         &crl_context->crl_tree,
                         "(sequence ()"
                         "  (any ())"     /* version */
                         "  (any ())"     /* signature id */
                         "  (any ())"     /* issuer name */
                         "  (any ())"     /* this update */
                         "  (any ())"     /* next update */
                         "  (any ())"     /* revoked certificates */
                         "  (any (e 0)))",  /* extensions */
                         version_node,
                         crl_context->sig_alg,
                         issuer_name,
                         this_update, next_update,
                         revoked, crl_extensions);

  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  /* Do the encoding. */
  status =
    ssh_asn1_encode(encode_context->asn1_context, crl_context->crl_tree);
  if (status != SSH_ASN1_STATUS_OK)
    {
      encode_context->rv = SSH_X509_FAILED_ASN1_ENCODE;
      goto failed;
    }

  ssh_asn1_get_data(crl_context->crl_tree,
                    &crl_context->signed_data, &signed_data_len);

  /* Sign with the given issuer key. */
  crypto_handle = ssh_private_key_sign_async(encode_context->issuer_key,
                                             crl_context->signed_data,
                                             signed_data_len,
                                             ssh_x509_crl_sign_cb,
                                             crl_context);

  /* If we are dealing with truly asynchronous signing, assert that
     this encode is asynchronous. */
  if (crypto_handle != NULL)
    {
      SSH_ASSERT(SSH_X509_CERT_ENCODE_IS_ASYNCHRONOUS(encode_context));
      encode_context->crypto_handle = crypto_handle;
      ssh_mprz_clear(&version);
      return SSH_X509_ASYNC_CALL_PENDING;
    }

  /* The sign has called the callback that freed the sign_context and
     the encode_context. */
  ssh_mprz_clear(&version);
  return SSH_X509_ASYNC_CALL_COMPLETED;

 failed:
  ssh_free(crl_context);
  ssh_mprz_clear(&version);
  return SSH_X509_ASYNC_CALL_ERROR;
}

SshX509AsyncCallStatus
ssh_x509_crl_encode_internal(SshX509CertEncodeContext encode_context)
{
  /* Initialize the ASN.1 allocation context, that we're using and
     encode. */
  if ((encode_context->asn1_context = ssh_asn1_init()) == NULL)
    return SSH_X509_ASYNC_CALL_ERROR;

  return ssh_x509_crl_encode_asn1(encode_context);
}

/* This starts an asynchronous encoding. */
SshOperationHandle ssh_x509_crl_encode_async(SshX509Crl c,
                                              SshPrivateKey issuer_key,
                                              SshX509EncodeCB encode_cb,
                                              void *context)
{
  SshX509CertEncodeContext encode_context;
  SshX509AsyncCallStatus call_status;

  SSH_ASSERT(encode_cb != NULL_FNPTR);

  if ((encode_context = ssh_calloc(1, sizeof(*encode_context))) == NULL)
    {
      (*encode_cb)(SSH_X509_FAILURE, NULL, 0, context);
      return NULL;
    }

  encode_context->crl = c;
  encode_context->issuer_key = issuer_key;
  encode_context->rv = SSH_X509_OK;
  encode_context->user_context = context;
  encode_context->user_encode_cb = encode_cb;
  encode_context->operation_handle =
    ssh_operation_register(ssh_x509_cert_encode_async_abort,
                           encode_context);

  call_status = ssh_x509_crl_encode_internal(encode_context);

  switch(call_status)
    {
    case SSH_X509_ASYNC_CALL_COMPLETED:
    default:
      return NULL;
    case SSH_X509_ASYNC_CALL_PENDING:
      return encode_context->operation_handle;
    case SSH_X509_ASYNC_CALL_ERROR:
      /* internal encode returned error. Abort all. */
      encode_cb(encode_context->rv, NULL, 0, context);
      ssh_x509_cert_encode_async_abort(encode_context);
      return NULL;
    }
}
#endif /* SSHDIST_CERT */
