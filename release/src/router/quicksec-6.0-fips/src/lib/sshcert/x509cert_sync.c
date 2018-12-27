/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic certificate handling functions (allocation, freeing etc).
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

Boolean ssh_x509_cert_verify(SshX509Certificate c,
                             SshPublicKey issuer_key)
{
  char *sign, *key_type;

  if (issuer_key == NULL)
    return FALSE;

  /* Get the signature algorithm type so that we can look very transparent
     to the application. */
  if (ssh_public_key_get_info(issuer_key,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_SIGN, &sign,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(issuer_key,
                                   SSH_PKF_SIGN, c->pop.signature.pk_algorithm,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    return FALSE;

  if (ssh_public_key_verify_signature(issuer_key,
                                      c->pop.signature.signature,
                                      c->pop.signature.signature_len,
                                      c->pop.proved_message,
                                      c->pop.proved_message_len)
      != SSH_CRYPTO_OK)
    return FALSE;

  /* Return the issuer signature scheme to where it originally was. */

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(issuer_key,
                                   SSH_PKF_SIGN, sign,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    /* We're not really interested in this, but just return an error
       anyway. */
    return FALSE;

  return TRUE;
}


/* This starts an synchronous encoding call. Arguments are stored to
   encoding context, and the same functions are used as in asynchronous
   case. If the private key passed as an argument here is not capable of
   doing synchronous call, ssh_fatal will be called later. */
SshX509Status ssh_x509_cert_encode(SshX509Certificate c,
                                   SshPrivateKey issuer_key,
                                   unsigned char **buf, size_t *buf_len)
{
  SshX509CertEncodeContext encode_context;
  SshX509Status rv;

  /* Make the context and pass it forward. */
  if ((encode_context = ssh_calloc(1, sizeof(*encode_context))) == NULL)
    return SSH_X509_FAILURE;

  encode_context->cert = c;
  encode_context->issuer_key = issuer_key;
  encode_context->rv = SSH_X509_OK;

  encode_context->operation_handle
    = ssh_operation_register(ssh_x509_cert_encode_async_abort, encode_context);

  /* Pass the context. */
  ssh_x509_cert_encode_internal(encode_context);

  /* Read data from context. */
  *buf = encode_context->buf;
  *buf_len = encode_context->buf_len;
  rv = encode_context->rv;

  /* Free the context. */
  ssh_x509_cert_encode_async_abort(encode_context);
  return rv;
}
#endif /* SSHDIST_CERT */
