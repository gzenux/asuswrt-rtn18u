/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic certificate revocation list functions (allocation, freeing etc).
*/

#include "sshincludes.h"
#include "x509.h"
#include "x509internal.h"

#ifdef SSHDIST_CERT

/* CRL extensions. */
void ssh_x509_crl_extensions_init(SshX509CrlExtensions e)
{
  /* Initialize the extension information. */
  memset(e, 0, sizeof(*e));

  /* CRL number */
  ssh_mprz_init_set_si(&e->crl_number, -1);
  /* Delta CRL indicator */
  ssh_mprz_init_set_si(&e->delta_crl_ind, -1);
}

void ssh_x509_crl_extensions_clear(SshX509CrlExtensions e)
{
  if (e == NULL)
    return;

  if (e->issuer_alt_names != NULL)
    ssh_x509_name_free(e->issuer_alt_names);
  if (e->auth_key_id != NULL)
    ssh_x509_key_id_free(e->auth_key_id);
  if (e->dist_point != NULL)
    ssh_x509_issuing_dist_point_free(e->dist_point);
  ssh_mprz_clear(&e->crl_number);
  ssh_mprz_clear(&e->delta_crl_ind);

  /* Clean. */
  e->issuer_alt_names = NULL;
  e->auth_key_id = NULL;
  e->dist_point  = NULL;
}

/* CRL revocation information extensions. */
void ssh_x509_crl_rev_extensions_init(SshX509CrlRevExtensions e)
{
  memset(e, 0, sizeof(*e));
  ssh_ber_time_zero(&e->invalidity_date);
}

void ssh_x509_crl_rev_extensions_clear(SshX509CrlRevExtensions e)
{
  if (e == NULL)
    return;

  /* Free the data within the revoked certificate. */
  ssh_free(e->hold_inst_code);
  if (e->certificate_issuer != NULL)
    ssh_x509_name_free(e->certificate_issuer);

  ssh_x509_crl_rev_extensions_init(e);
}

SshX509Crl ssh_x509_crl_allocate(void)
{
  SshX509Crl crl = ssh_calloc(1, sizeof(*crl));
  SshX509Config pc;

  if (crl)
    {
      /* Initialize with NULLs. */
      crl->version = SSH_X509_VERSION_UNKNOWN;

      /* Initialize the pop. */
      ssh_x509_pop_init(&crl->pop);

      ssh_ber_time_zero(&crl->this_update);
      ssh_ber_time_zero(&crl->next_update);
      crl->use_next_update = FALSE;

      /* Initialize the extensions. */
      ssh_x509_crl_extensions_init(&crl->extensions);

      pc = ssh_x509_get_configuration();
      memmove(&crl->config, pc, sizeof(*pc));
    }
  /* Return the allocated CRL context. */
  return crl;
}

void ssh_x509_crl_reset(SshX509Crl c)
{
  ssh_x509_name_reset(c->issuer_name);
  ssh_x509_name_reset(c->extensions.issuer_alt_names);
}

SshX509RevokedCerts ssh_x509_revoked_allocate(void)
{
  SshX509RevokedCerts rc = ssh_malloc(sizeof(*rc));

  if (rc)
    {
      /* Place NULLs. */
      rc->next = NULL;
      ssh_mprz_init_set_ui(&rc->serial_number, 0);
      ssh_ber_time_zero(&rc->revocation_date);

      /* Initialize the extensions. */
      ssh_x509_crl_rev_extensions_init(&rc->extensions);
    }
  return rc;
}

void ssh_x509_revoked_free(SshX509RevokedCerts rc)
{
  SshX509RevokedCerts next;

  while (rc)
    {
      next = rc->next;
      /* Free the data within the revoked certificate. */
      ssh_mprz_clear(&rc->serial_number);

      /* Free the extensions. */
      ssh_x509_crl_rev_extensions_clear(&rc->extensions);

      /* Free revoked certificate identifier itself. */
      ssh_free(rc);
      rc = next;
    }
}

void ssh_x509_crl_free(SshX509Crl crl)
{
  if (crl)
    {
      ssh_x509_name_free(crl->issuer_name);
      ssh_x509_revoked_free(crl->revoked);

      /* Clear the pop. */
      ssh_x509_pop_clear(&crl->pop);

      /* Free the rest. */
      ssh_x509_crl_extensions_clear(&crl->extensions);

      /* Free the certificate itself. */
      ssh_free(crl);
    }
}


SshOperationHandle ssh_x509_crl_verify_async(SshX509Crl crl,
                                             SshPublicKey issuer_key,
                                             SshX509VerifyCB verify_cb,
                                             void *context)
{
  char *sign, *key_type;
  const SshX509PkAlgorithmDefStruct *algorithm;
  SshX509VerifyContext ctx;
  SshOperationHandle handle;

  if (issuer_key == NULL)
    goto failed;

  if (crl->version == SSH_X509_VERSION_UNKNOWN)
    goto failed;


  /* Set the algorithm of the issuer key to correspond the subject. */

  /* Get the signature algorithm type so that we can look very transparent
     to the application. */
  if (ssh_public_key_get_info(issuer_key,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_SIGN, &sign,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    goto failed;

  /* Now select the scheme. */
  if (ssh_public_key_select_scheme(issuer_key,
                                   SSH_PKF_SIGN,
                                   crl->pop.signature.pk_algorithm,
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    goto failed;

  /* Check that this implementation supports the given algorithm and
     key type pair. */
  algorithm = ssh_x509_match_algorithm(key_type,
                                       crl->pop.signature.pk_algorithm, NULL);
  if (algorithm == NULL)
    goto failed;

  /* Set up the verification context. */
  if ((ctx = ssh_calloc(1, sizeof(*ctx))) == NULL)
    goto failed;

  ctx->sign       = sign;
  ctx->issuer_key = issuer_key;
  ctx->verify_cb  = verify_cb;
  ctx->verify_ctx = context;

  ctx->op_handle = ssh_operation_register(ssh_x509_verify_async_abort,
                                          ctx);
  handle =
    ssh_public_key_verify_async(issuer_key,
                                crl->pop.signature.signature,
                                crl->pop.signature.signature_len,
                                crl->pop.proved_message,
                                crl->pop.proved_message_len,
                                ssh_x509_verify_async_finish,
                                ctx);
  if (handle == NULL)
    {
      /* Operation already done, the context has already been freed, thus we
         just return NULL here */
      return NULL;
    }
  ctx->crypto_handle = handle;
  return ctx->op_handle;

failed:
  /* Failure case. */
  (*verify_cb)(SSH_X509_FAILURE, context);
  return NULL;
}


/* x509crl.c */
#endif /* SSHDIST_CERT */
