/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

static SshTlsTransStatus read_cert(SshTlsProtocolState s,
                                   unsigned char *data,
                                   int data_len)
{
#ifndef SSHDIST_VALIDATOR









  return SSH_TLS_TRANS_FAILED;
#endif /* SSHDIST_VALIDATOR */
#ifdef SSHDIST_VALIDATOR
  int cert_list_len;
  int cert_len;
  int i;

  SshCMCertificate leaf_cert = NULL;
  Boolean must_free_leaf_cert = FALSE;
  SshCMCertificate cert;
  SshX509Certificate x509;
  SshCMStatus status = SSH_CM_STATUS_FAILURE;
  SshTlsBerCert *ptr;

  MIN_LENGTH(3);

  cert_list_len = (data[0] << 16) | (data[1] << 8) | (data[2]);
  data += 3;
  data_len -= 3;

  SSH_DEBUG(6, ("The certificate list is %d bytes long.", cert_list_len));

  if (cert_list_len != data_len)
    {
      FAIL(SSH_TLS_ALERT_DECODE_ERROR,
           ("Garbage after the certificate list."));
    }

  ptr = &(s->kex.peer_certs);

  for (i = 0; data_len > 0; i++)
    {
      MIN_LENGTH(3);

      cert_len = (data[0] << 16) | (data[1] << 8) | (data[2]);
      data += 3;
      data_len -= 3;

      SSH_DEBUG(6, ("The next certificate is %d bytes long.", cert_len));

      MIN_LENGTH(cert_len);

      cert = ssh_cm_cert_allocate(s->conf.cert_manager);

      if (cert == NULL)
        FAIL(SSH_TLS_ALERT_INTERNAL_ERROR, ("Out of memory error"));

      if ((status = ssh_cm_cert_set_ber(cert, data, cert_len)) !=
          SSH_CM_STATUS_OK)
        {
          ssh_cm_cert_free(cert);
          FAIL(SSH_TLS_ALERT_DECODE_ERROR,
               ("Invalid certificate (status %d).", status));
        }

      /* Create an SshTlsBerCert and add it to the `peer_certs' chain. */
      if ((*ptr = ssh_tls_create_ber_cert(data, cert_len)) != NULL)
        ptr = &((*ptr)->next);

      /* Skip the certificate in the packet now. */
      data += cert_len;
      data_len -= cert_len;

#ifdef DEBUG_LIGHT
      {
        char *subject, *issuer;

        if (ssh_cm_cert_get_x509(cert, &x509) == SSH_CM_STATUS_OK)
          {
            ssh_x509_cert_get_subject_name(x509, &subject);
            ssh_x509_cert_get_issuer_name(x509, &issuer);
            SSH_DEBUG(5, ("Subject: %s Issuer: %s", subject, issuer));
            ssh_free(subject); ssh_free(issuer);
            ssh_x509_cert_free(x509);
          }
      }
#endif

      switch (s->conf.crl_check_policy)
        {
        case SSH_TLS_CRL_CHECK_NEVER:
          ssh_cm_cert_non_crl_issuer(cert);
          ssh_cm_cert_non_crl_user(cert);
          break;
        case SSH_TLS_CRL_CHECK_IF_CRLDP:
          if (ssh_cm_cert_get_x509(cert, &x509) == SSH_CM_STATUS_OK)
            {
              if (ssh_x509_cert_ext_available(x509,
                                              SSH_X509_EXT_CRL_DIST_POINTS,
                                              NULL))
                ssh_cm_cert_make_crl_user(cert);
              else
                ssh_cm_cert_non_crl_user(cert);
              ssh_cm_cert_make_crl_issuer(cert);
              ssh_x509_cert_free(x509);
            }
          break;
        default:
          SSH_ASSERT(SSH_TLS_CRL_CHECK_ALWAYS == s->conf.crl_check_policy);
          ssh_cm_cert_make_crl_issuer(cert);
          ssh_cm_cert_make_crl_user(cert);
          break;
        }

      if (i == 0) leaf_cert = cert;

      /* Add the certificate to the manager if we have a manager. */
      if (s->conf.cert_manager != NULL)
        {
          status = ssh_cm_add(cert);

          if (status != SSH_CM_STATUS_OK &&
              status != SSH_CM_STATUS_ALREADY_EXISTS)
            {
              ssh_cm_cert_free(cert);
              FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
                   ("Certificate manager does not work (status %d).", status));
            }
        }
      else
        {
          status = SSH_CM_STATUS_OK; /* To make the compiler happy. */
        }

      /* Free the certificates when appropriate. */
      if (status == SSH_CM_STATUS_ALREADY_EXISTS ||
          s->conf.cert_manager == NULL)
        {
          if (i > 0)
            ssh_cm_cert_free(cert);
          else
            must_free_leaf_cert = TRUE;
        }
    }

  SSH_ASSERT(data_len == 0);
  s->kex.state = SSH_TLS_KEX_WAIT_CM_CERT_VERIFY;

  if (leaf_cert == NULL)
    {
      if (s->conf.is_server)
        {
          SSH_DEBUG(4, ("The client sent empty certificate chain."));
          SSH_ASSERT(s->kex.her_public_key == NULL);

          if (s->conf.flags & SSH_TLS_STRICTAUTH)
            FAIL(SSH_TLS_ALERT_ACCESS_DENIED,
                 ("Client authentication is strictly required but got "
                  "no certificates."));

          s->kex.query_status = SSH_TLS_CERT_NONE;
          s->kex.flags ^= SSH_TLS_KEX_CLIENT_CERT_REQUESTED;

          return SSH_TLS_TRANS_OK;
        }

      SSH_ASSERT(!(s->conf.is_server));

      FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
           ("No certificate from the server."));
    }

  /* Get the key. */
  SSH_ASSERT(s->kex.her_public_key == NULL);

  {
    SshX509Certificate x509;

    SSH_DEBUG(5, ("Getting the public key from the leaf certificate."));

    if (ssh_cm_cert_get_x509(leaf_cert, &x509) == SSH_CM_STATUS_OK)
      {
        if (ssh_x509_cert_get_public_key(x509, &(s->kex.her_public_key))
            != TRUE)
          {
            ssh_x509_cert_free(x509);
            FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
                 ("Couldn't get the public key from the leaf certificate."));
          }
        ssh_x509_cert_free(x509);
      }

    SSH_ASSERT(s->kex.her_public_key != NULL);

    /* Let's look at the key. */
    {
      const char *scheme;
      SshCryptoStatus status;

      if ((status = ssh_public_key_get_info(s->kex.her_public_key,
                                            SSH_PKF_ENCRYPT, &scheme,
                                            SSH_PKF_END))
          == SSH_CRYPTO_OK)
        {
          if (strcmp(scheme, "rsa-pkcs1-none"))
            {
              FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
                   ("The public key type `%s' is not supported.", scheme));
            }
          SSH_DEBUG(7, ("Her public key supports %s for encrypting.",
                        scheme));
        }

      if ((status = ssh_public_key_get_info(s->kex.her_public_key,
                                  SSH_PKF_SIGN, &scheme, SSH_PKF_END))
          == SSH_CRYPTO_OK)
        {
          if (strncmp(scheme, "rsa-pkcs1-", strlen("rsa-pkcs1-")))
            {
              FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
                   ("The public key type `%s' is not supported.", scheme));
            }
          SSH_DEBUG(7, ("Her public key supports %s for signign.",
                        scheme));
        }
    }
  }


  /* Now the certificate chain is available for the application. */
  s->kex.query_status = SSH_TLS_CERT_OK;

  /* Try to verify the certificate.*/
  SSH_DEBUG(5, ("Trying to verify the peer certificate."));

  if (s->conf.cert_manager != NULL)
    {
      int id = ssh_cm_cert_get_cache_id(leaf_cert);

      /* Free the leaf certificate now if that can be done. */
      if (must_free_leaf_cert)
        ssh_cm_cert_free(leaf_cert);

      /* The asynchronous operation starts. */
      if (!ssh_tls_verify_certificate(s, id))
        FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
             ("Certificate manager does not work (status %d).", status));
    }
  else
    {
      SSH_ASSERT(must_free_leaf_cert);
      ssh_cm_cert_free(leaf_cert);
      /* Now we fall to the ...S_CERT_VERIFY continuation which calls
         the application hook anyway. */
    }
  return SSH_TLS_TRANS_OK;

#endif /* SSHDIST_VALIDATOR */
}

SshTlsTransStatus
ssh_tls_trans_read_server_cert(SshTlsProtocolState s,
                               SshTlsHandshakeType type,
                               unsigned char *data, int data_len)
{
  if (s->kex.flags & SSH_TLS_KEX_ANONYMOUS_SERVER)
    {
      if (type == SSH_TLS_HS_CERT)
        {
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Got server certificate for anonymous key exchange."));
        }
      s->kex.query_status = SSH_TLS_CERT_NONE;
      s->kex.state = SSH_TLS_KEX_WAIT_S_KEX;
      return SSH_TLS_TRANS_REPROCESS;
    }

  CHECKTYPE(SSH_TLS_HS_CERT);

  return read_cert(s, data, data_len);
}

SshTlsTransStatus ssh_tls_trans_read_client_cert(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  if (type != SSH_TLS_HS_CERT)
    {
      if (s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED)
        FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
             ("Waiting for the client certificate but did not get it."));

      /* Otherwise. */
      s->kex.state = SSH_TLS_KEX_WAIT_C_KEX;
      return SSH_TLS_TRANS_REPROCESS;
    }

  if (!(s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED))
    {
      SSH_DEBUG(3, ("Got client certificate but not expecting it."));
      ssh_tls_send_alert_message(s, SSH_TLS_ALERT_FATAL,
                                 SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
      return SSH_TLS_TRANS_FAILED;
    }

  /* Parse the client's certificate. */
  return read_cert(s, data, data_len);
}
