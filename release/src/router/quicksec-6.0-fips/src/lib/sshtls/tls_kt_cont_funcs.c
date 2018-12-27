/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

/* Continue after the certificate manager has tried to verify
   the certificates. */
SshTlsTransStatus ssh_tls_trans_cont_cert_verify(SshTlsProtocolState s)
{
  s->kex.state = SSH_TLS_KEX_WAIT_APP_CERT_DECIDE;
  ssh_tls_call_app_hook(s, SSH_TLS_PEER_CERTS);
  return SSH_TLS_TRANS_OK;
}

SshTlsTransStatus ssh_tls_trans_cont_cert_decide(SshTlsProtocolState s)
{
  if (!(s->kex.flags & SSH_TLS_KEX_CERT_VERIFIED))
    {
      FAIL(SSH_TLS_ALERT_CERTIFICATE_UNKNOWN,
           ("Could not verify certificate."));
    }

  s->kex.state = (s->conf.is_server ?
                  SSH_TLS_KEX_WAIT_C_KEX :
                  SSH_TLS_KEX_WAIT_S_KEX);
  return SSH_TLS_TRANS_OK;
}

SshTlsTransStatus ssh_tls_trans_cont_got_own_certs(SshTlsProtocolState s)
{
  if (s->conf.is_server)
    {
      s->kex.state = SSH_TLS_KEX_SEND_S_HELLO;
      return ssh_tls_choose_suite(s);
    }
  else
    {
      s->kex.state = SSH_TLS_KEX_WAIT_S_HELLODONE;
      return SSH_TLS_TRANS_OK;
    }
}

SshTlsTransStatus ssh_tls_trans_cont_keyop_completion(SshTlsProtocolState s)
{
  if (s->kex.flags & SSH_TLS_KEX_KEYOP_FAILED)
    {
      FAIL(s->kex.alert, (s->kex.alert_text));
    }

  s->kex.state = s->kex.next_state;
  s->kex.next_state = SSH_TLS_KEX_CLEAR;
  return SSH_TLS_TRANS_OK;
}

SshTlsTransStatus ssh_tls_trans_cont_auth_decide(SshTlsProtocolState s)
{
  if (s->conf.private_key == NULL)
    {
      SSH_DEBUG(6, ("No private key, so will send empty certificate chain."));
      s->kex.state = SSH_TLS_KEX_WAIT_S_HELLODONE;
      return SSH_TLS_TRANS_OK;
    }

#ifdef SSHDIST_VALIDATOR
  /* Try to get certs. */
  return ssh_tls_get_own_certificates(s);
#endif /* SSHDIST_VALIDATOR */

#ifndef SSHDIST_VALIDATOR
  /* The client is assumed to have previously input its certificates
     in the 'own_certs' in the SshTlsConfiguration structure. */
  s->kex.state = SSH_TLS_KEX_WAIT_S_HELLODONE;
  return SSH_TLS_TRANS_OK;

#endif /* SSHDIST_VALIDATOR */
}

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
SshTlsTransStatus ssh_tls_trans_cont_out_crypto_completion(
  SshTlsProtocolState s)
{
  s->kex.state = s->kex.next_state;
  s->kex.next_state = SSH_TLS_KEX_CLEAR;
  return SSH_TLS_TRANS_OK;
}
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
