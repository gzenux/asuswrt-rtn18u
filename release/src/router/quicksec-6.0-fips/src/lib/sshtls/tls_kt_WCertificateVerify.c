/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

static void
tls_kt_wcv_sign_done(SshCryptoStatus status,
                     const unsigned char *signature, size_t signature_len,
                     void *context)
{
  SshTlsProtocolState s = context;
  unsigned char temp[2];

  if (status != SSH_CRYPTO_OK)
    {
      s->kex.flags |= SSH_TLS_KEX_KEYOP_FAILED;
      s->kex.alert = SSH_TLS_ALERT_INTERNAL_ERROR;
      s->kex.alert_text = "Can't construct signature.";
      ssh_tls_async_continue(s);
      return;
    }

  ssh_tls_make_hs_header(s, SSH_TLS_HS_CERT_VERIFY, signature_len + 2);

  SSH_PUT_16BIT(temp, signature_len);
  ssh_tls_add_to_kex_packet(s, temp, 2);
  ssh_tls_add_to_kex_packet(s, signature, signature_len);
  ssh_tls_async_continue(s);
}

SshTlsTransStatus ssh_tls_trans_write_client_certverify(SshTlsProtocolState s)
{
  unsigned char *ptr; int len;
  unsigned char hashes[16 + 20];
  size_t signlen;

  s->kex.state = SSH_TLS_KEX_SEND_C_CC;

  if (!(s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED))
    {
      return SSH_TLS_TRANS_REPROCESS;
    }

  /* If we do not have a private key we have ignored the
     authentication request and thus do not send the CertificateVerify
     packet. */
  if (s->conf.private_key == NULL)
    return SSH_TLS_TRANS_REPROCESS;

  /* If we do not have a certificate we obviously have not sent
     "a client certificate that has signing capability" and thus
     we do not send the CertificateVerify packet. */
#ifdef SSHDIST_VALIDATOR
  if (s->kex.own_certificate_list == NULL)
    return SSH_TLS_TRANS_REPROCESS;
#endif /* SSHDIST_VALIDATOR */
#ifndef SSHDIST_VALIDATOR
  if (s->kex.own_certs == NULL)
    return SSH_TLS_TRANS_REPROCESS;
#endif /* SSHDIST_VALIDATOR */

  SSH_ASSERT(s->kex.handshake_history != NULL);
  ptr = ssh_buffer_ptr(s->kex.handshake_history);
  len = ssh_buffer_len(s->kex.handshake_history);

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
      if (!ssh_tls_ssl_certverify_digest(s->kex.master_secret, 48,
                                         ptr, len,
                                         TRUE, hashes))
        return SSH_TLS_TRANS_FAILED;
    }
  else
    {
#endif
      if (ssh_hash_of_buffer("md5", ptr, len, hashes) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;
      if (ssh_hash_of_buffer("sha1", ptr, len, hashes + 16) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;
#ifdef SSH_TLS_SSL_3_0_COMPAT
    }
#endif

  SSH_ASSERT(s->conf.private_key != NULL);

  if (ssh_private_key_select_scheme(s->conf.private_key,
                                    SSH_PKF_SIGN, "rsa-pkcs1-none",
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot set private key signature scheme"));
      return SSH_TLS_TRANS_FAILED;
    }

  signlen = ssh_private_key_max_signature_output_len(s->conf.private_key);
  SSH_ASSERT(signlen > 0);

  s->kex.state = SSH_TLS_KEX_WAIT_KEYOP_COMPLETION;
  s->kex.next_state = SSH_TLS_KEX_SEND_C_CC;
  s->kex.alert = 0;
  s->kex.alert_text = NULL;

  ssh_tls_async_freeze(s);
  ssh_private_key_sign_async(s->conf.private_key,
                             hashes, 36,
                             tls_kt_wcv_sign_done,
                             s);

  return SSH_TLS_TRANS_OK;
}
