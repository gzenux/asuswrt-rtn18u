/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

static void
tls_kt_rcv_verify_done(SshCryptoStatus status,
                       void *context)
{
  SshTlsProtocolState s = context;

  if (status != SSH_CRYPTO_OK)
    {
      s->kex.flags |= SSH_TLS_KEX_KEYOP_FAILED;
      s->kex.alert = SSH_TLS_ALERT_DECRYPT_ERROR;
      s->kex.alert_text = "Invalid signature in the client CertVerify packet.";
      ssh_tls_async_continue(s);
      return;
    }
  ssh_tls_async_continue(s);
}

SshTlsTransStatus
ssh_tls_trans_read_client_certverify(SshTlsProtocolState s,
                                     SshTlsHandshakeType type,
                                     unsigned char *data, int data_len)
{
  int l;
  unsigned char hashes[16 + 20];
  unsigned char *ptr; int len;

  s->kex.state = SSH_TLS_KEX_WAIT_C_CC;

  if (type != SSH_TLS_HS_CERT_VERIFY)
    {
      if ((s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED) &&
          s->kex.her_public_key != NULL)
        {
          FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
               ("Did not got certificate verify message when expecting!"));
        }
      return SSH_TLS_TRANS_REPROCESS;
    }

  if (!(s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED))
    {
      FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
           ("Got a certificate verify message when not expecting."));
    }

  if (s->kex.her_public_key == NULL)
    {
      FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
           ("Get certificate verify message but have no client certificate."));
    }

  MIN_LENGTH(2);
  l = SSH_GET_16BIT(data);
  SSH_DEBUG(7, ("Signature %d bytes long.", l));
  data += 2;
  data_len -= 2;
  if (data_len != l) FAILMF;

  /* Calculate the hashes. */

  SSH_ASSERT(s->kex.handshake_history != NULL);
  ptr = ssh_buffer_ptr(s->kex.handshake_history);
  len = ssh_buffer_len(s->kex.handshake_history);

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
      SSH_DEBUG(7, ("Using the SSL3 certificate verify digest."));
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

  /* Ignore the return value. If this fails then so does the signature
     verification below. */
  if (ssh_public_key_select_scheme(s->kex.her_public_key,
                                   SSH_PKF_SIGN,
                                   "rsa-pkcs1-none",
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    return SSH_TLS_TRANS_FAILED;

  s->kex.state = SSH_TLS_KEX_WAIT_KEYOP_COMPLETION;
  s->kex.next_state = SSH_TLS_KEX_WAIT_C_CC;
  s->kex.alert = 0;
  s->kex.alert_text = NULL;

  ssh_tls_async_freeze(s);
  ssh_public_key_verify_async(s->kex.her_public_key,
                              data, data_len, hashes, 36,
                              tls_kt_rcv_verify_done, s);

  return SSH_TLS_TRANS_OK;
}
