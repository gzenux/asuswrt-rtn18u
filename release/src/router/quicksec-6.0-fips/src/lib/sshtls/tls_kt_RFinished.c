/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus
ssh_tls_trans_read_finished(SshTlsProtocolState s,
                            SshTlsHandshakeType type,
                            unsigned char *data, int data_len)
{
  unsigned char *ptr;
  int len;
  unsigned char locally_computed_verify_data[36];
  unsigned char hashes[16 + 20];

  CHECKTYPE(SSH_TLS_HS_FINISHED);
  SSH_DEBUG(7, ("Got the (expected) finished message."));

  SSH_ASSERT(s->kex.handshake_history != NULL);

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
      if (data_len != 36)
        {
          FAIL(SSH_TLS_ALERT_DECODE_ERROR,
               ("Invalid length verify data (%d bytes).", data_len));
        }

      ptr = ssh_buffer_ptr(s->kex.handshake_history);
      len = ssh_buffer_len(s->kex.handshake_history);

      SSH_DEBUG(7, ("Verifying SSL3 finished digest, buffer len = %d.",
                    len));

      SSH_DEBUG_HEXDUMP(10, ("Handshake buffer"), ptr, len);

      if (!ssh_tls_ssl_finished_digest(s->kex.master_secret, 48,
                                       ptr, len,
                                       s->conf.is_server,
                                       locally_computed_verify_data))
        {
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Local and remote verify data do not match."));
        }

      if (memcmp(data, locally_computed_verify_data, 36))
        {
          SSH_DEBUG_HEXDUMP(5, ("Local and remote verify data do not match. "
                                "Local: "),
                            locally_computed_verify_data, 36);
          SSH_DEBUG_HEXDUMP(5, ("Remote: "),
                            data, 36);
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Local and remote verify data do not match."));
        }
      goto accepted;
    }

#endif /* SSH_TLS_SSL_3_0_COMPAT */

  ptr = ssh_buffer_ptr(s->kex.handshake_history);
  len = ssh_buffer_len(s->kex.handshake_history);

  if (ssh_hash_of_buffer("md5", ptr, len, hashes) != SSH_CRYPTO_OK)
    return SSH_TLS_TRANS_FAILED;
  if (ssh_hash_of_buffer("sha1", ptr, len, hashes + 16) != SSH_CRYPTO_OK)
    return SSH_TLS_TRANS_FAILED;

  ssh_tls_prf(s->kex.master_secret, 48,
              (unsigned char *)
              (s->conf.is_server ? "client finished" : "server finished"),
              15 /* strlen("client finished") */,
              hashes, 16 + 20,
              locally_computed_verify_data, 12);

  memset(hashes, 0, 16 + 20);

  if (data_len != 12)
    {
      FAIL(SSH_TLS_ALERT_DECODE_ERROR,
           ("Invalid length verify data (%d bytes).", data_len));
    }

  if (memcmp(data, locally_computed_verify_data, 12))
    {
      SSH_DEBUG_HEXDUMP(5, ("Local and remote verify data do not match. "
                            "Local: "),
                        locally_computed_verify_data, 12);
      SSH_DEBUG_HEXDUMP(5, ("Remote: "),
                        data, 12);
      FAIL(SSH_TLS_ALERT_ILLEGAL_PARAMETER,
           ("Local and remote verify data do not match."));
    }

accepted:
  memset(locally_computed_verify_data, 0,
         sizeof(locally_computed_verify_data));

  SSH_DEBUG(6, ("Verify data verified."));

  /* The order of client's and server's change_cipher and finished
     messages is different depending on whether we are resuming and
     old session or defining a new one. This is another strange
     property of the TLS protocol. */
  if ((s->conf.is_server && !(s->kex.flags & SSH_TLS_KEX_NEW_SESSION))
      ||
      (!s->conf.is_server && (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)))
    {
      ssh_tls_kex_finished(s);
    }
  else
    {
      if (s->conf.is_server)
        {
          s->kex.state = SSH_TLS_KEX_SEND_S_CC;
        }
      else
        {
          s->kex.state = SSH_TLS_KEX_SEND_C_CC;
        }
    }

  return SSH_TLS_TRANS_OK;
}
