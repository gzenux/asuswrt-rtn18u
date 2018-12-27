/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_write_finished(SshTlsProtocolState s)
{
  unsigned char *ptr; int len;
  unsigned char hashes[16 + 20];
  unsigned char locally_computed_verify_data[36];

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
      SSH_DEBUG(7, ("Computing finished digest for SSL3, "
                    "buffer length = %d.",
                    ssh_buffer_len(s->kex.handshake_history)));
      SSH_DEBUG_HEXDUMP(10, ("Handshake buffer"),
                        ssh_buffer_ptr(s->kex.handshake_history),
                        ssh_buffer_len(s->kex.handshake_history));

      if (!ssh_tls_ssl_finished_digest(
                                  s->kex.master_secret, 48,
                                  ssh_buffer_ptr(s->kex.handshake_history),
                                  ssh_buffer_len(s->kex.handshake_history),
                                  !(s->conf.is_server),
                                  locally_computed_verify_data))
        {
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Local and remote verify data do not match."));
        }

      ssh_tls_make_hs_header(s, SSH_TLS_HS_FINISHED, 36);
      ssh_tls_add_to_kex_packet(s, locally_computed_verify_data, 36);

      goto done;
    }
#endif

  /* Must be done before `ssh_tls_make_hs_header'.*/
  SSH_ASSERT(s->kex.handshake_history != NULL);
  ptr = ssh_buffer_ptr(s->kex.handshake_history);
  len = ssh_buffer_len(s->kex.handshake_history);

  if (ssh_hash_of_buffer("md5", ptr, len, hashes) != SSH_CRYPTO_OK)
    FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
         ("Cannot compute hash digest."));
  if (ssh_hash_of_buffer("sha1", ptr, len, hashes + 16) != SSH_CRYPTO_OK)
    FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
         ("Cannot compute hash digest."));

  /* Now write the header. */
  ssh_tls_make_hs_header(s, SSH_TLS_HS_FINISHED, 12);

  ssh_tls_prf(s->kex.master_secret, 48,
              (unsigned char *)
              (s->conf.is_server ? "server finished" : "client finished"),
              15 /* strlen("client finished") */,
              hashes, 16 + 20,
              locally_computed_verify_data, 12);

  memset(hashes, 0, 16 + 20);
  ssh_tls_add_to_kex_packet(s, locally_computed_verify_data, 12);
  memset(locally_computed_verify_data, 0,
         sizeof(locally_computed_verify_data));

 done:
  /* The order of client's and server's change_cipher and finished
     messages is different depending on whether we are resuming and
     old session or defining a new one. This is another strange
     property of the TLS protocol. */
  if ((s->conf.is_server && (s->kex.flags & SSH_TLS_KEX_NEW_SESSION))
      ||
      (!s->conf.is_server && !(s->kex.flags & SSH_TLS_KEX_NEW_SESSION)))
    {
      ssh_tls_kex_finished(s);
    }
  else
    {
      if (s->conf.is_server)
        {
          s->kex.state = SSH_TLS_KEX_WAIT_C_CC;
        }
      else
        {
          s->kex.state = SSH_TLS_KEX_WAIT_S_CC;
        }
    }

  return SSH_TLS_TRANS_OK;
}
