/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
static void ssh_tls_write_change_cipher_finish(SshTlsProtocolState s)
{
  /* All outgoing crypto operations are complete, change cipher context. */
  if (!ssh_tls_change_cipher_context(s, TRUE))
    s->flags |= SSH_TLS_FLAG_DELETED;

  ssh_tls_async_continue(s);
  return;
}
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

SshTlsTransStatus ssh_tls_trans_write_change_cipher(SshTlsProtocolState s)
{
  ssh_tls_start_building(s, SSH_TLS_CTYPE_CHANGE_CIPHER);

  if (ssh_buffer_append(s->outgoing_raw_data, (unsigned char *)"\001", 1)
      == SSH_BUFFER_OK)
    s->built_len++;
  else
    return SSH_TLS_TRANS_FAILED;

  /* Must flush so that the coming change does not affect
     this packet. */
  ssh_tls_flush(s);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  /* Wait outgoing crypto operations to complete */
  if (s->conn.outgoing.ops_pending)
    {
      s->outgoing_all_complete_cb = ssh_tls_write_change_cipher_finish;
      s->kex.state = SSH_TLS_KEX_WAIT_OUT_CRYPTO_COMPLETION;
      s->kex.next_state = s->conf.is_server ?
        SSH_TLS_KEX_SEND_S_FINISHED:SSH_TLS_KEX_SEND_C_FINISHED;
      s->kex.alert = 0;
      s->kex.alert_text = NULL;
      ssh_tls_async_freeze(s);
      return SSH_TLS_TRANS_OK;
    }
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  /* Now change cipher context. */
  if (!ssh_tls_change_cipher_context(s, TRUE))
    return SSH_TLS_TRANS_FAILED;

  if (s->conf.is_server)
    s->kex.state = SSH_TLS_KEX_SEND_S_FINISHED;
  else
    s->kex.state = SSH_TLS_KEX_SEND_C_FINISHED;
  return SSH_TLS_TRANS_OK;
}
