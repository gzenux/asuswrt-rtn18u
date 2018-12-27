/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_read_change_cipher(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  /* The change cipher messages are actually processed in
     `ssh_tls_cc_process', see `tls_kex.c'. */
  FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
       ("Got a handshake message when waiting for a change cipher "
        "notification."));
}
