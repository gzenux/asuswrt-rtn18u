/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_write_server_hellodone(SshTlsProtocolState s)
{
  SSH_DEBUG(6, ("Sending server hello done."));

  ssh_tls_make_hs_header(s, SSH_TLS_HS_SERVER_HELLO_DONE, 0);
  s->kex.state = SSH_TLS_KEX_WAIT_C_CERT;
  return SSH_TLS_TRANS_OK;
}
