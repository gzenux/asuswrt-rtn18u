/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

void ssh_tls_send_hello_request(SshTlsProtocolState s)
{
  /* This message is not included in the final hash. */
  ssh_tls_make_hs_header_no_history(s, SSH_TLS_HS_HELLO_REQUEST, 0);
  /* No contents! */
  ssh_tls_flush(s);
}
