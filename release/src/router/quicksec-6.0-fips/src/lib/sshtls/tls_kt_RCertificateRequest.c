/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_read_server_certreq(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  if (type == SSH_TLS_HS_CERT_REQ)
    {
      Boolean rsa_sign_supported = FALSE;

      if (s->kex.flags & SSH_TLS_KEX_ANONYMOUS_SERVER)
        {
          FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
               ("Got client certificate request from an anonymous server!"));
        }

      s->kex.flags |= SSH_TLS_KEX_CLIENT_CERT_REQUESTED;

      /* Changed length check to 5 from 6 to make
         it work with openssl 0.9.7a */
      MIN_LENGTH(5);

      /* Check that rsa-sign(1) is supported. */
      {
        int l = data[0];

        if (l == 0) FAILMF;

        data++; data_len--;

        MIN_LENGTH(l + 2);

        while (l > 0)
          {

            if (data[0] == SSH_TLS_CERTTYPE_RSA_SIGN)
              rsa_sign_supported = TRUE;
            data++; data_len--;
            l--;
          }
      }

      /* Read the distinguished names. */
      {
        int l;
        MIN_LENGTH(2);
        l = SSH_GET_16BIT(data);
        data_len -= 2; data += 2;

        /* The packet must end after the names. */
        if (data_len != l) FAILMF;
        SSH_ASSERT(s->kex.encoded_ca_list == NULL);
        s->kex.encoded_ca_list = ssh_memdup(data, l);
        SSH_DEBUG_HEXDUMP(3, ("ENCODED CA LIST"), s->kex.encoded_ca_list, l);
      }

      if (rsa_sign_supported == FALSE)
        {
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Certificate requested only for types we do not understand."));
        }

      s->kex.state = SSH_TLS_KEX_WAIT_AUTH_DECISION;
      ssh_tls_call_app_hook(s, SSH_TLS_AUTH_REQUEST);

      return SSH_TLS_TRANS_OK;
    }

  s->kex.state = SSH_TLS_KEX_WAIT_S_HELLODONE;
  return SSH_TLS_TRANS_REPROCESS;
}
