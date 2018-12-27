/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_write_server_hello(SshTlsProtocolState s)
{
  int i;
  unsigned char tempbuf[2];

#ifdef SSH_TLS_EXTRAS
  if (s->extra.flags & SSH_TLS_EXTRA_UNRESPONSIVE)
    {
      s->kex.state = SSH_TLS_KEX_VOID;
      return SSH_TLS_TRANS_OK;
    }
#endif

  SSH_DEBUG(6, ("Sending the server hello message."));

  if ((s->kex.flags & SSH_TLS_KEX_NEW_SESSION) &&
      (s->conf.session_cache != NULL))
    {
      SSH_DEBUG(5, ("Creating a new session identifier."));

      /* Create an identifier for this session. */
      ssh_tls_create_session_id(s->conf.session_cache,
                                s->kex.session_id,
                                &(s->kex.id_len));
    }

  /* Size: server_version 2 bytes, random 32 bytes,
     session_id 1 + N bytes, cipher_suite 2 bytes,
     compression_method 1 byte. */

  /* This writes the handshake protocol header */
  ssh_tls_make_hs_header(s, SSH_TLS_HS_SERVER_HELLO,
                         2 + 32 + 1 + s->kex.id_len + 2 + 1);

  /* Write protocol identifier. At this point we have decided upon the
     protocol version. */
  tempbuf[0] = s->protocol_version.major;
  tempbuf[1] = s->protocol_version.minor;
  ssh_tls_add_to_kex_packet(s, tempbuf, 2);

  /* Write unix time. */
  SSH_PUT_32BIT(s->kex.server_random, (SshUInt32)ssh_time());

  /* Write 28 random bytes. */
  for (i = 4; i < 32; i++)
    {
      s->kex.server_random[i]
        = ssh_random_get_byte();
    }
  ssh_tls_add_to_kex_packet(s, s->kex.server_random, 32);

  /* Write the session ID, the cipher suite
     and the compression method. */
  tempbuf[0] = s->kex.id_len;
  ssh_tls_add_to_kex_packet(s, tempbuf, 1);

  if (s->kex.id_len > 0)
    {
      ssh_tls_add_to_kex_packet(s, s->kex.session_id, s->kex.id_len);
    }

  SSH_PUT_16BIT(&tempbuf[0], s->kex.cipher_suite);
  ssh_tls_add_to_kex_packet(s, tempbuf, 2);

  tempbuf[0] = 0; /* the null compression */

  ssh_tls_add_to_kex_packet(s, tempbuf, 1);

  /* If this a new session, the next thing is to send the server
     certificate. For a resumed session we just wait for the finished
     message now... And that's almost all about session caching. */
  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      s->kex.state = SSH_TLS_KEX_SEND_S_CERT;
    }
  else
    {
      s->kex.state = SSH_TLS_KEX_SEND_S_CC;
    }

  return SSH_TLS_TRANS_OK;
}
