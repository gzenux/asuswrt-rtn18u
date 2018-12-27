/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_write_client_hello(SshTlsProtocolState s)
{
  SshTlsCipherSuite tab[SSH_TLS_NUM_CIPHERSUITES];
  SshTlsCipherSuite *suites_to_send;
  SshTlsCipherSuiteDetailsStruct details;
  int number_suites;
  int contents_len;
  unsigned char tempbuf[2];
  int i;

  s->kex.flags |= SSH_TLS_KEX_NEW_SESSION; /* Initially. */

  if (s->conf.preferred_suites != NULL)
    {

      /* If a preference list has been given, check that the
         preferences are sound w.r.t. the protocol flags given in the
         configuration. */

      SshTlsCipherSuite *tmp;

      SSH_DEBUG(6, ("Got a preference list."));

      number_suites = 0;
      tmp = s->conf.preferred_suites;
      while (*tmp != SSH_TLS_NO_CIPHERSUITE)
        {
          ssh_tls_get_ciphersuite_details(*tmp, &details);
          if (details.crippled && (!(s->conf.flags & SSH_TLS_WEAKCIPHERS)))
            {
              return SSH_TLS_TRANS_FAILED;
            }
          if (details.cipher == SSH_TLS_CIPH_NULL &&
              (!(s->conf.flags & SSH_TLS_NULLCIPHER)))
            {
              return SSH_TLS_TRANS_FAILED;
            }
          tmp++; number_suites++;
        }
      suites_to_send = s->conf.preferred_suites;
    }
  else
    {
      /* Otherwise construct a list containing all those ciphersuites
         that are supported by our implementation and that can be used
         according to the protocol configuration flags. */

      number_suites = 0;

      for (i = SSH_TLS_RSA_WITH_NULL_MD5; i < SSH_TLS_MAX_CIPHERSUITE; i++)
        {
          ssh_tls_get_ciphersuite_details(i, &details);

          SSH_DEBUG(7, ("Check if suite %d can be supported.", i));

          if ((details.kex_method == SSH_TLS_UNKNOWN_SUITE)
               || !(ssh_tls_supported_suite(s->conf.flags,
                                            (SshTlsCipherSuite) i)))
             continue;

          SSH_DEBUG(7, ("Null? %d  Crippled? %d  RC2? %d  RSA? %d  "
                        "Nosign? %d",
                        (details.cipher == SSH_TLS_CIPH_NULL),
                        (details.crippled),
                        (details.cipher == SSH_TLS_CIPH_RC2),
                        (details.kex_method == SSH_TLS_KEX_RSA),
                        (details.signature_method == SSH_TLS_SIGN_NONE)));

          if ((details.cipher == SSH_TLS_CIPH_NULL &&
               (!(s->conf.flags & SSH_TLS_NULLCIPHER)))
              || (details.crippled && (!(s->conf.flags & SSH_TLS_WEAKCIPHERS)))
              || (details.cipher == SSH_TLS_CIPH_RC2)
              || (details.kex_method != SSH_TLS_KEX_RSA)
              || (details.signature_method != SSH_TLS_SIGN_NONE))
            continue;

          SSH_DEBUG(7, ("Adding the cipher suite %d.", i));

          tab[number_suites++] = i;
        }
      suites_to_send = tab;
    }

  /* Now we can calculate the length of the packet. */

  /* Protocol version 2 bytes, random value 32 bytes,
     session ID 1 + N bytes, ciphersuites list 2 bytes (length)
     plus number_suites * 2 bytes, and 2 bytes for the single
     compression method (no compression) we support. */

  contents_len = 2 + 32 + 1 + s->kex.id_len + 2 + number_suites * 2 + 2;

  /* Initialize the handshake history buffer now. */
  SSH_ASSERT(s->kex.handshake_history == NULL);
  s->kex.handshake_history = ssh_buffer_allocate();

  if (s->kex.handshake_history == NULL)
    return SSH_TLS_TRANS_FAILED;

  ssh_tls_make_hs_header(s, SSH_TLS_HS_CLIENT_HELLO, contents_len);

  /* Write the highest protocol version or that of a hopefully-resumed
     session. */

  tempbuf[0] = s->kex.client_version.major;
  tempbuf[1] = s->kex.client_version.minor;

  ssh_tls_add_to_kex_packet(s, tempbuf, 2);

  /* Write unix time. */
  SSH_PUT_32BIT(s->kex.client_random, (SshUInt32)ssh_time());

  /* Write 28 random bytes. */
  for (i = 4; i < 32; i++)
    {
      s->kex.client_random[i]
        = ssh_random_get_byte();
    }
  ssh_tls_add_to_kex_packet(s, s->kex.client_random, 32);

  /* Write the requested session identifier. */
  tempbuf[0] = s->kex.id_len;
  ssh_tls_add_to_kex_packet(s, &tempbuf[0], 1);
  if (s->kex.id_len > 0)
    {
      ssh_tls_add_to_kex_packet(s, s->kex.session_id, s->kex.id_len);
    }

  /* Write the cipher suites. */
  SSH_PUT_16BIT(tempbuf, number_suites * 2);
  ssh_tls_add_to_kex_packet(s, tempbuf, 2);

  for (i = 0; i < number_suites; i++)
    {
      SSH_PUT_16BIT(tempbuf, suites_to_send[i]);
      ssh_tls_add_to_kex_packet(s, tempbuf, 2);
    }

  /* And the compression method. */
  tempbuf[0] = 1;
  tempbuf[1] = 0; /* the null compression */
  ssh_tls_add_to_kex_packet(s, tempbuf, 2);

  s->kex.state = SSH_TLS_KEX_WAIT_S_HELLO;

  return SSH_TLS_TRANS_OK;
}
