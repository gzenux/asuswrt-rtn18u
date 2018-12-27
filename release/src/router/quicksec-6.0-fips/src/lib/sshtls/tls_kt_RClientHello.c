/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_read_client_hello(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  int sessid_len;
  int cipher_suites;
  int compression_methods;
  int i;
  SshTlsCipherSuite        suite;
  SshTlsCipherSuiteDetailsStruct details;
  unsigned char degraded_major, degraded_minor;

  unsigned char *ptr;

  CHECKTYPE(SSH_TLS_HS_CLIENT_HELLO);

  /* Minimum length after the header has been stripped:
     client_version 2 bytes, random 32 bytes, session_id
     1 byte, cipher_suites 2 bytes, compression_methods 1 byte. */
  MIN_LENGTH(2 + 32 + 1 + 2 + 1);

  /* Remember the original client version. */
  s->kex.client_version.major = data[0];
  s->kex.client_version.minor = data[1];

  degraded_major = data[0];
  degraded_minor = data[1];

  /* Degrade the client version if necessary. */
  ssh_tls_degrade_version(s, &degraded_major, &degraded_minor);

  SSH_DEBUG(5, ("Client version %d.%d, degraded %d.%d, protocol %d.%d.",
                data[0], data[1], degraded_major, degraded_minor,
                s->protocol_version.major,
                s->protocol_version.minor));

  /* Check that the degraded version can be supported. */
  if (!(ssh_tls_supported_version(s, degraded_major, degraded_minor)))
    {
      FAIL(SSH_TLS_ALERT_PROTOCOL_VERSION,
           ("Unsupported protocol version %d.%d.",
            degraded_major,
            degraded_minor));
    }

  /* Now degraded_major . degraded_minor is the highest common
     version. Use it. */
  s->protocol_version.major = degraded_major;
  s->protocol_version.minor = degraded_minor;

  /* The client cannot send more messages before receiving the
     ServerHello packet, so the version number can be fixed now. */
  s->flags |= SSH_TLS_FLAG_VERSION_FIXED;

  /* Get the random value. */
  memcpy(s->kex.client_random, data + 2, 32);

  /* Show the unix time. */
#ifdef DEBUG_LIGHT
  {
    SshUInt32 client_time;
    struct SshCalendarTimeRec calendar_time;

    client_time = SSH_GET_32BIT(data + 2);

    ssh_calendar_time((SshTime)client_time,
                      &calendar_time,
                      TRUE);

    SSH_DEBUG(4, ("Client time: %04d/%02d/%02d %02d:%02d:%02d.",
                  (int)calendar_time.year,
                  (int)calendar_time.month + 1,
                  (int)calendar_time.monthday,
                  (int)calendar_time.hour,
                  (int)calendar_time.minute,
                  (int)calendar_time.second));
  }
#endif

  /* Get the session id. */

  ptr = data + 2 + 32;
  sessid_len = *ptr;

  SSH_DEBUG(6, ("Session identifier length %d bytes.", sessid_len));

  /* Let's look at the session identifier. */

  ptr += 1;

  s->kex.flags |= SSH_TLS_KEX_NEW_SESSION; /* Initially. */

  if (sessid_len > 0 && s->conf.session_cache != NULL
      && !(s->kex.flags & SSH_TLS_KEX_NO_CACHING))
    {
      SshTlsCachedSession session;

      session = ssh_tls_find_cached_session(s->conf.session_cache,
                                            ptr, sessid_len);
      if (session != NULL)
        {
          SSH_DEBUG(5, ("The client wants to reuse a session that we have "
                        "cached; do that."));

          memcpy(s->kex.master_secret,
                 session->master_secret, 48);
          s->kex.flags |= SSH_TLS_KEX_HAVE_MASTER_SECRET;
          s->kex.cipher_suite = session->cipher_suite;
          memcpy(s->kex.session_id, session->session_id,
                 session->id_len);
          s->kex.id_len = session->id_len;
          s->kex.peer_certs =
            ssh_tls_duplicate_ber_cert_chain(session->peer_certs);

          /* Drop the new session flag. */
          s->kex.flags &= ~SSH_TLS_KEX_NEW_SESSION;

          /* Check the protocol version!

             We should perhaps check (?) that the record layer was
             also initially using the same version, but this seems
             quite unnecessary as the version is now anyway that of
             the cached version, and it is trusted. */
          if (s->protocol_version.major != session->protocol_version.major ||
              s->protocol_version.minor != session->protocol_version.minor)
            {
              FAIL(SSH_TLS_ALERT_ILLEGAL_PARAMETER,
                   ("The client is trying to resume an old session but uses "
                    "different protocol version than that of the "
                    "cached session."));
            }

          /* We still proceed on to parse the rest of the packet to
             make sure it is correctly structured. However, the
             absence of the NEW_SESSION flag causes the parsed values
             to be discarded. */
        }
    }

  ptr += sessid_len;            /* Skip the ID no matter what. */

  if (ptr + 2 > data + data_len) FAILMF;

  cipher_suites = SSH_GET_16BIT(ptr);

  if (cipher_suites % 2 != 0)
    FAIL(SSH_TLS_ALERT_DECODE_ERROR,
         ("Cipher suite vector length is not a multiple of two."));

  cipher_suites /= 2;

  ptr += 2;

  SSH_DEBUG(6, ("%d cipher suites enumerated.", cipher_suites));

  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      s->kex.cipher_suite = SSH_TLS_CIPHERSUITE_NOT_AVAILABLE;
      s->kex.num_client_cipher_suites = 0;

      for (i = 0; i < cipher_suites; i++)
        {
          if (ptr + 2 > data + data_len) FAILMF;
          suite = SSH_GET_16BIT(ptr);
          ptr += 2;
          ssh_tls_get_ciphersuite_details(suite, &details);
          if (details.kex_method == SSH_TLS_UNKNOWN_SUITE)
            {
              SSH_DEBUG(6, ("Unknown cipher suite number %d (ignored).",
                            suite));
            }
          else
            {
              SSH_DEBUG(6, ("Client supports the cipher suite `%s'.",
                            ssh_tls_format_suite(suite)));
              SSH_ASSERT(s->kex.num_client_cipher_suites
                         < SSH_TLS_NUM_CIPHERSUITES);
              {
                int j;

                for (j = 0; j < s->kex.num_client_cipher_suites; j++)
                  {
                    if (s->kex.client_cipher_suites[j] == suite)
                      {
                        SSH_DEBUG(6, ("Multiply defined cipher suite, latter "
                                      "instance ignored."));
                        goto skip_over;
                      }
                  }
                s->kex.client_cipher_suites[s->kex.num_client_cipher_suites++]
                  = suite;

              skip_over:
                continue;
              }
            }
        }
    }
  else
    {
      ptr += cipher_suites * 2;
    }

  if (ptr >= data + data_len) FAILMF;

  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      /* At this point, sort the client's cipher suites if a preference
         list has been given. */

      if (s->conf.preferred_suites != NULL)
        {
          ssh_tls_sort_suites(s->kex.client_cipher_suites,
                              &(s->kex.num_client_cipher_suites),
                              s->conf.preferred_suites);
        }
    }

  compression_methods = *ptr;
  ptr++;

  SSH_DEBUG(6, ("%d compression methods enumerated.", compression_methods));
  {
    int support_no_compression = 0;

    for (i = 0; i < compression_methods; i++)
      {
        if (ptr >= data + data_len) FAILMF;
        SSH_DEBUG(6, ("Client supports the compression method %d.", *ptr));
        if (*ptr == 0)
          {
            support_no_compression = 1;
          }
        ptr++;
      }

    if (!support_no_compression)
      {
        FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
             ("`No compression' is not supported."));
      }
  }

  /* There can be extra data at the end of the ClientHello message.
     This is dictated by the standard. */
  if (ptr > data + data_len)
    FAILMF;

#ifdef SSHDIST_VALIDATOR
  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      return ssh_tls_get_own_certificates(s);
    }
  else                          /* Resumed session. */
    {
      s->kex.state = SSH_TLS_KEX_SEND_S_HELLO;
      return SSH_TLS_TRANS_OK;
    }
#else /* SSHDIST_VALIDATOR */
  /* When no SSHDIST_VALIDATOR is defined the server already has
     its certificates ready. */
  s->kex.state = SSH_TLS_KEX_SEND_S_HELLO;
  return ssh_tls_choose_suite(s);
#endif /* SSHDIST_VALIDATOR */
}
