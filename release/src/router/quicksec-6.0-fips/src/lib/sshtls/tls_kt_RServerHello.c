/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

SshTlsTransStatus ssh_tls_trans_read_server_hello(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  unsigned char *ptr;
  int sessid_len;
  int cipher_suite;
  int compression_method;

  CHECKTYPE(SSH_TLS_HS_SERVER_HELLO);

  /* Minimum length after the header has been stripped. */
  MIN_LENGTH(2 + 32 + 1 + 2 + 1);

  /* Check that the server has responded with a protocol version that
     we support and that it is not greater than that we sent. */
  SSH_ASSERT(s->protocol_version.major > 0);

  if (!(SSH_TLS_VERSION_LEQ(data[0], data[1],
                            s->kex.client_version.major,
                            s->kex.client_version.minor)))
    {
      FAIL(SSH_TLS_ALERT_PROTOCOL_VERSION,
           ("The server responded with too high a protocol version "
            "(%d.%d).", (int)data[0], (int)data[1]));
    }

  if (!(ssh_tls_supported_version(s, data[0], data[1])))
    {
      FAIL(SSH_TLS_ALERT_PROTOCOL_VERSION,
           ("Invalid server protocol version %d.%d.", data[0], data[1]));
    }

  /* Accept the version. */
  s->protocol_version.major = data[0];
  s->protocol_version.minor = data[1];

  s->flags |= SSH_TLS_FLAG_VERSION_FIXED;

  /* Get the random value. */
  memcpy(s->kex.server_random, data + 2, 32);

  /* Show the unix time. */
#ifdef DEBUG_LIGHT
  {
    SshUInt32 client_time;
    struct SshCalendarTimeRec calendar_time;

    client_time = SSH_GET_32BIT(data + 2);

    ssh_calendar_time((SshTime)client_time,
                      &calendar_time,
                      TRUE);

    SSH_DEBUG(4, ("Server time: %04d/%02d/%02d %02d:%02d:%02d.",
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

  ptr += 1;

  if (sessid_len > 0)
    {
      /* Check if the session identifier is the same that we
         requested. */
      if (sessid_len == s->kex.id_len &&
          !memcmp(s->kex.session_id, ptr, sessid_len))
        {
          SSH_DEBUG(6, ("Server is willing to resume the cached connection."));
          s->kex.flags &= ~SSH_TLS_KEX_NEW_SESSION;

          /* The master secret and cipher suite are already correctly
             in the kex state. Necessary to do so because otherwise
             the cached session could have disappeared from the cache
             meanwhile... */
        }

      /* If we do not have a session identifier, the session ID
         is a new one. Remember it so that caching works. */
      if (s->kex.id_len == 0 ||
          sessid_len != s->kex.id_len ||
          memcmp(s->kex.session_id, ptr, sessid_len))
        {
          /* Invalidate the cached entry if the server refused
           * to resume the session */
          if (s->kex.id_len != 0)
            {
              if (s->conf.session_cache != NULL)
                ssh_tls_invalidate_cached_session(s->conf.session_cache,
                                                  s->kex.session_id,
                                                  s->kex.id_len);
              if (s->kex.peer_certs)
                ssh_tls_free_cert_chain(s->kex.peer_certs);
            }

          s->kex.id_len = sessid_len;
          memcpy(s->kex.session_id, ptr, sessid_len);
        }
    }

  ptr += sessid_len;

  if (ptr + 2 > data + data_len) FAILMF;

  /* Get the cipher suite. */
  cipher_suite = SSH_GET_16BIT(ptr);

  ptr += 2;

  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      s->kex.cipher_suite = SSH_TLS_CIPHERSUITE_NOT_AVAILABLE;

      /* Check that it is supported. */
      if (s->conf.preferred_suites != NULL)
        {
          int i;
          for (i = 0; s->conf.preferred_suites[i] != SSH_TLS_NO_CIPHERSUITE;
               i++)
            {
              if (s->conf.preferred_suites[i] == cipher_suite)
                {
                  SSH_DEBUG(6, ("Server chose the preferred cipher suite #%d.",
                                i));
                  goto checked; /* a few lines below */
                }
            }
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("The cipher suite chosen by the server was not in the "
                "list of preferred suites."));
        }
    }
  else
    {
      if (cipher_suite != s->kex.cipher_suite)
        {
          /* The cached cipher suite and that in the packet do not match! */
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("The cipher suite in the server hello packet is different "
                "from that of the resumed session."));
        }
    }

checked:
  if (cipher_suite >= SSH_TLS_RSA_WITH_NULL_MD5 &&
      cipher_suite <= SSH_TLS_MAX_CIPHERSUITE)
    {
      SSH_DEBUG(5, ("Suite chosen: %s [%d].",
                    ssh_tls_format_suite(cipher_suite), cipher_suite));

      if (ssh_tls_supported_suite(s->conf.flags, cipher_suite))
        {
          s->kex.cipher_suite = cipher_suite;
        }
      else
        {
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("The chosen cipher suite is not supported. "
               "(Problem in the external server, because we did not "
               "list cipher suites we do not support.)"));
        }
    }
  else
    {
      FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
           ("Cipher suite out of bounds."));
    }

  /* Check that the NULL compression method is supported. */
  compression_method = *ptr;
  ptr++;

  if (compression_method != 0)
    {
      FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
           ("The chosen compression method is not the null compression."));
    }

  if (ptr != data + data_len) FAILMF;

  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      s->kex.state = SSH_TLS_KEX_WAIT_S_CERT;
    }
  else
    {
      /* Proceed immediately to the cipher change message now that
         we are resuming a new session. */
      s->kex.state = SSH_TLS_KEX_WAIT_S_CC;
    }

  return SSH_TLS_TRANS_OK;
}
