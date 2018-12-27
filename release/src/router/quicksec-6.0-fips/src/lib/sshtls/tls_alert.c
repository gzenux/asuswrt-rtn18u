/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshmalloc.h"

#define SSH_DEBUG_MODULE "SshTlsAlert"

typedef struct {
  int number;
  const char *name;
  const char *longdescr;
} SshTlsAlertDescription;

/* This copyright notice applies to the descriptive paragraphs below:

   ----------------------------------------------------------------------

   This document and translations of it may be copied and furnished to
   others, and derivative works that comment on or otherwise explain
   it or assist in its implementation may be prepared, copied,
   published and distributed, in whole or in part, without restriction
   of any kind, provided that the above copyright notice and this
   paragraph are included on all such copies and derivative works.
   However, this document itself may not be modified in any way, such
   as by removing the copyright notice or references to the Internet
   Society or other Internet organizations, except as needed for the
   purpose of developing Internet standards in which case the
   procedures for copyrights defined in the Internet Standards process
   must be followed, or as required to translate it into languages
   other than English.
   ----------------------------------------------------------------------

   */

static const SshTlsAlertDescription ssh_tls_alert_descriptions[] =
{
  { 0, "close_notify",
    "This message notifies the recipient that the sender will not send "
    "any more messages on this connection. The session becomes "
    "unresumable if any connection is terminated without proper "
    "close_notify messages with level equal to warning. " },

  { 10, "unexpected_message",
    "An inappropriate message was received. This alert is always fatal "
    "and should never be observed in communication between proper "
    "implementations." },

  { 20, "bad_record_mac",
    "This alert is returned if a record is received with an incorrect "
    "MAC. This message is always fatal." },

  { 21, "decryption_failed",
    "A TLSCiphertext decrypted in an invalid way: either it wasn`t an "
    "even multiple of the block length or its padding values, when "
    "checked, weren`t correct. This message is always fatal." },

  { 22, "record_overflow",
    "A TLSCiphertext record was received which had a length more than "
    "2^14+2048 bytes, or a record decrypted to a TLSCompressed record "
    "with more than 2^14+1024 bytes. This message is always fatal." },

  { 30, "decompression_failure",
    "The decompression function received improper input (e.g. data "
    "that would expand to excessive length). This message is always "
    "fatal." },

  { 40, "handshake_failure",
    "Reception of a handshake_failure alert message indicates that the "
    "sender was unable to negotiate an acceptable set of security "
    "parameters given the options available. This is a fatal error." },

  /* This has not been quoted. */
  { 41, "no_certificate",
    "The client informs that it has no certificate. This message is used "
    "in SSL 3.0 but not in TLS 1.0." },

  { 42, "bad_certificate",
    "A certificate was corrupt, contained signatures that did not "
    "verify correctly, etc." },

  { 43, "unsupported_certificate",
    "A certificate was of an unsupported type." },

  { 44, "certificate_revoked",
    "A certificate was revoked by its signer." },

  { 45, "certificate_expired",
    "A certificate has expired or is not currently valid." },

  { 46, "certificate_unknown",
    "Some other (unspecified) issue arose in processing the "
    "certificate, rendering it unacceptable." },

  { 47, "illegal_parameter",
    "A field in the handshake was out of range or inconsistent with "
    "other fields. This is always fatal." },

  { 48, "unknown_ca",
    "A valid certificate chain or partial chain was received, but the "
    "certificate was not accepted because the CA certificate could not "
    "be located or couldn`t be matched with a known, trusted CA.  This "
    "message is always fatal." },

  { 49, "access_denied",
    "A valid certificate was received, but when access control was "
    "applied, the sender decided not to proceed with negotiation. "
    "This message is always fatal." },

  { 50, "decode_error",
    "A message could not be decoded because some field was out of the "
    "specified range or the length of the message was incorrect. This "
    "message is always fatal." },

  { 51, "decrypt_error",
    "A handshake cryptographic operation failed, including being "
    "unable to correctly verify a signature, decrypt a key exchange, "
    "or validate a finished message." },

  { 60, "export_restriction",
    "A negotiation not in compliance with export restrictions was "
    "detected; for example, attempting to transfer a 1024 bit "
    "ephemeral RSA key for the RSA_EXPORT handshake method. This "
    "message is always fatal." },

  { 70, "protocol_version",
    "The protocol version the client has attempted to negotiate is "
    "recognized, but not supported. (For example, old protocol "
    "versions might be avoided for security reasons). This message is "
    "always fatal." },

  { 71, "insufficient_security",
    "Returned instead of handshake_failure when a negotiation has "
    "failed specifically because the server requires ciphers more "
    "secure than those supported by the client. This message is always "
    "fatal." },

  { 80, "internal_error",
    "An internal error unrelated to the peer or the correctness of the "
    "protocol makes it impossible to continue (such as a memory "
    "allocation failure). This message is always fatal." },

  { 90, "user_canceled",
    "This handshake is being canceled for some reason unrelated to a "
    "protocol failure. If the user cancels an operation after the "
    "handshake is complete, just closing the connection by sending a "
    "close_notify is more appropriate. This alert should be followed "
    "by a close_notify. This message is generally a warning." },

  { 100, "no_renegotiation",
    "Sent by the client in response to a hello request or by the "
    "server in response to a client hello after initial handshaking. "
    "Either of these would normally lead to renegotiation; when that "
    "is not appropriate, the recipient should respond with this alert; "
    "at that point, the original requester can decide whether to "
    "proceed with the connection. One case where this would be "
    "appropriate would be where a server has spawned a process to "
    "satisfy a request; the process might receive security parameters "
    "(key length, authentication, etc.) at startup and it might be "
    "difficult to communicate changes to these parameters after that "
    "point. This message is always a warning." }
};

#define SSH_TLS_NUM_ALERT_DESCRIPTIONS (sizeof(ssh_tls_alert_descriptions)/\
                                        sizeof(ssh_tls_alert_descriptions[0]))

/* Process that belongs to the alert protocol. */
int ssh_tls_alert_process(SshTlsProtocolState s, SshTlsHigherProtocol p)
{
  int length;
  int processed = 0;
  int level, number;
  unsigned char *ptr;
  int i;

  length = ssh_buffer_len(p->data);
  ptr = ssh_buffer_ptr(p->data);

  while (length >= 2)
    {
      level = ptr[0]; number = ptr[1];
      if (level != SSH_TLS_ALERT_WARNING &&
          level != SSH_TLS_ALERT_FATAL)
        {
          SSH_DEBUG(2, ("The alert message level %d is out of bounds.",
                        level));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_DECODE_ERROR);
          return -1;
        }

      for (i = 0; i < SSH_TLS_NUM_ALERT_DESCRIPTIONS; i++)
        {
          if (ssh_tls_alert_descriptions[i].number == number)
            {
              SSH_DEBUG(2, ("Got the %s alert message `%s'.",
                            level == SSH_TLS_ALERT_WARNING ?
                            "warning" : "FATAL",
                            ssh_tls_alert_descriptions[i].name));
              SSH_DEBUG(5, ("Explanation follows: \"%s\"",
                            ssh_tls_alert_descriptions[i].longdescr));

              if (level == SSH_TLS_ALERT_FATAL)
                {
                  switch (number)
                    {
                    case SSH_TLS_ALERT_CERTIFICATE_REVOKED:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_REMOTE_CERT_REVOKED);
                      break;

                    case SSH_TLS_ALERT_CERTIFICATE_EXPIRED:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_REMOTE_CERT_EXPIRED);
                      break;

                    case SSH_TLS_ALERT_CERTIFICATE_UNKNOWN:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_REMOTE_CERT_UNKNOWN);
                      break;

                    case SSH_TLS_ALERT_UNSUPPORTED_CERTIFICATE:
                      ssh_tls_immediate_kill(s,
                                         SSH_TLS_FAIL_REMOTE_CERT_UNSUPPORTED);
                      break;

                    case SSH_TLS_ALERT_BAD_CERTIFICATE:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_REMOTE_CERT_BAD);
                      break;

                    case SSH_TLS_ALERT_UNKNOWN_CA:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_REMOTE_CERT_CA);
                      break;

                    case SSH_TLS_ALERT_ACCESS_DENIED:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_REMOTE_DENY_ACCESS);
                      break;

                    case SSH_TLS_ALERT_INSUFFICIENT_SECURITY:
                      ssh_tls_immediate_kill(s,
                                   SSH_TLS_FAIL_REMOTE_INSUFFICIENT_SECURITY);
                      break;

                    case SSH_TLS_FAIL_HANDSHAKE_FAILURE:
                      ssh_tls_immediate_kill(s,
                                             SSH_TLS_FAIL_HANDSHAKE_FAILURE);
                      break;

                    default:
                      ssh_tls_immediate_kill(s, SSH_TLS_FAIL_REMOTE_BUG);
                      break;
                    }
                  return -1;
                }
              /* Correct message found so break the loop. */
              break;
            }
        }

#ifdef SSH_TLS_SSL_3_0_COMPAT
      if (number == SSH_TLS_ALERT_NO_CERTIFICATE)
        {
          if (s->protocol_version.minor != 0 ||
              s->protocol_version.major != 3)
            {
              SSH_DEBUG(5, ("Got the old no certificate alert for protocol "
                            "version different from SSL 3.0."));
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
              return -1;
            }

          if (!(s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED))
            {
              SSH_DEBUG(5, ("Got the no certificate alert but no certificate "
                            "was actually requested."));
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
              return -1;
            }

          SSH_DEBUG(5, ("The client has no certificate! :("));

          if (s->conf.flags & SSH_TLS_STRICTAUTH)
            {
              SSH_DEBUG(5, ("Client authentication is strictly required, "
                            "drop the connection."));
              ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_ACCESS_DENIED);
              return -1;
            }

          s->kex.flags ^= SSH_TLS_KEX_CLIENT_CERT_REQUESTED;
        }
#endif

      if (i == SSH_TLS_NUM_ALERT_DESCRIPTIONS)
        {
          /* Couldn't understand the message. */
          SSH_DEBUG(5, ("The alert message number `%d' is unknown.", number));
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_DECODE_ERROR);
          return -1;
        }

      if (number == SSH_TLS_ALERT_CLOSE_NOTIFY)
        {
          SSH_DEBUG(5, ("Got close notify."));
          s->flags |= SSH_TLS_FLAG_GOT_CLOSE_NOTIFY;

          if (!(s->flags & SSH_TLS_FLAG_SENT_CLOSE_NOTIFY))
            {
              SSH_DEBUG(5, ("Have not sent close notify yet, so "
                            "send it now."));
              ssh_tls_send_alert_message(s, SSH_TLS_ALERT_WARNING,
                                         SSH_TLS_ALERT_CLOSE_NOTIFY);
              s->flags |= SSH_TLS_FLAG_SENT_CLOSE_NOTIFY;
            }

          s->status = SSH_TLS_TERMINATED;

          /* Inform the application layer that EOF can be now read
             as the close notify has been received. */
          ssh_tls_ready_for_reading(s);
          ssh_tls_ready_for_writing(s);
        }

      processed += 2;
      ptr += 2;
      length -= 2;
    }
  return processed;
}

void ssh_tls_send_alert_message(SshTlsProtocolState s,
                                int level, int description)
{
  unsigned char *ptr;

  SSH_DEBUG(7, ("Sending an alert packet."));

  ssh_tls_start_building(s, SSH_TLS_CTYPE_ALERT);

  if (ssh_buffer_append_space(s->outgoing_raw_data, &ptr, 2) == SSH_BUFFER_OK)
    {
      ptr[0] = level;
      ptr[1] = description;
      s->built_len += 2;
    }
  else
    {
      ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }

  ssh_tls_flush(s);
}
