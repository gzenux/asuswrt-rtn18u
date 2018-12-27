/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"

#define SSH_DEBUG_MODULE "SshTlsKexTrans"

/* These messages occur many times in the code, so put them into
   variables so that the compiler won't replicate them in any case. */
const SshCharPtr ssh_tls_minlength_str =
"Contents too short (min. length %d bytes, got %d).";

const SshCharPtr ssh_tls_checktype_str =
"Invalid handshake message type %d (expected %d).";

const SshCharPtr ssh_tls_malformed_str =
"Malformed packet.";

/* Add `length' bytes of data starting from `data' to the buffer that
   is used to calculate the key exchange verification hashes. This
   increases also `built_len' accordingly. */
void ssh_tls_add_to_kex_history(SshTlsProtocolState s,
                                const unsigned char *data,
                                int length)
{
  SSH_ASSERT(s->kex.handshake_history != NULL);

  if (ssh_buffer_append(s->kex.handshake_history, data, length) !=
      SSH_BUFFER_OK)
    {
      ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
      return;
    }

  SSH_DEBUG_HEXDUMP(8, ("Added to handshake history: (local)"), data, length);
}

/* This appends `data' to the outgoing raw data and also adds it to
   the key exchange hashes.

   This function also modifies `built_len'. */
void ssh_tls_add_to_kex_packet(SshTlsProtocolState s,
                               const unsigned char *data,
                               int length)
{
  if (ssh_buffer_append(s->outgoing_raw_data, data, length) == SSH_BUFFER_OK)
    {
      s->built_len += length;
      ssh_tls_add_to_kex_history(s, data, length);
    }
}

/* Create a key exchange packet header (4 bytes). `built_len' is
   inreased accordingly. */
static void
make_hs_header(SshTlsProtocolState s,
               SshTlsHandshakeType type,
               int length, Boolean add_to_history)
{
  unsigned char data[4];

  SSH_ASSERT(length >= 0);
  SSH_ASSERT(length < (1 << 24));
  ssh_tls_start_building(s, SSH_TLS_CTYPE_HANDSHAKE);
  data[0] = (unsigned char)type;
  data[1] = (unsigned char)((length >> 16) & 0xff);
  data[2] = (unsigned char)((length >> 8) & 0xff);
  data[3] = (unsigned char)(length & 0xff);
  if (add_to_history)
    {
      ssh_tls_add_to_kex_packet(s, data, 4);
    }
  else
    {
      if (ssh_buffer_append(s->outgoing_raw_data, data, 4) == SSH_BUFFER_OK)
        {
          s->built_len += 4;
        }
      else
        {
          ssh_tls_immediate_kill(s, SSH_TLS_ALERT_INTERNAL_ERROR);
          return;
        }
    }
}

void ssh_tls_make_hs_header(SshTlsProtocolState s,
                            SshTlsHandshakeType type,
                            int length)
{
  make_hs_header(s, type, length, TRUE);
}

void ssh_tls_make_hs_header_no_history(SshTlsProtocolState s,
                                       SshTlsHandshakeType type,
                                       int length)
{
  make_hs_header(s, type, length, FALSE);
}

/* Cache the current session context when the Finished messages
   have been sent and received. */
void ssh_tls_cache_current_session(SshTlsProtocolState s)
{
  if (s->conf.session_cache != NULL &&
      s->kex.id_len > 0 &&
      s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      SSH_DEBUG(6, ("Caching a security context."));

      ssh_tls_cache_session(s->conf.session_cache,
                            &s->protocol_version,
                            s->kex.session_id, s->kex.id_len,
                            s->kex.master_secret,
                            s->kex.cipher_suite,
                            s->kex.peer_certs);

      if (s->conf.group_name != NULL)
        {
          SSH_DEBUG(6, ("Associating the context with the group `%s'.",
                        s->conf.group_name));

          ssh_tls_associate_with_group(s->conf.session_cache,
                                       s->kex.session_id,
                                       s->kex.id_len,
                                       s->conf.group_name);
        }
    }
}

/* This will be called when the key exchange has been succesfully
   finished. */
void ssh_tls_kex_finished(SshTlsProtocolState s)
{
  s->kex.state = SSH_TLS_KEX_CLEAR;

  if (s->status == SSH_TLS_STARTING_UP) s->status = SSH_TLS_READY;

  ssh_tls_cancel_kex_timeout(s);

  if (s->kex.flags & SSH_TLS_KEX_NEW_SESSION)
    {
      s->kex.flags |= SSH_TLS_KEX_VIRGIN_AFTER_FULL_REKEY;
      ssh_tls_cache_current_session(s);
      s->stats.num_key_exchanges++;
      ssh_tls_reset_rekeying_counters(s, TRUE);
      ssh_tls_call_app_hook(s, SSH_TLS_NEGOTIATED);
    }
  else
    {
      s->kex.flags |= SSH_TLS_KEX_VIRGIN_AFTER_FAST_REKEY;
      s->stats.num_context_changes++;
      ssh_tls_reset_rekeying_counters(s, FALSE);
      ssh_tls_call_app_hook(s, SSH_TLS_RENEGOTIATED);
    }

  ssh_tls_clear_kex_state(s);

  s->flags |= SSH_TLS_FLAG_INITIAL_KEX_DONE;

  SSH_DEBUG(6, ("Key exchange finished, status = %d.", s->status));

  if (s->flags & SSH_TLS_FLAG_FROZEN) return;

  if (s->status == SSH_TLS_READY)
    /* We are now ready for writing in any case. */
    ssh_tls_ready_for_writing(s);
}

#ifdef SSHDIST_VALIDATOR

void ssh_tls_cert_verify_callback(void *context,
                                  SshCMSearchInfo info,
                                  SshCMCertList list)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  if (list != NULL)
    ssh_cm_cert_list_free(s->conf.cert_manager, list);

  /* Get a local copy of the info structure. */
  memcpy(&(s->kex.cm_info), info, sizeof(s->kex.cm_info));
  s->kex.flags |= SSH_TLS_KEX_CM_INFO_VALID;

  if (info->status != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(5, ("Certificate manager returned non-ok status %d when "
                    "trying to verify the server certificate chain.",
                    info->status));
    }
  else
    {
      SSH_DEBUG(5, ("Certificate verified."));
      /* Set the flag to denote succesful verification. */

      s->kex.flags |=
        ( SSH_TLS_KEX_CERT_VERIFIED | SSH_TLS_KEX_CERT_VERIFIED_CM );
    }

  /* Then go on! */
  ssh_tls_async_continue(s);
}

Boolean ssh_tls_verify_certificate(SshTlsProtocolState s, int id)
{
  SshCMStatus status;
  SshCertDBKey *keylist = NULL;
  SshCMSearchConstraints search = ssh_cm_search_allocate();

  SSH_DEBUG(5, ("Cache id is %d.\n", id));

  if (search == NULL)
    return FALSE;

  if (!ssh_cm_key_set_cache_id(&keylist, id))
    {
      ssh_cm_search_free(search);
      return FALSE;
    }

  SSH_ASSERT(keylist != NULL);

  ssh_cm_search_set_keys(search, keylist);
  if (s->conf.trusted_set_peer_validation)
    ssh_cm_search_set_trusted_set(search, s->conf.trusted_set_peer_validation);

  ssh_tls_async_freeze(s);
  status = ssh_cm_find(s->conf.cert_manager,
                       search,
                       ssh_tls_cert_verify_callback,
                       s);

  if (status != SSH_CM_STATUS_OK && status != SSH_CM_STATUS_SEARCHING)
      return FALSE;

  return TRUE;
}
#endif /* SSHDIST_VALIDATOR */

/*

   READ server's Certificate message.

   Executed by clients to parse the server's certificate list.

   This transition CAN SUSPEND.

   */

/* Called by the server, choose the cipher suite to use from the list
   of suites presented by client. That is, from the array
   s->kex.client_cipher_suites[].

   This either writes a valid, supported ciphersuite to
   s->kex.cipher_suite and returns SSH_TLS_TRANS_OK, write
   SSH_TLS_CIPHERSUITE_NOT_AVAILABLE to s->kex.cipher_suite and
   returns SSH_TLS_TRANS_FAILED. */
SshTlsTransStatus ssh_tls_choose_suite(SshTlsProtocolState s)
{
  int i;
  SshTlsCipherSuiteDetailsStruct details;

  SSH_DEBUG(6, ("Choosing the suite to use..."));

  for (i = 0; i < s->kex.num_client_cipher_suites; i++)
    {
      ssh_tls_get_ciphersuite_details(s->kex.client_cipher_suites[i],
                                      &details);
      SSH_DEBUG(6, ("Considering the suite `%s'.",
                    ssh_tls_format_suite(s->kex.client_cipher_suites[i])));

#ifdef SSHDIST_VALIDATOR
      if (details.kex_method != SSH_TLS_KEX_DH_ANON
          && (s->conf.cert_manager == NULL
              || s->conf.private_key == NULL
              || s->kex.own_certificate_list == NULL))
        {
          SSH_DEBUG(6, ("The key exchange is not anonymous, "
                        "and we don't have a certificate manager, "
                        "a private key and an own certificate chain."));
          continue;
        }
#else /* SSHDIST_VALIDATOR */
      if (details.kex_method != SSH_TLS_KEX_DH_ANON
          && (s->conf.private_key == NULL || s->kex.own_certs == NULL))
        {
          SSH_DEBUG(6, ("The key exchange is not anonymous, "
                        "and we don't have "
                        "a private key and an own certificate chain."));
          continue;
        }
#endif /* SSHDIST_VALIDATOR */

      if (!ssh_tls_supported_suite(s->conf.flags,
                                   s->kex.client_cipher_suites[i]))
        continue;

      s->kex.cipher_suite = s->kex.client_cipher_suites[i];
      SSH_DEBUG(6, ("Suite %d accepted.", s->kex.cipher_suite));

      /* Set the anonymous server flag on if we are using
         an anonymous key exchange method. */
      if (details.kex_method == SSH_TLS_KEX_DH_ANON)
        {
          s->kex.flags |= SSH_TLS_KEX_ANONYMOUS_SERVER;
        }
      break;
    }

  if (s->kex.cipher_suite == SSH_TLS_CIPHERSUITE_NOT_AVAILABLE)
    {
      SSH_DEBUG(6, ("No cipher suite found."));
      ssh_tls_send_alert_message(s, SSH_TLS_ALERT_FATAL,
                                 SSH_TLS_ALERT_HANDSHAKE_FAILURE);
      return SSH_TLS_TRANS_FAILED;
    }

  return SSH_TLS_TRANS_OK;
}

#ifdef SSHDIST_VALIDATOR

/* This is a callback that will be called from the certificate
   manager. The callback is given to the CMI in
   ssh_tls_get_own_certificates(). */
void ssh_tls_got_own_certificates(void *context,
                                  SshCMSearchInfo info,
                                  SshCMCertList list)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  if (info->status != SSH_CM_STATUS_OK)
    {
      SSH_DEBUG(5, ("Certificate manager returned non-ok status %d.",
                    info->status));
      if (list != NULL)
        {
          ssh_cm_cert_list_free(s->conf.cert_manager, list);
        }
    }
  else
    {
      SSH_DEBUG(5, ("Ok, got certificate list."));
      s->kex.own_certificate_list = list;
    }

  /* Then continue. */
  ssh_tls_async_continue(s);
}

SshTlsTransStatus ssh_tls_get_own_certificates(SshTlsProtocolState s)
{
  SshCMStatus status;

  SshCMSearchConstraints search_cert;
  SshPublicKey pub_key;
  SshCertDBKey *keys = NULL;

  SSH_DEBUG(5, ("Starting to fetch own certificates."));
  s->kex.state = SSH_TLS_KEX_WAIT_CM_OWN_CERTS;

  if (s->conf.cert_manager == NULL)
    {
      SSH_DEBUG(5, ("Cannot find local certificates because there is no "
                    "certificate manager!"));
      return SSH_TLS_TRANS_OK;
    }

  search_cert = ssh_cm_search_allocate();

  if (search_cert == NULL)
    return SSH_TLS_TRANS_FAILED;

  if (s->conf.id_data)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Identity set for private key, using is as a certificate "
                 "search key."));

      if (!ssh_cm_key_set_dn(&keys, s->conf.id_data, s->conf.id_data_size))
        {
          ssh_cm_search_free(search_cert);
          FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
               ("ssh_cm_key_set_dn failed."));
        }
    }
  else
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Trying to derive public key from private key to be used "
                 "as a certificate search key."));

      SSH_ASSERT(s->conf.private_key != NULL);

      if (ssh_private_key_derive_public_key(s->conf.private_key, &pub_key)
          != SSH_CRYPTO_OK)
        {
          ssh_cm_search_free(search_cert);
          FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
               ("Couldn't derive the public key."));
        }


      if (!ssh_cm_key_set_public_key(&keys, pub_key))
        {
          ssh_cm_search_free(search_cert);
          ssh_public_key_free(pub_key);
          FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
               ("ssh_cm_key_set_public_key failed."));
        }
      ssh_public_key_free(pub_key);
    }

  ssh_cm_search_set_keys(search_cert, keys);

  {
    SshBerTimeStruct before, after;

    ssh_ber_time_set_from_unix_time(&before, ssh_time());
    ssh_ber_time_set_from_unix_time(&after,  ssh_time()+5);

    ssh_cm_search_set_time(search_cert, &before, &after);
  }

  /* Get the cert chain upto a trusted root...*/
  ssh_cm_search_set_until_root(search_cert);

  /* ...which is in the trusted_set_own_root, if the application
     has explicitly configured one. If it hasn't, any trusted
     root will terminate the chain which will get sent to the client. */
  if (s->conf.trusted_set_own_root)
    ssh_cm_search_set_trusted_set(search_cert, s->conf.trusted_set_own_root);

  /* It is not really our business to validate our own cert, and it
     might trigger external LDAP/OCSP queries, so let's disable
     revocation checks. */
  ssh_cm_search_check_revocation(search_cert, FALSE);

  /* Asynchronous operation starts! Set the next state already. */
  ssh_tls_async_freeze(s);

  status = ssh_cm_find(s->conf.cert_manager,
                       search_cert,
                       ssh_tls_got_own_certificates,
                       (void *)s);

  if (status != SSH_CM_STATUS_OK && status != SSH_CM_STATUS_SEARCHING)
    {
      FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
           ("ssh_cm_find returned a bad status."));
    }

  return SSH_TLS_TRANS_OK;
}

#endif /* SSHDIST_VALIDATOR */

static const char reject_str[] = "Cannot support the cipher suite `%s': %s.";

#define REJECT(x) do { \
SSH_DEBUG(5, (reject_str, buf, x)); \
return FALSE; } while (0)

Boolean ssh_tls_supported_suite(SshUInt32 s_conf_flags,
                                SshTlsCipherSuite suite)
{
  SshTlsCipherSuiteDetailsStruct details;
#ifdef DEBUG_LIGHT
  const char *buf = ssh_tls_format_suite(suite);
#endif

  ssh_tls_get_ciphersuite_details(suite, &details);

  if (details.kex_method != SSH_TLS_KEX_RSA)
    REJECT("non-RSA key exchange not supported");

  if (details.crippled && !(s_conf_flags & SSH_TLS_WEAKCIPHERS))
    REJECT("crippled cipher disabled in configuration");

  switch (details.cipher)
    {
    case SSH_TLS_CIPH_RC4:
      if (!(ssh_cipher_supported("arcfour")))
        REJECT("RC4 cipher not supported.");
      break;

    case SSH_TLS_CIPH_AES128:
    case SSH_TLS_CIPH_AES256:
      if (!(ssh_cipher_supported("aes-cbc")))
        REJECT("AES cipher not supported.");
      break;

    case SSH_TLS_CIPH_3DES:
      if (!(ssh_cipher_supported("3des-cbc")))
        REJECT("3DES cipher not supported.");
      break;

    case SSH_TLS_CIPH_IDEA:
      if (!(ssh_cipher_supported("idea-cbc")))
        REJECT("IDEA cipher not supported.");
      break;

    case SSH_TLS_CIPH_DES:
      if (!(ssh_cipher_supported("des-cbc")))
        REJECT("DES cipher not supported.");
      if (!(s_conf_flags & SSH_TLS_SINGLEDES))
        REJECT("single DES cipher not supported in configuration");
      break;

    case SSH_TLS_CIPH_RC2:
      if (!(ssh_cipher_supported("rc2-cbc")))
        REJECT("RC2 cipher not supported.");
      break;

    case SSH_TLS_CIPH_NULL:
      if (!(s_conf_flags & SSH_TLS_NULLCIPHER))
        REJECT("NULL cipher disabled in configuration");
      break;

    default:
      REJECT("cipher unknown");
    }

  return TRUE;
}

#undef REJECT
