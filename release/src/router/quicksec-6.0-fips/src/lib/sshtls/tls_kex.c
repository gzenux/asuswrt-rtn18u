/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshtimeouts.h"
#include "sshmalloc.h"
#include "sshbuffer.h"
#include "tls_accel.h"

#define SSH_DEBUG_MODULE "SshTlsKex"

const SshTlsKexStateInfo ssh_tls_kex_state_info[SSH_TLS_NUM_KEX_STATES] =
{
  {SSH_TLS_KEX_CLEAR, "clear", FALSE, NULL},

  /* Client path */

  {SSH_TLS_KEX_SEND_C_HELLO, "send ClientHello",
    FALSE, ssh_tls_trans_write_client_hello},

  {SSH_TLS_KEX_WAIT_S_HELLO, "wait for ServerHello",
    TRUE, ssh_tls_trans_read_server_hello},

  {SSH_TLS_KEX_WAIT_S_CERT, "wait for server's Certificate",
    TRUE, ssh_tls_trans_read_server_cert},

  {SSH_TLS_KEX_WAIT_S_KEX, "wait for ServerKeyExchange",
    TRUE, ssh_tls_trans_read_server_kex},

  {SSH_TLS_KEX_WAIT_S_CERTREQ, "wait for server's CertificateRequest",
    TRUE, ssh_tls_trans_read_server_certreq},

  {SSH_TLS_KEX_WAIT_S_HELLODONE, "wait for ServerHelloDone",
    TRUE, ssh_tls_trans_read_server_hellodone},

  {SSH_TLS_KEX_SEND_C_CERT, "send client's Certificate",
    FALSE, ssh_tls_trans_write_client_cert},

  {SSH_TLS_KEX_SEND_C_KEX, "send ClientKeyExchange",
    FALSE, ssh_tls_trans_write_client_kex},

  {SSH_TLS_KEX_SEND_C_CERTVERIFY, "send client's CertificateVerify",
    FALSE, ssh_tls_trans_write_client_certverify},

  {SSH_TLS_KEX_SEND_C_CC, "send client's ChangeCipherSpec",
    FALSE, ssh_tls_trans_write_change_cipher},

  {SSH_TLS_KEX_SEND_C_FINISHED, "send client's Finished",
    FALSE, ssh_tls_trans_write_finished},

  {SSH_TLS_KEX_WAIT_S_CC, "wait for server's ChangeCipherSpec",
    TRUE, ssh_tls_trans_read_change_cipher},

  {SSH_TLS_KEX_WAIT_S_FINISHED, "wait for server's Finished",
    TRUE, ssh_tls_trans_read_finished},

  /* Server path */

  {SSH_TLS_KEX_WAIT_C_HELLO, "wait for ClientHello",
    TRUE, ssh_tls_trans_read_client_hello},

  {SSH_TLS_KEX_SEND_S_HELLO, "send ServerHello",
    FALSE, ssh_tls_trans_write_server_hello},

  {SSH_TLS_KEX_SEND_S_CERT, "send server's Certificate",
    FALSE, ssh_tls_trans_write_server_cert},

  {SSH_TLS_KEX_SEND_S_KEX, "send ServerKeyExchange",
    FALSE, ssh_tls_trans_write_server_kex},

  {SSH_TLS_KEX_SEND_S_CERTREQ, "send server's CertificateRequest",
    FALSE, ssh_tls_trans_write_server_certreq},

  {SSH_TLS_KEX_SEND_S_HELLODONE, "send ServerHelloDone",
    FALSE, ssh_tls_trans_write_server_hellodone},

  {SSH_TLS_KEX_WAIT_C_CERT, "wait for client's Certificate",
    TRUE, ssh_tls_trans_read_client_cert},

  {SSH_TLS_KEX_WAIT_C_KEX, "wait for ClientKeyExchange",
    TRUE, ssh_tls_trans_read_client_kex},

  {SSH_TLS_KEX_WAIT_C_CERTVERIFY, "wait for client's CertificateVerify",
    TRUE, ssh_tls_trans_read_client_certverify},

  {SSH_TLS_KEX_WAIT_C_CC, "wait for client's ChangeCipherSpec",
    TRUE, ssh_tls_trans_read_change_cipher},

  {SSH_TLS_KEX_WAIT_C_FINISHED, "wait for client's Finished",
    TRUE, ssh_tls_trans_read_finished},

  {SSH_TLS_KEX_SEND_S_CC, "send server's ChangeCipherSpec",
    FALSE, ssh_tls_trans_write_change_cipher},

  {SSH_TLS_KEX_SEND_S_FINISHED, "send server's Finished",
    FALSE, ssh_tls_trans_write_finished},

  /* Continuations */

  {SSH_TLS_KEX_WAIT_CM_CERT_VERIFY, "wait for CM to verify the peer certs",
    FALSE, ssh_tls_trans_cont_cert_verify},

  {SSH_TLS_KEX_WAIT_APP_CERT_DECIDE, "wait for app to decide the peer certs",
    FALSE, ssh_tls_trans_cont_cert_decide},

  {SSH_TLS_KEX_WAIT_CM_OWN_CERTS, "wait for CM to get our own certs",
    FALSE, ssh_tls_trans_cont_got_own_certs},

  {SSH_TLS_KEX_WAIT_AUTH_DECISION, "wait app to decide if to authenticate",
    FALSE, ssh_tls_trans_cont_auth_decide},

  {SSH_TLS_KEX_WAIT_KEYOP_COMPLETION, "wait for async private key operation",
    FALSE, ssh_tls_trans_cont_keyop_completion},

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  {SSH_TLS_KEX_WAIT_OUT_CRYPTO_COMPLETION, "wait out bulk crypto completion",
    FALSE, ssh_tls_trans_cont_out_crypto_completion},
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  /* Test states */

  {SSH_TLS_KEX_VOID, "do nothing (for testing)", FALSE, NULL},
};

void ssh_tls_initialize_new_kex(SshTlsProtocolState s)
{
  SshTlsKexState *k = &(s->kex);

  if (s->conf.is_server)
    k->state = SSH_TLS_KEX_S_INITIAL;
  else
    k->state = SSH_TLS_KEX_C_INITIAL;

  k->num_client_cipher_suites = 0;

  SSH_ASSERT(k->encoded_ca_list == NULL);

  SSH_ASSERT(k->handshake_history    == NULL);
  SSH_ASSERT(k->server_temporary_key == NULL);
  SSH_ASSERT(k->her_public_key    == NULL);

  if (s->conf.is_server)
    k->id_len = 0;              /* This is always the correct thing to do. */

  /* Do not know yet whether or not a certificate chain will be got. */
  k->query_status = SSH_TLS_CERT_KEX_IN_PROGRESS;

  /* Schedule timeout. */
  ssh_tls_install_kex_timeout(s);
}

Boolean ssh_tls_initialize_kex(SshTlsProtocolState s)
{
  SshTlsKexState *k = &(s->kex);

  k->flags = SSH_TLS_KEX_INITIAL_FLAGS;
  k->cipher_suite = SSH_TLS_CIPHERSUITE_NOT_AVAILABLE;

#ifdef SSHDIST_VALIDATOR
  k->own_certificate_list = NULL;
#else /* SSHDIST_VALIDATOR */
  k->own_certs = ssh_tls_duplicate_ber_cert_chain(s->conf.own_certs);
#endif /* SSHDIST_VALIDATOR */

  k->handshake_history = NULL;
  k->temporary_private_key = NULL;
  k->locked_temporary_key = NULL;
  k->server_temporary_key = NULL;
  k->her_public_key = NULL;
  k->peer_certs = NULL;
  k->id_len = 0;
  k->encoded_ca_list = NULL;

  ssh_tls_initialize_new_kex(s);

  /* Set the rekeying limits. */
  k->fast_rekey_data_limit = s->conf.fast_rekey_bytes;
  k->full_rekey_data_limit = s->conf.full_rekey_bytes;

  /* Get the temporary key object if it is available. */
  if (s->conf.temporary_key != NULL)
    {
      ssh_tls_lock_temporary_key(s->conf.temporary_key);
      k->locked_temporary_key = s->conf.temporary_key;

      if (s->conf.temporary_key->regeneration_interval <=
          s->conf.key_exchange_timeout)
        {
          SSH_DEBUG(SSH_D_ERROR,
                    ("The temporary key must have longer regeneration "
                     "interval than the key exchange timeout in "
                     "the TLS configuration."));
          return FALSE;
        }
    }

  if (!s->conf.is_server)
    {
      /* for client highest configured version will be taken */
      k->client_version.major = 3;
      k->client_version.minor = 0;
      if (s->conf.flags & SSH_TLS_TLS)
        k->client_version.minor = 1;
      if (s->conf.flags & SSH_TLS_TLS1_1)
        k->client_version.minor = 2;
    }

  return TRUE;
}

Boolean ssh_tls_kex_dispatch(SshTlsProtocolState s,
                             SshTlsHandshakeType type,
                             unsigned char *data,
                             int data_len)
{
  const SshTlsKexStateInfo *kexinfo;
  SshTlsTransStatus r;

reprocess:
  if (s->flags & SSH_TLS_FLAG_FROZEN)
    {
      SSH_ASSERT(data == NULL);
      return TRUE;
    }

  if (s->kex.flags & SSH_TLS_KEX_REJECT_NEW_CONNECTION_REQUEST)
    {
      ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_USER_CANCELED);
      return FALSE;
    }

  kexinfo = &(ssh_tls_kex_state_info[s->kex.state]);

  SSH_DEBUG(5, ("Key exchange dispatch: protocol version=%d.%d%s, "
                "class=%s, state=%s (%d), "
                "anon server=%s, "
                "client cert=%s, %s associated data (length %d), "
                "waiting=%s.",
                s->protocol_version.major, s->protocol_version.minor,
                (s->flags & SSH_TLS_FLAG_VERSION_FIXED) ?
                "" : " (tentative)",
                s->conf.is_server ? "server" : "client",
                kexinfo->description,
                s->kex.state,
                (s->kex.flags & SSH_TLS_KEX_ANONYMOUS_SERVER) ? "yes" : "no",
                (s->kex.flags & SSH_TLS_KEX_CLIENT_CERT_REQUESTED)
                ? "yes" : "no",
                (data == NULL) ? "no" : "has",
                (data == NULL) ? 0 : data_len,
                kexinfo->waiting ? "yes" : "no"));

  if (kexinfo->waiting)
    {
      SshTlsReadTransition trans;

      if (data == NULL)
        {
          SSH_DEBUG(5, ("Did not got a packet, so can't do anything."));
          return TRUE;
        }

      trans = (SshTlsReadTransition)(kexinfo->trans);
      r = (* trans)(s, type, data, data_len);

      switch (r)
        {
        case SSH_TLS_TRANS_OK:
          SSH_DEBUG(6, ("Transition ok, was read transition, return TRUE "
                        "and hope we will be revived again..."));
          return TRUE;

        case SSH_TLS_TRANS_FAILED:
          SSH_DEBUG(6, ("Transition failed."));
          return FALSE;

        case SSH_TLS_TRANS_REPROCESS:
          SSH_DEBUG(6, ("Packet must be reprocessed."));
          goto reprocess;

        default:
          SSH_NOTREACHED;
        }
    }

  /* kexinfo->waiting == FALSE */
  {
    SshTlsWriteTransition trans = (SshTlsWriteTransition)(kexinfo->trans);

    /* There might be no transition, for SSH_TLS_KEX_CLEAR and
       SSH_TLS_KEX_VOID (the latter is a testing state). */
    if (trans == NULL_FNPTR)
      return TRUE;

    r = (* trans)(s);

    switch (r)
      {
      case SSH_TLS_TRANS_OK:
      case SSH_TLS_TRANS_REPROCESS:
        SSH_DEBUG(6, ("Transition ok or reprocess, redo."));
        goto reprocess;

      case SSH_TLS_TRANS_FAILED:
        SSH_DEBUG(6, ("Transition failed."));
        return FALSE;

      default:
        SSH_NOTREACHED;
      }
  }

  /* not actually reached */
  SSH_NOTREACHED;
  return FALSE;
}

int ssh_tls_kex_process(SshTlsProtocolState s, SshTlsHigherProtocol p)
{
  int l;
  unsigned char *ptr;
  SshTlsHandshakeType type;
  int packet_len;
  int processed = 0;

  l = ssh_buffer_len(p->data);
  ptr = ssh_buffer_ptr(p->data);

redo:
  SSH_DEBUG(7, ("%d bytes of data in the handshake protocol's buffer.",
                l));

  if (s->flags & SSH_TLS_FLAG_FROZEN)
    {
      SSH_DEBUG(7, ("Protocol frozen so stop immediately."));
      return processed;
    }

  if (l < 4) /* no header present */
    return processed;

  type = *ptr;
  packet_len = (ptr[1] << 16) + (ptr[2] << 8) + ptr[3];

  if (packet_len > l - 4) /* packet not fully received */
    {
      SSH_DEBUG(7, ("Packet only partially received (%d bytes of %d + 4).",
                    l, packet_len));
      return 0;
    }

  /* Initialize the history if this is a client hello message. */
  if (type == SSH_TLS_HS_CLIENT_HELLO)
    {
      if (s->kex.state == SSH_TLS_KEX_CLEAR &&
          s->conf.is_server)
        {
          SSH_DEBUG(5, ("Got a new ClientHello packet --- rekeying starts."));

          /* The new hello packet cannot be in the v2.0 format. */
          s->kex.flags &= ~SSH_TLS_KEX_CONVERTED_CLIENT_HELLO;
          ssh_tls_initialize_new_kex(s);
        }

      if (!(s->kex.flags & SSH_TLS_KEX_CONVERTED_CLIENT_HELLO))
        {
          SSH_ASSERT(s->kex.handshake_history == NULL);
          s->kex.handshake_history = ssh_buffer_allocate();

          if (s->kex.handshake_history == NULL)
            return -1;
        }
    }

  /* Check for the HelloRequest message. */
  if (type == SSH_TLS_HS_HELLO_REQUEST)
    {
      if (s->conf.is_server)
        {
          /* Only clients should receive these messages... */
          ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
          return -1;
        }

      if (s->kex.state != SSH_TLS_KEX_CLEAR)
        {
          /* This action is dictated by the standard. */
          SSH_DEBUG(5, ("Got HelloRequest during key exchange, so "
                        "ignore it."));
          goto done;
        }

      ssh_tls_initialize_new_kex(s);

      if (!ssh_tls_kex_dispatch(s, 0, NULL, 0))
        return -1;

      goto done;
    }

  /* Now call kex dispatch with the data and then remember
     that the data has been consumed. */
  if (!ssh_tls_kex_dispatch(s, type, ptr + 4, packet_len))
    {
      /* failed */
      return -1; /* Inform about the failure. */
    }

  /* Add the received message to the history if it exists. */

  if (s->kex.handshake_history != NULL)
    {
      SSH_ASSERT(s->kex.handshake_history != NULL);

      if (!(type == SSH_TLS_HS_CLIENT_HELLO &&
            (s->kex.flags & SSH_TLS_KEX_CONVERTED_CLIENT_HELLO)))
        if (ssh_buffer_append(s->kex.handshake_history,
                              ptr, packet_len + 4)
            != SSH_BUFFER_OK)
          return -1;
    }

  /* Now call KEX dispatch again to write a response, after the hashes
     have been updated. */

  if (!ssh_tls_kex_dispatch(s, 0, NULL, 0))
    {
      return -1;
    }

done:
  processed += packet_len + 4;
  ptr += packet_len + 4;
  l -= packet_len + 4;

  goto redo;
}

void ssh_tls_kex_revive_processing(SshTlsProtocolState s)
{
  SshTlsHigherProtocol i;
  int r;

  for (i = s->protocols; i != NULL; i = i->next)
    {
      if (i->type == SSH_TLS_CTYPE_HANDSHAKE)
        {
          r = (*(i->func))(s, i);
          if (r > 0)
            {
              SSH_ASSERT(ssh_buffer_len(i->data) >= r);
              ssh_buffer_consume(i->data, r);
            }
          return;
        }
    }
  SSH_NOTREACHED;
}

/* `from_us' should be set to TRUE if the affected data stream is that
   written by us. */
Boolean ssh_tls_change_cipher_context(SshTlsProtocolState s,
                                      Boolean from_us)
{

  /* Note, key material derived is function of crypto algorithm */
  unsigned char key_material[2*32 + 2*20 + 2*16 + 8]; /* %16 == 0 => +8 */
  unsigned char final_cipher_key[16];
  unsigned char *key_ptr;
  const char *cipher;
  const unsigned char *iv;

  SshTlsUnidirectionalState *state;
  Boolean client_write; /* True if changing the client write state. */
  int mac_key_len = 0, cipher_key_len = 0, iv_len = 0;

  SshTlsCipherSuiteDetailsStruct details;
  SSH_DEBUG(5, ("Changing cipher context."));
  ssh_tls_get_ciphersuite_details(s->kex.cipher_suite, &details);

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 &&
      s->protocol_version.minor == 0)
    {
      ssh_tls_ssl_prf(s->kex.master_secret, 48,
                      s->kex.server_random, 32,
                      s->kex.client_random, 32,
                      key_material,
                      2*32 + 2*20 + 2*16 + 8);
      SSH_DEBUG_HEXDUMP(5, ("SSL key block."), key_material,
                        2*32 + 2*20 + 2*16 + 8);
    }
  else
#endif /* SSH_TLS_SSL_3_0_COMPAT */
    {
      unsigned char random_buf[64];
      memcpy(random_buf, s->kex.server_random, 32);
      memcpy(random_buf + 32, s->kex.client_random, 32);
      ssh_tls_prf(s->kex.master_secret, 48,
                  (unsigned char *)"key expansion",
                  13 /* strlen("key expansion") */,
                  random_buf, 64,
                  key_material, 2*32 + 2*20 + 2*16);
      SSH_DEBUG_HEXDUMP(5, ("TLS key block."), key_material,
                        2*32 + 2*20 + 2*16);
      memset(random_buf, 0, 64);
    }

  /* Key material generated. Now go for the change. */
  if (from_us)
    {
      state = &(s->conn.outgoing);
      if (s->conf.is_server) client_write = FALSE;
      else client_write = TRUE;
    }
  else
    {
      state = &(s->conn.incoming);
      if (s->conf.is_server) client_write = TRUE;
      else client_write = FALSE;
    }

  /* Delete the old cipher and MAC states. */
  if (state->cipher != NULL) ssh_cipher_free(state->cipher);
  if (state->mac != NULL) ssh_mac_free(state->mac);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  SSH_ASSERT(state->ops_pending == 0);
  if (state->accel_ctx)
    tls_accel_free_key(state->accel_ctx);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  state->is_stream_cipher = FALSE; /* Changed for RC4 below. */
  state->block_length = 8; /* All block ciphers except AES have
                              eight-byte blocks. */

  switch (details.cipher)
    {
    case SSH_TLS_CIPH_RC4:
      cipher_key_len = 16; iv_len = 0;
      state->is_stream_cipher = TRUE; break;

    case SSH_TLS_CIPH_3DES:
      cipher_key_len = 24; iv_len = 8; break;

    case SSH_TLS_CIPH_AES128:
      state->block_length = 16;
      cipher_key_len = 16; iv_len = 16;
      break;

    case SSH_TLS_CIPH_AES256:
      state->block_length = 16;
      cipher_key_len = 32; iv_len = 16;
      break;

    case SSH_TLS_CIPH_IDEA:
      cipher_key_len = 16; iv_len = 8; break;

    case SSH_TLS_CIPH_DES:
      cipher_key_len = 8; iv_len = 8; break;

    case SSH_TLS_CIPH_RC2:
      cipher_key_len = 16; iv_len = 8; break;

    case SSH_TLS_CIPH_NULL:
      cipher_key_len = 0;  iv_len = 0; break;

    default:
      SSH_NOTREACHED;
    }

  switch (details.mac)
    {
    case SSH_TLS_MAC_MD5: state->mac_length = 16; mac_key_len = 16; break;
    case SSH_TLS_MAC_SHA: state->mac_length = 20; mac_key_len = 20; break;
    default:
      SSH_NOTREACHED;
    }

  SSH_DEBUG_HEXDUMP(8, ("MAC key, client->server"),
                    key_material, mac_key_len);
  SSH_DEBUG_HEXDUMP(8, ("MAC key, server->client"),
                    key_material + mac_key_len, mac_key_len);
  SSH_DEBUG_HEXDUMP(8, ("Encipherment key, client->server"),
                    key_material + 2 * mac_key_len, cipher_key_len);
  SSH_DEBUG_HEXDUMP(8, ("Encipherment key, server->client"),
                    key_material + 2 * mac_key_len + cipher_key_len,
                    cipher_key_len);
  SSH_DEBUG_HEXDUMP(8, ("Initialization vector, client->server"),
                    key_material + 2 * mac_key_len + 2 * cipher_key_len,
                    iv_len);
  SSH_DEBUG_HEXDUMP(8, ("Initialization vector, server->client"),
                    key_material + 2 * mac_key_len + 2 * cipher_key_len +
                    iv_len,
                    iv_len);

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
      if (ssh_mac_allocate(details.mac == SSH_TLS_MAC_MD5
                           ? "ssl3-md5" : "ssl3-sha1",
                           key_material + (!client_write ? mac_key_len : 0),
                           mac_key_len, &(state->mac))
          != SSH_CRYPTO_OK)
        return FALSE;
    }
  else
#endif /* SSH_TLS_SSL_3_0_COMPAT */

    if (ssh_mac_allocate(details.mac == SSH_TLS_MAC_MD5
                         ? "hmac-md5" : "hmac-sha1",
                         key_material + (!client_write ? mac_key_len : 0),
                         mac_key_len, &(state->mac))
        != SSH_CRYPTO_OK)
      return FALSE;

  if (details.cipher == SSH_TLS_CIPH_NULL)
    {
      state->cipher = NULL;
    }
  else
    {
      if (details.crippled)
        {
          unsigned char random_buf[64];

          key_ptr =
            key_material + (2 * mac_key_len) +
            (!client_write ? 5 : 0);

          SSH_DEBUG(7, ("Crippled algorithm so must still derive the final "
                        "encryption key."));


#ifdef SSH_TLS_SSL_3_0_COMPAT
          if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
            {
              SshHash md5;

              if (ssh_hash_allocate("md5", &md5) != SSH_CRYPTO_OK)
                return FALSE;

              ssh_hash_reset(md5);

              ssh_hash_update(md5, key_ptr, 5);
              if (client_write)
                {
                  ssh_hash_update(md5, s->kex.client_random, 32);
                  ssh_hash_update(md5, s->kex.server_random, 32);
                }
              else
                {
                  ssh_hash_update(md5, s->kex.server_random, 32);
                  ssh_hash_update(md5, s->kex.client_random, 32);
                }
              if (ssh_hash_final(md5, final_cipher_key) != SSH_CRYPTO_OK)
                {
                  ssh_hash_free(md5);
                  return FALSE;
                }
              ssh_hash_free(md5);
              key_ptr = final_cipher_key;
              goto key_done;
            }
#endif
          memcpy(random_buf, s->kex.client_random, 32);
          memcpy(random_buf + 32, s->kex.server_random, 32);

          ssh_tls_prf(key_ptr, 5, /* cipher_key_len == 5 */
                      (unsigned char *)
                      (client_write ? "client write key" :
                       "server write key"),
                      16 /* strlen("****** write key") */,
                      random_buf, 64,
                      final_cipher_key, cipher_key_len);

          key_ptr = final_cipher_key;
        }
      else
        {
          key_ptr =
            key_material + (2 * mac_key_len) +
            (!client_write ? cipher_key_len : 0);
        }

    key_done:
      cipher =
        details.cipher == SSH_TLS_CIPH_RC4  ? "arcfour"  :
        (details.cipher == SSH_TLS_CIPH_AES128 ||
        details.cipher == SSH_TLS_CIPH_AES256) ? "aes-cbc" :
        details.cipher == SSH_TLS_CIPH_3DES ? "3des-cbc" :
        details.cipher == SSH_TLS_CIPH_IDEA ? "idea-cbc" :
        details.cipher == SSH_TLS_CIPH_DES  ? "des-cbc"  :
        details.cipher == SSH_TLS_CIPH_RC2  ? "rc2-cbc"  : NULL;

      if (ssh_cipher_allocate(cipher, key_ptr, cipher_key_len,
                              from_us, &(state->cipher))
          != SSH_CRYPTO_OK)
        return FALSE;

      if (iv_len > 0)
        {
          if (details.crippled)
            {
              unsigned char random_buf[64];

#ifdef SSH_TLS_SSL_3_0_COMPAT
              if (s->protocol_version.major == 3 &&
                  s->protocol_version.minor == 0)
                {
                  SshHash md5;
                  if (ssh_hash_allocate("md5", &md5) != SSH_CRYPTO_OK)
                    return FALSE;
                  ssh_hash_reset(md5);

                  if (client_write)
                    {
                      ssh_hash_update(md5, s->kex.client_random, 32);
                      ssh_hash_update(md5, s->kex.server_random, 32);
                    }
                  else
                    {
                      ssh_hash_update(md5, s->kex.server_random, 32);
                      ssh_hash_update(md5, s->kex.client_random, 32);
                    }

                  if (ssh_hash_final(md5, final_cipher_key) != SSH_CRYPTO_OK)
                    {
                      ssh_hash_free(md5);
                      return FALSE;
                    }

                  ssh_hash_free(md5);
                  goto export_iv_calculated;
                }
#endif
              memcpy(random_buf, s->kex.client_random, 32);
              memcpy(random_buf + 32, s->kex.server_random, 32);

              SSH_ASSERT(iv_len <= sizeof(final_cipher_key));

              ssh_tls_prf((unsigned char *)"", 0,
                          (unsigned char *)"IV block",
                          8 /* strlen("IV block") */,
                          random_buf, 64,
                          final_cipher_key, iv_len);

            export_iv_calculated:
              ssh_cipher_set_iv(state->cipher, final_cipher_key);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
                state->accel_ctx =
                  tls_accel_init_key(
                    from_us, details.cipher,
                    key_ptr, cipher_key_len,
                    final_cipher_key);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

            }
          else
            {
              iv = key_material + (2 * mac_key_len +
                2 * cipher_key_len + (!client_write ? iv_len : 0));
              ssh_cipher_set_iv(state->cipher, iv);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
              state->accel_ctx =
                tls_accel_init_key(
                  from_us, details.cipher,
                  key_ptr, cipher_key_len,
                  iv);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
            }
          memset(final_cipher_key, 0, sizeof(final_cipher_key));
        }
      else
        {
          /* IV len == 0*/
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
          state->accel_ctx =
            tls_accel_init_key(
              from_us, details.cipher,
              key_ptr, cipher_key_len,
              NULL);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
        }
    }

  memset(key_material, 0, sizeof(key_material));

  SSH_TLS_ZERO_SEQ(state->seq);
  SSH_DEBUG(5, ("Cipher context changed."));
  return TRUE;
}

int ssh_tls_cc_process(SshTlsProtocolState s, SshTlsHigherProtocol p)
{
  int l;
  unsigned char *ptr;

  l = ssh_buffer_len(p->data);

  SSH_ASSERT(l > 0);

  /* Skip the certificate verify message if this comes in place of it. */
  if (s->kex.state == SSH_TLS_KEX_WAIT_C_CERTVERIFY)
    s->kex.state = SSH_TLS_KEX_WAIT_C_CC;

  if (s->kex.state != SSH_TLS_KEX_WAIT_S_CC &&
      s->kex.state != SSH_TLS_KEX_WAIT_C_CC)
    {
      ssh_tls_send_alert_message(s, SSH_TLS_ALERT_FATAL,
                                 SSH_TLS_ALERT_UNEXPECTED_MESSAGE);
      return -1;
    }

  /* Check that the single byte has the correct value. */
  ptr = ssh_buffer_ptr(p->data);

  if (*ptr != (unsigned char)1)
    {
      ssh_tls_send_alert_message(s, SSH_TLS_ALERT_FATAL,
                                 SSH_TLS_ALERT_ILLEGAL_PARAMETER);
      return -1;
    }

  if (!ssh_tls_change_cipher_context(s, FALSE))
    {
      ssh_tls_send_alert_message(s, SSH_TLS_ALERT_FATAL,
                                 SSH_TLS_ALERT_INTERNAL_ERROR);
      return -1;
    }

  /* The next KEX event is to receive the finished message so no need
     to revive the KEX processing explicitly. */
  if (s->kex.state == SSH_TLS_KEX_WAIT_S_CC)
    s->kex.state = SSH_TLS_KEX_WAIT_S_FINISHED;
  else
    s->kex.state = SSH_TLS_KEX_WAIT_C_FINISHED;

  return 1;                     /* One byte processed. */
}

void ssh_tls_cancel_kex(SshTlsProtocolState s)
{
  /* Release the private key object that can be shared between many
     TLS server sessions. */
  if (s->kex.temporary_private_key != NULL)
    {
      ssh_tls_release_private_key(s->kex.locked_temporary_key,
                                  s->kex.temporary_private_key);
      s->kex.temporary_private_key = NULL;
    }
}

void ssh_tls_kex_timeout(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;

  SSH_DEBUG(4, ("Key exchange timeout!"));

  /* Release the temporary private key. This has been the main
     reason for causing the key exchange timeout. */
  ssh_tls_cancel_kex(s);

  /* Hard to figure out a good alert message. */
  ssh_tls_alert_and_kill(s, SSH_TLS_ALERT_USER_CANCELED);
}

void ssh_tls_install_kex_timeout(SshTlsProtocolState s)
{
  SSH_ASSERT(!(s->kex.flags & SSH_TLS_KEX_TIMEOUT_COMING));
  s->kex.flags |= SSH_TLS_KEX_TIMEOUT_COMING;
  ssh_xregister_timeout(s->conf.key_exchange_timeout, 0L,
                       ssh_tls_kex_timeout, s);
}

void ssh_tls_cancel_kex_timeout(SshTlsProtocolState s)
{
  s->kex.flags &= ~SSH_TLS_KEX_TIMEOUT_COMING;
  ssh_cancel_timeouts(ssh_tls_kex_timeout, s);
}

void ssh_tls_reset_rekeying_counters(SshTlsProtocolState s,
                                     Boolean also_full_rekey)
{
  if (s->conf.fast_rekey_bytes > 0)
    s->kex.fast_rekey_data_limit =
      s->stats.bytes_sent +
      s->stats.bytes_received +
      s->conf.fast_rekey_bytes;

  if (also_full_rekey)
    if (s->conf.full_rekey_bytes > 0)
      s->kex.full_rekey_data_limit =
        s->stats.bytes_sent +
        s->stats.bytes_received +
        s->conf.full_rekey_bytes;

  ssh_cancel_timeouts(ssh_tls_fast_rekey_timeout, s);
  if (s->conf.fast_rekey_interval > 0)
    ssh_xregister_timeout((long)s->conf.fast_rekey_interval, 0L,
                         ssh_tls_fast_rekey_timeout, s);

  if (also_full_rekey)
    {
      ssh_cancel_timeouts(ssh_tls_full_rekey_timeout, s);
      if (s->conf.full_rekey_interval > 0)
        ssh_xregister_timeout((long)s->conf.full_rekey_interval, 0L,
                             ssh_tls_full_rekey_timeout, s);
    }
}

void ssh_tls_start_rekey(SshTlsProtocolState s,
                         SshTlsRekeyingMode mode)
{
  /* Do not perform rekeying when the protocol is terminating. */
  if (SSH_TLS_IS_FAILED_STATUS(s->status) ||
      (s->flags & SSH_TLS_FLAG_DELETED))
    return;

  if (s->flags & SSH_TLS_FLAG_FROZEN) return;

  if ((mode == SSH_TLS_REKEY_FAST
       && (s->kex.flags & (SSH_TLS_KEX_VIRGIN_AFTER_FAST_REKEY |
                           SSH_TLS_KEX_VIRGIN_AFTER_FULL_REKEY)))
      ||
      (mode == SSH_TLS_REKEY_FULL
       && (s->kex.flags & SSH_TLS_KEX_VIRGIN_AFTER_FULL_REKEY)))
    {
      SSH_DEBUG(6, ("The security context has not been used at all "
                    "so do not do rekey."));
      ssh_tls_reset_rekeying_counters(s, (mode == SSH_TLS_REKEY_FULL));
      return;
    }

  if (s->kex.state != SSH_TLS_KEX_CLEAR)
    {
      SSH_DEBUG(4, ("Cannot start rekey because there is already "
                    "a key exchange in progress (%d)!", s->kex.state));
      return;
    }

  SSH_DEBUG(5, ("Starting rekeying in the %s mode.",
                (mode == SSH_TLS_REKEY_FULL ? "full" : "fast")));

  if (s->conf.is_server)
    {
      ssh_tls_initialize_new_kex(s);

      /* Initialize new kex has dropped the NO_CACHING flag, so
         must set it not before it. */
      if (mode == SSH_TLS_REKEY_FULL)
        s->kex.flags |= SSH_TLS_KEX_NO_CACHING;

      ssh_tls_send_hello_request(s);
      return;
    }
  else
    {
      if (mode == SSH_TLS_REKEY_FULL)
        {
          /* Clear any identifier that was present. */
          s->kex.id_len = 0;
          /* Otherwise the identifier remains and will be hopefully used. */
        }

      ssh_tls_initialize_new_kex(s);
      ssh_tls_kex_dispatch(s, 0, NULL, 0);
    }
}

void ssh_tls_cancel_rekeying_timeouts(SshTlsProtocolState s)
{
  ssh_cancel_timeouts(ssh_tls_fast_rekey_timeout, s);
  ssh_cancel_timeouts(ssh_tls_full_rekey_timeout, s);
}

void ssh_tls_fast_rekey_timeout(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;
  ssh_tls_start_rekey(s, SSH_TLS_REKEY_FAST);
}

void ssh_tls_full_rekey_timeout(void *context)
{
  SshTlsProtocolState s = (SshTlsProtocolState)context;
  ssh_tls_start_rekey(s, SSH_TLS_REKEY_FULL);
}

void ssh_tls_clear_kex_state(SshTlsProtocolState s)
{
  SshTlsKexState *k = &(s->kex);

  /* Clear some flags so that they do not mess the renegotiations in
     the future. */
  k->flags &= ~(SSH_TLS_KEX_NO_CACHING|
                SSH_TLS_KEX_CERT_VERIFIED_CM|
                SSH_TLS_KEX_CLIENT_CERT_REQUESTED|
                SSH_TLS_KEX_CERT_VERIFIED|
                SSH_TLS_KEX_CM_INFO_VALID);

  if (k->encoded_ca_list != NULL)
    {
      ssh_free(k->encoded_ca_list);
      k->encoded_ca_list = NULL;
    }

#ifdef SSHDIST_VALIDATOR
  if (k->own_certificate_list != NULL)
    {
      SSH_ASSERT(s->conf.cert_manager != NULL);
      ssh_cm_cert_list_free(s->conf.cert_manager, k->own_certificate_list);
      k->own_certificate_list = NULL;
    }
#else /* SSHDIST_VALIDATOR */
  if (k->own_certs != NULL)
    {
      ssh_tls_free_cert_chain(k->own_certs);
      k->own_certs = NULL;
    }
#endif /* SSHDIST_VALIDATOR */

  if (k->peer_certs != NULL)
    {
      if (s->kex.flags & SSH_TLS_KEX_GRABBED_CERTS)
        {
          s->kex.flags &= ~SSH_TLS_KEX_GRABBED_CERTS;
        }
      else
        {
          ssh_tls_free_cert_chain(k->peer_certs);
        }
      k->peer_certs = NULL;
      k->query_status = SSH_TLS_CERT_FORGOTTEN;
    }

  if (k->handshake_history != NULL)
    {
      ssh_buffer_free(k->handshake_history);
      k->handshake_history = NULL;
    }

  if (k->temporary_private_key != NULL)
    {
      ssh_tls_release_private_key(k->locked_temporary_key,
                                  k->temporary_private_key);
      k->temporary_private_key = NULL;
    }

  if (k->server_temporary_key != NULL)
    {
      ssh_public_key_free(k->server_temporary_key);
      k->server_temporary_key = NULL;
    }

  if (k->her_public_key != NULL)
    {
      ssh_public_key_free(k->her_public_key);
      k->her_public_key = NULL;
    }
}
