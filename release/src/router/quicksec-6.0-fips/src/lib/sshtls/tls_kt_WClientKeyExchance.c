/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"
struct WhileEncryptRec {
  SshTlsProtocolState state;
  unsigned char premaster_secret[48];
};

static void
tls_kt_wke_encrypt_done(SshCryptoStatus status,
                        const unsigned char *ciphertext,
                        size_t ciphertext_len,
                        void *context)
{
  unsigned char tempbuf[2];
  struct WhileEncryptRec *e = context;
  SshTlsProtocolState s = e->state;


  if (status != SSH_CRYPTO_OK)
    {
      s->kex.flags |= SSH_TLS_KEX_KEYOP_FAILED;
      s->kex.alert = SSH_TLS_ALERT_INTERNAL_ERROR;
      s->kex.alert_text = "Public key encryption failed.";
      ssh_tls_async_continue(s);
      return;
    }

  /* Construct the packet. */
#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
      ssh_tls_make_hs_header(s, SSH_TLS_HS_CLIENT_KEX, ciphertext_len);
      ssh_tls_add_to_kex_packet(s, ciphertext, ciphertext_len);
      goto encrypted_data_written;
    }
#endif

  ssh_tls_make_hs_header(s, SSH_TLS_HS_CLIENT_KEX, ciphertext_len + 2);
  SSH_PUT_16BIT(tempbuf, ciphertext_len);
  ssh_tls_add_to_kex_packet(s, tempbuf, 2);
  ssh_tls_add_to_kex_packet(s, ciphertext, ciphertext_len);
#ifdef SSH_TLS_SSL_3_0_COMPAT
 encrypted_data_written:
#endif

  /* Calculate the master secret */
  SSH_DEBUG(6, ("Encryption succesful."));
  SSH_DEBUG(6, ("Computing the master secret."));

  if (s->protocol_version.major == 3 && s->protocol_version.minor == 0)
    {
#ifdef SSH_TLS_SSL_3_0_COMPAT
      ssh_tls_ssl_prf(e->premaster_secret, 48,
                      s->kex.client_random, 32,
                      s->kex.server_random, 32,
                      s->kex.master_secret, 48);
      s->kex.flags |= SSH_TLS_KEX_HAVE_MASTER_SECRET;
#else
      SSH_NOTREACHED;
#endif
    }
  else
    {
      unsigned char random_buf[64];

      memcpy(random_buf, s->kex.client_random, 32);
      memcpy(random_buf + 32, s->kex.server_random, 32);
      ssh_tls_prf(e->premaster_secret, 48,
                  (unsigned char *)"master secret",
                  13            /* strlen("master secret") */,
                  random_buf, 64,
                  s->kex.master_secret, 48);
      memset(random_buf, 0, 64);
    }

  s->kex.flags |= SSH_TLS_KEX_HAVE_MASTER_SECRET;

  SSH_DEBUG_HEXDUMP(5, ("Client random:"), s->kex.client_random, 32);
  SSH_DEBUG_HEXDUMP(5, ("Server random:"), s->kex.server_random, 32);
  SSH_DEBUG_HEXDUMP(5, ("Pre-master secret:"), e->premaster_secret, 48);
  SSH_DEBUG_HEXDUMP(5, ("Master secret:"), s->kex.master_secret, 48);

  ssh_free(e);
  ssh_tls_async_continue(s);
  return;
}

SshTlsTransStatus ssh_tls_trans_write_client_kex(SshTlsProtocolState s)
{
  int i;
  SshPublicKey encryption_key;
  struct WhileEncryptRec *e;

#ifdef SSH_TLS_EXTRAS
  if (s->extra.flags & SSH_TLS_EXTRA_UNRESPONSIVE)
    {
      s->kex.state = SSH_TLS_KEX_VOID;
      return SSH_TLS_TRANS_OK;
    }
#endif

  if ((e = ssh_calloc(1, sizeof(*e))) == NULL)
    {
      SSH_DEBUG(6, ("Can not allocate space for encrypt context."));
      return SSH_TLS_TRANS_FAILED;
    }
  e->state = s;

  /* Create the premaster secret. */
  e->premaster_secret[0] = s->kex.client_version.major;
  e->premaster_secret[1] = s->kex.client_version.minor;

  SSH_DEBUG(7, ("Making premaster secret, version %d.%d.",
                (int)(e->premaster_secret[0]),
                (int)(e->premaster_secret[1])));

  for (i = 2; i < 48; i++)
    e->premaster_secret[i] = ssh_random_get_byte();

  encryption_key = s->kex.her_public_key;
  if (s->kex.server_temporary_key != NULL)
    {
      SSH_DEBUG(7, ("Using the server's temporary key."));
      encryption_key = s->kex.server_temporary_key;
    }

  if (ssh_public_key_max_encrypt_input_len(encryption_key) < 48)
    {
      ssh_free(e);
      FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
           ("The premaster secret encryption key cannot be actually used "
            "for long enough encryption."));
    }

  if (ssh_public_key_select_scheme(encryption_key,
                                   SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                   SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_free(e);
      return SSH_TLS_TRANS_FAILED;
    }


  s->kex.state = SSH_TLS_KEX_WAIT_KEYOP_COMPLETION;
  s->kex.next_state =  SSH_TLS_KEX_SEND_C_CERTVERIFY;
  s->kex.alert = 0;
  s->kex.alert_text = NULL;
  ssh_tls_async_freeze(s);

  ssh_public_key_encrypt_async(encryption_key,
                               e->premaster_secret, 48,
                               tls_kt_wke_encrypt_done, e);
  return SSH_TLS_TRANS_OK;
}
