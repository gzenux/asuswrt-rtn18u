/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"
#include "sshmp.h"

static void
tls_kt_rke_decrypt_done(SshCryptoStatus status,
                        const unsigned char *plaintext_buffer,
                        size_t plaintext_buffer_len,
                        void *context)
{
  unsigned char *tempbuf;
  size_t tempbuf_len;
  SshTlsProtocolState s = context;

  if (s->kex.temporary_private_key != NULL)
    {
      ssh_tls_release_private_key(s->kex.locked_temporary_key,
                                  s->kex.temporary_private_key);
      s->kex.temporary_private_key = NULL;
    }

  if (status != SSH_CRYPTO_OK || plaintext_buffer_len != 48)
    {
      tempbuf = ssh_calloc(1, 48);
      tempbuf_len = 48;
    }
  else
    {
      tempbuf = ssh_memdup(plaintext_buffer, plaintext_buffer_len);
      tempbuf_len = plaintext_buffer_len;
    }

  if (tempbuf == NULL)
    {
      s->kex.flags |= SSH_TLS_KEX_KEYOP_FAILED;
      s->kex.alert = SSH_TLS_ALERT_INTERNAL_ERROR;
      s->kex.alert_text = "No space for decrypt result.";
      ssh_tls_async_continue(s);
      return;
    }

  if (status != SSH_CRYPTO_OK || plaintext_buffer_len != 48)
    {
      int i;

      SSH_DEBUG(4, ("Could not decrypt the data correctly (status = %d, "
                    "plaintext length = %d).", status, plaintext_buffer_len));
      SSH_DEBUG(4, ("Following the recommendations, generating now a "
                    "random 48-byte premaster secret so that the PKCS#1 "
                    "attack does not work."));

      for (i = 0; i < 48; i++)
        tempbuf[i] = ssh_random_get_byte();
    }
  else
    {
      if (tempbuf[0] != s->kex.client_version.major ||
          tempbuf[1] != s->kex.client_version.minor)
        {
          int i;
          SSH_DEBUG(4, ("Version roll-back attack or BVO attack detected."));
          SSH_DEBUG(6, ("Generating random premaster secret."));

          for (i = 0; i < 48; i++)
            tempbuf[i] = ssh_random_get_byte();
          tempbuf[0] = s->kex.client_version.major;
          tempbuf[1] = s->kex.client_version.minor;
        }
      else
        {
          SSH_DEBUG(6, ("Decryption succesful."));
          SSH_DEBUG(6, ("Computing the master secret."));
        }
      if (s->protocol_version.major == 3 &&
          s->protocol_version.minor == 0)
        {
#ifdef SSH_TLS_SSL_3_0_COMPAT
          ssh_tls_ssl_prf(tempbuf, 48,
                          s->kex.client_random, 32,
                          s->kex.server_random, 32,
                          s->kex.master_secret, 48);
          s->kex.flags |= SSH_TLS_KEX_HAVE_MASTER_SECRET;
#else
#ifdef DEBUG_LIGHT
          SSH_NOTREACHED;
#else
          /* Should not be reached, but insert a statement here so that
             the block doesn't become empty in any case. */
          return;
#endif
#endif
        }
      else
        {
          unsigned char random_buf[64];

          memcpy(random_buf, s->kex.client_random, 32);
          memcpy(random_buf + 32, s->kex.server_random, 32);
          ssh_tls_prf(tempbuf, 48,
                      (unsigned char *)"master secret",
                      13 /* strlen("master secret") */,
                      random_buf, 64,
                      s->kex.master_secret, 48);
          s->kex.flags |= SSH_TLS_KEX_HAVE_MASTER_SECRET;
          memset(random_buf, 0, 64);
        }

      SSH_DEBUG_HEXDUMP(5, ("Client random:"), s->kex.client_random, 32);
      SSH_DEBUG_HEXDUMP(5, ("Server random:"), s->kex.server_random, 32);
      SSH_DEBUG_HEXDUMP(5, ("Pre-master secret:"), tempbuf, 48);
      SSH_DEBUG_HEXDUMP(5, ("Master secret:"), s->kex.master_secret, 48);
    }

  memset(tempbuf, 0, tempbuf_len);
  ssh_free(tempbuf);
  ssh_tls_async_continue(s);
  return;
}

SshTlsTransStatus ssh_tls_trans_read_client_kex(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len)
{
  int blob_len;
  SshTlsCipherSuiteDetailsStruct details;
  SshPrivateKey key;

  CHECKTYPE(SSH_TLS_HS_CLIENT_KEX);

  ssh_tls_get_ciphersuite_details(s->kex.cipher_suite, &details);

  if (details.kex_method != SSH_TLS_KEX_RSA)
    {
      FAIL(SSH_TLS_ALERT_INTERNAL_ERROR, ("Unsupported kex method."));
    }

  /* RSA premaster secret */

#ifdef SSH_TLS_SSL_3_0_COMPAT
  if (s->protocol_version.major == 3 &&
      s->protocol_version.minor == 0)
    {
      blob_len = data_len;
      goto blob_len_decided;
    }
#endif /* SSH_TLS_SSL_3_0_COMPAT */

  if (data_len < 2)
    FAIL(SSH_TLS_ALERT_DECODE_ERROR, ("Cannot get encoded blob length."));

  blob_len = SSH_GET_16BIT(data);

  if (blob_len < data_len - 2)
    FAIL(SSH_TLS_ALERT_DECODE_ERROR, ("Garbage after the encoded blob."));

  if (blob_len > data_len - 2)
    FAIL(SSH_TLS_ALERT_DECODE_ERROR, ("Encoded blob not fully contained."));

  /* Skip over the length field. */
  data += 2;

blob_len_decided:

  if (ssh_private_key_select_scheme(s->conf.private_key,
                                    SSH_PKF_ENCRYPT, "rsa-pkcs1-none",
                                    SSH_PKF_END) != SSH_CRYPTO_OK)
    return SSH_TLS_TRANS_FAILED;


  if (s->kex.temporary_private_key != NULL)
    key = s->kex.temporary_private_key;
  else
    key = s->conf.private_key;

  s->kex.state = SSH_TLS_KEX_WAIT_KEYOP_COMPLETION;
  s->kex.next_state =  SSH_TLS_KEX_WAIT_C_CERTVERIFY;
  s->kex.alert = 0;
  s->kex.alert_text = NULL;
  ssh_tls_async_freeze(s);

  ssh_private_key_decrypt_async(key, data, blob_len,
                                tls_kt_rke_decrypt_done,
                                s);

  return SSH_TLS_TRANS_OK;
}
