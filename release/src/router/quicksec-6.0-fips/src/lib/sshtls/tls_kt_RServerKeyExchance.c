/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"
#include "sshmp.h"

static void
tls_kt_ske_verify_done(SshCryptoStatus status,
                       void *context)
{
  SshTlsProtocolState s = context;

  if (status != SSH_CRYPTO_OK)
    {
      s->kex.flags |= SSH_TLS_KEX_KEYOP_FAILED;
      s->kex.alert = SSH_TLS_ALERT_DECRYPT_ERROR;
      s->kex.alert_text = "Invalid signature in the server KEX packet.";
      ssh_tls_async_continue(s);
      return;
    }
  ssh_tls_async_continue(s);
}

SshTlsTransStatus
ssh_tls_trans_read_server_kex(SshTlsProtocolState s,
                              SshTlsHandshakeType type,
                              unsigned char *data, int data_len)
{
  Boolean want_kex_packet = FALSE;
  SshTlsCipherSuiteDetailsStruct details;

  SSH_DEBUG(6, ("Preparing to parse the server key exchange packet for the "
                "cipher suite `%s'.",
                ssh_tls_format_suite(s->kex.cipher_suite)));

  ssh_tls_get_ciphersuite_details(s->kex.cipher_suite, &details);
  /* Check whether we except the key exchange or not. */

  SSH_ASSERT(details.kex_method == SSH_TLS_KEX_RSA);
  if (details.crippled)
    {
      int bits;
      if (ssh_public_key_get_info(s->kex.her_public_key,
                                  SSH_PKF_SIZE, &bits,
                                  SSH_PKF_END) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;

      if (bits > 512)
        {
          want_kex_packet = TRUE;
        }
    }

  if (want_kex_packet)
    {
      int modlen, explen, signlen;
      unsigned char *modptr, *expptr, *signptr, *all_data;
      SshMPIntegerStruct modulus, exponent;
      SshHash md5, sha1;
      unsigned char hashes[36];


      CHECKTYPE(SSH_TLS_HS_SERVER_KEX);

      /* Get the modulus and the exponent. */
      MIN_LENGTH(2);
      modlen = SSH_GET_16BIT(data);
      MIN_LENGTH(modlen + 4);
      all_data = data;
      modptr = data + 2;
      data += 2 + modlen; data_len -= 2 + modlen;
      explen = SSH_GET_16BIT(data);
      MIN_LENGTH(explen + 2);
      expptr = data + 2;
      data += explen + 2;
      data_len -= explen + 2;
      signlen = SSH_GET_16BIT(data);
      if (data_len != signlen + 2)
        FAILMF;
      signptr = data + 2;

      /* Ok, got everything. Now let's look at the data. */
      ssh_mprz_init(&modulus);
      ssh_mprz_init(&exponent);

      ssh_mprz_set_buf(&modulus, modptr, modlen);
      ssh_mprz_set_buf(&exponent, expptr, explen);

      if (ssh_mprz_cmp_ui(&exponent, 2) < 0)
        {
          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Invalid or trivial RSA exponent!"));
        }

      /* Check that the key is long enough.  We accept only exactly
         512-bit moduli. */
      if (ssh_mprz_get_size(&modulus, 2) < 510)
        {
          ssh_mprz_clear(&modulus); ssh_mprz_clear(&exponent);

          FAIL(SSH_TLS_ALERT_HANDSHAKE_FAILURE,
               ("Too short temporary key (want at least 510 bits)."));
        }

      /* Create the temporary public key. */
      if (ssh_public_key_define(&(s->kex.server_temporary_key),
                                "if-modn",
                                SSH_PKF_ENCRYPT,
                                "rsa-pkcs1-none",
                                SSH_PKF_MODULO_N, &modulus,
                                SSH_PKF_PUBLIC_E, &exponent,
                                SSH_PKF_END)
          != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&modulus); ssh_mprz_clear(&exponent);

          FAIL(SSH_TLS_ALERT_INTERNAL_ERROR,
               ("Could not create the temporary RSA key."));
        }

      /* Clear the MP ints. */
      ssh_mprz_clear(&modulus); ssh_mprz_clear(&exponent);

      /* The next thing is to verify the signature. */
      /* Calculate the annoying non-standard signature. */
      if (ssh_hash_allocate("md5", &md5) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;
      if (ssh_hash_allocate("sha1", &sha1) != SSH_CRYPTO_OK)
        {
          ssh_hash_free(md5);
        return SSH_TLS_TRANS_FAILED;
        }
      ssh_hash_reset(md5);
      ssh_hash_reset(sha1);

      ssh_hash_update(md5, s->kex.client_random, 32);
      ssh_hash_update(md5, s->kex.server_random, 32);
      ssh_hash_update(md5, all_data, modlen + explen + 4);

      ssh_hash_update(sha1, s->kex.client_random, 32);
      ssh_hash_update(sha1, s->kex.server_random, 32);
      ssh_hash_update(sha1, all_data, modlen + explen + 4);

      if (ssh_hash_final(md5, hashes) != SSH_CRYPTO_OK)
        {
          ssh_hash_free(md5);
          ssh_hash_free(sha1);
        return SSH_TLS_TRANS_FAILED;
        }

      if (ssh_hash_final(sha1, hashes + 16) != SSH_CRYPTO_OK)
        {
          ssh_hash_free(md5);
          ssh_hash_free(sha1);
        return SSH_TLS_TRANS_FAILED;
        }

      ssh_hash_free(md5);
      ssh_hash_free(sha1);

      /* Now that the digest is calculated, try to verify it. */

      if (ssh_public_key_select_scheme(s->kex.her_public_key,
                                       SSH_PKF_SIGN,
                                       "rsa-pkcs1-none",
                                       SSH_PKF_END) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;

      s->kex.state = SSH_TLS_KEX_WAIT_KEYOP_COMPLETION;
      s->kex.next_state = SSH_TLS_KEX_WAIT_S_CERTREQ;
      s->kex.alert = 0;
      s->kex.alert_text = NULL;

      ssh_tls_async_freeze(s);
      ssh_public_key_verify_async(s->kex.her_public_key,
                                  signptr, signlen, hashes, 36,
                                  tls_kt_ske_verify_done, s);
    }
  else
    {
      if (type == SSH_TLS_HS_SERVER_KEX)
        {
          FAIL(SSH_TLS_ALERT_UNEXPECTED_MESSAGE,
               ("Got server key exchange packet when not waiting for it!"));
        }
      s->kex.state = SSH_TLS_KEX_WAIT_S_CERTREQ;
      return SSH_TLS_TRANS_REPROCESS;
    }

  return SSH_TLS_TRANS_OK;
}
