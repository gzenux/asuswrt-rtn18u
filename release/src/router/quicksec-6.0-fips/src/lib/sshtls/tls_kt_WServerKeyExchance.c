/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshtlskextrans.h"
#include "sshmp.h"

struct WhileSignRec {
  SshTlsProtocolState state;
  unsigned char *data;
  size_t sigoff;
};

static void
tls_kt_wsk_sign_done(SshCryptoStatus status,
                     const unsigned char *signature, size_t signature_len,
                     void *context)
{
  struct WhileSignRec *ws = context;

  if (status != SSH_CRYPTO_OK)
    {
      ws->state->kex.flags |= SSH_TLS_KEX_KEYOP_FAILED;
      ws->state->kex.alert = SSH_TLS_ALERT_INTERNAL_ERROR;
      ws->state->kex.alert_text = "Can't construct signature.";
      goto cleanup;
    }

  /* Fill in the signature length[2] and signature data[signature_len]. */
  memcpy(ws->data + ws->sigoff, signature, signature_len);
  SSH_PUT_16BIT(ws->data + ws->sigoff - 2, signature_len);

  ssh_tls_make_hs_header(ws->state,
                         SSH_TLS_HS_SERVER_KEX, ws->sigoff + signature_len);
  ssh_tls_add_to_kex_packet(ws->state, ws->data, ws->sigoff + signature_len);

 cleanup:
  ssh_tls_async_continue(ws->state);
  ssh_free(ws->data);
  ssh_free(ws);
}

SshTlsTransStatus ssh_tls_trans_write_server_kex(SshTlsProtocolState s)
{
  SshTlsCipherSuiteDetailsStruct details;

  SSH_DEBUG(6, ("Preparing the server key exchange packet for the "
                "cipher suite `%s'.",
                ssh_tls_format_suite(s->kex.cipher_suite)));

  ssh_tls_get_ciphersuite_details(s->kex.cipher_suite, &details);

  if (details.kex_method != SSH_TLS_KEX_RSA)
    {
      /* If this happens it is an internal programming error. */
      return SSH_TLS_TRANS_FAILED;
    }

  if (details.crippled == FALSE)
    {
      SSH_DEBUG(6, ("Non-crippled RSA key exchange, so KEX packet not sent."));
      s->kex.state = SSH_TLS_KEX_SEND_S_CERTREQ;
      return SSH_TLS_TRANS_OK;
    }

  /* Check the strength of the private key. */
  {
    int bits;

    if (ssh_private_key_get_info(s->conf.private_key,
                                 SSH_PKF_SIZE, &bits,
                                 SSH_PKF_END) != SSH_CRYPTO_OK)
      {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot set private key info"));
        return SSH_TLS_TRANS_FAILED;
      }

    if (bits <= 512)
      {
        SSH_DEBUG(6, ("Private key size is no more than 512 bits so do "
                      "not need to generate a temporary key."));
        s->kex.state = SSH_TLS_KEX_SEND_S_CERTREQ;
        return SSH_TLS_TRANS_OK;
      }
  }

  /* Now we need a temporary key and all kinds of stupid stuff. */
  if (s->kex.locked_temporary_key == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Cannot proceed with TLS key exchange because a temporary "
                 "key object is not available, an export-crippled suite "
                 "was chosen and the server RSA key is larger than "
                 "512 bits. (Try to add a valid temporary key object to the "
                 "protocol configuration.)"));
      return SSH_TLS_TRANS_FAILED;
    }

  {
    SshPublicKey temp_pub_key;
    SshMPIntegerStruct modulus, exponent;
    int modlen, explen;
    size_t signlen;
    unsigned char *contents;
    unsigned char hashes[36];
    SshHash md5, sha1;
    struct WhileSignRec *ws;

    ssh_tls_get_temporary_keys(s->kex.locked_temporary_key,
                               &temp_pub_key,
                               &(s->kex.temporary_private_key));

    /* Get the public key modulus and exponent. */
    ssh_mprz_init(&modulus);
    ssh_mprz_init(&exponent);
    (void)ssh_public_key_get_info(temp_pub_key,
                                  SSH_PKF_MODULO_N, &modulus,
                                  SSH_PKF_PUBLIC_E, &exponent,
                                  SSH_PKF_END);
    modlen = (ssh_mprz_get_size(&modulus, 2) + 7) / 8;
    explen = (ssh_mprz_get_size(&exponent, 2) + 7) / 8;

    /* Get an upper bound for the signature size. */
    signlen = ssh_private_key_max_signature_output_len(s->conf.private_key);
    SSH_ASSERT(signlen > 0);

    if ((contents = ssh_calloc(1, modlen + explen + 4 + signlen + 2))
        == NULL)
      {
        SSH_DEBUG(6, ("Can not allocate space for contents."));
        return SSH_TLS_TRANS_FAILED;
      }

    /* Create the ServerRSAParams field. */
    SSH_PUT_16BIT(contents, modlen);
    ssh_mprz_get_buf(contents + 2, modlen, &modulus);
    SSH_PUT_16BIT(contents + 2 + modlen, explen);
    ssh_mprz_get_buf(contents + 4 + modlen, explen, &exponent);

    ssh_mprz_clear(&modulus);
    ssh_mprz_clear(&exponent);

    /* Calculate the annoying non-standard signature. */
      if (ssh_hash_allocate("md5", &md5) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;
      if (ssh_hash_allocate("sha1", &sha1) != SSH_CRYPTO_OK)
        return SSH_TLS_TRANS_FAILED;

    ssh_hash_reset(md5); ssh_hash_reset(sha1);

    ssh_hash_update(md5, s->kex.client_random, 32);
    ssh_hash_update(md5, s->kex.server_random, 32);
    ssh_hash_update(md5, contents, modlen + explen + 4);

    ssh_hash_update(sha1, s->kex.client_random, 32);
    ssh_hash_update(sha1, s->kex.server_random, 32);
    ssh_hash_update(sha1, contents, modlen + explen + 4);

    if (ssh_hash_final(md5, hashes) != SSH_CRYPTO_OK)
      return SSH_TLS_TRANS_FAILED;
    if (ssh_hash_final(sha1, hashes + 16) != SSH_CRYPTO_OK)
      return SSH_TLS_TRANS_FAILED;

    ssh_hash_free(md5); ssh_hash_free(sha1);

    if (ssh_private_key_select_scheme(s->conf.private_key,
                                      SSH_PKF_SIGN, "rsa-pkcs1-none",
                                      SSH_PKF_END) != SSH_CRYPTO_OK)
      {
        SSH_DEBUG(SSH_D_FAIL, ("Cannot set private key scheme"));
        return SSH_TLS_TRANS_FAILED;
      }

    if ((ws = ssh_calloc(1, sizeof(*ws))) == NULL)
      {
        SSH_DEBUG(6, ("Can not allocate space for sign context."));
        ssh_free(contents);
        return SSH_TLS_TRANS_FAILED;
      }

    ws->state  = s;
    ws->data   = contents;
    ws->sigoff = modlen + explen + 6;

    s->kex.state = SSH_TLS_KEX_WAIT_KEYOP_COMPLETION;
    s->kex.next_state = SSH_TLS_KEX_SEND_S_CERTREQ;
    s->kex.alert = 0;
    s->kex.alert_text = NULL;


    ssh_tls_async_freeze(s);
    ssh_private_key_sign_async(s->conf.private_key,
                               hashes, 36,
                               tls_kt_wsk_sign_done,
                                 ws);
  }

  return SSH_TLS_TRANS_OK;
}
