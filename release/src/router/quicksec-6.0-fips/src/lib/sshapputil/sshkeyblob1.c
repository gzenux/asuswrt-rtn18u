/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Import ssh1 key blobs.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "ssh1encode.h"
#include "ssh2pubkeyencode.h"
#include "sshkeyblob1.h"

#define SSH_DEBUG_MODULE "Ssh1KeyDecode"

const char *ssh1_cipher_name(int cipher_number);
Boolean ssh1_passphrase_to_key(const char *passphrase,
                               const char *cipher_name,
                               unsigned char **key,
                               size_t *key_len);

const char *ssh1_cipher_name(int cipher_number)
{
  switch (cipher_number) {
  case SSH1_CIPHER_NONE:
    return "none";
  case SSH1_CIPHER_IDEA:
    return "idea-cfb";
  case SSH1_CIPHER_DES:
    return "des-cbc";
  case SSH1_CIPHER_3DES:
    return "3des-cbc-ssh1";
  case SSH1_CIPHER_ARCFOUR:
    return "arcfour";
  case SSH1_CIPHER_BLOWFISH:
    return "blowfish-cbc";
  default:
    return NULL;
  }
  /*NOTREACHED*/
}

Boolean ssh1_passphrase_to_key(const char *passphrase,
                               const char *cipher_name,
                               unsigned char **key,
                               size_t *key_len)
{
  SshHash hash;
  SshCryptoStatus cr;
  unsigned char *key_tmp;
  size_t key_tmp_len, digest_len;

  cr = ssh_hash_allocate("md5", &hash);
  if (cr != SSH_CRYPTO_OK)
    return FALSE;
  ssh_hash_update(hash, (unsigned char *)passphrase, strlen(passphrase));
  digest_len = ssh_hash_digest_length(ssh_hash_name(hash));
  key_tmp_len = (digest_len < 32) ? 32 : digest_len;
  key_tmp = ssh_xcalloc(key_tmp_len + 1, sizeof (char));
  ssh_hash_final(hash, key_tmp);
  ssh_hash_free(hash);
  key_tmp[key_tmp_len] = 0;
  *key = key_tmp;
  if (key_len)
    *key_len = key_tmp_len;
  return TRUE;
}

SshCryptoStatus
ssh1_decode_pubkeyblob(const unsigned char *buf, size_t len,
                       char **comment,
                       SshPublicKey *key)
{
  SshBufferStruct b1[1], b2[1], b3[1], b4[1];
  unsigned char c;
  size_t i;
  SshMPIntegerStruct n, e;
  SshCryptoStatus cr = SSH_CRYPTO_OK;

  if (comment == NULL)
    return SSH_CRYPTO_INTERNAL_ERROR;

  *comment = NULL;

  i = 0;
  ssh_buffer_init(b1);
  ssh_buffer_init(b2);
  ssh_buffer_init(b3);
  ssh_buffer_init(b4);
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);

  /* Length */
  while ((i < len) && (isdigit(buf[i])))
    {
      c = buf[i];
      ssh_xbuffer_append(b1, &c, 1);
      i++;
    }
  c = 0;
  ssh_xbuffer_append(b1, &c, 1);
  if ((i >= len) || (buf[i] != ' '))
    {
      SSH_DEBUG(5, ("unable to decode length of N"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  i++;

  /* E */
  while ((i < len) && (isdigit(buf[i])))
    {
      c = buf[i];
      ssh_xbuffer_append(b2, &c, 1);
      i++;
    }
  c = 0;
  ssh_xbuffer_append(b2, &c, 1);
  if ((i >= len) || (buf[i] != ' '))
    {
      SSH_DEBUG(5, ("unable to decode E"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  i++;

  /* N */
  while ((i < len) && (isdigit(buf[i])))
    {
      c = buf[i];
      ssh_xbuffer_append(b3, &c, 1);
      i++;
    }
  c = 0;
  ssh_xbuffer_append(b3, &c, 1);
  if ((i >= len) || (buf[i] != ' '))
    {
      SSH_DEBUG(5, ("unable to decode N"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  i++;

  /* Comment */
  while ((i < len) && (buf[i] != '\n'))
    {
      c = buf[i];
      ssh_xbuffer_append(b4, &c, 1);
      i++;
    }
  c = 0;
  ssh_xbuffer_append(b3, &c, 1);

  SSH_DEBUG(7, ("e = \"%s\", n = \"%s\", c = \"%s\"",
                ssh_buffer_ptr(b2),
                ssh_buffer_ptr(b3),
                ssh_buffer_ptr(b4)));

  /* Decode the integers. */
  if (ssh_mprz_set_str(&e, (const char *)(ssh_buffer_ptr(b2)), 10) == 0)
    {
      SSH_DEBUG(5, ("unable to import E"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  if (ssh_mprz_set_str(&n, (const char *)(ssh_buffer_ptr(b3)), 10) == 0)
    {
      SSH_DEBUG(5, ("unable to import N"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }

  /* Construct the key. */
  cr = ssh_public_key_define(key,
                             SSH_CRYPTO_RSA,
                             SSH_PKF_MODULO_N, &n,
                             SSH_PKF_PUBLIC_E, &e,
                             SSH_PKF_END);
  if (cr != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(5, ("ssh_public_key_define failed with %d.", (int)cr));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }

  if (comment)
    *comment = ssh_xmemdup(ssh_buffer_ptr(b4), ssh_buffer_len(b4));

  /* Modulus length gets ignored.  It could be used as a sanity check,
     but it is really not needed, so let's forget it. */

 cleanup_and_return:
  ssh_buffer_uninit(b1);
  ssh_buffer_uninit(b2);
  ssh_buffer_uninit(b3);
  ssh_buffer_uninit(b4);
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  return cr;
}

SshCryptoStatus
ssh1_decode_privkeyblob(const unsigned char *blob, size_t bloblen,
                        const char *passphrase,
                        char **comment,
                        SshPrivateKey *key)
{
  const char *cipher_name;
  SshBufferStruct buf[1];
  SshMPIntegerStruct n, e, d, p, q, u;
  char *tmp_comment = NULL;
  unsigned char *cipher_key = NULL;
  size_t cipher_key_len;
  SshCipher cipher;
  SshCryptoStatus cr;
  int i;

  *key = NULL;

  ssh_buffer_init(buf);
  ssh_mprz_init(&n);
  ssh_mprz_init(&e);
  ssh_mprz_init(&d);
  ssh_mprz_init(&p);
  ssh_mprz_init(&q);
  ssh_mprz_init(&u);

  if ((bloblen > (strlen(SSH1_PRIVATE_KEY_ID_STRING) + 20))
      && (strncmp(SSH1_PRIVATE_KEY_ID_STRING,
                  (char *)blob,
                  strlen(SSH1_PRIVATE_KEY_ID_STRING)) == 0)
      && (blob[strlen(SSH1_PRIVATE_KEY_ID_STRING)] == 0))
    {
      cipher_name =
        ssh1_cipher_name((int)(blob[strlen(SSH1_PRIVATE_KEY_ID_STRING) + 1]));
      if (cipher_name == NULL)
        {
          cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
          goto cleanup_and_return;
        }
      ssh_xbuffer_append(buf,
                         &(blob[strlen(SSH1_PRIVATE_KEY_ID_STRING) + 10]),
                         (bloblen -
                          (strlen(SSH1_PRIVATE_KEY_ID_STRING) +
                           10)));
    }
  else
    {
      SSH_DEBUG(5, ("blob is not a ssh1 private key blob"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }

  if (!ssh1_decode_mp(buf, &n))
    {
      SSH_DEBUG(5, ("unable to decode N"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  if (!ssh1_decode_mp(buf, &e))
    {
      SSH_DEBUG(5, ("unable to decode E"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  if (!ssh1_decode_string(buf, &tmp_comment, NULL))
    {
      SSH_DEBUG(5, ("unable to decode comment"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }

  if (!ssh1_passphrase_to_key(passphrase,
                              cipher_name,
                              &cipher_key, &cipher_key_len))
    {
      SSH_DEBUG(5, ("unable to turn passphrase to key"));
      cr = SSH_CRYPTO_UNSUPPORTED;
      goto cleanup_and_return;
    }
  if (strcmp(cipher_name, "3des-cbc-ssh1") != 0)
    {
      cr = ssh_cipher_allocate(cipher_name,
                               cipher_key, cipher_key_len,
                               FALSE,
                               &cipher);
      if (cr != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(5, ("unable to allocate cipher (cr=%d)", (int)cr));
          goto cleanup_and_return;
        }
      cr = ssh_cipher_start(cipher);
      if (cr != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          SSH_DEBUG(5, ("decrypt start failed (cr=%d)", (int)cr));
          goto cleanup_and_return;
        }
      cr = ssh_cipher_transform(cipher,
                                ssh_buffer_ptr(buf),
                                ssh_buffer_ptr(buf),
                                ssh_buffer_len(buf));
      ssh_cipher_free(cipher);
      if (cr != SSH_CRYPTO_OK)
        {
          SSH_DEBUG(5, ("decrypt failed (cr=%d)", (int)cr));
          goto cleanup_and_return;
        }
    }
  else
    {
      /* ssh1 uses weird inner mode cbc, that has to be emulated. */
      SSH_DEBUG(5, ("emulating ssh1 inner mode cbc"));
      if (cipher_key_len < 16)
        {
          SSH_DEBUG(5, ("key length %d too short for 3des", cipher_key_len));
          cr = SSH_CRYPTO_INVALID_PASSPHRASE;
          goto cleanup_and_return;
        }
      for (i = 0; i < 3; i++)
        {
          cr =
            ssh_cipher_allocate("des-cbc",
                                ((i == 1) ? (cipher_key + 8) : cipher_key),
                                8,
                                ((i == 1) ? TRUE : FALSE),
                                &cipher);
          if (cr != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(5, ("unable to allocate cipher (cr=%d)", (int)cr));
              goto cleanup_and_return;
            }
          cr = ssh_cipher_start(cipher);
          if (cr != SSH_CRYPTO_OK)
            {
              ssh_cipher_free(cipher);
              SSH_DEBUG(5, ("decrypt start failed (cr=%d)", (int)cr));
              goto cleanup_and_return;
            }
          cr = ssh_cipher_transform(cipher,
                                    ssh_buffer_ptr(buf),
                                    ssh_buffer_ptr(buf),
                                    ssh_buffer_len(buf));
          ssh_cipher_free(cipher);
          if (cr != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(5, ("decrypt failed (cr=%d)", (int)cr));
              goto cleanup_and_return;
            }
        }
      SSH_DEBUG(5, ("inner mode cbc decryption completed."));
    }

  if (ssh_buffer_len(buf) < 4)
    {
      SSH_DEBUG(5, ("encrypted buffer too short"));
      cr = SSH_CRYPTO_BLOCK_SIZE_ERROR;
      goto cleanup_and_return;
    }

  if ((*(ssh_buffer_ptr(buf)) != *(ssh_buffer_ptr(buf) + 2)) ||
      (*(ssh_buffer_ptr(buf) + 1) != *(ssh_buffer_ptr(buf) + 3)))
    {
      SSH_DEBUG(5, ("check bytes do not match"));
      cr = SSH_CRYPTO_INVALID_PASSPHRASE;
      goto cleanup_and_return;
    }
  else
    {
      SSH_DEBUG(7, ("check bytes match"));
      ssh_buffer_consume(buf, 4);
    }

  if (!ssh1_decode_mp(buf, &d))
    {
      SSH_DEBUG(5, ("unable to decode D"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  else
    {
      SSH_DEBUG(7, ("D decoded"));
    }
  if (!ssh1_decode_mp(buf, &u))
    {
      SSH_DEBUG(5, ("unable to decode U"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  else
    {
      SSH_DEBUG(7, ("U decoded"));
    }
  if (!ssh1_decode_mp(buf, &p))
    {
      SSH_DEBUG(5, ("unable to decode P"));
      cr = SSH_CRYPTO_CORRUPTED_KEY_FORMAT;
      goto cleanup_and_return;
    }
  else
    {
      SSH_DEBUG(7, ("P decoded"));
    }
  if (!ssh1_decode_mp(buf, &q))
    {
      SSH_DEBUG(5, ("unable to decode Q"));
      goto cleanup_and_return;
    }
  else
    {
      SSH_DEBUG(7, ("Q decoded"));
    }

  cr = ssh_private_key_define(key,
                              "if-modn{sign{rsa-pkcs1-none},"
                              "encrypt{rsa-pkcs1-none}}",
                              SSH_PKF_MODULO_N, &n,
                              SSH_PKF_PUBLIC_E, &e,
                              SSH_PKF_SECRET_D, &d,
                              SSH_PKF_INVERSE_U, &u,
                              SSH_PKF_PRIME_P, &p,
                              SSH_PKF_PRIME_Q, &q,
                              SSH_PKF_END);
  if (cr != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(5, ("unable to define private key"));
      goto cleanup_and_return;
    }
  else
    {
      SSH_DEBUG(7, ("private key defined"));
    }

 cleanup_and_return:
  if (*key && tmp_comment && comment)
    *comment = tmp_comment;
  else
    ssh_xfree(tmp_comment);

  if (cipher_key && (cipher_key_len > 0))
    memset(cipher_key, 0, cipher_key_len);

  ssh_xfree(cipher_key);
  ssh_buffer_uninit(buf);

  ssh_mprz_clear(&n);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&p);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&u);

  return cr;
}
