/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshtlsi.h"
#include "sshdebug.h"
#include "sshmalloc.h"
#include "sshbuffer.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshTlsCrypto"

static Boolean prf_xor(unsigned char *dest, int dest_len,
                       SshMac mac, int mac_len, unsigned char *seed,
                       int seed_len)
{
  unsigned char A[20];
  unsigned char digest[20];
  int i;

  SSH_ASSERT(mac_len <= 20);

  /* Calculate A(1). (Notation from RFC 2246.) */
  ssh_mac_reset(mac);
  ssh_mac_update(mac, seed, seed_len);
  if (ssh_mac_final(mac, A) != SSH_CRYPTO_OK)
    return FALSE;

  while (1)
    {
      SSH_ASSERT(dest_len > 0);

      ssh_mac_reset(mac);
      ssh_mac_update(mac, A, mac_len);
      ssh_mac_update(mac, seed, seed_len);
      if (ssh_mac_final(mac, digest) != SSH_CRYPTO_OK)
        return FALSE;

      for (i = 0; i < mac_len; i++)
        {
          *dest ^= digest[i];
          dest++;
          dest_len--;
          if (dest_len == 0)
            {
              memset(A, 0, 20);
              memset(digest, 0, 20);
              return TRUE;
            }
        }

      /* Compute A(i+1) (see RFC 2246. `i' is induction variable, not
         the loop variable above. */
      ssh_mac_reset(mac);
      ssh_mac_update(mac, A, mac_len);
      if (ssh_mac_final(mac, A) != SSH_CRYPTO_OK)
        return FALSE;

    }

  return TRUE;
}

Boolean
ssh_tls_prf(const unsigned char *key, int key_len,
            const unsigned char *label, int label_len,
            const unsigned char *seed, int seed_len,
            unsigned char *return_buf, int return_len)
{
  int half_len;
  SshMac md5, sha1;
  SshCryptoStatus status;
  unsigned char *temp;

  /* hmac-md5, hmac-sha1 */
  if (!(ssh_mac_supported("hmac-md5") &&
        ssh_mac_supported("hmac-sha1")))
    {
      return FALSE;
    }

  /* Allocate the MACs so that both the MACs get half of the key. */
  half_len = (key_len + 1) / 2;

  status = ssh_mac_allocate("hmac-md5", key, half_len, &md5);
  if (status != SSH_CRYPTO_OK)
    return FALSE;

  status = ssh_mac_allocate("hmac-sha1", key + (key_len - half_len),
                            half_len, &sha1);
  if (status != SSH_CRYPTO_OK)
    {
      ssh_mac_free(md5);
      return FALSE;
    }

  /* Create the concatenated seed. */
  if ((temp = ssh_calloc(1, label_len + seed_len)) != NULL)
    {
      memcpy(temp, label, label_len);
      memcpy(temp + label_len, seed, seed_len);

      /* Clear the return buffer so that we can XOR into it. */
      memset(return_buf, 0, return_len);

      /* Calculate the XOR. */
      if (!prf_xor(return_buf, return_len,
                   md5, 16, temp, label_len + seed_len))
        {
          ssh_mac_free(md5);
          ssh_mac_free(sha1);
          return FALSE;
        }

      if (!prf_xor(return_buf, return_len,
                   sha1, 20, temp, label_len + seed_len))
        {
          ssh_mac_free(md5);
          ssh_mac_free(sha1);
          return FALSE;
        }

      /* All done. Free the MAC contexts. */
      ssh_mac_free(md5); ssh_mac_free(sha1);
      memset(temp, 0, label_len + seed_len);
      ssh_free(temp);
      return TRUE;
    }

  ssh_mac_free(md5);
  ssh_mac_free(sha1);
  return FALSE;
}

Boolean
ssh_tls_ssl_prf(const unsigned char *secret, int secret_len,
                const unsigned char *random_1, int random_1_len,
                const unsigned char *random_2, int random_2_len,
                unsigned char *return_buf, int return_len)
{
  unsigned char label;
  int i, j;
  SshHash md5, sha1;
  unsigned char sha_digest[20];

  SSH_ASSERT(return_len % 16 == 0);
  SSH_ASSERT(return_len < 400);

  if (ssh_hash_allocate("md5", &md5) != SSH_CRYPTO_OK)
    return FALSE;
  if (ssh_hash_allocate("sha1", &sha1) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(md5);
    return FALSE;
    }

  for (i = 1, label = 'A';
       return_len > 0;
       i++, label++, return_buf += 16, return_len -= 16)
    {
      ssh_hash_reset(sha1);

      for (j = 0; j < i; j++)
        ssh_hash_update(sha1, &label, 1);

      ssh_hash_update(sha1, secret, secret_len);
      ssh_hash_update(sha1, random_1, random_1_len);
      ssh_hash_update(sha1, random_2, random_2_len);
      if (ssh_hash_final(sha1, sha_digest) != SSH_CRYPTO_OK)
        {
          ssh_hash_free(md5);
          ssh_hash_free(sha1);
        return FALSE;
        }

      ssh_hash_reset(md5);

      ssh_hash_update(md5, secret, secret_len);
      ssh_hash_update(md5, sha_digest, 20);
      if (ssh_hash_final(md5, return_buf) != SSH_CRYPTO_OK)
        {
          ssh_hash_free(md5);
          ssh_hash_free(sha1);
        return FALSE;
    }
    }

  ssh_hash_free(md5);
  ssh_hash_free(sha1);
  return TRUE;
}


/* There must be room for 36 bytes in `buf'. */
static Boolean generic_ssl_digest(unsigned char *secret,
                                  int secret_len,
                                  unsigned char *handshake_messages,
                                  int handshake_messages_len,
                                  Boolean is_client,
                                  unsigned char *buf,
                                  Boolean include_sender_token)
{
  SshHash md5, sha1;
  int i;

  const unsigned char client_label[4] = { 0x43, 0x4c, 0x4e, 0x54 };
  const unsigned char sender_label[4] = { 0x53, 0x52, 0x56, 0x52 };

  unsigned char pad_36[48], pad_5c[48];

  for (i = 0; i < 48; i++)
    {
      pad_36[i] = 0x36; pad_5c[i] = 0x5c;
    }

  SSH_ASSERT(secret_len == 48);

  if (ssh_hash_allocate("md5", &md5) != SSH_CRYPTO_OK)
    return FALSE;
  if (ssh_hash_allocate("sha1", &sha1) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(md5);
    return FALSE;
    }

  ssh_hash_reset(md5);
  ssh_hash_update(md5, handshake_messages, handshake_messages_len);

  if (include_sender_token)
    ssh_hash_update(md5, is_client ? client_label : sender_label, 4);

  ssh_hash_update(md5, secret, secret_len);
  ssh_hash_update(md5, pad_36, 48);
  if (ssh_hash_final(md5, buf) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(md5);
      ssh_hash_free(sha1);
    return FALSE;
    }

  ssh_hash_reset(md5);
  ssh_hash_update(md5, secret, secret_len);
  ssh_hash_update(md5, pad_5c, 48);
  ssh_hash_update(md5, buf, 16);
  if (ssh_hash_final(md5, buf) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(md5);
      ssh_hash_free(sha1);
    return FALSE;
    }

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, handshake_messages, handshake_messages_len);

  if (include_sender_token)
    ssh_hash_update(sha1, is_client ? client_label : sender_label, 4);

  ssh_hash_update(sha1, secret, secret_len);
  ssh_hash_update(sha1, pad_36, 40);
  if (ssh_hash_final(sha1, buf + 16) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(md5);
      ssh_hash_free(sha1);
    return FALSE;
    }

  ssh_hash_reset(sha1);
  ssh_hash_update(sha1, secret, secret_len);
  ssh_hash_update(sha1, pad_5c, 40);
  ssh_hash_update(sha1, buf + 16, 20);
  if (ssh_hash_final(sha1, buf + 16) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(md5);
      ssh_hash_free(sha1);
    return FALSE;
    }

  ssh_hash_free(md5);
  ssh_hash_free(sha1);
  return TRUE;
}

/* There must be room for 36 bytes in `buf'. */
Boolean ssh_tls_ssl_finished_digest(unsigned char *secret,
                                    int secret_len,
                                    unsigned char *handshake_messages,
                                    int handshake_messages_len,
                                    Boolean is_client,
                                    unsigned char *buf)
{
  return generic_ssl_digest(secret, secret_len, handshake_messages,
                            handshake_messages_len, is_client, buf, TRUE);
}

Boolean ssh_tls_ssl_certverify_digest(unsigned char *secret,
                                      int secret_len,
                                      unsigned char *handshake_messages,
                                      int handshake_messages_len,
                                      Boolean is_client,
                                      unsigned char *buf)
{
  return generic_ssl_digest(secret, secret_len, handshake_messages,
                            handshake_messages_len, is_client, buf, FALSE);
}
