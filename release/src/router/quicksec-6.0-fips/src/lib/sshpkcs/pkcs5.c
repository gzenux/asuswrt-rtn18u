/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of the PKCS-5 v2.0.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "sshmp.h"
#include "sshpkcs5.h"

#define SSH_DEBUG_MODULE "SshPkcs5"

#ifdef SSHDIST_CERT
unsigned char *
ssh_pkcs5_pbkdf1(const char *hash_name,
                 const unsigned char *passwd, size_t passwd_len,
                 const unsigned char  salt[8],
                 unsigned int c,
                 unsigned int dk_len)
{
  SshHash hash;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char *ret;
  size_t digest_length;
  int i;

  if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
    return NULL;

  if (dk_len > ssh_hash_digest_length(ssh_hash_name(hash)))
    {
      ssh_hash_free(hash);
      return NULL;
    }

  ssh_hash_reset(hash);
  ssh_hash_update(hash, passwd, passwd_len);
  ssh_hash_update(hash, salt, 8);
  ssh_hash_final(hash, digest);

  digest_length = ssh_hash_digest_length(ssh_hash_name(hash));

  for (i = 2; i <= c; i++)
    {
      ssh_hash_reset(hash);
      ssh_hash_update(hash, digest, digest_length);
      ssh_hash_final(hash, digest);
    }

  ssh_hash_free(hash);

  /* Get the dk_len first octets. */
  dk_len = (dk_len < digest_length) ? dk_len : digest_length;
  if ((ret = ssh_malloc(dk_len)) == NULL)
    return NULL;

  for (i = 0; i < dk_len; i++)
    ret[i] = digest[i];

  return ret;
}


unsigned char *ssh_pkcs5_pbkdf2(const char *mac_name,
                                const unsigned char *passwd,
                                size_t passwd_len,
                                const unsigned char *salt,
                                size_t salt_len,
                                unsigned int c,
                                unsigned int dk_len)
{
  SshMac mac;
  SshBufferStruct t;
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char comb[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned int l, i, hlen;
  unsigned char *tmp = NULL;

  if (ssh_mac_allocate(mac_name, passwd, passwd_len, &mac) != SSH_CRYPTO_OK)
    return NULL;

  /* Calculate the sizes. */
  hlen = ssh_mac_length(ssh_mac_name(mac));

  SSH_ASSERT(hlen != 0);

  l = (dk_len + hlen - 1) / hlen;

  ssh_buffer_init(&t);

  for (i = 1; i <= l; i++)
    {
      unsigned char data[4];
      int j, k;

      ssh_mac_reset(mac);
      if (salt != NULL)
        ssh_mac_update(mac, salt, salt_len);
      SSH_PUT_32BIT(data, i);
      ssh_mac_update(mac, data, 4);
      ssh_mac_final(mac, digest);

      memcpy(comb, digest, hlen);

      for (j = 2; j <= c; j++)
        {
          ssh_mac_reset(mac);
          ssh_mac_update(mac, digest, hlen);
          ssh_mac_final(mac, digest);

          for (k = 0; k < hlen; k++)
            comb[k] ^= digest[k];
        }

      if (ssh_buffer_append(&t, comb, hlen) != SSH_BUFFER_OK)
        goto error;
   }

  tmp = ssh_memdup(ssh_buffer_ptr(&t), dk_len);
 error:
  ssh_buffer_uninit(&t);
  ssh_mac_free(mac);
  return tmp;
}

unsigned char *ssh_pkcs5_pbes1_encrypt(const unsigned char *cipher_name,
                                       const char *hash_name,
                                       const unsigned char *passwd,
                                       size_t passwd_len,
                                       const unsigned char salt[8],
                                       unsigned int c,
                                       const unsigned char *src,
                                       size_t src_len,
                                       size_t *ret_len)
{
  unsigned char *dk, *dest;
  SshCipher cipher;
  size_t dest_len, i;

  /* Initialize the return value length. */
  *ret_len = 0;

  dk = ssh_pkcs5_pbkdf1(hash_name, passwd, passwd_len,
                        salt, c, 16);
  if (dk == NULL)
    return NULL;

  if (ssh_cipher_allocate(ssh_csstr(cipher_name),
                          dk, 8, TRUE, &cipher) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      return NULL;
    }

  if (ssh_cipher_get_iv_length(ssh_cipher_name(cipher)) != 8)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  if (ssh_cipher_set_iv(cipher, dk+8) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  ssh_free(dk);

  /* Create still the destination. */
  dest_len = src_len + (8 - (src_len % 8));
  if ((dest = ssh_malloc(dest_len)) != NULL)
    {
      memcpy(dest, src, src_len);
      for (i = src_len; i < dest_len; i++)
        dest[i] = (dest_len - src_len);

      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }

      /* We can finally transform the message. */
      if (ssh_cipher_transform(cipher, dest, dest, dest_len) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }
      ssh_cipher_free(cipher);

      /* Return the correct length. */
      *ret_len = dest_len;
    }
  else
    {
      ssh_cipher_free(cipher);
    }

  /* Return the encrypted (unless malloc failed) data. */
  return dest;
}

unsigned char *ssh_pkcs5_pbes1_decrypt(const char *cipher_name,
                                       const char *hash_name,
                                       const unsigned char *passwd,
                                       size_t passwd_len,
                                       const unsigned char salt[8],
                                       unsigned int c,
                                       const unsigned char *src,
                                       size_t src_len,
                                       size_t *ret_len)
{
  unsigned char *dk, *dest;
  SshCipher cipher;
  size_t dest_len, i, j;

  *ret_len = 0;

  dk = ssh_pkcs5_pbkdf1(hash_name, passwd, passwd_len,
                        salt, c, 16);
  if (dk == NULL)
    return NULL;

  if (ssh_cipher_allocate(cipher_name,
                          dk, 8, FALSE, &cipher) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      return NULL;
    }

  if (ssh_cipher_get_iv_length(ssh_cipher_name(cipher)) != 8)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  if (ssh_cipher_set_iv(cipher, dk+8) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  ssh_free(dk);

  if ((dest = ssh_malloc(src_len)) != NULL)
    {
      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }

      if (ssh_cipher_transform(cipher, dest, src, src_len) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }
      ssh_cipher_free(cipher);

      j = dest[src_len-1];
      if (j > 8)
        {
          ssh_free(dest);
          return NULL;
        }

      /* Set the correct length. */
      dest_len = src_len - j;
      for (i = dest_len; i < src_len; i++)
        {
          /* Check for PKCS#5 padding */
          if (dest[i] != j)
            {
              ssh_free(dest);
              return NULL;
            }
        }
      *ret_len = dest_len;
    }
  else
    {
      ssh_cipher_free(cipher);
    }

  /* Return the encrypted data. */
  return dest;
}

unsigned char *
ssh_pkcs5_pbes2_encrypt(const char *cipher_name,
                        const char *mac_name,
                        const unsigned char *passwd, size_t passwd_len,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *iv, size_t iv_len,
                        unsigned int c,
                        const unsigned char *src, size_t src_len,
                        size_t *ret_len)
{
  unsigned char *dk, *dest;
  SshCipher cipher;
  size_t dest_len, i, dk_keylen, blocklen;

  /* TODO: Determine the blob length correctly from the cipher. */
  dk_keylen = ssh_cipher_get_key_length(cipher_name);

  /* Initialize the return value length. */
  *ret_len = 0;

  dk = ssh_pkcs5_pbkdf2(mac_name, passwd, passwd_len,
                        salt, salt_len, c, dk_keylen);
  if (dk == NULL)
    return NULL;

  if (ssh_cipher_allocate(cipher_name,
                          dk, dk_keylen, TRUE, &cipher) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      return NULL;
    }

  if (ssh_cipher_get_iv_length(ssh_cipher_name(cipher)) != iv_len)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  if (ssh_cipher_set_iv(cipher, iv) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }
  ssh_free(dk);

  blocklen = ssh_cipher_get_block_length(ssh_cipher_name(cipher));

  SSH_ASSERT(blocklen != 0);

  /* Create still the destination. */
  dest_len = src_len + (blocklen - (src_len % blocklen));
  if ((dest = ssh_malloc(dest_len)) != NULL)
    {
      memcpy(dest, src, src_len);
      for (i = src_len; i < dest_len; i++)
        dest[i] = (dest_len - src_len);

      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }

      /* We can finally transform the message. */
      if (ssh_cipher_transform(cipher, dest, dest, dest_len) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }
      ssh_cipher_free(cipher);

      /* Return the correct length. */
      *ret_len = dest_len;
    }
  else
    {
      ssh_cipher_free(cipher);
    }

  /* Return the encrypted data. */
  return dest;
}

unsigned char *
ssh_pkcs5_pbes2_decrypt(const char *cipher_name,
                        const char *mac_name,
                        const unsigned char *passwd, size_t passwd_len,
                        const unsigned char *salt, size_t salt_len,
                        const unsigned char *iv, size_t iv_len,
                        unsigned int c,
                        const unsigned char *src, size_t src_len,
                        size_t *ret_len)
{
  unsigned char *dk, *dest;
  SshCipher cipher;
  size_t dest_len, i, j, dk_keylen, blocklen;

  /* TODO: Determine the blob length correctly from the cipher. */
  dk_keylen = ssh_cipher_get_key_length(cipher_name);

  /* Initialize the return value length. */
  *ret_len = 0;

  dk = ssh_pkcs5_pbkdf2(mac_name, passwd, passwd_len,
                        salt, salt_len, c, dk_keylen);
  if (dk == NULL)
    return NULL;

  if (ssh_cipher_allocate(cipher_name,
                          dk, dk_keylen, FALSE, &cipher) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      return NULL;
    }

  if (ssh_cipher_get_iv_length(ssh_cipher_name(cipher)) != iv_len)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  if (ssh_cipher_set_iv(cipher, iv) != SSH_CRYPTO_OK)
    {
      ssh_free(dk);
      ssh_cipher_free(cipher);
      return NULL;
    }

  ssh_free(dk);
  blocklen = ssh_cipher_get_block_length(ssh_cipher_name(cipher));
  if ((dest = ssh_malloc(src_len)) != NULL)
    {
      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }

      if (ssh_cipher_transform(cipher, dest, src, src_len) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }
      ssh_cipher_free(cipher);

      j = dest[src_len-1];
      if (j > blocklen)
        {
          ssh_free(dest);
          return NULL;
        }

      /* Set the correct length. */
      dest_len = src_len - j;
      for (i = dest_len; i < src_len; i++)
        {
          /* Check for PKCS#5 padding */
          if (dest[i] != j)
            {
              ssh_free(dest);
              return NULL;
            }
        }
      *ret_len = dest_len;
    }
  else
    {
      ssh_cipher_free(cipher);
    }
  /* Return the encrypted data. */
  return dest;
}

#define DIV_UP(D, S) ((D + S - 1) / S)
#define MAX_INPUT_BLOCK_LENGTH (512 / 8)

Boolean
ssh_pkcs12_derive_random(size_t amount,
                         SshPkcs12DiversifyID id,
                         const char *hash_name,
                         int iterations,
                         const unsigned char *passwd, size_t passwd_len,
                         const unsigned char *salt, size_t salt_len,
                         unsigned char *dest)
{
  SshHash hash;
  size_t u, v, i, c, I_len, S_len, P_len, j;
  SshMPIntegerStruct bi, bb;
  unsigned char *I, *p;
  unsigned char A[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char B[MAX_INPUT_BLOCK_LENGTH + 1];
  unsigned char D[MAX_INPUT_BLOCK_LENGTH];
  size_t BMPS_len = 2 * passwd_len + 2;
  Boolean unicode = TRUE;
  unsigned char *BMPS_passwd = NULL;

  if (passwd_len == 0)
    {
      return FALSE;
    }

  /* Password must be encoded in unicode and end in 0x00, 0x00.
     If not, we assume it must be changed to unicode-string.
     An extra check for empty password, which is not converted. */
  if (passwd_len != 0 &&
      ((passwd_len < 2) ||
       ((passwd[passwd_len - 2] != 0x00) ||
        (passwd[passwd_len - 1] != 0x00))))
     unicode = FALSE;

  /* Try to fix to correct big-endian form, eg. "pass" ->
     0x00, 'p', 0x00, 'a', 0x00, 's', 0x00, 's', 0x00, 0x00 */
  if (!unicode)
    {
      if ((BMPS_passwd = ssh_malloc(BMPS_len)) == NULL)
        return FALSE;

      /* Add zero-bytes before characters */
      for (i = 0; i < BMPS_len - 2;)
        {
          BMPS_passwd[i++] = 0x00;
          BMPS_passwd[i] = passwd[(i - 1) / 2];
          i++;
        }

      /* Add zero-bytes to the end */
      BMPS_passwd[BMPS_len - 2] = 0x00;
      BMPS_passwd[BMPS_len - 1] = 0x00;

      passwd = BMPS_passwd;
      passwd_len = BMPS_len;
    }

  /* B is used both for calculation of B+1 and for storing sum Ij + B
     + 1, hence it is one byte longer than needed, as the sum may
     overflow. */


  if (ssh_hash_allocate(hash_name, &hash) != SSH_CRYPTO_OK)
    {
      ssh_free(BMPS_passwd);
      return FALSE;
    }

  /* The length of digest A is u */
  u = ssh_hash_digest_length(ssh_hash_name(hash));
  v = ssh_hash_input_block_size(ssh_hash_name(hash));

  SSH_ASSERT(v != 0);

  memset(D, id, v);

  S_len = v * DIV_UP(salt_len, v);
  P_len = v * DIV_UP(passwd_len, v);
  I_len = S_len + P_len;

  if ((I = ssh_malloc(I_len)) == NULL)
    {
      ssh_hash_free(hash);
      ssh_free(BMPS_passwd);
      return FALSE;
    }

  /* Make I = salt ||salt ||salt ,,, || passwd || passwd ... for now */
  for (i = 0; i < S_len; i++) I[i] = salt[i % salt_len];
  for (i = 0; i < P_len; i++) I[S_len + i] = passwd[i % passwd_len];

  /* c equals how many times we loop. */
  c = DIV_UP(amount, u);
  p = dest;

  /* Now construct the buffer piece by piece. */
  for (i = 0; i < c; i++)
    {
      ssh_hash_reset(hash);
      ssh_hash_update(hash, D, v);
      ssh_hash_update(hash, I, I_len);
      ssh_hash_final(hash, A);

      for (j = 1; j < iterations; j++)
        {
          ssh_hash_reset(hash);
          ssh_hash_update(hash, A, u);
          ssh_hash_final(hash, A);
        }

      if (amount < u)
        {
          /* Copy the rest of the bytes from A to our destination buf
             pointed by p */
          memcpy (p, A, amount);
          goto out;
        }
      else
        {
          /* Copy whole A to our dest buf pointed by p */
          memcpy (p, A, u);
          amount -= u;
          p += u;
        }

      /* Set B to be concatenations of the output of the hash. */
      for (j = 0; j < v; j++) B[j] = A[j % u];

      /* Calculate B + 1 */
      ssh_mprz_init(&bb);
      ssh_mprz_set_buf(&bb, B, v);
      ssh_mprz_add_ui(&bb, &bb, 1);

      ssh_mprz_init(&bi);

      for (j = 0; j < I_len; j += v)
        {
          /* bi = ( Ij + B + 1) */
          ssh_mprz_set_buf(&bi, I + j, v);
          ssh_mprz_add(&bi, &bi, &bb);

          if (ssh_mprz_byte_size(&bi) > v)
            {
              ssh_mprz_get_buf(B, v + 1, &bi);
              memcpy(I + j, B + 1, v);
            }
          else
            {
              ssh_mprz_get_buf(I + j, v, &bi);
            }
        }
      ssh_mprz_clear(&bi);
      ssh_mprz_clear(&bb);
    }

 out:
  ssh_hash_free(hash);
  ssh_free(I);
  ssh_free(BMPS_passwd);

  return TRUE;
}

static unsigned char *
ssh_pkcs12_pbe_transform(Boolean encrypt,
                         const char *cipher_name,
                         size_t key_len,
                         const char *hash_name,
                         int iterations,
                         const unsigned char *passwd,
                         size_t passwd_len,
                         const unsigned char *salt,
                         size_t salt_len,
                         const unsigned char *src,
                         size_t src_len,
                         size_t *dest_len_ret)
{
  SshCipher cipher;
  unsigned char *material, *dest;
  size_t iv_len, dest_len, i;

  iv_len = 8;

  if (ssh_cipher_has_fixed_key_length(cipher_name))
    key_len = ssh_cipher_get_key_length(cipher_name);
  else
    {
      /* variable key length cipher. */
      if (key_len == 0)
        key_len = 16; /* useable for blowfish, rc2, rc4 */
    }

  if ((material = ssh_malloc(key_len + iv_len)) != NULL)
    {
      if (!ssh_pkcs12_derive_random(key_len,
                                    SSH_PKCS12_DIVERSIFY_KEY,
                                    hash_name,
                                    iterations,
                                    passwd, passwd_len,
                                    salt, salt_len,
                                    material))
        {
          ssh_free(material);
          return NULL;
        }
      if (!ssh_pkcs12_derive_random(iv_len,
                                    SSH_PKCS12_DIVERSIFY_IV,
                                    hash_name,
                                    iterations,
                                    passwd, passwd_len,
                                    salt, salt_len,
                                    material + key_len))
        {
          ssh_free(material);
          return NULL;
        }
      if (ssh_cipher_allocate(cipher_name,
                              material, key_len,
                              encrypt, &cipher) != SSH_CRYPTO_OK)
        {
          ssh_free(material);
          return NULL;
        }

      if (iv_len > 0 &&
          ssh_cipher_set_iv(cipher, material+key_len) != SSH_CRYPTO_OK)
        {
          ssh_free(material);
          ssh_cipher_free(cipher);
          return NULL;
        }
      ssh_free(material);
    }
  else
    return NULL;

  if (encrypt)
    dest_len = src_len + (8 - (src_len % 8));
  else
    dest_len = src_len;

  if ((dest = ssh_malloc(dest_len)) != NULL)
    {
      memcpy(dest, src, src_len);
      if (encrypt)
        for (i = src_len; i < dest_len; i++) dest[i] = (dest_len - src_len);

      if (ssh_cipher_start(cipher) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }

      if (ssh_cipher_transform(cipher, dest, dest, dest_len) != SSH_CRYPTO_OK)
        {
          ssh_cipher_free(cipher);
          ssh_free(dest);
          return NULL;
        }
      if (encrypt)
        *dest_len_ret = dest_len;
      else
        *dest_len_ret = dest_len - dest[dest_len - 1];
    }
  ssh_cipher_free(cipher);
  return dest;
}

unsigned char *
ssh_pkcs12_pbe_decrypt(const char *cipher_name,
                       size_t key_len,
                       const char *hash_name,
                       int iterations,
                       const unsigned char *passwd,
                       size_t passwd_len,
                       const unsigned char *salt,
                       size_t salt_len,
                       const unsigned char *src,
                       size_t src_len,
                       size_t *dest_len_ret)
{
  return ssh_pkcs12_pbe_transform(FALSE,
                                  cipher_name, key_len, hash_name, iterations,
                                  passwd, passwd_len,
                                  salt, salt_len,
                                  src, src_len,
                                  dest_len_ret);
}

unsigned char *
ssh_pkcs12_pbe_encrypt(const char *cipher_name,
                       size_t key_len,
                       const char *hash_name,
                       int iterations,
                       const unsigned char *passwd,
                       size_t passwd_len,
                       const unsigned char *salt,
                       size_t salt_len,
                       const unsigned char *src,
                       size_t src_len,
                       size_t *dest_len_ret)
{
  return ssh_pkcs12_pbe_transform(TRUE,
                                  cipher_name, key_len, hash_name, iterations,
                                  passwd, passwd_len,
                                  salt, salt_len,
                                  src, src_len,
                                  dest_len_ret);
}


/* End. */
#endif /* SSHDIST_CERT */
