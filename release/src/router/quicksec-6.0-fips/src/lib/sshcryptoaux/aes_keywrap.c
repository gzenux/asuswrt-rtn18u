/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   AES Key Wrap as specified in RFC 3394
*/

#include "sshincludes.h"
#include "sshmp-xuint.h"
#include "sshgetput.h"
#include "aes_keywrap.h"


#define SSH_DEBUG_MODULE "SshAesKeyWrap"

SshCryptoStatus ssh_aes_key_wrap_kek(const unsigned char *kek,
                                     size_t kek_len,
                                     const unsigned char *iv,
                                     size_t iv_len,
                                     unsigned char *dest,
                                     size_t dest_len,
                                     const unsigned char *src,
                                     size_t src_len)
{
  SshCryptoStatus status;
  SshCipher cipher;
  char *cipher_name;

  switch (kek_len)
    {
    case 16:
      cipher_name = "aes128-ecb";
      break;
    case 24:
      cipher_name = "aes192-ecb";
      break;
    case 32:
      cipher_name = "aes256-ecb";
      break;
    default:
      return SSH_CRYPTO_KEY_INVALID;
    }

  status = ssh_cipher_allocate(cipher_name, kek, kek_len, TRUE, &cipher);
  if (status != SSH_CRYPTO_OK)
    return status;

  status = ssh_aes_key_wrap(cipher, iv, iv_len,
                            dest, dest_len,
                            src, src_len);

  ssh_cipher_free(cipher);
  return status;
}

SshCryptoStatus ssh_aes_key_unwrap_kek(const unsigned char *kek,
                                       size_t kek_len,
                                       const unsigned char *iv,
                                       size_t iv_len,
                                       unsigned char *dest,
                                       size_t dest_len,
                                       const unsigned char *src,
                                       size_t src_len)
{
  SshCryptoStatus status;
  char *cipher_name;
  SshCipher cipher;

  switch (kek_len)
    {
    case 16:
      cipher_name = "aes128-ecb";
      break;
    case 24:
      cipher_name = "aes192-ecb";
      break;
    case 32:
      cipher_name = "aes256-ecb";
      break;
    default:
      return SSH_CRYPTO_KEY_INVALID;
    }

  status = ssh_cipher_allocate(cipher_name, kek, kek_len, FALSE, &cipher);
  if (status != SSH_CRYPTO_OK)
    return status;

  status = ssh_aes_key_unwrap(cipher, iv, iv_len,
                              dest, dest_len,
                              src, src_len);

  ssh_cipher_free(cipher);
  return status;
}

SshCryptoStatus ssh_aes_key_wrap(SshCipher cipher,
                                 const unsigned char *iv,
                                 size_t iv_len,
                                 unsigned char *dest,
                                 size_t dest_len,
                                 const unsigned char *src,
                                 size_t src_len)
{
  SshCryptoStatus status;
  unsigned char iv_buf[8];
  unsigned char tmp[16];
  SshXUInt64 A, X;
  int i, j;

  if (!cipher || !ssh_cipher_name(cipher))
    return SSH_CRYPTO_OPERATION_FAILED;

  if (strcmp(ssh_cipher_name(cipher), "aes-ecb") &&
      strcmp(ssh_cipher_name(cipher), "aes128-ecb") &&
      strcmp(ssh_cipher_name(cipher), "aes192-ecb") &&
      strcmp(ssh_cipher_name(cipher), "aes256-ecb"))
    return SSH_CRYPTO_OPERATION_FAILED;

  /* Must have at least 2 64 bit blocks */
  if (src_len < 16)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  /* Input length must be a multiple of 64 bits */
  if (src_len % 8)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  if (dest_len != src_len + 8)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  if (iv != NULL && iv_len != 8)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  /* Use default IV if none specified */
  if (iv == NULL)
    memset(iv_buf, 0xA6, 8);
  else
    memcpy(iv_buf, iv, 8);

  SSH_XUINT64_GET(A, iv_buf);

  SSH_XUINT64_PUT(A, dest);
  memcpy(dest + 8, src, src_len);

  status = ssh_cipher_start(cipher);
  if (status != SSH_CRYPTO_OK)
    return status;

  for (j = 0; j <= 5; j++)
    {
      for (i = 0; i < src_len / 8; i++)
        {
          SSH_XUINT64_PUT(A, tmp);
          SSH_XUINT64_GET(X, dest + 8 + 8 * i);
          SSH_XUINT64_PUT(X, tmp + 8);

          status = ssh_cipher_transform(cipher, tmp, tmp, 16);

          if (status != SSH_CRYPTO_OK)
            return status;

          SSH_XUINT64_BUILD(X, ((src_len / 8) * j) + i + 1, 0);
          SSH_XUINT64_GET(A, tmp);
          SSH_XUINT64_XOR(A, A, X);

          SSH_XUINT64_GET(X, tmp + 8);
          SSH_XUINT64_PUT(X, dest + 8 + 8 * i);
        }
    }

  SSH_XUINT64_PUT(A, dest);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_aes_key_unwrap(SshCipher cipher,
                                   const unsigned char *iv,
                                   size_t iv_len,
                                   unsigned char *dest,
                                   size_t dest_len,
                                   const unsigned char *src,
                                   size_t src_len)
{
  SshCryptoStatus status;
  unsigned char iv_buf[8];
  unsigned char tmp[16];
  SshXUInt64 A, X;
  int i, j;

  if (!cipher || !ssh_cipher_name(cipher))
    return SSH_CRYPTO_OPERATION_FAILED;

  if (strcmp(ssh_cipher_name(cipher), "aes-ecb") &&
      strcmp(ssh_cipher_name(cipher), "aes128-ecb") &&
      strcmp(ssh_cipher_name(cipher), "aes192-ecb") &&
      strcmp(ssh_cipher_name(cipher), "aes256-ecb"))
    return SSH_CRYPTO_OPERATION_FAILED;

  /* Must have at least 3 64 bit blocks */
  if (src_len < 24)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  /* Input length must be a multiple of 64 bits */
  if (src_len % 8)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  if (dest_len != src_len - 8)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  if (iv != NULL && iv_len != 8)
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  /* Use default IV if none specified */
  if (iv == NULL)
    memset(iv_buf, 0xA6, 8);
  else
    memcpy(iv_buf, iv, 8);

  SSH_XUINT64_GET(A, src);
  memcpy(dest, src + 8, dest_len);

  status = ssh_cipher_start(cipher);
  if (status != SSH_CRYPTO_OK)
    return status;

  for (j = 5; j >= 0; j--)
    {
      for (i = dest_len / 8 - 1; i >= 0; i--)
        {
          SSH_XUINT64_BUILD(X, ((dest_len / 8) * j) + i + 1, 0);
          SSH_XUINT64_XOR(A, A, X);
          SSH_XUINT64_PUT(A, tmp);

          SSH_XUINT64_GET(X, dest + 8 * i);
          SSH_XUINT64_PUT(X, tmp + 8);

          status = ssh_cipher_transform(cipher, tmp, tmp, 16);

          if (status != SSH_CRYPTO_OK)
            return status;

          SSH_XUINT64_GET(A, tmp);

          SSH_XUINT64_GET(X, tmp + 8);
          SSH_XUINT64_PUT(X, dest + 8 * i);
        }
    }
  SSH_XUINT64_PUT(A, src);

  if (memcmp(iv_buf, src, 8))
    return SSH_CRYPTO_OPERATION_FAILED;

  return SSH_CRYPTO_OK;
}
