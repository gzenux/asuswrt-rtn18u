/**
   @copyright
   Copyright (c) 2006 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cipher routines for MSCAPI.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshgetput.h"
#ifdef SSHDIST_MSCAPI
#ifdef HAVE_MSCAPI_CRYPTO
#include <wincrypt.h>
#include "des.h"
#include "rijndael.h"

#define SSH_DEBUG_MODULE "SshMscapiCipher"

typedef struct {
  HCRYPTKEY session_key;
  HCRYPTPROV prov;
  Boolean for_encryption;
} SshMscapiCipherContext;


Boolean
mscapi_create_private_exponent_one_key(LPTSTR provider_name,
                                       DWORD provider_type,
                                       LPTSTR container_name,
                                       DWORD keyspec,
                                       HCRYPTPROV *prov,
                                       HCRYPTKEY *privatekey)
{
  Boolean result = FALSE;
  LPBYTE keyblob = NULL;
  DWORD keyblob_len, bit_len;
  BYTE *ptr;
  int count;


  *prov = 0;
  *privatekey = 0;

  if ((keyspec != AT_KEYEXCHANGE) && (keyspec != AT_SIGNATURE))
    goto operation_failed;

  /* Try to get a key container, either existing or new */
  result = CryptAcquireContext(prov, container_name, provider_name,
                               provider_type, 0);
  if (!result && GetLastError() == NTE_BAD_KEYSET)
    result = CryptAcquireContext(prov, container_name, provider_name,
                                 provider_type, CRYPT_NEWKEYSET);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,  ("CryptAcquireContext failed with error %x",
                              GetLastError()));
      goto operation_failed;
    }

  /* Generate the private key */
  result = CryptGenKey(*prov, keyspec, CRYPT_EXPORTABLE, privatekey);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptGenKey failed with error %x", GetLastError()));
      goto operation_failed;
    }

  /* Export the private key, we'll convert it to a private
     exponent of one key */
  result = CryptExportKey(*privatekey, 0, PRIVATEKEYBLOB,
                          0, NULL, &keyblob_len);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptExportKey failed with error %x", GetLastError()));
      goto operation_failed;
    }

  keyblob = (LPBYTE)ssh_malloc(keyblob_len);
  if (!keyblob)
    goto operation_failed;

  result = CryptExportKey(*privatekey, 0, PRIVATEKEYBLOB, 0, keyblob,
                          &keyblob_len);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptExportKey failed with error %x", GetLastError()));
      goto operation_failed;
    }

  CryptDestroyKey(*privatekey);
  *privatekey = 0;

  /* Get the bit length of the key */
  memcpy(&bit_len, &keyblob[12], 4);

  /* Modify the exponent in key BLOB format
     key BLOB format is documented in SDK */

  /* Convert pubexp in rsapubkey to 1 */
  ptr = &keyblob[16];
  for (count = 0; count < 4; count++)
    {
      if (count == 0)
        ptr[count] = 1;
      else
        ptr[count] = 0;
    }

  /* Skip pubexp */
  ptr += 4;
  /* Skip modulus, prime1, prime2 */
  ptr += (bit_len / 8);
  ptr += (bit_len / 16);
  ptr += (bit_len / 16);

  /* Convert exponent1 to 1 */
  for (count= 0; count < (bit_len / 16); count++)
    {
      if (count == 0)
        ptr[count] = 1;
      else
        ptr[count] = 0;
    }

  /* Skip exponent1 */
  ptr += (bit_len / 16);

  /* Convert exponent2 to 1 */
  for (count = 0; count < (bit_len / 16); count++)
    {
      if (count == 0)
        ptr[count] = 1;
      else
        ptr[count] = 0;
    }

  /* Skip exponent2, coefficient */
  ptr += (bit_len / 16);
  ptr += (bit_len / 16);

  /* Convert privateExponent to 1 */
  for (count = 0; count < (bit_len / 8); count++)
    {
      if (count == 0)
        ptr[count] = 1;
      else
        ptr[count] = 0;
    }
  /* Import the exponent-of-one private key */
  result = CryptImportKey(*prov, keyblob, keyblob_len, 0, 0, privatekey);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptImportKey failed with error %x", GetLastError()));
      goto operation_failed;
    }

  ssh_free(keyblob);
  return TRUE;

 operation_failed:

  if (keyblob)
    ssh_free(keyblob);
  if (*privatekey)
    CryptDestroyKey(*privatekey);
  if (*prov)
    {
      CryptReleaseContext(*prov, 0);
      *prov = 0;
    }
  return FALSE;
}


Boolean
mscapi_import_plain_session_blob(HCRYPTPROV prov, HCRYPTKEY privatekey,
                                 ALG_ID alg_id, const BYTE *keymaterial,
                                 DWORD keymaterial_len,
                                 HCRYPTKEY *sessionkey)
{
  Boolean result = FALSE;
  Boolean found = FALSE;
  LPBYTE sessionblob = NULL;
  DWORD sessionblob_len, size, n;
  DWORD publickeysize;
  DWORD provsessionkeysize;
  ALG_ID privkeyalg;
  LPBYTE ptr;
  DWORD flags = CRYPT_FIRST;
  PROV_ENUMALGS_EX provenum;
  HCRYPTKEY tempkey = 0;

  /* Double check to see if this provider supports
     this algorithm and key size */
  do
    {
      size = sizeof(provenum);
      result = CryptGetProvParam(prov, PP_ENUMALGS_EX, (LPBYTE)&provenum,
                                 &size, flags);
      if (!result)
        break;
      flags = 0;
      if (provenum.aiAlgid == alg_id)
        found = TRUE;

    } while (!found);

  if (!found)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Algorithm ID %d not found", alg_id));
      goto operation_failed;
    }

  /* We have to get the key size(including padding)
     from an HCRYPTKEY handle. PP_ENUMALGS_EX contains
     the key size without the padding so we can't use it */
  result = CryptGenKey(prov, alg_id, 0, &tempkey);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptGenKey failed with error %x", GetLastError()));
      goto operation_failed;
    }
  size = sizeof(DWORD);
  result = CryptGetKeyParam(tempkey, KP_KEYLEN, (LPBYTE)&provsessionkeysize,
                            &size, 0);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptGetKeyParam failed with error %x", GetLastError()));
      goto operation_failed;
    }

  CryptDestroyKey(tempkey);
  tempkey = 0;

  /* Our key is too big, leave */
  if ((keymaterial_len * 8) > provsessionkeysize)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Keymaterial length is greater than provider session key"));
      goto operation_failed;
    }

  /* Get private key's algorithm */
  size = sizeof(ALG_ID);
  result = CryptGetKeyParam(privatekey, KP_ALGID, (LPBYTE)&privkeyalg,
                            &size, 0);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptGetKeyParam failed with error %X", GetLastError()));
      goto operation_failed;
    }

  /* Get private key's length in bits */
  size = sizeof(DWORD);
  result = CryptGetKeyParam(privatekey, KP_KEYLEN, (LPBYTE)&publickeysize,
                            &size, 0);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptGetKeyParam failed with error %x", GetLastError()));
      goto operation_failed;
    }

  /* calculate Simple blob's length */
  sessionblob_len = (publickeysize / 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

  /* allocate simple blob buffer */
  sessionblob = (LPBYTE)ssh_calloc(sessionblob_len, sizeof(BYTE));
  if (!sessionblob)
    goto operation_failed;

  ptr = sessionblob;

  /* SIMPLEBLOB Format is documented in SDK. Copy header to buffer */
  ((BLOBHEADER *)ptr)->bType = SIMPLEBLOB;
  ((BLOBHEADER *)ptr)->bVersion = 2;
  ((BLOBHEADER *)ptr)->reserved = 0;
  ((BLOBHEADER *)ptr)->aiKeyAlg = alg_id;
  ptr += sizeof(BLOBHEADER);

  /* Copy private key algorithm to buffer */
  *((DWORD *)ptr) = privkeyalg;
  ptr += sizeof(ALG_ID);

  /* Place the key material in reverse order */
  for (n = 0; n < keymaterial_len; n++)
    {
      ptr[n] = keymaterial[keymaterial_len - n - 1];
    }

  /* 3 is for the first reserved byte after the key material + the 2
     reserved bytes at the end. */
  size = sessionblob_len -
    (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keymaterial_len + 3);
  ptr += (keymaterial_len + 1);

  /* Generate random data for the rest of the buffer (except that
     last two bytes) */
  result = CryptGenRandom(prov, size, ptr);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptGenRandom failed with error %x", GetLastError()));
      goto operation_failed;
    }
  for (n = 0; n < size; n++)
    {
      if (ptr[n] == 0)
        ptr[n] = 1;
    }

  sessionblob[sessionblob_len - 2] = 2;

  result = CryptImportKey(prov, sessionblob, sessionblob_len,
                          privatekey, CRYPT_EXPORTABLE, sessionkey);
  if (!result)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("CryptImportKey failed with error %x", GetLastError()));
      goto operation_failed;
    }

  ssh_free(sessionblob);
  return TRUE;

 operation_failed:

  if (tempkey)
    CryptDestroyKey(tempkey);
  if (sessionblob)
    ssh_free(sessionblob);
  return FALSE;
}


size_t mscapi_cipher_ctxsize(void)
{
  return sizeof(SshMscapiCipherContext);
}


SshCryptoStatus
mscapi_cipher_init(SshMscapiCipherContext *ctx,
                   const unsigned char *key, size_t keylen,
                   ALG_ID algid, Boolean for_encryption)
{
  HCRYPTKEY private_key;
  TCHAR *provider_name, *aes_provider_name;
  DWORD provider_type;

  memset(ctx, 0, sizeof(ctx));
  ctx->for_encryption = for_encryption;

  /* Workaround for the fact that for some reason, the AES-cabable
     crypto provider is named differently on Windows XP. */
  aes_provider_name = MS_ENH_RSA_AES_PROV;

  switch (algid)
    {
    case CALG_AES:
    case CALG_AES_128:
    case CALG_AES_192:
    case CALG_AES_256:
      provider_name = aes_provider_name;
      provider_type = PROV_RSA_AES;
      break;
    default:
      provider_name = MS_ENHANCED_PROV;
      provider_type = PROV_RSA_FULL;
      break;
    }

  if (!mscapi_create_private_exponent_one_key(provider_name,
                                              provider_type,
                                              NULL,
                                              AT_KEYEXCHANGE,
                                              &ctx->prov, &private_key))
    {
      SSH_DEBUG(SSH_D_FAIL,("create_private_exponent_one_key failed"));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Import this key and get an HCRYPTKEY handle */
  if (!mscapi_import_plain_session_blob(ctx->prov, private_key, algid,
                                        key, keylen, &ctx->session_key))
    {
      SSH_DEBUG(SSH_D_FAIL,("ssh_import_plain_session_blob failed algid=%d",
                            algid));

      CryptDestroyKey(private_key);
      CryptReleaseContext(ctx->prov, 0);
      ctx->prov = 0;
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  CryptDestroyKey(private_key);
  return SSH_CRYPTO_OK;
}


SshCryptoStatus mscapi_cipher_transform(SshMscapiCipherContext *ctx,
                                        DWORD mode,
                                        unsigned char *dest,
                                        const unsigned char *src,
                                        size_t len,
                                        unsigned char *iv_arg)
{
  DWORD return_len, input_len;
  Boolean for_encryption = ctx->for_encryption;

  if (mode == CRYPT_MODE_CFB || mode == CRYPT_MODE_OFB)
    for_encryption = TRUE;

  if (CryptSetKeyParam(ctx->session_key, KP_MODE, (PBYTE)&mode, 0) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot set keyparam %x", GetLastError()));
      goto failed;
    }

  /* set the initialization vector */
  if (CryptSetKeyParam(ctx->session_key, KP_IV, iv_arg, 0) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot set IV %x", GetLastError()));
      goto failed;
    }

  memmove(dest, src, len);

  input_len = (DWORD) len;
  return_len = (DWORD) len;

  if (for_encryption)
    {
      if (!CryptEncrypt(ctx->session_key, 0, FALSE, 0, dest, &return_len,
                        input_len))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("CryptEncrypt failed with error %x", GetLastError()));
          goto failed;
        }
    }
  else
    {
      if (!CryptDecrypt(ctx->session_key, 0, FALSE, 0, dest, &return_len))
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("CryptDecrypt failed with error %x",GetLastError()));
          goto failed;
        }
    }

  if (return_len != input_len)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Return length invalid %x", GetLastError()));
      goto failed;
    }

    return SSH_CRYPTO_OK;

 failed:
  SSH_DEBUG(SSH_D_FAIL, ("Cipher transform operation failed with error %x",
                         GetLastError()));
  return SSH_CRYPTO_OPERATION_FAILED;
}

void
mscapi_cipher_uninit(SshMscapiCipherContext *ctx)
{
  if (ctx->session_key)
    CryptDestroyKey(ctx->session_key);
  if (ctx->prov)
    {
      CryptReleaseContext(ctx->prov, 0);
      ctx->prov = 0;
    }
}


/* DES */

size_t ssh_des_ctxsize(void)
{
  return mscapi_cipher_ctxsize();
}


SshCryptoStatus
ssh_des_init(void *context,
             const unsigned char *key, size_t keylen,
             Boolean for_encryption)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  if (keylen < 8)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return mscapi_cipher_init(ctx, key, keylen, CALG_DES, for_encryption);
}

SshCryptoStatus
ssh_des_init_with_key_check(void *context,
                            const unsigned char *key, size_t keylen,
                            Boolean for_encryption)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  if (keylen < 8)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return mscapi_cipher_init(ctx, key, keylen, CALG_DES, for_encryption);
}


void ssh_des_uninit(void *context)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  mscapi_cipher_uninit(ctx);
}


SshCryptoStatus ssh_des_cbc(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  SshCryptoStatus status;
  SshUInt32 iv[2], c[2], v[2], temp_len;
  temp_len = 8;

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          if (len < temp_len)
            temp_len = len;
          iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
          iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);

          status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                        (unsigned char *)iv, (unsigned char *)iv, temp_len,
                        (unsigned char *)iv);

          if (status != SSH_CRYPTO_OK)
            return status;

          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1]);
          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          if (len < temp_len)
            temp_len = len;

          c[0] = SSH_GET_32BIT_LSB_FIRST(src);
          c[1] = SSH_GET_32BIT_LSB_FIRST(src + 4);

          status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                        (unsigned char *)v, (unsigned char *)c, temp_len,
                        (unsigned char *)iv);

          if (status != SSH_CRYPTO_OK)
            return status;

          v[0] ^= iv[0];
          iv[0] = c[0];
          v[1] ^= iv[1];
          iv[1] = c[1];

          SSH_PUT_32BIT_LSB_FIRST(dest, v[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, v[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  memset(iv, 0, sizeof(iv));
  return len ? SSH_CRYPTO_OPERATION_FAILED : SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des_ecb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

 return mscapi_cipher_transform(ctx, CRYPT_MODE_ECB, dest, src, len, iv_arg);
}


SshCryptoStatus ssh_des_cfb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

 return mscapi_cipher_transform(ctx, CRYPT_MODE_CFB, dest, src, len, iv_arg);
}


SshCryptoStatus ssh_des_ofb(void *context, unsigned char *dest,
                            const unsigned char *src, size_t len,
                            unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  return mscapi_cipher_transform(ctx, CRYPT_MODE_OFB, dest, src, len, iv_arg);
}

/* Triple des */

size_t ssh_des3_ctxsize(void)
{
  return mscapi_cipher_ctxsize();
}


SshCryptoStatus
ssh_des3_init(void *context,
             const unsigned char *key, size_t keylen,
             Boolean for_encryption)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  SSH_DEBUG(SSH_D_MY, ("3DES cipher init"));

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return mscapi_cipher_init(ctx, key, keylen, CALG_3DES, for_encryption);
}

SshCryptoStatus
ssh_des3_init_with_key_check(void *context,
                            const unsigned char *key, size_t keylen,
                            Boolean for_encryption)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  SSH_DEBUG(SSH_D_MY, ("3DES cipher init with key check"));

  if (keylen < 24)
    return SSH_CRYPTO_KEY_TOO_SHORT;

  return mscapi_cipher_init(ctx, key, keylen, CALG_3DES, for_encryption);
}

void ssh_des3_uninit(void *context)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  mscapi_cipher_uninit(ctx);
}

SshCryptoStatus ssh_des3_cbc(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  SshCryptoStatus status;
  SshUInt32 iv[2], c[2], v[2], temp_len;
  temp_len = 8;

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          if (len < temp_len)
            temp_len = len;
          iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
          iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);

          status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                        (unsigned char *)iv, (unsigned char *)iv, temp_len,
                        (unsigned char *)iv);

          if (status != SSH_CRYPTO_OK)
            return status;

          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1]);
          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  else
    {
      while (len > 0)
        {
          if (len < temp_len)
            temp_len = len;

          c[0] = SSH_GET_32BIT_LSB_FIRST(src);
          c[1] = SSH_GET_32BIT_LSB_FIRST(src + 4);

          status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                        (unsigned char *)v, (unsigned char *)c, temp_len,
                        (unsigned char *)iv);

          if (status != SSH_CRYPTO_OK)
            return status;

          v[0] ^= iv[0];
          iv[0] = c[0];
          v[1] ^= iv[1];
          iv[1] = c[1];

          SSH_PUT_32BIT_LSB_FIRST(dest, v[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, v[1]);

          src += 8;
          dest += 8;
          len -= 8;
        }
    }
  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  memset(iv, 0, sizeof(iv));
  return len ? SSH_CRYPTO_OPERATION_FAILED : SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_des3_ecb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

 return mscapi_cipher_transform(ctx, CRYPT_MODE_ECB, dest, src, len, iv_arg);
}


SshCryptoStatus ssh_des3_cfb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

 return mscapi_cipher_transform(ctx, CRYPT_MODE_CFB, dest, src, len, iv_arg);
}


SshCryptoStatus ssh_des3_ofb(void *context, unsigned char *dest,
                             const unsigned char *src, size_t len,
                             unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  return mscapi_cipher_transform(ctx, CRYPT_MODE_OFB, dest, src, len, iv_arg);
}

/* AES */

size_t ssh_rijndael_ctxsize(void)
{
  return mscapi_cipher_ctxsize();
}


SshCryptoStatus ssh_rijndael_init(void *context,
                                  const unsigned char *key,
                                  size_t keylen,
                                  Boolean for_encryption)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  ALG_ID alg_id;

  switch (keylen)
    {
    case 16:
      alg_id = CALG_AES_128;
      break;

    case 24:
      alg_id = CALG_AES_192;
      break;

    case 32:
      alg_id = CALG_AES_256;
      break;

    default:
      SSH_DEBUG(SSH_D_FAIL, ("Unsupported AES key size %d", keylen));
      return SSH_CRYPTO_UNSUPPORTED;
    }

 return mscapi_cipher_init(ctx, key, keylen, alg_id, for_encryption);
}

SshCryptoStatus ssh_rijndael_init_fb(void *context,
                                     const unsigned char *key,
                                     size_t keylen,
                                     Boolean for_encryption)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  SshCryptoStatus status;

  status = ssh_rijndael_init(context, key, keylen, TRUE);
  ctx->for_encryption = TRUE;

  return status;
}

void ssh_rijndael_uninit(void *context)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  mscapi_cipher_uninit(ctx);
}

SshCryptoStatus ssh_aes_init_fb(void *context,
                                const unsigned char *key,
                                size_t keylen,
                                Boolean for_encryption)
{
  return ssh_rijndael_init_fb(context, key, keylen, for_encryption);
}

SshCryptoStatus ssh_aes_init(void *context,
                             const unsigned char *key,
                             size_t keylen,
                             Boolean for_encryption)
{
  return ssh_rijndael_init(context, key, keylen, for_encryption);
}


void ssh_aes_uninit(void *context)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  mscapi_cipher_uninit(ctx);
}


SshCryptoStatus ssh_rijndael_cbc(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  SshCryptoStatus status;
  SshUInt32 iv[4], c[4], v[4], temp_len;
  temp_len = 16;

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 12);

  if (ctx->for_encryption)
    {
      while (len > 0)
        {
          if (len < temp_len)
            temp_len = len;
          iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
          iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);
          iv[2] ^= SSH_GET_32BIT_LSB_FIRST(src + 8);
          iv[3] ^= SSH_GET_32BIT_LSB_FIRST(src + 12);

          status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                        (unsigned char *)iv, (unsigned char *)iv, temp_len,
                        (unsigned char *)iv);

          if (status != SSH_CRYPTO_OK)
            return status;

          SSH_PUT_32BIT_LSB_FIRST(dest, iv[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, iv[1]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, iv[2]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, iv[3]);
          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  else
    {
      while (len > 0)
        {
          if (len < temp_len)
            temp_len = len;

          c[0] = SSH_GET_32BIT_LSB_FIRST(src);
          c[1] = SSH_GET_32BIT_LSB_FIRST(src + 4);
          c[2] = SSH_GET_32BIT_LSB_FIRST(src + 8);
          c[3] = SSH_GET_32BIT_LSB_FIRST(src + 12);

          status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                        (unsigned char *)v, (unsigned char *)c, temp_len,
                        (unsigned char *)iv);

          if (status != SSH_CRYPTO_OK)
            return status;

          v[0] ^= iv[0];
          iv[0] = c[0];
          v[1] ^= iv[1];
          iv[1] = c[1];
          v[2] ^= iv[2];
          iv[2] = c[2];
          v[3] ^= iv[3];
          iv[3] = c[3];

          SSH_PUT_32BIT_LSB_FIRST(dest, v[0]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 4, v[1]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 8, v[2]);
          SSH_PUT_32BIT_LSB_FIRST(dest + 12, v[3]);

          src += 16;
          dest += 16;
          len -= 16;
        }
    }
  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 8, iv[2]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 12, iv[3]);

  memset(iv, 0, sizeof(iv));
  return len ? SSH_CRYPTO_OPERATION_FAILED : SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rijndael_ecb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  return mscapi_cipher_transform(ctx, CRYPT_MODE_ECB, dest, src, len, iv_arg);
}


SshCryptoStatus ssh_rijndael_cfb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  return mscapi_cipher_transform(ctx, CRYPT_MODE_CFB, dest, src, len, iv_arg);
}


SshCryptoStatus ssh_rijndael_ofb(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;

  return mscapi_cipher_transform(ctx, CRYPT_MODE_OFB, dest, src, len, iv_arg);
}


/* Convert from big endian to little endian. */
#define SSH_MSB_TO_LSB(A) \
 ((((A) & 0xff000000) >> 24) | (((A) & 0xff0000) >> 8) | \
 (((A) & 0xff00) << 8) | (((A) & 0xff) << 24))

SshCryptoStatus ssh_rijndael_ctr(void *context, unsigned char *dest,
                                 const unsigned char *src, size_t len,
                                 unsigned char *ctr_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  unsigned char zero_iv[16];
  SshUInt32 t, iv[4], ctr[4];
  SshCryptoStatus status;

  memset(zero_iv, 0, sizeof(zero_iv));

  iv[0] = SSH_GET_32BIT_LSB_FIRST(ctr_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(ctr_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(ctr_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(ctr_arg + 12);

  ctr[0] = SSH_GET_32BIT(ctr_arg);
  ctr[1] = SSH_GET_32BIT(ctr_arg + 4);
  ctr[2] = SSH_GET_32BIT(ctr_arg + 8);
  ctr[3] = SSH_GET_32BIT(ctr_arg + 12);

  while (len >= 16)
    {
      status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                                       (unsigned char *)iv,
                                       (unsigned char *)iv, 16, zero_iv);
      if (status != SSH_CRYPTO_OK)
        return status;

      t = SSH_GET_32BIT_LSB_FIRST(src) ^ iv[0];
      SSH_PUT_32BIT_LSB_FIRST(dest, t);
      t = SSH_GET_32BIT_LSB_FIRST(src + 4) ^ iv[1];
      SSH_PUT_32BIT_LSB_FIRST(dest + 4, t);
      t = SSH_GET_32BIT_LSB_FIRST(src + 8) ^ iv[2];
      SSH_PUT_32BIT_LSB_FIRST(dest + 8, t);
      t = SSH_GET_32BIT_LSB_FIRST(src + 12) ^ iv[3];
      SSH_PUT_32BIT_LSB_FIRST(dest + 12, t);

      src += 16;
      dest += 16;
      len -= 16;
      /* Increment the counter by 1 (treated as a MSB first integer). */
      if (++ctr[3] == 0)
        if (++ctr[2] == 0)
          if (++ctr[1] == 0)
            ++ctr[0];

      iv[0] = SSH_MSB_TO_LSB(ctr[0]);
      iv[1] = SSH_MSB_TO_LSB(ctr[1]);
      iv[2] = SSH_MSB_TO_LSB(ctr[2]);
      iv[3] = SSH_MSB_TO_LSB(ctr[3]);
    }


  /* Encrypt the last block (which may be less than 16 bytes) */
  if (len)
    {
      unsigned char tmp[16];

      SSH_ASSERT(len < 16);

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, src, len);

      status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                                       (unsigned char *)iv,
                                       (unsigned char *)iv, 16, zero_iv);

      if (status != SSH_CRYPTO_OK)
        return status;

      t = SSH_GET_32BIT_LSB_FIRST(tmp) ^ iv[0];
      SSH_PUT_32BIT_LSB_FIRST(tmp, t);
      t = SSH_GET_32BIT_LSB_FIRST(tmp + 4) ^ iv[1];
      SSH_PUT_32BIT_LSB_FIRST(tmp + 4, t);
      t = SSH_GET_32BIT_LSB_FIRST(tmp + 8) ^ iv[2];
      SSH_PUT_32BIT_LSB_FIRST(tmp + 8, t);
      t = SSH_GET_32BIT_LSB_FIRST(tmp + 12) ^ iv[3];
      SSH_PUT_32BIT_LSB_FIRST(tmp + 12, t);

     memcpy(dest, tmp, len);

     /* Increment the counter by 1 (treated as a MSB first integer). */
     if (++ctr[3] == 0)
       if (++ctr[2] == 0)
         if (++ctr[1] == 0)
           ++ctr[0];
    }

  /* Set the new counter value. */
  SSH_PUT_32BIT(ctr_arg, ctr[0]);
  SSH_PUT_32BIT(ctr_arg + 4, ctr[1]);
  SSH_PUT_32BIT(ctr_arg + 8, ctr[2]);
  SSH_PUT_32BIT(ctr_arg + 12, ctr[3]);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rijndael_cbc_mac(void *context, const unsigned char *src, size_t len,
                     unsigned char *iv_arg)
{
  SshMscapiCipherContext *ctx = (SshMscapiCipherContext *) context;
  SshCryptoStatus status;
  unsigned char zero_iv[16];
  SshUInt32 iv[4];

  memset(zero_iv, 0, sizeof(zero_iv));

  iv[0] = SSH_GET_32BIT_LSB_FIRST(iv_arg);
  iv[1] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 4);
  iv[2] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 8);
  iv[3] = SSH_GET_32BIT_LSB_FIRST(iv_arg + 12);

  while (len >= 16)
    {
      iv[0] ^= SSH_GET_32BIT_LSB_FIRST(src);
      iv[1] ^= SSH_GET_32BIT_LSB_FIRST(src + 4);
      iv[2] ^= SSH_GET_32BIT_LSB_FIRST(src + 8);
      iv[3] ^= SSH_GET_32BIT_LSB_FIRST(src + 12);

      status = mscapi_cipher_transform(ctx, CRYPT_MODE_ECB,
                                       (unsigned char *)iv,
                                       (unsigned char *)iv, 16, zero_iv);

      if (status != SSH_CRYPTO_OK)
        return status;

      src += 16;
      len -= 16;
    }

  SSH_PUT_32BIT_LSB_FIRST(iv_arg, iv[0]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 4, iv[1]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 8, iv[2]);
  SSH_PUT_32BIT_LSB_FIRST(iv_arg + 12, iv[3]);

  return len ? SSH_CRYPTO_OPERATION_FAILED : SSH_CRYPTO_OK;
}

#endif /* HAVE_MSCAPI_CRYPTO */
#endif /* SSHDIST_MSCAPI */
