/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   OAEP encryption for RSA
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshrgf.h"
#include "sshrgf-internal.h"
#include "rsa.h"

#define SSH_DEBUG_MODULE "SshCryptoRGF"

SshCryptoStatus
ssh_rsa_oaep_encode_with_mgf1(const char *hash_name,
                              const unsigned char *msg,
                              size_t msg_len,
                              const unsigned char *param,
                              size_t param_len,
                              unsigned char *emsg, size_t emsg_len)
{
  unsigned char *db;
  unsigned char seed[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t db_len, i, digest_len;
  SshHash hash;
  SshCryptoStatus status;

  if ((status = ssh_hash_allocate(hash_name, &hash)) != SSH_CRYPTO_OK)
    return status;

  digest_len = ssh_hash_digest_length(hash_name);

  /* Check that the size constraints are satisfied. */
  if (msg_len > emsg_len - 2 * digest_len - 1)
    {
      ssh_hash_free(hash);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* This is: emLen - ||M|| - 2hLen - 1  + hLen + 1 + ||M|| =
     emLen - hLen. */
  db_len = emsg_len - digest_len;
  if ((db = ssh_calloc(1, db_len)) == NULL)
    {
      ssh_hash_free(hash);
      return SSH_CRYPTO_NO_MEMORY;
    }

  ssh_hash_update(hash, param, param_len);
  if ((status = ssh_hash_final(hash, db)) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(hash);
      return status;
    }

  /* Add the "01" before the last msg_len bytes. */
  db[db_len - msg_len - 1] = 0x1;

  /* Now throw in the msg. */
  memcpy(db + db_len - msg_len, msg, msg_len);

  /* Generate a random octet string. */
  for (i = 0; i < digest_len; i++)
    seed[i] = ssh_random_get_byte();

  /* Now use the MGF1. */
  if ((status = ssh_rsa_mgf1(hash_name,
                             seed, digest_len,
                             emsg + digest_len, db_len))
      != SSH_CRYPTO_OK)
    {
      ssh_hash_free(hash);
      ssh_free(db);
      return status;
    }

  /* Xor. */
  for (i = 0; i < db_len; i++)
    emsg[digest_len + i] ^= db[i];
  memset(db, 0, db_len);

  /* Use MGF1 again. */
  if ((status = ssh_rsa_mgf1(hash_name,
                             emsg + digest_len, db_len,
                             emsg, digest_len))
      != SSH_CRYPTO_OK)
    {
      ssh_hash_free(hash);
      ssh_free(db);
      return status;
    }

  /* Xor the seed. */
  for (i = 0; i < digest_len; i++)
    emsg[i] ^= seed[i];
  memset(seed, 0, digest_len);

  /* Now free the allocated information. */
  ssh_hash_free(hash);
  ssh_free(db);

  return SSH_CRYPTO_OK;
}

/* OAEP decode using MGF1. */
SshCryptoStatus
ssh_rsa_oaep_decode_with_mgf1(const char *hash_name,
                              const unsigned char *emsg,
                              size_t emsg_len,
                              const unsigned char *param,
                              size_t param_len,
                              unsigned char **msg, size_t *msg_len)
{
  unsigned char  seed[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char  phash[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char *db = NULL;
  size_t         db_len, i, digest_len;
  SshHash hash;
  SshCryptoStatus status;

  if ((status = ssh_hash_allocate(hash_name, &hash)) != SSH_CRYPTO_OK)
    return status;

  digest_len = ssh_hash_digest_length(hash_name);

  if (emsg_len < 2 * digest_len + 1)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto failed;
    }

  /* Allocate enough working buffers. */
  db_len = emsg_len - digest_len;
  if ((db = ssh_malloc(db_len)) == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      goto failed;
    }

  /* Use the mgf. */
  if ((status = ssh_rsa_mgf1(hash_name, emsg + digest_len, db_len,
                             seed, digest_len))
      != SSH_CRYPTO_OK)
    {
      goto failed;
    }

  /* Now xor. */
  for (i = 0; i < digest_len; i++)
    seed[i] ^= emsg[i];

  /* Use the mgf again. */
  if ((status = ssh_rsa_mgf1(hash_name, seed, digest_len, db, db_len))
      != SSH_CRYPTO_OK)
    {
      goto failed;
    }

  /* Now xor again. */
  for (i = 0; i < db_len; i++)
    db[i] ^= emsg[digest_len + i];

  ssh_hash_update(hash, param, param_len);
  if ((status = ssh_hash_final(hash, phash)) != SSH_CRYPTO_OK)
    {
      goto failed;
    }

  /* Do the check. */
  if (memcmp(db, phash, digest_len) != 0)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto failed;
    }

  for (i = digest_len; i < db_len; i++)
    {
      if (db[i] != 0)
        {
          if (db[i] != 0x1)
            {
              status = SSH_CRYPTO_OPERATION_FAILED;
              goto failed;
            }
          break;
        }
    }
  if (i >= db_len)
    {
      status = SSH_CRYPTO_OPERATION_FAILED;
      goto failed;
    }

  /* Now we must have db[i] == 0x1. */
  *msg_len = db_len - i - 1;
  if ((*msg = ssh_malloc(*msg_len)) == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      goto failed;
    }
  memcpy(*msg, db + i + 1, *msg_len);
  status = SSH_CRYPTO_OK;

failed:
  ssh_hash_free(hash);
  ssh_free(db);

  return status;
}

/* Note: this should be changed to take the hash function as an argument.
   Indeed, even more nicely take the MGF as an argument. */
size_t ssh_rsa_public_key_max_oaep_encrypt_input_len(const void *public_key,
                                                     SshRGF rgf)
{
  const SshRSAPublicKey *pub = public_key;
  size_t len = ((pub->bits + 7)/8 - 2 - 2 * ssh_rgf_hash_digest_length(rgf));

  SSH_DEBUG(7, ("The max OAEP public key encrypt input len is %d "
                "with key size %d and digest length %d", len,
                pub->bits, ssh_rgf_hash_digest_length(rgf)));

  if (len > 0 && len < SSH_RSA_MAX_BYTES)
    return len;
  return 0;
}

/* RSA PKCS-1 v2.0 */

SshCryptoStatus
ssh_rgf_pkcs1v2_encrypt(SshRGF rgf, size_t key_size_in_bits,
                        const unsigned char *msg, size_t msg_len,
                        unsigned char **output_msg,
                        size_t *output_msg_len)
{
  unsigned char *param, *buf;
  size_t param_len, max_output_msg_len;
  SshCryptoStatus status;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if (rgf->def->hash == NULL)
    return SSH_CRYPTO_OPERATION_FAILED;

  param = ssh_rsa_pkcs1v2_default_explicit_param(rgf->def->hash,
                                                 &param_len);
  if (param == NULL)
    return SSH_CRYPTO_OPERATION_FAILED;

  if (max_output_msg_len == 0)
    {
      ssh_free(param);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    {
      ssh_free(param);
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* Initialize the highest octet. */
  buf[0] = 0;
  if ((status = ssh_rsa_oaep_encode_with_mgf1(rgf->def->hash,
                                              msg, msg_len,
                                              param, param_len,
                                              buf+1, max_output_msg_len-1))
      != SSH_CRYPTO_OK)
    {
      ssh_free(param);
      ssh_free(buf);
      return status;
    }
  ssh_free(param);

  *output_msg = buf;
  *output_msg_len = max_output_msg_len;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_pkcs1v2_decrypt(SshRGF rgf, size_t key_size_in_bits,
                        const unsigned char *decrypted_msg,
                        size_t decrypted_msg_len,
                        unsigned char **output_msg,
                        size_t *output_msg_len)
{
  unsigned char *param;
  size_t param_len;
  SshCryptoStatus status;

  if (rgf->def->hash == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No hash defined for rgf"));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  if (decrypted_msg_len == 0 ||
      decrypted_msg[0] != 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Invalid input"));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Find params. */
  param = ssh_rsa_pkcs1v2_default_explicit_param(rgf->def->hash,
                                                 &param_len);
  if (param == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("No parameter found for rgf"));
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Apply the OAEP decoding. */
  if ((status =
       ssh_rsa_oaep_decode_with_mgf1(rgf->def->hash,
                                     decrypted_msg+1, decrypted_msg_len-1,
                                     param, param_len,
                                     output_msg, output_msg_len))
      != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("RSA OAEP decoding failed"));
      ssh_free(param);
      return status;
    }

  ssh_free(param);
  return SSH_CRYPTO_OK;
}

/* RSA PKCS-1 v2.0 */

const SshRGFDefStruct ssh_rgf_pkcs1v2_sha256_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "sha256",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};

const SshRGFDefStruct ssh_rgf_pkcs1v2_sha224_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "sha224",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};


#ifdef SSHDIST_CRYPT_SHA512
const SshRGFDefStruct ssh_rgf_pkcs1v2_sha512_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "sha512",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};

const SshRGFDefStruct ssh_rgf_pkcs1v2_sha384_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "sha384",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};
#endif /* SSHDIST_CRYPT_SHA512 */

const SshRGFDefStruct ssh_rgf_pkcs1v2_sha1_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "sha1",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};

const SshRGFDefStruct ssh_rgf_pkcs1v2_md5_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "md5",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};
const SshRGFDefStruct ssh_rgf_pkcs1v2_md2_def =
{
  ssh_rgf_std_allocate,
  ssh_rgf_std_free,

  ssh_rgf_std_hash_update,
  ssh_rgf_std_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  "md2",

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign,
  ssh_rgf_pkcs1_verify
};
const SshRGFDefStruct ssh_rgf_pkcs1v2_none_def =
{
  ssh_rgf_none_allocate,
  ssh_rgf_none_free,

  ssh_rgf_none_hash_update,
  ssh_rgf_none_hash_finalize,
  ssh_rgf_hash_asn1_oid_compare,
  ssh_rgf_hash_asn1_oid_generate,
  NULL,

  ssh_rgf_pkcs1v2_encrypt,
  ssh_rgf_pkcs1v2_decrypt,
  ssh_rgf_pkcs1_sign_nohash,
  ssh_rgf_pkcs1_verify_nohash
};
