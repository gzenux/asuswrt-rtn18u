/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   PSS encoding using MGF1
*/

#include "sshincludes.h"
#ifdef SSHDIST_CRYPT_RSA
#include "sshcrypt.h"
#include "sshrgf.h"
#include "sshrgf-internal.h"
#include "rsa.h"

#define SSH_DEBUG_MODULE "SshCryptoRGF"

SshCryptoStatus
ssh_rsa_pss_encode_with_mgf1(const char *hash_name,
                             size_t salt_len,
                             size_t maximal_bit_length,
                             const unsigned char *msg_digest,
                             size_t msg_digest_len,
                             unsigned char *emsg, size_t emsg_len)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char *salt, *db, mask;
  unsigned char tmp[8];
  size_t db_len, digest_len;
  int i, bits;
  SshHash hash;
  SshCryptoStatus status;

  status = SSH_CRYPTO_OPERATION_FAILED;

  digest_len = ssh_hash_digest_length(hash_name);
  if (msg_digest_len != digest_len)
    return status;

  if ((maximal_bit_length + 7) / 8 != emsg_len)
    return status;

  if (maximal_bit_length < ((8 * msg_digest_len) + (8 * salt_len) + 9))
    return status;

  /* Allocate a context for the hash computation. */
  if ((status = ssh_hash_allocate(hash_name, &hash)) != SSH_CRYPTO_OK)
    return status;

  /* Generate a random salt. */
  if ((salt = ssh_malloc(salt_len)) == NULL)
    {
      ssh_hash_free(hash);
      return SSH_CRYPTO_NO_MEMORY;
    }
  for (i = 0; i < salt_len; i++) salt[i] = ssh_random_get_byte();

  memset(tmp, 0, sizeof(tmp));

  /* Update the hash with 8 bytes of zero padding, followed by the
     hash digest of the original message followed by the salt. */
  ssh_hash_update(hash, tmp, sizeof(tmp));
  ssh_hash_update(hash, msg_digest, msg_digest_len);
  ssh_hash_update(hash, salt, salt_len);

  if ((status = ssh_hash_final(hash, digest)) != SSH_CRYPTO_OK)
    {
      ssh_hash_free(hash);
      ssh_free(salt);
      return status;
    }

  db_len = emsg_len - digest_len - 1;
  if ((db = ssh_calloc(1, db_len)) == NULL)
    {
      ssh_hash_free(hash);
      ssh_free(salt);
      return SSH_CRYPTO_NO_MEMORY;
    }

  db[db_len - salt_len - 1] = 0x01;
  memcpy(db + db_len - salt_len, salt, salt_len);

  ssh_free(salt);

  if ((status = ssh_rsa_mgf1(hash_name, digest, digest_len, emsg, db_len))
      != SSH_CRYPTO_OK)
    {
      ssh_hash_free(hash);
      ssh_free(db);
      return status;
    }

  /* XOR. */
  for (i = 0; i < db_len; i++)
    emsg[i] ^= db[i];
  memset(db, 0, db_len);

  bits = (8 * emsg_len) - maximal_bit_length;
  SSH_ASSERT(bits < 8);

  mask = 0xff;
  if (bits)
    mask >>= bits;
  emsg[0] &= mask;

  memcpy(emsg + db_len, digest, digest_len);
  emsg[emsg_len - 1] = 0xbc;

  ssh_hash_free(hash);
  ssh_free(db);
  return SSH_CRYPTO_OK;
}

/* PSS decoding using MGF1. */
SshCryptoStatus
ssh_rsa_pss_decode_with_mgf1(const char *hash_name,
                             size_t salt_len,
                             size_t maximal_bit_length,
                             const unsigned char *msg_digest,
                             size_t msg_digest_len,
                             const unsigned char *emsg,
                             size_t emsg_len)
{
  unsigned char digest[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char *db = NULL, *salt, tmp[8], mask;
  unsigned int i, bits;
  size_t db_len, digest_len;
  SshHash hash;
  SshCryptoStatus status;


  if ((status = ssh_hash_allocate(hash_name, &hash)) != SSH_CRYPTO_OK)
    return status;

  digest_len = ssh_hash_digest_length(hash_name);

  status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

  if (maximal_bit_length < (8 * digest_len) + (8 * salt_len) + 9)
    goto failed;

  if (emsg[emsg_len - 1] != 0xbc)
    goto failed;

  if ((maximal_bit_length + 7) / 8 != emsg_len)
    goto failed;

  bits = (8 * emsg_len) - maximal_bit_length;
  SSH_ASSERT(bits < 8);

  mask = 0xff << (8 - bits);
  if (emsg[0] & mask)
    goto failed;

  db_len = emsg_len - digest_len - 1;
  if ((db = ssh_malloc(db_len)) == NULL)
    {
      status = SSH_CRYPTO_NO_MEMORY;
      goto failed;
    }

  if ((status = ssh_rsa_mgf1(hash_name,
                             emsg + emsg_len - digest_len - 1,
                             digest_len,
                             db, db_len))
      != SSH_CRYPTO_OK)
    {
      goto failed;
    }

  /* XOR. */
  for (i = 0; i < db_len; i++)
    db[i] ^= emsg[i];

  mask = 0xff >> bits;
  db[0] &= mask;

  for (i = 0; i < emsg_len - digest_len - salt_len - 2; i++)
    {
      if (db[i] != 0x0)
        {
          /* status was reset above */
          status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
          goto failed;
        }
    }

  if (db[i] != 0x1)
    {
      /* status was reset above */
      status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
      goto failed;
    }

  memset(tmp, 0, sizeof(tmp));
  salt = db + (db_len - salt_len);

  /* Update the hash with 8 bytes of zero padding, followed by the
     hash digest of the original message followed by the salt. */

  ssh_hash_update(hash, tmp, sizeof(tmp));
  ssh_hash_update(hash, msg_digest, msg_digest_len);
  ssh_hash_update(hash, salt, salt_len);

  if ((status = ssh_hash_final(hash, digest)) != SSH_CRYPTO_OK)
    goto failed;

  /* Compare the hash digests */
  if (memcmp(digest, emsg + emsg_len - digest_len - 1,
             digest_len))
    {
      /* status was reset above */
      status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    failed:
      ssh_hash_free(hash);
      ssh_free(db);
      return status;
    }

  ssh_hash_free(hash);
  ssh_free(db);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_pss_sign(SshRGF rgf, size_t key_size_in_bits,
                 unsigned char **output_msg, size_t *output_msg_len)
{
  unsigned char *buf, *digest = NULL;
  size_t digest_len, max_output_msg_len;
  SshCryptoStatus status;

  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_len))
      != SSH_CRYPTO_OK)
    return status;

  max_output_msg_len = ((key_size_in_bits - 1) + 7) / 8;

  if ((buf = ssh_calloc(1, max_output_msg_len)) == NULL)
    {
      ssh_free(digest);
      return SSH_CRYPTO_NO_MEMORY;
    }









  if ((status =
       ssh_rsa_pss_encode_with_mgf1(rgf->def->hash, 20,
                                    key_size_in_bits - 1,
                                    digest, digest_len,
                                    buf, max_output_msg_len)) != SSH_CRYPTO_OK)
    {
      ssh_free(digest);
      ssh_free(buf);
      return status;
    }

  ssh_free(digest);
  *output_msg = buf;
  *output_msg_len = max_output_msg_len;
  return SSH_CRYPTO_OK;
}


SshCryptoStatus ssh_rgf_pss_verify(SshRGF rgf, size_t key_size_in_bits,
                                   const unsigned char *decrypted_signature,
                                   size_t decrypted_signature_len)
{
  unsigned char *digest = NULL;
  size_t digest_len;
  SshCryptoStatus status;

  if (rgf->def->hash == NULL)
    return SSH_CRYPTO_INTERNAL_ERROR;

  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_len))
      != SSH_CRYPTO_OK)
    return status;

  /* The input to the PSS decode function should be an octet buffer of
     size (key_size_in_bits - 1 + 7) / 8. If there is an extra zero
     byte in the decrypted signature, then remove it here. */
  if (decrypted_signature_len > (key_size_in_bits - 1 + 7) / 8)
    {
      if (decrypted_signature[0] != 0)
        return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

      decrypted_signature++;
      decrypted_signature_len--;
    }

  if (decrypted_signature_len != (key_size_in_bits - 1 + 7) / 8)
    return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;









  if ((status =
       ssh_rsa_pss_decode_with_mgf1(rgf->def->hash, 20,
                                    key_size_in_bits - 1,
                                    digest, digest_len,
                                    decrypted_signature,
                                    decrypted_signature_len)) != SSH_CRYPTO_OK)
    {
      ssh_free(digest);
      return status;
    }

  ssh_free(digest);
  return SSH_CRYPTO_OK;
}

#define DEFPSS(hash)            \
  ssh_rgf_std_allocate,         \
  ssh_rgf_std_free,             \
  ssh_rgf_std_hash_update,      \
  ssh_rgf_std_hash_finalize,    \
  NULL_FNPTR,                   \
  NULL_FNPTR,                   \
  hash,                         \
  NULL_FNPTR,                   \
  NULL_FNPTR,                   \
  ssh_rgf_pss_sign,             \
  ssh_rgf_pss_verify

#define DEFPSSDIGEST(hash)      \
  ssh_rgf_std_allocate,         \
  ssh_rgf_std_free,             \
  ssh_rgf_ignore_hash_update,   \
  ssh_rgf_ignore_hash_finalize, \
  NULL_FNPTR,                   \
  NULL_FNPTR,                   \
  hash,                         \
  NULL_FNPTR,                   \
  NULL_FNPTR,                   \
  ssh_rgf_pss_sign,             \
  ssh_rgf_pss_verify


#ifdef SSHDIST_CRYPT_SHA256
const SshRGFDefStruct ssh_rgf_pss_sha256_def = { DEFPSS("sha256") };
const SshRGFDefStruct ssh_rgf_pss_sha256_no_hash_def =
  { DEFPSSDIGEST("sha256") };
const SshRGFDefStruct ssh_rgf_pss_sha224_def = { DEFPSS("sha224") };
const SshRGFDefStruct ssh_rgf_pss_sha224_no_hash_def =
  { DEFPSSDIGEST("sha224") };
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
const SshRGFDefStruct ssh_rgf_pss_sha512_def = { DEFPSS("sha512") };
const SshRGFDefStruct ssh_rgf_pss_sha512_no_hash_def =
  { DEFPSSDIGEST("sha512") };
const SshRGFDefStruct ssh_rgf_pss_sha384_def = { DEFPSS("sha384") };
const SshRGFDefStruct ssh_rgf_pss_sha384_no_hash_def =
  { DEFPSSDIGEST("sha384") };
#endif /* SSHDIST_CRYPT_SHA512 */
#ifdef SSHDIST_CRYPT_SHA
const SshRGFDefStruct ssh_rgf_pss_sha1_def = { DEFPSS("sha1") };
const SshRGFDefStruct ssh_rgf_pss_sha1_no_hash_def = { DEFPSSDIGEST("sha1") };
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_MD5
const SshRGFDefStruct ssh_rgf_pss_md5_def = { DEFPSS("md5") };
const SshRGFDefStruct ssh_rgf_pss_md5_no_hash_def = { DEFPSSDIGEST("md5") };
#endif /* SSHDIST_CRYPT_MD5 */
#endif /* SSHDIST_CRYPT_RSA */
