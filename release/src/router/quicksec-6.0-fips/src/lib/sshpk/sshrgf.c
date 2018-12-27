/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A library for redundancy generation functions for specific
   algorithms.  This file contains general purpose and PKCS#1v1.5
   related code. See sshrgf-pss.c and sshrgf-oaep.c for more.
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshrgf.h"
#include "sshrgf-internal.h"
#ifdef SSHDIST_CRYPT_RSA
#include "pkcs1.h"
#endif /* SSHDIST_CRYPT_RSA */

#define SSH_DEBUG_MODULE "SshCryptoRGF"

#define SSH_RGF_MAXLEN  0xffffffff

struct SshRgfRestrictedAlg {
  char *sign;
  int hash_id;
};

static struct SshRgfRestrictedAlg const rgf_restricted_alg[] =
  {
    {"sha1", SSH_RGF_HASH_SHA1},
    /* Other signing algorithms not considered. */
    { NULL }
  };


/************** RGF's that have a standard hash function. ***********/

SshRGF ssh_rgf_std_allocate(const SshRGFDefStruct *def)
{
  SshRGF created;
  SshCryptoStatus status;

  if (def == NULL || def->hash == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("No hash definition."));
      return NULL;
    }

  if ((created = ssh_calloc(1, sizeof(*created))) != NULL)
    {
      SshHash hash;

      created->def = def;

      if ((status =
           ssh_hash_allocate(def->hash, &hash))
          != SSH_CRYPTO_OK)
        {
          ssh_free(created);
          return NULL;
        }

      created->context = hash;
      ssh_hash_reset(created->context);
    }
  return created;
}

void ssh_rgf_std_free(SshRGF rgf)
{
  ssh_hash_free(rgf->context);
  ssh_free(rgf);
}

SshCryptoStatus ssh_rgf_std_hash_update(SshRGF rgf,
                                        Boolean for_digest,
                                        const unsigned char *data,
                                        size_t data_len)
{
  size_t digest_len;

  /* Handle the case when possibly setting the finalized digest
     beforehand. */
  if (for_digest)
    {
      digest_len = ssh_hash_digest_length(rgf->def->hash);
      if (digest_len == data_len)
        {
          /* This does not allocate new space for the data. */
          rgf->precomp_digest        = data;
          rgf->precomp_digest_length = data_len;
          return SSH_CRYPTO_OK;
        }
      return (data_len < digest_len)
        ? SSH_CRYPTO_DATA_TOO_SHORT : SSH_CRYPTO_DATA_TOO_LONG;
    }

  if (rgf->precomp_digest)
    return SSH_CRYPTO_INTERNAL_ERROR; /* called twice, program error */

  ssh_hash_update(rgf->context, data, data_len);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rgf_ignore_hash_update(SshRGF rgf,
                                           Boolean for_digest,
                                           const unsigned char *data,
                                           size_t data_len)
{
  size_t digest_len = ssh_hash_digest_length(rgf->def->hash);

  if (digest_len != data_len)
    return (data_len < digest_len)
      ? SSH_CRYPTO_DATA_TOO_SHORT : SSH_CRYPTO_DATA_TOO_LONG;

  /* This does not allocate new space for the data. */
  rgf->precomp_digest        = data;
  rgf->precomp_digest_length = data_len;
  return SSH_CRYPTO_OK;
}

Boolean
ssh_rgf_restricted_signature_algorithm(const char *sign, int hash_id)
{
  unsigned int i;

  for (i = 0; rgf_restricted_alg[i].sign; i++)
    {
      if (sign != NULL)
        {
          if (rgf_restricted_alg[i].sign != NULL &&
              strcmp(sign, rgf_restricted_alg[i].sign) == 0)
            return TRUE;
        }
      if (hash_id != 0)
        {
          if (hash_id == rgf_restricted_alg[i].hash_id)
            return TRUE;
        }
    }

  return FALSE;
}

SshCryptoStatus ssh_rgf_pkcs1_hash_finalize_implicit(SshRGF rgf,
                                                     unsigned char **digest,
                                                     size_t *digest_length)
{
  SshHash hash;
  char *hash_name = NULL;
  unsigned char *buf;
  size_t buflen;
  SshCryptoStatus status;

  *digest = NULL;
  *digest_length = 0;

  if (rgf->def == &ssh_rgf_pkcs1_restricted_def &&
      ssh_rgf_restricted_signature_algorithm(NULL, rgf->hash_id) == TRUE)
        return SSH_CRYPTO_INTERNAL_ERROR;

  switch (rgf->hash_id)
    {
    case SSH_RGF_HASH_SHA1:
      hash_name = "sha1";
      break;
    case SSH_RGF_HASH_SHA224:
      hash_name = "sha224";
      break;
    case SSH_RGF_HASH_SHA256:
      hash_name = "sha256";
      break;
    case SSH_RGF_HASH_SHA384:
      hash_name = "sha384";
      break;
    case SSH_RGF_HASH_SHA512:
      hash_name = "sha512";
      break;
    case SSH_RGF_HASH_MD5:
      hash_name = "md5";
      break;
    case SSH_RGF_HASH_MD4:
      hash_name = "md4";
      break;
    case SSH_RGF_HASH_MD2:
      hash_name = "md2";
      break;
    case SSH_RGF_HASH_RIPEMED128:
      hash_name = "ripemd128";
      break;
    case SSH_RGF_HASH_RIPEMD160:
      hash_name = "ripemd160";
      break;
    default:
      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  if ((status = ssh_hash_allocate(hash_name, &hash)) != SSH_CRYPTO_OK)
    return status;

  buflen = ssh_hash_digest_length(hash_name);
  if ((buf = ssh_malloc(buflen)) == NULL)
    {
      ssh_hash_free(hash);
      return SSH_CRYPTO_NO_MEMORY;
    }

  ssh_hash_update(hash, rgf->precomp_digest, rgf->precomp_digest_length);

  if ((status = ssh_hash_final(hash, buf)) != SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      ssh_hash_free(hash);
      return status;
    }

  *digest = buf;
  *digest_length = buflen;
  ssh_hash_free(hash);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rgf_std_hash_finalize(SshRGF rgf,
                                          unsigned char **digest,
                                          size_t *digest_length)
{
  unsigned char *buf;
  size_t buflen;
  SshCryptoStatus status;

  *digest = NULL;
  *digest_length = 0;

  buflen = ssh_hash_digest_length(rgf->def->hash);

  if ((buf = ssh_malloc(buflen)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  if (rgf->precomp_digest)
    {
      SSH_ASSERT(rgf->precomp_digest_length == buflen);
      memcpy(buf, rgf->precomp_digest, rgf->precomp_digest_length);
    }
  else
    {
      if ((status = ssh_hash_final(rgf->context, buf)) != SSH_CRYPTO_OK)
        {
          ssh_free(buf);
          return status;
        }
    }

  *digest = buf;
  *digest_length = buflen;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rgf_ignore_hash_finalize(SshRGF rgf,
                                             unsigned char **digest,
                                             size_t *digest_length)
{
  unsigned char *buf;
  size_t buflen;

  *digest = NULL;
  *digest_length = 0;

  if (rgf->precomp_digest)
    {
      buflen = rgf->precomp_digest_length;

      if ((buf = ssh_malloc(buflen)) == NULL)
        return SSH_CRYPTO_NO_MEMORY;

      memcpy(buf, rgf->precomp_digest, rgf->precomp_digest_length);
      *digest = buf;
      *digest_length = buflen;
      return SSH_CRYPTO_OK;
    }
  else
    {
      return SSH_CRYPTO_INTERNAL_ERROR;
    }
}


size_t
ssh_rgf_hash_asn1_oid_compare(SshRGF rgf,
                              const unsigned char *oid,
                              size_t max_len)
{
  if (rgf->def->hash)
    return ssh_hash_asn1_oid_compare(rgf->def->hash, oid, max_len);
  else
    return 0;
}

const unsigned char *
ssh_rgf_hash_asn1_oid_generate(SshRGF rgf, size_t *len)
{
  if (len) *len = 0;
  if (rgf->def->hash)
    return ssh_hash_asn1_oid_generate(rgf->def->hash, len);
  else
    return NULL;
}

/************** RGF's that have no standard hash function. ***********/

SshRGF ssh_rgf_none_allocate(const SshRGFDefStruct *def)
{
  SshRGF created = NULL;

  if (def == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR, ("No hash definition."));
      return NULL;
    }

  if ((created = ssh_calloc(1, sizeof(*created))) != NULL)
    created->def = def;

  return created;
}

void ssh_rgf_none_free(SshRGF rgf)
{
  ssh_free(rgf);
}

SshCryptoStatus ssh_rgf_none_hash_update(SshRGF rgf,
                                         Boolean for_digest,
                                         const unsigned char *data,
                                         size_t data_len)
{
  rgf->precomp_digest        = data;
  rgf->precomp_digest_length = data_len;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rgf_none_hash_finalize(SshRGF rgf,
                                           unsigned char **digest,
                                           size_t *digest_length)
{
  unsigned char *buf;
  size_t buflen;

  *digest = NULL;
  *digest_length = 0;

  if (!rgf->precomp_digest)
    return SSH_CRYPTO_INTERNAL_ERROR;

  buflen = rgf->precomp_digest_length;

  if ((buf = ssh_malloc(buflen)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  memcpy(buf, rgf->precomp_digest, rgf->precomp_digest_length);
  *digest = buf;
  *digest_length = buflen;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rgf_none_hash_finalize_no_allocate(SshRGF rgf,
                                                       unsigned char **digest,
                                                       size_t *digest_length)
{
  *digest  = (unsigned char *) rgf->precomp_digest;
  *digest_length = rgf->precomp_digest_length;
  return SSH_CRYPTO_OK;
}

#ifdef SSHDIST_CRYPT_RSA

/* RSA PKCS-1 v1.5 */

/* Some useful routines doing the dirty work. */
SshCryptoStatus
ssh_rgf_pkcs1_encrypt(SshRGF rgf, size_t key_size_in_bits,
                      const unsigned char *msg, size_t msg_len,
                      unsigned char **output_msg,
                      size_t *output_msg_len)
{
  unsigned char *buf;
  size_t max_output_msg_len;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  if (!ssh_pkcs1_pad(msg, msg_len, 2, buf, max_output_msg_len))
    {
      ssh_free(buf);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  *output_msg     = buf;
  *output_msg_len = max_output_msg_len;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_pkcs1_decrypt(SshRGF rgf, size_t key_size_in_bits,
                      const unsigned char *decrypted_msg,
                      size_t decrypted_msg_len,
                      unsigned char **output_msg,
                      size_t *output_msg_len)
{
  unsigned char *buf;
  size_t max_output_msg_len, buf_len;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  if (!ssh_pkcs1_unpad(decrypted_msg, decrypted_msg_len, 2,
                       buf, max_output_msg_len, &buf_len))
    {
      ssh_free(buf);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Return the unpadded msg. */
  *output_msg     = buf;
  *output_msg_len = buf_len;
  return SSH_CRYPTO_OK;
}

static SshCryptoStatus
rgf_pkcs1_sign(Boolean do_padding, SshRGF rgf, size_t max_output_msg_len,
               unsigned char **output_msg, size_t *output_msg_len)
{
  unsigned char *digest, *buf;
  const unsigned char *encoded_oid;
  size_t digest_len, encoded_oid_len;
  Boolean rv = FALSE;
  SshCryptoStatus status;

  encoded_oid = (*rgf->def->rgf_hash_asn1_oid_generate)(rgf, &encoded_oid_len);
  if (encoded_oid == NULL || encoded_oid_len == 0)
    return SSH_CRYPTO_OPERATION_FAILED;

  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_len))
      != SSH_CRYPTO_OK)
    return status;

  if ((buf = ssh_calloc(1, max_output_msg_len)) == NULL)
    {
      ssh_free(digest);
      return SSH_CRYPTO_NO_MEMORY;
    }

  if (do_padding)
    {
      rv = ssh_pkcs1_wrap_and_pad(encoded_oid, encoded_oid_len,
                                  digest, digest_len, 1,
                                  buf, max_output_msg_len);
    }
  else
    {
      if (max_output_msg_len < digest_len + encoded_oid_len)
        {
          rv = FALSE;
        }
      else
        {
          memcpy(buf, encoded_oid, encoded_oid_len);
          memcpy(buf + encoded_oid_len, digest, digest_len);
          rv = TRUE;
        }
    }

  ssh_free(digest);

  if (rv)
    {
      *output_msg     = buf;
      *output_msg_len = max_output_msg_len;
      return SSH_CRYPTO_OK;
    }

  ssh_free(buf);
  return SSH_CRYPTO_OPERATION_FAILED;
}


SshCryptoStatus
ssh_rgf_pkcs1_nopad_sign(SshRGF rgf, size_t key_size_in_bits,
                         unsigned char **output_msg, size_t *output_msg_len)
{
  size_t max_output_msg_len;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  return rgf_pkcs1_sign(FALSE, rgf, max_output_msg_len,
                        output_msg, output_msg_len);
}

SshCryptoStatus
ssh_rgf_pkcs1_sign(SshRGF rgf, size_t key_size_in_bits,
                   unsigned char **output_msg, size_t *output_msg_len)
{
  size_t max_output_msg_len;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  return rgf_pkcs1_sign(TRUE, rgf, max_output_msg_len,
                        output_msg, output_msg_len);
}


static SshCryptoStatus
rgf_pkcs1_verify(Boolean do_unpad,
                 SshRGF rgf,
                 const unsigned char *decrypted_signature,
                 size_t decrypted_signature_len)
{
  unsigned char *ber_buf;
  unsigned char *digest;
  size_t digest_len, return_len, encoded_oid_len;
  size_t max_output_msg_len;
  Boolean rv;
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;

  max_output_msg_len = decrypted_signature_len;

  /* Decode the msg. */
  if ((ber_buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  if (do_unpad)
    {
      rv = ssh_pkcs1_unpad(decrypted_signature, decrypted_signature_len,
                           1, ber_buf, max_output_msg_len, &return_len);
      if (!rv)
        {
          ssh_free(ber_buf);
          return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
        }
    }
  else
    {
      memcpy(ber_buf, decrypted_signature, decrypted_signature_len);
      return_len = decrypted_signature_len;
    }

  /* Finalize the hash */
  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_len))
      != SSH_CRYPTO_OK)
    {
      ssh_free(ber_buf);
      return status;
    }

  encoded_oid_len =
    (*rgf->def->rgf_hash_asn1_oid_compare)(rgf, ber_buf, return_len);
  if (encoded_oid_len == 0
      || return_len != encoded_oid_len + digest_len)
    {
      ssh_free(ber_buf);
      ssh_free(digest);
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }

  /* Compare. */
  if (memcmp(ber_buf + encoded_oid_len, digest, digest_len) == 0)
    status = SSH_CRYPTO_OK;
  else
    status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

  ssh_free(digest);
  ssh_free(ber_buf);
  return status;
}

SshCryptoStatus
ssh_rgf_pkcs1_nopad_verify(SshRGF rgf,
                           size_t key_size_in_bits,
                           const unsigned char *decrypted_signature,
                           size_t decrypted_signature_len)
{
  return rgf_pkcs1_verify(FALSE, rgf, decrypted_signature,
                          decrypted_signature_len);
}

SshCryptoStatus ssh_rgf_pkcs1_verify(SshRGF rgf,
                                     size_t key_size_in_bits,
                                     const unsigned char *decrypted_signature,
                                     size_t decrypted_signature_len)
{
  return rgf_pkcs1_verify(TRUE, rgf, decrypted_signature,
                          decrypted_signature_len);
}



SshCryptoStatus
ssh_rgf_pkcs1_sign_nohash(SshRGF rgf, size_t key_size_in_bits,
                          unsigned char **output_msg, size_t *output_msg_len)
{
  Boolean rv;
  unsigned char *digest, *buf;
  size_t digest_length, max_output_msg_len;
  SshCryptoStatus status;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Finalize the hash */
  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_length))
      != SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      return status;
    }

  rv = ssh_pkcs1_pad(digest, digest_length, 1, buf, max_output_msg_len);

  ssh_free(digest);

  *output_msg     = buf;
  *output_msg_len = max_output_msg_len;

  if (rv)
    return SSH_CRYPTO_OK;
  else
    return SSH_CRYPTO_OPERATION_FAILED;
}

SshCryptoStatus
ssh_rgf_pkcs1_verify_nohash(SshRGF rgf,
                            size_t key_size_in_bits,
                            const unsigned char *decrypted_signature,
                            size_t decrypted_signature_len)
{
  unsigned char *buf;
  size_t return_len;
  unsigned char *digest;
  size_t digest_length, max_output_msg_len;
  SshCryptoStatus status;

  max_output_msg_len = decrypted_signature_len;

  /* Allocate a suitable decoding buffer. */
  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Unpad. */
  if (ssh_pkcs1_unpad(decrypted_signature, decrypted_signature_len, 1,
                      buf, max_output_msg_len, &return_len) == FALSE)
    {
      ssh_free(buf);
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }

  /* Finalize the hash */
  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_length))
      != SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      return status;
    }

  if (digest_length != return_len
      || memcmp(digest, buf, digest_length) != 0)
    {
      ssh_free(digest);
      ssh_free(buf);
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  ssh_free(digest);
  ssh_free(buf);
  return SSH_CRYPTO_OK;
}

/* Set the hash function of the RGF from an encoded oid buffer. */
static Boolean
ssh_rgf_set_hash_from_oid(SshRGF rgf, const unsigned char *oid,
                          size_t max_oid_len, size_t *actual_oid_len)
{
  const char *name;

  name = ssh_hash_get_hash_from_oid(oid, max_oid_len, actual_oid_len);

  SSH_DEBUG(SSH_D_LOWOK, ("Hash name is %s", name));

  if (!name)
    return FALSE;

 if (rgf->def == &ssh_rgf_pkcs1_restricted_def &&
     ssh_rgf_restricted_signature_algorithm(name, 0) == TRUE)
        return FALSE;

  if (!strcmp(name, "sha1"))
    rgf->hash_id = SSH_RGF_HASH_SHA1;
  else if (!strcmp(name, "sha224"))
    rgf->hash_id = SSH_RGF_HASH_SHA224;
  else if (!strcmp(name, "sha256"))
    rgf->hash_id = SSH_RGF_HASH_SHA256;
  else if (!strcmp(name, "sha384"))
    rgf->hash_id = SSH_RGF_HASH_SHA384;
  else if (!strcmp(name, "sha512"))
    rgf->hash_id = SSH_RGF_HASH_SHA512;
  else if (!strcmp(name, "md5"))
    rgf->hash_id = SSH_RGF_HASH_MD5;
  else if (!strcmp(name, "md4"))
    rgf->hash_id = SSH_RGF_HASH_MD4;
  else if (!strcmp(name, "md2"))
    rgf->hash_id = SSH_RGF_HASH_MD2;
  else if (!strcmp(name, "ripemd160"))
    rgf->hash_id = SSH_RGF_HASH_RIPEMD160;
  else if (!strcmp(name, "ripemd128"))
    rgf->hash_id = SSH_RGF_HASH_RIPEMED128;
  else
    return FALSE;

  return TRUE;
}


SshCryptoStatus
ssh_rgf_pkcs1_verify_implicit(SshRGF rgf,
                              size_t key_size_in_bits,
                              const unsigned char *decrypted_signature,
                              size_t decrypted_signature_len)
{
  unsigned char *ber_buf, *digest;
  size_t digest_length, max_output_msg_len;
  size_t return_len, actual_oid_len;
  SshCryptoStatus status;

  max_output_msg_len = decrypted_signature_len;

  /* Allocate a suitable decoding buffer. */
  if ((ber_buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Unpad. */
  if (ssh_pkcs1_unpad(decrypted_signature, decrypted_signature_len, 1,
                      ber_buf, max_output_msg_len, &return_len) == FALSE)
    {
      ssh_free(ber_buf);
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }

  /* Set the correct hash function from the encoded hash OID. */
  if (!ssh_rgf_set_hash_from_oid(rgf, ber_buf, return_len, &actual_oid_len))
    {
      ssh_free(ber_buf);
      return SSH_CRYPTO_UNSUPPORTED;
    }

  /* Finalize the hash */
  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_length))
      != SSH_CRYPTO_OK)
    {
      ssh_free(ber_buf);
      return status;
    }

  if (digest_length + actual_oid_len != return_len
      || memcmp(digest, ber_buf + actual_oid_len, digest_length) != 0)
    {
      ssh_free(digest);
      ssh_free(ber_buf);
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  ssh_free(digest);
  ssh_free(ber_buf);
  return SSH_CRYPTO_OK;
}

#endif /* SSHDIST_CRYPT_RSA */


/* A generic routines that can be used with many cryptosystems with
   little redundancy management. These include e.g. the DSA algorithm.

   Common idea with all the methods is that they basically do not
   do any redundancy related operations. For example, they just hash
   the message for signature using one of the standard hash functions.
   They do not pad the digest before signing, usually because these
   methods include the digest into the cryptosystem in more complicated
   manner than RSA does, for example.
*/

SshCryptoStatus
ssh_rgf_std_encrypt(SshRGF rgf, size_t key_size_in_bits,
                    const unsigned char *msg, size_t msg_len,
                    unsigned char **output_msg, size_t *output_msg_len)
{
  unsigned char *buf;
  size_t max_output_msg_len;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if (msg_len > max_output_msg_len)
    return SSH_CRYPTO_DATA_TOO_LONG;

  /* Allocate a suitable decoding buffer. */
  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Zero the output msg. */
  memset(buf, 0, max_output_msg_len);
  memcpy(buf + (max_output_msg_len - msg_len), msg, msg_len);

  *output_msg     = buf;
  *output_msg_len = max_output_msg_len;

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_std_decrypt(SshRGF rgf, size_t key_size_in_bits,
                    const unsigned char *decrypted_msg,
                    size_t decrypted_msg_len,
                    unsigned char **output_msg,
                    size_t *output_msg_len)
{
  size_t max_output_msg_len;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if (decrypted_msg_len > max_output_msg_len)
    return SSH_CRYPTO_OPERATION_FAILED;

  if ((*output_msg = ssh_memdup(decrypted_msg, decrypted_msg_len)) != NULL)
    *output_msg_len = decrypted_msg_len;
  else
    {
      *output_msg_len = 0;
      return SSH_CRYPTO_NO_MEMORY;
    }
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_std_sign(SshRGF rgf, size_t key_size_in_bits,
                 unsigned char **output_msg, size_t *output_msg_len)
{
  unsigned char  *digest, *buf;
  size_t digest_len, max_output_msg_len;
  SshCryptoStatus status;

  max_output_msg_len = (key_size_in_bits + 7) / 8;

  if ((buf = ssh_malloc(max_output_msg_len)) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  memset(buf, 0, max_output_msg_len);

  /* Finalize the hash */
  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_len))
      != SSH_CRYPTO_OK)
    {
      ssh_free(buf);
      return status;
    }

  /* Output MIN(digest_len, max_output_msg_len) */
  if (digest_len > max_output_msg_len)
    {
      memcpy(buf, digest, max_output_msg_len);
      *output_msg_len  = max_output_msg_len;
    }
  else
    {
      memcpy(buf, digest, digest_len);
      *output_msg_len  = digest_len;
    }

  *output_msg = buf;

  ssh_free(digest);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus ssh_rgf_std_verify(SshRGF rgf,
                                   size_t key_size_in_bits,
                                   const unsigned char *decrypted_signature,
                                   size_t decrypted_signature_len)
{
  unsigned char  *digest;
  size_t digest_len;
  SshCryptoStatus status;

  /* Finalize the hash */
  if ((status = (*rgf->def->rgf_hash_finalize)(rgf, &digest, &digest_len))
      != SSH_CRYPTO_OK)
    return status;

  if (digest_len != decrypted_signature_len
      || memcmp(decrypted_signature, digest, digest_len) != 0)
    {
      ssh_free(digest);
      return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
    }
  ssh_free(digest);
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_std_encrypt_no_allocate(SshRGF rgf, size_t key_size_in_bits,
                                const unsigned char *msg,
                                size_t msg_len,
                                unsigned char **output_msg,
                                size_t *output_msg_len)
{
  *output_msg     = (unsigned char *) msg;
  *output_msg_len = (key_size_in_bits + 7) / 8;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_std_decrypt_no_allocate(SshRGF rgf, size_t key_size_in_bits,
                                const unsigned char *decrypted_msg,
                                size_t decrypted_msg_len,
                                unsigned char **output_msg,
                                size_t *output_msg_len)
{
  *output_msg     = (unsigned char *) decrypted_msg;
  *output_msg_len = decrypted_msg_len;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_std_sign_no_allocate(SshRGF rgf, size_t key_size_in_bits,
                             unsigned char **output_msg,
                             size_t *output_msg_len)
{
  *output_msg     = (unsigned char *) rgf->precomp_digest;
  *output_msg_len = rgf->precomp_digest_length;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_rgf_std_verify_no_allocate(SshRGF rgf, size_t key_size_in_bits,
                               const unsigned char *decrypted_signature,
                               size_t decrypted_signature_len)
{
  if (rgf->precomp_digest_length != decrypted_signature_len ||
      memcmp(decrypted_signature, rgf->precomp_digest,
             rgf->precomp_digest_length) != 0)
    return SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

  return SSH_CRYPTO_OK;
}



/********************* Externally visible  functions. ***********************/

SshRGF ssh_rgf_allocate(const SshRGFDefStruct *rgf_def)
{
  SshRGF rgf;

  if (!rgf_def->rgf_allocate)
    return NULL;

  rgf = (*rgf_def->rgf_allocate)(rgf_def);

  if (rgf)
    rgf->def = rgf_def;

  return rgf;
}

void ssh_rgf_free(SshRGF rgf)
{
  if (rgf)
    {
      (*rgf->def->rgf_free)(rgf);
    }
}

SshCryptoStatus ssh_rgf_hash_update(SshRGF rgf,
                                    const unsigned char *data,
                                    size_t data_len)
{
  return (*rgf->def->rgf_hash_update)(rgf, FALSE, data, data_len);
}

SshCryptoStatus ssh_rgf_hash_update_with_digest(SshRGF rgf,
                                                const unsigned char *data,
                                                size_t data_len)
{
  rgf->sign_digest = TRUE;
  return (*rgf->def->rgf_hash_update)(rgf, TRUE, data, data_len);
}

SshHash ssh_rgf_derive_hash(SshRGF rgf)
{
  SshCryptoStatus status;
  SshHash h;

  /* Check whether the conversion is possible. */
  if (rgf->def->hash == NULL)
    return NULL;

  status = ssh_hash_allocate(rgf->def->hash, &h);

  if (status != SSH_CRYPTO_OK)
    return NULL;

  return h;
}

SshCryptoStatus ssh_rgf_for_encryption(SshRGF rgf,
                                       size_t key_size_in_bits,
                                       const unsigned char *msg,
                                       size_t msg_len,
                                       unsigned char **output_msg,
                                       size_t *output_msg_len)
{
  SshCryptoStatus status = SSH_CRYPTO_UNSUPPORTED;

  if (rgf->def->rgf_encrypt)
    status = (*rgf->def->rgf_encrypt)(rgf, key_size_in_bits, msg, msg_len,
                                      output_msg, output_msg_len);
  return status;
}

SshCryptoStatus ssh_rgf_for_decryption(SshRGF rgf,
                                       size_t key_size_in_bits,
                                       const unsigned char *decrypted_msg,
                                       size_t decrypted_msg_len,
                                       unsigned char **output_msg,
                                       size_t *output_msg_len)
{
  SshCryptoStatus status = SSH_CRYPTO_UNSUPPORTED;

  if (rgf->def->rgf_decrypt)
    status = (*rgf->def->rgf_decrypt)(rgf, key_size_in_bits,
                                      decrypted_msg, decrypted_msg_len,
                                      output_msg, output_msg_len);
  return status;
}

SshCryptoStatus ssh_rgf_for_signature(SshRGF rgf,
                                      size_t key_size_in_bits,
                                      unsigned char **output_msg,
                                      size_t *output_msg_len)
{
  SshCryptoStatus status = SSH_CRYPTO_UNSUPPORTED;

  if (rgf->def->rgf_sign)
    status = (*rgf->def->rgf_sign)(rgf, key_size_in_bits,
                                   output_msg, output_msg_len);

  return status;
}

SshCryptoStatus
ssh_rgf_for_verification(SshRGF rgf,
                         size_t key_size_in_bits,
                         const unsigned char *decrypted_signature,
                         size_t decrypted_signature_len)
{
  SshCryptoStatus status = SSH_CRYPTO_UNSUPPORTED;

  if (rgf->def->rgf_verify)
    status = (*rgf->def->rgf_verify)(rgf, key_size_in_bits,
                                     decrypted_signature,
                                     decrypted_signature_len);
  return status;
}

Boolean ssh_rgf_data_is_digest(SshRGF rgf)
{
  if (rgf->sign_digest)
    return TRUE;
  else
    return FALSE;
}

size_t ssh_rgf_hash_digest_length(SshRGF rgf)
{
  if (rgf->def->hash)
    return ssh_hash_digest_length(rgf->def->hash);
  else
    return 0;
}

#define RGF(hash, encr, sign, digest)           \
    ssh_rgf_std_allocate,                       \
    ssh_rgf_std_free,                           \
    ssh_rgf_ ## digest ## _hash_update,         \
    ssh_rgf_ ## digest ## _hash_finalize,       \
    ssh_rgf_hash_asn1_oid_compare,              \
    ssh_rgf_hash_asn1_oid_generate,             \
    hash,                                       \
    ssh_rgf_ ## encr ## _encrypt,               \
    ssh_rgf_ ## encr ## _decrypt,               \
    ssh_rgf_ ## sign ## _sign,                  \
    ssh_rgf_ ## sign ## _verify


#ifdef SSHDIST_CRYPT_SHA
const SshRGFDefStruct ssh_rgf_std_sha1_def =
  {
    RGF("sha1", std, std, std)
  };
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
const SshRGFDefStruct ssh_rgf_std_sha256_def =
  {
    RGF("sha256", std, std, std)
  };
const SshRGFDefStruct ssh_rgf_std_sha224_def =
  {
    RGF("sha224", std, std, std)
  };
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
const SshRGFDefStruct ssh_rgf_std_sha384_def =
  {
    RGF("sha384", std, std, std)
  };

const SshRGFDefStruct ssh_rgf_std_sha512_def =
  {
    RGF("sha512", std, std, std)
  };
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_MD5
const SshRGFDefStruct ssh_rgf_std_md5_def =
  {
    RGF("md5", std, std, std)
  };
#endif /* SSHDIST_CRYPT_MD5 */

#ifdef SSHDIST_CRYPT_RSA
#ifdef SSHDIST_CRYPT_SHA
const SshRGFDefStruct ssh_rgf_pkcs1_implicit_def =
  {
    ssh_rgf_none_allocate,
    ssh_rgf_none_free,

    ssh_rgf_none_hash_update,
    ssh_rgf_pkcs1_hash_finalize_implicit,
    ssh_rgf_hash_asn1_oid_compare,
    ssh_rgf_hash_asn1_oid_generate,
    NULL,
    NULL_FNPTR,
    NULL_FNPTR,
    NULL_FNPTR,
    ssh_rgf_pkcs1_verify_implicit
  };

const SshRGFDefStruct ssh_rgf_pkcs1_restricted_def =
  {
    ssh_rgf_none_allocate,
    ssh_rgf_none_free,

    ssh_rgf_none_hash_update,
    ssh_rgf_pkcs1_hash_finalize_implicit,
    ssh_rgf_hash_asn1_oid_compare,
    ssh_rgf_hash_asn1_oid_generate,
    NULL,
    NULL_FNPTR,
    NULL_FNPTR,
    NULL_FNPTR,
    ssh_rgf_pkcs1_verify_implicit
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha1_def =
  {
    RGF("sha1", pkcs1, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha1_no_hash_def =
  {
    RGF("sha1", pkcs1, pkcs1, ignore)
  };


const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha1_def =
  {
    RGF("sha1", std, pkcs1, std)
  };

#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
const SshRGFDefStruct ssh_rgf_pkcs1_sha256_def =
  {
    RGF("sha256", pkcs1, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha256_no_hash_def =
  {
    RGF("sha256", pkcs1, pkcs1, ignore)
  };
const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha256_def =
  {
    RGF("sha256", std, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha224_def =
  {
    RGF("sha224", pkcs1, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha224_no_hash_def =
  {
    RGF("sha224", pkcs1, pkcs1, ignore)
  };
const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha224_def =
  {
    RGF("sha224", std, pkcs1, std)
  };
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
const SshRGFDefStruct ssh_rgf_pkcs1_sha512_def =
  {
    RGF("sha512", pkcs1, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha512_no_hash_def =
  {
    RGF("sha512", pkcs1, pkcs1, ignore)
  };
const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha512_def =
  {
    RGF("sha512", std, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha384_def =
  {
    RGF("sha384", pkcs1, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_sha384_no_hash_def =
  {
    RGF("sha384", pkcs1, pkcs1, ignore)
  };
const SshRGFDefStruct ssh_rgf_pkcs1_nopad_sha384_def =
  {
    RGF("sha384", std, pkcs1, std)
  };
#endif /* SSHDIST_CRYPT_SHA512 */

#ifdef SSHDIST_CRYPT_MD5
const SshRGFDefStruct ssh_rgf_pkcs1_md5_def =
  {
    RGF("md5", pkcs1, pkcs1, std)
  };

const SshRGFDefStruct ssh_rgf_pkcs1_md5_no_hash_def =
  {
    RGF("md5", pkcs1, pkcs1, ignore)
  };


const SshRGFDefStruct ssh_rgf_pkcs1_nopad_md5_def =
  {
    RGF("md5", std, pkcs1, std)
  };
#endif /* SSHDIST_CRYPT_MD5 */

const SshRGFDefStruct ssh_rgf_pkcs1_none_def =
  {
    ssh_rgf_none_allocate,
    ssh_rgf_none_free,

    ssh_rgf_none_hash_update,
    ssh_rgf_none_hash_finalize,
    ssh_rgf_hash_asn1_oid_compare,
    ssh_rgf_hash_asn1_oid_generate,
    NULL,

    ssh_rgf_pkcs1_encrypt,
    ssh_rgf_pkcs1_decrypt,
    ssh_rgf_pkcs1_sign_nohash,
    ssh_rgf_pkcs1_verify_nohash
  };
#endif /* SSHDIST_CRYPT_RSA */

const SshRGFDefStruct ssh_rgf_dummy_def =
  {
    ssh_rgf_none_allocate,
    ssh_rgf_none_free,

    ssh_rgf_none_hash_update,
    ssh_rgf_none_hash_finalize,
    ssh_rgf_hash_asn1_oid_compare,
    ssh_rgf_hash_asn1_oid_generate,
    NULL,

    ssh_rgf_std_encrypt,
    ssh_rgf_std_decrypt,
    ssh_rgf_std_sign,
    ssh_rgf_std_verify
  };

const SshRGFDefStruct ssh_rgf_dummy_no_allocate_def =
  {
    ssh_rgf_none_allocate,
    ssh_rgf_none_free,

    ssh_rgf_none_hash_update,
    ssh_rgf_none_hash_finalize_no_allocate,
    ssh_rgf_hash_asn1_oid_compare,
    ssh_rgf_hash_asn1_oid_generate,
    NULL,

    ssh_rgf_std_encrypt_no_allocate,
    ssh_rgf_std_decrypt_no_allocate,
    ssh_rgf_std_sign_no_allocate,
    ssh_rgf_std_verify_no_allocate
  };

/* sshrgf.c */
