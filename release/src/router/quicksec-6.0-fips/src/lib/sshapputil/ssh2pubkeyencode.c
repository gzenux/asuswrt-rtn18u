/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Encodes and decodes ssh2-format public key blobs.
*/

#include "sshincludes.h"

#ifdef SSHDIST_APPUTIL_KEYUTIL
#include "ssh2pubkeyencode.h"
#include "sshcrypt.h"
#include "sshmp.h"
#include "sshencode.h"
#include "sshgetput.h"
#include "sshbufaux.h"
#ifdef SSHDIST_CERT
#include "x509.h"
#endif /* SSHDIST_CERT */

#define SSH_DEBUG_MODULE "Ssh2KeyBlob"

/* define this to dump all keys encoded/decoded */
#undef DUMP_KEYS

/* define this to dump key blobs going in/out */
#undef DUMP_BLOBS

void
ssh_bufaux_put_mp_int_ssh2style(SshBuffer buffer, SshMPInteger mp)
{
  unsigned char *data;
  size_t len, bytes;

  len = 4 + (8 + ssh_mprz_get_size(mp, 2) + 7)/8;
  data = ssh_xmalloc(len);
  bytes = ssh_mprz_encode_ssh2style(mp, data, len);
  SSH_VERIFY(bytes <= len && bytes > 0);
  ssh_xbuffer_append(buffer, data, bytes);
  ssh_xfree(data);
}

Boolean
ssh_bufaux_get_mp_int_ssh2style(SshBuffer buffer, SshMPInteger mp)
{
  unsigned char *data;
  size_t len, bytes;

  len = ssh_buffer_len(buffer);
  data = ssh_buffer_ptr(buffer);
  if ((bytes = ssh_mprz_decode_ssh2style(data, len, mp)) > 0)
    ssh_buffer_consume(buffer, bytes);

  return bytes != 0;
}

void
ssh_bufaux_put_msb_encoded_mp_int_ssh2style(SshBuffer buffer,
                                            const unsigned char *buf,
                                            size_t len)
{
  SshUInt32 encode_len;

  /* Rip out extra zero bytes from the beginning (the crypto library
     ssh_pk_dh_*() functions don't do this). */
  while (buf[0] == 0 && len > 0)
    {
      buf++;
      len--;
    }
  encode_len = (SshUInt32) len;

  /* If `len' is zero, the mpint value is zero, which will be encoded as
     an empty string (the length field set to zero, no data). */
  if (len == 0)
    {
      unsigned char head[4];
      SSH_PUT_32BIT(head, (SshUInt32)0);
      ssh_xbuffer_append(buffer, head, 4);
      return;
    }
  /* If the highest bit is set, append an extra zero byte to the buffer. */
  else if (buf[0] & 0x80)
    {
      unsigned char head[5];
      encode_len++;
      SSH_PUT_32BIT(head, encode_len);
      SSH_PUT_8BIT(head + 4, 0);
      ssh_xbuffer_append(buffer, head, 5);
    }
  else
    {
      unsigned char head[4];
      SSH_PUT_32BIT(head, encode_len);
      ssh_xbuffer_append(buffer, head, 4);
    }

  ssh_xbuffer_append(buffer, buf, len);
}


Boolean
ssh_bufaux_get_msb_encoded_mp_int_ssh2style(SshBuffer buffer,
                                            unsigned char **buf,
                                            size_t *len)
{
  unsigned char *data;
  size_t data_len, byte_size;

  data = ssh_buffer_ptr(buffer);
  data_len = ssh_buffer_len(buffer);

  if (data_len < 4)
    return FALSE;

  byte_size = SSH_GET_32BIT(data);

  if ((byte_size + 4) > data_len)
    return FALSE;

  /* Check if the encoded integer is negative. */
  if (byte_size > 0 && (data[4] & 0x80))
    return FALSE;

  if (byte_size == 0)
    {
      *buf = ssh_xmalloc(1);
      *buf[0] = 0;
      *len = 1;
    }
  else
    {
      *buf = ssh_xmemdup(data + 4, byte_size);
      *len = byte_size;
    }

  ssh_buffer_consume(buffer, byte_size + 4);
  return TRUE;
}


/* Encode a public key into a SSH2 format blob. Return size or 0 on
   failure. */

size_t ssh_encode_pubkeyblob(SshPublicKey pubkey, unsigned char **blob)
{
#ifdef SSHDIST_CRYPT_DSA
  SshMPIntegerStruct p, q, g, y;  /* DSS public parameters */
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_RSA
  SshMPIntegerStruct n, e;        /* RSA public parameters */
#endif /* SSHDIST_CRYPT_RSA */
  SshBuffer buf;
  size_t len;
  char *keytype;

  *blob = NULL;

  /* try to determine the exact type of the public key */

  if ((keytype = ssh_public_key_name(pubkey)) == NULL)
    {
      ssh_debug("ssh_encode_pubkeyblob: failed to extract "
                "key type information.");
      return 0;
    }

#ifdef SSHDIST_CRYPT_DSA
  /* -- DSS key type -- */

  /* this is sort of kludge-ish */
  if (strstr(keytype, "sign{dsa-nist") != NULL)
    {
      /* dig out the public parameters */

      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);
      ssh_mprz_init(&y);

      if (ssh_public_key_get_info(pubkey,
                                  SSH_PKF_PRIME_P, &p,
                                  SSH_PKF_PRIME_Q, &q,
                                  SSH_PKF_GENERATOR_G, &g,
                                  SSH_PKF_PUBLIC_Y, &y,
                                  SSH_PKF_END)
          != SSH_CRYPTO_OK)
        {
          ssh_debug("ssh_encode_pubkeyblob: failed to get "
                    "internal parameters from a DSS public key.");

          ssh_xfree(keytype);
          return 0;
        }

      /* construct the public key string */

      buf = ssh_xbuffer_allocate();

      ssh_bufaux_put_uint32_string(buf, SSH_SSH_DSS, strlen(SSH_SSH_DSS));
      ssh_bufaux_put_mp_int_ssh2style(buf, &p);
      ssh_bufaux_put_mp_int_ssh2style(buf, &q);
      ssh_bufaux_put_mp_int_ssh2style(buf, &g);
      ssh_bufaux_put_mp_int_ssh2style(buf, &y);

#ifdef DUMP_KEYS
      printf("encode:\n p = ");
      ssh_mprz_out_str(stdout, 16, &p);
      printf("\n q = ");
      ssh_mprz_out_str(stdout, 16, &q);
      printf("\n g = ");
      ssh_mprz_out_str(stdout, 16, &g);
      printf("\n y = ");
      ssh_mprz_out_str(stdout, 16, &y);
      printf("\n\n");
#endif

      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&g);
      ssh_mprz_clear(&y);

      len = ssh_buffer_len(buf);
      *blob = ssh_xmalloc(len);
      memcpy(*blob, ssh_buffer_ptr(buf), len);
      ssh_buffer_free(buf);
      ssh_xfree(keytype);

      return len;
    }
#endif /* SSHDIST_CRYPT_DSA */

#ifdef SSHDIST_CRYPT_RSA
  /* -- RSA key type -- */

  if (strstr(keytype, "sign{rsa-pkcs1") != NULL)
    {
      /* dig out the public parameters */

      ssh_mprz_init(&e);
      ssh_mprz_init(&n);

      if (ssh_public_key_get_info(pubkey,
                                  SSH_PKF_PUBLIC_E, &e,
                                  SSH_PKF_MODULO_N, &n,
                                  SSH_PKF_END)
          != SSH_CRYPTO_OK)
        {
          ssh_debug("ssh_encode_pubkeyblob: failed to get "
                    "internal parameters from a RSA public key.");
          ssh_xfree(keytype);

          return 0;
        }

      buf = ssh_xbuffer_allocate();
      ssh_bufaux_put_uint32_string(buf, SSH_SSH_RSA, strlen(SSH_SSH_RSA));
      ssh_bufaux_put_mp_int_ssh2style(buf, &e);
      ssh_bufaux_put_mp_int_ssh2style(buf, &n);

#ifdef DUMP_KEYS
      printf("encode:\n e = ");
      ssh_mprz_out_str(stdout, 16, &e);
      printf("\n n = ");
      ssh_mprz_out_str(stdout, 16, &n);
      printf("\n\n");
#endif

      len = ssh_buffer_len(buf);
      *blob = ssh_xmalloc(len);
      memcpy(*blob, ssh_buffer_ptr(buf), len);
      ssh_buffer_free(buf);

      ssh_mprz_clear(&e);
      ssh_mprz_clear(&n);

      ssh_xfree(keytype);
      return len;
    }
#endif /* SSHDIST_CRYPT_RSA */

  ssh_debug("ssh_encode_pubkeyblob: unrecognized key type %s", keytype);
  ssh_xfree(keytype);
  return 0;
}


/* Decode a public key blob. Return NULL on failure. */

SshPublicKey ssh_decode_pubkeyblob(const unsigned char *blob, size_t bloblen)
{
  unsigned char *keytype;
  SshPublicKey pubkey;
#ifdef SSHDIST_CRYPT_DSA
  SshMPIntegerStruct p, q, g, y;  /* DSS public parameters */
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_RSA
  SshMPIntegerStruct n, e;          /* RSA public parameters */
#endif /* SSHDIST_CRYPT_RSA */
  SshCryptoStatus code;
  SshBuffer buf;

#ifdef DUMP_BLOBS
  ssh_debug("ssh_decode_pubkeyblob:");
  ssh_debug_hexdump(0, blob, bloblen);
#endif

  buf = ssh_xbuffer_allocate();
  ssh_xbuffer_append(buf, blob, bloblen);

  if (ssh_decode_buffer(buf,
                        SSH_DECODE_UINT32_STR(&keytype, NULL),
                        SSH_FORMAT_END) == 0)
    {
      ssh_buffer_free(buf);
      return NULL;
    }

#ifdef SSHDIST_CRYPT_DSA
  /* -- DSS key type -- */

  if (strcmp(SSH_SSH_DSS, (char *) keytype) == 0)
    {
      ssh_mprz_init(&p);
      ssh_mprz_init(&q);
      ssh_mprz_init(&g);
      ssh_mprz_init(&y);

      if (!ssh_bufaux_get_mp_int_ssh2style(buf, &p))
        goto fail1;
      if (!ssh_bufaux_get_mp_int_ssh2style(buf, &q))
        goto fail1;
      if (!ssh_bufaux_get_mp_int_ssh2style(buf, &g))
        goto fail1;
      if (!ssh_bufaux_get_mp_int_ssh2style(buf, &y))
        goto fail1;

      /* ok, construct the public key */

      code = ssh_public_key_define(&pubkey,
                                   SSH_CRYPTO_DSS,
                                   SSH_PKF_PRIME_P, &p,
                                   SSH_PKF_PRIME_Q, &q,
                                   SSH_PKF_GENERATOR_G, &g,
                                   SSH_PKF_PUBLIC_Y, &y,
                                   SSH_PKF_END);
#ifdef DUMP_KEYS
      printf("decode:\n p = ");
      ssh_mprz_out_str(stdout, 16, &p);
      printf("\n q = ");
      ssh_mprz_out_str(stdout, 16, &q);
      printf("\n g = ");
      ssh_mprz_out_str(stdout, 16, &g);
      printf("\n y = ");
      ssh_mprz_out_str(stdout, 16, &y);
      printf("\n\n");
#endif

      ssh_mprz_clear(&p);
      ssh_mprz_clear(&q);
      ssh_mprz_clear(&g);
      ssh_mprz_clear(&y);

      if (code != SSH_CRYPTO_OK)
        {
          ssh_debug("ssh_decode_pubkeyblob: failed to set the "
                    "parameters of an DSS public key.");
          goto fail1;
        }

      ssh_buffer_free(buf);
      ssh_xfree(keytype);
      return pubkey;
    }
#endif /* SSHDIST_CRYPT_DSA */

#ifdef SSHDIST_CRYPT_RSA
  /* -- RSA key type -- */

  if (strcmp(SSH_SSH_RSA, (char *) keytype) == 0)
    {
      ssh_mprz_init(&e);
      ssh_mprz_init(&n);

      if (!ssh_bufaux_get_mp_int_ssh2style(buf, &e))
        goto fail1;
      if (!ssh_bufaux_get_mp_int_ssh2style(buf, &n))
        goto fail1;

#ifdef DUMP_KEYS
      printf("decode:\n e = ");
      ssh_mprz_out_str(stdout, 16, &e);
      printf("\n n = ");
      ssh_mprz_out_str(stdout, 16, &n);
      printf("\n\n");
#endif

      code = ssh_public_key_define(&pubkey,
                                   SSH_CRYPTO_RSA,
                                   SSH_PKF_PUBLIC_E, &e,
                                   SSH_PKF_MODULO_N, &n,
                                   SSH_PKF_END);
      ssh_mprz_clear(&e);
      ssh_mprz_clear(&n);

      if (code != SSH_CRYPTO_OK)
        {
          ssh_debug("ssh_decode_pubkeyblob: failed to set the "
                    "parameters of an RSA public key.");
          goto fail1;
        }

      ssh_buffer_free(buf);
      ssh_xfree(keytype);

      return pubkey;
    }
#endif /* SSHDIST_CRYPT_RSA */

  /* could not identify key type */

  ssh_debug("ssh_decode_pubkeyblob: unrecognized key type %s",
            keytype);

fail1:
  ssh_buffer_free(buf);
  ssh_xfree(keytype);

  return NULL;
}

char *ssh_pubkeyblob_type(const unsigned char *blob, size_t bloblen)
{
  unsigned char *keytype = NULL;

  if (ssh_decode_array(blob, bloblen,
                       SSH_DECODE_UINT32_STR(&keytype, NULL),
                       SSH_FORMAT_END) == 0)
    return NULL;

  return ((char *)keytype);
}

/* Returns TRUE if pk_format matches one of the defined plain pubkey
   formats */
Boolean
ssh_pubkeyblob_type_plain(const unsigned char *pk_format)
{
  if (strcmp(SSH_SSH_DSS, (char *)pk_format) == 0 ||
      strcmp(SSH_SSH_RSA, (char *)pk_format) == 0)
    return TRUE;
  return FALSE;
}

#ifdef SSHDIST_CERT
Boolean
ssh_pki_decode_x509cert(const unsigned char *ber,
                        size_t ber_len,
                        SshPublicKey *pk_return,
                        char **pk_format_return)
{
  SshX509Certificate x509cert;
  SshPublicKey pubkey;
  const char *key_type = NULL;

  /* Try to decode the certificate before accepting it as a candidate */
  x509cert = ssh_x509_cert_allocate(SSH_X509_PKIX_CERT);
  if (ssh_x509_cert_decode(ber, ber_len, x509cert) != SSH_X509_OK)
    {
      SSH_DEBUG(5, ("Could not decode certificate file"));
      ssh_x509_cert_free(x509cert);
      return FALSE;
    }
  if (ssh_x509_cert_get_public_key(x509cert, &pubkey) == FALSE)
    {
      SSH_DEBUG(2, ("Could not extract public key from certificate"));
      ssh_x509_cert_free(x509cert);
      return FALSE;
    }
  ssh_x509_cert_free(x509cert);
  if (ssh_public_key_get_info(pubkey,
                              SSH_PKF_KEY_TYPE, &key_type,
                              SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(2, ("Could not extract public key info from certificate"));
      ssh_public_key_free(pubkey);
      return FALSE;
    }
  if (strcmp(key_type, SSH_CRYPTO_DSS_SHORT) == 0)
    {
      if (pk_return)
        *pk_return = pubkey;
      else
        ssh_public_key_free(pubkey);
      if (pk_format_return)
        *pk_format_return = ssh_xstrdup(SSH_SSH_X509_DSS);
      return TRUE;
    }
  else if (strcmp(key_type, SSH_CRYPTO_RSA_SHORT) == 0)
    {
      if (pk_return)
        *pk_return = pubkey;
      else
        ssh_public_key_free(pubkey);
      if (pk_format_return)
        *pk_format_return = ssh_xstrdup(SSH_SSH_X509_RSA);
      return TRUE;
    }
  else
    {
      SSH_DEBUG(2, ("Could not recognize public key format in certificate"));
      return FALSE;
    }
}

Boolean
ssh_pubkeyblob_type_x509(const unsigned char *pk_format)
{
  if (strcmp(SSH_SSH_X509_DSS, (char *)pk_format) == 0 ||
      strcmp(SSH_SSH_X509_RSA, (char *)pk_format) == 0)
    return TRUE;
  return FALSE;
}

#endif /* SSHDIST_CERT */


/* Decodes the public key from a public key blob or
   certificate. Returns NULL on failure.  pk_format must be set to
   "ssh_dss", "x509v3-sign-dss", etc. (as defined in ssh2 transport
   layer document).  If the type of the blob does not match the format
   given, returns NULL. */

SshPublicKey ssh_decode_pubkeyblob_general(const unsigned char *blob,
                                           size_t bloblen,
                                           const unsigned char *pk_format)
{
  SshPublicKey pk = NULL;
  char *pk_type = NULL;

  if (ssh_pubkeyblob_type_plain(pk_format))
    {
      /* The blob is an ordinary keyblob. Decode it in the usual way. */
      pk_type = ssh_pubkeyblob_type(blob, bloblen);

      pk = ssh_decode_pubkeyblob(blob, bloblen);
      if (!pk || !pk_type)
        return NULL;
    }
#ifdef SSHDIST_CERT
  else if (ssh_pubkeyblob_type_x509(pk_format))
    {
      /* The blob is an X.509 certificate. */
      if (ssh_pki_decode_x509cert(blob, bloblen, &pk, &pk_type)
          == FALSE)
        return NULL;
    }
#endif /* SSHDIST_CERT */
  else
    {
      return NULL;
    }

  /* Got the public key and format. Check that the format matches
     before returning the key. */

  if (strcmp((char *)pk_format, pk_type) != 0)
    {
      ssh_public_key_free(pk);
      pk = NULL;
    }

  ssh_xfree(pk_type);
  return pk;
}
#endif /* SSHDIST_APPUTIL_KEYUTIL */
