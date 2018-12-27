/**
   @copyright
   Copyright (c) 2014 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   File implements oid utilities needed for supported hash functions.
   These are needed e.g. in the PKCS1 signature generation and
   verification.
 */

#include "sshincludes.h"

#define SSH_DEBUG_MODULE "SshCryptoHash"

static const unsigned char ssh_encoded_md5_oid[] =
{
  0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
  0x04, 0x10
};

static const unsigned char ssh_encoded_sha_oid[] =
{
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
  0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static const unsigned char ssh_encoded_sha_noparams_oid[] =
{
  0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e,
  0x03, 0x02, 0x1a, 0x04, 0x14
};

static const unsigned char ssh_encoded_sha224_oid[] =
{
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
  0x00, 0x04, 0x1c
};

static const unsigned char ssh_encoded_sha224_noparams_oid[] =
{
  0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x04,
  0x1c
};

static const unsigned char ssh_encoded_sha256_oid[] =
{
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20
};

static const unsigned char ssh_encoded_sha256_noparams_oid[] =
{
  0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04,
  0x20
};

static const unsigned char ssh_encoded_sha384_oid[] =
{
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
  0x00, 0x04, 0x30
};

static const unsigned char ssh_encoded_sha384_noparams_oid[] =
{
  0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04,
  0x30
};

static const unsigned char ssh_encoded_sha512_oid[] =
{
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
  0x00, 0x04, 0x40
};

static const unsigned char ssh_encoded_sha512_noparams_oid[] =
{
  0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04,
  0x40
};

typedef struct OidHashRec
{
  const char *hash_name;
  const unsigned char *encoded_oid;
  size_t encoded_oid_len;
  const unsigned char *encoded_noparams_oid;
  size_t encoded_noparams_oid_len;

  Boolean prefer_noparams_oid;
} OidHashStruct;

static const OidHashStruct hash_oid_md5 =
  {
    "md5",
    ssh_encoded_md5_oid,
    sizeof(ssh_encoded_md5_oid) / sizeof(unsigned char),
    NULL,
    0,
    FALSE
  };

static const OidHashStruct hash_oid_sha1 =
  {
    "sha1",
    ssh_encoded_sha_oid,
    sizeof(ssh_encoded_sha_oid) / sizeof(unsigned char),
    ssh_encoded_sha_noparams_oid,
    sizeof(ssh_encoded_sha_noparams_oid) / sizeof(unsigned char),
    FALSE
  };

static const OidHashStruct hash_oid_sha224 =
  {
    "sha224",
    ssh_encoded_sha224_oid,
    sizeof(ssh_encoded_sha224_oid) / sizeof(unsigned char),
    ssh_encoded_sha224_noparams_oid,
    sizeof(ssh_encoded_sha224_noparams_oid) / sizeof(unsigned char),
    TRUE
  };

static const OidHashStruct hash_oid_sha256 =
  {
    "sha256",
    ssh_encoded_sha256_oid,
    sizeof(ssh_encoded_sha256_oid) / sizeof(unsigned char),
    ssh_encoded_sha256_noparams_oid,
    sizeof(ssh_encoded_sha256_noparams_oid) / sizeof(unsigned char),
    TRUE
  };

static const OidHashStruct hash_oid_sha384 =
  {
    "sha384",
    ssh_encoded_sha384_oid,
    sizeof(ssh_encoded_sha384_oid) / sizeof(unsigned char),
    ssh_encoded_sha384_noparams_oid,
    sizeof(ssh_encoded_sha384_noparams_oid) / sizeof(unsigned char),
    TRUE
  };

static const OidHashStruct hash_oid_sha512 =
  {
    "sha512",
    ssh_encoded_sha512_oid,
    sizeof(ssh_encoded_sha512_oid) / sizeof(unsigned char),
    ssh_encoded_sha512_noparams_oid,
    sizeof(ssh_encoded_sha512_noparams_oid) / sizeof(unsigned char),
    TRUE
  };

static Boolean
hash_asn1_array_compare(const unsigned char *oid,
                        size_t oid_len,
                        const unsigned char *input,
                        size_t input_len)
{
  if (oid == NULL)
    return FALSE;

  if (oid_len > input_len)
    return FALSE;

  if (memcmp(oid, input, oid_len) != 0)
    return FALSE;

  return TRUE;
}

static size_t
hash_asn1_compare(OidHashStruct oid,
                  const unsigned char *input,
                  size_t input_len)
{
  SSH_ASSERT(oid.hash_name != NULL);
  SSH_ASSERT(oid.encoded_oid != NULL);

  if (hash_asn1_array_compare(oid.encoded_noparams_oid,
                              oid.encoded_noparams_oid_len,
                              input,
                              input_len) == TRUE)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Found %s no params oid from buffer",
                 oid.hash_name));
      return oid.encoded_noparams_oid_len;
    }

  if (hash_asn1_array_compare(oid.encoded_oid,
                              oid.encoded_oid_len,
                              input,
                              input_len) == TRUE)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Found %s oid from buffer",
                 oid.hash_name));
      return oid.encoded_oid_len;
    }

  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW,
                    ("%s oid not found from buffer:", oid.hash_name),
                    input, input_len);

  return 0;
}

const unsigned char *
hash_asn1_generate(OidHashStruct oid, size_t *len)
{
  SSH_ASSERT(oid.hash_name != NULL);
  SSH_ASSERT(oid.encoded_oid != NULL);

  if ((oid.encoded_noparams_oid != NULL) &&
      (oid.prefer_noparams_oid == TRUE))
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Generated oid with no params for %s",
                 oid.hash_name));

      *len = oid.encoded_noparams_oid_len;
      return oid.encoded_noparams_oid;
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Generated oid with for %s", oid.hash_name));

      *len = oid.encoded_oid_len;
      return oid.encoded_oid;
    }
}


size_t
ssh_hash_oid_asn1_compare_md5(const unsigned char *oid, size_t max_len)
{
  return hash_asn1_compare(hash_oid_md5, oid, max_len);
}

const unsigned char *
ssh_hash_oid_asn1_generate_md5(size_t *len)
{
  return hash_asn1_generate(hash_oid_md5, len);
}

size_t
ssh_hash_oid_asn1_compare_sha(const unsigned char *oid, size_t max_len)
{
  return hash_asn1_compare(hash_oid_sha1, oid, max_len);
}

const unsigned char *
ssh_hash_oid_asn1_generate_sha(size_t *len)
{
  return hash_asn1_generate(hash_oid_sha1, len);
}

size_t
ssh_hash_oid_asn1_compare_sha224(const unsigned char *oid, size_t max_len)
{
  return hash_asn1_compare(hash_oid_sha224, oid, max_len);
}

const unsigned char *
ssh_hash_oid_asn1_generate_sha224(size_t *len)
{
  return hash_asn1_generate(hash_oid_sha224, len);
}

size_t
ssh_hash_oid_asn1_compare_sha256(const unsigned char *oid, size_t max_len)
{
  return hash_asn1_compare(hash_oid_sha256, oid, max_len);
}

const unsigned char *
ssh_hash_oid_asn1_generate_sha256(size_t *len)
{
  return hash_asn1_generate(hash_oid_sha256, len);
}

size_t
ssh_hash_oid_asn1_compare_sha384(const unsigned char *oid, size_t max_len)
{
  return hash_asn1_compare(hash_oid_sha384, oid, max_len);
}

const unsigned char *
ssh_hash_oid_asn1_generate_sha384(size_t *len)
{
  return hash_asn1_generate(hash_oid_sha384, len);
}

size_t
ssh_hash_oid_asn1_compare_sha512(const unsigned char *oid, size_t max_len)
{
  return hash_asn1_compare(hash_oid_sha512, oid, max_len);
}

const unsigned char *
ssh_hash_oid_asn1_generate_sha512(size_t *len)
{
  return hash_asn1_generate(hash_oid_sha512, len);
}
