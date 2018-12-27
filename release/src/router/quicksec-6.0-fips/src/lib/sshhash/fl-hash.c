/**
   @copyright
   Copyright (c) 2012 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   FL-Hash - Implementation for hash algorithms using FIPS Library.

             The following algorithms are supported:
              - SHA1 with 160/96/80-bits message digests
              - SHA-256 with 256/128/96/80-bits message digests
              - SHA-224 with 224-bits message digest
              - SHA-512 with 512-bits message digest
              - SHA-384 with 384-bits message digest
*/

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshhash_i.h"
#include "hash-oid.h"
#include "sshfl.h"

#include <fl.h>
#include <fl-hash.h>

#define SSH_DEBUG_MODULE "SshCryptoFlHash"

#if defined SSHDIST_CRYPT_SHA || \
    defined SSHDIST_CRYPT_SHA256 || \
    defined SSHDIST_CRYPT_SHA512

/******************************** Generic code *******************************/

/* FL Hash Context used for all SHA algorithms */
typedef struct
{
  /* Hash algorithm */
  FL_HashAlgorithm_t algorithm;
  /* State asset */
  FL_AnyAsset_t state;

} SshFlHashContext;


static Boolean
fl_hash_is_lib_functional(void)
{
  FL_LibStatus_t status;

  status = FL_LibStatus();
  if (status == FL_STATUS_ERROR)
    {
      return FALSE;
    }
  else
    {
      return TRUE;
    }
}

static size_t
fl_hash_ctxsize(void)
{
  return sizeof(SshFlHashContext);
}

static SshCryptoStatus
fl_hash_create_state_and_do_init(FL_HashAlgorithm_t algorithm,
                                 FL_AnyAsset_t *state)
{
  FL_RV rv;

  /* Acquire new state for storing intermediate values. */
  SSH_FL_ALLOCATE_STATE(rv, state);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_ALLOCATE_STATE failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
    }
  else
    {
      /* Init hash with proper algorithm. */
      rv = FL_HashInit(*state, algorithm, NULL, 0);
      if (rv != FLR_OK)
        {
          SSH_DEBUG(SSH_D_FAIL, ("FL_HashInit failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
        }
    }

  /* Check error */
  if (rv != FLR_OK)
    {
      SSH_VERIFY(fl_hash_is_lib_functional());
      *state = FL_ASSET_INVALID;
      return SSH_CRYPTO_NO_MEMORY;
    }

  return SSH_CRYPTO_OK;
}

static void
fl_hash_free_state(FL_AnyAsset_t *state)
{
  FL_RV rv;

  /* Free state object. */
  rv = FL_AssetCheck(*state, FL_CHECK_EXISTS);
  if (rv == FLR_OK)
    {
      SSH_FL_ASSETFREE(*state);
    }

  *state = FL_ASSET_INVALID;
}

static SshCryptoStatus
fl_hash_init_context(void *context,
                     FL_HashAlgorithm_t algorithm)
{
  SshFlHashContext *hash_ctx = context;

  /* Init context */
  hash_ctx->algorithm = algorithm;
  hash_ctx->state = FL_ASSET_INVALID;

  /* Create state and init hash with proper algorithm. */
  return fl_hash_create_state_and_do_init(algorithm, &hash_ctx->state);
}

static void
fl_hash_reset_context(void *context)
{
  SshFlHashContext *hash_ctx = context;

  /* Free state object. */
  fl_hash_free_state(&hash_ctx->state);

  /* Create state and init hash with proper algorithm. */
  (void) fl_hash_create_state_and_do_init(hash_ctx->algorithm,
                                          &hash_ctx->state);
}

static void
fl_hash_uninit_context(void *context)
{
  SshFlHashContext *hash_ctx = context;

  /* Free state object. */
  fl_hash_free_state(&hash_ctx->state);
}

static void
fl_hash_update(void *context,
               const unsigned char *buf,
               size_t len)
{
  SshFlHashContext *hash_ctx = context;
  FL_RV rv;

  /* Do hash. */
  rv = FL_HashContinue(hash_ctx->state, buf, len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_HashContinue failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hash_is_lib_functional());
    }
}

static SshCryptoStatus
fl_hash_final(void *context,
              unsigned char *digest,
              size_t digest_len)
{
  SshFlHashContext *hash_ctx = context;
  FL_RV rv;

  /* Finish hash calculation operation. */
  rv = FL_HashFinish(hash_ctx->state, digest, digest_len);
  if (rv != FLR_OK)
    {
      SSH_DEBUG(SSH_D_FAIL, ("FL_HashFinish failed: %s (%d)",
                             ssh_fl_rv_to_string(rv), rv));
      SSH_VERIFY(fl_hash_is_lib_functional());

      return SSH_CRYPTO_INTERNAL_ERROR;
    }

  return SSH_CRYPTO_OK;
}

#endif /* SSHDIST_CRYPT_SHA || SSHDIST_CRYPT_SHA256 || SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA

/**************************** SHA1 implementation ****************************/

static SshCryptoStatus
fl_hash_sha1_init(void *context)
{
  /* Init context. */
  return fl_hash_init_context(context, FL_ALGO_HASH_SHA1);
}

static SshCryptoStatus
fl_hash_sha1_final(void *context,
                   unsigned char *digest)
{
  return fl_hash_final(context, digest, 20);
}

static SshCryptoStatus
fl_hash_sha1_96_final(void *context,
                      unsigned char *digest)
{
  return fl_hash_final(context, digest, 12);
}

static SshCryptoStatus
fl_hash_sha1_80_final(void *context,
                      unsigned char *digest)
{
  return fl_hash_final(context, digest, 10);
}

/* Define SHA-1 with 160-bits message digest size. */
const SshHashDefStruct fl_hash_sha_def =
{
  /* Name of the hash function. */
  "sha1",
  /* ASN.1 Object identifier */
  "1.3.14.3.2.26",
  /* ISO/IEC dedicated hash identifier. */
  0x33,
  /* Message digest size */
  20,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha1_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha1_final,
  /* ASN1 compare function */
  ssh_hash_oid_asn1_compare_sha,
  /* ASN1 generate function */
  ssh_hash_oid_asn1_generate_sha
};

/* Define SHA-1 with 96-bits message digest size. */
const SshHashDefStruct fl_hash_sha_96_def =
{
  /* Name of the hash function. */
  "sha1-96",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Message digest size */
  12,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha1_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha1_96_final,
  /* No ASN1. */
  NULL,
  NULL
};

/* Define SHA-1 with 80-bits message digest size. */
const SshHashDefStruct fl_hash_sha_80_def =
{
  /* Name of the hash function. */
  "sha1-80",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Message digest size */
  10,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha1_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha1_80_final,
  /* No ASN1. */
  NULL,
  NULL
};

#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256

/************************** SHA-256 implementation **************************/

static SshCryptoStatus
fl_hash_sha256_init(void *context)
{
  /* Init context. */
  return fl_hash_init_context(context, FL_ALGO_HASH_SHA2_256);
}

static SshCryptoStatus
fl_hash_sha256_final(void *context,
                     unsigned char *digest)
{
  return fl_hash_final(context, digest, 32);
}

static SshCryptoStatus
fl_hash_sha256_128_final(void *context,
                         unsigned char *digest)
{
  return fl_hash_final(context, digest, 16);
}

static SshCryptoStatus
fl_hash_sha256_96_final(void *context,
                        unsigned char *digest)
{
  return fl_hash_final(context, digest, 12);
}

static SshCryptoStatus
fl_hash_sha256_80_final(void *context,
                        unsigned char *digest)
{
  return fl_hash_final(context, digest, 10);
}

/* Define SHA-256 with 256-bits message digest size. */
const SshHashDefStruct fl_hash_sha256_def =
{
  /* Name of the hash function. */
  "sha256",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.1",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Message digest size */
  32,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha256_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha256_final,
  /* ASN1 compare function */
  ssh_hash_oid_asn1_compare_sha256,
  /* ASN1 generate function */
  ssh_hash_oid_asn1_generate_sha256
};

/* Define SHA-256 with 128-bits message digest size. */
const SshHashDefStruct fl_hash_sha256_128_def =
{
  /* Name of the hash function. */
  "sha256-128",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Message digest size */
  16,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha256_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha256_128_final,
  /* No ASN1 */
  NULL,
  NULL
};

/* Define SHA-256 with 96-bits message digest size. */
const SshHashDefStruct fl_hash_sha256_96_def =
{
  /* Name of the hash function. */
  "sha256-96",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Message digest size */
  12,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha256_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha256_96_final,
  /* No ASN1 */
  NULL,
  NULL
};

/* Define SHA-256 with 80-bits message digest size. */
const SshHashDefStruct fl_hash_sha256_80_def =
{
  /* Name of the hash function. */
  "sha256-80",
  /* ASN.1 Object identifier (not defined) */
  NULL,
  /* ISO/IEC dedicated hash identifier. */
  0, /* None */
  /* Message digest size */
  10,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha256_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha256_80_final,
  /* No ASN1 */
  NULL,
  NULL
};


/************************** SHA-224 implementation **************************/

static SshCryptoStatus
fl_hash_sha224_init(void *context)
{
  /* Init context. */
  return fl_hash_init_context(context, FL_ALGO_HASH_SHA2_224);
}

static SshCryptoStatus
fl_hash_sha224_final(void *context,
                     unsigned char *digest)
{
  return fl_hash_final(context, digest, 28);
}

/* Define SHA-224 with 224-bits message digest size. */
const SshHashDefStruct fl_hash_sha224_def =
{
  /* Name of the hash function. */
  "sha224",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.4",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Message digest size */
  28,
  /* Input block length */
  64,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha224_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha224_final,
  /* ASN1 compare function */
  ssh_hash_oid_asn1_compare_sha224,
  /* ASN1 generate function */
  ssh_hash_oid_asn1_generate_sha224
};

#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512

/************************** SHA-512 implementation **************************/

static SshCryptoStatus
fl_hash_sha512_init(void *context)
{
  /* Init context. */
  return fl_hash_init_context(context, FL_ALGO_HASH_SHA2_512);
}

static SshCryptoStatus
fl_hash_sha512_final(void *context,
                     unsigned char *digest)
{
  return fl_hash_final(context, digest, 64);
}



/* Define SHA-512 with 512-bits message digest size. */
const SshHashDefStruct fl_hash_sha512_def =
{
  /* Name of the hash function. */
  "sha512",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.3",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Message digest size. */
  64,
  /* Input block length. */
  128,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha512_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha512_final,
  /* ASN1 compare function */
  ssh_hash_oid_asn1_compare_sha512,
  /* ASN1 generate function */
  ssh_hash_oid_asn1_generate_sha512
};


/************************** SHA-384 implementation **************************/

static SshCryptoStatus
fl_hash_sha384_init(void *context)
{
  /* Init context. */
  return fl_hash_init_context(context, FL_ALGO_HASH_SHA2_384);
}

static SshCryptoStatus
fl_hash_sha384_final(void *context,
                     unsigned char *digest)
{
  return fl_hash_final(context, digest, 48);
}

/* Define SHA-384 with 384-bits message digest size. */
const SshHashDefStruct fl_hash_sha384_def =
{
  /* Name of the hash function. */
  "sha384",
  /* ASN.1 Object identifier */
  "2.16.840.1.101.3.4.2.2",
  /* ISO/IEC dedicated hash identifier. */
  0,
  /* Message digest size */
  48,
  /* Input block length */
  128,
  /* Context size */
  fl_hash_ctxsize,
  /* Init context */
  fl_hash_sha384_init,
  /* Uninit context */
  fl_hash_uninit_context,
  /* Reset function, between long usage of one context. */
  fl_hash_reset_context,
  /* Update function */
  fl_hash_update,
  /* Final function */
  fl_hash_sha384_final,
  /* ASN1 compare function */
  ssh_hash_oid_asn1_compare_sha384,
  /* ANS1 generate function */
  ssh_hash_oid_asn1_generate_sha384
};

#endif /* SSHDIST_CRYPT_SHA512 */
