/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 tables etc.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2Tables"

/* Length KE payload of the group in bits */
const size_t
ssh_ikev2_predefined_group_lengths[SSH_IKEV2_TRANSFORM_D_H_MAX] = {
  0,                            /* 0, NONE */
  768,                          /* 1, MODP_768 */
  1024,                         /* 2, MODP_1024 */
  0,                            /* 3, NONE */
  0,                            /* 4, NONE */
  1536,                         /* 5, MODP_1536 */
  0,                            /* 6, NONE */
  0,                            /* 7, NONE */
  0,                            /* 8, NONE */
  0,                            /* 9, NONE */
  0,                            /* 10, NONE */
  0,                            /* 11, NONE */
  0,                            /* 12, NONE */
  0,                            /* 13, NONE */
  2048,                         /* 14, MODP_2048 */
  3072,                         /* 15, MODP_3072 */
  4096,                         /* 16, MODP_4096 */
  6144,                         /* 17, MODP_6144 */
  8192,                         /* 18, MODP_8192 */
#ifdef SSHDIST_CRYPT_ECP
  512,                          /* 19, ECP_256 */
  768,                          /* 20, ECP_384 */
  1056,                         /* 21, ECP_521 */
#else /* SSHDIST_CRYPT_ECP */
  0,                            /* 19, NONE */
  0,                            /* 20, NONE */
  0,                            /* 21, NONE */
#endif /* SSHDIST_CRYPT_ECP */
  1024,                         /* 22, MODP_1024_160 */
  2048,                         /* 23, MODP_2048_224 */
  2048,                         /* 24, MODP_2048_256 */
#ifdef SSHDIST_CRYPT_ECP
  384,                          /* 25, ECP_192 */
  448,                          /* 26, ECP_224 */
  448,                          /* 27, Brainpool ECP_224 */
  512,                          /* 28, Brainpool ECP_256 */
  768,                          /* 29, Brainpool ECP_384 */
  1024                          /* 30, Brainpool ECP_512 */
#else /* SSHDIST_CRYPT_ECP */
  0,                            /* 25, NONE */
  0,                            /* 26, NONE */
  0,                            /* 27, NONE */
  0,                            /* 28, NONE */
  0,                            /* 29, NONE */
  0                             /* 30, NONE */
#endif /* SSHDIST_CRYPT_ECP */
};

/* Group names for default groups */
SSH_RODATA
const char *
ssh_ikev2_predefined_group_names[SSH_IKEV2_TRANSFORM_D_H_MAX] = {
  NULL,                         /* 0, NONE */
  "ietf-ike-grp-modp-768",      /* 1, MODP_768 */
  "ietf-ike-grp-modp-1024",     /* 2, MODP_1024 */
  NULL,                         /* 3, NONE */
  NULL,                         /* 4, NONE */
  "ietf-ike-grp-modp-1536",     /* 5, MODP_1536 */
  NULL,                         /* 6, NONE */
  NULL,                         /* 7, NONE */
  NULL,                         /* 8, NONE */
  NULL,                         /* 9, NONE */
  NULL,                         /* 10, NONE */
  NULL,                         /* 11, NONE */
  NULL,                         /* 12, NONE */
  NULL,                         /* 13, NONE */
  "ietf-ike-grp-modp-2048",     /* 14, MODP_2048 */
  "ietf-ike-grp-modp-3072",     /* 15, MODP_3072 */
  "ietf-ike-grp-modp-4096",     /* 16, MODP_4096 */
  "ietf-ike-grp-modp-6144",     /* 17, MODP_6144 */
  "ietf-ike-grp-modp-8192",     /* 18, MODP_8192 */
#ifdef SSHDIST_CRYPT_ECP
  "prime256v1",                 /* 19, ietf-ike-grp-ecp-256, ECP_256 */
  "secp384r1",                  /* 20, ietf-ike-grp-ecp-384, ECP_384 */
  "secp521r1",                  /* 21, ietf-ike-grp-ecp-521 ECP_521 */
#else /* SSHDIST_CRYPT_ECP */
  NULL,                         /* 19, NONE */
  NULL,                         /* 20, NONE */
  NULL,                         /* 21, NONE */
#endif /* SSHDIST_CRYPT_ECP */
  "ietf-rfc5114-2-1-modp-1024-160", /* 22, MODP_1024_160 */
  "ietf-rfc5114-2-2-modp-2048-224", /* 23, MODP_2048_224 */
  "ietf-rfc5114-2-3-modp-2048-256",  /* 24, MODP_2048_256 */
#ifdef SSHDIST_CRYPT_ECP
  "secp192r1",                  /* 25, ietf-ike-grp-ecp-192, ECP_192 */
  "secp224r1",                  /* 26, ietf-ike-grp-ecp-224, ECP_224 */
  "brainpoolP224r1",            /* 27, RFC6932 brainpool, ECP_224 */
  "brainpoolP256r1",            /* 28, RFC6932 brainpool, ECP_256 */
  "brainpoolP384r1",            /* 29, RFC6932 brainpool, ECP_384 */
  "brainpoolP512r1"             /* 30, RFC6932 brainpool, ECP_512 */
#else /* SSHDIST_CRYPT_ECP */
  NULL,                         /* 25, NONE */
  NULL,                         /* 26, NONE */
  NULL,                         /* 27, NONE */
  NULL,                         /* 28, NONE */
  NULL,                         /* 29, NONE */
  NULL                          /* 30, NONE */
#endif /* SSHDIST_CRYPT_ECP */
};

/* Group types for default groups */
SSH_RODATA
const char *
ssh_ikev2_predefined_group_types[SSH_IKEV2_TRANSFORM_D_H_MAX] = {
  NULL,                         /* 0, NONE */
  "dl-modp",                    /* 1, MODP_768 */
  "dl-modp",                    /* 2, MODP_1024 */
  NULL,                         /* 3, NONE */
  NULL,                         /* 4, NONE */
  "dl-modp",                    /* 5, MODP_1536 */
  NULL,                         /* 6, NONE */
  NULL,                         /* 7, NONE */
  NULL,                         /* 8, NONE */
  NULL,                         /* 9, NONE */
  NULL,                         /* 10, NONE */
  NULL,                         /* 11, NONE */
  NULL,                         /* 12, NONE */
  NULL,                         /* 13, NONE */
  "dl-modp",                    /* 14, MODP_2048 */
  "dl-modp",                    /* 15, MODP_3072 */
  "dl-modp",                    /* 16, MODP_4096 */
  "dl-modp",                    /* 17, MODP_6144 */
  "dl-modp",                    /* 18, MODP_8192 */
#ifdef SSHDIST_CRYPT_ECP
  "ec-modp",                    /* 19, ECP_256 */
  "ec-modp",                    /* 20, ECP_384 */
  "ec-modp",                    /* 21, ECP_521 */
#else /* SSHDIST_CRYPT_ECP */
  NULL,                         /* 19, NONE */
  NULL,                         /* 20, NONE */
  NULL,                         /* 21, NONE */
#endif /* SSHDIST_CRYPT_ECP */
  "dl-modp",                    /* 22, MODP_1024_160 */
  "dl-modp",                    /* 23, MODP_2048_224 */
  "dl-modp",                    /* 24, MODP_2048_256 */
#ifdef SSHDIST_CRYPT_ECP
  "ec-modp",                    /* 25, ECP_192 */
  "ec-modp",                    /* 26, ECP_224 */
  "ec-modp",                    /* 27, Brainpool ECP_224 */
  "ec-modp",                    /* 28, Brainpool ECP_256 */
  "ec-modp",                    /* 29, Brainpool ECP_384 */
  "ec-modp"                     /* 30, Brainpool ECP_512 */
#else /* SSHDIST_CRYPT_ECP */
  NULL,                         /* 25, NONE */
  NULL,                         /* 26, NONE */
  NULL,                         /* 27, NONE */
  NULL,                         /* 28, NONE */
  NULL,                         /* 29, NONE */
  NULL                          /* 30, NONE */
#endif /* SSHDIST_CRYPT_ECP */
};

/* Strengths of group in bits */
const unsigned int
ssh_ikev2_predefined_group_strengths[SSH_IKEV2_TRANSFORM_D_H_MAX] = {
  0,                            /* 0, NONE */
  0x42,                         /* 1, MODP_768 */
  0x4d,                         /* 2, MODP_1024 */
  0,                            /* 3, NONE */
  0,                            /* 4, NONE */
  0x5b,                         /* 5, MODP_1536 */
  0,                            /* 6, NONE */
  0,                            /* 7, NONE */
  0,                            /* 8, NONE */
  0,                            /* 9, NONE */
  0,                            /* 10, NONE */
  0,                            /* 11, NONE */
  0,                            /* 12, NONE */
  0,                            /* 13, NONE */
  110,                          /* 14, MODP_2048 */
  130,                          /* 15, MODP_3072 */
  150,                          /* 16, MODP_4096 */
  170,                          /* 17, MODP_6144 */
  190,                          /* 18, MODP_8192 */
#ifdef SSHDIST_CRYPT_ECP
  128,                          /* 19, ECP_256 */
  192,                          /* 20, ECP_384 */
  256,                          /* 21, ECP_521 */
#else /* SSHDIST_CRYPT_ECP */
  0,                            /* 19, NONE */
  0,                            /* 20, NONE */
  0,                            /* 21, NONE */
#endif /* SSHDIST_CRYPT_ECP */
  80,                           /* 22, MODP_1024_160 */
  112,                          /* 23, MODP_2048_224 */
  112,                          /* 24, MODP_2048_256 */
#ifdef SSHDIST_CRYPT_ECP
  96,                           /* 25, ECP_192 */
  112,                          /* 26, ECP_224 */
  112,                          /* 27, Brainpool ECP_224 */
  128,                          /* 28, Brainpool ECP_256 */
  192,                          /* 29, Brainpool ECP_384 */
  256                           /* 30, Brainpool ECP_512 */
#else /* SSHDIST_CRYPT_ECP */
  0,                            /* 25, NONE */
  0,                            /* 26, NONE */
  0,                            /* 27, NONE */
  0,                            /* 28, NONE */
  0,                            /* 29, NONE */
  0                             /* 30, NONE */
#endif /* SSHDIST_CRYPT_ECP */
};

/* Mapping between encryption algorithm name and ikev2
   encryption algorithm number */
const SshKeywordStruct ssh_ikev2_encr_algorithms[] = {
  /*  { "des_iv64", SSH_IKEV2_TRANSFORM_ENCR_DES_IV64 }, */
  { "des-cbc", SSH_IKEV2_TRANSFORM_ENCR_DES },
  { "3des-cbc", SSH_IKEV2_TRANSFORM_ENCR_3DES },
  { "rc5-16-cbc", SSH_IKEV2_TRANSFORM_ENCR_RC5 },
  { "idea-cbc", SSH_IKEV2_TRANSFORM_ENCR_IDEA },
  { "cast128-cbc", SSH_IKEV2_TRANSFORM_ENCR_CAST },
  { "blowfish-cbc", SSH_IKEV2_TRANSFORM_ENCR_BLOWFISH },
  { "camellia128-cbc", SSH_IKEV2_TRANSFORM_ENCR_CAMELLIA  | (128<<16) },
  { "camellia192-cbc", SSH_IKEV2_TRANSFORM_ENCR_CAMELLIA  | (192<<16) },
  { "camellia256-cbc", SSH_IKEV2_TRANSFORM_ENCR_CAMELLIA  | (256<<16) },
  /* { "3idea", SSH_IKEV2_TRANSFORM_ENCR_3IDEA }, */
  /* { "des_iv32", SSH_IKEV2_TRANSFORM_ENCR_DES_IV32 }, */
  { "null", SSH_IKEV2_TRANSFORM_ENCR_NULL },
  { "aes128-cbc", SSH_IKEV2_TRANSFORM_ENCR_AES_CBC | (128<<16) },
  { "aes192-cbc", SSH_IKEV2_TRANSFORM_ENCR_AES_CBC | (192<<16) },
  { "aes256-cbc", SSH_IKEV2_TRANSFORM_ENCR_AES_CBC | (256<<16) },
  { "aes128-ctr", SSH_IKEV2_TRANSFORM_ENCR_AES_CTR | (128<<16) },
  { "aes192-ctr", SSH_IKEV2_TRANSFORM_ENCR_AES_CTR | (192<<16) },
  { "aes256-ctr", SSH_IKEV2_TRANSFORM_ENCR_AES_CTR | (256<<16) },
  { "aes128-gcm", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16 | (128<<16) },
  { "aes192-gcm", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16 | (192<<16) },
  { "aes256-gcm", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16 | (256<<16) },
  { "aes128-gcm-8", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8 | (128<<16) },
  { "aes192-gcm-8", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8 | (192<<16) },
  { "aes256-gcm-8", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8 | (256<<16) },
  { "aes128-gcm-12", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12 | (128<<16) },
  { "aes192-gcm-12", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12 | (192<<16) },
  { "aes256-gcm-12", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12 | (256<<16) },
  { "aes128-ccm", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16 | (128<<16) },
  { "aes192-ccm", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16 | (192<<16) },
  { "aes256-ccm", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16 | (256<<16) },
  { "aes128-ccm-8", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8 | (128<<16) },
  { "aes192-ccm-8", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8 | (192<<16) },
  { "aes256-ccm-8", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8 | (256<<16) },
  { "aes128-ccm-12", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12 | (128<<16) },
  { "aes192-ccm-12", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12 | (192<<16) },
  { "aes256-ccm-12", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12 | (256<<16) },
  { "aes128-gmac", SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC | (128<<16) },
  { "aes192-gmac", SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC | (192<<16) },
  { "aes256-gmac", SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC | (256<<16) },
  { NULL, 0 }
};

/* Mapping between prf algorithm name and ikev2 prf
   algorithm number */
const SshKeywordStruct ssh_ikev2_prf_algorithms[] = {
  { "hmac-md5", SSH_IKEV2_TRANSFORM_PRF_HMAC_MD5 },
  { "hmac-sha1", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA1 },
  /* NOTE: we do not know the key length for tiger, assume 128. */
  { "hmac-tiger128", SSH_IKEV2_TRANSFORM_PRF_HMAC_TIGER },
  { "xcbcmac-aes", SSH_IKEV2_TRANSFORM_PRF_AES128_CBC },
  { "hmac-sha256", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA256 },
  { "hmac-sha384", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA384 },
  { "hmac-sha512", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA512 },
  { NULL, 0 }
};

/* Mapping between integrity algorithm name and ikev2
   integrity algorithm number */
const SshKeywordStruct ssh_ikev2_mac_algorithms[] = {
  { "hmac-md5-96", SSH_IKEV2_TRANSFORM_AUTH_HMAC_MD5_96 },
  { "hmac-sha1-96", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96 },
  { "cbcmac-des", SSH_IKEV2_TRANSFORM_AUTH_DES_MAC },
  /* { "kpdk_md5", SSH_IKEV2_TRANSFORM_AUTH_KPDK_MD5 }, */
  { "xcbcmac-aes-96", SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96 },
  { "hmac-sha256-128", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA256_128 },
  { "hmac-sha384-192", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA384_192 },
  { "hmac-sha512-256", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA512_256 },
  { "gmac-aes128", SSH_IKEV2_TRANSFORM_AUTH_AES_128_GMAC_128 },
  { "gmac-aes192", SSH_IKEV2_TRANSFORM_AUTH_AES_192_GMAC_128 },
  { "gmac-aes256", SSH_IKEV2_TRANSFORM_AUTH_AES_256_GMAC_128 },
  { NULL, 0 }
};

/* Mapping between integrity algorithm name and key length
   used in the underlaying hash.  */
const SshKeywordStruct ssh_ikev2_mac_key_lengths[] = {
  { "hmac-md5-96", 16 },
  { "hmac-sha1-96", 20 },
  { "hmac-sha256-128", 32 },
  { "hmac-sha384-192", 48 },
  { "hmac-sha512-256", 64 },
  { "gmac-aes128", 8 + 16 },
  { "gmac-aes192", 8 + 16 },
  { "gmac-aes256", 8 + 16 },
  { NULL, 0 }
};
