/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 transform numbers table and print function.
*/

#include "sshincludes.h"
#include "sshikev2-initiator.h"
#include "sshikev2-util.h"

#define SSH_DEBUG_MODULE "SshIkev2StringTransform"

/* Encryption numbers to string mapping.  */
const SshKeywordStruct ssh_ikev2_encr_to_string_table[] = {
  { "DES IV64", SSH_IKEV2_TRANSFORM_ENCR_DES_IV64 },
  { "DES", SSH_IKEV2_TRANSFORM_ENCR_DES },
  { "3DES", SSH_IKEV2_TRANSFORM_ENCR_3DES },
  { "RC5", SSH_IKEV2_TRANSFORM_ENCR_RC5 },
  { "IDEA", SSH_IKEV2_TRANSFORM_ENCR_IDEA },
  { "Cast", SSH_IKEV2_TRANSFORM_ENCR_CAST },
  { "Blowfish", SSH_IKEV2_TRANSFORM_ENCR_BLOWFISH },
  { "3IDEA", SSH_IKEV2_TRANSFORM_ENCR_3IDEA },
  { "DES IV32", SSH_IKEV2_TRANSFORM_ENCR_DES_IV32 },
  { "NULL", SSH_IKEV2_TRANSFORM_ENCR_NULL },
  { "AES CBC", SSH_IKEV2_TRANSFORM_ENCR_AES_CBC },
  { "AES CTR", SSH_IKEV2_TRANSFORM_ENCR_AES_CTR },
  { "AES GCM 8", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_8 },
  { "AES GCM 12", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_12 },
  { "AES GCM", SSH_IKEV2_TRANSFORM_ENCR_AES_GCM_16 },
  { "AES CCM 8", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_8 },
  { "AES CCM 12", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_12 },
  { "AES CCM", SSH_IKEV2_TRANSFORM_ENCR_AES_CCM_16 },
  { "NULL AUTH AES GCM", SSH_IKEV2_TRANSFORM_ENCR_NULL_AUTH_AES_GMAC },
  { NULL, 0 }
};

/* PRF numbers to string mapping.  */
const SshKeywordStruct ssh_ikev2_prf_to_string_table[] = {
  { "HMAC-MD5 PRF", SSH_IKEV2_TRANSFORM_PRF_HMAC_MD5 },
  { "HMAC-SHA1 PRF", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA1 },
  { "HMAC-TIGER PRF", SSH_IKEV2_TRANSFORM_PRF_HMAC_TIGER },
  { "AES128 CBC PRF", SSH_IKEV2_TRANSFORM_PRF_AES128_CBC },
  { "HMAC-SHA256 PRF", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA256 },
  { "HMAC-SHA384 PRF", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA384 },
  { "HMAC-SHA512 PRF", SSH_IKEV2_TRANSFORM_PRF_HMAC_SHA512 },
  { NULL, 0 }
};

/* Integrity numbers to string mapping.  */
const SshKeywordStruct ssh_ikev2_integ_to_string_table[] = {
  { "NONE", SSH_IKEV2_TRANSFORM_AUTH_NONE },
  { "HMAC-MD5-96", SSH_IKEV2_TRANSFORM_AUTH_HMAC_MD5_96 },
  { "HMAC-SHA1-96", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA1_96 },
  { "DES MAC", SSH_IKEV2_TRANSFORM_AUTH_DES_MAC },
  { "KPDK MD5", SSH_IKEV2_TRANSFORM_AUTH_KPDK_MD5 },
  { "AES-XCBC-96", SSH_IKEV2_TRANSFORM_AUTH_AES_XCBC_96 },
  { "HMAC-SHA256-128", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA256_128 },
  { "HMAC-SHA384-192", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA384_192 },
  { "HMAC-SHA512-256", SSH_IKEV2_TRANSFORM_AUTH_HMAC_SHA512_256 },
  { "AES128-GMAC-128", SSH_IKEV2_TRANSFORM_AUTH_AES_128_GMAC_128 },
  { "AES192-GMAC-128", SSH_IKEV2_TRANSFORM_AUTH_AES_192_GMAC_128 },
  { "AES256-GMAC-128", SSH_IKEV2_TRANSFORM_AUTH_AES_256_GMAC_128 },
  { NULL, 0 }
};

/* Diffie Hellman group numbers to string mapping.  */
const SshKeywordStruct ssh_ikev2_dh_to_string_table[] = {
  { "None", SSH_IKEV2_TRANSFORM_D_H_NONE},
  { "768 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_768 },
  { "155 bit EC2N", SSH_IKEV2_TRANSFORM_D_H_EC2N_155 },
  { "185 bit EC2N", SSH_IKEV2_TRANSFORM_D_H_EC2N_185 },
  { "1024 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_1024 },
  { "1536 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_1536 },
  { "2048 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_2048 },
  { "3072 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_3072 },
  { "4096 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_4096 },
  { "6144 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_6144 },
  { "8192 bit MODP", SSH_IKEV2_TRANSFORM_D_H_MODP_8192 },
#ifdef SSHDIST_CRYPT_ECP
  { "256 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_256},
  { "384 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_384},
  { "521 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_521},
#endif /* SSHDIST_CRYPT_ECP */
  { "RFC5114 1024-160 bit MODP",
    SSH_IKEV2_TRANSFORM_D_H_MODP_RFC5114_1024_160 },
  { "RFC5114 2048-224 bit MODP",
    SSH_IKEV2_TRANSFORM_D_H_MODP_RFC5114_2048_224 },
  { "RFC5114 2048-256 bit MODP",
    SSH_IKEV2_TRANSFORM_D_H_MODP_RFC5114_2048_256 },
#ifdef SSHDIST_CRYPT_ECP
  { "192 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC5114_192},
  { "224 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC5114_224},
#endif /* SSHDIST_CRYPT_ECP */
#ifdef SSHDIST_CRYPT_ECP
  { "Brainpool 224 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_224},
  { "Brainpool 256 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_256},
  { "Brainpool 384 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_384},
  { "Brainpool 512 bit ECP",   SSH_IKEV2_TRANSFORM_D_H_EC_MODP_RFC6932_512},
#endif /* SSHDIST_CRYPT_ECP */
  { NULL, 0 }
};

/* ESN numbers to string mapping.  */
const SshKeywordStruct ssh_ikev2_esn_to_string_table[] = {
  { "No ESN", SSH_IKEV2_TRANSFORM_ESN_NO_ESN },
  { "ESN", SSH_IKEV2_TRANSFORM_ESN_ESN },
  { NULL, 0 }
};

const char *ssh_ikev2_transform_to_string(SshIkev2TransformType type,
                                          SshIkev2TransformID value)
{
  const char *name, *unknown = NULL;

  switch (type)
    {
    case SSH_IKEV2_TRANSFORM_TYPE_ENCR:
      name = ssh_find_keyword_name(ssh_ikev2_encr_to_string_table, value);
      unknown = "unknown encryption";
      break;
    case SSH_IKEV2_TRANSFORM_TYPE_PRF:
      name = ssh_find_keyword_name(ssh_ikev2_prf_to_string_table, value);
      unknown = "unknown prf";
      break;
    case SSH_IKEV2_TRANSFORM_TYPE_INTEG:
      name = ssh_find_keyword_name(ssh_ikev2_integ_to_string_table, value);
      unknown = "unknown integrity";
      break;
    case SSH_IKEV2_TRANSFORM_TYPE_D_H:
      name = ssh_find_keyword_name(ssh_ikev2_dh_to_string_table, value);
      unknown = "unknown DH group";
      break;
    case SSH_IKEV2_TRANSFORM_TYPE_ESN:
      name = ssh_find_keyword_name(ssh_ikev2_esn_to_string_table, value);
      unknown = "unknown ESN value";
      break;
    default:
      name = "unknown type";
      break;
    }

  if (name == NULL)
    return unknown;
  return name;
}


/* Transform type number to string mapping */

const SshKeywordStruct ssh_ikev2_transform_type_to_string_table[] = {
  { "ENCR", SSH_IKEV2_TRANSFORM_TYPE_ENCR  },
  { "PRF", SSH_IKEV2_TRANSFORM_TYPE_PRF   },
  { "INTEG", SSH_IKEV2_TRANSFORM_TYPE_INTEG },
  { "D-H", SSH_IKEV2_TRANSFORM_TYPE_D_H   },
  { "ESN", SSH_IKEV2_TRANSFORM_TYPE_ESN   },
  { NULL, 0 }
};

const char *
ssh_ikev2_transform_type_to_string(
        SshIkev2TransformType type)
{
  const char *name;

  name = ssh_find_keyword_name(ssh_ikev2_transform_type_to_string_table, type);
  if (name != NULL)
    {
      return name;
    }

  return "UNKNOWN TRANSFORM TYPE";
}


int
ikev2_render_transform_attribute(
        unsigned char *buf,
        int buf_size,
        int precision,
        void *datum)
{
  SshUInt32 attribute;
  int len;

  attribute = *(SshUInt32 *) datum;

  if (attribute == 0)
    {
      len = ssh_snprintf(buf, buf_size, "");
    }
  else
  if ((attribute & 0x80000000) == 0)
    {
      len = ssh_snprintf(buf, buf_size, "TLV Attributes not supported");
    }
  else
    {
      unsigned type = ((attribute & 0x7fff0000) >> 16);
      unsigned value = (attribute & 0x0000ffff);

      if (type == 14)
        {
          len = ssh_snprintf(
                  buf, buf_size, "Key Length (%u) = %u", type, value);
        }
      else
        {
          len = ssh_snprintf(
                  buf, buf_size, "Unknown (%u) = %u", type, value);
        }
    }

  return len;
}
