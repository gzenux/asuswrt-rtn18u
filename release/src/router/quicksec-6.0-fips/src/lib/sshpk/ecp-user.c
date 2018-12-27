/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Description for how to make ECP keys
*/

#include "sshincludes.h"
#include "sshpk_i.h"
#include "sshrgf.h"
#include "ecpglue.h"
#include "sshcrypt.h"

#ifdef SSHDIST_CRYPT_ECP

/* Elliptic curves over finite field modulo a prime. */

const SshPkSignature ssh_ec_modp_signature_schemes[] =
{
#ifdef SSHDIST_CRYPT_SHA
  { "dsa-none-sha1",
    &ssh_rgf_std_sha1_def,
    ssh_ecp_dsa_private_key_max_signature_input_len,
    ssh_ecp_dsa_private_key_max_signature_output_len,
    ssh_ecp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_ecp_dsa_private_key_sign,
    NULL_FNPTR },
#endif /* SSHDIST_CRYPT_SHA */
#ifdef SSHDIST_CRYPT_SHA256
  { "dsa-none-sha224",
    &ssh_rgf_std_sha224_def,
    ssh_ecp_dsa_private_key_max_signature_input_len,
    ssh_ecp_dsa_private_key_max_signature_output_len,
    ssh_ecp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_ecp_dsa_private_key_sign,
    NULL_FNPTR },
  { "dsa-none-sha256",
    &ssh_rgf_std_sha256_def,
    ssh_ecp_dsa_private_key_max_signature_input_len,
    ssh_ecp_dsa_private_key_max_signature_output_len,
    ssh_ecp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_ecp_dsa_private_key_sign,
    NULL_FNPTR },
#endif /* SSHDIST_CRYPT_SHA256 */
#ifdef SSHDIST_CRYPT_SHA512
  { "dsa-none-sha384",
    &ssh_rgf_std_sha384_def,
    ssh_ecp_dsa_private_key_max_signature_input_len,
    ssh_ecp_dsa_private_key_max_signature_output_len,
    ssh_ecp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_ecp_dsa_private_key_sign,
    NULL_FNPTR },
  { "dsa-none-sha512",
    &ssh_rgf_std_sha512_def,
    ssh_ecp_dsa_private_key_max_signature_input_len,
    ssh_ecp_dsa_private_key_max_signature_output_len,
    ssh_ecp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_ecp_dsa_private_key_sign,
    NULL_FNPTR },
#endif /* SSHDIST_CRYPT_SHA512 */
  { NULL },
};

const SshPkEncryption ssh_ec_modp_encryption_schemes[] =
{
  { NULL }
};

#ifdef SSHDIST_CRYPT_DH
/* Table of all supported diffie-hellman schemes for dl-modp keys. */

const SshPkDiffieHellman ssh_ec_modp_diffie_hellman_schemes[] =
{
  { "plain",
    ssh_ecp_diffie_hellman_exchange_length,
    ssh_ecp_diffie_hellman_shared_secret_length,
    ssh_ecp_diffie_hellman_generate,
    NULL_FNPTR,
    ssh_ecp_diffie_hellman_final,
    NULL_FNPTR
  },
  { NULL },
};
#endif /* SSHDIST_CRYPT_DH */

const SshPkAction ssh_pk_ec_modp_actions[] =
{
  /* key type */
  { SSH_PKF_KEY_TYPE,
    SSH_PK_ACTION_FLAG_KEY_TYPE | SSH_PK_ACTION_FLAG_PRIVATE_KEY |
    SSH_PK_ACTION_FLAG_PUBLIC_KEY | SSH_PK_ACTION_FLAG_PK_GROUP,
    NULL_FNPTR, NULL_FNPTR },

  /* Handling of keys and parameters. */

  /* prime-p (private_key, public_key, pk_group versions) */
  { SSH_PKF_PRIME_P,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_PRIME_P,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_PRIME_P,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* generator-g (private_key, public_key, pk_group versions) */
  { SSH_PKF_GENERATOR_G,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_GENERATOR_G,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_GENERATOR_G,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* prime-q (private_key, public_key, pk_group versions) */
  { SSH_PKF_PRIME_Q,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_PRIME_Q,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_PRIME_Q,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* Curve a */
  { SSH_PKF_CURVE_A,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_CURVE_A,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_CURVE_A,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* Curve b */
  { SSH_PKF_CURVE_B,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_CURVE_B,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_CURVE_B,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* Cardinality */
  { SSH_PKF_CARDINALITY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_CARDINALITY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_CARDINALITY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* secret-x (private_key) */
  { SSH_PKF_SECRET_X,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  /* public-y (private_key, public_key) */
  { SSH_PKF_PUBLIC_Y,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_PUBLIC_Y,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  /* size (private_key, public_key, pk_group) */
  { SSH_PKF_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* Predefined group. */
  { SSH_PKF_PREDEFINED_GROUP,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_PREDEFINED_GROUP,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_PREDEFINED_GROUP,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* randomizer entropy (private_key, public_key, pk_group) */
  { SSH_PKF_RANDOMIZER_ENTROPY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_RANDOMIZER_ENTROPY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_RANDOMIZER_ENTROPY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* Point compression */
  { SSH_PKF_POINT_COMPRESS,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_ecp_action_private_key_put,
    ssh_ecp_action_private_key_get },

  { SSH_PKF_POINT_COMPRESS,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_ecp_action_public_key_put,
    ssh_ecp_action_public_key_get },

  { SSH_PKF_POINT_COMPRESS,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_ecp_action_param_put,
    ssh_ecp_action_param_get },

  /* End of list. */
  { SSH_PKF_END }
};


const SshPkType ssh_pk_ec_modp =
/* Key type for elliptic curve discrete log based systems. */
{
  "ec-modp",
  ssh_pk_ec_modp_actions,
  ssh_ec_modp_signature_schemes,
  NULL,
#ifdef SSHDIST_CRYPT_DH
  ssh_ec_modp_diffie_hellman_schemes,
#else /* SSHDIST_CRYPT_DH */
  NULL,
#endif /* SSHDIST_CRYPT_DH */

  /* Basic group operations. */
  ssh_ecp_action_init,
  ssh_ecp_param_action_make,
  ssh_ecp_action_free,

  ssh_ecp_param_import,
  ssh_ecp_param_export,
  ssh_ecp_param_free,
  ssh_ecp_param_copy,
  ssh_ecp_param_get_predefined_groups,

  /* Precomputation. */
  NULL_FNPTR,

  /* Randomizer generation. */
  ssh_ecp_param_count_randomizers,
  NULL_FNPTR, /* return_randomizer */
  ssh_ecp_param_generate_randomizer,
  ssh_ecp_param_export_randomizer,
  ssh_ecp_param_import_randomizer,

  /* Public key operations. */
  ssh_ecp_action_public_key_init,
  ssh_ecp_public_key_action_make,
  ssh_ecp_action_free,

  ssh_ecp_public_key_import,
  ssh_ecp_public_key_export,
  ssh_ecp_public_key_free,
  ssh_ecp_public_key_copy,
  ssh_ecp_public_key_derive_param,

  /* Precomputation. */
  NULL_FNPTR,

  /* Private key operations. */
  ssh_ecp_action_init,
  ssh_ecp_private_key_action_make,
  NULL_FNPTR,
  ssh_ecp_action_free,

  ssh_ecp_private_key_import,
  ssh_ecp_private_key_export,
  ssh_ecp_private_key_free,
  ssh_ecp_private_key_derive_public_key,
  ssh_ecp_private_key_copy,
  ssh_ecp_private_key_derive_param,

  /* Precomputation. */
  NULL_FNPTR,

  /* Key pointer */
  NULL_FNPTR
};
#endif /* SSHDIST_CRYPT_ECP */
