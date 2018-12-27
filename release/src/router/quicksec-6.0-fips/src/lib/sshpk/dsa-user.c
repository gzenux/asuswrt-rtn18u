/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Description for how to make DSA keys
*/

#include "sshincludes.h"
#include "sshpk_i.h"
#include "dlglue.h"
#include "sshrgf.h"
#include "sshcrypt.h"

#ifdef SSHDIST_CRYPT_DL
#ifdef SSHDIST_CRYPT_DSA

const SshPkSignature ssh_dl_modp_signature_schemes[] =
{
#ifdef SSHDIST_CRYPT_SHA
  { "dsa-nist-sha1",
    &ssh_rgf_std_sha1_def,
    ssh_dlp_dsa_private_key_max_signature_input_len,
    ssh_dlp_dsa_private_key_max_signature_output_len,
    ssh_dlp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_dlp_dsa_private_key_sign_fips,
    NULL_FNPTR
  },
#endif /* SSHDIST_CRYPT_SHA */

#ifdef SSHDIST_CRYPT_SHA256
  { "dsa-nist-sha224",
    &ssh_rgf_std_sha224_def,
    ssh_dlp_dsa_private_key_max_signature_input_len,
    ssh_dlp_dsa_private_key_max_signature_output_len,
    ssh_dlp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_dlp_dsa_private_key_sign_fips,
    NULL_FNPTR
  },

  { "dsa-nist-sha256",
    &ssh_rgf_std_sha256_def,
    ssh_dlp_dsa_private_key_max_signature_input_len,
    ssh_dlp_dsa_private_key_max_signature_output_len,
    ssh_dlp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_dlp_dsa_private_key_sign_fips,
    NULL_FNPTR
  },
#endif /* SSHDIST_CRYPT_SHA256 */

#ifdef SSHDIST_CRYPT_SHA512
  { "dsa-nist-sha384",
    &ssh_rgf_std_sha384_def,
    ssh_dlp_dsa_private_key_max_signature_input_len,
    ssh_dlp_dsa_private_key_max_signature_output_len,
    ssh_dlp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_dlp_dsa_private_key_sign_fips,
    NULL_FNPTR
  },

  { "dsa-nist-sha512",
    &ssh_rgf_std_sha512_def,
    ssh_dlp_dsa_private_key_max_signature_input_len,
    ssh_dlp_dsa_private_key_max_signature_output_len,
    ssh_dlp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_dlp_dsa_private_key_sign_fips,
    NULL_FNPTR
  },
#endif /* SSHDIST_CRYPT_SHA512 */

  { "dsa",
    NULL,
    NULL_FNPTR,
    NULL_FNPTR,
    ssh_dlp_dsa_public_key_verify,
    NULL_FNPTR,
    ssh_dlp_dsa_private_key_sign_fips,
    NULL_FNPTR
  },

  { NULL }
};

/* Table of all supported encryption schemes for dl-modp keys. */
const SshPkEncryption ssh_dl_modp_encryption_schemes[] =
{
  { NULL }
};
#endif /* SSHDIST_CRYPT_DSA */

#ifdef SSHDIST_CRYPT_DH
/* Table of all supported diffie-hellman schemes for dl-modp keys. */
const SshPkDiffieHellman ssh_dl_modp_diffie_hellman_schemes[] =
{
  { "plain",
    ssh_dlp_diffie_hellman_exchange_length,
    ssh_dlp_diffie_hellman_shared_secret_length,
    ssh_dlp_diffie_hellman_generate,
    NULL_FNPTR,
    ssh_dlp_diffie_hellman_final,
    NULL_FNPTR
  },
  { NULL },
};
#endif /* SSHDIST_CRYPT_DH */

/* DLP special actions. */
const SshPkAction ssh_pk_dl_modp_actions[] =
{
  /* key type */
  { SSH_PKF_KEY_TYPE,
    SSH_PK_ACTION_FLAG_KEY_TYPE | SSH_PK_ACTION_FLAG_PRIVATE_KEY |
    SSH_PK_ACTION_FLAG_PUBLIC_KEY | SSH_PK_ACTION_FLAG_PK_GROUP,
    NULL_FNPTR, NULL_FNPTR },
  /* Handling of keys and parameters. */

#ifdef SSHDIST_CRYPT_DH
  { SSH_PKF_PRIME_P,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  { SSH_PKF_GENERATOR_G,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  { SSH_PKF_PRIME_Q,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  { SSH_PKF_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  { SSH_PKF_RANDOMIZER_ENTROPY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },

  { SSH_PKF_PREDEFINED_GROUP,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PK_GROUP,
    ssh_dlp_action_param_put,
    ssh_dlp_action_param_get },
#endif /* SSHDIST_CRYPT_DH */

#ifdef SSHDIST_CRYPT_DSA
  /* prime-p (private_key, public_key, pk_group versions) */
  { SSH_PKF_PRIME_P,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_PRIME_P,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* generator-g (private_key, public_key, pk_group versions) */
  { SSH_PKF_GENERATOR_G,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_GENERATOR_G,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* prime-q (private_key, public_key, pk_group versions) */
  { SSH_PKF_PRIME_Q,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_PRIME_Q,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* prime-q size (private_key, public_key) */
  { SSH_PKF_PRIME_Q_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_PRIME_Q_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* secret-x (private_key) */
  { SSH_PKF_SECRET_X,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  /* public-y (private_key, public_key) */
  { SSH_PKF_PUBLIC_Y,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_PUBLIC_Y,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* size (private_key, public_key, pk_group) */
  { SSH_PKF_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_SIZE,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* randomizer entropy (private_key, public_key, pk_group) */
  { SSH_PKF_RANDOMIZER_ENTROPY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_RANDOMIZER_ENTROPY,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

  /* Predefined group. */
  { SSH_PKF_PREDEFINED_GROUP,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PRIVATE_KEY,
    ssh_dlp_action_private_key_put,
    ssh_dlp_action_private_key_get },

  { SSH_PKF_PREDEFINED_GROUP,
    SSH_PK_ACTION_FLAG_GET_PUT | SSH_PK_ACTION_FLAG_PUBLIC_KEY,
    ssh_dlp_action_public_key_put,
    ssh_dlp_action_public_key_get },

#endif /* SSHDIST_CRYPT_DSA */

  /* End of list. */
  { SSH_PKF_END }
};

const SshPkType ssh_pk_dl_modp =
{
  "dl-modp",
  ssh_pk_dl_modp_actions,
#ifdef SSHDIST_CRYPT_DSA
  ssh_dl_modp_signature_schemes,
  ssh_dl_modp_encryption_schemes,
#else /* SSHDIST_CRYPT_DSA */
  NULL,
  NULL,
#endif /* SSHDIST_CRYPT_DSA */
#ifdef SSHDIST_CRYPT_DH
  ssh_dl_modp_diffie_hellman_schemes,
#else /* SSHDIST_CRYPT_DH */
  NULL,
#endif /* SSHDIST_CRYPT_DH */

  /* Basic group operations. */
  ssh_dlp_action_init,
  ssh_dlp_param_action_make,
  ssh_dlp_action_free,

  ssh_dlp_param_import,
  ssh_dlp_param_export,
  ssh_dlp_param_free,
  ssh_dlp_param_copy,
  ssh_dlp_param_get_predefined_groups,

  /* Precomputation. */
  ssh_dlp_param_precompute,

  /* Randomizer generation. */
  ssh_dlp_param_count_randomizers,
  ssh_dlp_param_return_randomizer,
  ssh_dlp_param_generate_randomizer,
  ssh_dlp_param_export_randomizer,
  ssh_dlp_param_import_randomizer,

  /* Public key operations. */
  ssh_dlp_action_public_key_init,
  ssh_dlp_public_key_action_make,
  ssh_dlp_action_free,

  ssh_dlp_public_key_import,
  ssh_dlp_public_key_export,
  ssh_dlp_public_key_free,
  ssh_dlp_public_key_copy,
  ssh_dlp_public_key_derive_param,

  /* Precomputation. */
  ssh_dlp_public_key_precompute,

  /* Private key operations. */
  ssh_dlp_action_init,
  ssh_dlp_private_key_action_define,
  NULL_FNPTR,
  ssh_dlp_action_free,

  ssh_dlp_private_key_import,
  ssh_dlp_private_key_export,
  ssh_dlp_private_key_free,
  ssh_dlp_private_key_derive_public_key,
  ssh_dlp_private_key_copy,
  ssh_dlp_private_key_derive_param,

  /* Precomputation. */
  ssh_dlp_private_key_precompute,

  /* Key pointer */
  NULL_FNPTR
};

#endif /* SSHDIST_CRYPT_DL */
