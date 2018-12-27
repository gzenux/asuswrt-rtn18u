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

extern const SshPkAction ssh_pk_ec_modp_actions[];
extern const SshPkSignature ssh_ec_modp_signature_schemes[];
extern const SshPkEncryption ssh_ec_modp_encryption_schemes[];
#ifdef SSHDIST_CRYPT_DH
extern const SshPkDiffieHellman ssh_ec_modp_diffie_hellman_schemes[];
#endif /* SSHDIST_CRYPT_DH */

const SshPkType ssh_pk_ec_modp_generator =
/* Key type for elliptic curve discrete log based systems. */
{
  "ec-modp",
  ssh_pk_ec_modp_actions,
  ssh_ec_modp_signature_schemes,
  NULL_FNPTR,
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
  ssh_ecp_private_key_action_make,
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
