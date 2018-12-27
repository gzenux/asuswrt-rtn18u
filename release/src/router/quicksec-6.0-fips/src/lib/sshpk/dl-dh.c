/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete Logarithm Diffie Hellman
*/

#include "sshincludes.h"
#ifdef SSHDIST_CRYPT_DL
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "dlglue.h"
#include "dl-internal.h"
#include "sshgenmp.h"

/************************ Key exchange **************************/


/* Diffie-Hellman */
size_t
ssh_dlp_diffie_hellman_exchange_length(const void *parameters)
{
  const SshDLParamStruct *param = parameters;
  return ssh_mprz_byte_size(&param->p);
}

size_t
ssh_dlp_diffie_hellman_shared_secret_length(const void *parameters)
{
  const SshDLParamStruct *param = parameters;
  return ssh_mprz_byte_size(&param->p);
}

void ssh_dlp_diffie_hellman_internal_generate(SshMPInteger ret,
                                              SshDLParam param,
                                              SshMPInteger k)
{
  SshDLStackRandomizer *stack_r;

  stack_r = (SshDLStackRandomizer *)ssh_cstack_pop(&param->stack,
                                                   SSH_DLP_STACK_RANDOMIZER);
  if (!stack_r)
    {
      /* This is the main place where the entropy limitation will
         be very useful. Usually Diffie-Hellman session keys are for
         short term use, and are not used for stuff that needs to
         be secure forever. Thus smaller amount of entropy is suitable. */
      if (param->exponent_entropy)
        ssh_mprz_mod_random_entropy(k, &param->q,
                                  param->exponent_entropy);
      else
        ssh_mprz_mod_random(k, &param->q);

      ssh_mprz_powm(ret, &param->g, k, &param->p);
    }
  else
    {
      ssh_mprz_set(ret, &stack_r->gk);
      ssh_mprz_set(k, &stack_r->k);
      ssh_cstack_free(stack_r);
    }
}

SshCryptoStatus
ssh_dlp_diffie_hellman_generate(const void *parameters,
                                SshPkGroupDHSecret *secret,
                                unsigned char *exchange,
                                size_t exchange_length,
                                size_t *return_length)
{
  const SshDLParamStruct *param = parameters;
  SshMPIntegerStruct e;
  SshMPIntegerStruct k;
  SshMPIntegerStruct p_minus_one;
  unsigned int len = ssh_mprz_byte_size(&param->p);

  if (exchange_length < len)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  ssh_mprz_init(&k);
  ssh_mprz_init(&e);
  ssh_mprz_init(&p_minus_one);

 retry:
  ssh_dlp_diffie_hellman_internal_generate(&e, (SshDLParam )param, &k);

  if (ssh_mprz_isnan(&k) || ssh_mprz_isnan(&e))
    {
      ssh_mprz_clear(&k);
      ssh_mprz_clear(&e);
      ssh_mprz_clear(&p_minus_one);
      return SSH_CRYPTO_NO_MEMORY;
    }

  /* draft-ietf-ipsecme-dh-checks-01: 1 < public_value < p-1 */
  ssh_mprz_sub_ui(&p_minus_one, &param->p, 1);
  if ((ssh_mprz_cmp_ui(&e, 1) <= 0) ||
      (ssh_mprz_cmp(&e, &p_minus_one) >= 0))
    goto retry;

  ssh_mprz_clear(&p_minus_one);

  /* Linearize. */
  ssh_mprz_get_buf(exchange, len, &e);
  *return_length = len;

  ssh_mprz_clear(&e);

  *secret = ssh_mprz_to_dh_secret(&k);

  if (*secret == NULL)
    {
      ssh_mprz_clear(&k);
      return SSH_CRYPTO_NO_MEMORY;
    }

  ssh_mprz_clear(&k);
  return SSH_CRYPTO_OK;
}

static Boolean
ssh_dlp_diffie_hellman_internal_final(SshMPInteger ret,
                                      SshMPIntegerConst input,
                                      const SshDLParamStruct *param,
                                      SshMPInteger k)

{
  SshMPMontIntIdealStruct ideal;
  SshMPMontIntModStruct modint;
  SshMPIntegerStruct t;
  SshMPIntegerStruct p_minus_one;

  ssh_mprz_init(&p_minus_one);
  ssh_mprz_sub_ui(&p_minus_one, &param->p, 1);

  /* draft-ietf-ipsecme-dh-checks-01: 1 < public_value < p-1 */
  if (ssh_mprz_cmp_ui(input, 1) <= 0 || ssh_mprz_cmp(input, &p_minus_one) >= 0)
    return FALSE;

  ssh_mprz_clear(&p_minus_one);

  /* We can use montgomery ideals, since param->p is prime and hence odd. */
  if (!ssh_mpmzm_init_ideal(&ideal, &param->p))
    return FALSE;

  ssh_mpmzm_init(&modint, &ideal);
  ssh_mpmzm_set_mprz(&modint, ret);
  ssh_mpmzm_square(&modint, &modint);

  /* Get a temporary variable. */
  ssh_mprz_init(&t);

  /* Remark. We probably should add here the more general subgroup
     checks. The subgroup check could be interleaved with the actual
     Diffie-Hellman part. However, that would definitely be slower
     than just one exponentiation. */

  ssh_mprz_set_mpmzm(&t, &modint);

  /* Check for trivial subgroup of 2. */
  if (ssh_mprz_cmp_ui(&t, 1) == 0)
    {
      ssh_mprz_clear(&t);
      return FALSE;
    }

  ssh_mprz_clear(&t);
  ssh_mpmzm_clear(&modint);
  ssh_mpmzm_clear_ideal(&ideal);

  /* Diffie-Hellman part. */
  ssh_mprz_powm(ret, input, k, &param->p);
  return TRUE;
}

SshCryptoStatus
ssh_dlp_diffie_hellman_final(const void *parameters,
                             SshPkGroupDHSecret secret,
                             const unsigned char *exchange,
                             size_t exchange_length,
                             unsigned char *shared_secret,
                             size_t shared_secret_length,
                             size_t *return_length)
{
  const SshDLParamStruct *param = parameters;
  SshMPIntegerStruct v, k;
  unsigned int len = ssh_mprz_byte_size(&param->p);

  if (shared_secret_length < len)
    {
      ssh_pk_group_dh_secret_free(secret);
      return SSH_CRYPTO_DATA_TOO_SHORT;
    }

  ssh_mprz_init(&v);
  ssh_mprz_init(&k);

  /* Import the secret. */
  ssh_dh_secret_to_mprz(&k, secret);

  ssh_mprz_set_buf(&v, exchange, exchange_length);

  /* Compute v further. */
  if (ssh_dlp_diffie_hellman_internal_final(&v, &v, param, &k) == FALSE)
    {
      ssh_mprz_clear(&v);
      ssh_mprz_clear(&k);

      ssh_pk_group_dh_secret_free(secret);
      return SSH_CRYPTO_OPERATION_FAILED;
    }

  /* Free the secret. */
  ssh_pk_group_dh_secret_free(secret);

  ssh_mprz_clear(&k);

  /* Linearize. */
  ssh_mprz_get_buf(shared_secret, len, &v);
  *return_length = len;

  /* Clear memory. */
  ssh_mprz_clear(&v);
  return SSH_CRYPTO_OK;
}
#endif /* SSHDIST_CRYPT_DL */
