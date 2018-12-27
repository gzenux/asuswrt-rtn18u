/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete Logarithm Parameter and Key Generation
*/

#include "sshincludes.h"
#ifdef SSHDIST_CRYPT_DL_GENERATE
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "dlglue.h"
#include "dl-internal.h"
#include "dl-stack.h"
#include "sshgenmp.h"



SshCryptoStatus ssh_dlp_param_generate(int bits, int small_bits,
                                       SshDLParam *param_return,
                                       Boolean fips)
{
  SshDLParam param, temp;
  SshCryptoStatus status = SSH_CRYPTO_OPERATION_FAILED;

  if ((param = ssh_malloc(sizeof(*param))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  ssh_dlp_init_param(param);

  if ((status = ssh_mp_fips186_ffc_domain_parameter_create(&param->p,
                                                           &param->q,
                                                           bits, small_bits))
      != SSH_CRYPTO_OK)
    {
      ssh_dlp_clear_param(param);
      ssh_free(param);
      return status;
    }


  if (ssh_mprz_random_generator(&param->g, &param->q, &param->p) != TRUE)
    {
      ssh_dlp_clear_param(param);
      ssh_free(param);
      return status;
    }

  temp = ssh_dlp_param_list_add(param);
  if (temp)
    {
      ssh_dlp_clear_param(param);
      ssh_free(param);
      param = temp;
    }

  *param_return = param;
  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_dlp_private_key_action_generate(void *context, void **key_ctx,
                                    Boolean dsa_key, Boolean fips)

{
  SshDLPInitCtx *ctx = context;
  SshCryptoStatus status;
  SshDLParam param = { 0 };

  /* First generate paramters. */
  if (!ctx->predefined)
    {
      if (ssh_mprz_cmp_ui(&ctx->p, 0) == 0 ||
          ssh_mprz_cmp_ui(&ctx->q, 0) == 0 ||
          ssh_mprz_cmp_ui(&ctx->g, 0) == 0)
        {
          if (ctx->size)
            {
              unsigned int q_size;

              /* In DSA if q_size is set in the context use the selected
                 value, else use 160 for up to 1024 bit keys and 256 for
                 larger. */
              if (dsa_key)
                {
                  if (ctx->q_size != 0)
                    q_size = ctx->q_size;
                  else if (ctx->size <= 1024)
                    q_size = 160;
                  else
                    q_size = 256;

                  if (ctx->size < q_size)
                    return SSH_CRYPTO_KEY_SIZE_INVALID;
                }
              else
                q_size = ctx->size / 2;

              status = ssh_dlp_param_generate(ctx->size,
                                              q_size,
                                              &param, fips);

              if (status != SSH_CRYPTO_OK)
                return status;
            }
          else
            return SSH_CRYPTO_OPERATION_FAILED;
        }
      else
        {
          if ((param = ssh_dlp_param_create(&ctx->p, &ctx->q, &ctx->g))
              == NULL)
            return SSH_CRYPTO_NO_MEMORY;
        }
    }
  else
    {
      if ((param = ssh_dlp_param_create_predefined(ctx->predefined)) == NULL)
        return SSH_CRYPTO_NO_MEMORY;
    }

  /* Then maybe generate private key components. */
  if (ssh_mprz_cmp_ui(&ctx->x, 0) == 0 || ssh_mprz_cmp_ui(&ctx->y, 0) == 0)
    {
      status = ssh_mp_fips186_ffc_keypair_generation(&param->p,
                                                     &param->q,
                                                     &param->g,
                                                     &ctx->x,
                                                     &ctx->y);

      if (status != SSH_CRYPTO_OK)
        return status;
    }

  return ssh_dlp_action_make(context, param, 2, key_ctx);
}


SshCryptoStatus
ssh_dlp_private_key_action_generate_dsa_fips(void *context, void **key_ctx)
{
  return ssh_dlp_private_key_action_generate(context, key_ctx, TRUE, TRUE);
}

SshCryptoStatus
ssh_dlp_private_key_action_generate_dsa_std(void *context, void **key_ctx)
{
  return ssh_dlp_private_key_action_generate(context, key_ctx, TRUE, FALSE);
}

SshCryptoStatus
ssh_dlp_private_key_action_generate_std(void *context, void **key_ctx)
{
  return ssh_dlp_private_key_action_generate(context, key_ctx, FALSE, FALSE);
}
#endif /* SSHDIST_CRYPT_DL_GENERATE */
