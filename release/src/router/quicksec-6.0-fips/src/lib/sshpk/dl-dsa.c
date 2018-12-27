/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Discrete Logarithm Digital Signature Algorithm
*/

#include "sshincludes.h"
#ifdef SSHDIST_CRYPT_DSA
#include "sshmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "dlglue.h"
#include "dl-internal.h"
#include "sshgenmp.h"

/* DSA - Digital Signature Algorithm */

SshCryptoStatus
ssh_dlp_dsa_public_key_verify(const void *public_key,
                              const unsigned char *signature,
                              size_t signature_len,
                              SshRGF rgf)
{
  const SshDLPublicKey *pub_key = public_key;
  unsigned int len = ssh_mprz_byte_size(&pub_key->param->q);
  unsigned int vlen;
  SshMPIntegerStruct v, w, s, r, e, invs, u1, u2;
  unsigned char *digest;
  size_t digest_len;
  /* Assume failure. */
  SshCryptoStatus status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;

  if (signature_len & 1)
      return status;

  vlen = signature_len / 2;

  if (vlen > len)
    return status;

  ssh_mprz_init(&v);
  ssh_mprz_init(&w);
  ssh_mprz_init(&e);
  ssh_mprz_init(&s);
  ssh_mprz_init(&r);
  ssh_mprz_init(&u1);
  ssh_mprz_init(&u2);
  ssh_mprz_init(&invs);

  /* Verify the signature. */
  if ((status = ssh_rgf_for_signature(rgf, 8 * len,
                                      &digest, &digest_len)) != SSH_CRYPTO_OK)
    goto failed;

  /* Reduce to correct length. */
  ssh_mprz_set_buf(&e, digest, digest_len);
  ssh_mprz_mod(&e, &e, &pub_key->param->q);

  ssh_free(digest);

  /* Convert and reduce signature. */
  ssh_mprz_set_buf(&r, signature, vlen);
  if (ssh_mprz_cmp(&r, &pub_key->param->q) >= 0 ||
      ssh_mprz_cmp_ui(&r, 0) <= 0)
    {
      status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
      goto failed;
    }

  ssh_mprz_set_buf(&s, signature + vlen, vlen);
  if (ssh_mprz_cmp(&s, &pub_key->param->q) >= 0 ||
      ssh_mprz_cmp_ui(&s, 0) <= 0)
    {
      status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
      goto failed;
    }

  /* Compute verification parameters:

  g^(k(m + rx)^-1 * m) * g^(x*k(m + rx)^-1 * r)) =
     g^k((m + rx)^-1 * m + (m + rx)^-1 * x * r) =
     g^k((m + rx)^-1 * (m + rx)) = g^k.

   */

  ssh_mprz_mod_invert(&invs, &s, &pub_key->param->q);
  ssh_mprz_mul(&u1, &invs, &e);
  ssh_mprz_mod(&u1, &u1, &pub_key->param->q);
  ssh_mprz_mul(&u2, &invs, &r);
  ssh_mprz_mod(&u2, &u2, &pub_key->param->q);

  /* Exponentiate. */
  ssh_mprz_powm_gg(&v, &pub_key->param->g, &u1,
                 &pub_key->y, &u2, &pub_key->param->p);
  ssh_mprz_mod(&v, &v, &pub_key->param->p);
  ssh_mprz_mod(&v, &v, &pub_key->param->q);

  /* Check validy. If and only if v = r then successful. */
  status = SSH_CRYPTO_SIGNATURE_CHECK_FAILED;
  if (ssh_mprz_cmp(&v, &r) == 0)
    status = SSH_CRYPTO_OK;

failed:
  /* Clean memory. */
  ssh_mprz_clear(&v);
  ssh_mprz_clear(&w);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&s);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&invs);
  ssh_mprz_clear(&u1);
  ssh_mprz_clear(&u2);

  return status;
}

size_t
ssh_dlp_dsa_private_key_max_signature_input_len(const void *private_key,
                                                SshRGF rgf)
{
  return (size_t)-1;
}

size_t
ssh_dlp_dsa_private_key_max_signature_output_len(const void *private_key,
                                                 SshRGF rgf)
{
  const SshDLPrivateKey *prv_key = private_key;
  return ssh_mprz_byte_size(&prv_key->param->q) * 2;
}

static SshCryptoStatus
ssh_dlp_dsa_private_key_sign(const void *private_key,
                             SshRGF rgf,
                             unsigned char *signature_buffer,
                             size_t ssh_buffer_len,
                             size_t *signature_length_return,
                             Boolean fips)
{
  const SshDLPrivateKey *prv_key = private_key;
  SshDLStackRandomizer *stack;
  SshCryptoStatus status;
  SshMPIntegerStruct k, e, r, k_inverse, s;
  unsigned int len = ssh_mprz_byte_size(&prv_key->param->q);
  unsigned char *digest;
  size_t digest_len;

  if (ssh_buffer_len < len * 2)
    return SSH_CRYPTO_DATA_TOO_SHORT;

  if ((status = ssh_rgf_for_signature(rgf, 8 * len,
                                      &digest, &digest_len)) != SSH_CRYPTO_OK)
    return status;

  ssh_mprz_init(&k);
  ssh_mprz_init(&e);
  ssh_mprz_init(&r);
  ssh_mprz_init(&k_inverse);
  ssh_mprz_init(&s);

  /* Reduce */
  ssh_mprz_set_buf(&e, digest, digest_len);
  ssh_mprz_mod(&e, &e, &prv_key->param->q);

  ssh_free(digest);

retry0:

  stack = (SshDLStackRandomizer *)
    ssh_cstack_pop(&prv_key->param->stack, SSH_DLP_STACK_RANDOMIZER);

  /* Check if in stack. */
  if (!stack)
    {
      status =
        ssh_mp_fips186_ffc_per_message_secret(&prv_key->param->p,
                                              &prv_key->param->q,
                                              &prv_key->param->g,
                                              &k,
                                              &k_inverse);

      if (status != SSH_CRYPTO_OK)
        {
          ssh_mprz_clear(&k);
          ssh_mprz_clear(&e);
          ssh_mprz_clear(&r);
          ssh_mprz_clear(&k_inverse);
          ssh_mprz_clear(&s);
          return status;
        }

      /* Check if we have done any precomputation. */



#ifndef SSHMATH_MINIMAL
      if (prv_key->param->base_defined)
        ssh_mprz_powm_with_precomp(&r, &k, prv_key->param->base);
      else
        ssh_mprz_powm(&r, &prv_key->param->g, &k, &prv_key->param->p);
#else /* !SSHMATH_MINIMAL */
      ssh_mprz_powm(&r, &prv_key->param->g, &k, &prv_key->param->p);
#endif /* !SSHMATH_MINIMAL */


    }
  else
    {
      ssh_mprz_set(&k, &stack->k);
      ssh_mprz_set(&r, &stack->gk);
      /* This is legal, uses the destructor we have defined. */
      ssh_cstack_free(stack);

      /* Invert. */
      ssh_mprz_mod_invert(&k_inverse, &k, &prv_key->param->q);
    }

  /* Compute: r = (g^(k mod q) mod p) mod q */
  ssh_mprz_mod(&r, &r, &prv_key->param->q);
  if (ssh_mprz_cmp_ui(&r, 0) == 0)
    goto retry0;

  /* Compute signature s = k^-1(e + xr). */
  ssh_mprz_mul(&s, &r, &prv_key->x);
  ssh_mprz_add(&s, &s, &e);
  ssh_mprz_mul(&s, &s, &k_inverse);
  ssh_mprz_mod(&s, &s, &prv_key->param->q);

  if (ssh_mprz_cmp_ui(&s, 0) == 0)
    goto retry0;

  /* Linearize signature. */
  ssh_mprz_get_buf(signature_buffer, len, &r);
  ssh_mprz_get_buf(signature_buffer + len, len, &s);
  *signature_length_return = len * 2;

  /* Clear temps. */
  ssh_mprz_clear(&k);
  ssh_mprz_clear(&e);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&k_inverse);
  ssh_mprz_clear(&s);

  return SSH_CRYPTO_OK;
}

SshCryptoStatus
ssh_dlp_dsa_private_key_sign_std(const void *private_key,
                                 SshRGF rgf,
                                 unsigned char *signature_buffer,
                                 size_t ssh_buffer_len,
                                 size_t *signature_length_return)
{
  return ssh_dlp_dsa_private_key_sign(private_key,
                                      rgf,
                                      signature_buffer,
                                      ssh_buffer_len,
                                      signature_length_return,
                                      FALSE);
}

SshCryptoStatus
ssh_dlp_dsa_private_key_sign_fips(const void *private_key,
                                 SshRGF rgf,
                                 unsigned char *signature_buffer,
                                 size_t ssh_buffer_len,
                                 size_t *signature_length_return)
{
  return ssh_dlp_dsa_private_key_sign(private_key,
                                      rgf,
                                      signature_buffer,
                                      ssh_buffer_len,
                                      signature_length_return,
                                      TRUE);
}
#endif /* SSHDIST_CRYPT_DSA */
