/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Description:

         Take on the RSA key generation, modified after Tatu Ylonen's
         original SSH implementation.

         Description of the RSA algorithm can be found e.g. from the
         following sources:

   - Bruce Schneier: Applied Cryptography.  John Wiley & Sons, 1994.
   - Jennifer Seberry and Josed Pieprzyk: Cryptography: An Introduction to
     Computer Security.  Prentice-Hall, 1989.
   - Man Young Rhee: Cryptography and Secure Data Communications.  McGraw-Hill,
     1994.
   - R. Rivest, A. Shamir, and L. M. Adleman: Cryptographic Communications
     System and Method.  US Patent 4,405,829, 1983.
   - Hans Riesel: Prime Numbers and Computer Methods for Factorization.
     Birkhauser, 1994.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshpk_i.h"
#include "sshhash_i.h"
#include "rsa.h"

#define SSH_DEBUG_MODULE "SshCryptoRSA"

#define SSH_RSA_MINIMUM_PADDING 10
#define SSH_RSA_MAX_BYTES       65535

/* The size in bits of the integer r in the SshRSAPrivateKey structure
   used to protact against fault attacks. If a fault occurs, the probability
   that the fault verification test will fail is
   2^(-SSH_RSA_RANDOM_CRT_INTEGER_SIZE). 48 seems a reasonable number here,
   we don't want it too large as it will slow the private key operations
   excessively.
*/
#define SSH_RSA_RANDOM_CRT_INTEGER_SIZE 48

/* Generate a random short prime r, and compute the CRT
   exponents dp, dq from the private exponent d, and r.
   Since we choose r to be prime, this computes
   dp = d mod (r-1)(p-1) and dq = d mod (r-1)(q-1) */
void ssh_rsa_private_key_generate_crt_exponents(SshMPInteger dp,
                                                SshMPInteger dq,
                                                SshMPInteger r,
                                                SshMPIntegerConst p,
                                                SshMPIntegerConst q,
                                                SshMPIntegerConst d)
{
  SshMPIntegerStruct t1, t2;

 retry:
  ssh_mprz_random_prime(r, SSH_RSA_RANDOM_CRT_INTEGER_SIZE);

  /* Check the generate prime r is different to both p and q */
  if (ssh_mprz_isnan(r) || (ssh_mprz_cmp(r, p) == 0) ||
      (ssh_mprz_cmp(r, q) == 0))
    {
      if (ssh_mprz_isnan(r))
        return;
      goto retry;
    }

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  ssh_mprz_sub_ui(&t1, r, 1);
  ssh_mprz_sub_ui(&t2, p, 1);
  ssh_mprz_mul(&t1, &t1, &t2);
  ssh_mprz_mod(dp, d, &t1);

  ssh_mprz_sub_ui(&t1, r, 1);
  ssh_mprz_sub_ui(&t2, q, 1);
  ssh_mprz_mul(&t1, &t1, &t2);
  ssh_mprz_mod(dq, d, &t1);

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
}

/* Initialize the blinding integers, i.e. generate a random integer b,
   and compute b_exp = b^e mod n, and b_inv = b ^ (-1) mod n */
void ssh_rsa_private_key_init_blinding(SshMPInteger b_exp,
                                       SshMPInteger b_inv,
                                       SshMPIntegerConst n,
                                       SshMPIntegerConst e)
{
  SshMPIntegerStruct b;

  ssh_mprz_init(&b);

  /* Choose a random integer b */
  ssh_mprz_mod_random(&b, n);
  /* Compute b_exp as b ^ e mod n */
  ssh_mprz_powm(b_exp, &b, e, n);
  /* Compute b_inv as b ^ (-1) mod n */
  ssh_mprz_mod_invert(b_inv, &b, n);

  ssh_mprz_clear(&b);
}

/* Given mutual primes p and q, derives RSA key components n, d, e,
   and u.  The exponent e will be at least ebits bits in size. p must
   be smaller than q. */

static Boolean
derive_rsa_keys(SshMPInteger n, SshMPInteger e,
                SshMPInteger d, SshMPInteger u,
                SshMPInteger p, SshMPInteger q,
                unsigned int ebits)
{
  SshMPIntegerStruct p_minus_1, q_minus_1, aux, phi, G, F;
  Boolean rv = TRUE;

  /* Initialize. */
  ssh_mprz_init(&p_minus_1);
  ssh_mprz_init(&q_minus_1);
  ssh_mprz_init(&aux);
  ssh_mprz_init(&phi);
  ssh_mprz_init(&G);
  ssh_mprz_init(&F);

  /* Compute p-1 and q-1. */
  ssh_mprz_sub_ui(&p_minus_1, p, 1);
  ssh_mprz_sub_ui(&q_minus_1, q, 1);

  /* phi = (p - 1) * (q - 1); the number of positive integers less than p*q
     that are relatively prime to p*q. */
  ssh_mprz_mul(&phi, &p_minus_1, &q_minus_1);

  /* G is the number of "spare key sets" for a given modulus n.  The
     smaller G is, the better.  The smallest G can get is 2. This
     tells in practice nothing about the safety of primes p and q. */
  ssh_mprz_gcd(&G, &p_minus_1, &q_minus_1);

  /* F = phi / G; the number of relative prime numbers per spare key
     set. */
  ssh_mprz_div(&F, &phi, &G);

  /* Find a suitable e (the public exponent). */
  ssh_mprz_set_ui(e, 1);
  ssh_mprz_mul_2exp(e, e, ebits);
  ssh_mprz_sub_ui(e, e, 1); /* make lowest bit 1, and substract 2. */

  /* Keep adding 2 until it is relatively prime to (p-1)(q-1). */
  do
    {
      ssh_mprz_add_ui(e, e, 2);
      ssh_mprz_gcd(&aux, e, &phi);
    }
  while (!ssh_mprz_isnan(&aux) && ssh_mprz_cmp_ui(&aux, 1) != 0);

  /* d is the multiplicative inverse of e, mod F.  Could also be mod
     (p-1)(q-1); however, we try to choose the smallest possible d. */
  ssh_mprz_mod_invert(d, e, &F);

  /* u is the multiplicative inverse of p, mod q, if p < q.  It is used
     when doing private key RSA operations using the chinese remainder
     theorem method. */
  ssh_mprz_mod_invert(u, p, q);

  /* n = p * q (the public modulus). */
  ssh_mprz_mul(n, p, q);

  /* Check modulus (n) inv(p) (u) and inv(e) (d) */
  if (ssh_mprz_isnan(n) || ssh_mprz_isnan(u) || ssh_mprz_isnan(d))
    rv = FALSE;

  /* Clear auxiliary variables. */
  ssh_mprz_clear(&p_minus_1);
  ssh_mprz_clear(&q_minus_1);
  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&phi);
  ssh_mprz_clear(&G);
  ssh_mprz_clear(&F);

  return rv;
}

/* Generate RSA keys with e set to a probably fixed value. Beware of the
   rv. The rv is returned upon exit, and there is at least 3 different
   return values. 0 = failure, 1 = e has been changed from the given
   e, 2 = e is correct */
static int
derive_rsa_keys_with_e(SshMPInteger n, SshMPInteger e, SshMPInteger d,
                       SshMPInteger u, SshMPInteger p, SshMPInteger q,
                       SshMPInteger given_e)
{
  SshMPIntegerStruct p_minus_1, q_minus_1, aux, phi, G, F;
  int rv;

  /* Initialize. */
  ssh_mprz_init(&p_minus_1);
  ssh_mprz_init(&q_minus_1);
  ssh_mprz_init(&aux);
  ssh_mprz_init(&phi);
  ssh_mprz_init(&G);
  ssh_mprz_init(&F);

  /* Compute p-1 and q-1. */
  ssh_mprz_sub_ui(&p_minus_1, p, 1);
  ssh_mprz_sub_ui(&q_minus_1, q, 1);

  /* phi = (p - 1) * (q - 1); the number of positive integers less than p*q
     that are relatively prime to p*q. */
  ssh_mprz_mul(&phi, &p_minus_1, &q_minus_1);

  /* G is the number of "spare key sets" for a given modulus n.  The smaller
     G is, the better.  The smallest G can get is 2. This tells
     in practice nothing about the safety of primes p and q. */
  ssh_mprz_gcd(&G, &p_minus_1, &q_minus_1);

  /* F = phi / G; the number of relative prime numbers per spare key set. */
  ssh_mprz_div(&F, &phi, &G);

  /* Find a suitable e (the public exponent). */
  ssh_mprz_set(e, given_e);
  if (ssh_mprz_cmp_ui(e, 3) < 0)
    {
      rv = 0;
      goto failed;
    }

  /* Transform the e into something that is has some probability of
     being correct. */
  if ((ssh_mprz_get_ui(e) & 0x1) == 0)
    ssh_mprz_add_ui(e, e, 1);
  ssh_mprz_sub_ui(e, e, 2);
  /* Keep adding 2 until it is relatively prime to (p-1)(q-1). */
  do
    {
      ssh_mprz_add_ui(e, e, 2);
      ssh_mprz_gcd(&aux, e, &phi);
    }
  while (!ssh_mprz_isnan(&aux) && ssh_mprz_cmp_ui(&aux, 1) != 0);

  /* Verify that the e is correct still! */
  if (ssh_mprz_cmp(e, given_e) != 0)
    rv = 1;
  else
    rv = 2;

  /* d is the multiplicative inverse of e, mod F.  Could also be mod
     (p-1)(q-1); however, we try to choose the smallest possible d. */
  ssh_mprz_mod_invert(d, e, &F);

  /* u is the multiplicative inverse of p, mod q, if p < q.  It is used
     when doing private key RSA operations using the chinese remainder
     theorem method. */
  ssh_mprz_mod_invert(u, p, q);

  /* n = p * q (the public modulus). */
  ssh_mprz_mul(n, p, q);

failed:

  /* Clear auxiliary variables. */
  ssh_mprz_clear(&p_minus_1);
  ssh_mprz_clear(&q_minus_1);
  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&phi);
  ssh_mprz_clear(&G);
  ssh_mprz_clear(&F);

  return rv;
}

/* Almost same as above but is given d also. Creates the valid
   SshRSAPrivateKey. Is used from action make routines. */
SshCryptoStatus
ssh_rsa_make_private_key_of_pqd(SshMPInteger p, SshMPInteger q, SshMPInteger d,
                                void **key_ctx)
{
  SshMPIntegerStruct p_minus_1, q_minus_1, aux, phi, G, F;
  SshRSAPrivateKey *private_key;

  if ((private_key = ssh_malloc(sizeof(*private_key))) == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Initialize. */
  ssh_mprz_init(&p_minus_1);
  ssh_mprz_init(&q_minus_1);
  ssh_mprz_init(&aux);
  ssh_mprz_init(&phi);
  ssh_mprz_init(&G);
  ssh_mprz_init(&F);

  /* Initialize the private key. */
  ssh_mprz_init(&private_key->e);
  ssh_mprz_init(&private_key->d);
  ssh_mprz_init(&private_key->u);
  ssh_mprz_init(&private_key->n);
  ssh_mprz_init(&private_key->p);
  ssh_mprz_init(&private_key->q);
  ssh_mprz_init(&private_key->dp);
  ssh_mprz_init(&private_key->dq);
  ssh_mprz_init(&private_key->r);
  ssh_mprz_init(&private_key->b_exp);
  ssh_mprz_init(&private_key->b_inv);

  /* Compute p-1 and q-1. */
  ssh_mprz_sub_ui(&p_minus_1, p, 1);
  ssh_mprz_sub_ui(&q_minus_1, q, 1);

  /* Set the p and q. */
  ssh_mprz_set(&private_key->p, p);
  ssh_mprz_set(&private_key->q, q);

  /* phi = (p - 1) * (q - 1); the number of positive integers less than p*q
     that are relatively prime to p*q. */
  ssh_mprz_mul(&phi, &p_minus_1, &q_minus_1);

  /* G is the number of "spare key sets" for a given modulus n.  The smaller
     G is, the better.  The smallest G can get is 2. This tells
     in practice nothing about the safety of primes p and q. */
  ssh_mprz_gcd(&G, &p_minus_1, &q_minus_1);

  /* F = phi / G; the number of relative prime numbers per spare key set. */
  ssh_mprz_div(&F, &phi, &G);

  /* Find a suitable e (the public exponent). */
  ssh_mprz_mod_invert(&private_key->e, d, &phi);
  ssh_mprz_set(&private_key->d, d);

  /* u is the multiplicative inverse of p, mod q, if p < q.  It is used
     when doing private key RSA operations using the chinese remainder
     theorem method. */
  ssh_mprz_mod_invert(&private_key->u, p, q);

  /* n = p * q (the public modulus). */
  ssh_mprz_mul(&private_key->n, p, q);

  /* We generate a new random prime r, and from r derive dp, dq */
  ssh_rsa_private_key_generate_crt_exponents(&private_key->dp,
                                             &private_key->dq,
                                             &private_key->r,
                                             &private_key->p,
                                             &private_key->q,
                                             &private_key->d);

  ssh_rsa_private_key_init_blinding(&private_key->b_exp, &private_key->b_inv,
                                    &private_key->n, &private_key->e);

  /* Compute the bit size of the key. */
    private_key->bits = ssh_mprz_bit_size(&private_key->n);

  if (ssh_mprz_isnan(&private_key->p) ||
      ssh_mprz_isnan(&private_key->q) ||
      ssh_mprz_isnan(&private_key->u) ||
      ssh_mprz_isnan(&private_key->d) ||
      ssh_mprz_isnan(&private_key->e) ||
      ssh_mprz_isnan(&private_key->n) ||
      ssh_mprz_isnan(&private_key->dp) ||
      ssh_mprz_isnan(&private_key->dq) ||
      ssh_mprz_isnan(&private_key->r) ||
      ssh_mprz_isnan(&private_key->b_exp) ||
      ssh_mprz_isnan(&private_key->b_inv))
    {
      ssh_mprz_clear(&private_key->n);
      ssh_mprz_clear(&private_key->e);
      ssh_mprz_clear(&private_key->d);
      ssh_mprz_clear(&private_key->u);
      ssh_mprz_clear(&private_key->p);
      ssh_mprz_clear(&private_key->q);
      ssh_mprz_clear(&private_key->dq);
      ssh_mprz_clear(&private_key->dp);
      ssh_mprz_clear(&private_key->r);
      ssh_mprz_clear(&private_key->b_exp);
      ssh_mprz_clear(&private_key->b_inv);
      ssh_free(private_key);
      private_key = NULL;
      return SSH_CRYPTO_OPERATION_FAILED;
    }


  /* Clear auxiliary variables. */
  ssh_mprz_clear(&p_minus_1);
  ssh_mprz_clear(&q_minus_1);
  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&phi);
  ssh_mprz_clear(&G);
  ssh_mprz_clear(&F);


  /* Return the private key object. */
  *key_ctx = (void *)private_key;
  return SSH_CRYPTO_OK;
}

/* Generates RSA public and private keys.  This initializes the data
   structures; they should be freed with rsa_clear_private_key and
   rsa_clear_public_key. */

SshCryptoStatus
ssh_rsa_generate_private_key(unsigned int bits, SshMPInteger e, void **key_ctx)
{
  SshMPIntegerStruct test, aux, min, max;
  unsigned int pbits;
  int ret;
  SshRSAPrivateKey *prv = ssh_malloc(sizeof(*prv));

  if (prv == NULL)
    return SSH_CRYPTO_NO_MEMORY;

  /* Initialize our key. */
  ssh_mprz_init(&prv->q);
  ssh_mprz_init(&prv->p);
  ssh_mprz_init(&prv->e);
  ssh_mprz_init(&prv->d);
  ssh_mprz_init(&prv->u);
  ssh_mprz_init(&prv->n);
  ssh_mprz_init(&prv->dp);
  ssh_mprz_init(&prv->dq);
  ssh_mprz_init(&prv->r);
  ssh_mprz_init(&prv->b_exp);
  ssh_mprz_init(&prv->b_inv);

  /* Auxiliary variables. */
  ssh_mprz_init(&test);
  ssh_mprz_init(&aux);
  ssh_mprz_init(&min);
  ssh_mprz_init(&max);

  /* Compute the number of bits in each prime. Now, both p and q are
     always of same size. */
  if (bits & 1)
    pbits = (bits + 1) / 2;
  else
    pbits = bits / 2;

  if (pbits < 3)
    goto failure;

  /* Choose an interval to search for p and q so that we ensure that p
     and q are both integers of 'pbits' bits and their product is an
     integer of 'bits' bits.

     If 'bits' is even, then 'bits' = 2 * 'pbits', and if we choose

     3/4 * 2^(pbits) < p, q < 2^(pbits),  we then have

     2^(bits-1)<  9/16 * 2^(bits) < p*q < 2^(bits)

     so p and q are both 'pbits' bit numbers and n=pq is a 'bits' bit number.

     If 'bits' is odd, then 'bits' = 2 * 'pbits' - 1, and if we choose

     2^(pbits-1) < p, q < 5/8 * 2^(pbits),  we then have

     2^(bits-1)< p*q < 25/64 * 2^(2*pbits) < 2^(bits)

     so p and q are both 'pbits' bit numbers and n=pq is a 'bits' bit number.
  */
  if ((bits & 1) == 0)
    {
      /* Form 2^(pbits-1) + 2^(pbits-2) = 3/4 * 2^(pbits)   */
      ssh_mprz_set_ui(&aux, 0);
      ssh_mprz_set_bit(&aux, pbits - 1);
      ssh_mprz_set_bit(&aux, pbits - 2);
      ssh_mprz_set(&min, &aux);

      /* Form 2^(pbits) */
      ssh_mprz_set_ui(&aux, 0);
      ssh_mprz_set_bit(&aux, pbits);
      ssh_mprz_set(&max, &aux);
    }
  else
    {
      /* Form 2^(pbits-1) */
      ssh_mprz_set_ui(&aux, 0);
      ssh_mprz_set_bit(&aux, pbits - 1);
      ssh_mprz_set(&min, &aux);

      /* Form 2^(pbits-1) + 2^(pbits-3) = 5/8 * 2^(pbits)   */
      ssh_mprz_set_ui(&aux, 0);
      ssh_mprz_set_bit(&aux, pbits - 1);
      ssh_mprz_set_bit(&aux, pbits - 3);
      ssh_mprz_set(&max, &aux);
    }

  if (ssh_mprz_isnan(&min) || ssh_mprz_isnan(&max))
    goto failure;

  /* Get a random prime p within the specified interval */
  ssh_mprz_random_prime_within_interval(&prv->p, &min, &max);

  if (ssh_mprz_isnan(&prv->p))
    goto failure;

 retry:
  /* Get a random prime q within the specified interval */
  ssh_mprz_random_prime_within_interval(&prv->q, &min, &max);

  if (ssh_mprz_isnan(&prv->q))
    goto failure;

  /* Sort them so that p < q. */
  ret = ssh_mprz_cmp(&prv->p, &prv->q);
  if (ret == 0)
    goto retry;

  if (ret > 0)
    {
      ssh_mprz_set(&aux, &prv->p);
      ssh_mprz_set(&prv->p, &prv->q);
      ssh_mprz_set(&prv->q, &aux);
    }

  /* Make certain p and q are relatively prime (in case one or both were false
     positives...  Though this is quite impossible). */
  ssh_mprz_gcd(&aux, &prv->p, &prv->q);
  if (ssh_mprz_cmp_ui(&aux, 1) != 0)
    goto retry;

  if (e == NULL)
    {
      /* Derive the RSA private key from the primes. */
      if (!derive_rsa_keys(&prv->n, &prv->e, &prv->d, &prv->u,
                           &prv->p, &prv->q, 16))
        goto failure;
    }
  else
    switch (derive_rsa_keys_with_e(&prv->n, &prv->e, &prv->d, &prv->u,
                                   &prv->p, &prv->q, e))
      {
      case 0:
        goto failure;
      case 1:
      case 2:
        /* Do nothing special, accept possible changes to the given value. */
        break;
      }

  /* We generate a new random prime r and from this dp, dq */
  ssh_rsa_private_key_generate_crt_exponents(&prv->dp, &prv->dq,
                                             &prv->r, &prv->p,
                                             &prv->q, &prv->d);

  ssh_rsa_private_key_init_blinding(&prv->b_exp, &prv->b_inv,
                                    &prv->n, &prv->e);

  if (ssh_mprz_isnan(&prv->b_exp) || ssh_mprz_isnan(&prv->b_inv) ||
      ssh_mprz_isnan(&prv->dp) || ssh_mprz_isnan(&prv->dq))
    goto failure;

  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&test);
  ssh_mprz_clear(&min);
  ssh_mprz_clear(&max);

  /* Compute the bit size of the key. */
  prv->bits = ssh_mprz_bit_size(&prv->n);
  *key_ctx = (void *)prv;
  return SSH_CRYPTO_OK;

 failure:
  ssh_mprz_clear(&prv->n);
  ssh_mprz_clear(&prv->e);
  ssh_mprz_clear(&prv->d);
  ssh_mprz_clear(&prv->u);
  ssh_mprz_clear(&prv->p);
  ssh_mprz_clear(&prv->q);
  ssh_mprz_clear(&prv->dp);
  ssh_mprz_clear(&prv->dq);
  ssh_mprz_clear(&prv->r);
  ssh_mprz_clear(&prv->b_exp);
  ssh_mprz_clear(&prv->b_inv);
  ssh_free(prv);

  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&test);
  ssh_mprz_clear(&min);
  ssh_mprz_clear(&max);
  return SSH_CRYPTO_OPERATION_FAILED;
}

/* Try to handle the given data in a reasonable manner. This can
   generate and define key. */
SshCryptoStatus
ssh_rsa_private_key_generate_action(void *context, void **key_ctx)
{
  SshRSAInitCtx *ctx = context;

  if (ssh_mprz_cmp_ui(&ctx->d, 0) == 0 ||
      ssh_mprz_cmp_ui(&ctx->p, 0) == 0 ||
      ssh_mprz_cmp_ui(&ctx->q, 0) == 0)
    {
      /* Generate with e, p and q set. */
      if (ssh_mprz_cmp_ui(&ctx->e, 0) != 0 &&
          ssh_mprz_cmp_ui(&ctx->p, 0) != 0 &&
          ssh_mprz_cmp_ui(&ctx->q, 0) != 0)
        {
          SshRSAPrivateKey *prv ;
          int rv;

          if ((prv = ssh_malloc(sizeof(*prv))) == NULL)
            return SSH_CRYPTO_NO_MEMORY;

          ssh_rsa_private_key_init(prv);

          ssh_mprz_set(&prv->q, &ctx->q);
          ssh_mprz_set(&prv->p, &ctx->p);
          rv = derive_rsa_keys_with_e(&prv->n, &prv->e, &prv->d, &prv->u,
                                      &prv->p, &prv->q, &ctx->e);

          /* We generate a new random prime r and from this dp, dq */
          ssh_rsa_private_key_generate_crt_exponents(&prv->dp, &prv->dq,
                                                     &prv->r, &prv->p,
                                                     &prv->q, &prv->d);

          ssh_rsa_private_key_init_blinding(&prv->b_exp, &prv->b_inv,
                                            &prv->n, &prv->e);

          if (ssh_mprz_isnan(&prv->b_exp) || ssh_mprz_isnan(&prv->b_inv) ||
              ssh_mprz_isnan(&prv->dp) || ssh_mprz_isnan(&prv->dq))
            {
              ssh_rsa_private_key_free(prv);
              return SSH_CRYPTO_OPERATION_FAILED;
            }

          prv->bits = ssh_mprz_bit_size(&prv->n);
          if (rv != 0)
            {
              *key_ctx = prv;
              return SSH_CRYPTO_OK;
            }
          else
            {
              ssh_rsa_private_key_free(prv);
              return SSH_CRYPTO_OPERATION_FAILED;
            }
        }

      /* Cannot generate because no predefined size exists. */
      if (ctx->bits == 0)
        return SSH_CRYPTO_KEY_INVALID;

      /* Generate with e set. */
      if (ssh_mprz_cmp_ui(&ctx->e, 0) != 0)
        return ssh_rsa_generate_private_key(ctx->bits,
                                            &ctx->e, key_ctx);

      /* Just generate from assigned values. */
      return ssh_rsa_generate_private_key(ctx->bits, NULL, key_ctx);
    }
  else
    {
      if (ssh_mprz_cmp_ui(&ctx->d, 0) != 0 &&
          ssh_mprz_cmp_ui(&ctx->p, 0) != 0 &&
          ssh_mprz_cmp_ui(&ctx->q, 0) != 0)
        {
          if (ssh_mprz_cmp_ui(&ctx->e, 0) != 0 &&
              ssh_mprz_cmp_ui(&ctx->n, 0) != 0 &&
              ssh_mprz_cmp_ui(&ctx->u, 0) != 0)
            {
              return
                ssh_rsa_make_private_key_of_all(&ctx->p, &ctx->q,
                                                &ctx->n, &ctx->e,
                                                &ctx->d, &ctx->u, key_ctx);
            }

          return ssh_rsa_make_private_key_of_pqd(&ctx->p, &ctx->q, &ctx->d,
                                                 key_ctx);
        }
    }
  return SSH_CRYPTO_KEY_INVALID;
}
