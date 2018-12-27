/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshmp-integer.h"

#define SSH_DEBUG_MODULE "SshMPArithmetic"

#ifdef SSHDIST_MATH

/* Arithmetic and number theory routines. */

int ssh_mprz_miller_rabin(SshMPIntegerConst op, unsigned int limit)
{
  SshMPMontIntIdealStruct ideal;
  SshMPMontIntModStruct modint;
  SshMPIntegerStruct q, a, b, op_1;
  int rv;
  unsigned int t, k, e;

  if (ssh_mprz_isnan(op))
    return 0;

  /* Assume primes are larger than 1. */
  if (ssh_mprz_cmp_ui(op, 1) <= 0)
    return 0;

  /* 'op' should be odd, so we can use Montgomery ideals. */
  if (!ssh_mpmzm_init_ideal(&ideal, op))
    return 0;

  ssh_mpmzm_init(&modint, &ideal);
  ssh_mprz_init(&q);
  ssh_mprz_init(&op_1);
  ssh_mprz_init(&a);
  ssh_mprz_init(&b);

  ssh_mprz_set(&q, op);
  ssh_mprz_sub_ui(&q, &q, 1);
  ssh_mprz_set(&op_1, &q);
  t = 0;
  while ((ssh_mprz_get_ui(&q) & 0x1) == 0)
    {
      ssh_mprz_div_2exp(&q, &q, 1);
      if (ssh_mprz_isnan(&q))
        {
          rv = 0;
          goto failure;
        }

      t++;
    }

  rv = 1;
  /* To the witness tests. */
  for (; limit; limit--)
    {
      /* We want to be fast, thus we use 0 < a < 2^(SSH_WORD_BITS).
         Some purists would insist that 'k' should be selected in more
         uniform way, however, this is accordingly to Cohen a reasonable
         approach. */
      do
        {
          k = ssh_rand();
          /* In the rare case that op is small, we need to ensure that
             k is not a multiple of op. */
          while (ssh_mprz_cmp_ui(op, k) <= 0)
            k = k/2;
        }
      while (k == 0);

      /* Exponentiate. */
      ssh_mprz_powm_ui_g(&b, k, &q, op);
      if (ssh_mprz_cmp_ui(&b, 1) != 0)
        {
          e = 0;
          while (ssh_mprz_cmp_ui(&b, 1) != 0 &&
                 ssh_mprz_cmp(&b, &op_1) != 0 &&
                 e <= t - 1)
            {
              ssh_mpmzm_set_mprz(&modint, &b);
              ssh_mpmzm_square(&modint, &modint);
              ssh_mprz_set_mpmzm(&b, &modint);
              e++;
            }

          if (ssh_mprz_cmp(&b, &op_1) != 0)
            {
              rv = 0;
              break;
            }
        }
    }

 failure:
  ssh_mpmzm_clear(&modint);
  ssh_mpmzm_clear_ideal(&ideal);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&op_1);

  return rv;
}

/* Following routine decides if the given value is very likely a prime
   or not. Returns 1 if 'op' is a probable prime, 0 otherwise. */
int ssh_mprz_is_probable_prime(SshMPIntegerConst op, unsigned int limit)
{
  SshMPIntegerStruct temp;

  /* The small prime test, this one should be performed for speed. */
  static const SshWord
    very_small_primes[10] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
  static const SshWord ideal = 3234846615UL;
  SshWord i, res;

  /* Assuming we mostly are looking for primes */
  if (ssh_mprz_isnan(op))
    return 0;

  /* Check for trivial cases. */
  if (ssh_mprz_cmp_ui(op, 2) < 0)
    return 0;

  if ((ssh_mprz_get_ui(op) & 0x1) == 0)
    {
      /* Perhaps the input is equal to 2. */
      if (ssh_mprz_cmp_ui(op, 2) == 0)
        return 1;
      return 0;
    }

  /* The small 'ideal' test. */
  res = ssh_mprz_mod_ui(op, ideal);
  for (i = 1; i < 10; i++)
    {
      /* Explicitly testing the base. */
      if ((res % very_small_primes[i]) == 0)
        {
          /* Perhaps the input is equal to the prime element? */
          if (ssh_mprz_cmp_ui(op, very_small_primes[i]) == 0)
            return 1;
          /* Was not and hence it must be composite. */
          return 0;
        }
    }

  /* Test first with Fermat's test with witness 2. */
  ssh_mprz_init(&temp);
  ssh_mprz_powm_ui_g(&temp, 2, op, op);
  if (ssh_mprz_cmp_ui(&temp, 2) != 0)
    {
      ssh_mprz_clear(&temp);
      return 0;
    }
  ssh_mprz_clear(&temp);

  /* Finally try Miller-Rabin test. */
  if (ssh_mprz_miller_rabin(op, limit) == 1)
    return 1;
  return 0;
}


/* Inversion routine, slow one, but fast enough. In particular, we
   could write a specialized routine for this along the binary
   extended GCD or other variations. But the point is how often do we
   need this? Not very. */
Boolean ssh_mprz_invert(SshMPInteger inv,
                        SshMPIntegerConst op, SshMPIntegerConst m)
{
  SshMPIntegerStruct g, v, t;
  Boolean rv = TRUE;

  if (ssh_mprz_nanresult2(inv, op, m))
    return FALSE;

  ssh_mprz_init(&g);
  ssh_mprz_init(&v);
  ssh_mprz_init(&t);

  /* Make sure that the input will lead to correct answer. */
  if (ssh_mprz_cmp_ui(op, 0) < 0)
    ssh_mprz_mod(&t, op, m);
  else
    ssh_mprz_set(&t, op);

  /* Compute with extented euclidean algorithm. */
  ssh_mprz_gcdext(&g, inv, &v, &t, m);
  if (ssh_mprz_isnan(&g))
    {
      ssh_mprz_makenan(inv, g.nankind);
      rv = FALSE;
    }

  /* Now, did we succeed? */
  if (rv == TRUE && ssh_mprz_cmp_ui(&g, 1) != 0)
    rv = FALSE;

  /* If we did, we don't want to return negative values. */
  if (rv == TRUE)
    {
      /* Return only values which are positive. */
      if (ssh_mprz_cmp_ui(inv, 0) < 0)
        ssh_mprz_add(inv, inv, m);
    }

  ssh_mprz_clear(&g);
  ssh_mprz_clear(&v);
  ssh_mprz_clear(&t);

  return rv;
}

/* End. */
#endif /* SSHDIST_MATH */
