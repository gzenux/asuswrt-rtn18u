/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshmp-integer.h"

#define SSH_DEBUG_MODULE "SshMPArithmeticExtra"

#ifdef SSHDIST_MATH

/* Additional arithmetic and number theory routines. */


/* Routine which seeks next prime starting from start.

   This function does work for every start value, although, clearly
   very large values might make things difficult.
   */
Boolean ssh_mprz_next_prime(SshMPInteger p, SshMPIntegerConst start)
{
  SshMPIntegerStruct s;
  SshSieveStruct sieve;
  SshWord *moduli, m;
  unsigned char *diffs;
  unsigned long difference;
  unsigned int i, j, k, prime, bits, max, count, alloc_count;
  Boolean rv;
  /* The following tables are not the best possible. I have not done
     any analysis on the best possible tables. These are tables that
     seem almost sensible, although better ones could be computed. */
  unsigned int ssh_mprz_table_bits[9] =
  { 16, 64, 256, 512, 1024, 2048, 4192, 16384, 0 };
  unsigned int ssh_mprz_table_size[10] =
  { 64, 512, 1024, 2*1024, 4*1024, 8*1024, 16*1024, 32*1024, 64*1024,
    128*1024 };

  if (ssh_mprz_nanresult1(p, start))
    return FALSE;

  /* Check for very small inputs. */
  if (ssh_mprz_cmp_ui(start, 3) <= 0)
    {
      /* Handle trivial cases. */
      switch (ssh_mprz_get_ui(start))
        {
        case 0:
        case 1:
          ssh_mprz_set_ui(p, 2);
          return TRUE;
        case 2:
          ssh_mprz_set_ui(p, 3);
          return TRUE;
        case 3:
          ssh_mprz_set_ui(p, 5);
          return TRUE;
        default:
          break;
        }
      ssh_mprz_set_ui(p, 0);
      return FALSE;
    }

  ssh_mprz_init_set(&s, start);
  if (!(ssh_mprz_get_ui(&s) & 0x1))
    ssh_mprz_add_ui(&s, &s, 1);

  /* Compute reasonable amount of small primes.
   */

  bits = ssh_mprz_get_size(&s, 2);

  /* This limit can be changed quite a lot higher, although, probably
     32 is the limit? */
  if (bits < 16)
    {
      max = ssh_mprz_get_ui(&s);
      if (max < 1024)
        max = 1024;

      /* We can do the job with one large table. This proves that
         we actually have a prime. */
      if (ssh_sieve_allocate_ui(&sieve, max, 100000) == FALSE)
        {
          ssh_mprz_clear(&s);
          return FALSE;
        }

      /* Trivial case. */
      if (ssh_sieve_last_prime(&sieve) > ssh_mprz_get_ui(&s))
        {
          k = ssh_sieve_next_prime(ssh_mprz_get_ui(&s) - 1, &sieve);
          ssh_mprz_set_ui(p, k);
          ssh_sieve_free(&sieve);
          ssh_mprz_clear(&s);
          return TRUE;
        }

      for (k = ssh_mprz_get_ui(&s); k; k += 2)
        {
          for (i = 2; i; i = ssh_sieve_next_prime(i, &sieve))
            if ((k % i) == 0)
              break;
          if (i == 0)
            break;
        }
      ssh_mprz_set_ui(p, k);
      ssh_sieve_free(&sieve);
      ssh_mprz_clear(&s);
      return TRUE;
    }

  /* Find the max for this bit size. */
  for (i = 0, max = 0; ssh_mprz_table_bits[i]; i++)
    if (bits > ssh_mprz_table_bits[i])
      max = i + 1;
  max = ssh_mprz_table_size[max];
  if (ssh_sieve_allocate(&sieve, max) == FALSE)
    {
      ssh_mprz_clear(&s);
      return FALSE;
    }

  /* Count the primes (actually they have already been counted). */
  alloc_count = count = ssh_sieve_prime_count(&sieve);

  /* Allocate some space for us to work on. */
  moduli = ssh_malloc(alloc_count * sizeof(SshWord));
  if (!moduli)
    {
      ssh_sieve_free(&sieve);
      ssh_mprz_clear(&s);
      return FALSE;
    }

  diffs = ssh_malloc(alloc_count);
  if (!diffs)
    {
      ssh_free(moduli);
      ssh_sieve_free(&sieve);
      ssh_mprz_clear(&s);
      return FALSE;
    }


  /* Set up the tables. E.g. the moduli table and the
     table which contains the prime gaps. */
  prime = 3;
  moduli[0] = ssh_mprz_mod_ui(&s, prime);
  for (i = 1, j = ssh_sieve_next_prime(prime, &sieve);
       i < count && j; i++, j = ssh_sieve_next_prime(j, &sieve))
    {
      moduli[i] = ssh_mprz_mod_ui(&s, j);
      if (j - prime > 0xff)
        break;
      diffs[i - 1]  = j - prime;
      prime = j;
    }

  /* Set the correct size, might be slightly off in the first guess. */
  count = i;

  /* Free the sieve, we'll work with the tables. */
  ssh_sieve_free(&sieve);

  /* Start the main search iteration. */
  rv = FALSE;
  for (difference = 0; ; difference += 2)
    {
      /* We can assume that the largest prime gap is less than this,
         if not then better to try again. */
      if (difference > (unsigned int)((SshWord)1 << 20))
        goto failed;

      for (i = 0, prime = 3; i < count; prime += diffs[i], i++)
        {
          m = moduli[i];
          while (m + difference >= prime)
            m -= prime;
          moduli[i] = m;
          if (m + difference == 0)
            break;
        }

      /* Multiple of a known prime. */
      if (i < count)
        continue;

      /* Compute the number in question. */
      ssh_mprz_add_ui(p, &s, difference);

      /* Now do the good probable prime testing that we have
         implemented above! Note that this routine has been optimized
         and thus we don't need to do anything special here. */
      if (ssh_mprz_is_probable_prime(p, 20))
        break;

      /* Was not a prime! */
    }
  /* Success! */
  rv = TRUE;
failed:

  memset(moduli, 0, alloc_count * sizeof(SshWord));
  memset(diffs, 0, alloc_count);

  ssh_free(moduli);
  ssh_free(diffs);
  ssh_mprz_clear(&s);

  /* Finished. */
  return rv;
}


/* We follow here Henri Cohen's naming. All ideas in this function are
   basically standard, but optimizations are all from Cohen's book. */
int ssh_mprz_kronecker(SshMPIntegerConst a, SshMPIntegerConst b)
{
  int tab2[8] = { 0, 1, 0, -1, 0, -1, 0, 1};
  int v, k;
  SshMPIntegerStruct b0, a0, r;





  /* The initial test. */
  if (ssh_mprz_cmp_ui(b, 0) == 0)
    {
      ssh_mprz_init(&a0);
      ssh_mprz_abs(&a0, a);
      if (ssh_mprz_cmp_ui(&a0, 1) != 0)
        {
          ssh_mprz_clear(&a0);
          return 0;
        }
      ssh_mprz_clear(&a0);
      return 1;
    }

  /* Check if both a and b are even. */
  if ((ssh_mprz_get_ui(b) & 0x1) == 0 &&
      (ssh_mprz_get_ui(a) & 0x1) == 0)
    return 0;

  ssh_mprz_init(&b0);
  ssh_mprz_init(&a0);
  ssh_mprz_init(&r);

  ssh_mprz_set(&b0, b);
  ssh_mprz_set(&a0, a);

  /* Removal of 2's from b. */
  v = 0;
  while ((ssh_mprz_get_ui(&b0) & 0x1) == 0)
    {
      ssh_mprz_div_2exp(&b0, &b0, 1);
      v++;
    }

  /* Alter the k accordingly. */
  if ((v & 0x1) == 0)
    k = 1;
  else
    k = tab2[ssh_mprz_get_ui(&a0) & 0x7];

  /* Handle negative values. */
  if (ssh_mprz_cmp_ui(&b0, 0) < 0)
    {
      ssh_mprz_neg(&b0, &b0);
      if (ssh_mprz_cmp_ui(&a0, 0) < 0)
        k = -k;
    }

  /* Loop until done. */
  while (ssh_mprz_cmp_ui(&a0, 0) != 0)
    {
      /* This loop could be optimized significantly. */
      v = 0;
      while ((ssh_mprz_get_ui(&a0) & 0x1) == 0)
        {
          ssh_mprz_div_2exp(&a0, &a0, 1);
          v++;
        }

      if (v & 0x1)
        {
          /* This is crude, but works. */
          if (k < 0)
            k = -tab2[ssh_mprz_get_ui(&b0) & 0x7];
          else
            k = tab2[ssh_mprz_get_ui(&b0) & 0x7];
        }

      /* This is a funny invention by Cohen. The quadratic reciprocity
         in very simplicity. */
      if (ssh_mprz_get_ui(&b0) & ssh_mprz_get_ui(&a0) & 0x2)
        k = -k;

      ssh_mprz_abs(&r, &a0);
      ssh_mprz_mod(&a0, &b0, &r);
      ssh_mprz_set(&b0, &r);
    }

  if (ssh_mprz_cmp_ui(&b0, 1) > 0)
    k = 0;

  ssh_mprz_clear(&a0);
  ssh_mprz_clear(&b0);
  ssh_mprz_clear(&r);

  return k;
}

int ssh_mprz_jacobi(SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  return ssh_mprz_kronecker(op1, op2);
}

/* We can actually compute Legendre symbol faster with Jacobi's symbol
   and with the known rules. */
int ssh_mprz_legendre(SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  return ssh_mprz_kronecker(op1, op2);
}

/* Square tables. We follow Henri Cohen very closely here. */
const unsigned char ssh_mprz_sq11[11] =
{ 1,1,0,1,1,1,0,0,0,1,0, };
const unsigned char ssh_mprz_sq63[63] =
{ 1,1,0,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,0,0,0,1,0,0,1,0,0,1,0,0,0,
  0,0,0,0,1,1,0,0,0,0,0,1,0,0,1,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0 };
const unsigned char ssh_mprz_sq64[64] =
{ 1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,
  0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0 };
const unsigned char ssh_mprz_sq65[65] =
{ 1,1,0,0,1,0,0,0,0,1,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,1,1,0,0,1,1,0,
  0,0,0,1,1,0,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,0,1,1,0,0,0,0,1,0,0,
  1 };

int ssh_mprz_is_perfect_square(SshMPIntegerConst op)
{
  int r;
  SshMPIntegerStruct t;

  /* Quick check for case op is a square. */
  if (ssh_mprz_sq64[ssh_mprz_get_ui(op) & 63] == 0)
    return 0;

  /* Other Quick tests. */
  r = ssh_mprz_mod_ui(op, 45045);
  if (ssh_mprz_sq63[r % 63] == 0)
    return 0;
  if (ssh_mprz_sq65[r % 65] == 0)
    return 0;
  if (ssh_mprz_sq11[r % 11] == 0)
    return 0;

  /* We have now no other choice but to compute the square root. */
  ssh_mprz_init(&t);
  ssh_mprz_sqrt(&t, op);
  ssh_mprz_square(&t, &t);

  /* Lets expect failure. */
  r = 0;
  if (ssh_mprz_cmp(&t, op) == 0)
    r = 1;

  ssh_mprz_clear(&t);

  return r;
}

void ssh_mprz_sqrtrem(SshMPInteger sqrt_out, SshMPInteger rem,
                    SshMPIntegerConst op)
{
  SshMPIntegerStruct r, t;

  /* Lets have some temporary variables. */
  ssh_mprz_init(&r);
  ssh_mprz_init(&t);

  /* Compute square root and then square it. */
  ssh_mprz_sqrt(&t, op);
  ssh_mprz_square(&r, &t);

  /* Find the remainder. */
  ssh_mprz_sub(rem, op, &r);
  ssh_mprz_set(sqrt_out, &t);

  /* Clear temporary space. */
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&t);
}

/* Simple implementation of Tonelli & Shanks algorithm for computing
   square root mod a prime number. */

/* Algorithm for computing a = b^(1/2) (mod p), the general case.
   Note: we are using mostly integers, and not the values in
   modular representation, which might be nicer. This means, that
   we have to do mods, but also its easier to compare values etc.

   This should be transformed into a form that uses the intmod
   representation. However, it is not needed often and thus
   the current implementation is sufficient.
*/
Boolean ssh_mprz_tonelli_shanks(SshMPInteger sqrt_out, SshMPIntegerConst op,
                                SshMPIntegerConst p)
{
  SshMPIntegerStruct n, q, x, y, b, t;
  unsigned int counter, e, r, m, size;
  Boolean rv = FALSE;
  int i;

  /* We are assuming that the input prime (it should be prime), is
     larger or equal to 2. */
  if (ssh_mprz_cmp_ui(p, 1) <= 0)
    return rv;

  /* Get good size. */
  size = ssh_mprz_get_size(p, 2);

  ssh_mprz_init(&n);
  ssh_mprz_init(&q);
  ssh_mprz_init(&x);
  ssh_mprz_init(&y);
  ssh_mprz_init(&b);
  ssh_mprz_init(&t);

  /* Find q */
  ssh_mprz_sub_ui(&q, p, 1);
  e = 0;
  while ((ssh_mprz_get_ui(&q) & 0x1) == 0)
    {
      e++;
      ssh_mprz_div_2exp(&q, &q, 1);
    }

  /* This loop might take forever, though, it should not. */
  for (counter = 0; counter < 0xffff; counter++)
    {
      ssh_mprz_rand(&n, size);
      if (ssh_mprz_kronecker(&n, p) == -1)
        break;
    }
  if (counter >= 0xffff)
    /* This is not entirely correct, but we are now sufficiently
       sure that there does not exists quadratic residue. */
    goto failed;

  /* Initialize, as Cohen says. */

  /* Compute y = n^q (mod p). */
  ssh_mprz_powm(&y, &n, &q, p);
  r = e;

  /* (q - 1)/2 */
  ssh_mprz_sub_ui(&t, &q, 1);
  ssh_mprz_div_2exp(&t, &t, 1);

  ssh_mprz_powm(&x, op, &t, p);

  ssh_mprz_square(&b, &x);
  ssh_mprz_mul(&b, &b, op);
  ssh_mprz_mod(&b, &b, p);
  ssh_mprz_mul(&x, &x, op);
  ssh_mprz_mod(&x, &x, p);

  /* Now start the main loop. This should be deterministic, and thus
     finish is reasonable time. */
  while (ssh_mprz_cmp_ui(&b, 1) != 0)
    {
      ssh_mprz_set(&t, &b);
      for (m = 1; m < r; m++)
        {
          ssh_mprz_square(&t, &t);
          ssh_mprz_mod(&t, &t, p);
          if (ssh_mprz_cmp_ui(&t, 1) == 0)
            break;
        }

      /* We are finished, not a quadratic residue. */
      if (m >= r)
        goto failed;

      /* Compute y^(2^(r - m - 1)) (mod p). */
      ssh_mprz_set(&t, &y);
      for (i = 0; i < r - m - 1; i++)
        {
          ssh_mprz_square(&t, &t);
          ssh_mprz_mod(&t, &t, p);
        }
      ssh_mprz_square(&y, &t);
      ssh_mprz_mod(&y, &y, p);
      r = m;

      /* x = xt (mod p) */
      ssh_mprz_mul(&x, &x, &t);
      ssh_mprz_mod(&x, &x, p);

      /* b = by (mod p) */
      ssh_mprz_mul(&b, &b, &y);
      ssh_mprz_mod(&b, &b, p);
    }

  /* The result. */
  ssh_mprz_set(sqrt_out, &x);

  rv = TRUE;

failed:
  ssh_mprz_clear(&n);
  ssh_mprz_clear(&q);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&t);

  return rv;
}

/* Algorithm for computing the above one in all cases where p is prime,
   optimized for some specific cases. */
Boolean ssh_mprz_mod_sqrt(SshMPInteger sqrt_out, SshMPIntegerConst op,
                          SshMPIntegerConst p)
{
  SshMPIntegerStruct in;
  Boolean rv = FALSE;

  ssh_mprz_init(&in);
  ssh_mprz_mod(&in, op, p);

  /* First we want to know if the given op is quadratic residue, and
     we can use the Kronecker method. */
  if (ssh_mprz_kronecker(&in, p) != 1)
    goto failed;

  /* Handle case p == 3 (mod 4) */
  if ((ssh_mprz_get_ui(p) & 3) == 3)
    {
      SshMPIntegerStruct t;
      ssh_mprz_init(&t);
      ssh_mprz_add_ui(&t, p, 1);
      ssh_mprz_div_2exp(&t, &t, 2);
      ssh_mprz_powm(sqrt_out, &in, &t, p);
      ssh_mprz_clear(&t);

      rv = TRUE;
      goto failed;
    }

  /* Handle case p == 5 (mod 8).
     Here we don't do it as Henri Cohen suggest because better method
     with just one exponentiation is available. It is described for
     example in P1363. Proof follows easily, along the lines that Cohen
     does.
   */
  if ((ssh_mprz_get_ui(p) & 7) == 5)
    {
      SshMPIntegerStruct t, h, k;
      ssh_mprz_init(&t);
      ssh_mprz_init(&h);
      ssh_mprz_init(&k);

      /* First compute (p - 5)/8. */
      ssh_mprz_sub_ui(&k, p, 5);
      ssh_mprz_div_2exp(&k, &k, 3);

      /* Now t = (2*op)^k (mod p). */
      ssh_mprz_mul_2exp(&t, &in, 1);
      ssh_mprz_mod(&t, &t, p);
      ssh_mprz_powm(&t, &t, &k, p);

      /* Then h = 2*op*t^2 (mod p). */
      ssh_mprz_square(&h, &t);
      ssh_mprz_mod(&h, &h, p);
      ssh_mprz_mul_2exp(&h, &h, 1);
      ssh_mprz_mul(&h, &h, &in);
      ssh_mprz_mod(&h, &h, p);

      /* Now the final computation. */
      ssh_mprz_sub_ui(&h, &h, 1);
      ssh_mprz_mul(&h, &h, &t);
      ssh_mprz_mul(&h, &h, &in);
      ssh_mprz_mod(sqrt_out, &h, p);

      ssh_mprz_clear(&t);
      ssh_mprz_clear(&h);
      ssh_mprz_clear(&k);

      rv = TRUE;
      goto failed;
    }
  /* Use the algorithm of Tonelli-Shanks in remaining cases. */

  if (ssh_mprz_tonelli_shanks(sqrt_out, &in, p) == FALSE)
    goto failed;

  /* Consider using Lucas functions as P1363 does. I have tried the
     method in past and it works nicely. However, this version here is
     more self-contained, and theoretically easier. */

  rv = TRUE;
failed:
  ssh_mprz_clear(&in);
  return rv;
}


/* The method of Cornacchia for solving the diophantine equation
   x^2 + dy^2 = p, where p is a prime.

   Algorithm is from H. Cohen's book.
*/
Boolean ssh_mprz_cornacchia(SshMPInteger ret_x, SshMPInteger ret_y,
                            SshMPIntegerConst d, SshMPIntegerConst p)
{
  SshMPIntegerStruct t1, t2, x0, a, b, r, q;
  int k;
  Boolean rv;

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&r);
  ssh_mprz_init(&q);

  ssh_mprz_set(&t1, d);
  ssh_mprz_mod(&t1, &t1, p);
  ssh_mprz_sub(&t1, p, &t1);
  k = ssh_mprz_kronecker(&t1, p);
  if (k == -1)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return FALSE;
    }
  ssh_mprz_mod_sqrt(&t2, &t1, p);

  /* Make sure that p/2 < t2 < p. */
  ssh_mprz_set(&t1, p);
  ssh_mprz_div_2exp(&t1, &t1, 1);

  if (ssh_mprz_cmp(&t2, &t1) <= 0)
    ssh_mprz_sub(&t2, p, &t2);

  /* Initialize the Euclidean algorithm. */
  ssh_mprz_set(&a, p);
  ssh_mprz_set(&b, &t2);
  ssh_mprz_sqrt(&t1, p);

  /* Run the Euclidean algorithm. */
  while (ssh_mprz_cmp(&b, &t1) > 0)
    {
      ssh_mprz_mod(&r, &a, &b);
      ssh_mprz_set(&a, &b);
      ssh_mprz_set(&b, &r);
    }

  /* Now test for solution. */
  ssh_mprz_square(&t2, &b);
  ssh_mprz_sub(&t1, p, &t2);
  ssh_mprz_divrem(&q, &r, &t1, d);
  if (ssh_mprz_cmp_ui(&r, 0) != 0)
    {
      rv = FALSE;
    }
  else
    {
      if (ssh_mprz_is_perfect_square(&q) == 0)
        {
          rv = FALSE;
        }
      else
        {
          ssh_mprz_set(ret_x, &b);
          ssh_mprz_sqrt(ret_y, &q);
          rv = TRUE;
        }
    }

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
  ssh_mprz_clear(&x0);
  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&q);

  return rv;
}

/* eof */
#endif /* SSHDIST_MATH */
