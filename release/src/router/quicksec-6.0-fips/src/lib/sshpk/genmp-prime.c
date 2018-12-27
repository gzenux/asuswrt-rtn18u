/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains generic functions for generating
   multiple-precision primes.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgenmp.h"
#include "sshcrypt.h"
#include "sshcrypt_i.h"
#include "libmonitor.h"

#define SSH_GENMP_MAX_PRIME        16000
#define SSH_GENMP_MAX_SIEVE_MEMORY 8192

#define SSH_DEBUG_MODULE "SshGenMPPrime"

/* FIPS PUB 186-3 C.3.3 */
Boolean ssh_mprz_crypto_lucas_test(SshMPIntegerConst c)
{
  SshMPIntegerStruct d, k, u, v, u_temp, v_temp, temp;
  int jacobi, i;
  unsigned int r;
  Boolean rv = FALSE;

  /* Step 1, perfect square */
  if (ssh_mprz_is_perfect_square(c) == 1)
    return rv;

  ssh_mprz_init(&d);
  ssh_mprz_init(&k);
  ssh_mprz_init(&u);
  ssh_mprz_init(&v);
  ssh_mprz_init(&u_temp);
  ssh_mprz_init(&v_temp);
  ssh_mprz_init(&temp);

  /* Step 2, iterate through series {5, -7, 9, -11, 13, -15, ...} until
     suitable d is found */
  ssh_mprz_set_si(&d, 5);

  jacobi = ssh_mprz_jacobi(&d, c);

  if (jacobi == 0)
    goto exit;

  while (jacobi != -1)
    {
      if (ssh_mprz_signum(&d) == 1)
        {
          ssh_mprz_add_ui(&d, &d, 2);
          ssh_mprz_neg(&d, &d);

          /* d is negative number, use step 1. from FIPS PUB 186-3 C.5 to
             make it positive, temp = d mod c */
          ssh_mprz_add(&temp, &d, c);
        }
      else
        {
          ssh_mprz_neg(&d, &d);
          ssh_mprz_add_ui(&d, &d, 2);

          ssh_mprz_set(&temp, &d);
        }

      /* ssh_mprz_jacobi() accepts only positive integers, which we can
         guarantee at this point */
      jacobi = ssh_mprz_jacobi(&temp, c);

      if (jacobi == 0)
        goto exit;
    }

  /* Step 3. */
  ssh_mprz_add_ui(&k, c, 1);

  r = ssh_mprz_get_size(&k, 2) - 1;

  ssh_mprz_set_ui(&u, 1);
  ssh_mprz_set_ui(&v, 1);

  /* Step 6.
     If an odd integer is to be divided by 2, add integer c to make
     it even as specified by the document. */
  for (i = r - 1; i >= 0; i--)
    {
      ssh_mprz_mul(&u_temp, &u, &v);
      ssh_mprz_mod(&u_temp, &u_temp, c);

      ssh_mprz_square(&v_temp, &v);
      ssh_mprz_square(&temp, &u);
      ssh_mprz_mul(&temp, &d, &temp);
      ssh_mprz_add(&v_temp, &temp, &v_temp);

      if (ssh_mprz_get_bit(&v_temp, 0) == 1)
        ssh_mprz_add(&v_temp, &v_temp, c);

      ssh_mprz_div_2exp(&v_temp, &v_temp, 1);
      ssh_mprz_mod(&v_temp, &v_temp, c);

      if (ssh_mprz_get_bit(&k, i) == 1)
        {
          ssh_mprz_add(&temp, &u_temp, &v_temp);

          if (ssh_mprz_get_bit(&temp, 0) == 1)
            ssh_mprz_add(&temp, &temp, c);

          ssh_mprz_div_2exp(&temp, &temp, 1);
          ssh_mprz_mod(&u, &temp, c);

          ssh_mprz_mul(&temp, &d, &u_temp);
          ssh_mprz_add(&temp, &v_temp, &temp);

          if (ssh_mprz_get_bit(&temp, 0) == 1)
            ssh_mprz_add(&temp, &temp, c);

          ssh_mprz_div_2exp(&temp, &temp, 1);
          ssh_mprz_mod(&v, &temp, c);
        }
      else
        {
          ssh_mprz_set(&u, &u_temp);
          ssh_mprz_set(&v, &v_temp);
        }
    }

  /* Step 7. */
  if (ssh_mprz_signum(&u) == 0)
    rv = TRUE;

 exit:
  ssh_mprz_clear(&d);
  ssh_mprz_clear(&k);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&v);
  ssh_mprz_clear(&u_temp);
  ssh_mprz_clear(&v_temp);
  ssh_mprz_clear(&temp);

  return rv;
}

/* Similar to Miller Rabin in the math library. This version however uses
   the strong cryptographic random number generator when generating random
   integers for the Miller Rabin test. */
static Boolean ssh_mprz_crypto_miller_rabin(SshMPIntegerConst op,
                                            unsigned int limit)
{
  SshMPMontIntIdealStruct ideal;
  SshMPMontIntModStruct modint;
  SshMPIntegerStruct q, a, b, op_1;
  Boolean rv = FALSE;
  SshUInt32 t, k, e;

  if (ssh_mprz_isnan(op))
    return FALSE;

  /* Assume primes are larger than 1. */
  if (ssh_mprz_cmp_ui(op, 1) <= 0)
    return FALSE;

  /* 'op' should be odd, so we can use Montgomery ideals. */
  if (!ssh_mpmzm_init_ideal(&ideal, op))
    return FALSE;

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

  rv = TRUE;
  /* To the witness tests. */
  for (; limit; limit--)
    {
      /* We want to be fast, thus we use 0 < a < 2^(SSH_WORD_BITS).
         Some purists would insist that 'k' should be selected in more
         uniform way, however, this is accordingly to Cohen a reasonable
         approach. */
      do
        {
          k = (((SshUInt32)ssh_random_object_get_byte()) << 24) |
              (((SshUInt32)ssh_random_object_get_byte()) << 16) |
              (((SshUInt32)ssh_random_object_get_byte()) << 8) |
              ((SshUInt32)ssh_random_object_get_byte());

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
              rv = FALSE;
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
   or not. mr_tests is the amount of Miller-Rabin tests for the potential
   prime and if lucas_test is TRUE Lucas test is applied after M-R tests.
   Returns TRUE if 'op' is a probable prime, FALSE otherwise. */
Boolean ssh_mprz_is_strong_probable_prime(SshMPIntegerConst op,
                                          unsigned int mr_tests,
                                          Boolean lucas_test)
{
  SshMPIntegerStruct temp;

  /* The small prime test, this one should be performed for speed. */
  static const SshWord
    very_small_primes[10] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
  static const SshWord ideal = 3234846615UL;
  SshWord i, res;

  /* Assuming we mostly are looking for primes */
  if (ssh_mprz_isnan(op))
    return FALSE;

  /* Check for trivial cases. */
  if (ssh_mprz_cmp_ui(op, 2) < 0)
    return FALSE;

  if ((ssh_mprz_get_ui(op) & 0x1) == 0)
    {
      /* Perhaps the input is equal to 2. */
      if (ssh_mprz_cmp_ui(op, 2) == 0)
        return TRUE;
      return FALSE;
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
            return TRUE;
          /* Was not and hence it must be composite. */
          return FALSE;
        }
    }

  /* Test first with Fermat's test with witness 2. */
  ssh_mprz_init(&temp);
  ssh_mprz_powm_ui_g(&temp, 2, op, op);
  if (ssh_mprz_cmp_ui(&temp, 2) != 0)
    {
      ssh_mprz_clear(&temp);
      return FALSE;
    }
  ssh_mprz_clear(&temp);

  /* Finally try Miller-Rabin test. */
  if (!ssh_mprz_crypto_miller_rabin(op, mr_tests))
    return FALSE;

  if (lucas_test &&
      !ssh_mprz_crypto_lucas_test(op))
    return FALSE;

  return TRUE;
}


/* Generate traditional prime. */

/* In failure, the ret is set to NaN. */
void ssh_mprz_random_prime(SshMPInteger ret, unsigned int bits)
{
  SshMPIntegerStruct start, aux;
  SshSieveStruct sieve;
  unsigned int num_primes, p, i;
  SshWord *moduli = NULL, *prime_table = NULL;
  SshWord difference;

  /* Progress monitoring. */
  unsigned int progress_counter = 0;

  /* Initialize the prime search. */
  ssh_mprz_init(&start);
  ssh_mprz_init(&aux);

  if (ssh_mprz_isnan(&start) || ssh_mprz_isnan(&aux))
    {
    failure_nosieve:
      ssh_mprz_clear(&start);
      ssh_mprz_clear(&aux);
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  if (bits < 16)
    {
      SshWord temp;

      /* Check from the prime sieve. */
      if (!ssh_sieve_allocate_ui(&sieve, (1 << bits), (1 << bits)))
        goto failure_nosieve;

      /* Do not choose 2. */
      num_primes = ssh_sieve_prime_count(&sieve) - 1;

      ssh_mprz_random_integer(&aux, bits);
      if (ssh_mprz_isnan(&aux))
        goto failure;

      temp = ssh_mprz_get_ui(&aux) % num_primes;

      for (p = 2; p; p = ssh_sieve_next_prime(p, &sieve), temp--)
        if (temp == 0)
          {
            ssh_mprz_set_ui(ret, p);
            break;
          }
      if (temp != 0)
        ssh_fatal("ssh_mprz_random_prime: could not find small prime.");

      ssh_mprz_clear(&start);
      ssh_mprz_clear(&aux);
      return;
    }

  /* Generate the prime sieve, this takes very little time. */
  if (!ssh_sieve_allocate_ui(&sieve, SSH_GENMP_MAX_PRIME,
                             SSH_GENMP_MAX_SIEVE_MEMORY))
    goto failure_nosieve;

  /* Don't count 2. */
  num_primes = ssh_sieve_prime_count(&sieve)-1;

  /* Generate a simply indexed prime table. */
  if ((prime_table = ssh_malloc(num_primes * sizeof(SshWord))) == NULL)
    goto failure;
  /* Allocate moduli table. */

  if ((moduli = ssh_malloc(num_primes * sizeof(SshWord))) == NULL)
    goto failure;

  for (p = 2, i = 0; p; p = ssh_sieve_next_prime(p, &sieve), i++)
    prime_table[i] = p;

 retry:

  /* Pick a random integer of the appropriate size. */
  ssh_mprz_random_integer(&start, bits);
  if (ssh_mprz_isnan(&start))
    goto failure;

  /* Set the highest bit. */
  ssh_mprz_set_bit(&start, bits - 1);
  /* Set the lowest bit to make it odd. */
  ssh_mprz_set_bit(&start, 0);

  /* Initialize moduli of the small primes with respect to the given
     random number. */
  for (i = 0; i < num_primes; i++)
    moduli[i] = ssh_mprz_mod_ui(&start, prime_table[i]);

  /* Look for numbers that are not evenly divisible by any of the small
     primes. */
  for (difference = 0; ; difference += 2)
    {
      unsigned int i;

      if (difference > 0x70000000)
        {
          /* Might never happen... */
          goto retry;
        }

      /* Check if it is a multiple of any small prime.  Note that this
         updates the moduli into negative values as difference grows. */
      for (i = 1; i < num_primes; i++)
        {
          while (moduli[i] + difference >= prime_table[i])
            moduli[i] -= prime_table[i];
          if (moduli[i] + difference == 0)
            break;
        }
      if (i < num_primes)
        continue; /* Multiple of a known prime. */

      /* Progress information. */
      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);

      /* Compute the number in question. */
      ssh_mprz_add_ui(ret, &start, difference);

      if (ssh_mprz_isnan(ret))
        goto failure;

      /* Perform Miller-Rabin strong pseudo primality tests */
      if (ssh_mprz_is_strong_probable_prime(ret, 50, FALSE))
        break;
    }

  /* Found a (probable) prime.  It is in ret. */

  /* Sanity check: does it still have the high bit set (we might have
     wrapped around)? */
  ssh_mprz_div_2exp(&aux, ret, bits - 1);
  if (ssh_mprz_isnan(&aux))
    goto failure;
  if (ssh_mprz_get_ui(&aux) != 1)
    {
      goto retry;
    }

  /* Free the small prime moduli; they are no longer needed. Also free
     start, aux and sieve. */

  ssh_free(moduli);
  ssh_free(prime_table);

  ssh_mprz_clear(&start);
  ssh_mprz_clear(&aux);
  ssh_sieve_free(&sieve);

  /* Return value already set in ret. */
  return;

 failure:
  ssh_sieve_free(&sieve);

  ssh_free(moduli);
  ssh_free(prime_table);

  ssh_mprz_clear(&start);
  ssh_mprz_clear(&aux);
  ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
}

/* Generate a random prime within the [min, max] interval. We observe
   that the process can just choose a random number modulo (max - min)
   and then start from there. If it goes beyond max-1 then it
   cycles. */

void ssh_mprz_random_prime_within_interval(SshMPInteger ret,
                                         SshMPInteger min, SshMPInteger max)
{
  SshMPIntegerStruct pprime, temp, aux;
  SshSieveStruct sieve;
  SshWord *moduli = NULL, *prime_table = NULL;
  SshWord difference, max_difference, num_primes, p;
  unsigned int i, bits;

  /* Progress monitoring. */
  unsigned int progress_counter = 0;

  /* Verify the interval. */
  if (ssh_mprz_cmp(min, max) >= 0)
    ssh_fatal("ssh_mprz_random_prime_within_interval: interval invalid.");

  /* Initialize temps. */
  ssh_mprz_init(&pprime);
  ssh_mprz_init(&temp);
  ssh_mprz_init(&aux);

  /* Allocate a sieve. */
  if (!ssh_sieve_allocate_ui(&sieve, SSH_GENMP_MAX_PRIME,
                             SSH_GENMP_MAX_SIEVE_MEMORY))
    {
      ssh_mprz_clear(&pprime);
      ssh_mprz_clear(&aux);
      ssh_mprz_clear(&temp);
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  /* Don't count 2. */
  num_primes = ssh_sieve_prime_count(&sieve) - 1;

  /* Make a table of the primes. */
  if ((prime_table = ssh_malloc(num_primes * sizeof(SshWord))) == NULL)
    goto failure;

  /* Allocate moduli table. */
  if ((moduli = ssh_malloc(num_primes * sizeof(SshWord))) == NULL)
    {
      goto failure;
    }

  for (p = 2, i = 0; p; p = ssh_sieve_next_prime(p, &sieve), i++)
    prime_table[i] = p;

retry:

  /* Generate the random number within the interval. */
  ssh_mprz_sub(&temp, max, min);
  bits = ssh_mprz_get_size(&temp, 2);

  /* Generate suitable random number (some additional bits for perhaps
     more uniform distribution, these really shouldn't matter). */
  ssh_mprz_random_integer(&aux, bits + 10);
  /* Compute. */
  ssh_mprz_mod(&aux, &aux, &temp);
  ssh_mprz_add(&pprime, &aux, min);

  /* Fix it as odd. */
  ssh_mprz_set_bit(&pprime, 0);

  /* Compute the max difference. */
  ssh_mprz_sub(&aux, max, &pprime);
  if (ssh_mprz_cmp_ui(&aux, 0) < 0)
    goto retry;

  /* Get it. */
  max_difference = ssh_mprz_get_ui(&aux);

  if (ssh_mprz_isnan(&pprime) || ssh_mprz_isnan(&aux))
    goto failure;

  /* Now we need to set up the moduli table. */
  for (i = 0; i < num_primes; i++)
    moduli[i] = ssh_mprz_mod_ui(&pprime, prime_table[i]);

  /* Look for numbers that are not evenly divisible by any of the small
     primes. */
  for (difference = 0; ; difference += 2)
    {
      unsigned int i;

      if (difference > max_difference)
        /* Although we could just wrap around, we currently choose to
           just start from the scratch again. */
        goto retry;

      /* Check if it is a multiple of any small prime.  Note that this
         updates the moduli into negative values as difference grows. */
      for (i = 1; i < num_primes; i++)
        {
          while (moduli[i] + difference >= prime_table[i])
            moduli[i] -= prime_table[i];
          if (moduli[i] + difference == 0)
            break;
        }
      if (i < num_primes)
        continue; /* Multiple of a known prime. */

      /* Progress information. */
      ssh_crypto_progress_monitor(SSH_CRYPTO_PRIME_SEARCH,
                                  ++progress_counter);

      /* Compute the number in question. */
      ssh_mprz_add_ui(ret, &pprime, difference);

      /* Perform Miller-Rabin strong pseudo primality tests */
      if (ssh_mprz_isnan(ret) ||
          ssh_mprz_is_strong_probable_prime(ret, 50, FALSE))
        break;
    }

  /* Found a (probable) prime.  It is in ret. */

  /* Sanity check, are we in the interval. */
  if (!ssh_mprz_isnan(ret) &&
      (ssh_mprz_cmp(ret, min) <= 0 || ssh_mprz_cmp(ret, max) >= 0))
    goto retry;

  /* Free the small prime moduli; they are no longer needed. */
  ssh_sieve_free(&sieve);

  ssh_free(moduli);
  ssh_free(prime_table);

  ssh_mprz_clear(&pprime);
  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&temp);
  /* Return value already set in ret. */
  return;

 failure:
  ssh_sieve_free(&sieve);

  ssh_free(moduli);
  ssh_free(prime_table);

  ssh_mprz_clear(&pprime);
  ssh_mprz_clear(&aux);
  ssh_mprz_clear(&temp);
  ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
}


/* From p and q, compute a generator h (of the multiplicative group mod p)
   of order p-1, and g of order p-1/q with g = h ^ {(p-1)/q} mod p. Returns
   TRUE if g and h can be generated in this manner and FALSE otherwise
   (if p and q are both prime with q dividing p-1, then it is guaranteed
   to return TRUE).  */
static Boolean ssh_mp_random_generator_internal(SshMPInteger g,
                                                SshMPInteger h,
                                                SshMPIntegerConst q,
                                                SshMPIntegerConst p)
{
  SshMPIntegerStruct r, s, tmp;
  Boolean rv = FALSE;
  unsigned int bits;

  ssh_mprz_init(&r);
  ssh_mprz_init(&s);
  ssh_mprz_init(&tmp);

  /* Set r = p-1 and s = (p-1)/q */
  ssh_mprz_sub_ui(&r, p, 1);
  ssh_mprz_div(&s, &r, q);

  /* Verify that q | (p - 1 ) */
  ssh_mprz_mod(&tmp, &r, q);

  if (ssh_mprz_cmp_ui(&tmp, 0) != 0)
    goto fail;

  bits = ssh_mprz_get_size(p, 2);

  /* Search for h such that h^(p-1) mod p != 1 mod p, and then compute
     g = h^(p-1/q) mod p. To begin, we check if h = 2 is a generator. */
  ssh_mprz_set_ui(h, 2);
  while (1)
    {
      ssh_mprz_mod(h, h, p);
      ssh_mprz_powm(g, h, &s, p);

      if (ssh_mprz_cmp_ui(g, 1) != 0)
        break;

      /* If 2 is not a generator, look for a random generator. */
      ssh_mprz_random_integer(h, bits);
    }

  /* Verify that g has order q. */
  ssh_mprz_powm(&tmp, g, q, p);

  if (ssh_mprz_cmp_ui(&tmp, 1) != 0)
    goto fail;

  /* Have now successfully generated h and g. */
  rv = TRUE;

 fail:
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&s);
  ssh_mprz_clear(&tmp);

  return rv;
}

/* Find a random generator of order 'order' modulo 'modulo'. */
Boolean ssh_mprz_random_generator(SshMPInteger g,
                                  SshMPInteger order,
                                  SshMPInteger modulo)
{
  SshMPIntegerStruct aux;
  Boolean rv;

  ssh_mprz_init(&aux);
  rv = ssh_mp_random_generator_internal(g, &aux, order, modulo);
  ssh_mprz_clear(&aux);
  return rv;
}

/* Hashes one buffer with selected hash type and returns the
   digest. This can return error codes from either ssh_hash_allocate
   or ssh_hash_final. (This function is essentially the same as the
   one in lib/sshcryptoaux/hashbuf.c. Copied here to avoid addition to
   public API (FIPS).) */
static SshCryptoStatus
genmp_hash_of_buffer(const char *type,
                     const void *buf, size_t len,
                     unsigned char *digest)
{
  SshHash hash;
  SshCryptoStatus status;

  if ((status = ssh_hash_allocate(type, &hash)) != SSH_CRYPTO_OK)
    return status;

  ssh_hash_update(hash, buf, len);
  status = ssh_hash_final(hash, digest);
  ssh_hash_free(hash);

  return status;
}

#define MP_HASH_INPUT_LEN_MAX 64

static SshCryptoStatus
genmp_hash_of_mp(const char *type,
                 SshMPInteger ret,
                 SshMPIntegerConst mp)
{
  SshCryptoStatus status;
  unsigned char mp_buffer[MP_HASH_INPUT_LEN_MAX];
  unsigned char digest_buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  size_t mp_buffer_len, offset;

  memset(mp_buffer, 0x00, MP_HASH_INPUT_LEN_MAX);
  memset(digest_buffer, 0x00, SSH_MAX_HASH_DIGEST_LENGTH);

  offset = ssh_mprz_get_buf(mp_buffer, MP_HASH_INPUT_LEN_MAX, mp);

  SSH_ASSERT(offset != 0);

  mp_buffer_len = (size_t) (ssh_mprz_get_size(mp, 16) + 1) / 2;

  status = genmp_hash_of_buffer(type,
                                mp_buffer + offset - 1,
                                mp_buffer_len,
                                digest_buffer);

  if (status != SSH_CRYPTO_OK)
    return status;

  ssh_mprz_set_buf(ret, digest_buffer, ssh_hash_digest_length(type));

  return status;
}

#ifdef SSHDIST_CRYPT_SHA256
#define FIPS_DEFAULT_PRIME_HASH "sha256"
#else /* SSHDIST_CRYPT_SHA256 */
#define FIPS_DEFAULT_PRIME_HASH "sha1"
#endif /* SSHDIST_CRYPT_SHA256 */

#define FIPS_DEFAULT_SEED_LEN 64

/* FIPS PUB 186-3 A.1.1.2 */
SshCryptoStatus
fips186_ffc_domain_parameter_create_internal(SshMPInteger p,
                                             SshMPInteger q,
                                             unsigned int p_bits,
                                             unsigned int q_bits,
                                             unsigned char *seed_buffer_ext,
                                             size_t seed_buffer_ext_len,
                                             const char *hash_alg,
                                             SshUInt32 *counter_final)
{
  SshCryptoStatus status = SSH_CRYPTO_OK;
  SshMPIntegerStruct q_min, u, seed_mp, v, w, temp, x, c;
  SshUInt32 n, b, p_mr_tests, q_mr_tests, offset, i, j, outlen;
  SshUInt32 counter = 0;
  unsigned char digest_buffer[SSH_MAX_HASH_DIGEST_LENGTH];
  unsigned char seed_buffer_internal[FIPS_DEFAULT_SEED_LEN];
  unsigned char *seed_buffer = NULL;
  Boolean deterministic_mode;
  size_t seed_len;

  if (seed_buffer_ext != NULL)
    {
      deterministic_mode = TRUE;
      seed_len = seed_buffer_ext_len;
      seed_buffer = seed_buffer_ext;
    }
  else
    {
      deterministic_mode = FALSE;
      seed_len = FIPS_DEFAULT_SEED_LEN;
      seed_buffer = seed_buffer_internal;
    }

  if (hash_alg == NULL)
    hash_alg = FIPS_DEFAULT_PRIME_HASH;

  /* Accepted pairs are (1024,160), (2048,224), (2048,256) and (3072,256) */
  if ((p_bits == 1024) && (q_bits == 160))
    {
      p_mr_tests = 3;
      q_mr_tests = 19;
    }
  else if ((p_bits == 2048) && (q_bits == 224))
    {
      p_mr_tests = 3;
      q_mr_tests = 24;
    }
  else if ((p_bits == 2048) && (q_bits == 256))
    {
      p_mr_tests = 3;
      q_mr_tests = 27;
    }
  else if ((p_bits == 3072) && (q_bits == 256))
    {
      p_mr_tests = 2;
      q_mr_tests = 27;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Invalid prime length pair for p and q (%u,%u)",
                 p_bits, q_bits));
      return SSH_CRYPTO_KEY_INVALID;
    }

  /* q length must not be larger than the seed */
  if (seed_len * 8 < q_bits)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Too large prime q length (%u), maximun size is %u",
                 q_bits, seed_len * 8));
      return SSH_CRYPTO_KEY_INVALID;
    }

  outlen = (SshUInt32) ssh_hash_digest_length(hash_alg);

  if (outlen * 8 < q_bits)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Prime q length (%u) is larger than hash function (%s) "
                 "output length %u",
                 q_bits, hash_alg, outlen * 8));
      return SSH_CRYPTO_KEY_INVALID;
    }

  ssh_mprz_init(&q_min);
  ssh_mprz_init(&u);
  ssh_mprz_init(&seed_mp);
  ssh_mprz_init(&v);
  ssh_mprz_init(&w);
  ssh_mprz_init(&temp);
  ssh_mprz_init(&x);
  ssh_mprz_init(&c);

  ssh_mprz_set_ui(q, 0);

  /* Steps 3. and 4. */
  n = ((p_bits + (outlen * 8) - 1) / (outlen * 8)) - 1;
  b = p_bits - 1 - (n * outlen * 8);

  /* q_min is 2 ^ (q_bits - 1) */
  ssh_mprz_set_ui(&q_min, 1);
  ssh_mprz_mul_2exp(&q_min, &q_min, q_bits - 1);

  /* Step 5, restarts begin here */
 retry:
  if (deterministic_mode == FALSE)
    {
      for (i = 0; i < seed_len; i++)
        seed_buffer[i] = ssh_random_object_get_byte();
    }

  /* U = HASH(domain_parameter_seed) */
  status = genmp_hash_of_buffer(hash_alg,
                                seed_buffer, seed_len,
                                digest_buffer);

  if (status != SSH_CRYPTO_OK)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Failed hash operation"));
      goto exit;
    }

  ssh_mprz_set_buf(&u, digest_buffer, outlen);

  /* U = U mod 2 ^ (N - 1) */
  ssh_mprz_mod(&u, &u, &q_min);

  /* U = 2 ^ (N - 1) + U + 1 - (U mod 2) */
  ssh_mprz_add(q, &u, &q_min);
  ssh_mprz_add_ui(q, q, !ssh_mprz_get_bit(q, 0));

  SSH_ASSERT(q_bits == ssh_mprz_get_size(q, 2));

  /* If running deterministic mode we fail, if not we just get
     new seed and try again until suitable prime is found. */
  if (!ssh_mprz_is_strong_probable_prime(q, q_mr_tests, TRUE))
    {
      if (deterministic_mode)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Failed to create prime q from given seed value"));
          status = SSH_CRYPTO_KEY_INVALID;
          goto exit;
        }
      else
        goto retry;
    }

  /* Step 10, q is done, move to p */
  offset = 1;

  /* For counter 0 to (4L - 1) do */
  for (counter = 0; counter < (4 * p_bits) - 1; counter++)
    {
      ssh_mprz_set_ui(&w, 0);

      /* For j = 0 to n do */
      for (j = 0; j <= n; j++)
        {
          /* HASH((domain_parameter_seed + offset + j) mod 2 ^ seedlen) */
          ssh_mprz_set_buf(&seed_mp, seed_buffer, seed_len);
          ssh_mprz_add_ui(&seed_mp, &seed_mp, offset);
          ssh_mprz_add_ui(&seed_mp, &seed_mp, j);
          ssh_mprz_mod_2exp(&seed_mp, &seed_mp, seed_len * 8);
          status = genmp_hash_of_mp(hash_alg, &v, &seed_mp);

          if (status != SSH_CRYPTO_OK)
            {
              SSH_DEBUG(SSH_D_ERROR, ("Failed hash operation"));
              goto exit;
            }

          /* Vn mod 2 ^ b */
          if (j == n)
            ssh_mprz_mod_2exp(&v, &v, b);

          /* W = SUM(Vj * 2 ^ (j * outlen)) */
          ssh_mprz_mul_2exp(&v, &v, j * outlen * 8);
          ssh_mprz_add(&w, &w, &v);
        }

      /* 0 <= w < 2 ^ (L - 1) */
      SSH_ASSERT(ssh_mprz_get_size(&w, 2) < p_bits);

      /* X = W + 2^(L - 1) */
      ssh_mprz_set_ui(&temp, 1);
      ssh_mprz_mul_2exp(&temp, &temp, p_bits - 1);
      ssh_mprz_add(&x, &w, &temp);

      /* c = X mod (2q) */
      ssh_mprz_mul_ui(&temp, q, 2);
      ssh_mprz_mod(&c, &x, &temp);

      /* p = X - (c - 1) */
      ssh_mprz_sub_ui(&c, &c, 1);
      ssh_mprz_sub(p, &x, &c);

      /* Check if ready */
      if (p_bits == ssh_mprz_get_size(p, 2) &&
          ssh_mprz_is_strong_probable_prime(p, p_mr_tests, TRUE))
        goto exit;

      offset = offset + n + 1;
    }

  SSH_DEBUG(SSH_D_LOWOK,
            ("Failed to create %u-bit prime p for %u-bit co-prime after "
             "%u attempts, restarting search.", p_bits, q_bits, counter));

  if (deterministic_mode == FALSE)
    goto retry;

 exit:
  ssh_mprz_clear(&q_min);
  ssh_mprz_clear(&u);
  ssh_mprz_clear(&seed_mp);
  ssh_mprz_clear(&v);
  ssh_mprz_clear(&w);
  ssh_mprz_clear(&temp);
  ssh_mprz_clear(&x);
  ssh_mprz_clear(&c);

  if (status != SSH_CRYPTO_OK)
    {
      ssh_mprz_set_ui(p, 0);
      ssh_mprz_set_ui(q, 0);
    }

  if (counter_final != NULL)
    *counter_final = counter;

  return status;
}

SshCryptoStatus
ssh_mp_fips186_ffc_domain_parameter_create(SshMPInteger p,
                                           SshMPInteger q,
                                           unsigned int p_bits,
                                           unsigned int q_bits)
{
  return fips186_ffc_domain_parameter_create_internal(p, q,
                                                      p_bits, q_bits,
                                                      NULL, 0,
                                                      NULL,
                                                      NULL);
}

/* genmp-prime.c */
