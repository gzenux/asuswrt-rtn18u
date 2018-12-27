/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Sieve for small prime numbers.
*/

#include "sshincludes.h"
#include "sshmp-types.h"
#include "sshmp.h"
#include "sshsieve.h"

#define SSH_DEBUG_MODULE "SshMPSieve"

#ifdef SSHDIST_MATH

/* Compute square root with Newton's iteration for small integers. We
   could of course use sqrt(), but then again. We don't usually use
   any floating point instructions, thus this seems usable. */

SshWord ssh_sieve_sqrt_ui(SshWord x)
{
  SshWord u1, u2;

  switch (x)
    {
    case 0:
      break;
      /* For sqrt(x) = 1 cases */
    case 1:
    case 2:
    case 3:
      return 1;
      break;
    default:
      /* Search for the initial root estimation */
      u2 = x;
      u1 = 1;
      while (u2)
        {
          u2 >>= 2;
          u1 <<= 1;
        }

      /* Seek the result such that sqrt(x)^2 <= x < (sqrt(x) + 1)^2 */
      while (1)
        {
          u1 = (u1 + x/u1) >> 1;
          u2 = u1 * u1;
          if (u2 <= x)
            {
              /* (u1 + 1)^2 = u1^2 + 2*u1 + 1 */
              if (u2 + (u1 << 1) + 1 > x)
                break;
            }
        }
      return u1;
      break;
    }
  /* Invalid. */
  return 0;
}

/* Function to compute a table where i'th bit is representing number
   3 + i*2 and the value of the i'th bit: 1 is composite, 0 is prime.
   */

void ssh_sieve_generate_primes(SshWord *table, unsigned int len)
{
  unsigned int max = len * SSH_WORD_BITS;
  SshWord stop = ssh_sieve_sqrt_ui(max) + 1, k;
  unsigned int i, j;

  /* Clear table */
  memset(table, 0, len * (SSH_WORD_BITS/8));

  /*
    For taking as little space a possible I remove 1, 2 and 2's multiples.
    Could be done even more efficiently, but it might not be useful enough.
    */

  for (i = 0; i < stop ; i++)
    {
      if (!(table[i / SSH_WORD_BITS] &
            ((SshWord)1 << (i & (SSH_WORD_BITS - 1)))))
        {
          k = 3 + i*2;
          for (j = i + k; j < max; j += k)
            {
               table[j / SSH_WORD_BITS] |=
                 ((SshWord)1 << (j & (SSH_WORD_BITS - 1)));
            }
        }
    }
}

unsigned const char ssh_sieve_bit_counts[256] =
{ 0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,1,
  2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,1,2,
  2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,2,3,3,
  4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,1,2,2,3,
  2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,2,3,3,4,3,
  4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,2,3,3,4,3,4,
  4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,3,4,4,5,4,5,5,
  6,4,5,5,6,5,6,6,7,4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8 };


/* count the primes in the table, containing len SshWord's */
SshWord ssh_sieve_prime_counter(SshWord *table, unsigned int len)
{
  unsigned int i, bits;
  SshWord w, primes;
  for (i = 0, primes = 2; i < len; i++)
    {
      w = table[i];
      for (bits = 0; w; w >>= 8)
        bits += ssh_sieve_bit_counts[w & 0xff];
      primes += (SSH_WORD_BITS - bits);
    }
  return primes;
}


SshWord ssh_sieve_get_next_prime(unsigned int x, SshWord *table,
                                 unsigned int len)
{
  SshWord p = ((x - 3) / 2) + 1;

  switch (x)
    {
      /* Trivial cases. */
    case 0:
    case 1:
      return 2;
    case 2:
      return 3;
      /* Cases above 2 are handled with the table. */
    default:
      while (1)
        {
          if ((p / SSH_WORD_BITS) >= len)
            break;

          if (!(table[p / SSH_WORD_BITS] &
                ((SshWord)1 << (p & (SSH_WORD_BITS - 1)))))
            return p*2 + 3;
          p++;
        }
      break;
    }
  return 0;
}

/* retruns the maximum prime in the sieve */
SshWord ssh_sieve_get_max_prime(SshWord *table, unsigned int len)
{
  SshWord p;

/* Set the sieve to relatively good size. */
  for (p = len * SSH_WORD_BITS - 1; p; p--)
    if (!(table[p / SSH_WORD_BITS] &
          ((SshWord)1 << (p & (SSH_WORD_BITS - 1)))))
      return p * 2 + 3;
  return 0;
}


Boolean
ssh_sieve_allocate_ui(SshSieve sieve, unsigned int x,
                      unsigned int memory_limit)
{

  SSH_ASSERT(sieve != NULL);

  if (x > 3)
    sieve->len = (x - 3) / (SSH_WORD_BITS * 2);
  else
    sieve->len = 2 * SSH_WORD_BITS + 3;

  /* We cannot give more memory. */
  if (sieve->len * (SSH_WORD_BITS / 8) > memory_limit)
    sieve->len = memory_limit / (SSH_WORD_BITS / 8);

  if (SSH_MP_SIEVE_STATIC_BYTE_SIZE >= sieve->len * (SSH_WORD_BITS / 8))
    {
      sieve->dynamic_table = FALSE;
      sieve->table = sieve->table_array;
    }
  else
    {
      sieve->dynamic_table = TRUE;

      if ((sieve->table = ssh_malloc(sieve->len * (SSH_WORD_BITS/8))) == NULL)
        return FALSE;
    }

  /* generate the primes */
  ssh_sieve_generate_primes(sieve->table, sieve->len);
  /* count the primes */
  sieve->count = ssh_sieve_prime_counter(sieve->table, sieve->len);

  return TRUE;
}

Boolean
ssh_sieve_allocate(SshSieve sieve,
                   unsigned int memory_limit)
{

  SSH_ASSERT(sieve != NULL);

  sieve->len = memory_limit / (SSH_WORD_BITS / 8);


  if (SSH_MP_SIEVE_STATIC_BYTE_SIZE >= sieve->len * (SSH_WORD_BITS / 8))
    {
      sieve->dynamic_table = FALSE;
      sieve->table = sieve->table_array;
    }
  else
    {
      sieve->dynamic_table = TRUE;

      if ((sieve->table = ssh_malloc(sieve->len * (SSH_WORD_BITS/8))) == NULL)
        return FALSE;
    }

  ssh_sieve_generate_primes(sieve->table, sieve->len);
  /* count the primes */
  sieve->count = ssh_sieve_prime_counter(sieve->table, sieve->len);
  return TRUE;
}

SshWord ssh_sieve_next_prime(unsigned long x, SshSieveConst sieve)
{
  /* return the next prime in the sieve */
  return ssh_sieve_get_next_prime(x, sieve->table, sieve->len);
}

SshWord ssh_sieve_last_prime(SshSieveConst sieve)
{
  /* return the maximum prime in the sieve */
  return ssh_sieve_get_max_prime(sieve->table, sieve->len);
}

SshWord ssh_sieve_prime_count(SshSieveConst sieve)
{
  return sieve->count;
}

void ssh_sieve_free(SshSieve sieve)
{
  if (sieve->dynamic_table)
    ssh_free(sieve->table);

  sieve->table = NULL;
}

/* sieve.h */
#endif /* SSHDIST_MATH */
