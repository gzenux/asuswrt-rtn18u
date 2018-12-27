/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Sieve for small primes.

   Purpose of this file is to allow any application an almost endless
   source of small primes. E.g. you don't need to table them, or anything,
   just compute them with this program when needed and then use 'em.

   This code is reasonably fast, and compared to large integer arithmetic,
   for example, this won't slow down anything.

   OBJECTIVE:

     Replace the old SSH large prime seeking code with code that
     uses SshSieve and thus probably works faster and is cleaner.
*/

#ifndef SIEVE_H
#define SIEVE_H

/* This size is large enough for most applications and in these cases
   avoids using dynamic memory for the sieve. */
#define SSH_MP_SIEVE_STATIC_BYTE_SIZE 1024

/* The sieve data structure. */
typedef struct
{
  Boolean dynamic_table;
  unsigned int len;
  unsigned int count;

  SshWord *table;
  SshWord table_array[(SSH_MP_SIEVE_STATIC_BYTE_SIZE * 8) / SSH_WORD_BITS];

} *SshSieve, SshSieveStruct;

typedef const SshSieveStruct *SshSieveConst;

/* Prototypes. */

/* Allocate a prime sieve. */
Boolean
ssh_sieve_allocate_ui(SshSieve sieve, unsigned int x,
                      unsigned int memory_limit);
Boolean
ssh_sieve_allocate(SshSieve sieve,
                   unsigned int memory_limit);

/* Find next prime to x, e.g. prime p that is larger than x and there
   is no small prime between them. Returns 0 if sieve doesn't
   contain enough primes. */
unsigned long ssh_sieve_next_prime(unsigned long x, SshSieveConst sieve);

/* Find the largest prime this sieve contains. */
unsigned long ssh_sieve_last_prime(SshSieveConst sieve);
/* Returns the number of primes this sieve contains. */
unsigned long ssh_sieve_prime_count(SshSieveConst sieve);

/* Free the sieve data structure. */
void ssh_sieve_free(SshSieve sieve);

#endif /* SIEVE_H */
