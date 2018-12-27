/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Random number generation.

   <keywords random number generation, utility functions/random number
   generation, RNG (Random Number Generator), number/random>

   A simple (deterministic) pseudo-random number generator.

   The main purpose of this file is to introduce a simple and standard
   mechanism for SSH software to generate random numbers in test programs
   in a deterministic way.

   For the convenience of test programs the caller can use the state
   passing approach, or the global state.

   The pseudo-random number generator is robust enough for usage in
   applications requiring randomness. Some features in this library are
   often lacking from more well-known libraries. Especially the `range'
   functionality should be valuable.

   @internal
*/

#ifndef SSH_RAND_H
#define SSH_RAND_H

/* **** Private structures. */

/**  This section contains definitions of the internal representation
     of the pseudo-random number generator. This may change and
     applications should not rely on details of this section. */

/**  The random number generation is based on following approach:

     Lagged Fibonacci generator (LFG) is used for generating
     individual pseudo-random numbers. The benefit is high-speed, and
     LFG's have good statistical justification. (At the moment the LFG
     uses a simple extension, which may cause unstable behaviour. More
     study on this will be conducted.)

     Inversive Congruental generator (ICG) is used to seed the LGF.
     ICG's are statistically very stable generators, however, in
     practice rather slow.  */

/**  The Lagged Fibonacci generator vector size. This was selected
     to achieve a period close to 2^128. */
#define SSH_RAND_LGF_VSIZE 98
struct SshLFGStateRec
{
  /**  The lagged Fibonacci vector and the current position. */
  SshUInt32 v[SSH_RAND_LGF_VSIZE];
  SshUInt32 pos;
};

typedef struct SshLFGStateRec    SshLFGStateStruct;

/**  The main random state structure. */
struct SshRandStructRec
{
  SshLFGStateStruct lfg;
};

/* **** Public interface. */

/*  This section contains the public interface of the pseudo-random
    number generator. */

/**  The random state context. */
typedef struct SshRandStructRec *SshRand;
typedef struct SshRandStructRec  SshRandStruct;

/**  Seed the global generator state. Any value from [0, 2^32) is
     allowed for the seed, including the value zero. The caller may
     trust that no pair of seeds will produce pseudo-random number
     sequences that are highly correlated.

     Note: There is no such proof that correlation would not be
     possible, however, it is unlikely.

     Seeding is not a fast operation, it is approximately 1000 times
     slower than obtaining a new pseudo-random number from the
     generator. */
void ssh_rand_seed(SshUInt32 seed);

/**  Convenience interface, that follows the established naming
     convention for the random number generation seeding. */
#define ssh_srand ssh_rand_seed

/**  Obtain a pseudo-random number uniformly selected from [0,2^32). It
     is guaranteed that the sequence of numbers produced has a high
     period, and passes most empirical statistical randomness tests.

     This operation updates the global state irreversibly. */
SshUInt32 ssh_rand(void);

/**  Obtain a pseudo-random number (almost) uniformly distributed from
     [lo, hi]. The following preconditions must be fulfilled by the `lo'
     and `hi':

      lo < hi   and   hi < lo + 0x80000000.

     The first condition is natural and violation will cause
     `ssh_fatal'. It can be argued that the latter is only a
     implementation technical detail, but avoiding it is not always
     practical. Violation of the latter precondition will also cause
     appropriate `ssh_fatal'.

     In most situations usage of this function is to be preferred to
     the `ssh_rand', as this frees the application from concern of
     bias in the distribution.

     This operation updates the global state irreversibly. */
SshUInt32 ssh_rand_range(SshUInt32 lo, SshUInt32 hi);


/*  The local state interface. */

/**  As a general rule a variable `state' may be NULL, and it will be
     interpreted as the global state. */

/**  Re-seed a state. This operation destroys the previous state
     irreversibly. The `state' may be NULL in which case the global state
     is reseeded.

     See also the comments for `ssh_rand_seed'. */
void ssh_rand_state_seed(SshRand state, SshUInt32 seed);

/**  Obtain a pseudo-random number uniformly selected from [0,2^32). The
     `state' may be NULL in which case the global state is used to obtain
     the number.

     This operation updates the state irreversibly. */
SshUInt32 ssh_rand_state(SshRand state);

/**  Obtain a pseudo-random number (almost) uniformly selected from [lo,

     hi]. The `state' may be NULL in which case the global state is
     used to obtain the number. See the `ssh_rand_range' for
     preconditions that `lo' and `hi' must satisfy. In most situations
     usage of this function is to be preferred to the
     `ssh_rand_state', as this frees the application from concern of
     bias in the distribution.

     This operation updates the state irreversibly. */
SshUInt32 ssh_rand_state_range(SshRand state, SshUInt32 lo, SshUInt32 hi);

/**  Make a copy of the current state. This can be used to backtrack in
     a program that uses randomness to direct its state transition.
     The states `dst' and `src' may either or both be NULL, in which
     case NULL is replaced by the global state.

     This operation is efficient and does not require reseeding. */
void ssh_rand_state_copy(SshRand dst, SshRand src);

#endif /* SSH_RAND_H */

