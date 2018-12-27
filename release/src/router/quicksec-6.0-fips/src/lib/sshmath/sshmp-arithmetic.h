/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmp-arithmetic.h
*/

#ifndef SSHMP_ARITHMETIC_H
#define SSHMP_ARITHMETIC_H

/* Arithmetic and number theory. The terminology here suggest that
   we consider integers (number theory) and their arithmetic
   properties (e.g. primes).

   Some such functions are placed also to the more lower-level libraries,
   for implementation reasons.
*/

/* Probabilistic primality test. This test ultimately uses the
   Miller-Rabin primality test in which one iteration has probability
   1/4:th giving false answer. Thus the caller can assume that
   (1/4)^(`limit'), where `limit' is the argument, gives the probability
   that this method gives an false answer.

   It is known assuming Generalized Riemann hypothesis that sufficiently
   many tests of Miller-Rabin give proof of primality. (As this function
   is probabilistic there would still be some change of mistake.)

   It is very unlikely that numbers above 100 digits pass this test
   even with small `limit' (say, 5) and would not be provable primes.
*/
int ssh_mprz_is_probable_prime(SshMPIntegerConst op,
                               unsigned int limit);

/* This function searches for the next prime number given a
   starting position. The primality is verified only probabilistically
   (except for very small values), and thus there is some change
   for failure. */
Boolean ssh_mprz_next_prime(SshMPInteger p, SshMPIntegerConst start);


/* op*inv == 1 (mod m), where op and m are given as input. */
Boolean ssh_mprz_invert(SshMPInteger inv, SshMPIntegerConst op,
                        SshMPIntegerConst m);

/* Following routines all compute (a/b) that is the Kronecker - Jacobi
   - Legendre symbol. In a case when b is prime we find out whether a
   is a quadratic residue or not. (These all use the same routine, thus
   there is no other need, but completeness, to include them all).*/
int ssh_mprz_kronecker(SshMPIntegerConst a, SshMPIntegerConst b);
int ssh_mprz_jacobi(SshMPIntegerConst a, SshMPIntegerConst b);
int ssh_mprz_legendre(SshMPIntegerConst a, SshMPIntegerConst b);

/* Routine to check whether a given value 'op' is perfect square, that is
   if op = t^2. Returns 1 if it is, 0 if not. */
int ssh_mprz_is_perfect_square(SshMPIntegerConst op);

/* Compute square root modulo a prime number. This uses the
   Tonelli & Shanks algorithm. */
Boolean ssh_mprz_mod_sqrt(SshMPInteger ret, SshMPIntegerConst op,
                          SshMPIntegerConst p);

#endif /* SSHMP_ARITHMETIC_H */
