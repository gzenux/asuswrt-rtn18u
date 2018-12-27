/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for generating primes.
*/

#ifndef GENMP_H
#define GENMP_H

#include "sshcrypt.h"

/* Generates a random integer of the desired number of bits. */

void ssh_mprz_random_integer(SshMPInteger ret, unsigned int bits);

/* Makes and returns a random pseudo prime of the desired number of bits.
   Note that the random number generator must be initialized properly
   before using this.

   The generated prime will have the highest bit set, and will have
   the two lowest bits set.

   Primality is tested with Miller-Rabin test, ret thus having
   probability about 1 - 2^(-50) (or more) of being a true prime.
   */
void ssh_mprz_random_prime(SshMPInteger ret,unsigned int bits);

/* Generate a random prime within the [min, max] interval. We observe that
   the process can just choose a random number modulo (max - min) and
   then start from there. If it goes beyond max-1 then it cycles.
   */
void ssh_mprz_random_prime_within_interval(SshMPInteger ret,
                                         SshMPInteger min, SshMPInteger max);

/* Modular invert with positive results. */

int ssh_mprz_mod_invert(SshMPInteger op_dest, SshMPIntegerConst op_src,
                      SshMPIntegerConst modulo);

/* Random number with special modulus */

void ssh_mprz_mod_random(SshMPInteger op, SshMPIntegerConst modulo);

/* Generate a random integer with entropy at most _bits_ bits. The atmost,
   means that the actual number of bits depends whether the modulus is
   smaller in bits than the _bits_.  */
void ssh_mprz_mod_random_entropy(SshMPInteger op, SshMPIntegerConst modulo,
                               unsigned int bits);


/* Find a random generator of order 'order' modulo 'modulo'. */

Boolean ssh_mprz_random_generator(SshMPInteger g,
                                  SshMPInteger order, SshMPInteger modulo);


/* Generate primes p and q according to the method described in
   Appendix A.1.1.2 of FIPS 186-3. The input is p_bits and q_bits, the
   bit sizes of the primes to be generated. Output the primes p, q and
   return crypto status.
*/
SshCryptoStatus
ssh_mp_fips186_ffc_domain_parameter_create(SshMPInteger p,
                                           SshMPInteger q,
                                           unsigned int p_bits,
                                           unsigned int q_bits);

/* Create FFC keypair (x, y) from domain parameters p, q and g using
   extra random bits according to the Appendix B.1.1 of FIPS 186-3 */
SshCryptoStatus
ssh_mp_fips186_ffc_keypair_generation(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger x,
                                      SshMPInteger y);

/* Create FFC per-message secret random number using extra random bits
   according to the Appendix B.2.1 of FIPS 186-3 */
SshCryptoStatus
ssh_mp_fips186_ffc_per_message_secret(SshMPIntegerConst p,
                                      SshMPIntegerConst q,
                                      SshMPIntegerConst g,
                                      SshMPInteger k,
                                      SshMPInteger k_inverse);

/* Run General Lucas Probabilistic Primality Test for integer
   according to the Appendix C.3.3 of FIPS 186-3. Return FALSE
   if integer is composite, TRUE if integer is probably prime. */
Boolean ssh_mprz_crypto_lucas_test(SshMPIntegerConst c);

#endif /* GENMP_H */
