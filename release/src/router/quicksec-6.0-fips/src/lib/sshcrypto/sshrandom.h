/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   In most cases, you should use the interface in the sshcrypt.h file.
   The previous API (ssh_random_add_noise, ssh_random_stir,
   ssh_random_get_byte and ssh_random_free) use this API on a lower
   level.

   Note: When speaking about RNG, in most cases the correct term would
   be PRNG (for Pseudo Random Number Generator). However, because the
   implementation may also be a real RNG implementation using
   hardware randomness, comments generally speak of RNG.
*/

#ifndef SSHRANDOM_H
#define SSHRANDOM_H

/* ***************** Random Number Generators **********************/

typedef struct SshRandomRec *SshRandom;

/** Return a comma-separated list of supported RNG names. The caller
    must free the returned value with a ssh_crypto_free() call. */
char *
ssh_random_get_supported(void);

/** Return TRUE or FALSE depending on whether the RNG called `name' is
    supported by this version of cryptographic library (and the
    current FIPS mode). */
Boolean
ssh_random_supported(const char *name);

/** Allocates and initializes a random number generator
    context.

    Note: It is valid to pass NULL as `name' - in that case
    some "default" RNG is allocated (however it is guaranteed that
    the RNG is FIPS-compliant if FIPS mode is enabled). */
SshCryptoStatus
ssh_random_allocate(const char *name,
                    SshRandom *random_ret);

/** Frees a RNG. This can also be called when the library is in an
    error state. */
void
ssh_random_free(SshRandom random);

/** Returns the name of the RNG. The name is equal to that which was used in
    ssh_random_allocate. The name points to an internal data structure and
    should NOT be freed, modified, or used after ssh_random_free is called. */
const char *
ssh_random_name(SshRandom random);

/** Fill a buffer with bytes from the RNG output. */
SshCryptoStatus
ssh_random_get_bytes(SshRandom random,
                     unsigned char *buffer, size_t bufferlen);

/** Add noise to the RNG. */
SshCryptoStatus
ssh_random_add_entropy(SshRandom random,
                       const unsigned char *buf, size_t buflen,
                       size_t estimated_entropy_bits);

/** Adds environmental noise to the given random number generator.

    If the NULL random is given, the default RNG (usable
    using sshcrypt.h API) will be targeted.

    Note: On embedded systems this may actually not do anything.
    */
void
ssh_random_add_light_noise(SshRandom random);

#endif /* SSHRANDOM_H */
