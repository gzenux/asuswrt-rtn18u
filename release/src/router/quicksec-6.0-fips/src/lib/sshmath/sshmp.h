/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmp.h
*/

#ifndef SSHMP_H
#define SSHMP_H

/********** MATH LIBRARY INITIALIZATION AND UNINITIALIZATION *************/

#ifdef SSHDIST_MATH

/* Indicates the current status of the math library. */
typedef enum
{
  SSH_MATH_LIBRARY_UNINITIALIZED = 0,
  SSH_MATH_LIBRARY_OK = 1,
  SSH_MATH_LIBRARY_SELF_TEST = 2
} SshMathLibraryStatus;

/* Initialize the math library with the default configuration
   parameters.

   The library cannot be used before this function is called. This function
   may call the library's self tests. It returns TRUE if the library was
   properly initialized and all the self tests succedeed. The status of the
   library is then set to SSH_MATH_LIBRARY_OK. If the self tests fail, FALSE
   is returned and the global status of the library is reset to
   SSH_MATH_LIBRARY_UNINITIALIZED. */
Boolean ssh_math_library_initialize(void);

/* Uninitialize the math library. */
void ssh_math_library_uninitialize(void);

/* Performs the math library self tests, namely to test the integer
   and modular integer routines. Returns TRUE if all tests succeed,
   and FALSE otherwise. This may be called on library initialization by
   ssh_math_library_initialize. It can also be called at any subsequent time
   to verify the correct working order of the library. */
Boolean ssh_math_library_self_tests(void);

/* Returns TRUE if the math library status is SSH_MATH_LIBRARY_OK
   or SSH_MATH_LIBRARY_SELF_TEST (needed so that the library can
   perform the self tests). Otherwise returns FALSE. */
Boolean ssh_math_library_is_initialized(void);


/************************************************************************/
/* General definitions.                                                 */

/* The pseudo-random number generator. Please recall that this is not a
   cryptographically secure generator. It is mainly used at places where
   large number of pseudo-random numbers are needed at quick interval.

   Indeed, all routines in the mathematics library utilize this random
   number generator, if they use any. To create cryptographical
   randomness use some external means to generate it and introduce it
   to the computations through the high-level interface.
*/
#include "sshrand.h"

#include "sshbuffer.h"


/************************************************************************/
/* Mathematic library specific definitions.                             */

/* Mathematics library special type definitions. */
#include "sshmp-types.h"

/* The kernel definitions and primitives. */
#include "sshmp-kernel.h"

/* This defines the use of workspace. That is, the workspace will be
   allocated (to minimize the needed allocations in modular arithmetic)
   to the modulus structure.

   You can of course undefine it, and then most allocation will be handled
   dynamically when doing computations. */
#define SSHMATH_USE_WORKSPACE

/************************************************************************/
/* Integers.                                                            */

/* Library for large integers. Most libraries requiring support for
   large integers do not need the code below. */
#include "sshmp-integer.h"

int
ssh_mprz_encode_rendered(unsigned char *buf, size_t len, const void *ptr);
int
ssh_mprz_decode_rendered(const unsigned char *buf, size_t len, void *ptr);

int
ssh_mprz_encode_ssh2style(SshMPIntegerConst mp,
                          unsigned char *buf, size_t len);
int
ssh_mprz_decode_ssh2style(const unsigned char *buf, size_t len,
                          SshMPInteger mp);

int
ssh_mprz_encode_uint32_str(unsigned char *buf, size_t len, const void *datum);

int
ssh_mprz_decode_uint32_str_noalloc(const unsigned char *buf, size_t len,
                                   void *datum);


/************************************************************************/
/* Arithmetic.                                                          */

#ifdef SSHDIST_MATH_SIEVE
/* The prime number sieve. This is required by certain arithmetical
   functions. */
#include "sshsieve.h"
#endif /* SSHDIST_MATH_SIEVE */

#ifdef SSHDIST_MATH_ARITHMETIC
/* Arithmetic of numbers. */
#include "sshmp-arithmetic.h"
#endif /* SSHDIST_MATH_ARITHMETIC */

/************************************************************************/
/* Routines for residue rings.                                          */

#ifdef SSHDIST_MATH_2ADIC
/* 2-adic integers. */
#include "sshmp-2adic.h"
#endif /* SSHDIST_MATH_2ADIC */
#ifdef SSHDIST_MATH_MONTGOMERY
/* Montgomery representation. */
#include "sshmp-montgomery.h"
#endif /* SSHDIST_MATH_MONTGOMERY */

#ifdef SSHDIST_MATH_INTMOD
/* Library for integers modulo N. */
#include "sshmp-intmod.h"
#endif /* SSHDIST_MATH_INTMOD */

/************************************************************************/
/* Numbers.                                                             */














/************************************************************************/
/* Miscellaneous, but important.                                        */

/* Convenience abstractions. */
#include "sshmp-convabs.h"

#ifdef SSHDIST_MATH_POWM
/* Convenient functions for modular exponentiation, used extensively
   in the older versions. It is possible that this interface will be
   moved later to the "legacy" department. */
#include "sshmp-powm.h"
#endif /* SSHDIST_MATH_POWM */

/************************************************************************/
/* Function fields (and rings).                                         */






















/* Future work, more general function field code. */

/************************************************************************/
/* Elliptic curves (and rings).                                         */

#ifdef SSHDIST_MATH_NAF
#include "sshmp-naf.h"
#endif /* SSHDIST_MATH_NAF */

/* XX Initial conversion from the old code. Some modifications are to
   be still made. */
#ifdef SSHDIST_MATH_ECP
#include "sshmp-ecp.h"
#endif /* SSHDIST_MATH_ECP */





#endif /* SSHDIST_MATH */
#endif /* SSHMP_H */
