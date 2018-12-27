/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This is a replacement function for random for systems that do not
   have this function.
*/

#ifndef VXWORKS

#ifdef KERNEL

/* Resolve which kernels do not provide random(). */
#ifdef __linux__
#define SSH_COMPILE_RANDOM_C 1
#endif /* __linux__ */

#else /* not KERNEL */

/* Check if the user-mode compilation needs random(). */
#ifndef HAVE_RANDOM
#define SSH_COMPILE_RANDOM_C 1
#endif /* not HAVE_RANDOM */

#endif /* not KERNEL */

#if defined(SSH_COMPILE_RANDOM_C)

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)random.c    5.9 (Berkeley) 2/23/91";
#endif /* LIBC_SCCS and not lint */

#include "sshincludes.h"
#include "sshrand.h"

void srandom(unsigned int x)
{
  SshUInt32 seed = (SshUInt32)x;

  ssh_rand_seed(seed);
}

long random(void)
{
  return (long) ssh_rand();
}

#else /* not SSH_COMPILE_RANDOM_C */
/* A typedef to keep compiler quiet with this otherwise empty source
   file. */
typedef enum
  {
    SSH_RANDOM_C_EMPTY
  } SshRandomCEmpty;
#endif /* not SSH_COMPILE_RANDOM_C */

#endif /* VXWORKS */
