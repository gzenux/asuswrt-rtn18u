/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Simple extension for sshmp-integer*.c that gives exactly 64 and
   128 bit integers without any dynamic memory management and using
   only minimal amount of memory. 64bit integer is implemented using
   built-in 64bit type if such type exists.
*/

/* On userspace required functionality to implement 64-bit and 128-bit
   operations is gotten from sshmp-kernel.c. On kernel, however,
   sshmp-kernel.c is not compiled, so we'll need to substitute it here.
   Also some helpers for 2x32, to make things easier... */

#include "sshincludes.h"
#include "sshmp-xuint.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshMPXUInt"

#ifdef KERNEL

/* These functions are copied from sshmp-kernel.c, but only code for handling
   case op1_n == op2_n is retained. */

SshWord ssh_mpk_add(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n)
{
  SshWord c;
  unsigned int i;
  SshWord t, k;

  SSH_ASSERT( op1_n == op2_n ); /* Currently we only handle
                                   buffers of the same size. */

  /* Add two buffers of equal length. */
  for (i = 0, c = 0; i < op2_n; i++)
    {
      /* Do the standard addition procedure. We assume that the word
         size is correct, and no additional bits are available for
         the word. This assumption is used throughout this code. */
      k = op1[i] + c;
      if (k < c)
        c = 1;
      else
        c = 0;
      t = k + op2[i];
      if (t < k)
        c++;
      ret[i] = t;
    }
  return c;
}

SshWord ssh_mpk_sub(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n)
{
  SshWord c;
  unsigned int i;
  SshWord t, k, j;

  SSH_ASSERT( op1_n == op2_n ); /* Currently we only handle
                                   buffers of the same size. */

  /* Subtraction with buffers of equal length. */
  for (i = 0, c = 0; i < op2_n; i++)
    {
      /* Standard subtraction. Assumes same things as addition. */
      k = op1[i];
      j = op2[i] + c;
      if (j < c)
        c = 1;
      else
        c = 0;
      t = k - j;
      if (t > k)
        c++;
      ret[i] = t;
    }
  return c;
}
#endif /* KERNEL */

#ifdef SSH_XUINT64_EMULATED_2X32
void ssh_xuint64_build(SshXUInt64 r,SshUInt32 a,SshUInt32 b)
{
  SshXUInt64 result;
  result[0] = a&0xffffffffu;
  result[1] = b&0xffffffffu;
  r[0] = result[0];
  r[1] = result[1];
}
#endif /* SSH_XUINT64_EMULATED_2X32 */
