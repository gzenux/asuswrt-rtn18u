/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains generic functions for generating multiple-precision
   primes.

   (These functions were copied from sshcrypto/sshpk/genmp*, which are
   cryptolib internal files, and which are not public..)
*/

#include "sshincludes.h"
#ifdef SSHDIST_MATH
#include "sshmp.h"
#include "sshcrypt.h"

#define SSH_DEBUG_MODULE "SshGenMPAux"


/* Generate a random integer (using the cryptographically strong
   random number generator). */

static void ssh_mprz_random_integer(SshMPInteger ret, unsigned int bits)
{
  unsigned int i, bytes;
  unsigned char *buf;

  ssh_mprz_set_ui(ret, 0);

  bytes = (bits + 7) / 8;
  if ((buf = ssh_malloc(bytes)) == NULL)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  for (i = 0; i < bytes; i++)
    buf[i] = ssh_random_get_byte();

  ssh_mprz_set_buf(ret, buf, bytes);
  ssh_free(buf);

  /* Cut unneeded bits off */
  ssh_mprz_mod_2exp(ret, ret, bits);
}


/* Get random number mod 'modulo' */

/* Random number with some sense in getting only a small number of
   bits. This will avoid most of the extra bits. However, we could
   do it in many other ways too. Like we could distribute the random bits
   in reasonably random fashion around the available size. This would
   ensure that cryptographical use would be slightly safer. */
void ssh_mprz_aux_mod_random_entropy(SshMPInteger op,
                                     SshMPIntegerConst modulo,
                                     unsigned int bits)
{
  ssh_mprz_random_integer(op, bits);
  ssh_mprz_mod(op, op, modulo);
}

/* Just plain _modular_ random number generation. */
void ssh_mprz_aux_mod_random(SshMPInteger op, SshMPIntegerConst modulo)
{
  unsigned int bits;

  bits = ssh_mprz_bit_size(modulo);
  ssh_mprz_random_integer(op, bits);
  ssh_mprz_mod(op, op, modulo);
}

int ssh_mprz_aux_mod_invert(SshMPInteger op_dest, SshMPIntegerConst op_src,
                            SshMPIntegerConst modulo)
{
  int status;

  status = ssh_mprz_invert(op_dest, op_src, modulo);

  if (ssh_mprz_cmp_ui(op_dest, 0) < 0)
    ssh_mprz_add(op_dest, op_dest, modulo);

  return status;
}
#endif /* SSHDIST_MATH */
