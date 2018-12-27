/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#ifdef SSHDIST_MATH
void ssh_mprz_convabs_init_all(SshMPInteger *x, unsigned int l)
{
  unsigned int i;
  for (i = 0; i < l; i++)
    ssh_mprz_init(x[i]);
}

void ssh_mprz_convabs_clear_all(SshMPInteger *x, unsigned int l)
{
  unsigned int i;
  for (i = 0; i < l; i++)
    ssh_mprz_clear(x[i]);
}

#ifdef SSHDIST_MATH_INTMOD
void ssh_mprzm_convabs_init_all(SshMPIntMod *x, unsigned int l,
                                SshMPIntIdealConst m)
{
  unsigned int i;
  for (i = 0; i < l; i++)
    ssh_mprzm_init(x[i], m);
}

void ssh_mprzm_convabs_clear_all(SshMPIntMod *x, unsigned int l)
{
  unsigned int i;
  for (i = 0; i < l; i++)
    ssh_mprzm_clear(x[i]);
}
#endif /* SSHDIST_MATH_INTMOD */

















































/* sshmp-convabs.c */
#endif /* SSHDIST_MATH */
