/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmp-convabs.h
*/

#ifndef SSHMP_CONVABS_H
#define SSHMP_CONVABS_H

/* Useful abstractions which may make parts of the library easier to
   use, hopefully.
*/

/* The following functions are defined.

   void ssh_mprz_init_all(SshMPInteger *x);
   void ssh_mprm_init_all(SshMPIntMod *x, SshMPIntModuli m);
   void ssh_mprq_init_all(SshMPRational *x);
   void ssh_mprf_init_all(SshMPFloat *x);
   void ssh_mpcf_init_all(SshMPComplex *x);

   And their `clear' counterparts.

   These routines are supposed to be used in the following way;

     SshMPIntegerStruct  a, b;
     SshMPInteger *x = { &a, &b }
     ssh_mprz_init_all(x);
     ... do something ...
     ssh_mprz_clear_all(x);

   The benefit is the simplicity, which helps at times when
   one works with lots of big variables.
 */

#define ssh_mprz_init_all(x) \
  ssh_mprz_convabs_init_all(x, sizeof(x)/sizeof((x)[0]));
#define ssh_mprz_clear_all(x) \
  ssh_mprz_convabs_clear_all(x, sizeof(x)/sizeof((x)[0]));

#ifdef SSHDIST_MATH_INTMOD
#define ssh_mprzm_init_all(x, m) \
  ssh_mprzm_convabs_init_all(x, sizeof(x)/sizeof((x)[0]), m);
#define ssh_mprzm_clear_all(x) \
  ssh_mprzm_convabs_clear_all(x, sizeof(x)/sizeof((x)[0]));
#endif /* SSHDIST_MATH_INTMOD */






















#endif /* SSHMP_CONVABS_H */



