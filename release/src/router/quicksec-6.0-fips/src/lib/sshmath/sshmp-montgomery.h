/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmp-montgomery.h
*/

#ifndef SSHMP_MONTGOMERY_H
#define SSHMP_MONTGOMERY_H

/* Library for Montgomery representation of Z/(n) for any odd positive
   integer n.
*/

/* Definitions of a Montgomery "ideals". */
typedef struct SshMPMontIntIdealRec
{
  /* First word (least significant) of -m^-1 (mod 2^n), where m is the
     moduli, and 2 does not divide m. */
  SshWord mp;

#ifdef ASM_PLATFORM_OCTEON
  SshWord big_mp[3];
#endif /* ASM_PLATFORM_OCTEON */

  /* The modulus.

     <m, m_n> denote the Montgomery moduli
     <d, m_n> denote the real moduli
     shift    tells the difference of `m' and `d'. */
  SshWord *m, *d;
  unsigned int m_n, shift;

  SshWord *karatsuba_work_space,  *work_space;

  unsigned int karatsuba_work_space_n, work_space_n;
} *SshMPMontIntIdeal, SshMPMontIntIdealStruct;

typedef const SshMPMontIntIdealStruct     *SshMPMontIntIdealConst;

/* Definition of a Montgomery representation numbers mod n. */
typedef struct SshMPMontIntModRec
{
  /* Basic integer information. That is

       n denotes the number of used words
       v denotes the array where these words are stored
     */
  unsigned int n;
  SshWord *v;

  unsigned int isnan:1;
  unsigned int nankind:2;
#define SSH_MPMZM_NAN_ENOMEM    1
#define SSH_MPMZM_NAN_IDEAL     2

  /* Modulus information. */
  SshMPMontIntIdealConst m;
} *SshMPMontIntMod, SshMPMontIntModStruct;

typedef const SshMPMontIntModStruct     *SshMPMontIntModConst;

/* This defines the use of workspace. That is, the workspace will be
   allocated (to minimize the needed allocations in modular arithmetic)
   to the modulus structure.

   You can of course undefine it, and then most allocation will be handled
   dynamically when doing computations. The amount of memory used is not
   prohibitive. */
#define SSHMATH_USE_WORKSPACE

/* Initialize the moduli. That is, this translates the moduli given in
   integer form to faster representation m. */
Boolean ssh_mpmzm_init_ideal(SshMPMontIntIdeal m, SshMPIntegerConst op);

/* Clear/free the modulus. */
void ssh_mpmzm_clear_ideal(SshMPMontIntIdeal m);

/* Initialize a new integer modulo m. Notice that the moduli must be known
   when this is called. */

/* Inherit the moduli from another integer mod n. */
void ssh_mpmzm_init_inherit(SshMPMontIntMod op1,
                            SshMPMontIntModConst op2);
void ssh_mpmzm_init(SshMPMontIntMod op, SshMPMontIntIdealConst m);

/* Clear the modulo m integer. */
void ssh_mpmzm_clear(SshMPMontIntMod op);

/* Convert a SshMPInteger into a value modulo m. */
void ssh_mpmzm_set_mprz(SshMPMontIntMod ret, SshMPIntegerConst op);
/* Copy one value modulo m into another. I.e. ret = op. */
void ssh_mpmzm_set(SshMPMontIntMod ret, SshMPMontIntModConst op);
/* Copy unsigned int value to ret. */
void ssh_mpmzm_set_ui(SshMPMontIntMod ret, SshWord u);

/* Convert a value modulo m into SshMPInt. */
void ssh_mprz_set_mpmzm(SshMPInteger ret, SshMPMontIntModConst op);
void ssh_mprz_set_mpmzm_ideal(SshMPInteger ret, SshMPMontIntIdealConst m);

/* Comparison function. -1 means the two arguments are different. 1
   means that one of the inputs is a NaN. 0 means always the
   the inputs are same. */
int ssh_mpmzm_cmp(SshMPMontIntModConst op1,
                  SshMPMontIntModConst op2);
int ssh_mpmzm_cmp_ui(SshMPMontIntModConst op, SshWord u);

/* Basic arithmetic in modulo m representation. */

/* Fast modular addition and subtraction, keeps the values always within
   the modular domain. */
void ssh_mpmzm_add(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                   SshMPMontIntModConst op2);
void ssh_mpmzm_sub(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                   SshMPMontIntModConst op2);

/* Fast multiplication which keeps the values within modular domain. */
void ssh_mpmzm_mul(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                  SshMPMontIntModConst op2);
/* Fast multiplication by small integer. */
void ssh_mpmzm_mul_ui(SshMPMontIntMod ret, SshMPMontIntModConst op,
                      SshWord u);
/* Very quick squaring operation. */
void ssh_mpmzm_square(SshMPMontIntMod ret, SshMPMontIntModConst op);

/* Routines for handling modular divisions by powers of 2.

   These routines are meant mainly to be used for small powers and thus
   are not fastest for larger ones. However, for very small powers these
   work with small amount of operations.
   */
void ssh_mpmzm_div_2exp(SshMPMontIntMod ret, SshMPMontIntModConst op,
                        unsigned int exp);
/* Very simple, and fast, multiplication by powers of 2. */
void ssh_mpmzm_mul_2exp(SshMPMontIntMod ret, SshMPMontIntModConst op,
                        unsigned int exp);

/* This inversion is not fast, but we assume that you don't need faster
   implementation. It is possible to write faster inversion later. */
Boolean ssh_mpmzm_invert(SshMPMontIntMod ret, SshMPMontIntModConst op);

/* Compute the square root mod Q. */
Boolean ssh_mpmzm_sqrt(SshMPMontIntMod ret, SshMPMontIntModConst op);

/* Compute: g^e. */
void ssh_mpmzm_pow(SshMPMontIntMod ret,
                   SshMPMontIntModConst g,
                   SshMPIntegerConst e);

void ssh_mpmzm_pow_gg(SshMPMontIntMod ret,
                      SshMPMontIntModConst g1, SshMPIntegerConst e1,
                      SshMPMontIntModConst g2, SshMPIntegerConst e2);

void ssh_mpmzm_pow_ui(SshMPMontIntMod ret,
                      SshWord g,
                      SshMPIntegerConst e);

void ssh_mpmzm_makenan(SshMPMontIntMod op, unsigned int kind);
Boolean ssh_mpmzm_isnan(SshMPMontIntModConst op);

Boolean ssh_mpmzm_nanresult1(SshMPMontIntMod ret, SshMPMontIntModConst op);
Boolean ssh_mpmzm_nanresult2(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                        SshMPMontIntModConst op2);

/*
   POW computations done iteratively with the current state
   stored in the SshMPMontPowState object. This can be useful for
   applications which want to compute modular exponentiations during idle
   time. Instead of computing the full modular exponentiation in one go it
   can instead be performed in multiple stages.
*/

typedef struct SshMPMontPowStateRec *SshMPMontPowState;

/* Allocate a state for performing the ssh_mprzm_pow operation with base
   g. */
SshMPMontPowState ssh_mpmzm_pow_state_alloc(SshMPMontIntModConst g);

/* Initialize the state from an integer 'e'. This returns FALSE in case of
   failure and TRUE otherwise. */
Boolean ssh_mpmzm_pow_state_init(SshMPMontPowState state, SshMPIntegerConst e);

/* Iterate through the next state in the POW computation. Returns TRUE
   if the computation has completed and FALSE otherwise. When this function
   returns TRUE the computed exponent g ^ e should be retrieved using the
   ssh_mpmzm_pow_state_set_result function. */
Boolean ssh_mpmzm_pow_state_iterate(SshMPMontPowState pow);

/* Returns the generated result of the POW computation. This function should
   only be called when a previous call to ssh_mpmzm_pow_state_iterate() has
   returned TRUE. It is illegal to call this function before
   ssh_mpmzm_pow_state_iterate() has returned TRUE. */
void ssh_mpmzm_pow_state_set_result(SshMPMontIntMod result,
                                    SshMPMontPowState state);

/* Free state and any resources from 'state'. */
void ssh_mpmzm_pow_state_free(SshMPMontPowState state);

#endif /* SSHMP_MONTGOMERY_H */
