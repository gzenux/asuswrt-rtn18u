/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHMP_INTMOD_H
#define SSHMP_INTMOD_H

/* This library implements the "modular arithmetic". More correctly
   here are the routines for particular approach to arithmetic in
   Z/NZ where Z is the symbol denoting the set of integers, and N
   is a suitable integer.

   This library requires that N > 1, and only this.
 */

/* Definitions of a SSH Integer Moduli. */
typedef struct SshMPIntIdealRec
{
  Boolean d1,d2;
  Boolean primeideal;
  SshMPMontIntIdealStruct mideal;
  SshMPIntegerStruct i1, i2;
  unsigned int z2prec_n, z2prec_bits;
} *SshMPIntIdeal, *SshMPIntegerIdeal,
  SshMPIntIdealStruct, SshMPIntegerIdealStruct;

typedef const SshMPIntIdealStruct         *SshMPIntIdealConst;

/* Definition of a SSH Integer Modulo a Integer Q. */
typedef struct SshMPIntModRec
{
  SshMPMontIntModStruct   v1;
  SshMP2AdicIntegerStruct v2;
  SshMPIntIdealConst      m;
  unsigned int isnan:1;
  unsigned int nankind:4;
#define SSH_MPRZM_NAN_ENOMEM    1
#define SSH_MPRZM_NAN_IDEAL     2
#define SSH_MPRZM_NAN_MONT      4
#define SSH_MPRZM_NAN_2ADIC     8
} *SshMPIntMod, *SshMPIntegerModIdeal,
  SshMPIntModStruct, SshMPIntegerModIdealStruct;

typedef const SshMPIntModStruct           *SshMPIntModConst;

typedef struct SshMPIntModPowPrecompRec
{
  /* This number increases the speed, but also also the storage
     amount. Basically speed increases "linearly", but storage requirements
     increase exponentially. The linear increase, however, does not
     hold in practice that well. */
#define SSH_MPRZM_POW_PRECOMP_K 5

  /* A large table for computed values. */
  unsigned int table_size;
  unsigned int table_bits;
  SshMPIntMod        table;
  SshMPIntegerStruct order;
} *SshMPIntModPowPrecomp, SshMPIntModPowPrecompStruct;

typedef const SshMPIntModPowPrecompStruct *SshMPIntModPowPrecompConst;

/* Initialize the moduli. That is, this translates the moduli given in
   integer form to faster representation m. */
Boolean ssh_mprzm_init_ideal(SshMPIntIdeal m, SshMPIntegerConst op);
Boolean ssh_mprzm_init_primeideal(SshMPIntIdeal m, SshMPIntegerConst op);

/* Clear/free the modulus. */
void ssh_mprzm_clear_ideal(SshMPIntIdeal m);

/* Initialize a new integer modulo m. Notice that the moduli must be known
   when this is called. */

/* Inherit the moduli from another integer mod n. */
void ssh_mprzm_init_inherit(SshMPIntMod op1, SshMPIntModConst op2);
void ssh_mprzm_init(SshMPIntMod op, SshMPIntIdealConst m);

SshMPIntIdealConst ssh_mprzm_get_ideal(SshMPIntModConst op);

/* Clear the modulo m integer. */
void ssh_mprzm_clear(SshMPIntMod op);

/* Convert a SshMPInteger into a value modulo m. */
void ssh_mprzm_set_mprz(SshMPIntMod ret, SshMPIntegerConst op);
/* Copy one value modulo m into another. I.e. ret = op. */
void ssh_mprzm_set(SshMPIntMod ret, SshMPIntModConst op);
/* Copy unsigned int value to ret. */
void ssh_mprzm_set_ui(SshMPIntMod ret, SshWord u);

/* Convert a value modulo m into SshMPInt. */
void ssh_mprz_set_mprzm(SshMPInteger ret, SshMPIntModConst op);
void ssh_mprz_set_mprzm_ideal(SshMPInteger ret, SshMPIntIdealConst m);


/*  Comparison function. -1 means the two arguments are different. 1
    means that one of the inputs is a NaN. 0 means always the
    the inputs are same. */
int ssh_mprzm_cmp(SshMPIntModConst op1,
                  SshMPIntModConst op2);
int ssh_mprzm_cmp_ui(SshMPIntModConst op, SshWord u);

/* Basic arithmetic in modulo m representation. */

/* Fast modular addition and subtraction, keeps the values always within
   the modular domain. */
void ssh_mprzm_add(SshMPIntMod ret, SshMPIntModConst op1,
                   SshMPIntModConst op2);
void ssh_mprzm_sub(SshMPIntMod ret, SshMPIntModConst op1,
                   SshMPIntModConst op2);

/* Fast multiplication which keeps the values within modular domain. */
void ssh_mprzm_mul(SshMPIntMod ret, SshMPIntModConst op1,
                   SshMPIntModConst op2);
/* Fast multiplication by small integer. */
void ssh_mprzm_mul_ui(SshMPIntMod ret, SshMPIntModConst op,
                      SshWord u);
/* Very quick squaring operation. */
void ssh_mprzm_square(SshMPIntMod ret, SshMPIntModConst op);

/* Routines for handling modular divisions by powers of 2.

   These routines are meant mainly to be used for small powers and thus
   are not fastest for larger ones. However, for very small powers these
   work with small amount of operations.
   */
void ssh_mprzm_div_2exp(SshMPIntMod ret, SshMPIntModConst op,
                        unsigned int exp);
/* Very simple, and fast, multiplication by powers of 2. */
void ssh_mprzm_mul_2exp(SshMPIntMod ret, SshMPIntModConst op,
                        unsigned int exp);

/* This inversion is not fast, but we assume that you don't need faster
   implementation. It is possible to write faster inversion later. */
Boolean ssh_mprzm_invert(SshMPIntMod ret, SshMPIntModConst op);

/* Compute the square root mod Q. */
Boolean ssh_mprzm_sqrt(SshMPIntMod ret, SshMPIntModConst op);

/* Compute: g^e, in a variety of ways. */
void ssh_mprzm_pow(SshMPIntMod ret,
                   SshMPIntModConst g,
                   SshMPIntegerConst e);

void ssh_mprzm_pow_ui_g(SshMPIntMod ret,
                        SshWord g,
                        SshMPIntegerConst e);

void ssh_mprzm_pow_gg(SshMPIntMod ret,
                      SshMPIntModConst g1, SshMPIntegerConst e1,
                      SshMPIntModConst g2, SshMPIntegerConst e2);

void ssh_mprzm_pow_ui_exp(SshMPIntMod ret,
                          SshMPIntModConst g, SshWord e);

/* Modular exponentation with precomputation. Returns FALSE on failure. */
Boolean ssh_mprzm_pow_precomp_init(SshMPIntModPowPrecomp precomp,
                                   SshMPIntModConst g,
                                   SshMPIntegerConst order);

void ssh_mprzm_pow_precomp_clear(SshMPIntModPowPrecomp precomp);

SshMPIntIdealConst
ssh_mprzm_pow_precomp_get_ideal(SshMPIntModPowPrecompConst precomp);

void ssh_mprzm_pow_precomp(SshMPIntMod ret, SshMPIntegerConst e,
                           SshMPIntModPowPrecompConst precomp);

/* NaN routines */
void ssh_mprzm_makenan(SshMPIntMod op, unsigned int kind);
Boolean ssh_mprzm_isnan(SshMPIntModConst op);

Boolean ssh_mprzm_nanresult1(SshMPIntMod ret, SshMPIntModConst op);
Boolean ssh_mprzm_nanresult2(SshMPIntMod ret, SshMPIntModConst op1,
                             SshMPIntModConst op2);
Boolean ssh_mprzm_nanresult3(SshMPIntMod ret, SshMPIntModConst op1,
                             SshMPIntModConst op2, SshMPIntModConst op3);

#endif /* SSHMP_INTMOD_H */
