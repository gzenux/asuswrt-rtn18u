/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHMP_2ADIC_H
#define SSHMP_2ADIC_H

/* This library implements 2-adic multiple precision arithmetic. The intuitive
   idea is that we just expand the accuracy of the machine word size
   in arbitrary way, but keeping all its usual structure.

   In more rigorous words this is an approximate implementation of the
   2-adic integers Z_{2}. They can be expressed as the direct sum

   Z/(2) + Z/(2^2) + ...

   and thus approximated by Z/(2^n) for sufficiently large n.
*/

typedef struct SshMP2AdicRec
{
  SshWord n,m;
  SshWord *v;
  unsigned int isnan:1;
  unsigned int nankind:1;
#define SSH_MP2AZ_NAN_ENOMEM    1
} *SshMP2AdicInteger, SshMP2AdicIntegerStruct;

typedef const SshMP2AdicIntegerStruct *SshMP2AdicIntegerConst;

#define SSH_MP2AZ_DEF_PREC 128

void ssh_mp2az_init(SshMP2AdicInteger op);
void ssh_mp2az_init_with_prec(SshMP2AdicInteger op, unsigned int prec);
void ssh_mp2az_init_inherit_prec(SshMP2AdicInteger ret,
                                 SshMP2AdicIntegerConst op);
void ssh_mp2az_clear(SshMP2AdicInteger op);

void ssh_mp2az_set_prec(SshMP2AdicInteger ret, unsigned int prec);
unsigned int ssh_mp2az_get_prec(SshMP2AdicIntegerConst op);

void ssh_mp2az_set_mprz(SshMP2AdicInteger ret, SshMPIntegerConst op);
void ssh_mprz_set_mp2az(SshMPInteger ret, SshMP2AdicIntegerConst op);

void ssh_mp2az_set_ui(SshMP2AdicInteger ret, SshWord ui);
SshWord ssh_mp2az_get_ui(SshMP2AdicIntegerConst op);

void ssh_mp2az_set(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op);

int ssh_mp2az_dist(SshMP2AdicIntegerConst op1, SshMP2AdicIntegerConst op2);
int ssh_mp2az_dist_ui(SshMP2AdicIntegerConst op, SshWord ui);

/* This returns the number n s.t. p^n divides `op'. It is called
   here the valuation (or norm) of the 2-adic integer. Observe that
   the more standard definition is 1/(p^n) for the norm, but we
   do not want to introduce the difficulty of handling those value.

   Infact, note that 1/(p^(a)) < 1/(p^(b)) <=> p^b < p^a <=> b < a (as
   a,b are both positive integers). Thus we see that to obtain
   "correct" comparison rules we can just return negatives of the
   2-valuations. However, we do not do that here, as it would make
   the interface somewhat adhoc.

   Notice that here if P = 0 then |P| = -1.

   Fact. If |P| = 0 then P is invertible, or in the standard
         p-valuation |P| = 1 then P is invertible.
*/
int ssh_mp2az_norm(SshMP2AdicIntegerConst op);

/* Basic arithmetic. */
void ssh_mp2az_mul(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                   SshMP2AdicIntegerConst op2);
void ssh_mp2az_mul_ui(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                      SshWord u);
void ssh_mp2az_square(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op);
void ssh_mp2az_add(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                   SshMP2AdicIntegerConst op2);
void ssh_mp2az_sub(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                   SshMP2AdicIntegerConst op2);
void ssh_mp2az_negate(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op);

void ssh_mp2az_mul_2exp(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                        unsigned int bits);
void ssh_mp2az_div_2exp(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                        unsigned int bits);

/* Try to invert the 2-adic integer. This operation may fail. */
Boolean ssh_mp2az_invert(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op);

/* Try to compute square root of the 2-adic integer. This operation
   may fail. */
Boolean ssh_mp2az_sqrt(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op);

/* Fast exponentiation. */
void ssh_mp2az_pow(SshMP2AdicInteger ret, SshMP2AdicIntegerConst g,
                   SshMPIntegerConst e);

void ssh_mp2az_makenan(SshMP2AdicInteger op, unsigned int kind);
Boolean ssh_mp2az_isnan(SshMP2AdicIntegerConst op);

Boolean ssh_mp2az_nanresult1(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op);
Boolean ssh_mp2az_nanresult2(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                        SshMP2AdicIntegerConst op2);

#endif /* SSHMP_2ADIC_H */
