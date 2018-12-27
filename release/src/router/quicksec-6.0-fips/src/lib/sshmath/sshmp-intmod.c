/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMPIntMod"

#ifdef SSHDIST_MATH
/* NaN routines. */

Boolean ssh_mprzm_isnan(SshMPIntModConst op)
{
  return (op->m == NULL && op->isnan);
}

void ssh_mprzm_makenan(SshMPIntMod op, unsigned int kind)
{
   if (op->m)
    {
      if (op->m->d1)
        ssh_mpmzm_clear(&op->v1);
      if (op->m->d2)
        ssh_mp2az_clear(&op->v2);
    }

  op->m = NULL;
  op->isnan = TRUE;
  op->nankind = kind;
}

void ssh_mprzm_checknan(SshMPIntMod op)
{
  if (op->m)
    {
      if (op->m->d1 && ssh_mpmzm_isnan(&op->v1))
        {
          ssh_mprzm_makenan(op, SSH_MPRZM_NAN_MONT);
          return;
        }

      if (op->m->d2 && ssh_mp2az_isnan(&op->v2))
        {
          ssh_mprzm_makenan(op, SSH_MPRZM_NAN_2ADIC);
          return;
        }
    }
}

Boolean ssh_mprzm_nanresult1(SshMPIntMod ret, SshMPIntModConst op)
{
  if (ssh_mprzm_isnan(ret))
    return TRUE;

  if (ssh_mprzm_isnan(op))
    {
      ssh_mprzm_makenan(ret, op->nankind);
      return TRUE;
    }

  if (ret->m != op->m)
    {
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_IDEAL);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_mprzm_nanresult2(SshMPIntMod ret, SshMPIntModConst op1,
                             SshMPIntModConst op2)
{
  if (ssh_mprzm_isnan(ret))
    return TRUE;

  if (ssh_mprzm_isnan(op1))
    {
      ssh_mprzm_makenan(ret, op1->nankind);
      return TRUE;
    }

  if (ssh_mprzm_isnan(op2))
    {
      ssh_mprzm_makenan(ret, op2->nankind);
      return TRUE;
    }

  if (ret->m != op1->m || ret->m != op2->m)
    {
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_IDEAL);
      return TRUE;
    }

  return FALSE;

}


/* Initialization (if 2 divides op then this may take quite a long time). */

Boolean ssh_mprzm_init_ideal(SshMPIntIdeal m, SshMPIntegerConst op)
{
  SshMPIntegerStruct k;
  unsigned int i;

  memset(m, 0, sizeof(*m));

  if (ssh_mprz_isnan(op))
    return FALSE;

  ssh_mprz_init(&k);
  ssh_mprz_set(&k, op);
  ssh_mprz_abs(&k, &k);

  ssh_mprz_init(&m->i1);
  ssh_mprz_init(&m->i2);

  /* The ideal the full ring, and thus the residue class is empty. */
  if (ssh_mprz_isnan(&k) || ssh_mprz_cmp_ui(&k, 1) == 0)
    goto fail;

  if (ssh_mprz_cmp_ui(&k, 0) == 0)
    goto fail;

  /* Find 2^n that divides the moduli. */
  for (i = 0; ssh_mprz_get_bit(&k,i) == 0; i++)
    ;

  ssh_mprz_div_2exp(&k, &k, i);

  if (ssh_mprz_cmp_ui(&k, 1) > 0)
    {
      m->d1 = TRUE;
      if (!ssh_mpmzm_init_ideal(&m->mideal, &k))
        goto fail;
    }

  m->z2prec_n    = (i + SSH_WORD_BITS - 1) / SSH_WORD_BITS;
  m->z2prec_bits = i;

  if (m->z2prec_n)
    {
      m->d2 = TRUE;
    }

  if (m->d1 && m->d2)
    {
      SshMP2AdicIntegerStruct t2;
      SshMPMontIntModStruct tm;

      /* We now precompute inverses for the CRT. These are both
         usually quite fast, althought computation of 2^{-n} (mod q),
         for q odd, gets very slow when n is large. However,
         nevertheless n <= log_2 N, of the moduli N. */

      /* The Monty case. */
      ssh_mpmzm_init(&tm, &m->mideal);
      ssh_mpmzm_set_ui(&tm, 1);
      ssh_mpmzm_div_2exp(&tm, &tm, m->z2prec_bits);
      ssh_mprz_set_mpmzm(&m->i1, &tm);
      ssh_mpmzm_clear(&tm);

      /* The 2-adic case. */
      ssh_mp2az_init_with_prec(&t2, m->z2prec_n);
      ssh_mp2az_set_mprz(&t2, &k);
      ssh_mp2az_invert(&t2, &t2);
      ssh_mprz_set_mp2az(&m->i2, &t2);
      ssh_mprz_mod_2exp(&m->i2, &m->i2, m->z2prec_bits);
      ssh_mp2az_clear(&t2);

      /* If Failed, free memory. */
      if (ssh_mprz_isnan(&m->i1) || ssh_mprz_isnan(&m->i2))
        {
          ssh_mpmzm_clear_ideal(&m->mideal);
          ssh_mprz_clear(&m->i1);
          ssh_mprz_clear(&m->i2);
          goto fail;
        }
    }

  ssh_mprz_clear(&k);

  return TRUE;
 fail:
  ssh_mprz_clear(&k);
  memset(m, 0, sizeof(*m));
  return FALSE;
}

Boolean ssh_mprzm_init_primeideal(SshMPIntIdeal m, SshMPIntegerConst op)
{
  if (ssh_mprzm_init_ideal(m, op))
    {
      /* This is a useful piece of information. Basically
         it tells us that Z/(p) is a field. */
      m->primeideal = TRUE;
      return TRUE;
    }
  else
    {
      memset(m, 0, sizeof(*m));
      return FALSE;
    }
}

/* Clean up the used moduli space. */
void ssh_mprzm_clear_ideal(SshMPIntIdeal m)
{
  if (m == NULL)
    return;

  /* Free. */
  if (m->d1)
    ssh_mpmzm_clear_ideal(&m->mideal);
  ssh_mprz_clear(&m->i1);
  ssh_mprz_clear(&m->i2);
  /* Clean. */
  memset(m, 0, sizeof(*m));
}

void ssh_mprz_set_mprzm_ideal(SshMPInteger ret, SshMPIntIdealConst m)
{
  if (m == NULL)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  if (m->d1 && m->d2)
    {
      ssh_mprz_set_mpmzm_ideal(ret, &m->mideal);
      ssh_mprz_mul_2exp(ret, ret, m->z2prec_bits);
      return;
    }
  if (m->d1)
    {
      ssh_mprz_set_mpmzm_ideal(ret, &m->mideal);
      return;
    }
  if (m->d2)
    {
      ssh_mprz_set_ui(ret, 1);
      ssh_mprz_mul_2exp(ret, ret, m->z2prec_bits);
      return;
    }
  ssh_mprz_set_ui(ret, 0);
}

void ssh_mprzm_init(SshMPIntMod op, SshMPIntIdealConst m)
{
  memset(op, 0, sizeof(*op));
  op->isnan = FALSE;
  op->nankind = 0;
  op->m = m;

  if (m == NULL)
    {
      ssh_mprzm_makenan(op, SSH_MPRZM_NAN_ENOMEM);
      return;
    }

  if (m->d1)
    ssh_mpmzm_init(&op->v1, &m->mideal);
  if (m->d2)
    ssh_mp2az_init_with_prec(&op->v2, m->z2prec_n);

  ssh_mprzm_checknan(op);
}

void ssh_mprzm_init_inherit(SshMPIntMod op1, SshMPIntModConst op2)
{
  if (ssh_mprzm_isnan(op2))
    {
      op1->isnan = TRUE;
      op1->nankind = op2->nankind;
      op1->m = NULL;
      return;
    }

  memset(op1, 0, sizeof(*op1));
  op1->isnan = FALSE;
  op1->nankind = 0;
  op1->m = op2->m;

  if (op2->m->d1)
      ssh_mpmzm_init(&op1->v1, &op2->m->mideal);
  if (op2->m->d2)
      ssh_mp2az_init_with_prec(&op1->v2, op2->m->z2prec_n);

  ssh_mprzm_checknan(op1);
}

SshMPIntIdealConst ssh_mprzm_get_ideal(SshMPIntModConst op)
{
  return op->m;
}

void ssh_mprzm_clear(SshMPIntMod op)
{
  if (!ssh_mprzm_isnan(op))
    {
      if (op->m->d1)
        ssh_mpmzm_clear(&op->v1);
      if (op->m->d2)
        ssh_mp2az_clear(&op->v2);
      op->m  = NULL;
    }

  op->isnan = FALSE;
  op->nankind = 0;
  memset(op, 0, sizeof(*op));
}

void ssh_mprzm_set(SshMPIntMod ret, SshMPIntModConst op)
{
  if (ret == op)
    return;

  if (ssh_mprzm_nanresult1(ret, op))
    return;

  if (op->m->d1)
    ssh_mpmzm_set(&ret->v1, &op->v1);
  if (op->m->d2)
    ssh_mp2az_set(&ret->v2, &op->v2);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_set_mprz(SshMPIntMod ret, SshMPIntegerConst op)
{
  if (ssh_mprzm_isnan(ret))
    return;

  if (ssh_mprz_isnan(op))
    {
      ssh_mprzm_makenan(ret, op->nankind);
      return;
    }

  if (ret->m->d1)
    ssh_mpmzm_set_mprz(&ret->v1, op);
  if (ret->m->d2)
    ssh_mp2az_set_mprz(&ret->v2, op);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_set_ui(SshMPIntMod ret, SshWord u)
{
  if (ssh_mprzm_isnan(ret))
    return;

  if (ret->m->d1)
    ssh_mpmzm_set_ui(&ret->v1, u);
  if (ret->m->d2)
    ssh_mp2az_set_ui(&ret->v2, u);

  ssh_mprzm_checknan(ret);
}

void ssh_mprz_set_mprzm(SshMPInteger ret, SshMPIntModConst op)
{
  SshMPIntegerStruct a, b, k,l;

  if (ssh_mprzm_isnan(op))
    {
      ssh_mprz_makenan(ret, op->nankind);
      return;
    }

  ssh_mprz_init(&a);
  ssh_mprz_init(&b);
  ssh_mprz_init(&k);
  ssh_mprz_init(&l);

  ssh_mprz_set_ui(&a, 0);
  ssh_mprz_set_ui(&b, 0);

  if (op->m->d1)
    {
      ssh_mprz_set_mpmzm(&a, &op->v1);
    }
  if (op->m->d2)
    {
      ssh_mprz_set_mp2az(&b, &op->v2);
      ssh_mprz_mod_2exp(&b, &b, op->m->z2prec_bits);
    }

  if (op->m->d1 && op->m->d2)
    {
      /* CRT: compute x = a.2^n.2^{-n} + b.q.q^{-1}.
       */

      ssh_mprz_mul_2exp(&k, &a, op->m->z2prec_bits);
      ssh_mprz_mul(&k, &k, &op->m->i1);

      ssh_mprz_set_mpmzm_ideal(&a, &op->m->mideal);
      ssh_mprz_mul(&l, &a, &op->m->i2);
      ssh_mprz_mul(&l, &l, &b);

      ssh_mprz_add(&l, &l, &k);
      ssh_mprz_mul_2exp(&a, &a, op->m->z2prec_bits);
      ssh_mprz_mod(ret, &l, &a);
    }
  else
    {
      if (op->m->d1)
        ssh_mprz_set(ret, &a);
      else if (op->m->d2)
        ssh_mprz_set(ret, &b);
      else
        ssh_mprz_set_ui(ret, 0);
    }

  ssh_mprz_clear(&a);
  ssh_mprz_clear(&b);
  ssh_mprz_clear(&k);
  ssh_mprz_clear(&l);
}

/* This is a simple wrapper but rather useful in many occasions. */
int ssh_mprzm_cmp(SshMPIntModConst op1,
                  SshMPIntModConst op2)
{
  int rv1, rv2;

  /* Two NaNs are unequal, and a NaN is not equal to any IntMod. */
  if (ssh_mprzm_isnan(op1) || ssh_mprzm_isnan(op2))
    return 1;

  rv1 = rv2 = 0;
  if (op1->m->d1)
    rv1 = ssh_mpmzm_cmp(&op1->v1, &op2->v1);
  if (op2->m->d2)
    rv2 = (ssh_mp2az_dist(&op1->v2, &op2->v2) ==
           op1->m->z2prec_n * SSH_WORD_BITS) ? 0 : -1;
  return (rv1 == 0 && rv2 == 0) ? 0 : -1;
}

int ssh_mprzm_cmp_ui(SshMPIntModConst op, SshWord u)
{
  int rv1, rv2;

  if (ssh_mprzm_isnan(op))
    return 1;

  rv1 = rv2 = 0;
  if (op->m->d1)
    rv1 = ssh_mpmzm_cmp_ui(&op->v1, u);
  if (op->m->d2)
    rv2 = (ssh_mp2az_dist_ui(&op->v2, u) == op->v2.n * SSH_WORD_BITS) ? 0 : -1;
  return (rv1 == 0 && rv2 == 0) ? 0 : -1;
}


void ssh_mprzm_add(SshMPIntMod ret, SshMPIntModConst op1,
                   SshMPIntModConst op2)
{
  if (ssh_mprzm_nanresult2(ret, op1, op2))
    return;

  if (ret->m->d1)
    ssh_mpmzm_add(&ret->v1, &op1->v1, &op2->v1);
  if (ret->m->d2)
    ssh_mp2az_add(&ret->v2, &op1->v2, &op2->v2);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_sub(SshMPIntMod ret, SshMPIntModConst op1,
                   SshMPIntModConst op2)
{
  if (ssh_mprzm_nanresult2(ret, op1, op2))
    return;

  if (ret->m->d1)
    ssh_mpmzm_sub(&ret->v1, &op1->v1, &op2->v1);
  if (ret->m->d2)
    ssh_mp2az_sub(&ret->v2, &op1->v2, &op2->v2);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_mul(SshMPIntMod ret, SshMPIntModConst op1,
                   SshMPIntModConst op2)
{
  if (ssh_mprzm_nanresult2(ret, op1, op2))
    return;

  if (ret->m->d1)
    ssh_mpmzm_mul(&ret->v1, &op1->v1, &op2->v1);
  if (ret->m->d2)
    ssh_mp2az_mul(&ret->v2, &op1->v2, &op2->v2);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_mul_ui(SshMPIntMod ret, SshMPIntModConst op,
                      SshWord u)
{
  if (ssh_mprzm_nanresult1(ret, op))
    return;

  if (ret->m->d1)
    ssh_mpmzm_mul_ui(&ret->v1, &op->v1, u);
  if (ret->m->d2)
    ssh_mp2az_mul_ui(&ret->v2, &op->v2, u);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_square(SshMPIntMod ret, SshMPIntModConst op)
{
  if (ssh_mprzm_nanresult1(ret, op))
    return;

  if (ret->m->d1)
    ssh_mpmzm_square(&ret->v1, &op->v1);
  if (ret->m->d2)
    ssh_mp2az_square(&ret->v2, &op->v2);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_mul_2exp(SshMPIntMod ret, SshMPIntModConst op,
                        unsigned int e)
{
  if (ssh_mprzm_nanresult1(ret, op))
    return;

  if (ret->m->d1)
    ssh_mpmzm_mul_2exp(&ret->v1, &op->v1, e);
  if (ret->m->d2)
    ssh_mp2az_mul_2exp(&ret->v2, &op->v2, e);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_div_2exp(SshMPIntMod ret, SshMPIntModConst op,
                        unsigned int e)
{
  if (ssh_mprzm_nanresult1(ret, op))
    return;

  if (ret->m->d1)
    ssh_mpmzm_div_2exp(&ret->v1, &op->v1, e);
  if (ret->m->d2)
    ssh_mp2az_div_2exp(&ret->v2, &op->v2, e);

  ssh_mprzm_checknan(ret);
}

Boolean ssh_mprzm_invert(SshMPIntMod ret, SshMPIntModConst op)
{
  if (ssh_mprzm_nanresult1(ret, op))
    return FALSE;

  if (ret->m->d1 && (ssh_mpmzm_invert(&ret->v1, &op->v1) == FALSE))
    {
      ssh_mprzm_checknan(ret);
      return FALSE;
    }

  if (ret->m->d2 && (ssh_mp2az_invert(&ret->v2, &op->v2) == FALSE))
    {
      ssh_mprzm_checknan(ret);
      return FALSE;
    }

  return TRUE;
}

Boolean ssh_mprzm_sqrt(SshMPIntMod ret, SshMPIntModConst op)
{
  if (ssh_mprzm_nanresult1(ret, op))
    return FALSE;

  if (ret->m->primeideal == FALSE)
    return FALSE;

  if (ret->m->d1 && (ssh_mpmzm_sqrt(&ret->v1, &op->v1) == FALSE))
    {
      ssh_mprzm_checknan(ret);
      return FALSE;
    }

  if (ret->m->d2 && (ssh_mp2az_sqrt(&ret->v2, &op->v2) == FALSE))
    {
      ssh_mprzm_checknan(ret);
      return FALSE;
    }

  return TRUE;
}

void ssh_mprzm_pow(SshMPIntMod ret, SshMPIntModConst g, SshMPIntegerConst e)
{
  SshMPIntModStruct temp, x;
  unsigned int table_bits, table_size;
  SshMPIntMod table;
  unsigned int bits, i, j, mask, end_square, first;
  unsigned int tab[] = { 24, 88, 277, 798, 2173, 5678, 14373, 0 };

  if (ssh_mprzm_nanresult1(ret, g))
    return;

  if (ssh_mprz_isnan(e))
    {
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_ENOMEM);
      return;
    }

  /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e, 0) == 0)
    {
      ssh_mprzm_set_ui(ret, 1);
      return;
    }

  if (ssh_mprz_cmp_ui(e, 1) == 0)
    {
      ssh_mprzm_set(ret, g);
      return;
    }

  ssh_mprzm_init_inherit(&temp, ret);
  ssh_mprzm_init_inherit(&x,    ret);

  /* Initialize the generator. */
  ssh_mprzm_set(&x, g);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e->v, e->n);

  /* Select a reasonable window size. */
  for (i = 0; tab[i]; i++)
    {
      if (bits < tab[i])
        break;
    }
  table_bits = i + 2;
  table_size = ((SshWord)1 << (table_bits - 1));

  /* Allocate the table. */
  table = ssh_malloc(sizeof(SshMPIntModStruct) * table_size);
  if (!table)
    {
      ssh_mprzm_clear(&temp);
      ssh_mprzm_clear(&x);
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_ENOMEM);
      return;
    }


  /* Start computing the table. */
  ssh_mprzm_init_inherit(&table[0], ret);
  ssh_mprzm_set(&table[0], &x);

  /* Compute g^2 into temp. */
  ssh_mprzm_set(&temp, &table[0]);
  ssh_mprzm_square(&temp, &temp);

  /* Compute the small table of powers. */
  for (i = 1; i < table_size; i++)
    {
      ssh_mprzm_init_inherit(&table[i], ret);
      ssh_mprzm_mul(&table[i], &table[i - 1], &temp);
    }

  for (first = 1, i = bits; i;)
    {
      for (j = 0, mask = 0; j < table_bits && i; j++, i--)
        {
          mask <<= 1;
          mask |= ssh_mprz_get_bit(e, i - 1);
        }

      for (end_square = 0; (mask & 0x1) == 0;)
        {
          mask >>= 1;
          end_square++;
        }

      if (!first)
        {
          /* First square. */
          for (j = mask; j; j >>= 1)
            ssh_mprzm_square(&temp, &temp);

          ssh_mprzm_mul(&temp, &temp, &table[(mask - 1)/2]);
        }
      else
        {
          ssh_mprzm_set(&temp, &table[(mask - 1)/2]);
          first = 0;
        }

      /* Get rid of zero bits... */
      while (end_square)
        {
          ssh_mprzm_square(&temp, &temp);
          end_square--;
        }

      while (i && ssh_mprz_get_bit(e, i - 1) == 0)
        {
          ssh_mprzm_square(&temp, &temp);
          i--;
        }
    }

  /* Clear and free the table. */
  for (i = 0; i < table_size; i++)
    ssh_mprzm_clear(&table[i]);
  ssh_free(table);

  ssh_mprzm_set(ret, &temp);

  ssh_mprzm_clear(&temp);
  ssh_mprzm_clear(&x);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_pow_gg(SshMPIntMod ret,
                      SshMPIntModConst g1, SshMPIntegerConst e1,
                      SshMPIntModConst g2, SshMPIntegerConst e2)
{
  SshMPIntModStruct temp, x1, x2, x3;
  unsigned int bits, i;

  if (ssh_mprzm_nanresult2(ret, g1, g2))
    return;

  if (ssh_mprz_isnan(e1) || ssh_mprz_isnan(e2))
    {
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_ENOMEM);
      return;
    }
      /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e1, 0) == 0)
    {
      ssh_mprzm_pow(ret, g2, e2);
      return;
    }
  if (ssh_mprz_cmp_ui(e2, 0) == 0)
    {
      ssh_mprzm_pow(ret, g1, e1);
      return;
    }

  ssh_mprzm_init_inherit(&temp, ret);
  ssh_mprzm_init_inherit(&x1,   ret);
  ssh_mprzm_init_inherit(&x2,   ret);
  ssh_mprzm_init_inherit(&x3,   ret);

  ssh_mprzm_set(&x1, g1);
  ssh_mprzm_set(&x2, g2);
  ssh_mprzm_mul(&x3, &x1, &x2);
  ssh_mprzm_set_ui(&temp, 1);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e2->v, e2->n);
  i = ssh_mpk_size_in_bits(e1->v, e1->n);
  if (i > bits)
    bits = i;

  for (i = bits; i; i--)
    {
      int k;
      ssh_mprzm_square(&temp, &temp);

      k  = ssh_mprz_get_bit(e1, i - 1);
      k |= ssh_mprz_get_bit(e2, i - 1) << 1;

      switch (k)
        {
        case 0:
          break;
        case 1:
          ssh_mprzm_mul(&temp, &temp, &x1);
          break;
        case 2:
          ssh_mprzm_mul(&temp, &temp, &x2);
          break;
        case 3:
          ssh_mprzm_mul(&temp, &temp, &x3);
          break;
        }
    }

  ssh_mprzm_set(ret, &temp);

  ssh_mprzm_clear(&temp);
  ssh_mprzm_clear(&x1);
  ssh_mprzm_clear(&x2);
  ssh_mprzm_clear(&x3);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_pow_ui_g(SshMPIntMod ret, SshWord g, SshMPIntegerConst e)
{
  SshMPIntModStruct temp, x;
  unsigned int bits, i;

  if (ssh_mprz_isnan(e))
    {
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_ENOMEM);
      return;
    }

  /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e, 0) == 0)
    {
      ssh_mprzm_set_ui(ret, 1);
      return;
    }

  if (ssh_mprz_cmp_ui(e, 1) == 0)
    {
      ssh_mprzm_set_ui(ret, g);
      return;
    }

  ssh_mprzm_init_inherit(&temp, ret);
  ssh_mprzm_init_inherit(&x,    ret);

  ssh_mprzm_set_ui(&x, g);
  ssh_mprzm_set(&temp, &x);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mprzm_square(&temp, &temp);
      if (ssh_mprz_get_bit(e, i - 1))
        ssh_mprzm_mul_ui(&temp, &temp, g);
    }

  ssh_mprzm_set(ret, &temp);
  ssh_mprzm_clear(&temp);
  ssh_mprzm_clear(&x);

  ssh_mprzm_checknan(ret);
}

void ssh_mprzm_pow_ui_exp(SshMPIntMod ret,
                          SshMPIntModConst g, SshWord e)
{
  SshMPIntModStruct t;

  if (ssh_mprzm_nanresult1(ret, g))
    return;

  /* Trivial cases, these are given here to make sure that this quite
     efficient way to, say, square a value. */
  switch (e)
    {
    case 0:
      ssh_mprzm_set_ui(ret, 1);
      return;
    case 1:
      ssh_mprzm_set(ret, g);
      return;
    case 2:
      ssh_mprzm_square(ret, g);
      return;
    case 3:
      ssh_mprzm_init_inherit(&t, ret);
      ssh_mprzm_square(&t, g);
      ssh_mprzm_mul(ret, &t, g);
      ssh_mprzm_clear(&t);
      return;
    case 4:
      ssh_mprzm_square(ret, g);
      ssh_mprzm_square(ret, ret);
      return;
    case 5:
      ssh_mprzm_init_inherit(&t, ret);
      ssh_mprzm_square(&t, g);
      ssh_mprzm_square(&t, &t);
      ssh_mprzm_mul(ret, &t, g);
      ssh_mprzm_clear(&t);
      break;
    default:
      /* Something more complicated. */
      break;
    }

  ssh_mprzm_init_inherit(&t, ret);
  ssh_mprzm_set(&t, g);
  ssh_mprzm_set_ui(ret, 1);

  /* We want to do the computation as fast as possible, assuming that
     small apprear most often. Thus we remove most of the overhead
     of book keeping by going upwards (rather than downwards as
     we have otherwise done). */
  while (e)
    {
      if (e & 1)
        ssh_mprzm_mul(ret, ret, &t);
      e >>= 1; if (!e) break;
      ssh_mprzm_square(&t, &t);
    }

  ssh_mprzm_clear(&t);

  ssh_mprzm_checknan(ret);
}

Boolean ssh_mprzm_pow_precomp_init(SshMPIntModPowPrecomp precomp,
                                   SshMPIntModConst g,
                                   SshMPIntegerConst order)
{
  SshMPIntModStruct x;
  SshMPIntMod       table;
  unsigned int k_bits, bits, i, id;

  /* Clean the precomputation structure and allocate tables. Done here
     to make rest of the code cleaner. */
  memset(precomp, 0, sizeof(*precomp));
  precomp->table_size = ((unsigned int)1 << SSH_MPRZM_POW_PRECOMP_K) - 1;
  precomp->table = ssh_calloc(1,
                              sizeof(SshMPIntModStruct) * precomp->table_size);

  table = ssh_calloc(1, sizeof(SshMPIntModStruct) * SSH_MPRZM_POW_PRECOMP_K);

  if (table == NULL || precomp->table == NULL)
    {
      ssh_free(table);
      ssh_free(precomp->table);
      precomp->table = NULL;
      return FALSE;
    }

  /* Bound on the order. */
  ssh_mprz_init(&precomp->order);
  ssh_mprz_set(&precomp->order, order);

  /* Compute the division for the table powers. */
  bits = ssh_mpk_size_in_bits(order->v, order->n);

  /* Now make a division into k values. */
  k_bits = (bits + SSH_MPRZM_POW_PRECOMP_K-1) / SSH_MPRZM_POW_PRECOMP_K;
  precomp->table_bits = k_bits;

  /* Now compute all the k powers. */
  for (i = 0; i < SSH_MPRZM_POW_PRECOMP_K; i++)
    ssh_mprzm_init_inherit(&table[i], g);

  /* g^2^0 */
  ssh_mprzm_init_inherit(&x, g);
  ssh_mprzm_set(&x, g);
  ssh_mprzm_set(&table[0], &x);

  /* Compute g^2^(i*k_bits). */
  for (id = 1; id < SSH_MPRZM_POW_PRECOMP_K; id++)
    {
      /* Compute x^2^k_bits. */
      for (i = 0; i < k_bits; i++)
        ssh_mprzm_square(&x, &x);
      ssh_mprzm_set(&table[id], &x);
    }

  /* Now produce a table of all combinations.

     Remark. This takes quite a lot of space, but should be worth
     it. This could be also done in the actual exponentiation routine,
     but if the number of division points is small then we don't
     perhaps spend too much space. */
  for (i = 0; i < precomp->table_size; i++)
    ssh_mprzm_init_inherit(&precomp->table[i], g);

  for (i = 0; i < precomp->table_size; i++)
    {
      unsigned int mask = i + 1;
      unsigned int s, r;

      /* Determine the maximum mask spanning the index. */
      for (s = 0;
           (mask ^ ((((unsigned int)1 << s)-1) & mask)) != 0;
           s++)
        ;

      /* Now take one smaller. */
      r = (mask & (((unsigned int)1 << (s - 1))-1));

      /* Compute the current mask. */
      if (r != 0)
        ssh_mprzm_mul(&precomp->table[i],
                      &table[s-1], &precomp->table[r-1]);
      else
        ssh_mprzm_set(&precomp->table[i], &table[s-1]);
    }

  /* Free the temporary variables. */
  for (i = 0; i < SSH_MPRZM_POW_PRECOMP_K; i++)
    ssh_mprzm_clear(&table[i]);
  ssh_free(table);
  ssh_mprzm_clear(&x);
  return TRUE;
}

void ssh_mprzm_pow_precomp_clear(SshMPIntModPowPrecomp precomp)
{
  unsigned int i;

  for (i = 0; i < precomp->table_size; i++)
    ssh_mprzm_clear(&precomp->table[i]);
  ssh_mprz_clear(&precomp->order);
  ssh_free(precomp->table);
  memset(precomp, 0, sizeof(*precomp));
}

void ssh_mprzm_pow_precomp(SshMPIntMod ret, SshMPIntegerConst e,
                           SshMPIntModPowPrecompConst precomp)
{
  SshMPIntModStruct x;
  SshMPIntMod table;
  SshMPIntMod g;
  SshMPIntegerStruct re;
  unsigned int i;
  unsigned int bits[SSH_MPRZM_POW_PRECOMP_K];

  if (precomp->table == NULL)
    {
      ssh_mprzm_makenan(ret, SSH_MPRZM_NAN_ENOMEM);
      return;
    }

  /* Make a convenient change of variable. */
  g = &precomp->table[0];

  /* Us shorthand notation. */
  table = precomp->table;

  /* Reduce the exponent. */
  ssh_mprz_init(&re);
  ssh_mprz_mod(&re, e, &precomp->order);

  /* Trivial case. */
  if (ssh_mprz_cmp_ui(&re, 0) == 0)
    {
      ssh_mprzm_set_ui(ret, 1);
      return;
    }
  if (ssh_mprz_cmp_ui(&re, 1) == 0)
    {
      ssh_mprzm_set(ret, &table[0]);
      return;
    }

  /* Initialize. */
  ssh_mprzm_init_inherit(&x, g);
  ssh_mprzm_set_ui(&x, 1);

  /* Now get the number of bits. */
  bits[0] = precomp->table_bits-1;
  for (i = 1; i < SSH_MPRZM_POW_PRECOMP_K; i++)
    bits[i] = bits[i-1] + precomp->table_bits;

  /* Now run through the bits. */
  for (i = 0; i < precomp->table_bits; i++)
    {
      unsigned int j, mask;

      /* Square. */
      ssh_mprzm_square(&x, &x);

      for (j = SSH_MPRZM_POW_PRECOMP_K, mask = 0; j; j--)
        {
          mask <<= 1;
          mask |= ssh_mprz_get_bit(&re, bits[j-1]-i);
        }
      if (mask == 0)
        continue;

      ssh_mprzm_mul(&x, &x, &table[mask - 1]);
    }

  /* Finished. */
  ssh_mprzm_set(ret, &x);
  ssh_mprzm_clear(&x);
  ssh_mprz_clear(&re);

 return;
}

SshMPIntIdealConst
ssh_mprzm_pow_precomp_get_ideal(SshMPIntModPowPrecompConst precomp)
{
  return ssh_mprzm_get_ideal(&precomp->table[0]);
}


#if 0
/* Simple dumping code for monty values. */
void ssh_mprzm_dump(SshMPIntModConst op)
{
  int i;

  printf("ssh_mprzm_dump: \n  ");
  for (i = op->n; i; i--)
#if SIZEOF_LONG==4
    printf("%08lx ", op->v[i-1]);
#else
    printf("%16lx ", op->v[i-1]);
#endif /* SIZEOF_LONG==4 */

  printf("\n (0 ");
  for (i = 0; i < op->n; i++)
    printf("+ %lu*2^%u", op->v[i], i*32);
  printf(")\n");
}
#else
void ssh_mprzm_dump(SshMPIntModConst op)
{
  /* Do nothing. */
}
#endif


/* End. */
#endif /* SSHDIST_MATH */
