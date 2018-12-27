/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMP2Adic"

#ifdef SSHDIST_MATH

Boolean ssh_mp2az_isnan(SshMP2AdicIntegerConst op)
{
  return (op->n == 0 && op->isnan);
}

void ssh_mp2az_makenan(SshMP2AdicInteger op, unsigned int kind)
{
  if (op->v)
    {
      memset(op->v, 0, sizeof(SshWord) * op->m);
      ssh_free(op->v);
      op->v = NULL;
    }
  op->n = 0;
  op->m = 0;
  op->isnan = TRUE;
  op->nankind = kind;
}

Boolean ssh_mp2az_nanresult1(SshMP2AdicInteger ret,
                             SshMP2AdicIntegerConst op)
{
  if (ssh_mp2az_isnan(ret))
    return TRUE;

  if (ssh_mp2az_isnan(op))
    {
      ssh_mp2az_makenan(ret, op->nankind);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_mp2az_nanresult2(SshMP2AdicInteger ret,
                             SshMP2AdicIntegerConst op1,
                             SshMP2AdicIntegerConst op2)
{
  if (ssh_mp2az_isnan(ret))
    return TRUE;

  if (ssh_mp2az_isnan(op1))
    {
      ssh_mp2az_makenan(ret, op1->nankind);
      return TRUE;
    }

  if (ssh_mp2az_isnan(op2))
    {
      ssh_mp2az_makenan(ret, op2->nankind);
      return TRUE;
    }

  return FALSE;
}

void ssh_mp2az_init_raw(SshMP2AdicInteger op)
{
  op->m = (SSH_MP2AZ_DEF_PREC + SSH_WORD_BITS - 1) / SSH_WORD_BITS;
  op->n = op->m;
  op->v = NULL;
  op->isnan = FALSE;
  op->nankind = 0;
}

void ssh_mp2az_set_prec(SshMP2AdicInteger op, unsigned int prec)
{
  /* This is needed since we don't always want to unset NaN values. */
  if (ssh_mp2az_isnan(op))
    return;

  if (op->v == NULL)
    {
      op->v = ssh_malloc(sizeof(SshWord) * prec);
      if (!op->v)
        goto failure;
      ssh_mpk_memzero(op->v, prec);
      op->m = prec;
      op->n = prec;
      return;
    }

  if (op->m < prec)
    {
      SshWord *nv;

      if ((nv = ssh_malloc(sizeof(SshWord) * prec)) != NULL)
        memcpy(nv, op->v, sizeof(SshWord) * op->m);

      memset(op->v, 0, sizeof(SshWord) * op->m);
      ssh_free(op->v);
      op->v = nv;

      if (!op->v)
        goto failure;
      op->m = prec;
    }

  if (op->n < prec)
    ssh_mpk_memzero(op->v + op->n, prec - op->n);
  op->n = prec;
  return;

 failure:
  op->n = 0;
  op->m = 0;
  op->isnan = TRUE;
  op->nankind = SSH_MP2AZ_NAN_ENOMEM;
}

unsigned int ssh_mp2az_get_prec(SshMP2AdicIntegerConst op)
{
  return op->n;
}

void ssh_mp2az_init(SshMP2AdicInteger op)
{
  ssh_mp2az_init_raw(op);
  ssh_mp2az_set_prec(op, op->n);
}

void ssh_mp2az_init_with_prec(SshMP2AdicInteger op, unsigned int prec)
{
  ssh_mp2az_init_raw(op);
  ssh_mp2az_set_prec(op, prec);
}

void ssh_mp2az_init_inherit_prec(SshMP2AdicInteger op,
                                 SshMP2AdicIntegerConst prec)
{
  if (ssh_mp2az_isnan(prec))
    {
      op->v = NULL;
      op->n = 0;
      op->m = 0;
      op->isnan = TRUE;
      op->nankind = prec->nankind;
      return;
    }

  ssh_mp2az_init_raw(op);
  ssh_mp2az_set_prec(op, prec->n);
}

void ssh_mp2az_clear(SshMP2AdicInteger op)
{
  if (!ssh_mp2az_isnan(op))
    {
      /* Zeroize and free */
      memset(op->v, 0, sizeof(SshWord) * op->m);
      ssh_free(op->v);
    }

  op->n = 0;
  op->m = 0;
  op->isnan = FALSE;
  op->nankind = 0;
  op->v = NULL;
}

void ssh_mp2az_set_mprz(SshMP2AdicInteger ret, SshMPIntegerConst op)
{
  unsigned int n;

  if (ssh_mp2az_isnan(ret))
    return;

  if (ssh_mprz_isnan(op))
    {
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      return;
    }

  if (op->n < ret->n)
    n = op->n;
  else
    n = ret->n;

  ssh_mpk_memcopy(ret->v, op->v, n);
  ssh_mpk_memzero(ret->v + n, ret->n - n);
  /* Handle the sign. */
  if (SSH_MP_GET_SIGN(op))
    ssh_mpmk_2adic_neg(ret->v, ret->v, ret->n);
}

void ssh_mprz_set_mp2az(SshMPInteger ret, SshMP2AdicIntegerConst op)
{
  if (ssh_mp2az_isnan(op))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  (void)ssh_mprz_realloc(ret, op->n);
  if (!ssh_mprz_isnan(ret))
    {
      ssh_mpk_memcopy(ret->v, op->v, op->n);
      ret->n = op->n;
      SSH_MP_NO_SIGN(ret);
    }
}

void ssh_mp2az_set_ui(SshMP2AdicInteger ret, SshWord ui)
{
  if (ssh_mp2az_isnan(ret))
    return;

  ret->v[0] = ui;
  ssh_mpk_memzero(ret->v + 1, ret->n - 1);
}

SshWord ssh_mp2az_get_ui(SshMP2AdicIntegerConst op)
{
  if (op->n == 0)
    return 0;
  return op->v[0];
}

void ssh_mp2az_set(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op)
{
  unsigned int n;
  if (ret == op)
    return;

  if (ssh_mp2az_nanresult1(ret, op))
    return;

  if (ret->n > op->n)
    n = op->n;
  else
    n = ret->n;
  ssh_mpk_memcopy(ret->v, op->v, n);
  ssh_mpk_memzero(ret->v + n, ret->n - n);
}

int ssh_mp2az_dist(SshMP2AdicIntegerConst op1, SshMP2AdicIntegerConst op2)
{
  unsigned int i, k;

  /* A negative return value indicates failure. */
  if (ssh_mp2az_isnan(op1) || ssh_mp2az_isnan(op2))
    return -1;

  for (i = 0, k = 0; i < op1->n && i < op2->n; i++, k += SSH_WORD_BITS)
    if (op1->v[i] != op2->v[i])
      {
        k += ssh_mpk_count_trailing_zeros(op1->v[i] ^ op2->v[i]);
        break;
      }
  return k;
}

int ssh_mp2az_dist_ui(SshMP2AdicIntegerConst op, SshWord ui)
{
  if (ssh_mp2az_isnan(op))
    return -1;

  if (op->n == 0)
    return 0;
  if (op->v[0] == ui)
    {
      if (op->n == 1)
        return SSH_WORD_BITS;
      else
        {
          unsigned int i;
          for (i = 1; i < op->n; i++)
            {
              if (op->v[i] != 0)
                return i * SSH_WORD_BITS;
            }
          return op->n * SSH_WORD_BITS;
        }
    }
  return ssh_mpk_count_trailing_zeros(op->v[0] ^ ui);
}

int ssh_mp2az_norm(SshMP2AdicIntegerConst op)
{
  int i, k;

  if (ssh_mp2az_isnan(op))
    return -1;

  for (i = 0, k = 0; i < op->n; i++, k += SSH_WORD_BITS)
    if (op->v[i] != 0)
      {
        k += ssh_mpk_count_trailing_zeros(op->v[i]);
        break;
      }
  return k;
}

void ssh_mp2az_add(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                   SshMP2AdicIntegerConst op2)
{
  unsigned int prec;

  if (ssh_mp2az_nanresult2(ret, op1, op2))
    return;

  prec = ret->m;
  if (prec > op1->n)
    prec = op1->n;
  if (prec > op2->n)
    prec = op2->n;

  ssh_mpk_add(ret->v, op1->v, prec, op2->v, prec);
  ret->n = prec;
}

void ssh_mp2az_add_ui(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                      SshWord u)
{
  unsigned int prec;

  if (ssh_mp2az_nanresult1(ret, op))
    return;

  prec = ret->m;
  if (prec > op->n)
    prec = op->n;
  ssh_mpk_add_ui(ret->v, op->v, prec, u);
  ret->n = prec;
}

void ssh_mp2az_sub(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                   SshMP2AdicIntegerConst op2)
{
  unsigned int prec;

  if (ssh_mp2az_nanresult2(ret, op1, op2))
    return;

  prec = ret->m;
  if (prec > op1->n)
    prec = op1->n;
  if (prec > op2->n)
    prec = op2->n;

  ssh_mpk_sub(ret->v, op1->v, prec, op2->v, prec);
  ret->n = prec;
}

void ssh_mp2az_negate(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op)
{
  ssh_mp2az_set(ret, op);
  ssh_mpmk_2adic_neg(ret->v, ret->v, ret->n);
}

void ssh_mp2az_mul(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op1,
                   SshMP2AdicIntegerConst op2)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t;
  unsigned int t_n;

  if (ssh_mp2az_nanresult2(ret, op1, op2))
    return;

  t_n = op1->n + op2->n + 1;
  SSH_MP_WORKSPACE_ALLOC(t, t_n);
  if (!t)
    {
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      return;
    }

  ssh_mpk_memzero(t, t_n);
  if (!ssh_mpk_mul_karatsuba(t, t_n, op1->v, op1->n,
                             op2->v, op2->n, NULL, 0))
    {
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      SSH_MP_WORKSPACE_FREE(t);
      return;
    }

  while (t_n && t[t_n-1] == 0)
    t_n--;

  /* Cut the size. */
  ret->n = (op1->n < op2->n) ? op1->n : op2->n;
  if (ret->n > ret->m)
    ret->n = ret->m;
  ssh_mpk_memcopy(ret->v, t, ret->n);

  SSH_MP_WORKSPACE_FREE(t);
}

void ssh_mp2az_mul_ui(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                      SshWord u)
{
  SshMP2AdicIntegerStruct t;
  ssh_mp2az_init_with_prec(&t, op->n);
  ssh_mp2az_set_ui(&t, u);
  ssh_mp2az_mul(ret, op, &t);
  ssh_mp2az_clear(&t);
}

void ssh_mp2az_square(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t;
  unsigned int t_n;

  if (ssh_mp2az_nanresult1(ret, op))
    return;

  t_n = op->n * 2 + 2;
  SSH_MP_WORKSPACE_ALLOC(t, t_n);
  if (!t)
    {
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      return;
    }

  ssh_mpk_memzero(t, t_n);
  if (!ssh_mpk_square_karatsuba(t, t_n, op->v, op->n, NULL, 0))
    {
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      SSH_MP_WORKSPACE_FREE(t);
      return;
    }

  while (t_n && t[t_n-1] == 0)
    t_n--;

  ret->n = (op->n > ret->m) ? ret->m : op->n;
  ssh_mpk_memcopy(ret->v, t, ret->n);

  SSH_MP_WORKSPACE_FREE(t);
}

void ssh_mp2az_mul_2exp(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                        unsigned int bits)
{
  unsigned int k, t, i;

  if (ssh_mp2az_nanresult1(ret, op))
    return;

  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  if (ret->m <= k)
    {
      ssh_mpk_memzero(ret->v, ret->m);
      ret->n = ret->m;
      return;
    }

  t = ret->m - k;
  if (t > op->n)
    t = op->n;
  for (i = t; i; i--)
    ret->v[k + (i-1)] = op->v[i-1];
  ret->n = t + k;

  ssh_mpk_shift_up_bits(ret->v + k, ret->n - k, bits);
}

void ssh_mp2az_div_2exp(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op,
                        unsigned int bits)
{
  unsigned int k, t, i;

  if (ssh_mp2az_nanresult1(ret, op))
    return;

  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  if (k >= op->n)
    {
      ret->n = 0;
      return;
    }

  t = op->n - k;
  if (t > ret->m)
    t = ret->m;

  for (i = 0; i < t; i++)
    ret->v[i] = op->v[i + k];
  ret->n = t;

  ssh_mpk_shift_down_bits(ret->v, ret->n, bits);
}

Boolean ssh_mp2az_invert(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op)
{
  SshMP2AdicIntegerStruct x, y;
  SshWord v;
  unsigned int prec, max_prec;
  int dist;

  if (ssh_mp2az_nanresult1(ret, op))
    return FALSE;

  if (op->n == 0)
    {
      ret->n = 0;
      return FALSE;
    }

  if (!(op->v[0] & 1))
    return FALSE;

  max_prec = (ret->m > op->n) ? op->n : ret->m;

  /* Initialize temporary variables. */
  ssh_mp2az_init_with_prec(&x, ret->m);
  ssh_mp2az_init_with_prec(&y, ret->m);

  /* Resize. */
  prec = 1;
  ssh_mp2az_set_prec(&x, prec);
  ssh_mp2az_set_prec(&y, prec);

  /* Find quickly a good initial value. */
  v = ssh_mpmk_small_inv(op->v[0]);
  ssh_mp2az_set_ui(&x, v);

  while (1)
    {
      ssh_mp2az_mul(&y, &x, op);
      if (ssh_mp2az_isnan(&y))
        goto failure;

      dist = ssh_mp2az_dist_ui(&y, 1);
      if (dist == -1)
        goto failure;

      if ((unsigned int)dist == prec * SSH_WORD_BITS)
        {
          if (prec >= max_prec)
            break;

          /* Increase the precision. */
          prec *= 2;
          if (prec >= ret->m)
            prec = ret->m;
          ssh_mp2az_set_prec(&x, prec);
          ssh_mp2az_set_prec(&y, prec);
        }
      ssh_mp2az_negate(&y, &y);
      ssh_mp2az_add_ui(&y, &y, 2);
      ssh_mp2az_mul(&x, &x, &y);
    }

  ssh_mp2az_set_prec(ret, max_prec);
  ssh_mp2az_set(ret, &x);

  ssh_mp2az_clear(&x);
  ssh_mp2az_clear(&y);

  if (ssh_mp2az_isnan(ret))
    return FALSE;
  else
    return TRUE;

 failure:
  ssh_mp2az_clear(&x);
  ssh_mp2az_clear(&y);
  ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
  return FALSE;
}

/* This table contains non-zero when that index has such square root (plus
   one). */
const static unsigned char ssh_mp2az_sqrt_tab[64] =
{1, 2, 0, 0, 3, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0, 0,
 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 7, 0, 0, 0, 0, 14, 0, 0,
 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0};

Boolean ssh_mp2az_sqrt(SshMP2AdicInteger ret, SshMP2AdicIntegerConst op)
{
  SshMP2AdicIntegerStruct x, y, t;
  unsigned int i, bits, prec, max_prec;
  int dist;

  if (ssh_mp2az_nanresult1(ret, op))
    return FALSE;

  if (op->n == 0)
    {
      ret->n = 0;
      return TRUE;
    }

  for (i = 0; op->v[i] == 0 && i < op->n; i++)
    ;
  bits = i * SSH_WORD_BITS;
  if (i < op->n)
    bits += ssh_mpk_count_trailing_zeros(op->v[i]);

  if (bits & 1)
    return FALSE;

  ssh_mp2az_init_with_prec(&t, ret->m);
  ssh_mp2az_set(&t, op);
  ssh_mp2az_div_2exp(&t, &t, bits);

  if (ssh_mp2az_isnan(&t))
    {
      ssh_mp2az_clear(&t);
      return FALSE;
    }

  /* Check whether the square root can be computed at all. */
  if (ssh_mp2az_sqrt_tab[t.v[0] & 0x3f] == 0)
    {
      ssh_mp2az_clear(&t);
      return FALSE;
    }

  max_prec = (ret->m > op->n) ? op->n : ret->m;

  ssh_mp2az_init_with_prec(&x, ret->m);
  ssh_mp2az_init_with_prec(&y, ret->m);

  /* Resize. */
  prec = 1;
  ssh_mp2az_set_prec(&x, prec);
  ssh_mp2az_set_prec(&y, prec);

  /* Try to obtain an initial approximation of the square root. */
  ssh_mp2az_set_ui(&x, ssh_mp2az_sqrt_tab[t.v[0] & 0x3f] - 1);

  while (1)
    {
      ssh_mp2az_mul(&y, &x, &x);
      if (ssh_mp2az_isnan(&y))
        goto failure;

      dist = ssh_mp2az_dist_ui(&y, 1);
      if (dist == -1)
        goto failure;

      if ((unsigned int)dist == prec * SSH_WORD_BITS)
        {
          if (prec >= max_prec)
            break;
          prec *= 2;
          if (prec > ret->n)
            prec = ret->n;

          ssh_mp2az_set_prec(&x, prec);
          ssh_mp2az_set_prec(&y, prec);
        }

      ssh_mp2az_invert(&x, &x);
      ssh_mp2az_add(&y, &y, &t);
      ssh_mp2az_div_2exp(&y, &y, 1);
      ssh_mp2az_mul(&x, &y, &x);
    }

  ssh_mp2az_mul_2exp(&x, &x, bits/2);
  ssh_mp2az_set_prec(ret, max_prec);
  ssh_mp2az_set(ret, &x);

  ssh_mp2az_clear(&x);
  ssh_mp2az_clear(&y);
  ssh_mp2az_clear(&t);

  if (ssh_mp2az_isnan(ret))
    return FALSE;
  else
    return TRUE;

 failure:
  ssh_mp2az_clear(&x);
  ssh_mp2az_clear(&y);
  ssh_mp2az_clear(&t);
  ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
  return FALSE;
}


void ssh_mp2az_pow(SshMP2AdicInteger ret, SshMP2AdicIntegerConst g,
                   SshMPIntegerConst e)
{
  SshMP2AdicIntegerStruct temp, x;
  unsigned int table_bits, table_size;
  SshMP2AdicInteger table;
  unsigned int bits, i, j, mask, end_square, first;
  unsigned int tab[] =
  { 24, 88, 277, 798, 2173, 5678, 14373, 0 };

  if (ssh_mp2az_nanresult1(ret, g))
    return;

  if (ssh_mprz_isnan(e))
    {
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      return;
    }

  /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e, 0) == 0)
    {
      ssh_mp2az_set_ui(ret, 1);
      return;
    }

  if (ssh_mprz_cmp_ui(e, 1) == 0)
    {
      ssh_mp2az_set(ret, g);
      return;
    }

  ssh_mp2az_init_inherit_prec(&temp, ret);
  ssh_mp2az_init_inherit_prec(&x,    ret);

  /* Initialize the generator. */
  ssh_mp2az_set(&x, g);

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
  table = ssh_malloc(sizeof(SshMP2AdicIntegerStruct) * table_size);
  if (!table)
    {
      ssh_mp2az_clear(&temp);
      ssh_mp2az_clear(&x);
      ssh_mp2az_makenan(ret, SSH_MP2AZ_NAN_ENOMEM);
      return;
    }

  /* Start computing the table. */
  ssh_mp2az_init_inherit_prec(&table[0], ret);
  ssh_mp2az_set(&table[0], &x);

  /* Compute g^2 into temp. */
  ssh_mp2az_set(&temp, &table[0]);
  ssh_mp2az_square(&temp, &temp);

  /* Compute the small table of powers. */
  for (i = 1; i < table_size; i++)
    {
      ssh_mp2az_init_inherit_prec(&table[i], ret);
      ssh_mp2az_mul(&table[i], &table[i - 1], &temp);
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
            ssh_mp2az_square(&temp, &temp);

          ssh_mp2az_mul(&temp, &temp, &table[(mask - 1)/2]);
        }
      else
        {
          ssh_mp2az_set(&temp, &table[(mask - 1)/2]);
          first = 0;
        }

      /* Get rid of zero bits... */
      while (end_square)
        {
          ssh_mp2az_square(&temp, &temp);
          end_square--;
        }

      while (i && ssh_mprz_get_bit(e, i - 1) == 0)
        {
          ssh_mp2az_square(&temp, &temp);
          i--;
        }
    }

  /* Clear and free the table. */
  for (i = 0; i < table_size; i++)
    ssh_mp2az_clear(&table[i]);
  ssh_free(table);

  ssh_mp2az_set(ret, &temp);

  ssh_mp2az_clear(&temp);
  ssh_mp2az_clear(&x);
}

/* sshmp-2adic.c */
#endif /* SSHDIST_MATH */
