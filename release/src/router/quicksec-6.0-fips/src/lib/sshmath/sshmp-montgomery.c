/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMPMont"

#ifdef SSHDIST_MATH
/* NaN routines. */

Boolean ssh_mpmzm_isnan(SshMPMontIntModConst op)
{
  return (op->m == NULL && op->n == 0 && op->isnan);
}

void ssh_mpmzm_makenan(SshMPMontIntMod op, unsigned int kind)
{
  if (op->v)
    ssh_free(op->v);

  memset(op, 0, sizeof(*op));
  op->v = NULL;
  op->n = 0;
  op->m = NULL;
  op->isnan = TRUE;
  op->nankind = kind;
}

Boolean ssh_mpmzm_nanresult1(SshMPMontIntMod ret, SshMPMontIntModConst op)
{
  if (ssh_mpmzm_isnan(ret))
    return TRUE;

  if (ssh_mpmzm_isnan(op))
    {
      ssh_mpmzm_makenan(ret, op->nankind);
      return TRUE;
    }

  if (ret->m != op->m)
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_IDEAL);
      return TRUE;
    }

  return FALSE;
}

Boolean ssh_mpmzm_nanresult2(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                             SshMPMontIntModConst op2)
{
  if (ssh_mpmzm_isnan(ret))
    return TRUE;

  if (ssh_mpmzm_isnan(op1))
    {
      ssh_mpmzm_makenan(ret, op1->nankind);
      return TRUE;
    }

  if (ssh_mpmzm_isnan(op2))
    {
      ssh_mpmzm_makenan(ret, op2->nankind);
      return TRUE;
    }

  if (ret->m != op1->m || ret->m != op2->m)
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_IDEAL);
      return TRUE;
    }

  return FALSE;
}

/* Montgomery representation implementation. The modulus is required
   to be odd. */

/* Very quick initialization! */
Boolean ssh_mpmzm_init_ideal(SshMPMontIntIdeal m, SshMPIntegerConst op)
{
  unsigned int temp_n;

  /* Clean. */
  memset(m, 0, sizeof(*m));

  if (ssh_mprz_isnan(op))
    return FALSE;

  /* If op < 3 or op % 2 == 0 we cannot work in Montgomery
     representation. */
  if (ssh_mprz_cmp_ui(op, 3) < 0 || (ssh_mprz_get_ui(op) & 0x1) == 0)
    return FALSE;

#ifdef ASM_PLATFORM_OCTEON
  ssh_mpk_memcopy(m->big_mp, op->v, 3);

  ssh_mpmk_triple_inv(m->big_mp);
    {
      SshWord *p = m->big_mp;
      p[0] = ~p[0];
      p[1] = ~p[1];
      p[2] = ~p[2];

      if (++p[0] < 1)
        if (++p[1] < 1)
          ++p[2];
    }
#endif /* ASM_PLATFORM_OCTEON */

  /* Compute mp = -op^-1 (mod 2^SSH_WORD_BITS).
   */
  m->mp = SSH_WORD_NEGATE(ssh_mpmk_small_inv(op->v[0]));
  m->karatsuba_work_space   = NULL;
  m->work_space             = NULL;

  /* Set the modulus up, also in normalized form. */
  m->m = ssh_malloc(sizeof(SshWord) * (op->n + op->n));
  if (m->m == NULL)
    goto failure;

  m->d = m->m + op->n;
  m->m_n = op->n;
  ssh_mpk_memcopy(m->m, op->v, m->m_n);
  ssh_mpk_memcopy(m->d, op->v, m->m_n);
  m->shift = ssh_mpk_leading_zeros(m->d, m->m_n);
  ssh_mpk_shift_up_bits(m->d, m->m_n, m->shift);

#ifdef SSHMATH_USE_WORKSPACE
  /* Determine how much memory we want to keep in reserve as working
     space. */

  temp_n =
    ssh_mpk_square_karatsuba_needed_memory(m->m_n);

  m->karatsuba_work_space_n =
    ssh_mpk_mul_karatsuba_needed_memory(m->m_n, m->m_n);

  if (m->karatsuba_work_space_n < temp_n)
    m->karatsuba_work_space_n = temp_n;

  /* Note that it is still possible that no extra memory is needed! */
  if (m->karatsuba_work_space_n)
    {
      m->karatsuba_work_space = ssh_malloc(sizeof(SshWord) *
                                           m->karatsuba_work_space_n);
      if (m->karatsuba_work_space == NULL)
        goto failure;
    }

  /* Now allocate the extra higher level working space. */

  /* The amount of memory for multiplication and squaring! */
  m->work_space_n = (m->m_n * 2 + 1) * 2;
  m->work_space   = ssh_malloc(sizeof(SshWord) * m->work_space_n);
  if (m->work_space == NULL)
    goto failure;

#else /* SSHMATH_USE_WORKSPACE */
  m->karatsuba_work_space_n = 0;
  m->work_space_n           = 0;
#endif /* SSHMATH_USE_WORKSPACE */

  return TRUE;

 failure:
  ssh_free(m->m);
  ssh_free(m->work_space);
  ssh_free(m->karatsuba_work_space);
  memset(m, 0, sizeof(*m));
  return FALSE;
}

/* Clean up the used moduli space. */
void ssh_mpmzm_clear_ideal(SshMPMontIntIdeal m)
{
  /* Free. */
  ssh_free(m->m);
  ssh_free(m->work_space);
  ssh_free(m->karatsuba_work_space);

  /* Clean. */
  memset(m, 0, sizeof(*m));
}

void ssh_mprz_set_mpmzm_ideal(SshMPInteger ret, SshMPMontIntIdealConst m)
{
  (void)ssh_mprz_realloc(ret, m->m_n);
  if (!ssh_mprz_isnan(ret))
    {
      ssh_mpk_memcopy(ret->v, m->m, m->m_n);
      ret->n = m->m_n;
    }
  /* Our moduli cannot be negative! */
  SSH_MP_NO_SIGN(ret);
}

void ssh_mpmzm_init(SshMPMontIntMod op, SshMPMontIntIdealConst m)
{
  op->n = 0;
  op->m = m;
  op->isnan = FALSE;
  op->nankind = 0;

  if ((op->v = ssh_malloc(sizeof(SshWord) * (m->m_n + 1))) == NULL)
    ssh_mpmzm_makenan(op, SSH_MPMZM_NAN_ENOMEM);
}

void ssh_mpmzm_init_inherit(SshMPMontIntMod op1,
                            SshMPMontIntModConst op2)
{
  if (ssh_mpmzm_isnan(op2))
    {
      op1->v = NULL;
      op1->n = 0;
      op1->m = NULL;
      op1->isnan = TRUE;
      op1->nankind = op2->nankind;
      return;
    }

  memset(op1, 0, sizeof(*op1));
  op1->n = 0;
  op1->m = op2->m;
  op1->isnan = FALSE;
  op1->nankind = 0;

  if ((op1->v = ssh_malloc(sizeof(SshWord) * (op2->m->m_n + 1))) == NULL)
    ssh_mpmzm_makenan(op1, SSH_MPMZM_NAN_ENOMEM);
}

void ssh_mpmzm_clear(SshMPMontIntMod op)
{
  if (!ssh_mpmzm_isnan(op))
    ssh_free(op->v);

  memset(op, 0 , sizeof(*op));
}

void ssh_mpmzm_set(SshMPMontIntMod ret, SshMPMontIntModConst op)
{
  if (ret == op)
    return;

  if (ssh_mpmzm_nanresult1(ret, op))
    return;

  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }
  ssh_mpk_memcopy(ret->v, op->v, op->n);
  ret->n = op->n;
}

void ssh_mpmzm_set_mprz(SshMPMontIntMod ret, SshMPIntegerConst op)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t;
  unsigned int t_n;

  if (ssh_mpmzm_isnan(ret))
    return;

  if (ssh_mprz_isnan(op))
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }
  /* Trivial case. */
  if (op->n == 0)
    {
      /* Return zero also. */
      ret->n = 0;
      return;
    }

  /* If the input op != 0 then we will necessarily need some modular
     reduction. Thus the following doesn't need checks for the size
     of the input. */

  /* Compute R*op = ret (mod m) */

  /* Allocate some temporary space. */
  SSH_MP_WORKSPACE_ALLOC(t, (op->n + 1 + ret->m->m_n));
  if (!t)
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }

  /* Multiply by R the remainder. */
  ssh_mpk_memzero(t, ret->m->m_n);
  ssh_mpk_memcopy(t + ret->m->m_n, op->v, op->n);
  t_n = op->n + ret->m->m_n + 1;
  t[t_n - 1] = 0;

  /* Normalize. */
  ssh_mpk_shift_up_bits(t + ret->m->m_n, op->n + 1, ret->m->shift);

  /* Validate that length is correct. */
  if (t[t_n - 1] == 0)
    t_n--;

  /* Modular operations. */
  ssh_mpk_mod(t, t_n, ret->m->d, ret->m->m_n);

  /* Denormalize the remainder. */
  ssh_mpk_shift_down_bits(t, ret->m->m_n, ret->m->shift);

  /* Compute exact size. */
  t_n = ret->m->m_n;
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Copy into ret. */
  ssh_mpk_memcopy(ret->v, t, t_n);
  ret->n = t_n;

  SSH_MP_WORKSPACE_FREE(t);
}

void ssh_mpmzm_set_ui(SshMPMontIntMod ret, SshWord u)
{
  if (ssh_mpmzm_isnan(ret))
    return;

  /* Do zeroing fast. */
  if (u == 0)
    {
      ret->n = 0;
      return;
    }
  else
    {
      SshMPIntegerStruct mp;
      /* This is slow, and unoptimized. Most of the time you
         don't need to do this. */
      ssh_mprz_init(&mp);
      ssh_mprz_set_ui(&mp, u);
      ssh_mpmzm_set_mprz(ret, &mp);
      ssh_mprz_clear(&mp);
    }
  return;
}

void ssh_mprz_set_mpmzm(SshMPInteger ret, SshMPMontIntModConst op)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t;
  unsigned int t_n;

  if (ssh_mpmzm_isnan(op))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  /* Allocate enough space for reduction to happen. */
  t_n = op->m->m_n * 2 + 1;
  SSH_MP_WORKSPACE_ALLOC(t, t_n);
  if (!t)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }
  ssh_mpk_memzero(t, t_n);

#ifdef ASM_PLATFORM_OCTEON
  ssh_mpmk_reduce_192(t, t_n,
                  op->v, op->n,
                  op->m->mp,
                  op->m->big_mp,
                  op->m->m, op->m->m_n);
#else /* ASM_PLATFORM_OCTEON */
  /* Reduce. */
  ssh_mpmk_reduce(t, t_n,
                  op->v, op->n,
                  op->m->mp,
                  op->m->m, op->m->m_n);
#endif /* !ASM_PLATFORM_OCTEON */

  /* Compute exact length. */
  t_n = op->m->m_n;
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Copy the result into ret. */
  (void)ssh_mprz_realloc(ret, t_n);
  if (!ssh_mprz_isnan(ret))
    {
      ssh_mpk_memcopy(ret->v, t, t_n);
      ret->n = t_n;
    }

  /* Free temporary storage. */
  SSH_MP_WORKSPACE_FREE(t);

  SSH_MP_NO_SIGN(ret);
}

/* This is a simple wrapper but rather useful in many occasions. */
int ssh_mpmzm_cmp(SshMPMontIntModConst op1,
                  SshMPMontIntModConst op2)
{
  /* Two NaNs are unequal, and a NaN is not equal to any MontInt. */
  if (ssh_mpmzm_isnan(op1) || ssh_mpmzm_isnan(op2))
    return 1;

  return ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n);
}

/* Simple wrapper. */
int ssh_mpmzm_cmp_ui(SshMPMontIntModConst op, SshWord u)
{
  int b;
  SshMPMontIntModStruct tmp;

  if (ssh_mpmzm_isnan(op))
    return 1;

  ssh_mpmzm_init_inherit(&tmp, op);
  ssh_mpmzm_set_ui(&tmp, u);

  b = ssh_mpmzm_cmp(op, &tmp);
  ssh_mpmzm_clear(&tmp);

  return b;
}

/* Addition is easy with Montgomery representation. */
void ssh_mpmzm_add(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                   SshMPMontIntModConst op2)
{
  SshWord c;

  if (ssh_mpmzm_nanresult2(ret, op1, op2))
    return;

  if (op1->n < op2->n)
    {
      SshMPMontIntModConst t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Perform the addition. */
  c = ssh_mpk_add(ret->v, op1->v, op1->n, op2->v, op2->n);
  if (c)
    {
      ret->v[op1->n] = c;
      ret->n = op1->n + 1;
    }
  else
    ret->n = op1->n;

  /* Do modular reduction. */
  if (ssh_mpk_cmp(ret->v, ret->n, ret->m->m, ret->m->m_n) > 0)
    {
      ssh_mpk_sub(ret->v, ret->v, ret->n, ret->m->m, ret->m->m_n);
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
}

/* Subtraction is a bit more difficult. */
void ssh_mpmzm_sub(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                   SshMPMontIntModConst op2)
{
  if (ssh_mpmzm_nanresult2(ret, op1, op2))
    return;

  if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
    {
      ssh_mpk_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
      ret->n = op1->n;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
  else
    {
      ssh_mpk_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
      ret->n = op2->n;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;

      /* Do modular reduction. */
      ssh_mpk_sub(ret->v, ret->m->m, ret->m->m_n, ret->v, ret->n);
      ret->n = ret->m->m_n;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
}

void ssh_mpmzm_mul(SshMPMontIntMod ret, SshMPMontIntModConst op1,
                   SshMPMontIntModConst op2)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t, *r;
  unsigned int t_n, r_n;

  if (ssh_mpmzm_nanresult2(ret, op1, op2))
    return;

  if (op1->n == 0 || op2->n == 0)
    {
      ret->n = 0;
      return;
    }

  /* Allocate some temporary space. */
  t_n = op1->n + op2->n + 1;
  r_n = ret->m->m_n*2 + 1;
  if (ret->m->work_space == NULL)
    {
      /* Use the stack based workspace if possible. */
      SSH_MP_WORKSPACE_ALLOC(t, t_n + r_n);
      if (!t)
        {
          ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
          return;
        }
    }
  else
    t = ret->m->work_space;
  r = t + t_n;

  /* Clear temporary space. */
  ssh_mpk_memzero(t, t_n);
  if (!ssh_mpk_mul_karatsuba(t, t_n, op1->v, op1->n, op2->v, op2->n,
                             ret->m->karatsuba_work_space,
                             ret->m->karatsuba_work_space_n))
    {
      if (ret->m->work_space == NULL)
        SSH_MP_WORKSPACE_FREE(t);

      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }


  /* Find the exact length. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Do the reduction step. */
  ssh_mpk_memzero(r, r_n);
#ifdef ASM_PLATFORM_OCTEON
  ssh_mpmk_reduce_192(
          r, r_n,
          t, t_n,
          ret->m->mp,
          ret->m->big_mp,
          ret->m->m, ret->m->m_n);
#else /* ASM_PLATFORM_OCTEON */
  /* Reduce. */
  ssh_mpmk_reduce(r, r_n,
                  t, t_n,
                  ret->m->mp,
                  ret->m->m, ret->m->m_n);
#endif /* !ASM_PLATFORM_OCTEON */

  /* Compute exact length. */
  r_n = ret->m->m_n;
  while (r_n && r[r_n - 1] == 0)
    r_n--;

  /* Copy to destination. */
  ssh_mpk_memcopy(ret->v, r, r_n);
  ret->n = r_n;

  /* Free temporary storage. */
  if (ret->m->work_space == NULL)
    SSH_MP_WORKSPACE_FREE(t);
}

/* This should work, because op = x*R (mod m) and we can just
   compute op*u = x*R*u (mod m) as before. This should be much
   faster than standard multiplication. */
void ssh_mpmzm_mul_ui(SshMPMontIntMod ret, SshMPMontIntModConst op,
                      SshWord u)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t;
  int t_n;

  if (ssh_mpmzm_nanresult1(ret, op))
    return;

  /* Handle the trivial case. */
  if (op->n == 0 || u == 0)
    {
      ret->n = 0;
      return;
    }

  /* Another trivial case. */
  if (u == 1)
    {
      ssh_mpmzm_set(ret, op);
      return;
    }

  /* Multiply first. */
  t_n = op->n + 2;
  if (ret->m->work_space == NULL)
    {
      SSH_MP_WORKSPACE_ALLOC(t, t_n);
      if (!t)
        {
          ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
          return;
        }
    }
  else
    t = ret->m->work_space;
  ssh_mpk_memzero(t, t_n);
  ssh_mpk_mul_ui(t, op->v, op->n, u);

  /* Correct the size. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Do a compare, which determines whether the modular reduction
     is necessary. */
  if (ssh_mpk_cmp(t, t_n, ret->m->m, ret->m->m_n) >= 0)
    {
      /* Allow growing a bit. */
      t_n ++;

      /* Now reduce (mod m). */

      /*The normalization first. */
      ssh_mpk_shift_up_bits(t, t_n, ret->m->shift);

      /* Check the size again. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      /* Reduction function. */
      ssh_mpk_mod(t, t_n, ret->m->d, ret->m->m_n);
      t_n = ret->m->m_n;

      ssh_mpk_shift_down_bits(t, t_n, ret->m->shift);

      /* Correct the size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;
    }

  ssh_mpk_memcopy(ret->v, t, t_n);
  ret->n = t_n;

  /* Free if necessary. */
  if (ret->m->work_space == NULL)
    SSH_MP_WORKSPACE_FREE(t);
}

void ssh_mpmzm_square(SshMPMontIntMod ret, SshMPMontIntModConst op)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *t, *r;
  unsigned int t_n, r_n;

  if (ssh_mpmzm_nanresult1(ret, op))
    return;

  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }

  /* Allocate some temporary space. */
  t_n = op->n*2 + 1;
  r_n = ret->m->m_n*2 + 1;
  if (ret->m->work_space == NULL)
    {
      SSH_MP_WORKSPACE_ALLOC(t, t_n + r_n);
      if (!t)
        {
          ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
          return;
        }
    }
  else
    t = ret->m->work_space;
  r = t + t_n;

  /* Clear temporary space. */
  ssh_mpk_memzero(t, t_n + r_n);
  if (!ssh_mpk_square_karatsuba(t, t_n, op->v, op->n,
                           ret->m->karatsuba_work_space,
                                ret->m->karatsuba_work_space_n))
    {
      if (ret->m->work_space == NULL)
        SSH_MP_WORKSPACE_FREE(t);

      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }

  /* Find the exact length. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Do the reduction step. */
  ssh_mpk_memzero(r, r_n);
#ifdef ASM_PLATFORM_OCTEON
  ssh_mpmk_reduce_192(
          r, r_n,
          t, t_n,
          ret->m->mp,
          ret->m->big_mp,
          ret->m->m, ret->m->m_n);
#else /* ASM_PLATFORM_OCTEON */
  /* Reduce. */
  ssh_mpmk_reduce(r, r_n,
                  t, t_n,
                  ret->m->mp,
                  ret->m->m, ret->m->m_n);
#endif /* !ASM_PLATFORM_OCTEON */

  /* Compute exact length. */
  r_n = ret->m->m_n;
  while (r_n && r[r_n - 1] == 0)
    r_n--;

  /* Copy to destination. */
  ssh_mpk_memcopy(ret->v, r, r_n);
  ret->n = r_n;

  /* Free temporary storage. */
  if (ret->m->work_space == NULL)
    SSH_MP_WORKSPACE_FREE(t);
}

void ssh_mpmzm_mul_2exp(SshMPMontIntMod ret, SshMPMontIntModConst op,
                        unsigned int exp)
{
  SSH_MP_WORKSPACE_DEFINE;
  unsigned int k;
  SshWord *t;
  int t_n, max;

  if (ssh_mpmzm_nanresult1(ret, op))
    return;

  /* Check if no need to to anything. */
  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }

  /* Handle some special number of bits here. */
  if (exp == 0)
    {
      ssh_mpmzm_set(ret, op);
      return;
    }

  if (exp < SSH_WORD_BITS)
    {
      t_n = op->n + 2;
      if (ret->m->work_space == NULL)
        {
          SSH_MP_WORKSPACE_ALLOC(t, t_n);
          if (!t)
            {
              ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
              return;
            }
        }
      else
        t = ret->m->work_space;

      /* Copy to ret. */
      ssh_mpk_memcopy(t, op->v, op->n);
      /* This can be done, because ret has always one extra word. */
      t[op->n] = 0;
      ssh_mpk_shift_up_bits(t, op->n + 1, exp);
      t_n = op->n + 1;
      /* Figure out the correct length. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;
      /* Check if reduction is necessary. */
      if (ssh_mpk_cmp(t, t_n, ret->m->m, ret->m->m_n) >= 0)
        {
          /* Do some additional operations. */
          t[t_n] = 0;
          ssh_mpk_shift_up_bits(t, t_n + 1, ret->m->shift);
          t_n++;
          while (t_n && t[t_n - 1] == 0)
            t_n--;
          /* Perform the reduction. */
          ssh_mpk_mod(t, t_n, ret->m->d, ret->m->m_n);
          t_n = ret->m->m_n;
          ssh_mpk_shift_down_bits(t, t_n, ret->m->shift);
          /* Figure out the correct size. */
          while (t_n && t[t_n - 1] == 0)
            t_n--;
        }

      /* Copy to the ret. */
      ssh_mpk_memcopy(ret->v, t, t_n);
      ret->n = t_n;

      if (ret->m->work_space == NULL)
        SSH_MP_WORKSPACE_FREE(t);
      return;
    }

  /* Compute the maximum number of suitable bits. */
  max = ret->m->m_n * SSH_WORD_BITS;

  for (; exp; )
    {
      int bits;

      if (exp > max)
        {
          bits = max;
          exp -= max;
        }
      else
        {
          bits = exp;
          exp  = 0;
        }

      /* The standard way of doing the same thing. */
      bits += ret->m->shift;
      k = bits / SSH_WORD_BITS;
      bits %= SSH_WORD_BITS;

      /* Allocate new space. */
      t_n = k + 2 + op->n;
      if (ret->m->work_space == NULL)
        {
          SSH_MP_WORKSPACE_ALLOC(t, t_n);
          if (!t)
            {
              ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
              return;
            }
        }
      else
        t = ret->m->work_space;

      /* Move from op to ret. */
      ssh_mpk_memzero(t, t_n);
      ssh_mpk_memcopy(t + k, op->v, op->n);
      ssh_mpk_shift_up_bits(t + k, op->n + 1, bits);

      /* Figure out the correct size here. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      /* Compute the modulus. */
      if (ssh_mpk_cmp(t, t_n, ret->m->d, ret->m->m_n) >= 0)
        {
          ssh_mpk_mod(t, t_n, ret->m->d, ret->m->m_n);
          t_n = ret->m->m_n;
        }
      ssh_mpk_shift_down_bits(t, t_n, ret->m->shift);

      /* Figure out the correct size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      /* Now copy to the ret. */
      ssh_mpk_memcopy(ret->v, t, t_n);
      ret->n = t_n;

      if (ret->m->work_space == NULL)
        SSH_MP_WORKSPACE_FREE(t);
    }
}

void ssh_mpmzm_div_2exp(SshMPMontIntMod ret, SshMPMontIntModConst op,
                        unsigned int exp)
{
  unsigned int i;
  SshWord c;

  if (ssh_mpmzm_nanresult1(ret, op))
    return;

  /* Handle trivial cases first. */
  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }

  if (exp == 0)
    {
      ssh_mpmzm_set(ret, op);
      return;
    }

  /* Now handle the main iteration, notice that dividing by very
     large values this way isn't fast! */

  /* Set up the return integer. */
  ssh_mpmzm_set(ret, op);
  if (ret->m->m_n + 1 - ret->n)
    ssh_mpk_memzero(ret->v + ret->n, ret->m->m_n + 1 - ret->n);

  /* Loop until done, might take a while. */
  for (i = 0; i < exp; i++)
    {
      if (ret->v[0] & 0x1)
        {
          if (ret->n < ret->m->m_n)
            ret->n = ret->m->m_n;
          c = ssh_mpk_add(ret->v, ret->v, ret->n, ret->m->m, ret->m->m_n);
          if (c)
            {
              ret->v[ret->n] = c;
              ret->n++;
            }
        }
      ssh_mpk_shift_down_bits(ret->v, ret->n, 1);
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
}

#ifdef SSHDIST_MATH_INTMOD
/* This will be needed in some future time. E.g. when writing fast
   polynomial arithmetic modulo large integer. Although, one should
   then also implement some other routines which would be of lots of
   use. */
Boolean ssh_mpmzm_invert(SshMPMontIntMod ret, SshMPMontIntModConst op)
{
  SshMPIntegerStruct t, q;
  Boolean rv;

  if (ssh_mpmzm_nanresult1(ret, op))
    return FALSE;

  ssh_mprz_init(&t);
  ssh_mprz_init(&q);
  /* Convert into basic integers. */
  ssh_mprz_set_mpmzm(&t, op);
  ssh_mprz_set_mpmzm_ideal(&q, ret->m);
  rv = ssh_mprz_invert(&t, &t, &q);
  ssh_mpmzm_set_mprz(ret, &t);
  ssh_mprz_clear(&t);
  ssh_mprz_clear(&q);
  return rv;
}

Boolean ssh_mpmzm_sqrt(SshMPMontIntMod ret, SshMPMontIntModConst op)
{
  SshMPIntegerStruct t, q;
  Boolean rv;

  if (ssh_mpmzm_nanresult1(ret, op))
    return FALSE;

  ssh_mprz_init(&t);
  ssh_mprz_init(&q);
  /* Convert into basic integers. */
  ssh_mprz_set_mpmzm(&t, op);
  ssh_mprz_set_mpmzm_ideal(&q, ret->m);
  rv = ssh_mprz_mod_sqrt(&t, &t, &q);
  ssh_mpmzm_set_mprz(ret, &t);
  ssh_mprz_clear(&t);
  ssh_mprz_clear(&q);
  return rv;
}
#endif /* SSHDIST_MATH_INTMOD */

void ssh_mpmzm_pow_ui(SshMPMontIntMod ret, SshWord g, SshMPIntegerConst e)
{
  SshMPMontIntModStruct temp, x;
  unsigned int bits, i;

  if (ssh_mpmzm_isnan(ret))
    return;

  if (ssh_mprz_isnan(e))
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }

  /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e, 0) == 0)
    {
      ssh_mpmzm_set_ui(ret, 1);
      return;
    }

  if (ssh_mprz_cmp_ui(e, 1) == 0)
    {
      ssh_mpmzm_set_ui(ret, g);
      return;
    }

  ssh_mpmzm_init_inherit(&temp, ret);
  ssh_mpmzm_init_inherit(&x,    ret);

  ssh_mpmzm_set_ui(&x, g);
  ssh_mpmzm_set(&temp, &x);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mpmzm_square(&temp, &temp);
      if (ssh_mprz_get_bit(e, i - 1))
        ssh_mpmzm_mul_ui(&temp, &temp, g);
    }

  ssh_mpmzm_set(ret, &temp);
  ssh_mpmzm_clear(&temp);
  ssh_mpmzm_clear(&x);
}


void ssh_mpmzm_pow(SshMPMontIntMod ret, SshMPMontIntModConst g,
                   SshMPIntegerConst e)
{
  SshMPMontIntModStruct temp, x;
  unsigned int table_bits, table_size;
  SshMPMontIntMod table;
  unsigned int bits, i, j, mask, end_square, first;
  unsigned int tab[] =
  { 24, 88, 277, 798, 2173, 5678, 14373, 0 };

  if (ssh_mpmzm_nanresult1(ret, g))
    return;

  if (ssh_mprz_isnan(e))
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }

  /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e, 0) == 0)
    {
      ssh_mpmzm_set_ui(ret, 1);
      return;
    }

  if (ssh_mprz_cmp_ui(e, 1) == 0)
    {
      ssh_mpmzm_set(ret, g);
      return;
    }

  ssh_mpmzm_init_inherit(&temp, ret);
  ssh_mpmzm_init_inherit(&x,    ret);

  /* Initialize the generator (in Montgomery representation). */
  ssh_mpmzm_set(&x, g);

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
  table = ssh_malloc(sizeof(SshMPMontIntModStruct) * table_size);
  if (!table)
    {
      ssh_mpmzm_clear(&temp);
      ssh_mpmzm_clear(&x);
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }

  /* Start computing the table. */
  ssh_mpmzm_init_inherit(&table[0], ret);
  ssh_mpmzm_set(&table[0], &x);

  /* Compute g^2 into temp. */
  ssh_mpmzm_set(&temp, &table[0]);
  ssh_mpmzm_square(&temp, &temp);

  /* Compute the small table of powers. */
  for (i = 1; i < table_size; i++)
    {
      ssh_mpmzm_init_inherit(&table[i], ret);
      ssh_mpmzm_mul(&table[i], &table[i - 1], &temp);
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
            ssh_mpmzm_square(&temp, &temp);

          ssh_mpmzm_mul(&temp, &temp, &table[(mask - 1)/2]);
        }
      else
        {
          ssh_mpmzm_set(&temp, &table[(mask - 1)/2]);
          first = 0;
        }

      /* Get rid of zero bits... */
      while (end_square)
        {
          ssh_mpmzm_square(&temp, &temp);
          end_square--;
        }

      while (i && ssh_mprz_get_bit(e, i - 1) == 0)
        {
          ssh_mpmzm_square(&temp, &temp);
          i--;
        }
    }

  /* Clear and free the table. */
  for (i = 0; i < table_size; i++)
    ssh_mpmzm_clear(&table[i]);

  ssh_mpmzm_set(ret, &temp);

  ssh_mpmzm_clear(&temp);
  ssh_mpmzm_clear(&x);

 ssh_free(table);
}

void ssh_mpmzm_pow_gg(SshMPMontIntMod ret,
                      SshMPMontIntModConst g1, SshMPIntegerConst e1,
                      SshMPMontIntModConst g2, SshMPIntegerConst e2)
{
  SshMPMontIntModStruct temp, x1, x2, x3;
  unsigned int bits, i;

  if (ssh_mpmzm_nanresult2(ret, g1, g2))
    return;

  if (ssh_mprz_isnan(e1) || ssh_mprz_isnan(e2))
    {
      ssh_mpmzm_makenan(ret, SSH_MPMZM_NAN_ENOMEM);
      return;
    }
      /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e1, 0) == 0)
    {
      ssh_mpmzm_pow(ret, g2, e2);
      return;
    }
  if (ssh_mprz_cmp_ui(e2, 0) == 0)
    {
      ssh_mpmzm_pow(ret, g1, e1);
      return;
    }

  ssh_mpmzm_init_inherit(&temp, ret);
  ssh_mpmzm_init_inherit(&x1,   ret);
  ssh_mpmzm_init_inherit(&x2,   ret);
  ssh_mpmzm_init_inherit(&x3,   ret);

  ssh_mpmzm_set(&x1, g1);
  ssh_mpmzm_set(&x2, g2);
  ssh_mpmzm_mul(&x3, &x1, &x2);
  ssh_mpmzm_set_ui(&temp, 1);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e2->v, e2->n);
  i = ssh_mpk_size_in_bits(e1->v, e1->n);
  if (i > bits)
    bits = i;

  for (i = bits; i; i--)
    {
      int k;
      ssh_mpmzm_square(&temp, &temp);

      k  = ssh_mprz_get_bit(e1, i - 1);
      k |= ssh_mprz_get_bit(e2, i - 1) << 1;

      switch (k)
        {
        case 0:
          break;
        case 1:
          ssh_mpmzm_mul(&temp, &temp, &x1);
          break;
        case 2:
          ssh_mpmzm_mul(&temp, &temp, &x2);
          break;
        case 3:
          ssh_mpmzm_mul(&temp, &temp, &x3);
          break;
        }
    }

  ssh_mpmzm_set(ret, &temp);

  ssh_mpmzm_clear(&temp);
  ssh_mpmzm_clear(&x1);
  ssh_mpmzm_clear(&x2);
  ssh_mpmzm_clear(&x3);
}

/**********************************************************************/

/* Perform the pow operation as a series of operations saving the current
   state of the operartion in the SshMPMontPowState structure. */

struct SshMPMontPowStateRec {

  SshMPMontIntModStruct temp;
  SshMPMontIntModStruct x;

  SshMPIntegerStruct e;

  Boolean finished;
  SshUInt32 step;
};

SshMPMontPowState ssh_mpmzm_pow_state_alloc(SshMPMontIntModConst g)
{
  SshMPMontPowState state;

  if (ssh_mpmzm_isnan(g))
    return NULL;

  if ((state = ssh_calloc(1, sizeof(*state))) == NULL)
    return NULL;

  /* Initialize e to 0 */
  ssh_mprz_init_set_ui(&state->e, 0);

  ssh_mpmzm_init_inherit(&state->temp, g);
  ssh_mpmzm_init_inherit(&state->x, g);

  ssh_mpmzm_set(&state->x, g);
  ssh_mpmzm_set(&state->temp, &state->x);

  state->step = 0;
  return state;
}

Boolean ssh_mpmzm_pow_state_init(SshMPMontPowState state, SshMPIntegerConst e)
{
  unsigned int bits;

  if (ssh_mprz_isnan(e))
    return FALSE;

  /* Don't waste our time on trivial cases. */
  if ((ssh_mprz_cmp_ui(e, 0) == 0) || (ssh_mprz_cmp_ui(e, 1) == 0))
    return FALSE;

  ssh_mprz_set(&state->e, e);
  ssh_mpmzm_set(&state->temp, &state->x);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e->v, e->n);

  state->finished = FALSE;
  state->step = bits - 1;
  return TRUE;
}

Boolean ssh_mpmzm_pow_state_iterate(SshMPMontPowState state)
{
 SSH_DEBUG(SSH_D_MY + 15, ("In POW state iterate"));

  if (state->finished)
    return TRUE;

  SSH_ASSERT(state->step > 0);

  ssh_mpmzm_square(&state->temp, &state->temp);

   if (ssh_mprz_get_bit(&state->e, state->step - 1))
    ssh_mpmzm_mul(&state->temp, &state->temp, &state->x);

  state->step--;

  if (state->step == 0)
    state->finished = TRUE;

  /* We are finished when state->step reaches zero. */
  return state->finished;
}

void ssh_mpmzm_pow_state_set_result(SshMPMontIntMod result,
                                    SshMPMontPowState state)
{
  SSH_ASSERT(state->finished);

  ssh_mpmzm_set(result, &state->temp);
  return;
}

void ssh_mpmzm_pow_state_free(SshMPMontPowState state)
{
  ssh_mpmzm_clear(&state->x);
  ssh_mpmzm_clear(&state->temp);
  ssh_mprz_clear(&state->e);
  ssh_free(state);
  return;
}

/* sshmp-montgomery.c */
#endif /* SSHDIST_MATH */
