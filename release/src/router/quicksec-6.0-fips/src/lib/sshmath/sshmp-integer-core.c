/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This library implements the computations in the ring of integers,
   that is in the set

   Z = {..., -2, -1, 0, 1, 2, ...}.

   Namely, the ring operations and some convenience routines.

   The more arithmetical routines (i.e. routines that also utilize
   local mod p features) are implemented elsewhere.

   This module only contains the routines that are necessary for RSA and
   Diffie-Hellman with predefined keys. The remaining integer routines
   can be found in sshmp-int-misc.c.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgetput.h"

#define SSH_DEBUG_MODULE "SshMPIntegerCore"

#ifdef SSHDIST_MATH

/********** Routines for handling variable length integers *****/

/* NaN routines. */

Boolean ssh_mprz_isnan(SshMPIntegerConst op)
{
  return (op == NULL || (op->n == 0 && op->isnan));
}

void ssh_mprz_makenan(SshMPInteger op, unsigned int kind)
{
  if (op)
    {
      if (op->v)
        {
          /* zeroize and free */
          if (op->dynamic_v)
            {
              memset(op->v, 0, sizeof(SshWord) * op->m);
              ssh_free(op->v);
            }
        }

      /* zeroize */
      memset(op->w, 0, SSH_MP_INTEGER_STATIC_ARRAY_SIZE);

      op->dynamic_v = 0;
      op->v = NULL;
      op->n = 0;
      op->m = 0;
      op->isnan = 1;
      op->nankind = kind;
    }
}

Boolean ssh_mprz_nanresult1(SshMPInteger ret, SshMPIntegerConst op)
{
#ifdef DEBUG_HEAVY
  unsigned char opstr[128];
  ssh_mprz_get_buf(opstr, sizeof(opstr), op);
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("OP= "  ), opstr, sizeof(opstr));
#endif

  if (op == NULL)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return TRUE;
    }
  if (ssh_mprz_isnan(op))
    {
      ssh_mprz_makenan(ret, op->nankind);
      return TRUE;
    }
  return FALSE;
}


Boolean ssh_mprz_nanresult2(SshMPInteger ret, SshMPIntegerConst op1,
                            SshMPIntegerConst op2)
{
#ifdef DEBUG_HEAVY
  unsigned char opstr1[128], opstr2[128];
  ssh_mprz_get_buf(opstr1, sizeof(opstr1), op1);
  ssh_mprz_get_buf(opstr2, sizeof(opstr2), op2);
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("OP1= "  ), opstr1, sizeof(opstr1));
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("OP2= "  ), opstr2, sizeof(opstr2));
#endif

  if (op1 == NULL || op2 == NULL)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return TRUE;
    }
  if (ssh_mprz_isnan(op1))
    {
      ssh_mprz_makenan(ret, op1->nankind);
      return TRUE;
    }

  if (ssh_mprz_isnan(op2))
    {
      ssh_mprz_makenan(ret, op2->nankind);
      return TRUE;
    }
  return FALSE;
}

Boolean ssh_mprz_nanresult3(SshMPInteger ret, SshMPIntegerConst op1,
                            SshMPIntegerConst op2, SshMPIntegerConst op3)
{
#ifdef DEBUG_HEAVY
  unsigned char opstr1[128], opstr2[128], opstr3[128];
  ssh_mprz_get_buf(opstr1, sizeof(opstr1), op1);
  ssh_mprz_get_buf(opstr2, sizeof(opstr2), op2);
  ssh_mprz_get_buf(opstr3, sizeof(opstr3), op3);
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("OP1= "  ), opstr1, sizeof(opstr1));
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("OP2= "  ), opstr2, sizeof(opstr2));
  SSH_DEBUG_HEXDUMP(SSH_D_MY, ("OP3= "  ), opstr3, sizeof(opstr3));
#endif

  if (op1 == NULL || op2 == NULL || op3 == NULL)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return TRUE;
    }
  if (ssh_mprz_isnan(op1))
    {
      ssh_mprz_makenan(ret, op1->nankind);
      return TRUE;
    }

  if (ssh_mprz_isnan(op2))
    {
      ssh_mprz_makenan(ret, op2->nankind);
      return TRUE;
    }

  if (ssh_mprz_isnan(op3))
    {
      ssh_mprz_makenan(ret, op3->nankind);
      return TRUE;
    }
  return FALSE;
}

/* Routines for allocating and expanding SshMPInteger's. */


SshMPInteger ssh_mprz_malloc(void)
{
  SshMPInteger op;

  op = ssh_calloc(1, sizeof(*op));

  if (op)
    {
      op->m = SSH_MP_INTEGER_STATIC_ARRAY_SIZE;
      op->v = op->w;
    }

  return op;
}

void ssh_mprz_free(SshMPInteger op)
{
  if (op)
    {
      ssh_mprz_clear(op);
      ssh_free(op);
    }
}

/* Allocates an MPInteger data area into `op'. Returns true, if
   allocation is successful, and FALSE, if it fails. In latter case
   the destination `op' will be set as NAM/enomem. */

Boolean ssh_mprz_realloc(SshMPInteger op, unsigned int new_size)
{
  if (ssh_mprz_isnan(op))
    return FALSE;

  if (new_size <= SSH_MP_INTEGER_STATIC_ARRAY_SIZE)
    return TRUE;

  if (new_size > op->m)
    {
      SshWord *nv;

      /* Allocate, copy and clear the rest. */
      nv = ssh_malloc((size_t)new_size * sizeof(SshWord));
      if (nv)
        {
          ssh_mpk_memcopy(nv, op->v, op->n);

          /* Free the old, set the new. */
          if (op->dynamic_v && op->v)
            {
              memset(op->v, 0, sizeof(SshWord) * op->m);
              ssh_free(op->v);
            }
          op->v = nv;
          op->dynamic_v = 1;
          op->m = new_size;
          return TRUE;
        }
      else
        {
          ssh_mprz_makenan(op, SSH_MP_NAN_ENOMEM);
          return FALSE;
        }
    }
  return TRUE;
}

/* Clear the upper (part which is not used) part of the
   integer. This allows us to sometimes use the integer's own
   data area for computations. */
void ssh_mprz_clear_extra(SshMPInteger op)
{
  unsigned int i;
  for (i = op->n; i < op->m; i++)
    op->v[i] = 0;
}

/****************** The integer interface. ******************/

/* Initialize the integer. */
void ssh_mprz_init(SshMPInteger op)
{

  memset(op->w, 0, SSH_MP_INTEGER_STATIC_ARRAY_SIZE);
  op->m = SSH_MP_INTEGER_STATIC_ARRAY_SIZE;
  op->v = op->w;
  op->n = 0;
  op->dynamic_v = 0;
  op->sign = 0;
  op->isnan = FALSE;
  op->nankind = 0;
}

/* Clear the integer up, free the space occupied, but don't free the
   integer context. */
void ssh_mprz_clear(SshMPInteger op)
{
  if (!ssh_mprz_isnan(op))
    {
      /* Zeroize and free */
      memset(op->w, 0, SSH_MP_INTEGER_STATIC_ARRAY_SIZE);

      if (op->dynamic_v)
        {
          memset(op->v, 0, sizeof(SshWord) * op->m);
          ssh_free(op->v);
        }
    }
  op->n = 0;
  op->m = 0;
  op->dynamic_v = 0;
  op->isnan = FALSE;
  op->nankind = 0;
  op->sign = 0;
  op->v = op->w;
}


void ssh_mprz_set(SshMPInteger ret, SshMPIntegerConst op)
{
  /* Check that pointers are not equal, in which case, anything more
     would be stupid. */
  if (ret == op)
    return;

  if (ssh_mprz_isnan(op))
    {
      ssh_mprz_makenan(ret, op->nankind);
      return;
    }

  if (ssh_mprz_realloc(ret, op->n))
    {
      /* Copy */
      ssh_mpk_memcopy(ret->v, op->v, op->n);
      ret->n = op->n;
      SSH_MP_COPY_SIGN(ret, op);
    }
}


SshWord ssh_mprz_get_ui(SshMPIntegerConst op)
{
  if (op->n == 0)
    return 0;
  return op->v[0];
}

SshWord ssh_mprz_get_word(SshMPIntegerConst op, unsigned int i)
{
  if (i >= op->n)
    return 0;
  return op->v[i];
}

void ssh_mprz_set_ui(SshMPInteger op, SshWord n)
{
  if (n == 0)
    {
      op->n = 0;
      SSH_MP_NO_SIGN(op);
      return;
    }

  /* Check that we have enough space. */
  if (ssh_mprz_realloc(op, 1))
    {
      /* Set the integer. */
      op->v[0] = (SshWord)n;
      op->n = 1;
      SSH_MP_NO_SIGN(op);
    }
}

void ssh_mprz_init_set(SshMPInteger ret, SshMPIntegerConst op)
{
  ssh_mprz_init(ret);
  ssh_mprz_set(ret, op);
}

void ssh_mprz_init_set_ui(SshMPInteger ret, SshWord u)
{
  ssh_mprz_init(ret);
  ssh_mprz_set_ui(ret, u);
}

/* Negate an integer. This is very easy operation. */
void ssh_mprz_neg(SshMPInteger ret, SshMPIntegerConst op)
{
  ssh_mprz_set(ret, op);
  if (ret->n)
    SSH_MP_XOR_SIGN(ret);
}

/* Get the absolute of an integer, basically a distance in Z. */
void ssh_mprz_abs(SshMPInteger ret, SshMPIntegerConst op)
{
  ssh_mprz_set(ret, op);
  SSH_MP_NO_SIGN(ret);
}


/* The sign of an integer. We follow here the standard practice of
   naming the function. However, some call it just sign, but in
   number theory I have read about it as signum. */
int ssh_mprz_signum(SshMPIntegerConst op)
{
  if (op->n == 0)
    return 0;
  if (SSH_MP_GET_SIGN(op))
    return -1;
  return 1;
}

/* These routines are written to be quick enough to be used in general.
   In some particular cases faster ways might be available. */

void ssh_mprz_mul_2exp(SshMPInteger ret,
                       SshMPIntegerConst op, unsigned int bits)
{
  unsigned int k, i;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  /* Check if no need to to anything. */
  if (op->n == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  if (bits == 0)
    {
      ssh_mprz_set(ret, op);
      return;
    }

  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  /* Move from op to ret. */
  ssh_mprz_set(ret, op);

  /* Allocate new space. */
  if (!ssh_mprz_realloc(ret, k + 1 + ret->n))
    return;

  /* Move words first. */
  if (k)
    {
      for (i = ret->n; i; i--)
        ret->v[i + k - 1] = ret->v[i - 1];
      for (i = 0; i < k; i++)
        ret->v[i] = 0;
    }

  /* Set the possible highest word to zero. */
  ret->v[k + ret->n] = 0;
  ssh_mpk_shift_up_bits(ret->v + k, ret->n + 1, bits);

  /* Compute the correct size. */
  ret->n = ret->n + k + 1;

  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  /* Remember the sign thing. */
  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

void ssh_mprz_div_2exp(SshMPInteger ret,
                       SshMPIntegerConst op, unsigned int bits)
{
  unsigned int k, i;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  /* Check sizes. */
  if (op->n == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  if (bits == 0)
    {
      ssh_mprz_set(ret, op);
      return;
    }

  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  if (k >= op->n)
    {
      ret->n = 0;
      return;
    }

  /* Move from op to ret. */
  ssh_mprz_set(ret, op);

  if (ssh_mprz_isnan(ret))
    return;

  /* Move down. */
  if (k)
    for (i = 0; i < ret->n - k; i++)
      ret->v[i] = ret->v[i + k];

  ssh_mpk_shift_down_bits(ret->v, ret->n - k, bits);

  /* Compute new size. */
  ret->n = ret->n - k;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

void ssh_mprz_mod_2exp(SshMPInteger ret,
                       SshMPIntegerConst op, unsigned int bits)
{
  unsigned int k;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  /* Check for trivial cases. */
  if (op->n == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  if (bits == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  /* Now copy to the ret. This might not be the optimal way but easy.  */
  ssh_mprz_set(ret, op);

  /* Check yet one more trivial case. We might be done already. */
  if (k >= ret->n)
    return;

  /* Now we have to do the very hard part. */
  ret->v[k] = (ret->v[k] & (((SshWord)1 << bits) - 1));

  /* Check sizes. */
  ret->n = k + 1;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Comparison function which use directly the ssh_mpk_* functions. */
int ssh_mprz_cmp(SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  int rv;

  /* Two NaNs are unequal, and a NaN is not equal to any integer. */
  if (ssh_mprz_isnan(op1) || ssh_mprz_isnan(op2))
    return 1;

  /* Handle signs. */
  if (SSH_MP_GET_SIGN(op1) || SSH_MP_GET_SIGN(op2))
    {
      if (SSH_MP_GET_SIGN(op1) && !SSH_MP_GET_SIGN(op2))
        return -1;
      if (!SSH_MP_GET_SIGN(op1) && SSH_MP_GET_SIGN(op2))
        return 1;
    }
  rv = ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n);
  if (SSH_MP_GET_SIGN(op1) || SSH_MP_GET_SIGN(op2))
    rv = -rv;
  return rv;
}

int ssh_mprz_cmp_ui(SshMPIntegerConst op, SshWord u)
{
  if (ssh_mprz_isnan(op))
    return 1;

  if (SSH_MP_GET_SIGN(op))
    return -1;
  return ssh_mpk_cmp_ui(op->v, op->n, u);
}

/* Addition routine which handles signs. */

void ssh_mprz_add(SshMPInteger ret,
                  SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  SshWord c;

  if (ssh_mprz_nanresult2(ret, op1, op2))
    return;

  if (op1->n == 0)
    {
      ssh_mprz_set(ret, op2);
      return;
    }

  if (op2->n == 0)
    {
      ssh_mprz_set(ret, op1);
      return;
    }

  /* Make op1 > op2 in absolute value. Also enlarge ret so that the
     result fits into it. */

  if (op1->n < op2->n)
    {
      SshMPIntegerConst  t;

      t   = op1;
      op1 = op2;
      op2 = t;
    }

  if (op1->n + 1 > ret->n)
    {
      if (!ssh_mprz_realloc(ret, op1->n + 1))
        return;
    }

  /* Then figure out which case it really is. This idea of
     switching cames from my small floating point library that I
     wrote year ago. */

  switch ((SSH_MP_GET_SIGN(op1) << 1) + SSH_MP_GET_SIGN(op2))
    {
    case 0:
      c = ssh_mpk_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      SSH_MP_NO_SIGN(ret);
      break;
    case 1:
      if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpk_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_NO_SIGN(ret);
        }
      else
        {
          ssh_mpk_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_SET_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 2:
      if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpk_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_SET_SIGN(ret);
        }
      else
        {
          ssh_mpk_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_NO_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 3:
      c = ssh_mpk_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      SSH_MP_SET_SIGN(ret);
      break;
    }

  /* Following code should be place into either a macro or a function. */

  /* Correct the size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Subtraction routine which handles signs. */

void ssh_mprz_sub(SshMPInteger ret, SshMPIntegerConst op1,
                  SshMPIntegerConst op2)
{
  SshWord c;
  unsigned int signs;

  if (ssh_mprz_nanresult2(ret, op1, op2))
    return;

  if (op2->n == 0)
    {
      ssh_mprz_set(ret, op1);
      return;
    }

  if (op1->n == 0)
    {
      ssh_mprz_neg(ret, op2);
      return;
    }

  /* Make op1 > op2 in absolute value. Also enlarge ret so that the
     result fits in it. */

  if (op1->n < op2->n)
    {
      SshMPIntegerConst t;

      t = op1;
      op1 = op2;
      op2 = t;

      signs = ((SSH_MP_GET_SIGN(op1) ^ 0x1) << 1) + SSH_MP_GET_SIGN(op2);
    }
  else
    signs = (SSH_MP_GET_SIGN(op1) << 1) + (SSH_MP_GET_SIGN(op2) ^ 0x1);

  if (op1->n + 1 > ret->n)
    {
      if (!ssh_mprz_realloc(ret, op1->n + 1))
        return;
    }

  /* Then figure out which case it really is. Note the difference between
     addition and subtraction. */

  switch (signs)
    {
    case 0:
      c = ssh_mpk_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      /* No sign for ret. */
      SSH_MP_NO_SIGN(ret);
      break;
    case 1:
      if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpk_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_NO_SIGN(ret);
        }
      else
        {
          ssh_mpk_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_SET_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 2:
      if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpk_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_SET_SIGN(ret);
        }
      else
        {
          ssh_mpk_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_NO_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 3:
      c = ssh_mpk_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      SSH_MP_SET_SIGN(ret);
      break;
    }

  /* Following code should be place into either a macro or a function. */

  /* Correct the size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Addition of a SshMPInteger and an SshWord. */
void ssh_mprz_add_ui(SshMPInteger ret, SshMPIntegerConst op, SshWord u)
{
  SshWord c;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  if (op->n == 0)
    {
      ssh_mprz_set_ui(ret, u);
      return;
    }

  if (!ssh_mprz_realloc(ret, op->n + 1))
    return;

  switch (SSH_MP_GET_SIGN(op))
    {
    case 0:
      c = ssh_mpk_add(ret->v, op->v, op->n, &u, 1);
      if (c)
        {
          ret->v[op->n] = c;
          ret->n = op->n + 1;
        }
      else
        ret->n = op->n;
      SSH_MP_NO_SIGN(ret);
      break;
    case 1:
      if (ssh_mpk_cmp_ui(op->v, op->n, u) > 0)
        {
          ssh_mpk_sub(ret->v, op->v, op->n, &u, 1);
          SSH_MP_SET_SIGN(ret);
        }
      else
        {
          ssh_mpk_sub(ret->v, &u, 1, op->v, op->n);
          SSH_MP_NO_SIGN(ret);
        }
      ret->n = op->n;
      break;
    }

  /* Check size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Subtraction of an unsigned integer from a SshMPInteger. */
void ssh_mprz_sub_ui(SshMPInteger ret, SshMPIntegerConst op, SshWord u)
{
  SshWord c;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  if (op->n == 0)
    {
      ssh_mprz_set_ui(ret, u);
      if (ret->n)
        SSH_MP_XOR_SIGN(ret);
      return;
    }

  if (!ssh_mprz_realloc(ret, op->n + 1))
    return;

  switch (SSH_MP_GET_SIGN(op))
    {
    case 0:
      if (ssh_mpk_cmp_ui(op->v, op->n, u) > 0)
        {
          ssh_mpk_sub(ret->v, op->v, op->n, &u, 1);
          SSH_MP_NO_SIGN(ret);
        }
      else
        {
          ssh_mpk_sub(ret->v, &u, 1, op->v, op->n);
          SSH_MP_SET_SIGN(ret);
        }
      ret->n = op->n;
      break;
    case 1:
      c = ssh_mpk_add(ret->v, op->v, op->n, &u, 1);
      if (c)
        {
          ret->v[op->n] = c;
          ret->n = op->n + 1;
        }
      else
        ret->n = op->n;
      SSH_MP_SET_SIGN(ret);
      break;
    }

  /* Check size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Multiplication routine. */
void ssh_mprz_mul(SshMPInteger ret,
                  SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *temp;
  unsigned int temp_n;

  if (ssh_mprz_nanresult2(ret, op1, op2))
    return;

  /* Check the inputs. */
  if (op1->n == 0 || op2->n == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  /* Allocate some temporary memory. */
  temp_n = op1->n + op2->n + 1;
  if (!ssh_mprz_realloc(ret, temp_n))
    return;

  if (op1->v == ret->v || op2->v == ret->v)
    {
      SSH_MP_WORKSPACE_ALLOC(temp, temp_n);
      if (!temp)
        {
          ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
          return;
        }
    }
  else
    temp = ret->v;

  ssh_mpk_memzero(temp, temp_n);

  /* Do the multiplication. */
  if (!ssh_mpk_mul_karatsuba(temp, temp_n, op1->v, op1->n, op2->v, op2->n,
                             NULL, 0))
    {
      if (temp != ret->v)
        SSH_MP_WORKSPACE_FREE(temp);
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  /* Check the exact length of the result. */

  while (temp_n && temp[temp_n - 1] == 0)
    temp_n--;

  /* Check the sign. */
  SSH_MP_XOR_SIGNS(ret, op1, op2);

  /* Finish by copying result to ret. */
  if (ret->v != temp)
    {
      ssh_mpk_memcopy(ret->v, temp, temp_n);
      SSH_MP_WORKSPACE_FREE(temp);
    }

  ret->n = temp_n;
}

/* Squaring routine. */

void ssh_mprz_square(SshMPInteger ret, SshMPIntegerConst op)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *temp;
  unsigned int temp_n;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  /* Check the inputs. */
  if (op->n == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  /* Allocate some temporary memory. */
  temp_n = op->n * 2 + 2;
  if (!ssh_mprz_realloc(ret, temp_n))
    return;

  if (op->v == ret->v)
    {
      SSH_MP_WORKSPACE_ALLOC(temp, temp_n);
      if (!temp)
        {
          ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
          return;
        }
    }
  else
    temp = ret->v;

  ssh_mpk_memzero(temp, temp_n);

  /* Do the multiplication. */
  if (!ssh_mpk_square_karatsuba(temp, temp_n, op->v, op->n,
                                NULL, 0))
    {
      if (temp != ret->v)
        SSH_MP_WORKSPACE_FREE(temp);
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  /* Check the exact length of the result. */

  while (temp_n && temp[temp_n - 1] == 0)
    temp_n--;

  /* Squaring, thus no sign! */
  SSH_MP_NO_SIGN(ret);

  /* Finish by copying result to ret. */
  if (ret->v != temp)
    {
      ssh_mpk_memcopy(ret->v, temp, temp_n);
      SSH_MP_WORKSPACE_FREE(temp);
    }

  ret->n = temp_n;
}

/* Compute the remainder i.e. op1 (mod op2). */
void ssh_mprz_mod(SshMPInteger r,
                  SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *rem, *div;
  unsigned int rem_n, bits, div_n;

  if (ssh_mprz_nanresult2(r, op1, op2))
    return;

  /* Check sizes first. */
  if (op1->n == 0)
    {
      ssh_mprz_set_ui(r, 0);
      return;
    }

  if (op1->n < op2->n)
    {
      if (SSH_MP_GET_SIGN(op1))
        {
          ssh_mprz_add(r, op2, op1);
          return;
        }
      ssh_mprz_set(r, op1);
      return;
    }

  if (op1->n == op2->n)
    {
      if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) < 0)
        {
          if (SSH_MP_GET_SIGN(op1))
            {
              ssh_mprz_add(r, op2, op1);
              return;
            }
          ssh_mprz_set(r, op1);
          return;
        }
    }

  rem_n = op1->n + 1;
  div_n = op2->n;

  /* Do some reallocation. */
  if (!ssh_mprz_realloc(r, op2->n))
    return;

  /* Allocate temporary space. */
  SSH_MP_WORKSPACE_ALLOC(rem, (rem_n + div_n));
  if (!rem)
    {
      ssh_mprz_makenan(r, SSH_MP_NAN_ENOMEM);
      return;
    }
  div  = rem + rem_n;

  /* Clear and copy. */
  ssh_mpk_memcopy(rem, op1->v, op1->n);
  rem[op1->n] = 0;




  ssh_mpk_memcopy(div, op2->v, op2->n);

  bits = ssh_mpk_leading_zeros(div, op2->n);
  ssh_mpk_shift_up_bits(div, op2->n, bits);
  ssh_mpk_shift_up_bits(rem, rem_n, bits);

  /* Certify the length. */
  if (rem[rem_n - 1] == 0)
    rem_n--;

  /* Do the division iteration. */
  if (!ssh_mpk_mod(rem, rem_n, div, op2->n))
    {
      SSH_MP_WORKSPACE_FREE(rem);
      ssh_mprz_makenan(r, SSH_MP_NAN_EDIVZERO);
      return;
    }

  /* Quotient is immediately correct. However, remainder must be
     denormalized. */
  ssh_mpk_shift_down_bits(rem, op2->n, bits);

  /* Check sizes. */
  rem_n = op2->n;
  while (rem_n && rem[rem_n - 1] == 0)
    rem_n--;

  /* Handle possible negative input here. */
  if (SSH_MP_GET_SIGN(op1))
    {
      ssh_mpk_sub(rem, op2->v, op2->n, rem, rem_n);

      /* Check size again. */
      rem_n = op2->n;
      while (rem_n && rem[rem_n - 1] == 0)
        rem_n--;
    }

  /* Set the remainder. */
  r->n = rem_n;
  ssh_mpk_memcopy(r->v, rem, rem_n);
  SSH_MP_WORKSPACE_FREE(rem);

  /* Remainder has no sign (it is always positive). */
  SSH_MP_NO_SIGN(r);
}

/* Extra routines for special numbers. */

void ssh_mprz_mul_ui(SshMPInteger ret,
                     SshMPIntegerConst op, SshWord u)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *temp;
  unsigned int temp_n;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  if (u == 0 || op->n == 0)
    {
      ssh_mprz_set_ui(ret, 0);
      return;
    }

  temp_n = op->n + 1;
  if (!ssh_mprz_realloc(ret, temp_n))
    return;

  if (op->v != ret->v)
    temp = ret->v;
  else
    {
      SSH_MP_WORKSPACE_ALLOC(temp, temp_n);
      if (!temp)
        {
          ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
          return;
        }
    }

  ssh_mpk_memzero(temp, temp_n);

  /* Multiply. */
  ssh_mpk_mul_ui(temp, op->v, op->n, u);

  /* Finish the management. */
  if (temp != ret->v)
    {
      ssh_mpk_memcopy(ret->v, temp, temp_n);
      SSH_MP_WORKSPACE_FREE(temp);
    }

  ret->n = temp_n;

  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  SSH_MP_COPY_SIGN(ret, op);
}


SshWord ssh_mprz_divrem_ui(SshMPInteger q,
                           SshMPIntegerConst op, SshWord u)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *temp, *norm, t, rem;
  SshWord norm_array[SSH_MP_INTEGER_STATIC_ARRAY_SIZE + 1];
  Boolean dynamic;
  unsigned int temp_n, r;
  Boolean wp_alloc = FALSE;

  if (ssh_mprz_nanresult1(q, op))
    return 0;

  if (u == 0)
    {
      ssh_mprz_makenan(q, SSH_MP_NAN_EDIVZERO);
      return 0;
    }

  if (op->n == 0)
    {
      ssh_mprz_set_ui(q, 0);
      return 0;
    }

  /* Figure out the normalization of 'u'. */
  t = u;
  SSH_MPK_COUNT_LEADING_ZEROS(r, t);
  t <<= r;

  /* Enlarge integers. */
  temp_n = op->n + 1;

  if (!ssh_mprz_realloc(q, temp_n))
    return 0;

  if (q->v != op->v)
    temp = q->v;
  else
    {
      SSH_MP_WORKSPACE_ALLOC(temp, temp_n);
      wp_alloc = TRUE;
      if (temp == NULL)
        {
          ssh_mprz_makenan(q, SSH_MP_NAN_ENOMEM);
          return 0;
        }
    }

  if (op->n <= SSH_MP_INTEGER_STATIC_ARRAY_SIZE)
    {
      memset(norm_array, 0, SSH_MP_INTEGER_STATIC_ARRAY_SIZE + 1);
      norm = norm_array;
      dynamic = FALSE;
    }
  else
    {
      /* Normalize. */
      dynamic = TRUE;
      if ((norm = ssh_malloc(sizeof(SshWord) * (op->n + 1))) == NULL)
        {
          if (wp_alloc == TRUE)
            SSH_MP_WORKSPACE_FREE(temp);
          ssh_mprz_makenan(q, SSH_MP_NAN_ENOMEM);
          return 0;
        }
  }

  ssh_mpk_memcopy(norm, op->v, op->n);
  norm[op->n] = 0;

  ssh_mpk_shift_up_bits(norm, op->n + 1, r);

  rem = ssh_mpk_div_ui(temp, temp_n, norm, op->n + 1, t);

  if (dynamic)
    ssh_free(norm);

  /* Correct remainder. */
  rem >>= r;

  /* Quotient is correct. */
  if (temp != q->v)
    {
      ssh_mpk_memcopy(q->v, temp, temp_n);
      if (wp_alloc == TRUE)
        SSH_MP_WORKSPACE_FREE(temp);
    }

  /* Set the size. */
  q->n = temp_n;

  while (q->n && q->v[q->n - 1] == 0)
    q->n--;

  if (q->n == 0)
    SSH_MP_NO_SIGN(q);

  return rem;
}

void ssh_mprz_div_ui(SshMPInteger q,
                     SshMPIntegerConst op, SshWord u)
{
  ssh_mprz_divrem_ui(q, op, u);
}

/* Miscellaneous, these will be useful later. */

/* Compute the size of integer 'op' in base 'base'. Slow in many cases,
   but fast in base 2.  */
unsigned int ssh_mprz_get_size(SshMPIntegerConst op, SshWord base)
{
  unsigned int digits;
  SshMPIntegerStruct temp;

  if (ssh_mprz_isnan(op))
    return 0;

  switch (base)
    {
    case 0:
    case 1:
      return 0;
    case 2:
      /* Exact bit size quickly. */
      return ssh_mpk_size_in_bits(op->v, op->n);
    default:
      /* Use division to divide to the base. Clearly this is slow, but
         this will be used only rarely. */
      ssh_mprz_init(&temp);
      ssh_mprz_set(&temp, op);
      if (ssh_mprz_cmp_ui(&temp, 0) < 0)
        ssh_mprz_neg(&temp, &temp);
      for (digits = 0; temp.n; digits++)
        ssh_mprz_divrem_ui(&temp, &temp, base);
      ssh_mprz_clear(&temp);
      return digits;
    }
}

/* Get a bit at position 'bit'. Returns thus either 1 or 0. */
unsigned int ssh_mprz_get_bit(SshMPIntegerConst op, unsigned int bit)
{
  unsigned int i;

  if (ssh_mprz_isnan(op) || op->n == 0)
    return 0;

  /* Find out the amount of words. */
  i = bit / SSH_WORD_BITS;
  bit %= SSH_WORD_BITS;

  /* Too large. */
  if (i >= op->n)
    return 0;

  return (op->v[i] >> bit) & 0x1;
}

/* Set a bit at position 'bit'. */
void ssh_mprz_set_bit(SshMPInteger op, unsigned int bit)
{
  unsigned int i;

  if (ssh_mprz_isnan(op))
    return;

  /* Find out the amount of words. */
  i = bit / SSH_WORD_BITS;
  bit %= SSH_WORD_BITS;

  /* Allocate some new space and clear the extra space. */
  if (!ssh_mprz_realloc(op, i + 1))
    return;

  ssh_mprz_clear_extra(op);

  op->v[i] |= ((SshWord)1 << bit);

  if (op->n < i + 1)
    op->n = i + 1;
}


/* Print routine. */

/* These are useful for hex and less bases. */
const unsigned char ssh_mprz_int_to_char[16] =
  { "0123456789abcdef" };

const unsigned char ssh_mprz_char_to_int[128] =
  {
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    0,   1,   2,   3,   4,   5,   6,   7,
    8,   9, 255, 255, 255, 255, 255, 255,
    255,  10,  11,  12,  13,  14,  15, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255,  10,  11,  12,  13,  14,  15, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
  };

/* These are useful for bases upto hexes, that is most
   importantly base 64. */
const unsigned char ssh_mprz_int_to_base64[64] =
  { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

const unsigned char ssh_mprz_base64_to_int[128] =
  {
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,
    60,  61, 255, 255, 255, 255, 255, 255,
    255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,
    23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,
    33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255,
  };

/* Transform the integer into a string format in base 'base'. */
char *ssh_mprz_get_str(SshMPIntegerConst op, SshWord base)
{
  SshMPIntegerStruct temp;
  unsigned int digits, real_digits, i, j, l;
  SshWord k, d;
  char *str;
  const unsigned char *table;
  Boolean sign = FALSE;

  /* Cannot handle larger than base 64 numbers nor smaller than 2. */
  if (base > 64 || base < 2)
    return NULL;


  if (op == NULL)
    return NULL;

  if (ssh_mprz_isnan(op))
    {
      if (op->nankind == SSH_MP_NAN_ENOMEM)
        return NULL;
      if (op->nankind == SSH_MP_NAN_EDIVZERO)
        return ssh_strdup("<NaN: divzero>");
      if (op->nankind == SSH_MP_NAN_EVENMOD)
        return ssh_strdup("<NaN: even modulus>");
      if (op->nankind == SSH_MP_NAN_ENEGPOWER)
        return ssh_strdup("<NaN: negative exponent");

      return NULL;
    }

  if (base <= 16)
    table = ssh_mprz_int_to_char;
  else
    table = ssh_mprz_int_to_base64;

  if (ssh_mprz_cmp_ui(op, 0) == 0)
    {
      if ((str = ssh_calloc(1, 10)) == NULL)
        return NULL;

      if (base <= 16)
        {
          str[0] = '0';
          str[1] = '\0';
        }
      else
        {
          str[0] = 'A';
          str[1] = '\0';
        }
      return str;
    }

  ssh_mprz_init(&temp);
  ssh_mprz_set(&temp, op);

  real_digits = digits = ssh_mprz_get_size(op, base);

  if (ssh_mprz_cmp_ui(&temp, 0) < 0)
    {
      digits++;
      sign = TRUE;
      ssh_mprz_neg(&temp, &temp);
    }

  switch (base)
    {
    case 8:
      digits++;
      break;
    case 16:
      digits += 2;
      break;
    case 64:
      digits++;
      break;
    default:
      break;
    }

  if (digits < 10)
    {
      if ((str = ssh_calloc(1, 10)) == NULL)
        return NULL;
    }
  else
    {
      if ((str = ssh_calloc(1, digits + 1)) == NULL)
        return NULL;
    }

  /* This is a very slow way to compute. We should atleast optimize this
     to take care of cases when base = 2^n. */

  for (j = 1, d = base; ;
       d = k, j++)
    {
      k = d * base;
      if (k / base != d)
        break;
    }

  for (i = 0; i < real_digits && temp.n; i += j)
    {
      k = ssh_mprz_divrem_ui(&temp, &temp, d);

      if (j + i > real_digits)
        j = real_digits - i;

      for (l = 0; l < j; l++)
        {
          str[(digits - (1 + i + l))] = table[k % base];
          k /= base;
        }
    }

  ssh_mprz_clear(&temp);

  /* Set the beginning to indicate the sign and base. */
  i = 0;
  if (sign)
    {
      str[0] = '-';
      i = 1;
    }

  switch (base)
    {
    case 8:
      str[i] = '0';
      break;
    case 16:
      str[i] = '0';
      str[i + 1] = 'x';
      break;
    case 64:
      str[i] = '#';
      break;
    default:
      break;
    }

  str[digits] = '\0';
  return str;
}

/* Convert a string into an integer in base 'base'. */
int ssh_mprz_set_str(SshMPInteger op, const char *str, SshWord base)
{
  size_t size = strlen(str);
  size_t i;
  const unsigned char *table;
  Boolean sign = FALSE;
  SshWord k, d, s;
  unsigned int j, l;

  /* Init with zero. */
  ssh_mprz_set_ui(op, 0);

  /* Skip leading whitespace and signs. */
  for (i = 0; i < size; i++)
    {
      switch (str[i])
        {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
          break;
        case '-':
          if (!sign)
            {
              sign = TRUE;
              break;
            }
          return 0;
          break;
        case '0':
          /* Either base 8 or base 16. */
          if (tolower(((const unsigned char *)str)[i + 1]) == 'x')
            {
              /* Base-16. */
              if (base == 16 || base == 0)
                {
                  table = ssh_mprz_char_to_int;
                  base = 16;
                  i += 2;
                  goto read_number;
                }
            }
          if (isdigit((unsigned char)str[i + 1]))
            {
              /* Base-8 */
              if (base == 8 || base == 0)
                {
                  table = ssh_mprz_char_to_int;
                  base = 8;
                  i++;
                  goto read_number;
                }
            }
          if (base == 0)
            return 0;
          if (base <= 16)
            table = ssh_mprz_char_to_int;
          else
            table = ssh_mprz_base64_to_int;
          goto read_number;
          break;
        case '#':
          /* Base-64. */
          if (base == 64 || base == 0)
            {
              table = ssh_mprz_base64_to_int;
              base = 64;
              i++;
              goto read_number;
            }
          return 0;
          break;
        default:
          /* Any base or base-10 */
          if (base == 0)
            base = 10;
          if (base <= 16)
            table = ssh_mprz_char_to_int;
          else
            table = ssh_mprz_base64_to_int;
          goto read_number;
          break;
        }
    }

  /* No number to read. */
  return 0;

 read_number:

  /* Generate large divisor. */
  for (j = 1, d = base;;
       d = k, j++)
    {
      k = d * base;
      if ((k / base) != d)
        break;
    }

  /* Loop through the string. */
  for (l = 0, k = 0; i <= size; i++)
    {
      switch (str[i])
        {
        case '\t':
        case ' ':
        case '\n':
          continue;
        }

      s = table[(unsigned char)(str[i] & 127)];
      if (s == 255)
        break;
      if (s >= base)
        break;

      k *= base;
      k += s;

      l++;
      if (l == j)
        {
          ssh_mprz_mul_ui(op, op, d);
          ssh_mprz_add_ui(op, op, k);
          l = 0;
          k = 0;
        }
    }

  /* Finish it off. */
  if (l)
    {
      for (i = 1, d = base; i < l; i++)
        d *= base;

      ssh_mprz_mul_ui(op, op, d);
      ssh_mprz_add_ui(op, op, k);
    }

  if (sign)
    ssh_mprz_neg(op, op);

  /* Return the number of limbs used. */
  return 1;
}

/* Linearizing the multiple precision integer to a stream of 8 bit octets. */

size_t ssh_mprz_to_buf(unsigned char *cp, size_t len, SshMPIntegerConst x)
{
  unsigned long limb;
  size_t i;
  SshMPIntegerStruct aux;

  ssh_mprz_init_set(&aux, x);
  if (ssh_mprz_isnan(&aux))
    return 0;

  for (i = len; i >= 4; i -= 4)
    {
      limb = ssh_mprz_get_ui(&aux);
      SSH_PUT_32BIT(cp + i - 4, limb);
      ssh_mprz_div_2exp(&aux, &aux, 32);
      if (ssh_mprz_isnan(&aux))
        {
          ssh_mprz_clear(&aux);
          return 0;
        }
    }
  for (; i > 0; i--)
    {
      cp[i - 1] = (unsigned char)(ssh_mprz_get_ui(&aux) & 0xff);
      ssh_mprz_div_2exp(&aux, &aux, 8);
      if (ssh_mprz_isnan(&aux))
        {
          ssh_mprz_clear(&aux);
          return 0;
        }
    }

  ssh_mprz_clear(&aux);
  return len;
}

/* Converting a stream of 8 bit octets to multiple precision integer. */

void ssh_buf_to_mp(SshMPInteger x, const unsigned char *cp, size_t len)
{
  size_t i;
  unsigned long limb;

  ssh_mprz_set_ui(x, 0);
  for (i = 0; i + 4 <= len; i += 4)
    {
      limb = SSH_GET_32BIT(cp + i);
      ssh_mprz_mul_2exp(x, x, 32);
      ssh_mprz_add_ui(x, x, limb);
    }
  for (; i < len; i++)
    {
      ssh_mprz_mul_2exp(x, x, 8);
      ssh_mprz_add_ui(x, x, cp[i]);
    }
}


/* Faster routines of the above quick and dirty routines. */
size_t ssh_mprz_get_buf(unsigned char *buf, size_t buf_length,
                        SshMPIntegerConst op)
{
  size_t i, j, k;

  /* Set up k. */
  k = buf_length;

  if (op == NULL)
    {
      strncpy((char *)buf, "<NaN: nomemory>", buf_length);
      return 0;
    }
  if (ssh_mprz_isnan(op))
    {
      if (op->nankind == SSH_MP_NAN_ENOMEM)
        strncpy((char *)buf, "<NaN: nomemory>", buf_length);
      if (op->nankind == SSH_MP_NAN_EDIVZERO)
        strncpy((char *)buf, "<NaN: divzero>", buf_length);
      if (op->nankind == SSH_MP_NAN_EVENMOD)
        strncpy((char *)buf, "<NaN: even modulus>", buf_length);
      if (op->nankind == SSH_MP_NAN_ENEGPOWER)
        strncpy((char *)buf, "<NaN: negative exponent>", buf_length);

      return 0;
    }

  /* Check if the buffer is large enough to correctly encode the integer. */
  if (buf_length < ssh_mprz_byte_size(op))
    return 0;

  /* Loop through all the words in the big number. */
  for (i = 0; i < op->n && k; i++)
    {
      SshWord w = op->v[i];

      /* Run through all the bytes of the input.

      Remark. In special cases (when k*8 >= SSH_WORD_BITS) we could
      be slightly faster than this.
      */
      for (j = 0; j < SSH_WORD_BITS && k; j += 8, k--)
        {
          buf[k-1] = (unsigned char)(w & 0xff);
          w >>= 8;
        }
    }

  i = k;

  /* Clean up the rest of the buffer. */
  for (; k; k--)
    buf[k - 1] = 0x0;

  /* Scan out the extra 0's we might have left in the buffer.
     Note that we add one extra to the i in this loop. */
  while (buf[i++] == 0);

  return (i);
}

void ssh_mprz_set_buf(SshMPInteger ret,
                      const unsigned char *buf, size_t buf_length)
{
  size_t i, j, k;

  /* Compute the size of the buffer, in words. */
  k = (buf_length + (SSH_WORD_BITS/8) - 1)/(SSH_WORD_BITS/8);

  /* Reallocate enough space. */
  if (!ssh_mprz_realloc(ret, k + 1))
    return;

  /* Set k as one beyond the buffer. */
  k = buf_length;

  for (i = 0; k; i++)
    {
      SshWord w;

      /* Build the word. */
      for (j = 0, w = 0; j < SSH_WORD_BITS && k; j += 8, k--)
        w += (((SshWord)buf[k-1]) << j);

      ret->v[i] = w;
    }

  ret->n = i;
  while (ret->n && ret->v[ret->n-1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}



size_t ssh_mprz_get_buf_lsb_first(unsigned char *buf,
                                  size_t buf_length,
                                  SshMPIntegerConst op)
{
  size_t i, j, k;

  /* Set up k. */
  k = 0;
  memset(buf, 0, buf_length);

  if (op == NULL)
    {
      strncpy((char *)buf, "<NaN: nomemory>", buf_length);
      return 0;
    }
  if (ssh_mprz_isnan(op))
    {
      if (op->nankind == SSH_MP_NAN_ENOMEM)
        strncpy((char *)buf, "<NaN: nomemory>", buf_length);
      if (op->nankind == SSH_MP_NAN_EDIVZERO)
        strncpy((char *)buf, "<NaN: divzero>", buf_length);
      if (op->nankind == SSH_MP_NAN_EVENMOD)
        strncpy((char *)buf, "<NaN: even modulus>", buf_length);
      if (op->nankind == SSH_MP_NAN_ENEGPOWER)
        strncpy((char *)buf, "<NaN: negative exponent>", buf_length);

      return 0;
    }

  /* Check if the buffer is large enough to correctly encode the integer. */
  if (buf_length < ssh_mprz_byte_size(op))
    return 0;

  /* Loop through all the words in the big number. */
  for (i = 0; i < op->n && k < buf_length; i++)
    {
      SshWord w = op->v[i];

      /* Run through all the bytes of the input.

      Remark. In special cases (when k*8 >= SSH_WORD_BITS) we could
      be slightly faster than this.
      */
      for (j = 0; j < SSH_WORD_BITS && k < buf_length; j += 8, k++)
        {
          buf[k] = (unsigned char)(w & 0xff);
          w >>= 8;
        }
    }

  i = k;

  return (buf_length - i - 1);
}

void ssh_mprz_set_buf_lsb_first(SshMPInteger ret,
                                const unsigned char *buf,
                                size_t buf_length)
{
  size_t i, j, k;

  /* Compute the size of the buffer, in words. */
  k = (buf_length + (SSH_WORD_BITS/8) - 1)/(SSH_WORD_BITS/8);

  /* Reallocate enough space. */
  if (!ssh_mprz_realloc(ret, k + 1))
    return;

  /* Set k to zero. */
  k = 0;
  for (i = 0; k < buf_length; i++)
    {
      SshWord w;

      /* Build the word. */
      for (j = 0, w = 0; j < SSH_WORD_BITS && k < buf_length; j += 8, k++)
        w += (((SshWord)buf[k]) << j);

      ret->v[i] = w;
    }

  ret->n = i;
  while (ret->n && ret->v[ret->n-1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}


/* sshencode mp-integer encoder and decoder routines. */

int
ssh_mprz_encode_rendered(unsigned char *buf, size_t len, const void *ptr)
{
  SshMPInteger mp = (void *) ptr;
  unsigned int bits;
  size_t buf_len;

  if (mp)
    {
      bits = ssh_mprz_get_size(mp, 2);
      buf_len = (bits + 7)/8;

      /* Special case. Unnecessary, but funny. */
      if (bits == 0 && len >= 4)
        {
          unsigned char *four = buf;

          SSH_ASSERT(buf != NULL);
          four[0] = four[1] = four[2] = four[3] = 0;

          return 4;
        }

      if (buf_len + 4 > len)
        return len + 1;

      SSH_ASSERT(buf != NULL);

      SSH_PUT_32BIT(buf, bits);
      ssh_mprz_get_buf(buf + 4, buf_len, mp);
      return buf_len + 4;
    }
  else
    return 0;
}

/* This takes in rendered buffer and returns mp-integer from it. */
int
ssh_mprz_decode_rendered(const unsigned char *buf, size_t len, void *ptr)
{
  SshMPInteger mp = ptr;
  unsigned int bits;
  size_t bytes;

  /* Check that there is enough data left for length. */
  if (len < 4) return 4;

  /* Get the number of bits, and convert it to bytes. */
  bits = SSH_GET_32BIT(buf);
  bytes = (bits + 7) / 8;

  /* Check that there is enough data in the buffer. */
  if (len < 4 + bytes) return 4 + bytes;

  /* If not storing the value, just return its length. */
  if (mp == NULL) return 4 + bytes;

  ssh_mprz_set_buf(mp, buf + 4, bytes);

  /* Return its length. */
  return 4 + bytes;
}

/* Encode mp-integer as a string with explicit SshUInt32 length in bytes.

   A call to this:
   SSH_ENCODE_SPECIAL(ssh_mprz_encode_uint32_str, mp)

   is equivalent to:
   len = ssh_mprz_byte_size(mp);
   buf = ssh_malloc(len);
   ssh_mprz_get_buf(buf, len, mp);
   SSH_ENCODE_UINT32_STR(buf, len);
   ssh_free(buf);

   but without the extra memory allocation. */
int
ssh_mprz_encode_uint32_str(unsigned char *buf, size_t len,
                           const void *datum)
{
  SshMPIntegerConst i = (SshMPIntegerConst) datum;
  size_t i_len;

  /* Fetch mp-interger length in bytes. */
  i_len = ssh_mprz_byte_size(i);
  if (len >= 4 + i_len)
    {
      /* Encode length. */
      SSH_PUT_32BIT(buf, i_len);

      /* Encode mp-integer. */
      if (i_len > 0)
        SSH_VERIFY(ssh_mprz_get_buf(buf + 4, i_len, i) != 0);
    }

  return 4 + i_len;
}

/* Decode a string with explicit SshUInt32 length in bytes to a mp-integer.
   The argument `datum' be valid pointer to an initialized SshMPInteger or
   NULL in which case this discards the decode result. This decoder is
   suitable for use with SSH_DECODE_SPECIAL_NOALLOC() decoder macro. */
int
ssh_mprz_decode_uint32_str_noalloc(const unsigned char *buf, size_t len,
                                   void *datum)
{
  SshMPInteger i = (SshMPInteger) datum;
  size_t i_len = 0;

  /* Not enough data for length field. */
  if (len < 4)
    return 4;

  /* Read data length in bytes. */
  i_len = SSH_GET_32BIT(buf);

  /* Not enough data for mp-integer. */
  if (len < 4 + i_len)
    return 4 + i_len;

  /* Decode integer from buffer. If no return value parameter was given
     for result, just ignore the decoded data. */
  if (i != NULL && i_len > 0)
    ssh_mprz_set_buf(i, buf + 4, i_len);

  return 4 + i_len;
}


/* Note that there is no way to distinguish between zero division, a NAN
   argument and divident being zero. */
SshWord ssh_mprz_mod_ui(SshMPIntegerConst op, SshWord u)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *norm, rem, t;
  unsigned int r;

  if (u == 0 || ssh_mprz_isnan(op))
    return 0;

  if (op->n == 0)
    return 0;

  /* Handle the normalization of 'u'. */
  t = u;
  SSH_MPK_COUNT_LEADING_ZEROS(r, t);
  t <<= r;

  /* Allocate and normalize. */
  SSH_MP_WORKSPACE_ALLOC(norm, op->n + 1);
  if (!norm)
    {
      return 0;
    }
  ssh_mpk_memcopy(norm, op->v, op->n);
  norm[op->n] = 0;

  ssh_mpk_shift_up_bits(norm, op->n + 1, r);
  rem = ssh_mpk_mod_ui(norm, op->n + 1, t);

  SSH_MP_WORKSPACE_FREE(norm);

  /* Correct remainder. */
  rem >>= r;

  return rem;
}


/* Division routine. */

void ssh_mprz_divrem(SshMPInteger q, SshMPInteger r,
                     SshMPIntegerConst op1,
                     SshMPIntegerConst op2)
{
  SSH_MP_WORKSPACE_DEFINE;
  SshWord *rem, *quot, *div;
  unsigned int rem_n, quot_n, bits;

  if (ssh_mprz_nanresult2(q, op1, op2))
    return;

  if (ssh_mprz_cmp_ui(op2, 0) == 0)
    {
      ssh_mprz_makenan(q, SSH_MP_NAN_EDIVZERO);
      ssh_mprz_makenan(r, SSH_MP_NAN_EDIVZERO);
      return;
    }

  /* Check sizes first. */
  if (op1->n < op2->n)
    {
      ssh_mprz_set(r, op1);
      ssh_mprz_set_ui(q, 0);
      return;
    }

  if (op1->n == op2->n)
    {
      if (ssh_mpk_cmp(op1->v, op1->n, op2->v, op2->n) < 0)
        {
          ssh_mprz_set(r, op1);
          ssh_mprz_set_ui(q, 0);
          return;
        }
    }

  rem_n = op1->n + 1;
  quot_n = op1->n - op2->n + 1;

  /* Do some reallocation. */
  if (!ssh_mprz_realloc(q, op1->n - op2->n + 1))
    {
      ssh_mprz_makenan(r, SSH_MP_NAN_ENOMEM);
      return;
    }
  if (!ssh_mprz_realloc(r, op2->n))
    {
      ssh_mprz_makenan(q, SSH_MP_NAN_ENOMEM);
      return;
    }

  /* Allocate temporary space. */
  SSH_MP_WORKSPACE_ALLOC(rem, (rem_n + quot_n + op2->n));
  if (!rem)
    {
      ssh_mprz_makenan(r, SSH_MP_NAN_ENOMEM);
      return;
    }
  quot = rem + rem_n;
  div  = quot + quot_n;

  /* Clear and copy. */
  ssh_mpk_memzero(quot, quot_n);
  ssh_mpk_memcopy(rem, op1->v, op1->n);
  rem[op1->n] = 0;




  ssh_mpk_memcopy(div, op2->v, op2->n);

  bits = ssh_mpk_leading_zeros(div, op2->n);
  ssh_mpk_shift_up_bits(div, op2->n, bits);
  ssh_mpk_shift_up_bits(rem, rem_n, bits);

  /* Certify the length. */
  if (rem[rem_n - 1] == 0)
    rem_n--;

  /* Do the division iteration. */
  if (!ssh_mpk_div(quot, quot_n, rem, rem_n, div, op2->n))
    {
      SSH_MP_WORKSPACE_FREE(rem);
      ssh_mprz_makenan(q, SSH_MP_NAN_EDIVZERO);
      return;
    }
  /* Quotient is immediately correct. However, remainder must be
     denormalized. */
  ssh_mpk_shift_down_bits(rem, op2->n, bits);

  /* Now set the quotient. */
  ssh_mpk_memcopy(q->v, quot, quot_n);
  q->n = quot_n;

  /* Set the remainder. */
  ssh_mpk_memcopy(r->v, rem, op2->n);
  r->n = op2->n;

  /* Figure out quotient sign. */
  SSH_MP_XOR_SIGNS(q, op1, op2);

  /* Check sizes. */
  while (q->n && q->v[q->n - 1] == 0)
    q->n--;

  while (r->n && r->v[r->n - 1] == 0)
    r->n--;

  /* Handle the sign of the remainder. */
  if (SSH_MP_GET_SIGN(op1))
    SSH_MP_SET_SIGN(r);
  else
    SSH_MP_NO_SIGN(r);

  /* Make sure that zeros are positive :) */
  if (r->n == 0)
    SSH_MP_NO_SIGN(r);
  if (q->n == 0)
    SSH_MP_NO_SIGN(q);

  /* Free temporary storage. */
  SSH_MP_WORKSPACE_FREE(rem);
}


/* Compute (d, u, v) given (a, b) such that au + bv = d. */
void ssh_mprz_gcdext(SshMPInteger d, SshMPInteger u, SshMPInteger v,
                     SshMPIntegerConst a, SshMPIntegerConst b)
{
  SshMPIntegerStruct v1, v3, t1, t3, d0, u0, x;

  if (ssh_mprz_nanresult2(d, a, b))
    return;

  if (ssh_mprz_cmp_ui(b, 0) == 0)
    {
      ssh_mprz_set(d, a);
      ssh_mprz_set_ui(v, 0);
      ssh_mprz_set_ui(u, 1);
    }

  ssh_mprz_init(&v1);
  ssh_mprz_init(&v3);
  ssh_mprz_init(&t1);
  ssh_mprz_init(&t3);
  ssh_mprz_init(&u0);
  ssh_mprz_init(&d0);
  ssh_mprz_init(&x);

  ssh_mprz_set_ui(&u0, 1);
  ssh_mprz_set(&d0, a);
  ssh_mprz_set_ui(&v1, 0);
  ssh_mprz_set(&v3, b);

  /* Check for zero value using the internal size, which is bit ugly. */
  while (v3.n != 0)
    {
      /* Standard extended GCD algorithm inner loop. See for example
         Cohen's book. */
      ssh_mprz_divrem(&x, &t3, &d0, &v3);
      ssh_mprz_mul(&t1, &x, &v1);
      ssh_mprz_sub(&t1, &u0, &t1);
      ssh_mprz_set(&u0, &v1);
      ssh_mprz_set(&d0, &v3);
      ssh_mprz_set(&v1, &t1);
      ssh_mprz_set(&v3, &t3);

      if (ssh_mprz_isnan(&v3))
        ssh_mprz_makenan(d, v3.nankind);

      if (ssh_mprz_isnan(&v1))
        ssh_mprz_makenan(d, v1.nankind);

      if (ssh_mprz_isnan(d))
        return;
    }

  /* Compute v. */
  ssh_mprz_mul(&t1, a, &u0);
  ssh_mprz_sub(&t1, &d0, &t1);
  ssh_mprz_divrem(&v1, &v3, &t1, b);

  ssh_mprz_set(d, &d0);
  ssh_mprz_set(u, &u0);
  ssh_mprz_set(v, &v1);

  ssh_mprz_clear(&v1);
  ssh_mprz_clear(&v3);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t3);
  ssh_mprz_clear(&d0);
  ssh_mprz_clear(&u0);
  ssh_mprz_clear(&x);
}

/* Naive versions of this routine, which is fairly rarely used. */
void ssh_mprz_gcd(SshMPInteger d,
                  SshMPIntegerConst a, SshMPIntegerConst b)
{
  SshMPIntegerStruct a0, b0, r;

  if (ssh_mprz_nanresult2(d, a, b))
    return;

  ssh_mprz_init(&a0);
  ssh_mprz_init(&b0);
  ssh_mprz_init(&r);

  ssh_mprz_set(&a0, a);
  ssh_mprz_set(&b0, b);

  /* Standard gcd, however, we should implemented much faster ways also. */
  while (ssh_mprz_cmp_ui(&b0, 0) != 0)
    {
      ssh_mprz_mod(&r, &a0, &b0);
      ssh_mprz_set(&a0, &b0);
      ssh_mprz_set(&b0, &r);

      if (ssh_mprz_isnan(&b0))
        {
          ssh_mprz_makenan(d, b0.nankind);
          return;
        }
    }

  ssh_mprz_set(d, &a0);

  ssh_mprz_clear(&a0);
  ssh_mprz_clear(&b0);
  ssh_mprz_clear(&r);
}

/* Naive versions of this routine, which is fairly rarely used. */
void ssh_mprz_div(SshMPInteger ret_q,
                  SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  SshMPIntegerStruct t;

  if (ssh_mprz_nanresult2(ret_q, op1, op2))
    return;

  ssh_mprz_init(&t);
  ssh_mprz_divrem(ret_q, &t, op1, op2);
  ssh_mprz_clear(&t);
}

/* sshmp-integer-core.c */
#endif /* SSHDIST_MATH */
