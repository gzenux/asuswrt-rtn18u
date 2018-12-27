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

   This module together with sshmp-int-core.c comprise the integer
   library. The routines here are not necessary for RSA and
   Diffie-Hellman with predefined keys.
*/

#include "sshincludes.h"
#include "sshmp.h"
#include "sshgetput.h"

#define SSH_DEBUG_MODULE "SshMPIntegerMisc"


#ifdef SSHDIST_MATH
/* The following functions get and set 32 and 64 bit words to and from
   SshMPIntegers. They assume that unsigned long (SshWord) is at least
   32 bits. */

/* Get the lsb 32 bits (unsigned) out of the integer.*/
SshUInt32 ssh_mprz_get_ui32(SshMPIntegerConst op)
{
  SshWord u;

  /* The SshWord is at least 32 bits, so no conversion problem. */
  u = ssh_mprz_get_ui(op);
  return (SshUInt32) u;
}

/* Set the 32 bit unsigned word into op. */
void ssh_mprz_set_ui32(SshMPInteger op, SshUInt32 u)
{
  SshWord w;

  /* The SshWord is at least 32 bits, so no conversion problem. */
  w = (SshWord) u;
  ssh_mprz_set_ui(op, w);
}

/* Get the lsb 64 bits (unsigned) out of the integer. */
SshUInt64 ssh_mprz_get_ui64(SshMPIntegerConst op)
{
#ifdef SSHUINT64_IS_64BITS
#if SIZEOF_LONG < 8
  {
    /* Here SshUint64 is 64 bits and SshWord is less than 64 bits,
       but at least 32 bits. */
    SshUInt64 u;
    SshWord v, w;

    v = ssh_mprz_get_word(op, 0);
    w = ssh_mprz_get_word(op, 1);

    u = (SshUInt64) w;
    u <<= SSH_WORD_BITS;
    u += v;

    return u;
  }
#else /* SIZEOF_LONG < 8 */
  {
    /* The SshWord is at least 64 bits, no conversion problem. */
    SshWord w;
    w = ssh_mprz_get_ui(op);
    return (SshUInt64) w;
  }
#endif /* SIZEOF_LONG < 8 */
#else /* SSHUINT64_IS_64BITS */
  {
    SshWord w;

    /* The SshWord is at least 32 bits, and the SshUInt64 is 32 bits,
       so no conversion problem. */
    w = ssh_mprz_get_ui(op);
    return (SshUInt64) w;
  }
#endif /* SSHUINT64_IS_64BITS */
}

/* Set the 64 bit unsigned word into op. */
void ssh_mprz_set_ui64(SshMPInteger op, SshUInt64 u)
{
#ifdef SSHUINT64_IS_64BITS
#if SIZEOF_LONG >= 8
  /* The SshWord is at least 64 bits, no conversion problem. */
  ssh_mprz_set_ui(op, (SshWord)u);
  return;
#else /* SIZEOF_LONG >= 8 */
  {
    /* Here u is 64 bits and SshWord is less than 64 bits,
       but at least 32 bits. */
    SshWord w;
    w = (SshWord) (u >> SSH_WORD_BITS);
    ssh_mprz_set_ui(op, w);
    ssh_mprz_mul_2exp(op, op, SSH_WORD_BITS);
    ssh_mprz_add_ui(op, op, (SshWord)u);
  return;
  }
#endif /* SIZEOF_LONG >= 8 */
#else /* SSHUINT64_IS_64BITS */
  /* The SshWord is at least 32 bits, and the SshUInt64 u is 32 bits,
     so no conversion problem. */
 ssh_mprz_set_ui(op, (SshWord) u);
#endif /* SSHUINT64_IS_64BITS */
}

SshSignedWord ssh_mprz_get_si(SshMPIntegerConst op)
{
  SshSignedWord si;
  if (op->n == 0)
    return 0;
  /* Figure the bits that can be used. */
  si = (SshSignedWord)(op->v[0] & (SSH_WORD_MASK >> 1));

  if (SSH_MP_GET_SIGN(op))
    return -si;
  return si;
}

void ssh_mprz_set_si(SshMPInteger op, SshSignedWord n)
{
  if (n == 0)
    {
      op->n = 0;
      SSH_MP_NO_SIGN(op);
      return;
    }

  /* Check that we have enough space. */
  if (!ssh_mprz_realloc(op, 1))
    return;

  if (n < 0)
    {
      SSH_MP_SET_SIGN(op);
      n = -n;
    }
  else
    SSH_MP_NO_SIGN(op);
  /* Set the integer. */
  op->v[0] = (SshWord)n;
  op->n = 1;
}

/* Get the lsb 32 bits (signed) out of the integer. The sign is
   determined by the sign of the integer */
SshInt32 ssh_mprz_get_si32(SshMPIntegerConst op)
{
  SshUInt32 u, mask;
  SshInt32 v;

  u = ssh_mprz_get_ui32(op);

  /* Set the msb of u to 0 */
  mask = ~((SshUInt32) 0);
  v = (SshInt32) (u & (mask >> 1));

  if (SSH_MP_GET_SIGN(op))
    return -v;
  return v;
}

/* Set the 32 bit signed word into op. */
void ssh_mprz_set_si32(SshMPInteger op, SshInt32 s)
{
  SshSignedWord si;

  /* The SshSignedWord is at least 32 bits, and the SshInt32 is 32 bits,
     so no conversion problem. */
  si = (SshSignedWord) s;
  ssh_mprz_set_si(op, si);
}


/* Get the lsb 64 bits (signed) out of the integer. The sign is
   determined by the sign of the integer */
SshInt64 ssh_mprz_get_si64(SshMPIntegerConst op)
{
  SshUInt64 u, mask;
  SshInt64 v;

  u = ssh_mprz_get_ui64(op);

  /* Set the msb of u to 0 */
  mask = ~((SshUInt64)0);
  v = (SshInt64) (u & (mask >> 1));

  if (SSH_MP_GET_SIGN(op))
    return -v;
  return v;
}

/* Set the 64 bit signed word into op. */
void ssh_mprz_set_si64(SshMPInteger op, SshInt64 s)
{
  SshUInt64 u;
  Boolean sign = FALSE;

  if (s < 0)
    {
      sign = TRUE;
      s = -s;
    }

  u = (SshUInt64) s;
  ssh_mprz_set_ui64(op, u);

  if (sign)
    SSH_MP_SET_SIGN(op);
}
























































































int ssh_mprz_init_set_str(SshMPInteger ret, const char *str, unsigned int base)
{
  ssh_mprz_init(ret);
  return ssh_mprz_set_str(ret, str, base);
}

void ssh_mprz_init_set_si(SshMPInteger ret, SshSignedWord s)
{
  ssh_mprz_init(ret);
  ssh_mprz_set_si(ret, s);
}

int ssh_mprz_cmp_si(SshMPIntegerConst op, SshSignedWord s)
{
  int rv;
  SshWord sw = 0L;

  if (ssh_mprz_isnan(op))
    return 1;

  if (SSH_MP_GET_SIGN(op) || (s < 0))
    {
      if (SSH_MP_GET_SIGN(op) && (s >= 0))
        return -1;
      if (!SSH_MP_GET_SIGN(op) && (s < 0))
        return 1;
      /* Make s positive. */
      if (s < 0)
        sw = (SshWord)(-s);
    }
  else
    sw = (SshWord)s;
  rv = ssh_mpk_cmp_ui(op->v, op->n, sw);
  if (SSH_MP_GET_SIGN(op) && (s < 0))
    rv = -rv;
  return rv;
}

/* GMP like interface to mod_ui. Just for compatibility. */
SshWord ssh_mprz_mod_ui2(SshMPInteger ret, SshMPIntegerConst op,
                         SshWord u)
{
  SshWord t;

  if (ssh_mprz_nanresult1(ret, op))
    return 0;

  t = ssh_mprz_mod_ui(op, u);
  ssh_mprz_set_ui(ret, t);
  return t;
}

/* Clear a bit at position 'bit'. */
void ssh_mprz_clr_bit(SshMPInteger op, unsigned int bit)
{
  unsigned int i;

  if (ssh_mprz_isnan(op))
    return;

  /* Find out the word offset. */
  i = bit / SSH_WORD_BITS;
  if (i >= op->n)
    return;
  /* Find out the bit offset. */
  bit %= SSH_WORD_BITS;
  op->v[i] &= (~((SshWord)1 << bit));
  /* Normalize. */
  while (op->n > 0 && op->v[op->n-1] == 0)
    op->n--;
}

/* Scan the integer starting from given position 'bitpos' for bit
   with value 'bitval'. Returns new bit position where the bitval
   differs from what was given. */
unsigned int ssh_mprz_scan_bit(SshMPIntegerConst op,
                               unsigned int bitpos,
                               unsigned int bitval)
{
  unsigned int bit = bitpos;

  while (ssh_mprz_get_bit(op, bit) == bitval)
    bit++;
  return bit;
}

/* Random number routines. */

/* 'Find' a random number of 'bits' bits. */
void ssh_mprz_rand(SshMPInteger op, unsigned int bits)
{
  unsigned int i, k;

  /* Compute the word and bit positions. */
  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  if (!ssh_mprz_realloc(op, k + 1))
    return;

  /* Generate enough random bits. */
  for (i = 0; i < k + 1; i++)
    op->v[i] = ssh_rand();

  /* Don't do any shifting? */
  if (bits == 0)
    {
      op->n = k;
      while (op->n && op->v[op->n - 1] == 0)
        op->n--;
      SSH_MP_NO_SIGN(op);
      return;
    }

  /* Trivial shifting, masking... */
  op->v[k] = op->v[k] & (((SshWord)1 << bits) - 1);
  op->n = k + 1;

  while (op->n && op->v[op->n - 1] == 0)
    op->n--;
  SSH_MP_NO_SIGN(op);
}


/* Slow, but so simple to write that I had to do it. */
void ssh_mprz_pow(SshMPInteger ret,
                  SshMPIntegerConst g, SshMPIntegerConst e)
{
  SshMPIntegerStruct temp;
  unsigned int bits, i;

  if (ssh_mprz_nanresult2(ret, g, e))
    return;

  /* Check the sign. */
  if (ssh_mprz_cmp_ui(e, 0) < 0)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENEGPOWER);
      return;
    }

  /* Trivial cases. */
  if (ssh_mprz_cmp_ui(e, 0) == 0)
    {
      ssh_mprz_set_ui(ret, 1);
      return;
    }

  if (ssh_mprz_cmp_ui(e, 1) == 0)
    {
      ssh_mprz_set(ret, g);
      return;
    }

  ssh_mprz_init(&temp);
  ssh_mprz_set(&temp, g);

  /* Compute the size of the exponent. */
  bits = ssh_mpk_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mprz_square(&temp, &temp);
      if (ssh_mprz_get_bit(e, i - 1))
        ssh_mprz_mul(&temp, &temp, g);
    }

  ssh_mprz_set(ret, &temp);
  ssh_mprz_clear(&temp);
}

void ssh_mprz_pow_ui_exp(SshMPInteger ret, SshMPIntegerConst g, SshWord e)
{
  SshMPIntegerStruct temp;

  if (ssh_mprz_nanresult1(ret, g))
    return;

  /* Trivial cases. */
  if (e == 0)
    {
      ssh_mprz_set_ui(ret, 1);
      return;
    }

  if (e == 1)
    {
      ssh_mprz_set(ret, g);
      return;
    }

  ssh_mprz_init(&temp);
  ssh_mprz_set(&temp, g);
  ssh_mprz_set_ui(ret, 1);

  while (e)
    {
      if (e & 1)
        ssh_mprz_mul(ret, ret, &temp);
      e >>= 1; if (!e) break;
      ssh_mprz_square(&temp, &temp);
    }

  ssh_mprz_clear(&temp);
}


/* Simple, but hopefully reasonably efficient. This is almost directly
   from Cohen's book. Improve if more speed is needed, one could open
   things up a bit, but this seems reasonably efficient. */
void ssh_mprz_sqrt(SshMPInteger sqrt_out, SshMPIntegerConst op)
{
  SshMPIntegerStruct x, y, r, t;
  int bits;

  if (ssh_mprz_nanresult1(sqrt_out, op))
    return;

  /* Check impossible cases. */
  if (ssh_mprz_cmp_ui(op, 0) <= 0)
    {
      /* Should we terminate? Perhaps we return the integer part of this
         operation. */
      ssh_mprz_set_ui(sqrt_out, 0);
      return;
    }

  ssh_mprz_init(&x);
  ssh_mprz_init(&y);
  ssh_mprz_init(&r);
  ssh_mprz_init(&t);

  /* Find a nice estimate for n. */
  bits = ssh_mpk_size_in_bits(op->v, op->n);

  /* This should be fairly correct estimate. */
  ssh_mprz_set_bit(&x, (bits + 2)/2);

  /* Loop until a nice value found. */
  while (1)
    {
      /* Compute the newtonian step. */
      ssh_mprz_divrem(&t, &r, op, &x);
      ssh_mprz_add(&t, &t, &x);
      ssh_mprz_div_2exp(&y, &t, 1);

      if (ssh_mprz_cmp(&y, &x) < 0)
        ssh_mprz_set(&x, &y);
      else
        break;
    }

  /* Finished. */
  ssh_mprz_set(sqrt_out, &x);

  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
  ssh_mprz_clear(&r);
  ssh_mprz_clear(&t);
}

/* Basic bit operations, for integers. These are simple, but useful
   sometimes. */
void ssh_mprz_and(SshMPInteger ret,
                  SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  unsigned int i;

  if (ssh_mprz_nanresult2(ret, op1, op2))
    return;

  /* Swap. */
  if (op1->n > op2->n)
    {
      SshMPIntegerConst t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Reallocate. */
  if (!ssh_mprz_realloc(ret, op1->n))
    return;

  /* This can be written more optimally. */
  for (i = 0; i < op1->n; i++)
    ret->v[i] = op1->v[i] & op2->v[i];

  ret->n = op1->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

void ssh_mprz_or(SshMPInteger ret,
                 SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  unsigned int i;

  if (ssh_mprz_nanresult2(ret, op1, op2))
    return;

  /* Swap. */
  if (op1->n > op2->n)
    {
      SshMPIntegerConst t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Reallocate. */
  if (!ssh_mprz_realloc(ret, op2->n))
    return;

  /* This can be written more optimally. */
  for (i = 0; i < op1->n; i++)
    ret->v[i] = op1->v[i] | op2->v[i];
  for (; i < op2->n; i++)
    ret->v[i] = op2->v[i];

  ret->n = op2->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

void ssh_mprz_xor(SshMPInteger ret,
                  SshMPIntegerConst op1, SshMPIntegerConst op2)
{
  unsigned int i;

  if (ssh_mprz_nanresult2(ret, op1, op2))
    return;

  /* Swap. */
  if (op1->n > op2->n)
    {
      SshMPIntegerConst t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Reallocate. */
  if (!ssh_mprz_realloc(ret, op1->n))
    return;

  /* This can be written more optimally. */
  for (i = 0; i < op1->n; i++)
    ret->v[i] = op1->v[i] ^ op2->v[i];
  for (; i < op2->n; i++)
    ret->v[i] = op2->v[i];

  ret->n = op2->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

void ssh_mprz_com(SshMPInteger ret, SshMPIntegerConst op)
{
  unsigned int i;

  if (ssh_mprz_nanresult1(ret, op))
    return;

  /* Reallocate. */
  if (!ssh_mprz_realloc(ret, op->n))
    return;

  /* This can be written more optimally. */
  for (i = 0; i < op->n; i++)
    ret->v[i] = ~op->v[i];

  ret->n = op->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

/* Encode given SshMPInteger in SSH2 style.  return length of the
   buffer (which this allocates) presenting the number, or zero in
   case of failure. */
int
ssh_mprz_encode_ssh2style(SshMPIntegerConst mp,
                          unsigned char *buf, size_t len)
{
  SshMPIntegerStruct temp;
  unsigned int i;
  unsigned char *four = buf;
  size_t buf_len;

  /* This code is written along the lines of the code in ber.c */
  switch (ssh_mprz_cmp_ui(mp, 0))
    {
    case 0: /* Handle the zero case. */

      if (len >= 4)
        {
          four = buf;
          four[0] = four[1] = four[2] = four[3] = 0;
        }
      return 4;

    case 1: /* Handle the positive case. */

      buf_len = ssh_mprz_get_size(mp, 2);
      /* If highest bit set add one empty octet, then correct octet count. */
      if ((buf_len & 7) == 0)
        buf_len += 8;
      buf_len = (buf_len + 7)/8;

      if ((4 + buf_len) > len)
        return 4 + buf_len;

      /* Put the length and integer value. */
      SSH_PUT_32BIT(buf, buf_len);
      ssh_mprz_get_buf(buf+4, buf_len, mp);
      return 4 + buf_len;

    case -1: /* Handle negative case. */

      ssh_mprz_init(&temp);
      /* Compute temp = (-value - 1) = -(value + 1). E.g. -1 -> 0, which
         then can be complemented. */
      ssh_mprz_set_ui(&temp, 0);
      ssh_mprz_sub(&temp, &temp, mp);
      ssh_mprz_sub_ui(&temp, &temp, 1);
      /* Compute the correct length in base 2. */
      buf_len = ssh_mprz_get_size(&temp, 2);

      /* Check the highest bit case. Note that here we actually want the
         highest bit be set (after complementing). */
      if ((buf_len & 7) == 0)
        buf_len += 8;
      buf_len = (buf_len + 7)/8;

      if ((buf_len + 4) > len)
        {
          ssh_mprz_clear(&temp);
          return buf_len + 4;
        }

      SSH_PUT_32BIT(buf, buf_len);
      ssh_mprz_get_buf(buf+4, buf_len, mp);

      /* Doing the complementing. Currently the ssh_mprz_get_buf doesn't
         know how to do it. */
      for (i = 0; i < buf_len; i++)
        buf[i + 4] ^= 0xff;
      return buf_len + 4;

    default:
      return 0;
    }
}

int
ssh_mprz_decode_ssh2style(const unsigned char *buf, size_t len,
                          SshMPInteger mp)
{
  size_t byte_size;
  const unsigned char *bufptr;
  int i;

  if (len < 4)
    return 0;
  byte_size = SSH_GET_32BIT(buf);

  if (byte_size == 0)
    {
      ssh_mprz_set_ui(mp, 0);
      return 4;
    }

  if ((byte_size + 4) > len)
    return 0;

  bufptr = buf + 4;
  if (bufptr[0] & 0x80)
    {
      unsigned char *tmp;

      if ((tmp = ssh_memdup(bufptr, byte_size)) != NULL)
        {
          for (i = 0; i < byte_size; i++)
            tmp[i] ^= 0xff;

          ssh_mprz_set_buf(mp, tmp, byte_size);
          ssh_mprz_add_ui(mp, mp, 1);
          ssh_mprz_neg(mp, mp);
          ssh_free(tmp);
        }
      else
        return 0;
    }
  else
    {
      ssh_mprz_set_buf(mp, bufptr, byte_size);
    }
  return byte_size + 4;
}
/* sshmp-integer-misc.c */
#endif /* SSHDIST_MATH */
