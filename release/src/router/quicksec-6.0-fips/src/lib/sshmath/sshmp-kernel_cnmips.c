/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains the low level functions that are needed in
   the implementation of the SSH mathematics library routines.
*/

#include "sshincludes.h"
#include "sshmp-types.h"
#include "sshmp-kernel.h"

#define SSH_DEBUG_MODULE "SshMPKernel"

#ifdef SSHDIST_MATH

#undef SSH_MPK_USE_MONTGOMERYS_ALGORITHM

/* Prototypes of assembler functions. */

/* Addition routines. Perform addition of equal length buffers, and
   addition by 1. */
SshWord ssh_mpk_add_n(SshWord *ret, SshWord *op1,
                      SshWord *op2, unsigned int len);
SshWord ssh_mpk_add_1(SshWord *ret, SshWord *op, unsigned int len);

/* Subtraction routines. Perform subtraction of equal length buffers, and
   subtraction by 1. */
SshWord ssh_mpk_sub_n(SshWord *ret,
                      SshWord *op1, SshWord *op2, unsigned int len);
SshWord ssh_mpk_sub_1(SshWord *ret, SshWord *op, unsigned int len);

/* Standard style addition after multiplication by word. */
SshWord ssh_mpk_addmul_n(SshWord *ret, SshWord k,
                         SshWord *op, unsigned int len);

/* Standard style addition after multiplication by word. */
SshWord ssh_mpk_addmul_n_nc(SshWord *ret, SshWord k,
                         SshWord *op, unsigned int len);

/* Standard style subtraction after multiplication by word. */
SshWord ssh_mpk_submul_n(SshWord *ret, SshWord k,
                         SshWord *op, unsigned int len);
/* Fast shift up by 1 bit. */
SshWord ssh_mpk_shift_up_1(SshWord *ret, unsigned int len);
/* Specialized routine for squaring all the words in the buffer, and
   adding to the result at new positions. */
SshWord ssh_mpk_square_words_n(SshWord *ret, SshWord *op, unsigned int len);
/* Montgomery style addition after multiplication by word. */
SshWord ssh_mpmk_addmul_n(SshWord *ret, SshWord mp, const SshWord *op,
                          unsigned int len/*, SshWord carry*/);

SshWord ssh_mpmk_addmul_n_orig(SshWord *ret, SshWord mp, SshWord *op,
                          unsigned int len, SshWord carry);

SshWord ssh_mpmk_addmul_n_192(SshWord *ret, const SshWord * mp,
                              const SshWord *op,
                              unsigned int len/*, SshWord carry*/);


/* Define these additional macros for usage here. */
#define SSH_MPK_1ST_OCTET    ((SshWord)0xff << (SSH_WORD_BITS -  8))
#define SSH_MPK_2ND_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 16))
#define SSH_MPK_3RD_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 24))
#define SSH_MPK_4TH_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 32))
#define SSH_MPK_5TH_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 40))
#define SSH_MPK_6TH_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 48))
#define SSH_MPK_7TH_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 56))
#define SSH_MPK_8TH_OCTET    ((SshWord)0xff << (SSH_WORD_BITS - 64))

#define SSH_MPK_HIGH_OCTET   SSH_MPK_1ST_OCTET

int ssh_mpk_count_trailing_zeros(SshWord x)
{
  static const unsigned char trailing_zero_table[256] =
  {
    8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
  };

#define SSH_MPK_CTZ_HELP(octet,offset) \
  if (x & octet) return (offset + trailing_zero_table[(x >> offset) & 0xff])

#define SSH_MPK_CTZ_HELP_LAST(offset) \
  return (offset + trailing_zero_table[(x >> offset)])

#if (SSH_WORD_BITS == 32)
  SSH_MPK_CTZ_HELP(SSH_MPK_4TH_OCTET, 0);
  SSH_MPK_CTZ_HELP(SSH_MPK_3RD_OCTET, 8);
  SSH_MPK_CTZ_HELP(SSH_MPK_2ND_OCTET, 16);
  SSH_MPK_CTZ_HELP_LAST(24);
#elif (SSH_WORD_BITS == 64)
  SSH_MPK_CTZ_HELP(SSH_MPK_8TH_OCTET, 0);
  SSH_MPK_CTZ_HELP(SSH_MPK_7TH_OCTET, 8);
  SSH_MPK_CTZ_HELP(SSH_MPK_6TH_OCTET, 16);
  SSH_MPK_CTZ_HELP(SSH_MPK_5TH_OCTET, 24);
  SSH_MPK_CTZ_HELP(SSH_MPK_4TH_OCTET, 32);
  SSH_MPK_CTZ_HELP(SSH_MPK_3RD_OCTET, 40);
  SSH_MPK_CTZ_HELP(SSH_MPK_2ND_OCTET, 48);
  SSH_MPK_CTZ_HELP_LAST(56);
#else /* Some other bit size (strange at least now) */
  int i, count = 0;
  for (i = 0; i < (SSH_WORD_BITS/8) - 1; i++)
    {
      if (x & 0xff) return count + trailing_zero_table[x & 0xff];
      count += 8;
      x >>= 8;
    }
  return (SSH_WORD_BITS - 8) + trailing_zero_table[x & 0xff];
#endif /* SSH_WORD_BITS == ? */

#undef SSH_MPK_CTZ_HELP
#undef SSH_MPK_CTZ_HELP_LAST
}

int ssh_mpk_count_leading_zeros(SshWord x)
{
  static const unsigned char leading_zero_table[256] =
  {
    8, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };

#define SSH_MPK_CLZ_HELP(octet,offset) \
  if (x & octet) \
    return ((SSH_WORD_BITS - (offset + 8)) + \
            leading_zero_table[(x >> offset) & 0xff])

#define SSH_MPK_CLZ_HELP_LAST() \
  return ((SSH_WORD_BITS - 8) + leading_zero_table[x])

#if (SSH_WORD_BITS == 32)
  SSH_MPK_CLZ_HELP(SSH_MPK_1ST_OCTET, 24);
  SSH_MPK_CLZ_HELP(SSH_MPK_2ND_OCTET, 16);
  SSH_MPK_CLZ_HELP(SSH_MPK_3RD_OCTET, 8);
  SSH_MPK_CLZ_HELP_LAST();
#elif (SSH_WORD_BITS == 64)
  SSH_MPK_CLZ_HELP(SSH_MPK_1ST_OCTET, 56);
  SSH_MPK_CLZ_HELP(SSH_MPK_2ND_OCTET, 48);
  SSH_MPK_CLZ_HELP(SSH_MPK_3RD_OCTET, 40);
  SSH_MPK_CLZ_HELP(SSH_MPK_4TH_OCTET, 32);
  SSH_MPK_CLZ_HELP(SSH_MPK_5TH_OCTET, 24);
  SSH_MPK_CLZ_HELP(SSH_MPK_6TH_OCTET, 16);
  SSH_MPK_CLZ_HELP(SSH_MPK_7TH_OCTET, 8);
  SSH_MPK_CLZ_HELP_LAST();
#else /* Some other word size... */
  int i, count;

  count = 0;
  for (i = 0; i < (SSH_WORD_BITS/8) - 1; i++)
  {
    if (x & SSH_MPK_HIGH_OCTET)
      return count + leading_zero_table[x >> (SSH_WORD_BITS - 8)];
    count += 8;
    x <<= 8;
  }
  return (SSH_WORD_BITS - 8) + leading_zero_table[x >> (SSH_WORD_BITS - 8)];

#endif /* SSH_WORD_BITS == ? */
#undef SSH_MPK_CLZ_HELP
#undef SSH_MPK_CLZ_HELP_LAST
}

#define SSHMATH_FAST_MEM_ROUTINES

#ifndef SSHMATH_FAST_MEM_ROUTINES
/* C versions. */
#if 0
void ssh_mpk_memcopy(SshWord *d, SshWord *s, unsigned int len)
{
  int i, j;
  /* Run the buffers two words at a time if possible. This should
     lower the overhead. */
  for (j = 0, i = len >> 1; i; j += 2, i--)
    {
      d[j    ] = s[j    ];
      d[j + 1] = s[j + 1];
    }
  if (len & 0x1)
    d[j] = s[j];
}

void ssh_mpk_memzero(SshWord *d, unsigned int len)
{
  int i, j;
  /* Run the buffers two words at a time if possible. This should
     lower the overhead. */
  for (j = 0, i = len >> 1; i; j += 2, i--)
    {
      d[j    ] = 0;
      d[j + 1] = 0;
    }
  if (len & 0x1)
    d[j] = 0;
}
#else
void ssh_mpk_memcopy(SshWord *d, SshWord *s, unsigned int len)
{
  SshWord *__d = (d), *__s = (s);
  switch ((len))
    {
    case 0:
      break;
    case 1:
      __d[0] = __s[0];
      break;
    case 2:
      __d[0] = __s[0];
      __d[1] = __s[1];
      break;
    case 3:
      __d[0] = __s[0];
      __d[1] = __s[1];
      __d[2] = __s[2];
      break;
    default:
      {
        int i, j;
        for (j = 0, i = (len) >> 2; i; j += 4, i--)
          {
            __d[j    ] = __s[j    ];
            __d[j + 1] = __s[j + 1];
            __d[j + 2] = __s[j + 2];
            __d[j + 3] = __s[j + 3];
          }
        switch ((len) & 0x3)
          {
          case 0:
            break;
          case 1:
            __d[j    ] = __s[j    ];
            break;
          case 2:
            __d[j    ] = __s[j    ];
            __d[j + 1] = __s[j + 1];
            break;
          case 3:
            __d[j    ] = __s[j    ];
            __d[j + 1] = __s[j + 1];
            __d[j + 2] = __s[j + 2];
            break;
          }
      }
      break;
    }
}

void ssh_mpk_memzero(SshWord *d, unsigned int len)
{
  SshWord *__d = (d);
  switch ((len))
    {
    case 0:
      break;
    case 1:
      __d[0] = 0;
      break;
    case 2:
      __d[0] = 0;
      __d[1] = 0;
      break;
    case 3:
      __d[0] = 0;
      __d[1] = 0;
      __d[2] = 0;
      break;
    default:
      {
        int i, j;
        for (j = 0, i = (len) >> 2; i; j += 4, i--)
          {
            __d[j    ] = 0;
            __d[j + 1] = 0;
            __d[j + 2] = 0;
            __d[j + 3] = 0;
          }
        switch ((len) & 0x3)
          {
          case 0:
            break;
          case 1:
            __d[j    ] = 0;
            break;
          case 2:
            __d[j    ] = 0;
            __d[j + 1] = 0;
            break;
          case 3:
            __d[j    ] = 0;
            __d[j + 1] = 0;
            __d[j + 2] = 0;
            break;
          }
      }
      break;
    }
}
#endif
#else /* SSHMATH_FAST_MEM_ROUTINES */

/* Wrappers for memory copy. */
#if 0
void ssh_mpk_memcopy(SshWord *d, SshWord *s, unsigned int len)
{
  if (d == s)
    return;

  memcpy(d, s, len * sizeof(SshWord));
}
#endif
#if 0
void ssh_mpk_memzero(SshWord *d, unsigned int len)
{
  memset(d, 0, len * sizeof(SshWord));
}
#endif
#endif /* SSHMATH_FAST_MEM_ROUTINES */

/* Some bit level operations. */

/* Shifting, that is dividing and multiplying with 2^n's.*/

int ssh_mpk_shift_up_bits(SshWord *op, unsigned int op_n,
                          unsigned int bits)
{
  unsigned int i;
  /* Nothing to do if zero integer. */
  if (!op_n)
    return 0;

  /* We need a simple macro to make life easier. I.e. other wise
     we would have to dublicate it for all the cases. */

#define UP_SHIFT_MACRO(__bits__)                  \
  for (i = op_n - 1; i; i--)                  \
    op[i] = (op[i] << (__bits__)) | (op[i - 1] >> \
            (SSH_WORD_BITS - __bits__));          \
  op[0] <<= __bits__;

  /* It is not of course necessarily best to do things this way,
     but in princible the shifting with just some variable is
     slower than by fixed value. At least this is so in Intel
     Pentiums. */
  switch (bits)
    {
    case 0:
      break;
    case 1:
      UP_SHIFT_MACRO(1);
      break;
    case 2:
      UP_SHIFT_MACRO(2);
      break;
    case 3:
      UP_SHIFT_MACRO(3);
      break;
    default:
      UP_SHIFT_MACRO(bits);
      break;
    }
#undef UP_SHIFT_MACRO

  if (op[op_n - 1])
    op_n++;
  return op_n;
}

int ssh_mpk_shift_down_bits(SshWord *op, SshWord op_n,
                            SshWord bits)
{
  unsigned int i;

  /* Nothing to do if zero integer. */
  if (!op_n)
    return 0;

  /* We need a simple macro to make life easier. I.e. other wise
     we would have to dublicate it for all the cases. */

#define DOWN_SHIFT_MACRO(__bits__)                \
  for (i = 0; i < op_n - 1; i++)              \
    op[i] = (op[i] >> (__bits__)) | (op[i + 1] << \
            (SSH_WORD_BITS - __bits__));          \
    op[op_n - 1] >>= __bits__;

  /* It is not of course necessarily best to do things this way,
     but in princible the shifting with just some variable is
     slower than by fixed value. At least this is so in Intel
     Pentiums. */
  switch (bits)
    {
    case 0:
      break;
    case 1:
      DOWN_SHIFT_MACRO(1);
      break;
    case 2:
      DOWN_SHIFT_MACRO(2);
      break;
    case 3:
      DOWN_SHIFT_MACRO(3);
      break;
    default:
      DOWN_SHIFT_MACRO(bits);
      break;
    }
#undef DOWN_SHIFT_MACRO
  if (!op[op_n - 1])
    op_n--;
  return op_n;
}

/* Compute the size of the input word array in base 2. Fast. */
unsigned int ssh_mpk_size_in_bits(SshWord *op, unsigned int op_n)
{
  SshWord t;
  unsigned int r;

  if (op_n == 0)
    return 0;

  t = op[op_n - 1];
  r = 0;
  SSH_MPK_COUNT_LEADING_ZEROS(r, t);

  return op_n * SSH_WORD_BITS - r;
}

/* Comparison of integers routines. */

/* Comparison of unsigned integer with an large integer. */
int ssh_mpk_cmp_ui(SshWord *op, unsigned int op_n, SshWord u)
{
  /* First check if values are both zero. */
  if (op_n == 0 && u == 0)
    return 0;

  /* If large integer is zero. */
  if (op_n == 0)
    return -1;

  /* If integer is zero. */
  if (u == 0)
    return 1;

  /* If large integer is larger than just one integer. */
  if (op_n > 1)
    return 1;

  /* If both are of roughly equal size. */
  if (op[0] > u)
    return 1;
  if (op[0] < u)
    return -1;

  /* Must be equal then. */
  return 0;
}

/* General compare with two large natural integers given as arrays. This
   should be written so that it is usually faster than running through
   all words of an integer array. */
int ssh_mpk_cmp(SshWord *op1, unsigned int op1_n,
                SshWord *op2, unsigned int op2_n)
{
  unsigned int i;

  /* Both might be zero? */
  if (op1_n == 0 && op2_n == 0)
    return 0;

  /* We may check just their sizes, because they are supposed to be
     kept updated. */
  if (op1_n > op2_n)
    return 1;
  if (op1_n < op2_n)
    return -1;

  /* Check whether the words are equal and if not which is larger. */
  for (i = op2_n; i; i--)
    {
      if (op1[i - 1] != op2[i - 1])
        {
          if (op1[i - 1] > op2[i - 1])
            return 1;
          return -1;
        }
    }

  /* Must be totally equal. Sadly in this case we have runned the loop
     in full, no other way I guess. */
  return 0;
}

SshWord ssh_mpk_add_ui(SshWord *ret,
                       SshWord *op, unsigned int op_n,
                       SshWord v)
{
  SshWord c;
  /* Set carry. */
  c = 0;

  /* Do the addition. */
  ret[0] = op[0] + v;

  /* Compute carry. */
  if (ret[0] < v)
    c = 1;

  /* Propagate. */
  if (c)
    {
      c = ssh_mpk_add_1(ret + 1, op + 1, op_n - 1);
    }
  else
    ssh_mpk_memcopy(ret + 1, op + 1, op_n - 1);
  return c;
}

/* We assume that op1_n > op2_n and that ret_n >= op1_n. */

SshWord ssh_mpk_add(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n)
{
  SshWord c;

  /* Addition in two phases. First we add the buffers up to the
     smallest. This ensures simplicity in the inner loop. */

  /* Assembler routine for fast unsigned addition of two
     buffers of equal length. */
  c = ssh_mpk_add_n(ret, op1, op2, op2_n);
  if (op2_n < op1_n)
    {
      if (c)
        {
          c = ssh_mpk_add_1(ret + op2_n, op1 + op2_n, op1_n - op2_n);
        }
      else
        ssh_mpk_memcopy(ret + op2_n, op1 + op2_n, op1_n - op2_n);
    }

  return c;
}

SshWord ssh_mpk_sub_ui(SshWord *ret,
                       SshWord *op, unsigned int op_n,
                       SshWord v)
{
  SshWord c, t;

  /* Set carry. */
  c = 0;

  /* Do the subtraction. */
  t = op[0];
  ret[0] = t - v;

  /* Compute carry. */
  if (ret[0] > t)
    c = 1;

  /* Propagate. */
  if (c)
    {
      c = ssh_mpk_sub_1(ret + 1, op + 1, op_n - 1);
    }
  else
    ssh_mpk_memcopy(ret + 1, op + 1, op_n - 1);
  return c;
}

/* We assume that op1_n > op2_n and op1 > op2 in absolute value. */

SshWord ssh_mpk_sub(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n)
{
  SshWord c;

  /* Subtraction in two phases. */

  /* Assembler subtraction with buffers of equal length. */
  c = ssh_mpk_sub_n(ret, op1, op2, op2_n);
  if (op2_n < op1_n)
    {
      if (c)
        c = ssh_mpk_sub_1(ret + op2_n, op1 + op2_n, op1_n - op2_n);
      else
        ssh_mpk_memcopy(ret + op2_n, op1 + op2_n, op1_n - op2_n);
    }

  return c;
}


/* Standard style addition after multiplication by word. */
void ssh_mpk_addmul_n_192(SshWord *ret, SshWord *k,
                          SshWord *op, unsigned int len);

void ssh_mpk_mul(SshWord *ret,
                 SshWord *op1, unsigned int op1_n,
                 SshWord *op2, unsigned int op2_n)
{
  unsigned int i;

  /* Loop through the multiplier. We assume usually that the multiplier
     is shorter, thus there will probably exists slightly less
     overhead. */
  for (i = 0; i + 2 < op1_n; i += 3)
    {
      ssh_mpk_addmul_n_192(ret + i, op1 + i, op2, op2_n);
    }

  for (; i < op1_n; i++)
    {
      ssh_mpk_addmul_n_nc(ret + i, op1[i], op2, op2_n);
    }
}


/* Faster version for specific multiplication by just single digit. This case
   cannot be speeded up asymptotically. */

void ssh_mpk_mul_ui(SshWord *ret,
                    SshWord *op,  unsigned int op_n,
                    SshWord u)
{
  unsigned int i;
  SshWord c;




  for (i = 0, c = 0; i < op_n; i++)
    {
      SshWord n1, n2, t1, t2;
      /* Simplied from above. */
      SSH_MPK_LONG_MUL(n2, n1, u, op[i]);
      t1 = n1 + c;
      t2 = n2;
      if (t1 < c)
        t2++;
      ret[i] = t1;
      c = t2;
    }
  /* Set the carry. */
  if (c)
    ret[i] = c;
}

void ssh_mpk_square(SshWord *ret,
                    SshWord *op,  unsigned int op_n)
{
  ssh_mpk_mul(ret, op, op_n, op, op_n);
}

/* Standard Karatsuba multiplying and non-standard squaring.

   Following formulas are used in following:

   Multiplication with Karatsuba's idea:

   Let

     u = u0 + u1*b
     v = v0 + v1*b
     b is the word size (e.g. 2^32)

   Karatsuba multiplication algorithm:

     u * v = (b^2 + b) * u1 * v1 + b*(u1 - u0)*(v0 - v1) + (b + 1) * v0 * u0


   Here is the algorithm by Montgomery. Let u and v be as before, then

     u * v = u1*v1*b^2 + u0*v0 + ((u1 + u0)*(v1 + v0) - u1*v1 - u0*v0)*b.

   This is an asymptotically fast algorithm for multiplication, and
   squaring.


   Squaring algorithm 1 (due to Markku-Juhani Saarinen):

   Let

     x = (u1 + u0)^2
     y = (u1 - u0)^2
     z = u1^2

   then

     u^2 = z*b^2 + ((x - y)*b + (x + y))/2 - z

   Squaring algorithm 2 (due to Colin Plumb):

     (u*b + v)^2 = u^2*(b^2 + b) + v^2 * (b + 1) - (u - v)^2 * b

   Saarinen's method uses 3 squaring's, 4 additions and 3
   subtractions.

   Plumb's method uses 3 squaring's, 3 additions and 2 subtractions.

   Both can be reasonably efficiently implemented. Note that squaring
   such as (u - v)^2 forgets the sign of the u - v computation, which
   makes implementation nicer.

   */

/* The thresholds for multiplication and squaring. These can be
   modified on the runtime. */









const SshWord ssh_mpk_karatsuba_mul_words    = SSH_MPK_KARATSUBA_MUL_CROSSOVER;
const SshWord ssh_mpk_karatsuba_square_words =
        SSH_MPK_KARATSUBA_SQUARE_CROSSOVER;

#if defined(SSH_MPK_USE_PLUMBS_ALGORITHM)

/* Compute the needed memory for the Karatsuba squaring. */
unsigned int ssh_mpk_square_karatsuba_needed_memory(unsigned int op_n)
{
  unsigned int work_n, div_n;

  /* If smaller than the threshold. */
  if (op_n < ssh_mpk_karatsuba_square_words)
    return 0;

  /* Select nearly optimal sizes. */
  div_n = op_n/2;
  work_n = ((div_n + 1) * 2 + 1)*4;

  /* Compute recursively the amount of memory needed! */
  work_n += ssh_mpk_square_karatsuba_needed_memory(div_n);
  work_n += ssh_mpk_square_karatsuba_needed_memory(op_n - div_n);
  work_n += ssh_mpk_square_karatsuba_needed_memory(op_n - div_n);

  return work_n;
}

/* This is the algorithm of Plumb's. As one can see this falls in place
   quite nicely. */

/* Original idea was to do all this in data recursion rather than the
   more easier code recursion. But that would mean some allocation,
   and might not be too much faster.
   */
Boolean ssh_mpk_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space,
                              unsigned int work_space_n)
{
  if (op_n < ssh_mpk_karatsuba_square_words)
    {
      /* If the compiler is smart it probably will inline this function
         here. */
      ssh_mpk_square(ret, op, op_n);
      return TRUE;
    }
  else
    {
      SshWord *u0, *u1, *x, *y, *z, *t, *work;
      unsigned int u0_n, u1_n, x_n, y_n, z_n, work_n, div_n, t_n;
      Boolean work_allocated;

      /* (u*b + v)^2 = u^2*(b^2 + b) + v^2 * (b + 1) - (u - v)^2 * b

         x = u1^2
         y = u0^2
         t = u1 - u0
         z = t^2
       */

      /* Select nearly optimal sizes. */
      div_n = op_n / 2;

      /* Compute divided parts. */
      u1 = op + div_n;
      u1_n = op_n - div_n;
      u0 = op;
      u0_n = div_n;

      /* Compute lengths for partial values. */
      x_n = (div_n + 1) * 2 + 1;
      y_n = (div_n + 1) * 2 + 1;
      z_n = (div_n + 1) * 2 + 1;
      t_n = (div_n + 1) * 2 + 1;
      work_n = x_n + y_n + z_n + t_n;

      /* Allocate working space. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_malloc(work_n * sizeof(SshWord));
          if (!work)
            {
              return FALSE;
            }
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          /* Advance the working space. */
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      x = work;
      y = x + x_n;
      z = y + y_n;
      t = z + z_n;

      /* Compute x = u1^2 */
      x_n = u1_n * 2 + 1;
      ssh_mpk_memzero(x, x_n);
      if (!ssh_mpk_square_karatsuba(x, x_n, u1, u1_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }
      /* Check size. */
      while (x_n && x[x_n - 1] == 0)
        x_n--;

      /* Compute y = u0^2 */
      y_n = u0_n * 2 + 1;
      ssh_mpk_memzero(y, y_n);
      if (!ssh_mpk_square_karatsuba(y, y_n, u0, u0_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }
      /* Check size. */
      while (y_n && y[y_n - 1] == 0)
        y_n--;

      /* Compute t = u1 - u0. Note that we do not need to remember the
         sign of this computation.

         It should be reasonably rare occurance that u1 < u0, but
         there is really no need to try to avoid it by selecting the
         division point "better".
         */
      t_n = u1_n;
      ssh_mpk_memzero(t, t_n);
      if (ssh_mpk_cmp(u1, u1_n, u0, u0_n) >= 0)
        ssh_mpk_sub(t, u1, u1_n, u0, u0_n);
      else
        ssh_mpk_sub(t, u0, u0_n, u1, u1_n);
      /* Check size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      /* Compute z = u1^2 */
      z_n = t_n * 2 + 1;
      ssh_mpk_memzero(z, z_n);
      if (!ssh_mpk_square_karatsuba(z, z_n, t, t_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }
      /* Check size. */
      while (z_n && z[z_n - 1] == 0)
        z_n--;

      /* (u1*b + u0)^2 = u1^2*(b^2 + b) + u0^2 * (b + 1) - (u1 - u0)^2 * b

         x = u1^2
         y = u0^2
         t = u1 - u0
         z = t^2
       */

      /* Copy the x up there. */
      ssh_mpk_memcopy(ret + div_n * 2, x, x_n);
      ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
              x, x_n);
      ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
              y, y_n);
      ssh_mpk_add(ret, ret, ret_n,
              y, y_n);

      /* Subtract last to be assured that we cannot get negative. */
      ssh_mpk_sub(ret + div_n, ret + div_n, ret_n - div_n,
              z, z_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_free(work);

      return TRUE;
    }
}

#elif defined(SSH_MPK_USE_SAARINENS_ALGORITHM)

/* Compute amount of memory needed for the Karatsuba squaring to
   work. This is recursive, but could be written out probably as
   a simple formula. */
unsigned int ssh_mpk_square_karatsuba_needed_memory(unsigned int op_n)
{
  unsigned int work_n, div_n;

  /* If smaller than the threshold. */
  if (op_n < ssh_mpk_karatsuba_square_words)
    return 0;

  /* Select nearly optimal sizes. */
  div_n = op_n/2;
  work_n = ((div_n + 1) * 2 + 1)*4;

  /* Compute recursively the amount of memory needed! */
  work_n += ssh_mpk_square_karatsuba_needed_memory((op_n - div_n) + 1);
  work_n += ssh_mpk_square_karatsuba_needed_memory(op_n - div_n);
  work_n += ssh_mpk_square_karatsuba_needed_memory(op_n - div_n);

  return work_n;
}

/* This is the algorithm due to Saarinen. */
Boolean ssh_mpk_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space, unsigned int work_space_n)
{
  if (op_n < ssh_mpk_karatsuba_square_words)
    {
      /* Lets call the school squaring algorithm. */
      ssh_mpk_square(ret, op, op_n);
      return TRUE;
    }
  else
    {
      SshWord *u0, *u1, *x, *y, *z, *t, *work, c;
      unsigned int u0_n, u1_n, x_n, y_n, z_n, work_n, div_n, t_n;
      Boolean work_allocated;

      /* Select nearly optimal sizes. */
      div_n = op_n / 2;

      /* Compute divided parts. */
      u1 = op + div_n;
      u1_n = op_n - div_n;
      u0 = op;
      u0_n = div_n;

      /* Compute lengths for partial values. */
      x_n = (div_n + 1) * 2 + 1;
      y_n = (div_n + 1) * 2 + 1;
      z_n = (div_n + 1) * 2 + 1;
      t_n = (div_n + 1) * 2 + 1;
      work_n = x_n + y_n + z_n + t_n;

      /* Allocate working space. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_malloc(work_n * sizeof(SshWord));
          if (!work)
            {
              return FALSE;
            }
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      x = work;
      y = x + x_n;
      z = y + y_n;
      t = z + z_n;

      /* Compute x = (u1 + u0)^2 */
      t_n = u1_n;
      ssh_mpk_memzero(t, t_n);
      c = ssh_mpk_add(t, u1, u1_n, u0, u0_n);
      if (c)
        {
          t[t_n] = 1;
          t_n++;
        }
      else
        /* Check size. */
        while (t_n && t[t_n - 1] == 0)
          t_n--;

      x_n = t_n * 2 + 1;
      ssh_mpk_memzero(x, x_n);
      if (!ssh_mpk_square_karatsuba(x, x_n, t, t_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute y = (u1 - u0)^2 */
      t_n = u1_n;
      ssh_mpk_memzero(t, u1_n);
      if (ssh_mpk_cmp(u1, u1_n, u0, u0_n) >= 0)
        ssh_mpk_sub(t, u1, u1_n, u0, u0_n);
      else
        ssh_mpk_sub(t, u0, u0_n, u1, u1_n);
      /* Check size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      y_n = t_n * 2 + 1;
      ssh_mpk_memzero(y, y_n);
      if (!ssh_mpk_square_karatsuba(y, y_n, t, t_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute z = u1^2 */
      z_n = u1_n * 2 + 1;
      ssh_mpk_memzero(z, z_n);
      if (!ssh_mpk_square_karatsuba(z, z_n, u1, u1_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }





      /* u^2 = z*b^2 + ((x - y)/2)*b + ((x + y)/2 - z) */

      /* Check sizes. */
      while (x_n && x[x_n - 1] == 0)
        x_n--;
      while (y_n && y[y_n - 1] == 0)
        y_n--;
      while (z_n && z[z_n - 1] == 0)
        z_n--;

      /* Compute t = (x + y)/2 and x = (x - y)/2. */
      t_n = x_n;
      c = ssh_mpk_add(t, x, x_n, y, y_n);
      ssh_mpk_sub(x, x, x_n, y, y_n);

      /* Handle possible carry. And correct sizes. */
      if (c)
        {
          t[t_n] = 1;
          t_n++;
        }
      else
        while (t_n && t[t_n - 1] == 0)
          t_n--;

      while (x_n && x[x_n - 1] == 0)
        x_n--;

      /* u^2 = z*b^2 + x*b + (t - z) */

      /* Shift down, that is divide by 2. */
      ssh_mpk_memcopy(ret + div_n, x, x_n);
      ssh_mpk_add(ret, ret, div_n + x_n, t, t_n);

      /* Correct the size. */
      t_n = div_n + x_n + 1;
      while (t_n && ret[t_n - 1] == 0)
        t_n--;

      /* Divide by 2. */
      ssh_mpk_shift_down_bits(ret, t_n, 1);

      /* Compute the rest. */

      /* Add and subtract z. */
      ssh_mpk_add(ret + div_n * 2, ret + div_n * 2, ret_n - div_n * 2,
              z, z_n);
      ssh_mpk_sub(ret, ret, ret_n, z, z_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_free(work);

      return TRUE;
    }
}

#elif defined(SSH_MPK_USE_MONTGOMERYS_ALGORITHM)

/* Compute amount of memory needed for the Karatsuba squaring to
   work. This is recursive, but could be written out probably as
   a simple formula. */
unsigned int ssh_mpk_square_karatsuba_needed_memory(unsigned int op_n)
{
  unsigned int work_n, div_n;

  /* If smaller than the threshold. */
  if (op_n < ssh_mpk_karatsuba_square_words)
    return 0;

  /* Select nearly optimal sizes. */
  div_n = op_n/2;
  work_n = ((div_n + 1) * 2 + 1)*2 + (div_n + 2)*2 + 1 + div_n + 2;

  /* Compute recursively the amount of memory needed! */
  work_n += ssh_mpk_square_karatsuba_needed_memory((op_n - div_n) + 1);
  work_n += ssh_mpk_square_karatsuba_needed_memory(op_n - div_n);
  work_n += ssh_mpk_square_karatsuba_needed_memory((op_n - div_n) + 1);

  return work_n;
}

/* This is the algorithm due to Montgomery. */
Boolean
ssh_mpk_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space, unsigned int work_space_n)
{
  if (op_n < ssh_mpk_karatsuba_square_words)
    {
      /* Lets call the school squaring algorithm. */
      ssh_mpk_square(ret, op, op_n);
      return TRUE;
    }
  else
    {
      SshWord *u0, *u1, *x, *y, *z, *t, *work;
      unsigned int u0_n, u1_n, x_n, y_n, z_n, work_n, div_n, t_n;
      Boolean work_allocated;

      /* Montgomery's idea is almost equal to that of Plumb's, however,
         there are some tiny differenrences. They may become important
         in certain situations. */

      /* (u*b + v)^2 = u^2*b^2 + v^2 + ((u+v)*(u+v) - u^2 - v^2)*b

         x = u1^2
         y = u0^2
         t = u1 + u0
         z = t^2
       */

      /* Select nearly optimal sizes. */
      div_n = op_n / 2;

      /* Compute divided parts. */
      u1   = op + div_n;
      u1_n = op_n - div_n;
      u0   = op;
      u0_n = div_n;

      /* Compute lengths for partial values. */
      x_n = (div_n + 1) * 2 + 1;
      y_n = (div_n + 1) * 2 + 1;
      z_n = (div_n + 2) * 2 + 1;
      t_n =  div_n + 2;
      work_n = x_n + y_n + z_n + t_n;

      /* Allocate working space. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_malloc(work_n * sizeof(SshWord));
          if (!work)
            {
              return FALSE;
            }
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          /* Advance the working space. */
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      x = work;
      y = x + x_n;
      z = y + y_n;
      t = z + z_n;

      /* Compute x = u1^2 */
      x_n = u1_n * 2 + 1;
      ssh_mpk_memzero(x, x_n);
      if (!ssh_mpk_square_karatsuba(x, x_n, u1, u1_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }
      /* Check size. */
      while (x_n && x[x_n - 1] == 0)
        x_n--;

      /* Compute y = u0^2 */
      y_n = u0_n * 2 + 1;
      ssh_mpk_memzero(y, y_n);
      if (!ssh_mpk_square_karatsuba(y, y_n, u0, u0_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Check size. */
      while (y_n && y[y_n - 1] == 0)
        y_n--;

      /* Compute t = u1 + u0.
         */
      if (u1_n > u0_n)
        t_n = u1_n;
      else
        t_n = u0_n;
      if (ssh_mpk_add(t, u1, u1_n, u0, u0_n))
        {
          t[t_n] = 1;
          t_n++;
        }

      /* Compute z = u1^2 */
      z_n = t_n * 2 + 1;
      ssh_mpk_memzero(z, z_n);
      if (!ssh_mpk_square_karatsuba(z, z_n, t, t_n,
                                    work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* (u1*b + u0)^2 = u1^2*b^2 + u0^2  +
                         ((u1 + u0)^2 - u1^2 - u0^2)* b

         x = u1^2
         y = u0^2
         t = u1 + u0
         z = t^2
       */

      /* Perform subtractions z - x - y */

      /* Subtraction z - x */
      ssh_mpk_sub(z, z, z_n, x, x_n);
      /* Subtraction z - y */
      ssh_mpk_sub(z, z, z_n, y, y_n);
      /* Check size. */
      while (z_n && z[z_n - 1] == 0)
        z_n--;

      /* Copy the values. */
      ssh_mpk_memcopy(ret, y, y_n);
      ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
                  z, z_n);
      ssh_mpk_add(ret + div_n * 2, ret + div_n * 2, ret_n - div_n * 2,
                  x, x_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_free(work);

      return TRUE;
    }
}

#endif /* SSH_MPK_USE_MONTGOMERYS_ALGORITHM */


#if defined(SSH_MPK_USE_KARATSUBAS_ALGORITHM)

/* Compute the needed memory for the Karatsuba multiplication. */
unsigned int ssh_mpk_mul_karatsuba_needed_memory(unsigned int op1_n,
                                                 unsigned int op2_n)
{
  unsigned int u0_n, u1_n, v0_n, v1_n, work_n, div_n, uv1_n, uv0_n,
    um_n, vm_n, vum_n;

  /* Check for threshold. */
  if (op1_n < ssh_mpk_karatsuba_mul_words ||
      op2_n < ssh_mpk_karatsuba_mul_words)
    return 0;

  if (op1_n < op2_n)
    div_n = op1_n / 2;
  else
    div_n = op2_n / 2;

  /* Compute sizes and positions to make things much clearer later.
     Compiler will interleave these if it is any good? */
  u0_n = div_n;
  u1_n = op1_n - div_n;
  v0_n = div_n;
  v1_n = op2_n - div_n;

  /* We need some working space. */
  uv1_n = u1_n + v1_n + 1;
  uv0_n = u0_n + u0_n + 1;
  um_n  = u1_n + 1;
  vm_n  = v1_n + 1;
  vum_n = um_n + vm_n + 1;

  /* Add up all sizes. */
  work_n = uv1_n + uv0_n + um_n + vm_n + vum_n;

  /* Compute the recursive effect! */
  work_n += ssh_mpk_mul_karatsuba_needed_memory(u1_n, v1_n);
  work_n += ssh_mpk_mul_karatsuba_needed_memory(u0_n, v0_n);
  work_n += ssh_mpk_mul_karatsuba_needed_memory(um_n, vm_n);

  /* Return the amount of memory used in total. */
  return work_n;
}

/* Karatsuba multiplication. This is basically a recursive function, which
   divides each input into two and calls itself until ready for
   school multiplication. */
Boolean ssh_mpk_mul_karatsuba(SshWord *ret, unsigned int ret_n,
                           SshWord *op1, unsigned int op1_n,
                           SshWord *op2, unsigned int op2_n,
                           SshWord *work_space, unsigned int work_space_n)
{
  if (op1_n < ssh_mpk_karatsuba_mul_words ||
      op2_n < ssh_mpk_karatsuba_mul_words)
    {
      /* Call ssh_mpk_mul in such a way that the faster loop runs longer. */
      if (op1_n < op2_n)
        ssh_mpk_mul(ret, op1, op1_n,
                    op2, op2_n);
      else
        ssh_mpk_mul(ret, op2, op2_n,
                    op1, op1_n);
      return TRUE;
    }
  else
    {
      SshWord *u0, *u1, *v0, *v1, *work;
      unsigned int u0_n, u1_n, v0_n, v1_n, work_n, div_n, uv1_n, uv0_n,
        um_n, vm_n, vum_n;
      SshWord *uv1, *uv0, *um, *vm, *vum;
      Boolean vm_sign = FALSE, um_sign = FALSE, vum_sign, work_allocated;

      /*
        Let

        u = u0 + u1*b
        v = v0 + v1*b
        b is the word size (e.g. 2^32)

        Karatsuba multiplication algorithm:

        u * v = (b^2 + b) * u1 * v1 + b*(u1 - u0)*(v0 - v1) + (b + 1) * v0 * u0

     */

      if (op1_n < op2_n)
        div_n = op1_n / 2;
      else
        div_n = op2_n / 2;

      /* Compute sizes and positions to make things much clearer later.
         Compiler will interleave these if it is any good? */
      u0   = op1;
      v0   = op2;
      u1   = op1 + div_n;
      v1   = op2 + div_n;
      u0_n = div_n;
      u1_n = op1_n - div_n;
      v0_n = div_n;
      v1_n = op2_n - div_n;

      /* We need some working space. */
      uv1_n = u1_n + v1_n + 1;
      uv0_n = u0_n + v0_n + 1;
      um_n  = u1_n + 1;
      vm_n  = v1_n + 1;
      vm_sign = FALSE;
      vum_n = um_n + vm_n + 1;

      /* Add up all sizes. */
      work_n = uv1_n + uv0_n + vum_n + vm_n + um_n;

      /* Allocate space with ssh_malloc which should be fast enough. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_malloc(sizeof(SshWord) * work_n);
          if (!work)
            {
              return FALSE;
            }
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      /* Divide amongst the intermediate variables. */
      uv1 = work;
      uv0 = uv1 + uv1_n;
      um  = uv0 + uv0_n;
      vm  = um  + um_n;
      vum = vm  + vm_n;

      /* Compute u1 * v1 */
      ssh_mpk_memzero(uv1, uv1_n);
      if (!ssh_mpk_mul_karatsuba(uv1, uv1_n, u1, u1_n, v1, v1_n,
                                 work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute u0 * v0 */
      ssh_mpk_memzero(uv0, uv0_n);
      if (!ssh_mpk_mul_karatsuba(uv0, uv0_n, u0, u0_n, v0, v0_n,
                                 work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute (u1 - u0) * (v0 - v1) */
      if (ssh_mpk_cmp(u1, u1_n, u0, u0_n) >= 0)
        {
          ssh_mpk_sub(um, u1, u1_n, u0, u0_n);
          um_n = u1_n;
          um_sign = FALSE;
        }
      else
        {
          ssh_mpk_sub(um, u0, u0_n, u1, u1_n);
          um_n = u0_n;
          um_sign = TRUE;
        }

      /* Check size. */
      while (um_n && um[um_n - 1] == 0)
        um_n--;

      if (ssh_mpk_cmp(v0, v0_n, v1, v1_n) >= 0)
        {
          ssh_mpk_sub(vm, v0, v0_n, v1, v1_n);
          vm_n = v0_n;
          vm_sign = FALSE;
        }
      else
        {
          ssh_mpk_sub(vm, v1, v1_n, v0, v0_n);
          vm_n = v1_n;
          vm_sign = TRUE;
        }

      /* Check size. */
      while (vm_n && vm[vm_n - 1] == 0)
        vm_n--;

      /* Multiply. */
      vum_n = um_n + vm_n + 1;
      ssh_mpk_memzero(vum, vum_n);
      if (!ssh_mpk_mul_karatsuba(vum, vum_n, um, um_n, vm, vm_n,
                                work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }
      vum_sign = um_sign ^ vm_sign;

      /* Check size. */
      while (vum_n && vum[vum_n - 1] == 0)
        vum_n--;

      /*
        u * v = (b^2 + b) * u1 * v1 + b*(u1 - u0)*(v0 - v1) + (b + 1) * v0 * u0
        */

      /* Add up. */

      ssh_mpk_memcopy(ret + div_n * 2, uv1, uv1_n);
      ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
              uv0, uv0_n);
      ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
              uv1, uv1_n);
      ssh_mpk_add(ret, ret, ret_n, uv0, uv0_n);

      /* The middle place with either subtraction or addition. */
      if (vum_sign)
        ssh_mpk_sub(ret + div_n, ret + div_n, ret_n - div_n,
                vum, vum_n);
      else
        ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
                vum, vum_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_free(work);

      return TRUE;
    }
}

#elif defined(SSH_MPK_USE_MONTGOMERYS_ALGORITHM)

/* Compute the needed memory for the Montgomery's fast multiplication. */
unsigned int ssh_mpk_mul_karatsuba_needed_memory(unsigned int op1_n,
                                                 unsigned int op2_n)
{
  unsigned int u0_n, u1_n, v0_n, v1_n, work_n, div_n, uv1_n, uv0_n,
    u01_n, v01_n, z_n;

  /* Check for threshold. */
  if (op1_n < ssh_mpk_karatsuba_mul_words ||
      op2_n < ssh_mpk_karatsuba_mul_words)
    return 0;

  if (op1_n < op2_n)
    div_n = op1_n / 2;
  else
    div_n = op2_n / 2;

  /* Compute sizes and positions to make things much clearer later.
     Compiler will interleave these if it is any good? */
  u0_n = div_n;
  u1_n = op1_n - div_n;
  v0_n = div_n;
  v1_n = op2_n - div_n;

  /* We need some working space. */
  uv1_n = u1_n + v1_n + 1;
  uv0_n = u0_n + u0_n + 1;

  if (u1_n > u0_n)
    u01_n = u1_n + 1;
  else
    u01_n = u0_n + 1;

  if (v1_n > v0_n)
    v01_n = v1_n + 1;
  else
    v01_n = v0_n + 1;

  z_n = u01_n + v01_n + 1;

  /* Add up all sizes. */
  work_n = uv1_n + uv0_n + u01_n + v01_n + z_n;

  /* Compute the recursive effect! */
  work_n += ssh_mpk_mul_karatsuba_needed_memory(u1_n, v1_n);
  work_n += ssh_mpk_mul_karatsuba_needed_memory(u0_n, v0_n);
  work_n += ssh_mpk_mul_karatsuba_needed_memory(u01_n, v01_n);

  /* Return the amount of memory used in total. */
  return work_n;
}

/* Montgomerys asymptotically fast multiplication. This is basically a
   recursive function, which divides each input into two and calls
   itself until ready for school multiplication. */
Boolean
ssh_mpk_mul_karatsuba(SshWord *ret, unsigned int ret_n,
                           SshWord *op1, unsigned int op1_n,
                           SshWord *op2, unsigned int op2_n,
                           SshWord *work_space, unsigned int work_space_n)
{
  if (op1_n < ssh_mpk_karatsuba_mul_words ||
      op2_n < ssh_mpk_karatsuba_mul_words)
    {
      /* Call ssh_mpk_mul in such a way that the faster loop runs longer. */
      if (op1_n < op2_n)
        ssh_mpk_mul(ret, op1, op1_n, op2, op2_n);
      else
        ssh_mpk_mul(ret, op2, op2_n, op1, op1_n);

      return TRUE;
    }
  else
    {
      SshWord *u0, *u1, *v0, *v1, *work;
      unsigned int u0_n, u1_n, v0_n, v1_n, work_n, div_n, uv1_n, uv0_n,
        u01_n, v01_n, z_n;
      SshWord *uv1, *uv0, *u01, *v01, *z;
      Boolean work_allocated;

      /*
        Let

        u = u0 + u1*b
        v = v0 + v1*b
        b is the word size (e.g. 2^32)

        Montgomery's idea

        u * v = u1*v1*b^2 + u0*v0 +
                ((u0 + u1)*(v0 + v1) - (u1*v1) - (u0*v0))*b
              = u1*v1*b^2 + u0*v0 + (u0*v1 + u1*v0)*b
        writing

        x = u1*v1
        y = u0*v0
        z = (u0 + u1)*(v0 + v1) - x - y

        we have

        u * v = x*b^2 + y + z*b.

     */

      if (op1_n < op2_n)
        div_n = op1_n / 2;
      else
        div_n = op2_n / 2;

      /* Compute sizes and positions to make things much clearer later.
         Compiler will interleave these if it is any good? */
      u0   = op1;
      v0   = op2;
      u1   = op1 + div_n;
      v1   = op2 + div_n;
      u0_n = div_n;
      u1_n = op1_n - div_n;
      v0_n = div_n;
      v1_n = op2_n - div_n;

      /* We need some working space. */
      uv1_n = u1_n + v1_n + 1;
      uv0_n = u0_n + v0_n + 1;

      if (u0_n > u1_n)
        u01_n = u0_n + 1;
      else
        u01_n = u1_n + 1;

      if (v0_n > v1_n)
        v01_n = v0_n + 1;
      else
        v01_n = v1_n + 1;

      z_n   = u01_n + v01_n + 1;

      /* Add up all sizes. */
      work_n = uv1_n + uv0_n + u01_n + v01_n + z_n;

      /* Allocate space with ssh_malloc which should be fast enough. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_malloc(sizeof(SshWord) * work_n);
          if (!work)
            {
              return FALSE;
            }
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      /* Divide amongst the intermediate variables. */
      uv1 = work;
      uv0 = uv1 + uv1_n;
      u01 = uv0 + uv0_n;
      v01 = u01 + u01_n;
      z   = v01 + v01_n;

      /* Compute u1 * v1 */
      ssh_mpk_memzero(uv1, uv1_n);
      if (!ssh_mpk_mul_karatsuba(uv1, uv1_n, u1, u1_n, v1, v1_n,
                                 work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute u0 * v0 */
      ssh_mpk_memzero(uv0, uv0_n);
      if (!ssh_mpk_mul_karatsuba(uv0, uv0_n, u0, u0_n, v0, v0_n,
                                 work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute sizes. */
      while (uv1_n && uv1[uv1_n - 1] == 0)
        uv1_n--;
      while (uv0_n && uv0[uv0_n - 1] == 0)
        uv0_n--;

      /* Compute (u0 + u1). */
      if (ssh_mpk_add(u01, u1, u1_n, u0, u0_n))
        u01[u01_n - 1] = 1;
      else
        u01_n--;

      /* Compute (v0 + v1). */
      if (ssh_mpk_add(v01, v1, v1_n, v0, v0_n))
        v01[v01_n - 1] = 1;
      else
        v01_n--;

      /* Compute (u0 + u1)*(v0 + v1). */
      z_n = u01_n + v01_n + 1;
      ssh_mpk_memzero(z, z_n);
      if (!ssh_mpk_mul_karatsuba(z, z_n, u01, u01_n, v01, v01_n,
                                 work_space, work_space_n))
        {
          if (work_allocated) ssh_free(work);
          return FALSE;
        }

      /* Compute now:
         z - x - y. */

      ssh_mpk_sub(z, z, z_n, uv1, uv1_n);
      ssh_mpk_sub(z, z, z_n, uv0, uv0_n);
      /* Compute size. */
      while (z_n && z[z_n - 1] == 0)
        z_n--;

      /* Add up. */

      ssh_mpk_memcopy(ret, uv0, uv0_n);
      ssh_mpk_add(ret + div_n, ret + div_n, ret_n - div_n,
                  z, z_n);
      ssh_mpk_add(ret + div_n * 2, ret + div_n * 2, ret_n - div_n * 2,
                  uv1, uv1_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_free(work);

      return TRUE;
    }
}

#else










/* Compute the needed memory for the Karatsuba squaring. */
unsigned int ssh_mpk_square_karatsuba_needed_memory(unsigned int op_n)
{
  return 0;
}

Boolean ssh_mpk_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space,
                              unsigned int work_space_n)
{
  ssh_mpk_mul(ret, op, op_n, op, op_n);

  return TRUE;
}

unsigned int ssh_mpk_mul_karatsuba_needed_memory(unsigned int op1_n,
                                                 unsigned int op2_n)
{
  return 0;
}


Boolean ssh_mpk_mul_karatsuba(SshWord *ret, unsigned int ret_n,
                           SshWord *op1, unsigned int op1_n,
                           SshWord *op2, unsigned int op2_n,
                           SshWord *work_space, unsigned int work_space_n)
{
  if (op1_n < op2_n)
    ssh_mpk_mul(ret, op1, op1_n,
                op2, op2_n);
  else
    ssh_mpk_mul(ret, op2, op2_n,
                op1, op1_n);
  return TRUE;
}

#endif /* SSH_MPK_USE_ALGORITHM */

/* Compute the number of leading zero bits. This is useful with
   division, especially when needing normalization. */
unsigned int ssh_mpk_leading_zeros(SshWord *d, unsigned int d_n)
{
  SshWord r, v;

  /* Quick check. */
  v = d[d_n - 1];
  if (v & ((SshWord)1 << (SSH_WORD_BITS - 1)))
    return 0;

  r = 0;
  SSH_MPK_COUNT_LEADING_ZEROS(r, v);
  return r;
}

/* Basic division of an large integer. Returns quotient in q and
   remainder in r. r should be set to the dividend when called.
   This algorithm is derived from HAC. Returns FALSE in case of
   division by zero. */
Boolean ssh_mpk_div(SshWord *q, unsigned int q_n,
                 SshWord *r, unsigned int r_n,
                 SshWord *d, unsigned int d_n)
{
  unsigned int i;
  SshWord div, divl, rem, quot, c2, c1, c, rh, rl, rll;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord *tmp, k, t;
#endif

  /* We'd like to have optimized cases for all lengths of divisor, but
     that's impossible. Instead we have separated the trivial cases,
     and we'll do most of the work in the default case. */
  if (d_n == 0)
    {
    /* Divide by zero. */
      return FALSE;
    }

  if (d_n == 1)
    {
      /* This should be very fast, one could even check for some
         special divisors. Same algorithm is basically used later
         in some functions. */
      div = d[0];
      rem = 0;

      for (i = r_n; i; i--)
        SSH_MPK_LONG_DIV(q[i - 1], rem, rem, r[i - 1], div);
      r[0] = rem;

      return TRUE;
    }
  /* Other small cases? 2, 3, 4, ... would these speed things up
     in some particular cases? Probably, considering that some of
     our applications use integers of size 200 bits, and 64*4 >
     200. */

  /* General case, with very large divisors. */

  /* Reduce n such that n < d_n*b^(n_n - d_n). This step should be
     performed only once if everything goes nicely. Notice that
     this step also ensures that our macro for division
     will work. */

  if (ssh_mpk_cmp(r + (r_n - d_n), d_n, d, d_n) >= 0)
    {
      ssh_mpk_sub(r + (r_n - d_n), r + (r_n - d_n), d_n, d, d_n);
      q[r_n - d_n] = 1;
    }

  /* Main loop of division code. */
  for (i = r_n, div = d[d_n - 1], divl = d[d_n - 2]; i > d_n; i--)
    {
      rh = r[i - 1];
      rl = r[i - 2];

      /* This test makes it possible to use this loop for division
         of less than 3 word numbers. Otherwise we'd need to write
         special case routine. Which would be faster though. */

      if (i >= 3)
        rll = r[i - 3];
      else
        rll = 0;

      if (rh == div)
        quot = -1;
      else
        {
          /* Idea here is to compute:

             quot = (xh*b + xl) / yh
             rem  = (xh*b + xl) % yh

             then

             c = quot * yl

             now we can check if

             quot * (yh*b + yl) > xh*b^2 + xl*b + xll

             by checking when

             quot*yl + quot * yh*b > xh*b^2 + xl*b + xll

             <=>

             c + xh*b^2 + xl*b - rem*b > xh*b^2 + xl*b + xll

             <=>

             c - rem*b > xll

             Now we can easily work with only one division and
             one multiplication to get the quot correct.

             */

          SSH_MPK_LONG_DIV(quot, rem, rh, rl, div);
          SSH_MPK_LONG_MUL(c2, c1, quot, divl);

          /* Now reduce quot, until it is correct. This loop is
             correct, because c - rem*b > xll iff c2 > rem or
             c2 == rem and c1 > n[i - 2], otherwise c - rem*b is equal
             or less than xll.

             The reduction of c and rem can be performed without slow
             arithmetic because

             c = quot*yh

             that is

             c = (quot - 1)*yl =  quot * yl - yl

             and

             rem = (xh*b + xl) % yh

             thus

             rem = xh*b + xl - quot*yh

             now

             rem = xh*b + xl - (quot - 1)*yh
             <=> rem = xh*b + xl - quot*yh + yh
             <=> rem = rem + yh

             which is what we are after.
             */

          while (c2 > rem || (c2 == rem && c1 > rll))
            {
              quot--;

              rem += div;
              if (rem < div)
                break;

              if (c1 < divl)
                c2--;
              c1 -= divl;
            }
        }
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
      c = ssh_mpk_submul_n(r + i - d_n - 1, quot, d, d_n);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */

      /* Now we have a "quot" which is almost correct (possibly 1
         too large). And can thus compute quickly a suitable
         multiple of d such that we can reduce the dividend.  */

      for (j = 0, c = 0, tmp = r + i - d_n - 1; j < d_n; j++)
        {
          SSH_MPK_LONG_MUL(c2, c1, d[j], quot);

          /* We use here the carry along the way. That is we don't need
             to loop at all, but just to keep track of the carry
             until the end of the run. */
          c1 += c;
          if (c1 < c)
            c2++;
          c = c2;

          /* Now compute the actual word to place in appropriate place. */
          k = tmp[j];
          t = k - c1;
          if (t > k)
            c++;
          tmp[j] = t;
        }
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */

      /* Add if negative to make positive. E.g. this is the
         final correction phase, after the "quot" must be correct. */
      if (rh < c)
        {
          ssh_mpk_add(r + (i - d_n - 1), r + (i - d_n - 1), d_n, d, d_n);
          quot--;
        }

      q[i - d_n - 1] = quot;
    }

  return TRUE;
}

/* Simple proof for the following algorithm (we have used it before
   already).

   input: k of n words

   Computation:
     q * d + r = k
   where r is a one word remainder.

   Now, k - q*d = r and given division of 2 word by 1 word we can compute

       div(q_0, r_0, 0, k_n-1, d)
   <=> k_n-1 = q_0*d + r_0

   then

       div(q_1, r_1, r_0, k_n-2, d)
   <=> r_0*b + k_n-2 = q_1*d + r_1

   and thus

       (k_n-1 - q_0*d)*b + k_n-2 = q_1*d + r_1
   <=> k_n-1*b + k_n-2 = (q_0*b + q_1)*d + r_1

   now by induction this holds until the end. That is, we get the
   remainder as r_n-1 and quotients in (wrong) order q_0...q_n-1.
 */

/* Note, the 'r' here is not altered, although it basically would
   contain the remainder if computed in above way. */
SshWord ssh_mpk_div_ui(SshWord *q, unsigned int q_n,
                       SshWord *r, unsigned int r_n,
                       SshWord d)
{
  unsigned int i;
  SshWord rem;

  /* Initialize the remainder. */
  rem = 0;

  /* Follow up with the rest. */
  for (i = r_n; i; i--)
    SSH_MPK_LONG_DIV(q[i - 1], rem, rem, r[i - 1], d);
  return rem;
}

/* This works as the one above. */
SshWord ssh_mpk_mod_ui(SshWord *r, unsigned int r_n,
                       SshWord d)
{
  unsigned int i;
  SshWord rem, t;

  /* Initialize the remainder variable. */
  rem = 0;

  /* Follow up with the rest. */
  for (i = r_n; i; i--)
    SSH_MPK_LONG_DIV(t, rem, rem, r[i - 1], d);
  return rem;
}

/* Computation of the remainder in a way that ignores the quotient
   altogether.  Makes allocation easier for the ssh_mpk_mod. Might be
   a bit faster than the ssh_mpk_div however, main point is to reduce
   allocation. */
Boolean ssh_mpk_mod(SshWord *r, unsigned int r_n,
                 SshWord *d, unsigned int d_n)
{
  unsigned int i;
  SshWord div, divl, rem, quot, c2, c1, c, t, rh, rl, rll;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord *tmp, k;
#endif

  /* We'd like to have optimized cases for all lengths of divisor. */
  if (d_n == 0)
    {
    /* Divide by zero. */
      return FALSE;
    }

  if (d_n == 1)
    {
      /* This should be very fast, one could even check for some
         special divisors. */
      div = d[0];
      rem = 0;

      for (i = r_n; i; i--)
        SSH_MPK_LONG_DIV(t, rem, rem, r[i - 1], div);
      r[0] = rem;

      return TRUE;
    }

  /* Other small cases? 2, 3, 4, ... would these speed things
     up in some particular cases. */

  /* General case, with very large divisors. */

  /* Reduce n such that n < d_n*b^(n_n - d_n). This step should be
     performed only once if everything goes nicely. */

  if (ssh_mpk_cmp(r + (r_n - d_n), d_n, d, d_n) >= 0)
    ssh_mpk_sub(r + (r_n - d_n), r + (r_n - d_n), d_n, d, d_n);

  for (i = r_n, div = d[d_n - 1], divl = d[d_n - 2]; i > d_n; i--)
    {
      rh = r[i - 1];
      rl = r[i - 2];

      /* This allows us to divide by two limb values. */
      if (i >= 3)
        rll = r[i - 3];
      else
        rll = 0;

      if (rh == div)
        quot = -1;
      else
        {
          /* See ssh_mpk_div for further comments. */

          SSH_MPK_LONG_DIV(quot, rem, rh, rl, div);
          SSH_MPK_LONG_MUL(c2, c1,  quot, divl);

          while (c2 > rem || (c2 == rem && c1 > rll))
            {
              quot--;

              rem += div;
              if (rem < div)
                break;

              if (c1 < divl)
                c2--;
              c1 -= divl;
            }
        }

#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
      c = ssh_mpk_submul_n(r + i - d_n - 1, quot, d, d_n);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */

      /* Use assembler subroutine here if possible. */

      for (j = 0, c = 0, tmp = r + i - d_n - 1; j < d_n; j++)
        {
          SSH_MPK_LONG_MUL(c2, c1, d[j], quot);

          c1 += c;
          if (c1 < c)
            c2++;
          c = c2;

          /* Now compute the actual word to place in appropriate place. */
          k = tmp[j];
          t = k - c1;
          if (t > k)
            c++;
          tmp[j] = t;
        }
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */

      /* Add if negative to make positive. */
      if (rh < c)
        ssh_mpk_add(r + (i - d_n - 1), r + (i - d_n - 1), d_n, d, d_n);
    }
  return TRUE;
}

/* Reasonably fast binary gcdext. Here `g' must have size

     `min(u_n, v_n) + 1'.

   This function modifies the arguments it obtains, but does not grow
   beyond their original sizes.

   The temporary variable `t' must have size `max(u_n, v_n)'.

   It is unclear whether this is faster that the traditional Euclid's
   algorithm for greatest common divisor.
*/
void ssh_mpk_gcd(SshWord *g, SshWord *t,
                 SshWord *u, unsigned int u_n, SshWord *v, unsigned int v_n)
{
  unsigned int i = 0, j = 0, k = 0, words = 0, bits = 0, t_n = 0;
  Boolean t_s;

  /* Nothing to do? */
  if (u_n == 0 || v_n == 0)
    return;

  /* When working with single precision integers we can do it faster
     using Euclid's algorithm. */
  if (u_n == 1 && v_n == 1)
    {
      SshWord a, b;

      a = u[0];
      b = v[1];

      while (b != 0)
        {
          SshWord c;
          a = a % b;
          c = a;
          a = b;
          b = c;
        }
      g[0] = a;
      return;
    }

  /* Compute the number of times 2 divides u and v. */
  for (words = 0; u_n && v_n;)
    {
      SshWord b;
      for (j = 0, bits = 0, b = 1; j < SSH_WORD_BITS; j++, b <<= 1)
        {
          if ((u[0] & b) == 0 &&
              (v[0] & b) == 0)
            bits++;
          else
            break;
        }
      if (j < SSH_WORD_BITS)
        break;

      words++;

      u++;
      v++;
      u_n--;
      v_n--;
    }

  /* Shift. */
  ssh_mpk_shift_down_bits(u, u_n, bits);
  ssh_mpk_shift_down_bits(v, v_n, bits);

  /* Handle the special case. */
  if (u[0] & 1)
    {
      t_n = v_n;
      t_s = TRUE;
      for (i = 0; i < v_n; i++)
        t[i] = v[i];
    }
  else
    {
      t_n = u_n;
      t_s = FALSE;
      ssh_mpk_memcopy(t, u, u_n);
    }

  while (1)
    {
      SshWord b;
      int rv;

      /* Divide by 2. */
      for (k = 0; t_n;)
        {
          for (i = 0, b = 1, k = 0; i < SSH_WORD_BITS; i++)
            {
              if (t[0] & b) k++; else break;
            }
          if (i < SSH_WORD_BITS)
            break;
          t++;
          t_n--;
        }
      if (k) ssh_mpk_shift_down_bits(t, t_n, k);

      /* Check the sign. */
      if (!t_s)
        {
          u_n = t_n;
          ssh_mpk_memcopy(u, t, t_n);
        }
      else
        {
          v_n = t_n;
          ssh_mpk_memcopy(v, t, t_n);
        }

      /* Recompute `t'. */
      rv = ssh_mpk_cmp(u, u_n, v, v_n);
      if (rv == 0)
        break;

      /* Subtract. */
      if (rv < 0)
        {
          t_n = v_n;
          t_s = TRUE;
          ssh_mpk_sub(t, v, v_n, u, u_n);
        }
      else
        {
          t_n = u_n;
          t_s = FALSE;
          ssh_mpk_sub(t, u, u_n, v, v_n);
        }

      /* Find the exact size for `t'. */
      while (t_n && t[t_n-1] == 0)
        t_n--;
    }

  /* Copy to output. */
  ssh_mpk_memcopy(g + words, u, u_n);
  ssh_mpk_shift_up_bits(g + words, u_n + 1, bits);
}


void ssh_mpmk_reduce_192(SshWord *ret, unsigned int ret_n,
                         SshWord *op,  unsigned int op_n,
                         SshWord mp, const SshWord big_mp[3],
                         const SshWord *m,   unsigned int m_n)
{
  unsigned int i;

  ssh_mpk_memcopy(ret, op, op_n);

  for (i = 0; i + 2 < m_n; i += 3)
    {
      ssh_mpmk_addmul_n_192(ret + i, big_mp, m, m_n);
    }

  for (; i < m_n; i++)
    {
      ssh_mpmk_addmul_n(ret + i, mp, m, m_n);
    }

  ssh_mpk_memcopy(ret, ret + m_n, m_n + 1);

  ret_n = m_n + 1;

  while (ret_n && ret[ret_n - 1] == 0)
    ret_n--;

  if (ssh_mpk_cmp(ret, ret_n, (SshWord *) m, m_n) >= 0)
    ssh_mpk_sub(ret, ret, ret_n, (SshWord *) m, m_n);
}

/* Compute x^-1 == a (mod 2^SSH_WORD_BITS). Please, use the Newton
   iteration method. It is fastest and easily proven to be correct. */


SshWord ssh_mpmk_small_inv(SshWord a)
{
  SshWord t, k;

  /* Check to make sure that this terminates. */
  if (!(a & 1))
    return 0;

  /* Using the standard Newton's iteration. This should be significantly
     faster than the above.

     Exercise: Prove that this sequence (x_n+1 = x_n*(2 - a*x_n) (mod 2^k))
               converges quadratically, iff a == a^-1 (mod 2).
     Hint:     Follow the steps

               1. Obtain an expression for the error e_i+1 in terms of
                  error e_i.
               2. Use the expression to show that e_k -> 0.
               3. Now as the sequence converges determine the speed.

               as given by G.W. Stewart in his
               Afternotes on Numerical Analysis.

     You can also prove it for the more general case (mod p^k) as easily.  */
  t = a;
  while (1)
    {
      k = t * a;
      if (k == 1)
        break;
      k = 2 - k;
      t = k * t;
    }
  return t;
}

void ssh_mpmk_2adic_neg(SshWord *ret, SshWord *op, unsigned int op_n)
{
  unsigned int i, c;
  for (i = 0, c = 1; i < op_n; i++)
    {
      SshWord t;
      t      = ~op[i];
      ret[i] = t + c;
      if (ret[i] < t)
        c = 1;
      else
        c = 0;
    }
}
































void
ssh_mpmk_triple_inv(SshWord * a)
{
  SshWord t[3], k[6];
  SshWord two[3] = {2, 0, 0};

  /* Check to make sure that this terminates. */
  if (!(a[0] & 1))
    return;

  ssh_mpk_memcopy(t,a, 3);
  while (1)
    {
      SshWord tmp[6];
      k[0] = 0; k[1] = 0; k[2] = 0;

      /* k = t * a; */
      ssh_mpk_addmul_n_192(k, t, a, 3);

      if (k[0] == 1 && k[1] == 0 && k[2] == 0)
        break;

      /* k = 2 - k; */
      ssh_mpk_sub_n(tmp, two, k, 3);

      ssh_mpk_memcopy(k, tmp, 3);

      ssh_mpk_memzero(tmp, 3);
      /* t = k * t; */
      ssh_mpk_addmul_n_192(tmp, t, k, 3);

      ssh_mpk_memcopy(t, tmp, 3);
    }

  ssh_mpk_memcopy(a, t, 3);
}

/* sshmath-kernel.c */
#endif /* SSHDIST_MATH */
