/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The kernel functions of the SSH mathematics library.
*/

#ifndef SSHMP_KERNEL
#define SSHMP_KERNEL

#include "sshmp-types.h"

#ifdef HAVE_MATH_H
#include "math.h"
#endif /* HAVE_MATH_H */

/* We define here all the macros that are needed by the SSH mathematics
   library. */

#ifdef SSHMATH_ASSEMBLER_MACROS
#ifdef SSHMATH_I386
#ifdef WINDOWS

#include "sshmp-asmopt_i386-windows.h"
/* Rename the macros for this library. */
#define SSH_MPK_COUNT_TRAILING_ZEROS(count,x) \
  ssh_winasm_count_trailing_zeros(count,x)
#define SSH_MPK_COUNT_LEADING_ZERO(count,x) \
  ssh_winasm_count_leading_zeros(count,x)
#define SSH_MPK_LONG_MUL(w1,w0,u,v) \
  ssh_winasm_long_mul(w1,w0,u,v)
#define SSH_MPK_LONG_SQUARE(w1,w0,u) \
  ssh_winasm_long_mul(w1,w0,u,u)
#define SSH_MPK_LONG_DIV(q,r,n1,n0,d) \
  ssh_winasm_long_div(q,r,n1,n0,d)

#else /* !WINDOWS */
/* Fast trailing zero searching using i386 special instruction. */
#define SSH_MPK_COUNT_TRAILING_ZEROS(count, x)  \
__asm__("bsfl %1,%0" : \
        "=r" (count) : "rm" ((SshWord)(x))); \

/* For leading zeros. */
#define SSH_MPK_COUNT_LEADING_ZEROS(count, x) \
  __asm__("bsrl %1,%0; xorl $31, %0" : \
          "=r" (count) : "rm" ((SshWord)(x)));

/* Fast multiplication. */
#define SSH_MPK_LONG_MUL(u, v, a, b)      \
__asm__("mull %3"                 \
        : "=a" ((SshWord)v), \
          "=d" ((SshWord)u)  \
        : "0" ((SshWord)a), \
          "rm" ((SshWord)b))

#define SSH_MPK_LONG_SQUARE(u,v,a) \
  SSH_MPK_LONG_MUL(u,v,a,a);

/* Fast division. */
#define SSH_MPK_LONG_DIV(q, r, d1, d0, d)  \
__asm__("divl %4"                  \
        : "=a" ((SshWord)q),  \
          "=d" ((SshWord)r)   \
        : "0"  ((SshWord)d0), \
          "1"  ((SshWord)d1), \
          "rm" ((SshWord)d))
#endif /* WINDOWS */
#endif /* SSHMATH_I386 */

/* Other assembler language macros. */

/* DEC Alpha inline macros. */
#ifdef SSHMATH_ALPHA
#ifdef __GNUC__
/* GCC compiler. */
#define SSH_MPK_LONG_MUL(w1,w0,n1,n0)                           \
{                                                               \
  __asm__ ("umulh %1,%2,%0"                                     \
           : "=r" ((SshWord) w1)                                \
           : "%rJ" ((SshWord) n1), "rI" ((SshWord) n0));        \
  w0 = n1 * n0;                                                 \
}
#define SSH_MPK_LONG_SQUARE(w1,w0,a) SSH_MPK_LONG_MUL(w1,w0,a,a)

#elif defined(SSHMATH_ALPHA_DEC_CC_ASM)
/* DEC compiler. See the file "c_asm.h" for details of Alpha
   inline assembler. (There is an example for this very macro!)

   It says that DEC C++ versions before V5.3 do not support this. One should
   have a check for this somewhere.
   */
#include <c_asm.h>
#define SSH_MPK_LONG_MUL(w1,w0,n1,n0) \
{ \
  w1 = asm("umulh %a0, %a1, %v0", (SshWord)n1, (SshWord)n0); \
  w0 = asm("mulq  %a0, %a1, %v0", (SshWord)n1, (SshWord)n0); \
}
#define SSH_MPK_LONG_SQUARE(w1,w0,a) SSH_MPK_LONG_MUL(w1,w0,a,a)
#endif /* ! __GNUC__ */
#endif /* SSHMATH_ALPHA */

#endif /* SSHMATH_ASSEMBLER_MACROS */

/* The general purpose macros. */

/* Low and high bit masks. */
#define SSH_MPK_LOW_BIT_MASK (((SshWord)1   << (SSH_WORD_HALF_BITS)) - 1)
#define SSH_MPK_HIGH_BIT_MASK (SSH_MPK_LOW_BIT_MASK << (SSH_WORD_HALF_BITS))

/* Take the low and high halves of words. */
#define SSH_MPK_LOW_PART(x) ((x) & SSH_MPK_LOW_BIT_MASK)
#define SSH_MPK_HIGH_PART(x) ((x) >> (SSH_WORD_HALF_BITS))

#ifndef SSH_MPK_COUNT_LEADING_ZEROS
#define SSH_MPK_COUNT_LEADING_ZEROS(count,x) \
  do { count = ssh_mpk_count_leading_zeros(x); } while(0)
#endif /* SSH_MPK_COUNT_LEADING_ZEROS */

#ifndef SSH_MPK_COUNT_TRAILING_ZEROS
#define SSH_MPK_COUNT_TRAILING_ZEROS(count, x) \
  do { count = ssh_mpk_count_trailing_zeros(x); } while(0)
#endif /* SSH_MPK_COUNT_TRAILING_ZEROS */

#ifndef SSH_MPK_LONG_MUL
/* Determine the macro to use. If multiplication is very fast relative to
   addition then use the other method implemented. However, it has
   been found that on Digital Alpha platform the speed of the latter
   multiplication is faster by noticeable amount. Nevertheless, other
   platforms likely will benefit from the choice between algorithms. */
#ifdef SSHMATH_MUL_IS_FAST

/* Multiply the two SshWords `n1' and `n0' and store the result to
   `(w1, w0)'. `w1' is the more significant word and `w0' the less
   significant.

   The algorithm is the standard elementary-school method for
   multiplication: to calculate

         d c
       * b a

   calculate e = ca, f = db, g = cb, h = ad and sum up: (a-d are
   half-words, e-h are full words. e^ is the upper half and e_ the
   lower):

           e^ e_
        g^ g_
        h^ h_
   + f^ f_
   --------------

   Note: the code uses the variable `c' to store `g' and inlines the
   variable `h'.

   There are many possibilities for choosing how to perform the
   summation. We use this method: first add together

           e^
        g^ g_
        h^ h_

   If SshWord is `n' bits long, then

        g, h <= (2^(n/2) - 1)(2^(n/2) - 1) = 2^n - 2^(n/2 + 1) + 1.

   Obviously e^ <= (2^(n/2) - 1). Therefore the sum, S, is bounded by

        S <= 2^(n + 1) - 2^(n/2 + 1) + 2 + 2^(n/2) - 1 =
             2^(n + 1) - 2^(n/2) + 1

   Therefore, S can have wrapped around at most once.  If wrapping has
   happened (check if the result is smaller than e.g. `g'), remember
   the carry.

   We now have S = S^ S_.  The remaining addition is

                  e_
            S^ S_
         C
       + f^ f_

   The result will be in two words. The lower word is S_ + e_. This
   can be calculated by ORing because e_ < 2^(n/2) and S_ % 2^(n/2) ==
   0.  The upper word is calculated by adding S^ to f, and then the
   carry bit to f^ if necessary.

   [Why is this a good way for performing the summation?  Because the
   initial addition succeeds in adding five half-words together and
   still can produce at most 1 as a carry.  Adding e.g. the two
   left-most columns could give 2 as a carry which would lead to
   complications.]

   */

#define SSH_MPK_LONG_MUL(w1, w0, n1, n0) \
{ \
  SshWord __a, __b, __c, __d, __e, __f; \
 \
  __c = SSH_MPK_LOW_PART(n0); \
  __d = SSH_MPK_HIGH_PART(n0); \
  __a = SSH_MPK_LOW_PART(n1); \
  __b = SSH_MPK_HIGH_PART(n1); \
  __e = __c * __a; \
  __f = __d * __b; \
  __c *= __b; \
  __b = (__c + __d * __a + SSH_MPK_HIGH_PART(__e)); \
  if (__b < __c) __f += ((SshWord)1 << SSH_WORD_HALF_BITS);  \
  w1 = __f + (SSH_MPK_HIGH_PART(__b)); \
  w0 = SSH_MPK_LOW_PART(__e) | (__b << SSH_WORD_HALF_BITS); \
}
#else /* SSHMATH_MUL_IS_FAST */

/* This algorithm is based on an idea by prof. Peter L. Montgomery. It
   seems to be more suitable for word size multiplication than
   Karatsuba's idea. We describe the details of the algorithm.

   Note also that Henri Cohen discusses the generalization of this method
   in his book.

   Basic idea here is to compute w = n1*n0, 0 < n1, n0 <= W - 1, in parts as

     n0 = c + W*d
     n1 = a + W*b

   where W = 2^m, and m is the bit size of the computer word. Hence, this
   algorithm computes

     x = a*c and y = d*b

   from where

     z = (a + b)*(c + d) - (x + y)
       = a*d + b*c

   is calculated modulo W. That is, z = overflow*W + z', of which
   z' is computed.

   Montgomery's idea is to retrieve the overflow by a clever inequality. One
   has

     -2^m + 2^(m/2) < z - 2^(m/2-1)*(a + c + b + d) < 0,

   which implies that

     2^m - 1 > (a + c + b + d)/2 - z/2^(m/2) > 0.

   From this we can substitute the above as

     2^m - 1 + overflow*2^(m/2) >
         (a + c + b + d)/2 - z'/2^(m/2) > overflow*2^(m/2),

   which can be interpreted as a quarantee that computing

      t = (a + c + b + d)/2 - z'/2^(m/2),

   recovers the bits of the overflow exactly (by suitably masking the
   result).


   The most interesting aspect of this algorithm is that only three
   multiplications are needed. Also this algorithm seems to be
   slightly more efficient than Karatsuba with word size inputs. Perhaps
   this can be generalized.

   Also it needs only one conditional and hence may compete with the
   four multiplication variants quite favourably.

   There are cases when this algorithm is slower than method with four
   multiplications, as multiplication can be sometimes very fast relative
   to the speed of addition. However, on most platforms this method is
   likely to be the fastest. It is unlikely that much faster methods
   are available.

   */

#define SSH_MPK_LONG_MUL(w1,w0,n1,n0) \
{ \
  SshWord __a, __b, __c, __d, __x, __y, __z; \
 \
  __c = SSH_MPK_LOW_PART(n0); \
  __d = SSH_MPK_HIGH_PART(n0); \
  __a = SSH_MPK_LOW_PART(n1); \
  __b = SSH_MPK_HIGH_PART(n1); \
 \
  __x = __a*__c; __y = __d*__b; \
  __c += __d; __d = __a + __b;  \
  __z = __c*__d - __x - __y; \
 \
  __a = __z << SSH_WORD_HALF_BITS; __b = __z >> SSH_WORD_HALF_BITS; \
  __x += __a; if (__x < __a) __y++; \
  \
  (w0) = __x; \
  (w1) = __y + __b + ((((__c + __d)>>1) - __b) & SSH_MPK_HIGH_BIT_MASK); \
 \
}
#endif /* SSHMATH_MUL_IS_FAST */
#endif /* SSH_MPK_LONG_MUL */

#ifndef SSH_MPK_LONG_SQUARE

#ifdef SSHMATH_MUL_IS_FAST
/* Specific squaring macro.

   Square the SshWord `a' and store the result to `(w1, w0)',
   `w1' being the more significant word.

   This is derived from SSH_MPK_LONG_MUL(w1, w0, a, a) by observing
   that now __c == __a and __d == __b.

   */

#define SSH_MPK_LONG_SQUARE(w1, w0, a) \
{ \
  SshWord __a, __b, __c, __e, __f; \
  __a = SSH_MPK_LOW_PART(a); __b = SSH_MPK_HIGH_PART(a); \
  __e = __a * __a; __f = __b * __b; __c = __a * __b; \
  __b = (__c + __c + SSH_MPK_HIGH_PART(__e)); \
  if (__b < __c) __f += ((SshWord)1 << SSH_WORD_HALF_BITS);  \
  w1 = __f + (SSH_MPK_HIGH_PART(__b)); \
  w0 = SSH_MPK_LOW_PART(__e) | (__b << SSH_WORD_HALF_BITS); \
}

#else /* SSHMATH_MUL_IS_FAST */

/* This squaring algorithm is based on the idea of prof. Peter L.
   Montgomery. It is not clear whether this is faster than the
   above one.

   There is one noteworthy distinction. This algorithm can be generalized
   to squaring of arbitrary size integers. The above one needs general
   multiplication for support, however, this method is an asymptotically
   fast squaring method.
   */

#define SSH_MPK_LONG_SQUARE(w1,w0,a) \
{ \
  SshWord __a, __b, __x, __y, __z, __t; \
 \
  __a = SSH_MPK_LOW_PART(a); \
  __b = SSH_MPK_HIGH_PART(a); \
 \
  __x = __a*__a; __y = __b*__b; \
  __t = (__a + __b); \
  __z = __t*__t - __x - __y; \
 \
  __a = __z << SSH_WORD_HALF_BITS; __b = __z >> SSH_WORD_HALF_BITS; \
  __x += __a; if (__x < __a) __y++; \
 \
  (w0) = __x; \
  (w1) = __y + __b + ((__t - __b) & SSH_MPK_HIGH_BIT_MASK); \
 \
}

#endif /* SSHMATH_MUL_IS_FAST */

#endif /* SSH_MPK_LONG_SQUARE */

/* The long division macro.

   I. Interface

   Divide the two-word value `(n1, n0)', `n1' being the more
   significant word, by the single-word value `d'.  Store the quotient
   to `q' and the remainder to `r'.

   The preconditions for invoking this macro are:

   (1) (n1, n0) / d fits into a single SshWord, and

   (2) d is normalized, i.e. its highest bit is set.

   II. Method

   The method is derived from the standard elementary-school method
   for long division. The normalization idea comes from Knuth.

   The method is the following: Let (n1, n0) = (h3, h2, h1, h0),
   i.e. `n1' contains the half-words `h3' and `h2', and `n0' contains
   the half-words `h1' and `h0'. Let `d' = `(d1, d0)' similarly.

   We may assume n1 < d because q must fit into a single word.
   Standard long division would first divide (h3, h2, h1) by (d1, d0)
   and obtain the higher word of the quotient:

   :                         q1
   :                 _______________
   :           d1 d0 | h3 h2 h1 **

   However, we cannot do that because (h3, h2, h1) is longer than a
   single word. Instead, use the following idea (this is why
   normalization is used): compute an approximation of q1 as

      q1' = (h3, h2) / d1

   Let a half-word be `h' bits long. We find that

      q1' - q1 = (h3, h2, 0) / (d1, 0) - (h3, h2, h1) / (d1, d2).

   This cannot be less than zero because

      h1/(d1, d2) <= (2^h - 1)/(d1 * 2^h + 0) = 0,

   as far as integer division is concerned (and we are now performing
   integer division). An upper bound for the difference is obtained as
   follows: Assume (h3, h2) is the largest possible value i.e.  2^(2h)
   - 1. Let d2 be the largest possible value 2^h - 1 and h1 = 0. Let
   d1 be the smallest possible value, i.e. 2^(h-1).  The difference
   becomes

      (2^(2h) - 1)/(2^h 2^(h-1)) -
        { (2^(2h) - 1)/(2^h 2^(h-1) + 2^h - 1) }

      = 2 - { ... }

   But as shown above, the difference cannot be less than zero.
   Therefore the maximum difference is 2.

   This shows that *q1' lies in the set {q1, q1 + 1, q1 + 2}*.

   The next thing to do normally is to subtract
   q1 (d1, d0) from (h3, h2, h1):

   :                         q1
   :                 _______________
   :           d1 d0 | h3 h2 h1 h0
   :                -  ........
   :                      r2 r1 h0

   and then continue division by dividing (r2, r1, h0).  In other
   words, to calculate (h3, h2, h1) % (d1, d0).

   Here, calculate an approximation of this value as

     (h3, h2, 0) % (d1, 0) + (0, h1) - (d0 * q1') = (r2', r1')

   Which is the same as

     (h3, h2, h1) - q1' (d1, d0)

   and thus corresponds to the approximation of q1 that we computed.

   The next thing is to fix the remainder and the quotient in the case
   the approximation is wrong. This is easy. Because q1 is the correct
   quotient,

     (h3, h2, h1) - q1 (d1, d0) < (d1, d0).

   Therefore, if q1' > q1,

     (h3, h2, h1) - q1' (d1, d0) < 0.  (1)

   Thus while (h3, h2, h1) - q1' (d1, d0) < 0, decrement q1' by one
   and increment (r2', r1') by (d1, d0) to compensate for the
   decremented quotient.  This must be done at most twice because of
   the (q1 + 2) bound on the value of q1'.

   After these fixes (r2', r1') is the correct remainder.
   Then do the whole thing again but now divide (r2, r1, h0):

   :                          q1 ??
   :                     __________
   :               d1 d0 | r2 r1 h0

   This is done, of course, identically.

   III. Implementation

   In the SSH_MPK_LONG_DIV macro the following variables are used:

   __a  :  d1
   __b  :  d0

   __c  :  q1' and later q0'
     d  :  divider
   __g  :  a temporary variable that contains the values of
          (h3, h2, h1) - q1' (d1, 0) and
          (r2, r1, h0) - q0' (d1, 0)
   __h  :  a temporary variable to store q1

   The computation of q1' and q0' is performed by
   SSH_MPK_LONG_DIV_STEP. The remainder approximation (r2', r1') is
   calculated in SSH_MPK_LONG_DIV_STEP except that q1' (0, d0) is
   subtracted only in SSH_MPK_LONG_DIV_FIX_REMAINDER.  The reason is
   that the condition (1) is checked for by checking whether the
   subtraction wraps around or not and it is thus more natural to do
   it in that macro.

   (Note that

      (h3, h2, h1) - q1' (d1, 0) >= 0

   because q1' was obtained by dividing (h3, h2, 0) by (d1, 0).)

                                          -- Huima

   Remark. It is often possible to select the highest word of the
   divisor in such a way that it is of some special form. Here is a
   trivial one:

     d = 2^w - 1 (all bits are ones)

   now

     (n1*2^w + n0) = b1*(2^w - 1) + b0

     (n1 - b1)*2^w + (n0 + b1) = b0 < (2^w-1).

   We may write b0' = n0 + n1, and then b1' = n1. Iff 0 <= b0' < 2^w - 1,
   we're done, otherwise b0' must be too large.

   At this point we have b0' + b1'*(2^w-1) = n1*2^w + n0, as
   we have b0' - b1' + b1'*2^w = n1*2^w + n0. Thus it is sufficient to
   compute (b0' + b1'(2^w - 1)) / (2^w - 1) = b0' / (2^w - 1) + b1'.

   Hence, we can just continue with b0' with the same algorithm
   recursively. Namely the algorithm could be

     Input: n1*2^w + n0 and 2^w - 1
     Output: (c1,c0)

     Step 1. Write i = 0, c1_i = c1, c0_i = c0.
     Step 2. Write b1_i = b1_i + c1_i, b0_i = c1_i + c0_i.
     Step 4. If b0_i < 2^w - 1, return (b1_i,b0_i). If b0_i = 2^w - 1,
             return (b1_i+1, 0).
     Step 3. Write c1_{i+1}*2^w + c0_{i+1} = b0_i, i = i + 1, goto Step 1.

   It can be extended to divisors of form (2^w +- c), where c is reasonably
   small. However, this has very little use in computations with
   single word divisors.

   In our application it can be shown that 2 iterations are required at
   most. This code will be implement, however, later.

   */

#ifndef SSH_MPK_LONG_DIV
#define SSH_MPK_LONG_DIV_FIX_REMAINDER(b,c,d,e,g)  \
  do{e=g-c*b;if(e>g){if(e+d>e){e+=d<<1;c-=2;}else{e+=d;c--;}}}while(0)
/* Remark. The expression n-c*a can be replaced by n%a, but the
   former is usually faster. */
#define SSH_MPK_LONG_DIV_STEP(a,n,c,g,extr,n0)  \
do{c=n/a;g=((n-c*a)<<SSH_WORD_HALF_BITS)|(extr(n0));}while(0)

#define SSH_MPK_LONG_DIV(q, r, n1, n0, d)  \
{ \
   SshWord __a,__b,__c,__e,__g,__h; \
\
   __a=SSH_MPK_HIGH_PART(d); \
   __b=SSH_MPK_LOW_PART(d); \
\
   /* First step */\
   SSH_MPK_LONG_DIV_STEP(__a,n1,__c,__g,SSH_MPK_HIGH_PART,n0); \
   SSH_MPK_LONG_DIV_FIX_REMAINDER(__b,__c,d,__e,__g); \
\
   /* Remember the higher part of the correct quotient */ \
   __h=__c<<SSH_WORD_HALF_BITS;\
\
   /* Second step */ \
   SSH_MPK_LONG_DIV_STEP(__a,__e,__c,__g,SSH_MPK_LOW_PART,n0); \
   SSH_MPK_LONG_DIV_FIX_REMAINDER(__b,__c,d,__e,__g); \
   /* Copy results */ \
   q=__h|__c; r=__e; \
}
#endif /* SSH_MPK_LONG_DIV */

/* Workspace definitions, that will be used when on average small amount
   of memory will be (always) needed in a function. */
#define SSH_MP_WORKSPACE_SIZE \
((SSH_MP_INTEGER_BIT_SIZE_STATIC * 2) / SSH_WORD_BITS) + 8


#define SSH_MP_WORKSPACE_DEFINE                          \
   SshWord __workspace[SSH_MP_WORKSPACE_SIZE];           \
   unsigned int __workspace_size = SSH_MP_WORKSPACE_SIZE

#define SSH_MP_WORKSPACE_ALLOC(t, t_n)                                  \
do {                                                                    \
  unsigned int __s = (t_n);                                             \
  if (__s < SSH_MP_WORKSPACE_SIZE)                                      \
    {                                                                   \
      t = __workspace;                                                  \
      __workspace_size = SSH_MP_WORKSPACE_SIZE;                         \
    }                                                                   \
  else                                                                  \
    {                                                                   \
      t = ssh_malloc(sizeof(SshWord) * (__s));                          \
      __workspace_size = __s;                                           \
    }                                                                   \
} while(0)
#define SSH_MP_WORKSPACE_FREE(t)      \
do {                                  \
  if (t != NULL)                      \
    memset((t), 0, __workspace_size); \
  if (t != __workspace)               \
    ssh_free(t);                      \
} while(0)

/* Definitions that force the library to use certain specific routines. */

/* Which squaring/multiplication algorithm to use for Karatsuba
   style speed-up?

   Algorithms by Plumb suggests only squaring, algorithm by Saarinen's
   suggests only squaring, algorithm by Karatsuba suggests multiplication,
   and algorithms by Montgomery suggest both squaring and multiplication.
   The selection of Montgomery can be taken with any of the others.

   Note that the algorithm of Montgomery here presented is given in the
   book by Henri Cohen also.
   */
#undef    SSH_MPK_USE_PLUMBS_ALGORITHM
#undef    SSH_MPK_USE_SAARINENS_ALGORITHM
#undef    SSH_MPK_USE_KARATSUBAS_ALGORITHM
#define   SSH_MPK_USE_MONTGOMERYS_ALGORITHM

/* Crossover for the Karatsuba long multiplication. This is similar concept
   as that of many other divide-and-conquer methods. One uses the fast
   method upto a crossover point after traditional (or school) algorithm
   is used. (Often fast algorithms have overhead that makes school method
   faster with short inputs.) */

#ifndef SSH_MPK_KARATSUBA_MUL_CROSSOVER
/* This choice seems good for 32-bit architectures. */
#define SSH_MPK_KARATSUBA_MUL_CROSSOVER    28
#endif /* SSH_MPK_KARATSUBA_MUL_CROSSOVER */
#ifndef SSH_MPK_KARATSUBA_SQUARE_CROSSOVER
/* This choice seems good for 32-bit architectures. */
#define SSH_MPK_KARATSUBA_SQUARE_CROSSOVER 20
#endif /* SSH_MPK_KARATSUBA_SQUARE_CROSSOVER */

/* The kernel level C functions. These functions implement the elementary
   functionality for arithmetic functions. */

/* The convention is that the word array has n words, least significant
   is the element [0], and most significant [n-1].

   In following op usually denotes the word array, and op_n length of the
   array.
   */

/* Counting bits. */
int ssh_mpk_count_trailing_zeros(SshWord x);
int ssh_mpk_count_leading_zeros(SshWord x);

/* Function for copying word arrays. The destination array 'd' must be
   of 'len' words, as well as the source array 's'. */
void ssh_mpk_memcopy(SshWord *d, SshWord *s, unsigned int len);
/* Function for zeroing word arrays. */
void ssh_mpk_memzero(SshWord *d, unsigned int len);


/* Bit shifts up for word arrays. That is, multiplies by 2^bits. */
int ssh_mpk_shift_up_bits(SshWord *op, unsigned int op_n,
                          unsigned int bits);
/* Bit shifts down for word arrays. That is, divides by 2^bits, without
   remainder.  */
int ssh_mpk_shift_down_bits(SshWord *op, SshWord op_n,
                            SshWord bits);

/* Return the exact bit length of the word array. */
unsigned int ssh_mpk_size_in_bits(SshWord *op, unsigned int op_n);

/* Compare word array with an unsigned integer. Returns 0 if equal, 1 if
   word arrays is larger, and -1 if smaller. */
int ssh_mpk_cmp_ui(SshWord *op, unsigned int op_n, SshWord u);
/* Compare two word arrays. Returns 1 if op1 is larger, -1 if smaller and
   0 otherwise. */
int ssh_mpk_cmp(SshWord *op1, unsigned int op1_n,
                SshWord *op2, unsigned int op2_n);

/* Addition of two word arrays. The result is computed to the 'ret'. 'op1'
   nor 'op2' are not modified. The return value is the carry, the addition
   is computed only upto the largest of the word arrays. The 'ret' must
   be as large as max(op1_n, op2_n). */
SshWord ssh_mpk_add(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n);
SshWord ssh_mpk_add_ui(SshWord *ret,
                       SshWord *op, unsigned int op_n,
                       SshWord v);
/* Subtraction of op2 from op1. Returns the carry, and is otherwise similar
   to the addition. */
SshWord ssh_mpk_sub(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n);
SshWord ssh_mpk_sub_ui(SshWord *ret,
                       SshWord *op, unsigned int op_n,
                       SshWord v);

/* Multiplication of 'op1' and 'op2'. The result 'ret' must have enough space
   allocated (in practice op1_n + op2_n - 1 words is enough). */
void ssh_mpk_mul(SshWord *ret,
                 SshWord *op1, unsigned int op1_n,
                 SshWord *op2, unsigned int op2_n);
/* Multiplication of 'op' with an unsigned integer. */
void ssh_mpk_mul_ui(SshWord *ret,
                    SshWord *op,  unsigned int op_n,
                    SshWord u);

/* Squaring of 'op'. The 'ret' must be of length to contain the result.
   In general op_n + op_n - 1 is enough. */
void ssh_mpk_square(SshWord *ret,
                    SshWord *op,  unsigned int op_n);


/* Karatsuba squaring algorithm. */

/* This function computes the number of words needed as work space in
   the Karatsuba squaring algorithm. */
unsigned int ssh_mpk_square_karatsuba_needed_memory(unsigned int op_n);

/* The Karatsuba squaring algorithm. The 'op' is squared to
   'ret'. Here 'ret' must be large enough. The work space pointer
   'work_space' may be NULL, in which case 'work_space_n' should also
   be 0. If work space is not allocated outside the routine does it
   itself. The function returns FALSE if work space allocation fails,
   else it returns TRUE.

   Out side allocation may speed up the routine slightly, however, in
   usual personal computers this is not dramatic.
   */
Boolean
ssh_mpk_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space,
                              unsigned int work_space_n);

/* Karatsuba multiplication algorithm. */

/* Computation of the number of words needed as work space in the Karatsuba
   multiplication algorithm. */
unsigned int ssh_mpk_mul_karatsuba_needed_memory(unsigned int op1_n,
                                                 unsigned int op2_n);

/* Multiplies 'op1' and 'op2' and places the result in 'ret'. This
   computation can use the 'work_space' if available, although it may
   be set to NULL. The function return FALSE in case of workspace
   memory allocation error, else it returns TRUE. */
Boolean
ssh_mpk_mul_karatsuba(SshWord *ret, unsigned int ret_n,
                           SshWord *op1, unsigned int op1_n,
                           SshWord *op2, unsigned int op2_n,
                           SshWord *work_space, unsigned int work_space_n);

/* Function to compute the leading zeroes of a word array. Returns the
   number of zero bits before the msb-bit (or end of the word array). */
unsigned int ssh_mpk_leading_zeros(SshWord *d, unsigned int d_n);

/* Division of 'r' by 'd'. Returns the quotient in 'q' and remainder in
   'r'. The 'q' should have at least 'r_n - d_n + 1' words of space
   preallocated. The divisor 'd' should be normalized.

   Normalization means that the integer 'd' is multiplied by 2^n so that
   the most significant word has the most significant bit set.
   */
Boolean ssh_mpk_div(SshWord *q, unsigned int q_n,
                 SshWord *r, unsigned int r_n,
                 SshWord *d, unsigned int d_n);

/* Division of 'r' by 'd'. Quotient should have enough space, about r_n
   words. The divisor 'd' should be normalized. */
SshWord ssh_mpk_div_ui(SshWord *q, unsigned int q_n,
                       SshWord *r, unsigned int r_n,
                       SshWord d);

/* Computation of 'r' modulo 'd'. As in usual division, 'd' must be
   normalized. */
Boolean
ssh_mpk_mod(SshWord *r, unsigned int r_n,
                 SshWord *d, unsigned int d_n);

/* Computation of 'r' modulo 'd', where 'd' is unsigned integer. Here 'd'
   must be normalized. */
SshWord ssh_mpk_mod_ui(SshWord *r, unsigned int r_n,
                       SshWord d);

/* Montgomery reduction of 'op'. This computation needs the 'mp' which
   is inverse of the moduli mod 2^n, and the actual moduli. */
void ssh_mpmk_reduce(SshWord *ret, unsigned int ret_n,
                     SshWord *op,  unsigned int op_n,
                     SshWord mp,
                     SshWord *m,   unsigned int m_n);

#ifdef ASM_PLATFORM_OCTEON
void ssh_mpmk_triple_inv(SshWord a[3]);

void ssh_mpmk_reduce_192(SshWord *ret, unsigned int ret_n,
                         SshWord *op,  unsigned int op_n,
                         SshWord mp, const SshWord big_mp[3],
                         const SshWord *m, unsigned int m_n);
#endif /* ASM_PLATFORM_OCTEON */


/* Computation of a^-1 (mod 2^n). Input 'a' must be odd. */
SshWord ssh_mpmk_small_inv(SshWord a);

/* Compute -op mod 2^n. */
void ssh_mpmk_2adic_neg(SshWord *ret, SshWord *op, unsigned int op_n);








#endif /* SSHMP_KERNEL */
