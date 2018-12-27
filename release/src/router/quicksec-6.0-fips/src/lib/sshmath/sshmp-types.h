/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definitions for types and definitions that are often used in
   SSH arithmetic library components.
*/

#ifndef SSHMATH_TYPES_H
#define SSHMATH_TYPES_H

/* This is the current word used internally, however, one should build
   a better system later for deducing the fastest available word size. */

/* The definitions later _in this file_ assume currently that SshWord
   is the long integer. */
typedef unsigned long SshWord;
typedef long          SshSignedWord;




/* SIZEOF_LONG is defined typically in sshconf.h. */
#ifndef SIZEOF_LONG
#error SIZEOF_LONG is not defined! Required by SSH MP libraries.
#endif

/* Computation of negating unsigned SshWords. */
#define SSH_WORD_NEGATE(x) ((~((SshWord)(x))) + 1)
#define SSH_WORD_NEG       SSH_WORD_NEGATE

/* SSH_WORD_BITS cannot be defined as sizeof(SshWord) because
   `sizeof' cannot appear in a preprocessor conditional. */
#define SSH_WORD_BITS (SIZEOF_LONG * 8)
#define SSH_WORD_HALF_BITS (SSH_WORD_BITS / 2)
#define SSH_WORD_MASK (~(SshWord)0)

/* Polymorphic sign manipulation. */

/* Evaluate the sign, either to TRUE or FALSE. */
#define SSH_MP_GET_SIGN(x)      (((x)->sign) & TRUE)
/* Clear the sign, i.e. make positive. */
#define SSH_MP_NO_SIGN(x)       (((x)->sign) &= (~SSH_MP_GET_SIGN(x)))
/* Make negative. */
#define SSH_MP_SET_SIGN(x)      (((x)->sign) |= TRUE)
/* Copy sign from one integer to another. */
#define SSH_MP_COPY_SIGN(x,y)   (((x)->sign) = ((y)->sign))
/* Xor sign, negation. */
#define SSH_MP_XOR_SIGN(x)      (((x)->sign) ^= TRUE)
/* Xor signs together, useful in multiplication. */
#define SSH_MP_XOR_SIGNS(x,y,z) (((x)->sign) = ((y)->sign) ^ ((z)->sign))

#endif /* SSHMATH_TYPES_H */
