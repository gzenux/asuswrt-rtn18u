/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmp-integer.h
*/

#ifndef SSHMP_INTEGER_H
#define SSHMP_INTEGER_H

/* This defines how many static words we to use. */

#ifndef SSH_MP_INTEGER_BIT_SIZE_STATIC
#define SSH_MP_INTEGER_BIT_SIZE_STATIC 0
#endif

#if SSH_MP_INTEGER_BIT_SIZE_STATIC > 0
#define SSH_MP_INTEGER_STATIC_ARRAY_SIZE  \
 ((SSH_MP_INTEGER_BIT_SIZE_STATIC / SSH_WORD_BITS) + 4)
#else
#define SSH_MP_INTEGER_STATIC_ARRAY_SIZE 1
#endif

/* This library implement the multiple precision integer arithmetic.
   This library works as the basis for the other multiple precision
   libraries in this mathematics library, for example, for modular
   arithmetic, rational numbers and floating point numbers. */

/* The basic definitions of SSH MP Integers. */
typedef struct SshMPIntRec
{
  /* To make the code "harder" to read, we use short names
       m denotes the amount of memory allocated for a integer (in words)
       n denotes the amount of memory used by the integer (in words)
     */
  unsigned int m;
  unsigned int n;

  /* We use one additional word for dynamic, sign and nan-information. */

  /* 1 if dynamic memory has been allocated to v, 0 otherwise. */
  unsigned int dynamic_v:1;
  unsigned int sign:1;
  unsigned int isnan:1;
  unsigned int nankind:4;
#define SSH_MP_NAN_EDIVZERO   1
#define SSH_MP_NAN_EVENMOD    2
#define SSH_MP_NAN_ENOMEM     4
#define SSH_MP_NAN_ENEGPOWER  8

  /* The array of integer words in base 2. */

  SshWord w[SSH_MP_INTEGER_STATIC_ARRAY_SIZE];
  /* Dynamically allocated if necessary. */
  SshWord *v;
} *SshMPInteger, SshMPIntegerStruct;

typedef const SshMPIntegerStruct *SshMPIntegerConst;

/* Some memory management. */
SshMPInteger ssh_mprz_malloc(void);
void ssh_mprz_free(SshMPInteger op);

/* This function makes the integer 'op' to have new_size words of
   memory reserved, even if it doesn't need it at the moment. This
   cannot truncate the size of an allocated memory space for an
   integer, thus should be used only when known that a lot of memory
   is needed.

   This function is not needed to be called ever, library calls it
   itself if necessary. The resulting integer may become a
   NAN/enomem. */

Boolean ssh_mprz_realloc(SshMPInteger op, unsigned int new_size);

/* The basic integer manipulation functions. */

/* Following routine initializes a multiple precision integer. This function
   must be called before any other use of SshMPInteger structure. */
void ssh_mprz_init(SshMPInteger op);

/* After the SshMPInteger structure has been used, and is not needed
   anymore one could free it with this function. Any new use of the
   given structure must preceed again a call to ssh_mprz_init
   function. */
void ssh_mprz_clear(SshMPInteger op);

/* Clear a bit in op. */
void ssh_mprz_clr_bit(SshMPInteger ret, unsigned int n);

/* Get something out of SshMPInteger. */

/* Get the lsb-word out of the integer. */
SshWord ssh_mprz_get_ui(SshMPIntegerConst op);
/* Get the lsb-signed word (the sign is given by the sign of the integer)
   out of the integer. */
SshSignedWord ssh_mprz_get_si(SshMPIntegerConst op);

/* Returns the i'th least significant word of op. */
SshWord ssh_mprz_get_word(SshMPIntegerConst op, unsigned int i);

/* Return the bit in position 'bit' in op. */
unsigned int ssh_mprz_get_bit(SshMPIntegerConst op, unsigned int bit);

/* Scan the integer starting from given position 'bitpos' for bit
   with value 'bitval'. Returns new bit position where the bitval
   differs from what was given. */
unsigned int ssh_mprz_scan_bit(SshMPIntegerConst op,
                               unsigned int bitpos,
                               unsigned int bitval);

/* Get of some base out of op. Result is either a number, or one of
   the allocated strings <nan:divzero>, <nan:overflow>, or if out of
   memory, NULL */
char *ssh_mprz_get_str(SshMPIntegerConst op, SshWord base);

/* Get the size in given 'base'. User of this function should notice,
   that the returned value will be one off. That is, the returned
   value gives the value e so that base^e > op and base^{e-1} <=
   op. */
unsigned int ssh_mprz_get_size(SshMPIntegerConst op, SshWord base);

/* Put something into SshMPInt. */

/* Set op into ret. */
void ssh_mprz_set(SshMPInteger ret, SshMPIntegerConst op);
/* Set unsigned int (of same size as our word) u into op. */
void ssh_mprz_set_ui(SshMPInteger ret, SshWord u);
/* Set int (of same size as our word) s into op. */
void ssh_mprz_set_si(SshMPInteger ret, SshSignedWord s);
/* Set the bit in position 2^bit as one. */
void ssh_mprz_set_bit(SshMPInteger ret, unsigned int bit);
/* Put an integer in base 'base' (represented as a null-terminated string)
   into op. Returns 0 if error, 1 if successful. */
int ssh_mprz_set_str(SshMPInteger ret, const char *str, SshWord base);


/**************************************************************************
  Get and set functions between SshMPIntegers and
  SshUInt32, SshUInt64, SshInt32 SshInt64 integer types.
**************************************************************************/

/* Set the 32 bit unsigned word into op. */
void ssh_mprz_set_ui32(SshMPInteger op, SshUInt32 u);
/* Set the 64 bit unsigned word into op. */
void ssh_mprz_set_ui64(SshMPInteger op, SshUInt64 u);

/* Set the 32 bit signed word into op. */
void ssh_mprz_set_si32(SshMPInteger op, SshInt32 s);
/* Set the 64 bit signed word into op. */
void ssh_mprz_set_si64(SshMPInteger op, SshInt64 s);

/* Get the lsb 32 bits (unsigned) out of the integer.*/
SshUInt32 ssh_mprz_get_ui32(SshMPIntegerConst op);
/* Get the lsb 64 bits (unsigned) out of the integer. */
SshUInt64 ssh_mprz_get_ui64(SshMPIntegerConst op);

/* Get the lsb-signed word (the sign is given by the sign of the integer)
   out of the integer. Please note that ssh_mprz_get_si32 is *NOT* the
   same as casting ssh_mprz_get_si64 to SshInt32. */
SshInt32 ssh_mprz_get_si32(SshMPIntegerConst op);
SshInt64 ssh_mprz_get_si64(SshMPIntegerConst op);







/* Corresponding initialization functions. */
void ssh_mprz_init_set(SshMPInteger ret, SshMPIntegerConst op);
void ssh_mprz_init_set_ui(SshMPInteger ret, SshWord u);
void ssh_mprz_init_set_si(SshMPInteger ret, SshSignedWord s);
int ssh_mprz_init_set_str(SshMPInteger ret, const char *str,
                          unsigned int base);

/* Routines to linearize the absolute value of the input integer into an
   octet buffer (most significant byte first). That is, it doesn't
   include the sign. The decoding function hence returns only positive
   values. */

/* Returns nonzero on success (if 'buf' is large enough to encode 'op)
   and zero on failure. The value returned is index of first used byte
   in the buffer plus one, e.g. the filled in buffer starts at return
   value 1.  */
size_t ssh_mprz_get_buf(unsigned char *buf, size_t buf_length,
                        SshMPIntegerConst op);
void ssh_mprz_set_buf(SshMPInteger ret, const unsigned char *buf,
                      size_t buf_length);

/* Same as the above two functions but encode the integer least
   significant byte first. */
size_t ssh_mprz_get_buf_lsb_first(unsigned char *buf, size_t buf_length,
                                  SshMPIntegerConst op);
void ssh_mprz_set_buf_lsb_first(SshMPInteger ret, const unsigned char *buf,
                                size_t buf_length);

/* Handle signs. */
/* Equals to ret = -op. */
void ssh_mprz_neg(SshMPInteger ret, SshMPIntegerConst op);
/* Equals to ret = |op|, that is, ret is the absolute value of op. */
void ssh_mprz_abs(SshMPInteger ret, SshMPIntegerConst op);
/* Returns -1 if negative, 1 if positive, 0 if zero. */
int ssh_mprz_signum(SshMPIntegerConst op);

/* Basic binary (boolean) arithmetic operations. */

/* Equals to ret = op1 & op2, in C language. */
void ssh_mprz_and(SshMPInteger ret, SshMPIntegerConst op1,
                SshMPIntegerConst op2);
/* Equals to ret = op1 ^ op2, in C language. */
void ssh_mprz_xor(SshMPInteger ret, SshMPIntegerConst op1,
                SshMPIntegerConst op2);
/* Equals to ret = op1 | op2, in C language. */
void ssh_mprz_or(SshMPInteger ret, SshMPIntegerConst op1,
               SshMPIntegerConst op2);
/* Equals to ret = ~op, in C language. */
void ssh_mprz_com(SshMPInteger ret, SshMPIntegerConst op);

/* Comparison routines. */

/* Returns 0 if op1 = op2, 1 if op1 > op2, -1 if op1 < op2. */
int ssh_mprz_cmp(SshMPIntegerConst op1, SshMPIntegerConst op2);
/* Returns 0 if op = u, 1 if op > u, -1 if op < u. */
int ssh_mprz_cmp_ui(SshMPIntegerConst op, SshWord u);
/* Returns 0 if op = s, 1 if op > s, -1 if op < s. */
int ssh_mprz_cmp_si(SshMPIntegerConst op, SshSignedWord s);

/* The very basic arithmetic operations of ordinary integer. */

/* Equals to ret = op1 + op2. */
void ssh_mprz_add(SshMPInteger ret, SshMPIntegerConst op1,
                  SshMPIntegerConst op2);
/* Equals to ret = op1 - op2. */
void ssh_mprz_sub(SshMPInteger ret, SshMPIntegerConst op1,
                SshMPIntegerConst op2);
/* Equals to ret = op + u. */
void ssh_mprz_add_ui(SshMPInteger ret, SshMPIntegerConst op,
                     SshWord u);
/* Equals to ret = op - u. */
void ssh_mprz_sub_ui(SshMPInteger ret, SshMPIntegerConst op,
                     SshWord u);

/* Multiplication, squaring and division routines. */

/* Equals to ret = op1 * op2. */
void ssh_mprz_mul(SshMPInteger ret, SshMPIntegerConst op1,
                SshMPIntegerConst op2);
/* Equals to ret = op * u. */
void ssh_mprz_mul_ui(SshMPInteger ret, SshMPIntegerConst op,
                     SshWord u);
/* Equals to ret = op^2. Note: This function is faster than ordinary
   multiplication, thus in places where computation of squares is high
   one should use this function. All routines in this library are
   optimized in this sense. */
void ssh_mprz_square(SshMPInteger ret, SshMPIntegerConst op);

/* Warning! This version does not have multiple rounding modes, and
   you should be aware the way that rounding happens within these
   functions. */

/* Equals to op1 = q * op2 + r. Rounding towards zero. */
void ssh_mprz_divrem(SshMPInteger ret_q, SshMPInteger ret_r,
                     SshMPIntegerConst op1,
                     SshMPIntegerConst op2);
/* Equals to (op1 - (op1 % op2)) / op2 = q. Rounding towards zero. */
void ssh_mprz_div(SshMPInteger ret_q, SshMPIntegerConst op1,
                  SshMPIntegerConst op2);
/* Equals to r == op1 (mod op2). Sign of r is always positive, and
   it is assumed that op2 has positive sign. */
void ssh_mprz_mod(SshMPInteger ret_r, SshMPIntegerConst op1,
                  SshMPIntegerConst op2);
/* Equals to op = q * u + r, where r is returned. Rounding towards zero. */
SshWord ssh_mprz_divrem_ui(SshMPInteger ret_q,
                           SshMPIntegerConst op, SshWord u);
void ssh_mprz_div_ui(SshMPInteger ret_q, SshMPIntegerConst op,
                     SshWord u);
/* Equals to r == op (mod u), where r is returned. Use this function
   rather the next one. */
SshWord ssh_mprz_mod_ui(SshMPIntegerConst op, SshWord u);

/* The basic routines which compute with 2^n's, that is basically
   do shifting. */

/* Mod_2exp returns in r only positive values. */
void ssh_mprz_mod_2exp(SshMPInteger r, SshMPIntegerConst op,
                       unsigned int bits);
void ssh_mprz_div_2exp(SshMPInteger q, SshMPIntegerConst op,
                       unsigned int bits);
void ssh_mprz_mul_2exp(SshMPInteger ret, SshMPIntegerConst op,
                       unsigned int bits);

/* Random numbers (for testing etc. not for cryptography) */

/* Generate random number op < 2^bits. */
void ssh_mprz_rand(SshMPInteger op, unsigned int bits);

/* Some elementary integer operations. */

/* Computation of ret = g^e, which gives usually rather large
   return values. */
void ssh_mprz_pow(SshMPInteger ret, SshMPIntegerConst g,
                SshMPIntegerConst e);
void ssh_mprz_pow_ui_exp(SshMPInteger ret, SshMPIntegerConst g, SshWord e);

/* d = gcd(a, b), that is, this computes the greatest common divisor. */
void ssh_mprz_gcd(SshMPInteger d, SshMPIntegerConst a,
                SshMPIntegerConst b);

/* Computes d = u*a + v*b, where a, b are given as input. */
void ssh_mprz_gcdext(SshMPInteger d, SshMPInteger u, SshMPInteger v,
                   SshMPIntegerConst a, SshMPIntegerConst b);

/* Solves sqrt^2 = op, where op is given as input. Works with integers, and
   the output thus is only an approximation. */
void ssh_mprz_sqrt(SshMPInteger ret, SshMPIntegerConst op);

/* Make given Large Integer 'op' a NaN of subtype 'kind'. If op is
   NULL (considered as a special kind of NaN, do nothing. */
void ssh_mprz_makenan(SshMPInteger op, unsigned int kind);

/* Check if the integer is a NaN, e.g. it is either NULL, or it has
   is_nan bit set. */
Boolean ssh_mprz_isnan(SshMPIntegerConst op);

/* Propagate NaN'ess of 'op' into result 'ret'. If 'op' is a NaN, this
   makes 'ret' a same kind of NaN as well, and returns true. It also
   makes 'ret' a NaN, if mathematics library has not been
   initialized. If 'op' is not a NaN, 'ret' remains intact, and FALSE
   is returned.

   ssh_mprz_nanresult2 and ssh_mprz_nanresult3 are similar, but they
   check if any of given 'op1', 'op2' or 'op3' is a NaN and propagate
   this to 'ret'. The kind of NaN 'ret' becomes is the 'op' with least
   argument position. */

Boolean ssh_mprz_nanresult1(SshMPInteger ret, SshMPIntegerConst op);
Boolean ssh_mprz_nanresult2(SshMPInteger ret, SshMPIntegerConst op1,
                            SshMPIntegerConst op2);
Boolean ssh_mprz_nanresult3(SshMPInteger ret, SshMPIntegerConst op1,
                            SshMPIntegerConst op2, SshMPIntegerConst op3);

/* Size macros */

#define ssh_mp_byte_size(op)   ((ssh_mprz_get_size((op), 2) + 7) / 8)
#define ssh_mp_word32_size(op) ((ssh_mprz_get_size((op), 2) + 31) / 32)
#define ssh_mp_bit_size(op)      ssh_mprz_get_size((op), 2)

#define ssh_mprz_byte_size(op)   ((ssh_mprz_get_size((op), 2) + 7) / 8)
#define ssh_mprz_word32_size(op) ((ssh_mprz_get_size((op), 2) + 31) / 32)
#define ssh_mprz_bit_size(op)      ssh_mprz_get_size((op), 2)


#endif /* SSHMP_INTEGER_H */
