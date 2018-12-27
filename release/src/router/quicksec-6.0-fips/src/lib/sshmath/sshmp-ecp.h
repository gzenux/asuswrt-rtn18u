/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The basis of an implement for elliptic curve cryptosystem. This
   is basically over F_p, where p is prime.

   Curve is of form

     y^2 = x^3 + ax + b (mod p)

   Functions here implemented allow very fast multiplication (or
   exponentiation which ever suits your imagination), and thus is suitable
   for cryptography.
*/

#ifndef ECPMATH_H
#define ECPMATH_H

/* Definitions of arithmetic elements for elliptic curve cryptosystems. */

/* Elliptic curve affine point. */
typedef enum
{
  /* The specified curve point is in compressed form */
  SSH_ECP_CURVE_POINT_COMPRESSED = 2,

  /* The specified curve point is in uncompressed form */
  SSH_ECP_CURVE_POINT_UNCOMPRESSED = 4,

  /* The specified curve point is in hybrid notation */
  SSH_ECP_CURVE_POINT_HYBRID = 6
}SshECPPointAttribute;

typedef struct
{
  /* If z = 0 then point at infinity. */
  SshMPIntegerStruct x, y;
  int z;
} *SshECPPoint, SshECPPointStruct;

/* Elliptic curve (of form y^2 = x^3 + ax + b). */

typedef struct
{
  /* Field modulus. */
  SshMPIntegerStruct q;
  SshMPIntIdealStruct m;
  /* Defining constants. */
  SshMPIntegerStruct a, b;
  /* Cardinality, useful in verification and possibly when generating
     new prime order points. */
  SshMPIntegerStruct c;
} *SshECPCurve, SshECPCurveStruct;

typedef const SshECPPointStruct *SshECPPointConst;
typedef const SshECPCurveStruct *SshECPCurveConst;

/* Prototypes of public functions. */
/* Point handling functions */






/* Auxliary curve handling functions. */

/* Set curve to some specific values. Values given should be correct in
   that

      q     is the field modulus (a prime number)
      a, b  define an elliptic curve x^3 + ax + b = y^2
            (this is trivial, because it happens always, but the following
             restriction is real).
      c     is the cardinality of the curve that is curve has this
            many distinct points (x, y).
   */
Boolean ssh_ecp_set_curve(SshECPCurve E, SshMPIntegerConst q,
                          SshMPIntegerConst a,
                          SshMPIntegerConst b, SshMPIntegerConst c);

/* Clean memory used by the curve. */
void ssh_ecp_clear_curve(SshECPCurve E);

/* Compare two curves, this returns TRUE if equal, FALSE if not. */
Boolean ssh_ecp_compare_curves(SshECPCurve E0, SshECPCurve E1);

/* Copy curve E_src to E_dest. */
void ssh_ecp_copy_curve(SshECPCurve E_dest, SshECPCurveConst E_src);

/* Auxliary functions for points. */

/* Init a point with a point at infinity. */
void ssh_ecp_init_point(SshECPPoint P, SshECPCurveConst E);

/* Clear point (i.e. delete memory allocated by point). */
void ssh_ecp_clear_point(SshECPPoint P);

/* Set to identity (i.e. z = 0). */
void ssh_ecp_set_identity(SshECPPoint P);

/* Set point to selected values. x and y must satisfy the relation
   x^3 + ax + b = y^2. Also z must be 1 if point at infinity is not
   desired. */
void ssh_ecp_set_point(SshECPPoint P, SshMPIntegerConst x,
                       SshMPIntegerConst y, int z);

/* Set point from an octet string. point_len is the expected length
   of the coordinates in  bytes. */
Boolean ssh_ecp_set_point_from_octet_str(SshECPPoint P,
                                         SshECPCurveConst E,
                                         size_t point_len,
                                         unsigned char * buf,
                                         size_t buf_len,
                                         Boolean * pc);

/* Copy P to Q. */
void ssh_ecp_copy_point(SshECPPoint Q, SshECPPointConst P);

/* Negate a point  (i.e. Q = -P). */
void ssh_ecp_negate_point(SshECPPoint Q,
                          SshECPPointConst P,
                          SshECPCurveConst E);

/* Compare Q and P, returns TRUE if equal and FALSE if not. */
Boolean ssh_ecp_compare_points(SshECPPointConst P,
                               SshECPPointConst Q);

/* Add two points together using affine coordinates, this is not fast
   although in occasional use there is no faster. */
void ssh_ecp_add(SshECPPoint R, SshECPPointConst Q,
                 SshECPPointConst P,
                 SshECPCurveConst E);

/* Compute multiple k of P. Generic version in that this will handle
   every value k can have nicely. (If not contact author ;) */
void ssh_ecp_generic_mul(SshECPPoint R, SshECPPointConst P,
                         SshMPIntegerConst k,
                         SshECPCurveConst E);

/* Compute multiple k of P, where P has prime order and 0 <= k < #P.
   If the order of P is not know use the ssh_ecp_generic_mul instead.
   This works faster due few small optimizations. However, at greater
   risk of failing (is guaranteed to fail if k >= #P, however if used
   properly this should give only the utmost speed). */
void ssh_ecp_mul(SshECPPoint R, SshECPPointConst P,
                 SshMPIntegerConst k,
                 SshECPCurveConst E);

/* Compute y = sqrt(x^3 + ax + b) mod q. Where a, b and q define the curve
   and field and x is the x-coordinate of a valid point on the elliptic
   curve. */
Boolean ssh_ecp_compute_y_from_x(SshMPInteger y, SshMPIntegerConst x,
                                 SshECPCurveConst E);

/* Function to reconstruct a point P which contains only x coordinate.
   'bit' denotes the least significant bit of y coordinate. Puts
   reconstructed y to P, if succeeds and returns TRUE, otherwise
   returns FALSE. (Reconstruction takes few moments so it isn't suggested
   to use point compression if speed is neccessary.) */

Boolean ssh_ecp_restore_y(SshECPPoint P, SshECPCurveConst E,
                          Boolean bit);

/* Generate a random elliptic curve point. */

void ssh_ecp_random_point(SshECPPoint P, SshECPCurveConst E);

/* In point generation it is assumed that the elliptic curve point
   counting has been performed. */

/* Generate a random elliptic curve point of prime order. These points are
   valuable for all cryptosystems. */

Boolean ssh_ecp_random_point_of_prime_order(SshECPPoint P,
                                            SshMPIntegerConst n,
                                            SshECPCurveConst E);

/* The first point, in the sense that the components are as small as
   possible, of the given order. */
Boolean ssh_ecp_first_point_of_order(SshECPPoint P, SshMPIntegerConst n,
                                     SshECPCurveConst E);

/* Check whether a given curve is supersingular. */

Boolean ssh_ecp_is_supersingular(SshECPCurveConst E);

/* Compute the count of elliptic curve points exhaustively, i.e. in
   time exponential. There exists polynomial time algorithm due to R. Schoof
   (with enhancements by many). */

void ssh_ecp_brute_point_count(SshECPCurve E);

/* Verify quickly that given parameters are correct (within reasonable
   assumptions). Returns TRUE if all tests passed and FALSE otherwise. */





Boolean ssh_ecp_verify_param(SshECPCurveConst E,
                             SshECPPointConst P,
                             SshMPIntegerConst n);

#endif /* ECPMATH_H */
