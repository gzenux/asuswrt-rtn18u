/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of basic arithmetic on elliptic curves over Fp. These
   routines are suitable for use in cryptosystems.

   TODO:

     convert to modular representation as much as possible!
*/

#include "sshincludes.h"
#include "sshmp.h"

#ifdef SSHDIST_MATH
#ifdef SSHDIST_MATH_ECP
/* Elliptic curve arithmetics. */

/* Auxliary functions for elliptic curve definition. */

/* Set curve. */
Boolean ssh_ecp_set_curve(SshECPCurve E,
                          SshMPIntegerConst q,
                          SshMPIntegerConst a,
                          SshMPIntegerConst b,
                          SshMPIntegerConst c)
{
  memset(E, 0, sizeof(*E));

  ssh_mprz_init_set(&E->q, q);
  ssh_mprz_init_set(&E->a, a);
  ssh_mprz_init_set(&E->b, b);
  ssh_mprz_init_set(&E->c, c);

  if (ssh_mprz_isnan(&E->q) ||
       ssh_mprz_isnan(&E->a) ||
       ssh_mprz_isnan(&E->b) ||
       ssh_mprz_isnan(&E->c))
    return FALSE;

  if (!ssh_mprzm_init_ideal(&E->m, &E->q))
    return FALSE;

  return TRUE;
}

/* Clean up the elliptic curve from memory. */
void ssh_ecp_clear_curve(SshECPCurve E)
{
  ssh_mprzm_clear_ideal(&E->m);

  ssh_mprz_clear(&E->q);
  ssh_mprz_clear(&E->a);
  ssh_mprz_clear(&E->b);
  ssh_mprz_clear(&E->c);

  memset(E, 0, sizeof(*E));
}

/* Copy curve. */
void ssh_ecp_copy_curve(SshECPCurve E_dest, SshECPCurveConst E_src)
{
  ssh_mprz_set(&E_dest->q, &E_src->q);
  ssh_mprz_set(&E_dest->a, &E_src->a);
  ssh_mprz_set(&E_dest->b, &E_src->b);
  ssh_mprz_set(&E_dest->c, &E_src->c);




  if (!ssh_mprzm_init_ideal(&E_dest->m, &E_dest->q))
    return;
}

Boolean ssh_ecp_compare_curves(SshECPCurve E0, SshECPCurve E1)
{
  if (ssh_mprz_cmp(&E0->a, &E1->a) != 0 ||
      ssh_mprz_cmp(&E0->b, &E1->b) != 0 ||
      ssh_mprz_cmp(&E0->c, &E1->c) != 0 ||
      ssh_mprz_cmp(&E0->q, &E1->q) != 0)
    return FALSE;
  return TRUE;
}

/* Affine case. */

/* Auxliary functions for points */

/* Initialize affine point to point at infinity. The elliptic curve
   is included for compatibility towards future enhancements. */
void ssh_ecp_init_point(SshECPPoint P, SshECPCurveConst E)
{
  ssh_mprz_init_set_ui(&P->x, 0);
  ssh_mprz_init_set_ui(&P->y, 0);
  P->z = 0;
}

/* Delete affine points context. */
void ssh_ecp_clear_point(SshECPPoint P)
{
  ssh_mprz_clear(&P->x);
  ssh_mprz_clear(&P->y);
  P->z = 0;
}

/* Set affine point to point at infinity (the identity element). */
void ssh_ecp_set_identity(SshECPPoint P)
{
  ssh_mprz_set_ui(&P->x, 1);
  ssh_mprz_set_ui(&P->y, 1);
  P->z = 0;
}

/* Set affine point to MP integer values. */
void ssh_ecp_set_point(SshECPPoint P, SshMPIntegerConst x,
                       SshMPIntegerConst y,
                       int z)
{
  ssh_mprz_set(&P->x, x);
  ssh_mprz_set(&P->y, y);

  P->z = (z != 0) ? 1 : 0;
}

Boolean ssh_ecp_set_point_from_octet_str(SshECPPoint P,
                                         SshECPCurveConst E,
                                         size_t point_len,
                                         unsigned char * buf,
                                         size_t buf_len,
                                         Boolean * pc)
{
  unsigned int form;
  Boolean y_bit, rv;
  size_t enc_len;
  SshMPIntegerStruct t1, t2;

  if (buf_len == 0)
    return FALSE;

  form = buf[0];
  y_bit = form & 0x1;
  /* Clear the least significant bit */
  form &= ~1U;
  if ((form != 0)
         && (form != SSH_ECP_CURVE_POINT_COMPRESSED)
         && (form != SSH_ECP_CURVE_POINT_UNCOMPRESSED)
         && (form != SSH_ECP_CURVE_POINT_HYBRID))
      /* Point is neither at inifinity, compressed, uncompressed
      or hybrid */
    return FALSE;

  if (form == 0)
    {
      if (buf_len != 1 || y_bit)
          /* Point at infinity is represented by a single 00 */
        return FALSE;
      ssh_mprz_init_set_ui(&P->x, 0);
      ssh_mprz_init_set_ui(&P->y, 0);
      P->z = 0;
      return 0;
    }

  if ((form == SSH_ECP_CURVE_POINT_UNCOMPRESSED) && y_bit)
    return FALSE;

  /* This value would be in bytes. */
  enc_len  = (form == SSH_ECP_CURVE_POINT_COMPRESSED)? point_len + 1:
                           2 * point_len + 1;

  if (buf_len != enc_len * 8)
    return FALSE;

  ssh_mprz_set_buf(&P->x, buf + 1, point_len);
  if (form == SSH_ECP_CURVE_POINT_COMPRESSED)
    {
      if (!ssh_ecp_restore_y(P, E, y_bit))
        return FALSE;
      *pc = TRUE;
    }
  else
    {
      ssh_mprz_set_buf(&P->y, buf + 1 + point_len, point_len);
      *pc = FALSE;
      /* TODO if form == HYBRID
         convert (x,y_bit) to (x,y) make sure that both y's match.
         Atleast check that if y_bit is set, then number is odd */
    }
  /* Make sure that the point lies on the curve. This check is required
   by the X.92 draft */
  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);
  ssh_mprz_mul(&t1, &P->y, &P->y);
  ssh_mprz_mul(&t2, &P->x, &P->x);
  ssh_mprz_mul(&t2, &P->x, &t2);
  ssh_mprz_mod(&t2, &t2, &E->q);
  ssh_mprz_sub(&t1, &t1, &t2);
  ssh_mprz_mul(&t2, &P->x, &E->a);
  ssh_mprz_mod(&t2, &t2, &E->q);
  ssh_mprz_sub(&t1, &t1, &t2);
  ssh_mprz_sub(&t1, &t1, &E->b);
  ssh_mprz_mod(&t1, &t1, &E->q);

  rv = ssh_mprz_cmp_ui(&t1, 0);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
  return !rv;
}


/* Copy affine point to another affine point */
void ssh_ecp_copy_point(SshECPPoint Q, SshECPPointConst P)
{
  ssh_mprz_set(&Q->x, &P->x);
  ssh_mprz_set(&Q->y, &P->y);
  Q->z = P->z;
}

/* Negate affine point (probably for subtraction). */
void ssh_ecp_negate_point(SshECPPoint Q, SshECPPointConst P,
                          SshECPCurveConst E)
{
  ssh_mprz_set(&Q->x, &P->x);
  ssh_mprz_sub(&Q->y, &E->q, &P->y);
  Q->z = P->z;
}

/* Compare Q to P for equality. */
Boolean ssh_ecp_compare_points(SshECPPointConst P,
                               SshECPPointConst Q)
{
  if (P->z != Q->z)
    return FALSE;
  if (P->z == 0 && Q->z == 0)
    return TRUE;

  if (ssh_mprz_cmp(&P->x, &Q->x) != 0)
    return FALSE;
  if (ssh_mprz_cmp(&P->y, &Q->y) != 0)
    return FALSE;

  return TRUE;
}

/* Add affine points. Full addition (for general use). */
void ssh_ecp_add(SshECPPoint R, SshECPPointConst Q,
                 SshECPPointConst P,
                 SshECPCurveConst E)
{
  SshMPIntegerStruct lambda, t1, t2, t3, rx;

  /* Identity checks. */
  if (P->z == 0)
    {
      ssh_ecp_copy_point(R, Q);
      return;
    }
  if (Q->z == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }

  if (ssh_mprz_cmp(&P->x, &Q->x) == 0)
    {
      /* If P = -Q then set R = "point at infinity". */
      if (ssh_mprz_cmp(&P->y, &Q->y) != 0 || ssh_mprz_cmp_ui(&P->y, 0) == 0)
        {
          /* Must be thus that P = -Q. */
          ssh_ecp_set_identity(R);
          return;
        }

      /* Doubling a point. */

      /* Initialize temporary variables */
      ssh_mprz_init(&lambda);
      ssh_mprz_init(&t1);
      ssh_mprz_init(&t2);
      ssh_mprz_init(&t3);
      ssh_mprz_init(&rx);

      /* Calculate the lambda = (3x1^2 + a)/2y1 */
      ssh_mprz_mul(&t1, &P->x, &P->x);
      ssh_mprz_mul_ui(&t1, &t1, 3);
      ssh_mprz_add(&t1, &t1, &E->a);
      ssh_mprz_mod(&t1, &t1, &E->q);
      ssh_mprz_mul_2exp(&t2, &P->y, 1);
      ssh_mprz_mod(&t2, &t2, &E->q);
    }
  else
    {
      /* Initialize temporary variables */
      ssh_mprz_init(&lambda);
      ssh_mprz_init(&t1);
      ssh_mprz_init(&t2);
      ssh_mprz_init(&t3);
      ssh_mprz_init(&rx);

      /* Calculate the lambda  = (y2 - y1)/(x2 - x1) */
      ssh_mprz_sub(&t1, &Q->y, &P->y);
      ssh_mprz_sub(&t2, &Q->x, &P->x);
      ssh_mprz_mod(&t2, &t2, &E->q);
    }

  /* We don't want to throw negative values to this function. */
  ssh_mprz_invert(&t3, &t2, &E->q);
  ssh_mprz_mul(&lambda, &t1, &t3);
  ssh_mprz_mod(&lambda, &lambda, &E->q);

  /* Calculate result x3 = lambda^2 - x1 - x2. */
  ssh_mprz_square(&t1, &lambda);
  ssh_mprz_mod(&t1, &t1, &E->q);
  ssh_mprz_sub(&t1, &t1, &P->x);
  ssh_mprz_sub(&t1, &t1, &Q->x);
  ssh_mprz_mod(&rx, &t1, &E->q);

  /* Calculate result y3 = lambda(x1 - x3) - y1. */
  ssh_mprz_sub(&t1, &P->x, &rx);
  ssh_mprz_mul(&t1, &lambda, &t1);
  ssh_mprz_sub(&t1, &t1, &P->y);

  /* Set results to R. */
  ssh_mprz_mod(&R->y, &t1, &E->q);
  ssh_mprz_set(&R->x, &rx);
  R->z = 1;

  /* Clear temporary variables */
  ssh_mprz_clear(&t3);
  ssh_mprz_clear(&t2);
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&lambda);
  ssh_mprz_clear(&rx);
}

/* Projective coordinate cases. */

#if 0

/* Elliptic curve projective point. */

typedef struct
{
  /* If z = 0 then point at infinity. */
  SshMPIntegerStruct x, y, z;
} *SshECPProjectivePoint, SshECPProjectivePointStruct;

/* Projective point initialization. */
void ssh_ecp_init_projective_point(SshECPProjectivePoint P,
                                   SshECPCurveConst E)
{
  ssh_mprz_init_set_ui(&P->x, 1);
  ssh_mprz_init_set_ui(&P->y, 1);
  ssh_mprz_init_set_ui(&P->z, 0);
}

/* Set projective point to the identity (z = 0). */
void ssh_ecp_set_projective_identity(SshECPProjectivePoint P)
{
  ssh_mprz_init_set_ui(&P->x, 1);
  ssh_mprz_init_set_ui(&P->y, 1);
  ssh_mprz_init_set_ui(&P->z, 0);
}

/* Free projective point. */
void ssh_ecp_clear_projective_point(SshECPProjectivePoint P)
{
  ssh_mprz_clear(&P->x);
  ssh_mprz_clear(&P->y);
  ssh_mprz_clear(&P->z);
}

/* Projective point copy P to Q. */
void ssh_ecp_copy_projective_point(SshECPProjectivePoint Q,
                                   const SshECPProjectivePoint P)
{
  ssh_mprz_set(&Q->x, &P->x);
  ssh_mprz_set(&Q->y, &P->y);
  ssh_mprz_set(&Q->z, &P->z);
}

/* Negate projective point -P = Q. */
void ssh_ecp_negate_projective_point(SshECPProjectivePoint Q,
                                     const SshECPProjectivePoint P,
                                     SshECPCurveConst E)
{
  ssh_mprz_set(&Q->x, &P->x);
  ssh_mprz_sub(&Q->y, &E->q, &P->y);
  ssh_mprz_set(&Q->z, &P->z);
}

/* Conversion between affine (normal) and projective coordinates. */

/* Convert from affine to projective coordinate system. */
void ssh_ecp_affine_to_projective(SshECPProjectivePoint R,
                                  SshECPPointConst P)
{
  /* Checking for identity. */
  if (!P->z)
    {
      /* This is the actual point at the infinity. */
      ssh_ecp_set_projective_identity(R);
    }
  else
    {
      ssh_mprz_set(&R->x, &P->x);
      ssh_mprz_set(&R->y, &P->y);
      ssh_mprz_set_ui(&R->z, 1);
    }
}

/* Convert from projective to affine coordinate system. */
void ssh_ecp_projective_to_affine(SshECPPoint R,
                                  const SshECPProjectivePoint P,
                                  SshECPCurveConst E)
{
  SshMPIntegerStruct t1, t2;

  /* Initialize temporary variables. */
  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  /* Check for point at infinity */
  if (ssh_mprz_cmp_ui(&P->z, 0) == 0)
    {
      ssh_ecp_set_identity(R);
    }
  else
    {
      /* Compute the inverse of z */
      ssh_mprz_invert(&t1, &P->z, &E->q);
      ssh_mprz_square(&t2, &t1);

      /* Compute x*(1/z)^2 mod q */
      ssh_mprz_mul(&R->x, &P->x, &t2);
      ssh_mprz_mod(&R->x, &R->x, &E->q);

      ssh_mprz_mul(&t2, &t2, &t1);

      /* Compute y*(1/z)^3 mod q */
      ssh_mprz_mul(&R->y, &P->y, &t2);
      ssh_mprz_mod(&R->y, &R->y, &E->q);

      R->z = 1;
    }
  /* Clear temporary variables. */
  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);
}

/* Definition of temporary structure. */

typedef struct
{
  /* General temporary registers. */
  SshMPIntegerStruct t1, t2, t3, t4, t5, t6, t7;
} SshECPProjectiveTemp;

void ssh_ecp_init_projective_temp(SshECPProjectiveTemp *t)
{
  ssh_mprz_init(&t->t1);
  ssh_mprz_init(&t->t2);
  ssh_mprz_init(&t->t3);
  ssh_mprz_init(&t->t4);
  ssh_mprz_init(&t->t5);
  ssh_mprz_init(&t->t6);
  ssh_mprz_init(&t->t7);
}

void ssh_ecp_clear_projective_temp(SshECPProjectiveTemp *t)
{
  ssh_mprz_clear(&t->t1);
  ssh_mprz_clear(&t->t2);
  ssh_mprz_clear(&t->t3);
  ssh_mprz_clear(&t->t4);
  ssh_mprz_clear(&t->t5);
  ssh_mprz_clear(&t->t6);
  ssh_mprz_clear(&t->t7);
}

/* Projective doubling of a point.
   This is after the P1363 draft. November 1996. These formulas can be
   acquired from the original paper by Chudnovsky and Chudnovsky (reference
   in P1363).

   One optimization problem is to know how many consecutive multiplications
   can one let be performed before reducing with the modulus. That is, to
   gain optimal performance. My guess is that with GMP routines reduction
   should be performed after the values is about three (3) times the length
   of the modulus for optimal performance.

   */

void ssh_ecp_projective_double(SshECPProjectivePoint R,
                               const SshECPProjectivePoint P,
                               SshECPCurveConst E,
                               SshECPProjectiveTemp *t)
{
  ssh_mprz_set(&t->t1, &P->x);
  ssh_mprz_set(&t->t2, &P->y);
  ssh_mprz_set(&t->t3, &P->z);

  /* Case a = -3 mod q could be included here.

     That is we could write the 3x^2 + az^4 as

     3x^2 - 3z_4 = 3(x - z^2)(x + z^2)

     if a = - 3 mod q. Which should be possible to set for half of elliptic
     curves. This is not currently forced though and thus not currently
     done, but maybe later.
   */

  ssh_mprz_square(&t->t5, &t->t3);
  ssh_mprz_square(&t->t5, &t->t5);
  ssh_mprz_mod(&t->t5, &t->t5, &E->q);

  ssh_mprz_mul(&t->t5, &t->t5, &E->a);

  ssh_mprz_square(&t->t4, &t->t1);
  ssh_mprz_mul_ui(&t->t4, &t->t4, 3);
  ssh_mprz_add(&t->t4, &t->t4, &t->t5);

  ssh_mprz_mul(&t->t3, &t->t2, &t->t3);
  ssh_mprz_mul_2exp(&t->t3, &t->t3, 1);
  ssh_mprz_mod(&t->t3, &t->t3, &E->q);

  ssh_mprz_square(&t->t2, &t->t2);
  ssh_mprz_mul(&t->t5, &t->t1, &t->t2);
  ssh_mprz_mul_2exp(&t->t5, &t->t5, 2);
  ssh_mprz_mod(&t->t5, &t->t5, &E->q);

  ssh_mprz_square(&t->t1, &t->t4);

  ssh_mprz_sub(&t->t1, &t->t1, &t->t5);
  ssh_mprz_sub(&t->t1, &t->t1, &t->t5);
  ssh_mprz_mod(&t->t1, &t->t1, &E->q);

  ssh_mprz_square(&t->t2, &t->t2);
  ssh_mprz_mul_2exp(&t->t2, &t->t2, 3);

  ssh_mprz_sub(&t->t5, &t->t5, &t->t1);
  ssh_mprz_mul(&t->t5, &t->t4, &t->t5);
  ssh_mprz_sub(&t->t2, &t->t5, &t->t2);
  ssh_mprz_mod(&t->t2, &t->t2, &E->q);

  ssh_mprz_set(&R->x, &t->t1);
  ssh_mprz_set(&R->y, &t->t2);
  ssh_mprz_set(&R->z, &t->t3);
}

/* Projective addition of distinct points. Q = (x_0, y_0, z_0) and
   P = (x_1, y_1, 1). This is the preferred addition, because no nonsense
   compares, does just the job as fast as possible (I think). */

void ssh_ecp_projective_add(SshECPProjectivePoint R,
                            const SshECPProjectivePoint Q,
                            const SshECPProjectivePoint P,
                            SshECPCurveConst E,
                            SshECPProjectiveTemp *t)
{

  ssh_mprz_set(&t->t1, &Q->x);
  ssh_mprz_set(&t->t2, &Q->y);
  ssh_mprz_set(&t->t3, &Q->z);
  ssh_mprz_set(&t->t4, &P->x);
  ssh_mprz_set(&t->t5, &P->y);

  ssh_mprz_square(&t->t6, &t->t3);
  ssh_mprz_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprz_mul(&t->t6, &t->t3, &t->t6);
  ssh_mprz_mod(&t->t6, &t->t6, &E->q);

  ssh_mprz_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprz_add(&t->t1, &t->t1, &t->t4);
  ssh_mprz_add(&t->t2, &t->t2, &t->t5);
  ssh_mprz_mul_2exp(&t->t4, &t->t4, 1);
  ssh_mprz_sub(&t->t4, &t->t1, &t->t4);
  ssh_mprz_mul_2exp(&t->t5, &t->t5, 1);
  ssh_mprz_sub(&t->t5, &t->t2, &t->t5);

  ssh_mprz_mul(&t->t3, &t->t3, &t->t4);
  ssh_mprz_mod(&t->t3, &t->t3, &E->q);

  ssh_mprz_square(&t->t6, &t->t4);
  ssh_mprz_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprz_mul(&t->t6, &t->t1, &t->t6);
  ssh_mprz_square(&t->t1, &t->t5);
  ssh_mprz_sub(&t->t1, &t->t1, &t->t6);
  ssh_mprz_mod(&t->t1, &t->t1, &E->q);

  ssh_mprz_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprz_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprz_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprz_mul(&t->t4, &t->t2, &t->t4);
  ssh_mprz_sub(&t->t2, &t->t5, &t->t4);

  /* Compute t*2^-1 mod q (note that here 2^-1 is the multiplicative
     inverse and division by 2 is not!)

     We get q = (q-1)/2 * 2 + 1 <=>
            2q - (q-1)/2*2 = q + 1 <=>
            (q+1)/2 * 2 = q + 1 <=>
            2^-1 = (q+1)/2.

     (Same result could be gotten by noticing that
       2^-1 * 2 = 1 (mod q)
       =>
       2^-1 * 2 = q + 1 <=>
       2^-1 = (q + 1)/2.
       There is no other possible value for 2^-1 < q that
       2^-1 * 2 = 1 (mod q).)

     This gives us the formula for computing 2^-1 * n (mod q).

     We can derive the method thus

     case t even
       ((q + 1) * t) / 2 (mod q) = qt/2 + t/2 (mod q) = t/2 (mod q).
     case t odd
       ((q + 1) * t) / 2 (mod q) = (t' + 1)(q + 1)/2 (mod q) =
        (t'q + t' + q + 1)/2 (mod q) = (t' + q + 1)/2 (mod q) =
        (t + q) / 2 (mod q).

   */
  if (ssh_mprz_get_ui(&t->t2) & 0x1)
    ssh_mprz_add(&t->t2, &t->t2, &E->q);

  ssh_mprz_div_2exp(&t->t2, &t->t2, 1);
  ssh_mprz_mod(&t->t2, &t->t2, &E->q);

  ssh_mprz_set(&R->x, &t->t1);
  ssh_mprz_set(&R->y, &t->t2);
  ssh_mprz_set(&R->z, &t->t3);
}

/* Projective addition of distinct points. Q = (x_0, y_0, z_0) and
   P = (x_1, y_1, z_1). */

void ssh_ecp_projective_add2(SshECPProjectivePoint R,
                             const SshECPProjectivePoint Q,
                             const SshECPProjectivePoint P,
                             SshECPCurveConst E,
                             SshECPProjectiveTemp *t)
{

  ssh_mprz_set(&t->t1, &Q->x);
  ssh_mprz_set(&t->t2, &Q->y);
  ssh_mprz_set(&t->t3, &Q->z);
  ssh_mprz_set(&t->t4, &P->x);
  ssh_mprz_set(&t->t5, &P->y);

  if (ssh_mprz_cmp_ui(&P->z, 1) != 0)
    {
      ssh_mprz_set(&t->t7, &P->z);
      ssh_mprz_square(&t->t6, &t->t7);
      ssh_mprz_mul(&t->t1, &t->t1, &t->t6);
      ssh_mprz_mul(&t->t6, &t->t7, &t->t6);
      ssh_mprz_mul(&t->t2, &t->t2, &t->t6);
    }

  ssh_mprz_square(&t->t6, &t->t3);
  ssh_mprz_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprz_mul(&t->t6, &t->t3, &t->t6);
  ssh_mprz_mod(&t->t6, &t->t6, &E->q);

  ssh_mprz_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprz_add(&t->t1, &t->t1, &t->t4);
  ssh_mprz_add(&t->t2, &t->t2, &t->t5);
  ssh_mprz_mul_2exp(&t->t4, &t->t4, 1);
  ssh_mprz_sub(&t->t4, &t->t1, &t->t4);
  ssh_mprz_mul_2exp(&t->t5, &t->t5, 1);
  ssh_mprz_sub(&t->t5, &t->t2, &t->t5);

  if (ssh_mprz_cmp_ui(&P->z, 1) != 0)
    ssh_mprz_mul(&t->t3, &t->t3, &t->t7);

  ssh_mprz_mul(&t->t3, &t->t3, &t->t4);
  ssh_mprz_mod(&t->t3, &t->t3, &E->q);

  ssh_mprz_square(&t->t6, &t->t4);
  ssh_mprz_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprz_mul(&t->t6, &t->t1, &t->t6);
  ssh_mprz_square(&t->t1, &t->t5);
  ssh_mprz_sub(&t->t1, &t->t1, &t->t6);
  ssh_mprz_mod(&t->t1, &t->t1, &E->q);

  ssh_mprz_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprz_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprz_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprz_mul(&t->t4, &t->t2, &t->t4);
  ssh_mprz_sub(&t->t2, &t->t5, &t->t4);

  if (ssh_mprz_get_ui(&t->t2) & 0x1)
    ssh_mprz_add(&t->t2, &t->t2, &E->q);

  ssh_mprz_div_2exp(&t->t2, &t->t2, 1);
  ssh_mprz_mod(&t->t2, &t->t2, &E->q);

  ssh_mprz_set(&R->x, &t->t1);
  ssh_mprz_set(&R->y, &t->t2);
  ssh_mprz_set(&R->z, &t->t3);
}

/* Generic double. */

void ssh_ecp_projective_generic_double(SshECPProjectivePoint R,
                                       const SshECPProjectivePoint P,
                                       SshECPCurveConst E,
                                       SshECPProjectiveTemp *t)
{
  if (ssh_mprz_cmp_ui(&P->z, 0) == 0)
    {
      ssh_ecp_set_projective_identity(R);
      return;
    }

  ssh_ecp_projective_double(R, P, E, t);
}

/* For cases Q = (x_0, y_0, z_0) and P = (x_1, y_1, 1). */

void ssh_ecp_projective_generic_add(SshECPProjectivePoint R,
                                    const SshECPProjectivePoint Q,
                                    const SshECPProjectivePoint P,
                                    SshECPCurveConst E,
                                    SshECPProjectiveTemp *t)
{
  if (ssh_mprz_cmp_ui(&Q->z, 0) == 0)
    {
      ssh_ecp_copy_projective_point(R, P);
      return;
    }

  ssh_mprz_square(&t->t1, &Q->z);
  ssh_mprz_mul(&t->t2, &P->x, &t->t1);
  ssh_mprz_mod(&t->t2, &t->t2, &E->q);

  if (ssh_mprz_cmp(&t->t2, &Q->x) != 0)
    {
      ssh_ecp_projective_add(R, Q, P, E, t);
      return;
    }

  ssh_mprz_mul(&t->t2, &P->y, &t->t1);
  ssh_mprz_mul(&t->t2, &t->t2, &Q->z);
  ssh_mprz_mod(&t->t2, &t->t2, &E->q);

  if (ssh_mprz_cmp(&t->t2, &Q->y) == 0)
    {
      ssh_ecp_projective_double(R, P, E, t);
      return;
    }
  ssh_ecp_set_projective_identity(R);
}

#else

/* Faster code with Montgomery representation. */


/* Elliptic curve projective point. */

typedef struct
{
  /* If z = 0 then point at infinity. */
  SshMPIntModStruct x, y, z;
} *SshECPProjectivePoint, SshECPProjectivePointStruct;

/* Projective point initialization. */
void ssh_ecp_init_projective_point(SshECPProjectivePoint P,
                                   SshECPCurveConst E)
{
  ssh_mprzm_init(&P->x, &E->m);
  ssh_mprzm_init(&P->y, &E->m);
  ssh_mprzm_init(&P->z, &E->m);

  ssh_mprzm_set_ui(&P->z, 0);
}

/* Set projective point to the identity (z = 0). */
void ssh_ecp_set_projective_identity(SshECPProjectivePoint P)
{
  ssh_mprzm_set_ui(&P->z, 0);
}

/* Free projective point. */
void ssh_ecp_clear_projective_point(SshECPProjectivePoint P)
{
  ssh_mprzm_clear(&P->x);
  ssh_mprzm_clear(&P->y);
  ssh_mprzm_clear(&P->z);
}

/* Projective point copy P to Q. */
void ssh_ecp_copy_projective_point(SshECPProjectivePoint Q,
                                   const SshECPProjectivePoint P)
{
  ssh_mprzm_set(&Q->x, &P->x);
  ssh_mprzm_set(&Q->y, &P->y);
  ssh_mprzm_set(&Q->z, &P->z);
}

/* Negate projective point -P = Q. */
void ssh_ecp_negate_projective_point(SshECPProjectivePoint Q,
                                     const SshECPProjectivePoint P,
                                     SshECPCurveConst E)
{
  ssh_mprzm_set(&Q->x, &P->x);
  ssh_mprzm_set_ui(&Q->y, 0);
  ssh_mprzm_sub(&Q->y, &Q->y, &P->y);
  ssh_mprzm_set(&Q->z, &P->z);
}

/* Conversion between affine (normal) and projective coordinates. */

/* Convert from affine to projective coordinate system. */
void ssh_ecp_affine_to_projective(SshECPProjectivePoint R,
                                  SshECPPointConst P)
{
  /* Checking for identity. */
  if (!P->z)
    {
      /* This is the actual point at the infinity. */
      ssh_ecp_set_projective_identity(R);
    }
  else
    {
      ssh_mprzm_set_mprz(&R->x, &P->x);
      ssh_mprzm_set_mprz(&R->y, &P->y);
      ssh_mprzm_set_ui(&R->z, 1);
    }
}

/* Convert from projective to affine coordinate system. */
void ssh_ecp_projective_to_affine(SshECPPoint R,
                                  const SshECPProjectivePoint P,
                                  SshECPCurveConst E)
{
  SshMPIntModStruct t1, t2, t3;

  /* Initialize temporary variables. */
  ssh_mprzm_init(&t1, &E->m);
  ssh_mprzm_init(&t2, &E->m);
  ssh_mprzm_init(&t3, &E->m);

  /* Check for point at infinity */
  if (ssh_mprzm_cmp_ui(&P->z, 0) == 0)
    {
      ssh_ecp_set_identity(R);
    }
  else
    {
      /* Compute the inverse of z */
      ssh_mprzm_invert(&t1, &P->z);
      ssh_mprzm_square(&t2, &t1);

      /* Compute x*(1/z)^2 mod q */
      ssh_mprzm_mul(&t3, &P->x, &t2);
      ssh_mprzm_mul(&t2, &t2, &t1);

      /* Compute y*(1/z)^3 mod q */
      ssh_mprzm_mul(&t1, &P->y, &t2);

      /* Copy into (x,y). */
      ssh_mprz_set_mprzm(&R->x, &t3);
      ssh_mprz_set_mprzm(&R->y, &t1);

      R->z = 1;
    }
  /* Clear temporary variables. */
  ssh_mprzm_clear(&t1);
  ssh_mprzm_clear(&t2);
  ssh_mprzm_clear(&t3);
}

/* Definition of temporary structure. */

typedef struct
{
  /* General temporary registers. */
  SshMPIntModStruct t1, t2, t3, t4, t5, t6, t7, x;
} SshECPProjectiveTemp;

void ssh_ecp_init_projective_temp(SshECPProjectiveTemp *t,
                                  SshECPCurveConst E)
{
  ssh_mprzm_init(&t->t1, &E->m);
  ssh_mprzm_init(&t->t2, &E->m);
  ssh_mprzm_init(&t->t3, &E->m);
  ssh_mprzm_init(&t->t4, &E->m);
  ssh_mprzm_init(&t->t5, &E->m);
  ssh_mprzm_init(&t->t6, &E->m);
  ssh_mprzm_init(&t->t7, &E->m);
  ssh_mprzm_init(&t->x, &E->m);
}

void ssh_ecp_clear_projective_temp(SshECPProjectiveTemp *t)
{
  ssh_mprzm_clear(&t->t1);
  ssh_mprzm_clear(&t->t2);
  ssh_mprzm_clear(&t->t3);
  ssh_mprzm_clear(&t->t4);
  ssh_mprzm_clear(&t->t5);
  ssh_mprzm_clear(&t->t6);
  ssh_mprzm_clear(&t->t7);
  ssh_mprzm_clear(&t->x);
}

/* Projective doubling of a point.
   This is after the P1363 draft. November 1996. These formulas can be
   acquired from the original paper by Chudnovsky and Chudnovsky (reference
   in P1363).

   One optimization problem is to know how many consecutive multiplications
   can one let be performed before reducing with the modulus. That is, to
   gain optimal performance. My guess is that with GMP routines reduction
   should be performed after the values is about three (3) times the length
   of the modulus for optimal performance.

   */

void ssh_ecp_projective_double(SshECPProjectivePoint R,
                               const SshECPProjectivePoint P,
                               SshECPCurveConst E,
                               SshECPProjectiveTemp *t)
{
  SshMPIntModStruct ma;

  ssh_mprzm_init(&ma, &E->m);
  ssh_mprzm_set_mprz(&ma, &E->a);

  /* Case a = -3 mod q could be included here.

     That is we could write the 3x^2 + az^4 as

     3x^2 - 3z_4 = 3(x - z^2)(x + z^2)

     if a = - 3 mod q. Which should be possible to set for half of elliptic
     curves. This is not currently forced though and thus not currently
     done, but maybe later.
   */

  ssh_mprzm_square(&t->t5, &P->z);
  ssh_mprzm_square(&t->t5, &t->t5);

  ssh_mprzm_mul(&t->t5, &t->t5, &ma);
  ssh_mprzm_clear(&ma);


  ssh_mprzm_square(&t->t4, &P->x);

  /* This might be faster than doing "small" multiplication! */
  ssh_mprzm_add(&t->x,  &t->t4, &t->t4);
  ssh_mprzm_add(&t->t4, &t->x, &t->t4);

  ssh_mprzm_add(&t->t4, &t->t4, &t->t5);

  ssh_mprzm_mul(&t->t3, &P->y, &P->z);

  /* This is probably much faster than doing actual multiplication. */
  ssh_mprzm_add(&t->t3, &t->t3, &t->t3);

  ssh_mprzm_square(&t->t2, &P->y);
  ssh_mprzm_mul(&t->t5, &P->x, &t->t2);
  /* This should be faster than multiplication by 4. */
  ssh_mprzm_add(&t->x, &t->t5, &t->t5);
  ssh_mprzm_add(&t->t5, &t->x, &t->x);

  ssh_mprzm_square(&t->t1, &t->t4);
  ssh_mprzm_sub(&t->t1, &t->t1, &t->t5);
  ssh_mprzm_sub(&t->t1, &t->t1, &t->t5);

  ssh_mprzm_square(&t->t2, &t->t2);
  /* Attempt to multiply by 8 without actually doing any multiplication. */
  ssh_mprzm_add(&t->x,  &t->t2, &t->t2);
  ssh_mprzm_add(&t->x,  &t->x,  &t->x);
  ssh_mprzm_add(&t->t2, &t->x,  &t->x);

  ssh_mprzm_sub(&t->t5, &t->t5, &t->t1);
  ssh_mprzm_mul(&t->t5, &t->t4, &t->t5);
  ssh_mprzm_sub(&t->t2, &t->t5, &t->t2);

  ssh_mprzm_set(&R->x, &t->t1);
  ssh_mprzm_set(&R->y, &t->t2);
  ssh_mprzm_set(&R->z, &t->t3);
}

/* Projective addition of distinct points. Q = (x_0, y_0, z_0) and
   P = (x_1, y_1, 1). This is the preferred addition, because no nonsense
   compares, does just the job as fast as possible (I think). */

void ssh_ecp_projective_add(SshECPProjectivePoint R,
                            const SshECPProjectivePoint Q,
                            const SshECPProjectivePoint P,
                            SshECPCurveConst E,
                            SshECPProjectiveTemp *t)
{
  ssh_mprzm_square(&t->t6, &Q->z);
  ssh_mprzm_mul(&t->t4, &P->x, &t->t6);
  ssh_mprzm_mul(&t->t6, &Q->z, &t->t6);

  ssh_mprzm_mul(&t->t5, &P->y, &t->t6);
  ssh_mprzm_add(&t->t1, &Q->x, &t->t4);
  ssh_mprzm_add(&t->t2, &Q->y, &t->t5);

  /* Multiply by 2. */
  ssh_mprzm_add(&t->t4, &t->t4, &t->t4);
  ssh_mprzm_sub(&t->t4, &t->t1, &t->t4);

  /* Multiply by 2. */
  ssh_mprzm_add(&t->t5, &t->t5, &t->t5);
  ssh_mprzm_sub(&t->t5, &t->t2, &t->t5);

  ssh_mprzm_mul(&t->t3, &t->t3, &t->t4);

  ssh_mprzm_square(&t->t6, &t->t4);
  ssh_mprzm_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprzm_mul(&t->t6, &t->t1, &t->t6);
  ssh_mprzm_square(&t->t1, &t->t5);
  ssh_mprzm_sub(&t->t1, &t->t1, &t->t6);

  ssh_mprzm_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprzm_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprzm_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprzm_mul(&t->t4, &t->t2, &t->t4);
  ssh_mprzm_sub(&t->t2, &t->t5, &t->t4);

  ssh_mprzm_div_2exp(&t->t2, &t->t2, 1);

  ssh_mprzm_set(&R->x, &t->t1);
  ssh_mprzm_set(&R->y, &t->t2);
  ssh_mprzm_set(&R->z, &t->t3);
}

/* Projective addition of distinct points. Q = (x_0, y_0, z_0) and
   P = (x_1, y_1, z_1). */

void ssh_ecp_projective_add2(SshECPProjectivePoint R,
                             const SshECPProjectivePoint Q,
                             const SshECPProjectivePoint P,
                             SshECPCurveConst E,
                             SshECPProjectiveTemp *t)
{

  ssh_mprzm_set(&t->t1, &Q->x);
  ssh_mprzm_set(&t->t2, &Q->y);
  ssh_mprzm_set(&t->t3, &Q->z);
  ssh_mprzm_set(&t->t4, &P->x);
  ssh_mprzm_set(&t->t5, &P->y);

  if (ssh_mprzm_cmp_ui(&P->z, 1) != 0)
    {
      ssh_mprzm_set(&t->t7, &P->z);
      ssh_mprzm_square(&t->t6, &t->t7);
      ssh_mprzm_mul(&t->t1, &t->t1, &t->t6);
      ssh_mprzm_mul(&t->t6, &t->t7, &t->t6);
      ssh_mprzm_mul(&t->t2, &t->t2, &t->t6);
    }

  ssh_mprzm_square(&t->t6, &t->t3);
  ssh_mprzm_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprzm_mul(&t->t6, &t->t3, &t->t6);

  ssh_mprzm_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprzm_add(&t->t1, &t->t1, &t->t4);
  ssh_mprzm_add(&t->t2, &t->t2, &t->t5);

  /* Multiply by 2. */
  ssh_mprzm_add(&t->t4, &t->t4, &t->t4);
  ssh_mprzm_sub(&t->t4, &t->t1, &t->t4);

  /* Multiply by 2. */
  ssh_mprzm_add(&t->t5, &t->t5, &t->t5);
  ssh_mprzm_sub(&t->t5, &t->t2, &t->t5);

  if (ssh_mprzm_cmp_ui(&P->z, 1) != 0)
    ssh_mprzm_mul(&t->t3, &t->t3, &t->t7);

  ssh_mprzm_mul(&t->t3, &t->t3, &t->t4);

  ssh_mprzm_square(&t->t6, &t->t4);
  ssh_mprzm_mul(&t->t4, &t->t4, &t->t6);
  ssh_mprzm_mul(&t->t6, &t->t1, &t->t6);
  ssh_mprzm_square(&t->t1, &t->t5);
  ssh_mprzm_sub(&t->t1, &t->t1, &t->t6);

  ssh_mprzm_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprzm_sub(&t->t6, &t->t6, &t->t1);
  ssh_mprzm_mul(&t->t5, &t->t5, &t->t6);
  ssh_mprzm_mul(&t->t4, &t->t2, &t->t4);
  ssh_mprzm_sub(&t->t2, &t->t5, &t->t4);

  ssh_mprzm_div_2exp(&t->t2, &t->t2, 1);

  ssh_mprzm_set(&R->x, &t->t1);
  ssh_mprzm_set(&R->y, &t->t2);
  ssh_mprzm_set(&R->z, &t->t3);
}

/* Generic double. */

void ssh_ecp_projective_generic_double(SshECPProjectivePoint R,
                                       const SshECPProjectivePoint P,
                                       SshECPCurveConst E,
                                       SshECPProjectiveTemp *t)
{
  if (ssh_mprzm_cmp_ui(&P->z, 0) == 0)
    {
      ssh_ecp_set_projective_identity(R);
      return;
    }

  ssh_ecp_projective_double(R, P, E, t);
}

/* For cases Q = (x_0, y_0, z_0) and P = (x_1, y_1, 1). */

void ssh_ecp_projective_generic_add(SshECPProjectivePoint R,
                                    const SshECPProjectivePoint Q,
                                    const SshECPProjectivePoint P,
                                    SshECPCurveConst E,
                                    SshECPProjectiveTemp *t)
{
  if (ssh_mprzm_cmp_ui(&Q->z, 0) == 0)
    {
      ssh_ecp_copy_projective_point(R, P);
      return;
    }

  ssh_mprzm_square(&t->t1, &Q->z);
  ssh_mprzm_mul(&t->t2, &P->x, &t->t1);

  if (ssh_mprzm_cmp(&t->t2, &Q->x) != 0)
    {
      ssh_ecp_projective_add(R, Q, P, E, t);
      return;
    }

  ssh_mprzm_mul(&t->t2, &P->y, &t->t1);
  ssh_mprzm_mul(&t->t2, &t->t2, &Q->z);

  if (ssh_mprzm_cmp(&t->t2, &Q->y) == 0)
    {
      ssh_ecp_projective_double(R, P, E, t);
      return;
    }
  ssh_ecp_set_projective_identity(R);
}

#endif

/* Computation of multiples of point P. Generic case. */

void ssh_ecp_generic_mul(SshECPPoint R, SshECPPointConst P,
                         SshMPIntegerConst k,
                         SshECPCurveConst E)
{
  SshECPProjectiveTemp t;
  SshECPProjectivePointStruct T, H, I;
  char *transform;
  int i;

  if (P->z == 0 || ssh_mprz_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }

  if (ssh_mprz_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }

  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&H, E);
  ssh_ecp_init_projective_point(&I, E);

  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t, E);

  /* Transform scalar multiplier to a signed representation. */
  i = ssh_mprz_transform_binary(k, &transform) - 1;

  /* Set temporary projective points. */

  ssh_ecp_affine_to_projective(&H, P);
  ssh_ecp_copy_projective_point(&T, &H);
  ssh_ecp_negate_projective_point(&I, &H, E);

  /* Multiply using transform bit-vector. */

  for (; i; i--)
    {
      ssh_ecp_projective_generic_double(&T, &T, E, &t);
      if (transform[i - 1])
        {
          ssh_ecp_projective_generic_add(&T, &T, &H, E, &t);
        }
    }

  /* Convert to affine coordinates. */

  ssh_ecp_projective_to_affine(R, &T, E);

  /* Clear temporary space. */

  ssh_xfree(transform);

  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&H);
  ssh_ecp_clear_projective_point(&I);

  ssh_ecp_clear_projective_temp(&t);
}

/* Implementation of the comb algorithm (apparently originally due to Lim
   and Lee, but easily derived from Shamir's trick). */

/* The base shall contain the precompute base points (which are actually
   in affine space).

   This precomputation method is actually written to work with
   positive and negative values. So the formulation of the comb method
   shall be as follows.

   Let e be the exponent. Then we basically throw it into a matrix on
   m columns and n rows. This operation actually produces a matrix with
   coefficients a_ij such that a_ij \in { -1, 0, 1 }. This is because
   we use signed digit representation of the exponent.

   The basic idea is that we have precomputed at least m
   powers/multiples of the base points such that following the algorithm

   1. T = 0

   2. For j = 0 to n
      T = 2T
      T = T + \sum_i a_ijw_iP

   However, observe that we can actually compute all the possible
   a_ijw_iP beforehand, and thus gain significant speed-up for two
   reasons. First, we need to do only one addition and one doubling in the
   loop at line 2. Second, we can use affine representation for \sum a_ijw_iP.
   This allows us to use faster addition routine (with less checks).

   The problem with this precomputation idea is that we actually need to
   store all the possible combinations for \sum a_ijw_iP. There are quite
   many of those.

   A signed digit expansion is of form a_0 + 2*(a_1 + 2*(....)), where
   a_i \in { -1, 0, 1 }. Further this expansion is one "digit" longer than
   the binary { 0, 1 } expansion. However, there is no problem in
   choosing w_i = 2^{v_i}. The v_i can be selected at even distances.

   So we need first to compute w_iP, as these surely are at least needed
   in the comb algorithm. This can be easily achieved by repeated
   doubling.

   The second phase which is needed is to compute all possible sums
   \sum a_i w_iP, where a_i \in { -1, 0, 1}. We can require that the
   first non-zero a_i is always 1.

   Now clearly there are 3^m combinations without the reduction. Thus
   even small m gives quite a large number of needed points. E.g.  3^4
   = 81, and this is already significant number of points. However,
   this would probably give also speed-up of about factor 2 or 3
   already. Also the space requirements are not that bad as points are
   usually quite small (and we can actually reduce them to affine
   co-ordinates.)

   We need a way to index these 3^m values in particularly efficient
   way.  First it suffices to observe that mapping the value into an
   integer (a_0+1) + 3*((a_1+1) + 3*(...)) gives us already one
   way. Further, as a_0 \in { 0, 1} we get a_0 + 2*((a_1 + 1) +
   3*(...)), which gives 3^(m-1)*2 combinations, i.e. 3^m * 2/3.

   To give an explicit algorithm, we let P[.] denote the point table.

   1. t = 1, P[0] = P_\infty

   2. for j = 0 to m

      ;; points P[1] = P, P[2] = 2^v_1*P, P[5] = 2^v_2*P ..
      ;;
      ;; Let t denote the index of the new "row". Then the length of
      ;; the current row is necessarily 2*t - 1. So, when t = 1
      ;; we get 1, and when t = 5 we get 9. Infact, we can compute the
      ;; indexes for the above list by the recursion
      ;;   t = 1  -> 1  +  1 = 2
      ;;   t = 2  -> 2  +  3 = 5
      ;;   t = 5  -> 5  +  9 = 14
      ;;   t = 14 -> 14 + 27 = 41
      ;; thus we need total 41 points for 4 division of the expansion.

   2.1  P[t] = v_jP

   2.2. for i = 1 to t-1

   2.2.1 P[t + i*2 - 1] = P[t] + P[i]
   2.2.2 P[t + i*2    ] = P[t] - P[i]

   2.3 t = t*3 - 1

   It is necessary to observe that the points here computed are all
   in projective co-ordinates.

   The conversion to affine can be implemented efficiently with the
   Montgomery trick. This goes as follows;

   ;; We have t points of form (x_i, y_i, z_i) and wish to compute
   ;; (x_i/z_i^2, y_i/z_i^3). The main problem is that
   ;; computing 1/z_i is very slow relative to the time of multiplication
   ;; add squaring. Thus we attempt to use divide and conquer strategy.
   ;; Let z_0, ..., z_t be the z-coordinates of the points. Thus by
   ;; computing z_0 * z_1 * ... * z_t we can invert them all at once.
   ;; However, we need to be able to get individual 1/z_i from this
   ;; combined inverse. The idea is to create t/2 (or (t-1)/2 + 1)
   ;; table where we store the multiples z_i*z_(i+1) (or just z_i).
   ;; Then we continue to build table of size (t/2)/2 and so on.
   ;; Finally this produces us after t*t/2*t/4*... = 2*t.

   1. Fill in the table z[i] = z_i, for i = 0...t-1.

   2. t[0] = t, f[0] = 0, p = 0, d = t.

   3. while t[p] > 1

   3.1 for i = 0 to floor(t[p]/2) - 1
   3.1.1 z[d + i] = z[d - t[p] + i*2]*z[d - t[p] + i*2 + 1].

   3.2 if t[p] == 0 (mod 2)
   3.2.1 then p = p + 1, t[p] = (t[p-1]/2), d = d + t[p].
   3.2.2 else p = p + 1, f[p] = 1,
         t[p]   = (t[p-1] - 1)/2 + 1,
         d      = d + t[p] - 1.

   4. z[d-t[p]] = 1/z[d-t[p]], d = d - (t[p] - f[p]), p = p - 1.

   5. while p >= 0

   5.1 for i = 0 to floor(t[p]/2) - 1
   5.1.1 tau = z[d - t[p] + i*2],
   5.1.1 z[d - t[p] + i*2    ] = z[d - t[p] + i*2 + 1] * z[d + i],
   5.1.1 z[d - t[p] + i*2 + 1] = tau * z[d + i].
   5.2 d = d - (t[p] - f[p]), p = p - 1.

   6. Return [z[i], ..., z[t-1]].


   The algorithm is now practically explained. We need to implement
   it next.

   */
#if 0
void ssh_ecp_mul_with_base_init(const SshECPPoint *P,
                                const SshECPCurve *E,
                                SshECPBase        *base)
{
  /* Define the base. */
  base->defined = TRUE;

  /* Start up creating the base. */

}

#endif

#if 0

/* Specialized multiplication for points P of prime order, where
   0 <= k < #P. */

void ssh_ecp_mul(SshECPPoint R, SshECPPointConst P,
                 SshMPIntegerConst k,
                 SshECPCurveConst E)
{
  SshECPProjectiveTemp t;
  SshECPProjectivePointStruct T, H, I;
  char *transform;
  int i;

  if (P->z == 0 || ssh_mprz_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }
  if (ssh_mprz_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }

  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&H, E);
  ssh_ecp_init_projective_point(&I, E);

  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t);

  /* Transform scalar multiplier to signed representation. */
  i = ssh_mprz_transform_binary(k, &transform) - 1;

  /* Set temporary projective points. */

  ssh_ecp_affine_to_projective(&H, P);
  ssh_ecp_copy_projective_point(&T, &H);
  ssh_ecp_negate_projective_point(&I, &H, E);

  /* Multiply using transform bit-vector. */

  for (; i; i--)
    {
      ssh_ecp_projective_double(&T, &T, E, &t);
      if (transform[i - 1])
        {
          if (transform[i - 1] == -1)
            ssh_ecp_projective_add(&T, &T, &I, E, &t);
          else
            ssh_ecp_projective_add(&T, &T, &H, E, &t);
        }
    }

  /* Convert to affine coordinates. */

  ssh_ecp_projective_to_affine(R, &T, E);

  /* Clear temporary space. */

  ssh_xfree(transform);

  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&H);
  ssh_ecp_clear_projective_point(&I);

  ssh_ecp_clear_projective_temp(&t);
}

#else

/* Specialized multiplication for points P of prime order, where
   0 <= k < #P. This version also features basic 2^k-ary computation
   which of course "should" (but doesn't) speed computation. */

void ssh_ecp_mul(SshECPPoint R, SshECPPointConst P,
                 SshMPIntegerConst k,
                 SshECPCurveConst E)
{
  SshECPProjectiveTemp t;
#define K_ARY      4
#define K_ARY_SIZE (1 << K_ARY)
  SshECPProjectivePointStruct T, H[K_ARY_SIZE], N;
  char *transform;
  unsigned int transform_index;
  unsigned int i, j;
  int first, mask, zeros, steps;

  if (P->z == 0 || ssh_mprz_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }
  if (ssh_mprz_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }

  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&N, E);
  for (i = 0; i < K_ARY_SIZE/2; i++)
    ssh_ecp_init_projective_point(&H[i], E);

  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t, E);

  /* Transform scalar multiplier into signed representation. */
  transform_index = ssh_mprz_transform_binary(k, &transform) - 1;

  /* Set temporary projective points. */










  ssh_ecp_affine_to_projective(&H[0], P);
  ssh_ecp_projective_double(&T, &H[0], E, &t);
  for (i = 1; i < K_ARY_SIZE/2; i++)
    ssh_ecp_projective_add2(&H[i], &H[i - 1], &T, E, &t);

  /* Multiply using transform bit-vector. */

  /* 2^k-ary case. */

  ssh_ecp_copy_projective_point(&T, &H[0]);

  /* Do the main looping. */
  for (first = 1, i = transform_index + 1; i;)
    {
      for (j = 0, mask = zeros = steps = 0; j < K_ARY && i; j++, i--)
        {
          if (transform[i - 1])
            {
              steps += zeros;
              /* Multiply by 2, if necessary. */
              if (mask)
                {
                  while (zeros)
                    {
                      mask <<= 1;
                      zeros--;
                    }
                  /* The base case. */
                  mask <<= 1;
                }
              mask += transform[i - 1];
              steps++;
            }
          else
            zeros++;
        }

      if (mask == 0)
        ssh_fatal("ssh_ecp_mul: failure in handling the multiplier.");

      /* Handle the actual elliptic curve operations. */
      if (!first)
        {
          for (j = 0; j < steps; j++)
            ssh_ecp_projective_double(&T, &T, E, &t);

          /* Notice, that we have tabulate all values nP where, n is
             odd. Here we must have mask odd, and thus we can happily
             get the correct place by shifting down by one. */
          if (mask < 0)
            {
              ssh_ecp_negate_projective_point(&N, &H[(-mask) >> 1], E);
              ssh_ecp_projective_add2(&T, &T, &N, E, &t);
            }
          else
            ssh_ecp_projective_add2(&T, &T, &H[mask >> 1], E, &t);
        }
      else
        {
          if (mask < 0)
            {
              ssh_ecp_negate_projective_point(&N, &H[(-mask) >> 1], E);
              ssh_ecp_copy_projective_point(&T, &N);
            }
          else
            ssh_ecp_copy_projective_point(&T, &H[mask >> 1]);
          first = 0;
        }

      /* Now do the doubling phase. */
      while (zeros)
        {
          ssh_ecp_projective_double(&T, &T, E, &t);
          zeros--;
        }

      while (i && transform[i - 1] == 0)
        {
          ssh_ecp_projective_double(&T, &T, E, &t);
          i--;
          zeros++;
        }
    }

  /* Convert to affine coordinates. */

  ssh_ecp_projective_to_affine(R, &T, E);

  /* Clear temporary space. */

  ssh_xfree(transform);

  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&N);
  for (i = 0; i < K_ARY_SIZE/2; i++)
    ssh_ecp_clear_projective_point(&H[i]);

  ssh_ecp_clear_projective_temp(&t);

#undef K_ARY
#undef K_ARY_SIZE
}
#endif

/* Point compression. */

Boolean ssh_ecp_compute_y_from_x(SshMPInteger y, SshMPIntegerConst x,
                                 SshECPCurveConst E)
{
  SshMPIntegerStruct t1, t2;
  Boolean rv = FALSE;

  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  ssh_mprz_mul(&t1, x, x);
  ssh_mprz_mul(&t1, &t1, x);
  ssh_mprz_mod(&t1, &t1, &E->q);

  ssh_mprz_mul(&t2, x, &E->a);
  ssh_mprz_add(&t2, &t2, &E->b);
  ssh_mprz_add(&t1, &t1, &t2);

  ssh_mprz_mod(&t1, &t1, &E->q);

  if (ssh_mprz_mod_sqrt(y, &t1, &E->q))
    rv = TRUE;
  else
    rv = FALSE;

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  return rv;
}

Boolean ssh_ecp_restore_y(SshECPPoint P, SshECPCurveConst E,
                          Boolean bit)
{
  if (ssh_ecp_compute_y_from_x(&P->y, &P->x, E) == FALSE)
    return FALSE;
  if (bit != (ssh_mprz_get_ui(&P->y) & 0x1))
    ssh_mprz_sub(&P->y, &E->q, &P->y);
  return TRUE;
}

/* Select a random point from E(Fq). */

void ssh_ecp_random_point(SshECPPoint P, SshECPCurveConst E)
{
  while (1)
    {
      /* Get a random point from Fq. */
      ssh_mprz_rand(&P->x, ssh_mprz_get_size(&E->q, 2) + 1);
      ssh_mprz_mod(&P->x, &P->x, &E->q);

      if (ssh_ecp_compute_y_from_x(&P->y, &P->x, E))
        {
          P->z = 1;
          break;
        }
    }
}

/* Find a point of a prime order. This function needs to know the
   largest prime divisor of the cardinality of the given curve.

   Be careful when giving the prime factor that it really is the largest
   factor, this function does not check it.

   Return value FALSE means that the cardinality, point or curve is not
   correct.
   */

Boolean ssh_ecp_random_point_of_prime_order(SshECPPoint P,
                                            SshMPIntegerConst n,
                                            SshECPCurveConst E)
{
  SshMPIntegerStruct t, r;
  SshECPPointStruct Q;

  ssh_mprz_init(&t);
  ssh_mprz_init(&r);

  /* n must be factor of cardinality, either trivial or non-trivial. */
  ssh_mprz_divrem(&t, &r, &E->c, n);

  if (ssh_mprz_cmp_ui(&r, 0) != 0)
    {
      ssh_mprz_clear(&t);
      ssh_mprz_clear(&r);
      return FALSE;
    }

  /* Because we cannot use the time to factor we have restricted this
     function to primes (probable primes more accurately). */
  if (!ssh_mprz_is_probable_prime(n, 25))
    {
      ssh_mprz_clear(&t);
      ssh_mprz_clear(&r);
      return FALSE;
    }

  ssh_ecp_init_point(&Q, E);

  while (1)
    {
      /* Select a random point */
      ssh_ecp_random_point(&Q, E);
      ssh_ecp_generic_mul(P, &Q, &t, E);

      if (P->z)
        break;
    }

  ssh_ecp_generic_mul(&Q, P, n, E);

  if (Q.z)
    {
      ssh_mprz_clear(&t);
      ssh_mprz_clear(&r);
      return FALSE;
    }

  ssh_mprz_clear(&t);
  ssh_mprz_clear(&r);

  return TRUE;
}

/* Check whether parameters define supersingular curve. Returns TRUE if
   curve is supersingular. I.e. return value FALSE is good for our purposes.

   Let E be an elliptic curve over finite field and #E(Fq) = q + 1 - t
   then E is supersingular if

   t^2 = 0, q, 2q, 3q or 4q.

   */
Boolean ssh_ecp_is_supersingular(SshECPCurveConst E)
{
  SshMPIntegerStruct t, temp;
  Boolean rv = TRUE;

  ssh_mprz_init(&t);
  ssh_mprz_init(&temp);

  /* Compute t from #E(Fq) = q + 1 - t */
  ssh_mprz_add_ui(&temp, &E->q, 1);
  ssh_mprz_sub(&t, &temp, &E->c);

  /* Compute t^2 */
  ssh_mprz_mul(&t, &t, &t);

  /* Check whether t = 0, q, 2q, 3q or 4q. */

  if (ssh_mprz_cmp_ui(&t, 0) == 0)
    goto end;

  ssh_mprz_set(&temp, &E->q);
  if (ssh_mprz_cmp(&t, &temp) == 0)
    goto end;

  ssh_mprz_add(&temp, &temp, &E->q);
  if (ssh_mprz_cmp(&t, &temp) == 0)
    goto end;

  ssh_mprz_add(&temp, &temp, &E->q);
  if (ssh_mprz_cmp(&t, &temp) == 0)
    goto end;

  ssh_mprz_add(&temp, &temp, &E->q);
  if (ssh_mprz_cmp(&t, &temp) == 0)
    goto end;

  rv = FALSE;

end:

  ssh_mprz_clear(&t);
  ssh_mprz_clear(&temp);

  return rv;
}

/* Brute force #E(Fq), i.e. counting points in elliptic curve over
   finite field Fq. Uses the fact that for every x there lies at most
   two y coordinates in Fq.

   This is not a general purpose counting algorithm because it is
   infeasible after about q > 10^5 which is not very great.

   There exists polynomial time algorithm due to R. Schoof and also method
   called complex multiplication; use either of those or some other similar
   method for actual cardinality computations.
   */
void ssh_ecp_brute_point_count(SshECPCurve E)
{
  SshMPIntegerStruct x, y, t1, t2;

  /* Temporary variables. */
  ssh_mprz_init_set_ui(&x, 0);
  ssh_mprz_init(&y);
  ssh_mprz_init(&t1);
  ssh_mprz_init(&t2);

  /* Clear the counter */
  ssh_mprz_set_ui(&E->c, 0);

  /* Set up t2 = b */
  ssh_mprz_set(&t2, &E->b);

  for (; ssh_mprz_cmp(&x, &E->q) < 0; ssh_mprz_add_ui(&x, &x, 1))
    {
      /* This should say:
         (t2) + 3x + (3x^2) + a + 1. */
      ssh_mprz_mul_ui(&t1, &x, 3);
      ssh_mprz_add(&t2, &t2, &t1);
      ssh_mprz_mul(&t1, &t1, &x);
      ssh_mprz_add(&t2, &t2, &t1);
      ssh_mprz_add(&t2, &t2, &E->a);
      ssh_mprz_add_ui(&t2, &t2, 1);

      if (ssh_mprz_cmp(&t2, &E->q) >= 0)
        ssh_mprz_mod(&t2, &t2, &E->q);

      ssh_mprz_add_ui(&E->c, &E->c, ssh_mprz_legendre(&t2, &E->q) + 1);
    }
  /* And the point at the infinity! */
  ssh_mprz_add_ui(&E->c, &E->c, 1);

  ssh_mprz_clear(&x);
  ssh_mprz_clear(&y);
}

/* Check the Menezes, Okamoto and Vanstone elliptic curve reduction attack
   possibility. */

Boolean ssh_ecp_mov_condition(SshMPIntegerConst op_b,
                              SshMPIntegerConst op_q,
                              SshMPIntegerConst op_r)
{
  SshMPIntegerStruct t, i;
  Boolean mov_condition = FALSE;

  /* Initialize temporary variables. */
  ssh_mprz_init_set_ui(&t, 1);
  ssh_mprz_init_set(&i, op_b);

  /* Iterate the mov condition */
  while (ssh_mprz_cmp_ui(&i, 0) != 0)
    {
      ssh_mprz_mul(&t, &t, op_q);
      ssh_mprz_mod(&t, &t, op_r);
      if (ssh_mprz_cmp_ui(&t, 1) == 0)
        {
          mov_condition = TRUE;
          break;
        }
      ssh_mprz_sub_ui(&i, &i, 1);
    }

  /* Clear temporary variables. */
  ssh_mprz_clear(&t);
  ssh_mprz_clear(&i);
  return mov_condition;
}

/* Verify that the curve is (probably) good. */

Boolean ssh_ecp_verify_param(SshECPCurveConst E,
                             SshECPPointConst P,
                             SshMPIntegerConst n)
{
  SshECPPointStruct Q;
  SshMPIntegerStruct t1, t2;
  unsigned int i;

  /* Checks for the field modulus. */

  if (ssh_mprz_cmp_ui(&E->q, 0) <= 0)
    return FALSE;

  /* Checks for the order of the point. */

  if (ssh_mprz_cmp_ui(n, 0) <= 0)
    return FALSE;

  /* Trivial check for strength. */
  if (ssh_mprz_get_size(n, 2) < 100)
    return FALSE;

  if (ssh_mprz_cmp(n, &E->q) >= 0)
    return FALSE;

  /* Test lower limits. */

  if (ssh_mprz_cmp_ui(&E->a, 0) <= 0)
    return FALSE;
  if (ssh_mprz_cmp_ui(&E->b, 0) <= 0)
    return FALSE;
  if (ssh_mprz_cmp_ui(&P->x, 0) < 0)
    return FALSE;
  if (ssh_mprz_cmp_ui(&P->y, 0) < 0)
    return FALSE;

  /* Check for point at infinity. */
  if (P->z != 1)
    return FALSE;

  /* Check higher limits. */

  if (ssh_mprz_cmp(&E->a, &E->q) >= 0)
    return FALSE;
  if (ssh_mprz_cmp(&E->b, &E->q) >= 0)
    return FALSE;
  if (ssh_mprz_cmp(&E->c, &E->q) >= 0)
    return FALSE;
  if (ssh_mprz_cmp(&P->x, &E->q) >= 0)
    return FALSE;
  if (ssh_mprz_cmp(&P->y, &E->q) >= 0)
    return FALSE;

  /* Check that n divides the cardinality of the curve. */

  ssh_mprz_init(&t1);
  ssh_mprz_mod(&t1, &E->c, n);
  if (ssh_mprz_cmp_ui(&t1, 0) != 0)
    {
      ssh_mprz_clear(&t1);
      return FALSE;
    }
  ssh_mprz_clear(&t1);

  /* Trivial checks are done, checking primalities. This can take some
     time, which is not so good. */

  if (!ssh_mprz_is_probable_prime(&E->q, 25))
    return FALSE;

  if (!ssh_mprz_is_probable_prime(n, 25))
    return FALSE;

  /* Check that the curve and point are really correct. */

  if (ssh_ecp_is_supersingular(E))
    return FALSE;

  /* Check that the curve is not anomalous. E.g. the attack by
     Smart (and Satoh et al.) doesn't apply. */

  if (ssh_mprz_cmp(&E->c, &E->q) == 0 ||
      ssh_mprz_cmp(n, &E->q) == 0)
    return FALSE;

  ssh_mprz_init(&t1);






  ssh_mprz_set_ui(&t1, 500);

  if (ssh_ecp_mov_condition(&t1, &E->q, n))
    {
      ssh_mprz_clear(&t1);
      return FALSE;
    }

  ssh_mprz_init(&t2);

  /* Test that 4a^3 + 27b^2 != 0 */
  ssh_mprz_square(&t1, &E->a);
  ssh_mprz_mod(&t1, &t1, &E->q);
  ssh_mprz_mul(&t1, &t1, &E->a);
  ssh_mprz_mod(&t1, &t1, &E->q);
  ssh_mprz_mul_ui(&t1, &t1, 4);

  ssh_mprz_square(&t2, &E->b);
  ssh_mprz_mod(&t2, &t2, &E->q);
  ssh_mprz_mul_ui(&t2, &t2, 27);

  ssh_mprz_add(&t1, &t1, &t2);
  ssh_mprz_mod(&t1, &t1, &E->q);

  if (ssh_mprz_cmp_ui(&t1, 0) == 0)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return FALSE;
    }

  /* Test that y^2 = x^3 + ax + b */
  ssh_mprz_mul(&t1, &P->y, &P->y);
  ssh_mprz_mul(&t2, &P->x, &P->x);
  ssh_mprz_mul(&t2, &P->x, &t2);
  ssh_mprz_mod(&t2, &t2, &E->q);
  ssh_mprz_sub(&t1, &t1, &t2);
  ssh_mprz_mul(&t2, &P->x, &E->a);
  ssh_mprz_mod(&t2, &t2, &E->q);
  ssh_mprz_sub(&t1, &t1, &t2);
  ssh_mprz_sub(&t1, &t1, &E->b);
  ssh_mprz_mod(&t1, &t1, &E->q);

  if (ssh_mprz_cmp_ui(&t1, 0) != 0)
    {
      ssh_mprz_clear(&t1);
      ssh_mprz_clear(&t2);
      return FALSE;
    }

  ssh_mprz_clear(&t1);
  ssh_mprz_clear(&t2);

  /* Check that the order of the point is correct. */

  ssh_ecp_init_point(&Q, E);
  ssh_ecp_generic_mul(&Q, P, n, E);
  if (Q.z != 0)
    {
      ssh_ecp_clear_point(&Q);
      return FALSE;
    }

  /* For completeness check that the cardinality is correct. */

  ssh_mprz_init(&t1);
  ssh_mprz_div(&t1, &E->c, n);

  /* Try four different points and see if point at infinity will be
     found. */
  for (i = 0; i < 4; i++)
    {
      /* Generate a random point. */
      ssh_ecp_random_point(&Q, E);
      ssh_ecp_generic_mul(&Q, &Q, &t1, E);
      if (Q.z != 0)
        {
          /* This must get to point at infinity or something is wrong. */
          ssh_ecp_generic_mul(&Q, &Q, n, E);
          if (Q.z != 0)
            {
              ssh_mprz_clear(&t1);
              ssh_ecp_clear_point(&Q);
              return FALSE;
            }
        }
    }
  ssh_mprz_clear(&t1);
  ssh_ecp_clear_point(&Q);

  /* We have found that the curve satisfies all our tests. */
  return TRUE;
}

/* ecpmath.c */
#endif /* SSHDIST_MATH_ECP */
#endif /* SSHDIST_MATH */
