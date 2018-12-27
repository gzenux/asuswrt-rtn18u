/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshmp.h"

#define SSH_DEBUG_MODULE "SshMPPowM"

#ifdef SSHDIST_MATH
static void ssh_mprz_powm_montgomery(SshMPInteger ret,
                                     SshMPIntegerConst g,
                                     SshMPIntegerConst e,
                                     SshMPIntegerConst p)
{
  SshMPMontIntIdealStruct m;
  SshMPMontIntModStruct gm;

  /* Check the modulus is odd, if not then this method fails. */
  if ((ssh_mprz_get_ui(p) & 0x1) != 0x1)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_EVENMOD);
      return;
    }

  if (!ssh_mpmzm_init_ideal(&m, p))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  ssh_mpmzm_init(&gm, &m);
  if (ssh_mpmzm_isnan(&gm))
    {
      ssh_mpmzm_clear_ideal(&m);
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }

  ssh_mpmzm_set_mprz(&gm, g);
  ssh_mpmzm_pow(&gm, &gm, e);
  ssh_mprz_set_mpmzm(ret, &gm);

  ssh_mpmzm_clear(&gm);
  ssh_mpmzm_clear_ideal(&m);
}























































































#ifndef SSHMATH_MINIMAL

void ssh_mprz_powm(SshMPInteger ret,
                   SshMPIntegerConst g, SshMPIntegerConst e,
                   SshMPIntegerConst p)
{
  SshMPIntIdealStruct m;
  SshMPIntModStruct gm;

  if (ssh_mprz_nanresult3(ret, g, e, p))
    return;

  /* Check the sign. */
  if (ssh_mprz_cmp_ui(e, 0) < 0)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENEGPOWER);
      return;
    }

  /* If the modulus is odd we can use the Montgomery routine. */
  if (ssh_mprz_get_ui(p) & 0x1)
    {
      ssh_mprz_powm_montgomery(ret, g, e, p);
      return;
    }

  /* Otherwise we use the generic Intmod routine. */
  if (!ssh_mprzm_init_ideal(&m, p))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }
  ssh_mprzm_init(&gm, &m);

  ssh_mprzm_set_mprz(&gm, g);
  ssh_mprzm_pow(&gm, &gm, e);
  ssh_mprz_set_mprzm(ret, &gm);

  ssh_mprzm_clear(&gm);
  ssh_mprzm_clear_ideal(&m);
}

void ssh_mprz_powm_gg(SshMPInteger ret,
                      SshMPIntegerConst g1, SshMPIntegerConst e1,
                      SshMPIntegerConst g2, SshMPIntegerConst e2,
                      SshMPIntegerConst p)
{
  SshMPIntIdealStruct m;
  SshMPIntModStruct g1m, g2m;

  if (ssh_mprz_nanresult3(ret, g1, e1, p))
    return;

  if (ssh_mprz_nanresult2(ret, g2, e2))
    return;

  /* Check the sign. */
  if ((ssh_mprz_cmp_ui(e1, 0) < 0) || (ssh_mprz_cmp_ui(e2, 0) < 0))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENEGPOWER);
      return;
    }

  if (!ssh_mprzm_init_ideal(&m, p))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }
  ssh_mprzm_init(&g1m, &m);
  ssh_mprzm_init(&g2m, &m);

  ssh_mprzm_set_mprz(&g1m, g1);
  ssh_mprzm_set_mprz(&g2m, g2);

  ssh_mprzm_pow_gg(&g1m, &g1m, e1, &g2m, e2);
  ssh_mprz_set_mprzm(ret, &g1m);

  ssh_mprzm_clear(&g1m);
  ssh_mprzm_clear(&g2m);
  ssh_mprzm_clear_ideal(&m);
}

void ssh_mprz_powm_ui_g(SshMPInteger ret, SshWord g, SshMPIntegerConst e,
                        SshMPIntegerConst p)
{
  SshMPIntIdealStruct m;
  SshMPIntModStruct gm;

  if (ssh_mprz_nanresult2(ret, e, p))
    return;

  /* Check the sign. */
  if (ssh_mprz_cmp_ui(e, 0) < 0)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENEGPOWER);
      return;
    }

  if (!ssh_mprzm_init_ideal(&m, p))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }
  ssh_mprzm_init(&gm, &m);

  ssh_mprzm_pow_ui_g(&gm, g, e);
  ssh_mprz_set_mprzm(ret, &gm);

  ssh_mprzm_clear(&gm);
  ssh_mprzm_clear_ideal(&m);
}

void ssh_mprz_powm_ui_exp(SshMPInteger ret, SshMPIntegerConst g,
                          SshWord e, SshMPIntegerConst p)
{
  SshMPIntIdealStruct m;
  SshMPIntModStruct gm;

  if (ssh_mprz_nanresult2(ret, g, p))
    return;

  if (!ssh_mprzm_init_ideal(&m, p))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }
  ssh_mprzm_init(&gm, &m);
  ssh_mprzm_set_mprz(&gm, g);

  ssh_mprzm_pow_ui_exp(&gm, &gm, e);
  ssh_mprz_set_mprzm(ret, &gm);

  ssh_mprzm_clear(&gm);
  ssh_mprzm_clear_ideal(&m);
}

Boolean ssh_mprz_powm_precomp_init(SshMPIntModPowPrecomp precomp,
                                   SshMPIntegerConst g, SshMPIntegerConst p,
                                   SshMPIntegerConst order)
{
  SshMPIntIdeal m = ssh_calloc(1, sizeof(*m));
  SshMPIntModStruct gm;
  Boolean ret;

  if (m == NULL)
    return FALSE;

  ssh_mprzm_init_ideal(m, p);
  ssh_mprzm_init(&gm, m);
  ssh_mprzm_set_mprz(&gm, g);

  ret = ssh_mprzm_pow_precomp_init(precomp, &gm, order);

  ssh_mprzm_clear(&gm);
  return ret;
}

SshMPIntModPowPrecomp
ssh_mprz_powm_precomp_create(SshMPIntegerConst g,
  SshMPIntegerConst p,
                             SshMPIntegerConst order)
{
  SshMPIntModPowPrecomp precomp = ssh_calloc(1, sizeof(*precomp));

  if (precomp == NULL)
    return NULL;

  if (!ssh_mprz_powm_precomp_init(precomp, g, p, order))
    {
      ssh_free(precomp);
      return NULL;
    }

  return precomp;
}

void ssh_mprz_powm_precomp_clear(SshMPIntModPowPrecomp precomp)
{
  SshMPIntIdeal m = (SshMPIntIdeal)ssh_mprzm_pow_precomp_get_ideal(precomp);

  ssh_mprzm_pow_precomp_clear(precomp);
  ssh_mprzm_clear_ideal(m);
  ssh_free(m);
}

void ssh_mprz_powm_precomp_destroy(SshMPIntModPowPrecomp precomp)
{
  ssh_mprz_powm_precomp_clear(precomp);
  ssh_free(precomp);
}

void ssh_mprz_powm_with_precomp(SshMPInteger ret, SshMPIntegerConst e,
                                SshMPIntModPowPrecompConst precomp)
{
  SshMPIntModStruct gm;

  ssh_mprzm_init(&gm, ssh_mprzm_pow_precomp_get_ideal(precomp));

  ssh_mprzm_pow_precomp(&gm, e, precomp);
  ssh_mprz_set_mprzm(ret, &gm);

  ssh_mprzm_clear(&gm);
}

#else /* SSHMATH_MINIMAL */

void ssh_mprz_powm(SshMPInteger ret,
                   SshMPIntegerConst g, SshMPIntegerConst e,
                   SshMPIntegerConst p)
{
  if (ssh_mprz_nanresult3(ret, g, e, p))
    return;

  /* Check the sign. */
  if (ssh_mprz_cmp_ui(e, 0) < 0)
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENEGPOWER);
      return;
    }

  ssh_mprz_powm_montgomery(ret, g, e, p);
}


void ssh_mprz_powm_gg(SshMPInteger ret,
                      SshMPIntegerConst g1, SshMPIntegerConst e1,
                      SshMPIntegerConst g2, SshMPIntegerConst e2,
                      SshMPIntegerConst p)
{
  SshMPMontIntIdealStruct m;
  SshMPMontIntModStruct g1m, g2m;

  if (ssh_mprz_nanresult3(ret, g1, e1, p))
    return;

  if (ssh_mprz_nanresult2(ret, g2, e2))
    return;

  /* Check the sign. */
  if ((ssh_mprz_cmp_ui(e1, 0) < 0) || (ssh_mprz_cmp_ui(e2, 0) < 0))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENEGPOWER);
      return;
    }

  if (!ssh_mpmzm_init_ideal(&m, p))
    {
      ssh_mprz_makenan(ret, SSH_MP_NAN_ENOMEM);
      return;
    }
  ssh_mpmzm_init(&g1m, &m);
  ssh_mpmzm_init(&g2m, &m);

  ssh_mpmzm_set_mprz(&g1m, g1);
  ssh_mpmzm_set_mprz(&g2m, g2);

  ssh_mpmzm_pow_gg(&g1m, &g1m, e1, &g2m, e2);
  ssh_mprz_set_mpmzm(ret, &g1m);

  ssh_mpmzm_clear(&g1m);
  ssh_mpmzm_clear(&g2m);
  ssh_mpmzm_clear_ideal(&m);
}

/* The following two functions are unoptimized. */

void ssh_mprz_powm_ui_g(SshMPInteger ret, SshWord g, SshMPIntegerConst e,
                        SshMPIntegerConst p)
{
  SshMPIntegerStruct temp;

  ssh_mprz_init(&temp);
  ssh_mprz_set_ui( &temp, g);
  ssh_mprz_powm(ret, &temp, e, p);
  ssh_mprz_clear(&temp);
}

void ssh_mprz_powm_ui_exp(SshMPInteger ret, SshMPIntegerConst g,
                          SshWord e, SshMPIntegerConst p)
{
  SshMPIntegerStruct temp;

  ssh_mprz_init(&temp);
  ssh_mprz_set_ui(&temp, e);
  ssh_mprz_powm(ret, g, &temp, p);
  ssh_mprz_clear(&temp);
}

#endif /* SSHMATH_MINIMAL */




/* sshmp-powm.c */
#endif /* SSHDIST_MATH */
