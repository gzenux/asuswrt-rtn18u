/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSHMP_POWM_H
#define SSHMP_POWM_H

void ssh_mprz_powm(SshMPInteger ret, SshMPIntegerConst g, SshMPIntegerConst e,
                   SshMPIntegerConst p);

void ssh_mprz_powm_gg(SshMPInteger ret,
                      SshMPIntegerConst g1, SshMPIntegerConst e1,
                      SshMPIntegerConst g2, SshMPIntegerConst e2,
                      SshMPIntegerConst p);

void ssh_mprz_powm_ui_g(SshMPInteger ret, SshWord g, SshMPIntegerConst e,
                        SshMPIntegerConst p);

void ssh_mprz_powm_ui_exp(SshMPInteger ret, SshMPIntegerConst g,
                          SshWord e, SshMPIntegerConst p);


#ifndef SSHMATH_MINIMAL
/* Modular exponentation with precomputation. Returns FALSE on failure. */
Boolean ssh_mprz_powm_precomp_init(SshMPIntModPowPrecomp precomp,
                                   SshMPIntegerConst g, SshMPIntegerConst p,
                                   SshMPIntegerConst bound);
SshMPIntModPowPrecomp
ssh_mprz_powm_precomp_create(SshMPIntegerConst g,
                             SshMPIntegerConst p,
                             SshMPIntegerConst order);

void ssh_mprz_powm_precomp_clear(SshMPIntModPowPrecomp precomp);
void ssh_mprz_powm_precomp_destroy(SshMPIntModPowPrecomp precomp);

void ssh_mprz_powm_with_precomp(SshMPInteger ret, SshMPIntegerConst e,
                                SshMPIntModPowPrecompConst precomp);
#endif /* SSHMATH_MINIMAL */


#endif /* SSHMP_POWM_H */

