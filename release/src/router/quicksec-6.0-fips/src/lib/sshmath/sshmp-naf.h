/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmp-naf.h
*/

#ifndef SSHMP_NAF_H
#define SSHMP_NAF_H

/* Routines to compute NAFs (Non-adjacent forms), and
   other representations of integer "exponents". */

/* The Morain-Olivos signed digit {-1,0,1} NAF. */
unsigned int ssh_mprz_transform_mo(SshMPIntegerConst k,
                                   char **transform_table);

/* Standard binary expansion. */
unsigned int ssh_mprz_transform_binary(SshMPIntegerConst k,
                                       char **transform_table);

/* KMOV NAF-expansions. */
unsigned int ssh_mprz_transform_kmov(SshMPIntegerConst k,
                                     char **transform_table);


#endif /* SSHMP_NAF_H */
