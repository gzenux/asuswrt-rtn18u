/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Canonialize comma-separated cipher lists.
*/

#ifndef SSHCIPHERLIST_H
#define SSHCIPHERLIST_H

/*
   Return a name list that contains items in list `original'
   so that items in list `excluded' are excluded.
*/
char *
ssh_cipher_list_exclude(const char *original,
                        const char *excluded);

/*
   Convert between canonical cryptolib names and
   names in secsh draft.
 */
char *ssh_public_key_name_ssh_to_cryptolib(const char *str);
char *ssh_public_key_name_cryptolib_to_ssh(const char *str);

/* When given a list of public key algorithms (ssh-dsa,...)
   constructs an xmallocated list of corresponding X509 versions
   (x509v3-sign-dss,...) and returns it. */
char *
ssh_cipher_list_x509_from_pk_algorithms(const char *alglist);

#endif /* SSHCIPHERLIST_H */

/* eof (sshcipherlist.h) */
