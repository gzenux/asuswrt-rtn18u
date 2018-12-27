/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshbase16.h
*/

#ifndef SSHBASE16_H
#define SSHBASE16_H

/* Determine whether the 'byte' is in the set of base-16 characters or
   not. Returns 0 if not and 1 yes. */
int ssh_is_base16(unsigned char byte);

/* Conversion from base-16 to binary octet stream. The input must not
   contain any other characters (or else a NULL will be returned). */
unsigned char *ssh_base16_to_buf(const char *str,
                                 size_t *buf_len);
/* Conversion of binary octet string to base-16. The output will be
   in BIG alphanumeric characters. */
char *ssh_buf_to_base16(const unsigned char *buf, size_t buf_len);

#endif /* SSHBASE16_H */
