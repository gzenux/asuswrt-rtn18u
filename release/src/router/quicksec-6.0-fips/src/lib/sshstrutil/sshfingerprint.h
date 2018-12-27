/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshfingerprint.h
*/

#ifndef SSH_FINGERPRINT_H_INCLUDED
#define SSH_FINGERPRINT_H_INCLUDED

typedef enum {
  /* Fingerprint is in SSH Babble format described in Bubble Babble
     Binary Data Encoding draft by Antti Huima <huima@ssh.com>.
     Format is a set of five lowercase letter pronouncable strings
     separated by dashes '-'.  The first and the last character of the
     string is always x. */
  SSH_FINGERPRINT_BABBLE,

  /* Same as SSH_FINGERPRINT_BABBLE, except in capital letters. */
  SSH_FINGERPRINT_BABBLE_UPPER,

  /* Fingerprint is in PGP-2.x format.  In other words, it's in upper case
     hexadecimal string where the string is divided to groups of two
     hexadigits.  Between each group, there is a single space character,
     except between every eighth group, there are two space characters. */
  SSH_FINGERPRINT_PGP2,

  /* Fingerprint is in PGP-5.x format.  In other words, it's in upper case
     hexadecimal string where the string is divided to groups of four
     hexadigits.  Between each group, there is a single space character,
     except between every fifth group there are two space characters. */
  SSH_FINGERPRINT_PGP5,

  /* Fingerprint is in raw hexadecimal format.  Bytes are encoded into
     one hexadecimal string containing only characters 0, 1, 2, 3, 4,
     5, 6, 7, 8, 9, a, b, c, d, e and f. */
  SSH_FINGERPRINT_HEX,

  /* Fingerprint is in raw hexadecimal format.  Bytes are encoded into
     one hexadecimal string containing only characters 0, 1, 2, 3, 4,
     5, 6, 7, 8, 9, A, B, C, D, E and F. */
  SSH_FINGERPRINT_HEX_UPPER
} SshFingerPrintType;

/* Return fingerprint as a string.  Return value is a NUL-terminated
   ascii-string that has been allocated with ssh_xmalloc and should be
   freed by the caller with ssh_xfree.  If unknown fingerprint type is
   requested, this function calls ssh_fatal(). */
char *ssh_fingerprint(const unsigned char *digest,
                      size_t digest_len,
                      SshFingerPrintType fingerprint_type);

/* Return fingerprint type as a statically allocated string.  Name is
   a human readable NUL-terminated string describing the method used
   in converting binary data to printable string with given
   fingerprint_type.  If unknown fingerprint type is given as an
   argument, this function calls ssh_fatal(). */
const char *ssh_fingerprint_name(SshFingerPrintType fingerprint_type);

#endif /* SSH_FINGERPRINT_H_INCLUDED */
