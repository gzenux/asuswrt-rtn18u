/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Few routines for converting between strings defined by different
   character sets.
*/

#ifndef SSHSTR_H
#define SSHSTR_H

/* Policy: SSH is not going to support all special character sets or
   country specific ASCII sets. That would be almost impossible. It is
   hoped that the UTF-8 will become de facto standard in near future
   and atleast after 2003 as hoped by PKIX, thus we concentrate our
   support for that set.

   Why UTF-8 is the choice? Mainly because it extends the US-ASCII in
   a transparent way and has the full power of UCS-4 and UCS-2. I
   feel, and probably other too, that having just one common character
   set is best for us all. */

/* Following charsets are only ones supported at the moment. */
typedef enum
{
  /* Given any as argument to conversion function will convert the
     string into smallest charset it fits into. */
  SSH_CHARSET_ANY = -1,

  /* The basic charset (a subset of ASCII). Usually printable
     strings are case insensitive. */
  SSH_CHARSET_PRINTABLE,

  /* Another relative of ASCII, but instead of letters such as '@'
     there are some like 'A' with acute. Equivalent to ISO 646. */
  SSH_CHARSET_VISIBLE,

  /* US ASCII. Handled as a 7 bits of the Unicode standard. */
  SSH_CHARSET_US_ASCII,

  /* ISO 8859-1:1987, or ISO latin1. Equivalent to the US ASCII. */
  SSH_CHARSET_ISO_8859_1,
  /* ISO 8859-2:1987 character set. */
  SSH_CHARSET_ISO_8859_2,
  /* ISO 8859-3:1988 character set. */
  SSH_CHARSET_ISO_8859_3,
  /* ISO 8859-4:1988 character set. */
  SSH_CHARSET_ISO_8859_4,

  /* ISO-8859-15 character set, a.k.a Latin9, a.k.a Latin0. */
  SSH_CHARSET_ISO_8859_15,

  /* T.61/Teletex string. */
  SSH_CHARSET_T61,

  /* 16 bit Basic Multilingual Plane (BMP), or UCS-2 as in ISO 10646-1. */
  SSH_CHARSET_BMP,

  /* 32 bit Universal Character Set, or UCS-4 as in ISO 10646-1. */
  SSH_CHARSET_UNIVERSAL,

  /* UTF-8 encoding format for UCS-2 and UCS-4. */
  SSH_CHARSET_UTF8
} SshCharset;

/* The size of the 16-bit character set. */
#define SSH_CHARSET_BMP_SIZE 65536

/* Our string type. */
typedef struct SshStrRec *SshStr;

/***** Initialization. */

/* This function makes a character string in given `charset', e.g. the
   input data given in octet array `str' whose length is `str_length'
   is converted into the internal presentation which is returned.

   This function steals the input string. It must no longer be
   referenced directly by the caller.

   The function will return NULL if the given input can not be a
   presenation of string using charset, or if memory allocation for
   the internal presentation fails. */
SshStr
ssh_str_make(SshCharset charset,
             unsigned char *str, size_t str_length);

/* Free a string that is no longer used. */
void ssh_str_free(SshStr str);

/* Get pointer to internal string representation. */
unsigned char *ssh_str_get_data(SshStr in_str, size_t *out_str_length);

/* This function frees the wrapper data structure only, not the
   underlying string. */
void ssh_str_free_wrapper(SshStr str);


/***** Character set operations. */

/* Convert a string to some particular character set. Usually one
   cannot expect to convert a string into character set with less
   characters.  However, the opposite does work. Returns NULL if
   fails. */
SshStr ssh_str_charset_convert(SshStr str, SshCharset charset);

/* Deduce whether one can use the 'charset' to represent this string.
   Returns TRUE if possible.  This function is subject to be removed
   from the library. Use of it should be avoided in applications based
   on toolkit release 4 or later. */
Boolean ssh_str_charset_test(SshStr str, SshCharset charset);

/* Get the charset used for the string internally. */
SshCharset ssh_str_charset_get(SshStr str);

/***** Elementary manipulation. */

/* Duplicate a string. */
SshStr ssh_str_dup(SshStr str);

/* This function returns the length of the given string. The length is
   equivalent to the number of symbols or letters in the string rather
   than the number of octets needed represent it. */






size_t ssh_str_length(SshStr str);


/* Comparison. */
typedef enum
{
  SSH_STR_ORDREL_LT = -1, /* Less than. */
  SSH_STR_ORDREL_EQ = 0,  /* Equal. */
  SSH_STR_ORDREL_GT = 1,  /* Greater than. */
  SSH_STR_ORDREL_IC = 2   /* Incomparable. */
} SshStrOrdRel;

/* Comparison of two strings. Returns an element of the type
   SshStrOrdRel */
SshStrOrdRel ssh_str_cmp(SshStr op1, SshStr op2);


/***** Output conversions. */

/* This function returns the string encoded into a byte sequence. */
unsigned char *ssh_str_get(SshStr str, size_t *str_length);

/* This function returns the string encoded into a byte sequence, and
   transformed by a) taking all the 'unnecessary' whitespace away b)
   making letters lower-case in printable strings. */
unsigned char *ssh_str_get_canonical(SshStr str, size_t *str_length);


#endif /* SSHSTR_H */
