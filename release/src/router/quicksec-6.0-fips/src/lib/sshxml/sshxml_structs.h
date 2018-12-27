/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal structure definitions (which are shown only to allow
   inlining them into structures and for allocating them from the
   stack).
*/

#ifndef SSHXML_STRUCTS_H
#define SSHXML_STRUCTS_H

#ifndef SSHXML_H
#error "Do not include sshxml_structs.h, include the sshxml.h instead"
#endif /* not SSHXML_H */

/* ************************* Internal structures ****************************/

/* The structures are declared here to allow allocation from stack or
   from pre-allocated structures.  You must not modify or refer any of
   the fields directly. */

/** Context data for an attribute value enumeration. */
struct SshXmlAttrEnumCtxRec
{
  /** The value of the attribute. */
  const unsigned char *value;
  size_t value_len;

  /** The type of the enumeration. */
  SshXmlAttrEnumType type;

  /** Enumeration position in the value. */
  size_t pos;

  /** The input was not correcly formatted UTF-8. */
  Boolean invalid;
};

#endif /* not SSHXML_STRUCTS_H */
