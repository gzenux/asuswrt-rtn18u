/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to system-specific substitute functions.
*/

#ifndef ICEPT_ATTACH_H
#define ICEPT_ATTACH_H

typedef enum
{
  /* Terminates the list. */
  SSH_ATTACH_END,

  /* The original function is to be replaced by the replacement function.
     A replacement function of this type has full access to the original
     arguments. */
  SSH_ATTACH_REPLACE,

  /* The replacement function is to be called before the original function;
     the original function will also be called.  A replacement function
     of this type cannot access the original arguments. */
  SSH_ATTACH_BEFORE,

  /* The replacement function is to be called after the original function;
     the original function will also be called.  A replacement function
     of this type cannot access the original arguments. */
  SSH_ATTACH_AFTER
} SshAttachType;

typedef struct
{
  /* Specifies the type of substitution. */
  SshAttachType type;

  /* Specifies the address of the original function. */
  void *original;

  /* Specifies the address of the replacement function that will be called
     instead of, after, or before the original. */
  void *substitute;

  /* The fields below are not to be used or inspected by the caller,
     they are internal to the attach implementation. */

#ifdef __ppc__
  size_t len;
  unsigned char scratch[256];

#else /* __ppc__ */
  /* Always consider as default the __i386__. */
  /* This is actually __i386__ case. */

  /* Scratch space to be used by the attach implementation.  This is used
     and modified by the implementation of the attach/detach functions. */
  unsigned char scratch[100];
#endif /* __ppc__ */
} SshAttachRec;

/* Attaches any defined substitutions for this system. */
void ssh_attach_substitutions(void);

/* Detaches any defined substitutions for this system. */
void ssh_detach_substitutions(void);

/************ Functions implemented by substitution modules ***************/

/* This function should be implemented by the substitution module.  This
   returns the array of substitutions to make for this platform.  The array
   is not freed.  This function should return the same array (with the
   scratch space kept) on every call; preferably the array should be in
   static storage. */
SshAttachRec *ssh_get_substitutions(void);

#endif /* ICEPT_ATTACH_H */
