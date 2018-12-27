/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_conv.h
*/

#ifndef SSHADT_CONV_I_H_INCLUDED
#define SSHADT_CONV_I_H_INCLUDED

#include "sshadt.h"


/******************************************** Convenience callbacks: General */

/* destroy by simply freeing the object */
void ssh_adt_callback_destroy_free(void *obj, void *context);

/* destroy by freeing, but leave NULL objects untouched */
void ssh_adt_callback_destroy_free_null(void *obj, void *context);


/******************************************** Convenience callbacks: Strings */

/* call to strcmp */
int ssh_adt_callback_compare_str(const void *obj1, const void *obj2,
                                 void *ctx);

/* call to strdup */
void *ssh_adt_callback_duplicate_str(const void *obj, void *ctx);

/* Iteration over a string with some shifts and additions. */
SshUInt32 ssh_adt_callback_hash_str(const void *obj, void *ctx);


/******************************************* Convenience callbacks: Integers */

/* compare objects that are integers and not void pointers */
int ssh_adt_callback_compare_int(const void *obj1, const void *obj2,
                                 void *context);

/* returns '*(SshUInt32 *)obj' */
SshUInt32 ssh_adt_callback_hash_int(const void *obj, void *ctx);


/*************************************************** A Generic Hash Callback */

/* The following macro takes a function name and a size and an offset
   in bytes, and generates a function of that name that hashes
   objects.  The fraction of the object that will be taken into
   account by the hash function is determined by size and offset.  */

#define SSH_ADT_MAKE_HASH_CBK(name, length, offset)                           \
SshUInt32 name(const void *__obj, void *__context)                            \
{                                                                             \
  const size_t __n = length;                                                  \
  unsigned char *__s;                                                         \
  int __i;                                                                    \
  SshUInt32 __hash = 0;                                                       \
                                                                              \
  __s = (unsigned char *)__obj + offset;                                      \
                                                                              \
  for (__i = 0; __i < (__n & 3); __i++)                                       \
    __hash = (__hash << 8) | *(__s++);                                        \
                                                                              \
  if (__i)                                                                    \
    __hash = __hash ^ (__hash << 9) ^ (__hash << 15) ^ (__hash >> 17);        \
                                                                              \
  for (__i = 0; __i < (__n >> 2); __i++)                                      \
    {                                                                         \
      __hash = __hash ^ *__s;          __s++;                                 \
      __hash = __hash ^ (*__s << 8);   __s++;                                 \
      __hash = __hash ^ (*__s << 16);  __s++;                                 \
      __hash = __hash ^ (*__s << 24);  __s++;                                 \
                                                                              \
      __hash = (__hash << 3) ^ (__hash >> 17);                                \
      __hash = __hash ^ (__hash >> 8);                                        \
      __hash = (__hash << 4) ^ (__hash >> 16);                                \
      __hash = __hash ^ (__hash >> 16);                                       \
      __hash = (__hash << 5) ^ (__hash >> 15);                                \
      __hash = __hash ^ (__hash >> 24);                                       \
    }                                                                         \
                                                                              \
  return __hash;                                                              \
}


#endif /* !SSHADT_CONV_I_H_INCLUDED */
