/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definitions for SSH types.
*/

#ifndef SSHTYPES_H
#define SSHTYPES_H

#ifndef KERNEL

/** A Boolean type which can take the values TRUE or FALSE */
typedef unsigned int Boolean;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if !defined (__STDC_VERSION__)
#define __STDC_VERSION__ 0
#endif

/* Use the C99 types if available */
#if __STDC_VERSION__ >= 199901L

#include <stdint.h>

#ifndef SSH_TYPES_DEFINED
#define SSH_TYPES_DEFINED
typedef uint8_t    SshUInt8;
typedef uint16_t  SshUInt16;
typedef uint32_t  SshUInt32;
typedef uint64_t  SshUInt64;
typedef int8_t      SshInt8;
typedef int16_t    SshInt16;
typedef int32_t    SshInt32;
typedef int64_t    SshInt64;
#endif /* !SSH_TYPES_DEFINED */

#else /* __STDC_VERSION__ >= 199901L */

#ifndef SSH_TYPES_DEFINED
#define SSH_TYPES_DEFINED



typedef unsigned char   SshUInt8;
typedef unsigned short SshUInt16;
typedef unsigned int   SshUInt32;
typedef unsigned long  SshUInt64;
typedef signed char      SshInt8;
typedef short           SshInt16;
typedef int             SshInt32;
typedef long            SshInt64;
#endif /* !SSH_TYPES_DEFINED */

#endif /* __STDC_VERSION__ >= 199901L */

#endif /* !KERNEL */
#endif /* !SSHTYPES_H */
