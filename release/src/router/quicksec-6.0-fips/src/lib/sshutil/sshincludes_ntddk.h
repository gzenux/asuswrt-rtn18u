/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows NT -specific kernel mode environment for IPSEC engine
*/

#ifndef SSHINCLUDES_NTDDK_H
#define SSHINCLUDES_NTDDK_H

#if !defined(WINNT) || !defined(KERNEL)
#error "This file is for Windows NT kernel-mode builds only!"
#endif

#include "sshwinconf.h"
#include "toolkit_params.h"

#pragma warning( push,3 )
/* Basic Windows NT kernel definitions */
#include <ntddk.h>
#include <stdarg.h>
#include <tchar.h>
#pragma warning( pop )

#ifndef __cplusplus
/* Newer Windows DDKs define 'try', 'except', 'finally' and 'leave' keywords
   (i.e. C++ exception handling) also for C compiler but we don't want this
   to happen. (See ..._IS_CPLUSPLUS_RESERVED_WORD macros in sshincludes.h) */
#undef try
#undef except
#undef finally
#undef leave
#endif /* __cplusplus */

/* Not relevant in NT kernel modules */
#define DLLEXPORT
#define DLLCALLCONV

/* Basic SSH compilation environment definitions */

typedef unsigned int Boolean;

typedef unsigned char SshUInt8;         /* At least 8 bits. */
typedef signed char SshInt8;            /* At least 8 bits. */

typedef unsigned short SshUInt16;       /* At least 16 bits. */
typedef short SshInt16;                 /* At least 16 bits. */

typedef unsigned int SshUInt32;         /* At least 32 bits. */
typedef int SshInt32;                   /* At least 32 bits. */

typedef unsigned __int64 SshUInt64;
typedef __int64 SshInt64;

#define SIZEOF_SHORT        2
#define SIZEOF_INT          4
#define SIZEOF_LONG         4
#define SIZEOF_LONG_LONG    8

#if defined(_WIN64)
#define SIZEOF_VOID_P       8
#define SIZEOF_SIZE_T       8
#else
#define SIZEOF_VOID_P       4
#define SIZEOF_SIZE_T       4
#endif /* _WIN64 */

#define SSHUINT64_IS_64BITS
#define SSH_C64(x) (x)
#define SSH_S64(x) (x)

#define HAVE_SHORT
#define HAVE_INT
#define HAVE_LONG
#define HAVE_LONG_LONG

#ifdef SSHDIST_MSCAPI
/* If building with MSCAPI support on Windows CE indicate that we have
   alternative versions of AES, DES and 3DES algorithms. */
#ifdef WITH_MSCAPI
#endif /* WITH_MSCAPI */
#endif /* SSHDIST_MSCAPI */


/*
  NT kernel includes some string-related routines, but prototypes
  seem to be missing from DDK headers or names are non-ANSI.
*/
#define HAVE_STRNCASECMP
#define strncasecmp   _strnicmp

int __cdecl atoi(const char *);

#if defined(_WIN64)

/* Undefine RtlMoveMemory macro and force linking to real function */
#undef RtlMoveMemory
NTSYSAPI VOID
RtlMoveMemory(PVOID destination, const VOID *source, SIZE_T length);

#define memmove   RtlMoveMemory
#endif /* _WIN64 */

/* Enable IPv6 support by default */
#define WITH_IPV6

#ifndef inline
#define inline __inline
#endif /* inline */

#if defined SSHDIST_IPSEC_VIRTUAL_ADAPTERS
#ifndef INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
#define INTERCEPTOR_HAS_VIRTUAL_ADAPTERS
#endif /* INTERCEPTOR_HAS_VIRTUAL_ADAPTERS */
#endif /* SSHDIST_IPSEC_VIRTUAL_ADAPTERS */

#endif /* SSHINCLUDES_NTDDK_H */
