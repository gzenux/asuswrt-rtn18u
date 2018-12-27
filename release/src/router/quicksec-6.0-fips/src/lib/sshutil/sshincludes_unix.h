/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common definitions for various Unix platforms, extracted
   from sshincludes.h (which was becoming messy).
*/

#ifndef SSHINCLUDES_UNIX_H
#define SSHINCLUDES_UNIX_H

#include <sys/types.h>
#include <sys/stat.h>
#ifndef VXWORKS
#include <sys/param.h>
#endif /* VXWORKS */

#include "sshconf.h"
#include "toolkit_params.h"

#define DLLCALLCONV
#define DLLEXPORT

/* Set SIZEOF_* defines to point to usermode definitions of those */
#define SIZEOF_INT       USERMODE_SIZEOF_INT
#define SIZEOF_LONG      USERMODE_SIZEOF_LONG
#define SIZEOF_LONG_LONG USERMODE_SIZEOF_LONG_LONG
#define SIZEOF_SHORT     USERMODE_SIZEOF_SHORT
#define SIZEOF_VOID_P    USERMODE_SIZEOF_VOID_P

typedef unsigned char SshUInt8;         /* At least 8 bits. */
typedef signed char SshInt8;            /* At least 8 bits. */

typedef unsigned short SshUInt16;       /* At least 16 bits. */
typedef short SshInt16;                 /* At least 16 bits. */

#if SIZEOF_LONG == 4
typedef unsigned long SshUInt32;        /* At least 32 bits. */
typedef long SshInt32;                  /* At least 32 bits. */
#else
#if SIZEOF_INT == 4
typedef unsigned int SshUInt32;         /* At least 32 bits. */
typedef int SshInt32;                   /* At least 32 bits. */
#else
#if SIZEOF_SHORT >= 4
typedef unsigned short SshUInt32;       /* At least 32 bits. */
typedef short SshInt32;                 /* At least 32 bits. */
#else
#error "Autoconfig error, your compiler doesn't support any 32 bit type"
#endif
#endif
#endif

/* Transcribe the HAVE_USERMODE_xxx to HAVE_xxx versions. */
#ifdef HAVE_USERMODE_INT
#define HAVE_INT
#endif /* HAVE_USERMODE_INT */
#ifdef HAVE_USERMODE_LONG
#define HAVE_LONG
#endif /* HAVE_USERMODE_LONG */
#ifdef HAVE_USERMODE_LONG_LONG
#define HAVE_LONG_LONG
#endif /* HAVE_USERMODE_LONG_LONG */
#ifdef HAVE_USERMODE_SHORT
#define HAVE_SHORT
#endif /* HAVE_USERMODE_SHORT */
#ifdef HAVE_USERMODE_VOID_P
#define HAVE_VOID_P
#endif /* HAVE_USERMODE_VOID_P */

#if SIZEOF_LONG >= 8
typedef unsigned long SshUInt64;
typedef long SshInt64;
#define SSHUINT64_IS_64BITS
#define SSH_C64(x) (x##lu)
#define SSH_S64(x) (x##l)
#else /* SIZEOF_LONG < 8 */
#if defined(HAVE_LONG_LONG) && (SIZEOF_LONG_LONG >= 8)
typedef unsigned long long SshUInt64;
typedef long long SshInt64;
#define SSHUINT64_IS_64BITS
#define SSH_C64(x) (x##llu)
#define SSH_S64(x) (x##ll)
#else /* !HAVE_LONG_LONG || SIZEOF_LONG_LONG < 8 */
/* No 64 bit type; SshUInt64 and SshInt64 will be 32 bits. */
typedef unsigned long SshUInt64;
typedef long SshInt64;
#define SSH_C64(x) ssh_fatal(ERROR_NO_64_BIT_ON_THIS_SYSTEM)
#endif /* !HAVE_LONG_LONG || SIZEOF_LONG_LONG < 8 */
#endif /* SIZEOF_LONG < 8 */

/* Data type for file descriptors and sockets on unix. */
typedef int SshIOHandle;

#include <sys/types.h>
#ifdef HAVE_MACHINE_ENDIAN_H
#include <sys/param.h>
#include <machine/endian.h>
#endif /* HAVE_MACHINE_ENDIAN_H */

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif /* HAVE_ENDIAN_H */

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#else /* STDC_HEADERS */

/* stdarg.h is present almost everywhere, and comes with gcc; I am too lazy
   to make things work with both it and varargs. */
#include <stdarg.h>
#ifndef HAVE_STRCHR
#define strchr index
#define strrchr rindex
#endif
char *strchr(), *strrchr();
#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy((s), (d), (n))
#define memmove(d, s, n) bcopy((s), (d), (n))
#define memcmp(a, b, n) bcmp((a), (b), (n))
#endif
#endif /* STDC_HEADERS */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif /* HAVE_PATHS_H */
#ifdef _PATH_VARRUN
#define PIDDIR _PATH_VARRUN
#else /* _PATH_VARRUN */
#ifdef HAVE_VAR_RUN
#define PIDDIR "/var/run"
#else /* HAVE_VAR_RUN */
#define PIDDIR "/etc"
#endif /* HAVE_VAR_RUN */
#endif /* _PATH_VARRUN */

#if defined(HAVE_SYS_TIME_H) && !defined(SCO)
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#ifdef VXWORKS
#undef _POSIX_DELAYTIMER_MAX /* Remove redefinition warning */
#endif /* VXWORKS */
#include <time.h>
#ifdef VXWORKS
#undef _POSIX_DELAYTIMER_MAX /* Remove redefinition warning */
#endif /* VXWORKS */

/* These are used for initializing the random number generator. */
#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
#ifdef HAVE_RUSAGE_H
#include <sys/rusage.h>
#endif /* HAVE_RUSAGE_H */
#endif /* HAVE_GETRUSAGE */


#ifdef HAVE_TIMES
#include <sys/times.h>
#endif /* HAVE_TIMES */

#ifdef HAVE_UTIME
#include <utime.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */

#ifdef HAVE_GRP_H
#include <grp.h>
#endif /* HAVE_GRP_H */

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif /* HAVE_DIRENT_H */

/* These POSIX macros are not defined in every system. */

#ifndef S_IRWXU
#define S_IRWXU 00700           /* read, write, execute: owner */
#define S_IRUSR 00400           /* read permission: owner */
#define S_IWUSR 00200           /* write permission: owner */
#define S_IXUSR 00100           /* execute permission: owner */
#define S_IRWXG 00070           /* read, write, execute: group */
#define S_IRGRP 00040           /* read permission: group */
#define S_IWGRP 00020           /* write permission: group */
#define S_IXGRP 00010           /* execute permission: group */
#define S_IRWXO 00007           /* read, write, execute: other */
#define S_IROTH 00004           /* read permission: other */
#define S_IWOTH 00002           /* write permission: other */
#define S_IXOTH 00001           /* execute permission: other */
#endif /* S_IRWXU */

#ifndef S_ISUID
#define S_ISUID 0x800
#endif /* S_ISUID */
#ifndef S_ISGID
#define S_ISGID 0x400
#endif /* S_ISGID */

#ifndef S_ISDIR
/* NextStep apparently fails to define this. */
#define S_ISDIR(mode)   (((mode)&(_S_IFMT))==(_S_IFDIR))
#endif
#ifndef _S_IFMT
#define _S_IFMT 0170000
#endif
#ifndef _S_IFDIR
#define _S_IFDIR 0040000
#endif
#ifndef _S_IFLNK
#define _S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) (((mode)&(_S_IFMT))==(_S_IFLNK))
#endif

/* Some systems (Solaris, at least) fail to define this in
   <sys/param.h>. */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif /* MAXHOSTNAMELEN */

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif

#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef STAT_MACROS_BROKEN
/* Some systems have broken S_ISDIR etc. macros in sys/stat.h.  Please ask
   your vendor to fix them.  You can then remove the line below, but only
   after you have sent a complaint to your vendor. */
#error "Warning macros in sys stat h are broken read sshincludes unix h"
#endif /* STAT_MACROS_BROKEN */

#if USE_STRLEN_FOR_AF_UNIX
#define AF_UNIX_SIZE(unaddr) \
  (ssh_socklen_t) (sizeof((unaddr).sun_family) + strlen((unaddr).sun_path) + 1)
#else
#define AF_UNIX_SIZE(unaddr) (ssh_socklen_t) sizeof(unaddr)
#endif


#ifndef O_BINARY
/* Define O_BINARY for compatibility with Windows. */
#define O_BINARY 0
#endif

#include "sshsnprintf.h"

#ifdef HAVE_USLEEP
#define ssh_sleep(secs, usecs) \
  do { \
    if ((secs) > 0) sleep((secs)); \
    SSH_ASSERT((usecs) < 1000000); \
    usleep((usecs)); \
} while (0)
#else /* HAVE_USLEEP */
#define ssh_sleep(secs, usecs)    sleep((secs))
#endif /* HAVE_USLEEP */

#ifdef __SUNPRO_C
#pragma error_messages (off,E_END_OF_LOOP_CODE_NOT_REACHED)
#endif /* __SUNPRO_C */

#ifdef __SUNPRO_C
#pragma error_messages (off,E_END_OF_LOOP_CODE_NOT_REACHED)
#endif /* __SUNPRO_C */

#endif /* SSHINCLUDES_UNIX_H */
