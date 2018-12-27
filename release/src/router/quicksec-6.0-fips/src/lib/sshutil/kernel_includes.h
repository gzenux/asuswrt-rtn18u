/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Common kernel (packet processing engine) include files for various
   platforms.  Some platforms have platform-specific versions of this
   file.  This file is automatically included from sshincludes.h if
   KERNEL is defined.
*/

#ifndef KERNEL_INCLUDES_H
#define KERNEL_INCLUDES_H

#ifdef SSHDIST_PLATFORM_WIN32
# if defined(WINDOWS) || defined(_WINDOWS) || defined(WIN32)
#  error "On Windows machine, you shouldn't need kernel_includes.h."
# endif /* WINDOWS || WIN32 */
#endif /* SSHDIST_PLATFORM_WIN32 */

#ifdef KERNEL
# undef _KERNEL
# define _KERNEL
#endif /* KERNEL */

#include "sshdistdefs.h"
#include "sshconf.h"
#include "toolkit_params.h"

/* Set SIZEOF_* defines to point to kernel definitions of those. BTW,
   on some platforms these might be defined independently from
   configure, so watch out for those. */
#ifndef SIZEOF_INT
# define SIZEOF_INT      KERNEL_SIZEOF_INT
#endif /* SIZEOF_INT */

#ifndef SIZEOF_LONG
# define SIZEOF_LONG     KERNEL_SIZEOF_LONG
#endif /* SIZEOF_LONG */

#ifndef SIZEOF_LONG_LONG
# define SIZEOF_LONG_LONG KERNEL_SIZEOF_LONG_LONG
#endif /* SIZEOF_LONG_LONG */

#ifndef SIZEOF_SHORT
# define SIZEOF_SHORT    KERNEL_SIZEOF_SHORT
#endif /* SIZEOF_SHORT */

#ifndef SIZEOF_VOID_P
# define SIZEOF_VOID_P    KERNEL_SIZEOF_VOID_P
#endif /* SIZEOF_VOID_P */

/* Set HAVE_ */
#ifdef HAVE_KERNEL_SHORT
# define HAVE_SHORT
#endif
#ifdef HAVE_KERNEL_INT
# define HAVE_INT
#endif
#ifdef HAVE_KERNEL_LONG
# define HAVE_LONG
#endif
#ifdef HAVE_KERNEL_LONG_LONG
# define HAVE_LONG_LONG
#endif
#ifdef HAVE_KERNEL_VOID_P
# define HAVE_VOID_P
#endif

typedef unsigned char SshUInt8;         /* At least 8 bits. */
typedef signed char SshInt8;            /* At least 8 bits. */

typedef unsigned short SshUInt16;       /* At least 16 bits. */
typedef short SshInt16;                 /* At least 16 bits. */

#if SIZEOF_LONG == 4
typedef unsigned long SshUInt32;        /* At least 32 bits. */
typedef long SshInt32;                  /* At least 32 bits. */
#else /* SIZEOF_LONG != 4 */
# if SIZEOF_INT == 4
typedef unsigned int SshUInt32;         /* At least 32 bits. */
typedef int SshInt32;                   /* At least 32 bits. */
# else /* SIZEOF_INT != 4 */
#  if SIZEOF_SHORT >= 4
typedef unsigned short SshUInt32;       /* At least 32 bits. */
typedef short SshInt32;                 /* At least 32 bits. */
#  else /* SIZEOF_SHORT < 4 */
#   error "Autoconfig error, your compiler doesn't support any 32 bit type"
#  endif /* SIZEOF_SHORT < 4 */
# endif /* SIZEOF_INT != 4 */
#endif /* SIZEOF_LONG != 4 */

#if SIZEOF_LONG >= 8
typedef unsigned long SshUInt64;
typedef long SshInt64;
# define SSHUINT64_IS_64BITS
# define SSH_C64(x) (x##lu)
# define SSH_S64(x) (x##l)
#else /* SIZEOF_LONG < 8 */
# if SIZEOF_LONG_LONG >= 8
typedef unsigned long long SshUInt64;
typedef long long SshInt64;
#  define SSHUINT64_IS_64BITS
#  define SSH_C64(x) (x##llu)
#  define SSH_S64(x) (x##ll)
# else /* SIZEOF_LONG_LONG < 8 */
/* No 64 bit type; SshUInt64 and SshInt64 will be 32 bits. */
typedef unsigned long SshUInt64;
typedef long SshInt64;
#  define SSH_C64(x) ssh_fatal(ERROR_NO_64_BIT_ON_THIS_SYSTEM)
# endif /* SIZEOF_LONG_LONG < 8 */
#endif /* SIZEOF_LONG < 8 */


#if !(defined (_KERNEL) && defined (__linux__))
# ifndef macintosh
#  include <sys/types.h>
# else /* macintosh */
#  ifdef __MWERKS__
#   include <types.h>
#   include <OpenTransport.h>
#  else /* !__MWERKS__ */
#   error "Don't know how to compile Mac code without CodeWarrior"
#  endif /* !__MWERKS__ */
# endif /* macintosh */
#endif /* !(_KERNEL && __linux__) */

#if defined(_KERNEL) && defined(__linux__)
#   include <linux/types.h>
#endif /* defined(_KERNEL) && defined(__linux__) */

#ifdef HAVE_MACHINE_ENDIAN_H
# include <sys/param.h>
# include <machine/endian.h>
#endif

#ifdef HAVE_ENDIAN_H
#if !defined(__linux__) || !defined(KERNEL)
# include <endian.h>
#endif /* !defined(__linux__) || !defined(KERNEL) */
#endif

#include <stddef.h>


#ifndef _KERNEL
# ifndef macintosh
#  include <sys/types.h>
#  include <sys/stat.h>
# else /* !macintosh */
#  include <stat.h>
# endif /* macintosh */
# include <stdio.h>
# include <ctype.h>
# include <errno.h>
# include <fcntl.h>
# include <assert.h>
# include <signal.h>
# ifdef STDC_HEADERS
#  include <stdlib.h>
#  include <string.h>
# else /* STDC_HEADERS */
#  ifndef HAVE_STRCHR
#   define strchr index
#   define strrchr rindex
#  endif /* HAVE_STRCHR */
char *strchr(), *strrchr();
#  ifndef HAVE_MEMCPY
#   define memcpy(d, s, n) bcopy((s), (d), (n))
#   define memmove(d, s, n) bcopy((s), (d), (n))
#   define memcmp(a, b, n) bcmp((a), (b), (n))
#  endif /* HAVE_MEMCPY */
# endif /* STDC_HEADERS */
#endif /* _KERNEL */

/* stdarg.h is present almost everywhere, and comes with gcc; I am too lazy
   to make things work with both it and varargs. */
#include <stdarg.h>

#ifndef _KERNEL
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif /* HAVE_UNISTD_H */

# ifdef HAVE_PATHS_H
#  include <paths.h>
# endif /* HAVE_PATHS_H */
# ifdef _PATH_VARRUN
#  define PIDDIR _PATH_VARRUN
# else /* _PATH_VARRUN */
#  ifdef HAVE_VAR_RUN
#   define PIDDIR "/var/run"
#  else /* HAVE_VAR_RUN */
#   define PIDDIR "/etc"
#  endif /* HAVE_VAR_RUN */
# endif /* _PATH_VARRUN */

# if defined(HAVE_SYS_TIME_H) && !defined(SCO)
#  include <sys/time.h>
# endif /* HAVE_SYS_TIME_H */
# include <time.h>

/* These are used for initializing the random number generator. */
# ifdef HAVE_GETRUSAGE
#  include <sys/resource.h>
#  ifdef HAVE_RUSAGE_H
#   include <sys/rusage.h>
#  endif /* HAVE_RUSAGE_H */
# endif /* HAVE_GETRUSAGE */

# ifdef HAVE_TIMES
#  include <sys/times.h>
# endif /* HAVE_TIMES */

# ifdef HAVE_PWD_H
#  include <pwd.h>
# endif /* HAVE_PWD_H */

# ifdef HAVE_GRP_H
#  include <grp.h>
# endif /* HAVE_GRP_H */

# ifdef HAVE_DIRENT_H
#  include "dirent.h"
# endif /* HAVE_DIRENT_H */

/* These POSIX macros are not defined in every system. */

# ifndef S_IRWXU
#  define S_IRWXU 00700           /* read, write, execute: owner */
#  define S_IRUSR 00400           /* read permission: owner */
#  define S_IWUSR 00200           /* write permission: owner */
#  define S_IXUSR 00100           /* execute permission: owner */
#  define S_IRWXG 00070           /* read, write, execute: group */
#  define S_IRGRP 00040           /* read permission: group */
#  define S_IWGRP 00020           /* write permission: group */
#  define S_IXGRP 00010           /* execute permission: group */
#  define S_IRWXO 00007           /* read, write, execute: other */
#  define S_IROTH 00004           /* read permission: other */
#  define S_IWOTH 00002           /* write permission: other */
#  define S_IXOTH 00001           /* execute permission: other */
# endif /* S_IRWXU */

# ifndef S_ISUID
#  define S_ISUID 0x800
# endif /* S_ISUID */
# ifndef S_ISGID
#  define S_ISGID 0x400
# endif /* S_ISGID */

# ifndef S_ISDIR
/* NextStep apparently fails to define this. */
#  define S_ISDIR(mode)   (((mode)&(_S_IFMT))==(_S_IFDIR))
# endif
# ifndef _S_IFMT
#  define _S_IFMT 0170000
# endif
# ifndef _S_IFDIR
#  define _S_IFDIR 0040000
# endif
# ifndef _S_IFLNK
#  define _S_IFLNK 0120000
# endif
# ifndef S_ISLNK
#  define S_ISLNK(mode) (((mode)&(_S_IFMT))==(_S_IFLNK))
# endif

# ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
# endif

# ifndef WEXITSTATUS
#  define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
# endif

# ifndef WIFEXITED
#  define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
# endif

# ifdef STAT_MACROS_BROKEN
/* Some systems have broken S_ISDIR etc. macros in sys/stat.h.  Please ask
   your vendor to fix them.  You can then remove the line below, but only
   after you have sent a complaint to your vendor. */
#  error "Macros in sys stat h are broken on your system read sshincludes.h"
# endif /* STAT_MACROS_BROKEN */

# if USE_STRLEN_FOR_AF_UNIX
#  define AF_UNIX_SIZE(unaddr) \
  (sizeof((unaddr).sun_family) + strlen((unaddr).sun_path) + 1)
# else
#  define AF_UNIX_SIZE(unaddr) sizeof(unaddr)
# endif

#endif /* !_KERNEL */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#ifndef macintosh
typedef unsigned int Boolean;
#endif

#ifndef O_BINARY
/* Define O_BINARY for compatibility with Windows. */
# define O_BINARY 0
#endif

#ifdef _KERNEL

int atoi(const char *cp);
# ifndef __linux__
char *strrchr(const char *strchr, int ch);
# endif

# define ssh_xmalloc \
        ssh_fatal(SSH_XMALLOC_IS_FORBIDDEN_USE_SSH_MALLOC_INSTEAD)
# define ssh_xcalloc \
        ssh_fatal(SSH_XCALLOC_IS_FORBIDDEN_USE_SSH_CALLOC_INSTEAD)
# define ssh_xrealloc \
        ssh_fatal(SSH_XREALLOC_IS_FORBIDDEN_USE_SSH_REALLOC_INSTEAD)
# define ssh_xfree \
        ssh_fatal(SSH_XFREE_IS_FORBIDDEN_USE_SSH_FREE_INSTEAD)
# define ssh_xstrdup \
        ssh_fatal(SSH_XSTRDUP_IS_FORBIDDEN_USE_SSH_STRDUP_INSTEAD)
# define ssh_xmemdup \
        ssh_fatal(SSH_XMEMDUP_IS_FORBIDDEN_USE_SSH_MEMDUP_INSTEAD)

#else /* !_KERNEL */

# ifdef index
#  undef index
# endif
# define index(A,B)      ssh_fatal(INDEX_IS_BSDISM_USE_STRCHR_INSTEAD)

# ifdef rindex
#  undef rindex
# endif
# define rindex(A,B)     ssh_fatal(RINDEX_IS_BSDISM_USE_STRRCHR_INSTEAD)

/* Force library to use ssh- memory allocators (they may be implemented
   using zone mallocs, debug-routines or something similar) */
# ifdef malloc
#  undef malloc
# endif
# ifdef calloc
#  undef calloc
# endif
# ifdef realloc
#  undef realloc
# endif
# ifdef free
#  undef free
# endif
# ifdef strdup
#  undef strdup
# endif
# ifdef memdup
#  undef memdup
# endif

# define malloc ssh_fatal(MALLOC_IS_FORBIDDEN_USE_SSH_XKALLOC_INSTEAD)
# define calloc ssh_fatal(CALLOC_IS_FORBIDDEN_USE_SSH_XKALLOC_INSTEAD)
# define realloc ssh_fatal(REALLOC_IS_FORBIDDEN_USE_SSH_XKEALLOC_INSTEAD)
# define free ssh_fatal(FREE_IS_FORBIDDEN_USE_SSH_XKREE_INSTEAD)
# define strdup ssh_fatal(STRDUP_IS_FORBIDDEN_USE_SSH_XKTRDUP_INSTEAD)
# define memdup ssh_fatal(MEMDUP_IS_FORBIDDEN_USE_SSH_XKEMDUP_INSTEAD)

/* The sprintf and vsprintf functions are FORBIDDEN in all SSH code.  This is
   for security reasons - they are the source of way too many security bugs.
   Instead, we guarantee the existence of snprintf and vsnprintf.  These
   should be used instead. */
# ifdef sprintf
#  undef sprintf
# endif
# ifdef vsprintf
#  undef vsprintf
# endif

# define sprintf ssh_fatal(SPRINTF_IS_FORBIDDEN_USE_SSH_SNPRINTF_INSTEAD)
# define vsprintf ssh_fatal(VSPRINTF_IS_FORBIDDEN_USE_SSH_VSNPRINTF_INSTEAD)

# define snprintf ssh_fatal(SNPRINTF_IS_FORBIDDEN_USE_SSH_SNPRINTF_INSTEAD)
# define vsnprintf ssh_fatal(VSNPRINTF_IS_FORBIDDEN_USE_SSH_VSNPRINTF_INSTEAD)

#endif /* _KERNEL */

# include "sshsnprintf.h"

#ifdef macintosh
int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t len);
#endif

#ifdef _KERNEL

/* Platform-specific kernel-mode definitions follow. */

# ifdef SSHDIST_PLATFORM_NETBSD

/********************************* NetBSD ********************************/
#  if defined(__NetBSD__)

#   include <sys/systm.h>
void *memchr(const void *ptr, int ch, size_t len);

#  endif /* defined(__NetBSD__) */
# endif /* SSHDIST_PLATFORM_NETBSD */

# ifdef SSHDIST_PLATFORM_LINUX

/******************************   LINUX       *****************************/
#  if defined(__linux__)

/* Sanity checks about module support and that we are supporting it really  */
#   ifndef MODULE
#    error  "MODULE must be define when compiling for Linux"
#   endif

#   include <linux/string.h>

#ifdef __arm__
/* memcmp() seems to produce wrong results when using >= 0x80 bytes with
 * Linux kernel memcmp() (char substraction) */
#define memcmp ssh_memcmp
extern int ssh_memcmp (const void *, const void *, size_t);
#endif /* __arm__ */

/* memchr seems to be supported only for i386 Linux kernels */
#   ifndef __i386__
#    undef  memchr
#    define memchr  ssh_memchr
extern void * ssh_memchr(const void *, int, size_t);
#   endif /* !__i386 __ */

#  endif /* defined(__linux__) */
/******************************   LINUX (END) *****************************/

# endif /* SSHDIST_PLATFORM_LINUX */

#endif /* _KERNEL */
#endif /* KERNEL_INCLUDES_H */
