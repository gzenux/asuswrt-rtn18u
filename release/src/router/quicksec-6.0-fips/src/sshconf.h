/**
   @copyright
   Copyright (c) 2010 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Platform description macros.

   @description

   Definitions describing library features and integer type properties
   on UNIX platforms. These definitions are derived from built-in
   compiler macros and other macros defined by particular toolchains.
*/

#if defined(__unix) || defined(__unix__) || defined(__linux__)

/* Generic UNIX platform features. */

#define HAVE_CHMOD
#define HAVE_CHOWN
#define HAVE_CLOCK
#define HAVE_DIRENT_H
#define HAVE_DLCLOSE
#define HAVE_DLFCN_H
#define HAVE_DLOPEN
#define HAVE_DLSYM
#define HAVE_ENDSERVENT
#define HAVE_EXTERNAL_TIMEZONE
#define HAVE_FCHMOD
#define HAVE_FCHOWN
#define HAVE_FSYNC
#define HAVE_GETENV
#define HAVE_GETEUID
#define HAVE_GETGID
#define HAVE_GETGRGID
#define HAVE_GETHOSTBYNAME2
#define HAVE_GETHOSTNAME
#define HAVE_GETOPT
#define HAVE_GETPASS
#define HAVE_GETPGRP
#define HAVE_GETPID
#define HAVE_GETPPID
#define HAVE_GETPWUID
#define HAVE_GETRUSAGE
#define HAVE_GETSERVBYNAME
#define HAVE_GETSERVBYPORT
#define HAVE_GETTIMEOFDAY
#define HAVE_GETUID
#define HAVE_GRP_H
#define HAVE_INET_ATON
#define HAVE_KERNEL_INT
#define HAVE_KERNEL_LONG
#define HAVE_KERNEL_LONG_LONG
#define HAVE_KERNEL_SHORT
#define HAVE_KERNEL_VOID_P
#define HAVE_KEY_SECRETKEY_IS_SET
#define HAVE_LIMITS_H
#define HAVE_LOCALTIME
#define HAVE_LOCKF
#define HAVE_LSTAT
#define HAVE_MEMCPY
#define HAVE_MEMSET
#define HAVE_MPROTECT
#define HAVE_NANOSLEEP
#define HAVE_NETINET_IN_H
#define HAVE_NETINET_IN_SYSTM_H
#define HAVE_NO_SYMBOL_UNDERSCORE
#define HAVE_PATHS_H
#define HAVE_POLL
#define HAVE_PUTENV
#define HAVE_PWD_H
#define HAVE_RANDOM
#define HAVE_SELECT
#define HAVE_SETSID
#define HAVE_SIGNAL
#define HAVE_SLEEP
#define HAVE_SOCKADDR_IN6_SCOPE_ID
#define HAVE_SOCKADDR_IN6_STRUCT
#define HAVE_SOCKLEN_T
#define HAVE_STRCASECMP
#define HAVE_STRCHR
#define HAVE_STRERROR
#define HAVE_STRNCASECMP
#define HAVE_SYS_IOCTL_H
#define HAVE_SYS_POLL_H
#define HAVE_SYS_SELECT_H
#define HAVE_SYS_TIME_H
#define HAVE_SYS_UN_H
#define HAVE_SYS_UTSNAME_H
#define HAVE_SYS_WAIT_H
#define HAVE_TERMIOS_H
#define HAVE_TIMES
#define HAVE_TM_GMTOFF_IN_STRUCT_TM
#define HAVE_TM_ISDST_IN_STRUCT_TM
#define HAVE_UNAME
#define HAVE_UNISTD_H
#define HAVE_USERMODE_INT
#define HAVE_USERMODE_LONG
#define HAVE_USERMODE_LONG_LONG
#define HAVE_USERMODE_SHORT
#define HAVE_USERMODE_VOID_P
#define HAVE_USLEEP
#define HAVE_UTIME
#define HAVE_VAR_RUN

/* Pthread support */
#if defined(_REENTRANT)
#define HAVE_THREADS
#define HAVE_PTHREADS
#endif /* defined(_REENTRANT) */

/* Enable platform crypto on OCTEON */

#if defined(__OCTEON__)
#define HAVE_3DES
#define HAVE_AES
#define HAVE_SHA
#define HAVE_MD5
#endif /* defined(__OCTEON__) */

/* Hardware accelerated algorithm set for tilegx */

#if defined(__tilegx__)
#define TGX_ALGORITHMS
#define TGX_PACKET_LIMIT
#endif /* defined(__tilegx__) */

/* Memory debugging support */

#if defined(__linux__)
#define HAVE_GDBM_H
#define HAVE_GDBM_OPEN
#define HAVE_LIBC_STACK_END
#define HAVE_LIBGDBM
#else /* defined(__linux__) */
#define HAVE_DBM_OPEN
#define HAVE_NDBM_H
#endif

/* Miscellaneous. */

#define RETSIGTYPE void
#define STDC_HEADERS
#define WITH_IPV6
#define WITH_RSA
#define WITH_IKE

/* Sizes of integer types */

#define KERNEL_SIZEOF_SHORT 2
#define USERMODE_SIZEOF_SHORT 2
#define KERNEL_SIZEOF_INT 4
#define USERMODE_SIZEOF_INT 4
#define KERNEL_SIZEOF_LONG_LONG 8
#define USERMODE_SIZEOF_LONG_LONG 8

#ifdef __LP64__
#define KERNEL_SIZEOF_LONG 8
#define USERMODE_SIZEOF_LONG 8
#define KERNEL_SIZEOF_SIZE_T 8
#define USERMODE_SIZEOF_SIZE_T 8
#define KERNEL_SIZEOF_VOID_P 8
#define USERMODE_SIZEOF_VOID_P 8
#else
#define KERNEL_SIZEOF_LONG 4
#define USERMODE_SIZEOF_LONG 4
#define KERNEL_SIZEOF_SIZE_T 4
#define USERMODE_SIZEOF_SIZE_T 4
#define KERNEL_SIZEOF_VOID_P 4
#define USERMODE_SIZEOF_VOID_P 4
#endif

/* Stack size */
#if defined(__linux__) && defined(__KERNEL__)

#ifdef CONFIG_4KSTACKS
#ifndef MINIMAL_STACK
#define MINIMAL_STACK
#endif /* MINIMAL_STACK */
#endif /* CONFIG_4KSTACKS */

#endif /* defined(__linux__) && defined(__KERNEL__) */

/* Byte order */

#if defined(__linux__) && defined(__KERNEL__)

#include <asm/byteorder.h>

#if defined(__BIG_ENDIAN)
#define WORDS_BIGENDIAN
#elif !defined(__LITTLE_ENDIAN)
#error cannot determine byte order
#endif

#elif defined(__linux__)

#include <endian.h>

#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
#define WORDS_BIGENDIAN
#elif __BYTE_ORDER != __LITTLE_ENDIAN
#error cannot determine byte order
#endif
#else
#error cannot determine byte order
#endif

#else /* !defined(__linux__) */

#include <sys/endian.h>

#ifdef _BYTE_ORDER
#if _BYTE_ORDER == _BIG_ENDIAN
#define WORDS_BIGENDIAN
#elif _BYTE_ORDER != _LITTLE_ENDIAN
#error cannot determine byte order
#endif
#else
#error cannot determine byte order
#endif

#endif /* !defined(__linux__) */

#elif defined(__vxworks)

/* VxWorks 5.5.1/6.1 */

#define HAVE_DIRENT_H
#define HAVE_KERNEL_INT
#define HAVE_KERNEL_LONG
#define HAVE_KERNEL_LONG_LONG
#define HAVE_KERNEL_SHORT
#define HAVE_KERNEL_VOID_P
#define HAVE_LIMITS_H
#define HAVE_NETINET_IN_H
#define HAVE_NETINET_IN_SYSTM_H
#define HAVE_NO_SYMBOL_UNDERSCORE
#define HAVE_SOCKADDR_IN6_SCOPE_ID
#define HAVE_SOCKADDR_IN6_STRUCT
#define HAVE_SOCKLEN_T
#define HAVE_SYS_IOCTL_H
#define HAVE_SYS_WAIT_H
#define HAVE_TM_ISDST_IN_STRUCT_TM
#define HAVE_UNISTD_H
#define HAVE_USERMODE_INT
#define HAVE_USERMODE_LONG
#define HAVE_USERMODE_LONG_LONG
#define HAVE_USERMODE_SHORT
#define HAVE_USERMODE_VOID_P
#define HAVE_VAR_RUN
#define KERNEL_SIZEOF_INT 4
#define KERNEL_SIZEOF_LONG 4
#define KERNEL_SIZEOF_LONG_LONG 8
#define KERNEL_SIZEOF_SHORT 2
#define KERNEL_SIZEOF_SIZE_T 4
#define KERNEL_SIZEOF_VOID_P 4

#define USERMODE_SIZEOF_INT 4
#define USERMODE_SIZEOF_LONG 4
#define USERMODE_SIZEOF_LONG_LONG 8
#define USERMODE_SIZEOF_SHORT 2
#define USERMODE_SIZEOF_SIZE_T 4
#define USERMODE_SIZEOF_VOID_P 4

#define RETSIGTYPE void
#define STDC_HEADERS
#define WITH_IPV6
#define WITH_RSA

#elif defined(__mips) && (__mips == 64)

/* Non-unix 64bit MIPS */

#define KERNEL_SIZEOF_SHORT 2
#define USERMODE_SIZEOF_SHORT 2
#define KERNEL_SIZEOF_INT 4
#define USERMODE_SIZEOF_INT 4
#define KERNEL_SIZEOF_LONG_LONG 8
#define USERMODE_SIZEOF_LONG_LONG 8

#define KERNEL_SIZEOF_LONG 8
#define USERMODE_SIZEOF_LONG 8
#define KERNEL_SIZEOF_SIZE_T 8
#define USERMODE_SIZEOF_SIZE_T 8
#define KERNEL_SIZEOF_VOID_P 8
#define USERMODE_SIZEOF_VOID_P 8

#endif /* defined(__mips) && (__mips == 64) */

#if 0
/* Disabled because compilers do not support the render function usage (%@). */
#define __ssh_printf_attribute__(x) __attribute__ (x)
#else
#define __ssh_printf_attribute__(x)
#endif

#define __ssh_noreturn__            __attribute__ ((noreturn))
#define __ssh_unused__              __attribute__ ((unused))


