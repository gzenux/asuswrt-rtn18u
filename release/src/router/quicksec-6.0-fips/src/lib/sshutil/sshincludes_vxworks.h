/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshincludes_vxworks.h
*/

#ifndef SSHINCLUDES_VXWORKS_H
#define SSHINCLUDES_VXWORKS_H

#include <vxWorks.h>
#include <ioLib.h>
#include <selectLib.h>
#include <string.h>
#include <dirent.h>

/* sp() */
#include <usrLib.h>

/* shutdown(), setsockopt(), socket(), bind(), connect(), recvfrom(), send(),
   sendto() */
#include <sockLib.h>

#ifdef VIRTUAL_STACK
#include <wrn/coreip/net/if.h>
#include <wrn/coreip/net/if_var.h>
#include <wrn/coreip/netinet/vsData.h>
#include <wrn/coreip/netinet/vsLib.h>
#include <wrn/coreip/vs/vsIf.h>
#include <wrn/coreip/netinet/vsNetCore.h>
#endif /* VIRTUAL_STACK */

#include "sshconf.h"
#include "toolkit_params.h"

#if 1
/* If the VxWorks target architecture does not support 64 bit integers
   change this to correct defines that the configure script did not
   recognize correctly. The configure script cannot detect sizes of
   various data types because we are cross compiling and cannot
   execute resulting executables. NOTE that the usage of 64 bit
   integers in the SSH code need to be checked/modified after the
   changes have been made here. */

/* For VxWorks 5.4 we disable long long */
#ifndef _WRS_VXWORKS_5_X
#undef HAVE_USERMODE_LONG_LONG
#undef HAVE_KERNEL_LONG_LONG
#endif /* _WRS_VXWORKS_5_X */

#undef USERMODE_SIZEOF_INT
#undef USERMODE_SIZEOF_LONG
#undef USERMODE_SIZEOF_LONG_LONG
#undef USERMODE_SIZEOF_SHORT
#undef USERMODE_SIZEOF_VOID_P

#define USERMODE_SIZEOF_INT       4
#define USERMODE_SIZEOF_LONG      4
#define USERMODE_SIZEOF_LONG_LONG 8
#define USERMODE_SIZEOF_SHORT     2
#define USERMODE_SIZEOF_VOID_P    4

#endif /* 1 */

#ifndef HAVE_INET_ATON
#define HAVE_INET_ATON 1
#endif

#ifndef HAVE_SIGNAL
#define HAVE_SIGNAL 1
#endif

#ifndef HAVE_STRCHR
#define HAVE_STRCHR 1
#endif

#ifndef HAVE_STRERROR
#define HAVE_STRERROR 1
#endif

#ifndef HAVE_FSTAT
#define HAVE_FSTAT 1
#endif

#ifndef HAVE_SELECT
#define HAVE_SELECT 1
#endif

/* I960 defines */
#ifndef HAVE_MEMCPY
#define HAVE_MEMCPY 1
#endif

#ifndef HAVE_NETINET_IN_SYSTM_H
#define HAVE_NETINET_IN_SYSTM_H
#endif

#undef HAVE_LASTLOG

#if (CPU_FAMILY==ARM)
#undef PPC
#endif /* (CPU_FAMILY==ARM) */

#if (CPU==SH7750)
#undef PPC
#endif /* (CPU==SH7750) */

#if (CPU_FAMILY==I960)
#undef PPC
#endif /* (CPU_FAMILY==I960) */

/* tell sshd2 to disable X11 features for VxWorks */
#define X_DISPLAY_MISSING 1

/* In VxWorks there is no kernel mode memory, so we use the same
   "user-mode" memory pool for the SSH IPSEC engine */
#undef SSHMALLOC_H

#include "sshincludes_unix.h"

/* We use the VxWorks native define */
#undef MAXHOSTNAMELEN

#include <inetLib.h>
#include <hostLib.h>
#include <stdarg.h>
#include <taskLib.h>





#define getpid() taskIdSelf()

/* main is defined by command line flag -Dmain=vxmain */
#ifdef main
#undef main
#endif /* main */







#define main testMain
#define show testShow

/* VxWorks mkdir does not support mode_t mode argument */
#define mkdir(x,y) mkdir((x))

/* These structures are missing from VxWorks */
struct group {
  char *gr_name;          /* the name of the group */
  char *gr_passwd;        /* the encrypted group password */
  gid_t gr_gid;           /* the numerical group ID */
  char **gr_mem;          /* vector of pointers to member names */
};

struct passwd {
  char *pw_name;      /* user's login name */
  char *pw_passwd;    /* no longer used */
  uid_t pw_uid;       /* user's uid */
  gid_t pw_gid;       /* user's gid */
  char *pw_age;       /* not used */
  char *pw_comment;   /* not used */
  char *pw_gecos;     /* typically user's full name */
  char *pw_dir;       /* user's home dir */
  char *pw_shell;     /* user's login shell */
};


/* Defines for sshd2 */
#define WTERMSIG(stat)          ((int)((stat)&0x7F))
#define WIFSTOPPED(stat)        ((int)((stat)&0xFF) == 0177 && \
                                    (int)((stat)&0xFF00) != 0)
/*
 *  Facility codes from syslog.h
 */
#define LOG_KERN        (0<<3)  /* kernel messages */
#define LOG_USER        (1<<3)  /* random user-level messages */
#define LOG_MAIL        (2<<3)  /* mail system */
#define LOG_DAEMON      (3<<3)  /* system daemons */
#define LOG_AUTH        (4<<3)  /* security/authorization messages */
#define LOG_SYSLOG      (5<<3)  /* messages generated internally by syslogd */
#define LOG_LPR         (6<<3)  /* line printer subsystem */
#define LOG_NEWS        (7<<3)  /* netnews subsystem */
#define LOG_UUCP        (8<<3)  /* uucp subsystem */
#define LOG_CRON        (15<<3) /* cron/at subsystem */
/* other codes through 15 reserved for system use */
#define LOG_LOCAL0      (16<<3) /* reserved for local use */
#define LOG_LOCAL1      (17<<3) /* reserved for local use */
#define LOG_LOCAL2      (18<<3) /* reserved for local use */
#define LOG_LOCAL3      (19<<3) /* reserved for local use */
#define LOG_LOCAL4      (20<<3) /* reserved for local use */
#define LOG_LOCAL5      (21<<3) /* reserved for local use */
#define LOG_LOCAL6      (22<<3) /* reserved for local use */
#define LOG_LOCAL7      (23<<3) /* reserved for local use */

#define LOG_NFACILITIES  24     /* maximum number of facilities */
#define LOG_FACMASK      0x03f8 /* mask to extract facility part */

/*
 *  Priorities (these are ordered) from syslog.h
 */
#define LOG_EMERG        0      /* system is unusable */
#define LOG_ALERT        1      /* action must be taken immediately */
#define LOG_CRIT         2      /* critical conditions */
#define LOG_ERR          3      /* error conditions */
#define LOG_WARNING      4      /* warning conditions */
#define LOG_NOTICE       5      /* normal but signification condition */
#define LOG_INFO         6      /* informational */
#define LOG_DEBUG        7      /* debug-level messages */

#define LOG_PRIMASK      0x0007 /* mask to extract priority part (internal) */

/*
 * arguments to setlogmask from syslog.h.
 */
#define LOG_MASK(pri) (1 << (pri))            /* mask for one priority */
#define LOG_UPTO(pri) ((1 << ((pri)+1)) - 1)  /* all priorities through pri */

/*
 *  Option flags for openlog from syslog.h.
 *
 *        LOG_ODELAY no longer does anything; LOG_NDELAY is the
 *        inverse of what it used to be.
 */
#define LOG_PID    0x01        /* log the pid with each message */
#define LOG_CONS   0x02        /* log on the console if errors in sending */
#define LOG_ODELAY 0x04        /* delay open until syslog() is called */
#define LOG_NDELAY 0x08        /* don't delay open */
#define LOG_NOWAIT 0x10        /* if forking to log on console, don't wait() */

/* Function prototypes for sshd2, these are implemented, if necessary,
   in the apps/ssh/sshvxworks.c, file */

/* pipes */
FILE *popen(const char *command, const char *mode);
int pclose(FILE *stream);
int pipe(int fildes[2]);

/* uid, pw, user, group */
struct passwd *getpwuid(uid_t uid);
struct passwd *getpwnam(const char *name);
uid_t getuid(void);
uid_t geteuid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
struct group *getgrgid(gid_t gid);
struct group *getgrnam(const char *name);
void endpwent(void);
void endgrent(void);

/* process and file management */
pid_t fork(void);
int dup2(int fildes, int fildes2);
int execve(const char *path, char *const argv[], char *const envp[]);
int execvp(const char *file, char *const argv[]);

/* files */
void openlog(const char *ident, int logopt, int facility);
mode_t umask(mode_t cmask);
struct hostent *gethostbyname(const char *name);
int chroot(const char *path);
int chown(const char *path, uid_t owner, gid_t group);
int chmod(const char *path, mode_t mode);
int lstat(const char *path, struct stat *buf);

/* misc */
int readlink(const char *path, char *buf, size_t bufsiz);
pid_t wait(int *stat_loc);
int grantpt(int fildes);
int unlockpt(int fildes);
char *ptsname(int fildes);
int fcntl(int fildes, int cmd, /* arg */ ...);

/* Make sure the missing fcntl operation does not cause an undefined
   reference to `fcntl' in DEBUG_HEAVY mode compilation */
#define fcntl(fd, cmd, arglist) 1























#endif /* SSHINCLUDES_VXWORKS_H */
