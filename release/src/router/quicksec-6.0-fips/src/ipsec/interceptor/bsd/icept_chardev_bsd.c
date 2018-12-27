/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Character device interface for communicating with the user-level process.
*/

#if 0
#define SSHCHARDEV_DEBUG
#endif

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS
#include "sshincludes.h"
#include "icept_internal.h"
#include "icept_chardev.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/buf.h>

#ifndef __FreeBSD__
#include <sys/ioctl.h>
#else /* not __FreeBSD__ */
#if defined(SSH_FreeBSD_22)
#include <sys/ioctl.h>
#else /* not SSH_FreeBSD_22 */
#include <sys/filio.h>
#endif /* not SSH_FreeBSD_22 */
#endif /* not __FreeBSD__ */

#include <sys/errno.h>
#include <sys/fcntl.h>
#ifndef DARWIN
#include <sys/poll.h>
#endif /* DARWIN */
#include <sys/select.h>
#include <sys/conf.h>

/* Structure for processing select() for reads for this device. */
struct selinfo ssh_chardev_rsel;

/* Flag indicating whether the character device is open.  If not, all
   packets will go straight through. */
int ssh_chardev_is_open = 0;
int ssh_chardev_polled = 0;
int ssh_chardev_nonblocking = 0;
int ssh_chardev_initial_read = 1;



/* This is the attach entry point for the device.  There is nothing we
   need to do here, unless the ipsec engine is compiled into the kernel,
   in which case we start it here. */

void ssh_chardev_attach(int unused)
{
#ifdef SSHIPSECKERNEL
  ssh_upper_initialize();
  printf("SSH Interceptor device attached\n");
#endif

#ifdef SSHCHARDEV_DEBUG
  printf("SSH Interceptor device attached\n");
#endif
}

/* This is called whenever the device is opened.  This returns
   errno, or 0 on successs. */

int ssh_cdevsw_open(dev_t dev, int flag, int mode, SSH_PROC *p)
{
  int error, s;

  /* Only allow opens as a superuser for security reasons. */
  if ((error
#if SSH_FreeBSD == 4
       = suser(p)
#else /* SSH_FreeBSD == 4 */
#if SSH_NetBSD >= 400
       = kauth_authorize_generic(p->l_cred,
				 KAUTH_GENERIC_ISSUSER, &p->l_acflag)
#else /* SSH_NetBSD >= 400 */
       = suser(p->p_ucred, &p->p_acflag)
#endif /* SSH_NetBSD >= 400 */
#endif /* not SSH_FreeBSD == 4 */
       ) != 0)
    return error;

  s = ssh_interceptor_spl();

  /* If already open, return error. */
  if (ssh_chardev_is_open)
    {
      splx(s);
      return EBUSY;
    }

#ifdef SSHCHARDEV_DEBUG
  printf("SSH Interceptor device opened\n");
#endif /* SSHCHARDEV_DEBUG */

  /* Mark that we are open, and otherwise initialize state. */
  ssh_chardev_is_open = 1;
  ssh_chardev_polled = 0;

  /* Perform any implementation-specific initializations. */
  error = ssh_chardev_open();

  if (error)
    /* We could not open the character device. */
    ssh_chardev_is_open = 0;

  splx(s);

  return error;
}

/* This is called when the character device is closed for the last
   time (since we only one process to have it open at a time, this
   means whenever it is closed). */

int ssh_cdevsw_close(dev_t dev, int flag, int mode, SSH_PROC *p)
{
  int s;

#ifdef SSHCHARDEV_DEBUG
  printf("SSH Interceptor device closed\n");
#endif /* SSHCHARDEV_DEBUG */

  s = ssh_interceptor_spl();

  /* Mark that we are closed. */
  ssh_chardev_is_open = 0;

  /* Notify the implementation-specific code. */
  ssh_chardev_close();

  splx(s);

  return 0;
}

/* IOCTL entry point for the device. */

int ssh_cdevsw_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag,
                     SSH_PROC *p)
{
  switch (cmd)
    {
    case FIONBIO:
      ssh_chardev_nonblocking = *(int *)data != 0;
#ifdef SSHCHARDEV_DEBUG
      printf("SSH Interceptor device nonblocking=%d\n",
             ssh_chardev_nonblocking);
#endif
      return 0;

    case FIOASYNC:
      /* We do not support async operation, but we must recognize it or
         the upper level will cancel nonblocking... */
      return 0;

    default:
      return ENOTTY;
    }
  /*NOTREACHED*/
}

/* Read entry point. */

int ssh_cdevsw_read(dev_t dev, struct uio *uio, int ioflag)
{
  int error = 0, orig_resid, s;

#ifdef SSHCHARDEV_DEBUG
  printf("SSH Interceptor device read\n");
#endif

  s = ssh_interceptor_spl();

  /* Try to read, blocking if there is no data and we are in blocking mode. */
  orig_resid = uio->uio_resid;
  for (;;)
    {
      error = ssh_chardev_read((void *)uio, uio->uio_resid);
      if (error != 0 || uio->uio_resid != orig_resid)
        break;

      /* We don't have data yet.  Block or bail out, depending on the
         nonblocking setting. */
      if (ssh_chardev_nonblocking)
        {
          /* We are in non-blocking mode.  Return immediately with
             an error. */
          splx(s);
#ifdef SSHCHARDEV_DEBUG
          printf("chardev read would block\n");
#endif /* SSHCHARDEV_DEBUG */
          return EWOULDBLOCK;
        }

#ifdef SSHCHARDEV_DEBUG
      printf("chardev read blocking\n");
#endif /* SSHCHARDEV_DEBUG */

      /* Block until we have received something. */
      ssh_chardev_polled = 1;
      if (tsleep((caddr_t)&ssh_chardev_nonblocking, PZERO|PCATCH,
                 "ssh_chardev_read", 0))
        {
          splx(s);
#ifdef SSHCHARDEV_DEBUG
          printf("chardev sleep interrupted\n");
#endif /* SSHCHARDEV_DEBUG */
          return EINTR;
        }
    }

  splx(s);
#ifdef SSHCHARDEV_DEBUG
  printf("chardev read %d bytes\n", orig_resid - uio->uio_resid);
#endif /* SSHCHARDEV_DEBUG */
  return error;
}

/* This is the write entry point for the device.  The written data contains
   one or more packets to send out (to the network or to protocols).
   Packets must always be sent with a single write.  Sending multiple packets
   with a single write is allowed. */

int ssh_cdevsw_write(dev_t dev, struct uio *uio, int ioflag)
{
  int error = 0, orig_resid, s;

#ifdef SSHCHARDEV_DEBUG
  printf("SSH Interceptor device write, len = %d\n",
         (int)uio->uio_resid);
#endif

  s = ssh_interceptor_spl();

  /* Try to read, blocking if there is no data and we are in blocking mode. */
  orig_resid = uio->uio_resid;
  for (;;)
    {
      error = ssh_chardev_write((void *)uio, uio->uio_resid);
      if (error != 0 || uio->uio_resid != orig_resid)
        break;

      /* We don't have data yet.  Block or bail out, depending on the
         nonblocking setting. */
      if (ssh_chardev_nonblocking)
        {
          /* We are in non-blocking mode.  Return immediately with
             an error. */
          splx(s);
          return EWOULDBLOCK;
        }

      /* Block until we have received something. */
      ssh_chardev_polled = 1;
      if (tsleep((caddr_t)ssh_chardev_nonblocking, PZERO|PCATCH,
                 "ssh_chardev_write", 0))
        {
          splx(s);
          return EINTR;
        }
    }

  splx(s);
  return error;
}

/* This is the select interface that the kernel uses to implement select().
   This checks whether reads/writes are possible (as requested), and
   if so, returns that information immediately.  Otherwise, this records
   that we are in a select, and causes the select to be woken up when
   data is available. */

int ssh_cdevsw_poll(dev_t dev, int rw, SSH_PROC *p)
{
  int s, revents = 0;

  s = ssh_interceptor_spl();

#if defined(SSH_FreeBSD_22) || SSH_Darwin >= 10300
  revents = 0;
  switch (rw)
    {
    case FREAD:
      if (ssh_chardev_read_available())
        revents = 1;
      else
        {
          selrecord(p, &ssh_chardev_rsel);
          /* call selwakeup(&ssh_chardev_rsel); when output ready */
          /* That can be done by calling ssh_chardev_wakeup. */
          ssh_chardev_polled = 1;
        }
      break;

    case FWRITE:
      revents = 1;
      break;

    }
#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(DARWIN)
  if (rw & (POLLIN | POLLRDNORM))
    {
      if (ssh_chardev_read_available())
        revents |= rw & (POLLIN | POLLRDNORM);
      else
        {
          selrecord(p, &ssh_chardev_rsel);
          /* call selwakeup(&ssh_chardev_rsel); when output ready */
          /* That can be done by calling ssh_chardev_wakeup. */
          ssh_chardev_polled = 1;
        }
    }
  if (rw & (POLLOUT | POLLWRNORM))
    {
      revents |= rw & (POLLOUT | POLLWRNORM);
    }
#else
#error implement select processing for this platform
#endif
  splx(s);
  return revents;
}

/* Transfers data between the character device and the implementation in
   a read or write operation.  This can only be called from within
   ssh_chardev_{read,write}.  This returns an errno value, 0 on
   success.  This function is implemented by the character device code. */

int ssh_chardev_io_transfer(void *buf,
                            size_t len,
                            void *io_context)
{
  struct uio *uio = io_context;

  return uiomove(buf, len, uio);
}

/* Wakes up the character device if it is blocked in a read or write.
   This function can be called from anywhere in the code (typically not
   from one of the character device functions).  This function is implemented
   by the character device code. */

void ssh_chardev_wakeup(void)
{
  int s;

#ifdef SSHCHARDEV_DEBUG
  printf("ssh_chardev_wakeup\n");
#endif

  /* If we are being polled (i.e., someone is blocked in a select waiting
     for us), wake it up. */
  s = ssh_interceptor_spl();
  if (ssh_chardev_polled)
    {
#ifdef SSHCHARDEV_DEBUG
      printf("SSH Interceptor device: waking up\n");
#endif
      ssh_chardev_polled = 0;
      selwakeup(&ssh_chardev_rsel);
      wakeup((caddr_t)&ssh_chardev_nonblocking);
    }
  splx(s);
}

/* Returns the number of bytes that can still be transferred using this
   context. */

size_t ssh_chardev_io_residual(void *io_context)
{
  struct uio *uio = io_context;

  return uio->uio_resid;
}

/* Define a cdevsw structure describing the device. */

#if defined(__NetBSD__)
struct cdevsw ssh_chardev_cdevsw =
{
  ssh_cdevsw_open,              /* open */
  ssh_cdevsw_close,             /* close */
  ssh_cdevsw_read,              /* read */
  ssh_cdevsw_write,             /* write */
  ssh_cdevsw_ioctl,             /* ioctl */
  (void *)nullop,               /* stop */
  (void *)NULL,                 /* tty */
  ssh_cdevsw_poll,              /* poll */
  (void *)nullop,               /* mmap */
#if SSH_NetBSD > 199
  (void *)nullop,               /* kqfilter */
#endif
  0                             /* type */
};
#if SSH_NetBSD > 199
struct bdevsw ssh_chardev_bdevsw =
  {
    (void *)nullop, /* o */
    (void *)nullop, /* c */
    (void *)nullop, /* s */
    (void *)nullop, /* i */
    (void *)nullop, /* d */
    (void *)nullop, /* p */
    0,
  };
#endif
#elif defined(__FreeBSD__)
#if SSH_Darwin >= 10300
struct cdevsw ssh_chardev_cdevsw =
{
  ssh_cdevsw_open,              /* open */
  ssh_cdevsw_close,             /* close */
  ssh_cdevsw_read,              /* read */
  ssh_cdevsw_write,             /* write */
  ssh_cdevsw_ioctl,             /* ioctl */
  eno_stop,                     /* stop */
  eno_reset,                    /* reset */
  NULL,                         /* ttys */
  ssh_cdevsw_poll,              /* select */
  eno_mmap,                     /* mmap */
  eno_strat,                    /* strategy */
  eno_getc,                     /* getc */
  eno_putc,                     /* putc */
  0                             /* type */
};
#elif __FreeBSD__ >= 4
struct cdevsw ssh_chardev_cdevsw =
{
  ssh_cdevsw_open,              /* open */
  ssh_cdevsw_close,             /* close */
  ssh_cdevsw_read,              /* read */
  ssh_cdevsw_write,             /* write */
  ssh_cdevsw_ioctl,             /* ioctl */
  ssh_cdevsw_poll,              /* poll */
  nommap,                       /* mmap */
  nostrategy,                   /* strategy */
  "sshchardev",                 /* name */
  -1,                           /* maj */
  nodump,                       /* dump */
  nopsize,                      /* psize */
  0,                            /* flags */
  -1                            /* bmaj */
};
#else /* __FreeBSD__ < 4 */
struct cdevsw ssh_chardev_cdevsw =
{
  ssh_cdevsw_open,
  ssh_cdevsw_close,
  ssh_cdevsw_read,
  ssh_cdevsw_write,
  ssh_cdevsw_ioctl,
  nullstop,
  noreset,
  nodevtotty,
  ssh_cdevsw_poll,
  nommap,
  nostrategy,
  "sshchardev",
  NULL,
  -1
};
#endif /* __FreeBSD__ < 4 */
#else /* unknown */
#error Check cdevsw format for this platform
#endif
