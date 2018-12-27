/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definition of the character device interface.
*/

#ifndef ICEPT_CHARDEV_H
#define ICEPT_CHARDEV_H

#ifndef VXWORKS
#include <sys/conf.h>
#endif /* VXWORKS */

/* This flag indicates whether the character device is open.
   It is non-zero if it is open. */
extern int ssh_chardev_is_open;

/***********************************************************************
 * Support functions for interacting with the character device.
 ***********************************************************************/

/* Transfers data between the character device and the implementation in
   a read or write operation.  This can only be called from within
   ssh_chardev_{read,write}.  This returns an errno value, 0 on
   success.  This function is implemented by the character device code. */
int ssh_chardev_io_transfer(void *buf,
                            size_t len,
                            void *io_context);

/* Returns the number of bytes that can still be transferred using this
   context. */
size_t ssh_chardev_io_residual(void *io_context);

/* Wakes up the character device if it is blocked in a read or write.
   This function can be called from anywhere in the code (typically not
   from one of the character device functions).  This function is implemented
   by the character device code. */
void ssh_chardev_wakeup(void);

/***********************************************************************
 * Functions that need to be implemented by the rest of the code.
 ***********************************************************************/

/* This function is called whenever the character device is
   opened.  This should return an errno value, 0 on success. */
int ssh_chardev_open(void);

/* This function is called whenever the character device is
   closed. */
void ssh_chardev_close(void);

/* This function is called whenever a read request is received from the
   device.  This should return an errno value, 0 on success. */
int ssh_chardev_read(void *context, size_t maxlen);

/* This function is called whenever a write request is received from the
   device.  This should return an errno value, 0 on success. */
int ssh_chardev_write(void *context, size_t maxlen);

/* This function should return non-zero if data is available for reading, and
   0 if no data is currently available for reading. */
int ssh_chardev_read_available(void);

/* This function should return non-zero if data can be written to the device,
   and 0 if no data can currently be written to the device (e.g., buffers
   are full). */
int ssh_chardev_write_available(void);

/* A cdevsw structure for the character device. */
extern struct cdevsw ssh_chardev_cdevsw;
extern struct bdevsw ssh_chardev_bdevsw;

#if SSH_NetBSD >= 400
#include <sys/kauth.h>
#define SSH_PROC struct lwp
#define SSH_CURPROC curlwp
#define SSH_UCRED curlwp->l_cred
#else /* SSH_NetBSD >= 400 */
#define SSH_PROC struct proc
#define SSH_CURPROC curproc
#define SSH_UCRED curproc->p_ucred
#endif /* SSH_NetBSD >= 400 */

#if defined(__NetBSD__)
int ssh_cdevsw_open(dev_t dev, int flag, int mode, SSH_PROC *p);
int ssh_cdevsw_close(dev_t dev, int flag, int mode, SSH_PROC *p);
int ssh_cdevsw_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag,
                     SSH_PROC *p);
int ssh_cdevsw_read(dev_t dev, struct uio *uio, int ioflag);
int ssh_cdevsw_write(dev_t dev, struct uio *uio, int ioflag);
int ssh_cdevsw_poll(dev_t dev, int rw, SSH_PROC *p);

#define ssh_cdev_ipsec_init(c,n) { \
        ssh_cdevsw_open, ssh_cdevsw_close, \
        ssh_cdevsw_read, ssh_cdevsw_write, \
        ssh_cdevsw_ioctl, \
        (void *)nullop, \
        (void *)NULL, \
        ssh_cdevsw_poll, (void *)nullop, 0 }
#endif /* NetBSD */
#endif /* ICEPT_CHARDEV_H */
