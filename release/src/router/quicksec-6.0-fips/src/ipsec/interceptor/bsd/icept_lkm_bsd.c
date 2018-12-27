/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Main program for a ssh packet interceptor kernel module.
   This file handles {Net,Free}BSD LKM style attachment and
   new FreeBSD-3.1 KLD style.
*/

/*      $NetBSD: mln_ipl.c,v 1.16.2.2 1997/11/11 09:16:46 veego Exp $   */

/*
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 */

#define SSH_ALLOW_CPLUSPLUS_KEYWORDS
#include "sshincludes.h"
#include "version.h"
#include "icept_chardev.h"
#include "icept_internal.h"
#include "icept_attach.h"

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/exec.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/route.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <sys/systm.h>
#include <sys/lkm.h>

#if defined(__NetBSD__)
#if SSH_NetBSD < 153
#include <netinet/ip_compat.h>
#include <netinet/ip_fil.h>
#endif /* SSH_NetBSD < 153 */
extern int lkmenodev();
#endif /* __NetBSD__ */

#if SSH_NetBSD > 199
extern struct cdevsw *cdevsw[];
#endif

#if !defined(VOP_LEASE) && defined(LEASE_CHECK)
#define VOP_LEASE       LEASE_CHECK
#endif

/* The version of the interceptor.  This must be a constant string
   because of MOD_DEV. */





#ifdef SSHDIST_QUICKSEC
#undef SSH_INTERCEPTOR_VERSION
#define SSH_INTERCEPTOR_VERSION "SSH QuickSec " ## SSH_IPSEC_VERSION
#endif /* SSHDIST_QUICKSEC */

/* The version of the packet processing engine. */
#define SSH_ENGINE_VERSION ssh_engine_version

int ssh_interceptor_major = -1;

#if SSH_NetBSD < 200
MOD_DEV(SSH_INTERCEPTOR_VERSION, LM_DT_CHAR, -1, &ssh_chardev_cdevsw);
extern int nchrdev;
#else
MOD_DEV("quicksec", "quicksec", NULL, -1, &ssh_chardev_cdevsw, -1);
int nchrdev = -1;
#endif

/* Creates the interceptor device to the file system.  This function
   is used when loading the packet interceptor. */

static int ssh_interceptor_create()
{
  struct nameidata nd;
  int error = 0;
  int fmode = S_IFCHR | 0600;
  char name[100];
  struct vattr vattr;

  ssh_snprintf(name, sizeof(name), "%s%s", ssh_device_name, ssh_device_suffix);
  NDINIT(&nd, CREATE, LOCKPARENT, UIO_SYSSPACE, name, SSH_CURPROC);
  error = namei(&nd);
  if (error)
    {
      return error;
    }

  if (nd.ni_vp != NULL)
    {
      VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
      if (nd.ni_dvp == nd.ni_vp)
        vrele(nd.ni_dvp);
      else
        vput(nd.ni_dvp);
      vrele(nd.ni_vp);
      return EEXIST;
    }

  VATTR_NULL(&vattr);
  vattr.va_type = VCHR;
  vattr.va_mode = (fmode & 07777);
  vattr.va_rdev = makedev(ssh_interceptor_major, 0);
  VOP_LEASE(nd.ni_dvp, SSH_CURPROC, SSH_UCRED, LEASE_WRITE);
  error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);

#if SSH_NetBSD >= 160
  if (error == 0)
    vput(nd.ni_vp);
#endif /* SSH_NetBSD >= 160 */

  if (error)
    return error;

  return 0;
}

/* Removes the interceptor device from the file system.  This function is
   used when loading and unloading the packet interceptor. */

static int ssh_interceptor_remove()
{
  struct nameidata nd;
  int error;
  char name[100];

  ssh_snprintf(name, sizeof(name), "%s%s", ssh_device_name, ssh_device_suffix);
  NDINIT(&nd, DELETE, LOCKPARENT, UIO_SYSSPACE, name, SSH_CURPROC);
  error = namei(&nd);
  if (error)
    {
      return error;
    }

  VOP_LEASE(nd.ni_vp, SSH_CURPROC, SSH_UCRED, LEASE_WRITE);

#if SSH_NetBSD >= 140
  VOP_LOCK(nd.ni_vp, LK_EXCLUSIVE);
#else
  VOP_LOCK(nd.ni_vp);
#endif

  VOP_LEASE(nd.ni_dvp, SSH_CURPROC, SSH_UCRED, LEASE_WRITE);
  error = VOP_REMOVE(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);

  return error;
}

/* This function is called after loading the packet interceptor into
   memory.  This will create the device that the packet interceptor
   uses to communicate with user-mode processes.  This also attaches
   the packet interceptor into the system's TCP/IP stack. */
static int sshipsec_load(struct lkm_table *lkmtp, int cmd)
{
  int error;
#if SSH_NetBSD < 200
  struct lkm_dev *args = lkmtp->private.lkm_dev;
  int i;
#endif

  if (lkmexists(lkmtp))
    return EEXIST;

  ssh_interceptor_major = -1;

#if SSH_NetBSD > 199
  {
    int bmajor = -1, cmajor = -1, error;

    if ((error =
	 devsw_attach("quicksec", NULL, &bmajor, &ssh_chardev_cdevsw, &cmajor))
	!= EEXIST)
      {
	printf("devsw_attach failed; error %d major %d\n",
	       error, cmajor);
	return error;
      }
    else
      {
	ssh_interceptor_major = cmajor;
      }
  }
#else
  for (i = 0; i < nchrdev; i++)
    {
      if ((void *)cdevsw[i].d_open == (void *)lkmenodev
	  || cdevsw[i].d_open == ssh_chardev_cdevsw.d_open)
	break;
    }

  if (i != nchrdev)
    ssh_interceptor_major = i;

#endif

  if (ssh_interceptor_major == -1)
    {
      printf("%s: No free cdevsw slots\n", SSH_ENGINE_VERSION);
      return ENODEV;
    }

#if SSH_NetBSD < 200
  args->lkm_offset = i;   /* slot in cdevsw[] */
#endif

  printf("LOAD: %s (%s, %s): loaded, major dev %d\n",
         SSH_ENGINE_VERSION, ssh_ident_attach, ssh_ident_mode,
         ssh_interceptor_major);

  /* Remove any existing devices with the name used by the packet
     interceptor. */
  ssh_interceptor_remove();

  /* Create the interceptor device. */
  error = ssh_interceptor_create();

  if (error)
    {
#if SSH_NetBSD > 199
      devsw_detach(NULL, &ssh_chardev_cdevsw);
#endif
      return error;
    }

  /* Attach the interceptor to the TCP/IP stack. */
  ssh_attach_substitutions();

  /* Initialize upper-level code. */
  ssh_upper_initialize();

  return 0;
}

/* This function is called just before unloading the packet
   interceptor from memory. */
static int sshipsec_unload(struct lkm_table *lkmtp, int cmd)
{

  /* If the interceptor is currently open as a device, refuse to unload it. */
  if (ssh_chardev_is_open)
    return EBUSY;


  /* Uninitialize upper-level code. */
  ssh_upper_uninitialize();

  /* Detach the interceptor from the TCP/IP stack. */
  ssh_detach_substitutions();

  /* Remove the interceptor device. */
  ssh_interceptor_remove();








  printf("UNLOAD %s: unloaded from major dev %d\n",
         SSH_ENGINE_VERSION, ssh_interceptor_major);

#if SSH_NetBSD > 199
  devsw_detach(NULL, &ssh_chardev_cdevsw);
#endif

  return 0;
}

/* Status query entry point. */

static int sshipsec_stat(struct lkm_table *lkmtp, int cmd)
{
  return 0;
}

/* This is the public entry point that is called first when the module
   is loaded. */

int sshipsec(struct lkm_table *lkmtp, int cmd, int ver)
{
  DISPATCH(lkmtp, cmd, ver, sshipsec_load, sshipsec_unload, sshipsec_stat);
}

#define ENTRY_FUNC(name)                                \
int name(struct lkm_table *lkmtp, int cmd, int ver)     \
{                                                       \
  return sshipsec(lkmtp, cmd, ver);                     \
}

/* Old NetBSD */
ENTRY_FUNC(xxxinit)

/* New NetBSD */
ENTRY_FUNC(sshipsec_lkmentry)
ENTRY_FUNC(sshipsec_ether_lkmentry)
ENTRY_FUNC(sshipsec_usermode_lkmentry)
ENTRY_FUNC(sshipsec_usermode_ether_lkmentry)
ENTRY_FUNC(sshipsec_tester_lkmentry)

ENTRY_FUNC(quicksec_lkmentry)
ENTRY_FUNC(quicksec_ether_lkmentry)
ENTRY_FUNC(quicksec_usermode_lkmentry)
ENTRY_FUNC(quicksec_usermode_ether_lkmentry)
ENTRY_FUNC(quicksec_tester_lkmentry)
