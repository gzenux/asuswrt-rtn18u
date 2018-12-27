/**
   @copyright
   Copyright (c) 2005 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   TLS hardware acceleration.
*/

#ifdef __linux__
#include <sys/ioctl.h>
#endif /* __linux__ */
#include "sshincludes.h"
#include "ssheloop.h"
#include "sshdebug.h"
#include "sshtls.h"
#include "tls_accel.h"

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS

#include "sshtlsaccel.h"

#define SSH_DEBUG_MODULE "SshTlsAccel"

/* File handle to submit acceleration requests to the device */
static int device_fd = -1;
/* File handle to add to event loop and read results */
static SshIOHandle device_rd_fd = -1;
/* Registered to event loop */
static Boolean registered;

/* Initialize and allocate crypto context. Return context or NULL
on failure. */
void *tls_accel_init_key(
  Boolean encode, int cipher,
  const unsigned char *key, int keylen,
  const unsigned char *iv)
{
#ifdef __linux__
  SshTlsAccelInitkeyParamRec pb;
  int algo, fmode, rc;

  /* If hardware acceleration device is not available, return NULL */
  if (!device_fd)
    return NULL;

  switch(cipher)
    {
      case SSH_TLS_CIPH_AES128:
      case SSH_TLS_CIPH_AES256:
        algo = SA_CRYPTO_AES; break;
      case SSH_TLS_CIPH_3DES:
        algo = SA_CRYPTO_TDES; break;
      case SSH_TLS_CIPH_DES:
        algo = SA_CRYPTO_DES; break;
      case SSH_TLS_CIPH_RC4:
        algo = SA_CRYPTO_ARC4; break;
      default:
        return NULL;
    }

  fmode=SA_CRYPTO_MODE_CBC;

  pb.algo = algo;
  pb.fmode = fmode;
  pb.keylen = keylen;
  pb.key = key;
  pb.iv = iv;
  pb.dir = encode;
  rc = ioctl(device_fd, SAFENET_IOCINITKEY, &pb);
  if (rc < 0)
    SSH_DEBUG(SSH_D_FAIL, ("Allocate accel context failed, %d", rc));
  return rc >= 0 ? pb.ctx:NULL;
#else
  return NULL;
#endif /* __linux__ */
}

/* Submit encrypt/decrypt operation to hardware */
Boolean tls_accel_cipher(void *ctx, void *usr_ctx, void *buff, int len)
{
#ifdef __linux__
  SshTlsAccelCryptoParamRec pb;
  int rc;

  SSH_ASSERT(ctx);

  pb.usr_ctx = usr_ctx;
  pb.ctx = ctx;
  pb.data = (unsigned char *)buff;
  pb.size = len;

  rc = ioctl(device_fd, SAFENET_IOCCIPHER, &pb);
  if (rc < 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Crypto op failed, %d", rc));
      return FALSE;
    }
  return TRUE;
#else
  return FALSE;
#endif /* __linux__ */
}

Boolean tls_accel_free_key(void *ctx)
{
#ifdef __linux__
  int rc;

  SSH_ASSERT(ctx);
  rc = ioctl(device_fd, SAFENET_IOCCLEANKEY, ctx);
  if (rc < 0)
    SSH_DEBUG(SSH_D_FAIL, ("Free accel context failed, %d", rc));
  return rc >= 0;
#else
  return FALSE;
#endif /* __linux__ */
}

/* Open interface to tls acceleration */
Boolean tls_accel_open(void (*rd_cb)(unsigned int, void *))
{
#ifdef __linux__
  const char *name = "/proc/quicksec/hwaccel";

  if (device_fd >= 0)
    return TRUE;

  /* Try to open the device. */
  device_fd = open(name, O_RDWR);
  device_rd_fd = open(name, O_RDWR);

  if (device_fd == -1 || device_rd_fd == -1)
    {
      SSH_DEBUG(1 , ("Hardware accelerator n/a"));
      tls_accel_close();
      return FALSE;
    }

  registered = ssh_io_register_fd(device_rd_fd, rd_cb, NULL);
  if (!registered)
    {
      SSH_DEBUG(SSH_D_FAIL, ("ssh_io_register_fd failed"));
      tls_accel_close();
      return FALSE;
    }
  ssh_io_set_fd_request(device_rd_fd, SSH_IO_READ);

  return TRUE;
#else
  return FALSE;
#endif /* __linux__ */
}

/* Close interface to tls acceleration */
void tls_accel_close(void)
{
#ifdef __linux__
  if (registered)
    ssh_io_unregister_fd(device_rd_fd, FALSE);
  registered = FALSE;

  if (device_fd != -1)
    close(device_fd);
  if (device_rd_fd != -1)
    close(device_rd_fd);

  device_fd = device_rd_fd = -1;
#endif /* __linux__ */
}

/* Get read file descriptor */
int tls_accel_get_rd_fd(void)
{
#ifdef __linux__
  return device_rd_fd;
#else
  return -1;
#endif /* __linux__ */
}

#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */
