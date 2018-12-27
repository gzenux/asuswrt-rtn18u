/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic interface for opening a data stream to/from a device (hardware
   device or pseudo-device).  This is the unix implementation.
*/

#include "sshincludes.h"
#include "sshdevicestream.h"
#include "ssheloop.h"
#include "sshfdstream.h"

/* Opens a stream for the device specified by the given name.  Returns NULL
   on failure. */

SshStream ssh_device_open(const char *name)
{
  SshIOHandle fd;
  SshStream str;

  /* Try to open the device. */
#ifndef VXWORKS
  fd = open(name, O_RDWR);
#else
  fd = open(name, O_RDWR, 0777);
#endif

  /* On error, return NULL. */
  if (fd < 0)
    return NULL;

  /* On success, wrap the device file descriptor into a stream and return
     the stream. */
  str = ssh_stream_fd_wrap(fd, TRUE);

  if (str == NULL)
    {
      close(fd);
      return NULL;
    }

  return str;
}
