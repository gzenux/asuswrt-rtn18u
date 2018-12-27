/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/* #includes */

#include "sshincludes.h"
#include "sshdevicestream.h"
#include "sshfdstream.h"

#define SSH_DEBUG_MODULE "SshDeviceStream"

/* #defines */

/* Exported functions */



SshStream ssh_device_open(const char *name)
{
  HANDLE h;
#ifdef UNICODE
  WCHAR dev_name[MAX_PATH];
#else
  const char *dev_name = name;
#endif /* UNICODE */
  SshStream str;

#ifdef UNICODE
  ssh_ascii_to_unicode(dev_name, sizeof(dev_name), name);
#endif /* UNICODE */

  h = CreateFile(
    dev_name,
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,
    NULL
  );

  if (h != INVALID_HANDLE_VALUE)
    {
      /*
        On success, wrap the device file descriptor into a stream and
        return the stream. */
      str = ssh_stream_fd_wrap_with_callbacks(h, h, TRUE,
                                              NULL, NULL, NULL);
      if (str == NULL)
        {
          CloseHandle(h);
          return NULL;
        }
      return str;
    }
  else
    {
      DWORD e = GetLastError();

      return NULL;
    }
}

/* EOF */
