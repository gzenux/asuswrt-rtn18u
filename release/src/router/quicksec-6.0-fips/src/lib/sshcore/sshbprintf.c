/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshsnprintf.h"
#include "sshdebug.h"
#include "sshbprintf.h"
#include "sshdsprintf.h"













int ssh_vbprintf(SshBuffer buf, const char *format, va_list ap)
{
  unsigned char *str;
  size_t len, size;
  int len_tmp;

  size = 0;
  str = NULL;
  len_tmp = ssh_dvsprintf(&str, format, ap);

  if (len_tmp < 0)
    return size;

  len = (size_t)len_tmp;

  if (len > 0 &&
      ssh_buffer_append(buf, str, len) == SSH_BUFFER_OK)
    size = len;
  ssh_free(str);
  return size;
}

int ssh_bprintf(SshBuffer buf, const char *format, ...)
{
  int ret;
  va_list ap;
  va_start(ap, format);

  ret = ssh_vbprintf(buf, format, ap);
  va_end(ap);

  return ret;
}

int ssh_xvbprintf(SshBuffer buf, const char *format, va_list ap)
{
  unsigned char *str;
  size_t len;

  str = NULL;
  len = ssh_xdvsprintf(&str, format, ap);
  ssh_xbuffer_append(buf, str, len);
  ssh_free(str);
  return len;
}

int ssh_xbprintf(SshBuffer buf, const char *format, ...)
{
  int ret;
  va_list ap;
  va_start(ap, format);

  ret = ssh_xvbprintf(buf, format, ap);
  va_end(ap);

  return ret;
}
