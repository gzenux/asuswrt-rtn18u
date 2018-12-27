/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for manipulating fifo buffers (that can grow if needed).
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshBuffer"

SshBuffer ssh_xbuffer_allocate(void)
{
  SshBuffer buffer;

  if ((buffer = ssh_buffer_allocate()) == NULL)
    ssh_fatal("Can not allocate a buffer. Not enough memory.");
  return buffer;
}

void ssh_xbuffer_append(SshBuffer buffer, const unsigned char *data,
                        size_t len)
{
  if (ssh_buffer_append(buffer, data, len) != SSH_BUFFER_OK)
    ssh_fatal("Can not append %d bytes to buffer. "
              "Not enough memory.", len);
}

void ssh_xbuffer_append_space(SshBuffer buffer, unsigned char **datap,
                              size_t len)
{
  if (ssh_buffer_append_space(buffer, datap, len) != SSH_BUFFER_OK)
    ssh_fatal("Can not append %d bytes empty space to buffer. "
              "Not enough memory.", len);
}

void ssh_xbuffer_append_cstrs(SshBuffer buffer, ...)
{
  va_list ap;
  SshBufferStatus status = SSH_BUFFER_OK;

  va_start(ap, buffer);

  status = ssh_buffer_append_cstrs_va(buffer, ap);

  va_end(ap);

  if (status != SSH_BUFFER_OK)
    ssh_fatal("Can not append strings to buffer. Not enough memory.");
}
