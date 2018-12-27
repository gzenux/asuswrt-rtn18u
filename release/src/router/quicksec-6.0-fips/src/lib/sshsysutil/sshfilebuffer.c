/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Code for reading files into SshBuffer.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshfilebuffer.h"

#define SSH_DEBUG_MODULE "SshFileBuffer"

#define SSH_FILE_BUFFER_MINIMUM_READ    1024

/* Allocate a file buffer */
SshFileBuffer ssh_file_buffer_allocate(void)
{
  SshFileBuffer r;

  r = ssh_xmalloc(sizeof (*r));
  ssh_file_buffer_init(r);
  return r;
}

/* Free a file buffer */
void ssh_file_buffer_free(SshFileBuffer buf)
{
  SSH_ASSERT(buf != NULL);
  if (ssh_file_buffer_attached(buf))
    {
      if (!(buf->attached_as_fileptr))
        fclose(buf->f);
      buf->attached_as_fileptr = FALSE;
      buf->f = NULL;
    }
  ssh_buffer_uninit(&(buf->buf));
  ssh_xfree(buf);
  return;
}

/* Initialize an already allocated file buffer */
void ssh_file_buffer_init(SshFileBuffer buf)
{
  SSH_ASSERT(buf != NULL);
  buf->attached_as_fileptr = FALSE;
  buf->f = NULL;
  buf->read_callback = NULL_FNPTR;
  buf->read_context = NULL;
  ssh_buffer_init(&(buf->buf));
  return;
}

/* Uninitialize a file buffer initialized by ssh_file_buffer_init */
void ssh_file_buffer_uninit(SshFileBuffer buf)
{
  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  ssh_buffer_uninit(&(buf->buf));
  return;
}

/* Clear the allocated file buffer.
   Detach the possibly attached file and zero the buffer. */
void ssh_file_buffer_clear(SshFileBuffer buf)
{
  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  ssh_buffer_clear(&(buf->buf));
  return;
}

/* Attech a file to a file buffer. */
Boolean ssh_file_buffer_attach(SshFileBuffer buf, char *filename)
{
  FILE *f;

  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  f = fopen(filename, "rb");
  if (f == NULL)
    return FALSE;
  buf->f = f;
  buf->attached_as_fileptr = FALSE;
  return TRUE;
}

Boolean ssh_file_buffer_attach_fileptr(SshFileBuffer buf, FILE *f)
{
  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  buf->f = f;
  buf->attached_as_fileptr = TRUE;
  return TRUE;
}

/* Attach a file pointer with a read callback. */
Boolean ssh_file_buffer_attach_with_read_callback(SshFileBuffer buf,
                                      SshFileBufferReadCallback read_callback,
                                      void *read_context)
{
  SSH_ASSERT(buf != NULL);
  SSH_ASSERT(read_callback != NULL_FNPTR);
  ssh_file_buffer_detach(buf);
  buf->read_callback = read_callback;
  buf->read_context = read_context;
  return TRUE;
}

/* Return TRUE if file is attached to a buffer. */
Boolean ssh_file_buffer_attached(SshFileBuffer buf)
{
  SSH_ASSERT(buf != NULL);
  return (((buf->f != NULL) || (buf->read_callback != NULL_FNPTR))
          ? TRUE : FALSE);
}

/* Detach file.  Leave the buffer untouched. */
void ssh_file_buffer_detach(SshFileBuffer buf)
{
  SSH_ASSERT(buf != NULL);
  if (ssh_file_buffer_attached(buf))
    {
      if (buf->attached_as_fileptr)
        {
          buf->attached_as_fileptr = FALSE;
        }
      else
        {
          if (buf->f != NULL)
            fclose(buf->f);
        }
      buf->f = NULL;
      buf->read_callback = NULL_FNPTR;
      buf->read_context = NULL;
    }
  return;
}

/* Read attached file so that buffer size exceeds argument bytes. */
Boolean ssh_file_buffer_expand(SshFileBuffer buf, size_t bytes)
{
  size_t len, need_bytes;
  unsigned char *newdata;

  SSH_ASSERT(buf != NULL);
  len = ssh_buffer_len(&(buf->buf));
  if (len >= bytes)
    return TRUE;
  if (!ssh_file_buffer_attached(buf))
    return FALSE;
  need_bytes = bytes - len;
  bytes = ((need_bytes > SSH_FILE_BUFFER_MINIMUM_READ) ?
           need_bytes :
           SSH_FILE_BUFFER_MINIMUM_READ);
  (void)ssh_buffer_append_space(&(buf->buf), &newdata, bytes);
  SSH_ASSERT(newdata != NULL);
  if (buf->read_callback == NULL_FNPTR)
    {
      SSH_DEBUG(5, ("attempting to read %d bytes with fread", (int)bytes));
      len = fread(newdata, 1, bytes, buf->f);
    }
  else
    {
      SSH_DEBUG(5, ("attempting to read %d bytes with callback", (int)bytes));
      len = buf->read_callback(newdata, bytes, buf->read_context);
    }
  SSH_ASSERT(len <= bytes);
  if (len < need_bytes)
    {
      ssh_buffer_consume_end(&(buf->buf), bytes - len);
      ssh_file_buffer_detach(buf);
      return FALSE;
    }
  else if (len < bytes)
    {
      ssh_buffer_consume_end(&(buf->buf), bytes - len);
    }
  return TRUE;
}

/* eof (sshfilebuffer.c) */
