/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Auxiliary functions for storing and retrieving various data types
   to/from Buffers.
*/

#include "sshincludes.h"
#include "sshbufaux.h"
#include "sshgetput.h"

#define SSH_DEBUG_MODULE "SshBufferAux"

/* Returns an integer from the buffer (4 bytes, msb first). */
unsigned long ssh_bufaux_get_int(SshBuffer buffer)
{
  unsigned long val = 0;
  unsigned char *buf;

  if (ssh_buffer_len(buffer) >= 4)
    {
      /* just to not have function call as assembly optimized macro
         argument. */
      buf = ssh_buffer_ptr(buffer);
      val = SSH_GET_32BIT(buf);
      ssh_buffer_consume(buffer, 4);
    }
  return val;
 }

/* Stores an integer in the buffer in 4 bytes, msb first. */

void ssh_bufaux_put_int(SshBuffer buffer, unsigned long value)
{
  unsigned char buf[4];

  SSH_PUT_32BIT(buf, value);
  ssh_xbuffer_append(buffer, buf, 4);
}


/* Returns an arbitrary binary string from the buffer.  The string
   cannot be longer than 256k.  The returned value points to memory
   allocated with ssh_xmalloc; it is the responsibility of the calling
   function to free the data.  If length_ptr is non-NULL, the length
   of the returned data will be stored there.  A null character will
   be automatically appended to the returned string, and is not
   counted in length. */

void *ssh_bufaux_get_uint32_string(SshBuffer buffer, size_t *length_ptr)
{
  size_t len;
  unsigned char *value;

  /* Get the length. */
  len = ssh_bufaux_get_int(buffer);
  if (len > XMALLOC_MAX_SIZE)
    ssh_fatal("Received packet with bad string length %d", len);
  /* Allocate space for the string.  Add one byte for a null character. */

  if ((value = ssh_malloc(len + 1)) != NULL)
    {
      memcpy(value, ssh_buffer_ptr(buffer), len);
      ssh_buffer_consume(buffer, len);
      value[len] = 0;
    }
  else
    len = 0;

  if (length_ptr)
    *length_ptr = len;

  return value;
}

/* Stores and arbitrary binary string in the buffer. */

void
ssh_bufaux_put_uint32_string(SshBuffer buffer,
                             const void *buf, size_t len)
{
  ssh_bufaux_put_int(buffer, len);
  ssh_xbuffer_append(buffer, buf, len);
}

/* Returns a character from the buffer (0 - 255). */

unsigned int ssh_bufaux_get_char(SshBuffer buffer)
{
  unsigned char ch = 0;

  if (ssh_buffer_len(buffer) > 0)
    {
      ch = *(ssh_buffer_ptr(buffer));
      ssh_buffer_consume(buffer, 1);
    }
  return ch;
}

/* Stores a character in the buffer. */

void ssh_bufaux_put_char(SshBuffer buffer, unsigned int value)
{
  unsigned char ch = value;
  ssh_xbuffer_append(buffer, &ch, 1);
}

void ssh_bufaux_put_boolean(SshBuffer buffer, Boolean value)
{
  if (value)
    ssh_bufaux_put_char(buffer, 1);
  else
    ssh_bufaux_put_char(buffer, 0);
}

Boolean ssh_bufaux_get_boolean(SshBuffer buffer)
{
  int value = ssh_bufaux_get_char(buffer);
  if (value == 0)
    return FALSE;
  return TRUE;
}
