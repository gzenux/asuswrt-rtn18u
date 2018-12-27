/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshbufaux.h
*/

#ifndef BUFAUX_H
#define BUFAUX_H

#include "sshbuffer.h"

/* Returns a 32-bit integer from the buffer (4 bytes, msb first). */
unsigned long ssh_bufaux_get_int(SshBuffer buffer);

/* Stores a 32-bit integer in the buffer in 4 bytes, msb first. */
void ssh_bufaux_put_int(SshBuffer buffer, unsigned long value);

/* Returns a character from the buffer (0 - 255). */
unsigned int ssh_bufaux_get_char(SshBuffer buffer);

/* Stores a character in the buffer. */
void ssh_bufaux_put_char(SshBuffer buffer, unsigned int value);

/* Store a boolean into the buffer. */
void ssh_bufaux_put_boolean(SshBuffer buffer, Boolean value);

/* Get it */
Boolean ssh_bufaux_get_boolean(SshBuffer buffer);

/* Returns an arbitrary binary string from the buffer.  The string
   cannot be longer than 256k.  The returned value points to memory
   allocated with ssh_xmalloc; it is the responsibility of the calling
   function to free the data.  If length_ptr is non-NULL, the length
   of the returned data will be stored there.  A null character will
   be automatically appended to the returned string, and is not
   counted in length. */
void *ssh_bufaux_get_uint32_string(SshBuffer buffer, size_t *length_ptr);

/* Stores and arbitrary binary string in the buffer.  NOTE: this
   format uses uint32 length. */
void ssh_bufaux_put_uint32_string(SshBuffer buffer,
                                  const void *buf, size_t len);


#endif /* BUFAUX_H */
