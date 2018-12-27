/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Functions for manipulating fifo buffers (that can grow if needed).
   Based on the Tatu Ylonen's implementation from 1995

   Original was copywritten by Tatu Ylonen <ylo@cs.hut.fi>.
*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshBuffer"

#ifdef DEBUG_HEAVY
/* Provoke errors. */
#define SSH_BUFFER_MALLOC_SLOP  1
#define SSH_BUFFER_BASE_SIZE    2
#else
#define SSH_BUFFER_MALLOC_SLOP  32
#define SSH_BUFFER_BASE_SIZE    512
#endif

#define SSH_BUFFER_SIZE(x)                              \
  (SSH_BUFFER_BASE_SIZE * (x) - SSH_BUFFER_MALLOC_SLOP)

static const size_t ssh_buffer_size[] =
{
  0,
  SSH_BUFFER_SIZE(1),
  SSH_BUFFER_SIZE(2),
  SSH_BUFFER_SIZE(3),
  SSH_BUFFER_SIZE(5),
  SSH_BUFFER_SIZE(8),
  SSH_BUFFER_SIZE(13),
  SSH_BUFFER_SIZE(21),
  SSH_BUFFER_SIZE(34),
  SSH_BUFFER_SIZE(55),
  SSH_BUFFER_SIZE(89),
  SSH_BUFFER_SIZE(144),
  SSH_BUFFER_SIZE(233),
  SSH_BUFFER_SIZE(377),
  SSH_BUFFER_SIZE(610),
  SSH_BUFFER_SIZE(987),
  SSH_BUFFER_SIZE(1597),
  SSH_BUFFER_SIZE(2584),
  SSH_BUFFER_SIZE(4181),
  SSH_BUFFER_SIZE(6765),
  SSH_BUFFER_SIZE(10946),
  SSH_BUFFER_SIZE(17711),
  SSH_BUFFER_SIZE(28657),
  SSH_BUFFER_SIZE(46368),
  SSH_BUFFER_SIZE(75025),
  SSH_BUFFER_SIZE(121393),
  SSH_BUFFER_SIZE(196418),
  SSH_BUFFER_SIZE(317811),
  SSH_BUFFER_SIZE(514229),
  SSH_BUFFER_SIZE(832040),
  SSH_BUFFER_SIZE(1346269),
  SSH_BUFFER_SIZE(2178309),
  SSH_BUFFER_SIZE(3524578),
#if 0
  /* These would overflow, use 2^32 - 255 instead. */
  SSH_BUFFER_SIZE(5702887),
  SSH_BUFFER_SIZE(9227465),
  SSH_BUFFER_SIZE(14930352),
  SSH_BUFFER_SIZE(24157817),
  SSH_BUFFER_SIZE(39088169),
  SSH_BUFFER_SIZE(63245986),
  SSH_BUFFER_SIZE(102334155),
  SSH_BUFFER_SIZE(165580141),
  SSH_BUFFER_SIZE(267914296),
  SSH_BUFFER_SIZE(433494437),
  SSH_BUFFER_SIZE(701408733),
  SSH_BUFFER_SIZE(1134903170),
  SSH_BUFFER_SIZE(1836311903),
  SSH_BUFFER_SIZE(2971215073),
#else
  0xFFFFFF00UL,
#endif
  0
};


/* Allocates a new buffer. */
SshBuffer ssh_buffer_allocate(void)
{
  SshBuffer buffer = ssh_malloc(sizeof(*buffer));

  if (buffer)
    {
      ssh_buffer_init(buffer);
      buffer->dynamic = TRUE;
    }
  return buffer;
}

/* Zeroes and frees the buffer. */

void ssh_buffer_free(SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(buffer->dynamic);

  ssh_buffer_uninit(buffer);
  ssh_free(buffer);
}

/* Initializes the buffer structure. */

void ssh_buffer_init(SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);

  buffer->offset = 0;
  buffer->end = 0;
  buffer->dynamic = FALSE;
  buffer->borrowed = FALSE;
  buffer->size_index = 0;
  buffer->alloc = 0;
  buffer->buf = NULL;
}

/* Frees any memory used for the buffer. */

void ssh_buffer_uninit(SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);

  if (buffer->buf && !buffer->borrowed)
    {
      /* memset to clear away all possible sensitive information. */
      memset(buffer->buf, 0, buffer->alloc);
      ssh_free(buffer->buf);
    }
}


/* Wrap a given memory area `mem' of length `n_bytes' inside the given
   SshBuffer `buf'.  The `buffer' is assumed uninited. */

void ssh_buffer_wrap(SshBuffer buffer, unsigned char *mem, size_t n_bytes)
{
  Boolean was_dynamic;

  SSH_ASSERT(mem != NULL);

  was_dynamic = buffer->dynamic;
  ssh_buffer_init(buffer);
  buffer->buf = mem;
  buffer->alloc = n_bytes;
  buffer->borrowed = TRUE;
  buffer->dynamic = was_dynamic;
}


/* Move the buffer's content to the beginning of the allocated memory,
   realloc it to the current size, and leave the buffer in an uninited
   state. */

unsigned char *ssh_buffer_steal(SshBuffer buffer, size_t *len)
{
  unsigned char *buf = buffer->buf;
  Boolean was_dynamic;

  if (buf != NULL && buffer->offset > 0)
    {
      memmove(buf, buf + buffer->offset, buffer->end - buffer->offset);
      buffer->end -= buffer->offset;
    }

  if (!buffer->borrowed)
    {
      unsigned char *tmp;

      if ((tmp = ssh_realloc(buf, buffer->alloc, buffer->end)) == NULL)
        {
          ssh_free(buf);
          buffer->buf = NULL;
          if (len != NULL) *len = 0;
          return NULL;
        }
      buf = tmp;
    }

  if (len != NULL)
    *len = (buf) ? buffer->end: 0;

  was_dynamic = buffer->dynamic;
  ssh_buffer_init(buffer);
  buffer->dynamic = was_dynamic;
  return buf;
}


/* Clears any data from the buffer, making it empty.  This does not actually
   zero the memory. */

void ssh_buffer_clear(SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);

  buffer->offset = 0;
  buffer->end = 0;
}

/* Appends data to the buffer, expanding it if necessary. */

SshBufferStatus
ssh_buffer_append(SshBuffer buffer, const unsigned char *data, size_t len)
{
  unsigned char *cp;
  SshBufferStatus status = SSH_BUFFER_OK;

  SSH_ASSERT(buffer != NULL);

  status = ssh_buffer_append_space(buffer, &cp, len);
  if (status == SSH_BUFFER_OK && len > 0)
    memcpy(cp, data, len);
  return status;
}

/* Appends space to the buffer, expanding the buffer if necessary.
   This does not actually copy the data into the buffer, but instead
   returns a pointer to the allocated region. */

SshBufferStatus
ssh_buffer_append_space(SshBuffer buffer, unsigned char **datap, size_t len)
{
  unsigned char *tmp;
  SshUInt16 new_size_index;

  SSH_ASSERT(buffer != NULL);

  /* Now allocate the buffer space if not done already. */
  if (buffer->buf == NULL)
    {
      SSH_ASSERT(!buffer->borrowed);

      if (buffer->alloc == 0)
        {
          buffer->size_index = 1;
          buffer->alloc = ssh_buffer_size[buffer->size_index];
        }
      buffer->buf = ssh_malloc(buffer->alloc);
      if (buffer->buf == NULL)
        return SSH_BUFFER_ERROR;
    }

  /* If the buffer is empty, start using it from the beginning. */
  if (buffer->offset == buffer->end)
    {
      buffer->offset = 0;
      buffer->end = 0;
    }

 restart:
  /* If there is enough space to store all data, store it now. */
  if (buffer->end + len <= buffer->alloc)
    {
      *datap = buffer->buf + buffer->end;
      buffer->end += len;
      return SSH_BUFFER_OK;
    }

  /* If the buffer is quite empty, but all data is at the end, move
     the data to the beginning and retry.  Do this also if the buffer
     is borrowed, since we can't realloc it in any case. */
  if (buffer->offset > buffer->alloc / 2
      || (buffer->borrowed && buffer->offset != 0))
    {
      memmove(buffer->buf, buffer->buf + buffer->offset,
              buffer->end - buffer->offset);
      buffer->end -= buffer->offset;
      buffer->offset = 0;
      goto restart;
    }

  /* If the buffer is borrowed, then don't proceed, because we can
     increase the buffer size in any case, and hence we have already
     failed. */
  if (buffer->borrowed)
    return SSH_BUFFER_ERROR;

  /* Increase the size of the buffer and retry. */
  new_size_index = buffer->size_index + 1;
  while (ssh_buffer_size[new_size_index] != 0 &&
         ssh_buffer_size[new_size_index] <= buffer->end + len)
    new_size_index++;
  if (ssh_buffer_size[new_size_index] == 0)
    return SSH_BUFFER_ERROR;

  tmp = ssh_realloc(buffer->buf,
                    buffer->alloc,
                    ssh_buffer_size[new_size_index]);
  if (tmp)
    {
      buffer->buf = tmp;
      buffer->size_index = new_size_index;
      buffer->alloc = ssh_buffer_size[new_size_index];
      goto restart;
    }

  /* Realloc failed. */
  return SSH_BUFFER_ERROR;
}


/* Appends NUL-terminated C-strings <...> to the buffer.  The argument
   list must be terminated with a NULL pointer. */

SshBufferStatus ssh_buffer_append_cstrs(SshBuffer buffer, ...)
{
  va_list ap;
  SshBufferStatus status = SSH_BUFFER_OK;

  va_start(ap, buffer);

  status = ssh_buffer_append_cstrs_va(buffer, ap);

  va_end(ap);
  return status;
}

SshBufferStatus ssh_buffer_append_cstrs_va(SshBuffer buffer, va_list ap)
{
  char *str;
  SshBufferStatus status = SSH_BUFFER_OK;

  while (status == SSH_BUFFER_OK && (str = va_arg(ap, char *)) != NULL)
    status = ssh_buffer_append(buffer, (unsigned char *) str, strlen(str));

  return status;
}


/* Returns the number of bytes of data in the buffer. */

size_t ssh_buffer_len(const SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(buffer->offset <= buffer->end);

  return buffer->end - buffer->offset;
}

/* Returns the number of bytes allocated, but not yet in use. */

size_t ssh_buffer_space(const SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(buffer->offset <= buffer->end);
  SSH_ASSERT(buffer->end <= buffer->alloc);

  return buffer->alloc - buffer->end;
}

/* Consumes the given number of bytes from the beginning of the buffer. */

void ssh_buffer_consume(SshBuffer buffer, size_t bytes)
{
  if (bytes > buffer->end - buffer->offset)
    ssh_fatal("buffer_consume trying to get more bytes than in buffer");
  buffer->offset += bytes;
}

/* Consumes the given number of bytes from the end of the buffer. */

void ssh_buffer_consume_end(SshBuffer buffer, size_t bytes)
{
  if (bytes > buffer->end - buffer->offset)
    ssh_fatal("buffer_consume_end trying to get more bytes than in buffer");
  buffer->end -= bytes;
}

/* Returns a pointer to the first used byte in the buffer. */

unsigned char *ssh_buffer_ptr(const SshBuffer buffer)
{
  SSH_ASSERT(buffer != NULL);
  SSH_ASSERT(buffer->offset <= buffer->end);

  if (buffer->buf == NULL || ssh_buffer_len(buffer) == 0)
    return NULL;

  return buffer->buf + buffer->offset;
}
