/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Versions of malloc and friends that check their results, and
   never return failure (they call fatal if they encounter an
   error).
*/

#include "sshincludes.h"

/* Note, these functions are multithread safe, thus they can not call
   any MT-unsafe routines, notably debugging macros. */

#undef SSH_DEBUG_MODULE












void *ssh_xmalloc(size_t size)
{
  void *ptr;

  if ((ptr = ssh_malloc(size)) == NULL)
    ssh_fatal("ssh_xmalloc: Can not allocate %zd bytes of memory.", size);
  return ptr;
}

void *ssh_xcalloc(size_t nitems, size_t size)
{
  void *ptr;

  if ((ptr = ssh_calloc(nitems, size)) == NULL)
    ssh_fatal("ssh_xcalloc: Can not allocate %zd bytes of memory.", size);
  return ptr;
}

void *ssh_xrealloc(void *ptr, size_t new_size)
{
  void *new_ptr = NULL;

  if ((new_ptr = ssh_realloc(ptr, 0, new_size)) == NULL)
    ssh_fatal("ssh_xrealloc: Can not allocate %zd bytes of memory.", new_size);
  return new_ptr;
}

void ssh_xfree(void *ptr)
{
  ssh_free(ptr);
}

void *ssh_xstrdup(const void *p)
{
  char *cp;

  if (p == NULL)
    return NULL;

  if ((cp = ssh_strdup(p)) == NULL)
    ssh_fatal("ssh_xstrdup: Can not duplicate string.");

  return (void *)cp;
}

void *ssh_xmemdup(const void *p, size_t len)
{
  char *cp;

  if ((cp = ssh_memdup(p, len)) == NULL)
    {
      if (p && len > 0)
        ssh_fatal("ssh_xmemdup: Can not duplicate %d bytes of memory.", len);
    }
  return (void *)cp;
}
