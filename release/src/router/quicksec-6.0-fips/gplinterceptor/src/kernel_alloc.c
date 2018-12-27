/**
   The following copyright and permission notice must be included in all
   copies, modified as well as unmodified, of this file.

   This file is free software: you may copy, redistribute and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation, either version 2 of the License, or (at your
   option) any later version.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   This file incorporates work covered by the following copyright and
   permission notice:

   @copyright
   Copyright (c) 2010-2012, AuthenTec Inc, all rights reserved.

 */

/*
 * kernel_alloc.
 *
 * Engine memory allocation API implementation for kernel space.
 *
 */

#include "sshincludes.h"
#include "kernel_alloc.h"

void *
ssh_malloc_flags(size_t size, SshUInt32 flags)
{
  return ssh_kernel_alloc(size, flags);
}

void *
ssh_malloc(size_t size)
{
  return ssh_malloc_flags(size, SSH_KERNEL_ALLOC_NOWAIT);
}

void *
ssh_realloc_flags(void *oldptr, size_t oldsize, size_t newsize,
                  SshUInt32 flags)
{
  void * newptr;

  if (oldptr == NULL)
    return ssh_kernel_alloc(newsize, flags);

  if (newsize <= oldsize)
    return oldptr;

  if ((newptr = ssh_kernel_alloc(newsize, flags)) == NULL)
      return NULL;

  /* newsize > oldsize, see above */
  if (oldsize > 0)
    memcpy(newptr, oldptr, oldsize);

  /* Success, thus we can release the old memory */
  ssh_kernel_free(oldptr);

  return newptr;
}

void *
ssh_realloc(void * oldptr, size_t oldsize, size_t newsize)
{
  return ssh_realloc_flags(oldptr, oldsize, newsize, SSH_KERNEL_ALLOC_NOWAIT);
}

/* coverity[ -tainted_data_sink : arg-0 ] */
void ssh_free (void * ptr)
{
  if (ptr != NULL)
    ssh_kernel_free(ptr);
}

void*
ssh_calloc_flags (size_t nitems, size_t isize, SshUInt32 flags)
{
  void                * ptr;
  unsigned long       size;

  size = isize * nitems;

  if ((ptr = ssh_malloc_flags(size ? size : 1, flags)) == NULL)
    return NULL;

  if (size > 0)
    memset(ptr, 0, size);

  return ptr;
}

void *
ssh_calloc(size_t nitems, size_t isize)
{
  return ssh_calloc_flags(nitems, isize, SSH_KERNEL_ALLOC_NOWAIT);
}

void *ssh_strdup (const void * p)
{
  const char  * str;
  char        * cp;

  SSH_PRECOND(p != NULL);

  str = (const char *) p;

  if ((cp = (char *) ssh_malloc(strlen(str) + 1)) == NULL)
    return NULL;

  strcpy(cp, str);

  return (void *) cp;
}

void *ssh_memdup(const void * p, size_t len)
{
  void        * cp;

  if ((cp = ssh_malloc(len + 1)) == NULL)
    return NULL;

  memcpy(cp, p, (size_t)len);

  ((unsigned char *) cp)[len] = '\0';

  return cp;
}
