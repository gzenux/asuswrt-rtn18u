/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Versions of malloc and friends that check their results, and never return
   failure (they call fatal if they encounter an error).
*/

#include "sshincludes.h"

/* Note, these functions can be called from other threads also, thus
   cannot use any debugging macros (they can only be called from the
   SSH main thread).  Also note that you cannot call any other SSH
   library functions that are not marked thread safe from this file */
#undef SSH_DEBUG_MODULE

#undef malloc
#undef calloc
#undef realloc
#undef free
#undef memdup
#undef strdup

#ifdef SSH_DEBUG_MALLOC
#include "sshgetput.h"
#define SSH_DEBUG_MALLOC_SIZE_BEFORE    8
#define SSH_DEBUG_MALLOC_SIZE_AFTER     4
#define SSH_DEBUG_MALLOC_MAGIC_IN_USE   0x21041999
#define SSH_DEBUG_MALLOC_MAGIC_FREED    0x13061968
#define SSH_DEBUG_MALLOC_MAGIC_AFTER    0x99190214

#ifndef SSH_DEBUG_MALLOC_HEAVY
#define SSH_DEBUG_MALLOC_HEAVY
#endif /* not SSH_DEBUG_MALLOC_HEAVY */
#endif /* SSH_DEBUG_MALLOC */












#ifdef SSHDIST_PLATFORM_VXWORKS
#ifdef VXWORKS
#ifdef ENABLE_VXWORKS_RESTART_WATCHDOG
/* The ENABLE_VXWORKS_RESTART_WATCHDOG option creates an own memory
   partition for SSH applications running on VxWorks. With the usage
   of this option we can create "highly available" SSH VxWorks
   applications to handle fatal situations, like failed memory
   allocations or badly corrupted packets with the SecSH server,
   (basically calls to ssh_fatal() of ssh_fatal callback) all of which
   are potential sources of a "Denial of Service" attack (DoS).
   Further this prevents SSH applications consuming all memory from
   other VxWorks applications, that is with the SSH_MEM_QUOTA define
   below, we can define the maximum amount of memory the SSH
   application is allowed to use.

   The usage of this is very simple, when the application starts a
   call to ssh_mem_init() initializes, or re-initializes the memory
   pool. This enables the SSH application to safely restart itself
   without the fear of memory leaks */

/* The size of the memory quota for the SSH SecSH server. Currently
   2MB is more than enough, adjust this to fit your systems
   configuration needs */
#define SSH_MEM_QUOTA (2 * 1024 * 1024)

static PART_ID ssh_mem_partid = NULL;
static char *ssh_mem_quota = NULL;
static size_t ssh_mem_quota_size = 0;

/* In VxWorks there is no way to "delete" or "destroy" a memory
   partition, the reason to this is because that part of the code is
   not finished yet, and the memPartDestroy() needs to make sure that
   all mem used is properly returned to the partition and restored to
   original state or somehow reclamation should be done before a
   partition can be deleted.

   However, there is a (undocumented) memPartInit (PART_ID partId,
   char *pPool, unsigned poolSize); that allows reuse of a partition
   created with memPartCreate(). This clears the freelist of the
   partition to the state it was right after the memory partition was
   succesfully created for the first time with memPartCreate. */
int ssh_mem_restart(void)
{

  /* possibly recreate the VxWorks memory partition, */
  if (ssh_mem_partid)
    {
      memPartInit(ssh_mem_partid, ssh_mem_quota, ssh_mem_quota_size);
      return TRUE;
    }

  /* find the largest free block in the system memory partition */
  ssh_mem_quota_size = memFindMax();

  if (ssh_mem_quota_size > SSH_MEM_QUOTA)
    ssh_mem_quota_size = SSH_MEM_QUOTA;

  /* allocate a quota for the SSH VxWorks application */
  ssh_mem_quota = malloc(ssh_mem_quota_size);

  if (!ssh_mem_quota)
    return FALSE;

  /* clear the memory, note this cannot be done after memPartInit() */
  memset(ssh_mem_quota, 0, ssh_mem_quota_size);

  /* create the VxWorks memory partition, */
  ssh_mem_partid = memPartCreate(ssh_mem_quota, ssh_mem_quota_size);

  if (!ssh_mem_partid)
    {
      /* free the quota */
      free(ssh_mem_quota);
      return FALSE;
    }

  /* return success */
  return TRUE;
}

void ssh_mem_destroy(void)
{
  free(ssh_mem_quota);
  ssh_mem_quota = NULL;
}

void *ssh_mem_calloc(size_t nelem, size_t elsize)
{
  void *p;
  p = memPartAlloc(ssh_mem_partid, nelem * elsize);
  memset(p, 0, nelem * elsize);
  return p;
}

#define malloc(x) memPartAlloc(ssh_mem_partid, (x))
#define realloc(x,y) memPartRealloc(ssh_mem_partid, (x), (y))
#define calloc ssh_mem_calloc
#define free(x) memPartFree(ssh_mem_partid, (x))

#endif /* ENABLE_VXWORKS_RESTART_WATCHDOG */
#endif /* VXWORKS */
#endif /* SSHDIST_PLATFORM_VXWORKS */

/* Callback that is called if set when the malloc runs out of memory */
SSH_BSS_INITONCE
Boolean (*ssh_malloc_failed_cb)(void);

void *ssh_malloc(size_t size)
{
  void *ptr;

  if (size > XMALLOC_MAX_SIZE)
    return NULL;

  if (size == 0)
    size = 1;
#ifdef SSH_DEBUG_MALLOC
  while (1)
    {
      ptr = (void *)malloc((size_t)
                           size +
                           SSH_DEBUG_MALLOC_SIZE_BEFORE +
                           SSH_DEBUG_MALLOC_SIZE_AFTER);
      if (ptr != NULL)
        break;

      if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
        return NULL;
    }

  SSH_PUT_32BIT(ptr, size);
  SSH_PUT_32BIT((unsigned char *) ptr + 4, SSH_DEBUG_MALLOC_MAGIC_IN_USE);
  SSH_PUT_32BIT((unsigned char *) ptr + size + SSH_DEBUG_MALLOC_SIZE_BEFORE,
                SSH_DEBUG_MALLOC_MAGIC_AFTER);
  ptr = (unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
#ifdef SSH_DEBUG_MALLOC_HEAVY
  /* don't memset memory with purify, as it would mark the memory as
     "initialized" */
#ifndef WITH_PURIFY
  memset(ptr, 'A', size);
#endif /* WITH_PURIFY */
#endif /* SSH_DEBUG_MALLOC_HEAVY */
#else /* SSH_DEBUG_MALLOC */
  while (1)
    {
      ptr = (void *)malloc((size_t) size);
      if (ptr != NULL)
        break;
      if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
        return NULL;
    }
#endif /* SSH_DEBUG_MALLOC */
  return ptr;
}

void *ssh_calloc(size_t nitems, size_t size)
{
  void *ptr;

  if (nitems == 0)
    nitems = 1;
  if (size == 0)
    size = 1;

  if (size * nitems > XMALLOC_MAX_SIZE)
    return NULL;

#ifdef SSH_DEBUG_MALLOC
  while (1)
    {
      ptr = (void *)malloc(((size_t) nitems * (size_t) size) +
                           SSH_DEBUG_MALLOC_SIZE_BEFORE +
                           SSH_DEBUG_MALLOC_SIZE_AFTER);
      if (ptr != NULL)
        break;
      if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
        return NULL;
    }

  memset((unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE,
         0, (nitems * size));
  SSH_PUT_32BIT(ptr, (size * nitems));
  SSH_PUT_32BIT((unsigned char *) ptr + 4, SSH_DEBUG_MALLOC_MAGIC_IN_USE);
  SSH_PUT_32BIT((unsigned char *) ptr + (size * nitems) +
                SSH_DEBUG_MALLOC_SIZE_BEFORE,
                SSH_DEBUG_MALLOC_MAGIC_AFTER);
  ptr = (unsigned char *) ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
#else /* SSH_DEBUG_MALLOC */
  while (1)
    {
      ptr = (void *)calloc((size_t) nitems, (size_t) size);
      if (ptr != NULL)
        break;
      if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
        return NULL;
    }
#endif /* SSH_DEBUG_MALLOC */
  return ptr;
}

void *ssh_realloc(void *ptr,
                  size_t old_size, size_t new_size)
{
  void *new_ptr = NULL;

  if (ptr == NULL)
    return ssh_malloc(new_size);

  if (new_size > XMALLOC_MAX_SIZE)
    return NULL;

  if (new_size == 0)
    new_size = 1;

#ifdef SSH_DEBUG_MALLOC
  if (SSH_GET_32BIT((unsigned char *) ptr - 4) !=
      SSH_DEBUG_MALLOC_MAGIC_IN_USE)
    {
      if (SSH_GET_32BIT((unsigned char *) ptr - 4) ==
          SSH_DEBUG_MALLOC_MAGIC_FREED)
        ssh_fatal("Reallocating block that is already freed");

      ssh_fatal("Reallocating block that is either not mallocated, "
                "or whose magic number before the object was overwritten");
    }
  else
    {
      size_t osize;

      osize = SSH_GET_32BIT((unsigned char *) ptr -
                            SSH_DEBUG_MALLOC_SIZE_BEFORE);

      /* Zero check here for use of ssh_xrealloc (where the API does
         not know old size. One should not call ssh_realloc(p, 0,
         new), even if that now happens to work. */

      if (old_size != 0 && old_size != osize)
        ssh_fatal("Application concept of old size does not match "
                  "the block being reallocated: %zd vs %zd",
                  old_size, osize);

      if (SSH_GET_32BIT((unsigned char *) ptr + osize) !=
          SSH_DEBUG_MALLOC_MAGIC_AFTER)
        ssh_fatal("Reallocating block whose magic number after the "
                  "object was overwritten");

      /* Mark the old block freed */
      SSH_PUT_32BIT((unsigned char *) ptr - 4, SSH_DEBUG_MALLOC_MAGIC_FREED);
      SSH_PUT_32BIT((unsigned char *) ptr + osize,
                    SSH_DEBUG_MALLOC_MAGIC_FREED);

      while (1)
        {
          new_ptr = (void *)realloc((unsigned char *) ptr -
                                    SSH_DEBUG_MALLOC_SIZE_BEFORE,
                                    (size_t) new_size +
                                    SSH_DEBUG_MALLOC_SIZE_BEFORE +
                                    SSH_DEBUG_MALLOC_SIZE_AFTER);
          if (new_ptr != NULL)
            break;
          if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
            return NULL;
        }

      SSH_PUT_32BIT(new_ptr, new_size);
      SSH_PUT_32BIT((unsigned char *) new_ptr + 4,
                    SSH_DEBUG_MALLOC_MAGIC_IN_USE);
      SSH_PUT_32BIT((unsigned char *) new_ptr + new_size +
                    SSH_DEBUG_MALLOC_SIZE_BEFORE,
                    SSH_DEBUG_MALLOC_MAGIC_AFTER);
      new_ptr = (unsigned char *) new_ptr + SSH_DEBUG_MALLOC_SIZE_BEFORE;
    }
#else /* SSH_DEBUG_MALLOC */
  while (1)
    {
      new_ptr = (void *)realloc(ptr, (size_t) new_size);
      if (new_ptr != NULL)
        break;
      if (!ssh_malloc_failed_cb || !(*ssh_malloc_failed_cb)())
        return NULL;
    }
#endif /* SSH_DEBUG_MALLOC */
  return new_ptr;
}

/* coverity[ -tainted_data_sink : arg-0 ] */
void ssh_free(void *ptr)
{
#ifdef SSH_DEBUG_MALLOC
  if (ptr != NULL)
    {
      size_t size;

      if (SSH_GET_32BIT((unsigned char *) ptr - 4) !=
          SSH_DEBUG_MALLOC_MAGIC_IN_USE)
        {
          if (SSH_GET_32BIT((unsigned char *) ptr - 4) ==
              SSH_DEBUG_MALLOC_MAGIC_FREED)
            ssh_fatal("Freeing block that is already freed");
          ssh_fatal("Freeing block that is either not mallocated, "
                    "or whose magic number before the object was overwritten");
        }

      size = SSH_GET_32BIT((unsigned char *) ptr -
                           SSH_DEBUG_MALLOC_SIZE_BEFORE);
      if (SSH_GET_32BIT((unsigned char *) ptr + size) !=
          SSH_DEBUG_MALLOC_MAGIC_AFTER)
        ssh_fatal("Freeing block whose magic number after the object "
                  "was overwritten");

      /* Mark the old block freed */
      SSH_PUT_32BIT((unsigned char *) ptr - 4, SSH_DEBUG_MALLOC_MAGIC_FREED);
      SSH_PUT_32BIT((unsigned char *) ptr + size,
                    SSH_DEBUG_MALLOC_MAGIC_FREED);
#ifdef SSH_DEBUG_MALLOC_HEAVY
      SSH_CLEAR_MEMORY(ptr, size);
#endif /* SSH_DEBUG_MALLOC_HEAVY */
      free((unsigned char *) ptr - SSH_DEBUG_MALLOC_SIZE_BEFORE);
    }
#else /* SSH_DEBUG_MALLOC */
  if (ptr != NULL)
    free(ptr);
#endif /* SSH_DEBUG_MALLOC */
}

void *ssh_strdup(const void *p)
{
  const char *str;
  char *cp = NULL;

  if (p)
    {
      str = (const char *)p;
      if ((cp = ssh_malloc(strlen(str) + 1)) != NULL)
        strcpy(cp, str);
    }
  return (void *)cp;
}

void *ssh_memdup(const void *p, size_t len)
{
  const char *str = (const char *)p;
  char *cp = NULL;

  if (len < XMALLOC_MAX_SIZE)
    {
      if ((cp = ssh_malloc(len + 1)) != NULL)
        {
          memcpy(cp, str, (size_t)len);
          cp[len] = '\0';
        }
    }
  return (void *)cp;
}
