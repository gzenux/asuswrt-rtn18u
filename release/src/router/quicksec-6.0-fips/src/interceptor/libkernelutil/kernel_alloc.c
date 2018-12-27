/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implements the ssh_malloc and the deprecated ssh_xmalloc allocation
   APIs. This is done platform-independently by interfacing to the
   (interceptor's) platform-dependent ssh_kernel_* allocation routines.
*/

#ifndef VXWORKS
#include "sshincludes.h"
#include "kernel_alloc.h"
#include "kernel_mutex.h"

#define SSH_DEBUG_MODULE "SshEngineAlloc"

#ifndef ENGINE_MEMORY_DEBUG
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
  void *newp;

  if (oldptr == NULL)
    return ssh_kernel_alloc(newsize, flags);

  if (newsize <= oldsize)
    return oldptr;

  newp = ssh_kernel_alloc(newsize, flags);
  if (newp == NULL)
      return NULL;

  /* newsize > oldsize, see above */
  if (oldsize > 0)
    memcpy(newp, oldptr, oldsize);

  /* Success, thus we can release the old memory */
  ssh_kernel_free(oldptr);

  return newp;
}

void *
ssh_realloc(void *oldptr, size_t oldsize, size_t newsize)
{
  return ssh_realloc_flags(oldptr, oldsize, newsize, SSH_KERNEL_ALLOC_NOWAIT);
}

/* coverity[ -tainted_data_sink : arg-0 ] */
void ssh_free(void *ptr)
{
  if (ptr != NULL)
    ssh_kernel_free(ptr);
}

void *
ssh_calloc_flags(size_t nitems, size_t isize, SshUInt32 flags)
{
  void *ptr;
  size_t size;

  size = isize * nitems;

  ptr = ssh_malloc_flags(size ? size : 1, flags);
  if (ptr == NULL)
    return NULL;

  if (size > 0)
    memset(ptr, 0x0, size);

  return ptr;
}

void *
ssh_calloc(size_t nitems, size_t isize)
{
  return ssh_calloc_flags(nitems, isize, SSH_KERNEL_ALLOC_NOWAIT);
}

void *ssh_strdup(const void *p)
{
  const char *str;
  char *cp;

  SSH_PRECOND(p != NULL);

  str = (const char *)p;

  cp = (char *) ssh_malloc(strlen(str) + 1);
  if (cp == NULL)
    return NULL;

  ssh_strcpy(cp, str);

  return (void *)cp;
}

void *ssh_memdup(const void *p, size_t len)
{
  void *cp;

  cp = ssh_malloc(len + 1);
  if (cp == NULL)
    return NULL;

  memcpy(cp, p, (size_t)len);

  ((unsigned char *) cp)[len] = '\0';

  return cp;
}

#else /* ENGINE_MEMORY_DEBUG */

#define SSH_MEM_DEBUG_MAGIC 0xfeeddead

typedef struct SshMemDebugRec
{
  /* A linked list of debug allocations. */
  struct SshMemDebugRec *next;

  /* Information of the allocator. */
  const char *file;
  unsigned int line;

  /* The memory. */
  size_t size;
  void *memory;
  SshUInt32 safeguard;
  SshUInt32 magic;
} SshMemDebugStruct, *SshMemDebug;

/* OK, a kind of ackward solution for handling these,
   but debug_mutex is defined as a struct. This is since
   during uninit time we may still allocate memory and
   we do not wan't to touch the debug_head etc... items.
   So this mutex is used for protecting debug_initialized flag
   and debug_head. Unfortunately it is never uninitialized. */
#define DEBUG_FREELIST_SIZE 1024
#define DEBUG_HEAD_SIZE     1024

#define DEBUG_HEAD_OPTIMIZED 1
#undef DEBUG_HEAD_OPTIMIZED

SshKernelMutexStruct debug_mutex;
#ifndef DEBUG_HEAD_OPTIMIZED
SshMemDebug debug_head = NULL;
#else /* DEBUG_HEAD_OPTIMIZED */
SshMemDebug debug_head[DEBUG_HEAD_SIZE];
#endif /* DEBUG_HEAD_OPTIMIZED */
SshMemDebug debug_freelist;
SshUInt32 debug_freelist_items;
SshUInt32 debug_freelist_items_allocated;
SshUInt32 debug_freelist_items_freed;
Boolean debug_initialized = FALSE;
SshUInt32 debug_allocations_failed;
SshUInt32 debug_not_audited;
SshUInt32 debug_passed;
SshUInt32 debug_total_audited_allocated;
SshUInt32 debug_total_audited_freed;

#define SSH_DEBUG_HEAD_HASH(_ptr) \
  (((size_t)(_ptr) / DEBUG_HEAD_SIZE) % DEBUG_HEAD_SIZE)

void
ssh_kmalloc_freelist_uninit(SshMemDebug list)
{
  SshMemDebug next;

  while (list)
    {
      next = list->next;
      ssh_kernel_free(list);
      debug_freelist_items_freed++;
      debug_freelist_items--;

      list = next;
    }

  SSH_ASSERT(debug_freelist_items == 0);
}

SshMemDebug
ssh_kmalloc_freelist_get(void)
{
  SshMemDebug item;

  ssh_kernel_mutex_assert_is_locked(&debug_mutex);

  if (debug_freelist == NULL)
    {
      SSH_ASSERT(debug_freelist_items == 0);

      item = ssh_kernel_alloc(sizeof(SshMemDebugStruct),
                              SSH_KERNEL_ALLOC_NOWAIT);
      if (item != NULL)
        {
          debug_freelist_items_allocated++;
          item->magic = SSH_MEM_DEBUG_MAGIC;
        }

      return item;
    }
  else
    {
      SSH_ASSERT(debug_freelist_items > 0);

      item = debug_freelist;
      debug_freelist = item->next;
      debug_freelist_items--;
      SSH_ASSERT(debug_freelist_items < DEBUG_FREELIST_SIZE);

      SSH_ASSERT(item->magic == 0);
      item->magic = SSH_MEM_DEBUG_MAGIC;

      item->next = NULL;

      return item;
    }
}

void
ssh_kmalloc_freelist_put(SshMemDebug mem)
{
  SSH_ASSERT(mem != NULL);

  mem->next = NULL;

  ssh_kernel_mutex_assert_is_locked(&debug_mutex);

  if ((debug_freelist_items + 1) > DEBUG_FREELIST_SIZE)
    {
      SSH_ASSERT(debug_freelist_items == DEBUG_FREELIST_SIZE);

      debug_freelist_items_freed++;
      ssh_kernel_free(mem);
      return;
    }

  if (debug_freelist_items == 0)
    SSH_ASSERT(debug_freelist == NULL);

  memset(mem, 0x0, sizeof(SshMemDebugStruct));
  mem->magic = 0;

  mem->next = debug_freelist;
  debug_freelist = mem;
  debug_freelist_items++;

}

SshMemDebug
ssh_kmalloc_debug_freelist_init(SshUInt32 size)
{
  SshMemDebug tmp_list = NULL;
  SshMemDebug item;
  SshUInt32 i;

  ssh_kernel_mutex_assert_is_locked(&debug_mutex);

  for (i = 0; i < size; i++)
    {
      item = ssh_kernel_alloc(sizeof(SshMemDebugStruct),
                              SSH_KERNEL_ALLOC_NOWAIT);
      if (item == NULL)
        {
          ssh_kmalloc_freelist_uninit(tmp_list);
          return NULL;
        }

      memset(item, 0x0, sizeof(SshMemDebugStruct));
      item->magic = 0;
      debug_freelist_items_allocated++;
      debug_freelist_items++;

      item->next = tmp_list;
      tmp_list = item;
    }

  SSH_ASSERT(debug_freelist_items_allocated == size);
  SSH_ASSERT(debug_freelist_items == size);

  return tmp_list;
}

void
ssh_kmalloc_debug_init(void)
{
  ssh_kernel_mutex_init(&debug_mutex);

  ssh_kernel_mutex_lock(&debug_mutex);

#ifndef DEBUG_HEAD_OPTIMIZED
  debug_head = NULL;
#else /* DEBUG_HEAD_OPTIMIZED */
  memset(debug_head, 0x0, DEBUG_HEAD_SIZE * sizeof(SshMemDebug));
#endif /* DEBUG_HEAD_OPTIMIZED */

  debug_freelist_items_allocated = 0;
  debug_freelist_items_freed = 0;
  debug_freelist_items = 0;

  debug_freelist = ssh_kmalloc_debug_freelist_init(DEBUG_FREELIST_SIZE);
  if (debug_freelist == NULL)
    ssh_fatal("Debug freelist allocation failed!");

  debug_allocations_failed = 0;
  debug_not_audited = 0;
  debug_passed = 0;

  debug_initialized = TRUE;
  ssh_kernel_mutex_unlock(&debug_mutex);
}

void ssh_kmalloc_debug_uninit()
{
  SshMemDebug mem, next;
  SshUInt32 count = 0;
  size_t total_leaks = 0;
  SshUInt32 i = 0;

  /* Uninitialize debug. */
  ssh_kernel_mutex_lock(&debug_mutex);

  SSH_ASSERT(debug_initialized == TRUE);
  debug_initialized = FALSE;

  ssh_kernel_mutex_unlock(&debug_mutex);

#ifndef DEBUG_HEAD_OPTIMIZED
  mem = debug_head;
#else /* DEBUG_HEAD_OPTIMIZED */
  mem = debug_head[i];
#endif /* DEBUG_HEAD_OPTIMIZED */

#ifdef DEBUG_HEAD_OPTIMIZED
  while (i < DEBUG_HEAD_SIZE)
#else /* DEBUG_HEAD_OPTIMIZED */
  while (mem != NULL)
#endif /* DEBUG_HEAD_OPTIMIZED */
    {
      next = mem->next;

      /* We may call SSH_DEBUG here even though it allocates memory.
         We have disabled memory book keeping by setting
         debug_initialized = FALSE. */
      ssh_warning("Memleak: %p size %d from (%s:%d)",
                  mem->memory, mem->size, mem->file, mem->line);

      count++;
      total_leaks += mem->size;

      /* ssh_kernel_free(mem->memory); */
      ssh_kernel_mutex_lock(&debug_mutex);
      ssh_kmalloc_freelist_put(mem);
      ssh_kernel_mutex_unlock(&debug_mutex);

      mem = next;
#ifdef DEBUG_HEAD_OPTIMIZED
      if (mem == NULL)
        {
          while (mem == NULL && ++i < DEBUG_HEAD_SIZE)
            mem = debug_head[i];
        }
#endif /* DEBUG_HEAD_OPTIMIZED */
    }


  ssh_kmalloc_freelist_uninit(debug_freelist);

  if (count != 0)
    {
      ssh_warning("Total leaks: %d bytes in %u allocations",
                  total_leaks, count);

      ssh_warning("MEMORY DEBUG: allocated %u freed %u alloc failed %u"
                  " not audited %u passed %u freelist items %u "
                  "audited allocated %u audited freed %u",
                  debug_freelist_items_allocated,
                  debug_freelist_items_freed, debug_allocations_failed,
                  debug_not_audited, debug_passed, debug_freelist_items,
                  debug_total_audited_allocated, debug_total_audited_freed);
    }
  /* Here we leave the debug_mutex as initialized. */
  }

static inline void *
add_allocation(size_t size, const char *file,
               unsigned int line, SshUInt32 flags)
{
  char *ptr;
  SshMemDebug mem;
  SshUInt32 slot;

  ptr = ssh_kernel_alloc(size, flags);
  if (ptr == NULL)
    return NULL;

  ssh_kernel_mutex_lock(&debug_mutex);
  /* If the debug is still in working state, we may add this allocation into
     the debug lists. */
  if (debug_initialized == TRUE)
    {
      mem = ssh_kmalloc_freelist_get();
      if (mem == NULL)
        {
          /* Hmm, this we wont debug. */
          debug_allocations_failed++;
          goto unlock;
        }

      mem->size = size;
      mem->memory = ptr;
      mem->file = file;
      mem->line = line;

      debug_total_audited_allocated++;

      slot = SSH_DEBUG_HEAD_HASH(ptr);
      SSH_ASSERT(slot < DEBUG_HEAD_SIZE);

#ifdef DEBUG_HEAD_OPTIMIZED
      mem->next = debug_head[slot];
      debug_head[slot] = mem;
#else /* DEBUG_HEAD_OPTIMIZED */
      mem->next = debug_head;
      debug_head = mem;
#endif /* DEBUG_HEAD_OPTIMIZED */
    }
  else
    {
      debug_passed++;
    }

 unlock:
  ssh_kernel_mutex_unlock(&debug_mutex);

  return (void *)ptr;
}

static inline void remove_allocation(void *ptr)
{
  SshMemDebug pp, mem;
  SshUInt32 slot;
  Boolean found = FALSE;

  /* We leave here a potential timeframe that we are freeing this
     memory block and we are uninitializing this module. Unfortunate.
     This block is reported by uninit as a lost block. */
  ssh_kernel_mutex_lock(&debug_mutex);
  if (debug_initialized == TRUE)
    {
      slot = SSH_DEBUG_HEAD_HASH(ptr);
      SSH_ASSERT(slot < DEBUG_HEAD_SIZE);

#ifndef DEBUG_HEAD_OPTIMIZED
      mem = debug_head;
#else /* DEBUG_HEAD_OPTIMIZED */
      mem = debug_head[slot];
#endif /* DEBUG_HEAD_OPTIMIZED */
      if (mem == NULL)
        goto not_audited;

      if (ptr == mem->memory)
        {
          SSH_ASSERT(mem->magic == SSH_MEM_DEBUG_MAGIC);

#ifndef DEBUG_HEAD_OPTIMIZED
          debug_head = mem->next;
#else /* DEBUG_HEAD_OPTIMIZED */
          debug_head[slot] = mem->next;
#endif /* DEBUG_HEAD_OPTIMIZED */

          ssh_kmalloc_freelist_put(mem);
          found = TRUE;
          debug_total_audited_freed++;
          goto unlock;
        }
      else
        {
          /* Awfully slow way to find the allocation, but still
             working one. */
          for (pp = mem; pp; pp = pp->next)
            {
              if (pp->next->memory == ptr)
                {
                  mem = pp->next;
                  SSH_ASSERT(mem->magic == SSH_MEM_DEBUG_MAGIC);

                  pp->next = mem->next;
                  ssh_kmalloc_freelist_put(mem);
                  found = TRUE;
                  debug_total_audited_freed++;
                  goto unlock;
                }
            }
        }

    not_audited:
      debug_not_audited++;
    }
  else
    {
      debug_not_audited++;
    }

 unlock:
  ssh_kernel_mutex_unlock(&debug_mutex);
  ssh_kernel_free(ptr);
}

void *
ssh_kmalloc_flags_debug(size_t size, SshUInt32 flags,
                        const char *file, int line)
{
  return add_allocation(size, file, line, flags);
}

void *
ssh_kcalloc_flags_debug(unsigned long nitems, unsigned long size,
                        SshUInt32 flags, const char *file, int line)
{
  void *p;

  p = add_allocation(nitems * size, file, line, flags);
  if (p == NULL)
    return NULL;

  memset(p, 0x0, nitems * size);

  return p;
}

void *
ssh_krealloc_flags_debug(void *oldptr, size_t oldsize, size_t newsize,
                         SshUInt32 flags, const char *file, int line)
{
  void *newp;

  if (oldptr == NULL)
    return add_allocation(newsize, file, line, flags);

  if (newsize <= oldsize)
    return oldptr;

  newp = add_allocation(newsize, file, line, flags);
  if (newp == NULL)
    return NULL;

  if (oldsize > 0)
    memcpy(newp, oldptr, oldsize);

  /* Success, thus we can remove the old allocation */
  remove_allocation(oldptr);

  return newp;
}

void *
ssh_kmalloc_debug(size_t size, const char *file, int line)
{
  return ssh_kmalloc_flags_debug(size, SSH_KERNEL_ALLOC_NOWAIT, file, line);
}

void *
ssh_kcalloc_debug(unsigned long nitems, unsigned long size,
                  const char *file, int line)
{
  return ssh_kcalloc_flags_debug(nitems, size, SSH_KERNEL_ALLOC_NOWAIT,
                                 file, line);
}

void *
ssh_krealloc_debug(void *oldptr, size_t oldsize, size_t newsize,
                   const char *file, int line)
{
  return ssh_krealloc_flags_debug(oldptr, oldsize, newsize,
                                  SSH_KERNEL_ALLOC_NOWAIT, file, line);
}

void ssh_kfree_debug(void *ptr, const char *file, int line)
{
  if (ptr != NULL)
    remove_allocation(ptr);
}

void *
ssh_kstrdup_debug(const void *p, const char *file, int line)
{
  const char *str;
  char *cp;

  SSH_PRECOND(p != NULL);

  str = (const char *) p;

  cp = (char *)add_allocation(strlen(str) + 1, file, line,
                              SSH_KERNEL_ALLOC_NOWAIT);
  if (cp == NULL)
    return NULL;

  ssh_strcpy(cp, str);

  return (void *)cp;
}

void *
ssh_kmemdup_debug(const void *p, size_t len, const char *file, int line)
{
  void *cp;

  cp = add_allocation(len + 1, file, line, SSH_KERNEL_ALLOC_NOWAIT);
  if (cp == NULL)
    return NULL;

  memcpy(cp, p, (size_t)len);

  ((unsigned char *) cp)[len] = '\0';

  return cp;
}

#endif /* ENGINE_MEMORY_DEBUG */
#endif /* VXWORKS */
