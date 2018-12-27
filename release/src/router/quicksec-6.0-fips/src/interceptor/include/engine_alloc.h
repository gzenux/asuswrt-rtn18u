/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface for allocation done by engine routines.

   The ssh_x* allocation routines are deprecated! Use ssh_k* routines
   instead and FIX THE RETURN VALUE CHECKING!
*/

#ifndef VXWORKS

#ifndef ENGINE_ALLOC_H
#define ENGINE_ALLOC_H

#define ENGINE_NEED_MEMORY_PROTOTYPES











#ifdef ENGINE_MEMORY_DEBUG

#define ssh_malloc(S)        ssh_kmalloc_debug((S), __FILE__, __LINE__)
#define ssh_calloc(N, S)     ssh_kcalloc_debug((N), (S), __FILE__, __LINE__)
#define ssh_realloc(P, O, N) ssh_krealloc_debug((P), (O), (N), \
                             __FILE__, __LINE__)

#define ssh_malloc_flags(S, F)        \
   ssh_kmalloc_flags_debug((S), (F), __FILE__, __LINE__)

#define ssh_calloc_flags(N, S, F)     \
   ssh_kcalloc_flags_debug((N), (S),(F),  __FILE__, __LINE__)

#define ssh_realloc_flags(P, O, N, F) \
   ssh_krealloc_flags_debug((P), (O), (N), (F), __FILE__, __LINE__)

#define ssh_free(P)          ssh_kfree_debug((P), __FILE__, __LINE__)
#define ssh_strdup(T)        ssh_kstrdup_debug((T), __FILE__, __LINE__)
#define ssh_memdup(P, S)     ssh_kmemdup_debug((P), (S), __FILE__, __LINE__)

void ssh_kmalloc_dump_allocations(void);

void *ssh_kmalloc_debug(size_t size, const char *, int);
void *ssh_kcalloc_debug(unsigned long nitems, unsigned long size,
                        const char *, int);
void *ssh_krealloc_debug(void *oldptr, size_t oldsize, size_t newsize,
                         const char *, int);

void *
ssh_kmalloc_flags_debug (size_t size, SshUInt32 flags,
                         const char * file, int line);

void *
ssh_kcalloc_flags_debug (unsigned long nitems, unsigned long size,
                         SshUInt32 flags,
                         const char * file, int line);

void *
ssh_krealloc_flags_debug (void * oldptr, size_t oldsize, size_t newsize,
                          SshUInt32 flags,
                          const char * file, int line);

void ssh_kfree_debug(void *ptr, const char *, int);
void *ssh_kstrdup_debug(const void *str, const char *, int);
void *ssh_kmemdup_debug(const void *mem, size_t len, const char *, int);
void ssh_kmalloc_debug_init(void);
void ssh_kmalloc_debug_uninit(void);

#else /* ENGINE_MEMORY_DEBUG */

#ifdef ENGINE_NEED_MEMORY_PROTOTYPES
void *ssh_malloc(size_t size);
void *ssh_malloc_flags(size_t size, SshUInt32 flags);
void *ssh_realloc(void *ptr, size_t old_size, size_t new_size);
void *ssh_realloc_flags(void *ptr, size_t old_size, size_t new_size,
                        SshUInt32 flags);
void *ssh_calloc(size_t nitems, size_t size);
void *ssh_calloc_flags(size_t nitems, size_t size, SshUInt32 flags);
void *ssh_strdup(const void *p);
void *ssh_memdup(const void *p, size_t len);
void ssh_free(void *ptr);
#endif /* ENGINE_NEED_MEMORY_PROTOTYPES */

#endif /* ENGINE_MEMORY_DEBUG */

#endif /* ENGINE_ALLOC_H */

#else /* VXWORKS */
/* for VxWorks we always use the "user-mode" allocators */
#define ssh_malloc_flags(a, b)     ssh_malloc((a))
#define ssh_calloc_flags(a, b, c)  ssh_calloc((a), (b))
#define ssh_realloc_flags(a, b, c) ssh_realloc((a), (b))
#endif /* VXWORKS */
