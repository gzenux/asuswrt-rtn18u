/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface (implemented by interceptor) for memory allocation in the
   kernel level.

   Notice that the engine-level allocation is done by ssh_k*alloc
   routines, not by the functions defined below! This API is meant to
   be implemented by interceptor and to be used only through single
   point in the engine code (engine_alloc.c).

   See engine_alloc.h for engine-level allocation definitions.
*/

#ifndef KERNEL_ALLOC_H
#define KERNEL_ALLOC_H

/* Allocate 'size' amount of memory, with the 'flag'
   parameters. Returns a NULL value if the allocation request cannot
   be satisfied for some reason.

   Notice: 'flag' is nothing more than a hint to the allocator. The
   allocator is free to ignore 'flag'. The allocatee is free to
   specify flag as ssh_rand() number, and the returned memory must still
   have the same semantics as any other memory block allocated. */
void *ssh_kernel_alloc(size_t size, SshUInt32 flag);

/* Flag is or-ed together of the following flags. */
#define SSH_KERNEL_ALLOC_NOWAIT 0x0000 /* allocation/use atomic. */
#define SSH_KERNEL_ALLOC_WAIT   0x0001 /* allow sleeping alloc/use. */
#define SSH_KERNEL_ALLOC_DMA    0x0002 /* allow DMA use. */
/* Other bits are usable for other purposes? */

/* Frees a previously allocated block of memory. */
void ssh_kernel_free(void *ptr);

/* Convention here: If KERNEL_ALLOC_USE_FUNCTIONS is defined, the
   interceptor *must* define the function interface. If
   KERNEL_ALLOC_USE_FUNCTIONS is undefined, it is free to either
   define functions, or use macros to directly access the kernel
   allocator or inline functions or anything (as long as it is correct
   implementation). */

#ifdef DEBUG_LIGHT
#define KERNEL_ALLOC_USE_FUNCTIONS
#endif /* DEBUG_LIGHT */

#ifdef KERNEL
/* This must be in the -I path of the machine-dependent interceptor
   dir. It defines any platform-dependent things (such as the inline
   functions, if KERNEL_ALLOC_USE_FUNCTIONS is not defined). */
#include "platform_kernel_alloc.h"
#endif

#endif /* KERNEL_ALLOC_H */
