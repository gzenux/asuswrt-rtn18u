/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Versions of malloc and friends that check their results, and never
   return failure (they call fatal if they encounter an error).

   <keywords malloc, utility functions/malloc>

   Note: These functions MUST be multi-thread safe if the system is using
   threads.

   @internal
*/

#ifndef SSHMALLOC_H
#define SSHMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

/* This XMALLOC_MAX_SIZE is the maximum size that x*alloc routines can allocate
   with one call. */

#ifdef WINDOWS
#ifdef WIN32
#define XMALLOC_MAX_SIZE (100*1024L*1024L)
#else  /* WIN32 */
#define XMALLOC_MAX_SIZE 65500L
#endif  /* WIN32 */
#else  /* WINDOWS */
#define XMALLOC_MAX_SIZE (1024*1024L*1024L)
#endif /* WINDOWS */

#ifdef DEBUG_LIGHT
 #define SSH_DEBUG_MALLOC
 #define SSH_CLEAR_MEMORY(x, y) memset(x, 'F', y)

# ifdef __STRICT_ANSI__
#  undef SSH_DEBUG_MALLOC
# endif /* __STRICT_ANSI__ */
#else /* DEBUG_LIGHT */
#define SSH_CLEAR_MEMORY(x, y)
#endif /* DEBUG_LIGHT */

#ifdef SSH_DISABLE_DEBUG_MALLOC
#undef SSH_DEBUG_MALLOC
#endif /* SSH_DISABLE_DEBUG_MALLOC */

#ifdef __COVERITY__
#undef SSH_DEBUG_MALLOC
#undef SSH_CLEAR_MEMORY
#define SSH_CLEAR_MEMORY(x, y)
#endif /* __COVERITY__ */

/**  Like malloc, but calls ssh_fatal() if out of memory.  Allocating
     zero bytes is permitted, and results in a valid object. */
void *
ssh_xmalloc(size_t size);

void *
ssh_malloc(size_t size);

/**  Like realloc, but calls ssh_fatal() if out of memory.

     @param ptr
     May be NULL, in which case this behaves like ssh_xmalloc.

     @param new_size
     May be zero, in which case a valid object is returned.

     @return
     The size of memory block returned in case of 0 byte allocation
     will be 1 (one).

     */
void *
ssh_xrealloc(void *ptr, size_t new_size);

void *
ssh_realloc(void *ptr, size_t old_size, size_t new_size);

/**  Allocates a buffer of size nitems*size, and fills the buffer with
     zeroes.  It is guaranteed that allocating zero bytes works, and
     returns a valid object.  */
void *
ssh_xcalloc(size_t nitems, size_t size);

void *
ssh_calloc(size_t nitems, size_t size);

/**  Frees memory allocated using ssh_xmalloc or ssh_xrealloc.

     @param ptr
     If ptr is NULL, nothing is done.

     */
void
ssh_xfree(void *ptr);

void ssh_free(void *ptr);

/**  Allocates memory using ssh_xmalloc, and copies the string into that
     memory.  This takes and returns void pointers so that this can also
     be used for unsigned char strings. Duplicating a NULL pointer results
     into a NULL pointer. */
void *
ssh_xstrdup(const void *str);

void *
ssh_strdup(const void *str);

/**  Allocates memory using ssh_xmalloc, and copies the buffer into that
     memory.  This takes and returns void pointers so that this can also
     be used for unsigned char strings. Note that the string will
     always be null-terminated.

     @return
     The returned pointer is properly aligned for any type of data.
     Duplicating a NULL pointer results in an empty string (i.e., a
     valid pointer, with the first character being the null
     character).

     */
void *
ssh_xmemdup(const void *str, size_t len);

void *
ssh_memdup(const void *data, size_t len);


/**  Realloc ptr table to bigger.

     @param ptr
     The ptr points to an address containing the pointer to the
     beginning of the table. The ptr is modified to contain new
     address if this call is successful. The same value is also
     returned.

     @param cnt_ptr
     The cnt_ptr is a pointer to the integer containing the number of
     items in the table and it will be modified to contain the new
     number of items.

     @param new_cnt
     The table is reallocated to contain new_cnt number of items of
     size item_size. The newly allocated items are filled with zeros.

     @param item_size
     The size of the items allocated to the table.

     @return
     If the realloc fails, then *ptr and *cnt_ptr are left untouched
     and FALSE is returned. If operation was successful then it
     returns TRUE.

     */
Boolean ssh_recalloc(void *ptr, SshUInt32 *cnt_ptr, SshUInt32 new_cnt,
                     size_t item_size);


extern Boolean (*ssh_malloc_failed_cb)(void);

typedef enum {
  SSH_MALLOC_STATE_NORMAL = 0,
  SSH_MALLOC_STATE_MEMORY_LOW = 1,
  SSH_MALLOC_STATE_MEMORY_CRITICAL = 2
} SshMallocState;

/**  Out of memory signaling function. This function is called to
     signal a change in the memory allocation system.

     When this is called with state set to SSH_MALLOC_STATE_MEMORY_LOW
     then it means that the memory resources are low, and we should
     start cleaning up the memory and free some more memory. The
     function can call malloc, but it should not allocate too much.
     This MEMORY_LOW state can insert timeouts, and to protect
     subsystems data structures this normally should just simply
     insert one 0 time timeout and do all the work there (otherwise it
     might be possible that you are in the middle of the allocation
     process for something and the internal data structures of the
     subsystem are not consistent because of that).

     This is called with state set to SSH_MALLOC_STATE_MEMORY_CRITICAL
     when we do not have enough memory in main pool to satisfy the
     requested memory allocation operation. In this case, this
     function SHOULD NOT allocate anything, but it should start
     limiting the other memory allocation operations happening later.

     It might for example put on the flag that will drop all new
     tcp/ip connections immediately, without allocating anything until
     the memory shortage goes away.

     When the allocation systems is able to regain the spare memory
     pools, it will call this function again with state set to
     SSH_MALLOC_STATE_MEMORY_LOW or SSH_MALLOC_STATE_NORMAL. This
     means that new connections etc can be allowed again.

     */
typedef void (*SshMallocSignalFunction)(SshMallocState state,
                                        void *context);

/**  Register a signal function to allocation system. Signal functions
     will be called when there is a change in the memory allocation
     system status. */
void ssh_malloc_signal_function_register(SshMallocSignalFunction func,
                                         void *context);

/**  Deregister signal function from the allocation function. After
     this call the signal function is no longer called. */
void ssh_malloc_signal_function_unregister(SshMallocSignalFunction func,
                                           void *context);

/**  Change amount of spare buffers needed by the system. The signed
     32-bit number is added to the size of the spare buffer. In the
     initialization this function is called with positive number that
     is the maximum amount of memory the subsystem needs to be able to
     work after the signal function is called. When the subsystem is
     uninitialized it must call this function with negative amount
     that lowers the spare buffer size by the amount it added there.
     One subsystem can call this function multiple times, i.e it can
     raise the amount of memory needed depending on the activity. */
void ssh_malloc_change_spare_buffer_size(SshInt32 change_in_bytes);

/**  Return the current state of the memory allocation system.
     This can be used to select suitable algorithms depending if you
     have lots of memory of if you are almost running out of the
     memory. */
SshMallocState ssh_malloc_get_state(void);
















































































































#ifdef __cplusplus
}
#endif

#endif /* SSHMALLOC_H */
