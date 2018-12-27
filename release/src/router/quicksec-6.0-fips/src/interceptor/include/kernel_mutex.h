/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A simple mutex-type lock that can be used in the IPSEC engine.
   Depending on the configuration, the mutex might be implemented as a
   no-op, a spinlock, a real mutex, disabling interrupts (with a count of
   number of mutexes), setting spl level, etc.
*/

#ifndef KERNEL_MUTEX_H
#define KERNEL_MUTEX_H

typedef struct SshKernelMutexRec *SshKernelMutex;
typedef struct SshKernelRWMutexRec *SshKernelRWMutex;
typedef struct SshKernelCriticalSectionRec *SshKernelCriticalSection;

/* Implements a mutex debugging facility for VxWorks, shows all tasks
   which have allocated and taken a mutex, and the location in code */
/* #define ENGINE_MUTEX_DEBUG */


#ifndef ENGINE_MUTEX_DEBUG
/* Allocates and initializes a simple mutex.  This should be as fast as
   possible, but work between different processors in a multiprocessor
   machine. Also, it is a fatal error for a thread to attempt to lock
   this twice (i.e., this need not check whether it is actually held
   by the same thread).  The recommended implementation is a spinlock. */
SshKernelMutex ssh_kernel_mutex_alloc(void);

/* Initializes a mutex allocated from the stack. Returns TRUE on success
   and FALSE on failure. */
Boolean ssh_kernel_mutex_init(SshKernelMutex mutex);

/* Frees the given mutex.  The mutex must not be locked when it is
   freed. */
void ssh_kernel_mutex_free(SshKernelMutex mutex);

/* Uninitializes the given mutex.  The mutex must not be locked when it is
   uninitialized. */
void ssh_kernel_mutex_uninit(SshKernelMutex mutex);

/* Locks the mutex. Only one thread of execution can have a mutex locked
   at a time.  This will block until execution can continue.  One should
   not keep mutexes locked for extended periods of time. */
void ssh_kernel_mutex_lock(SshKernelMutex mutex);

/* Unlocks the mutex. The mutex must be unlocked from the same thread
   from which it was locked. If other threads are waiting to lock the mutex,
   one of them will get the lock and continue execution. */
void ssh_kernel_mutex_unlock(SshKernelMutex mutex);

#else /* ENGINE_MUTEX_DEBUG */

#define ssh_kernel_mutex_alloc() ssh_kernel_mutex_alloc_i(__FILE__, __LINE__)
#define ssh_kernel_mutex_init(m) ssh_kernel_mutex_init_i((m))
#define ssh_kernel_mutex_uninit(m) ssh_kernel_mutex_uninit_i((m))
#define ssh_kernel_mutex_free(m) ssh_kernel_mutex_free_i((m))

#define ssh_kernel_mutex_lock(m) \
  ssh_kernel_mutex_lock_i((m), __FILE__, __LINE__)
#define ssh_kernel_mutex_unlock(m) \
  ssh_kernel_mutex_unlock_i((m), __FILE__, __LINE__)

void ssh_kernel_mutex_lock_i(SshKernelMutex mutex, const char *, int);
void ssh_kernel_mutex_unlock_i(SshKernelMutex mutex, const char *, int);

#endif /* ENGINE_MUTEX_DEBUG */

#ifdef DEBUG_LIGHT
/* Check that the mutex is locked.  It is a fatal error if it is not. */
void ssh_kernel_mutex_assert_is_locked(SshKernelMutex mutex);
#else /* DEBUG_LIGHT */
#define ssh_kernel_mutex_assert_is_locked(mutex)
#endif /* DEBUG_LIGHT */

/* Allocates and initializes a reader-writer mutex. Reader-Writer mutexes
   allow multiples threads to hold a reader lock but only a single thread
   to hold a writer lock. This should be as fast as possible, but work
   between different processors in a multiprocessor machine. Also, it
   is a fatal error for a thread to attempt to write lock this twice
   (i.e., this need not check whether it is actually held by the same
   thread).  The recommended implementation is a spinlock. */
SshKernelRWMutex ssh_kernel_rw_mutex_alloc(void);

/* Initializes a mutex allocated from the stack. Returns TRUE on success
   and FALSE on failure. */
Boolean ssh_kernel_rw_mutex_init(SshKernelRWMutex mutex);

/* Uninitializes the given mutex.  The mutex must not be locked when it is
   uninitialized. */
void ssh_kernel_rw_mutex_uninit(SshKernelRWMutex mutex);

/* Frees the given mutex.  The mutex must not be locked when it is
   freed. */
void ssh_kernel_rw_mutex_free(SshKernelRWMutex mutex);

/* Takes a read lock on the mutex. Multiple threads of execution can
   have a mutex read locked at a time. There is no limit on the number
   of threads that can concurrently hold a reader lock. If a write lock
   is currently held, this will block until execution can continue by
   release of the write lock. The calling code must not modify any data
   protected by this lock when holding the read lock. One should not keep
   mutexes locked for extended periods of time. */
void ssh_kernel_rw_mutex_lock_read(SshKernelRWMutex mutex);

/* Releases the read lock on the mutex. The mutex must be unlocked from
   the same thread from which the read lock was taken. If other threads
   are waiting to write lock the mutex, one of them will get the lock
   and continue execution if this was the only thread holding the read lock. */
void ssh_kernel_rw_mutex_unlock_read(SshKernelRWMutex mutex);

/* Takes a write lock on the mutex. Only one thread of execution can have
   a write lock at a time. In addition the write lock cannot be taken
   unless there are no threads holding the read lock. This will block until
   execution can continue. The calling code may modify the data protected
   by this lock when holding the write lock. One should not keep mutexes
   locked for extended periods of time. */
void ssh_kernel_rw_mutex_lock_write(SshKernelRWMutex mutex);

/* Releases the write lock on the mutex. If other threads are waiting to
   lock the mutex, one of them will get the lock and continue execution. This
   API does not specify any priority between readers and writers, i.e. if
   there are both readers and writers currently waiting for this lock, it
   is an implementation specific matter to decide which thread should
   take the lock. */
void ssh_kernel_rw_mutex_unlock_write(SshKernelRWMutex mutex);

/* Returns the ID of the kernel thread that is currently executing the
   code. The returned ID must be a non-zero pointer identifying the
   thread. The returned values is used only to identify the thread.
   The caller must not assume anything about it nor modify it (or any
   value pointed by it) in any ways. */
void *ssh_kernel_thread_id(void);


/* Functions for handling concurreny control over per-CPU data.  */

/* Returns the number of processors in the system. This value must remain
   constant for the duration the system is running. */
unsigned int ssh_kernel_num_cpus(void);

/* Returns an id of the currently executing processor. The returned value
   must be less than the value returned by ssh_kernel_num_cpus(). The code
   calling this function should be made from an execution context where
   the current processor will not be preempted (for example after
   ssh_kernel_critical_section_start has been called), so the return value
   does actually represent the currently executing processor. */
unsigned int ssh_kernel_get_cpu(void);


/* Allocates and initializes a critical section. Critical sections prevent
   threads from migrating between processors and the preemption of threads
   by interrupts and other threads. The code within a critical section must
   execute without preemption. However it is possible for multiple threads
   on different CPU's to concurrently access the same critical section,
   hence synchronization is only required within the executing processor.
   The recommended implementation is to disable interrupts and preemption
   on the local CPU. If this is not possible, then multi-processor safe
   locking, as defined by the SshKernelMutex abstraction may be used
   instead. Code using this API must not nest different critical sections. */
SshKernelCriticalSection ssh_kernel_critical_section_alloc(void);

/* Initializes a critical section allocated from the stack. Returns TRUE
   on success and FALSE on failure. */
Boolean ssh_kernel_critical_section_init(SshKernelCriticalSection cs);

/* Uninitializes the given critical section. The critical section must
   not be entered when it is uninitialized. */
void ssh_kernel_critical_section_uninit(SshKernelCriticalSection cs);

/* Frees the given critical section. The critical section must not be
   entered when it is freed. */
void ssh_kernel_critical_section_free(SshKernelCriticalSection cs);

/* Enter the critical section. The code within the critical section
   (until ssh_kernel_critical_section_end() is called) will run on the
   same processor without preemption. It is a fatal error for code within
   the critical section to block or cause the processor to schedule the
   current thread. One should not stay within critical sections for extended
   periods of time. */
void ssh_kernel_critical_section_start(SshKernelCriticalSection cs);

/* Signals the end of the critical section. This must be called from the
   same thread that called ssh_kernel_critical_section_start(). */
void ssh_kernel_critical_section_end(SshKernelCriticalSection cs);

#ifdef DEBUG_LIGHT
#define KERNEL_MUTEX_USE_FUNCTIONS
#endif /* DEBUG_LIGHT */

/* This must be in the -I path of the machine-dependent interceptor
   dir. It defines any platform-dependent things (such as the inline
   functions, if KERNEL_MUTEX_USE_FUNCTIONS is not defined). */
#include "platform_kernel_mutex.h"

#endif /* KERNEL_MUTEX_H */
