/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Thread API. This API has been designed to be as simple as possible
   to allow easy implementation on different platforms. For that reason
   there is no explicit thread destroy/cancel operation available at
   all.. (that would have required cancellation points/thread
   destructors, which hardly are common on all existing thread
   implementations.)
*/

#ifdef HAVE_THREADS

#ifndef SSH_THREAD_H
#define SSH_THREAD_H
/* Arbitrary thread context pointer */
typedef struct SshThreadRec *SshThread;

/* When you call ssh_thread_execute, it starts executing this type of
   function from it. */
typedef void *(*SshThreadFuncCB)(void *context);

/* Creates a new thread and starts its execution from the `func'
   function with argument `context'. When `func' returns, its return
   value can be retrieved with ssh_thread_join(), or it is
   automatically destructed if the thread has called
   ssh_thread_detach(). The returned value is non-NULL on successful
   thread creation. */
SshThread ssh_thread_create(SshThreadFuncCB func, void *context);

/* Detaches a thread. If a thread is detached, its return value is
   ignored and it is automatically destructed when the `func' callback
   of thread creation returns. If `thread' may have already been
   terminated. It is fatal error to call this routine more than once
   for a thread. This routine can only be called by the thread which
   created the `thread' through ssh_thread_create. */
void ssh_thread_detach(SshThread thread);

/* Waits until thread `thread' has finished its execution, and
   returned from the `func' callback. The return value of `func' is
   returned as the value of this function. `thread' is invalid after
   this routine returns. It is a fatal error for multiple threads to
   call this routine for the same thread, or to call for a detached
   thread.*/
void *ssh_thread_join(SshThread thread);

/* Returns the currently executing thread, or NULL if the current
   thread is not "valid" in the sense that it can be manipulated with
   the API defined here. (The last definition is not strict: it just
   means that the caller should be prepared to handle a NULL value
   unless it knows it is created explicitly through the
   ssh_thread_create interface, in which case it will never receive a
   NULL value.) */
SshThread ssh_thread_current(void);

#define ssh_thread_sleep \
 *SSH_THREAD_SLEEP_NOT_SUPPORTED_USE_SSH_SLEEP_INSTEAD*

#endif /* SSH_THREAD_H */
#endif /* HAVE_THREADS */
