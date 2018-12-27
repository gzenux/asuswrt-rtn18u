/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Timeout processing.  This header is part of the event loop interface.
   This header is machine-independent; however, the implementation is
   machine-dependent.

   The fSshTimeoutStruct and its size is platform specific. The
   application MUST NOT directly access contents of this structure. It
   content is visible only because of the application may need to know
   its size for embedding timeouts into its own data structures.
*/

#ifndef SSHTIMEOUTS_H
#define SSHTIMEOUTS_H

#include "sshadt_map.h"
#include "sshadt_priority_heap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Special wild-card context arguments to ssh_cancel_timeouts. */
#define SSH_ALL_CALLBACKS ((SshTimeoutCallback)1)
#define SSH_ALL_CONTEXTS  ((void *)1)

/* Callback functions of this type are called when a timeout occurs.
   The function receives as argument the context supplied when the
   timeout was registered.  A timeout is delivered only once, but can
   be reregistered in the callback function.  There are no
   restrictions as to what operations can be performed in timeout
   callbacks. */
typedef void (*SshTimeoutCallback)(void *context);

/* A structure for housing the state for a timeout. The definition of
   this structure is given so that it may be directly included in
   structures that use timeouts. DO NOT manipulate it directly. */

typedef struct SshTimeoutRec
{
#ifdef KERNEL
  unsigned long firing_time[4];
#else
  struct timeval firing_time;
#endif /* !KERNEL */

  /* The platform specific code is here */
  union {

    struct {
#ifdef KERNEL
      unsigned long firing_time[4];
#else /* !KERNEL */
      int x;
#endif /* !KERNEL */
    } os_unix;

    struct {
      unsigned int is_expired:1;
#if defined(WINDOWS) && !defined(KERNEL)
      LIST_ENTRY link;
#endif /* WINDOWS && !KERNEL */
    } os_win32;

  } platform;

  /* Unique timeout identifier. */
  SshUInt64 identifier;

  /* Timeout callback and its context argument. */
  SshTimeoutCallback callback;
  void *context;

  /* Implementation specific issues. */
  SshADTMapHeaderStruct adt_id_map_hdr;
  SshADTPriorityHeapHeaderStruct adt_ft_ph_hdr;

  SshADTMapHeaderStruct adt_ctx_map_hdr;
  struct SshTimeoutRec *prev;
  struct SshTimeoutRec *next;

  /* Has this instance been allocated via _xregister_() */
  unsigned int is_dynamic:1;

} *SshTimeout,  SshTimeoutStruct;

  /* Check if timeout is registered */
#define SSH_TIMEOUT_IS_REGISTERED(timeout)                              \
  (((timeout) == NULL || (timeout)->identifier == 0) ? FALSE : TRUE)

#if !defined(VXWORKS) || !defined(RUNS_IN_NETTASK)

/* Registers a timeout function that is to be called once when the
   specified time has elapsed.  The time may be zero, in which case
   the callback will be called as soon as possible from the bottom of
   the event loop.  There is no guarantee about the order in which
   callbacks with zero timeouts are delivered.

   The timeout will be delivered approximately after the specified
   time.  The exact time may differ somewhat from the specified time.
   The timeout will be delivered from the bottom of the event loop
   (i.e., it will be delayed if another callback from the event loop
   is being executed).

   ssh_fatal() will be called if there are insufficient resources
   available to register a timeout.

   The arguments are as follows:

     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function.

   The function returns pointer to timeout queue entry, which can be
   used to cancel the timeout with a call `ssh_cancel_timeout'. */

SshTimeout
ssh_xregister_timeout(long seconds, long microseconds,
                      SshTimeoutCallback callback, void *context);


/* Registers a timeout function that is to be called once when the
   specified time has elapsed.  The time may be zero, in which case
   the callback will be called as soon as possible from the bottom of
   the event loop.  There is no guarantee about the order in which
   callbacks with zero timeouts are delivered.

   The timeout will be delivered approximately after the specified
   time.  The exact time may differ somewhat from the specified time.
   The timeout will be delivered from the bottom of the event loop
   (i.e., it will be delayed if another callback from the event loop
   is being executed).

   The first parameter 'state' is either NULL or a pointer to a unused
   SshTimeoutRec structure. If 'state' is NULL, then
   ssh_register_timeout() will attempt to malloc() the memory for the
   timeout, and if it fails, then the timeout is not registered.  If
   'state' is not NULL, then the SshTimeoutRec instance pointed to by
   'state' will be used to contain the state for the timeout.

   The 'state' instance may be freed or re-used after the timeout has
   been executed (in the timeout callback) or cancelled. It is a fatal
   error to re-use timeout not yet triggered or cancelled.

   The arguments are as follows:
     state          A pointer to an unused SshTimeoutRec structure for
                    containing the state for the timeout or NULL.
     seconds        number of full seconds after which the timeout is delivered
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function.

   The function returns pointer to timeout queue entry, which can be
   used to cancel the timeout with a call `ssh_cancel_timeout'. */

SshTimeout
ssh_register_timeout(SshTimeout state,
                     long seconds, long microseconds,
                     SshTimeoutCallback callback, void *context);

/* Returns time left until expiration on a registered timeout.

   The arguments are as follows:
     timeout        pointer to timeout queue entry, that has not triggered
                    and has not been cancelled
     seconds        pointer to return seconds of time left
     microseconds   pointer to return microseconds of time left ([0-999999]) */
void ssh_timeout_time_left(SshTimeout timeout, long *seconds,
                          long *microseconds);

/* Registers an idle timeout function.  An idle timeout will be called once
   when the system has been sufficiently idle for the specified amount of
   time.  The definition of idle is somewhat implementation-dependent, but
   typically means when it is a good time to perform cpu-intensive operations.
   There is no guarantee that the idle timeout ever gets called.  Idle timeouts
   are always delivered from the bottom of the event loop.

   The arguments are as follows:
     seconds        number of seconds the system must be idle before delivering
     microseconds   number of microseconds to add to full seconds
                    (this may be larger than 1000000, meaning several seconds)
     callback       the callback function to call
     context        context argument to pass to callback function. */
SshTimeout
ssh_xregister_idle_timeout(long seconds, long microseconds,
                           SshTimeoutCallback callback, void *context);

/* ssh_cancel_timeout() will cancel the timeout pointed to by
   'timeout'.  The timeout may be active or expired. (e.g. the
   callback has been called, in which case this does nothing). This
   can be called also for an expired timeout, which has been allocated
   by the user, and is not yet freed.

   It is also allowed to call the ssh_cancel_timeout to a zero memory
   (e.g. ssh_calloc'ed memory) in which case this does nothing */

void
ssh_cancel_timeout(SshTimeout timeout);

/* Cancels any timeouts with a matching callback function and context.
   `callback' may be SSH_ALL_CALLBACKS, which matches any function, and
   `context' may be SSH_ALL_CONTEXTS, which matches any context.
   It is guaranteed that the timeout will not be delivered once it has
   been cancelled, even if it had elapsed (but not yet delivered) before
   cancelling it. */
void
ssh_cancel_timeouts(SshTimeoutCallback callback, void *context);

/*****************************************************************************
 * Thread support for timeouts
 *
 * SSH library functions can only be called from single thread. This
 * SSH main thread is the thread that is running the event loop. If
 * the program is multiple threads and the other threads want to call
 * some SSH library functions they must pass the execution of that
 * code to the SSH main thread.  Only method of doing that is to call
 * ssh_register_threaded_timeout. That function can be called from
 * other threads also, and it will pass the timeout given to it to the
 * SSH main thread. When the timeout expires it is run on the SSH main
 * thread. If you want to the call to be done as soon as possible use
 * zero length timeout. The SSH library contains few other functions
 * that can be called from other threads also. Each of those functions
 * contains a note saying that they can be called from other threads
 * also.
 */

/* Initialize function for timeouts in multithreaded environment. If
   program uses multiple threads, it MUST call this function before
   calling ssh_register_threaded_timeout function. If the system
   environment does not support threads this will call ssh_fatal. If
   program does not use multiple threads it should not call this
   function, but it may still call ssh_register_threaded_timeout. This
   function MUST be called from the SSH main thread after the event
   loop has been initialized. */
void ssh_threaded_timeouts_init(void);

/* Uninitialize multithreading environment. This should be called
   before the program ends. After this is called the program MUST NOT
   call any other ssh_register_threaded_timeout functions before
   calling the ssh_threaded_timeouts_init function again. This
   function MUST be called from the SSH main thread. */
void ssh_threaded_timeouts_uninit(void);

/* Insert timeout to the SSH library thread on the given time. This
   function can be called from the any thread, provided that
   ssh_threaded_timeouts_init function is called before this. This
   function can also be called without calling the
   ssh_threaded_timeouts_init, but in that case this function assumes
   that there is no other threads and it will just call regular
   ssh_register_timeout directly. See documentation for
   ssh_register_timeout for more information. These timeouts can be
   cancelled normally using the ssh_cancel_timeouts, but ONLY from the
   SSH main thread. Note, also that there might be race conditions on
   that kind of situations, the other thread might be just calling
   this function while the SSH main thread is cancelling the
   timeout. In that case the timeout might be inserted again when this
   message from here receives the SSH main thread.

   ssh_xregister_threaded_timeout() calls ssh_fatal() if it fails to
   allocate the necessary resourecs.

   ssh_register_threaded_timeout()
   uses the store provided via the 'state' parameter to contain the
   timeout state and does not fail in this case. The store pointed
   to by 'state' can be freed after the timeout has been executed
   (e.g. in the timeout callback).  If 'state' is NULL, then
   ssh_register_threaded_timeout() attempts to reserve the store
   needed and fails silently if there is insufficient memory available.

   Threaded timeouts can not currently be canceled safely.
*/
SshTimeout
ssh_xregister_threaded_timeout(long seconds, long microseconds,
                               SshTimeoutCallback callback,
                               void *context);

SshTimeout
ssh_register_threaded_timeout(SshTimeout state,
                              long seconds,long microsecodns,
                              SshTimeoutCallback callback,
                              void *context);

/* Macros for initializing and uninitializing threaded timeouts. If
   HAVE_THREADS is not defined, these will do nothing. */
#ifdef HAVE_THREADS
#define SSH_THREADED_TIMEOUTS_INIT     \
 do {                                  \
  ssh_threaded_timeouts_init()         \
    } while (0)

#define SSH_THREADED_TIMEOUTS_UNINIT  \
 do {                                 \
  ssh_threaded_timeouts_uninit()      \
    } while (0)
#else /* !HAVE_THREADS */
#define SSH_THREADED_TIMEOUTS_INIT do { } while (0)
#define SSH_THREADED_TIMEOUTS_UNINIT do { } while (0)
#endif /* HAVE_THREADS */

#ifdef __cplusplus
}
#endif

#else /* !defined(VXWORKS) || !defined(RUNS_IN_NETTASK) */

/* If system runs in nettask on VxWorks, these timeout functions
   should not be used. These definitions cause things to break if
   they are used nevertheless. */
#define NO_RUNS_IN_NETTASK(a) *** CANNOT_DO_##a##_IN_NETTASK ***

#define SSH_THREADED_TIMEOUTS_INIT \
  NO_RUNS_IN_NETTASK(SSH_THREADED_TIMEOUTS_INIT)
#define SSH_THREADED_TIMEOUTS_UNINIT \
  NO_RUNS_IN_NETTASK(SSH_THREADED_TIMEOUTS_UNINIT)
#define ssh_xregister_threaded_timeout \
  NO_RUNS_IN_NETTASK(ssh_xregister_threaded_timeout)
#define ssh_register_threaded_timeout \
  NO_RUNS_IN_NETTASK(ssh_register_threaded_timeout)
#define ssh_cancel_timeout NO_RUNS_IN_NETTASK(ssh_cancel_timeout)
#define ssh_cancel_timeouts NO_RUNS_IN_NETTASK(ssh_cancel_timeouts)
#define ssh_xregister_idle_timeout \
  NO_RUNS_IN_NETTASK(ssh_xregister_idle_timeout)
#define ssh_register_timeout NO_RUNS_IN_NETTASK(ssh_register_timeout)
#define ssh_xregister_timeout NO_RUNS_IN_NETTASK(ssh_xregister_timeout)

#endif /* !defined(VXWORKS) || !defined(RUNS_IN_NETTASK) */

#endif /* SSHTIMEOUTS_H */
