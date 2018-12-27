/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Event loop API, containing event loop meta operations
   (start/stop/run) and associating operating system events (file
   handles) with callbacks and contexts.

   @description
   Note that implementations themselves are very platform-specific.
*/

#ifndef SSHELOOP_H
#define SSHELOOP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Public prototypes */

/** Initializes the event loop.  This must be called before any other
    event loop, timeout, or stream function. */
void ssh_event_loop_initialize(void);

/** This function runs the event loop.  This should normally be called
    from the application main loop after the application has been
    initialized.  This returns when all event loop activity has ceased
    (ssh_event_loop_status returns SSH_EVENT_LOOP_INACTIVE), or when
    ssh_event_loop_abort has been called. */
void ssh_event_loop_run(void);

/** Uninitializes the event loop, and frees resources used by it. This
    automatically cancels any pending timeouts and unregisters file
    descriptors.  This must not be called from within an event loop
    callback. */
void ssh_event_loop_uninitialize(void);

/** When called within a call to ssh_event_loop_run, causes the event
    loop to stop running and no longer deliver callbacks.  The event
    loop stops when control returns to the bottom of the event loop.*/
void ssh_event_loop_abort(void);

/* *********************************************************************
 * Event-loop locking routines.
 * *********************************************************************/

/** The event loop guarantees that only one callback is running at any
    one time - if any callbacks (in the same "domain" as the callbacks
    called by the event loop) are called from other threads, they must
    call this function to lock the event loop.

    This function essentially takes a mutex that is locked by the
    event loop whenever it is running in a callback.  Holding this
    lock ensures that no other callbacks will be running in
    parallel.  This call will block until the callback mutex has
    been obtained.

    Also, functions related to the event loop cannot be called
    from other threads (i.e., from somewhere other than a
    callback) without taking this first.  Beware, however, that
    calling this function twice without first releasing the lock
    will cause the application to hang. Taking this lock is
    automatically performed before calling any callback function
    defined in this file, or any callback derived from these.

    */

void ssh_event_loop_lock(void);

/** Releases the event loop mutex, allowing other callbacks
    to be executed.  Note that it is illegal to unlock and then
    reacquire this lock within a callback called with this lock held.
    This is because the caller might have cached state that might be
    invalidated if this lock is momentarily released. */
void ssh_event_loop_unlock(void);


/* *********************************************************************
 * Signal processing functions
 * *********************************************************************/

/** This type represents a signal callback.  Such a function can be
    registered to be called whenever a particular signal is delivered.
    The callback function will always be called from the bottom of the
    event loop.  There are no restrictions on what can be done in the
    callback. */
typedef void (*SshSignalCallback)(int signal, void *context);

/** Registers the specified callback function to be called from the
    bottom of the event loop whenever the given signal is received.
    The registration will remain in effect until explicitly
    unregistered.  If the same signal is received multiple times
    before the callback is called, the callback may get called only
    once for those multiple signals.

    If there is insufficient memory to perform the operation, then
    ssh_fatal() will be called.

    @param callback
    The 'callback' argument may be NULL, in which case the signal will
    be ignored.

    */
void ssh_register_signal(int signal, SshSignalCallback callback,
                         void *context);

/** Restores the handling of the signal to the default behavior.  Any
    callback registered for the signal will no longer be called (even
    if the signal has already been triggered, but the callback has not
    yet been called, it is guaranteed that the callback will not get
    called for the signal if this has been called before it is
    delivered).

    Note that this function restores the signal to default behavior
    (e.g., core dump), whereas setting the callback to NULL causes the
    signal to be ignored.

    */
void ssh_unregister_signal(int signal);


/* =====================================================================
 * I/O notification functions
 * ===================================================================== */

/* Notification flags for ssh_io_set_fd_request. */
#define SSH_IO_CLOSED     0  /** Request notification when the handle
                                 was closed - note that this is only
                                 for ssh library internal use, and may
                                 not be supported on all platforms. */

#define SSH_IO_READ       1  /** Request notification for data available. */
#define SSH_IO_WRITE      2  /** Request notification when can output. */

/** Callback functions of this type are used to receive notifications
    of I/O being possible on the file descriptor for which the callback
    is being registered.  Events is bitwise-or of the SSH_IO_ values
    defined above.  There are no restrictions on what can be done in the
    callback. */
typedef void (*SshIoCallback)(unsigned int events, void *context);

/** Registers the given file descriptor for the event loop.  This sets
    the descriptor in non-blocking mode, and registers the callback for
    the file descriptor.  Initially, no events will be requested, and
    ssh_io_set_fd_request must be called before any events will be
    delivered. If the operation fails due insufficient memory, then
    ssh_fatal() will be called. */
void
ssh_io_xregister_fd(SshIOHandle fd, SshIoCallback callback, void *context);

/** The ssh_io_register_fd() function is similar to ssh_io_xregister_fd()
    with the exception that if there is insufficient memory to register
    the file descriptor, then FALSE is returned instead of calling
    ssh_fatal(). */
Boolean
ssh_io_register_fd(SshIOHandle fd, SshIoCallback callback, void *context);

/** Cancels any callbacks registered for the file descriptor.  The
    blocking mode of the file descriptor will be restored to its
    original value.  It is guaranteed that no more callbacks will be
    received for the file descriptor after this fucntion has been
    called.

    @param keep_nonblocking
    If 'keep_nonblocking' is TRUE, the file descriptor will be left
    non-blocking (this may be useful after a fork).

    */
void ssh_io_unregister_fd(SshIOHandle fd, Boolean keep_nonblocking);

/** Specifies the types of events for which callbacks are to be
    delivered for the file descriptor.

    If SSH_IO_READ is included, the callback will be called whenever
    data is available for reading.  If SSH_IO_WRITE is specified, the
    callback will be called whenever more data can be written to the
    file descriptor. Callbacks will continue to be delivered from the
    event loop until the event is either removed from the request or
    the condition causing the event to trigger ceases to exist (e.g.,
    via reading all buffered data from a socket).

    @param events
    The 'events' argument is a bitwise-or of the SSH_IO_ values
    defined above.

    */
void ssh_io_set_fd_request(SshIOHandle fd, unsigned int events);


#ifdef WIN32
/** Event registration.

   In the context of event loop, registered events are something
   that can wake up the event loop. The event handle itself is
   considered opaque data by the event loop interface. Besides
   synchronization primitives, also file (communications endpoint)
   handles can be passed, provided that the underlying OS supports
   wait operations on those.

   On UNIX system-like platforms all the handles can be registered
   by using an ssh_io_register_fd() call.

   */
typedef void (*SshEventCallback)(void *context);

/** Registers waitable handle with event loop. Callback gets called
    from the bottom of the event loop when event is in signaled
    state. There is no guarantee of order or fairness in callback
    delivery.  */
void ssh_event_loop_register_handle(HANDLE hevent,
                                    Boolean manual_reset,
                                    SshEventCallback callback,
                                    void* context);

/** Unregisters waitable handle from the event loop. No callbacks will
    be called after this call completes. */
void ssh_event_loop_unregister_handle(HANDLE hevent);

/** The Event loop exits automatically when there are no events or
    callbacks which to execute. This will set the event loop to run
    forever, until ssh_event_loop_uninitialize is called. */
void ssh_event_loop_dont_check_termination();

#endif /* WIN32 */

#ifdef VXWORKS
/** Unregister wakeup device handle from event loop in preparation for
    stopping Policy Manager and exiting the event loop. */
void ssh_event_loop_vx_unregister_wakeup();
#endif /* VXWORKS */

#ifdef __cplusplus
}
#endif


#endif /* SSHELOOP_H */
