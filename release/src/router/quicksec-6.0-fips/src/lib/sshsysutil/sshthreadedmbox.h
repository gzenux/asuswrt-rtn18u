/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains definitions for the thread-safe message box
   concept, which is used to perform synchronization between the
   thread-unaware eloop and other code which is thread-aware.

   Notice: This API will work even if the environment does not support
   threads (all send_to_{thread,eloop} call the callback directly), if
   the code callings this is programmed correctly.
*/

#include "sshincludes.h"
#include "sshstream.h"

#ifndef SSH_THREADED_MBOX_H
#define SSH_THREADED_MBOX_H

typedef struct SshThreadedMboxRec *SshThreadedMbox;

/* Callback which is invoked on the thread-unaware part as a result to
   receiving a message, while being in the eloop handler */
typedef void (*SshThreadedMboxEloopCB) (void *ctx);

/* Callback which is invoked on the thread-aware part as a result to
   receiving a message from the eloop. Note that this might be on a
   separate thread from the eloop, or it might be the eloop
   thread.. */
typedef void (*SshThreadedMboxThreadCB) (void *ctx);

/* Create a new threaded mbox. At most `max_threads' threads will be
   run concurrently on the thread-aware side of the mbox. If
   `max_threads' is 0, then no separate handling thread will be
   allocated. If `max_threads' is -1, then no thread limit is
   imposed. */
SshThreadedMbox ssh_threaded_mbox_create(SshInt32 max_threads);

/* Destroy threaded mbox. This will force all further additions of
   messages to the queue to fail, and all queued messages will then be
   handled. Upon return from this routine, the `mbox' argument is
   invalidated. */
void ssh_threaded_mbox_destroy(SshThreadedMbox mbox);

/* Put a message to the mbox, to be sent to the eloop side. This
   routine is thread-safe. If an error has occured and the message can
   not be either queued or delivered, FALSE value is returned,
   otherwise TRUE. */
Boolean ssh_threaded_mbox_send_to_eloop(SshThreadedMbox mbox,
                                        SshThreadedMboxEloopCB eloop_cb,
                                        void *ctx);

/* Put a message to the mbox to be sent to the threaded side. This
   routine is thread-safe. If queueing or delivering the message
   fails, a FALSE value is returned. TRUE value is returned on
   success. */
Boolean ssh_threaded_mbox_send_to_thread(SshThreadedMbox mbox,
                                         SshThreadedMboxThreadCB thread_cb,
                                         void *ctx);

#ifdef DEBUG_LIGHT
/* Returns TRUE if the current thread is executing in thread context,
   in a thread (or execution path) which has been created through the
   mbox message handling. This function is available only if
   DEBUG_LIGHT has been enabled. */
Boolean ssh_threaded_mbox_is_thread(SshThreadedMbox mbox);
#endif /* DEBUG_LIGHT */

#endif /* SSH_THREADED_MBOX_H */
