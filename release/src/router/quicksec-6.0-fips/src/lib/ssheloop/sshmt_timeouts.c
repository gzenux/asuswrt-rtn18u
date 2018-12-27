/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Multithread timeouts support
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshmutex.h"

#define SSH_DEBUG_MODULE "SshMtTimeouts"

/* SSH library functions can only be called from single thread. This SSH main
   thread is the thread that is running the event loop. If the program is
   multiple threads and the other threads want to call some SSH library
   functions they must pass the execution of that code to the SSH main thread.
   Only method of doing that is to call ssh_register_threaded_timeout. That
   function can be called from other threads also, and it will pass the timeout
   given to it to the SSH main thread. When the timeout expires it is run on
   the SSH main thread. If you want to the call to be done as soon as possible
   use zero length timeout. The SSH library contains few other functions that
   can be called from other threads also. Each of those functions contains a
   note saying that they can be called from other threads also. */

/* Threaded environment context */
typedef struct SshThreadedCtxRec {
  SshMutex mutex;
  SshIOHandle pipe_read_fd;
  SshIOHandle pipe_write_fd;
  SshTimeout items;
} *SshThreadedCtx;

/* Global multi thread context structure. If this is NULL then
   ssh_threaded_timeout_init is not called, and we are not using threads */
SshThreadedCtx ssh_threaded_timeout_context = NULL;

/* Prototype for an ssheloop internal function which preserves
   flags already set in SshTimeout state */
SshTimeout
ssh_register_timeout_internal(SshTimeout state,
                              long seconds,
                              long microseconds,
                              SshTimeoutCallback callback,
                              void *context);

static SshTimeout
ssh_register_threaded_timeout_internal(SshTimeout timeout,
                                       long seconds, long microseconds,
                                       SshTimeoutCallback callback,
                                       void *context);

/* This is the callback function that is called when the pipe_read_fd wakes up
   because there is data in the pipe. This function will first read everything
   from the pipe, and then take a mutex and insert all items in the timeout
   list ot the event loop timeout list. */
void ssh_threaded_timeout_io_read(unsigned int events, void *context)
{
  SshThreadedCtx ctx = context;
  SshTimeout item,tmp;
  unsigned char buffer[16];

  if (events & SSH_IO_WRITE)
    ssh_fatal("IO notification for write received, even when none requested");

  while (read(ctx->pipe_read_fd, buffer, sizeof(buffer)) > 0)
    ;

  /* Take a lock  */
  ssh_mutex_lock(ctx->mutex);

  /* Check timeout items */
  item = ctx->items;

  if (item)
    {
      while (1)
        {
          tmp = item;
          item = item->next;
          tmp->next = NULL;
          tmp->prev = NULL;
          /* Insert timeout so that the is_dynamic field is preserved */
          ssh_register_timeout(NULL,
                               tmp->firing_time.tv_sec,
                               tmp->firing_time.tv_usec,
                               tmp->callback,
                               tmp->context);
          if (tmp->is_dynamic)
            ssh_free(tmp);
          if (item == NULL)
            break;
        }

      /* Invalidate the list */
      ctx->items = NULL;
    }
  ssh_mutex_unlock(ctx->mutex);
}


/* Initialize function for timeouts in multithreaded environment. If program
   uses multiple threads, it MUST call this function before calling
   ssh_register_threaded_timeout function. If the system environment does not
   support threads this will call ssh_fatal. If program does not use multiple
   threads it should not call this function, but it may still call
   ssh_register_threaded_timeout. This function MUST be called from the SSH
   main thread after the event loop has been initialized. */
void ssh_threaded_timeouts_init(void)
{
  int filedes[2];

  if (ssh_threaded_timeout_context)
    ssh_fatal("Ssh_threaded_timeout_init called twice");

  ssh_threaded_timeout_context =
    ssh_xcalloc(1, sizeof(*ssh_threaded_timeout_context));
  ssh_threaded_timeout_context->mutex =
    ssh_mutex_create("ThreadedTimeoutItemLock", 0);
  if (ssh_threaded_timeout_context->mutex == NULL)
    ssh_fatal("Creating mutex failed in ssh_threaded_timeout_init");

  if (pipe(filedes) != 0)
    ssh_fatal("Creating pipe failed in ssh_threaded_timeout_init : %s",
              strerror(errno));

  /* Store the file descriptors to the structure */
  ssh_threaded_timeout_context->pipe_read_fd = filedes[0];
  ssh_threaded_timeout_context->pipe_write_fd = filedes[1];

  /* Install the read end to the event loop. */
  ssh_io_xregister_fd(ssh_threaded_timeout_context->pipe_read_fd,
                     ssh_threaded_timeout_io_read,
                     ssh_threaded_timeout_context);
  ssh_io_set_fd_request(ssh_threaded_timeout_context->pipe_read_fd,
                        SSH_IO_READ);
  return;
}

/* Uninitialize multithreading environment. This should be called before the
   program ends. After this is called the program MUST NOT call any other
   ssh_register_threaded_timeout functions before calling the
   ssh_threaded_timeouts_init function again. This function MUST be called from
   the SSH main thread. */
void ssh_threaded_timeouts_uninit(void)
{
  SshTimeout item,next_item;

  if (ssh_threaded_timeout_context == NULL)
    ssh_fatal("Ssh_threaded_timeout_uninit called before "
              "ssh_threaded_timeout_init was called");

  ssh_mutex_destroy(ssh_threaded_timeout_context->mutex);
  ssh_io_unregister_fd(ssh_threaded_timeout_context->pipe_read_fd, FALSE);
  close(ssh_threaded_timeout_context->pipe_read_fd);
  close(ssh_threaded_timeout_context->pipe_write_fd);

  item = ssh_threaded_timeout_context->items;
  while (item != NULL)
    {
      next_item = item->next;
      if (item->is_dynamic == TRUE)
        ssh_xfree(item);
      item = next_item;
    }

  ssh_xfree(ssh_threaded_timeout_context);
  ssh_threaded_timeout_context = NULL;
}

/* Insert timeout to the SSH library thread on the given time. This function
   can be called from the any thread, provided that ssh_threaded_timeouts_init
   function is called before this. This function can also be called without
   calling the ssh_threaded_timeouts_init, but in that case this function
   assumes that there is no other threads and it will just call regular
   ssh_register_timeout directly. See documentation for ssh_xregister_timeout
   for more information. These timeouts can be cancelled normally using the
   ssh_cancel_timeouts, but ONLY from the SSH main thread. Note, also that
   there might be race conditions on that kind of situations, the other thread
   might be just calling this function while the SSH main thread is cancelling
   the timeout. In that case the timeout might be inserted again when this
   message from here receives the SSH main thread. */
SshTimeout
ssh_xregister_threaded_timeout(long seconds, long microseconds,
                               SshTimeoutCallback callback,
                               void *context)
{
  SshTimeout timeout;

  if (ssh_threaded_timeout_context == NULL)
    {
      return ssh_xregister_timeout(seconds, microseconds, callback, context);
    }
  if ((timeout = ssh_calloc(1,sizeof(*timeout))) == NULL)
    ssh_fatal("Out of memory while trying to register threaded timeout with "
              "call to ssh_xregister_threaded_timeout().");

  timeout->is_dynamic = TRUE;
  return ssh_register_threaded_timeout_internal(timeout,
                                                seconds, microseconds,
                                                callback, context);
}

SshTimeout
ssh_register_threaded_timeout(SshTimeout timeout,
                              long seconds, long microseconds,
                              SshTimeoutCallback callback,
                              void *context)
{
  if (ssh_threaded_timeout_context == NULL)
    {
      return ssh_register_timeout(timeout,
                                  seconds, microseconds,
                                  callback, context);
    }

  if (timeout != NULL)
    {
      memset(timeout,0,sizeof(*timeout));
      timeout->is_dynamic = FALSE;
    }
  else
    {
      timeout = ssh_calloc(1,sizeof(*timeout));
      if (timeout == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("insufficient memory to instantiate timeout!"));
          return NULL;
        }
      timeout->is_dynamic = TRUE;
    }

  return ssh_register_threaded_timeout_internal(timeout,
                                                seconds, microseconds,
                                                callback, context);

}

SshTimeout
ssh_register_threaded_timeout_internal(SshTimeout timeout,
                                       long seconds, long microseconds,
                                       SshTimeoutCallback callback,
                                       void *context)
{
  SSH_ASSERT(timeout != NULL);

  timeout->firing_time.tv_sec = seconds;
  timeout->firing_time.tv_usec = microseconds;
  timeout->callback = callback;
  timeout->context = context;

  /* Take a lock  */
  ssh_mutex_lock(ssh_threaded_timeout_context->mutex);

  /* Insert item to the list */
  timeout->next = ssh_threaded_timeout_context->items;
  ssh_threaded_timeout_context->items = timeout;

  /* Release the lock */
  ssh_mutex_unlock(ssh_threaded_timeout_context->mutex);

  /* Wake up the ssh main thread in the event loop. We don't need to care if
     the pipe is full or something, we just do write and the event loop will
     wake up later. */
  write(ssh_threaded_timeout_context->pipe_write_fd, " ", 1);

  return timeout;
}
