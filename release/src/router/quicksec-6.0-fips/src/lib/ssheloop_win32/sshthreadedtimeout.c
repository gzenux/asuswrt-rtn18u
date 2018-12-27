/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SSH system independent multithread environment support.
*/

#include "sshincludes.h"
#include "sshtimeouts.h"

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

/* Initialize function for timeouts in multithreaded environment. If program
   uses multiple threads, it MUST call this function before calling
   ssh_register_threaded_timeout function. If the system environment does not
   support threads this will call ssh_fatal. If program does not use multiple
   threads it should not call this function, but it may still call
   ssh_register_threaded_timeout. This function MUST be called from the SSH
   main thread after the event loop has been initialized. */
void ssh_threaded_timeouts_init(void)
{

}

/* Uninitialize multithreading environment. This should be called before the
   program ends. After this is called the program MUST NOT call any other
   ssh_register_threaded_timeout functions before calling the
   ssh_threaded_timeouts_init function again. This function MUST be called from
   the SSH main thread. */
void ssh_threaded_timeouts_uninit(void)
{

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
  /* In Win32 implementation the ssh_xregister_timeout is already a
     thread safe function. That is why we can call it directly without
     any synchronization in here */
  return ssh_xregister_timeout(seconds, microseconds, callback, context);
}

SshTimeout
ssh_register_threaded_timeout(SshTimeout timeout,
                              long seconds, long microseconds,
                              SshTimeoutCallback callback,
                              void *context)
{
  /* In Win32 implementation the ssh_xregister_timeout is already a
     thread safe function. That is why we can call it directly without
     any synchronization in here */
  return ssh_register_timeout(timeout,
                              seconds, microseconds,
                              callback, context);
}
