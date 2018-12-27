/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Windows specific thread implementation.
*/

#include "sshincludes.h"
#include "sshthread.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include <process.h>

#define SSH_DEBUG_MODULE  "SshThread"

typedef struct SshThreadRec
{
  /* Pointer to next thread */
  struct SshThreadRec *next;

  /* Thread function and its context. */
  SshThreadFuncCB func;
  void *context;

  /* Handle to native OS thread */
  HANDLE thread_handle;

  /* Native thread ID */
  DWORD thread_id;

  /* TRUE if ssh_thread_detach() has been called for this thread. */
  Boolean detached;
} SshThreadStruct, *SshThread;


static SshThread thread_list = NULL;
/* We must protect the 'thread_list' with a critical section because also
   ssh_thread_current() need to access this list. */
static CRITICAL_SECTION thread_list_lock;


static void
ssh_thread_free(SshThread thread)
{
  SshThread prev, current;

  if (thread == NULL)
    return;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Freeing thread 0x%p...", thread));

  if (thread->thread_handle)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Closing thread handle: 0x%p", thread->thread_handle));
      CloseHandle(thread->thread_handle);
    }

  EnterCriticalSection(&thread_list_lock);

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Searching for thread 0x%p...", thread));
  prev = thread_list;
  current = thread_list;
  while (current)
    {
      if (current == thread)
        {
          if (current == prev)
            thread_list = current->next;
          else
            prev->next = current->next;

          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Thread 0x%p found; freeing context...", thread));

          ssh_free(current);
          break;
        }

      prev = current;
      current = current->next;
    }
  LeaveCriticalSection(&thread_list_lock);
}

static void
ssh_thread_complete_callback(void *context)
{
  SshThread thread = (SshThread)context;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Thread 0x%p: completion callback", thread));

  if (thread->detached)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Unregistering handle 0x%p from event loop",
                 thread->thread_handle));

      ssh_event_loop_unregister_handle(thread->thread_handle);

      ssh_thread_free(thread);
    }
}

static unsigned __stdcall
ssh_thread_start_i(void *ctx)
{
  SshThread thread = (SshThread)ctx;
  void *ret;

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Thread 0x%p executing: function=0x%p, context=0x%p",
             thread, thread->func, thread->context));

  ret = (*thread->func)(thread->context);

#pragma warning(disable : 4311)
  _endthreadex((unsigned)ret);

  return (unsigned)ret;
#pragma warning(default: 4311)
}

SshThread
ssh_thread_create(SshThreadFuncCB func, void *context)
{
  SshThread thread;

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Creating new thread: function=0x%p, context=0x%p",
             func, context));

  /* Create an internal call to our function which is __stdcall */
  thread = ssh_calloc(1, sizeof(*thread));
  if (!thread)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to allocate context for new thread"));
      goto failed;
    }

  thread->func = func;
  thread->context = context;

  if (thread_list == NULL)
    InitializeCriticalSection(&thread_list_lock);

  EnterCriticalSection(&thread_list_lock);
  thread->next = thread_list;
  thread_list = thread;
  LeaveCriticalSection(&thread_list_lock);

  thread->thread_handle =
    (HANDLE)_beginthreadex(NULL, 0, ssh_thread_start_i, thread,
                           0, (unsigned int *)&thread->thread_id);

  if (thread->thread_handle == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to start native Windows thread"));
      goto failed;
    }

  /* Register thread handle to event loop so the application doesn't exit
     before this thread has completed its work. */
  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Registering handle 0x%p to event loop", thread->thread_handle));
  ssh_event_loop_register_handle(thread->thread_handle,
                                 FALSE,
                                 ssh_thread_complete_callback,
                                 thread);

  SSH_DEBUG(SSH_D_HIGHOK,
            ("Thread 0x%p created (function=0x%p, context=0x%p)",
             thread, func, context));

  return thread;

 failed:

  ssh_thread_free(thread);

  return NULL;
}

void
ssh_thread_detach(SshThread thread)
{
  SSH_DEBUG(SSH_D_HIGHSTART, ("Detaching thread 0x%p", thread));

  thread->detached = TRUE;
}

void *
ssh_thread_join(SshThread thread)
{
  DWORD ret;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Joining thread 0x%p", thread));

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Waiting for thread 0x%p to complete.", thread));
  WaitForSingleObject(thread->thread_handle, INFINITE);
  GetExitCodeThread(thread->thread_handle, &ret);
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Thread 0x%p completed."));

  SSH_DEBUG(SSH_D_NICETOKNOW,
            ("Unregistering handle 0x%p from event loop",
             thread->thread_handle));
  ssh_event_loop_unregister_handle(thread->thread_handle);
  ssh_thread_free(thread);

#pragma warning(disable : 4312)
  return (void *)ret;
#pragma warning(default : 4312)
}

void ssh_thread_cancel(SshThread thread)
{
  TerminateThread(thread->thread_handle, 0);
}

SshThread
ssh_thread_current(void)
{
  SshThread thread;
  DWORD thread_id = GetCurrentThreadId();

  EnterCriticalSection(&thread_list_lock);
  thread = thread_list;
  while (thread)
    {
      if (thread->thread_id == thread_id)
        {
          LeaveCriticalSection(&thread_list_lock);
          return thread;
        }

      thread = thread->next;
    };
  LeaveCriticalSection(&thread_list_lock);

  SSH_NOTREACHED;

  return NULL;
}
