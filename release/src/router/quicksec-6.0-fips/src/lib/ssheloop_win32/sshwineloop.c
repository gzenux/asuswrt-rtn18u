/**
   @copyright
   Copyright (c) 2010 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   EventLoop for windows platforms. This file implements
   timeouts, socket I/O, event and signal callbacks.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include "sshtimeoutsi.h"
#include "sshadt.h"
#include "sshadt_list.h"

#define SSH_DEBUG_MODULE "SshEventLoop"

#define SSH_TIMEOUT_FREELIST_INITIAL_SIZE 200
#define SSH_EVENT_FREELIST_SIZE           200

/* Context for event waiter thread */
typedef struct SshWaitThreadContextRec
{
  /* Lock for protecting access of the data members of this context */
  CRITICAL_SECTION lock;

  /* Global list entry for the event loop */
  LIST_ENTRY global_link;

  /* Handle to waiter thread */
  HANDLE thread;

  /* Waitable events associated with this thread */
  LONG num_wait_events;
  LIST_ENTRY wait_events;
  LIST_ENTRY unregistered_events;

  /* Handle to event for waking up the waiter thread */
  HANDLE wakeup_event;
  /* Flags specifying the reason of wakeup */
  ULONG wakeup_reason;
      /* Reconstruct wait handle array and restart the wait. */
#define SSH_WAKEUP_RESTART_WAIT   0x00000001
      /* Thread must be stopped */
#define SSH_WAKEUP_EXIT           0x10000000
} SshWaitThreadContextStruct, *SshWaitThreadContext;

typedef enum
{
  SSH_ELOOP_OBJECT_EVENT,
  SSH_ELOOP_OBJECT_SIGNAL
} SshEloopObjType;

typedef struct SshEloopObjHeaderRec
{
  /* Entry for keeping signaled objects in event loop's list */
  LIST_ENTRY link;
  /* Type of event loop object */
  SshEloopObjType obj_type;
  /* Pointer to object */
  void *obj;
} SshEloopObjHeaderStruct, *SshEloopObjHeader;

typedef struct SshEventRec
{
  /* Event loop object header */
  SshEloopObjHeaderStruct hdr;
  /* How many times this event has been signaled before the callback is
     called */
  LONG signaled_count;
  /* For keeping events in global list */
  LIST_ENTRY link;
  /* Handle to native OS event object */
  HANDLE handle;
  /* Callback and context to be used when event is signaled. */
  SshEventCallback callback;
  void *context;
  /* Pointer to waiter thread 'owning' this event */
  SshWaitThreadContext waiter_thread;

  /* For keeping events in waiter thread specific list */
  LIST_ENTRY waiter_link;
  /* Flags: */
  unsigned int unregistered : 1;
  unsigned int pre_allocated : 1;
  unsigned int manual_reset : 1;
} SshEventStruct, *SshEvent;

typedef struct SshSocketRec
{
  /* Pointer to next socket */
  struct SshSocketRec *next;
  /* Native socket handle */
  SshIOHandle sock;
  /* I/O callback to be executed */
  SshIoCallback callback;
  void *context;
  /* Native event handle */
  HANDLE hevent;
  unsigned int unregistered : 1;
} SshSocketStruct, *SshSocket;

typedef struct SshSignalRec
{
  /* Event loop object header */
  SshEloopObjHeaderStruct hdr;
  /* For keeping signals in linked list */
  LIST_ENTRY link;
  /* Signal number */
  int signal;
  /* Callback function to be executed when the signal is raised */
  SshSignalCallback callback;
  void *context;
  /* Signal has been unregistered */
  unsigned int unregistered : 1;
} SshSignalStruct, *SshSignal;

typedef void (*SshEventLoopCallback)(void* context);

typedef struct SshEloopRec
{
  /* Global event loop lock. This must be held while executing callbacks */
  CRITICAL_SECTION lock;

  HANDLE eloop_wakeup_event;

  /* ADT container for timeouts */
  SshTimeoutContainerStruct to;
  /* Freelist of timeouts */
  LIST_ENTRY timeout_freelist;
  /* Lock for timeouts */
  CRITICAL_SECTION timeout_lock;
  /* Number of scheduled timeouts */
  LONG timeout_count;
  /* Timeout thread */
  HANDLE timeout_thread;
  /* Abort request for timeout thread */
  LONG abort_timeout_thread;
  /* Timeout thread wakeup event */
  HANDLE to_thread_event;
  /* List of expired timeouts waiting for execution */
  LIST_ENTRY expired_timeouts;
  /* Synthetized 64 bit monotonic system tick count */
  ULARGE_INTEGER tick_count;

  /* List of I/O events waiting for execution */
  LIST_ENTRY io_event_list;
  CRITICAL_SECTION io_event_list_lock;

  /* List of sockets */
  SshSocket sockets;
  SshSocket unregistered_sockets;

  /* Lists of events */
  LIST_ENTRY event_freelist;
  CRITICAL_SECTION event_freelist_lock;
  SshUInt32 num_registered_events;
  LIST_ENTRY events;
  LIST_ENTRY unregistered_events;

  /* List of signals */
  LIST_ENTRY signals;
  LIST_ENTRY unregistered_signals;

  /* Event waiter threads */
  CRITICAL_SECTION event_waiter_lock;
  LIST_ENTRY event_waiter_list;

  DWORD main_thread_id;

  SshEventStruct event_array[SSH_EVENT_FREELIST_SIZE];
} SshEloopStruct, *SshEloop;

/* Local variables */
static SshEloopStruct ssheloop;

/* Abort flag causing event loop to exit */
static UINT ssh_eloop_aborted = 0;

/* Data for waiting events in multiple threads. If the number of
   waitable events is more than 63 (MAXIMUM_WAIT_OBJECTS-1),
   waiting has to be performed in multiple threads with each
   thread capable of waiting up to 63 event handles. (Actually
   its 62 events plus a wakeup event.) The limitation of 63 events
   is built-in to WaitForMultipleObjects(). */
#define SSH_MAXIMUM_REAL_WAIT_OBJECTS    (MAXIMUM_WAIT_OBJECTS - 2)

/* Local prototypes */
static void
the_event_loop(void *params);

static void
ssh_eloop_get_current_time(ULARGE_INTEGER *tick_count, struct timeval *tv);

static void
ssh_eloop_add_time(long seconds, long microseconds, struct timeval *timeval);

static void
ssh_io_fd_complete(void *context);

/* Macros and inline functions for doubly-linked lists. (Unfortunately these
   are not readily defined in Windows user mode APIs...) */
#ifndef InitializeListHead

#define InitializeListHead(head)   \
do                                 \
{                                  \
 (head)->Flink = (head);           \
 (head)->Blink = (head);           \
} while (0);

#define IsListEmpty(head) \
 ((((head)->Flink == (head)) ? TRUE : FALSE))

__forceinline PLIST_ENTRY
RemoveHeadList(PLIST_ENTRY head)
{
  PLIST_ENTRY first = head->Flink;

  first->Flink->Blink = head;
  head->Flink = first->Flink;

  return first;
}

__forceinline void
RemoveEntryList(PLIST_ENTRY entry)
{
  PLIST_ENTRY next = entry->Flink;
  PLIST_ENTRY prev = entry->Blink;

  prev->Flink = next;
  next->Blink = prev;
}

__forceinline void
InsertTailList(PLIST_ENTRY head,
               PLIST_ENTRY entry)
{
  PLIST_ENTRY last = head->Blink;

  entry->Blink = last;
  entry->Flink = head;
  head->Blink = entry;
  last->Flink = entry;
}

#endif /* InitializeListHead */

__forceinline Boolean
ssh_move_list(PLIST_ENTRY to,
              PLIST_ENTRY from)
{
  if (!IsListEmpty(from))
    {
      /* Move items from source to destination list */
      *to = *from;
      to->Flink->Blink = to;
      to->Blink->Flink = to;
      /* Clear the source list */
      from->Flink = from;
      from->Blink = from;
      return TRUE; /* One or more item(s) moved */
    }
  else
    {
      to->Flink = to;
      to->Blink = to;
      return FALSE; /* No items moved */
    }
}

void
ssh_timeout_freelist_alloc(SshEloop eloop)
{
  unsigned int i;

  SSH_ASSERT(eloop != NULL);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating the freelist of timeouts"));

  InitializeListHead(&eloop->timeout_freelist);

  for (i = 0; i < SSH_TIMEOUT_FREELIST_INITIAL_SIZE; i++)
    {
      SshTimeout to = ssh_calloc(1, sizeof(*to));

      if (to)
        InsertTailList(&eloop->timeout_freelist,
                       &to->platform.os_win32.link);
    }
}

void
ssh_timeout_freelist_free(SshEloop eloop)
{
  SSH_ASSERT(eloop != NULL);

  SSH_DEBUG(SSH_D_HIGHOK, ("Freeing timeout freelist"));
  while (!IsListEmpty(&eloop->timeout_freelist))
    {
      ssh_free(CONTAINING_RECORD(RemoveHeadList(&eloop->timeout_freelist),
                                 SshTimeoutStruct,
                                 platform.os_win32.link));
    }
}

__inline SshTimeout
ssh_timeout_alloc(SshEloop eloop)
{
  SshTimeout created = NULL;

  EnterCriticalSection(&eloop->timeout_lock);
  if (!IsListEmpty(&eloop->timeout_freelist))
    {
      created = CONTAINING_RECORD(RemoveHeadList(&eloop->timeout_freelist),
                                  SshTimeoutStruct,
                                  platform.os_win32.link);
    }
  LeaveCriticalSection(&eloop->timeout_lock);

  if (created == NULL)
    {
      SSH_DEBUG(SSH_D_HIGHOK,
       ("Timeout freelist empty, allocating new entry"));
      created = ssh_calloc(1, sizeof(*created));
    }

  if (created)
    {
      InterlockedIncrement(&eloop->timeout_count);
    }

  return created;
}

__inline void
ssh_timeout_free(SshEloop eloop,
                 SshTimeout timeout)
{
#ifdef DEBUG_LIGHT
  timeout->platform.os_win32.is_expired = 0;
#endif /* DEBUG_LIGHT */

  if (timeout->is_dynamic)
    {
      InsertTailList(&eloop->timeout_freelist,
                     &timeout->platform.os_win32.link);
    }
  else
    {
      memset(timeout, 0, sizeof(*timeout));
    }

  InterlockedDecrement(&eloop->timeout_count);
}

static DWORD WINAPI
ssh_timeout_thread(void *context)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Timeout thread started"));

  while (InterlockedCompareExchange(&ssheloop.abort_timeout_thread,
                                    TRUE, TRUE) != TRUE)
    {
      struct timeval now;
      SshADTHandle ph;
      Boolean timeouts_expired = FALSE;
      SshUInt32 wait_timeout = INFINITE;

      /* Send all expired timeouts to event loop thread */

      EnterCriticalSection(&ssheloop.timeout_lock);

      ssh_eloop_get_current_time(&ssheloop.tick_count, &now);

      ph = ssh_adt_get_handle_to_location(ssheloop.to.ph_by_firing_time,
                                          SSH_ADT_DEFAULT);
      while (ph != SSH_ADT_INVALID)
        {
          SshTimeout current_timeout;
          long us, ms;

          current_timeout = ssh_adt_get(ssheloop.to.ph_by_firing_time, ph);

          /* Compute time left before the firing time. */
          ms = current_timeout->firing_time.tv_sec - now.tv_sec;
          us = current_timeout->firing_time.tv_usec - now.tv_usec;

          /* Catch bad firing times (e.g. zero) causing large negative ms */
          if (ms < 0)
            ms = -1;

          if (us < 0)
            {
              ms--;
              us += 1000000L;
              SSH_ASSERT(us >= 0 && us < 1000000L);
            }
          ms = 1000 * ms + us / 1000;

          if (ms > 0)
            {
              wait_timeout = ms;
              break;
            }

          current_timeout->platform.os_win32.is_expired = 1;

          ssh_adt_detach(ssheloop.to.ph_by_firing_time, ph);

          InsertTailList(&ssheloop.expired_timeouts,
                         &current_timeout->platform.os_win32.link);
          timeouts_expired = TRUE;

          ph = ssh_adt_get_handle_to_location(ssheloop.to.ph_by_firing_time,
                                              SSH_ADT_DEFAULT);
        }
      LeaveCriticalSection(&ssheloop.timeout_lock);

      if (timeouts_expired)
        SetEvent(ssheloop.eloop_wakeup_event);

      WaitForSingleObject(ssheloop.to_thread_event, wait_timeout);
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Timeout thread finished"));

  ExitThread(ERROR_SUCCESS);

  return ERROR_SUCCESS;
}


/*****************************************************************************
 * The event loop - initialization, uninitialization, looping
 ****************************************************************************/

void
ssh_event_loop_initialize(void)
{
  SshUInt32 i;
  WSADATA data;

  int major_version, minor_version;

  /* Initialize event loop lock. */
  InitializeCriticalSection(&ssheloop.lock);
  InitializeCriticalSection(&ssheloop.timeout_lock);
  InitializeCriticalSection(&ssheloop.io_event_list_lock);
  InitializeCriticalSection(&ssheloop.event_freelist_lock);

  ssheloop.main_thread_id = GetCurrentThreadId();

  ssheloop.tick_count.QuadPart = 0;

  /* Clear the data structures. */
  ssheloop.sockets = NULL;
  ssheloop.unregistered_sockets = NULL;

  InitializeListHead(&ssheloop.expired_timeouts);
  InitializeListHead(&ssheloop.io_event_list);
  InitializeListHead(&ssheloop.events);
  InitializeListHead(&ssheloop.unregistered_events);
  InitializeListHead(&ssheloop.signals);
  InitializeListHead(&ssheloop.unregistered_signals);

  InitializeListHead(&ssheloop.event_waiter_list);
  InitializeCriticalSection(&ssheloop.event_waiter_lock);

  /* Initialize the Winsock library, requesting winsock version 2 */
  if (WSAStartup(MAKEWORD(2,2), &data) != 0)
    ssh_fatal("Initialization of Windows Sockets (WINSOCK) failed.");

  /* Check the winsock version. */
  major_version = HIBYTE(data.wVersion);
  minor_version = LOBYTE(data.wVersion);

  if (major_version < 2 || (major_version == 2 && minor_version < 2))
    ssh_fatal("Unsupported Winsock version %d.%d.  At least 2.2 required.",
              major_version, minor_version);

  ssheloop.to_thread_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (ssheloop.to_thread_event == NULL)
    ssh_fatal("Failed to create event!");

  ssh_timeout_container_initialize(&ssheloop.to);
  /* Alloc the freelist of timeouts */
  ssh_timeout_freelist_alloc(&ssheloop);
  /* Initialize event context freelist */
  InitializeListHead(&ssheloop.event_freelist);
  for (i = 0; i < SSH_EVENT_FREELIST_SIZE; i++)
    {
      SshEvent event_obj = &ssheloop.event_array[i];

      event_obj->pre_allocated = 1;
      event_obj->hdr.obj_type = SSH_ELOOP_OBJECT_EVENT;
      event_obj->hdr.obj = event_obj;
      InsertTailList(&ssheloop.event_freelist, &event_obj->link);
    }

  /* Create event loop wakeup event */
  ssheloop.eloop_wakeup_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (ssheloop.eloop_wakeup_event == NULL)
    {
      ssh_fatal("Failed to create wakeup event!");
    }

  /* Create timeout thread */
  ssheloop.abort_timeout_thread = FALSE;
  ssheloop.timeout_thread = CreateThread(NULL, 1024,
                                         ssh_timeout_thread, &ssheloop,
                                         0, NULL);
  if (ssheloop.timeout_thread == NULL)
    ssh_fatal("Failed to start timeout thread!");
}


void
ssh_event_loop_uninitialize(void)
{
  SshSocket socket, next_socket;
  SshEvent event_obj;
  PLIST_ENTRY entry;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Uninitializing event loop"));

  InterlockedExchange(&ssh_eloop_aborted, 1);

  /* Free pending timeouts. */
  ssh_cancel_timeouts(SSH_ALL_CALLBACKS, SSH_ALL_CONTEXTS);

  /* Terminate timeout thread */
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Terminating timeout thread..."));
  InterlockedExchange(&ssheloop.abort_timeout_thread, TRUE);
  SetEvent(ssheloop.to_thread_event);
  WaitForSingleObject(ssheloop.timeout_thread, INFINITE);

  ssh_timeout_container_uninitialize(&ssheloop.to);

  /* Free the timeout's freelist */
  ssh_timeout_freelist_free(&ssheloop);

  /* Free socket records. */
  for (socket = ssheloop.sockets; socket; socket = next_socket)
    {
      next_socket = socket->next;
      ssh_io_unregister_fd(socket->sock, FALSE);
    }
  ssheloop.sockets = NULL;

  for (socket = ssheloop.unregistered_sockets; socket; socket = next_socket)
    {
      next_socket = socket->next;
      CloseHandle(socket->hevent);
      ssh_free(socket);
    }
  ssheloop.unregistered_sockets = NULL;

  /* Delete the event lists */
  while (!IsListEmpty(&ssheloop.events))
    {
      event_obj = CONTAINING_RECORD(ssheloop.events.Flink,
                                    SshEventStruct, link);
      ssh_event_loop_unregister_handle(event_obj->handle);
    }
  while (!IsListEmpty(&ssheloop.unregistered_events))
    {
      event_obj =
        CONTAINING_RECORD(RemoveHeadList(&ssheloop.unregistered_events),
                          SshEventStruct, link);

      if (event_obj->pre_allocated == 0)
        ssh_free(event_obj);
    }

  while (!IsListEmpty(&ssheloop.signals))
    {
      SshSignal ssh_signal;

      ssh_signal = CONTAINING_RECORD(ssheloop.signals.Flink,
                                     SshSignalStruct, link);
      ssh_unregister_signal(ssh_signal->signal);
    }
  while (!IsListEmpty(&ssheloop.unregistered_signals))
    {
      ssh_free(
        CONTAINING_RECORD(RemoveHeadList(&ssheloop.unregistered_signals),
                          SshSignalStruct, link));
    }

  /* Terminate event waiter threads */
  while (!IsListEmpty(&ssheloop.event_waiter_list))
    {
      SshWaitThreadContext wtctx;

      entry = RemoveHeadList(&ssheloop.event_waiter_list);
      wtctx = CONTAINING_RECORD(entry,
                                SshWaitThreadContextStruct,
                                global_link);

      EnterCriticalSection(&wtctx->lock);
      wtctx->wakeup_reason |= SSH_WAKEUP_EXIT;
      SetEvent(wtctx->wakeup_event);
      LeaveCriticalSection(&wtctx->lock);

      WaitForSingleObject(wtctx->thread, INFINITE);

      DeleteCriticalSection(&wtctx->lock);
      CloseHandle(wtctx->wakeup_event);

      ssh_free(wtctx);
    };

  CloseHandle(ssheloop.eloop_wakeup_event);
  CloseHandle(ssheloop.to_thread_event);

  /* Clean up the windows sockets library. */
  WSACleanup();

  DeleteCriticalSection(&ssheloop.event_waiter_lock);

  /* Destroy event loop lock object. */
  DeleteCriticalSection(&ssheloop.lock);
  DeleteCriticalSection(&ssheloop.timeout_lock);
  DeleteCriticalSection(&ssheloop.io_event_list_lock);
}


void
ssh_event_loop_run(void)
{
  /* stay in the loop until process ends */
  the_event_loop(NULL);
}


void
ssh_event_loop_abort(void)
{
  InterlockedExchange(&ssh_eloop_aborted, 1);
}


static DWORD WINAPI
ssh_event_waiter_thread(void *context)
{
  SshWaitThreadContext ctx = (SshWaitThreadContext)context;
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  SshEvent events[MAXIMUM_WAIT_OBJECTS];
  DWORD num_wait_handles;
  DWORD handle_index;
  DWORD wait_result;
#ifdef DEBUG_LIGHT
  DWORD thread_id = GetCurrentThreadId();
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(SSH_D_HIGHSTART,
            ("Event waiter thread %u started.", thread_id));

  handles[0] = ctx->wakeup_event;
  events[0] = NULL;

  while (TRUE)
    {
      PLIST_ENTRY entry;
      SshEvent e;

      /* Event(s) added or removed; reconstruct the handle array and restart
         the wait. */
      num_wait_handles = 1;

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Thread %u reconstructing handle array...",
                 thread_id));

      EnterCriticalSection(&ctx->lock);
      entry = ctx->wait_events.Flink;
      while (entry != &ctx->wait_events)
        {
          e = CONTAINING_RECORD(entry, SshEventStruct, waiter_link);

          if (e->manual_reset
              && (InterlockedCompareExchange(&e->signaled_count, 0, 0) != 0))
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Thread %u: skipped pending manual-reset event "
                         "(handle=0x%p, event=0x%p)",
                         thread_id, e->handle, e));
            }
          else
            {
              handles[num_wait_handles] = e->handle;
              events[num_wait_handles] = e;

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Thread %u wait[%u]: handle=0x%p, event=0x%p",
                         thread_id,
                         num_wait_handles,
                         handles[num_wait_handles],
                         events[num_wait_handles]));

              num_wait_handles++;
            }

          entry = entry->Flink;
        }

      while (!IsListEmpty(&ctx->unregistered_events))
        {
          entry = RemoveHeadList(&ctx->unregistered_events);
          e = CONTAINING_RECORD(entry, SshEventStruct, waiter_link);

          InterlockedExchangePointer(&e->waiter_thread, NULL);
        }
      LeaveCriticalSection(&ctx->lock);

      while (TRUE)
        {
          SSH_DEBUG(SSH_D_NICETOKNOW,
                    ("Thread %u waiting for %u event(s)...",
                     thread_id, num_wait_handles));

          wait_result = WaitForMultipleObjects(num_wait_handles,
                                               handles,
                                               FALSE,
                                               INFINITE);
          if (wait_result == WAIT_OBJECT_0)
            {
              /* Wakeup event signaled */
              DWORD wakeup_reason;

              EnterCriticalSection(&ctx->lock);
              wakeup_reason = ctx->wakeup_reason;
              ctx->wakeup_reason = 0;
              LeaveCriticalSection(&ctx->lock);

              if (wakeup_reason & SSH_WAKEUP_EXIT)
                {
                  SSH_DEBUG(SSH_D_HIGHOK,
                            ("Event waiter thread %u finished.",
                             thread_id));

                  ExitThread(ERROR_SUCCESS);
                }

              if (wakeup_reason & SSH_WAKEUP_RESTART_WAIT)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Thread %u received wakeup event",
                             thread_id));
                  break;
                }
            }
          else if ((wait_result > WAIT_OBJECT_0)
                   && (wait_result < WAIT_OBJECT_0 + num_wait_handles))
            {
              SshEvent event_obj;
              Boolean was_unregistered = TRUE;
              LONG signaled_count;

              handle_index = wait_result - WAIT_OBJECT_0;
              event_obj = events[handle_index];

              EnterCriticalSection(&ctx->lock);
              if (event_obj->unregistered == 0)
                {
                  was_unregistered = FALSE;
                  signaled_count =
                    InterlockedIncrement(&event_obj->signaled_count);
                }
              LeaveCriticalSection(&ctx->lock);

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Thread %u: signaled handle=0x%p, event=0x%p",
                         thread_id,
                         handles[handle_index],
                         event_obj));

              if (was_unregistered == FALSE && signaled_count == 1)
                {
                  EnterCriticalSection(&ssheloop.io_event_list_lock);
                  InsertTailList(&ssheloop.io_event_list,
                                 &event_obj->hdr.link);
                  LeaveCriticalSection(&ssheloop.io_event_list_lock);
                }

              SetEvent(ssheloop.eloop_wakeup_event);

              if (event_obj->manual_reset)
                {
                  SSH_DEBUG(SSH_D_NICETOKNOW,
                            ("Thread %u: manual-reset event 0x%p signaled; "
                             "temporarily removing this event from wait "
                             "list",
                             thread_id, event_obj));
                  break; /* Reconstruct handle array */
                }
            }
          else if ((wait_result > WAIT_ABANDONED_0)
                   && (wait_result < WAIT_ABANDONED_0 + num_wait_handles))
            {
              handle_index = wait_result - WAIT_ABANDONED_0;

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Thread %u: wait completed with ABANDONED status! "
                         "(handle=0x%p, event=0x%p)",
                         thread_id,
                         handles[handle_index],
                         events[handle_index]));
              break;  /* Reconstruct handle array */
            }
          else
            {
              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Wait Failed for unknown reason, "
                         "last error = %lu, num handles %d",
                         GetLastError(), num_wait_handles));
              break;  /* Reconstruct handle array */
            }
        }
    }

  SSH_NOTREACHED;

  return ERROR_GEN_FAILURE;
}


/* === WAITING FOR EVENTS WITH THREADS === */


/*
*/
static Boolean ssh_event_loop_check_for_termination = TRUE;

void
ssh_event_loop_dont_check_termination(void)
{
  ssh_event_loop_check_for_termination = FALSE;
}

void
ssh_event_loop_lock(void)
{
  EnterCriticalSection(&ssheloop.lock);
}

void
ssh_event_loop_unlock(void)
{
  LeaveCriticalSection(&ssheloop.lock);
}


/*****************************************************************************
 * Timers
 ****************************************************************************/

/* Internal timeout registering workhorse. External API is below. */
SshTimeout
ssh_register_timeout_internal(SshTimeout timeout,
                              long seconds, long microseconds,
                              SshTimeoutCallback callback, void *context)
{
  SshTimeout created = timeout, p;
  SshADTHandle handle;
  Boolean is_zero_timeout = FALSE;

  created->callback = callback;
  created->context = context;

  EnterCriticalSection(&ssheloop.timeout_lock);

  if ((seconds == 0) && (microseconds == 0))
    {
      is_zero_timeout = TRUE;
      created->platform.os_win32.is_expired = 1;
    }
  else
    {
      ssh_eloop_get_current_time(&ssheloop.tick_count, &timeout->firing_time);
      ssh_eloop_add_time(seconds, microseconds, &timeout->firing_time);
      created->platform.os_win32.is_expired = 0;
    }

  /* Insert the new timeout in the sorted list of timeouts. */
  created->identifier = ssheloop.to.next_identifier++;
  ssh_adt_insert(ssheloop.to.map_by_identifier, created);

  if (is_zero_timeout)
    {
      /* Put the zero-timeout directly to expired_timeouts list. */
      InsertTailList(&ssheloop.expired_timeouts,
                     &created->platform.os_win32.link);
    }
  else
    {
      ssh_adt_insert(ssheloop.to.ph_by_firing_time, created);
    }

  if ((handle =
       ssh_adt_get_handle_to_equal(ssheloop.to.map_by_context, created))
      != SSH_ADT_INVALID)
    {
      p = ssh_adt_get(ssheloop.to.map_by_context, handle);
      created->next = p->next;
      created->prev = p;
      if (p->next)
        p->next->prev = created;
      p->next = created;
    }
  else
    {
      created->next = NULL;
      created->prev = NULL;
      ssh_adt_insert(ssheloop.to.map_by_context, created);
    }
  LeaveCriticalSection(&ssheloop.timeout_lock);

  /* Wake up the timeout thread (non-zero timeout) or the event loop (zero
     timeout) */
  if (is_zero_timeout)
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Registered zero-timeout 0x%p: cb=0x%p, ctx=0x%p",
                 timeout, callback, context));

      SetEvent(ssheloop.eloop_wakeup_event);
    }
  else
    {
      SSH_DEBUG(SSH_D_LOWOK,
                ("Timeout 0x%p registered at %x, cb=0x%p, ctx=0x%p",
                 timeout,
                 timeout->firing_time.tv_sec,
                 callback, context));

      SetEvent(ssheloop.to_thread_event);
    }

  return timeout;
}

SshTimeout
ssh_xregister_timeout(long seconds, long microseconds,
                      SshTimeoutCallback callback, void *context)
{
  SshTimeout created = ssh_timeout_alloc(&ssheloop);

  if (created == NULL)
    {
      ssh_fatal("Insufficient memory available to create timeout.");
    }

  created->is_dynamic = TRUE;

  return ssh_register_timeout_internal(created, seconds, microseconds,
                                       callback, context);

}

SshTimeout
ssh_register_timeout(SshTimeout timeout,
                     long seconds, long microseconds,
                     SshTimeoutCallback callback, void *context)
{
  if (timeout != NULL)
    {
      InterlockedIncrement(&ssheloop.timeout_count);

      memset(timeout, 0, sizeof(*timeout));

      timeout->is_dynamic = FALSE;
    }
  else
    {
      /* Use the freelist and get the timeout */
      timeout = ssh_timeout_alloc(&ssheloop);
      if (timeout == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Insufficient memory to allocate timeout."));
          return NULL;
        }

      timeout->is_dynamic = TRUE;
    }

  return ssh_register_timeout_internal(timeout, seconds, microseconds,
                                       callback, context);
}

SshTimeout
ssh_xregister_idle_timeout(long seconds, long microseconds,
                           SshTimeoutCallback callback, void *context)
{
  SSH_TRACE(SSH_D_NICETOKNOW, ("Idle timeouts not yet implemented."));






  return NULL;
}

void
ssh_timeout_remove_from_id_map(SshTimeout timeout,
                               SshADTHandle mh)
{
  SshADTHandle cmh;

  ssh_adt_detach(ssheloop.to.map_by_identifier, mh);

  if (timeout->prev == NULL)
    {
      cmh = &timeout->adt_ctx_map_hdr;
      ssh_adt_detach(ssheloop.to.map_by_context, cmh);
      if (timeout->next)
        {
          timeout->next->prev = NULL;
          ssh_adt_insert(ssheloop.to.map_by_context, timeout->next);
        }
    }
  else
    {
      timeout->prev->next = timeout->next;
      if (timeout->next)
        timeout->next->prev = timeout->prev;
    }
}

static void
ssh_to_filter_list(SshTimeout list,
                   SshTimeoutCallback callback,
                   void *context,
                   SshTimeout *cancel,
                   SshTimeout *keep)
{
  SshTimeout to, nto, cto, kto;

  to = list;

  for (kto = cto = NULL; to; to = nto)
    {
      nto = to->next;

      if ((callback == SSH_ALL_CALLBACKS || to->callback == callback) &&
          (context == SSH_ALL_CONTEXTS || to->context == context))
        {
          /* Add to list of cancelled */
          if (cto)
            {
              to->next = cto->next;
              cto->next = to;
            }
          else
            {
              cto = to;
              to->next = NULL;
            }
        }
      else
        {
          /* Timeout was not cancelled. Add to list of remaining. */
          if (kto)
            {
              to->next = kto->next;
              if (to->next)
                to->next->prev = to;
              to->prev = kto;
              kto->next = to;
            }
          else
            {
              kto = to;
              to->next = NULL;
              to->prev = NULL;
            }
        }
    }
  *cancel = cto;
  *keep = kto;
}

void
ssh_timeout_delete_from_contextmap(SshTimeoutContainer toc,
                                   SshTimeoutCallback callback,
                                   void *context,
                                   SshADTHandle cmh)
{
  SshADTHandle ph, mh;
  SshTimeout to, nto, cto, rto;

  to = ssh_adt_get(toc->map_by_context, cmh);
  ssh_adt_detach(toc->map_by_context, cmh);

  ssh_to_filter_list(to, callback, context, &cto, &rto);

  /* Re-insert the timeouts not cancelled. */
  if (rto)
    ssh_adt_insert(toc->map_by_context, rto);

  /* Cancel the rest of timeouts */
  for (to = cto; to; to = nto)
    {
      nto = to->next;
      if (to->platform.os_win32.is_expired)
        {
          /* Remove the timeout from expired_timeouts list if the timeout
             has already expired */
          RemoveEntryList(&to->platform.os_win32.link);
        }
      else
        {
          ph = &to->adt_ft_ph_hdr;
          ssh_adt_detach(toc->ph_by_firing_time, ph);
        }
      mh = &to->adt_id_map_hdr;
      ssh_adt_detach(toc->map_by_identifier, mh);

      ssh_timeout_free(&ssheloop, to);
    }
}


void
ssh_cancel_timeout(SshTimeout timeout)
{
  SshTimeout p;
  SshADTHandle mh, ph;

  SSH_DEBUG(SSH_D_LOWSTART, ("Cancelling timeout 0x%p...", timeout));

  if (timeout == NULL)
    return;

  EnterCriticalSection(&ssheloop.timeout_lock);
  if ((mh =
       ssh_adt_get_handle_to_equal(ssheloop.to.map_by_identifier, timeout))
      != SSH_ADT_INVALID)
    {
      p = ssh_adt_get(ssheloop.to.map_by_identifier, mh);

      SSH_DEBUG(SSH_D_MIDOK, ("cancelled %qd", p->identifier));

      ph = &p->adt_ft_ph_hdr;

      if (p->platform.os_win32.is_expired)
        {
          RemoveEntryList(&p->platform.os_win32.link);
        }
      else
        {
          ssh_adt_detach(ssheloop.to.ph_by_firing_time, ph);
        }

      ssh_timeout_remove_from_id_map(p, mh);
      ssh_timeout_free(&ssheloop, p);
    }
  LeaveCriticalSection(&ssheloop.timeout_lock);
}

/* Cancel all timeouts that call `callback' with context `context'.
   SSH_ALL_CALLBACKS and SSH_ALL_CONTEXTS can be used as wildcards. */
void
ssh_cancel_timeouts(SshTimeoutCallback callback, void *context)
{
  SshADTHandle nmh, mh, cmh;
  SshTimeoutStruct probe;

  EnterCriticalSection(&ssheloop.timeout_lock);
  if (context != SSH_ALL_CONTEXTS)
    {
      /* Cancel with given context. */
      probe.context = context;
      if ((cmh =
           ssh_adt_get_handle_to_equal(ssheloop.to.map_by_context, &probe))
          != SSH_ADT_INVALID)
        {
          ssh_timeout_delete_from_contextmap(&ssheloop.to,
                                             callback, context, cmh);
        }
    }
  else
    {
      /* Cancel with wildcard context. Enumerates context map and
         traverses its lists. */
      for (mh = ssh_adt_enumerate_start(ssheloop.to.map_by_context);
           mh != SSH_ADT_INVALID;
           mh = nmh)
        {
          nmh = ssh_adt_enumerate_next(ssheloop.to.map_by_context, mh);
          ssh_timeout_delete_from_contextmap(&ssheloop.to,
                                             callback, context, mh);
        }
    }
  LeaveCriticalSection(&ssheloop.timeout_lock);

  /* Wake up the event timeout thread. */
  SetEvent(ssheloop.to_thread_event);
}

/* Update the 64-bit millisecond tick count in *tick_count and convert
   it into a struct timeval into *tv. Needs exclusive access to the
   64-bit tick count. */

static void
ssh_eloop_get_current_time(ULARGE_INTEGER *tick_count, struct timeval *tv)
{
  DWORD tick_count_low, difference;

  /* Get milliseconds since system startup. Wraps every 49.7 days. */
  tick_count_low = GetTickCount();

  /* Get unsigned 32-bit difference. */
  difference = tick_count_low - tick_count->LowPart;

  /* Update tick count with 64-bit addition which correctly takes care
     of the possible wrap of the low 32 bits. */
  tick_count->QuadPart += difference;

  tv->tv_sec = (long)(tick_count->QuadPart / 1000);
  tv->tv_usec = (long)(tick_count->QuadPart % 1000 * 1000);
}


/* Add timer value in seconds and microseconds to absolute system
   uptime. */

static void
ssh_eloop_add_time(long seconds, long microseconds, struct timeval *timeval)
{
  long sec, usec;

  if (seconds > 1000000000)
    {
      sec = 1000000000;
      usec = 0;
    }
  else
    {
      sec = seconds + microseconds / 1000000L;
      usec = microseconds % 1000000L;
    }

  /* Move full seconds from microseconds to seconds. */
  sec += usec / 1000000L;
  usec %= 1000000L;

  /* Add current time to the specified time. */
  timeval->tv_sec += sec;
  timeval->tv_usec += usec;
  if (timeval->tv_usec > 999999L)
    {
      timeval->tv_usec -= 1000000L;
      timeval->tv_sec++;
    }
}

/* Signal handlers */

void
ssh_eloop_signal_handler(void *context)
{
#pragma warning(disable : 4311)
  int signal_num = (int)context;
#pragma warning(default : 4311)
  SshSignal ssh_signal = NULL;
  PLIST_ENTRY entry;

  SSH_DEBUG(SSH_D_MIDRESULT, ("Received signal %d.", signal_num));

  entry = ssheloop.signals.Flink;
  while (entry != &ssheloop.signals)
    {
      ssh_signal = CONTAINING_RECORD(entry, SshSignalStruct, link);
      if (ssh_signal->signal == signal_num
          && !ssh_signal->unregistered
          && ssh_signal->callback)
        {
          EnterCriticalSection(&ssheloop.io_event_list_lock);
          InsertTailList(&ssheloop.io_event_list, &ssh_signal->hdr.link);
          LeaveCriticalSection(&ssheloop.io_event_list_lock);

          SetEvent(ssheloop.eloop_wakeup_event);
        }

      entry = entry->Flink;
    }
}

void
ssh_eloop_signal_callback(int signal_num)
{
  if (InterlockedCompareExchange(&ssh_eloop_aborted, 1, 1) == 1)
    {
      SSH_DEBUG(SSH_D_NICETOKNOW, ("Event loop aborted, ignoring signal!"));
      return;
    }

#pragma warning(disable : 4312)
  ssh_register_threaded_timeout(NULL,
                                0, 0,
                                ssh_eloop_signal_handler,
                                (void *)signal_num);
#pragma warning(default : 4312)

  signal(signal_num, ssh_eloop_signal_callback);
}

void
ssh_register_signal(int signal_num,
                    SshSignalCallback callback,
                    void *context)
{
  SshSignal ssh_signal = NULL;
  PLIST_ENTRY entry;

  /* Check if the signal has been registered earlier un unregister earlier
     registerations. */
  entry = ssheloop.signals.Flink;
  while (entry != &ssheloop.signals)
    {
      PLIST_ENTRY next = entry->Flink;

      ssh_signal = CONTAINING_RECORD(entry, SshSignalStruct, link);
      if (ssh_signal->signal == signal_num)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Signal reregistered"));
          RemoveEntryList(entry);
          ssh_free(ssh_signal);
        }

      entry = next;
    }

  ssh_signal = ssh_calloc(1, sizeof(*ssh_signal));
  if (ssh_signal)
    {
      ssh_signal->hdr.obj_type = SSH_ELOOP_OBJECT_SIGNAL;
      ssh_signal->hdr.obj = ssh_signal;

      ssh_signal->callback = callback;
      ssh_signal->context = context;
      ssh_signal->signal = signal_num;

      InsertTailList(&ssheloop.signals, &ssh_signal->link);

      signal(signal_num, ssh_eloop_signal_callback);
    }
}


void
ssh_unregister_signal(int signal_num)
{
  SshSignal ssh_signal = NULL;
  PLIST_ENTRY entry;

  SSH_DEBUG(SSH_D_MIDRESULT, ("Unregistering signal %d.", signal_num));

  entry = ssheloop.signals.Flink;
  while (entry != &ssheloop.signals)
    {
      ssh_signal = CONTAINING_RECORD(entry, SshSignalStruct, link);
      if (ssh_signal->signal == signal_num)
        {
          RemoveEntryList(entry);
          EnterCriticalSection(&ssheloop.lock);
          InsertTailList(&ssheloop.unregistered_signals, &ssh_signal->link);
          LeaveCriticalSection(&ssheloop.lock);
          break;
        }

      entry = entry->Flink;
    }

  signal(signal_num, SIG_DFL);
}

/* Waitable handle registration */
void
ssh_event_loop_register_handle(HANDLE hevent,
                               Boolean manual_reset,
                               SshEventCallback callback,
                               void *context)
{
  SshEvent event_obj = NULL;

  SSH_DEBUG(SSH_D_MIDRESULT,
            ("Registering new handle 0x%p, handle count before %u",
             hevent, ssheloop.num_registered_events));
  if (hevent == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot register NULL handle!"));
      return;
    }

  SSH_ASSERT(ssheloop.main_thread_id == GetCurrentThreadId());

  EnterCriticalSection(&ssheloop.event_freelist_lock);
  if (!IsListEmpty(&ssheloop.event_freelist))
    {
      PLIST_ENTRY entry = RemoveHeadList(&ssheloop.event_freelist);
      event_obj = CONTAINING_RECORD(entry, SshEventStruct, link);
    }
  LeaveCriticalSection(&ssheloop.event_freelist_lock);

  if (event_obj == NULL)
    event_obj = ssh_calloc(1, sizeof(*event_obj));

  if (event_obj)
    {
      SshWaitThreadContext wait_thread = NULL;
      PLIST_ENTRY entry;

      event_obj->hdr.obj_type = SSH_ELOOP_OBJECT_EVENT;
      event_obj->hdr.obj = event_obj;

      event_obj->handle = hevent;
      event_obj->callback = callback;
      event_obj->context = context;
      event_obj->unregistered = 0;
      event_obj->signaled_count = 0;
      if (manual_reset)
        event_obj->manual_reset = 1;
      else
        event_obj->manual_reset = 0;

      InsertTailList(&ssheloop.events, &event_obj->link);
      ssheloop.num_registered_events++;

      EnterCriticalSection(&ssheloop.event_waiter_lock);
      entry = ssheloop.event_waiter_list.Flink;
      while ((entry != &ssheloop.event_waiter_list)
             && (wait_thread == NULL))
        {
          SshWaitThreadContext wtctx;

          wtctx = CONTAINING_RECORD(entry,
                                    SshWaitThreadContextStruct,
                                    global_link);

          EnterCriticalSection(&wtctx->lock);
          if (wtctx->num_wait_events < SSH_MAXIMUM_REAL_WAIT_OBJECTS)
            {
              wtctx->num_wait_events++;
              event_obj->waiter_thread = wtctx;

              InsertTailList(&wtctx->wait_events, &event_obj->waiter_link);

              SSH_DEBUG(SSH_D_NICETOKNOW,
                        ("Waking up thread: %u...", wtctx->thread));

              wtctx->wakeup_reason |= SSH_WAKEUP_RESTART_WAIT;
              SetEvent(wtctx->wakeup_event);
              wait_thread = wtctx;
            }
          LeaveCriticalSection(&wtctx->lock);

          entry = entry->Flink;
        }

      if (wait_thread == NULL)
        {
          wait_thread = ssh_calloc(1, sizeof(*wait_thread));

          if (wait_thread == NULL)
            ssh_fatal("Failed to allocate new waiter thread context");

          InitializeCriticalSection(&wait_thread->lock);
          InitializeListHead(&wait_thread->wait_events);
          InitializeListHead(&wait_thread->unregistered_events);

          wait_thread->wakeup_event = CreateEvent(NULL, FALSE, FALSE, NULL);
          if (wait_thread->wakeup_event == NULL)
            ssh_fatal("Failed to create notification event for waiter thread");

          wait_thread->num_wait_events = 1;
          event_obj->waiter_thread = wait_thread;
          InsertTailList(&wait_thread->wait_events, &event_obj->waiter_link);

          wait_thread->thread = CreateThread(NULL, 1024,
                                             ssh_event_waiter_thread,
                                             wait_thread, 0, NULL);
          if (wait_thread->thread == NULL)
            ssh_fatal("Failed to create waiter thread!");

          InsertTailList(&ssheloop.event_waiter_list,
                         &wait_thread->global_link);
        }
      LeaveCriticalSection(&ssheloop.event_waiter_lock);
    }
  else
    {



      ssh_fatal("Failed to allocated memory for new event");
    }
}


void
ssh_event_loop_unregister_handle(HANDLE hevent)
{
  PLIST_ENTRY entry;
  SshEvent event_obj;

  SSH_DEBUG(SSH_D_MIDRESULT, ("Unregistering handle 0x%p", hevent));

  if (hevent == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Not unregistering NULL handle"));
      return;
    }

  SSH_ASSERT(ssheloop.main_thread_id == GetCurrentThreadId());

  entry = ssheloop.events.Flink;
  while (entry != &ssheloop.events)
    {
      event_obj = CONTAINING_RECORD(entry, SshEventStruct, link);
      if (event_obj->handle == hevent && !event_obj->unregistered)
        {
          SshWaitThreadContext wtctx;
          Boolean was_signaled = FALSE;
          SshEvent io_event = NULL;
          PLIST_ENTRY e;

          SSH_ASSERT(event_obj->waiter_thread != NULL);
          wtctx = event_obj->waiter_thread;

          EnterCriticalSection(&wtctx->lock);
          SSH_ASSERT(wtctx->num_wait_events > 0);
          wtctx->num_wait_events--;

          event_obj->unregistered++;

          if (event_obj->signaled_count > 0)
            was_signaled = TRUE;

          /* Move event from 'wait' list to 'unregistered' list */
          RemoveEntryList(&event_obj->waiter_link);
          InsertTailList(&wtctx->unregistered_events,
                         &event_obj->waiter_link);
          LeaveCriticalSection(&wtctx->lock);

          wtctx->wakeup_reason |= SSH_WAKEUP_RESTART_WAIT;
          SetEvent(wtctx->wakeup_event);

          /* Wait until waiter_thread has reconstructed handle table (i.e.
             it has removed this event from the wait list) */
          while (InterlockedCompareExchangePointer(&event_obj->waiter_thread,
                                                   NULL, NULL) != NULL)
            Sleep(1);

          /* Move this item to the list of unregistered events */
          RemoveEntryList(entry);

          if (was_signaled == TRUE)
            {
              /* Go through the io_event_list and remove the event we
                 are handling from the list. */
              EnterCriticalSection(&ssheloop.io_event_list_lock);
              e = ssheloop.io_event_list.Flink;

              /* The entry MUST be found from the io_event_list at this stage,
                 so therefore using while (TRUE) loop. In error case we are
                 in infinite loop. */
              while (TRUE)
                {
                  SshEloopObjHeader hdr;

                  hdr = CONTAINING_RECORD(&e->Flink,
                                          SshEloopObjHeaderStruct, link);

                  io_event = hdr->obj;
                  SSH_ASSERT(hdr->obj_type == SSH_ELOOP_OBJECT_EVENT ||
                             hdr->obj_type == SSH_ELOOP_OBJECT_SIGNAL);
                  if (hdr->obj_type == SSH_ELOOP_OBJECT_EVENT &&
                      io_event == event_obj)
                    {
                      RemoveEntryList(e);
                      goto out;
                    }
                  e = e->Flink;
                }

            out:
              LeaveCriticalSection(&ssheloop.io_event_list_lock);
            }

          EnterCriticalSection(&ssheloop.lock);
          InsertTailList(&ssheloop.unregistered_events, &event_obj->link);
          LeaveCriticalSection(&ssheloop.lock);

          ssheloop.num_registered_events--;

          break;
        }

      entry = entry->Flink;
    }
}


/**************************** Socket I/O *********************************/

void
ssh_io_xregister_fd(SshIOHandle fd,
                    SshIoCallback callback,
                                void *context)
{
  if (ssh_io_register_fd(fd, callback, context) == FALSE)
    ssh_fatal("Insufficient memory available to register file descriptor.");
}

Boolean
ssh_io_register_fd(SshIOHandle fd,
                   SshIoCallback callback,
                   void *context)
{
  SshSocket s;
  SSH_DEBUG(SSH_D_NICETOKNOW, ("ssh_io_register_fd(fd = 0x%p)", fd));

  s = ssh_calloc(1, sizeof(*s));

  if (s == NULL)
    return FALSE;

  s->hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (s->hevent == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to create event object"));
      ssh_free(s);
      return FALSE;
    }
  ssh_event_loop_register_handle(s->hevent, FALSE, ssh_io_fd_complete, s);

  s->sock = fd;
  s->callback = callback;
  s->context = context;
  s->next = ssheloop.sockets;
  ssheloop.sockets = s;

  return TRUE;
}

void
ssh_io_unregister_fd(SshIOHandle sock,
                     Boolean keep_nonblocking)
{
  SshSocket s, *sp;

  /* Find the socket in the list. */
  for (sp = &ssheloop.sockets; *sp && (*sp)->sock != sock;
       sp = &(*sp)->next);

  /* If not found, return with a warning. */
   if (!*sp)
    {
      ssh_warning("ssh_socket_unregister: socket 0x%p not found", sock);
      return;
    }

  /* Remove the socket from the list. */
  s = *sp;
  *sp = s->next;
  /* Move to list of unregistered sockets */
  s->next = ssheloop.unregistered_sockets;
  ssheloop.unregistered_sockets = s;

  /* Cancel the associationg between network events and the socket. */
  WSAEventSelect(s->sock, s->hevent, 0);
  ssh_event_loop_unregister_handle(s->hevent);

  s->unregistered = 1;
}

#ifdef DEBUG_LIGHT
static int
ssh_io_event_render(unsigned char *buf,
                    int buf_size,
                    int precision,
                    void *datum)
{
  unsigned int *io_event = (unsigned int *)datum;
  int len;
  const unsigned char *event_str = NULL;

  switch (*io_event)
    {
    case SSH_IO_CLOSED:
      event_str = "CLOSED";
      break;

    case SSH_IO_READ:
      event_str = "READ";
      break;

    case SSH_IO_WRITE:
      event_str = "WRITE";
      break;

    case SSH_IO_READ | SSH_IO_WRITE:
      event_str = "(READ|WRITE)";
      break;

    default:
      break;
    }

  if (event_str != NULL)
    ssh_snprintf(buf, buf_size + 1, event_str);
  else
    ssh_snprintf(buf, buf_size + 1, "0x%08X", *io_event);

  len = ssh_ustrlen(buf);

  if (precision >= 0)
    if (len > precision)
      len = precision;

  if (len >= buf_size)
    return buf_size + 1;

  return len;
}

#endif /* DEBUG_LIGHT */

/* This is a callback for a signaled socket event */
static void
ssh_io_fd_complete(void *context)
{
  SshSocket s = (SshSocket)context;
  WSANETWORKEVENTS events;
  unsigned int io_event = 0;
  unsigned error = 0;
  unsigned net_events = 0;

  SSH_DEBUG(SSH_D_MIDRESULT,
            ("Handling socket events (socket = 0x%p)", s));

  /* Get network events that have occurred for the indicated socket AND
     reset the associated event object. */
  WSAEnumNetworkEvents(s->sock, s->hevent, &events);

  net_events = (unsigned)events.lNetworkEvents;
  if (net_events & FD_CONNECT)
    error = events.iErrorCode[FD_CONNECT_BIT];

  if (s->callback != NULL_FNPTR)
    {
      if (net_events & FD_CLOSE)
        {
          io_event = SSH_IO_CLOSED;
        }
      else
        {
          io_event |= (net_events & FD_READ) ? SSH_IO_READ : 0;
          io_event |= (net_events & FD_WRITE) ? SSH_IO_WRITE : 0;
          if (io_event == 0)
            io_event = SSH_IO_WRITE;

          /* If we got an error when we tried to connect we pass
             an SSH_IO_CLOSED to the event callback. */
          if (net_events & FD_CONNECT && error != 0)
            io_event = SSH_IO_CLOSED;
        }

      SSH_DEBUG(SSH_D_NICETOKNOW,
                ("Executing socket event: "
                 "callback=0x%p, event=%@, context=0x%p",
                 s->callback,
                 ssh_io_event_render, &io_event,
                 s->context));

      /* We don't need to take event loop lock any more here, because
         ssh_io_fd_complete() is an event loop callback (and thus the
         lock is already held). */
      (s->callback)(io_event, s->context);
    }
}


void ssh_io_set_fd_request(SshIOHandle fd,
                           unsigned int events)
{
  SshSocket s;

  /* Look for the requested socket */
  for (s = ssheloop.sockets; s && s->sock != fd; s = s->next)
    {};

  if (s == NULL)
    {
      SSH_DEBUG(SSH_D_UNCOMMON, ("ssh_io_set_fd_request: No socket found!"));
      return;
    }

  if (s->unregistered == 0)
    {
      int ret = WSAEventSelect(fd, s->hevent, events);

      if (ret != 0)
        SSH_DEBUG(SSH_D_FAIL, ("ssh_io_set_fd_request() failed %d, %d",
                               ret, WSAGetLastError()));
    }
}


static void
the_event_loop(void *params)
{
  DWORD wait_time = INFINITE;

  SSH_DEBUG(SSH_D_HIGHSTART, ("Event loop started"));

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Starting timeout thread..."));

  /* SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL); */

  for (;;)
    {
      LIST_ENTRY unregistered_events;
      LIST_ENTRY unregistered_signals;
      Boolean events_pending = FALSE;
      DWORD wait_time_ms = INFINITE;

      do
        {
          /* Check if the event loop should be exited. */
          if (InterlockedCompareExchange(&ssh_eloop_aborted, 1, 1) == 1)
            {
              SSH_DEBUG(SSH_D_NICETOKNOW, ("Event loop aborted!"));
              return;
            }

          events_pending = FALSE;

          EnterCriticalSection(&ssheloop.io_event_list_lock);
          if (!IsListEmpty(&ssheloop.io_event_list))
            {
              SshEloopObjHeader hdr;

              hdr = CONTAINING_RECORD(RemoveHeadList(&ssheloop.io_event_list),
                                      SshEloopObjHeaderStruct, link);

              if (!IsListEmpty(&ssheloop.io_event_list))
                events_pending = TRUE;

              LeaveCriticalSection(&ssheloop.io_event_list_lock);

              switch (hdr->obj_type)
                {
                case SSH_ELOOP_OBJECT_EVENT:
                  {
                    SshEvent e = hdr->obj;

                    if (e->callback)
                      {
                        ULONG count;

                        count = InterlockedExchange(&e->signaled_count, 0);

                        if (e->unregistered)
                          {
                            ssh_fatal("Unregistered event pulled from "
                                      "queue; not executing the callback"
                                      " function.");
                          }
                        else
                          {
                            SSH_DEBUG(SSH_D_NICETOKNOW,
                                      ("Executing event callback: "
                                       "event=0x%p, callback=0x%p, "
                                       "context=0x%p",
                                       e, e->callback, e->context));

                            EnterCriticalSection(&ssheloop.lock);
                            (e->callback)(e->context);
                            LeaveCriticalSection(&ssheloop.lock);

                            if (e->manual_reset && !e->unregistered)
                              {
                                SshWaitThreadContext wtctx;

                                SSH_DEBUG(SSH_D_NICETOKNOW,
                                          ("Adding manual-reset event 0x%p "
                                           "back to wait list",
                                           e));

                                SSH_ASSERT(e->waiter_thread != NULL);
                                wtctx = e->waiter_thread;

                                EnterCriticalSection(&wtctx->lock);
                                wtctx->wakeup_reason
                                  |= SSH_WAKEUP_RESTART_WAIT;
                                LeaveCriticalSection(&wtctx->lock);

                                SetEvent(wtctx->wakeup_event);
                              }
                          }
                      }
                  }
                  break;

                case SSH_ELOOP_OBJECT_SIGNAL:
                  {
                    SshSignal s = hdr->obj;

                    SSH_DEBUG(SSH_D_NICETOKNOW,
                              ("Executing signal callback: "
                               "callback=0x%p, signal=%u, context=0x%p",
                               s->callback, s->signal, s->context));

                    EnterCriticalSection(&ssheloop.lock);
                    (s->callback)(s->signal, s->context);
                    LeaveCriticalSection(&ssheloop.lock);
                  }
                  break;

                default:
                  SSH_NOTREACHED;
                  break;
                }

              wait_time_ms = 100;
            }
          else
            {
              LeaveCriticalSection(&ssheloop.io_event_list_lock);

              /* "Bottom of the event loop". Time to execute expired timeouts
                 (if any) */
              EnterCriticalSection(&ssheloop.timeout_lock);
              if (!IsListEmpty(&ssheloop.expired_timeouts))
                {
                  SshTimeout timeout;
                  SshTimeoutCallback callback = NULL_FNPTR;
                  void *context = NULL;

                  timeout =
                    CONTAINING_RECORD(
                                  RemoveHeadList(&ssheloop.expired_timeouts),
                                  SshTimeoutStruct,
                                  platform.os_win32.link);

                  callback = timeout->callback;
                  context = timeout->context;

                  SSH_ASSERT(timeout->platform.os_win32.is_expired == 1);

                  ssh_timeout_remove_from_id_map(timeout,
                                                 &timeout->adt_id_map_hdr);
                  ssh_timeout_free(&ssheloop, timeout);
                  LeaveCriticalSection(&ssheloop.timeout_lock);

                  SSH_ASSERT(callback != NULL_FNPTR);

                  if (callback != NULL_FNPTR)
                    {
                      SSH_DEBUG(SSH_D_NICETOKNOW,
                                ("Executing timeout 0x%p: "
                                 "callback=0x%p, context=0x%p",
                                 timeout, callback, context));

                      EnterCriticalSection(&ssheloop.lock);
                      (callback)(context);
                      LeaveCriticalSection(&ssheloop.lock);
                    }

                  EnterCriticalSection(&ssheloop.timeout_lock);

                  if (!IsListEmpty(&ssheloop.expired_timeouts))
                    events_pending = TRUE;

                  wait_time_ms = 100;
                }
              LeaveCriticalSection(&ssheloop.timeout_lock);
            }
        }
      while (events_pending);

      /* Currently we don't have any pending I/O events or expired timeouts.
         Now we have excellent time to perform some cleanup (before we restart
         waiting events)... */
      EnterCriticalSection(&ssheloop.lock);
      ssh_move_list(&unregistered_events,
                    &ssheloop.unregistered_events);
      ssh_move_list(&unregistered_signals,
                    &ssheloop.unregistered_signals);
      LeaveCriticalSection(&ssheloop.lock);

      while (!IsListEmpty(&unregistered_events))
        {
          SshEvent event_obj;

          event_obj =
            CONTAINING_RECORD(RemoveHeadList(&unregistered_events),
                              SshEventStruct, link);

          if (event_obj->pre_allocated)
            {
              EnterCriticalSection(&ssheloop.event_freelist_lock);
              InsertTailList(&ssheloop.event_freelist,
                             &event_obj->link);
              LeaveCriticalSection(&ssheloop.event_freelist_lock);
            }
          else
            {
              ssh_free(event_obj);
            }
        }

      while (!IsListEmpty(&unregistered_signals))
        {
          ssh_free(CONTAINING_RECORD(RemoveHeadList(&unregistered_signals),
                                     SshSignalStruct, link));
        }

      while (ssheloop.unregistered_sockets)
        {
          SshSocket s = ssheloop.unregistered_sockets;

          ssheloop.unregistered_sockets = s->next;

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Closing event: 0x%p", s->hevent));
          CloseHandle(s->hevent);

          SSH_DEBUG(SSH_D_NICETOKNOW, ("Freeing socket: 0x%p", s));
          ssh_free(s);
        }

      events_pending = TRUE;
      EnterCriticalSection(&ssheloop.lock);
      EnterCriticalSection(&ssheloop.io_event_list_lock);
      EnterCriticalSection(&ssheloop.timeout_lock);
      if (ssheloop.sockets == NULL
          && (ssheloop.num_registered_events == 0)
          && ssh_event_loop_check_for_termination
          && IsListEmpty(&ssheloop.io_event_list)
          && IsListEmpty(&ssheloop.expired_timeouts)
          && (InterlockedCompareExchange(&ssheloop.timeout_count, 0, 0) == 0))
          {
            events_pending = FALSE;
          }
      LeaveCriticalSection(&ssheloop.timeout_lock);
      LeaveCriticalSection(&ssheloop.io_event_list_lock);
      LeaveCriticalSection(&ssheloop.lock);

      if (events_pending)
        {
          WaitForSingleObject(ssheloop.eloop_wakeup_event, wait_time_ms);
        }
      else
        {
          SSH_DEBUG(SSH_D_NICETOKNOW, ("Exit from event loop"));
          return;  /* Exit the event loop */
        }
    }
}

