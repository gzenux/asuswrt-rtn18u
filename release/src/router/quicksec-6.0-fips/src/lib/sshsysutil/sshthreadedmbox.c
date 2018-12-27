/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Threaded message box interface implementation. This implementation
   is platform-independent, and relies on the sshmutex.h,
   and sshthreadpool.h abstractions.
*/

#include "sshincludes.h"
#include "ssheloop.h"
#include "sshthreadedmbox.h"
#include "sshmutex.h"
#include "sshthread.h"
#ifdef DEBUG_LIGHT
#include "sshadt.h"
#include "sshadt_map.h"
#endif /* DEBUG_LIGHT */
#include "sshtimeouts.h"
#include "sshthreadpool.h"

#define SSH_DEBUG_MODULE "SshThreadedMbox"

/* We have two implementations: One using threads, and the other not,
   since the non-thread one is simpler and of course -- doesn't have
   threads. Doh. */

#ifdef HAVE_THREADS

typedef struct SshThreadedMboxMsgRec {
  union {
    SshThreadedMboxEloopCB eloop_cb;
    SshThreadedMboxThreadCB thread_cb;
  } u_cb;
  void *ctx;
  struct SshThreadedMboxMsgRec *next;
} *SshThreadedMboxMsg, SshThreadedMboxMsgStruct;

typedef struct SshThreadedMboxThreadStateRec {
  SshThreadedMbox mbox;
  SshThreadedMboxMsg msg;
} *SshThreadedMboxThreadState, SshThreadedMboxThreadStateStruct;

typedef struct SshThreadedMboxRec {
  /* This mutex is used to lock all concurrent accesses to this
     structure. */
  SshMutex mutex;

  /* Maximum number of concurrent threads that are allowed to be
     executing on the thread side. */
  SshInt32 max_threads;

  /* Current number of threads executing */
  SshUInt32 num_threads;

  /* This is set to TRUE if the mbox is being destroyed. Any callback
     returning must check this flag and then check if num_callbacks ==
     0, and perform final destruction if so. */
  Boolean destroyed;

  SshUInt32 num_callbacks;

  /* TRUE if the eloop has been sent a notification of pending
     messages already */
  Boolean eloop_notified;

  /* Queue of messages to eloop */
  SshThreadedMboxMsg eloop_queue;

  /* Pointer to the last-elem-next eloop_queue */
  SshThreadedMboxMsg *eloop_queue_last_ptr;

  /* Queue of messages to threads */
  SshThreadedMboxMsg thread_queue;

  /* Pointer to the last-elem-next thread_queue */
  SshThreadedMboxMsg *thread_queue_last_ptr;

  /* Freelist of SshThreadedMboxMsg objects */
  SshThreadedMboxMsg message_freelist;

#ifdef DEBUG_LIGHT
  /* Map of all our threads that we have created */
  SshADTContainer thread_map;
#endif /* DEBUG_LIGHT */

  /* If max_threads is 0, then there is no threads, and we must handle
     the is_thread handling differently through data in the mbox
     structure instead. This is used only is max_threads == 0. */
  Boolean single_is_thread;

  /* Thread pool */
  SshThreadPool thread_pool;
} SshThreadedMboxStruct;

#define SSH_MBOX_MESSAGE_FREELIST_INITIAL_SIZE 10

Boolean mbox_message_freelist_alloc(SshThreadedMbox mbox)
{
  void *item;
  void *list = NULL;
  int i;

  for (i = 0; i < SSH_MBOX_MESSAGE_FREELIST_INITIAL_SIZE; i++)
    {
      item = ssh_calloc(1, sizeof(SshThreadedMboxMsgStruct));

      if (item == NULL)
        goto fail;
      *((void **)item) = list;
      list = item;
    }
  mbox->message_freelist = list;
  return TRUE;

 fail:
  while (list)
    {
      item = *((void **)list);
      ssh_free(list);
      list = item;
    }
  return FALSE;
}

void mbox_message_freelist_free(SshThreadedMbox mbox)
{
  void *list = mbox->message_freelist;
  void *next;

  SSH_DEBUG(SSH_D_HIGHOK, ("Freeing Mbox message structure freelist"));

  while (list)
    {
      next = *((void **)list);
      ssh_free(list);
      list = next;
    }
}

#define MESSAGE_FREELIST_GET(item, list)                \
do                                                      \
  {                                                     \
    (item) = (void *)(list);                            \
    if (list)                                           \
      (list) = *((void **)(item));                      \
  }                                                     \
while (0)

#define MESSAGE_FREELIST_PUT(item, list)                \
do                                                      \
  {                                                     \
    *((void **)(item)) = (list);                        \
    (list) = (void *)(item);                            \
  }                                                     \
while (0)



static void ssh_threaded_mbox_destroy_final(SshThreadedMbox mbox);

/* Put a message to be sent to the eloop side */
Boolean ssh_threaded_mbox_send_to_eloop(SshThreadedMbox mbox,
                                        SshThreadedMboxEloopCB eloop_cb,
                                        void *ctx)
{
  SSH_DEBUG(12, ("to eloop: eloop_cb %p, ctx %p", eloop_cb, ctx));

  ssh_mutex_lock(mbox->mutex);

  if (mbox->destroyed)
    {
      ssh_mutex_unlock(mbox->mutex);
      return FALSE;
    }

  /* If there is no threads used at *all*, then we *are* currently
     running in eloop and cannot postpone that actual call (or we'll
     create deadlock situations) */
  if (mbox->max_threads == 0)
    {
      Boolean was_thread = mbox->single_is_thread;

      mbox->num_callbacks++;
      mbox->single_is_thread = FALSE;
      ssh_mutex_unlock(mbox->mutex);
      (*eloop_cb)(ctx);
      ssh_mutex_lock(mbox->mutex);
      mbox->num_callbacks--;
      mbox->single_is_thread = was_thread;

      ssh_mutex_unlock(mbox->mutex);
      return TRUE;
    }
  ssh_mutex_unlock(mbox->mutex);

  if (!ssh_register_threaded_timeout(NULL, 0, 0, eloop_cb, ctx))
    return FALSE;
  return TRUE;
}

/* Thread runner. This will start with the given message and emit
   it. After that, it will check the thread queue and process a
   message from there if any exist (ad infinitum). Finally it will
   check the destroyed flag and num_callbacks value and proceed with
   final destruction if necessary. */

static void *ssh_threaded_mbox_thread_start(void *ctx)
{
  SshThreadedMboxThreadState state = (SshThreadedMboxThreadState)ctx;
  SshThreadedMboxMsg msg = state->msg;
  SshThreadedMbox mbox = state->mbox;
  SshThread thread;

  SSH_DEBUG(13, ("thread starting with msg %p, ctx %p", msg, msg->ctx));

  thread = ssh_thread_current();

#ifdef DEBUG_LIGHT
  /* put us into the thread map, so we can later tell we're a true thread */
  ssh_mutex_lock(mbox->mutex);
  ssh_adt_put(mbox->thread_map, &thread);
  SSH_ASSERT(ssh_adt_get_handle_to_equal(mbox->thread_map, &thread)
             != SSH_ADT_INVALID);
  ssh_mutex_unlock(mbox->mutex);
#endif /* DEBUG_LIGHT */

  /* not needed anymore, remove the dangling pointer */
  state->msg = NULL;

 again:

  (*msg->u_cb.thread_cb)(msg->ctx);

  ssh_mutex_lock(mbox->mutex);
  MESSAGE_FREELIST_PUT(msg, mbox->message_freelist);

  if (mbox->thread_queue != NULL)
    {
      msg = mbox->thread_queue;
      mbox->thread_queue = msg->next;
      msg->next = NULL;

      if (&msg->next == mbox->thread_queue_last_ptr)
        mbox->thread_queue_last_ptr = &mbox->thread_queue;

      ssh_mutex_unlock(mbox->mutex);

      SSH_DEBUG(13, ("thread has more work to do with msg %p, ctx %p",
                     msg, msg->ctx));

      goto again;
    }

  /* Done. Fall out, destruct self state. */
  mbox->num_threads--;
  mbox->num_callbacks--;

#ifdef DEBUG_LIGHT
  ssh_adt_delete(mbox->thread_map,
                 ssh_adt_get_handle_to_equal(mbox->thread_map, &thread));
#endif /* DEBUG_LIGHT */

  SSH_DEBUG(13, ("thread done, %d threads left",
                 mbox->num_threads));

  ssh_mutex_unlock(mbox->mutex);
  ssh_free(state);

  return NULL;
}

/* Put a message to be sent to the thread side */
Boolean ssh_threaded_mbox_send_to_thread(SshThreadedMbox mbox,
                                         SshThreadedMboxThreadCB thread_cb,
                                         void *ctx)
{
  SshThreadedMboxMsg msg;
  SshThreadedMboxThreadState state;

  SSH_DEBUG(12, ("to thread: thread_cb %p, ctx %p",
                 thread_cb, ctx));

  ssh_mutex_lock(mbox->mutex);

  if (mbox->destroyed)
    {
      ssh_mutex_unlock(mbox->mutex);
      return FALSE;
    }

  /* If max_threads == 0, we perform the call directly from here. */
  if (mbox->max_threads == 0)
    {
      Boolean was_thread = mbox->single_is_thread;

      mbox->num_callbacks++;
      mbox->single_is_thread = TRUE;
      ssh_mutex_unlock(mbox->mutex);

      SSH_DEBUG(12, ("single-threaded fall-through call"));
      (*thread_cb)(ctx);

      ssh_mutex_lock(mbox->mutex);
      mbox->num_callbacks--;
      mbox->single_is_thread = was_thread;

      ssh_mutex_unlock(mbox->mutex);

      return TRUE;
    }

  /* We need message struct, initialize */
  MESSAGE_FREELIST_GET(msg, mbox->message_freelist);
  if (msg == NULL)
    {
      msg = ssh_malloc(sizeof(*msg));
      if (msg == NULL)
        {
          ssh_mutex_unlock(mbox->mutex);
          return FALSE;
        }
    }
  msg->u_cb.thread_cb = thread_cb;
  msg->ctx = ctx;
  msg->next = NULL;

  /* If max_threads == -1 or num_threads < max_threads, spawn a new thread */
  if (mbox->max_threads == -1 || mbox->num_threads < mbox->max_threads)
    {
      mbox->num_threads++;
      mbox->num_callbacks++;

      SSH_DEBUG(12, ("creating new thread, %d threads total",
                     mbox->num_threads));

      ssh_mutex_unlock(mbox->mutex);

      state = ssh_malloc(sizeof(*state));
      if (!state)
        {
          ssh_mutex_lock(mbox->mutex);

          MESSAGE_FREELIST_PUT(msg, mbox->message_freelist);
          mbox->num_threads--;
          mbox->num_callbacks--;
          ssh_mutex_unlock(mbox->mutex);

          return FALSE;
        }

      state->mbox = mbox;
      state->msg = msg;

      /* Umm, actually, this should never happen.. */
      if (!ssh_thread_pool_start(mbox->thread_pool, TRUE,
                                 ssh_threaded_mbox_thread_start, state))
        return FALSE;

      return TRUE;
    }

  /* Otherwise, queue the message. A thread done its work will always
     check the thread side queue, and process messages in there before
     exiting. */

  SSH_DEBUG(12, ("queueing msg %p, %d thread limit reached",
                 msg, mbox->max_threads));

  *mbox->thread_queue_last_ptr = msg;
  mbox->thread_queue_last_ptr = &msg->next;
  ssh_mutex_unlock(mbox->mutex);

  return TRUE;
}

#ifdef DEBUG_LIGHT
/* Returns TRUE if the current executing thread is running in the
   "thread" context side of the mbox messages */
Boolean ssh_threaded_mbox_is_thread(SshThreadedMbox mbox)
{
  Boolean is_thread;
  SshThread thread;

  if (mbox->max_threads == 0)
    return mbox->single_is_thread;

  thread = ssh_thread_current();

  ssh_mutex_lock(mbox->mutex);
  is_thread = ssh_adt_get_handle_to_equal(mbox->thread_map, &thread)
    != SSH_ADT_INVALID;
  ssh_mutex_unlock(mbox->mutex);

  return is_thread;
}

static unsigned long void_hash(const void *ptr, void *ctx)
{
  return (unsigned long) *(void**)ptr;
}

static int void_cmp(const void *ptr1, const void *ptr2, void *ctx)
{
  if (*(void **) ptr1 == *(void **) ptr2)
    return 0;

  if (*(void **) ptr1 < *(void **) ptr2)
    return -1;

  return 1;
}
#endif /* DEBUG_LIGHT */

/* Create a new mbox */
SshThreadedMbox ssh_threaded_mbox_create(SshInt32 max_threads)
{
  SshThreadedMbox mbox;

  mbox = ssh_calloc(1, sizeof(*mbox));

  if (!mbox)
    return NULL;

  if (!mbox_message_freelist_alloc(mbox))
    {
      ssh_free(mbox);
      return NULL;
    }

  mbox->max_threads = max_threads;
  mbox->eloop_queue_last_ptr = &mbox->eloop_queue;
  mbox->thread_queue_last_ptr = &mbox->thread_queue;

  /* Initialize mutex and condvars */
  mbox->mutex = ssh_mutex_create("thread_mbox", 0);

  if (!mbox->mutex)
    {
      ssh_threaded_mbox_destroy_final(mbox);
      return NULL;
    }

#ifdef DEBUG_LIGHT
  mbox->thread_map = ssh_adt_create_generic(SSH_ADT_MAP,
                                            SSH_ADT_HASH, void_hash,
                                            SSH_ADT_COMPARE, void_cmp,
                                            SSH_ADT_SIZE, sizeof(SshThread),
                                            SSH_ADT_ARGS_END);

  if (!mbox->thread_map)
    {
      ssh_threaded_mbox_destroy_final(mbox);
      return NULL;
    }
#endif /* DEBUG_LIGHT */

  if (max_threads > 0)
    {
      SshThreadPoolParamsStruct params;
      params.min_threads = 0;
      params.max_threads = max_threads > 0 ? max_threads : 0;
      mbox->thread_pool = ssh_thread_pool_create(&params);

      if (!mbox->thread_pool)
        {
          ssh_threaded_mbox_destroy_final(mbox);
          return NULL;
        }
    }
  else
    mbox->thread_pool = NULL;

  mbox->destroyed = FALSE;
  return mbox;
}

/* This must be called from eloop context */
void ssh_threaded_mbox_destroy(SshThreadedMbox mbox)
{
  SshThreadedMboxMsg eloop_queue, thread_queue, next;

  SSH_DEBUG(12, ("destroying mbox %p", mbox));

  ssh_mutex_lock(mbox->mutex);

  SSH_ASSERT(!mbox->destroyed);
  mbox->destroyed = TRUE;

  /* grab heads of the message queues, and set them to NULL */
  eloop_queue = mbox->eloop_queue;
  thread_queue = mbox->thread_queue;

  mbox->eloop_queue = mbox->thread_queue = NULL;

  mbox->eloop_queue_last_ptr = &mbox->eloop_queue;
  mbox->thread_queue_last_ptr = &mbox->thread_queue;

  /* Exit lock, and emit all messages */
  mbox->num_callbacks++;
  ssh_mutex_unlock(mbox->mutex);

  for (; eloop_queue != NULL; eloop_queue = next)
    {
      next = eloop_queue->next;
      (*eloop_queue->u_cb.eloop_cb)(eloop_queue->ctx);

      ssh_mutex_lock(mbox->mutex);
      MESSAGE_FREELIST_PUT(eloop_queue, mbox->message_freelist);
      ssh_mutex_unlock(mbox->mutex);
   }

  for (; thread_queue != NULL; thread_queue = next)
    {
      next = thread_queue->next;
      (*thread_queue->u_cb.thread_cb)(thread_queue->ctx);

      ssh_mutex_lock(mbox->mutex);
      MESSAGE_FREELIST_PUT(thread_queue, mbox->message_freelist);
      ssh_mutex_unlock(mbox->mutex);
    }

  ssh_mutex_lock(mbox->mutex);
  mbox->num_callbacks--;

  ssh_mutex_unlock(mbox->mutex);

  if (mbox->thread_pool != NULL)
    ssh_thread_pool_destroy(mbox->thread_pool);

  /* Do the final destruction */
  ssh_threaded_mbox_destroy_final(mbox);
}

/* This routine must be called with the lock held */
static void ssh_threaded_mbox_destroy_final(SshThreadedMbox mbox)
{
  SSH_ASSERT(mbox->num_callbacks == 0);
  SSH_ASSERT(mbox->num_threads == 0);

  /* From this point onwards, there is no other threads concurrently
     accessing the `mbox' state. (This routine is called from the
     eloop single-threaded context.) */

  SSH_ASSERT(mbox->thread_queue == NULL && mbox->eloop_queue == NULL);

#ifdef DEBUG_LIGHT
  if (mbox->thread_map != NULL)
    ssh_adt_destroy(mbox->thread_map);
#endif /* DEBUG_LIGHT */

  if (mbox->mutex)
    ssh_mutex_destroy(mbox->mutex);

  mbox_message_freelist_free(mbox);

  ssh_free(mbox);
}

#else /* !HAVE_THREADS */

typedef struct SshThreadedMboxRec {
  /* TRUE if we're being destructed. In that case, final destruction
     will happen when num_callbacks reaches 0 */
  Boolean destroyed;

  /* Calculate levels of callbacks we're handling */
  SshUInt32 num_callbacks;

  /* Whether we're in the thread side (TRUE) or eloop side (FALSE) */
  Boolean in_thread;
} SshThreadedMboxStruct;

SshThreadedMbox ssh_threaded_mbox_create(SshInt32 max_threads)
{
  SshThreadedMbox mbox;
  mbox = ssh_calloc(1, sizeof(*mbox));
  return mbox;
}

void ssh_threaded_mbox_destroy(SshThreadedMbox mbox)
{
  SSH_ASSERT(!mbox->destroyed);
  mbox->destroyed = TRUE;
  if (mbox->num_callbacks == 0)
    ssh_free(mbox);
}

Boolean ssh_threaded_mbox_send_to_eloop(SshThreadedMbox mbox,
                                        SshThreadedMboxEloopCB eloop_cb,
                                        void *ctx)
{
  Boolean was_thread;

  if (mbox->destroyed)
    return FALSE;

  was_thread = mbox->in_thread;
  mbox->in_thread = FALSE;

  mbox->num_callbacks++;
  (*eloop_cb)(ctx);
  mbox->num_callbacks--;
  mbox->in_thread = was_thread;

  if (mbox->destroyed && mbox->num_callbacks == 0)
    ssh_free(mbox);

  return TRUE;
}

Boolean ssh_threaded_mbox_send_to_thread(SshThreadedMbox mbox,
                                        SshThreadedMboxThreadCB thread_cb,
                                        void *ctx)
{
  Boolean was_thread;

  if (mbox->destroyed)
    return FALSE;

  was_thread = mbox->in_thread;
  mbox->in_thread = TRUE;

  mbox->num_callbacks++;
  (*thread_cb)(ctx);
  mbox->num_callbacks--;
  mbox->in_thread = was_thread;

  if (mbox->destroyed && mbox->num_callbacks == 0)
    ssh_free(mbox);

  return TRUE;
}

#ifdef DEBUG_LIGHT
Boolean ssh_threaded_mbox_is_thread(SshThreadedMbox mbox)
{
  return mbox->in_thread;
}
#endif /* DEBUG_LIGHT */

#endif /* HAVE_THREADS */
