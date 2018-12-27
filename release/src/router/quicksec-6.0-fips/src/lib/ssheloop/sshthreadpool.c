/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Thread pool implementation. The implementation is
   platform-independent, and relies on the abstracted mutex, condition
   variable and thread interfaces.
*/

#include "sshincludes.h"
#include "sshmutex.h"
#include "sshcondition.h"
#include "sshthreadpool.h"

#define SSH_DEBUG_MODULE "SshThreadPool"

#ifdef HAVE_THREADS

typedef struct SshThreadPoolJobRec {
  SshThreadFuncCB func;
  void *context;

  struct SshThreadPoolJobRec *next;
} *SshThreadPoolJob, SshThreadPoolJobStruct;

typedef struct SshThreadPoolRec {
  /* Mutex to protect concurrent access to volatile structure parts */
  SshMutex mutex;

  /* Pool parameters */
  SshThreadPoolParamsStruct params;

  /* Set to true if the pool is being destructed */
  Boolean destroyed;

  /* Total number of threads */
  SshUInt32 num_threads;

  /* Number of threads not executing a job. Notice that this can get
     negative.. */
  SshInt32 avail_threads;

  /* Queue of jobs waiting to be executed. */
  SshThreadPoolJob jobs;

  /* Last pointer of the queue */
  SshThreadPoolJob *jobs_last_ptr;

  /* Condition variable which is signaled every time a new job is
     added to the jobs list */
  SshCondition jobs_cond;

  /* Condition which is signaled by all threads that are terminating
     (eg. after they have decreased num_jobs) */
  SshCondition destroy_cond;
} SshThreadPoolStruct;

static void *ssh_thread_pool_internal_thread_start(void *ctx)
{
  SshThreadPool pool = (SshThreadPool)ctx;
  SshThreadPoolJob job;

  ssh_mutex_lock(pool->mutex);

  while (1)
    {
      while (!pool->destroyed && pool->jobs == NULL)
        ssh_condition_wait(pool->jobs_cond, pool->mutex);

      if ((job = pool->jobs) != NULL)
        {
          pool->jobs = job->next;

          if (pool->jobs == NULL)
            pool->jobs_last_ptr = &pool->jobs;

          /* Notice: the entity that queued this job has already
             decremented avail_threads, so we only increment it after
             we're done. */

          ssh_mutex_unlock(pool->mutex);

          (*job->func)(job->context);
          ssh_xfree(job);

          ssh_mutex_lock(pool->mutex);

          pool->avail_threads++;

          /* Notice: we keep going around until all jobs are
             exhausted, even when the pool is being destructed */

          continue;
        }

      if (pool->destroyed)
        break;
    }

  SSH_ASSERT(pool->destroyed);

  pool->num_threads--;
  pool->avail_threads--;

  ssh_condition_broadcast(pool->destroy_cond);
  ssh_mutex_unlock(pool->mutex);

  /* return value ignored */
  return NULL;
}

/* The caller of this routine must update num_threads etc. This will
   just start a new thread from the correct place with correct
   parameters. */
static Boolean ssh_thread_pool_internal_new_thread(SshThreadPool pool)
{
  SshThread thread;

  /* Create a new thread to start from the thread pool */
  thread = ssh_thread_create(ssh_thread_pool_internal_thread_start, pool);
  if (thread == NULL)
    return FALSE;
  /* We communicate with the threads through pool, and don't need
     return values */
  ssh_thread_detach(thread);
  return TRUE;
}

SshThreadPool ssh_thread_pool_create(SshThreadPoolParams params)
{
  SshThreadPool pool;
  int i;

  pool = ssh_calloc(1, sizeof(*pool));
  if (pool == NULL)
    return NULL;

  if (params != NULL)
    pool->params = *params;

  pool->mutex = ssh_mutex_create("thread_pool", 0);
  pool->jobs_cond = ssh_condition_create("thread_pool", 0);
  pool->destroy_cond = ssh_condition_create("thread_pool", 0);

  if (!pool->mutex || !pool->jobs_cond || !pool->destroy_cond)
    goto error;

  pool->jobs_last_ptr = &pool->jobs;

  /* Start the minimum number of threads */
  if (pool->params.min_threads > 0)
    {
      pool->avail_threads = pool->num_threads = pool->params.min_threads;

      for (i = 0; i < pool->params.min_threads; i++)
        if (!ssh_thread_pool_internal_new_thread(pool))
          goto error;
    }

  return pool;

 error:
  if (pool->mutex)
    ssh_mutex_destroy(pool->mutex);
  if (pool->jobs_cond)
    ssh_condition_destroy(pool->jobs_cond);
  if (pool->destroy_cond)
    ssh_condition_destroy(pool->destroy_cond);
  ssh_free(pool);
  return NULL;
}

Boolean ssh_thread_pool_start(SshThreadPool pool, Boolean queue,
                              SshThreadFuncCB func, void *context)
{
  SshThreadPoolJob job;

  ssh_mutex_lock(pool->mutex);

  if (pool->destroyed)
    {
      ssh_mutex_unlock(pool->mutex);
      return FALSE;
    }

  /* Check out the early-chicken-out case of not wanting to
     queue. Eg. if no queueing is allowed, AND there are immediately
     no available threads, AND a maximum limit has been set, AND there
     is already maximum number of threads, then fail. */

  if (!queue && pool->avail_threads <= 0 && pool->params.max_threads > 0 &&
      pool->num_threads == pool->params.max_threads)
    {
      ssh_mutex_unlock(pool->mutex);
      return FALSE;
    }

  if ((job = ssh_malloc(sizeof(*job))) == NULL)
    {
      ssh_mutex_unlock(pool->mutex);
      return FALSE;
    }

  job->func = func;
  job->context = context;
  job->next = NULL;

  *pool->jobs_last_ptr = job;
  pool->jobs_last_ptr = &job->next;

  /* Can we start a new thread? */
  if (pool->avail_threads <= 0 &&
      (pool->params.max_threads == 0 ||
       pool->num_threads < pool->params.max_threads))
    {
      /* number of available threads won't increase, as the new thread
         has been "reserved" for us */

      if (!ssh_thread_pool_internal_new_thread(pool))
        {
          ssh_mutex_unlock(pool->mutex);
          pool->avail_threads--;
          return TRUE;
        }
      pool->num_threads++;
    }
  else
    /* just reserve a thread for us */
    pool->avail_threads--;

  /* this can lead to spurious wakeup on some cases, but only one per
     pool start */
  ssh_condition_signal(pool->jobs_cond);

  ssh_mutex_unlock(pool->mutex);

  return TRUE;
}

void ssh_thread_pool_destroy(SshThreadPool pool)
{
  ssh_mutex_lock(pool->mutex);

  SSH_ASSERT(!pool->destroyed);
  pool->destroyed = TRUE;

  /* Broadcast to all job threads, so they'll wake up and see the
     destroyed flag. Then wait until num_threads reaches 0. */

  ssh_condition_broadcast(pool->jobs_cond);

  while (pool->num_threads > 0)
    ssh_condition_wait(pool->destroy_cond, pool->mutex);

  /* no more concurrent access on the pool structure */
  ssh_mutex_unlock(pool->mutex);

  SSH_ASSERT(pool->jobs == NULL && pool->avail_threads == 0);

  ssh_mutex_destroy(pool->mutex);
  ssh_condition_destroy(pool->jobs_cond);
  ssh_condition_destroy(pool->destroy_cond);
  ssh_free(pool);
}
#endif /* HAVE_THREADS */
