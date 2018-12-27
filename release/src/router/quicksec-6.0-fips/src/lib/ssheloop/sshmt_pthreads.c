/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementations of sshmutex.h, sshcondition.h, sshbsem.h and
   sshthread.h APIs based on the pthreads threading API.
*/

/* Tru64 pthreads does not work if XOPEN_SOURCE is defined. */

#ifdef _XOPEN_SOURCE_EXTENDED
#undef _XOPEN_SOURCE_EXTENDED
#define SAVED_XOPEN_SOURCE_EXTENDED
#endif /* _XOPEN_SOURCE_EXTENDED */

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#define SAVED_XOPEN_SOURCE
#endif /* _XOPEN_SOURCE */

#include <pthread.h>
/* We must include strings.h here because otherwise we get conflict later */
#include <strings.h>

#ifdef SAVED_XOPEN_SOURCE_EXTENDED
#undef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED 1
#undef SAVED_XOPEN_SOURCE_EXTENDED
#endif /* SAVED_XOPEN_SOURCE_EXTENDED */

#ifdef SAVED_XOPEN_SOURCE
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 1
#undef SAVED_XOPEN_SOURCE
#endif /* SAVED_XOPEN_SOURCE */

#include "sshincludes.h"
#include "sshthread.h"
#include "sshmutex.h"
#include "sshcondition.h"
#include "sshbsem.h"

/* NOTE: Do not use debug prints here, because the debugging system might be
   using mutexes to protect itself. */

#undef SSH_DEBUG_MODULE

/* Mutex type, the actual contents is system dependent */
struct SshMutexRec {
  char *name;
  pthread_mutex_t mutex;
};

struct SshConditionRec {
  char *name;
  pthread_cond_t condition;
};

struct SshBSemRec {
  char *name;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  int value;
  int init;
#define SSH_BSEM_INIT_MUTEX 1
#define SSH_BSEM_INIT_COND 1
};

/*****************************  Mutexes   **********************************/

/* Allocate mutex and initialize it to unlocked state. Currently no flags
   defined. Name is the name of the mutex, it is only used for debugging. This
   function will take a copy of the name. The name can also be NULL. */
SshMutex ssh_mutex_create(const char *name, SshUInt32 flags)
{
  SshMutex mutex;
  int err;

  if ((mutex = ssh_calloc(1, sizeof(*mutex))) == NULL)
    return NULL;
  if (name)
    {
      if ((mutex->name = ssh_strdup(name)) == NULL)
        {
          ssh_free(mutex);
          return NULL;
        }
    }
  err = pthread_mutex_init(&(mutex->mutex), NULL);
  if (err != 0)
    {
      if (mutex->name)
        ssh_free(mutex->name);
      ssh_free(mutex);
      return NULL;
    }

  return mutex;
}

/* Destroy mutex. It is fatal error to call this if mutex is locked. */
void ssh_mutex_destroy(SshMutex mutex)
{
  int err;
  err = pthread_mutex_destroy(&(mutex->mutex));
  if (err != 0)
    ssh_fatal("Mutex destroy failed: %s", strerror(err));
  ssh_free(mutex->name);
  ssh_free(mutex);
}

/* Locks the mutex. If the mutex is already locked then this will block until
   the mutex is unlocked. */
void ssh_mutex_lock(SshMutex mutex)
{
  int err;

  err = pthread_mutex_lock(&(mutex->mutex));
  if (err != 0)
    ssh_fatal("Mutex lock failed: %s", strerror(err));
}

/* Unlocks the mutex. It is fatal error to call this function if the mutex is
   already unlocked. Also only the original thread that took the lock is
   allowed to unlock it. */
void ssh_mutex_unlock(SshMutex mutex)
{
  int err;

  err = pthread_mutex_unlock(&(mutex->mutex));
  if (err != 0)
    ssh_fatal("Mutex lock failed: %s", strerror(err));
}

/* Returns the name of the mutex. This returns NULL if the mutex does not have
   name. */
const char *ssh_mutex_get_name(SshMutex mutex)
{
  return mutex->name;
}

/*************************** Condition variables ***************************/

/* Create a condition variable */
SshCondition ssh_condition_create (const char *name, SshUInt32 flags)
{
  SshCondition cond;

  if ((cond = ssh_calloc(1, sizeof(*cond))) == NULL)
    return NULL;
  if (name)
    {
      if ((cond->name = ssh_strdup(name)) == NULL)
        {
          ssh_free(cond);
          return NULL;
        }
    }
  pthread_cond_init(&cond->condition, NULL);

  return cond;
}

/* Create a condition variable */
SshCondition ssh_xcondition_create (const char *name, SshUInt32 flags)
{
  SshCondition cond;

  cond = ssh_xcalloc(1, sizeof(*cond));
  if (name)
    cond->name = ssh_xstrdup(name);

  pthread_cond_init(&cond->condition, NULL);
  return cond;
}

/* Destroy a condition variable */
void ssh_condition_destroy(SshCondition cond)
{
  pthread_cond_destroy(&cond->condition);
  ssh_free(cond->name);
  ssh_free(cond);
}

/* Signal a thread blocked on a condition variable */
void ssh_condition_signal(SshCondition cond)
{
  pthread_cond_signal(&cond->condition);
}

/* Signal all threads blocked on a condition variable */
void ssh_condition_broadcast(SshCondition cond)
{
  pthread_cond_broadcast(&cond->condition);
}

/* Wait on a condition variable */
void ssh_condition_wait(SshCondition cond, SshMutex mutex)
{
  pthread_cond_wait(&cond->condition, &mutex->mutex);
}

/* Returns the name assigned to a condition variable */
const char *ssh_condition_get_name(SshCondition cond)
{
  return cond->name;
}

/**************************** Binary semaphores ****************************/

SshBSem ssh_bsem_create(const char *name, SshUInt32 flags)
{
  SshBSem bsem = NULL;
  int error;

  if ((bsem = ssh_calloc(1, sizeof *bsem)) == NULL)
    goto fail;

  if (name != NULL && (bsem->name = ssh_strdup(name)) == NULL)
    goto fail;

  if ((error = pthread_mutex_init(&bsem->mutex, NULL)) != 0)
    goto fail;
  bsem->init |= SSH_BSEM_INIT_MUTEX;

  if ((error = pthread_cond_init(&bsem->cond, NULL)) != 0)
    goto fail;
  bsem->init |= SSH_BSEM_INIT_COND;

  return bsem;

 fail:
  ssh_bsem_destroy(bsem);
  return NULL;
}

void ssh_bsem_destroy(SshBSem bsem)
{
  if (bsem == NULL)
    return;

  if ((bsem->init & SSH_BSEM_INIT_COND) != 0)
    pthread_cond_destroy(&bsem->cond);

  if ((bsem->init & SSH_BSEM_INIT_MUTEX) != 0)
    pthread_mutex_destroy(&bsem->mutex);

  if (bsem->name)
    ssh_free(bsem->name);

  ssh_free(bsem);
}

void ssh_bsem_signal(SshBSem bsem)
{
  pthread_mutex_lock(&bsem->mutex);

  if (bsem->value == 0)
    {
      bsem->value = 1;
      pthread_cond_signal(&bsem->cond);
    }

  pthread_mutex_unlock(&bsem->mutex);
}

void ssh_bsem_wait(SshBSem bsem)
{
  pthread_mutex_lock(&bsem->mutex);

  if (bsem->value == 0)
    pthread_cond_wait(&bsem->cond, &bsem->mutex);

  bsem->value = 0;

  pthread_mutex_unlock(&bsem->mutex);
}

const char *ssh_bsem_get_name(SshBSem bsem)
{
  return bsem->name;
}

/*******************************  Threads **********************************/

/* pthread_t is either void pointer or "unsigned int" -- a pointer
   (SshThread) should be always large enough */
#define SSH_THREAD_TO_PTHREAD(X)        ((pthread_t) (X))
#define SSH_PTHREAD_TO_THREAD(X)        ((SshThread) (X))

SshThread ssh_thread_create(SshThreadFuncCB func_cb, void *context)
{
  pthread_t tid;
  int err;

  err = pthread_create(&tid, NULL, func_cb, context);

  if (err != 0)
    return NULL;

  return SSH_PTHREAD_TO_THREAD(tid);
}

void *ssh_thread_join(SshThread thread)
{
  void *ret;
  int err;

  err = pthread_join(SSH_THREAD_TO_PTHREAD(thread), &ret);

  if (err != 0)
    ssh_fatal("invalid thread given to ssh_thread_join");

  return ret;
}

void ssh_thread_detach(SshThread thread)
{
  pthread_detach(SSH_THREAD_TO_PTHREAD(thread));
}

void ssh_thread_cancel(SshThread thread)
{
  pthread_cancel(SSH_THREAD_TO_PTHREAD(thread));
}

SshThread ssh_thread_current(void)
{
  return SSH_PTHREAD_TO_THREAD(pthread_self());
}
