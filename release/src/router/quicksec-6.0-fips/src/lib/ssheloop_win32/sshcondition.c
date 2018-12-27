/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   API to condition variables.
*/

#include "sshincludes.h"
#include "sshcondition.h"
#include "sshmutex.h"

#define SSH_DEBUG_MODULE "SshCondVar"
/* Condition variable type, the actual contents is system dependent */
struct SshConditionRec
{
  HANDLE sem;
  SshMutex mutex;
  SshUInt32 count;
  char *name;
};

/* Allocate condition variable and initialize it to unlocked
   state. Currently no flags defined. Name is the name of the
   condition variable, it is only used for debugging. This function
   will take a copy of the name. The name can also be NULL. */
SshCondition ssh_condition_create(const char *name, SshUInt32 flags)
{
  SshCondition c;
  HANDLE sem = NULL;
  SshMutex mutex = NULL;
  char *copied_name = NULL;

  c = ssh_calloc(1, sizeof(*c));
  if (c == NULL)
    goto failed;

  if (name)
    {
      copied_name = ssh_strdup(name);
      if (copied_name == NULL)
        goto failed;
    }

  mutex = ssh_mutex_create(name, 0);

  if (mutex == NULL)
    goto failed;

  /* Create semaphore without a name, because if the name conflicts with
     an exisiting semaphore, the same semaphore is returned. */
  sem = CreateSemaphore(NULL, 0, 0xffff, NULL);
  if (sem == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("CreateSemaphore failed, lasterror = %d", GetLastError()));
      goto failed;
    }

  c->mutex = mutex;
  c->sem = sem;
  c->name = copied_name;

  return c;

 failed:  /* failed on mem alloc or resource exhaustion */

  if (c)
    ssh_free(c);

  if (copied_name)
    ssh_free(copied_name);

  if (mutex)
    ssh_mutex_destroy(mutex);

  if (sem != NULL)
    CloseHandle(sem);

  return NULL;
}


SshCondition ssh_xcondition_create(const char *name, SshUInt32 flags)
{
  SshCondition c;
  HANDLE sem = NULL;
  SshMutex mutex = NULL;
  char *copied_name = NULL;

  c = ssh_xcalloc(1, sizeof(*c));
  if (name)
    {
      copied_name = ssh_xstrdup(name);
    }
  mutex = ssh_mutex_create(name, 0);

  if (mutex == NULL)
    goto failed;

  /* Create semaphore without a name, because if the name conflicts with
     an exisiting semaphore, the same semaphore is returned. */
  sem = CreateSemaphore(NULL, 0, 0xffff, NULL);
  if (sem == NULL)
    {
      SSH_DEBUG(SSH_D_ERROR,
                ("CreateSemaphore failed, lasterror = %d", GetLastError()));
      goto failed;
    }
  c->mutex = mutex;
  c->sem = sem;
  c->name = copied_name;
  return c;

 failed:
  ssh_fatal("Failed to create condition variable");
  return NULL;
}



/* Destroy condition variable. It is fatal error to call this if
 * condition variable is locked. */
void ssh_condition_destroy(SshCondition cond)
{
  ssh_mutex_destroy(cond->mutex);
  CloseHandle(cond->sem);
  ssh_free(cond->name);
  ssh_free(cond);
}

/* Signals a condition on the condition variable. This will unblock a
   thread which has blocked on the condition variable. It is possible
   that more than one blocked thread is unblocked, but at least one is
   guaranteed. */
void ssh_condition_signal(SshCondition cond)
{
  ssh_mutex_lock(cond->mutex);
  if (cond->count == 0)
    {
      ssh_mutex_unlock(cond->mutex);
      return;
    }

  cond->count--;
  ssh_mutex_unlock(cond->mutex);
  /* Release one of the waiters. */
  ReleaseSemaphore(cond->sem, 1, NULL);
}

/* Signals a condition on the condition variable. This will unblock
 * all threads which have blocked on this condition variable. */
void ssh_condition_broadcast(SshCondition cond)
{
  int x;
  ssh_mutex_lock(cond->mutex);

  x = cond->count;
  cond->count = 0;
  ssh_mutex_unlock(cond->mutex);

  /* Release all waiters. */
  while (x > 0)
    {
      ReleaseSemaphore(cond->sem, 1, NULL);
      x--;
    }
}

/* Waits on a condition variable for a signal. The `mutex' must be
   locked. Upon entry, current thread will atomically unlock `mutex'
   and block on the condition variable. When this routine returns, the
   `mutex' will be locked. */
void ssh_condition_wait(SshCondition cond, SshMutex mutex)
{

  ssh_mutex_lock(cond->mutex);
  cond->count++;
  ssh_mutex_unlock(cond->mutex);

  ssh_mutex_unlock(mutex);
  WaitForSingleObject(cond->sem, INFINITE);

  ssh_mutex_lock(mutex);

}

/* Returns the name of the condition variable. This returns NULL if
   the condition variable does not have name. The name returned will
   be valid as long as the condition variable is not destroyed. */
const char *ssh_condition_get_name(SshCondition cond)
{
  return cond->name;
}
