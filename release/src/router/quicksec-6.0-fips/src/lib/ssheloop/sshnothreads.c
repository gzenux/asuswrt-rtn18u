/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementation of sshmutex.h and sshcondition.h in the case where no
   threads are available.
*/

#include "sshincludes.h"
#include "sshmutex.h"
#include "sshcondition.h"

#ifndef HAVE_THREADS

#define SSH_DEBUG_MODULE "SshThreadStubs"

typedef struct SshMutexRec {
  Boolean taken;
  char *name;
} SshMutexStruct;

typedef struct SshConditionRec {
  char *name;
} SshConditionStruct;

SshMutex ssh_mutex_create(const char *name, SshUInt32 flags)
{
  SshMutex mutex;

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
  return mutex;
}

void ssh_mutex_destroy(SshMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
  ssh_free(mutex->name);
  ssh_free(mutex);
}

void ssh_mutex_lock(SshMutex mutex)
{
  SSH_ASSERT(!mutex->taken);
  mutex->taken = TRUE;
}

void ssh_mutex_unlock(SshMutex mutex)
{
  SSH_ASSERT(mutex->taken);
  mutex->taken = FALSE;
}

const char *ssh_mutex_get_name(SshMutex mutex)
{
  return mutex->name;
}

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
  return cond;
}

SshCondition ssh_xcondition_create (const char *name, SshUInt32 flags)
{
  SshCondition cond;

  cond = ssh_xcalloc(1, sizeof(*cond));
  if (name)
    cond->name = ssh_xstrdup(name);
  return cond;
}

void ssh_condition_destroy(SshCondition cond)
{
  ssh_free(cond->name);
  ssh_free(cond);
}

void ssh_condition_signal(SshCondition cond)
{
}

void ssh_condition_broadcast(SshCondition cond)
{
}

void ssh_condition_wait(SshCondition cond, SshMutex mutex)
{
  SSH_ASSERT(mutex->taken);
}

const char *ssh_condition_get_name(SshCondition cond)
{
  return cond->name;
}

#endif /* !HAVE_THREADS */
