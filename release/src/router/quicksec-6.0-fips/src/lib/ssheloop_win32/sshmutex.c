/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   SshMutex implementation for Microsoft Windows
*/

#include "sshincludes.h"
#include "sshmutex.h"

#define SSH_DEBUG_MODULE "SshMutex"

struct SshMutexRec
{
  CRITICAL_SECTION critical;
  char *name;
  DWORD locked;
};

SshMutex ssh_mutex_create(const char *name, SshUInt32 flags)
{
  SshMutex mutex;

  mutex = ssh_xmalloc(sizeof(*mutex));
  InitializeCriticalSection(&mutex->critical);
  if (name)
    mutex->name = ssh_xstrdup(name);
  else
    mutex->name = NULL;
  mutex->locked = 0;
  return mutex;
}

void ssh_mutex_destroy(SshMutex mutex)
{
  if (mutex->locked)
    ssh_fatal("Tried to destroy locked mutex %s", mutex->name);
  DeleteCriticalSection(&mutex->critical);
  if (mutex->name)
    ssh_xfree(mutex->name);
  ssh_xfree(mutex);
}

void ssh_mutex_lock(SshMutex mutex)
{
  EnterCriticalSection(&mutex->critical);
  if (mutex->locked)
    ssh_fatal("thread tried to lock mutex %s twice", mutex->name);
  mutex->locked= 1;
}

void ssh_mutex_unlock(SshMutex mutex)
{
  if (!mutex->locked)
    ssh_fatal("Tried to unlock nonlocked mutex %s.", mutex->name);
  mutex->locked = 0;
  LeaveCriticalSection(&mutex->critical);
}

const char *ssh_mutex_get_name(SshMutex mutex)
{
  return mutex->name;
}
