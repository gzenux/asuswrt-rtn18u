/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshmutex.h
*/

#ifndef SSHMUTEX_H
#define SSHMUTEX_H

/* Mutex type, the actual contents is system dependent */
typedef struct SshMutexRec *SshMutex;

/* Allocate mutex and initialize it to unlocked state. Currently no flags
   defined. Name is the name of the mutex, it is only used for debugging. This
   function will take a copy of the name. The name can also be NULL.
   This function returns NULL on failure. */
SshMutex ssh_mutex_create(const char *name, SshUInt32 flags);

/* Destroy mutex. It is fatal error to call this if mutex is locked. */
void ssh_mutex_destroy(SshMutex mutex);

/* Locks the mutex. If the mutex is already locked then this will block until
   the mutex is unlocked. */
void ssh_mutex_lock(SshMutex mutex);

/* Unlocks the mutex. It is fatal error to call this function if the mutex is
   already unlocked. Also only the original thread that took the lock is
   allowed to unlock it. */
void ssh_mutex_unlock(SshMutex mutex);

/* Returns the name of the mutex. This returns NULL if the mutex does not have
   name. The name returned will be valid as long as the mutex is not
   destroyed. */
const char *ssh_mutex_get_name(SshMutex mutex);

#endif /* SSHMUTEX_H */
