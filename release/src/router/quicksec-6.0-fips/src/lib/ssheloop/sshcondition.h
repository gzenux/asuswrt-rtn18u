/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   API to condition variables.
*/

#include "sshmutex.h"

#ifndef SSH_CONDITION_H
#define SSH_CONDITION_H

/* Condition variable type, the actual contents is system dependent */
typedef struct SshConditionRec *SshCondition;

/* Allocate condition variable and initialize it to unlocked
   state. Currently no flags defined. Name is the name of the
   condition variable, it is only used for debugging. This function
   will take a copy of the name. The name can also be NULL.
   This function returns NULL on failure. */
SshCondition ssh_condition_create(const char *name, SshUInt32 flags);

/** Allocate a condition variable. This behaves exactly as
    ssh_condition_create except that it is a fatal error (causing program
    termination) if insufficient memory is available for creating the
    condition. This routine should only be used by test code.*/
SshCondition ssh_xcondition_create(const char *name, SshUInt32 flags);

/* Destroy condition variable. It is fatal error to call this if
 * condition variable is locked. */
void ssh_condition_destroy(SshCondition cond);

/* Signals a condition on the condition variable. This will unblock a
   thread which has blocked on the condition variable. It is possible
   that more than one blocked thread is unblocked, but at least one is
   guaranteed. */
void ssh_condition_signal(SshCondition cond);

/* Signals a condition on the condition variable. This will unblock
 * all threads which have blocked on this condition variable. */
void ssh_condition_broadcast(SshCondition cond);

/* Waits on a condition variable for a signal. The `mutex' must be
   locked. Upon entry, current thread will atomically unlock `mutex'
   and block on the condition variable. When this routine returns, the
   `mutex' will be locked. */
void ssh_condition_wait(SshCondition cond, SshMutex mutex);

/* Returns the name of the condition variable. This returns NULL if
   the condition variable does not have name. The name returned will
   be valid as long as the condition variable is not destroyed. */
const char *ssh_condition_get_name(SshCondition cond);

#endif /* SSH_CONDITION_H */
