/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Priority heap functionality.

   @description
   Priority heaps behave like priority queues but it is additionally
   possible to remove arbitrary items from the middle of the heap,
   and it is possible to move all items from one priority queue to
   another.  All of those operations take logarithmic time.

   EXPERIMENTAL FEATURE: Priority heaps can also be associated with
   maps (see the sshadt_assoc.h file).  This hasn't been tested but
   should work. Priority queues will never provide this feature
   for technical reasons.
*/

#ifndef SSH_ADT_PRIORITY_HEAP_INCLUDED
#define SSH_ADT_PRIORITY_HEAP_INCLUDED

#include "sshadt.h"

#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_priority_heap_type;

#define SSH_ADT_PRIORITY_HEAP (ssh_adt_priority_heap_type)

/** Type for inlined headers. */
typedef struct {
  SshUInt32 height;
  void *left, *right, *parent;
} SshADTPriorityHeapHeaderStruct;


#if 0
/* Temporarily disabled. */
/** Move all objects from the priority heap 'from' to the priority heap
    'to'.  This is accomplished in logarithmic time.  No memory is
    allocated or freed.  */
void ssh_adt_priority_heap_move(SshADTContainer to, SshADTContainer from);
#endif

#endif /* SSH_ADT_PRIORITY_HEAP_INCLUDED */
