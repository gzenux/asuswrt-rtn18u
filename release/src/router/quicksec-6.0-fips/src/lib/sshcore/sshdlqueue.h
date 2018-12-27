/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshdlqueue.h
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshdllist.h"

#ifndef SSH_DL_QUEUE_INCLUDED
#define SSH_DL_QUEUE_INCLUDED 1

#undef SSH_ADS_ASSERT
#ifdef SSH_DEBUG_MODULE
#define SSH_ADS_ASSERT SSH_ASSERT
#else /* SSH_DEBUG_MODULE */
#define SSH_ADS_ASSERT(x) do { } while(0)
#endif /* SSH_DEBUG_MODULE */

typedef struct SshDlQueueRec
{
  struct SshDlListRec l;
  unsigned int capacity_left;
} *SshDlQueue;

typedef struct SshDlQueueRec SshDlQueueStruct;

#define SSH_DLQUEUE_GET_DLLIST(queue) (&(queue)->l)
#define SSH_DLQUEUE_INIT(queue, len) \
do { \
  SSH_ADS_ASSERT(len > 0); \
  SSH_DLLIST_INIT(SSH_DLQUEUE_GET_DLLIST(queue)); \
  (queue)->capacity_left = len; \
} while(0)

#define SSH_DLQUEUE_INSERT(queue, node) ssh_dlqueue_insert(queue, node)

SshDlNode ssh_dlqueue_insert(SshDlQueue queue, SshDlNode node);

#define SSH_DLQUEUE_DETACH_SPECIFIC(queue, node) \
do { \
    SSH_DLLIST_DETACH(SSH_DLQUEUE_GET_DLLIST(queue), node); \
    (queue)->capacity_left++; \
} while(0)

#define SSH_DLQUEUE_DETACH(queue) ssh_dlqueue_detach(queue)

SshDlNode ssh_dlqueue_detach(SshDlQueue queue);

#endif /* SSH_DL_QUEUE_INCLUDED */
