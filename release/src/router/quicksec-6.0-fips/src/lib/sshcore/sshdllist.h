/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshdllist.h
*/

#include "sshincludes.h"
#include "sshdebug.h"

#ifndef SSH_DLLIST_INCLUDED
#define SSH_DLLIST_INCLUDED 1

#undef SSH_ADS_ASSERT
#ifdef SSH_DEBUG_MODULE
#define SSH_ADS_ASSERT SSH_ASSERT
#else /* SSH_DEBUG_MODULE */
#define SSH_ADS_ASSERT(x) do { } while(0)
#endif /* SSH_DBEUG_MODULE */

typedef struct SshDlListRec
{
  struct SshDlNodeRec *first;
  struct SshDlNodeRec *last;
} *SshDlList;

typedef struct SshDlListRec SshDlListStruct;

typedef struct SshDlNodeRec
{
  struct SshDlNodeRec *next;
  struct SshDlNodeRec *prev;
} *SshDlNode;

typedef struct SshDlNodeRec SshDlNodeStruct;
typedef struct SshDlNodeRec *SshDlListMark;

#define SSH_DLLIST_GET_START_MARK(list) ((struct SshDlNodeRec *)(list))
#define SSH_DLLIST_GET_END_MARK(list) ((struct SshDlNodeRec *)(list))

#define SSH_DLLIST_IS_UNINIT(list) (!((list)->first))

#define SSH_DLLIST_GET_FIRST(list) ((list)->first)
#define SSH_DLLIST_GET_LAST(list) ((list)->last)

#define SSH_DLLIST_INIT(list) \
  do { (list)->first = SSH_DLLIST_GET_END_MARK(list); \
       (list)->last = SSH_DLLIST_GET_START_MARK(list); } while(0)

#define SSH_DLLIST_INSERT(list, node) \
  do { struct SshDlNodeRec *dl_i_smp = (void*)(list);      \
       (node)->prev = SSH_DLLIST_GET_START_MARK(dl_i_smp); \
       (node)->next = (list)->first; \
       (list)->first->prev = (node); \
       (list)->first = (node); \
     } while(0)

/* Mark potentially unused variables, to remove warnings. */
#define SSH_DLLIST_UNUSED_VAR(x) ((void)(x))

#define SSH_DLLIST_DETACH(list, node) \
  do { SSH_ADS_ASSERT(SSH_DLLIST_EXISTS(list, node)); \
       SSH_DLLIST_UNUSED_VAR(list); \
       (node)->prev->next = (node)->next; \
       (node)->next->prev = (node)->prev; \
     } while(0)

#define SSH_DLLIST_EXISTS(list, node) ssh_dllist_exists(list,node)

#define SSH_DLNODE_NEXT(node) ((node)->next)
#define SSH_DLNODE_PREV(node) ((node)->prev)

Boolean ssh_dllist_exists(SshDlList list, SshDlNode node);

#define SSH_DLLIST_LEN(list) ssh_dllist_len(list)

size_t ssh_dllist_len(SshDlList list);

#endif /* SSH_DLLIST_INCLUDED */
