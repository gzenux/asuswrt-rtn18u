/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic list routines written to be easy to use in many situations. This
   interface is very similar to the sshdllist, however, we do not
   spend time to write routines to interface the nodes, applications are
   free to read the node information by themselves.
*/

#ifndef SSHGLIST_H
#define SSHGLIST_H

typedef struct SshGListRec *SshGList;

typedef struct SshGListNodeRec
{
  /* Application is free to read this information, however,
     modifications should not be done (except to the data pointer). */
  SshGList list;

  /* Doubly linked list. */
  struct SshGListNodeRec *next, *prev;

  /* The data.  */
  void  *data;

  /* The lenght of the data. Application can do anything it pleases
     with this, added to make strings and buffers easy to push to a
     list. */
  size_t data_length;
} *SshGListNode;

struct SshGListRec
{
  /* Number of nodes in the list. */
  size_t num_n;
  /* The head of the list. */
  SshGListNode head;
  /* The tail of the list. */
  SshGListNode tail;
};

/* Prototypes for basic operations. */

/* Allocation of lists. */

SshGList ssh_glist_allocate(void);

/* Freeing of the nodes of the lists. The operation doesn't free the
   data elements. For this operation you should write a callback and
   use the iterator defined later. */
void ssh_glist_free(SshGList list);

/* As all information of the data structures is open knowledge and the
   following iterator can be used to search information there is only
   need for routines which add nodes. */

typedef void (*SshGListIterateCB)(SshGListNode node, void *context);

/* Iterator. */
void ssh_glist_iterator(SshGList          list,
                        SshGListIterateCB callback,
                        void             *callback_context);

/* Allocate a node. Initially the node is not in the list, although it
   has a reference to the list. You must remove the node from the
   list if you want to join it to another list. */
SshGListNode ssh_glist_allocate_n(SshGList list);

/* Nodes can be freed independly. */
void ssh_glist_free_n(SshGListNode node);


void ssh_glist_free_with_iterator(SshGList list,
                                  SshGListIterateCB callback,
                                  void  *context);

typedef enum
{
  SSH_GLIST_NEXT,
  SSH_GLIST_PREV,
  SSH_GLIST_HEAD,
  SSH_GLIST_TAIL
} SshGListNodePosition;

/* Append the node to the list. */
void ssh_glist_add_n(SshGListNode         new_node,
                     SshGListNode         reference_node,
                     SshGListNodePosition position);

/* Add an item. */
void ssh_glist_add_item(SshGList list, void *data,
                        SshGListNodePosition position);

/* Join the node to another list. The node must be remove from the
   list it was occupying previously. After this operation you can add
   it to the suitable place in the list. */
void ssh_glist_join_n(SshGList     list,
                      SshGListNode node);

/* Remove the node from the current list it occupies. */
void ssh_glist_remove_n(SshGListNode node);

#endif /* SSHGLIST_H */
