/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_list_i.h
*/

#ifndef SSHADT_LIST_I_H_INCLUDED
#define SSHADT_LIST_I_H_INCLUDED

#include "sshadt.h"

/* SshADTListNodeStruct can be used instead of SshADTHeaderStruct.
   The latter is more convenient because we need not know which
   container type we are using, but it might also be bigger because
   other container types need more control data.  */
typedef struct SshADTListNodeRec {
  struct SshADTListNodeRec *next, *prev;
} SshADTListNodeStruct;

/* SshADTListENode is a tuple of header and object pointer.  If
   SSH_ADT_FLAG_NEED_EXTRA_NODES is OFF, this is not used because
   header and object can be stored in the same blob.  */
typedef struct {
  void *object;
  SshADTListNodeStruct i;
} SshADTListENodeStruct;

/* SshADTListRoot is written the container_specific field of the
   generic container structure, and contains pointers to both ends of
   the list.  */
typedef struct {
  SshADTListNodeStruct *first_node, *last_node;
} SshADTListRootStruct;

/* The container type.  (Defined at the bottom of sshadt_list.c,
   that's why we need to declare it here.)  */
extern const SshADTStaticData ssh_adt_list_static_data;

#define SSH_ADT__LIST_INSERT_TO_END(root, node)                               \
do                                                                            \
{                                                                             \
  SshADTListNodeStruct *__last = (root)->last_node;                           \
  node->next = NULL;                                                          \
  if (__last == NULL)                                                         \
    {                                                                         \
      node->prev = NULL;                                                      \
      (root)->last_node = (root)->first_node = node;                          \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      node->prev = __last; __last->next = node;                               \
      (root)->last_node = node;                                               \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_ADT__LIST_INSERT_TO_BEGINNING(root, node)                         \
do                                                                            \
{                                                                             \
  SshADTListNodeStruct *__first = (root)->first_node;                         \
  node->prev = NULL;                                                          \
  if (__first == NULL)                                                        \
    {                                                                         \
      node->next = NULL;                                                      \
      (root)->last_node = (root)->first_node = node;                          \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      node->next = __first; __first->prev = node;                             \
      (root)->first_node = node;                                              \
    }                                                                         \
}                                                                             \
while (0)

#endif /* SSHADT_LIST_I_H_INCLUDED */
