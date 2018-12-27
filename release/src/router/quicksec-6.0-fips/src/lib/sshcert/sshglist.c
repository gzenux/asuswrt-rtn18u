/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   List implementation for the Certificate, PKCS and validator
   functionality.
*/

#include "sshincludes.h"
#include "sshglist.h"

#ifdef SSHDIST_CERT

/* Handle the nodes. */

SshGListNode ssh_glist_allocate_n(SshGList list)
{
  SshGListNode node = ssh_malloc(sizeof(*node));

  if (node)
    {
      /* Initialize the node. */
      node->list = list;
      node->next = node->prev = NULL;
      node->data = NULL;
      node->data_length = 0;
    }
  return node;
}

void ssh_glist_remove_n(SshGListNode node)
{
  /* Clearly this case can be ignored. */
  if (node == NULL)
    return;

  /* Determine whether the node is in the list at all. */
  if (node->next == NULL && node->prev == NULL)
    {
      if (node->list == NULL)
        return;
      if (node->list->head != node)
        return;
    }

  if (node->prev)
    node->prev->next = node->next;
  else
    if (node->list)
      node->list->head = node->next;
  if (node->next)
    node->next->prev = node->prev;
  else
    if (node->list)
      node->list->tail = node->prev;

  /* Remove the node from the list. */
  if (node->list)
    node->list->num_n--;

  /* Clear the list information. */
  node->next = node->prev = NULL;
  node->list = NULL;
}

void ssh_glist_add_n(SshGListNode new_node,
                     SshGListNode reference_node,
                     SshGListNodePosition position)
{
  SshGList list;

  if (new_node == NULL)
    return;

  switch (position)
    {
    case SSH_GLIST_NEXT:
      if (reference_node == NULL)
        {
          /* Assume that the application wants to put the element as
             last in the list. */
          ssh_glist_add_n(new_node, NULL, SSH_GLIST_TAIL);
          return;
        }

      /* Determine whether the node is just moved or placed. */
      if (reference_node->list == new_node->list &&
          (new_node->next || new_node->prev))
        ;
      else
        /* We get a new element to the list. */
        reference_node->list->num_n++;

      /* Remove the node. */
      ssh_glist_remove_n(new_node);

      /* Add to the new list. */
      new_node->prev = reference_node;
      new_node->next = reference_node->next;
      if (reference_node->next)
        reference_node->next->prev = new_node;
      else
        reference_node->list->tail = new_node;
      reference_node->next = new_node;

      /* Change the list. */
      new_node->list = reference_node->list;
      break;

    case SSH_GLIST_PREV:
      if (reference_node == NULL)
        {
          /* Assume that the application wants to put the element as
             the first in the list. */
          ssh_glist_add_n(new_node, NULL, SSH_GLIST_HEAD);
          return;
        }

      /* Determine whether the node is just moved or placed. */
      if (reference_node->list == new_node->list &&
          (new_node->next || new_node->prev))
        ;
      else
        /* We get a new element to the list. */
        reference_node->list->num_n++;


      /* Remove the node. */
      ssh_glist_remove_n(new_node);


      new_node->next = reference_node;
      new_node->prev = reference_node->prev;
      if (reference_node->prev)
        reference_node->prev->next = new_node;
      else
        reference_node->list->head = new_node;
      reference_node->prev = new_node;

      /* Add the node to the right list. */
      new_node->list = reference_node->list;
      break;

    case SSH_GLIST_HEAD:

      /* Find the list. */
      if (reference_node != NULL)
        list = reference_node->list;
      else
        list = new_node->list;

      /* Is the node already in the list? */
      if (new_node->list == list &&
          (new_node->prev || new_node->next || list->head == new_node))
        ;
      else
        list->num_n++;

      /* Remove the node. */
      ssh_glist_remove_n(new_node);

      new_node->next = list->head;
      new_node->prev = NULL;

      if (list->head)
        list->head->prev = new_node;
      else
        list->tail = new_node;
      list->head = new_node;

      /* Set the correct list. */
      new_node->list = list;
      break;

    case SSH_GLIST_TAIL:

      /* Find the list. */
      if (reference_node != NULL)
        list = reference_node->list;
      else
        list = new_node->list;

      if (new_node->list == list &&
          (new_node->next || new_node->prev || list->head == new_node))
        ;
      else
        list->num_n++;

      /* Remove the node. */
      ssh_glist_remove_n(new_node);

      new_node->prev = list->tail;
      new_node->next = NULL;

      if (list->tail)
        list->tail->next = new_node;
      else
        list->head = new_node;
      list->tail = new_node;

      /* Set the correct list. */
      new_node->list = list;
      break;

    default:
      ssh_fatal("ssh_glist_add_n: position flag not supported.");
      break;
    }
}

/* This function might be redundant. */
void ssh_glist_join_n(SshGList list,
                      SshGListNode node)
{
  /* Remove from the old list. */
  ssh_glist_remove_n(node);
  /* Join to the list. */
  node->list = list;
}

/* Routines to free the above elements. */

void ssh_glist_free_n(SshGListNode node)
{
  ssh_glist_remove_n(node);
  ssh_free(node);
}


SshGList ssh_glist_allocate(void)
{
  SshGList list = ssh_malloc(sizeof(*list));

  if (list)
    {
      /* Clear the list. */
      list->num_n = 0;
      list->head  = NULL;
      list->tail  = NULL;
    }
  return list;
}

void ssh_glist_free(SshGList list)
{
  SshGListNode temp, next;

  for (temp = list->head; temp; temp = next)
    {
      next = temp->next;
      ssh_glist_free_n(temp);
    }
  ssh_free(list);
}

/* The iterator. */

void ssh_glist_iterator(SshGList list,
                        SshGListIterateCB callback,
                        void             *callback_context)
{
  SshGListNode temp, next;
  for (temp = list->head; temp; temp = next)
    {
      next = temp->next;
      (*callback)(temp, callback_context);
    }
}


/* Extensions to the glist. */
void ssh_glist_add_item(SshGList list, void *data,
                        SshGListNodePosition position)
{
  SshGListNode node;

  if (data && (node = ssh_glist_allocate_n(list)) != NULL)
    {
      node->data = data;
      ssh_glist_add_n(node, NULL, position);
    }
}

void ssh_glist_free_with_iterator(SshGList list,
                                  SshGListIterateCB callback,
                                  void  *context)
{
  if (list)
    {
      ssh_glist_iterator(list, callback, context);
      ssh_glist_free(list);
    }
}


/* sshglist.c */
#endif /* SSHDIST_CERT */
