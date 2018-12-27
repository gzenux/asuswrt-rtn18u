/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshdllist.h"
#include "sshdlqueue.h"

SshDlNode ssh_dlqueue_insert(SshDlQueue queue, SshDlNode node)
{
  if (!(queue)->capacity_left)
    {
      SshDlList list = SSH_DLQUEUE_GET_DLLIST(queue);
      SshDlNode noderet = SSH_DLLIST_GET_LAST(list);
      SSH_DLLIST_INSERT(list, node);
      SSH_DLLIST_DETACH(list, noderet);
      return noderet;
    }
  else
    {
      SSH_DLLIST_INSERT(SSH_DLQUEUE_GET_DLLIST(queue), node);
      queue->capacity_left--;
      return NULL;
    }
}

SshDlNode ssh_dlqueue_detach(SshDlQueue queue)
{
  SshDlList list = SSH_DLQUEUE_GET_DLLIST(queue);
  SshDlNode nodelast = SSH_DLLIST_GET_LAST(list);
  SshDlListMark end = SSH_DLLIST_GET_END_MARK(list);

  if (nodelast == end) return NULL;

  SSH_DLLIST_DETACH(list, nodelast);
  queue->capacity_left++;
  return nodelast;
}
