/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshdllist.h"

size_t ssh_dllist_len(SshDlList list)
{
  SshDlListMark end = SSH_DLLIST_GET_END_MARK(list);
  SshDlNode ptr = SSH_DLLIST_GET_FIRST(list);
  size_t count = 0;

  while (ptr != end)
    {
      count++;
      ptr = SSH_DLNODE_NEXT(ptr);
    }

  return count;
}

Boolean ssh_dllist_exists(SshDlList list, SshDlNode node)
{
  SshDlListMark end = SSH_DLLIST_GET_END_MARK(list);
  SshDlNode ptr = SSH_DLLIST_GET_FIRST(list);

  while (ptr != end)
    {
      if (ptr == node) return TRUE;
      ptr = SSH_DLNODE_NEXT(ptr);
    }

  return FALSE;
}
