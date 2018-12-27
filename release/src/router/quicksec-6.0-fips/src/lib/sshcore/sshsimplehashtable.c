/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshdllist.h"
#include "sshsimplehashtable.h"

void ssh_simple_hash_init(SshSimpleHash hash,
                          size_t elements,
                          size_t bytesize)
{
  size_t sz;
  SSH_ADS_ASSERT(bytesize >= sizeof(SshSimpleHashStruct));
  SSH_ADS_ASSERT(SSH_SIMPLE_HASH_SIZE(elements) <= bytesize);

  hash->max_elem = elements - 1;
  hash->cur_elems = 0;

  for(sz = 0; sz < elements; sz++)
    {
      SSH_DLLIST_INIT(&(hash->elem[sz]));
    }
}

Boolean ssh_simple_hash_node_exists(SshSimpleHash hash,
                                    SshDlNode node,
                                    SshUInt32 hashvalue)
{
  SshDlList dl = SSH_SIMPLE_HASH_GET_DL(hash, hashvalue);
  return SSH_DLLIST_EXISTS(dl, node);
}

SshDlNode ssh_simple_hash_enumerator(SshSimpleHash sh,
                                     SshSimpleHashEnumerator *e,
                                     Boolean start)
{
  SshDlNode current;
  SshDlListMark end;

  if (start)
    {
      if (sh == NULL) return NULL;

      e->hashvalue = 0;
      e->end = NULL;
      e->next = NULL;
    }

  /* More in this chain? */
  if (e->next != e->end)
    {
      current = e->next;
      e->next = SSH_DLNODE_NEXT(e->next);
      return current;
    }

  /* More in subsequent chains */
  while (e->hashvalue <= sh->max_elem)
    {
      SshDlList list = SSH_SIMPLE_HASH_GET_DL(sh, e->hashvalue);
      e->hashvalue++;
      current = SSH_DLLIST_GET_FIRST(list);
      end = SSH_DLLIST_GET_END_MARK(list);
      if (current != end)
        {
          e->next = SSH_DLNODE_NEXT(current);
          e->end = end;
          return current;
        }
    }

  return NULL;
}

SshDlNode ssh_simple_hash_enumerator_hash(
  SshSimpleHash sh, SshSimpleHashEnumerator *e, Boolean start, SshUInt32 hash)
{
  SshDlNode current;
  SshDlListMark end;
  SshDlList list;

  SSH_ADS_ASSERT(start);

  e->hashvalue = sh->max_elem + 1;
  e->end = NULL;
  e->next = NULL;

  list = SSH_SIMPLE_HASH_GET_DL(sh, hash);
  current = SSH_DLLIST_GET_FIRST(list);
  end = SSH_DLLIST_GET_END_MARK(list);
  if (current != end)
    {
      e->next = SSH_DLNODE_NEXT(current);
      e->end = end;
      return current;
    }

  return NULL;
}
