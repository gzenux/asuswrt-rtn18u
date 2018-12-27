/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshsimplehashtable.h
*/

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshdllist.h"

#ifndef SSH_SIMPLE_HASH_TABLE_INCLUDED
#define SSH_SIMPLE_HASH_TABLE_INCLUDED 1

#undef SSH_ADS_ASSERT
#ifdef SSH_DEBUG_MODULE
#define SSH_ADS_ASSERT SSH_ASSERT
#else /* SSH_DEBUG_MODULE */
#define SSH_ADS_ASSERT(x) do { } while(0)
#endif /* SSH_DBEUG_MODULE */

typedef struct SshSimpleHashRec
{
  size_t max_elem;
  size_t cur_elems;
  SshDlListStruct elem[1];
} *SshSimpleHash;

typedef struct SshSimpleHashRec SshSimpleHashStruct;

#define SSH_SIMPLE_HASH_GET_DL(sh, hash) \
  (sh)?&((sh)->elem[(hash)&((sh)->max_elem)]):NULL

#define SSH_SIMPLE_HASH_ROUND(elements) \
  ((elements)?1+(SSH_SIMPLE_HASH_ROUND16((elements)-1)):0)

#define SSH_SIMPLE_HASH_ROUND16(elements) \
  (SSH_SIMPLE_HASH_ROUND8((elements)>>16) | SSH_SIMPLE_HASH_ROUND8(elements))

#define SSH_SIMPLE_HASH_ROUND8(elements) \
  (SSH_SIMPLE_HASH_ROUND4((elements)>>8) | SSH_SIMPLE_HASH_ROUND4(elements))

#define SSH_SIMPLE_HASH_ROUND4(elements) \
  (SSH_SIMPLE_HASH_ROUND2((elements)>>4) | SSH_SIMPLE_HASH_ROUND2(elements))

#define SSH_SIMPLE_HASH_ROUND2(elements) \
  (SSH_SIMPLE_HASH_ROUND1((elements)>>2) | SSH_SIMPLE_HASH_ROUND1(elements))

#define SSH_SIMPLE_HASH_ROUND1(elements) \
  (((elements)>>1) | (elements))

#define SSH_SIMPLE_HASH_SIZE(elements) \
  (sizeof(struct SshSimpleHashRec) + \
   sizeof(SshDlListStruct) * (SSH_SIMPLE_HASH_ROUND(elements)-1))

#define SSH_SIMPLE_HASH_SIZE_POINTERS(elements) \
  ((SSH_SIMPLE_HASH_SIZE(elements) + sizeof(void*) - 1)/ sizeof(void*))

#define SSH_SIMPLE_HASH_INIT(hash, elements, bytesize) \
  ssh_simple_hash_init(hash, elements, bytesize)

void ssh_simple_hash_init(SshSimpleHash hash,
                          size_t elements,
                          size_t bytesize);

#define SSH_SIMPLE_HASH_NODE_INSERT(hash, node, hashvalue) \
  do { SshDlList dl = SSH_SIMPLE_HASH_GET_DL(hash, hashvalue); \
       (hash)->cur_elems++; \
       SSH_DLLIST_INSERT(dl, node); } while(0)

#define SSH_SIMPLE_HASH_NODE_DETACH(hash, node, hashvalue) \
  do { SshDlList dl = SSH_SIMPLE_HASH_GET_DL(hash, hashvalue); \
       (hash)->cur_elems--; \
       SSH_DLLIST_DETACH(dl, node); } while(0)

#define SSH_SIMPLE_HASH_NODE_EXISTS(hash, node, hashvalue) \
  ssh_simple_hash_node_exists(hash, node, hashvalue)

Boolean ssh_simple_hash_node_exists(SshSimpleHash hash,
                                    SshDlNode node,
                                    SshUInt32 hashvalue);

typedef struct
{
  SshDlListMark end;
  SshDlNode next;
  SshUInt32 hashvalue;
} SshSimpleHashEnumerator;

#define SSH_SIMPLE_HASH_ENUMERATOR_START(hash, enum) \
  ssh_simple_hash_enumerator(hash, &(enum), 1)

#define SSH_SIMPLE_HASH_ENUMERATOR_NEXT(hash, enum) \
  ssh_simple_hash_enumerator(hash, &(enum), 0)

SshDlNode ssh_simple_hash_enumerator(SshSimpleHash sh,
                                     SshSimpleHashEnumerator *e,
                                     Boolean start);

#define SSH_SIMPLE_HASH_ENUMERATOR_START_HASHVALUE(hash, enum, hashvalue) \
  ssh_simple_hash_enumerator_hash(hash, &(enum), 1, hashvalue)

SshDlNode ssh_simple_hash_enumerator_hash(SshSimpleHash sh,
                                          SshSimpleHashEnumerator *e,
                                          Boolean start, SshUInt32 hash);

#endif /* SSH_SIMPLE_HASH_TABLE_INCLUDED */
