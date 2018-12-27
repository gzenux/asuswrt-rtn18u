/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   The range container can be used to store and merge intervals of
   arbitrary delimiter type.  It shares most of its code with AVL
   trees.

   Basic philosophy follows: a node N in the tree represents the lower
   bound of the interval [N, M), where M is the next bigger node.  Each
   interval is associated with a map value (see ssh_adt_map_lookup and
   ssh_adt_map_attach).  For instance, (void *)TRUE and (void *)FALSE
   can be used to decide simple set membership of all elements in the
   interval.  However, arbitrary ranges are possible.  There are two
   restrictions to the semantics of values:

    - Since there is no callback for comparing map values, equality of
      values means "(void *)o1 == (void *)o2".

    - By definition, (-inf, K) maps always to NULL, where K is the
      smallest element in the container.  The biggest element N in the
      container defines an interval [N, +inf) that can have any value
      attached to it.  Note that NULL == (void *)FALSE.

   Note that this model implies that the set of intervals in a range
   container always covers the entire range of all possible values.

   Usage: for an application that enables you to allocate and free
   resource handles from a set of integers, see the sshadt_ranges.c.
   More generally,

    - A new interval is added by inserting its lower bound and mapping
      it to the desired value.  The higher bound is implicit by the
      tree: it's simply the next larger node.

    - To retrieve the value attached to the range that contains a given
      key object, use ssh_adt_get_handle_to_glb and ssh_adt_map_lookup.

    - Not very surprisingly, to discard a range, use ssh_adt_delete.

   After a non-empty sequence of insertions and deletions, two
   neighbouring ranges can map to the same value.  The ranges container
   caches all places in which that can be the case.  The special method
   ssh_adt_ranges_merge purges this cache and merges all neighbouring
   ranges that map to the same value.  One of two such ranges will be
   removed with ssh_adt_delete.  The generic callback mechanisms must
   be used to make sure that all allocated memory is freed.
*/

#ifndef SSH_ADT_RANGES_H_INCLUDED
#define SSH_ADT_RANGES_H_INCLUDED

#include "sshadt.h"
#include "sshadt_avltree.h"

#ifdef WINDOWS_IMPORT_BASE
__declspec(dllimport)
#endif
extern const SshADTContainerType ssh_adt_ranges_type;

#define SSH_ADT_RANGES (ssh_adt_ranges_type)

/* After a sequence of insertions and deletions of lower range bounds,
   merge the container so that no two neighbouring ranges have the
   same map value.  */
void ssh_adt_ranges_merge(SshADTContainer c);


/************************************************************* Applications. */

/* The following functions provide a ranges container for resource
   allocation.  A resources is a non-negative integer that can be
   allocated and freed.  A resource allocator knows two operations: it
   can allocate and return a free resource, or free this resource if
   it is no longer needed.  */

#define SSH_ADT_RANGES_FREE        ((void *)TRUE)
#define SSH_ADT_RANGES_ALLOCATED   ((void *)FALSE)

/* Initialize a resource allocator.  */
SshADTContainer ssh_adt_resource_allocator_create(void);

/* Allocate the least free resource and returns it.  */
Boolean ssh_adt_resource_allocator_allocate(SshADTContainer c, SshUInt32 *i);

/* Free resource.  Returns FALSE if resource was not allocated, TRUE
   if it was and is now free again.  */
Boolean ssh_adt_resource_allocator_free(SshADTContainer c, SshUInt32 i);


#endif /* SSH_ADT_RANGES_H_INCLUDED */

