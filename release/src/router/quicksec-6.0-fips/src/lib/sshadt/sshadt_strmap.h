/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_strmap.h
*/

#ifndef SSHADT_STRMAP_H_INCLUDED
#define SSHADT_STRMAP_H_INCLUDED

#include "sshadt.h"
#include "sshadt_map.h"
#include "sshadt_xmap.h"


/* Default constructor: the resulting map does clean up the values
   attached to keys during deletion.  This is suitable if the strings
   map to, say, unboxed integers.  If they map to references to any
   objects, e.g. other strings that are allocated from the heap,
   ssh_adt_xcreate_strmap must be used instead.  */
SshADTContainer ssh_adt_create_strmap(void);

/* Like ssh_adt_create_strmap, but sets the attach and detach
   callbacks (both can be NULL_FNPTR, which would be the default).
   See documentation for ssh_adt_create_generic.  */
SshADTContainer ssh_adt_xcreate_strmap(SshADTMapAttachFunc attach,
                                       SshADTMapDetachFunc detach);

/* See sshadt_xmap.h for a description of this interface.  */
#define ssh_adt_strmap_add(c, key, val) \
  ssh_adt_xmap_add(c, (unsigned char *)key, val)
#define ssh_adt_strmap_remove(c, key) \
  ssh_adt_xmap_remove(c, (unsigned char *)key)
#define ssh_adt_strmap_set(c, key, val) \
  ssh_adt_xmap_set(c, (unsigned char *)key, val)
#define ssh_adt_strmap_get(c, key) \
  ssh_adt_xmap_get(c, (unsigned char *)key)
#define ssh_adt_strmap_exists(c, key) \
  ssh_adt_xmap_exists(c, (unsigned char *)key)

#endif /* !SSHADT_STRMAP_H_INCLUDED */
