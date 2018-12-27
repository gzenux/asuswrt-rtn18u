/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_intmap.h
*/

#ifndef SSHADT_INTMAP_H_INCLUDED
#define SSHADT_INTMAP_H_INCLUDED

#include "sshadt.h"
#include "sshadt_map.h"
#include "sshadt_xmap.h"

/* Create a hashtable with unboxed integer keys.  Default constructor:
   the resulting map does clean up the values attached to keys during
   deletion.  This is suitable if the values are unboxed integers
   also.  If they are references to objects instead, e.g. to strings
   allocated from the heap, ssh_adt_xcreate_intmap must be used
   instead.  */
SshADTContainer ssh_adt_create_intmap(void);

/* Like ssh_adt_create_intmap, but sets the attach and detach
   callbacks (both can be NULL_FNPTR, which would be the default).
   See documentation for ssh_adt_create_generic.  */
SshADTContainer ssh_adt_xcreate_intmap(SshADTMapAttachFunc attach,
                                       SshADTMapDetachFunc detach);

/* See sshadt_xmap.h for a description of this interface.  */
SshADTHandle ssh_adt_intmap_add(SshADTContainer c, SshUInt32 key, void *value);
void ssh_adt_intmap_remove(SshADTContainer c, SshUInt32 key);
void ssh_adt_intmap_set(SshADTContainer c, SshUInt32 key, void *value);
void *ssh_adt_intmap_get(SshADTContainer c, SshUInt32 key);
Boolean ssh_adt_intmap_exists(SshADTContainer c, SshUInt32 key);

#endif /* !SSHADT_INTMAP_H_INCLUDED */
