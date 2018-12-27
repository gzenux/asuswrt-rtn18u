/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_strmap.h
*/

#ifndef SSHADT_XMAP_H_INCLUDED
#define SSHADT_XMAP_H_INCLUDED

#include "sshadt.h"
#include "sshadt_map.h"


/*********************************************** The abstract map interface ***

   The following high-level mapping function can be used on any
   mapping container that

     * implements the following methods:
         - ssh_adt_get_handle_to_equal
         - ssh_adt_map_attach
         - ssh_adt_map_detach

     * has the following callbacks up and working:
         - SshADTCompareFunc
         - SshADTDuplicateFunc or SshADTCopyFunc (depending on the
           layout mode used)

   Two of the mapping containers currently available are SSH_ADT_MAP
   and SSH_ADT_AVLTREE.

   The keys are always copied into the container, so make sure all the
   keys that are passed to ssh_adt_xmap_add from the heap are freed
   properly by hand.

   However, the values are hooked into the container with
   ssh_adt_map_attach, so if you have string values you might have to
   call ssh_xstrdup by hand.

 *****************************************************************************/

/* Add a new element (using ssh_adt_duplicate or ssh_adt_put,
   depending on memory allocation mode).  Fails with an exception if
   key exist.  If you don't care whether key exists or not, use
   ssh_adt_xmap_set.  */
SshADTHandle ssh_adt_xmap_add(SshADTContainer c, void *key, void *value);

/* Delete a map entry.  If the key does not exist, nothing happens.
   If the MapDetach callback is installed, it is called on the value
   (if it exists) before its reference is dropped.  */
void ssh_adt_xmap_remove(SshADTContainer c, void *key);

/* Map key to value.  If key already exists, the new value is attached
   to the old key, and the new key is ignored.  If key is new
   (ie. ssh_adt_get_handle_to_equal returns SSH_ADT_INVALID),
   ssh_adt_xmap_add is called.  Either way caller is responsible for
   freeing key (see above).  */
void ssh_adt_xmap_set(SshADTContainer c, void *key, void *value);

/* Get the value to a key, or NULL if key is not found.  */
void *ssh_adt_xmap_get(SshADTContainer c, void *key);

/* Check whether a key exists in the map.  */
Boolean ssh_adt_xmap_exists(SshADTContainer c, void *key);


#endif /* SSHADT_XMAP_H_INCLUDED */
