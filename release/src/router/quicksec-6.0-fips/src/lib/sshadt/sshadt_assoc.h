/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#ifndef SSH_ADT_ASSOC_H_INCLUDED
#define SSH_ADT_ASSOC_H_INCLUDED

#include "sshadt.h"

/* This module can be used to conveniently glue together mapping
   containers so that they share keys and values.  The idea is that
   even if an object is referenced by both containers, it is deleted
   once and only once when removed from one container.

   There are two types of associations, unimaps and bimaps.  Unimaps
   map a dedicated domain into a dedicated range, and bimaps do the
   same thing symmetrically, i.e. both containers are domain as well
   as range.  A domain must be of mapping type (ie. implement
   ssh_adt_map_*, as for example SSH_ADT_MAP or SSH_ADT_AVLTREE),
   whereas a range can be any container.

   The association requires that the values of a domain must be
   handles of the corresponding range.

   THE PRECISE RULES:

     If an object in a domain D1 is mapped to a new value (or to
     SSH_ADT_INVALID if the mapping is to be deleted):

       - before the mapping is registered, the old value will be
       deleted from the corresponding range.

       - mappings are always ensured to be symmetric in bimaps: after
       the mapping has been registered in D1, if the range is a domain
       D2 and the map value in D2 is not mapping to its key object in
       D1, this mapping is registered.

     Before an object is detached from a domain, the value pointer in
     the handle is set to NULL.  This way the old value will stay in
     the range unmodified.

     If an object is deleted, nothing happens.  (The SshADTMapDetach
     callback can be used to clean up the range container if desired,
     but make sure that it accepts SSH_ADT_INVALID as a map value and
     does nothing then.  Especially in bimaps there is a risk of loops
     if deleting the one part of a symmetric key-value pair triggers
     deletion of the other one, and back, and so on.)

     If any of the two containers is destroyed, the two will be
     unassociated first.

   IMPORTANT CONSTRAINTS:

     - A container can only be associated with another container once
     at a time.  The second call to ssh_adt_associate_{uni,bi}map will
     cause the previous association to be deleted and leave the peer
     container in an inconsistent state.

     - If a mapping is not injective, particular care must be taken.
     If two keys map to the same value object and one of the keys is
     destroyed, the destruction callback of the value object must not
     invalidate it, but e.g. decrease a reference counter or do
     nothing.

     - priority queues have a peculiar structure that makes them
     unsuitable for the hook paradigm: objects in PQs have no headers,
     and can move around in the heap at any time.  As a consequence, a
     hook would address a random object that happens to occupy a
     certain array slot, while the targeted object has moved somewhere
     else.  Therefore PQs do not call hooks at all in the first place.
     It is possible to associate priority heaps, though, since they
     are implemented as proper trees with headers and everything.  */

/* Here 'domain' must be of a type that implements
   ssh_adt_map_{lookup,detach}.  */
Boolean ssh_adt_associate_unimap(SshADTContainer domain,
                                 SshADTContainer range);

/* Here both containers must be of a mapping type.  */
Boolean ssh_adt_associate_bimap(SshADTContainer c1, SshADTContainer c2);

/* Remove the association and leave both containers in a sound state.
   (There might still be shared structure if there was before, but at
   least the two containers behave in the standard way again.)  */
void ssh_adt_unassociate(SshADTContainer c1, SshADTContainer c2);

#endif /* SSH_ADT_ASSOC_H_INCLUDED */
