/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_structs.h
*/

#ifndef SSHADT_STRUCTS_H_INCLUDED
#define SSHADT_STRUCTS_H_INCLUDED

#ifndef SSHADT_INSIDE_SSHADT_H
#error  sshadt_structs.h improperly included
#endif

#include "sshfastalloc.h"

/* SshADTMethods is the internal structure of the type tag passed to
   ssh_adt_create_generic as a first argument.  It contains the method
   implementations for any particular container type.  */

struct ssh_adt_container_pars;

typedef struct {
  /* $$METHODSDECL */
  /* DO NOT EDIT THIS, edit METHODS.h instead. */
  Boolean (* container_init)
    (SshADTContainer, struct ssh_adt_container_pars *);
  void (* clear)
    (SshADTContainer);
  void (* destr)
    (SshADTContainer);
  SshADTHandle (* insert_at)
    (SshADTContainer, SshADTRelativeLocation, SshADTHandle, void *);
  SshADTHandle (* insert_to)
    (SshADTContainer, SshADTAbsoluteLocation, void *);
  SshADTHandle (* alloc_n_at)
    (SshADTContainer, SshADTRelativeLocation, SshADTHandle, size_t);
  SshADTHandle (* alloc_n_to)
    (SshADTContainer, SshADTAbsoluteLocation, size_t);
  SshADTHandle (* put_n_at)
    (SshADTContainer, SshADTRelativeLocation, SshADTHandle, size_t, void *);
  SshADTHandle (* put_n_to)
    (SshADTContainer, SshADTAbsoluteLocation, size_t, void *);
  void * (* get)
    (SshADTContainer, SshADTHandle);
  size_t (* num_objects)
    (SshADTContainer);
  SshADTHandle (* get_handle_to)
    (SshADTContainer, void *);
  SshADTHandle (* get_handle_to_location)
    (SshADTContainer, SshADTAbsoluteLocation);
  SshADTHandle (* next)
    (SshADTContainer, SshADTHandle);
  SshADTHandle (* previous)
    (SshADTContainer, SshADTHandle);
  SshADTHandle (* enumerate_start)
    (SshADTContainer);
  SshADTHandle (* enumerate_next)
    (SshADTContainer, SshADTHandle);
  SshADTHandle (* get_handle_to_equal)
    (SshADTContainer, void *);
  void * (* reallocate)
    (SshADTContainer, void *, size_t);
  void * (* detach)
    (SshADTContainer, SshADTHandle);
  void (* delet)
    (SshADTContainer, SshADTHandle);
  void * (* map_lookup)
    (SshADTContainer, SshADTHandle);
  void (* map_attach)
    (SshADTContainer, SshADTHandle, void *);
  /* $$ENDMETHODSDECL */
} SshADTMethods;

typedef struct {
  SshADTMethods methods;
  size_t internal_header_size;
  SshUInt32 flags;
} SshADTStaticData;

struct ssh_adt_hooks;

typedef struct {
  /* The application supplied methods (callbacks).  */
  SshADTCompareFunc compare;
  SshADTCopyFunc copy;
  SshADTDuplicateFunc duplicate;
  SshADTDestroyFunc destr;
  SshADTInitFunc init;
  SshADTHashFunc hash;
  SshADTCleanupFunc cleanup;
  SshADTMapAttachFunc map_attach;
  SshADTMapDetachFunc map_detach;

  /* Context common to all callbacks. */
  void *context;
} SshADTAppMethods;

typedef struct {
  /* Callbacks (installed with ssh_adt_create_generic).  */
  SshADTAppMethods app_methods;

  /* 'default_object_size' is used only when SSH_ADT_FLAG_ALLOCATE is
     set. In that case it is the default size of objects to allocate.  */
  size_t default_object_size;

  /* 'header_offset' is the difference between header and object
     pointers.  It is set by the user if an concrete headers and
     concrete objects are used, and by the library if abstract objects
     and abstract headers are used.  If objects are concrete and
     headers are abstract, this does not apply.  Must be signed
     (SshInt32) because the offset can be negative. */
  SshInt32 header_offset;
} SshADTStandardFields;

struct SshADTContainerRec {
  /* Static data that is container type specific.  The flags in this
     structure are shared by all container instances. */
  const SshADTStaticData *static_data;

  /* Pointer to extra data that the container wants to use.
     Allocated and released by the container. */
  void *container_specific;

  /* The active hooks, or NULL if no hooks are active.  (See 'Hooks'
     section in sshadt_i.h for more information on hooks.)  */
  struct ssh_adt_hooks *hooks;

  /* Private instance flags (changes invisible to other instances). */
  SshUInt32 flags;

  /* Contains the user definitions made at container creation time */
  SshADTStandardFields f;

  /* Number of contained objects. */
  size_t num_objects;
};

#define SSH_ADT_DEFAULT_SIZE(c) ((c)->f.default_object_size)

#define SSH_ADT_USER_CONTEXT(c) ((c)->f.app_methods.context)

#endif /* SSHADT_STRUCTS_H_INCLUDED */
