/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Abstract Data Type (ADT) utility functions.

   @internal
*/

#ifndef SSHADT_H_INCLUDED
#define SSHADT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

/* The fast macro interface is used unless DEBUG_LIGHT is defined.  */

#ifndef DEBUG_LIGHT
#define SSH_ADT_WITH_MACRO_INTERFACE
#endif /* DEBUG_LIGHT */

#define SSHADT_INSIDE_SSHADT_H

/** Generic header type.  */
typedef struct {
  void *ptr[5];       /** Pointer. */
} SshADTHeaderStruct;

/** Abstract Data Type container. */
typedef struct SshADTContainerRec *SshADTContainer;

/** Handles for doing iteration, inserting objects etc.  */
typedef void *SshADTHandle;


/* ********************************************************* Callback types. */

/** Compare two objects.  */
typedef int (* SshADTCompareFunc)(const void *obj1, const void *obj2,
                                  void *context);

/** Duplicate an object.  'obj' is not constant because it is possible
    that the object is duplicated by for example increasing its
    reference count and returning itself.  */
typedef void *(* SshADTDuplicateFunc)(void *obj, void *context);

/** Initialize an abstract object from an another.  */
typedef void (* SshADTCopyFunc)(void *dst, size_t dst_size,
                                const void *src, void *context);

/** Destroy an object.  */
typedef void (* SshADTDestroyFunc)(void *obj, void *context);

/** Initialize an abstract object.  */
typedef void (* SshADTInitFunc)(void *obj, size_t size, void *context);

/** Calculate the hash of an object.  */
typedef SshUInt32 (* SshADTHashFunc)(const void *obj, void *context);

/** Notify a map value that there is a new reference to it. To be more
    precise, this callback is invoked iff map_attach binds a value to
    a key object in a container.  */
typedef void (* SshADTMapAttachFunc)(void *value, void *context);

/** Notify a map value that a key referencing it has been deleted.
    More precisely, this callback is invoked if:

    - a value is overwritten by a new value attached to an object by
      map_attach, or

    - if a key is deleted from a container.

   In particular, if a key is only detached but not deleted, MapDetach
   is not called.  */
typedef void (* SshADTMapDetachFunc)(void *value, void *context);

/** Clean up the container context.  This is called when the container
    is destroyed, after all elements have been removed from the
    container.  */
typedef void (* SshADTCleanupFunc)(void *ctx);


/* ****************************************** Container creation parameters. */


/** Container creation parameters: argument types. */
typedef enum {
  /* Argument type identifier           C type of the next argument
     ========================           =========================== */

  /** Set the user-supplied context for all callbacks - defaults to
      NULL when not set. */
  SSH_ADT_CONTEXT,                      /* void * */

  /** Set the compare function.  */
  SSH_ADT_COMPARE,                      /* SshADTCompareFunc */

  /** Set the duplicate function.  */
  SSH_ADT_DUPLICATE,                    /* SshADTDuplicateFunc */

  /** Set the copy function.  */
  SSH_ADT_COPY,                         /* SshADTCopyFunc */

  /** Set the destroy function.  */
  SSH_ADT_DESTROY,                      /* SshADTDestroyFunc */

  /** Set the hash function.  */
  SSH_ADT_HASH,                         /* SshADTHashFunc */

  /** Set the init function. */
  SSH_ADT_INIT,                         /* SshADTInitFunc */

  /** Set the map insert notification functions. */
  SSH_ADT_MAP_ATTACH,                   /* SshADTMapAttachFunc */

  /** Set the map insert notification function. */
  SSH_ADT_MAP_DETACH,                   /* SshADTMapDetachFunc */

  /** Set the cleanup function. */
  SSH_ADT_CLEANUP,                      /* SshADTCleanupFunc */

  /** Tell the ADT library to use a header inside the objects instead
      of allocating auxiliary data outside the objects; the next
      argument must be the offset (size_t) to an SshADTHeader field. */
  SSH_ADT_HEADER,                       /* SSH_ADT_OFFSET_OF(...) */

  /** Tell the ADT library the default size of the objects; this turns
      automatic object allocation on.  */
  SSH_ADT_SIZE,                         /* size_t */

  /** End of arguments marker.  */
  SSH_ADT_ARGS_END                      /* None */
} SshADTArgumentType;

#define SSH_ADT_OFFSET_OF(type,field) \
((unsigned char *)(&((type *)0)->field) - (unsigned char *)0)

/** Container types.  */

typedef const void *SshADTContainerType;

/** Invalid handle.  (Never ever redefine this to be something
    different from NULL.  It will never work.)  */
#define SSH_ADT_INVALID   NULL


/* ****************************************** Handling containers as a whole */

/** Generic container allocation. This can return NULL if memory
    allocation fails in those cases where memory allocation can fail
    (e.g. in kernel code).  */
SshADTContainer ssh_adt_create_generic(SshADTContainerType type,
                                       ...);

/** Destroy a container and all objects contained therein.  */
void ssh_adt_destroy(SshADTContainer container);

/** Make the container empty: destroy the contained objects but not the
    container itself. This returns the container basically to the state
    it had just after create.  */
void ssh_adt_clear(SshADTContainer container);


/* ***************************************** Absolute and relative locations */

/** Absolute locations. */
typedef long SshADTAbsoluteLocation;

/** Negative integer denoting a 'special' value: beginning.  */
#define SSH_ADT_BEGINNING -1
/** Negative integer denoting a 'special' value: end.  */
#define SSH_ADT_END       -2
/** Negative integer denoting a 'special' value: default.  */
#define SSH_ADT_DEFAULT   -3

/* Concrete absolute locations (e.g. array indices) are not natural
   numbers but quite.  The following macros transform integers into
   absolute locations and back.  Negative integers are forbidden.  */

/** Transform long -> SshADTAbsoluteLocation.
    Negative integers are forbidden.
 */
#define SSH_ADT_INDEX(n) (n)

/** Transform SshADTAbsoluteLocation -> long.
    Negative integers are forbidden.
 */
#define SSH_ADT_GET_INDEX(n) (n)

/** Transform SshADTAbsoluteLocation -> Boolean.
    Negative integers are forbidden.
 */
#define SSH_ADT_IS_INDEX(n) ((n) >= 0)  /* (No BEGINNING, END, DEFAULT here) */

/** Relative locations. */
typedef enum {
  SSH_ADT_BEFORE,       /** Relative location before. */
  SSH_ADT_AFTER         /** Relative location after. */
} SshADTRelativeLocation;


/* **************************************** Creating and inserting objects */

/* 1. concrete objects.  */

/** Insert an object into a container - in effect copy the pointer
    (relative location).

    The object may only be used as long as it is clear that the object
    is still alive in the container.  The container is responsible for
    destroying the object with an SshADTDestroyFunc callback.

    @return
    Returns a handle to the inserted object.

    */
SshADTHandle ssh_adt_insert_at(SshADTContainer container,
                               SshADTRelativeLocation location,
                               SshADTHandle handle,
                               void *object);

/** Insert an object into a container - in effect copy the pointer
    (absolute location).

    The object may only be used as long as it is clear that the object
    is still alive in the container.  The container is responsible for
    destroying the object with an SshADTDestroyFunc callback.

    @return
    Returns a handle to the inserted object.

    */
SshADTHandle ssh_adt_insert_to(SshADTContainer container,
                               SshADTAbsoluteLocation location,
                               void *object);

/** Insert an object into a container - in effect copy the pointer.

    The object may only be used as long as it is clear that the object
    is still alive in the container.  The container is responsible for
    destroying the object with an SshADTDestroyFunc callback.

    @return
    Returns a handle to the inserted object.

    */
SshADTHandle ssh_adt_insert(SshADTContainer container,
                            void *object);

/** Initialize a new concrete object from the original (relative location).

    Instead of copying the pointer of a concrete object, initialize a
    new concrete object from the original using the SshADTDuplicateFunc
    callback.  */

SshADTHandle ssh_adt_duplicate_at(SshADTContainer container,
                               SshADTRelativeLocation location,
                               SshADTHandle handle,
                               void *object);

/** Initialize a new concrete object from the original (absolute location).

    Instead of copying the pointer of a concrete object, initialize a
    new concrete object from the original using the SshADTDuplicateFunc
    callback.  */

SshADTHandle ssh_adt_duplicate_to(SshADTContainer container,
                               SshADTAbsoluteLocation location,
                               void *object);

/** Initialize a new concrete object from the original.

    Instead of copying the pointer of a concrete object, initialize a
    new concrete object from the original using the SshADTDuplicateFunc
    callback.  */

SshADTHandle ssh_adt_duplicate(SshADTContainer container,
                               void *object);

/* 2. abstract objects.  */

/** Initialize a new abstract object in the container (relative location).

    Invoke SshADTInitFunc to initialize a new object in the container.
    */

SshADTHandle ssh_adt_alloc_n_at(SshADTContainer container,
                                SshADTRelativeLocation location,
                                SshADTHandle handle,
                                size_t size);

/** Initialize a new abstract object in the container (absolute location).

    Invoke SshADTInitFunc to initialize a new object in the container.
    */

SshADTHandle ssh_adt_alloc_n_to(SshADTContainer container,
                                SshADTAbsoluteLocation location,
                                size_t size);

/** Initialize a new abstract object in the container (relative location).

    Invoke SshADTInitFunc to initialize a new object in the container.
    */

SshADTHandle ssh_adt_alloc_at(SshADTContainer container,
                              SshADTRelativeLocation location,
                              SshADTHandle handle);

/** Initialize a new abstract object in the container (absolute location).

    Invoke SshADTInitFunc to initialize a new object in the container.
    */

SshADTHandle ssh_adt_alloc_to(SshADTContainer container,
                              SshADTAbsoluteLocation location);

/** Initialize a new abstract object in the container.

    Invoke SshADTInitFunc to initialize a new object in the container.
    */

SshADTHandle ssh_adt_alloc_n(SshADTContainer container,
                             size_t size);

/** Initialize a new abstract object in the container.

    Invoke SshADTInitFunc to initialize a new object in the container.
    */

SshADTHandle ssh_adt_alloc(SshADTContainer container);

/** Copy an object to container (relative location).

   Invoke the SshADTCopyFunc callback to copy an object provided by
   the user into the container.  After this operation, the user's
   object is not associated to the container in any way and must be
   freed by hand eventually.  */

SshADTHandle ssh_adt_put_n_at(SshADTContainer container,
                              SshADTRelativeLocation location,
                              SshADTHandle handle,
                              size_t size,
                              void *obj);

/** Copy an object to container (relative location).

   Invoke the SshADTCopyFunc callback to copy an object provided by
   the user into the container.  After this operation, the user's
   object is not associated to the container in any way and must be
   freed by hand eventually.  */

SshADTHandle ssh_adt_put_n_to(SshADTContainer container,
                              SshADTAbsoluteLocation location,
                              size_t size,
                              void *obj);

/** Copy an object to container (relative location).

   Invoke the SshADTCopyFunc callback to copy an object provided by
   the user into the container.  After this operation, the user's
   object is not associated to the container in any way and must be
   freed by hand eventually.  */

SshADTHandle ssh_adt_put_at(SshADTContainer container,
                            SshADTRelativeLocation location,
                            SshADTHandle handle,
                            void *obj);

/** Copy an object to container (absolute location).

   Invoke the SshADTCopyFunc callback to copy an object provided by
   the user into the container.  After this operation, the user's
   object is not associated to the container in any way and must be
   freed by hand eventually.  */

SshADTHandle ssh_adt_put_to(SshADTContainer container,
                            SshADTAbsoluteLocation location,
                            void *obj);

/** Copy an object to container.

   Invoke the SshADTCopyFunc callback to copy an object provided by
   the user into the container.  After this operation, the user's
   object is not associated to the container in any way and must be
   freed by hand eventually.  */

SshADTHandle ssh_adt_put_n(SshADTContainer container,
                           size_t size,
                           void *obj);

/** Copy an object to container.

   Invoke the SshADTCopyFunc callback to copy an object provided by
   the user into the container.  After this operation, the user's
   object is not associated to the container in any way and must be
   freed by hand eventually.  */

SshADTHandle ssh_adt_put(SshADTContainer container,
                         void *obj);


/* ******************************************************* Accessing objects */

/** Get the object at the handle.  */
void *ssh_adt_get(SshADTContainer container, SshADTHandle handle);

/** Get the number of objects inside a container.  */
size_t ssh_adt_num_objects(SshADTContainer container);


/* ********************************************************* Setting handles */

/** Get a handle to the object. The pointers must match exactly. This
    can be a slow operation with concrete objects and abstract headers,
    because there is only a reference in the wrong direction and the
    container must be searched using brute force methods.  */
SshADTHandle ssh_adt_get_handle_to(SshADTContainer container,
                                   void *object);

/** Get a handle to any object that is equal to 'object'.  */
SshADTHandle ssh_adt_get_handle_to_equal(SshADTContainer container,
                                         void *object);

/** Get any object that is equal to 'object'.  */
void *ssh_adt_get_object_from_equal(SshADTContainer container,
                                    void *object);

/** Get the handle from an absolute location. */
SshADTHandle ssh_adt_get_handle_to_location(SshADTContainer container,
                                            SshADTAbsoluteLocation location);

/** Get the object from an absolute location. */
void *ssh_adt_get_object_from_location(SshADTContainer container,
                                       SshADTAbsoluteLocation location);

/*  Moving handles in containers that support some kind of ordering. */

/** Move the handle to the next object.

    In contrast to enumeration, this only works when there is any
    meaningful order in the container structure.  (E.g., even if a map
    is provided with a compare function it won't allow calls to these
    functions.)  */

SshADTHandle ssh_adt_next(SshADTContainer container, SshADTHandle handle);

/** Move the handle to the previous object.

    In contrast to enumeration, this only works when there is any
    meaningful order in the container structure.  (E.g., even if a map
    is provided with a compare function it won't allow calls to these
    functions.)  */

SshADTHandle ssh_adt_previous(SshADTContainer container, SshADTHandle handle);


/* *************************************** Removing objects from a container */

/** Detach the object that ssh_adt_get(container, handle) would return
    from the container.  After this the handle is invalidated.  The handle
    must be valid initial to the method call.  */
void *ssh_adt_detach(SshADTContainer container,
                     SshADTHandle handle);

/** Detach an object from a valid location.  */
void *ssh_adt_detach_from(SshADTContainer container,
                          SshADTAbsoluteLocation location);

/** Detach an object from a container.  It is an error for an object
    if it has not been found in a container.  */
void *ssh_adt_detach_object(SshADTContainer container, void *object);


/* *************************************** Deleting objects from a container */

/* (These methods exactly parallel the detach methods.)  */

/** Destroy the object that ssh_adt_get(container, handle) would
    return.  Invalidates the handle.  The handle must be valid initial to
    the method call.  */
void ssh_adt_delete(SshADTContainer container,
                    SshADTHandle handle);

/** Destroy an object from a valid location.  */
void ssh_adt_delete_from(SshADTContainer container,
                         SshADTAbsoluteLocation location);

/** Delete an object from a container.  It is an error for an object
    if it has not been found in a container.  */
void ssh_adt_delete_object(SshADTContainer container,
                           void *object);


/* *********************************************** Resizing abstract objects */

/** Reallocate an object inside a container.  */
void *ssh_adt_realloc(SshADTContainer container, void *object,
                      size_t new_size);

/** Return the default size of abstract objects.  */
size_t ssh_adt_default_size(SshADTContainer container);


/* ***************************************************** Duplicating objects */

/** Duplicate a concrete object.  */
void *ssh_adt_duplicate_object(SshADTContainer container, void *object);


/* ******************************************* Generic enumeration functions */

/** Start enumerating a container.

    @return
    Returns 'SSH_ADT_INVALID' if the container is empty.  */

SshADTHandle ssh_adt_enumerate_start(SshADTContainer container);

/** Continue enumeration.

    @return
    Returns 'SSH_ADT_INVALID' if all objects have been enumerated.  */

SshADTHandle ssh_adt_enumerate_next(SshADTContainer container,
                                    SshADTHandle handle);


/* *********************************************** Generic mapping functions */

/** Look up the value of a key handle in a mapping container.  */
void *ssh_adt_map_lookup(SshADTContainer container, SshADTHandle handle);

/** Add a new value to a mapping with a key handle.  */
void ssh_adt_map_attach(SshADTContainer container,
                        SshADTHandle handle, void *obj);


/* ********************** If the macro interface is active, include the rest */

#ifdef SSH_ADT_WITH_MACRO_INTERFACE
#include "sshadt_structs.h"
#include "sshadt_impls.h"
#include "sshadt_shortcuts.h"
#endif

#undef SSHADT_INSIDE_SSHADT_H

#ifdef __cplusplus
}
#endif

#endif /* SSHADT_H_INCLUDED */

