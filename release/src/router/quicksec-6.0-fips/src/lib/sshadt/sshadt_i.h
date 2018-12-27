/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshadt_i.h
*/

#ifndef SSHADT_I_H_INCLUDED
#define SSHADT_I_H_INCLUDED


#include "sshadt.h"

/* If SSH_ADT_WITH_MACRO_INTERFACE is undefined, sshadt_structs.h does
   not get included from sshadt.h, but new we definitely need it.  */
#define SSHADT_INSIDE_SSHADT_H
#include "sshadt_structs.h"
#undef SSHADT_INSIDE_SSHADT_H

/* Workaround for macro optimization bug in MSC (by siren@ssh.fi).  */
#if _MSC_VER == 1200
#pragma optimize( "", off )
#endif


/************************************************************* Layout modes. */

/* OFF: objects are concrete; ON: objects are abstract.  */
#define SSH_ADT_FLAG_ALLOCATE           0x0002

/* ON: header is concrete; OFF: header is abstract.  */
#define SSH_ADT_FLAG_CONTAINED_HEADER   0x0004

/* This flag is ON if and only if abstract headers and concrete
   objects are selected.  In this case, the behaviour of the mappings
   between objects and handles is more complicated: objects can NOT be
   mapped to handles by efficient pointer arithmetics, because they
   are not stored in one blob of memory.  Only handle->object can be
   done in O(1).  (See sshadt_std_i.h and the documentation for
   ssh_adt_get_handle_to in sshadt.h.)  */
#define SSH_ADT_FLAG_NEED_EXTRA_NODES   0x0008


/**************************************************************** Callbacks. */

int ssh_adt_default_compare(const void *obj1, const void *obj2,
                            void *context);

void *ssh_adt_default_duplicate(void *obj, void *context);

void ssh_adt_default_copy(void *dst, size_t d_size,
                          const void *src, void *context);

void ssh_adt_default_destroy(void *obj, void *context);

void ssh_adt_default_init(void *obj, size_t size, void *context);

SshUInt32 ssh_adt_default_hash(const void *obj, void *context);

#define SSH_ADT_CALL_APP(container, method, args)                             \
do                                                                            \
{                                                                             \
  if (container->f.app_methods.method != NULL_FNPTR)                          \
    {                                                                         \
      SSH_DEBUG(9, ("Invoking callback @%p.",                                 \
                    container->f.app_methods.method));                        \
      (*(container->f.app_methods.method))args;                               \
      SSH_DEBUG(9, ("Callback @%p returned.",                                 \
                    container->f.app_methods.method));                        \
    }                                                                         \
  else                                                                        \
    SSH_DEBUG(9, ("Reference to non-existent callback (doing nothing)."));    \
}                                                                             \
while (0)

#define SSH_ADT_CALL_APP_MANDATORY(container, method, args, result)     \
do                                                                      \
{                                                                       \
  SSH_ASSERT(container->f.app_methods.method != NULL_FNPTR);            \
  SSH_DEBUG(9, ("Invoking callback @%p.",                               \
                container->f.app_methods.method));                      \
  result = (*(container->f.app_methods.method))args;                    \
  SSH_DEBUG(9, ("Callback @%p returned.",                               \
                container->f.app_methods.method));                      \
}                                                                       \
while (0)

#define SSH_ADT_APPCTX(container) \
  (container->f.app_methods.context)

#define SSH_ADT_HASH_OBJECT(c, obj, result) \
  SSH_ADT_CALL_APP_MANDATORY(c, hash, (obj, SSH_ADT_APPCTX(c)), result)


/******************************************************************** Hooks. */

/* Hooks are the same thing as callbacks (the functions that can be
   registered in a container by the user), and they are called more or
   less in the same situations, but they are intended for internal use
   only.  Currently they are only used in sshadt_assoc.c.

   (If there is ever a need for hooks for something else, it is
   probably wisest to think about a generic concept that unifies hooks
   and callbacks and allows for registering many hooks for one event.)  */

typedef void (* SshADTHookFunc)(SshADTHandle handle, void *context);

typedef void (* SshADTDestroyHookFunc)(void *context);

typedef void (* SshADTReallocHookFunc)(SshADTHandle old_handle,
                                       SshADTHandle new_handle,
                                       void *context);

/* The structure in which the hooks and their contexts are stored in
   the container.  */
struct ssh_adt_hooks {

  /* Directly before methods insert_*, duplicate_*, alloc_*, put_* are
     invoked.  */
  SshADTHookFunc insert;

  /* In the detach method.  */
  SshADTHookFunc detach;

  /* After the map value has been assigned.  */
  SshADTHookFunc map;

  /* Directly before the map value is assigned.  */
  SshADTHookFunc unmap;

  void *insert_ctx, *detach_ctx, *map_ctx, *unmap_ctx;

  /* After an object has been reallocated.  oldh must not be used as a
     pointer any more, it is invalidated by the reallocation.  */
  SshADTReallocHookFunc reallocated;
  void *reallocated_ctx;

  /* Before a container is destroyed.  */
  SshADTDestroyHookFunc destr;
  void *destr_ctx;
};

typedef struct ssh_adt_hooks SshADTHooksStruct;

int ssh_adt_initialize_hooks(SshADTContainer container);
void ssh_adt_uninitialize_hooks(SshADTContainer container);

/* Calling the hooks.  For different numbers of arguments, there need
   to be different macros.  */
#define SSH_ADT_CALL_HOOK_GENERIC(container, hook_name, args)                 \
do                                                                            \
{                                                                             \
  SshADTHooksStruct *__h = container->hooks;                                  \
  if (__h == NULL) break;                                                     \
  if (__h->hook_name == NULL_FNPTR) break;                                    \
                                                                              \
  (*(__h->hook_name)) args;                                                   \
}                                                                             \
while (0)

#define SSH_ADT_CALL_HOOK(container, hook_name, a) \
SSH_ADT_CALL_HOOK_GENERIC(container, hook_name, (a, __h->hook_name ## _ctx))

#define SSH_ADT_CALL_DESTROY_HOOK(container, hook_name) \
SSH_ADT_CALL_HOOK_GENERIC(container, hook_name, (__h->hook_name ## _ctx))

#define SSH_ADT_CALL_REALLOC_HOOK(container, hook_name, a, b) \
SSH_ADT_CALL_HOOK_GENERIC(container, hook_name, (a, b, __h->hook_name ## _ctx))


/******************************************************************* Things. */

/* This is the argument structure that is passed from the generic
   creation method to that specific to the container type.  */

typedef struct ssh_adt_container_pars {
  SshADTContainerType type;
  SshUInt32 flags;
  SshADTStandardFields f;
} SshADTContainerParsStruct;


/* Use only if SSH_ADT_FLAG_NEED_EXTRA_NODES is undefined: convert
   handles into objects and vice versa.  (Since the handle is the
   header embedded in the object, this is just a matter of adding or
   substracting the header offset to or from the argument pointer.
   The header offset is specified as an argument to
   ssh_adt_create_generic.) */

#define SSH_ADT_HANDLE_FROM_OBJECT(c, o) \
  ((SshADTHandle)(((unsigned char *) o) + ((c)->f.header_offset)))

#define SSH_ADT_OBJECT_FROM_HANDLE(c, h) \
  ((void *)(((unsigned char *) h) - ((c)->f.header_offset)))

/* Use only if SSH_ADT_FLAG_NEED_EXTRA_NODES is defined: given an
   extra node (ENode) of the from "struct { void *obj; N node; }",
   compute "obj" from "node".  */

#define SSH_ADT_OBJECT_AT_NODE(n) \
  (*((void **)(((unsigned char *)n) - sizeof(void *))))


/* This is called from inside the container implementations when
   objects are detached just prior to destroying them.  In this case
   we need not require that objects are external because no user will
   ever get hold on them.  (This is used in SSH_ADT_STD_DELETE macro
   in sshadt_std_i.h.)  */

#ifdef SSH_ADT_WITH_MACRO_INTERFACE
#define ssh_adt_detach_i(c,h) ssh_adt_detach(c,h)
#else
void *ssh_adt_detach_i(SshADTContainer container, SshADTHandle handle);
#endif


#endif /* SSHADT_I_H_INCLUDED */
