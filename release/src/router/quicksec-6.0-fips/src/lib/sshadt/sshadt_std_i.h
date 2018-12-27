/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   This file contains some callback and method skeletons that are used
   in different container types to implement syntactially similar
   structures.  (It serves a similar purpose as sshadt_i.h, but it is
   only used in the container implementations, whereas sshadt_i.h is
   also used in the generic implementation, the convenience extenions
   and so on.)
*/

#ifndef SSHADT_STD_I_H_INCLUDED
#define SSHADT_STD_I_H_INCLUDED

#include "sshadt.h"
#include "sshadt_i.h"


#define SSH_ADT_PROTECT(block) do { block } while (0)

/* A handle is mapped to an object in two different ways, depending on
   the layout mode.

   If SSH_ADT_FLAG_NEED_EXTRA_NODES is defined, move backwards from
   the header structure (ENodeStruct) by one pointer in order to get
   to the object's base address (Node *) (it is required that this
   ENode structure has the form '{ void *obj, HeaderStruct header }').

   If not, move backwards by header_offset.  */

#define SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(container, handle, result)         \
do                                                                            \
{                                                                             \
  if ((container)->flags & SSH_ADT_FLAG_NEED_EXTRA_NODES)                     \
    {                                                                         \
      unsigned char *__ptr2 = ((SshADTHandle)(handle));                       \
      __ptr2 -= sizeof(void *);                                               \
      result = *((void **)__ptr2);                                            \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      result = ((unsigned char *)((SshADTHandle)(handle))) -                  \
        (container)->f.header_offset;                                         \
    }                                                                         \
}                                                                             \
while (0)

#define SSH_ADT_STD_FREE_I(container, handle)                                 \
do                                                                            \
{                                                                             \
  if ((container)->flags & SSH_ADT_FLAG_CONTAINED_HEADER)                     \
    {                                                                         \
      unsigned char *__ptr;                                                   \
      SSH_ADT_STD_GET_OBJECT_FROM_HANDLE((container), (handle), __ptr);       \
      ssh_free(__ptr);                                                        \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      ssh_free(handle);                                                       \
    }                                                                         \
}                                                                             \
while (0)

#ifdef _KERNEL
#define SSH_ADT_STD_ALLOC_I(container, size, result)                          \
do                                                                            \
{                                                                             \
  result = NULL;                                                              \
  ssh_fatal("SSH_ADT_STD_ALLOC_I(): memory mode not supported in _KERNEL");   \
}                                                                             \
while (0)
#else /* _KERNEL */
#define SSH_ADT_STD_ALLOC_I(container, size, result)                          \
do                                                                            \
{                                                                             \
  unsigned char *__ptr;                                                       \
  if (!((container)->flags & SSH_ADT_FLAG_CONTAINED_HEADER))                  \
    {                                                                         \
      __ptr = ssh_xmalloc((size) +                                            \
                          (container)->static_data->internal_header_size);    \
      result = __ptr - (container)->f.header_offset;                          \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      result = ssh_xmalloc(size);                                             \
    }                                                                         \
}                                                                             \
while (0)
#endif /* _KERNEL */

/* Construct a handle from an object.  See comment in sshadt_i.h for
   the SSH_ADT_FLAG_NEED_EXTRA_NODES flag.  */

#define SSH_ADT_STD_MAKE_HANDLE(container, object, block, result)             \
do                                                                            \
{                                                                             \
  if ((container)->flags & SSH_ADT_FLAG_NEED_EXTRA_NODES)                     \
    {                                                                         \
      SshADTHandle __handle;                                                  \
      SSH_ADT_PROTECT(block);                                                 \
      if (__handle != NULL)                                                   \
        {                                                                     \
          *((void **)__handle) = object;                                      \
          result = (unsigned char *)__handle + sizeof(void *);                \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          result = NULL;                                                      \
        }                                                                     \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      result = SSH_ADT_HANDLE_FROM_OBJECT((container), (object));             \
    }                                                                         \
}                                                                             \
while (0)


/******************************************************* Callback skeletons. */

#define SSH_ADT_STD_COMPARE(container, h1, h2, result)                        \
do                                                                            \
{                                                                             \
  void *o1, *o2;                                                              \
  SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(container, (SshADTHandle)h1, o1);        \
  SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(container, (SshADTHandle)h2, o2);        \
  SSH_ADT_CALL_APP_MANDATORY(container, compare,                              \
                             (o1, o2, SSH_ADT_APPCTX(container)), result);    \
}                                                                             \
while (0)

#define SSH_ADT_STD_COMPARE_H_O(container, h1, o2, result)                    \
do                                                                            \
{                                                                             \
  void *o1;                                                                   \
  SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(container, (SshADTHandle)h1, o1);        \
  SSH_ADT_CALL_APP_MANDATORY(container, compare,                              \
                             (o1, o2, SSH_ADT_APPCTX(container)), result);    \
}                                                                             \
while (0)

#define SSH_ADT_STD_HASH(container, h1, result)                               \
do                                                                            \
{                                                                             \
  void *o1;                                                                   \
  SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(container, (SshADTHandle)h1, o1);        \
  SSH_ADT_CALL_APP_MANDATORY(container, hash,                                 \
                             (o1, SSH_ADT_APPCTX(container)), result);        \
}                                                                             \
while (0)


/********************************************************* Method skeletons. */

/* Initialize a container.  */

#define SSH_ADT_STD_INIT(name, block)                                         \
static Boolean name(SshADTContainer c, SshADTContainerParsStruct *pars)       \
{                                                                             \
  c->static_data = pars->type;                                                \
  c->flags       = pars->flags;                                               \
  c->hooks       = NULL;                                                      \
                                                                              \
  memcpy(&(c->f), &(pars->f), sizeof(c->f));                                  \
                                                                              \
  if (!(c->flags & (SSH_ADT_FLAG_ALLOCATE                                     \
                    | SSH_ADT_FLAG_CONTAINED_HEADER)))                        \
    c->flags |= SSH_ADT_FLAG_NEED_EXTRA_NODES;                                \
                                                                              \
  if ((c->flags & SSH_ADT_FLAG_ALLOCATE) &&                                   \
      !(c->flags & SSH_ADT_FLAG_CONTAINED_HEADER))                            \
    {                                                                         \
      c->f.header_offset =                                                    \
        -((SshInt32)(c->static_data->internal_header_size));                  \
    }                                                                         \
                                                                              \
  c->num_objects = 0;                                                         \
  return (block);                                                             \
}

#define SSH_ADT_STD_DESTROY(name, block)                                      \
static void name(SshADTContainer c)                                           \
{                                                                             \
  SSH_ADT_CALL_DESTROY_HOOK(c, destr);                                        \
  SSH_ADT_PROTECT(block);                                                     \
  SSH_ADT_CALL_APP(c, cleanup, SSH_ADT_APPCTX(c));                            \
  if (c->flags & (SSH_ADT_FLAG_CONTAINED_HEADER | SSH_ADT_FLAG_ALLOCATE))     \
    ssh_free(c->hooks);                                                       \
}

#define SSH_ADT_STD_INSERT_AT(name, block, make_node_block)                   \
static SshADTHandle name(SshADTContainer c,                                   \
                         SshADTRelativeLocation location,                     \
                         SshADTHandle handle,                                 \
                         void *object)                                        \
{                                                                             \
  SshADTHandle h;                                                             \
  SSH_ADT_STD_MAKE_HANDLE(c, object, make_node_block, h);                     \
  if (h == SSH_ADT_INVALID)                                                   \
    {                                                                         \
      SSH_DEBUG(9, ("inserting %p failed.", object));                         \
      return SSH_ADT_INVALID;                                                 \
    }                                                                         \
  if (block == FALSE)                                                         \
    {                                                                         \
      SSH_DEBUG(9, ("inserting %p failed.", object));                         \
      return SSH_ADT_INVALID;                                                 \
    }                                                                         \
  c->num_objects++;                                                           \
  SSH_ADT_CALL_HOOK(c, insert, h);                                            \
  return h;                                                                   \
}

#define SSH_ADT_STD_INSERT_TO(name, block, make_node_block)                   \
static SshADTHandle name(SshADTContainer c,                                   \
                         SshADTAbsoluteLocation location,                     \
                         void *object)                                        \
{                                                                             \
  SshADTHandle h;                                                             \
  SSH_ADT_STD_MAKE_HANDLE(c, object, make_node_block, h);                     \
  if (h == SSH_ADT_INVALID)                                                   \
    {                                                                         \
      SSH_DEBUG(9, ("inserting %p failed (alloc).", object));                 \
      return SSH_ADT_INVALID;                                                 \
    }                                                                         \
  if (!(block))                                                               \
    {                                                                         \
      SSH_DEBUG(9, ("inserting %p failed (init).", object));                  \
      return SSH_ADT_INVALID;                                                 \
    }                                                                         \
  c->num_objects++;                                                           \
  SSH_ADT_CALL_HOOK(c, insert, h);                                            \
  return h;                                                                   \
}

#define SSH_ADT_STD_ALLOC_N_AT(name, block)                                   \
static SshADTHandle name(SshADTContainer c,                                   \
                         SshADTRelativeLocation location,                     \
                         SshADTHandle handle,                                 \
                         size_t size)                                         \
{                                                                             \
  SshADTHandle h;                                                             \
  void *newp;                                                                 \
                                                                              \
  SSH_ADT_STD_ALLOC_I(c, size, newp);                                         \
  SSH_ADT_CALL_APP(c, init, (newp, size, SSH_ADT_APPCTX(c)));                 \
  h = SSH_ADT_HANDLE_FROM_OBJECT(c, newp);                                    \
  SSH_ADT_PROTECT(block);                                                     \
  c->num_objects++;                                                           \
  SSH_ADT_CALL_HOOK(c, insert, h);                                            \
  return h;                                                                   \
}

#define SSH_ADT_STD_ALLOC_N_TO(name, block)                                   \
static SshADTHandle name(SshADTContainer c,                                   \
                  SshADTAbsoluteLocation location,                            \
                  size_t size)                                                \
{                                                                             \
  SshADTHandle h;                                                             \
  void *newp;                                                                 \
                                                                              \
  SSH_ADT_STD_ALLOC_I(c, size, newp);                                         \
  SSH_ADT_CALL_APP(c, init, (newp, size, SSH_ADT_APPCTX(c)));                 \
  h = SSH_ADT_HANDLE_FROM_OBJECT(c, newp);                                    \
  SSH_ADT_PROTECT(block);                                                     \
  c->num_objects++;                                                           \
  SSH_ADT_CALL_HOOK(c, insert, h);                                            \
  return h;                                                                   \
}

#define SSH_ADT_STD_PUT_N_AT(name, block)                                     \
static SshADTHandle name(SshADTContainer c,                                   \
                         SshADTRelativeLocation location,                     \
                         SshADTHandle handle,                                 \
                         size_t size,                                         \
                         void *object)                                        \
{                                                                             \
  SshADTHandle h;                                                             \
  void *newp;                                                                 \
                                                                              \
  SSH_ADT_STD_ALLOC_I(c, size, newp);                                         \
  SSH_ADT_CALL_APP(c, copy, (newp, size, object,                              \
                             SSH_ADT_APPCTX(c)));                             \
  h = SSH_ADT_HANDLE_FROM_OBJECT(c, newp);                                    \
  SSH_ADT_PROTECT(block);                                                     \
  c->num_objects++;                                                           \
  SSH_ADT_CALL_HOOK(c, insert, h);                                            \
  return h;                                                                   \
}

#define SSH_ADT_STD_PUT_N_TO(name, block)                                     \
static SshADTHandle name(SshADTContainer c,                                   \
                         SshADTAbsoluteLocation location,                     \
                         size_t size,                                         \
                         void *object)                                        \
{                                                                             \
  SshADTHandle h;                                                             \
  void *newp;                                                                 \
                                                                              \
  SSH_ADT_STD_ALLOC_I(c, size, newp);                                         \
  SSH_ADT_CALL_APP(c, copy, (newp, size, object,                              \
                                     SSH_ADT_APPCTX(c)));                     \
  h = SSH_ADT_HANDLE_FROM_OBJECT(c, newp);                                    \
  SSH_ADT_PROTECT(block);                                                     \
  c->num_objects++;                                                           \
  SSH_ADT_CALL_HOOK(c, insert, h);                                            \
  return h;                                                                   \
}

#define SSH_ADT_STD_GET(name)                                                 \
static void *name(SshADTContainer c, SshADTHandle handle)                     \
{                                                                             \
  void *ptr;                                                                  \
  SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(c, handle, ptr);                         \
  return ptr;                                                                 \
}

#define SSH_ADT_STD_NUM_OBJECTS(name)                                         \
static size_t name(SshADTContainer c)                                         \
{                                                                             \
  return c->num_objects;                                                      \
}

#define SSH_ADT_STD_GET_HANDLE_TO(name, block)                                \
static SshADTHandle name(SshADTContainer c,                                   \
                         void *object)                                        \
{                                                                             \
  if (c->flags & SSH_ADT_FLAG_NEED_EXTRA_NODES)                               \
    {                                                                         \
      SshADTHandle handle;                                                    \
      SSH_ADT_PROTECT(block);                                                 \
      return handle;                                                          \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      return SSH_ADT_HANDLE_FROM_OBJECT(c, object);                           \
    }                                                                         \
}

#ifdef _KERNEL
#define SSH_ADT_STD_REALLOC(name, block1, block2)                             \
static void *name(SshADTContainer c, void *object, size_t new_size)           \
{                                                                             \
  ssh_fatal("SSH_ADT_STD_REALLOC(): memory mode not supported in _KERNEL");   \
  return NULL;                                                                \
}
#else /* _KERNEL */
#define SSH_ADT_STD_REALLOC(name, block1, block2)                             \
static void *name(SshADTContainer c, void *object, size_t new_size)           \
{                                                                             \
  unsigned char *ptr;                                                         \
  SshADTHandle oldh, newh;                                                    \
                                                                              \
  oldh = SSH_ADT_HANDLE_FROM_OBJECT(c, object);                               \
  SSH_ADT_PROTECT(block1);                                                    \
  if (c->flags & SSH_ADT_FLAG_CONTAINED_HEADER)                               \
    {                                                                         \
      ptr = ssh_realloc(object, 0, new_size);                                 \
      newh = SSH_ADT_HANDLE_FROM_OBJECT(c, (void *)ptr);                      \
    }                                                                         \
  else                                                                        \
    {                                                                         \
      ptr = object;                                                           \
      ptr -= c->static_data->internal_header_size;                            \
      ptr = ssh_realloc(ptr, 0, new_size +                                    \
                        c->static_data->internal_header_size);                \
      newh = ptr;                                                             \
    }                                                                         \
  SSH_ADT_PROTECT(block2);                                                    \
  SSH_ADT_CALL_REALLOC_HOOK(c, reallocated, oldh, newh);                      \
  return ptr;                                                                 \
}
#endif /* _KERNEL */

#define SSH_ADT_STD_DETACH(name, block, destroy_node_block)                   \
static void *name(SshADTContainer c, SshADTHandle handle)                     \
{                                                                             \
  unsigned char *object;                                                      \
                                                                              \
  SSH_ADT_CALL_HOOK(c, detach, handle);                                       \
  SSH_DEBUG(9, ("Detach: handle=%p", handle));                                \
                                                                              \
  SSH_ADT_STD_GET_OBJECT_FROM_HANDLE(c, handle, object);                      \
  SSH_ADT_PROTECT(block);                                                     \
                                                                              \
  if (c->flags & SSH_ADT_FLAG_NEED_EXTRA_NODES)                               \
    {                                                                         \
      void *node = ((unsigned char *)handle) - sizeof(void *);                \
      SSH_ADT_PROTECT(destroy_node_block);                                    \
    }                                                                         \
                                                                              \
  c->num_objects--;                                                           \
  return object;                                                              \
}

#define SSH_ADT_STD_DELETE(name)                                              \
static void name(SshADTContainer container, SshADTHandle handle)              \
{                                                                             \
  void *object;                                                               \
                                                                              \
  /* For mappings, the CALL_APP macros are not used here because the          \
     conditions for calling are slightly different.  Also observe that        \
     the detaching operation above invalidated the handle, but did not        \
     free it.  The mapping remains untouched, and the image has to be         \
     freed manually later.  */                                                \
  if (container->f.app_methods.map_detach != NULL_FNPTR)                      \
    {                                                                         \
      void *old_image = ssh_adt_map_lookup(container, handle);                \
      if (old_image != NULL)                                                  \
        (*(container->f.app_methods.map_detach))                              \
          (old_image, SSH_ADT_APPCTX(container));                             \
    }                                                                         \
                                                                              \
  object = ssh_adt_detach_i(container, handle);                               \
                                                                              \
  SSH_ADT_CALL_APP(container, destr, (object, SSH_ADT_APPCTX(container)));    \
                                                                              \
  if (container->flags & SSH_ADT_FLAG_ALLOCATE)                               \
    {                                                                         \
      SSH_ADT_STD_FREE_I(container, handle);                                  \
    }                                                                         \
}

#define SSH_ADT_STD_MAP_ATTACH(name, image_location)                          \
static void name(SshADTContainer container,                                   \
                 SshADTHandle handle, void *new_image)                        \
{                                                                             \
  if (container->f.app_methods.map_detach != NULL_FNPTR)                      \
    {                                                                         \
      void *old_image = ssh_adt_map_lookup(container, handle);                \
      if (old_image != NULL)                                                  \
        (*(container->f.app_methods.map_detach))                              \
          (old_image, SSH_ADT_APPCTX(container));                             \
    }                                                                         \
                                                                              \
  if (container->f.app_methods.map_attach != NULL_FNPTR)                      \
    if (new_image != NULL)                                                    \
      (*(container->f.app_methods.map_attach))                                \
        (new_image, SSH_ADT_APPCTX(container));                               \
                                                                              \
  SSH_ADT_CALL_HOOK(container, unmap, handle);                                \
  image_location = new_image;                                                 \
  SSH_ADT_CALL_HOOK(container, map, handle);                                  \
}

#define SSH_ADT_STD_MAP_LOOKUP(name, image_location)                          \
static void *name(SshADTContainer container, SshADTHandle handle)             \
{                                                                             \
  return image_location;                                                      \
}

#define SSH_ADT_STD_NOTHING do { } while (0);

#endif /* SSHADT_STD_I_H_INCLUDED */
