/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

#include "sshincludes.h"
#include "sshadt_i.h"
#include "sshdebug.h"

#define SSH_DEBUG_MODULE "SshADT"


/******************************************************** Default callbacks. */

int ssh_adt_default_compare(const void *obj1, const void *obj2,
                            void *context)
{
  if (obj1 < obj2) return -1;
  if (obj1 > obj2) return 1;
  return 0;
}

void *ssh_adt_default_duplicate(void *obj, void *context)
{
  return obj;
}

void ssh_adt_default_copy(void *dst, size_t d_size,
                          const void *src, void *context)
{
  SSH_DEBUG(9, ("Copying %d bytes from %p to %p.", d_size, src, dst));
  memcpy(dst, src, d_size);
}

void ssh_adt_default_destroy(void *obj, void *context)
{
  return;
}

void ssh_adt_default_init(void *obj, size_t size, void *context)
{
  memset(obj, 0, size);
}

SshUInt32 ssh_adt_default_hash(const void *obj, void *context)
{
  /* This kludge is here to remove a compilation warning on 64-bit
     platforms. */
  unsigned long ptr_num = (unsigned long) obj;
  return (SshUInt32) ptr_num;
}


/**************************************** Initialize and destroy containers. */

static void set_default_values(SshADTStandardFields *f)
{
  f->app_methods.compare       = ssh_adt_default_compare;
  f->app_methods.copy          = ssh_adt_default_copy;
  f->app_methods.duplicate     = ssh_adt_default_duplicate;
  f->app_methods.destr         = ssh_adt_default_destroy;
  f->app_methods.init          = ssh_adt_default_init;
  f->app_methods.hash          = ssh_adt_default_hash;
  f->app_methods.cleanup       = NULL_FNPTR;
  f->app_methods.map_attach    = NULL_FNPTR;
  f->app_methods.map_detach    = NULL_FNPTR;
  f->app_methods.context       = NULL;
}

static Boolean init_toplevel_container(SshADTContainer c,
                                       SshADTContainerType type,
                                       va_list args)
{
  SshADTArgumentType t;
  SshADTContainerParsStruct pars, *ptr;
  const SshADTStaticData *static_data;

  SSH_PRECOND(type != NULL);

  memset(&pars, 0, sizeof(pars));
  set_default_values(&(pars.f));
  ptr = &(pars);

  ptr->type = type;

  while ((t = va_arg(args, SshADTArgumentType)) != SSH_ADT_ARGS_END)
    {
      switch (t)
        {
        case SSH_ADT_CONTEXT:
          ptr->f.app_methods.context = va_arg(args, void *);
          SSH_DEBUG(9, ("Registered callback context @%p.",
                        ptr->f.app_methods.context));
          break;

        case SSH_ADT_COMPARE:
          ptr->f.app_methods.compare = va_arg(args, SshADTCompareFunc);
          SSH_DEBUG(9, ("Registered compare callback @%p.",
                        ptr->f.app_methods.compare));
          break;

        case SSH_ADT_COPY:
          ptr->f.app_methods.copy = va_arg(args, SshADTCopyFunc);
          SSH_DEBUG(9, ("Registered copy callback @%p.",
                        ptr->f.app_methods.copy));
          break;

        case SSH_ADT_DUPLICATE:
          ptr->f.app_methods.duplicate = va_arg(args, SshADTDuplicateFunc);
          SSH_DEBUG(9, ("Registered duplicate callback @%p.",
                        ptr->f.app_methods.duplicate));
          break;

        case SSH_ADT_DESTROY:
          ptr->f.app_methods.destr = va_arg(args, SshADTDestroyFunc);
          SSH_DEBUG(9, ("Registered destroy callback @%p.",
                        ptr->f.app_methods.destr));
          break;

        case SSH_ADT_HASH:
          ptr->f.app_methods.hash = va_arg(args, SshADTHashFunc);
          SSH_DEBUG(9, ("Registered hash callback @%p.",
                        ptr->f.app_methods.hash));
          break;

        case SSH_ADT_INIT:
          ptr->f.app_methods.init = va_arg(args, SshADTInitFunc);
          SSH_DEBUG(9, ("Registered init callback @%p.",
                        ptr->f.app_methods.init));
          break;

        case SSH_ADT_MAP_ATTACH:
          ptr->f.app_methods.map_attach = va_arg(args, SshADTMapAttachFunc);
          SSH_DEBUG(9, ("Registered map_attach callback @%p.",
                        ptr->f.app_methods.map_attach));
          break;

        case SSH_ADT_MAP_DETACH:
          ptr->f.app_methods.map_detach = va_arg(args, SshADTMapDetachFunc);
          SSH_DEBUG(9, ("Registered map_detach callback @%p.",
                        ptr->f.app_methods.map_detach));
          break;

        case SSH_ADT_CLEANUP:
          ptr->f.app_methods.cleanup = va_arg(args, SshADTCleanupFunc);
          SSH_DEBUG(9, ("Registered cleanup callback @%p.",
                        ptr->f.app_methods.cleanup));
          break;

        case SSH_ADT_SIZE:
          ptr->flags |= SSH_ADT_FLAG_ALLOCATE;
          ptr->f.default_object_size = va_arg(args, size_t);
          break;

        case SSH_ADT_HEADER:
          ptr->flags |= SSH_ADT_FLAG_CONTAINED_HEADER;
          ptr->f.header_offset = va_arg(args, SshUInt32);
          break;

        default:
          SSH_NOTREACHED;
        }
    }

#ifdef _KERNEL
  /* In kernel mode, objects must be concrete.  (Also, if there is a
     header structure at all, it must be inlined.  This is checked in
     the implementations because at least array does not need headers
     and thus this restriction is void.)  */
  SSH_ASSERT(!(ptr->flags & SSH_ADT_FLAG_ALLOCATE));
#endif

  static_data = pars.type;

  return ((*(static_data->methods.container_init))(c, ptr));
}

SshADTContainer ssh_adt_create_generic(SshADTContainerType type, ...)
{
  va_list args;
  SshADTContainer c;

  if (!(c = ssh_malloc(sizeof(*c))))
    return NULL;

  va_start(args, type);

  if (init_toplevel_container(c, type, args) == FALSE)
    {
      ssh_free(c);
      va_end(args);
      return NULL;
    }
  else
    {
      va_end(args);
      return c;
    }
}

void ssh_adt_destroy(SshADTContainer container)
{
  if (!container)
    return;

  (*(container->static_data->methods.destr))(container);
  ssh_free(container);
}

#if 0
void ssh_adt_init_generic(SshADTContainer container,
                          SshADTContainerType type, ...)
{
  va_list args;

  va_start(args, type);
  init_toplevel_container(container, type, args);
  va_end(args);
}

void ssh_adt_uninit(SshADTContainer container)
{
  SSH_ADT_CALL_DESTROY_HOOK(container, destr);
  SSH_ADT_CALL(container, FALSE, container_uninit, (container));
  ssh_free(container->hooks);
}
#endif

/************************************************************* Record magic. */

void *ssh_adt_duplicate_object(SshADTContainer container, void *object)
{
  void *result;
  SSH_ADT_CALL_APP_MANDATORY(container, duplicate,
                             (object, SSH_ADT_APPCTX(container)), result);
  return result;
}

/******************************************************************** Hooks. */

int ssh_adt_initialize_hooks(SshADTContainer container)
{
  ssh_free(container->hooks);
  if (!(container->hooks = ssh_malloc(sizeof(*container->hooks))))
    return 1;

  container->hooks->insert      = NULL_FNPTR;
  container->hooks->detach      = NULL_FNPTR;
  container->hooks->map         = NULL_FNPTR;
  container->hooks->unmap       = NULL_FNPTR;
  container->hooks->reallocated = NULL_FNPTR;
  container->hooks->destr       = NULL_FNPTR;
  return 0;
}

void ssh_adt_uninitialize_hooks(SshADTContainer container)
{
  ssh_free(container->hooks);
  container->hooks = NULL;
}

#ifndef SSH_ADT_WITH_MACRO_INTERFACE

#define SSH_ADT_INTERNAL_MACROS
#include "sshadt_impls.h"
#undef SSH_ADT_INTERNAL_MACROS

/****************************************************** Non-macro Interface. */

#define SSH_ADT_ASSERT_CONTAINER SSH_PRECOND(container != NULL)
#define SSH_ADT_ASSERT_EXTERNAL  \
  SSH_PRECOND(SSH_ADT_DEFAULT_SIZE(container) == 0)
#define SSH_ADT_ASSERT_INTERNAL  \
  SSH_PRECOND(SSH_ADT_DEFAULT_SIZE(container) != 0)
#define SSH_ADT_ASSERT_HANDLE    SSH_PRECOND(handle != SSH_ADT_INVALID)
#define SSH_ADT_ASSERT_OBJECT    SSH_PRECOND(object != NULL)

size_t ssh_adt_default_size(SshADTContainer container)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  return SSH_ADT_DEFAULT_SIZE(container);
}

void ssh_adt_clear(SshADTContainer container)
{
  SSH_ADT_ASSERT_CONTAINER;
  ssh_adt_clear__(container);
}

SshADTHandle ssh_adt_insert_at(SshADTContainer container,
                               SshADTRelativeLocation location,
                               SshADTHandle handle,
                               void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  SSH_ADT_ASSERT_HANDLE;
  if (container->flags & SSH_ADT_FLAG_CONTAINED_HEADER)
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.insert_at != NULL_FNPTR);
  return ssh_adt_insert_at__(container, location, handle, object);
}

SshADTHandle ssh_adt_insert_to(SshADTContainer container,
                               SshADTAbsoluteLocation location,
                               void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  if (container->flags & SSH_ADT_FLAG_CONTAINED_HEADER)
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.insert_to != NULL_FNPTR);
  return ssh_adt_insert_to__(container, location, object);
}

SshADTHandle ssh_adt_insert(SshADTContainer container,
                            void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  if (container->flags & SSH_ADT_FLAG_CONTAINED_HEADER)
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.insert_to != NULL_FNPTR);
  return ssh_adt_insert_to(container, SSH_ADT_DEFAULT, object);
}

SshADTHandle ssh_adt_duplicate_at(SshADTContainer container,
                                  SshADTRelativeLocation location,
                                  SshADTHandle handle,
                                  void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  if (container->flags & SSH_ADT_FLAG_CONTAINED_HEADER)
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.insert_at != NULL_FNPTR);
  return ssh_adt_insert_at(container, location, handle,
                           ssh_adt_duplicate_object(container, object));
}

SshADTHandle ssh_adt_duplicate_to(SshADTContainer container,
                                  SshADTAbsoluteLocation location,
                                  void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  if (container->flags & SSH_ADT_FLAG_CONTAINED_HEADER)
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.insert_to != NULL_FNPTR);
  return ssh_adt_insert_to(container, location,
                           ssh_adt_duplicate_object(container, object));
}

SshADTHandle ssh_adt_duplicate(SshADTContainer container,
                               void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  if (container->flags & SSH_ADT_FLAG_CONTAINED_HEADER)
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.insert_to != NULL_FNPTR);
  return ssh_adt_insert(container,
                        ssh_adt_duplicate_object(container, object));
}

SshADTHandle ssh_adt_alloc_n_at(SshADTContainer container,
                                SshADTRelativeLocation location,
                                SshADTHandle handle,
                                size_t size)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.alloc_n_at != NULL_FNPTR);
  return ssh_adt_alloc_n_at__(container, location, handle, size);
}

SshADTHandle ssh_adt_alloc_n_to(SshADTContainer container,
                                SshADTAbsoluteLocation location,
                                size_t size)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ASSERT(container->static_data->methods.alloc_n_to != NULL_FNPTR);
  return ssh_adt_alloc_n_to__(container, location, size);
}

SshADTHandle ssh_adt_alloc_at(SshADTContainer container,
                              SshADTRelativeLocation location,
                              SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.alloc_n_at != NULL_FNPTR);
  return ssh_adt_alloc_n_at(container, location,
                            handle, SSH_ADT_DEFAULT_SIZE(container));
}

SshADTHandle ssh_adt_alloc_to(SshADTContainer container,
                              SshADTAbsoluteLocation location)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ASSERT(container->static_data->methods.alloc_n_to != NULL_FNPTR);
  return ssh_adt_alloc_n_to(container, location,
                            SSH_ADT_DEFAULT_SIZE(container));
}

SshADTHandle ssh_adt_alloc_n(SshADTContainer container,
                             size_t size)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ASSERT(container->static_data->methods.alloc_n_to != NULL_FNPTR);
  return ssh_adt_alloc_n_to(container, SSH_ADT_DEFAULT, size);
}

SshADTHandle ssh_adt_alloc(SshADTContainer container)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ASSERT(container->static_data->methods.alloc_n_to != NULL_FNPTR);
  return ssh_adt_alloc_n(container, SSH_ADT_DEFAULT_SIZE(container));
}

SshADTHandle ssh_adt_put_n_at(SshADTContainer container,
                              SshADTRelativeLocation location,
                              SshADTHandle handle,
                              size_t size,
                              void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.put_n_at != NULL_FNPTR);
  return ssh_adt_put_n_at__(container, location, handle, size, object);
}

SshADTHandle ssh_adt_put_n_to(SshADTContainer container,
                              SshADTAbsoluteLocation location,
                              size_t size,
                              void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.put_n_to != NULL_FNPTR);
  return ssh_adt_put_n_to__(container, location, size, object);
}

SshADTHandle ssh_adt_put_at(SshADTContainer container,
                            SshADTRelativeLocation location,
                            SshADTHandle handle,
                            void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.put_n_at != NULL_FNPTR);
  return ssh_adt_put_n_at(container, location, handle,
                          SSH_ADT_DEFAULT_SIZE(container), object);
}

SshADTHandle ssh_adt_put_to(SshADTContainer container,
                            SshADTAbsoluteLocation location,
                            void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.put_n_to != NULL_FNPTR);
  return ssh_adt_put_n_to(container, location,
                          SSH_ADT_DEFAULT_SIZE(container), object);
}

SshADTHandle ssh_adt_put_n(SshADTContainer container,
                           size_t size,
                           void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.put_n_to != NULL_FNPTR);
  return ssh_adt_put_n_to(container, SSH_ADT_DEFAULT, size, object);
}

SshADTHandle ssh_adt_put(SshADTContainer container,
                         void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_INTERNAL;
  SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.put_n_to != NULL_FNPTR);
  return ssh_adt_put_n(container, SSH_ADT_DEFAULT_SIZE(container), object);
}

void *ssh_adt_get(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.get != NULL_FNPTR);
  return ssh_adt_get__(container, handle);
}

size_t ssh_adt_num_objects(SshADTContainer container)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ASSERT(container->static_data->methods.num_objects != NULL_FNPTR);
  return ssh_adt_num_objects__(container);
}

SshADTHandle ssh_adt_get_handle_to(SshADTContainer container,
                                   void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  if (container->flags & (SSH_ADT_FLAG_CONTAINED_HEADER |
                          SSH_ADT_FLAG_ALLOCATE))
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.get_handle_to != NULL_FNPTR);
  return ssh_adt_get_handle_to__(container, object);
}

SshADTHandle ssh_adt_get_handle_to_equal(SshADTContainer container,
                                         void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  if (container->flags & (SSH_ADT_FLAG_CONTAINED_HEADER |
                          SSH_ADT_FLAG_ALLOCATE))
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.get_handle_to_equal !=
             NULL_FNPTR);
  return ssh_adt_get_handle_to_equal__(container, object);
}

void *ssh_adt_get_object_from_equal(SshADTContainer container,
                                    void *object)
{
  SSH_ADT_ASSERT_CONTAINER;
  if (container->flags & (SSH_ADT_FLAG_CONTAINED_HEADER |
                          SSH_ADT_FLAG_ALLOCATE))
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.get_handle_to_equal !=
             NULL_FNPTR);
  return ssh_adt_get(container,
                     ssh_adt_get_handle_to_equal__(container, object));
}

SshADTHandle ssh_adt_next(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.next != NULL_FNPTR);
  return ssh_adt_next__(container, handle);
}

SshADTHandle ssh_adt_previous(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.previous != NULL_FNPTR);
  return ssh_adt_previous__(container, handle);
}

SshADTHandle ssh_adt_get_handle_to_location(SshADTContainer container,
                                            SshADTAbsoluteLocation location)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ASSERT(container->static_data->methods.get_handle_to_location !=
             NULL_FNPTR);
  return ssh_adt_get_handle_to_location__(container, location);
}

void *ssh_adt_get_object_from_location(SshADTContainer container,
                                       SshADTAbsoluteLocation location)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ASSERT(container->static_data->methods.get_handle_to_location !=
             NULL_FNPTR);
  return ssh_adt_get(container,
                     ssh_adt_get_handle_to_location__(container, location));
}

void *ssh_adt_detach(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.detach != NULL_FNPTR);
  return ssh_adt_detach__(container, handle);
}

void *ssh_adt_detach_from(SshADTContainer container,
                          SshADTAbsoluteLocation location)
{
  SshADTHandle handle;
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  SSH_ASSERT(container->static_data->methods.detach != NULL_FNPTR);
  SSH_ASSERT(container->static_data->methods.get_handle_to_location !=
             NULL_FNPTR);
  handle = ssh_adt_get_handle_to_location(container, location);
  SSH_ADT_ASSERT_HANDLE;
  return ssh_adt_detach(container, handle);
}

void *ssh_adt_detach_object(SshADTContainer container,
                            void *object)
{
  SshADTHandle handle;
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_EXTERNAL;
  if (container->flags & (SSH_ADT_FLAG_CONTAINED_HEADER |
                          SSH_ADT_FLAG_ALLOCATE))
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.detach != NULL_FNPTR);
  SSH_ASSERT(container->static_data->methods.get_handle_to != NULL_FNPTR);
  handle = ssh_adt_get_handle_to(container, object);
  SSH_ADT_ASSERT_HANDLE;
  return ssh_adt_detach(container, handle);
}

void ssh_adt_delete(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.delet != NULL_FNPTR);
  ssh_adt_delete__(container, handle);
}

void ssh_adt_delete_from(SshADTContainer container,
                         SshADTAbsoluteLocation location)
{
  SshADTHandle handle;
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ASSERT(container->static_data->methods.delet != NULL_FNPTR);
  SSH_ASSERT(container->static_data->methods.get_handle_to_location !=
             NULL_FNPTR);
  handle = ssh_adt_get_handle_to_location(container, location);
  SSH_ADT_ASSERT_HANDLE;
  ssh_adt_delete(container, handle);
}

void ssh_adt_delete_object(SshADTContainer container,
                           void *object)
{
  SshADTHandle handle;
  SSH_ADT_ASSERT_CONTAINER;
  if (container->flags & (SSH_ADT_FLAG_CONTAINED_HEADER |
                          SSH_ADT_FLAG_ALLOCATE))
    SSH_ADT_ASSERT_OBJECT;
  SSH_ASSERT(container->static_data->methods.delet != NULL_FNPTR);
  SSH_ASSERT(container->static_data->methods.get_handle_to != NULL_FNPTR);
  handle = ssh_adt_get_handle_to(container, object);
  SSH_ADT_ASSERT_HANDLE;
  ssh_adt_delete(container, handle);
}

SshADTHandle ssh_adt_enumerate_start(SshADTContainer container)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ASSERT(container->static_data->methods.enumerate_start != NULL_FNPTR);
  return ssh_adt_enumerate_start__(container);
}

SshADTHandle ssh_adt_enumerate_next(SshADTContainer container,
                                    SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.enumerate_next != NULL_FNPTR);
  return ssh_adt_enumerate_next__(container, handle);
}

void *ssh_adt_map_lookup(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.map_lookup != NULL_FNPTR);
  return ssh_adt_map_lookup__(container, handle);
}

void ssh_adt_map_attach(SshADTContainer container,
                        SshADTHandle handle, void *obj)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.map_attach != NULL_FNPTR);
  ssh_adt_map_attach__(container, handle, obj);
}

/* (for ssh_adt_detach_i, see comment in sshadt_i.h) */

void *ssh_adt_detach_i(SshADTContainer container, SshADTHandle handle)
{
  SSH_ADT_ASSERT_CONTAINER;
  SSH_ADT_ASSERT_HANDLE;
  SSH_ASSERT(container->static_data->methods.detach != NULL_FNPTR);
  return ssh_adt_detach__(container, handle);
}

#endif /* !SSH_ADT_WITH_MACRO_INTERFACE */
