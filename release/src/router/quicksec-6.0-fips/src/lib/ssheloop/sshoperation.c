/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic asynchronous call interface.  Registering, aborting and finishing
   asynchronous calls.
*/

#include "sshincludes.h"
#include "sshoperation.h"

#define SSH_DEBUG_MODULE "SshOperation"

/* Attach destructor and provide the memory for the operation. This
   function can not fail. Caller must provide the pointer to the
   allocated structure in dstr_ptr. */
void ssh_operation_attach_destructor_no_alloc(SshOperationDestructor dest,
                                              SshOperationHandle handle,
                                              SshOperationDestructorCB cb,
                                              void *context)
{
  if (handle == NULL)
    {
      (*cb)(FALSE, context);
    }
  else if (cb)
    {
      dest->destructor_cb = cb;
      dest->context = context;
      dest->dynamic_mem = FALSE;
      dest->next = handle->destructor_list;
      handle->destructor_list = dest;
    }
}

/* Registeres a callback to be called when a handle is unregistered or
   aborted. If this function is called with a NULL operation handle
   the destructor_cb is called inside the call. This functionality is
   usefull for modules that pass handles from lower modules to higher
   modules. Usually the middle module needs to know, when the
   asynchronous call ends, so that it may free the allocated data that it
   has passed as parameters to lower modules.

   This function can be called multiple times for the same handle,
   even with the same callback and context. The callbacks are simply
   queued, and called whenever the ssh_operation_unregister is
   called. The destructor functions are called in the reverse order
   than they are attached to the handle. */
Boolean ssh_operation_attach_destructor(SshOperationHandle handle,
                                        SshOperationDestructorCB callback,
                                        void *context)
{
  SshOperationDestructor dest;

  /* The simple case. */
  if (handle == NULL)
    {
      (*callback)(FALSE, context);
    }
  else if (callback)
    {
      if ((dest = ssh_calloc(1, sizeof(*dest))) == NULL)
        return FALSE;
      ssh_operation_attach_destructor_no_alloc(dest, handle,
                                               callback, context);
      dest->dynamic_mem = TRUE;
    }
  return TRUE;
}

/* Calls destructors for a handle, when it is being unregistered or
   aborted. */
static void ssh_operation_call_destructors(SshOperationDestructor dest,
                                           Boolean aborted)
{
  SshOperationDestructor next;

  while (dest)
    {
      Boolean dynamic = dest->dynamic_mem;

      next = dest->next;
      (*dest->destructor_cb)(aborted, dest->context);
      if (dynamic)
        ssh_free(dest);
      dest = next;
    }
}


/* Register started asynchronous call and corresponding abort callback
   with no memory allocation. The caller must provide the pointer to
   the allocated handle (which typically is stored inside the
   operation_context). This call is called by the function that
   starts the real operation, and the handle must be returned to the
   caller of the function, so it can then abort the operation using
   the ssh_operation_abort. This function can not fail. */
void ssh_operation_register_no_alloc(SshOperationHandle handle,
                                     SshOperationAbortCB abort_cb,
                                     void *operation_context)
{
  memset(handle, 0, sizeof(*handle));
  handle->abort_cb = abort_cb;
  handle->operation_context = operation_context;
}

/* Register started asynchronous call and corresponding abort callback. This
   call is called by the function that starts the real operation, and the
   handle must be returned to the caller of the function, so it can then abort
   the operation using the ssh_operation_abort. */
SshOperationHandle ssh_operation_register(SshOperationAbortCB abort_cb,
                                          void *operation_context)
{
  SshOperationHandle handle;

  if ((handle = ssh_calloc(1, sizeof(*handle))) == NULL)
    return NULL;

  ssh_operation_register_no_alloc(handle, abort_cb, operation_context);
  handle->dynamic_mem = 1;

  return handle;
}

/* Unregister the handle. The abort callback will not be called, and the handle
   is invalid after this (i.e any other part of the code must not call
   ssh_operation_abort using the handle). */
void ssh_operation_unregister_no_free(SshOperationHandle handle)
{
  SshOperationDestructor destructor_list = handle->destructor_list;

  SSH_ASSERT(handle->dynamic_mem == 0);

  /* Enforce that behaviour follows the API description.
     The operation handle is invalid after ssh_operation_unregister
     or ssh_operation_abort is called. */
  SSH_ASSERT(handle->unregistered == 0);
  SSH_ASSERT(handle->aborted == 0);
  handle->unregistered = 1;

  /* If we are inside the abort call, all fields of the handle are
     already cleared and these are effectively no-ops. */
  ssh_operation_call_destructors(destructor_list, FALSE);
}

/* Unregister the handle. The abort callback will not be called, and the handle
   is invalid after this (i.e any other part of the code must not call
   ssh_operation_abort using the handle). */
void ssh_operation_unregister(SshOperationHandle handle)
{
  if (handle != NULL)
    {
      Boolean dynamic = FALSE;
      SshOperationDestructor destructor_list = handle->destructor_list;

      /* Enforce that behaviour follows the API description.
         The operation handle is invalid after ssh_operation_unregister
         or ssh_operation_abort is called. */
      SSH_ASSERT(handle->unregistered == 0);
      SSH_ASSERT(handle->aborted == 0);
      handle->unregistered = 1;

      if (handle->dynamic_mem != 0)
        dynamic = TRUE;

      /* If we are inside the abort call, all fields of the handle are
         already cleared and these are effectively no-ops. */
      ssh_operation_call_destructors(destructor_list, FALSE);
      if (dynamic)
        ssh_free(handle);
    }
}

/* Return operation context pointer from the given operation handle. */
void *ssh_operation_get_context(SshOperationHandle handle)
{
  /* Enforce that behaviour follows the API description.
     The operation handle is invalid after ssh_operation_unregister
     or ssh_operation_abort is called. */
  SSH_ASSERT(handle->unregistered == 0);
  SSH_ASSERT(handle->aborted == 0);

  return handle->operation_context;
}

/* Call abort callback of the pending asynchronous call. The abort callback
   will then abort the operation if it is possible, and free the context
   associated to it. Note, after this call then, the handle is invalid, and no
   other calls can be made using it. The abort callback will also make sure
   that no other callbacks are called associated with this asynchronous call.
   */
void ssh_operation_abort(SshOperationHandle handle)
{
  if (handle != NULL)
    {
      Boolean dynamic = handle->dynamic_mem;
      SshOperationDestructor destructor_list = handle->destructor_list;
      SshOperationAbortCB abort_cb = handle->abort_cb;
      void *context = handle->operation_context;

      /* Enforce that behaviour follows the API description.
         The operation handle is invalid after ssh_operation_unregister
         or ssh_operation_abort is called. */
      SSH_ASSERT(handle->unregistered == 0);
      SSH_ASSERT(handle->aborted == 0);
      handle->aborted = 1;

      (*abort_cb)(context);
      ssh_operation_call_destructors(destructor_list, TRUE);
      if (dynamic)
        ssh_free(handle);
    }
}
