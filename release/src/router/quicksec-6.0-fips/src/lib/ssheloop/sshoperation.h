/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Generic asynchronous call interface.  Registering, aborting and finishing
   asynchronous calls.
*/

#ifndef SSHOPERATION_H
#define SSHOPERATION_H

#ifdef __cplusplus
extern "C" {
#endif

/* Asyncronous return handler returned by the sshoperation code. This
   handle should be returned to the caller of the function that starts
   the asyncronous operation so the caller can store it, and call the
   ssh_operation_abort function later. */
typedef struct SshOperationHandleRec *SshOperationHandle;
typedef struct SshOperationHandleRec  SshOperationHandleStruct;

/* Interface which is used by the functions which gets the
   SshOperationHandles from the other functions */

/* Aborts the asynchronous call. Implementation calls the abort
   callback of the pending asynchronous call. The abort callback will
   then abort the operation if it is possible, and free the context
   associated to it. Note, after this call then, the handle is
   invalid, and no other calls can be made using it. The abort
   callback will also make sure that no other callbacks are called
   associated with this asynchronous call. */
void ssh_operation_abort(SshOperationHandle handle);

/* Interface that is used by intermediate libraries passing the handle. */

/* This type of callbacks are used with
   ssh_operation_attach_destructor. The callback is called whenewer
   the handle is unregistered, or if the
   ssh_operation_attach_destructor is called with a NULL handle. The
   aborted argument is set to TRUE when the call was aborted and FALSE
   otherwise. */
typedef void (*SshOperationDestructorCB)(Boolean aborted,
                                         void *context);

/* The destructor record that is used to save attached destructors for
   the handle. Do not access any of the fields of this record. The
   contents of the structure are visible only because the
   ssh_operation_attach_destructor_no_alloc function uses this
   structure. */
typedef struct SshOperationDestructorRec
{
  /* The link to  the next destructor. */
  struct SshOperationDestructorRec *next;
  /* Callback and the context for the callback. */
  SshOperationDestructorCB destructor_cb;
  void *context;
  Boolean dynamic_mem;
} *SshOperationDestructor, SshOperationDestructorStruct;


/* Registeres a callback to be called when a handle is unregistered or
   aborted. Returs TRUE if attaching is successfull, or FALSE when failed
   for memory allocation reasons.

   If this function is called with a NULL operation handle, the
   destructor_cb is called inside the call. The application does not
   need to check whether the application returned NULL or a valid
   handle. The destructor will be called regardless.

   Attaching destructors is usefull for modules that pass handles from
   lower modules to higher modules. Usually the middle module needs to
   know, when the asynchronous call ends, so that it may free the
   allocated data that it has passed as parameters to lower modules.

   This function can be called multiple times for the same handle,
   even with the same callback and context. The callbacks are simply
   queued, and called whenever the ssh_operation_unregister is
   called. The destructor functions are called in the reverse order
   than they are attached to the handle.

   When the operation is aborted, the abort callback is called before
   the attached destructor callbacks. If the handle is unregistered,
   the asynchronous function should call the completion callback
   first, and then ssh_operation_unregister which will call the
   attached destructors. */
Boolean ssh_operation_attach_destructor(SshOperationHandle handle,
                                        SshOperationDestructorCB callback,
                                        void *context);

/* Attach destructor and provide the memory for the operation. This
   function can not fail. Caller must provide the pointer to the
   allocated structure in dstr_ptr. */
void ssh_operation_attach_destructor_no_alloc(SshOperationDestructor dest,
                                              SshOperationHandle handle,
                                              SshOperationDestructorCB cb,
                                              void *context);

/* Interface which is used inside the functions that implement the
   asyncronous operations. */

/* Abort callback type. This callback is called when the asyncronous
   operations is aborted to stop the real operation. After this
   callback returns the asyncronous operation is not allowed to call
   any callbacks associated to the asyncronous operation. It should
   also either free all the data structures associated to it
   immediately, or postpone their freeing for the later time. */
typedef void (*SshOperationAbortCB)(void *operation_context);

/* The implementation of SshOperationHandle. Do not access any of the
   fields of this record. The contents of the structure are visible
   only because the ssh_operation_register_no_alloc function uses this
   structure. */
struct SshOperationHandleRec {
  SshOperationAbortCB abort_cb;
  void *operation_context;
  SshOperationDestructor destructor_list;
  SshUInt8 dynamic_mem : 1;
  SshUInt8 aborted : 1;
  SshUInt8 unregistered : 1;
};

/* Register started asynchronous call and corresponding abort
   callback. This call is called by the function that starts the real
   operation, and the handle must be returned to the caller of the
   function, so it can then abort the operation using the
   ssh_operation_abort. This call returns NULL if memory allocation
   fails. */
SshOperationHandle ssh_operation_register(SshOperationAbortCB abort_cb,
                                          void *operation_context);

/* Register started asynchronous call and corresponding abort callback
   with no memory allocation. The caller must provide the pointer to
   the allocated handle (which typically is stored inside the
   operation_context). This call is called by the function that
   starts the real operation, and the handle must be returned to the
   caller of the function, so it can then abort the operation using
   the ssh_operation_abort. This function can not fail. */
void ssh_operation_register_no_alloc(SshOperationHandle handle,
                                     SshOperationAbortCB abort_cb,
                                     void *operation_context);

/* Unregister the handle. The abort callback will not be called, and
   the handle is invalid after this (i.e any other part of the code
   must not call ssh_operation_abort using the handle). This should be
   called after the asynchronous function has called its completion
   callback. */
void ssh_operation_unregister(SshOperationHandle handle);

/* Like ssh_operation_unregister(), but without free.*/
void ssh_operation_unregister_no_free(SshOperationHandle handle);

/* Return operation context pointer from the given operation handle. */
void *ssh_operation_get_context(SshOperationHandle handle);

#ifdef __cplusplus
}
#endif

#endif /* SSHOPERATION_H */
/* eof (sshoperation.h) */
