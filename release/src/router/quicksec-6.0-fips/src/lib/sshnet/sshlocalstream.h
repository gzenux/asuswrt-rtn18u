/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Local streams between two processes running on the same machine.
   These may correspond to e.g. named pipes, unix-domain sockets, or some
   other form of inter-process communication, depending on the system.
   Listeners with these streams are identified with file names.
*/

#ifndef SSHLOCALSTREAM_H
#define SSHLOCALSTREAM_H

#include "sshstream.h"
#include "sshoperation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Data type for a local listener. */
typedef struct SshLocalListenerRec *SshLocalListener;

/* Type for a callback function to be called when a local listener receives
   a connection or when connecting to a local listener is complete. */
typedef void (*SshLocalCallback)(SshStream stream, void *context);

  /* The enum type which is used to define who is allowed to access
     the stream. If you do not specify the params to the local stream
     creation, the default is SSH_LOCAL_STREAM_ACCESS_ALLOW_ROOT. */
typedef enum
{
  /* Allow the administrator/root and the current user to connect to
     the stream, regardless of the logon session. (There is no need to
     specify a separate SSH_LOCAL_STREAM_ACCESS_ALLOW_USER, because
     the root/Administrator can anyway impersonate the user
     anyway). This is the default if the params is not given. */
  SSH_LOCAL_STREAM_ACCESS_ROOT,

  /* only allow other processes of the same user running in the same
     logon session to connect. This can only be used in Windows. In
     Unix this behaves the same way as
     SSH_LOCAL_STREAM_ACCESS_ALLOW_ROOT. */
  SSH_LOCAL_STREAM_ACCESS_LOGON_SESSION,

  /* Allow everybody to connect to the stream. */
  SSH_LOCAL_STREAM_ACCESS_ALL
} SshLocalStreamAccessType;

  /* Parameters for the local stream creation. If not specified
     (memset to zero) or if the params argument provided to
     ssh_local_make_listener is NULL, the default values are used. */
typedef struct SshLocalStreamParamsRec
{
  /* Specifies who can access the stream. */
  SshLocalStreamAccessType access;
} *SshLocalStreamParams, SshLocalStreamParamsStruct;

/* Creates a local listener for receiving connections to the supplied
   path.  If there already is a listener for the specified path, this
   fails.  Otherwise, this reserves the given pathname, and any
   connect requests with the same path will result in a call to the
   supplied callback.  The listener created by this is only accessible
   from within the local machine. The parameters given in the params
   argument further specify, what kind of stream is created.

   The implementation must provide the necessary access control
   mechanisms to guarantee that connections cannot be made from
   outside the local machine. */
SshLocalListener ssh_local_make_listener(const unsigned char *path,
                                         SshLocalStreamParams params,
                                         SshLocalCallback callback,
                                         void *context);

/* Destroys the local listener.  However, this might leave entries in
   the file system on some systems.  (For example, in Unix this does
   not remove the unix-domain socket, as this might be called after a
   fork, and we might wish to continue receiving connections in the
   other fork.)  Thus, it is recommended that remove() be called for
   the path to ensure that any garbage has been removed.  (The remove
   call should probably be made just before creating a new listener,
   in case the application has previously crashed before destroying
   the listener). */
void ssh_local_destroy_listener(SshLocalListener listener);

/* Connects to the local listener with the given path.  The callback
   will be colled when the connection is complete or has failed. If
   the connection is successful, an SshStream object is created and
   passed to the callback.  If connecting fails, NULL is passed to the
   callback as the stream.

   Returns an operation handle, which is non NULL if the connect is
   asynchronous. Connection can be aborted by calling
   ssh_operation_abort, for the returned handle. */
SshOperationHandle ssh_local_connect(const unsigned char *path,
                                     SshLocalCallback callback,
                                     void *context);
#ifdef __cplusplus
}
#endif

#endif /* SSHLOCALSTREAM_H */

